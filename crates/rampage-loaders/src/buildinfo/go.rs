//! Go build info, the record `go version -m` prints: the toolchain version, the main package and module, every
//! dependency module (with its `=>` replacement), and the build settings. The linker writes it as a 32-byte header
//! starting with `\xff Go buildinf:` in `.go.buildinfo` (ELF), `__go_buildinfo` (Mach-O) or, on PE, at a 16-byte
//! aligned spot in the data; stripping (`-ldflags "-s -w"`) keeps it.
//!
//! Header: magic (14 bytes), pointer size (1), flags (1), then layout-specific bytes up to 32. With flag `0x2`
//! (go1.18 and later) the version and modinfo strings follow inline, each prefixed by its uvarint length. Earlier
//! binaries instead hold two pointers at offset 16 to Go string headers (data pointer, length), read here through
//! the image's file-backed virtual memory, in the byte order flag `0x1` gives. Modinfo is wrapped in 16-byte
//! sentinels and holds tab-separated `path`, `mod`, `dep`, `=>` and `build` lines.
//!
//! This parser is independent of the pclntab reader (`gopclntab.rs`); callers can cross-check the two with
//! [`expected_table`].

use rampage_arch::bytes::read_uint;
use serde::Serialize;

use super::{BlobLocation, BlobStatus, clip};
use crate::gopclntab::GoTableVersion;
use crate::warnings::CappedWarnings;
use crate::{Binary, SectionKind};

pub const MAGIC: &[u8; 14] = b"\xff Go buildinf:";
const HEADER_BYTES: usize = 32;
const ALIGN: u64 = 16;
const FLAG_BIG_ENDIAN: u8 = 0x1;
const FLAG_INLINE: u8 = 0x2;
/// The dedicated sections the Go linker writes; other images are scanned like Go's `debug/buildinfo` does.
const SECTIONS: &[&str] = &[".go.buildinfo", "__go_buildinfo"];
const MAX_VERSION_BYTES: usize = 1024;
/// Cap on the modinfo string, generous for real programs (a large one is tens of KiB).
pub const MAX_MODINFO_BYTES: usize = 4 << 20;
pub const MAX_DEPS: usize = 65_536;
pub const MAX_SETTINGS: usize = 1024;
const WARNINGS: CappedWarnings = CappedWarnings::new(64, "Go build info");
/// `runtime/debug` modinfo sentinels are 16 bytes each, and the text before the end one ends in a newline.
const SENTINEL_BYTES: usize = 16;

/// The Go build info of an image; `status` says whether it could be decoded at all.
#[derive(Debug, Clone, Serialize)]
pub struct GoBuildInfo {
    pub status: BlobStatus,
    /// Why an unreadable record could not be decoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub location: BlobLocation,
    pub layout: GoLayout,
    /// The header's pointer size; meaningful for the pointer layout only.
    pub pointer_size: u8,
    /// The header's byte order flag; meaningful for the pointer layout only.
    pub big_endian: bool,
    /// The toolchain that built the binary, e.g. `go1.22.4`.
    pub go_version: Option<String>,
    /// Whether modinfo was present (module-mode builds); GOPATH-mode builds have none.
    pub modinfo: bool,
    /// The main package's import path (`path` line).
    pub path: Option<String>,
    /// The main module (`mod` line).
    pub main: Option<GoModule>,
    /// Dependency modules in modinfo order (`dep` lines), up to [`MAX_DEPS`].
    pub deps: Vec<GoModule>,
    pub deps_truncated: bool,
    /// Build settings (`build` lines) in order, up to [`MAX_SETTINGS`].
    pub settings: Vec<GoSetting>,
    pub settings_truncated: bool,
    pub warnings: Vec<String>,
}

/// How the header holds its strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoLayout {
    /// go1.18+: uvarint-length-prefixed strings after the header.
    Inline,
    /// Before go1.18: pointers to Go string headers.
    Pointers,
    /// The header was too short to tell.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoModule {
    pub path: String,
    /// Empty for a directory replacement; `(devel)` for a main module built from a working tree.
    pub version: String,
    /// The go.sum hash, absent when modinfo leaves it empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sum: Option<String>,
    /// The module this one was replaced by (`=>` line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace: Option<Box<GoModule>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoSetting {
    pub key: String,
    pub value: String,
}

/// The image's Go build info, or `None` when it has none: no dedicated section and no magic in the data.
pub fn read(binary: &Binary) -> Option<GoBuildInfo> {
    let memory = |address: u64, len: u64| binary.read(address, len);
    let mut dedicated = super::sections_named(binary, SECTIONS).peekable();
    if dedicated.peek().is_some() {
        let mut first = None;
        for section in dedicated {
            let location = BlobLocation { section: section.name.clone(), address: section.address };
            let Some(bytes) = binary.section_file_bytes(section) else {
                first.get_or_insert_with(|| unreadable(location, "the build info section has no file bytes"));
                continue;
            };
            match find_magic(bytes, section.address) {
                Some(start) => {
                    let location = BlobLocation { section: section.name.clone(), address: section.address + start };
                    return Some(decode(&bytes[start as usize..], location, &memory));
                }
                None => {
                    first.get_or_insert_with(|| unreadable(location, "the build info section lacks the Go magic"));
                }
            }
        }
        return first;
    }
    for section in &binary.sections {
        if !matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData) {
            continue;
        }
        let Some(bytes) = binary.section_file_bytes(section) else { continue };
        if let Some(start) = find_magic(bytes, section.address) {
            let location = BlobLocation { section: section.name.clone(), address: section.address + start };
            return Some(decode(&bytes[start as usize..], location, &memory));
        }
    }
    None
}

/// The offset of the first 16-byte aligned (by virtual address) magic in `bytes`, which start at `address`.
fn find_magic(bytes: &[u8], address: u64) -> Option<u64> {
    let mut offset = (ALIGN - address % ALIGN) % ALIGN;
    while let Some(window) = usize::try_from(offset).ok().and_then(|start| bytes.get(start..start + MAGIC.len())) {
        if window == MAGIC {
            return Some(offset);
        }
        offset += ALIGN;
    }
    None
}

fn unreadable(location: BlobLocation, reason: &str) -> GoBuildInfo {
    let mut info = empty(location);
    info.status = BlobStatus::Unreadable;
    info.reason = Some(reason.to_owned());
    info
}

/// A record with nothing decoded yet.
fn empty(location: BlobLocation) -> GoBuildInfo {
    GoBuildInfo {
        status: BlobStatus::Present,
        reason: None,
        location,
        layout: GoLayout::Unknown,
        pointer_size: 0,
        big_endian: false,
        go_version: None,
        modinfo: false,
        path: None,
        main: None,
        deps: Vec::new(),
        deps_truncated: false,
        settings: Vec::new(),
        settings_truncated: false,
        warnings: Vec::new(),
    }
}

/// Decodes the blob that starts with the magic. `memory` reads file-backed virtual memory, for the pointer layout.
pub fn decode<'a>(
    blob: &'a [u8],
    location: BlobLocation,
    memory: &dyn Fn(u64, u64) -> Option<&'a [u8]>,
) -> GoBuildInfo {
    let mut info = empty(location);
    let Some(header) = blob.get(..HEADER_BYTES) else {
        info.status = BlobStatus::Unreadable;
        info.reason = Some(format!("the header is cut short at {} of {HEADER_BYTES} bytes", blob.len()));
        return info;
    };
    info.pointer_size = header[14];
    let flags = header[15];
    let strings = if flags & FLAG_INLINE != 0 {
        info.layout = GoLayout::Inline;
        inline_strings(&blob[HEADER_BYTES..])
    } else {
        info.layout = GoLayout::Pointers;
        info.big_endian = flags & FLAG_BIG_ENDIAN != 0;
        pointer_strings(header, info.pointer_size, info.big_endian, memory)
    };
    let (version, modinfo) = match strings {
        Ok(strings) => strings,
        Err(reason) => {
            info.status = BlobStatus::Unreadable;
            info.reason = Some(reason);
            return info;
        }
    };
    if version.is_empty() {
        info.status = BlobStatus::Unreadable;
        info.reason = Some("the Go version string is empty".to_owned());
        return info;
    }
    if version.len() > MAX_VERSION_BYTES {
        info.status = BlobStatus::Unreadable;
        info.reason = Some(format!("the Go version string is {} bytes, over {MAX_VERSION_BYTES}", version.len()));
        return info;
    }
    info.status = BlobStatus::Present;
    info.go_version = Some(String::from_utf8_lossy(version).into_owned());
    let text = match unwrap_sentinels(modinfo) {
        Some(text) => text,
        None => {
            if !modinfo.is_empty() {
                WARNINGS.push(&mut info.warnings, "modinfo lacks its 16-byte sentinels; ignored".to_owned());
            }
            return info;
        }
    };
    info.modinfo = true;
    parse_modinfo(&String::from_utf8_lossy(text), &mut info);
    info
}

/// The go1.18+ inline version and modinfo strings.
fn inline_strings(bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let (version, rest) = varint_string(bytes, MAX_VERSION_BYTES + 1).map_err(|why| format!("version string {why}"))?;
    let (modinfo, _) = varint_string(rest, MAX_MODINFO_BYTES).map_err(|why| format!("modinfo string {why}"))?;
    Ok((version, modinfo))
}

/// A uvarint-length-prefixed string at the start of `bytes`, and what follows it.
fn varint_string(bytes: &[u8], max: usize) -> Result<(&[u8], &[u8]), &'static str> {
    let (len, used) = uvarint(bytes).ok_or("has a malformed or cut-short length")?;
    let len = usize::try_from(len).ok().filter(|&len| len <= max).ok_or("is longer than the cap")?;
    let rest = &bytes[used..];
    let text = rest.get(..len).ok_or("runs past the end of the section")?;
    Ok((text, &rest[len..]))
}

/// Go's `binary.Uvarint`: the value and the bytes it used, or `None` when cut short or over 64 bits.
fn uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate().take(10) {
        if index == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte < 0x80 {
            return Some((value, index + 1));
        }
    }
    None
}

/// The pre-1.18 version and modinfo strings, through the pointers at header offsets 16 and 16 + pointer size.
fn pointer_strings<'a>(
    header: &[u8],
    pointer_size: u8,
    big_endian: bool,
    memory: &dyn Fn(u64, u64) -> Option<&'a [u8]>,
) -> Result<(&'a [u8], &'a [u8]), String> {
    if !matches!(pointer_size, 4 | 8) {
        return Err(format!("the pointer size {pointer_size} is neither 4 nor 8"));
    }
    let width = usize::from(pointer_size);
    let pointer = |bytes: &[u8], offset: usize| read_uint(bytes, offset, width, big_endian);
    let string = |at: usize, what: &str, max: usize| -> Result<&'a [u8], String> {
        let header_address = pointer(header, at).ok_or_else(|| format!("the {what} pointer is cut short"))?;
        let string_header = memory(header_address, 2 * u64::from(pointer_size))
            .ok_or_else(|| format!("the {what} string header at {header_address:#x} is not file-backed memory"))?;
        let data = pointer(string_header, 0).unwrap_or(0);
        let len = pointer(string_header, width).unwrap_or(0);
        if len == 0 {
            return Ok(&[]);
        }
        if len > max as u64 {
            return Err(format!("the {what} string is {len} bytes, over the {max}-byte cap"));
        }
        memory(data, len).ok_or_else(|| format!("the {what} string at {data:#x} is not file-backed memory"))
    };
    let version = string(16, "version", MAX_VERSION_BYTES + 1)?;
    let modinfo = string(16 + width, "modinfo", MAX_MODINFO_BYTES)?;
    Ok((version, modinfo))
}

/// Modinfo without its sentinels, by `runtime/debug`'s rule; `None` when it has none.
fn unwrap_sentinels(modinfo: &[u8]) -> Option<&[u8]> {
    let len = modinfo.len();
    (len > 2 * SENTINEL_BYTES && modinfo[len - SENTINEL_BYTES - 1] == b'\n')
        .then(|| &modinfo[SENTINEL_BYTES..len - SENTINEL_BYTES])
}

/// Parses modinfo lines like `runtime/debug.ParseBuildInfo`, but keeps going past a bad line with a warning.
fn parse_modinfo(text: &str, info: &mut GoBuildInfo) {
    // Which module a `=>` line replaces: the main module, the last dep, or none (after a replacement).
    enum Last {
        None,
        Main,
        Dep,
    }
    let mut last = Last::None;
    let mut warnings = std::mem::take(&mut info.warnings);
    for (number, line) in text.lines().enumerate().map(|(index, line)| (index + 1, line)) {
        let mut warn = |why: String| WARNINGS.push(&mut warnings, format!("modinfo line {number}: {why}"));
        let Some((kind, rest)) = line.split_once('\t') else {
            if !line.is_empty() {
                warn("not a tab-separated record; skipped".to_owned());
            }
            continue;
        };
        match kind {
            "path" => {
                info.path = Some(field(rest, &mut warn));
                last = Last::None;
            }
            "mod" => match module(rest, &mut warn) {
                Some(module) => {
                    info.main = Some(module);
                    last = Last::Main;
                }
                None => last = Last::None,
            },
            "dep" => {
                last = Last::None;
                if info.deps.len() >= MAX_DEPS {
                    info.deps_truncated = true;
                    continue;
                }
                if let Some(module) = module(rest, &mut warn) {
                    info.deps.push(module);
                    last = Last::Dep;
                }
            }
            "=>" => {
                let target = match last {
                    Last::Main => info.main.as_mut(),
                    Last::Dep => info.deps.last_mut(),
                    Last::None => None,
                };
                match target {
                    Some(target) => target.replace = module(rest, &mut warn).map(Box::new),
                    None if !info.deps_truncated => warn("a replacement with no module before it; skipped".to_owned()),
                    None => {}
                }
                last = Last::None;
            }
            "build" => {
                if info.settings.len() >= MAX_SETTINGS {
                    info.settings_truncated = true;
                    continue;
                }
                match setting(rest) {
                    Some((key, value)) => {
                        let (key, value) = (field(&key, &mut warn), field(&value, &mut warn));
                        info.settings.push(GoSetting { key, value });
                    }
                    None => warn("a malformed build setting; skipped".to_owned()),
                }
            }
            _ => warn(format!("unknown record `{}`; skipped", clip(kind).0)),
        }
    }
    info.warnings = warnings;
}

/// A field clipped to the field cap, warning when it is cut.
fn field(text: &str, warn: &mut impl FnMut(String)) -> String {
    let (text, truncated) = clip(text);
    if truncated {
        warn(format!("a field over {} bytes was truncated", super::MAX_FIELD_BYTES));
    }
    text
}

/// A module record: path, version and an optional (possibly empty) sum.
fn module(rest: &str, warn: &mut impl FnMut(String)) -> Option<GoModule> {
    let fields: Vec<&str> = rest.splitn(4, '\t').collect();
    if !matches!(fields.len(), 2 | 3) {
        warn(format!("a module record has {} fields, not 2 or 3; skipped", fields.len()));
        return None;
    }
    let sum = fields.get(2).filter(|sum| !sum.is_empty()).map(|sum| field(sum, warn));
    Some(GoModule { path: field(fields[0], warn), version: field(fields[1], warn), sum, replace: None })
}

/// A `key=value` build setting, either side possibly a Go-quoted string.
fn setting(text: &str) -> Option<(String, String)> {
    let (key, value) = if text.starts_with('"') {
        let end = quoted_prefix(text)?;
        (unquote(&text[..end])?, text[end..].strip_prefix('=')?)
    } else {
        let (key, value) = text.split_once('=')?;
        (key.to_owned(), value)
    };
    if key.is_empty() {
        return None;
    }
    let value = if value.starts_with('"') { unquote(value)? } else { value.to_owned() };
    Some((key, value))
}

/// The length of the double-quoted Go string literal at the start of `text`.
fn quoted_prefix(text: &str) -> Option<usize> {
    let mut chars = text.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    while let Some((index, char)) = chars.next() {
        match char {
            '"' => return Some(index + 1),
            '\\' => {
                chars.next()?;
            }
            '\n' => return None,
            _ => {}
        }
    }
    None
}

/// Decodes one whole double-quoted Go string literal, as `strconv.Unquote` does; byte escapes that do not form
/// UTF-8 become U+FFFD.
fn unquote(literal: &str) -> Option<String> {
    let inner = literal.strip_prefix('"')?.strip_suffix('"')?;
    let mut bytes = Vec::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(char) = chars.next() {
        if char == '"' {
            return None;
        }
        if char != '\\' {
            let mut buffer = [0; 4];
            bytes.extend_from_slice(char.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        let escape = chars.next()?;
        let simple = match escape {
            'a' => Some(0x07),
            'b' => Some(0x08),
            'f' => Some(0x0c),
            'n' => Some(b'\n'),
            'r' => Some(b'\r'),
            't' => Some(b'\t'),
            'v' => Some(0x0b),
            '\\' => Some(b'\\'),
            '"' => Some(b'"'),
            '\'' => Some(b'\''),
            _ => None,
        };
        if let Some(byte) = simple {
            bytes.push(byte);
            continue;
        }
        let mut digits = |count: usize, radix: u32| -> Option<u32> {
            let text: String = chars.by_ref().take(count).collect();
            (text.len() == count).then(|| u32::from_str_radix(&text, radix).ok()).flatten()
        };
        match escape {
            'x' => bytes.push(u8::try_from(digits(2, 16)?).ok()?),
            '0'..='7' => {
                let rest = digits(2, 8)?;
                bytes.push(u8::try_from(escape.to_digit(8)? * 64 + rest).ok()?);
            }
            'u' | 'U' => {
                let char = char::from_u32(digits(if escape == 'u' { 4 } else { 8 }, 16)?)?;
                let mut buffer = [0; 4];
                bytes.extend_from_slice(char.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The pclntab layout a toolchain version writes, for cross-checking the two records; `None` when the version
/// is not a `go1.N` release (a devel build, or something else).
pub fn expected_table(version: &str) -> Option<GoTableVersion> {
    let rest = version.strip_prefix("go1.")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let minor: u32 = digits.parse().ok()?;
    Some(match minor {
        2..=15 => GoTableVersion::Go12,
        16 | 17 => GoTableVersion::Go116,
        18 | 19 => GoTableVersion::Go118,
        20.. => GoTableVersion::Go120,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: &[u8; 16] = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6";
    const END: &[u8; 16] = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2";

    fn location() -> BlobLocation {
        BlobLocation { section: ".go.buildinfo".to_owned(), address: 0x1000 }
    }

    fn no_memory<'a>() -> impl Fn(u64, u64) -> Option<&'a [u8]> {
        |_, _| None
    }

    fn wrapped(modinfo: &str) -> Vec<u8> {
        [START.as_slice(), modinfo.as_bytes(), END.as_slice()].concat()
    }

    fn varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn inline_blob(version: &str, modinfo: &[u8]) -> Vec<u8> {
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&[8, FLAG_INLINE]);
        blob.resize(HEADER_BYTES, 0);
        varint(version.len(), &mut blob);
        blob.extend_from_slice(version.as_bytes());
        varint(modinfo.len(), &mut blob);
        blob.extend_from_slice(modinfo);
        blob
    }

    const MODINFO: &str = "path\texample.com/cmd/tool\n\
        mod\texample.com\tv1.2.3\th1:main=\n\
        dep\tgolang.org/x/sys\tv0.1.0\th1:sys=\n\
        dep\texample.com/old\tv1.0.0\th1:old=\n\
        =>\texample.com/new\tv2.0.0\th1:new=\n\
        dep\texample.com/local\tv0.0.0\n\
        =>\t../local\t\t\n\
        build\t-compiler=gc\n\
        build\tCGO_ENABLED=1\n\
        build\t\"-ldflags=x\"=\"-s -w \\\"q\\\"\"\n\
        build\tvcs.revision=0123abcd\n\
        build\tvcs.time=2024-01-02T03:04:05Z\n";

    #[test]
    fn inline_layout_decodes_every_record_kind() {
        let blob = inline_blob("go1.22.4", &wrapped(MODINFO));
        let info = decode(&blob, location(), &no_memory());
        assert_eq!(info.status, BlobStatus::Present, "{info:?}");
        assert_eq!(info.layout, GoLayout::Inline);
        assert_eq!(info.go_version.as_deref(), Some("go1.22.4"));
        assert!(info.modinfo);
        assert_eq!(info.path.as_deref(), Some("example.com/cmd/tool"));
        let main = info.main.as_ref().unwrap();
        assert_eq!(
            (main.path.as_str(), main.version.as_str(), main.sum.as_deref()),
            ("example.com", "v1.2.3", Some("h1:main="))
        );
        assert_eq!(info.deps.len(), 3);
        assert_eq!(info.deps[0].replace, None);
        let replaced = info.deps[1].replace.as_ref().unwrap();
        assert_eq!((replaced.path.as_str(), replaced.version.as_str()), ("example.com/new", "v2.0.0"));
        let local = info.deps[2].replace.as_ref().unwrap();
        assert_eq!((local.path.as_str(), local.version.as_str(), local.sum.as_deref()), ("../local", "", None));
        let settings: Vec<(&str, &str)> =
            info.settings.iter().map(|setting| (setting.key.as_str(), setting.value.as_str())).collect();
        assert_eq!(
            settings,
            [
                ("-compiler", "gc"),
                ("CGO_ENABLED", "1"),
                ("-ldflags=x", "-s -w \"q\""),
                ("vcs.revision", "0123abcd"),
                ("vcs.time", "2024-01-02T03:04:05Z"),
            ]
        );
        assert!(info.warnings.is_empty(), "{:?}", info.warnings);
    }

    #[test]
    fn pointer_layout_reads_string_headers_through_memory() {
        // Header pointers at 0x2000 (version) and 0x2010 (modinfo), big-endian, 8-byte pointers.
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&[8, FLAG_BIG_ENDIAN]);
        blob.extend_from_slice(&0x2000u64.to_be_bytes());
        blob.extend_from_slice(&0x2010u64.to_be_bytes());
        let modinfo = wrapped("path\tcmd\nmod\tcmd\t(devel)\t\n");
        let mut memory = vec![0u8; 0x100];
        memory[..8].copy_from_slice(&0x2040u64.to_be_bytes());
        memory[8..16].copy_from_slice(&9u64.to_be_bytes());
        memory[16..24].copy_from_slice(&0x2060u64.to_be_bytes());
        memory[24..32].copy_from_slice(&(modinfo.len() as u64).to_be_bytes());
        memory[0x40..0x49].copy_from_slice(b"go1.16.15");
        memory[0x60..0x60 + modinfo.len()].copy_from_slice(&modinfo);
        let read = |address: u64, len: u64| {
            let start = usize::try_from(address.checked_sub(0x2000)?).ok()?;
            memory.get(start..start + usize::try_from(len).ok()?)
        };
        let info = decode(&blob, location(), &read);
        assert_eq!(info.status, BlobStatus::Present, "{info:?}");
        assert_eq!((info.layout, info.big_endian, info.pointer_size), (GoLayout::Pointers, true, 8));
        assert_eq!(info.go_version.as_deref(), Some("go1.16.15"));
        assert_eq!(info.main.as_ref().unwrap().sum, None);

        let info = decode(&blob, location(), &no_memory());
        assert_eq!(info.status, BlobStatus::Unreadable);
        assert!(info.reason.unwrap().contains("not file-backed"));
    }

    #[test]
    fn hostile_headers_are_unreadable_never_panics() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (MAGIC.to_vec(), "cut short"),
            (inline_blob("", b""), "empty"),
            ([&inline_blob("go1.22", b"")[..HEADER_BYTES], &[0xff; 11]].concat(), "malformed"),
            ([&inline_blob("go1.22", b"")[..HEADER_BYTES], &[0x10, b'g']].concat(), "past the end"),
            ([MAGIC.as_slice(), &[3, 0], &[0; 16]].concat(), "neither 4 nor 8"),
        ];
        for (blob, reason) in cases {
            let info = decode(&blob, location(), &no_memory());
            assert_eq!(info.status, BlobStatus::Unreadable);
            assert!(info.reason.as_deref().unwrap().contains(reason), "{reason}: {:?}", info.reason);
        }
        let full = inline_blob("go1.22.4", &wrapped(MODINFO));
        for length in 0..full.len() {
            let _ = decode(&full[..length], location(), &no_memory());
        }
    }

    #[test]
    fn modinfo_without_sentinels_or_with_bad_lines_degrades_with_warnings() {
        let info = decode(&inline_blob("go1.22", b"path\tx\n"), location(), &no_memory());
        assert_eq!(info.status, BlobStatus::Present);
        assert!(!info.modinfo);
        assert_eq!(info.warnings.len(), 1);

        let info = decode(&inline_blob("go1.22", &[]), location(), &no_memory());
        assert!(info.warnings.is_empty() && !info.modinfo);

        let bad = "=>\torphan\tv1\t\nmod\tonly-path\njunk\nweird\tx\nbuild\tnoequals\nbuild\t\"open=1\ndep\ta\tv1\n";
        let info = decode(&inline_blob("go1.22", &wrapped(bad)), location(), &no_memory());
        assert_eq!(info.status, BlobStatus::Present);
        assert_eq!(info.main, None);
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.warnings.len(), 6, "{:?}", info.warnings);
    }

    #[test]
    fn deps_and_settings_are_capped() {
        let mut text = String::new();
        for index in 0..=MAX_DEPS {
            text.push_str(&format!("dep\tm{index}\tv1\n"));
        }
        for index in 0..=MAX_SETTINGS {
            text.push_str(&format!("build\tk{index}=v\n"));
        }
        let info = decode(&inline_blob("go1.22", &wrapped(&text)), location(), &no_memory());
        assert_eq!((info.deps.len(), info.deps_truncated), (MAX_DEPS, true));
        assert_eq!((info.settings.len(), info.settings_truncated), (MAX_SETTINGS, true));
    }

    #[test]
    fn magic_is_found_only_at_aligned_addresses() {
        let mut bytes = vec![0u8; 64];
        bytes[8..22].copy_from_slice(MAGIC);
        assert_eq!(find_magic(&bytes, 0x1000), None);
        assert_eq!(find_magic(&bytes, 0x1008), Some(8));
        bytes[48..62].copy_from_slice(MAGIC);
        assert_eq!(find_magic(&bytes, 0x1000), Some(48));
        assert_eq!(find_magic(&bytes[..60], 0x1000), None);
    }

    #[test]
    fn quoted_settings_follow_go_unquoting() {
        assert_eq!(unquote(r#""a\tb\x41\101é\U0001F600\\""#).as_deref(), Some("a\tbAAé😀\\"));
        assert_eq!(unquote(r#""bad\q""#), None);
        assert_eq!(unquote(r#""x"y""#), None);
        assert_eq!(setting("\"k=1\"=v"), Some(("k=1".to_owned(), "v".to_owned())));
        assert_eq!(setting("=v"), None);
    }

    #[test]
    fn toolchain_versions_map_to_pclntab_layouts() {
        assert_eq!(expected_table("go1.15.15"), Some(GoTableVersion::Go12));
        assert_eq!(expected_table("go1.17"), Some(GoTableVersion::Go116));
        assert_eq!(expected_table("go1.18rc1"), Some(GoTableVersion::Go118));
        assert_eq!(expected_table("go1.27.3"), Some(GoTableVersion::Go120));
        assert_eq!(expected_table("devel go1.23-abc"), None);
        assert_eq!(expected_table("go2.0"), None);
    }
}
