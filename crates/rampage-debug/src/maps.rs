//! Loaded modules and memory regions as stubs report them: `qXfer:libraries-svr4:read`, `qXfer:libraries:read`,
//! `qXfer:memory-map:read` and `qOffsets`.

use serde::Serialize;

use crate::packet::parse_hex_u64;
use crate::stop::hex_address;
use crate::xml;

/// Most modules or regions kept from one list.
pub const MAX_ENTRIES: usize = 4096;

fn optional_hex<S: serde::Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.collect_str(&format_args!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

fn hex_list<S: serde::Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| format!("{value:#x}")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Module {
    /// The path the stub reports.
    pub name: String,
    /// `libraries-svr4` (a `link_map` entry) or `libraries` (segment or section addresses).
    pub source: &'static str,
    /// svr4: the module's load bias (`l_addr`), the difference between runtime and link-time addresses.
    #[serde(serialize_with = "optional_hex")]
    pub l_addr: Option<u64>,
    /// svr4: the runtime address of the module's dynamic section.
    #[serde(serialize_with = "optional_hex")]
    pub l_ld: Option<u64>,
    /// svr4: the address of the module's `link_map` entry.
    #[serde(serialize_with = "optional_hex")]
    pub lm: Option<u64>,
    /// libraries: the load addresses of the module's segments, or of its sections.
    #[serde(serialize_with = "hex_list")]
    pub segments: Vec<u64>,
    #[serde(serialize_with = "hex_list")]
    pub sections: Vec<u64>,
    /// The GNU build ID, read from the module's ELF note in target memory when its header is mapped at `l_addr`.
    pub build_id: Option<String>,
    /// Whether this is the main program's entry (`main-lm`), or for dyld images the `MH_EXECUTE` image.
    pub main: bool,
    /// dyld (`jGetLoadedDynamicLibrariesInfos`): the Mach-O image's header address, UUID, segments and whether it
    /// lives in the dyld shared cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dyld: Option<crate::lldb::DyldImage>,
    /// Windows stubs: the PE image read from target memory at the base the stub's address gives (gdbserver's
    /// `<segment>` minus 0x1000, lldb-server's `<section>` as is), with its CodeView record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<crate::pe::PeImage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Region {
    #[serde(serialize_with = "hex_address")]
    pub start: u64,
    pub length: u64,
    /// `ram`, `rom` or `flash` from a memory map; `mapped` from LLDB's `qMemoryRegionInfo`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Flash erase block size, from the region's `blocksize` property.
    pub flash_block_size: Option<u64>,
    /// `qMemoryRegionInfo`: the region's permissions (`r`, `w`, `x`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    /// `qMemoryRegionInfo`: the region's name, when the stub gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

fn address(text: Option<&str>, what: &str) -> Result<u64, String> {
    text.and_then(parse_hex_u64).ok_or_else(|| format!("{what} is missing or not a hex address"))
}

/// At most 4096 bytes of `text`, cut at a character boundary.
fn path(text: &str) -> String {
    let mut end = text.len().min(4096);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Parses a `<library-list-svr4>` document.
pub fn parse_svr4(text: &str) -> Result<Vec<Module>, String> {
    let root = xml::parse(text)?;
    if root.name != "library-list-svr4" {
        return Err(format!("unexpected <{}> in place of <library-list-svr4>", root.name));
    }
    let main = root.attribute("main-lm").map(|lm| address(Some(lm), "main-lm")).transpose()?;
    let mut modules = Vec::new();
    for library in root.children_named("library").take(MAX_ENTRIES) {
        let lm = address(library.attribute("lm"), "library lm")?;
        modules.push(Module {
            name: path(library.attribute("name").unwrap_or("")),
            source: "libraries-svr4",
            l_addr: Some(address(library.attribute("l_addr"), "library l_addr")?),
            l_ld: Some(address(library.attribute("l_ld"), "library l_ld")?),
            lm: Some(lm),
            segments: Vec::new(),
            sections: Vec::new(),
            build_id: None,
            main: main == Some(lm),
            dyld: None,
            pe: None,
        });
    }
    Ok(modules)
}

/// Parses a `<library-list>` document (Windows-style and other stubs).
pub fn parse_libraries(text: &str) -> Result<Vec<Module>, String> {
    let root = xml::parse(text)?;
    if root.name != "library-list" {
        return Err(format!("unexpected <{}> in place of <library-list>", root.name));
    }
    let mut modules = Vec::new();
    for library in root.children_named("library").take(MAX_ENTRIES) {
        let addresses = |kind: &str| {
            library
                .children_named(kind)
                .take(MAX_ENTRIES)
                .map(|child| address(child.attribute("address"), kind))
                .collect::<Result<Vec<_>, _>>()
        };
        let segments = addresses("segment")?;
        let sections = addresses("section")?;
        if !segments.is_empty() && !sections.is_empty() {
            return Err("library mixes segments and sections".into());
        }
        modules.push(Module {
            name: path(library.attribute("name").unwrap_or("")),
            source: "libraries",
            l_addr: None,
            l_ld: None,
            lm: None,
            segments,
            sections,
            build_id: None,
            main: false,
            dyld: None,
            pe: None,
        });
    }
    Ok(modules)
}

/// Parses a `<memory-map>` document.
pub fn parse_memory_map(text: &str) -> Result<Vec<Region>, String> {
    let root = xml::parse(text)?;
    if root.name != "memory-map" {
        return Err(format!("unexpected <{}> in place of <memory-map>", root.name));
    }
    let mut regions = Vec::new();
    for memory in root.children_named("memory").take(MAX_ENTRIES) {
        let kind = memory.attribute("type").unwrap_or("");
        if !matches!(kind, "ram" | "rom" | "flash") {
            return Err(format!("memory region has unknown type `{}`", kind.chars().take(16).collect::<String>()));
        }
        let start = address(memory.attribute("start"), "memory start")?;
        let length = address(memory.attribute("length"), "memory length")?;
        if length == 0 || start.checked_add(length - 1).is_none() {
            return Err("memory region is empty or overflows the address space".into());
        }
        let flash_block_size = memory
            .children_named("property")
            .find(|property| property.attribute("name") == Some("blocksize"))
            .map(|property| address(Some(property.text.trim()), "flash blocksize"))
            .transpose()?;
        regions.push(Region { start, length, kind: kind.to_owned(), flash_block_size, permissions: None, name: None });
    }
    regions.sort_by_key(|region| region.start);
    if regions.windows(2).any(|pair| pair[0].start + (pair[0].length - 1) >= pair[1].start) {
        return Err("memory map regions overlap".into());
    }
    Ok(regions)
}

/// The section or segment offsets `qOffsets` reports, relative to the program's link-time addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offsets {
    /// `section` (`Text=`, `Data=`, `Bss=`) or `segment` (`TextSeg=`, `DataSeg=`).
    pub kind: &'static str,
    #[serde(serialize_with = "hex_address")]
    pub text: u64,
    #[serde(serialize_with = "hex_address")]
    pub data: u64,
    #[serde(serialize_with = "optional_hex")]
    pub bss: Option<u64>,
}

pub fn parse_offsets(reply: &str) -> Result<Offsets, String> {
    let mut fields = std::collections::BTreeMap::new();
    for field in reply.split(';') {
        let (name, value) = field.split_once('=').ok_or("malformed qOffsets reply")?;
        let value = parse_hex_u64(value).ok_or("malformed qOffsets value")?;
        if fields.insert(name, value).is_some() {
            return Err("duplicate qOffsets field".into());
        }
    }
    let field = |name| fields.get(name).copied();
    match (field("Text"), field("Data"), field("TextSeg")) {
        (Some(text), Some(data), None) if fields.len() <= 3 => {
            let bss = field("Bss");
            if fields.len() == 3 && bss.is_none() {
                return Err("unknown qOffsets field".into());
            }
            Ok(Offsets { kind: "section", text, data, bss })
        }
        (None, None, Some(text)) if fields.len() <= 2 => {
            let data = field("DataSeg").unwrap_or(text);
            if fields.len() == 2 && field("DataSeg").is_none() {
                return Err("unknown qOffsets field".into());
            }
            Ok(Offsets { kind: "segment", text, data, bss: None })
        }
        _ => Err("malformed qOffsets reply".into()),
    }
}

/// Where an ELF image's build-ID note lies, from its header and program headers (read from target memory).
pub struct ElfHeader {
    pub little: bool,
    pub wide: bool,
    pub phoff: u64,
    pub phentsize: u64,
    pub phnum: u64,
}

pub fn elf_header(bytes: &[u8]) -> Option<ElfHeader> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    let wide = match bytes[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match bytes[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let read = |at: usize, size: usize| read_uint(&bytes[at..at + size], little);
    let (phoff, phentsize, phnum) =
        if wide { (read(32, 8), read(54, 2), read(56, 2)) } else { (read(28, 4), read(42, 2), read(44, 2)) };
    let minimum = if wide { 56 } else { 32 };
    (phentsize >= minimum && phnum > 0 && phnum <= 64).then_some(ElfHeader { little, wide, phoff, phentsize, phnum })
}

/// The `(offset_in_image, size)` of each `PT_NOTE` segment in `headers`, which hold `phnum` program headers.
pub fn note_segments(header: &ElfHeader, headers: &[u8]) -> Vec<(u64, u64)> {
    let mut notes = Vec::new();
    for index in 0..header.phnum as usize {
        let start = index * header.phentsize as usize;
        let Some(entry) = headers.get(start..start + header.phentsize as usize) else { break };
        let read = |at: usize, size: usize| read_uint(&entry[at..at + size], header.little);
        if read(0, 4) != 4 {
            continue;
        }
        let (vaddr, size) = if header.wide { (read(16, 8), read(32, 8)) } else { (read(8, 4), read(16, 4)) };
        notes.push((vaddr, size));
    }
    notes
}

/// The `NT_GNU_BUILD_ID` descriptor in a note segment's bytes, as hex.
pub fn build_id(notes: &[u8], little: bool) -> Option<String> {
    let mut at = 0usize;
    while at + 12 <= notes.len() {
        let read = |offset: usize| read_uint(&notes[at + offset..at + offset + 4], little) as usize;
        let (name_size, desc_size, kind) = (read(0), read(4), read(8));
        let name_start = at + 12;
        let desc_start = name_start.checked_add(name_size.checked_next_multiple_of(4)?)?;
        let desc_end = desc_start.checked_add(desc_size)?;
        if desc_end > notes.len() {
            return None;
        }
        if kind == 3 && &notes[name_start..name_start + name_size] == b"GNU\0" && (1..=64).contains(&desc_size) {
            return Some(crate::packet::encode_hex(&notes[desc_start..desc_end]));
        }
        at = desc_start.checked_add(desc_size.checked_next_multiple_of(4)?)?;
    }
    None
}

pub(crate) fn read_uint(bytes: &[u8], little: bool) -> u64 {
    let fold = |value: u64, byte: &u8| value << 8 | u64::from(*byte);
    if little { bytes.iter().rev().fold(0, fold) } else { bytes.iter().fold(0, fold) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_svr4_library_lists() {
        let modules = parse_svr4(
            "<library-list-svr4 version=\"1.0\" main-lm=\"0x7ffff7ffe190\">\
             <library name=\"\" lm=\"0x7ffff7ffe190\" l_addr=\"0x555555554000\" l_ld=\"0x555555557df8\" lmid=\"0x0\"/>\
             <library name=\"/lib/aarch64-linux-gnu/libc.so.6\" lm=\"0x7ffff7fc2000\" l_addr=\"0x7ffff7e00000\" \
             l_ld=\"0x7ffff7fa8d90\" lmid=\"0x0\"/></library-list-svr4>",
        )
        .unwrap();
        assert_eq!(modules.len(), 2);
        assert!(modules[0].main);
        assert_eq!(modules[1].l_addr, Some(0x7ffff7e00000));
        assert!(parse_svr4("<library-list-svr4><library name=\"x\" lm=\"zz\"/></library-list-svr4>").is_err());
        assert!(parse_svr4("<library-list/>").is_err());
    }

    #[test]
    fn parses_windows_style_library_lists() {
        let modules = parse_libraries(
            "<library-list><library name=\"C:\\a.dll\"><segment address=\"0x10000000\"/></library>\
             <library name=\"b\"><section address=\"0x2000\"/><section address=\"0x3000\"/></library></library-list>",
        )
        .unwrap();
        assert_eq!(modules[0].segments, vec![0x10000000]);
        assert_eq!(modules[1].sections, vec![0x2000, 0x3000]);
        assert!(
            parse_libraries("<library-list><library name=\"x\"><segment address=\"1\"/><section address=\"2\"/></library></library-list>")
                .is_err()
        );
    }

    #[test]
    fn parses_memory_maps() {
        let regions = parse_memory_map(
            "<?xml version=\"1.0\"?><!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\" \
             \"http://sourceware.org/gdb/gdb-memory-map.dtd\"><memory-map>\
             <memory type=\"ram\" start=\"0x20000000\" length=\"0x10000\"/>\
             <memory type=\"flash\" start=\"0x0\" length=\"0x40000\"><property name=\"blocksize\">0x400</property></memory>\
             </memory-map>",
        )
        .unwrap();
        assert_eq!(regions[0].kind, "flash");
        assert_eq!(regions[0].flash_block_size, Some(0x400));
        assert_eq!(regions[1].start, 0x20000000);
        for text in [
            "<memory-map><memory type=\"io\" start=\"0\" length=\"1\"/></memory-map>",
            "<memory-map><memory type=\"ram\" start=\"0\" length=\"0\"/></memory-map>",
            "<memory-map><memory type=\"ram\" start=\"0xffffffffffffffff\" length=\"2\"/></memory-map>",
            "<memory-map><memory type=\"ram\" start=\"0\" length=\"10\"/><memory type=\"ram\" start=\"8\" length=\"10\"/></memory-map>",
        ] {
            assert!(parse_memory_map(text).is_err(), "{text}");
        }
    }

    #[test]
    fn parses_offsets() {
        assert_eq!(
            parse_offsets("Text=1000;Data=2000;Bss=2000").unwrap(),
            Offsets { kind: "section", text: 0x1000, data: 0x2000, bss: Some(0x2000) }
        );
        assert_eq!(
            parse_offsets("TextSeg=8000").unwrap(),
            Offsets { kind: "segment", text: 0x8000, data: 0x8000, bss: None }
        );
        for reply in ["", "Text=1", "Text=1;Data=2;Bogus=3", "Text=zz;Data=1", "TextSeg=1;Bogus=2", "Text=1;Text=1"] {
            assert!(parse_offsets(reply).is_err(), "{reply}");
        }
    }

    #[test]
    fn finds_gnu_build_ids_in_notes() {
        let mut notes = Vec::new();
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&1u32.to_le_bytes());
        notes.extend_from_slice(b"GNU\0\x01\x02\x03\x04");
        notes.extend_from_slice(&4u32.to_le_bytes());
        notes.extend_from_slice(&3u32.to_le_bytes());
        notes.extend_from_slice(&3u32.to_le_bytes());
        notes.extend_from_slice(b"GNU\0\xaa\xbb\xcc\0");
        assert_eq!(build_id(&notes, true).as_deref(), Some("aabbcc"));
        assert_eq!(build_id(&notes[..30], true), None);
        let mut rng = crate::packet::tests::Rng::new(6);
        for _ in 0..2000 {
            let length = rng.below(80);
            let _ = build_id(&rng.bytes(length), rng.below(2) == 0);
            let header = rng.bytes(64);
            let _ = elf_header(&header);
        }
    }
}
