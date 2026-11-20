//! `list_dir`: one directory's entries (name, kind, size and a format sniff), paged by name, so an agent given only
//! a folder can find the files to open. Symlinks are listed, never followed; nothing is opened as a project.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Entries one call reads from a directory; past it the listing covers those read and says so.
pub const MAX_DIR_ENTRIES: usize = 1_000_000;
pub const MAX_LIST_DIR_PAGE: usize = 500;
const DEFAULT_LIST_DIR_PAGE: usize = 100;
/// Bytes read from each regular file for the format sniff.
const SNIFF_BYTES: usize = 1024 + 64;

#[derive(Debug, Clone)]
pub struct ListDirQuery {
    pub path: PathBuf,
    /// The name to resume at, as a previous page's `next_cursor` gives it.
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DirEntry {
    /// The entry's name: UTF-8 as is, a backslash doubled, any other byte as `\xHH`.
    pub name: String,
    /// `file`, `dir`, `symlink` or `other` (device, socket, FIFO), from the entry itself; links are not followed.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Regular files only: what the first bytes say (see [`sniff`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Symlinks only: the target as stored, not resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DirListing {
    pub path: PathBuf,
    /// Entries in the directory (those read, when `truncated`).
    pub total: usize,
    pub entries: Vec<DirEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Present when the directory held more than [`MAX_DIR_ENTRIES`] entries, saying what was listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
    pub next: &'static str,
}

/// Whether `cursor` is a name as [`escape`] writes it: every backslash starts `\\` or `\xHH`.
fn check_cursor(cursor: &str) -> Result<(), String> {
    let bytes = cursor.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            match bytes.get(index + 1) {
                Some(b'\\') => index += 2,
                Some(b'x')
                    if bytes.get(index + 2..index + 4).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) =>
                {
                    index += 4
                }
                _ => return Err("cursor is not a name list_dir returned; pass a previous page's next_cursor".into()),
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

/// A name's raw bytes as text: UTF-8 as is, a backslash doubled, any other byte as `\xHH`, so distinct names never
/// share a text form. Entries are sorted by this text, and the cursor compares against it, so paging is monotonic
/// (the text order is not the raw byte order: `\xff` sorts with the backslash).
fn escape(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for character in chunk.valid().chars() {
            if character == '\\' {
                text.push_str("\\\\");
            } else {
                text.push(character);
            }
        }
        for byte in chunk.invalid() {
            text.push_str(&format!("\\x{byte:02x}"));
        }
    }
    text
}

#[cfg(unix)]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

/// The format the first bytes of a file show: an executable (`elf`, `pe`, `macho`, `macho_universal`, `dex`,
/// `wasm`), a filesystem image (`squashfs`, `ext`, `cpio`, `tar`, ...), an archive or compressed stream (`ar`, `zip`,
/// `gzip`, `xz`, `zstd`, `bzip2`, `lz4_frame`, `7z`), Intel HEX or S-records (`ihex`, `srec`), an ESP32/ESP8266 app
/// image (`esp_image`), `text`, or `unknown`.
fn sniff(head: &[u8]) -> &'static str {
    if let Some(format) = rampage_unpack::executable_format(head) {
        return format;
    }
    if rampage_loaders::esp::looks_like_app_image(head, 0) {
        return "esp_image";
    }
    if let Some(format) = rampage_unpack::detect_bytes(head) {
        return format.name();
    }
    let archive = [
        (&b"!<arch>\n"[..], "ar"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"\x1f\x8b", "gzip"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"BZh", "bzip2"),
        (b"\x04\x22\x4d\x18", "lz4_frame"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
    ];
    if let Some((_, name)) = archive.iter().find(|(magic, _)| head.starts_with(magic)) {
        return name;
    }
    // Records are ASCII lines: `:` or `S0`..`S9`, then hex digits.
    let hex = |tail: &[u8]| tail.len() >= 8 && tail[..8].iter().all(u8::is_ascii_hexdigit);
    match head {
        [b':', tail @ ..] if hex(tail) => return "ihex",
        [b'S', digit, tail @ ..] if digit.is_ascii_digit() && hex(tail) => return "srec",
        _ => {}
    }
    if !head.is_empty() && head.iter().all(|&byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e)) {
        return "text";
    }
    "unknown"
}

/// An ESP32 flash dump starts erased (0xff) up to its bootloader image at 0x1000; it is `esp_flash` when that image
/// or a partition table at 0x8000 is there.
fn sniff_flash(path: &Path, head: &[u8]) -> Option<&'static str> {
    use std::io::{Seek, SeekFrom};
    if head.len() < SNIFF_BYTES || head.iter().any(|&byte| byte != 0xff) {
        return None;
    }
    let mut file = open_listed(path)?;
    let mut read_at = |offset: u64, length: usize| {
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut bytes = Vec::with_capacity(length);
        (&mut file).take(length as u64).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    };
    let bootloader = read_at(0x1000, 32).is_some_and(|bytes| rampage_loaders::esp::looks_like_app_image(&bytes, 0));
    let table =
        read_at(0x8000, 0xc00).is_some_and(|bytes| rampage_loaders::esp::parse_partition_table(&bytes, 0).is_some());
    (bootloader || table).then_some("esp_flash")
}

/// Opens the regular file at `path` for reading without following a symlink put in its place, and without blocking
/// on a FIFO swapped in since it was listed.
fn open_listed(path: &Path) -> Option<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32);
    }
    let file = options.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// Reads the first bytes of the regular file at `path` without following a symlink put in its place, and without
/// blocking on a FIFO swapped in since it was listed.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    let file = open_listed(path)?;
    let mut head = Vec::with_capacity(SNIFF_BYTES);
    file.take(SNIFF_BYTES as u64).read_to_end(&mut head).ok()?;
    Some(head)
}

/// Lists the directory at `query.path` (not through a final symlink), sorted by name, one page at a time.
pub fn list_dir(query: &ListDirQuery) -> Result<DirListing, String> {
    let limit = query.limit.unwrap_or(DEFAULT_LIST_DIR_PAGE);
    if !(1..=MAX_LIST_DIR_PAGE).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_LIST_DIR_PAGE}"));
    }
    let shown = query.path.display();
    let metadata = std::fs::symlink_metadata(&query.path).map_err(|error| format!("{shown}: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{shown} is a symlink; list the directory it names by its own path"));
    }
    if !metadata.is_dir() {
        return Err(format!("{shown} is not a directory; open it by path with binary_info or file_layout"));
    }
    if let Some(cursor) = &query.cursor {
        check_cursor(cursor)?;
    }
    // Only the page and the entry after it are kept: the smallest keys at or after the cursor, so a directory of
    // any size pages in memory bounded by the page size.
    let mut total = 0;
    let mut truncated = false;
    let mut kept: std::collections::BinaryHeap<(String, std::ffi::OsString)> = std::collections::BinaryHeap::new();
    for entry in std::fs::read_dir(&query.path).map_err(|error| format!("{shown}: {error}"))? {
        let entry = entry.map_err(|error| format!("{shown}: {error}"))?;
        if total == MAX_DIR_ENTRIES {
            truncated = true;
            break;
        }
        total += 1;
        let name = entry.file_name();
        let key = escape(&name_bytes(&name));
        if query.cursor.as_ref().is_some_and(|cursor| key.as_str() < cursor.as_str()) {
            continue;
        }
        kept.push((key, name));
        if kept.len() > limit + 1 {
            kept.pop();
        }
    }
    let mut names = kept.into_sorted_vec();
    let next_cursor = (names.len() > limit).then(|| names.remove(limit).0);
    names.truncate(limit);
    let entries = names
        .iter()
        .map(|(key, name)| {
            let path = query.path.join(name);
            let metadata = std::fs::symlink_metadata(&path).ok();
            let file_type = metadata.as_ref().map(std::fs::Metadata::file_type);
            let kind = match file_type {
                Some(kind) if kind.is_symlink() => "symlink",
                Some(kind) if kind.is_dir() => "dir",
                Some(kind) if kind.is_file() => "file",
                _ => "other",
            };
            let size = metadata.as_ref().filter(|metadata| metadata.is_file()).map(std::fs::Metadata::len);
            let format = (kind == "file").then(|| {
                read_head(&path).map_or("unreadable", |head| sniff_flash(&path, &head).unwrap_or_else(|| sniff(&head)))
            });
            let link = (kind == "symlink")
                .then(|| std::fs::read_link(&path).ok())
                .flatten()
                .map(|target| escape(&name_bytes(target.as_os_str())));
            DirEntry { name: key.clone(), kind, size, format, link }
        })
        .collect();
    Ok(DirListing {
        path: query.path.clone(),
        total,
        entries,
        next_cursor,
        truncated: truncated.then(|| {
            format!(
                "the directory holds more than {MAX_DIR_ENTRIES} entries: only the first {MAX_DIR_ENTRIES} read (in \
                 directory order) were listed and counted; list a subdirectory or narrow the tree"
            )
        }),
        next: "Open an executable by its path with binary_info or triage_report; a headerless image with \
               file_layout; a filesystem image (squashfs, ext, cpio, tar) or a ZIP with fs_list; an APK, AAB, JAR \
               or DEX with dex_metadata (group `android`); an esp_image or esp_flash with binary_info, which names \
               its `raw` selector.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_escape_without_collisions_and_sniffs_name_formats() {
        assert_eq!(escape(b"a\\b\xff"), "a\\\\b\\xff");
        assert_ne!(escape(b"\\xff"), escape(b"\xff"));

        assert_eq!(sniff(b"\x7fELF\x02\x01"), "elf");
        assert_eq!(sniff(b"!<arch>\nfoo"), "ar");
        assert_eq!(sniff(b"\x1f\x8b\x08"), "gzip");
        assert_eq!(sniff(b"hello\n"), "text");
        assert_eq!(sniff(b"\x00\x01\x02"), "unknown");
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/xtensa");
        assert_eq!(sniff(&read_head(&fixtures.join("esp32-app.bin")).unwrap()), "esp_image");
        let flash = fixtures.join("esp32-flash.bin");
        assert_eq!(sniff_flash(&flash, &read_head(&flash).unwrap()), Some("esp_flash"));
    }

    /// Sorting by the escaped key and partitioning on it at the next key always advances, even where the key order
    /// differs from the byte order (0xff escapes to a backslash-led text).
    #[test]
    fn pages_by_escaped_key_always_advance() {
        let mut keys: Vec<String> = [&b"a"[..], b"b", b"\xff", b"\\"].iter().map(|name| escape(name)).collect();
        keys.sort();
        assert_eq!(keys, ["\\\\", "\\xff", "a", "b"]);
        let mut seen = Vec::new();
        let mut cursor: Option<&str> = None;
        loop {
            let start = cursor.map_or(0, |cursor| keys.partition_point(|key| key.as_str() < cursor));
            let page = &keys[start..keys.len().min(start + 1)];
            seen.extend(page.iter().cloned());
            match keys.get(start + 1) {
                Some(next) => cursor = Some(next),
                None => break,
            }
            assert!(seen.len() <= keys.len(), "paging loops: {seen:?}");
        }
        assert_eq!(seen, keys);
        for cursor in &keys {
            check_cursor(cursor).unwrap();
        }
        for malformed in ["\\", "\\q", "a\\x4", "\\xzz"] {
            assert!(check_cursor(malformed).is_err(), "{malformed}");
        }
    }
}
