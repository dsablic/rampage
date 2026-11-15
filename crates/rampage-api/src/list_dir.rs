//! `list_dir`: one directory's entries (name, kind, size and a format sniff), paged by name, so an agent given only
//! a folder can find the files to open. Symlinks are listed, never followed; nothing is opened as a project.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Entries one call reads from a directory before refusing to list it whole.
pub const MAX_DIR_ENTRIES: usize = 100_000;
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
    /// Entries in the directory.
    pub total: usize,
    pub entries: Vec<DirEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub next: &'static str,
}

/// A name's raw bytes as text: UTF-8 as is, a backslash doubled, any other byte as `\xHH`, so distinct names never
/// share a text form and the order of texts is the order of names for the cursor.
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
/// `gzip`, `xz`, `zstd`, `bzip2`, `lz4_frame`, `7z`), Intel HEX or S-records (`ihex`, `srec`), `text`, or `unknown`.
fn sniff(head: &[u8]) -> &'static str {
    if let Some(format) = rampage_unpack::executable_format(head) {
        return format;
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

/// Reads the first bytes of the regular file at `path` without following a symlink put in its place.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
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
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&query.path).map_err(|error| format!("{shown}: {error}"))? {
        let entry = entry.map_err(|error| format!("{shown}: {error}"))?;
        if names.len() == MAX_DIR_ENTRIES {
            return Err(format!("{shown} holds more than {MAX_DIR_ENTRIES} entries; list a subdirectory"));
        }
        names.push(entry.file_name());
    }
    let mut names: Vec<(Vec<u8>, std::ffi::OsString)> =
        names.into_iter().map(|name| (name_bytes(&name), name)).collect();
    names.sort_unstable();
    let start = match &query.cursor {
        Some(cursor) => names.partition_point(|(bytes, _)| escape(bytes).as_str() < cursor.as_str()),
        None => 0,
    };
    let end = names.len().min(start + limit);
    let entries = names[start..end]
        .iter()
        .map(|(bytes, name)| {
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
            let format = (kind == "file").then(|| read_head(&path).map_or("unreadable", |head| sniff(&head)));
            let link = (kind == "symlink")
                .then(|| std::fs::read_link(&path).ok())
                .flatten()
                .map(|target| escape(&name_bytes(target.as_os_str())));
            DirEntry { name: escape(bytes), kind, size, format, link }
        })
        .collect();
    Ok(DirListing {
        path: query.path.clone(),
        total: names.len(),
        entries,
        next_cursor: names.get(end).map(|(bytes, _)| escape(bytes)),
        next: "Open an executable by its path with binary_info or triage_report; a headerless image with \
               file_layout; a filesystem image (squashfs, ext, cpio, tar) with fs_list.",
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
    }
}
