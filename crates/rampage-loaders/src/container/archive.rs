//! Standalone, single-disk ZIP32 central-directory evidence, never a member-opening interface.
//! Bounded tail reads may overlap member data; no member or local-header offset is followed.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::LoadError;

pub const MAX_TAIL_BYTES: usize = 65_557;
pub const MAX_CENTRAL_DIRECTORY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_NAME_BYTES: usize = 1024;
pub const MAX_RETAINED_NAME_BYTES: usize = 1024 * 1024;
pub const MAX_WARNINGS: usize = 64;
pub const MAX_METADATA_READ_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_EOCD_CANDIDATES: usize = 4096;
pub const MAX_EXTRA_FIELDS: usize = 65_536;
pub const MAX_NAME_FILTER_STEPS: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveRef {
    pub kind: &'static str,
    pub file_size: u64,
    pub central_directory_offset: u64,
    pub central_directory_size: u32,
    pub eocd_offset: u64,
    /// SHA-256 of validated central-directory bytes followed by EOCD fields and the complete raw archive comment.
    /// This is metadata evidence, not a whole-file hash, authenticity proof or atomic snapshot.
    pub metadata_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveMemberRef {
    pub archive: ArchiveRef,
    /// Central-directory order, not a filesystem path or native-image offset. Duplicates remain distinct.
    pub ordinal: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveMember {
    /// Match against the full raw name before retention truncation; omitted from serialized member metadata.
    #[serde(skip)]
    pub matches_filter: bool,
    pub member_ref: ArchiveMemberRef,
    pub flags: u16,
    pub compression_method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: u32,
    pub encrypted: bool,
    pub data_descriptor: bool,
    pub name_encoding: &'static str,
    pub name_utf8_valid: bool,
    /// Only a UTF-8 interpretation of raw bytes, never a normalized or extraction-safe path.
    pub name_display: Option<String>,
    pub raw_name_hex: String,
    pub original_name_bytes: usize,
    pub name_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct ArchiveInventory {
    pub archive_ref: ArchiveRef,
    pub declared: usize,
    pub examined: usize,
    /// Structurally checked directory records, not validated members, local headers or payloads.
    pub validated: usize,
    pub retained: usize,
    pub matched: usize,
    pub retained_name_bytes: usize,
    pub names_truncated: usize,
    pub central_directory_complete: bool,
    pub truncated: bool,
    pub metadata_read_bytes: usize,
    pub eocd_candidates_examined: usize,
    pub extra_fields_examined: usize,
    pub name_filter_steps: usize,
    pub members: Vec<ArchiveMember>,
    pub warnings: Vec<String>,
    pub warnings_total: usize,
    pub warnings_truncated: bool,
}

fn malformed(reason: &str) -> LoadError {
    LoadError::Malformed(format!("ZIP metadata: {reason}"))
}

fn unsupported(reason: &str) -> LoadError {
    LoadError::Unsupported(format!("ZIP metadata: {reason}"))
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, i64, i64),
    #[cfg(windows)]
    windows: (u32, u64, u64),
}

fn stamp(metadata: &Metadata) -> Result<Stamp, LoadError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(malformed("requires a regular file, not a symlink, device or pipe"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(malformed("reparse points are unsupported"));
        }
    }
    Ok(Stamp {
        size: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
        #[cfg(unix)]
        unix: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
        #[cfg(windows)]
        windows: {
            use std::os::windows::fs::MetadataExt;
            (metadata.file_attributes(), metadata.creation_time(), metadata.last_write_time())
        },
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "macos")]
    const FLAGS: i32 = 0x0004 | 0x0100;
    #[cfg(target_os = "linux")]
    const FLAGS: i32 = {
        let nonblock = if cfg!(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )) {
            0x0080
        } else if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
            0x4000
        } else {
            0x0800
        };
        let nofollow = if cfg!(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )) {
            0x8000
        } else {
            0x20000
        };
        nonblock | nofollow
    };
    // O_NONBLOCK avoids FIFO-open waits; O_NOFOLLOW refuses final-component symlink substitution.
    std::fs::OpenOptions::new().read(true).custom_flags(FLAGS).open(path)
}

#[cfg(windows)]
fn open_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileType"]
        fn get_file_type(file: *mut std::ffi::c_void) -> u32;
    }
    let file = std::fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path)?;
    // SAFETY: this live File owns the handle; no seeking or reading precedes this disk-object check.
    if unsafe { get_file_type(file.as_raw_handle()) } != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "archive is not a disk file"));
    }
    Ok(file)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn open_file(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "safe archive path reads require macOS, Linux or Windows"))
}

struct Reader<'a> {
    file: File,
    path: &'a Path,
    size: u64,
    read_bytes: usize,
}

impl Reader<'_> {
    fn read(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, LoadError> {
        let end = offset.checked_add(length as u64).ok_or_else(|| malformed("read range overflows"))?;
        let total = self.read_bytes.checked_add(length).ok_or_else(|| malformed("read budget overflows"))?;
        if end > self.size || total > MAX_METADATA_READ_BYTES {
            return Err(malformed("metadata read range or cumulative byte budget exceeded"));
        }
        self.read_bytes = total;
        let io_error = |source| LoadError::Io { path: self.path.to_owned(), source };
        self.file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut bytes = vec![0; length];
        self.file.read_exact(&mut bytes).map_err(io_error)?;
        Ok(bytes)
    }

    fn stamp(&self) -> Result<Stamp, LoadError> {
        stamp(&self.file.metadata().map_err(|source| LoadError::Io { path: self.path.to_owned(), source })?)
    }
}

#[derive(Clone, Copy)]
struct Eocd {
    tail_index: usize,
    offset: u64,
    directory_offset: u64,
    directory_size: u32,
    count: usize,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn find_eocd(tail: &[u8], tail_offset: u64) -> Result<(Eocd, usize), LoadError> {
    let mut found = None;
    let mut attempts = 0;
    let mut refusal = "no complete EOCD with comment ending at EOF";
    for index in 0..tail.len().saturating_sub(21) {
        if &tail[index..index + 4] != b"PK\x05\x06" {
            continue;
        }
        attempts += 1;
        if attempts > MAX_EOCD_CANDIDATES {
            return Err(malformed("EOCD candidate work budget exceeded"));
        }
        let record = &tail[index..];
        if 22 + usize::from(u16_at(record, 20)) != record.len() {
            continue;
        }
        if u16_at(record, 4) != 0 || u16_at(record, 6) != 0 || u16_at(record, 8) != u16_at(record, 10) {
            refusal = "multi-disk ZIP is unsupported";
            continue;
        }
        let count = usize::from(u16_at(record, 10));
        let directory_size = u32_at(record, 12);
        let directory_offset = u64::from(u32_at(record, 16));
        if count == 65535 || directory_size == u32::MAX || directory_offset == u64::from(u32::MAX) {
            refusal = "ZIP64 is unsupported";
            continue;
        }
        let offset = tail_offset + index as u64;
        if directory_offset.checked_add(u64::from(directory_size)) != Some(offset) {
            refusal = "central directory must adjoin EOCD; gaps and digital signatures are unsupported";
            continue;
        }
        if (count == 0 && (directory_size != 0 || directory_offset != 0))
            || (count > 0 && (u64::from(directory_size) < count as u64 * 46 || directory_offset < 4))
        {
            refusal = "central directory range/count mismatch";
            continue;
        }
        if found.is_some() {
            return Err(malformed("ambiguous EOF-matching EOCD candidates"));
        }
        found = Some(Eocd { tail_index: index, offset, directory_offset, directory_size, count });
    }
    found.map(|record| (record, attempts)).ok_or_else(|| unsupported(refusal))
}

fn metadata_digest(directory: &[u8], end: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(directory);
    hash.update(end);
    hex(&hash.finalize())
}

fn revalidate(
    reader: &mut Reader<'_>,
    before: &Stamp,
    prefix: &[u8],
    tail: &[u8],
    tail_offset: u64,
    eocd: Eocd,
    directory: &[u8],
) -> Result<(), LoadError> {
    if reader.stamp()? != *before {
        return Err(malformed("descriptor metadata changed during inventory"));
    }
    let prefix_again = reader.read(0, 4)?;
    let tail_again = reader.read(tail_offset, tail.len())?;
    let directory_again = reader.read(eocd.directory_offset, eocd.directory_size as usize)?;
    if prefix_again != prefix || tail_again != tail || directory_again != directory || reader.stamp()? != *before {
        return Err(malformed("metadata changed during bounded revalidation"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 15)] as char);
    }
    text
}

fn validate_extra(mut extra: &[u8], examined: &mut usize) -> Result<(), LoadError> {
    while !extra.is_empty() {
        *examined += 1;
        if *examined > MAX_EXTRA_FIELDS {
            return Err(malformed("cumulative extra-field work budget exceeded"));
        }
        if extra.len() < 4 {
            return Err(malformed("truncated central-directory extra field"));
        }
        if u16_at(extra, 0) == 1 {
            return Err(unsupported("ZIP64 extra fields are unsupported"));
        }
        let length = usize::from(u16_at(extra, 2));
        extra = extra
            .get(4..4 + length)
            .and_then(|_| extra.get(4 + length..))
            .ok_or_else(|| malformed("truncated central-directory extra field"))?;
    }
    Ok(())
}

struct NameFilter<'a> {
    needle: &'a [u8],
    fallback: Vec<usize>,
    steps: usize,
}

impl<'a> NameFilter<'a> {
    fn new(contains: Option<&'a str>) -> Result<Self, LoadError> {
        let needle = contains.unwrap_or_default().as_bytes();
        if needle.len() > MAX_NAME_BYTES {
            return Err(malformed("contains exceeds 1024 UTF-8 bytes"));
        }
        let mut fallback = vec![0; needle.len()];
        let mut matched = 0;
        let mut steps = 0;
        for index in 1..needle.len() {
            steps += 1;
            while matched > 0 && needle[matched] != needle[index] {
                steps += 1;
                matched = fallback[matched - 1];
            }
            if needle[matched] == needle[index] {
                matched += 1;
            }
            fallback[index] = matched;
        }
        Ok(Self { needle, fallback, steps })
    }

    fn matches(&mut self, name: &[u8]) -> Result<bool, LoadError> {
        if self.needle.is_empty() {
            return Ok(true);
        }
        let mut matched = 0;
        for byte in name {
            self.steps += 1;
            while matched > 0 && self.needle[matched] != *byte {
                self.steps += 1;
                matched = self.fallback[matched - 1];
            }
            if self.steps > MAX_NAME_FILTER_STEPS {
                return Err(malformed("cumulative name-filter work budget exceeded"));
            }
            if self.needle[matched] == *byte {
                matched += 1;
                if matched == self.needle.len() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

/// Inventory an explicit standalone ZIP32 file. Limits reject the whole operation, never certify a partial CD.
/// `contains` is a case-sensitive raw-name byte substring using the query's UTF-8 bytes, before name truncation.
pub fn inventory(path: &Path, contains: Option<&str>) -> Result<ArchiveInventory, LoadError> {
    let mut name_filter = NameFilter::new(contains)?;
    let file = open_file(path).map_err(|source| LoadError::Io { path: path.to_owned(), source })?;
    let before = stamp(&file.metadata().map_err(|source| LoadError::Io { path: path.to_owned(), source })?)?;
    if before.size < 22 || before.size > u64::from(u32::MAX) {
        return Err(unsupported("requires a complete ZIP32 file of 22 bytes through 4 GiB minus one"));
    }
    let mut reader = Reader { file, path, size: before.size, read_bytes: 0 };
    let prefix = reader.read(0, 4)?;
    if prefix != b"PK\x03\x04" && prefix != b"PK\x05\x06" {
        return Err(unsupported("standalone ZIP prefix required; SFX and inferred offsets are unsupported"));
    }
    let tail_length = usize::try_from(before.size.min(MAX_TAIL_BYTES as u64)).unwrap();
    let tail_offset = before.size - tail_length as u64;
    let tail = reader.read(tail_offset, tail_length)?;
    let (eocd, attempts) = find_eocd(&tail, tail_offset)?;
    if eocd.count > MAX_RECORDS || eocd.directory_size as usize > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(malformed("central-directory size or record-attempt budget exceeded; no partial inventory"));
    }
    if (eocd.count == 0) != (prefix == b"PK\x05\x06") {
        return Err(malformed("standalone prefix and directory count disagree"));
    }
    let directory = reader.read(eocd.directory_offset, eocd.directory_size as usize)?;
    let mut archive_ref = ArchiveRef {
        kind: "standalone_single_disk_zip32",
        file_size: before.size,
        central_directory_offset: eocd.directory_offset,
        central_directory_size: eocd.directory_size,
        eocd_offset: eocd.offset,
        metadata_sha256: String::new(),
    };
    let mut members = Vec::new();
    let mut cursor = 0usize;
    let mut name_bytes = 0usize;
    let mut warnings = Vec::new();
    let mut warnings_total = 0;
    let mut extra_fields_examined = 0;
    for ordinal in 0..eocd.count {
        let header = directory.get(cursor..cursor + 46).ok_or_else(|| malformed("truncated directory record"))?;
        if &header[..4] != b"PK\x01\x02" {
            return Err(malformed("invalid central-directory record signature"));
        }
        let flags = u16_at(header, 8);
        let compressed_size = u32_at(header, 20);
        let uncompressed_size = u32_at(header, 24);
        let local_header_offset = u32_at(header, 42);
        if compressed_size == u32::MAX || uncompressed_size == u32::MAX || local_header_offset == u32::MAX {
            return Err(unsupported("ZIP64 member sizes or offsets are unsupported"));
        }
        if u16_at(header, 34) != 0 {
            return Err(unsupported("multi-disk member is unsupported"));
        }
        if u64::from(local_header_offset) >= eocd.directory_offset {
            return Err(malformed("declared local-header offset is outside the pre-directory range"));
        }
        let name_length = usize::from(u16_at(header, 28));
        let extra_length = usize::from(u16_at(header, 30));
        let comment_length = usize::from(u16_at(header, 32));
        let name_start = cursor + 46;
        let name_end = name_start + name_length;
        let extra_end = name_end + extra_length;
        let end = extra_end + comment_length;
        let record = directory.get(cursor..end).ok_or_else(|| malformed("truncated variable directory record"))?;
        let name = &record[46..46 + name_length];
        validate_extra(&directory[name_end..extra_end], &mut extra_fields_examined)?;
        let text = std::str::from_utf8(name).ok();
        let kept_length = name.len().min(MAX_NAME_BYTES);
        let display_length = text.map_or(0, |text| {
            let mut end = kept_length;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            end
        });
        name_bytes += kept_length * 2 + display_length;
        if name_bytes > MAX_RETAINED_NAME_BYTES {
            return Err(malformed("retained-name budget exceeded; no partial inventory"));
        }
        if flags & 0x800 != 0 && text.is_none() {
            warnings_total += 1;
            if warnings.len() < MAX_WARNINGS {
                warnings.push(format!("member {ordinal}: UTF-8 flag set but full raw name is invalid UTF-8"));
            }
        }
        cursor = end;
        let matches_filter = name_filter.matches(name)?;
        let name_display = text.map(|text| text[..display_length].to_owned());
        members.push(ArchiveMember {
            matches_filter,
            member_ref: ArchiveMemberRef { archive: archive_ref.clone(), ordinal },
            flags,
            compression_method: u16_at(header, 10),
            crc32: u32_at(header, 16),
            compressed_size,
            uncompressed_size,
            local_header_offset,
            encrypted: flags & 1 != 0,
            data_descriptor: flags & 8 != 0,
            name_encoding: if flags & 0x800 == 0 { "legacy_raw" } else { "utf8_flag" },
            name_utf8_valid: text.is_some(),
            name_display,
            raw_name_hex: hex(&name[..kept_length]),
            original_name_bytes: name_length,
            name_truncated: name_length > kept_length,
        });
    }
    if cursor != directory.len() {
        return Err(malformed("central-directory size/count mismatch or unsupported trailing digital signature"));
    }
    revalidate(&mut reader, &before, &prefix, &tail, tail_offset, eocd, &directory)?;
    archive_ref.metadata_sha256 = metadata_digest(&directory, &tail[eocd.tail_index..]);
    for member in &mut members {
        member.member_ref.archive.clone_from(&archive_ref);
    }
    Ok(ArchiveInventory {
        archive_ref,
        declared: eocd.count,
        examined: eocd.count,
        validated: eocd.count,
        retained: members.len(),
        matched: members.iter().filter(|member| member.matches_filter).count(),
        retained_name_bytes: name_bytes,
        names_truncated: members.iter().filter(|member| member.name_truncated).count(),
        central_directory_complete: true,
        truncated: false,
        metadata_read_bytes: reader.read_bytes,
        eocd_candidates_examined: attempts,
        extra_fields_examined,
        name_filter_steps: name_filter.steps,
        members,
        warnings_total,
        warnings_truncated: warnings_total > warnings.len(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SERIAL: AtomicUsize = AtomicUsize::new(0);

    struct Input(PathBuf);

    impl Input {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rampage-zip32-reader-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            let mut bytes = [0; 22];
            bytes[..4].copy_from_slice(b"PK\x05\x06");
            std::fs::write(&path, bytes).unwrap();
            Self(path)
        }

        fn reader(&self) -> Reader<'_> {
            Reader { file: open_file(&self.0).unwrap(), path: &self.0, size: 22, read_bytes: 0 }
        }
    }

    impl Drop for Input {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }

    #[test]
    fn read_budget_and_range_failures_precede_seeking_and_allocation() {
        let input = Input::new();
        let mut reader = input.reader();
        reader.read_bytes = MAX_METADATA_READ_BYTES - 1;
        assert!(reader.read(0, 2).is_err());
        reader.read_bytes = 0;
        assert!(reader.read(u64::MAX, 2).is_err());
        assert!(reader.read(reader.size, 1).is_err());
        assert_eq!(reader.file.stream_position().unwrap(), 0);
        assert_eq!(reader.read_bytes, 0);
    }

    #[test]
    fn revalidation_checks_descriptor_stamp_and_metadata_bytes_separately() {
        let input = Input::new();
        let mut reader = input.reader();
        let before = reader.stamp().unwrap();
        let tail = reader.read(0, 22).unwrap();
        let eocd = find_eocd(&tail, 0).unwrap().0;
        let mut changed = reader.stamp().unwrap();
        changed.size += 1;
        let error = revalidate(&mut reader, &changed, &tail[..4], &tail, 0, eocd, &[]).unwrap_err();
        assert!(error.to_string().contains("descriptor metadata changed"));
        let error = revalidate(&mut reader, &before, b"bad!", &tail, 0, eocd, &[]).unwrap_err();
        assert!(error.to_string().contains("bounded revalidation"));
        assert!(revalidate(&mut reader, &before, &tail[..4], &tail, 0, eocd, &[]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn metadata_changed_on_the_open_descriptor_is_refused() {
        let input = Input::new();
        let mut reader = input.reader();
        let before = reader.stamp().unwrap();
        let tail = reader.read(0, 22).unwrap();
        let eocd = find_eocd(&tail, 0).unwrap().0;
        std::fs::write(&input.0, b"changed length and metadata").unwrap();
        assert!(revalidate(&mut reader, &before, &tail[..4], &tail, 0, eocd, &[]).is_err());
    }
}
