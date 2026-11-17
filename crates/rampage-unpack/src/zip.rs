//! ZIP archives (and APK/AAB/JAR, which are ZIP): the central directory, ZIP64 included, with stored and deflated
//! members. The central directory is authoritative, as for Android's installer: local headers only locate the data.
//! Every declared size is checked against the archive, and inflation stops at the declared size, the per-file limit
//! and the ratio meter.

use crate::codec::{Codec, decompress_stream};
use crate::error::{Result, UnpackError};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::{Budget, Limits};
use crate::source::{Cursor, Source, read_prefix, within};

const FORMAT: &str = "zip";
/// The end-of-central-directory record and the largest comment after it.
const MAX_TAIL: u64 = 22 + 65_535;
/// Bytes of central directory read into memory.
const MAX_DIRECTORY: u64 = 64 << 20;

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Where a member's data lies and how it is stored.
#[derive(Debug, Clone, Copy)]
struct Member {
    local_header: u64,
    method: u16,
    compressed: u64,
    size: u64,
    encrypted: bool,
}

pub struct Zip {
    source: Source,
    entries: Vec<Entry>,
    members: Vec<Member>,
    notes: Vec<String>,
}

struct Directory {
    count: u64,
    offset: u64,
    size: u64,
}

/// Finds the end-of-central-directory record (the last one whose comment ends at the end of the archive), following
/// the ZIP64 locator when the record's fields are saturated.
fn find_directory(source: &Source) -> Result<Directory> {
    let size = source.size();
    let tail_len = size.min(MAX_TAIL);
    let tail_at = size - tail_len;
    let tail = read_prefix(&**source, tail_at, tail_len as usize).map_err(|error| UnpackError::io("read", error))?;
    let found = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&at| &tail[at..at + 4] == b"PK\x05\x06" && at + 22 + usize::from(u16_at(&tail, at + 20)) == tail.len())
        .or_else(|| (0..tail.len().saturating_sub(21)).rev().find(|&at| &tail[at..at + 4] == b"PK\x05\x06"))
        .ok_or_else(|| malformed("no end-of-central-directory record"))?;
    let record = &tail[found..];
    if u16_at(record, 4) != 0 || u16_at(record, 6) != 0 {
        return Err(UnpackError::Unsupported("multi-disk ZIP archives".to_owned()));
    }
    let mut directory = Directory {
        count: u64::from(u16_at(record, 10)),
        size: u64::from(u32_at(record, 12)),
        offset: u64::from(u32_at(record, 16)),
    };
    let saturated = directory.count == 0xffff || directory.size == 0xffff_ffff || directory.offset == 0xffff_ffff;
    let eocd_at = tail_at + found as u64;
    if saturated && eocd_at >= 20 {
        let mut locator = [0u8; 20];
        source.read_at(eocd_at - 20, &mut locator).map_err(|error| UnpackError::io("read", error))?;
        if &locator[..4] == b"PK\x06\x07" {
            let at = u64_at(&locator, 8);
            let mut record = [0u8; 56];
            if !within(at, 56, size) {
                return Err(malformed("ZIP64 end record outside the archive"));
            }
            source.read_at(at, &mut record).map_err(|error| UnpackError::io("read", error))?;
            if &record[..4] != b"PK\x06\x06" {
                return Err(malformed("ZIP64 locator points at no ZIP64 end record"));
            }
            directory =
                Directory { count: u64_at(&record, 32), size: u64_at(&record, 40), offset: u64_at(&record, 48) };
        }
    }
    Ok(directory)
}

/// Replaces saturated 32-bit sizes and offsets with the ZIP64 extra field's values, in their fixed order.
fn zip64(extra: &[u8], size: &mut u64, compressed: &mut u64, offset: &mut u64) -> Result<()> {
    let mut at = 0;
    while at + 4 <= extra.len() {
        let id = u16_at(extra, at);
        let len = usize::from(u16_at(extra, at + 2));
        let body = extra.get(at + 4..at + 4 + len).ok_or_else(|| malformed("truncated extra field"))?;
        if id == 1 {
            let mut fields = body.as_chunks::<8>().0.iter().map(|chunk| u64::from_le_bytes(*chunk));
            for value in [size, compressed, offset] {
                if *value == 0xffff_ffff {
                    *value = fields.next().ok_or_else(|| malformed("ZIP64 extra field too short"))?;
                }
            }
            return Ok(());
        }
        at += 4 + len;
    }
    Ok(())
}

impl Zip {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let size = source.size();
        let directory = find_directory(&source)?;
        if directory.size > MAX_DIRECTORY {
            return Err(UnpackError::Limit(format!("central directory of {} bytes", directory.size)));
        }
        if !within(directory.offset, directory.size, size) {
            return Err(malformed("central directory runs past the end of the archive"));
        }
        if directory.count > limits.max_entries as u64 {
            return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
        }
        if directory.count.saturating_mul(46) > directory.size {
            return Err(malformed(format!(
                "{} entries cannot fit a {}-byte central directory",
                directory.count, directory.size
            )));
        }
        let mut bytes = vec![0u8; directory.size as usize];
        source
            .read_at(directory.offset, &mut bytes)
            .map_err(|error| UnpackError::io("read the central directory", error))?;
        let mut entries = Vec::with_capacity(directory.count as usize);
        let mut members = Vec::with_capacity(directory.count as usize);
        let mut notes = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut at = 0usize;
        for ordinal in 0..directory.count {
            let header = bytes.get(at..at + 46).ok_or_else(|| malformed(format!("entry {ordinal} is truncated")))?;
            if &header[..4] != b"PK\x01\x02" {
                return Err(malformed(format!("entry {ordinal} has no central-directory signature")));
            }
            let made_by = header[5];
            let flags = u16_at(header, 8);
            let method = u16_at(header, 10);
            let mut compressed = u64::from(u32_at(header, 20));
            let mut file_size = u64::from(u32_at(header, 24));
            let (name_len, extra_len, comment_len) =
                (usize::from(u16_at(header, 28)), usize::from(u16_at(header, 30)), usize::from(u16_at(header, 32)));
            let external = u32_at(header, 38);
            let mut local_header = u64::from(u32_at(header, 42));
            let name_at = at + 46;
            let end = name_at + name_len + extra_len + comment_len;
            let record =
                bytes.get(at..end).ok_or_else(|| malformed(format!("entry {ordinal} runs past the directory")))?;
            let name = &record[46..46 + name_len];
            zip64(
                &record[46 + name_len..46 + name_len + extra_len],
                &mut file_size,
                &mut compressed,
                &mut local_header,
            )?;
            at = end;
            let raw_path = String::from_utf8_lossy(name);
            let is_dir = raw_path.ends_with('/');
            let path = crate::image::normalize(&raw_path).to_owned();
            if path.is_empty() {
                continue;
            }
            if !seen.insert(path.clone()) && notes.len() < 16 {
                notes.push(format!("duplicate entry `{path}`: readers may disagree on which copy applies"));
            }
            let unix_mode = (made_by == 3).then_some(external >> 16).filter(|mode| *mode != 0);
            let kind = match unix_mode.map(EntryKind::from_mode) {
                _ if is_dir => EntryKind::Dir,
                Some(EntryKind::Dir) => EntryKind::Dir,
                Some(EntryKind::File) | None => EntryKind::File,
                Some(_) => EntryKind::Other,
            };
            let mode = unix_mode.map_or(if kind == EntryKind::Dir { 0o755 } else { 0o644 }, |mode| mode & 0o7777);
            let encrypted = flags & 1 != 0;
            let note = match (encrypted, method) {
                (true, _) => Some("encrypted: not read".to_owned()),
                (false, 0 | 8) => None,
                (false, method) => Some(format!("compression method {method}: not read")),
            };
            entries.push(Entry {
                path,
                kind,
                size: if kind == EntryKind::File { file_size } else { 0 },
                mode,
                uid: 0,
                gid: 0,
                link: None,
                note,
            });
            members.push(Member { local_header, method, compressed, size: file_size, encrypted });
        }
        // Members whose data overlap (two entries at one local header, or one inside another): a ZIP bomb or a
        // polyglot trick. Each range here is no longer than the member's real one, so an overlap is real.
        let mut ranges: Vec<(u64, u64, usize)> = members
            .iter()
            .enumerate()
            .filter(|(index, _)| entries[*index].kind == EntryKind::File)
            .map(|(index, member)| {
                (member.local_header, member.local_header.saturating_add(30).saturating_add(member.compressed), index)
            })
            .collect();
        ranges.sort_unstable();
        let mut overlapping = 0usize;
        let mut reach: Option<(u64, usize)> = None;
        for &(start, end, index) in &ranges {
            if let Some((furthest, previous)) = reach
                && start < furthest
            {
                overlapping += 1;
                if overlapping <= 8 {
                    notes.push(format!("`{}` overlaps the data of `{}`", entries[index].path, entries[previous].path));
                }
                entries[index].note.get_or_insert_with(|| "data overlaps another entry".to_owned());
            }
            if reach.is_none_or(|(furthest, _)| end > furthest) {
                reach = Some((end, index));
            }
        }
        if overlapping > 8 {
            notes.push(format!("{overlapping} entries overlap the data of another entry"));
        }
        Ok(Self { source, entries, members, notes })
    }
}

impl Image for Zip {
    fn format(&self) -> Format {
        Format::Zip
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let member = *self.members.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        if self.entries[index].kind != EntryKind::File {
            return Ok(());
        }
        if member.encrypted {
            return Err(UnpackError::Unsupported(format!("`{}` is encrypted", self.entries[index].path)));
        }
        let limit = budget.limits.max_file_bytes;
        if member.size > limit {
            return Err(UnpackError::Limit(format!("{} bytes is more than max_file_bytes ({limit})", member.size)));
        }
        let mut local = [0u8; 30];
        self.source
            .read_at(member.local_header, &mut local)
            .map_err(|_| malformed(format!("local header of `{}` is outside the archive", self.entries[index].path)))?;
        if &local[..4] != b"PK\x03\x04" {
            return Err(malformed(format!("no local header for `{}`", self.entries[index].path)));
        }
        let data_at = member.local_header + 30 + u64::from(u16_at(&local, 26)) + u64::from(u16_at(&local, 28));
        if !within(data_at, member.compressed, self.source.size()) {
            return Err(malformed(format!("data of `{}` runs past the end of the archive", self.entries[index].path)));
        }
        match member.method {
            0 => {
                if member.compressed != member.size {
                    return Err(malformed(format!("stored entry `{}` has two sizes", self.entries[index].path)));
                }
                crate::sparse::copy_range(&*self.source, data_at, member.size, budget, sink)
            }
            8 => {
                let input = Cursor::range(self.source.clone(), data_at, member.compressed);
                let produced =
                    decompress_stream(Codec::Deflate, input, member.compressed, member.size, &mut |chunk| {
                        budget.charge_bytes(chunk.len() as u64)?;
                        sink(chunk)
                    })?;
                if produced != member.size {
                    return Err(malformed(format!(
                        "`{}` inflates to {produced} bytes, not the declared {}",
                        self.entries[index].path, member.size
                    )));
                }
                Ok(())
            }
            method => Err(UnpackError::Unsupported(format!(
                "compression method {method} of `{}` (stored and deflate are read)",
                self.entries[index].path
            ))),
        }
    }
}
