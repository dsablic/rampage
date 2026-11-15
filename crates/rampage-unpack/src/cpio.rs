//! cpio archives in the "newc" (070701) and "crc" (070702) formats, as initramfs images use.

use std::collections::HashMap;

use crate::error::{Result, UnpackError, checked};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::Limits;
use crate::source::{Source, within};

const FORMAT: &str = "cpio";
const HEADER: u64 = 110;
const MAX_NAME: u64 = 4096;

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

/// Where an entry's content lies in the archive.
#[derive(Debug, Clone, Copy)]
struct Data {
    offset: u64,
    len: u64,
}

pub struct Cpio {
    source: Source,
    entries: Vec<Entry>,
    data: Vec<Data>,
}

fn align4(value: u64) -> Option<u64> {
    value.checked_add(3).map(|value| value & !3)
}

fn hex_field(header: &[u8], index: usize) -> Result<u64> {
    let text = &header[6 + index * 8..14 + index * 8];
    let text = std::str::from_utf8(text).map_err(|_| malformed("non-ASCII header field"))?;
    u64::from_str_radix(text, 16).map_err(|_| malformed(format!("header field `{text}` is not hexadecimal")))
}

impl Cpio {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let size = source.size();
        let mut entries = Vec::new();
        let mut data = Vec::new();
        // (inode, device) of hard-linked regular files, for newc's convention of storing the data once, with the
        // last link.
        let mut links: Vec<(usize, (u64, u64, u64))> = Vec::new();
        let mut offset = 0u64;
        loop {
            let mut header = [0u8; HEADER as usize];
            source.read_at(offset, &mut header).map_err(|_| malformed(format!("truncated header at {offset}")))?;
            if &header[..6] != b"070701" && &header[..6] != b"070702" {
                return Err(malformed(format!("no header magic at {offset}")));
            }
            let field = |index| hex_field(&header, index);
            let (inode, mode, uid, gid, nlink) = (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
            let (file_size, dev_major, dev_minor, name_size) = (field(6)?, field(7)?, field(8)?, field(11)?);
            if name_size == 0 || name_size > MAX_NAME {
                return Err(malformed(format!("name size {name_size} at {offset}")));
            }
            let name_at = offset + HEADER;
            if !within(name_at, name_size, size) {
                return Err(malformed("name runs past the end of the archive"));
            }
            let mut name = vec![0u8; name_size as usize];
            source.read_at(name_at, &mut name).map_err(|_| malformed("truncated name"))?;
            if name.last() != Some(&0) {
                return Err(malformed("name is not NUL-terminated"));
            }
            name.pop();
            let data_at = checked(align4(name_at + name_size), FORMAT, "data offset")?;
            if !within(data_at, file_size, size) {
                return Err(malformed(format!("data of `{}` runs past the end", String::from_utf8_lossy(&name))));
            }
            offset = checked(align4(data_at + file_size), FORMAT, "next header")?;
            if name == b"TRAILER!!!" {
                break;
            }
            let path = String::from_utf8_lossy(&name);
            let path = crate::image::normalize(&path).to_owned();
            if path.is_empty() {
                continue;
            }
            if entries.len() >= limits.max_entries {
                return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
            }
            let kind = EntryKind::from_mode(u32::try_from(mode).unwrap_or(0));
            let link = if kind == EntryKind::Symlink {
                if file_size > MAX_NAME {
                    return Err(malformed("symlink target longer than 4096 bytes"));
                }
                let mut target = vec![0u8; file_size as usize];
                source.read_at(data_at, &mut target).map_err(|_| malformed("truncated symlink target"))?;
                Some(String::from_utf8_lossy(&target).into_owned())
            } else {
                None
            };
            if kind == EntryKind::File && nlink > 1 {
                links.push((entries.len(), (inode, dev_major, dev_minor)));
            }
            entries.push(Entry {
                path,
                kind,
                size: if kind == EntryKind::File { file_size } else { 0 },
                mode: (mode & 0o7777) as u32,
                uid: u32::try_from(uid).unwrap_or(u32::MAX),
                gid: u32::try_from(gid).unwrap_or(u32::MAX),
                link,
                note: None,
            });
            data.push(Data { offset: data_at, len: if kind == EntryKind::File { file_size } else { 0 } });
        }
        // Earlier links of a hard-linked file carry no data: share the copy that does.
        let mut holder: HashMap<(u64, u64, u64), usize> = HashMap::new();
        for &(index, key) in &links {
            if data[index].len > 0 {
                holder.insert(key, index);
            }
        }
        for &(index, key) in &links {
            if data[index].len == 0
                && let Some(&with_data) = holder.get(&key)
            {
                data[index] = data[with_data];
                entries[index].size = data[with_data].len;
                entries[index].note = Some(format!("hard link to {}", entries[with_data].path));
            }
        }
        Ok(Self { source, entries, data })
    }
}

impl Image for Cpio {
    fn format(&self) -> Format {
        Format::Cpio
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn read(&self, index: usize, limit: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let data = self.data.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        crate::sparse::copy_range(&*self.source, data.offset, data.len, limit, sink)
    }
}
