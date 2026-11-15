//! POSIX ustar archives, with GNU long names and pax `path`/`linkpath`/`size` records.

use std::collections::HashMap;

use crate::error::{Result, UnpackError, checked};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::Limits;
use crate::source::{Source, within};

const FORMAT: &str = "tar";
const BLOCK: u64 = 512;
/// Long names and pax headers larger than this are refused.
const MAX_EXTENSION: u64 = 1 << 20;

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

/// Whether a 512-byte header's checksum field matches its bytes (the field itself counted as spaces).
pub(crate) fn header_checksum_ok(header: &[u8]) -> bool {
    if header.len() < BLOCK as usize {
        return false;
    }
    let Some(stored) = octal(&header[148..156]) else { return false };
    let sum: u64 = header[..512]
        .iter()
        .enumerate()
        .map(|(index, byte)| if (148..156).contains(&index) { 32 } else { u64::from(*byte) })
        .sum();
    sum == stored
}

/// An octal numeric field, or a GNU base-256 one (high bit of the first byte set).
fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        let mut value = 0u64;
        for (index, byte) in field.iter().enumerate() {
            let byte = if index == 0 { byte & 0x7f } else { *byte };
            value = value.checked_mul(256)?.checked_add(u64::from(byte))?;
        }
        return Some(value);
    }
    let text = field.iter().take_while(|byte| **byte != 0).copied().collect::<Vec<_>>();
    let text = std::str::from_utf8(&text).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn text(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(field.len());
    &field[..end]
}

/// The `path`, `linkpath` and `size` records of a pax extended header.
fn pax(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    let mut records = HashMap::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let space = rest.iter().position(|byte| *byte == b' ').ok_or_else(|| malformed("pax record without length"))?;
        let len: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|len| len.parse().ok())
            .filter(|len| *len > space && *len <= rest.len())
            .ok_or_else(|| malformed("bad pax record length"))?;
        let record = &rest[space + 1..len];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(equals) = record.iter().position(|byte| *byte == b'=') {
            let key = String::from_utf8_lossy(&record[..equals]).into_owned();
            records.insert(key, record[equals + 1..].to_vec());
        }
        rest = &rest[len..];
    }
    Ok(records)
}

#[derive(Debug, Clone, Copy)]
struct Data {
    offset: u64,
    len: u64,
}

pub struct Tar {
    source: Source,
    entries: Vec<Entry>,
    data: Vec<Data>,
}

impl Tar {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let size = source.size();
        let mut entries: Vec<Entry> = Vec::new();
        let mut data: Vec<Data> = Vec::new();
        let mut by_path: HashMap<String, usize> = HashMap::new();
        let (mut long_name, mut long_link): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        let mut extended: HashMap<String, Vec<u8>> = HashMap::new();
        let mut offset = 0u64;
        while offset < size {
            if !within(offset, BLOCK, size) {
                return Err(malformed(format!("truncated header at {offset}")));
            }
            let mut header = [0u8; BLOCK as usize];
            source.read_at(offset, &mut header).map_err(|_| malformed("truncated header"))?;
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            if !header_checksum_ok(&header) {
                return Err(malformed(format!("header checksum mismatch at {offset}")));
            }
            let declared = octal(&header[124..136]).ok_or_else(|| malformed("bad size field"))?;
            let type_flag = header[156];
            let body_at = offset + BLOCK;
            let body_len = match extended.get("size") {
                Some(value) if matches!(type_flag, b'0' | 0 | b'7') => std::str::from_utf8(value)
                    .ok()
                    .and_then(|value: &str| value.parse::<u64>().ok())
                    .ok_or_else(|| malformed("bad pax size"))?,
                _ => declared,
            };
            if !within(body_at, body_len, size) {
                return Err(malformed(format!("entry at {offset} runs past the end of the archive (truncated?)")));
            }
            let padded = checked(body_len.checked_add(BLOCK - 1), FORMAT, "entry size")? / BLOCK * BLOCK;
            offset = checked(body_at.checked_add(padded), FORMAT, "next header")?;
            let read_body = |what: &str| -> Result<Vec<u8>> {
                if body_len > MAX_EXTENSION {
                    return Err(malformed(format!("{what} larger than {MAX_EXTENSION} bytes")));
                }
                let mut body = vec![0u8; body_len as usize];
                source.read_at(body_at, &mut body).map_err(|_| malformed(format!("truncated {what}")))?;
                Ok(body)
            };
            match type_flag {
                b'L' => {
                    long_name = Some(text(&read_body("long name")?).to_vec());
                    continue;
                }
                b'K' => {
                    long_link = Some(text(&read_body("long link name")?).to_vec());
                    continue;
                }
                b'x' => {
                    extended = pax(&read_body("pax header")?)?;
                    continue;
                }
                b'g' => continue,
                _ => {}
            }
            let mut name = text(&header[0..100]).to_vec();
            let ustar = &header[257..262] == b"ustar";
            let prefix = text(&header[345..500]);
            if ustar && !prefix.is_empty() && header[263..265] == *b"00" {
                name = [prefix, b"/", &name].concat();
            }
            let name = extended.remove("path").or(long_name.take()).unwrap_or(name);
            let link_name =
                extended.remove("linkpath").or(long_link.take()).unwrap_or_else(|| text(&header[157..257]).to_vec());
            extended.clear();
            let path = crate::image::normalize(&String::from_utf8_lossy(&name)).to_owned();
            if path.is_empty() {
                continue;
            }
            if entries.len() >= limits.max_entries {
                return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
            }
            let link_text = String::from_utf8_lossy(&link_name).into_owned();
            let (kind, mut entry_data, mut note, link) = match type_flag {
                b'0' | 0 | b'7' => (EntryKind::File, Data { offset: body_at, len: body_len }, None, None),
                b'1' => {
                    let target = crate::image::normalize(&link_text).to_owned();
                    (EntryKind::File, Data { offset: 0, len: 0 }, Some(format!("hard link to {target}")), Some(target))
                }
                b'2' => (EntryKind::Symlink, Data { offset: 0, len: 0 }, None, Some(link_text.clone())),
                b'3' => (EntryKind::CharDevice, Data { offset: 0, len: 0 }, None, None),
                b'4' => (EntryKind::BlockDevice, Data { offset: 0, len: 0 }, None, None),
                b'5' => (EntryKind::Dir, Data { offset: 0, len: 0 }, None, None),
                b'6' => (EntryKind::Fifo, Data { offset: 0, len: 0 }, None, None),
                other => {
                    let note = format!("tar entry type `{}` is not read", char::from(other));
                    (EntryKind::Other, Data { offset: 0, len: 0 }, Some(note), None)
                }
            };
            if type_flag == b'1' {
                // A hard link shares the content of an earlier regular file.
                match link.as_ref().and_then(|target| by_path.get(target)) {
                    Some(&earlier) => entry_data = data[earlier],
                    None => note = Some(format!("hard link to {link_text}, which is not an earlier file")),
                }
            }
            if kind == EntryKind::File {
                by_path.insert(path.clone(), entries.len());
            }
            let mode = octal(&header[100..108]).unwrap_or(0) & 0o7777;
            entries.push(Entry {
                path,
                kind,
                size: entry_data.len,
                mode: mode as u32,
                uid: octal(&header[108..116]).and_then(|id| u32::try_from(id).ok()).unwrap_or(0),
                gid: octal(&header[116..124]).and_then(|id| u32::try_from(id).ok()).unwrap_or(0),
                link: if type_flag == b'1' { None } else { link },
                note,
            });
            data.push(entry_data);
        }
        Ok(Self { source, entries, data })
    }
}

impl Image for Tar {
    fn format(&self) -> Format {
        Format::Tar
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn read(&self, index: usize, limit: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let data = self.data.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        crate::sparse::copy_range(&*self.source, data.offset, data.len, limit, sink)
    }
}
