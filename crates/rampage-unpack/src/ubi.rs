//! UBI images (raw flash dumps or `ubinize` output): erase-counter and volume-identifier headers, the volume table,
//! and each volume's logical eraseblocks put back in order. Every volume is listed as an image entry; its content
//! is streamed LEB by LEB and opens as a nested image (UBIFS, SquashFS, ...). Layouts follow `ubi-media.h`.

use std::collections::{BTreeMap, HashMap};

use crate::error::{Result, UnpackError};
use crate::image::{Entry, EntryKind, Format, Image, detect_bytes};
use crate::limits::{Budget, Limits};
use crate::source::{ReadAt, Source};

const FORMAT: &str = "ubi";
const EC_MAGIC: &[u8; 4] = b"UBI#";
const VID_MAGIC: &[u8; 4] = b"UBI!";
const HEADER: usize = 64;
/// Volume ids from here up are UBI's own (the layout volume, fastmap).
const INTERNAL_VOLUMES: u32 = 0x7fff_efff;
const LAYOUT_VOLUME: u32 = INTERNAL_VOLUMES;
const VTBL_RECORD: usize = 172;
const MAX_VOLUMES: usize = 128;
const DYNAMIC: u8 = 1;
const STATIC: u8 = 2;
/// PEB sizes tried, smallest first: 4 KiB to 16 MiB, powers of two.
const MIN_PEB: u64 = 4 << 10;
const MAX_PEB: u64 = 16 << 20;
/// PEBs an image may hold: a 64 GiB dump of 16 KiB blocks.
const MAX_PEBS: u64 = 4_000_000;
/// Input charged to the ratio meter for an unmapped LEB, whose 0xFF bytes are synthesised.
const NOMINAL_UNMAPPED_INPUT: u64 = 64;

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn be64(bytes: &[u8], at: usize) -> u64 {
    (u64::from(be32(bytes, at)) << 32) | u64::from(be32(bytes, at + 4))
}

/// CRC-32 as UBI and UBIFS store it: the IEEE polynomial from an all-ones seed, without the final inversion.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    !crc.sum()
}

/// The fields of an erase-counter header that place the rest of the eraseblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ec {
    vid_offset: u32,
    data_offset: u32,
    image_seq: u32,
}

fn parse_ec(header: &[u8; HEADER]) -> Option<Ec> {
    if &header[..4] != EC_MAGIC || header[4] != 1 || crc32(&header[..60]) != be32(header, 60) {
        return None;
    }
    Some(Ec { vid_offset: be32(header, 16), data_offset: be32(header, 20), image_seq: be32(header, 24) })
}

#[derive(Debug, Clone, Copy)]
struct Vid {
    vol_type: u8,
    copy_flag: bool,
    vol_id: u32,
    lnum: u32,
    data_size: u32,
    used_ebs: u32,
    data_crc: u32,
    sqnum: u64,
}

fn parse_vid(header: &[u8; HEADER]) -> Option<Vid> {
    if &header[..4] != VID_MAGIC || header[4] != 1 || crc32(&header[..60]) != be32(header, 60) {
        return None;
    }
    Some(Vid {
        vol_type: header[5],
        copy_flag: header[6] != 0,
        vol_id: be32(header, 8),
        lnum: be32(header, 12),
        data_size: be32(header, 20),
        used_ebs: be32(header, 24),
        data_crc: be32(header, 32),
        sqnum: be64(header, 40),
    })
}

/// A mapped LEB: the PEB that holds it and its header.
#[derive(Debug, Clone, Copy)]
struct Leb {
    pnum: u64,
    vid: Vid,
}

#[derive(Debug)]
struct Volume {
    id: u32,
    name: String,
    vol_type: u8,
    reserved: u32,
    /// Bytes of each LEB this volume uses: the eraseblock less its headers and the alignment padding.
    usable: u64,
    /// The LEBs found, by number.
    lebs: BTreeMap<u32, Leb>,
    update_interrupted: bool,
    size: u64,
}

impl Volume {
    /// The LEB count the content spans: `used_ebs` for a static volume, up to the last mapped LEB for a dynamic one.
    /// LEB numbers are below `reserved` (checked when the LEBs are assigned), and so is a static volume's span.
    fn span(&self) -> u32 {
        match self.vol_type {
            STATIC => self.lebs.values().next().map_or(0, |leb| leb.vid.used_ebs.min(self.reserved)),
            _ => self.lebs.keys().next_back().map_or(0, |last| last + 1),
        }
    }
}

pub struct Ubi {
    source: Source,
    peb_size: u64,
    data_offset: u64,
    volumes: Vec<Volume>,
    entries: Vec<Entry>,
    notes: Vec<String>,
}

/// Eraseblocks probed after the first intact one when sizing them.
const PROBES: u64 = 16;

/// The first intact erase-counter header, at a multiple of the smallest eraseblock size within the first 16 MiB:
/// raw dumps can start with bad or erased blocks.
fn first_header(source: &dyn ReadAt) -> Option<(u64, Ec)> {
    let mut header = [0u8; HEADER];
    (0..source.size().min(MAX_PEB) / MIN_PEB).map(|index| index * MIN_PEB).find_map(|at| {
        source.read_at(at, &mut header).ok()?;
        parse_ec(&header).map(|ec| (at, ec))
    })
}

/// The PEB size: the smallest power of two that divides `start`, the offset of the first intact header `first`,
/// at which most of the following eraseblock starts hold a valid header of the same image (half of them do at half
/// the real size).
fn find_peb_size(source: &dyn ReadAt, start: u64, first: Ec) -> Option<u64> {
    let size = source.size();
    let sizes = std::iter::successors(Some(MIN_PEB), |peb| Some(peb * 2)).take_while(|peb| *peb <= MAX_PEB);
    for peb in sizes {
        if peb <= u64::from(first.data_offset) || !start.is_multiple_of(peb) {
            continue;
        }
        let after = (size - start) / peb;
        if after < 2 {
            break;
        }
        let probes = (after - 1).min(PROBES);
        let mut valid = 0;
        for k in 1..=probes {
            let mut header = [0u8; HEADER];
            if source.read_at(start + k * peb, &mut header).is_ok() && parse_ec(&header).is_some_and(|ec| ec == first) {
                valid += 1;
            }
        }
        if valid * 2 > probes {
            return Some(peb);
        }
    }
    // A single eraseblock, or nothing after it is UBI.
    (start == 0 && size.is_power_of_two() && (MIN_PEB..=MAX_PEB).contains(&size)).then_some(size)
}

impl Ubi {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let mut header = [0u8; HEADER];
        let (start, first) = first_header(&*source)
            .ok_or_else(|| malformed("no intact erase-counter header (its CRC checked) in the first 16 MiB"))?;
        let peb_size = find_peb_size(&*source, start, first)
            .ok_or_else(|| malformed("no eraseblock size from 4 KiB to 16 MiB repeats the first header"))?;
        let (vid_offset, data_offset) = (u64::from(first.vid_offset), u64::from(first.data_offset));
        // The data area is most of the block in every real layout; a tiny one would make reads crawl.
        if vid_offset < HEADER as u64 || vid_offset + HEADER as u64 > data_offset || data_offset > peb_size / 2 {
            return Err(malformed(format!("header offsets {vid_offset} and {data_offset} in a {peb_size}-byte block")));
        }
        let pebs = source.size() / peb_size;
        if pebs > MAX_PEBS {
            return Err(UnpackError::Limit(format!("{pebs} eraseblocks (at most {MAX_PEBS})")));
        }
        let mut candidates: HashMap<(u32, u32), Vec<Leb>> = HashMap::new();
        let (mut free, mut empty, mut damaged, mut foreign) = (0u64, 0u64, 0u64, 0u64);
        for pnum in 0..pebs {
            let base = pnum * peb_size;
            source.read_at(base, &mut header).map_err(|error| UnpackError::io("read the image", error))?;
            let Some(ec) = parse_ec(&header) else {
                if header.iter().all(|byte| *byte == 0xff) {
                    empty += 1;
                } else {
                    damaged += 1;
                }
                continue;
            };
            if ec != first {
                foreign += 1;
                continue;
            }
            source.read_at(base + vid_offset, &mut header).map_err(|error| UnpackError::io("read the image", error))?;
            let Some(vid) = parse_vid(&header) else {
                if header.iter().all(|byte| *byte == 0xff) {
                    free += 1;
                } else {
                    damaged += 1;
                }
                continue;
            };
            candidates.entry((vid.vol_id, vid.lnum)).or_default().push(Leb { pnum, vid });
        }
        let mut ubi =
            Self { source, peb_size, data_offset, volumes: Vec::new(), entries: Vec::new(), notes: Vec::new() };
        // A LEB written more than once (wear levelling, an interrupted copy): the newest copy whose data checks out.
        let mut mapped: HashMap<(u32, u32), Leb> = HashMap::new();
        let mut stale = 0u64;
        for (key, mut copies) in candidates {
            copies.sort_by_key(|leb| std::cmp::Reverse(leb.vid.sqnum));
            stale += copies.len() as u64 - 1;
            let chosen = if copies.len() == 1 {
                copies[0]
            } else {
                let checked = copies.iter().find(|leb| ubi.data_ok(leb).unwrap_or(false));
                *checked.unwrap_or(&copies[0])
            };
            mapped.insert(key, chosen);
        }
        ubi.read_volume_table(&mapped)?;
        let mut orphans = 0u64;
        for ((vol_id, lnum), leb) in mapped {
            if vol_id >= INTERNAL_VOLUMES {
                continue;
            }
            match ubi.volumes.iter_mut().find(|volume| volume.id == vol_id) {
                Some(volume) if lnum < volume.reserved => {
                    volume.lebs.insert(lnum, leb);
                }
                _ => orphans += 1,
            }
        }
        if ubi.volumes.len() > limits.max_entries {
            return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
        }
        ubi.list(pebs, [free, empty, damaged, foreign, stale, orphans])?;
        Ok(ubi)
    }

    /// The bytes of the PEB `leb` lives in that hold its data, from the start of the data area.
    fn data_range(&self, leb: &Leb, len: u64) -> Result<u64> {
        let start = leb.pnum * self.peb_size + self.data_offset;
        if len > self.peb_size - self.data_offset {
            return Err(malformed(format!("LEB {} of volume {} declares {len} bytes", leb.vid.lnum, leb.vid.vol_id)));
        }
        Ok(start)
    }

    /// Whether a LEB's data matches its CRC; `true` when the header carries none (a dynamic LEB never copied).
    fn data_ok(&self, leb: &Leb) -> Result<bool> {
        if leb.vid.vol_type != STATIC && !leb.vid.copy_flag {
            return Ok(true);
        }
        let len = u64::from(leb.vid.data_size);
        let start = self.data_range(leb, len)?;
        let mut data = vec![0u8; len as usize];
        self.source.read_at(start, &mut data).map_err(|error| UnpackError::io("read the image", error))?;
        Ok(crc32(&data) == leb.vid.data_crc)
    }

    /// The volume table, from the first copy of the layout volume whose records all check out.
    fn read_volume_table(&mut self, mapped: &HashMap<(u32, u32), Leb>) -> Result<()> {
        let usable = self.peb_size - self.data_offset;
        let slots = MAX_VOLUMES.min(usable as usize / VTBL_RECORD);
        let mut table = None;
        for copy in 0..2 {
            let Some(leb) = mapped.get(&(LAYOUT_VOLUME, copy)) else { continue };
            let mut records = vec![0u8; slots * VTBL_RECORD];
            let start = self.data_range(leb, records.len() as u64)?;
            self.source.read_at(start, &mut records).map_err(|error| UnpackError::io("read the image", error))?;
            if records.chunks(VTBL_RECORD).all(|record| crc32(&record[..168]) == be32(record, 168)) {
                table = Some(records);
                break;
            }
        }
        let table = table.ok_or_else(|| malformed("no copy of the volume table is intact"))?;
        for (id, record) in table.chunks(VTBL_RECORD).enumerate() {
            let reserved = be32(record, 0);
            if reserved == 0 {
                continue;
            }
            let (alignment, data_pad, vol_type) = (be32(record, 4), u64::from(be32(record, 8)), record[12]);
            let name_len = usize::from(u16::from_be_bytes([record[14], record[15]])).min(127);
            if !matches!(vol_type, DYNAMIC | STATIC) || alignment == 0 || data_pad > usable / 2 {
                return Err(malformed(format!("volume table record {id} is inconsistent")));
            }
            self.volumes.push(Volume {
                id: id as u32,
                name: String::from_utf8_lossy(&record[16..16 + name_len]).into_owned(),
                vol_type,
                reserved,
                usable: usable - data_pad,
                lebs: BTreeMap::new(),
                update_interrupted: record[13] != 0,
                size: 0,
            });
        }
        Ok(())
    }

    fn list(&mut self, pebs: u64, [free, empty, damaged, foreign, stale, orphans]: [u64; 6]) -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for volume in &mut self.volumes {
            let span = volume.span();
            let mut note = Vec::new();
            volume.size = match volume.vol_type {
                STATIC => {
                    // Present LEBs at their data size, missing ones at a full LEB, without walking the span.
                    let present: Vec<u64> =
                        volume.lebs.range(..span).map(|(_, leb)| u64::from(leb.vid.data_size)).collect();
                    let missing = u64::from(span) - present.len() as u64;
                    let size = present.iter().sum::<u64>() + missing * volume.usable;
                    note.push(format!("static volume {}, {span} LEBs", volume.id));
                    let declared = volume.lebs.values().next().map_or(0, |leb| leb.vid.used_ebs);
                    if volume.lebs.values().any(|leb| leb.vid.used_ebs != declared) {
                        note.push(format!(
                            "LEBs disagree on the LEB count; LEB {} says {declared}",
                            volume.lebs.keys().next().unwrap_or(&0)
                        ));
                    }
                    if declared > volume.reserved {
                        note.push(format!("declares {declared} LEBs, more than the {} reserved", volume.reserved));
                    }
                    if missing > 0 {
                        note.push(format!("{missing} LEBs missing, content unreadable"));
                    }
                    size
                }
                _ => {
                    note.push(format!(
                        "dynamic volume {}, {} of {} LEBs mapped",
                        volume.id,
                        volume.lebs.len(),
                        volume.reserved
                    ));
                    if span as usize > volume.lebs.len() {
                        note.push("unmapped LEBs read as 0xFF".to_owned());
                    }
                    u64::from(span) * volume.usable
                }
            };
            if volume.update_interrupted {
                note.push("an update was interrupted: the content is incomplete".to_owned());
            }
            if let Some(first) = volume.lebs.get(&0) {
                let len = (volume.usable as usize).min(1088);
                let mut head = vec![0u8; len];
                let start = first.pnum * self.peb_size + self.data_offset;
                if self.source.read_at(start, &mut head).is_ok()
                    && let Some(format) = detect_bytes(&head)
                {
                    note.push(format!("holds {}", format.name()));
                }
            }
            // `<name>.img`, unless the name is empty, unsafe or taken.
            let simple = !volume.name.is_empty()
                && !volume.name.contains(['/', '\\', '\0'])
                && volume.name != "."
                && volume.name != "..";
            let mut path = format!("{}.img", volume.name);
            if !simple || names.contains(&path) {
                // `volume<id>.img`, then `volume<id>-2.img` and so on until no earlier volume has the name.
                path = format!("volume{}.img", volume.id);
                let mut suffix = 2;
                while names.contains(&path) {
                    path = format!("volume{}-{suffix}.img", volume.id);
                    suffix += 1;
                }
                note.push(format!("named {:?}", volume.name));
            }
            names.push(path.clone());
            self.entries.push(Entry {
                path,
                kind: EntryKind::Image,
                size: volume.size,
                mode: 0o644,
                uid: 0,
                gid: 0,
                link: None,
                note: Some(note.join("; ")),
            });
        }
        let used = self.volumes.iter().map(|volume| volume.lebs.len() as u64).sum::<u64>();
        self.notes = vec![
            format!("eraseblock size {}", self.peb_size),
            format!("LEB size {} (data offset {})", self.peb_size - self.data_offset, self.data_offset),
            format!("{} volumes", self.volumes.len()),
            format!("{pebs} eraseblocks: {used} in volumes, {} free", free + empty),
        ];
        let trailing = self.source.size() % self.peb_size;
        let mut odd = Vec::new();
        for (count, what) in [
            (damaged, "with damaged headers"),
            (foreign, "from another UBI image"),
            (stale, "older copies of a LEB"),
            (orphans, "of no volume in the table"),
        ] {
            if count > 0 {
                odd.push(format!("{count} {what}"));
            }
        }
        if !odd.is_empty() {
            self.notes.push(format!("eraseblocks ignored: {}", odd.join(", ")));
        }
        if trailing > 0 {
            self.notes.push(format!("{trailing} bytes after the last whole eraseblock ignored"));
        }
        Ok(())
    }
}

impl Image for Ubi {
    fn format(&self) -> Format {
        Format::Ubi
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let volume = self.volumes.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        let limit = budget.limits.max_file_bytes;
        if volume.size > limit {
            return Err(UnpackError::Limit(format!(
                "volume `{}` is {} bytes, more than max_file_bytes ({limit})",
                volume.name, volume.size
            )));
        }
        let mut buffer = vec![0u8; volume.usable as usize];
        for lnum in 0..volume.span() {
            let chunk = match volume.lebs.get(&lnum) {
                Some(leb) => {
                    let data_size = u64::from(leb.vid.data_size);
                    let len = if volume.vol_type == STATIC { data_size } else { volume.usable };
                    if len > volume.usable || data_size > volume.usable {
                        return Err(malformed(format!(
                            "LEB {lnum} of volume `{}` declares {data_size} bytes",
                            volume.name
                        )));
                    }
                    let start = self.data_range(leb, len)?;
                    let chunk = &mut buffer[..len as usize];
                    self.source.read_at(start, chunk).map_err(|error| UnpackError::io("read the image", error))?;
                    let checked = volume.vol_type == STATIC || leb.vid.copy_flag;
                    if checked && crc32(&chunk[..data_size as usize]) != leb.vid.data_crc {
                        return Err(malformed(format!("LEB {lnum} of volume `{}` fails its data CRC", volume.name)));
                    }
                    &buffer[..len as usize]
                }
                None if volume.vol_type == STATIC => {
                    return Err(malformed(format!("static volume `{}` is missing LEB {lnum}", volume.name)));
                }
                None => {
                    crate::limits::account(NOMINAL_UNMAPPED_INPUT, volume.usable)?;
                    buffer.fill(0xff);
                    &buffer[..]
                }
            };
            budget.charge_bytes(chunk.len() as u64)?;
            sink(chunk)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_ubi_convention() {
        // The CRC of nothing from an all-ones seed is the seed.
        assert_eq!(crc32(b""), 0xffff_ffff);
        assert_eq!(crc32(b"123456789"), !0xcbf4_3926);
    }
}
