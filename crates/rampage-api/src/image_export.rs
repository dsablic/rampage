//! `export_image`: the effective (patched) image written to a new file in its original container (Intel HEX,
//! S-record, the original binary file, or the native file) or as a flat binary.

use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

use rampage_loaders::raw_records::{
    MAX_RAW_RECORD_TEXT_BYTES, RawRecordFormat, parse_raw_records, rewrite_raw_records,
};
use rampage_loaders::{Binary, Format, RawRegionInfo, RawRegionKind, RawRegionSource};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::range_source::RangeSource;
use crate::{ApiError, MAX_PATCH_SOURCE_BYTES, PatchReceipt, Project};

/// Largest flat binary written: a gap between flash and a far region would otherwise fill gigabytes.
pub const MAX_FLAT_EXPORT_BYTES: u64 = 64 << 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportFormat {
    /// The container the image came from: Intel HEX or S-record text with only data records rewritten, the
    /// original binary file with the mapped ranges rewritten, or the native file's bytes.
    #[default]
    Original,
    /// Raw bytes: one region, or every non-RAM region laid out flat with `fill` in the gaps.
    Binary,
}

#[derive(Debug, Clone)]
pub struct ExportImageRequest {
    pub destination: PathBuf,
    pub format: ExportFormat,
    /// Binary format: the address of the one region to write.
    pub region: Option<u64>,
    /// Binary format: the byte between regions (default 0xff).
    pub fill: u8,
    /// PE: recompute the optional-header CheckSum in the written file.
    pub pe_checksum: bool,
    /// The reviewed patch revision; required when patches are active.
    pub expected_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportedRegion {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageExport {
    pub path: PathBuf,
    /// `ihex`, `srec`, `binary_file` (the original file rewritten), `native` or `flat_binary`.
    pub format: &'static str,
    pub size: u64,
    pub sha256: String,
    pub regions: Vec<ExportedRegion>,
    /// Record files: data records whose bytes changed and were re-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_rewritten: Option<usize>,
    /// Flat binary: the address of its first byte.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rampage_arch::hex::optional_address")]
    pub base_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_checksum: Option<PeChecksumUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<PatchReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeChecksumUpdate {
    pub old: String,
    pub new: String,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

/// A region to write: name, address, bytes and, for a Raw project, its region facts.
type Region<'a> = (String, u64, &'a [u8], Option<&'a RawRegionInfo>);

/// The backed regions of a Raw image with their bytes, or a native image's file-backed segments.
fn regions(binary: &Binary) -> Vec<Region<'_>> {
    if let Some(raw) = binary.raw_code_image() {
        return raw
            .regions()
            .iter()
            .filter(|region| region.backed())
            .map(|region| {
                (region.name.clone(), region.base_address, &binary.image_bytes()[region.data_range()], Some(region))
            })
            .collect();
    }
    binary
        .segments
        .iter()
        .filter(|segment| segment.file_size > 0)
        .filter_map(|segment| {
            binary
                .read(segment.address, segment.file_size)
                .map(|bytes| (segment.name.clone(), segment.address, bytes, None))
        })
        .collect()
}

/// An allocated section with file contents in a little-endian ELF32 image: where it runs and where it is loaded.
pub(crate) struct LoadSection {
    pub name: String,
    /// `sh_addr`.
    pub run: u64,
    /// The load address: its offset mapped through the PT_LOAD segment holding it, at that segment's `p_paddr`.
    pub load: u64,
    pub file: Range<usize>,
}

fn le(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(bytes.get(at..at.checked_add(width)?)?);
    Some(u64::from_le_bytes(value))
}

/// The allocated file-backed (non-NOBITS) sections of a little-endian ELF32 image at their load addresses, ascending,
/// as `objcopy -O binary` lays them out: headers, tables and bytes outside sections are left out. Each section's load
/// address is its file offset mapped through the PT_LOAD segment holding it, at the segment's `p_paddr` when the
/// segments' physical ranges are pairwise disjoint, else at `p_vaddr`; sections outside every segment's file bytes
/// are not loaded. `None` for any other image, or one without section and program headers (its segments then lay
/// out at their run addresses). Independent of patch admission; the tables are bounded and range-checked.
pub(crate) fn elf32_load_sections(bytes: &[u8]) -> Option<Result<Vec<LoadSection>, String>> {
    if bytes.get(..6) != Some(b"\x7fELF\x01\x01") {
        return None;
    }
    let (phoff, shoff) = (le(bytes, 28, 4)? as usize, le(bytes, 32, 4)? as usize);
    let (phnum, shnum, shstr) = (le(bytes, 44, 2)? as usize, le(bytes, 48, 2)? as usize, le(bytes, 50, 2)? as usize);
    if phnum == 0 || shnum == 0 || le(bytes, 42, 2)? != 32 || le(bytes, 46, 2)? != 40 || phnum > 1024 || shnum > 4096 {
        return None;
    }
    Some(
        load_sections(bytes, phoff, phnum, shoff, shnum, shstr)
            .unwrap_or_else(|| Err("unreadable ELF32 program or section headers".into())),
    )
}

fn load_sections(
    bytes: &[u8],
    phoff: usize,
    phnum: usize,
    shoff: usize,
    shnum: usize,
    shstr: usize,
) -> Option<Result<Vec<LoadSection>, String>> {
    // (file range, run address, physical address) of each PT_LOAD with file bytes.
    let mut loads = Vec::new();
    for index in 0..phnum {
        let at = phoff.checked_add(index * 32)?;
        if le(bytes, at, 4)? != 1 || le(bytes, at + 16, 4)? == 0 {
            continue;
        }
        let (offset, size) = (le(bytes, at + 4, 4)?, le(bytes, at + 16, 4)?);
        let end = offset.checked_add(size).filter(|&end| end <= bytes.len() as u64)?;
        loads.push((offset..end, le(bytes, at + 8, 4)?, le(bytes, at + 12, 4)?));
    }
    let physical = |(file, _, paddr): &(Range<u64>, u64, u64)| *paddr..paddr + (file.end - file.start);
    let use_physical = loads.iter().enumerate().all(|(index, left)| {
        loads[index + 1..].iter().all(|right| {
            let (left, right) = (physical(left), physical(right));
            left.end <= right.start || right.end <= left.start
        })
    });
    let names = (shstr < shnum).then(|| {
        let at = shoff.checked_add(shstr * 40)?;
        let (offset, size) = (le(bytes, at + 16, 4)? as usize, le(bytes, at + 20, 4)? as usize);
        bytes.get(offset..offset.checked_add(size)?)
    });
    let mut sections = Vec::new();
    for index in 0..shnum {
        let at = shoff.checked_add(index * 40)?;
        let (kind, flags, run) = (le(bytes, at + 4, 4)?, le(bytes, at + 8, 4)?, le(bytes, at + 12, 4)?);
        let (offset, size) = (le(bytes, at + 16, 4)?, le(bytes, at + 20, 4)?);
        if kind == 0 || kind == 8 || flags & 2 == 0 || size == 0 {
            continue;
        }
        let file = offset..offset.checked_add(size)?;
        let Some((segment, vaddr, paddr)) =
            loads.iter().find(|(segment, ..)| segment.start <= file.start && file.end <= segment.end)
        else {
            continue;
        };
        let base = if use_physical { *paddr } else { *vaddr };
        let name = names
            .flatten()
            .and_then(|names| {
                let name = names.get(le(bytes, at, 4)? as usize..)?;
                let end = name.iter().take(256).position(|&byte| byte == 0)?;
                String::from_utf8(name[..end].to_vec()).ok()
            })
            .unwrap_or_else(|| format!("section{index}"));
        sections.push(LoadSection {
            name,
            run,
            load: base + (file.start - segment.start),
            file: file.start as usize..file.end as usize,
        });
    }
    sections.sort_by_key(|section| section.load);
    if sections.windows(2).any(|pair| pair[0].load + pair[0].file.len() as u64 > pair[1].load) {
        return Some(Err("ELF32 sections overlap at their load addresses".into()));
    }
    Some(Ok(sections))
}

/// The regions a flat binary lays out: a little-endian ELF32 image's allocated sections at their load addresses, as a
/// flash programmer writes them (firmware `.data` initial values follow the code), else `regions`.
fn load_regions(binary: &Binary) -> Result<Vec<Region<'_>>, ApiError> {
    let bytes = binary.file_bytes();
    let Some(sections) = (binary.format == Format::Elf).then(|| elf32_load_sections(bytes)).flatten() else {
        return Ok(regions(binary));
    };
    Ok(sections
        .map_err(invalid)?
        .into_iter()
        .map(|section| (section.name, section.load, &bytes[section.file], None))
        .collect())
}

impl Project {
    /// Writes this effective image to a new file (never replacing one) and reports its hash and regions.
    /// The reviewed revision is checked under the annotation writer against the authoritative patch log, which
    /// this held view must also match, and the file is published before the lock is released.
    pub fn export_image(self: &Arc<Self>, request: &ExportImageRequest) -> Result<ImageExport, ApiError> {
        let held = self.patch_receipt().ok().map(|held| held.revision_sha256);
        self.under_patch_authority(|receipt| {
            if held != receipt.as_ref().map(|receipt| receipt.revision_sha256.clone()) {
                return Err(invalid("the held view is not the current patch revision; acquire a new receipt"));
            }
            self.export_image_under(request, receipt)
        })
    }

    fn export_image_under(
        self: &Arc<Self>,
        request: &ExportImageRequest,
        receipt: Option<PatchReceipt>,
    ) -> Result<ImageExport, ApiError> {
        let source = self.patch_source();
        match (&receipt, &request.expected_revision) {
            (Some(receipt), Some(expected)) if &receipt.revision_sha256 != expected => {
                return Err(invalid("patch revision changed since review; acquire a new receipt"));
            }
            (Some(receipt), None) if receipt.active_ranges > 0 => {
                return Err(invalid(
                    "patches are active: pass expected_revision from list_patches or integrity_checks",
                ));
            }
            (None, Some(_)) => return Err(invalid("this image takes no patches; omit expected_revision")),
            _ => {}
        }
        if request.pe_checksum && self.binary.format != Format::Pe {
            return Err(invalid("pe_checksum applies to PE images only"));
        }
        let mut regions_out: Vec<ExportedRegion> = regions(&self.binary)
            .into_iter()
            .map(|(name, start, bytes, _)| ExportedRegion {
                name,
                start,
                end: start + bytes.len() as u64,
                sha256: digest(bytes),
            })
            .collect();
        let mut records_rewritten = None;
        let mut base_address = None;
        let mut pe = None;
        let (format, mut bytes) = match request.format {
            ExportFormat::Binary => {
                let mut chosen = load_regions(&self.binary)?;
                match request.region {
                    Some(address) => {
                        chosen.retain(|(_, start, bytes, _)| (*start..*start + bytes.len() as u64).contains(&address));
                        if chosen.is_empty() {
                            return Err(invalid(format!("no backed region holds {address:#x}")));
                        }
                    }
                    None => {
                        chosen.retain(|(_, _, _, region)| region.is_none_or(|region| region.kind != RawRegionKind::Ram))
                    }
                }
                chosen.sort_by_key(|(_, start, _, _)| *start);
                let (Some(first), Some(last)) = (chosen.first(), chosen.last()) else {
                    return Err(invalid("the image has no backed bytes to write"));
                };
                let base = first.1;
                let size = last.1 + last.2.len() as u64 - base;
                if size > MAX_FLAT_EXPORT_BYTES {
                    return Err(invalid(format!(
                        "a flat image from {base:#x} spans {size} bytes, over {MAX_FLAT_EXPORT_BYTES}; pass region"
                    )));
                }
                let mut flat = vec![request.fill; size as usize];
                for (_, start, region, _) in &chosen {
                    let at = (start - base) as usize;
                    flat[at..at + region.len()].copy_from_slice(region);
                }
                regions_out = chosen
                    .iter()
                    .map(|(name, start, bytes, _)| ExportedRegion {
                        name: name.clone(),
                        start: *start,
                        end: start + bytes.len() as u64,
                        sha256: digest(bytes),
                    })
                    .collect();
                base_address = Some(base);
                ("flat_binary", flat)
            }
            ExportFormat::Original if self.binary.format == Format::Raw => {
                let path = source
                    .raw_source
                    .get()
                    .ok_or_else(|| invalid("this Raw project has no source file; use format binary"))?;
                let original = regions(&source.binary);
                let effective = regions(&self.binary);
                let record_format = original.iter().find_map(|(_, _, _, region)| match (*region)?.source {
                    Some(RawRegionSource::Records { format }) => Some(format),
                    _ => None,
                });
                match record_format {
                    Some(format) => {
                        let file = RangeSource::open_sized(path, 0, |size| {
                            usize::try_from(size)
                                .ok()
                                .filter(|&size| (1..=MAX_RAW_RECORD_TEXT_BYTES).contains(&size))
                                .ok_or_else(|| invalid("record file size changed or exceeds the record budget"))
                        })?;
                        let text = file.read()?;
                        file.revalidate()?;
                        // The file must still hold exactly the runs the project admitted.
                        let runs = parse_raw_records(&text, format, usize::MAX)
                            .map_err(|source| ApiError::Load { path: path.clone(), source })?
                            .runs;
                        for (name, start, bytes, region) in &original {
                            if matches!(
                                region.and_then(|region| region.source.as_ref()),
                                Some(RawRegionSource::Records { .. })
                            ) && !runs.iter().any(|(run, run_bytes)| run == start && run_bytes.as_slice() == *bytes)
                            {
                                return Err(invalid(format!(
                                    "{} no longer holds region {name} as admitted",
                                    path.display()
                                )));
                            }
                        }
                        let current = |address: u64, length: usize| {
                            effective.iter().find_map(|(_, start, bytes, _)| {
                                let offset = address.checked_sub(*start)? as usize;
                                bytes.get(offset..offset + length).map(<[u8]>::to_vec)
                            })
                        };
                        let (text, count) = rewrite_raw_records(&text, format, current)
                            .map_err(|source| ApiError::Load { path: path.clone(), source })?;
                        records_rewritten = Some(count);
                        (if format == RawRecordFormat::Ihex { "ihex" } else { "srec" }, text)
                    }
                    None => {
                        let file = RangeSource::open_sized(path, 0, |size| {
                            usize::try_from(size)
                                .ok()
                                .filter(|&size| (1..=MAX_PATCH_SOURCE_BYTES).contains(&size))
                                .ok_or_else(|| invalid("source file size exceeds the export budget"))
                        })?;
                        let mut bytes = file.read()?;
                        file.revalidate()?;
                        for ((name, _, original, region), (_, _, patched, _)) in original.iter().zip(&effective) {
                            let Some(RawRegionSource::FileRange { offset, length }) =
                                region.and_then(|region| region.source.clone())
                            else {
                                continue;
                            };
                            let range = offset as usize..(offset + length) as usize;
                            if bytes.get(range.clone()) != Some(*original) {
                                return Err(invalid(format!(
                                    "{} no longer holds region {name} as admitted",
                                    path.display()
                                )));
                            }
                            bytes[range].copy_from_slice(patched);
                        }
                        ("binary_file", bytes)
                    }
                }
            }
            ExportFormat::Original => ("native", self.binary.file_bytes().to_vec()),
        };
        if request.pe_checksum {
            if format != "native" {
                return Err(invalid("pe_checksum needs format original"));
            }
            let field = crate::integrity::pe_checksum_offset(&bytes).ok_or_else(|| invalid("no PE optional header"))?;
            let old = rampage_arch::hex::bytes(&bytes[field..field + 4]);
            let value = crate::integrity::pe_checksum(&bytes, field).to_le_bytes();
            bytes[field..field + 4].copy_from_slice(&value);
            pe = Some(PeChecksumUpdate { old, new: rampage_arch::hex::bytes(&value) });
        }
        crate::patches::publish_export(&request.destination, &bytes, |file, bytes| {
            use std::io::Write;
            file.write_all(bytes)?;
            file.sync_all()
        })?;
        Ok(ImageExport {
            path: request.destination.clone(),
            format,
            size: bytes.len() as u64,
            sha256: digest(&bytes),
            regions: regions_out,
            records_rewritten,
            base_address,
            pe_checksum: pe,
            receipt,
        })
    }
}
