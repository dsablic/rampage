use rampage_loaders::{Details, ImageAt};

use super::{MAX_PLUGIN_TRIAGE_SOURCE_BYTES, invalid};
use crate::{ApiError, Project};

mod pe;

const MAX_PRELOAD_NAME_WORK: usize = 64 * 1024 * 1024;

pub(super) fn reject_loaded_managed(project: &Project) -> Result<(), ApiError> {
    let bytes = project.binary.image_bytes();
    if bytes.len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
        return Err(invalid("plugin triage source exceeds 16 MiB"));
    }
    reject_clr(bytes)?;
    if matches!(&project.binary.details, Details::Pe(details) if details.dotnet) {
        return Err(managed());
    }
    Ok(())
}

fn managed() -> ApiError {
    ApiError::Unavailable("managed CLR sources are not admitted by native plugin triage preparation".into())
}

/// Constant-space PE directory inspection. No CLI metadata tables, heaps, blobs or methods are parsed.
pub(super) fn reject_clr(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return Ok(());
    }
    let pe = u32_at(bytes, 0x3c)? as usize;
    if span(bytes, pe, 24)?.get(..4) != Some(b"PE\0\0".as_slice()) {
        return Err(invalid("invalid PE header during managed-source preflight"));
    }
    let optional = pe.checked_add(24).ok_or_else(|| invalid("PE offset overflow"))?;
    let header = span(bytes, optional, u16_at(bytes, pe + 20)? as usize)?;
    let (count_offset, directory_offset) = match u16_at(header, 0)? {
        0x10b => (92, 96),
        0x20b => (108, 112),
        _ => return Err(invalid("unsupported PE optional header during managed-source preflight")),
    };
    if u32_at(header, count_offset)? > 14 {
        let directory = directory_offset + 14 * 8;
        if u32_at(header, directory)? != 0 || u32_at(header, directory + 4)? != 0 {
            return Err(managed());
        }
    }
    Ok(())
}

pub(super) fn admit_before_load(bytes: &[u8], image: Option<ImageAt>) -> Result<(), ApiError> {
    let bytes = match image.filter(|image| !image.is_whole_file()) {
        Some(image) => {
            let offset = usize::try_from(image.offset()).map_err(|_| invalid("image offset is not addressable"))?;
            let length = image
                .length()
                .map(usize::try_from)
                .transpose()
                .map_err(|_| invalid("image length is not addressable"))?
                .unwrap_or_else(|| bytes.len().saturating_sub(offset));
            span(bytes, offset, length)?
        }
        None => bytes,
    };
    reject_clr(bytes)?;
    // Other native loaders have not yet acquired a raw metadata amplification admission contract. Refuse
    // rather than invoke them and pretend a later serialized-facts check bounded their allocations.
    if bytes.get(..2) == Some(b"MZ".as_slice()) {
        if image.is_some_and(|image| !image.is_whole_file()) {
            return Err(invalid("embedded PE selection is outside plugin preload admission"));
        }
        return pe::admit(bytes);
    }
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) || u16_at(bytes, 18)? != 62 {
        return Err(ApiError::Unavailable(
            "preload metadata admission supports only conservative little-endian x86-64 ELF and PE profiles".into(),
        ));
    }
    if !matches!(u16_at(bytes, 16)?, 2 | 3) {
        return Err(invalid("plugin source preloading requires an ELF executable or shared image"));
    }
    admit_elf64(bytes)
}

fn admit_elf64(bytes: &[u8]) -> Result<(), ApiError> {
    span(bytes, 0, 64)?;
    let program = usize_at(bytes, 32)?;
    let sections = usize_at(bytes, 40)?;
    let program_count = u16_at(bytes, 56)? as usize;
    let section_count = u16_at(bytes, 60)? as usize;
    let strings_index = u16_at(bytes, 62)? as usize;
    if u16_at(bytes, 52)? != 64
        || u16_at(bytes, 54)? != 56
        || u16_at(bytes, 58)? != 64
        || section_count == 0
        || section_count >= 0xff00
        || program_count == 0xffff
        || strings_index >= section_count
    {
        return Err(invalid("extended or noncanonical ELF headers are outside plugin preload admission"));
    }
    span(bytes, program, program_count * 56)?;
    span(bytes, sections, section_count * 64)?;
    let section = |index: usize| -> Result<&[u8], ApiError> {
        if index >= section_count {
            return Err(invalid("ELF section link is out of range"));
        }
        span(bytes, sections + index * 64, 64)
    };
    let section_bytes = |header: &[u8]| span(bytes, usize_at(header, 24)?, usize_at(header, 32)?);
    let names = section_bytes(section(strings_index)?)?;
    if u32_at(section(strings_index)?, 4)? != 3 {
        return Err(invalid("ELF section names must use an admitted string table"));
    }
    let mut records = program_count + section_count;
    let mut named_records = records;
    let mut table_bytes = 0usize;
    for index in 0..section_count {
        let header = section(index)?;
        let name = c_string(names, u32_at(header, 0)? as usize)?;
        if name.contains("gopclntab") {
            return Err(invalid("Go recovery metadata is outside plugin preload admission"));
        }
        let kind = u32_at(header, 4)?;
        if name == "__eh_frame" {
            return Err(invalid("unwind alias __eh_frame is outside canonical preload admission"));
        }
        if name == ".eh_frame" {
            if kind != 1 {
                return Err(invalid("unwind metadata must be file-backed PROGBITS, never NOBITS"));
            }
            admit_unwind_mapping(bytes, header, program, program_count)?;
        }
        if kind == 8 {
            continue;
        }
        let data = section_bytes(header)?;
        if kind == 7 && data.len() > rampage_plugin_contract::MAX_TEXT_BYTES / 2 {
            return Err(invalid("ELF note/build identity exceeds preload text admission"));
        }
        table_bytes = table_bytes.checked_add(data.len()).ok_or_else(|| invalid("ELF table budget overflow"))?;
        let (row_size, copies) = match kind {
            2 | 11 => (24, 3),
            4 => (24, 2),
            9 => (16, 2),
            6 => (16, 1),
            0x6fff_ffff => (2, 0),
            0x6fff_fffd | 0x6fff_fffe => (4, 1),
            7 => (4, 0),
            _ if name == ".eh_frame" => (4, 0),
            _ => (data.len().max(1), 0),
        };
        let rows = data.len() / row_size;
        records = records.checked_add(rows).ok_or_else(|| invalid("ELF record budget overflow"))?;
        named_records =
            named_records.checked_add(rows * copies).ok_or_else(|| invalid("ELF name-work budget overflow"))?;
        if matches!(name, ".plt" | ".plt.sec" | ".plt.got" | ".iplt" | "__stubs" | "__auth_stubs") {
            // Project construction names import stubs before API admission. One name per input byte is a
            // deliberately conservative bound, including attacker-chosen instruction/stub boundaries.
            records = records.checked_add(data.len()).ok_or_else(|| invalid("ELF stub record overflow"))?;
            named_records = named_records.checked_add(data.len()).ok_or_else(|| invalid("ELF stub work overflow"))?;
        }
        if records > rampage_plugin_contract::MAX_RECORDS || table_bytes > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
            return Err(invalid("ELF metadata exceeds pre-loader record or overlapping-span budget"));
        }
        if matches!(kind, 2 | 11 | 4 | 9 | 6) && (usize_at(header, 56)? != row_size || data.len() % row_size != 0) {
            return Err(invalid("noncanonical ELF metadata rows are outside preload admission"));
        }
        if matches!(kind, 2 | 11 | 6 | 0x6fff_fffd | 0x6fff_fffe) {
            let strings_header = section(u32_at(header, 40)? as usize)?;
            if u32_at(strings_header, 4)? != 3 {
                return Err(invalid("ELF symbol/dynamic names must use an admitted string table"));
            }
            let strings = section_bytes(strings_header)?;
            if matches!(kind, 0x6fff_fffd | 0x6fff_fffe) {
                admit_versions(data, strings, kind, u32_at(header, 44)? as usize, &mut records, &mut named_records)?;
            } else if kind == 6 {
                let value = |tag| -> Result<Option<usize>, ApiError> {
                    for entry in data.as_chunks::<16>().0 {
                        if usize_at(entry, 0)? == 0 {
                            break;
                        }
                        if usize_at(entry, 0)? == tag {
                            return Ok(Some(usize_at(entry, 8)?));
                        }
                    }
                    Ok(None)
                };
                if value(5)? != Some(usize_at(strings_header, 16)?) || value(10)? != Some(strings.len()) {
                    return Err(invalid("ELF dynamic string mapping is outside preload admission"));
                }
                for entry in data.as_chunks::<16>().0 {
                    if usize_at(entry, 0)? == 0 {
                        break;
                    }
                    if matches!(usize_at(entry, 0)?, 1 | 14 | 15 | 29) {
                        c_string(strings, usize_at(entry, 8)?)?;
                    }
                }
            } else {
                for entry in data.as_chunks::<24>().0 {
                    c_string(strings, u32_at(entry, 0)? as usize)?;
                }
            }
        }
        if kind == 3 {
            for text in data.split(|byte| *byte == 0) {
                if text.len() > rampage_plugin_contract::MAX_TEXT_BYTES || std::str::from_utf8(text).is_err() {
                    return Err(invalid("ELF string table exceeds preload text admission"));
                }
            }
        }
    }
    let work = bytes.len().checked_mul(named_records).and_then(|work| work.checked_mul(8));
    if work.is_none_or(|work| work > MAX_PRELOAD_NAME_WORK) {
        return Err(invalid("ELF repeated-name expansion exceeds pre-loader work admission"));
    }
    // Hidden Go recovery scans data sections even without a named pclntab section. Reject candidate magics
    // conservatively; this source lane does not run that producer merely to discover it was too large.
    for header in bytes.windows(8) {
        if matches!(header, [0xfb | 0xfa | 0xf0 | 0xf1, 0xff, 0xff, 0xff, 0, 0, 1 | 2 | 4, 8]) {
            return Err(invalid("possible Go recovery table is outside plugin preload admission"));
        }
    }
    for index in 0..program_count {
        let header = span(bytes, program + index * 56, 56)?;
        let data = span(bytes, usize_at(header, 8)?, usize_at(header, 32)?)?;
        match u32_at(header, 0)? {
            3 if data.len() > rampage_plugin_contract::MAX_TEXT_BYTES => {
                return Err(invalid("ELF interpreter exceeds preload text admission"));
            }
            3 if std::str::from_utf8(data).is_err() => {
                return Err(invalid("ELF interpreter exceeds preload text admission"));
            }
            4 if data.len() > rampage_plugin_contract::MAX_TEXT_BYTES / 2 => {
                return Err(invalid("ELF note/build identity exceeds preload text admission"));
            }
            2 => {
                // Native details use PT_DYNAMIC, not necessarily SHT_DYNAMIC. Require the exact same table.
                let found = (0..section_count).any(|index| {
                    section(index).is_ok_and(|section| {
                        u32_at(section, 4).ok() == Some(6)
                            && usize_at(section, 24).ok() == usize_at(header, 8).ok()
                            && usize_at(section, 32).ok() == usize_at(header, 32).ok()
                    })
                });
                if !found {
                    return Err(invalid("unaccounted ELF dynamic segment is outside preload admission"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn c_string(bytes: &[u8], offset: usize) -> Result<&str, ApiError> {
    let tail = bytes.get(offset..).ok_or_else(|| invalid("ELF string offset is out of range"))?;
    let length = tail
        .iter()
        .take(rampage_plugin_contract::MAX_TEXT_BYTES + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("ELF name is unbounded or unterminated"))?;
    std::str::from_utf8(&tail[..length]).map_err(|_| invalid("ELF preload names must be UTF-8"))
}

/// Native starts::eh_frame reads by sh_addr through PT_LOAD, not by sh_offset. Only admit a single exact,
/// fully file-backed mapping for that complete span, so the bytes counted above are the bytes it consumes.
fn admit_unwind_mapping(bytes: &[u8], section: &[u8], program: usize, program_count: usize) -> Result<(), ApiError> {
    let address = usize_at(section, 16)?;
    let offset = usize_at(section, 24)?;
    let length = usize_at(section, 32)?;
    if length == 0 {
        return Err(invalid("empty unwind spans are outside canonical preload admission"));
    }
    let end = address.checked_add(length).ok_or_else(|| invalid("unwind address overflow"))?;
    let mut overlaps = 0;
    for index in 0..program_count {
        let load = span(bytes, program + index * 56, 56)?;
        if u32_at(load, 0)? != 1 {
            continue;
        }
        let start = usize_at(load, 16)?;
        let memory = usize_at(load, 40)?;
        let memory_end = start.checked_add(memory).ok_or_else(|| invalid("load address overflow"))?;
        if memory == 0 || start >= end || memory_end <= address {
            continue;
        }
        overlaps += 1;
        if overlaps > 1 || address < start {
            return Err(invalid("unwind span has ambiguous or partial PT_LOAD backing"));
        }
        let delta = address - start;
        let backed = usize_at(load, 32)?.min(memory);
        if delta.checked_add(length).is_none_or(|end| end > backed) {
            return Err(invalid("unwind span crosses a PT_LOAD boundary or zero-fill tail"));
        }
        let backing = usize_at(load, 8)?.checked_add(delta).ok_or_else(|| invalid("unwind file offset overflow"))?;
        if backing != offset {
            return Err(invalid("unwind sh_offset does not match the PT_LOAD span consumed through sh_addr"));
        }
        span(bytes, backing, length)?;
    }
    if overlaps != 1 {
        return Err(invalid("unwind span requires exactly one file-backed PT_LOAD mapping"));
    }
    Ok(())
}

fn admit_versions(
    data: &[u8],
    strings: &[u8],
    kind: u32,
    declared_headers: usize,
    records: &mut usize,
    named_records: &mut usize,
) -> Result<(), ApiError> {
    let definitions = kind == 0x6fff_fffd;
    let header_size = if definitions { 20 } else { 16 };
    let auxiliary_size = if definitions { 8 } else { 16 };
    let mut offset = 0usize;
    let mut headers = 0usize;
    loop {
        let header = span(data, offset, header_size)?;
        let count = u16_at(header, if definitions { 6 } else { 2 })? as usize;
        if count == 0 {
            return Err(invalid("empty ELF version auxiliary chain is not admitted"));
        }
        *records = records.checked_add(count + 1).ok_or_else(|| invalid("ELF version record overflow"))?;
        *named_records = named_records.checked_add(count + 1).ok_or_else(|| invalid("ELF version work overflow"))?;
        if *records > rampage_plugin_contract::MAX_RECORDS {
            return Err(invalid("ELF declared version counts exceed pre-loader admission"));
        }
        if !definitions {
            c_string(strings, u32_at(header, 4)? as usize)?;
        }
        let auxiliary = u32_at(header, if definitions { 12 } else { 8 })? as usize;
        if auxiliary < header_size {
            return Err(invalid("ELF version chain overlaps its header"));
        }
        let mut current = offset.checked_add(auxiliary).ok_or_else(|| invalid("ELF version offset overflow"))?;
        for index in 0..count {
            let entry = span(data, current, auxiliary_size)?;
            c_string(strings, u32_at(entry, if definitions { 0 } else { 8 })? as usize)?;
            let next = u32_at(entry, if definitions { 4 } else { 12 })? as usize;
            if index + 1 == count {
                if next != 0 {
                    return Err(invalid("ELF version auxiliary count is not exhaustive"));
                }
            } else {
                if next < auxiliary_size {
                    return Err(invalid("ELF version auxiliary chain is not forward-only"));
                }
                current = current.checked_add(next).ok_or_else(|| invalid("ELF version offset overflow"))?;
            }
        }
        headers += 1;
        let next = u32_at(header, if definitions { 16 } else { 12 })? as usize;
        if next == 0 {
            break;
        }
        if next < header_size {
            return Err(invalid("ELF version header chain is not forward-only"));
        }
        offset = offset.checked_add(next).ok_or_else(|| invalid("ELF version offset overflow"))?;
    }
    if headers != declared_headers {
        return Err(invalid("ELF version header count is not exhaustive"));
    }
    Ok(())
}

fn span(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], ApiError> {
    let end = offset.checked_add(length).ok_or_else(|| invalid("preload span overflow"))?;
    bytes.get(offset..end).ok_or_else(|| invalid("preload span is outside the retained source"))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ApiError> {
    Ok(u16::from_le_bytes(span(bytes, offset, 2)?.try_into().map_err(|_| invalid("invalid u16"))?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ApiError> {
    Ok(u32::from_le_bytes(span(bytes, offset, 4)?.try_into().map_err(|_| invalid("invalid u32"))?))
}

fn usize_at(bytes: &[u8], offset: usize) -> Result<usize, ApiError> {
    let value = u64::from_le_bytes(span(bytes, offset, 8)?.try_into().map_err(|_| invalid("invalid u64"))?);
    usize::try_from(value).map_err(|_| invalid("preload offset is not addressable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNWIND_NAMES: &[u8] = b"\0.shstrtab\0.eh_frame\0__eh_frame\0";

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
        std::fs::read(path).unwrap()
    }

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }

    fn unwind_elf(cies: usize) -> Vec<u8> {
        let names = UNWIND_NAMES;
        let length = 0x200 + cies * 16;
        let mut bytes = vec![0; length];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 32, 64);
        put64(&mut bytes, 40, 0x100);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 1);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 3);
        put16(&mut bytes, 62, 1);
        put32(&mut bytes, 64, 1);
        put32(&mut bytes, 68, 4);
        put64(&mut bytes, 64 + 16, 0x1000);
        put64(&mut bytes, 64 + 32, length);
        put64(&mut bytes, 64 + 40, length);
        put32(&mut bytes, 0x140, 1);
        put32(&mut bytes, 0x144, 3);
        put64(&mut bytes, 0x140 + 24, 0xc0);
        put64(&mut bytes, 0x140 + 32, names.len());
        bytes[0xc0..0xc0 + names.len()].copy_from_slice(names);
        let unwind_name = names.windows(10).position(|name| name == b".eh_frame\0").unwrap();
        put32(&mut bytes, 0x180, unwind_name as u32);
        put32(&mut bytes, 0x184, 1);
        put64(&mut bytes, 0x180 + 16, 0x1200);
        put64(&mut bytes, 0x180 + 24, 0x200);
        put64(&mut bytes, 0x180 + 32, cies * 16);
        // Each record is a version-1 CIE, not an FDE. Native parsing retains one CIE entry per record.
        for cie in bytes[0x200..].as_chunks_mut::<16>().0 {
            cie.copy_from_slice(&[12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0, 0, 0]);
        }
        bytes
    }

    #[test]
    fn unwind_alias_and_nobits_cannot_hide_cie_records_from_preload_budget() {
        admit_before_load(&unwind_elf(512), None).unwrap();
        let excessive = unwind_elf(rampage_plugin_contract::MAX_RECORDS + 1);
        assert!(admit_before_load(&excessive, None).unwrap_err().to_string().contains("record"));

        let mut alias = excessive.clone();
        let names = &alias[0xc0..0xc0 + UNWIND_NAMES.len()];
        let index = names.windows(11).position(|name| name == b"__eh_frame\0").unwrap();
        put32(&mut alias, 0x180, index as u32);
        assert!(admit_before_load(&alias, None).unwrap_err().to_string().contains("alias __eh_frame"));

        let mut nobits = excessive;
        put32(&mut nobits, 0x184, 8);
        assert!(admit_before_load(&nobits, None).unwrap_err().to_string().contains("never NOBITS"));
    }

    #[test]
    fn unwind_budget_matches_exact_native_address_mapping_not_other_section_bytes() {
        let mut different_offset = unwind_elf(512);
        // Native sh_addr still reads the CIE array, while the declared file offset names different bytes.
        put64(&mut different_offset, 0x180 + 24, 0xc0);
        assert!(admit_before_load(&different_offset, None).unwrap_err().to_string().contains("sh_offset"));

        let mut wrong_address = unwind_elf(512);
        put64(&mut wrong_address, 0x180 + 16, 0x1100);
        assert!(admit_before_load(&wrong_address, None).unwrap_err().to_string().contains("sh_offset"));

        let mut zero_fill = unwind_elf(512);
        let length = zero_fill.len();
        put64(&mut zero_fill, 64 + 40, length + 8192);
        put64(&mut zero_fill, 0x180 + 16, 0x1000 + length);
        assert!(admit_before_load(&zero_fill, None).unwrap_err().to_string().contains("zero-fill"));

        let mut ambiguous = unwind_elf(512);
        let load = ambiguous[64..120].to_vec();
        ambiguous[120..176].copy_from_slice(&load);
        put16(&mut ambiguous, 56, 2);
        assert!(admit_before_load(&ambiguous, None).unwrap_err().to_string().contains("ambiguous"));
    }

    #[test]
    fn clr_preflight_refuses_the_directory_without_managed_table_or_blob_parsing() {
        let bytes = fixture("Microsoft.Bcl.HashCode.dll");
        assert!(reject_clr(&bytes).unwrap_err().to_string().contains("managed CLR"));
        assert!(admit_before_load(&bytes, None).unwrap_err().to_string().contains("managed CLR"));
        let mut truncated = bytes;
        truncated.truncate(64);
        assert!(reject_clr(&truncated).is_err());
    }

    #[test]
    fn unreviewed_native_loader_profiles_and_hidden_go_recovery_are_not_invoked() {
        admit_before_load(&fixture("hello-x64.exe"), None).unwrap();
        assert!(admit_before_load(&fixture("hello-x64.macho"), None).is_err());
        assert!(admit_before_load(&fixture("hello-go-x64.elf"), None).is_err());
    }

    #[test]
    fn malformed_or_extended_metadata_is_rejected_before_native_loading() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/net-client-x64.elf");
        let bytes = std::fs::read(path).unwrap();
        admit_before_load(&bytes, None).unwrap();
        let mut extended = bytes.clone();
        extended[60..62].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(admit_before_load(&extended, None).is_err());
        let mut table_outside = bytes;
        table_outside[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(admit_before_load(&table_outside, None).is_err());
    }
}
