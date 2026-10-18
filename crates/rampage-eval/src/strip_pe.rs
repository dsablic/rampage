use std::ops::Range;

use object::{Object, ObjectSection};

const MAX_BYTES: usize = 256 * 1024 * 1024;

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(bytes.get(at..at + 2).ok_or("truncated PE field")?.try_into().unwrap()))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(bytes.get(at..at + 4).ok_or("truncated PE field")?.try_into().unwrap()))
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Exact PE32+ x64 copy: only terminal COFF symbols/strings and their two header fields may disappear.
/// RSDS linkage may remain: no PDB is opened and it contains no function names or ranges.
pub(crate) fn strip_pe(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_BYTES || bytes.get(..2) != Some(b"MZ") {
        return Err("requires a bounded PE32+ x64 image".into());
    }
    let pe = u32_at(bytes, 0x3c)? as usize;
    if pe > bytes.len().saturating_sub(24)
        || bytes.get(pe..pe + 4) != Some(b"PE\0\0")
        || u16_at(bytes, pe + 4)? != 0x8664
    {
        return Err("requires PE32+ x64 headers".into());
    }
    let optional = pe + 24;
    let optional_size = usize::from(u16_at(bytes, pe + 20)?);
    if optional_size < 112 || u16_at(bytes, optional)? != 0x20b {
        return Err("requires a complete PE32+ optional header".into());
    }
    let section_count = usize::from(u16_at(bytes, pe + 6)?);
    if section_count == 0 || section_count > 4096 {
        return Err("PE section count exceeds bounds".into());
    }
    let table = optional + optional_size;
    let headers_end = table.checked_add(section_count * 40).ok_or("PE section table overflows")?;
    if headers_end > bytes.len() || u32_at(bytes, optional + 60)? as usize > bytes.len() {
        return Err("truncated PE headers".into());
    }
    let directory_count = u32_at(bytes, optional + 108)? as usize;
    if directory_count > 16 || optional_size < 112 + directory_count * 8 {
        return Err("unsupported PE data directory extent".into());
    }
    let file = object::File::parse(bytes).map_err(|error| error.to_string())?;
    let mut mapped = Vec::new();
    let mut debug_ranges = Vec::new();
    for section in file.sections() {
        let name = section.name().map_err(|error| error.to_string())?;
        if name.starts_with(".debug") || name.starts_with(".zdebug") || name.starts_with(".stab") {
            return Err("embedded function debug metadata is unsupported; use an explicit matched PDB".into());
        }
        if let Some((start, size)) = section.file_range() {
            let end = start.checked_add(size).ok_or("PE raw section overflows")?;
            if end > bytes.len() as u64 || (size > 0 && start < headers_end as u64) {
                return Err("invalid PE raw section backing".into());
            }
            let range = start as usize..end as usize;
            if mapped.iter().any(|previous| overlaps(previous, &range)) {
                return Err("overlapping PE raw sections".into());
            }
            mapped.push(range);
        }
    }
    // Only RSDS linkage and reproducible-build records are admitted, never embedded symbol formats.
    if directory_count > 6 {
        let rva = u32_at(bytes, optional + 112 + 6 * 8)?;
        let size = u32_at(bytes, optional + 116 + 6 * 8)? as usize;
        if size != 0 {
            if size > 64 * 28 || !size.is_multiple_of(28) {
                return Err("invalid PE debug directory size".into());
            }
            let data = file
                .sections()
                .find_map(|section| {
                    let offset =
                        u64::from(rva).checked_add(file.relative_address_base())?.checked_sub(section.address())?;
                    let offset = usize::try_from(offset).ok()?;
                    section.data().ok()?.get(offset..offset.checked_add(size)?)
                })
                .ok_or("unbacked PE debug directory")?;
            for record in data.as_chunks::<28>().0 {
                let kind = u32_at(record, 12)?;
                let length = u32_at(record, 16)? as usize;
                let offset = u32_at(record, 24)? as usize;
                let payload = bytes
                    .get(offset..offset.checked_add(length).ok_or("debug range overflow")?)
                    .ok_or("unbacked PE debug record")?;
                debug_ranges.push(offset..offset + length);
                if kind == 2 {
                    if length > 4096
                        || payload.get(..4) != Some(b"RSDS")
                        || payload.get(24..).is_none_or(|path| !path.contains(&0))
                    {
                        return Err("only complete RSDS debug linkage is supported".into());
                    }
                } else if kind != 16 {
                    return Err("embedded PE debug record is not linkage-only".into());
                }
            }
        } else if rva != 0 {
            return Err("inconsistent PE debug directory".into());
        }
    }
    let pointer = u32_at(bytes, pe + 12)? as usize;
    let count = u32_at(bytes, pe + 16)? as usize;
    if pointer == 0 && count == 0 {
        return Ok(bytes.to_vec());
    }
    if pointer < headers_end.max(u32_at(bytes, optional + 60)? as usize) || count > 1_000_000 {
        return Err("invalid COFF symbol table extent".into());
    }
    for index in 0..section_count {
        if bytes[table + index * 40] == b'/' {
            return Err("COFF string table is required by long section names; refusing to remove it".into());
        }
        if u32_at(bytes, table + index * 40 + 24)? != 0 || u32_at(bytes, table + index * 40 + 28)? != 0 {
            return Err("PE section retains relocation or line-number file references".into());
        }
    }
    let strings =
        pointer.checked_add(count.checked_mul(18).ok_or("COFF count overflow")?).ok_or("COFF range overflow")?;
    let string_size = u32_at(bytes, strings)? as usize;
    let end = strings.checked_add(string_size).ok_or("COFF string range overflow")?;
    if string_size < 4
        || end != bytes.len()
        || mapped.iter().chain(&debug_ranges).any(|range| overlaps(range, &(pointer..end)))
    {
        return Err("COFF symbols/strings must be a verified nonmapped terminal range, without extra overlay".into());
    }
    let mut index = 0;
    while index < count {
        let at = pointer + index * 18;
        let record = bytes.get(at..at + 18).ok_or("truncated COFF symbol")?;
        let next = index + 1 + usize::from(record[17]);
        if next > count {
            return Err("COFF auxiliary records exceed the declared symbol table".into());
        }
        if record[..4] == [0; 4] {
            let name = u32_at(record, 4)? as usize;
            if name < 4 || name >= string_size || !bytes[strings + name..end].contains(&0) {
                return Err("COFF symbol has an invalid string-table name".into());
            }
        }
        let section = i16::from_le_bytes(record[12..14].try_into().unwrap());
        if section < -2 || section > section_count as i16 {
            return Err("COFF symbol has an invalid section number".into());
        }
        index = next;
    }
    // Certificates use file offsets rather than RVAs; never truncate their bytes as symbol evidence.
    if directory_count > 4 {
        let certificate = u32_at(bytes, optional + 112 + 4 * 8)? as usize;
        let size = u32_at(bytes, optional + 116 + 4 * 8)? as usize;
        if size > 0
            && overlaps(&(certificate..certificate.checked_add(size).ok_or("certificate overflow")?), &(pointer..end))
        {
            return Err("COFF symbol range overlaps certificate metadata".into());
        }
    }
    let mut output = bytes[..pointer].to_vec();
    output[pe + 12..pe + 20].fill(0);
    Ok(output)
}

pub(crate) fn verify_pe_twin(original: &[u8], twin: &[u8]) -> Result<(), String> {
    if strip_pe(original)? != twin {
        return Err("PE twin differs outside the exact permitted COFF stripping transform".into());
    }
    strip_pe(twin)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x416];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x8c..0x90].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[0x90..0x94].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xbc..0xc0].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        let section = 0x188;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        bytes[0x200] = 0xc3;
        bytes[0x400..0x405].copy_from_slice(b"owned");
        bytes[0x40c..0x40e].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x40e..0x410].copy_from_slice(&0x20u16.to_le_bytes());
        bytes[0x410] = 2;
        bytes[0x412..0x416].copy_from_slice(&4u32.to_le_bytes());
        bytes
    }

    #[test]
    fn exact_pe_strip_preserves_mapping_entry_and_every_code_byte() {
        let original = fixture();
        let twin = strip_pe(&original).unwrap();
        assert_eq!(twin.len(), 0x400);
        assert_eq!(&twin[0x200..], &original[0x200..0x400]);
        assert_eq!(&twin[0x8c..0x94], &[0; 8]);
        verify_pe_twin(&original, &twin).unwrap();
        for index in [0xa8, 0x188 + 12, 0x188 + 36, 0x200, 0x300] {
            let mut mutant = twin.clone();
            mutant[index] ^= 1;
            assert!(verify_pe_twin(&original, &mutant).is_err(), "byte {index}");
        }
    }

    #[test]
    fn pe_strip_refuses_truncation_overlay_long_names_and_mapped_symbol_tables() {
        let original = fixture();
        for length in [0, 0x3f, 0x99, 0x190, 0x413] {
            assert!(strip_pe(&original[..length]).is_err());
        }
        let mut overlay = original.clone();
        overlay.push(0x55);
        assert!(strip_pe(&overlay).is_err());
        let mut long_name = original.clone();
        long_name[0x188..0x190].copy_from_slice(b"/4\0\0\0\0\0\0");
        assert!(strip_pe(&long_name).is_err());
        let mut mapped = original;
        mapped[0x8c..0x90].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(strip_pe(&mapped).is_err());
    }
}
