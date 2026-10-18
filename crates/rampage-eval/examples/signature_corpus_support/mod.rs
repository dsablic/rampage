use object::{Object, ObjectSection, ObjectSymbol};
use rampage_eval::Truth;
use rampage_loaders::Binary;
use rampage_signatures::canonical_functions;
use sha2::{Digest, Sha256};

pub(super) fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

pub(super) fn verify_twin(symbolized: &Binary, stripped: &Binary, truth: &Truth) -> Result<(), String> {
    let before = symbolized.target();
    let after = stripped.target();
    if before.arch != after.arch
        || before.big_endian != after.big_endian
        || before.data_big_endian != after.data_big_endian
        || before.thumb != after.thumb
    {
        return Err("stripped twin target differs from symbolized target".into());
    }
    if symbolized.format != rampage_loaders::Format::Elf || stripped.format != rampage_loaders::Format::Elf {
        return Err("this corpus pilot validates ELF stripping only".into());
    }
    if symbolized.segments != stripped.segments || symbolized.entry != stripped.entry {
        return Err("stripping changed load mappings or entry point".into());
    }
    for segment in &symbolized.segments {
        let original = normalized_segment(symbolized.image_bytes(), segment.file_offset, segment.file_size)?;
        let retained = normalized_segment(stripped.image_bytes(), segment.file_offset, segment.file_size)?;
        if original != retained {
            return Err("stripping changed load-image bytes outside permitted section-table header fields".into());
        }
    }
    let retained_sections = |binary: &Binary, stripped: bool| -> Result<Vec<_>, String> {
        let file = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
        let mut sections = Vec::new();
        for section in file.sections() {
            let name = section.name().map_err(|error| error.to_string())?;
            if removable_metadata(name, section.flags())? {
                if stripped && name != ".shstrtab" {
                    return Err("stripped twin retains removable metadata".into());
                }
                continue;
            }
            let backing = section.file_range().map(|(_, size)| size);
            let allocated = matches!(section.flags(),object::SectionFlags::Elf {sh_flags,..}
                if sh_flags.contains(object::elf::SHF_ALLOC));
            sections.push((
                name.to_owned(),
                section.address(),
                section.size(),
                section.align(),
                section.flags(),
                section.kind(),
                backing,
                if allocated { section.file_range() } else { None },
                digest(section.data().map_err(|error| error.to_string())?),
            ));
        }
        Ok(sections)
    };
    if retained_sections(symbolized, false)? != retained_sections(stripped, true)? {
        return Err("stripping changed retained section types, boundaries, backing or data".into());
    }
    let symbols = canonical_functions(symbolized);
    for address in truth.0.keys() {
        let symbol = symbols.get(address).ok_or("missing sized library function")?;
        let original = symbolized.read(*address, symbol.size).ok_or("unbacked truth function")?;
        if stripped.read(*address, symbol.size) != Some(original) {
            return Err(format!("stripping changed library function bytes at {address:#x}"));
        }
    }
    let file = object::File::parse(stripped.image_bytes()).map_err(|error| error.to_string())?;
    if file
        .symbols()
        .chain(file.dynamic_symbols())
        .any(|symbol| symbol.kind() == object::SymbolKind::Text && !symbol.is_undefined())
        || file
            .sections()
            .any(|section| section.name().is_ok_and(|name| name.starts_with(".debug") || name.starts_with(".zdebug")))
    {
        return Err("stripped twin retains static function symbols or debug sections".into());
    }
    Ok(())
}

fn removable_metadata(name: &str, flags: object::SectionFlags) -> Result<bool, String> {
    let object::SectionFlags::Elf { sh_type, sh_flags } = flags else {
        return Err("expected ELF section flags".into());
    };
    let expected = match name {
        ".symtab" => Some(object::elf::SHT_SYMTAB),
        ".strtab" | ".shstrtab" => Some(object::elf::SHT_STRTAB),
        ".symtab_shndx" => Some(object::elf::SHT_SYMTAB_SHNDX),
        _ => None,
    };
    if let Some(expected) = expected {
        if sh_type != expected || sh_flags.0 != 0 {
            return Err("reserved metadata section name has incompatible type/flags".into());
        }
        return Ok(true);
    }
    if name.starts_with(".debug") || name.starts_with(".zdebug") {
        if sh_type != object::elf::SHT_PROGBITS
            || sh_flags.contains(object::elf::SHF_ALLOC)
            || sh_flags.contains(object::elf::SHF_EXECINSTR)
        {
            return Err("debug section has analysis-relevant type/flags".into());
        }
        return Ok(true);
    }
    Ok(false)
}

fn normalized_segment(image: &[u8], offset: u64, length: u64) -> Result<Vec<u8>, String> {
    let start = usize::try_from(offset).map_err(|_| "invalid load offset")?;
    let end =
        usize::try_from(offset.checked_add(length).ok_or("invalid load extent")?).map_err(|_| "invalid load extent")?;
    let mut bytes = image.get(start..end).ok_or("unbacked load segment")?.to_vec();
    let fields: &[(usize, usize)] = match image.get(..5) {
        Some([0x7f, b'E', b'L', b'F', 1]) => &[(32, 36), (48, 52)],
        Some([0x7f, b'E', b'L', b'F', 2]) => &[(40, 48), (60, 64)],
        _ => return Err("expected ELF header".into()),
    };
    for &(first, last) in fields {
        for position in first..last {
            if (start..end).contains(&position) {
                bytes[position - start] = 0;
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_normalization_never_ignores_entry_program_headers_or_body_changes() {
        let mut original = vec![0u8; 128];
        original[..5].copy_from_slice(b"\x7fELF\x02");
        let expected = normalized_segment(&original, 0, 128).unwrap();
        let mut stripped = original.clone();
        for range in [40..48, 60..64] {
            stripped[range].fill(0xff);
        }
        assert_eq!(normalized_segment(&stripped, 0, 128).unwrap(), expected);
        for index in [24, 32, 48, 56, 64, 100] {
            let mut changed = original.clone();
            changed[index] = 0xff;
            assert_ne!(normalized_segment(&changed, 0, 128).unwrap(), expected, "byte {index}");
        }
        assert!(normalized_segment(&original, 100, 29).is_err());
    }

    #[test]
    fn metadata_names_do_not_hide_analysis_changing_section_types_or_permissions() {
        let flags = |sh_type, sh_flags| object::SectionFlags::Elf { sh_type, sh_flags };
        assert!(removable_metadata(".strtab", flags(object::elf::SHT_STRTAB, object::elf::SectionFlags(0))).unwrap());
        assert!(removable_metadata(".strtab", flags(object::elf::SHT_PROGBITS, object::elf::SHF_EXECINSTR)).is_err());
        assert!(removable_metadata(".debug_line", flags(object::elf::SHT_PROGBITS, object::elf::SHF_ALLOC)).is_err());
        assert!(
            !removable_metadata(".eh_frame", flags(object::elf::SHT_PROGBITS, object::elf::SectionFlags(0))).unwrap()
        );
    }
}
