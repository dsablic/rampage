//! Native memory admission for pilot profiles without a legacy machine width. Bounds come from the exact
//! language's code space, checked against the verified translator, never from a C pointer default.

use crate::sleigh_decode::SleighDecoder;
use crate::{Error, MemoryRegion};

/// Reviewed code-space facts for each exact language with an admitted C model. Offsets are internal bytes.
struct CodeSpace {
    language: &'static str,
    name: &'static str,
    word_size: u32,
    highest_byte: u64,
}

const CODE_SPACES: &[CodeSpace] = &[
    CodeSpace { language: "TI_MSP430:LE:16:default", name: "RAM", word_size: 1, highest_byte: 0xffff },
    CodeSpace { language: "avr8:LE:16:default", name: "code", word_size: 2, highest_byte: 0x1ffff },
];

fn reviewed(language: &str) -> Option<&'static CodeSpace> {
    CODE_SPACES.iter().find(|space| space.language == language)
}

/// Whether a 4-part Raw language ID (no compiler part) has a reviewed C model. This is the single source of
/// truth for Raw C admission; the decompiler still rechecks the exact pair and the translator bounds.
pub fn has_reviewed_raw_c_model(language: &str) -> bool {
    reviewed(language).is_some()
}

/// Highest code-space byte for a 5-part language/compiler ID, after the translator agrees with the table.
pub(crate) fn verified_code_highest(language_id: &str) -> Result<u64, Error> {
    let (language, _) = language_id
        .rsplit_once(':')
        .ok_or_else(|| Error::Ghidra(format!("invalid language/compiler ID {language_id}")))?;
    let space =
        reviewed(language).ok_or_else(|| Error::Ghidra(format!("no reviewed native memory bounds for {language}")))?;
    let decoder = SleighDecoder::open(language)?;
    let metadata = decoder.metadata();
    let code = metadata
        .spaces
        .iter()
        .find(|candidate| candidate.id == metadata.code_space)
        .ok_or_else(|| Error::Ghidra(format!("translator for {language} has no code space")))?;
    if code.name != space.name || code.word_size != space.word_size || code.highest != space.highest_byte {
        return Err(Error::Ghidra(format!("translator code space for {language} disagrees with reviewed bounds")));
    }
    Ok(space.highest_byte)
}

/// Exactly one fully backed, read-only RX code region within the code space. Every other address and every
/// non-code space stays unavailable to the native image.
pub(crate) fn validate_code_region(regions: &[MemoryRegion], highest: u64) -> Result<(), Error> {
    let [region] = regions else {
        return Err(Error::Ghidra("pilot native memory requires exactly one code region".to_owned()));
    };
    if !(region.readable && region.executable) || region.writable {
        return Err(Error::Ghidra("pilot native memory requires a read-only executable code region".to_owned()));
    }
    if region.size == 0 || region.bytes.len() as u64 != region.size {
        return Err(Error::Ghidra("pilot native code region must be fully backed".to_owned()));
    }
    let last = region
        .base
        .checked_add(region.size - 1)
        .ok_or_else(|| Error::Ghidra("memory region overflows address space".to_owned()))?;
    if last > highest {
        return Err(Error::Ghidra("memory region exceeds the target code space".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decompiler, DecompilerOptions};
    use rampage_arch::Arch;

    fn region(base: u64, bytes: &[u8]) -> MemoryRegion<'_> {
        MemoryRegion { base, bytes, size: bytes.len() as u64, readable: true, writable: false, executable: true }
    }

    #[test]
    fn reviewed_bounds_match_the_verified_translator() {
        assert_eq!(verified_code_highest("TI_MSP430:LE:16:default:default").unwrap(), 0xffff);
        assert_eq!(verified_code_highest("avr8:LE:16:default:gcc").unwrap(), 0x1ffff);
        for language in ["6502:LE:16:default:default", "avr8:LE:16:extended:gcc", "TI_MSP430X:LE:32:default:default"] {
            assert!(verified_code_highest(language).is_err(), "{language}");
        }
    }

    #[test]
    fn reviewed_raw_c_models_are_exactly_the_code_space_table_with_a_c_data_model() {
        assert!(has_reviewed_raw_c_model("TI_MSP430:LE:16:default"));
        assert!(has_reviewed_raw_c_model("avr8:LE:16:default"));
        for language in ["6502:LE:16:default", "TI_MSP430:LE:16:default:default", "avr8:LE:16:extended"] {
            assert!(!has_reviewed_raw_c_model(language), "{language}");
        }
        for space in CODE_SPACES {
            let modeled = ["default", "gcc"]
                .iter()
                .any(|compiler| crate::c_data_organization(&format!("{}:{compiler}", space.language)).is_some());
            assert!(modeled, "{} has bounds but no reviewed C data organization", space.language);
        }
    }

    #[test]
    fn pilot_regions_are_one_bounded_read_only_code_mapping() {
        let bytes = [0x30, 0x41];
        assert!(validate_code_region(&[region(0xfffe, &bytes)], 0xffff).is_ok());
        assert!(validate_code_region(&[region(0xffff, &bytes)], 0xffff).is_err());
        assert!(validate_code_region(&[], 0xffff).is_err());
        assert!(validate_code_region(&[region(0x1000, &bytes), region(0x2000, &bytes)], 0xffff).is_err());
        let writable = MemoryRegion { writable: true, ..region(0x1000, &bytes) };
        assert!(validate_code_region(&[writable], 0xffff).is_err());
        let data = MemoryRegion { executable: false, ..region(0x1000, &bytes) };
        assert!(validate_code_region(&[data], 0xffff).is_err());
        let zero_fill = MemoryRegion { size: 4, ..region(0x1000, &bytes) };
        assert!(validate_code_region(&[zero_fill], 0xffff).is_err());
    }

    #[test]
    fn pilot_constructor_admits_reviewed_models_and_refuses_6502() {
        let options = DecompilerOptions::default();
        let msp430 = [0x30, 0x41];
        let engine = Decompiler::open_with_options(Arch::Msp430, false, &[region(0x4400, &msp430)], &options).unwrap();
        assert_eq!(engine.address_highest(), 0xffff);
        let avr = [0x08, 0x95];
        let engine = Decompiler::open_with_options(Arch::Avr8, false, &[region(0x200, &avr)], &options).unwrap();
        assert_eq!(engine.address_highest(), 0x1ffff);
        let beyond = Decompiler::open_with_options(Arch::Avr8, false, &[region(0x1fffe, &[0, 0, 0, 0])], &options);
        assert!(beyond.is_err());
        let error = match Decompiler::open_with_options(Arch::Mos6502, false, &[region(0x1000, &[0x60])], &options) {
            Err(error) => error,
            Ok(_) => panic!("6502 has no reviewed C model"),
        };
        assert!(error.to_string().contains("no reviewed C data organization"), "{error}");
        let unreviewed = DecompilerOptions { compiler: Some("iarV1".into()), ..Default::default() };
        assert!(Decompiler::open_with_options(Arch::Avr8, false, &[region(0x200, &avr)], &unreviewed).is_err());
    }

    /// AVR `lds r24, 0x0200; ret` at code byte 0x200. The data address numerically overlaps the read-only
    /// code mapping, so a numeric-offset image would fold the code bytes into a constant.
    #[test]
    fn avr_data_space_reads_are_not_served_from_the_code_mapping() {
        let code = [0x80, 0x91, 0x00, 0x02, 0x08, 0x95];
        let options = DecompilerOptions::default();
        let mut engine = Decompiler::open_with_options(Arch::Avr8, false, &[region(0x200, &code)], &options).unwrap();
        assert!(engine.add_global(0x200, "uint1 shadow;").is_err());
        let text = engine.decompile(0x200, "load", false).unwrap();
        println!("AVR_DATA_SPACE_ISOLATION {text}");
        assert!(text.contains("R24 = xMem0200;"), "data read must stay a mem-space reference: {text}");
        for folded in ["0x80", "0x91", "-0x80", "0x9180"] {
            assert!(!text.contains(folded), "code bytes leaked into a data read: {text}");
        }
    }
}
