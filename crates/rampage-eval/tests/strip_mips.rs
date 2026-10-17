use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{Endianness, Object, ObjectSection, ObjectSymbol};
use rampage_eval::strip;

const SECTION_TABLE: usize = 0x200;
const ABI_HEADER: usize = SECTION_TABLE + 2 * 40;
const ABI_TYPE: u32 = 0x7000_002a;

fn put16(bytes: &mut [u8], offset: usize, value: u16, little: bool) {
    let value = if little { value.to_le_bytes() } else { value.to_be_bytes() };
    bytes[offset..offset + 2].copy_from_slice(&value);
}

fn put32(bytes: &mut [u8], offset: usize, value: u32, little: bool) {
    let value = if little { value.to_le_bytes() } else { value.to_be_bytes() };
    bytes[offset..offset + 4].copy_from_slice(&value);
}

// A linked ELF32 fixture, independent of the builder under test and any cross compiler.
// .text is `jr $ra; nop`; ABIFlags_v0 describes MIPS32r2 with 32-bit GPRs.
fn fixture(little: bool) -> Vec<u8> {
    let mut bytes = vec![0; SECTION_TABLE + 7 * 40];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, if little { 1 } else { 2 }, 1]);
    put16(&mut bytes, 16, 2, little);
    put16(&mut bytes, 18, 8, little);
    put32(&mut bytes, 20, 1, little);
    put32(&mut bytes, 24, 0x10100, little);
    put32(&mut bytes, 28, 52, little);
    put32(&mut bytes, 32, SECTION_TABLE as u32, little);
    put32(&mut bytes, 36, 0x7000_1005, little);
    for (offset, value) in [(40, 52), (42, 32), (44, 2), (46, 40), (48, 7), (50, 6)] {
        put16(&mut bytes, offset, value, little);
    }
    for (index, words) in
        [[1, 0, 0x10000, 0x10000, 0x120, 0x120, 5, 0x10000], [0x7000_0003, 0x108, 0x10108, 0x10108, 24, 24, 4, 8]]
            .iter()
            .enumerate()
    {
        for (word, value) in words.iter().enumerate() {
            put32(&mut bytes, 52 + index * 32 + word * 4, *value, little);
        }
    }
    put32(&mut bytes, 0x100, 0x03e0_0008, little);
    bytes[0x10a..0x110].copy_from_slice(&[32, 2, 1, 0, 0, 3]);
    bytes[0x120..0x124].copy_from_slice(&[1, 2, 3, 4]);
    put32(&mut bytes, 0x150, 1, little);
    put32(&mut bytes, 0x154, 0x10100, little);
    put32(&mut bytes, 0x158, 8, little);
    bytes[0x15c] = 0x12;
    put16(&mut bytes, 0x15e, 1, little);
    bytes[0x160..0x168].copy_from_slice(b"\0sample\0");

    let names = ["", ".text", ".MIPS.abiflags", ".debug_info", ".symtab", ".strtab", ".shstrtab"];
    let mut strings = Vec::new();
    let mut name_offsets = Vec::new();
    for name in names {
        name_offsets.push(strings.len() as u32);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    bytes[0x180..0x180 + strings.len()].copy_from_slice(&strings);
    let headers = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 6, 0x10100, 0x100, 8, 0, 0, 4, 0],
        [ABI_TYPE, 2, 0x10108, 0x108, 24, 0, 0, 8, 24],
        [1, 0, 0, 0x120, 4, 0, 0, 1, 0],
        [2, 0, 0, 0x140, 32, 5, 1, 4, 16],
        [3, 0, 0, 0x160, 8, 0, 0, 1, 0],
        [3, 0, 0, 0x180, strings.len() as u32, 0, 0, 1, 0],
    ];
    for (index, words) in headers.iter().enumerate() {
        put32(&mut bytes, SECTION_TABLE + index * 40, name_offsets[index], little);
        for (word, value) in words.iter().enumerate() {
            put32(&mut bytes, SECTION_TABLE + index * 40 + 4 + word * 4, *value, little);
        }
    }
    bytes
}

fn verify(input: &[u8], keep_symbols: bool) {
    let output = strip(input, keep_symbols).unwrap();
    let original = object::File::parse(input).unwrap();
    let stripped = object::File::parse(output.as_slice()).unwrap();
    let debug_count = |file: &object::File<'_>| {
        file.sections().filter(|section| section.name().unwrap().starts_with(".debug")).count()
    };
    assert!(debug_count(&original) > 0);
    assert_eq!(debug_count(&stripped), 0);
    let symbols = |file: &object::File<'_>| {
        file.symbols()
            .map(|symbol| (symbol.name().unwrap().to_owned(), symbol.address(), symbol.size()))
            .collect::<Vec<_>>()
    };
    assert!(!symbols(&original).is_empty());
    if keep_symbols {
        assert_eq!(symbols(&original), symbols(&stripped));
    } else {
        assert_eq!(stripped.symbols().count(), 0);
        for name in [".symtab", ".strtab", ".symtab_shndx"] {
            assert!(stripped.section_by_name(name).is_none(), "{name} remains");
        }
    }

    for section in original.sections() {
        let object::SectionFlags::Elf { sh_flags, .. } = section.flags() else { unreachable!() };
        if !sh_flags.contains(elf::SHF_ALLOC) {
            continue;
        }
        let retained = stripped.section_by_name(section.name().unwrap()).unwrap();
        assert_eq!(section.address(), retained.address());
        assert_eq!(section.size(), retained.size());
        assert_eq!(section.align(), retained.align());
        assert_eq!(section.flags(), retained.flags());
        assert_eq!(section.data().unwrap(), retained.data().unwrap());
    }
    let header = elf::FileHeader32::<Endianness>::parse(input).unwrap();
    let endian = header.endian().unwrap();
    let output_header = elf::FileHeader32::<Endianness>::parse(output.as_slice()).unwrap();
    let sections = header.sections(endian, input).unwrap();
    let output_sections = output_header.sections(endian, output.as_slice()).unwrap();
    let (_, abi) = sections.section_by_name(endian, b".MIPS.abiflags").unwrap();
    let (_, retained_abi) = output_sections.section_by_name(endian, b".MIPS.abiflags").unwrap();
    assert_eq!(retained_abi.sh_type(endian), elf::SectionType(ABI_TYPE));
    assert_eq!(abi.sh_flags(endian), retained_abi.sh_flags(endian));
    assert_eq!(abi.sh_offset(endian), retained_abi.sh_offset(endian));
    assert_eq!(abi.sh_addr(endian), retained_abi.sh_addr(endian));
    assert_eq!(abi.sh_size(endian), retained_abi.sh_size(endian));
    assert_eq!(abi.sh_link(endian), retained_abi.sh_link(endian));
    assert_eq!(abi.sh_info(endian), retained_abi.sh_info(endian));
    assert_eq!(abi.sh_addralign(endian), retained_abi.sh_addralign(endian));
    assert_eq!(abi.sh_entsize(endian), retained_abi.sh_entsize(endian));
    let program_headers = header.program_headers(endian, input).unwrap();
    let program_start = header.e_phoff(endian) as usize;
    let program_end = program_start + std::mem::size_of_val(program_headers);
    assert_eq!(&input[program_start..program_end], &output[program_start..program_end]);
    // Only section-table bookkeeping may change in the mapped ELF header.
    // The entry point, machine, e_flags, program table and all other loaded bytes stay exact.
    for program in program_headers.iter().filter(|program| program.p_type(endian) == elf::PT_LOAD) {
        let start = program.p_offset(endian) as usize;
        let end = start + program.p_filesz(endian) as usize;
        for offset in start..end {
            if (32..36).contains(&offset) || (48..52).contains(&offset) {
                continue;
            }
            assert_eq!(input[offset], output[offset], "loaded byte changed at file offset {offset:#x}");
        }
    }
}

#[test]
fn mips_abi_metadata_survives_stripping_in_both_byte_orders() {
    for little in [false, true] {
        let input = fixture(little);
        let error = match object::build::elf::Builder::read(input.as_slice()) {
            Err(error) => error,
            Ok(_) => panic!("unadapted reader must refuse ABI flags"),
        };
        assert!(error.to_string().contains("7000002a"), "unexpected reader error: {error}");
        verify(&input, false);
        verify(&input, true);
    }
}

#[test]
fn refuses_loss_of_nonsection_mapped_bytes_in_both_byte_orders() {
    for little in [false, true] {
        for keep_symbols in [false, true] {
            let mut input = fixture(little);
            input[0x80] = 0x7f;
            let error = strip(&input, keep_symbols).expect_err("nonsection load bytes must not be lost");
            assert!(error.contains("file-backed ELF load bytes"), "unexpected error: {error}");

            let mut header_padding = fixture(little);
            header_padding[9] = 0x7f;
            let error = strip(&header_padding, keep_symbols).expect_err("ELF padding is not a bookkeeping field");
            assert!(error.contains("ELF file header"), "unexpected error: {error}");
        }
    }
}

#[test]
fn refuses_invalid_mapped_ranges_and_overlapping_header_tables() {
    for little in [false, true] {
        for keep_symbols in [false, true] {
            for (file_size, memory_size) in [(0x1000, 0x1000), (0x120, 0x100), (0x240, 0x240)] {
                let mut input = fixture(little);
                put32(&mut input, 52 + 16, file_size, little);
                put32(&mut input, 52 + 20, memory_size, little);
                assert!(strip(&input, keep_symbols).is_err(), "accepted load range {file_size:#x}/{memory_size:#x}");
            }
            let mut overlapping_headers = fixture(little);
            put32(&mut overlapping_headers, 28, 32, little);
            assert!(strip(&overlapping_headers, keep_symbols).is_err());
            let mut invalid_abi_segment = fixture(little);
            put32(&mut invalid_abi_segment, 52 + 32 + 4, 0xffff_fff8, little);
            assert!(strip(&invalid_abi_segment, keep_symbols).is_err());
        }
    }
}

#[test]
fn rejects_malformed_or_unsupported_mips_abi_metadata() {
    let input = fixture(false);
    for (offset, value) in [
        (ABI_HEADER + 20, 23),
        (ABI_HEADER + 36, 0),
        (ABI_HEADER + 32, 4),
        (ABI_HEADER + 24, 4),
        (ABI_HEADER + 28, 1),
        (ABI_HEADER + 8, 0x802),
        (ABI_HEADER + 16, 0xffff_fff8),
        (ABI_HEADER + 16, SECTION_TABLE as u32),
        (ABI_HEADER + 4, ABI_TYPE + 1),
        (32, 0xffff_fffc),
        (SECTION_TABLE + 3 * 40 + 16, SECTION_TABLE as u32),
    ] {
        let mut invalid = input.clone();
        put32(&mut invalid, offset, value, false);
        for keep_symbols in [false, true] {
            assert!(strip(&invalid, keep_symbols).is_err(), "accepted mutation at {offset:#x}: {value:#x}");
        }
    }
    let mut future_version = input.clone();
    put16(&mut future_version, 0x108, 1, false);
    assert!(strip(&future_version, false).is_err());
    let mut duplicate = input.clone();
    duplicate[SECTION_TABLE + 3 * 40..SECTION_TABLE + 4 * 40].copy_from_slice(&input[ABI_HEADER..ABI_HEADER + 40]);
    assert!(strip(&duplicate, false).is_err());
    for end in [0, 16, 51, SECTION_TABLE + 40, input.len() - 1] {
        assert!(strip(&input[..end], false).is_err(), "accepted truncation at {end:#x}");
    }
    let mut wrong_machine = input;
    put16(&mut wrong_machine, 18, 3, false);
    assert!(strip(&wrong_machine, false).is_err());
}

#[test]
fn opt_in_compiler_built_mips_fixture() {
    let Some(path) = std::env::var_os("RAMPAGE_MIPS_STRIP_FIXTURE") else { return };
    let input = std::fs::read(path).expect("read RAMPAGE_MIPS_STRIP_FIXTURE");
    verify(&input, false);
    verify(&input, true);
}
