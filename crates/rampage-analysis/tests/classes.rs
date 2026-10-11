use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_arch::Arch;
use rampage_loaders::{Binary, Format, SectionKind, Symbol, SymbolKind};

pub use rampage_analysis::language;

#[path = "../src/classes.rs"]
mod classes;

use classes::{HeaderClassification, RttiClassification, ScanStop, SlotClassification, recover};

struct FixtureFile(PathBuf);

impl Drop for FixtureFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).expect("remove class-evidence fixture");
    }
}

fn fixture(arch: Arch, big_endian: bool, words: &[u64], thumb: bool) -> Binary {
    fixture_with_code(arch, big_endian, words, thumb, "00000000000000000000000000000000")
}

fn fixture_with_code(arch: Arch, big_endian: bool, words: &[u64], thumb: bool, code: &str) -> Binary {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rampage-class-evidence-{}-{}.snapshot.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let guard = FixtureFile(path);
    let mut bytes = String::new();
    for &word in words {
        let encoded = if big_endian { word.to_be_bytes() } else { word.to_le_bytes() };
        let width = usize::from(arch.pointer_size());
        let encoded = if big_endian { &encoded[8 - width..] } else { &encoded[..width] };
        for byte in encoded {
            write!(bytes, "{byte:02x}").unwrap();
        }
    }
    write!(
        file,
        r#"{{"format":"rampage-snapshot-v1","arch":"{arch}","data_big_endian":{big_endian},
        "provenance":"controlled class-evidence test model","regions":[
        {{"name":"text","address":"0x1000","permissions":"r-x","thumb":{thumb},
          "bytes":"{code}"}},
        {{"name":"vtable","address":"0x3000","permissions":"r--","bytes":"{bytes}"}},
        {{"name":"rtti","address":"0x4000","permissions":"r--","bytes":"0000000000000000"}}
        ]}}"#
    )
    .unwrap();
    drop(file);
    let mut binary = Binary::open(&guard.0).unwrap();
    binary.format = Format::Elf;
    for section in &mut binary.sections {
        if section.name != "text" {
            section.kind = SectionKind::ReadOnlyData;
        }
    }
    binary.symbols = vec![
        Symbol {
            name: "_ZTV3Foo".to_owned(),
            address: 0x3000,
            size: (words.len() * usize::from(arch.pointer_size())) as u64,
            kind: SymbolKind::Data,
        },
        Symbol { name: "_ZTI3Foo".to_owned(), address: 0x4000, size: 8, kind: SymbolKind::Data },
    ];
    binary
}

#[test]
fn named_headers_preserve_signed_offsets_endianness_and_sources() {
    for (arch, endian, offset) in [
        (Arch::X86_64, false, u64::MAX - 7),
        (Arch::X86, true, u64::from(u32::MAX) - 7),
        (Arch::Aarch64, true, u64::MAX - 7),
    ] {
        let binary = fixture(arch, endian, &[offset, 0x4000, 0x1000, 0x1004], false);
        let result = recover(&binary);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let class = &result.classes[0];
        assert_eq!(class.name, "Foo");
        assert_eq!(class.vtable_symbol, "_ZTV3Foo");
        assert_eq!(class.address, 0x3000);
        assert_eq!(class.offset_to_top, Some(-8));
        assert_eq!(class.header, HeaderClassification::KnownRtti);
        assert_eq!(class.rtti_candidate.classification, RttiClassification::KnownSymbol);
        assert_eq!(class.rtti_candidate.symbol.as_deref(), Some("_ZTI3Foo"));
        assert_eq!(class.slots.iter().map(|slot| slot.target).collect::<Vec<_>>(), [Some(0x1000), Some(0x1004)]);
        assert_eq!(class.slots[0].address, 0x3000 + 2 * u64::from(arch.pointer_size()));
        assert_eq!(class.slots[1].index, 1);
        assert_eq!(class.source, "named_itanium_vtable_symbol");
        assert_eq!(class.confidence, "raw_named_vtable_evidence");
    }
}

#[test]
fn macho_names_are_demangled_but_not_replaced_in_evidence() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
    binary.format = Format::MachO;
    for symbol in &mut binary.symbols {
        symbol.name.insert(0, '_');
    }
    let result = recover(&binary);
    assert_eq!(result.classes[0].name, "Foo");
    assert_eq!(result.classes[0].vtable_symbol, "__ZTV3Foo");
    assert_eq!(result.classes[0].rtti_candidate.symbol.as_deref(), Some("__ZTI3Foo"));
}

#[test]
fn rtti_requires_a_known_readonly_image_backed_typeinfo_symbol() {
    for raw in [0, 0x4000, 0x4004, 0x9999] {
        let mut binary = fixture(Arch::X86_64, false, &[0, raw, 0x1000], false);
        if raw == 0x4000 {
            binary.symbols[1].name = "_ZTS3Foo".to_owned();
        }
        let result = recover(&binary);
        let rtti = &result.classes[0].rtti_candidate;
        assert_eq!(rtti.address, raw);
        assert_eq!(rtti.symbol, None);
        assert_eq!(
            rtti.classification,
            if raw == 0 { RttiClassification::Null } else { RttiClassification::Unresolved }
        );
        assert_eq!(result.classes[0].slots[0].target, Some(0x1000));
        assert_eq!(result.classes[0].offset_to_top, None);
        assert_eq!(result.classes[0].header, HeaderClassification::UnverifiedPrefix);
    }
    let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
    binary.segments.iter_mut().find(|segment| segment.address == 0x4000).unwrap().perms.write = true;
    assert_eq!(recover(&binary).classes[0].rtti_candidate.classification, RttiClassification::Unresolved);
    binary.segments.iter_mut().find(|segment| segment.address == 0x4000).unwrap().perms.write = false;
    binary.symbols[1].name = "_ZTI3Bar".to_owned();
    let result = recover(&binary);
    assert_eq!(result.classes[0].name, "Foo");
    assert_eq!(result.classes[0].rtti_candidate.symbol.as_deref(), Some("_ZTI3Bar"));
    assert_eq!(result.classes[0].rtti_candidate.classification, RttiClassification::KnownSymbol);
    assert_eq!(result.classes[0].header, HeaderClassification::UnverifiedPrefix);
    assert_eq!(result.classes[0].offset_to_top, None);
    assert_eq!(result.classes[0].slots[0].target, Some(0x1000));
}

#[test]
fn header_verification_compares_encoded_types_after_macho_normalization() {
    for (vtable, rtti, expected) in [
        ("__ZTV3Foo", "_ZTI3Foo", HeaderClassification::KnownRtti),
        ("_ZTV3Foo", "__ZTI3Foo", HeaderClassification::KnownRtti),
        ("__ZTV3Foo", "__ZTI3Bar", HeaderClassification::UnverifiedPrefix),
    ] {
        let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
        binary.symbols[0].name = vtable.to_owned();
        binary.symbols[1].name = rtti.to_owned();
        let result = recover(&binary);
        assert_eq!(result.classes[0].header, expected);
        assert_eq!(result.classes[0].slots[0].target, Some(0x1000));
    }
}

#[test]
fn equal_demangled_types_do_not_replace_exact_encoded_identity() {
    let expanded = "1XI3Foo3FooE";
    let substituted = "1XI3FooS0_E";
    assert_eq!(language::demangle(&format!("_ZTV{expanded}")), language::demangle(&format!("_ZTV{substituted}")));
    assert!(language::demangle(&format!("_ZTV{expanded}")).is_some());
    for (rtti, expected) in
        [(expanded, HeaderClassification::KnownRtti), (substituted, HeaderClassification::UnverifiedPrefix)]
    {
        let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
        binary.symbols[0].name = format!("_ZTV{expanded}");
        binary.symbols[1].name = format!("_ZTI{rtti}");
        let result = recover(&binary);
        let class = &result.classes[0];
        assert_eq!(class.rtti_candidate.classification, RttiClassification::KnownSymbol);
        assert_eq!(class.header, expected);
        assert_eq!(class.offset_to_top, (expected == HeaderClassification::KnownRtti).then_some(0));
        assert_eq!(class.slots[0].target, Some(0x1000));
    }
}

#[test]
fn null_and_unresolved_values_are_reported_without_skipping_to_later_code() {
    for (raw, classification) in [(0, SlotClassification::Null), (0x9999, SlotClassification::Unresolved)] {
        let binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000, raw, 0x1004], false);
        let result = recover(&binary);
        let class = &result.classes[0];
        assert_eq!(class.slots.len(), 2);
        assert_eq!(class.slots[1].raw_value, raw);
        assert_eq!(class.slots[1].classification, classification);
        assert_eq!(class.slots[1].target, None);
        assert_eq!(class.stop, ScanStop::NonFunction);
        assert_eq!(class.scan_end, 0x3020);
        assert_eq!(class.scan_limit, 0x3028);
    }
}

#[test]
fn code_targets_require_supported_alignment_mode_and_complete_backing() {
    for (arch, thumb, raw, expected) in [
        (Arch::Aarch64, false, 0x1001, None),
        (Arch::Aarch64, false, 0x100c, Some(0x100c)),
        (Arch::Aarch64, false, 0x1010, None),
        (Arch::X86_64, false, 0x1001, Some(0x1001)),
        (Arch::Arm, true, 0x1001, Some(0x1000)),
        (Arch::Arm, true, 0x1000, None),
        (Arch::Arm, false, 0x1001, None),
        (Arch::Arm, false, 0x1002, None),
        (Arch::PowerPc64, false, 0x1000, None),
    ] {
        let binary = fixture(arch, false, &[0, 0, raw], thumb);
        let result = recover(&binary);
        assert_eq!(result.classes[0].slots[0].target, expected, "{arch} {raw:#x}");
    }
    let mut binary = fixture(Arch::Aarch64, false, &[0, 0, 0x100c], false);
    binary.segments[0].file_size = 14;
    assert_eq!(recover(&binary).classes[0].slots[0].target, None);
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x100c], false);
    binary.segments[0].file_size = 12;
    assert_eq!(recover(&binary).classes[0].slots[0].target, None);
}

#[test]
fn targets_require_execution_and_a_whole_minimum_instruction_inside_the_segment() {
    for arch in [Arch::X86_64, Arch::Aarch64] {
        let mut binary = fixture(arch, false, &[0, 0x4000, 0x1000], false);
        binary.segments[0].perms.execute = false;
        assert!(binary.code_from(0x1000).is_some());
        let result = recover(&binary);
        assert_eq!(result.classes[0].slots[0].classification, SlotClassification::Unresolved);
        assert_eq!(result.classes[0].slots[0].target, None);
    }
    for (arch, thumb, raw, size) in
        [(Arch::Aarch64, false, 0x100c, 14), (Arch::Arm, false, 0x100c, 14), (Arch::Arm, true, 0x100f, 15)]
    {
        let mut binary = fixture(arch, false, &[0, 0x4000, raw], thumb);
        binary.segments[0].size = size;
        let address = if thumb { raw & !1 } else { raw };
        assert!(binary.code_from(address).is_some_and(|bytes| bytes.len() >= 2));
        let result = recover(&binary);
        assert_eq!(result.classes[0].slots[0].classification, SlotClassification::Unresolved);
        assert_eq!(result.classes[0].slots[0].target, None);
    }
}

#[test]
fn code_range_and_image_backing_must_supply_the_minimum_instruction_span() {
    for (arch, thumb, exact, short, raw) in [
        (Arch::Aarch64, false, "00000000", "000000", 0x1000),
        (Arch::Arm, false, "00000000", "000000", 0x1000),
        (Arch::Arm, true, "0000", "00", 0x1001),
    ] {
        let binary = fixture_with_code(arch, false, &[0, 0x4000, raw], thumb, exact);
        assert_eq!(recover(&binary).classes[0].slots[0].target, Some(0x1000));

        let mut binary = fixture_with_code(arch, false, &[0, 0x4000, raw], thumb, short);
        binary.segments[0].size = 16;
        binary.segments[0].file_size = 16;
        assert_eq!(binary.code_from(0x1000).unwrap().len(), short.len() / 2);
        assert_eq!(recover(&binary).classes[0].slots[0].target, None);

        let mut binary = fixture(arch, false, &[0, 0x4000, raw], thumb);
        binary.segments[0].file_offset = (binary.image_bytes().len() - short.len() / 2) as u64;
        assert_eq!(binary.code_from(0x1000).unwrap().len(), short.len() / 2);
        assert_eq!(recover(&binary).classes[0].slots[0].target, None);
    }
}

#[test]
fn mips64_elfclass32_is_rejected_before_assuming_eight_byte_pointers() {
    let binary = mips_elf(false);
    assert_eq!(binary.arch, Arch::Mips64);
    assert_eq!(binary.format, Format::Elf);
    assert_eq!(&binary.image_bytes()[..5], b"\x7fELF\x01");
    assert_eq!(binary.symbols[0].name, "_ZTV3Foo");
    let result = recover(&binary);
    assert!(result.classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("unsupported MIPS64 ELFCLASS32/N32")));

    let binary = mips_elf(true);
    assert_eq!(binary.arch, Arch::Mips64);
    assert_eq!(&binary.image_bytes()[..5], b"\x7fELF\x02");
    let result = recover(&binary);
    assert_eq!(result.classes.len(), 1);
    assert!(!result.warnings.iter().any(|warning| warning.contains("N32")));
}

fn mips_elf(elf64: bool) -> Binary {
    let (header_size, program_size, section_size, symbol_size, pointer_size) =
        if elf64 { (64, 56, 64, 24, 8) } else { (52, 32, 40, 16, 4) };
    let mut bytes = vec![0_u8; 0x200 + 4 * section_size];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', if elf64 { 2 } else { 1 }, 1, 1]);
    put_integer(&mut bytes, 16, 2, 2);
    put_integer(&mut bytes, 18, 2, 8);
    put_integer(&mut bytes, 20, 4, 1);
    let (phoff, shoff, flags, sizes) = if elf64 { (32, 40, 48, 52) } else { (28, 32, 36, 40) };
    put_integer(&mut bytes, phoff, pointer_size, header_size as u64);
    put_integer(&mut bytes, shoff, pointer_size, 0x200);
    put_integer(&mut bytes, flags, 4, if elf64 { 0x6000_0000 } else { 0x6000_0020 });
    for (index, value) in [header_size, program_size, 1, section_size, 4, 3].into_iter().enumerate() {
        put_integer(&mut bytes, sizes + 2 * index, 2, value as u64);
    }
    let ph = header_size;
    put_integer(&mut bytes, ph, 4, 1);
    let (permissions, address, file_size, memory_size, alignment) =
        if elf64 { (4, 16, 32, 40, 48) } else { (24, 8, 16, 20, 28) };
    put_integer(&mut bytes, ph + permissions, 4, 4);
    put_integer(&mut bytes, ph + address, pointer_size, 0x1000);
    let image_size = bytes.len() as u64;
    put_integer(&mut bytes, ph + file_size, pointer_size, image_size);
    put_integer(&mut bytes, ph + memory_size, pointer_size, image_size);
    put_integer(&mut bytes, ph + alignment, pointer_size, 0x1000);
    put_integer(&mut bytes, 0x100 + 2 * pointer_size, pointer_size, 0x1000);
    bytes[0x180..0x189].copy_from_slice(b"\0_ZTV3Foo");
    let symbol = 0x140 + symbol_size;
    put_integer(&mut bytes, symbol, 4, 1);
    let (value, size, info, index) = if elf64 { (8, 16, 4, 6) } else { (4, 8, 12, 14) };
    put_integer(&mut bytes, symbol + value, pointer_size, 0x1100);
    put_integer(&mut bytes, symbol + size, pointer_size, (3 * pointer_size) as u64);
    bytes[symbol + info] = 0x11;
    put_integer(&mut bytes, symbol + index, 2, 1);
    for (index, kind, offset, size) in
        [(1, 1, 0x100, 3 * pointer_size), (2, 2, 0x140, 2 * symbol_size), (3, 3, 0x180, 10)]
    {
        let section = 0x200 + index * section_size;
        put_integer(&mut bytes, section + 4, 4, kind);
        let (address, file_offset, length, link, info, alignment, entry_size) =
            if elf64 { (16, 24, 32, 40, 44, 48, 56) } else { (12, 16, 20, 24, 28, 32, 36) };
        if index == 1 {
            put_integer(&mut bytes, section + 8, pointer_size, 2);
            put_integer(&mut bytes, section + address, pointer_size, 0x1100);
        }
        put_integer(&mut bytes, section + file_offset, pointer_size, offset as u64);
        put_integer(&mut bytes, section + length, pointer_size, size as u64);
        put_integer(&mut bytes, section + alignment, pointer_size, 1);
        if index == 2 {
            put_integer(&mut bytes, section + link, 4, 3);
            put_integer(&mut bytes, section + info, 4, 1);
            put_integer(&mut bytes, section + entry_size, pointer_size, symbol_size as u64);
        }
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rampage-class-evidence-mips-{}-{}.elf",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let guard = FixtureFile(path);
    file.write_all(&bytes).unwrap();
    drop(file);
    Binary::open(&guard.0).unwrap()
}

fn put_integer(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

#[test]
fn symbol_section_and_slot_bounds_prevent_adjacent_reads() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000, 0x1004], false);
    binary.symbols[0].size = 24;
    assert_eq!(recover(&binary).classes[0].slots.len(), 1);
    binary.symbols[0].size = 0;
    let result = recover(&binary);
    assert_eq!(result.classes[0].slots.len(), 2);
    assert_eq!(result.classes[0].bound, "section_end");
    binary.sections.iter_mut().find(|section| section.address == 0x3000).unwrap().size = 24;
    assert_eq!(recover(&binary).classes[0].slots.len(), 1);
    binary.symbols[0].size = 1024;
    assert_eq!(recover(&binary).classes[0].slots.len(), 1);

    let mut words = vec![0, 0];
    words.extend(std::iter::repeat_n(0x1000, 100));
    let mut binary = fixture(Arch::X86_64, false, &words, false);
    for size in [0, 816] {
        binary.symbols[0].size = size;
        let result = recover(&binary);
        assert_eq!(result.classes[0].slots.len(), 64);
        assert_eq!(result.classes[0].stop, ScanStop::SlotLimit);
        assert_eq!(result.classes[0].scan_end, 0x3210);
    }
}

#[test]
fn malformed_mutable_unreadable_and_nonstatic_tables_are_excluded() {
    for case in 0..9 {
        let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
        match case {
            0 => binary.format = Format::Snapshot,
            1 => binary.format = Format::Pe,
            2 => binary.segments[1].perms.write = true,
            3 => binary.segments[1].perms.read = false,
            4 => binary.sections[1].kind = SectionKind::Data,
            5 => binary.symbols[0].size = 8,
            6 => binary.symbols[0].address += 1,
            7 => binary.symbols[0].size = u64::MAX,
            8 => binary.symbols[0].name = "_ZTVnot_a_type".to_owned(),
            _ => unreachable!(),
        }
        let result = recover(&binary);
        assert!(result.classes.is_empty(), "case {case}");
        assert!(!result.warnings.is_empty(), "case {case}");
    }
}

#[test]
fn unnamed_and_construction_tables_are_not_guessed() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0x4000, 0x1000], false);
    for name in ["table", "_ZTC3Foo0_3Bar", "__ZTC3Foo0_3Bar"] {
        binary.symbols[0].name = name.to_owned();
        assert!(recover(&binary).classes.is_empty());
    }
    binary.symbols.clear();
    assert!(recover(&binary).classes.is_empty());
}

#[test]
fn candidate_and_symbol_name_budgets_are_bounded_and_visible() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000], false);
    binary.symbols = vec![binary.symbols[0].clone(); 4097];
    let result = recover(&binary);
    assert_eq!(result.classes.len(), 4096);
    assert!(result.warnings.iter().any(|warning| warning.contains("candidate limit")));

    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000], false);
    binary
        .symbols
        .insert(0, Symbol { name: "x".repeat(32 * 1024 * 1024 + 1), address: 0, size: 0, kind: SymbolKind::Other });
    let result = recover(&binary);
    assert!(result.classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("32 MiB budget")));
}

#[test]
fn oversized_or_expanding_vtable_names_do_not_reach_unbounded_demangling() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000], false);
    binary.symbols[0].name = format!("_ZTV{}", "x".repeat(4096));
    let result = recover(&binary);
    assert!(result.classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("4096-byte limit")));

    let digits = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut name = "1XI1AIiE".to_owned();
    for index in 0..18 {
        let letter = char::from(b'B' + index as u8);
        let substitution = char::from(digits[2 * index + 1]);
        name.push_str(&format!("1{letter}IS{substitution}_S{substitution}_E"));
    }
    name.push('E');
    for prefix in ["_ZTV", "_ZTI"] {
        let mangled = format!("{prefix}{name}");
        let parsed = cpp_demangle::Symbol::new(mangled.as_str()).expect("valid expanding type mangling");
        let mut sink = CountingSink(0);
        parsed.structured_demangle(&mut sink, &Default::default()).unwrap();
        assert!(sink.0 > 4096);
        assert_eq!(language::demangle(&mangled), None);
    }
    binary.symbols[0].name = format!("_ZTV{name}");
    assert!(recover(&binary).classes.is_empty());
}

struct CountingSink(usize);

impl std::fmt::Write for CountingSink {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0 += value.len();
        Ok(())
    }
}

#[test]
fn virtual_base_prefixes_are_not_attributed_as_header_facts() {
    let binary = fixture(Arch::X86_64, false, &[16, 0, 0x4000, 0x1000], false);
    let result = recover(&binary);
    let class = &result.classes[0];
    assert_eq!(class.header, HeaderClassification::UnverifiedPrefix);
    assert_eq!(class.raw_offset_word, 16);
    assert_eq!(class.offset_to_top, None);
    assert_eq!(class.rtti_candidate.address, 0);
    assert_eq!(class.slots[0].raw_value, 0x4000);
    assert_eq!(class.slots[0].classification, SlotClassification::Unresolved);
    assert_eq!(class.stop, ScanStop::NonFunction);
}

#[test]
fn unreadable_slots_do_not_claim_unexamined_bytes() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000, 0x1004], false);
    let segment = &mut binary.segments[1];
    segment.file_offset = 40;
    let result = recover(&binary);
    let class = &result.classes[0];
    assert!(class.slots.is_empty());
    assert_eq!(class.stop, ScanStop::Unreadable);
    assert_eq!(class.scan_end, 0x3010);
    assert_eq!(class.scan_limit, 0x3020);
}

#[test]
fn large_irrelevant_metadata_cannot_amplify_slot_lookup_work() {
    let mut binary = fixture(Arch::X86_64, false, &[0, 0, 0x1000], false);
    binary.symbols = vec![binary.symbols[0].clone(); 4096];
    let mut segment = binary.segments[0].clone();
    segment.address = 0x5000;
    binary.segments.splice(0..0, std::iter::repeat_n(segment.clone(), 1000));
    let result = recover(&binary);
    assert!(!result.classes.is_empty());
    assert!(result.classes.len() < 4096);
    assert!(result.warnings.iter().any(|warning| warning.contains("lookup work budget")));

    binary.segments.extend(std::iter::repeat_n(segment, 16_384));
    let result = recover(&binary);
    assert!(result.classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("metadata budget")));
}
