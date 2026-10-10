use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::{Binary, Format, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

const GREETING: &[u8] = b"rampage fixture greeting";

fn check_x64_fixture(name: &str, format: Format, add_symbol: &str) {
    let binary = Binary::open(fixture(name)).unwrap();
    assert_eq!(binary.format, format);
    assert_eq!(binary.arch, Arch::X86_64);

    let entry = binary.entry.expect("executable has an entry point");
    let entry_segment = binary.segment_containing(entry).expect("entry inside a segment");
    assert!(entry_segment.perms.execute, "entry segment {:?} not executable", entry_segment.name);
    assert_eq!(binary.read(entry, 16).map(<[u8]>::len), Some(16));

    let add_address = match binary.symbol_by_name(add_symbol) {
        Some(symbol) => {
            assert_eq!(symbol.kind, SymbolKind::Function);
            symbol.address
        }
        None => binary.exports.iter().find(|export| export.name == add_symbol).expect("add symbol or export").address,
    };
    assert!(binary.segment_containing(add_address).unwrap().perms.execute);

    let found = binary.segments.iter().any(|segment| {
        binary
            .read(segment.address, segment.file_size)
            .is_some_and(|bytes| bytes.windows(GREETING.len()).any(|w| w == GREETING))
    });
    assert!(found, "greeting not readable through segments");
}

#[test]
fn loads_elf() {
    check_x64_fixture("hello-x64.elf", Format::Elf, "add");
}

#[test]
fn loads_pe() {
    check_x64_fixture("hello-x64.exe", Format::Pe, "add");
}

#[test]
fn loads_macho() {
    check_x64_fixture("hello-x64.macho", Format::MachO, "_add");
}

#[test]
fn loads_arm64_macho_metadata() {
    let binary = Binary::open(fixture("hello-arm64.macho")).unwrap();
    assert_eq!(binary.arch, Arch::Aarch64);
    assert!(binary.imports.iter().any(|import| import.name == "_puts"));
}

#[test]
fn reads_never_cross_past_file_backed_bytes() {
    let binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    let segment = binary.segments.iter().find(|segment| segment.file_size > 0).unwrap();
    assert!(binary.read(segment.address + segment.file_size - 1, 1).is_some());
    assert!(binary.read(segment.address + segment.file_size - 1, 2).is_none());
    assert!(binary.read(u64::MAX - 4, 8).is_none());
}

#[test]
fn rejects_non_binaries() {
    let error = Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap_err();
    assert!(matches!(error, rampage_loaders::LoadError::Parse(_)), "{error:?}");
}

#[test]
fn universal_binary_defaults_to_x86_64_slice() {
    let binary = Binary::open(fixture("hello-universal.macho")).unwrap();
    assert_eq!(binary.arch, Arch::X86_64);
    assert_eq!(binary.slices, [Arch::X86_64, Arch::Aarch64]);
    let main = binary.symbol_by_name("_main").unwrap();
    assert_eq!(binary.entry, Some(main.address));
    assert_eq!(binary.read(main.address, 1), Some(&[0x55][..]), "push rbp");
}

#[test]
fn universal_binary_slice_can_be_selected() {
    let binary = Binary::open_with(fixture("hello-universal.macho"), Some(Arch::Aarch64)).unwrap();
    assert_eq!(binary.arch, Arch::Aarch64);
    assert!(binary.imports.iter().any(|import| import.name == "_puts"));
    let thin = Binary::open(fixture("hello-arm64.macho")).unwrap();
    assert_eq!(binary.read(binary.entry.unwrap(), 16), thin.read(thin.entry.unwrap(), 16));
}

#[test]
fn missing_slice_is_an_error() {
    let error = Binary::open_with(fixture("hello-universal.macho"), Some(Arch::X86)).unwrap_err();
    assert!(error.to_string().contains("x86_64"), "{error}");
}

#[test]
fn thin_binary_reports_itself_as_only_slice_and_rejects_other_arch() {
    let binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    assert_eq!(binary.slices, [Arch::X86_64]);
    assert!(Binary::open_with(fixture("hello-x64.elf"), Some(Arch::Aarch64)).is_err());
}

#[test]
fn library_without_entry_point_has_no_entry() {
    let binary = Binary::open(fixture("hello-x64.dylib")).unwrap();
    assert_eq!(binary.entry, None);
    assert!(binary.symbol_by_name("_add").is_some());
}

#[test]
fn stripped_macho_function_starts_cover_add_and_main() {
    let full = Binary::open(fixture("hello-x64.macho")).unwrap();
    let stripped = Binary::open(fixture("hello-x64-stripped.macho")).unwrap();
    assert!(stripped.symbol_by_name("_add").is_none());
    for name in ["_add", "_main"] {
        let address = full.symbol_by_name(name).unwrap().address;
        assert!(stripped.function_starts.contains(&address), "{name} {address:#x}: {:x?}", stripped.function_starts);
    }
    assert!(stripped.function_starts.is_sorted());
}

#[test]
fn pe_function_starts_come_from_pdata() {
    let binary = Binary::open(fixture("hello-x64.exe")).unwrap();
    let add = binary.exports.iter().find(|export| export.name == "add").unwrap().address;
    assert!(binary.function_starts.contains(&add), "{add:#x}");
    assert!(binary.function_starts.len() > 10);
    assert!(binary.function_starts.iter().all(|&start| binary.segment_containing(start).unwrap().perms.execute));
}

fn malformed(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/malformed").join(name)
}

#[test]
fn segment_at_top_of_address_space_is_clipped_not_wrapped() {
    let binary = Binary::open(malformed("wrap.elf")).unwrap();
    for segment in &binary.segments {
        assert!(segment.address.checked_add(segment.size).is_some(), "{segment:?}");
    }
    let segment = &binary.segments[0];
    assert!(binary.read_to_segment_end(segment.address).is_some());
}

#[test]
fn i386_macho_lc_main_entry_is_an_address() {
    let binary = Binary::open(malformed("i386.macho")).unwrap();
    assert_eq!(binary.arch, Arch::X86);
    assert_eq!(binary.entry, Some(0x1f50));
}

#[test]
fn universal_binary_skips_unsupported_first_slice() {
    let binary = Binary::open(malformed("ppc_i386.fat")).unwrap();
    assert_eq!(binary.arch, Arch::X86);
    assert_eq!(binary.slices, [Arch::X86]);
}

#[test]
fn truncated_segment_still_reads_bytes_present_in_the_file() {
    let binary = Binary::open(malformed("trunc.elf")).unwrap();
    let bytes = binary.read_to_segment_end(0x400078).expect("bytes up to end of file");
    assert!(bytes.starts_with(b"\x90\x90\x90\x90\x90\x90\x90\x90SECRETSTRING"));
    assert!(binary.read(0x400078, 0x1000).is_none(), "exact reads past end of file still fail");
}

#[test]
fn corrupt_import_table_is_a_warning_not_a_failure() {
    let binary = Binary::open(malformed("badimport.exe")).unwrap();
    assert!(binary.imports.is_empty());
    assert!(!binary.segments.is_empty());
    assert!(binary.warnings.iter().any(|warning| warning.contains("import")), "{:?}", binary.warnings);
}

#[test]
fn well_formed_fixtures_have_no_warnings() {
    for name in ["hello-x64.elf", "hello-x64.exe", "hello-x64.macho", "hello-arm64.macho"] {
        assert_eq!(Binary::open(fixture(name)).unwrap().warnings, Vec::<String>::new(), "{name}");
    }
}

#[test]
fn code_means_code_sections_not_executable_segments() {
    let binary = Binary::open(fixture("hello-x64.macho")).unwrap();
    let header = binary.symbol_by_name("__mh_execute_header").unwrap().address;
    assert!(binary.segment_containing(header).unwrap().perms.execute, "header shares the executable __TEXT segment");
    assert!(!binary.is_code(header));
    assert!(binary.is_code(binary.symbol_by_name("_main").unwrap().address));
    let cstring = binary.sections.iter().find(|section| section.name == "__cstring").unwrap();
    assert!(!binary.is_code(cstring.address));
}

#[test]
fn code_falls_back_to_segment_permissions_without_sections() {
    let binary = Binary::open(malformed("trunc.elf")).unwrap();
    assert!(binary.sections.iter().all(|section| section.size == 0 || section.address == 0));
    assert!(binary.is_code(0x400078));
}

#[test]
fn oversized_pdata_is_clamped_with_a_warning() {
    let binary = Binary::open(malformed("bigpdata.exe")).unwrap();
    let intact = Binary::open(fixture("hello-x64.exe")).unwrap();
    assert_eq!(binary.function_starts, intact.function_starts);
    assert!(binary.warnings.iter().any(|warning| warning.contains(".pdata")), "{:?}", binary.warnings);
}

#[test]
fn code_from_stops_at_the_end_of_the_code_section() {
    let binary = Binary::open(fixture("hello-x64.macho")).unwrap();
    let main = binary.symbol_by_name("_main").unwrap().address;
    let text = binary.sections.iter().find(|section| section.name == "__text").unwrap();
    assert_eq!(binary.code_from(main).unwrap().len() as u64, text.address + text.size - main);
    let header = binary.symbol_by_name("__mh_execute_header").unwrap().address;
    assert!(binary.code_from(header).is_none());
}

#[test]
fn import_slots_name_the_pointers_each_format_binds() {
    for (name, puts) in [
        ("hello-x64.macho", "_puts"),
        ("hello-arm64.macho", "_puts"),
        ("hello-x64-dyn.elf", "puts"),
        ("hello-arm64.elf", "puts"),
        ("hello-x64.exe", "puts"),
    ] {
        let binary = Binary::open(fixture(name)).unwrap();
        let slot = binary.import_slots.iter().find(|slot| slot.name == puts);
        let slot = slot.unwrap_or_else(|| panic!("{name}: no {puts} slot in {:?}", binary.import_slots));
        assert!(binary.segment_containing(slot.address).is_some_and(|segment| segment.perms.read), "{name}");
        assert!(binary.import_slots.windows(2).all(|pair| pair[0].address < pair[1].address), "{name}: unsorted");
        assert!(binary.warnings.is_empty(), "{name}: {:?}", binary.warnings);
    }
}
