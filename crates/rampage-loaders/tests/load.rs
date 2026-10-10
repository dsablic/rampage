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
fn universal_binary_prefers_common_slices_over_the_first() {
    // The PowerPC slice comes first (and is not a valid image); x86 is preferred by default.
    let binary = Binary::open(malformed("ppc_i386.fat")).unwrap();
    assert_eq!(binary.arch, Arch::X86);
    assert_eq!(binary.slices, [Arch::PowerPc, Arch::X86]);
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

#[test]
fn eh_frame_supplies_function_starts_for_elf() {
    for name in ["hello-x64.elf", "hello-x64-dyn.elf", "hello-arm64.elf"] {
        let binary = Binary::open(fixture(name)).unwrap();
        assert!(binary.function_starts.len() >= 4, "{name}: {:?}", binary.function_starts);
        let functions: Vec<u64> = binary
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
            .map(|symbol| symbol.address)
            .collect();
        for start in &binary.function_starts {
            assert!(functions.contains(start), "{name}: {start:#x} is not a function symbol");
        }
        let main = binary.symbol_by_name("main").unwrap().address;
        assert!(binary.function_starts.contains(&main), "{name}: main missing");
    }
}

#[test]
fn hostile_bind_streams_and_image_bases_do_not_hang_or_overflow() {
    // A bind repeated 2^62 times stops with a warning instead of exhausting memory.
    let binary = Binary::open(malformed("bindloop.macho")).unwrap();
    assert!(binary.warnings.iter().any(|warning| warning.contains("bind stream")), "{:?}", binary.warnings);
    // Binds that wrap the address space or fall outside their segment are dropped.
    for name in ["bindwrap.macho", "bindfar.macho"] {
        let binary = Binary::open(malformed(name)).unwrap();
        assert!(binary.import_slots.is_empty(), "{name}: {:?}", binary.import_slots);
    }
    // Import address table entries past the top of the address space are dropped.
    let binary = Binary::open(malformed("highbase.exe")).unwrap();
    assert!(binary.import_slots.iter().all(|slot| slot.address >= 0xffff_ffff_fffe_0000));
}

#[test]
fn details_describe_each_format() {
    let pe = Binary::open(fixture("hello-x64.exe")).unwrap();
    let rampage_loaders::Details::Pe(details) = &pe.details else { panic!("{:?}", pe.details) };
    assert_eq!(details.subsystem, "windows_cui");
    assert!(details.characteristics.contains(&"aslr") && details.characteristics.contains(&"dep"));
    assert!(!details.signed);

    let elf = Binary::open(fixture("hello-x64-dyn.elf")).unwrap();
    let rampage_loaders::Details::Elf(details) = &elf.details else { panic!("{:?}", elf.details) };
    assert_eq!(details.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
    assert_eq!(details.needed, ["libc.so.6"]);
    assert!(details.nx);

    let macho = Binary::open(fixture("hello-arm64.macho")).unwrap();
    let rampage_loaders::Details::MachO(details) = &macho.details else { panic!("{:?}", macho.details) };
    assert_eq!(details.file_type, "execute");
    assert!(details.flags.contains(&"pie"));
    assert_eq!(details.dylibs, ["/usr/lib/libSystem.B.dylib"]);
    assert_eq!(details.platform.as_deref(), Some("macos"));
    assert!(details.code_signature && details.uuid.is_some());
}

#[test]
fn appended_data_is_an_overlay_and_padding_is_not() {
    for (name, original) in [("overlay.exe", "hello-x64.exe"), ("overlay.elf", "hello-x64-dyn.elf")] {
        let clean = Binary::open(fixture(original)).unwrap();
        assert_eq!(clean.overlay, None, "{original}");
        let binary = Binary::open(malformed(name)).unwrap();
        let overlay = binary.overlay.unwrap_or_else(|| panic!("{name}: no overlay"));
        assert_eq!(overlay.size, 512, "{name}");
        assert_eq!(&binary.image_bytes()[overlay.offset as usize..][..8], b"PAYLOAD!");
    }
}

#[test]
fn overlays_respect_certificates_and_ignore_impossible_ranges() {
    for name in ["signed_overlay.exe", "bigcert.exe"] {
        let overlay = Binary::open(malformed(name)).unwrap().overlay.unwrap_or_else(|| panic!("{name}: no overlay"));
        assert_eq!((overlay.offset, overlay.size), (0x35c00, 512), "{name}");
    }
    // A truncated file's segments run past its end, and still account for all of it.
    assert_eq!(Binary::open(malformed("trunc.elf")).unwrap().overlay, None);
    // Object files keep symbols and relocations past their sections; none of it is overlay.
    for name in ["hello-x64.o", "hello-x64-elf.o"] {
        assert_eq!(Binary::open(fixture(name)).unwrap().overlay, None, "{name}");
    }
}

#[test]
fn imphash_reads_regular_imports_only() {
    let imphash = |binary: Binary| match binary.details {
        rampage_loaders::Details::Pe(pe) => pe.imphash,
        other => panic!("{other:?}"),
    };
    let original = imphash(Binary::open(fixture("hello-x64.exe")).unwrap());
    assert_eq!(original.as_deref(), Some("ce66a1eb6671f220f5a569f65867a95b"));
    let delayed = Binary::open(malformed("delay.exe")).unwrap();
    assert!(delayed.imports.len() > Binary::open(fixture("hello-x64.exe")).unwrap().imports.len());
    assert_eq!(imphash(delayed), original);
}

#[test]
fn elf_dynamic_data_survives_missing_section_headers() {
    let binary = Binary::open(malformed("sstrip.elf")).unwrap();
    let rampage_loaders::Details::Elf(details) = &binary.details else { panic!("{:?}", binary.details) };
    assert_eq!(details.needed, ["libc.so.6"]);
    assert_eq!(details.relro, "full");
}

#[test]
fn import_slots_know_their_library() {
    let binary = Binary::open(malformed("dup.exe")).unwrap();
    let frees: Vec<_> = binary.import_slots.iter().filter(|slot| slot.name == "free").collect();
    assert_eq!(frees.len(), 2);
    assert_ne!(frees[0].library, frees[1].library);
    let macho = Binary::open(fixture("hello-arm64.macho")).unwrap();
    let puts = macho.import_slots.iter().find(|slot| slot.name == "_puts").unwrap();
    assert_eq!(puts.library.as_deref(), Some("/usr/lib/libSystem.B.dylib"));
}

#[test]
fn big_endian_eh_frame_gives_function_starts() {
    for name in ["hello-ppc.elf", "hello-mips.elf", "hello-s390x.elf"] {
        let binary = Binary::open(fixture(name)).unwrap();
        assert!(binary.big_endian && binary.warnings.is_empty(), "{name}: {:?}", binary.warnings);
        let main = binary.symbol_by_name("main").unwrap().address;
        assert!(binary.function_starts.contains(&main), "{name}: main {main:#x} not among the starts");
    }
}

#[test]
fn thumb_functions_cover_their_whole_body() {
    let binary = Binary::open(fixture("hello-thumb.elf")).unwrap();
    let main = binary.symbol_by_name("main").unwrap();
    let target = binary.target();
    assert!(target.is_thumb(main.address) && target.is_thumb(main.address + main.size - 2));
    assert!(binary.thumb.iter().all(|range| range.end != u64::MAX));
}
