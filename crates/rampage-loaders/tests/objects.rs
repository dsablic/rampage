//! Relocatable objects and static archives (tests/fixtures/build-objects.sh): the layout, externs, relocations,
//! Thumb mode, MIPS HI16/LO16 pairs, and opening archive members.

use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::relocatable::OBJECT_BASE;
use rampage_loaders::{Binary, ImageAt, SymbolKind};

fn object(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/objects").join(name)
}

/// Every object fixture and its architecture.
const OBJECTS: [(&str, Arch); 11] = [
    ("objects-x86_64.o", Arch::X86_64),
    ("objects-x86_64-pic.o", Arch::X86_64),
    ("objects-x86.o", Arch::X86),
    ("objects-aarch64.o", Arch::Aarch64),
    ("objects-aarch64-pic.o", Arch::Aarch64),
    ("objects-arm.o", Arch::Arm),
    ("objects-thumb.o", Arch::Arm),
    ("objects-mipsel.o", Arch::Mips),
    ("objects-mipsel-pic.o", Arch::Mips),
    ("objects-riscv64.o", Arch::Riscv64),
    ("objects-riscv64-pic.o", Arch::Riscv64),
];

fn open(name: &str) -> Binary {
    Binary::open(object(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn symbol(binary: &Binary, name: &str) -> u64 {
    binary.symbol_by_name(name).unwrap_or_else(|| panic!("no symbol {name}")).address
}

#[test]
fn allocated_sections_are_laid_out_from_the_base_without_overlap() {
    for (name, arch) in OBJECTS {
        let binary = open(name);
        assert_eq!(binary.arch, arch, "{name}");
        let mut segments = binary.segments.clone();
        segments.sort_by_key(|segment| segment.address);
        assert!(segments.first().is_some_and(|segment| segment.address == OBJECT_BASE), "{name}: {segments:?}");
        for pair in segments.windows(2) {
            assert!(pair[0].address + pair[0].size <= pair[1].address, "{name}: {pair:?} overlap");
        }
        let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
        assert!(text.address >= OBJECT_BASE && binary.is_code(text.address), "{name}");
        for function in ["sum", "main", "dispatch", "scale"] {
            let address = symbol(&binary, function);
            assert!(binary.is_code(address), "{name}: {function} at {address:#x} is not code");
            assert!(binary.read(address, 4).is_some(), "{name}: {function} has no bytes");
        }
        let relocated = binary.relocated().unwrap_or_else(|| panic!("{name}: not laid out"));
        assert!(relocated.unsupported.is_empty(), "{name}: {:?}", relocated.unsupported);
        assert!(relocated.sites_total > 10, "{name}");
    }
}

#[test]
fn undefined_symbols_get_named_extern_slots_and_are_imports() {
    for (name, _) in OBJECTS {
        let binary = open(name);
        let externs = binary.segments.iter().find(|segment| segment.name == "extern").expect(name);
        // Writable (an extern variable never folds), and executable only for the function stubs: no code section.
        assert!(externs.perms.write && externs.perms.execute, "{name}");
        assert!(!binary.is_code(externs.address), "{name}: the extern segment is not code to discover");
        // A function extern's slot branches to itself; a data extern's is zero.
        let stub = binary.read(symbol(&binary, "printf"), 4).unwrap();
        assert_ne!(stub, [0; 4], "{name}");
        assert_eq!(binary.read(symbol(&binary, "ext_counter"), 4), Some(&[0u8; 4][..]), "{name}");
        for (import, kind) in [
            ("printf", SymbolKind::Function),
            ("hal_init", SymbolKind::Function),
            ("strlen", SymbolKind::Function),
            ("ext_counter", SymbolKind::Data),
        ] {
            let found = binary.symbol_by_name(import).unwrap_or_else(|| panic!("{name}: no {import}"));
            assert!(externs.contains(found.address), "{name}: {import} at {:#x}", found.address);
            assert_eq!(found.kind, kind, "{name}: {import}");
            assert!(binary.imports.iter().any(|item| item.name == import), "{name}: {import} not imported");
        }
        // Defined globals are exports, at their placed addresses.
        let main = binary.exports.iter().find(|export| export.name == "main").expect(name);
        assert_eq!(main.address, symbol(&binary, "main"), "{name}");
    }
}

#[test]
fn relocation_sites_keep_their_type_symbol_and_addend() {
    let binary = open("objects-x86_64.o");
    let relocated = binary.relocated().unwrap();
    let main = symbol(&binary, "main");
    let size = binary.symbol_by_name("main").unwrap().size;
    let printf = relocated
        .sites_in(main..main + size)
        .iter()
        .find(|site| site.symbol.as_deref() == Some("printf"))
        .expect("a relocation against printf in main");
    assert_eq!((printf.kind.as_str(), printf.addend), ("R_X86_64_PLT32", -4));
    assert_eq!(printf.value, symbol(&binary, "printf").wrapping_sub(4));
    // The patched field makes the call land on the extern slot.
    let field = binary.read(printf.address, 4).unwrap();
    let displacement = i32::from_le_bytes(field.try_into().unwrap());
    assert_eq!(printf.address.wrapping_add(4).wrapping_add(displacement as i64 as u64), symbol(&binary, "printf"));
    // A table of function pointers holds the functions' placed addresses.
    let handlers = symbol(&binary, "handlers");
    assert_eq!(binary.read_constant(handlers, 8), Some(symbol(&binary, "twice")));
    assert_eq!(binary.read_constant(handlers + 8, 8), Some(symbol(&binary, "thrice")));
}

#[test]
fn got_references_reach_a_synthetic_got_whose_extern_entries_are_import_slots() {
    for name in ["objects-x86_64-pic.o", "objects-aarch64-pic.o", "objects-mipsel-pic.o", "objects-riscv64-pic.o"] {
        let binary = open(name);
        let got = binary.sections.iter().find(|section| section.name == ".got").expect(name);
        let slot = binary.import_slots.iter().find(|slot| slot.name == "ext_counter").expect(name);
        assert!(slot.address >= got.address && slot.address < got.address + got.size, "{name}");
        let width = binary.arch.default_pointer_size().unwrap();
        assert_eq!(binary.read_pointer(slot.address, width), Some(symbol(&binary, "ext_counter")), "{name}");
    }
    // MIPS reaches its GOT through $gp, which is the GOT plus 0x7ff0.
    let mips = open("objects-mipsel-pic.o");
    let got = mips.sections.iter().find(|section| section.name == ".got").unwrap();
    assert_eq!(mips.target().global_pointer, Some(got.address + 0x7ff0));
}

#[test]
fn thumb_objects_mark_their_functions_thumb_and_arm_ones_do_not() {
    let thumb = open("objects-thumb.o");
    let arm = open("objects-arm.o");
    let covered = |binary: &Binary, name: &str| {
        let address = symbol(binary, name);
        binary.thumb.iter().any(|range| range.contains(&address))
    };
    for function in ["sum", "main", "dispatch"] {
        assert!(covered(&thumb, function), "Thumb {function}: {:?}", thumb.thumb);
        assert!(!covered(&arm, function), "ARM {function}: {:?}", arm.thumb);
    }
    // A Thumb function's pointer carries the Thumb bit.
    let handlers = symbol(&thumb, "handlers");
    assert_eq!(thumb.read_constant(handlers, 4), Some(symbol(&thumb, "twice") | 1));
}

#[test]
fn mips_hi16_and_lo16_pairs_together_form_the_address() {
    let binary = open("objects-mipsel.o");
    let relocated = binary.relocated().unwrap();
    let greeting = symbol(&binary, "greeting");
    let sites: Vec<_> = relocated.sites.iter().filter(|site| site.symbol.as_deref() == Some("greeting")).collect();
    let high = sites.iter().find(|site| site.kind == "R_MIPS_HI16").expect("a %hi(greeting)");
    let low = sites.iter().find(|site| site.kind == "R_MIPS_LO16").expect("a %lo(greeting)");
    let immediate = |address: u64| {
        let word = u32::from_le_bytes(binary.read(address, 4).unwrap().try_into().unwrap());
        word & 0xffff
    };
    let formed = (u64::from(immediate(high.address)) << 16).wrapping_add(immediate(low.address) as i16 as i64 as u64);
    assert_eq!(formed, greeting);
    // `jal` reaches the extern slots within their 256 MiB region.
    let hal_init = relocated.sites.iter().find(|site| site.symbol.as_deref() == Some("hal_init")).unwrap();
    assert_eq!(hal_init.kind, "R_MIPS_26");
    let word = u32::from_le_bytes(binary.read(hal_init.address, 4).unwrap().try_into().unwrap());
    assert_eq!(u64::from(word & 0x3ff_ffff) << 2 | (hal_init.address & 0xf000_0000), symbol(&binary, "hal_init"));
}

#[test]
fn common_symbols_live_in_a_zero_filled_segment() {
    let binary = open("objects-x86_64.o");
    let address = symbol(&binary, "shared_total");
    let common = binary.segments.iter().find(|segment| segment.contains(address)).unwrap();
    assert!(matches!(common.name.as_str(), "COMMON" | ".common"), "{common:?}");
    assert!(common.file_size == 0 && common.perms.write);
}

fn archive(name: &str) -> (Vec<u8>, rampage_loaders::ar::Archive) {
    let bytes = std::fs::read(object(name)).unwrap();
    let archive = rampage_loaders::ar::read(&bytes).unwrap();
    (bytes, archive)
}

#[test]
fn gnu_and_bsd_archives_list_members_and_their_index_symbols() {
    let (_, gnu) = archive("libobjects-gnu.a");
    assert_eq!(gnu.kind, "gnu");
    let names: Vec<&str> = gnu.members.iter().map(|member| member.name.as_str()).collect();
    assert_eq!(names, ["objects.o", "helper.o", "objects.o"]);
    assert_eq!((gnu.members[0].duplicates, gnu.members[1].duplicates), (1, 0));
    assert_eq!((gnu.members[0].selector(), gnu.members[2].selector()), ("objects.o#0".into(), "objects.o#2".into()));
    let defines = |archive: &rampage_loaders::ar::Archive, symbol: &str| {
        archive.symbols.iter().filter(|(name, _)| name == symbol).map(|(_, member)| *member).collect::<Vec<_>>()
    };
    assert_eq!(defines(&gnu, "hal_init"), [1]);
    assert_eq!(defines(&gnu, "main"), [0, 2]);

    let (_, bsd) = archive("libobjects-bsd.a");
    assert_eq!(bsd.kind, "bsd");
    let names: Vec<&str> = bsd.members.iter().map(|member| member.name.as_str()).collect();
    assert_eq!(names, ["objects.o", "helper.o"]);
    assert_eq!(defines(&bsd, "hal_init"), [1]);
}

#[test]
fn members_open_by_name_or_index_and_repeated_names_need_the_index() {
    let gnu = object("libobjects-gnu.a");
    let member = |selector: &str| PathBuf::from(format!("{}({selector})", gnu.display()));
    let helper = Binary::open(member("helper.o")).unwrap();
    assert!(helper.symbol_by_name("hal_init").is_some());
    let chosen = helper.archive_member.as_ref().unwrap();
    assert_eq!((chosen.name.as_str(), chosen.index), ("helper.o", 1));
    assert_eq!(helper.embedded.unwrap().offset, chosen.offset);

    let ambiguous = Binary::open(member("objects.o")).unwrap_err().to_string();
    assert!(ambiguous.contains("objects.o#0") && ambiguous.contains("objects.o#2"), "{ambiguous}");
    // The two objects.o members are different builds: non-PIC first, PIC (with a GOT) second.
    let first = Binary::open(member("objects.o#0")).unwrap();
    let second = Binary::open(member("#2")).unwrap();
    assert!(first.sections.iter().all(|section| section.name != ".got"));
    assert!(second.sections.iter().any(|section| section.name == ".got"));
    let wrong = Binary::open(member("helper.o#0")).unwrap_err().to_string();
    assert!(wrong.contains("is `objects.o`"), "{wrong}");
    let missing = Binary::open(member("absent.o")).unwrap_err().to_string();
    assert!(missing.contains("no archive member is named `absent.o`") && missing.contains("helper.o"), "{missing}");

    let bsd = object("libobjects-bsd.a");
    let helper = Binary::open(format!("{}(helper.o)", bsd.display())).unwrap();
    assert!(helper.symbol_by_name("ext_counter").is_some());
}

#[test]
fn a_whole_archive_is_refused_with_its_members_and_how_to_open_one() {
    let error = Binary::open(object("libobjects-gnu.a")).unwrap_err().to_string();
    assert!(error.contains("static archive (gnu ar format, 3 members)"), "{error}");
    assert!(error.contains("libobjects-gnu.a(objects.o#0)") && error.contains("`helper.o`"), "{error}");
}

#[test]
fn an_image_offset_at_a_member_opens_that_member() {
    let (_, gnu) = archive("libobjects-gnu.a");
    let helper = &gnu.members[1];
    let binary = Binary::open_image(object("libobjects-gnu.a"), Some(ImageAt::new(helper.offset, None)), None).unwrap();
    assert_eq!(binary.archive_member.as_ref(), Some(helper));
    assert!(binary.relocated().is_some());
    // A member path with an image offset as well is refused.
    let path = PathBuf::from(format!("{}(helper.o)", object("libobjects-gnu.a").display()));
    assert!(Binary::open_image(path, Some(ImageAt::new(8, None)), None).is_err());
}

/// The applied fields at relocation sites, each as ld.lld writes them when linking the object at the same
/// addresses (the review's comparison: .text, .data and .rodata were byte-identical on every non-PIC fixture).
#[test]
fn applied_fields_match_what_lld_writes_at_the_same_layout() {
    let expected: [(&str, &[(u64, &str)]); 7] = [
        ("objects-x86_64.o", &[(0x100af, "40010100"), (0x100e3, "51000000"), (0x10110, "5c010000")]),
        ("objects-x86.o", &[(0x100b5, "44010100"), (0x100e2, "40010100"), (0x10112, "4a010000")]),
        (
            "objects-aarch64.o",
            &[(0x10098, "09000090"), (0x1009c, "29010591"), (0x100d8, "159d40f9"), (0x10104, "53000094")],
        ),
        ("objects-arm.o", &[(0x100a8, "842100e3"), (0x100b0, "012040e3"), (0x10114, "2d0000eb")]),
        ("objects-thumb.o", &[(0x10078, "40f24012"), (0x10080, "c0f20102"), (0x100ca, "00f061f8")]),
        (
            "objects-mipsel.o",
            &[(0x1013c, "0100013c"), (0x10140, "24022124"), (0x101a8, "2002328c"), (0x101d0, "d840000c")],
        ),
        (
            "objects-riscv64.o",
            &[(0x100b2, "37060100"), (0x100b6, "13068615"), (0x100ec, "83390515"), (0x10116, "97000000")],
        ),
    ];
    for (name, words) in expected {
        let binary = open(name);
        for &(address, hex) in words {
            let bytes: String = binary.read(address, 4).unwrap().iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(bytes, hex, "{name} at {address:#x}");
        }
    }
}

#[test]
fn unapplied_relocations_are_reported_once_per_type_with_their_fields() {
    let binary = open("objects-tls-x86_64.o");
    let relocated = binary.relocated().unwrap();
    assert_eq!(relocated.unsupported.len(), 1);
    let item = &relocated.unsupported[0];
    assert_eq!((item.kind.as_str(), item.count), ("R_X86_64_TPOFF32", 2));
    assert_eq!(relocated.unapplied.len(), 2);
    assert_eq!(relocated.unapplied[0], item.first);
    assert!(binary.warnings.iter().any(|warning| warning.starts_with("R_X86_64_TPOFF32 relocations are not applied")));
}

/// Rewrites the section headers of an ELF64 little-endian object: `edit` gets each section's name and its header
/// fields (`sh_name`, `sh_type`, `sh_flags`, `sh_addr`, `sh_offset`, `sh_size`, `sh_link`, `sh_info`,
/// `sh_addralign`, `sh_entsize`) and the whole file.
fn crafted(name: &str, edit: impl Fn(&str, &mut [u64; 10], &mut Vec<u8>)) -> PathBuf {
    let mut bytes = std::fs::read(object(name)).unwrap();
    let u16_at = |bytes: &[u8], at: usize| u64::from(u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()));
    let u64_at = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let shoff = u64_at(&bytes, 0x28) as usize;
    let (count, strings) = (u16_at(&bytes, 0x3c) as usize, u16_at(&bytes, 0x3e) as usize);
    let header = |bytes: &[u8], index: usize| -> [u64; 10] {
        let at = shoff + index * 64;
        let u32_at =
            |offset: usize| u64::from(u32::from_le_bytes(bytes[at + offset..at + offset + 4].try_into().unwrap()));
        [
            u32_at(0),
            u32_at(4),
            u64_at(bytes, at + 8),
            u64_at(bytes, at + 16),
            u64_at(bytes, at + 24),
            u64_at(bytes, at + 32),
            u32_at(40),
            u32_at(44),
            u64_at(bytes, at + 48),
            u64_at(bytes, at + 56),
        ]
    };
    let names = header(&bytes, strings)[4] as usize;
    for index in 0..count {
        let mut fields = header(&bytes, index);
        let start = names + fields[0] as usize;
        let end = start + bytes[start..].iter().position(|&byte| byte == 0).unwrap();
        let section = String::from_utf8(bytes[start..end].to_vec()).unwrap();
        edit(&section, &mut fields, &mut bytes);
        let at = shoff + index * 64;
        for (offset, width, value) in [
            (0, 4, fields[0]),
            (4, 4, fields[1]),
            (8, 8, fields[2]),
            (16, 8, fields[3]),
            (24, 8, fields[4]),
            (32, 8, fields[5]),
            (40, 4, fields[6]),
            (44, 4, fields[7]),
            (48, 8, fields[8]),
            (56, 8, fields[9]),
        ] {
            bytes[at + offset..at + offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
    }
    let directory = std::env::temp_dir().join(format!("rampage-crafted-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = directory.join(format!("{serial}-{name}"));
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn malformed_objects_load_without_panicking() {
    // A relocation whose offset lies far past the end of the file.
    let past_end = crafted("objects-x86_64.o", |name, fields, bytes| {
        if name == ".rela.text" {
            let at = fields[4] as usize;
            bytes[at..at + 8].copy_from_slice(&0x7fff_ffffu64.to_le_bytes());
        }
    });
    let binary = Binary::open(&past_end).unwrap();
    assert!(binary.warnings.iter().any(|warning| warning.contains("outside their section")), "{:?}", binary.warnings);
    // A zero-fill section of nearly 2^64 bytes, and a section aligned to 2^63: neither is placed, the rest is.
    let huge = crafted("objects-x86_64.o", |name, fields, _| {
        if name == "COMMON" {
            fields[5] = 0xffff_ffff_ffff_0000;
        }
    });
    let binary = Binary::open(&huge).unwrap();
    assert!(binary.warnings.iter().any(|warning| warning.starts_with("section COMMON")), "{:?}", binary.warnings);
    assert!(binary.symbol_by_name("main").is_some());
    let aligned = crafted("objects-x86_64.o", |name, fields, _| {
        if name == ".text" {
            fields[8] = 1 << 63;
        }
    });
    let binary = Binary::open(&aligned).unwrap();
    assert!(binary.warnings.iter().any(|warning| warning.starts_with("section .text")), "{:?}", binary.warnings);
    assert!(binary.symbol_by_name("main").is_none(), "main lies in the unplaced .text");
    for path in [past_end, huge, aligned] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn a_missing_member_path_says_what_was_looked_for() {
    let error = Binary::open(object("absent.a(member.o)")).unwrap_err().to_string();
    let error = format!(
        "{error}: {}",
        std::error::Error::source(&Binary::open(object("absent.a(member.o)")).unwrap_err())
            .map(ToString::to_string)
            .unwrap_or_default()
    );
    assert!(error.contains("absent.a(member.o)") && error.contains("member `member.o`"), "{error}");
}

/// The COFF and Mach-O fixtures and their architectures.
const COFF_AND_MACHO: [(&str, Arch); 7] = [
    ("objects-coff-x86_64.obj", Arch::X86_64),
    ("objects-coff-bigobj.obj", Arch::X86_64),
    ("objects-coff-x86.obj", Arch::X86),
    ("objects-coff-aarch64.obj", Arch::Aarch64),
    ("objects-coff-thumb.obj", Arch::Arm),
    ("objects-macho-x86_64.o", Arch::X86_64),
    ("objects-macho-arm64.o", Arch::Aarch64),
];

/// A symbol's address, under its COFF i386 or Mach-O spelling (a leading underscore) where it has one.
fn either(binary: &Binary, name: &str) -> u64 {
    binary
        .symbol_by_name(name)
        .or_else(|| binary.symbol_by_name(&format!("_{name}")))
        .unwrap_or_else(|| panic!("no symbol {name}"))
        .address
}

#[test]
fn coff_and_macho_objects_are_laid_out_with_every_relocation_applied() {
    for (name, arch) in COFF_AND_MACHO {
        let binary = open(name);
        assert_eq!(binary.arch, arch, "{name}");
        let relocated = binary.relocated().unwrap_or_else(|| panic!("{name}: not laid out"));
        assert!(relocated.unsupported.is_empty(), "{name}: {:?}", relocated.unsupported);
        assert!(relocated.sites_total > 15, "{name}: {}", relocated.sites_total);
        let mut segments = binary.segments.clone();
        segments.sort_by_key(|segment| segment.address);
        assert!(segments.first().is_some_and(|segment| segment.address == OBJECT_BASE), "{name}: {segments:?}");
        for pair in segments.windows(2) {
            assert!(pair[0].address + pair[0].size <= pair[1].address, "{name}: {pair:?} overlap");
        }
        // Debug and linker-directive sections are not loaded.
        assert!(!segments.iter().any(|segment| segment.name.starts_with(".debug") || segment.name == ".drectve"));
        for function in ["sum", "main", "dispatch"] {
            assert!(binary.is_code(either(&binary, function)), "{name}: {function}");
        }
        // A call to an extern lands on its slot, a function.
        let printf = binary.symbol_by_name("printf").or_else(|| binary.symbol_by_name("_printf")).unwrap();
        assert_eq!(printf.kind, SymbolKind::Function, "{name}");
        let call = relocated.sites.iter().find(|site| site.symbol.as_deref() == Some(printf.name.as_str())).unwrap();
        assert_eq!(call.value & !1, printf.address, "{name}");
    }
}

#[test]
fn coff_imports_go_through_pointer_slots_holding_their_externs() {
    for name in
        ["objects-coff-x86_64.obj", "objects-coff-x86.obj", "objects-coff-aarch64.obj", "objects-coff-thumb.obj"]
    {
        let binary = open(name);
        let relocated = binary.relocated().unwrap();
        assert_eq!(relocated.directives, ["/DEFAULTLIB:kernel32.lib"], "{name}");
        let table = binary.sections.iter().find(|section| section.name == ".idata").expect(name);
        let width = binary.arch.default_pointer_size().unwrap();
        for import in ["GetTickCount", "imported_flag"] {
            let slot = binary.import_slots.iter().find(|slot| slot.name.trim_start_matches('_') == import).unwrap();
            assert!(slot.address >= table.address && slot.address < table.address + table.size, "{name}");
            assert_eq!(binary.read_pointer(slot.address, width), Some(either(&binary, import)), "{name}: {import}");
            assert_eq!(either(&binary, &format!("__imp_{}", slot.name)), slot.address, "{name}: {import}");
        }
        let function = binary.symbol_by_name("GetTickCount").or(binary.symbol_by_name("_GetTickCount")).unwrap();
        assert_eq!(function.kind, SymbolKind::Function, "{name}");
        // The weak definition is named for what it defines; the undefined weak function is null, as linked.
        assert!(binary.is_code(either(&binary, "weak_hook")), "{name}");
        assert!(!binary.symbols.iter().any(|symbol| symbol.name.starts_with(".weak.")), "{name}");
        let null =
            relocated.sites.iter().find(|site| matches!(site.symbol.as_deref(), Some("maybe_hook" | "_maybe_hook")));
        assert_eq!(null.map(|site| site.value), Some(0), "{name}");
    }
}

#[test]
fn a_big_object_loads_as_the_object_it_was_made_from() {
    let small = open("objects-coff-x86_64.obj");
    let big = open("objects-coff-bigobj.obj");
    let read = |binary: &Binary| {
        let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
        binary.read(text.address, text.size).unwrap().to_vec()
    };
    assert_eq!(read(&small), read(&big));
    assert_eq!(small.relocated().unwrap().sites, big.relocated().unwrap().sites);
}

/// Fields as rampage applies them, each checked against lld-link and ld64.lld output for the same object: every
/// relocation references S + A in both images, with each image's own S.
#[test]
fn coff_and_macho_applied_fields_are_pinned() {
    let expected: [(&str, &[(u64, &str)]); 6] = [
        ("objects-coff-x86_64.obj", &[(0x100fa, "12020000"), (0x10130, "fc010000")]),
        ("objects-coff-x86.obj", &[(0x100d3, "78010100"), (0x100dd, "1f010000"), (0x1011a, "20020100")]),
        ("objects-coff-aarch64.obj", &[(0x100fc, "69000094"), (0x10130, "08000090"), (0x10138, "086141f9")]),
        ("objects-coff-thumb.obj", &[(0x100cc, "00f0d0f8"), (0x100f0, "40f29020")]),
        (
            "objects-macho-arm64.o",
            &[(0x10104, "49080094"), (0x10140, "082141f9"), (0x10150, "000000b0"), (0x10154, "00d02891")],
        ),
        (
            "objects-macho-x86_64.o",
            &[(0x10112, "82220000"), (0x10136, "f9020000"), (0x1013d, "f3020000"), (0x10148, "64220000")],
        ),
    ];
    for (name, words) in expected {
        let binary = open(name);
        for &(address, hex) in words {
            let bytes: String = binary.read(address, 4).unwrap().iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(bytes, hex, "{name} at {address:#x}");
        }
    }
}

#[test]
fn macho_objects_keep_their_section_addresses_and_resolve_pairs() {
    let binary = open("objects-macho-arm64.o");
    let relocated = binary.relocated().unwrap();
    // An ADDEND pair: the page and offset of `local_array + 6000`.
    let far = relocated.sites.iter().find(|site| site.kind == "ARM64_RELOC_PAGEOFF12" && site.addend == 6000).unwrap();
    assert_eq!(far.value, symbol(&binary, "_local_array") + 6000);
    // A SUBTRACTOR pair: `_greeting - _sum` in `_differences`.
    let field = binary.read(symbol(&binary, "_differences"), 8).unwrap();
    let difference = u64::from_le_bytes(field.try_into().unwrap());
    assert_eq!(difference, symbol(&binary, "_greeting") - symbol(&binary, "_sum"));
    // The assembler's section labels do not shadow the functions.
    assert!(binary.symbols.iter().all(|symbol| !symbol.name.starts_with("ltmp")));
    // An extern reached through the GOT is an import slot.
    let slot = binary.import_slots.iter().find(|slot| slot.name == "_ext_array").unwrap();
    assert_eq!(binary.read_pointer(slot.address, 8), Some(symbol(&binary, "_ext_array")));
}

#[test]
fn msvc_libraries_and_universal_libraries_open_members() {
    let lib = object("libobjects-coff.lib");
    let (_, archive) = archive("libobjects-coff.lib");
    assert_eq!(archive.kind, "coff");
    let helper = Binary::open(format!("{}(helper.obj)", lib.display())).unwrap();
    assert!(helper.symbol_by_name("hal_init").is_some() && helper.relocated().is_some());
    let objects = Binary::open(format!("{}(objects.obj)", lib.display())).unwrap();
    assert!(objects.symbol_by_name("uses_imports").is_some());

    // An import library's members are imports, which open with a message, not as code.
    let imports = std::fs::read(object("imports-coff.lib")).unwrap();
    let library = rampage_loaders::ar::read(&imports).unwrap();
    let rows: Vec<_> = library
        .members
        .iter()
        .filter_map(|member| {
            let bytes = &imports[member.offset as usize..(member.offset + member.size) as usize];
            rampage_loaders::ar::import_member(bytes).map(|import| (member.index, import))
        })
        .collect();
    let by = |symbol: &str| rows.iter().find(|(_, import)| import.symbol == symbol).unwrap();
    assert_eq!((by("GetTickCount").1.dll.as_str(), by("GetTickCount").1.kind), ("fixture.dll", "code"));
    assert_eq!(by("imported_flag").1.kind, "data");
    assert_eq!((by("by_ordinal").1.by, by("by_ordinal").1.ordinal_or_hint), ("ordinal", 7));
    let error = Binary::open(format!("{}(#{})", object("imports-coff.lib").display(), by("GetTickCount").0))
        .unwrap_err()
        .to_string();
    assert!(error.contains("short import object") && error.contains("fixture.dll!GetTickCount"), "{error}");

    // A universal library opens a member of the slice the architecture picks.
    let universal = object("libobjects-macho.a");
    let member = format!("{}(objects.o)", universal.display());
    let x86 = Binary::open(&member).unwrap();
    let arm = Binary::open_with(&member, Some(Arch::Aarch64)).unwrap();
    assert_eq!((x86.arch, arm.arch), (Arch::X86_64, Arch::Aarch64));
    assert_eq!(arm.archive_member.as_ref().and_then(|member| member.arch.as_deref()), Some("aarch64"));
    assert!(arm.symbol_by_name("_bump").is_some() && arm.relocated().is_some());
    let whole = Binary::open(&universal).unwrap_err().to_string();
    assert!(whole.contains("universal library"), "{whole}");
}
