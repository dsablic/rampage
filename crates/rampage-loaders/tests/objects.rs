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
        assert_eq!((externs.file_size, externs.perms.execute), (0, false), "{name}");
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
