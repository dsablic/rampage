use super::*;
use crate::pe_test_image::{SECTION_RVA, TestPe};
use object::pe::{ImageLoadConfigDirectory32, ImageLoadConfigDirectory64};
use std::mem::{offset_of, size_of};

const LOAD_CONFIG: usize = object::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
const DEBUG: usize = object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG;
const CFG: u16 = 0x4000;
const NO_SEH: u16 = 0x0400;

#[test]
fn layouts_match_the_object_crate_structures() {
    macro_rules! check {
        ($layout:expr, $structure:ty) => {
            assert_eq!($layout.security_cookie, offset_of!($structure, security_cookie));
            assert_eq!($layout.se_handler_table, offset_of!($structure, sehandler_table));
            assert_eq!($layout.se_handler_count, offset_of!($structure, sehandler_count));
            assert_eq!($layout.guard_cf_check, offset_of!($structure, guard_cf_check_function_pointer));
            assert_eq!($layout.guard_cf_dispatch, offset_of!($structure, guard_cf_dispatch_function_pointer));
            assert_eq!($layout.guard_cf_table, offset_of!($structure, guard_cf_function_table));
            assert_eq!($layout.guard_cf_count, offset_of!($structure, guard_cf_function_count));
            assert_eq!($layout.guard_flags, offset_of!($structure, guard_flags));
            assert_eq!($layout.iat_table, offset_of!($structure, guard_address_taken_iat_entry_table));
            assert_eq!($layout.iat_count, offset_of!($structure, guard_address_taken_iat_entry_count));
            assert_eq!($layout.long_jump_table, offset_of!($structure, guard_long_jump_target_table));
            assert_eq!($layout.long_jump_count, offset_of!($structure, guard_long_jump_target_count));
            assert_eq!($layout.dynamic_value_reloc_table, offset_of!($structure, dynamic_value_reloc_table));
            assert_eq!($layout.dynamic_value_reloc_offset, offset_of!($structure, dynamic_value_reloc_table_offset));
            assert_eq!($layout.dynamic_value_reloc_section, offset_of!($structure, dynamic_value_reloc_table_section));
            // The object crate stops at VolatileMetadataPointer; the EH continuation table follows it.
            assert_eq!($layout.eh_table, size_of::<$structure>());
            assert_eq!($layout.eh_count, size_of::<$structure>() + $layout.word);
        };
    }
    check!(LAYOUT_32, ImageLoadConfigDirectory32);
    check!(LAYOUT_64, ImageLoadConfigDirectory64);
}

fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

/// A section holding a load config of `size` declared bytes at offset 0, tables at 0x200.., and a debug directory
/// with an extended DllCharacteristics entry at 0x300.
fn image(bits: u8, size: u32, edit: impl FnOnce(&mut [u8], &Layout, u64)) -> TestPe {
    let layout = if bits == 64 { &LAYOUT_64 } else { &LAYOUT_32 };
    let base = if bits == 64 { crate::pe_test_image::IMAGE_BASE_64 } else { crate::pe_test_image::IMAGE_BASE_32 };
    let va = |offset: u64| base + u64::from(SECTION_RVA) + offset;
    let mut section = vec![0; 0x400];
    let word = layout.word;
    put(&mut section, 0, 4, size.into());
    put(&mut section, 8, 2, 14);
    put(&mut section, layout.security_cookie, word, va(0x1f0));
    put(&mut section, layout.se_handler_table, word, va(0x200));
    put(&mut section, layout.se_handler_count, word, 2);
    put(&mut section, layout.guard_cf_check, word, va(0x1e0));
    put(&mut section, layout.guard_cf_dispatch, word, va(0x1e8));
    put(&mut section, layout.guard_cf_table, word, va(0x220));
    put(&mut section, layout.guard_cf_count, word, 3);
    // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT | LONGJUMP | EH continuation, one metadata byte per entry.
    put(&mut section, layout.guard_flags, 4, 0x1000_0000 | 0x100 | 0x400 | 0x1_0000 | 0x40_0000);
    put(&mut section, layout.long_jump_table, word, va(0x240));
    put(&mut section, layout.long_jump_count, word, 1);
    put(&mut section, layout.dynamic_value_reloc_offset, 4, 0x10);
    put(&mut section, layout.dynamic_value_reloc_section, 2, 1);
    put(&mut section, layout.eh_table, word, va(0x250));
    put(&mut section, layout.eh_count, word, 2);
    put(&mut section, 0x200, 4, 0x1100);
    put(&mut section, 0x204, 4, 0x1180);
    // Debug directory entry: type EX_DLLCHARACTERISTICS, 4 bytes at file offset 0x200 + 0x320.
    put(&mut section, 0x300 + 12, 4, 20);
    put(&mut section, 0x300 + 16, 4, 4);
    put(&mut section, 0x300 + 24, 4, 0x200 + 0x320);
    put(&mut section, 0x320, 4, 0x41);
    edit(&mut section, layout, base);
    let mut pe =
        TestPe::new(bits, section).directory(LOAD_CONFIG, SECTION_RVA, size).directory(DEBUG, SECTION_RVA + 0x300, 28);
    pe.dll_characteristics = CFG | 0x0100;
    pe
}

fn parse(pe: &TestPe) -> PeLoadConfig {
    parse_load_config(&pe.build()).unwrap().unwrap()
}

#[test]
fn reads_a_full_64_bit_load_config() {
    let report = parse(&image(64, 320, |_, _, _| {}));
    assert_eq!(report.warnings, Vec::<String>::new());
    assert_eq!(report.findings, Vec::<String>::new());
    assert_eq!(report.dll_characteristics, ["dep", "cfg"]);
    let config = report.load_config.unwrap();
    assert_eq!((config.declared_size, config.read_size, config.absent_fields.len()), (Some(320), 320, 0));
    assert_eq!(config.version.as_deref(), Some("14.0"));
    let base = crate::pe_test_image::IMAGE_BASE_64 + 0x1000;
    assert_eq!(config.security_cookie, Some(base + 0x1f0));
    assert_eq!(config.safe_seh, None);
    let guard = config.guard.unwrap();
    assert_eq!(
        guard.flag_names,
        ["cf_instrumented", "cf_function_table_present", "cf_longjump_table_present", "eh_continuation_table_present"]
    );
    assert_eq!(
        (guard.check_function_pointer, guard.dispatch_function_pointer),
        (Some(base + 0x1e0), Some(base + 0x1e8))
    );
    assert_eq!(guard.function_table, Some(GuardTable { va: base + 0x220, count: 3, entry_size: 5, in_image: true }));
    assert_eq!(config.long_jump_targets.unwrap().count, 1);
    assert_eq!(
        config.eh_continuations.unwrap(),
        GuardTable { va: base + 0x250, count: 2, entry_size: 5, in_image: true }
    );
    assert_eq!(config.address_taken_iat, Some(GuardTable { va: 0, count: 0, entry_size: 5, in_image: false }));
    let relocations = config.dynamic_value_relocations.unwrap();
    assert!(relocations.present);
    assert_eq!((relocations.table_offset, relocations.table_section), (Some(0x10), Some(1)));
    let cet = report.cet.unwrap();
    assert!(cet.cet_compatible);
    assert_eq!(cet.flag_names, ["cet_compat", "forward_cfi_compat"]);
}

#[test]
fn fields_past_the_declared_size_are_absent() {
    // 72 bytes: through SEHandlerCount, as a Windows 8-era 32-bit linker wrote it.
    let mut pe = image(32, 72, |_, _, _| {});
    pe.dll_characteristics = 0;
    let report = parse(&pe);
    let config = report.load_config.unwrap();
    assert_eq!(config.read_size, 72);
    let seh = config.safe_seh.unwrap();
    assert_eq!((seh.table.count, seh.handlers.as_slice(), seh.handlers_truncated), (2, &[0x1100, 0x1180][..], false));
    assert!(seh.table.in_image);
    assert!(config.guard.is_none() && config.eh_continuations.is_none() && config.dynamic_value_relocations.is_none());
    for field in ["guard_flags", "guard_cf_function_table", "guard_eh_continuation_table"] {
        assert!(config.absent_fields.contains(&field), "{field}");
    }
    assert!(!config.absent_fields.contains(&"security_cookie"));
    assert_eq!(report.findings, Vec::<String>::new());
}

#[test]
fn cross_checks_against_dll_characteristics() {
    // CFG declared but the guard flags are past the declared size, and a 32-bit image without SafeSEH or NO_SEH.
    let mut pe = image(32, 64, |_, _, _| {});
    pe.dll_characteristics = CFG;
    let report = parse(&pe);
    assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
    assert!(report.findings[0].contains("no CF_INSTRUMENTED"));
    assert!(report.findings[1].contains("not validated"));

    // Instrumented without the DllCharacteristics bit, and NO_SEH contradicting a SafeSEH table.
    let mut pe = image(32, 192, |_, _, _| {});
    pe.dll_characteristics = NO_SEH;
    let report = parse(&pe);
    assert!(report.findings[0].contains("does not enforce CFG"), "{:?}", report.findings);
    assert!(report.findings[1].contains("no_seh yet the load config lists 2"));

    // CFG declared and no load config at all.
    let mut pe = TestPe::new(64, vec![0; 16]);
    pe.dll_characteristics = CFG;
    let report = parse(&pe);
    assert!(report.load_config.is_none() && report.cet.is_none());
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn tables_outside_the_image_are_flagged_and_not_read() {
    let pe = image(32, 192, |section, layout, base| {
        put(section, layout.guard_cf_table, 4, base + 0x10_0000);
        put(section, layout.se_handler_count, 4, u64::from(u32::MAX));
        put(section, layout.long_jump_table, 4, base - 0x10);
    });
    let report = parse(&pe);
    let config = report.load_config.unwrap();
    assert!(!config.guard.unwrap().function_table.unwrap().in_image);
    let seh = config.safe_seh.unwrap();
    assert!(!seh.table.in_image && seh.handlers.is_empty() && seh.handlers_truncated);
    assert!(!config.long_jump_targets.unwrap().in_image);
    assert!(report.findings.iter().any(|finding| finding.contains("absent or outside the image")));
}

#[test]
fn a_size_beyond_the_file_reads_what_is_there() {
    let pe = image(64, 0x2000, |_, _, _| {});
    let report = parse(&pe);
    let config = report.load_config.unwrap();
    assert_eq!((config.declared_size, config.read_size), (Some(0x2000), 0x400));
    assert!(config.absent_fields.is_empty());
    assert!(config.guard.is_some());
    assert!(
        report.warnings.iter().any(|warning| warning.contains("only 1024 are in the file")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn an_unmapped_load_config_is_unread_not_absent() {
    let pe = TestPe::new(64, vec![0; 16]).directory(LOAD_CONFIG, 0x9000, 320);
    let report = parse(&pe);
    let config = report.load_config.unwrap();
    assert_eq!((config.declared_size, config.read_size), (None, 0));
    assert!(config.absent_fields.is_empty() && config.guard.is_none() && config.security_cookie.is_none());
    assert!(report.warnings[0].contains("not in the file"));
}

#[test]
fn hostile_debug_entries_are_bounded() {
    let pe = image(64, 320, |section, _, _| put(section, 0x300 + 24, 4, 0xffff_fff0));
    let report = parse(&pe);
    assert!(report.cet.is_none());
    assert!(report.warnings.iter().any(|warning| warning.contains("unreadable")));
}

#[test]
fn non_pe_images_have_no_load_config() {
    assert!(matches!(parse_load_config(b"\x7fELF"), Ok(None)));
}
