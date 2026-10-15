#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_arch::Arch;
use rampage_loaders::{
    Binary, Format, LinkageCoverageStatus, LinkageExportTarget, LinkageImportProvenance, LinkageLimitation,
    LinkageLimits, LinkageMetadata, LinkageStatus, LinkageSymbol,
};

struct Source {
    path: PathBuf,
}

impl Source {
    fn new(data: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-linkage-{}-{}.renamed",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, data).unwrap();
        Self { path }
    }

    fn binary(&self) -> Binary {
        Binary::open(&self.path).unwrap()
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn text(data: &mut [u8], at: usize, value: &[u8]) {
    data[at..at + value.len()].copy_from_slice(value);
    data[at + value.len()] = 0;
}

// Deliberately independent source oracle: RVAs equal file offsets in this single-section test image.
fn image() -> Vec<u8> {
    let mut data = vec![0; 0x3000];
    text(&mut data, 0, b"MZ");
    put32(&mut data, 0x3c, 0x80);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut data, 0x84, 0x8664);
    put16(&mut data, 0x86, 1);
    put16(&mut data, 0x94, 240);
    put16(&mut data, 0x96, 0x2022);
    put16(&mut data, 0x98, 0x20b);
    put64(&mut data, 0xb0, 0x1_4000_0000);
    put32(&mut data, 0xb8, 0x1000);
    put32(&mut data, 0xbc, 0x200);
    put32(&mut data, 0xd0, 0x4000);
    put32(&mut data, 0xd4, 0x200);
    put32(&mut data, 0x104, 16);
    put32(&mut data, 0x108, 0x1000);
    put32(&mut data, 0x10c, 0x200);
    put32(&mut data, 0x110, 0x1300);
    put32(&mut data, 0x114, 40);
    put32(&mut data, 0x170, 0x1500);
    put32(&mut data, 0x174, 64);
    text(&mut data, 0x188, b".rdata");
    for (at, value) in [(0x190, 0x3000), (0x194, 0x1000), (0x198, 0x2000), (0x19c, 0x1000)] {
        put32(&mut data, at, value);
    }
    put32(&mut data, 0x1ac, 0x4000_0040);
    for (at, value) in [
        (0x100c, 0x1100),
        (0x1010, 7),
        (0x1014, 3),
        (0x1018, 3),
        (0x101c, 0x1040),
        (0x1020, 0x1060),
        (0x1024, 0x1080),
        (0x1040, 0x2000),
        (0x1044, 0x1180),
        (0x1048, 0x2008),
        (0x1060, 0x1120),
        (0x1064, 0x1130),
        (0x1068, 0x1140),
        (0x1300, 0x1400),
        (0x130c, 0x1380),
        (0x1310, 0x1440),
        (0x1500, 1),
        (0x1504, 0x1380),
        (0x150c, 0x1480),
        (0x1510, 0x14a0),
    ] {
        put32(&mut data, at, value);
    }
    put16(&mut data, 0x1080, 0);
    put16(&mut data, 0x1082, 0);
    put16(&mut data, 0x1084, 1);
    text(&mut data, 0x1100, b"ACTUAL.DLL");
    text(&mut data, 0x1120, b"#7");
    text(&mut data, 0x1130, b"alias\xff");
    text(&mut data, 0x1140, b"forwarded");
    text(&mut data, 0x1180, b"OTHER.#9");
    text(&mut data, 0x1380, b"Provider.DLL");
    put64(&mut data, 0x1400, 0x1600);
    put64(&mut data, 0x1408, 0x8000_0000_0000_0007);
    put64(&mut data, 0x14a0, 0x1600);
    text(&mut data, 0x1602, b"#7");
    data
}

fn metadata(data: &[u8], limits: LinkageLimits) -> LinkageMetadata {
    Source::new(data).binary().linkage_metadata(limits).unwrap()
}

#[test]
fn exact_source_identity_raw_aliases_forwarders_ordinals_and_slots_are_not_legacy_dto_guesses() {
    let source = Source::new(&image());
    let mut binary = source.binary();
    binary.imports.clear();
    binary.import_slots.clear();
    binary.exports.clear();
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.status, LinkageStatus::Available);
    assert_eq!(report.export_directory_present, Some(true));
    assert_eq!(report.producer_library.as_deref(), Some(b"ACTUAL.DLL".as_slice()));
    assert_eq!(report.imports.len(), 3);
    assert_eq!(report.imports[0].symbol, LinkageSymbol::Named(b"#7".to_vec()));
    assert_eq!(report.imports[1].symbol, LinkageSymbol::Ordinal(7));
    assert_eq!(report.imports[2].symbol, report.imports[0].symbol);
    assert_eq!(report.imports[0].slot_address, 0x1_4000_1440);
    assert_eq!(report.imports[1].slot_address, 0x1_4000_1448);
    assert_eq!(report.imports[2].slot_address, 0x1_4000_1480);
    assert_eq!(report.imports[0].provenance, LinkageImportProvenance::PeImportDirectory);
    assert_eq!(report.imports[2].provenance, LinkageImportProvenance::PeDelayImportDirectory);
    assert_eq!(report.exports.len(), 4);
    assert_eq!(report.exports[0].ordinal, 7);
    assert_eq!(report.exports[1].name.as_deref(), Some(b"alias\xff".as_slice()));
    assert_eq!(report.exports[1].ordinal, 7);
    assert!(matches!(
        report.exports[0].target,
        LinkageExportTarget::Direct { address: 0x1_4000_2000, executable_backing: false }
    ));
    assert_eq!(report.exports[2].target, LinkageExportTarget::Forwarder { raw: b"OTHER.#9".to_vec() });
    assert_eq!(report.exports[3].name, None);
    assert_eq!(report.exports[3].ordinal, 9);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["imports"][0]["slot_address"], "0x140001440");
}

#[test]
fn missing_producer_identity_has_no_path_or_product_fallback() {
    let mut data = image();
    put32(&mut data, 0x100c, 0);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.status, LinkageStatus::InsufficientIdentity);
    assert_eq!(report.export_directory_present, Some(true));
    assert_eq!(report.producer_library, None);
    assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Complete);
}

#[test]
fn delay_va_mode_and_missing_descriptor_terminators_never_claim_complete_coverage() {
    for (at, value, expected) in
        [(0x1500, 0, LinkageLimitation::DelayVaModeUnsupported), (0x114, 20, LinkageLimitation::MalformedTable)]
    {
        let mut data = image();
        put32(&mut data, at, value);
        let report = metadata(&data, LinkageLimits::default());
        assert_eq!(report.status, LinkageStatus::Incomplete);
        assert!(report.limitations.contains(&expected));
        let coverage = if at == 0x1500 { &report.delay_imports } else { &report.regular_imports };
        assert_ne!(coverage.status, LinkageCoverageStatus::Complete);
    }
}

#[test]
fn empty_tables_report_complete_zero_counts_but_not_a_fabricated_library_identity() {
    let mut data = image();
    for at in [0x108, 0x10c, 0x110, 0x114, 0x170, 0x174] {
        put32(&mut data, at, 0);
    }
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.export_directory_present, Some(false));
    for coverage in [&report.regular_imports, &report.delay_imports, &report.export_coverage] {
        assert_eq!(coverage.status, LinkageCoverageStatus::Complete);
        assert_eq!(coverage.declared_records, Some(0));
        assert_eq!(coverage.records, 0);
    }
    assert_eq!(report.status, LinkageStatus::InsufficientIdentity);
}

#[test]
fn record_and_native_vector_preflights_precede_any_name_copy() {
    let report = metadata(&image(), LinkageLimits { max_records: 2, ..LinkageLimits::default() });
    assert!(report.limitations.contains(&LinkageLimitation::RecordLimit));
    assert_eq!(report.name_bytes, 0);
    let source = Source::new(&image());
    let binary = source.binary();
    let report = binary.linkage_metadata(LinkageLimits { max_records: 0, ..LinkageLimits::default() }).unwrap();
    assert_eq!(report.lookup_work, 0);
    assert!(report.imports.is_empty());
    assert!(report.exports.is_empty());
}

#[test]
fn string_limits_and_lookup_budget_never_leave_partial_tables_marked_complete() {
    for limits in [
        LinkageLimits { max_name_bytes: 2, ..LinkageLimits::default() },
        LinkageLimits { max_total_name_bytes: 5, ..LinkageLimits::default() },
        LinkageLimits { max_lookup_work: 2, ..LinkageLimits::default() },
    ] {
        let report = metadata(&image(), limits);
        assert_ne!(report.status, LinkageStatus::Available);
        assert!(report.imports.is_empty());
        assert!(report.exports.is_empty());
        assert!(report.name_bytes <= limits.max_total_name_bytes);
        assert!(report.lookup_work <= limits.max_lookup_work);
    }
}

#[test]
fn virtual_zero_fill_truncated_names_and_overlapping_sections_cannot_supply_identity() {
    let mut zero_fill = image();
    put32(&mut zero_fill, 0x100c, 0x3100);
    let report = metadata(&zero_fill, LinkageLimits::default());
    assert_eq!(report.producer_library, None);
    assert!(report.limitations.contains(&LinkageLimitation::UnavailableBytes));

    let mut unterminated = image();
    put32(&mut unterminated, 0x100c, 0x2ff0);
    unterminated[0x2ff0..].fill(b'x');
    let report = metadata(&unterminated, LinkageLimits::default());
    assert_eq!(report.producer_library, None);
    assert!(report.limitations.contains(&LinkageLimitation::UnterminatedString));

    let mut overlap = image();
    put16(&mut overlap, 0x86, 2);
    let section = overlap[0x188..0x1b0].to_vec();
    overlap[0x1b0..0x1d8].copy_from_slice(&section);
    let report = metadata(&overlap, LinkageLimits::default());
    assert_ne!(report.export_coverage.status, LinkageCoverageStatus::Complete);
    assert!(report.limitations.contains(&LinkageLimitation::AmbiguousMapping));
}

#[test]
fn selected_embedded_image_is_the_only_metadata_source() {
    let selected = image();
    let mut outer = vec![0x5a; 0x1000];
    outer.extend_from_slice(&selected);
    outer.extend_from_slice(&[0x5a; 0x100]);
    let source = Source::new(&outer);
    let binary = Binary::open_at(&source.path, 0x1000, Some(selected.len() as u64)).unwrap();
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.producer_library.as_deref(), Some(b"ACTUAL.DLL".as_slice()));
    assert_eq!(report.imports[0].slot_address, 0x1_4000_1440);
}

#[test]
fn owned_snapshot_even_when_relabelled_pe_is_not_native_header_evidence() {
    let source = serde_json::to_vec(&serde_json::json!({
        "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
        "provenance":"not a native source", "seeds":["0x1000"],
        "regions":[{"name":"code","address":"0x1000","permissions":"r-x","bytes":"c3"}]
    }))
    .unwrap();
    let mut binary = Binary::from_snapshot_bytes(source).unwrap();
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.status, LinkageStatus::Unsupported);
    assert_eq!(report.export_directory_present, None);
    binary.format = Format::Pe;
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.status, LinkageStatus::Unsupported);
    assert_eq!(report.export_directory_present, None);
    assert!(report.limitations.contains(&LinkageLimitation::UnverifiedSource));
}

#[test]
fn changed_or_replaced_backing_source_is_rejected_before_mapped_reads() {
    use std::io::{Seek, SeekFrom, Write};
    let source = Source::new(&image());
    let binary = source.binary();
    let mut file = std::fs::OpenOptions::new().write(true).open(&source.path).unwrap();
    file.seek(SeekFrom::Start(0x1100)).unwrap();
    file.write_all(b"CHANGED").unwrap();
    file.set_len(0x3001).unwrap();
    assert!(binary.linkage_metadata(LinkageLimits::default()).is_err());

    let source = Source::new(&image());
    let binary = source.binary();
    let replacement = Source::new(&image());
    std::fs::rename(&replacement.path, &source.path).unwrap();
    assert!(binary.linkage_metadata(LinkageLimits::default()).is_err());
}

#[test]
fn architecture_mismatch_and_image_cap_fail_without_guessing_addresses() {
    let source = Source::new(&image());
    let mut binary = source.binary();
    binary.arch = Arch::X86;
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.status, LinkageStatus::WidthUnsupported);
    assert!(report.imports.is_empty());
    let report = binary.linkage_metadata(LinkageLimits { max_image_bytes: 32, ..LinkageLimits::default() }).unwrap();
    assert_eq!(report.lookup_work, 0);
    assert!(report.limitations.contains(&LinkageLimitation::ImageLimit));
}

#[test]
fn raw_long_names_and_overflowing_export_counts_are_bounded_before_copying() {
    let mut data = image();
    put32(&mut data, 0x100c, 0x1800);
    data[0x1800..0x2802].fill(b'x');
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.producer_library, None);
    assert!(report.limitations.contains(&LinkageLimitation::NameLimit));

    let mut data = image();
    put32(&mut data, 0x1014, u32::MAX);
    let report = metadata(&data, LinkageLimits::default());
    assert!(report.exports.is_empty());
    assert_eq!(report.export_coverage.declared_records, Some(u64::from(u32::MAX) + 3));
    assert_eq!(report.export_coverage.limitation, Some(LinkageLimitation::RecordLimit));
}

#[test]
fn x86_image_base_plus_image_extent_must_fit_the_architecture_width() {
    let mut data = image();
    let directories = data[0x108..0x188].to_vec();
    let section = data[0x188..0x1b0].to_vec();
    data[0xf8..0x178].copy_from_slice(&directories);
    data[0x178..0x1a0].copy_from_slice(&section);
    put16(&mut data, 0x84, 0x14c);
    put16(&mut data, 0x94, 224);
    put16(&mut data, 0x98, 0x10b);
    put32(&mut data, 0xb4, 0xffff_f000);
    put32(&mut data, 0xf4, 16);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.status, LinkageStatus::WidthUnsupported);
    assert!(report.exports.is_empty());
}

#[test]
fn retained_native_fixture_export_add_is_raw_evidence_and_elf_is_explicitly_unsupported() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
    let binary = Binary::open(fixtures.join("hello-x64.exe")).unwrap();
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Complete);
    let add = report.exports.iter().find(|export| export.name.as_deref() == Some(b"add".as_slice())).unwrap();
    assert!(matches!(add.target, LinkageExportTarget::Direct { .. }));
    let binary = Binary::open(fixtures.join("hello-x64.elf")).unwrap();
    let report = binary.linkage_metadata(LinkageLimits::default()).unwrap();
    assert_eq!(report.status, LinkageStatus::Unsupported);
    assert!(report.limitations.contains(&LinkageLimitation::UnsupportedFormat));
}

#[test]
fn exe_with_real_imports_and_absent_export_directory_is_not_an_unknown_export_provider() {
    let mut data = image();
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, 0x108, 0);
    put32(&mut data, 0x10c, 0);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.export_directory_present, Some(false));
    assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.export_coverage.declared_records, Some(0));
    assert_eq!(report.export_coverage.records, 0);
    assert!(report.exports.is_empty());
    assert_eq!(report.producer_library, None);
    assert_eq!(report.regular_imports.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.delay_imports.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.imports.len(), 3);
    assert_eq!(report.imports[0].symbol, LinkageSymbol::Named(b"#7".to_vec()));
}

#[test]
fn unreadable_declared_export_directory_remains_present_not_absent() {
    let mut data = image();
    put32(&mut data, 0x108, 0x3100);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.export_directory_present, Some(true));
    assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Unavailable);
    assert!(report.exports.is_empty());
    assert_eq!(report.producer_library, None);
    assert_eq!(report.regular_imports.status, LinkageCoverageStatus::Complete);
}

#[test]
fn inconsistent_export_directory_entries_are_malformed_header_evidence_not_absence() {
    for (rva, size) in [(0, 0x200), (0x1000, 0)] {
        let mut data = image();
        put32(&mut data, 0x108, rva);
        put32(&mut data, 0x10c, size);
        let report = metadata(&data, LinkageLimits::default());
        assert_eq!(report.export_directory_present, None);
        assert_eq!(report.status, LinkageStatus::Unavailable);
        assert!(report.limitations.contains(&LinkageLimitation::MalformedHeaders));
        assert_ne!(report.export_coverage.status, LinkageCoverageStatus::Complete);
    }
}

#[test]
fn zero_declared_data_directories_prove_absence_without_consulting_undeclared_entry_bytes() {
    let mut data = image();
    put32(&mut data, 0x104, 0);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.export_directory_present, Some(false));
    assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.export_coverage.declared_records, Some(0));
    assert_eq!(report.export_coverage.records, 0);
    assert!(report.exports.is_empty());
    assert!(report.imports.is_empty());
}

#[test]
fn outside_header_rvas_distinguish_backed_sections_from_unmapped_gaps_without_underflow() {
    for (rva, expected) in [(0x1100, Some(b"ACTUAL.DLL".as_slice())), (0x800, None)] {
        let mut data = image();
        put32(&mut data, 0x100c, rva);
        let report = metadata(&data, LinkageLimits::default());
        assert_eq!(report.producer_library.as_deref(), expected);
        assert_eq!(report.export_directory_present, Some(true));
        assert_eq!(report.export_coverage.status, LinkageCoverageStatus::Complete);
        if expected.is_none() {
            assert!(report.limitations.contains(&LinkageLimitation::UnavailableBytes));
        }
    }
}

#[test]
fn regular_and_delay_iats_require_a_backed_terminal_slot_after_the_last_import() {
    for delay in [false, true] {
        let mut data = image();
        let (iat_field, first_slot) = if delay { (0x150c, 0x2ff8) } else { (0x1310, 0x2ff0) };
        put32(&mut data, iat_field, first_slot);
        let report = metadata(&data, LinkageLimits::default());
        let coverage = if delay { &report.delay_imports } else { &report.regular_imports };
        let provenance = if delay {
            LinkageImportProvenance::PeDelayImportDirectory
        } else {
            LinkageImportProvenance::PeImportDirectory
        };
        assert_eq!(coverage.status, LinkageCoverageStatus::Unavailable);
        assert_eq!(coverage.limitation, Some(LinkageLimitation::UnavailableBytes));
        assert_eq!(coverage.records, 0);
        assert!(report.imports.iter().all(|import| import.provenance != provenance));
    }
}

#[test]
fn empty_regular_and_delay_ints_still_require_backed_null_iat_entries() {
    for delay in [false, true] {
        let mut data = image();
        let (lookup_rva, iat_field) = if delay { (0x14a0, 0x150c) } else { (0x1400, 0x1310) };
        put64(&mut data, lookup_rva, 0);
        put32(&mut data, iat_field, 0x800);
        let report = metadata(&data, LinkageLimits::default());
        let coverage = if delay { &report.delay_imports } else { &report.regular_imports };
        let provenance = if delay {
            LinkageImportProvenance::PeDelayImportDirectory
        } else {
            LinkageImportProvenance::PeImportDirectory
        };
        assert_eq!(coverage.status, LinkageCoverageStatus::Unavailable);
        assert_eq!(coverage.limitation, Some(LinkageLimitation::UnavailableBytes));
        assert_eq!(coverage.records, 0);
        assert!(report.imports.iter().all(|import| import.provenance != provenance));
    }
}

#[test]
fn regular_and_delay_iat_terminators_must_be_zero_even_for_empty_ints() {
    for delay in [false, true] {
        for empty in [false, true] {
            let mut data = image();
            let (lookup_rva, iat_rva, count) = if delay { (0x14a0, 0x1480, 1) } else { (0x1400, 0x1440, 2) };
            let terminal_index = if empty {
                put64(&mut data, lookup_rva, 0);
                0
            } else {
                count
            };
            put64(&mut data, iat_rva + terminal_index * 8, 0x7fff_1234_5678_9000);
            let report = metadata(&data, LinkageLimits::default());
            let coverage = if delay { &report.delay_imports } else { &report.regular_imports };
            let provenance = if delay {
                LinkageImportProvenance::PeDelayImportDirectory
            } else {
                LinkageImportProvenance::PeImportDirectory
            };
            assert_eq!(coverage.status, LinkageCoverageStatus::Unavailable);
            assert_eq!(coverage.limitation, Some(LinkageLimitation::MalformedTable));
            assert_eq!(coverage.records, 0);
            assert!(report.imports.iter().all(|import| import.provenance != provenance));
        }
    }
}

#[test]
fn nonterminal_bound_and_delay_iat_values_are_not_int_comparison_keys_or_runtime_evidence() {
    let mut data = image();
    put32(&mut data, 0x1304, 1);
    put64(&mut data, 0x1440, 0x7fff_1234_5678_9000);
    put64(&mut data, 0x1448, 0x7fff_ffff_ffff_ffff);
    put64(&mut data, 0x1480, 0x1_4000_2000);
    let report = metadata(&data, LinkageLimits::default());
    assert_eq!(report.regular_imports.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.delay_imports.status, LinkageCoverageStatus::Complete);
    assert_eq!(report.imports.len(), 3);
    assert_eq!(report.imports[0].symbol, LinkageSymbol::Named(b"#7".to_vec()));
    assert_eq!(report.imports[1].symbol, LinkageSymbol::Ordinal(7));
    assert_eq!(report.imports[2].symbol, LinkageSymbol::Named(b"#7".to_vec()));
    assert_eq!(report.imports[0].slot_address, 0x1_4000_1440);
    assert_eq!(report.imports[2].slot_address, 0x1_4000_1480);
}
