use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_analysis::classes::{HeaderClassification, ScanStop, recover, recover_named_bounded};
use rampage_loaders::{Binary, Format, SectionKind, Symbol, SymbolKind};

struct FixtureFile(PathBuf);

impl Drop for FixtureFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).expect("remove bounded named-class fixture");
    }
}

fn fixture() -> Binary {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rampage-named-class-bounds-{}-{}.snapshot.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let guard = FixtureFile(path);
    let slots = "0010000000000000".repeat(80);
    write!(
        file,
        r#"{{"format":"rampage-snapshot-v1","arch":"x86_64","data_big_endian":false,
        "provenance":"bounded raw named evidence only","regions":[
        {{"name":"text","address":"0x1000","permissions":"r-x","bytes":"c3"}},
        {{"name":"vtable","address":"0x3000","permissions":"r--",
          "bytes":"00000000000000000000000000000000{slots}"}}
        ]}}"#
    )
    .unwrap();
    drop(file);
    let mut binary = Binary::open(&guard.0).unwrap();
    binary.format = Format::Elf;
    binary.sections.iter_mut().find(|section| section.address == 0x3000).unwrap().kind = SectionKind::ReadOnlyData;
    binary.symbols =
        vec![Symbol { name: "_ZTV3Foo".to_owned(), address: 0x3000, size: 82 * 8, kind: SymbolKind::Data }];
    binary
}

#[test]
fn bounded_named_recovery_limits_before_slot_reads_and_preserves_unknown_headers() {
    let mut binary = fixture();
    binary.symbols = vec![binary.symbols[0].clone(); 40];
    let result = recover_named_bounded(&binary, 2, 3);
    assert_eq!(result.classes.len(), 2);
    assert!(result.rtti_classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("2 named-vtable candidate limit")));
    for raw in result.classes {
        assert_eq!(raw.slots.len(), 3);
        assert_eq!(raw.scan_limit, 0x3028);
        assert_eq!(raw.scan_end, 0x3028);
        assert_eq!(raw.stop, ScanStop::SlotLimit);
        assert_eq!(raw.header, HeaderClassification::UnverifiedPrefix);
        assert_eq!(raw.offset_to_top, None);
    }
}

#[test]
fn zero_and_excessive_requested_limits_do_not_expand_the_full_recovery_caps() {
    let binary = fixture();
    assert!(recover_named_bounded(&binary, 0, 64).classes.is_empty());
    assert!(recover_named_bounded(&binary, 32, 0).classes.is_empty());
    let result = recover_named_bounded(&binary, usize::MAX, u64::MAX);
    assert_eq!(result.classes[0].slots.len(), 64);
    assert_eq!(result.classes[0].stop, ScanStop::SlotLimit);
    assert!(result.rtti_classes.is_empty());
}

#[test]
fn cumulative_raw_name_budget_is_checked_before_copying_another_table() {
    let mut binary = fixture();
    let name = "x".repeat(3000);
    binary.symbols[0].name = format!("_ZTV3000{name}");
    binary.symbols = vec![binary.symbols[0].clone(); 32];
    let result = recover_named_bounded(&binary, 32, 1);
    assert!(!result.classes.is_empty());
    assert!(result.classes.len() < 32);
    let bytes: usize = result.classes.iter().map(|raw| raw.name.len() + raw.vtable_symbol.len()).sum();
    assert!(bytes <= 64 * 1024);
    assert!(result.warnings.iter().any(|warning| warning.contains("text budget exhausted")));
}

#[test]
fn bounded_named_recovery_retains_the_pre_read_metadata_budget() {
    let mut binary = fixture();
    binary.segments.extend(std::iter::repeat_n(binary.segments[0].clone(), 16_384));
    let result = recover_named_bounded(&binary, 32, 64);
    assert!(result.classes.is_empty());
    assert!(result.rtti_classes.is_empty());
    assert!(result.warnings.iter().any(|warning| warning.contains("metadata budget")));
}

#[test]
fn bounded_named_recovery_reserves_lookup_work_before_reading_another_table() {
    let mut binary = fixture();
    binary.symbols = vec![binary.symbols[0].clone(); 32];
    let mut unrelated = binary.segments[0].clone();
    unrelated.address = 0x5000;
    binary.segments.splice(0..0, std::iter::repeat_n(unrelated, 1000));
    let result = recover_named_bounded(&binary, 32, 64);
    assert!(!result.classes.is_empty());
    assert!(result.classes.len() < 32);
    assert!(result.warnings.iter().any(|warning| warning.contains("lookup work budget")));
}

#[test]
fn failed_named_candidates_consume_the_attempt_cap_before_a_later_valid_table() {
    let mut binary = fixture();
    let valid = binary.symbols[0].clone();
    let mut invalid = valid.clone();
    invalid.address = 0x9000;
    binary.symbols = vec![invalid.clone(), invalid, valid];
    let bounded = recover_named_bounded(&binary, 2, 2);
    assert!(bounded.classes.is_empty(), "failed reads must not exempt candidates from the attempt budget");
    assert!(bounded.warnings.iter().any(|warning| warning.contains("2 named-vtable candidate limit")));
    let larger = recover_named_bounded(&binary, 3, 2);
    assert_eq!(larger.classes.len(), 1, "the later table is readable when its attempt is explicitly budgeted");
    assert_eq!(larger.classes[0].address, 0x3000);
}

#[test]
fn full_recovery_raw_named_table_facts_are_unchanged_by_the_bounded_path() {
    let binary = fixture();
    let full = recover(&binary);
    let bounded = recover_named_bounded(&binary, 32, 64);
    assert!(!full.classes.is_empty());
    assert_eq!(format!("{:?}", full.classes), format!("{:?}", bounded.classes));
    assert!(bounded.rtti_classes.is_empty());
}
