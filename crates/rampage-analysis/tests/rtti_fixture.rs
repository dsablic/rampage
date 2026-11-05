//! Checks RTTI class recovery against a committed, stripped Mach-O arm64 fixture built from
//! `tests/fixtures/src/classes.cpp`. The binary carries no vtable or typeinfo symbols, so recovery relies
//! entirely on the Itanium RTTI structures in its data.

use std::path::PathBuf;

use rampage_analysis::{classes, rtti};
use rampage_loaders::Binary;

fn fixture() -> Binary {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/classes-arm64.macho");
    Binary::open(path).unwrap()
}

#[test]
fn recovers_class_names_and_base_edges_from_stripped_rtti() {
    let binary = fixture();
    // The fixture is stripped: no named vtable symbols feed the symbol-driven path.
    let recovery = classes::recover(&binary);
    let direct = rtti::recover(&binary).expect("native RTTI fixture must be admitted");
    assert_eq!(direct, recovery.rtti_classes);
    assert!(recovery.classes.is_empty(), "expected no symbol-derived classes, got {:?}", recovery.classes);

    let find = |name: &str| {
        recovery.rtti_classes.iter().find(|class| class.name == name).unwrap_or_else(|| {
            panic!("missing {name}; got {:?}", recovery.rtti_classes.iter().map(|c| &c.name).collect::<Vec<_>>())
        })
    };
    assert_eq!(recovery.rtti_classes.len(), 4, "{:?}", recovery.rtti_classes);
    assert!(find("Shape").bases.is_empty());
    assert!(find("Printable").bases.is_empty());
    assert_eq!(find("Circle").bases, ["Shape"]);
    let mut square_bases = find("Square").bases.clone();
    square_bases.sort();
    assert_eq!(square_bases, ["Printable", "Shape"]);
    assert!(recovery.rtti_classes.iter().all(|class| class.abi == "itanium"));
}

/// Benchmark v2: class_evidence found no classes in a stripped arm64 Mach-O built with the linker's default
/// chained fixups, where typeinfo records hold chain-encoded rebases and binds instead of addresses.
#[test]
fn recovers_the_same_classes_through_chained_fixups() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/classes-chained-arm64.macho");
    let binary = Binary::open(path).unwrap();
    assert!(binary.has_chained_fixups());
    let chained = rtti::recover(&binary).unwrap();
    let names = |classes: &[rtti::RttiClass]| {
        let mut names: Vec<(String, Vec<String>)> = classes
            .iter()
            .map(|class| {
                let mut bases = class.bases.clone();
                bases.sort();
                (class.name.clone(), bases)
            })
            .collect();
        names.sort();
        names
    };
    assert_eq!(names(&chained), names(&rtti::recover(&fixture()).unwrap()));
    assert_eq!(chained.len(), 4, "{chained:?}");
}

#[test]
fn an_admitted_native_fixture_without_rtti_is_a_successful_empty_scan() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let binary = Binary::open(path).unwrap();
    assert_eq!(binary.format, rampage_loaders::Format::Elf);
    assert!(rtti::recover(&binary).expect("native ELF must be admitted").is_empty());
}

#[test]
fn snapshot_refusal_is_typed_and_survives_in_the_class_report() {
    let binary =
        Binary::from_snapshot_bytes(include_bytes!("../../../tests/data/runtime-arm64.snapshot.json").to_vec())
            .unwrap();
    assert_eq!(binary.format, rampage_loaders::Format::Snapshot);
    assert_eq!(rtti::recover(&binary), Err(rtti::RttiLimitation::UnsupportedFormat(rampage_loaders::Format::Snapshot)),);
    let recovery = classes::recover(&binary);
    assert!(recovery.rtti_classes.is_empty());
    assert!(recovery.warnings.iter().any(|warning| {
        warning.starts_with("Symbol-independent RTTI not inspected:") && warning.contains("Snapshot")
    }));
}
