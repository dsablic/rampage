use std::path::PathBuf;

use rampage_loaders::{Binary, Format};

#[test]
fn sparse_snapshot_keeps_virtual_addresses_separate_from_file_offsets() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let binary = Binary::open(path).unwrap();
    assert_eq!(binary.format, Format::Snapshot);
    assert_eq!(binary.function_starts, [0x1000]);
    assert!(binary.is_code(0x1000));
    assert!(!binary.is_code(0x3000));
    assert_eq!(binary.read(0x3000, 8).unwrap(), [0x10, 0x10, 0, 0, 0, 0, 0, 0]);
    assert!(binary.read(0x1010, 16).is_none());
    assert!(binary.read(0x2000, 1).is_none());
    assert!(binary.provenance.as_deref().unwrap().contains("controlled"));
}

#[test]
fn unreadable_regions_are_not_trusted_as_pointer_sources() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let mut binary = Binary::open(path).unwrap();
    assert_eq!(binary.read_pointer(0x3000, 8), Some(0x1010));
    assert_eq!(binary.read_pointer(0x3000, 2), None);
    assert_eq!(binary.read_constant(0x3000, 2), Some(0x1010));
    assert_eq!(binary.read_constant(0x3001, 1), Some(0x10));
    binary.segments[1].perms.read = false;
    assert_eq!(binary.read_pointer(0x3000, 8), None);
    assert_eq!(binary.read_constant(0x3000, 1), None);
    binary.segments[1].perms.read = true;
    binary.segments[1].perms.write = true;
    assert_eq!(binary.read_pointer(0x3000, 8), None);
    assert_eq!(binary.read_constant(0x3000, 1), None);
}

#[test]
fn module_and_register_metadata_are_validated_and_preserved() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-stack.snapshot.json");
    let binary = Binary::open(path).unwrap();
    assert_eq!(binary.snapshot_modules[0].runtime_base, "0x1000");
    assert_eq!(binary.snapshot_registers[0].value, "0x8000");
}
