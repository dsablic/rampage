use rampage_api::Project;
use rampage_loaders::{Binary, Format};

fn binary() -> Binary {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-x64-string-boundary.snapshot.json");
    Binary::open(path).unwrap()
}

fn code(binary: Binary) -> String {
    let project = Project::new(binary);
    project.rename(0x2000, Some("puts")).unwrap();
    project.decompile(0x1000).unwrap().code
}

#[test]
fn uncaptured_snapshot_tails_are_not_zero_fill() {
    let mut binary = binary();
    binary.segments[2].size = 4;
    let code = code(binary);
    assert!(code.contains("puts("), "{code}");
    assert!(!code.contains("\"abc\""), "{code}");
}

#[test]
fn declared_static_zero_fill_can_terminate_a_string() {
    let mut binary = binary();
    binary.format = Format::Elf;
    binary.segments[2].size = 4;
    let code = code(binary);
    assert!(code.contains("\"abc\""), "{code}");
}

#[test]
fn truncated_backing_stays_unavailable_before_a_declared_zero_fill_tail() {
    let mut binary = binary();
    binary.format = Format::Elf;
    binary.segments[2].file_size = 6;
    binary.segments[2].size = 8;
    assert_eq!(binary.read_to_segment_end(0x3000).unwrap(), b"abc");
    let code = code(binary);
    assert!(!code.contains("\"abc\""), "{code}");
}

#[test]
fn unreadable_mappings_cannot_supply_otherwise_valid_string_contents() {
    let mut readable = binary();
    readable.format = Format::Elf;
    readable.segments[2].size = 4;
    assert!(code(readable).contains("\"abc\""));
    let mut binary = binary();
    binary.format = Format::Elf;
    binary.segments[2].size = 4;
    binary.segments[2].perms.read = false;
    assert!(!code(binary).contains("\"abc\""));
}

#[test]
fn instruction_permissions_are_distinct_from_data_read_permissions() {
    let mut binary = binary();
    binary.segments[0].perms.read = false;
    assert!(code(binary).contains("return 0;"));
    let mut binary = self::binary();
    binary.segments[0].perms.execute = false;
    assert!(Project::new(binary).decompile(0x1000).is_err());
    let project = Project::new(self::binary());
    assert!(project.decompile(0x3000).is_err());
    assert!(project.decompile(0xffff).is_err());
}
