use rampage_api::Project;
use rampage_loaders::Binary;

#[test]
fn explicit_tables_validate_every_target_without_modifying_discovery() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-jumptable.snapshot.json");
    let project = Project::new(Binary::open(&path).unwrap());
    for (at, base) in [(0x3000, None), (0x4000, Some(0x3000))] {
        let table = project.inspect_jump_table(at, 2, base).unwrap();
        assert_eq!(table.entries.iter().map(|entry| entry.target).collect::<Vec<_>>(), [0x1000, 0x1004]);
    }
    assert_eq!(project.functions(&Default::default()).unwrap().total, 1);
    for (at, count, base) in
        [(0x3001, 2, None), (0x3000, 3, None), (0x3000, 0, None), (0x4000, 2, Some(0)), (0x3000, 4097, None)]
    {
        assert!(project.inspect_jump_table(at, count, base).is_err());
    }
    let mut binary = Binary::open(path).unwrap();
    binary.segments[1].perms.write = true;
    assert!(Project::new(binary).inspect_jump_table(0x3000, 2, None).is_err());
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-jumptable.snapshot.json");
    let mut binary = Binary::open(path).unwrap();
    binary.segments[0].perms.write = true;
    assert!(Project::new(binary).inspect_jump_table(0x3000, 2, None).is_err());
}
