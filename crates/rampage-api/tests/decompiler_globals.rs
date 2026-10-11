use rampage_api::Project;
use rampage_loaders::Binary;

#[test]
fn typed_global_annotations_validate_complete_mapping_and_undo_cleanly() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-x64-string-boundary.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    project.set_global(0x3000, Some("char captured[3];")).unwrap();
    assert_eq!(project.annotation_list().globals.len(), 1);
    project.set_global(0x3000, None).unwrap();
    assert!(project.set_global(0x3002, Some("int4 incomplete;")).is_err());
    project.set_global(0x3000, Some("char captured[3];")).unwrap();
    assert!(project.set_global(0x1000, Some("int4 code;")).is_err());
    project.undo().unwrap();
    assert!(project.annotation_list().globals.is_empty());
    project.redo().unwrap();
    assert_eq!(project.annotation_list().globals.len(), 1);
}

#[test]
fn name_edits_cannot_invalidate_registered_global_objects() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-x64-string-boundary.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    project.set_global(0x3000, Some("char counter[3];")).unwrap();
    assert!(project.rename(0x1000, Some("counter")).is_err());
    assert_eq!(project.name_at(0x1000).as_deref(), Some("entry"));
    project.decompile(0x1000).unwrap();
    project.rename(0x1000, Some("safe_name")).unwrap();
    project.undo().unwrap();
    project.redo().unwrap();
    assert!(project.decompile(0x1000).unwrap().code.contains("safe_name("));
}
