use rampage_api::Project;
use rampage_loaders::{Binary, Details, snapshot::SnapshotModule};

#[test]
fn explicit_uuid_matched_slide_maps_runtime_addresses_without_opening_recorded_paths() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests");
    let original = Binary::open(root.join("fixtures/bin/hello-arm64.macho")).unwrap();
    let Details::MachO(details) = &original.details else { panic!("not Mach-O") };
    let uuid = details.uuid.clone().unwrap();
    let image_base =
        original.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let mut snapshot = Binary::open(root.join("data/runtime-arm64.snapshot.json")).unwrap();
    snapshot.snapshot_modules = vec![SnapshotModule {
        name: "fixture".to_owned(),
        path: "/never/open/this/path".to_owned(),
        uuid: uuid.clone(),
        image_base: format!("{image_base:#x}"),
        runtime_base: "0x1000".to_owned(),
    }];
    let project = Project::new(snapshot);
    let result = project.correlate_runtime(&uuid, &original, 0x1010).unwrap();
    assert_eq!(result.image_address, image_base + 16);
    assert!(project.correlate_runtime(&uuid, &original, 0x2000).is_err());
    assert!(project.correlate_runtime("00000000000000000000000000000000", &original, 0x1010).is_err());
    let mut snapshot = Binary::open(root.join("data/runtime-arm64.snapshot.json")).unwrap();
    let module = SnapshotModule {
        name: "fixture".to_owned(),
        path: "unused".to_owned(),
        uuid: uuid.clone(),
        image_base: format!("{image_base:#x}"),
        runtime_base: "0x1000".to_owned(),
    };
    let mut duplicate = module.clone();
    duplicate.uuid = uuid.to_ascii_uppercase();
    duplicate.runtime_base = "0x2000".to_owned();
    snapshot.snapshot_modules = vec![module, duplicate];
    assert!(Project::new(snapshot).correlate_runtime(&uuid, &original, 0x1010).is_err());
}
