use rampage_api::{Project, ReferenceAnalysis};
use rampage_loaders::Binary;

#[test]
fn function_comparisons_require_matching_identity_and_report_missing_and_extra_addresses() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
    let project = Project::new(Binary::open(path).unwrap());
    let mut reference = ReferenceAnalysis {
        tool: "controlled-fixture".to_owned(),
        version: "1".to_owned(),
        image_sha256: project.triage().image_hashes.sha256.clone(),
        arch: "aarch64".to_owned(),
        functions: vec!["0x100000468".to_owned()],
    };
    let comparison = project.compare_functions(&reference).unwrap();
    assert_eq!(comparison.matched, 1);
    assert!(comparison.missing.is_empty());
    reference.functions.clear();
    assert!(!project.compare_functions(&reference).unwrap().extra.is_empty());
    reference.image_sha256 = "wrong".to_owned();
    assert!(project.compare_functions(&reference).is_err());
    reference.image_sha256 = project.triage().image_hashes.sha256.clone();
    reference.functions = vec!["0xffff".to_owned()];
    assert!(project.compare_functions(&reference).is_err());
}

#[test]
fn comparison_metadata_rejects_terminal_controls_and_snapshot_mapping_ambiguity() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let reference = ReferenceAnalysis {
        tool: "fixture".to_owned(),
        version: "1".to_owned(),
        image_sha256: project.triage().image_hashes.sha256.clone(),
        arch: "aarch64".to_owned(),
        functions: vec![],
    };
    assert!(project.compare_functions(&reference).is_err());
    let invalid = serde_json::json!({ "tool": "fixture", "version": "1", "arch": "aarch64",
        "image_sha256": "hash", "functions": ["0x1234567890123456789"] });
    assert!(serde_json::from_value::<ReferenceAnalysis>(invalid).is_err());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
    let project = Project::new(Binary::open(path).unwrap());
    let reference = ReferenceAnalysis {
        tool: "fixture\n\u{1b}[2J".to_owned(),
        version: "1".to_owned(),
        image_sha256: project.triage().image_hashes.sha256.clone(),
        arch: "aarch64".to_owned(),
        functions: vec![],
    };
    assert!(project.compare_functions(&reference).is_err());
}
