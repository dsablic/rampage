use rampage_api::{FunctionsQuery, Project};
use rampage_loaders::Binary;

#[test]
fn project_audit_reports_candidate_evidence_without_altering_discovery() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    assert!(project.analysis_diagnostics(false).unwrap().discovery.is_none());
    let before = project.functions(&FunctionsQuery::default()).unwrap();
    let diagnostics = project.analysis_diagnostics(true).unwrap();
    assert_eq!(diagnostics.discovery.unwrap().total_candidates, before.total);
    assert!(diagnostics.limitations.iter().any(|text| text.contains("not verified functions")));
    assert_eq!(project.functions(&FunctionsQuery::default()).unwrap().total, before.total);
    assert!(project.analysis_diagnostics(false).unwrap().discovery.is_some());
}

#[test]
fn sampled_decoding_reuses_branch_learned_thumb_modes() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm-mixed-modes.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let before = project.analysis_diagnostics(false).unwrap();
    let before = before.regions.iter().find(|region| region.address == 0x1014).unwrap();
    assert_eq!(before.instructions, 1);
    let after = project.analysis_diagnostics(true).unwrap();
    let after = after.regions.iter().find(|region| region.address == 0x1014).unwrap();
    assert_eq!(after.invalid, 0);
    assert_eq!(after.instructions, 2);
    assert_eq!(after.discovery.as_ref().unwrap().candidates, 1);
}
