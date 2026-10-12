use std::path::PathBuf;

use rampage_api::{Confidence, DotNetQuery, ReportLimits, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

const ASSEMBLY: &str = "Microsoft.Bcl.HashCode.dll";

#[test]
fn dotnet_metadata_reports_identity_and_filters_types() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let all = project.dotnet_metadata(&DotNetQuery::default()).unwrap().expect("managed assembly");
    assert_eq!(all.assembly.as_ref().unwrap().name, "Microsoft.Bcl.HashCode");
    assert_eq!(all.counts.methods, 48);
    assert_eq!(all.counts.il_methods, 48);
    assert_eq!(all.types.total, all.counts.types);

    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let filtered = project.dotnet_metadata(&query).unwrap().unwrap();
    let names: Vec<String> = filtered.types.items.iter().map(|ty| ty.full_name()).collect();
    assert_eq!(names, ["System.HashCode"], "a method-name match selects its type");

    let page = project.dotnet_metadata(&DotNetQuery { limit: Some(1), ..DotNetQuery::default() }).unwrap().unwrap();
    assert_eq!((page.types.items.len(), page.types.total), (1, all.counts.types));
}

#[test]
fn native_images_have_no_dotnet_metadata() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(project.dotnet_metadata(&DotNetQuery::default()).unwrap().is_none());
}

#[test]
fn managed_dll_is_detected_strongly_and_triaged_as_managed() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let detections = project.detect_tools(None).unwrap();
    assert!(detections.iter().any(|d| d.name == ".NET" && d.confidence == Confidence::Strong), "{detections:?}");
    let report = project.triage_report(ReportLimits::default()).unwrap();
    assert!(report.next_steps.iter().any(|step| step.tool == "dotnet_metadata"), "{report:#?}");
    assert!(report.next_steps.iter().all(|step| step.tool != "find_main"), "{report:#?}");
    assert!(report.limitations.iter().any(|text| text.contains("CIL bytecode")), "{report:#?}");
}
