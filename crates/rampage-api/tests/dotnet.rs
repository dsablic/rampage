use std::path::PathBuf;

use rampage_api::{DetectionConfidence, DotNetQuery, ReportLimits, Session};

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
    assert_eq!((page.custom_attributes.items.len(), page.custom_attributes.total), (1, 76));
}

#[test]
fn dotnet_metadata_reports_signatures_and_filters_attributes() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let combine = summary.types.items[0].methods.iter().find(|method| method.name == "Combine").unwrap();
    assert_eq!(combine.signature, "int32 Combine<T1>(T1)");
    assert_eq!((summary.counts.pinvokes, summary.pinvokes.total), (0, 0));

    let query = DotNetQuery { contains: Some("obsolete".to_owned()), ..DotNetQuery::default() };
    let obsolete = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes;
    let parents: Vec<Option<&str>> = obsolete.items.iter().map(|attribute| attribute.parent.as_deref()).collect();
    assert_eq!(parents, [Some("System.HashCode::GetHashCode"), Some("System.HashCode::Equals")]);
    let query = DotNetQuery { contains: Some("HashCode::Equals".to_owned()), ..DotNetQuery::default() };
    let on_equals = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes;
    assert_eq!(on_equals.total, 3, "attributes match by their target too");
}

#[test]
fn native_images_have_no_dotnet_metadata() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(project.dotnet_metadata(&DotNetQuery::default()).unwrap().is_none());
}

#[test]
fn managed_dll_is_detected_strongly_and_triaged_as_managed() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let detections = project.detect_tools(None).unwrap().detections;
    assert!(
        detections.iter().any(|d| d.name == ".NET" && d.confidence == DetectionConfidence::Strong),
        "{detections:?}"
    );
    let report = project.triage_report(ReportLimits::default()).unwrap();
    assert!(report.next_steps.iter().any(|step| step.tool == "dotnet_metadata"), "{report:#?}");
    assert!(report.next_steps.iter().all(|step| step.tool != "find_main"), "{report:#?}");
    assert!(report.limitations.iter().any(|text| text.contains("CIL bytecode")), "{report:#?}");
}
