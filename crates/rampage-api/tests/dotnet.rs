use std::path::PathBuf;

use rampage_api::{ApiError, DetectionConfidence, DotNetList, DotNetQuery, ReportLimits, Session};

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
    assert_eq!(all.types.unwrap().total, all.counts.types);

    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let filtered = project.dotnet_metadata(&query).unwrap().unwrap();
    let names: Vec<String> = filtered.types.unwrap().items.iter().map(|ty| ty.full_name()).collect();
    assert_eq!(names, ["System.HashCode"], "a method-name match selects its type");

    let page = project.dotnet_metadata(&DotNetQuery { limit: Some(1), ..DotNetQuery::default() }).unwrap().unwrap();
    let types = page.types.unwrap();
    assert_eq!((types.items.len(), types.total), (1, all.counts.types));
    assert!(page.pinvokes.is_none() && page.custom_attributes.is_none(), "only the selected list is paged");
    assert_eq!((page.counts.custom_attributes, page.counts.pinvokes), (76, 0));

    // Each list pages on its own: the second attribute is not the second type's neighbour.
    let query = DotNetQuery { list: DotNetList::Attributes, offset: Some(1), limit: Some(1), ..DotNetQuery::default() };
    let page = project.dotnet_metadata(&query).unwrap().unwrap();
    assert!(page.types.is_none());
    let attributes = page.custom_attributes.unwrap();
    assert_eq!((attributes.offset, attributes.items.len(), attributes.total), (1, 1, 76));
}

#[test]
fn dotnet_metadata_reports_signatures_and_filters_attributes() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let query = DotNetQuery { contains: Some("combine".to_owned()), ..DotNetQuery::default() };
    let summary = project.dotnet_metadata(&query).unwrap().unwrap();
    let hash_code = &summary.types.unwrap().items[0];
    let combine = hash_code.methods.iter().find(|method| method.name == "Combine").unwrap();
    assert_eq!(combine.signature, "int32 Combine<T1>(T1)");
    let equals = hash_code.methods.iter().find(|method| method.name == "Equals").unwrap().token;
    let query = DotNetQuery { list: DotNetList::Pinvokes, ..DotNetQuery::default() };
    assert_eq!(project.dotnet_metadata(&query).unwrap().unwrap().pinvokes.unwrap().total, 0);

    let attributes = |contains: &str| {
        let query =
            DotNetQuery { list: DotNetList::Attributes, contains: Some(contains.to_owned()), ..DotNetQuery::default() };
        project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap()
    };
    let obsolete = attributes("obsolete");
    let parents: Vec<Option<&str>> = obsolete.items.iter().map(|attribute| attribute.parent.as_deref()).collect();
    assert_eq!(parents, [Some("System.HashCode::GetHashCode"), Some("System.HashCode::Equals")]);
    assert_eq!(attributes("HashCode::Equals").total, 3, "attributes match by their target too");

    let query = DotNetQuery { list: DotNetList::Attributes, parent_token: Some(equals), ..DotNetQuery::default() };
    let on_equals = project.dotnet_metadata(&query).unwrap().unwrap().custom_attributes.unwrap();
    assert!(on_equals.total > 0);
    assert!(on_equals.items.iter().all(|attribute| attribute.parent_token == equals));
    let query = DotNetQuery { parent_token: Some(equals), ..DotNetQuery::default() };
    assert!(matches!(project.dotnet_metadata(&query), Err(ApiError::Invalid(_))), "parent_token needs attributes");
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
