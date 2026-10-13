use std::path::PathBuf;

use rampage_api::{ApiError, DetectionConfidence, DotNetIlQuery, DotNetList, DotNetQuery, ReportLimits, Session};

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
fn dotnet_il_pages_one_method_by_token_or_name() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let query = |method: &str, offset, limit| DotNetIlQuery { method: method.to_owned(), offset, limit, at: None };
    let by_token = project.dotnet_il(&query("0x0600000d", Some(5), Some(3))).unwrap().expect("managed assembly");
    assert_eq!(by_token.method, "System.HashCode::Combine");
    let page = &by_token.instructions;
    assert_eq!((page.offset, page.items.len()), (5, 3));
    assert!(page.total > 50);
    assert_eq!(page.items[0].text(), "IL_000b: ldarga.s 0");
    assert_eq!(by_token.locals.len(), 10);
    assert_eq!((by_token.locals_total, by_token.locals_truncated), (10, false));
    let decimal = project.dotnet_il(&query(&0x0600_000D_u32.to_string(), None, Some(1))).unwrap().unwrap();
    assert_eq!(decimal.token, by_token.token);

    let by_name = project.dotnet_il(&query("System.SR::GetResourceString", None, None)).unwrap().unwrap();
    assert_eq!(by_name.exception_clauses.len(), 1);
    assert_eq!(by_name.instructions.items.len(), by_name.instructions.total);

    let ambiguous = project.dotnet_il(&query("System.HashCode::Combine", None, None)).unwrap_err();
    assert!(matches!(&ambiguous, ApiError::Invalid(text) if text.contains("0x0600000d")), "{ambiguous}");
    let missing = project.dotnet_il(&query("System.HashCode::Missing", None, None)).unwrap_err();
    assert!(matches!(missing, ApiError::NotFound(_)), "{missing}");
    assert!(matches!(project.dotnet_il(&query(" ", None, None)), Err(ApiError::Invalid(_))));
    let native = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    assert!(native.dotnet_il(&query("0x06000001", None, None)).unwrap().is_none());
}

#[test]
fn dotnet_il_pages_from_an_il_offset() {
    let project = Session::default().open(&fixture(ASSEMBLY), None).unwrap();
    let at = |at: &str, offset| DotNetIlQuery {
        method: "0x0600000d".to_owned(),
        offset,
        limit: Some(2),
        at: Some(rampage_api::parse_il_offset(at).unwrap()),
    };
    // IL_000b is the sixth instruction; IL_000c is the second byte of the same `ldarga.s`.
    for label in ["IL_000b", "0xc", "11"] {
        let page = project.dotnet_il(&at(label, None)).unwrap().unwrap().instructions;
        assert_eq!((page.offset, page.items[0].text()), (5, "IL_000b: ldarga.s 0".to_owned()), "{label}");
    }
    assert_eq!(project.dotnet_il(&at("IL_0000", None)).unwrap().unwrap().instructions.offset, 0);
    let last = project.dotnet_il(&at("IL_00e0", None)).unwrap().unwrap().instructions;
    assert_eq!((last.offset, last.items.len()), (last.total - 1, 1));
    let past = project.dotnet_il(&at("IL_00e1", None)).unwrap_err();
    assert!(matches!(&past, ApiError::Invalid(text) if text.contains("past the end")), "{past}");
    assert!(matches!(project.dotnet_il(&at("IL_0000", Some(1))), Err(ApiError::Invalid(_))));
    assert!(rampage_api::parse_il_offset("IL_zz").is_err());
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
