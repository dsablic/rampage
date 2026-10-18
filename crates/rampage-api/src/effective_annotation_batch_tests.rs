use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use rampage_loaders::Binary;
use rampage_signatures::fuzzy::CalleeProvenance;

use super::name_snapshot;
use crate::{ApiError, DebugTypesRequest, DeclareTypesRequest, Project, PropagationRequest};

fn project() -> Arc<Project> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    Arc::new(Project::new(Binary::open(path).unwrap()))
}

fn patched(project: &Arc<Project>) -> Arc<Project> {
    project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project
}

fn declare_record(project: &Project, field: &str, replace: bool) {
    let edit = project
        .declare_types(&DeclareTypesRequest {
            declarations: Some(format!("struct BatchRecord {{ int4 {field}; }};")),
            replace,
            ..Default::default()
        })
        .unwrap();
    assert!(edit.changed);
}

fn assert_record(project: &Project, field: &str) {
    let inspected = project.get_type("BatchRecord").unwrap();
    assert_eq!(inspected.metadata.size, Some(4));
    assert_eq!(inspected.metadata.fields.len(), 1);
    assert_eq!(inspected.metadata.fields[0].name, field);
    let page = project.list_types(Some("BatchRecord"), 0, 10).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.types.len(), 1);
    assert_eq!(page.types[0].metadata, inspected.metadata);
    assert_eq!(page.types[0].declaration, inspected.declaration);
}

#[test]
fn effective_type_queries_and_propagation_preview_keep_one_held_annotation_view() {
    let original = project();
    let main = original.resolve("main").unwrap();
    declare_record(&original, "first_live_field", false);
    assert_record(&original, "first_live_field");
    declare_record(&original, "frozen_field", true);
    assert_record(&original, "frozen_field");

    let held = patched(&original);
    assert_record(&held, "frozen_field");
    let request = PropagationRequest { address: main, apply: false, max_functions: 1, max_candidates: 16 };
    let before = held.propagate_types(&request).unwrap();
    assert!(!before.apply && !before.persisted);
    declare_record(&held, "new_authoritative_field", true);

    assert_record(&held, "frozen_field");
    assert_record(&original, "frozen_field");
    let after = held
        .propagate_types_with_preflight(&request, |_| {
            assert!(held.annotations.try_write().is_ok());
            Ok(())
        })
        .unwrap();
    assert_eq!(serde_json::to_value(&after).unwrap(), serde_json::to_value(&before).unwrap());

    let current = held.effective_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&held, &current));
    assert_eq!(held.binary.image_bytes(), current.binary.image_bytes());
    assert_eq!(current.binary.read(0x100191e, 5), Some([0xb8, 7, 0, 0, 0].as_slice()));
    assert_record(&current, "new_authoritative_field");
    let refreshed = current.propagate_types(&request).unwrap();
    assert!(!refreshed.apply && !refreshed.persisted);
    assert_ne!(refreshed.source_fingerprint, before.source_fingerprint);
    assert_record(&held, "frozen_field");

    for view in [&held, &current] {
        let error = view.import_debug_types(&DebugTypesRequest::default()).unwrap_err();
        assert!(error.to_string().contains("owned input has no mapped-file identity"), "{error}");
    }
}

fn assert_name_evidence(project: &Project, address: u64, expected: &str) {
    let (names, callees) = name_snapshot(project, &BTreeMap::new()).unwrap();
    assert_eq!(names.get(&address).map(String::as_str), Some(expected));
    let callee = callees.get(&address).unwrap();
    assert_eq!(callee.name, expected);
    assert_eq!(callee.provenance, CalleeProvenance::Analyst);
}

#[test]
fn effective_fuzzy_name_and_callee_evidence_freezes_without_freezing_authoritative_edits() {
    let original = project();
    let callee = original.resolve("puts").unwrap();
    original.rename(callee, Some("batch_first_live_callee")).unwrap();
    assert_name_evidence(&original, callee, "batch_first_live_callee");
    original.rename(callee, Some("batch_frozen_callee")).unwrap();
    assert_name_evidence(&original, callee, "batch_frozen_callee");
    {
        let _writer = original.annotations.write().unwrap();
        assert!(matches!(name_snapshot(&original, &BTreeMap::new()), Err(ApiError::Unavailable(_))));
    }

    let held = patched(&original);
    original.rename(callee, Some("batch_new_callee")).unwrap();
    let current = held.effective_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&held, &current));
    assert_eq!(held.binary.image_bytes(), current.binary.image_bytes());
    assert_eq!(current.binary.read(0x100191e, 5), Some([0xb8, 7, 0, 0, 0].as_slice()));
    {
        let writer = original.annotations.write().unwrap();
        assert_eq!(writer.name(callee), Some("batch_new_callee"));
        assert_name_evidence(&held, callee, "batch_frozen_callee");
        assert_name_evidence(&original, callee, "batch_frozen_callee");
        assert_name_evidence(&current, callee, "batch_new_callee");
    }
    {
        let _frozen_writer = held.frozen_annotations.get().unwrap().write().unwrap();
        assert!(matches!(name_snapshot(&held, &BTreeMap::new()), Err(ApiError::Unavailable(_))));
    }
    assert_name_evidence(&held, callee, "batch_frozen_callee");
}
