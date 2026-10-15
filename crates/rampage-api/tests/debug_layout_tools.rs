#[path = "support/debug_layout_tools.rs"]
#[allow(dead_code)]
mod support;

use rampage_api::Project;
use rampage_api::tools::{self, Group};
use serde_json::{Value, json};
use support::{TempFiles, log_bytes, open, wrong_digest};

fn call(project: &Project, arguments: Value, success: bool) -> Value {
    let (text, failed) = tools::call(&tools::tools(), project, "import_debug_layouts", arguments);
    assert_eq!(!failed, success, "{text}");
    assert!(text.len() <= 60_000, "{} bytes", text.len());
    serde_json::from_str(&text).unwrap()
}

#[test]
fn checked_layout_schema_is_types_gated_strict_and_keeps_legacy_signature_import() {
    let registry = tools::tools();
    let tool = registry.iter().find(|tool| tool.name == "import_debug_layouts").unwrap();
    assert_eq!(tool.group, Group::Types);
    assert!(tool.reads_annotations);
    assert_eq!(tool.effect, tools::Effect::Annotations);
    assert_eq!(tool.input_schema["additionalProperties"], false);
    for name in ["apply", "review_sha256", "offset", "limit"] {
        assert!(tool.input_schema["properties"].get(name).is_some(), "{name}");
    }
    assert!(!tool.input_schema["required"].as_array().is_some_and(|required| required.contains(&json!("apply"))));
    let files = TempFiles::new();
    let path = files.negative();
    let project = open(&path);
    let (text, failed) = tools::call(&registry, &project, "import_debug_signatures", json!({ "apply": false }));
    assert!(!failed, "{text}");
    assert!(serde_json::from_str::<Value>(&text).unwrap()["preview"]["signatures"].is_array());
    assert!(log_bytes(&path).is_empty());
}

#[test]
fn invalid_shared_arguments_and_wrong_digest_never_apply_or_change_existing_annotation_bytes() {
    let files = TempFiles::new();
    let path = files.negative();
    let project = open(&path);
    project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
    let before = log_bytes(&path);
    for arguments in [
        json!({ "apply": true }),
        json!({ "review_sha256": "a".repeat(64) }),
        json!({ "apply": false, "review_sha256": "a".repeat(64) }),
        json!({ "apply": true, "review_sha256": "A".repeat(64) }),
        json!({ "apply": true, "review_sha256": "a".repeat(63) }),
        json!({ "apply": "true" }),
        json!({ "apply": true, "review_sha256": "a".repeat(64), "limit": 0 }),
        json!({ "limit": 1001 }),
        json!({ "limit": -1 }),
        json!({ "offset": -1 }),
        json!({ "confirm": true }),
        json!({ "pdb": "must-not-open" }),
        json!([]),
    ] {
        let rejected = call(&project, arguments, false);
        assert_eq!(rejected["ok"], false);
        assert_eq!(rejected["status"], "rejected");
        assert_eq!(rejected["whole_apply_succeeded"], false);
        assert_eq!(rejected["applied_total"], 0);
        assert!(rejected["error_truncated"].is_boolean());
        assert_eq!(log_bytes(&path), before);
    }
    let preview = call(&project, json!({ "limit": 1 }), true);
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["apply_requested"], false);
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["applied_total"], 0);
    assert_eq!(preview["approved_total"], 0, "negative fixture is not a positive layout proof");
    for key in ["review_sha256", "image_sha256", "compiler_spec_sha256"] {
        assert_eq!(preview[key].as_str().unwrap().len(), 64);
    }
    let final_page = call(&project, json!({ "offset": usize::MAX, "limit": 1 }), true);
    assert_eq!(final_page["review_sha256"], preview["review_sha256"]);
    assert_eq!(final_page["details"], json!([]));
    assert_eq!(final_page["more"], false);
    let rejected = call(
        &project,
        json!({ "apply": true, "review_sha256": wrong_digest(preview["review_sha256"].as_str().unwrap()) }),
        false,
    );
    assert_eq!(rejected["apply_requested"], true);
    assert_eq!(rejected["whole_apply_succeeded"], false);
    assert_eq!(log_bytes(&path), before);
    assert!(open(&path).annotation_list().types.is_empty());
    assert!(open(&path).annotation_list().signatures.is_empty());
    assert_eq!(project.undo().unwrap().len(), 1, "only the analyst comment entered undo history");
}

#[test]
fn large_unicode_and_escaped_failures_keep_a_bounded_json_rejection_receipt() {
    let error = "\0\n\"λ".repeat(60_000);
    let text = tools::debug_layout_import_error(&error, Some(true));
    assert!(text.len() <= 60_000);
    let receipt: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(receipt["ok"], false);
    assert_eq!(receipt["apply_requested"], true);
    assert_eq!(receipt["whole_apply_succeeded"], false);
    assert_eq!(receipt["applied_total"], 0);
    assert_eq!(receipt["error_truncated"], true);
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn compiled_shared_tool_apply_ignores_detail_subset_reopens_and_undoes_the_whole_atomic_dependency_batch() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let files = TempFiles::new();
        let path = files.generated(variant, "flat");
        let project = open(&path);
        project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
        let before = log_bytes(&path);
        let preview = call(&project, json!({ "limit": 1 }), true);
        let expected = support::expected_functions(&project);
        assert_eq!(preview["approved_total"], expected.len());
        assert_eq!(preview["types_total"], 1);
        assert_eq!(preview["fields_total"], support::oracle()["flat"]["fields"].as_array().unwrap().len());
        assert_eq!(preview["details"].as_array().unwrap().len(), 1);
        assert_eq!(preview["more"], true);
        assert_eq!(preview["details"][0]["kind"], "type");
        assert_eq!(log_bytes(&path), before);
        let evidence = call(&project, json!({ "limit": 1000 }), true);
        assert_eq!(evidence["review_sha256"], preview["review_sha256"]);
        let rows = evidence["details"].as_array().unwrap();
        assert!(rows.iter().any(|row| row["kind"] == "field" && row["source"] == "checked"));
        assert!(rows.iter().any(|row| row["kind"] == "function" && row["status"] == "approved"));
        assert!(rows.iter().any(|row| row["source"] == "producer"));
        let applied = call(
            &project,
            json!({ "apply": true, "review_sha256": preview["review_sha256"], "offset": usize::MAX, "limit": 1 }),
            true,
        );
        assert_eq!(applied["whole_apply_succeeded"], true);
        assert_eq!(applied["review_sha256"], preview["review_sha256"]);
        assert_eq!(applied["applied_total"], expected.len());
        assert_eq!(applied["imported_types_total"], 1);
        assert_eq!(applied["details"], json!([]));
        support::assert_atomic_append(&path, &before, expected.len() + 1, preview["image_sha256"].as_str().unwrap());
        support::assert_source_signatures(&open(&path));
        let persisted = log_bytes(&path);
        let stale = call(&project, json!({ "apply": true, "review_sha256": preview["review_sha256"] }), false);
        assert_eq!(stale["applied_total"], 0);
        assert_eq!(log_bytes(&path), persisted);
        assert_eq!(project.undo().unwrap().len(), expected.len() + 1);
        let reopened = open(&path);
        assert!(reopened.annotation_list().types.is_empty());
        assert!(reopened.annotation_list().signatures.is_empty());
        assert_eq!(reopened.comment_at(project.binary.entry.unwrap()).as_deref(), Some("keep analyst comment"));
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn changed_annotation_eligibility_rejects_a_review_without_a_partial_type_or_signature_batch() {
    let files = TempFiles::new();
    let path = files.generated("dwarf5-o2", "flat");
    let project = open(&path);
    let preview = call(&project, json!({}), true);
    let address = project.resolve("debug_flat_read_first").unwrap();
    project.set_signature(address, Some("int4 analyst_first(void *opaque);")).unwrap();
    let before = log_bytes(&path);
    let failed = call(&project, json!({ "apply": true, "review_sha256": preview["review_sha256"] }), false);
    assert_eq!(failed["whole_apply_succeeded"], false);
    assert_eq!(failed["applied_total"], 0);
    assert_eq!(log_bytes(&path), before);
    let reopened = open(&path);
    assert!(reopened.annotation_list().types.is_empty());
    assert_eq!(reopened.annotation_list().signatures.len(), 1);
    let annotations = reopened.annotation_list();
    let signature = annotations.signatures.iter().find(|row| row.address == address).unwrap();
    assert_eq!(signature.text, "int4 analyst_first(void *opaque);");
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn compiled_refusal_evidence_pages_preserve_unknown_alignment_and_every_producer_warning_without_importing() {
    let files = TempFiles::new();
    let path = files.generated("dwarf5-o2", "refusals");
    let project = open(&path);
    let review = project.review_debug_layouts().unwrap();
    let producer = review.producer_report.as_ref().unwrap();
    assert!(review.approved.is_empty());
    assert!(!producer.warnings.is_empty());
    let mut rows = Vec::new();
    let mut offset = 0;
    loop {
        let page = call(&project, json!({ "offset": offset, "limit": 17 }), true);
        assert_eq!(page["review_sha256"], review.review_sha256);
        assert_eq!(page["producer_warnings_total"], producer.warnings.len());
        assert_eq!(page["approved_total"], 0);
        rows.extend(page["details"].as_array().unwrap().iter().cloned());
        if page["more"] == false {
            break;
        }
        let next = page["next_offset"].as_u64().unwrap() as usize;
        assert!(next > offset);
        offset = next;
    }
    let warnings: Vec<_> = rows
        .iter()
        .filter(|row| row["kind"] == "warning" && row["source"] == "producer")
        .map(|row| row["text"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(warnings, producer.warnings);
    let missing = rows
        .iter()
        .find(|row| {
            row["kind"] == "type"
                && row["source"] == "producer"
                && row["data"]["original_name"] == "debug_missing_alignment"
        })
        .unwrap();
    assert_eq!(missing["status"], "preview_only");
    assert!(missing["data"]["producer_alignment"].is_null());
    assert_eq!(missing["data"]["byte_size"], support::oracle()["flat"]["size"]);
    let fields = rows
        .iter()
        .filter(|row| row["kind"] == "field" && row["source"] == "producer" && row["type_id"] == missing["data"]["id"])
        .count();
    assert_eq!(fields, support::oracle()["flat"]["fields"].as_array().unwrap().len());
    assert!(log_bytes(&path).is_empty());
    assert!(project.annotation_list().types.is_empty());
    assert!(project.annotation_list().signatures.is_empty());
    assert!(project.undo().unwrap().is_empty());
}
