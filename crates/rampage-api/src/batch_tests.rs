use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_loaders::Binary;
use serde_json::{Value, json};

use super::*;

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-annotation-operations-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("hello-x64.elf");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        std::fs::copy(source, &path).unwrap();
        Self { log: directory.join("annotations.jsonl"), directory, path }
    }

    fn project(&self) -> Project {
        Project::with_annotations(Binary::open(&self.path).unwrap(), Annotations::open(self.log.clone()).unwrap())
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.log).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn snapshot(project: &Project) -> Value {
    let annotations = project.annotations.read().unwrap();
    json!({
        "names": annotations.names(), "comments": annotations.comments(),
        "signatures": annotations.signatures(), "types": annotations.types(),
        "type_library": annotations.type_library(), "debug_types": annotations.debug_types(),
        "globals": annotations.globals(), "local_names": annotations.local_names(),
        "local_types": annotations.local_types(), "type_hints": annotations.type_hints(),
        "data_types": annotations.data_types(), "operand_types": annotations.operand_types(),
        "patches": annotations.patches(), "cursor": annotations.test_log_cursor(),
    })
}

fn operation(value: Value) -> AnnotationBatchEntry {
    serde_json::from_value(value).unwrap()
}

#[test]
fn annotation_operations_require_explicit_values_and_reject_raw_fields() {
    let schema = serde_json::to_value(schemars::schema_for!(AnnotationBatchEntry)).unwrap();
    for variant in schema["oneOf"].as_array().unwrap() {
        assert!(variant["required"].as_array().unwrap().contains(&json!("value")));
        assert!(variant["properties"]["value"]["type"].as_array().unwrap().contains(&json!("null")));
    }
    for operation in ["rename", "comment", "signature", "types", "global"] {
        assert!(
            serde_json::from_value::<AnnotationBatchEntry>(json!({
                "operation": operation, "at": "0x1000"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AnnotationBatchEntry>(json!({
                "operation": operation, "at": "0x1000", "value": null
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<AnnotationBatchEntry>(json!({
                "operation": operation, "at": "0x1000", "value": null, "field": "patch"
            }))
            .is_err()
        );
    }
    for operation in ["patch", "local_type", "operand_type", "debug_types", "type_library"] {
        assert!(
            serde_json::from_value::<AnnotationBatchEntry>(json!({
                "operation": operation, "at": "0x1000", "value": null
            }))
            .is_err()
        );
    }
}

#[test]
fn mixed_annotations_validate_together_and_undo_redo_reopen_as_one_batch() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let add = project.resolve("add").unwrap();
    let data =
        project.binary.segments.iter().find(|segment| !segment.perms.execute && segment.size >= 4).unwrap().address;
    project.rename(add, Some("old_add")).unwrap();
    project.comment(add, Some("remove this")).unwrap();
    let before = snapshot(&project);
    let entries = vec![
        operation(json!({"operation": "rename", "at": "old_add", "value": null})),
        operation(json!({"operation": "comment", "at": "old_add", "value": null})),
        operation(json!({"operation": "signature", "at": (add + 1).to_string(),
            "value": "batch_number sum(batch_number left,batch_number right);"})),
        operation(json!({"operation": "global", "at": format!("{data:#x}"), "value": "batch_number batch_counter;"})),
        operation(json!({"operation": "types", "at": "old_add", "value": "typedef int4 batch_number;"})),
    ];
    let result = project.batch_annotations(&entries).unwrap();
    assert_eq!(result.changed, entries.len());
    assert_eq!(result.entries[2].address, add);
    assert!(result.entries[0].value.is_none() && result.entries[1].value.is_none());
    assert_eq!(project.resolve("add").unwrap(), add);
    assert!(project.resolve("old_add").is_err());
    assert!(project.comment_at(add).is_none());
    let code = project.decompile(add).unwrap().code;
    assert!(code.contains("batch_number left") && code.contains("batch_number right"), "{code}");
    let applied = snapshot(&project);
    assert_eq!(project.undo().unwrap().len(), entries.len());
    let restored = snapshot(&project);
    for field in before.as_object().unwrap().keys().filter(|field| field.as_str() != "cursor") {
        assert_eq!(restored[field], before[field], "{field}");
    }
    assert_eq!(project.redo().unwrap().len(), entries.len());
    let reopened = fixture.project();
    let persisted = snapshot(&reopened);
    for field in applied.as_object().unwrap().keys().filter(|field| field.as_str() != "cursor") {
        assert_eq!(persisted[field], applied[field], "{field}");
    }
    assert!(reopened.decompile(add).unwrap().code.contains("batch_number left"));
    let unchanged = reopened
        .batch_annotations(&[operation(
            json!({"operation": "types", "at": "add", "value": "typedef int4 batch_number;"}),
        )])
        .unwrap();
    assert_eq!(unchanged.changed, 0);
    assert!(reopened.undo().unwrap().is_empty());
}

#[test]
fn invalid_final_native_declaration_preserves_all_fields_history_bytes_and_sidecar() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let add = project.resolve("add").unwrap();
    project.comment(add, Some("retained undo")).unwrap();
    project.comment(add + 1, Some("retained redo")).unwrap();
    project.undo().unwrap();
    let before = snapshot(&project);
    let sidecar = fixture.bytes();
    let binary = std::fs::read(&fixture.path).unwrap();
    let data =
        project.binary.segments.iter().find(|segment| !segment.perms.execute && segment.size >= 4).unwrap().address;
    for entries in [
        vec![
            operation(json!({"operation": "rename", "at": "add", "value": "not_applied"})),
            operation(json!({"operation": "comment", "at": "add", "value": null})),
            operation(json!({"operation": "types", "at": "add", "value": "typedef int4 batch_number;"})),
            operation(json!({"operation": "signature", "at": "add", "value": "batch_missing sum(batch_number left);"})),
        ],
        vec![
            operation(json!({"operation": "rename", "at": "add", "value": "batch_counter"})),
            operation(json!({"operation": "comment", "at": "add", "value": null})),
            operation(json!({"operation": "types", "at": "add", "value": "typedef int4 batch_number;"})),
            operation(json!({"operation": "global", "at": data.to_string(), "value": "batch_number batch_counter;"})),
        ],
    ] {
        assert!(project.batch_annotations(&entries).is_err());
        assert_eq!(snapshot(&project), before);
        assert_eq!(fixture.bytes(), sidecar);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), binary);
    }
    assert_eq!(project.redo().unwrap().len(), 1);
    assert_eq!(project.comment_at(add + 1).as_deref(), Some("retained redo"));
    assert_eq!(project.undo().unwrap().len(), 1);
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn public_batch_rejects_valid_internal_layouts_signature_seals_and_global_payloads_atomically() {
    use crate::debug_layout_import::{LayoutBundle, image_digest, seal_signature};
    use rampage_decompiler::layout::{
        LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
    };

    let fixture = Fixture::new();
    let project = fixture.project();
    let add = project.resolve("add").unwrap();
    let data =
        project.binary.segments.iter().find(|segment| !segment.perms.execute && segment.size >= 4).unwrap().address;
    let layout = PlainStructLayout {
        name: "batch_internal_record".into(),
        size: 4,
        alignment: 4,
        organization: LayoutOrganization {
            pointer_size: 8,
            int_size: 4,
            long_size: 8,
            scalar_alignments: [1, 2, 4, 8],
        },
        fields: vec![LayoutField {
            name: "value".into(),
            offset: 0,
            size: 4,
            ty: LayoutType::Scalar {
                scalar: LayoutScalar { name: "int4".into(), kind: ScalarKind::SignedInteger, size: 4, alignment: 4 },
            },
        }],
    };
    let text = LayoutBundle::encode(&image_digest(&project).unwrap(), &[layout]).unwrap();
    let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
    let sealed = seal_signature("int4 sum(batch_internal_record *record);", &[&bundle.layouts[0]]).unwrap();
    let mut trusted = Annotations::in_memory();
    trusted.set(Field::Types, add, Some(text.clone())).unwrap();
    trusted.set(Field::Signature, add, Some(sealed.clone())).unwrap();
    {
        let state = project.decompiler.lock().unwrap();
        let options = crate::decompile::default_options(&project.binary);
        project.validate_annotation_snapshot(&state, &options, &trusted).unwrap();
    }
    project.comment(add, Some("retained undo")).unwrap();
    project.comment(add + 1, Some("retained redo")).unwrap();
    project.undo().unwrap();
    let before = snapshot(&project);
    let sidecar = fixture.bytes();
    let binary = std::fs::read(&fixture.path).unwrap();
    for (field, at, value) in
        [("types", add, text), ("signature", add, sealed), ("global", data, "!rampage-internal-global-payload".into())]
    {
        let result = project.batch_annotations(&[
            operation(json!({"operation": "rename", "at": "add", "value": "must_not_apply"})),
            operation(json!({"operation": "comment", "at": "add", "value": null})),
            operation(json!({"operation": field, "at": at.to_string(), "value": value})),
        ]);
        let error = result.unwrap_err().to_string();
        assert!(error.contains("unsupported syntax"), "{field}: {error}");
        assert_eq!(snapshot(&project), before, "{field}");
        assert_eq!(fixture.bytes(), sidecar, "{field}");
        assert_eq!(std::fs::read(&fixture.path).unwrap(), binary, "{field}");
    }
    assert_eq!(project.redo().unwrap().len(), 1);
    assert_eq!(project.comment_at(add + 1).as_deref(), Some("retained redo"));
    assert_eq!(project.undo().unwrap().len(), 1);
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn response_preflight_rejection_preserves_all_fields_history_bytes_and_sidecar_even_for_noops() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let add = project.resolve("add").unwrap();
    project.comment(add, Some("retained undo")).unwrap();
    project.comment(add + 1, Some("retained redo")).unwrap();
    project.undo().unwrap();
    let before = snapshot(&project);
    let sidecar = fixture.bytes();
    let binary = std::fs::read(&fixture.path).unwrap();
    let calls = std::cell::Cell::new(0);
    for (entries, changed, comment) in [
        (
            vec![
                operation(json!({"operation": "rename", "at": "add", "value": "rejected_name"})),
                operation(json!({"operation": "comment", "at": "add", "value": " normalized "})),
                operation(json!({"operation": "signature", "at": "add", "value": "int4 sum(int4 left,int4 right);"})),
            ],
            3,
            "normalized",
        ),
        (vec![operation(json!({"operation": "comment", "at": "add", "value": "retained undo"}))], 0, "retained undo"),
    ] {
        let result = project.batch_annotations_with_preflight(&entries, |result| {
            calls.set(calls.get() + 1);
            assert_eq!(result.changed, changed);
            assert_eq!(result.entries.len(), entries.len());
            assert!(result.entries.iter().any(|entry| {
                entry.field == Field::Comment && entry.address == add && entry.value.as_deref() == Some(comment)
            }));
            Err(ApiError::Invalid("response exceeds caller byte budget".into()))
        });
        assert!(result.unwrap_err().to_string().contains("caller byte budget"));
        assert_eq!(snapshot(&project), before);
        assert_eq!(fixture.bytes(), sidecar);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), binary);
    }
    assert_eq!(calls.get(), 2);
    assert_eq!(project.redo().unwrap().len(), 1);
    assert_eq!(project.comment_at(add + 1).as_deref(), Some("retained redo"));
    assert_eq!(project.undo().unwrap().len(), 1);
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn names_swap_and_all_targets_resolve_before_the_first_rename() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let add = project.resolve("add").unwrap();
    project.rename(add, Some("left")).unwrap();
    project.rename(add + 1, Some("right")).unwrap();
    project
        .batch_annotations(&[
            operation(json!({"operation": "rename", "at": "left", "value": "right"})),
            operation(json!({"operation": "rename", "at": "right", "value": "left"})),
            operation(json!({"operation": "comment", "at": "left", "value": " original left "})),
            operation(json!({"operation": "comment", "at": "right", "value": "original right"})),
        ])
        .unwrap();
    assert_eq!(project.resolve("right").unwrap(), add);
    assert_eq!(project.resolve("left").unwrap(), add + 1);
    assert_eq!(project.comment_at(add).as_deref(), Some("original left"));
    assert_eq!(project.comment_at(add + 1).as_deref(), Some("original right"));
    let before = snapshot(&project);
    let sidecar = fixture.bytes();
    for entries in [
        vec![
            operation(json!({"operation": "rename", "at": "left", "value": "same"})),
            operation(json!({"operation": "rename", "at": "right", "value": "same"})),
        ],
        vec![
            operation(json!({"operation": "comment", "at": "right", "value": null})),
            operation(json!({"operation": "comment", "at": add.to_string(), "value": "duplicate"})),
        ],
        vec![operation(json!({"operation": "rename", "at": (add + 2).to_string(), "value": "left"}))],
        vec![
            operation(json!({"operation": "rename", "at": "left", "value": "new_name"})),
            operation(json!({"operation": "comment", "at": "new_name", "value": "must not resolve"})),
        ],
        vec![
            operation(json!({"operation": "signature", "at": add.to_string(), "value": null})),
            operation(json!({"operation": "signature", "at": (add + 1).to_string(), "value": null})),
        ],
    ] {
        assert!(project.batch_annotations(&entries).is_err());
        assert_eq!(snapshot(&project), before);
        assert_eq!(fixture.bytes(), sidecar);
    }
}

#[test]
fn native_configuration_errors_reject_the_whole_mixed_batch_without_fallback() {
    let fixture = Fixture::new();
    let project = fixture.project();
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("no-such-batch-compiler".into()),
        ..Default::default()
    }));
    let before = snapshot(&project);
    assert!(
        project
            .batch_annotations(&[
                operation(json!({"operation": "comment", "at": "add", "value": "must not persist"})),
                operation(json!({"operation": "signature", "at": "add", "value": "int4 sum(int4 left,int4 right);"})),
            ])
            .is_err()
    );
    assert_eq!(snapshot(&project), before);
    assert!(fixture.bytes().is_empty());
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn annotation_batch_refuses_stale_byte_authority_before_resolving_or_validating_native_input() {
    let fixture = Fixture::new();
    let original = std::sync::Arc::new(fixture.project());
    let held = original.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    let entries = [
        operation(json!({"operation": "comment", "at": "main", "value": "must stay atomic"})),
        operation(json!({"operation": "signature", "at": "main", "value": "int4 main(void);"})),
    ];
    let before = snapshot(&original);
    let sidecar = fixture.bytes();
    let error = original.batch_annotations(&entries).unwrap_err().to_string();
    assert!(error.contains("stale"), "{error}");
    assert_eq!(snapshot(&original), before);
    assert_eq!(fixture.bytes(), sidecar);
    assert_eq!(held.batch_annotations(&entries).unwrap().changed, entries.len());
    let peer = std::sync::Arc::new(fixture.project());
    let latest = peer.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 9, 0, 0, 0], false).unwrap().project;
    let before = snapshot(&latest);
    let held_before = snapshot(&held);
    let sidecar = fixture.bytes();
    assert!(held.batch_annotations(&entries).unwrap_err().to_string().contains("stale"));
    assert_eq!(snapshot(&latest), before);
    assert_eq!(snapshot(&held), held_before);
    assert_eq!(fixture.bytes(), sidecar);
}

#[test]
fn annotation_operations_enforce_entry_and_text_budgets_before_publication() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let entry = operation(json!({"operation": "comment", "at": "add", "value": "bounded"}));
    assert!(project.batch_annotations(&vec![entry; MAX_BATCH + 1]).is_err());
    assert!(
        project
            .batch_annotations(&[operation(json!({
                "operation": "comment", "at": "add", "value": "x".repeat(1024 * 1024 + 1)
            }))])
            .is_err()
    );
    assert!(fixture.bytes().is_empty());
    assert!(project.undo().unwrap().is_empty());
}
