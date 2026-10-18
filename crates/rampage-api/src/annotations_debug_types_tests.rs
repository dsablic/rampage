use super::*;
use crate::debug_type_import::{DebugTypesManifest, DebugTypesSignature};
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};
use rampage_loaders::debug_types::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct DebugTypesLog(PathBuf);

impl DebugTypesLog {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("rampage-debug-types-{}.jsonl", batch_id())))
    }

    fn append(&self, edit: &Edit) {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.0).unwrap();
        serde_json::to_writer(&mut file, edit).unwrap();
        file.write_all(b"\n").unwrap();
    }

    fn append_batch(&self, edits: &[Edit], escaped: bool) {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.0).unwrap();
        let batch = batch_id();
        serde_json::to_writer(&mut file, &BatchHeader { batch: batch.clone(), edits: edits.len() }).unwrap();
        file.write_all(b"\n").unwrap();
        for edit in edits {
            let mut raw = serde_json::to_string(&BatchMember { edit, batch: &batch }).unwrap();
            if escaped {
                raw = raw.replace("\"field\"", "\"\\u0066ield\"").replace("\"debugtypes\"", "\"debug\\u0074ypes\"");
            }
            writeln!(file, "{raw}").unwrap();
        }
    }
}

impl Drop for DebugTypesLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

fn envelope(id: u64) -> Value {
    json!({"version": 1, "imports": [{"id": format!("{id:064x}"), "library_names": ["Entry"]}]})
}

fn encoded(id: u64) -> String {
    encode_debug_types(&envelope(id)).unwrap()
}

fn hash(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

#[derive(Clone)]
pub(crate) struct RetainedDebugTypesFixture {
    pub(crate) manifest: DebugTypesManifest,
}

pub(crate) fn retained_fixture(seed: u64) -> RetainedDebugTypesFixture {
    static BASE: std::sync::OnceLock<DebugTypesManifest> = std::sync::OnceLock::new();
    let mut manifest = BASE
        .get_or_init(|| {
            let origin =
                DebugTypeOrigin { source: DebugSourceKind::Dwarf, unit: Some("fixture:unit".into()), index: 1 };
            let ty = |id: &str, name: &str, byte_size: Option<u64>, kind| DebugType {
                id: id.into(),
                original_name: Some(name.into()),
                emitted_name: None,
                byte_size,
                alignment: None,
                kind,
                origin: origin.clone(),
                unsupported: vec![],
            };
            let producer = DebugTypeReport {
                types: vec![
                    ty(
                        "integer",
                        "I32",
                        Some(4),
                        DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Signed, c_name: None },
                    ),
                    ty(
                        "alias",
                        "Entry",
                        Some(4),
                        DebugTypeKind::Typedef { target: "integer".into(), constant: false, volatile: false },
                    ),
                    ty(
                        "function",
                        "Callback",
                        None,
                        DebugTypeKind::Function {
                            convention: "normal".into(),
                            parameters: vec![],
                            return_type: "integer".into(),
                            variadic: false,
                        },
                    ),
                ],
                signatures: vec![DebugSignature {
                    address: 0x1000,
                    name: Some("fixture_function".into()),
                    type_id: "function".into(),
                    origin,
                    unsupported: vec![],
                }],
                provenance: DebugTypeProvenance {
                    source: DebugSourceKind::Dwarf,
                    source_sha256: hash(b"annotation test producer report"),
                    pdb_guid: None,
                    pdb_age: None,
                },
                warnings: vec![],
                limits: DebugTypeLimits::default(),
            };
            let options = DecompilerOptions::default();
            let mut engine = Decompiler::open_with_options(
                rampage_arch::Arch::X86_64,
                false,
                &[MemoryRegion {
                    base: 0x1000,
                    bytes: &[0xc3],
                    size: 1,
                    readable: true,
                    writable: false,
                    executable: true,
                }],
                &options,
            )
            .expect("annotation proof fixtures require the real native engine");
            let declarations = "typedef int4 Entry;\ntypedef int4 Callback(void);\n".to_owned();
            let native = engine.parse_type_library(&declarations, None).unwrap();
            let default_calling_convention = native
                .iter()
                .find_map(|ty| ty.callback.as_ref().and_then(|callback| callback.calling_convention.clone()))
                .expect("measured native callback convention");
            DebugTypesManifest {
                id: String::new(),
                review_sha256: String::new(),
                image_sha256: String::new(),
                specification_sha256: crate::debug_layout_import::current_specification_digest().unwrap(),
                options: json!({"platform": format!("{:?}", options.platform),
                    "compiler": options.compiler, "arm_be8": options.arm_be8}),
                language_id: engine.language_id().to_owned(),
                organization: engine.data_organization(),
                default_calling_convention,
                producer: serde_json::to_value(producer).unwrap(),
                library_names: vec!["Callback".into(), "Entry".into()],
                declarations_sha256: hash(declarations.as_bytes()),
                declarations,
                expected_native_named_types: native,
                signatures: vec![DebugTypesSignature {
                    address: 0x1000,
                    declaration: "int4 debug_signature(void);".into(),
                    producer_type_id: "function".into(),
                }],
            }
        })
        .clone();
    manifest.image_sha256 = hash(&seed.to_le_bytes());
    manifest.producer["provenance"]["source_sha256"] = json!(manifest.image_sha256);
    let mut fixture = RetainedDebugTypesFixture { manifest };
    fixture.rehash();
    fixture
}

impl RetainedDebugTypesFixture {
    fn rehash(&mut self) {
        self.manifest.id.clear();
        self.manifest.review_sha256.clear();
        self.manifest.id = hash(&serde_json::to_vec(&self.manifest).unwrap());
        self.manifest.review_sha256 = hash(self.manifest.id.as_bytes());
    }

    fn value(&self) -> String {
        encode_debug_types(&json!({"version": 1, "imports": [&self.manifest]})).unwrap()
    }

    fn library(&self) -> String {
        encode_type_library(&[LibraryDeclaration {
            names: self.manifest.library_names.clone(),
            declarations: self.manifest.declarations.clone(),
            packing: None,
            source: Some(TypeLibrarySource { kind: "checked_debug_types".into(), identity: self.manifest.id.clone() }),
        }])
        .unwrap()
    }

    fn signature(&self) -> String {
        format!("!rampage-debug-types-signature-v1\n{}\n{}", self.manifest.id, self.manifest.signatures[0].declaration)
    }

    fn changes(&self) -> Vec<(Field, u64, Option<String>)> {
        vec![
            (Field::DebugTypes, 0, Some(self.value())),
            (Field::TypeLibrary, 0, Some(self.library())),
            (Field::Signature, 0x1000, Some(self.signature())),
        ]
    }

    fn install(&self, annotations: &mut Annotations) {
        annotations.set_batch_validated(&self.changes(), |_| Ok(())).unwrap();
    }

    fn edits(&self, previous: &Annotations) -> Vec<Edit> {
        edits_for(&self.changes(), previous)
    }
}

fn clears() -> Vec<(Field, u64, Option<String>)> {
    vec![(Field::DebugTypes, 0, None), (Field::TypeLibrary, 0, None), (Field::Signature, 0x1000, None)]
}

fn edits_for(changes: &[(Field, u64, Option<String>)], previous: &Annotations) -> Vec<Edit> {
    changes
        .iter()
        .map(|(field, address, value)| Edit {
            field: *field,
            address: *address,
            value: value.clone(),
            previous: previous.field_map(*field).get(address).cloned(),
        })
        .collect()
}

#[test]
fn canonical_envelope_preserves_import_and_library_name_order_without_claiming_native_proof() {
    let mut value = envelope(2);
    value["imports"][0]["library_names"] = json!(["ZBase", "ADependent"]);
    value["imports"][0]["source"] = json!({"kind": "not-native-proof", "future": [true]});
    value["imports"].as_array_mut().unwrap().push(envelope(1)["imports"][0].clone());
    let raw = serde_json::to_string_pretty(&value).unwrap();
    let canonical = encode_debug_types(&value).unwrap();
    assert_ne!(raw, canonical);
    assert_eq!(parse_debug_types(&raw).unwrap(), value);
    assert_eq!(encode_debug_types(&parse_debug_types(&raw).unwrap()).unwrap(), canonical);
    assert_eq!(parse_debug_types(&canonical).unwrap()["imports"][0]["id"], format!("{:064x}", 2));
    assert_eq!(value["imports"][0]["library_names"], json!(["ZBase", "ADependent"]));
    assert_eq!(serde_json::to_string(&Field::DebugTypes).unwrap(), "\"debugtypes\"");
    assert_eq!(serde_json::from_str::<Field>("\"debugtypes\"").unwrap(), Field::DebugTypes);
}

#[test]
fn version_shape_ids_and_root_keys_are_guarded() {
    let valid = envelope(1);
    let mut invalid = vec![
        json!([]),
        json!(null),
        json!({"version": 1}),
        json!({"imports": valid["imports"]}),
        json!({"version": 0, "imports": valid["imports"]}),
        json!({"version": 2, "imports": valid["imports"]}),
        json!({"version": "1", "imports": valid["imports"]}),
        json!({"version": 1.0, "imports": valid["imports"]}),
        json!({"version": 1, "imports": valid["imports"], "extra": true}),
        json!({"version": 1, "imports": []}),
        json!({"version": 1, "imports": {}}),
        json!({"version": 1, "imports": [null]}),
        json!({"version": 1, "imports": [{}]}),
        json!({"version": 1, "imports": [valid["imports"][0], valid["imports"][0]]}),
    ];
    for id in [json!(1), json!(""), json!("f".repeat(63)), json!("f".repeat(65)), json!("A".repeat(64))] {
        invalid.push(json!({"version": 1, "imports": [{"id": id}]}));
    }
    for value in invalid {
        assert!(encode_debug_types(&value).is_err(), "{value}");
        assert!(parse_debug_types(&value.to_string()).is_err(), "{value}");
    }
    let raw = format!("{{\"version\":1,\"version\":1,\"imports\":{}}}", valid["imports"]);
    assert!(parse_debug_types(&raw).is_err());
    let imports: Vec<_> = (0..16).map(|id| envelope(id)["imports"][0].clone()).collect();
    let mut at_limit = json!({"version": 1, "imports": imports});
    encode_debug_types(&at_limit).unwrap();
    at_limit["imports"].as_array_mut().unwrap().push(envelope(16)["imports"][0].clone());
    assert!(encode_debug_types(&at_limit).is_err());
}

#[test]
fn flexible_import_fields_still_have_bounded_identifiers_text_depth_and_value_bytes() {
    let names: Vec<_> = (0..256).map(|index| format!("Type{index}")).collect();
    let mut value = envelope(1);
    value["imports"][0]["library_names"] = json!(names);
    encode_debug_types(&value).unwrap();
    value["imports"][0]["library_names"].as_array_mut().unwrap().push(json!("Extra"));
    assert!(encode_debug_types(&value).is_err());
    for names in [
        json!(null),
        json!("Entry"),
        json!([1]),
        json!([""]),
        json!(["1Entry"]),
        json!(["two words"]),
        json!(["Týpe"]),
        json!(["x".repeat(129)]),
    ] {
        value["imports"][0]["library_names"] = names;
        assert!(encode_debug_types(&value).is_err());
        assert!(parse_debug_types(&value.to_string()).is_err());
    }
    for extra in [json!({"text": "bad\0text"}), json!({"bad\0key": true}), json!([{"nested": "\0"}])] {
        let mut value = envelope(1);
        value["imports"][0]["extra"] = extra;
        assert!(encode_debug_types(&value).is_err());
        assert!(parse_debug_types(&value.to_string()).is_err());
    }
    let mut value = envelope(1);
    value["imports"][0].as_object_mut().unwrap().remove("library_names");
    encode_debug_types(&value).unwrap();
    value["imports"][0]["extra"] = json!("x".repeat(CHECKED_VALUE_BYTES));
    assert!(encode_debug_types(&value).is_err());
    assert!(parse_debug_types(&value.to_string()).is_err());
    assert!(parse_debug_types(&" ".repeat(CHECKED_VALUE_BYTES + 1)).is_err());
    let mut nested = json!(0);
    for _ in 0..9 {
        nested = json!([nested]);
    }
    value["imports"][0]["extra"] = nested;
    assert!(encode_debug_types(&value).is_err());
    assert!(parse_debug_types(&value.to_string()).is_err());
}

#[test]
fn invalid_project_keys_even_clears_and_mixed_batches_are_atomic() {
    let log = DebugTypesLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
    annotations.refresh().unwrap();
    let cursor = annotations.log.clone();
    let revision = annotations.revision();
    let before = std::fs::read(&log.0).unwrap();
    for value in [Some(encoded(1)), None, Some(json!({"version": 1, "imports": []}).to_string())] {
        assert!(annotations.set(Field::DebugTypes, 1, value.clone()).is_err());
        assert!(
            annotations
                .set_batch_validated(
                    &[(Field::Comment, 1, Some("unpublished".into())), (Field::DebugTypes, 9, value)],
                    |_| panic!("invalid project keys must refuse before validation"),
                )
                .is_err()
        );
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.debug_types().is_empty());
        assert_eq!(annotations.done.len(), 1);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.log, cursor);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
    assert!(annotations.set(Field::DebugTypes, 0, Some(json!({"version": 1, "imports": []}).to_string())).is_err());
}

#[test]
fn mixed_library_signature_and_debug_types_batch_has_one_history_step_and_native_replay_validation() {
    let log = DebugTypesLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let fixture = retained_fixture(1);
    let changes = fixture.changes();
    let names_revision = annotations.names_revision();
    assert!(annotations.set_batch_validated(&changes, |_| Err("native rejection".into())).is_err());
    assert!(annotations.debug_types().is_empty());
    assert!(annotations.type_library().is_empty());
    assert!(annotations.signatures().is_empty());
    assert!(annotations.done.is_empty());
    assert!(!log.0.exists());
    assert_eq!(annotations.set_batch_validated(&changes, |_| Ok(())).unwrap(), [true; 3]);
    assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
    assert_eq!(annotations.address_of("Entry"), None);
    assert!(annotations.has_checked_annotations());
    let before = std::fs::read(&log.0).unwrap();
    assert!(
        annotations
            .undo_validated(|candidate| {
                assert!(candidate.debug_types().is_empty());
                assert!(candidate.type_library().is_empty());
                assert!(candidate.signatures().is_empty());
                Err("native replay rejection".into())
            })
            .is_err()
    );
    assert_eq!(annotations.done.len(), 1);
    assert!(annotations.undone.is_empty());
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    assert_eq!(annotations.undo().unwrap().len(), 3);
    assert!(annotations.debug_types().is_empty());
    assert!(annotations.redo_validated(|_| Err("native rejection".into())).is_err());
    assert_eq!(annotations.undone.len(), 1);
    assert!(annotations.debug_types().is_empty());
    assert_eq!(annotations.redo().unwrap().len(), 3);
    let reopened = Annotations::open_checked(log.0.clone()).unwrap();
    assert_eq!(reopened.debug_types(), annotations.debug_types());
    assert_eq!(reopened.type_library(), annotations.type_library());
    assert_eq!(reopened.signatures(), annotations.signatures());
}

#[test]
fn debug_types_alone_require_replay_validator_and_preserve_shared_raw_previous_text() {
    let log = DebugTypesLog::new();
    let fixture = retained_fixture(1);
    let mut initial = fixture.edits(&Annotations::in_memory());
    let raw = serde_json::to_string_pretty(&parse_debug_types(&fixture.value()).unwrap()).unwrap();
    initial[0].value = Some(raw.clone());
    log.append_batch(&initial, false);
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let mut replacement = fixture.clone();
    replacement.manifest.review_sha256 = hash(b"new review of unchanged retained facts");
    let replacement = replacement.value();
    annotations.set(Field::DebugTypes, 0, Some(replacement.clone())).unwrap();
    assert!(
        annotations
            .undo_validated(|candidate| {
                assert_eq!(candidate.debug_types()[&0], raw);
                Err("restored proof must be checked".into())
            })
            .is_err()
    );
    annotations.undo().unwrap();
    assert_eq!(annotations.debug_types()[&0], raw);
    assert!(annotations.redo_validated(|_| Err("reapplied proof must be checked".into())).is_err());
    annotations.redo().unwrap();
    assert!(annotations.set(Field::DebugTypes, 0, None).is_err());
    annotations.set_batch_validated(&clears(), |_| Ok(())).unwrap();
    assert!(annotations.debug_types().is_empty());
    annotations.undo().unwrap();
    assert_eq!(annotations.debug_types()[&0], replacement);
}

#[test]
fn shared_project_key_replacement_blocks_history_without_discarding_it() {
    let log = DebugTypesLog::new();
    let mut first = Annotations::open_checked(log.0.clone()).unwrap();
    let original = retained_fixture(1);
    let replacement = retained_fixture(2);
    original.install(&mut first);
    let mut other = Annotations::open_checked(log.0.clone()).unwrap();
    replacement.install(&mut other);
    for _ in 0..2 {
        assert!(first.undo().unwrap_err().ends_with(DISCARD_HINT));
        assert_eq!(first.debug_types()[&0], replacement.value());
        assert_eq!(first.done.len(), 1);
        assert!(first.undone.is_empty());
    }
    original.install(&mut other);
    assert_eq!(first.undo().unwrap().len(), 3);
    assert!(first.debug_types().is_empty());
    first.redo().unwrap();
    first.refresh().unwrap();
    std::fs::write(&log.0, b"").unwrap();
    assert!(first.refresh().unwrap());
    assert!(first.debug_types().is_empty());
}

#[test]
fn debug_types_cache_history_and_snapshots_share_checked_budgets() {
    let fixture = retained_fixture(1);
    let value = fixture.value();
    let mut annotations = Annotations::in_memory();
    fixture.install(&mut annotations);
    assert_eq!(annotations.snapshot().debug_types(), annotations.debug_types());
    assert_eq!(annotations.checked_snapshot().unwrap().debug_types(), annotations.debug_types());
    assert_eq!(annotations.checked_read_snapshot().unwrap().debug_types(), annotations.debug_types());
    let mut budget = CheckedBudget::default();
    budget.edit(&annotations.done[0][0]).unwrap();
    assert_eq!(budget.bytes, value.len());
    assert_eq!(budget.records, 2);
    annotations.done.clear();
    let rows = annotations.debug_types.len() + annotations.type_library.len() + annotations.signatures.len();
    annotations.comments = (0..(CHECKED_RECORDS - rows) as u64).map(|address| (address, String::new())).collect();
    annotations.preflight_checked().unwrap();
    annotations.comments.insert(CHECKED_RECORDS as u64, String::new());
    assert!(annotations.preflight_checked().is_err());
    annotations.comments.clear();
    annotations.debug_types.insert(1, value);
    assert!(annotations.checked_snapshot().is_err());
    annotations.debug_types.clear();
    annotations.done.push(vec![Edit { field: Field::DebugTypes, address: 1, value: None, previous: None }]);
    assert!(annotations.checked_snapshot().is_err());
}

#[test]
fn oversized_mixed_batch_refuses_before_publishing_any_field_or_history() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
    let revision = annotations.revision();
    let mut changes = retained_fixture(1).changes();
    changes.push((Field::Comment, 1, Some("x".repeat(CHECKED_VALUE_BYTES + 1))));
    assert!(annotations.set_batch_validated(&changes, |_| panic!("budget must refuse first")).is_err());
    assert!(annotations.debug_types().is_empty());
    assert_eq!(annotations.comment(1), Some("kept"));
    assert_eq!(annotations.done.len(), 1);
    assert!(annotations.undone.is_empty());
    assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
}

#[test]
fn debug_type_history_text_and_step_counts_are_included_in_cumulative_budgets() {
    let mut fixture = retained_fixture(1);
    fixture.manifest.producer["warnings"] = json!(["x".repeat(512 * 1024)]);
    fixture.rehash();
    let mut annotations = Annotations::in_memory();
    fixture.install(&mut annotations);
    annotations.done.clear();
    let step = fixture.edits(&Annotations::in_memory());
    annotations.done = vec![step.clone(); 14];
    annotations.preflight_checked().unwrap();
    annotations.done.push(step);
    assert!(annotations.preflight_checked().is_err());
    annotations.done = vec![Vec::new(); CHECKED_HISTORY_STEPS];
    annotations.preflight_checked().unwrap();
    assert!(annotations.set_batch_validated(&retained_fixture(2).changes(), |_| Ok(())).is_err());
    assert_eq!(annotations.done.len(), CHECKED_HISTORY_STEPS);
    assert!(annotations.undone.is_empty());
}

#[test]
fn staged_debug_type_history_bounds_shared_refresh_even_when_redo_starts_with_an_empty_map() {
    for redo in [false, true] {
        let log = DebugTypesLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        retained_fixture(1).install(&mut annotations);
        if redo {
            annotations.undo().unwrap();
            assert!(annotations.debug_types().is_empty());
        }
        annotations.refresh().unwrap();
        let checked_reads = annotations.checked_reads;
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        log.append(&Edit {
            field: Field::Comment,
            address: 1,
            value: Some("x".repeat(CHECKED_VALUE_BYTES + 1)),
            previous: None,
        });
        let before = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(redo, |_| {
            panic!("debug type history must bound shared refresh before the native callback")
        });
        assert!(result.is_err(), "redo={redo}");
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert_eq!(annotations.comment(1), None);
        assert_eq!(annotations.debug_types().is_empty(), redo);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        assert_eq!(annotations.checked_reads, checked_reads);
        assert!(!annotations.held);
    }
}

#[test]
fn first_checked_transition_rechecks_malformed_legacy_prefix_without_mutation() {
    let fixture = retained_fixture(1);
    for shared in [false, true] {
        let log = DebugTypesLog::new();
        std::fs::write(&log.0, b"{\"legacy_fragment\":true}\n").unwrap();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        if shared {
            log.append_batch(&fixture.edits(&annotations), false);
        }
        let before = std::fs::read(&log.0).unwrap();
        let result = if shared {
            annotations.refresh()
        } else {
            annotations.set_batch_validated(&fixture.changes(), |_| Ok(())).map(|changed| changed.iter().any(|x| *x))
        };
        assert!(result.is_err(), "shared={shared}");
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.debug_types().is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn invalid_shared_debug_types_refuse_without_advancing_cache_cursor_or_history() {
    for (address, value, previous) in [
        (1, Some(encoded(1)), None),
        (1, None, None),
        (0, Some("not json".into()), None),
        (0, Some(json!({"version": 1, "imports": []}).to_string()), None),
        (0, None, Some("{}".into())),
    ] {
        let log = DebugTypesLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        log.append(&Edit { field: Field::DebugTypes, address, value, previous });
        let before = std::fs::read(&log.0).unwrap();
        assert!(annotations.refresh().is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.debug_types().is_empty());
        assert_eq!(annotations.done.len(), 1);
        assert!(annotations.undone.is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(Annotations::open_checked(log.0.clone()).is_err());
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn unread_escaped_debug_types_even_if_cleared_keep_staged_history_refusal_atomic() {
    for clear in [false, true] {
        let log = DebugTypesLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        let fixture = retained_fixture(1);
        log.append_batch(&fixture.edits(&annotations), true);
        if clear {
            let mut previous = annotations.snapshot();
            fixture.install(&mut previous);
            log.append_batch(&edits_for(&clears(), &previous), false);
        }
        log.append(&Edit { field: Field::Comment, address: 2, value: Some("shared".into()), previous: None });
        let before = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(false, |staged| {
            assert!(staged.checked_reads);
            assert_eq!(staged.debug_types().is_empty(), clear);
            assert_eq!(staged.comment(2), Some("shared"));
            Err(ApiError::Invalid("native refusal".into()))
        });
        assert!(result.is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert!(annotations.debug_types().is_empty());
        assert_eq!(annotations.comment(2), None);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(!annotations.checked_reads);
        assert!(!annotations.held);
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn checked_debug_type_edits_do_not_change_existing_analyst_or_derived_maps() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0x10, Some("typedef int Analyst;".into())).unwrap();
    annotations.set(Field::Global, 0x20, Some("int analyst_global;".into())).unwrap();
    let data_type = encode_data_type(&DataTypeAnnotation {
        type_name: Some("Analyst".into()),
        count: 1,
        byte_length: 4,
        encoding: None,
    })
    .unwrap();
    annotations.set(Field::DataType, 0x30, Some(data_type)).unwrap();
    let hints = encode_type_hints(&TypeHintAnnotation {
        source_fingerprint: "a".repeat(64),
        hints: vec![DerivedTypeHint { target: TypeHintTarget::Return, data_type: "int".into(), evidence: vec![] }],
    })
    .unwrap();
    annotations.set(Field::TypeHint, 0x40, Some(hints)).unwrap();
    let before = annotations.snapshot();
    retained_fixture(1).install(&mut annotations);
    annotations.undo().unwrap();
    annotations.redo().unwrap();
    assert_eq!(annotations.types(), before.types());
    assert_eq!(annotations.globals(), before.globals());
    assert_eq!(annotations.data_types(), before.data_types());
    assert_eq!(annotations.type_hints(), before.type_hints());
}

#[test]
fn structural_envelopes_cannot_be_published_as_checked_business_proofs() {
    let mut annotations = Annotations::in_memory();
    let value = encoded(1);
    parse_debug_types(&value).unwrap();
    assert!(
        annotations
            .set_validated(Field::DebugTypes, 0, Some(value), |_| {
                panic!("assembled business validation must reject before native validation")
            })
            .is_err()
    );
    assert!(annotations.debug_types().is_empty());
    assert!(annotations.done.is_empty());
    let fixture = retained_fixture(1);
    assert!(
        annotations
            .import_signatures(
                &[(0x1000, "unused".into())],
                |_, _, _| fixture.signature(),
                |_| { panic!("signature imports must reject orphan seals before native validation") }
            )
            .is_err()
    );
    assert!(annotations.signatures().is_empty());
    assert!(annotations.done.is_empty());
}

#[test]
fn assembled_tampered_orphan_library_source_and_sealed_signature_changes_refuse_atomically() {
    let fixture = retained_fixture(1);
    let mut bad_native = fixture.clone();
    bad_native.manifest.expected_native_named_types.iter_mut().find(|ty| ty.name == "Entry").unwrap().size = Some(8);
    bad_native.rehash();
    let mut bad_producer = fixture.clone();
    bad_producer.manifest.producer["types"][0]["unexpected_source_fact"] = json!(true);
    bad_producer.rehash();
    let mut wrong_source = parse_type_library(&fixture.library()).unwrap();
    wrong_source[0].source.as_mut().unwrap().identity = hash(b"not the retained proof");
    let mut textual_source = parse_type_library(&fixture.library()).unwrap();
    textual_source[0].source.as_mut().unwrap().kind = "dwarf".into();
    let mutations = vec![
        bad_native.changes(),
        bad_producer.changes(),
        vec![(Field::DebugTypes, 0, Some(retained_fixture(2).value()))],
        vec![(Field::DebugTypes, 0, None)],
        vec![(Field::TypeLibrary, 0, None)],
        vec![(Field::TypeLibrary, 0, Some(encode_type_library(&wrong_source).unwrap()))],
        vec![(Field::TypeLibrary, 0, Some(encode_type_library(&textual_source).unwrap()))],
        vec![(
            Field::Signature,
            0x1000,
            Some(format!("!rampage-debug-types-signature-v1\n{}\nint8 changed(void);", fixture.manifest.id)),
        )],
        vec![(Field::Signature, 0x1000, None), (Field::Signature, 0x2000, Some(fixture.signature()))],
    ];
    for (index, changes) in mutations.iter().enumerate() {
        let log = DebugTypesLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        fixture.install(&mut annotations);
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let names_revision = annotations.names_revision();
        let done = annotations.done.clone();
        let before = std::fs::read(&log.0).unwrap();
        assert!(
            annotations
                .set_batch_validated(changes, |_| panic!("invalid assembled proof must reject before native work"))
                .is_err(),
            "mutation={index}"
        );
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.debug_types()[&0], fixture.value());
        assert_eq!(annotations.type_library()[&0], fixture.library());
        assert_eq!(annotations.signatures()[&0x1000], fixture.signature());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);

        log.append_batch(&edits_for(changes, &annotations), false);
        let shared = std::fs::read(&log.0).unwrap();
        assert!(annotations.refresh().is_err(), "mutation={index}");
        let result: Result<(), ApiError> = annotations
            .locked_staged_history(false, |_| panic!("invalid shared proof must refuse before history/native work"));
        assert!(result.is_err(), "mutation={index}");
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.debug_types()[&0], fixture.value());
        assert_eq!(annotations.type_library()[&0], fixture.library());
        assert_eq!(annotations.signatures()[&0x1000], fixture.signature());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
        assert!(Annotations::open_checked(log.0.clone()).is_err(), "mutation={index}");
        assert_eq!(std::fs::read(&log.0).unwrap(), shared);
    }
}

#[test]
fn first_unchecked_orphan_source_or_signature_refresh_refuses_without_publishing() {
    let fixture = retained_fixture(1);
    for (field, address, value) in [
        (Field::DebugTypes, 0, fixture.value()),
        (Field::TypeLibrary, 0, fixture.library()),
        (Field::Signature, 0x1000, fixture.signature()),
    ] {
        let log = DebugTypesLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        assert!(annotations.set(field, address, Some(value.clone())).is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        log.append(&Edit { field, address, value: Some(value), previous: None });
        let shared = std::fs::read(&log.0).unwrap();
        assert!(annotations.refresh().is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.debug_types().is_empty());
        assert!(annotations.type_library().is_empty());
        assert!(annotations.signatures().is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), shared);
    }
}

#[test]
fn generic_signature_seals_do_not_enable_the_legacy_layout_gate_but_unknown_bang_values_do() {
    let log = DebugTypesLog::new();
    let fixture = retained_fixture(1);
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    fixture.install(&mut annotations);
    assert!(!annotations.has_checked_layouts());
    assert!(annotations.has_checked_annotations());
    assert!(!Annotations::open_checked(log.0.clone()).unwrap().has_checked_layouts());
    let unknown = "!rampage-debug-types-signature-v99\nnot a recognized seal";
    assert!(crate::debug_layout_import::signature(unknown, &BTreeMap::new()).is_err());
    annotations.set(Field::Signature, 0x1000, Some(unknown.into())).unwrap();
    assert!(annotations.has_checked_layouts());
    assert!(Annotations::open_checked(log.0.clone()).unwrap().has_checked_layouts());
    annotations.undo().unwrap();
    assert_eq!(annotations.signatures()[&0x1000], fixture.signature());
    assert!(!annotations.has_checked_layouts());
    annotations.redo().unwrap();
    assert!(annotations.has_checked_layouts());
    annotations.undo().unwrap();
    assert!(!Annotations::open_checked(log.0.clone()).unwrap().has_checked_layouts());
    let generic_seal = fixture.signature();
    for (field, value) in [
        (Field::Types, "!rampage-layout-v1\nlegacy"),
        (Field::Types, "!rampage-layout-v2\nlegacy"),
        (Field::Signature, "!rampage-layout-signature-v1\nlegacy"),
        (Field::Types, generic_seal.as_str()),
    ] {
        let mut candidate = annotations.snapshot();
        candidate.apply(&Edit { field, address: 0x2000, value: Some(value.into()), previous: None });
        assert!(candidate.has_checked_layouts(), "{field:?}: {value}");
        assert_eq!(candidate.managed_layouts, 1);
    }
}
