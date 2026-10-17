use super::*;
use rampage_decompiler::results::{StorageKind, StorageUseRange};
use serde_json::json;

struct HintLog(PathBuf);

impl HintLog {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("rampage-type-hints-{}.jsonl", batch_id())))
    }

    fn append(&self, edit: &Edit) {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.0).unwrap();
        serde_json::to_writer(&mut file, edit).unwrap();
        file.write_all(b"\n").unwrap();
    }

    fn lock_path(&self) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
        path.push(".lock");
        PathBuf::from(path)
    }
}

impl Drop for HintLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.lock_path());
    }
}

fn storage(address: u64) -> VariableStorage {
    VariableStorage {
        kind: StorageKind::Processor,
        space: "register".into(),
        address,
        size: 8,
        use_ranges: vec![StorageUseRange { space: "ram".into(), start: 0x401000, end: 0x401020 }],
    }
}

fn hint(target: TypeHintTarget) -> DerivedTypeHint {
    DerivedTypeHint {
        target,
        data_type: "struct Derived *".into(),
        evidence: vec![TypeHintEvidence { function: u64::MAX, at: u64::MAX - 1, reason: "callee parameter".into() }],
    }
}

fn annotation() -> TypeHintAnnotation {
    TypeHintAnnotation { source_fingerprint: "AB".repeat(32), hints: vec![hint(TypeHintTarget::Return)] }
}

#[test]
fn type_hints_canonicalize_targets_evidence_fingerprints_and_lossless_addresses_without_mutating_callers() {
    let mut entry = annotation();
    let mut local = hint(TypeHintTarget::Local { storage: storage(0x20) });
    local.evidence.push(TypeHintEvidence { function: 7, at: 8, reason: "second".into() });
    local.evidence.push(TypeHintEvidence { function: 7, at: 8, reason: "first".into() });
    entry.hints.push(hint(TypeHintTarget::Parameter { index: 0, storage: storage(0x10) }));
    entry.hints.push(local);
    let original = entry.clone();
    let encoded = encode_type_hints(&entry).unwrap();
    assert_eq!(entry, original);
    assert_eq!(serde_json::to_string(&Field::TypeHint).unwrap(), "\"typehint\"");
    let parsed = parse_type_hints(&serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    assert_eq!(parsed.source_fingerprint, "ab".repeat(32));
    assert!(matches!(&parsed.hints[0].target, TypeHintTarget::Local { .. }));
    assert!(matches!(&parsed.hints[1].target, TypeHintTarget::Parameter { index: 0, .. }));
    assert_eq!(parsed.hints[2].target, TypeHintTarget::Return);
    assert_eq!(
        parsed.hints[0].evidence.iter().map(|item| item.reason.as_str()).collect::<Vec<_>>(),
        ["first", "second", "callee parameter"]
    );
    let wire: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(wire["hints"][2]["evidence"][0]["function"], "0xffffffffffffffff");
    assert_eq!(wire["hints"][2]["evidence"][0]["at"], "0xfffffffffffffffe");
    let mut numeric = wire.clone();
    numeric["hints"][2]["evidence"][0]["function"] = json!(u64::MAX);
    numeric["hints"][2]["evidence"][0]["at"] = json!(u64::MAX - 1);
    numeric["hints"][0]["target"]["storage"]["address"] = json!(32);
    numeric["hints"][0]["target"]["storage"]["size"] = json!("0x8");
    assert_eq!(encode_type_hints(&parse_type_hints(&numeric.to_string()).unwrap()).unwrap(), encoded);
    entry.hints.reverse();
    entry.hints.last_mut().unwrap().evidence.reverse();
    assert_eq!(encode_type_hints(&entry).unwrap(), encoded);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), encoded);
}

#[test]
fn evidence_addresses_accept_lossless_unsigned_numbers_and_hex_but_always_serialize_hex() {
    for address in [0, 1, (1u64 << 53) + 1, u64::MAX - 1, u64::MAX] {
        for function in [json!(address), json!(format!("{address:#x}"))] {
            for at in [json!(address), json!(format!("{address:#x}"))] {
                let input = json!({"function": function, "at": at, "reason": "source parameter"});
                let parsed: TypeHintEvidence = serde_json::from_value(input).unwrap();
                assert_eq!(parsed.function, address);
                assert_eq!(parsed.at, address);
                assert_eq!(
                    serde_json::to_value(parsed).unwrap(),
                    json!({
                        "function": format!("{address:#x}"),
                        "at": format!("{address:#x}"),
                        "reason": "source parameter",
                    })
                );
            }
        }
    }
    for invalid in ["-1", "1.5", "18446744073709551616", "18446744073709551615.0", "null", "true"] {
        for field in ["function", "at"] {
            let other = if field == "function" { "at" } else { "function" };
            let input = format!(r#"{{"{field}":{invalid},"{other}":"0x1","reason":"source parameter"}}"#);
            assert!(serde_json::from_str::<TypeHintEvidence>(&input).is_err(), "{input}");
        }
    }
}

#[test]
fn type_hints_reject_duplicate_targets_aliases_parameter_indices_and_incomplete_shapes() {
    for target in [
        TypeHintTarget::Return,
        TypeHintTarget::Local { storage: storage(0x20) },
        TypeHintTarget::Parameter { index: 0, storage: storage(0x20) },
    ] {
        let mut entry = annotation();
        entry.hints = vec![hint(target.clone()), hint(target)];
        assert!(encode_type_hints(&entry).is_err());
    }
    let mut entry = annotation();
    entry.hints = vec![
        hint(TypeHintTarget::Parameter { index: 0, storage: storage(0x20) }),
        hint(TypeHintTarget::Parameter { index: 0, storage: storage(0x30) }),
    ];
    assert!(encode_type_hints(&entry).is_err());
    entry.hints = vec![hint(TypeHintTarget::Local { storage: storage(0x20) })];
    let valid = serde_json::to_value(&entry).unwrap();
    let mut alias = valid["hints"][0].clone();
    alias["target"]["storage"]["address"] = json!("0x00020");
    let mut duplicate = valid.clone();
    duplicate["hints"].as_array_mut().unwrap().push(alias);
    assert!(parse_type_hints(&duplicate.to_string()).is_err());
    for target in [
        json!({"kind": "Local", "storage": storage(0x20)}),
        json!({"kind": "local"}),
        json!({"kind": "parameter", "storage": storage(0x20)}),
        json!({"kind": "parameter", "index": -1, "storage": storage(0x20)}),
        json!({"kind": "parameter", "index": 4294967296u64, "storage": storage(0x20)}),
        json!({"kind": "return", "storage": storage(0x20)}),
        json!({"kind": "local", "storage": storage(0x20), "index": 0}),
        json!({"local": {"storage": storage(0x20)}}),
    ] {
        let mut invalid = valid.clone();
        invalid["hints"][0]["target"] = target;
        assert!(parse_type_hints(&invalid.to_string()).is_err(), "{invalid}");
    }
    for pointer in ["/hints/0/target/storage", "/hints/0", "/hints/0/evidence/0", ""] {
        let mut invalid = valid.clone();
        invalid.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert!(parse_type_hints(&invalid.to_string()).is_err(), "{invalid}");
    }
    for pointer in ["/hints/0/target/storage/size", "/hints/0/target/storage/use_ranges", "/hints/0/evidence"] {
        let mut invalid = valid.clone();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        invalid.pointer_mut(parent).unwrap().as_object_mut().unwrap().remove(field);
        assert!(parse_type_hints(&invalid.to_string()).is_err());
    }
    for malformed in ["not json", "[]", "{}", r#"{"source_fingerprint":"a","source_fingerprint":"b","hints":[]}"#] {
        assert!(parse_type_hints(malformed).is_err());
    }
}

#[test]
fn type_hint_bounds_apply_to_declarations_fingerprints_evidence_and_total_text() {
    for fingerprint in [String::new(), "a".repeat(63), "a".repeat(65), "g".repeat(64), "é".repeat(32)] {
        let mut entry = annotation();
        entry.source_fingerprint = fingerprint;
        assert!(encode_type_hints(&entry).is_err());
    }
    for declaration in [String::new(), " ".into(), "int\0".into(), "int\n".into(), "x".repeat(4097)] {
        let mut entry = annotation();
        entry.hints[0].data_type = declaration;
        assert!(encode_type_hints(&entry).is_err());
    }
    let mut entry = annotation();
    entry.hints[0].data_type = "x".repeat(4096);
    encode_type_hints(&entry).unwrap();
    entry.hints[0].evidence = vec![entry.hints[0].evidence[0].clone(); 16];
    encode_type_hints(&entry).unwrap();
    let extra_evidence = entry.hints[0].evidence[0].clone();
    entry.hints[0].evidence.push(extra_evidence);
    assert!(encode_type_hints(&entry).is_err());
    entry.hints[0].evidence.clear();
    encode_type_hints(&entry).unwrap();
    entry.hints =
        (0..256).map(|index| hint(TypeHintTarget::Parameter { index, storage: storage(index as u64) })).collect();
    encode_type_hints(&entry).unwrap();
    entry.hints.push(hint(TypeHintTarget::Return));
    assert!(encode_type_hints(&entry).is_err());
    entry = annotation();
    entry.hints[0].evidence[0].reason = "x".repeat(65536 - 64 - entry.hints[0].data_type.len());
    encode_type_hints(&entry).unwrap();
    entry.hints[0].evidence[0].reason.push('x');
    assert!(encode_type_hints(&entry).is_err());
    entry.hints.clear();
    assert!(encode_type_hints(&entry).unwrap_err().contains("clear with None"));
    assert!(parse_type_hints(&" ".repeat(CHECKED_VALUE_BYTES + 1)).is_err());
}

#[test]
fn canonical_storage_identity_detects_reordered_ranges_but_keeps_distinct_mapping_selectors() {
    let mut first = storage(0x20);
    first.use_ranges.push(StorageUseRange { space: "code".into(), start: 1, end: 2 });
    let mut second = first.clone();
    second.use_ranges.reverse();
    let mut entry = annotation();
    entry.hints = vec![hint(TypeHintTarget::Local { storage: first.clone() })];
    let original = entry.clone();
    let canonical = encode_type_hints(&entry).unwrap();
    assert_eq!(entry, original);
    entry.hints = vec![hint(TypeHintTarget::Local { storage: second.clone() })];
    assert_eq!(encode_type_hints(&entry).unwrap(), canonical);
    entry.hints.push(hint(TypeHintTarget::Local { storage: first }));
    assert!(encode_type_hints(&entry).is_err());
    second.use_ranges[0].end += 1;
    entry.hints[0].target = TypeHintTarget::Local { storage: second };
    encode_type_hints(&entry).unwrap();
}

#[test]
fn same_space_range_order_canonicalizes_before_validation_and_duplicate_target_detection() {
    let mut ordered = storage(0x20);
    ordered.use_ranges.push(StorageUseRange { space: "ram".into(), start: 0x401030, end: 0x401040 });
    let mut reversed = ordered.clone();
    reversed.use_ranges.reverse();
    let mut entry = annotation();
    entry.hints = vec![hint(TypeHintTarget::Local { storage: ordered.clone() })];
    let canonical = encode_type_hints(&entry).unwrap();
    entry.hints[0].target = TypeHintTarget::Local { storage: reversed.clone() };
    let original = entry.clone();
    assert_eq!(encode_type_hints(&entry).unwrap(), canonical);
    assert_eq!(entry, original);
    let parsed = parse_type_hints(&serde_json::to_string_pretty(&entry).unwrap()).unwrap();
    assert_eq!(parsed.hints[0].target, TypeHintTarget::Local { storage: ordered.clone() });
    assert_eq!(encode_type_hints(&parsed).unwrap(), canonical);
    entry.hints.push(hint(TypeHintTarget::Local { storage: ordered }));
    assert!(encode_type_hints(&entry).unwrap_err().contains("duplicate type hint target"));
    assert!(parse_type_hints(&serde_json::to_string(&entry).unwrap()).is_err());
    entry.hints.truncate(1);
    reversed.use_ranges[1].end = 0x401035;
    entry.hints[0].target = TypeHintTarget::Local { storage: reversed.clone() };
    assert!(encode_type_hints(&entry).is_err());
    reversed.use_ranges[1] = reversed.use_ranges[0].clone();
    entry.hints[0].target = TypeHintTarget::Local { storage: reversed };
    assert!(encode_type_hints(&entry).is_err());
}

#[test]
fn type_hint_evidence_and_storage_reject_invalid_addresses_missing_fields_and_native_selector_shapes() {
    let mut entry = annotation();
    entry.hints = vec![hint(TypeHintTarget::Local { storage: storage(0x20) })];
    let valid = serde_json::to_value(&entry).unwrap();
    for (pointer, value) in [
        ("/hints/0/evidence/0/function", json!(-1)),
        ("/hints/0/evidence/0/at", json!(1.5)),
        ("/hints/0/evidence/0/at", json!("0x10000000000000000")),
        ("/hints/0/evidence/0/at", json!("not an address")),
        ("/hints/0/evidence/0/reason", json!("")),
        ("/hints/0/evidence/0/reason", json!("bad\0reason")),
        ("/hints/0/target/storage/size", json!(0)),
        ("/hints/0/target/storage/kind", json!("dynamic")),
        ("/hints/0/target/storage/use_ranges/0/end", json!(0)),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(parse_type_hints(&invalid.to_string()).is_err(), "{invalid}");
    }
    for field in ["function", "at", "reason"] {
        let mut invalid = valid.clone();
        invalid["hints"][0]["evidence"][0].as_object_mut().unwrap().remove(field);
        assert!(parse_type_hints(&invalid.to_string()).is_err());
    }
}

#[test]
fn type_hint_batches_undo_redo_reopen_and_clear_leave_analyst_maps_and_name_index_unchanged() {
    let log = HintLog::new();
    let mut first = Annotations::open_for_image(log.0.clone(), Some([0xab; 32])).unwrap();
    first.set(Field::Name, 0x401000, Some("analyst_function".into())).unwrap();
    first.set(Field::Signature, 0x401000, Some("int analyst_function(void);".into())).unwrap();
    first.set(Field::Global, 0x500000, Some("int analyst_global;".into())).unwrap();
    first
        .set(
            Field::LocalType,
            0x401000,
            Some(
                encode_local_types(&[LocalTypeAnnotation { storage: storage(0x20), data_type: "int".into() }]).unwrap(),
            ),
        )
        .unwrap();
    let analyst = first.snapshot();
    let names_revision = first.names_revision();
    let revision = first.revision();
    let mut second = Annotations::open(log.0.clone()).unwrap();
    let encoded = encode_type_hints(&annotation()).unwrap();
    let changes =
        [(Field::TypeHint, 0x401000, Some(encoded.clone())), (Field::TypeHint, 0x402000, Some(encoded.clone()))];
    assert_eq!(first.set_batch_validated(&changes, |_| Ok(())).unwrap(), [true, true]);
    assert!(!first.set(Field::TypeHint, 0x401000, Some(serde_json::to_string_pretty(&annotation()).unwrap())).unwrap());
    assert!(!std::sync::Arc::ptr_eq(&revision, &first.revision()));
    assert!(std::sync::Arc::ptr_eq(&names_revision, &first.names_revision()));
    second.refresh().unwrap();
    assert_eq!(second.type_hints(), first.type_hints());
    assert_eq!(first.checked_read_snapshot().unwrap().type_hints(), first.type_hints());
    assert_eq!(first.undo().unwrap().len(), 2);
    second.refresh().unwrap();
    assert!(second.type_hints().is_empty());
    assert_eq!(first.redo().unwrap().len(), 2);
    for checked in [false, true] {
        let reopened =
            if checked { Annotations::open_checked(log.0.clone()) } else { Annotations::open(log.0.clone()) };
        let reopened = reopened.unwrap();
        assert_eq!(reopened.type_hints(), first.type_hints());
        assert_eq!(reopened.local_types(), analyst.local_types());
        assert_eq!(reopened.signatures(), analyst.signatures());
        assert_eq!(reopened.globals(), analyst.globals());
        assert_eq!(reopened.names(), analyst.names());
        assert_eq!(reopened.addresses, analyst.addresses);
        assert_eq!(reopened.name_owners, analyst.name_owners);
        assert_eq!(reopened.types(), analyst.types());
    }
    first.set(Field::TypeHint, 0x401000, None).unwrap();
    assert!(!first.type_hints().contains_key(&0x401000));
    first.undo().unwrap();
    assert_eq!(first.type_hints()[&0x401000], encoded);
    first.refresh().unwrap();
    std::fs::write(&log.0, b"").unwrap();
    first.refresh().unwrap();
    assert!(first.type_hints().is_empty());
}

#[test]
fn type_hint_history_validates_restored_values_and_shared_edits_block_without_overwrite() {
    let log = HintLog::new();
    let raw = serde_json::to_string_pretty(&annotation()).unwrap();
    log.append(&Edit { field: Field::TypeHint, address: 0x401000, value: Some(raw.clone()), previous: None });
    let mut first = Annotations::open(log.0.clone()).unwrap();
    first.set(Field::TypeHint, 0x401000, None).unwrap();
    let before = std::fs::read(&log.0).unwrap();
    assert_eq!(
        first
            .undo_validated(|candidate| {
                assert_eq!(candidate.type_hints()[&0x401000], raw);
                Err("native hint validation rejected".into())
            })
            .unwrap_err(),
        "native hint validation rejected"
    );
    assert!(first.type_hints().is_empty());
    assert_eq!(first.done.len(), 1);
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    first.undo().unwrap();
    assert!(first.redo_validated(|_| Err("native clear rejected".into())).is_err());
    assert_eq!(first.type_hints()[&0x401000], raw);
    first.redo().unwrap();
    first.set(Field::TypeHint, 0x401000, Some(encode_type_hints(&annotation()).unwrap())).unwrap();
    let mut second = Annotations::open(log.0.clone()).unwrap();
    second.set(Field::TypeHint, 0x401000, None).unwrap();
    let before = std::fs::read(&log.0).unwrap();
    assert!(first.undo().unwrap_err().ends_with(DISCARD_HINT));
    assert!(first.type_hints().is_empty());
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
}

#[test]
fn malformed_shared_type_hint_values_and_previous_values_do_not_publish_refresh() {
    for checked in [false, true] {
        for previous_only in [false, true] {
            let log = HintLog::new();
            let mut annotations = if checked {
                Annotations::open_checked(log.0.clone()).unwrap()
            } else {
                Annotations::open(log.0.clone()).unwrap()
            };
            annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
            annotations.refresh().unwrap();
            let cursor = annotations.log.clone();
            let revision = annotations.revision();
            let (value, previous) = if previous_only { (None, Some("{}".into())) } else { (Some("{}".into()), None) };
            log.append(&Edit { field: Field::TypeHint, address: 0x401000, value, previous });
            let bytes = std::fs::read(&log.0).unwrap();
            assert!(annotations.refresh().is_err());
            assert_eq!(annotations.log, cursor);
            assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
            assert_eq!(annotations.comment(1), Some("kept"));
            assert!(annotations.type_hints().is_empty());
            assert_eq!(annotations.done.len(), 1);
            assert!(Annotations::open(log.0.clone()).is_err());
            assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
        }
    }
}

#[test]
fn type_hint_maps_history_and_checked_read_snapshots_use_existing_budgets() {
    let log = HintLog::new();
    let encoded = encode_type_hints(&annotation()).unwrap();
    log.append(&Edit { field: Field::TypeHint, address: 0x401000, value: Some(encoded.clone()), previous: None });
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    assert_eq!(annotations.checked_read_snapshot().unwrap().type_hints()[&0x401000], encoded);
    assert!(!log.lock_path().exists());
    annotations.done.push(vec![Edit {
        field: Field::TypeHint,
        address: 0x401000,
        value: None,
        previous: Some("{}".into()),
    }]);
    assert!(annotations.checked_read_snapshot().is_err());
    annotations.done.clear();
    annotations.type_hints.insert(0x402000, "{}".into());
    assert!(annotations.preflight_checked().is_err());
    annotations.type_hints.remove(&0x402000);
    annotations.comments.insert(1, "x".repeat(CHECKED_VALUE_BYTES + 1));
    assert!(annotations.set(Field::TypeHint, 0x402000, Some(encoded)).is_err());
    assert!(!annotations.type_hints().contains_key(&0x402000));
}

#[test]
fn first_type_hint_transition_checks_the_full_legacy_prefix_before_mutation_or_append() {
    for prefix in [
        "malformed complete legacy line\n".to_owned(),
        format!("{{\"image\":\"{}\"}}\n{{\"image\":\"legacy\"}}\n", "x".repeat(129)),
        "{\"image\":\"legacy\"}\n".repeat(CHECKED_RECORDS + 1),
    ] {
        let log = HintLog::new();
        std::fs::write(&log.0, prefix).unwrap();
        log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 2, Some("history".into())).unwrap();
        annotations.set(Field::Comment, 3, Some("redo history".into())).unwrap();
        annotations.undo().unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        let revision = annotations.revision();
        let bytes = std::fs::read(&log.0).unwrap();
        let encoded = encode_type_hints(&annotation()).unwrap();
        assert!(annotations.set(Field::TypeHint, 0x401000, Some(encoded.clone())).is_err());
        assert!(
            annotations
                .set_batch_validated(
                    &[(Field::Comment, 1, Some("not published".into())), (Field::TypeHint, 0x401000, Some(encoded)),],
                    |_| panic!("prefix must fail before validation")
                )
                .is_err()
        );
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.type_hints().is_empty());
        assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    }
}

#[test]
fn first_shared_checked_transition_rejects_skipped_legacy_prefix_without_publishing_any_state() {
    let values = [
        (Field::TypeHint, encode_type_hints(&annotation()).unwrap()),
        (
            Field::TypeLibrary,
            encode_type_library(&[LibraryDeclaration {
                names: vec!["Entry".into()],
                declarations: "typedef unsigned int Entry;".into(),
                packing: None,
                source: None,
            }])
            .unwrap(),
        ),
        (
            Field::DataType,
            encode_data_type(&DataTypeAnnotation {
                type_name: Some("Entry".into()),
                count: 1,
                byte_length: 4,
                encoding: None,
            })
            .unwrap(),
        ),
        (
            Field::OperandType,
            encode_operand_types(&[OperandTypeAnnotation {
                operand: 0,
                kind: OperandTypeKind::Enum,
                type_name: "Flags".into(),
                instruction_hex: "90".into(),
            }])
            .unwrap(),
        ),
        (Field::Types, "!managed layout text".into()),
        (Field::Signature, "!managed signature text".into()),
    ];
    for (field, value) in values {
        let log = HintLog::new();
        std::fs::write(&log.0, b"malformed complete legacy line\n").unwrap();
        log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
        let mut annotations = Annotations::open_for_image(log.0.clone(), Some([0xab; 32])).unwrap();
        assert_eq!(annotations.comment(1), Some("kept"));
        log.append(&Edit { field: Field::Comment, address: 2, value: Some("legacy shared".into()), previous: None });
        assert!(annotations.refresh().unwrap());
        assert_eq!(annotations.comment(2), Some("legacy shared"));
        annotations.set(Field::Comment, 3, Some("history".into())).unwrap();
        annotations.set(Field::Comment, 4, Some("redo history".into())).unwrap();
        annotations.undo().unwrap();
        annotations.refresh().unwrap();
        let cache = annotations.snapshot();
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        let revision = annotations.revision();
        let names_revision = annotations.names_revision();
        let warnings = annotations.warnings();
        let address = if field == Field::TypeLibrary { 0 } else { 0x401000 };
        log.append(&Edit { field, address, value: Some(value), previous: None });
        log.append(&Edit { field: Field::Comment, address: 5, value: Some("not published".into()), previous: None });
        let bytes = std::fs::read(&log.0).unwrap();
        assert!(annotations.refresh().is_err(), "{field:?}");
        assert!(annotations.refresh().is_err(), "refusal must retain the original cursor");
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert_eq!(annotations.comments(), cache.comments());
        assert_eq!(annotations.names(), cache.names());
        assert_eq!(annotations.addresses, cache.addresses);
        assert_eq!(annotations.name_owners, cache.name_owners);
        assert_eq!(annotations.signatures(), cache.signatures());
        assert_eq!(annotations.types(), cache.types());
        assert_eq!(annotations.type_library(), cache.type_library());
        assert_eq!(annotations.data_types(), cache.data_types());
        assert_eq!(annotations.operand_types(), cache.operand_types());
        assert_eq!(annotations.type_hints(), cache.type_hints());
        assert_eq!(annotations.managed_layouts, cache.managed_layouts);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
        assert_eq!(annotations.warnings(), warnings);
        assert_eq!(annotations.checked_reads, cache.checked_reads);
        assert!(Annotations::open(log.0.clone()).is_err());
        assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    }
}

#[test]
fn type_hint_history_stages_shared_checked_overflow_even_when_current_hints_are_cleared() {
    for redo in [false, true] {
        let log = HintLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::TypeHint, 0x401000, Some(encode_type_hints(&annotation()).unwrap())).unwrap();
        if redo {
            annotations.undo().unwrap();
        }
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        log.append(&Edit {
            field: Field::Comment,
            address: 2,
            value: Some("x".repeat(CHECKED_VALUE_BYTES + 1)),
            previous: None,
        });
        let bytes = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(redo, |_| panic!("reject before work"));
        assert!(result.is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    }
}

#[test]
fn shared_type_hint_introduction_requires_staged_history_even_when_the_same_tail_clears_it() {
    for clear in [false, true] {
        let log = HintLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        let revision = annotations.revision();
        let encoded = encode_type_hints(&annotation()).unwrap();
        log.append(&Edit { field: Field::TypeHint, address: 0x401000, value: Some(encoded.clone()), previous: None });
        if clear {
            log.append(&Edit { field: Field::TypeHint, address: 0x401000, value: None, previous: Some(encoded) });
        }
        log.append(&Edit { field: Field::Comment, address: 2, value: Some("shared".into()), previous: None });
        let bytes = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(false, |staged| {
            assert!(staged.checked_reads);
            assert_eq!(staged.type_hints().is_empty(), clear);
            assert_eq!(staged.comment(2), Some("shared"));
            Err(ApiError::Invalid("native validation refusal".into()))
        });
        assert!(result.is_err());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.type_hints().is_empty());
        assert_eq!(annotations.comment(2), None);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), bytes);
    }
}

#[test]
fn empty_and_latest_legacy_history_keep_their_existing_compatibility_with_type_hints() {
    let log = HintLog::new();
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    log.append(&Edit {
        field: Field::TypeHint,
        address: 0x401000,
        value: Some(encode_type_hints(&annotation()).unwrap()),
        previous: None,
    });
    annotations
        .locked_staged_history(false, |staged| {
            assert!(staged.type_hints().is_empty());
            assert!(staged.undo().map_err(ApiError::Invalid)?.is_empty());
            Ok(())
        })
        .unwrap();
    assert_eq!(annotations.log.as_ref().unwrap().read, 0);
    let mut annotations = Annotations::in_memory();
    annotations.done.resize(
        CHECKED_HISTORY_STEPS + 1,
        vec![Edit { field: Field::TypeHint, address: 0x401000, value: None, previous: None }],
    );
    annotations.set(Field::Comment, 1, Some("x".repeat(CHECKED_VALUE_BYTES + 1))).unwrap();
    annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(annotations.comment(1), None);
    annotations.locked_staged_history(true, |staged| staged.redo().map_err(ApiError::Invalid)).unwrap();
    assert!(annotations.comment(1).unwrap().len() > CHECKED_VALUE_BYTES);
    assert!(!annotations.checked_reads);
}
