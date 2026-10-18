use super::*;
use serde_json::json;

struct TypedLog(PathBuf);

impl TypedLog {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("rampage-data-types-{}.jsonl", batch_id())))
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

impl Drop for TypedLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.lock_path());
    }
}

fn data(name: &str) -> DataTypeAnnotation {
    DataTypeAnnotation { type_name: Some(name.into()), count: 2, byte_length: 8, encoding: None }
}

fn operand(index: u8, kind: OperandTypeKind) -> OperandTypeAnnotation {
    OperandTypeAnnotation { operand: index, kind, type_name: "Flags".into(), instruction_hex: "AaBB".into() }
}

fn typed_values() -> [(Field, String); 2] {
    [
        (Field::DataType, encode_data_type(&data("Entry")).unwrap()),
        (Field::OperandType, encode_operand_types(&[operand(1, OperandTypeKind::Enum)]).unwrap()),
    ]
}

#[test]
fn canonical_json_has_independent_lowercase_fields_and_explicit_encoding() {
    assert_eq!(serde_json::to_string(&Field::DataType).unwrap(), "\"datatype\"");
    assert_eq!(serde_json::to_string(&Field::OperandType).unwrap(), "\"operandtype\"");
    let entry = data("Entry");
    let encoded = encode_data_type(&entry).unwrap();
    assert_eq!(encoded, r#"{"type_name":"Entry","count":2,"byte_length":8,"encoding":null}"#);
    let mut annotations = Annotations::in_memory();
    let names_revision = annotations.names_revision();
    let revision = annotations.revision();
    let pretty = serde_json::to_string_pretty(&entry).unwrap();
    assert!(annotations.set(Field::DataType, 0x1000, Some(pretty.clone())).unwrap());
    assert!(!annotations.set(Field::DataType, 0x1000, Some(pretty)).unwrap());
    assert_eq!(annotations.data_types()[&0x1000], encoded);
    assert_eq!(annotations.address_of("Entry"), None);
    assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
    assert!(!std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
    for (encoding, text) in [
        (DataStringEncoding::Utf8, "utf8"),
        (DataStringEncoding::Utf16Le, "utf16_le"),
        (DataStringEncoding::Utf16Be, "utf16_be"),
        (DataStringEncoding::Ascii, "ascii"),
    ] {
        let string = DataTypeAnnotation { type_name: None, count: 1, byte_length: 7, encoding: Some(encoding) };
        let encoded = encode_data_type(&string).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&encoded).unwrap()["encoding"], text);
        assert_eq!(parse_data_type(&encoded).unwrap(), string);
    }
}

#[test]
fn operands_sort_by_index_canonicalize_hex_and_do_not_mutate_inputs() {
    let entries = [operand(31, OperandTypeKind::Offset), operand(0, OperandTypeKind::Enum)];
    let encoded = encode_operand_types(&entries).unwrap();
    assert_eq!(entries[0].operand, 31);
    assert_eq!(entries[0].instruction_hex, "AaBB");
    let parsed = parse_operand_types(&serde_json::to_string_pretty(&entries).unwrap()).unwrap();
    assert_eq!(parsed.iter().map(|entry| entry.operand).collect::<Vec<_>>(), [0, 31]);
    assert!(parsed.iter().all(|entry| entry.instruction_hex == "aabb"));
    assert_eq!(encoded, serde_json::to_string(&parsed).unwrap());
    let json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(json[0]["kind"], "enum");
    assert_eq!(json[1]["kind"], "offset");
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::OperandType, 0x20, Some(encoded)).unwrap();
    assert!(!annotations.set(Field::OperandType, 0x20, Some(serde_json::to_string(&entries).unwrap())).unwrap());
    let all: Vec<_> = (0..32).map(|index| operand(index, OperandTypeKind::Enum)).collect();
    encode_operand_types(&all).unwrap();
}

#[test]
fn data_requires_one_interpretation_bounded_counts_lengths_and_exact_identifiers() {
    for name in
        ["", "two words", "Entry *", "struct Entry", "Entry[2]", "1Entry", "Entry;", "{Entry}", "Éntry", "E\0ntry"]
    {
        assert!(encode_data_type(&data(name)).is_err(), "{name:?}");
    }
    assert!(encode_data_type(&data(&"x".repeat(129))).is_err());
    encode_data_type(&data(&"x".repeat(128))).unwrap();
    let valid = serde_json::to_value(data("Entry")).unwrap();
    for (key, value) in [
        ("type_name", json!(null)),
        ("encoding", json!("utf8")),
        ("count", json!(0)),
        ("count", json!(4097)),
        ("byte_length", json!(0)),
        ("byte_length", json!(1048577)),
        ("count", json!(-1)),
        ("byte_length", json!(1.5)),
        ("encoding", json!("UTF8")),
        ("unknown", json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        assert!(parse_data_type(&invalid.to_string()).is_err(), "{invalid}");
    }
    let mut maximum = data("Entry");
    maximum.count = 4096;
    maximum.byte_length = 1048576;
    encode_data_type(&maximum).unwrap();
    let invalid_string =
        DataTypeAnnotation { type_name: None, count: 2, byte_length: 8, encoding: Some(DataStringEncoding::Utf8) };
    assert!(encode_data_type(&invalid_string).is_err());
    for invalid in [
        "not json",
        "[]",
        r#"{"type_name":"Entry","count":1,"count":2,"byte_length":4}"#,
        r#"{"type_name":"Entry","byte_length":4}"#,
    ] {
        assert!(parse_data_type(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn data_type_selectors_accept_native_core_names_without_allowing_abstract_c_or_injection() {
    for name in ["char", "int", "long", "return", "_Atomic"] {
        let entry = data(name);
        let encoded = encode_data_type(&entry).unwrap();
        assert_eq!(parse_data_type(&encoded).unwrap(), entry);
    }
    let mut annotations = Annotations::in_memory();
    let entry = DataTypeAnnotation { type_name: Some("char".into()), count: 4, byte_length: 4, encoding: None };
    let encoded = encode_data_type(&entry).unwrap();
    annotations.set(Field::DataType, 0x2000, Some(encoded.clone())).unwrap();
    assert_eq!(annotations.data_types()[&0x2000], encoded);
    for name in ["char *", "char[4]", "char;", "char{}", "char\n", "char\0", "unsigned char", "9char", "chár"] {
        assert!(encode_data_type(&data(name)).is_err(), "{name:?}");
    }
}

#[test]
fn operand_shapes_reject_storage_selectors_duplicates_wrong_kinds_and_invalid_hex() {
    let entry = operand(1, OperandTypeKind::Enum);
    assert!(encode_operand_types(&[]).is_err());
    assert!(encode_operand_types(&vec![entry.clone(); 33]).is_err());
    assert!(encode_operand_types(&[entry.clone(), operand(1, OperandTypeKind::Offset)]).is_err());
    let mut invalid = entry.clone();
    invalid.operand = 32;
    assert!(encode_operand_types(&[invalid]).is_err());
    for hex in ["", "a", "0x90", "zz", "é", "90\n", "９０"] {
        let mut invalid = entry.clone();
        invalid.instruction_hex = hex.into();
        assert!(encode_operand_types(&[invalid]).is_err(), "{hex:?}");
    }
    let mut longest = entry.clone();
    longest.instruction_hex = "ab".repeat(32);
    encode_operand_types(&[longest.clone()]).unwrap();
    longest.instruction_hex.push_str("00");
    assert!(encode_operand_types(&[longest]).is_err());
    for name in ["Entry *", "struct Entry", "return", "é", ""] {
        let mut invalid = entry.clone();
        invalid.type_name = name.into();
        assert!(encode_operand_types(&[invalid]).is_err());
    }
    for (key, value) in [
        ("kind", json!("Enum")),
        ("kind", json!("struct")),
        ("kind", json!({"enum": "Flags"})),
        ("operand", json!(-1)),
        ("operand", json!(256)),
        ("storage", json!({"space": "register", "address": "0x0", "size": 4})),
    ] {
        let mut invalid = serde_json::to_value(&entry).unwrap();
        invalid[key] = value;
        assert!(parse_operand_types(&json!([invalid]).to_string()).is_err());
    }
    assert!(parse_operand_types(&serde_json::to_string(&entry).unwrap()).is_err());
    assert!(parse_operand_types(&encode_data_type(&data("Entry")).unwrap()).is_err());
    assert!(parse_data_type(&encode_operand_types(&[entry]).unwrap()).is_err());
}

#[test]
fn mixed_typed_batch_is_one_undo_step_with_shared_refresh_reopen_and_clear() {
    let log = TypedLog::new();
    let mut first = Annotations::open_for_image(log.0.clone(), Some([0xab; 32])).unwrap();
    let mut second = Annotations::open(log.0.clone()).unwrap();
    let [(data_field, data_value), (operand_field, operand_value)] = typed_values();
    let changes =
        [(data_field, 0x1000, Some(data_value.clone())), (operand_field, 0x2000, Some(operand_value.clone()))];
    assert_eq!(first.set_batch_validated(&changes, |_| Ok(())).unwrap(), [true, true]);
    assert!(second.refresh().unwrap());
    assert_eq!(second.data_types()[&0x1000], data_value);
    assert_eq!(second.operand_types()[&0x2000], operand_value);
    assert_eq!(first.undo().unwrap().len(), 2);
    second.refresh().unwrap();
    assert!(second.data_types().is_empty() && second.operand_types().is_empty());
    first.redo().unwrap();
    let reopened = Annotations::open_checked(log.0.clone()).unwrap();
    assert_eq!(reopened.data_types(), first.data_types());
    assert_eq!(reopened.operand_types(), first.operand_types());
    for (field, address) in [(data_field, 0x1000), (operand_field, 0x2000)] {
        first.set(field, address, None).unwrap();
        assert!(first.field_map(field).is_empty());
        first.undo().unwrap();
        assert!(first.field_map(field).contains_key(&address));
    }
    let bytes = std::fs::read_to_string(&log.0).unwrap();
    assert!(bytes.starts_with(&format!("{{\"image\":\"{}\"}}\n", "ab".repeat(32))));
    assert_eq!(Annotations::open_for_image(log.0.clone(), Some([0xcd; 32])).unwrap().warnings().len(), 1);
    first.refresh().unwrap();
    std::fs::write(&log.0, b"").unwrap();
    first.refresh().unwrap();
    assert!(first.data_types().is_empty() && first.operand_types().is_empty());
}

#[test]
fn typed_history_requires_native_validation_and_preserves_raw_previous_payloads() {
    for (field, canonical) in typed_values() {
        let log = TypedLog::new();
        let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        let raw = serde_json::to_string_pretty(&value).unwrap();
        log.append(&Edit { field, address: 0x10, value: Some(raw.clone()), previous: None });
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(field, 0x10, None).unwrap();
        let before = std::fs::read(&log.0).unwrap();
        let error = annotations
            .undo_validated(|candidate| {
                assert_eq!(candidate.field_map(field)[&0x10], raw);
                Err("native rejects restored dependencies or instruction bytes".into())
            })
            .unwrap_err();
        assert!(error.contains("native rejects"));
        assert!(annotations.field_map(field).is_empty());
        assert_eq!(annotations.done.len(), 1);
        assert!(annotations.undone.is_empty());
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        annotations.undo().unwrap();
        assert_eq!(annotations.field_map(field)[&0x10], raw);
        let before = std::fs::read(&log.0).unwrap();
        assert!(annotations.redo_validated(|_| Err("native rejects clear".into())).is_err());
        assert_eq!(annotations.field_map(field)[&0x10], raw);
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        annotations.redo().unwrap();
        assert!(annotations.field_map(field).is_empty());
    }
}

#[test]
fn shared_typed_replacements_block_undo_without_overwriting_another_client() {
    for (field, value) in typed_values() {
        let log = TypedLog::new();
        let mut first = Annotations::open(log.0.clone()).unwrap();
        first.set(field, 0x10, Some(value)).unwrap();
        let mut second = Annotations::open(log.0.clone()).unwrap();
        second.set(field, 0x10, None).unwrap();
        let before = std::fs::read(&log.0).unwrap();
        assert!(first.undo().unwrap_err().ends_with(DISCARD_HINT));
        assert!(first.field_map(field).is_empty());
        assert_eq!(first.done.len(), 1);
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn shared_data_bindings_require_native_validation_for_name_undo_and_redo() {
    for redo in [false, true] {
        let log = TypedLog::new();
        let mut first = Annotations::open(log.0.clone()).unwrap();
        first.set(Field::Name, 0x2010, Some("data_2000".into())).unwrap();
        first.set(Field::Name, 0x2000, Some("custom".into())).unwrap();
        if redo {
            first.set(Field::Name, 0x2000, None).unwrap();
            first.undo().unwrap();
        }
        let mut second = Annotations::open(log.0.clone()).unwrap();
        let entry = DataTypeAnnotation { type_name: Some("int4".into()), count: 1, byte_length: 4, encoding: None };
        second.set(Field::DataType, 0x2000, Some(encode_data_type(&entry).unwrap())).unwrap();
        let before = std::fs::read(&log.0).unwrap();
        let cursor = first.log.clone();
        let done = first.done.clone();
        let undone = first.undone.clone();
        let revision = first.revision();
        let names_revision = first.names_revision();
        let called = std::cell::Cell::new(false);
        let result = first.locked_staged_history(redo, |staged| {
            let validate = |candidate: &Annotations| {
                called.set(true);
                assert_eq!(candidate.name(0x2000), None);
                assert_eq!(candidate.name(0x2010), Some("data_2000"));
                assert_eq!(parse_data_type(&candidate.data_types()[&0x2000]).unwrap(), entry);
                assert!(candidate.globals().is_empty());
                Err("native typed global fallback label conflicts with another name".to_owned())
            };
            let result = if redo { staged.redo_validated(validate) } else { staged.undo_validated(validate) };
            result.map_err(ApiError::Invalid)
        });
        assert!(called.get(), "name replay must validate shared typed data bindings; redo={redo}");
        assert!(result.unwrap_err().to_string().contains("fallback label conflicts"));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        assert_eq!(first.name(0x2000), Some("custom"));
        assert_eq!(first.name(0x2010), Some("data_2000"));
        assert!(first.data_types().is_empty());
        assert_eq!(first.log, cursor);
        assert_eq!(first.done, done);
        assert_eq!(first.undone, undone);
        assert!(std::sync::Arc::ptr_eq(&revision, &first.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &first.names_revision()));
    }
}

#[test]
fn malformed_typed_shared_values_and_previous_values_do_not_publish_refresh() {
    let bad_data = [
        "[]".to_owned(),
        json!({"type_name": "Entry *", "count": 1, "byte_length": 4}).to_string(),
        json!({"type_name": "Entry", "count": 1, "byte_length": 4, "storage": {}}).to_string(),
    ];
    let bad_operands = [
        "{}".to_owned(),
        json!([{"operand": 0, "kind": "enum", "type_name": "Flags", "instruction_hex": "0g"}]).to_string(),
        serde_json::to_string(&[operand(0, OperandTypeKind::Enum), operand(0, OperandTypeKind::Offset)]).unwrap(),
    ];
    for (field, values) in [(Field::DataType, bad_data), (Field::OperandType, bad_operands)] {
        for value in values {
            for previous_only in [false, true] {
                for checked in [false, true] {
                    let log = TypedLog::new();
                    let mut annotations = if checked {
                        Annotations::open_checked(log.0.clone()).unwrap()
                    } else {
                        Annotations::open(log.0.clone()).unwrap()
                    };
                    annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
                    annotations.refresh().unwrap();
                    let cursor = annotations.log.clone();
                    let revision = annotations.revision();
                    let (value, previous) =
                        if previous_only { (None, Some(value.clone())) } else { (Some(value.clone()), None) };
                    log.append(&Edit { field, address: 0x10, value, previous });
                    let before = std::fs::read(&log.0).unwrap();
                    assert!(annotations.refresh().is_err());
                    assert_eq!(annotations.log, cursor);
                    assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
                    assert_eq!(annotations.comment(1), Some("kept"));
                    assert!(annotations.data_types().is_empty() && annotations.operand_types().is_empty());
                    assert_eq!(annotations.done.len(), 1);
                    assert!(Annotations::open(log.0.clone()).is_err());
                    assert_eq!(std::fs::read(&log.0).unwrap(), before);
                }
            }
        }
    }
}

#[test]
fn typed_targets_and_current_maps_use_checked_staged_history_before_shared_overflow() {
    for (field, value) in typed_values() {
        for redo in [false, true] {
            let log = TypedLog::new();
            let mut annotations = Annotations::open(log.0.clone()).unwrap();
            annotations.set(field, 0x10, Some(value.clone())).unwrap();
            if redo {
                annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
                assert!(annotations.field_map(field).is_empty());
            }
            let cursor = annotations.log.clone();
            let done = annotations.done.clone();
            let undone = annotations.undone.clone();
            let revision = annotations.revision();
            log.append(&Edit {
                field: Field::Comment,
                address: 2,
                value: Some("x".repeat(CHECKED_VALUE_BYTES + 1)),
                previous: None,
            });
            let before = std::fs::read(&log.0).unwrap();
            let result: Result<(), ApiError> = annotations
                .locked_staged_history(redo, |_| panic!("typed history must reject overflow before callback"));
            assert!(result.is_err());
            assert_eq!(annotations.log, cursor);
            assert_eq!(annotations.done, done);
            assert_eq!(annotations.undone, undone);
            assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
            assert_eq!(std::fs::read(&log.0).unwrap(), before);
        }
    }
}

#[test]
fn a_current_typed_map_makes_a_legacy_target_checked_without_scanning_unrelated_steps() {
    for (field, value) in typed_values() {
        let log = TypedLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(field, 0x10, Some(value.clone())).unwrap();
        annotations.set(Field::Comment, 1, Some("latest legacy target".into())).unwrap();
        annotations.refresh().unwrap();
        annotations.checked_reads = false;
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        log.append(&Edit { field: Field::Comment, address: 2, value: Some("shared".into()), previous: None });
        let result: Result<(), ApiError> = annotations.locked_staged_history(false, |staged| {
            assert!(staged.checked_reads);
            assert_eq!(staged.field_map(field)[&0x10], value);
            assert_eq!(staged.comment(2), Some("shared"));
            Err(ApiError::Invalid("checked refusal".into()))
        });
        assert!(result.is_err());
        assert_eq!(annotations.comment(2), None);
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
    }
}

#[test]
fn unexpected_shared_typed_annotations_require_checked_reread_even_after_clear() {
    for (field, value) in typed_values() {
        for clear in [false, true] {
            let log = TypedLog::new();
            let mut annotations = Annotations::open(log.0.clone()).unwrap();
            annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
            annotations.refresh().unwrap();
            let cursor = annotations.log.clone();
            let revision = annotations.revision();
            let edit = Edit { field, address: 0x10, value: Some(value.clone()), previous: None };
            let encoded = serde_json::to_string(&edit).unwrap().replace("\"field\"", "\"\\u0066ield\"");
            let mut file = OpenOptions::new().append(true).open(&log.0).unwrap();
            writeln!(file, "{encoded}").unwrap();
            drop(file);
            if clear {
                log.append(&Edit { field, address: 0x10, value: None, previous: Some(value.clone()) });
            }
            log.append(&Edit { field: Field::Comment, address: 2, value: Some("shared".into()), previous: None });
            let before = std::fs::read(&log.0).unwrap();
            let result: Result<(), ApiError> = annotations.locked_staged_history(false, |staged| {
                assert!(staged.checked_reads);
                assert_eq!(staged.field_map(field).is_empty(), clear);
                assert_eq!(staged.comment(2), Some("shared"));
                Err(ApiError::Invalid("native rejects shared typed references".into()))
            });
            assert!(result.is_err());
            assert_eq!(annotations.log, cursor);
            assert_eq!(annotations.comment(2), None);
            assert!(annotations.field_map(field).is_empty());
            assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
            assert_eq!(std::fs::read(&log.0).unwrap(), before);
        }
    }
}

#[test]
fn typed_maps_and_history_are_preflighted_and_read_snapshots_do_not_create_locks() {
    for (field, value) in typed_values() {
        let log = TypedLog::new();
        log.append(&Edit { field, address: 0x10, value: Some(value.clone()), previous: None });
        let annotations = Annotations::open(log.0.clone()).unwrap();
        let before = annotations.log.clone();
        let snapshot = annotations.checked_read_snapshot().unwrap();
        assert_eq!(snapshot.field_map(field)[&0x10], value);
        assert_eq!(annotations.log, before);
        assert!(!log.lock_path().exists());
        let mut annotations = annotations;
        annotations.comments.insert(1, "x".repeat(CHECKED_VALUE_BYTES + 1));
        assert!(annotations.set(field, 0x20, Some(value.clone())).is_err());
        assert!(!annotations.field_map(field).contains_key(&0x20));
        annotations.comments.clear();
        annotations.done.push(vec![Edit { field, address: 0x10, value: None, previous: Some("[]".into()) }]);
        assert!(annotations.checked_read_snapshot().is_err());
        annotations.done.clear();
        annotations.log = None;
        annotations.comments = (1..CHECKED_RECORDS as u64).map(|address| (address, String::new())).collect();
        annotations.preflight_checked().unwrap();
        annotations.comments.insert(CHECKED_RECORDS as u64, String::new());
        assert!(annotations.preflight_checked().is_err());
    }
    assert!(parse_data_type(&" ".repeat(CHECKED_VALUE_BYTES + 1)).is_err());
    assert!(parse_operand_types(&" ".repeat(CHECKED_VALUE_BYTES + 1)).is_err());
}

#[test]
fn legacy_empty_and_latest_legacy_history_keep_refresh_and_unbounded_history_contracts() {
    let log = TypedLog::new();
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    let value = encode_data_type(&data("Entry")).unwrap();
    log.append(&Edit { field: Field::DataType, address: 0x10, value: Some(value), previous: None });
    annotations
        .locked_staged_history(false, |staged| {
            assert!(staged.data_types().is_empty(), "empty history must not refresh");
            assert!(staged.undo().map_err(ApiError::Invalid)?.is_empty());
            Ok(())
        })
        .unwrap();
    assert_eq!(annotations.log.as_ref().unwrap().read, 0);

    let mut annotations = Annotations::in_memory();
    let old_typed = Edit { field: Field::DataType, address: 0x10, value: None, previous: None };
    annotations.done.resize(CHECKED_HISTORY_STEPS + 1, vec![old_typed]);
    let text = format!("{}\"field\":\"datatype\"", "x".repeat(CHECKED_VALUE_BYTES + 1));
    annotations.set(Field::Comment, 1, Some(text.clone())).unwrap();
    annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(annotations.comment(1), None);
    annotations.locked_staged_history(true, |staged| staged.redo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(annotations.comment(1), Some(text.as_str()));
    assert!(!annotations.checked_reads);
}

fn first_checked_values() -> Vec<(Field, String)> {
    let mut values = typed_values().to_vec();
    values.push((
        Field::TypeLibrary,
        encode_type_library(&[LibraryDeclaration {
            names: vec!["Entry".into()],
            declarations: "typedef unsigned int Entry;".into(),
            packing: None,
            source: None,
        }])
        .unwrap(),
    ));
    values
}

#[test]
fn first_checked_write_refuses_a_malformed_complete_legacy_prefix_without_publishing_or_appending() {
    for (field, value) in first_checked_values() {
        let log = TypedLog::new();
        std::fs::write(&log.0, b"{\"legacy_fragment\":true}\n").unwrap();
        log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
        let mut annotations = Annotations::open_for_image(log.0.clone(), Some([0xab; 32])).unwrap();
        assert_eq!(annotations.comment(1), Some("kept"));
        annotations.set(Field::Comment, 2, Some("earlier history".into())).unwrap();
        annotations.set(Field::Comment, 3, Some("redo history".into())).unwrap();
        annotations.undo().unwrap();
        annotations.refresh().unwrap();
        let before = std::fs::read(&log.0).unwrap();
        let cursor = annotations.log.clone();
        assert_eq!(cursor.as_ref().unwrap().read, before.len() as u64);
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        let revision = annotations.revision();
        let names_revision = annotations.names_revision();
        let warnings = annotations.warnings();
        assert!(annotations.set(field, 0, Some(value.clone())).is_err());
        assert!(
            annotations
                .set_batch_validated(
                    &[(Field::Comment, 1, Some("not published".into())), (field, 0, Some(value))],
                    |_| panic!("malformed prefix must be rejected before native validation"),
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.comment(1), Some("kept"));
        assert_eq!(annotations.comment(2), Some("earlier history"));
        assert_eq!(annotations.comment(3), None);
        assert!(annotations.field_map(field).is_empty());
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert_eq!(annotations.warnings(), warnings);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
        let reopened = Annotations::open(log.0.clone()).unwrap();
        assert_eq!(reopened.comment(1), Some("kept"));
        assert_eq!(reopened.comment(2), Some("earlier history"));
        assert!(reopened.field_map(field).is_empty());
    }
}

#[test]
fn staged_first_checked_write_keeps_unread_shared_refresh_private_on_prefix_refusal() {
    for (field, value) in first_checked_values() {
        let log = TypedLog::new();
        std::fs::write(&log.0, b"{\"legacy_fragment\":true}\n").unwrap();
        log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 2, Some("history".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let done = annotations.done.clone();
        let revision = annotations.revision();
        let names_revision = annotations.names_revision();
        log.append(&Edit { field: Field::Comment, address: 3, value: Some("shared".into()), previous: None });
        let before = std::fs::read(&log.0).unwrap();
        let result = annotations.locked_staged_checked(|staged| {
            assert_eq!(staged.comment(3), Some("shared"));
            staged.set(field, 0, Some(value)).map_err(ApiError::Invalid)
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.comment(3), None);
        assert!(annotations.field_map(field).is_empty());
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert!(!annotations.checked_reads && !annotations.held);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
        let reopened = Annotations::open(log.0.clone()).unwrap();
        assert_eq!(reopened.comment(1), Some("kept"));
        assert_eq!(reopened.comment(3), Some("shared"));
        assert!(reopened.field_map(field).is_empty());
    }
}

#[test]
fn first_checked_write_reads_old_image_headers_and_enforces_the_whole_prefix_budget() {
    for (field, value) in first_checked_values() {
        for prefix in [
            format!("{{\"image\":\"{}\"}}\n{{\"image\":\"{}\"}}\n", "a".repeat(129), "b".repeat(64)),
            "{\"image\":\"legacy\"}\n".repeat(CHECKED_RECORDS + 1),
        ] {
            let log = TypedLog::new();
            std::fs::write(&log.0, &prefix).unwrap();
            log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
            if prefix.lines().count() > CHECKED_RECORDS {
                let before = std::fs::read(&log.0).unwrap();
                assert!(Annotations::open(log.0.clone()).is_err(), "raw record caps now apply before the first read");
                assert_eq!(std::fs::read(&log.0).unwrap(), before);
                continue;
            }
            let mut annotations = Annotations::open(log.0.clone()).unwrap();
            let cursor = annotations.log.clone();
            let revision = annotations.revision();
            let before = std::fs::read(&log.0).unwrap();
            assert!(annotations.set(field, 0, Some(value.clone())).is_err());
            assert_eq!(annotations.log, cursor);
            assert_eq!(annotations.comment(1), Some("kept"));
            assert!(annotations.field_map(field).is_empty());
            assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
            assert_eq!(std::fs::read(&log.0).unwrap(), before);
            assert_eq!(Annotations::open(log.0.clone()).unwrap().comment(1), Some("kept"));
        }
    }
}

#[test]
fn a_valid_legacy_prefix_still_accepts_the_first_checked_write_and_reopens() {
    for (field, value) in first_checked_values() {
        let log = TypedLog::new();
        log.append(&Edit { field: Field::Comment, address: 1, value: Some("kept".into()), previous: None });
        let mut annotations = Annotations::open_for_image(log.0.clone(), Some([0xab; 32])).unwrap();
        assert!(annotations.set(field, 0, Some(value.clone())).unwrap());
        let reopened = Annotations::open_checked(log.0.clone()).unwrap();
        assert_eq!(reopened.comment(1), Some("kept"));
        assert_eq!(reopened.field_map(field)[&0], value);
        assert!(reopened.warnings().is_empty());
    }
}
