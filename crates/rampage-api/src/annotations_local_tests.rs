use super::*;
use rampage_decompiler::results::{StorageKind, StorageUseRange};
use serde_json::json;

struct LocalLog(PathBuf);

impl LocalLog {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("rampage-local-annotations-{}.jsonl", batch_id())))
    }
}

impl Drop for LocalLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

fn storage(address: u64) -> VariableStorage {
    VariableStorage {
        kind: StorageKind::Processor,
        space: "register".to_owned(),
        address,
        size: 8,
        use_ranges: vec![StorageUseRange { space: "ram".to_owned(), start: 0x401000, end: 0x401020 }],
    }
}

fn named(address: u64, name: &str) -> LocalNameAnnotation {
    LocalNameAnnotation { storage: storage(address), name: name.to_owned() }
}

fn typed(address: u64, data_type: &str) -> LocalTypeAnnotation {
    LocalTypeAnnotation { storage: storage(address), data_type: data_type.to_owned() }
}

#[test]
fn local_collection_wire_identity_is_storage_and_hex_numbers_are_canonicalized() {
    let input = json!([{
        "storage": {
            "kind": "processor", "space": "register", "address": 32, "size": "0x8",
            "use_ranges": [{"space": "ram", "start": 4198400, "end": "0x401020"}]
        },
        "name": "state"
    }]);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::LocalName, 0x401000, Some(input.to_string())).unwrap();
    assert_eq!(
        annotations.local_names()[&0x401000],
        concat!(
            "[{\"storage\":{\"kind\":\"processor\",\"space\":\"register\",\"address\":\"0x20\",",
            "\"size\":8,\"use_ranges\":[{\"space\":\"ram\",\"start\":\"0x401000\",\"end\":\"0x401020\"}]},",
            "\"name\":\"state\"}]"
        )
    );
    let mut entries = vec![named(0x20, "state"), named(0x10, "count")];
    let canonical = encode_local_names(&entries).unwrap();
    entries.reverse();
    assert_eq!(canonical, encode_local_names(&entries).unwrap());
    let pretty = serde_json::to_string_pretty(&entries).unwrap();
    assert!(annotations.set(Field::LocalName, 0x401000, Some(pretty.clone())).unwrap());
    assert!(!annotations.set(Field::LocalName, 0x401000, Some(pretty)).unwrap());
    assert_eq!(annotations.local_names()[&0x401000], canonical);
    let types = encode_local_types(&[typed(0x20, "struct PhaseState *")]).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&types).unwrap()[0]["data_type"], "struct PhaseState *");
}

#[test]
fn local_undo_restores_the_exact_noncanonical_shared_log_value() {
    let log = LocalLog::new();
    let raw = serde_json::to_string_pretty(&vec![named(0x20, "original")]).unwrap();
    let edit = Edit { field: Field::LocalName, address: 0x401000, value: Some(raw.clone()), previous: None };
    let mut file = File::create(&log.0).unwrap();
    serde_json::to_writer(&mut file, &edit).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let replacement = encode_local_names(&[named(0x20, "replacement")]).unwrap();
    annotations.set(Field::LocalName, 0x401000, Some(replacement.clone())).unwrap();
    assert_eq!(annotations.undo().unwrap()[0].previous, Some(raw.clone()));
    assert_eq!(annotations.local_names()[&0x401000], raw);
    annotations.redo().unwrap();
    assert_eq!(annotations.local_names()[&0x401000], replacement);
}

#[test]
fn replacing_names_for_the_same_storage_preserves_exact_undo_and_redo() {
    let mut annotations = Annotations::in_memory();
    let first = encode_local_names(&[named(0x20, "first")]).unwrap();
    let second = encode_local_names(&[named(0x20, "second")]).unwrap();
    annotations.set(Field::LocalName, 0x401000, Some(first.clone())).unwrap();
    let names_revision = annotations.names_revision();
    let revision = annotations.revision();
    annotations.set(Field::LocalName, 0x401000, Some(second.clone())).unwrap();
    assert!(!std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
    assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
    assert_eq!(annotations.address_of("second"), None);
    let edits = annotations.undo().unwrap();
    assert_eq!(edits[0].previous, Some(first.clone()));
    assert_eq!(edits[0].value, Some(second.clone()));
    assert_eq!(annotations.local_names()[&0x401000], first);
    annotations.redo().unwrap();
    assert_eq!(annotations.local_names()[&0x401000], second);
    annotations.set(Field::LocalName, 0x401000, None).unwrap();
    assert!(annotations.local_names().is_empty());
    annotations.undo().unwrap();
    assert_eq!(annotations.local_names()[&0x401000], second);
}

#[test]
fn reused_physical_storage_keeps_distinct_use_range_selectors() {
    let mut entries = vec![named(0x20, "early"), named(0x20, "late")];
    entries[1].storage.use_ranges[0].start = 0x401030;
    entries[1].storage.use_ranges[0].end = 0x401040;
    let original = encode_local_names(&entries).unwrap();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::LocalName, 0x401000, Some(original.clone())).unwrap();
    entries[1].name = "later_state".to_owned();
    let replacement = encode_local_names(&entries).unwrap();
    annotations.set(Field::LocalName, 0x401000, Some(replacement)).unwrap();
    let parsed = parse_local_names(&annotations.local_names()[&0x401000]).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed.iter().any(|entry| entry.name == "early" && entry.storage == entries[0].storage));
    assert!(parsed.iter().any(|entry| entry.name == "later_state" && entry.storage == entries[1].storage));
    annotations.undo().unwrap();
    assert_eq!(annotations.local_names()[&0x401000], original);
}

#[test]
fn local_fields_share_batch_history_image_identity_and_log_reopen() {
    let log = LocalLog::new();
    let mut annotations = Annotations::open_for_image_checked(log.0.clone(), Some([1; 32])).unwrap();
    let names = encode_local_names(&[named(0x20, "state")]).unwrap();
    let types = encode_local_types(&[typed(0x20, "struct PhaseState *")]).unwrap();
    annotations
        .set_batch_validated(
            &[(Field::LocalName, 0x401000, Some(names.clone())), (Field::LocalType, 0x401000, Some(types.clone()))],
            |_| Ok(()),
        )
        .unwrap();
    let reopened = Annotations::open_for_image_checked(log.0.clone(), Some([2; 32])).unwrap();
    assert_eq!(reopened.local_names()[&0x401000], names);
    assert_eq!(reopened.local_types()[&0x401000], types);
    assert_eq!(reopened.warnings().len(), 1);
    assert_eq!(annotations.undo().unwrap().len(), 2);
    let reopened = Annotations::open_checked(log.0.clone()).unwrap();
    assert!(reopened.local_names().is_empty() && reopened.local_types().is_empty());
    assert_eq!(annotations.redo().unwrap().len(), 2);
}

#[test]
fn another_clients_local_edit_blocks_undo_without_discarding_history() {
    let log = LocalLog::new();
    let mut first = Annotations::open_checked(log.0.clone()).unwrap();
    first.set(Field::Comment, 1, Some("earlier".to_owned())).unwrap();
    let original = encode_local_names(&[named(0x20, "first")]).unwrap();
    first.set(Field::LocalName, 0x401000, Some(original.clone())).unwrap();
    let mut other = Annotations::open_checked(log.0.clone()).unwrap();
    let replacement = encode_local_names(&[named(0x20, "other")]).unwrap();
    other.set(Field::LocalName, 0x401000, Some(replacement.clone())).unwrap();
    for _ in 0..2 {
        assert!(first.undo().unwrap_err().ends_with(DISCARD_HINT));
        assert_eq!(first.done.len(), 2);
        assert!(first.undone.is_empty());
        assert_eq!(first.local_names()[&0x401000], replacement);
    }
    other.set(Field::LocalName, 0x401000, Some(original)).unwrap();
    assert_eq!(first.undo().unwrap().len(), 1);
    assert!(first.local_names().is_empty());
    assert_eq!(first.comment(1), Some("earlier"));
}

#[test]
fn native_validation_failure_during_local_replay_preserves_state_log_and_history() {
    let log = LocalLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let unsupported = encode_local_types(&[typed(0x20, "struct NotAvailable *")]).unwrap();
    annotations.set(Field::LocalType, 0x401000, Some(unsupported.clone())).unwrap();
    annotations.set(Field::LocalType, 0x401000, None).unwrap();
    let before = std::fs::read(&log.0).unwrap();
    assert_eq!(
        annotations
            .undo_validated(|candidate| {
                assert_eq!(candidate.local_types()[&0x401000], unsupported);
                Err("unsupported native type".to_owned())
            })
            .unwrap_err(),
        "unsupported native type"
    );
    assert!(annotations.local_types().is_empty());
    assert_eq!(annotations.done.len(), 2);
    assert!(annotations.undone.is_empty());
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    annotations.undo().unwrap();
    let before = std::fs::read(&log.0).unwrap();
    assert!(annotations.redo_validated(|_| Err("native rejection".to_owned())).is_err());
    assert_eq!(annotations.local_types()[&0x401000], unsupported);
    assert_eq!(annotations.undone.len(), 1);
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
}

#[test]
fn checked_log_refresh_rejects_malformed_duplicate_and_incomplete_selectors_atomically() {
    let valid = serde_json::to_value(vec![named(0x20, "state")]).unwrap();
    let mut missing_ranges = valid.clone();
    missing_ranges[0]["storage"].as_object_mut().unwrap().remove("use_ranges");
    let mut missing_size = valid.clone();
    missing_size[0]["storage"].as_object_mut().unwrap().remove("size");
    let mut invalid_kind = valid.clone();
    invalid_kind[0]["storage"]["kind"] = json!("dynamic");
    let mut zero_size = valid.clone();
    zero_size[0]["storage"]["size"] = json!(0);
    let mut bad_ranges = valid.clone();
    bad_ranges[0]["storage"]["use_ranges"][0]["end"] = json!(0);
    let mut alias = valid[0].clone();
    alias["storage"]["address"] = json!(32);
    alias["name"] = json!("different_label");
    let duplicate = json!([valid[0], alias]);
    for value in [
        "not json".to_owned(),
        "[]".to_owned(),
        missing_ranges.to_string(),
        missing_size.to_string(),
        invalid_kind.to_string(),
        zero_size.to_string(),
        bad_ranges.to_string(),
        duplicate.to_string(),
    ] {
        let log = LocalLog::new();
        let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".to_owned())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.as_ref().unwrap().read;
        let revision = annotations.revision();
        let edit = Edit { field: Field::LocalName, address: 0x401000, value: Some(value), previous: None };
        let mut file = OpenOptions::new().append(true).open(&log.0).unwrap();
        serde_json::to_writer(&mut file, &edit).unwrap();
        file.write_all(b"\n").unwrap();
        assert!(annotations.refresh().is_err());
        assert_eq!(annotations.log.as_ref().unwrap().read, cursor);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.local_names().is_empty());
        assert!(Annotations::open_checked(log.0.clone()).is_err());
    }
}

#[test]
fn local_labels_conflict_by_function_but_same_storage_can_have_a_name_and_type() {
    assert!(encode_local_names(&[named(0x20, "state"), named(0x30, "state")]).is_err());
    for name in ["", "two words", "1state", "bad\0name", "bad\nname", "int", "return", "_Atomic"] {
        assert!(encode_local_names(&[named(0x20, name)]).is_err());
    }
    for declaration in ["", "  ", "int\0", "int\n"] {
        assert!(encode_local_types(&[typed(0x20, declaration)]).is_err());
    }
    let mut annotations = Annotations::in_memory();
    let names = encode_local_names(&[named(0x20, "state")]).unwrap();
    for function in [0x401000, 0x402000] {
        annotations.set(Field::LocalName, function, Some(names.clone())).unwrap();
    }
    let types = encode_local_types(&[typed(0x20, "struct PhaseState *")]).unwrap();
    annotations.set(Field::LocalType, 0x401000, Some(types)).unwrap();
    annotations.set(Field::Name, 0x401000, Some("renamed_function".to_owned())).unwrap();
    assert_eq!(annotations.local_names()[&0x401000], names);
    assert_eq!(annotations.local_names()[&0x402000], names);
    assert_eq!(annotations.address_of("state"), None);
}

#[test]
fn checked_logs_validate_previous_local_values_and_type_collections() {
    for (field, value, previous) in [
        (Field::LocalName, None, Some("[]".to_owned())),
        (Field::LocalType, Some(json!([{"storage": storage(0x20), "data_type": "  "}]).to_string()), None),
        (Field::LocalType, Some(json!([{"storage": storage(0x20), "data_type": "int\0"}]).to_string()), None),
    ] {
        let log = LocalLog::new();
        let edit = Edit { field, address: 0x401000, value, previous };
        let mut file = File::create(&log.0).unwrap();
        serde_json::to_writer(&mut file, &edit).unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);
        assert!(Annotations::open_checked(log.0.clone()).is_err());
    }
}

#[test]
fn replacing_a_shared_log_clears_both_local_maps() {
    let log = LocalLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    annotations.set(Field::LocalName, 0x401000, Some(encode_local_names(&[named(0x20, "state")]).unwrap())).unwrap();
    annotations.set(Field::LocalType, 0x401000, Some(encode_local_types(&[typed(0x20, "int")]).unwrap())).unwrap();
    annotations.refresh().unwrap();
    std::fs::write(&log.0, b"").unwrap();
    assert!(annotations.refresh().unwrap());
    assert!(annotations.local_names().is_empty() && annotations.local_types().is_empty());
}

#[test]
fn combined_local_selector_limit_rejects_a_batch_without_publishing_partial_edits() {
    let mut annotations = Annotations::in_memory();
    let names: Vec<_> = (0..256).map(|index| named(index * 8, &format!("local_{index}"))).collect();
    let names = encode_local_names(&names).unwrap();
    let types = encode_local_types(&[typed(0x2000, "int")]).unwrap();
    assert!(
        annotations
            .set_batch_validated(
                &[(Field::LocalName, 0x401000, Some(names)), (Field::LocalType, 0x401000, Some(types))],
                |_| Ok(()),
            )
            .is_err()
    );
    assert!(annotations.local_names().is_empty() && annotations.local_types().is_empty());
    assert!(annotations.done.is_empty());
}
