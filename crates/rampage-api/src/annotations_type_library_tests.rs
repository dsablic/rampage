use super::*;
use serde_json::json;

struct LibraryLog(PathBuf);

impl LibraryLog {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("rampage-type-library-{}.jsonl", batch_id())))
    }

    fn append(&self, edit: &Edit) {
        let mut file = OpenOptions::new().create(true).append(true).open(&self.0).unwrap();
        serde_json::to_writer(&mut file, edit).unwrap();
        file.write_all(b"\n").unwrap();
    }
}

impl Drop for LibraryLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

fn unit(name: &str, declarations: &str) -> LibraryDeclaration {
    LibraryDeclaration {
        names: vec![name.to_owned()],
        declarations: declarations.to_owned(),
        packing: None,
        source: None,
    }
}

fn library(name: &str) -> String {
    encode_type_library(&[unit(name, &format!("typedef int {name};"))]).unwrap()
}

#[test]
fn canonical_names_do_not_reorder_dependency_units_or_mutate_inputs() {
    let mut base = unit("ZBase", "typedef int ZBase; typedef ZBase *ZPointer;");
    base.names.push("ZPointer".to_owned());
    base.names.reverse();
    base.source = Some(TypeLibrarySource { kind: "bundled_header".into(), identity: "core-posix-v1".into() });
    let dependent = unit("ADependent", "typedef ZPointer ADependent;");
    let entries = vec![base.clone(), dependent.clone()];
    let canonical = encode_type_library(&entries).unwrap();
    assert_eq!(entries[0].names, ["ZPointer", "ZBase"]);
    let parsed = parse_type_library(&canonical).unwrap();
    assert_eq!(parsed[0].names, ["ZBase", "ZPointer"]);
    assert_eq!(parsed[0].declarations, base.declarations);
    assert_eq!(parsed[0].source, base.source);
    assert_eq!(parsed[1], dependent);
    let pretty = serde_json::to_string_pretty(&entries).unwrap();
    let mut annotations = Annotations::in_memory();
    assert!(annotations.set(Field::TypeLibrary, 0, Some(pretty.clone())).unwrap());
    assert!(!annotations.set(Field::TypeLibrary, 0, Some(pretty)).unwrap());
    assert_eq!(annotations.type_library()[&0], canonical);
    let mut reversed = entries;
    reversed.reverse();
    assert_ne!(encode_type_library(&reversed).unwrap(), canonical);
}

#[test]
fn project_key_refusal_is_atomic_even_in_a_mixed_batch_or_clear() {
    let log = LibraryLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
    annotations.refresh().unwrap();
    let before = std::fs::read(&log.0).unwrap();
    let cursor = annotations.log.clone();
    let revision = annotations.revision();
    for value in [Some(library("Entry")), None] {
        assert!(annotations.set(Field::TypeLibrary, 1, value.clone()).is_err());
        assert!(
            annotations
                .set_batch_validated(
                    &[(Field::Comment, 1, Some("not published".into())), (Field::TypeLibrary, 9, value)],
                    |_| panic!("invalid project key must be rejected before validation"),
                )
                .is_err()
        );
        assert_eq!(annotations.comment(1), Some("kept"));
        assert!(annotations.type_library().is_empty());
        assert_eq!(annotations.done.len(), 1);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.log, cursor);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn library_and_legacy_address_types_have_independent_batch_history_and_reopen() {
    let log = LibraryLog::new();
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let names_revision = annotations.names_revision();
    let revision = annotations.revision();
    let value = library("Entry");
    let changes = [
        (Field::TypeLibrary, 0, Some(value.clone())),
        (Field::Types, 0x401000, Some("typedef int Legacy;".to_owned())),
        (Field::Name, 0x401000, Some("Entry".to_owned())),
    ];
    assert_eq!(annotations.set_batch_validated(&changes[..2], |_| Ok(())).unwrap(), [true, true]);
    assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
    assert!(!std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
    assert_eq!(annotations.address_of("Entry"), None);
    annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
    let reopened = Annotations::open_checked(log.0.clone()).unwrap();
    assert_eq!(reopened.type_library().len(), 1);
    assert_eq!(reopened.type_library()[&0], value);
    assert_eq!(reopened.types()[&0x401000], "typedef int Legacy;");
    assert_eq!(reopened.address_of("Entry"), Some(0x401000));
    assert_eq!(annotations.undo().unwrap().len(), 1);
    assert_eq!(annotations.undo().unwrap().len(), 2);
    assert!(annotations.type_library().is_empty());
    assert!(Annotations::open_checked(log.0.clone()).unwrap().type_library().is_empty());
    assert_eq!(annotations.redo().unwrap().len(), 2);
    assert_eq!(annotations.type_library()[&0], value);
    annotations.set(Field::TypeLibrary, 0, None).unwrap();
    annotations.undo().unwrap();
    assert_eq!(annotations.type_library()[&0], value);
}

#[test]
fn library_undo_preserves_noncanonical_shared_text_and_requires_native_validation() {
    let log = LibraryLog::new();
    let raw = serde_json::to_string_pretty(&[unit("Original", "typedef int Original;")]).unwrap();
    log.append(&Edit { field: Field::TypeLibrary, address: 0, value: Some(raw.clone()), previous: None });
    let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
    let replacement = library("Replacement");
    annotations.set(Field::TypeLibrary, 0, Some(replacement.clone())).unwrap();
    let before = std::fs::read(&log.0).unwrap();
    assert_eq!(
        annotations
            .undo_validated(|candidate| {
                assert_eq!(candidate.type_library()[&0], raw);
                Err("native rejects restored dependencies".into())
            })
            .unwrap_err(),
        "native rejects restored dependencies"
    );
    assert_eq!(annotations.type_library()[&0], replacement);
    assert_eq!(annotations.done.len(), 1);
    assert!(annotations.undone.is_empty());
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    annotations.undo().unwrap();
    assert_eq!(annotations.type_library()[&0], raw);
    let before = std::fs::read(&log.0).unwrap();
    assert!(annotations.redo_validated(|_| Err("native rejection".into())).is_err());
    assert_eq!(annotations.type_library()[&0], raw);
    assert_eq!(annotations.undone.len(), 1);
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    annotations.redo().unwrap();
    assert_eq!(annotations.type_library()[&0], replacement);
}

#[test]
fn another_clients_library_replacement_blocks_undo_as_one_project_key() {
    let log = LibraryLog::new();
    let mut first = Annotations::open_checked(log.0.clone()).unwrap();
    first.set(Field::Comment, 1, Some("earlier".into())).unwrap();
    let original = library("Original");
    first.set(Field::TypeLibrary, 0, Some(original.clone())).unwrap();
    let mut other = Annotations::open_checked(log.0.clone()).unwrap();
    let replacement = library("Other");
    other.set(Field::TypeLibrary, 0, Some(replacement.clone())).unwrap();
    for _ in 0..2 {
        assert!(first.undo().unwrap_err().ends_with(DISCARD_HINT));
        assert_eq!(first.type_library()[&0], replacement);
        assert_eq!(first.done.len(), 2);
        assert!(first.undone.is_empty());
    }
    other.set(Field::TypeLibrary, 0, Some(original)).unwrap();
    assert_eq!(first.undo().unwrap().len(), 1);
    assert!(first.type_library().is_empty());
    assert_eq!(first.comment(1), Some("earlier"));
}

#[test]
fn invalid_library_json_and_project_keys_refuse_checked_refresh_without_publishing() {
    let valid = serde_json::to_value([unit("Entry", "typedef int Entry;")]).unwrap();
    let mut duplicate_names = valid.clone();
    duplicate_names[0]["names"] = json!(["Entry", "Entry"]);
    let duplicate_units = json!([valid[0], valid[0]]);
    let mut bad_packing = valid.clone();
    bad_packing[0]["packing"] = json!(3);
    let mut unknown_field = valid.clone();
    unknown_field[0]["unexpected"] = json!(true);
    let deep = format!("{}0{}", "[".repeat(9), "]".repeat(9));
    let duplicate_key = r#"[{"names":["Entry"],"names":["Other"],"declarations":"typedef int Entry;"}]"#;
    for (address, value, previous) in [
        (1, Some(valid.to_string()), None),
        (1, None, None),
        (0, Some("not json".into()), None),
        (0, Some("[]".into()), None),
        (0, Some(duplicate_names.to_string()), None),
        (0, Some(duplicate_units.to_string()), None),
        (0, Some(bad_packing.to_string()), None),
        (0, Some(unknown_field.to_string()), None),
        (0, Some(duplicate_key.into()), None),
        (0, Some(deep), None),
        (0, None, Some("[]".into())),
    ] {
        let log = LibraryLog::new();
        let mut annotations = Annotations::open_checked(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        log.append(&Edit { field: Field::TypeLibrary, address, value, previous });
        let before = std::fs::read(&log.0).unwrap();
        assert!(annotations.refresh().is_err());
        assert_eq!(annotations.log, cursor);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(annotations.type_library().is_empty());
        assert_eq!(annotations.comment(1), Some("kept"));
        assert_eq!(annotations.done.len(), 1);
        assert!(Annotations::open_checked(log.0.clone()).is_err());
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}

#[test]
fn library_names_packing_provenance_and_declaration_budgets_are_checked() {
    for name in ["", "two words", "1entry", "bad\0name", "int", "return", "_Atomic"] {
        assert!(encode_type_library(&[unit(name, "typedef int Entry;")]).is_err(), "{name:?}");
    }
    assert!(encode_type_library(&[unit(&"x".repeat(129), "typedef int Entry;")]).is_err());
    assert!(encode_type_library(&[]).is_err());
    let entries: Vec<_> = (0..256).map(|index| unit(&format!("Type{index}"), "typedef int Entry;")).collect();
    encode_type_library(&entries).unwrap();
    let mut too_many = entries.clone();
    too_many.push(unit("Extra", "typedef int Extra;"));
    assert!(encode_type_library(&too_many).is_err());
    for packing in [None, Some(1), Some(2), Some(4), Some(8), Some(16)] {
        let mut entry = entries[0].clone();
        entry.packing = packing;
        encode_type_library(&[entry]).unwrap();
    }
    for declarations in ["".to_owned(), " \n ".to_owned(), "int\0".to_owned(), "x".repeat(65537)] {
        assert!(encode_type_library(&[unit("Entry", &declarations)]).is_err());
    }
    let at_limit = unit("Entry", &"x".repeat(65536));
    encode_type_library(&[at_limit]).unwrap();
    let large: Vec<_> =
        (0..CHECKED_VALUE_BYTES / 65536 + 1).map(|index| unit(&format!("Type{index}"), &"x".repeat(65536))).collect();
    assert!(encode_type_library(&large).is_err());
    assert!(parse_type_library(&" ".repeat(CHECKED_VALUE_BYTES + 1)).is_err());
    let mut user = entries[0].clone();
    user.source = Some(TypeLibrarySource { kind: "user_header".into(), identity: "supplied-text-v1".into() });
    encode_type_library(&[user.clone()]).unwrap();
    user.source.as_mut().unwrap().identity = "bad\0identity".into();
    assert!(encode_type_library(&[user]).is_err());
}

#[test]
fn library_storage_and_history_participate_in_checked_budgets_and_snapshots() {
    let value = library("Entry");
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::TypeLibrary, 0, Some(value.clone())).unwrap();
    let snapshot = annotations.checked_snapshot().unwrap();
    assert_eq!(snapshot.type_library(), annotations.type_library());
    let mut budget = CheckedBudget::default();
    budget.edit(&annotations.done[0][0]).unwrap();
    assert_eq!(budget.records, 2);
    assert_eq!(budget.bytes, value.len());
    annotations.done.clear();
    annotations.comments = (1..CHECKED_RECORDS as u64).map(|address| (address, String::new())).collect();
    annotations.preflight_checked().unwrap();
    annotations.comments.insert(CHECKED_RECORDS as u64, String::new());
    assert!(annotations.preflight_checked().is_err());
    annotations.comments.clear();
    annotations.type_library.insert(1, value);
    assert!(annotations.checked_snapshot().is_err());
    annotations.type_library.clear();
    annotations.done.push(vec![Edit { field: Field::TypeLibrary, address: 1, value: None, previous: None }]);
    assert!(annotations.checked_snapshot().is_err());
}

#[test]
fn replacing_shared_log_clears_library_and_failed_legacy_refresh_keeps_cursor() {
    let log = LibraryLog::new();
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    annotations.set(Field::TypeLibrary, 0, Some(library("Entry"))).unwrap();
    annotations.refresh().unwrap();
    std::fs::write(&log.0, b"").unwrap();
    assert!(annotations.refresh().unwrap());
    assert!(annotations.type_library().is_empty());
    let mut legacy = Annotations::open(log.0.clone()).unwrap();
    let cursor = legacy.log.clone();
    log.append(&Edit { field: Field::TypeLibrary, address: 9, value: Some(library("Invalid")), previous: None });
    assert!(legacy.refresh().is_err());
    assert_eq!(legacy.log, cursor);
    assert!(legacy.type_library().is_empty());
}

#[test]
fn staged_legacy_history_keeps_oversized_values_and_long_history_undoable() {
    let log = LibraryLog::new();
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    let text = format!("{}\"field\":\"typelibrary\"", "x".repeat(CHECKED_VALUE_BYTES + 1));
    annotations.set(Field::Comment, 1, Some(text.clone())).unwrap();
    let undone = annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(undone.len(), 1);
    assert_eq!(annotations.comment(1), None);
    assert!(!annotations.checked_reads);
    assert_eq!(
        annotations.locked_staged_history(true, |staged| staged.redo().map_err(ApiError::Invalid)).unwrap(),
        undone
    );
    assert_eq!(annotations.comment(1), Some(text.as_str()));
    assert_eq!(Annotations::open(log.0.clone()).unwrap().comment(1), Some(text.as_str()));
    assert!(!annotations.checked_reads);

    let mut annotations = Annotations::in_memory();
    for index in 0..=CHECKED_HISTORY_STEPS {
        annotations.set(Field::Comment, 1, Some(format!("step {index}"))).unwrap();
    }
    annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(annotations.comment(1), Some(format!("step {}", CHECKED_HISTORY_STEPS - 1).as_str()));
    annotations.locked_staged_history(true, |staged| staged.redo().map_err(ApiError::Invalid)).unwrap();
    assert_eq!(annotations.comment(1), Some(format!("step {CHECKED_HISTORY_STEPS}").as_str()));
    assert_eq!(annotations.done.len(), CHECKED_HISTORY_STEPS + 1);
    assert!(!annotations.checked_reads);
}

#[test]
fn staged_library_history_checks_shared_overflow_before_undo_or_empty_library_redo() {
    for redo in [false, true] {
        let log = LibraryLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::TypeLibrary, 0, Some(library("Entry"))).unwrap();
        if redo {
            annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid)).unwrap();
            assert!(annotations.type_library().is_empty());
        }
        assert!(!annotations.checked_reads);
        let cursor = annotations.log.clone();
        let cache = annotations.snapshot();
        let revision = annotations.revision();
        let names_revision = annotations.names_revision();
        let done = annotations.done.clone();
        let undone = annotations.undone.clone();
        log.append(&Edit {
            field: Field::Comment,
            address: 1,
            value: Some("x".repeat(CHECKED_VALUE_BYTES + 1)),
            previous: None,
        });
        let shared = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(redo, |_| {
            panic!("library-target history must reject shared overflow before the callback")
        });
        assert!(result.is_err(), "redo={redo}");
        assert_eq!(annotations.type_library(), cache.type_library());
        assert_eq!(annotations.comments(), cache.comments());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert_eq!(annotations.undone, undone);
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(std::sync::Arc::ptr_eq(&names_revision, &annotations.names_revision()));
        assert!(!annotations.checked_reads);
        assert!(!annotations.held);
        assert_eq!(std::fs::read(&log.0).unwrap(), shared);
    }
}

#[test]
fn unexpected_escaped_shared_library_uses_checked_reread_even_after_shared_clear() {
    for clear in [false, true] {
        let log = LibraryLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("kept".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        let value = library("Shared");
        let edit = Edit { field: Field::TypeLibrary, address: 0, value: Some(value.clone()), previous: None };
        let encoded = serde_json::to_string(&edit)
            .unwrap()
            .replace("\"field\"", "\"\\u0066ield\"")
            .replace("\"typelibrary\"", "\"type\\u006cibrary\"");
        let mut file = OpenOptions::new().append(true).open(&log.0).unwrap();
        writeln!(file, "{encoded}").unwrap();
        drop(file);
        if clear {
            log.append(&Edit { field: Field::TypeLibrary, address: 0, value: None, previous: Some(value) });
        }
        log.append(&Edit {
            field: Field::Comment,
            address: 2,
            value: Some("x".repeat(CHECKED_VALUE_BYTES + 1)),
            previous: None,
        });
        let shared = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations
            .locked_staged_history(false, |_| panic!("unread library edits require checked validation before work"));
        assert!(result.is_err(), "clear={clear}");
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert_eq!(annotations.comment(1), Some("kept"));
        assert_eq!(annotations.comment(2), None);
        assert!(annotations.type_library().is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(!annotations.checked_reads);
        assert_eq!(std::fs::read(&log.0).unwrap(), shared);
    }
}

#[test]
fn legacy_history_refusal_publishes_shared_refresh_and_preserves_history_and_outer_lock() {
    let log = LibraryLog::new();
    let mut annotations = Annotations::open(log.0.clone()).unwrap();
    annotations.set(Field::Comment, 1, Some("original".into())).unwrap();
    annotations.refresh().unwrap();
    let cursor = annotations.log.clone();
    let revision = annotations.revision();
    let done = annotations.done.clone();
    log.append(&Edit { field: Field::Comment, address: 1, value: Some("external".into()), previous: None });
    let before = std::fs::read(&log.0).unwrap();
    let result = annotations.locked_staged_history(false, |staged| staged.undo().map_err(ApiError::Invalid));
    assert!(result.unwrap_err().to_string().ends_with(DISCARD_HINT));
    assert_eq!(annotations.comment(1), Some("external"));
    assert!(annotations.log.as_ref().unwrap().read > cursor.as_ref().unwrap().read);
    assert_eq!(annotations.log.as_ref().unwrap().read, before.len() as u64);
    assert_eq!(annotations.done, done);
    assert!(annotations.undone.is_empty());
    assert!(!std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
    assert!(!annotations.held);
    assert_eq!(std::fs::read(&log.0).unwrap(), before);

    annotations
        .locked(|outer| {
            assert!(outer.held);
            log.append(&Edit { field: Field::Comment, address: 2, value: Some("also shared".into()), previous: None });
            let result: Result<(), ApiError> = outer.locked_staged_history(false, |staged| {
                assert!(staged.held);
                assert_eq!(staged.comment(2), Some("also shared"));
                Err(ApiError::Invalid("refused".into()))
            });
            assert!(result.is_err());
            assert!(outer.held);
            assert_eq!(outer.comment(2), Some("also shared"));
            assert_eq!(outer.done, done);
            assert!(outer.undone.is_empty());
            outer.locked_staged_history(false, |staged| {
                assert!(staged.held);
                Ok(())
            })?;
            assert!(outer.held);
            Ok(())
        })
        .unwrap();
    assert!(!annotations.held);
}

#[test]
fn unexpected_shared_library_keeps_callback_refusal_atomic_even_after_shared_clear() {
    for clear in [false, true] {
        let log = LibraryLog::new();
        let mut annotations = Annotations::open(log.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("original".into())).unwrap();
        annotations.refresh().unwrap();
        let cursor = annotations.log.clone();
        let revision = annotations.revision();
        let done = annotations.done.clone();
        let value = library("Shared");
        log.append(&Edit { field: Field::TypeLibrary, address: 0, value: Some(value.clone()), previous: None });
        if clear {
            log.append(&Edit { field: Field::TypeLibrary, address: 0, value: None, previous: Some(value) });
        }
        log.append(&Edit { field: Field::Comment, address: 2, value: Some("external".into()), previous: None });
        let before = std::fs::read(&log.0).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged_history(false, |staged| {
            assert!(staged.checked_reads);
            assert_eq!(staged.comment(2), Some("external"));
            assert_eq!(staged.type_library().is_empty(), clear);
            Err(ApiError::Invalid("refused".into()))
        });
        assert!(result.is_err());
        assert_eq!(annotations.comment(2), None);
        assert!(annotations.type_library().is_empty());
        assert_eq!(annotations.log, cursor);
        assert_eq!(annotations.done, done);
        assert!(annotations.undone.is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
        assert!(!annotations.held);
        assert_eq!(std::fs::read(&log.0).unwrap(), before);
    }
}
