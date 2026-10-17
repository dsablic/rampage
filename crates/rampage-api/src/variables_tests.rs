use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decompiler::results::{StorageKind, Variable};
use rampage_decompiler::worker::WorkerConfig;
use rampage_loaders::Binary;

use super::*;
use crate::{DecompileEntryRequest, EntryValidation};

const ENTRY: u64 = 0x4000ae;

fn binary() -> Binary {
    Binary::from_snapshot_bytes(include_bytes!("../../../tests/data/local-variables-x64.snapshot.json").to_vec())
        .unwrap()
}

fn new_project(annotations: Annotations, worker: Option<WorkerConfig>) -> Project {
    let project = Project::with_annotations(binary(), annotations);
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("gcc".to_owned()),
        ..Default::default()
    }));
    project.set_decompiler_worker(worker);
    project
}

fn stack_pointer(decompilation: &Decompilation) -> &VariableDescriptor {
    decompilation
        .variables
        .iter()
        .find(|variable| {
            variable.editable
                && variable.kind == VariableKind::Local
                && variable
                    .storage
                    .as_ref()
                    .is_some_and(|storage| storage.kind == StorageKind::Spacebase && storage.size == 8)
        })
        .expect("owned source barrier keeps the pointer local in one complete stack mapping")
}

fn storage(address: u64) -> VariableStorage {
    VariableStorage {
        kind: StorageKind::Spacebase,
        space: "stack".to_owned(),
        address,
        size: 8,
        use_ranges: Vec::new(),
    }
}

fn variable(name: &str, selector: VariableStorage) -> Variable {
    Variable {
        name: name.to_owned(),
        data_type: TypeInfo { name: "undefined8".to_owned(), size: 8 },
        kind: VariableKind::Local,
        storage: vec![rampage_decompiler::results::Storage {
            kind: selector.kind,
            space: Some(selector.space),
            address: Some(selector.address),
            address_size_bytes: Some(8),
            size: selector.size,
            use_ranges: Some(selector.use_ranges),
            dynamic_hash: None,
            symbol_offset: Some(0),
            is_piece: Some(false),
            join_logical_size: None,
            pieces: Vec::new(),
        }],
    }
}

#[test]
fn selectors_refuse_ambiguous_names_duplicate_storage_and_partial_mappings() {
    let first = storage(0xffff_ffff_ffff_fff0);
    let second = storage(0xffff_ffff_ffff_ffe0);
    let mut structure = StructuredResult::empty();
    structure.variables = vec![variable("same", first.clone()), variable("same", second.clone())];
    let by_name = VariableEditRequest { variable: Some("same".to_owned()), clear_name: true, ..Default::default() };
    let descriptors = descriptors(&structure);
    assert!(resolve(&descriptors, &by_name).is_err());
    let by_storage = VariableEditRequest { storage: Some(first.clone()), clear_name: true, ..Default::default() };
    assert_eq!(resolve(&descriptors, &by_storage).unwrap(), &first);
    structure.variables[1] = variable("other", first.clone());
    assert!(resolve(&super::descriptors(&structure), &by_storage).is_err());
    structure.variables.truncate(1);
    structure.variables[0].storage.push(variable("unused", second).storage.remove(0));
    let unsupported = super::descriptors(&structure);
    assert!(!unsupported[0].editable);
    assert!(unsupported[0].key.is_none());
    assert!(resolve(&unsupported, &by_storage).is_err());
}

#[test]
fn request_requires_one_selector_and_unambiguous_field_operations() {
    for request in [
        VariableEditRequest { name: Some("state".to_owned()), ..Default::default() },
        VariableEditRequest {
            variable: Some("old".to_owned()),
            storage: Some(storage(0x10)),
            clear_name: true,
            ..Default::default()
        },
        VariableEditRequest {
            variable: Some("old".to_owned()),
            name: Some("state".to_owned()),
            clear_name: true,
            ..Default::default()
        },
        VariableEditRequest {
            variable: Some("old".to_owned()),
            data_type: Some("int4; int4 injected".to_owned()),
            ..Default::default()
        },
    ] {
        assert!(validate_request(&request).is_err(), "{request:?}");
    }
}

struct LogFixture(PathBuf);

impl LogFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-local-api-{}-{index}.jsonl", std::process::id())))
    }

    fn annotations(&self) -> Annotations {
        Annotations::open_checked(self.0.clone()).unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap_or_default()
    }
}

impl Drop for LogFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

fn edit_and_replay(worker: Option<WorkerConfig>) {
    let log = LogFixture::new();
    let project = new_project(log.annotations(), worker.clone());
    project.set_types(ENTRY, Some("struct phaseState { int4 gain; int4 bias; }; ")).unwrap();
    let before = project.decompile(ENTRY).unwrap();
    let original = stack_pointer(&before);
    let selector = original.storage.clone().unwrap();
    let key = original.key.clone();
    let result = project
        .edit_variable(
            ENTRY + 1,
            &VariableEditRequest {
                variable: Some(original.name.clone()),
                name: Some("state".to_owned()),
                data_type: Some("struct phaseState *".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(result.address, ENTRY);
    assert_eq!(result.edits.len(), 2);
    assert!(result.edits.iter().all(|edit| edit.changed));
    assert_eq!(result.storage, selector);
    assert!(result.decompilation.code.contains("state->gain"), "{}", result.decompilation.code);
    assert!(result.decompilation.code.contains("state->bias"), "{}", result.decompilation.code);
    assert_eq!(stack_pointer(&result.decompilation).key, key);
    assert_eq!(project.decompile(ENTRY).unwrap().code, result.decompilation.code);
    let accepted_log = log.bytes();
    assert!(project.set_types(ENTRY, None).is_err());
    assert_eq!(log.bytes(), accepted_log);
    assert_eq!(project.decompile(ENTRY).unwrap().code, result.decompilation.code);
    let reloaded = new_project(log.annotations(), worker.clone());
    assert_eq!(reloaded.decompile(ENTRY).unwrap().code, result.decompilation.code);
    let exact = reloaded
        .decompile_entry(&DecompileEntryRequest { address: ENTRY, validation: EntryValidation::AnalystAsserted })
        .unwrap();
    assert!(exact.decompilation.code.contains("state->gain"), "{}", exact.decompilation.code);
    assert_eq!(project.undo().unwrap().len(), 2);
    assert_eq!(project.decompile(ENTRY).unwrap().code, before.code);
    assert_eq!(project.redo().unwrap().len(), 2);
    assert_eq!(project.decompile(ENTRY).unwrap().code, result.decompilation.code);
    let clear = project
        .edit_variable(
            ENTRY,
            &VariableEditRequest { storage: Some(selector.clone()), clear_type: true, ..Default::default() },
        )
        .unwrap();
    assert_eq!(stack_pointer(&clear.decompilation).name, "state");
    assert!(project.annotations().local_types().is_empty());
    assert!(!clear.decompilation.code.contains("state->gain"));
    assert_eq!(project.undo().unwrap().len(), 1);
    let clear = project
        .edit_variable(ENTRY, &VariableEditRequest { storage: Some(selector), clear_name: true, ..Default::default() })
        .unwrap();
    assert_ne!(stack_pointer(&clear.decompilation).name, "state");
    assert!(project.annotations().local_names().is_empty());
    assert!(clear.decompilation.code.contains("->gain"));
    assert_eq!(project.undo().unwrap().len(), 1);
    assert_eq!(project.decompile(ENTRY).unwrap().code, result.decompilation.code);
}

#[test]
fn native_variable_edits_refresh_clear_undo_redo_reload_and_exact_entry() {
    edit_and_replay(None);
}

#[test]
fn supervised_variable_edits_refresh_clear_undo_redo_reload_and_exact_entry() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    edit_and_replay(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
}

#[test]
fn sequential_renames_reuse_vacated_names_and_replay_with_final_batch_names() {
    let mut workers = vec![None];
    if let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") {
        workers.push(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
    }
    for worker in workers {
        let log = LogFixture::new();
        let project = new_project(log.annotations(), worker.clone());
        let before = project.decompile(ENTRY).unwrap();
        let parameters: Vec<_> =
            before.variables.iter().filter(|variable| variable.kind == VariableKind::Parameter).collect();
        assert_eq!(parameters.len(), 2);
        let first = parameters.iter().find(|variable| variable.data_type.size == 8).unwrap();
        let second = parameters.iter().find(|variable| variable.data_type.size == 4).unwrap();
        project
            .edit_variable(
                ENTRY,
                &VariableEditRequest {
                    variable: Some(second.name.clone()),
                    name: Some("sample".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let result = project
            .edit_variable(
                ENTRY,
                &VariableEditRequest {
                    variable: Some(first.name.clone()),
                    name: Some(second.name.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        for (name, storage) in [(second.name.as_str(), &first.storage), ("sample", &second.storage)] {
            assert!(
                result
                    .decompilation
                    .variables
                    .iter()
                    .any(|variable| { variable.name == name && &variable.storage == storage })
            );
        }
        let reloaded = new_project(log.annotations(), worker);
        assert_eq!(reloaded.decompile(ENTRY).unwrap().code, result.decompilation.code);
        let accepted = log.bytes();
        assert!(
            project
                .edit_variable(
                    ENTRY,
                    &VariableEditRequest {
                        variable: Some("sample".into()),
                        name: Some(second.name.clone()),
                        ..Default::default()
                    }
                )
                .is_err()
        );
        assert_eq!(log.bytes(), accepted);
        project.undo().unwrap();
        project.redo().unwrap();
        assert_eq!(project.decompile(ENTRY).unwrap().code, result.decompilation.code);
    }
}

#[test]
fn rejected_native_type_name_selector_and_response_budget_leave_the_log_and_result_unchanged() {
    let log = LogFixture::new();
    let project = new_project(log.annotations(), None);
    let before = project.decompile(ENTRY).unwrap();
    let selector = stack_pointer(&before).storage.clone().unwrap();
    let initial_log = log.bytes();
    for request in [
        VariableEditRequest {
            storage: Some(selector.clone()),
            name: Some("renamed".to_owned()),
            data_type: Some("NoSuchPhaseType *".to_owned()),
            ..Default::default()
        },
        VariableEditRequest {
            storage: Some(selector.clone()),
            name: Some("not-an-identifier".to_owned()),
            ..Default::default()
        },
        VariableEditRequest {
            storage: Some(storage(0xffff_ffff_ffff_ffd0)),
            name: Some("missing".to_owned()),
            ..Default::default()
        },
    ] {
        assert!(project.edit_variable(ENTRY, &request).is_err());
        assert_eq!(log.bytes(), initial_log);
        assert!(project.annotations().local_names().is_empty());
        assert!(project.annotations().local_types().is_empty());
        assert_eq!(project.decompile(ENTRY).unwrap().code, before.code);
    }
    let rejected = project.edit_variable_with_preflight(
        ENTRY,
        &VariableEditRequest {
            storage: Some(selector.clone()),
            name: Some("renamed".to_owned()),
            ..Default::default()
        },
        |refreshed| {
            assert_eq!(refreshed.address, ENTRY);
            assert_eq!(refreshed.storage, selector);
            assert!(refreshed.decompilation.code.contains("renamed"));
            let [edit] = refreshed.edits.as_slice() else { panic!("one prospective name edit") };
            assert_eq!(edit.field, Field::LocalName);
            assert_eq!(edit.address, ENTRY);
            assert!(edit.changed);
            let entries = parse_local_names(edit.value.as_deref().unwrap()).unwrap();
            assert_eq!(entries[0].storage, selector);
            assert_eq!(entries[0].name, "renamed");
            let envelope = serde_json::to_value(refreshed).unwrap();
            assert!(envelope["edits"][0]["value"].as_str().unwrap().contains("renamed"));
            assert_eq!(envelope["storage"]["space"], "stack");
            Err(ApiError::Invalid("response budget".to_owned()))
        },
    );
    assert!(rejected.unwrap_err().to_string().contains("response budget"));
    assert_eq!(log.bytes(), initial_log);
    assert!(project.undo().unwrap().is_empty());
    assert_eq!(project.decompile(ENTRY).unwrap().code, before.code);
}

#[test]
fn unchanged_variable_edit_preflights_the_complete_envelope_without_writing() {
    let log = LogFixture::new();
    let project = new_project(log.annotations(), None);
    let current = project.decompile(ENTRY).unwrap();
    let selector = stack_pointer(&current).storage.clone().unwrap();
    let request =
        VariableEditRequest { storage: Some(selector.clone()), name: Some("state".to_owned()), ..Default::default() };
    let accepted = project.edit_variable(ENTRY, &request).unwrap();
    let before_log = log.bytes();
    let rejected = project.edit_variable_with_preflight(ENTRY, &request, |result| {
        assert_eq!(result.storage, selector);
        assert_eq!(result.decompilation.code, accepted.decompilation.code);
        assert_eq!(result.edits.len(), 1);
        assert!(!result.edits[0].changed);
        assert_eq!(result.edits[0].value, accepted.edits[0].value);
        Err(ApiError::Invalid("unchanged response budget".to_owned()))
    });
    assert!(rejected.unwrap_err().to_string().contains("unchanged response budget"));
    assert_eq!(log.bytes(), before_log);
    assert_eq!(project.decompile(ENTRY).unwrap().code, accepted.decompilation.code);
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn candidate_validation_decompiles_stored_local_selectors_instead_of_only_registering_them() {
    let project = new_project(Annotations::in_memory(), None);
    let mut annotations = Annotations::in_memory();
    annotations
        .set(
            Field::LocalName,
            ENTRY,
            Some(
                encode_local_names(&[LocalNameAnnotation {
                    storage: storage(0xffff_ffff_ffff_ffd0),
                    name: "missing".to_owned(),
                }])
                .unwrap(),
            ),
        )
        .unwrap();
    let state = project.decompiler.lock().unwrap();
    let options = state.options.clone().unwrap();
    assert!(project.validate_annotation_snapshot(&state, &options, &annotations).is_err());
}
