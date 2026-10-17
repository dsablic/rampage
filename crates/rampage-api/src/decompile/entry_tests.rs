use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::annotations::{
    Annotations, DerivedTypeHint, Field, LocalTypeAnnotation, TypeHintAnnotation, TypeHintTarget, encode_local_types,
    encode_type_hints,
};
use rampage_loaders::Binary;

fn project() -> Project {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    Project::new(Binary::open(path).unwrap())
}

fn request(project: &Project) -> DecompileEntryRequest {
    DecompileEntryRequest { address: project.resolve("main").unwrap(), validation: EntryValidation::MetadataBacked }
}

fn assert_no_discovery(project: &Project) {
    assert!(project.cached_analysis().is_none());
    assert!(project.go_prototypes.get().is_none());
}

#[test]
fn exact_entry_preserves_import_arguments_strings_and_return_without_discovery_or_live_engine_publication() {
    let project = project();
    let before = serde_json::to_value(project.annotation_list()).unwrap();
    assert_no_discovery(&project);
    let result = project.decompile_entry(&request(&project)).unwrap();
    assert_no_discovery(&project);
    assert!(
        result.decompilation.code.contains("puts@plt(\"rampage fixture greeting\")"),
        "{}",
        result.decompilation.code
    );
    assert!(result.decompilation.code.contains("return 5;"), "{}", result.decompilation.code);
    assert_eq!(result.context.scope, "exact_entry");
    assert!(result.context.full_image_mapping && result.context.mapped_backing_checked);
    assert!(result.context.mapped_regions > 1 && result.context.mapped_backed_bytes > 0);
    assert!(result.context.origins.contains(&DecompileEntryOrigin::FunctionSymbol));
    assert!(!result.context.omissions.is_empty());
    assert!(project.decompiler.lock().unwrap().engine.is_none());
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn exact_context_does_not_depend_on_earlier_discovery_legacy_engine_or_another_entry() {
    let project = project();
    let request = request(&project);
    let fresh = project.decompile_entry(&request).unwrap();
    project.functions(&crate::FunctionsQuery::default()).unwrap();
    let legacy = project.decompile(request.address).unwrap();
    let other = project.binary.entry.expect("owned ELF fixture entry");
    assert_ne!(other, request.address, "the order regression must exercise a different entry");
    project
        .decompile_entry(&DecompileEntryRequest { address: other, validation: EntryValidation::MetadataBacked })
        .unwrap();
    let after = project.decompile_entry(&request).unwrap();
    assert_eq!(fresh.decompilation.code, after.decompilation.code);
    assert_eq!(fresh.decompilation.structure, after.decompilation.structure);
    assert_eq!(fresh.decompilation.language_id, legacy.language_id);
    let mut first = serde_json::to_value(fresh.context).unwrap();
    let mut last = serde_json::to_value(after.context).unwrap();
    first.as_object_mut().unwrap().remove("timings");
    last.as_object_mut().unwrap().remove("timings");
    assert_eq!(first, last);
}

#[test]
fn arbitrary_declared_starts_do_not_trigger_program_discovery() {
    let mut project = project();
    project.binary.function_starts.extend((0..20_000).map(|index| 0x9000_0000 + index * 16));
    let result = project.decompile_entry(&request(&project)).unwrap();
    assert_no_discovery(&project);
    assert!(result.decompilation.code.contains("return 5;"));
    assert!(!result.context.counts.context_budget_exhausted);
}

#[test]
fn cancellation_busy_state_unsupported_architecture_and_invalid_compiler_fail_without_fallback() {
    let project = project();
    let request = request(&project);
    let cancellation = AtomicBool::new(true);
    assert!(
        project.decompile_entry_cancellable(&request, &cancellation).unwrap_err().to_string().contains("cancelled")
    );
    let state = project.decompiler.lock().unwrap();
    assert!(project.decompile_entry(&request).unwrap_err().to_string().contains("busy"));
    drop(state);
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("unknown_exact_entry_compiler".to_owned()),
        ..Default::default()
    }));
    assert!(project.decompile_entry(&request).is_err());
    assert_no_discovery(&project);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm-be8.snapshot.json");
    let unsupported = Project::new(Binary::open(path).unwrap());
    let error = unsupported
        .decompile_entry(&DecompileEntryRequest { address: 0x1000, validation: EntryValidation::AnalystAsserted })
        .unwrap_err()
        .to_string();
    assert!(error.contains("supports little-endian"), "{error}");
    assert_no_discovery(&unsupported);
}

struct SnapshotFile(PathBuf);

impl Drop for SnapshotFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn record_snapshot() -> (SnapshotFile, Project) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "entry-record-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = SnapshotFile(path);
    std::fs::write(
        &file.0,
        r#"{
        "format":"rampage-snapshot-v1","arch":"x86_64","data_big_endian":false,
        "provenance":"owned exact-entry annotation replay fixture", "seeds":["0x1000"],
        "regions":[{"name":"code","address":"0x1000","permissions":"r-x","bytes":"8b4708c3"}]
    }"#,
    )
    .unwrap();
    let project = Project::new(Binary::open(&file.0).unwrap());
    (file, project)
}

#[test]
fn exact_replay_preserves_distant_type_dependencies_and_actual_analyst_signature_changes() {
    let (_file, project) = record_snapshot();
    {
        let mut annotations = project.annotations.write().unwrap();
        annotations.set(Field::Types, 0x9000, Some("struct Record { void *opaque; int4 count; };".to_owned())).unwrap();
        annotations.set(Field::Signature, 0x1000, Some("int4 read_record(Record *record);".to_owned())).unwrap();
    }
    let request = DecompileEntryRequest { address: 0x1000, validation: EntryValidation::MetadataBacked };
    let first = project.decompile_entry(&request).unwrap();
    assert!(first.decompilation.code.contains("record->count"), "{}", first.decompilation.code);
    assert_no_discovery(&project);
    project
        .annotations
        .write()
        .unwrap()
        .set(Field::Signature, 0x1000, Some("int4 analyst_kept(Record *analyst);".to_owned()))
        .unwrap();
    let changed = project.decompile_entry(&request).unwrap();
    assert!(changed.decompilation.code.contains("analyst->count"), "{}", changed.decompilation.code);
    assert_no_discovery(&project);
}

#[test]
fn legacy_interior_requests_still_resolve_the_containing_function() {
    let project = project();
    let request = request(&project);
    assert!(
        project
            .decompile_entry(&DecompileEntryRequest {
                address: request.address + 1,
                validation: EntryValidation::MetadataBacked,
            })
            .is_err()
    );
    assert_no_discovery(&project);
    assert_eq!(project.decompile(request.address + 1).unwrap().address, request.address);
}

#[test]
fn progress_reports_only_real_native_phases_outside_project_locks_and_keeps_json_compatible() {
    let project = project();
    let revision = project.decompiler_configuration_revision().unwrap();
    let mut events = Vec::new();
    let result = project
        .decompile_entry_with_progress(&request(&project), &AtomicBool::new(false), |event| {
            assert!(project.decompiler.try_lock().is_ok());
            assert!(project.annotations.try_write().is_ok());
            events.push(event);
        })
        .unwrap();
    assert_eq!(
        events.iter().map(|event| event.phase).collect::<Vec<_>>(),
        vec![
            EntryPreparationPhase::Configuration,
            EntryPreparationPhase::Metadata,
            EntryPreparationPhase::Replay,
            EntryPreparationPhase::Mapping,
            EntryPreparationPhase::NativeInitialization,
            EntryPreparationPhase::NativeReplay,
            EntryPreparationPhase::NativeExecution,
            EntryPreparationPhase::ResultValidation,
        ]
    );
    assert!(events.windows(2).all(|pair| pair[0].elapsed_ms <= pair[1].elapsed_ms));
    assert_eq!(result.context.configuration_revision, revision);
    assert!(result.decompilation.code.contains("return 5;"));
    let json = serde_json::to_value(result).unwrap();
    assert!(json["context"].get("configuration_revision").is_none());
    assert!(json.get("code").is_some());
    assert_no_discovery(&project);
}

#[test]
fn observer_cancellation_stops_before_native_setup_without_emitting_later_phases() {
    let project = project();
    let cancellation = AtomicBool::new(false);
    let mut phases = Vec::new();
    let error = project
        .decompile_entry_with_progress(&request(&project), &cancellation, |event| {
            phases.push(event.phase);
            if event.phase == EntryPreparationPhase::Mapping {
                cancellation.store(true, Ordering::Relaxed);
            }
        })
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(phases.last(), Some(&EntryPreparationPhase::Mapping));
    assert!(!phases.contains(&EntryPreparationPhase::NativeInitialization));
    assert!(project.decompiler.lock().unwrap().engine.is_none());
    assert_no_discovery(&project);
    phases.clear();
    assert!(
        project
            .decompile_entry_with_progress(&request(&project), &cancellation, |event| {
                phases.push(event.phase);
            })
            .is_err()
    );
    assert!(phases.is_empty());
}

#[test]
fn failed_worker_reports_worker_phases_without_a_native_fallback() {
    let project = project();
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(std::env::temp_dir().join("entry-progress-no-such-worker")),
        ..Default::default()
    }));
    let mut phases = Vec::new();
    let error = project
        .decompile_entry_with_progress(&request(&project), &AtomicBool::new(false), |event| {
            phases.push(event.phase);
        })
        .unwrap_err();
    assert!(error.to_string().contains("exact-entry worker"));
    assert_eq!(
        phases,
        vec![
            EntryPreparationPhase::Configuration,
            EntryPreparationPhase::Metadata,
            EntryPreparationPhase::Replay,
            EntryPreparationPhase::Mapping,
            EntryPreparationPhase::WorkerSerialization,
            EntryPreparationPhase::WorkerExecution,
        ]
    );
    assert_no_discovery(&project);
}

#[test]
fn configuration_identity_rejects_aba_and_getters_do_not_construct_native_or_analysis_state() {
    let project = project();
    let original = project.decompiler_configuration_revision().unwrap();
    assert_eq!(original, project.decompiler_configuration_revision().unwrap());
    assert!(project.configured_decompiler_options().unwrap().is_none());
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("deliberately_unavailable_configuration".into()),
        ..Default::default()
    }));
    assert_ne!(original, project.decompiler_configuration_revision().unwrap());
    assert_eq!(
        project.configured_decompiler_options().unwrap().unwrap().compiler.as_deref(),
        Some("deliberately_unavailable_configuration")
    );
    project.set_decompiler_options(None);
    assert_ne!(original, project.decompiler_configuration_revision().unwrap());
    let after = project.decompiler_configuration_revision().unwrap();
    project.set_decompiler_worker(None);
    assert_ne!(after, project.decompiler_configuration_revision().unwrap());
    let guard = project.decompiler.lock().unwrap();
    assert!(project.decompiler_configuration_revision().is_err());
    assert!(project.configured_decompiler_options().is_err());
    assert!(guard.engine.is_none());
    drop(guard);
    assert_no_discovery(&project);
}

#[test]
fn exact_result_binds_captured_configuration_even_if_an_observer_changes_current_options() {
    let project = project();
    let original = project.decompiler_configuration_revision().unwrap();
    let result = project
        .decompile_entry_with_progress(&request(&project), &AtomicBool::new(false), |event| {
            if event.phase == EntryPreparationPhase::Metadata {
                project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
                    compiler: Some("new_options_not_used_by_this_request".into()),
                    ..Default::default()
                }));
            }
        })
        .unwrap();
    assert_eq!(result.context.configuration_revision, original);
    assert_ne!(result.context.configuration_revision, project.decompiler_configuration_revision().unwrap());
    assert!(result.decompilation.code.contains("return 5;"));
    assert_no_discovery(&project);
}

#[test]
fn phase_observers_cannot_invalidate_mapped_input_before_byte_consumption() {
    static NEXT_SOURCE: AtomicU64 = AtomicU64::new(0);
    for phase in [
        EntryPreparationPhase::Metadata,
        EntryPreparationPhase::WorkerSerialization,
        EntryPreparationPhase::NativeInitialization,
    ] {
        let file = SnapshotFile(std::env::temp_dir().join(format!(
            "entry-observer-source-{}-{}.elf",
            std::process::id(),
            NEXT_SOURCE.fetch_add(1, Ordering::Relaxed),
        )));
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf"),
            &file.0,
        )
        .unwrap();
        let project = Project::new(Binary::open(&file.0).unwrap());
        if phase == EntryPreparationPhase::WorkerSerialization {
            project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
                executable: Some(std::env::temp_dir().join("observer-source-no-worker")),
                ..Default::default()
            }));
        }
        let request = request(&project);
        let mut observed = Vec::new();
        let error = project
            .decompile_entry_with_progress(&request, &AtomicBool::new(false), |event| {
                observed.push(event.phase);
                if event.phase == phase {
                    std::fs::write(&file.0, b"truncated owned input").unwrap();
                }
            })
            .unwrap_err();
        assert!(error.to_string().contains("exact-entry source"), "{error}");
        assert_eq!(observed.last(), Some(&phase));
        assert_no_discovery(&project);
    }
}

#[test]
fn cancellation_from_final_validation_rejects_an_otherwise_completed_result() {
    let project = project();
    let cancellation = AtomicBool::new(false);
    let mut last = None;
    let error = project
        .decompile_entry_with_progress(&request(&project), &cancellation, |event| {
            last = Some(event.phase);
            if event.phase == EntryPreparationPhase::ResultValidation {
                cancellation.store(true, Ordering::Relaxed);
            }
        })
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(last, Some(EntryPreparationPhase::ResultValidation));
    assert_no_discovery(&project);
}

#[test]
fn observer_work_is_charged_to_the_original_worker_deadline_before_dispatch() {
    let project = project();
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        timeout: std::time::Duration::from_millis(5),
        executable: Some(std::env::temp_dir().join("observer-budget-no-worker")),
        ..Default::default()
    }));
    let mut phases = Vec::new();
    let error = project
        .decompile_entry_with_progress(&request(&project), &AtomicBool::new(false), |event| {
            phases.push(event.phase);
            let work = Instant::now();
            while work.elapsed() < std::time::Duration::from_millis(10) {
                std::thread::yield_now();
            }
        })
        .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
    assert_eq!(phases, vec![EntryPreparationPhase::Configuration]);
    assert_no_discovery(&project);
}

#[test]
fn measured_exact_entry_emits_no_supervisor_observation_for_inline_native_execution() {
    let project = project();
    let result = project
        .decompile_entry_measured(
            &request(&project),
            &AtomicBool::new(false),
            |_| {},
            |_| panic!("inline execution has no worker supervisor"),
        )
        .unwrap();
    assert!(result.decompilation.code.contains("return 5;"));
    assert_eq!(result.context.execution, "in_process_native");
    assert_no_discovery(&project);
}

#[test]
fn measured_exact_entry_delivers_partial_supervisor_observations_before_spawn_error() {
    let project = project();
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(std::env::temp_dir().join("missing-entry-measurement-worker")),
        ..Default::default()
    }));
    let mut observations = Vec::new();
    let error = project
        .decompile_entry_measured(
            &request(&project),
            &AtomicBool::new(false),
            |_| {},
            |metrics| observations.push(metrics),
        )
        .unwrap_err();
    assert!(error.to_string().contains("spawn"), "{error}");
    assert_eq!(observations.len(), 1);
    let metrics = serde_json::to_value(&observations[0]).unwrap();
    assert_eq!(metrics["ownership"], "not_spawned");
    assert!(metrics["cleanup_succeeded"].is_null());
    assert_no_discovery(&project);
}

fn hint_project(annotations: Annotations) -> Project {
    let binary = Binary::from_snapshot_bytes(
        br#"{
            "format":"rampage-snapshot-v1","arch":"x86_64","data_big_endian":false,
            "target":{"platform":"default","compiler":"gcc"},
            "provenance":"owned exact-entry persisted hint fixture", "seeds":["0x1000","0x1100"],
            "regions":[
                {"name":"read","address":"0x1000","permissions":"r-x","bytes":"8b4708c3"},
                {"name":"caller","address":"0x1100","permissions":"r-x","bytes":"50e8fafeffff59c3"}
            ]
        }"#
        .to_vec(),
    )
    .unwrap();
    Project::with_annotations(binary, annotations)
}

fn hint_request(address: u64) -> DecompileEntryRequest {
    DecompileEntryRequest { address, validation: EntryValidation::MetadataBacked }
}

fn hint_types(project: &Project) {
    project
        .annotations
        .write()
        .unwrap()
        .set(
            Field::Types,
            0x9000,
            Some(
                concat!(
                    "struct ExactRecord { void *opaque; int4 count; }; ",
                    "struct ExactOwner { void *opaque; int4 owned; };"
                )
                .into(),
            ),
        )
        .unwrap();
}

fn parameter_hint(project: &Project) -> DerivedTypeHint {
    let baseline = project.decompile_entry(&hint_request(0x1000)).unwrap();
    let storage = rampage_decompiler::VariableStorage::try_from(
        &baseline.decompilation.structure.signature.parameters[0].storage,
    )
    .unwrap();
    DerivedTypeHint {
        target: TypeHintTarget::Parameter { index: 0, storage },
        data_type: "ExactRecord *".into(),
        evidence: Vec::new(),
    }
}

fn store_hint(project: &Project, function: u64, hint: DerivedTypeHint, stale: bool) {
    let mut annotations = project.annotations.write().unwrap();
    let options = default_options(&project.binary);
    let fingerprint = if stale {
        "00".repeat(32)
    } else {
        crate::propagation::source_fingerprint(project, &options, &annotations).unwrap()
    };
    let text = encode_type_hints(&TypeHintAnnotation { source_fingerprint: fingerprint, hints: vec![hint] }).unwrap();
    annotations.set(Field::TypeHint, function, Some(text)).unwrap();
}

fn hint_messages(result: &EntryDecompilation) -> Vec<&str> {
    result
        .decompilation
        .structure
        .diagnostics
        .as_ref()
        .map(|diagnostics| diagnostics.warnings.iter().map(|warning| warning.message.as_str()).collect())
        .unwrap_or_default()
}

#[test]
fn exact_entry_replays_a_persisted_hint_with_full_snapshot_fingerprint_without_discovery() {
    static NEXT_LOG: AtomicU64 = AtomicU64::new(0);
    let log = SnapshotFile(std::env::temp_dir().join(format!(
        "entry-hints-{}-{}.jsonl",
        std::process::id(),
        NEXT_LOG.fetch_add(1, Ordering::Relaxed),
    )));
    let _lock = SnapshotFile(PathBuf::from(format!("{}.lock", log.0.display())));
    {
        let project = hint_project(Annotations::open_checked(log.0.clone()).unwrap());
        hint_types(&project);
        let hint = parameter_hint(&project);
        store_hint(&project, 0x1000, hint, false);
    }
    let project = hint_project(Annotations::open_checked(log.0.clone()).unwrap());
    let before = std::fs::read(&log.0).unwrap();
    let result = project.decompile_entry(&hint_request(0x1000)).unwrap();
    assert!(result.decompilation.code.contains("->count"), "{}", result.decompilation.code);
    assert!(result.decompilation.structure.signature.parameters[0].data_type.name.contains("ExactRecord"));
    assert!(!hint_messages(&result).iter().any(|message| message.contains("stale derived")));
    assert_eq!(std::fs::read(&log.0).unwrap(), before);
    assert!(project.annotations().signatures().is_empty());
    assert!(project.annotations().local_types().is_empty());
    assert!(project.decompiler.lock().unwrap().engine.is_none());
    assert_no_discovery(&project);
}

#[test]
fn exact_entry_omits_stale_hints_with_structured_and_context_diagnostics() {
    let project = hint_project(Annotations::in_memory());
    hint_types(&project);
    let mut hint = parameter_hint(&project);
    hint.data_type = "MissingStaleExactType *".into();
    store_hint(&project, 0x1000, hint, true);
    let result = project.decompile_entry(&hint_request(0x1000)).unwrap();
    assert!(!result.decompilation.code.contains("ExactRecord"));
    assert!(hint_messages(&result).iter().any(|message| message.contains("stale derived type hints")));
    assert!(result.context.omissions.iter().any(|message| message.contains("stale derived type hints")));
    assert_no_discovery(&project);
}

#[test]
fn exact_entry_never_replays_or_validates_hints_outside_its_admitted_function_context() {
    let project = hint_project(Annotations::in_memory());
    hint_types(&project);
    let mut hint = parameter_hint(&project);
    hint.data_type = "MissingOutsideExactType *".into();
    store_hint(&project, 0x1100, hint, false);
    let result = project.decompile_entry(&hint_request(0x1000)).unwrap();
    assert!(!result.decompilation.code.contains("ExactRecord"));
    assert!(
        hint_messages(&result)
            .iter()
            .any(|message| { message.contains("0x1100") && message.contains("outside bounded exact-entry context") })
    );
    assert!(result.context.omissions.iter().any(|message| message.contains("outside bounded exact-entry context")));
    assert_no_discovery(&project);
}

#[test]
fn exact_entry_hard_local_and_signature_types_take_priority_over_fresh_soft_hints() {
    for signature in [false, true] {
        let project = hint_project(Annotations::in_memory());
        hint_types(&project);
        let hint = parameter_hint(&project);
        let TypeHintTarget::Parameter { storage, .. } = &hint.target else { unreachable!() };
        let (field, value) = if signature {
            (Field::Signature, "int4 read_owned(ExactOwner *owner);".to_owned())
        } else {
            (
                Field::LocalType,
                encode_local_types(&[LocalTypeAnnotation {
                    storage: storage.clone(),
                    data_type: "ExactOwner *".into(),
                }])
                .unwrap(),
            )
        };
        project.annotations.write().unwrap().set(field, 0x1000, Some(value)).unwrap();
        store_hint(&project, 0x1000, hint, false);
        let result = project.decompile_entry(&hint_request(0x1000)).unwrap();
        assert!(result.decompilation.code.contains("->owned"), "{}", result.decompilation.code);
        assert!(!result.decompilation.code.contains("ExactRecord"));
        assert!(hint_messages(&result).iter().any(|message| message.contains("analyst type overrides derived hint")));
        assert!(!hint_messages(&result).iter().any(|message| message.contains("stale derived")));
        assert_no_discovery(&project);
    }
}

#[test]
fn exact_entry_replays_hard_local_overrides_for_admitted_callees_before_soft_hints() {
    let project = hint_project(Annotations::in_memory());
    hint_types(&project);
    let hint = parameter_hint(&project);
    let TypeHintTarget::Parameter { storage, .. } = &hint.target else { unreachable!() };
    let value =
        encode_local_types(&[LocalTypeAnnotation { storage: storage.clone(), data_type: "ExactOwner *".into() }])
            .unwrap();
    project.annotations.write().unwrap().set(Field::LocalType, 0x1000, Some(value)).unwrap();
    store_hint(&project, 0x1000, hint, false);
    let result = project.decompile_entry(&hint_request(0x1100)).unwrap();
    assert!(result.decompilation.code.contains("ExactOwner"), "{}", result.decompilation.code);
    assert!(!result.decompilation.code.contains("ExactRecord"));
    assert!(!hint_messages(&result).iter().any(|message| message.contains("outside bounded exact-entry context")));
    assert_no_discovery(&project);
}

#[test]
fn exact_entry_validates_hint_storage_and_type_in_native_and_optional_worker_results() {
    let worker = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER");
    for executable in std::iter::once(None).chain(worker.map(|path| Some(PathBuf::from(path)))) {
        let project = hint_project(Annotations::in_memory());
        hint_types(&project);
        let mut hint = parameter_hint(&project);
        let TypeHintTarget::Parameter { index, .. } = &mut hint.target else { unreachable!() };
        *index = 99;
        store_hint(&project, 0x1000, hint, false);
        if let Some(executable) = executable {
            project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
                executable: Some(executable),
                ..Default::default()
            }));
        }
        let error = project.decompile_entry(&hint_request(0x1000)).unwrap_err();
        assert!(error.to_string().contains("canonical target identity"), "{error}");
        assert_no_discovery(&project);
    }
}

#[test]
fn exact_entry_worker_and_native_replay_have_matching_soft_hint_types_storage_and_diagnostics() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    let project = hint_project(Annotations::in_memory());
    hint_types(&project);
    let hint = parameter_hint(&project);
    store_hint(&project, 0x1000, hint, false);
    let native = project.decompile_entry(&hint_request(0x1000)).unwrap();
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(PathBuf::from(executable)),
        ..Default::default()
    }));
    let worker = project.decompile_entry(&hint_request(0x1000)).unwrap();
    assert_eq!(native.decompilation.code, worker.decompilation.code);
    assert_eq!(native.decompilation.structure, worker.decompilation.structure);
    assert_eq!(native.decompilation.language_id, worker.decompilation.language_id);
    assert_eq!(native.context.omissions, worker.context.omissions);
    assert_eq!(worker.context.execution, "supervised_worker");
    assert_no_discovery(&project);
}

#[test]
fn caller_requests_reject_invalid_admitted_callee_hint_indices_in_native_and_optional_worker() {
    let worker = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER");
    for executable in std::iter::once(None).chain(worker.map(|path| Some(PathBuf::from(path)))) {
        let is_worker = executable.is_some();
        let project = hint_project(Annotations::in_memory());
        hint_types(&project);
        let mut hint = parameter_hint(&project);
        let TypeHintTarget::Parameter { index, .. } = &mut hint.target else { unreachable!() };
        *index = 99;
        store_hint(&project, 0x1000, hint, false);
        if let Some(executable) = executable {
            project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
                executable: Some(executable),
                ..Default::default()
            }));
        }
        let mut observations = 0;
        let error = project
            .decompile_entry_measured(&hint_request(0x1100), &AtomicBool::new(false), |_| {}, |_| observations += 1)
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("canonical target identity") && message.contains("0x1000"), "{message}");
        assert_eq!(observations, usize::from(is_worker));
        assert!(project.decompiler.lock().unwrap().engine.is_none());
        assert_no_discovery(&project);
    }
}

#[test]
fn caller_requests_validate_matching_admitted_callee_hints_and_keep_the_root_result_last() {
    let worker = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER");
    let mut native = None;
    for executable in std::iter::once(None).chain(worker.map(|path| Some(PathBuf::from(path)))) {
        let is_worker = executable.is_some();
        let project = hint_project(Annotations::in_memory());
        hint_types(&project);
        let hint = parameter_hint(&project);
        store_hint(&project, 0x1000, hint, false);
        if let Some(executable) = executable {
            project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
                executable: Some(executable),
                ..Default::default()
            }));
        }
        let mut observations = 0;
        let result = project
            .decompile_entry_measured(&hint_request(0x1100), &AtomicBool::new(false), |_| {}, |_| observations += 1)
            .unwrap();
        assert_eq!(observations, if is_worker { 2 } else { 0 });
        assert_eq!(result.context.validated_hint_callees, 1);
        assert_eq!(result.decompilation.address, 0x1100);
        assert!(result.decompilation.code.contains("ExactRecord"), "{}", result.decompilation.code);
        assert!(!result.decompilation.code.contains("->count"), "{}", result.decompilation.code);
        if let Some(native) = &native {
            assert_eq!(native, &result.decompilation.structure);
        } else {
            native = Some(result.decompilation.structure.clone());
        }
        assert_no_discovery(&project);
    }
}

fn import_model_project() -> Project {
    let mut project = hint_project(Annotations::in_memory());
    project.binary.symbols.push(rampage_loaders::Symbol {
        name: "memcpy".into(),
        address: 0x1000,
        size: 4,
        kind: rampage_loaders::SymbolKind::Function,
    });
    project
}

fn typed_query_project() -> Project {
    let binary = Binary::from_snapshot_bytes(
        br#"{
            "format":"rampage-snapshot-v1","arch":"x86_64","data_big_endian":false,
            "target":{"platform":"default","compiler":"gcc"},
            "provenance":"owned exact-entry preliminary typed query fixture", "seeds":["0x1100"],
            "regions":[
                {"name":"read","address":"0x1100","permissions":"r-x","bytes":"c3"},
                {"name":"value","address":"0x2000","permissions":"rw-","bytes":"01000000"}
            ]
        }"#
        .to_vec(),
    )
    .unwrap();
    let project = Project::new(binary);
    let binding = crate::annotations::encode_data_type(&crate::annotations::DataTypeAnnotation {
        type_name: Some("int4".into()),
        count: 1,
        byte_length: 4,
        encoding: None,
    })
    .unwrap();
    project.annotations.write().unwrap().set(Field::DataType, 0x2000, Some(binding)).unwrap();
    project
}

#[test]
fn measured_preliminary_queries_deliver_spawn_failure_metrics_without_a_native_fallback() {
    for (project, stage) in
        [(import_model_project(), "exact-entry import model query"), (typed_query_project(), "exact-entry type query")]
    {
        project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
            executable: Some(std::env::temp_dir().join("missing-entry-preliminary-query-worker")),
            ..Default::default()
        }));
        let mut observations = Vec::new();
        let mut phases = Vec::new();
        let error = project
            .decompile_entry_measured(
                &hint_request(0x1100),
                &AtomicBool::new(false),
                |event| phases.push(event.phase),
                |metrics| {
                    assert!(project.decompiler.try_lock().is_ok());
                    assert!(project.annotations.try_write().is_ok());
                    observations.push(metrics);
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains(stage), "{error}");
        assert_eq!(observations.len(), 1);
        let metrics = serde_json::to_value(&observations[0]).unwrap();
        assert_eq!(metrics["ownership"], "not_spawned");
        assert_eq!(phases.last(), Some(&EntryPreparationPhase::WorkerExecution));
        assert!(!phases.contains(&EntryPreparationPhase::NativeInitialization));
        assert!(project.decompiler.lock().unwrap().engine.is_none());
        assert_no_discovery(&project);
    }
}

#[test]
fn preliminary_query_observer_cancellation_is_checked_before_consuming_a_failed_child_result() {
    for project in [import_model_project(), typed_query_project()] {
        project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
            executable: Some(std::env::temp_dir().join("missing-entry-prequery-cancel-worker")),
            ..Default::default()
        }));
        let cancellation = AtomicBool::new(false);
        let mut observations = 0;
        let error = project
            .decompile_entry_measured(
                &hint_request(0x1100),
                &cancellation,
                |_| {},
                |_| {
                    observations += 1;
                    cancellation.store(true, Ordering::Relaxed);
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("cancelled during supervisor observer"), "{error}");
        assert_eq!(observations, 1);
        assert_no_discovery(&project);
    }
}

#[test]
fn preliminary_query_observer_time_is_charged_to_the_original_deadline_even_on_spawn_failure() {
    let project = import_model_project();
    let timeout = std::time::Duration::from_secs(2);
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        timeout,
        executable: Some(std::env::temp_dir().join("missing-entry-prequery-timeout-worker")),
        ..Default::default()
    }));
    let mut observations = 0;
    let error = project
        .decompile_entry_measured(
            &hint_request(0x1100),
            &AtomicBool::new(false),
            |_| {},
            |_| {
                observations += 1;
                let observed = Instant::now();
                while observed.elapsed() <= timeout {
                    std::thread::yield_now();
                }
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("timed out during supervisor observer"), "{error}");
    assert_eq!(observations, 1);
    assert_no_discovery(&project);
}

#[test]
fn successful_preliminary_queries_honor_observer_cancellation_before_dispatching_the_root() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    for (fixture, query, project) in [
        ("import_model_project", "model-only Inventory with no replay operations", import_model_project()),
        ("typed_query_project", "Get int4 after typed-data replay", typed_query_project()),
    ] {
        project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
            executable: Some(PathBuf::from(&executable)),
            ..Default::default()
        }));
        project.decompile_entry(&hint_request(0x1100)).expect("successful preliminary query fixture");
        let cancellation = AtomicBool::new(false);
        let mut observations = 0;
        let error = project
            .decompile_entry_measured(
                &hint_request(0x1100),
                &cancellation,
                |_| {},
                |metrics| {
                    observations += 1;
                    assert!(
                        metrics.root_exit_status.as_ref().is_some_and(|status| status.success)
                            || metrics.intentional_stop,
                        "fixture={fixture}, query={query}, observation={observations}, worker={executable:?}, \
                         metrics={metrics:#?}"
                    );
                    assert!(metrics.response_decoded_us.is_some(), "{fixture}: response not decoded");
                    assert_eq!(metrics.cleanup_succeeded, Some(true), "{fixture}: cleanup not established");
                    cancellation.store(true, Ordering::Relaxed);
                },
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("cancelled during supervisor observer"),
            "fixture={fixture}, query={query}, error={error}"
        );
        assert_eq!(observations, 1, "fixture={fixture}, query={query}");
        assert_no_discovery(&project);
    }
}

#[test]
fn preliminary_query_observers_cannot_invalidate_backing_source_before_result_consumption() {
    static NEXT_SOURCE: AtomicU64 = AtomicU64::new(0);
    let file = SnapshotFile(std::env::temp_dir().join(format!(
        "entry-prequery-source-{}-{}.elf",
        std::process::id(),
        NEXT_SOURCE.fetch_add(1, Ordering::Relaxed),
    )));
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf"),
        &file.0,
    )
    .unwrap();
    let mut project = Project::new(Binary::open(&file.0).unwrap());
    let request = request(&project);
    project
        .binary
        .symbols
        .iter_mut()
        .find(|symbol| symbol.address == request.address && symbol.kind == rampage_loaders::SymbolKind::Function)
        .unwrap()
        .name = "memcpy".into();
    project.set_decompiler_worker(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(std::env::temp_dir().join("missing-entry-prequery-source-worker")),
        ..Default::default()
    }));
    let mut observations = 0;
    let error = project
        .decompile_entry_measured(
            &request,
            &AtomicBool::new(false),
            |_| {},
            |_| {
                observations += 1;
                std::fs::write(&file.0, b"truncated owned exact-entry source").unwrap();
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("exact-entry source"), "{error}");
    assert_eq!(observations, 1);
    assert_no_discovery(&project);
}
