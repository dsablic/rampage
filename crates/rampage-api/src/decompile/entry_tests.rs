use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::annotations::Field;
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
