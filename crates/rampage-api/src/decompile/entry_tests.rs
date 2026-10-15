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
