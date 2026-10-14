use std::path::PathBuf;

use rampage_api::{DecompilerOptions, DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;

fn fixture_root() -> PathBuf {
    std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES")
        .map(PathBuf::from)
        .expect("requires centrally compiled owned DWARF fixtures through the --check wrapper")
}

fn worker() -> DecompilerWorkerConfig {
    DecompilerWorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn legacy_debug_preview_does_not_import_layouts_or_change_native_worker_results() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = Project::new(Binary::open(fixture_root().join(variant).join("flat.debug.elf")).unwrap());
        let address = project.resolve("debug_flat_read_final").unwrap();
        let before = project.decompile(address).unwrap();
        let annotations = serde_json::to_value(project.annotation_list()).unwrap();
        let preview = project.import_debug_signatures(false).unwrap();
        assert!(preview.applied.is_empty());
        assert!(!preview.preview.signatures.iter().any(|signature| signature.name.starts_with("debug_flat_")));
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), annotations);
        let after = project.decompile(address).unwrap();
        assert_eq!(after.code, before.code);
        assert_eq!(after.structure, before.structure);
        assert_eq!(serde_json::to_value(&after.tokens).unwrap(), serde_json::to_value(&before.tokens).unwrap());
        assert!(!after.code.contains("->tail"), "legacy preview introduced an asserted field: {}", after.code);
        project.set_decompiler_worker(Some(worker()));
        let isolated = project.decompile(address).unwrap();
        assert_eq!(isolated.code, after.code);
        assert_eq!(isolated.structure, after.structure);
        assert_eq!(isolated.recovery_status, after.recovery_status);
        assert_eq!(serde_json::to_value(isolated.tokens).unwrap(), serde_json::to_value(after.tokens).unwrap());
    }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn checked_field_import_replays_in_workers_and_rejects_option_changes_without_publication() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = fixture_root().join(variant).join("flat.debug.elf");
        let log = fixture_root().join(format!("worker-layout-{}-{variant}.jsonl", std::process::id()));
        let project = Project::with_annotations(Binary::open(&path).unwrap(), annotations(&log));
        let preview = project.preview_debug_layouts().unwrap();
        let imported = project.apply_debug_layouts(&preview).unwrap();
        let address = project.resolve("debug_flat_read_interior").unwrap();
        assert!(imported.applied.contains(&address));
        let native = project.decompile(address).unwrap();
        assert!(native.code.contains("->count"), "{}", native.code);

        for supervised in [false, true] {
            project.set_decompiler_worker(supervised.then(worker));
            let incompatible = DecompilerOptions { compiler: Some("windows".to_owned()), ..Default::default() };
            let before = serde_json::to_value(project.annotation_list()).unwrap();
            assert!(project.try_set_decompiler_options(Some(incompatible)).is_err());
            assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
            let result = project.decompile(address).unwrap();
            assert_eq!(result.language_id, native.language_id);
            assert_eq!(result.code, native.code);
            assert_eq!(result.structure, native.structure);
            assert_eq!(serde_json::to_value(result.tokens).unwrap(), serde_json::to_value(&native.tokens).unwrap());
        }

        let reopened = Project::with_annotations(Binary::open(&path).unwrap(), annotations(&log));
        reopened.set_decompiler_worker(Some(worker()));
        let restored = reopened.decompile(address).unwrap();
        assert_eq!(restored.code, native.code);
        assert_eq!(restored.structure, native.structure);
        assert_eq!(serde_json::to_value(restored.tokens).unwrap(), serde_json::to_value(&native.tokens).unwrap());
        let undo = project.undo().unwrap();
        assert_eq!(undo.len(), imported.applied.len() + imported.imported_types.len());
        reopened.refresh_annotations().unwrap();
        assert!(!reopened.decompile(address).unwrap().code.contains("->count"));
    }
}

fn annotations(path: &std::path::Path) -> rampage_api::annotations::Annotations {
    rampage_api::annotations::Annotations::open_checked(path.to_path_buf()).unwrap()
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn stale_managed_source_refuses_cached_native_and_worker_reads_before_using_mapped_bytes() {
    let original = fixture_root().join("dwarf5-o2/flat.debug.elf");
    let path = fixture_root().join(format!("worker-stale-layout-{}.elf", std::process::id()));
    std::fs::copy(original, &path).unwrap();
    let project = Project::new(Binary::open(&path).unwrap());
    let preview = project.preview_debug_layouts().unwrap();
    project.apply_debug_layouts(&preview).unwrap();
    let address = project.resolve("debug_flat_read_final").unwrap();
    assert!(project.decompile(address).unwrap().code.contains("->tail"));
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(0).unwrap();
    let cached = project.decompile(address).unwrap_err().to_string();
    assert!(cached.contains("modified or replaced"), "cached engine touched a stale source: {cached}");
    project.set_decompiler_worker(Some(worker()));
    let isolated = project.decompile(address).unwrap_err().to_string();
    assert!(isolated.contains("modified or replaced"), "worker path touched a stale source: {isolated}");
    let error = project.set_signature(address, Some("int4 analyst(void);")).unwrap_err().to_string();
    assert!(error.contains("modified or replaced"), "signature touched a stale source: {error}");
    let error = project.try_set_decompiler_options(None).unwrap_err().to_string();
    assert!(error.contains("modified or replaced"), "option validation touched a stale source: {error}");
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn removing_managed_annotations_does_not_erase_the_previous_native_cache_source_guard() {
    let root = fixture_root();
    let path = root.join(format!("worker-cleared-layout-{}.elf", std::process::id()));
    let log = root.join(format!("worker-cleared-layout-{}.jsonl", std::process::id()));
    std::fs::copy(root.join("dwarf5-o2/flat.debug.elf"), &path).unwrap();
    let owner = Project::with_annotations(Binary::open(&path).unwrap(), annotations(&log));
    let preview = owner.preview_debug_layouts().unwrap();
    owner.apply_debug_layouts(&preview).unwrap();
    let address = owner.resolve("debug_flat_read_final").unwrap();
    assert!(owner.decompile(address).unwrap().code.contains("->tail"));
    let peer = Project::with_annotations(Binary::open(&path).unwrap(), annotations(&log));
    assert!(peer.decompile(address).unwrap().code.contains("->tail"));
    assert!(!owner.undo().unwrap().is_empty());
    peer.refresh_annotations().unwrap();
    assert!(peer.annotation_list().types.is_empty());
    assert!(peer.annotation_list().signatures.is_empty());
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(0).unwrap();
    for project in [&owner, &peer] {
        let option_error = project.try_set_decompiler_options(None).unwrap_err().to_string();
        assert!(option_error.contains("modified or replaced"), "{option_error}");
        let decompile_error = project.decompile(address).unwrap_err().to_string();
        assert!(decompile_error.contains("modified or replaced"), "{decompile_error}");
    }
    peer.set_decompiler_worker(Some(worker()));
    let isolated_error = peer.decompile(address).unwrap_err().to_string();
    assert!(isolated_error.contains("modified or replaced"), "{isolated_error}");
}
