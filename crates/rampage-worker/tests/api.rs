use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;

#[test]
fn api_supervised_path_matches_native_imports_tokens_and_typed_annotations() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let main = project.resolve("main").unwrap();
    let native = project.decompile(main).unwrap();
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    let isolated = project.decompile(main).unwrap();
    assert_eq!(isolated.code, native.code);
    assert_eq!(isolated.language_id, native.language_id);
    assert_eq!(isolated.tokens.len(), native.tokens.len());
    assert_eq!(isolated.structure, native.structure);
    let add = project.resolve("add").unwrap();
    project.set_signature(add, Some("int4 sum(int4 left,int4 right);")).unwrap();
    let typed = project.decompile(add).unwrap();
    assert!(typed.code.contains("int4 left"), "{}", typed.code);
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(project.decompile_cancellable(add, &cancelled).is_err());
}

#[test]
fn annotation_validation_does_not_require_an_entry_and_recovery_does_not_require_a_worker() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let mut binary = Binary::open(path).unwrap();
    binary.entry = None;
    binary.function_starts.clear();
    let project = Project::new(binary);
    let add = project.resolve("add").unwrap();
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    project.set_signature(add, Some("int4 sum(int4 left,int4 right);")).unwrap();
    project.comment(add, Some("comment")).unwrap();
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some("/nonexistent/worker".into()),
        ..Default::default()
    }));
    project.undo().unwrap();
    assert_eq!(project.comment_at(add), None);
    project.set_signature(add, None).unwrap();
    assert!(project.annotation_list().signatures.is_empty());
}

#[test]
fn isolated_debug_signature_import_matches_native_name_recovery() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    project.import_debug_signatures(true).unwrap();
    let result = project.decompile(project.resolve("debug_mix").unwrap()).unwrap();
    assert!(result.code.contains("total") && result.code.contains("message"), "{}", result.code);
}
