use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;

#[test]
fn generated_go_result_dependencies_replay_before_analyst_signatures_in_both_engines() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-go-x64.elf");
    for (types, result) in
        [(None, "go_results_2"), (Some("typedef struct{xunknown8 r0; xunknown8 r1;}go_results_2;"), "go_results_2")]
    {
        let project = Project::new(Binary::open(&path).unwrap());
        let greet = project.resolve("main.greet").unwrap();
        project.set_decompiler_worker(Some(DecompilerWorkerConfig {
            executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
            ..Default::default()
        }));
        project.set_types(1, Some("struct result_box { go_results_2 result; };")).unwrap();
        if let Some(types) = types {
            project.set_types(greet, Some(types)).unwrap();
        }
        let signature = format!("{result} greet(xunknown8 who, xunknown8 size);");
        project.set_signature(greet, Some(&signature)).unwrap();
        let isolated = project.decompile(greet).unwrap();
        assert!(isolated.code.contains(&format!("{result} main.greet")), "{}", isolated.code);
        project.set_decompiler_worker(None);
        let native = project.decompile(greet).unwrap();
        assert_eq!(isolated.code, native.code);
        assert_eq!(isolated.structure, native.structure);
    }
}

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
    assert_eq!(isolated.recovery_status, native.recovery_status);
    let add = project.resolve("add").unwrap();
    project.set_signature(add, Some("int4 sum(int4 left,int4 right);")).unwrap();
    let typed = project.decompile(add).unwrap();
    assert!(typed.code.contains("int4 left"), "{}", typed.code);
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(project.decompile_cancellable(add, &cancelled).is_err());
}

#[test]
fn isolated_and_native_bad_code_diagnostics_match() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-x64-bad-code.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let native = project.decompile(0x1000).unwrap();
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    let isolated = project.decompile(0x1000).unwrap();
    assert_eq!(isolated.recovery_status, rampage_api::RecoveryStatus::Incomplete);
    assert_eq!(isolated.structure.diagnostics, native.structure.diagnostics);
}

#[test]
fn isolated_decompilation_preserves_declared_capture_platform() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-darwin.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    let result = project.decompile(0x1000).unwrap();
    assert!(result.language_id.ends_with(":apple"));
    assert!(result.code.contains("return 7;"), "{}", result.code);
}

#[test]
fn darwin_narrow_prototypes_and_arithmetic_match_native_and_supervised_engines() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-arm64-darwin-narrow.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let cases = [
        (0x1000, "int4 narrow_signed_char(int1 value);", 1),
        (0x1008, "int4 narrow_signed_short(int2 value);", 2),
        (0x1010, "uint4 narrow_unsigned_char(uint1 value);", 1),
        (0x1018, "uint4 narrow_unsigned_short(uint2 value);", 2),
        (0x1020, "uint8 narrow_signed_char_u32(int1 value);", 1),
        (0x1028, "uint8 narrow_signed_short_u32(int2 value);", 2),
    ];
    for (address, declaration, width) in cases {
        project.set_decompiler_worker(None);
        project.set_signature(address, Some(declaration)).unwrap();
        let native = project.decompile(address).unwrap();
        assert!(native.language_id.ends_with(":apple"));
        let parameters = &native.structure.signature.parameters;
        assert_eq!(parameters.len(), 1, "{}", native.code);
        assert_eq!(parameters[0].name, "value");
        assert_eq!(parameters[0].data_type.size, width);
        if declaration.contains("(int1") || declaration.contains("(int2") {
            assert!(!native.code.contains("(uint1)value"), "{}", native.code);
            assert!(!native.code.contains("(uint2)value"), "{}", native.code);
        }
        project.set_decompiler_worker(Some(DecompilerWorkerConfig {
            executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
            ..Default::default()
        }));
        let isolated = project.decompile(address).unwrap();
        assert_eq!(isolated.code, native.code);
        assert_eq!(isolated.language_id, native.language_id);
        assert_eq!(isolated.structure, native.structure);
        assert_eq!(isolated.recovery_status, native.recovery_status);
        assert_eq!(serde_json::to_value(isolated.tokens).unwrap(), serde_json::to_value(native.tokens).unwrap());
    }
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

/// Decompile results say where native code ran, and a session requiring the worker never runs it in-process.
#[test]
fn decompile_results_name_the_decompiler_and_a_required_worker_is_never_bypassed() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let decompile = |project: &Project| {
        let arguments = serde_json::json!({ "at": "main", "view": "summary" });
        rampage_api::tools::call(&rampage_api::tools::tools(), project, "decompile", arguments)
    };
    let field = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap()["decompiler"].clone();

    let in_process = Project::new(Binary::open(&path).unwrap());
    assert!(!in_process.decompiles_in_worker());
    let (text, failed) = decompile(&in_process);
    assert!(!failed, "{text}");
    assert_eq!(field(&text), "in-process");

    let worker = std::path::PathBuf::from(env!("CARGO_BIN_EXE_rampage-worker"));
    let session = rampage_api::Session::default().requiring_decompiler_worker(worker.clone());
    assert_eq!(session.required_decompiler_worker(), Some(worker.as_path()));
    let supervised = session.open(&path, None).unwrap();
    assert!(supervised.decompiles_in_worker());
    let (text, failed) = decompile(&supervised);
    assert!(!failed, "{text}");
    assert_eq!(field(&text), "supervised");

    // A required worker that is missing refuses the call; nothing falls back to in-process.
    let missing = rampage_api::Session::default()
        .requiring_decompiler_worker("/nonexistent/rampage-worker".into())
        .open(&path, None)
        .unwrap();
    assert!(missing.decompiles_in_worker());
    let (text, failed) = decompile(&missing);
    assert!(failed, "{text}");
    assert!(!text.contains("\"decompiler\""), "{text}");
}
