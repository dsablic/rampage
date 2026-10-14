use rampage_api::{DecompilerOptions, Project};
use rampage_loaders::{Binary, Format};

fn binary() -> Binary {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-x64-windows-arguments.snapshot.json");
    Binary::open(path).unwrap()
}

#[test]
fn pe_format_selects_windows_spec_and_options_rebuild_the_cached_engine() {
    let mut binary = binary();
    binary.format = Format::Pe;
    let project = Project::new(binary);
    let windows = project.decompile(0x1000).unwrap();
    assert_eq!(windows.language_id, "x86:LE:64:default:windows");
    assert!(!windows.code.contains("param_3"), "{}", windows.code);
    project.set_decompiler_options(Some(DecompilerOptions::default()));
    let sysv = project.decompile(0x1000).unwrap();
    assert!(sysv.language_id.ends_with(":gcc"));
    assert!(sysv.code.contains("param_4"), "{}", sysv.code);
    project.set_decompiler_options(None);
    assert_eq!(project.decompile(0x1000).unwrap().code, windows.code);
}

#[test]
fn snapshot_compiler_override_is_explicit_and_bad_overrides_do_not_fall_back() {
    let project = Project::new(binary());
    project
        .set_decompiler_options(Some(DecompilerOptions { compiler: Some("windows".to_owned()), ..Default::default() }));
    assert!(!project.decompile(0x1000).unwrap().code.contains("param_3"));
    project.set_decompiler_options(Some(DecompilerOptions {
        compiler: Some("not_a_spec".to_owned()),
        ..Default::default()
    }));
    assert!(project.decompile(0x1000).is_err());
}

#[test]
fn compiler_overrides_preserve_loader_be8_instruction_byte_order() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm-be8.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let automatic = project.decompile(0x1000).unwrap();
    assert!(automatic.language_id.contains(":LEBE:"));
    assert!(automatic.code.contains("return 7;"), "{}", automatic.code);
    project.set_decompiler_options(Some(DecompilerOptions { compiler: Some("apcs".to_owned()), ..Default::default() }));
    let overridden = project.decompile(0x1000).unwrap();
    assert!(overridden.language_id.contains(":LEBE:"));
    assert!(overridden.code.contains("return 7;"), "{}", overridden.code);
}

#[test]
fn declared_snapshot_context_selects_darwin_and_explicit_overrides_can_be_reset() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-darwin.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    assert!(project.decompile(0x1000).unwrap().language_id.ends_with(":apple"));
    let summary = serde_json::to_value(project.summary()).unwrap();
    assert_eq!(summary["snapshot_target"]["platform"], "darwin");
    project
        .set_decompiler_options(Some(DecompilerOptions { compiler: Some("default".to_owned()), ..Default::default() }));
    assert!(project.decompile(0x1000).unwrap().language_id.ends_with(":default"));
    project.set_decompiler_options(None);
    assert!(project.decompile(0x1000).unwrap().language_id.ends_with(":apple"));
}

#[test]
fn snapshot_compiler_context_overrides_platform_selection_without_silent_fallback() {
    use rampage_loaders::snapshot::{SnapshotPlatform, SnapshotTarget};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-x64-windows-arguments.snapshot.json");
    for (compiler, extra_arguments) in [(None, false), (Some("gcc"), true)] {
        let mut binary = Binary::open(&path).unwrap();
        binary.snapshot_target =
            Some(SnapshotTarget { platform: SnapshotPlatform::Windows, compiler: compiler.map(str::to_owned) });
        let result = Project::new(binary).decompile(0x1000).unwrap();
        assert_eq!(result.code.contains("param_3"), extra_arguments, "{}", result.code);
    }
    let mut binary = Binary::open(path).unwrap();
    binary.snapshot_target =
        Some(SnapshotTarget { platform: SnapshotPlatform::Windows, compiler: Some("unknown_compiler".to_owned()) });
    assert!(Project::new(binary).decompile(0x1000).is_err());
}

fn fixture(name: &str) -> Binary {
    Binary::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)).unwrap()
}

#[test]
fn go_register_abi_binaries_select_the_golang_spec() {
    for name in ["hello-go-x64.elf", "hello-go-arm64.elf"] {
        let project = Project::new(fixture(name));
        let main = project.decompile(project.resolve("main.main").unwrap()).unwrap();
        assert!(main.language_id.ends_with(":golang"), "{name}: {}", main.language_id);
        // Under the C convention `who` looks unused, so its `os.Args` branch vanished and greet took nothing.
        assert!(main.code.contains("if ("), "{name}: {}", main.code);
        assert!(!main.code.contains("main.greet();"), "{name}: {}", main.code);
    }
}

#[test]
fn ambiguous_go_tables_keep_the_platform_default_and_overrides_win() {
    let mut binary = fixture("hello-go-x64.elf");
    binary.go_table = Some(rampage_loaders::gopclntab::GoTableVersion::Go116);
    let project = Project::new(binary);
    let main = project.resolve("main.main").unwrap();
    assert!(project.decompile(main).unwrap().language_id.ends_with(":gcc"));

    let project = Project::new(fixture("hello-go-x64.elf"));
    project.set_decompiler_options(Some(DecompilerOptions { compiler: Some("gcc".to_owned()), ..Default::default() }));
    assert!(project.decompile(main).unwrap().language_id.ends_with(":gcc"));
}

#[test]
fn go_results_inferred_from_callers_flow_into_the_next_call() {
    for name in ["hello-go-x64.elf", "hello-go-arm64.elf"] {
        let project = Project::new(fixture(name));
        let at = |function: &str| project.resolve(function).unwrap();
        // fmt.Println(shout(greet(who))): each string result reaches the next call as its two words.
        let main = project.decompile(at("main.main")).unwrap().code;
        assert!(main.contains("= main.greet(xVar1,xVar2);"), "{name}: {main}");
        assert!(main.contains("= main.shout(gVar3.r0,gVar3.r1);"), "{name}: {main}");
        assert!(main.contains("runtime.convTstring(gVar3.r0,gVar3.r1);"), "{name}: {main}");
        // greet returns the string fmt.Sprintf builds.
        let greet = project.decompile(at("main.greet")).unwrap().code;
        assert!(greet.contains("go_results_2 main.greet(xunknown8 param_1,xunknown8 param_2)"), "{name}: {greet}");
        assert!(greet.contains("= fmt.Sprintf(") && greet.contains("return gVar1;"), "{name}: {greet}");
    }
}

#[test]
fn arm64_go_calls_leave_the_stack_pointer_trackable() {
    // The Go ARM64 specification once popped 8 bytes per call, as x86 does, and lost the stack pointer.
    let project = Project::new(fixture("hello-go-arm64.elf"));
    let main = project.decompile(project.resolve("main.main").unwrap()).unwrap().code;
    assert!(!main.contains("BADSPACEBASE") && !main.contains("register0x"), "{main}");
    assert!(main.contains("while (&stack0x00000000 <="), "{main}");
}

#[test]
fn user_signatures_and_c_conventions_replace_derived_go_prototypes() {
    let project = Project::new(fixture("hello-go-x64.elf"));
    let greet = project.resolve("main.greet").unwrap();
    project.set_signature(greet, Some("int8 greet(int8 who);")).unwrap();
    assert!(project.decompile(greet).unwrap().code.contains("int8 main.greet(int8 who)"));

    let project = Project::new(fixture("hello-go-x64.elf"));
    project.set_decompiler_options(Some(DecompilerOptions { compiler: Some("gcc".to_owned()), ..Default::default() }));
    assert!(!project.decompile(greet).unwrap().code.contains("go_results"));
}

#[test]
fn analyst_signatures_can_reuse_generated_go_result_types() {
    let project = Project::new(fixture("hello-go-x64.elf"));
    let greet = project.resolve("main.greet").unwrap();
    project.set_signature(greet, Some("go_results_2 greet(xunknown8 who, xunknown8 size);")).unwrap();
    assert!(project.decompile(greet).unwrap().code.contains("go_results_2 main.greet"));
}

#[test]
fn analyst_types_can_supply_generated_go_result_declarations() {
    let project = Project::new(fixture("hello-go-x64.elf"));
    let greet = project.resolve("main.greet").unwrap();
    project.set_types(1, Some("struct result_box { go_results_2 result; };")).unwrap();
    project.set_types(greet, Some("typedef struct{xunknown8 r0;\nxunknown8 r1;}go_results_2;")).unwrap();
    project.set_signature(greet, Some("go_results_2 greet(xunknown8 who, xunknown8 size);")).unwrap();
    assert!(project.decompile(greet).unwrap().code.contains("go_results_2 main.greet"));
    project.set_types(greet, None).unwrap();
    assert!(project.decompile(greet).unwrap().code.contains("go_results_2 main.greet"));
}
