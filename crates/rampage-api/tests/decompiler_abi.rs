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
