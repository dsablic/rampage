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
