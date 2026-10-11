use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;

#[test]
fn worker_failures_do_not_fall_back_to_native_in_process_decompilation() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let add = project.resolve("add").unwrap();
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(std::path::PathBuf::from("/nonexistent/rampage-worker")),
        ..Default::default()
    }));
    assert!(project.decompile(add).is_err());
    project.set_decompiler_worker(None);
    assert!(project.decompile(add).unwrap().code.contains("add("));
}
