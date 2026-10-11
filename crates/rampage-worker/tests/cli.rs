use std::process::Command;

#[test]
#[ignore = "requires RAMPAGE_TEST_CLI pointing to the CLI executable"]
fn cli_isolated_mode_selects_explicit_worker_and_returns_typed_import_calls() {
    let executable = std::env::var_os("RAMPAGE_TEST_CLI");
    let Some(executable) = executable else { return };
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let output = Command::new(executable)
        .args(["decompile", "--isolated", "--at", "main"])
        .arg(fixture)
        .env("RAMPAGE_WORKER", env!("CARGO_BIN_EXE_rampage-worker"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("puts@plt(\"rampage fixture greeting\")"));
}
