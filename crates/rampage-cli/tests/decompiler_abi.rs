use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

#[test]
fn compiler_override_changes_argument_recovery_and_rejects_unknown_specs() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-x64-windows-arguments.snapshot.json");
    for (compiler, extra_args) in [("windows", false), ("gcc", true)] {
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .args(["--json", "decompile", "--at", "0x1000", "--compiler", compiler])
            .arg(&path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["code"].as_str().unwrap().contains("param_3"), extra_args);
        assert!(result["language_id"].as_str().unwrap().ends_with(compiler));
    }
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["decompile", "--at", "0x1000", "--compiler", "not_a_spec"])
        .arg(&path)
        .assert()
        .failure();
}

#[test]
fn pe_images_select_windows_without_an_override() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "decompile", "--at", "add"])
        .arg(path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["language_id"], "x86:LE:64:default:windows");
    assert!(!result["code"].as_str().unwrap().contains("param_3"));
}
