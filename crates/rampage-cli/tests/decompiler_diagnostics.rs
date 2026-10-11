use assert_cmd::Command;
use predicates::str::contains;
use std::path::PathBuf;

#[test]
fn produced_code_exposes_incomplete_recovery_in_text_and_json() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-x64-bad-code.snapshot.json");
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["decompile", "--at", "0x1000"])
        .arg(&path)
        .assert()
        .success()
        .stdout(contains("Recovery: incomplete recovery"));
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "decompile", "--at", "0x1000"])
        .arg(path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["recovery_status"], "incomplete");
    assert_eq!(result["structure"]["diagnostics"]["bad_data"], true);
    assert!(
        result["structure"]["diagnostics"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["address"] == "0x1000")
    );
}
