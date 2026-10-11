use assert_cmd::Command;

#[test]
fn writable_pointer_observation_is_explicit_in_json_and_text() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-thumb-pointer.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "observe-pointer", "--at", "0x3004"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["raw_value"], "0x1003");
    assert_eq!(result["candidate_target"], "0x1002");
    assert_eq!(result["slot_permissions"]["write"], true);
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["observe-pointer", "--at", "0x3004"])
        .arg(path)
        .assert()
        .success()
        .stdout(predicates::str::contains("not a proven edge"));
}

#[test]
fn indirect_branch_reports_a_slot_link_without_converting_it_to_direct_flow() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "observe-indirect-branch", "--start", "0x1000", "--at", "0x1008"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["flow"]["kind"], "indirect_jump");
    assert_eq!(result["slot_status"], "linked");
    assert_eq!(result["pointer"]["slot"], "0x3000");
    assert_eq!(result["pointer"]["candidate_target"], "0x1010");
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["observe-indirect-branch", "--start", "0x1000", "--at", "0x1008"])
        .arg(path)
        .assert()
        .success()
        .stdout(predicates::str::contains("not a proven edge"));
}
