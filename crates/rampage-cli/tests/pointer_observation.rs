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

#[test]
fn pointer_comparison_preserves_identity_and_explicit_slot_correspondence() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "compare-pointers", "--at", "0x3000", "--other-at", "0x1000"])
        .arg(&path)
        .arg("--other")
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["raw_value_change"], "changed");
    assert_eq!(result["before"]["slot"], "0x3000");
    assert_eq!(result["after"]["slot"], "0x1000");
    assert_eq!(result["before"]["capture_identity"], result["after"]["capture_identity"]);
}

#[test]
fn pointer_comparison_requires_snapshots_on_both_sides() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests");
    let snapshot = root.join("data/runtime-arm64.snapshot.json");
    let macho = root.join("fixtures/bin/hello-arm64.macho");
    for route in [&["compare-pointers"][..], &["runtime", "pointer", "compare"][..]] {
        for name in ["hello-x64.elf", "hello-x64.exe", "hello-arm64.macho"] {
            let native = root.join("fixtures/bin").join(name);
            Command::cargo_bin("rampage")
                .unwrap()
                .args(route)
                .arg(&native)
                .arg("--other")
                .arg(&native)
                .args(["--at", "0x1000", "--other-at", "0x1000"])
                .assert()
                .failure()
                .stdout("")
                .stderr(predicates::str::contains("pointer comparison requires snapshots"));
        }
        for (before, after) in [(&snapshot, &macho), (&macho, &snapshot)] {
            Command::cargo_bin("rampage")
                .unwrap()
                .args(route)
                .arg(before)
                .arg("--other")
                .arg(after)
                .args(["--at", "0x1000", "--other-at", "0x1000"])
                .assert()
                .failure()
                .stdout("")
                .stderr(predicates::str::contains("pointer comparison requires snapshots"));
        }
    }
}

#[test]
fn pointer_comparison_does_not_advertise_or_accept_unusable_peer_image_flags() {
    let missing = "/nonexistent/rampage-pointer-capture";
    for route in [&["compare-pointers"][..], &["runtime", "pointer", "compare"][..]] {
        for flag in ["--other-image-offset", "--other-image-length", "--original-image-offset"] {
            let output = Command::cargo_bin("rampage")
                .unwrap()
                .args(route)
                .args([missing, "--other", missing, "--at", "0", "--other-at", "0", flag, "37"])
                .assert()
                .failure()
                .get_output()
                .clone();
            assert_eq!(output.status.code(), Some(2), "{route:?}: {flag}");
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("unexpected argument"), "{error}");
            assert!(error.contains(flag), "{error}");
            assert!(!error.contains("cannot read"), "{error}");
        }
        let output = Command::cargo_bin("rampage").unwrap().args(route).arg("--help").output().unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(!help.contains("--other-image"), "{help}");
        assert!(!help.contains("--original-image"), "{help}");
    }
}

#[test]
fn nontrivial_image_selection_does_not_turn_embedded_json_into_a_pointer_snapshot() {
    struct Fixture(std::path::PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let root = Fixture(std::env::temp_dir().join(format!("rampage-cli-pointer-embedded-{}", std::process::id())));
    std::fs::create_dir(&root.0).unwrap();
    let snapshot =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let snapshot_bytes = std::fs::read(&snapshot).unwrap();
    let mut wrapper = vec![b'w'; 37];
    wrapper.extend_from_slice(&snapshot_bytes);
    let wrapper_path = root.0.join("wrapper.bin");
    std::fs::write(&wrapper_path, wrapper).unwrap();
    for route in [&["observe-pointer"][..], &["runtime", "pointer", "observe"][..]] {
        Command::cargo_bin("rampage")
            .unwrap()
            .args(route)
            .arg(&snapshot)
            .args(["--at", "0x3000", "--image-offset", "0"])
            .assert()
            .success();
        Command::cargo_bin("rampage")
            .unwrap()
            .args(route)
            .arg(&wrapper_path)
            .args(["--at", "0x3000", "--image-offset", "37"])
            .assert()
            .failure()
            .stdout("")
            .stderr(predicates::str::contains("no ELF, PE or Mach-O header"));
    }
}
