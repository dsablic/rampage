use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use serde_json::Value;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-cli-patches-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf"),
            directory.join("source.elf"),
        )
        .unwrap();
        Self(directory)
    }

    fn command(&self, action: &str) -> Command {
        let mut command = Command::cargo_bin("rampage").unwrap();
        command.args(["binary", action]).arg(self.0.join("source.elf"));
        command
    }

    fn list(&self) -> Value {
        output(&mut self.command("list-patches"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn output(command: &mut Command) -> Value {
    let result = command.assert().success();
    assert!(result.get_output().stdout.len() <= 60001);
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

fn review(command: &mut Command, receipt: &Value) {
    command.args([
        "--source-sha256",
        receipt["source_sha256"].as_str().unwrap(),
        "--expected-revision",
        receipt["revision_sha256"].as_str().unwrap(),
    ]);
}

#[test]
fn cli_patch_list_export_and_revert_use_persistent_effective_bytes_without_overwriting_source() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source.elf");
    let original = std::fs::read(&source).unwrap();
    let baseline = fixture.list();
    let mut patch = fixture.command("patch-bytes");
    patch.args([
        "--at",
        "0x100191e",
        "--original-hex",
        "b805000000",
        "--replacement-hex",
        "b807000000",
        "--allow-data",
        "false",
    ]);
    review(&mut patch, &baseline["receipt"]);
    assert_eq!(output(&mut patch)["changed"], true);
    let patched = fixture.list();
    assert_eq!(patched["patches"][0]["replacement_hex"], "b807000000");
    let destination = fixture.0.join("export.elf");
    let mut export = fixture.command("export-patched");
    export.arg("--destination").arg(&destination);
    review(&mut export, &patched["receipt"]);
    output(&mut export);
    assert_eq!(&std::fs::read(&destination).unwrap()[0x91e..0x923], &[0xb8, 7, 0, 0, 0]);
    export.assert().failure();
    let mut revert = fixture.command("revert-patch");
    revert.args(["--at", "0x100191e"]);
    review(&mut revert, &patched["receipt"]);
    assert_eq!(output(&mut revert)["changed"], true);
    assert!(fixture.list()["patches"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::read(source).unwrap(), original);
    assert!(!fixture.0.join("export.elf.rampage").exists());
}

#[test]
fn cli_requires_explicit_preimage_review_and_boolean_data_consent() {
    let fixture = Fixture::new();
    fixture.command("patch-bytes").args(["--at", "0x100191e"]).assert().failure();
    let baseline = fixture.list();
    let mut patch = fixture.command("patch-bytes");
    patch.args(["--at", "0x100191e", "--original-hex", "b805000000", "--replacement-hex", "b807000000"]);
    review(&mut patch, &baseline["receipt"]);
    patch.assert().failure();
    assert_eq!(fixture.list()["receipt"], baseline["receipt"]);
    let destination = fixture.0.join("stale.elf");
    fixture
        .command("export-patched")
        .arg("--destination")
        .arg(&destination)
        .args([
            "--source-sha256",
            baseline["receipt"]["source_sha256"].as_str().unwrap(),
            "--expected-revision",
            &"0".repeat(64),
        ])
        .assert()
        .failure();
    assert!(!destination.exists());
}
