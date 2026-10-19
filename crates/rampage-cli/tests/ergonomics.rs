use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use serde_json::{Value, json};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-cli-ergonomics-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("owned.json"),json!({
            "format":"rampage-snapshot-v1","arch":"x86_64","provenance":"owned CLI ergonomics fixture; never executed",
            "seeds":["0x1000"],"regions":[
                {"name":"code","address":"0x1000","permissions":"r-x","bytes":"b807000000c3"},
                {"name":"data","address":"0x3000","permissions":"rw-","bytes":"0000000000000000"}
            ]
        }).to_string()).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("owned.json")
    }
    fn files(&self) -> BTreeMap<OsString, Vec<u8>> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect()
    }
    fn view(&self, args: &[&str], view: Option<&str>) -> Value {
        let mut command = Command::cargo_bin("rampage").unwrap();
        command.arg("--json").args(args).arg(self.path());
        if let Some(view) = view {
            command.args(["--view", view]);
        }
        let output = command.assert().success();
        assert!(output.get_output().stdout.len() <= 60001);
        serde_json::from_slice(&output.get_output().stdout).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_cli_views_share_full_default_and_keep_code_and_identity_evidence_without_writes() {
    let fixture = Fixture::new();
    let before = fixture.files();
    for args in [
        &["binary", "inspect"][..],
        &["function", "disassemble", "--at", "sub_1000", "--count", "2"][..],
        &["function", "graph", "--at", "sub_1000"][..],
        &["function", "summarize", "--at", "sub_1000"][..],
        &["function", "decompile", "--at", "sub_1000"][..],
    ] {
        let full = fixture.view(args, None);
        assert_eq!(fixture.view(args, Some("full")), full, "{args:?}");
        let summary = fixture.view(args, Some("summary"));
        assert!(summary["view_projection"]["omissions"].is_array());
        if args[1] != "inspect" {
            let code = fixture.view(args, Some("code"));
            if args[1] == "disassemble" {
                assert_eq!(code, full);
            }
            if args[1] == "decompile" {
                assert_eq!(code["code"], full["code"]);
                assert_eq!(code["recovery_status"], full["recovery_status"]);
                assert_eq!(code["language_id"], full["language_id"]);
            }
        }
    }
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "inspect", "--view", "code"])
        .arg(fixture.path())
        .assert()
        .failure();
    assert_eq!(fixture.files(), before);
}

#[test]
fn standalone_data_cli_view_retains_metadata_and_refuses_code() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let before = std::fs::read(&path).unwrap();
    let at = format!("{:#x}", rampage_loaders::Binary::open(&path).unwrap().entry.unwrap());
    let mut values = Vec::new();
    for view in ["full", "summary"] {
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "inspect-data"])
            .arg(&path)
            .args(["--at", &at, "--size", "16", "--view", view])
            .assert()
            .success();
        values.push(serde_json::from_slice::<Value>(&output.get_output().stdout).unwrap());
    }
    assert_eq!(values[0]["address"], values[1]["address"]);
    assert_eq!(values[0]["limitations"], values[1]["limitations"]);
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "inspect-data"])
        .arg(&path)
        .args(["--at", &at, "--size", "16", "--view", "code"])
        .assert()
        .failure();
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn function_batch_accepts_explicit_file_or_inline_and_rejections_leave_whole_log_unchanged() {
    let fixture = Fixture::new();
    let source = std::fs::read(fixture.path()).unwrap();
    let request = json!({"entries":[
        {"operation":"rename","at":"sub_1000","value":"reviewed_entry"},
        {"operation":"comment","at":"sub_1000","value":"same pre-batch target"},
        {"operation":"signature","at":"4097","value":"batch_number reviewed_entry(void);"},
        {"operation":"types","at":"sub_1000","value":"typedef int4 batch_number;"},
        {"operation":"global","at":"0x3000","value":"batch_number reviewed_counter;"}
    ]});
    let input = fixture.0.join("batch.json");
    std::fs::write(&input, request.to_string()).unwrap();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["function", "batch"])
        .arg(fixture.path())
        .arg("--entries")
        .arg(&input)
        .assert()
        .success();
    assert_eq!(serde_json::from_slice::<Value>(&output.get_output().stdout).unwrap()["changed"], 5);
    let before = fixture.files();
    for request in [
        json!({"entries":[{"operation":"comment","at":"reviewed_entry"}]}),
        json!({"entries":[{"operation":"comment","at":"reviewed_entry","value":"\"".repeat(30000)}]}),
        json!({"entries":[
            {"operation":"comment","at":"reviewed_entry","value":"would change"},
            {"operation":"signature","at":"reviewed_entry","value":"not a declaration"}
        ]}),
    ] {
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["function", "batch"])
            .arg(fixture.path())
            .arg("--entries-json")
            .arg(request.to_string())
            .assert()
            .failure();
        assert_eq!(fixture.files(), before);
    }
    let clear = json!({"entries":[
        {"operation":"rename","at":"reviewed_entry","value":null},
        {"operation":"comment","at":"reviewed_entry","value":null},
        {"operation":"signature","at":"reviewed_entry","value":null},
        {"operation":"types","at":"reviewed_entry","value":null},
        {"operation":"global","at":"0x3000","value":null}
    ]});
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["function", "batch"])
        .arg(fixture.path())
        .arg("--entries-json")
        .arg(clear.to_string())
        .assert()
        .success();
    assert_eq!(std::fs::read(fixture.path()).unwrap(), source);
}
