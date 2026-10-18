use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new(arch: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-cli-assembly-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let code = if arch == "aarch64" { "00008052c0035fd6" } else { "b800000000c3" };
        std::fs::write(
            root.join("owned.json"),
            json!({
                "format":"rampage-snapshot-v1", "arch":arch,"provenance":"owned assembly CLI fixture; never executed",
                "seeds":["0x1000"],"regions":[{"name":"code","address":"0x1000","permissions":"r-x","bytes":code}]
            })
            .to_string(),
        )
        .unwrap();
        let fixture = Self(root);
        let project = rampage_api::Session::default().open(&fixture.path(), None).unwrap();
        project.rename(0x1000, Some("analyst_function")).unwrap();
        project.comment(0x1000, Some("preserve existing annotations")).unwrap();
        fixture
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
    fn assemble(&self, source: &str, nested: bool) -> Value {
        let mut command = Command::cargo_bin("rampage").unwrap();
        if nested {
            command.arg("binary");
        }
        let output = command
            .arg("assemble")
            .arg(self.path())
            .args(["--at", "analyst_function", "--source", source])
            .assert()
            .success();
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
fn nested_and_compat_assembly_return_target_vectors_without_modifying_any_source_or_annotation_file() {
    for (arch, source, bytes) in
        [("x86_64", "mov eax,7\nret", "b807000000c3"), ("aarch64", "mov w0,7\nret", "e0008052c0035fd6")]
    {
        let fixture = Fixture::new(arch);
        let before = fixture.files();
        let nested = fixture.assemble(source, true);
        assert_eq!(nested, fixture.assemble(source, false));
        assert_eq!(nested["architecture"], arch);
        assert_eq!(nested["address"], "0x1000");
        assert_eq!(nested["bytes_hex"], bytes);
        assert_eq!(nested["instruction_count"], 2);
        assert_eq!(nested["canonical_disassembly"].as_array().unwrap().len(), 2);
        assert_eq!(nested["read_only"], true);
        assert_eq!(nested["execution_verified"], false);
        assert_eq!(fixture.files(), before);
    }
}

#[test]
fn literal_source_errors_limits_and_x86_bitness_cannot_become_file_io_or_implicit_application() {
    let fixture = Fixture::new("x86");
    let before = fixture.files();
    for source in ["mov rax,7", "nop\ninvalid", ".byte 0x90", "mov eax,[eax]", "/bin/sh", "jmp analyst_function"] {
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "assemble"])
            .arg(fixture.path())
            .args(["--at", "analyst_function", "--source", source])
            .assert()
            .failure();
        assert!(String::from_utf8_lossy(&output.get_output().stderr).contains("assembly line"));
        assert_eq!(fixture.files(), before);
    }
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "assemble"])
        .arg(fixture.path())
        .args(["--at", "analyst_function", "--source", "nop\ninvalid"])
        .assert()
        .failure()
        .stderr(contains("assembly line 2"));
    for source in ["nop\n".repeat(65), " ".repeat(16 * 1024 + 1)] {
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "assemble"])
            .arg(fixture.path())
            .args(["--at", "analyst_function", "--source"])
            .arg(source)
            .assert()
            .failure();
    }
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "assemble"])
        .arg(fixture.path())
        .args(["--at", "missing_name", "--source", "nop"])
        .assert()
        .failure()
        .stderr(contains("no symbol or export"));
    assert_eq!(fixture.files(), before);
}
