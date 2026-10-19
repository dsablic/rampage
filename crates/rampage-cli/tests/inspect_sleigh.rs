use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use serde_json::{Value, json};

struct Owned(PathBuf);
impl Owned {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-cli-inspect-sleigh-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn fixture(&self, name: &str) -> (PathBuf, usize) {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/fixtures/sleigh/{name}.bin")),
        )
        .unwrap();
        let mut source = vec![0xab; 7];
        source.extend_from_slice(&bytes);
        source.extend_from_slice(&[0xcd; 3]);
        let path = self.0.join(format!("{name}.raw"));
        std::fs::write(&path, source).unwrap();
        (path, bytes.len())
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
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn output(path: &Path, request: &Value, nested: bool) -> Value {
    let mut command = Command::cargo_bin("rampage").unwrap();
    if nested {
        command.arg("binary");
    }
    let result =
        command.arg("inspect-sleigh").arg(path).arg("--request-json").arg(request.to_string()).assert().success();
    assert!(result.get_output().stdout.len() <= 60001);
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

#[test]
fn raw_listing_and_seeded_discovery_are_user_visible_without_executable_admission_or_source_writes() {
    let owned = Owned::new();
    let mut functions = 0;
    for (name, profile, base, returned) in [
        ("msp430", "TI_MSP430:LE:16:default", 0x4400, 8),
        ("avr8", "avr8:LE:16:default", 0x200, 8),
        ("6502", "6502:LE:16:default", 0x8000, 7),
    ] {
        let (path, length) = owned.fixture(name);
        let before = owned.files();
        let request = json!({"profile":profile,"offset":7,"length":length,"base_address":format!("{base:#x}")});
        let report = output(&path, &request, true);
        assert_eq!(report["rows"][0]["address"], format!("{base:#x}"));
        assert_eq!(report["rows"][0]["source_byte_offset"], 7);
        assert_eq!(report["rows"][0]["flow"]["target"], base + 16);
        assert!(
            report["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["address"] == format!("{:#x}", base + returned) && row["flow"]["kind"] == "return")
        );
        assert!(report["profile"]["abi"].as_str().unwrap().contains("unknown"));
        assert_eq!(report["source_range_sha256"], report["source_range_sha256_after"]);
        let legacy = output(&path, &request, false);
        assert_eq!(legacy["rows"], report["rows"]);
        assert_eq!(legacy["profile"], report["profile"]);
        let mut request = request;
        request["discover"] = json!(true);
        request["seeds"] = json!([base]);
        request["listing_limit"] = json!(1);
        let report = output(&path, &request, true);
        let entries = report["program"]["functions"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "{name}: {report}");
        assert_eq!(entries[0]["address"], format!("{base:#x}"));
        assert_eq!(entries[1]["address"], format!("{:#x}", base + 16));
        functions += entries.len();
        assert_eq!(owned.files(), before);
    }
    assert_eq!(functions, 6);
}

#[test]
fn request_file_is_explicit_bounded_and_invalid_profiles_coordinates_or_native_flags_fail_without_writes() {
    let owned = Owned::new();
    let (path, length) = owned.fixture("6502");
    let valid = json!({"profile":"6502:LE:16:default","offset":"0x7","length":length,"base_address":"0x8000"});
    let query = owned.0.join("request.json");
    std::fs::write(&query, valid.to_string()).unwrap();
    let before = owned.files();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "inspect-sleigh"])
        .arg(&path)
        .arg("--request")
        .arg(&query)
        .assert()
        .success();
    for (field, value) in [
        ("profile", json!("/tmp/custom.sla")),
        ("base_address", json!("main")),
        ("length", json!(65537)),
        ("seeds", json!(["0x8000"])),
        ("arch", json!("6502")),
        ("compiler_spec", json!("default")),
    ] {
        let mut request = valid.clone();
        request[field] = value;
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "inspect-sleigh"])
            .arg(&path)
            .arg("--request-json")
            .arg(request.to_string())
            .assert()
            .failure();
        assert_eq!(owned.files(), before);
    }
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["--arch", "x86_64", "binary", "inspect-sleigh"])
        .arg(&path)
        .arg("--request-json")
        .arg(valid.to_string())
        .assert()
        .failure();
    #[cfg(unix)]
    {
        let link = owned.0.join("request-link.json");
        std::os::unix::fs::symlink(&query, &link).unwrap();
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "inspect-sleigh"])
            .arg(&path)
            .arg("--request")
            .arg(link)
            .assert()
            .failure();
        Command::cargo_bin("rampage")
            .unwrap()
            .args(["binary", "inspect-sleigh"])
            .arg(&path)
            .args(["--request", "/dev/zero"])
            .assert()
            .failure();
    }
    std::fs::OpenOptions::new().write(true).open(&query).unwrap().set_len(1024 * 1024 + 1).unwrap();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["binary", "inspect-sleigh"])
        .arg(&path)
        .arg("--request")
        .arg(query)
        .assert()
        .failure();
    assert_eq!(std::fs::read(path).unwrap(), before[&OsString::from("6502.raw")]);
}
