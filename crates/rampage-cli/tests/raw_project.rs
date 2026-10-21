use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::{Value, json};

const MSP430: &[u8] = include_bytes!("../../../tests/fixtures/sleigh/msp430.bin");

/// An owned canonical temp directory holding one copy of the MSP430 fixture.
struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rampage-cli-raw-project-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("code.bin"), MSP430).unwrap();
        Self(path)
    }

    fn binary(&self) -> PathBuf {
        self.0.join("code.bin")
    }

    fn names(&self) -> Vec<OsString> {
        let mut names: Vec<_> = std::fs::read_dir(&self.0).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        names.sort();
        names
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request() -> Value {
    json!({
        "profile": "TI_MSP430:LE:16:default",
        "offset": 0,
        "length": MSP430.len(),
        "base_address": "0x4400",
        "seeds": ["0x4400", "0x4410"],
    })
}

fn rampage(args: &[&str], path: &Path) -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.args(args).arg(path);
    command
}

fn json_output(command: &mut Command) -> Value {
    let output = command.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn raw_json_lists_and_disassembles_seeded_functions_without_writing_files() {
    let fixture = Fixture::new();
    let raw = request().to_string();
    let functions = json_output(rampage(&["function", "list"], &fixture.binary()).args(["--json", "--raw-json", &raw]));
    let addresses: Vec<&str> =
        functions.as_array().unwrap().iter().map(|row| row["address"].as_str().unwrap()).collect();
    assert!(addresses.contains(&"0x4400"), "{functions}");
    assert!(addresses.contains(&"0x4410"), "{functions}");

    let lines = json_output(
        rampage(&["function", "disassemble"], &fixture.binary())
            .args(["--at", "0x4400", "--count", "4", "--json", "--raw-json", &raw]),
    );
    let lines = lines.as_array().unwrap();
    assert_eq!(lines[0]["address"], "0x4400", "{lines:?}");
    assert!(lines[0]["text"].as_str().unwrap().to_lowercase().contains("call"), "{lines:?}");

    assert_eq!(fixture.names(), [OsString::from("code.bin")]);
}

#[test]
fn raw_request_file_opens_the_same_project() {
    let fixture = Fixture::new();
    let request_dir = Fixture::new();
    let request_path = request_dir.0.join("request.json");
    std::fs::write(&request_path, request().to_string()).unwrap();
    let functions = json_output(
        rampage(&["function", "list"], &fixture.binary()).arg("--json").arg("--raw-request").arg(&request_path),
    );
    assert!(functions.as_array().unwrap().iter().any(|row| row["address"] == "0x4410"), "{functions}");
    assert_eq!(fixture.names(), [OsString::from("code.bin")]);
}

#[test]
fn raw_rejects_native_selectors_and_each_other() {
    let fixture = Fixture::new();
    let raw = request().to_string();
    for extra in [&["--arch", "x86_64"][..], &["--image-offset", "0"], &["--raw-request", "request.json"]] {
        rampage(&["function", "list"], &fixture.binary())
            .args(["--raw-json", &raw])
            .args(extra)
            .assert()
            .failure()
            .stderr(contains("cannot be used with"));
    }
    assert_eq!(fixture.names(), [OsString::from("code.bin")]);
}

#[test]
fn raw_rejects_commands_that_are_not_raw_capable() {
    let fixture = Fixture::new();
    let raw = request().to_string();
    // Annotations are raw-capable over MCP, but a one-shot CLI process would discard memory-only edits and could
    // only ever list nothing.
    for (command, extra) in [
        (&["binary", "triage"][..], &[][..]),
        (&["string", "list"], &[]),
        (&["annotation", "rename"], &["0x4400", "entry"]),
        (&["annotation", "list"], &[]),
    ] {
        rampage(command, &fixture.binary())
            .args(extra)
            .args(["--raw-json", &raw])
            .assert()
            .failure()
            .stderr(contains("does not open a Raw Project"));
    }
    assert_eq!(fixture.names(), [OsString::from("code.bin")]);
}

#[test]
fn raw_rejects_malformed_and_unknown_field_requests() {
    let fixture = Fixture::new();
    let mut unknown = request();
    unknown["compiler"] = json!("gcc");
    let mut bad_profile = request();
    bad_profile["profile"] = json!("x86_64");
    for (raw, message) in [
        ("{not json".to_owned(), "invalid Raw Project request"),
        (unknown.to_string(), "unknown field `compiler`"),
        (bad_profile.to_string(), "unsupported Raw profile"),
    ] {
        rampage(&["function", "list"], &fixture.binary())
            .args(["--json", "--raw-json", &raw])
            .assert()
            .failure()
            .stderr(contains(message));
    }
    assert_eq!(fixture.names(), [OsString::from("code.bin")]);
}
