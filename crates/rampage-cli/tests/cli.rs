use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

const X64_FIXTURES: [(&str, &str); 3] =
    [("hello-x64.elf", "add"), ("hello-x64.exe", "add"), ("hello-x64.macho", "_add")];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn rampage(args: &[&str], file: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("rampage").unwrap().args(args).arg(fixture(file)).assert()
}

fn json(args: &[&str], file: &str) -> Value {
    let output = rampage(args, file).success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn every_command_succeeds_on_every_x64_fixture() {
    for (file, _) in X64_FIXTURES {
        for command in ["info", "disasm", "strings", "funcs"] {
            rampage(&[command], file).success();
            rampage(&["--json", command], file).success();
        }
    }
}

#[test]
fn info_json_reports_format_and_entry() {
    let info = json(&["--json", "info"], "hello-x64.elf");
    assert_eq!(info["format"], "elf");
    assert_eq!(info["arch"], "x86_64");
    assert!(info["entry"].as_u64().unwrap() > 0);
}

#[test]
fn strings_include_the_greeting() {
    for (file, _) in X64_FIXTURES {
        let output = rampage(&["strings"], file).success().get_output().stdout.clone();
        assert!(String::from_utf8(output).unwrap().contains("rampage fixture greeting"), "{file}");
    }
}

#[test]
fn funcs_include_add() {
    for (file, add) in X64_FIXTURES {
        let funcs = json(&["--json", "funcs"], file);
        assert!(funcs.as_array().unwrap().iter().any(|function| function["name"] == add), "{file}");
    }
}

#[test]
fn disasm_at_symbol_starts_at_that_symbol() {
    for (file, add) in X64_FIXTURES {
        let funcs = json(&["--json", "funcs"], file);
        let add_address = funcs.as_array().unwrap().iter().find(|function| function["name"] == add).unwrap()["address"]
            .as_u64()
            .unwrap();
        let lines = json(&["--json", "disasm", "--count", "3", "--at", add], file);
        let lines = lines.as_array().unwrap();
        assert_eq!(lines.len(), 3, "{file}");
        assert_eq!(lines[0]["address"].as_u64(), Some(add_address), "{file}");
        let hex_at = format!("{add_address:#x}");
        let by_hex = json(&["--json", "disasm", "--count", "3", "--at", &hex_at], file);
        assert_eq!(&by_hex, &Value::Array(lines.clone()), "{file}");
    }
}

#[test]
fn disasm_on_arm64_reports_unsupported_architecture() {
    rampage(&["disasm"], "hello-arm64.macho").failure().stderr(predicates::str::contains("unsupported architecture"));
}

#[test]
fn unknown_symbol_is_an_error() {
    rampage(&["disasm", "--at", "no_such_symbol"], "hello-x64.elf")
        .failure()
        .stderr(predicates::str::contains("no_such_symbol"));
}

#[test]
fn non_binary_input_is_an_error() {
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["info", env!("CARGO_MANIFEST_PATH")])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot parse binary"));
}

#[test]
fn arch_flag_selects_universal_slice() {
    assert_eq!(json(&["--json", "info"], "hello-universal.macho")["arch"], "x86_64");
    let arm = json(&["--json", "--arch", "arm64", "info"], "hello-universal.macho");
    assert_eq!(arm["arch"], "aarch64");
    assert_eq!(arm["slices"], serde_json::json!(["x86_64", "aarch64"]));
    rampage(&["--arch", "x86", "info"], "hello-universal.macho")
        .failure()
        .stderr(predicates::str::contains("x86 slice; the file contains x86_64, aarch64"));
}
