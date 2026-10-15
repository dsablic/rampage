use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::{Value, json};

const DECOMPILE_COMMANDS: &[&[&str]] = &[&["function", "decompile"], &["decompile"]];
const AUDIT_COMMANDS: &[&[&str]] = &[&["binary", "audit"], &["audit"]];

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests").join(relative)
}

fn decompile(command: &[&str], relative: &str, at: &str, exact: bool, json: bool) -> Vec<u8> {
    let mut cli = Command::cargo_bin("rampage").unwrap();
    if json {
        cli.arg("--json");
    }
    cli.args(command).arg(fixture(relative)).args(["--at", at]);
    if exact {
        cli.arg("--exact-entry");
    }
    cli.assert().success().get_output().stdout.clone()
}

fn assert_exact_context(result: &Value, mapped_backing_checked: bool) {
    assert!(result["code"].is_string(), "{result}");
    assert!(result["address"].is_string(), "{result}");
    assert!(result.get("decompilation").is_none(), "{result}");
    let context = &result["context"];
    assert_eq!(context["scope"], "exact_entry");
    assert_eq!(context["validation"], "analyst_asserted");
    assert_eq!(context["full_image_mapping"], true);
    assert_eq!(context["mapped_backing_checked"], mapped_backing_checked);
    assert!(context["mapped_backed_bytes"].as_u64().unwrap() > 0);
    assert!(!context["omissions"].as_array().unwrap().is_empty());
}

#[test]
fn canonical_and_legacy_exact_flags_keep_root_json_and_native_bad_code_diagnostics() {
    for command in DECOMPILE_COMMANDS {
        let output = decompile(command, "data/runtime-x64-bad-code.snapshot.json", "0x1000", true, true);
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_exact_context(&result, false);
        assert_eq!(result["address"], "0x1000");
        assert_eq!(result["recovery_status"], "incomplete");
        assert_eq!(result["structure"]["diagnostics"]["bad_data"], true);
        assert!(result["structure"]["diagnostics"]["warnings"].as_array().unwrap().iter().any(|warning| {
            warning["address"] == "0x1000" && warning["message"].as_str().unwrap().contains("Bad instruction")
        }));
        let text = decompile(command, "data/runtime-x64-bad-code.snapshot.json", "0x1000", true, false);
        let text = String::from_utf8(text).unwrap();
        for visible in ["Exact-entry", "Context:", "whole-program", "incomplete", "Bad instruction"] {
            assert!(text.contains(visible), "missing {visible:?}: {text}");
        }
    }
}

#[test]
fn exact_elf_entry_keeps_import_argument_string_return_and_stronger_metadata_origin() {
    let output = decompile(DECOMPILE_COMMANDS[0], "fixtures/bin/hello-x64-dyn.elf", "main", true, true);
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_exact_context(&result, true);
    let code = result["code"].as_str().unwrap();
    assert!(code.contains("puts@plt(\"rampage fixture greeting\")"), "{code}");
    assert!(code.contains("return 5;"), "{code}");
    assert!(result["context"]["origins"].as_array().unwrap().contains(&json!("function_symbol")));
    assert!(result["context"]["counts"]["stub_aliases"].as_u64().unwrap() > 0);
}

#[test]
fn exact_aarch64_entry_retains_the_owned_hello_return_value() {
    let output = decompile(DECOMPILE_COMMANDS[0], "fixtures/bin/hello-arm64.elf", "main", true, true);
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_exact_context(&result, true);
    assert!(result["language_id"].as_str().unwrap().starts_with("AARCH64:"));
    assert!(result["code"].as_str().unwrap().contains("return 5;"), "{result}");
}

#[test]
fn exact_pe_entry_selects_windows_argument_recovery_without_an_override() {
    let output = decompile(DECOMPILE_COMMANDS[0], "fixtures/bin/hello-x64.exe", "add", true, true);
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_exact_context(&result, true);
    assert_eq!(result["language_id"], "x86:LE:64:default:windows");
    assert_eq!(result["structure"]["signature"]["parameters"].as_array().unwrap().len(), 2);
    assert!(!result["code"].as_str().unwrap().contains("param_3"), "{result}");
}

#[test]
fn omitting_exact_entry_keeps_both_legacy_response_shapes() {
    for command in DECOMPILE_COMMANDS {
        let output = decompile(command, "fixtures/bin/hello-x64-dyn.elf", "main", false, true);
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert!(result["code"].as_str().unwrap().contains("puts@plt("), "{result}");
        assert!(result.get("context").is_none(), "{result}");
    }
}

#[test]
fn entry_audit_accepts_exact_addresses_and_rejects_invalid_combinations_before_loading() {
    let missing = fixture("entry-scope-missing-image.elf");
    assert!(!missing.exists());
    for command in AUDIT_COMMANDS {
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .arg("--json")
            .args(*command)
            .arg(fixture("data/runtime-x64-bad-code.snapshot.json"))
            .args(["--entries", "--at", "0x1000"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let audit: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(audit["entries"].as_array().unwrap().len(), 1);
        assert_eq!(audit["entries"][0]["address"], "0x1000");
        assert!(!audit["limitations"].as_array().unwrap().is_empty());

        for flags in [&["--at", "0x1000"][..], &["--entries", "--include-discovery"][..]] {
            let output = Command::cargo_bin("rampage")
                .unwrap()
                .args(*command)
                .arg(&missing)
                .args(flags)
                .assert()
                .code(2)
                .get_output()
                .stderr
                .clone();
            let error = String::from_utf8(output).unwrap();
            assert!(error.contains("--entries"), "{error}");
            assert!(error.contains("required") || error.contains("cannot be used"), "{error}");
            assert!(!error.contains("No such file"), "{error}");
        }
    }
}
