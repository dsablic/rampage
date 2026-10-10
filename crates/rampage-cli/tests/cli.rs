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

fn address(value: &Value) -> u64 {
    let text = value.as_str().unwrap_or_else(|| panic!("address is not a string: {value}"));
    u64::from_str_radix(text.strip_prefix("0x").expect("0x prefix"), 16).unwrap()
}

fn json(args: &[&str], file: &str) -> Value {
    let output = rampage(args, file).success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn every_command_succeeds_on_every_x64_fixture() {
    for (file, _) in X64_FIXTURES {
        for command in ["info", "disasm", "strings", "funcs", "funcs --symbols-only"] {
            let command: Vec<&str> = command.split(' ').collect();
            let json_command: Vec<&str> = std::iter::once("--json").chain(command.iter().copied()).collect();
            rampage(&command, file).success();
            rampage(&json_command, file).success();
        }
    }
}

#[test]
fn info_json_reports_format_and_entry() {
    let info = json(&["--json", "info"], "hello-x64.elf");
    assert_eq!(info["format"], "elf");
    assert_eq!(info["arch"], "x86_64");
    assert!(address(&info["entry"]) > 0);
    assert!(json(&["--json", "info"], "hello-x64.dylib")["entry"].is_null());
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
        let add_address =
            address(&funcs.as_array().unwrap().iter().find(|function| function["name"] == add).unwrap()["address"]);
        let lines = json(&["--json", "disasm", "--count", "3", "--at", add], file);
        let lines = lines.as_array().unwrap();
        assert_eq!(lines.len(), 3, "{file}");
        assert_eq!(address(&lines[0]["address"]), add_address, "{file}");
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

#[test]
fn library_without_entry_needs_explicit_disasm_address() {
    rampage(&["disasm"], "hello-x64.dylib").failure().stderr(predicates::str::contains("no entry point"));
    rampage(&["disasm", "--at", "_add"], "hello-x64.dylib").success();
    let funcs = json(&["--json", "funcs"], "hello-x64.dylib");
    assert!(funcs.as_array().unwrap().iter().all(|function| function["name"] != "entry"));
}

#[test]
fn json_output_into_a_closed_pipe_exits_cleanly() {
    use std::io::Read;
    use std::process::{Command as Process, Stdio};

    let mut child = Process::new(assert_cmd::cargo::cargo_bin("rampage"))
        .args(["--json", "strings"])
        .arg(fixture("hello-x64.exe"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert!(status.success(), "{status}: {stderr}");
}

#[test]
fn malformed_inputs_do_not_crash() {
    let malformed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/malformed");
    for name in ["wrap.elf", "trunc.elf", "i386.macho", "ppc_i386.fat", "badimport.exe"] {
        for command in ["info", "strings", "funcs"] {
            let output =
                Command::cargo_bin("rampage").unwrap().arg(command).arg(malformed.join(name)).output().unwrap();
            assert!(output.status.success(), "{command} {name}: {}", String::from_utf8_lossy(&output.stderr));
        }
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .args(["disasm", "--count", "500"])
            .arg(malformed.join(name))
            .output()
            .unwrap();
        assert!(output.status.code().is_some(), "disasm {name} was killed by a signal");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"), "disasm {name} panicked");
    }
}

fn function_named<'a>(funcs: &'a Value, name: &str) -> Option<&'a Value> {
    funcs.as_array().unwrap().iter().find(|function| function["name"] == name)
}

#[test]
fn funcs_discovers_stripped_functions() {
    let add = address(&function_named(&json(&["--json", "funcs"], "hello-x64.macho"), "_add").unwrap()["address"]);
    let stripped = json(&["--json", "funcs"], "hello-x64-stripped.macho");
    let found = function_named(&stripped, &format!("sub_{add:x}")).expect("add found without symbols");
    assert!(found["instructions"].as_u64().unwrap() >= 2);
    assert!(found["blocks"].as_u64().unwrap() >= 1);
}

#[test]
fn xrefs_to_puts_come_from_main() {
    let xrefs = json(&["--json", "xrefs", "--to", "puts"], "hello-x64.elf");
    let xrefs = xrefs.as_array().unwrap();
    assert!(xrefs.iter().any(|xref| xref["kind"] == "call" && xref["from_function"] == "main"), "{xrefs:?}");
}

#[test]
fn xrefs_from_main_include_the_call_to_puts() {
    let xrefs = json(&["--json", "xrefs", "--from", "main"], "hello-x64.elf");
    let xrefs = xrefs.as_array().unwrap();
    assert!(xrefs.iter().any(|xref| xref["kind"] == "call" && xref["to_name"] == "puts"), "{xrefs:?}");
    assert!(xrefs.iter().all(|xref| xref["from_function"] == "main"));
}

#[test]
fn xrefs_requires_a_direction() {
    rampage(&["xrefs"], "hello-x64.elf").failure();
}

#[test]
fn sub_names_resolve_as_addresses() {
    let lines = json(&["--json", "disasm", "--count", "1", "--at", "sub_1001910"], "hello-x64.elf");
    assert_eq!(lines[0]["address"], "0x1001910");
}

#[test]
fn funcs_ignores_headers_and_strings_in_executable_segments() {
    let funcs = json(&["--json", "funcs"], "hello-x64-stripped.macho");
    let names: Vec<_> = funcs.as_array().unwrap().iter().map(|function| function["name"].as_str().unwrap()).collect();
    assert!(!names.contains(&"__mh_execute_header"), "{names:?}");
    assert!(funcs.as_array().unwrap().iter().all(|function| function["instructions"].as_u64().unwrap() < 100));
}

#[test]
fn json_addresses_are_hex_strings() {
    let lines = json(&["--json", "disasm", "--count", "4", "--at", "main"], "hello-x64.elf");
    assert_eq!(lines[0]["address"], "0x1001910");
    let call = lines.as_array().unwrap().iter().find(|line| line["flow"]["kind"] == "call").unwrap();
    assert!(call["flow"]["target"].as_str().unwrap().starts_with("0x"));
    let info = json(&["--json", "info"], "hello-x64.elf");
    assert!(info["segments"][0]["address"].as_str().unwrap().starts_with("0x"));
    assert!(info["segments"][0]["size"].is_u64(), "sizes stay numeric");
}

#[test]
fn mcp_subcommand_speaks_json_rpc_over_stdio() {
    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0" },
        },
    });
    let requests = [
        initialize.to_string(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_owned(),
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_owned(),
    ];
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .arg("mcp")
        .write_stdin(requests.join("\n") + "\n")
        .timeout(std::time::Duration::from_secs(10))
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let responses: Vec<Value> = stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let tools = responses.iter().find(|response| response["id"] == 2).expect("tools/list response");
    let names: Vec<_> = tools["result"]["tools"].as_array().unwrap().iter().map(|tool| tool["name"].clone()).collect();
    assert!(names.contains(&Value::from("list_functions")), "{names:?}");
}
