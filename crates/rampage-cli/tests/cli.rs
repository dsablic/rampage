use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

const X64_FIXTURES: [(&str, &str); 3] =
    [("hello-x64.elf", "add"), ("hello-x64.exe", "add"), ("hello-x64.macho", "_add")];

#[test]
fn snapshot_disassembly_and_functions_use_captured_virtual_addresses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "disasm", "--count", "3"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let lines: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(lines[2]["flow"]["target"], "0x1010");
    Command::cargo_bin("rampage").unwrap().arg("funcs").arg(&path).assert().success();
    for command in ["audit", "metadata"] {
        Command::cargo_bin("rampage").unwrap().arg(command).arg(&path).assert().success();
    }
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "summarize", "--at", "0x1000"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let summary: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(summary["graph"]["edges"].as_array().unwrap().len(), 1);
    assert!(summary["ssa"]["definitions"].is_array());
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "pseudocode", "--at", "0x1000"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let pseudocode: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(pseudocode["structured"], false);
    assert!(pseudocode["text"].as_str().unwrap().contains("Partial ARM64 SSA"));
    let diamond = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-ssa-diamond.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "pseudocode", "--at", "0x1000", "--structured"])
        .arg(diamond)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let pseudocode: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(pseudocode["structured"], true);
    assert!(pseudocode["text"].as_str().unwrap().contains("} else {"));
    let table = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-jumptable.snapshot.json");
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "jump-table", "--at", "0x3000", "--count", "2"])
        .arg(table)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let table: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(table["entries"][1]["target"], "0x1004");
}

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
fn carve_lists_universal_slices_in_text_and_json() {
    let output = rampage(&["carve"], "hello-universal.macho").success().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "0x00000000 mach_o_fat validated big-endian extent 0xc2b0");
    assert_eq!(lines[1], "  slice x86_64 at 0x1000 size 0x2110");
    assert!(lines.contains(&"0x00001000 mach_o validated x86_64 64-bit little-endian extent 0x2110"), "{text}");
    assert!(lines.contains(&"3 candidates in 0xc2b0 of 0xc2b0 bytes"), "{text}");

    let carving = json(&["--json", "carve", "--max-candidates", "2"], "hello-universal.macho");
    assert_eq!(carving["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(carving["candidates"][1]["offset"], 0x1000);
    assert_eq!(carving["truncated"], true);
    assert!(carving["limitations"][0].as_str().unwrap().contains("candidate cap (2) at offset 0x4000"));
    for out_of_range in ["0", "4097"] {
        rampage(&["carve", "--max-candidates", out_of_range], "hello-universal.macho").failure();
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
fn disasm_on_arm64_prints_a64() {
    rampage(&["disasm", "--at", "_main", "--count", "4"], "hello-arm64.macho")
        .success()
        .stdout(predicates::str::contains("stp x29, x30, [sp, #-16]!"))
        .stdout(predicates::str::contains("adrp x0, 0x100000000"));
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
fn export_cfg_lists_blocks_edges_and_calls_of_every_function() {
    let functions = json(&["export-cfg"], "hello-x64.elf");
    let functions = functions.as_array().unwrap();
    assert_eq!(functions.len(), 41);
    let find = |address: &str| functions.iter().find(|function| function["address"] == address).unwrap();
    let main = find("0x1001910");
    assert_eq!(main["blocks"], serde_json::json!(["0x1001910"]));
    let references = main["references"].as_array().unwrap();
    assert!(references.iter().any(|reference| reference[1] == "0x1001e21" && reference[2] == "call"), "{main}");
    let puts = find("0x1001e21");
    let blocks = puts["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 12);
    let edges = puts["edges"].as_array().unwrap();
    assert!(!edges.is_empty());
    assert!(edges.iter().all(|edge| blocks.contains(&edge[0]) && blocks.contains(&edge[1])), "{puts}");
}

#[test]
fn export_cfg_keeps_a_function_whose_start_does_not_decode() {
    let functions = json(&["export-cfg"], "hello-arm.elf");
    let empty = functions.as_array().unwrap().iter().find(|function| function["address"] == "0x2036c").unwrap();
    assert_eq!(empty["blocks"], serde_json::json!([]));
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

#[test]
fn triage_imports_and_exports_commands() {
    rampage(&["triage"], "hello-x64.exe")
        .success()
        .stdout(predicates::str::contains("sha256"))
        .stdout(predicates::str::contains("imphash"))
        .stdout(predicates::str::contains(".text"));
    let triage = json(&["--json", "triage"], "hello-arm64.macho");
    assert_eq!(triage["details"]["format"], "macho");
    rampage(&["imports"], "hello-x64-dyn.elf").success().stdout(predicates::str::contains("puts"));
    rampage(&["exports"], "hello-x64.exe").success().stdout(predicates::str::contains("add"));
}

#[test]
fn signatures_reports_function_signatures_and_callee_keys_apart() {
    let output = std::env::temp_dir().join(format!("rampage-cli-build-db-{}.json", std::process::id()));
    let assert = Command::cargo_bin("rampage")
        .unwrap()
        .arg("signatures")
        .arg(fixture("eval-ref-x86_64.elf"))
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    std::fs::remove_file(&output).unwrap();
    let count = |field: &str| written.get(field).and_then(Value::as_object).map_or(0, |map| map.len());
    assert!(count("calls") > 0);
    let expected = format!(
        "wrote {} signatures and {} callee keys to {}\n",
        count("entries") + count("exact"),
        count("calls"),
        output.display()
    );
    assert.stdout(expected);
}

#[test]
fn rename_and_comment_persist_beside_the_binary() {
    let directory = std::env::temp_dir().join(format!("rampage-cli-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-x64.elf");
    std::fs::copy(fixture("hello-x64.elf"), &path).unwrap();
    let run = |args: &[&str]| assert_cmd::Command::cargo_bin("rampage").unwrap().args(args).arg(&path).assert();
    let path_text = path.to_str().unwrap();
    assert_cmd::Command::cargo_bin("rampage")
        .unwrap()
        .args(["rename", path_text, "main", "start_here"])
        .assert()
        .success();
    assert_cmd::Command::cargo_bin("rampage")
        .unwrap()
        .args(["comment", path_text, "start_here", "prints the greeting"])
        .assert()
        .success();
    run(&["funcs", "--name", "start_here"]).success().stdout(predicates::str::contains("start_here"));
    run(&["annotations"]).success().stdout(predicates::str::contains("prints the greeting"));
    assert!(directory.join("hello-x64.elf.rampage").exists());
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn annotate_batch_applies_a_json_file_all_or_nothing() {
    let directory = std::env::temp_dir().join(format!("rampage-cli-batch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-x64.elf");
    std::fs::copy(fixture("hello-x64.elf"), &path).unwrap();
    let entries = directory.join("entries.json");
    let rampage = |args: &[&str]| assert_cmd::Command::cargo_bin("rampage").unwrap().args(args).assert();
    let (path_text, entries_text) = (path.to_str().unwrap(), entries.to_str().unwrap());
    std::fs::write(&entries, r#"[{"at": "main", "name": "start_here"}, {"at": "puts", "name": "bad name"}]"#).unwrap();
    rampage(&["annotate-batch", path_text, entries_text])
        .failure()
        .stderr(predicates::str::contains("nothing applied"))
        .stderr(predicates::str::contains("entry 1"));
    rampage(&["check-names", path_text, "start_here", "puts"])
        .success()
        .stdout(predicates::str::contains("start_here  free"))
        .stdout(predicates::str::contains("puts  used by symbol"));
    std::fs::write(&entries, r#"[{"at": "main", "name": "start_here", "comment": "greets"}]"#).unwrap();
    rampage(&["annotate-batch", path_text, entries_text]).success().stdout(predicates::str::contains("1 of 1 entries"));
    rampage(&["annotations", path_text])
        .success()
        .stdout(predicates::str::contains("start_here"))
        .stdout(predicates::str::contains("greets"));
    std::fs::remove_dir_all(&directory).unwrap();
}
