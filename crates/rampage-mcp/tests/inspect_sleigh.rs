//! Actual duplex MCP coverage of asserted raw windows; no target bytes are executed.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(20);
#[derive(Default)]
struct TestClient;
impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}
type Client = RunningService<RoleClient, TestClient>;
struct Server(JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Connection {
    client: Option<Client>,
    server: Server,
}
impl Connection {
    async fn connect() -> Self {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = Server(tokio::spawn(async move {
            RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
        }));
        let client = timeout(TIMEOUT, TestClient.serve(client_transport)).await.unwrap().unwrap();
        let listed = timeout(TIMEOUT, client.list_all_tools()).await.unwrap().unwrap();
        let tool =
            listed.iter().find(|tool| tool.name == "inspect_sleigh").expect("standalone Core tool is initially listed");
        assert!(tool.input_schema["properties"].get("path").is_some());
        for native_field in ["arch", "image_offset", "image_length"] {
            assert!(tool.input_schema["properties"].get(native_field).is_none());
        }
        let roster = tool.input_schema["properties"]["profile"]["enum"].as_array().unwrap();
        assert_eq!(roster.len(), 20);
        for profile in [
            "8051:BE:16:default",
            "PIC-16:LE:16:PIC-16",
            "SuperH:BE:32:SH-2",
            "V850:LE:32:default",
            "tricore:LE:32:default",
            "Xtensa:LE:32:default",
            "z80:LE:16:default",
            "HCS-12:BE:24:default",
            "6805:BE:16:default",
            "CR16C:LE:16:default",
            "eBPF:LE:64:default",
            "Loongarch:LE:64:lp64d",
            "Hexagon:LE:32:default",
        ] {
            assert!(roster.iter().any(|id| id == profile));
        }
        assert!(
            !tool.input_schema["properties"]["profile"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|profile| profile == "MIPS:BE:32:default")
        );
        Self { client: Some(client), server }
    }
    async fn call(&self, path: &Path, mut args: Value) -> CallToolResult {
        args["path"] = json!(path);
        timeout(
            TIMEOUT,
            self.client.as_ref().unwrap().call_tool(
                CallToolRequestParams::new("inspect_sleigh".to_owned())
                    .with_arguments(args.as_object().unwrap().clone()),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn shutdown(mut self) {
        timeout(TIMEOUT, self.client.take().unwrap().cancel()).await.unwrap().unwrap();
        timeout(TIMEOUT, &mut self.server.0).await.unwrap().unwrap();
    }
}
fn text(result: &CallToolResult) -> &str {
    &result.content.first().unwrap().as_text().unwrap().text
}
fn body(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    assert!(text(result).len() <= 60000);
    serde_json::from_str(text(result)).expect("whole typed Sleigh report, never cut strings")
}
struct Owned(PathBuf);
impl Owned {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-inspect-sleigh-{}-{}",
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
        let path = self.0.join(format!("{}.raw", Path::new(name).file_name().unwrap().to_str().unwrap()));
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

#[tokio::test]
async fn raw_profiles_keep_caller_only_six_and_preserve_the_explicit_valid_unknown_entry() {
    timeout(Duration::from_secs(150), async {
        let owned = Owned::new();
        let connection = Connection::connect().await;
        let mut count = 0;
        for (name, profile, base, return_offset) in [
            ("msp430", "TI_MSP430:LE:16:default", 0x4400, 8),
            ("avr8", "avr8:LE:16:default", 0x200, 8),
            ("6502", "6502:LE:16:default", 0x8000, 7),
        ] {
            let (path, length) = owned.fixture(name);
            let before = owned.files();
            let request = json!({"profile":profile,"offset":"0x7","length":length,"base_address":format!("{base:#x}")});
            let listing = body(&connection.call(&path, request.clone()).await);
            assert_eq!(listing["source_offset"], 7);
            assert_eq!(listing["rows"][0]["source_byte_offset"], 7);
            assert_eq!(listing["end_address_exclusive"], format!("{:#x}", base + length as u64));
            assert_eq!(listing["rows"][0]["address"], format!("{base:#x}"));
            assert_eq!(listing["rows"][0]["flow"]["kind"], "direct_call");
            assert_eq!(listing["rows"][0]["flow"]["target"], base + 16);
            assert!(
                listing["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["address"] == format!("{:#x}", base + return_offset)
                        && row["flow"]["kind"] == "return")
            );
            assert_eq!(listing["source_range_sha256"], listing["source_range_sha256_after"]);
            assert!(listing["profile"]["abi"].as_str().unwrap().contains("unknown"));
            assert!(listing["profile"]["mapping_validation"].as_str().unwrap().contains("analyst_asserted"));
            assert!(listing["program"].is_null());
            let mut request = request;
            request["discover"] = json!(true);
            request["listing_limit"] = json!(1);
            request["seeds"] = json!([base]);
            let caller_only = body(&connection.call(&path, request.clone()).await);
            assert_eq!(
                caller_only["program"]["functions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|function| function["address"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec![format!("{base:#x}"), format!("{:#x}", base + 16)]
            );
            request["seeds"] = if name == "avr8" { json!([base, base + 22]) } else { json!([base]) };
            let report = body(&connection.call(&path, request.clone()).await);
            let functions = report["program"]["functions"].as_array().unwrap();
            let mut expected = vec![format!("{base:#x}"), format!("{:#x}", base + 16)];
            if name == "avr8" {
                expected.push("0x216".to_owned());
            }
            assert_eq!(
                functions.iter().map(|function| function["address"].as_str().unwrap()).collect::<Vec<_>>(),
                expected
            );
            count += functions.len();
            assert_eq!(report["rows"].as_array().unwrap().len(), 1);
            assert!(report["listing_total"].as_u64().unwrap() > 1);
            assert_eq!(report["listing_next_offset"], 1);
            assert!(report["program"]["xrefs"].as_array().unwrap().iter().any(|xref| xref["kind"] == "call"
                && xref["from"] == format!("{base:#x}")
                && xref["to"] == format!("{:#x}", base + 16)));
            if name == "avr8" {
                let code = report["profile"]["spaces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|space| space["id"] == report["profile"]["code_space"])
                    .unwrap();
                assert_eq!(code["word_size"], 2);
                let gate = report["stops"].as_array().unwrap().iter().find(|stop| stop["address"] == "0x216").unwrap();
                assert_eq!(gate["status"], "valid");
                assert_eq!(gate["flow"]["kind"], "unknown");
                assert_eq!(gate["unknown_gate"]["address"], 0x216);
                assert_eq!(gate["unknown_gate"]["reason"], "context_mediated_flow");
                assert_eq!(gate["reason"], "conservative_unknown_flow_not_invalid_opcode");
                assert_eq!(gate["context_mediated_flow"], true);
                let retained = functions.iter().find(|function| function["address"] == "0x216").unwrap();
                assert_eq!(retained["instruction_count"], 1);
                assert_eq!(retained["blocks"], json!([{"start":"0x216","end":"0x218"}]));
                let production = report["program"]["decode_gates"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["function"] == "0x216" && entry["gate"]["address"] == "0x216")
                    .unwrap();
                assert_eq!(production["len"], 2);
                assert_eq!(production["gate"]["backend"], "sleigh");
                assert_eq!(production["gate"]["profile"], profile);
                assert_eq!(production["gate"]["reason"], "context_mediated_flow");
                assert!(report["program"]["xrefs"].as_array().unwrap().iter().all(|xref| xref["from"] != "0x216"));
                for field in ["noreturn", "inferred_noreturn", "noreturn_calls"] {
                    assert!(
                        report["program"][field]
                            .as_array()
                            .is_none_or(|items| !items.iter().any(|item| item == "0x216"))
                    );
                }
                assert!(
                    caller_only["program"]["decode_gates"]
                        .as_array()
                        .is_none_or(|gates| !gates.iter().any(|gate| gate["gate"]["address"] == "0x216"))
                );
                assert!(functions.iter().flat_map(|function| function["blocks"].as_array().unwrap()).all(|block| {
                    let start =
                        u64::from_str_radix(block["start"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                    let end = u64::from_str_radix(block["end"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                    !(start <= 0x218 && 0x218 < end)
                }));
                request["listing_offset"] = json!(report["listing_total"].as_u64().unwrap() - 1);
                let gate_page = body(&connection.call(&path, request).await);
                assert_eq!(gate_page["rows"][0]["address"], "0x216");
                assert_eq!(gate_page["rows"][0]["length"], 2);
                assert_eq!(gate_page["rows"][0]["status"], "valid");
                assert_eq!(gate_page["rows"][0]["flow"]["kind"], "unknown");
                assert_eq!(gate_page["stops"], report["stops"]);
            }
            assert_eq!(owned.files(), before);
        }
        assert_eq!(count, 7);
        connection.shutdown().await;
    })
    .await
    .expect("MCP Sleigh pilot transport timed out");
}

#[tokio::test]
async fn outside_calls_are_retained_not_followed_and_bad_bounds_profiles_or_work_limits_never_publish_partial_programs()
{
    timeout(Duration::from_secs(90), async {
        let owned = Owned::new();
        let path = owned.0.join("outside.raw");
        std::fs::write(&path, [0x20, 0x00, 0x90, 0x60]).unwrap();
        let before = owned.files();
        let connection = Connection::connect().await;
        let valid = json!({"profile":"6502:LE:16:default","offset":0,"length":4,"base_address":"0x8000",
            "discover":true,"seeds":["0x8000"],"include_pcode":true,"listing_limit":1});
        let report = body(&connection.call(&path, valid.clone()).await);
        assert_eq!(report["program"]["functions"].as_array().unwrap().len(), 1);
        assert!(
            report["program"]["xrefs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|xref| xref["to"] == "0x9000" && xref["kind"] == "call")
        );
        assert!(
            report["stops"]
                .as_array()
                .unwrap()
                .iter()
                .any(|stop| stop["reason"] == "direct_target_outside_window_not_followed")
        );
        assert!(!report["rows"][0]["pcode"].as_array().unwrap().is_empty());
        for (field, value) in [
            ("profile", json!("../../arbitrary.sla")),
            ("profile", json!("MIPS:BE:32:default")),
            ("profile", json!("68000:BE:32:default")),
            ("arch", json!("6502")),
            ("compiler_spec", json!("default")),
            ("base_address", json!("main")),
            ("length", json!(65537)),
            ("offset", json!("0xffffffffffffffff")),
            ("seeds", json!(["0x9000"])),
            ("instruction_limit", json!(1)),
            ("decode_attempt_limit", json!(0)),
            ("handle_open_limit", json!(1)),
            ("timeout_ms", json!(0)),
            ("image_offset", json!(0)),
        ] {
            let mut request = valid.clone();
            request[field] = value;
            let rejected = connection.call(&path, request).await;
            assert_eq!(rejected.is_error, Some(true), "{field}: {}", text(&rejected));
            assert!(!text(&rejected).contains("\"program\""), "partial Program must not appear on error");
            assert_eq!(owned.files(), before);
        }
        let oversized_path = format!("/must/not/be/opened/{}", "\"".repeat(1024 * 1024 / 2 + 1));
        let rejected = connection.call(Path::new(&oversized_path), valid).await;
        assert_eq!(rejected.is_error, Some(true));
        assert_eq!(text(&rejected), "Sleigh request exceeds 1 MiB");
        assert_eq!(owned.files(), before);
        connection.shutdown().await;
    })
    .await
    .expect("MCP Sleigh bounds transport timed out");
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn operation(name: &str) -> String {
    name.trim_start_matches("CPUI_").to_ascii_uppercase()
}
impl Connection {
    /// Pages a whole listing at four p-code rows per response; every page is checked against the JSON budget.
    async fn pages(&self, path: &Path, mut request: Value) -> (Value, Vec<Value>) {
        request["listing_limit"] = json!(4);
        let first = body(&self.call(path, request.clone()).await);
        let mut rows = first["rows"].as_array().unwrap().clone();
        let mut next = first["listing_next_offset"].clone();
        while let Some(offset) = next.as_u64() {
            request["listing_offset"] = json!(offset);
            let page = body(&self.call(path, request.clone()).await);
            assert_eq!(page["stops"], first["stops"]);
            assert_eq!(page["program"], first["program"]);
            rows.extend(page["rows"].as_array().unwrap().iter().cloned());
            next = page["listing_next_offset"].clone();
        }
        assert_eq!(rows.len() as u64, first["listing_total"].as_u64().unwrap());
        (first, rows)
    }
}

#[tokio::test]
async fn full_roster_rows_match_the_independent_oracle_with_pcode_and_explicit_gates() {
    timeout(Duration::from_secs(300), async {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh");
        let read = |name: &str| -> Value { serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap() };
        let (pilots, extended, truth) =
            (read("oracle.json"), read("extended/oracle-current.json"), read("extended/truth-current.json"));
        let mut roster = Vec::new();
        for fixture in pilots["fixtures"].as_array().unwrap() {
            roster.push((
                fixture["name"].as_str().unwrap().to_owned(),
                fixture,
                hex(&fixture["base"]["getOffset_bytes"]),
                &fixture["rows"],
                &fixture["program_oracle"]["functions"],
            ));
        }
        for fixture in extended["fixtures"].as_array().unwrap() {
            let name = fixture["name"].as_str().unwrap();
            let owned = truth["fixtures"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
            assert_eq!(owned["language_id"], fixture["language_id"]);
            roster.push((
                format!("extended/{name}"),
                fixture,
                hex(&owned["base_byte_offset"]),
                &fixture["oracle"]["standalone_rows"],
                &fixture["oracle"]["program_oracle"]["functions"],
            ));
        }
        let owned = Owned::new();
        let connection = Connection::connect().await;
        let mut profiles = std::collections::BTreeSet::new();
        let mut compared = 0;
        for (name, fixture, base, oracle_rows, functions) in roster {
            let profile = fixture["language_id"].as_str().unwrap();
            assert!(profiles.insert(profile));
            let (path, length) = owned.fixture(&name);
            let before = owned.files();
            let request = json!({"profile":profile,"offset":7,"length":length,
                "base_address":format!("{base:#x}"),"include_pcode":true});
            let (linear, rows) = connection.pages(&path, request.clone()).await;
            assert!(linear["program"].is_null());
            let mut gates = Vec::new();
            for java in oracle_rows.as_array().unwrap().iter().filter(|row| row["status"] == "decoded") {
                let address = hex(&java["address"]["getOffset_bytes"]);
                let offset = java["fixture_offset_bytes"].as_u64().unwrap();
                assert_eq!(address, base + offset);
                let native = rows
                    .iter()
                    .find(|row| row["address"] == format!("{address:#x}"))
                    .unwrap_or_else(|| panic!("{name}: linear listing skipped oracle row {address:#x}"));
                assert_eq!(native["source_byte_offset"], 7 + offset);
                assert_eq!(native["status"], "valid", "{name} {address:#x}: {native}");
                assert_eq!(native["length"], java["length_bytes"], "{name} {address:#x}");
                assert!(
                    native["mnemonic"].as_str().unwrap().eq_ignore_ascii_case(java["mnemonic"].as_str().unwrap()),
                    "{name} {address:#x}: native {} Java {}",
                    native["mnemonic"],
                    java["mnemonic"]
                );
                let native_ops: Vec<_> = native["pcode"]
                    .as_array()
                    .expect("include_pcode publishes p-code for every valid row")
                    .iter()
                    .map(|op| operation(op["name"].as_str().unwrap()))
                    .collect();
                let java_ops: Vec<_> = java["raw_pcode"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|op| operation(op["mnemonic"].as_str().unwrap()))
                    .collect();
                assert_eq!(native_ops, java_ops, "{name} {address:#x}");
                if !native["unknown_gate"].is_null() {
                    assert_eq!(native["flow"]["kind"], "unknown");
                    assert_eq!(native["unknown_gate"]["profile"], profile);
                    gates.push((address, native["unknown_gate"]["reason"].as_str().unwrap().to_owned()));
                }
                compared += 1;
            }
            let seeds: Vec<_> = functions
                .as_array()
                .unwrap()
                .iter()
                .map(|function| hex(&function["entry"]["getOffset_bytes"]))
                .collect();
            let mut request = request;
            request["discover"] = json!(true);
            request["seeds"] = json!(seeds);
            let (report, discovered) = connection.pages(&path, request).await;
            let program = &report["program"];
            for seed in &seeds {
                assert!(
                    program["functions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|function| function["address"] == format!("{seed:#x}")),
                    "{name}: oracle entry {seed:#x} missing: {report}"
                );
            }
            for row in discovered.iter().filter(|row| row["status"] == "valid") {
                assert!(row["pcode"].is_array(), "{name} {}", row["address"]);
                if row["unknown_gate"].is_null() {
                    assert_ne!(row["flow"]["kind"], "unknown", "{name} {}", row["address"]);
                }
            }
            let program_gates: Vec<_> = program["decode_gates"]
                .as_array()
                .map(|gates| {
                    gates.iter().map(|gate| (gate["gate"]["address"].clone(), gate["gate"]["reason"].clone())).collect()
                })
                .unwrap_or_default();
            let helper = gates.iter().any(|(_, reason)| reason == "processor_helper_required");
            let delay = gates.iter().any(|(_, reason)| reason == "delay_slot_aggregation");
            match fixture["family"].as_str() {
                Some("Hexagon") => {
                    assert!(helper, "{name}: {gates:?}");
                    assert!(program_gates.iter().any(|(_, reason)| reason == "processor_helper_required"));
                    assert!(!linear["profile"]["required_parallel_helper"].as_str().unwrap().is_empty());
                    assert!(
                        rows.iter()
                            .filter(|row| row["unknown_gate"]["reason"] == "processor_helper_required")
                            .all(|row| row["processor_helper_required"] == true)
                    );
                }
                Some("SuperH") => {
                    assert!(delay, "{name}: {gates:?}");
                    assert!(program_gates.iter().any(|(_, reason)| reason == "delay_slot_aggregation"));
                }
                _ => assert!(!helper && !delay, "{name}: {gates:?}"),
            }
            eprintln!(
                "{name} {profile}: oracle_rows={} linear_rows={} gates={gates:?} \
                 functions={} program_gates={program_gates:?}",
                oracle_rows.as_array().unwrap().len(),
                rows.len(),
                program["functions"].as_array().unwrap().len()
            );
            assert_eq!(owned.files(), before);
        }
        assert_eq!(profiles.len(), 16);
        eprintln!("compared {compared} oracle rows");
        connection.shutdown().await;
    })
    .await
    .expect("MCP Sleigh full roster transport timed out");
}
