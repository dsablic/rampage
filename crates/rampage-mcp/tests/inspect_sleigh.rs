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

#[tokio::test]
async fn raw_profiles_preserve_calls_returns_byte_coordinates_six_manual_functions_and_valid_unknown_gate() {
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
            request["seeds"] = if name == "avr8" { json!([base, base + 22]) } else { json!([base]) };
            let report = body(&connection.call(&path, request).await);
            let functions = report["program"]["functions"].as_array().unwrap();
            assert_eq!(functions.len(), 2, "{name}: {report}");
            assert_eq!(functions[0]["address"], format!("{base:#x}"));
            assert_eq!(functions[1]["address"], format!("{:#x}", base + 16));
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
            }
            assert_eq!(owned.files(), before);
        }
        assert_eq!(count, 6);
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
