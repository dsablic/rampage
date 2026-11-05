//! Real MCP transport coverage for output-only views and one checked heterogeneous transaction.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_api::{ToolView, ToolViewKind, project_tool_view};
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
        for name in ["decompile", "function_summary", "disassemble", "function_graph", "binary_info", "inspect_data"] {
            let tool = listed.iter().find(|tool| tool.name == name).unwrap();
            assert!(tool.input_schema["properties"].get("view").is_some(), "{name}");
        }
        assert!(listed.iter().any(|tool| tool.name == "batch"));
        Self { client: Some(client), server }
    }
    async fn call(&self, name: &str, args: Value) -> CallToolResult {
        timeout(
            TIMEOUT,
            self.client.as_ref().unwrap().call_tool(
                CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()),
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
    serde_json::from_str(text(result)).expect("complete JSON view or complete batch receipt")
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-ergonomics-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("owned.json"),json!({
            "format":"rampage-snapshot-v1","arch":"x86_64","provenance":"owned MCP ergonomics fixture; never executed",
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
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entries() -> Value {
    json!([
        {"operation":"rename","at":"sub_1000","value":"reviewed_entry"},
        {"operation":"comment","at":"sub_1000","value":"same pre-batch name"},
        {"operation":"signature","at":"4097","value":"batch_number reviewed_entry(void);"},
        {"operation":"types","at":"sub_1000","value":"typedef int4 batch_number;"},
        {"operation":"global","at":"0x3000","value":"batch_number reviewed_counter;"}
    ])
}

#[tokio::test]
async fn six_tool_views_use_identical_projection_semantics_and_full_default_without_writes() {
    timeout(Duration::from_secs(120), async {
        let fixture = Fixture::new();
        let path = fixture.path();
        let before = fixture.files();
        let connection = Connection::connect().await;
        let elf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
        let elf_before = std::fs::read(&elf).unwrap();
        let at = format!("{:#x}", rampage_loaders::Binary::open(&elf).unwrap().entry.unwrap());
        for (name, kind, args) in [
            ("binary_info", ToolViewKind::BinaryInfo, json!({"path":path})),
            ("disassemble", ToolViewKind::Disassemble, json!({"path":path,"at":"sub_1000","count":2})),
            ("function_graph", ToolViewKind::FunctionGraph, json!({"path":path,"at":"sub_1000"})),
            ("function_summary", ToolViewKind::FunctionSummary, json!({"path":path,"at":"sub_1000"})),
            ("decompile", ToolViewKind::Decompile, json!({"path":path,"at":"sub_1000"})),
            ("inspect_data", ToolViewKind::InspectData, json!({"path":elf,"at":at,"size":16,"word_size":8})),
        ] {
            let full = body(&connection.call(name, args.clone()).await);
            for view in [ToolView::Full, ToolView::Summary, ToolView::Code] {
                let mut input = args.clone();
                input["view"] = serde_json::to_value(view).unwrap();
                let result = connection.call(name, input).await;
                // function_summary's compact views add its callees and fit rather than refuse.
                let expected = if kind == ToolViewKind::FunctionSummary {
                    rampage_api::project_function_summary(full.clone(), view, rampage_api::SummaryPages::default())
                } else {
                    project_tool_view(full.clone(), kind, view)
                };
                match expected {
                    Ok(expected) => assert_eq!(body(&result), expected, "{name}: {view:?}"),
                    Err(_) => {
                        assert_eq!(result.is_error, Some(true));
                        assert!(text(&result).contains("view=code"), "{}", text(&result));
                    }
                }
            }
        }
        assert_eq!(fixture.files(), before);
        assert_eq!(std::fs::read(elf).unwrap(), elf_before);
        connection.shutdown().await;
    })
    .await
    .expect("MCP view projection test timed out");
}

#[tokio::test]
async fn heterogeneous_batch_is_atomic_nullable_and_one_undo_while_bad_requests_never_publish() {
    timeout(Duration::from_secs(120), async {
        let fixture = Fixture::new();
        let path = fixture.path();
        let source = std::fs::read(&path).unwrap();
        let connection = Connection::connect().await;
        let before = body(&connection.call("list_annotations", json!({"path":path})).await);
        let result = body(&connection.call("batch", json!({"path":path,"entries":entries()})).await);
        assert_eq!(result["changed"], 5);
        assert_eq!(result["entries"].as_array().unwrap().len(), 5);
        assert_eq!(result["entries"][2]["address"], "0x1000");
        let applied = fixture.files();
        for invalid in [
            json!([{"operation":"comment","at":"reviewed_entry"}]),
            json!([
                {"operation":"comment","at":"reviewed_entry","value":"would change"},
                {"operation":"signature","at":"reviewed_entry","value":"not a declaration"}
            ]),
            json!([{"operation":"comment","at":"reviewed_entry","value":"\"".repeat(30000)}]),
            json!([{"operation":"patch","at":"reviewed_entry","value":"90"}]),
        ] {
            let rejected = connection.call("batch", json!({"path":path,"entries":invalid})).await;
            assert_eq!(rejected.is_error, Some(true), "{}", text(&rejected));
            assert_eq!(fixture.files(), applied);
        }
        let undone = body(&connection.call("undo", json!({"path":path})).await);
        assert_eq!(undone.as_array().unwrap().len(), 5);
        assert_eq!(body(&connection.call("list_annotations", json!({"path":path})).await), before);
        body(&connection.call("batch", json!({"path":path,"entries":entries()})).await);
        let cleared = body(
            &connection
                .call(
                    "batch",
                    json!({"path":path,"entries":[
                        {"operation":"rename","at":"reviewed_entry","value":null},
                        {"operation":"comment","at":"reviewed_entry","value":null},
                        {"operation":"signature","at":"reviewed_entry","value":null},
                        {"operation":"types","at":"reviewed_entry","value":null},
                        {"operation":"global","at":"0x3000","value":null}
                    ]}),
                )
                .await,
        );
        assert_eq!(cleared["changed"], 5);
        assert_eq!(body(&connection.call("list_annotations", json!({"path":path})).await), before);
        assert_eq!(std::fs::read(path).unwrap(), source);
        connection.shutdown().await;
    })
    .await
    .expect("MCP heterogeneous annotation batch test timed out");
}

#[tokio::test]
async fn oversized_valid_full_metadata_returns_explicit_error_and_summary_stays_complete_json() {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new();
        let path = fixture.0.join("large.json");
        let regions: Vec<_> = (0..1024)
            .map(|index| {
                json!({
                    "name":format!("owned_{index}_{}","x".repeat(128)),"address":format!("{:#x}",0x1000+index*0x1000),
                    "permissions":"r--","bytes":"00"
                })
            })
            .collect();
        std::fs::write(
            &path,
            json!({"format":"rampage-snapshot-v1","arch":"x86_64",
            "provenance":"owned large full-view transport fixture","regions":regions})
            .to_string(),
        )
        .unwrap();
        let before = fixture.files();
        let connection = Connection::connect().await;
        let rejected = connection.call("binary_info", json!({"path":path})).await;
        assert_eq!(rejected.is_error, Some(true));
        assert!(text(&rejected).contains("view=summary"), "{}", text(&rejected));
        assert!(text(&rejected).contains("no strings were truncated"), "{}", text(&rejected));
        let summary = body(&connection.call("binary_info", json!({"path":path,"view":"summary"})).await);
        assert_eq!(summary["segments_count"], 1024);
        assert_eq!(summary["sections_count"], 1024);
        assert_eq!(fixture.files(), before);
        connection.shutdown().await;
    })
    .await
    .expect("MCP oversized full-view rejection test timed out");
}
