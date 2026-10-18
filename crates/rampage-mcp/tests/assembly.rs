//! Production MCP duplex coverage; proposal bytes and owned fixture code are never executed.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(15);

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
            listed.iter().find(|tool| tool.name == "assemble").expect("assemble is available in the initial Core list");
        assert!(tool.input_schema["properties"].get("at").is_some());
        assert!(tool.input_schema["properties"].get("source").is_some());
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
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert!(text.len() <= 60000);
    text
}
fn body(result: &CallToolResult) -> Value {
    let text = text(result);
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(text).expect("complete byte-bounded JSON assembly proposal")
}

struct Fixture(PathBuf);
impl Fixture {
    fn new(arch: &str, annotated: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-mcp-assembly-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let code = if arch == "aarch64" { "00008052c0035fd6" } else { "b800000000c3" };
        std::fs::write(
            root.join("owned.json"),
            json!({
                "format":"rampage-snapshot-v1","arch":arch,"provenance":"owned assembly MCP transport fixture",
                "seeds":["0x1000"],"regions":[{"name":"code","address":"0x1000","permissions":"r-x","bytes":code}]
            })
            .to_string(),
        )
        .unwrap();
        let fixture = Self(root);
        if annotated {
            let project = rampage_api::Session::default().open(&fixture.path(), None).unwrap();
            project.rename(0x1000, Some("analyst_function")).unwrap();
            project.comment(0x1000, Some("analyst comment must survive assembly proposals")).unwrap();
        }
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
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn core_assembly_transport_returns_x64_and_a64_vectors_without_writing_any_files() {
    timeout(Duration::from_secs(90), async {
        for (arch, source, expected, annotated) in [
            ("x86_64", "mov eax,7\nret", "b807000000c3", true),
            ("aarch64", "mov w0,7\nret", "e0008052c0035fd6", false),
        ] {
            let fixture = Fixture::new(arch, annotated);
            let path = fixture.path();
            let before = fixture.files();
            let connection = Connection::connect().await;
            let annotations = body(&connection.call("list_annotations", json!({"path":path})).await);
            let at = if annotated { "analyst_function" } else { "0x1000" };
            let result = body(
                &connection
                    .call(
                        "assemble",
                        json!({
                            "path":path,"at":at,"source":source
                        }),
                    )
                    .await,
            );
            assert_eq!(result["architecture"], arch);
            assert_eq!(result["address"], "0x1000");
            assert_eq!(result["bytes_hex"], expected);
            assert_eq!(result["instruction_count"], 2);
            assert_eq!(result["canonical_disassembly"].as_array().unwrap().len(), 2);
            assert!(result["bytes"].as_array().unwrap().len() > 1);
            assert_eq!(result["read_only"], true);
            assert_eq!(result["execution_verified"], false);
            assert_eq!(body(&connection.call("list_annotations", json!({"path":path})).await), annotations);
            assert_eq!(fixture.files(), before);
            connection.shutdown().await;
        }
    })
    .await
    .expect("MCP assembly vector test timed out");
}

#[tokio::test]
async fn invalid_assembly_batches_bitness_limits_and_apply_fields_cannot_modify_the_project() {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new("x86", true);
        let path = fixture.path();
        let before = fixture.files();
        let connection = Connection::connect().await;
        let annotations = body(&connection.call("list_annotations", json!({"path":path})).await);
        for source in [
            "mov rax,7".to_owned(),
            "nop\ninvalid".to_owned(),
            ".byte 0x90".to_owned(),
            "mov eax,[eax]".to_owned(),
            "jmp analyst_function".to_owned(),
            "/bin/sh".to_owned(),
            "nop\n".repeat(65),
            " ".repeat(16 * 1024 + 1),
        ] {
            let rejected =
                connection.call("assemble", json!({"path":path,"at":"analyst_function","source":source})).await;
            assert_eq!(rejected.is_error, Some(true), "{}", text(&rejected));
            assert!(!text(&rejected).contains("\"bytes_hex\""));
            if source == "nop\ninvalid" {
                assert!(text(&rejected).contains("assembly line 2"), "{}", text(&rejected));
            }
            assert_eq!(fixture.files(), before);
        }
        for args in [
            json!({"path":path,"at":"analyst_function","source":"nop","apply":true}),
            json!({"path":path,"at":"missing_function","source":"nop"}),
        ] {
            let rejected = connection.call("assemble", args).await;
            assert_eq!(rejected.is_error, Some(true), "{}", text(&rejected));
        }
        assert_eq!(body(&connection.call("list_annotations", json!({"path":path})).await), annotations);
        assert_eq!(fixture.files(), before);
        connection.shutdown().await;
    })
    .await
    .expect("MCP assembly rejection test timed out");
}
