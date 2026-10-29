use std::path::PathBuf;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, TestClient>, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().unwrap().as_text().unwrap().text.as_str()
}

fn body(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

fn ids(list: &Value) -> Vec<u64> {
    list["findings"].as_array().unwrap().iter().map(|finding| finding["id"].as_u64().unwrap()).collect()
}

#[tokio::test]
async fn two_servers_share_one_durable_ledger() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-findings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho"), &path)
        .unwrap();
    let first = connect().await;
    let second = connect().await;

    let tools = first.list_all_tools().await.unwrap();
    let record = tools.iter().find(|tool| tool.name == "record_finding").expect("record_finding is a core tool");
    assert!(tools.iter().any(|tool| tool.name == "list_findings"));
    assert!(serde_json::to_string(&*record.input_schema).unwrap().contains("question"));

    let created = body(
        &call(
            &first,
            "record_finding",
            json!({
                "path": path, "kind": "unknown", "text": "what does the global at x8 hold?", "function": "_main",
                "evidence": [{"tool": "decompile", "detail": "at=_main"}], "confidence": "medium",
            }),
        )
        .await,
    );
    assert_eq!((created["created"].as_bool(), created["finding"]["id"].as_u64()), (Some(true), Some(1)));
    assert_eq!(created["finding"]["function_name"], "_main");
    assert_eq!(created["finding"]["status"], "open");
    let question = json!({ "path": path, "kind": "question", "text": "is the greeting localized?" });
    assert_eq!(body(&call(&first, "record_finding", question).await)["finding"]["id"], 2);

    // Another server picks the entries up from the sidecar and settles one.
    let listed = body(&call(&second, "list_findings", json!({ "path": path })).await);
    assert_eq!(ids(&listed), [1, 2]);
    assert_eq!(listed["counts"][1], json!({ "kind": "unknown", "open": 1, "resolved": 0, "rejected": 0 }));
    let resolved = json!({ "path": path, "id": 1, "status": "resolved", "resolution": "a static string pointer" });
    assert_eq!(body(&call(&second, "record_finding", resolved).await)["changed"], true);

    let settled = body(&call(&first, "list_findings", json!({ "path": path, "status": "resolved" })).await);
    assert_eq!(ids(&settled), [1]);
    assert_eq!(settled["findings"][0]["resolution"], "a static string pointer");
    assert_eq!(settled["findings"][0]["evidence"][0]["tool"], "decompile");
    // The first server's last step was entry 2, which nobody else touched: undo removes it.
    let undone = body(&call(&first, "undo", json!({ "path": path })).await);
    assert_eq!((undone[0]["field"].as_str(), undone[0]["address"].as_str()), (Some("finding"), Some("0x2")));
    assert_eq!(ids(&body(&call(&second, "list_findings", json!({ "path": path })).await)), [1]);

    let refused = call(&first, "record_finding", json!({ "path": path, "text": "no kind" })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("kind is required"), "{}", text(&refused));
    let paged = call(&first, "list_findings", json!({ "path": path, "limit": 101 })).await;
    assert_eq!(paged.is_error, Some(true));

    first.cancel().await.unwrap();
    second.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}
