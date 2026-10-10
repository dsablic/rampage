use std::path::PathBuf;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_string_lossy().into_owned()
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, TestClient>, tool: &str, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().and_then(|content| content.as_text()).map(|text| text.text.as_str()).unwrap()
}

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

#[tokio::test]
async fn lists_all_tools_with_instructions() {
    let client = connect().await;
    let mut names: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
    names.sort();
    assert_eq!(names, ["binary_info", "disassemble", "list_functions", "list_strings", "xrefs"]);
    let info = client.peer_info().unwrap();
    assert_eq!(info.server_info.as_ref().unwrap().name, "rampage");
    assert!(info.instructions.as_deref().unwrap().contains("list_functions"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn explores_a_binary_end_to_end() {
    let client = connect().await;
    let path = fixture("hello-x64.elf");

    let info = json_of(&call(&client, "binary_info", json!({ "path": path })).await);
    assert_eq!(info["format"], "elf");
    assert_eq!(info["entry"], "0x10018c0");

    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "main" })).await);
    let main = functions["items"].as_array().unwrap().iter().find(|row| row["name"] == "main").unwrap();
    assert_eq!(main["address"], "0x1001910");

    let lines = json_of(&call(&client, "disassemble", json!({ "path": path, "at": "main", "count": 3 })).await);
    assert_eq!(lines.as_array().unwrap().len(), 3);
    assert_eq!(lines[0]["label"], "main");

    let xrefs = json_of(&call(&client, "xrefs", json!({ "path": path, "to": "puts" })).await);
    assert!(xrefs.as_array().unwrap().iter().any(|row| row["from_function"] == "main"));

    let strings = json_of(&call(&client, "list_strings", json!({ "path": path, "contains": "greeting" })).await);
    assert_eq!(strings["total"], 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pages_are_capped() {
    let client = connect().await;
    let page = json_of(&call(&client, "list_functions", json!({ "path": fixture("hello-x64.elf"), "limit": 2 })).await);
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(page["total"].as_u64().unwrap() > 2);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn arm64_functions_are_listed() {
    let client = connect().await;
    let arm = call(&client, "list_functions", json!({ "path": fixture("hello-arm64.macho") })).await;
    assert_eq!(arm.is_error, Some(false));
    assert!(text(&arm).contains("\"_main\""), "{}", text(&arm));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn failures_are_tool_errors_the_caller_can_read() {
    let client = connect().await;
    let missing = call(&client, "binary_info", json!({ "path": "/nonexistent/binary" })).await;
    assert_eq!(missing.is_error, Some(true));
    assert!(text(&missing).contains("/nonexistent/binary"), "{}", text(&missing));

    let path = fixture("hello-x64.elf");
    let ambiguous = call(&client, "xrefs", json!({ "path": path, "to": "main", "from": "main" })).await;
    assert_eq!(ambiguous.is_error, Some(true));

    let bad_arch = call(&client, "binary_info", json!({ "path": path, "arch": "mips" })).await;
    assert!(text(&bad_arch).contains("unknown architecture"));

    client.cancel().await.unwrap();
}
