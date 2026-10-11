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
    let expected = [
        "analysis_diagnostics",
        "binary_info",
        "decompile",
        "disassemble",
        "function_graph",
        "function_summary",
        "inspect_jump_table",
        "language_metadata",
        "list_annotations",
        "list_exports",
        "list_functions",
        "list_imports",
        "list_strings",
        "redo",
        "rename",
        "set_comment",
        "triage",
        "undo",
        "xrefs",
    ];
    assert_eq!(names, expected);
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
    assert!(xrefs["items"].as_array().unwrap().iter().any(|row| row["from_function"] == "main"));

    let strings = json_of(&call(&client, "list_strings", json!({ "path": path, "contains": "greeting" })).await);
    assert_eq!(strings["total"], 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn function_summary_exposes_ssa_through_the_shared_registry() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-ssa-diamond.snapshot.json")
        .to_string_lossy()
        .into_owned();
    let summary = json_of(&call(&client, "function_summary", json!({ "path": path, "at": "0x1000" })).await);
    assert!(
        summary["ssa"]["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|definition| definition["expression"]["kind"] == "phi"
                && definition["expression"]["inputs"].as_array().unwrap().len() == 2)
    );
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

    let bad_arch = call(&client, "binary_info", json!({ "path": path, "arch": "vax" })).await;
    assert!(text(&bad_arch).contains("unknown architecture"));

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn triage_and_imports_describe_a_binary() {
    let client = connect().await;
    let path = fixture("hello-x64-dyn.elf");
    let triage = json_of(&call(&client, "triage", json!({ "path": path })).await);
    assert_eq!(triage["image_hashes"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(triage["details"]["format"], "elf");
    assert_eq!(triage["details"]["interpreter"], "/lib64/ld-linux-x86-64.so.2");
    let imports = json_of(&call(&client, "list_imports", json!({ "path": path, "contains": "puts" })).await);
    assert_eq!(imports["total"], 1);
    assert_eq!(imports["items"][0]["library"], "libc.so.6");
    assert!(imports["items"][0]["slot"].as_str().unwrap().starts_with("0x"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn agents_rename_and_comment() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(fixture("hello-arm64.macho"), &path).unwrap();
    let path = path.to_str().unwrap();
    let client = connect().await;
    let renamed = json_of(&call(&client, "rename", json!({ "path": path, "at": "_main", "name": "say_hello" })).await);
    assert_eq!(renamed["changed"], true);
    json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "text": "entry" })).await);
    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "say_" })).await);
    assert_eq!(functions["items"][0]["name"], "say_hello");
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(list["comments"][0]["text"], "entry");
    let undone = json_of(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undone["field"], "comment");
    let redone = json_of(&call(&client, "redo", json!({ "path": path })).await);
    assert_eq!(redone["value"], "entry");
    let cleared =
        json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "clear": true })).await);
    assert_eq!((&cleared["value"], &cleared["changed"]), (&json!(null), &json!(true)));
    let neither = call(&client, "rename", json!({ "path": path, "at": "say_hello" })).await;
    assert_eq!(neither.is_error, Some(true));
    let bad = call(&client, "rename", json!({ "path": path, "at": "say_hello", "name": "two words" })).await;
    assert_eq!(bad.is_error, Some(true));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}
