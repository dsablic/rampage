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

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[tokio::test]
async fn format_tools_are_gated_by_the_formats_group_and_need_no_binary() {
    let client = connect().await;
    let refused = call(&client, "wasm_module", json!({ "path": fixture("module.wasm") })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("`formats` group"), "{}", text(&refused));
    json_of(&call(&client, "enable_tools", json!({ "groups": ["formats"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    for name in ["wasm_module", "pyinstaller_archive"] {
        let tool = tools.iter().find(|tool| tool.name == name).unwrap();
        assert!(tool.input_schema["required"].as_array().unwrap().contains(&json!("path")), "{name}");
    }

    let functions =
        json_of(&call(&client, "wasm_module", json!({ "path": fixture("module.wasm"), "list": "functions" })).await);
    assert_eq!(functions["counts"]["functions"], 2);
    assert_eq!(functions["functions"][3]["name"], "tick");
    assert_eq!(functions["total"], 4);
    assert!(functions.get("imports").is_none());
    let component = json_of(&call(&client, "wasm_module", json!({ "path": fixture("component.wasm") })).await);
    assert_eq!((component["encoding"].as_str(), component["supported"].as_bool()), (Some("component"), Some(false)));
    let foreign = json_of(&call(&client, "wasm_module", json!({ "path": fixture("hello-x64.elf") })).await);
    assert!(foreign.is_null());
    let bad = call(&client, "wasm_module", json!({ "path": fixture("module.wasm"), "list": "globals" })).await;
    assert_eq!(bad.is_error, Some(true));

    let archive = json_of(
        &call(&client, "pyinstaller_archive", json!({ "path": fixture("pyinstaller-312.elf"), "limit": 4 })).await,
    );
    assert_eq!(archive["cookie_layout"], "with_python_library");
    assert_eq!(archive["python_version"], "3.12");
    assert_eq!(archive["entries"].as_array().unwrap().len(), 4);
    assert_eq!(archive["entries"][2]["kind"], "script");
    assert_eq!(archive["next_offset"], 4);
    assert_eq!(archive["pyz"]["python_version"], "3.12");
    let none = json_of(&call(&client, "pyinstaller_archive", json!({ "path": fixture("module.wasm") })).await);
    assert!(none.is_null());
    let missing = call(&client, "pyinstaller_archive", json!({ "path": fixture("does-not-exist") })).await;
    assert_eq!(missing.is_error, Some(true));
    client.cancel().await.unwrap();
}
