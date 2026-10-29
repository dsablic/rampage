use std::path::PathBuf;

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Client;

impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_string_lossy().into_owned()
}

async fn connect(server: RampageServer) -> RunningService<RoleClient, Client> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, Client>, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new("build_info").with_arguments(arguments)).await.unwrap()
}

fn json_of(result: &CallToolResult) -> Value {
    let text = result.content.first().and_then(|content| content.as_text()).map(|text| text.text.as_str()).unwrap();
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn build_info_is_a_formats_tool_reading_go_and_rust_records() {
    let client = connect(RampageServer::with_groups([Group::Formats])).await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "build_info").expect("build_info listed");
    let properties = tool.input_schema.get("properties").and_then(Value::as_object).unwrap();
    for argument in ["path", "offset", "limit"] {
        assert!(properties.contains_key(argument), "{argument}");
    }

    let go = json_of(&call(&client, json!({ "path": fixture("buildinfo-go-arm64.macho") })).await);
    assert_eq!(go["rust"], json!(null));
    assert_eq!(go["go"]["status"], "present");
    assert_eq!(go["go"]["location"]["section"], "__go_buildinfo");
    assert_eq!(go["go"]["deps"]["items"][0]["path"], "example.com/greet");

    let rust = json_of(&call(&client, json!({ "path": fixture("auditable-arm64.macho"), "limit": 1 })).await);
    assert_eq!(rust["go"], json!(null));
    assert_eq!(rust["rust"]["packages"]["total"], 4);
    assert_eq!(rust["rust"]["packages"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(rust["rust"]["roots"][0]["version"], "0.1.0");

    let none = json_of(&call(&client, json!({ "path": fixture("hello-x64.exe") })).await);
    assert_eq!((&none["go"], &none["rust"]), (&json!(null), &json!(null)));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn build_info_is_not_listed_until_the_formats_group_is_enabled() {
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "build_info"));
    let refused = call(&client, json!({ "path": fixture("buildinfo-go-x64.elf") })).await;
    assert_eq!(refused.is_error, Some(true));
    client.cancel().await.unwrap();
}
