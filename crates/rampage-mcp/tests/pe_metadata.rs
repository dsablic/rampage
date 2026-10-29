use std::path::PathBuf;

use rampage_api::tools::Group;
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

async fn connect(server: RampageServer) -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_string_lossy().into_owned()
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
async fn pe_tools_belong_to_the_formats_group() {
    let client = connect(RampageServer::default()).await;
    let refused = call(&client, "pe_resources", json!({ "path": fixture("pe-metadata-x64.exe") })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("`formats` group"), "{}", text(&refused));
    json_of(&call(&client, "enable_tools", json!({ "groups": ["formats"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    for name in ["pe_resources", "pe_load_config"] {
        let tool = tools.iter().find(|tool| tool.name == name).unwrap();
        assert!(tool.description.as_deref().unwrap().contains("Returns null for a non-PE image"), "{name}");
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pe_resources_pages_filters_and_decodes() {
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let path = fixture("pe-metadata-x64.exe");
    let all = json_of(&call(&client, "pe_resources", json!({ "path": path })).await);
    assert_eq!(all["total_leaves"], 4);
    assert_eq!(all["types"][0], json!({ "type": "BLOB", "type_name": "BLOB", "count": 1 }));
    assert_eq!((all["types_total"].as_u64(), all["types_truncated"].as_bool()), (Some(4), Some(false)));
    let rows = all["resources"]["items"].as_array().unwrap();
    assert_eq!(rows[0]["type"], "BLOB");
    assert_eq!(rows[0]["name"], "FIXTURE");
    assert_eq!(rows[0]["language"], 0x409);
    assert!(rows[0].get("decoded").is_none());

    let version = json_of(&call(&client, "pe_resources", json!({ "path": path, "type": "RT_VERSION" })).await);
    assert_eq!(version["resources"]["total"], 1);
    let decoded = &version["resources"]["items"][0]["decoded"];
    assert_eq!(decoded["kind"], "version");
    assert_eq!(decoded["fixed"]["file_version"], "1.2.3.4");
    assert_eq!(decoded["string_tables"][0]["strings"][0], json!({ "key": "CompanyName", "value": "Rampage Fixtures" }));
    assert_eq!(decoded["translations"], json!([{ "language": 0x409, "code_page": 1200 }]));

    let manifest = json_of(&call(&client, "pe_resources", json!({ "path": path, "type": "24" })).await);
    let decoded = &manifest["resources"]["items"][0]["decoded"];
    assert_eq!(decoded["requested_execution_level"]["level"], "requireAdministrator");
    assert_eq!(decoded["dependent_assemblies"], json!(["Microsoft.Windows.Common-Controls"]));

    let page = json_of(&call(&client, "pe_resources", json!({ "path": path, "offset": 1, "limit": 2 })).await);
    assert_eq!((page["resources"]["offset"].as_u64(), page["returned"].as_u64()), (Some(1), Some(2)));
    assert_eq!(
        (page["resources"]["next_offset"].as_u64(), page["resources"]["byte_capped"].as_bool()),
        (Some(3), Some(false))
    );
    let version = json_of(&call(&client, "pe_resources", json!({ "path": path, "type": "#16" })).await);
    assert_eq!(version["resources"]["total"], 1);

    let native = json_of(&call(&client, "pe_resources", json!({ "path": fixture("hello-x64.elf") })).await);
    assert!(native.is_null());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pe_load_config_reports_size_bounded_fields_and_findings() {
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let report = json_of(&call(&client, "pe_load_config", json!({ "path": fixture("pe-metadata-x86.exe") })).await);
    assert_eq!(report["bits"], 32);
    let config = &report["load_config"];
    assert_eq!(config["declared_size"], 92);
    assert_eq!(config["safe_seh"]["table"]["count"], 2);
    assert_eq!(config["safe_seh"]["handlers"], json!([0x1060, 0x1070]));
    assert_eq!(config["guard"]["function_table"]["in_image"], true);
    assert!(config["eh_continuations"].is_null());
    assert!(config["absent_fields"].as_array().unwrap().contains(&json!("guard_eh_continuation_table")));
    assert!(report["findings"][0].as_str().unwrap().contains("does not enforce CFG"));

    let native = json_of(&call(&client, "pe_load_config", json!({ "path": fixture("hello-x64.elf") })).await);
    assert!(native.is_null());
    client.cancel().await.unwrap();
}
