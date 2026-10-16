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

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests").join(relative)
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

fn body(result: &CallToolResult) -> Value {
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(text.len() <= 60_000, "{} bytes", text.len());
    serde_json::from_str(text).expect("MCP entry results must be whole JSON, not truncated text")
}

#[tokio::test]
async fn exact_entry_is_optional_only_on_decompile_and_diagnostics_is_additively_group_gated() {
    let client = connect().await;
    let initial = client.list_all_tools().await.unwrap();
    assert!(!initial.iter().any(|tool| tool.name == "entry_diagnostics"));
    let missing = fixture("entry-scope-missing-image.elf");
    assert!(!missing.exists());
    let denied = call(&client, "entry_diagnostics", json!({ "path": missing })).await;
    assert_eq!(denied.is_error, Some(true));
    let message = &denied.content.first().unwrap().as_text().unwrap().text;
    assert!(message.contains("`diagnostics` group") && message.contains("nothing was run"), "{message}");

    body(&call(&client, "enable_tools", json!({ "groups": ["all"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    for tool in &tools {
        assert_eq!(
            tool.input_schema["properties"].get("exact_entry").is_some(),
            tool.name == "decompile",
            "exact_entry leaked into {}",
            tool.name
        );
    }
    let decompile = tools.iter().find(|tool| tool.name == "decompile").unwrap();
    assert_eq!(decompile.input_schema["properties"]["exact_entry"]["type"], "boolean");
    assert_eq!(decompile.input_schema["properties"]["exact_entry"]["default"], false);
    let required = decompile.input_schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("at")));
    assert!(!required.contains(&json!("exact_entry")));
    assert_eq!(tools.iter().filter(|tool| tool.name == "entry_diagnostics").count(), 1);
    for original in initial {
        assert!(tools.iter().any(|tool| tool.name == original.name), "removed {}", original.name);
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn decompile_flag_returns_flattened_exact_context_without_replacing_native_diagnostics_or_legacy_defaults() {
    let client = connect().await;
    let path = fixture("data/runtime-x64-bad-code.snapshot.json");
    let exact = body(&call(&client, "decompile", json!({ "path": path, "at": "0x1000", "exact_entry": true })).await);
    assert!(exact.get("decompilation").is_none());
    assert_eq!(exact["address"], "0x1000");
    assert!(exact["code"].as_str().unwrap().contains("Bad instruction"), "{exact}");
    assert_eq!(exact["context"]["scope"], "exact_entry");
    assert_eq!(exact["context"]["validation"], "analyst_asserted");
    assert_eq!(exact["context"]["full_image_mapping"], true);
    assert!(!exact["context"]["omissions"].as_array().unwrap().is_empty());
    assert_eq!(exact["recovery_status"], "incomplete");
    assert_eq!(exact["structure"]["diagnostics"]["bad_data"], true);
    assert!(exact["structure"]["diagnostics"]["warnings"].as_array().unwrap().iter().any(|warning| {
        warning["address"] == "0x1000" && warning["message"].as_str().unwrap().contains("Bad instruction")
    }));

    let omitted = body(&call(&client, "decompile", json!({ "path": path, "at": "0x1000" })).await);
    let explicit =
        body(&call(&client, "decompile", json!({ "path": path, "at": "0x1000", "exact_entry": false })).await);
    assert!(omitted.get("context").is_none());
    assert_eq!(omitted, explicit);
    assert_eq!(omitted["recovery_status"], exact["recovery_status"]);
    let explicit_full =
        body(&call(&client, "decompile", json!({ "path": path, "at": "0x1000", "view": "full" })).await);
    assert_eq!(explicit_full, omitted);
    for exact_entry in [false, true] {
        let compact = body(
            &call(
                &client,
                "decompile",
                json!({ "path": path, "at": "0x1000", "exact_entry": exact_entry, "view": "code" }),
            )
            .await,
        );
        let full = if exact_entry { &exact } else { &omitted };
        for field in ["address", "name", "code", "language_id", "recovery_status"] {
            assert_eq!(compact[field], full[field], "code view changed {field}");
        }
        assert_eq!(compact["diagnostics"], full["structure"]["diagnostics"]);
        assert_eq!(compact["context"]["scope"], full["context"]["scope"]);
        assert_eq!(compact["context"]["omissions"], full["context"]["omissions"]);
        assert!(compact.get("tokens").is_none());
        assert!(compact.get("structure").is_none());
        assert!(!compact["omitted_details"].as_array().unwrap().is_empty());
    }
    let invalid = call(&client, "decompile", json!({ "path": path, "at": "0x1000", "view": "unknown" })).await;
    assert_eq!(invalid.is_error, Some(true));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn native_data_inspection_returns_whole_json_and_rejects_invalid_ranges() {
    let client = connect().await;
    let path = fixture("fixtures/bin/hello-x64.elf");
    let data = body(&call(&client, "inspect_data", json!({ "path": path, "at": "main", "size": 16 })).await);
    assert_eq!(data["size"], 16);
    assert_eq!(data["spans"][0]["status"], "stored");
    assert_eq!(data["words"].as_array().unwrap().len(), 2);
    assert!(!data["limitations"].as_array().unwrap().is_empty());
    for arguments in [
        json!({ "path": path, "at": "main", "size": 0 }),
        json!({ "path": path, "at": "main", "size": 1025 }),
        json!({ "path": path, "at": "main", "word_size": 3 }),
    ] {
        let refused = call(&client, "inspect_data", arguments).await;
        assert_eq!(refused.is_error, Some(true));
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn enabled_entry_diagnostics_pages_whole_entries_with_stable_sampling_and_exact_address_selection() {
    let client = connect().await;
    body(&call(&client, "enable_tools", json!({ "groups": ["diagnostics"] })).await);
    let path = fixture("fixtures/bin/hello-x64-dyn.elf");
    let first = body(&call(&client, "entry_diagnostics", json!({ "path": path, "limit": 1 })).await);
    let total = first["entries_total"].as_u64().unwrap();
    assert!(total > 1);
    assert_eq!(first["entries"].as_array().unwrap().len(), 1);
    assert_eq!(first["more"], true);
    assert_eq!(first["next_offset"], 1);
    assert!(first["transport"]["names_omitted_total"].is_u64());
    let second = body(&call(&client, "entry_diagnostics", json!({ "path": path, "offset": 1, "limit": 1 })).await);
    assert_eq!(second["entries_total"], total);
    assert_eq!(second["usage"], first["usage"]);
    assert_ne!(second["entries"][0]["address"], first["entries"][0]["address"]);
    let last =
        body(&call(&client, "entry_diagnostics", json!({ "path": path, "offset": total - 1, "limit": 1 })).await);
    assert_eq!(last["entries"].as_array().unwrap().len(), 1);
    assert_eq!(last["more"], false);
    assert!(last["next_offset"].is_null());

    let at = first["entries"][0]["address"].as_str().unwrap();
    let exact = body(&call(&client, "entry_diagnostics", json!({ "path": path, "at": at, "limit": 1 })).await);
    assert_eq!(exact["entries_total"], 1);
    assert_eq!(exact["entries"][0]["address"], at);
    assert_eq!(exact["more"], false);
    client.cancel().await.unwrap();
}
