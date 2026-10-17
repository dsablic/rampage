use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-frame-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("owned.snapshot.json"), bytes).unwrap();
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("owned.snapshot.json")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
async fn connect() -> RunningService<RoleClient, Client> {
    let (server, client) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(client).await.unwrap()
}
async fn call(client: &RunningService<RoleClient, Client>, fixture: &Fixture, name: &str, mut args: Value) -> Value {
    args["path"] = json!(fixture.path());
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content[0].as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{name}: {text}");
    assert!(text.len() <= 60_000);
    serde_json::from_str(text).unwrap()
}
async fn enable(client: &RunningService<RoleClient, Client>) {
    let result = client
        .call_tool(
            CallToolRequestParams::new("enable_tools")
                .with_arguments(json!({"groups":["types"]}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true));
}

#[tokio::test]
async fn current_local_names_types_and_native_widths_survive_frame_query_and_fresh_server() {
    let fixture = Fixture::new(include_bytes!("../../../tests/data/local-variables-x64.snapshot.json"));
    let client = connect().await;
    enable(&client).await;
    let decompile = call(&client, &fixture, "decompile", json!({"at":"0x4000ae","view":"code"})).await;
    let local = decompile["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variable| {
            variable["kind"] == "local" && variable["editable"] == true && variable["storage"]["space"] == "stack"
        })
        .unwrap();
    call(
        &client,
        &fixture,
        "declare_types",
        json!({"declarations":
        "struct FrameState { int4 gain; int4 bias; };"}),
    )
    .await;
    call(
        &client,
        &fixture,
        "edit_variable",
        json!({"at":"0x4000ae","storage":local["storage"],
        "name":"frame_state","data_type":"struct FrameState *"}),
    )
    .await;
    let before = call(&client, &fixture, "list_annotations", json!({})).await;
    let frame = call(
        &client,
        &fixture,
        "function_frame",
        json!({"at":"0x4000ae","limit":128,
        "include_tracker":false}),
    )
    .await;
    let row =
        frame["rows"].as_array().unwrap().iter().find(|row| row["native_variable"]["name"] == "frame_state").unwrap();
    assert_eq!(row["native_variable"]["data_type"]["name"], "FrameState *");
    assert_eq!(row["native_variable"]["storage"], local["storage"]);
    assert_eq!(row["locations"][0]["address_size_bits"], 64);
    assert_eq!(row["locations"][0]["signed_offset"], "-16");
    assert_eq!(row["coordinate_id"], "native:stack");
    assert_eq!(call(&client, &fixture, "list_annotations", json!({})).await, before);
    client.cancel().await.unwrap();
    let reopened = connect().await;
    enable(&reopened).await;
    let replay = call(
        &reopened,
        &fixture,
        "function_frame",
        json!({"at":"0x4000ae","limit":128,
        "include_tracker":false}),
    )
    .await;
    assert!(replay["rows"].as_array().unwrap().iter().any(|row| row["native_variable"]["name"] == "frame_state"));
    reopened.cancel().await.unwrap();
}

#[tokio::test]
async fn arm64_frame_keeps_call_weakened_register_evidence_and_coordinates_separate() {
    let fixture = Fixture::new(include_bytes!("../../../tests/data/function-frame-arm64.snapshot.json"));
    let client = connect().await;
    enable(&client).await;
    let frame = call(&client, &fixture, "function_frame", json!({"at":"0x210124","limit":128})).await;
    assert_eq!(frame["native"]["available"], true);
    assert_eq!(frame["tracker"]["available"], true);
    let rows = frame["rows"].as_array().unwrap();
    for offset in ["-48", "-40", "-32", "-24", "-16"] {
        assert!(rows.iter().any(|row| row["category"] == "tracker_slot"
            && row["tracker_slot"]["offset"] == offset
            && row["coordinate_id"] == "tracker:entry_sp"));
    }
    assert!(rows.iter().any(|row| row["register_evidence"]["register"] == 19
        && row["register_evidence"]["classification"] == "reload_candidate"
        && row["register_evidence"]["confidence"] == "conditional"
        && row["register_evidence"]["stores"].as_array().is_some_and(Vec::is_empty)));
    assert!(!rows.iter().any(|row| row["register_evidence"]["classification"] == "matching_register_reload"));
    let annotations = call(&client, &fixture, "list_annotations", json!({})).await;
    for values in annotations.as_object().unwrap().values().filter_map(Value::as_array) {
        assert!(values.is_empty());
    }
    client.cancel().await.unwrap();
    assert!(std::fs::read_dir(&fixture.0).unwrap().all(|entry| entry.unwrap().path() == fixture.path()));
}
