use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

const AT: &str = "0x4000ae";
#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-local-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("owned.snapshot.json"),
            include_bytes!("../../../tests/data/local-variables-x64.snapshot.json"),
        )
        .unwrap();
        Self(path)
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
async fn call(client: &RunningService<RoleClient, Client>, name: &str, args: Value) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content[0].as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(text.len() <= 60_000);
    serde_json::from_str(text).unwrap()
}
async fn code(client: &RunningService<RoleClient, Client>, fixture: &Fixture) -> Value {
    call(client, "decompile", json!({"path":fixture.path(),"at":AT,"view":"code"})).await
}
fn fields(value: &Value) {
    let text = value["code"].as_str().unwrap();
    assert!(text.contains("state->gain") && text.contains("state->bias"), "{text}");
}

#[tokio::test]
async fn storage_keyed_native_edit_refreshes_c_and_survives_undo_redo_and_fresh_server_replay() {
    let fixture = Fixture::new();
    let client = connect().await;
    let before = code(&client, &fixture).await;
    assert!(!before["code"].as_str().unwrap().contains("->gain"));
    let local = before["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variable| {
            variable["kind"] == "local"
                && variable["editable"] == true
                && variable["storage"]["space"] == "stack"
                && variable["storage"]["size"] == 8
        })
        .expect("owned compiler fixture exposes one addressable pointer");
    let storage = local["storage"].clone();
    call(&client, "enable_tools", json!({"groups":["types"]})).await;
    call(
        &client,
        "set_types",
        json!({"path":fixture.path(),"at":AT,
        "text":"struct PhaseState { int4 gain; int4 bias; };"}),
    )
    .await;
    let edited = call(
        &client,
        "edit_variable",
        json!({"path":fixture.path(),"at":AT,
        "variable":local["name"],"name":"state","data_type":"struct PhaseState *"}),
    )
    .await;
    fields(&edited["decompilation"]);
    assert_eq!(edited["storage"], storage);
    assert_eq!(edited["edits"].as_array().unwrap().len(), 2);
    fields(&code(&client, &fixture).await);
    let annotations = call(&client, "list_annotations", json!({"path":fixture.path()})).await;
    for field in ["local_names", "local_types"] {
        let stored: Value = serde_json::from_str(annotations[field][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(stored[0]["storage"], storage);
    }
    for bad in [
        json!({"variable":"state","name":"return"}),
        json!({"variable":"state","data_type":"uint4"}),
        json!({"variable":local["name"],"name":"stale"}),
    ] {
        let mut args = bad;
        args["path"] = json!(fixture.path());
        args["at"] = json!(AT);
        let result = client
            .call_tool(CallToolRequestParams::new("edit_variable").with_arguments(args.as_object().unwrap().clone()))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
    }
    assert_eq!(call(&client, "list_annotations", json!({"path":fixture.path()})).await, annotations);
    call(&client, "undo", json!({"path":fixture.path()})).await;
    assert!(!code(&client, &fixture).await["code"].as_str().unwrap().contains("->gain"));
    call(&client, "redo", json!({"path":fixture.path()})).await;
    fields(&code(&client, &fixture).await);
    client.cancel().await.unwrap();
    let reopened = connect().await;
    fields(&code(&reopened, &fixture).await);
    call(&reopened, "enable_tools", json!({"groups":["types"]})).await;
    let cleared = call(
        &reopened,
        "edit_variable",
        json!({"path":fixture.path(),"at":AT,
        "storage":storage,"clear_name":true,"clear_type":true}),
    )
    .await;
    assert!(!cleared["decompilation"]["code"].as_str().unwrap().contains("->gain"));
    reopened.cancel().await.unwrap();
}

#[tokio::test]
async fn variable_edit_schema_is_group_gated_and_requires_an_unambiguous_selector() {
    let client = connect().await;
    let missing = "/nonexistent/owned-variable-fixture";
    let denied = client
        .call_tool(CallToolRequestParams::new("edit_variable").with_arguments(
            json!({"path":missing,"at":AT,"variable":"param_1","name":"state"}).as_object().unwrap().clone(),
        ))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true));
    assert!(denied.content[0].as_text().unwrap().text.contains("types"));
    call(&client, "enable_tools", json!({"groups":["types"]})).await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "edit_variable").unwrap();
    for key in ["variable", "storage", "name", "data_type", "clear_name", "clear_type"] {
        assert!(tool.input_schema["properties"].get(key).is_some());
    }
    client.cancel().await.unwrap();
}
