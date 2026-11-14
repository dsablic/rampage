//! `evaluate_function` over MCP: a core tool listed without enabling a group, which runs fixture functions on
//! arguments (cdecl with a 64-bit edx:eax result, Thumb-2 with a buffer) and names why a run stopped.

use std::path::PathBuf;

use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

type Client = RunningService<RoleClient, ()>;

async fn connect() -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

async fn call(client: &Client, arguments: Value) -> (bool, Value) {
    let result: CallToolResult = client
        .call_tool(
            CallToolRequestParams::new("evaluate_function".to_owned())
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let text = result.content.first().unwrap().as_text().unwrap().text.as_str();
    (result.is_error == Some(true), serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned())))
}

fn fixture(path: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(path).to_str().unwrap().to_owned()
}

#[tokio::test]
async fn evaluate_function_runs_functions_and_names_stops() {
    let client = connect().await;
    let listed = client.list_all_tools().await.unwrap();
    assert!(listed.iter().any(|tool| tool.name == "evaluate_function"), "a core tool");

    // scale64(16, 3) of tests/fixtures/bench-v3/src/semantics.c, returned in edx:eax.
    let x86 = fixture("bench-v3/twins/semantics-x86.elf");
    let (failed, report) =
        call(&client, json!({"path": x86, "at": "scale64", "args": [16, 3], "return_bits": 64})).await;
    assert!(!failed, "{report}");
    let wide = (16u64 * 3).wrapping_add(16 << 21);
    let expected = (wide ^ (wide >> 29)).wrapping_sub(3 * 0x1_0000_0001);
    assert_eq!(report["stop"], "returned", "{report}");
    assert_eq!(report["convention"], "cdecl");
    assert_eq!(report["result"]["unsigned"], expected, "{report}");
    assert_eq!(report["result"]["registers"], json!(["EDX", "EAX"]));
    assert_eq!(report["arguments"][0]["location"], "stack+0x4");

    // A Thumb-2 strlen of the static runtime on a text buffer, and the buffer's final contents.
    let thumb = fixture("bin/hello-thumb.elf");
    let (_, report) =
        call(&client, json!({"path": thumb, "at": "0x20e8c", "args": [{"buffer": {"text": "four"}}]})).await;
    assert_eq!(report["result"]["unsigned"], 4, "{report}");
    assert_eq!(report["buffers"][0]["text"], "four");

    // A dynamically linked call stops at the import, named.
    let dynamic = fixture("bin/hello-arm64.elf");
    let (_, report) = call(&client, json!({"path": dynamic, "at": "main"})).await;
    assert_eq!(report["stop"], "external_call", "{report}");
    assert!(report["detail"].as_str().unwrap().contains("puts"), "{report}");
    assert!(report.get("result").is_none());

    // Requests that cannot run are tool errors, not stops.
    let (failed, report) = call(&client, json!({"path": x86, "at": "scale64", "convention": "win64"})).await;
    assert!(failed, "{report}");
}
