#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

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

#[cfg(unix)]
struct Fixture(PathBuf);
#[cfg(unix)]
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-decode-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("input.bin"), [7, b'A', b'B', b'C']).unwrap();
        Self(path)
    }
}
#[cfg(unix)]
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, TestClient>, arguments: Value) -> CallToolResult {
    client
        .call_tool(
            CallToolRequestParams::new("decode_file_range".to_owned())
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn decoder_is_explicit_core_and_returns_whole_transient_receipts_without_native_loading() {
    let fixture = Fixture::new();
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "decode_file_range").unwrap();
    assert!(tool.input_schema["required"].as_array().unwrap().contains(&json!("codec")));
    let result = call(
        &client,
        json!({
            "path": fixture.0.join("input.bin"), "codec": "lzss-4k", "offset": "0x0", "length": "0x4",
            "expected_output_size": 3,
        }),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = &result.content[0].as_text().unwrap().text;
    assert!(text.len() <= 16_384);
    let receipt: Value = serde_json::from_str(text).unwrap();
    assert_eq!(receipt["preview"]["ascii"], "ABC");
    assert_eq!(receipt["input_consumed"], 4);
    assert_eq!(receipt["completion"], "expected_output_size_reached");
    assert_eq!(receipt["input_fully_consumed"], true);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn decoder_rejects_implicit_selection_and_native_image_selectors_before_io() {
    let client = connect().await;
    let base = json!({"path": "/nonexistent/rampage-decode", "offset": 0, "length": 4, "expected_output_size": 3});
    let result = call(&client, base.clone()).await;
    assert_eq!(result.is_error, Some(true));
    assert!(result.content[0].as_text().unwrap().text.contains("codec"));
    for (field, value) in [("codec", json!("auto")), ("arch", json!("arm")), ("image_offset", json!(0))] {
        let mut args = base.clone();
        args["codec"] = json!("lzss-4k");
        args[field] = value;
        let result = call(&client, args).await;
        assert_eq!(result.is_error, Some(true));
        let text = &result.content[0].as_text().unwrap().text;
        assert!(!text.contains("source open"), "{text}");
    }
    client.cancel().await.unwrap();
}
