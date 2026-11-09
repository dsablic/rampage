use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
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

struct Input(std::path::PathBuf);

impl Input {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-mcp-file-layout-{}.bin", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn connect() -> RunningService<RoleClient, Client> {
    let (server, transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, Client>, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new("file_layout").with_arguments(arguments)).await.unwrap()
}

fn text(result: &CallToolResult) -> &str {
    &result.content[0].as_text().unwrap().text
}

#[tokio::test]
async fn file_layout_is_a_default_core_tool_mapping_a_headerless_image() {
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "file_layout").expect("file_layout is served by default");
    assert_eq!(tool.input_schema["required"], json!(["path"]));

    let mut bytes = vec![0xff; 256];
    bytes.extend([0x00, 0x20, 0x00, 0x20, 0x01, 0x01, 0x00, 0x08]);
    bytes.extend([0x41, 0x01, 0x00, 0x08].repeat(14));
    bytes.extend(b"boot v1\0config\0update failed\0");
    bytes.extend([0; 128]);
    let input = Input::new(&bytes);
    let result = call(&client, json!({"path": input.0, "offset": "0x80"})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let report: Value = serde_json::from_str(text(&result)).unwrap();

    assert_eq!(
        (report["source_offset"].as_u64(), report["source_length"].as_u64()),
        (Some(0x80), Some(bytes.len() as u64 - 128))
    );
    let kinds: Vec<(u64, &str)> = report["regions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|region| (region["offset"].as_u64().unwrap(), region["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [(0x80, "fill_ff"), (0x100, "occupied"), (0x15c, "fill_zero")]);
    assert_eq!(report["regions"][1]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(report["hints"][0]["kind"], "cortex_m_vector_table_candidate");
    assert_eq!(
        (
            report["hints"][0]["cortex_m"]["initial_sp"].as_str(),
            report["hints"][0]["cortex_m"]["reset_handler"].as_str()
        ),
        (Some("0x20002000"), Some("0x8000101"))
    );
    assert_eq!(report["hint_interpretation"], "heuristic_candidates_not_mappings");
    assert_eq!(report["string_clusters"][0]["strings"], 3);
    assert_eq!(report["continuation"], Value::Null);

    let result = call(&client, json!({"path": input.0, "offset": bytes.len()})).await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("empty"), "{}", text(&result));
    let result = call(&client, json!({"path": input.0, "image_offset": 0})).await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("image_offset"), "{}", text(&result));
    let result = call(&client, json!({"path": input.0, "block_size": 16})).await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("block_size"), "{}", text(&result));
    client.cancel().await.unwrap();
}
