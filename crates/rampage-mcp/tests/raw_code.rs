use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

#[cfg(unix)]
struct Fixture(std::path::PathBuf);
#[cfg(unix)]
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn raw_code_mapping_requires_explicit_mode_orders_and_rejects_native_selectors() {
    let (server, transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    let client = Client.serve(transport).await.unwrap();
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "inspect_raw_code").unwrap();
    let required = tool.input_schema["required"].as_array().unwrap();
    for field in ["arch", "mode", "code_byte_order", "data_byte_order", "base_address", "path"] {
        assert!(required.contains(&json!(field)));
    }
    let base = json!({ "path": "/nonexistent/raw-code", "offset": 0, "length": 4, "arch": "arm",
        "mode": "thumb", "code_byte_order": "little", "data_byte_order": "little", "base_address": "0x1000" });
    for field in ["mode", "code_byte_order", "data_byte_order", "base_address"] {
        let mut args = base.clone();
        args.as_object_mut().unwrap().remove(field);
        let result = client
            .call_tool(CallToolRequestParams::new("inspect_raw_code").with_arguments(args.as_object().unwrap().clone()))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].as_text().unwrap().text.contains(field));
    }
    let mut args = base;
    args["image_offset"] = json!(0);
    let result = client
        .call_tool(CallToolRequestParams::new("inspect_raw_code").with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(result.content[0].as_text().unwrap().text.contains("image_offset"));
    client.cancel().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn raw_thumb_window_without_a_header_has_source_coordinates_hash_and_real_instructions() {
    let path = std::env::temp_dir().join(format!("rampage-mcp-raw-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);
    let file = fixture.0.join("input.bin");
    std::fs::write(&file, [0xaa, 0xbb, 0x00, 0xbf, 0x70, 0x47, 0xcc]).unwrap();
    let (server, transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    let client = Client.serve(transport).await.unwrap();
    let result = client.call_tool(CallToolRequestParams::new("inspect_raw_code").with_arguments(json!({
        "path": file, "offset": "0x2", "length": 4, "arch": "arm", "mode": "thumb",
        "code_byte_order": "little", "data_byte_order": "little", "base_address": "0x1000", "instruction_limit": 1,
    }).as_object().unwrap().clone())).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = &result.content[0].as_text().unwrap().text;
    assert!(text.len() <= 60_000);
    let report: Value = serde_json::from_str(text).unwrap();
    assert_eq!(report["source_offset"], 2);
    assert_eq!(report["mapping"]["mapping_validation"], "analyst_asserted");
    assert_eq!(report["mapping"]["rows"][0]["address"], "0x1000");
    assert_eq!(report["mapping"]["rows"][0]["bytes"], "00bf");
    assert_eq!(report["continuation"]["source_offset"], 4);
    assert_eq!(report["continuation"]["base_address"], "0x1002");
    assert_eq!(report["source_range_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    client.cancel().await.unwrap();
}
