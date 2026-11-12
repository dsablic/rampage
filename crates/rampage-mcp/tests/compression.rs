//! The unknown-firmware decompression path end to end: `file_layout` flags a header-checked compressed component,
//! `probe_compression` finds the codec parameters from its payload range and decoded-size word, and
//! `decode_file_range` reproduces the bytes from the candidate's `decode_arguments` unchanged.

use rampage_decode::encode;
use rampage_decode::{FlagOrder, Lzss, OffsetMode, ReferenceLayout};
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

struct Input(std::path::PathBuf);

impl Input {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-mcp-{name}-{}.bin", std::process::id()));
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

async fn call(client: &RunningService<RoleClient, Client>, tool: &str, arguments: Value) -> Result<Value, String> {
    let request = CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments.as_object().unwrap().clone());
    let result = client.call_tool(request).await.unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    if result.is_error == Some(true) { Err(text) } else { Ok(serde_json::from_str(&text).unwrap()) }
}

#[tokio::test]
async fn layout_hint_probe_and_decode_recover_a_compressed_component() {
    let original = encode::synthetic_firmware(20 << 10, 77);
    let variant = Lzss {
        window_bits: 12,
        min_match: 3,
        flag_order: FlagOrder::MsbFirst,
        literal_flag: true,
        layout: ReferenceLayout::Be16LengthLow,
        offset_mode: OffsetMode::DistanceMinusOne,
        initial_write_offset: 0,
        dictionary_fill: 0,
    };
    let payload = encode::lzss(&variant, &original);
    let sum = payload.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
    // A plain loader, erased flash, then a header: load address, payload size, decoded size, byte sum.
    let mut image = encode::synthetic_firmware(4096, 1);
    image.extend([0xff; 256]);
    for word in [0x2000_8000u32, payload.len() as u32, original.len() as u32, sum] {
        image.extend(word.to_le_bytes());
    }
    image.extend(&payload);
    image.extend([0xff; 1024]);
    let input = Input::new("compression", &image);
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    let probe = tools.iter().find(|tool| tool.name == "probe_compression").expect("probe_compression is core");
    assert!(probe.input_schema["required"].as_array().unwrap().contains(&json!("length")));

    let layout = call(&client, "file_layout", json!({"path": input.0})).await.unwrap();
    let hint = layout["hints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hint| hint["kind"] == "compressed_component_candidate")
        .expect("compressed component hint");
    let container = &hint["container"];
    assert_eq!(container["payload_offset"], 4096 + 256 + 16);
    assert_eq!(container["payload_length"], payload.len());
    assert_eq!(container["checksum_field"]["kind"], "byte_sum32");
    let decoded_size = &container["decoded_size_candidates"][0]["value"];
    assert_eq!(decoded_size, &json!(original.len()));

    let report = call(
        &client,
        "probe_compression",
        json!({"path": input.0, "offset": container["payload_offset"], "length": container["payload_length"],
               "expected_output_size": decoded_size}),
    )
    .await
    .unwrap();
    assert_eq!(report["interpretation"], "ranked_candidates_not_identifications");
    let best = &report["candidates"][0];
    assert_eq!(best["verdict"], "confident", "{report:#}");
    assert_eq!(best["decode_check"], "reproduced");
    assert_eq!(best["trailing_input_bytes"], 0);

    let mut arguments = best["decode_arguments"].clone();
    arguments["path"] = json!(input.0);
    let receipt = call(&client, "decode_file_range", arguments).await.unwrap();
    assert_eq!(receipt["output_sha256"], best["output_sha256"]);
    assert_eq!(receipt["input_fully_consumed"], true);
    assert_eq!(receipt["lzss"]["flag_order"], "msb_first");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn probe_refuses_unknown_fields_and_decode_refuses_mismatched_codec_parameters() {
    let input = Input::new("compression-refusals", &[0u8; 64]);
    let client = connect().await;
    let error =
        call(&client, "probe_compression", json!({"path": input.0, "offset": 0, "length": 64, "codec": "lzss"}))
            .await
            .unwrap_err();
    assert!(error.contains("codec"), "{error}");
    let lzss = json!({"window_bits": 12, "min_match": 3, "flag_order": "lsb_first", "literal_bit": 1,
        "reference_layout": "split_byte", "offset_mode": "distance"});
    for arguments in [
        json!({"codec": "lzss-4k", "lzss": lzss}),
        json!({"codec": "lzss"}),
        json!({"codec": "lzss", "lzss": lzss, "initial_write_offset": 5}),
        json!({"codec": "lz4-block", "dictionary_fill": 1}),
    ] {
        let mut arguments = arguments;
        arguments["path"] = json!(input.0);
        arguments["offset"] = json!(0);
        arguments["length"] = json!(64);
        arguments["expected_output_size"] = json!(64);
        let error = call(&client, "decode_file_range", arguments).await.unwrap_err();
        assert!(error.contains("lzss") || error.contains("lz4"), "{error}");
    }
    client.cancel().await.unwrap();
}
