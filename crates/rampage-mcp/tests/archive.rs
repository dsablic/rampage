use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Input {
    directory: PathBuf,
    pub(crate) path: PathBuf,
    bytes: Vec<u8>,
}

impl Input {
    pub(crate) fn new(names: &[Vec<u8>]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rampage-mcp-zip32-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("input.zip");
        let bytes = zip(names);
        std::fs::write(&path, &bytes).unwrap();
        Self { directory, path, bytes }
    }

    fn unchanged(&self) {
        assert_eq!(std::fs::read(&self.path).unwrap(), self.bytes);
        assert_eq!(std::fs::read_dir(&self.directory).unwrap().count(), 1);
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
        std::fs::remove_dir(&self.directory).unwrap();
    }
}

fn zip(names: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if names.is_empty() { vec![] } else { b"PK\x03\x04not a local header".to_vec() };
    let cd = bytes.len();
    for name in names {
        let mut record = [0; 46];
        record[..4].copy_from_slice(b"PK\x01\x02");
        record[8..10].copy_from_slice(&9u16.to_le_bytes());
        record[10..12].copy_from_slice(&8u16.to_le_bytes());
        record[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend(record);
        bytes.extend(name);
    }
    let mut end = [0; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&(names.len() as u16).to_le_bytes());
    end[10..12].copy_from_slice(&(names.len() as u16).to_le_bytes());
    end[12..16].copy_from_slice(&((bytes.len() - cd) as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(cd as u32).to_le_bytes());
    bytes.extend(end);
    bytes
}

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

async fn call(client: &RunningService<RoleClient, TestClient>, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().unwrap().as_text().unwrap().text.as_str()
}

fn page(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    assert!(text(result).len() <= 60_000);
    serde_json::from_str(text(result)).unwrap()
}

#[tokio::test]
async fn archive_tool_is_carve_gated_path_required_and_works_on_nonloadable_zip_without_sidecars() {
    let input = Input::new(&[b"duplicate".to_vec(), b"duplicate".to_vec(), b"../member".to_vec()]);
    assert!(rampage_loaders::Binary::open(&input.path).is_err());
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "archive_inventory"));
    let refused = call(&client, "archive_inventory", json!({ "path": input.path })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("`carve` group"));
    page(&call(&client, "enable_tools", json!({ "groups": ["carve"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "archive_inventory").unwrap();
    assert!(
        !tool
            .input_schema
            .get("required")
            .is_some_and(|required| required.as_array().unwrap().contains(&json!("path"))),
        "path defaults to the session's target"
    );
    assert!(tool.input_schema["properties"].get("image_offset").is_none());
    let output = page(
        &call(
            &client,
            "archive_inventory",
            json!({ "path": input.path,
        "offset": 1, "limit": 1, "contains": "duplicate" }),
        )
        .await,
    );
    assert_eq!(output["declared"], 3);
    assert_eq!(output["examined"], 3);
    assert_eq!(output["validated"], 3);
    assert_eq!(output["retained"], 3);
    assert_eq!(output["matched"], 2);
    assert_eq!(output["returned"], 1);
    assert_eq!(output["members"][0]["member_ref"]["ordinal"], 1);
    assert_eq!(output["members"][0]["encrypted"], true);
    assert_eq!(output["members"][0]["data_descriptor"], true);
    assert_eq!(output["central_directory_complete"], true);
    assert_eq!(output["more"], false);
    let names = page(&call(&client, "archive_inventory", json!({ "path": input.path })).await);
    assert_eq!(names["members"][2]["name_display"], "../member");
    assert_ne!(names["members"][0]["member_ref"], names["members"][1]["member_ref"]);
    input.unchanged();
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn actual_mcp_results_are_valid_byte_bounded_json_with_stable_receipts_and_forward_paging() {
    let input = Input::new(&vec![vec![0; 1024]; 100]);
    let client = connect(RampageServer::with_groups([Group::Carve])).await;
    let mut offset = 0u64;
    let mut ordinals = Vec::new();
    let mut identity = None;
    loop {
        let result = call(&client, "archive_inventory", json!({ "path": input.path, "offset": offset })).await;
        let output = page(&result);
        if let Some(identity) = &identity {
            assert_eq!(&output["archive_ref"], identity);
        } else {
            identity = Some(output["archive_ref"].clone());
        }
        assert_eq!(output["validated"], 100);
        assert_eq!(output["matched"], 100);
        for member in output["members"].as_array().unwrap() {
            ordinals.push(member["member_ref"]["ordinal"].as_u64().unwrap());
        }
        if output["more"] == false {
            assert_eq!(output["next_offset"], Value::Null);
            break;
        }
        let next = output["next_offset"].as_u64().unwrap();
        assert!(next > offset);
        assert_eq!(next, offset + output["returned"].as_u64().unwrap());
        offset = next;
    }
    assert_eq!(ordinals, (0..100).collect::<Vec<_>>());
    input.unchanged();
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn unsupported_native_image_and_automatic_member_actions_are_refused_without_io() {
    let input = Input::new(&[]);
    let client = connect(RampageServer::with_groups([Group::Carve])).await;
    for field in ["arch", "image_offset", "image_length", "extract", "auto_open", "nest"] {
        let mut arguments = json!({ "path": "/nonexistent/rampage-mcp-archive" });
        arguments[field] = json!(0);
        let refused = call(&client, "archive_inventory", arguments).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(text(&refused).contains("unknown field"), "{}", text(&refused));
    }
    for arguments in [json!({}), json!({ "path": input.path, "limit": 0 }), json!({ "path": input.path, "offset": -1 })]
    {
        assert_eq!(call(&client, "archive_inventory", arguments).await.is_error, Some(true));
    }
    let empty = page(&call(&client, "archive_inventory", json!({ "path": input.path })).await);
    assert_eq!(empty["declared"], 0);
    assert_eq!(empty["members"], json!([]));
    input.unchanged();
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn deserialization_debug_expansion_returns_bounded_utf8_mcp_errors_without_opening_a_project() {
    let input = Input::new(&[]);
    let client = connect(RampageServer::with_groups([Group::Carve])).await;
    let unexpected = "\u{0085}".repeat(15_000);
    for field in ["offset", "limit"] {
        let mut arguments = json!({ "path": input.path });
        arguments[field] = json!(unexpected);
        assert!(arguments.to_string().len() < 48_000);
        let refused = call(&client, "archive_inventory", arguments).await;
        assert_eq!(refused.is_error, Some(true));
        let error = text(&refused);
        assert!(error.starts_with("invalid arguments:"), "{error}");
        assert!(error.contains("invalid type"));
        assert!(error.ends_with("[archive error truncated]"));
        assert!(error.len() <= 4096);
        assert!(std::str::from_utf8(error.as_bytes()).is_ok());
        assert!(!error.contains("cannot read"));
        input.unchanged();
    }
    client.cancel().await.unwrap();
}

/// A static library: archive_inventory lists its members with the path that opens each, and that path opens the
/// member in an ordinary binary tool; the whole library names its members instead.
#[tokio::test]
async fn static_library_members_are_listed_and_open_as_lib_member_paths() {
    let library = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/objects/libobjects-gnu.a");
    let client = connect(RampageServer::with_groups([Group::Carve])).await;
    let listing = page(&call(&client, "archive_inventory", json!({ "path": library })).await);
    assert_eq!((listing["format"].as_str(), listing["members_total"].as_u64()), (Some("ar"), Some(3)));
    let rows = listing["members"].as_array().unwrap();
    let opens: Vec<&str> = rows.iter().map(|row| row["open"].as_str().unwrap()).collect();
    assert!(opens[0].ends_with("(objects.o#0)") && opens[1].ends_with("(helper.o)"), "{opens:?}");
    let functions = page(&call(&client, "list_functions", json!({ "path": opens[0] })).await);
    assert!(functions.to_string().contains("\"dispatch\""), "{functions}");
    let decompiled = page(&call(&client, "decompile", json!({ "path": opens[0], "at": "main" })).await);
    assert!(decompiled.to_string().contains("printf("), "{decompiled}");
    let info = page(&call(&client, "binary_info", json!({ "path": opens[1] })).await);
    assert_eq!(info["archive_member"]["name"], "helper.o");
    assert!(info["relocatable"]["relocations_applied"].as_u64().unwrap() > 0);
    let whole = call(&client, "binary_info", json!({ "path": library })).await;
    assert_eq!(whole.is_error, Some(true));
    assert!(text(&whole).contains("objects.o#0"), "{}", text(&whole));
    client.cancel().await.unwrap();
}
