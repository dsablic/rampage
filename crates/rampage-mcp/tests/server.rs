use std::path::PathBuf;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_string_lossy().into_owned()
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
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
async fn lists_all_tools_with_instructions() {
    let client = connect().await;
    let mut names: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
    names.sort();
    let expected = [
        "analysis_diagnostics",
        "binary_info",
        "build_signatures",
        "capabilities",
        "class_evidence",
        "compare_runtime_bytes",
        "decompile",
        "disassemble",
        "function_graph",
        "function_summary",
        "identify_functions",
        "import_debug_signatures",
        "inspect_jump_table",
        "language_metadata",
        "list_annotations",
        "list_exports",
        "list_functions",
        "list_imports",
        "list_strings",
        "observe_indirect_branch",
        "observe_pointer",
        "redo",
        "rename",
        "set_comment",
        "set_global",
        "set_signature",
        "set_types",
        "triage",
        "undo",
        "xrefs",
    ];
    assert_eq!(names, expected);
    let info = client.peer_info().unwrap();
    assert_eq!(info.server_info.as_ref().unwrap().name, "rampage");
    assert!(info.instructions.as_deref().unwrap().contains("list_functions"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn explores_a_binary_end_to_end() {
    let client = connect().await;
    let path = fixture("hello-x64.elf");

    let info = json_of(&call(&client, "binary_info", json!({ "path": path })).await);
    assert_eq!(info["format"], "elf");
    assert_eq!(info["entry"], "0x10018c0");

    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "main" })).await);
    let main = functions["items"].as_array().unwrap().iter().find(|row| row["name"] == "main").unwrap();
    assert_eq!(main["address"], "0x1001910");

    let lines = json_of(&call(&client, "disassemble", json!({ "path": path, "at": "main", "count": 3 })).await);
    assert_eq!(lines.as_array().unwrap().len(), 3);
    assert_eq!(lines[0]["label"], "main");

    let xrefs = json_of(&call(&client, "xrefs", json!({ "path": path, "to": "puts" })).await);
    assert!(xrefs["items"].as_array().unwrap().iter().any(|row| row["from_function"] == "main"));

    let strings = json_of(&call(&client, "list_strings", json!({ "path": path, "contains": "greeting" })).await);
    assert_eq!(strings["total"], 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn function_summary_exposes_ssa_through_the_shared_registry() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-ssa-diamond.snapshot.json")
        .to_string_lossy()
        .into_owned();
    let summary = json_of(&call(&client, "function_summary", json!({ "path": path, "at": "0x1000" })).await);
    assert!(
        summary["ssa"]["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|definition| definition["expression"]["kind"] == "phi"
                && definition["expression"]["inputs"].as_array().unwrap().len() == 2)
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pages_are_capped() {
    let client = connect().await;
    let page = json_of(&call(&client, "list_functions", json!({ "path": fixture("hello-x64.elf"), "limit": 2 })).await);
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(page["total"].as_u64().unwrap() > 2);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn arm64_functions_are_listed() {
    let client = connect().await;
    let arm = call(&client, "list_functions", json!({ "path": fixture("hello-arm64.macho") })).await;
    assert_eq!(arm.is_error, Some(false));
    assert!(text(&arm).contains("\"_main\""), "{}", text(&arm));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn failures_are_tool_errors_the_caller_can_read() {
    let client = connect().await;
    let missing = call(&client, "binary_info", json!({ "path": "/nonexistent/binary" })).await;
    assert_eq!(missing.is_error, Some(true));
    assert!(text(&missing).contains("/nonexistent/binary"), "{}", text(&missing));

    let path = fixture("hello-x64.elf");
    let ambiguous = call(&client, "xrefs", json!({ "path": path, "to": "main", "from": "main" })).await;
    assert_eq!(ambiguous.is_error, Some(true));

    let bad_arch = call(&client, "binary_info", json!({ "path": path, "arch": "vax" })).await;
    assert!(text(&bad_arch).contains("unknown architecture"));

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pointer_observations_preserve_writable_slot_values_without_annotations() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-thumb-pointer.snapshot.json")
        .to_string_lossy()
        .into_owned();
    let observation = json_of(&call(&client, "observe_pointer", json!({"path": path, "at": "0x3004"})).await);
    assert_eq!(observation["raw_value"], "0x1003");
    assert_eq!(observation["slot_permissions"]["write"], true);
    assert_eq!(observation["candidate_target"], "0x1002");
    let annotations = json_of(&call(&client, "list_annotations", json!({"path": path})).await);
    assert!(annotations["names"].as_array().unwrap().is_empty());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn branch_observation_decodes_explicit_window_without_resolving_captured_flow() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let result = json_of(
        &call(&client, "observe_indirect_branch", json!({"path": path, "start": "0x1000", "at": "0x1008"})).await,
    );
    assert_eq!(result["flow"]["kind"], "indirect_jump");
    assert_eq!(result["load_address"], "0x1004");
    assert_eq!(result["pointer"]["slot"], "0x3000");
    assert_eq!(result["capture_identity"], result["pointer"]["capture_identity"]);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn runtime_comparison_ignores_sidecars_and_requires_explicit_matching_originals() {
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(std::env::temp_dir().join(format!("rampage-mcp-compare-{}", std::process::id())));
    std::fs::create_dir(&directory.0).unwrap();
    let original = fixture("hello-arm64.macho");
    let binary = rampage_loaders::Binary::open(&original).unwrap();
    let rampage_loaders::Details::MachO(details) = &binary.details else { panic!("not Mach-O") };
    let uuid = details.uuid.as_deref().unwrap();
    let image_base =
        binary.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let snapshot = json!({"format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
        "provenance": "controlled MCP comparison", "regions": [{"name": "header", "address": "0x1000",
            "permissions": "r--", "bytes": "cffaedfe"}], "modules": [{"name": "fixture",
            "path": "/never/open/this", "uuid": uuid, "image_base": format!("{image_base:#x}"),
            "runtime_base": "0x1000"}]});
    let path = directory.0.join("snapshot.json");
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    std::fs::create_dir(path.with_extension("json.rampage")).unwrap();
    let client = connect().await;
    let mut arguments = json!({"path": path, "original": original, "module": uuid,
        "ranges": [{"address": "0x1000", "size": 6}], "limit": 1});
    let first = json_of(&call(&client, "compare_runtime_bytes", arguments.clone()).await);
    assert_eq!(first["equal_bytes"], 4);
    assert_eq!(first["unavailable_bytes"], 2);
    assert_eq!(first["spans_total"], 2);
    assert_eq!(first["spans"].as_array().unwrap().len(), 1);
    arguments["offset"] = json!(1);
    let second = json_of(&call(&client, "compare_runtime_bytes", arguments.clone()).await);
    assert_eq!(second["spans"][0]["status"], "capture_unavailable");
    assert_eq!(second["capture_identity"], first["capture_identity"]);
    arguments["module"] = json!("00000000000000000000000000000000");
    assert_eq!(call(&client, "compare_runtime_bytes", arguments.clone()).await.is_error, Some(true));
    arguments["original"] = json!("/nonexistent/explicit-original");
    let error = call(&client, "compare_runtime_bytes", arguments).await;
    assert_eq!(error.is_error, Some(true));
    assert!(text(&error).starts_with("/nonexistent/explicit-original: "), "{}", text(&error));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn triage_and_imports_describe_a_binary() {
    let client = connect().await;
    let path = fixture("hello-x64-dyn.elf");
    let triage = json_of(&call(&client, "triage", json!({ "path": path })).await);
    assert_eq!(triage["image_hashes"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(triage["details"]["format"], "elf");
    assert_eq!(triage["details"]["interpreter"], "/lib64/ld-linux-x86-64.so.2");
    let imports = json_of(&call(&client, "list_imports", json!({ "path": path, "contains": "puts" })).await);
    assert_eq!(imports["total"], 1);
    assert_eq!(imports["items"][0]["library"], "libc.so.6");
    assert!(imports["items"][0]["slot"].as_str().unwrap().starts_with("0x"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn agents_rename_and_comment() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(fixture("hello-arm64.macho"), &path).unwrap();
    let path = path.to_str().unwrap();
    let client = connect().await;
    let renamed = json_of(&call(&client, "rename", json!({ "path": path, "at": "_main", "name": "say_hello" })).await);
    assert_eq!(renamed["changed"], true);
    json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "text": "entry" })).await);
    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "say_" })).await);
    assert_eq!(functions["items"][0]["name"], "say_hello");
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(list["comments"][0]["text"], "entry");
    let undone = json_of(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undone["field"], "comment");
    let redone = json_of(&call(&client, "redo", json!({ "path": path })).await);
    assert_eq!(redone["value"], "entry");
    let cleared =
        json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "clear": true })).await);
    assert_eq!((&cleared["value"], &cleared["changed"]), (&json!(null), &json!(true)));
    let neither = call(&client, "rename", json!({ "path": path, "at": "say_hello" })).await;
    assert_eq!(neither.is_error, Some(true));
    let bad = call(&client, "rename", json!({ "path": path, "at": "say_hello", "name": "two words" })).await;
    assert_eq!(bad.is_error, Some(true));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}
