#[path = "../../rampage-api/tests/support/debug_layout_tools.rs"]
#[allow(dead_code)]
mod support;

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use support::{TempFiles, log_bytes, open, wrong_digest};

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

fn body(result: &CallToolResult, success: bool) -> Value {
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_eq!(result.is_error == Some(true), !success, "{text}");
    assert!(text.len() <= 60_000, "{} bytes", text.len());
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn layout_tool_is_types_gated_and_exposes_review_controls_without_renaming_legacy_tools() {
    let files = TempFiles::new();
    let path = files.negative();
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "import_debug_layouts"));
    let refused = body(&call(&client, "import_debug_layouts", json!({ "path": path, "apply": true })).await, false);
    assert_eq!(refused["apply_requested"], true);
    assert_eq!(refused["whole_apply_succeeded"], false);
    assert_eq!(refused["applied_total"], 0);
    assert!(refused["error"].as_str().unwrap().contains("`types` group"));
    assert!(!support::sidecar(&path).exists());
    body(&call(&client, "enable_tools", json!({ "groups": ["types"] })).await, true);
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "import_debug_layouts").unwrap();
    for property in ["path", "arch", "image_offset", "image_length", "apply", "review_sha256", "offset", "limit"] {
        assert!(tool.input_schema["properties"].get(property).is_some(), "{property}");
    }
    let required = tool.input_schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("path")));
    assert!(!required.contains(&json!("apply")));
    assert!(!required.contains(&json!("review_sha256")));
    assert_eq!(tool.input_schema["additionalProperties"], false);
    assert!(tools.iter().any(|tool| tool.name == "import_debug_signatures"));
    assert!(tools.iter().any(|tool| tool.name == "import_pdb_names"));
    assert!(client.peer_info().unwrap().instructions.as_deref().unwrap().contains("import_debug_layouts"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn invalid_layout_arguments_fail_before_source_or_sidecar_actions_with_bounded_json_receipts() {
    let files = TempFiles::new();
    let path = files.negative();
    let missing = path.with_file_name("missing.elf");
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    for image in [&path, &missing] {
        for extra in [
            json!({ "apply": true }),
            json!({ "review_sha256": "a".repeat(64) }),
            json!({ "apply": true, "review_sha256": "A".repeat(64) }),
            json!({ "apply": true, "review_sha256": "a".repeat(63) }),
            json!({ "apply": true, "review_sha256": "a".repeat(64), "limit": 0 }),
            json!({ "limit": 1001 }),
            json!({ "offset": -1 }),
            json!({ "apply": "true" }),
            json!({ "confirm": true }),
        ] {
            let mut arguments = extra.as_object().unwrap().clone();
            arguments.insert("path".to_owned(), json!(image));
            let rejected = body(&call(&client, "import_debug_layouts", Value::Object(arguments)).await, false);
            assert_eq!(rejected["ok"], false);
            assert_eq!(rejected["status"], "rejected");
            assert_eq!(rejected["whole_apply_succeeded"], false);
            assert_eq!(rejected["applied_total"], 0);
            assert!(
                rejected["error"].as_str().unwrap().contains("arguments")
                    || rejected["error"].as_str().unwrap().contains("review_sha256")
                    || rejected["error"].as_str().unwrap().contains("limit")
            );
            assert!(!support::sidecar(image).exists(), "validation opened an annotation sidecar");
        }
    }
    for arguments in [
        json!({ "apply": true, "review_sha256": "a".repeat(64) }),
        json!({ "path": path, "arch": [], "apply": true, "review_sha256": "a".repeat(64) }),
        json!({ "path": "/missing/".to_owned() + &"λ".repeat(60_000) }),
    ] {
        let rejected = body(&call(&client, "import_debug_layouts", arguments).await, false);
        assert_eq!(rejected["whole_apply_succeeded"], false);
        assert_eq!(rejected["applied_total"], 0);
        assert!(!support::sidecar(&path).exists());
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn negative_preview_and_wrong_digest_do_not_change_persisted_annotations() {
    let files = TempFiles::new();
    let path = files.negative();
    let project = open(&path);
    project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
    let before = log_bytes(&path);
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let preview = body(&call(&client, "import_debug_layouts", json!({ "path": path, "limit": 1 })).await, true);
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["apply_requested"], false);
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["approved_total"], 0, "negative fixture is not positive layout proof");
    assert_eq!(log_bytes(&path), before);
    let failed = body(
        &call(
            &client,
            "import_debug_layouts",
            json!({ "path": path, "apply": true,
                "review_sha256": wrong_digest(preview["review_sha256"].as_str().unwrap()) }),
        )
        .await,
        false,
    );
    assert_eq!(failed["apply_requested"], true);
    assert_eq!(failed["whole_apply_succeeded"], false);
    assert_eq!(failed["applied_total"], 0);
    assert_eq!(log_bytes(&path), before);
    assert!(open(&path).annotation_list().types.is_empty());
    assert!(open(&path).annotation_list().signatures.is_empty());
    client.cancel().await.unwrap();
}

#[tokio::test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
async fn compiled_mcp_whole_apply_reopens_refreshes_other_clients_and_undoes_one_complete_dependency_batch() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let files = TempFiles::new();
        let path = files.generated(variant, "flat");
        let expected = support::expected_functions(&open(&path));
        let before = log_bytes(&path);
        let client = connect(RampageServer::with_groups([Group::Types])).await;
        let observer = connect(RampageServer::default()).await;
        body(&call(&observer, "list_annotations", json!({ "path": path })).await, true);
        let preview = body(&call(&client, "import_debug_layouts", json!({ "path": path, "limit": 1 })).await, true);
        assert_eq!(preview["approved_total"], expected.len());
        assert_eq!(preview["more"], true);
        assert_eq!(log_bytes(&path), before);
        let applied = body(
            &call(
                &client,
                "import_debug_layouts",
                json!({ "path": path, "apply": true, "review_sha256": preview["review_sha256"],
                    "offset": usize::MAX, "limit": 1 }),
            )
            .await,
            true,
        );
        assert_eq!(applied["whole_apply_succeeded"], true);
        assert_eq!(applied["review_sha256"], preview["review_sha256"]);
        assert_eq!(applied["applied_total"], expected.len());
        assert_eq!(applied["imported_types_total"], 1);
        assert_eq!(applied["details"], json!([]));
        support::assert_atomic_append(&path, &before, expected.len() + 1, preview["image_sha256"].as_str().unwrap());
        support::assert_source_signatures(&open(&path));
        let refreshed = body(&call(&observer, "list_annotations", json!({ "path": path })).await, true);
        assert_eq!(refreshed["types"].as_array().unwrap().len(), 1);
        assert_eq!(refreshed["signatures"].as_array().unwrap().len(), expected.len());
        let persisted = log_bytes(&path);
        let stale = body(
            &call(
                &client,
                "import_debug_layouts",
                json!({ "path": path, "apply": true, "review_sha256": preview["review_sha256"] }),
            )
            .await,
            false,
        );
        assert_eq!(stale["whole_apply_succeeded"], false);
        assert_eq!(log_bytes(&path), persisted);
        let undo = body(&call(&client, "undo", json!({ "path": path })).await, true);
        assert_eq!(undo.as_array().unwrap().len(), expected.len() + 1);
        let refreshed = body(&call(&observer, "list_annotations", json!({ "path": path })).await, true);
        assert_eq!(refreshed["types"], json!([]));
        assert_eq!(refreshed["signatures"], json!([]));
        assert!(open(&path).annotation_list().types.is_empty());
        assert!(open(&path).annotation_list().signatures.is_empty());
        client.cancel().await.unwrap();
        observer.cancel().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
async fn another_clients_signature_change_requires_re_review_and_never_applies_a_partial_dependency_batch() {
    let files = TempFiles::new();
    let path = files.generated("dwarf5-o2", "flat");
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let writer = connect(RampageServer::with_groups([Group::Types])).await;
    let preview = body(&call(&client, "import_debug_layouts", json!({ "path": path })).await, true);
    body(
        &call(
            &writer,
            "set_signature",
            json!({ "path": path, "at": "debug_flat_read_first", "text": "int4 analyst_first(void *opaque);" }),
        )
        .await,
        true,
    );
    let before = log_bytes(&path);
    let stale = body(
        &call(
            &client,
            "import_debug_layouts",
            json!({ "path": path, "apply": true, "review_sha256": preview["review_sha256"] }),
        )
        .await,
        false,
    );
    assert_eq!(stale["whole_apply_succeeded"], false);
    assert_eq!(stale["applied_total"], 0);
    assert_eq!(log_bytes(&path), before);
    assert!(open(&path).annotation_list().types.is_empty());
    assert_eq!(open(&path).annotation_list().signatures.len(), 1);
    client.cancel().await.unwrap();
    writer.cancel().await.unwrap();
}
