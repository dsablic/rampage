use crate::pdb_support as support;

use rampage_api::Session;
use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use support::{TempFiles, fixture, rsds_offset};

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

async fn call(client: &RunningService<RoleClient, TestClient>, tool: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().unwrap().as_text().unwrap().text.as_str()
}

fn body(result: &CallToolResult) -> Value {
    assert!(text(result).len() <= 60_000, "{}", text(result).len());
    serde_json::from_str(text(result)).unwrap()
}

fn success(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    body(result)
}

#[tokio::test]
async fn pdb_tool_is_types_gated_and_requires_separate_binary_and_pdb_paths() {
    let files = TempFiles::new();
    let path = files.write("gated.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    files.write("gated.pdb", &std::fs::read(fixture("fixture.pdb")).unwrap());
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "import_pdb_names"));
    let refused =
        call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true })).await;
    assert_eq!(refused.is_error, Some(true));
    let receipt = body(&refused);
    assert_eq!(receipt["whole_apply_succeeded"], false);
    assert_eq!(receipt["applied_total"], 0);
    assert!(receipt["error"].as_str().unwrap().contains("`types` group"));
    assert!(!path.with_extension("exe.rampage").exists());
    success(&call(&client, "enable_tools", json!({ "groups": ["types"] })).await);
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "import_pdb_names").unwrap();
    let schema = &tool.input_schema;
    for required in ["path", "pdb"] {
        assert!(schema["required"].as_array().unwrap().contains(&json!(required)), "{required}");
    }
    for property in ["arch", "image_offset", "image_length", "apply", "offset", "limit"] {
        assert!(schema["properties"].get(property).is_some(), "{property}");
    }
    assert!(!schema["required"].as_array().unwrap().contains(&json!("apply")));
    let missing = call(&client, "import_pdb_names", json!({ "path": path, "apply": true })).await;
    assert_eq!(missing.is_error, Some(true));
    assert_eq!(body(&missing)["whole_apply_succeeded"], false);
    let annotations = success(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(annotations["names"], json!([]));
    assert!(client.peer_info().unwrap().instructions.as_deref().unwrap().contains("import_pdb_names"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pdb_preview_is_unchanged_and_whole_apply_persists_refreshes_and_undoes_one_batch() {
    let files = TempFiles::new();
    let path = files.write("apply.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let observer = connect(RampageServer::default()).await;
    let before = success(&call(&observer, "list_annotations", json!({ "path": path })).await);
    assert_eq!(before["names"], json!([]));
    let sidecar = path.with_extension("exe.rampage");
    let before_log = std::fs::read(&sidecar).unwrap_or_default();
    let preview = success(
        &call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb"), "limit": 1 })).await,
    );
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["applied_total"], 0);
    assert_eq!(preview["details"].as_array().unwrap().len(), 1);
    assert_eq!(preview["more"], true);
    assert_eq!(std::fs::read(&sidecar).unwrap_or_default(), before_log);
    let applied = success(
        &call(
            &client,
            "import_pdb_names",
            json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true,
                "offset": usize::MAX, "limit": 1 }),
        )
        .await,
    );
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["preview_total"], preview["preview_total"]);
    assert_eq!(applied["identity"], preview["identity"]);
    assert_eq!(applied["applied_total"], 2);
    assert_eq!(applied["details"], json!([]));
    assert_eq!(applied["more"], false);
    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(reopened.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    let refreshed = success(&call(&observer, "list_annotations", json!({ "path": path })).await);
    assert_eq!(refreshed["names"].as_array().unwrap().len(), 2);
    let next_preview = success(
        &call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb"), "offset": 1 })).await,
    );
    assert_eq!(next_preview["whole_apply_succeeded"], false);
    assert_eq!(next_preview["applied_total"], 0);
    assert_eq!(next_preview["preserved_total"], next_preview["preview_total"]);
    let undo = success(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undo.as_array().unwrap().len(), 2);
    assert!(undo.as_array().unwrap().iter().all(|edit| edit["field"] == "name"));
    let refreshed = success(&call(&observer, "list_annotations", json!({ "path": path })).await);
    assert_eq!(refreshed["names"], json!([]));
    client.cancel().await.unwrap();
    observer.cancel().await.unwrap();
}

#[tokio::test]
async fn pdb_apply_preserves_a_concurrent_label_that_arrived_after_preview() {
    let files = TempFiles::new();
    let path = files.write("concurrent.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let writer = connect(RampageServer::default()).await;
    let preview =
        success(&call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb") })).await);
    success(&call(&writer, "rename", json!({ "path": path, "at": "0x140001000", "name": "other_client_mix" })).await);
    let applied = success(
        &call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true })).await,
    );
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["applied_total"], 1);
    assert_eq!(applied["preserved_total"].as_u64().unwrap(), preview["preserved_total"].as_u64().unwrap() + 1);
    let mix = applied["details"].as_array().unwrap().iter().find(|detail| detail["name"] == "pdb_mix").unwrap();
    assert_eq!(mix["status"], "preserved");
    let undo = success(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undo.as_array().unwrap().len(), 1);
    let names = success(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(names["names"].as_array().unwrap().len(), 1);
    assert_eq!(names["names"][0]["text"], "other_client_mix");
    client.cancel().await.unwrap();
    writer.cancel().await.unwrap();
}

#[tokio::test]
async fn pdb_identity_malformed_arguments_and_large_errors_return_bounded_failure_receipts_without_edits() {
    let files = TempFiles::new();
    let image = std::fs::read(fixture("fixture.exe")).unwrap();
    let path = files.write("errors.exe", &image);
    let mut mismatch = image.clone();
    mismatch[rsds_offset(&image) + 4] ^= 1;
    let mismatch = files.write("mismatch.exe", &mismatch);
    let pdb = std::fs::read(fixture("fixture.pdb")).unwrap();
    let truncated = files.write("truncated.pdb", &pdb[..pdb.len() - 1]);
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    for arguments in [
        json!({ "path": mismatch, "pdb": fixture("fixture.pdb"), "apply": true }),
        json!({ "path": path, "pdb": truncated, "apply": true }),
        json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true, "limit": 0 }),
        json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": "true" }),
        json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true, "auto_sidecar": true }),
        json!({ "path": path, "pdb": "/nonexistent/".to_owned() + &"\u{03bb}".repeat(70_000), "apply": true }),
        json!({ "path": "/nonexistent/".to_owned() + &"\u{03bb}".repeat(70_000),
            "pdb": fixture("fixture.pdb"), "apply": true }),
        json!({ "pdb": fixture("fixture.pdb"), "apply": true }),
        json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true, "arch": "not-an-architecture" }),
    ] {
        let failed = call(&client, "import_pdb_names", arguments).await;
        assert_eq!(failed.is_error, Some(true));
        let receipt = body(&failed);
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["status"], "rejected");
        assert_eq!(receipt["whole_apply_succeeded"], false);
        assert_eq!(receipt["applied_total"], 0);
        assert!(receipt["error"].is_string());
        for path in [&path, &mismatch] {
            let annotations = success(&call(&client, "list_annotations", json!({ "path": path })).await);
            assert_eq!(annotations["names"], json!([]));
        }
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn invalid_arch_refuses_pdb_apply_and_other_binary_tools_before_creating_a_sidecar() {
    let files = TempFiles::new();
    let path = files.write("invalid-arch.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let sidecar = path.with_extension("exe.rampage");
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    for arch in [json!([]), json!({}), json!(true), json!(false), json!(42), json!(1.5), json!("unknown-arch")] {
        let refused = call(
            &client,
            "import_pdb_names",
            json!({ "path": path, "pdb": fixture("fixture.pdb"), "apply": true, "arch": arch }),
        )
        .await;
        assert_eq!(refused.is_error, Some(true), "arch={arch}: {}", text(&refused));
        let receipt = body(&refused);
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["status"], "rejected");
        assert_eq!(receipt["apply_requested"], true);
        assert_eq!(receipt["whole_apply_succeeded"], false);
        assert_eq!(receipt["applied_total"], 0);
        assert_eq!(receipt["identity"], Value::Null);
        assert_eq!(receipt["details"], json!([]));
        assert!(receipt["error"].as_str().unwrap().contains("arch"), "{receipt}");
        assert!(!sidecar.exists(), "arch={arch} created a sidecar before refusing the apply");

        let refused = call(&client, "binary_info", json!({ "path": path, "arch": arch })).await;
        assert_eq!(refused.is_error, Some(true), "arch={arch}: {}", text(&refused));
        assert!(text(&refused).contains("arch"), "{}", text(&refused));
        assert!(!sidecar.exists(), "arch={arch} created a sidecar before refusing binary_info");
    }
    let annotations = success(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(annotations["names"], json!([]));
    let undo = success(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undo, json!([]));
    for arch in [Value::Null, json!("x86_64")] {
        let preview = success(
            &call(&client, "import_pdb_names", json!({ "path": path, "pdb": fixture("fixture.pdb"), "arch": arch }))
                .await,
        );
        assert_eq!(preview["status"], "preview");
        assert_eq!(preview["whole_apply_succeeded"], false);
        assert_eq!(preview["applied_total"], 0);
        assert!(preview["identity"]["guid"].is_string());
    }
    let annotations = success(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(annotations["names"], json!([]));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pdb_tool_uses_the_selected_embedded_pe_and_keeps_its_annotations_separate() {
    let files = TempFiles::new();
    let image = std::fs::read(fixture("fixture.exe")).unwrap();
    let mut file = image.clone();
    file.extend(b"not executable padding");
    let offset = file.len();
    file.extend_from_slice(&image);
    let path = files.write("embedded.bin", &file);
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let arguments = json!({ "path": path, "arch": "x86_64", "image_offset": format!("{offset:#x}"),
        "image_length": image.len(), "pdb": fixture("fixture.pdb"), "apply": true, "limit": 1 });
    let imported = success(&call(&client, "import_pdb_names", arguments).await);
    assert_eq!(imported["whole_apply_succeeded"], true);
    assert_eq!(imported["applied_total"], 2);
    let inner = success(
        &call(
            &client,
            "list_annotations",
            json!({ "path": path, "image_offset": offset,
            "image_length": image.len(), "arch": "x86_64" }),
        )
        .await,
    );
    assert_eq!(inner["names"].as_array().unwrap().len(), 2);
    let outer = success(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(outer["names"], json!([]));
    let undone = success(
        &call(
            &client,
            "undo",
            json!({ "path": path, "image_offset": offset,
            "image_length": image.len(), "arch": "x86_64" }),
        )
        .await,
    );
    assert_eq!(undone.as_array().unwrap().len(), 2);
    client.cancel().await.unwrap();
}
