//! Owned ELF transport fixtures are inspected and exported, never executed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(90);

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct TestClient;
impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-mcp-patches-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf"),
            directory.join("source.elf"),
        )
        .unwrap();
        Self(directory)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn call(client: &RunningService<RoleClient, TestClient>, name: &str, args: Value, failed: bool) -> Value {
    let result = timeout(
        TIMEOUT,
        client.call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone())),
    )
    .await
    .unwrap()
    .unwrap();
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_eq!(result.is_error == Some(true), failed, "{name}: {text}");
    assert!(text.len() <= 60000);
    if failed { Value::String(text.clone()) } else { serde_json::from_str(text).expect("complete bounded JSON") }
}

async fn assert_return(client: &RunningService<RoleClient, TestClient>, path: &PathBuf, value: u8) {
    let result = call(client, "decompile", json!({ "path": path, "at": "main", "view": "code" }), false).await;
    assert!(result["code"].as_str().unwrap().contains(&format!("return {value};")), "{result}");
}

#[tokio::test]
async fn mcp_decompile_patch_undo_redo_export_and_reopen_follow_one_effective_revision() {
    timeout(Duration::from_secs(240), async {
        let fixture = Fixture::new();
        let source = fixture.0.join("source.elf");
        let original = std::fs::read(&source).unwrap();
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let mut server = Server(tokio::spawn(async move {
            RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
        }));
        let client = timeout(TIMEOUT, TestClient.serve(client_transport)).await.unwrap().unwrap();
        let listed = client.list_all_tools().await.unwrap();
        for name in ["patch_bytes", "revert_patch", "list_patches", "export_patched"] {
            let tool = listed.iter().find(|tool| tool.name == name).unwrap();
            assert!(tool.input_schema["required"].as_array().unwrap().contains(&json!("path")));
        }
        assert_return(&client, &source, 5).await;
        let baseline = call(&client, "list_patches", json!({"path":source}), false).await;
        let request = json!({
            "path": source, "at":"0x100191e", "original_hex":"b805000000", "replacement_hex":"b807000000",
            "allow_data":false, "source_sha256":baseline["receipt"]["source_sha256"],
            "expected_revision":baseline["receipt"]["revision_sha256"],
        });
        call(&client, "patch_bytes", request.clone(), false).await;
        assert_return(&client, &source, 7).await;
        call(&client, "patch_bytes", request, true).await;
        call(&client, "undo", json!({"path":source}), false).await;
        assert_return(&client, &source, 5).await;
        call(&client, "redo", json!({"path":source}), false).await;
        assert_return(&client, &source, 7).await;
        let patched = call(&client, "list_patches", json!({"path":source}), false).await;
        let destination = fixture.0.join("export.elf");
        let mut export = json!({
            "path": source, "destination": destination,
            "source_sha256": patched["receipt"]["source_sha256"], "expected_revision":"0".repeat(64),
        });
        call(&client, "export_patched", export.clone(), true).await;
        assert!(!destination.exists());
        export["expected_revision"] = patched["receipt"]["revision_sha256"].clone();
        call(&client, "export_patched", export.clone(), false).await;
        assert_return(&client, &destination, 7).await;
        call(&client, "export_patched", export, true).await;
        call(
            &client,
            "revert_patch",
            json!({
                "path": source, "at":"0x100191e", "source_sha256":patched["receipt"]["source_sha256"],
                "expected_revision":patched["receipt"]["revision_sha256"],
            }),
            false,
        )
        .await;
        assert_return(&client, &source, 5).await;
        assert_eq!(std::fs::read(source).unwrap(), original);
        assert!(!fixture.0.join("export.elf.rampage").exists());
        timeout(TIMEOUT, client.cancel()).await.unwrap().unwrap();
        timeout(TIMEOUT, &mut server.0).await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
