//! `transfer_annotations` over MCP: preview, conflicts, apply with a provenance ledger entry, and undo.

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

async fn call(client: &Client, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().unwrap().as_text().unwrap().text.as_str()
}

fn body(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

fn row<'a>(report: &'a Value, kind: &str, value: &str) -> &'a Value {
    let rows = report["rows"].as_array().unwrap();
    rows.iter().find(|row| row["kind"] == kind && row["value"] == value).unwrap_or_else(|| panic!("{report}"))
}

fn comments(listed: &Value) -> Vec<&str> {
    listed["comments"].as_array().unwrap().iter().map(|row| row["text"].as_str().unwrap()).collect()
}

#[tokio::test]
async fn transfer_previews_applies_with_provenance_and_undoes() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-transfer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let (old, new) = (directory.join("old.elf"), directory.join("new.elf"));
    std::fs::copy(&fixture, &old).unwrap();
    std::fs::copy(&fixture, &new).unwrap();
    let (old, new) = (old.to_str().unwrap(), new.to_str().unwrap());
    let client = connect().await;

    body(&call(&client, "rename", json!({ "path": old, "at": "main", "name": "entry_logic" })).await);
    body(
        &call(&client, "set_comment", json!({ "path": old, "at": "entry_logic", "text": "prints the greeting" })).await,
    );
    body(&call(&client, "set_comment", json!({ "path": old, "at": "add", "text": "adds two ints" })).await);
    // The new build already comments main differently: that comment is a conflict.
    body(&call(&client, "set_comment", json!({ "path": new, "at": "main", "text": "analyst note" })).await);

    let preview = body(&call(&client, "transfer_annotations", json!({ "path": new, "from": old })).await);
    assert_eq!(preview["status"], "preview");
    assert!(preview["matching"]["matched"].as_u64().unwrap() > 0, "{preview}");
    assert_eq!(preview["matching"]["changed"], 0);
    assert_eq!(preview["source"]["sha256"], preview["target"]["sha256"]);
    // A user name over a real symbol of the new build is a conflict, never a silent replacement.
    let name = row(&preview, "name", "entry_logic");
    assert_eq!(name["status"], "conflict", "{name}");
    assert!(name["reason"].as_str().unwrap().contains("`main`"), "{name}");
    let comment = row(&preview, "comment", "prints the greeting");
    assert_eq!(comment["status"], "conflict");
    assert!(comment["reason"].as_str().unwrap().contains("analyst note"), "{comment}");
    let adds = row(&preview, "comment", "adds two ints");
    assert_eq!(adds["status"], "transfer", "{adds}");
    assert!(adds["confidence"].as_f64().unwrap() >= 0.9, "{adds}");
    // A preview writes nothing.
    let listed = body(&call(&client, "list_annotations", json!({ "path": new })).await);
    assert_eq!(comments(&listed), ["analyst note"]);

    // Paging reuses the matching; a bad threshold is refused.
    let matches = body(
        &call(&client, "transfer_annotations", json!({ "path": new, "from": old, "list": "matches", "limit": 1 }))
            .await,
    );
    assert_eq!(matches["reused_matching"], true);
    assert_eq!((matches["returned"].as_u64(), matches["next_offset"].as_u64()), (Some(1), Some(1)));
    assert!(matches["rows"][0]["method"].is_string());
    let refused =
        call(&client, "transfer_annotations", json!({ "path": new, "from": old, "min_confidence": 2.0 })).await;
    assert_eq!(refused.is_error, Some(true));

    let applied =
        body(&call(&client, "transfer_annotations", json!({ "path": new, "from": old, "apply": true })).await);
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["applied"]["changed"], 1, "{applied}");
    assert_eq!(applied["applied"]["batches"], 1);
    assert_eq!(applied["applied"]["batches_needed"], 1);
    let finding = applied["applied"]["provenance_finding"].as_u64().unwrap();
    let listed = body(&call(&client, "list_annotations", json!({ "path": new })).await);
    assert!(comments(&listed).contains(&"adds two ints"), "{listed}");
    let ledger = body(&call(&client, "list_findings", json!({ "path": new })).await);
    let entry = &ledger["findings"][0];
    assert_eq!(entry["id"].as_u64(), Some(finding));
    assert!(entry["text"].as_str().unwrap().contains(preview["source"]["sha256"].as_str().unwrap()), "{entry}");

    // Applying again finds the comment already present.
    let again = body(&call(&client, "transfer_annotations", json!({ "path": new, "from": old })).await);
    assert_eq!(row(&again, "comment", "adds two ints")["status"], "already_present");

    // One undo removes the transferred comment and the provenance entry together.
    body(&call(&client, "undo", json!({ "path": new })).await);
    let listed = body(&call(&client, "list_annotations", json!({ "path": new })).await);
    assert_eq!(comments(&listed), ["analyst note"]);
    let ledger = body(&call(&client, "list_findings", json!({ "path": new })).await);
    assert_eq!(ledger["total"], 0, "{ledger}");
    std::fs::remove_dir_all(&directory).unwrap();
}
