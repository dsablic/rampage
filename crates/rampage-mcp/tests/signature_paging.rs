//! In-memory MCP coverage; fixtures are read, never executed or compiled.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::Session;
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

type Client = RunningService<RoleClient, TestClient>;

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-signature-paging-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn copy(&self, source: &Path, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::copy(source, &path).unwrap();
        path
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(&self.0);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

async fn connect() -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    let client = TestClient.serve(client_transport).await.unwrap();
    body(&call(&client, "enable_tools", json!({"groups": ["detection"]})).await);
    client
}

async fn call(client: &Client, name: &str, args: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn body(result: &CallToolResult) -> Value {
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(text.len() <= 60_000, "{} bytes", text.len());
    serde_json::from_str(text).expect("signature MCP responses must be complete JSON")
}

async fn collect_pages(client: &Client, mut args: Value, expected: usize, limit: usize) -> Vec<Value> {
    let mut offset = 0;
    let mut rows = Vec::new();
    let mut addresses = BTreeSet::new();
    let mut warnings = Vec::new();
    loop {
        args["offset"] = json!(offset);
        args["limit"] = json!(limit);
        let page = body(&call(client, "identify_functions", args.clone()).await);
        assert_eq!(page["matched"], json!(expected));
        assert_eq!(page["applied"], 0);
        assert_eq!(page["totals_scope"], "whole_result");
        let matches = page["matches"].as_array().unwrap();
        let page_warnings = page["warnings"].as_array().unwrap();
        assert!(matches.len() + page_warnings.len() <= limit);
        for row in matches {
            let address = u64::from_str_radix(row["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            assert!(addresses.insert(address), "repeated address {address:#x}");
            rows.push(row.clone());
        }
        warnings.extend(page_warnings.iter().cloned());
        assert_eq!(page["matches_omitted"], json!(expected - matches.len()));
        if page["more"] == false {
            assert_eq!(page["next_offset"], Value::Null);
            assert_eq!(page["details_total"], json!(rows.len() + warnings.len()));
            break;
        }
        let next = page["next_offset"].as_u64().unwrap() as usize;
        assert!(next > offset);
        offset = next;
    }
    assert_eq!(rows.len(), expected);
    let ordered: Vec<_> = rows
        .iter()
        .map(|row| u64::from_str_radix(row["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();
    assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
    rows
}

#[tokio::test]
async fn exported_database_pages_full_matches_through_actual_mcp() {
    let owned = OwnedDirectory::new();
    let reference = owned.copy(&fixture("eval-ref-x86_64.elf"), "reference.elf");
    let database = owned.0.join("database.json");
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    let identify = tools.iter().find(|tool| tool.name == "identify_functions").unwrap();
    assert!(identify.input_schema["properties"].get("offset").is_some());
    assert!(identify.input_schema["properties"].get("limit").is_some());
    let built = body(&call(&client, "build_signatures", json!({"path": reference, "output": database})).await);
    assert!(built["signatures"].as_u64().unwrap() > 0);
    let args = json!({"path": reference, "database": database, "no_bundled": true});
    let first = body(&call(&client, "identify_functions", args.clone()).await);
    let total = first["matched"].as_u64().unwrap() as usize;
    assert!(total > 1);
    assert!(first["returned"].as_u64().unwrap() <= 100);
    let rows = collect_pages(&client, args.clone(), total, 3).await;
    assert!(rows.iter().all(|row| row["source"] == "user database"));
    let mut beyond = args;
    beyond["offset"] = json!(usize::MAX);
    let empty = body(&call(&client, "identify_functions", beyond).await);
    assert_eq!(empty["matched"], json!(total));
    assert_eq!(empty["returned"], 0);
    assert_eq!(empty["matches"], json!([]));
    assert_eq!(empty["warnings"], json!([]));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn apply_uses_all_matches_and_invalid_limits_write_nothing() {
    let owned = OwnedDirectory::new();
    let reference = owned.copy(&fixture("eval-ref-x86_64.elf"), "reference.elf");
    let database = owned.0.join("database.json");
    let client = connect().await;
    body(&call(&client, "build_signatures", json!({"path": reference, "output": database})).await);
    for (name, user_database) in [("eval-twin-x86_64.elf", true), ("musl-static-x86_64.elf", false)] {
        let path = owned.copy(&fixture(name), name);
        let mut args = json!({"path": path, "limit": 1});
        if user_database {
            args["database"] = json!(database);
            args["no_bundled"] = json!(true);
        }
        let before = body(&call(&client, "list_annotations", json!({"path": path})).await);
        for limit in [0, 257] {
            let mut invalid = args.clone();
            invalid["limit"] = json!(limit);
            invalid["apply"] = json!(true);
            assert_eq!(call(&client, "identify_functions", invalid).await.is_error, Some(true));
            assert_eq!(body(&call(&client, "list_annotations", json!({"path": path})).await), before);
        }
        let preview = body(&call(&client, "identify_functions", args.clone()).await);
        let total = preview["matched"].as_u64().unwrap() as usize;
        let rows = collect_pages(&client, args.clone(), total, 256).await;
        assert!(rows.iter().filter(|row| row["unnamed"] == true).count() > 1, "{name}");
        let preserved = rows.iter().find(|row| row["unnamed"] == true).unwrap();
        body(
            &call(
                &client,
                "rename",
                json!({"path": path, "at": preserved["address"], "name": "analyst_preserved_function"}),
            )
            .await,
        );
        args["apply"] = json!(true);
        let applied = body(&call(&client, "identify_functions", args.clone()).await);
        assert_eq!(applied["matched"], json!(total));
        assert_eq!(applied["returned"], 1);
        assert!(applied["applied"].as_u64().unwrap() > 1, "apply was restricted to the visible page: {applied}");
        assert_eq!(applied["apply_scope"], "whole_result");
        assert_eq!(applied["apply_requested"], true);
        args["apply"] = json!(false);
        let after = collect_pages(&client, args, total, 256).await;
        assert!(after.iter().filter(|row| row["unnamed"] == false).count() > 1);
        let newly_named = rows
            .iter()
            .zip(&after)
            .filter(|(before, after)| before["unnamed"] == true && after["unnamed"] == false)
            .count();
        assert_eq!(applied["applied"], json!(newly_named - 1));
        let annotations = body(&call(&client, "list_annotations", json!({"path": path})).await);
        assert!(
            annotations["names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| { row["address"] == preserved["address"] && row["text"] == "analyst_preserved_function" })
        );
    }
    client.cancel().await.unwrap();
}

fn replace_name(value: &mut Value, old: &str, new: &str) -> usize {
    match value {
        Value::String(text) if text == old => {
            *text = new.to_owned();
            1
        }
        Value::Array(values) => values.iter_mut().map(|value| replace_name(value, old, new)).sum(),
        Value::Object(fields) => fields.values_mut().map(|value| replace_name(value, old, new)).sum(),
        _ => 0,
    }
}

#[tokio::test]
async fn oversized_complete_row_is_rejected_before_apply_writes() {
    let owned = OwnedDirectory::new();
    let reference = owned.copy(&fixture("eval-ref-x86_64.elf"), "reference.elf");
    let target = owned.copy(&fixture("eval-twin-x86_64.elf"), "target.elf");
    let database = owned.0.join("database.json");
    let client = connect().await;
    body(&call(&client, "build_signatures", json!({"path": reference, "output": database})).await);
    let args = json!({"path": target, "database": database, "no_bundled": true});
    let first = body(&call(&client, "identify_functions", args.clone()).await);
    let total = first["matched"].as_u64().unwrap() as usize;
    let rows = collect_pages(&client, args.clone(), total, 256).await;
    assert!(rows.iter().filter(|row| row["unnamed"] == true).count() > 1);
    let row = &rows[0];
    let mut db: Value = serde_json::from_str(&std::fs::read_to_string(&database).unwrap()).unwrap();
    assert!(replace_name(&mut db, row["name"].as_str().unwrap(), &"x".repeat(60_000)) > 0);
    std::fs::write(&database, db.to_string()).unwrap();
    let before = body(&call(&client, "list_annotations", json!({"path": target})).await);
    let mut oversized = args;
    oversized["offset"] = json!(0);
    oversized["limit"] = json!(1);
    oversized["apply"] = json!(true);
    let refused = call(&client, "identify_functions", oversized).await;
    assert_eq!(refused.is_error, Some(true));
    let text = &refused.content.first().unwrap().as_text().unwrap().text;
    assert!(text.contains("first complete row") && text.contains("no names written"), "{text}");
    assert_eq!(body(&call(&client, "list_annotations", json!({"path": target})).await), before);
    client.cancel().await.unwrap();
}

#[test]
fn failing_full_plan_preflight_does_not_rename_any_function() {
    let owned = OwnedDirectory::new();
    let path = owned.copy(&fixture("musl-static-x86_64.elf"), "target.elf");
    std::fs::write(
        owned.0.join("rampage-pack.toml"),
        "name = \"broken-signatures\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\n\
         source = \"https://example.com/local-fixture\"\ndescription = \"Missing local database\"\n\
         [[contents]]\nkind = \"signatures\"\npath = \"missing.json\"\narch = \"x86_64\"\n",
    )
    .unwrap();
    let packs = rampage_api::Packs::load(std::slice::from_ref(&owned.0));
    let project = Session::default().with_packs(std::sync::Arc::new(packs)).open(&path, None).unwrap();
    let preview = project.identify_functions(None, true, false).unwrap();
    assert!(preview.matches.iter().filter(|row| row.unnamed).count() > 1);
    assert!(!preview.warnings.is_empty());
    let before: Vec<_> = preview.matches.iter().map(|row| project.function_name(row.address)).collect();
    let mut callbacks = 0;
    let result = project.identify_functions_with_preflight(None, true, true, |planned| {
        callbacks += 1;
        assert_eq!(planned.matched, preview.matched);
        assert_eq!(planned.applied, 0);
        assert_eq!(planned.warnings, preview.warnings);
        Err(rampage_api::ApiError::Invalid("receipt rejected".to_owned()))
    });
    assert!(result.is_err());
    assert_eq!(callbacks, 1);
    let after: Vec<_> = preview.matches.iter().map(|row| project.function_name(row.address)).collect();
    assert_eq!(after, before);
    assert!(!PathBuf::from(format!("{}.rampage", path.display())).exists());
}

#[tokio::test]
#[ignore = "set RAMPAGE_SIGNATURE_LARGE_FIXTURE and RAMPAGE_SIGNATURE_LARGE_DB to generated corpus artifacts"]
async fn large_generated_corpus_returns_complete_pages() {
    let owned = OwnedDirectory::new();
    let source = PathBuf::from(std::env::var_os("RAMPAGE_SIGNATURE_LARGE_FIXTURE").expect("large fixture path"));
    let source_db = PathBuf::from(std::env::var_os("RAMPAGE_SIGNATURE_LARGE_DB").expect("large database path"));
    let path = owned.copy(&source, "target.elf");
    let database = owned.copy(&source_db, "database.json");
    let client = connect().await;
    let args = json!({"path": path, "database": database, "no_bundled": true});
    let first = body(&call(&client, "identify_functions", args.clone()).await);
    let total = first["matched"].as_u64().unwrap() as usize;
    assert!(total > 256, "expected a scale fixture, got {total}");
    assert_eq!(first["limit"], 100);
    assert_eq!(first["more"], true);
    collect_pages(&client, args, total, 256).await;
    client.cancel().await.unwrap();
}
