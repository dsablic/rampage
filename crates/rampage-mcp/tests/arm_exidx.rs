use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_arch::Arch;
use rampage_loaders::{Binary, SymbolKind};
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

const UNREFERENCED: &str = "arm_exidx_unreferenced";
const OWNED_NAMES: [&str; 3] = [UNREFERENCED, "arm_exidx_reachable", "main"];
const FIXTURE_INSTRUCTIONS: &str = "build tests/fixtures/arm-exidx/build.sh OUTPUT_DIRECTORY with Zig 0.17.0, \
    set RAMPAGE_ARM_EXIDX_FIXTURES=OUTPUT_DIRECTORY, then run the ignored arm_exidx MCP test";

struct Fixtures(PathBuf);

impl Fixtures {
    fn copy() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let source = std::env::var_os("RAMPAGE_ARM_EXIDX_FIXTURES")
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{FIXTURE_INSTRUCTIONS}"));
        let directory = std::env::temp_dir().join(format!(
            "rampage-mcp-arm-exidx-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        let files = Self(directory);
        for profile in ["distinct", "coalesced"] {
            for suffix in ["elf", "stripped.elf"] {
                let name = format!("arm-exidx-{profile}.{suffix}");
                std::fs::copy(source.join(&name), files.0.join(&name))
                    .unwrap_or_else(|error| panic!("missing or unreadable {name}: {error}; {FIXTURE_INSTRUCTIONS}"));
            }
        }
        files
    }

    fn symbolized(&self, profile: &str) -> PathBuf {
        self.0.join(format!("arm-exidx-{profile}.elf"))
    }

    fn stripped(&self, profile: &str) -> PathBuf {
        self.0.join(format!("arm-exidx-{profile}.stripped.elf"))
    }

    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path.file_name().unwrap().into(), bytes)
            })
            .collect()
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
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
    assert_eq!(result.content.len(), 1, "{result:?}");
    let text = &result.content[0].as_text().unwrap().text;
    assert!(text.len() <= 60_000, "{} bytes", text.len());
    text
}

fn body(result: &CallToolResult) -> Value {
    let text = text(result);
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(text).expect("MCP must return complete JSON rather than a truncated preview")
}

async fn empty_annotations(client: &RunningService<RoleClient, TestClient>, path: &Path) -> Value {
    let annotations = body(&call(client, "list_annotations", json!({ "path": path })).await);
    for (field, rows) in annotations.as_object().unwrap() {
        assert!(rows.as_array().unwrap().is_empty(), "unexpected {field}: {annotations}");
    }
    annotations
}

async fn candidate(
    client: &RunningService<RoleClient, TestClient>,
    path: &Path,
    address: &str,
    retained_start: bool,
) -> Value {
    body(&call(client, "enable_tools", json!({ "groups": ["diagnostics"] })).await);
    assert!(client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "entry_diagnostics"));
    let report = body(&call(client, "entry_diagnostics", json!({ "path": path, "at": address, "limit": 1 })).await);
    assert_eq!(report["entries_total"], 1);
    assert_eq!(report["entries"].as_array().unwrap().len(), 1);
    assert_eq!(report["more"], false);
    assert!(report["next_offset"].is_null());
    assert_eq!(report["byte_capped"], false);
    assert_eq!(report["transport"]["names_omitted_total"], 0);
    assert!(report["transport"]["json_byte_budget"].as_u64().unwrap() <= 60_000);
    assert!(report["warnings"].is_array());
    assert!(report["truncation"].as_array().unwrap().is_empty(), "{report}");
    let limitations = report["limitations"].as_array().unwrap();
    assert!(limitations.iter().any(|line| line.as_str().unwrap().contains("not verified functions")));
    assert!(limitations.iter().any(|line| line.as_str().unwrap().contains("not proof")));
    let entry = &report["entries"][0];
    assert_eq!(entry["address"], address);
    // Coalesced unwind ranges do not assert that every interior source function has its own start record.
    let origin = if retained_start { "function_starts" } else { "caller_address" };
    assert_eq!(
        entry["origins"],
        json!([{ "kind": origin, "name": null, "name_omitted": false, "symbol_kind": null }]),
        "exact-address producer provenance must not be inferred from an enclosing unwind range: {report}",
    );
    assert_eq!(entry["metadata_records_at_address"].as_u64().unwrap() > 0, retained_start);
    assert_eq!(entry["origins_truncated"], false);
    assert_eq!(entry["status"], "backed_executable_code");
    assert!(entry["unavailable_reason"].is_null());
    assert!(entry["decoded_bytes"].as_u64().unwrap() > 0, "{report}");
    assert!(entry["instruction_count"].as_u64().unwrap() > 0, "{report}");
    report
}

async fn discovered_function(client: &RunningService<RoleClient, TestClient>, path: &Path, address: &str) -> Value {
    let mut offset = 0;
    let mut found = None;
    loop {
        let page = body(&call(client, "list_functions", json!({ "path": path, "offset": offset, "limit": 100 })).await);
        let rows = page["items"].as_array().unwrap();
        let total = page["total"].as_u64().unwrap() as usize;
        assert_eq!(page["offset"], offset);
        for row in rows {
            assert!(!OWNED_NAMES.contains(&row["name"].as_str().unwrap()), "stripped symbol name leaked: {row}");
            if row["address"] == address {
                assert!(found.replace(row.clone()).is_none(), "duplicate function at {address}");
            }
        }
        offset += rows.len();
        if offset == total {
            break;
        }
        assert!(!rows.is_empty() && offset < total, "function paging made no progress: {page}");
    }
    let row = found.unwrap_or_else(|| panic!("unreferenced producer candidate {address} was not discovered"));
    let numeric = u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap();
    assert_eq!(row["name"], format!("sub_{numeric:x}"));
    for field in ["size", "blocks", "instructions"] {
        assert!(row[field].as_u64().unwrap() > 0, "empty discovered {field}: {row}");
    }
    row
}

async fn structural_summary(client: &RunningService<RoleClient, TestClient>, path: &Path, address: &str) -> Value {
    let summary = body(&call(client, "function_summary", json!({ "path": path, "at": address })).await);
    assert_eq!(summary["graph"]["address"], address);
    assert!(summary["graph"]["name"].as_str().unwrap().starts_with("sub_"));
    let blocks = summary["graph"]["blocks"].as_array().unwrap();
    let entry = blocks.iter().find(|block| block["start"] == address).expect("decoded entry block");
    let lines = entry["lines"].as_array().unwrap();
    assert!(!lines.is_empty(), "{summary}");
    assert_eq!(lines[0]["address"], address);
    assert!(!lines[0]["bytes"].as_str().unwrap().is_empty());
    assert!(!lines[0]["text"].as_str().unwrap().is_empty());
    assert_ne!(lines[0]["flow"]["kind"], "invalid");
    assert!(
        summary["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| { line.as_str().unwrap().contains("Unknown indirect transfers") })
    );
    assert!(
        summary["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| { line.as_str().unwrap().contains("not decompiled source") })
    );
    assert!(summary.get("code").is_none());
    assert!(summary.get("ssa").is_none(), "ARM32 must not use the AArch64 summary path");
    summary
}

async fn exact_entry_unsupported(client: &RunningService<RoleClient, TestClient>, path: &Path, address: &str) {
    let result = call(client, "decompile", json!({ "path": path, "at": address, "exact_entry": true })).await;
    assert_eq!(result.is_error, Some(true), "{result:?}");
    assert!(
        text(&result).contains("exact-entry decompilation supports little-endian x86, x86-64 and AArch64 only"),
        "ARM32 must be refused without a whole-program, inline or other-architecture fallback: {result:?}",
    );
}

fn unreferenced_address(files: &Fixtures, profile: &str) -> String {
    let truth = Binary::open(files.symbolized(profile)).unwrap();
    assert_eq!(truth.arch, Arch::Arm);
    let function = truth
        .symbols
        .iter()
        .find(|symbol| symbol.kind == SymbolKind::Function && symbol.name == UNREFERENCED)
        .expect("owned symbolized fixture must retain the unreferenced function as test truth");
    format!("{:#x}", function.address & !1)
}

#[tokio::test]
#[ignore = "build tests/fixtures/arm-exidx/build.sh OUT with Zig 0.17.0; set RAMPAGE_ARM_EXIDX_FIXTURES=OUT"]
async fn stripped_arm_exidx_candidate_survives_real_mcp_discovery_and_fresh_server_without_edits() {
    let files = Fixtures::copy();
    let before = files.snapshot();
    let address = unreferenced_address(&files, "distinct");
    let path = files.stripped("distinct");

    let client = connect().await;
    let annotations = empty_annotations(&client, &path).await;
    let info = body(&call(&client, "binary_info", json!({ "path": path })).await);
    assert_eq!(info["arch"], "arm");
    assert_eq!(info["symbols"], 0, "stripped fixture must not provide symbol-table discovery seeds");
    assert!(info["function_starts"].as_u64().unwrap() > 0);
    assert!(info["warnings"].is_array());
    let metadata = candidate(&client, &path, &address, true).await;
    exact_entry_unsupported(&client, &path, &address).await;
    let function = discovered_function(&client, &path, &address).await;
    let summary = structural_summary(&client, &path, &address).await;
    assert_eq!(empty_annotations(&client, &path).await, annotations);
    assert_eq!(files.snapshot(), before, "read tools changed ELF bytes or created annotation logs/locks");
    client.cancel().await.unwrap();

    let fresh = connect().await;
    assert_eq!(empty_annotations(&fresh, &path).await, annotations);
    assert_eq!(candidate(&fresh, &path, &address, true).await, metadata);
    assert_eq!(discovered_function(&fresh, &path, &address).await, function);
    assert_eq!(structural_summary(&fresh, &path, &address).await, summary);
    exact_entry_unsupported(&fresh, &path, &address).await;
    assert_eq!(empty_annotations(&fresh, &path).await, annotations);
    fresh.cancel().await.unwrap();
    assert_eq!(files.snapshot(), before, "fresh-server reads changed source files or annotation logs/locks");
}

#[tokio::test]
#[ignore = "build tests/fixtures/arm-exidx/build.sh OUT with Zig 0.17.0; set RAMPAGE_ARM_EXIDX_FIXTURES=OUT"]
async fn coalesced_arm_exidx_range_does_not_fabricate_an_interior_function_start() {
    let files = Fixtures::copy();
    let before = files.snapshot();
    let address = unreferenced_address(&files, "coalesced");
    let path = files.stripped("coalesced");
    let client = connect().await;
    let annotations = empty_annotations(&client, &path).await;
    let info = body(&call(&client, "binary_info", json!({ "path": path })).await);
    assert_eq!(info["arch"], "arm");
    assert_eq!(info["symbols"], 0);
    assert!(info["function_starts"].as_u64().unwrap() > 0, "negative fixture must retain enclosing records");
    let metadata = candidate(&client, &path, &address, false).await;
    exact_entry_unsupported(&client, &path, &address).await;
    assert_eq!(empty_annotations(&client, &path).await, annotations);
    assert_eq!(files.snapshot(), before, "negative-control reads changed source files or annotation logs/locks");
    client.cancel().await.unwrap();

    let fresh = connect().await;
    assert_eq!(candidate(&fresh, &path, &address, false).await, metadata);
    exact_entry_unsupported(&fresh, &path, &address).await;
    assert_eq!(empty_annotations(&fresh, &path).await, annotations);
    fresh.cancel().await.unwrap();
    assert_eq!(files.snapshot(), before, "fresh negative-control reads changed files or annotation logs/locks");
}
