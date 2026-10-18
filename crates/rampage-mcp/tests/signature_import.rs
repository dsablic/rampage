//! Owned hand-authored code exercised through the production MCP duplex transport, never executed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_TIMEOUT: Duration = Duration::from_secs(60);
const FUZZY_SOURCE: &str = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C00783FF03740383C00535785634125DC3";

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

type Client = RunningService<RoleClient, TestClient>;

struct ServerTask(JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Connection {
    client: Option<Client>,
    server: ServerTask,
}

impl Connection {
    async fn connect() -> Self {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = ServerTask(tokio::spawn(async move {
            RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
        }));
        let client = timeout(CALL_TIMEOUT, TestClient.serve(client_transport)).await.unwrap().unwrap();
        let connection = Self { client: Some(client), server };
        body(&connection.call("enable_tools", json!({"groups":["detection"]})).await);
        connection
    }

    async fn call(&self, name: &str, arguments: Value) -> CallToolResult {
        timeout(
            CALL_TIMEOUT,
            self.client.as_ref().unwrap().call_tool(
                CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()),
            ),
        )
        .await
        .expect("MCP tool request timed out")
        .unwrap()
    }

    async fn annotations(&self, path: &Path) -> Value {
        body(&self.call("list_annotations", json!({"path":path})).await)
    }

    async fn shutdown(mut self) {
        timeout(CALL_TIMEOUT, self.client.take().unwrap().cancel()).await.unwrap().unwrap();
        timeout(CALL_TIMEOUT, &mut self.server.0).await.unwrap().unwrap();
    }
}

fn text(result: &CallToolResult) -> &str {
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert!(text.len() <= 60_000, "{} response bytes", text.len());
    text
}

fn body(result: &CallToolResult) -> Value {
    let text = text(result);
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(text).expect("complete MCP JSON response")
}

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-signature-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn snapshot(&self, name: &str, bodies: &[(u64, &str)]) -> PathBuf {
        self.write(
            name,
            json!({
                "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
                "provenance":"owned hand-authored MCP import transport fixture",
                "seeds":bodies.iter().map(|(address, _)| format!("{address:#x}")).collect::<Vec<_>>(),
                "regions":bodies.iter().map(|(address, bytes)| json!({
                    "name":"code", "address":format!("{address:#x}"), "permissions":"r-x", "bytes":bytes
                })).collect::<Vec<_>>()
            })
            .to_string(),
        )
    }

    fn assert_no_annotations(&self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.ends_with(".jsonl") && !name.ends_with(".rampage") && !name.ends_with(".lock"),
                "unexpected annotation file: {name}"
            );
        }
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

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn named_reference_elf() -> Vec<u8> {
    let code: Vec<u8> = FUZZY_SOURCE
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let strings = b"\0owned_reference\0";
    let section_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let mut bytes = vec![0; 0x1340];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x401000);
    put64(&mut bytes, 32, 64);
    put64(&mut bytes, 40, 0x1200);
    for (offset, value) in [(52, 64), (54, 56), (56, 1), (58, 64), (60, 5), (62, 4)] {
        put16(&mut bytes, offset, value);
    }
    put32(&mut bytes, 64, 1);
    put32(&mut bytes, 68, 5);
    for (offset, value) in
        [(72, 0x1000), (80, 0x401000), (88, 0x401000), (96, code.len() as u64), (104, code.len() as u64), (112, 0x1000)]
    {
        put64(&mut bytes, offset, value);
    }
    bytes[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    put32(&mut bytes, 0x1118, 1);
    bytes[0x111c] = 0x12;
    put16(&mut bytes, 0x111e, 1);
    put64(&mut bytes, 0x1120, 0x401000);
    put64(&mut bytes, 0x1128, code.len() as u64);
    bytes[0x1140..0x1140 + strings.len()].copy_from_slice(strings);
    bytes[0x1160..0x1160 + section_names.len()].copy_from_slice(section_names);
    for (index, name, kind, flags, address, offset, size, link, info, alignment, entry_size) in [
        (1, 1, 1, 6, 0x401000, 0x1000, code.len() as u64, 0, 0, 16, 0),
        (2, 7, 2, 0, 0, 0x1100, 48, 3, 1, 8, 24),
        (3, 15, 3, 0, 0, 0x1140, strings.len() as u64, 0, 0, 1, 0),
        (4, 23, 3, 0, 0, 0x1160, section_names.len() as u64, 0, 0, 1, 0),
    ] {
        let header = 0x1200 + index * 64;
        put32(&mut bytes, header, name);
        put32(&mut bytes, header + 4, kind);
        for (field, value) in [(8, flags), (16, address), (24, offset), (32, size), (48, alignment), (56, entry_size)] {
            put64(&mut bytes, header + field, value);
        }
        put32(&mut bytes, header + 40, link);
        put32(&mut bytes, header + 44, info);
    }
    bytes
}

#[tokio::test]
async fn user_pat_preview_matches_through_mcp_without_writes() {
    timeout(TEST_TIMEOUT, async {
        let owned = OwnedDirectory::new();
        let prefix = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C0075D90";
        let body_hex = format!("{prefix}83C0019090C3");
        let target = owned.snapshot("query.json", &[(0x1000, &body_hex)]);
        let pat = format!("{prefix} 06 2FCD 0026 :0000 owned_pat_function\n---\n");
        let database = owned.write("owned.pat", &pat);
        let connection = Connection::connect().await;
        let before = connection.annotations(&target).await;
        assert_eq!(before["names"], json!([]));
        let page = body(
            &connection
                .call(
                    "identify_functions",
                    json!({
                        "path":target,"database":database,"no_bundled":true,"limit":1
                    }),
                )
                .await,
        );
        assert_eq!(page["matched"], 1);
        assert_eq!(page["applied"], 0);
        assert_eq!(page["apply_requested"], false);
        assert_eq!(page["details_total"], 1);
        assert_eq!(page["matches"][0]["address"], "0x1000");
        assert_eq!(page["matches"][0]["name"], "owned_pat_function");
        assert_eq!(page["matches"][0]["source"], "user database");
        assert_eq!(page["matches"][0]["unnamed"], true);
        assert_eq!(connection.annotations(&target).await, before);
        assert_eq!(std::fs::read_to_string(database).unwrap(), pat);
        owned.assert_no_annotations();
        connection.shutdown().await;
    })
    .await
    .expect("PAT MCP transport test timed out");
}

#[tokio::test]
async fn fuzzy_mcp_build_pages_secondary_candidates_and_applies_only_exact_names() {
    timeout(TEST_TIMEOUT, async {
        let owned = OwnedDirectory::new();
        let reference = owned.write("reference.elf", named_reference_elf());
        let changed = FUZZY_SOURCE.replacen("B82A000000", "B82B000000", 1);
        let other = FUZZY_SOURCE.replacen("B82A000000", "B82C000000", 1);
        assert_ne!(changed, FUZZY_SOURCE);
        assert_ne!(other, FUZZY_SOURCE);
        let target = owned.snapshot("query.json", &[(0x1000, &changed), (0x2000, &other)]);
        let identical = owned.snapshot("identical.json", &[(0x1000, FUZZY_SOURCE)]);
        let build_request = owned.write(
            "build.json",
            json!({
                "owned_names":["owned_reference"],
                "provenance":{"library":"owned", "source":"hand-authored ELF body", "cohort":"source"}
            })
            .to_string(),
        );
        let request = owned.write(
            "query-request.json",
            json!({
                "cohort":"held-out-query", "addresses":[4096,8192], "candidates_per_function":2
            })
            .to_string(),
        );
        let database = owned.0.join("fuzzy.json");
        let connection = Connection::connect().await;
        let built = body(
            &connection
                .call(
                    "build_signatures",
                    json!({
                        "path":reference,"output":database,"fuzzy_request":build_request
                    }),
                )
                .await,
        );
        assert_eq!(built["fuzzy_references"], 1);
        assert_eq!(built["suggestions_only"], true);
        assert!(database.is_file());
        let before = connection.annotations(&target).await;
        assert_eq!(before["names"], json!([]));
        let mut offset = 0;
        let mut addresses = BTreeSet::new();
        for _ in 0..4 {
            let page = body(
                &connection
                    .call(
                        "identify_functions",
                        json!({
                            "path":target,"fuzzy_database":database,"fuzzy_request":request,
                            "apply":true,"offset":offset,"limit":1
                        }),
                    )
                    .await,
            );
            assert_eq!(page["matched"], 0);
            assert_eq!(page["applied"], 0);
            assert_eq!(page["matches"], json!([]));
            assert_eq!(page["matches_omitted"], 0);
            assert_eq!(page["totals_scope"], "whole_result");
            assert_eq!(page["details_total"], 2);
            assert_eq!(page["returned"], 1);
            assert_eq!(page["fuzzy"]["read_only"], true);
            assert_eq!(page["fuzzy"]["suggestions_total"], 2);
            assert_eq!(page["fuzzy"]["candidates_total"], 2);
            assert_eq!(page["fuzzy"]["suggestions_omitted"], 1);
            let rows = page["fuzzy"]["suggestions"].as_array().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["status"], "candidate_evidence");
            assert_eq!(rows[0]["report"]["candidates"][0]["name"], "owned_reference");
            assert!(addresses.insert(rows[0]["address"].as_str().unwrap().to_owned()));
            if page["more"] == false {
                assert_eq!(page["next_offset"], Value::Null);
                break;
            }
            let next = page["next_offset"].as_u64().unwrap();
            assert!(next > offset);
            offset = next;
        }
        assert_eq!(addresses, BTreeSet::from(["0x1000".to_owned(), "0x2000".to_owned()]));
        assert_eq!(connection.annotations(&target).await, before);
        owned.assert_no_annotations();

        let exact = owned.write(
            "exact.pat",
            format!(
                "{} 00 0000 {:04X} :0000 owned_exact_only {}\n---\n",
                &changed[..64],
                changed.len() / 2,
                &changed[64..]
            ),
        );
        let invalid_request = owned.write("invalid-query.json", "{}");
        let rejected = connection
            .call(
                "identify_functions",
                json!({
                    "path":target,"database":exact,"fuzzy_database":database,
                    "fuzzy_request":invalid_request,"apply":true
                }),
            )
            .await;
        assert_eq!(rejected.is_error, Some(true), "{}", text(&rejected));
        assert!(text(&rejected).contains("missing field"), "{}", text(&rejected));
        assert_eq!(connection.annotations(&target).await, before);

        let same_code_request = owned.write(
            "same-code-query.json",
            json!({
                "cohort":"different-textual-cohort", "addresses":[4096], "candidates_per_function":2
            })
            .to_string(),
        );
        let identical_before = connection.annotations(&identical).await;
        let rejected = connection
            .call(
                "identify_functions",
                json!({
                    "path":identical,"fuzzy_database":database,"fuzzy_request":same_code_request,"apply":true
                }),
            )
            .await;
        assert_eq!(rejected.is_error, Some(true));
        assert!(text(&rejected).contains("executable code duplicates"), "{}", text(&rejected));
        assert_eq!(connection.annotations(&identical).await, identical_before);
        owned.assert_no_annotations();

        let applied = body(
            &connection
                .call(
                    "identify_functions",
                    json!({
                        "path":target,"database":exact,"fuzzy_database":database,"fuzzy_request":request,
                        "apply":true,"limit":1
                    }),
                )
                .await,
        );
        assert_eq!(applied["matched"], 1);
        assert_eq!(applied["applied"], 1);
        assert_eq!(applied["details_total"], 3);
        assert_eq!(applied["returned"], 1);
        assert_eq!(applied["more"], true);
        assert_eq!(applied["matches"][0]["name"], "owned_exact_only");
        assert_eq!(applied["fuzzy"]["suggestions_total"], 2);
        assert_eq!(applied["fuzzy"]["candidates_total"], 1);
        let annotations = connection.annotations(&target).await;
        let names = annotations["names"].as_array().unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0]["address"], "0x1000");
        assert_eq!(names[0]["text"], "owned_exact_only");
        connection.shutdown().await;
    })
    .await
    .expect("fuzzy MCP transport test timed out");
}
