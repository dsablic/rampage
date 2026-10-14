use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{Session, tools::Group};
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
    assert_eq!(result.content.len(), 1);
    result.content[0].as_text().unwrap().text.as_str()
}

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

fn assert_error(result: &CallToolResult, message: &str) {
    assert_eq!(result.is_error, Some(true), "{}", text(result));
    assert!(text(result).contains(message), "expected {message:?}: {}", text(result));
}

const UUID: &str = "11111111111111111111111111111111";
const IMAGE_BASE: u64 = 0x100000000;
// Independent Python hashlib goldens from the CLI's committed controlled comparison specification.
// Raw 256-byte Mach-O; capture v1 BE u64 lengths/counts/addresses, aarch64, little-endian, no target context;
// read-only regions (0x1002, edfef3000001), (0x10fe, a5a50102), no Thumb/seeds/entry;
// module (UUID, IMAGE_BASE, 0x1000). Names, paths and provenance are excluded from identity.
const IMAGE_SHA256: &str = "8002eb6adf4b391fbb0e0561ad011f8b90b64ece0bc91f2a541d9f6e36647075";
const CAPTURE_SCHEMA: &str = "rampage-capture-identity-v1";
const CAPTURE_SHA256: &str = "bf2175b02e8fab15c29fa7920a9651613353d85b540d428f1cf1e44ac2445568";

fn controlled_macho(cpu: u32, uuid_byte: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xfeedfacf, cpu, 0, 2, 2, 96, 0, 0, 0x19, 72] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let segment_name: &[u8; 16] = b"__TEXT\0\0\0\0\0\0\0\0\0\0";
    bytes.extend_from_slice(segment_name);
    for word in [IMAGE_BASE, 0x200, 0, 0x100] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for word in [5u32, 5, 0, 0, 0x1b, 24] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(bytes.len(), 112);
    bytes.extend_from_slice(&[uuid_byte; 16]);
    assert_eq!(bytes.len(), 128);
    bytes.resize(0x100, 0xa5);
    bytes
}

fn controlled_universal(selected: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xcafebabfu32, 2] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    for (cpu, subtype, offset) in [(0x01000007u32, 3u32, 0x1000u64), (0x0100000c, 0, 0x2000)] {
        bytes.extend_from_slice(&cpu.to_be_bytes());
        bytes.extend_from_slice(&subtype.to_be_bytes());
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.extend_from_slice(&0x100u64.to_be_bytes());
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
    }
    bytes.resize(0x2000, 0);
    bytes[0x1000..0x1100].copy_from_slice(&controlled_macho(0x01000007, 0x22));
    bytes.extend_from_slice(selected);
    bytes
}

struct Fixture {
    root: PathBuf,
    original: PathBuf,
    capture: PathBuf,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-mcp-selected-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let bytes = controlled_macho(0x0100000c, 0x11);
        let original = root.join("original.macho");
        std::fs::write(&original, &bytes).unwrap();
        let snapshot = json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
            "provenance": "constructed MCP comparison fixture",
            "regions": [
                {"name": "selected", "address": "0x1002", "permissions": "r--", "bytes": "edfef3000001"},
                {"name": "file-end", "address": "0x10fe", "permissions": "r--", "bytes": "a5a50102"}
            ],
            "modules": [{"name": "fixture", "path": "/never/opened/original", "uuid": UUID,
                "image_base": "0x100000000", "runtime_base": "0x1000"}]
        });
        let capture = root.join("snapshot.json");
        std::fs::write(&capture, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        Self { root, original, capture, bytes }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn wrap(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let mut wrapper = vec![b'w'; 37];
        wrapper.extend_from_slice(bytes);
        wrapper.extend_from_slice(&[b'z'; 59]);
        self.write(name, &wrapper)
    }

    fn arguments(&self, original: &Path) -> Value {
        json!({"path": self.capture, "original": original, "module": UUID,
            "ranges": [{"address": "0x1000", "size": 10}, {"address": "0x10fe", "size": 4},
                {"address": "0x1200", "size": 2}]})
    }

    fn entries(&self) -> BTreeSet<PathBuf> {
        std::fs::read_dir(&self.root).unwrap().map(|entry| entry.unwrap().path()).collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn schema_types(root: &Value, schema: &Value) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    if let Some(reference) = schema["$ref"].as_str() {
        types.extend(schema_types(root, root.pointer(reference.strip_prefix('#').unwrap()).unwrap()));
    }
    if let Some(name) = schema["type"].as_str() {
        types.insert(name.to_owned());
    }
    if let Some(names) = schema["type"].as_array() {
        types.extend(names.iter().map(|name| name.as_str().unwrap().to_owned()));
    }
    if let Some(choices) = schema["anyOf"].as_array() {
        for choice in choices {
            types.extend(schema_types(root, choice));
        }
    }
    types
}

#[tokio::test]
async fn runtime_opt_in_exposes_canonical_tool_and_original_file_offset_schema() {
    let client = connect(RampageServer::default()).await;
    let initial = client.list_all_tools().await.unwrap();
    assert!(!initial.iter().any(|tool| tool.name == "compare_runtime_bytes"));
    let disabled = call(&client, "compare_runtime_bytes", json!({"path": "/does/not/exist"})).await;
    assert_error(&disabled, "`runtime` group");
    assert!(text(&disabled).contains("nothing was run"));
    let enabled = json_of(&call(&client, "enable_tools", json!({"groups": ["runtime"]})).await);
    assert_eq!(enabled["newly_enabled"], json!(["runtime"]));
    let tools = client.list_all_tools().await.unwrap();
    let comparison = tools.iter().find(|tool| tool.name == "compare_runtime_bytes").unwrap();
    let schema = Value::Object(comparison.input_schema.as_ref().clone());
    assert_eq!(schema["additionalProperties"], false);
    for name in ["original_image_offset", "original_image_length"] {
        assert_eq!(
            schema_types(&schema, &schema["properties"][name]),
            BTreeSet::from(["integer".to_owned(), "null".to_owned(), "string".to_owned()])
        );
        assert!(!schema["required"].as_array().unwrap().contains(&json!(name)));
    }
    for name in ["original", "module", "ranges", "path"] {
        assert!(schema["required"].as_array().unwrap().contains(&json!(name)), "{name}");
    }
    assert!(
        schema["properties"]["original_image_length"]["description"]
            .as_str()
            .unwrap()
            .contains("requires original_image_offset")
    );
    assert!(schema["properties"].get("image_offset").is_some());
    assert!(schema["properties"].get("image_length").is_some());
    let pointer = tools.iter().find(|tool| tool.name == "compare_pointer_observations").unwrap();
    assert!(!pointer.input_schema["properties"].as_object().unwrap().contains_key("original_image_offset"));
    assert!(!tools.iter().any(|tool| tool.name == "compare-runtime" || tool.name == "runtime_bytes_compare"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn selected_original_returns_independent_hash_identity_and_image_relative_addresses_without_sidecars() {
    let fixture = Fixture::new();
    let thin = fixture.wrap("thin.bin", &fixture.bytes);
    let fat = fixture.wrap("fat.bin", &controlled_universal(&fixture.bytes));
    let mut logs = vec![
        fixture.capture.with_extension("json.rampage"),
        fixture.original.with_extension("macho.rampage"),
        fixture.root.join(format!(".{CAPTURE_SCHEMA}-{CAPTURE_SHA256}.jsonl")),
    ];
    for (path, length, arch) in [(&thin, "0x100", ""), (&fat, "0x2100", ".aarch64")] {
        for suffix in [
            ".rampage".to_owned(),
            format!("@0x25{arch}.rampage-image"),
            format!("@0x25+{length}{arch}.rampage-image"),
            format!("@0x25{arch}.rampage"),
        ] {
            let mut log = path.as_os_str().to_owned();
            log.push(suffix);
            logs.push(PathBuf::from(log));
        }
    }
    for log in &logs {
        std::fs::create_dir(log).unwrap();
        std::fs::write(log.join("sentinel"), b"poisoned annotation directory\n").unwrap();
    }
    let entries = fixture.entries();
    // A Session-based snapshot open would fail on this directory; runtime tools must still open fresh Binary inputs.
    let server = RampageServer::with_groups([Group::Runtime])
        .with_session(Session::with_capture_annotations(fixture.root.join("missing-annotation-directory")));
    let client = connect(server).await;
    let expected = call(&client, "compare_runtime_bytes", fixture.arguments(&fixture.original)).await;
    let result = json_of(&expected);
    assert_eq!(result["original_image_sha256"], IMAGE_SHA256);
    assert_eq!(result["capture_identity"], json!({"schema": CAPTURE_SCHEMA, "sha256": CAPTURE_SHA256}));
    assert_eq!(result["module_uuid"], UUID);
    assert_eq!(result["arch"], "aarch64");
    assert_eq!(result["runtime_base"], "0x1000");
    assert_eq!(result["image_base"], "0x100000000");
    assert_eq!(result["requested_bytes"], 16);
    assert_eq!(result["equal_bytes"], 7);
    assert_eq!(result["changed_bytes"], 1);
    assert_eq!(result["unavailable_bytes"], 8);
    assert_eq!(result["spans_total"], 8);
    let spans: Vec<_> = result["spans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|span| {
            (
                span["runtime_address"].as_str().unwrap(),
                span["image_address"].as_str().unwrap(),
                span["size"].as_u64().unwrap(),
                span["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        spans,
        [
            ("0x1000", "0x100000000", 2, "capture_unavailable"),
            ("0x1002", "0x100000002", 2, "equal"),
            ("0x1004", "0x100000004", 1, "changed"),
            ("0x1005", "0x100000005", 3, "equal"),
            ("0x1008", "0x100000008", 2, "capture_unavailable"),
            ("0x10fe", "0x1000000fe", 2, "equal"),
            ("0x1100", "0x100000100", 2, "original_unavailable"),
            ("0x1200", "0x100000200", 2, "both_unavailable")
        ]
    );
    for (path, length) in [(&thin, 0x100), (&fat, 0x2100)] {
        for offset in [json!(37), json!("37"), json!("0x25")] {
            for length in [
                None,
                Some(Value::Null),
                Some(json!(length)),
                Some(json!(length.to_string())),
                Some(json!(format!("{length:#x}"))),
            ] {
                for arch in [None, Some("aarch64")] {
                    let mut input = fixture.arguments(path);
                    input["original_image_offset"] = offset.clone();
                    if let Some(length) = &length {
                        input["original_image_length"] = length.clone();
                    }
                    if let Some(arch) = arch {
                        input["arch"] = json!(arch);
                    }
                    let actual = call(&client, "compare_runtime_bytes", input).await;
                    assert_eq!(json_of(&actual), result);
                    assert_eq!(text(&actual), text(&expected));
                }
            }
        }
    }
    assert_eq!(fixture.entries(), entries);
    for log in logs {
        assert!(log.is_dir());
        assert_eq!(std::fs::read(log.join("sentinel")).unwrap(), b"poisoned annotation directory\n");
        assert_eq!(std::fs::read_dir(log).unwrap().count(), 1);
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn original_selector_nulls_are_absence_bad_json_is_rejected_and_lone_length_precedes_original_io() {
    let fixture = Fixture::new();
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let expected = json_of(&call(&client, "compare_runtime_bytes", fixture.arguments(&fixture.original)).await);
    for selectors in [
        json!({"original_image_offset": null}),
        json!({"original_image_length": null}),
        json!({"original_image_offset": null, "original_image_length": null}),
        json!({"original_image_offset": 0}),
        json!({"original_image_offset": "0x0"}),
        json!({"original_image_offset": "0", "original_image_length": "256"}),
        json!({"original_image_offset": 0, "original_image_length": "0x100"}),
    ] {
        let mut input = fixture.arguments(&fixture.original);
        input.as_object_mut().unwrap().extend(selectors.as_object().unwrap().clone());
        assert_eq!(json_of(&call(&client, "compare_runtime_bytes", input).await), expected);
    }
    let missing = fixture.root.join("missing-explicit-original");
    for value in [
        json!(true),
        json!([]),
        json!({}),
        json!(-1),
        json!(1.5),
        json!(""),
        json!("0xzz"),
        json!("18446744073709551616"),
        json!("0x10000000000000000"),
    ] {
        for field in ["original_image_offset", "original_image_length"] {
            let mut input = fixture.arguments(&missing);
            input[field] = value.clone();
            let result = call(&client, "compare_runtime_bytes", input).await;
            assert_error(&result, "file offset or byte count");
            assert!(!text(&result).contains("missing-explicit-original"), "{}", text(&result));
        }
    }
    for offset in [None, Some(Value::Null)] {
        for length in [json!(0), json!("256"), json!("0x100")] {
            let mut input = fixture.arguments(&missing);
            if let Some(offset) = &offset {
                input["original_image_offset"] = offset.clone();
            }
            input["original_image_length"] = length;
            let result = call(&client, "compare_runtime_bytes", input).await;
            assert_error(&result, "original_image_length needs original_image_offset");
            assert!(!text(&result).contains("missing-explicit-original"), "{}", text(&result));
        }
    }
    let mut absent = fixture.arguments(&fixture.original);
    absent.as_object_mut().unwrap().remove("original");
    assert_error(&call(&client, "compare_runtime_bytes", absent).await, "missing field `original`");
    let mut explicit_missing = fixture.arguments(&missing);
    explicit_missing["original_image_offset"] = json!(37);
    let result = call(&client, "compare_runtime_bytes", explicit_missing).await;
    assert_error(&result, "missing-explicit-original");
    assert!(!text(&result).contains("/never/opened/original"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn original_selector_typos_and_unknown_sources_fail_before_original_io_without_comparison_output() {
    let fixture = Fixture::new();
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let missing = fixture.root.join("missing-explicit-original");
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    for path in [&wrapper, &missing] {
        for field in ["original_image_lenght", "original_source"] {
            let mut input = fixture.arguments(path);
            input["original_image_offset"] = json!(37);
            input[field] = json!(20);
            let result = call(&client, "compare_runtime_bytes", input).await;
            assert_error(&result, &format!("unknown field `{field}`"));
            assert!(!text(&result).contains("missing-explicit-original"), "{}", text(&result));
            assert!(!text(&result).contains("original_image_sha256"), "{}", text(&result));
            assert!(result.structured_content.is_none());
        }
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn selected_original_rejects_bounds_truncation_identity_and_malformed_universal_headers() {
    let fixture = Fixture::new();
    let wrapper = fixture.wrap("wrapper.bin", &fixture.bytes);
    let mut truncated = vec![b'w'; 37];
    truncated.extend_from_slice(&fixture.bytes[..20]);
    let truncated = fixture.write("truncated.bin", &truncated);
    let wrong_uuid = fixture.wrap("wrong-uuid.bin", &controlled_macho(0x0100000c, 0x22));
    let wrong_arch = fixture.wrap("wrong-arch.bin", &controlled_macho(0x01000007, 0x11));
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let cases = [
        (&truncated, json!({"original_image_offset": 37}), "truncated"),
        (&wrapper, json!({"original_image_offset": 0}), "Unknown file magic"),
        (&wrapper, json!({"original_image_offset": "0xffffffffffffffff"}), "past the end"),
        (&wrapper, json!({"original_image_offset": 37, "original_image_length": 0}), "does not fit"),
        (&wrapper, json!({"original_image_offset": 37, "original_image_length": "0x1000"}), "does not fit"),
        (&wrapper, json!({"original_image_offset": 37, "original_image_length": 20}), "cannot parse"),
        (
            &wrapper,
            json!({"original_image_offset": 37,
            "original_image_length": "0xffffffffffffffff"}),
            "overflows",
        ),
        (&wrong_uuid, json!({"original_image_offset": 37}), "UUID does not match"),
        (&wrong_arch, json!({"original_image_offset": 37}), "contains x86_64"),
    ];
    for (path, selectors, message) in cases {
        let mut input = fixture.arguments(path);
        input.as_object_mut().unwrap().extend(selectors.as_object().unwrap().clone());
        assert_error(&call(&client, "compare_runtime_bytes", input).await, message);
    }
    let valid = controlled_universal(&fixture.bytes);
    let mut malformed = valid.clone();
    malformed[64..68].copy_from_slice(&21u32.to_be_bytes());
    let mut duplicate = valid.clone();
    duplicate[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
    let mut overflow = valid;
    overflow[48..56].copy_from_slice(&(u64::MAX - 0xf).to_be_bytes());
    overflow[64..68].copy_from_slice(&4u32.to_be_bytes());
    for (name, bytes, message) in [
        ("malformed.bin", malformed, "invalid file range or alignment"),
        ("duplicate.bin", duplicate, "multiple aarch64 slices"),
        ("overflow.bin", overflow, "invalid file range or alignment"),
    ] {
        let path = fixture.wrap(name, &bytes);
        for length in [None, Some(json!("0x2100"))] {
            let mut input = fixture.arguments(&path);
            input["original_image_offset"] = json!(37);
            if let Some(length) = length {
                input["original_image_length"] = length;
            }
            assert_error(&call(&client, "compare_runtime_bytes", input).await, message);
        }
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn primary_image_selectors_apply_only_to_capture_and_embedded_json_is_not_a_new_source() {
    let fixture = Fixture::new();
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let mut input = fixture.arguments(&wrapper);
    input["image_offset"] = json!(0);
    assert_error(&call(&client, "compare_runtime_bytes", input.clone()).await, "Unknown file magic");
    input["original_image_offset"] = json!(37);
    let selected = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(selected["original_image_sha256"], IMAGE_SHA256);
    input["image_offset"] = json!(37);
    assert_error(&call(&client, "compare_runtime_bytes", input).await, "no ELF, PE or Mach-O header");
    let embedded_capture = fixture.wrap("capture.bin", &std::fs::read(&fixture.capture).unwrap());
    let mut input = fixture.arguments(&fixture.original);
    input["path"] = json!(embedded_capture);
    input["image_offset"] = json!(37);
    assert_error(&call(&client, "compare_runtime_bytes", input).await, "no ELF, PE or Mach-O header");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn runtime_pages_keep_whole_range_totals_identity_and_valid_json_under_the_span_cap() {
    let fixture = Fixture::new();
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let mut capture: Value = serde_json::from_slice(&std::fs::read(&fixture.capture).unwrap()).unwrap();
    let mut captured = fixture.bytes.clone();
    captured.resize(400, 0xa5);
    for (index, byte) in captured.iter_mut().enumerate() {
        if index % 2 != 0 {
            *byte ^= 0xff;
        }
    }
    capture["regions"] = json!([{"name": "alternating", "address": "0x1000", "permissions": "r--",
        "bytes": rampage_arch::hex::bytes(&captured)}]);
    std::fs::write(&fixture.capture, serde_json::to_vec(&capture).unwrap()).unwrap();
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let mut input = fixture.arguments(&wrapper);
    input["original_image_offset"] = json!(37);
    input["ranges"] = json!([{"address": "0x1000", "size": 400}]);
    input["limit"] = json!(1000);
    let first_result = call(&client, "compare_runtime_bytes", input.clone()).await;
    assert!(text(&first_result).len() <= 60_000);
    let first = json_of(&first_result);
    assert_eq!(first["spans_total"], 257);
    assert_eq!(first["spans"].as_array().unwrap().len(), 200);
    assert_eq!(first["requested_bytes"], 400);
    assert_eq!(first["equal_bytes"], 128);
    assert_eq!(first["changed_bytes"], 128);
    assert_eq!(first["unavailable_bytes"], 144);
    assert_eq!(first["original_image_sha256"], IMAGE_SHA256);
    input["offset"] = json!(200);
    let second = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(second["spans"].as_array().unwrap().len(), 57);
    assert_eq!(second["spans"][0]["runtime_address"], "0x10c8");
    assert_eq!(second["spans"][0]["image_address"], "0x1000000c8");
    assert_eq!(second["spans"][56]["status"], "original_unavailable");
    assert_eq!(second["spans"][56]["size"], 144);
    for field in [
        "requested_bytes",
        "equal_bytes",
        "changed_bytes",
        "unavailable_bytes",
        "capture_identity",
        "original_image_sha256",
        "spans_total",
    ] {
        assert_eq!(second[field], first[field], "{field}");
    }
    input["offset"] = json!(1000);
    let beyond = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(beyond["offset"], 257);
    assert_eq!(beyond["spans"], json!([]));
    assert_eq!(beyond["requested_bytes"], 400);
    input["offset"] = json!(0);
    input["limit"] = json!(0);
    let zero = json_of(&call(&client, "compare_runtime_bytes", input).await);
    assert_eq!(zero["spans"], json!([]));
    assert_eq!(zero["spans_total"], 257);
    assert_eq!(zero["capture_identity"], first["capture_identity"]);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn comparisons_reopen_changed_capture_inputs_and_never_resolve_annotation_aliases() {
    let fixture = Fixture::new();
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let mut input = fixture.arguments(&wrapper);
    input["original_image_offset"] = json!(37);
    let first = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(first["capture_identity"]["sha256"], CAPTURE_SHA256);
    let mut snapshot: Value = serde_json::from_slice(&std::fs::read(&fixture.capture).unwrap()).unwrap();
    snapshot["regions"][0]["bytes"] = json!("ecfef3000001");
    let replacement = fixture.write("replacement.json", &serde_json::to_vec(&snapshot).unwrap());
    std::fs::rename(replacement, &fixture.capture).unwrap();
    let second = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_ne!(second["capture_identity"], first["capture_identity"]);
    assert_eq!(second["original_image_sha256"], IMAGE_SHA256);
    assert_eq!(second["equal_bytes"], 6);
    assert_eq!(second["changed_bytes"], 2);
    input["ranges"][0]["address"] = json!("sub_1000");
    assert_error(&call(&client, "compare_runtime_bytes", input).await, "hexadecimal address");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn same_path_capture_architecture_change_reselects_original_and_refuses_wrong_architectures() {
    let fixture = Fixture::new();
    let thin = fixture.wrap("arm-original.bin", &fixture.bytes);
    let fat = fixture.wrap("fat-original.bin", &controlled_universal(&fixture.bytes));
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let mut input = fixture.arguments(&fat);
    input["original_image_offset"] = json!(37);
    let before = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(before["arch"], "aarch64");
    assert_eq!(before["original_image_sha256"], IMAGE_SHA256);
    assert_eq!(before["capture_identity"]["sha256"], CAPTURE_SHA256);

    let x86_uuid = "22222222222222222222222222222222";
    let mut capture: Value = serde_json::from_slice(&std::fs::read(&fixture.capture).unwrap()).unwrap();
    capture["arch"] = json!("x86_64");
    capture["modules"][0]["uuid"] = json!(x86_uuid);
    capture["regions"][0]["bytes"] = json!("edfef8000001");
    let replacement = fixture.write("x86-replacement.json", &serde_json::to_vec(&capture).unwrap());
    std::fs::rename(replacement, &fixture.capture).unwrap();
    input["module"] = json!(x86_uuid);

    let mut wrong_original = input.clone();
    wrong_original["original"] = json!(thin);
    assert_error(
        &call(&client, "compare_runtime_bytes", wrong_original).await,
        "x86_64 slice; the file contains aarch64",
    );
    let after = json_of(&call(&client, "compare_runtime_bytes", input.clone()).await);
    assert_eq!(after["arch"], "x86_64");
    assert_eq!(after["module_uuid"], x86_uuid);
    assert_ne!(after["original_image_sha256"], IMAGE_SHA256);
    assert_ne!(after["capture_identity"], before["capture_identity"]);
    for field in [
        "runtime_base",
        "image_base",
        "requested_bytes",
        "equal_bytes",
        "changed_bytes",
        "unavailable_bytes",
        "spans",
        "spans_total",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    input["arch"] = json!("aarch64");
    assert_error(&call(&client, "compare_runtime_bytes", input.clone()).await, "snapshot architecture is x86_64");
    input["arch"] = json!("x86_64");
    assert_eq!(json_of(&call(&client, "compare_runtime_bytes", input).await), after);
    client.cancel().await.unwrap();
}
