//! Owned fixtures only; no source inputs are executed and no compiler is launched by these tests.
//! Prepare them separately with `tests/fixtures/debug-types/build.sh /absolute/fixture-directory`, then run:
//! `RAMPAGE_DEBUG_TYPE_FIXTURES=/absolute/fixture-directory cargo test -p rampage-mcp --test integration debug_types:: -- --ignored`.
//! The recipe compiles debug-types.c (DWARF and negative C CodeView), debug-types-pdb.cpp
//! (positive CodeView UniqueNames), and debug-types.cpp (C++ classes), retaining their sizeof/offsetof tables.

use crate::pdb_support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::Session;
use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

const OPT_IN: &str = "compile tests/fixtures/debug-types/build.sh OUTPUT and set RAMPAGE_DEBUG_TYPE_FIXTURES=OUTPUT";
const POSITIVE_IMAGES: [(&str, Option<&str>); 3] = [
    ("debug-types-x64.elf", None),
    ("debug-types-arm64.elf", None),
    ("debug-types-cpp.exe", Some("debug-types-cpp.pdb")),
];
const RECORD_FIELDS: [(&str, u64, u64); 7] = [
    ("identifier", 0, 4),
    ("nested", 4, 8),
    ("taps", 12, 16),
    ("mode", 28, 4),
    ("payload", 32, 8),
    ("next", 40, 8),
    ("callback", 48, 8),
];

struct OwnedFixture {
    directory: PathBuf,
    path: PathBuf,
    pdb: Option<PathBuf>,
    originals: Vec<(PathBuf, Vec<u8>)>,
}

impl OwnedFixture {
    fn new(image: &str, pdb: Option<&str>) -> Self {
        let root = PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES").expect(OPT_IN));
        assert!(root.is_dir(), "{}: {OPT_IN}", root.display());
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-mcp-debug-types-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut owned = Self { path: directory.join(image), pdb: None, directory, originals: Vec::new() };
        for name in std::iter::once(image).chain(pdb) {
            let source = root.join(name);
            assert!(source.is_file(), "missing compiler-generated fixture {}: {OPT_IN}", source.display());
            let bytes = std::fs::read(&source).unwrap();
            assert!(!bytes.is_empty(), "empty fixture {}", source.display());
            std::fs::write(owned.directory.join(name), &bytes).unwrap();
            owned.originals.push((source, bytes));
        }
        owned.pdb = pdb.map(|name| owned.directory.join(name));
        owned
    }

    fn arguments(&self, mut extra: Value) -> Value {
        extra["path"] = json!(self.path);
        if let Some(pdb) = &self.pdb {
            extra["pdb"] = json!(pdb);
        }
        extra
    }

    fn annotation_bytes(&self) -> Vec<u8> {
        let sidecar = PathBuf::from(format!("{}.rampage", self.path.display()));
        match std::fs::read(sidecar) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("cannot read owned annotation log: {error}"),
        }
    }

    fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(&entry.path(), files);
                } else {
                    files.insert(entry.path(), std::fs::read(entry.path()).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(&self.directory, &mut files);
        files
    }

    fn replace(&self, path: &Path, bytes: &[u8]) {
        let replacement = self.directory.join("replacement.bin");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(replacement, path).unwrap();
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        let unchanged = self.originals.iter().all(|(path, bytes)| std::fs::read(path).is_ok_and(|now| now == *bytes));
        let cleanup = std::fs::remove_dir_all(&self.directory);
        if !std::thread::panicking() {
            cleanup.unwrap();
            assert!(unchanged, "test changed a source fixture outside its owned directory");
        }
    }
}

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

type Client = RunningService<RoleClient, TestClient>;

async fn connect(server: RampageServer) -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &Client, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn response_text(result: &CallToolResult) -> &str {
    let text = &result.content.first().expect("MCP content").as_text().expect("text response").text;
    assert!(text.len() <= 60_000, "response is not bounded: {} bytes", text.len());
    text
}

async fn success(client: &Client, name: &str, arguments: Value) -> Value {
    let result = call(client, name, arguments).await;
    let text = response_text(&result);
    assert_ne!(result.is_error, Some(true), "{name}: {text}");
    serde_json::from_str(text).unwrap_or_else(|error| panic!("{name}: invalid JSON: {error}: {text}"))
}

async fn refused(client: &Client, name: &str, arguments: Value) -> String {
    let result = call(client, name, arguments).await;
    let text = response_text(&result);
    assert_eq!(result.is_error, Some(true), "{name} unexpectedly succeeded: {text}");
    assert!(!text.is_empty(), "{name}: missing refusal reason");
    text.to_owned()
}

async fn annotations(client: &Client, fixture: &OwnedFixture) -> Value {
    success(client, "list_annotations", json!({"path": fixture.path})).await
}

async fn preview_all(client: &Client, fixture: &OwnedFixture) -> (Value, Vec<Value>) {
    let first = success(client, "import_debug_types", fixture.arguments(json!({"limit": 1}))).await;
    assert_eq!(first["applied"], false);
    assert_eq!(first["imported_types"], 0);
    assert_eq!(first["imported_signatures"], 0);
    assert_eq!(first["offset"], 0);
    assert_eq!(first["limit"], 1);
    let hash = first["review_sha256"].as_str().expect("whole-plan review digest");
    assert_eq!(hash.len(), 64);
    assert!(hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert!(first["warnings"].is_array());
    let total = first["total"].as_u64().unwrap();
    assert!(total > 1 && total <= 256, "owned fixture should exercise paging: {first}");
    let mut page = first.clone();
    let mut details = Vec::new();
    loop {
        for field in [
            "review_sha256",
            "manifest_id",
            "total",
            "applicable_types",
            "applicable_signatures",
            "preserved_signatures",
        ] {
            assert_eq!(page[field], first[field], "paging changed {field}");
        }
        details.extend(page["details"].as_array().unwrap().iter().cloned());
        let Some(offset) = page["next_offset"].as_u64() else { break };
        assert_eq!(offset, details.len() as u64, "non-progressing or overlapping page");
        assert!(offset < total);
        page = success(client, "import_debug_types", fixture.arguments(json!({"offset": offset, "limit": 8}))).await;
    }
    assert_eq!(details.len() as u64, total, "paging lost producer facts");
    (first, details)
}

fn detail<'a>(details: &'a [Value], original: &str) -> &'a Value {
    let mut matching: Vec<_> =
        details.iter().filter(|row| row["original_name"] == original && row["applicable"] == true).collect();
    let definitions: Vec<_> = matching
        .iter()
        .copied()
        .filter(|row| matches!(row["producer"]["kind"]["kind"].as_str(), Some("struct" | "union" | "enum")))
        .collect();
    if !definitions.is_empty() {
        matching = definitions;
    }
    assert_eq!(matching.len(), 1, "expected one complete applicable {original}: {details:#?}");
    matching[0]
}

fn native_field<'a>(native: &'a Value, name: &str) -> &'a Value {
    native["fields"].as_array().unwrap().iter().find(|field| field["name"] == name).expect(name)
}

fn producer_member<'a>(producer: &'a Value, name: &str) -> &'a Value {
    producer["kind"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["name"] == name)
        .unwrap_or_else(|| panic!("missing producer member {name}: {producer}"))
}

fn assert_native_nested_gain(code: &str) {
    let compact: String = code.chars().filter(|character| !character.is_whitespace()).collect();
    assert!(
        compact.contains("->nested.gain") || compact.contains("->nested).gain"),
        "native nested field missing: {code}"
    );
}

fn assert_record_facts(details: &[Value]) {
    let record = detail(details, "DebugRecord");
    assert_eq!(record["producer"]["byte_size"], 56);
    assert!(record["producer"]["alignment"].is_null(), "the recipe supplies no producer alignment attribute");
    assert_eq!(record["native"]["kind"], "struct");
    assert_eq!(record["native"]["size"], 56);
    assert_eq!(record["native"]["incomplete"], false);
    assert_eq!(record["producer"]["kind"]["members"].as_array().unwrap().len(), RECORD_FIELDS.len());
    assert_eq!(record["native"]["fields"].as_array().unwrap().len(), RECORD_FIELDS.len());
    for (name, offset, size) in RECORD_FIELDS {
        let member = producer_member(&record["producer"], name);
        assert_eq!(member["byte_offset"], offset, "producer {name}");
        assert_eq!(member["bitfield"], Value::Null);
        assert_eq!(native_field(&record["native"], name)["offset"], offset, "native {name}");
        assert_eq!(native_field(&record["native"], name)["size"], size, "native {name}");
    }
    let inner = detail(details, "DebugInner");
    assert_eq!(inner["producer"]["byte_size"], 8);
    assert_eq!(inner["native"]["size"], 8);
    for (name, offset, size) in [("gain", 0, 4), ("bias", 4, 2)] {
        assert_eq!(producer_member(&inner["producer"], name)["byte_offset"], offset);
        assert_eq!(native_field(&inner["native"], name)["offset"], offset);
        assert_eq!(native_field(&inner["native"], name)["size"], size);
    }
    let taps = producer_member(&record["producer"], "taps");
    let array = details.iter().find(|row| row["producer_type_id"] == taps["type_id"]).expect("array facts");
    assert_eq!(array["producer"]["kind"]["kind"], "array");
    assert_eq!(array["producer"]["kind"]["count"], 2);
    assert_eq!(array["producer"]["kind"]["element"], inner["producer_type_id"]);
    assert_eq!(native_field(&record["native"], "taps")["identity"]["length"], 2);
    assert_eq!(native_field(&record["native"], "taps")["identity"]["element"]["reference"], inner["emitted_name"]);
    assert_eq!(native_field(&record["native"], "nested")["type_name"], inner["emitted_name"]);
    assert_eq!(native_field(&record["native"], "next")["identity"]["target"]["reference"], record["emitted_name"]);
    let mode = detail(details, "DebugMode");
    assert_eq!(native_field(&record["native"], "mode")["type_name"], mode["emitted_name"]);
    for (name, value) in [("DEBUG_OFF", "0"), ("DEBUG_READY", "7"), ("DEBUG_FAULT", "-3")] {
        for values in [&mode["producer"]["kind"]["values"], &mode["native"]["enum_values"]] {
            assert!(values.as_array().unwrap().iter().any(|entry| entry["name"] == name && entry["value"] == value));
        }
    }
    assert_eq!(detail(details, "DebugPayload")["native"]["kind"], "union");
    assert_eq!(detail(details, "DebugPayload")["native"]["size"], 8);
    let callback = detail(details, "DebugCallback");
    assert_eq!(callback["native"]["size"], 8);
    assert_eq!(callback["native"]["callback"]["variadic"], false);
    assert_eq!(callback["native"]["callback"]["parameters"].as_array().unwrap().len(), 2);
    let bits: Vec<_> = details.iter().filter(|row| row["original_name"] == "DebugBits").collect();
    assert!(!bits.is_empty(), "bitfield source evidence disappeared");
    assert!(
        bits.iter().any(|bits| {
            bits["producer_evidence"]["members"]
                .as_array()
                .or_else(|| bits["producer"]["kind"]["members"].as_array())
                .is_some_and(|members| {
                    !members.is_empty()
                        && members.iter().any(|member| {
                            member["bitfield"]["bit_size"].as_u64().is_some()
                                && ["bit_offset", "data_bit_offset", "legacy_bit_offset"]
                                    .iter()
                                    .any(|key| member["bitfield"][*key].as_u64().is_some())
                        })
                })
        }),
        "unsupported bitfield records must expose retained members and raw bit-size/offset facts"
    );
    for bits in bits {
        assert_eq!(bits["applicable"], false, "must not import a partial DebugBits");
        assert!(bits["native"].is_null());
        assert!(!bits["reasons"].as_array().unwrap().is_empty());
    }
}

async fn assert_native_record(client: &Client, fixture: &OwnedFixture, details: &[Value]) {
    for original in ["DebugRecord", "DebugInner", "DebugPayload", "DebugMode", "DebugCallback"] {
        let proof = detail(details, original);
        let native =
            success(client, "get_type", json!({"path": fixture.path, "name": proof["emitted_name"].as_str().unwrap()}))
                .await;
        assert_library_native(&native, &proof["native"]);
    }
}

fn assert_library_native(entry: &Value, expected: &Value) {
    assert_eq!(entry["scope"], "library");
    assert_eq!(entry["declaration"]["source"]["kind"], "checked_debug_types");
    let mut metadata = entry.as_object().unwrap().clone();
    metadata.remove("scope");
    metadata.remove("declaration");
    assert_eq!(Value::Object(metadata), *expected, "native metadata differs from the reviewed producer counterpart");
}

fn assert_one_import_batch(fixture: &OwnedFixture, before: &[u8], signatures: u64) {
    let after = fixture.annotation_bytes();
    assert!(after.starts_with(before), "import rewrote the existing annotation prefix");
    let appended = std::str::from_utf8(&after[before.len()..]).unwrap();
    let lines: Vec<Value> = appended.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(lines.len() as u64, signatures + 3, "one header, one library, one proof, all signatures");
    assert_eq!(lines[0]["edits"], signatures + 2);
    let batch = lines[0]["batch"].as_str().unwrap();
    for edit in &lines[1..] {
        assert_eq!(edit["batch"], batch, "import escaped its atomic batch");
    }
}

fn assert_compiler_table(fixture: &OwnedFixture, name: &str, expected: &[u32]) {
    let project = Session::default().open(&fixture.path, None).unwrap();
    let address = project.resolve(name).expect("compiler-emitted sizeof/offsetof table");
    let bytes = project.binary.read(address, (expected.len() * 4) as u64).expect("backed layout table");
    let words: Vec<_> = bytes.as_chunks::<4>().0.iter().map(|word| u32::from_le_bytes(*word)).collect();
    assert_eq!(words, expected, "fixture no longer matches its source static assertions");
}

fn manifest(annotations: &Value) -> Value {
    assert_eq!(annotations["debug_types"].as_array().unwrap().len(), 1);
    let proofs: Value = serde_json::from_str(annotations["debug_types"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(proofs["version"], 1);
    assert_eq!(proofs["imports"].as_array().unwrap().len(), 1);
    let mut manifest = proofs["imports"][0].clone();
    for field in ["producer", "expected_native_named_types"] {
        let framed = manifest[field].as_str().unwrap_or_else(|| panic!("{field} must be a framed JSON string"));
        assert!(framed.len() <= 1024 * 1024, "{field} exceeds the 1 MiB proof frame bound");
        manifest[field] =
            serde_json::from_str(framed).unwrap_or_else(|error| panic!("invalid {field} proof frame: {error}"));
    }
    assert!(manifest["producer"].is_object(), "producer frame must retain the structured report");
    assert!(manifest["expected_native_named_types"].is_array(), "native frame must retain the type inventory");
    manifest
}

fn function_address(proof: &Value, name: &str) -> String {
    proof["producer"]["signatures"].as_array().unwrap().iter().find(|signature| signature["name"] == name).expect(name)
        ["address"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn debug_type_catalog_is_types_gated_and_keeps_the_legacy_import_contracts_separate() {
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "import_debug_types"));
    success(&client, "enable_tools", json!({"groups": ["types"]})).await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "import_debug_types").expect("actual MCP debug-type tool");
    for property in ["path", "pdb", "apply", "review_sha256", "offset", "limit"] {
        assert!(tool.input_schema["properties"].get(property).is_some(), "missing {property}");
    }
    assert_eq!(tool.input_schema["additionalProperties"], false);
    let required = tool.input_schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("path")));
    for optional in ["pdb", "apply", "review_sha256", "offset", "limit"] {
        assert!(!required.contains(&json!(optional)), "{optional} must be optional");
    }
    let pdb = tools.iter().find(|tool| tool.name == "import_pdb_names").unwrap();
    assert!(pdb.input_schema["required"].as_array().unwrap().contains(&json!("pdb")));
    assert!(pdb.input_schema["properties"].get("review_sha256").is_none());
    let dwarf = tools.iter().find(|tool| tool.name == "import_debug_layouts").unwrap();
    assert!(dwarf.input_schema["properties"].get("review_sha256").is_some());
    assert!(dwarf.input_schema["properties"].get("pdb").is_none());
    client.cancel().await.unwrap();
}

#[tokio::test]
#[ignore = "requires RAMPAGE_DEBUG_TYPE_FIXTURES; see module instructions; never compiles or executes fixtures"]
async fn owned_preview_is_read_only_and_missing_wrong_or_oversized_review_requests_are_atomic() {
    for (image, pdb) in POSITIVE_IMAGES {
        let fixture = OwnedFixture::new(image, pdb);
        let before = fixture.files();
        let client = connect(RampageServer::with_groups([Group::Types])).await;
        let (preview, details) = preview_all(&client, &fixture).await;
        assert!(preview["applicable_types"].as_u64().unwrap() > 1, "{image}: {preview}");
        assert!(preview["applicable_signatures"].as_u64().unwrap() > 1, "{image}: {preview}");
        assert_record_facts(&details);
        assert!(details.iter().any(|row| row["applicable"] == true && row["producer"]["alignment"].is_null()));
        assert_eq!(fixture.files(), before, "preview created or modified source, annotation, or lock files");
        for extra in [
            json!({"limit": 257}),
            json!({"apply": true, "review_sha256": preview["review_sha256"], "limit": 257}),
            json!({"limit": 0}),
        ] {
            refused(&client, "import_debug_types", fixture.arguments(extra)).await;
            assert_eq!(fixture.files(), before, "invalid paging created an annotation or lock file");
        }
        for extra in [json!({"apply": true}), json!({"apply": true, "review_sha256": "0".repeat(64)})] {
            refused(&client, "import_debug_types", fixture.arguments(extra)).await;
            assert_eq!(fixture.annotation_bytes(), Vec::<u8>::new(), "rejected request persisted annotations");
        }
        let empty = annotations(&client, &fixture).await;
        for field in ["debug_types", "type_library", "types", "signatures"] {
            assert_eq!(empty[field], json!([]), "rejected request changed {field}");
        }
        assert_eq!(success(&client, "undo", json!({"path": fixture.path})).await, json!([]));
        if pdb.is_none() {
            assert_compiler_table(&fixture, "debug_type_layout", &[8, 4, 56, 8, 0, 4, 12, 28, 32, 40, 48, 8, 8, 4]);
        }
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires RAMPAGE_DEBUG_TYPE_FIXTURES; see module instructions; never compiles or executes fixtures"]
async fn owned_whole_import_preserves_analyst_signature_decompiles_native_members_and_replays_one_batch() {
    for (image, pdb) in POSITIVE_IMAGES {
        let fixture = OwnedFixture::new(image, pdb);
        let original_image = std::fs::read(&fixture.path).unwrap();
        let original_pdb = fixture.pdb.as_ref().map(|path| std::fs::read(path).unwrap());
        let entry = Session::default().open(&fixture.path, None).unwrap().binary.entry.unwrap();
        let analyst = "int4 analyst_main(void);";
        let client = connect(RampageServer::with_groups([Group::Types])).await;
        success(&client, "set_signature", json!({"path": fixture.path, "at": format!("{entry:#x}"), "text": analyst}))
            .await;
        let baseline = annotations(&client, &fixture).await;
        let before_log = fixture.annotation_bytes();
        let (preview, details) = preview_all(&client, &fixture).await;
        assert_eq!(fixture.annotation_bytes(), before_log);
        assert!(preview["preserved_signatures"].as_u64().unwrap() >= 1);
        let applied = success(
            &client,
            "import_debug_types",
            fixture.arguments(json!({"apply": true, "review_sha256": preview["review_sha256"], "limit": 1})),
        )
        .await;
        assert_eq!(applied["applied"], true);
        for field in ["review_sha256", "manifest_id", "total", "applicable_types", "applicable_signatures"] {
            assert_eq!(applied[field], preview[field]);
        }
        assert_eq!(applied["details"].as_array().unwrap().len(), 1);
        assert_eq!(applied["imported_types"], preview["applicable_types"]);
        assert_eq!(applied["imported_signatures"], preview["applicable_signatures"]);
        assert!(applied["imported_types"].as_u64().unwrap() > 1, "limit=1 must not truncate the write batch");
        let imported = annotations(&client, &fixture).await;
        assert_eq!(imported["types"], json!([]), "legacy layout annotations must remain separate");
        assert_eq!(imported["type_library"].as_array().unwrap().len(), 1);
        let proof = manifest(&imported);
        assert_eq!(proof["id"], applied["manifest_id"]);
        assert_eq!(proof["review_sha256"], preview["review_sha256"]);
        assert_eq!(proof["library_names"].as_array().unwrap().len() as u64, applied["imported_types"]);
        for row in &details {
            assert!(proof["producer"]["types"].as_array().unwrap().contains(&row["producer"]));
        }
        let signatures = imported["signatures"].as_array().unwrap();
        let count = applied["imported_signatures"].as_u64().unwrap();
        assert!(count > 1, "limit=1 must not truncate the signature batch");
        assert_one_import_batch(&fixture, &before_log, count);
        assert_eq!(signatures.len() as u64, count + 1);
        assert!(signatures.iter().any(|signature| signature["text"] == analyst));
        for signature in signatures.iter().filter(|signature| signature["text"] != analyst) {
            let text = signature["text"].as_str().unwrap();
            assert!(text.starts_with("!rampage-debug-types-signature-v1\n"));
            assert!(text.lines().nth(1).is_some_and(|id| id == proof["id"].as_str().unwrap()));
        }
        assert_native_record(&client, &fixture, &details).await;
        let code = success(
            &client,
            "decompile",
            json!({"path": fixture.path, "at": function_address(&proof, "debug_types_query"), "view": "code"}),
        )
        .await;
        let code = code["code"].as_str().unwrap();
        assert_native_nested_gain(code);
        assert!(code.contains("taps[") && code.contains("].bias"), "native indexed field missing: {code}");
        let undo = success(&client, "undo", json!({"path": fixture.path})).await;
        assert_eq!(undo.as_array().unwrap().len() as u64, count + 2, "proof/library/signatures must be one batch");
        for field in ["debugtypes", "typelibrary", "signature"] {
            assert!(undo.as_array().unwrap().iter().any(|edit| edit["field"] == field), "missing undo {field}");
        }
        assert_eq!(annotations(&client, &fixture).await, baseline);
        let redo = success(&client, "redo", json!({"path": fixture.path})).await;
        assert_eq!(redo.as_array().unwrap().len(), undo.as_array().unwrap().len());
        assert_eq!(annotations(&client, &fixture).await, imported);
        assert_native_record(&client, &fixture, &details).await;
        client.cancel().await.unwrap();

        let replay = connect(RampageServer::with_groups([Group::Types])).await;
        assert_eq!(annotations(&replay, &fixture).await, imported);
        assert_native_record(&replay, &fixture, &details).await;
        let replayed = success(
            &replay,
            "decompile",
            json!({"path": fixture.path, "at": function_address(&proof, "debug_types_query"), "view": "code"}),
        )
        .await;
        assert_native_nested_gain(replayed["code"].as_str().unwrap());
        assert_eq!(manifest(&annotations(&replay, &fixture).await)["image_sha256"], proof["image_sha256"]);
        let before_delete = fixture.annotation_bytes();
        refused(
            &replay,
            "delete_type",
            json!({"path": fixture.path, "name": detail(&details, "DebugRecord")["emitted_name"],
                "definition_group": true}),
        )
        .await;
        assert_eq!(fixture.annotation_bytes(), before_delete, "sealed signatures still reference the group");
        for signature in proof["signatures"].as_array().unwrap() {
            success(
                &replay,
                "set_signature",
                json!({"path": fixture.path, "at": format!("{:#x}", signature["address"].as_u64().unwrap()),
                    "clear": true}),
            )
            .await;
        }
        success(
            &replay,
            "delete_type",
            json!({"path": fixture.path, "name": detail(&details, "DebugRecord")["emitted_name"],
                "definition_group": true}),
        )
        .await;
        let deleted = annotations(&replay, &fixture).await;
        assert_eq!(deleted["debug_types"], json!([]));
        assert_eq!(deleted["type_library"], json!([]));
        assert_eq!(deleted["signatures"], baseline["signatures"]);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), original_image, "analysis patched the executable");
        assert_eq!(fixture.pdb.as_ref().map(|path| std::fs::read(path).unwrap()), original_pdb);
        replay.cancel().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires RAMPAGE_DEBUG_TYPE_FIXTURES; see module instructions; never compiles or executes fixtures"]
async fn owned_c_codeview_unresolved_forwards_stay_negative_and_pdb_paths_are_never_discovered() {
    let fixture = OwnedFixture::new("debug-types.exe", Some("debug-types.pdb"));
    let before = fixture.files();
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let (_, details) = preview_all(&client, &fixture).await;
    assert!(
        details.iter().any(|row| {
            row["original_name"] == "DebugRecord"
                && row["applicable"] == false
                && row["reasons"].as_array().unwrap().iter().any(|reason| {
                    let reason = reason.as_str().unwrap();
                    reason.contains("forward") || reason.contains("unresolved")
                })
        }),
        "C display names must not substitute for CodeView UniqueNames: {details:#?}"
    );
    assert!(!details.iter().any(|row| row["original_name"] == "DebugRecord" && row["applicable"] == true));
    let implicit = success(&client, "import_debug_types", json!({"path": fixture.path, "limit": 1})).await;
    assert_eq!(implicit["applied"], false);
    assert_eq!(implicit["applicable_types"], 0, "adjacent/producer PDB paths must not be read implicitly");
    assert_eq!(implicit["applicable_signatures"], 0);
    assert_eq!(fixture.files(), before, "negative/implicit previews must not create annotations or locks");
    client.cancel().await.unwrap();
}

#[tokio::test]
#[ignore = "requires RAMPAGE_DEBUG_TYPE_FIXTURES; see module instructions; never compiles or executes fixtures"]
async fn owned_review_is_invalidated_by_changed_image_and_same_guid_age_pdb_bytes_before_commit() {
    for change_pdb in [false, true] {
        let fixture = OwnedFixture::new("debug-types-cpp.exe", Some("debug-types-cpp.pdb"));
        let client = connect(RampageServer::with_groups([Group::Types])).await;
        let preview = success(&client, "import_debug_types", fixture.arguments(json!({"limit": 1}))).await;
        let baseline = annotations(&client, &fixture).await;
        let before = fixture.annotation_bytes();
        if change_pdb {
            let path = fixture.pdb.as_ref().unwrap();
            let mut bytes = std::fs::read(path).unwrap();
            let offset = pdb_support::stream_offset(&bytes, 1, 4);
            bytes[offset] ^= 1;
            fixture.replace(path, &bytes);
        } else {
            let mut bytes = std::fs::read(&fixture.path).unwrap();
            let rsds = pdb_support::rsds_offset(&bytes);
            let identity = bytes[rsds..rsds + 24].to_vec();
            bytes.push(0x5a);
            assert_eq!(&bytes[rsds..rsds + 24], identity.as_slice());
            fixture.replace(&fixture.path, &bytes);
        }
        let current = success(&client, "import_debug_types", fixture.arguments(json!({"limit": 1}))).await;
        assert!(current["applicable_types"].as_u64().unwrap() > 1, "changed fixture remains valid producer input");
        assert_ne!(current["review_sha256"], preview["review_sha256"]);
        refused(
            &client,
            "import_debug_types",
            fixture.arguments(json!({"apply": true, "review_sha256": preview["review_sha256"], "limit": 1})),
        )
        .await;
        assert_eq!(fixture.annotation_bytes(), before, "source digest rejection committed annotations");
        assert_eq!(annotations(&client, &fixture).await, baseline);
        assert_eq!(success(&client, "undo", json!({"path": fixture.path})).await, json!([]));
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires RAMPAGE_DEBUG_TYPE_FIXTURES; see module instructions; never compiles or executes fixtures"]
async fn owned_cpp_class_fields_match_compiler_facts_in_the_native_project_library() {
    let fixture = OwnedFixture::new("debug-cpp-x64.elf", None);
    let client = connect(RampageServer::with_groups([Group::Types])).await;
    let (preview, details) = preview_all(&client, &fixture).await;
    assert_compiler_table(&fixture, "debug_cpp_layout", &[16, 8, 0, 8, 48, 8, 0, 32, 40]);
    let owner = detail(&details, "DebugOwner");
    let cell = detail(&details, "DebugCell");
    assert_eq!(owner["producer"]["byte_size"], 48);
    assert_eq!(owner["native"]["size"], 48);
    assert_eq!(cell["producer"]["byte_size"], 16);
    assert_eq!(cell["native"]["size"], 16);
    for (record, fields) in [
        (owner, vec![("cells", 0, 32), ("bias", 32, 4), ("next", 40, 8)]),
        (cell, vec![("count", 0, 4), ("level", 8, 8)]),
    ] {
        assert_eq!(record["native"]["fields"].as_array().unwrap().len(), fields.len());
        for (name, offset, size) in fields {
            assert_eq!(producer_member(&record["producer"], name)["byte_offset"], offset);
            assert_eq!(native_field(&record["native"], name)["offset"], offset);
            assert_eq!(native_field(&record["native"], name)["size"], size);
        }
    }
    success(
        &client,
        "import_debug_types",
        fixture.arguments(json!({"apply": true, "review_sha256": preview["review_sha256"], "limit": 1})),
    )
    .await;
    for record in [owner, cell] {
        let native = success(&client, "get_type", json!({"path": fixture.path, "name": record["emitted_name"]})).await;
        assert_library_native(&native, &record["native"]);
    }
    client.cancel().await.unwrap();
}
