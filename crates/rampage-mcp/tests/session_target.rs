//! The session's target over MCP, and the other repairs of benchmark suite v4's Haiku pass (19 tool errors on
//! rampage 1.10.0): a call without `path` works on the one binary the connection opened; Intel HEX and S-record
//! files open by path alone when their records show a Cortex-M vector table; evaluate_function and inspect_data
//! take sizes they used to refuse; a guessed group name and an .svd file given as `path` get a way forward.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Calls `tool`, returning its text and whether it failed.
async fn call(client: &Client, tool: &str, arguments: Value) -> (String, bool) {
    let arguments = arguments.as_object().unwrap().clone();
    let result: CallToolResult =
        client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    (text, result.is_error == Some(true))
}

/// Calls `tool`, returning every content block's text and whether it failed.
async fn call_blocks(client: &Client, tool: &str, arguments: Value) -> (Vec<String>, bool) {
    let arguments = arguments.as_object().unwrap().clone();
    let result: CallToolResult =
        client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap();
    let texts = result.content.iter().map(|content| content.as_text().unwrap().text.clone()).collect();
    (texts, result.is_error == Some(true))
}

/// `tool`'s result as JSON, asserting it succeeded.
async fn ok(client: &Client, tool: &str, arguments: Value) -> Value {
    let (text, failed) = call(client, tool, arguments).await;
    assert!(!failed, "{tool}: {text}");
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{tool}: {error}: {text}"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// A canonical temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rampage-mcp-session-target-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn copy(&self, fixture: &str, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::copy(fixtures().join(fixture), &path).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Intel HEX text for `bytes` at address 0: 16-byte data records and the end record.
fn ihex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for (index, chunk) in bytes.chunks(16).enumerate() {
        let address = (index * 16) as u16;
        let mut record = vec![chunk.len() as u8, (address >> 8) as u8, address as u8, 0];
        record.extend_from_slice(chunk);
        let checksum = record.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)).wrapping_neg();
        record.push(checksum);
        text.push(':');
        text.extend(record.iter().map(|byte| format!("{byte:02X}")));
        text.push('\n');
    }
    text + ":00000001FF\n"
}

/// Haiku v4: four calls repeated or dropped the `raw` selector of the one image a run worked on, and two reached
/// peripheral_access before an applied import. Once a connection has opened one binary, `path` and `raw` default to
/// it, peripheral state included; with several, the error lists them; an explicit `path` always wins.
#[tokio::test]
async fn a_call_without_path_works_on_the_one_binary_the_session_opened() {
    let client = connect().await;
    let (text, failed) = call(&client, "binary_info", json!({})).await;
    assert!(failed && text.contains("no binary is open in this session") && text.contains("pass `path`"), "{text}");
    // Arguments are still checked first: a missing `path` is no longer one of the refusals.
    let (text, failed) = call(&client, "disassemble", json!({ "count": 2 })).await;
    assert!(failed && text.contains("pass `path`"), "{text}");

    let path = fixtures().join("firmware/raw-cortex-m-svd.bin");
    let svd = fixtures().join("svd/ARM_Example.svd");
    let selector = json!({ "profile": "ARM:LE:32:Cortex", "base_address": "0x8000000", "vector_table": true });
    let explicit = ok(&client, "list_functions", json!({ "path": path, "raw": selector })).await;
    let defaulted = ok(&client, "list_functions", json!({})).await;
    assert_eq!(explicit["total"], defaulted["total"], "{defaulted}");
    // Another spelling of the same interpretation is the same target.
    let alias = json!({ "profile": "cortex-m", "base_address": 134217728, "vector_table": true });
    ok(&client, "binary_info", json!({ "path": path, "raw": alias })).await;

    ok(&client, "enable_tools", json!({ "groups": ["types"] })).await;
    // A preview says that nothing was applied.
    let preview = ok(&client, "import_svd", json!({ "svd": svd })).await;
    assert_eq!(preview["applied"], false);
    assert!(preview["next"].as_str().unwrap().contains("apply=true"), "{preview}");
    let (text, failed) = call(&client, "peripheral_access", json!({})).await;
    assert!(failed && text.contains("only previews"), "{text}");
    // The .svd file given as `path` with no `svd` is the map, and the session's target the image.
    let applied = ok(&client, "import_svd", json!({ "path": svd, "apply": true })).await;
    assert_eq!(applied["applied"], true, "{applied}");
    let peripherals = ok(&client, "peripheral_access", json!({})).await;
    assert!(peripherals.to_string().contains("TIMER0"), "{peripherals}");
    // The path alone reaches the same Raw project and its peripherals.
    let registers = ok(&client, "peripheral_access", json!({ "path": path, "peripheral": "TIMER0" })).await;
    assert!(registers.to_string().contains("RELOAD[2]"), "{registers}");
    let listing = ok(&client, "list_annotations", json!({})).await;
    assert!(listing.is_object(), "{listing}");

    // A second binary: an explicit path wins, and a call without one is told to pick.
    let elf = fixtures().join("firmware/cortex-m3.elf");
    ok(&client, "binary_info", json!({ "path": elf })).await;
    let (text, failed) = call(&client, "list_functions", json!({})).await;
    assert!(failed && text.contains("opened 2 binaries"), "{text}");
    assert!(text.contains("raw-cortex-m-svd.bin with raw=") && text.contains("cortex-m3.elf`"), "{text}");
    ok(&client, "list_functions", json!({ "path": path, "raw": selector })).await;
    client.cancel().await.unwrap();
}

/// Haiku v4: triage_report, list_patches and integrity_checks refused a .hex or .srec file given by path alone, and
/// disassemble of a record file opened without vector_table found no entry. A record file whose lowest run starts
/// with a Cortex-M vector table opens by path; any other names the exact selector to pass.
#[tokio::test]
async fn record_files_with_a_cortex_m_vector_table_open_by_path_alone() {
    let client = connect().await;
    let scratch = Scratch::new();
    ok(&client, "enable_tools", json!({ "groups": ["formats"] })).await;
    for (fixture, name) in
        [("firmware/raw-cortex-m-crc.hex", "fixture.hex"), ("firmware/raw-cortex-m-crc.srec", "f.srec")]
    {
        let path = scratch.copy(fixture, name);
        let triage = ok(&client, "triage_report", json!({ "path": path })).await;
        assert_eq!(triage["target"]["format"], "raw", "{triage}");
        ok(&client, "list_patches", json!({ "path": path })).await;
        let checks = ok(&client, "integrity_checks", json!({ "path": path })).await;
        assert_eq!(checks["checks"][0]["algorithm"], "crc32", "{checks}");
        let lines = ok(&client, "disassemble", json!({ "path": path, "count": 4 })).await;
        assert_eq!(lines.as_array().map(Vec::len), Some(4), "{lines}");
        // Without a start address (the S-record end record states 0) and opened without vector_table, the project
        // has no entry: disassemble starts at the Reset handler.
        let (format, start, replacement) =
            if name.ends_with("hex") { ("ihex", ":04000005", None) } else { ("srec", "S7", Some("S70500000000FA")) };
        let text = std::fs::read_to_string(&path).unwrap();
        let stripped = scratch.0.join(format!("no-start-{name}"));
        let records: Vec<&str> =
            text.lines().filter_map(|line| if line.starts_with(start) { replacement } else { Some(line) }).collect();
        std::fs::write(&stripped, records.join("\n")).unwrap();
        let selector = json!({ "profile": "cortex-m", "format": format });
        let info = ok(&client, "binary_info", json!({ "path": stripped, "raw": selector })).await;
        assert!(info["entry"].is_null(), "{info}");
        let from_reset = ok(&client, "disassemble", json!({ "path": stripped, "raw": selector, "count": 4 })).await;
        assert_eq!(from_reset[0]["address"], lines[0]["address"], "{from_reset}");
        assert!(from_reset[0]["comment"].as_str().unwrap().contains("Reset handler"), "{from_reset}");
    }

    // Records without a vector table (an initial SP outside RAM): the error names the selector to pass.
    let mut bytes = vec![0x34, 0x12, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00];
    bytes.resize(64, 0x43);
    let path = scratch.0.join("other.hex");
    std::fs::write(&path, ihex(&bytes)).unwrap();
    let (text, failed) = call(&client, "triage_report", json!({ "path": path })).await;
    assert!(failed && text.contains("no Cortex-M vector table"), "{text}");
    assert!(text.contains(r#""raw":{"profile":"<processor>","format":"ihex"}"#), "{text}");
    client.cancel().await.unwrap();
}

/// Haiku v4: five evaluate_function calls sent a text buffer's size without its NUL, and two inspect_data calls
/// asked for word_size 1. Such sizes now take the content's length, and inspect_data reads its 1024-byte cap and
/// the pointer width, saying what was asked for. Past evaluate_function's 1 MiB cap is still an error.
#[tokio::test]
async fn short_buffers_and_oversized_reads_are_clamped_instead_of_refused() {
    let client = connect().await;
    let thumb = fixtures().join("bin/hello-thumb.elf");
    let strlen =
        |size: u64| json!({ "path": thumb, "at": "0x20e8c", "args": [{"buffer": {"text": "four", "size": size}}] });
    let report = ok(&client, "evaluate_function", strlen(4)).await;
    assert_eq!(
        (report["buffers"][0]["size"].as_u64(), report["buffers"][0]["requested_size"].as_u64()),
        (Some(5), Some(4))
    );
    assert_eq!(report["result"]["unsigned"], 4, "{report}");
    let (text, failed) = call(&client, "evaluate_function", strlen(2 << 20)).await;
    assert!(failed && text.contains("buffer size must be"), "{text}");
    // `arguments` as the JSON text of a list is `args`.
    let report = ok(
        &client,
        "evaluate_function",
        json!({ "path": thumb, "at": "0x20e8c", "arguments": r#"[{"buffer": {"text": "seven!!"}}]"# }),
    )
    .await;
    assert_eq!(report["result"]["unsigned"], 7, "{report}");

    let arm64 = fixtures().join("bin/hello-arm64.elf");
    let report = ok(&client, "inspect_data", json!({ "path": arm64, "at": "main", "size": 4096 })).await;
    assert_eq!((report["size"].as_u64(), report["requested_size"].as_u64()), (Some(1024), Some(4096)), "{report}");
    assert_eq!(report["truncated"], true);
    // `count` with a width it does not read counts bytes, not words of that width.
    let report = ok(&client, "inspect_data", json!({ "path": arm64, "at": "main", "count": 33, "word_size": 1 })).await;
    assert_eq!(report["size"], 33, "{report}");
    assert_eq!((report["word_size"].as_u64(), report["requested_word_size"].as_u64()), (Some(8), Some(1)));
    assert!(report.get("truncated").is_none(), "{report}");
    client.cancel().await.unwrap();
}

/// Haiku v4: `enable_tools` with `firmware` failed with only the group list, and import_svd given the .svd file as
/// `path` with nothing open failed on the missing `svd`.
#[tokio::test]
async fn guessed_groups_and_an_svd_path_get_a_way_forward() {
    let client = connect().await;
    let (text, failed) = call(&client, "enable_tools", json!({ "groups": ["firmware"] })).await;
    assert!(failed && text.contains("groups: core") && text.contains("import_svd"), "{text}");
    assert!(text.contains("formats") && text.contains("diff_firmware"), "{text}");
    let listing = ok(&client, "enable_tools", json!({ "groups": ["svd"] })).await;
    assert_eq!(listing["newly_enabled"], json!(["types"]), "{listing}");

    let svd = fixtures().join("svd/ARM_Example.svd");
    let (text, failed) = call(&client, "import_svd", json!({ "path": svd })).await;
    assert!(failed && text.contains("no binary is open") && text.contains("svd=`"), "{text}");
    assert!(Path::new(&svd).exists());
    client.cancel().await.unwrap();
}

/// Only a successful project-tool call records a target, results say which target filled them in, and `raw: null`
/// asks for the native image instead.
#[tokio::test]
async fn only_successful_project_calls_record_targets_and_results_name_the_one_used() {
    let client = connect().await;
    let path = fixtures().join("firmware/raw-cortex-m-svd.bin");
    // A call that fails records nothing, and nor does a file tool.
    let refused = json!({ "profile": "cortex-m", "base_address": "0x8000000", "entry": "0x1" });
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": refused })).await;
    assert!(failed, "{text}");
    ok(&client, "file_layout", json!({ "path": path })).await;
    let (text, failed) = call(&client, "binary_info", json!({})).await;
    assert!(failed && text.contains("no binary is open"), "{text}");

    let selector = json!({ "profile": "cortex-m", "base_address": "0x8000000", "vector_table": true });
    let explicit = ok(&client, "list_functions", json!({ "path": path, "raw": selector })).await;
    assert!(explicit.get("session_target").is_none(), "{explicit}");
    let defaulted = ok(&client, "list_functions", json!({})).await;
    let named = defaulted["session_target"].as_str().unwrap();
    assert!(named.contains("raw-cortex-m-svd.bin with raw="), "{named}");
    // The path alone fails to open natively, so it reuses the target's selector and says so.
    let reused = ok(&client, "list_functions", json!({ "path": path })).await;
    assert_eq!(reused["session_target"], named, "{reused}");
    // A result that is not a JSON object names the target in a second content block.
    let (blocks, failed) = call_blocks(&client, "disassemble", json!({ "count": 2 })).await;
    assert!(!failed && blocks.len() == 2 && blocks[1].starts_with("session_target: "), "{blocks:?}");
    // `raw: null` is the native image: no selector is reused, with or without the path.
    for arguments in [json!({ "raw": null }), json!({ "path": path, "raw": null })] {
        let (text, failed) = call(&client, "binary_info", arguments).await;
        assert!(failed && text.contains("Unknown file magic"), "{text}");
    }
    client.cancel().await.unwrap();
}

/// A file a native loader opens stays native when named by path, even after a Raw slice of it was opened.
#[tokio::test]
async fn an_explicit_path_that_opens_natively_never_reuses_a_raw_selector() {
    let client = connect().await;
    let elf = fixtures().join("firmware/cortex-m3.elf");
    let slice = json!({ "profile": "cortex-m", "offset": 0, "length": 64, "base_address": "0x0" });
    let raw = ok(&client, "binary_info", json!({ "path": elf, "raw": slice })).await;
    assert_eq!(raw["format"], "raw", "{raw}");
    let native = ok(&client, "binary_info", json!({ "path": elf })).await;
    assert_eq!(native["format"], "elf", "{native}");
    assert!(native.get("session_target").is_none(), "{native}");
    client.cancel().await.unwrap();
}

/// A HEX file opened by path is recorded with the selector it was read with: inspect_data reads its records with
/// or without the path, and byte-level file tools do not default to its text.
#[tokio::test]
async fn a_hex_target_opened_by_path_serves_inspect_data_but_not_byte_level_file_tools() {
    let client = connect().await;
    let scratch = Scratch::new();
    let path = scratch.copy("firmware/raw-cortex-m-crc.hex", "fixture.hex");
    let triage = ok(&client, "triage_report", json!({ "path": path })).await;
    assert_eq!(triage["target"]["format"], "raw", "{triage}");
    let data = ok(&client, "inspect_data", json!({ "at": "0x8000000", "size": 8 })).await;
    assert_eq!(data["spans"][0]["status"], "stored", "{data}");
    assert!(data["session_target"].as_str().unwrap().contains("\"format\":\"ihex\""), "{data}");
    let data = ok(&client, "inspect_data", json!({ "path": path, "at": "0x8000000", "size": 8 })).await;
    assert_eq!(data["spans"][0]["status"], "stored", "{data}");
    let (text, failed) = call(&client, "file_layout", json!({})).await;
    assert!(failed && text.contains("record text"), "{text}");
    client.cancel().await.unwrap();
}
