//! Raw Projects over MCP: the optional `raw` selector on raw-capable tools opens an explicit file range as a
//! headerless code project, with memory-only annotations kept per interpretation.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::tools::raw_capable;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh")
}

fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A canonical temporary directory holding a copy of the MSP430 fixture, removed on drop.
struct FixtureCopy(PathBuf);

impl FixtureCopy {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rampage-mcp-raw-project-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(fixtures().join("msp430.bin"), directory.join("msp430.bin")).unwrap();
        Self(directory)
    }

    fn file(&self) -> PathBuf {
        self.0.join("msp430.bin")
    }
}

impl Drop for FixtureCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn connect() -> RunningService<RoleClient, Client> {
    let (server, transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(transport).await.unwrap()
}

fn raw(seeds: &[&str]) -> Value {
    let length = std::fs::metadata(fixtures().join("msp430.bin")).unwrap().len();
    json!({
        "profile": "TI_MSP430:LE:16:default",
        "offset": 0,
        "length": length,
        "base_address": "0x4400",
        "entry": "0x4400",
        "seeds": seeds,
    })
}

/// Calls `tool` and returns its text and whether it failed, checking every response stays within the budget.
async fn call(client: &RunningService<RoleClient, Client>, tool: &str, arguments: Value) -> (String, bool) {
    let arguments = arguments.as_object().unwrap().clone();
    let result: CallToolResult =
        client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    assert!(text.len() <= 60_000, "{tool}: {} bytes", text.len());
    (text, result.is_error == Some(true))
}

/// Benchmark v2 firmware runs: 20 of rampage's 41 errors came from a headerless Cortex-M3 image. binary_info
/// refused it without saying how to read it, and `raw` rejected `cortex-m3`, `thumb` and `ARM:LE:32:Cortex`
/// without naming the right tool or profile. Those names now select the Cortex-M profile; A-profile ARM and
/// AArch64 still point at inspect_raw_code.
#[tokio::test]
async fn headerless_files_and_unknown_profiles_say_what_to_use_instead() {
    let fixture = FixtureCopy::new();
    let client = connect().await;
    let path = fixture.file().to_string_lossy().into_owned();
    let (text, failed) = call(&client, "binary_info", json!({ "path": path })).await;
    assert!(failed && text.contains("Unknown file magic"), "{text}");
    assert!(text.contains("inspect_raw_code") && text.contains("\"profile\":\"msp430\""), "{text}");
    // Acceptance pass: an agent asked what changed between two ESP32 flash dumps called diff_builds, whose error did
    // not name diff_firmware, and never found it.
    let (text, failed) = call(&client, "diff_builds", json!({ "path": path, "other": path })).await;
    assert!(failed && text.contains("Unknown file magic") && text.contains("use diff_firmware"), "{text}");
    // Seventh Haiku run: `triage` answers such a file at container level instead of with the error.
    for tool in ["triage", "triage_report"] {
        let (text, failed) = call(&client, tool, json!({ "path": path })).await;
        assert!(!failed && text.contains("\"parsed_as_executable\":false"), "{tool}: {text}");
        assert!(text.contains("Unknown file magic") && text.contains("largest_occupied_regions"), "{tool}: {text}");
    }

    let mut selector = raw(&[]);
    for profile in ["cortex-m3", "thumb", "ARM:LE:32:Cortex", "armv7m", "cortex-m0+", "armv6m"] {
        selector["profile"] = json!(profile);
        let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": selector })).await;
        assert!(!failed && text.contains("\"profile\":\"ARM:LE:32:Cortex\""), "{profile}: {text}");
    }
    for profile in ["arm", "armv7a", "cortex-a53", "aarch64"] {
        selector["profile"] = json!(profile);
        let (text, failed) = call(&client, "disassemble", json!({ "path": path, "raw": selector })).await;
        assert!(failed && text.contains("with inspect_raw_code"), "{text}");
        assert!(text.contains("\"mode\":\"thumb\"") && text.contains("cortex-m"), "{text}");
    }
    selector["profile"] = json!("msp431");
    let (text, failed) = call(&client, "disassemble", json!({ "path": path, "raw": selector })).await;
    assert!(failed && text.contains("closest: TI_MSP430:LE:16:default"), "{text}");
    // Aliases and any letter case select the reviewed profile.
    for profile in ["msp430", "MSP430", "ti_msp430:le:16:default"] {
        selector["profile"] = json!(profile);
        let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": selector })).await;
        assert!(!failed, "{profile}: {text}");
        assert!(text.contains("\"arch\":\"msp430\""), "{text}");
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn raw_selector_is_offered_only_on_raw_capable_tools() {
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    for tool in &tools {
        let properties = tool.input_schema.get("properties").and_then(Value::as_object);
        let selector = properties.and_then(|properties| properties.get("raw"));
        assert_eq!(selector.is_some(), raw_capable(&tool.name), "{}", tool.name);
        if let Some(selector) = selector {
            assert_eq!(selector["additionalProperties"], false);
            assert_eq!(selector["properties"]["profile"]["type"], "string");
            // Repeated on every raw-capable tool, so it stays compact; the instructions describe it (and each
            // region's shape) once.
            let text = selector.to_string();
            assert!(!text.contains("$ref") && text.len() < 778, "{} bytes: {text}", text.len());
            let required = tool.input_schema.get("required").and_then(Value::as_array).cloned().unwrap_or_default();
            assert!(!required.contains(&json!("raw")) && !required.contains(&json!("path")));
        }
    }
    assert!(tools.iter().any(|tool| tool.name == "list_functions"));
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap();
    for profile in rampage_loaders::RawProfile::ALL {
        assert!(instructions.contains(profile.language_id()), "{}", profile.language_id());
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn raw_projects_list_disassemble_annotate_and_refuse_explicitly() {
    let fixture_names = names(&fixtures());
    let copy = FixtureCopy::new();
    let path = copy.file();
    let client = connect().await;
    let seeded = raw(&["0x4400", "0x4410"]);

    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": seeded })).await;
    assert!(!failed, "{text}");
    let listing: Value = serde_json::from_str(&text).unwrap();
    assert!(text.contains("0x4400") && text.contains("0x4410"), "{listing}");

    let (text, failed) =
        call(&client, "disassemble", json!({ "path": path, "raw": seeded, "at": "0x4400", "count": 4 })).await;
    assert!(!failed, "{text}");
    serde_json::from_str::<Value>(&text).unwrap();
    assert!(text.contains("0x4400"), "{text}");

    // Raw code has no typed operands, so immediate search refuses instead of guessing from display text.
    let immediate = json!({ "kind": "immediate", "immediate": { "value": { "kind": "unsigned", "value": 0 } } });
    let (text, failed) = call(&client, "search", json!({ "path": path, "raw": seeded, "mode": immediate })).await;
    assert!(failed, "immediate search must refuse on Raw: {text}");
    assert!(text.contains("no typed operand evidence; immediate search is unsupported"), "{text}");

    let (text, failed) =
        call(&client, "set_comment", json!({ "path": path, "raw": seeded, "at": "0x4400", "text": "reset" })).await;
    assert!(!failed, "{text}");
    // The same interpretation (seeds are a set) keeps its memory-only comment across calls.
    let reordered = raw(&["0x4410", "0x4400"]);
    let (text, failed) = call(&client, "list_annotations", json!({ "path": path, "raw": reordered })).await;
    assert!(!failed && text.contains("reset"), "{text}");
    // Different seeds are a different interpretation: a fresh project without the comment.
    let (text, failed) = call(&client, "list_annotations", json!({ "path": path, "raw": raw(&["0x4400"]) })).await;
    assert!(!failed && !text.contains("reset"), "{text}");

    // MSP430 has a reviewed C model: Raw decompilation returns C that calls the seeded callee.
    let (text, failed) = call(&client, "decompile", json!({ "path": path, "raw": seeded, "at": "0x4400" })).await;
    assert!(!failed, "{text}");
    serde_json::from_str::<Value>(&text).unwrap();
    assert!(text.contains("sub_4410()"), "{text}");

    // 6502 is discovery-only: decompilation refuses explicitly instead of guessing a C model.
    let mos6502 = fixtures().join("6502.bin");
    let raw6502 = json!({
        "profile": "6502:LE:16:default",
        "offset": 0,
        "length": std::fs::metadata(&mos6502).unwrap().len(),
        "base_address": "0x8000",
        "entry": "0x8000",
        "seeds": ["0x8000", "0x8010"],
    });
    let (text, failed) = call(&client, "decompile", json!({ "path": mos6502, "raw": raw6502, "at": "0x8000" })).await;
    assert!(failed && text.contains("no reviewed C model for 6502:LE:16:default"), "{text}");

    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": seeded, "arch": "x86" })).await;
    assert!(failed && text.contains("`raw` cannot be combined with `arch`"), "{text}");
    let (text, failed) =
        call(&client, "list_functions", json!({ "path": path, "raw": seeded, "image_offset": 0 })).await;
    assert!(failed && text.contains("`image_offset`"), "{text}");
    let (text, failed) =
        call(&client, "list_functions", json!({ "path": path, "raw": seeded, "image_length": "0x10" })).await;
    assert!(failed && text.contains("`image_length`"), "{text}");

    let (text, failed) = call(&client, "triage", json!({ "path": path, "raw": seeded })).await;
    assert!(!failed && text.contains("Raw project (TI_MSP430"), "{text}");
    // find_main models Cortex-M, MIPS and ESP-IDF startup only; on MSP430 it answers with a limitation and no
    // candidate.
    let (text, failed) = call(&client, "find_main", json!({ "path": path, "raw": seeded })).await;
    assert!(!failed && text.contains("model Cortex-M, MIPS and ESP-IDF startup only"), "{text}");
    let (text, failed) = call(&client, "inspect_sleigh", json!({ "path": path, "raw": seeded })).await;
    assert!(failed && text.contains("tool inspect_sleigh does not accept Raw projects"), "{text}");

    let mut unknown = seeded.clone();
    unknown["arch"] = json!("x86");
    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": unknown })).await;
    assert!(failed && text.contains("`raw`") && text.contains("unknown field"), "{text}");
    let mut profile = seeded.clone();
    profile["profile"] = json!("x86:LE:64:default");
    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": profile })).await;
    assert!(failed && text.contains("closed Raw language"), "{text}");

    assert_eq!(names(&copy.0), ["msp430.bin"], "Raw projects write no sidecars or logs");
    assert_eq!(names(&fixtures()), fixture_names, "the fixture directory is untouched");
    client.cancel().await.unwrap();
}

fn cortex_m_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware/raw-cortex-m.bin")
}

/// Haiku suite v4 (1.9.0): 41 tool errors, most of them the `raw` selector. Omitted offset and length now read the
/// whole file, `format` "bin"/"raw" mean binary, decorated Cortex-M spellings select the profile, and a selector sent
/// as a JSON string is parsed once: each opens the same project as the explicit form.
#[tokio::test]
async fn raw_defaults_spellings_and_a_stringified_selector_open_the_explicit_project() {
    let client = connect().await;
    let path = cortex_m_fixture();
    let length = std::fs::metadata(&path).unwrap().len();
    let explicit = json!({
        "profile": "ARM:LE:32:Cortex", "format": "binary", "offset": 0, "length": length, "base_address": "0x8000000",
        "vector_table": true,
    });
    let (expected, failed) = call(&client, "binary_info", json!({ "path": path, "raw": explicit })).await;
    assert!(!failed, "{expected}");
    let short = json!({ "profile": "cortex-m4", "base_address": "0x8000000", "vector_table": true });
    let spelled = json!({ "profile": "arm-thumb-cortex-m", "format": "bin", "base_address": "0x8000000",
                          "vector_table": true });
    let raw_format = json!({ "profile": "arm_cortex_m4_thumb", "format": "RAW", "offset": 0,
                             "base_address": "0x8000000", "vector_table": true });
    for selector in [short.clone(), spelled, raw_format, Value::String(short.to_string())] {
        let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": selector })).await;
        assert!(!failed, "{selector}: {text}");
        assert_eq!(text, expected, "{selector}");
    }
    // A file tool reads the stringified selector too.
    let stringified = Value::String(short.to_string());
    let (text, failed) =
        call(&client, "inspect_data", json!({ "path": path, "raw": stringified, "at": "0x8000000", "size": 8 })).await;
    assert!(!failed && text.contains("0x20005000"), "{text}");
    // A string that is not exactly one object is refused, not guessed at.
    for bad in ["cortex-m4", "[1]", "{\"profile\":\"cortex-m4\"} trailing"] {
        let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": bad })).await;
        assert!(failed && text.contains("`raw` must be a JSON object"), "{bad}: {text}");
    }
    // base_address is never guessed.
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": { "profile": "cortex-m" } })).await;
    assert!(failed && text.contains("needs base_address"), "{text}");
    client.cancel().await.unwrap();
}

/// Suite v4: "file range is outside the regular source" (12 times) said neither the file's size nor the range.
#[tokio::test]
async fn a_range_past_the_end_names_the_file_size_the_range_and_the_fix() {
    let client = connect().await;
    let path = cortex_m_fixture();
    let size = std::fs::metadata(&path).unwrap().len();
    let selector = json!({ "profile": "cortex-m4", "offset": 0, "length": 0x10_0000, "base_address": 0 });
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": selector })).await;
    assert!(failed, "{text}");
    assert!(text.contains("0x0..0x100000 (offset 0, length 1048576)"), "{text}");
    assert!(text.contains(&format!("holds {size} bytes ({size:#x})")), "{text}");
    assert!(text.contains(&format!("the length can be at most {size}")) && text.contains("omit length"), "{text}");
    let past = json!({ "profile": "cortex-m4", "offset": size, "base_address": 0 });
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": past })).await;
    assert!(failed && text.contains(&format!("offset must be below {size}")), "{text}");
    client.cancel().await.unwrap();
}

/// One `raw` selector with path, profile alias and base address opens a headerless Cortex-M image: the vector
/// table seeds the entry and handlers, and listing, cross-references and decompilation answer from there.
#[tokio::test]
async fn a_cortex_m_image_opens_with_its_vector_table_in_one_call() {
    let client = connect().await;
    let path = cortex_m_fixture();
    let length = std::fs::metadata(&path).unwrap().len();
    let selector = json!({
        "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    });
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": selector })).await;
    assert!(!failed, "{text}");
    let info: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(info["entry"], "0x8000240");
    let table = &info["raw"]["vector_table"];
    assert_eq!(table["vectors"][0]["name"], "initial_sp");
    assert_eq!(table["vectors"][0]["word"], "0x20005000");
    assert_eq!(table["vectors"][1]["target"], "0x8000240");
    assert_eq!(table["vectors"][7]["status"], "empty");

    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": selector })).await;
    assert!(!failed, "{text}");
    for start in ["0x8000060", "0x800008c", "0x80000b0", "0x8000150", "0x80001a0", "0x800020c", "0x800022c"] {
        assert!(text.contains(start), "{start}: {text}");
    }
    let (text, failed) = call(&client, "xrefs", json!({ "path": path, "raw": selector, "to": "0x800008c" })).await;
    assert!(!failed && text.contains("\"kind\":\"call\""), "{text}");
    let (text, failed) = call(&client, "decompile", json!({ "path": path, "raw": selector, "at": "0x80001a0" })).await;
    assert!(!failed && text.contains("sub_800008c("), "{text}");
    // inspect_data reads the Raw image's words at their mapped addresses: the vector table's initial SP.
    let (text, failed) =
        call(&client, "inspect_data", json!({ "path": path, "raw": selector, "at": "0x8000000", "size": 8 })).await;
    assert!(!failed && text.contains("0x20005000"), "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["spans"][0]["file_offset"], 0, "{report}");
    // A range further into the file maps its bytes to their own file offsets, not to the project's buffer.
    let prefixed = std::env::temp_dir().join(format!("rampage-mcp-raw-prefixed-{}.bin", std::process::id()));
    let mut bytes = vec![0xa5; 0x40];
    bytes.extend(std::fs::read(&path).unwrap());
    std::fs::write(&prefixed, &bytes).unwrap();
    let mut shifted = selector.clone();
    shifted["offset"] = json!("0x40");
    let (text, failed) =
        call(&client, "inspect_data", json!({ "path": prefixed, "raw": shifted, "at": "0x8000004", "size": 4 })).await;
    let _ = std::fs::remove_file(&prefixed);
    assert!(!failed, "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["spans"][0]["file_offset"], 0x44, "{report}");
    assert!(report["selected_image_file_offset"].is_null(), "{report}");
    let (text, failed) =
        call(&client, "inspect_data", json!({ "path": path, "raw": selector, "at": "0x8000000", "image_offset": 0 }))
            .await;
    assert!(failed && text.contains("cannot be combined"), "{text}");
    let (text, failed) = call(&client, "list_strings", json!({ "path": path, "raw": selector })).await;
    assert!(!failed, "{text}");

    // A wrong base reads the same words but seeds nothing, and only suggests a base.
    let mut wrong = selector.clone();
    wrong["base_address"] = json!(0);
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": wrong })).await;
    assert!(!failed, "{text}");
    let info: Value = serde_json::from_str(&text).unwrap();
    assert!(info["entry"].is_null(), "{text}");
    assert_eq!(info["raw"]["vector_table"]["base_address_suggestion"]["base_address"], "0x8000000");
    assert_eq!(info["raw"]["vector_table"]["vectors"][1]["refused_reason"], "outside_image");

    // The length bound holds at the MCP layer: 4 MiB for this profile.
    let mut long = selector.clone();
    long["length"] = json!(4 * 1024 * 1024 + 1);
    let (text, failed) = call(&client, "binary_info", json!({ "path": path, "raw": long })).await;
    assert!(failed && text.contains("1..=4194304 bytes for ARM:LE:32:Cortex"), "{text}");
    assert_eq!(info["segments"][0]["address"], "0x0");
    client.cancel().await.unwrap();
}

/// Identifies a committed embedded-libs flash image (owned FreeRTOS firmware built with a toolchain the embedded set
/// was not built from) as a Cortex-M Raw project, applying the names, and checks every name against the libid truth
/// of its symbolized build. Returns how many the embedded signatures and the call graph named; the doc's Raw rows
/// are these counts.
async fn identify_embedded_raw_image(fixture: &str, profile: &str, names: &[&str]) -> (usize, usize) {
    let client = connect().await;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let path = root.join(format!("firmware/embedded-libs-{fixture}.bin"));
    let truth = std::fs::read_to_string(root.join(format!("data/eval-truth-embedded-{fixture}.json"))).unwrap();
    let truth: Value = serde_json::from_str(&truth).unwrap();
    let length = std::fs::metadata(&path).unwrap().len();
    let selector = json!({
        "profile": profile, "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    });
    let (text, failed) = call(&client, "enable_tools", json!({ "groups": ["detection"] })).await;
    assert!(!failed, "{text}");
    let arguments = json!({ "path": path, "raw": selector, "apply": true, "limit": 256 });
    let (text, failed) = call(&client, "identify_functions", arguments).await;
    assert!(!failed, "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    let matches = result["matches"].as_array().unwrap();
    assert_eq!(result["matched"].as_u64(), Some(matches.len() as u64), "one page holds every match");
    for found in matches {
        let address = found["address"].as_str().unwrap();
        assert_eq!(found["name"], truth[address], "{address}: every name is the library function there");
        let source = found["source"].as_str().unwrap();
        assert!(source == "rampage-builtin embedded" || source == "rampage-builtin call graph", "{address}: {source}");
    }
    for name in names {
        assert!(matches.iter().any(|found| found["name"] == *name), "{name}: {text}");
    }
    let (text, failed) = call(&client, "list_functions", json!({ "path": path, "raw": selector })).await;
    assert!(!failed && text.contains(names[0]), "{text}");
    client.cancel().await.unwrap();
    let count = |source: &str| matches.iter().filter(|found| found["source"] == source).count();
    (count("rampage-builtin embedded"), count("rampage-builtin call graph"))
}

/// The bundled embedded firmware set names library functions of a headerless Cortex-M4F image (FreeRTOS, the
/// STM32F4 HAL, newlib-nano, libm and libgcc), and applying them renames the Raw project's functions for later calls
/// with the same selector.
#[tokio::test]
async fn identify_functions_names_library_code_in_a_cortex_m4f_raw_image() {
    let names = ["HAL_RCC_OscConfig", "xQueueCreateMutex", "memcpy", "__aeabi_i2d", "_malloc_r"];
    assert_eq!(identify_embedded_raw_image("m4f", "cortex-m4", &names).await, EMBEDDED_M4F_RAW);
}

/// The same for the Cortex-M0 image (FreeRTOS's ARMv6-M port at -O1, full newlib, soft float).
#[tokio::test]
async fn identify_functions_names_library_code_in_a_cortex_m0_raw_image() {
    let names = ["vListInsertEnd", "strlen", "__aeabi_i2d", "PendSV_Handler"];
    assert_eq!(identify_embedded_raw_image("m0", "cortex-m0", &names).await, EMBEDDED_M0_RAW);
}

/// Correct names the Raw rows of docs/signature-corpus.md report, from the embedded signatures and from the call
/// graph (no wrong or spurious name is allowed above).
const EMBEDDED_M4F_RAW: (usize, usize) = (81, 14);
const EMBEDDED_M0_RAW: (usize, usize) = (71, 32);

/// A CMSIS-SVD map imported once over MCP names a Cortex-M Raw project's registers in later calls with the same
/// `raw` selector: decompiled C, xrefs by peripheral name and the per-register access listing.
#[tokio::test]
async fn an_svd_map_names_registers_across_tools() {
    let client = connect().await;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let path = root.join("firmware/raw-cortex-m-svd.bin");
    let svd = root.join("svd/ARM_Example.svd");
    let length = std::fs::metadata(&path).unwrap().len();
    let selector = json!({
        "profile": "cortex-m", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    });
    let (text, failed) = call(&client, "enable_tools", json!({ "groups": ["types"] })).await;
    assert!(!failed, "{text}");
    let (text, failed) = call(&client, "import_svd", json!({ "path": path, "raw": selector, "svd": svd })).await;
    assert!(!failed && text.contains("\"applied\":false") && text.contains("\"added\":3"), "{text}");
    let (text, failed) =
        call(&client, "import_svd", json!({ "path": path, "raw": selector, "svd": svd, "apply": true })).await;
    assert!(!failed && text.contains("\"applied\":true"), "{text}");
    let (text, failed) = call(&client, "decompile", json!({ "path": path, "raw": selector, "at": "0x8000040" })).await;
    assert!(!failed && text.contains("TIMER0.CR = uVar1 | 0x21; /* CR: EN|MODE=Single_MATCH */"), "{text}");
    let (text, failed) = call(&client, "xrefs", json!({ "path": path, "raw": selector, "to": "TIMER1" })).await;
    assert!(!failed && text.contains("\"to_name\":\"TIMER1.COUNT\"") && text.contains("\"access\":\"read\""), "{text}");
    let (text, failed) =
        call(&client, "peripheral_access", json!({ "path": path, "raw": selector, "peripheral": "TIMER0" })).await;
    assert!(!failed && text.contains("\"name\":\"RELOAD[2]\""), "{text}");
    client.cancel().await.unwrap();
}

/// The firmware patching round trip over MCP on Intel HEX: find the application CRC, patch, fix, export the HEX and
/// reopen it with the check valid and the patch present.
#[tokio::test]
async fn a_patched_hex_image_is_fixed_and_exported_in_its_container() {
    let client = connect().await;
    let directory = FixtureCopy::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware");
    let path = directory.0.join("firmware.hex");
    std::fs::copy(root.join("raw-cortex-m-crc.hex"), &path).unwrap();
    let selector = json!({ "profile": "cortex-m3", "format": "ihex", "vector_table": true });
    let (text, failed) = call(&client, "enable_tools", json!({ "groups": ["formats"] })).await;
    assert!(!failed, "{text}");
    let (text, failed) = call(&client, "integrity_checks", json!({ "path": path, "raw": selector })).await;
    assert!(!failed, "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["checks"][0]["algorithm"], "crc32", "{text}");
    assert_eq!(report["checks"][0]["confirmed_by_emulation"], true, "{text}");
    let receipt = &report["receipt"];
    let patch = json!({
        "path": path, "raw": selector, "at": "0x8000434", "original_hex": "11", "replacement_hex": "42",
        "allow_data": false, "source_sha256": receipt["source_sha256"], "expected_revision": receipt["revision_sha256"],
    });
    let (text, failed) = call(&client, "patch_bytes", patch).await;
    assert!(!failed, "{text}");
    let patched: Value = serde_json::from_str(&text).unwrap();
    let fix = json!({
        "path": path, "raw": selector, "fix": true, "emulate": false,
        "source_sha256": receipt["source_sha256"], "expected_revision": patched["receipt"]["revision_sha256"],
    });
    let (text, failed) = call(&client, "integrity_checks", fix).await;
    assert!(!failed && text.contains("\"applied\":true"), "{text}");
    let fixed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(fixed["invalid"], 0, "{text}");
    let exported = directory.0.join("patched.hex");
    let export = json!({
        "path": path, "raw": selector, "destination": exported,
        "expected_revision": fixed["receipt"]["revision_sha256"],
    });
    let (text, failed) = call(&client, "export_image", export).await;
    assert!(!failed && text.contains("\"records_rewritten\":2"), "{text}");
    let (text, failed) = call(&client, "integrity_checks", json!({ "path": exported, "raw": selector })).await;
    assert!(!failed, "{text}");
    let reopened: Value = serde_json::from_str(&text).unwrap();
    assert_eq!((reopened["checks"][0]["valid"].as_bool(), reopened["invalid"].as_u64()), (Some(true), Some(0)));
    client.cancel().await.unwrap();
}

/// lock_mechanisms over MCP on the owned lock-mechanism firmware: after import_svd names its registers, the
/// signature check, the unique-ID binding, the rollback counter and the challenge-response unlock are explained,
/// each at its decision site.
#[tokio::test]
async fn lock_mechanisms_explain_a_cortex_m_raw_image_with_its_svd() {
    let client = connect().await;
    let directory = FixtureCopy::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let path = directory.0.join("firmware.bin");
    std::fs::copy(root.join("firmware/raw-cortex-m-locks.bin"), &path).unwrap();
    let length = std::fs::metadata(&path).unwrap().len();
    let selector = json!({
        "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    });
    let (text, failed) = call(&client, "enable_tools", json!({ "groups": ["detection", "types"] })).await;
    assert!(!failed, "{text}");
    let svd = root.join("svd/lock-device.svd");
    let import = json!({ "path": path, "raw": selector, "svd": svd, "apply": true });
    let (text, failed) = call(&client, "import_svd", import).await;
    assert!(!failed, "{text}");
    let (text, failed) = call(&client, "lock_mechanisms", json!({ "path": path, "raw": selector })).await;
    assert!(!failed, "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    let mechanisms = report["mechanisms"].as_array().unwrap();
    for category in ["signature_verification", "device_binding", "anti_rollback", "challenge_response"] {
        let found = mechanisms.iter().find(|row| row["category"] == category);
        assert!(found.is_some_and(|row| row["decision"]["at"].is_string()), "{category}: {text}");
    }
    let unknown = json!({ "path": path, "raw": selector, "category": "anything" });
    let (text, failed) = call(&client, "lock_mechanisms", unknown).await;
    assert!(failed && text.contains("signature_verification"), "{text}");
    client.cancel().await.unwrap();
}
