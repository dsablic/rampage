//! The MCP stable surface (docs/stability.md) pinned against snapshots in `tests/contract/`:
//! - `mcp-tools.json`: every tool's name, group and arguments (type and whether required), as `tools/list` gives
//!   them on a server with every group, a debug server with the write and kill flags, and a corpus server;
//! - `mcp-results-<group>.json`: the result field paths each tool of every stable group returns on committed
//!   fixtures (`query_debugger` against a scripted bridge socket, `debug` against the fake stub).
//!
//! `tests/contract/support.rs` classifies each difference as additive or breaking and says how to update.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rampage_api::tools::Group;
use rampage_api::{DebugConsent, DebugRegistry};
use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

use crate::contract_support as contract;

type Client = RunningService<RoleClient, ()>;

async fn connect(server: RampageServer) -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

async fn call(client: &Client, tool: &str, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().and_then(|content| content.as_text()).map(|text| text.text.as_str()).unwrap()
}

fn json_of(tool: &str, result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{tool}: {}", text(result));
    serde_json::from_str(text(result)).unwrap_or_else(|error| panic!("{tool}: {error}: {}", text(result)))
}

/// Every tool `client` lists once all its groups are enabled, with its group and argument summary.
async fn listed_tools(client: Client, tools: &mut BTreeMap<String, Value>) {
    let listing = json_of("enable_tools", &call(&client, "enable_tools", json!({ "groups": ["all"] })).await);
    let mut groups = BTreeMap::new();
    for group in listing["groups"].as_array().unwrap() {
        for tool in group["tools"].as_array().unwrap() {
            groups.insert(tool.as_str().unwrap().to_owned(), group["name"].as_str().unwrap().to_owned());
        }
    }
    for tool in client.list_all_tools().await.unwrap() {
        let name = tool.name.into_owned();
        let group = groups.get(&name).cloned().unwrap_or_else(|| "meta".to_owned());
        let schema = Value::Object((*tool.input_schema).clone());
        let mut entry = json!({ "group": group, "arguments": contract::arguments(&schema) });
        if group == Group::Improve.name() {
            entry["experimental"] = json!(true);
        }
        tools.entry(name).or_insert(entry);
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn contract_mcp_tool_schemas() {
    let mut tools = BTreeMap::new();
    listed_tools(connect(RampageServer::with_groups(Group::ALL)).await, &mut tools).await;
    // Nothing connects: listing needs no stub. Both flags list the write tools and the kill option.
    let registry = DebugRegistry::new(&["127.0.0.1:1".to_owned()])
        .unwrap()
        .with_consent(DebugConsent { writes: true, kill: true });
    listed_tools(connect(RampageServer::default().with_debug(registry)).await, &mut tools).await;
    let synthetic = crate::flywheel::synthetic("contract");
    let improve = crate::flywheel::improve(&synthetic, None);
    listed_tools(connect(RampageServer::default().with_improve(improve)).await, &mut tools).await;
    contract::check("mcp-tools.json", &json!({ "tools": tools }), contract::compare_tools);
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// Records the field paths of `result` under `owner`.
fn observe(observed: &mut BTreeMap<String, BTreeSet<String>>, owner: &str, result: &Value) {
    observed.entry(owner.to_owned()).or_default().extend(contract::field_paths(result));
}

/// A fresh directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rampage-mcp-contract-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Observed = BTreeMap<String, BTreeSet<String>>;

/// Calls `tool`, which must succeed, and records its result's field paths.
async fn exercise(client: &Client, observed: &mut Observed, tool: &str, arguments: Value) -> Value {
    let result = json_of(tool, &call(client, tool, arguments).await);
    observe(observed, tool, &result);
    result
}

/// The core tools, as served.
fn core_tools() -> BTreeSet<String> {
    let tools = rampage_api::tools::tools();
    let analysis = tools.iter().filter(|tool| tool.group == Group::Core && !tool.interactive).map(|tool| tool.name);
    let files = rampage_api::tools::file_tools();
    let files = files.iter().filter(|tool| tool.group == Group::Core).map(|tool| tool.name);
    analysis.chain(files).map(str::to_owned).collect()
}

/// The result fields of every core tool and of `enable_tools`, each run on committed fixtures. A core tool that is
/// not exercised here fails the test, so a new one gets a result contract before it ships.
#[tokio::test]
async fn contract_mcp_core_results() {
    let scratch = Scratch::new("core");
    let elf = scratch.0.join("hello-x64.elf");
    std::fs::copy(fixture("hello-x64.elf"), &elf).unwrap();
    let pe = fixture("hello-x64.exe");
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);

    exercise(c, o, "enable_tools", json!({})).await;
    exercise(c, o, "binary_info", json!({"path": elf})).await;
    exercise(c, o, "triage", json!({"path": elf})).await;
    exercise(c, o, "triage_report", json!({"path": elf})).await;
    exercise(c, o, "list_functions", json!({"path": elf, "limit": 3})).await;
    exercise(c, o, "list_imports", json!({"path": pe, "limit": 3})).await;
    exercise(c, o, "list_exports", json!({"path": fixture("hello-x64.dylib"), "limit": 3})).await;
    exercise(c, o, "list_strings", json!({"path": elf, "limit": 3})).await;
    exercise(c, o, "decompile", json!({"path": elf, "at": "main"})).await;
    exercise(c, o, "disassemble", json!({"path": elf, "at": "main", "count": 4})).await;
    exercise(c, o, "function_graph", json!({"path": elf, "at": "main"})).await;
    exercise(c, o, "function_summary", json!({"path": elf, "at": "main"})).await;
    exercise(c, o, "xrefs", json!({"path": elf, "from": "main"})).await;
    exercise(c, o, "inspect_data", json!({"path": elf, "at": "main", "size": 16})).await;
    exercise(c, o, "language_metadata", json!({"path": fixture("classes-arm64.macho")})).await;
    exercise(c, o, "class_evidence", json!({"path": fixture("classes-arm64.macho")})).await;
    let mode = json!({"kind": "text", "encoding": "ascii", "pattern": "rampage"});
    exercise(c, o, "search", json!({"path": elf, "mode": mode})).await;
    exercise(c, o, "assemble", json!({"path": elf, "at": "main", "source": "mov eax,7\nret"})).await;
    // Each workflow on a fixture where it finds something, so its finding fields are observed.
    let workflows = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rampage-api/tests/fixtures");
    for (workflow, binary) in [
        ("find_main", "net-client-x64.elf"),
        ("network_surface", "net-client-x64.elf"),
        ("persistence_surface", "persist-x64.exe"),
        ("string_decoding", "decode-x64.elf"),
    ] {
        exercise(c, o, workflow, json!({"path": workflows.join(binary)})).await;
    }
    exercise(c, o, "diff_builds", json!({"path": elf, "other": fixture("hello-x64-dyn.elf")})).await;

    // Notes on the copy: names, comments, both batch tools, undo and redo, and the ledger.
    exercise(c, o, "check_names", json!({"path": elf, "names": ["compat_main", "main"]})).await;
    exercise(c, o, "rename", json!({"path": elf, "at": "main", "name": "compat_main"})).await;
    exercise(c, o, "set_comment", json!({"path": elf, "at": "compat_main", "text": "entry"})).await;
    let entries = json!([{"at": "add", "name": "compat_add", "comment": "adds"}]);
    exercise(c, o, "annotate_batch", json!({"path": elf, "entries": entries})).await;
    let entries = json!([{"operation": "comment", "at": "compat_add", "value": "adds two ints"}]);
    exercise(c, o, "batch", json!({"path": elf, "entries": entries})).await;
    exercise(c, o, "list_annotations", json!({"path": elf})).await;
    exercise(c, o, "undo", json!({"path": elf})).await;
    exercise(c, o, "redo", json!({"path": elf})).await;
    exercise(c, o, "undo", json!({"path": elf})).await;
    exercise(c, o, "discard_undo", json!({"path": elf, "force": true})).await;
    let finding = json!({"path": elf, "kind": "finding", "text": "main calls add", "address": "compat_main",
        "evidence": [{"tool": "xrefs", "detail": "add from main"}], "confidence": "high"});
    exercise(c, o, "record_finding", finding).await;
    exercise(c, o, "list_findings", json!({"path": elf})).await;

    // Patches: patch one instruction of the copy, list, export and revert it.
    let baseline = exercise(c, o, "list_patches", json!({"path": elf})).await;
    let patch = json!({"path": elf, "at": "0x100191e", "original_hex": "b805000000", "replacement_hex": "b807000000",
        "allow_data": false, "source_sha256": baseline["receipt"]["source_sha256"],
        "expected_revision": baseline["receipt"]["revision_sha256"]});
    exercise(c, o, "patch_bytes", patch).await;
    let listed = exercise(c, o, "list_patches", json!({"path": elf})).await;
    let (source, revision) = (&listed["receipt"]["source_sha256"], &listed["receipt"]["revision_sha256"]);
    let destination = scratch.0.join("patched.elf");
    let export =
        json!({"path": elf, "destination": destination, "source_sha256": source, "expected_revision": revision});
    exercise(c, o, "export_patched", export).await;
    let revert = json!({"path": elf, "at": "0x100191e", "source_sha256": source, "expected_revision": revision});
    exercise(c, o, "revert_patch", revert).await;

    // Standalone file inspectors.
    let input = scratch.0.join("input.bin");
    std::fs::write(&input, [7, b'A', b'B', b'C']).unwrap();
    let decode =
        json!({"path": input, "codec": "lzss-4k", "offset": "0x0", "length": "0x4", "expected_output_size": 3});
    exercise(c, o, "decode_file_range", decode).await;
    let raw = json!({"path": elf, "offset": "0x1910", "length": 16, "arch": "x86_64", "mode": "native",
        "code_byte_order": "little", "data_byte_order": "little", "base_address": "0x1001910"});
    exercise(c, o, "inspect_raw_code", raw).await;
    let sleigh = json!({"path": elf, "profile": "x86:LE:64:default", "offset": "0x1910", "length": 16,
        "base_address": "0x1001910"});
    exercise(c, o, "inspect_sleigh", sleigh).await;
    let firmware = scratch.0.join("firmware.bin");
    std::fs::write(&firmware, contract::layout_fixture()).unwrap();
    let layout = json!({"path": firmware, "block_size": 512, "block_limit": 2, "utf16": true});
    exercise(c, o, "file_layout", layout).await;
    client.cancel().await.unwrap();

    let missing: Vec<String> = core_tools().into_iter().filter(|name| !observed.contains_key(name)).collect();
    assert!(missing.is_empty(), "core tools without a result-field contract: {missing:?}");
    contract::check("mcp-results-core.json", &contract::field_snapshot(&observed), contract::compare_fields);
}

/// The result fields of every debug tool, write and kill included, driven against the scripted fake stub.
#[cfg(unix)]
#[tokio::test]
async fn contract_mcp_debug_results() {
    use std::os::unix::fs::DirBuilderExt;

    use rampage_debug::fake::{Action, FakeStub, le_hex, transcripts};

    let stop = |signal: &str| Action::Reply(format!("T{signal}thread:p01.01;"));
    let script = transcripts::qemu_cortex_m3()
        .execution()
        .writes()
        .kill()
        .lenient()
        .memory(0x2000_0000, &[0; 16])
        .on("vCont?", "vCont;c;C;s;S")
        .on("pf", &le_hex(0x48, 4))
        .on("Z1,80,2", "OK")
        .on("z1,80,2", "OK")
        .once("vCont;c", vec![Action::Sleep(std::time::Duration::from_millis(20)), stop("05")])
        .on_actions("vCont;c", vec![])
        .on_prefix("vCont;s", vec![stop("05")])
        .on_prefix("P", vec![Action::Reply("OK".into())])
        .on_interrupt(vec![stop("02")])
        .on("vKill;1", "OK");
    let stub = FakeStub::tcp(script);
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()])
        .unwrap()
        .with_consent(DebugConsent { writes: true, kill: true });
    let client = connect(RampageServer::with_groups([Group::Core, Group::Debug]).with_debug(registry)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    let firmware = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware/cortex-m3.elf");

    exercise(c, o, "debug_connect", json!({})).await;
    exercise(c, o, "debug_bind", json!({"session": "s1", "path": firmware, "slide": 0})).await;
    exercise(c, o, "debug_status", json!({"session": "s1"})).await;
    exercise(c, o, "debug_registers", json!({"session": "s1", "annotate": true})).await;
    exercise(c, o, "debug_read_memory", json!({"session": "s1", "address": "0x0", "length": 8})).await;
    exercise(c, o, "debug_modules", json!({"session": "s1"})).await;
    exercise(c, o, "debug_evidence", json!({"session": "s1", "epoch": 1})).await;
    let directory = Scratch::new("debug");
    std::fs::remove_dir(&directory.0).unwrap();
    std::fs::DirBuilder::new().mode(0o700).create(&directory.0).unwrap();
    let ranges = json!([{"address": "0x0", "length": 8, "permissions": "r-x"}]);
    let output = directory.0.join("capture.json");
    exercise(c, o, "debug_snapshot", json!({"session": "s1", "output": output, "ranges": ranges})).await;
    let set = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": "0x80"});
    let set = exercise(c, o, "debug_breakpoints", set).await;
    let stopped = exercise(c, o, "debug_continue", json!({"session": "s1", "epoch": 1})).await;
    let epoch = stopped["epoch"].as_u64().unwrap();
    exercise(c, o, "debug_breakpoints", json!({"session": "s1", "action": "list"})).await;
    let clear = json!({"session": "s1", "action": "clear", "epoch": epoch, "id": set["breakpoint"]["id"]});
    exercise(c, o, "debug_breakpoints", clear).await;
    let stepped = exercise(c, o, "debug_step", json!({"session": "s1", "epoch": epoch})).await;
    let epoch = stepped["epoch"].as_u64().unwrap();
    let write = json!({"session": "s1", "epoch": epoch, "address": "0x20000000", "bytes": "01020304"});
    exercise(c, o, "debug_write_memory", write).await;
    let write = json!({"session": "s1", "epoch": epoch, "name": "r0", "value": "01000000"});
    exercise(c, o, "debug_write_register", write).await;
    let running = exercise(c, o, "debug_continue", json!({"session": "s1", "epoch": epoch, "timeout_ms": 0})).await;
    assert_eq!(running["state"], "running", "{running}");
    exercise(c, o, "debug_wait", json!({"session": "s1", "timeout_ms": 50})).await;
    exercise(c, o, "debug_interrupt", json!({"session": "s1"})).await;
    exercise(c, o, "debug_disconnect", json!({"session": "s1", "kill": true})).await;
    client.cancel().await.unwrap();
    drop(tokio::task::spawn_blocking(move || stub.finish()).await.unwrap());

    let debug: BTreeSet<String> = rampage_api::tools::debug_tools_with(DebugConsent { writes: true, kill: true })
        .iter()
        .map(|tool| tool.name.to_owned())
        .collect();
    let missing: Vec<&String> = debug.iter().filter(|name| !observed.contains_key(*name)).collect();
    assert!(missing.is_empty(), "debug tools without a result-field contract: {missing:?}");
    contract::check("mcp-results-debug.json", &contract::field_snapshot(&observed), contract::compare_fields);
}

/// The tools `group` serves, from the `enable_tools` catalog.
async fn served(client: &Client, group: &str) -> BTreeSet<String> {
    let listing = json_of("enable_tools", &call(client, "enable_tools", json!({ "groups": ["all"] })).await);
    listing["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["name"] == group)
        .flat_map(|entry| entry["tools"].as_array().unwrap().iter().map(|tool| tool.as_str().unwrap().to_owned()))
        .collect()
}

/// Fails when a tool of `group` (other than `exempt`) was not exercised, so a new one gets a result contract before
/// it ships, then checks `mcp-results-{group}.json`.
async fn check_group(client: Client, group: &str, observed: &Observed, exempt: &[&str]) {
    let tools = served(&client, group).await;
    client.cancel().await.unwrap();
    assert!(!tools.is_empty(), "the {group} group serves no tools");
    let missing: Vec<&String> =
        tools.iter().filter(|name| !observed.contains_key(*name) && !exempt.contains(&name.as_str())).collect();
    assert!(missing.is_empty(), "{group} tools without a result-field contract: {missing:?}");
    let name = format!("mcp-results-{group}.json");
    contract::check(&name, &contract::field_snapshot(observed), contract::compare_fields);
}

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data").join(name)
}

/// Copies `source` into `scratch` so sidecar logs land there, not beside the committed fixture.
fn owned(scratch: &Scratch, source: &std::path::Path) -> PathBuf {
    let path = scratch.0.join(source.file_name().unwrap());
    std::fs::copy(source, &path).unwrap();
    path
}

/// The result fields of the `carve` group: a carved embedded image and a ZIP inventory.
#[tokio::test]
async fn contract_mcp_carve_results() {
    let scratch = Scratch::new("carve");
    let mut file = std::fs::read(fixture("hello-x64.elf")).unwrap();
    file.extend(b"junk".repeat(25));
    file.extend(std::fs::read(fixture("hello-arm64.macho")).unwrap());
    let firmware = scratch.0.join("firmware.bin");
    std::fs::write(&firmware, file).unwrap();
    let archive = crate::archive::Input::new(&[b"first".to_vec(), b"second".to_vec()]);
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "carve", json!({"path": firmware})).await;
    exercise(c, o, "archive_inventory", json!({"path": archive.path})).await;
    check_group(client, "carve", &observed, &[]).await;
}

/// The result fields of the `formats` group, each on a fixture that has the structure it reads.
#[tokio::test]
async fn contract_mcp_formats_results() {
    let scratch = Scratch::new("formats");
    let fixture = |name: &str| owned(&scratch, &fixture(name));
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "build_info", json!({"path": fixture("buildinfo-go-x64.elf")})).await;
    exercise(c, o, "pe_load_config", json!({"path": fixture("pe-metadata-x86.exe")})).await;
    let resources = fixture("pe-metadata-x64.exe");
    exercise(c, o, "pe_resources", json!({"path": resources})).await;
    exercise(c, o, "pe_resources", json!({"path": resources, "type": "RT_VERSION"})).await;
    exercise(c, o, "pe_resources", json!({"path": resources, "type": "24"})).await;
    exercise(c, o, "pyinstaller_archive", json!({"path": fixture("pyinstaller-312.elf"), "limit": 4})).await;
    exercise(c, o, "wasm_module", json!({"path": fixture("module.wasm")})).await;
    exercise(c, o, "wasm_module", json!({"path": fixture("module.wasm"), "list": "functions"})).await;
    exercise(c, o, "wasm_module", json!({"path": fixture("component.wasm")})).await;
    check_group(client, "formats", &observed, &[]).await;
}

/// The result fields of the `dotnet` group on a committed .NET assembly.
#[tokio::test]
async fn contract_mcp_dotnet_results() {
    let scratch = Scratch::new("dotnet");
    let assembly = owned(&scratch, &fixture("Microsoft.Bcl.HashCode.dll"));
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "dotnet_metadata", json!({"path": assembly, "limit": 2})).await;
    exercise(c, o, "dotnet_metadata", json!({"path": assembly, "list": "resources", "limit": 2})).await;
    exercise(c, o, "dotnet_metadata", json!({"path": assembly, "list": "attributes", "limit": 2})).await;
    let il = json!({"path": assembly, "method": "System.HashCode::MixFinal", "limit": 2});
    exercise(c, o, "dotnet_il", il).await;
    check_group(client, "dotnet", &observed, &[]).await;
}

/// The result fields of the `diagnostics` group.
#[tokio::test]
async fn contract_mcp_diagnostics_results() {
    let scratch = Scratch::new("diagnostics");
    let elf = owned(&scratch, &fixture("hello-x64.elf"));
    let table = owned(&scratch, &data("runtime-jumptable.snapshot.json"));
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "analysis_diagnostics", json!({"path": elf, "include_discovery": true})).await;
    exercise(c, o, "entry_diagnostics", json!({"path": elf, "limit": 3})).await;
    exercise(c, o, "inspect_jump_table", json!({"path": table, "at": "0x3000", "count": 2})).await;
    check_group(client, "diagnostics", &observed, &[]).await;
}

/// The result fields of the `detection` group, with a loaded data pack so `list_packs` reports one.
#[tokio::test]
async fn contract_mcp_detection_results() {
    let scratch = Scratch::new("detection");
    let pe = owned(&scratch, &fixture("hello-x64.exe"));
    let rules = scratch.0.join("capa");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(
        rules.join("console.yml"),
        "rule:\n  meta:\n    name: write output to console\n    namespace: host-interaction/console\n    \
         scopes:\n      static: file\n  features:\n    - or:\n      - import: puts\n      - import: printf\n",
    )
    .unwrap();
    let pack = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/packs/compat-v1");
    let packs = std::sync::Arc::new(rampage_api::Packs::lazy(std::slice::from_ref(&pack)));
    let client = connect(RampageServer::with_groups(Group::ALL).with_packs(packs)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "list_packs", json!({})).await;
    exercise(c, o, "detect_tools", json!({"path": pe})).await;
    exercise(c, o, "capabilities", json!({"path": pe})).await;
    exercise(c, o, "capa_detect", json!({"path": pe, "rules_dir": rules})).await;
    let rule = "rule user_mz { strings: $mz = \"MZ\" condition: $mz at 0 }";
    exercise(c, o, "yara_scan", json!({"path": pe, "rules": rule})).await;
    exercise(c, o, "find_crypto", json!({"path": owned(&scratch, &fixture("hello-go-arm64.elf"))})).await;
    let target = owned(&scratch, &fixture("eval-target-x86_64.elf"));
    exercise(c, o, "identify_functions", json!({"path": target, "apply": false, "limit": 3})).await;
    let output = scratch.0.join("signatures.json");
    let build = json!({"path": owned(&scratch, &fixture("eval-ref-x86_64.elf")), "output": output});
    exercise(c, o, "build_signatures", build).await;
    check_group(client, "detection", &observed, &[]).await;
}

/// The result fields of the `runtime` group on committed runtime snapshots, and `query_debugger` against a scripted
/// bridge socket (its `data` object is the bridge's own and is not pinned beyond what the script returns).
#[cfg(unix)]
#[tokio::test]
async fn contract_mcp_runtime_results() {
    let scratch = Scratch::new("runtime");
    let pointer = owned(&scratch, &data("runtime-thumb-pointer.snapshot.json"));
    let arm64 = owned(&scratch, &data("runtime-arm64.snapshot.json"));
    let comparison = crate::runtime_compare::Fixture::new();
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);
    exercise(c, o, "observe_pointer", json!({"path": pointer, "at": "0x3004"})).await;
    exercise(c, o, "observe_indirect_branch", json!({"path": arm64, "start": "0x1000", "at": "0x1008"})).await;
    let compare = json!({"path": arm64, "other": arm64, "at": "0x3000", "other_at": "0x4000"});
    exercise(c, o, "compare_pointer_observations", compare).await;
    exercise(c, o, "compare_runtime_bytes", comparison.arguments(&comparison.original)).await;
    let mut socket = crate::debugger::Socket::new();
    let bridge = socket.serve(|_| crate::debugger::response());
    let query = json!({"socket": socket.path, "request": {"version": 1, "operation": "describe_session"}});
    exercise(c, o, "query_debugger", query).await;
    bridge.join().unwrap();
    check_group(client, "runtime", &observed, &[]).await;
}

/// The result fields of the `types` group: the type library, typed data and operands, variables and frames,
/// propagation, and the debug-information imports, each on a fixture that has what it reads.
#[tokio::test]
async fn contract_mcp_types_results() {
    use crate::type_propagation::{CALLEE, CALLER, TYPES};

    let scratch = Scratch::new("types");
    let typed = owned(&scratch, &data("typed-data-x64.snapshot.json"));
    let propagation = owned(&scratch, &data("type-propagation-x64.snapshot.json"));
    let debug = owned(&scratch, &fixture("debug-x64.elf"));
    let pdb_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/pdb");
    let exe = owned(&scratch, &pdb_dir.join("fixture.exe"));
    let pdb = owned(&scratch, &pdb_dir.join("fixture.pdb"));
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let mut observed = Observed::new();
    let (c, o) = (&client, &mut observed);

    // The type library and typed data.
    let declarations = "enum TypedMode { MODE_OFF=0, MODE_READY=7, MODE_FAULT=-3 }; \
         struct TypedRecord { enum TypedMode mode; int4 value; char label[8]; }; struct Spare { int4 unused; };";
    exercise(c, o, "declare_types", json!({"path": typed, "declarations": declarations})).await;
    exercise(c, o, "list_types", json!({"path": typed, "limit": 3})).await;
    exercise(c, o, "get_type", json!({"path": typed, "name": "TypedRecord"})).await;
    exercise(c, o, "delete_type", json!({"path": typed, "name": "Spare"})).await;
    let operand = json!({"path": typed, "at": "0x201182", "operand": 1, "type_name": "TypedMode"});
    exercise(c, o, "apply_enum", operand).await;
    let operand = json!({"path": typed, "at": "0x201187", "operand": 1, "type_name": "TypedRecord"});
    exercise(c, o, "apply_offset", operand).await;
    let record = json!({"path": typed, "at": "0x200120", "type_name": "TypedRecord", "count": 2});
    exercise(c, o, "apply_data_type", record).await;
    exercise(c, o, "read_data", json!({"path": typed, "at": "0x200120", "size": 32})).await;
    exercise(c, o, "set_global", json!({"path": typed, "at": "0x200150", "text": "uint8 counter;"})).await;
    exercise(c, o, "set_signature", json!({"path": typed, "at": "0x201180", "text": "int4 typed_entry(void);"})).await;
    let set = json!({"path": typed, "at": "0x201180", "text": "struct Local { int4 gain; };"});
    exercise(c, o, "set_types", set).await;

    // Variables, frames and propagation on the propagation fixture.
    exercise(c, o, "declare_types", json!({"path": propagation, "declarations": TYPES})).await;
    let callee = json_of("decompile", &call(c, "decompile", json!({"path": propagation, "at": CALLEE})).await);
    let parameter = callee["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variable| {
            variable["kind"] == "parameter" && variable["editable"] == true && variable["name"] == "param_1"
        })
        .unwrap();
    let edit = json!({"path": propagation, "at": CALLEE, "storage": parameter["storage"], "data_type": "PropState *"});
    exercise(c, o, "edit_variable", edit).await;
    exercise(c, o, "function_frame", json!({"path": propagation, "at": CALLEE, "limit": 8})).await;
    let propagate = json!({"path": propagation, "at": CALLER, "apply": true, "max_functions": 4, "max_candidates": 8});
    exercise(c, o, "propagate_types", propagate).await;

    // Debug-information imports, previewed.
    exercise(c, o, "import_debug_signatures", json!({"path": debug})).await;
    exercise(c, o, "import_debug_signatures", json!({"path": debug, "apply": true})).await;
    exercise(c, o, "import_debug_types", json!({"path": debug, "limit": 2})).await;
    exercise(c, o, "import_debug_layouts", json!({"path": debug, "limit": 2})).await;
    exercise(c, o, "import_pdb_names", json!({"path": exe, "pdb": pdb, "limit": 2})).await;
    exercise(c, o, "import_pdb_names", json!({"path": exe, "pdb": pdb, "limit": 2, "apply": true})).await;
    check_group(client, "types", &observed, &[]).await;
}
