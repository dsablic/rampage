//! The MCP stable surface (docs/stability.md) pinned against snapshots in `tests/contract/`:
//! - `mcp-tools.json`: every tool's name, group and arguments (type and whether required), as `tools/list` gives
//!   them on a server with every group, a debug server with the write and kill flags, and a corpus server;
//! - `mcp-results.json`: the result field paths each core and debug tool returns on committed fixtures.
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
