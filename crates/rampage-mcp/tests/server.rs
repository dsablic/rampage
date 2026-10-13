use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{NotificationContext, RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::sync::Notify;

#[derive(Clone, Default)]
struct TestClient {
    tools_changed: Arc<Notify>,
}

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }

    fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) -> impl Future<Output = ()> + Send + '_ {
        self.tools_changed.notify_one();
        std::future::ready(())
    }
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_string_lossy().into_owned()
}

/// A client of a server listing every tool group, as `rampage mcp --all-tools` does.
async fn connect() -> RunningService<RoleClient, TestClient> {
    connect_to(RampageServer::with_groups(Group::ALL)).await
}

async fn connect_to(server: RampageServer) -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient::default().serve(client_transport).await.unwrap()
}

async fn tool_names(client: &RunningService<RoleClient, TestClient>) -> Vec<String> {
    let mut names: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
    names.sort();
    names
}

async fn call(client: &RunningService<RoleClient, TestClient>, tool: &str, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().and_then(|content| content.as_text()).map(|text| text.text.as_str()).unwrap()
}

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

#[tokio::test]
async fn lists_all_tools_with_instructions() {
    let client = connect().await;
    let names = tool_names(&client).await;
    let expected = [
        "analysis_diagnostics",
        "annotate_batch",
        "binary_info",
        "build_signatures",
        "capa_detect",
        "capabilities",
        "carve",
        "check_names",
        "class_evidence",
        "compare_pointer_observations",
        "compare_runtime_bytes",
        "decompile",
        "detect_tools",
        "diff_builds",
        "disassemble",
        "dotnet_il",
        "dotnet_metadata",
        "enable_tools",
        "find_crypto",
        "find_main",
        "function_graph",
        "function_summary",
        "identify_functions",
        "import_debug_signatures",
        "inspect_jump_table",
        "language_metadata",
        "list_annotations",
        "list_exports",
        "list_functions",
        "list_imports",
        "list_packs",
        "list_strings",
        "network_surface",
        "observe_indirect_branch",
        "observe_pointer",
        "persistence_surface",
        "redo",
        "rename",
        "set_comment",
        "set_global",
        "set_signature",
        "set_types",
        "string_decoding",
        "triage",
        "triage_report",
        "undo",
        "xrefs",
        "yara_scan",
    ];
    assert_eq!(names, expected);
    let info = client.peer_info().unwrap();
    assert_eq!(info.server_info.as_ref().unwrap().name, "rampage");
    let instructions = info.instructions.as_deref().unwrap();
    for tool in ["list_functions", "annotate_batch", "check_names"] {
        assert!(instructions.contains(tool), "{tool}");
    }
    client.cancel().await.unwrap();
}

fn core_tool_names() -> Vec<String> {
    let mut names: Vec<String> = rampage_api::tools::tools()
        .iter()
        .filter(|tool| tool.group == Group::Core && !tool.interactive)
        .map(|tool| tool.name.to_owned())
        .chain(["enable_tools".to_owned()])
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn lists_core_tools_and_enable_tools_by_default() {
    let client = connect_to(RampageServer::default()).await;
    let names = tool_names(&client).await;
    assert_eq!(names, core_tool_names());
    for tool in ["triage_report", "decompile", "xrefs", "annotate_batch", "undo", "list_annotations"] {
        assert!(names.iter().any(|name| name == tool), "{tool}");
    }
    for tool in ["detect_tools", "find_crypto", "set_types", "observe_pointer", "dotnet_metadata", "carve"] {
        assert!(!names.iter().any(|name| name == tool), "{tool}");
    }
    let info = client.peer_info().unwrap();
    assert_eq!(info.capabilities.tools.as_ref().unwrap().list_changed, Some(true));
    let instructions = info.instructions.as_deref().unwrap();
    for text in ["enable_tools", "--all-tools", "RAMPAGE_MCP_TOOLS", "not enabled"] {
        assert!(instructions.contains(text), "{text}");
    }
    for group in Group::ALL {
        assert!(instructions.contains(&format!("- {}: ", group.name())), "{group:?}");
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn enabling_a_group_adds_its_tools_and_notifies() {
    let client = connect_to(RampageServer::default()).await;
    let listing = json_of(&call(&client, "enable_tools", json!({})).await);
    assert_eq!(listing["newly_enabled"], json!([]));
    let groups = listing["groups"].as_array().unwrap();
    assert_eq!(groups.len(), Group::ALL.len());
    let detection = groups.iter().find(|group| group["name"] == "detection").unwrap();
    assert_eq!(detection["enabled"], false);
    assert!(!detection["description"].as_str().unwrap().is_empty());
    assert_eq!(detection["tool_count"], detection["tools"].as_array().unwrap().len());
    assert!(detection["tools"].as_array().unwrap().contains(&json!("find_crypto")));
    assert_eq!(tool_names(&client).await, core_tool_names());

    let enabled = json_of(&call(&client, "enable_tools", json!({ "groups": ["detection"] })).await);
    assert_eq!(enabled["newly_enabled"], json!(["detection"]));
    tokio::time::timeout(Duration::from_secs(10), client.service().tools_changed.notified())
        .await
        .expect("notifications/tools/list_changed");
    let names = tool_names(&client).await;
    for tool in ["detect_tools", "find_crypto", "identify_functions", "yara_scan", "decompile", "enable_tools"] {
        assert!(names.iter().any(|name| name == tool), "{tool}");
    }
    assert!(!names.iter().any(|name| name == "carve"));
    assert_eq!(names.len(), core_tool_names().len() + detection["tool_count"].as_u64().unwrap() as usize);

    let again = json_of(&call(&client, "enable_tools", json!({ "groups": ["detection"] })).await);
    assert_eq!(again["newly_enabled"], json!([]));
    let unknown = call(&client, "enable_tools", json!({ "groups": ["everything"] })).await;
    assert_eq!(unknown.is_error, Some(true));
    assert!(text(&unknown).contains("unknown tool group `everything`"), "{}", text(&unknown));
    let all = json_of(&call(&client, "enable_tools", json!({ "groups": ["all"] })).await);
    assert!(all["groups"].as_array().unwrap().iter().all(|group| group["enabled"] == true));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn a_disabled_tool_fails_naming_its_group_and_runs_nothing() {
    let client = connect_to(RampageServer::default()).await;
    let path = fixture("hello-x64.elf");
    let refused = call(&client, "detect_tools", json!({ "path": path })).await;
    assert_eq!(refused.is_error, Some(true));
    let message = text(&refused);
    assert!(message.contains("`detection` group") && message.contains("enable_tools"), "{message}");
    let carve = call(&client, "carve", json!({ "path": path })).await;
    assert_eq!(carve.is_error, Some(true));
    assert!(text(&carve).contains("`carve` group"), "{}", text(&carve));
    let unknown = call(&client, "no_such_tool", json!({ "path": path })).await;
    assert!(text(&unknown).contains("unknown tool"), "{}", text(&unknown));

    json_of(&call(&client, "enable_tools", json!({ "groups": ["detection"] })).await);
    json_of(&call(&client, "detect_tools", json!({ "path": path })).await);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn every_served_tool_is_in_exactly_one_group() {
    let client = connect().await;
    let listing = json_of(&call(&client, "enable_tools", json!({})).await);
    let mut grouped: Vec<String> = listing["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["tools"].as_array().unwrap().iter().map(|name| name.as_str().unwrap().to_owned()))
        .chain(["enable_tools".to_owned()])
        .collect();
    grouped.sort();
    assert_eq!(grouped, tool_names(&client).await);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn image_offset_opens_a_carved_executable_with_its_own_annotations() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-embedded-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut file = std::fs::read(fixture("hello-x64.elf")).unwrap();
    file.extend(b"junk".repeat(25));
    file.push(b'!');
    let offset = file.len() as u64;
    file.extend(std::fs::read(fixture("hello-arm64.macho")).unwrap());
    let path = directory.join("firmware.bin");
    std::fs::write(&path, file).unwrap();
    let path = path.to_str().unwrap();
    let client = connect().await;

    let tools = client.list_all_tools().await.unwrap();
    let binary_tools: Vec<_> =
        tools.iter().filter(|tool| tool.input_schema["properties"].get("arch").is_some()).collect();
    assert!(binary_tools.iter().any(|tool| tool.name == "rename"));
    for tool in binary_tools {
        assert!(tool.input_schema["properties"].get("image_offset").is_some(), "{}", tool.name);
    }

    let carving = json_of(&call(&client, "carve", json!({ "path": path })).await);
    let candidate = carving["candidates"].as_array().unwrap().iter().find(|candidate| candidate["kind"] == "mach_o");
    assert_eq!(candidate.unwrap()["offset"], offset);
    let hex = format!("{offset:#x}");
    let direct = json_of(&call(&client, "list_functions", json!({ "path": fixture("hello-arm64.macho") })).await);
    let embedded = json_of(&call(&client, "list_functions", json!({ "path": path, "image_offset": hex })).await);
    assert_eq!(embedded, direct);

    let arguments = json!({ "path": path, "image_offset": offset, "at": "_main", "name": "say_hello" });
    assert_eq!(json_of(&call(&client, "rename", arguments).await)["changed"], true);
    assert!(directory.join(format!("firmware.bin@{hex}.rampage")).exists());
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path, "image_offset": hex })).await);
    assert_eq!(list["names"][0]["text"], "say_hello");
    let outer = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert!(outer["names"].as_array().unwrap().is_empty());
    let triage = json_of(&call(&client, "triage", json!({ "path": path, "image_offset": hex })).await);
    assert_eq!(triage["embedded"]["offset"], offset);

    let bad = call(&client, "binary_info", json!({ "path": path, "image_offset": "0x1" })).await;
    assert!(text(&bad).contains("no ELF, PE or Mach-O header at offset 0x1"), "{}", text(&bad));
    let unannotated = call(&client, "observe_pointer", json!({ "path": path, "image_offset": 1, "at": "0x0" })).await;
    assert!(text(&unannotated).contains("no ELF, PE or Mach-O header"), "{}", text(&unannotated));
    let malformed = call(&client, "binary_info", json!({ "path": path, "image_offset": "x" })).await;
    assert_eq!(malformed.is_error, Some(true));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[tokio::test]
async fn carve_scans_any_file_by_path_with_pages() {
    let client = connect().await;
    let path = fixture("hello-universal.macho");
    let carving = json_of(&call(&client, "carve", json!({ "path": path, "offset": 1, "limit": 1 })).await);
    assert_eq!(carving["more"], true);
    assert_eq!(carving["offset"], 1);
    let candidates = carving["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["offset"], 0x1000);
    assert_eq!(candidates[0]["kind"], "mach_o");
    assert_eq!(candidates[0]["confidence"], "validated");
    assert_eq!(candidates[0]["arch"], "x86_64");
    assert_eq!(carving["truncated"], false);
    let last = json_of(&call(&client, "carve", json!({ "path": path, "offset": 2 })).await);
    assert_eq!((last["candidates"].as_array().unwrap().len(), &last["more"]), (1, &json!(false)));

    let license = fixture("Microsoft.Bcl.HashCode.dll.LICENSE.txt");
    let none = json_of(&call(&client, "carve", json!({ "path": license })).await);
    assert_eq!((none["candidates"].as_array().unwrap().len(), &none["more"]), (0, &json!(false)));
    let failed = call(&client, "carve", json!({ "path": "/dev/zero" })).await;
    assert_eq!(failed.is_error, Some(true));
    assert!(text(&failed).contains("not a regular file"), "{}", text(&failed));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn explores_a_binary_end_to_end() {
    let client = connect().await;
    let path = fixture("hello-x64.elf");

    let info = json_of(&call(&client, "binary_info", json!({ "path": path })).await);
    assert_eq!(info["format"], "elf");
    assert_eq!(info["entry"], "0x10018c0");

    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "main" })).await);
    let main = functions["items"].as_array().unwrap().iter().find(|row| row["name"] == "main").unwrap();
    assert_eq!(main["address"], "0x1001910");

    let lines = json_of(&call(&client, "disassemble", json!({ "path": path, "at": "main", "count": 3 })).await);
    assert_eq!(lines.as_array().unwrap().len(), 3);
    assert_eq!(lines[0]["label"], "main");

    let xrefs = json_of(&call(&client, "xrefs", json!({ "path": path, "to": "puts" })).await);
    assert!(xrefs["items"].as_array().unwrap().iter().any(|row| row["from_function"] == "main"));

    let strings = json_of(&call(&client, "list_strings", json!({ "path": path, "contains": "greeting" })).await);
    assert_eq!(strings["total"], 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn dotnet_il_lists_a_method_by_name() {
    let client = connect().await;
    let path = fixture("Microsoft.Bcl.HashCode.dll");
    let arguments = json!({ "path": path, "method": "System.HashCode::MixFinal", "limit": 2 });
    let il = json_of(&call(&client, "dotnet_il", arguments).await);
    assert_eq!(il["method"], "System.HashCode::MixFinal");
    assert_eq!(il["instructions"]["items"][0]["opcode"], "ldarg.0");
    assert_eq!(il["instructions"]["items"].as_array().unwrap().len(), 2);
    let ambiguous = call(&client, "dotnet_il", json!({ "path": path, "method": "System.HashCode::Combine" })).await;
    assert_eq!(ambiguous.is_error, Some(true));
    assert!(text(&ambiguous).contains("0x0600000d"), "{}", text(&ambiguous));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn function_summary_exposes_ssa_through_the_shared_registry() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-ssa-diamond.snapshot.json")
        .to_string_lossy()
        .into_owned();
    let summary = json_of(&call(&client, "function_summary", json!({ "path": path, "at": "0x1000" })).await);
    assert!(
        summary["ssa"]["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|definition| definition["expression"]["kind"] == "phi"
                && definition["expression"]["inputs"].as_array().unwrap().len() == 2)
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pages_are_capped() {
    let client = connect().await;
    let page = json_of(&call(&client, "list_functions", json!({ "path": fixture("hello-x64.elf"), "limit": 2 })).await);
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(page["total"].as_u64().unwrap() > 2);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn arm64_functions_are_listed() {
    let client = connect().await;
    let arm = call(&client, "list_functions", json!({ "path": fixture("hello-arm64.macho") })).await;
    assert_eq!(arm.is_error, Some(false));
    assert!(text(&arm).contains("\"_main\""), "{}", text(&arm));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn failures_are_tool_errors_the_caller_can_read() {
    let client = connect().await;
    let missing = call(&client, "binary_info", json!({ "path": "/nonexistent/binary" })).await;
    assert_eq!(missing.is_error, Some(true));
    assert!(text(&missing).contains("/nonexistent/binary"), "{}", text(&missing));

    let path = fixture("hello-x64.elf");
    let ambiguous = call(&client, "xrefs", json!({ "path": path, "to": "main", "from": "main" })).await;
    assert_eq!(ambiguous.is_error, Some(true));

    let bad_arch = call(&client, "binary_info", json!({ "path": path, "arch": "vax" })).await;
    assert!(text(&bad_arch).contains("unknown architecture"));

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pointer_observations_preserve_writable_slot_values_without_annotations() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/data/runtime-thumb-pointer.snapshot.json")
        .to_string_lossy()
        .into_owned();
    let observation = json_of(&call(&client, "observe_pointer", json!({"path": path, "at": "0x3004"})).await);
    assert_eq!(observation["raw_value"], "0x1003");
    assert_eq!(observation["slot_permissions"]["write"], true);
    assert_eq!(observation["candidate_target"], "0x1002");
    let annotations = json_of(&call(&client, "list_annotations", json!({"path": path})).await);
    assert!(annotations["names"].as_array().unwrap().is_empty());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn branch_observation_decodes_explicit_window_without_resolving_captured_flow() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let result = json_of(
        &call(&client, "observe_indirect_branch", json!({"path": path, "start": "0x1000", "at": "0x1008"})).await,
    );
    assert_eq!(result["flow"]["kind"], "indirect_jump");
    assert_eq!(result["load_address"], "0x1004");
    assert_eq!(result["pointer"]["slot"], "0x3000");
    assert_eq!(result["capture_identity"], result["pointer"]["capture_identity"]);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn pointer_comparison_reports_unavailable_words_instead_of_zero() {
    let client = connect().await;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    let result = json_of(
        &call(
            &client,
            "compare_pointer_observations",
            json!({"path": path, "other": path, "at": "0x3000", "other_at": "0x4000"}),
        )
        .await,
    );
    assert_eq!(result["raw_value_change"], "after_unavailable");
    assert_eq!(result["before"]["raw_value"], "0x1010");
    assert!(result["after"]["raw_value"].is_null());
    let error = call(
        &client,
        "compare_pointer_observations",
        json!({"path": path, "other": path, "at": "sub_3000", "other_at": "0x3000"}),
    )
    .await;
    assert_eq!(error.is_error, Some(true));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn runtime_comparison_ignores_sidecars_and_requires_explicit_matching_originals() {
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(std::env::temp_dir().join(format!("rampage-mcp-compare-{}", std::process::id())));
    std::fs::create_dir(&directory.0).unwrap();
    let original = fixture("hello-arm64.macho");
    let binary = rampage_loaders::Binary::open(&original).unwrap();
    let rampage_loaders::Details::MachO(details) = &binary.details else { panic!("not Mach-O") };
    let uuid = details.uuid.as_deref().unwrap();
    let image_base =
        binary.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let snapshot = json!({"format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
        "provenance": "controlled MCP comparison", "regions": [{"name": "header", "address": "0x1000",
            "permissions": "r--", "bytes": "cffaedfe"}], "modules": [{"name": "fixture",
            "path": "/never/open/this", "uuid": uuid, "image_base": format!("{image_base:#x}"),
            "runtime_base": "0x1000"}]});
    let path = directory.0.join("snapshot.json");
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    std::fs::create_dir(path.with_extension("json.rampage")).unwrap();
    let client = connect().await;
    let mut arguments = json!({"path": path, "original": original, "module": uuid,
        "ranges": [{"address": "0x1000", "size": 6}], "limit": 1});
    let first = json_of(&call(&client, "compare_runtime_bytes", arguments.clone()).await);
    assert_eq!(first["equal_bytes"], 4);
    assert_eq!(first["unavailable_bytes"], 2);
    assert_eq!(first["spans_total"], 2);
    assert_eq!(first["spans"].as_array().unwrap().len(), 1);
    arguments["offset"] = json!(1);
    let second = json_of(&call(&client, "compare_runtime_bytes", arguments.clone()).await);
    assert_eq!(second["spans"][0]["status"], "capture_unavailable");
    assert_eq!(second["capture_identity"], first["capture_identity"]);
    let pointers = json_of(
        &call(
            &client,
            "compare_pointer_observations",
            json!({"path": path, "other": path, "at": "0x1000", "other_at": "0x1000"}),
        )
        .await,
    );
    assert_eq!(pointers["raw_value_change"], "both_unavailable");
    arguments["module"] = json!("00000000000000000000000000000000");
    assert_eq!(call(&client, "compare_runtime_bytes", arguments.clone()).await.is_error, Some(true));
    arguments["original"] = json!("/nonexistent/explicit-original");
    let error = call(&client, "compare_runtime_bytes", arguments).await;
    assert_eq!(error.is_error, Some(true));
    assert!(text(&error).starts_with("/nonexistent/explicit-original: "), "{}", text(&error));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn large_workflow_reports_stay_valid_json_with_their_limitations() {
    let client = connect().await;
    let arguments = json!({
        "path": fixture("hello-x64.elf"),
        "other": fixture("hello-go-x64.elf"),
        "max_per_section": 200,
    });
    let result = call(&client, "diff_builds", arguments).await;
    assert!(text(&result).len() <= 60_000, "{}", text(&result).len());
    let report = json_of(&result);
    let limitations = report["limitations"].as_array().unwrap();
    assert!(limitations.iter().any(|text| text.as_str().unwrap().contains("Hash matching is signature-level")));
    assert!(limitations.iter().any(|text| text.as_str().unwrap().contains("cut to fit")));
    assert!(report["sections"].as_array().unwrap().iter().any(|section| section["truncated"] == true));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn agent_supplied_databases_must_be_bounded_regular_files() {
    let client = connect().await;
    let path = fixture("hello-x64.elf");
    for (tool, argument) in [("identify_functions", "database"), ("detect_tools", "peid")] {
        let result = call(&client, tool, json!({ "path": path, argument: "/dev/zero" })).await;
        assert_eq!(result.is_error, Some(true), "{tool}");
        assert!(text(&result).ends_with("/dev/zero: not a regular file"), "{tool}: {}", text(&result));
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn detect_tools_reports_skipped_peid_entries() {
    let client = connect().await;
    let peid = std::env::temp_dir().join(format!("rampage-mcp-partial-peid-{}.txt", std::process::id()));
    let broken = "[Broken]\nsignature = ZZ ZZ\nep_only = true\n".repeat(25);
    std::fs::write(&peid, broken + "[Fine]\nsignature = 4D 5A\nep_only = false\n").unwrap();
    let result = call(&client, "detect_tools", json!({ "path": fixture("hello-x64.exe"), "peid": peid })).await;
    std::fs::remove_file(&peid).unwrap();
    let found = json_of(&result);
    assert!(found["detections"].as_array().unwrap().iter().any(|detection| detection["name"] == "Fine"), "{found}");
    let warnings = found["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 21, "{found}");
    assert!(warnings[0].as_str().unwrap().contains("[Broken]"), "{found}");
    assert_eq!(warnings[20], "PeID database: ... and 5 more problems skipped");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn identify_functions_can_leave_out_the_bundled_database() {
    let client = connect().await;
    let path = fixture("hello-x64.elf");
    let bundled = json_of(&call(&client, "identify_functions", json!({ "path": path })).await);
    assert!(bundled["matched"].as_u64().unwrap() > 0, "{bundled}");
    let error = call(&client, "identify_functions", json!({ "path": path, "no_bundled": true })).await;
    assert_eq!(error.is_error, Some(true));
    assert!(text(&error).contains("needs a signature database"), "{}", text(&error));

    let database = std::env::temp_dir().join(format!("rampage-mcp-empty-db-{}.json", std::process::id()));
    std::fs::write(&database, r#"{"arch":"x86_64","scheme":2,"entries":{}}"#).unwrap();
    let alone = json_of(
        &call(&client, "identify_functions", json!({ "path": path, "database": database, "no_bundled": true })).await,
    );
    std::fs::remove_file(&database).unwrap();
    assert_eq!(alone["matched"], 0, "{alone}");
    client.cancel().await.unwrap();
}

/// Function signatures (masked and exact) and callee keys are counted apart.
#[tokio::test]
async fn build_signatures_counts_function_signatures_and_callee_keys_apart() {
    let client = connect().await;
    let output = std::env::temp_dir().join(format!("rampage-mcp-build-db-{}.json", std::process::id()));
    let arguments = json!({ "path": fixture("eval-ref-x86_64.elf"), "output": output });
    let built = json_of(&call(&client, "build_signatures", arguments).await);
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&output).unwrap()).unwrap();
    std::fs::remove_file(&output).unwrap();
    let count = |field: &str| written.get(field).and_then(Value::as_object).map_or(0, |map| map.len() as u64);
    assert_eq!(built["signatures"].as_u64(), Some(count("entries") + count("exact")), "{built}");
    assert_eq!(built["callee_keys"].as_u64(), Some(count("calls")), "{built}");
    assert!(count("calls") > 0, "{built}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn triage_and_imports_describe_a_binary() {
    let client = connect().await;
    let path = fixture("hello-x64-dyn.elf");
    let triage = json_of(&call(&client, "triage", json!({ "path": path })).await);
    assert_eq!(triage["image_hashes"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(triage["details"]["format"], "elf");
    assert_eq!(triage["details"]["interpreter"], "/lib64/ld-linux-x86-64.so.2");
    let imports = json_of(&call(&client, "list_imports", json!({ "path": path, "contains": "puts" })).await);
    assert_eq!(imports["total"], 1);
    assert_eq!(imports["items"][0]["library"], "libc.so.6");
    assert!(imports["items"][0]["slot"].as_str().unwrap().starts_with("0x"));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn agents_rename_and_comment() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(fixture("hello-arm64.macho"), &path).unwrap();
    let path = path.to_str().unwrap();
    let client = connect().await;
    let renamed = json_of(&call(&client, "rename", json!({ "path": path, "at": "_main", "name": "say_hello" })).await);
    assert_eq!(renamed["changed"], true);
    json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "text": "entry" })).await);
    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "say_" })).await);
    assert_eq!(functions["items"][0]["name"], "say_hello");
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(list["comments"][0]["text"], "entry");
    let undone = json_of(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undone[0]["field"], "comment");
    let redone = json_of(&call(&client, "redo", json!({ "path": path })).await);
    assert_eq!(redone[0]["value"], "entry");
    let cleared =
        json_of(&call(&client, "set_comment", json!({ "path": path, "at": "say_hello", "clear": true })).await);
    assert_eq!((&cleared["value"], &cleared["changed"]), (&json!(null), &json!(true)));
    let neither = call(&client, "rename", json!({ "path": path, "at": "say_hello" })).await;
    assert_eq!(neither.is_error, Some(true));
    let bad = call(&client, "rename", json!({ "path": path, "at": "say_hello", "name": "two words" })).await;
    assert_eq!(bad.is_error, Some(true));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[tokio::test]
async fn agents_annotate_in_batches() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-batch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(fixture("hello-arm64.macho"), &path).unwrap();
    let path = path.to_str().unwrap();
    let client = connect().await;
    let checks =
        json_of(&call(&client, "check_names", json!({ "path": path, "names": ["_puts", "fresh", "0x10"] })).await);
    assert_eq!(
        (&checks[0]["used_by"], &checks[1]["valid"], &checks[2]["address_shaped"]),
        (&json!("symbol"), &json!(true), &json!(true))
    );

    let entries = json!([
        { "at": "_main", "name": "say_hello", "comment": "entry" },
        { "at": "_puts", "name": "two words" },
    ]);
    let refused = call(&client, "annotate_batch", json!({ "path": path, "entries": entries })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("entry 1"), "{}", text(&refused));
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!(list["names"], json!([]));

    let entries = json!([
        { "at": "_main", "name": "say_hello", "comment": "entry" },
        { "at": "_puts", "comment": "libc" },
    ]);
    let applied = json_of(&call(&client, "annotate_batch", json!({ "path": path, "entries": entries })).await);
    assert_eq!(applied["changed"], 2);
    let undone = json_of(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undone.as_array().unwrap().len(), 3);
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!((&list["names"], &list["comments"]), (&json!([]), &json!([])));
    json_of(&call(&client, "redo", json!({ "path": path })).await);
    let functions = json_of(&call(&client, "list_functions", json!({ "path": path, "name_contains": "say_" })).await);
    assert_eq!(functions["items"][0]["name"], "say_hello");
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[tokio::test]
async fn list_packs_reports_loaded_packs_and_scans_use_their_rules() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-pack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("rampage-pack.toml"),
        "name = \"mcp-pack\"\nversion = \"1\"\nlicense = \"MIT\"\nsource = \"https://example.com/mcp-pack\"\n\
         description = \"MCP test pack\"\n[[contents]]\nkind = \"yara\"\npath = \"pe.yar\"\n\
         [[contents]]\nkind = \"constants\"\npath = \"pe.yar\"\n",
    )
    .unwrap();
    std::fs::write(directory.join("pe.yar"), "rule mcp_pe { strings: $mz = \"MZ\" condition: $mz at 0 }").unwrap();
    let packs = rampage_api::Packs::load(std::slice::from_ref(&directory));
    let packs = std::sync::Arc::new(packs);
    let core = connect_to(RampageServer::default().with_packs(std::sync::Arc::clone(&packs))).await;
    let refused = call(&core, "list_packs", json!({})).await;
    assert!(text(&refused).contains("is in the `detection` group"), "{}", text(&refused));
    core.cancel().await.unwrap();
    let client = connect_to(RampageServer::with_groups(Group::ALL).with_packs(packs)).await;

    let listing = json_of(&call(&client, "list_packs", json!({})).await);
    assert_eq!(listing[0]["name"], "rampage-builtin");
    assert_eq!(listing[0]["license"], "Apache-2.0");
    assert_eq!(listing[1]["name"], "mcp-pack");
    assert_eq!(listing[1]["source"], "https://example.com/mcp-pack");
    assert_eq!(listing[1]["contents"][0]["status"], "loaded");
    assert_eq!(listing[1]["contents"][1]["status"], "unsupported");

    let matches = json_of(&call(&client, "yara_scan", json!({ "path": fixture("hello-x64.exe") })).await);
    assert_eq!(matches[0]["identifier"], "mcp_pe", "{matches}");
    assert_eq!(matches[0]["namespace"], "mcp-pack", "{matches}");
    let error = call(&client, "capa_detect", json!({ "path": fixture("hello-x64.exe") })).await;
    assert_eq!(error.is_error, Some(true));
    assert!(text(&error).contains("no capa rules"), "{}", text(&error));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}
