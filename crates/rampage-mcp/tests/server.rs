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
        "archive_inventory",
        "binary_info",
        "build_signatures",
        "capa_detect",
        "capabilities",
        "carve",
        "check_names",
        "class_evidence",
        "compare_pointer_observations",
        "compare_runtime_bytes",
        "decode_file_range",
        "decompile",
        "detect_tools",
        "diff_builds",
        "disassemble",
        "discard_undo",
        "dotnet_il",
        "dotnet_metadata",
        "edit_variable",
        "enable_tools",
        "entry_diagnostics",
        "find_crypto",
        "find_main",
        "function_graph",
        "function_summary",
        "identify_functions",
        "import_debug_layouts",
        "import_debug_signatures",
        "import_pdb_names",
        "inspect_data",
        "inspect_jump_table",
        "inspect_raw_code",
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
        "query_debugger",
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
        .chain(
            rampage_api::tools::file_tools()
                .into_iter()
                .filter(|tool| tool.group == Group::Core)
                .map(|tool| tool.name.to_owned()),
        )
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
    for tool in
        ["detect_tools", "find_crypto", "set_types", "observe_pointer", "dotnet_metadata", "carve", "archive_inventory"]
    {
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
async fn diff_builds_compares_an_embedded_image_in_the_other_file() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-diff-embedded-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut file = b"junk!".repeat(9);
    let offset = file.len() as u64;
    file.extend(std::fs::read(fixture("hello-x64-dyn.elf")).unwrap());
    let other = directory.join("firmware.bin");
    std::fs::write(&other, file).unwrap();
    let other = other.to_str().unwrap();
    let client = connect().await;
    let base = fixture("hello-x64.elf");
    let direct =
        json_of(&call(&client, "diff_builds", json!({ "path": base, "other": fixture("hello-x64-dyn.elf") })).await);
    let arguments = json!({ "path": base, "other": other, "other_image_offset": format!("{offset:#x}") });
    let embedded = json_of(&call(&client, "diff_builds", arguments).await);
    assert_eq!(embedded["sections"], direct["sections"]);
    let arguments = json!({ "path": base, "other": other, "other_image_offset": offset, "other_image_length": 1 });
    assert_eq!(call(&client, "diff_builds", arguments).await.is_error, Some(true));
    let lone = call(&client, "diff_builds", json!({ "path": base, "other": other, "other_image_length": 1 })).await;
    assert!(text(&lone).contains("`other_image_length` needs `other_image_offset`"), "{}", text(&lone));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
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
    // Raw windows assert architecture without opening a native embedded image.
    let binary_tools: Vec<_> = tools
        .iter()
        .filter(|tool| tool.name != "inspect_raw_code" && tool.input_schema["properties"].get("arch").is_some())
        .collect();
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
    assert!(directory.join(format!("firmware.bin@{hex}.rampage-image")).exists());
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
    // Every offset argument, at the server or in a tool, takes the same spellings and says so when refused.
    for value in [json!(-1), json!(1.5), json!("x")] {
        let refused = call(&client, "binary_info", json!({ "path": path, "image_offset": value })).await;
        assert!(text(&refused).starts_with("`image_offset`: "), "{}", text(&refused));
        assert!(text(&refused).contains("hex (\"0x1000\") or decimal"), "{}", text(&refused));
        let arguments = json!({ "path": path, "other": path, "other_image_offset": value });
        let refused = call(&client, "diff_builds", arguments).await;
        assert_eq!(refused.is_error, Some(true));
        assert!(text(&refused).contains("hex (\"0x1000\") or decimal"), "{}", text(&refused));
        assert!(!text(&refused).contains("untagged"), "{}", text(&refused));
    }

    let size = std::fs::metadata(fixture("hello-arm64.macho")).unwrap().len();
    let mut longer = std::fs::read(path).unwrap();
    longer.extend(b"appended overlay");
    let longer_path = directory.join("longer.bin");
    std::fs::write(&longer_path, longer).unwrap();
    let path = longer_path.to_str().unwrap();
    let cut = json_of(&call(&client, "triage", json!({ "path": path, "image_offset": hex })).await);
    assert_eq!(cut["embedded"]["trailing"], 16);
    assert!(cut["overlay"].is_null());
    let arguments = json!({ "path": path, "image_offset": hex, "image_length": size + 16 });
    let whole = json_of(&call(&client, "triage", arguments).await);
    assert_eq!(whole["overlay"]["size"], 16, "{whole}");
    let lone = call(&client, "triage", json!({ "path": path, "image_length": 16 })).await;
    assert!(text(&lone).contains("`image_length` needs `image_offset`"), "{}", text(&lone));
    for tool in client.list_all_tools().await.unwrap() {
        if tool.input_schema["properties"].get("image_offset").is_some() {
            assert!(tool.input_schema["properties"].get("image_length").is_some(), "{}", tool.name);
        }
    }
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
    let arguments = json!({ "path": path, "method": "0x0600000d", "at": "IL_000c", "limit": 1 });
    let page = json_of(&call(&client, "dotnet_il", arguments).await);
    assert_eq!(page["instructions"]["offset"], 5);
    assert_eq!(page["instructions"]["items"][0]["offset"], 11);
    let bad = call(&client, "dotnet_il", json!({ "path": path, "method": "0x0600000d", "at": "IL_zz" })).await;
    assert_eq!(bad.is_error, Some(true));
    let ambiguous = call(&client, "dotnet_il", json!({ "path": path, "method": "System.HashCode::Combine" })).await;
    assert_eq!(ambiguous.is_error, Some(true));
    assert!(text(&ambiguous).contains("0x0600000d"), "{}", text(&ambiguous));
    client.cancel().await.unwrap();
}

fn boxed_attribute_image() -> Vec<u8> {
    boxed_attribute_image_for_enum("Mode", None)
}

fn boxed_attribute_image_for_enum(mode_name: &str, enum_wire_name: Option<&str>) -> Vec<u8> {
    let mut strings = vec![0];
    let mut name = |text: &str| {
        let index = strings.len() as u16;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        index
    };
    let attribute = name("BoxedAttribute");
    let namespace = name("Demo");
    let ctor = name(".ctor");
    let enum_name = name("Enum");
    let system = name("System");
    let mode = name(mode_name);
    let value_field = name("value__");
    let all = name("All");
    let alias = name("Alias");
    let mscorlib = name("mscorlib");
    let mut value = vec![1, 0, 0x08, 42, 0, 0, 0, 2, 0, 0, 0, 0x0E, 2, b'4', b'2'];
    value.extend([0x1D, 0x08, 2, 0, 0, 0]);
    value.extend((-2i32).to_le_bytes());
    value.extend(7i32.to_le_bytes());
    value.extend([if enum_wire_name.is_some() { 3 } else { 2 }, 0, 0x54, 0x51, 5]);
    value.extend(b"Value");
    value.extend([0x50, 11]);
    value.extend(b"Demo.Target");
    value.extend([0x53, 0x1D, 0x51, 5]);
    value.extend(b"Items");
    value.extend([2, 0, 0, 0, 0x0E, 0xFF, 0x02, 1]);
    if let Some(enum_wire_name) = enum_wire_name {
        assert!(enum_wire_name.len() < 0x80);
        value.extend([0x53, 0x55, enum_wire_name.len() as u8]);
        value.extend(enum_wire_name.as_bytes());
        value.push(4);
        value.extend(b"Mode");
        value.extend(u64::MAX.to_le_bytes());
    }
    let mut blobs = vec![0, 6, 0x20, 2, 0x01, 0x1C, 0x1D, 0x1C];
    assert!(value.len() < 0x80);
    blobs.push(value.len() as u8);
    blobs.extend(value);
    let value_signature = blobs.len() as u16;
    blobs.extend([2, 0x06, 0x0B]);
    let literal_signature = blobs.len() as u16;
    blobs.extend([3, 0x06, 0x11, 4]);
    let constant_value = blobs.len() as u16;
    blobs.push(8);
    blobs.extend(u64::MAX.to_le_bytes());
    let present = [(1, 2u32), (2, 1), (4, 3), (10, 1), (11, 2), (12, 1), (35, 1)];
    let valid = present.iter().fold(0u64, |mask, &(table, _)| mask | (1 << table));
    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    tables.extend(valid.to_le_bytes());
    tables.extend(0u64.to_le_bytes());
    for &(_, rows) in &present {
        tables.extend(rows.to_le_bytes());
    }
    for row in [
        vec![0, attribute, namespace],
        vec![6, enum_name, system],
        vec![1, 0, mode, namespace, 9, 1, 1],
        vec![0x0606, value_field, value_signature],
        vec![0x8056, all, literal_signature],
        vec![0x8056, alias, literal_signature],
        vec![9, ctor, 1],
        vec![0x0B, 8, constant_value],
        vec![0x0B, 12, constant_value],
        vec![34, 11, 8],
        vec![4, 0, 0, 0, 0, 0, 0, mscorlib, 0, 0],
    ] {
        for column in row {
            tables.extend(column.to_le_bytes());
        }
    }
    let streams: [(&str, &[u8]); 3] = [("#~", &tables), ("#Strings", &strings), ("#Blob", &blobs)];
    let version = b"v4.0.30319\0\0";
    let mut root = b"BSJB\x01\0\x01\0\0\0\0\0".to_vec();
    root.extend((version.len() as u32).to_le_bytes());
    root.extend(version);
    root.extend([0, 0, 3, 0]);
    let mut offset =
        root.len() + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    for (name, data) in streams {
        root.extend((offset as u32).to_le_bytes());
        root.extend((data.len() as u32).to_le_bytes());
        root.extend(name.as_bytes());
        root.push(0);
        root.resize(root.len().next_multiple_of(4), 0);
        offset += data.len().next_multiple_of(4);
    }
    for (_, data) in streams {
        root.extend(data);
        root.resize(root.len().next_multiple_of(4), 0);
    }
    let mut image = std::fs::read(fixture("Microsoft.Bcl.HashCode.dll")).unwrap();
    let metadata = rampage_loaders::dotnet::parse_image(&image).unwrap().unwrap();
    let start = image.windows(4).position(|bytes| bytes == b"BSJB").unwrap();
    assert!(root.len() <= metadata.cli.metadata_size as usize);
    image[start..start + root.len()].copy_from_slice(&root);
    image
}

#[tokio::test]
async fn dotnet_metadata_transports_typed_boxed_values_through_the_existing_schema() {
    struct BoxedImage(PathBuf);
    impl Drop for BoxedImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let scratch = BoxedImage(std::env::temp_dir().join(format!("rampage-mcp-dotnet-boxed-{}.dll", std::process::id())));
    std::fs::write(&scratch.0, boxed_attribute_image()).unwrap();
    let client = connect().await;
    let tools = client.list_all_tools().await.unwrap();
    let metadata = tools.iter().find(|tool| tool.name == "dotnet_metadata").unwrap();
    assert!(metadata.input_schema["properties"].get("boxed").is_none());
    let result = call(
        &client,
        "dotnet_metadata",
        json!({"path": scratch.0.to_str().unwrap(), "list": "attributes", "limit": 1}),
    )
    .await;
    let json = json_of(&result);
    assert_eq!(json["custom_attributes"]["total"], 1);
    let attribute = &json["custom_attributes"]["items"][0];
    assert_eq!(attribute["attribute_type"], "Demo.BoxedAttribute");
    assert_eq!(attribute["arguments"], json!(["box(int32, 42)", "[box(string, \"42\"), box(int32[], [-2, 7])]"]));
    assert_eq!(
        attribute["named_arguments"],
        json!([
            {"kind": "property", "name": "Value", "argument_type": "object",
             "value": "box(System.Type, typeof(Demo.Target))"},
            {"kind": "field", "name": "Items", "argument_type": "object[]",
             "value": "[box(string, null), box(bool, true)]"},
        ])
    );
    assert!(attribute.get("arguments_error").is_none_or(Value::is_null));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn dotnet_metadata_preserves_escaped_local_enum_identity_and_numeric_values() {
    struct EscapedImage(PathBuf);
    impl Drop for EscapedImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    for (index, (wire_name, accepted)) in
        [(r"Demo.Mo\+de", true), ("Demo.Mo+de", false), (r"Demo.Mo\+de, Demo", false)].into_iter().enumerate()
    {
        let scratch = EscapedImage(
            std::env::temp_dir().join(format!("rampage-mcp-dotnet-escaped-{}-{index}.dll", std::process::id())),
        );
        std::fs::write(&scratch.0, boxed_attribute_image_for_enum("Mo+de", Some(wire_name))).unwrap();
        let client = connect().await;
        let summary = json_of(
            &call(&client, "dotnet_metadata", json!({"path": scratch.0, "list": "attributes", "limit": 1})).await,
        );
        let attribute = &summary["custom_attributes"]["items"][0];
        assert_eq!(attribute["arguments"][0], "box(int32, 42)");
        if accepted {
            assert!(attribute["arguments_error"].is_null(), "{summary}");
            assert_eq!(attribute["named_arguments"][2]["argument_type"], r"Demo.Mo\+de");
            assert_eq!(attribute["named_arguments"][2]["value"], r"Demo.Mo\+de(18446744073709551615)");
        } else {
            assert!(attribute["arguments_error"].is_string(), "{summary}");
        }
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn dotnet_metadata_transports_enum_constant_evidence_through_the_existing_types_selector() {
    struct EnumImage(PathBuf);
    impl Drop for EnumImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let scratch = EnumImage(std::env::temp_dir().join(format!("rampage-mcp-dotnet-enums-{}.dll", std::process::id())));
    std::fs::write(&scratch.0, boxed_attribute_image()).unwrap();
    let client = connect().await;
    let result = call(
        &client,
        "dotnet_metadata",
        json!({"path": scratch.0.to_str().unwrap(), "list": "types", "contains": "mode", "limit": 1}),
    )
    .await;
    let json = json_of(&result);
    assert_eq!(json["types"]["total"], 1);
    let fields = json["types"]["items"][0]["fields"].as_array().unwrap();
    assert!(fields[0].get("enum_constant").is_none());
    for (field, name, token) in [(&fields[1], "All", 0x0400_0002), (&fields[2], "Alias", 0x0400_0003)] {
        assert_eq!(field["name"], name);
        assert_eq!(field["token"], token);
        assert_eq!(
            field["enum_constant"],
            json!({
                "underlying_integral_type": "uint64", "value": "18446744073709551615"
            })
        );
    }
    assert!(json.get("custom_attributes").is_none());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn dotnet_resources_select_the_independent_metadata_page_and_counts() {
    let client = connect().await;
    let path = fixture("Microsoft.Bcl.HashCode.dll");
    let schema =
        client.list_all_tools().await.unwrap().into_iter().find(|tool| tool.name == "dotnet_metadata").unwrap();
    let schema = Value::Object((*schema.input_schema).clone());
    let list = &schema["properties"]["list"];
    let list = list
        .get("$ref")
        .and_then(Value::as_str)
        .map(|reference| schema.pointer(reference.strip_prefix('#').unwrap()).unwrap())
        .unwrap_or(list);
    let permits_resources = list["enum"].as_array().is_some_and(|values| values.contains(&json!("resources")))
        || list["oneOf"]
            .as_array()
            .is_some_and(|variants| variants.iter().any(|variant| variant["const"] == "resources"));
    assert!(permits_resources, "{schema}");
    let resources = json_of(
        &call(
            &client,
            "dotnet_metadata",
            json!({ "path": path, "list": "resources", "contains": "absent", "offset": 7, "limit": 1 }),
        )
        .await,
    );
    assert_eq!(resources["list"], "resources");
    assert_eq!(resources["resource_counts"]["declared_known"], true);
    assert_eq!(resources["resources"]["items"], json!([]));
    assert_eq!(resources["resource_counts"]["returned"], 0);
    assert_eq!(resources["counts"]["resources"], resources["resource_counts"]["retained"]);
    assert!(resources.get("types").is_none());
    assert!(resources.get("custom_attributes").is_none());
    let types = json_of(&call(&client, "dotnet_metadata", json!({ "path": path, "limit": 1 })).await);
    assert_eq!(types["list"], "types");
    assert!(types.get("resources").is_none());
    assert_eq!(types["resource_counts"]["returned"], 0);
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
    // Nothing blocks undoing the comment, so dropping it from the history takes force.
    let refused = call(&client, "discard_undo", json!({ "path": path })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("force"), "{}", text(&refused));
    let discarded = json_of(&call(&client, "discard_undo", json!({ "path": path, "force": true })).await);
    assert_eq!(discarded[0]["value"], "entry");
    let undone = json_of(&call(&client, "undo", json!({ "path": path })).await);
    assert_eq!(undone[0]["field"], "name");
    let list = json_of(&call(&client, "list_annotations", json!({ "path": path })).await);
    assert_eq!((&list["names"], &list["comments"][0]["text"]), (&json!([]), &json!("entry")));
    json_of(&call(&client, "redo", json!({ "path": path })).await);
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
    assert_eq!(listing[1]["name"], "rampage-builtin");
    assert_eq!(listing[1]["license"], "Apache-2.0");
    assert_eq!(listing[0]["name"], "mcp-pack");
    assert_eq!(listing[0]["source"], "https://example.com/mcp-pack");
    assert_eq!(listing[0]["contents"][0]["status"], "loaded");
    assert_eq!(listing[0]["contents"][1]["status"], "error");

    let scan = json_of(&call(&client, "yara_scan", json!({ "path": fixture("hello-x64.exe") })).await);
    let matches = &scan["matches"];
    assert_eq!(matches[0]["identifier"], "mcp_pe", "{matches}");
    assert_eq!(matches[0]["namespace"], "mcp-pack", "{matches}");
    assert_eq!(scan["warnings"], json!([]), "{scan}");
    let error = call(&client, "capa_detect", json!({ "path": fixture("hello-x64.exe") })).await;
    assert_eq!(error.is_error, Some(true));
    assert!(text(&error).contains("no capa rules"), "{}", text(&error));
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[tokio::test]
async fn pack_problems_reach_agents_in_instructions_and_detection_warnings() {
    let directory = std::env::temp_dir().join(format!("rampage-mcp-broken-pack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("rampage-pack.toml"),
        "name = \"broken-pack\"\nversion = \"1\"\nlicense = \"MIT\"\nsource = \"test\"\ndescription = \"test\"\n\
         [[contents]]\nkind = \"yara\"\npath = \"broken.yar\"\n\
         [[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n",
    )
    .unwrap();
    std::fs::write(directory.join("broken.yar"), "rule broken {").unwrap();
    std::fs::write(directory.join("userdb.txt"), "[Pack MZ]\nsignature = 4D 5A\nep_only = false\n").unwrap();
    let packs = Arc::new(rampage_api::Packs::lazy(std::slice::from_ref(&directory)));
    let client = connect_to(RampageServer::with_groups(Group::ALL).with_packs(packs)).await;

    let instructions = client.peer_info().unwrap().instructions.clone().unwrap();
    assert!(instructions.contains("Data packs: 1 loaded, 1 problems"), "{instructions}");
    let path = fixture("hello-x64.exe");
    let rules = "rule user_mz { strings: $mz = \"MZ\" condition: $mz at 0 }";
    let scan = json_of(&call(&client, "yara_scan", json!({ "path": path, "rules": rules })).await);
    assert_eq!(scan["matches"][0]["identifier"], "user_mz", "{scan}");
    let warnings = scan["warnings"].as_array().unwrap();
    assert!(warnings.len() == 1 && warnings[0].as_str().unwrap().contains("yara broken.yar"), "{scan}");
    // The problem bears on YARA rules alone, not on the PeID signatures detect_tools consults.
    let detected = json_of(&call(&client, "detect_tools", json!({ "path": path })).await);
    assert_eq!(detected["warnings"], json!([]), "{detected}");
    client.cancel().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}
