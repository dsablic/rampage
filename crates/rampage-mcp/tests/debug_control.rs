#![cfg(unix)]

//! The `debug` group through MCP, against the scripted fake stub, which fails a test on any execution-control
//! packet.

use std::os::unix::fs::DirBuilderExt;

use rampage_api::DebugRegistry;
use rampage_api::tools::Group;
use rampage_debug::fake::{FakeStub, Report, transcripts};
use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

const DEBUG_TOOLS: [&str; 7] = [
    "debug_connect",
    "debug_disconnect",
    "debug_modules",
    "debug_read_memory",
    "debug_registers",
    "debug_snapshot",
    "debug_status",
];

async fn connect(server: RampageServer) -> RunningService<RoleClient, ()> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, ()>, tool: &str, arguments: Value) -> CallToolResult {
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

async fn names(client: &RunningService<RoleClient, ()>) -> Vec<String> {
    client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect()
}

async fn finish(stub: FakeStub) -> Report {
    tokio::task::spawn_blocking(move || stub.finish()).await.unwrap()
}

#[tokio::test]
async fn without_an_endpoint_there_is_no_debug_group() {
    let client = connect(RampageServer::with_groups(Group::ALL)).await;
    let listed = names(&client).await;
    assert!(!listed.iter().any(|name| name.starts_with("debug_")), "{listed:?}");
    let listing = json_of(&call(&client, "enable_tools", json!({})).await);
    assert!(!listing["groups"].as_array().unwrap().iter().any(|group| group["name"] == "debug"));
    let refused = call(&client, "enable_tools", json!({ "groups": ["debug"] })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("unknown tool group `debug`"));
    let unknown = call(&client, "debug_connect", json!({})).await;
    assert_eq!(unknown.is_error, Some(true));
    assert!(text(&unknown).contains("unknown tool debug_connect"), "{}", text(&unknown));
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap_or_default();
    assert!(!instructions.contains("debug_connect"));
    assert!(rampage_mcp::debug_registry(&[], None).unwrap().is_none());
    assert!(rampage_mcp::debug_registry(&[], Some(" , ")).unwrap().is_none());
    assert!(rampage_mcp::debug_registry(&["bogus".into()], None).is_err());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn debug_tools_inspect_snapshot_and_detach_through_mcp() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let registry = rampage_mcp::debug_registry(&[], Some(&format!("{}, unix:/nonexistent/x.sock", stub.endpoint())))
        .unwrap()
        .unwrap();
    let client = connect(RampageServer::default().with_debug(registry)).await;
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap();
    assert!(instructions.contains(stub.endpoint()) && instructions.contains("- debug: "));

    // Listed by enable_tools, but not callable until enabled.
    let listing = json_of(&call(&client, "enable_tools", json!({})).await);
    let group = listing["groups"].as_array().unwrap().iter().find(|group| group["name"] == "debug").unwrap();
    assert_eq!(group["enabled"], false);
    assert_eq!(group["tool_count"], 7);
    assert!(!names(&client).await.iter().any(|name| name.starts_with("debug_")));
    let disabled = call(&client, "debug_connect", json!({})).await;
    assert!(text(&disabled).contains("not enabled"));
    json_of(&call(&client, "enable_tools", json!({ "groups": ["debug"] })).await);
    let mut listed: Vec<String> = names(&client).await.into_iter().filter(|name| name.starts_with("debug_")).collect();
    listed.sort();
    assert_eq!(listed, DEBUG_TOOLS);

    // Several endpoints are allowed, so one must be named, and only a listed one.
    assert!(text(&call(&client, "debug_connect", json!({})).await).starts_with("invalid_argument"));
    let refused = call(&client, "debug_connect", json!({ "endpoint": "127.0.0.1:1" })).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).starts_with("endpoint_not_allowed"));
    let connected = json_of(&call(&client, "debug_connect", json!({ "endpoint": stub.endpoint() })).await);
    assert_eq!(connected["session"], "s1");
    assert_eq!(connected["endianness"], "little");

    let registers = json_of(&call(&client, "debug_registers", json!({ "session": "s1", "names": ["pc", "sp"] })).await);
    assert_eq!(registers["registers"]["items"][0]["value"], "0x20010000");
    let memory =
        json_of(&call(&client, "debug_read_memory", json!({ "session": "s1", "address": "0x0", "length": 8 })).await);
    assert_eq!(memory["data"][0]["hex"], "0000012049000000");
    let modules = json_of(&call(&client, "debug_modules", json!({ "session": "s1" })).await);
    assert_eq!(modules["regions"].as_array().unwrap().len(), 2);
    let unknown = call(&client, "debug_status", json!({ "session": "s7" })).await;
    assert!(text(&unknown).starts_with("unknown_session"));

    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-debug-mcp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let output = directory.join("capture.json");
    let snapshot = json_of(
        &call(
            &client,
            "debug_snapshot",
            json!({ "session": "s1", "output": output, "ranges": [{ "address": "0x0", "length": 8, "permissions": "r-x" }] }),
        )
        .await,
    );
    assert_eq!(snapshot["status"], "published");
    // The snapshot opens with the ordinary tools.
    let info = json_of(&call(&client, "binary_info", json!({ "path": output })).await);
    assert_eq!(info["arch"], "arm");

    // Closing the MCP connection detaches the open session.
    client.cancel().await.unwrap();
    let report = finish(stub).await;
    report.assert_clean();
    assert_eq!(report.received.last().map(String::as_str), Some("D;1"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn disconnect_detaches_and_forgets_the_session() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    let client = connect(RampageServer::with_groups([Group::Core]).with_debug(registry)).await;
    json_of(&call(&client, "enable_tools", json!({ "groups": ["all"] })).await);
    json_of(&call(&client, "debug_connect", json!({})).await);
    let status = json_of(&call(&client, "debug_status", json!({ "session": "s1" })).await);
    assert_eq!(status["state"], "stopped");
    let disconnected = json_of(&call(&client, "debug_disconnect", json!({ "session": "s1" })).await);
    assert_eq!(disconnected["state"], "detached");
    assert!(text(&call(&client, "debug_status", json!({ "session": "s1" })).await).starts_with("unknown_session"));
    client.cancel().await.unwrap();
    let report = finish(stub).await;
    report.assert_clean();
    assert_eq!(report.received.iter().filter(|packet| packet.starts_with('D')).count(), 1);
}

#[test]
fn debug_endpoint_lists_tolerate_spacing_and_empty_entries() {
    let endpoints = |flags: &[&str], env: Option<&str>| {
        let flags: Vec<String> = flags.iter().map(|flag| (*flag).to_owned()).collect();
        rampage_mcp::debug_registry(&flags, env).map(|registry| registry.map(|registry| registry.endpoints()))
    };
    assert_eq!(endpoints(&[], None), Ok(None));
    assert_eq!(endpoints(&[" "], Some(",, ,")), Ok(None));
    assert_eq!(
        endpoints(&["127.0.0.1:2345"], Some(" 127.0.0.1:1234 ,unix:/run/stub.sock,\t,")),
        Ok(Some(vec!["127.0.0.1:2345".into(), "127.0.0.1:1234".into(), "unix:/run/stub.sock".into()]))
    );
    // The same endpoint listed twice is allowed once, as first written.
    assert_eq!(
        endpoints(&["[::1]:2345"], Some("[::1]:2345, 127.0.0.1:1")),
        Ok(Some(vec!["[::1]:2345".into(), "127.0.0.1:1".into()]))
    );
    for env in ["127.0.0.1", "host:0", "unix:relative", "127.0.0.1:2345 127.0.0.1:2346", "a b:1"] {
        assert!(endpoints(&[], Some(env)).is_err(), "{env}");
    }
}
