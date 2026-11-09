#![cfg(unix)]

use std::fs::{DirBuilder, Permissions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Value, json};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Socket {
    directory: PathBuf,
    pub(crate) path: PathBuf,
    listener: Option<UnixListener>,
}

impl Socket {
    pub(crate) fn new() -> Self {
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rmq-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        Self { directory, path, listener: Some(listener) }
    }

    pub(crate) fn serve(&mut self, run: impl FnOnce(Value) -> Value + Send + 'static) -> std::thread::JoinHandle<()> {
        let listener = self.listener.take().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let mut trailing = Vec::new();
            reader.read_to_end(&mut trailing).unwrap();
            assert!(trailing.is_empty());
            let mut stream = reader.into_inner();
            let _ = writeln!(stream, "{}", run(request));
        })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

async fn connect(server: RampageServer) -> RunningService<RoleClient, ()> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, ()>, name: &str, input: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(input.as_object().unwrap().clone()))
        .await
        .unwrap()
}

fn text(result: &CallToolResult) -> &str {
    &result.content[0].as_text().unwrap().text
}

pub(crate) fn response() -> Value {
    json!({"protocol":"rampage-lldb-query-v1","ok":true,"operation":"describe_session",
        "token":{"backend":"lldb-sb","session_id":"mcp-test","process_unique_id":7,"stop_id":3,"target_index":0},
        "data":{"state":"stopped","stop_evidence":{"source":"SBThread.GetStopReason/current-process-stop",
                "is_stopped":false,"stop_reason":3}},
        "observation":{"content_sha256":"0".repeat(64),"consistency":"revalidated-non-atomic",
                       "atomic_snapshot":false,"identity_scope":"content hash is not stop identity"}})
}

#[tokio::test]
async fn runtime_opt_in_and_explicit_socket_schema_run_no_image_or_sidecar_work() {
    let client = connect(RampageServer::default()).await;
    assert!(!client.list_all_tools().await.unwrap().iter().any(|tool| tool.name == "query_debugger"));
    let mut socket = Socket::new();
    let input = json!({"socket":socket.path,"request":{"version":1,"operation":"describe_session"}});
    let refused = call(&client, "query_debugger", input.clone()).await;
    assert_eq!(refused.is_error, Some(true));
    assert!(text(&refused).contains("runtime") && text(&refused).contains("not enabled"));
    call(&client, "enable_tools", json!({"groups":["runtime"]})).await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "query_debugger").unwrap();
    let schema = serde_json::to_value(&tool.input_schema).unwrap();
    assert!(schema["required"].as_array().unwrap().contains(&json!("socket")));
    assert!(schema["required"].as_array().unwrap().contains(&json!("request")));
    assert!(schema["properties"].get("path").is_none() && schema["properties"].get("arch").is_none());
    assert_eq!(schema["additionalProperties"], false);
    for invalid in [
        json!({"request":{"version":1,"operation":"describe_session"}}),
        json!({"socket":socket.path,"request":{"version":1,"operation":"continue"}}),
        json!({"socket":socket.path,"request":{"version":1,"operation":"describe_session"},
                           "path":"/must/not/open"}),
    ] {
        let result = call(&client, "query_debugger", invalid).await;
        assert_eq!(result.is_error, Some(true));
        assert!(text(&result).contains("invalid arguments"));
    }
    let server = socket.serve(|request| {
        assert_eq!(request["operation"], "describe_session");
        assert!(request["response_budget"].as_u64().unwrap() <= 60000);
        response()
    });
    let result = call(&client, "query_debugger", input).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let value: Value = serde_json::from_str(text(&result)).unwrap();
    assert_eq!(value, response());
    assert_eq!(value["data"]["stop_evidence"]["is_stopped"], false);
    server.join().unwrap();
    assert_eq!(std::fs::read_dir(&socket.directory).unwrap().count(), 1);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn actual_mcp_route_bounds_results_without_invalid_json_truncation() {
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let invalid = call(
        &client,
        "query_debugger",
        json!({"socket":"/must/not/connect",
        "request":{"version":1,"operation":"x".repeat(70000)}}),
    )
    .await;
    assert_eq!(invalid.is_error, Some(true));
    assert!(text(&invalid).len() < 60000 && text(&invalid).contains("input byte limit"));
    for length in [59000, 61000] {
        let mut socket = Socket::new();
        let server = socket.serve(move |request| {
            assert!(request["response_budget"].as_u64().unwrap() <= 60000);
            let mut value = response();
            value["data"]["padding"] = json!("a".repeat(length));
            value
        });
        let result = call(
            &client,
            "query_debugger",
            json!({"socket":socket.path,
            "request":{"version":1,"operation":"describe_session","response_budget":262144}}),
        )
        .await;
        assert!(text(&result).len() <= 60000);
        assert!(!text(&result).contains("truncated"));
        if length < 60000 {
            assert_ne!(result.is_error, Some(true), "{}", text(&result));
            let value: Value = serde_json::from_str(text(&result)).unwrap();
            assert_eq!(value["data"]["padding"].as_str().unwrap().len(), length);
        } else {
            assert_eq!(result.is_error, Some(true));
            assert!(text(&result).contains("budget"));
        }
        server.join().unwrap();
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn backend_failure_remains_json_and_an_mcp_error() {
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    for operation in [json!("describe_session"), Value::Null] {
        let mut socket = Socket::new();
        let expected = json!({"protocol":"rampage-lldb-query-v1","ok":false,"operation":operation,
                         "error":{"code":"state_changed","message":"backend lost stop context"}});
        let sent = expected.clone();
        let server = socket.serve(move |_| sent);
        let result = call(
            &client,
            "query_debugger",
            json!({"socket":socket.path,
        "request":{"version":1,"operation":"describe_session"}}),
        )
        .await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(serde_json::from_str::<Value>(text(&result)).unwrap(), expected);
        server.join().unwrap();
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn module_resolution_uses_shared_schema_budget_and_raw_qualified_results() {
    let client = connect(RampageServer::with_groups([Group::Runtime])).await;
    let tools = client.list_all_tools().await.unwrap();
    let schema =
        serde_json::to_value(&tools.iter().find(|tool| tool.name == "query_debugger").unwrap().input_schema).unwrap();
    assert!(schema.to_string().contains("resolve_module_address"));
    let base = json!({"version":1,"operation":"resolve_module_address","expected_token":response()["token"],
        "module_uuid":"01234567-89ab-cdef-0123-456789abcdef","file_address":"0x100000004"});
    let mut socket = Socket::new();
    for (field, value) in [
        ("module_uuid", json!("same")),
        ("expected_token", Value::Null),
        ("file_address", json!(u64::MAX)),
        ("path", json!("/must/not/open")),
    ] {
        let mut invalid = base.clone();
        invalid[field] = value;
        let result = call(&client, "query_debugger", json!({"socket":socket.path,"request":invalid})).await;
        assert_eq!(result.is_error, Some(true));
    }
    socket.listener.as_ref().unwrap().set_nonblocking(true).unwrap();
    assert!(socket.listener.as_ref().unwrap().accept().is_err());
    socket.listener.as_ref().unwrap().set_nonblocking(false).unwrap();
    let sent = base.clone();
    let server = socket.serve(move |request| {
        assert_eq!(request["module_uuid"], sent["module_uuid"]);
        assert_eq!(request["file_address"], sent["file_address"]);
        assert_eq!(request["expected_token"], sent["expected_token"]);
        assert!(request["response_budget"].as_u64().unwrap() <= 60000);
        let mut result = response();
        result["operation"] = json!("resolve_module_address");
        result["data"] = json!({"module_uuid":request["module_uuid"],"load_address":"0x1804",
            "file_address":"0x100000004","proven_flow":false,"proven_layout":false});
        result
    });
    let result = call(&client, "query_debugger", json!({"socket":socket.path,"request":base})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let value: Value = serde_json::from_str(text(&result)).unwrap();
    assert_eq!(value["data"]["load_address"], "0x1804");
    assert_eq!(value["data"]["proven_flow"], false);
    assert_eq!(value["observation"]["atomic_snapshot"], false);
    server.join().unwrap();
    assert_eq!(std::fs::read_dir(&socket.directory).unwrap().count(), 1);
    client.cancel().await.unwrap();
}
