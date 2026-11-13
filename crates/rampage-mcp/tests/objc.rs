//! Objective-C message sends over MCP on the stripped arm64 fixture (tests/fixtures/objc-dispatch): the
//! `objc_sends` listing, objc-dispatch xref edges, function_summary callees, listing comments, decompiled C
//! comments and selector stub names.

use std::path::PathBuf;

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

async fn call(client: &Client, name: &str, arguments: Value) -> Value {
    let result: CallToolResult = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = result.content.first().unwrap().as_text().unwrap().text.as_str();
    assert_ne!(result.is_error, Some(true), "{name}: {text}");
    serde_json::from_str(text).unwrap()
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    path.to_str().unwrap().to_owned()
}

fn names(rows: &Value, key: &str) -> Vec<String> {
    rows.as_array().unwrap().iter().filter_map(|row| row[key].as_str().map(str::to_owned)).collect()
}

#[tokio::test]
async fn objc_sends_resolve_to_methods_across_tools() {
    let client = connect().await;
    let path = fixture("objc-dispatch-arm64-stripped.macho");

    let all = call(&client, "objc_sends", json!({ "path": path, "limit": 500 })).await;
    let summary = &all["summary"];
    assert_eq!(summary["sends"], 32, "{summary}");
    assert_eq!(summary["with_selector"], 32, "{summary}");
    assert_eq!(summary["unknown_selector"], 0, "{summary}");
    assert_eq!(summary["selector_stubs"], 16, "{summary}");
    assert_eq!(all["sends"]["total"], 32);

    // [self area] in -[Shape scaledArea]: Circle and Square override it, so all three are reachable.
    let area =
        call(&client, "objc_sends", json!({ "path": path, "at": "-[Shape scaledArea]", "selector": "area" })).await;
    let send = &area["sends"]["items"][0];
    assert_eq!(send["confidence"], "ambiguous", "{send}");
    assert_eq!(send["receiver"]["class"], "Shape");
    assert_eq!(send["receiver"]["source"], "self");
    assert_eq!(names(&send["targets"], "name"), ["-[Shape area]", "-[Circle area]", "-[Square area]"]);

    // [super describe] in -[Circle describe] is an edge to -[Shape describe]; so is the category's [self describe].
    let callers = call(&client, "xrefs", json!({ "path": path, "to": "-[Shape describe]" })).await;
    let edges: Vec<&Value> =
        callers["items"].as_array().unwrap().iter().filter(|row| row["objc"].is_object()).collect();
    let from: Vec<&str> = edges.iter().map(|row| row["from_function"].as_str().unwrap()).collect();
    // The arm64 link merges the Debug category into Shape, so its method is named as Shape's own.
    assert!(from.contains(&"-[Circle describe]") && from.contains(&"-[Shape dump]"), "{callers}");
    let super_edge = edges.iter().find(|row| row["from_function"] == "-[Circle describe]").unwrap();
    assert_eq!(super_edge["kind"], "call");
    assert_eq!(super_edge["objc"]["confidence"], "resolved");
    assert_eq!(super_edge["objc"]["selector"], "describe");
    assert_eq!(super_edge["objc"]["receiver"], "Shape");

    // The class method send in -[Shape describe] reaches both +kind implementations.
    let summary =
        call(&client, "function_summary", json!({ "path": path, "at": "-[Shape describe]", "view": "summary" })).await;
    let callees = names(&summary["callees"], "name");
    assert!(callees.iter().any(|name| name == "+[Shape kind]"), "{callees:?}");
    assert!(callees.iter().any(|name| name == "+[Circle kind]"), "{callees:?}");
    assert!(callees.iter().any(|name| name == "_objc_msgSend$kind"), "{callees:?}");

    // The listing comments each send site.
    let graph = call(&client, "function_graph", json!({ "path": path, "at": "-[Circle describe]" })).await;
    let comments: Vec<String> = graph["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|block| block["lines"].as_array().unwrap())
        .filter_map(|line| line["comment"].as_str().map(str::to_owned))
        .collect();
    assert!(
        comments.iter().any(|comment| comment.contains("objc: [(Shape *) describe] -> -[Shape describe]")),
        "{comments:?}"
    );

    // Decompiled C names the selector and implementation at the send.
    let decompiled = call(&client, "decompile", json!({ "path": path, "at": "entry", "view": "code" })).await;
    let code = decompiled["code"].as_str().unwrap();
    assert!(code.contains("/* objc: [Square squareWithSide:] -> +[Square squareWithSide:] */"), "{code}");
    assert!(code.contains("_objc_msgSend$squareWithSide:"), "{code}");
}

#[tokio::test]
async fn binaries_without_objective_c_have_no_sends() {
    let client = connect().await;
    let sends = call(&client, "objc_sends", json!({ "path": fixture("hello-x64.elf") })).await;
    assert_eq!(sends["summary"]["sends"], 0);
    assert_eq!(sends["sends"]["items"], json!([]));
    let xrefs = call(&client, "xrefs", json!({ "path": fixture("hello-x64.elf"), "from": "main" })).await;
    assert!(xrefs["items"].as_array().unwrap().iter().all(|row| row.get("objc").is_none()));
}
