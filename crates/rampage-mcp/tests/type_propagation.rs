use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

const CALLEE: &str = "0x201160";
const CALLER: &str = "0x201170";
const TYPES: &str = "struct PropState { int4 gain; int4 bias; }; \
                     struct OtherState { int4 first; int4 second; };";

#[derive(Default)]
struct Client;

impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-type-propagation-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let fixture = Self(directory);
        std::fs::write(fixture.path(), include_bytes!("../../../tests/data/type-propagation-x64.snapshot.json"))
            .unwrap();
        fixture
    }

    fn path(&self) -> PathBuf {
        self.0.join("owned.snapshot.json")
    }

    fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

async fn connect() -> RunningService<RoleClient, Client> {
    let (server, client) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server).await.unwrap().waiting().await.unwrap();
    });
    Client.serve(client).await.unwrap()
}

async fn invoke(client: &RunningService<RoleClient, Client>, name: &str, args: Value, succeeds: bool) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content[0].as_text().unwrap().text;
    assert_eq!(result.is_error == Some(true), !succeeds, "{name}: {text}");
    assert!(text.len() <= 60_000, "{name}: complete JSON must fit the response budget");
    if succeeds { serde_json::from_str(text).unwrap() } else { json!(text) }
}

async fn call(client: &RunningService<RoleClient, Client>, fixture: &Fixture, name: &str, mut args: Value) -> Value {
    args["path"] = json!(fixture.path());
    invoke(client, name, args, true).await
}

async fn enable(client: &RunningService<RoleClient, Client>) {
    invoke(client, "enable_tools", json!({"groups":["types"]}), true).await;
}

async fn annotations(client: &RunningService<RoleClient, Client>, fixture: &Fixture) -> Value {
    call(client, fixture, "list_annotations", json!({})).await
}

async fn decompile(client: &RunningService<RoleClient, Client>, fixture: &Fixture, at: &str) -> Value {
    call(client, fixture, "decompile", json!({"at":at,"view":"full"})).await
}

async fn file_sha256(client: &RunningService<RoleClient, Client>, fixture: &Fixture) -> String {
    let triage = call(client, fixture, "triage", json!({})).await;
    let hashes = if triage["file_hashes"].is_object() { &triage["file_hashes"] } else { &triage["image_hashes"] };
    let sha256 = hashes["sha256"].as_str().unwrap();
    assert_eq!(sha256.len(), 64);
    sha256.to_owned()
}

fn propagation_args(apply: bool) -> Value {
    json!({"at":CALLER,"apply":apply,"max_functions":4,"max_candidates":32})
}

fn first_parameter(value: &Value) -> &Value {
    value["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variable| {
            variable["kind"] == "parameter" && variable["editable"] == true && variable["name"] == "param_1"
        })
        .expect("select the native param_1 descriptor, not unsorted native parameter position")
}

fn hard_annotations(value: &Value) -> Value {
    let mut hard = value.clone();
    hard.as_object_mut().unwrap().remove("type_hints");
    hard
}

fn caller_parameter_candidate(candidate: &Value) -> bool {
    candidate["function"] == CALLER
        && candidate["target"]["kind"] == "parameter"
        && candidate["target"]["index"] == 0
        && candidate["data_type"].as_str().is_some_and(|name| name.contains("PropState"))
}

fn assert_native_parameter(value: &Value, expected: &str) {
    let parameter = value["structure"]["signature"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["storage"]["space"] == "register" && parameter["storage"]["address"] == "0x38")
        .expect("native first argument register must have a recovered parameter");
    assert!(parameter["data_type"]["name"].as_str().unwrap().contains(expected), "{value}");
    assert_eq!(parameter["data_type"]["size"], 8);
    let code = value["code"].as_str().unwrap();
    let declaration = code.split('{').next().unwrap();
    assert!(declaration.contains(expected), "{code}");
}

fn assert_native_caller(value: &Value) {
    assert_native_parameter(value, "PropState");
    let call = value["structure"]["calls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|call| call["target"] == CALLEE)
        .expect("native caller must retain the direct call to the typed callee");
    let argument = call["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|argument| argument["parameter_index"] == 0)
        .expect("native call must expose the first callee argument");
    assert!(argument["value"]["data_type"]["name"].as_str().unwrap().contains("PropState"), "{call}");
    assert_eq!(argument["value"]["data_type"]["size"], 8);
    assert!(argument["value"]["storage"].is_object(), "{call}");
    let name = argument["value"]["display_name"].as_str().unwrap();
    let code = value["code"].as_str().unwrap();
    let body = code.split_once('{').unwrap().1;
    assert!(body.contains(&format!("({name},")) || body.contains(&format!("({name})")), "{code}");
}

#[tokio::test]
async fn native_parameter_propagation_is_read_only_until_apply_durable_and_lower_priority_than_analyst_types() {
    let fixture = Fixture::new();
    let client = connect().await;
    enable(&client).await;
    let original_sha256 = file_sha256(&client, &fixture).await;
    call(&client, &fixture, "declare_types", json!({"declarations":TYPES})).await;
    let callee = decompile(&client, &fixture, CALLEE).await;
    let source = first_parameter(&callee);
    let storage = source["storage"].clone();
    let key: Value = serde_json::from_str(source["key"].as_str().unwrap()).unwrap();
    assert_eq!(key, storage);
    let edit =
        call(&client, &fixture, "edit_variable", json!({"at":CALLEE,"storage":storage,"data_type":"PropState *"}))
            .await;
    assert_eq!(edit["storage"], storage);
    assert!(edit["decompilation"]["code"].as_str().unwrap().contains("->gain"), "{edit}");

    let before = annotations(&client, &fixture).await;
    assert!(before["type_hints"].as_array().unwrap().is_empty());
    let files_before = fixture.files();
    assert!(files_before.keys().any(|path| path.extension().is_some_and(|extension| extension == "jsonl")));
    let preview = call(&client, &fixture, "propagate_types", propagation_args(false)).await;
    assert!(preview["candidates"].as_array().unwrap().iter().any(caller_parameter_candidate), "{preview}");
    let candidate =
        preview["candidates"].as_array().unwrap().iter().find(|row| caller_parameter_candidate(row)).unwrap();
    assert!(candidate["evidence"].as_array().unwrap().iter().any(|evidence| evidence["function"] == CALLEE));
    assert_eq!(preview["counts"]["applied"], 0);
    assert_eq!(preview["apply"], false);
    assert_eq!(preview["persisted"], false);
    assert!(!preview["hint_edits"].as_array().unwrap().is_empty());
    assert!(preview["hint_edits"].as_array().unwrap().iter().all(|edit| edit["previous"].is_null()));
    assert!(preview["applied"].as_array().unwrap().is_empty());
    assert!(preview["counts"]["functions"].as_u64().unwrap() <= 4);
    assert!(preview["counts"]["candidates"].as_u64().unwrap() <= 32);
    for field in ["candidates", "applied", "skipped", "conflicts"] {
        assert_eq!(preview["counts"][field].as_u64().unwrap(), preview[field].as_array().unwrap().len() as u64);
    }
    assert_eq!(annotations(&client, &fixture).await, before);
    assert_eq!(fixture.files(), files_before);

    for limits in [
        json!({"max_functions":0,"max_candidates":32}),
        json!({"max_functions":33,"max_candidates":32}),
        json!({"max_functions":4,"max_candidates":0}),
        json!({"max_functions":4,"max_candidates":257}),
    ] {
        let mut args = limits;
        args["path"] = json!(fixture.path());
        args["at"] = json!(CALLER);
        args["apply"] = json!(true);
        let refused = invoke(&client, "propagate_types", args, false).await;
        assert!(refused.as_str().unwrap().contains("propagation"), "{refused}");
        assert_eq!(fixture.files(), files_before);
    }
    assert_eq!(annotations(&client, &fixture).await, before);

    let applied = call(&client, &fixture, "propagate_types", propagation_args(true)).await;
    assert_eq!(applied["apply"], true);
    assert_eq!(applied["persisted"], true);
    assert_eq!(applied["hint_edits"], preview["hint_edits"]);
    assert_eq!(applied["counts"]["persisted_hint_edits"], applied["counts"]["planned_hint_edits"]);
    assert!(applied["applied"].as_array().unwrap().iter().any(caller_parameter_candidate), "{applied}");
    assert!(applied["counts"]["applied"].as_u64().unwrap() > 0, "{applied}");
    assert_eq!(applied["candidates"], preview["candidates"]);
    assert_eq!(applied["source_fingerprint"], preview["source_fingerprint"]);
    let accepted = annotations(&client, &fixture).await;
    assert_eq!(hard_annotations(&accepted), hard_annotations(&before));
    assert!(!accepted["type_hints"].as_array().unwrap().is_empty());
    let caller_hints = accepted["type_hints"].as_array().unwrap().iter().find(|row| row["address"] == CALLER).unwrap();
    let payload: Value = serde_json::from_str(caller_hints["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["source_fingerprint"], applied["source_fingerprint"]);
    assert!(
        payload["hints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hint| { hint["target"] == candidate["target"] && hint["data_type"] == candidate["data_type"] })
    );
    assert_native_caller(&decompile(&client, &fixture, CALLER).await);

    // Read-only automatic inference may keep the displayed type after durable hints are undone.
    call(&client, &fixture, "undo", json!({})).await;
    assert_eq!(annotations(&client, &fixture).await, before);
    call(&client, &fixture, "redo", json!({})).await;
    assert_eq!(annotations(&client, &fixture).await, accepted);
    client.cancel().await.unwrap();

    let reopened = connect().await;
    enable(&reopened).await;
    assert_eq!(annotations(&reopened, &fixture).await, accepted);
    let replayed = call(&reopened, &fixture, "decompile", json!({"at":CALLER,"exact_entry":true,"view":"full"})).await;
    assert_native_caller(&replayed);
    call(
        &reopened,
        &fixture,
        "set_signature",
        json!({"at":CALLER,"text":"int4 owned_caller(OtherState *owner, int4 value);"}),
    )
    .await;
    let overridden = annotations(&reopened, &fixture).await;
    assert_eq!(overridden["type_hints"], accepted["type_hints"]);
    assert_eq!(overridden["local_types"], accepted["local_types"]);
    let stale = call(&reopened, &fixture, "decompile", json!({"at":CALLER,"exact_entry":true,"view":"full"})).await;
    assert_native_parameter(&stale, "OtherState");
    assert!(stale["structure"]["diagnostics"].to_string().contains("stale derived type hints"), "{stale}");
    let preserved = call(&reopened, &fixture, "propagate_types", propagation_args(true)).await;
    assert_ne!(preserved["source_fingerprint"], applied["source_fingerprint"]);
    assert!(preserved["skipped"].as_array().unwrap().iter().any(|skip| skip["function"] == CALLER), "{preserved}");
    assert_eq!(hard_annotations(&annotations(&reopened, &fixture).await), hard_annotations(&overridden));
    assert_native_parameter(&decompile(&reopened, &fixture, CALLER).await, "OtherState");
    let source_after = decompile(&reopened, &fixture, CALLEE).await;
    assert_native_parameter(&source_after, "PropState");
    assert!(source_after["code"].as_str().unwrap().contains("->gain"), "{source_after}");
    assert_eq!(file_sha256(&reopened, &fixture).await, original_sha256);
    assert_eq!(
        std::fs::read(fixture.path()).unwrap(),
        include_bytes!("../../../tests/data/type-propagation-x64.snapshot.json")
    );
    reopened.cancel().await.unwrap();
}

#[tokio::test]
async fn propagation_schema_is_types_gated_and_exposes_bounded_preview_and_apply_arguments() {
    let client = connect().await;
    let denied = invoke(
        &client,
        "propagate_types",
        json!({"path":"/nonexistent/type-propagation-fixture","at":CALLER,"apply":false,
            "max_functions":4,"max_candidates":32}),
        false,
    )
    .await;
    assert!(denied.as_str().unwrap().contains("types"), "{denied}");
    enable(&client).await;
    let tools = client.list_all_tools().await.unwrap();
    let tool = tools.iter().find(|tool| tool.name == "propagate_types").unwrap();
    for field in ["path", "at", "apply", "max_functions", "max_candidates"] {
        assert!(tool.input_schema["properties"].get(field).is_some(), "missing {field}");
    }
    client.cancel().await.unwrap();
}
