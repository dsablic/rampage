use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
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

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-type-library-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("owned.snapshot.json"),
            include_bytes!("../../../tests/data/local-variables-x64.snapshot.json"),
        )
        .unwrap();
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("owned.snapshot.json")
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

async fn invoke(
    client: &RunningService<RoleClient, Client>,
    fixture: &Fixture,
    name: &str,
    mut args: Value,
    succeeds: bool,
) -> Value {
    args["path"] = json!(fixture.path());
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content[0].as_text().unwrap().text;
    assert_eq!(result.is_error == Some(true), !succeeds, "{name}: {text}");
    assert!(text.len() <= 60_000, "{name}: result must retain valid bounded JSON");
    if succeeds { serde_json::from_str(text).unwrap() } else { Value::Null }
}

async fn enable(client: &RunningService<RoleClient, Client>) {
    let result = client
        .call_tool(
            CallToolRequestParams::new("enable_tools")
                .with_arguments(json!({"groups":["types"]}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true));
}

fn fields(value: &Value) {
    assert_eq!(value["size"], 8);
    let fields = value["fields"].as_array().unwrap();
    for (name, offset) in [("gain", 0), ("bias", 4)] {
        assert!(fields.iter().any(|field| field["name"] == name && field["offset"] == offset), "{value}");
    }
}

#[tokio::test]
async fn named_library_drives_native_layout_and_local_types_with_dependency_checked_delete_and_replay() {
    let fixture = Fixture::new();
    let client = connect().await;
    enable(&client).await;
    invoke(&client, &fixture, "get_type", json!({"name":"LibraryState"}), false).await;
    invoke(
        &client,
        &fixture,
        "declare_types",
        json!({"declarations":
        "struct LibraryState { int4 gain; int4 bias; }; typedef LibraryState *LibraryStatePtr; \
         enum LibraryMode { LibraryOff=0, LibraryOn=3 }; struct LibraryScratch { int4 spare; };"}),
        true,
    )
    .await;
    fields(&invoke(&client, &fixture, "get_type", json!({"name":"LibraryState"}), true).await);
    assert_eq!(invoke(&client, &fixture, "get_type", json!({"name":"LibraryStatePtr"}), true).await["size"], 8);
    invoke(&client, &fixture, "delete_type", json!({"name":"LibraryState"}), false).await;
    let edit = invoke(
        &client,
        &fixture,
        "edit_variable",
        json!({"at":"0x4000ae","variable":"piStack_10",
        "name":"state","data_type":"struct LibraryState *"}),
        true,
    )
    .await;
    let text = edit["decompilation"]["code"].as_str().unwrap();
    assert!(text.contains("state->gain") && text.contains("state->bias"), "{text}");
    let accepted = invoke(&client, &fixture, "list_annotations", json!({}), true).await;
    for args in [
        json!({"declarations":"struct LibraryState { int8 gain; int8 bias; };"}),
        json!({"declarations":"struct BadState { MissingType impossible; };"}),
        json!({"header":"#include \"/etc/passwd\"\nstruct BadHeader { int4 value; };"}),
    ] {
        invoke(&client, &fixture, "declare_types", args, false).await;
    }
    assert_eq!(invoke(&client, &fixture, "list_annotations", json!({}), true).await, accepted);
    invoke(&client, &fixture, "delete_type", json!({"name":"LibraryStatePtr"}), true).await;
    invoke(&client, &fixture, "delete_type", json!({"name":"LibraryState"}), false).await;
    invoke(&client, &fixture, "undo", json!({}), true).await;
    assert_eq!(invoke(&client, &fixture, "get_type", json!({"name":"LibraryStatePtr"}), true).await["size"], 8);
    invoke(&client, &fixture, "delete_type", json!({"name":"LibraryScratch"}), true).await;
    invoke(&client, &fixture, "get_type", json!({"name":"LibraryScratch"}), false).await;
    client.cancel().await.unwrap();
    let reopened = connect().await;
    enable(&reopened).await;
    fields(&invoke(&reopened, &fixture, "get_type", json!({"name":"LibraryState"}), true).await);
    let replayed = invoke(&reopened, &fixture, "decompile", json!({"at":"0x4000ae","view":"code"}), true).await;
    assert!(replayed["code"].as_str().unwrap().contains("state->gain"));
    reopened.cancel().await.unwrap();
}

#[tokio::test]
async fn inline_headers_report_real_packing_and_function_pointer_layout_without_external_include_access() {
    let fixture = Fixture::new();
    let client = connect().await;
    enable(&client).await;
    invoke(
        &client,
        &fixture,
        "declare_types",
        json!({"header":
        "/* owned C header */\n#pragma pack(push,1)\nstruct PackedHeader { uint1 tag; uint4 value; };\n\
         #pragma pack(pop)\ntypedef int4 (*LibraryCallback)(int4 input);\n"}),
        true,
    )
    .await;
    let packed = invoke(&client, &fixture, "get_type", json!({"name":"PackedHeader"}), true).await;
    assert_eq!(packed["size"], 5);
    assert!(
        packed["fields"].as_array().unwrap().iter().any(|field| field["name"] == "value" && field["offset"] == 1),
        "{packed}"
    );
    let callback = invoke(&client, &fixture, "get_type", json!({"name":"LibraryCallback"}), true).await;
    assert_eq!(callback["size"], 8);
    let before = invoke(&client, &fixture, "list_annotations", json!({}), true).await;
    invoke(&client, &fixture, "declare_types", json!({"header":"#include <unsupported-sdk.h>\n"}), false).await;
    assert_eq!(invoke(&client, &fixture, "list_annotations", json!({}), true).await, before);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn source_header_matches_compiler_sizeof_and_offsetof_table_including_forward_references() {
    let fixture = Fixture::new();
    let client = connect().await;
    enable(&client).await;
    invoke(
        &client,
        &fixture,
        "declare_types",
        json!({"header":
        include_str!("../../../tests/fixtures/src/type-library.h")}),
        true,
    )
    .await;
    let record = invoke(&client, &fixture, "get_type", json!({"name":"TypeLibraryRecord"}), true).await;
    assert_eq!(record["size"], 32);
    for (name, offset) in [("kind", 0), ("mode", 4), ("payload", 8), ("callback", 16), ("next", 24)] {
        assert!(
            record["fields"].as_array().unwrap().iter().any(|field| field["name"] == name && field["offset"] == offset),
            "{record}"
        );
    }
    for (name, size, field, offset) in [
        ("TypeLibraryPacked", 7, "identifier", 1),
        ("TypeLibraryPackTwo", 6, "value", 2),
        ("TypeLibraryRestoredPackOne", 5, "value", 1),
        ("TypeLibraryNatural", 8, "value", 4),
    ] {
        let native = invoke(&client, &fixture, "get_type", json!({"name":name}), true).await;
        assert_eq!(native["size"], size, "{name}: {native}");
        assert!(
            native["fields"].as_array().unwrap().iter().any(|row| row["name"] == field && row["offset"] == offset),
            "{native}"
        );
        if name == "TypeLibraryPacked" {
            assert!(
                native["fields"].as_array().unwrap().iter().any(|row| row["name"] == "flags" && row["offset"] == 5),
                "{native}"
            );
        }
    }
    let factory = invoke(&client, &fixture, "get_type", json!({"name":"TypeLibraryFactory"}), true).await;
    assert_eq!(factory["callback"]["return_type"], "TypeLibraryRecord");
    assert_eq!(factory["callback"]["parameters"].as_array().unwrap().len(), 1);
    assert_eq!(factory["callback"]["parameters"][0]["name"], "count");
    let by_value = invoke(&client, &fixture, "get_type", json!({"name":"TypeLibraryByValue"}), true).await;
    assert_eq!(by_value["callback"]["parameters"].as_array().unwrap().len(), 1);
    assert_eq!(by_value["callback"]["parameters"][0]["type_name"], "TypeLibraryRecord");
    invoke(&client, &fixture, "delete_type", json!({"name":"TypeLibraryFactory"}), true).await;
    invoke(&client, &fixture, "delete_type", json!({"name":"TypeLibraryByValue"}), true).await;
    invoke(&client, &fixture, "delete_type", json!({"name":"TypeLibraryRecord"}), false).await;
    invoke(
        &client,
        &fixture,
        "declare_types",
        json!({"declarations":
        "struct LibraryExternalReference { TypeLibraryRecord *record; };"}),
        true,
    )
    .await;
    invoke(&client, &fixture, "delete_type", json!({"name":"TypeLibraryRecord","definition_group":true}), false).await;
    invoke(&client, &fixture, "delete_type", json!({"name":"LibraryExternalReference"}), true).await;
    let removed =
        invoke(&client, &fixture, "delete_type", json!({"name":"TypeLibraryRecord","definition_group":true}), true)
            .await;
    for name in ["TypeLibraryRecord", "TypeLibraryCallback"] {
        assert!(removed["removed"].as_array().unwrap().iter().any(|removed| removed == name));
        invoke(&client, &fixture, "get_type", json!({"name":name}), false).await;
    }
    invoke(&client, &fixture, "undo", json!({}), true).await;
    assert_eq!(invoke(&client, &fixture, "get_type", json!({"name":"TypeLibraryRecord"}), true).await["size"], 32);
    client.cancel().await.unwrap();
}
