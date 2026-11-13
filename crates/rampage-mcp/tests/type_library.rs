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
        Self::with("owned.snapshot.json", include_bytes!("../../../tests/data/local-variables-x64.snapshot.json"))
    }
    fn with(name: &str, bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-type-library-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join(name), bytes).unwrap();
        Self(directory.join(name))
    }
    fn path(&self) -> PathBuf {
        self.0.clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
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

/// `get_type` falls back to embedded DWARF when the library lacks a name, and selects members by path or offset.
#[tokio::test]
async fn get_type_reads_dwarf_layouts_without_importing() {
    let fixture = Fixture::with("debug-x64.elf", include_bytes!("../../../tests/fixtures/bin/debug-x64.elf"));
    let client = connect().await;
    enable(&client).await;
    let layout = invoke(&client, &fixture, "get_type", json!({"name": "debug_pair"}), true).await;
    assert_eq!(layout["source"], "dwarf", "{layout}");
    assert_eq!(layout["ambiguous"], false);
    let definition = &layout["definitions"][0];
    assert_eq!(
        (definition["type_name"].as_str(), definition["byte_size"].as_u64()),
        (Some("struct debug_pair"), Some(8))
    );
    let members: Vec<_> = definition["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| {
            (
                member["name"].as_str().unwrap(),
                member["offset"].as_u64().unwrap(),
                member["type_name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(members, [("first", 0, "int"), ("second", 4, "int")]);
    assert!(layout["work"]["dies_read"].as_u64().unwrap() > 0);

    let at =
        invoke(&client, &fixture, "get_type", json!({"name": "struct debug_pair", "byte_offset": "0x5"}), true).await;
    let selection = &at["definitions"][0]["selection"];
    assert_eq!(
        (selection["path"].as_str(), selection["offset"].as_u64(), selection["within"].as_u64()),
        (Some("second"), Some(4), Some(1))
    );
    assert!(at["definitions"][0].get("members").is_none(), "selection alone pages no members: {at}");

    let member = invoke(
        &client,
        &fixture,
        "get_type",
        json!({"name": "debug_pair", "member": "second", "source": "dwarf"}),
        true,
    )
    .await;
    assert_eq!(member["definitions"][0]["selection"]["byte_size"], 4);

    let paged =
        invoke(&client, &fixture, "get_type", json!({"name": "debug_pair", "offset": 1, "limit": 1}), true).await;
    assert_eq!(paged["definitions"][0]["members"][0]["name"], "second");
    assert_eq!(paged["definitions"][0]["total"], 2);

    invoke(&client, &fixture, "get_type", json!({"name": "debug_pair", "member": "third"}), false).await;
    invoke(&client, &fixture, "get_type", json!({"name": "debug_pair", "byte_offset": 8}), false).await;
    invoke(&client, &fixture, "get_type", json!({"name": "no_such_type"}), false).await;
    invoke(&client, &fixture, "get_type", json!({"name": "debug_pair", "source": "library"}), false).await;
    invoke(&client, &fixture, "get_type", json!({"name": "debug_pair", "source": "library", "member": "first"}), false)
        .await;
    // Nothing was imported: the library is still empty.
    let listed = invoke(&client, &fixture, "list_types", json!({}), true).await;
    assert!(listed["types"].as_array().unwrap().iter().all(|ty| ty["name"] != "debug_pair"), "{listed}");
}

/// On a stripped Go binary `get_type` falls back to Go runtime type metadata, and `list_types` lists Go types while
/// the project library is empty.
#[tokio::test]
async fn get_type_reads_go_runtime_types_on_a_stripped_go_binary() {
    let fixture =
        Fixture::with("gotypes-go1.20-x64.elf", include_bytes!("../../../tests/fixtures/bin/gotypes-go1.20-x64.elf"));
    let client = connect().await;
    enable(&client).await;

    let record = invoke(&client, &fixture, "get_type", json!({"name": "main.Record"}), true).await;
    assert_eq!(record["source"], "go_runtime");
    assert!(record["caveats"].as_array().is_some_and(|caveats| !caveats.is_empty()));
    let definition = &record["definitions"][0];
    assert_eq!((definition["kind"].as_str(), definition["byte_size"].as_u64()), (Some("struct"), Some(144)));
    assert_eq!(definition["members"][3]["name"], "Inner");
    assert_eq!(definition["members"][3]["offset"], 56);

    let selected =
        invoke(&client, &fixture, "get_type", json!({"name": "main.Record", "member": "Inner.Ratio"}), true).await;
    assert_eq!(selected["definitions"][0]["selection"]["offset"], 64);
    assert!(selected["definitions"][0].get("members").is_none(), "selection alone pages no members");
    let at =
        invoke(&client, &fixture, "get_type", json!({"name": "main.Record", "byte_offset": "\"0x31\""}), true).await;
    assert_eq!(at["definitions"][0]["selection"]["path"], "flags");

    let shape = invoke(&client, &fixture, "get_type", json!({"name": "main.Shape", "source": "go"}), true).await;
    assert_eq!(shape["definitions"][0]["methods"][1]["name"], "Name");

    // An unknown name reports every source it tried and suggests Go names; source=dwarf does not fall back.
    let (text, failed) = call_text(&client, &fixture, "get_type", json!({"name": "main.Recor"})).await;
    assert!(failed && text.contains("no Go runtime type named") && text.contains("main.Record"), "{text}");
    assert!(text.contains("project type library has no type") && text.contains("Next: list_types"), "{text}");
    assert!(!text.contains("Unknown named type"), "{text}");
    invoke(&client, &fixture, "get_type", json!({"name": "main.Record", "source": "dwarf"}), false).await;
    invoke(&client, &fixture, "get_type", json!({"name": "main.Record", "source": "library"}), false).await;

    let listed = invoke(&client, &fixture, "list_types", json!({"contains": "main.R"}), true).await;
    assert_eq!(listed["source"], "go_runtime");
    assert_eq!(listed["types"][0]["name"], "main.Record");
    let library = invoke(&client, &fixture, "list_types", json!({"source": "library"}), true).await;
    assert_eq!(library["total"], 0);
    client.cancel().await.unwrap();
}

async fn call_text(
    client: &RunningService<RoleClient, Client>,
    fixture: &Fixture,
    name: &str,
    mut args: Value,
) -> (String, bool) {
    args["path"] = json!(fixture.path());
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    (result.content[0].as_text().unwrap().text.clone(), result.is_error == Some(true))
}
