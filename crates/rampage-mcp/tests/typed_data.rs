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
            "rampage-typed-data-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("owned.snapshot.json"),
            include_bytes!("../../../tests/data/typed-data-x64.snapshot.json"),
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
async fn call(
    client: &RunningService<RoleClient, Client>,
    fixture: &Fixture,
    name: &str,
    mut args: Value,
    success: bool,
) -> Value {
    args["path"] = json!(fixture.path());
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content[0].as_text().unwrap().text;
    assert_eq!(result.is_error == Some(true), !success, "{name}: {text}");
    assert!(text.len() <= 60_000);
    if success { serde_json::from_str(text).unwrap() } else { Value::Null }
}
async fn seed(client: &RunningService<RoleClient, Client>, fixture: &Fixture) {
    let enabled = client
        .call_tool(
            CallToolRequestParams::new("enable_tools")
                .with_arguments(json!({"groups":["types"]}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_ne!(enabled.is_error, Some(true));
    call(
        client,
        fixture,
        "declare_types",
        json!({"declarations":
        "enum TypedMode { MODE_OFF=0, MODE_READY=7, MODE_FAULT=-3 }; \
         struct TypedRecord { enum TypedMode mode; int4 value; char label[8]; };"}),
        true,
    )
    .await;
}

#[tokio::test]
async fn native_operand_annotations_render_without_modifying_raw_instructions_and_survive_replay() {
    let fixture = Fixture::new();
    let client = connect().await;
    seed(&client, &fixture).await;
    let before = call(&client, &fixture, "disassemble", json!({"at":"0x201180","count":5}), true).await;
    let applied = call(
        &client,
        &fixture,
        "apply_enum",
        json!({"at":"0x201182","operand":1,
        "type_name":"TypedMode"}),
        true,
    )
    .await;
    assert_eq!(applied["display"]["display"], "TypedMode::MODE_READY");
    assert_eq!(applied["display"]["matched"], true);
    let field = call(
        &client,
        &fixture,
        "apply_offset",
        json!({"at":"0x201187","operand":1,
        "type_name":"TypedRecord"}),
        true,
    )
    .await;
    assert_eq!(field["display"]["display"], "TypedRecord.value");
    let after = call(&client, &fixture, "disassemble", json!({"at":"0x201180","count":5}), true).await;
    for (old, new) in before.as_array().unwrap().iter().zip(after.as_array().unwrap()) {
        assert_eq!(old["bytes"], new["bytes"]);
        assert_eq!(old["text"], new["text"]);
    }
    assert_eq!(after[1]["operand_annotations"][0]["display"], "TypedMode::MODE_READY");
    assert_eq!(after[3]["operand_annotations"][0]["display"], "TypedRecord.value");
    let accepted = call(&client, &fixture, "list_annotations", json!({}), true).await;
    call(&client, &fixture, "apply_enum", json!({"at":"0x201182","operand":0,"type_name":"TypedMode"}), false).await;
    call(&client, &fixture, "apply_offset", json!({"at":"0x201182","operand":1,"type_name":"TypedRecord"}), false)
        .await;
    call(&client, &fixture, "delete_type", json!({"name":"TypedMode"}), false).await;
    assert_eq!(call(&client, &fixture, "list_annotations", json!({}), true).await, accepted);
    call(&client, &fixture, "undo", json!({}), true).await;
    call(&client, &fixture, "redo", json!({}), true).await;
    client.cancel().await.unwrap();
    let reopened = connect().await;
    let replayed = call(&reopened, &fixture, "disassemble", json!({"at":"0x201180","count":5}), true).await;
    assert_eq!(replayed[1]["operand_annotations"][0]["display"], "TypedMode::MODE_READY");
    assert_eq!(replayed[3]["operand_annotations"][0]["display"], "TypedRecord.value");
    reopened.cancel().await.unwrap();
}

fn field<'a>(report: &'a Value, suffix: &str) -> &'a Value {
    report["objects"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|object| object["fields"].as_array().unwrap())
        .find(|field| field["path"].as_str().is_some_and(|path| path.ends_with(suffix)))
        .unwrap_or_else(|| panic!("missing {suffix}: {report}"))
}

#[tokio::test]
async fn typed_arrays_strings_exact_integers_and_nonfinite_values_keep_bytes_and_replay() {
    let fixture = Fixture::new();
    let client = connect().await;
    seed(&client, &fixture).await;
    let applied = call(
        &client,
        &fixture,
        "apply_data_type",
        json!({"at":"0x200120",
        "type_name":"TypedRecord","count":2}),
        true,
    )
    .await;
    assert_eq!(applied["binding"]["byte_length"], 32);
    let report = call(&client, &fixture, "read_data", json!({"at":"0x200120","size":32}), true).await;
    assert_eq!(field(&report, "[0].value")["value"]["decimal"], "42");
    assert_eq!(field(&report, "[1].value")["value"]["decimal"], "-7");
    assert!(field(&report, "[0].mode")["value"]["enum_names"].as_array().unwrap().contains(&json!("MODE_READY")));
    assert!(field(&report, "[1].mode")["value"]["enum_names"].as_array().unwrap().contains(&json!("MODE_FAULT")));
    assert!(report["raw"]["spans"].as_array().unwrap().iter().all(|span| span["file_offset"].is_null()));
    for (at, encoding, length, expected) in
        [("0x200140", "utf8", 7, "Grüße"), ("0x200148", "utf16_le", 6, "A\u{1f680}")]
    {
        call(&client, &fixture, "apply_data_type", json!({"at":at,"encoding":encoding,"byte_length":length}), true)
            .await;
        let text = call(&client, &fixture, "read_data", json!({"at":at,"size":length}), true).await;
        assert_eq!(text["objects"][0]["fields"][0]["value"]["text"], expected);
    }
    call(&client, &fixture, "apply_data_type", json!({"at":"0x200150","type_name":"uint8"}), true).await;
    let integer = call(&client, &fixture, "read_data", json!({"at":"0x200150","size":8}), true).await;
    assert_eq!(integer["objects"][0]["fields"][0]["value"]["hex"], "0xfedcba9876543210");
    assert_eq!(integer["objects"][0]["fields"][0]["value"]["decimal"], 0xfedcba9876543210u64.to_string());
    call(&client, &fixture, "apply_data_type", json!({"at":"0x200158","type_name":"float4"}), true).await;
    let nan = call(&client, &fixture, "read_data", json!({"at":"0x200158","size":4}), true).await;
    assert_eq!(nan["objects"][0]["fields"][0]["value"]["display"], "NaN");
    assert_eq!(nan["objects"][0]["fields"][0]["value"]["finite"], false);
    let accepted = call(&client, &fixture, "list_annotations", json!({}), true).await;
    call(&client, &fixture, "delete_type", json!({"name":"TypedRecord"}), false).await;
    call(&client, &fixture, "apply_data_type", json!({"at":"0x201180","type_name":"uint4"}), false).await;
    assert_eq!(call(&client, &fixture, "list_annotations", json!({}), true).await, accepted);
    client.cancel().await.unwrap();
    let reopened = connect().await;
    let enabled = reopened
        .call_tool(
            CallToolRequestParams::new("enable_tools")
                .with_arguments(json!({"groups":["types"]}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_ne!(enabled.is_error, Some(true));
    let replayed = call(&reopened, &fixture, "read_data", json!({"at":"0x200120","size":32}), true).await;
    assert_eq!(field(&replayed, "[1].value")["value"]["decimal"], "-7");
    reopened.cancel().await.unwrap();
}
