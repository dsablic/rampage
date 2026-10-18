//! Native search requests over the real MCP duplex transport; owned fixture bytes are never executed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Default)]
struct TestClient;
impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}
type Client = RunningService<RoleClient, TestClient>;

struct Server(JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Connection {
    client: Option<Client>,
    server: Server,
}
impl Connection {
    async fn connect() -> Self {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = Server(tokio::spawn(async move {
            RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
        }));
        let client = timeout(TIMEOUT, TestClient.serve(client_transport)).await.unwrap().unwrap();
        let listed = timeout(TIMEOUT, client.list_all_tools()).await.unwrap().unwrap();
        let tool =
            listed.iter().find(|tool| tool.name == "search").expect("search belongs to the initial core tool list");
        assert!(tool.input_schema["properties"].get("mode").is_some());
        let connection = Self { client: Some(client), server };
        body(&connection.call("enable_tools", json!({"groups":["core"]})).await);
        connection
    }
    async fn call(&self, name: &str, args: Value) -> CallToolResult {
        timeout(
            TIMEOUT,
            self.client.as_ref().unwrap().call_tool(
                CallToolRequestParams::new(name.to_owned()).with_arguments(args.as_object().unwrap().clone()),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn search(&self, path: &std::path::Path, mut args: Value) -> Value {
        args["path"] = json!(path);
        body(&self.call("search", args).await)
    }
    async fn shutdown(mut self) {
        timeout(TIMEOUT, self.client.take().unwrap().cancel()).await.unwrap().unwrap();
        timeout(TIMEOUT, &mut self.server.0).await.unwrap().unwrap();
    }
}
fn body(result: &CallToolResult) -> Value {
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(text.len() <= 60000, "{} bytes", text.len());
    serde_json::from_str(text).expect("complete search JSON, never string-cut transport output")
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-mcp-search-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let unicode: Vec<u8> = "世界 🦀".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let hex = rampage_arch::hex::bytes(&unicode);
        let snapshot = json!({
            "format":"rampage-snapshot-v1","arch":"x86_64","provenance":"/untrusted/not-the-backing-source",
            "seeds":["0x1000","0x2000"],"regions":[
                {"name":"code","address":"0x1000","permissions":"r-x","bytes":"488d05f91f0000b82a000000c3"},
                {"name":"code","address":"0x2000","permissions":"r-x","bytes":"b8ffffffffc3"},
                {"name":"data","address":"0x3000","permissions":"r--","bytes":"48656c6c6f20776f726c6400"},
                {"name":"data","address":"0x4000","permissions":"r--","bytes":hex},
                {"name":"data","address":"0x5000","permissions":"r--","bytes":"61".repeat(4096)}
            ]
        });
        std::fs::write(path.join("owned.json"), snapshot.to_string()).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("owned.json")
    }
    fn assert_no_annotations(&self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".jsonl") && !name.ends_with(".lock") && !name.ends_with(".rampage"), "{name}");
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn core_search_transports_native_modes_unicode_names_and_owned_source_context() {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new();
        let path = fixture.path();
        let original = std::fs::read(&path).unwrap();
        let connection = Connection::connect().await;
        let before = body(&connection.call("list_annotations", json!({"path":path})).await);
        let page = connection
            .search(
                &path,
                json!({"mode":{"kind":"bytes","pattern":"B? 2A ?? 00 00"},
            "range":{"start":"sub_1000","end":"sub_2000"}}),
            )
            .await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["hits"][0]["address"], "0x1007");
        assert_eq!(page["hits"][0]["function"]["name"], "sub_1000");
        assert_eq!(page["hits"][0]["function"]["symbol_source"], "synthetic");
        assert_eq!(page["hits"][0]["file_offset"], Value::Null);
        assert_eq!(page["source"]["backing_path"], Value::Null);
        for mode in [
            json!({"kind":"text","encoding":"utf16_le","pattern":"世界.*🦀","regex":true}),
            json!({"kind":"text","encoding":"ascii","pattern":"Hello"}),
            json!({"kind":"immediate","immediate":{"value":{"kind":"unsigned","value":42}}}),
            json!({"kind":"immediate","immediate":{"value":{"kind":"signed","value":-1},"width_bits":32}}),
            json!({"kind":"instruction","mnemonic":"mov*","operands":"eax,*"}),
            json!({"kind":"references","target":"0x3000"}),
            json!({"kind":"functions_referencing","reference":{"kind":"address","target":"0x3000"}}),
            json!({"kind":"functions_referencing","reference":{"kind":"string","text":"Hello","encoding":"utf8"}}),
            json!({"kind":"functions_referencing","reference":{"kind":"constant",
                "immediate":{"value":{"kind":"unsigned","value":42}}}}),
        ] {
            let page = connection.search(&path, json!({"mode":mode})).await;
            assert!(page["total"].as_u64().unwrap() > 0, "{mode}: {page}");
            assert!(page["hits"].as_array().unwrap().iter().all(|hit| hit["file_offset"].is_null()));
        }
        let elf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
        let elf_bytes = std::fs::read(&elf).unwrap();
        let imports = connection
            .search(
                &elf,
                json!({"mode":{"kind":"functions_referencing","reference":{
                    "kind":"import","name":"puts"
                }}}),
            )
            .await;
        assert!(imports["total"].as_u64().unwrap() > 0, "{imports}");
        assert!(imports["hits"][0]["function"].is_object());
        assert_eq!(std::fs::read(elf).unwrap(), elf_bytes);
        assert_eq!(body(&connection.call("list_annotations", json!({"path":path})).await), before);
        assert_eq!(std::fs::read(path).unwrap(), original);
        fixture.assert_no_annotations();
        connection.shutdown().await;
    })
    .await
    .expect("MCP search modes timed out");
}

#[tokio::test]
async fn search_transport_pages_complete_rows_and_retains_lower_bound_continuations() {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new();
        let path = fixture.path();
        let connection = Connection::connect().await;
        let args =
            json!({"mode":{"kind":"bytes","pattern":"61"},"range":{"start":"0x5000","end":"0x6000"},"limit":1000});
        let first = connection.search(&path, args.clone()).await;
        let returned = first["returned"].as_u64().unwrap();
        assert!(returned > 0 && returned < 1000);
        assert_eq!(first["total"], 4096);
        assert_eq!(first["total_is_exact"], true);
        assert_eq!(first["byte_capped"], true);
        assert_eq!(first["next_offset"], returned);
        let mut next = args.clone();
        next["offset"] = json!(returned);
        next["limit"] = json!(1);
        let page = connection.search(&path, next).await;
        assert_eq!(page["hits"][0]["address"], format!("{:#x}", 0x5000 + returned));
        for offset in [0, 1] {
            let mut limited = args.clone();
            limited["limit"] = json!(1);
            limited["offset"] = json!(offset);
            limited["budget"] = json!({"match_work":2});
            let page = connection.search(&path, limited).await;
            assert_eq!(page["total"], 2);
            assert_eq!(page["total_is_exact"], false);
            assert_eq!(page["stop_reason"], "match_work_budget");
            assert_eq!(page["more"], offset == 0);
        }
        for bad in [
            json!({"mode":{"kind":"references","target":"no_such_label"}}),
            json!({"mode":{"kind":"bytes","pattern":"??"}}),
            json!({"mode":{"kind":"instruction"},"limit":0}),
            json!({"mode":{"kind":"text","encoding":"utf16_le","pattern":"[","regex":true}}),
            json!({"mode":{"kind":"bytes","pattern":"61"},"budget":{"match_work":0}}),
        ] {
            let mut args = bad;
            args["path"] = json!(path);
            let result = connection.call("search", args).await;
            assert_eq!(result.is_error, Some(true), "{result:?}");
        }
        fixture.assert_no_annotations();
        connection.shutdown().await;
    })
    .await
    .expect("MCP search paging timed out");
}
