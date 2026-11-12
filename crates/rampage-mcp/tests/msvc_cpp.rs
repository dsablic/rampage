//! MSVC C++ evidence over MCP on the owned clang-cl/lld-link fixtures in `tests/fixtures/msvc-cpp`: function
//! discovery against the PDB truth, vftables in `class_evidence`, paged `exception_handlers`, and PDB names.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let server = RampageServer::with_groups(Group::ALL);
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &RunningService<RoleClient, TestClient>, tool: &str, arguments: Value) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments.as_object().unwrap().clone()))
        .await
        .unwrap();
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{tool}: {text}");
    assert!(text.len() <= 60_000, "{tool}: {} bytes", text.len());
    serde_json::from_str(text).unwrap()
}

/// A private copy of a fixture, so project sidecars never land in the repository.
struct Copy(PathBuf);

impl Copy {
    fn new(name: &str) -> Self {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/msvc-cpp").join(name);
        let directory = std::env::temp_dir().join(format!("rampage-mcp-msvc-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for file in [name.to_owned(), name.replace(".exe", ".pdb")] {
            std::fs::copy(source.with_file_name(&file), directory.join(&file)).unwrap();
        }
        Self(directory.join(name))
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

/// Code addresses of the PDB's procedure and thunk records, from the truth listing build.sh dumps.
fn truth_code(arch: &str) -> BTreeSet<u64> {
    let base = if arch == "x64" { 0x1_4000_1000 } else { 0x40_1000 };
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/fixtures/msvc-cpp/truth-{arch}.txt"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("function ") || line.starts_with("thunk "))
        .filter_map(|line| {
            let offset = line.split(' ').nth(1)?.strip_prefix("0001:")?;
            Some(base + offset.parse::<u64>().unwrap())
        })
        .collect()
}

fn address(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

async fn all_functions(client: &RunningService<RoleClient, TestClient>, path: &PathBuf) -> BTreeSet<u64> {
    let mut found = BTreeSet::new();
    let mut offset = 0;
    loop {
        let page = call(client, "list_functions", json!({"path": path, "offset": offset, "limit": 100})).await;
        let rows = page["items"].as_array().unwrap();
        found.extend(rows.iter().map(|row| address(&row["address"])));
        offset += rows.len();
        if rows.is_empty() || offset as u64 >= page["total"].as_u64().unwrap() {
            break;
        }
    }
    found
}

#[tokio::test]
async fn msvc_functions_vftables_and_exception_handlers_match_the_pdb() {
    let client = connect().await;
    for arch in ["x64", "x86"] {
        let exe = Copy::new(&format!("msvc-cpp-{arch}.exe"));
        let found = all_functions(&client, &exe.0).await;
        let truth = truth_code(arch);
        let missed: Vec<String> = truth.difference(&found).map(|address| format!("{address:#x}")).collect();
        assert!(missed.is_empty(), "{arch}: discovery misses PDB functions {missed:?}");

        let classes = call(&client, "class_evidence", json!({"path": exe.0})).await;
        let tables = classes["vftables"].as_array().unwrap();
        assert_eq!(tables.len(), 20, "{arch}");
        let sprite: Vec<u64> = tables
            .iter()
            .filter(|table| table["class"] == "geo::Sprite")
            .map(|table| table["offset"].as_u64().unwrap())
            .collect();
        assert_eq!(sprite, [0, if arch == "x64" { 24 } else { 16 }, if arch == "x64" { 32 } else { 20 }]);
        for table in tables {
            for slot in table["slots"].as_array().unwrap() {
                assert!(found.contains(&address(slot)), "{arch}: vftable slot {slot} is not a function");
            }
        }
        let names: BTreeSet<&str> = tables.iter().map(|table| table["class"].as_str().unwrap()).collect();
        let rtti: BTreeSet<&str> =
            classes["rtti_classes"].as_array().unwrap().iter().map(|class| class["name"].as_str().unwrap()).collect();
        assert!(names.is_subset(&rtti), "{arch}: {names:?} vs {rtti:?}");

        // Paging: one function per page, exact totals.
        let first = call(&client, "exception_handlers", json!({"path": exe.0, "limit": 1})).await;
        assert_eq!(first["functions_total"], 4);
        assert_eq!(first["try_blocks_total"], 3);
        assert_eq!(first["catch_handlers_total"], 7);
        assert_eq!(first["cleanup_funclets_total"], 7);
        assert_eq!((first["more"].as_bool(), first["next_offset"].as_u64()), (Some(true), Some(1)));
        let lookup = &first["functions"][0];
        let catches: Vec<&str> = lookup["try_blocks"][0]["catches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|catch| catch["type"].as_str().unwrap())
            .collect();
        assert_eq!(catches, ["RangeError", "Error", "int", "..."], "{arch}");
        assert!(truth.contains(&address(&lookup["function"])), "{arch}: owner {}", lookup["function"]);
        for catch in lookup["try_blocks"][0]["catches"].as_array().unwrap() {
            assert!(found.contains(&address(&catch["handler"])), "{arch}: catch funclet {}", catch["handler"]);
        }
        // The function filter takes any address inside the function.
        let inside = address(&lookup["function"]) + 4;
        let filtered =
            call(&client, "exception_handlers", json!({"path": exe.0, "function": format!("{inside:#x}")})).await;
        assert_eq!(filtered["total"], 1);
        assert_eq!(filtered["functions"][0]["table"], lookup["table"]);

        let throws = call(&client, "exception_handlers", json!({"path": exe.0, "list": "throws"})).await;
        let thrown: Vec<Value> = throws["throws"].as_array().unwrap().iter().map(|row| row["types"].clone()).collect();
        assert_eq!(thrown, [json!(["int"]), json!(["RangeError", "Error"]), json!(["Error"])], "{arch}");

        // Every PDB procedure is named, and applying makes the names visible to function listings.
        let pdb = exe.0.with_extension("pdb");
        let preview = call(&client, "import_pdb_names", json!({"path": exe.0, "pdb": pdb, "limit": 1})).await;
        assert_eq!(preview["ok"], true, "{preview}");
        assert!(preview["preview_total"].as_u64().unwrap() >= truth.len() as u64 - 5, "{preview}");
    }
}

#[tokio::test]
async fn exception_handlers_refuse_non_pe_images() {
    let client = connect().await;
    let elf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let directory = std::env::temp_dir().join(format!("rampage-mcp-msvc-elf-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let copy = directory.join("hello-x64.elf");
    std::fs::copy(elf, &copy).unwrap();
    let result = client
        .call_tool(
            CallToolRequestParams::new("exception_handlers".to_owned())
                .with_arguments(json!({"path": copy}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let _ = std::fs::remove_dir_all(directory);
}
