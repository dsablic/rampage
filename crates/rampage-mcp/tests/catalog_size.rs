//! What the tool catalog costs an agent session: the bytes of the `tools/list` payload a default (core) server and an
//! all-groups server send, and of the server instructions, each split into tool descriptions, argument doc strings
//! and the rest of the schemas. Tokens are estimated as bytes / 4.
//!
//! Print the report, with the largest tools, by running
//! `cargo nextest run -p rampage-mcp --no-capture -E 'test(/catalog_size/)'`.
//!
//! The default payload has a budget, so growth is deliberate: when a new tool or description needs more, raise
//! [`DEFAULT_LIST_BUDGET`] in the same change and say why in its commit.

use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::ServiceExt;
use rmcp::model::Tool;
use rmcp::service::{RoleClient, RunningService};
use serde_json::Value;

type Client = RunningService<RoleClient, ()>;

/// Bytes of the default `tools/list` payload (core and enable_tools) as serialized JSON: the 99,455 left by the 1.7.0
/// description trim (from 134,699) plus about 5%.
const DEFAULT_LIST_BUDGET: usize = 104_400;

/// Set to a directory, the default and all-groups listings are written there as `default.json` and `all.json`, to
/// compare tools before and after a change.
const DUMP_VARIABLE: &str = "RAMPAGE_CATALOG_DUMP";

async fn connect(server: RampageServer) -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    ().serve(client_transport).await.unwrap()
}

/// One tool's bytes: its description, the description strings inside its schema, and everything else.
#[derive(Default, Clone, Copy)]
struct Size {
    description: usize,
    doc_strings: usize,
    total: usize,
}

impl Size {
    fn of(tool: &Tool) -> Self {
        fn doc_strings(value: &Value) -> usize {
            match value {
                Value::Object(map) => map
                    .iter()
                    .map(|(key, value)| match value {
                        Value::String(text) if key == "description" => text.len(),
                        _ => doc_strings(value),
                    })
                    .sum(),
                Value::Array(items) => items.iter().map(doc_strings).sum(),
                _ => 0,
            }
        }
        Self {
            description: tool.description.as_deref().map_or(0, str::len),
            doc_strings: doc_strings(&Value::Object((*tool.input_schema).clone())),
            total: serde_json::to_string(tool).unwrap().len(),
        }
    }

    fn add(self, other: Self) -> Self {
        Self {
            description: self.description + other.description,
            doc_strings: self.doc_strings + other.doc_strings,
            total: self.total + other.total,
        }
    }
}

/// Every tool `server` lists with its size, and its instructions.
async fn listing(server: RampageServer, name: &str) -> (Vec<(String, Size)>, String) {
    let client = connect(server).await;
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap_or_default();
    let tools = client.list_all_tools().await.unwrap();
    if let Ok(directory) = std::env::var(DUMP_VARIABLE) {
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{name}.json")),
            serde_json::to_string_pretty(&tools).unwrap(),
        )
        .unwrap();
    }
    let sizes = tools.iter().map(|tool| (tool.name.to_string(), Size::of(tool))).collect();
    client.cancel().await.unwrap();
    (sizes, instructions)
}

fn report(name: &str, tools: &[(String, Size)]) -> Size {
    let sum = tools.iter().fold(Size::default(), |sum, (_, size)| sum.add(*size));
    let rest = sum.total - sum.description - sum.doc_strings;
    println!(
        "{name}: {} tools, {} bytes (~{} tokens): descriptions {}, argument doc strings {}, schema structure and \
         framing {}",
        tools.len(),
        sum.total,
        sum.total / 4,
        sum.description,
        sum.doc_strings,
        rest
    );
    sum
}

#[tokio::test]
async fn the_default_tool_list_stays_within_its_budget() {
    let (default, instructions) = listing(RampageServer::default(), "default").await;
    let (all, _) = listing(RampageServer::with_groups(Group::ALL), "all").await;
    let default_size = report("default tools/list", &default);
    report("all-groups tools/list", &all);
    println!(
        "instructions: {} bytes, {} characters (~{} tokens)",
        instructions.len(),
        instructions.chars().count(),
        instructions.len() / 4
    );
    let mut largest = all.clone();
    largest.sort_by_key(|(_, size)| std::cmp::Reverse(size.total));
    println!("largest tools (total, description, doc strings):");
    for (name, size) in largest.iter().take(40) {
        println!("  {name}\t{}\t{}\t{}", size.total, size.description, size.doc_strings);
    }
    assert!(
        default_size.total <= DEFAULT_LIST_BUDGET,
        "the default tools/list payload is {} bytes, over its {DEFAULT_LIST_BUDGET}-byte budget; trim, or raise \
         the budget deliberately",
        default_size.total
    );
}
