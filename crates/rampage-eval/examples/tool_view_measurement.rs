//! One owned full-versus-summary MCP response experiment. No provider or target execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rampage_api::Project;
use rampage_api::tools::Group;
use rampage_loaders::Binary;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const SELF_SOURCE: &str = "crates/rampage-eval/examples/tool_view_measurement.rs";
const ARTIFACT_ROOT: &str = "target/phase3-3-measurement-first";
const FIXTURE: &str = "tests/data/typed-data-x64.snapshot.json";
const FIXTURE_SHA: &str = "0507caa9fe630d14243cf9d2419ad15516475fd831d0a4390d9c5dcf40275f94";
const ENTRY: u64 = 0x201190;
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_JSON: usize = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(90);

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(format!("not a bounded regular file: {}", path.display()).into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("file grew beyond read bound".into());
    }
    Ok(bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > MAX_JSON {
        return Err("JSON receipt exceeds bound".into());
    }
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() || output.stdout.len() > MAX_JSON {
        return Err("git provenance query failed or exceeded bound".into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn source_snapshot(root: &Path) -> Result<Value> {
    let listed = git(
        root,
        &["ls-files", "--cached", "--others", "--exclude-standard", "--", "crates", "Cargo.toml", "Cargo.lock"],
    )?;
    let mut paths: BTreeSet<String> = listed
        .lines()
        .filter(|name| {
            matches!(
                Path::new(name).extension().and_then(|part| part.to_str()),
                Some("rs" | "toml" | "lock" | "c" | "cc" | "cpp" | "h" | "hh" | "hpp" | "inc" | "s" | "S")
            )
        })
        .map(str::to_owned)
        .collect();
    paths.extend(
        [SELF_SOURCE, FIXTURE, "tests/fixtures/src/typed-data.c", "tests/fixtures/src/typed-data.h"].map(str::to_owned),
    );
    if paths.len() > 10_000 {
        return Err("source inventory exceeds 10000 files".into());
    }
    let mut total = 0_usize;
    let mut sources = Vec::new();
    for name in paths {
        if !Path::new(&name).components().all(|part| matches!(part, Component::Normal(_))) {
            return Err("source inventory path is not repository-relative".into());
        }
        let path = root.join(&name);
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err("source inventory symlink refused".into());
        }
        let bytes = read(&path, MAX_FILE)?;
        total += bytes.len();
        if total > 512 * 1024 * 1024 {
            return Err("source inventory exceeds 512 MiB".into());
        }
        sources.push(json!({"path":name,"bytes":bytes.len(),"sha256":digest(&bytes)}));
    }
    Ok(json!({"sources":sources,"total_bytes":total}))
}

fn independent_truth(root: &Path) -> Result<Value> {
    let project = Project::new(Binary::open(root.join(FIXTURE))?);
    let listing = project.function_listing(ENTRY)?;
    if listing.address != ENTRY || listing.blocks.is_empty() {
        return Err("independent native listing has the wrong entry or no blocks".into());
    }
    for instruction in listing.blocks.iter().flatten() {
        let bytes = project
            .binary
            .read(instruction.address, (instruction.bytes.len() / 2) as u64)
            .ok_or("native listing instruction is not source-backed")?;
        if rampage_arch::hex::bytes(bytes) != instruction.bytes {
            return Err("native listing bytes differ from the original owned snapshot".into());
        }
    }
    Ok(json!({"method":"Separate original-byte/native-listing verification before either MCP arm",
        "listing":listing,"target_executed":false,
        "limitations":["Shared native decoder, not an independent disassembler implementation.",
            "The snapshot's explicit seed is a fixture assertion, not recovered source identity."]}))
}

#[derive(Default)]
struct Client;
impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn arm(root: &Path, run: &Path, view: &str) -> Result<Value> {
    let directory = run.join(view);
    fs::create_dir(&directory)?;
    let path = directory.join("fixture.snapshot.json");
    let original = read(&root.join(FIXTURE), MAX_FILE)?;
    if digest(&original) != FIXTURE_SHA {
        return Err("owned snapshot changed before arm preparation".into());
    }
    write_bytes_new(&path, &original)?;
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        rampage_mcp::RampageServer::with_groups([Group::Core])
            .serve(server_transport)
            .await
            .map_err(|error| error.to_string())?
            .waiting()
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    let client = timeout(TIMEOUT, Client.serve(client_transport)).await??;
    let catalog = timeout(TIMEOUT, client.list_all_tools()).await??;
    let tool = catalog
        .iter()
        .find(|tool| tool.name == "function_summary")
        .ok_or("function_summary absent from actual MCP catalog")?;
    let schema = serde_json::to_value(&tool.input_schema)?;
    write_new(&directory.join("catalog-tool.json"), &serde_json::to_value(tool)?)?;
    let view_schema = schema.pointer("/properties/view").ok_or("actual function_summary schema lacks view")?;
    let view_schema = if let Some(reference) = view_schema.get("$ref").and_then(Value::as_str) {
        schema
            .pointer(reference.strip_prefix('#').ok_or("view schema is not a local reference")?)
            .ok_or("view schema local reference is missing")?
    } else {
        view_schema
    };
    if !view_schema.get("enum").and_then(Value::as_array).is_some_and(|values| values.contains(&json!(view))) {
        return Err("requested view is not in the actual catalog enum; no fallback dispatched".into());
    }
    let input = json!({"path":path,"at":"0x201190","view":view});
    write_new(
        &directory.join("request.json"),
        &json!({"name":"function_summary","input":input,
        "input_sha256":digest(&serde_json::to_vec(&input)?),"schema_sha256":digest(&serde_json::to_vec(&schema)?)}),
    )?;
    let started = Instant::now();
    let response = timeout(
        TIMEOUT,
        client.call_tool(
            CallToolRequestParams::new("function_summary")
                .with_arguments(input.as_object().ok_or("request is not an object")?.clone()),
        ),
    )
    .await;
    let elapsed_us = started.elapsed().as_micros();
    let mut receipt = json!({"view":view,"name":"function_summary","input":input,
        "elapsed_us":elapsed_us,"mcp_tools_call_requests":1,"transport":"actual_rmcp_in_memory_duplex",
        "catalog_schema_sha256":digest(&serde_json::to_vec(&schema)?)});
    match response {
        Err(error) => receipt["error"] = json!(error.to_string()),
        Ok(Err(error)) => receipt["error"] = json!(error.to_string()),
        Ok(Ok(result)) => {
            let encoded = serde_json::to_vec(&result)?;
            receipt["serialized_response_bytes"] = json!(encoded.len());
            receipt["response_sha256"] = json!(digest(&encoded));
            receipt["result"] = serde_json::to_value(&result)?;
            let text = result.content.first().and_then(|block| block.as_text()).map(|block| &block.text);
            if encoded.len() > 65_536 || text.is_some_and(|text| text.len() > 60_000) {
                receipt["error"] = json!("MCP response exceeds complete-output bound");
            } else {
                if result.is_error == Some(true) || result.content.len() != 1 || text.is_none() {
                    receipt["error"] = json!("MCP error or unexpected content shape");
                } else {
                    match serde_json::from_str::<Value>(text.ok_or("MCP text missing")?) {
                        Ok(body) => {
                            receipt["json_body_bytes"] = json!(text.ok_or("MCP text missing")?.len());
                            receipt["body_sha256"] = json!(digest(text.ok_or("MCP text missing")?.as_bytes()));
                            receipt["body"] = body;
                        }
                        Err(error) => receipt["error"] = json!(format!("MCP JSON is not complete: {error}")),
                    }
                }
            }
        }
    }
    write_new(&directory.join("response.json"), &receipt)?;
    timeout(TIMEOUT, client.cancel()).await??;
    timeout(TIMEOUT, server).await??.map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })?;
    if read(&path, MAX_FILE)? != original {
        return Err("arm mutated its isolated fixture".into());
    }
    if !receipt["error"].is_null() {
        return Err(format!("{view} arm failed; first response retained, no retry").into());
    }
    Ok(receipt)
}

fn without(value: &Value, keys: &[&str]) -> Result<Map<String, Value>> {
    let mut object = value.as_object().ok_or("selected native evidence is not an object")?.clone();
    for key in keys {
        object.remove(*key);
    }
    Ok(object)
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| format!("required native array {key} missing").into())
}

fn equal_facts(full: &Value, compact: &Value, gold: &Value) -> Result<Value> {
    let mut checks = BTreeMap::new();
    let graph = &full["graph"];
    let summary_graph = &compact["graph"];
    let blocks = array(graph, "blocks")?;
    let summary_blocks = array(summary_graph, "blocks")?;
    let edges = array(graph, "edges")?;
    let native_blocks = array(&gold["listing"], "blocks")?;
    checks.insert(
        "identity_matches_original_listing",
        graph["address"] == gold["listing"]["address"]
            && graph["name"] == gold["listing"]["name"]
            && blocks.len() == native_blocks.len(),
    );
    checks.insert(
        "graph_metadata_and_edges_equal",
        without(graph, &["blocks", "blocks_count", "edges_count", "instructions_count"])?
            == without(summary_graph, &["blocks", "blocks_count", "edges_count", "instructions_count"])?,
    );
    let mut block_equal = blocks.len() == summary_blocks.len();
    let mut original_lines_equal = blocks.len() == native_blocks.len();
    let mut instruction_count = 0_usize;
    for (index, block) in blocks.iter().enumerate() {
        let lines = array(block, "lines")?;
        instruction_count += lines.len();
        original_lines_equal &= native_blocks.get(index) == Some(&json!(lines));
        let Some(summary) = summary_blocks.get(index) else {
            block_equal = false;
            continue;
        };
        block_equal &= without(block, &["lines"])? == without(summary, &["instruction_summary"])?;
        let retained = &summary["instruction_summary"];
        let mut flows = BTreeMap::<String, usize>::new();
        let mut evidence = Vec::new();
        for line in lines {
            let kind = line["flow"]["kind"].as_str().ok_or("native instruction flow kind missing")?;
            *flows.entry(kind.to_owned()).or_default() += 1;
            let row = without(line, &["text", "bytes"])?;
            if line["flow"] != json!({"kind":"next"}) || row.keys().any(|key| key != "address" && key != "flow") {
                evidence.push(Value::Object(row));
            }
        }
        block_equal &= retained["instructions_count"] == lines.len()
            && retained["first_address"] == lines.first().ok_or("native block empty")?["address"]
            && retained["last_address"] == lines.last().ok_or("native block empty")?["address"]
            && retained["flow_counts"] == json!(flows)
            && retained["control_and_annotation_facts"] == json!(evidence);
    }
    checks.insert("native_full_lines_equal_original_listing", original_lines_equal);
    checks.insert("block_nonrendering_control_annotation_facts_equal", block_equal);
    checks.insert(
        "graph_counts_equal",
        summary_graph["blocks_count"] == blocks.len()
            && summary_graph["edges_count"] == edges.len()
            && summary_graph["instructions_count"] == instruction_count,
    );
    let references = &full["references"];
    let reference_items = array(references, "items")?;
    checks.insert(
        "references_complete_and_equal",
        references["offset"] == 0
            && references["total"] == reference_items.len()
            && without(references, &["returned_count"])? == without(&compact["references"], &["returned_count"])?
            && compact["references"]["returned_count"] == reference_items.len(),
    );
    let ir = array(full, "ir")?;
    checks.insert(
        "native_ir_completeness_counts_equal",
        compact["ir_count"] == ir.len()
            && compact["ir_complete_count"] == ir.iter().filter(|instruction| instruction["complete"] == true).count()
            && compact["lifted_instructions"] == full["lifted_instructions"],
    );
    for key in ["ssa", "pseudocode", "structured_pseudocode"] {
        let matched = match (full.get(key), compact.get(key)) {
            (None, None) => true,
            (Some(original), Some(retained)) if original.is_null() => retained.is_null(),
            (Some(original), Some(retained)) if key == "ssa" => {
                let definitions = array(original, "definitions")?;
                without(original, &["definitions"])? == without(retained, &["definitions_count"])?
                    && retained["definitions_count"] == definitions.len()
            }
            (Some(original), Some(retained)) => {
                let text = original["text"].as_str().ok_or("structural pseudocode text missing")?;
                without(original, &["text", "code_kind"])? == without(retained, &["text_utf8_bytes", "code_kind"])?
                    && retained["text_utf8_bytes"] == text.len()
                    && retained["code_kind"] == "partial_structural_pseudocode_not_native_recovered_c"
            }
            _ => false,
        };
        checks.insert(key, matched);
    }
    let transformed = [
        "graph",
        "references",
        "ir",
        "ir_count",
        "ir_complete_count",
        "ssa",
        "pseudocode",
        "structured_pseudocode",
        "view_projection",
    ];
    checks.insert(
        "all_other_native_facts_diagnostics_limits_equal",
        without(full, &transformed)? == without(compact, &transformed)?,
    );
    checks.insert(
        "compact_projection_receipt_present",
        compact["view_projection"]["kind"] == "function_summary"
            && compact["view_projection"]["view"] == "summary"
            && compact["view_projection"]["omissions"].as_array().is_some_and(|items| !items.is_empty()),
    );
    Ok(json!({"equivalent_selected_facts":checks.values().all(|matched|*matched),"checks":checks,
        "native_ssa_present":full.get("ssa").is_some_and(|ssa|!ssa.is_null()),
        "full_response_equivalence_claimed":false,"production_projection_called_locally":false}))
}

async fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3
        || args[1].is_empty()
        || !args[1].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("usage: tool_view_measurement RUN-ID BUILD-RECEIPT.json".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let artifacts = root.join(ARTIFACT_ROOT).canonicalize()?;
    let build_path = Path::new(&args[2]).canonicalize()?;
    if !build_path.starts_with(&artifacts) {
        return Err("build receipt outside owned artifact root".into());
    }
    let build_bytes = read(&build_path, MAX_JSON as u64)?;
    let build: Value = serde_json::from_slice(&build_bytes)?;
    let sources = source_snapshot(&root)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha = digest(&read(&executable, 256 * 1024 * 1024)?);
    if build["success"] != true
        || build["source_snapshot_before"] != sources
        || build["source_snapshot_after"] != sources
        || build["executable_sha256"] != executable_sha
        || build["argv"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("build receipt does not bind stable sources and this executable".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&executable)?.permissions().mode() & 0o222 != 0 {
            return Err("collector must be frozen read-only".into());
        }
    }
    let self_bytes = read(&root.join(SELF_SOURCE), MAX_FILE)?;
    if self_bytes != include_bytes!("tool_view_measurement.rs")
        || digest(&read(&root.join(FIXTURE), MAX_FILE)?) != FIXTURE_SHA
    {
        return Err("consumer source or fixed owned fixture digest mismatch".into());
    }
    let run = artifacts.join(&args[1]);
    fs::create_dir(&run)?;
    let before = json!({"argv":args,"executable":{"path":executable,"sha256":executable_sha},
        "consumer_source":{"path":SELF_SOURCE,"sha256":digest(&self_bytes)},
        "build_receipt":{"path":build_path,"sha256":digest(&build_bytes),"argv":build["argv"]},
        "source_snapshot":sources,"source_snapshot_sha256":digest(&serde_json::to_vec(&sources)?),
        "git_head":git(&root,&["rev-parse","HEAD"])?.trim(),
        "git_status":git(&root,&["status","--porcelain=v1","--untracked-files=all"])?,
        "fixture":{"path":FIXTURE,"sha256":FIXTURE_SHA},
        "started_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()});
    write_new(&run.join("before.json"), &before)?;
    let gold = independent_truth(&root)?;
    write_new(&run.join("independent-truth.json"), &gold)?;
    let attempted = timeout(Duration::from_secs(240), async {
        let full = arm(&root, &run, "full").await?;
        let compact = arm(&root, &run, "summary").await?;
        let facts = equal_facts(&full["body"], &compact["body"], &gold)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((full, compact, facts))
    })
    .await
    .unwrap_or_else(|_| Err("whole mechanical comparison exceeded 240 seconds".into()));
    let sources_unchanged = source_snapshot(&root)? == sources;
    let fixture_unchanged = digest(&read(&root.join(FIXTURE), MAX_FILE)?) == FIXTURE_SHA;
    let executable_unchanged = digest(&read(&executable, 256 * 1024 * 1024)?) == executable_sha;
    let mut report = json!({"schema_version":1,"scope":"owned_actual_mcp_full_vs_summary_response_bytes_only",
        "provenance":before,"independent_truth":gold,"provider_tokens":null,"provider_calls":0,
        "target_executed":false,"phase1_live_n_earned":false,"phase33_acceptance":false,
        "sources_unchanged":sources_unchanged,"fixture_unchanged":fixture_unchanged,
        "executable_unchanged":executable_unchanged,"complete":false,"byte_reduction_earned":false});
    match attempted {
        Err(error) => report["error"] = json!(error.to_string()),
        Ok((full, compact, facts)) => {
            let complete = sources_unchanged
                && fixture_unchanged
                && executable_unchanged
                && full["catalog_schema_sha256"] == compact["catalog_schema_sha256"]
                && facts["equivalent_selected_facts"] == true;
            let delta = full["serialized_response_bytes"].as_i64().ok_or("full response byte count missing")?
                - compact["serialized_response_bytes"].as_i64().ok_or("compact response byte count missing")?;
            report["complete"] = json!(complete);
            report["byte_reduction_earned"] = json!(complete && delta > 0);
            report["serialized_response_byte_delta"] = if complete { json!(delta) } else { Value::Null };
            report["full"] = full;
            report["compact"] = compact;
            report["selected_fact_comparison"] = facts;
        }
    }
    write_new(&run.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"report":run.join("report.json"),"complete":report["complete"],
        "byte_reduction_earned":report["byte_reduction_earned"],"error":report["error"],
        "report_sha256":digest(&read(&run.join("report.json"),MAX_JSON as u64)?)})
    );
    Ok(report["complete"] == true)
}

fn main() {
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })
        .and_then(|runtime| runtime.block_on(run()));
    match result {
        Ok(true) => (),
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("tool view measurement incomplete: {error}");
            std::process::exit(2);
        }
    }
}
