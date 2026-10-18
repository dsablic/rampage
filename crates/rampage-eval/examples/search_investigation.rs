//! One owned, scripted MCP comparison. No model, target execution, or Phase 0 regrading.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_api::tools::Group;
use rampage_api::{FunctionsQuery, Project};
use rampage_loaders::Binary;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const FIXTURE: &str = "tests/fixtures/bin/hello-x64.elf";
const FIXTURE_SHA: &str = "dd13c0fedd703a5a7ddd995e1a729ea42443ab23ec6e163c7c683263a1c62742";
const FIXTURE_SOURCE_SHA: &str = "3f06109c966ca8c3d6cf5c87a031aab612be8f871f42c704f37a41b16ca1ecf7";
const BASELINE: &str = "target/parity/phase0-completion/accepted-scorecard.json";
const BASELINE_SHA: &str = "28fdbdcc2077b906db0f4676550b08a4752a7b3498945923a5276d7f81a4ce90";
const LITERAL: &str = "rampage fixture greeting";
const ARTIFACT_ROOT: &str = "target/phase3-1-investigation-first";
const SELF_SOURCE: &str = "crates/rampage-eval/examples/search_investigation.rs";
const MAX_FILE: u64 = 32 * 1024 * 1024;
const MAX_RESULT: usize = 65_536;
const MAX_REPORT: usize = 2 * 1024 * 1024;

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

fn write_new(path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > MAX_REPORT {
        return Err("receipt exceeds output bound".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() || output.stdout.len() > MAX_REPORT {
        return Err("bounded git provenance query failed".into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn source_snapshot(root: &Path) -> Result<Value> {
    let paths = git(
        root,
        &["ls-files", "--cached", "--others", "--exclude-standard", "--", "crates", "Cargo.toml", "Cargo.lock"],
    )?;
    let mut names: BTreeSet<String> = paths
        .lines()
        .filter(|name| {
            matches!(
                Path::new(name).extension().and_then(|part| part.to_str()),
                Some("rs" | "toml" | "lock" | "c" | "cc" | "cpp" | "h" | "hh" | "hpp" | "inc" | "s" | "S")
            )
        })
        .map(str::to_owned)
        .collect();
    names.extend([SELF_SOURCE, "tests/fixtures/src/hello.c", "tests/fixtures/build.sh"].map(str::to_owned));
    if names.len() > 10_000 {
        return Err("source file count exceeds bound".into());
    }
    let mut total = 0_usize;
    let mut sources = Vec::new();
    for name in names {
        let path = Path::new(&name);
        if !path.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err("source inventory contains a non-relative path".into());
        }
        let joined = root.join(path);
        if fs::symlink_metadata(&joined)?.file_type().is_symlink() {
            return Err("source inventory contains a symlink".into());
        }
        let bytes = read(&joined, MAX_FILE)?;
        total += bytes.len();
        if total > 512 * 1024 * 1024 {
            return Err("source inventory exceeds byte bound".into());
        }
        sources.push(json!({"path":name,"bytes":bytes.len(),"sha256":digest(&bytes)}));
    }
    Ok(json!({"sources":sources,"total_bytes":total}))
}

fn independent_truth(root: &Path) -> Result<Value> {
    let project = Project::new(Binary::open(root.join(FIXTURE))?);
    let listing = project.function_listing(0x1001910)?;
    let functions = project.functions(&FunctionsQuery {
        name_contains: Some("main".into()),
        offset: Some(0),
        limit: Some(1000),
    })?;
    let same_name: Vec<_> = functions.items.iter().filter(|row| row.name == listing.name).collect();
    if functions.total != functions.items.len() || same_name.len() != 1 || same_name[0].address != listing.address {
        return Err("manual function-name join is not independently unique".into());
    }
    let literal = project.binary.read(0x100019a, (LITERAL.len() + 1) as u64).ok_or("truth literal is not backed")?;
    let mut expected = LITERAL.as_bytes().to_vec();
    expected.push(0);
    if literal != expected || listing.address != 0x1001910 || listing.name != "main" {
        return Err("independent original-byte/function truth mismatch".into());
    }
    let site = listing
        .blocks
        .iter()
        .flatten()
        .find(|line| line.address == 0x1001914)
        .ok_or("truth reference site absent from native listing")?;
    if site.data_ref != Some(0x100019a) && site.immediate != Some(0x100019a) {
        return Err("native instruction does not reference the truth literal".into());
    }
    let bytes =
        project.binary.read(site.address, (site.bytes.len() / 2) as u64).ok_or("truth instruction is not backed")?;
    if rampage_arch::hex::bytes(bytes) != site.bytes {
        return Err("native listing bytes disagree with original mapped bytes".into());
    }
    Ok(json!({
        "method":"original mapped bytes plus separate native function_listing before either arm",
        "literal_address":"0x100019a", "literal_bytes_hex":rampage_arch::hex::bytes(literal),
        "reference_site":"0x1001914", "function_address":"0x1001910", "function_name":listing.name,
        "native_function_name_unique":true,
        "listing":listing,
        "limitations":["Static native decoding, not observed execution.",
            "Manual xrefs supplies a function name, not its address; identity is joined to the independently verified native function."]
    }))
}

#[derive(Default)]
struct Client;

impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Connection {
    client: RunningService<RoleClient, Client>,
    server: tokio::task::JoinHandle<std::result::Result<(), String>>,
}

impl Connection {
    async fn open() -> Result<Self> {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let service = rampage_mcp::RampageServer::with_groups([Group::Core])
                .serve(server_transport)
                .await
                .map_err(|error| error.to_string())?;
            service.waiting().await.map(|_| ()).map_err(|error| error.to_string())
        });
        let client = Client.serve(client_transport).await?;
        Ok(Self { client, server })
    }

    async fn close(self) -> Result<()> {
        let closed = self.client.cancel().await;
        let server = self.server.await?;
        closed?;
        server.map_err(Into::into)
    }

    async fn call(&self, name: &str, input: Value, receipts: &mut Vec<Value>) -> Result<Value> {
        let started = Instant::now();
        let result = self
            .client
            .call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(input.as_object().ok_or("request is not an object")?.clone()),
            )
            .await;
        let elapsed_us = started.elapsed().as_micros();
        match result {
            Err(error) => {
                receipts.push(json!({"name":name,"input":input,"elapsed_us":elapsed_us,
                    "transport_error":error.to_string(),"invoked_transport":true}));
                Err("MCP transport request failed".into())
            }
            Ok(result) => {
                let serialized = serde_json::to_vec(&result)?;
                if serialized.len() > MAX_RESULT {
                    receipts.push(json!({"name":name,"input":input,"elapsed_us":elapsed_us,
                        "output_bytes":serialized.len(),"error":"output exceeds bound"}));
                    return Err("MCP result exceeds bound".into());
                }
                receipts.push(json!({"name":name,"input":input,"elapsed_us":elapsed_us,
                    "output_bytes":serialized.len(),"result":result,"invoked_transport":true}));
                if result.is_error == Some(true) || result.content.len() != 1 {
                    return Err("MCP error or unexpected content shape".into());
                }
                let text = &result.content[0].as_text().ok_or("MCP content is not text")?.text;
                Ok(serde_json::from_str(text)?)
            }
        }
    }
}

async fn requests(connection: &Connection, path: &str, manual: bool, calls: &mut Vec<Value>) -> Result<Value> {
    if manual {
        let strings = connection
            .call(
                "list_strings",
                json!({"path":path,"contains":LITERAL,
            "min_len":4,"offset":0,"limit":100}),
                calls,
            )
            .await?;
        let items = strings["items"].as_array().ok_or("manual string page missing")?;
        if strings["offset"] != 0 || strings["total"].as_u64() != Some(items.len() as u64) {
            return Err("manual strings page incomplete".into());
        }
        let matching: Vec<_> = items.iter().filter(|row| row["text"] == LITERAL).collect();
        if matching.len() != 1 {
            return Err("manual arm did not identify exactly one full literal".into());
        }
        let literal = matching[0]["address"].as_str().ok_or("manual string address missing")?;
        let refs = connection
            .call(
                "xrefs",
                json!({"path":path,"to":literal,
            "offset":0,"limit":100}),
                calls,
            )
            .await?;
        let rows = refs["items"].as_array().ok_or("manual reference page missing")?;
        if refs["offset"] != 0 || refs["total"].as_u64() != Some(rows.len() as u64) {
            return Err("manual reference page incomplete".into());
        }
        Ok(json!({"literal_candidates":matching,"reference_rows":rows}))
    } else {
        connection
            .call(
                "search",
                json!({"path":path,"mode":{"kind":"functions_referencing",
            "reference":{"kind":"string","text":LITERAL,"encoding":"utf8"}},
            "offset":0,"limit":100,"include_context":true}),
                calls,
            )
            .await
    }
}

async fn arm(root: &Path, run: &Path, manual: bool) -> Result<Value> {
    let name = if manual { "manual" } else { "search" };
    let directory = run.join(name);
    fs::create_dir(&directory)?;
    let path = directory.join("fixture.elf");
    let fixture = read(&root.join(FIXTURE), MAX_FILE)?;
    if digest(&fixture) != FIXTURE_SHA {
        return Err("original fixture changed before arm preparation".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path)?;
    file.write_all(&fixture)?;
    file.sync_all()?;
    drop(file);
    let cold = Project::new(Binary::open(&path)?).analysis_cache_status();
    let connection = Connection::open().await?;
    let catalog = connection.client.list_all_tools().await?;
    let selected: Vec<_> =
        catalog.iter().filter(|tool| matches!(tool.name.as_ref(), "search" | "xrefs" | "list_strings")).collect();
    let registered =
        ["search", "xrefs", "list_strings"].iter().all(|name| selected.iter().any(|tool| tool.name.as_ref() == *name));
    let mut calls = Vec::new();
    let started = Instant::now();
    let result = if registered {
        requests(&connection, path.to_str().ok_or("fixture path is not UTF-8")?, manual, &mut calls).await
    } else {
        Err("required tool absent from actual MCP catalog; wrapper integration incomplete".into())
    };
    let elapsed_us = started.elapsed().as_micros();
    connection.close().await?;
    let unchanged = digest(&read(&path, MAX_FILE)?) == FIXTURE_SHA;
    Ok(json!({"arm":name,"transport":"actual_rmcp_in_memory_duplex","catalog":selected,
        "catalog_discovery":"one list_all_tools invocation; not included in tools/call count",
        "required_tools_registered":registered,"fixture_sha256":digest(&fixture),
        "fixture_unchanged":unchanged,"separate_project_cache_probe":cold,
        "cache_boundary":"fresh server/session and unique fixture copy; native caches uninitialized by this arm",
        "os_file_cache":"not flushed; this is not an OS-cold latency experiment",
        "mcp_tools_call_requests":calls.len(),"api_dispatch_requests_direct":0,
        "elapsed_us":elapsed_us,"calls":calls,"payload":result.as_ref().ok(),
        "error":result.err().map(|error| error.to_string()),"provider_tokens":null}))
}

fn check_answers(manual: &Value, search: &Value, truth: &Value) -> Value {
    let m = &manual["payload"];
    let s = &search["payload"];
    let manual_rows = m["reference_rows"].as_array();
    let search_rows = s["hits"].as_array();
    let manual_complete =
        manual["error"].is_null() && manual["fixture_unchanged"] == true && manual["mcp_tools_call_requests"] == 2;
    let search_complete = search["error"].is_null()
        && search["fixture_unchanged"] == true
        && search["mcp_tools_call_requests"] == 1
        && s["total_is_exact"] == true
        && s["truncated"] == false
        && s["cancelled"] == false
        && s["stop_reason"] == "complete"
        && s["more"] == false
        && s["byte_capped"] == false
        && s["offset"] == 0
        && search_rows.is_some_and(|rows| s["total"].as_u64() == Some(rows.len() as u64));
    let manual_match = manual_complete
        && manual_rows.is_some_and(|rows| {
            rows.len() == 1
                && rows[0]["from"] == truth["reference_site"]
                && rows[0]["to"] == truth["literal_address"]
                && rows[0]["from_function"] == truth["function_name"]
        });
    let search_match = search_complete
        && search_rows.is_some_and(|rows| {
            rows.len() == 1
                && rows[0]["address"] == truth["function_address"]
                && rows[0]["target"] == truth["literal_address"]
                && rows[0]["code"]["site"] == truth["reference_site"]
                && rows[0]["code"]["native_function"] == truth["function_address"]
                && rows[0]["function"]["address"] == truth["function_address"]
                && rows[0]["function"]["name"] == truth["function_name"]
                && rows[0]["function"]["name_truncated"] == false
                && rows[0]["code"]["text_truncated"] == false
        });
    let matched = manual_match && search_match;
    json!({"manual_contract_matches":manual_match,"search_contract_matches":search_match,
        "search_complete":search_complete,"equivalent_answer_evidence":matched,
        "function_identity_rule":"manual native name equality joined to independent truth; search requires explicit entry, native_function and name",
        "controlled_mcp_call_delta":if matched {
            Some(manual["mcp_tools_call_requests"].as_i64().unwrap_or(0)
                - search["mcp_tools_call_requests"].as_i64().unwrap_or(0))
        } else { None },
        "phase0_improvement":false,"live_acceptance":false,"phase1_completion_n_earned":false})
}

async fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3
        || !args[1].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || args[1].is_empty()
    {
        return Err("usage: search_investigation RUN-ID BUILD-RECEIPT.json (receipt under artifact root)".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    let artifacts = root.join(ARTIFACT_ROOT).canonicalize()?;
    let build_path = Path::new(&args[2]).canonicalize()?;
    if !build_path.starts_with(&artifacts) {
        return Err("build receipt must be inside the owned artifact root".into());
    }
    let build_bytes = read(&build_path, MAX_REPORT as u64)?;
    let build: Value = serde_json::from_slice(&build_bytes)?;
    let sources_before = source_snapshot(&root)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha = digest(&read(&executable, 256 * 1024 * 1024)?);
    if build["success"] != true
        || build["source_snapshot_before"] != sources_before
        || build["source_snapshot_after"] != sources_before
        || build["executable_sha256"] != executable_sha
        || build["argv"].as_array().is_none_or(Vec::is_empty)
    {
        return Err("build receipt does not bind a stable source snapshot and this executable".into());
    }
    let self_bytes = read(&root.join(SELF_SOURCE), MAX_FILE)?;
    if self_bytes != include_bytes!("search_investigation.rs") {
        return Err("consumer source differs from compiled-in source".into());
    }
    let fixture_before = read(&root.join(FIXTURE), MAX_FILE)?;
    if digest(&fixture_before) != FIXTURE_SHA {
        return Err("owned fixture digest mismatch".into());
    }
    if digest(&read(&root.join("tests/fixtures/src/hello.c"), MAX_FILE)?) != FIXTURE_SOURCE_SHA {
        return Err("owned fixture source digest mismatch".into());
    }
    let baseline = read(&root.join(BASELINE), 64 * 1024 * 1024)?;
    if digest(&baseline) != BASELINE_SHA {
        return Err("frozen Phase 0 generic trace digest mismatch".into());
    }
    let run = artifacts.join(&args[1]);
    fs::create_dir(&run)?;
    let before = json!({"argv":args,"executable":{"path":executable,"sha256":executable_sha},
        "consumer_source":{"path":SELF_SOURCE,"sha256":digest(&self_bytes)},
        "source_snapshot":sources_before,"source_snapshot_sha256":digest(&serde_json::to_vec(&sources_before)?),
        "build_receipt":{"path":build_path,"sha256":digest(&build_bytes),"argv":build["argv"],
            "stable_sources_and_executable_checked":true},
        "git_head":git(&root,&["rev-parse","HEAD"])?.trim(),
        "git_status":git(&root,&["status","--porcelain=v1","--untracked-files=all"])?,
        "fixture":{"path":FIXTURE,"sha256":FIXTURE_SHA,
            "source_path":"tests/fixtures/src/hello.c","source_sha256":FIXTURE_SOURCE_SHA},
        "baseline":{"path":BASELINE,"sha256":BASELINE_SHA,
            "calls":38,"input_tokens":286183,"output_tokens":4347,"reasoning_tokens":1555,
            "comparison_denominator":false,"recorded_artifact_paths_followed":false},
        "started_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()});
    write_new(&run.join("before.json"), &before)?;
    let truth = independent_truth(&root)?;
    write_new(&run.join("independent-truth.json"), &truth)?;
    let manual = arm(&root, &run, true).await?;
    write_new(&run.join("manual.json"), &manual)?;
    let search = arm(&root, &run, false).await?;
    write_new(&run.join("search.json"), &search)?;
    let mut answers = check_answers(&manual, &search, &truth);
    let sources_unchanged = source_snapshot(&root)? == sources_before;
    let original_unchanged = read(&root.join(FIXTURE), MAX_FILE)? == fixture_before;
    let complete = sources_unchanged && original_unchanged && answers["equivalent_answer_evidence"] == true;
    if !complete {
        answers["controlled_mcp_call_delta"] = Value::Null;
    }
    let report = json!({"schema_version":1,"task_id":"phase31-owned-greeting-reference-elf",
        "scope":"owned_scripted_mechanical_mcp_comparison_not_live_acceptance",
        "question":"Locate the known greeting literal and its retained static reference site/function.",
        "complete":complete,"sources_unchanged":sources_unchanged,"original_fixture_unchanged":original_unchanged,
        "provenance":before,"independent_truth":truth,"manual":manual,"search":search,"checks":answers,
        "provider_tokens":null,"provider_calls":0,"target_executed":false,
        "limitations":["New known-literal task, not the original Phase 0 unknown-greeting question.",
            "One scripted run per arm, manual first; elapsed times are observations, not a speedup claim.",
            "MCP tools/call counts exclude discovery, independent evaluator truth and provenance collection.",
            "Caller-supplied build receipt binds observed inputs/executable, not source authenticity or a reproducible build.",
            "No model, provider authentication, network, baseline regrading or Phase 1 live completion."]});
    write_new(&run.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"report":run.join("report.json"),"complete":complete,
        "report_sha256":digest(&read(&run.join("report.json"), MAX_REPORT as u64)?),"checks":report["checks"]})
    );
    Ok(complete)
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
            eprintln!("search investigation incomplete: {error}");
            std::process::exit(2);
        }
    }
}
