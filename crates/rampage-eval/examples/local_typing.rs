//! Opt-in, paired local-typing measurement, not a blind whole-program RE benchmark.
//! Uses the in-process Anthropic transport (ANTHROPIC_API_KEY); never prints keys or provider transcripts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_agent::Anthropic;
use rampage_api::annotations::{Annotations, parse_local_names, parse_local_types};
use rampage_decompiler::VariableStorage;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, ModelSource, run_task};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::RoleClient;
use rmcp::{ClientHandler, Peer, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The pinned live model, requested through the in-process Anthropic transport (ANTHROPIC_API_KEY).
const MODEL: &str = "claude-sonnet-5-5";

const ENTRY: &str = "0x4000ae";
const ENTRY_ADDRESS: u64 = 0x4000ae;
const OWNED_FIXTURE: &[u8] = include_bytes!("../../../tests/data/local-variables-x64.snapshot.json");
const MAX_OUTPUT_BYTES: usize = 65_536;

#[derive(Default)]
struct MeasurementClient;

impl ClientHandler for MeasurementClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct OwnedFixture {
    directory: PathBuf,
    path: PathBuf,
    context: PathBuf,
    digest: String,
}

impl OwnedFixture {
    fn new(original: &Path) -> Result<Self, &'static str> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        std::fs::create_dir_all(&root).map_err(|_| "create temporary root")?;
        let directory =
            root.join(format!("rampage-local-typing-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&directory).map_err(|_| "create owned directory")?;
        let owned = Self {
            path: directory.join("fixture.snapshot.json"),
            context: directory.join("model-context"),
            directory,
            digest: rampage_arch::hex::bytes(&Sha256::digest(OWNED_FIXTURE)),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&owned.directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "restrict owned directory")?;
        }
        std::fs::copy(original, &owned.path).map_err(|_| "copy owned fixture")?;
        let bytes = std::fs::read(&owned.path).map_err(|_| "read owned fixture")?;
        if rampage_arch::hex::bytes(&Sha256::digest(&bytes)) != owned.digest {
            return Err("fixture identity differs from the owned local-variables snapshot");
        }
        std::fs::create_dir(&owned.context).map_err(|_| "create isolated model context")?;
        Ok(owned)
    }

    fn sidecar(&self) -> Result<PathBuf, &'static str> {
        let binary = rampage_loaders::Binary::open(&self.path).map_err(|_| "read snapshot identity")?;
        let identity =
            rampage_analysis::capture_identity::capture_identity(&binary).ok_or("snapshot identity unavailable")?;
        Ok(self.directory.join(format!(".{}-{}.jsonl", identity.schema, identity.sha256)))
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        // This directory was exclusively created above; includes context, sidecar and lock files.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn task(digest: &str) -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-1-local-typing".into(),
        kind: TaskKind::Capability,
        question: "At function 0x4000ae, use this user-supplied declaration exactly: \
            struct PhaseState { int4 gain; int4 bias; }; \
            Declare the struct, inspect native editable variable descriptors, and apply struct PhaseState * \
            to the editable STACK LOCAL pointer (not the RDI parameter). Rename that local to state. \
            Preserve its complete native storage selector including inclusive use_ranges. Re-decompile and \
            require state->gain and state->bias in the refreshed C. Do not change signatures, globals or bytes. \
            Return only the summary fields local_name and local_type, with the applied name and abstract type. \
            Your answer is a summary only; an independent evaluator checks native state and persistence."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-local-variables-x64".into(),
            path: "tests/data/local-variables-x64.snapshot.json".into(),
            sha256: digest.into(),
            source: "tests/fixtures/src/local-variables.c".into(),
            build: "crates/rampage-eval/tasks/phase1-1/local-pointer.toml".into(),
        },
        truth_reference: "Owned stack-local fixture; independently checked MCP state and sidecar".into(),
        required_capabilities: vec!["decompile".into(), "set_types".into(), "edit_variable".into()],
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Actual catalog and native checks determine this paired measurement".into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("local_name".into(), json!("state")),
                ("local_type".into(), json!("struct PhaseState *")),
            ]),
        },
    }
}

async fn call(client: &Peer<RoleClient>, name: &str, arguments: Value) -> Result<Value, &'static str> {
    let arguments = arguments.as_object().ok_or("invalid evaluator arguments")?.clone();
    let result = client
        .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments))
        .await
        .map_err(|_| "evaluator MCP request")?;
    if result.is_error == Some(true) {
        return Err("evaluator MCP tool error");
    }
    let text = &result.content.first().and_then(|content| content.as_text()).ok_or("evaluator MCP text")?.text;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err("evaluator MCP result exceeds bound");
    }
    serde_json::from_str(text).map_err(|_| "evaluator MCP JSON")
}

fn stack_local(decompilation: &Value) -> Result<&Value, &'static str> {
    let variables = decompilation["variables"].as_array().ok_or("native variable descriptors unavailable")?;
    let mut locals = variables.iter().filter(|variable| {
        variable["editable"] == true
            && variable["kind"] == "local"
            && variable["storage"]["kind"] == "spacebase"
            && variable["storage"]["space"] == "stack"
            && variable["storage"]["address"] == "0xfffffffffffffff0"
            && variable["storage"]["size"] == 8
    });
    let local = locals.next().ok_or("expected editable native stack local unavailable")?;
    if locals.next().is_some() {
        return Err("native stack-local identity is ambiguous");
    }
    let storage: VariableStorage =
        serde_json::from_value(local["storage"].clone()).map_err(|_| "native storage is incomplete")?;
    storage.validate().map_err(|_| "native whole storage is unsupported")?;
    if local["key"].as_str() != Some(serde_json::to_string(&storage).map_err(|_| "native storage key")?.as_str()) {
        return Err("native canonical storage key mismatch");
    }
    Ok(local)
}

fn persisted(owned: &OwnedFixture, storage: &Value) -> Result<bool, &'static str> {
    let path = owned.sidecar()?;
    if !path.is_file() {
        return Ok(false);
    }
    if std::fs::metadata(&path).map_err(|_| "sidecar metadata")?.len() > 1_000_000 {
        return Err("sidecar exceeds measurement bound");
    }
    let annotations = Annotations::open_checked(path).map_err(|_| "read persisted annotations")?;
    let Some(names) = annotations.local_names().get(&ENTRY_ADDRESS) else { return Ok(false) };
    let Some(types) = annotations.local_types().get(&ENTRY_ADDRESS) else { return Ok(false) };
    let names = parse_local_names(names).map_err(|_| "persisted local names")?;
    let types = parse_local_types(types).map_err(|_| "persisted local types")?;
    let selector: VariableStorage =
        serde_json::from_value(storage.clone()).map_err(|_| "persisted storage selector")?;
    Ok(names.iter().any(|entry| entry.storage == selector && entry.name == "state")
        && types.iter().any(|entry| {
            let compact: String = entry.data_type.chars().filter(|ch| !ch.is_whitespace()).collect();
            entry.storage == selector && matches!(compact.as_str(), "structPhaseState*" | "PhaseState*")
        })
        && annotations.types().get(&ENTRY_ADDRESS).is_some_and(|text| {
            let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
            compact == "structPhaseState{int4gain;int4bias;};"
        }))
}

async fn measure(owned: &OwnedFixture) -> Result<Value, &'static str> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        rampage_mcp::RampageServer::default()
            .serve(server_transport)
            .await
            .map_err(|_| "connect in-memory server")?
            .waiting()
            .await
            .map_err(|_| "close in-memory server")
    });
    let client = MeasurementClient.serve(client_transport).await.map_err(|_| "connect in-memory client")?;
    let result = measure_connected(&client, owned).await;
    let closed = client.cancel().await.map_err(|_| "close in-memory client");
    let stopped = server.await.map_err(|_| "join in-memory server")?;
    closed?;
    stopped?;
    result
}

async fn measure_connected(client: &Peer<RoleClient>, owned: &OwnedFixture) -> Result<Value, &'static str> {
    let task = task(&owned.digest);
    task.validate().map_err(|_| "validate measurement task")?;
    let initial = call(client, "decompile", json!({"path": owned.path, "at": ENTRY})).await?;
    let initial_local = stack_local(&initial)?;
    let initial_storage = initial_local["storage"].clone();
    let initial_key = initial_local["key"].clone();
    let transport = Anthropic::from_environment().ok_or("set ANTHROPIC_API_KEY for the Anthropic transport")?;
    let mut config = AgentConfig::new(MODEL);
    config.allow_variable_edits = true;
    config.max_turns = 12;
    config.max_tool_calls = 20;
    let run = run_task(client, Some(transport), ModelSource::Provider, &task, &owned.path, &config).await;

    // These reads are independent of the model's tool intents and happen before the client is closed.
    let checked_at = Instant::now();
    let refreshed = call(client, "decompile", json!({"path": owned.path, "at": ENTRY})).await;
    let annotations = call(client, "list_annotations", json!({"path": owned.path})).await;
    let mut verification_error = None;
    let verification = (|| -> Result<Value, &'static str> {
        let refreshed = refreshed?;
        let annotations = annotations?;
        let local = stack_local(&refreshed)?;
        let code = refreshed["code"].as_str().ok_or("refreshed C unavailable")?;
        let stable = local["storage"] == initial_storage && local["key"] == initial_key;
        let typed = local["name"] == "state"
            && local["data_type"]["size"] == 8
            && local["data_type"]["name"].as_str().is_some_and(|name| {
                let compact: String = name.chars().filter(|ch| !ch.is_whitespace()).collect();
                matches!(compact.as_str(), "PhaseState*" | "structPhaseState*")
            });
        let rendered = code.contains("state->gain") && code.contains("state->bias");
        let log_persisted = persisted(owned, &initial_storage)?;
        let declared = annotations["types"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row["address"] == ENTRY
                    && row["text"].as_str().is_some_and(|text| {
                        let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
                        compact == "structPhaseState{int4gain;int4bias;};"
                    })
            })
        });
        Ok(json!({
            "native_state_verified": stable && typed && rendered && log_persisted && declared,
            "stable_storage_key": stable, "editable_local": local,
            "annotation_log_persisted": log_persisted, "mcp_type_annotation_verified": declared,
            "rendered_c": code,
        }))
    })();
    let verification = match verification {
        Ok(value) => value,
        Err(stage) => {
            verification_error = Some(stage);
            json!({"native_state_verified": false, "rendered_c": null})
        }
    };
    let disposition = match &run.disposition {
        AgentDisposition::Unrun { .. } => "unrun",
        AgentDisposition::Failed { .. } => "failed",
        AgentDisposition::Unknown { .. } => "unknown",
        AgentDisposition::Unsupported { .. } => "unsupported",
        AgentDisposition::Answer { .. } => "answer",
    };
    let catalog_inventory: Vec<_> = run
        .catalog_tool_names
        .iter()
        .map(|names| {
            json!({
                "complete": true,
                "required_tools": task.required_capabilities.iter().map(|name| {
                    json!({"name": name, "present": names.contains(name)})
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "measurement": "phase1-1-local-typing", "design": "paired-owned-fixture-not-blind-whole-program-re",
        "requested_model": MODEL, "transport": "anthropic", "model_source": run.model_source,
        "fixture_sha256": owned.digest, "entry": ENTRY,
        "initial_local_name": initial_local["name"], "initial_storage": initial_storage,
        "initial_storage_key": initial_key,
        "agent_summary": {"disposition": disposition, "answer_contract_matches":
            matches!(&run.disposition, AgentDisposition::Answer { answer } if task.answer.matches(answer))},
        "model_turns": run.model_turns, "model_errors": run.model_errors,
        "tool_requests": run.tool_requests, "tool_calls": run.tool_calls, "tool_errors": run.tool_errors,
        "catalog_requests": run.catalog_requests, "catalog_tool_count": run.catalog_tool_count,
        "catalog_inventory": catalog_inventory,
        "comparison_baseline": {"source": "parent-reported-pre-change-missing-tool-catalog",
            "before": 0, "remeasured_here": false},
        "usage": run.usage, "agent_wall_time_ms": run.wall_time_ms,
        "agent_timing_boundary": run.timing_boundary,
        "evaluator_tool_calls": 3, "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "verification_error": verification_error,
        "native_state_verified": verification["native_state_verified"], "verification": verification,
        "limits": {"max_turns": config.max_turns, "max_tool_calls": config.max_tool_calls},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/local-variables-x64.snapshot.json")
    });
    if args.next().is_some() {
        return Err("usage: local_typing [owned-fixture.snapshot.json]; model is fixed");
    }
    let owned = OwnedFixture::new(&fixture)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "create measurement runtime")?;
    runtime.block_on(measure(&owned))
}

fn main() {
    let started = Instant::now();
    let evaluator_binary_sha256 = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| rampage_arch::hex::bytes(&Sha256::digest(&bytes)));
    let collector_source_sha256 = rampage_arch::hex::bytes(&Sha256::digest(include_bytes!("local_typing.rs")));
    let mut measurement = run().unwrap_or_else(|stage| {
        json!({"measurement": "phase1-1-local-typing", "status": "failed", "stage": stage,
            "native_state_verified": false})
    });
    measurement["owned_output_wall_time_ms"] = json!(started.elapsed().as_millis());
    measurement["provenance"] = json!({
        "evaluator_binary_sha256":evaluator_binary_sha256,"collector_source_sha256":collector_source_sha256,
        "measured_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok()),
    });
    measurement["owned_output_timing_boundary"] =
        json!("fixture preparation through verification, shutdown and cleanup");
    let output = measurement.to_string();
    if output.len() > MAX_OUTPUT_BYTES {
        println!("{{\"status\":\"failed\",\"stage\":\"measurement output exceeds bound\"}}");
        std::process::exit(1);
    }
    println!("{output}");
    if measurement["native_state_verified"] != true {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_check_uses_the_same_snapshot_identity_log_as_the_session() {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/local-variables-x64.snapshot.json");
        let owned = OwnedFixture::new(&fixture).unwrap();
        let session = rampage_api::Session::default();
        session.open(&owned.path, None).unwrap().comment(ENTRY_ADDRESS, Some("owned check")).unwrap();
        assert!(owned.sidecar().unwrap().is_file());
        assert!(!owned.path.with_extension("json.rampage").exists());
    }
}
