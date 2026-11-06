//! Opt-in project type-library measurement on an isolated owned snapshot, not a blind RE benchmark.
//! Uses the Anthropic transport and emits bounded metrics, never provider transcripts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_agent::Anthropic;
use rampage_api::annotations::{Annotations, LibraryDeclaration, parse_type_library};
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ToolCall, run_task};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, Peer, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The pinned live model, requested through the in-process Anthropic transport (ANTHROPIC_API_KEY).
const MODEL: &str = "claude-sonnet-5-5";

const OWNED_FIXTURE: &[u8] = include_bytes!("../../../tests/data/local-variables-x64.snapshot.json");
const MAX_OUTPUT_BYTES: usize = 65_536;
const NAMES: [&str; 3] = ["LibraryState", "LibraryStatePtr", "LibraryMode"];

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
            root.join(format!("rampage-type-library-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
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
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct Connection {
    client: RunningService<RoleClient, MeasurementClient>,
    server: tokio::task::JoinHandle<Result<(), &'static str>>,
}

impl Connection {
    async fn open() -> Result<Self, &'static str> {
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            rampage_mcp::RampageServer::default()
                .serve(server_transport)
                .await
                .map_err(|_| "connect in-memory server")?
                .waiting()
                .await
                .map(|_| ())
                .map_err(|_| "close in-memory server")
        });
        let client = MeasurementClient.serve(client_transport).await.map_err(|_| "connect in-memory client")?;
        Ok(Self { client, server })
    }

    async fn close(self) -> Result<(), &'static str> {
        let closed = self.client.cancel().await.map_err(|_| "close in-memory client");
        let stopped = self.server.await.map_err(|_| "join in-memory server")?;
        closed?;
        stopped
    }
}

fn task(digest: &str) -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-2-type-library".into(),
        kind: TaskKind::Capability,
        question: "Use the project-wide named type library, not function-local set_types. Declare exactly: \
            struct LibraryState { int4 gain; int4 bias; }; \
            typedef LibraryState *LibraryStatePtr; enum LibraryMode { LibraryOff=0, LibraryOn=3 }; \
            In a separate declare_types call, declare the independent spare type \
            struct LibraryScratch { int4 spare; }; \
            Inspect the declarations using list_types and get_type, then delete only LibraryScratch using \
            delete_type. Report LibraryState's field names, offsets and size, the alias pointer size, and \
            the enum's native kind. Preserve LibraryState, LibraryStatePtr and LibraryMode. No variable \
            edits are needed. Return a JSON summary with state_size, gain_offset, bias_offset, pointer_size, \
            enum_kind and scratch_deleted. Independent native inspection and a fresh server verify persistence; \
            the summary alone does not establish success."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-local-variables-x64".into(),
            path: "tests/data/local-variables-x64.snapshot.json".into(),
            sha256: digest.into(),
            source: "tests/fixtures/src/local-variables.c".into(),
            build: "crates/rampage-eval/examples/type_library.rs".into(),
            companions: Vec::new(),
        },
        truth_reference: "User-supplied declarations; target x64 native layout and identity-scoped log".into(),
        required_capabilities: ["declare_types", "delete_type", "list_types", "get_type"]
            .into_iter()
            .map(String::from)
            .collect(),
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Actual catalogs and independently reopened native state determine this measurement"
            .into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("state_size".into(), json!(8)),
                ("gain_offset".into(), json!(0)),
                ("bias_offset".into(), json!(4)),
                ("pointer_size".into(), json!(8)),
                ("enum_kind".into(), json!("enum")),
                ("scratch_deleted".into(), json!(true)),
            ]),
            hex_integers: false,
        },
    }
}

#[derive(Default)]
struct Checks {
    calls: usize,
    errors: usize,
    transport_errors: usize,
}

impl Checks {
    async fn call(
        &mut self,
        client: &Peer<RoleClient>,
        name: &str,
        input: Value,
    ) -> Result<CallToolResult, &'static str> {
        self.calls += 1;
        let result = client
            .call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(input.as_object().ok_or("invalid evaluator input")?.clone()),
            )
            .await;
        match result {
            Ok(result) => {
                self.errors += usize::from(result.is_error == Some(true));
                Ok(result)
            }
            Err(_) => {
                self.errors += 1;
                self.transport_errors += 1;
                Err("evaluator MCP request")
            }
        }
    }
}

fn native_json(result: Result<CallToolResult, &'static str>) -> Result<Value, &'static str> {
    let result = result?;
    if result.is_error == Some(true) {
        return Err("evaluator MCP tool error");
    }
    let text = &result.content.first().and_then(|content| content.as_text()).ok_or("evaluator MCP text")?.text;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err("evaluator MCP result exceeds bound");
    }
    serde_json::from_str(text).map_err(|_| "evaluator MCP JSON")
}

fn persisted(owned: &OwnedFixture) -> Result<(bool, String), &'static str> {
    let path = owned.sidecar()?;
    if std::fs::metadata(&path).map_err(|_| "sidecar metadata")?.len() > 1_000_000 {
        return Err("sidecar exceeds measurement bound");
    }
    let annotations = Annotations::open_checked(path).map_err(|_| "read persisted annotations")?;
    let library = annotations.type_library();
    let text = library.get(&0).ok_or("project type library missing at address zero")?;
    let declarations = parse_type_library(text).map_err(|_| "persisted type library")?;
    let valid = library.len() == 1 && annotations.warnings().is_empty() && exact_stored_names(&declarations);
    Ok((valid, rampage_arch::hex::bytes(&Sha256::digest(text.as_bytes()))))
}

fn exact_stored_names(declarations: &[LibraryDeclaration]) -> bool {
    let names: Vec<_> = declarations.iter().flat_map(|unit| unit.names.iter().map(String::as_str)).collect();
    names.len() == NAMES.len() && names.into_iter().collect::<BTreeSet<_>>() == NAMES.into_iter().collect()
}

fn native_layouts(state: &Value, alias: &Value, enumeration: &Value) -> (bool, bool, bool) {
    let state_layout = state["name"] == NAMES[0]
        && state["kind"] == "struct"
        && state["size"] == 8
        && state["alignment"] == 4
        && state.get("packing") == Some(&Value::Null)
        && state["incomplete"] == false
        && state["fields"].as_array().is_some_and(|fields| {
            fields.len() == 2
                && [("gain", 0), ("bias", 4)].into_iter().all(|(name, offset)| {
                    fields.iter().any(|field| {
                        field["name"] == name
                            && field["offset"] == offset
                            && field["type_name"] == "int4"
                            && field["size"] == 4
                    })
                })
        });
    let alias_layout = alias["name"] == NAMES[1]
        && alias["kind"] == "typedef"
        && alias["size"] == 8
        && alias["alignment"] == 8
        && alias["incomplete"] == false
        && alias["target"].as_str().is_some_and(|target| {
            let compact: String = target.chars().filter(|ch| !ch.is_whitespace()).collect();
            matches!(compact.as_str(), "LibraryState*" | "structLibraryState*")
        })
        && alias["dependencies"] == json!(["LibraryState"])
        && alias["by_value_dependencies"] == json!([]);
    let enum_layout = enumeration["name"] == NAMES[2]
        && enumeration["kind"] == "enum"
        && enumeration["size"] == 4
        && enumeration["alignment"] == 4
        && enumeration["incomplete"] == false
        && enumeration["enum_values"].as_array().is_some_and(|values| {
            values.len() == 2
                && values.iter().any(|value| value["name"] == "LibraryOff" && value["value"] == "0")
                && values.iter().any(|value| value["name"] == "LibraryOn" && value["value"] == "3")
        });
    (state_layout, alias_layout, enum_layout)
}

async fn verify(client: &Peer<RoleClient>, owned: &OwnedFixture, checks: &mut Checks) -> Value {
    let enabled = checks.call(client, "enable_tools", json!({"groups": ["types"]})).await;
    let state = checks.call(client, "get_type", json!({"path": owned.path, "name": NAMES[0]})).await;
    let alias = checks.call(client, "get_type", json!({"path": owned.path, "name": NAMES[1]})).await;
    let enumeration = checks.call(client, "get_type", json!({"path": owned.path, "name": NAMES[2]})).await;
    let scratch = checks.call(client, "get_type", json!({"path": owned.path, "name": "LibraryScratch"})).await;
    let listing = checks
        .call(
            client,
            "list_types",
            json!({"path": owned.path, "contains": "Library",
        "offset": 0, "limit": 16}),
        )
        .await;
    let result = (|| -> Result<Value, &'static str> {
        native_json(enabled)?;
        let state = native_json(state)?;
        let alias = native_json(alias)?;
        let enumeration = native_json(enumeration)?;
        // Pagination wrappers are not part of this check's contract; exact names/layouts come from get_type.
        native_json(listing)?;
        let scratch_missing = scratch?.is_error == Some(true);
        let (state_layout, alias_layout, enum_layout) = native_layouts(&state, &alias, &enumeration);
        let (log_match, log_digest) = persisted(owned)?;
        Ok(json!({
            "native_state_verified": state_layout && alias_layout && enum_layout && scratch_missing && log_match,
            "state_layout_verified": state_layout, "alias_layout_verified": alias_layout,
            "enum_verified": enum_layout, "native_list_query_succeeded": true,
            "scratch_missing_mcp_is_error": scratch_missing, "annotation_log_persisted": log_match,
            "annotation_library_sha256": log_digest,
        }))
    })();
    result.unwrap_or_else(|stage| json!({"native_state_verified": false, "verification_error": stage}))
}

fn summary(run: &AgentRun, task: &ParityTask) -> Value {
    let disposition = match &run.disposition {
        AgentDisposition::Unrun { .. } => "unrun",
        AgentDisposition::Failed { .. } => "failed",
        AgentDisposition::Unknown { .. } => "unknown",
        AgentDisposition::Unsupported { .. } => "unsupported",
        AgentDisposition::Answer { .. } => "answer",
    };
    let catalogs: Vec<_> = run
        .catalog_tool_names
        .iter()
        .map(|names| {
            json!({
                "complete": true, "required_tools": task.required_capabilities.iter().map(|name| {
                    json!({"name": name, "present": names.contains(name)})
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "disposition": disposition, "answer_contract_matches":
            matches!(&run.disposition, AgentDisposition::Answer { answer } if task.answer.matches(answer)),
        "model_source": run.model_source, "model_turns": run.model_turns, "model_errors": run.model_errors,
        "tool_requests": run.tool_requests, "tool_calls": run.tool_calls, "tool_errors": run.tool_errors,
        "catalog_requests": run.catalog_requests, "catalog_tool_count": run.catalog_tool_count,
        "catalog_inventory": catalogs, "usage": run.usage, "agent_wall_time_ms": run.wall_time_ms,
        "agent_timing_boundary": run.timing_boundary,
    })
}

fn call_evidence(call: &ToolCall) -> Option<(Value, Value)> {
    if !call.invoked || call.is_error || call.input.truncated || call.output.truncated {
        return None;
    }
    let input = serde_json::from_str(&call.input.text).ok()?;
    let result: CallToolResult = serde_json::from_str(&call.output.text).ok()?;
    Some((input, native_json(Ok(result)).ok()?))
}

fn workflow_verified(run: &AgentRun) -> bool {
    let mut retained = BTreeSet::new();
    let mut scratch_declared = false;
    let mut listed = false;
    let mut state_inspected = false;
    let mut scratch_deleted = false;
    for call in &run.calls {
        let Some((input, receipt)) = call_evidence(call) else {
            if call.invoked && !call.is_error && matches!(call.name.as_str(), "declare_types" | "delete_type") {
                retained.clear();
                scratch_declared = false;
                listed = false;
                state_inspected = false;
                scratch_deleted = false;
            }
            continue;
        };
        match call.name.as_str() {
            "declare_types" => {
                let names = receipt["types"]
                    .as_array()
                    .filter(|types| !types.is_empty())
                    .and_then(|types| types.iter().map(|ty| ty["name"].as_str()).collect::<Option<Vec<_>>>());
                if receipt["changed"] != false
                    && names.as_ref().is_none_or(|names| names.iter().any(|name| NAMES.contains(name)))
                {
                    listed = false;
                    state_inspected = false;
                    scratch_deleted = false;
                }
                let Some(names) = names else { continue };
                if names == ["LibraryScratch"] {
                    scratch_declared = true;
                    scratch_deleted = false;
                } else if names.iter().all(|name| NAMES.contains(name)) {
                    retained.extend(names.into_iter().map(String::from));
                }
            }
            "list_types"
                if retained.len() == NAMES.len()
                    && receipt["types"]
                        .as_array()
                        .is_some_and(|types| NAMES.iter().all(|name| types.iter().any(|ty| ty["name"] == *name))) =>
            {
                listed = true;
            }
            "get_type"
                if input["name"].as_str().is_some_and(|name| {
                    NAMES.contains(&name) && retained.contains(name) && receipt["name"] == name
                }) =>
            {
                state_inspected |= input["name"] == "LibraryState";
            }
            "delete_type"
                if receipt["changed"] != false
                    && receipt["removed"].as_array().is_some_and(|removed| {
                        removed.iter().any(|name| name.as_str().is_some_and(|name| NAMES.contains(&name)))
                    }) =>
            {
                retained.retain(|name| {
                    !receipt["removed"]
                        .as_array()
                        .is_some_and(|removed| removed.iter().any(|removed| removed.as_str() == Some(name.as_str())))
                });
                listed = false;
                state_inspected = false;
                scratch_deleted = false;
            }
            "delete_type"
                if input["name"] == "LibraryScratch"
                    && receipt["removed"] == json!(["LibraryScratch"])
                    && scratch_declared
                    && retained.len() == NAMES.len()
                    && listed
                    && state_inspected =>
            {
                scratch_deleted = true;
                scratch_declared = false;
            }
            _ => {}
        }
    }
    scratch_deleted && retained.len() == NAMES.len() && listed && state_inspected
}

fn task_verified(run: &AgentRun, task: &ParityTask, native_state: bool, workflow: bool) -> bool {
    run.model_source == Some(ModelSource::Provider)
        && native_state
        && workflow
        && matches!(&run.disposition, AgentDisposition::Answer { answer } if task.answer.matches(answer))
}

async fn measure(owned: &OwnedFixture) -> Result<Value, &'static str> {
    let task = task(&owned.digest);
    task.validate().map_err(|_| "validate measurement task")?;
    let transport = Anthropic::from_environment().ok_or("set ANTHROPIC_API_KEY for the Anthropic transport")?;
    let mut config = AgentConfig::new(MODEL);
    config.allow_type_library_edits = true;
    config.max_turns = 12;
    config.max_tool_calls = 24;
    let first = Connection::open().await?;
    let run = run_task(&first.client, Some(transport), ModelSource::Provider, &task, &owned.path, &config).await;
    let checked_at = Instant::now();
    let mut checks = Checks::default();
    let initial = verify(&first.client, owned, &mut checks).await;
    first.close().await?;
    // A new server owns a new Session and must restore the named types from the identity-scoped log.
    let reopened = Connection::open().await?;
    let fresh = verify(&reopened.client, owned, &mut checks).await;
    reopened.close().await?;
    let stable_log = initial["annotation_library_sha256"].is_string()
        && initial["annotation_library_sha256"] == fresh["annotation_library_sha256"];
    let workflow = workflow_verified(&run);
    let native_state = initial["native_state_verified"] == true && fresh["native_state_verified"] == true && stable_log;
    Ok(json!({
        "measurement": "phase1-2-type-library", "design": "paired-owned-fixture-not-blind-whole-program-re",
        "requested_model": MODEL, "transport": "anthropic", "fixture_sha256": owned.digest,
        "agent_summary": summary(&run, &task),
        "evaluator_tool_calls": checks.calls, "evaluator_tool_errors": checks.errors,
        "evaluator_transport_errors": checks.transport_errors, "expected_missing_type_errors": 2,
        "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "native_state_verified": native_state, "task_verified": task_verified(&run, &task, native_state, workflow),
        "model_tool_workflow_verified": workflow,
        "initial_verification": initial, "fresh_server_verification": fresh, "stable_annotation_log": stable_log,
        "limits": {"max_turns": config.max_turns, "max_tool_calls": config.max_tool_calls},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/local-variables-x64.snapshot.json")
    });
    if args.next().is_some() {
        return Err("usage: type_library [owned-fixture.snapshot.json]; model is fixed");
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
    let collector_source_sha256 = rampage_arch::hex::bytes(&Sha256::digest(include_bytes!("type_library.rs")));
    let mut measurement = run().unwrap_or_else(|stage| {
        json!({
            "measurement": "phase1-2-type-library", "status": "failed", "stage": stage,
            "native_state_verified": false, "task_verified": false,
        })
    });
    measurement["owned_output_wall_time_ms"] = json!(started.elapsed().as_millis());
    measurement["owned_output_timing_boundary"] =
        json!("fixture preparation through verification, shutdown and cleanup");
    measurement["provenance"] = json!({
        "evaluator_binary_sha256": evaluator_binary_sha256, "collector_source_sha256": collector_source_sha256,
        "measured_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok()),
    });
    let output = measurement.to_string();
    if output.len() > MAX_OUTPUT_BYTES {
        println!("{{\"status\":\"failed\",\"stage\":\"measurement output exceeds bound\"}}");
        std::process::exit(1);
    }
    println!("{output}");
    if measurement["task_verified"] != true {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_eval::parity_agent::RetainedText;

    fn retained(text: String) -> RetainedText {
        RetainedText { original_bytes: text.len(), text, truncated: false }
    }

    fn receipt(name: &str, input: Value, result: Value) -> ToolCall {
        ToolCall {
            name: name.into(),
            tool_use_id: "scripted-receipt".into(),
            input: retained(input.to_string()),
            output: retained(
                json!({"content": [{"type": "text", "text": result.to_string()}],
                "isError": false})
                .to_string(),
            ),
            invoked: true,
            is_error: false,
        }
    }

    fn declared(names: &[&str]) -> ToolCall {
        receipt(
            "declare_types",
            json!({"header": "/* receipt names, not this text, establish what was declared */"}),
            json!({"changed": true, "types": names.iter().map(|name| json!({"name": name})).collect::<Vec<_>>(),
                "removed": []}),
        )
    }

    fn workflow() -> Vec<ToolCall> {
        vec![
            declared(&NAMES),
            declared(&["LibraryScratch"]),
            receipt(
                "list_types",
                json!({"limit": 16}),
                json!({"types": NAMES.iter().map(|name| json!({"name": name})).collect::<Vec<_>>()}),
            ),
            receipt("get_type", json!({"name": "LibraryState"}), json!({"name": "LibraryState"})),
            receipt(
                "delete_type",
                json!({"name": "LibraryScratch"}),
                json!({"changed": true, "types": [], "removed": ["LibraryScratch"]}),
            ),
        ]
    }

    fn completed_run() -> AgentRun {
        let task = task(&"0".repeat(64));
        let mut run = AgentRun::without_provider(&AgentConfig::new(MODEL));
        run.model_source = Some(ModelSource::Provider);
        run.disposition = AgentDisposition::Answer {
            answer: json!({
                "state_size": 8, "gain_offset": 0, "bias_offset": 4, "pointer_size": 8,
                "enum_kind": "enum", "scratch_deleted": true,
            }),
        };
        run.calls = workflow();
        assert!(task.answer.matches(match &run.disposition {
            AgentDisposition::Answer { answer } => answer,
            _ => unreachable!(),
        }));
        run
    }

    #[test]
    fn correct_state_and_crud_do_not_accept_failed_unrun_or_wrong_provider_outcomes() {
        let task = task(&"0".repeat(64));
        let mut run = completed_run();
        assert!(workflow_verified(&run));
        assert!(task_verified(&run, &task, true, true));
        assert!(!task_verified(&run, &task, false, true));
        assert!(!task_verified(&run, &task, true, false));
        for disposition in [
            AgentDisposition::Failed { reason: "tool request rejected by benchmark policy after CRUD".into() },
            AgentDisposition::Unrun { reason: "no provider".into() },
            AgentDisposition::Unknown { reason: "not completed".into() },
            AgentDisposition::Unsupported { reason: "not supported".into() },
            AgentDisposition::Answer {
                answer: json!({
                    "state_size": 16, "gain_offset": 0, "bias_offset": 4, "pointer_size": 8,
                    "enum_kind": "enum", "scratch_deleted": true,
                }),
            },
        ] {
            run.disposition = disposition;
            assert!(!task_verified(&run, &task, true, workflow_verified(&run)), "{:?}", run.disposition);
        }
        let mut run = completed_run();
        for source in [None, Some(ModelSource::Scripted)] {
            run.model_source = source;
            assert!(!task_verified(&run, &task, true, true));
        }
    }

    #[test]
    fn canonical_persisted_names_reject_extra_definitions_and_duplicates() {
        let units = |names: &[&str]| {
            names
                .iter()
                .map(|name| LibraryDeclaration {
                    names: vec![(*name).into()],
                    declarations: format!("struct {name} {{ int4 value; }};"),
                    packing: None,
                    source: None,
                })
                .collect::<Vec<_>>()
        };
        let mut declarations = units(&NAMES);
        assert!(exact_stored_names(&declarations));
        declarations.extend(units(&["UnrequestedExtra"]));
        let stored = rampage_api::annotations::encode_type_library(&declarations).unwrap();
        let parsed = parse_type_library(&stored).unwrap();
        assert!(!exact_stored_names(&parsed));
        assert!(!exact_stored_names(&units(&["LibraryState", "LibraryStatePtr"])));
        assert!(!exact_stored_names(&units(&["LibraryState", "LibraryStatePtr", "LibraryMode", "LibraryState"])));
    }

    fn layouts() -> [Value; 3] {
        [
            json!({"name": "LibraryState", "kind": "struct", "size": 8, "alignment": 4,
                "packing": null, "incomplete": false, "fields": [
                    {"name": "gain", "offset": 0, "type_name": "int4", "size": 4},
                    {"name": "bias", "offset": 4, "type_name": "int4", "size": 4}]}),
            json!({"name": "LibraryStatePtr", "kind": "typedef", "size": 8, "alignment": 8,
                "incomplete": false, "target": "LibraryState *", "dependencies": ["LibraryState"],
                "by_value_dependencies": []}),
            json!({"name": "LibraryMode", "kind": "enum", "size": 4, "alignment": 4, "incomplete": false,
                "enum_values": [{"name": "LibraryOff", "value": "0"}, {"name": "LibraryOn", "value": "3"}]}),
        ]
    }

    #[test]
    fn native_semantics_reject_same_sized_but_wrong_types_packing_and_enum_layouts() {
        let check = |values: &[Value; 3]| native_layouts(&values[0], &values[1], &values[2]) == (true, true, true);
        assert!(check(&layouts()));
        for (index, pointer, replacement) in [
            (0, "/kind", json!("union")),
            (0, "/alignment", json!(1)),
            (0, "/packing", json!(4)),
            (0, "/incomplete", json!(true)),
            (0, "/fields/0/type_name", json!("float4")),
            (0, "/fields/1/size", json!(8)),
            (0, "/fields/1/offset", json!(0)),
            (1, "/kind", json!("primitive")),
            (1, "/target", json!("int8")),
            (1, "/target", json!("LibraryState")),
            (1, "/dependencies", json!([])),
            (2, "/size", json!(8)),
            (2, "/alignment", json!(8)),
            (2, "/enum_values/1/value", json!("4")),
        ] {
            let mut values = layouts();
            *values[index].pointer_mut(pointer).unwrap() = replacement;
            assert!(!check(&values), "type {index} pointer {pointer}");
        }
        let mut values = layouts();
        values[0]["fields"].as_array_mut().unwrap().push(json!({"name": "extra", "offset": 0}));
        assert!(!check(&values));
        let mut values = layouts();
        values[1]["target"] = json!("struct LibraryState *");
        assert!(check(&values), "equivalent struct-tag pointer spelling");
    }

    #[test]
    fn combined_declaration_receipt_does_not_establish_a_separate_scratch_call() {
        let mut run = completed_run();
        run.calls = workflow();
        run.calls.remove(1);
        run.calls[0] = declared(&["LibraryState", "LibraryStatePtr", "LibraryMode", "LibraryScratch"]);
        assert!(!workflow_verified(&run));
        run.calls.insert(1, declared(&["LibraryScratch"]));
        assert!(!workflow_verified(&run), "retained declarations also require independent receipts");
        run.calls.insert(0, declared(&NAMES));
        assert!(workflow_verified(&run));
    }

    #[test]
    fn receipt_names_not_comments_prove_declarations_and_allow_multiple_retained_calls() {
        let mut run = completed_run();
        run.calls[1] = declared(&["SomethingElse"]);
        run.calls[1].input =
            retained(json!({"declarations": "/* LibraryScratch */ struct SomethingElse {};"}).to_string());
        assert!(!workflow_verified(&run));
        run.calls = workflow();
        run.calls.remove(0);
        for name in NAMES.into_iter().rev() {
            run.calls.insert(0, declared(&[name]));
        }
        assert!(workflow_verified(&run));
        run.calls.swap(0, 6);
        assert!(!workflow_verified(&run), "deletion cannot precede declaration proof");
    }

    #[test]
    fn truncated_or_error_receipts_cannot_prove_required_operations() {
        for index in 0..workflow().len() {
            for truncate_output in [false, true] {
                let mut run = completed_run();
                if truncate_output {
                    run.calls[index].output.truncated = true;
                } else {
                    run.calls[index].input.truncated = true;
                }
                assert!(!workflow_verified(&run), "call {index}, output {truncate_output}");
            }
            let mut run = completed_run();
            run.calls[index].is_error = true;
            assert!(!workflow_verified(&run), "error call {index}");
        }
    }

    #[test]
    fn inspections_must_cover_retained_names_after_their_declaration() {
        let mut run = completed_run();
        let mut calls = workflow();
        let deletion = calls.pop().unwrap();
        run.calls = vec![
            receipt("list_types", json!({}), json!({"types": []})),
            receipt("get_type", json!({"name": "int4"}), json!({"name": "int4"})),
            declared(&NAMES),
            declared(&["LibraryScratch"]),
            deletion,
        ];
        assert!(!workflow_verified(&run), "empty list and builtin inspection before declarations");
        run.calls = workflow();
        assert!(workflow_verified(&run));
        run.calls[2] = receipt(
            "list_types",
            json!({"limit": 16}),
            json!({"types": [
            {"name": "LibraryState"}, {"name": "LibraryStatePtr"}]}),
        );
        assert!(!workflow_verified(&run), "a listing must cover all retained names");
        run.calls = workflow();
        let listing = run.calls.remove(2);
        run.calls.insert(0, listing);
        assert!(!workflow_verified(&run), "a relevant listing before declaration is not proof");
        for (input_name, receipt_name) in [
            ("LibraryState", "int4"),
            ("int4", "int4"),
            ("int4", "LibraryState"),
            ("LibraryStatePtr", "LibraryStatePtr"),
        ] {
            run.calls = workflow();
            run.calls[3] = receipt("get_type", json!({"name": input_name}), json!({"name": receipt_name}));
            assert!(!workflow_verified(&run), "get_type {input_name} returning {receipt_name}");
        }
        run.calls = workflow();
        let inspection = run.calls.remove(3);
        run.calls.insert(0, inspection);
        assert!(!workflow_verified(&run), "the inspected target must already have declaration evidence");
    }

    #[test]
    fn retained_changes_invalidate_inspection_but_no_op_receipts_preserve_it() {
        for after_deletion in [false, true] {
            for changed in [false, true] {
                let mut run = completed_run();
                let mut edit = declared(&["LibraryState"]);
                edit.output = receipt(
                    "declare_types",
                    json!({}),
                    json!({
                        "changed": changed, "types": [{"name": "LibraryState"}], "removed": [],
                    }),
                )
                .output;
                let at = if after_deletion { run.calls.len() } else { run.calls.len() - 1 };
                run.calls.insert(at, edit);
                assert_eq!(workflow_verified(&run), !changed, "changed {changed}, after deletion {after_deletion}");
            }
        }
        let mut run = completed_run();
        run.calls.insert(
            4,
            receipt(
                "delete_type",
                json!({"name": "LibraryMode"}),
                json!({
                    "changed": true, "types": [], "removed": ["LibraryMode"],
                }),
            ),
        );
        run.calls.insert(5, declared(&["LibraryMode"]));
        assert!(!workflow_verified(&run), "deletion and redeclaration require fresh inspection");
        let fresh = workflow();
        run.calls.insert(6, fresh[2].clone());
        run.calls.insert(7, fresh[3].clone());
        assert!(workflow_verified(&run), "fresh relevant inspection can establish new proof before deletion");
    }
}
