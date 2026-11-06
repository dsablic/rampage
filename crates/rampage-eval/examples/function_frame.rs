//! Opt-in, seeded read-only frame analysis on an isolated owned snapshot, not a blind RE benchmark.
//! Reuses the MCP driver over the Anthropic transport; never emits provider transcripts or answer text.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_agent::Anthropic;
use rampage_api::annotations::{Annotations, parse_local_names, parse_local_types};
use rampage_decompiler::VariableStorage;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ToolCall, run_task};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, Peer, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The pinned live model, requested through the in-process Anthropic transport (ANTHROPIC_API_KEY).
const MODEL: &str = "claude-sonnet-5-5";

const ENTRY: &str = "0x210124";
const OWNED_FIXTURE: &[u8] = include_bytes!("../../../tests/data/function-frame-arm64.snapshot.json");
const FIXTURE_SHA256: &str = "feebee327ef0394323e81b00dd7cbc7ab68fa022ad38c29a9ceb1316fb8d5204";
const MAX_OUTPUT_BYTES: usize = 65_536;
const UNRELATED_FIELDS: [&str; 8] =
    ["names", "comments", "signatures", "types", "globals", "type_library", "data_types", "operand_types"];

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

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
}

impl OwnedFixture {
    fn new(original: &Path) -> Result<Self, &'static str> {
        if digest(OWNED_FIXTURE) != FIXTURE_SHA256 {
            return Err("embedded function-frame snapshot identity mismatch");
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        std::fs::create_dir_all(&root).map_err(|_| "create temporary root")?;
        let directory = root.join(format!(
            "rampage-function-frame-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).map_err(|_| "create owned directory")?;
        let owned =
            Self { path: directory.join("fixture.snapshot.json"), context: directory.join("model-context"), directory };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&owned.directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "restrict owned directory")?;
        }
        std::fs::copy(original, &owned.path).map_err(|_| "copy owned fixture")?;
        if !owned.unchanged()? {
            return Err("fixture identity differs from the owned function-frame snapshot");
        }
        std::fs::create_dir(&owned.context).map_err(|_| "create isolated model context")?;
        Ok(owned)
    }

    fn unchanged(&self) -> Result<bool, &'static str> {
        let bytes = std::fs::read(&self.path).map_err(|_| "read owned fixture")?;
        Ok(bytes == OWNED_FIXTURE && digest(&bytes) == FIXTURE_SHA256)
    }

    fn sidecar(&self) -> Result<PathBuf, &'static str> {
        let binary = rampage_loaders::Binary::open(&self.path).map_err(|_| "read snapshot identity")?;
        let identity =
            rampage_analysis::capture_identity::capture_identity(&binary).ok_or("snapshot identity unavailable")?;
        Ok(self.directory.join(format!(".{}-{}.jsonl", identity.schema, identity.sha256)))
    }

    fn log_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let path = self.sidecar()?;
        if std::fs::metadata(&path).map_err(|_| "sidecar metadata")?.len() > 1_000_000 {
            return Err("identity log exceeds measurement bound");
        }
        std::fs::read(path).map_err(|_| "read identity-scoped log")
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

fn task() -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-4-function-frame".into(),
        kind: TaskKind::Analysis,
        question: "Inspect function_frame at 0x210124 with offset 0, limit 128 and include_tracker true. \
            Report the current first parameter name and native type, the renamed editable native stack local's \
            name, the native stack-space address width in bytes, all tracker slot offsets as sorted signed \
            integers, the x19 reload classification, and whether native stack and tracker entry-SP coordinates \
            are merged/equivalent. Distinguish entry-register stores from reload proof and account for the CALL. \
            Native signed offsets are not automatically tracker entry-SP offsets; do not infer a source-variable \
            association. Return only JSON fields parameter_name, input_type, local_name, stack_width_bytes, \
            tracker_offsets, x19_reload, coordinates_merged. Use the actual native type name and reload \
            classification string. Do not write any annotations, types, names, comments, signatures or bytes. \
            Independent native inspection and a fresh server verify current state and unchanged persistence; \
            your answer alone cannot establish success."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-function-frame-arm64".into(),
            path: "tests/data/function-frame-arm64.snapshot.json".into(),
            sha256: FIXTURE_SHA256.into(),
            source: "tests/fixtures/src/function-frame.c".into(),
            build: "crates/rampage-eval/examples/function_frame.rs".into(),
            companions: Vec::new(),
        },
        truth_reference: "Owned snapshot; seeded canonical native selectors; independent MCP and identity log".into(),
        required_capabilities: vec!["function_frame".into()],
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Actual catalog, complete relevant receipt and independent reopened native state".into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("parameter_name".into(), json!("input_value")),
                ("input_type".into(), json!("uint8")),
                ("local_name".into(), json!("frame_local")),
                ("stack_width_bytes".into(), json!(8)),
                ("tracker_offsets".into(), json!([-48, -40, -32, -24, -16])),
                ("x19_reload".into(), json!("reload_candidate")),
                ("coordinates_merged".into(), json!(false)),
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
    async fn call(&mut self, client: &Peer<RoleClient>, name: &str, input: Value) -> Result<Value, &'static str> {
        self.calls += 1;
        let result = client
            .call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(input.as_object().ok_or("invalid evaluator input")?.clone()),
            )
            .await;
        let result = match result {
            Ok(result) => native_json(result),
            Err(_) => {
                self.transport_errors += 1;
                Err("evaluator MCP request")
            }
        };
        self.errors += usize::from(result.is_err());
        result
    }

    fn summary(&self) -> Value {
        json!({"tool_calls": self.calls, "tool_errors": self.errors, "transport_errors": self.transport_errors})
    }
}

fn native_json(result: CallToolResult) -> Result<Value, &'static str> {
    if result.is_error == Some(true) || result.content.len() != 1 {
        return Err("evaluator MCP error or content shape");
    }
    let text = &result.content.first().and_then(|content| content.as_text()).ok_or("evaluator MCP text")?.text;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err("evaluator MCP result exceeds bound");
    }
    let value: Value = serde_json::from_str(text).map_err(|_| "evaluator MCP JSON")?;
    if value["truncated"] == true {
        return Err("truncated MCP JSON");
    }
    Ok(value)
}

fn frame_input(path: &Path) -> Value {
    json!({"path": path, "at": ENTRY, "offset": 0, "limit": 128, "include_tracker": true})
}

fn canonical(variable: &Value) -> Result<VariableStorage, &'static str> {
    if variable["editable"] != true {
        return Err("native variable is not editable");
    }
    let storage: VariableStorage =
        serde_json::from_value(variable["storage"].clone()).map_err(|_| "native storage descriptor")?;
    storage.validate().map_err(|_| "unsupported native storage")?;
    let key = serde_json::to_string(&storage).map_err(|_| "canonical native storage")?;
    if variable["key"].as_str() != Some(key.as_str()) {
        return Err("native storage key mismatch");
    }
    Ok(storage)
}

fn selected<'a>(variables: &'a [Value], selector: &Value) -> Option<&'a Value> {
    let mut matches = variables.iter().filter(|variable| variable["storage"] == *selector);
    let variable = matches.next()?;
    (matches.next().is_none() && canonical(variable).is_ok()).then_some(variable)
}

struct Baseline {
    parameter: Value,
    local: Value,
    local_type: Value,
    local_signed_offset: String,
    annotations: Value,
    log: Vec<u8>,
    frame: Value,
}

fn native_variables_verified(variables: &[Value], baseline: &Baseline) -> bool {
    let Some(parameter) = selected(variables, &baseline.parameter) else { return false };
    let Some(local) = selected(variables, &baseline.local) else { return false };
    parameter["kind"] == "parameter"
        && parameter["name"] == "input_value"
        && parameter["data_type"]["name"] == "uint8"
        && parameter["data_type"]["size"] == 8
        && local["kind"] == "local"
        && local["name"] == "frame_local"
        && local["data_type"] == baseline.local_type
}

fn complete_frame(report: &Value) -> bool {
    let Some(rows) = report["rows"].as_array() else { return false };
    report["address"] == ENTRY
        && report["offset"] == 0
        && report["next_offset"] == Value::Null
        && report.get("next_offset").is_some()
        && report["omitted_rows"] == 0
        && report["total_rows"].as_u64() == Some(rows.len() as u64)
        && report["available_rows"] == report["total_rows"]
        && report["native"]["available"] == true
        && report["native"]["omitted_variables"] == 0
        && report["native"]["omitted_mappings"] == 0
        && report["tracker"]["requested"] == true
        && report["tracker"]["available"] == true
        && report["tracker"]["omitted_slots"] == 0
        && report["tracker"]["omitted_register_evidence"] == 0
}

fn signed_native(mapping: &Value) -> Option<String> {
    if mapping["address_size_bytes"] != 8 {
        return None;
    }
    let address = u64::from_str_radix(mapping["address"].as_str()?.strip_prefix("0x")?, 16).ok()?;
    Some((i128::from(address) - if address & (1 << 63) != 0 { 1_i128 << 64 } else { 0 }).to_string())
}

fn frame_verified(report: &Value, baseline: &Baseline) -> bool {
    if !complete_frame(report)
        || report["native"]["frame_context"]["stack_space"] != "stack"
        || report["native"]["frame_context"]["address_size_bytes"] != 8
    {
        return false;
    }
    let rows = report["rows"].as_array().unwrap();
    let variables: Vec<_> =
        rows.iter().filter_map(|row| row.get("native_variable").filter(|v| v.is_object())).cloned().collect();
    if !native_variables_verified(&variables, baseline) {
        return false;
    }
    let Some(coordinates) = report["coordinates"].as_array() else { return false };
    let native: Vec<_> = coordinates.iter().filter(|coordinate| coordinate["id"] == "native:stack").collect();
    let tracker: Vec<_> = coordinates.iter().filter(|coordinate| coordinate["id"] == "tracker:entry_sp").collect();
    if native.len() != 1
        || tracker.len() != 1
        || native[0]["source"] != "native_decompiler"
        || native[0]["space"] != "stack"
        || native[0]["origin"] != "native_spacebase_register"
        || tracker[0]["source"] != "stack_tracker"
        || tracker[0]["space"] != Value::Null
        || tracker[0]["origin"] != "function_entry_stack_pointer"
    {
        return false;
    }
    let mut offsets = Vec::new();
    let mut local_seen = false;
    let mut x19_store = false;
    let mut x19_candidate = false;
    for row in rows {
        match row["source"].as_str() {
            Some("native_decompiler") => {
                if !matches!(row["category"].as_str(), Some("parameter" | "local")) {
                    return false;
                }
                let Some(mappings) = row["raw_native_storage"].as_array() else { return false };
                let Some(locations) = row["locations"].as_array() else { return false };
                for (index, mapping) in mappings.iter().enumerate() {
                    if mapping["kind"] == "spacebase" && mapping["space"] == "stack" {
                        let Some(signed) = signed_native(mapping) else { return false };
                        let matching: Vec<_> = locations
                            .iter()
                            .filter(|location| {
                                location["mapping_index"] == index && location["piece_index"] == Value::Null
                            })
                            .collect();
                        if matching.len() != 1
                            || matching[0]["address_size_bits"] != 64
                            || matching[0]["coordinate_id"] != "native:stack"
                            || matching[0]["signed_offset"] != signed
                        {
                            return false;
                        }
                    }
                }
                if row["native_variable"]["storage"] == baseline.local {
                    local_seen =
                        row["coordinate_id"] == "native:stack" && row["signed_offset"] == baseline.local_signed_offset;
                }
            }
            Some("stack_tracker") => {
                if row["coordinate_id"] != "tracker:entry_sp"
                    || row["native_variable"] != Value::Null
                    || row["raw_native_storage"] != json!([])
                    || row["locations"] != json!([])
                    || row["editable"] != false
                {
                    return false;
                }
                match row["category"].as_str() {
                    Some("tracker_slot") => {
                        let slot = &row["tracker_slot"];
                        let Some(offset) = slot["offset"].as_str().and_then(|offset| offset.parse::<i64>().ok()) else {
                            return false;
                        };
                        if row["signed_offset"] != slot["offset"]
                            || slot["bits"] != 64
                            || !slot["reads"].is_array()
                            || !slot["writes"].is_array()
                        {
                            return false;
                        }
                        offsets.push(offset);
                    }
                    Some("register_evidence") => {
                        let evidence = &row["register_evidence"];
                        if evidence["classification"] == "matching_register_reload"
                            || row["signed_offset"] != evidence["offset"]
                        {
                            return false;
                        }
                        if evidence["register"] == 19 {
                            if evidence["offset"] != "-16" || evidence["bits"] != 64 {
                                return false;
                            }
                            match evidence["classification"].as_str() {
                                Some("entry_register_store") => {
                                    x19_store = evidence["confidence"] == "ssa_proven"
                                        && evidence["stores"].as_array().is_some_and(|sites| !sites.is_empty())
                                        && evidence["restores"] == json!([]);
                                }
                                Some("reload_candidate") => {
                                    x19_candidate = evidence["confidence"] == "conditional"
                                        && evidence["stores"] == json!([])
                                        && evidence["restores"].as_array().is_some_and(|sites| !sites.is_empty());
                                }
                                _ => return false,
                            }
                        }
                    }
                    _ => return false,
                }
            }
            _ => return false,
        }
    }
    offsets.sort_unstable();
    local_seen && x19_store && x19_candidate && offsets == [-48, -40, -32, -24, -16]
}

fn annotations_exact(annotations: &Value, baseline: &Baseline) -> bool {
    if !UNRELATED_FIELDS.iter().all(|name| annotations[name].as_array().is_some_and(Vec::is_empty))
        || !annotations.get("warnings").is_none_or(|warnings| warnings.as_array().is_some_and(Vec::is_empty))
    {
        return false;
    }
    let parse = |field: &str| -> Option<&str> {
        let entries = annotations[field].as_array()?;
        (entries.len() == 1 && entries[0]["address"] == ENTRY).then(|| entries[0]["text"].as_str()).flatten()
    };
    let names = parse("local_names").and_then(|text| parse_local_names(text).ok());
    let types = parse("local_types").and_then(|text| parse_local_types(text).ok());
    names.is_some_and(|names| {
        names.len() == 2
            && [(&baseline.parameter, "input_value"), (&baseline.local, "frame_local")].iter().all(
                |(selector, name)| {
                    names.iter().any(|entry| {
                        serde_json::to_value(&entry.storage).ok().as_ref() == Some(*selector) && entry.name == *name
                    })
                },
            )
    }) && types.is_some_and(|types| {
        types.len() == 1
            && types[0].data_type == "uint8"
            && serde_json::to_value(&types[0].storage).ok().as_ref() == Some(&baseline.parameter)
    })
}

fn persisted(owned: &OwnedFixture) -> Result<Value, &'static str> {
    let annotations = Annotations::open_checked(owned.sidecar()?).map_err(|_| "read persisted annotations")?;
    if !annotations.warnings().is_empty() {
        return Err("persisted annotation warnings");
    }
    let mut result = json!({});
    for (name, map) in [
        ("names", annotations.names()),
        ("comments", annotations.comments()),
        ("signatures", annotations.signatures()),
        ("types", annotations.types()),
        ("globals", annotations.globals()),
        ("type_library", annotations.type_library()),
        ("local_names", annotations.local_names()),
        ("local_types", annotations.local_types()),
        ("data_types", annotations.data_types()),
        ("operand_types", annotations.operand_types()),
    ] {
        result[name] = json!(
            map.iter().map(|(at, text)| { json!({"address": format!("0x{at:x}"), "text": text}) }).collect::<Vec<_>>()
        );
    }
    Ok(result)
}

fn annotations_match(actual: &Value, stored: &Value) -> bool {
    actual.get("warnings").is_none_or(|warnings| warnings.as_array().is_some_and(Vec::is_empty))
        && stored
            .as_object()
            .is_some_and(|fields| fields.iter().all(|(name, expected)| actual.get(name) == Some(expected)))
}

async fn prepare(
    client: &Peer<RoleClient>,
    owned: &OwnedFixture,
    checks: &mut Checks,
) -> Result<Baseline, &'static str> {
    checks.call(client, "enable_tools", json!({"groups": ["types"]})).await?;
    let initial = checks.call(client, "decompile", json!({"path": owned.path, "at": ENTRY})).await?;
    let variables = initial["variables"].as_array().ok_or("initial native descriptors")?;
    let parameter =
        variables.iter().find(|variable| variable["kind"] == "parameter").ok_or("first parameter unavailable")?;
    canonical(parameter)?;
    if parameter["storage"]["size"] != 8 {
        return Err("first parameter width does not support uint8");
    }
    let local = variables
        .iter()
        .find(|variable| {
            variable["kind"] == "local"
                && variable["editable"] == true
                && variable["storage"]["kind"] == "spacebase"
                && variable["storage"]["space"] == "stack"
        })
        .ok_or("editable native stack local unavailable")?;
    canonical(local)?;
    let unseeded = checks.call(client, "function_frame", frame_input(&owned.path)).await?;
    if !complete_frame(&unseeded) || owned.sidecar()?.exists() {
        return Err("unseeded read-only query created log or incomplete frame");
    }
    let rows = unseeded["rows"].as_array().ok_or("initial frame rows")?;
    let matching: Vec<_> = rows.iter().filter(|row| row["native_variable"]["storage"] == local["storage"]).collect();
    if matching.len() != 1 || matching[0]["coordinate_id"] != "native:stack" {
        return Err("selected native local frame coordinate");
    }
    let local_signed_offset = matching[0]["signed_offset"].as_str().ok_or("native local signed offset")?.to_owned();
    let mut local_type = None;
    for (variable, name, data_type) in [(parameter, "input_value", Some("uint8")), (local, "frame_local", None)] {
        let mut input = json!({"path": owned.path, "at": ENTRY, "storage": variable["storage"], "name": name});
        if let Some(data_type) = data_type {
            input["data_type"] = json!(data_type);
        }
        let receipt = checks.call(client, "edit_variable", input).await?;
        if receipt["address"] != ENTRY || receipt["storage"] != variable["storage"] {
            return Err("seed edit native selector receipt");
        }
        if name == "frame_local" {
            let variables = receipt["decompilation"]["variables"].as_array().ok_or("seed local descriptors")?;
            local_type =
                Some(selected(variables, &local["storage"]).ok_or("seeded local selector")?["data_type"].clone());
        }
    }
    let seed_log = owned.log_bytes()?;
    let annotations = checks.call(client, "list_annotations", json!({"path": owned.path})).await?;
    let stored = persisted(owned)?;
    let frame = checks.call(client, "function_frame", frame_input(&owned.path)).await?;
    let baseline = Baseline {
        parameter: parameter["storage"].clone(),
        local: local["storage"].clone(),
        local_type: local_type.ok_or("seeded native local type")?,
        local_signed_offset,
        annotations: stored,
        log: seed_log,
        frame,
    };
    if !annotations_exact(&baseline.annotations, &baseline) {
        return Err("seeded exact annotation state");
    }
    if !annotations_match(&annotations, &baseline.annotations) {
        return Err("seeded MCP annotation state");
    }
    if !frame_verified(&baseline.frame, &baseline) {
        return Err("seeded native frame state");
    }
    if owned.log_bytes()? != baseline.log {
        return Err("seed query changed annotation log");
    }
    if !owned.unchanged()? {
        return Err("seed query changed fixture");
    }
    Ok(baseline)
}

async fn verify(client: &Peer<RoleClient>, owned: &OwnedFixture, baseline: &Baseline, checks: &mut Checks) -> Value {
    let enabled = checks.call(client, "enable_tools", json!({"groups":["types"]})).await;
    let frame = checks.call(client, "function_frame", frame_input(&owned.path)).await;
    let decompiled = checks.call(client, "decompile", json!({"path": owned.path, "at": ENTRY})).await;
    let annotations = checks.call(client, "list_annotations", json!({"path": owned.path})).await;
    let result = (|| -> Result<Value, &'static str> {
        enabled?;
        let frame = frame?;
        let decompiled = decompiled?;
        let annotations = annotations?;
        let stored = persisted(owned)?;
        let frame_ok = frame_verified(&frame, baseline) && frame == baseline.frame;
        let variables_ok =
            decompiled["variables"].as_array().is_some_and(|variables| native_variables_verified(variables, baseline));
        let annotations_ok = annotations_exact(&stored, baseline)
            && stored == baseline.annotations
            && annotations_match(&annotations, &stored);
        let log = owned.log_bytes()?;
        let log_ok = log == baseline.log;
        let bytes_ok = owned.unchanged()?;
        Ok(json!({
            "native_state_verified": frame_ok && variables_ok && annotations_ok && log_ok && bytes_ok,
            "complete_native_frame_verified": frame_ok, "current_native_descriptors_verified": variables_ok,
            "exact_seed_annotations_verified": annotations_ok, "read_only_identity_log_unchanged": log_ok,
            "fixture_bytes_and_sha256_unchanged": bytes_ok, "annotation_log_sha256": digest(&log),
        }))
    })();
    result.unwrap_or_else(|stage| json!({"native_state_verified": false, "verification_error": stage}))
}

fn call_evidence(call: &ToolCall) -> Option<(Value, Value)> {
    if !call.invoked || call.is_error || call.input.truncated || call.output.truncated {
        return None;
    }
    let input = serde_json::from_str(&call.input.text).ok()?;
    let result: CallToolResult = serde_json::from_str(&call.output.text).ok()?;
    Some((input, native_json(result).ok()?))
}

fn workflow_verified(run: &AgentRun, path: &Path, baseline: &Baseline) -> bool {
    run.calls.iter().any(|call| {
        if call.name != "function_frame" {
            return false;
        }
        let Some((input, report)) = call_evidence(call) else { return false };
        input == frame_input(path) && frame_verified(&report, baseline) && report == baseline.frame
    })
}

fn task_verified(run: &AgentRun, native_state: bool, workflow: bool) -> bool {
    run.model_source == Some(ModelSource::Provider)
        && run.requested_model == MODEL
        && native_state
        && workflow
        && matches!(&run.disposition, AgentDisposition::Answer { answer } if task().answer.matches(answer))
}

fn summary(run: &AgentRun) -> Value {
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
            json!({"complete": true, "tool_count": names.len(), "function_frame_present":
            names.iter().any(|name| name == "function_frame")})
        })
        .collect();
    json!({
        "disposition": disposition, "answer_contract_matches":
            matches!(&run.disposition, AgentDisposition::Answer { answer } if task().answer.matches(answer)),
        "model_source": run.model_source, "model_turns": run.model_turns, "model_errors": run.model_errors,
        "tool_requests": run.tool_requests, "tool_calls": run.tool_calls, "tool_errors": run.tool_errors,
        "catalog_requests": run.catalog_requests, "catalog_tool_count": run.catalog_tool_count,
        "catalog_inventory": catalogs, "usage": run.usage, "agent_wall_time_ms": run.wall_time_ms,
        "agent_timing_boundary": run.timing_boundary,
    })
}

async fn measure(owned: &OwnedFixture) -> Result<Value, &'static str> {
    let task = task();
    task.validate().map_err(|_| "validate measurement task")?;
    let mut config = AgentConfig::new(MODEL);
    config.max_turns = 12;
    config.max_tool_calls = 20;
    config.max_record_bytes = MAX_OUTPUT_BYTES;
    let first = Connection::open().await?;
    let mut seed = Checks::default();
    let prepared_at = Instant::now();
    let prepared = prepare(&first.client, owned, &mut seed).await;
    let preparation_wall_time_ms = prepared_at.elapsed().as_millis();
    let baseline = match prepared {
        Ok(baseline) => baseline,
        Err(stage) => {
            first.close().await?;
            return Err(stage);
        }
    };
    let transport = match Anthropic::from_environment() {
        Some(transport) => transport,
        None => {
            first.close().await?;
            return Err("set ANTHROPIC_API_KEY for the Anthropic transport");
        }
    };
    let run = run_task(&first.client, Some(transport), ModelSource::Provider, &task, &owned.path, &config).await;
    let checked_at = Instant::now();
    let mut checks = Checks::default();
    let initial = verify(&first.client, owned, &baseline, &mut checks).await;
    first.close().await?;
    let reopened = Connection::open().await?;
    let fresh = verify(&reopened.client, owned, &baseline, &mut checks).await;
    reopened.close().await?;
    let stable_log = owned.log_bytes()? == baseline.log;
    let native_state = initial["native_state_verified"] == true
        && fresh["native_state_verified"] == true
        && stable_log
        && owned.unchanged()?;
    let workflow = workflow_verified(&run, &owned.path, &baseline);
    Ok(json!({
        "measurement": "phase1-4-function-frame", "design": "seeded-read-only-owned-fixture-not-blind-re",
        "requested_model": MODEL, "transport": "anthropic", "fixture_sha256": FIXTURE_SHA256,
        "entry": ENTRY, "agent_summary": summary(&run), "seed_metrics": seed.summary(),
        "preparation_wall_time_ms": preparation_wall_time_ms, "verifier_metrics": checks.summary(),
        "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "selected_parameter_storage": baseline.parameter, "selected_local_storage": baseline.local,
        "selected_local_native_signed_offset": baseline.local_signed_offset,
        "selected_local_native_type_unchanged": baseline.local_type,
        "selected_local_coordinate_id": "native:stack", "tracker_coordinate_id": "tracker:entry_sp",
        "source_variable_association_asserted": false, "seed_annotation_log_sha256": digest(&baseline.log),
        "native_state_verified": native_state, "model_tool_workflow_verified": workflow,
        "task_verified": task_verified(&run, native_state, workflow), "initial_verification": initial,
        "fresh_server_verification": fresh, "stable_annotation_log": stable_log,
        "limits": {"max_turns": config.max_turns, "max_tool_calls": config.max_tool_calls,
            "max_record_bytes": config.max_record_bytes, "max_retained_bytes": config.max_retained_bytes,
            "max_conversation_bytes": config.max_conversation_bytes, "frame_limit": 128},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/function-frame-arm64.snapshot.json")
    });
    if args.next().is_some() {
        return Err("usage: function_frame [owned-fixture.snapshot.json]; model is fixed");
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
    let evaluator_binary_sha256 =
        std::env::current_exe().ok().and_then(|path| std::fs::read(path).ok()).map(|bytes| digest(&bytes));
    let mut measurement = run().unwrap_or_else(|stage| {
        json!({"measurement": "phase1-4-function-frame", "status": "failed", "stage": stage,
            "native_state_verified": false, "task_verified": false})
    });
    measurement["owned_output_wall_time_ms"] = json!(started.elapsed().as_millis());
    measurement["owned_output_timing_boundary"] =
        json!("fixture preparation through verification, shutdown and cleanup");
    measurement["provenance"] = json!({
        "evaluator_binary_sha256": evaluator_binary_sha256,
        "collector_source_sha256": digest(include_bytes!("function_frame.rs")),
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
    use rampage_api::annotations::{LocalNameAnnotation, LocalTypeAnnotation, encode_local_names, encode_local_types};
    use rampage_eval::parity_agent::RetainedText;

    fn descriptor(parameter: bool) -> Value {
        let storage: VariableStorage = serde_json::from_value(json!({
            "kind": if parameter { "processor" } else { "spacebase" },
            "space": if parameter { "register" } else { "stack" },
            "address": if parameter { "0x4000" } else { "0xffffffffffffffe0" },
            "size": 8, "use_ranges": [],
        }))
        .unwrap();
        json!({"editable": true, "storage": storage, "key": serde_json::to_string(&storage).unwrap(),
            "kind": if parameter { "parameter" } else { "local" },
            "name": if parameter { "input_value" } else { "frame_local" },
            "data_type": {"name": if parameter { "uint8" } else { "undefined8" }, "size": 8}})
    }

    fn annotations(parameter: &Value, local: &Value) -> Value {
        let parameter: VariableStorage = serde_json::from_value(parameter.clone()).unwrap();
        let local: VariableStorage = serde_json::from_value(local.clone()).unwrap();
        let names = encode_local_names(&[
            LocalNameAnnotation { storage: parameter.clone(), name: "input_value".into() },
            LocalNameAnnotation { storage: local, name: "frame_local".into() },
        ])
        .unwrap();
        let types =
            encode_local_types(&[LocalTypeAnnotation { storage: parameter, data_type: "uint8".into() }]).unwrap();
        let mut annotations = json!({
            "local_names": [{"address": ENTRY, "text": names}],
            "local_types": [{"address": ENTRY, "text": types}],
        });
        for field in UNRELATED_FIELDS {
            annotations[field] = json!([]);
        }
        annotations
    }

    fn baseline() -> Baseline {
        let parameter = descriptor(true);
        let local = descriptor(false);
        let mut rows = vec![
            json!({"category": "parameter", "source": "native_decompiler", "native_variable": parameter,
                "raw_native_storage": [], "locations": []}),
            json!({"category": "local", "source": "native_decompiler", "native_variable": local,
                "coordinate_id": "native:stack", "signed_offset": "-32",
                "raw_native_storage": [{"kind": "spacebase", "space": "stack", "address_size_bytes": 8,
                    "address": "0xffffffffffffffe0", "size": 8}],
                "locations": [{"mapping_index": 0, "piece_index": null, "coordinate_id": "native:stack",
                    "address_size_bits": 64, "signed_offset": "-32", "size_bytes": 8}]}),
        ];
        for offset in [-48, -40, -32, -24, -16] {
            rows.push(json!({"category": "tracker_slot", "source": "stack_tracker", "editable": false,
                "coordinate_id": "tracker:entry_sp", "signed_offset": offset.to_string(),
                "raw_native_storage": [], "locations": [], "native_variable": null,
                "tracker_slot": {"offset": offset.to_string(), "bits": 64, "reads": [], "writes": [ENTRY]}}));
        }
        for store in [true, false] {
            rows.push(json!({"category": "register_evidence", "source": "stack_tracker", "editable": false,
                "coordinate_id": "tracker:entry_sp", "signed_offset": "-16",
                "raw_native_storage": [], "locations": [], "native_variable": null,
                "register_evidence": {"register": 19, "offset": "-16", "bits": 64,
                    "classification": if store { "entry_register_store" } else { "reload_candidate" },
                    "confidence": if store { "ssa_proven" } else { "conditional" },
                    "stores": if store { vec!["0x210130"] } else { vec![] },
                    "restores": if store { vec![] } else { vec!["0x210158"] }}}));
        }
        let frame = json!({"address": ENTRY, "offset": 0, "limit": 128, "next_offset": null,
            "total_rows": rows.len(), "available_rows": rows.len(), "omitted_rows": 0,
            "native": {"available": true, "omitted_variables": 0, "omitted_mappings": 0,
                "frame_context": {"stack_space": "stack", "address_size_bytes": 8}},
            "tracker": {"requested": true, "available": true, "omitted_slots": 0,
                "omitted_register_evidence": 0},
            "coordinates": [
                {"id": "native:stack", "source": "native_decompiler", "space": "stack",
                    "origin": "native_spacebase_register"},
                {"id": "tracker:entry_sp", "source": "stack_tracker", "space": null,
                    "origin": "function_entry_stack_pointer"}], "rows": rows});
        Baseline {
            parameter: parameter["storage"].clone(),
            local: local["storage"].clone(),
            local_type: local["data_type"].clone(),
            local_signed_offset: "-32".into(),
            annotations: annotations(&parameter["storage"], &local["storage"]),
            log: vec![],
            frame,
        }
    }

    fn retained(text: String) -> RetainedText {
        RetainedText { original_bytes: text.len(), text, truncated: false }
    }

    fn receipt(report: Value) -> ToolCall {
        ToolCall {
            name: "function_frame".into(),
            tool_use_id: "synthetic-frame".into(),
            input: retained(frame_input(Path::new("owned.snapshot.json")).to_string()),
            output: retained(
                json!({"content": [{"type": "text", "text": report.to_string()}],
                "isError": false})
                .to_string(),
            ),
            invoked: true,
            is_error: false,
        }
    }

    fn completed_run(baseline: &Baseline) -> AgentRun {
        let mut run = AgentRun::without_provider(&AgentConfig::new(MODEL));
        run.model_source = Some(ModelSource::Provider);
        let AnswerContract::Exact { fields, .. } = task().answer else { panic!("exact contract") };
        run.disposition = AgentDisposition::Answer { answer: json!(fields) };
        run.calls = vec![receipt(baseline.frame.clone())];
        run
    }

    fn workflow(run: &AgentRun, baseline: &Baseline) -> bool {
        workflow_verified(run, Path::new("owned.snapshot.json"), baseline)
    }

    #[test]
    fn wrong_offsets_widths_names_and_coordinate_merging_fail_native_grading() {
        let baseline = baseline();
        assert!(frame_verified(&baseline.frame, &baseline));
        for (pointer, replacement) in [
            ("/rows/2/tracker_slot/offset", json!("-56")),
            ("/rows/2/signed_offset", json!("-56")),
            ("/rows/2/coordinate_id", json!("native:stack")),
            ("/rows/1/coordinate_id", json!("tracker:entry_sp")),
            ("/rows/1/locations/0/address_size_bits", json!(32)),
            ("/rows/1/locations/0/signed_offset", json!("-16")),
            ("/rows/1/raw_native_storage/0/address_size_bytes", json!(4)),
            ("/native/frame_context/address_size_bytes", json!(4)),
            ("/rows/0/native_variable/name", json!("guessed")),
            ("/rows/0/native_variable/data_type/name", json!("int8")),
            ("/rows/1/native_variable/data_type/size", json!(4)),
            ("/coordinates/0/origin", json!("function_entry_stack_pointer")),
            ("/coordinates/1/id", json!("native:stack")),
            ("/next_offset", json!(9)),
            ("/omitted_rows", json!(1)),
            ("/tracker/available", json!(false)),
        ] {
            let mut report = baseline.frame.clone();
            *report.pointer_mut(pointer).unwrap() = replacement;
            assert!(!frame_verified(&report, &baseline), "{pointer}");
        }
        let mut report = baseline.frame.clone();
        report["rows"][2]["tracker_slot"]["offset"] = json!("-56");
        report["rows"][2]["signed_offset"] = json!("-56");
        assert!(!frame_verified(&report, &baseline));
    }

    #[test]
    fn call_clobber_cannot_be_upgraded_to_a_proven_x19_restore() {
        let baseline = baseline();
        for (field, replacement) in [
            ("classification", json!("matching_register_reload")),
            ("confidence", json!("ssa_proven")),
            ("stores", json!(["0x210130"])),
            ("restores", json!([])),
        ] {
            let mut report = baseline.frame.clone();
            report["rows"][8]["register_evidence"][field] = replacement;
            assert!(!frame_verified(&report, &baseline), "{field}");
        }
        let mut report = baseline.frame.clone();
        report["rows"][7]["register_evidence"]["restores"] = json!(["0x210158"]);
        assert!(!frame_verified(&report, &baseline));
    }

    #[test]
    fn relevant_successful_complete_frame_receipt_is_required() {
        let baseline = baseline();
        assert!(workflow(&completed_run(&baseline), &baseline));
        for mode in 0..10 {
            let mut run = completed_run(&baseline);
            match mode {
                0 => run.calls.clear(),
                1 => run.calls[0].input.truncated = true,
                2 => run.calls[0].output.truncated = true,
                3 => run.calls[0].is_error = true,
                4 => run.calls[0].invoked = false,
                5 => run.calls[0].name = "function_summary".into(),
                6 => run.calls[0].input = retained(json!({"path": "other", "at": ENTRY}).to_string()),
                7 => {
                    let mut report = baseline.frame.clone();
                    report["address"] = json!("0x210120");
                    run.calls[0] = receipt(report);
                }
                8 => {
                    let mut report = baseline.frame.clone();
                    report["next_offset"] = json!(1);
                    run.calls[0] = receipt(report);
                }
                _ => {
                    let mut envelope: Value = serde_json::from_str(&run.calls[0].output.text).unwrap();
                    envelope["isError"] = json!(true);
                    run.calls[0].output = retained(envelope.to_string());
                }
            }
            assert!(!workflow(&run, &baseline), "mode {mode}");
            assert!(!task_verified(&run, true, workflow(&run, &baseline)));
        }
    }

    #[test]
    fn seeded_state_never_rescues_failed_unrun_scripted_or_wrong_answers() {
        let baseline = baseline();
        let mut run = completed_run(&baseline);
        assert!(task_verified(&run, true, workflow(&run, &baseline)));
        assert!(!task_verified(&run, false, true));
        assert!(!task_verified(&run, true, false));
        for disposition in [
            AgentDisposition::Failed { reason: "rejected write".into() },
            AgentDisposition::Unrun { reason: "no provider".into() },
            AgentDisposition::Unknown { reason: "unknown".into() },
            AgentDisposition::Unsupported { reason: "unsupported".into() },
            AgentDisposition::Answer { answer: json!({"coordinates_merged": true}) },
        ] {
            run.disposition = disposition;
            assert!(!task_verified(&run, true, true));
        }
        for source in [None, Some(ModelSource::Scripted)] {
            let mut run = completed_run(&baseline);
            run.model_source = source;
            assert!(!task_verified(&run, true, true));
        }
        let mut wrong_model = completed_run(&baseline);
        wrong_model.requested_model = "other-provider/model".into();
        assert!(!task_verified(&wrong_model, true, true));
        for (field, replacement) in [
            ("tracker_offsets", json!([-48, -40, -32, -24, -8])),
            ("coordinates_merged", json!(true)),
            ("x19_reload", json!("matching_register_reload")),
        ] {
            let mut run = completed_run(&baseline);
            let AgentDisposition::Answer { answer } = &mut run.disposition else { unreachable!() };
            answer[field] = replacement;
            assert!(!task_verified(&run, true, true));
        }
    }

    #[test]
    fn only_exact_seeded_local_names_and_parameter_type_are_permitted() {
        let baseline = baseline();
        assert!(annotations_exact(&baseline.annotations, &baseline));
        for field in UNRELATED_FIELDS {
            let mut changed = baseline.annotations.clone();
            changed[field] = json!([{"address": ENTRY, "text": "unauthorized"}]);
            assert!(!annotations_exact(&changed, &baseline), "{field}");
        }
        for field in ["local_names", "local_types"] {
            let mut changed = baseline.annotations.clone();
            changed[field] = json!([]);
            assert!(!annotations_exact(&changed, &baseline));
            let mut changed = baseline.annotations.clone();
            changed[field][0]["address"] = json!("0x210120");
            assert!(!annotations_exact(&changed, &baseline));
            let mut changed = baseline.annotations.clone();
            changed[field][0]["text"] = json!("[]");
            assert!(!annotations_exact(&changed, &baseline));
        }
        let mut changed = baseline.annotations.clone();
        let mut names: Value = serde_json::from_str(changed["local_names"][0]["text"].as_str().unwrap()).unwrap();
        names[0]["name"] = json!("agent_write");
        changed["local_names"][0]["text"] = json!(names.to_string());
        assert!(!annotations_exact(&changed, &baseline));
        let mut changed = baseline.annotations.clone();
        let mut types: Value = serde_json::from_str(changed["local_types"][0]["text"].as_str().unwrap()).unwrap();
        types[0]["data_type"] = json!("int8");
        changed["local_types"][0]["text"] = json!(types.to_string());
        assert!(!annotations_exact(&changed, &baseline));
    }

    #[tokio::test]
    async fn owned_seed_and_read_only_inspection_survive_fresh_server_without_extra_log_writes() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/function-frame-arm64.snapshot.json");
        let owned = OwnedFixture::new(&path).unwrap();
        let first = Connection::open().await.unwrap();
        let baseline = prepare(&first.client, &owned, &mut Checks::default()).await.unwrap();
        assert!(
            verify(&first.client, &owned, &baseline, &mut Checks::default()).await["native_state_verified"] == true
        );
        assert_eq!(owned.log_bytes().unwrap(), baseline.log);
        first.close().await.unwrap();
        let fresh = Connection::open().await.unwrap();
        assert!(
            verify(&fresh.client, &owned, &baseline, &mut Checks::default()).await["native_state_verified"] == true
        );
        fresh.close().await.unwrap();
        assert_eq!(owned.log_bytes().unwrap(), baseline.log);
        assert!(owned.unchanged().unwrap());
    }
}
