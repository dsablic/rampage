//! Opt-in seeded direct-call propagation measurement, not blind or whole-program reverse engineering.
//! Automatic ephemeral native recovery and durable lower-priority hints are measured separately.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_api::annotations::{
    Annotations, DerivedTypeHint, TypeHintAnnotation, TypeHintEvidence, TypeHintTarget, encode_type_hints,
    parse_local_names, parse_local_types, parse_type_hints, parse_type_library,
};
use rampage_decompiler::VariableStorage;
use rampage_decompiler::results::Storage;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ToolCall, run_task};
use rampage_eval::parity_opencode::{MODEL, MODEL_VARIANT, OpenCodeTransport};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, Peer, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CALLEE: &str = "0x201160";
const CALLER: &str = "0x201170";
const OWNED_FIXTURE: &[u8] = include_bytes!("../../../tests/data/type-propagation-x64.snapshot.json");
const FIXTURE_SHA256: &str = "40293c1598f6f1915fff91c6efbfb32a42e97d1790059dfd3a7c386a04312fc6";
const DECLARATIONS: &str = "struct PropState { int4 gain; int4 bias; };";
const MAX_OUTPUT_BYTES: usize = 65_536;
const MAX_FUNCTIONS: usize = 4;
const MAX_CANDIDATES: usize = 32;
const USER_FIELDS: [&str; 10] = [
    "names",
    "comments",
    "signatures",
    "types",
    "globals",
    "type_library",
    "local_names",
    "local_types",
    "data_types",
    "operand_types",
];

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
            return Err("embedded type-propagation snapshot identity mismatch");
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join("opencode");
        std::fs::create_dir_all(&root).map_err(|_| "create temporary root")?;
        let directory = root.join(format!(
            "rampage-type-propagation-{}-{}",
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
            return Err("fixture differs from owned type-propagation snapshot");
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
            return Err("identity log exceeds bound");
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

fn task() -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-5-type-propagation".into(),
        kind: TaskKind::Analysis,
        question: "The evaluator declared PropState { int4 gain; int4 bias; } and explicitly typed the native \
            first parameter of callee 0x201160 as PropState *, named state. Do not edit those analyst types. \
            Preview propagate_types at caller 0x201170 with apply false, max_functions 4 and max_candidates 32. \
            Inspect its actual candidates and provenance, then apply the same request with apply true. \
            After applying, inspect get_type for PropState and decompile caller 0x201170. Report only JSON \
            caller_parameter_type, callee_parameter_type, analyst_types_preserved, derived_hints_persisted. \
            Use the actual native pointer type spelling. Automatic ephemeral propagation may already recover \
            typed caller C before durable apply; a C delta is not required or evidence of persistence. \
            Only propagate_types may mutate this owned fixture, only at 0x201170 and within these bounds. \
            Do not write signatures, local types, names, declarations, comments, bytes, or any other annotations \
            or paths. Independent native inspection and fresh-server persistence checks verify the result."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-type-propagation-x64".into(),
            path: "tests/data/type-propagation-x64.snapshot.json".into(),
            sha256: FIXTURE_SHA256.into(),
            source: "tests/fixtures/src/type-propagation.c".into(),
            build: "crates/rampage-eval/examples/type_propagation.rs".into(),
        },
        truth_reference: "Owned snapshot, explicit callee native storage, provenance-bound receipts and identity log"
            .into(),
        required_capabilities: ["propagate_types", "decompile", "get_type"].into_iter().map(String::from).collect(),
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Actual catalogs, complete MCP receipts and independently reopened native state".into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("caller_parameter_type".into(), json!("PropState *")),
                ("callee_parameter_type".into(), json!("PropState *")),
                ("analyst_types_preserved".into(), json!(true)),
                ("derived_hints_persisted".into(), json!(true)),
            ]),
        },
    }
}

fn address(value: &Value) -> Option<u64> {
    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
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

fn signature_storage(parameter: &Value) -> Option<VariableStorage> {
    let storage: Storage = serde_json::from_value(parameter["storage"].clone()).ok()?;
    VariableStorage::try_from(&storage).ok()
}

fn first_parameter(report: &Value) -> Result<&Value, &'static str> {
    let parameter = report["structure"]["signature"]["parameters"]
        .as_array()
        .and_then(|parameters| parameters.first())
        .ok_or("native signature first parameter unavailable")?;
    let storage = signature_storage(parameter).ok_or("native first parameter whole storage unavailable")?;
    let variables = report["variables"].as_array().ok_or("native variable descriptors unavailable")?;
    let mut selected = variables
        .iter()
        .filter(|variable| variable["kind"] == "parameter" && canonical(variable).ok().as_ref() == Some(&storage));
    let variable = selected.next().ok_or("editable native signature first parameter unavailable")?;
    if selected.next().is_some() || variable["data_type"] != parameter["data_type"] {
        return Err("ambiguous or inconsistent native first parameter descriptor");
    }
    Ok(variable)
}

fn native_parameter(report: &Value, at: &str, storage: &Value, callee: bool) -> bool {
    let Ok(parameter) = first_parameter(report) else { return false };
    report["address"] == at
        && canonical(parameter).is_ok()
        && parameter["storage"] == *storage
        && parameter["data_type"]["name"] == "PropState *"
        && parameter["data_type"]["size"] == 8
        && (!callee || parameter["name"] == "state")
        && report["code"].as_str().is_some_and(|code| code.contains("PropState *"))
}

fn propagation_input(path: &Path, apply: bool) -> Value {
    json!({"path": path, "at": CALLER, "apply": apply,
        "max_functions": MAX_FUNCTIONS, "max_candidates": MAX_CANDIDATES})
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
        ("type_hints", annotations.type_hints()),
    ] {
        result[name] = json!(
            map.iter().map(|(at, text)| json!({"address": format!("0x{at:x}"), "text": text})).collect::<Vec<_>>()
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

struct Baseline {
    callee_storage: Value,
    caller_storage: Value,
    annotations: Value,
    library: Value,
    log: Vec<u8>,
    unseeded_caller_code_sha256: String,
    seeded_caller_code_sha256: String,
    seeded_caller_already_typed: bool,
    native_edges: Vec<NativeEdge>,
}

type NativeTarget = (u64, TypeHintTarget);

#[derive(Clone)]
struct NativeEdge {
    source: NativeTarget,
    target: NativeTarget,
    evidence: TypeHintEvidence,
}

fn parameter_target(report: &Value, index: usize) -> Option<TypeHintTarget> {
    let parameter = report["structure"]["signature"]["parameters"].as_array()?.get(index)?;
    let storage = signature_storage(parameter)?;
    Some(TypeHintTarget::Parameter { index: u32::try_from(index).ok()?, storage })
}

fn argument_target(report: &Value, storage: &VariableStorage) -> Option<TypeHintTarget> {
    let parameters = report["structure"]["signature"]["parameters"].as_array()?;
    for index in 0..parameters.len() {
        let Some(target) = parameter_target(report, index) else { continue };
        if matches!(&target, TypeHintTarget::Parameter { storage: selected, .. } if selected == storage) {
            return Some(target);
        }
    }
    let mut selected = report["variables"]
        .as_array()?
        .iter()
        .filter(|variable| variable["kind"] == "local" && canonical(variable).ok().as_ref() == Some(storage));
    selected.next()?;
    selected.next().is_none().then(|| TypeHintTarget::Local { storage: storage.clone() })
}

fn native_edges(reports: &[Value]) -> Result<Vec<NativeEdge>, &'static str> {
    if reports.len() > MAX_FUNCTIONS {
        return Err("native source-proof context exceeds function bound");
    }
    let mut edges = Vec::new();
    for caller in reports {
        let function = address(&caller["address"]).ok_or("native caller address")?;
        let calls = caller["structure"]["calls"].as_array().ok_or("native direct-call evidence unavailable")?;
        for call in calls {
            if call["indirect"] != false || !call["evidence_unavailable"].is_null() {
                continue;
            }
            let Some(at) = address(&call["source"]) else { continue };
            let Some(callee) = reports.iter().find(|report| report["address"] == call["target"]) else { continue };
            let Some(destination) = address(&callee["address"]) else { continue };
            let Some(arguments) = call["arguments"].as_array() else { continue };
            for argument in arguments {
                if argument["value"]["status"] != "variable" {
                    continue;
                }
                let Some(index) = argument["parameter_index"].as_u64().and_then(|index| usize::try_from(index).ok())
                else {
                    continue;
                };
                let Some(parameter) = parameter_target(callee, index) else { continue };
                let Ok(storage) = serde_json::from_value::<VariableStorage>(argument["value"]["storage"].clone())
                else {
                    continue;
                };
                let Some(value) = argument_target(caller, &storage) else { continue };
                if storage.validate().is_err()
                    || storage.size != 8
                    || !matches!(&parameter, TypeHintTarget::Parameter { storage, .. } if storage.size == 8)
                {
                    continue;
                }
                for (source, target, reason) in [
                    (
                        (destination, parameter.clone()),
                        (function, value.clone()),
                        "callee parameter to caller argument",
                    ),
                    ((function, value), (destination, parameter), "caller argument to callee parameter"),
                ] {
                    edges.push(NativeEdge {
                        source,
                        target,
                        evidence: TypeHintEvidence { function, at, reason: reason.into() },
                    });
                }
            }
        }
    }
    Ok(edges)
}

fn explicit_seed_exact(annotations: &Value, storage: &Value) -> bool {
    let text = |field: &str, at: &str| -> Option<&str> {
        let entries = annotations[field].as_array()?;
        (entries.len() == 1 && entries[0]["address"] == at).then(|| entries[0]["text"].as_str()).flatten()
    };
    USER_FIELDS
        .iter()
        .filter(|field| !matches!(**field, "type_library" | "local_names" | "local_types"))
        .all(|field| annotations[field].as_array().is_some_and(Vec::is_empty))
        && text("type_library", "0x0").and_then(|text| parse_type_library(text).ok()).is_some_and(|units| {
            units.len() == 1
                && units[0].names == ["PropState"]
                && units[0].declarations.split_whitespace().collect::<String>()
                    == DECLARATIONS.split_whitespace().collect::<String>()
                && units[0].packing.is_none()
                && units[0].source.is_none()
        })
        && text("local_names", CALLEE).and_then(|text| parse_local_names(text).ok()).is_some_and(|entries| {
            entries.len() == 1
                && entries[0].name == "state"
                && serde_json::to_value(&entries[0].storage).ok().as_ref() == Some(storage)
        })
        && text("local_types", CALLEE).and_then(|text| parse_local_types(text).ok()).is_some_and(|entries| {
            entries.len() == 1
                && entries[0].data_type == "PropState *"
                && serde_json::to_value(&entries[0].storage).ok().as_ref() == Some(storage)
        })
}

async fn prepare(
    client: &Peer<RoleClient>,
    owned: &OwnedFixture,
    checks: &mut Checks,
) -> Result<Baseline, &'static str> {
    checks.call(client, "enable_tools", json!({"groups": ["types"]})).await?;
    let unseeded = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLER})).await?;
    let callee = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLEE})).await?;
    let parameter = first_parameter(&callee)?;
    let storage = serde_json::to_value(canonical(parameter)?).map_err(|_| "seed canonical storage")?;
    if storage["size"] != 8 || owned.sidecar()?.exists() {
        return Err("unseeded native parameter or read-only log baseline");
    }
    checks.call(client, "declare_types", json!({"path": owned.path, "declarations": DECLARATIONS})).await?;
    let edited = checks
        .call(
            client,
            "edit_variable",
            json!({"path": owned.path, "at": CALLEE, "storage": storage,
                "data_type": "PropState *", "name": "state"}),
        )
        .await?;
    let seeded_callee = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLEE})).await?;
    if edited["address"] != CALLEE
        || edited["storage"] != storage
        || !native_parameter(&seeded_callee, CALLEE, &storage, true)
    {
        return Err("explicit callee seed receipt");
    }
    let caller = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLER})).await?;
    let caller_storage =
        serde_json::to_value(canonical(first_parameter(&caller)?)?).map_err(|_| "seeded caller native storage")?;
    let wrapper = checks.call(client, "decompile", json!({"path": owned.path, "at": "0x201180"})).await?;
    let global_caller = checks.call(client, "decompile", json!({"path": owned.path, "at": "0x2011a0"})).await?;
    let native_edges = native_edges(&[seeded_callee, caller.clone(), wrapper, global_caller])?;
    let annotations = persisted(owned)?;
    let query = checks.call(client, "list_annotations", json!({"path": owned.path})).await?;
    let library = checks.call(client, "get_type", json!({"path": owned.path, "name": "PropState"})).await?;
    if !explicit_seed_exact(&annotations, &storage)
        || !annotations["type_hints"].as_array().is_some_and(Vec::is_empty)
        || !annotations_match(&query, &annotations)
        || !owned.unchanged()?
    {
        return Err("exact explicit-only seed annotations");
    }
    Ok(Baseline {
        callee_storage: storage,
        caller_storage: caller_storage.clone(),
        annotations,
        library,
        log: owned.log_bytes()?,
        unseeded_caller_code_sha256: digest(unseeded["code"].as_str().ok_or("unseeded C")?.as_bytes()),
        seeded_caller_code_sha256: digest(caller["code"].as_str().ok_or("seeded C")?.as_bytes()),
        seeded_caller_already_typed: native_parameter(&caller, CALLER, &caller_storage, false),
        native_edges,
    })
}

fn known_function(function: u64) -> bool {
    matches!(function, 0x201160 | 0x201170 | 0x201180 | 0x20118c | 0x201190 | 0x2011a0)
}

fn candidate_hint(candidate: &Value, baseline: &Baseline) -> Option<(u64, DerivedTypeHint)> {
    let function = address(&candidate["function"])?;
    let hint: DerivedTypeHint = serde_json::from_value(json!({
        "target": candidate["target"], "data_type": candidate["data_type"], "evidence": candidate["evidence"],
    }))
    .ok()?;
    if !known_function(function)
        || hint.data_type != "PropState *"
        || !explicit_seed_exact(&baseline.annotations, &baseline.callee_storage)
        || hint.evidence.is_empty()
        || hint
            .evidence
            .iter()
            .any(|evidence| !known_function(evidence.function) || evidence.at < 0x201160 || evidence.at >= 0x2011b4)
    {
        return None;
    }
    let source_storage: VariableStorage = serde_json::from_value(baseline.callee_storage.clone()).ok()?;
    let source = (0x201160, TypeHintTarget::Parameter { index: 0, storage: source_storage.clone() });
    let origin = TypeHintEvidence {
        function: 0x201160,
        at: 0x201160,
        reason: format!("explicit analyst local type for {}", serde_json::to_string(&source_storage).ok()?),
    };
    if !hint.evidence.contains(&origin)
        || hint
            .evidence
            .iter()
            .any(|evidence| *evidence != origin && !baseline.native_edges.iter().any(|edge| edge.evidence == *evidence))
    {
        return None;
    }
    let mut reachable = vec![source.clone()];
    for _ in 0..MAX_CANDIDATES {
        let before = reachable.len();
        for edge in &baseline.native_edges {
            if reachable.contains(&edge.source) && !reachable.contains(&edge.target) {
                reachable.push(edge.target.clone());
            }
        }
        if before == reachable.len() {
            break;
        }
    }
    let target = (function, hint.target.clone());
    if target == source
        || !reachable.contains(&target)
        || !baseline.native_edges.iter().any(|edge| {
            edge.target == target && reachable.contains(&edge.source) && hint.evidence.contains(&edge.evidence)
        })
    {
        return None;
    }
    Some((function, hint))
}

fn caller_candidate(candidate: &Value, baseline: &Baseline) -> bool {
    let Some((function, hint)) = candidate_hint(candidate, baseline) else { return false };
    function == 0x201170
        && hint.data_type == "PropState *"
        && matches!(hint.target, TypeHintTarget::Parameter { index: 0, ref storage }
            if serde_json::to_value(storage).ok().as_ref() == Some(&baseline.caller_storage))
        && hint.evidence.iter().any(|evidence| {
            evidence.function == 0x201160
                && evidence.at == 0x201160
                && evidence.reason.starts_with("explicit analyst local type for ")
                && evidence
                    .reason
                    .strip_prefix("explicit analyst local type for ")
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .as_ref()
                    == Some(&baseline.callee_storage)
        })
        && hint.evidence.iter().any(|evidence| {
            evidence.function == 0x201170
                && evidence.at == 0x201171
                && evidence.reason == "callee parameter to caller argument"
        })
}

fn propagation_report(report: &Value, baseline: &Baseline, apply: bool) -> bool {
    let Some(candidates) = report["candidates"].as_array() else { return false };
    let Some(applied) = report["applied"].as_array() else { return false };
    report["address"] == CALLER
        && report["source_fingerprint"].as_str().is_some_and(|fingerprint| {
            fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && !candidates.is_empty()
        && candidates.len() <= MAX_CANDIDATES
        && candidates.iter().all(|candidate| candidate_hint(candidate, baseline).is_some())
        && candidates.iter().any(|candidate| caller_candidate(candidate, baseline))
        && report["counts"]["candidates"].as_u64() == Some(candidates.len() as u64)
        && report["counts"]["applied"].as_u64() == Some(applied.len() as u64)
        && report["counts"]["functions"].as_u64().is_some_and(|count| (1..=MAX_FUNCTIONS as u64).contains(&count))
        && report["conflicts"].as_array().is_some_and(Vec::is_empty)
        && report["skipped"].is_array()
        && report["limitations"].is_array()
        && if apply { !applied.is_empty() && applied == candidates } else { applied.is_empty() }
}

fn expected_hints(report: &Value, baseline: &Baseline) -> Option<Value> {
    let fingerprint = report["source_fingerprint"].as_str()?;
    let mut grouped: BTreeMap<u64, Vec<DerivedTypeHint>> = BTreeMap::new();
    for candidate in report["candidates"].as_array()? {
        let (function, hint) = candidate_hint(candidate, baseline)?;
        grouped.entry(function).or_default().push(hint);
    }
    let mut rows = Vec::new();
    for (function, hints) in grouped {
        let text = encode_type_hints(&TypeHintAnnotation { source_fingerprint: fingerprint.into(), hints }).ok()?;
        rows.push(json!({"address": format!("0x{function:x}"), "text": text}));
    }
    Some(json!(rows))
}

fn persisted_exact(stored: &Value, baseline: &Baseline, applied: &Value, current: &Value) -> bool {
    explicit_seed_exact(stored, &baseline.callee_storage)
        && USER_FIELDS.iter().all(|field| stored[field] == baseline.annotations[field])
        && current["source_fingerprint"] == applied["source_fingerprint"]
        && current["candidates"] == applied["candidates"]
        && expected_hints(applied, baseline).as_ref() == Some(&stored["type_hints"])
        && stored["type_hints"].as_array().is_some_and(|rows| {
            !rows.is_empty()
                && rows.iter().all(|row| {
                    row["text"].as_str().and_then(|text| parse_type_hints(text).ok()).is_some_and(|payload| {
                        Some(payload.source_fingerprint.as_str()) == current["source_fingerprint"].as_str()
                    })
                })
        })
}

fn call_evidence(call: &ToolCall) -> Option<(Value, Value)> {
    if !call.invoked || call.is_error || call.input.truncated || call.output.truncated {
        return None;
    }
    let input = serde_json::from_str(&call.input.text).ok()?;
    let envelope: CallToolResult = serde_json::from_str(&call.output.text).ok()?;
    Some((input, native_json(envelope).ok()?))
}

fn read_only_tool(name: &str) -> bool {
    matches!(
        name,
        "enable_tools"
            | "list_packs"
            | "binary_info"
            | "triage"
            | "triage_report"
            | "find_main"
            | "network_surface"
            | "persistence_surface"
            | "string_decoding"
            | "find_crypto"
            | "list_functions"
            | "disassemble"
            | "function_graph"
            | "function_summary"
            | "function_frame"
            | "decompile"
            | "xrefs"
            | "list_strings"
            | "list_imports"
            | "list_exports"
            | "list_annotations"
            | "list_types"
            | "get_type"
            | "language_metadata"
            | "class_evidence"
            | "capabilities"
            | "detect_tools"
            | "entry_diagnostics"
            | "analysis_diagnostics"
            | "inspect_jump_table"
            | "dotnet_metadata"
            | "dotnet_il"
            | "inspect_raw_code"
            | "inspect_data"
            | "read_data"
            | "decode_file_range"
            | "archive_inventory"
            | "carve"
            | "pyinstaller_archive"
            | "wasm_module"
            | "identify_functions"
    )
}

fn workflow_receipt(run: &AgentRun, path: &Path, baseline: &Baseline) -> Option<Value> {
    let mut preview: Option<Value> = None;
    let mut applied: Option<Value> = None;
    let mut inspected_type = false;
    let mut inspected_caller = false;
    for call in &run.calls {
        if !call.invoked {
            continue;
        }
        let input: Value = serde_json::from_str(&call.input.text).ok()?;
        if call.input.truncated
            || (!read_only_tool(&call.name) && call.name != "propagate_types")
            || (call.name != "enable_tools" && call.name != "list_packs" && input["path"] != json!(path))
            || (call.name != "propagate_types" && input["apply"] == true)
        {
            return None;
        }
        if call.name == "propagate_types" {
            let apply = input["apply"].as_bool()?;
            if input != propagation_input(path, apply) {
                return None;
            }
            // Every attempted durable mutation invalidates earlier post-apply inspection proof.
            if apply {
                inspected_type = false;
                inspected_caller = false;
                applied = None;
            }
            let (_, report) = call_evidence(call)?;
            if !propagation_report(&report, baseline, apply) {
                return None;
            }
            if apply {
                let preview = preview.as_ref()?;
                if report["source_fingerprint"] != preview["source_fingerprint"]
                    || report["candidates"] != preview["candidates"]
                {
                    return None;
                }
                applied = Some(report);
            } else {
                preview = Some(report);
            }
        } else if let Some((input, report)) = call_evidence(call) {
            if applied.is_some() && call.name == "get_type" && input["name"] == "PropState" {
                inspected_type |= report == baseline.library;
            }
            if applied.is_some() && call.name == "decompile" && input["at"] == CALLER {
                inspected_caller |= native_parameter(&report, CALLER, &baseline.caller_storage, false);
            }
        }
    }
    (inspected_type && inspected_caller).then_some(applied).flatten()
}

async fn verify(
    client: &Peer<RoleClient>,
    owned: &OwnedFixture,
    baseline: &Baseline,
    applied: Option<&Value>,
    checks: &mut Checks,
) -> Value {
    let before = owned.log_bytes();
    let enabled = checks.call(client, "enable_tools", json!({"groups": ["types"]})).await;
    let current = checks.call(client, "propagate_types", propagation_input(&owned.path, false)).await;
    let caller = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLER})).await;
    let callee = checks.call(client, "decompile", json!({"path": owned.path, "at": CALLEE})).await;
    let library = checks.call(client, "get_type", json!({"path": owned.path, "name": "PropState"})).await;
    let query = checks.call(client, "list_annotations", json!({"path": owned.path})).await;
    let result = (|| -> Result<Value, &'static str> {
        enabled?;
        let current = current?;
        let caller = caller?;
        let callee = callee?;
        let library = library?;
        let query = query?;
        let stored = persisted(owned)?;
        let applied = applied.ok_or("missing provenance-bound model workflow")?;
        let source_ok = propagation_report(&current, baseline, false);
        let hints_ok = source_ok && persisted_exact(&stored, baseline, applied, &current);
        let native_ok = native_parameter(&caller, CALLER, &baseline.caller_storage, false)
            && native_parameter(&callee, CALLEE, &baseline.callee_storage, true);
        let analyst_ok =
            library == baseline.library && USER_FIELDS.iter().all(|field| stored[field] == baseline.annotations[field]);
        let query_ok = annotations_match(&query, &stored);
        let log = owned.log_bytes()?;
        let log_ok = before? == log;
        let bytes_ok = owned.unchanged()?;
        Ok(json!({
            "native_state_verified": hints_ok && native_ok && analyst_ok && query_ok && log_ok && bytes_ok,
            "native_caller_and_callee_parameters_verified": native_ok,
            "exact_durable_hints_and_current_source_verified": hints_ok,
            "analyst_types_preserved": analyst_ok, "native_annotation_query_matches_log": query_ok,
            "read_only_verification_log_stable": log_ok, "fixture_sha256_unchanged": bytes_ok,
            "annotation_log_sha256": digest(&log), "source_fingerprint": current["source_fingerprint"],
            "durable_hint_sha256": digest(stored["type_hints"].to_string().as_bytes()),
            "caller_code_sha256": digest(caller["code"].as_str().ok_or("verified caller C")?.as_bytes()),
            "c_delta_required": false,
        }))
    })();
    result.unwrap_or_else(|stage| json!({"native_state_verified": false, "verification_error": stage}))
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
        .enumerate()
        .map(|(index, names)| {
            let raw = run.catalog_snapshot(index);
            let definitions =
                raw.filter(|raw| !raw.truncated).and_then(|raw| serde_json::from_str::<Value>(&raw.text).ok());
            let propagation_schema = definitions.as_ref().and_then(Value::as_array).and_then(|tools| {
                tools.iter().find(|tool| tool["name"] == "propagate_types").map(|tool| tool["inputSchema"].clone())
            });
            json!({"complete": true, "tool_count": names.len(), "required_tools":
                task().required_capabilities.iter().map(|name| {
                    json!({"name": name, "present": names.contains(name)})
                }).collect::<Vec<_>>(),
                "ordered_names_sha256": digest(json!(names).to_string().as_bytes()),
                "raw_catalog_sha256": raw.filter(|raw| !raw.truncated).map(|raw| digest(raw.text.as_bytes())),
                "raw_catalog_original_bytes": raw.map(|raw| raw.original_bytes),
                "raw_catalog_complete": raw.is_some_and(|raw| !raw.truncated),
                "propagate_types_input_schema": propagation_schema,
            })
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
    config.allow_type_propagation = true;
    config.allow_variable_edits = false;
    config.allow_type_library_edits = false;
    config.allow_data_type_edits = false;
    config.max_turns = 12;
    config.max_tool_calls = 24;
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
    let transport = match OpenCodeTransport::new(&owned.context) {
        Ok(transport) => transport,
        Err(_) => {
            first.close().await?;
            return Err("prepare OpenCode transport");
        }
    };
    let run = run_task(&first.client, Some(transport), ModelSource::Provider, &task, &owned.path, &config).await;
    let applied = workflow_receipt(&run, &owned.path, &baseline);
    let checked_at = Instant::now();
    let mut initial_checks = Checks::default();
    let initial = verify(&first.client, owned, &baseline, applied.as_ref(), &mut initial_checks).await;
    first.close().await?;
    let reopened = Connection::open().await?;
    let mut fresh_checks = Checks::default();
    let fresh = verify(&reopened.client, owned, &baseline, applied.as_ref(), &mut fresh_checks).await;
    reopened.close().await?;
    let final_log = owned.log_bytes()?;
    let stable_log = initial["annotation_log_sha256"].is_string()
        && initial["annotation_log_sha256"] == fresh["annotation_log_sha256"]
        && fresh["annotation_log_sha256"].as_str() == Some(digest(&final_log).as_str());
    let native_state = initial["native_state_verified"] == true
        && fresh["native_state_verified"] == true
        && stable_log
        && owned.unchanged()?;
    Ok(json!({
        "schema_version": 1, "measurement": "phase1-5-type-propagation",
        "design": "seeded-owned-direct-call-fixture-not-blind-re",
        "requested_model": MODEL, "model_variant": MODEL_VARIANT, "fixture_sha256": FIXTURE_SHA256,
        "caller": CALLER, "callee": CALLEE, "agent_summary": summary(&run), "seed_metrics": seed.summary(),
        "preparation_wall_time_ms": preparation_wall_time_ms,
        "initial_verifier_metrics": initial_checks.summary(), "fresh_verifier_metrics": fresh_checks.summary(),
        "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "selected_callee_storage": baseline.callee_storage, "selected_caller_storage": baseline.caller_storage,
        "derived_hint_authorization": {"source_function": CALLEE, "source_parameter_index": 0,
            "source_type": "PropState *", "independent_native_edge_count": baseline.native_edges.len(),
            "bootstrap_inference_is_source": false},
        "seed_annotation_log_sha256": digest(&baseline.log), "stable_annotation_log": stable_log,
        "seeded_caller_already_typed_by_automatic_recovery": baseline.seeded_caller_already_typed,
        "unseeded_caller_code_sha256": baseline.unseeded_caller_code_sha256,
        "seeded_caller_code_sha256": baseline.seeded_caller_code_sha256,
        "model_tool_workflow_verified": applied.is_some(), "native_state_verified": native_state,
        "applied_receipt_sha256": applied.as_ref().map(|receipt| digest(receipt.to_string().as_bytes())),
        "task_verified": task_verified(&run, native_state, applied.is_some()),
        "initial_verification": initial, "fresh_server_verification": fresh,
        "limitations": [
            "Only bounded native direct-call scalar/pointer recovery is evaluated; not blind RE or ABI proof.",
            "Multi-hop, indirect, aggregate, return-value and whole-program recovery are not graded.",
            "Native decompile already derives ephemeral types; durable apply need not change C.",
            "Undoing durable hints does not disable automatic ephemeral derivation."
        ],
        "limits": {"max_turns": config.max_turns, "max_tool_calls": config.max_tool_calls,
            "max_record_bytes": config.max_record_bytes, "max_retained_bytes": config.max_retained_bytes,
            "max_conversation_bytes": config.max_conversation_bytes,
            "max_functions": MAX_FUNCTIONS, "max_candidates": MAX_CANDIDATES},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/type-propagation-x64.snapshot.json")
    });
    if args.next().is_some() {
        return Err("usage: type_propagation [owned-fixture.snapshot.json]; model is fixed");
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
        json!({"measurement": "phase1-5-type-propagation", "status": "failed", "stage": stage,
            "native_state_verified": false, "task_verified": false})
    });
    measurement["owned_output_wall_time_ms"] = json!(started.elapsed().as_millis());
    measurement["owned_output_timing_boundary"] =
        json!("fixture preparation through verification, shutdown and cleanup");
    measurement["provenance"] = json!({
        "evaluator_binary_sha256": evaluator_binary_sha256,
        "collector_source_sha256": digest(include_bytes!("type_propagation.rs")),
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

    #[tokio::test]
    async fn real_mcp_preparation_uses_full_signature_responses_without_model_calls() {
        let original =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/type-propagation-x64.snapshot.json");
        let owned = OwnedFixture::new(&original).unwrap();
        let connection = Connection::open().await.unwrap();
        let baseline = prepare(&connection.client, &owned, &mut Checks::default()).await.unwrap();
        assert_eq!(baseline.callee_storage["address"], "0x38");
        assert_eq!(baseline.caller_storage["address"], "0x38");
        assert!(baseline.seeded_caller_already_typed);
        assert!(explicit_seed_exact(&baseline.annotations, &baseline.callee_storage));
        assert!(owned.unchanged().unwrap());
        connection.close().await.unwrap();
    }
    use rampage_api::annotations::{
        LibraryDeclaration, LocalNameAnnotation, LocalTypeAnnotation, encode_local_names, encode_local_types,
        encode_type_library,
    };
    use rampage_eval::parity_agent::RetainedText;

    fn storage() -> VariableStorage {
        serde_json::from_value(json!({"kind": "processor", "space": "register", "address": "0x38",
            "size": 8, "use_ranges": []}))
        .unwrap()
    }

    fn decompilation(callee: bool) -> Value {
        let storage = storage();
        let name = if callee { "state" } else { "param_1" };
        let data_type = json!({"name": "PropState *", "size": 8});
        let mapping = json!({"kind": storage.kind, "space": storage.space, "address": "0x38", "size": 8,
            "use_ranges": [], "symbol_offset": 0, "is_piece": false, "pieces": []});
        let calls = if callee {
            json!([])
        } else {
            json!([{"source": "0x201171", "target": CALLEE, "indirect": false, "arguments": [
                {"input_index": 1, "parameter_index": 0, "value": {"status": "variable", "storage": storage}}
            ]}])
        };
        json!({"address": if callee { CALLEE } else { CALLER }, "code": "int f(PropState *state) { return 0; }",
            "variables": [{"kind": "parameter", "name": name,
                "editable": true, "storage": storage, "key": serde_json::to_string(&storage).unwrap(),
                "data_type": data_type}], "structure": {"signature": {"parameters": [
                    {"name": name, "data_type": data_type, "storage": mapping}
                ]}, "calls": calls}})
    }

    fn baseline() -> Baseline {
        let storage = storage();
        let names =
            encode_local_names(&[LocalNameAnnotation { storage: storage.clone(), name: "state".into() }]).unwrap();
        let types =
            encode_local_types(&[LocalTypeAnnotation { storage: storage.clone(), data_type: "PropState *".into() }])
                .unwrap();
        let mut annotations = json!({"type_hints": []});
        for field in USER_FIELDS {
            annotations[field] = json!([]);
        }
        let library = encode_type_library(&[LibraryDeclaration {
            names: vec!["PropState".into()],
            declarations: DECLARATIONS.into(),
            packing: None,
            source: None,
        }])
        .unwrap();
        annotations["type_library"] = json!([{"address": "0x0", "text": library}]);
        annotations["local_names"] = json!([{"address": CALLEE, "text": names}]);
        annotations["local_types"] = json!([{"address": CALLEE, "text": types}]);
        Baseline {
            callee_storage: json!(storage),
            caller_storage: json!(storage),
            annotations,
            library: json!({"name": "PropState", "size": 8}),
            log: vec![],
            unseeded_caller_code_sha256: digest(b"unseeded"),
            seeded_caller_code_sha256: digest(b"already typed"),
            seeded_caller_already_typed: true,
            native_edges: native_edges(&[decompilation(true), decompilation(false)]).unwrap(),
        }
    }

    fn report(apply: bool) -> Value {
        let storage = storage();
        let candidates = json!([{"function": CALLER, "target": {"kind": "parameter", "index": 0,
        "storage": storage}, "data_type": "PropState *", "evidence": [
            {"function": CALLEE, "at": CALLEE,
                "reason": format!("explicit analyst local type for {}", serde_json::to_string(&storage).unwrap())},
            {"function": CALLER, "at": "0x201171", "reason": "callee parameter to caller argument"}
        ]}]);
        json!({"address": CALLER, "source_fingerprint": "a".repeat(64), "candidates": candidates,
            "applied": if apply { candidates.clone() } else { json!([]) }, "skipped": [], "conflicts": [],
            "limitations": [], "counts": {"functions": 4, "candidates": 1, "applied": usize::from(apply)}})
    }

    fn retained(text: String) -> RetainedText {
        RetainedText { original_bytes: text.len(), text, truncated: false }
    }

    fn receipt(name: &str, input: Value, output: Value) -> ToolCall {
        ToolCall {
            name: name.into(),
            tool_use_id: "synthetic-propagation".into(),
            input: retained(input.to_string()),
            output: retained(
                json!({"content": [{"type": "text", "text": output.to_string()}],
                "isError": false})
                .to_string(),
            ),
            invoked: true,
            is_error: false,
        }
    }

    fn completed_run() -> AgentRun {
        let baseline = baseline();
        let path = Path::new("owned.snapshot.json");
        let mut run = AgentRun::without_provider(&AgentConfig::new(MODEL));
        run.model_source = Some(ModelSource::Provider);
        let AnswerContract::Exact { fields } = task().answer else { panic!("exact contract") };
        run.disposition = AgentDisposition::Answer { answer: json!(fields) };
        run.calls = vec![
            receipt("propagate_types", propagation_input(path, false), report(false)),
            receipt("propagate_types", propagation_input(path, true), report(true)),
            receipt("get_type", json!({"path": path, "name": "PropState"}), baseline.library),
            receipt("decompile", json!({"path": path, "at": CALLER}), decompilation(false)),
        ];
        run
    }

    fn workflow(run: &AgentRun) -> bool {
        workflow_receipt(run, Path::new("owned.snapshot.json"), &baseline()).is_some()
    }

    fn rewrite_output(call: &mut ToolCall, change: impl FnOnce(&mut Value)) {
        let mut envelope: Value = serde_json::from_str(&call.output.text).unwrap();
        let mut output: Value = serde_json::from_str(envelope["content"][0]["text"].as_str().unwrap()).unwrap();
        change(&mut output);
        envelope["content"][0]["text"] = json!(output.to_string());
        call.output = retained(envelope.to_string());
    }

    fn stored() -> Value {
        let mut annotations = baseline().annotations;
        annotations["type_hints"] = expected_hints(&report(true), &baseline()).unwrap();
        annotations
    }

    #[test]
    fn failed_after_correct_state_wrong_answer_and_non_provider_never_pass() {
        let mut run = completed_run();
        assert!(workflow(&run));
        assert!(task_verified(&run, true, true));
        assert!(!task_verified(&run, false, true));
        assert!(!task_verified(&run, true, false));
        for disposition in [
            AgentDisposition::Failed { reason: "rejected mutation after apply".into() },
            AgentDisposition::Unrun { reason: "unrun".into() },
            AgentDisposition::Unknown { reason: "unknown".into() },
            AgentDisposition::Unsupported { reason: "unsupported".into() },
            AgentDisposition::Answer { answer: json!({"caller_parameter_type": "int4 *"}) },
        ] {
            run.disposition = disposition;
            assert!(!task_verified(&run, true, true));
        }
        for source in [None, Some(ModelSource::Scripted)] {
            let mut run = completed_run();
            run.model_source = source;
            assert!(!task_verified(&run, true, true));
        }
        let mut run = completed_run();
        run.requested_model = "different/model".into();
        assert!(!task_verified(&run, true, true));
    }

    #[test]
    fn automatic_typed_c_does_not_replace_durable_hints_and_matching_current_source() {
        let baseline = baseline();
        assert!(native_parameter(&decompilation(false), CALLER, &baseline.caller_storage, false));
        assert!(persisted_exact(&stored(), &baseline, &report(true), &report(false)));
        let mut no_hints = stored();
        no_hints["type_hints"] = json!([]);
        assert!(!persisted_exact(&no_hints, &baseline, &report(true), &report(false)));
        let mut stale = report(false);
        stale["source_fingerprint"] = json!("b".repeat(64));
        assert!(!persisted_exact(&stored(), &baseline, &report(true), &stale));
        let mut stale_log = stored();
        let payload = TypeHintAnnotation {
            source_fingerprint: "b".repeat(64),
            hints: parse_type_hints(stale_log["type_hints"][0]["text"].as_str().unwrap()).unwrap().hints,
        };
        stale_log["type_hints"][0]["text"] = json!(encode_type_hints(&payload).unwrap());
        assert!(!persisted_exact(&stale_log, &baseline, &report(true), &report(false)));
    }

    #[test]
    fn hard_caller_types_or_any_extra_user_map_change_fail_even_with_correct_hints() {
        let baseline = baseline();
        for field in USER_FIELDS {
            let mut changed = stored();
            changed[field] = json!([{"address": CALLER, "text": "hard user clobber"}]);
            assert!(!persisted_exact(&changed, &baseline, &report(true), &report(false)), "{field}");
        }
        let mut extra = stored();
        let duplicate = extra["type_hints"][0].clone();
        extra["type_hints"].as_array_mut().unwrap().push(duplicate);
        assert!(!persisted_exact(&extra, &baseline, &report(true), &report(false)));
    }

    #[test]
    fn preview_apply_and_post_apply_inspections_are_all_required_and_ordered() {
        for index in 0..4 {
            let mut run = completed_run();
            run.calls.remove(index);
            assert!(!workflow(&run), "missing {index}");
            for mode in 0..4 {
                let mut run = completed_run();
                match mode {
                    0 => run.calls[index].input.truncated = true,
                    1 => run.calls[index].output.truncated = true,
                    2 => run.calls[index].is_error = true,
                    _ => run.calls[index].invoked = false,
                }
                assert!(!workflow(&run), "call {index} mode {mode}");
            }
        }
        for (first, second) in [(0, 1), (1, 2), (1, 3)] {
            let mut run = completed_run();
            run.calls.swap(first, second);
            assert!(!workflow(&run));
        }
        let mut run = completed_run();
        run.calls.push(run.calls[1].clone());
        assert!(!workflow(&run));
    }

    #[test]
    fn preview_and_apply_must_have_matching_provenance_and_exact_candidates() {
        for (pointer, replacement) in [
            ("/source_fingerprint", json!("b".repeat(64))),
            ("/candidates/0/target/index", json!(1)),
            ("/candidates/0/target/storage/address", json!("0x30")),
            ("/candidates/0/data_type", json!("int4")),
            ("/candidates/0/evidence/0/function", json!(CALLER)),
            ("/candidates/0/evidence/1/at", json!("0x201172")),
            ("/applied", json!([])),
            ("/counts/candidates", json!(2)),
        ] {
            let mut run = completed_run();
            rewrite_output(&mut run.calls[1], |output| *output.pointer_mut(pointer).unwrap() = replacement);
            assert!(!workflow(&run), "{pointer}");
        }
    }

    #[test]
    fn wrong_caller_or_callee_native_storage_fails_despite_matching_pointer_text() {
        let baseline = baseline();
        for callee in [false, true] {
            let expected = if callee { &baseline.callee_storage } else { &baseline.caller_storage };
            let at = if callee { CALLEE } else { CALLER };
            assert!(native_parameter(&decompilation(callee), at, expected, callee));
            let mut wrong = decompilation(callee);
            wrong["variables"][0]["storage"]["address"] = json!("0x30");
            let storage: VariableStorage = serde_json::from_value(wrong["variables"][0]["storage"].clone()).unwrap();
            wrong["variables"][0]["key"] = json!(serde_json::to_string(&storage).unwrap());
            assert!(!native_parameter(&wrong, at, expected, callee));
        }
        let mut run = completed_run();
        rewrite_output(&mut run.calls[3], |output| output["variables"][0]["data_type"]["name"] = json!("int8 *"));
        assert!(!workflow(&run));
    }

    #[test]
    fn out_of_scope_mutations_are_permanent_failures_even_if_repaired_or_erroring() {
        let path = Path::new("owned.snapshot.json");
        for (name, input) in [
            ("edit_variable", json!({"path": path, "at": CALLER, "name": "clobber"})),
            ("set_signature", json!({"path": path, "at": CALLER})),
            ("undo", json!({"path": path})),
            (
                "propagate_types",
                json!({"path": "other", "at": CALLER, "apply": true,
                "max_functions": 4, "max_candidates": 32}),
            ),
            (
                "propagate_types",
                json!({"path": path, "at": CALLEE, "apply": true,
                "max_functions": 4, "max_candidates": 32}),
            ),
            (
                "propagate_types",
                json!({"path": path, "at": CALLER, "apply": true,
                "max_functions": 5, "max_candidates": 32}),
            ),
        ] {
            for error in [false, true] {
                let mut run = completed_run();
                let mut outside = receipt(name, input.clone(), json!({}));
                outside.is_error = error;
                run.calls.insert(0, outside);
                assert!(!workflow(&run), "{name} {input} error {error}");
            }
        }
    }

    #[test]
    fn inferred_scalar_shape_is_not_an_authorized_explicit_source_even_in_an_apply_receipt() {
        let baseline = baseline();
        let mut applied = report(true);
        let extra = json!({"function": CALLEE, "target": {"kind": "parameter", "index": 1,
            "storage": {"kind": "processor", "space": "register", "address": "0x20",
                "size": 4, "use_ranges": []}}, "data_type": "int4", "evidence": [
                {"function": CALLEE, "at": CALLEE, "reason": "native prototype-shape inference"}]});
        applied["candidates"].as_array_mut().unwrap().push(extra.clone());
        applied["applied"].as_array_mut().unwrap().push(extra);
        applied["counts"]["candidates"] = json!(2);
        applied["counts"]["applied"] = json!(2);
        assert!(!propagation_report(&applied, &baseline, true));
        let mut current = applied.clone();
        current["applied"] = json!([]);
        current["counts"]["applied"] = json!(0);
        assert!(expected_hints(&applied, &baseline).is_none());
        assert!(!persisted_exact(&stored(), &baseline, &applied, &current));
        let mut run = completed_run();
        let mut bad_preview = current.clone();
        bad_preview["counts"]["applied"] = json!(0);
        rewrite_output(&mut run.calls[0], |output| *output = bad_preview);
        rewrite_output(&mut run.calls[1], |output| *output = applied);
        run.calls.extend(completed_run().calls);
        assert!(!workflow(&run));
    }

    #[test]
    fn signature_index_zero_selects_complete_storage_not_variable_order_or_parameter_name() {
        for callee in [false, true] {
            let mut report = decompilation(callee);
            let mut second = report["variables"][0].clone();
            let mut second_signature = report["structure"]["signature"]["parameters"][0].clone();
            second["name"] = json!("param_1");
            second["storage"]["address"] = json!("0x30");
            second["storage"]["size"] = json!(4);
            second["key"] = json!(serde_json::to_string(&second["storage"]).unwrap());
            second["data_type"] = json!({"name": "int4", "size": 4});
            second_signature["storage"]["address"] = json!("0x30");
            second_signature["storage"]["size"] = json!(4);
            second_signature["data_type"] = second["data_type"].clone();
            report["structure"]["signature"]["parameters"].as_array_mut().unwrap().push(second_signature);
            report["variables"].as_array_mut().unwrap().insert(0, second);
            report["variables"][1]["name"] = json!("native_argument_name");
            let selected = first_parameter(&report).unwrap();
            assert_eq!(selected["storage"], json!(storage()));
            assert_eq!(selected["name"], "native_argument_name");
            assert_eq!(canonical(selected).unwrap().size, 8);
            report["variables"][1]["storage"]["use_ranges"] = json!([
                {"space": "ram", "start": "0x20116f", "end": "0x20116f"}
            ]);
            report["variables"][1]["key"] = json!(serde_json::to_string(&report["variables"][1]["storage"]).unwrap());
            assert!(first_parameter(&report).is_err());
        }
    }

    #[test]
    fn every_candidate_needs_the_seeded_pointer_origin_and_a_reachable_native_edge() {
        let baseline = baseline();
        let valid = report(false)["candidates"][0].clone();
        assert!(candidate_hint(&valid, &baseline).is_some());
        for (pointer, replacement) in [
            ("/data_type", json!("int4")),
            ("/target/index", json!(1)),
            ("/function", json!("0x201180")),
            ("/target/storage/address", json!("0x30")),
            ("/evidence/0/reason", json!("native prototype-shape inference")),
            ("/evidence/0/reason", json!("explicit analyst local type for {}")),
            ("/evidence/1/reason", json!("caller argument to callee parameter")),
            ("/evidence/1/at", json!("0x201172")),
        ] {
            let mut extra = valid.clone();
            *extra.pointer_mut(pointer).unwrap() = replacement;
            assert!(candidate_hint(&extra, &baseline).is_none(), "{pointer}");
            let mut run = completed_run();
            for index in 0..2 {
                rewrite_output(&mut run.calls[index], |output| {
                    output["candidates"].as_array_mut().unwrap().push(extra.clone());
                    output["counts"]["candidates"] = json!(2);
                    if index == 1 {
                        output["applied"].as_array_mut().unwrap().push(extra.clone());
                        output["counts"]["applied"] = json!(2);
                    }
                });
            }
            run.calls.extend(completed_run().calls);
            assert!(!workflow(&run), "unproven extra candidate cannot be repaired: {pointer}");
        }
        let mut disconnected = baseline;
        disconnected.native_edges.clear();
        assert!(candidate_hint(&valid, &disconnected).is_none());
    }

    #[test]
    fn additional_pointer_target_is_accepted_only_with_independently_captured_native_path() {
        let mut baseline = baseline();
        let mut wrapper = decompilation(false);
        wrapper["address"] = json!("0x201180");
        wrapper["structure"]["calls"][0]["source"] = json!("0x201181");
        wrapper["structure"]["calls"][0]["target"] = json!(CALLER);
        baseline.native_edges = native_edges(&[decompilation(true), decompilation(false), wrapper]).unwrap();
        let mut candidate = report(false)["candidates"][0].clone();
        candidate["function"] = json!("0x201180");
        candidate["evidence"][1]["function"] = json!("0x201180");
        candidate["evidence"][1]["at"] = json!("0x201181");
        assert!(candidate_hint(&candidate, &baseline).is_some());
        baseline.native_edges.retain(|edge| edge.evidence.function != 0x201170);
        assert!(candidate_hint(&candidate, &baseline).is_none());
    }
}
