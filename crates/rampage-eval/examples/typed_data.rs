//! Opt-in typed-data measurement on an isolated owned snapshot, not a blind RE benchmark.
//! Reuses the Phase 1.2 driver over the Anthropic transport; never emits provider transcripts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_agent::Anthropic;
use rampage_api::annotations::{Annotations, parse_data_type, parse_operand_types, parse_type_library};
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ToolCall, run_task};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, Peer, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The pinned live model, requested through the in-process Anthropic transport (ANTHROPIC_API_KEY).
const MODEL: &str = "claude-sonnet-5-5";

const OWNED_FIXTURE: &[u8] = include_bytes!("../../../tests/data/typed-data-x64.snapshot.json");
const FIXTURE_SHA256: &str = "0507caa9fe630d14243cf9d2419ad15516475fd831d0a4390d9c5dcf40275f94";
const RECORD_HEX: &str = "070000002a000000616c706861000000fdfffffff9ffffff6265746100000000";
const TEXT_HEX: &str = "4772c3bcc39f65";
const MAX_OUTPUT_BYTES: usize = 65_536;
const DECLARATIONS: &str = "enum TypedMode { MODE_OFF=0, MODE_READY=7, MODE_FAULT=-3 }; \
    struct TypedRecord { enum TypedMode mode; int4 value; char label[8]; };";
const UNRELATED_FIELDS: [&str; 7] =
    ["names", "comments", "signatures", "types", "globals", "local_names", "local_types"];

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
            return Err("embedded typed-data snapshot identity mismatch");
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        std::fs::create_dir_all(&root).map_err(|_| "create temporary root")?;
        let directory =
            root.join(format!("rampage-typed-data-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
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
            return Err("fixture identity differs from the owned typed-data snapshot");
        }
        std::fs::create_dir(&owned.context).map_err(|_| "create isolated model context")?;
        Ok(owned)
    }

    fn unchanged(&self) -> Result<bool, &'static str> {
        Ok(digest(&std::fs::read(&self.path).map_err(|_| "read owned fixture")?) == FIXTURE_SHA256)
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

fn task() -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-3-typed-data".into(),
        kind: TaskKind::Analysis,
        question: "Use the existing project library definitions TypedRecord and TypedMode; do not declare or \
            change types. Apply TypedRecord with count 2 at 0x200120. Apply explicit utf8 encoding with \
            byte_length 7 at 0x200140 (seven bytes, not seven characters). Apply TypedMode using apply_enum \
            to instruction 0x201182 operand 1, and TypedRecord using apply_offset to instruction 0x201187 \
            operand 1. Use bare type names. After both data bindings, inspect read_data at 0x200120 size 32 \
            and at 0x200140 size 7. After both operand writes, inspect disassemble at 0x201180 count 5. \
            Return only a JSON summary with first_value, second_value, \
            first_mode, second_mode, text, enum_display and field_display. Read the actual typed fields and \
            displays. Do not change binary bytes, names, comments, signatures, globals, local variables, \
            library declarations, other annotations, or other paths. Independent actual MCP inspection \
            and a fresh server verify native state and persistence; the answer alone cannot establish success."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-typed-data-x64".into(),
            path: "tests/data/typed-data-x64.snapshot.json".into(),
            sha256: FIXTURE_SHA256.into(),
            source: "tests/fixtures/src/typed-data.c".into(),
            build: "crates/rampage-eval/examples/typed_data.rs".into(),
        },
        truth_reference: "Owned original snapshot bytes, seeded native types and identity-scoped log".into(),
        required_capabilities: ["apply_data_type", "apply_enum", "apply_offset", "read_data", "disassemble"]
            .into_iter()
            .map(String::from)
            .collect(),
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Actual catalogs, receipts and independently reopened native state".into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("first_value".into(), json!(42)),
                ("second_value".into(), json!(-7)),
                ("first_mode".into(), json!("MODE_READY")),
                ("second_mode".into(), json!("MODE_FAULT")),
                ("text".into(), json!("Grüße")),
                ("enum_display".into(), json!("TypedMode::MODE_READY")),
                ("field_display".into(), json!("TypedRecord.value")),
            ]),
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
    if result.content.len() != 1 {
        return Err("evaluator MCP content shape");
    }
    let text = &result.content.first().and_then(|content| content.as_text()).ok_or("evaluator MCP text")?.text;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err("evaluator MCP result exceeds bound");
    }
    let value: Value = serde_json::from_str(text).map_err(|_| "evaluator MCP JSON")?;
    if value["truncated"] == true {
        return Err("truncated evaluator MCP JSON");
    }
    Ok(value)
}

fn address(value: &Value) -> Option<u64> {
    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn record_binding(binding: &Value) -> bool {
    binding["type_name"] == "TypedRecord"
        && binding["count"] == 2
        && binding["byte_length"] == 32
        && binding.get("encoding") == Some(&Value::Null)
}

fn text_binding(binding: &Value) -> bool {
    binding.get("type_name") == Some(&Value::Null)
        && binding["count"] == 1
        && binding["byte_length"] == 7
        && binding["encoding"] == "utf8"
}

fn raw_matches(report: &Value, at: u64, hex: &str) -> bool {
    let Some(spans) = report["raw"]["spans"].as_array() else { return false };
    report["raw"]["pointer_targets_suppressed"] == true
        && spans.iter().any(|span| {
            let Some(start) = address(&span["address"]) else { return false };
            let Some(bytes) = span["hex"].as_str() else { return false };
            let Some(offset) = at
                .checked_sub(start)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| offset.checked_mul(2))
            else {
                return false;
            };
            span.get("file_offset") == Some(&Value::Null)
                && offset.checked_add(hex.len()).and_then(|end| bytes.get(offset..end)) == Some(hex)
        })
}

fn object(report: &Value, at: u64, binding: fn(&Value) -> bool) -> Option<&Value> {
    let objects = report["objects"].as_array()?;
    let mut matches = objects.iter().filter(|object| address(&object["address"]) == Some(at));
    let result = matches.next()?;
    (matches.next().is_none() && binding(&result["binding"])).then_some(result)
}

fn record_fields_verified(report: &Value) -> bool {
    let Some(object) = object(report, 0x200120, record_binding) else { return false };
    let Some(fields) = object["fields"].as_array() else { return false };
    let expected = [
        ("[0].mode", 0, "TypedMode", "07000000", "7", "MODE_READY"),
        ("[0].value", 4, "int4", "2a000000", "42", ""),
        ("[1].mode", 16, "TypedMode", "fdffffff", "-3", "MODE_FAULT"),
        ("[1].value", 20, "int4", "f9ffffff", "-7", ""),
    ];
    raw_matches(report, 0x200120, RECORD_HEX)
        && expected.iter().all(|(suffix, offset, ty, raw, dec, en)| {
            let selected: Vec<_> = fields
                .iter()
                .filter(|field| field["path"].as_str().is_some_and(|path| path.ends_with(suffix)))
                .collect();
            selected.len() == 1
                && selected.iter().all(|field| {
                    address(&field["address"]) == Some(0x200120 + offset)
                        && field["offset"] == *offset
                        && field["type_name"] == *ty
                        && field["size"] == 4
                        && field["status"] == "stored"
                        && field["raw_hex"] == *raw
                        && field["value"]["decimal"] == *dec
                        && if en.is_empty() {
                            field["value"]["kind"] == "integer"
                        } else {
                            field["value"]["kind"] == "enum" && field["value"]["enum_names"] == json!([en])
                        }
                })
        })
}

fn text_fields_verified(report: &Value) -> bool {
    let Some(object) = object(report, 0x200140, text_binding) else { return false };
    let Some(fields) = object["fields"].as_array() else { return false };
    raw_matches(report, 0x200140, TEXT_HEX) && fields.len() == 1 && {
        let field = &fields[0];
        address(&field["address"]) == Some(0x200140)
            && field["offset"] == 0
            && field["size"] == 7
            && field["status"] == "stored"
            && field["raw_hex"] == TEXT_HEX
            && field["value"]["encoding"] == "utf8"
            && field["value"]["text"] == "Grüße"
    }
}

fn operand_display(value: &Value, enumeration: bool) -> bool {
    value["operand"] == 1
        && value["matched"] == true
        && value["kind"] == if enumeration { "enum" } else { "offset" }
        && value["type_name"] == if enumeration { "TypedMode" } else { "TypedRecord" }
        && value["display"] == if enumeration { "TypedMode::MODE_READY" } else { "TypedRecord.value" }
}

fn instruction_baseline(listing: &Value) -> Option<Value> {
    let lines = listing.as_array()?;
    let expected =
        [(0x201180, "31c0"), (0x201182, "833f07"), (0x201185, "7503"), (0x201187, "8b4704"), (0x20118a, "c3")];
    if lines.len() != expected.len()
        || !lines.iter().zip(expected).all(|(line, (at, hex))| {
            address(&line["address"]) == Some(at) && line["bytes"] == hex && line["text"].is_string()
        })
    {
        return None;
    }
    Some(json!(
        lines
            .iter()
            .map(|line| json!({
                "address": line["address"], "bytes": line["bytes"], "text": line["text"],
            }))
            .collect::<Vec<_>>()
    ))
}

fn instructions_verified(listing: &Value, baseline: &Value) -> bool {
    instruction_baseline(listing).as_ref() == Some(baseline)
        && listing.as_array().is_some_and(|lines| {
            lines.iter().enumerate().all(|(index, line)| {
                let annotations = line.get("operand_annotations").and_then(Value::as_array);
                if matches!(index, 1 | 3) {
                    annotations.is_some_and(|entries| entries.len() == 1 && operand_display(&entries[0], index == 1))
                } else {
                    annotations.is_none_or(Vec::is_empty)
                }
            })
        })
}

struct Persisted {
    annotations: Value,
    library_digest: String,
    log_digest: String,
}

fn persisted(owned: &OwnedFixture) -> Result<Persisted, &'static str> {
    let path = owned.sidecar()?;
    if std::fs::metadata(&path).map_err(|_| "sidecar metadata")?.len() > 1_000_000 {
        return Err("sidecar exceeds measurement bound");
    }
    let bytes = std::fs::read(&path).map_err(|_| "read identity-scoped log")?;
    let annotations = Annotations::open_checked(path).map_err(|_| "read persisted annotations")?;
    if !annotations.warnings().is_empty() {
        return Err("persisted annotation warnings");
    }
    let library = annotations.type_library();
    let text = library.get(&0).filter(|_| library.len() == 1).ok_or("seed library identity")?;
    let declarations = parse_type_library(text).map_err(|_| "parse seed library")?;
    let mut names: Vec<_> = declarations.iter().flat_map(|unit| unit.names.iter().map(String::as_str)).collect();
    names.sort_unstable();
    if names != ["TypedMode", "TypedRecord"] {
        return Err("seed library names");
    }
    let mut result = json!({});
    for (name, map) in [
        ("names", annotations.names()),
        ("comments", annotations.comments()),
        ("signatures", annotations.signatures()),
        ("types", annotations.types()),
        ("globals", annotations.globals()),
        ("local_names", annotations.local_names()),
        ("local_types", annotations.local_types()),
        ("type_library", library),
        ("data_types", annotations.data_types()),
        ("operand_types", annotations.operand_types()),
    ] {
        result[name] = json!(
            map.iter()
                .map(|(at, text)| json!({
                    "address": format!("0x{at:x}"), "text": text,
                }))
                .collect::<Vec<_>>()
        );
    }
    Ok(Persisted { annotations: result, library_digest: digest(text.as_bytes()), log_digest: digest(&bytes) })
}

fn exact_bindings(annotations: &Value) -> bool {
    let Some(data) = annotations["data_types"].as_array() else { return false };
    let Some(operands) = annotations["operand_types"].as_array() else { return false };
    UNRELATED_FIELDS.iter().all(|name| annotations[name].as_array().is_some_and(Vec::is_empty))
        && data.len() == 2
        && [0x200120, 0x200140].into_iter().all(|at| {
            let selected: Vec<_> = data.iter().filter(|row| address(&row["address"]) == Some(at)).collect();
            selected.len() == 1
                && selected.iter().all(|row| {
                    row["text"]
                        .as_str()
                        .and_then(|text| parse_data_type(text).ok())
                        .and_then(|binding| serde_json::to_value(binding).ok())
                        .is_some_and(
                            |binding| {
                                if at == 0x200120 { record_binding(&binding) } else { text_binding(&binding) }
                            },
                        )
                })
        })
        && operands.len() == 2
        && [0x201182, 0x201187].into_iter().all(|at| {
            let selected: Vec<_> = operands.iter().filter(|row| address(&row["address"]) == Some(at)).collect();
            selected.len() == 1
                && selected.iter().all(|row| {
                    row["text"].as_str().and_then(|text| parse_operand_types(text).ok()).is_some_and(|entries| {
                        entries.len() == 1
                            && serde_json::to_value(&entries[0]).ok().is_some_and(|entry| {
                                entry["operand"] == 1
                                    && entry["kind"] == if at == 0x201182 { "enum" } else { "offset" }
                                    && entry["type_name"] == if at == 0x201182 { "TypedMode" } else { "TypedRecord" }
                                    && entry["instruction_hex"] == if at == 0x201182 { "833f07" } else { "8b4704" }
                            })
                    })
                })
        })
}

fn annotations_match(actual: &Value, stored: &Value) -> bool {
    let warnings_ok = actual.get("warnings").is_none_or(|warnings| warnings.as_array().is_some_and(Vec::is_empty));
    warnings_ok
        && stored
            .as_object()
            .is_some_and(|fields| fields.iter().all(|(name, expected)| actual.get(name) == Some(expected)))
}

struct Baseline {
    instructions: Value,
    library_digest: String,
    library_query: Value,
}

async fn prepare(
    client: &Peer<RoleClient>,
    owned: &OwnedFixture,
    checks: &mut Checks,
) -> Result<Baseline, &'static str> {
    native_json(checks.call(client, "enable_tools", json!({"groups": ["types"]})).await)?;
    let seed = native_json(
        checks
            .call(
                client,
                "declare_types",
                json!({
                    "path": owned.path, "declarations": DECLARATIONS,
                }),
            )
            .await,
    )?;
    if seed["types"].as_array().is_none_or(|types| {
        types.len() != 2 || !["TypedMode", "TypedRecord"].iter().all(|name| types.iter().any(|ty| ty["name"] == *name))
    }) {
        return Err("seed declaration receipt");
    }
    let records = native_json(
        checks
            .call(
                client,
                "read_data",
                json!({
                    "path": owned.path, "at": "0x200120", "size": 32,
                }),
            )
            .await,
    )?;
    let text = native_json(
        checks
            .call(
                client,
                "read_data",
                json!({
                    "path": owned.path, "at": "0x200140", "size": 7,
                }),
            )
            .await,
    )?;
    if !raw_matches(&records, 0x200120, RECORD_HEX)
        || !raw_matches(&text, 0x200140, TEXT_HEX)
        || ![&records, &text].iter().all(|report| report["objects"].as_array().is_some_and(Vec::is_empty))
    {
        return Err("initial raw bytes or missing-binding baseline");
    }
    let listing = native_json(
        checks
            .call(
                client,
                "disassemble",
                json!({
                    "path": owned.path, "at": "0x201180", "count": 5,
                }),
            )
            .await,
    )?;
    let instructions = instruction_baseline(&listing).ok_or("initial instruction baseline")?;
    if !listing.as_array().is_some_and(|lines| {
        lines.iter().all(|line| {
            line.get("operand_annotations").is_none_or(|entries| entries.as_array().is_some_and(Vec::is_empty))
        })
    }) {
        return Err("initial operand baseline");
    }
    let query = native_json(checks.call(client, "list_annotations", json!({"path": owned.path})).await)?;
    let stored = persisted(owned)?;
    if !annotations_match(&query, &stored.annotations)
        || !UNRELATED_FIELDS
            .iter()
            .chain(["data_types", "operand_types"].iter())
            .all(|name| query[name].as_array().is_some_and(Vec::is_empty))
    {
        return Err("initial annotation baseline");
    }
    Ok(Baseline { instructions, library_digest: stored.library_digest, library_query: query["type_library"].clone() })
}

async fn verify(client: &Peer<RoleClient>, owned: &OwnedFixture, baseline: &Baseline, checks: &mut Checks) -> Value {
    let enabled = checks.call(client, "enable_tools", json!({"groups": ["types"]})).await;
    let records = checks
        .call(
            client,
            "read_data",
            json!({
                "path": owned.path, "at": "0x200120", "size": 32,
            }),
        )
        .await;
    let text = checks
        .call(
            client,
            "read_data",
            json!({
                "path": owned.path, "at": "0x200140", "size": 7,
            }),
        )
        .await;
    let listing = checks
        .call(
            client,
            "disassemble",
            json!({
                "path": owned.path, "at": "0x201180", "count": 5,
            }),
        )
        .await;
    let query = checks.call(client, "list_annotations", json!({"path": owned.path})).await;
    let result = (|| -> Result<Value, &'static str> {
        native_json(enabled)?;
        let records = native_json(records)?;
        let text = native_json(text)?;
        let listing = native_json(listing)?;
        let query = native_json(query)?;
        let stored = persisted(owned)?;
        let records_ok = record_fields_verified(&records);
        let text_ok = text_fields_verified(&text);
        let operands_ok = instructions_verified(&listing, &baseline.instructions);
        let log_ok = exact_bindings(&stored.annotations) && annotations_match(&query, &stored.annotations);
        let library_ok =
            stored.library_digest == baseline.library_digest && query["type_library"] == baseline.library_query;
        let unchanged = owned.unchanged()?;
        Ok(json!({
            "native_state_verified": records_ok && text_ok && operands_ok && log_ok && library_ok && unchanged,
            "record_fields_verified": records_ok, "utf8_verified": text_ok,
            "operand_displays_and_original_instructions_verified": operands_ok,
            "exact_identity_scoped_annotations_verified": log_ok, "seeded_library_unchanged": library_ok,
            "fixture_sha256_unchanged": unchanged, "annotation_log_sha256": stored.log_digest,
            "annotation_library_sha256": stored.library_digest,
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
    Some((input, native_json(Ok(result)).ok()?))
}

fn permitted_mutation_selector(name: &str, input: &Value) -> bool {
    let at = address(&input["at"]);
    match name {
        "apply_data_type" => matches!(at, Some(0x200120) | Some(0x200140)),
        "apply_enum" => at == Some(0x201182) && input["operand"] == 1,
        "apply_offset" => at == Some(0x201187) && input["operand"] == 1,
        _ => false,
    }
}

fn workflow_verified(run: &AgentRun, path: &Path, baseline: &Value) -> bool {
    let mut writes = [false; 4];
    let mut records_read = false;
    let mut text_read = false;
    let mut disassembled = false;
    for call in &run.calls {
        let data_write = call.name == "apply_data_type";
        let operand_write = matches!(call.name.as_str(), "apply_enum" | "apply_offset");
        if call.invoked && (data_write || operand_write) {
            if call.input.truncated {
                return false;
            }
            let Ok(input) = serde_json::from_str::<Value>(&call.input.text) else { return false };
            if input["path"] != json!(path) || !permitted_mutation_selector(&call.name, &input) {
                return false;
            }
        }
        if call.invoked && !call.is_error && data_write {
            records_read = false;
            text_read = false;
        }
        if call.invoked && !call.is_error && operand_write {
            disassembled = false;
        }
        let Some((input, receipt)) = call_evidence(call) else {
            if call.invoked && !call.is_error {
                if data_write {
                    writes[0..2].fill(false);
                }
                if operand_write {
                    writes[2..4].fill(false);
                }
            }
            continue;
        };
        if !matches!(
            call.name.as_str(),
            "apply_data_type" | "apply_enum" | "apply_offset" | "read_data" | "disassemble"
        ) {
            continue;
        }
        if input["path"] != json!(path) {
            return false;
        }
        if data_write {
            let at = address(&input["at"]);
            let valid_address = at.is_some() && at == address(&receipt["address"]);
            let not_clear = input["clear"] != true;
            match at {
                Some(0x200120) => {
                    writes[0] = valid_address
                        && not_clear
                        && input["type_name"] == "TypedRecord"
                        && input["count"] == 2
                        && record_binding(&receipt["binding"])
                }
                Some(0x200140) => {
                    writes[1] = valid_address
                        && not_clear
                        && input["encoding"] == "utf8"
                        && input["byte_length"] == 7
                        && text_binding(&receipt["binding"])
                }
                _ => return false,
            }
        } else if operand_write {
            let enumeration = call.name == "apply_enum";
            let index = if enumeration { 2 } else { 3 };
            let at = if enumeration { 0x201182 } else { 0x201187 };
            let ty = if enumeration { "TypedMode" } else { "TypedRecord" };
            let kind = if enumeration { "enum" } else { "offset" };
            let hex = if enumeration { "833f07" } else { "8b4704" };
            writes[index] = address(&input["at"]) == Some(at)
                && input["operand"] == 1
                && input["type_name"] == ty
                && input["clear"] != true
                && address(&receipt["address"]) == Some(at)
                && receipt["operand"] == 1
                && receipt["kind"] == kind
                && receipt["annotation"]["operand"] == 1
                && receipt["annotation"]["type_name"] == ty
                && receipt["annotation"]["kind"] == kind
                && receipt["annotation"]["instruction_hex"] == hex
                && operand_display(&receipt["display"], enumeration);
        } else if call.name == "read_data" && writes[0] && writes[1] {
            records_read |=
                address(&input["at"]) == Some(0x200120) && input["size"] == 32 && record_fields_verified(&receipt);
            text_read |=
                address(&input["at"]) == Some(0x200140) && input["size"] == 7 && text_fields_verified(&receipt);
        } else if call.name == "disassemble"
            && writes[2]
            && writes[3]
            && address(&input["at"]) == Some(0x201180)
            && input["count"] == 5
        {
            disassembled |= instructions_verified(&receipt, baseline);
        }
    }
    writes.into_iter().all(|written| written) && records_read && text_read && disassembled
}

fn task_verified(run: &AgentRun, task: &ParityTask, native_state: bool, workflow: bool) -> bool {
    run.model_source == Some(ModelSource::Provider)
        && native_state
        && workflow
        && matches!(&run.disposition, AgentDisposition::Answer { answer } if task.answer.matches(answer))
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

async fn measure(owned: &OwnedFixture) -> Result<Value, &'static str> {
    let task = task();
    task.validate().map_err(|_| "validate measurement task")?;
    let transport = Anthropic::from_environment().ok_or("set ANTHROPIC_API_KEY for the Anthropic transport")?;
    let mut config = AgentConfig::new(MODEL);
    config.allow_data_type_edits = true;
    config.allow_variable_edits = false;
    config.allow_type_library_edits = false;
    config.max_turns = 16;
    config.max_tool_calls = 32;
    let first = Connection::open().await?;
    let mut seed_checks = Checks::default();
    let prepared_at = Instant::now();
    let prepared = prepare(&first.client, owned, &mut seed_checks).await;
    let preparation_wall_time_ms = prepared_at.elapsed().as_millis();
    let baseline = match prepared {
        Ok(baseline) => baseline,
        Err(stage) => {
            first.close().await?;
            return Err(stage);
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
    let final_log_digest = persisted(owned).ok().map(|stored| stored.log_digest);
    let stable_log = initial["annotation_log_sha256"].is_string()
        && initial["annotation_log_sha256"] == fresh["annotation_log_sha256"]
        && final_log_digest.as_deref() == fresh["annotation_log_sha256"].as_str();
    let workflow = workflow_verified(&run, &owned.path, &baseline.instructions);
    let native_state = initial["native_state_verified"] == true
        && fresh["native_state_verified"] == true
        && stable_log
        && owned.unchanged()?;
    Ok(json!({
        "measurement": "phase1-3-typed-data", "design": "paired-owned-fixture-not-blind-whole-program-re",
        "requested_model": MODEL, "transport": "anthropic", "fixture_sha256": FIXTURE_SHA256,
        "agent_summary": summary(&run, &task), "seed_tool_calls": seed_checks.calls,
        "seed_tool_errors": seed_checks.errors, "seed_transport_errors": seed_checks.transport_errors,
        "preparation_wall_time_ms": preparation_wall_time_ms,
        "evaluator_tool_calls": checks.calls, "evaluator_tool_errors": checks.errors,
        "evaluator_transport_errors": checks.transport_errors, "expected_missing_binding_errors": 0,
        "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "native_state_verified": native_state, "task_verified": task_verified(&run, &task, native_state, workflow),
        "model_tool_workflow_verified": workflow, "initial_verification": initial,
        "fresh_server_verification": fresh, "stable_annotation_log": stable_log,
        "limits": {"max_turns": config.max_turns, "max_tool_calls": config.max_tool_calls},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture = args.next().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/typed-data-x64.snapshot.json")
    });
    if args.next().is_some() {
        return Err("usage: typed_data [owned-fixture.snapshot.json]; model is fixed");
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
    let collector_source_sha256 = digest(include_bytes!("typed_data.rs"));
    let mut measurement = run().unwrap_or_else(|stage| {
        json!({
            "measurement": "phase1-3-typed-data", "status": "failed", "stage": stage,
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

    fn receipt(name: &str, mut input: Value, result: Value) -> ToolCall {
        input["path"] = json!("owned.snapshot.json");
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

    fn record_binding_value() -> Value {
        json!({"type_name": "TypedRecord", "count": 2, "byte_length": 32, "encoding": null})
    }

    fn text_binding_value() -> Value {
        json!({"type_name": null, "count": 1, "byte_length": 7, "encoding": "utf8"})
    }

    fn raw(at: &str, hex: &str) -> Value {
        json!({"pointer_targets_suppressed": true, "spans": [{"address": at, "hex": hex, "file_offset": null}]})
    }

    fn records() -> Value {
        let fields = [
            ("[0].mode", 0, "TypedMode", "07000000", "7", "MODE_READY"),
            ("[0].value", 4, "int4", "2a000000", "42", ""),
            ("[1].mode", 16, "TypedMode", "fdffffff", "-3", "MODE_FAULT"),
            ("[1].value", 20, "int4", "f9ffffff", "-7", ""),
        ]
        .into_iter()
        .map(|(suffix, offset, ty, hex, decimal, en)| {
            json!({
                "path": format!("data_200120{suffix}"), "address": format!("0x{:x}", 0x200120 + offset),
                "offset": offset, "type_name": ty, "size": 4, "status": "stored", "raw_hex": hex,
                "value": {"kind": if en.is_empty() { "integer" } else { "enum" }, "decimal": decimal,
                    "enum_names": if en.is_empty() { vec![] } else { vec![en] }},
            })
        })
        .collect::<Vec<_>>();
        json!({"raw": raw("0x200120", RECORD_HEX), "objects": [{"address": "0x200120",
            "name": "data_200120", "binding": record_binding_value(), "fields": fields}]})
    }

    fn text() -> Value {
        json!({"raw": raw("0x200140", TEXT_HEX), "objects": [{"address": "0x200140",
        "name": "data_200140", "binding": text_binding_value(), "fields": [{
            "path": "data_200140", "address": "0x200140", "offset": 0, "size": 7,
            "status": "stored", "raw_hex": TEXT_HEX, "value": {"encoding": "utf8", "text": "Grüße"},
        }]}]})
    }

    fn display(enumeration: bool) -> Value {
        json!({"operand": 1, "kind": if enumeration { "enum" } else { "offset" },
            "type_name": if enumeration { "TypedMode" } else { "TypedRecord" }, "matched": true,
            "display": if enumeration { "TypedMode::MODE_READY" } else { "TypedRecord.value" }})
    }

    fn listing(annotated: bool) -> Value {
        let mut result = json!([
            {"address": "0x201180", "bytes": "31c0", "text": "xor eax, eax"},
            {"address": "0x201182", "bytes": "833f07", "text": "cmp dword ptr [rdi], 7"},
            {"address": "0x201185", "bytes": "7503", "text": "jne 0x20118a"},
            {"address": "0x201187", "bytes": "8b4704", "text": "mov eax, dword ptr [rdi+4]"},
            {"address": "0x20118a", "bytes": "c3", "text": "ret"},
        ]);
        if annotated {
            result[1]["operand_annotations"] = json!([display(true)]);
            result[3]["operand_annotations"] = json!([display(false)]);
        }
        result
    }

    fn workflow() -> Vec<ToolCall> {
        let mut calls = vec![
            receipt(
                "apply_data_type",
                json!({"at": "0x200120", "type_name": "TypedRecord", "count": 2}),
                json!({"address": "0x200120", "binding": record_binding_value()}),
            ),
            receipt(
                "apply_data_type",
                json!({"at": "0x200140", "encoding": "utf8", "byte_length": 7}),
                json!({"address": "0x200140", "binding": text_binding_value()}),
            ),
        ];
        for (name, at, ty, kind, hex, enumeration) in [
            ("apply_enum", "0x201182", "TypedMode", "enum", "833f07", true),
            ("apply_offset", "0x201187", "TypedRecord", "offset", "8b4704", false),
        ] {
            calls.push(receipt(
                name,
                json!({"at": at, "operand": 1, "type_name": ty}),
                json!({
                    "address": at, "operand": 1, "kind": kind, "annotation": {
                        "operand": 1, "type_name": ty, "kind": kind, "instruction_hex": hex,
                    }, "display": display(enumeration),
                }),
            ));
        }
        calls.extend([
            receipt("read_data", json!({"at": "0x200120", "size": 32}), records()),
            receipt("read_data", json!({"at": "0x200140", "size": 7}), text()),
            receipt("disassemble", json!({"at": "0x201180", "count": 5}), listing(true)),
        ]);
        calls
    }

    fn completed_run() -> AgentRun {
        let mut run = AgentRun::without_provider(&AgentConfig::new(MODEL));
        run.model_source = Some(ModelSource::Provider);
        run.disposition = AgentDisposition::Answer {
            answer: json!({
                "first_value": 42, "second_value": -7, "first_mode": "MODE_READY", "second_mode": "MODE_FAULT",
                "text": "Grüße", "enum_display": "TypedMode::MODE_READY", "field_display": "TypedRecord.value",
            }),
        };
        run.calls = workflow();
        run
    }

    fn check(run: &AgentRun) -> bool {
        workflow_verified(run, Path::new("owned.snapshot.json"), &instruction_baseline(&listing(false)).unwrap())
    }

    fn rewrite_output(call: &mut ToolCall, change: impl FnOnce(&mut Value)) {
        let mut envelope: Value = serde_json::from_str(&call.output.text).unwrap();
        let mut result: Value = serde_json::from_str(envelope["content"][0]["text"].as_str().unwrap()).unwrap();
        change(&mut result);
        envelope["content"][0]["text"] = json!(result.to_string());
        call.output = retained(envelope.to_string());
    }

    #[test]
    fn prepared_state_cannot_rescue_failed_policy_or_non_provider_outcomes() {
        let mut run = completed_run();
        assert!(check(&run));
        assert!(task_verified(&run, &task(), true, check(&run)));
        assert!(!task_verified(&run, &task(), false, true));
        assert!(!task_verified(&run, &task(), true, false));
        for disposition in [
            AgentDisposition::Failed { reason: "policy rejected after state preparation".into() },
            AgentDisposition::Unrun { reason: "no provider".into() },
            AgentDisposition::Unknown { reason: "incomplete".into() },
            AgentDisposition::Unsupported { reason: "unsupported".into() },
            AgentDisposition::Answer { answer: json!({"first_value": 42}) },
        ] {
            run.disposition = disposition;
            assert!(!task_verified(&run, &task(), true, true));
        }
        let mut run = completed_run();
        for source in [None, Some(ModelSource::Scripted)] {
            run.model_source = source;
            assert!(!task_verified(&run, &task(), true, true));
        }
    }

    #[test]
    fn typed_field_paths_require_the_correct_root_binding_addresses_and_actual_values() {
        assert!(record_fields_verified(&records()));
        for (pointer, replacement) in [
            ("/objects/0/address", json!("0x200130")),
            ("/objects/0/binding/type_name", json!("SomeOtherType")),
            ("/objects/0/binding/count", json!(1)),
            ("/objects/0/fields/0/value/enum_names", json!(["MODE_OFF"])),
            ("/objects/0/fields/1/address", json!("0x200120")),
            ("/objects/0/fields/1/value/decimal", json!(42)),
            ("/objects/0/fields/2/value/decimal", json!("4294967293")),
            ("/objects/0/fields/3/value/decimal", json!("7")),
            ("/objects/0/fields/3/raw_hex", json!("07000000")),
            ("/raw/pointer_targets_suppressed", json!(false)),
        ] {
            let mut report = records();
            *report.pointer_mut(pointer).unwrap() = replacement;
            assert!(!record_fields_verified(&report), "{pointer}");
        }
    }

    #[test]
    fn utf8_is_seven_original_bytes_not_character_count_or_a_decoded_claim() {
        assert!(text_fields_verified(&text()));
        for (pointer, replacement) in [
            ("/objects/0/binding/byte_length", json!(5)),
            ("/objects/0/fields/0/size", json!(5)),
            ("/objects/0/fields/0/value/text", json!("Grusse")),
            ("/objects/0/fields/0/value/encoding", json!("ascii")),
            ("/objects/0/fields/0/raw_hex", json!("4772c3bcc39f6500")),
            ("/raw/spans/0/hex", json!("00000000000000")),
            ("/raw/spans/0/file_offset", json!(64)),
        ] {
            let mut report = text();
            *report.pointer_mut(pointer).unwrap() = replacement;
            assert!(!text_fields_verified(&report), "{pointer}");
        }
    }

    #[test]
    fn display_selectors_and_original_instruction_text_and_bytes_are_independent_requirements() {
        let baseline = instruction_baseline(&listing(false)).unwrap();
        assert!(instructions_verified(&listing(true), &baseline));
        for (pointer, replacement) in [
            ("/1/operand_annotations/0/operand", json!(0)),
            ("/3/operand_annotations/0/type_name", json!("TypedMode")),
            ("/1/operand_annotations/0/display", json!("TypedMode::MODE_OFF")),
            ("/3/operand_annotations/0/matched", json!(false)),
            ("/1/bytes", json!("833f00")),
            ("/3/text", json!("mov eax, TypedRecord.value")),
            ("/3/address", json!("0x201188")),
        ] {
            let mut value = listing(true);
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(!instructions_verified(&value, &baseline), "{pointer}");
        }
    }

    #[test]
    fn missing_truncated_error_or_uninvoked_receipts_do_not_prove_workflow() {
        for index in 0..workflow().len() {
            let mut run = completed_run();
            run.calls.remove(index);
            assert!(!check(&run), "missing {index}");
            for mode in 0..4 {
                let mut run = completed_run();
                match mode {
                    0 => run.calls[index].input.truncated = true,
                    1 => run.calls[index].output.truncated = true,
                    2 => run.calls[index].is_error = true,
                    _ => run.calls[index].invoked = false,
                }
                assert!(!check(&run), "call {index} mode {mode}");
            }
        }
    }

    #[test]
    fn inspections_before_writes_and_later_rewrites_require_fresh_proof() {
        let mut run = completed_run();
        let read = run.calls.remove(4);
        run.calls.insert(0, read);
        assert!(!check(&run));
        for index in 0..4 {
            let mut run = completed_run();
            run.calls.push(workflow()[index].clone());
            assert!(!check(&run), "rewrite {index}");
            if index < 2 {
                run.calls.extend(workflow()[4..6].iter().cloned());
            } else {
                run.calls.push(workflow()[6].clone());
            }
            assert!(check(&run), "new proof after rewrite {index}");
        }
    }

    #[test]
    fn out_of_scope_cmp_offset_then_clear_cannot_be_repaired_by_the_requested_workflow() {
        let mut run = completed_run();
        let applied = receipt(
            "apply_offset",
            json!({"at": "0x201182", "operand": 0, "type_name": "TypedRecord"}),
            json!({"address": "0x201182", "operand": 0, "kind": "offset", "changed": true,
                "annotation": {"operand": 0, "kind": "offset", "type_name": "TypedRecord",
                    "instruction_hex": "833f07"},
                "display": {"operand": 0, "kind": "offset", "type_name": "TypedRecord",
                    "display": "TypedRecord.mode", "matched": true}}),
        );
        let cleared = receipt(
            "apply_offset",
            json!({"at": "0x201182", "operand": 0, "clear": true}),
            json!({"address": "0x201182", "operand": 0, "kind": "offset", "changed": true,
                "annotation": null, "display": null}),
        );
        run.calls.splice(0..0, [applied, cleared]);
        assert!(!check(&run));
        assert!(!task_verified(&run, &task(), true, check(&run)));
        assert!(check(&completed_run()));
    }

    #[test]
    fn every_invoked_mutation_is_scope_checked_even_without_a_successful_receipt() {
        for (name, input) in [
            ("apply_data_type", json!({"at": "0x200148", "encoding": "utf8", "byte_length": 1})),
            ("apply_enum", json!({"at": "0x201182", "operand": 0, "type_name": "TypedMode"})),
            ("apply_enum", json!({"at": "0x201187", "operand": 1, "clear": true})),
            ("apply_offset", json!({"at": "0x201182", "operand": 0, "clear": true})),
            ("apply_offset", json!({"at": "0x201187", "operand": 0, "type_name": "TypedRecord"})),
            ("apply_offset", json!({"at": "sub_201182", "operand": 1, "clear": true})),
        ] {
            for error in [false, true] {
                let mut run = completed_run();
                let mut outside = receipt(name, input.clone(), json!({}));
                outside.is_error = error;
                outside.output.truncated = !error;
                run.calls.insert(0, outside);
                assert!(!check(&run), "{name} {input} error {error}");
            }
        }
    }

    #[test]
    fn permitted_clears_can_be_repaired_and_numeric_address_spellings_share_the_same_scope() {
        let mut run = completed_run();
        for input in [
            json!({"at": " 0X00201187 ", "operand": 1, "clear": true}),
            json!({"at": 0x201187u64.to_string(), "operand": 1, "clear": true}),
        ] {
            assert!(permitted_mutation_selector("apply_offset", &input));
            run.calls.insert(
                0,
                receipt(
                    "apply_offset",
                    input,
                    json!({
                        "address": "0x201187", "operand": 1, "kind": "offset", "changed": true,
                        "annotation": null, "display": null,
                    }),
                ),
            );
        }
        assert!(check(&run));
    }

    #[test]
    fn write_receipts_must_match_requested_types_and_selectors_not_just_answer_text() {
        for (index, pointer, replacement) in [
            (0, "/binding/count", json!(1)),
            (1, "/binding/byte_length", json!(8)),
            (2, "/annotation/operand", json!(0)),
            (2, "/annotation/instruction_hex", json!("833f00")),
            (3, "/display/display", json!("TypedRecord.mode")),
            (3, "/address", json!("0x201182")),
        ] {
            let mut run = completed_run();
            rewrite_output(&mut run.calls[index], |value| *value.pointer_mut(pointer).unwrap() = replacement);
            assert!(!check(&run), "call {index} {pointer}");
        }
        let mut run = completed_run();
        let mut input: Value = serde_json::from_str(&run.calls[0].input.text).unwrap();
        input["path"] = json!("other.snapshot.json");
        run.calls[0].input = retained(input.to_string());
        assert!(!check(&run));
    }

    fn annotations() -> Value {
        let mut value = json!({});
        for name in UNRELATED_FIELDS {
            value[name] = json!([]);
        }
        value["data_types"] = json!([
            {"address": "0x200120", "text": record_binding_value().to_string()},
            {"address": "0x200140", "text": text_binding_value().to_string()},
        ]);
        value["operand_types"] = json!([
            {"address": "0x201182", "text": json!([{"operand": 1, "kind": "enum", "type_name": "TypedMode",
                "instruction_hex": "833f07"}]).to_string()},
            {"address": "0x201187", "text": json!([{"operand": 1, "kind": "offset", "type_name": "TypedRecord",
                "instruction_hex": "8b4704"}]).to_string()},
        ]);
        value
    }

    #[test]
    fn exact_log_state_rejects_extras_duplicates_and_unrelated_annotations() {
        assert!(exact_bindings(&annotations()));
        for name in UNRELATED_FIELDS {
            let mut value = annotations();
            value[name] = json!([{"address": "0x200120", "text": "unrequested"}]);
            assert!(!exact_bindings(&value), "{name}");
        }
        for name in ["data_types", "operand_types"] {
            let mut value = annotations();
            let duplicate = value[name][0].clone();
            value[name].as_array_mut().unwrap().push(duplicate);
            assert!(!exact_bindings(&value), "extra {name}");
            let mut value = annotations();
            value[name][1] = value[name][0].clone();
            assert!(!exact_bindings(&value), "duplicate selector {name}");
        }
        let mut value = annotations();
        value["operand_types"][1]["text"] = json!("[]");
        assert!(!exact_bindings(&value));
    }
}
