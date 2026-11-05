//! Opt-in phase-end central-struct reconstruction on an owned, source-recipe-pinned DWARF ELF.
//! Never compiles or executes the target. Uses the Anthropic transport and the fixed paired model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rampage_agent::Anthropic;
use rampage_api::DebugTypesManifest;
use rampage_api::annotations::{Annotations, parse_local_names, parse_local_types, parse_type_library};
use rampage_decompiler::VariableStorage;
use rampage_decompiler::results::Storage;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ToolCall, run_task};
use rampage_eval::parity_tasks::{AnswerContract, CapabilityStatus, FixtureIdentity, ParityTask, TaskKind};
use rampage_loaders::debug_types::{DebugScalarEncoding, DebugTypeKind, DebugTypeReport};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientConfig, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerConfig,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::{ClientHandler, ErrorData, Peer, ServerHandler, ServiceExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The pinned live model, requested through the in-process Anthropic transport (ANTHROPIC_API_KEY).
const MODEL: &str = "claude-sonnet-5-5";

const IMAGE_SHA: &str = "47458e57eaa7ec0e522b4db0ad3d57b284eef61d52f141b9fb02dc9ce2ed58ed";
const SOURCE_SHA: &str = "67d0d1d7392e8accb45bbdf612394ba065952dc0d36d15a6cd5b67082bed6115";
const METHOD: &str = "0x201190";
const WRAPPER: &str = "0x2011e0";
const METHOD_ADDRESS: u64 = 0x201190;
const WRAPPER_ADDRESS: u64 = 0x2011e0;
const MAX_OUTPUT_BYTES: usize = 65_536;
const MAPS: [&str; 12] = [
    "names",
    "comments",
    "signatures",
    "types",
    "globals",
    "local_names",
    "local_types",
    "type_library",
    "data_types",
    "operand_types",
    "type_hints",
    "debug_types",
];
const SEAL: &str = "!rampage-debug-types-signature-v1\n";

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn compact(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn owner_pointer(text: &str, owner: &str) -> bool {
    let text = compact(text);
    text == format!("{owner}*") || text == format!("struct{owner}*")
}

struct OwnedFixture {
    directory: PathBuf,
    path: PathBuf,
    original: PathBuf,
    context: PathBuf,
}

impl OwnedFixture {
    fn new(original: &Path) -> Result<Self, &'static str> {
        let original = original.canonicalize().map_err(|_| "explicit fixture does not exist")?;
        if !original.is_file() || digest(&std::fs::read(&original).map_err(|_| "read explicit fixture")?) != IMAGE_SHA {
            return Err("fixture differs from the source-recipe-pinned C++ x64 ELF");
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        std::fs::create_dir_all(&root).map_err(|_| "create temporary root")?;
        let directory = root.join(format!(
            "rampage-debug-type-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).map_err(|_| "create owned fixture directory")?;
        let owned = Self {
            path: directory.join("debug-cpp-x64.elf"),
            context: directory.join("model-context"),
            directory,
            original,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&owned.directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "restrict owned directory")?;
        }
        std::fs::copy(&owned.original, &owned.path).map_err(|_| "copy explicit fixture")?;
        std::fs::create_dir(&owned.context).map_err(|_| "create owned model context")?;
        if !owned.bytes_unchanged() {
            return Err("fixture changed while copying");
        }
        Ok(owned)
    }

    fn sidecar(&self) -> PathBuf {
        PathBuf::from(format!("{}.rampage", self.path.display()))
    }

    fn bytes_unchanged(&self) -> bool {
        [&self.path, &self.original]
            .into_iter()
            .all(|path| std::fs::read(path).is_ok_and(|bytes| digest(&bytes) == IMAGE_SHA))
    }

    fn log(&self) -> Result<Vec<u8>, &'static str> {
        let path = self.sidecar();
        if !path.exists() {
            return Ok(Vec::new());
        }
        if std::fs::metadata(&path).map_err(|_| "annotation log metadata")?.len() > 2_000_000 {
            return Err("annotation log exceeds bound");
        }
        std::fs::read(path).map_err(|_| "read annotation log")
    }

    fn exact_files(&self) -> bool {
        std::fs::read_dir(&self.directory).is_ok_and(|entries| {
            entries.into_iter().all(|entry| {
                entry.is_ok_and(|entry| {
                    let name = entry.file_name();
                    matches!(
                        name.to_str(),
                        Some(
                            "debug-cpp-x64.elf"
                                | "debug-cpp-x64.elf.rampage"
                                | "debug-cpp-x64.elf.rampage.lock"
                                | "model-context"
                        )
                    ) && !entry.file_type().map_or(true, |kind| kind.is_symlink())
                })
            })
        })
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        // Only this exclusively created directory is owned, including its model-context subdirectory.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn task() -> ParityTask {
    ParityTask {
        version: 1,
        id: "phase1-6-debug-type-import".into(),
        kind: TaskKind::Capability,
        question: "Reconstruct the central C++ DebugOwner/DebugCell layout from checked DWARF. Enable types. \
            Inspect decompile at method 0x201190 and wrapper debug_cpp_query at 0x2011e0. Preview \
            import_debug_types on this fixture only, with pdb omitted; inspect the complete detail pages, \
            including original DebugOwner/DebugCell to emitted native names. Apply the whole plan using \
            the exact fresh review_sha256. Do not replace preview-only qualified const-this evidence with \
            a claimed producer signature. Deliberately make a manual analyst retype: identify parameter \
            index 0 in structure.signature.parameters of method 0x201190, match its full native storage \
            to the editable parameter descriptor and use edit_variable with that canonical storage and \
            the imported emitted Owner pointer type (same 8 bytes). Optional name is owner. No set_types, \
            set_signature, declarations, other edits, secondary paths, patches, or target execution. \
            Re-inspect get_type for both imported records and decompile both functions after the edit. \
            Require actual native C paths for cells[].count, cells[].level and bias. Preserve all checked \
            import annotations and analyst edits. Return only JSON fields owner_size, cell_stride, \
            bias_offset, next_offset, typed_cells, analyst_edits_preserved. An independent evaluator checks \
            native metadata, complete consent receipts, exact side effects, persistence and unchanged bytes; \
            the summary alone is not proof."
            .into(),
        fixture: FixtureIdentity {
            id: "owned-debug-cpp-x64-dwarf".into(),
            path: "target/phase1-6/debug-cpp-x64.elf".into(),
            sha256: IMAGE_SHA.into(),
            source: "tests/fixtures/src/debug-types.cpp".into(),
            build: "crates/rampage-eval/tasks/phase1-6/debug-types.toml".into(),
            companions: Vec::new(),
        },
        truth_reference: "Source-recipe SHA, compiler layout table and independent debug::type_graph DTO".into(),
        required_capabilities: ["import_debug_types", "get_type", "decompile", "edit_variable"]
            .into_iter()
            .map(String::from)
            .collect(),
        capability_status: CapabilityStatus::Unknown,
        capability_evidence: "Complete actual MCP catalogs and native/fresh-server checks".into(),
        answer: AnswerContract::Exact {
            fields: BTreeMap::from([
                ("owner_size".into(), json!(48)),
                ("cell_stride".into(), json!(16)),
                ("bias_offset".into(), json!(32)),
                ("next_offset".into(), json!(40)),
                ("typed_cells".into(), json!(true)),
                ("analyst_edits_preserved".into(), json!(true)),
            ]),
            hex_integers: false,
        },
    }
}

fn json_result(result: &CallToolResult) -> Result<Value, &'static str> {
    if result.is_error == Some(true) {
        return Err("MCP tool error");
    }
    if result.content.len() != 1 {
        return Err("MCP result is not one complete text item");
    }
    let text = &result.content[0].as_text().ok_or("MCP text result unavailable")?.text;
    if text.len() > MAX_OUTPUT_BYTES {
        return Err("MCP result exceeds bound");
    }
    serde_json::from_str(text).map_err(|_| "MCP result JSON")
}

fn first_parameter(value: &Value) -> Result<(VariableStorage, &Value), &'static str> {
    let first = value["structure"]["signature"]["parameters"]
        .as_array()
        .and_then(|parameters| parameters.first())
        .ok_or("signature parameter index zero unavailable")?;
    let raw: Storage = serde_json::from_value(first["storage"].clone()).map_err(|_| "signature storage")?;
    let selector = VariableStorage::try_from(&raw).map_err(|_| "incomplete signature storage")?;
    let descriptor = selected_parameter(value, &selector).ok_or("first parameter canonical descriptor unavailable")?;
    if descriptor["data_type"] != first["data_type"] {
        return Err("signature parameter differs from canonical descriptor");
    }
    Ok((selector, descriptor))
}

fn selected_parameter<'a>(value: &'a Value, selector: &VariableStorage) -> Option<&'a Value> {
    let variables = value["variables"].as_array()?;
    let key = serde_json::to_string(selector).ok()?;
    let mut matches = variables.iter().filter(|variable| {
        variable["kind"] == "parameter"
            && variable["editable"] == true
            && variable["storage"] == serde_json::to_value(selector).unwrap_or(Value::Null)
            && variable["key"] == key
    });
    let descriptor = matches.next()?;
    if matches.next().is_some() || selector.size != 8 {
        return None;
    }
    Some(descriptor)
}

#[derive(Clone, Default)]
struct Consent {
    hash: Option<String>,
    manifest: Option<String>,
    total: usize,
    details: Vec<Value>,
    preview: Option<Value>,
    applied: Option<Value>,
    edited: bool,
    violation: bool,
}

fn detail<'a>(details: &'a [Value], original: &str) -> Option<&'a Value> {
    let mut rows = details.iter().filter(|row| {
        row["original_name"] == original
            && row["applicable"] == true
            && row["producer"]["kind"]["kind"] == "struct"
            && row["native"]["kind"] == "struct"
    });
    let row = rows.next()?;
    if rows.next().is_some() {
        return None;
    }
    Some(row)
}

impl Consent {
    fn record_preview(&mut self, receipt: &Value) -> bool {
        let Some(hash) = receipt["review_sha256"].as_str() else { return false };
        let Some(manifest) = receipt["manifest_id"].as_str() else { return false };
        let Some(total) = receipt["total"].as_u64().and_then(|n| usize::try_from(n).ok()) else { return false };
        let Some(rows) = receipt["details"].as_array() else { return false };
        if receipt["applied"] != false
            || receipt["imported_types"] != 0
            || receipt["imported_signatures"] != 0
            || hash.len() != 64
            || manifest.len() != 64
            || total == 0
            || total > 256
            || rows.is_empty()
            || self.applied.is_some()
        {
            return false;
        }
        if receipt["offset"] == 0 {
            self.hash = Some(hash.into());
            self.manifest = Some(manifest.into());
            self.total = total;
            self.details.clear();
            self.preview = Some(receipt.clone());
        }
        let Some(first) = &self.preview else { return false };
        if self.hash.as_deref() != Some(hash)
            || self.manifest.as_deref() != Some(manifest)
            || self.total != total
            || receipt["offset"].as_u64() != Some(self.details.len() as u64)
            || ["applicable_types", "applicable_signatures", "preserved_signatures"]
                .iter()
                .any(|key| receipt[*key] != first[*key])
        {
            return false;
        }
        self.details.extend(rows.iter().cloned());
        if self.details.len() > total {
            return false;
        }
        if self.details.len() == total {
            receipt["next_offset"].is_null()
        } else {
            receipt["next_offset"].as_u64() == Some(self.details.len() as u64)
        }
    }

    fn complete(&self) -> bool {
        self.total > 0
            && self.details.len() == self.total
            && detail(&self.details, "DebugOwner").is_some()
            && detail(&self.details, "DebugCell").is_some()
    }

    fn record_apply(&mut self, input: &Value, receipt: &Value) -> bool {
        let Some(preview) = &self.preview else { return false };
        if !self.complete()
            || self.applied.is_some()
            || input["apply"] != true
            || input["review_sha256"].as_str() != self.hash.as_deref()
            || receipt["applied"] != true
            || [
                "review_sha256",
                "manifest_id",
                "total",
                "applicable_types",
                "applicable_signatures",
                "preserved_signatures",
            ]
            .iter()
            .any(|key| receipt[*key] != preview[*key])
            || receipt["imported_types"] != preview["applicable_types"]
            || receipt["imported_signatures"] != preview["applicable_signatures"]
        {
            return false;
        }
        self.applied = Some(receipt.clone());
        true
    }
}

#[derive(Clone)]
struct Scope {
    inner: rampage_mcp::RampageServer,
    path: String,
    selector: Arc<Mutex<Option<VariableStorage>>>,
    consent: Arc<Mutex<Consent>>,
}

fn permitted(scope: &Scope, name: &str, input: &Value, consent: &Consent) -> bool {
    let Some(arguments) = input.as_object() else { return false };
    if name == "enable_tools" {
        return arguments.keys().all(|key| key == "groups");
    }
    if input["path"].as_str() != Some(scope.path.as_str())
        || ["pdb", "arch", "image_offset", "image_length"].iter().any(|key| arguments.contains_key(*key))
    {
        return false;
    }
    match name {
        "import_debug_types" => {
            arguments.keys().all(|key| matches!(key.as_str(), "path" | "apply" | "review_sha256" | "offset" | "limit"))
                && if input["apply"] == true {
                    consent.complete()
                        && consent.applied.is_none()
                        && input["review_sha256"].as_str() == consent.hash.as_deref()
                } else {
                    input.get("apply").is_none_or(|value| *value == false) && consent.applied.is_none()
                }
        }
        "edit_variable" => {
            let selector = scope.selector.lock().unwrap();
            let owner = detail(&consent.details, "DebugOwner").and_then(|row| row["emitted_name"].as_str());
            consent.applied.is_some()
                && !consent.edited
                && input["at"] == METHOD
                && selector
                    .as_ref()
                    .and_then(|selector| serde_json::to_value(selector).ok())
                    .is_some_and(|selector| input["storage"] == selector)
                && input["data_type"].as_str().zip(owner).is_some_and(|(ty, owner)| owner_pointer(ty, owner))
                && input.get("name").is_none_or(|name| *name == "owner")
                && arguments.keys().all(|key| matches!(key.as_str(), "path" | "at" | "storage" | "data_type" | "name"))
        }
        "decompile" | "function_frame" => {
            (input["at"] == METHOD || input["at"] == WRAPPER)
                && arguments.keys().all(|key| matches!(key.as_str(), "path" | "at" | "view" | "offset" | "limit"))
        }
        "get_type" => arguments.keys().all(|key| matches!(key.as_str(), "path" | "name")),
        "list_types" => arguments.keys().all(|key| matches!(key.as_str(), "path" | "contains" | "offset" | "limit")),
        "list_annotations" | "binary_info" => arguments.len() == 1,
        _ => false,
    }
}

impl ServerHandler for Scope {
    fn get_info(&self) -> ServerConfig {
        self.inner.get_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.inner.list_tools(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let input = Value::Object(request.arguments.clone().unwrap_or_default());
        let allowed = permitted(self, &name, &input, &self.consent.lock().unwrap());
        if !allowed {
            self.consent.lock().unwrap().violation = true;
            let error = CallToolResult::error(vec![ContentBlock::text("task-specific mutation/path policy refusal")]);
            return Ok(error.into());
        }
        let response = self.inner.call_tool(request, context).await?;
        if name == "import_debug_types" || name == "edit_variable" {
            let receipt = match &response {
                CallToolResponse::Complete(result) => json_result(result),
                _ => Err("incomplete mutation receipt"),
            };
            let mut consent = self.consent.lock().unwrap();
            let valid = receipt.is_ok_and(|receipt| match name.as_str() {
                "import_debug_types" if input["apply"] == true => consent.record_apply(&input, &receipt),
                "import_debug_types" => consent.record_preview(&receipt),
                "edit_variable" => {
                    consent.edited = true;
                    true
                }
                _ => false,
            });
            if !valid {
                consent.violation = true;
            }
        }
        Ok(response)
    }
}

#[derive(Default)]
struct MeasurementClient;
impl ClientHandler for MeasurementClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

struct Connection {
    client: RunningService<RoleClient, MeasurementClient>,
    server: tokio::task::JoinHandle<Result<(), &'static str>>,
    scope: Scope,
}

impl Connection {
    async fn open(owned: &OwnedFixture) -> Result<Self, &'static str> {
        let scope = Scope {
            inner: rampage_mcp::RampageServer::default(),
            path: owned.path.to_str().ok_or("fixture path encoding")?.into(),
            selector: Arc::new(Mutex::new(None)),
            consent: Arc::new(Mutex::new(Consent::default())),
        };
        let server_scope = scope.clone();
        let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            server_scope
                .serve(server_transport)
                .await
                .map_err(|_| "connect in-memory server")?
                .waiting()
                .await
                .map(|_| ())
                .map_err(|_| "close in-memory server")
        });
        let client = MeasurementClient.serve(client_transport).await.map_err(|_| "connect in-memory client")?;
        Ok(Self { client, server, scope })
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
}
impl Checks {
    async fn call(&mut self, client: &Peer<RoleClient>, name: &str, input: Value) -> Result<Value, &'static str> {
        self.calls += 1;
        let result = client
            .call_tool(
                CallToolRequestParams::new(name.to_owned())
                    .with_arguments(input.as_object().ok_or("evaluator arguments")?.clone()),
            )
            .await;
        let value = result.map_err(|_| "evaluator MCP transport").and_then(|result| json_result(&result));
        self.errors += usize::from(value.is_err());
        value
    }
}

struct Baseline {
    selector: VariableStorage,
    method: Value,
    wrapper: Value,
    annotations: Value,
    producer: DebugTypeReport,
    owner_id: String,
    reference: SourceSignature,
}

struct SourceSignature {
    function_id: String,
    return_type: Value,
    index_type: Value,
    pointer_size: u64,
}

fn source_scalar(report: &DebugTypeReport, id: &str) -> Result<Value, &'static str> {
    let ty = report.types.iter().find(|ty| ty.id == id).ok_or("source scalar ID unavailable")?;
    let prefix = match &ty.kind {
        DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Float, .. } => "float",
        DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Signed, .. } => "int",
        _ => return Err("unsupported source scalar encoding"),
    };
    let size = ty.byte_size.ok_or("source scalar width unavailable")?;
    Ok(json!({"name": format!("{prefix}{size}"), "size": size}))
}

fn source_reference(owned: &OwnedFixture) -> Result<(DebugTypeReport, String, SourceSignature), &'static str> {
    let binary = rampage_loaders::Binary::open(&owned.path).map_err(|_| "open owned native ELF")?;
    let report = rampage_loaders::debug::type_graph(&binary).map_err(|_| "independent DWARF type graph")?;
    if report.provenance.source != rampage_loaders::debug_types::DebugSourceKind::Dwarf
        || report.provenance.source_sha256 != IMAGE_SHA
        || report.provenance.pdb_guid.is_some()
        || report.provenance.pdb_age.is_some()
    {
        return Err("independent source provenance mismatch");
    }
    let matching: Vec<_> = report
        .signatures
        .iter()
        .filter(|signature| {
            signature.address == WRAPPER_ADDRESS
                && signature.name.as_deref() == Some("debug_cpp_query")
                && signature.unsupported.is_empty()
        })
        .collect();
    if matching.len() != 1 {
        return Err("exact wrapper producer identity unavailable");
    }
    let function = report.types.iter().find(|ty| ty.id == matching[0].type_id).ok_or("wrapper producer function ID")?;
    let DebugTypeKind::Function { parameters, return_type, variadic, .. } = &function.kind else {
        return Err("wrapper producer is not a function");
    };
    let lookup = |id: &str| report.types.iter().find(|ty| ty.id == id);
    let is_scalar = |id: &str, encoding, size| {
        lookup(id).is_some_and(|ty| {
            ty.byte_size == Some(size)
                && matches!(&ty.kind, DebugTypeKind::Scalar { encoding: actual, .. } if *actual == encoding)
        })
    };
    if *variadic
        || parameters.len() != 2
        || !is_scalar(return_type, DebugScalarEncoding::Float, 8)
        || !is_scalar(&parameters[1], DebugScalarEncoding::Signed, 4)
    {
        return Err("wrapper producer scalar reference differs from source recipe");
    }
    let pointer = lookup(&parameters[0]).ok_or("wrapper pointer producer ID")?;
    let DebugTypeKind::Pointer { target } = &pointer.kind else {
        return Err("wrapper source parameter is not pointer");
    };
    let owner = lookup(target).ok_or("wrapper pointee producer ID")?;
    if pointer.byte_size != Some(8)
        || owner.original_name.as_deref() != Some("DebugOwner")
        || owner.byte_size != Some(48)
        || !matches!(owner.kind, DebugTypeKind::Struct { .. })
    {
        return Err("wrapper producer Owner pointer reference mismatch");
    }
    let owner_id = owner.id.clone();
    let reference = SourceSignature {
        function_id: function.id.clone(),
        return_type: source_scalar(&report, return_type)?,
        index_type: source_scalar(&report, &parameters[1])?,
        pointer_size: pointer.byte_size.ok_or("source pointer width unavailable")?,
    };
    let project = rampage_api::Session::default().open(&owned.path, None).map_err(|_| "open compiler table")?;
    let address = project.resolve("debug_cpp_layout").map_err(|_| "compiler layout table symbol")?;
    let bytes = project.binary.read(address, 36).ok_or("backed compiler layout table")?;
    let (words, remainder) = bytes.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err("compiler layout table contains a partial word");
    }
    let table: Vec<u32> = words.iter().copied().map(u32::from_le_bytes).collect();
    if table != [16, 8, 0, 8, 48, 8, 0, 32, 40] {
        return Err("source compiler layout table mismatch");
    }
    Ok((report, owner_id, reference))
}

async fn prepare(connection: &Connection, owned: &OwnedFixture, checks: &mut Checks) -> Result<Baseline, &'static str> {
    let (producer, owner_id, reference) = source_reference(owned)?;
    checks.call(&connection.client, "enable_tools", json!({"groups": ["types"]})).await?;
    let method = checks.call(&connection.client, "decompile", json!({"path": owned.path, "at": METHOD})).await?;
    let (selector, _) = first_parameter(&method)?;
    let selector = selector.clone();
    *connection.scope.selector.lock().unwrap() = Some(selector.clone());
    let wrapper = checks.call(&connection.client, "decompile", json!({"path": owned.path, "at": WRAPPER})).await?;
    let annotations = checks.call(&connection.client, "list_annotations", json!({"path": owned.path})).await?;
    if MAPS.iter().any(|key| annotations[*key] != json!([])) || !owned.log()?.is_empty() {
        return Err("owned baseline contains annotations");
    }
    Ok(Baseline { selector, method, wrapper, annotations, producer, owner_id, reference })
}

fn agreement(decompilation: &Value, owner: &str, reference: &SourceSignature) -> Result<Value, &'static str> {
    let signature = &decompilation["structure"]["signature"];
    let parameters = signature["parameters"].as_array().ok_or("native wrapper signature unavailable")?;
    let components = [
        signature["return_type"] == reference.return_type,
        parameters.first().is_some_and(|parameter| {
            parameter["data_type"]["size"] == reference.pointer_size
                && parameter["data_type"]["name"].as_str().is_some_and(|name| owner_pointer(name, owner))
        }),
        parameters.get(1).is_some_and(|parameter| parameter["data_type"] == reference.index_type),
    ];
    Ok(json!({"matched_components": components.iter().filter(|matched| **matched).count(),
        "total_components": 3, "components": components, "exact_parameter_count": parameters.len() == 2,
        "reference": "independent DWARF DTO", "producer_function_id": reference.function_id,
        "producer_function_address": WRAPPER}))
}

fn native_field<'a>(native: &'a Value, name: &str) -> Option<&'a Value> {
    let mut fields = native["fields"].as_array()?.iter().filter(|field| field["name"] == name);
    let field = fields.next()?;
    if fields.next().is_some() { None } else { Some(field) }
}

fn layouts(owner: &Value, cell: &Value) -> bool {
    let Some(owner_name) = owner["name"].as_str() else { return false };
    let Some(cell_name) = cell["name"].as_str() else { return false };
    let base = |ty: &Value, size: u64, count: usize| {
        ty["kind"] == "struct"
            && ty["size"] == size
            && ty["incomplete"] == false
            && ty["packing"].is_null()
            && ty["fields"].as_array().is_some_and(|fields| fields.len() == count)
    };
    let scalar = |ty: &Value, name: &str, offset: u64, size: u64, type_name: &str| {
        native_field(ty, name)
            .is_some_and(|field| field["offset"] == offset && field["size"] == size && field["type_name"] == type_name)
    };
    base(owner, 48, 3)
        && base(cell, 16, 2)
        && scalar(owner, "bias", 32, 4, "int4")
        && scalar(cell, "count", 0, 4, "int4")
        && scalar(cell, "level", 8, 8, "float8")
        && native_field(owner, "cells").is_some_and(|field| {
            field["offset"] == 0
                && field["size"] == 32
                && field["identity"]["length"] == 2
                && field["identity"]["element"]["reference"] == cell_name
        })
        && native_field(owner, "next").is_some_and(|field| {
            field["offset"] == 40
                && field["size"] == 8
                && field["identity"]["target"]["reference"] == owner_name
                && field["type_name"].as_str().is_some_and(|name| owner_pointer(name, owner_name))
        })
}

fn library_metadata(entry: &Value) -> Option<Value> {
    if entry["scope"] != "library" || entry["declaration"]["source"]["kind"] != "checked_debug_types" {
        return None;
    }
    let mut metadata = entry.as_object()?.clone();
    metadata.remove("scope");
    metadata.remove("declaration");
    Some(Value::Object(metadata))
}

fn c_tokens(code: &str) -> Option<Vec<&str>> {
    if code.len() > MAX_OUTPUT_BYTES || !code.is_ascii() {
        return None;
    }
    let bytes = code.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if tokens.len() >= 8192 {
            return None;
        }
        if bytes[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if code[at..].starts_with("//") {
            at += code[at..].find('\n').unwrap_or(bytes.len() - at);
            continue;
        }
        if code[at..].starts_with("/*") {
            at += code[at + 2..].find("*/")? + 4;
            continue;
        }
        if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            at += 1;
            loop {
                let byte = *bytes.get(at)?;
                at += 1;
                if byte == quote {
                    break;
                }
                if byte == b'\\' {
                    bytes.get(at)?;
                    at += 1;
                }
            }
            tokens.push("__literal__");
            continue;
        }
        let start = at;
        at += 1;
        if bytes[start].is_ascii_alphanumeric() || bytes[start] == b'_' {
            while bytes.get(at).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_') {
                at += 1;
            }
        } else if code.get(start..start + 3).is_some_and(|token| matches!(token, "<<=" | ">>=")) {
            at += 2;
        } else if code.get(start..start + 2).is_some_and(|token| {
            matches!(
                token,
                "->" | "=="
                    | "!="
                    | "<="
                    | ">="
                    | "++"
                    | "--"
                    | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "<<"
                    | ">>"
                    | "&&"
                    | "||"
            )
        }) {
            at += 1;
        }
        tokens.push(&code[start..at]);
    }
    Some(tokens)
}

fn closing(tokens: &[&str], start: usize, open: &str, close: &str) -> Option<usize> {
    if tokens.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0;
    for (at, token) in tokens.iter().enumerate().skip(start) {
        if *token == open {
            depth += 1;
        }
        if *token == close {
            depth -= 1;
            if depth == 0 {
                return Some(at);
            }
        }
    }
    None
}

fn index_expression(tokens: &[&str]) -> bool {
    let mut depth = 0;
    for token in tokens {
        if *token == "(" {
            depth += 1;
        }
        if *token == ")" {
            depth -= 1;
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
        && !tokens.is_empty()
        && tokens.iter().any(|token| token.bytes().any(|byte| byte.is_ascii_alphanumeric()))
        && tokens.iter().all(|token| {
            *token != "__literal__"
                && (token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    || matches!(
                        *token,
                        "(" | ")" | "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "~" | "!" | "<<" | ">>"
                    ))
        })
}

fn cell_assignment(mut tokens: &[&str], owner: &str) -> Option<String> {
    while tokens.first() == Some(&"(") && closing(tokens, 0, "(", ")") == Some(tokens.len() - 1) {
        tokens = &tokens[1..tokens.len() - 1];
    }
    let address = tokens.first() == Some(&"&");
    if address {
        tokens = &tokens[1..];
    }
    while tokens.first() == Some(&"(") && closing(tokens, 0, "(", ")") == Some(tokens.len() - 1) {
        tokens = &tokens[1..tokens.len() - 1];
    }
    if tokens.get(..3) != Some(&[owner, "->", "cells"][..]) {
        return None;
    }
    if address && tokens.get(3) == Some(&"[") {
        let end = closing(tokens, 3, "[", "]")?;
        if end + 1 == tokens.len() && index_expression(&tokens[4..end]) {
            return Some(tokens[4..end].join(" "));
        }
    } else if !address && tokens.get(3) == Some(&"+") && index_expression(&tokens[4..]) {
        return Some(tokens[4..].join(" "));
    }
    None
}

fn actual_field_paths(code: &str, owner: &str) -> bool {
    let Some(tokens) = c_tokens(code) else { return false };
    if owner.is_empty() {
        return false;
    }
    let mut aliases = BTreeMap::<&str, String>::new();
    let mut fields = BTreeMap::<String, BTreeSet<&str>>::new();
    // Direct indexes observe current identifier generations; an already captured Cell pointer does not.
    let mut generations = BTreeMap::<&str, usize>::new();
    let mut bias = false;
    for at in 0..tokens.len() {
        let base = tokens[at];
        if !base.as_bytes().first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            || (at > 0 && matches!(tokens[at - 1], "->" | "."))
        {
            continue;
        }
        let (mut start, mut end) = (at, at + 1);
        while start > 0 && tokens[start - 1] == "(" && tokens.get(end) == Some(&")") {
            start -= 1;
            end += 1;
        }
        let prefix_mutation = start > 0 && matches!(tokens[start - 1], "++" | "--");
        let postfix_mutation = tokens.get(end).is_some_and(|token| {
            matches!(*token, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | "++" | "--")
        });
        if prefix_mutation || postfix_mutation {
            if base == owner {
                return false;
            }
            *generations.entry(base).or_default() += 1;
            aliases.remove(base);
            if tokens.get(end) == Some(&"=") {
                let rhs = end + 1;
                let statement_end = tokens[rhs..].iter().position(|token| *token == ";").map(|end| end + rhs);
                if let Some(relation) = statement_end.and_then(|end| cell_assignment(&tokens[rhs..end], owner)) {
                    aliases.insert(base, format!("alias:{at}:{relation}"));
                }
            }
        }
        if tokens.get(at + 1) != Some(&"->") {
            continue;
        }
        if base == owner {
            bias |= tokens.get(at + 2) == Some(&"bias");
            if tokens.get(at + 2) != Some(&"cells") || tokens.get(at + 3) != Some(&"[") {
                continue;
            }
            let Some(end) = closing(&tokens, at + 3, "[", "]") else { return false };
            let index = &tokens[at + 4..end];
            if index_expression(index)
                && tokens.get(end + 1) == Some(&".")
                && let Some(field @ ("count" | "level")) = tokens.get(end + 2).copied()
            {
                let versions: BTreeMap<_, _> = index
                    .iter()
                    .copied()
                    .filter(|token| {
                        token.as_bytes().first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
                    })
                    .map(|token| (token, generations.get(token).copied().unwrap_or(0)))
                    .collect();
                fields.entry(format!("direct:{}:{versions:?}", index.join(" "))).or_default().insert(field);
            }
        } else if let Some(relation) = aliases.get(base)
            && let Some(field @ ("count" | "level")) = tokens.get(at + 2).copied()
        {
            fields.entry(relation.clone()).or_default().insert(field);
        }
    }
    // Only a lexical relation for this fixture; layout/stride come from separate native metadata checks.
    bias && fields.values().any(|fields| fields.contains("count") && fields.contains("level"))
}

fn edit_receipt_name(
    input: &Value,
    receipt: &Value,
    selector: &VariableStorage,
    owner: &str,
    previous_name: &str,
) -> Option<String> {
    if receipt["address"] != METHOD
        || receipt["storage"] != input["storage"]
        || serde_json::to_value(selector).ok().as_ref() != Some(&receipt["storage"])
    {
        return None;
    }
    let edits = receipt["edits"].as_array()?;
    let expected = if input.get("name").is_some() { vec!["localtype", "localname"] } else { vec!["localtype"] };
    if edits.len() != expected.len()
        || expected
            .iter()
            .any(|field| edits.iter().filter(|edit| edit["field"] == *field && edit["changed"] == true).count() != 1)
    {
        return None;
    }
    let refreshed = &receipt["decompilation"];
    let descriptor = selected_parameter(refreshed, selector)?;
    let name = descriptor["name"].as_str()?;
    let expected_name = input.get("name").and_then(Value::as_str).unwrap_or(previous_name);
    if name != expected_name
        || descriptor["data_type"]["size"] != 8
        || !descriptor["data_type"]["name"].as_str().is_some_and(|name| owner_pointer(name, owner))
        || !refreshed["code"].as_str().is_some_and(|code| actual_field_paths(code, name))
    {
        return None;
    }
    Some(name.to_owned())
}

fn proof(annotations: &Value) -> Result<DebugTypesManifest, &'static str> {
    let rows = annotations["debug_types"].as_array().ok_or("checked proof annotation map missing")?;
    if rows.len() != 1 || rows[0]["address"] != "0x0" {
        return Err("checked proof ownership count/address");
    }
    let envelope: Value =
        serde_json::from_str(rows[0]["text"].as_str().ok_or("proof text")?).map_err(|_| "proof envelope JSON")?;
    let imports = envelope["imports"].as_array().ok_or("checked proof imports missing")?;
    if envelope["version"] != 1 || imports.len() != 1 {
        return Err("exactly one checked import required");
    }
    decode_manifest_wire(&imports[0])
}

fn decode_manifest_wire(wire: &Value) -> Result<DebugTypesManifest, &'static str> {
    for field in ["producer", "expected_native_named_types"] {
        let framed = wire[field].as_str().ok_or("checked manifest requires JSON-string framed fields")?;
        if framed.len() > 1024 * 1024 {
            return Err("checked manifest framed field exceeds bound");
        }
    }
    // The API DTO's bounded serde adapter decodes these strings to Value/Vec before semantic inspection.
    // Do not replace fields in the original wire value: log comparisons retain its exact framing bytes.
    serde_json::from_value(wire.clone()).map_err(|_| "checked manifest framed DTO")
}

fn manifest_identity(manifest: &DebugTypesManifest) -> Result<String, &'static str> {
    let mut identity = manifest.clone();
    identity.id.clear();
    identity.review_sha256.clear();
    // Match the producer's canonical typed serialization, including framing and the probed native model.
    Ok(digest(&serde_json::to_vec(&identity).map_err(|_| "manifest identity serialization")?))
}

fn persisted_maps(annotations: &Annotations) -> Value {
    let maps = [
        annotations.names(),
        annotations.comments(),
        annotations.signatures(),
        annotations.types(),
        annotations.globals(),
        annotations.local_names(),
        annotations.local_types(),
        annotations.type_library(),
        annotations.data_types(),
        annotations.operand_types(),
        annotations.type_hints(),
        annotations.debug_types(),
    ];
    Value::Object(
        MAPS.into_iter()
            .zip(maps)
            .map(|(name, map)| {
                (
                    name.to_owned(),
                    json!(
                        map.iter()
                            .map(|(address, text)| json!({"address": format!("{address:#x}"),
            "text": text}))
                            .collect::<Vec<_>>()
                    ),
                )
            })
            .collect(),
    )
}

fn retained_maps_present(annotations: &Value, manifest_id: &str, signatures: usize) -> bool {
    signatures > 0
        && ["debug_types", "type_library"]
            .iter()
            .all(|key| annotations[*key].as_array().is_some_and(|rows| rows.len() == 1))
        && annotations["signatures"].as_array().is_some_and(|rows| {
            rows.len() == signatures
                && rows.iter().all(|row| {
                    row["text"].as_str().is_some_and(|text| text.starts_with(&format!("{SEAL}{manifest_id}\n")))
                })
        })
}

fn exact_state(
    annotations: &Value,
    baseline: &Baseline,
    consent: &Consent,
    manifest: &DebugTypesManifest,
) -> Result<bool, &'static str> {
    if !retained_maps_present(annotations, &manifest.id, manifest.signatures.len()) {
        return Ok(false);
    }
    let retained = proof(annotations)?;
    if serde_json::to_value(&retained).map_err(|_| "retained manifest serialization")?
        != serde_json::to_value(manifest).map_err(|_| "expected manifest serialization")?
    {
        return Ok(false);
    }
    let owner = detail(&consent.details, "DebugOwner").ok_or("reviewed Owner detail")?;
    let cell = detail(&consent.details, "DebugCell").ok_or("reviewed Cell detail")?;
    let owner_name = owner["emitted_name"].as_str().ok_or("reviewed emitted Owner name")?;
    let identity = manifest_identity(manifest)?;
    if manifest.id != identity
        || Some(manifest.id.as_str()) != consent.manifest.as_deref()
        || Some(manifest.review_sha256.as_str()) != consent.hash.as_deref()
        || manifest.image_sha256 != IMAGE_SHA
        || manifest.specification_sha256.len() != 64
        || Some(manifest.language_id.as_str()) != baseline.method["language_id"].as_str()
        || manifest.organization != (rampage_decompiler::DataOrganization { pointer: 8, int: 4, long: 8 })
        || manifest.declarations_sha256 != digest(manifest.declarations.as_bytes())
        || manifest.producer != serde_json::to_value(&baseline.producer).map_err(|_| "producer reference JSON")?
        || owner["producer_type_id"] != baseline.owner_id
        || !owner["producer"]["alignment"].is_null()
        || !cell["producer"]["alignment"].is_null()
    {
        return Ok(false);
    }
    let producer_types = &baseline.producer.types;
    if consent.details.len() != producer_types.len()
        || producer_types.iter().any(|ty| {
            let matching: Vec<_> = consent.details.iter().filter(|row| row["producer_type_id"] == ty.id).collect();
            matching.len() != 1 || matching[0]["producer"] != serde_json::to_value(ty).unwrap_or(Value::Null)
        })
        || consent.applied.as_ref().is_none_or(|receipt| {
            receipt["imported_types"].as_u64() != Some(manifest.library_names.len() as u64)
                || receipt["imported_signatures"].as_u64() != Some(manifest.signatures.len() as u64)
        })
    {
        return Ok(false);
    }
    let expected_types = manifest
        .expected_native_named_types
        .iter()
        .map(|ty| (ty.name.as_str(), serde_json::to_value(ty).unwrap_or(Value::Null)))
        .collect::<BTreeMap<_, _>>();
    if expected_types.len() != manifest.library_names.len()
        || manifest.library_names.iter().any(|name| !expected_types.contains_key(name.as_str()))
        || consent
            .details
            .iter()
            .filter(|row| row["native"].is_object())
            .any(|row| row["emitted_name"].as_str().and_then(|name| expected_types.get(name)) != Some(&row["native"]))
    {
        return Ok(false);
    }
    let library = annotations["type_library"].as_array().ok_or("library annotation missing")?;
    if library.len() != 1 || library[0]["address"] != "0x0" {
        return Ok(false);
    }
    let units = parse_type_library(library[0]["text"].as_str().ok_or("library text")?)
        .map_err(|_| "checked library parsing")?;
    if units.len() != 1
        || units[0].names != manifest.library_names
        || units[0].declarations != manifest.declarations
        || units[0].packing.is_some()
        || units[0]
            .source
            .as_ref()
            .is_none_or(|source| source.kind != "checked_debug_types" || source.identity != manifest.id)
    {
        return Ok(false);
    }
    let signatures = annotations["signatures"].as_array().ok_or("signature map missing")?;
    if signatures.len() != manifest.signatures.len()
        || !manifest.signatures.iter().any(|sig| sig.address == WRAPPER_ADDRESS)
        || manifest.signatures.iter().any(|sig| sig.address == METHOD_ADDRESS)
        || manifest.signatures.iter().any(|signature| {
            !signatures.iter().any(|row| {
                row["address"] == format!("{:#x}", signature.address)
                    && row["text"] == format!("{SEAL}{}\n{}", manifest.id, signature.declaration)
            })
        })
    {
        return Ok(false);
    }
    let local_types = annotations["local_types"].as_array().ok_or("local type map missing")?;
    if local_types.len() != 1 || local_types[0]["address"] != METHOD {
        return Ok(false);
    }
    let types = parse_local_types(local_types[0]["text"].as_str().ok_or("local type text")?)
        .map_err(|_| "local types parsing")?;
    if types.len() != 1 || types[0].storage != baseline.selector || !owner_pointer(&types[0].data_type, owner_name) {
        return Ok(false);
    }
    let names = annotations["local_names"].as_array().ok_or("local names map missing")?;
    if !names.is_empty() {
        if names.len() != 1 || names[0]["address"] != METHOD {
            return Ok(false);
        }
        let names =
            parse_local_names(names[0]["text"].as_str().ok_or("local name text")?).map_err(|_| "local name parsing")?;
        if names.len() != 1 || names[0].storage != baseline.selector || names[0].name != "owner" {
            return Ok(false);
        }
    }
    Ok(MAPS
        .iter()
        .filter(|key| !matches!(**key, "debug_types" | "type_library" | "signatures" | "local_types" | "local_names"))
        .all(|key| annotations[*key] == baseline.annotations[*key]))
}

fn exact_log(bytes: &[u8], annotations: &Value, manifest: &DebugTypesManifest) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else { return false };
    if !text.ends_with('\n') {
        return false;
    }
    let Ok(lines) = text.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    if lines.first().is_none_or(|line| line["image"] != IMAGE_SHA) {
        return false;
    }
    let import_count = manifest.signatures.len() + 2;
    let Some(header) = lines.get(1) else { return false };
    let Some(batch) = header["batch"].as_str() else { return false };
    if header["edits"].as_u64() != Some(import_count as u64) {
        return false;
    }
    let Some(import) = lines.get(2..2 + import_count) else { return false };
    let mut expected = BTreeMap::new();
    expected.insert(("typelibrary", "0x0".to_owned()), annotations["type_library"][0]["text"].clone());
    expected.insert(("debugtypes", "0x0".to_owned()), annotations["debug_types"][0]["text"].clone());
    for signature in &manifest.signatures {
        expected.insert(
            ("signature", format!("{:#x}", signature.address)),
            json!(format!("{SEAL}{}\n{}", manifest.id, signature.declaration)),
        );
    }
    for row in import {
        let Some(field) = row["field"].as_str() else { return false };
        let Some(address) = row["address"].as_str() else { return false };
        if row["batch"] != batch
            || !row["previous"].is_null()
            || expected.remove(&(field, address.into())) != Some(row["value"].clone())
        {
            return false;
        }
    }
    if !expected.is_empty() {
        return false;
    }
    let tail = &lines[2 + import_count..];
    let edits: Vec<_> = tail.iter().filter(|row| row.get("field").is_some()).collect();
    let expected_count = 1 + usize::from(annotations["local_names"].as_array().is_some_and(|names| !names.is_empty()));
    if edits.len() != expected_count {
        return false;
    }
    let mut seen = BTreeSet::new();
    for row in &edits {
        let map = match row["field"].as_str() {
            Some("localtype") => "local_types",
            Some("localname") => "local_names",
            _ => return false,
        };
        if !seen.insert(map)
            || row["address"] != METHOD
            || !row["previous"].is_null()
            || row["value"] != annotations[map][0]["text"]
        {
            return false;
        }
    }
    // edit_variable may write name+type as one batch; no other headers, identity lines, or partial batches.
    match tail.len() - edits.len() {
        0 => edits.len() == 1 && edits[0].get("batch").is_none(),
        1 => tail.first().is_some_and(|header| {
            header["edits"].as_u64() == Some(edits.len() as u64)
                && header["batch"].as_str().is_some_and(|batch| edits.iter().all(|row| row["batch"] == batch))
        }),
        _ => false,
    }
}

async fn verify(
    connection: &Connection,
    owned: &OwnedFixture,
    baseline: &Baseline,
    consent: &Consent,
    checks: &mut Checks,
) -> Result<Value, &'static str> {
    checks.call(&connection.client, "enable_tools", json!({"groups": ["types"]})).await?;
    let annotations = checks.call(&connection.client, "list_annotations", json!({"path": owned.path})).await?;
    let manifest = proof(&annotations)?;
    let owner = detail(&consent.details, "DebugOwner").ok_or("Owner reviewed mapping missing")?;
    let cell = detail(&consent.details, "DebugCell").ok_or("Cell reviewed mapping missing")?;
    let owner_name = owner["emitted_name"].as_str().ok_or("Owner emitted name")?;
    let owner_native =
        checks.call(&connection.client, "get_type", json!({"path": owned.path, "name": owner_name})).await?;
    let cell_native =
        checks.call(&connection.client, "get_type", json!({"path": owned.path, "name": cell["emitted_name"]})).await?;
    let method = checks.call(&connection.client, "decompile", json!({"path": owned.path, "at": METHOD})).await?;
    let wrapper = checks.call(&connection.client, "decompile", json!({"path": owned.path, "at": WRAPPER})).await?;
    let (selector, parameter) = first_parameter(&method)?;
    let stable_storage = selector == baseline.selector;
    let typed = parameter["data_type"]["size"] == 8
        && parameter["data_type"]["name"].as_str().is_some_and(|name| owner_pointer(name, owner_name));
    let field_paths = actual_field_paths(
        method["code"].as_str().ok_or("native method C unavailable")?,
        parameter["name"].as_str().ok_or("native owner parameter name unavailable")?,
    );
    let layout = library_metadata(&owner_native) == Some(owner["native"].clone())
        && library_metadata(&cell_native) == Some(cell["native"].clone())
        && layouts(&owner_native, &cell_native);
    let maps = exact_state(&annotations, baseline, consent, &manifest)?;
    let log = owned.log()?;
    let persisted = Annotations::open_for_image_checked(
        owned.sidecar(),
        Some(Sha256::digest(std::fs::read(&owned.path).map_err(|_| "read native image identity")?).into()),
    )
    .map_err(|_| "checked annotation log replay")?;
    let log_match = persisted.warnings().is_empty()
        && MAPS.iter().all(|key| persisted_maps(&persisted)[*key] == annotations[*key])
        && exact_log(&log, &annotations, &manifest);
    let after = agreement(&wrapper, owner_name, &baseline.reference)?;
    let wrapper_verified = after["matched_components"] == 3 && after["exact_parameter_count"] == true;
    Ok(json!({
        "native_state_verified": stable_storage && typed && field_paths && layout && maps && log_match
            && wrapper_verified,
        "storage_unchanged": stable_storage, "native_owner_pointer": typed, "actual_native_field_paths": field_paths,
        "independent_field_metadata": layout, "exact_annotation_maps": maps, "checked_log_batch_verified": log_match,
        "annotation_log_sha256": digest(&log), "annotation_maps_sha256": digest(annotations.to_string().as_bytes()),
        "producer_alignment": {"owner": null, "cell": null},
        "native_fields": {"owner_size": owner_native["size"], "cell_stride": cell_native["size"],
            "bias_offset": native_field(&owner_native, "bias").map(|field| &field["offset"]),
            "next_offset": native_field(&owner_native, "next").map(|field| &field["offset"])},
        "wrapper_source_dwarf_agreement": after,
    }))
}

fn call_evidence(call: &ToolCall) -> Option<(Value, Value)> {
    if !call.invoked
        || call.is_error
        || call.input.truncated
        || call.output.truncated
        || call.input.original_bytes != call.input.text.len()
        || call.output.original_bytes != call.output.text.len()
    {
        return None;
    }
    let input = serde_json::from_str(&call.input.text).ok()?;
    let output: CallToolResult = serde_json::from_str(&call.output.text).ok()?;
    Some((input, json_result(&output).ok()?))
}

fn workflow(run: &AgentRun, scope: &Scope, selector: &VariableStorage) -> bool {
    let mut consent = Consent::default();
    let mut before = BTreeSet::new();
    let mut after = BTreeSet::new();
    let mut inspected = BTreeSet::new();
    let mut baseline_name = None::<String>;
    let mut edited_name = None::<String>;
    for call in &run.calls {
        let Some((input, receipt)) = call_evidence(call) else { return false };
        if !permitted(scope, &call.name, &input, &consent) {
            return false;
        }
        match call.name.as_str() {
            "import_debug_types" => {
                let valid = if input["apply"] == true {
                    before.len() == 2 && consent.record_apply(&input, &receipt)
                } else {
                    consent.record_preview(&receipt)
                };
                if !valid {
                    return false;
                }
            }
            "edit_variable" => {
                // Edit receipts have refreshed C and descriptors, not a decompile structure.signature.
                let Some(owner) = detail(&consent.details, "DebugOwner").and_then(|row| row["emitted_name"].as_str())
                else {
                    return false;
                };
                let Some(previous_name) = baseline_name.as_deref() else { return false };
                edited_name = edit_receipt_name(&input, &receipt, selector, owner, previous_name);
                if edited_name.is_none() {
                    return false;
                }
                consent.edited = true;
            }
            "decompile" => {
                if input["at"] == METHOD
                    && first_parameter(&receipt).map(|(storage, _)| storage) != Ok(selector.clone())
                {
                    return false;
                }
                let Some(address) = input["at"].as_str() else { return false };
                if address == METHOD && !consent.edited && consent.applied.is_none() {
                    baseline_name = first_parameter(&receipt)
                        .ok()
                        .and_then(|(_, descriptor)| descriptor["name"].as_str().map(str::to_owned));
                }
                if consent.edited {
                    if address == METHOD {
                        let Some(name) = edited_name.as_deref() else { return false };
                        if selected_parameter(&receipt, selector).is_none_or(|descriptor| descriptor["name"] != name)
                            || !receipt["code"].as_str().is_some_and(|code| actual_field_paths(code, name))
                        {
                            return false;
                        }
                    }
                    after.insert(address.to_owned());
                } else if consent.applied.is_none() {
                    before.insert(address.to_owned());
                }
            }
            "get_type" if consent.edited => {
                for original in ["DebugOwner", "DebugCell"] {
                    if let Some(row) = detail(&consent.details, original)
                        && input["name"] == row["emitted_name"]
                        && library_metadata(&receipt) == Some(row["native"].clone())
                    {
                        inspected.insert(original);
                    }
                }
            }
            _ => {}
        }
    }
    consent.complete() && consent.applied.is_some() && consent.edited && after.len() == 2 && inspected.len() == 2
}

fn accepted(run: &AgentRun, native: bool, workflow: bool, violation: bool) -> bool {
    run.model_source == Some(ModelSource::Provider)
        && native
        && workflow
        && !violation
        && run.model_turns <= 16
        && run.tool_calls <= 32
        && run.tool_errors == 0
        && run.model_errors == 0
        && matches!(&run.disposition, AgentDisposition::Answer { answer } if task().answer.matches(answer))
}

fn summary(run: &AgentRun) -> Value {
    let disposition = match run.disposition {
        AgentDisposition::Answer { .. } => "answer",
        AgentDisposition::Failed { .. } => "failed",
        AgentDisposition::Unrun { .. } => "unrun",
        AgentDisposition::Unknown { .. } => "unknown",
        AgentDisposition::Unsupported { .. } => "unsupported",
    };
    let required = task().required_capabilities;
    json!({"disposition": disposition, "model_source": run.model_source,
        "answer_contract_matches": matches!(&run.disposition, AgentDisposition::Answer { answer }
            if task().answer.matches(answer)), "model_turns": run.model_turns,
        "tool_requests": run.tool_requests, "tool_calls": run.tool_calls, "tool_errors": run.tool_errors,
        "model_errors": run.model_errors, "catalog_requests": run.catalog_requests,
        "catalog_tool_count": run.catalog_tool_count,
        "catalog_inventory": run.catalog_tool_names.iter().map(|names| json!({"complete": true,
            "tool_count": names.len(), "required_tools": required.iter().map(|name| json!({"name": name,
                "present": names.contains(name)})).collect::<Vec<_>>()})).collect::<Vec<_>>(),
        "usage": run.usage, "agent_wall_time_ms": run.wall_time_ms, "timing_boundary": run.timing_boundary})
}

async fn measure(owned: &OwnedFixture) -> Result<Value, &'static str> {
    task().validate().map_err(|_| "validate task contract")?;
    let first = Connection::open(owned).await?;
    let mut preparation = Checks::default();
    let prepared = prepare(&first, owned, &mut preparation).await;
    let baseline = match prepared {
        Ok(baseline) => baseline,
        Err(stage) => {
            first.close().await?;
            return Err(stage);
        }
    };
    let mut config = AgentConfig::new(MODEL);
    config.allow_debug_type_import = true;
    config.allow_variable_edits = true;
    config.max_turns = 16;
    config.max_tool_calls = 32;
    config.max_record_bytes = 65_536;
    config.max_retained_bytes = 2_000_000;
    let transport = match Anthropic::from_environment() {
        Some(transport) => transport,
        None => {
            first.close().await?;
            return Err("set ANTHROPIC_API_KEY for the Anthropic transport");
        }
    };
    let run = run_task(&first.client, Some(transport), ModelSource::Provider, &task(), &owned.path, &config).await;
    let checked_at = Instant::now();
    let consent = first.scope.consent.lock().unwrap().clone();
    let workflow = workflow(&run, &first.scope, &baseline.selector);
    let owner_name = detail(&consent.details, "DebugOwner").and_then(|row| row["emitted_name"].as_str());
    let before = owner_name.and_then(|name| agreement(&baseline.wrapper, name, &baseline.reference).ok());
    let mut checks = Checks::default();
    let initial = verify(&first, owned, &baseline, &consent, &mut checks)
        .await
        .unwrap_or_else(|stage| json!({"native_state_verified": false, "verification_error": stage}));
    first.close().await?;
    let reopened = Connection::open(owned).await?;
    let fresh = verify(&reopened, owned, &baseline, &consent, &mut checks)
        .await
        .unwrap_or_else(|stage| json!({"native_state_verified": false, "verification_error": stage}));
    reopened.close().await?;
    let stable = initial["annotation_log_sha256"].is_string()
        && initial["annotation_log_sha256"] == fresh["annotation_log_sha256"]
        && initial["annotation_maps_sha256"] == fresh["annotation_maps_sha256"];
    let bytes = owned.bytes_unchanged();
    let files = owned.exact_files();
    let native = initial["native_state_verified"] == true
        && fresh["native_state_verified"] == true
        && stable
        && bytes
        && files
        && preparation.errors == 0
        && checks.errors == 0;
    Ok(json!({"measurement": "phase1-6-debug-type-import",
        "design": "paired-owned-central-struct-reconstruction-not-blind-whole-program-re",
        "requested_model": MODEL, "transport": "anthropic", "fixture_sha256": IMAGE_SHA,
        "source_sha256": SOURCE_SHA, "source_recipe": "crates/rampage-eval/tasks/phase1-6/debug-types.toml",
        "method": METHOD, "wrapper": WRAPPER, "agent_summary": summary(&run),
        "task_contract": {"fields": ["owner_size", "cell_stride", "bias_offset", "next_offset",
            "typed_cells", "analyst_edits_preserved"], "manual_analyst_retype": true,
            "qualified_this_producer_signature_claimed": false},
        "preparation_tool_calls": preparation.calls, "preparation_tool_errors": preparation.errors,
        "preparation_native_checks": {"independent_dwarf_type_graph": 1, "compiler_layout_table": 1},
        "verifier_tool_calls": checks.calls, "verifier_tool_errors": checks.errors,
        "verification_wall_time_ms": checked_at.elapsed().as_millis(),
        "model_tool_workflow_verified": workflow, "permanent_scope_violation": consent.violation,
        "checked_import_receipt": {"review_sha256": consent.hash, "manifest_id": consent.manifest,
            "complete_detail_count": consent.details.len(), "producer_type_total": consent.total,
            "applied": consent.applied.as_ref().map(|receipt| &receipt["applied"]),
            "imported_types": consent.applied.as_ref().map(|receipt| &receipt["imported_types"]),
            "imported_signatures": consent.applied.as_ref().map(|receipt| &receipt["imported_signatures"])},
        "native_state_verified": native, "task_verified": accepted(&run, native, workflow, consent.violation),
        "initial_verification": initial, "fresh_server_verification": fresh, "stable_annotation_log": stable,
        "source_and_owned_image_bytes_unchanged": bytes, "no_extra_fixture_files": files,
        "wrapper_source_dwarf_comparison": {"before": before,
            "after": fresh["wrapper_source_dwarf_agreement"],
            "scope": "one wrapper, three components; not Phase-0 corpus improvement"},
        "baseline_method_field_paths": first_parameter(&baseline.method).ok().is_some_and(|(_, descriptor)| {
            descriptor["name"].as_str().zip(baseline.method["code"].as_str())
                .is_some_and(|(name, code)| actual_field_paths(code, name))
        }),
        "limits": {"max_turns": 16, "max_tool_calls": 32}, "target_executed": false,
        "permissions": {"allow_debug_type_import": true, "allow_variable_edits": true,
            "all_other_write_flags": false, "approved_debug_pdb": false,
            "task_scope_guard_rejects_set_types_and_signatures": true},
    }))
}

fn run() -> Result<Value, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let fixture =
        args.next().map(PathBuf::from).ok_or("usage: debug_type_import EXPLICIT_OWNED_ELF; model is fixed")?;
    if args.next().is_some() {
        return Err("usage: debug_type_import EXPLICIT_OWNED_ELF; model is fixed");
    }
    if digest(include_bytes!("../../../tests/fixtures/src/debug-types.cpp")) != SOURCE_SHA {
        return Err("compiled-in fixture source differs from pinned recipe");
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
    let executable_sha =
        std::env::current_exe().ok().and_then(|path| std::fs::read(path).ok()).map(|bytes| digest(&bytes));
    let mut output = run().unwrap_or_else(|stage| {
        json!({"measurement": "phase1-6-debug-type-import",
        "status": "failed", "stage": stage, "task_verified": false, "native_state_verified": false})
    });
    output["owned_output_wall_time_ms"] = json!(started.elapsed().as_millis());
    output["owned_output_timing_boundary"] =
        json!("fixture preparation through native/fresh verification, shutdown and cleanup");
    output["provenance"] = json!({"evaluator_binary_sha256": executable_sha,
        "collector_source_sha256": digest(include_bytes!("debug_type_import.rs")),
        "measured_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok())});
    let text = output.to_string();
    if text.len() > MAX_OUTPUT_BYTES {
        println!("{{\"status\":\"failed\",\"stage\":\"measurement output exceeds bound\"}}");
        std::process::exit(1);
    }
    println!("{text}");
    if output["task_verified"] != true {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_eval::parity_agent::RetainedText;

    const PATH: &str = "/owned/fixture.elf";

    fn selector() -> VariableStorage {
        serde_json::from_value(json!({"kind": "processor", "space": "register", "address": "0x38",
            "size": 8, "use_ranges": [{"space": "ram", "start": "0x20118f", "end": "0x20118f"}]}))
        .unwrap()
    }

    fn scope() -> Scope {
        Scope {
            inner: rampage_mcp::RampageServer::default(),
            path: PATH.into(),
            selector: Arc::new(Mutex::new(Some(selector()))),
            consent: Arc::new(Mutex::new(Consent::default())),
        }
    }

    fn decompilation(typed: bool) -> Value {
        let selector = selector();
        let mut storage = serde_json::to_value(&selector).unwrap();
        storage["symbol_offset"] = json!(0);
        storage["is_piece"] = json!(false);
        let ty = json!({"name": if typed { "ImportedOwner *" } else { "int8" }, "size": 8});
        json!({"structure": {"signature": {"return_type": {"name": "float8", "size": 8},
            "parameters": [{"name": "param_1", "data_type": ty, "storage": storage}]}},
            "variables": [{"kind": "parameter", "editable": true, "name": "param_1", "data_type": ty,
                "storage": selector, "key": serde_json::to_string(&selector).unwrap()}],
            "code": if typed { "return param_1->cells[i].level + param_1->cells[i].count + param_1->bias;" }
                else { "return *(double *)(param_1 + i * 16 + 8);" }})
    }

    fn preview() -> Value {
        json!({"applied": false, "review_sha256": "a".repeat(64), "manifest_id": "b".repeat(64),
            "total": 2, "applicable_types": 2, "applicable_signatures": 1, "preserved_signatures": 1,
            "imported_types": 0, "imported_signatures": 0, "offset": 0, "limit": 256, "next_offset": null,
            "details": [
                {"producer_type_id": "owner", "original_name": "DebugOwner", "emitted_name": "ImportedOwner",
                    "applicable": true, "producer": {"kind": {"kind": "struct"}},
                    "native": {"name": "ImportedOwner", "kind": "struct"}},
                {"producer_type_id": "cell", "original_name": "DebugCell", "emitted_name": "ImportedCell",
                    "applicable": true, "producer": {"kind": {"kind": "struct"}},
                    "native": {"name": "ImportedCell", "kind": "struct"}}]})
    }

    fn retained(text: String) -> RetainedText {
        RetainedText { original_bytes: text.len(), text, truncated: false }
    }

    fn good_edit_receipt() -> Value {
        let mut refreshed = decompilation(true);
        refreshed.as_object_mut().unwrap().remove("structure");
        json!({"address": METHOD, "storage": selector(), "edits": [{"field": "localtype", "changed": true}],
            "decompilation": refreshed})
    }

    fn framed_manifest_fixture() -> DebugTypesManifest {
        let origin = json!({"source": "dwarf", "unit": "fixture-cu", "index": 1});
        let producer: DebugTypeReport = serde_json::from_value(json!({
            "types": [
                {"id": "scalar-int4", "original_name": "int", "emitted_name": null,
                    "byte_size": 4, "alignment": null, "kind": {"kind": "scalar", "encoding": "signed",
                        "c_name": "int"}, "origin": origin, "unsupported": []},
                {"id": "record", "original_name": "FramedRecord", "emitted_name": null,
                    "byte_size": 4, "alignment": null, "kind": {"kind": "struct", "members": [
                        {"name": "value", "type_id": "scalar-int4", "byte_offset": 0,
                            "bitfield": null, "unsupported": []}]}, "origin": origin, "unsupported": []},
                {"id": "function-query", "original_name": null, "emitted_name": null,
                    "byte_size": null, "alignment": null, "kind": {"kind": "function", "convention": "normal",
                        "parameters": [], "return_type": "scalar-int4", "variadic": false},
                    "origin": origin, "unsupported": []}],
            "signatures": [{"address": WRAPPER, "name": "query", "type_id": "function-query",
                "origin": origin, "unsupported": []}],
            "provenance": {"source": "dwarf", "source_sha256": IMAGE_SHA, "pdb_guid": null, "pdb_age": null},
            "warnings": [], "limits": rampage_loaders::debug_types::DebugTypeLimits::default(),
        }))
        .unwrap();
        let native = serde_json::from_value(json!({"name": "FramedRecord", "kind": "struct", "size": 4,
            "alignment": 4, "incomplete": false, "packing": null, "fields": [
                {"name": "value", "offset": 0, "type_name": "int4", "size": 4}], "enum_values": [],
            "target": null, "array_length": null, "callback": null, "dependencies": [],
            "by_value_dependencies": []}))
        .unwrap();
        let declarations = "struct FramedRecord { int4 value; };".to_owned();
        let mut manifest = DebugTypesManifest {
            id: String::new(),
            review_sha256: "a".repeat(64),
            image_sha256: IMAGE_SHA.into(),
            specification_sha256: "c".repeat(64),
            options: json!({"platform": "Default", "compiler": null,
                "arm_be8": false}),
            language_id: "x86:LE:64:default".into(),
            organization: rampage_decompiler::DataOrganization { pointer: 8, int: 4, long: 8 },
            default_calling_convention: "fixture-native-model".into(),
            producer: serde_json::to_value(producer).unwrap(),
            library_names: vec!["FramedRecord".into()],
            declarations_sha256: digest(declarations.as_bytes()),
            declarations,
            expected_native_named_types: vec![native],
            signatures: vec![rampage_api::DebugTypesSignature {
                address: WRAPPER_ADDRESS,
                declaration: "int4 query(void);".into(),
                producer_type_id: "function-query".into(),
            }],
        };
        manifest.id = manifest_identity(&manifest).unwrap();
        manifest
    }

    fn framed_annotations(manifest: &DebugTypesManifest) -> Value {
        let library = rampage_api::annotations::encode_type_library(&[rampage_api::annotations::LibraryDeclaration {
            names: manifest.library_names.clone(),
            declarations: manifest.declarations.clone(),
            packing: None,
            source: Some(rampage_api::annotations::TypeLibrarySource {
                kind: "checked_debug_types".into(),
                identity: manifest.id.clone(),
            }),
        }])
        .unwrap();
        json!({"debug_types": [{"address": "0x0", "text": json!({"version": 1,
            "imports": [manifest]}).to_string()}], "type_library": [{"address": "0x0", "text": library}],
            "signatures": [{"address": WRAPPER, "text": format!("{SEAL}{}\n{}", manifest.id,
                manifest.signatures[0].declaration)}]})
    }

    #[test]
    fn manifest_framing_is_decoded_before_semantics_without_changing_wire_identity() {
        let manifest = framed_manifest_fixture();
        let wire = serde_json::to_value(&manifest).unwrap();
        assert!(wire["producer"].is_string());
        assert!(wire["expected_native_named_types"].is_string());
        let annotations = framed_annotations(&manifest);
        let original_text = annotations["debug_types"][0]["text"].as_str().unwrap().to_owned();
        let decoded = proof(&annotations).unwrap();
        assert!(decoded.producer.is_object());
        assert_eq!(decoded.producer["types"][1]["kind"]["members"][0]["name"], "value");
        assert_eq!(decoded.expected_native_named_types[0].fields[0].offset, 0);
        assert_eq!(decoded.default_calling_convention, "fixture-native-model");
        assert_eq!(serde_json::to_value(&decoded).unwrap(), wire);
        assert_eq!(manifest_identity(&decoded).unwrap(), manifest.id);
        assert_eq!(annotations["debug_types"][0]["text"], original_text);
        for field in ["producer", "expected_native_named_types"] {
            let mut unframed = wire.clone();
            unframed[field] = serde_json::from_str(wire[field].as_str().unwrap()).unwrap();
            assert!(decode_manifest_wire(&unframed).is_err(), "unframed {field}");
            let mut invalid = wire.clone();
            invalid[field] = json!("{not JSON");
            assert!(decode_manifest_wire(&invalid).is_err(), "invalid framed {field}");
        }
        let mut changed_model = decoded.clone();
        changed_model.default_calling_convention = "other-native-model".into();
        assert_ne!(manifest_identity(&changed_model).unwrap(), manifest.id);
    }

    fn receipt(name: &str, mut input: Value, result: Value) -> ToolCall {
        input["path"] = json!(PATH);
        ToolCall {
            name: name.into(),
            tool_use_id: "checked-receipt".into(),
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

    fn completed() -> AgentRun {
        let mut run = AgentRun::without_provider(&AgentConfig::new(MODEL));
        run.model_source = Some(ModelSource::Provider);
        run.disposition = AgentDisposition::Answer {
            answer: json!({"owner_size": 48, "cell_stride": 16,
            "bias_offset": 32, "next_offset": 40, "typed_cells": true, "analyst_edits_preserved": true}),
        };
        let preview = preview();
        let mut apply = preview.clone();
        apply["applied"] = json!(true);
        apply["imported_types"] = json!(2);
        apply["imported_signatures"] = json!(1);
        run.calls = vec![
            receipt("decompile", json!({"at": METHOD}), decompilation(false)),
            receipt("decompile", json!({"at": WRAPPER}), decompilation(false)),
            receipt("import_debug_types", json!({"limit": 256}), preview.clone()),
            receipt("import_debug_types", json!({"apply": true, "review_sha256": "a".repeat(64)}), apply),
            receipt(
                "edit_variable",
                json!({"at": METHOD, "storage": selector(), "data_type": "ImportedOwner *"}),
                good_edit_receipt(),
            ),
            receipt(
                "get_type",
                json!({"name": "ImportedOwner"}),
                json!({"name": "ImportedOwner", "kind": "struct",
                "scope": "library", "declaration": {"source": {"kind": "checked_debug_types"}}}),
            ),
            receipt(
                "get_type",
                json!({"name": "ImportedCell"}),
                json!({"name": "ImportedCell", "kind": "struct",
                "scope": "library", "declaration": {"source": {"kind": "checked_debug_types"}}}),
            ),
            receipt("decompile", json!({"at": METHOD}), decompilation(true)),
            receipt("decompile", json!({"at": WRAPPER}), decompilation(true)),
        ];
        run
    }

    #[test]
    fn baseline_selector_comes_from_signature_index_zero_not_descriptor_iteration_order() {
        let mut value = decompilation(false);
        let mut decoy = value["variables"][0].clone();
        decoy["storage"]["address"] = json!("0x30");
        value["variables"].as_array_mut().unwrap().insert(0, decoy);
        assert_eq!(first_parameter(&value).unwrap().0, selector());
        value["variables"][1]["storage"]["use_ranges"] = json!([]);
        assert!(first_parameter(&value).is_err());
        let edit_receipt = json!({"address": METHOD, "storage": selector(), "decompilation": decompilation(true)});
        assert!(first_parameter(&edit_receipt).is_err(), "edit receipt is not a decompile structure");
    }

    #[test]
    fn prepared_state_never_overrides_failed_policy_or_wrong_provider_outcome() {
        let mut run = completed();
        assert!(workflow(&run, &scope(), &selector()));
        assert!(accepted(&run, true, true, false));
        for disposition in [
            AgentDisposition::Failed { reason: "policy error after prepared state".into() },
            AgentDisposition::Unknown { reason: "incomplete".into() },
            AgentDisposition::Unrun { reason: "no provider".into() },
            AgentDisposition::Unsupported { reason: "missing".into() },
            AgentDisposition::Answer { answer: json!({"owner_size": 49}) },
        ] {
            run.disposition = disposition;
            assert!(!accepted(&run, true, true, false));
        }
        let mut run = completed();
        for source in [None, Some(ModelSource::Scripted)] {
            run.model_source = source;
            assert!(!accepted(&run, true, true, false));
        }
        let run = completed();
        for (native, workflow, violation) in [(false, true, false), (true, false, false), (true, true, true)] {
            assert!(!accepted(&run, native, workflow, violation));
        }
    }

    #[test]
    fn complete_ordered_receipts_are_required_and_out_of_task_mutations_are_permanent_failures() {
        for index in 0..completed().calls.len() {
            for mutation in 0..4 {
                let mut run = completed();
                match mutation {
                    0 => run.calls[index].input.truncated = true,
                    1 => run.calls[index].output.truncated = true,
                    2 => run.calls[index].is_error = true,
                    _ => run.calls[index].invoked = false,
                }
                assert!(!workflow(&run, &scope(), &selector()), "call {index} mutation {mutation}");
            }
        }
        for (left, right) in [(2, 3), (3, 4), (0, 8), (5, 2), (7, 0)] {
            let mut run = completed();
            run.calls.swap(left, right);
            assert!(!workflow(&run, &scope(), &selector()), "order {left}/{right}");
        }
        for (index, key, replacement) in [
            (2, "path", json!("/wrong-source.elf")),
            (3, "path", json!("/wrong-target.elf")),
            (3, "review_sha256", json!("c".repeat(64))),
            (4, "at", json!(WRAPPER)),
            (4, "data_type", json!("int8")),
            (4, "name", json!("other")),
            (
                4,
                "storage",
                json!({"kind": "processor", "space": "register", "address": "0x38",
                "size": 8, "use_ranges": []}),
            ),
        ] {
            let mut run = completed();
            let mut input: Value = serde_json::from_str(&run.calls[index].input.text).unwrap();
            input[key] = replacement;
            run.calls[index].input = retained(input.to_string());
            assert!(!workflow(&run, &scope(), &selector()), "wrong call {index} key {key}");
        }
        for name in ["set_types", "set_signature", "declare_types", "rename", "undo", "apply_data_type"] {
            let mut run = completed();
            run.calls.push(receipt(name, json!({"at": METHOD}), json!({})));
            assert!(!workflow(&run, &scope(), &selector()), "extra write {name}");
        }
    }

    #[test]
    fn consent_is_whole_plan_hash_bound_and_paged_details_cannot_be_skipped() {
        let mut consent = Consent::default();
        let mut first = preview();
        let second_row = first["details"].as_array_mut().unwrap().pop().unwrap();
        first["next_offset"] = json!(1);
        assert!(consent.record_preview(&first));
        assert!(!consent.complete());
        let mut applied = preview();
        applied["applied"] = json!(true);
        applied["imported_types"] = json!(2);
        applied["imported_signatures"] = json!(1);
        let input = json!({"apply": true, "review_sha256": "a".repeat(64)});
        assert!(!consent.record_apply(&input, &applied));
        let mut second = preview();
        second["offset"] = json!(1);
        second["details"] = json!([second_row]);
        assert!(consent.record_preview(&second));
        assert!(consent.complete());
        let mut wrong = applied.clone();
        wrong["manifest_id"] = json!("c".repeat(64));
        assert!(!consent.record_apply(&input, &wrong));
        assert!(!consent.record_apply(&json!({"apply": true, "review_sha256": "d".repeat(64)}), &applied));
        assert!(consent.record_apply(&input, &applied));
        assert!(!consent.record_apply(&input, &applied));
    }

    #[test]
    fn wrapper_agreement_scores_three_source_components_not_equal_width_guesses() {
        let reference = SourceSignature {
            function_id: "dwarf:exact-wrapper-id".into(),
            return_type: json!({"name": "float8", "size": 8}),
            index_type: json!({"name": "int4", "size": 4}),
            pointer_size: 8,
        };
        let mut wrapper = decompilation(true);
        wrapper["structure"]["signature"]["parameters"]
            .as_array_mut()
            .unwrap()
            .push(json!({"data_type": {"name": "int4", "size": 4}}));
        assert_eq!(agreement(&wrapper, "ImportedOwner", &reference).unwrap()["matched_components"], 3);
        wrapper["structure"]["signature"]["parameters"][1]["data_type"]["name"] = json!("uint4");
        assert_eq!(agreement(&wrapper, "ImportedOwner", &reference).unwrap()["matched_components"], 2);
        wrapper["structure"]["signature"]["parameters"][0]["data_type"]["name"] = json!("int8");
        assert_eq!(agreement(&wrapper, "ImportedOwner", &reference).unwrap()["matched_components"], 1);
        wrapper["structure"]["signature"]["return_type"]["name"] = json!("uint8");
        assert_eq!(agreement(&wrapper, "ImportedOwner", &reference).unwrap()["matched_components"], 0);
    }

    #[test]
    fn missing_proof_library_or_seal_is_not_evidence_and_c_text_is_not_layout_metadata() {
        let manifest = framed_manifest_fixture();
        let retained = framed_annotations(&manifest);
        assert!(proof(&retained).is_ok());
        assert!(retained_maps_present(&retained, &manifest.id, 1));
        for key in ["debug_types", "type_library", "signatures"] {
            let mut missing = retained.clone();
            missing[key] = json!([]);
            assert!(!retained_maps_present(&missing, &manifest.id, 1), "missing {key}");
        }
        let mut wrong = retained.clone();
        wrong["signatures"][0]["text"] = json!("float8 query(void);");
        assert!(!retained_maps_present(&wrong, &manifest.id, 1));
        assert!(!retained_maps_present(&retained, "other-id", 1));
        assert!(proof(&json!({"debug_types": []})).is_err());
        assert!(library_metadata(&json!({"scope": "library", "declaration": {}})).is_none());
        assert!(!layouts(&json!({"code": "cells[i].count + cells[i].level + bias"}), &json!({})));
        assert!(!actual_field_paths("return *(double *)(p + 8) + *(int *)p;", "owner"));
        assert!(!actual_field_paths("return owner->cells[i].level + owner->bias;", "owner"));
        assert!(actual_field_paths("return owner->cells[i].count + owner->cells[i].level + owner->bias;", "owner"));
        assert!(actual_field_paths(
            "cell = owner->cells + i; return cell->count + cell->level + owner->bias;",
            "owner"
        ));
        assert!(!actual_field_paths(
            "return owner->cells[i].count_extra + owner->cells[i].level + owner->bias;",
            "owner"
        ));
        assert!(!owner_pointer("const ImportedOwner *", "ImportedOwner"));
        assert!(!owner_pointer("ImportedOwner **", "ImportedOwner"));
        assert!(owner_pointer("struct ImportedOwner *", "ImportedOwner"));
    }

    #[test]
    fn field_relations_must_share_the_selected_owner_and_an_indexed_cell() {
        for code in [
            "return a->cells[i].count + a->cells[i].level + a->bias;",
            "return owner->cells[i].count + other->cells[i].level + owner->bias;",
            "return owner->cells[i].count + owner->cells[j].level + owner->bias;",
            "return owner->cells + b->count + c->level + owner->bias;",
            "/* return owner->cells[i].count + owner->cells[i].level + owner->bias; */ return 0;",
            "// owner->cells[i].count + owner->cells[i].level + owner->bias\nreturn 0;",
            "puts(\"owner->cells[i].count + owner->cells[i].level + owner->bias\");",
            "cell = other->cells + i; return cell->count + cell->level + owner->bias;",
            "cell = owner->cells; return cell->count + cell->level + owner->bias;",
            "cell = owner->cells + i; cell = other; return cell->count + cell->level + owner->bias;",
            "cell = owner->cells + i; x = other; return cell->count + x->level + owner->bias;",
            "cell = owner->cells + i; a = cell->count; cell = other; return cell->level + owner->bias;",
            "cell = owner->cells + i; a = cell->count; ++cell; return cell->level + owner->bias;",
            "cell = owner->cells + i; return cell->count + cell->level + other->bias;",
            "return unrelated->owner->cells[i].count + unrelated->owner->cells[i].level + owner->bias;",
        ] {
            assert!(!actual_field_paths(code, "owner"), "unrelated or non-code relation: {code}");
        }
        for code in [
            "return owner->cells[index & 1].count + owner->cells[index & 1].level + owner->bias;",
            "pDVar = owner->cells + (index & 1); return pDVar->level + pDVar->count + owner->bias;",
            "cellAlias = &owner->cells[index]; return cellAlias->count + cellAlias->level + owner->bias;",
            "cellAlias = &(owner->cells[index]); return cellAlias->count + cellAlias->level + owner->bias;",
            "cellAlias = owner /* ordinary comment */ ->cells + (long)(index & 1); \
                return cellAlias->count + cellAlias->level + owner->bias;",
        ] {
            assert!(actual_field_paths(code, "owner"), "valid fixture relation: {code}");
        }
    }

    #[test]
    fn direct_cell_evidence_tracks_index_mutations_without_invalidating_captured_cell_aliases() {
        for mutation in [
            "i++",
            "++i",
            "i--",
            "--i",
            "i = j",
            "i += 1",
            "i -= 1",
            "i *= 2",
            "i /= 2",
            "i %= 2",
            "i &= 1",
            "i |= 1",
            "i ^= 1",
            "i <<= 1",
            "i >>= 1",
            "(i)++",
            "++(i)",
            "((i)) = j",
            "(i) += 1",
        ] {
            let code = format!(
                "count = owner->cells[i].count; {mutation}; \
                return owner->cells[i].level + owner->bias;"
            );
            assert!(!actual_field_paths(&code, "owner"), "changed direct index: {mutation}");
            let captured = format!(
                "cell = owner->cells + i; count = cell->count; {mutation}; \
                return cell->level + owner->bias;"
            );
            assert!(actual_field_paths(&captured, "owner"), "unchanged captured cell: {mutation}");
        }
        for code in [
            "indexAlias = i; count = owner->cells[indexAlias].count; indexAlias = j; \
                return owner->cells[indexAlias].level + owner->bias;",
            "count = owner->cells[i & j].count; j++; return owner->cells[i & j].level + owner->bias;",
        ] {
            assert!(!actual_field_paths(code, "owner"), "changed index dependency: {code}");
        }
        for code in [
            "count = owner->cells[i].count; return owner->cells[i].level + owner->bias;",
            "count = owner->cells[i].count; unrelated = 7; count += unrelated; \
                return owner->cells[i].level + owner->bias;",
            "i++; count = owner->cells[i].count; return owner->cells[i].level + owner->bias;",
            "indexAlias = i; count = owner->cells[indexAlias].count; i++; \
                return owner->cells[indexAlias].level + owner->bias;",
            "cell = &owner->cells[i]; i++; return cell->count + cell->level + owner->bias;",
        ] {
            assert!(actual_field_paths(code, "owner"), "stable cell relation: {code}");
        }
    }

    #[test]
    fn workflow_requires_complete_refreshed_edit_receipt_even_when_later_inspections_are_good() {
        let good = good_edit_receipt();
        for (pointer, value) in [
            ("/edits", json!([])),
            ("/edits", json!([{"field": "localname", "changed": true}])),
            ("/edits/0/changed", json!(false)),
            ("/decompilation", json!({"code": "fresh native C"})),
            ("/decompilation/variables", json!([])),
            ("/decompilation/variables/0/data_type/name", json!("int8")),
            ("/decompilation/variables/0/data_type/size", json!(4)),
            ("/decompilation/variables/0/name", json!("unrelated")),
            ("/decompilation/variables/0/key", json!("stale key")),
            ("/decompilation/variables/0/storage/address", json!("0x30")),
            ("/decompilation/code", json!("return other->cells[i].count + other->cells[i].level + other->bias;")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            let mut run = completed();
            run.calls[4] = receipt(
                "edit_variable",
                json!({"at": METHOD, "storage": selector(), "data_type": "ImportedOwner *"}),
                bad,
            );
            assert!(!workflow(&run, &scope(), &selector()), "bad edit receipt {pointer}");
        }
        let input = json!({"at": METHOD, "storage": selector(), "data_type": "ImportedOwner *", "name": "owner"});
        assert!(edit_receipt_name(&input, &good, &selector(), "ImportedOwner", "param_1").is_none());
        let mut named = good.clone();
        named["edits"].as_array_mut().unwrap().push(json!({"field": "localname", "changed": true}));
        named["decompilation"]["variables"][0]["name"] = json!("owner");
        named["decompilation"]["code"] =
            json!("cell = owner->cells + (index & 1); return cell->count + cell->level + owner->bias;");
        assert_eq!(edit_receipt_name(&input, &named, &selector(), "ImportedOwner", "param_1"), Some("owner".into()));
        let unnamed = json!({"at": METHOD, "storage": selector(), "data_type": "ImportedOwner *"});
        assert!(edit_receipt_name(&unnamed, &named, &selector(), "ImportedOwner", "param_1").is_none());
        assert!(named["decompilation"].get("structure").is_none());
    }

    #[tokio::test]
    #[ignore = "requires direct ELF path in RAMPAGE_DEBUG_TYPE_FIXTURES; no build, model, or target execution"]
    async fn real_in_memory_preparation_and_checked_import_replay() {
        let original = PathBuf::from(
            std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES")
                .expect("set RAMPAGE_DEBUG_TYPE_FIXTURES to the direct recipe-pinned debug-cpp-x64.elf path"),
        );
        let owned = OwnedFixture::new(&original).unwrap();
        let first = Connection::open(&owned).await.unwrap();
        let mut checks = Checks::default();
        let baseline = prepare(&first, &owned, &mut checks).await.unwrap();
        let preview =
            checks.call(&first.client, "import_debug_types", json!({"path": owned.path, "limit": 256})).await.unwrap();
        assert!(first.scope.consent.lock().unwrap().complete());
        assert!(owned.log().unwrap().is_empty());
        checks
            .call(
                &first.client,
                "import_debug_types",
                json!({"path": owned.path, "apply": true,
            "review_sha256": preview["review_sha256"], "limit": 1}),
            )
            .await
            .unwrap();
        let owner = detail(preview["details"].as_array().unwrap(), "DebugOwner").unwrap()["emitted_name"]
            .as_str()
            .unwrap()
            .to_owned();
        let edit_input = json!({"path": owned.path, "at": METHOD,
            "storage": baseline.selector, "data_type": format!("{owner} *"), "name": "owner"});
        let edit = checks.call(&first.client, "edit_variable", edit_input.clone()).await.unwrap();
        let previous_name = first_parameter(&baseline.method).unwrap().1["name"].as_str().unwrap();
        assert_eq!(
            edit_receipt_name(&edit_input, &edit, &baseline.selector, &owner, previous_name),
            Some("owner".into())
        );
        let consent = first.scope.consent.lock().unwrap().clone();
        let initial = verify(&first, &owned, &baseline, &consent, &mut checks).await.unwrap();
        assert_eq!(initial["native_state_verified"], true, "{initial}");
        let annotations = checks.call(&first.client, "list_annotations", json!({"path": owned.path})).await.unwrap();
        let manifest = proof(&annotations).unwrap();
        for key in ["debug_types", "type_library", "signatures"] {
            let mut wrong = annotations.clone();
            wrong[key] = json!([]);
            assert!(!exact_state(&wrong, &baseline, &consent, &manifest).unwrap_or(false), "missing {key}");
        }
        let mut wrong = annotations.clone();
        wrong["comments"] = json!([{"address": METHOD, "text": "extra"}]);
        assert!(!exact_state(&wrong, &baseline, &consent, &manifest).unwrap());
        let mut wrong = manifest.clone();
        wrong.image_sha256 = "0".repeat(64);
        assert!(!exact_state(&annotations, &baseline, &consent, &wrong).unwrap());
        let log = owned.log().unwrap();
        first.close().await.unwrap();
        let fresh = Connection::open(&owned).await.unwrap();
        let replayed = verify(&fresh, &owned, &baseline, &consent, &mut checks).await.unwrap();
        assert_eq!(replayed["native_state_verified"], true);
        assert_eq!(initial["annotation_log_sha256"], replayed["annotation_log_sha256"]);
        assert_eq!(owned.log().unwrap(), log);
        assert!(owned.bytes_unchanged());
        assert!(owned.exact_files());
        fresh.close().await.unwrap();
    }
}
