//! The analysis tools AI models call, shared by the MCP server and the UI's assistant: each has a name, a
//! description, a JSON schema for its input, and a handler that runs it against a project.

use crate::workflows::{WORKFLOWS, Workflow};
use crate::{ApiError, FunctionsQuery, ListQuery, Packs, Project, StringsQuery, WorkflowReport, XrefQuery};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Results longer than this are cut, so that one large answer cannot crowd out the conversation. Workflow reports
/// and PDB import receipts fit themselves below it instead, preserving valid JSON and whole-operation status.
const MAX_RESULT_CHARS: usize = 60_000;
const DEFAULT_PAGE: usize = 100;
const MAX_PDB_DETAIL_BYTES: usize = 4096;
const MAX_PDB_ERROR_BYTES: usize = 1024;

type Handler = Box<dyn Fn(&Project, Value) -> Result<Value, String> + Send + Sync>;

/// A set of related tools. MCP clients see the core group first and enable the others when they need them, so the
/// tool list stays short as it grows; the UI's assistant offers every tool of every group that works on the open
/// binary ([`tools`], not the [`file_tools`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Core,
    Detection,
    Types,
    Runtime,
    Diagnostics,
    DotNet,
    Carve,
}

impl Group {
    pub const ALL: [Group; 7] =
        [Group::Core, Group::Detection, Group::Types, Group::Runtime, Group::Diagnostics, Group::DotNet, Group::Carve];

    pub fn name(self) -> &'static str {
        match self {
            Group::Core => "core",
            Group::Detection => "detection",
            Group::Types => "types",
            Group::Runtime => "runtime",
            Group::Diagnostics => "diagnostics",
            Group::DotNet => "dotnet",
            Group::Carve => "carve",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Group::Core => {
                "Layout, functions, disassembly, decompilation, xrefs, strings, imports, exports, annotations with \
                 undo/redo, and the guided workflows (triage_report, find_main, network_surface, \
                 persistence_surface, string_decoding, diff_builds)."
            }
            Group::Detection => {
                "Heuristic databases and rules: packer/compiler detection, library-function signatures (identify and \
                 build), capability tags, YARA and capa rules, and the find_crypto workflow."
            }
            Group::Types => {
                "C signatures, type declarations and globals, embedded DWARF signature import, demangled names and \
                 Itanium vtable/RTTI evidence, and explicit identity-matched PDB function-name import."
            }
            Group::Runtime => {
                "Memory snapshot evidence: captured pointer slots, pointer comparisons across captures, runtime \
                 bytes against the original Mach-O, ARM64 indirect-branch windows."
            }
            Group::Diagnostics => "Decode coverage and unreliable-code evidence, and explicit ARM64 jump-table checks.",
            Group::DotNet => "Managed (.NET) metadata (types, methods, properties, P/Invokes, attributes) and CIL.",
            Group::Carve => "Scan any file (firmware, installer, archive) for embedded executables and containers.",
        }
    }
}

impl std::str::FromStr for Group {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        Group::ALL.into_iter().find(|group| group.name() == text).ok_or_else(|| {
            let names: Vec<&str> = Group::ALL.iter().map(|group| group.name()).collect();
            format!("unknown tool group `{text}` (groups: {})", names.join(", "))
        })
    }
}

pub struct Tool {
    pub group: Group,
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    /// Acts on a person's view of the binary (`show_address`), so only clients with one offer it.
    pub interactive: bool,
    pub effect: Effect,
    /// Whether MCP should open and refresh the persistent annotation sidecar before calling this tool.
    pub reads_annotations: bool,
    handler: Handler,
}

impl Tool {
    fn without_annotations(self) -> Self {
        Self { reads_annotations: false, ..self }
    }
    fn interactive(self) -> Self {
        Self { interactive: true, effect: Effect::ShowAddress, ..self }
    }

    fn annotates(self) -> Self {
        Self { effect: Effect::Annotations, ..self }
    }

    /// The tool as the Anthropic Messages API describes one.
    pub fn definition(&self) -> Value {
        serde_json::json!({ "name": self.name, "description": self.description, "input_schema": self.input_schema })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Effect {
    #[default]
    None,
    Annotations,
    ShowAddress,
}

/// The JSON schema of a tool taking arguments `A`.
pub(crate) fn schema<A: JsonSchema>() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(A)).unwrap_or_default();
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("title");
        object.entry("properties").or_insert_with(|| serde_json::json!({}));
    }
    schema
}

fn tool<A, R>(
    group: Group,
    name: &'static str,
    description: &'static str,
    run: fn(&Project, A) -> Result<R, ApiError>,
) -> Tool
where
    A: DeserializeOwned + JsonSchema + 'static,
    R: Serialize + 'static,
{
    let handler = move |project: &Project, input: Value| -> Result<Value, String> {
        let arguments: A = arguments(input)?;
        let result = run(project, arguments).map_err(|error| error_chain(&error))?;
        serde_json::to_value(result).map_err(|error| error.to_string())
    };
    Tool {
        group,
        name,
        description,
        input_schema: schema::<A>(),
        interactive: false,
        effect: Effect::None,
        reads_annotations: true,
        handler: Box::new(handler),
    }
}

/// A tool's JSON `input` read as arguments `A`, or an error the model can read.
pub(crate) fn arguments<A: DeserializeOwned>(input: Value) -> Result<A, String> {
    serde_json::from_value(input).map_err(|error| format!("invalid arguments: {error}"))
}

fn error_chain(error: &ApiError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// A tool that works without a loaded binary: on a file path no loader needs to open first (carve), or on the
/// data packs in effect alone (list_packs).
pub struct FileTool {
    pub group: Group,
    pub name: &'static str,
    pub description: &'static str,
    /// The whole input schema; a tool taking a file has a required `path` argument.
    pub input_schema: Value,
    handler: fn(&Packs, Value) -> Result<Value, String>,
}

impl FileTool {
    /// Runs the tool with `input` and the `packs` in effect, returning its JSON result or an error the caller can
    /// read.
    pub fn call(&self, packs: &Packs, input: Value) -> Result<Value, String> {
        (self.handler)(packs, input)
    }
}

#[derive(serde::Deserialize, JsonSchema)]
struct CarveArgs {
    /// Path to the file to scan; any regular file, not only one rampage can load.
    path: String,
    /// Candidates to skip, for paging.
    offset: Option<usize>,
    /// Candidates per page (default and at most 100).
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct QueryDebuggerArgs {
    /// Explicit absolute path of an operator-started LLDB Unix socket in a same-user 0700 directory.
    socket: std::path::PathBuf,
    /// Version 1 read-only query. Copy the returned token into expected_token for subsequent operations.
    request: crate::DebuggerRequest,
    /// End-to-end timeout in milliseconds (1..=30000, default 3000).
    #[schemars(range(min = 1, max = 30000))]
    timeout_ms: Option<u64>,
}

/// Every tool that works without a loaded binary.
pub fn file_tools() -> Vec<FileTool> {
    vec![
        FileTool {
            group: Group::Runtime,
            name: "query_debugger",
            description: "Read an existing authorized stopped LLDB session through an explicitly supplied local Unix \
                          socket. The operator must start rampage-query-serve first. Only describe_session, \
                          list_modules, list_threads, read_registers, read_memory and resolve_module_address \
                          (explicit module UUID plus file address) are permitted; no attach, launch, \
                          resume, expressions, writes or process commands. Requires socket and a version 1 request; \
                          all but initial describe_session require expected_token from a prior response. No binary \
                          path, discovery, environment fallback or sidecar access. Responses preserve stop evidence \
                          and revalidated-non-atomic observations; content hashes are not authenticity or atomicity \
                          proofs. Reduce page size or memory size if a response exceeds the tool's 60000-byte budget.",
            input_schema: schema::<QueryDebuggerArgs>(),
            handler: |_, input| {
                let started = std::time::Instant::now();
                if input.to_string().len() > crate::MAX_DEBUGGER_REQUEST_BYTES + 1024 {
                    return Err("debugger arguments exceed the input byte limit".to_owned());
                }
                let mut args: QueryDebuggerArgs = arguments(input)?;
                let timeout = args.timeout_ms.unwrap_or(3000);
                if !(1..=30000).contains(&timeout) {
                    return Err("timeout_ms must be in 1..=30000".to_owned());
                }
                args.request.validate().map_err(|error| error_chain(&error))?;
                args.request.cap_response_budget(MAX_RESULT_CHARS);
                let deadline = started + std::time::Duration::from_millis(timeout);
                let response = crate::query_debugger(&args.socket, &args.request, deadline)
                    .map_err(|error| error_chain(&error))?;
                let output = serde_json::to_value(response).map_err(|error| error.to_string())?;
                if output.to_string().len() > MAX_RESULT_CHARS {
                    return Err("debugger result exceeds tool output limit; request a smaller page or range".to_owned());
                }
                Ok(output)
            },
        },
        FileTool {
            group: Group::Carve,
            name: "carve",
            description: "Scan any file (firmware, installer, dump, archive) for embedded executables and containers: \
                      ELF, PE, Mach-O (thin and universal), zip, gzip, xz, zstd, LZMA, squashfs, cpio, uImage and \
                      Android boot images. Each candidate has its offset, kind, validated header facts (arch, bits, \
                      endianness, declared size) and an extent estimated from headers, with confidence validated or \
                      magic_only. Read-only and bounded: nothing is extracted, decompressed or executed, and the \
                      scan stops at 4096 candidates, saying so. Paginated with offset/limit: each page scans only \
                      as far as the candidate after it and reports `more` (whether another page follows) rather \
                      than a total.",
            input_schema: schema::<CarveArgs>(),
            handler: |_, input| {
                let args: CarveArgs =
                    serde_json::from_value(input).map_err(|error| format!("invalid arguments: {error}"))?;
                let page = crate::carve_page(std::path::Path::new(&args.path), args.offset, args.limit)
                    .map_err(|error| error_chain(&error))?;
                serde_json::to_value(page).map_err(|error| error.to_string())
            },
        },
        FileTool {
            group: Group::Detection,
            name: "list_packs",
            description: "List the heuristic-database packs in effect, in precedence order: every data pack loaded \
                          with --pack or RAMPAGE_PACKS (earlier ones first), then the built-in one (bundled \
                          signatures, tool and crypto-constant databases), which applies last. Each has its name, \
                          version, SPDX licence, source (provenance) and description, and each content its kind, \
                          path and status (loaded, error or unsupported) with a detail saying what loaded or why not. \
                          Takes no arguments.",
            input_schema: schema::<Nothing>(),
            handler: |packs, input| {
                serde_json::from_value::<Nothing>(input).map_err(|error| format!("invalid arguments: {error}"))?;
                serde_json::to_value(packs.listing()).map_err(|error| error.to_string())
            },
        },
    ]
}

/// No arguments.
#[derive(serde::Deserialize, JsonSchema)]
pub struct Nothing {}

#[derive(serde::Deserialize, JsonSchema)]
pub struct At {
    /// An address (`0x401000`) or a name: symbol, export, import, user name, or `sub_<hex>`.
    pub at: String,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DebugImportArgs {
    #[serde(default)]
    apply: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PdbImportArgs {
    /// Explicit PDB file path. No automatic sidecar, recorded path, symbol server or download is used.
    pdb: std::path::PathBuf,
    /// Persist eligible names as one undoable batch; omitted or false only previews.
    #[serde(default)]
    apply: bool,
    /// Details to skip: function rows first, then warnings. Does not select which names are applied.
    offset: Option<usize>,
    /// Details per page (default 100, 1..=1000); the byte budget can shorten the page further.
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<usize>,
}

fn pdb_receipt(apply_requested: Option<bool>) -> Value {
    serde_json::json!({
        "ok": false,
        "status": "rejected",
        "apply_requested": apply_requested,
        "whole_apply_succeeded": false,
        "identity": null,
        "preview_total": null,
        "applied_total": 0,
        "preserved_total": null,
        "warnings_total": null,
        "details_total": null,
        "offset": 0,
        "limit": 0,
        "details": [],
        "more": false,
        "next_offset": null,
        "byte_capped": false,
        "error": null,
        "error_truncated": false,
    })
}

fn pdb_detail_capacity() -> Result<usize, ApiError> {
    // Reserve the largest receipt, including an escaped error, before any annotation action.
    let mut envelope = pdb_receipt(Some(false));
    envelope["identity"] = serde_json::json!({ "guid": "f".repeat(32), "age": u32::MAX });
    for field in [
        "preview_total",
        "applied_total",
        "preserved_total",
        "warnings_total",
        "details_total",
        "offset",
        "limit",
        "next_offset",
    ] {
        envelope[field] = serde_json::json!(usize::MAX);
    }
    envelope["error"] = Value::String("\0".repeat(MAX_PDB_ERROR_BYTES));
    MAX_RESULT_CHARS
        .checked_sub(envelope.to_string().len())
        .filter(|capacity| *capacity >= 6 * MAX_PDB_DETAIL_BYTES + 512)
        .ok_or_else(|| ApiError::Invalid("PDB receipt cannot fit the tool output budget; nothing imported".to_owned()))
}

fn pdb_bounded_text(text: &str, budget: usize) -> &str {
    let mut end = text.len().min(budget);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A bounded JSON failure receipt, also used for MCP failures before the shared PDB tool can run.
pub fn pdb_import_error(message: &str, apply_requested: Option<bool>) -> String {
    let mut receipt = pdb_receipt(apply_requested);
    let bounded = pdb_bounded_text(message, MAX_PDB_ERROR_BYTES);
    receipt["error"] = Value::String(bounded.to_owned());
    receipt["error_truncated"] = Value::Bool(bounded.len() != message.len());
    receipt.to_string()
}

fn import_pdb_page(project: &Project, args: PdbImportArgs) -> Result<Value, ApiError> {
    let limit = args.limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=1000).contains(&limit) {
        return Err(ApiError::Invalid("limit must be in 1..=1000; nothing imported".to_owned()));
    }
    let capacity = pdb_detail_capacity()?;
    let imported = project.import_pdb_names(&args.pdb, args.apply)?;
    Ok(pdb_import_page(imported, args.apply, args.offset.unwrap_or(0), limit, capacity))
}

fn pdb_import_page(imported: crate::PdbImport, apply: bool, offset: usize, limit: usize, capacity: usize) -> Value {
    let mut receipt = pdb_receipt(Some(apply));
    receipt["ok"] = Value::Bool(true);
    receipt["status"] = Value::String(if apply { "applied" } else { "preview" }.to_owned());
    receipt["whole_apply_succeeded"] = Value::Bool(apply);
    receipt["identity"] = imported.preview.identity.as_ref().map_or(
        Value::Null,
        |identity| serde_json::json!({ "guid": rampage_arch::hex::bytes(&identity.guid), "age": identity.age }),
    );
    let preview_total = imported.preview.functions.len();
    let warnings_total = imported.preview.warnings.len();
    let details_total = preview_total + warnings_total;
    let offset = offset.min(details_total);
    receipt["preview_total"] = serde_json::json!(preview_total);
    receipt["applied_total"] = serde_json::json!(imported.applied.len());
    receipt["preserved_total"] = serde_json::json!(imported.preserved.len());
    receipt["warnings_total"] = serde_json::json!(warnings_total);
    receipt["details_total"] = serde_json::json!(details_total);
    receipt["offset"] = serde_json::json!(offset);
    receipt["limit"] = serde_json::json!(limit);
    let applied: std::collections::BTreeSet<_> = imported.applied.into_iter().collect();
    let preserved: std::collections::BTreeSet<_> = imported.preserved.into_iter().collect();
    let mut details = Vec::new();
    let mut bytes = 0;
    for index in offset..details_total.min(offset.saturating_add(limit)) {
        let detail = if let Some(function) = imported.preview.functions.get(index) {
            let status = if applied.contains(&function.address) {
                "applied"
            } else if preserved.contains(&function.address) {
                "preserved"
            } else {
                "eligible"
            };
            let name = pdb_bounded_text(&function.name, MAX_PDB_DETAIL_BYTES);
            serde_json::json!({
                "kind": "function", "address": format!("{:#x}", function.address), "name": name,
                "name_bytes": function.name.len(), "name_truncated": name.len() != function.name.len(),
                "status": status,
            })
        } else {
            let warning = &imported.preview.warnings[index - preview_total];
            let text = pdb_bounded_text(warning, MAX_PDB_DETAIL_BYTES);
            serde_json::json!({
                "kind": "warning", "text": text, "text_bytes": warning.len(),
                "text_truncated": text.len() != warning.len(),
            })
        };
        let size = detail.to_string().len() + usize::from(!details.is_empty());
        if size > capacity - bytes {
            receipt["byte_capped"] = Value::Bool(true);
            break;
        }
        bytes += size;
        details.push(detail);
    }
    let next = offset + details.len();
    let more = next < details_total;
    receipt["details"] = Value::Array(details);
    receipt["more"] = Value::Bool(more);
    receipt["next_offset"] = if more { serde_json::json!(next) } else { Value::Null };
    receipt
}

#[derive(serde::Deserialize, JsonSchema)]
struct SignatureBuildArgs {
    /// File path to write the signature database (JSON). Required: the database is too large to return inline.
    output: String,
}

#[derive(serde::Deserialize, JsonSchema)]
struct IdentifyArgs {
    /// Optional file path of a signature database built with build_signatures, applied first: before the loaded
    /// data packs' databases and the bundled starter database. Omit it to match against those alone.
    #[serde(default)]
    database: Option<String>,
    /// Leave out the bundled starter database, matching against `database` and the data packs' databases only
    /// (needs at least one of them).
    #[serde(default)]
    no_bundled: bool,
    /// Persist matched names for still-unnamed functions as user names (never overwriting existing names).
    #[serde(default)]
    apply: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DotNetIlArgs {
    /// A MethodDef token (`0x0600000d`) or `Namespace.Type::Name` (nested types as `Outer/Inner`) naming one
    /// method; dotnet_metadata lists them.
    method: String,
    /// Instructions to skip, for paging: an instruction index, not an IL byte offset (use `at` for those).
    #[serde(default)]
    offset: Option<usize>,
    /// Instructions per page (default 100, at most 1000).
    #[serde(default)]
    limit: Option<usize>,
    /// Start the page at the instruction containing this IL byte offset instead of at `offset`: an `IL_0042`
    /// label, `0x42`, or decimal.
    #[serde(default)]
    at: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DotNetArgs {
    /// The list to page: `types` (default), `pinvokes`, `attributes` or `resources`.
    #[serde(default)]
    list: crate::DotNetList,
    /// Case-insensitive filter on the selected list: types whose full name (Namespace.Name) or a method name
    /// or property/event name contains this text, P/Invoke imports by method/DLL/import, attributes by type or
    /// target, resources by name or linked File/AssemblyRef name.
    #[serde(default)]
    contains: Option<String>,
    /// With `list: attributes`, only the attributes applied to this metadata token (e.g. 0x06000001 for
    /// MethodDef row 1, 0x20000001 for the assembly).
    #[serde(default)]
    parent_token: Option<u32>,
    /// Entries of the selected list to skip, for paging.
    #[serde(default)]
    offset: Option<usize>,
    /// Entries per page (default 100, at most 1000).
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DetectToolsArgs {
    /// Optional file path of a user-supplied PeID `userdb.txt`, overlaid on the bundled starter database.
    #[serde(default)]
    peid: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct YaraArgs {
    /// YARA rule source text to compile and run against the binary's image bytes. Optional when a loaded data
    /// pack holds YARA rules; those always run too.
    #[serde(default)]
    rules: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct CapaArgs {
    /// Path to a directory of Mandiant capa rule YAML files (only the file-scope feature subset is evaluated).
    /// Optional when a loaded data pack holds capa rules; those are always evaluated too.
    #[serde(default)]
    rules_dir: Option<String>,
}

/// A YARA scan's matches with the data-pack problems bearing on YARA rules.
#[derive(Serialize)]
struct YaraScan {
    matches: Vec<rampage_yara::YaraMatch>,
    warnings: Vec<String>,
}

/// A capa evaluation's capabilities with the data-pack problems bearing on capa rules.
#[derive(Serialize)]
struct CapaScan {
    capabilities: Vec<rampage_capabilities::Capability>,
    warnings: Vec<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DiscardUndoArgs {
    /// Drop the step even though undo could still revert it (no other client's edit blocks it).
    #[serde(default)]
    force: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
struct DiagnosticsArgs {
    /// Explicitly run whole-program discovery; otherwise reuse cached discovery or sample bytes only.
    #[serde(default)]
    include_discovery: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
struct RuntimeRangeArgs {
    /// Explicit runtime hexadecimal address, not a symbol or annotation alias.
    address: String,
    /// Nonzero byte count; all ranges together must fit within one MiB.
    size: u64,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RuntimeComparisonArgs {
    /// Explicit original Mach-O path; paths recorded in capture metadata are never opened.
    original: std::path::PathBuf,
    /// Original image's file offset (integer, decimal or hex string); applies only to the explicit original path.
    original_image_offset: Option<crate::FileOffset>,
    /// Original image's byte length (integer, decimal or hex string); requires original_image_offset.
    original_image_length: Option<crate::FileOffset>,
    /// UUID of the recorded module; original UUID, architecture and header base must agree.
    module: String,
    /// 1–256 non-overlapping explicit runtime ranges.
    ranges: Vec<RuntimeRangeArgs>,
    /// Comparison spans to skip; totals always cover every requested range.
    offset: Option<usize>,
    /// Span page size (default 100, at most 200).
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct BranchObservationArgs {
    /// Explicit hexadecimal start of a straight-line ARM64 window, at most 64 instructions.
    start: String,
    /// Explicit hexadecimal address of the indirect branch ending the window.
    at: String,
}

#[derive(serde::Deserialize, JsonSchema)]
struct PointerComparisonArgs {
    /// Explicit second capture path, opened fresh without an annotation sidecar.
    other: std::path::PathBuf,
    /// Explicit hexadecimal slot address in the current capture (analyst's "before").
    at: String,
    /// Explicit hexadecimal slot address in the second capture (analyst's "after").
    other_at: String,
}

#[derive(Serialize)]
struct RuntimeComparisonPage {
    #[serde(flatten)]
    comparison: crate::RuntimeComparison,
    spans_total: usize,
    offset: usize,
}

fn compare_runtime_page(project: &Project, args: RuntimeComparisonArgs) -> Result<RuntimeComparisonPage, ApiError> {
    let original_image = match (args.original_image_offset, args.original_image_length) {
        (Some(offset), length) => Some(rampage_loaders::ImageAt::new(offset.0, length.map(|length| length.0))),
        (None, Some(_)) => {
            return Err(ApiError::Invalid("original_image_length needs original_image_offset".to_owned()));
        }
        (None, None) => None,
    };
    if args.ranges.is_empty() || args.ranges.len() > 256 {
        return Err(ApiError::Invalid("select 1..256 runtime comparison ranges".to_owned()));
    }
    let ranges = args
        .ranges
        .iter()
        .map(|range| {
            let address = rampage_loaders::snapshot::address(&range.address)
                .map_err(|error| ApiError::Invalid(error.to_string()))?;
            Ok(crate::RuntimeRange { address, size: range.size })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let original = rampage_loaders::Binary::open_image(&args.original, original_image, Some(project.binary.arch))
        .map_err(|source| ApiError::Load { path: args.original, source })?;
    let mut comparison = project.compare_runtime_bytes(&args.module, &original, &ranges)?;
    let spans_total = comparison.spans.len();
    let offset = args.offset.unwrap_or(0).min(spans_total);
    comparison.spans = comparison.spans.into_iter().skip(offset).take(args.limit.unwrap_or(100).min(200)).collect();
    Ok(RuntimeComparisonPage { comparison, spans_total, offset })
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct JumpTableArgs {
    pub at: String,
    /// Exact analyst-specified entry count (1–4096).
    pub count: usize,
    /// Base for signed 32-bit relative entries; absent selects absolute 64-bit pointers.
    pub relative_base: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Start address or name; defaults to the entry point.
    pub at: Option<String>,
    /// Number of instructions (default 40, at most 1000).
    pub count: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct XrefsArgs {
    /// List references to this address or name (callers, readers).
    pub to: Option<String>,
    /// List references made by the function at this address or name.
    pub from: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return (default 100).
    pub limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct RenameArgs {
    /// The address or current name to rename.
    pub at: String,
    /// The new name, an identifier not used elsewhere. Required unless `clear` is set.
    pub name: Option<String>,
    /// Remove the user's name instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct CommentArgs {
    /// The address or name to comment.
    pub at: String,
    /// The comment. Required unless `clear` is set.
    pub text: Option<String>,
    /// Remove the comment instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
struct AnnotateBatchArgs {
    /// At most 1000 entries, each `at` plus `name`, `comment` or both.
    entries: Vec<crate::BatchEntry>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct CheckNamesArgs {
    /// At most 1000 candidate names.
    names: Vec<String>,
}

/// The value an edit sets: `value`, or nothing with `clear`; exactly one must be given, so that a forgotten
/// argument never erases a name.
fn edit_value(value: Option<String>, clear: bool, what: &str) -> Result<Option<String>, ApiError> {
    match (value, clear) {
        (Some(value), false) => Ok(Some(value)),
        (None, true) => Ok(None),
        _ => Err(ApiError::Invalid(format!("pass either `{what}` or `clear: true`"))),
    }
}

/// A workflow report shrunk to fit a tool result.
fn fitted(report: Result<WorkflowReport, ApiError>) -> Result<WorkflowReport, ApiError> {
    report.map(|mut report| {
        report.fit(MAX_RESULT_CHARS);
        report
    })
}

fn page_limit(limit: Option<usize>) -> Option<usize> {
    Some(limit.unwrap_or(DEFAULT_PAGE).min(1000))
}

/// Every tool, in the order the model sees them.
pub fn tools() -> Vec<Tool> {
    let mut tools = vec![
        tool(
            Group::Diagnostics,
            "inspect_jump_table",
            "Validate explicitly selected immutable ARM64 jump-table entries; \
             does not guess index ranges or CFG edges.",
            |project, args: JumpTableArgs| {
                project.inspect_jump_table(
                    project.resolve(&args.at)?,
                    args.count,
                    args.relative_base.as_deref().map(|base| project.resolve(base)).transpose()?,
                )
            },
        ),
        tool(
            Group::Core,
            "function_summary",
            "Structural function summary: decoded CFG, named references and explicit limitations. Not a decompiler.",
            |project, arguments: At| project.function_summary(project.resolve(&arguments.at)?),
        ),
        tool(
            Group::Core,
            "decompile",
            "Decompile the function at an address or name to C, using the embedded Ghidra decompiler. This is \
             real decompilation (types, control flow, expressions), the best starting point for understanding a \
              function. Processor specs are bundled; if unavailable, use function_summary.",
            |project, arguments: At| project.decompile(project.resolve(&arguments.at)?),
        ),
        tool(
            Group::Types,
            "language_metadata",
            "Demangled symbols, named Itanium vtables/RTTI, Objective-C selector strings and Objective-C classes and \
             categories (superclasses, methods with implementations, ivars, properties, protocols), with limits.",
            |project, _: Nothing| Ok(rampage_analysis::language::metadata(&project.binary)),
        ),
        tool(
            Group::Types,
            "class_evidence",
            "Bounded named Itanium vtable/RTTI evidence with validated code slots; not inferred C++ layouts.",
            |project, _: Nothing| Ok(rampage_analysis::classes::recover(&project.binary)),
        ),
        tool(
            Group::Types,
            "import_debug_signatures",
            "Preview bounded embedded-DWARF signatures; apply=true persists them without replacing user signatures.",
            |project, arguments: DebugImportArgs| project.import_debug_signatures(arguments.apply),
        )
        .annotates(),
        tool(
            Group::Types,
            "import_pdb_names",
            "Preview function names from an explicit `pdb` path matching this PE image's RSDS GUID and age. \
             Only apply=true persists names, atomically as one undo batch, for preexisting unnamed function entries; \
             user, symbol, export, entry and concurrent labels are preserved. No types, layouts, signatures, new \
             functions, automatic paths, symbol servers or downloads. `offset`/`limit` page details only: every apply \
             acts on the WHOLE import, not the page. Bounded JSON always retains identity, full preview/applied/\
             preserved totals and whole_apply_succeeded; more/next_offset continue byte-capped details. To inspect \
             later pages without another apply, omit apply or use false; eligibility reflects current annotations.",
            import_pdb_page,
        )
        .annotates(),
        tool(
            Group::Detection,
            "build_signatures",
            "Build a library-function signature database (FLIRT/Function-ID style) from this binary's named \
             functions and write it to the output path. Each function is hashed over its symbol size and over the \
             extent discovery finds for it; functions whose masked bodies collide also get callee keys (the \
             optional calls/ambiguous_calls fields). Reports function signatures and callee keys separately. Use it \
             on a binary with symbols, then identify_functions on a stripped one.",
            |project, arguments: SignatureBuildArgs| {
                let database = project.build_signatures();
                std::fs::write(&arguments.output, database.to_json())
                    .map_err(|error| ApiError::Invalid(format!("cannot write {}: {error}", arguments.output)))?;
                Ok(serde_json::json!({
                    "signatures": database.len(),
                    "callee_keys": database.callee_keys(),
                    "output": arguments.output,
                }))
            },
        ),
        tool(
            Group::Detection,
            "identify_functions",
            "Name functions by matching signature databases (FLIRT/Function-ID style), so statically linked \
             library code in a stripped binary gets recognized. Applies, first match winning: an optional \
             database path, then loaded data packs' databases in pack order, then the bundled starter database for \
             the architecture (left out with no_bundled=true, which works with a database path, a data pack's \
             database for the architecture, or both, and is refused with neither). Each match's `source` names \
             the database that named it: \"user database\", the data pack's name, or \"rampage-builtin\". \
             A function whose masked body collides with another's is named by the names of the functions it \
             calls, once those are named; thunks too small for the confidence gate are never named. apply=true \
             saves names for unnamed functions. `warnings` names data packs or pack signature databases that did \
             not load.",
            |project, arguments: IdentifyArgs| {
                let user = match &arguments.database {
                    Some(path) => {
                        let text = crate::read_bounded(
                            std::path::Path::new(path),
                            crate::MAX_SIGNATURE_DB_BYTES,
                            "signature database",
                        )?;
                        Some(
                            rampage_signatures::SignatureDb::from_json(&text)
                                .map_err(|error| ApiError::Invalid(error.to_string()))?,
                        )
                    }
                    None => None,
                };
                project.identify_functions(user.as_ref(), !arguments.no_bundled, arguments.apply)
            },
        )
        .annotates(),
    ];
    // The workflow registry's tools, at the place in the order models have always seen them.
    tools.extend(WORKFLOWS.iter().map(|&workflow| workflow_tool(workflow)));
    tools.extend([
        tool(
            Group::Diagnostics,
            "analysis_diagnostics",
            "Decode coverage and evidence of unreliable static code, with explicit limitations. \
             Does not assert encryption.",
            |project, args: DiagnosticsArgs| project.analysis_diagnostics(args.include_discovery),
        ),
        tool(
            Group::Detection,
            "capabilities",
            "Likely behaviors (networking, process creation and injection, anti-debugging, cryptography, \
             filesystem/registry, input capture) inferred from imports and strings. Triage evidence, not proof \
             the behavior executes.",
            |project, _: Nothing| Ok(project.capabilities()),
        ),
        tool(
            Group::DotNet,
            "dotnet_metadata",
            "Managed assembly identity and a bounded page chosen by `list`: types with method/property signatures \
             and event types, pinvokes with DLL/exports, attributes with fixed/named values, or resources with \
             metadata-only offset/reference evidence. Resource locations are not validated payload extents; no \
             payload or external resource is read. Supported attribute values include primitives, \
             strings, types, single-dimensional arrays and verified local enums; unsupported values report errors. \
             Property/event accessor tokens are metadata bindings, not inferred behavior. Filter with contains; \
             offset/limit page the list and parent_token selects an attribute target. Bodies are CIL, listed by \
             dotnet_il, not native code for decompile/disassemble. Returns null for a native image.",
            |project, args: DotNetArgs| {
                let query = crate::DotNetQuery {
                    list: args.list,
                    contains: args.contains,
                    parent_token: args.parent_token,
                    offset: args.offset,
                    limit: page_limit(args.limit),
                };
                project.dotnet_metadata(&query)
            },
        ),
        tool(
            Group::DotNet,
            "dotnet_il",
            "For a managed (.NET) assembly: the CIL of one method, ILDasm style (`IL_0000: ldarg.0`), with call, \
             field and type tokens resolved to names and signatures, `ldstr` literals escaped, branch and switch \
             targets as IL_xxxx labels, the local variable types and the exception clauses (try/handler/filter \
             ranges, catch type). `method` is a MethodDef token (`0x0600000d`) or `Namespace.Type::Name`; an \
             overloaded name is refused with each overload's token and signature. Instructions are paged with \
             offset/limit (offset counts instructions), or start at an IL label with `at` (`IL_0042`); bytes that \
             are no opcode show as `.byte`. Returns null for a native image.",
            |project, args: DotNetIlArgs| {
                let at = args.at.as_deref().map(crate::parse_il_offset).transpose().map_err(ApiError::Invalid)?;
                let query = crate::DotNetIlQuery {
                    method: args.method,
                    offset: args.offset,
                    limit: page_limit(args.limit),
                    at,
                };
                project.dotnet_il(&query)
            },
        ),
        tool(
            Group::Detection,
            "detect_tools",
            "Identify the tools that likely produced the binary (packer, compiler, protector, installer, linker, \
             runtime: the C runtime linked in) from a bundled heuristic database of entry-point, section, \
             import, symbol, Mach-O build-version, overlay and entropy signatures. Optionally overlay a \
             user-supplied PeID userdb.txt; loaded data packs' PeID signatures are always overlaid. Returns \
             {detections, warnings}: warnings name the PeID entries and lines skipped as malformed (the first 20, \
             then a count), then data packs or pack PeID files that did not load. Confidence is a signal, not \
             proof.",
            |project, args: DetectToolsArgs| {
                let peid = match &args.peid {
                    Some(path) => {
                        Some(crate::read_bounded(std::path::Path::new(path), crate::MAX_PEID_BYTES, "PeID database")?)
                    }
                    None => None,
                };
                project.detect_tools(peid.as_deref())
            },
        ),
        tool(
            Group::Detection,
            "yara_scan",
            "Compile the given YARA rule source and scan the binary's image bytes, returning matching rules with \
             their tags, metadata and bounded matched-string offsets. Rules are user-supplied; the rules of loaded \
             data packs (see list_packs) run too, in a namespace named after their pack. Returns {matches, \
             warnings}: warnings name data packs or pack rule files that did not load. include statements are \
             refused.",
            |project, args: YaraArgs| {
                let matches = match &args.rules {
                    Some(rules) => project.yara_scan(rules)?,
                    None => project.yara_scan_packs()?,
                };
                Ok(YaraScan { matches, warnings: project.packs().problems_for("yara") })
            },
        ),
        tool(
            Group::Detection,
            "capa_detect",
            "Evaluate a directory of Mandiant capa rules, plus those of loaded data packs (see list_packs), against \
             the binary's imports, exports and strings, returning the behaviors whose file-scope features match. A \
             partial capa evaluator (no disassembly features); triage evidence, not proof. Returns \
             {capabilities, warnings}: warnings name data packs or pack rule sets that did not load.",
            |project, args: CapaArgs| {
                let capabilities = match &args.rules_dir {
                    Some(directory) => project.detect_capa(std::path::Path::new(directory))?,
                    None => project.detect_capa_packs()?,
                };
                Ok(CapaScan { capabilities, warnings: project.packs().problems_for("capa") })
            },
        ),
        tool(
            Group::Runtime,
            "observe_pointer",
            "Observe one captured pointer slot, including writable memory; never inserts a call or discovery edge.",
            |project, args: At| project.observe_pointer(project.resolve(&args.at)?),
        ),
        tool(
            Group::Runtime,
            "compare_pointer_observations",
            "Compare raw pointer words at explicitly paired slots in two captures. Analyst-ordered before/after \
             observations, not verified chronology, process identity or proven flow; opens no sidecars.",
            |project, args: PointerComparisonArgs| {
                let address = |text: &str| {
                    rampage_loaders::snapshot::address(text).map_err(|error| ApiError::Invalid(error.to_string()))
                };
                let before_slot = address(&args.at)?;
                let after_slot = address(&args.other_at)?;
                let after = project.open_peer(&args.other)?;
                project.compare_pointer_observations(before_slot, &after, after_slot)
            },
        )
        .without_annotations(),
        tool(
            Group::Runtime,
            "compare_runtime_bytes",
            "Compare explicit captured ranges with a UUID-matched original Mach-O. original_image_offset and optional \
             original_image_length select an image inside the explicit original path, using the capture's \
             architecture. Paginated spans, full-range totals; no annotation transfer or claim of recovered flow. \
             Opens no sidecars or recorded module paths.",
            compare_runtime_page,
        )
        .without_annotations(),
        tool(
            Group::Runtime,
            "observe_indirect_branch",
            "Link an explicitly selected ARM64 indirect branch window to a captured pointer slot. \
             Bounded conditional decoding evidence, not executed or proven flow; no discovery or annotations.",
            |project, args: BranchObservationArgs| {
                let address = |text: &str| {
                    rampage_loaders::snapshot::address(text).map_err(|error| ApiError::Invalid(error.to_string()))
                };
                project.observe_indirect_branch(address(&args.start)?, address(&args.at)?)
            },
        )
        .without_annotations(),
        Tool {
            group: Group::Core,
            name: "binary_info",
            description: "Format, architecture, entry point, segments and sections of the binary.",
            input_schema: schema::<Nothing>(),
            interactive: false,
            effect: Effect::None,
            reads_annotations: true,
            handler: Box::new(|project, input| {
                let _: Nothing =
                    serde_json::from_value(input).map_err(|error| format!("invalid arguments: {error}"))?;
                serde_json::to_value(project.summary()).map_err(|error| error.to_string())
            }),
        },
        tool(
            Group::Core,
            "triage",
            "Hashes, entropy, format details (build time, libraries, hardening), overlay and hints of packing.",
            |project, _: Nothing| Ok(project.triage().clone()),
        ),
        tool(
            Group::Core,
            "list_functions",
            "Functions found by analysis, sorted by address, with size, blocks and instruction counts. Filter with \
             name_contains; paginated with offset and limit (default 100).",
            |project, mut query: FunctionsQuery| {
                query.limit = page_limit(query.limit);
                project.functions(&query)
            },
        ),
        tool(
            Group::Core,
            "disassemble",
            "Disassemble instructions from an address or name, with control flow, references and names.",
            |project, arguments: DisassembleArgs| {
                let count = arguments.count.unwrap_or(crate::DEFAULT_INSTRUCTIONS).min(1000);
                project.disassemble(arguments.at.as_deref(), count)
            },
        ),
        tool(
            Group::Core,
            "function_graph",
            "The control-flow graph of the function containing an address or name: its basic blocks with \
             disassembly, and edges (unconditional, taken, not_taken, or switch from a register jump to each case \
             of a bounded switch table) indexing into the blocks. A call that never returns ends its block with no \
             fall-through edge; its line says why in `noreturn`: `listed` (the callee is documented never to \
             return) or `inferred` (no path through the callee returns).",
            |project, arguments: At| project.function_graph(project.resolve(&arguments.at)?),
        ),
        tool(
            Group::Core,
            "xrefs",
            "Cross-references: pass `to` for who calls or reads an address, or `from` for what a function \
             references. Paginated.",
            |project, arguments: XrefsArgs| {
                let query = match (arguments.to, arguments.from) {
                    (Some(to), None) => XrefQuery::To(project.resolve(&to)?),
                    (None, Some(from)) => XrefQuery::From(project.resolve(&from)?),
                    _ => return Err(ApiError::Invalid("pass exactly one of `to` and `from`".to_owned())),
                };
                project.xrefs(query, arguments.offset, page_limit(arguments.limit))
            },
        ),
        tool(
            Group::Core,
            "list_strings",
            "Printable strings with their addresses. Filter with `contains`; paginated.",
            |project, mut query: StringsQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.strings(&query))
            },
        ),
        tool(
            Group::Core,
            "list_imports",
            "Imported functions with their libraries and import slots. Filter with `contains`; paginated.",
            |project, mut query: ListQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.imports(&query))
            },
        ),
        tool(
            Group::Core,
            "list_exports",
            "Exported symbols with their addresses. Filter with `contains`; paginated.",
            |project, mut query: ListQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.exports(&query))
            },
        ),
        tool(
            Group::Core,
            "rename",
            "Name a function or address. Names show everywhere and are saved beside the binary; record what you \
             learn as you go.",
            |project, arguments: RenameArgs| {
                let name = edit_value(arguments.name, arguments.clear, "name")?;
                project.rename(project.resolve(&arguments.at)?, name.as_deref())
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "set_signature",
            "Persist one C function signature at an address; use sized types and an optional calling convention.",
            |project, arguments: CommentArgs| {
                let text = edit_value(arguments.text, arguments.clear, "text")?;
                project.set_signature(project.resolve(&arguments.at)?, text.as_deref())
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "set_types",
            "Persist C typedef/struct/union/enum declarations; sized types, no comments or preprocessor directives.",
            |project, arguments: CommentArgs| {
                let text = edit_value(arguments.text, arguments.clear, "text")?;
                project.set_types(project.resolve(&arguments.at)?, text.as_deref())
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "set_global",
            "Persist a named C data declaration at a mapped non-code address.",
            |project, arguments: CommentArgs| {
                let text = edit_value(arguments.text, arguments.clear, "text")?;
                project.set_global(project.resolve(&arguments.at)?, text.as_deref())
            },
        )
        .annotates(),
        tool(
            Group::Core,
            "set_comment",
            "Comment an instruction or address; comments show in the disassembly and are saved beside the binary.",
            |project, arguments: CommentArgs| {
                let text = edit_value(arguments.text, arguments.clear, "text")?;
                project.comment(project.resolve(&arguments.at)?, text.as_deref())
            },
        )
        .annotates(),
        tool(
            Group::Core,
            "annotate_batch",
            "Set many names and comments in one call, as one undo step. All entries are checked first; if any is \
             invalid nothing is applied and each problem is listed by entry index. Each `at` resolves against the \
             names as they were before the batch, not as earlier entries leave them.",
            |project, arguments: AnnotateBatchArgs| project.annotate_batch(&arguments.entries),
        )
        .annotates(),
        tool(
            Group::Core,
            "check_names",
            "Pre-flight candidate names: whether each is a valid identifier, address-shaped, or already used (where).",
            |project, arguments: CheckNamesArgs| project.check_names(&arguments.names),
        ),
        tool(Group::Core, "list_annotations", "Every user name and comment, by address.", |project, _: Nothing| {
            Ok(project.annotation_list())
        }),
        tool(
            Group::Core,
            "show_address",
            "Move the user's view to an address or name, to point out what you are discussing.",
            |project, arguments: At| {
                Ok(serde_json::json!({ "address": format!("{:#x}", project.resolve(&arguments.at)?) }))
            },
        )
        .interactive(),
        tool(
            Group::Core,
            "undo",
            "Undo the last edit or batch made in this session. Returns its edits; empty if there was none.",
            |project, _: Nothing| project.undo(),
        )
        .annotates(),
        tool(
            Group::Core,
            "discard_undo",
            "Drop the last edit or batch from this session's undo history without reverting it, when another \
             client's edits block undoing it (which blocks every earlier step too). Its edits stay in effect; the \
             annotation log is not rewritten. Refuses a step undo could still revert unless force is true. Returns \
             the dropped edits; empty if there was none.",
            |project, arguments: DiscardUndoArgs| project.discard_undo_step(arguments.force),
        ),
        tool(
            Group::Core,
            "redo",
            "Redo the last edit or batch undone. Returns its edits; empty if there was none.",
            |project, _: Nothing| project.redo(),
        )
        .annotates(),
    ]);
    tools
}

/// The tool running `workflow`, its report shrunk to fit one result.
fn workflow_tool(workflow: &'static dyn Workflow) -> Tool {
    let handler = move |project: &Project, input: Value| -> Result<Value, String> {
        let options = workflow.options(input)?;
        let report = fitted(workflow.run(project, &options)).map_err(|error| error_chain(&error))?;
        serde_json::to_value(report).map_err(|error| error.to_string())
    };
    Tool {
        group: workflow.group(),
        name: workflow.name(),
        description: workflow.description(),
        input_schema: workflow.input_schema(),
        interactive: false,
        effect: Effect::None,
        reads_annotations: true,
        handler: Box::new(handler),
    }
}

/// The group of the tool (or file tool) `name` in the registry.
pub fn group_of(name: &str) -> Option<Group> {
    static GROUPS: std::sync::OnceLock<std::collections::HashMap<&'static str, Group>> = std::sync::OnceLock::new();
    let groups = GROUPS.get_or_init(|| {
        let tools = tools().into_iter().map(|tool| (tool.name, tool.group));
        tools.chain(file_tools().into_iter().map(|tool| (tool.name, tool.group))).collect()
    });
    groups.get(name).copied()
}

/// Runs the tool `name` with `input`, returning its result as text for the model and whether it failed.
pub fn call(tools: &[Tool], project: &Project, name: &str, input: Value) -> (String, bool) {
    let Some(tool) = tools.iter().find(|tool| tool.name == name) else {
        return (format!("unknown tool {name}"), true);
    };
    let apply_requested = input
        .get("apply")
        .and_then(Value::as_bool)
        .or_else(|| (input.is_object() && input.get("apply").is_none()).then_some(false));
    match (tool.handler)(project, input) {
        Ok(value) => {
            let mut text = value.to_string();
            if text.len() > MAX_RESULT_CHARS {
                let cut = (0..=MAX_RESULT_CHARS).rev().find(|&index| text.is_char_boundary(index)).unwrap_or(0);
                text.truncate(cut);
                text.push_str("... (truncated: ask for a narrower range, a smaller count, or a page)");
            }
            (text, false)
        }
        Err(error) if name == "import_pdb_names" => (pdb_import_error(&error, apply_requested), true),
        Err(error) => (error, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_name_belongs_to_exactly_one_listed_group() {
        let mut groups: std::collections::BTreeMap<&str, Vec<Group>> = std::collections::BTreeMap::new();
        for (name, group) in tools()
            .iter()
            .map(|tool| (tool.name, tool.group))
            .chain(file_tools().iter().map(|tool| (tool.name, tool.group)))
        {
            groups.entry(name).or_default().push(group);
        }
        for (name, in_groups) in &groups {
            assert_eq!(in_groups.len(), 1, "{name} is registered in {in_groups:?}");
            assert!(Group::ALL.contains(&in_groups[0]), "{name}");
        }
        for group in Group::ALL {
            assert!(groups.values().any(|in_groups| in_groups[0] == group), "{group:?} has no tools");
            assert_eq!(group.name().parse::<Group>(), Ok(group));
        }
        assert!("everything".parse::<Group>().unwrap_err().contains("core, detection"));
        assert_eq!(group_of("list_packs"), Some(Group::Detection));
        let listing = file_tools().into_iter().find(|tool| tool.name == "list_packs").unwrap();
        let packs = listing.call(&Packs::default(), serde_json::json!({})).unwrap();
        assert_eq!(packs[0]["name"], crate::packs::BUILTIN_PACK);
    }

    #[test]
    fn binary_info_keeps_its_schema_validation_and_json_result() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let tools = tools();
        let (text, failed) = call(&tools, &project, "binary_info", serde_json::json!({}));
        assert!(!failed);
        let result: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(result, serde_json::to_value(project.summary()).unwrap());
        let (text, failed) = call(&tools, &project, "binary_info", serde_json::json!(42));
        assert!(failed);
        assert!(text.starts_with("invalid arguments:"));
    }

    #[test]
    fn pdb_pages_keep_whole_import_receipts_and_exact_totals_under_the_byte_cap() {
        use rampage_loaders::pdb::{PdbFunction, PdbIdentity, PdbReport};

        let imported = || crate::PdbImport {
            preview: PdbReport {
                identity: Some(PdbIdentity { guid: [0xab; 16], age: 42 }),
                functions: (0..5000)
                    .map(|index| PdbFunction {
                        address: 0x140001000 + index * 16,
                        name: format!("symbol_{index}_{}", "x".repeat(700)),
                    })
                    .collect(),
                warnings: vec!["\u{03bb}\n".repeat(10_000)],
            },
            applied: (3..5000).map(|index| 0x140001000 + index * 16).collect(),
            preserved: (0..3).map(|index| 0x140001000 + index * 16).collect(),
        };
        assert!(serde_json::to_string(&imported()).unwrap().len() > MAX_RESULT_CHARS);
        let capacity = pdb_detail_capacity().unwrap();
        let first = pdb_import_page(imported(), true, 0, 1000, capacity);
        let text = first.to_string();
        assert!(text.len() <= MAX_RESULT_CHARS, "{}", text.len());
        let first: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(first["whole_apply_succeeded"], true);
        assert_eq!(first["status"], "applied");
        assert_eq!(first["preview_total"], 5000);
        assert_eq!(first["applied_total"], 4997);
        assert_eq!(first["preserved_total"], 3);
        assert_eq!(first["warnings_total"], 1);
        assert_eq!(first["details_total"], 5001);
        assert_eq!(first["byte_capped"], true);
        assert_eq!(first["more"], true);
        assert_eq!(first["details"][0]["status"], "preserved");
        assert_eq!(first["details"][3]["status"], "applied");
        let next = first["next_offset"].as_u64().unwrap() as usize;
        assert!(next > 0 && next < 1000);
        assert_eq!(next, first["details"].as_array().unwrap().len());
        let second = pdb_import_page(imported(), true, next, 1000, capacity);
        assert!(second.to_string().len() <= MAX_RESULT_CHARS);
        assert_eq!(second["identity"], first["identity"]);
        assert_eq!(second["applied_total"], first["applied_total"]);
        assert_eq!(second["details"][0]["address"], format!("{:#x}", 0x140001000u64 + next as u64 * 16));

        let last = pdb_import_page(imported(), true, 5000, 1000, capacity);
        let last: Value = serde_json::from_str(&last.to_string()).unwrap();
        assert!(last.to_string().len() <= MAX_RESULT_CHARS);
        assert_eq!(last["whole_apply_succeeded"], true);
        assert_eq!(last["applied_total"], 4997);
        assert_eq!(last["more"], false);
        assert_eq!(last["next_offset"], Value::Null);
        assert_eq!(last["details"][0]["kind"], "warning");
        assert_eq!(last["details"][0]["text_truncated"], true);
        assert_eq!(last["details"][0]["text_bytes"], 30_000);

        let mut preview = imported();
        preview.applied.clear();
        let preview = pdb_import_page(preview, false, usize::MAX, 1, capacity);
        assert_eq!(preview["status"], "preview");
        assert_eq!(preview["whole_apply_succeeded"], false);
        assert_eq!(preview["preview_total"], 5000);
        assert_eq!(preview["applied_total"], 0);
        assert_eq!(preview["offset"], 5001);
        assert_eq!(preview["details"], serde_json::json!([]));
        assert_eq!(preview["more"], false);
    }

    #[test]
    fn pdb_error_receipts_bound_escaped_unicode_without_losing_failure_status() {
        let message = "\0\n\u{03bb}".repeat(30_000);
        let text = pdb_import_error(&message, Some(true));
        assert!(text.len() <= MAX_RESULT_CHARS);
        let receipt: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["apply_requested"], true);
        assert_eq!(receipt["whole_apply_succeeded"], false);
        assert_eq!(receipt["applied_total"], 0);
        assert_eq!(receipt["error_truncated"], true);
        assert!(message.starts_with(receipt["error"].as_str().unwrap()));
    }

    #[test]
    fn pdb_byte_capped_pages_always_advance_even_for_maximally_escaped_detail_text() {
        use rampage_loaders::pdb::{PdbFunction, PdbIdentity, PdbReport};

        let imported = || crate::PdbImport {
            preview: PdbReport {
                identity: Some(PdbIdentity { guid: [0xff; 16], age: u32::MAX }),
                functions: (0..3)
                    .map(|index| PdbFunction { address: u64::MAX - index, name: "\0".repeat(MAX_PDB_DETAIL_BYTES) })
                    .collect(),
                warnings: vec!["\0".repeat(MAX_PDB_DETAIL_BYTES * 2)],
            },
            applied: vec![u64::MAX],
            preserved: vec![u64::MAX - 1, u64::MAX - 2],
        };
        let capacity = pdb_detail_capacity().unwrap();
        let mut offset = 0;
        let mut pages = 0;
        loop {
            let page = pdb_import_page(imported(), true, offset, 1000, capacity);
            let text = page.to_string();
            assert!(text.len() <= MAX_RESULT_CHARS, "{}", text.len());
            let page: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(page["whole_apply_succeeded"], true);
            assert_eq!(page["applied_total"], 1);
            assert_eq!(page["preserved_total"], 2);
            let count = page["details"].as_array().unwrap().len();
            assert!(count > 0);
            pages += 1;
            assert!(pages <= 4);
            if page["more"] == false {
                assert_eq!(offset + count, 4);
                assert_eq!(page["next_offset"], Value::Null);
                assert_eq!(page["details"].as_array().unwrap().last().unwrap()["text_truncated"], true);
                break;
            }
            assert_eq!(page["byte_capped"], true);
            let next = page["next_offset"].as_u64().unwrap() as usize;
            assert_eq!(next, offset + count);
            offset = next;
        }
        assert!(pages > 1);
    }
}
