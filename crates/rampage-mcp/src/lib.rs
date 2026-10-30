//! MCP server exposing rampage analysis to AI agents. It serves the tools of `rampage_api::tools`, the same ones
//! the UI's assistant uses, with each taking the path of the binary to work on. Tools are grouped: the server lists
//! the groups it was started with (by default only core) and an `enable_tools` meta-tool that adds the others.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rampage_api::tools::{self, DebugTool, FileTool, Group, Tool};
use rampage_api::{DebugRegistry, FileOffset, Packs, Project, RawProjectRequest, Session};
use rampage_arch::Arch;
use rampage_loaders::ImageAt;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Map, Value, json};

/// The meta-tool that lists the tool groups and enables them.
pub const ENABLE_TOOLS: &str = "enable_tools";

/// The environment variable choosing the groups served from the start: `all`, or a comma-separated list.
pub const TOOLS_ENV: &str = "RAMPAGE_MCP_TOOLS";

/// The environment variable listing debug endpoints (`host:port` or `unix:/path`, comma-separated) the operator
/// allows, in addition to `--debug-endpoint`. Without any, the server has no `debug` group.
pub const DEBUG_ENDPOINTS_ENV: &str = "RAMPAGE_DEBUG_ENDPOINTS";

const ENABLE_TOOLS_DESCRIPTION: &str = "\
List rampage's tool groups (name, one-line description, tool count and names, whether enabled), or enable groups \
with `groups`, e.g. [\"detection\"] or [\"all\"]. Enabling adds the group's tools to the tool list and sends \
notifications/tools/list_changed. Without `groups` nothing changes.";

const INSTRUCTIONS_INTRO: &str = "\
rampage analyzes PE, ELF and Mach-O binaries for x86, x86-64, AArch64, 32-bit ARM and Thumb, MIPS, PowerPC, \
RISC-V, SPARC, s390x and m68k. Native-image tools take the binary's file path and reuse cached project analysis \
when needed. Standalone file inspectors and decoders use explicit sources without that project cache. \
Addresses are hex strings like \"0x401000\". Wherever a tool \
takes an address (except comparison slots/ranges and branch observation windows) you may also pass a symbol, \
export or import name (an import name finds its stub) or a sub_<hex> name.

Tools come in groups. The server lists the groups it was started with, by default only core, plus enable_tools: \
call it without arguments to see every group with its tools, or with {\"groups\": [\"detection\"]} (or [\"all\"]) \
to add groups, after which the tool list changes (notifications/tools/list_changed). Calling a tool of a group that \
is not enabled fails with the group to enable and runs nothing. Clients that do not refresh their tool list can \
start the server with `rampage mcp --all-tools`, or set RAMPAGE_MCP_TOOLS to all or to a comma-separated list of \
groups. The groups:";

const INSTRUCTIONS_USAGE: &str = "\
Core: start with triage_report: one bounded overview (layout, triage hints, producing toolchain, capability tags, \
imports, notable strings, library functions) that ends with concrete next tool calls, each naming its `group`; enable \
that group first when it is not enabled. The other guided workflows compose the primitives the same way: find_main \
(the program's own entry logic), network_surface, persistence_surface (autostart locations, service and registry \
APIs), string_decoding (candidate byte-decoding loops with their call sites and encoded-looking data) and diff_builds; \
find_crypto (algorithm constants and crypto APIs with the code that uses them) is in detection. Every workflow finding \
carries its evidence, source tool and confidence, and every report states its limitations: treat findings as evidence, \
not verdicts. For a single question use triage or binary_info, then list_functions (filter with name_contains, page \
with offset/limit), then decompile a function to C to understand it (the best starting point; falls back to \
function_summary, a structural CFG/reference summary, where no decompiler specification is available), or disassemble \
or function_graph it, and follow references with xrefs. list_imports and list_strings are good starting points for \
finding behavior. Record findings with rename and set_comment, or many at once with annotate_batch (all or nothing; \
check_names pre-flights candidate names): they persist beside the binary and every client of the same binary, \
including the rampage UI, picks them up. record_finding keeps a ledger there of what you established, still don't \
know or want answered, with supporting tool calls and a status, so a later session or another agent can resume \
from list_findings. undo and redo revert or reapply one step, which may be a whole batch; when \
another client's edit blocks undoing a step, discard_undo drops it from the undo history (its edits stay) so earlier \
steps can be undone; it refuses a step undo could still revert unless force is true, since the user's UI may share \
that history. Memory snapshots and bundle directories use the same tools. inspect_raw_code provides bounded \
linear decoding of original-file windows with an explicitly asserted architecture/mode/orders/base, without \
native-image admission or target following. inspect_data provides bounded native \
bytes/word candidates without discovery or sidecars; names resolve only through retained metadata. \
decode_file_range instead accepts an explicit regular-file range and codec without an executable header. \
Its transient decoded preview uses decoded offsets, not source offsets or load addresses; supplied sizes and \
successful decoding do not authenticate content or prove stream boundaries. Tools whose schema has a `raw` \
object open that explicit file range as a headerless Raw project with a closed profile instead of a native image \
(never with arch/image_offset/image_length; null means absent). `raw` fields: profile (one of the Raw profiles \
listed below), offset and length (original-file bytes, length up to 128 KiB), base_address, optional entry and up to \
8192 seeds (internal code-space byte coordinates, even for word-addressed processors; hex strings or integers). \
The mapping is an analyst assertion; annotations are memory-only for this server and interpretation.

Detection: detect_tools (packer/compiler/protector/installer/linker/runtime), identify_functions (library code by \
signature, bundled databases applied; build_signatures makes a database from a binary with symbols), capabilities, \
yara_scan and capa_detect (user-supplied rules); data packs extend these databases, and list_packs shows which are \
loaded with their licence and provenance. Types: import_debug_types reviews embedded DWARF or an explicit \
identity-matched PDB into the project library. Native counterparts constrain retained producer facts; unknown \
alignment and unsupported bitfields/qualifiers remain explicit. Whole-plan review hashes gate one atomic \
library/proof/signature batch, not a page. Identity is linkage, not source authentication. \
propagate_types previews bounded direct-call candidates and \
optionally stores source-fingerprinted unlocked hints; analyst types win and conflicts/unsupported mappings \
remain explicit. Ordinary decompilation may derive ephemeral context without changing the hint log. \
function_frame pages native locals/parameters with current \
names/types, raw storage and address-space widths, plus available static stack/register candidates. Native \
stack-space coordinates and tracker entry-SP offsets remain separate; conditional reloads are not ABI proof. \
apply_data_type binds a complete element type/array or explicit \
string encoding to a data range; read_data shows native fields with raw bytes/backing status. apply_enum and \
apply_offset label decoder-native operand selectors in disassembly without changing raw bytes/text. Unsupported \
or stale operands refuse; interpretations are analyst assertions, not runtime object or producer proof. \
declare_types imports bounded C declarations/inline headers \
into a project library; list_types pages names, get_type inspects native target layouts and dependencies, and \
delete_type refuses outside dependencies. Multi-name definition groups require explicit definition_group=true. \
Bundled c/posix-linux/win32 profiles retain provenance and assert their ABI, not host layout or OS detection. \
No filesystem includes or host preprocessor. edit_variable renames/retypes a current local or parameter \
by display name or complete returned native storage, persists storage-keyed annotations, and returns refreshed \
C and descriptors in the same call. Single whole register/stack mappings and same-size types only; selectors \
include inclusive definition/use points, not live ranges. Undo/redo/replay preserve edits. \
set_signature, set_types and set_global persist C declarations; \
language_metadata exposes demangled names and bounded metadata. import_pdb_names requires an explicit pdb path \
matching the PE image's RSDS GUID/age; preview is the default, apply=true imports names only as one undo batch. \
Its detail pages never restrict the whole import; whole_apply_succeeded and exact totals survive byte caps. \
import_debug_layouts previews checked DWARF layouts/signatures; only apply=true with the exact review_sha256 from a \
fresh preview applies the complete atomic batch. The hash binds all evidence, not just the page; changed content \
requires re-review. Undo is same-process only and is not recovered after CLI exit. \
Diagnostics: analysis_diagnostics reports decode \
confidence limits. Runtime: compare_runtime_bytes takes an explicit original path, module UUID and hexadecimal runtime \
ranges, returning paginated byte evidence without sidecars or annotation transfer; verify identities when combining \
pages. observe_indirect_branch takes explicit hexadecimal start/at addresses for a bounded ARM64 branch window; slot \
links are conditional decoding evidence, not proof of execution or a call edge. compare_pointer_observations takes \
another explicit capture path and hexadecimal at/other_at slots; before/after ordering and slot correspondence are \
supplied by the analyst, not independently verified. Carve: carve scans any file (firmware, installer, archive) for \
embedded executables and containers by validated header, with offsets and header-estimated extents; it extracts and \
decompresses nothing. Pass an executable candidate's offset as image_offset to any binary tool to analyze it in place, \
with annotations kept apart from the outer file's.";

const INSTRUCTIONS_DEBUG: &str = "\
Debug: the operator allowed GDB remote stubs at these endpoints: {endpoints}. debug_connect opens a read-only \
session (the stub must already be running; rampage launches and attaches to nothing), then debug_status, \
debug_registers, debug_read_memory and debug_modules inspect the stopped target, debug_snapshot writes a \
rampage-snapshot-v1 file the other tools can open, and debug_disconnect detaches. Nothing resumes, steps, sets \
breakpoints, writes or kills; runtime bytes stay local.";

fn instructions(packs: &Packs, debug: Option<&DebugRegistry>) -> String {
    let groups: String = available_groups(debug.is_some())
        .iter()
        .map(|group| format!("\n- {}: {}", group.name(), group.description()))
        .collect();
    let mut text = format!("{INSTRUCTIONS_INTRO}{groups}\n\n{INSTRUCTIONS_USAGE}");
    if let Some(registry) = debug {
        text.push_str("\n\n");
        text.push_str(&INSTRUCTIONS_DEBUG.replace("{endpoints}", &registry.endpoints().join(", ")));
    }
    let profiles: Vec<_> = rampage_loaders::RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    text.push_str(&format!("\n\nRaw profiles: {}.", profiles.join(", ")));
    // Only a server given packs loads them here; the problem count must be known before any tool runs.
    if packs.configured() {
        let problems = packs.problems().len();
        text.push_str(&format!(
            "\n\nData packs: {} loaded, {problems} problems (packs rejected or contents that did not load). \
             Detection results that consult packs (identify_functions, detect_tools, yara_scan, capa_detect) list \
             the problems bearing on them in `warnings`; list_packs (detection) shows each pack's status.",
            packs.loaded().iter().filter(|pack| pack.error.is_none()).count()
        ));
    }
    text
}

/// The groups to serve from the start: every group with `all_tools`, else those `env` names (`all` or a
/// comma-separated list), else core alone. Core is always served.
pub fn initial_groups(all_tools: bool, env: Option<&str>) -> Result<BTreeSet<Group>, String> {
    initial_groups_with_debug(all_tools, env, false)
}

/// [`initial_groups`] for a server that has the `debug` group when `debug` is true.
pub fn initial_groups_with_debug(all_tools: bool, env: Option<&str>, debug: bool) -> Result<BTreeSet<Group>, String> {
    let available = available_groups(debug);
    if all_tools {
        return Ok(available.into_iter().collect());
    }
    let mut groups = BTreeSet::from([Group::Core]);
    for name in env.unwrap_or("").split(',').map(str::trim).filter(|name| !name.is_empty()) {
        if name == "all" {
            groups.extend(available.iter().copied());
        } else {
            groups.insert(parse_group(name, debug)?);
        }
    }
    Ok(groups)
}

/// Every group a server has: [`Group::ALL`], and `debug` when debug endpoints are configured.
fn available_groups(debug: bool) -> Vec<Group> {
    Group::ALL.into_iter().chain(debug.then_some(Group::Debug)).collect()
}

fn parse_group(name: &str, debug: bool) -> Result<Group, String> {
    if debug && name == Group::Debug.name() {
        return Ok(Group::Debug);
    }
    name.parse()
}

/// Parses the operator's debug endpoints: each `--debug-endpoint` value, then the comma-separated `env` list.
/// `None` when there are none, so the server has no `debug` group.
pub fn debug_registry(flags: &[String], env: Option<&str>) -> Result<Option<DebugRegistry>, String> {
    let endpoints: Vec<String> = flags
        .iter()
        .map(|flag| flag.trim().to_owned())
        .chain(env.unwrap_or("").split(',').map(|item| item.trim().to_owned()))
        .filter(|endpoint| !endpoint.is_empty())
        .collect();
    if endpoints.is_empty() {
        return Ok(None);
    }
    DebugRegistry::new(&endpoints).map(Some)
}

/// A tool's schema with the arguments every tool takes besides its own: which binary, which slice of a universal
/// one, and where in the file an embedded one starts; raw-capable tools also take the `raw` selector.
fn with_binary_arguments(name: &str, schema: &Value) -> Map<String, Value> {
    let mut schema = schema.as_object().cloned().unwrap_or_default();
    let properties = schema.entry("properties").or_insert_with(|| json!({}));
    if let Some(properties) = properties.as_object_mut() {
        properties.insert("path".to_owned(), json!({ "type": "string", "description": "Path to the binary file." }));
        properties.insert(
            "arch".to_owned(),
            json!({
                "type": ["string", "null"],
                "description": "Slice to load from a universal Mach-O (x86, x86_64, aarch64, arm, powerpc, ...). \
                                Defaults to x86_64, then aarch64, then x86, when present."
            }),
        );
        // Not `offset`, which many tools already take for paging.
        properties.insert(
            "image_offset".to_owned(),
            json!({
                "type": ["string", "integer", "null"],
                "description": "Open the ELF, PE or Mach-O image embedded at this file offset (hex \"0x...\" or \
                                decimal), such as a carve candidate's offset; for a universal Mach-O, its fat \
                                header's offset, with arch for the slice. Its annotations are kept apart from the \
                                outer file's; offset 0 without image_length is the file itself."
            }),
        );
        properties.insert(
            "image_length".to_owned(),
            json!({
                "type": ["string", "integer", "null"],
                "description": "With image_offset, the embedded image's length in bytes (hex or decimal). Defaults \
                                to the extent its header tables give, which leaves out bytes after it (an overlay)."
            }),
        );
        if tools::raw_capable(name) {
            properties.insert(RAW.to_owned(), compact_raw_selector());
        }
    }
    let required = schema.entry("required").or_insert_with(|| json!([]));
    if let Some(required) = required.as_array_mut() {
        required.push(json!("path"));
    }
    schema
}

/// The optional selector that opens a Raw Project in place of a native binary on raw-capable tools.
const RAW: &str = "raw";

/// The `raw` selector as repeated on every raw-capable tool: its shape without per-field prose or the profile
/// enum, which the server instructions state once. The server still parses it as a closed `RawProjectRequest`.
fn compact_raw_selector() -> Value {
    /// The member types of a union of plain typed schemas, flattening nested unions; None for anything richer.
    fn union_types(members: &[Value]) -> Option<Vec<Value>> {
        let mut types = Vec::new();
        for member in members {
            let object = member.as_object()?;
            if let Some(Value::Array(nested)) = object.get("anyOf") {
                types.extend(union_types(nested)?);
            } else if object.keys().all(|key| key == "type" || key == "minimum") {
                types.push(object.get("type")?.clone());
            } else {
                return None;
            }
        }
        Some(types)
    }
    fn strip(value: &mut Value) {
        match value {
            Value::Object(object) => {
                for key in ["description", "title", "examples", "enum"] {
                    object.remove(key);
                }
                if let Some(types) =
                    object.get("anyOf").and_then(Value::as_array).and_then(|members| union_types(members))
                {
                    object.remove("anyOf");
                    object.insert("type".to_owned(), Value::Array(types));
                }
                object.values_mut().for_each(strip);
            }
            Value::Array(entries) => entries.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut raw = tools::raw_selector_schema();
    strip(&mut raw);
    raw["type"] = json!(["object", "null"]);
    raw["description"] = json!("Headerless Raw project of path's byte range; see the server instructions.");
    raw
}

/// The explicit refusal of a `raw` selector on a tool that cannot serve Raw Projects.
fn raw_refusal(name: &str) -> String {
    format!(
        "tool {name} does not accept Raw projects; nothing was run. Raw-capable tools: {}",
        tools::RAW_CAPABLE_TOOLS.join(", ")
    )
}

fn enable_tools_schema(debug: bool) -> Map<String, Value> {
    let names: Vec<&str> = available_groups(debug).iter().map(|group| group.name()).chain(["all"]).collect();
    let schema = json!({
        "type": "object",
        "properties": {
            "groups": {
                "type": "array",
                "items": { "type": "string", "enum": names },
                "description": "Groups to enable; omit to list the groups without changing anything."
            }
        }
    });
    schema.as_object().cloned().unwrap_or_default()
}

/// One MCP connection's server. The loaded binaries are shared with its clones; the enabled groups are not, so a
/// clone serving another connection starts from the groups enabled when it was cloned. Debug sessions belong to the
/// connection: clones share them, and they detach when the server and its clones are dropped.
pub struct RampageServer {
    session: Arc<Session>,
    tools: Arc<Vec<Tool>>,
    file_tools: Arc<Vec<FileTool>>,
    debug: Option<Arc<DebugRegistry>>,
    debug_tools: Arc<Vec<DebugTool>>,
    enabled: Mutex<BTreeSet<Group>>,
}

impl Clone for RampageServer {
    fn clone(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
            tools: Arc::clone(&self.tools),
            file_tools: Arc::clone(&self.file_tools),
            debug: self.debug.clone(),
            debug_tools: Arc::clone(&self.debug_tools),
            enabled: Mutex::new(self.enabled()),
        }
    }
}

impl Default for RampageServer {
    fn default() -> Self {
        Self::with_groups([Group::Core])
    }
}

impl RampageServer {
    /// A server listing `groups` and core from the start.
    pub fn with_groups(groups: impl IntoIterator<Item = Group>) -> Self {
        // Without a person's view of the binary, tools that act on one have nothing to do.
        let tools = tools::tools().into_iter().filter(|tool| !tool.interactive).collect();
        let enabled = groups.into_iter().chain([Group::Core]).collect();
        Self {
            session: Arc::default(),
            tools: Arc::new(tools),
            file_tools: Arc::new(tools::file_tools()),
            debug: None,
            debug_tools: Arc::new(tools::debug_tools()),
            enabled: Mutex::new(enabled),
        }
    }

    /// This server with the `debug` group, connecting only to the endpoints `registry` allows. Its sessions belong
    /// to this server's connection.
    pub fn with_debug(self, registry: DebugRegistry) -> Self {
        Self { debug: Some(Arc::new(registry)), ..self }
    }

    fn groups(&self) -> Vec<Group> {
        available_groups(self.debug.is_some())
    }

    /// This server opening binaries in `session`, with its settings.
    pub fn with_session(self, session: Session) -> Self {
        Self { session: Arc::new(session), ..self }
    }

    /// This server with `packs` layered over the bundled databases of its heuristic-database tools, keeping its
    /// session's other settings.
    pub fn with_packs(self, packs: Arc<Packs>) -> Self {
        let session = Arc::try_unwrap(self.session).unwrap_or_else(|shared| shared.unloaded_copy());
        Self { session: Arc::new(session.with_packs(packs)), ..self }
    }

    fn packs(&self) -> Arc<Packs> {
        self.session.packs()
    }

    fn enabled(&self) -> BTreeSet<Group> {
        self.enabled.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Every tool this server can serve, with its group, whether enabled or not.
    fn catalog(&self) -> impl Iterator<Item = (Group, &'static str)> + '_ {
        let tools = self.tools.iter().map(|tool| (tool.group, tool.name));
        let file_tools = self.file_tools.iter().map(|tool| (tool.group, tool.name));
        let debug = self.debug.is_some().then(|| self.debug_tools.iter().map(|tool| (Group::Debug, tool.name)));
        tools.chain(file_tools).chain(debug.into_iter().flatten())
    }

    /// Enables the groups `arguments` names, returning the groups with their tools and the ones newly enabled.
    fn enable(&self, arguments: &Map<String, Value>) -> Result<(Value, bool), String> {
        let mut requested = BTreeSet::new();
        match arguments.get("groups") {
            None | Some(Value::Null) => {}
            Some(Value::Array(names)) => {
                for name in names {
                    match name.as_str() {
                        Some("all") => requested.extend(self.groups()),
                        Some(name) => {
                            requested.insert(parse_group(name, self.debug.is_some())?);
                        }
                        None => return Err("`groups` must be a list of group names".to_owned()),
                    }
                }
            }
            Some(_) => return Err("`groups` must be a list of group names".to_owned()),
        }
        let (newly, enabled) = {
            let mut enabled = self.enabled.lock().unwrap_or_else(PoisonError::into_inner);
            let newly: Vec<Group> = requested.into_iter().filter(|group| enabled.insert(*group)).collect();
            (newly, enabled.clone())
        };
        let groups: Vec<Value> = self
            .groups()
            .iter()
            .map(|&group| {
                let names: Vec<&str> =
                    self.catalog().filter(|(tool_group, _)| *tool_group == group).map(|(_, name)| name).collect();
                json!({
                    "name": group.name(),
                    "description": group.description(),
                    "tool_count": names.len(),
                    "tools": names,
                    "enabled": enabled.contains(&group),
                })
            })
            .collect();
        let newly_enabled: Vec<&str> = newly.iter().map(|group| group.name()).collect();
        Ok((json!({ "newly_enabled": newly_enabled, "groups": groups }), !newly.is_empty()))
    }

    /// Why `name` cannot be called now, when it belongs to a group that is not enabled.
    fn disabled_reason(&self, name: &str) -> Option<String> {
        let (group, _) = self.catalog().find(|(_, tool)| *tool == name)?;
        if self.enabled().contains(&group) {
            return None;
        }
        Some(format!(
            "tool `{name}` is in the `{group}` group, which is not enabled; nothing was run. Call {ENABLE_TOOLS} with \
             {{\"groups\": [\"{group}\"]}} first, or start the server with --all-tools or {TOOLS_ENV}={group}.",
            group = group.name()
        ))
    }

    /// Runs a tool on the binary its arguments name. Failures are results the caller sees, not protocol errors.
    fn run(&self, name: &str, mut arguments: Map<String, Value>) -> CallToolResult {
        let raw = arguments.remove(RAW).filter(|raw| !raw.is_null());
        if let (Some(registry), Some(tool)) = (&self.debug, self.debug_tools.iter().find(|tool| tool.name == name)) {
            if raw.is_some() {
                return CallToolResult::error(vec![ContentBlock::text(raw_refusal(name))]);
            }
            return match tool.call(registry, Value::Object(arguments)) {
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        if let Some(tool) = self.file_tools.iter().find(|tool| tool.name == name) {
            if raw.is_some() {
                return CallToolResult::error(vec![ContentBlock::text(raw_refusal(name))]);
            }
            return match tool.call(&self.packs(), Value::Object(arguments)) {
                Ok(output) if name == "query_debugger" && output.get("ok") == Some(&Value::Bool(false)) => {
                    CallToolResult::error(vec![ContentBlock::text(output.to_string())])
                }
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        let path = arguments.remove("path");
        let arch = arguments.remove("arch");
        let image_offset = arguments.remove("image_offset");
        let image_length = arguments.remove("image_length");
        let apply_requested = arguments.get("apply").map_or(Some(false), Value::as_bool);
        let outcome = (|| -> Result<(String, bool), String> {
            let tool =
                self.tools.iter().find(|tool| tool.name == name).ok_or_else(|| format!("unknown tool {name}"))?;
            if name == "import_debug_layouts" {
                tools::validate_debug_layout_arguments(&Value::Object(arguments.clone()))?;
            }
            let path = path.as_ref().and_then(Value::as_str).ok_or("`path` is required")?;
            if let Some(raw) = raw {
                let mut project = self.open_raw(name, Path::new(path), raw, [&arch, &image_offset, &image_length])?;
                return Ok(tools::call_shared(&self.tools, &mut project, name, Value::Object(arguments)));
            }
            let arch = match arch.as_ref() {
                None | Some(Value::Null) => None,
                Some(Value::String(arch)) => Some(arch.parse::<Arch>()?),
                Some(_) => return Err("`arch` must be an architecture string or null".to_owned()),
            };
            let offset = image_offset.as_ref().map(|value| file_offset("image_offset", value)).transpose()?.flatten();
            let length = image_length.as_ref().map(|value| file_offset("image_length", value)).transpose()?.flatten();
            let image = match (offset, length) {
                (Some(offset), length) => Some(ImageAt::new(offset, length)),
                (None, Some(_)) => return Err("`image_length` needs `image_offset`".to_owned()),
                (None, None) => None,
            };
            let mut project = if tool.reads_annotations {
                let project =
                    self.session.open_at(&PathBuf::from(path), arch, image).map_err(|error| error_text(&error))?;
                // Other clients (the UI, the CLI) may have saved names since the last call.
                project.refresh_annotations().map_err(|error| error_text(&error))?;
                project
            } else {
                let binary = rampage_loaders::Binary::open_image(path, image, arch);
                let project = Project::new(binary.map_err(|error| error_text(&error))?);
                project.set_packs(self.packs());
                Arc::new(project)
            };
            Ok(tools::call_shared(&self.tools, &mut project, name, Value::Object(arguments)))
        })();
        match outcome {
            Ok((output, false)) => CallToolResult::success(vec![ContentBlock::text(output)]),
            Ok((message, true)) => CallToolResult::error(vec![ContentBlock::text(message)]),
            Err(message) if name == "import_pdb_names" => {
                CallToolResult::error(vec![ContentBlock::text(tools::pdb_import_error(&message, apply_requested))])
            }
            Err(message) if name == "import_debug_layouts" => {
                let receipt = tools::debug_layout_import_error(&message, apply_requested);
                CallToolResult::error(vec![ContentBlock::text(receipt)])
            }
            Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
        }
    }

    /// The session's Raw Project for the `raw` selector of a call to `name`, refused for tools that cannot serve one
    /// and when combined with a native image selector.
    fn open_raw(
        &self,
        name: &str,
        path: &Path,
        raw: Value,
        selectors: [&Option<Value>; 3],
    ) -> Result<Arc<Project>, String> {
        if !tools::raw_capable(name) {
            return Err(raw_refusal(name));
        }
        for (selector, value) in ["arch", "image_offset", "image_length"].into_iter().zip(selectors) {
            if value.as_ref().is_some_and(|value| !value.is_null()) {
                return Err(format!(
                    "`raw` cannot be combined with `{selector}`: a Raw project's profile and range select the code; \
                     nothing was run"
                ));
            }
        }
        let request: RawProjectRequest =
            serde_json::from_value(raw).map_err(|error| format!("`raw`: invalid Raw project selector: {error}"))?;
        // Raw annotations are memory-only and shared through the session, so there is no log to refresh.
        self.session.open_raw(path, &request).map_err(|error| format!("`raw`: {}", error_text(&error)))
    }
}

/// An `image_offset` or `image_length` argument (see [`FileOffset`]); `null` means none.
fn file_offset(name: &str, value: &Value) -> Result<Option<u64>, String> {
    if value.is_null() {
        return Ok(None);
    }
    serde_json::from_value::<FileOffset>(value.clone())
        .map(|offset| Some(offset.0))
        .map_err(|error| format!("`{name}`: {error}"))
}

fn error_text(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

impl ServerHandler for RampageServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().enable_tool_list_changed().build())
            .with_server_info(Implementation::new("rampage", env!("CARGO_PKG_VERSION")))
            .with_instructions(instructions(&self.packs(), self.debug.as_deref()))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let enabled = self.enabled();
        let meta =
            rmcp::model::Tool::new(ENABLE_TOOLS, ENABLE_TOOLS_DESCRIPTION, enable_tools_schema(self.debug.is_some()));
        let tools = self.tools.iter().filter(|tool| enabled.contains(&tool.group)).map(|tool| {
            rmcp::model::Tool::new(tool.name, tool.description, with_binary_arguments(tool.name, &tool.input_schema))
        });
        let file_tools = self.file_tools.iter().filter(|tool| enabled.contains(&tool.group)).map(|tool| {
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema)
        });
        let debug_enabled = self.debug.is_some() && enabled.contains(&Group::Debug);
        let debug_tools = self.debug_tools.iter().filter(|_| debug_enabled).map(|tool| {
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema)
        });
        let all = std::iter::once(meta).chain(tools).chain(file_tools).chain(debug_tools);
        Ok(ListToolsResult::with_all_items(all.collect()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.into_owned();
        let arguments = request.arguments.unwrap_or_default();
        if name == ENABLE_TOOLS {
            let result = match self.enable(&arguments) {
                Ok((listing, changed)) => {
                    if changed {
                        // A client that ignores the notification still sees the change in this result.
                        let _ = context.peer.notify_tool_list_changed().await;
                    }
                    CallToolResult::success(vec![ContentBlock::text(listing.to_string())])
                }
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
            return Ok(result.into());
        }
        if let Some(reason) = self.disabled_reason(&name) {
            let reason = if name == "import_pdb_names" {
                let apply_requested = arguments.get("apply").map_or(Some(false), Value::as_bool);
                tools::pdb_import_error(&reason, apply_requested)
            } else if name == "import_debug_layouts" {
                let apply_requested = arguments.get("apply").map_or(Some(false), Value::as_bool);
                tools::debug_layout_import_error(&reason, apply_requested)
            } else {
                reason
            };
            return Ok(CallToolResult::error(vec![ContentBlock::text(reason)]).into());
        }
        let server = self.clone();
        // Analysis is blocking work; keep it off the async runtime.
        let result = tokio::task::spawn_blocking(move || server.run(&name, arguments))
            .await
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        Ok(result.into())
    }
}

/// Serves MCP over stdin/stdout until the client disconnects, listing `groups` (and core) from the start, with
/// `packs` layered over the bundled databases and, when `debug` is given, the `debug` group. Debug sessions detach
/// when the client disconnects.
pub async fn serve_stdio(
    groups: BTreeSet<Group>,
    packs: Arc<Packs>,
    debug: Option<DebugRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut server = RampageServer::with_groups(groups).with_packs(packs);
    if let Some(registry) = debug {
        server = server.with_debug(registry);
    }
    server.serve(rmcp::transport::stdio()).await?.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn packs_keep_the_session_settings_and_clones_keep_their_own_groups() {
        let directory = std::env::temp_dir();
        let packs = Arc::new(Packs::default());
        let server = RampageServer::default().with_session(Session::with_capture_annotations(directory.clone()));
        let shared = server.clone();
        for server in [server.with_packs(Arc::clone(&packs)), shared.with_packs(Arc::clone(&packs))] {
            assert_eq!(server.session.capture_annotations(), Some(directory.as_path()));
            assert!(Arc::ptr_eq(&server.packs(), &packs));
        }

        let first = RampageServer::default();
        let second = first.clone();
        first.enable(json!({ "groups": ["detection"] }).as_object().unwrap()).unwrap();
        assert!(first.enabled().contains(&Group::Detection));
        assert_eq!(second.enabled(), BTreeSet::from([Group::Core]));
    }

    #[test]
    fn every_registered_workflow_is_served_in_its_group_and_named_in_the_instructions() {
        let server = RampageServer::default();
        let text = instructions(&Packs::default(), None);
        for workflow in rampage_api::workflows::WORKFLOWS {
            let name = workflow.name();
            assert!(server.catalog().any(|entry| entry == (workflow.group(), name)), "{name} is not served");
            assert!(text.contains(name), "{name} is missing from the instructions");
        }
    }

    /// docs/mcp.md's "Tool groups" list is the published tool catalog: every served tool appears once, under the
    /// group that serves it.
    #[test]
    fn the_documented_tool_groups_match_the_served_catalog() {
        let doc = include_str!("../../../docs/mcp.md");
        let start = doc.find("## Tool groups").expect("docs/mcp.md has a Tool groups section");
        let section = &doc[start..];
        let section = &section[..section.find("\nCalling `enable_tools`").expect("the group list ends")];
        let mut documented = BTreeMap::<String, Vec<String>>::new();
        let mut current = None;
        for line in section.lines() {
            let line = line.trim();
            let names: Vec<String> = line.split('`').skip(1).step_by(2).map(str::to_owned).collect();
            if let Some(rest) = line.strip_prefix("- `") {
                let group = rest.split('`').next().unwrap().to_owned();
                documented.entry(group.clone()).or_default().extend(names.into_iter().skip(1));
                current = Some(group);
            } else if let Some(group) = &current {
                documented.get_mut(group).unwrap().extend(names);
            }
        }
        let registry = DebugRegistry::new(&["127.0.0.1:2345".to_owned()]).unwrap();
        let server = RampageServer::default().with_debug(registry);
        let mut served = BTreeMap::<String, Vec<String>>::new();
        for (group, name) in server.catalog() {
            served.entry(group.name().to_owned()).or_default().push(name.to_owned());
        }
        for names in documented.values_mut().chain(served.values_mut()) {
            names.sort();
        }
        assert_eq!(documented, served);
    }

    #[test]
    fn initial_groups_come_from_the_flag_then_the_environment() {
        let all: BTreeSet<Group> = Group::ALL.into();
        assert_eq!(initial_groups(true, Some("detection")), Ok(all.clone()));
        assert_eq!(initial_groups(false, Some("all")), Ok(all));
        assert_eq!(initial_groups(false, None), Ok(BTreeSet::from([Group::Core])));
        assert_eq!(initial_groups(false, Some("")), Ok(BTreeSet::from([Group::Core])));
        assert_eq!(
            initial_groups(false, Some("detection, types")),
            Ok(BTreeSet::from([Group::Core, Group::Detection, Group::Types]))
        );
        assert!(initial_groups(false, Some("core,bogus")).unwrap_err().contains("unknown tool group `bogus`"));
    }
}
