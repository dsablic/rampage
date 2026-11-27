//! MCP server exposing rampage analysis to AI agents. It serves the tools of `rampage_api::tools`, the same ones
//! the UI's assistant uses, with each taking the path of the binary to work on (by default the one binary the
//! connection has opened). Tools are grouped: the server lists the groups it was started with (by default only core)
//! and an `enable_tools` meta-tool that adds the others.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rampage_api::flywheel::{Improve, ImproveTool, ObservationStore, ObservationTool, improve_tools, observation_tool};
use rampage_api::tools::{self, DebugTool, FileTool, Group, Tool};
use rampage_api::{DebugCancel, DebugConsent, DebugRegistry, FileOffset, Packs, Project, RawProjectRequest, Session};
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

/// Every tool name any rampage server can list, whatever its groups, consent or mode: the analysis, file, observation
/// and debug tools (the consent-gated write tools included), the improve tools of a corpus server, and
/// [`ENABLE_TOOLS`]. Sorted, without duplicates.
pub fn all_tool_names() -> Vec<&'static str> {
    let consent = DebugConsent { writes: true, kill: true };
    let mut names: Vec<&'static str> = tools::tools()
        .into_iter()
        .filter(|tool| !tool.interactive)
        .map(|tool| tool.name)
        .chain(tools::file_tools().into_iter().map(|tool| tool.name))
        .chain([observation_tool().name, ENABLE_TOOLS])
        .chain(tools::debug_tools_with(consent).into_iter().map(|tool| tool.name))
        .chain(improve_tools().into_iter().map(|tool| tool.name))
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The tool `_meta` key with which Claude Code lets a tool's results grow past its 50,000-character default before
/// it replaces them with a preview.
pub const MAX_RESULT_SIZE_META: &str = "anthropic/maxResultSizeChars";

/// The environment variable choosing the groups served from the start: `all`, or a comma-separated list.
pub const TOOLS_ENV: &str = "RAMPAGE_MCP_TOOLS";

/// The environment variable listing debug endpoints (`host:port` or `unix:/path`, comma-separated) the operator
/// allows, in addition to `--debug-endpoint`. Without any, the server has no `debug` group.
pub const DEBUG_ENDPOINTS_ENV: &str = "RAMPAGE_DEBUG_ENDPOINTS";

/// The environment variable that, set to `1`, allows the debug write tools, as `--debug-writes` does.
pub const DEBUG_WRITES_ENV: &str = "RAMPAGE_DEBUG_WRITES";

/// The environment variable that, set to `1`, allows `debug_disconnect` to kill, as `--debug-kill` does.
pub const DEBUG_KILL_ENV: &str = "RAMPAGE_DEBUG_KILL";

const ENABLE_TOOLS_DESCRIPTION: &str = "\
List rampage's tool groups (name, one-line description, tool count and names, whether enabled), or enable groups \
with `groups`, e.g. [\"detection\"] or [\"all\"]. Enabling adds the group's tools to the tool list and sends \
notifications/tools/list_changed. Without `groups` nothing changes.";

/// How a server decompiles, decided once at startup by [`decompiler_worker_startup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerStartup {
    /// The worker every decompilation must run in (`--require-worker`). `None` keeps per-binary discovery, which
    /// runs in-process when no worker is found.
    pub required: Option<PathBuf>,
    /// What to tell the operator on stderr before serving, if anything.
    pub warning: Option<String>,
}

/// The decompiler worker policy for a server: `require` is `--require-worker`, `found` what
/// [`rampage_api::find_decompiler_worker`] found, and `expected` where an installed worker would be (beside the
/// executable). Without a worker, decompilation runs in-process: the server warns, or under `require` pins
/// `expected` so that decompile refuses until a worker is installed there, never falling back to in-process.
pub fn decompiler_worker_startup(require: bool, found: Option<PathBuf>, expected: PathBuf) -> WorkerStartup {
    match (require, found) {
        (true, Some(worker)) => WorkerStartup { required: Some(worker), warning: None },
        (true, None) => WorkerStartup {
            warning: Some(format!(
                "rampage: --require-worker: no rampage-worker found at {} (or in RAMPAGE_WORKER); decompile will \
                 refuse until one is installed there",
                expected.display()
            )),
            required: Some(expected),
        },
        (false, Some(_)) => WorkerStartup { required: None, warning: None },
        (false, None) => WorkerStartup {
            required: None,
            warning: Some(format!(
                "rampage: warning: no rampage-worker found at {} (or in RAMPAGE_WORKER); decompile will run \
                 in-process, inside this server, not in the supervised worker. Install rampage-worker beside rampage, \
                 or pass --require-worker to refuse instead",
                expected.display()
            )),
        },
    }
}

/// How many characters of the server instructions Claude Code shows a model; it cuts the rest. Everything an agent
/// needs to start (the groups with their key tools, the first calls, the debug consent) comes before this mark.
pub const INSTRUCTIONS_SHOWN_CHARS: usize = 4096;

const INSTRUCTIONS_INTRO: &str = "\
rampage reverse-engineers PE, ELF and Mach-O binaries (x86, x86-64, AArch64, ARM/Thumb, MIPS, PowerPC, RISC-V, \
SPARC, s390x, m68k). Binary tools take the file's `path`. Addresses are hex strings like \"0x401000\"; most tools \
also accept a symbol, export or import name or sub_<hex>.

Only the core group is listed at first. enable_tools {\"groups\": [\"types\"]} (or [\"all\"]) adds groups to the \
tool list; without arguments it describes every group. A tool of a group not enabled fails, naming the \
group, and runs nothing. Clients that do not refresh their tool list: start `rampage mcp --all-tools` or set \
RAMPAGE_MCP_TOOLS (all, or a comma-separated list). Groups and their key tools:";

/// One line per group naming its key tools and the questions they answer, in the order of [`Group::ALL`]. The
/// group's full description is in `enable_tools`' listing.
fn group_summary(group: Group) -> &'static str {
    match group {
        Group::Core => {
            "triage_report, list_functions, decompile, evaluate_function (run a function on arguments instead of \
             simulating it), disassemble, xrefs, search, list_strings, list_imports; classes: language_metadata \
             (Objective-C classes, demangled names), objc_sends (objc_msgSend targets), class_evidence (C++ \
             vtables/RTTI); notes: rename, annotate_batch, record_finding, undo; patch_bytes; workflows find_main, \
             network_surface, persistence_surface, string_decoding, diff_builds."
        }
        Group::Detection => {
            "packer/compiler and library code: detect_tools, identify_functions (signatures), capabilities, \
             find_crypto, yara_scan and capa_detect (your rules); lock_mechanisms (repair locks)."
        }
        Group::Types => {
            "struct layouts by name, member path or offset: get_type and list_types read DWARF, PDB and Go runtime \
             types (stripped Go too), so never decode type descriptors by hand; declare_types, set_signature, \
             set_types, edit_variable and function_frame (locals), apply_data_type, import_debug_types, \
             import_pdb_names; firmware: import_svd (CMSIS-SVD register names), peripheral_access and peripheral_map (no SVD)."
        }
        Group::Runtime => {
            "memory snapshots: observe_pointer, compare_runtime_bytes, observe_indirect_branch; query_debugger \
             (an existing LLDB session)."
        }
        Group::Diagnostics => "decode trouble: analysis_diagnostics, entry_diagnostics, inspect_jump_table.",
        Group::DotNet => ".NET: dotnet_metadata (types, methods, P/Invokes), dotnet_il (CIL).",
        Group::Android => "APK/DEX: dex_metadata, dex_code.",
        Group::Carve => {
            "files inside files: carve (embedded files), archive_inventory (ZIP, ar libraries), fs_list/fs_extract \
             (filesystems), privacy_surface."
        }
        Group::Formats => {
            "build_info (Go modules, Rust dependencies), pe_resources, pe_load_config, exception_handlers (MSVC C++ \
             try/catch), pyinstaller_archive, wasm_module; firmware: integrity_checks (CRC/checksum fields; fix \
             after patch_bytes), export_image (patched HEX/S-record/binary)."
        }
        Group::Debug => {
            "a live target: debug_connect, debug_registers, debug_read_memory, \
             debug_breakpoints, debug_continue, debug_step, debug_snapshot, debug_disconnect."
        }
        Group::Improve => {
            "the flywheel corpus: corpus_failures (training split), propose_heuristic, evaluate_candidate (fast, \
             then heldout), promote_candidate."
        }
    }
}

const INSTRUCTIONS_START: &str = "\
Start with triage_report: an overview ending with next calls, each naming the `group` to enable. For one \
question: list_functions (name_contains), decompile, xrefs. What a function returns for given inputs: run it with \
evaluate_function, never work loops or bit operations out by hand. Before reporting a claim (what a function \
computes, who calls or references what), check it with check_claim. rename, annotate_batch and record_finding \
persist beside the binary.";

const INSTRUCTIONS_DEBUG_START: &str = "\
Debug: the tools drive a live process through a GDB remote stub the operator started; rampage launches and \
attaches to nothing. Breakpoints, continue and step change its state; debug_disconnect detaches. {consent} \
Endpoints: {endpoints}.";

const INSTRUCTIONS_OBSERVATIONS: &str = "\
report_observation (core) records an evidence-backed weak label for the corpus; it changes nothing else.";

/// The whole instructions of a server started with `--corpus`, which serves only the improve group.
const INSTRUCTIONS_CORPUS: &str = "\
This rampage server works on the flywheel corpus and serves only the improve group: it improves rampage's \
library-identification signatures. No analysis tool is served, and no other group can be enabled.

The corpus holds target libraries (zlib, lz4, cJSON) in an older version for training and their current version, \
held out, plus negative binaries of unrelated code. Held-out binaries are never shown, only the gate's verdict and \
overall delta. Only the target libraries' own functions are scored; runtime functions (libc, compiler runtime) are not.

- improve: corpus_failures (training failures grouped by masked body), propose_heuristic (rows into a scratch \
candidate; check each row's train_preview), evaluate_candidate (the fast gate on training data and negatives, then \
stage heldout), promote_candidate (only after a passing held-out gate). The gate decides, not the agent. Held-out \
evaluations per corpus are limited across all servers.";

const INSTRUCTIONS_DETAILS: &str = "\
Details for each area follow. The full text of every tool is in its description.";

const INSTRUCTIONS_USAGE: &str = "\
Once a session has opened one binary (a path with its raw selector, if any), later calls may omit `path` and \
`raw`: they default to it. Core: native-image tools reuse cached project analysis when needed; standalone file inspectors and decoders use \
explicit sources without that project cache. A symbol or name is accepted wherever a tool takes an address except \
comparison slots/ranges and branch observation windows. Enabling a group sends notifications/tools/list_changed. \
triage_report's overview covers layout, triage hints, the producing toolchain, capability tags, imports, notable \
strings and library functions. The other guided workflows compose the primitives the same way: find_main (the program's own entry \
logic), network_surface, persistence_surface (autostart locations, service and registry APIs), string_decoding \
(candidate byte-decoding loops with their call sites and encoded-looking data) and diff_builds; find_crypto \
(algorithm constants and crypto APIs with the code that uses them) is in detection. Every workflow finding carries \
its evidence, source tool and confidence, and every report states its limitations. triage and binary_info answer \
quick layout questions; list_functions pages with offset/limit; decompile (to C) is the best starting point to \
understand a function and falls back to function_summary, a structural CFG/reference summary, where no decompiler \
specification is available; or disassemble or function_graph it. list_imports and list_strings are good starting \
points for finding behavior. Record findings with rename and set_comment, or many at once with annotate_batch (all \
or nothing; check_names pre-flights candidate names). Annotations persist beside the \
binary and every client of the same binary, including the rampage UI, picks them up. record_finding keeps a ledger \
there of what you established, still don't know or want answered, with supporting tool calls and a status, so a \
later session or another agent can resume from list_findings. undo and redo revert or reapply one step, which may be \
a whole batch; when another client's edit blocks undoing a step, discard_undo drops it from the undo history (its \
edits stay) so earlier steps can be undone; it refuses a step undo could still revert unless force is true, since \
the user's UI may share that history. Memory snapshots and bundle directories use the same tools. inspect_raw_code \
provides bounded linear decoding of original-file windows with an explicitly asserted \
architecture/mode/orders/base, without native-image admission or target following. inspect_data provides bounded \
native bytes/word candidates without discovery or sidecars; names resolve only through retained metadata. \
decode_file_range instead accepts an explicit regular-file range and codec without an executable header. \
Given a folder, list_dir lists it (kind, size and sniffed format per entry). \
An object file (.o) is laid out from 0x10000 with relocations applied and its undefined symbols in an extern \
segment; a static library member opens as path `lib.a(member.o)` (`member.o#N` where names repeat); \
archive_inventory lists the members. \
file_layout maps any file or range (padding, entropy, string clusters, hashes, hints) as a first look at firmware; \
its compressed_component_candidate hints give a payload range and decoded-size words for probe_compression, whose \
ranked decode_arguments go to decode_file_range unchanged; both return open_as_raw, which with a profile and \
base_address added is the `raw` selector for the decoded code, base_candidates (ranked load addresses for the \
decoded bytes as Cortex-M code, with evidence; next names one only when it is clearly strongest) and, when words \
just before the stream hold its length and decoded size, container_record (field roles, checksum, base_hints). \
Its transient decoded preview uses decoded offsets, not source offsets or load addresses; supplied sizes and \
successful decoding do not authenticate content or prove stream boundaries. Tools whose schema has a `raw` \
object open that explicit file range as a headerless Raw project with a closed profile instead of a native image \
(never with arch/image_offset/image_length; null means absent). `raw` fields: profile (one of the Raw profiles \
listed at the end), offset (default 0) and length (default the rest of the file; original-file bytes, up to \
128 KiB, 4 MiB for ARM:LE:32:Cortex, \
the MIPS profiles and Xtensa), \
base_address, optional entry and up to 8192 seeds (internal code-space byte coordinates, even for word-addressed \
processors; hex strings or integers). The mapping is an analyst assertion; annotations are memory-only for this \
server and interpretation. Cortex-M flash (profile cortex-m): vector_table true reads the vector table at \
base_address (or give its address); accepted Thumb handlers become the entry and seeds, and binary_info reports \
every word with its verdict and, for a base that misplaces the handlers, a base_address suggestion it never applies. \
pointer_tables true also seeds functions from tables of Thumb code pointers (handler arrays, command tables) that \
show prologue or call evidence; binary_info reports each table, accepted or refused, with evidence per entry. \
Unset, the scan runs by itself when discovery finds fewer than one function per 16 KiB of code or covers under \
an eighth of it (raw.pointer_tables.automatic and a list_functions note say so); false never scans. Every code \
region is scanned, and discovery also follows code pointers in records the code addresses (thread definitions). \
The reset code at the entry is followed (a bounded interpreter; nothing runs natively) for the sections startup \
code copies to their run addresses and the RAM it zeroes: binary_info's raw.scatter_load lists each copy \
(destination, length, source, store sites, routine) and, by default, a complete copy from mapped bytes to an \
unmapped destination is mapped there (code when the copy ran and was not stored into afterwards, else RAM; zero \
fill as unbacked RAM; a copy cut off by a skipped call or an unclean stop is reported only) and the jump into \
the copied code is seeded; scatter_load false reports them only. \
MIPS32 boot ROMs and bare-metal code (profile mips or mipsel): \
the entry defaults to base_address (the reset vector, 0xbfc00000 on MIPS32 boot ROMs); find_main follows the reset \
code's jump to its C entry, and decompile and evaluate_function run. \
ESP32/ESP8266 (profile xtensa, alias esp32 or esp8266): format esp maps the app image at offset (default 0; \
0x10000 in an ESP32 flash dump) by its segment headers, entry included; binary_info's raw.esp reports chip, ABI, \
segments, checksum, SHA-256 and esp_app_desc. \
For Cortex-M, binary_info's raw.base_check judges base_address against load-address candidates (pointer words \
landing on prologues and strings, literal constants, the vector table, a fetch outside every region by the reset \
code) and, when it looks wrong, names the better base in next. \
When Raw discovery is that sparse, list_functions (and binary_info \
afterwards) return a one-line next naming the options still off (pointer_tables false, unmapped startup copies). \
Cortex-M only: regions (up to 15) maps more of the same file beside the primary code region, each {kind: code|data|\
ram, base_address, offset, length, decode?, from?, writable?}: e.g. a second stage at its RAM base \
{\"kind\":\"code\",\"base_address\":\"0x20000000\",\"offset\":\"0x400\",\"length\":128}; ram is writable (its bytes \
are never folded as constants) and may omit offset for unbacked RAM/MMIO; decode {codec, lzss?, \
expected_output_size, initial_write_offset?, dictionary_fill?, timeout_ms?} maps decode_file_range's in-memory \
output of the range instead; from {region: 0|\"primary\"|n, offset} (no offset) copies length bytes of the primary \
region or regions[n-1] (decoded bytes too), as startup code copies code to its run address. A top-level \
raw.decode (same shape, any profile) maps the decoded output as the primary code region (length then counts \
encoded bytes), so vector_table, pointer_tables and seeds read decoded bytes. Overlaps are refused; references, \
calls and seeds cross regions; binary_info lists every region with its SHA-256 and source (file range, decode \
receipt, slice, scatter_load copy, records). format ihex|srec reads Intel HEX or S-records instead (omit offset/length/base_address): each contiguous run is a code region, a regions entry \
without offset matching a run exactly states its kind, and the start-address record becomes the entry, reported \
with its verdict. \
Cortex-M only: writable (top level for the primary region, or on a code region) says the program stores into that \
code: the decompiler maps it rwx so globals in it are never folded (function bodies, literal pools and string \
literals still are). Unset, code mapped in SRAM (0x20000000-0x3fffffff) is writable, and so is a decoded primary \
region two or more functions store into; binary_info reports writable and writable_reason per region.

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
set_signature, set_types and set_global persist C declarations. import_pdb_names requires an explicit pdb path \
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
Debug: debug_connect opens a session (the stub must already be running), then debug_status, debug_registers, \
debug_read_memory and debug_modules inspect the stopped target and debug_snapshot writes a rampage-snapshot-v1 file \
the other tools can open. debug_bind (or debug_connect with path) binds a binary to a runtime module with a verified \
slide; then breakpoints take a static_address or function name, stops report locations (function, offset, \
show_address), debug_registers annotate: true says what values point at, and debug_evidence gives an evidence item \
for record_finding. Execution control is all-stop: debug_breakpoints sets hardware or software breakpoints and \
watchpoints, debug_continue resumes without delivering a signal and waits for the stop, debug_wait waits again, \
debug_interrupt stops a running target, debug_step single-steps, steps over calls (over) or out of a function from \
its entry (out). Each stop is a new epoch; pass the epoch you last saw to execution tools (stale_epoch otherwise) \
and optionally to reads. debug_disconnect removes breakpoints before it detaches. Runtime bytes stay local.";

const DEBUG_READ_ONLY: &str = "Nothing writes registers or memory or kills: the operator did not allow it.";

const DEBUG_WRITES: &str = "The operator allowed writes (--debug-writes): debug_write_memory and \
debug_write_register; write only when the task needs it.";

const DEBUG_KILL: &str = "The operator allowed killing (--debug-kill): debug_disconnect with kill: true.";

const DEBUG_WRITES_DETAIL: &str = "The write tools write a stopped target at your epoch, reading the old bytes first \
(pass expect to refuse a stale view) and reading back (verified: false when the target dropped the write, as flash \
often does); rampage never writes on its own.";

const DEBUG_KILL_DETAIL: &str = "debug_disconnect with kill: true removes breakpoints and kills the target instead \
of detaching.";

/// The server instructions: what an agent needs to start, within the first [`INSTRUCTIONS_SHOWN_CHARS`], then the
/// details for clients that read the whole text.
fn instructions(packs: &Packs, debug: Option<&DebugRegistry>, improve: bool, observations: bool) -> String {
    if improve {
        return INSTRUCTIONS_CORPUS.to_owned();
    }
    let groups: String = available_groups(debug.is_some(), improve)
        .iter()
        .map(|group| format!("\n- {}: {}", group.name(), group_summary(*group)))
        .collect();
    let mut text = format!("{INSTRUCTIONS_INTRO}{groups}\n\n{INSTRUCTIONS_START}");
    if let Some(registry) = debug {
        let consent = registry.consent();
        let allowed: Vec<&str> = [(consent.writes, DEBUG_WRITES), (consent.kill, DEBUG_KILL)]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, text)| *text)
            .collect();
        let consent = if allowed.is_empty() { DEBUG_READ_ONLY.to_owned() } else { allowed.join(" ") };
        text.push_str("\n\n");
        text.push_str(
            &INSTRUCTIONS_DEBUG_START
                .replace("{consent}", &consent)
                .replace("{endpoints}", &registry.endpoints().join(", ")),
        );
    }
    if observations {
        text.push_str(&format!("\n\n{INSTRUCTIONS_OBSERVATIONS}"));
    }
    // Only a server given packs loads them here; the problem count must be known before any tool runs.
    if packs.configured() {
        let problems = packs.problems().len();
        text.push_str(&format!(
            "\n\nData packs: {} loaded, {problems} problems; list_packs (detection) shows each.",
            packs.loaded().iter().filter(|pack| pack.error.is_none()).count()
        ));
    }
    text.push_str(&format!("\n\n{INSTRUCTIONS_DETAILS}\n\n{INSTRUCTIONS_USAGE}"));
    if let Some(registry) = debug {
        text.push_str(&format!("\n\n{INSTRUCTIONS_DEBUG}"));
        let consent = registry.consent();
        for (on, detail) in [(consent.writes, DEBUG_WRITES_DETAIL), (consent.kill, DEBUG_KILL_DETAIL)] {
            if on {
                text.push(' ');
                text.push_str(detail);
            }
        }
    }
    if packs.configured() {
        text.push_str(
            "\n\nData pack problems are packs rejected or contents that did not load. Detection results that \
             consult packs (identify_functions, detect_tools, yara_scan, capa_detect) list the problems bearing on \
             them in `warnings`.",
        );
    }
    let profiles: Vec<_> = rampage_loaders::RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    text.push_str(&format!("\n\nRaw profiles: {}.", profiles.join(", ")));
    text
}

/// The groups to serve from the start: every group with `all_tools`, else those `env` names (`all` or a
/// comma-separated list), else core alone. Core is always served.
pub fn initial_groups(all_tools: bool, env: Option<&str>) -> Result<BTreeSet<Group>, String> {
    initial_groups_with_debug(all_tools, env, false)
}

/// [`initial_groups`] for a server that has the `debug` group when `debug` is true.
pub fn initial_groups_with_debug(all_tools: bool, env: Option<&str>, debug: bool) -> Result<BTreeSet<Group>, String> {
    initial_groups_with(all_tools, env, debug, false)
}

/// [`initial_groups`] for a server that has the `debug` group when `debug` is true and the `improve` group when
/// `improve` is true.
pub fn initial_groups_with(
    all_tools: bool,
    env: Option<&str>,
    debug: bool,
    improve: bool,
) -> Result<BTreeSet<Group>, String> {
    let available = available_groups(debug, improve);
    if improve {
        // A corpus server serves the improve group alone, whatever else was asked for.
        for name in env.unwrap_or("").split(',').map(str::trim).filter(|name| !name.is_empty()) {
            if name != "all" {
                parse_group(name, debug, improve)?;
            }
        }
        return Ok(BTreeSet::from([Group::Improve]));
    }
    if all_tools {
        return Ok(available.into_iter().collect());
    }
    let mut groups = BTreeSet::from([Group::Core]);
    for name in env.unwrap_or("").split(',').map(str::trim).filter(|name| !name.is_empty()) {
        if name == "all" {
            groups.extend(available.iter().copied());
        } else {
            groups.extend(parse_group(name, debug, improve)?.groups);
        }
    }
    Ok(groups)
}

/// Every group a server has: [`Group::ALL`] and `debug` when debug endpoints are configured; a server started with
/// a corpus has the `improve` group alone, so a proposer can reach no tool that reads binaries.
fn available_groups(debug: bool, improve: bool) -> Vec<Group> {
    if improve {
        return vec![Group::Improve];
    }
    Group::ALL.into_iter().chain(debug.then_some(Group::Debug)).collect()
}

fn parse_group(name: &str, debug: bool, improve: bool) -> Result<Resolved, String> {
    if improve {
        return if name == Group::Improve.name() {
            Ok(Resolved::group(Group::Improve))
        } else {
            Err(format!("this server was started with --corpus and has only the improve group, not `{name}`"))
        };
    }
    if debug && name == Group::Debug.name() {
        return Ok(Resolved::group(Group::Debug));
    }
    let guess = name.to_ascii_lowercase();
    if let Some(&(_, groups, reason)) = GROUP_ALIASES.iter().find(|(alias, _, _)| *alias == guess) {
        return Ok(Resolved { groups: groups.to_vec(), reason: Some(reason) });
    }
    name.parse().map(Resolved::group)
}

/// The groups a requested name enables, and for a name that is not a group's own, why those.
struct Resolved {
    groups: Vec<Group>,
    reason: Option<&'static str>,
}

impl Resolved {
    fn group(group: Group) -> Self {
        Self { groups: vec![group], reason: None }
    }
}

/// Group names agents guess, with the groups that hold the tools they mean and why. `core` is always served.
const GROUP_ALIASES: [(&str, &[Group], &str); 14] = [
    ("firmware", FIRMWARE, FIRMWARE_GROUPS),
    ("embedded", FIRMWARE, FIRMWARE_GROUPS),
    ("mcu", FIRMWARE, FIRMWARE_GROUPS),
    ("raw", FIRMWARE, FIRMWARE_GROUPS),
    ("svd", &[Group::Types], "CMSIS-SVD peripheral maps (import_svd, peripheral_access, peripheral_map) are in types"),
    ("peripherals", &[Group::Types], "peripheral maps (import_svd, peripheral_access, peripheral_map) are in types"),
    ("signatures", &[Group::Detection], "library signatures (identify_functions, build_signatures) are in detection"),
    ("yara", &[Group::Detection], "yara_scan is in detection"),
    ("crypto", &[Group::Detection], "find_crypto is in detection"),
    ("apk", &[Group::Android], "APK and DEX tools are in android"),
    ("dex", &[Group::Android], "APK and DEX tools are in android"),
    ("filesystem", &[Group::Carve], "filesystem images (fs_list, fs_extract) are in carve"),
    ("classes", &[Group::Core], CLASS_GROUP),
    ("rtti", &[Group::Core], CLASS_GROUP),
];

/// The groups holding the firmware tools.
const FIRMWARE: &[Group] = &[Group::Types, Group::Formats, Group::Carve];

/// Why a guessed `firmware` group enables [`FIRMWARE`]: no one group holds the firmware tools.
const FIRMWARE_GROUPS: &str = "no group is named firmware, so the three that hold its tools: CMSIS-SVD peripheral maps \
    (import_svd, peripheral_access, peripheral_map) in types, integrity_checks and export_image in formats, and \
    carve, fs_list and diff_firmware in carve; headerless images, Intel HEX and S-records open in core (`raw` on any \
    raw-capable tool)";

/// Why a guessed `classes` group enables only core.
const CLASS_GROUP: &str = "class metadata (class_evidence: C++ vtables/RTTI; language_metadata: demangled names, \
    Objective-C classes) is in core, which is always served";

/// Parses the operator's debug endpoints: each `--debug-endpoint` value, then the comma-separated `env` list.
/// `None` when there are none, so the server has no `debug` group.
pub fn debug_registry(flags: &[String], env: Option<&str>) -> Result<Option<DebugRegistry>, String> {
    debug_registry_with(flags, env, DebugConsent::default())
}

/// [`debug_registry`] allowing what `consent` allows. Consent without any endpoint is an error: it would allow
/// nothing, and an operator who passed it expected otherwise.
pub fn debug_registry_with(
    flags: &[String],
    env: Option<&str>,
    consent: DebugConsent,
) -> Result<Option<DebugRegistry>, String> {
    let endpoints: Vec<String> = flags
        .iter()
        .map(|flag| flag.trim().to_owned())
        .chain(env.unwrap_or("").split(',').map(|item| item.trim().to_owned()))
        .filter(|endpoint| !endpoint.is_empty())
        .collect();
    if endpoints.is_empty() {
        if consent.writes || consent.kill {
            return Err(format!(
                "--debug-writes and --debug-kill ({DEBUG_WRITES_ENV}, {DEBUG_KILL_ENV}) need at least one debug \
                 endpoint (--debug-endpoint or {DEBUG_ENDPOINTS_ENV})"
            ));
        }
        return Ok(None);
    }
    DebugRegistry::new(&endpoints).map(|registry| Some(registry.with_consent(consent)))
}

/// The operator's write and kill consent: each flag, or its environment variable set to `1`. Any other value of a
/// variable that is set (except empty or `0`) is an error rather than a guess.
pub fn debug_consent(
    writes_flag: bool,
    kill_flag: bool,
    writes_env: Option<&str>,
    kill_env: Option<&str>,
) -> Result<DebugConsent, String> {
    let parse = |name: &str, value: Option<&str>| match value.map(str::trim) {
        None | Some("" | "0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!("{name} must be 1 (or 0 or empty for off), not `{other}`")),
    };
    Ok(DebugConsent {
        writes: writes_flag || parse(DEBUG_WRITES_ENV, writes_env)?,
        kill: kill_flag || parse(DEBUG_KILL_ENV, kill_env)?,
    })
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
                "description": "Universal Mach-O slice (x86_64, aarch64, ...); default x86_64, then aarch64, then x86."
            }),
        );
        // Not `offset`, which many tools already take for paging. docs/mcp.md has the details.
        properties.insert(
            "image_offset".to_owned(),
            json!({
                "type": ["string", "integer", "null"],
                "description": "Open the ELF, PE or Mach-O image embedded at this file offset instead (e.g. a \
                                carve candidate's); its annotations are kept apart."
            }),
        );
        properties.insert(
            "image_length".to_owned(),
            json!({
                "type": ["string", "integer", "null"],
                "description": "With image_offset: the image's length; default from its headers."
            }),
        );
        if tools::raw_capable(name) {
            properties.insert(RAW.to_owned(), compact_raw_selector());
        }
    }
    // `path` is optional: a call without it works on the session's target (see `RampageServer::default_target`).
    schema
}

/// File tools whose `path` names the binary or image they read, so it defaults to the session's target like a
/// project tool's. Tools whose `path` may be a directory, or that compare two files, are left out.
const SESSION_PATH_FILE_TOOLS: [&str; 15] = [
    "inspect_sleigh",
    "inspect_raw_code",
    "decode_file_range",
    "write_decoded_range",
    "probe_compression",
    "file_layout",
    "inspect_data",
    "archive_inventory",
    "fs_list",
    "fs_extract",
    "carve",
    "pyinstaller_archive",
    "wasm_module",
    "dex_metadata",
    "dex_code",
];

/// A file tool's listed schema: `path` is optional on the tools where it defaults to the session's target.
/// `build_signatures` on a static library: every relocatable member's functions, written to `output`.
fn library_signatures(
    path: &Path,
    arguments: &Map<String, Value>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Value, String> {
    if arguments.get("fuzzy_request").is_some_and(|value| !value.is_null()) {
        return Err("fuzzy_request builds from a binary, not a static library; open one member as the path".to_owned());
    }
    for key in ["image_offset", "image_length"] {
        if arguments.get(key).is_some_and(|value| !value.is_null()) {
            return Err(format!("`{key}` selects an image in a binary; a static library is read whole"));
        }
    }
    let output = arguments.get("output").and_then(Value::as_str).ok_or("`output` is required")?;
    let arch = match arguments.get("arch") {
        None | Some(Value::Null) => None,
        Some(Value::String(arch)) => Some(arch.parse::<Arch>()?),
        Some(_) => return Err("`arch` must be an architecture string or null".to_owned()),
    };
    let built = rampage_api::build_library_signatures(path, arch, cancelled).map_err(|error| error.to_string())?;
    std::fs::write(output, built.database.to_json()).map_err(|error| format!("cannot write {output}: {error}"))?;
    let mut report = serde_json::to_value(&built.report).map_err(|error| error.to_string())?;
    report["output"] = Value::String(output.to_owned());
    Ok(report)
}

fn file_tool_schema(tool: &FileTool) -> Map<String, Value> {
    let mut schema = tool.input_schema.as_object().cloned().unwrap_or_default();
    if SESSION_PATH_FILE_TOOLS.contains(&tool.name)
        && let Some(Value::Array(required)) = schema.get_mut("required")
    {
        required.retain(|name| name != "path");
        if required.is_empty() {
            schema.remove("required");
        }
    }
    schema
}

/// Binary targets one connection keeps at most; the oldest is forgotten first.
const MAX_TARGETS: usize = 16;

/// A binary a connection has opened: the path as the call gave it, the selectors it was opened with (`raw`, or
/// arch/image_offset/image_length) and what was opened, so that two spellings of one Raw interpretation (a profile
/// alias, `0` and `"0x0"`) are one target.
#[derive(Debug, Clone)]
struct Target {
    path: String,
    selectors: Map<String, Value>,
    identity: (PathBuf, String),
    /// An Intel HEX or S-record file: its `raw` reads the records, not the file's bytes.
    records: bool,
}

impl Target {
    /// The target as an error lists it: its path and selector summary.
    fn summary(&self) -> String {
        if self.selectors.is_empty() {
            return self.path.clone();
        }
        let selectors: Vec<String> = self.selectors.iter().map(|(key, value)| format!("{key}={value}")).collect();
        format!("{} with {}", self.path, selectors.join(", "))
    }
}

/// The selectors a call to a project tool gives besides `path`.
const SELECTORS: [&str; 4] = [RAW, "arch", "image_offset", "image_length"];

/// What identifies a Raw project as a session target: its interpretation (bytes, profile, mapping, entry, seeds).
fn raw_identity(project: &Project) -> String {
    match project.binary.raw_interpretation_identity() {
        Ok(Some(identity)) => format!("raw:{}", identity.sha256),
        _ => format!("raw:{:p}", std::ptr::from_ref(project)),
    }
}

/// The targets as an error lists them.
fn target_listing(targets: &[Target]) -> String {
    let names: Vec<String> = targets.iter().map(|target| format!("`{}`", target.summary())).collect();
    names.join("; ")
}

/// Whether inspect_data cannot read the file at `path` as a native image (no executable header it admits), so it
/// would fail without a Raw selector.
fn native_headerless(path: &str) -> bool {
    rampage_loaders::Binary::open_image_metadata(path, None, None).is_err()
}

/// `result` naming the session target its call was filled from: a `session_target` field on a JSON object, or a
/// second content block for any other result.
fn with_session_target(mut result: CallToolResult, target: &str) -> CallToolResult {
    if result.is_error == Some(true) {
        return result;
    }
    let text = result.content.first().and_then(|content| content.as_text()).map(|text| text.text.clone());
    match text.as_deref().map(serde_json::from_str::<Value>) {
        Some(Ok(Value::Object(mut object))) => {
            object.insert("session_target".to_owned(), Value::String(target.to_owned()));
            result.content[0] = ContentBlock::text(Value::Object(object).to_string());
        }
        _ => result.content.push(ContentBlock::text(format!("session_target: {target}"))),
    }
    result
}

/// The canonical form of `path`, or `path` itself when it cannot be resolved.
fn canonical(path: &str) -> PathBuf {
    Path::new(path).canonicalize().unwrap_or_else(|_| PathBuf::from(path))
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
                for key in ["description", "title", "examples", "enum", "default"] {
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
    // Each region's shape (and its decoder-provider parameters) is stated once in the server instructions.
    raw["properties"]["regions"] = json!({ "type": ["array", "null"], "maxItems": 15, "items": { "type": "object" } });
    raw["properties"]["decode"] = json!({ "type": ["object", "null"] });
    strip(&mut raw);
    raw["type"] = json!(["object", "null"]);
    raw["description"] = json!("Headerless Raw project of path's byte range; see the server instructions.");
    raw
}

/// Drops the `$defs` no longer referenced once a tool's own `raw` schema is replaced by the compact selector, so
/// the full Raw request shape is not listed beside it.
fn remove_unreferenced_definitions(schema: &mut Map<String, Value>) {
    fn references(value: &Value, found: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    match value {
                        Value::String(target) if key == "$ref" => {
                            found.insert(target.trim_start_matches("#/$defs/").to_owned());
                        }
                        _ => references(value, found),
                    }
                }
            }
            Value::Array(values) => values.iter().for_each(|value| references(value, found)),
            _ => {}
        }
    }
    let Some(Value::Object(mut definitions)) = schema.remove("$defs") else { return };
    let mut live = BTreeSet::new();
    schema.values().for_each(|value| references(value, &mut live));
    let mut pending: Vec<String> = live.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        let mut found = BTreeSet::new();
        if let Some(definition) = definitions.get(&name) {
            references(definition, &mut found);
        }
        pending.extend(found.into_iter().filter(|name| live.insert(name.clone())));
    }
    definitions.retain(|name, _| live.contains(name));
    if !definitions.is_empty() {
        schema.insert("$defs".to_owned(), Value::Object(definitions));
    }
}

/// The explicit refusal of a `raw` selector on a tool that cannot serve Raw Projects.
fn raw_refusal(name: &str) -> String {
    format!(
        "tool {name} does not accept Raw projects; nothing was run. Raw-capable tools: {}",
        tools::RAW_CAPABLE_TOOLS.iter().chain(&tools::RAW_CAPABLE_FILE_TOOLS).copied().collect::<Vec<_>>().join(", ")
    )
}

fn enable_tools_schema(debug: bool, improve: bool) -> Map<String, Value> {
    let names: Vec<&str> = available_groups(debug, improve).iter().map(|group| group.name()).chain(["all"]).collect();
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

/// One MCP connection's server. The loaded binaries are shared with its clones; the enabled groups and the session's
/// targets are not, so a clone serving another connection starts from the groups enabled when it was cloned and with
/// no target. Debug sessions belong to the connection: clones share them, and they detach when the server and its
/// clones are dropped.
pub struct RampageServer {
    session: Arc<Session>,
    tools: Arc<Vec<Tool>>,
    file_tools: Arc<Vec<FileTool>>,
    debug: Option<Arc<DebugRegistry>>,
    debug_tools: Arc<Vec<DebugTool>>,
    improve: Option<Arc<Improve>>,
    improve_tools: Arc<Vec<ImproveTool>>,
    observations: Option<Arc<ObservationStore>>,
    observation_tool: Arc<ObservationTool>,
    /// Paths no tool may read: the flywheel's working directory (corpus binaries, truth caches) on a corpus server.
    guarded: Arc<Vec<PathBuf>>,
    enabled: Mutex<BTreeSet<Group>>,
    /// The binaries this connection has opened, oldest first: a call without `path` works on the only one.
    /// Shared only with the per-call copy each call runs on ([`RampageServer::for_call`]).
    targets: Arc<Mutex<Vec<Target>>>,
}

impl Clone for RampageServer {
    fn clone(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
            tools: Arc::clone(&self.tools),
            file_tools: Arc::clone(&self.file_tools),
            debug: self.debug.clone(),
            debug_tools: Arc::clone(&self.debug_tools),
            improve: self.improve.clone(),
            improve_tools: Arc::clone(&self.improve_tools),
            observations: self.observations.clone(),
            observation_tool: Arc::clone(&self.observation_tool),
            guarded: Arc::clone(&self.guarded),
            enabled: Mutex::new(self.enabled()),
            targets: Arc::default(),
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
            improve: None,
            improve_tools: Arc::new(improve_tools()),
            observations: None,
            observation_tool: Arc::new(observation_tool()),
            guarded: Arc::new(Vec::new()),
            enabled: Mutex::new(enabled),
            targets: Arc::default(),
        }
    }

    /// This server serving only the `improve` group over `improve`'s corpus: no analysis tool, no other group,
    /// and no tool argument may name a file under the corpus or the flywheel's working directory.
    pub fn with_improve(self, improve: Arc<Improve>) -> Self {
        let mut guarded = vec![improve.corpus().root.clone(), improve.paths().root().to_owned()];
        guarded.extend(guarded.clone().iter().filter_map(|path| path.canonicalize().ok()));
        Self {
            improve: Some(improve),
            guarded: Arc::new(guarded),
            enabled: Mutex::new(BTreeSet::from([Group::Improve])),
            ..self
        }
    }

    /// The argument naming a guarded path, if any: every string value is checked, at any depth.
    fn guarded_argument(&self, arguments: &Map<String, Value>) -> Option<String> {
        fn strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
            match value {
                Value::String(text) => out.push(text),
                Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
                Value::Object(map) => map.values().for_each(|item| strings(item, out)),
                _ => {}
            }
        }
        if self.guarded.is_empty() {
            return None;
        }
        let mut texts = Vec::new();
        arguments.values().for_each(|value| strings(value, &mut texts));
        let base = std::env::current_dir().unwrap_or_default();
        texts
            .into_iter()
            .find(|text| {
                let path = base.join(text);
                // A path that does not exist yet (a file a tool would write) resolves through its parent, as
                // the writers check it.
                let resolved = path.canonicalize().unwrap_or_else(|_| {
                    match (path.parent().and_then(|parent| parent.canonicalize().ok()), path.file_name()) {
                        (Some(parent), Some(name)) => parent.join(name),
                        _ => path.clone(),
                    }
                });
                self.guarded.iter().any(|root| resolved.starts_with(root))
            })
            .map(str::to_owned)
    }

    /// This server with `report_observation` (in core) recording into `store`.
    pub fn with_observations(self, store: Arc<ObservationStore>) -> Self {
        Self { observations: Some(store), ..self }
    }

    /// This server with the `debug` group, connecting only to the endpoints `registry` allows. Its sessions belong
    /// to this server's connection.
    pub fn with_debug(self, registry: DebugRegistry) -> Self {
        // The write tools and the kill option are listed only with the operator's consent.
        let debug_tools = Arc::new(tools::debug_tools_with(registry.consent()));
        Self { debug: Some(Arc::new(registry)), debug_tools, ..self }
    }

    fn groups(&self) -> Vec<Group> {
        available_groups(self.debug.is_some(), self.improve.is_some())
    }

    /// This server opening binaries in `session`, with its settings.
    pub fn with_session(self, session: Session) -> Self {
        Self { session: Arc::new(session), ..self }
    }

    /// This server decompiling only in the supervised worker at `executable`, never in-process (see
    /// [`Session::requiring_decompiler_worker`]), keeping its session's other settings.
    pub fn requiring_decompiler_worker(self, executable: PathBuf) -> Self {
        let session = Arc::try_unwrap(self.session).unwrap_or_else(|shared| shared.unloaded_copy());
        Self { session: Arc::new(session.requiring_decompiler_worker(executable)), ..self }
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

    /// Every tool this server can serve, with its group, whether enabled or not. A corpus server serves the
    /// improve tools alone.
    fn catalog(&self) -> impl Iterator<Item = (Group, &'static str)> + '_ {
        let analysis = self.improve.is_none();
        let tools = self.tools.iter().filter(move |_| analysis).map(|tool| (tool.group, tool.name));
        let file_tools = self.file_tools.iter().filter(move |_| analysis).map(|tool| (tool.group, tool.name));
        let debug =
            (analysis && self.debug.is_some()).then(|| self.debug_tools.iter().map(|tool| (Group::Debug, tool.name)));
        let improve = self.improve.is_some().then(|| self.improve_tools.iter().map(|tool| (Group::Improve, tool.name)));
        let observation = (analysis && self.observations.is_some())
            .then_some((self.observation_tool.group, self.observation_tool.name));
        tools
            .chain(file_tools)
            .chain(observation)
            .chain(debug.into_iter().flatten())
            .chain(improve.into_iter().flatten())
    }

    /// Enables the groups `arguments` names, returning the groups with their tools and the ones newly enabled.
    fn enable(&self, arguments: &Map<String, Value>) -> Result<(Value, bool), String> {
        let mut requested = BTreeSet::new();
        let mut resolved = Vec::new();
        match arguments.get("groups") {
            None | Some(Value::Null) => {}
            Some(Value::Array(names)) => {
                for name in names {
                    match name.as_str() {
                        Some("all") => requested.extend(self.groups()),
                        Some(name) => {
                            let found = parse_group(name, self.debug.is_some(), self.improve.is_some())?;
                            requested.extend(found.groups.iter().copied());
                            if let Some(reason) = found.reason {
                                let groups: Vec<&str> = found.groups.iter().map(|group| group.name()).collect();
                                resolved.push(json!({ "name": name, "groups": groups, "reason": reason }));
                            }
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
        let mut listing = json!({ "newly_enabled": newly_enabled, "groups": groups });
        if !resolved.is_empty() {
            // Names that are not a group's own: the groups each enabled, and why.
            listing["resolved"] = Value::Array(resolved);
        }
        Ok((listing, !newly.is_empty()))
    }

    /// The input schema `list_tools` gives `name`, when this server serves it.
    fn advertised_schema(&self, name: &str) -> Option<Value> {
        if let Some(tool) = self.tools.iter().find(|tool| tool.name == name) {
            return Some(Value::Object(with_binary_arguments(name, &tool.input_schema)));
        }
        if let Some(tool) = self.file_tools.iter().find(|tool| tool.name == name) {
            return Some(Value::Object(file_tool_schema(tool)));
        }
        if self.improve.is_some()
            && let Some(tool) = self.improve_tools.iter().find(|tool| tool.name == name)
        {
            return Some(tool.input_schema.clone());
        }
        if self.observations.is_some() && self.observation_tool.name == name {
            return Some(self.observation_tool.input_schema.clone());
        }
        // Debug tools check their own arguments, refusing options the operator has not allowed by name.
        None
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
    /// `used` is the session target the call's arguments were filled from, if any; the result names it.
    fn run(
        &self,
        name: &str,
        arguments: Map<String, Value>,
        cancel: &DebugCancel,
        used: Option<String>,
    ) -> CallToolResult {
        let used = RefCell::new(used);
        let result = self.dispatch(name, arguments, cancel, &used);
        match used.into_inner() {
            Some(target) => with_session_target(result, &target),
            None => result,
        }
    }

    fn dispatch(
        &self,
        name: &str,
        mut arguments: Map<String, Value>,
        cancel: &DebugCancel,
        used: &RefCell<Option<String>>,
    ) -> CallToolResult {
        if let Some(path) = self.guarded_argument(&arguments) {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "`{path}` is inside the flywheel corpus or its working directory, which no tool may read on this \
                 server; nothing was run"
            ))]);
        }
        if self.improve.is_some() && !self.improve_tools.iter().any(|tool| tool.name == name) {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "this server was started with --corpus and serves only the improve group; `{name}` is not served"
            ))]);
        }
        // `raw: null` asks for the native image: no Raw selector is reused for it.
        let native_asked = arguments.get(RAW).is_some_and(Value::is_null);
        let raw = match arguments.remove(RAW).filter(|raw| !raw.is_null()).map(raw_object).transpose() {
            Ok(raw) => raw,
            Err(message) => return CallToolResult::error(vec![ContentBlock::text(message)]),
        };
        if let (Some(registry), Some(tool)) = (&self.debug, self.debug_tools.iter().find(|tool| tool.name == name)) {
            if raw.is_some() {
                return CallToolResult::error(vec![ContentBlock::text(raw_refusal(name))]);
            }
            // Bound projects open in the server's session, sharing its cache with the project tools.
            return match tool.call_in(registry, &self.session, Value::Object(arguments), cancel) {
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        if let Some(result) = self.call_flywheel(name, &arguments) {
            if raw.is_some() {
                return CallToolResult::error(vec![ContentBlock::text(raw_refusal(name))]);
            }
            return match result {
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        if let Some(tool) = self.file_tools.iter().find(|tool| tool.name == name) {
            match raw {
                // A raw-capable file tool reads the Raw image itself, from its own arguments.
                Some(raw) if tools::raw_capable(name) => {
                    arguments.insert(RAW.to_owned(), raw);
                }
                Some(_) => return CallToolResult::error(vec![ContentBlock::text(raw_refusal(name))]),
                None => {}
            }
            return match tool.call(&self.packs(), Value::Object(arguments)) {
                Ok(output) if name == "query_debugger" && output.get("ok") == Some(&Value::Bool(false)) => {
                    CallToolResult::error(vec![ContentBlock::text(output.to_string())])
                }
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        // An APK or DEX file is no binary: privacy_surface reads it through the DEX tools and its native libraries.
        if name == "privacy_surface"
            && raw.is_none()
            && let Some(path) = arguments.get("path").and_then(Value::as_str)
            && let Some(result) = rampage_api::privacy_surface_input(Path::new(path), &Value::Object(arguments.clone()))
        {
            return match result {
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        // A static library is no binary: build_signatures reads its objects, with relocation-exact patterns.
        if name == "build_signatures"
            && raw.is_none()
            && let Some(path) = arguments.get("path").and_then(Value::as_str)
            && rampage_api::is_static_archive(Path::new(path))
        {
            return match library_signatures(Path::new(path), &arguments, &|| cancel.is_cancelled()) {
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
            // Runs the tool, remembering what it opened as a session target once the call succeeds.
            let call = |project: &mut Arc<Project>, selectors: Map<String, Value>, identity: String, records: bool| {
                let (output, failed) = tools::call_shared(&self.tools, project, name, Value::Object(arguments.clone()));
                if !failed {
                    self.record_target(path, selectors, identity, records);
                }
                (output, failed)
            };
            if let Some(raw) = raw {
                let mut project =
                    self.open_raw(name, Path::new(path), raw.clone(), [&arch, &image_offset, &image_length])?;
                let identity = raw_identity(&project);
                let records = raw
                    .get("format")
                    .and_then(Value::as_str)
                    .is_some_and(|format| matches!(format.to_ascii_lowercase().as_str(), "ihex" | "srec"));
                return Ok(call(&mut project, Map::from_iter([(RAW.to_owned(), raw)]), identity, records));
            }
            let mut selectors = Map::new();
            for (key, value) in [("arch", &arch), ("image_offset", &image_offset), ("image_length", &image_length)] {
                if let Some(value) = value.as_ref().filter(|value| !value.is_null()) {
                    selectors.insert(key.to_owned(), value.clone());
                }
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
            // A file with no executable header and no format of its own (a filesystem image, DEX or a record file
            // keeps its pointed error) gets triage at container level instead of an error.
            let container = |error: rampage_api::ApiError| -> Result<(String, bool), String> {
                if matches!(name, "triage" | "triage_report")
                    && image.is_none()
                    && headerless(&error)
                    && !rampage_api::headerless_format_known(Path::new(path))
                {
                    // Should the layout itself fail, the open error and its guidance still answer.
                    let reason = open_error(&error);
                    return rampage_api::headerless_triage(Path::new(path), &reason)
                        .map(|value| (value.to_string(), false))
                        .map_err(|_| reason);
                }
                // Agents reach for the core diff_builds on two firmware files; the comparison they need is in a group.
                if name == "diff_builds" && matches!(error, rampage_api::ApiError::Load { .. }) {
                    return Err(format!("{}. {DIFF_FIRMWARE_HINT}", open_error(&error)));
                }
                Err(open_error(&error))
            };
            // A file with no executable header, named with no selector: the Raw project the connection opened it as
            // (when only one), or else an Intel HEX or S-record file whose records show what they hold (a Cortex-M
            // vector table) as that Raw project, every address from the records. Otherwise its open error stands,
            // which for a record file names the selector.
            let records = |error: rampage_api::ApiError| -> Result<(String, bool), String> {
                if !(tools::raw_capable(name) && image.is_none() && arch.is_none() && headerless(&error)) {
                    return container(error);
                }
                if !native_asked && let Some(target) = self.only_raw_target(path) {
                    let raw = target.selectors.get(RAW).cloned().unwrap_or_default();
                    let mut project = self.open_raw(name, Path::new(path), raw.clone(), [&None, &None, &None])?;
                    let identity = raw_identity(&project);
                    *used.borrow_mut() = Some(target.summary());
                    return Ok(call(&mut project, Map::from_iter([(RAW.to_owned(), raw)]), identity, target.records));
                }
                let selector = rampage_api::record_file_selector(Path::new(path));
                let Some(request) = selector.clone().and_then(|selector| serde_json::from_value(selector).ok()) else {
                    return container(error);
                };
                let mut project = self
                    .session
                    .open_raw(Path::new(path), &request)
                    .map_err(|error| format!("{path}: {}", error_text(&error)))?;
                let identity = raw_identity(&project);
                // Recorded with the selector it was read with, so file tools such as inspect_data read it alike.
                let selectors = Map::from_iter(selector.map(|selector| (RAW.to_owned(), selector)));
                Ok(call(&mut project, selectors, identity, true))
            };
            let mut project = if tool.reads_annotations {
                let project = match self.session.open_at(&PathBuf::from(path), arch, image) {
                    Ok(project) => project,
                    Err(error) => return records(error),
                };
                // Other clients (the UI, the CLI) may have saved names since the last call.
                project.refresh_annotations().map_err(|error| error_text(&error))?;
                project
            } else {
                let project = match rampage_loaders::Binary::open_image(path, image, arch) {
                    Ok(binary) => Project::new(binary),
                    Err(source) => return records(rampage_api::ApiError::Load { path: PathBuf::from(path), source }),
                };
                project.set_packs(self.packs());
                Arc::new(project)
            };
            let identity = format!("native:{arch:?}:{offset:?}:{length:?}");
            Ok(call(&mut project, selectors, identity, false))
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

    /// Runs `name` when it is an improve tool or `report_observation` this server serves; `None` otherwise.
    fn call_flywheel(&self, name: &str, arguments: &Map<String, Value>) -> Option<Result<Value, String>> {
        let input = Value::Object(arguments.clone());
        if let Some(improve) = &self.improve
            && let Some(tool) = self.improve_tools.iter().find(|tool| tool.name == name)
        {
            return Some(tool.call(improve, input));
        }
        match &self.observations {
            Some(store) if self.observation_tool.name == name => Some(self.observation_tool.call(store, input)),
            _ => None,
        }
    }

    /// The copy one call runs on: this server, sharing its targets (unlike [`Clone`], whose copy serves another
    /// connection).
    fn for_call(&self) -> Self {
        Self { targets: Arc::clone(&self.targets), ..self.clone() }
    }

    fn targets(&self) -> Vec<Target> {
        self.targets.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Remembers that a call opened `path` with `selectors`, identified by `identity`; a target already known keeps
    /// its place and the selectors first used. `records` marks an Intel HEX or S-record file.
    fn record_target(&self, path: &str, selectors: Map<String, Value>, identity: String, records: bool) {
        let identity = (canonical(path), identity);
        let mut targets = self.targets.lock().unwrap_or_else(PoisonError::into_inner);
        if targets.iter().any(|target| target.identity == identity) {
            return;
        }
        targets.push(Target { path: path.to_owned(), selectors, identity, records });
        if targets.len() > MAX_TARGETS {
            targets.remove(0);
        }
    }

    /// The Raw target `path` was opened as, when the connection has opened that path once only and as Raw.
    fn only_raw_target(&self, path: &str) -> Option<Target> {
        let path = canonical(path);
        let targets = self.targets();
        let same: Vec<&Target> = targets.iter().filter(|target| target.identity.0 == path).collect();
        match same.as_slice() {
            [target] if target.selectors.contains_key(RAW) => Some((*target).clone()),
            _ => None,
        }
    }

    /// import_svd given the .svd file as `path` and no `svd`: that file becomes `svd`, and the session's only
    /// target the image (filled in by [`Self::default_target`]); with none or several, an error saying which is
    /// which.
    fn svd_as_path(&self, name: &str, arguments: &mut Map<String, Value>) -> Result<(), String> {
        if name != "import_svd" || arguments.get("svd").is_some_and(|svd| !svd.is_null()) {
            return Ok(());
        }
        let Some(path) = arguments.get("path").and_then(Value::as_str) else { return Ok(()) };
        if !Path::new(path).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("svd")) {
            return Ok(());
        }
        let targets = self.targets();
        if targets.len() != 1 {
            let opened = match targets.len() {
                0 => "no binary is open in this session yet".to_owned(),
                count => format!("this session has opened {count} binaries: {}", target_listing(&targets)),
            };
            return Err(format!(
                "`path` names the .svd file `{path}`, but import_svd takes the firmware image as `path` and the .svd \
                 file as `svd`, and {opened}; call import_svd with svd=`{path}` and path=<the image> (with its raw \
                 selector); nothing was run"
            ));
        }
        let svd = arguments.remove("path").unwrap_or_default();
        arguments.insert("svd".to_owned(), svd);
        Ok(())
    }

    /// Fills in what a call to `name` leaves out from the session's targets, once its arguments are checked, and
    /// returns the target it used, if any, for the result to name:
    /// - without `path`, the only target this connection has opened, with its selectors unless the call gives its
    ///   own (`raw: null` among them: the native image); with none or several, an error saying to pass `path`
    ///   (listing the targets). A byte-level file tool does not default to a record file, whose bytes are text.
    /// - inspect_data with a `path` the connection opened only as one Raw project, no selector, and no native image
    ///   there: that project's `raw`. Project tools do the same in [`Self::dispatch`], when the native open fails.
    ///
    /// An explicit `path` always wins. Tools that take no binary path are left alone.
    fn default_target(&self, name: &str, arguments: &mut Map<String, Value>) -> Result<Option<String>, String> {
        let project_tool = self.improve.is_none() && self.tools.iter().any(|tool| tool.name == name);
        let file_tool = self.improve.is_none()
            && SESSION_PATH_FILE_TOOLS.contains(&name)
            && self.file_tools.iter().any(|tool| tool.name == name);
        if !project_tool && !file_tool {
            return Ok(None);
        }
        // The selectors this tool takes: a project tool's (and inspect_data's) native and Raw selectors; other file
        // tools read the target's file by their own arguments.
        let selectors: &[&str] = if project_tool || tools::raw_capable(name) { &SELECTORS } else { &[] };
        let native_asked = selectors.contains(&RAW) && arguments.get(RAW).is_some_and(Value::is_null);
        let own_selector =
            native_asked || selectors.iter().any(|key| arguments.get(*key).is_some_and(|value| !value.is_null()));
        if let Some(path) = arguments.get("path").and_then(Value::as_str) {
            if name == "inspect_data"
                && !own_selector
                && let Some(target) = self.only_raw_target(path)
                && native_headerless(path)
            {
                arguments.insert(RAW.to_owned(), target.selectors.get(RAW).cloned().unwrap_or_default());
                return Ok(Some(target.summary()));
            }
            return Ok(None);
        }
        let targets = self.targets();
        let target = match targets.as_slice() {
            [] => {
                return Err("`path` is required: no binary is open in this session yet, so there is no session \
                            target to default to; pass `path` (and `raw` for a headerless image)"
                    .to_owned());
            }
            [target] => target,
            _ => {
                return Err(format!(
                    "`path` was omitted, but this session has opened {} binaries, so there is no single target to \
                     default to; pass `path` (with the same selector) for one of: {}",
                    targets.len(),
                    target_listing(&targets)
                ));
            }
        };
        if target.records && file_tool && !tools::raw_capable(name) {
            return Err(format!(
                "`path` was omitted, and the session's target `{}` is an Intel HEX or S-record file, whose bytes are \
                 record text; {name} reads file bytes, so it does not default to it: pass `path` to read the text, or \
                 use inspect_data (which reads the records) or a project tool; nothing was run",
                target.summary()
            ));
        }
        arguments.insert("path".to_owned(), Value::String(target.path.clone()));
        if !own_selector {
            for (key, value) in &target.selectors {
                if selectors.contains(&key.as_str()) {
                    arguments.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(Some(target.summary()))
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

/// The `raw` selector as an object: a JSON string holding one object (as some clients send nested arguments) is
/// parsed once, strictly; any other string is refused.
fn raw_object(raw: Value) -> Result<Value, String> {
    let Value::String(text) = raw else { return Ok(raw) };
    match serde_json::from_str::<Value>(&text) {
        Ok(object @ Value::Object(_)) => Ok(object),
        _ => Err("`raw` must be a JSON object such as {\"profile\":\"cortex-m\",\"base_address\":\"0x8000000\"}, \
                  not a string; a string is accepted only when it holds exactly one such object; nothing was run"
            .to_owned()),
    }
}

/// Appended to a diff_builds open error: it compares two executables, and firmware has its own comparison.
const DIFF_FIRMWARE_HINT: &str = "diff_builds compares two executables; to compare two versions of firmware (a \
    flash dump, update file, filesystem image, APK or Raw image), use diff_firmware (enable_tools group carve), \
    which finds their components, files and code and compares each";

/// Why a native open failed; for a file without a recognised header, also how to read it as headerless code.
fn open_error(error: &rampage_api::ApiError) -> String {
    let text = error_text(error);
    let headerless = headerless(error);
    match error {
        rampage_api::ApiError::Load { path, .. } if headerless => {
            format!("{text}. {}", rampage_api::headerless_guidance_for(path))
        }
        _ if headerless => format!("{text}. {}", rampage_api::headerless_guidance()),
        _ => text,
    }
}

/// Whether a native open failed because the file has no recognised executable header.
fn headerless(error: &rampage_api::ApiError) -> bool {
    matches!(error, rampage_api::ApiError::Load { source: rampage_loaders::LoadError::Parse(_), .. })
        && error_text(error).contains("Unknown file magic")
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
            .with_instructions(instructions(
                &self.packs(),
                self.debug.as_deref(),
                self.improve.is_some(),
                self.observations.is_some(),
            ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let enabled = self.enabled();
        let meta = rmcp::model::Tool::new(
            ENABLE_TOOLS,
            ENABLE_TOOLS_DESCRIPTION,
            enable_tools_schema(self.debug.is_some(), self.improve.is_some()),
        );
        let catalog: BTreeSet<&str> = self.catalog().map(|(_, name)| name).collect();
        let enabled: BTreeSet<Group> = enabled;
        let served = |group: &Group, name: &str| enabled.contains(group) && catalog.contains(name);
        let tools = self.tools.iter().filter(|tool| served(&tool.group, tool.name)).map(|tool| {
            rmcp::model::Tool::new(tool.name, tool.description, with_binary_arguments(tool.name, &tool.input_schema))
        });
        let file_tools = self.file_tools.iter().filter(|tool| served(&tool.group, tool.name)).map(|tool| {
            let mut schema = file_tool_schema(tool);
            if tools::raw_capable(tool.name)
                && let Some(Value::Object(properties)) = schema.get_mut("properties")
            {
                properties.insert(RAW.to_owned(), compact_raw_selector());
                remove_unreferenced_definitions(&mut schema);
            }
            let listed = rmcp::model::Tool::new(tool.name, tool.description, schema);
            match tool.effect {
                // endpoint_blocklist replaces the regular file it names (never through a symlink) with the same
                // content for the same arguments.
                tools::Effect::FileWrite if tool.name == "endpoint_blocklist" => listed.annotate(
                    rmcp::model::ToolAnnotations::new()
                        .read_only(false)
                        .destructive(true)
                        .idempotent(true)
                        .open_world(false),
                ),
                // New files (fs_extract, write_decoded_range) where the caller names, never over existing ones.
                tools::Effect::FileWrite => listed.annotate(
                    rmcp::model::ToolAnnotations::new()
                        .read_only(false)
                        .destructive(false)
                        .idempotent(false)
                        .open_world(false),
                ),
                // query_debugger only reads, but from an operator-started debugger outside rampage.
                tools::Effect::None if tool.name == "query_debugger" => {
                    listed.annotate(rmcp::model::ToolAnnotations::new().read_only(true).open_world(true))
                }
                // Effect::None means the tool writes nothing: it only reads the files it names.
                tools::Effect::None => {
                    listed.annotate(rmcp::model::ToolAnnotations::new().read_only(true).open_world(false))
                }
                _ => listed,
            }
        });
        let debug_enabled = self.debug.is_some() && self.improve.is_none() && enabled.contains(&Group::Debug);
        let debug_tools = self.debug_tools.iter().filter(|_| debug_enabled).map(|tool| {
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema).annotate(debug_annotations(tool.effect))
        });
        let improve_enabled = self.improve.is_some() && enabled.contains(&Group::Improve);
        let improve_tools = self.improve_tools.iter().filter(|_| improve_enabled).map(|tool| {
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema)
        });
        let observation = served(&self.observation_tool.group, self.observation_tool.name).then(|| {
            let tool = &self.observation_tool;
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema)
        });
        let all = std::iter::once(meta)
            .chain(tools)
            .chain(file_tools)
            .chain(observation)
            .chain(debug_tools)
            .chain(improve_tools);
        Ok(ListToolsResult::with_all_items(all.map(|tool| tool.with_meta(result_size_meta())).collect()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.into_owned();
        let mut arguments = request.arguments.unwrap_or_default();
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
        let schema = self.advertised_schema(&name);
        if let Some(schema) = &schema {
            // Clients often call a deferred tool before loading its schema; take unambiguous aliases and numbers
            // sent as strings rather than refusing the call.
            tools::normalize_arguments(&name, schema, &mut arguments);
        }
        // Unknown arguments are refused before the session's target fills in `path` (optional in every schema).
        let checked = self
            .svd_as_path(&name, &mut arguments)
            .and_then(|()| match &schema {
                Some(schema) => tools::check_arguments(&name, schema, &arguments),
                None => Ok(()),
            })
            .and_then(|()| self.default_target(&name, &mut arguments));
        let used = match checked {
            Ok(used) => used,
            Err(message) => {
                // The import tools answer every failure with their own JSON receipt.
                let apply_requested = arguments.get("apply").map_or(Some(false), Value::as_bool);
                let message = match name.as_str() {
                    "import_pdb_names" => tools::pdb_import_error(&message, apply_requested),
                    "import_debug_layouts" => tools::debug_layout_import_error(&message, apply_requested),
                    _ => message,
                };
                return Ok(CallToolResult::error(vec![ContentBlock::text(message)]).into());
            }
        };
        let server = self.for_call();
        // A cancelled request (notifications/cancelled, or the connection closing) sets the flag the debug tools
        // check: waits return early with the target untouched, long reads stop between chunks.
        let cancel = DebugCancel::new();
        let watcher = {
            let (cancel, token) = (cancel.clone(), context.ct.clone());
            tokio::spawn(async move {
                token.cancelled().await;
                cancel.cancel();
            })
        };
        // Analysis is blocking work; keep it off the async runtime.
        let result = tokio::task::spawn_blocking(move || server.run(&name, arguments, &cancel, used)).await;
        watcher.abort();
        let result = result.map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        Ok(result.into())
    }
}

/// Every tool's `_meta`: results fit [`tools::RESULT_LIMIT_CHARS`], so a client must not cut them shorter.
fn result_size_meta() -> rmcp::model::MetaObject {
    let mut meta = rmcp::model::MetaObject::new();
    meta.insert(MAX_RESULT_SIZE_META.to_owned(), json!(tools::RESULT_LIMIT_CHARS));
    meta
}

/// The MCP annotations of a debug tool: every one reaches a target outside rampage. Inspection is read-only; a
/// snapshot only adds a new file; execution control changes the target's state and is neither idempotent nor
/// merely additive.
fn debug_annotations(effect: tools::Effect) -> rmcp::model::ToolAnnotations {
    let annotations = rmcp::model::ToolAnnotations::new().open_world(true);
    match effect {
        tools::Effect::Execution | tools::Effect::TargetWrite => {
            annotations.read_only(false).destructive(true).idempotent(false)
        }
        tools::Effect::FileWrite => annotations.read_only(false).destructive(false).idempotent(false),
        _ => annotations.read_only(true),
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
    serve_stdio_with(groups, packs, debug, None, None, None).await
}

/// [`serve_stdio`], with the `improve` group over `improve`'s corpus, `report_observation` recording into
/// `observations`, and every decompilation in the `required_worker` (see [`decompiler_worker_startup`]) when they
/// are given.
pub async fn serve_stdio_with(
    groups: BTreeSet<Group>,
    packs: Arc<Packs>,
    debug: Option<DebugRegistry>,
    improve: Option<Arc<Improve>>,
    observations: Option<Arc<ObservationStore>>,
    required_worker: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut server = RampageServer::with_groups(groups).with_packs(packs);
    if let Some(worker) = required_worker {
        server = server.requiring_decompiler_worker(worker);
    }
    if let Some(registry) = debug {
        server = server.with_debug(registry);
    }
    if let Some(improve) = improve {
        server = server.with_improve(improve);
    }
    if let Some(store) = observations {
        server = server.with_observations(store);
    }
    server.serve(rmcp::transport::stdio()).await?.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn all_tool_names_match_the_tool_contract() {
        let contract: Value =
            serde_json::from_str(include_str!("../../../tests/contract/mcp-tools.json")).expect("contract JSON");
        let listed: Vec<&str> = contract["tools"].as_object().expect("tools").keys().map(String::as_str).collect();
        // The contract lists no observing server, so its one tool is the only name the contract lacks.
        let observation = observation_tool().name;
        let names: Vec<&str> = all_tool_names().into_iter().filter(|name| *name != observation).collect();
        assert_eq!(names, listed);
        assert!(all_tool_names().contains(&observation));
    }

    #[test]
    fn a_missing_worker_warns_or_under_require_pins_the_expected_path() {
        let expected = PathBuf::from("/opt/rampage/bin/rampage-worker");
        let found = PathBuf::from("/custom/rampage-worker");

        let quiet = decompiler_worker_startup(false, Some(found.clone()), expected.clone());
        assert_eq!(quiet, WorkerStartup { required: None, warning: None });

        let fallback = decompiler_worker_startup(false, None, expected.clone());
        assert_eq!(fallback.required, None);
        let warning = fallback.warning.unwrap();
        assert!(warning.contains("in-process") && warning.contains("--require-worker"), "{warning}");
        assert!(warning.contains("/opt/rampage/bin/rampage-worker"), "{warning}");

        let required = decompiler_worker_startup(true, Some(found.clone()), expected.clone());
        assert_eq!(required, WorkerStartup { required: Some(found), warning: None });

        let refusing = decompiler_worker_startup(true, None, expected.clone());
        assert_eq!(refusing.required, Some(expected));
        let warning = refusing.warning.unwrap();
        assert!(warning.contains("refuse") && !warning.contains("will run in-process"), "{warning}");

        let server = RampageServer::default().requiring_decompiler_worker(PathBuf::from("/nonexistent/rampage-worker"));
        assert_eq!(server.session.required_decompiler_worker(), Some(Path::new("/nonexistent/rampage-worker")));
    }

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
        let text = instructions(&Packs::default(), None, false, false);
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
        // The documented list includes the write tools, served with --debug-writes.
        let registry = DebugRegistry::new(&["127.0.0.1:2345".to_owned()])
            .unwrap()
            .with_consent(DebugConsent { writes: true, kill: true });
        let server = RampageServer::default()
            .with_debug(registry)
            .with_observations(Arc::new(ObservationStore::new(std::env::temp_dir().join("rampage-unused"))));
        // A corpus server serves the improve group alone.
        let corpus = RampageServer::default().with_improve(improve_fixture());
        let mut served = BTreeMap::<String, Vec<String>>::new();
        for (group, name) in server.catalog().chain(corpus.catalog()) {
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
        assert_eq!(
            initial_groups(false, Some("firmware")),
            Ok(BTreeSet::from([Group::Core, Group::Types, Group::Carve, Group::Formats]))
        );
    }

    /// A corpus of two fixture binaries, enough to construct the improve group (nothing is analysed).
    fn improve_fixture() -> Arc<Improve> {
        use rampage_api::flywheel::{ImproveOptions, sha256_file};
        static FIXTURE: std::sync::OnceLock<Arc<Improve>> = std::sync::OnceLock::new();
        Arc::clone(FIXTURE.get_or_init(|| {
            let root = std::env::temp_dir().join(format!("rampage-mcp-improve-{}", std::process::id()));
            let corpus = root.join("corpus").join("unit-v1");
            std::fs::create_dir_all(&corpus).unwrap();
            let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
            let mut binaries = Vec::new();
            for program in ["corpus", "target"] {
                let stripped = format!("{program}.elf");
                let twin = format!("{program}.twin.elf");
                let name = if program == "corpus" { "twin" } else { "target" };
                let split = if program == "corpus" { "train" } else { "heldout" };
                std::fs::copy(fixture.join(format!("eval-{name}-x86_64.elf")), corpus.join(&stripped)).unwrap();
                let symbolized = if program == "corpus" { "eval-ref-x86_64.elf" } else { "eval-target-sym-x86_64.elf" };
                std::fs::copy(fixture.join(symbolized), corpus.join(&twin)).unwrap();
                binaries.push(json!({
                    "id": program, "program": format!("musl/{program}"), "library": "musl",
                    "library_version": program, "split": split, "arch": "x86_64",
                    "compiler": "zig", "opt": "O1", "stripped": stripped, "twin": twin,
                    "stripped_sha256": sha256_file(&corpus.join(&stripped)).unwrap(),
                    "twin_sha256": sha256_file(&corpus.join(&twin)).unwrap(),
                }));
            }
            let manifest = json!({
                "schema_version": 2, "family": "libid", "name": "unit", "version": "unit-v1",
                "split": { "rule": "version", "fast_programs_per_library": 1, "max_heldout_overlap": 1.0 },
                "binaries": binaries,
            });
            std::fs::write(corpus.join("manifest.json"), manifest.to_string()).unwrap();
            let options = ImproveOptions {
                corpus,
                flywheel_dir: None,
                gate: Default::default(),
                workers: 1,
                run: None,
                baseline: Default::default(),
            };
            Arc::new(Improve::open(options).unwrap())
        }))
    }

    /// The tools an agent must find in the shown part of the instructions to know which group answers what.
    const KEY_TOOLS: [(Group, &[&str]); 11] = [
        (
            Group::Core,
            &[
                "triage_report",
                "list_functions",
                "decompile",
                "xrefs",
                "language_metadata",
                "class_evidence",
                "annotate_batch",
                "record_finding",
                "find_main",
            ],
        ),
        (Group::Detection, &["detect_tools", "identify_functions", "find_crypto", "yara_scan", "capa_detect"]),
        (Group::Types, &["declare_types", "get_type", "set_signature", "edit_variable", "import_debug_types"]),
        (Group::Runtime, &["observe_pointer", "compare_runtime_bytes", "query_debugger"]),
        (Group::Diagnostics, &["analysis_diagnostics", "entry_diagnostics", "inspect_jump_table"]),
        (Group::DotNet, &["dotnet_metadata", "dotnet_il"]),
        (Group::Android, &["dex_metadata", "dex_code"]),
        (Group::Carve, &["carve", "archive_inventory", "fs_list", "fs_extract"]),
        (Group::Formats, &["build_info", "pe_resources", "pe_load_config", "pyinstaller_archive", "wasm_module"]),
        (
            Group::Debug,
            &["debug_connect", "debug_read_memory", "debug_breakpoints", "debug_continue", "debug_disconnect"],
        ),
        (Group::Improve, &["corpus_failures", "propose_heuristic", "evaluate_candidate", "promote_candidate"]),
    ];

    /// Every configuration whose instructions differ, with a name for the size report. The enabled groups do not
    /// change the text, so a server with all groups, or one serving Raw projects, reads the default's.
    fn configurations() -> Vec<(&'static str, Packs, Option<DebugRegistry>, bool)> {
        let debug = |writes, kill| {
            // Two endpoints, longer than a typical one, so the debug paragraph is not measured at its smallest.
            let endpoints = ["192.168.100.200:12345".to_owned(), "unix:/var/run/rampage/target-debug.sock".to_owned()];
            Some(DebugRegistry::new(&endpoints).unwrap().with_consent(DebugConsent { writes, kill }))
        };
        let packs = || Packs::lazy(&[std::env::temp_dir().join("rampage-no-such-pack-directory")]);
        vec![
            ("default", Packs::default(), None, false),
            ("packs", packs(), None, false),
            ("debug", Packs::default(), debug(false, false), false),
            ("debug writes", Packs::default(), debug(true, false), false),
            ("debug kill", Packs::default(), debug(false, true), false),
            ("debug writes kill packs", packs(), debug(true, true), false),
            ("observations", Packs::default(), None, true),
        ]
    }

    /// Claude Code shows a model only the first [`INSTRUCTIONS_SHOWN_CHARS`] of the instructions, so that part
    /// names every group with its key tools, the first calls, and the debug consent and endpoints.
    #[test]
    fn the_shown_part_of_the_instructions_carries_every_group_and_its_key_tools() {
        for (name, packs, debug, observations) in configurations() {
            let text = instructions(&packs, debug.as_ref(), false, observations);
            let shown: String = text.chars().take(INSTRUCTIONS_SHOWN_CHARS).collect();
            let registry = DebugRegistry::new(&["127.0.0.1:2345".to_owned()]).unwrap();
            let server = RampageServer::default().with_debug(registry);
            let corpus = RampageServer::default().with_improve(improve_fixture());
            for (group, tools) in KEY_TOOLS {
                if group == Group::Debug && debug.is_none() {
                    assert!(!text.contains("- debug: ") && !text.contains("debug_connect"), "{name}");
                    continue;
                }
                if group == Group::Improve {
                    assert!(!text.contains("- improve: ") && !text.contains("corpus_failures"), "{name}");
                    for tool in tools {
                        assert!(corpus.catalog().any(|entry| entry == (group, *tool)), "{tool} is not served");
                    }
                    continue;
                }
                assert!(shown.contains(&format!("\n- {}: ", group.name())), "{name}: {group:?}");
                for tool in tools {
                    assert!(server.catalog().any(|entry| entry == (group, *tool)), "{tool} is not served in {group:?}");
                    assert!(shown.contains(tool), "{name}: {tool} is past the shown part");
                }
            }
            for text in ["enable_tools", "--all-tools", "RAMPAGE_MCP_TOOLS", "Objective-C", "C++ vtables/RTTI"] {
                assert!(shown.contains(text), "{name}: {text}");
            }
            if let Some(registry) = &debug {
                let consent = registry.consent();
                assert!(shown.contains("launches and attaches to nothing"), "{name}");
                assert_eq!(shown.contains(DEBUG_READ_ONLY), !consent.writes && !consent.kill, "{name}");
                assert_eq!(shown.contains(DEBUG_WRITES), consent.writes, "{name}");
                assert_eq!(shown.contains(DEBUG_KILL), consent.kill, "{name}");
                for endpoint in registry.endpoints() {
                    assert!(shown.contains(endpoint.as_str()), "{name}: {endpoint}");
                }
            }
            if packs.configured() {
                assert!(shown.contains("Data packs: "), "{name}");
            }
            assert_eq!(text.contains("report_observation"), observations, "{name}");
        }
    }

    /// A corpus server's instructions name the improve tools and nothing that reads a binary.
    #[test]
    fn a_corpus_server_is_told_it_serves_only_the_improve_group() {
        let text = instructions(&Packs::default(), None, true, false);
        assert!(text.chars().count() + 300 <= INSTRUCTIONS_SHOWN_CHARS);
        for tool in ["corpus_failures", "propose_heuristic", "evaluate_candidate", "promote_candidate"] {
            assert!(text.contains(tool), "{tool}");
        }
        for tool in ["triage_report", "decompile", "disassemble", "enable_tools with"] {
            assert!(!text.contains(tool), "{tool}");
        }
        assert!(text.contains("Held-out binaries are never shown"));
    }

    /// The part before the details stays well inside the shown characters, so a new sentence there fails here
    /// rather than silently pushing the last group or the debug consent past the cut. Run with --no-capture for
    /// the sizes.
    #[test]
    fn the_essential_part_of_the_instructions_leaves_a_margin_before_the_cut() {
        const MARGIN: usize = 300;
        for (name, packs, debug, observations) in configurations() {
            let text = instructions(&packs, debug.as_ref(), false, observations);
            let essentials = text.find(INSTRUCTIONS_DETAILS).expect("the details are marked");
            let essentials = text[..essentials].chars().count();
            println!("{name}: {essentials} essential characters of {} in all", text.chars().count());
            assert!(
                essentials + MARGIN <= INSTRUCTIONS_SHOWN_CHARS,
                "{name}: {essentials} essential characters leave less than {MARGIN} before the \
                 {INSTRUCTIONS_SHOWN_CHARS}-character cut; move detail after INSTRUCTIONS_DETAILS"
            );
        }
    }
}
