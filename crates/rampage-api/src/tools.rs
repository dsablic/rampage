//! The analysis tools AI models call, shared by the MCP server and the UI's assistant: each has a name, a
//! description, a JSON schema for its input, and a handler that runs it against a project.

use crate::tool_views::{ToolView, ToolViewKind, project_tool_view};
use crate::workflows::{WORKFLOWS, Workflow};
use crate::{ApiError, FunctionsQuery, ListQuery, Packs, Project, StringsQuery, WorkflowReport, XrefQuery};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

/// Results longer than this are cut, so that one large answer cannot crowd out the conversation. Workflow reports
/// and import receipts fit themselves below it instead, preserving valid JSON and whole-operation status.
const MAX_RESULT_CHARS: usize = 60_000;
const MAX_SLEIGH_REQUEST_BYTES: usize = 1024 * 1024;
const DEFAULT_PAGE: usize = 100;
const MAX_PDB_DETAIL_BYTES: usize = 4096;
const MAX_PDB_ERROR_BYTES: usize = 1024;

#[cfg(test)]
mod patch_dispatch_tests;
mod patch_page;
pub(crate) mod search_page;
mod signature_page;
use signature_page::identify_page;

type BorrowedHandler = Box<dyn Fn(&Project, Value) -> Result<Value, String> + Send + Sync>;
type SharedHandler = Box<dyn Fn(&mut Arc<Project>, Value) -> Result<SharedResult, String> + Send + Sync>;

struct SharedResult {
    value: Value,
    transition: Option<AnnotationTransition>,
}

struct AnnotationTransition {
    before: Arc<()>,
    after: Arc<()>,
}

impl SharedResult {
    fn read(value: Value) -> Self {
        Self { value, transition: None }
    }

    fn patch(value: Value, outcome: &crate::PatchOutcome) -> Self {
        Self {
            value,
            transition: Some(AnnotationTransition {
                before: Arc::clone(&outcome.before_annotation_revision),
                after: Arc::clone(&outcome.after_annotation_revision),
            }),
        }
    }
}

enum Handler {
    Borrowed(BorrowedHandler),
    /// Annotation handlers in this branch install their returned `PatchOutcome.project` themselves.
    Shared(SharedHandler),
}

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
    Formats,
}

impl Group {
    pub const ALL: [Group; 8] = [
        Group::Core,
        Group::Detection,
        Group::Types,
        Group::Runtime,
        Group::Diagnostics,
        Group::DotNet,
        Group::Carve,
        Group::Formats,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Group::Core => "core",
            Group::Detection => "detection",
            Group::Types => "types",
            Group::Runtime => "runtime",
            Group::Diagnostics => "diagnostics",
            Group::DotNet => "dotnet",
            Group::Carve => "carve",
            Group::Formats => "formats",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Group::Core => {
                "Layout, functions, disassembly, decompilation, xrefs, search, strings, imports, exports, \
                 annotations with undo/redo and batches, the findings ledger, assembly and checked byte patches, \
                 raw/Sleigh decode inspection, and the guided workflows (triage_report, find_main, network_surface, \
                 persistence_surface, string_decoding, diff_builds)."
            }
            Group::Detection => {
                "Heuristic databases and rules: packer/compiler detection, library-function signatures (identify and \
                 build), capability tags, YARA and capa rules, and the find_crypto workflow."
            }
            Group::Types => {
                "Project type libraries, C headers, signatures, type declarations and globals, \
                 reviewed checked DWARF/PDB type and signature import, \
                 demangled names and Itanium vtable/RTTI evidence, and explicit identity-matched PDB names."
            }
            Group::Runtime => {
                "Memory snapshot evidence: captured pointer slots, pointer comparisons across captures, runtime \
                 bytes against the original Mach-O, ARM64 indirect-branch windows."
            }
            Group::Diagnostics => {
                "Bounded entry/decode evidence and unreliable-code diagnostics, and explicit ARM64 jump-table checks."
            }
            Group::DotNet => "Managed (.NET) metadata (types, methods, properties, P/Invokes, attributes) and CIL.",
            Group::Carve => concat!(
                "Scan files for embedded executables/containers and inventory ",
                "standalone ZIP32 metadata without extraction."
            ),
            Group::Formats => {
                "Toolchain and container metadata: Go build info, Rust dependency audit data, PE resources and load config, PyInstaller archives and WebAssembly modules."
            }
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
    FileWrite,
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
        handler: Handler::Borrowed(Box::new(handler)),
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
struct PyInstallerArchiveArgs {
    /// Path to any regular file, such as a PyInstaller-built executable; it is not opened as a project.
    path: std::path::PathBuf,
    /// TOC entries to skip, for paging.
    offset: Option<usize>,
    /// TOC entries per page, 1..=100 (default 100), additionally bounded to 60000 JSON bytes.
    #[schemars(range(min = 1, max = 100))]
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WasmModuleArgs {
    /// Path to any regular file, such as a .wasm module; it is not opened as a project.
    path: std::path::PathBuf,
    /// The list to page; omit it for the summary alone.
    list: Option<crate::WasmList>,
    /// List items to skip, for paging.
    offset: Option<usize>,
    /// List items per page, 1..=100 (default 100), additionally bounded to 60000 JSON bytes.
    #[schemars(range(min = 1, max = 100))]
    limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ArchiveInventoryArgs {
    /// Explicit standalone single-disk ZIP32 file; never a binary or member path.
    path: std::path::PathBuf,
    /// Matching records to skip, not a native-image or byte offset.
    offset: Option<usize>,
    /// Records per page, 1..=100, additionally bounded to 60000 JSON bytes.
    #[schemars(range(min = 1, max = 100))]
    limit: Option<usize>,
    /// Case-sensitive UTF-8 byte substring of the full raw name, before display truncation.
    contains: Option<String>,
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
            group: Group::Core,
            name: "inspect_sleigh",
            description: "Inspect an explicit regular-file raw code window using a closed bundled Sleigh profile; \
                no native executable admission or Project is required. The closed runtime roster has 20 language \
                IDs: 16 reviewed processor profiles plus four x86/A64 variants. This is explicit raw-window \
                decoding/discovery, not ordinary Project, native-format, C ABI or packet support. No arbitrary \
                architecture aliases, spec paths or compiler specs. Native profile metadata supplies alignment, \
                spaces and helper requirements; widths are not inferred from CPU names. \
                path is the only common selector. profile/offset/length/base_address and optional discover/seeds, \
                instruction_limit/decode_attempt_limit/handle_open_limit/stop_limit, listing_offset/listing_limit, \
                include_pcode and timeout_ms are flattened request fields. All source offsets, bases, seeds and \
                targets use internal BYTE coordinates, even AVR code space word_size=2: never multiply again or \
                resolve names. The mapping is an analyst assertion; hashes/revalidation are observations, not \
                authentication or a proven executable mapping. Listing is capped at 64 KiB; discovery at 4 KiB \
                with explicit seeds and bounded work. Native calls/discovery are noninterruptible; deadlines are \
                cooperative between operations. Preserve complete spaces/program/stops, including valid instructions \
                gated for unknown flow (not invalid-opcode verdicts), including explicitly seeded unknown entries \
                and their bounded instruction extents. Unresolved gates forbid successor following and false \
                noreturn inference. Hexagon processor-helper requirements do not establish packet CFG support; \
                SuperH delay aggregation and user-defined/context-mediated operations remain explicit gates. \
                Entry retention is not exact body coverage or complete transitive call discovery. \
                P-code may require smaller listing pages. \
                Complete JSON is capped at 60000 bytes or explicitly refused, never string-cut. A C ABI/compiler \
                specification is not selected or attested by this workflow; C decompilation is unsupported. \
                Unix checked regular-file sources only; no fallback, execution, \
                sidecars, annotations, extraction, source publication or arbitrary metadata/spec-path following.",
            input_schema: sleigh_file_schema(),
            handler: |_, mut input| {
                check_sleigh_input_budget(&input)?;
                let object = input.as_object_mut().ok_or("Sleigh arguments must be an object")?;
                let path = object
                    .remove("path")
                    .and_then(|value| value.as_str().map(std::path::PathBuf::from))
                    .ok_or("Sleigh path must be a string")?;
                let request: crate::sleigh_window::SleighWindowRequest = arguments(input)?;
                let report = crate::sleigh_window::inspect_sleigh_file_range(&path, &request)
                    .map_err(|error| error_chain(&error))?;
                serde_json::to_value(report).map_err(|error| error.to_string())
            },
        },
        FileTool {
            group: Group::Core,
            name: "inspect_raw_code",
            description: "Linearly disassemble an explicit 1..4096-byte original-file window with analyst-supplied \
                base VA, architecture, mode and instruction/data byte orders. No executable header or guessing. \
                x86/x64/ARM/AArch64, little endian only; ARM requires arm/thumb, others native. No target following, \
                discovery, annotations, sidecars, extraction or execution. Return addressed decoder observations, \
                selected-range hash, source offsets and explicit stop/remaining information. Invalid/incomplete \
                instructions stop unconsumed. Mapping assertions and decoding are not execution or boundary proof. \
                Narrow length/count if output is oversized; repeat using continuation range/base when supplied.",
            input_schema: raw_file_schema(),
            handler: |_, mut input| {
                if input.to_string().len() > 16_384 {
                    return Err("raw-code arguments exceed input budget".into());
                }
                let object = input.as_object_mut().ok_or("raw-code arguments must be an object")?;
                let path = object
                    .remove("path")
                    .and_then(|value| value.as_str().map(std::path::PathBuf::from))
                    .ok_or("raw-code path must be a string")?;
                let request: crate::RawFileRequest = arguments(input)?;
                let report = crate::inspect_raw_file(&path, &request).map_err(|error| error_chain(&error))?;
                serde_json::to_value(report).map_err(|error| error.to_string())
            },
        },
        FileTool {
            group: Group::Core,
            name: "decode_file_range",
            description: "Decode an explicit regular-file range with a named built-in decoder, without requiring \
                an executable header. First provider: lzss-4k, LSB-first flags (1=literal), 12-bit references, \
                lengths nibble+3; dictionary start/fill are explicit parameters. Expected output size is supplied, \
                not discovered: no end marker, auto-detection, recursion, extraction, file publication or execution. \
                Return range/output hashes, consumed/trailing counts and a bounded decoded-offset preview. \
                Limits: 8 MiB input, 16 MiB output, 128:1 against selected input, cooperative decode deadline. \
                File I/O/hash phases are not forcibly timed out. Unix regular-file checks only. \
                Other native-image selectors are rejected; decoded offsets are not source offsets or load addresses.",
            input_schema: schema::<DecodeFileArgs>(),
            handler: |_, input| {
                if input.to_string().len() > 16_384 {
                    return Err("decode arguments exceed the input budget".into());
                }
                let args: DecodeFileArgs = arguments(input)?;
                let request = crate::DecodeFileRequest {
                    codec: args.codec,
                    offset: args.offset.0,
                    length: usize::try_from(args.length.0).map_err(|_| "decode length exceeds host width")?,
                    expected_output_size: usize::try_from(args.expected_output_size.0)
                        .map_err(|_| "decoded length exceeds host width")?,
                    initial_write_offset: args.initial_write_offset.unwrap_or(4078),
                    dictionary_fill: args.dictionary_fill.unwrap_or(0),
                    timeout_ms: args.timeout_ms.unwrap_or(3000),
                    preview_offset: usize::try_from(args.preview_offset.unwrap_or(crate::FileOffset(0)).0)
                        .map_err(|_| "preview offset exceeds host width")?,
                    preview_size: args.preview_size.unwrap_or(256),
                };
                let decoded = crate::decode_file_range(&args.path, &request).map_err(|error| error_chain(&error))?;
                serde_json::to_value(decoded.receipt).map_err(|error| error.to_string())
            },
        },
        FileTool {
            group: Group::Core,
            name: "inspect_data",
            description: "Inspect 1..=1024 native-image bytes and 4/8-byte words without discovery, naming scans or \
                sidecars. Image VAs, selected-image and outer-file offsets are distinct. Gaps, zero-fill, unreadable \
                and unavailable bytes stay explicit. Raw words remain candidates; retained Mach-O chained rebases \
                and import identities are separate. Partial encoded-pointer words are not followed. Metadata links \
                and bounded ASCII previews are not proven functions, layouts or execution. Other relocations are \
                 not applied. view=full (default) retains the original JSON; summary omits hex/ASCII previews with \
                 explicit counts/omission receipts while retaining word interpretations and source/status evidence. \
                 code is unsupported for metadata. Whole JSON or explicit refusal; reduce size on output-budget errors. \
                 No captures.",
            input_schema: schema::<InspectDataArgs>(),
            handler: |_, input| {
                if input.to_string().len() > 16_384 {
                    return Err("data inspection arguments exceed the input budget".into());
                }
                let args: InspectDataArgs = arguments(input)?;
                let arch = args.arch.map(|arch| arch.parse::<rampage_arch::Arch>()).transpose()?;
                let image = match (args.image_offset, args.image_length) {
                    (Some(offset), length) => {
                        Some(rampage_loaders::ImageAt::new(offset.0, length.map(|length| length.0)))
                    }
                    (None, Some(_)) => return Err("image_length requires image_offset".into()),
                    (None, None) => None,
                };
                let binary = rampage_loaders::Binary::open_image_metadata(&args.path, image, arch)
                    .map_err(|error| error_chain(&ApiError::Load { path: args.path, source: error }))?;
                let address = crate::resolve_data_address(&binary, &args.at).map_err(|error| error_chain(&error))?;
                let report = crate::inspect_native_data(
                    &binary,
                    &crate::DataQuery { address, size: args.size.unwrap_or(128), word_size: args.word_size },
                )
                .map_err(|error| error_chain(&error))?;
                let value = serde_json::to_value(report).map_err(|error| error.to_string())?;
                project_tool_view(value, ToolViewKind::InspectData, args.view).map_err(|error| error_chain(&error))
            },
        },
        FileTool {
            group: Group::Carve,
            name: "archive_inventory",
            description: "Inventory central-directory metadata in an explicit standalone single-disk ZIP32 file, \
                          without opening it as a binary or opening any member. Bounded prefix, tail and directory \
                          reads only; the tail can overlap member data. No member/local-header seeks, decompression, \
                          extraction, CRC verification, format probing, nesting or execution. ZIP64, multi-disk, SFX \
                          and directory gaps are unsupported. Limits: 65557-byte tail, 8 MiB directory, 4096 records, \
                          1 MiB retained name budget, 1024 bytes per name, 64 warnings, 24 MiB cumulative reads. \
                          Work is capped at 4096 EOCD candidates and 65536 extra fields; raw-name filtering is linear \
                          and bounded. \
                          Budget exhaustion rejects the whole inventory. Names preserve raw hex and ordinal identity, \
                          not filesystem paths or extraction safety. Metadata digest plus size/directory offsets is \
                          evidence only, not whole-payload hashing, authentication or an atomic snapshot. \
                          Full raw-name contains filtering precedes truncation. Exact metadata counts, \
                          byte-bounded JSON pages and next_offset allow progress even for maximum-size names. \
                          No annotations, packs or discovery. Native-image arch/image_offset/image_length arguments \
                          are rejected.",
            input_schema: schema::<ArchiveInventoryArgs>(),
            handler: |_, input| {
                (|| -> Result<Value, String> {
                    if input.to_string().len() > 48_000 {
                        return Err("archive arguments exceed the input byte budget".to_owned());
                    }
                    let args: ArchiveInventoryArgs = arguments(input)?;
                    let query = crate::ArchiveQuery { offset: args.offset, limit: args.limit, contains: args.contains };
                    let page = crate::archive_inventory(&args.path, &query).map_err(|error| error_chain(&error))?;
                    let output = serde_json::to_value(page).map_err(|error| error.to_string())?;
                    if output.to_string().len() > crate::MAX_ARCHIVE_RESULT_BYTES {
                        return Err("archive result exceeds the JSON byte budget".to_owned());
                    }
                    Ok(output)
                })()
                .map_err(|mut text| {
                    const MARKER: &str = "... [archive error truncated]";
                    if text.len() > 4096 {
                        let mut end = 4096 - MARKER.len();
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        text.truncate(end);
                        text.push_str(MARKER);
                    }
                    text
                })
            },
        },
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
            group: Group::Formats,
            name: "pyinstaller_archive",
            description: "Inspect the PyInstaller CArchive appended to any file (a PyInstaller-built ELF, PE or \
                          Mach-O), without opening it as a project. Finds the cookie (magic MEI\\x0c\\x0b\\x0a\\x0b\\x0e) \
                          by searching backwards through the file's last 8 MiB, so a signature appended after the \
                          archive is stepped over, and accepts both the 24-byte pre-2.1 and the 88-byte cookie. \
                          Reports cookie_offset, cookie_layout, package_offset/length, toc_offset/length, Python \
                          version (312 -> 3.12) and library name, typecode counts, and the PYZ entry's header (pyc \
                          magic and its Python version) when that entry is stored uncompressed. Pages TOC entries \
                          (offset/limit, at most 100 and 60000 JSON bytes): each has its record and data file \
                          offsets, compressed and uncompressed sizes, compression flag, typecode with its meaning \
                          (s script, m module, M package, z PYZ, Z zipfile, b binary, x data, o runtime option, d \
                          dependency, a nested package, l splash, n symlink) and name. Returns null when there is no \
                          cookie magic, and an error when magic matches but no cookie validates. Read-only: no \
                          extraction, decompression, decryption or pyc decompilation; use the file offsets with \
                          decode_file_range or carve.",
            input_schema: schema::<PyInstallerArchiveArgs>(),
            handler: |_, input| {
                let args: PyInstallerArchiveArgs = arguments(input)?;
                let page = crate::pyinstaller_archive(&args.path, args.offset, args.limit)
                    .map_err(|error| error_chain(&error))?;
                serde_json::to_value(page).map_err(|error| error.to_string())
            },
        },
        FileTool {
            group: Group::Formats,
            name: "wasm_module",
            description: "Summarise a core WebAssembly module in any file, without opening it as a project (the \
                          project loaders take native executables only). The summary has the version and layer \
                          fields, the section list (id, name, contents offset and size; at most 64 listed), counts \
                          of types, imports, functions, tables, memories, globals, tags, exports and data/elem \
                          segments, the start function, custom-section names, the name section's module name and \
                          the producers section (language, processed-by, sdk). list pages one list (offset/limit, \
                          at most 100 and 60000 JSON bytes): imports (module, name, kind, type), exports (name, \
                          kind, index) or functions (index, imported first; type signature; body offset and size; \
                          name-section name). A component-model binary (layer 1) is reported as unsupported, with \
                          no sections read. Malformed input returns what parsed before the error with complete \
                          false and the error in limitations. Returns null when the file has no \\0asm magic. Not \
                          validated, compiled, executed or disassembled.",
            input_schema: schema::<WasmModuleArgs>(),
            handler: |_, input| {
                let args: WasmModuleArgs = arguments(input)?;
                let page = crate::wasm_module(&args.path, args.list, args.offset, args.limit)
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

fn raw_file_schema() -> Value {
    let mut value = schema::<crate::RawFileRequest>();
    value["properties"].as_object_mut().expect("request properties").insert("path".into(),
        serde_json::json!({ "type": "string", "description": "Explicit regular input file; no native loader is used." }));
    value["required"].as_array_mut().expect("required raw mapping fields").push(Value::String("path".into()));
    value
}

fn sleigh_file_schema() -> Value {
    let mut schema = schema::<crate::sleigh_window::SleighWindowRequest>();
    let properties = schema["properties"].as_object_mut().expect("Sleigh request properties");
    properties.insert(
        "path".to_owned(),
        serde_json::json!({
            "type":"string", "description":"Explicit regular source file; raw bytes, not a native executable selector."
        }),
    );
    properties.get_mut("profile").expect("Sleigh profile property")["enum"] = serde_json::json!(
        rampage_decompiler::sleigh_decode::SleighDecoder::registered_profile_ids().collect::<Vec<_>>()
    );
    schema["required"].as_array_mut().expect("required Sleigh fields").push(Value::String("path".to_owned()));
    schema
}

/// Project tools that serve a Raw Project opened with [`crate::Session::open_raw`]: each returns a result or an
/// explicit typed refusal on Raw input. Clients offer the `raw` selector only on these.
pub const RAW_CAPABLE_TOOLS: [&str; 16] = [
    "binary_info",
    "list_functions",
    "disassemble",
    "function_graph",
    "xrefs",
    "search",
    "analysis_diagnostics",
    "entry_diagnostics",
    "capabilities",
    "rename",
    "set_comment",
    "annotate_batch",
    "list_annotations",
    "undo",
    "redo",
    "decompile",
];

/// Whether the project tool `name` accepts a Raw Project selector.
pub fn raw_capable(name: &str) -> bool {
    RAW_CAPABLE_TOOLS.contains(&name)
}

/// JSON schema of the `raw` selector object MCP and CLI add to raw-capable tools in place of a native binary.
pub fn raw_selector_schema() -> Value {
    let mut value = schema::<crate::RawProjectRequest>();
    let definitions = value.as_object_mut().and_then(|object| object.remove("$defs")).unwrap_or_default();
    inline_definitions(&mut value, &definitions);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "description".to_owned(),
            Value::String(
                "Open the explicit regular-file range as an ordinary Raw Project with an asserted closed profile. \
                 offset/length are original-file bytes; base_address, entry and seeds are internal code-space BYTE \
                 coordinates, even for word-addressed processors. The mapping is an analyst assertion, not header \
                 admission. Annotations are memory-only for this session and interpretation; no sidecars."
                    .to_owned(),
            ),
        );
    }
    value
}

/// Replaces each local `#/$defs/<name>` reference with its definition, keeping sibling keywords such as
/// descriptions, so the schema can be embedded inside another tool's input schema.
fn inline_definitions(value: &mut Value, definitions: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get("$ref")
                && let Some(Value::Object(definition)) =
                    reference.strip_prefix("#/$defs/").and_then(|name| definitions.get(name))
            {
                let definition = definition.clone();
                object.remove("$ref");
                for (key, entry) in definition {
                    object.entry(key).or_insert(entry);
                }
            }
            object.values_mut().for_each(|entry| inline_definitions(entry, definitions));
        }
        Value::Array(entries) => entries.iter_mut().for_each(|entry| inline_definitions(entry, definitions)),
        _ => {}
    }
}

pub fn parse_sleigh_window_request(bytes: &[u8]) -> Result<crate::sleigh_window::SleighWindowRequest, ApiError> {
    if bytes.len() > MAX_SLEIGH_REQUEST_BYTES {
        return Err(ApiError::Invalid("Sleigh request exceeds 1 MiB".to_owned()));
    }
    serde_json::from_slice(bytes).map_err(|error| ApiError::Invalid(format!("invalid Sleigh request: {error}")))
}

/// Checked bounded regular-file request input, without any executable admission or annotation handling.
pub fn read_sleigh_window_request(
    path: &std::path::Path,
) -> Result<crate::sleigh_window::SleighWindowRequest, ApiError> {
    let size = crate::range_source::RangeSource::open(path, 0, 0)?.size();
    if size > MAX_SLEIGH_REQUEST_BYTES as u64 {
        return Err(ApiError::Invalid("Sleigh request exceeds 1 MiB".to_owned()));
    }
    let source = crate::range_source::RangeSource::open(path, 0, size as usize)?;
    if source.size() != size {
        return Err(ApiError::Unavailable("Sleigh request size changed while opening".to_owned()));
    }
    let bytes = source.read()?;
    source.revalidate()?;
    parse_sleigh_window_request(&bytes)
}

fn check_sleigh_input_budget(input: &impl Serialize) -> Result<(), String> {
    #[derive(Default)]
    struct Counter {
        written: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_SLEIGH_REQUEST_BYTES.saturating_sub(self.written) {
                return Err(std::io::Error::other("Sleigh request exceeds 1 MiB"));
            }
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter::default(), input).map_err(|_| "Sleigh request exceeds 1 MiB".to_owned())
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
#[serde(deny_unknown_fields)]
struct ViewArgs {
    /// full (default) preserves original JSON; summary omits named payloads with counts/receipts.
    /// code keeps code/control evidence but is unsupported for binary_info and inspect_data metadata.
    #[serde(default)]
    view: ToolView,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ViewedAt {
    /// Numeric address string or existing symbol, import, export, analyst or sub_<hex> name.
    at: String,
    #[serde(default)]
    view: ToolView,
}

#[derive(serde::Deserialize, JsonSchema)]
struct ViewedDisassembleArgs {
    #[serde(flatten)]
    listing: DisassembleArgs,
    #[serde(default)]
    view: ToolView,
}

#[derive(Debug, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationBatchArgs {
    /// Atomic checked operations. Every value is required; null explicitly clears the selected annotation.
    #[schemars(length(max = 1000))]
    pub entries: Vec<crate::AnnotationBatchEntry>,
}

pub fn parse_annotation_batch_request(bytes: &[u8]) -> Result<AnnotationBatchArgs, ApiError> {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(ApiError::Invalid("annotation batch JSON request exceeds 8 MiB".to_owned()));
    }
    serde_json::from_slice(bytes).map_err(|error| ApiError::Invalid(format!("invalid annotation batch: {error}")))
}

/// Checked regular-file input on platforms with RangeSource; inline JSON is available on other platforms.
pub fn read_annotation_batch_request(path: &std::path::Path) -> Result<AnnotationBatchArgs, ApiError> {
    let size = crate::range_source::RangeSource::open(path, 0, 0)?.size();
    if size > 8 * 1024 * 1024 {
        return Err(ApiError::Invalid("annotation batch JSON request exceeds 8 MiB".to_owned()));
    }
    let source = crate::range_source::RangeSource::open(path, 0, size as usize)?;
    if source.size() != size {
        return Err(ApiError::Unavailable("annotation batch request size changed while opening".to_owned()));
    }
    let bytes = source.read()?;
    source.revalidate()?;
    parse_annotation_batch_request(&bytes)
}

/// Builds the full transport receipt under the core transaction lock, before publication.
/// Reserve space for the existing conservative post-commit refresh envelope used by bound assistants.
pub fn annotation_batch_page(project: &Project, entries: &[crate::AnnotationBatchEntry]) -> Result<Value, ApiError> {
    let mut receipt = None;
    project.batch_annotations_with_preflight(entries, |planned| {
        let value = serde_json::to_value(planned).map_err(|error| ApiError::Invalid(error.to_string()))?;
        if value.to_string().len() > MAX_RESULT_CHARS - 4096 {
            return Err(ApiError::Invalid(
                "complete batch receipt exceeds its reserved 60000-byte transport budget; \
                 split the batch; no edits persisted"
                    .to_owned(),
            ));
        }
        receipt = Some(value);
        Ok(())
    })?;
    Ok(receipt.expect("core checks complete batch receipt before publication"))
}

#[derive(serde::Deserialize, JsonSchema)]
struct DecompileToolArgs {
    /// Exact address or existing name. Default behavior resolves the containing function.
    at: String,
    /// Assert this exact entry and use bounded local context, without whole-program discovery.
    #[serde(default)]
    exact_entry: bool,
    /// full (default) preserves original JSON; code retains complete native C and essential evidence;
    /// summary omits C text too, with exact counts/omission receipts. Oversized views refuse, never truncate.
    #[serde(default)]
    view: DecompileView,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InspectDataArgs {
    /// Explicit native-image file; no annotation sidecar or dependency is opened.
    path: std::path::PathBuf,
    /// Architecture slice of a universal Mach-O image.
    arch: Option<String>,
    /// Embedded image's file offset; a universal image uses its fat-header offset.
    image_offset: Option<crate::FileOffset>,
    /// With image_offset, the embedded image's length in bytes.
    image_length: Option<crate::FileOffset>,
    /// Image address or existing name, not a runtime address or file offset.
    at: String,
    /// Bytes to inspect (default 128, 1..=1024). Output budgets may require a smaller range.
    #[schemars(range(min = 1, max = 1024))]
    size: Option<usize>,
    /// Word width in bytes, 4 or 8; omitted uses the image architecture's pointer width.
    word_size: Option<u8>,
    #[serde(default)]
    view: ToolView,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DecodeFileArgs {
    /// Explicit regular source file. No executable header, sidecar or dependency is opened.
    path: std::path::PathBuf,
    /// Required decoder selection; no codec guessing.
    codec: crate::ContentCodec,
    /// Byte offset in the original file, not a native-image or decoded address.
    offset: crate::FileOffset,
    /// Encoded range length, 1..=8388608 bytes.
    length: crate::FileOffset,
    /// Analyst-supplied stopping size, 1..=16777216 bytes; does not prove a stream boundary.
    expected_output_size: crate::FileOffset,
    /// Initial dictionary write position 0..4095; default 4078 (0xfee).
    initial_write_offset: Option<u16>,
    /// Dictionary initialization byte; default zero.
    dictionary_fill: Option<u8>,
    /// Cooperative decoder-phase timeout, default 3000 ms, at most 10000; excludes I/O/hash phases.
    timeout_ms: Option<u64>,
    /// Preview byte offset within decoded output; default zero.
    preview_offset: Option<crate::FileOffset>,
    /// Preview bytes, 0..1024; default 256. Zero requests a hash/metadata-only receipt.
    preview_size: Option<usize>,
}

type DecompileView = ToolView;

#[derive(serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum VariableStorageKindInput {
    Processor,
    Spacebase,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VariableUseRangeInput {
    space: String,
    /// Inclusive definition/use selector offset in this space, not a variable live range.
    start: crate::FileOffset,
    end: crate::FileOffset,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VariableStorageInput {
    kind: VariableStorageKindInput,
    space: String,
    /// Address-space offset, not file offset or necessarily a VA; copy returned stack offsets exactly.
    address: crate::FileOffset,
    /// Whole mapping size in bytes. Retypes must have this same native size.
    size: crate::FileOffset,
    use_ranges: Vec<VariableUseRangeInput>,
}

impl VariableStorageInput {
    fn native(self) -> Result<rampage_decompiler::VariableStorage, ApiError> {
        Ok(rampage_decompiler::VariableStorage {
            kind: match self.kind {
                VariableStorageKindInput::Processor => rampage_decompiler::results::StorageKind::Processor,
                VariableStorageKindInput::Spacebase => rampage_decompiler::results::StorageKind::Spacebase,
            },
            space: self.space,
            address: self.address.0,
            size: u32::try_from(self.size.0).map_err(|_| ApiError::Invalid("storage size exceeds 32 bits".into()))?,
            use_ranges: self
                .use_ranges
                .into_iter()
                .map(|range| rampage_decompiler::results::StorageUseRange {
                    space: range.space,
                    start: range.start.0,
                    end: range.end.0,
                })
                .collect(),
        })
    }
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EditVariableArgs {
    /// Function address or name. Select exactly one current display name or complete returned storage object.
    at: String,
    variable: Option<String>,
    storage: Option<VariableStorageInput>,
    /// New local/parameter identifier; changes are persisted by storage, not by generated display name.
    name: Option<String>,
    /// Abstract sized scalar/pointer type, for example struct PhaseState *. Declare named types with set_types.
    data_type: Option<String>,
    #[serde(default)]
    clear_name: bool,
    #[serde(default)]
    clear_type: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DeclareTypesArgs {
    /// Bounded C type declarations. No function bodies, object definitions or external preprocessor execution.
    declarations: Option<String>,
    /// Inline C header text; comments and supported bundled includes/pack pragmas are handled without file access.
    header: Option<String>,
    /// Bundled minimal header profiles: c, posix-linux, win32. Profiles are explicit ABI assertions, not discovery.
    #[serde(default)]
    profiles: Vec<String>,
    /// Packing cap for user declarations/header units: 1, 2, 4, 8 or 16. Bundled profiles retain their fixed ABI.
    packing: Option<u32>,
    /// Replace existing project declaration units. Dependent types, signatures and locals must remain valid.
    #[serde(default)]
    replace: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TypeNameArgs {
    /// Exact named type or alias. Named type inspection uses the target's native data organization.
    name: String,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DeleteTypeArgs {
    name: String,
    /// Explicitly remove every name in the inspected declaration group; outside dependencies still refuse.
    #[serde(default)]
    definition_group: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum DataEncodingInput {
    Utf8,
    Utf16Le,
    Utf16Be,
    Ascii,
}

impl DataEncodingInput {
    fn native(self) -> crate::annotations::DataStringEncoding {
        use crate::annotations::DataStringEncoding;
        match self {
            Self::Utf8 => DataStringEncoding::Utf8,
            Self::Utf16Le => DataStringEncoding::Utf16Le,
            Self::Utf16Be => DataStringEncoding::Utf16Be,
            Self::Ascii => DataStringEncoding::Ascii,
        }
    }
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApplyDataTypeArgs {
    at: String,
    /// Exact native/library type name. Count declares an array of this complete element type.
    type_name: Option<String>,
    count: Option<u32>,
    /// Explicit string decoding, not an inference from a char array; original bytes are preserved.
    encoding: Option<DataEncodingInput>,
    byte_length: Option<u32>,
    #[serde(default)]
    clear: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApplyOperandTypeArgs {
    at: String,
    /// Zero-based decoded explicit operand index; unsupported or stale selections are refused.
    operand: u8,
    type_name: Option<String>,
    #[serde(default)]
    clear: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadDataArgs {
    at: String,
    /// Bounded byte window. Missing/zero-fill bytes are not fabricated as stored zeros.
    size: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FunctionFrameArgs {
    at: String,
    offset: Option<usize>,
    limit: Option<usize>,
    /// Include available static stack-tracker evidence; unknown coordinates are never silently merged.
    include_tracker: Option<bool>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PropagateTypesArgs {
    at: String,
    /// Preview by default. Applying stores separate lower-priority hints, never analyst type overrides.
    #[serde(default)]
    apply: bool,
    max_functions: Option<usize>,
    max_candidates: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportDebugTypesArgs {
    /// Explicit identity-matched PDB path; omit for embedded DWARF. No recorded path or sidecar is followed.
    pdb: Option<String>,
    /// Apply the complete reviewed library/signature batch. Preview is read-only.
    #[serde(default)]
    apply: bool,
    /// Whole-plan review hash from a fresh preview; page boundaries do not limit approval or writes.
    review_sha256: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

pub(crate) fn data_typing_view(result: &impl Serialize) -> Result<Value, ApiError> {
    let value = serde_json::to_value(result).map_err(|error| ApiError::Invalid(error.to_string()))?;
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(ApiError::Invalid(
            "data/operand typing result exceeds the JSON budget; no edit was persisted".into(),
        ));
    }
    Ok(value)
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListTypesArgs {
    /// Case-sensitive substring of the native type name.
    contains: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

fn type_library_view(result: &impl Serialize) -> Result<Value, ApiError> {
    let value = serde_json::to_value(result).map_err(|error| ApiError::Invalid(error.to_string()))?;
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(ApiError::Invalid("type-library result exceeds the JSON budget; no edit was persisted".into()));
    }
    Ok(value)
}

fn variable_edit_view(result: &crate::VariableEditResult) -> Result<Value, ApiError> {
    let decompilation =
        serde_json::to_value(&result.decompilation).map_err(|error| ApiError::Invalid(error.to_string()))?;
    let value = serde_json::json!({
        "address":format!("{:#x}",result.address), "storage":result.storage,
        "edits":result.edits.iter().map(|edit| serde_json::json!({"field":edit.field,"changed":edit.changed}))
            .collect::<Vec<_>>(),
        "decompilation":decompilation_view(decompilation,DecompileView::Code)?,
        "omitted_details":["per-function annotation collection values; inspect the annotation log for replay history"],
    });
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(ApiError::Invalid("variable edit result exceeds the JSON budget; no edit was persisted".into()));
    }
    Ok(value)
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EntryDiagnosticsArgs {
    /// One exact address/name; omitted samples at most 64 metadata-declared addresses.
    at: Option<String>,
    /// Entries to skip; does not change the bounded sampling work.
    offset: Option<usize>,
    /// Entries per page (default 64, 1..64); the encoded byte budget can shorten a page.
    #[schemars(range(min = 1, max = 64))]
    limit: Option<usize>,
}

fn decompile_tool(project: &Project, args: DecompileToolArgs) -> Result<Value, ApiError> {
    let address = project.resolve(&args.at)?;
    let value = if args.exact_entry {
        serde_json::to_value(project.decompile_entry(&crate::DecompileEntryRequest {
            address,
            validation: crate::EntryValidation::AnalystAsserted,
        })?)
    } else {
        serde_json::to_value(project.decompile(address)?)
    };
    let value = value.map_err(|error| ApiError::Invalid(format!("decompilation serialization: {error}")))?;
    decompilation_view(value, args.view)
}

fn decompilation_view(value: Value, view: DecompileView) -> Result<Value, ApiError> {
    project_tool_view(value, ToolViewKind::Decompile, view)
}

fn entry_diagnostics_page(
    report: rampage_analysis::entry_audit::EntryAudit,
    offset: usize,
    limit: usize,
) -> Result<Value, ApiError> {
    if !(1..=64).contains(&limit) {
        return Err(ApiError::Invalid("entry diagnostic limit must be 1..64".to_owned()));
    }
    let mut value = serde_json::to_value(report)
        .map_err(|error| ApiError::Invalid(format!("entry diagnostic serialization: {error}")))?;
    let mut rows = value["entries"]
        .take()
        .as_array()
        .cloned()
        .ok_or_else(|| ApiError::Invalid("entry diagnostic rows unavailable".to_owned()))?;
    let offset = offset.min(rows.len());
    value["entries"] = serde_json::json!([]);
    value["entries_total"] = serde_json::json!(rows.len());
    value["offset"] = serde_json::json!(offset);
    value["limit"] = serde_json::json!(limit);
    value["more"] = Value::Bool(false);
    value["next_offset"] = Value::Null;
    value["byte_capped"] = Value::Bool(false);
    value["transport"] = serde_json::json!({
        "json_byte_budget": MAX_RESULT_CHARS,
        "names_omitted_total": 0,
        "note": "Paging and omitted display aliases do not change code samples or declaration counts."
    });
    let envelope = value.to_string().len() + 256;
    if envelope >= MAX_RESULT_CHARS {
        return Err(ApiError::Invalid("entry diagnostic envelope exceeds the JSON byte budget".to_owned()));
    }
    let mut names_omitted = 0usize;
    for row in &mut rows {
        if row.to_string().len() + 1 + envelope <= MAX_RESULT_CHARS {
            continue;
        }
        let mut omitted = 0usize;
        if let Some(origins) = row["origins"].as_array_mut() {
            for origin in origins {
                if origin["name"].is_string() {
                    origin["name"] = Value::Null;
                    origin["name_omitted"] = Value::Bool(true);
                    omitted += 1;
                }
            }
        }
        row["transport_names_omitted"] = serde_json::json!(omitted);
        names_omitted += omitted;
        if row.to_string().len() + 1 + envelope > MAX_RESULT_CHARS {
            return Err(ApiError::Invalid("entry diagnostic row exceeds the JSON byte budget".to_owned()));
        }
    }
    value["transport"]["names_omitted_total"] = serde_json::json!(names_omitted);
    let mut entries = Vec::new();
    let mut bytes = envelope;
    for row in rows.iter().skip(offset).take(limit) {
        let row_bytes = row.to_string().len() + 1;
        if bytes + row_bytes > MAX_RESULT_CHARS {
            value["byte_capped"] = Value::Bool(true);
            break;
        }
        bytes += row_bytes;
        entries.push(row.clone());
    }
    let next = offset + entries.len();
    value["more"] = Value::Bool(next < rows.len());
    if next < rows.len() {
        value["next_offset"] = serde_json::json!(next);
    }
    value["entries"] = Value::Array(entries);
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(ApiError::Invalid("entry diagnostic result exceeds the JSON byte budget".to_owned()));
    }
    Ok(value)
}

#[cfg(test)]
#[path = "tools/entry_diagnostics_tests.rs"]
mod entry_diagnostics_tests;

#[derive(serde::Deserialize, JsonSchema)]
struct DebugImportArgs {
    #[serde(default)]
    apply: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DebugLayoutImportArgs {
    /// Apply the complete reviewed import atomically; omitted or false is a read-only fresh preview.
    #[serde(default)]
    apply: bool,
    /// Exact lowercase SHA-256 from a fresh preview. Required with apply=true, otherwise omitted.
    #[schemars(length(min = 64, max = 64), regex(pattern = "^[0-9a-f]{64}$"))]
    review_sha256: Option<String>,
    /// Evidence rows to skip, including read-only projection and virtual evidence; never a write subset.
    offset: Option<usize>,
    /// Evidence rows per page (default 100, 1..=1000), also limited to 60000 JSON bytes.
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<usize>,
}

impl DebugLayoutImportArgs {
    fn validate(&self) -> Result<(), String> {
        if self.apply != self.review_sha256.is_some() {
            return Err("apply=true and review_sha256 must be supplied together; nothing imported".to_owned());
        }
        if let Some(digest) = &self.review_sha256 {
            parse_debug_layout_review_sha256(digest)?;
        }
        if !(1..=1000).contains(&self.limit.unwrap_or(DEFAULT_PAGE)) {
            return Err("limit must be in 1..=1000; nothing imported".to_owned());
        }
        Ok(())
    }
}

/// Validates a reviewed layout digest before a CLI or MCP client opens an image or its annotation sidecar.
pub fn parse_debug_layout_review_sha256(text: &str) -> Result<String, String> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("review_sha256 must be exactly 64 lowercase hexadecimal characters; nothing imported".to_owned());
    }
    Ok(text.to_owned())
}

/// Preflights shared-tool arguments before opening source images or annotation sidecars.
pub fn validate_debug_layout_arguments(input: &Value) -> Result<(), String> {
    if input.to_string().len() > 48_000 {
        return Err("debug layout arguments exceed the input byte budget; nothing imported".to_owned());
    }
    let args: DebugLayoutImportArgs = arguments(input.clone())?;
    args.validate()
}

fn debug_layout_receipt(apply_requested: Option<bool>) -> Value {
    serde_json::json!({
        "ok": false, "status": "rejected", "apply_requested": apply_requested,
        "whole_apply_succeeded": false, "review_sha256": null, "image_sha256": null,
        "compiler_spec_sha256": null, "types_total": null, "fields_total": null,
        "functions_total": null, "approved_total": null, "preserved_total": null,
        "applied_total": 0, "imported_types_total": 0, "warnings_total": null,
        "producer_types_total": null, "producer_fields_total": null, "producer_functions_total": null,
        "producer_parameters_total": null, "producer_warnings_total": null,
        "projections_total": null, "vtables_total": null, "vtable_slots_total": null,
        "virtual_methods_total": null, "virtual_warnings_total": null, "virtual_limitations_total": null,
        "details_total": null, "offset": 0, "limit": 0, "details": [],
        "more": false, "next_offset": null, "byte_capped": false,
        "error": null, "error_truncated": false,
    })
}

/// A bounded, unambiguous failure receipt, including failures before the shared layout tool can run.
pub fn debug_layout_import_error(message: &str, apply_requested: Option<bool>) -> String {
    let mut receipt = debug_layout_receipt(apply_requested);
    let bounded = pdb_bounded_text(message, MAX_PDB_ERROR_BYTES);
    receipt["error"] = Value::String(bounded.to_owned());
    receipt["error_truncated"] = Value::Bool(bounded.len() != message.len());
    receipt.to_string()
}

fn debug_layout_detail_capacity() -> Result<usize, ApiError> {
    let mut envelope = debug_layout_receipt(Some(false));
    for (key, value) in envelope.as_object_mut().unwrap() {
        if key.ends_with("_total") || matches!(key.as_str(), "offset" | "limit" | "next_offset") {
            *value = serde_json::json!(usize::MAX);
        } else if key.ends_with("_sha256") {
            *value = Value::String("f".repeat(64));
        }
    }
    envelope["error"] = Value::String("\0".repeat(MAX_PDB_ERROR_BYTES));
    MAX_RESULT_CHARS
        .checked_sub(envelope.to_string().len() + 512)
        .filter(|capacity| *capacity >= 32_000)
        .ok_or_else(|| ApiError::Invalid("debug layout receipt exceeds output capacity; nothing imported".to_owned()))
}

fn debug_layout_value(value: impl Serialize) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|error| ApiError::Invalid(format!("debug layout evidence: {error}")))
}

fn debug_layout_rows(review: &crate::DebugLayoutReview) -> Result<Vec<Value>, ApiError> {
    let mut rows = Vec::new();
    let necessary: std::collections::BTreeSet<_> = review
        .report
        .functions
        .iter()
        .filter(|function| review.approved.contains(&function.address))
        .flat_map(|function| function.dependencies.iter().map(String::as_str))
        .collect();
    for ty in &review.report.types {
        let status = if necessary.contains(ty.layout.name.as_str()) { "verified" } else { "unverified" };
        let mut data = debug_layout_value(ty)?;
        data["layout"].as_object_mut().unwrap().remove("fields");
        data.as_object_mut().unwrap().remove("projections");
        rows.push(serde_json::json!({ "kind": "type", "source": "checked", "status": status, "data": data }));
        for (index, field) in ty.layout.fields.iter().enumerate() {
            let mut row = serde_json::json!({
                "kind": "field", "source": "checked", "status": status,
                "type_name": ty.layout.name, "data": debug_layout_value(field)?,
            });
            if ty.projections.iter().any(|projection| match projection {
                crate::DebugLayoutProjection::OpaqueVptr { field_index, .. } => *field_index == index,
            }) {
                row["storage_role"] = serde_json::json!("opaque_projection_storage_not_exact_producer_type");
            }
            rows.push(row);
        }
    }
    for function in &review.report.functions {
        let status = if review.approved.contains(&function.address) {
            "approved"
        } else if review.preserved.contains(&function.address) {
            "preserved"
        } else {
            "not_approved"
        };
        rows.push(serde_json::json!({
            "kind": "function", "source": "checked", "status": status, "data": debug_layout_value(function)?,
        }));
    }
    for warning in &review.report.warnings {
        rows.push(serde_json::json!({ "kind": "warning", "source": "checked", "text": warning }));
    }
    if let Some(producer) = &review.producer_report {
        for ty in &producer.layouts {
            let mut data = debug_layout_value(ty)?;
            data.as_object_mut().unwrap().remove("fields");
            rows.push(serde_json::json!({
                "kind": "type", "source": "producer", "status": "preview_only", "data": data,
            }));
            for field in &ty.fields {
                rows.push(serde_json::json!({
                    "kind": "field", "source": "producer", "status": "preview_only",
                    "type_id": debug_layout_value(ty.id)?, "type_name": ty.emitted_name,
                    "data": debug_layout_value(field)?,
                }));
            }
        }
        for function in &producer.signatures {
            let mut data = debug_layout_value(function)?;
            data.as_object_mut().unwrap().remove("parameters");
            rows.push(serde_json::json!({
                "kind": "function", "source": "producer", "status": "preview_only", "data": data,
            }));
            for parameter in &function.parameters {
                rows.push(serde_json::json!({
                    "kind": "parameter", "source": "producer", "status": "preview_only",
                    "function_id": debug_layout_value(function.id)?, "data": debug_layout_value(parameter)?,
                }));
            }
        }
        for warning in &producer.warnings {
            rows.push(serde_json::json!({ "kind": "warning", "source": "producer", "text": warning }));
        }
    }
    for ty in &review.report.types {
        for projection in &ty.projections {
            rows.push(serde_json::json!({
                "kind": "projection", "source": "virtual_evidence", "status": "read_only",
                "type_name": ty.layout.name, "data": debug_layout_value(projection)?,
                "storage_role": "opaque_projection_storage_not_exact_producer_type",
            }));
        }
    }
    for table in &review.virtual_evidence.tables {
        let table_address = format!("{:#x}", table.raw.address);
        let mut data = debug_layout_value(&table.raw)?;
        data.as_object_mut().unwrap().remove("slots");
        rows.push(serde_json::json!({
            "kind": "vtable", "source": "virtual_evidence", "status": "read_only",
            "table_address": table_address, "data": data,
        }));
        for slot in &table.raw.slots {
            rows.push(serde_json::json!({
                "kind": "vtable_slot", "source": "virtual_evidence", "status": "read_only",
                "table_address": table_address, "data": debug_layout_value(slot)?,
            }));
        }
        for method in &table.methods {
            rows.push(serde_json::json!({
                "kind": "virtual_method", "source": "virtual_evidence", "status": "read_only",
                "table_address": table_address, "slot_index": method.slot_index,
                "data": debug_layout_value(method)?,
            }));
        }
    }
    for (kind, messages) in
        [("warning", &review.virtual_evidence.warnings), ("limitation", &review.virtual_evidence.limitations)]
    {
        for text in messages {
            rows.push(serde_json::json!({
                "kind": kind, "source": "virtual_evidence", "status": "read_only", "text": text,
            }));
        }
    }
    Ok(rows)
}

fn debug_layout_page(review: &crate::DebugLayoutReview, offset: usize, limit: usize) -> Result<Value, ApiError> {
    let capacity = debug_layout_detail_capacity()?;
    let rows = debug_layout_rows(review)?;
    let sizes: Vec<_> = rows.iter().map(|row| row.to_string().len() + 1).collect();
    if sizes.iter().any(|size| *size > capacity) {
        return Err(ApiError::Invalid(
            "debug layout evidence row exceeds output capacity; nothing imported".to_owned(),
        ));
    }
    let mut receipt = debug_layout_receipt(Some(false));
    receipt["ok"] = Value::Bool(true);
    receipt["status"] = serde_json::json!("preview");
    receipt["review_sha256"] = serde_json::json!(review.review_sha256);
    receipt["image_sha256"] = serde_json::json!(review.image_sha256);
    receipt["compiler_spec_sha256"] = serde_json::json!(review.compiler_spec_sha256);
    receipt["types_total"] = serde_json::json!(review.report.types.len());
    let fields_total = review.report.types.iter().map(|ty| ty.layout.fields.len()).sum::<usize>();
    receipt["fields_total"] = serde_json::json!(fields_total);
    receipt["functions_total"] = serde_json::json!(review.report.functions.len());
    receipt["approved_total"] = serde_json::json!(review.approved.len());
    receipt["preserved_total"] = serde_json::json!(review.preserved.len());
    receipt["warnings_total"] = serde_json::json!(review.report.warnings.len());
    let producer = review.producer_report.as_ref();
    receipt["producer_types_total"] = serde_json::json!(producer.map_or(0, |report| report.layouts.len()));
    receipt["producer_fields_total"] = serde_json::json!(
        producer.map_or(0, |report| { report.layouts.iter().map(|ty| ty.fields.len()).sum::<usize>() })
    );
    receipt["producer_functions_total"] = serde_json::json!(producer.map_or(0, |report| report.signatures.len()));
    receipt["producer_parameters_total"] = serde_json::json!(
        producer
            .map_or(0, |report| { report.signatures.iter().map(|function| function.parameters.len()).sum::<usize>() })
    );
    receipt["producer_warnings_total"] = serde_json::json!(producer.map_or(0, |report| report.warnings.len()));
    receipt["projections_total"] =
        serde_json::json!(review.report.types.iter().map(|ty| ty.projections.len()).sum::<usize>());
    let virtual_evidence = &review.virtual_evidence;
    receipt["vtables_total"] = serde_json::json!(virtual_evidence.tables.len());
    receipt["vtable_slots_total"] =
        serde_json::json!(virtual_evidence.tables.iter().map(|table| table.raw.slots.len()).sum::<usize>());
    receipt["virtual_methods_total"] =
        serde_json::json!(virtual_evidence.tables.iter().map(|table| table.methods.len()).sum::<usize>());
    receipt["virtual_warnings_total"] = serde_json::json!(virtual_evidence.warnings.len());
    receipt["virtual_limitations_total"] = serde_json::json!(virtual_evidence.limitations.len());
    let total = rows.len();
    let offset = offset.min(total);
    receipt["details_total"] = serde_json::json!(total);
    receipt["offset"] = serde_json::json!(offset);
    receipt["limit"] = serde_json::json!(limit);
    let mut bytes = 0;
    let count = sizes
        .iter()
        .skip(offset)
        .take(limit)
        .take_while(|size| {
            bytes += **size;
            bytes <= capacity
        })
        .count();
    let next = offset + count;
    receipt["byte_capped"] = Value::Bool(count < limit.min(total - offset));
    receipt["details"] = Value::Array(rows.into_iter().skip(offset).take(count).collect());
    receipt["more"] = Value::Bool(next < total);
    receipt["next_offset"] = if next < total { serde_json::json!(next) } else { Value::Null };
    Ok(receipt)
}

fn import_debug_layout_page(project: &Project, args: DebugLayoutImportArgs) -> Result<Value, ApiError> {
    args.validate().map_err(ApiError::Invalid)?;
    let review = project.review_debug_layouts()?;
    debug_layout_page_before_apply(&review, &args, |digest| project.apply_reviewed_debug_layouts(digest))
}

fn debug_layout_page_before_apply(
    review: &crate::DebugLayoutReview,
    args: &DebugLayoutImportArgs,
    apply: impl FnOnce(&str) -> Result<crate::DebugLayoutReview, ApiError>,
) -> Result<Value, ApiError> {
    // Serialize every evidence row and reserve the whole receipt before any annotation action.
    let mut receipt = debug_layout_page(review, args.offset.unwrap_or(0), args.limit.unwrap_or(DEFAULT_PAGE))?;
    if let Some(digest) = &args.review_sha256 {
        if review.review_sha256 != *digest {
            return Err(ApiError::Invalid(
                "debug layout review changed; preview and review again; nothing imported".to_owned(),
            ));
        }
        let applied = apply(digest)?;
        debug_layout_applied_receipt(&mut receipt, &applied);
    }
    Ok(receipt)
}

fn debug_layout_applied_receipt(receipt: &mut Value, applied: &crate::DebugLayoutReview) {
    receipt["apply_requested"] = Value::Bool(true);
    receipt["whole_apply_succeeded"] = Value::Bool(true);
    receipt["status"] = serde_json::json!("applied");
    if let Some(imported) = &applied.imported {
        receipt["applied_total"] = serde_json::json!(imported.applied.len());
        receipt["preserved_total"] = serde_json::json!(imported.preserved.len());
        receipt["imported_types_total"] = serde_json::json!(imported.imported_types.len());
        for row in receipt["details"].as_array_mut().unwrap() {
            if row["source"] != "checked" {
                continue;
            }
            let is_applied = match row["kind"].as_str() {
                Some("function") => imported
                    .applied
                    .iter()
                    .any(|address| row["data"]["address"].as_str() == Some(format!("{address:#x}").as_str())),
                Some("type") => imported.imported_types.iter().any(|name| row["data"]["layout"]["name"] == *name),
                Some("field") => imported.imported_types.iter().any(|name| row["type_name"] == *name),
                _ => false,
            };
            if is_applied {
                row["status"] = serde_json::json!("applied");
            } else if row["kind"] == "function"
                && imported
                    .preserved
                    .iter()
                    .any(|address| row["data"]["address"].as_str() == Some(format!("{address:#x}").as_str()))
            {
                row["status"] = serde_json::json!("preserved");
            }
        }
    }
}

#[cfg(test)]
#[path = "tools/debug_layout_tests.rs"]
mod debug_layout_tests;

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
    /// Optional bounded JSON FuzzyBuildRequest path: explicit owned_names and source provenance.
    /// Writes a separate fuzzy database, never an exact database or project annotations.
    #[serde(default)]
    fuzzy_request: Option<String>,
}

#[derive(serde::Deserialize, JsonSchema)]
struct IdentifyArgs {
    /// Optional native JSON/gzip or user-supplied PAT database, consulted before packs and builtins.
    /// FID namespaces require the separate explicitly configured trusted-host API.
    #[serde(default)]
    database: Option<String>,
    /// Separate bounded fuzzy JSON database, never an exact match or an applied name.
    /// Requires fuzzy_request; currently cannot combine with no_bundled.
    #[serde(default)]
    fuzzy_database: Option<String>,
    /// Bounded JSON FuzzySuggestRequest path: distinct cohort, 1..64 numeric entry addresses,
    /// and candidates_per_function (1..16). Required with fuzzy_database.
    #[serde(default)]
    fuzzy_request: Option<String>,
    /// Leave out the bundled starter database, matching against `database` and the data packs' databases only
    /// (needs at least one of them).
    #[serde(default)]
    no_bundled: bool,
    /// Persist matched names for still-unnamed functions as user names (never overwriting existing names).
    #[serde(default)]
    apply: bool,
    /// Detail rows to skip: exact matches, pack warnings, then fuzzy suggestions. Never selects writes.
    #[serde(default)]
    offset: Option<usize>,
    /// Detail rows per page (default 100, 1..=256), also bounded to 60000 complete JSON bytes.
    #[serde(default)]
    #[schemars(range(min = 1, max = 256))]
    limit: Option<usize>,
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
struct BuildInfoArgs {
    /// Go dependency modules and Rust packages to skip, for paging (each list independently).
    #[serde(default)]
    offset: Option<usize>,
    /// Entries per page of each list (default 100, at most 1000).
    #[serde(default)]
    limit: Option<usize>,
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
            Group::Core,
            "batch",
            "Atomically apply heterogeneous checked annotations: entries use operation=rename/comment/signature/\
             types/global, at as an existing name or numeric address STRING, and a REQUIRED value string or null \
             (clear). All names resolve against the pre-batch snapshot. One checked transaction and one undo step; \
             invalid operations, duplicate field/address targets, malformed declarations, conflicts or oversized \
             complete receipts write nothing. At most 1000 entries; split batches whose full receipt cannot fit \
             the 60000-byte JSON budget including reserved refresh/cancellation evidence. No patch, raw-field, \
             export or SSA bypass. annotate_batch retains its separate legacy name/comment shape. A bound \
             assistant may stop conservatively after a committed batch when exclusive transition attribution is \
             unavailable; its full outcome is retained and must not be automatically retried.",
            |project, args: AnnotationBatchArgs| annotation_batch_page(project, &args.entries),
        )
        .annotates(),
        tool(
            Group::Core,
            "assemble",
            "Assemble literal source into a read-only byte proposal for this binary's current target. \
             at is a numeric address string or resolvable name; only the base address resolves names. \
             source is literal assembly, never a filename or shell command: one instruction per nonempty line, \
             at most 16 KiB, 64 instructions and 4096 output bytes. Supported core subset: x86/x64 register \
             MOV/CMP, NOP/RET and numeric branches; little-endian AArch64 MOV/MOVZ/CMP, NOP/RET and numeric \
             branches. Other architectures/modes, labels, comments, directives, memory operands, macros and \
             symbolic branch targets are refused with line errors. Returns actual target/base, bytes_hex, \
             original byte array, canonical_disassembly, instruction_count and evidence_profile within 60000 \
             JSON bytes. Encoding/decoding evidence is NOT execution or behavior verification. No external \
             assembler, execution, image patches, annotation writes, exports or implicit application.",
            |project, request: crate::AssemblyRequest| project.assemble(&request),
        ),
        tool(
            Group::Core,
            "search",
            "Read-only unified native search. mode.kind selects bytes (hex/nibble wildcards), text \
             (ascii, utf16_le or utf16_be; literal or Unicode regex), immediate (signed/unsigned numeric value, \
             optional width_bits/include_displacements/include_addresses), instruction (mnemonic/operand globs), \
             references (exact target) or functions_referencing (address/string/import/constant reference). \
             Address targets and half-open range endpoints accept numbers, address strings or resolvable names; \
             immediate values never resolve names. Example: {\"mode\":{\"kind\":\"functions_referencing\",\"reference\":\
             {\"kind\":\"string\",\"text\":\"hello\",\"encoding\":\"utf8\"}}}. Context defaults true. \
             offset/limit (1..1000) page hits, never restrict scan work. total_is_exact distinguishes exact totals \
             from observed lower bounds; stop_reason/budget explain incomplete scans. more/next_offset page \
             observed rows even after incomplete scans, not scan resumption. Complete JSON stays within 60000 \
             bytes with whole hit rows and no wrapper string cutting. Native context truncation/provenance and \
             retained source paths are preserved. Capture file_offset is null. No annotations or source writes.",
            |project, request: crate::SearchRequest| project.search_page(&request),
        ),
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
            "Structural function summary, not native recovered C. view=full (default) preserves original JSON; \
             summary omits instruction/IR rendering with exact counts and omission receipts; code retains native \
             instructions and labels partial structural pseudocode explicitly. Source/control/diagnostic/type \
             evidence stays retained. Oversized results refuse; choose a compact view rather than truncated output.",
            |project, arguments: ViewedAt| {
                let value = serde_json::to_value(project.function_summary(project.resolve(&arguments.at)?)?)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?;
                project_tool_view(value, ToolViewKind::FunctionSummary, arguments.view)
            },
        ),
        tool(
            Group::Core,
            "decompile",
            "Decompile C with embedded Ghidra and retain native recovery diagnostics. Default behavior uses the \
             containing function and whole-program context. exact_entry=true treats at as an analyst-asserted \
             exact entry with bounded local context and the full mapped image (little-endian x86/x64/AArch64). \
              Entry metadata and successful decoding are not boundary or completeness proof; exact output includes \
               context counts, omissions and preparation timings. No silent whole-program fallback. view=full \
               (default) preserves original JSON; code omits token/structure payloads while retaining complete native \
               C, native diagnostics, recovery/context/specification evidence. summary also omits C text with exact \
               counts and omission receipts. Oversized views refuse, never truncate strings.",
            decompile_tool,
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
            "import_debug_layouts",
            "Review bounded embedded-DWARF checked plain layouts and function signatures (x86_64 ELF/GCC only). \
             Preview is read-only. Apply requires apply=true plus the exact lowercase review_sha256 from a fresh \
             preview, binding ALL admitted layouts, functions, producer evidence, warnings and current image/options/\
             specifications and annotation eligibility, not just the page. Changed content requires re-review; \
             the hash is not authentication or rebinding of an old process-local receipt. The core applies the whole \
             dependency batch atomically, preserving analyst signatures. offset/limit page whole evidence rows only; \
             they never select writes. Receipts retain hashes, exact counts and whole_apply_succeeded within 60000 \
             JSON bytes; more/next_offset continue evidence. Fetch later pages with apply=false and no review_sha256. \
             Opaque vptr projections describe consumer storage, not exact producer void pointers or callback types. \
             Read-only named vtable rows retain raw header confidence and candidate slots. Exact method associations \
             are native-checked source evidence, not current/applied analyst types, table ownership, object-vptr proof \
             or virtual-call targets. Producer evidence alone is not native layout proof. \
             Undo is same-process only, not recovered after CLI exit.",
            import_debug_layout_page,
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
            "Build a native library-function signature database from this binary's named \
             functions and write it to the output path. Each function is hashed over its symbol size and over the \
             extent discovery finds for it; functions whose masked bodies collide also get callee keys (the \
             optional calls/ambiguous_calls fields). Reports function signatures and callee keys separately. Use it \
              on a binary with symbols, then identify_functions on a stripped one. Optional fuzzy_request is an \
              explicit source-name/provenance JSON request; it builds a SEPARATE secondary fuzzy database, not \
              exact identity evidence. Query it with identify_functions fuzzy_database and fuzzy_request.",
            |project, arguments: SignatureBuildArgs| {
                if let Some(request) = &arguments.fuzzy_request {
                    let report = project.build_fuzzy_signature_file(std::path::Path::new(request))?;
                    let database = report.database.as_ref().ok_or_else(|| {
                        ApiError::Invalid(
                            "no selected source bodies passed the fuzzy evidence gate; no database written".to_owned(),
                        )
                    })?;
                    let bytes = database.save_json().map_err(|error| ApiError::Invalid(error.to_string()))?;
                    std::fs::write(&arguments.output, bytes)
                        .map_err(|error| ApiError::Invalid(format!("cannot write {}: {error}", arguments.output)))?;
                    return Ok(serde_json::json!({
                        "fuzzy_references":report.references,
                        "rejected":report.rejected.len(),
                        "suggestions_only":true,
                        "output":arguments.output,
                    }));
                }
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
            "Identify library functions using native databases or user-supplied PAT patterns. Statically linked \
             library code in a stripped binary gets recognized. Applies, first match winning: an optional \
             database path, then loaded data packs' databases in pack order, then the bundled starter database for \
             the architecture (left out with no_bundled=true, which works with a database path, a data pack's \
             database for the architecture, or both, and is refused with neither). Each match's `source` names \
             the database that named it: \"user database\", the data pack's name, or \"rampage-builtin\". \
             A function whose masked body collides with another's is named by the names of the functions it \
             calls, once those are named; thunks too small for the confidence gate are never named. apply=true \
             saves names for unnamed functions. `warnings` names data packs or pack signature databases that did \
             not load. offset/limit page details only (default 100, 1..=256): address-sorted matches first, then \
             warnings using the same offset. matches retains its original row shape. matched/applied are WHOLE \
             result totals; apply=true considers ALL matches regardless of the page, preserving existing names \
             and skipping rename collisions. Read later pages with apply=false. Complete rows and the full receipt \
             fit within 60000 JSON bytes; more/next_offset continue details, omission counts include prior pages. \
              An oversized first row or header is refused before any names are written; strings are never cut. \
              database accepts explicit .pat, .json, native .gz or extensionless JSON; FID requires separate \
              explicitly configured Ghidra import. Optional fuzzy_database plus fuzzy_request produces separate \
              read-only fuzzy suggestions after exact/warning rows. Fuzzy totals never increase matched/applied; \
              all fuzzy loading, querying and receipt validation finish BEFORE exact apply writes. Fuzzy requests \
              currently cannot combine with no_bundled. Exact and existing analyst names retain priority.",
            identify_page,
        )
        .annotates(),
    ];
    // The workflow registry's tools, at the place in the order models have always seen them.
    tools.extend(WORKFLOWS.iter().map(|&workflow| workflow_tool(workflow)));
    tools.extend([
        tool(
            Group::Diagnostics,
            "entry_diagnostics",
            "Sample one exact at address/name, or at most 64 metadata-declared entries when omitted. Returns \
             origins, bounded local decode evidence, limits and truncation without whole-program discovery. \
             Metadata and decode success do not verify a function; suspicious bytes do not prove encryption. \
             offset/limit page whole entry rows within 60000 JSON bytes. Oversized display aliases may be omitted \
             explicitly without changing sample evidence or declaration counts; more/next_offset continue pages.",
            |project, args: EntryDiagnosticsArgs| {
                let limit = args.limit.unwrap_or(64);
                if !(1..=64).contains(&limit) {
                    return Err(ApiError::Invalid("entry diagnostic limit must be 1..64".to_owned()));
                }
                entry_diagnostics_page(
                    project.entry_diagnostics(args.at.as_deref().map(|at| project.resolve(at)).transpose()?)?,
                    args.offset.unwrap_or(0),
                    limit,
                )
            },
        ),
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
             strings, types, single-dimensional arrays, verified local enums and boxed values/vectors in object[]; \
             unsupported values report errors. \
             Type fields can retain verified local enum constants as exact numeric strings; attribute numeric \
             values are not replaced by symbolic names. \
             Serialized local enum identities accept canonical reflection escapes, not assembly qualification \
             or external enum loading. \
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
            Group::Formats,
            "build_info",
            "Toolchain build metadata embedded in the image. go: Go build info (the `go version -m` record) from \
             .go.buildinfo, __go_buildinfo or a 16-byte aligned scan of PE/data sections, with go_version, main \
             package path, main module, dependency modules with their => replacements, build settings (-compiler, \
             CGO_ENABLED, GOOS/GOARCH, vcs.revision, vcs.time...) and a cross-check of the version against the \
             pclntab layout; go1.18+ inline strings and older pointer layouts are both read. rust: the \
             cargo-auditable .dep-v0 section (zlib JSON, 8 MiB cap) with root package(s) and every package's \
             name, version, source, kind and dependency indices. Each is null when not present, or has status \
             present/unreadable (with a reason) when found. offset/limit page go.deps and rust.packages \
             independently (default 100, at most 1000). Self-reported build data, not verified against code; no \
             vulnerability lookup, no network access.",
            |project, args: BuildInfoArgs| {
                let query = crate::BuildInfoQuery { offset: args.offset, limit: page_limit(args.limit) };
                Ok::<_, ApiError>(project.build_info(&query))
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
        tool(
            Group::Core,
            "binary_info",
            "Format, architecture, entry point and retained image metadata. view=full (default) preserves original \
             JSON; summary replaces segment/section/register/module rows with counts and explicit omission receipts \
             while retaining identity, source, warnings and other evidence. code is unsupported for metadata. \
             Oversized views refuse with compact-view guidance, never plaintext truncation.",
            |project, args: ViewArgs| {
                let value =
                    serde_json::to_value(project.summary()).map_err(|error| ApiError::Invalid(error.to_string()))?;
                project_tool_view(value, ToolViewKind::BinaryInfo, args.view)
            },
        ),
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
            "Disassemble instructions from an address/name with native bytes, control flow and annotations. \
             view=full (default) and code preserve the original complete listing; summary omits text/bytes with \
             bounds/counts and explicit omission receipts, retaining non-rendering control/annotation evidence. \
             Oversized views refuse; reduce count or choose summary. No string truncation.",
            |project, arguments: ViewedDisassembleArgs| {
                let count = arguments.listing.count.unwrap_or(crate::DEFAULT_INSTRUCTIONS).min(1000);
                let value = serde_json::to_value(project.disassemble(arguments.listing.at.as_deref(), count)?)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?;
                project_tool_view(value, ToolViewKind::Disassemble, arguments.view)
            },
        ),
        tool(
            Group::Core,
            "function_graph",
            "The control-flow graph of the function containing an address or name: its basic blocks with \
             disassembly, and edges (unconditional, taken, not_taken, or switch from a register jump to each case \
             of a bounded switch table) indexing into the blocks. A call that never returns ends its block with no \
             fall-through edge; its line says why in `noreturn`: `listed` (the callee is documented never to \
              return) or `inferred` (no path through the callee returns). view=full (default) preserves original JSON; \
              code keeps instructions/bytes/labels and control evidence; summary omits line rendering with counts \
              and explicit omission receipts. Oversized views refuse, never truncate strings.",
            |project, arguments: ViewedAt| {
                let value = serde_json::to_value(project.function_graph(project.resolve(&arguments.at)?)?)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?;
                project_tool_view(value, ToolViewKind::FunctionGraph, arguments.view)
            },
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
            "import_debug_types",
            "Preview checked project-library types and scalar/pointer function signatures from embedded DWARF \
             or an explicit identity-matched PDB. Independently compares retained producer facts with native \
             target layouts; unknown producer alignment stays unknown. Apply requires the whole-plan review \
             hash and commits the complete library/proof/signature batch atomically. Unsupported bitfields, \
             dependencies and ABI shapes remain explicit; no partial record is presented as complete. No \
             implicit debug paths, downloads, host preprocessor or executable-byte changes. Paging is read-only \
             detail selection, never a write subset. Identity linkage is not source authentication.",
            |project, args: ImportDebugTypesArgs| {
                let request = crate::DebugTypesRequest {
                    pdb: args.pdb.map(std::path::PathBuf::from),
                    apply: args.apply,
                    review_sha256: args.review_sha256,
                    offset: args.offset.unwrap_or(0),
                    limit: args.limit.unwrap_or(DEFAULT_PAGE),
                };
                let result = project
                    .import_debug_types_with_preflight(&request, |result| data_typing_view(result).map(|_| ()))?;
                data_typing_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "propagate_types",
            "Preview or apply bounded provenance-bearing type candidates across proven direct calls. Explicit \
             analyst signatures/variables/globals take priority; incompatible candidates and unsupported ABI \
             shapes remain conflicts or unknowns. Applied hints are separate lower-priority annotations, with \
             source fingerprints, checked undo/replay and no binary patching. Preview is read-only.",
            |project, args: PropagateTypesArgs| {
                let request = crate::PropagationRequest {
                    address: project.resolve(&args.at)?,
                    apply: args.apply,
                    max_functions: args.max_functions.unwrap_or(16),
                    max_candidates: args.max_candidates.unwrap_or(128),
                };
                let result =
                    project.propagate_types_with_preflight(&request, |result| data_typing_view(result).map(|_| ()))?;
                data_typing_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "function_frame",
            "Inspect one function's native locals/parameters with current user names/types and complete storage, \
             plus available static stack-access/register-preservation candidates. Coordinate origins and unknown \
             widths remain explicit; native stack space is not silently equated with entry-SP tracker offsets. \
             Bounded paging, diagnostics and omissions do not imply a complete frame or producer ABI proof.",
            |project, args: FunctionFrameArgs| {
                data_typing_view(&project.function_frame(
                    project.resolve(&args.at)?,
                    &crate::FrameQuery {
                        offset: args.offset.unwrap_or(0),
                        limit: args.limit.unwrap_or(64),
                        include_tracker: args.include_tracker.unwrap_or(true),
                    },
                )?)
            },
        ),
        tool(
            Group::Types,
            "apply_data_type",
            "Annotate a mapped data range with a complete native element type and optional array count, or an \
             explicit byte-length/string encoding. Native globals feed decompilation; read_data renders typed \
             fields without patching bytes. Checked undo/replay preserves bindings. Conflicting globals, invalid \
             ranges and unsupported layouts refuse atomically; missing bytes remain explicit.",
            |project, args: ApplyDataTypeArgs| {
                let request = crate::ApplyDataTypeRequest {
                    type_name: args.type_name,
                    count: args.count,
                    encoding: args.encoding.map(DataEncodingInput::native),
                    byte_length: args.byte_length,
                    clear: args.clear,
                };
                let result =
                    project.apply_data_type_with_preflight(project.resolve(&args.at)?, &request, |result| {
                        data_typing_view(result).map(|_| ())
                    })?;
                data_typing_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "apply_enum",
            "Apply a named enum to one native-decoded immediate operand. Uses decoded logical width and raw \
             value, not formatted-text matching. Disassembly keeps raw bytes/text and exposes analyst-symbolic \
             annotations. Unsupported forms, missing types and stale instruction bytes are refused; no patches.",
            |project, args: ApplyOperandTypeArgs| {
                let request = crate::ApplyOperandTypeRequest {
                    operand: args.operand,
                    type_name: args.type_name,
                    clear: args.clear,
                };
                let result = project.apply_enum_with_preflight(project.resolve(&args.at)?, &request, |result| {
                    data_typing_view(result).map(|_| ())
                })?;
                data_typing_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "apply_offset",
            "Display a decoded base-register memory displacement as a named struct field under an explicit \
             analyst type assertion. Rejects PC-relative, indexed, negative or unsupported selectors rather than \
             guessing an object base. Persists exact instruction-byte selectors with checked undo/replay.",
            |project, args: ApplyOperandTypeArgs| {
                let request = crate::ApplyOperandTypeRequest {
                    operand: args.operand,
                    type_name: args.type_name,
                    clear: args.clear,
                };
                let result = project.apply_offset_with_preflight(project.resolve(&args.at)?, &request, |result| {
                    data_typing_view(result).map(|_| ())
                })?;
                data_typing_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "read_data",
            "Read a bounded image or immutable-snapshot data window with persistent typed fields, array elements and \
             explicit string encodings. Retains raw bytes, backing status, byte order and loader limitations. \
             Integers remain exact, pointer words are not followed, and invalid/partial text stays visible.",
            |project, args: ReadDataArgs| {
                data_typing_view(
                    &project
                        .read_data(&crate::TypedDataQuery { address: project.resolve(&args.at)?, size: args.size })?,
                )
            },
        ),
        tool(
            Group::Types,
            "declare_types",
            "Declare named project struct/union/enum/typedef/function-pointer types, or import a bounded inline C \
             header with bundled profiles. Reports native target layouts and persists dependency-ordered units \
             with undo/redo/replay. Optional packing is explicit; profiles assert an ABI rather than detect one. \
             No filesystem includes, host preprocessor, function bodies or binary patches. Invalid dependencies \
             and oversized edit receipts do not persist. Existing set_types annotations remain compatible.",
            |project, args: DeclareTypesArgs| {
                let request = crate::DeclareTypesRequest {
                    declarations: args.declarations,
                    header: args.header,
                    profiles: args.profiles,
                    packing: args.packing,
                    replace: args.replace,
                };
                let result =
                    project.declare_types_with_preflight(&request, |result| type_library_view(result).map(|_| ()))?;
                type_library_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "list_types",
            "List the selected project's named type library with bounded paging. Use get_type for native field \
             offsets and alias/enum/callback detail. This does not infer producer layout from analyst declarations.",
            |project, args: ListTypesArgs| {
                type_library_view(&project.list_types(
                    args.contains.as_deref(),
                    args.offset.unwrap_or(0),
                    page_limit(args.limit).unwrap_or(DEFAULT_PAGE),
                )?)
            },
        ),
        tool(
            Group::Types,
            "get_type",
            "Inspect one native named type: target size/alignment, packing, fields and offsets, aliases, enum \
             values and function-pointer detail where present. Incomplete types remain explicitly incomplete; \
             declarations are analyst interpretation, not evidence of the original producer's ABI.",
            |project, args: TypeNameArgs| type_library_view(&project.get_type(&args.name)?),
        ),
        tool(
            Group::Types,
            "delete_type",
            "Delete a project type declaration without cascading. Refuses deletion when retained declarations, \
             globals, signatures or locals depend on it. Native checked undo/redo and replay preserve the library; \
             builtin and legacy address-bound types are not silently removed. Multi-name groups require \
             definition_group=true and report every removed name.",
            |project, args: DeleteTypeArgs| {
                let check = |result: &crate::TypeLibraryEdit| type_library_view(result).map(|_| ());
                let result = if args.definition_group {
                    project.delete_type_group_with_preflight(&args.name, check)?
                } else {
                    project.delete_type_with_preflight(&args.name, check)?
                };
                type_library_view(&result)
            },
        )
        .annotates(),
        tool(
            Group::Types,
            "edit_variable",
            "Rename/retype one decompiler local or parameter by its current display name OR complete returned \
             storage identity, including inclusive definition/use ranges. Returns refreshed complete C, diagnostics \
             and variable descriptors in this call. Persists storage-keyed annotations with atomic undo/redo/replay. \
             Named structs use existing set_types declarations. Initially supports single whole processor/stack \
             mappings and same-size scalar/pointer types; dynamic/join/piece/ambiguous selectors are refused. \
             Set name/data_type or clear_name/clear_type. Invalid or oversized refreshed results do not persist.",
            |project, args: EditVariableArgs| {
                let request = crate::VariableEditRequest {
                    variable: args.variable,
                    storage: args.storage.map(VariableStorageInput::native).transpose()?,
                    name: args.name,
                    data_type: args.data_type,
                    clear_name: args.clear_name,
                    clear_type: args.clear_type,
                };
                let result = project.edit_variable_with_preflight(project.resolve(&args.at)?, &request, |result| {
                    variable_edit_view(result).map(|_| ())
                })?;
                variable_edit_view(&result)
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
            "record_finding",
            "Record what you established, still don't know, or want answered (kind finding/unknown/question), with \
             the tool calls that support it, in a ledger saved beside the binary for later sessions and other \
             agents. Without id it creates an entry and returns its stable id; with id it updates only the fields \
             given (status, resolution, ...). One undo step per call.",
            |project, arguments: crate::LedgerRequest| project.record_finding(&arguments),
        )
        .annotates(),
        tool(
            Group::Core,
            "list_findings",
            "Page the investigation ledger by kind, status, address, function or text, with open/resolved counts \
             per kind. Entries recorded on another build of the binary are flagged image_changed.",
            |project, arguments: crate::LedgerQuery| project.list_findings(&arguments),
        ),
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
    tools.extend(patch_page::tools());
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
        handler: Handler::Borrowed(Box::new(handler)),
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
    dispatch(tools, name, input, |tool, input| match &tool.handler {
        Handler::Borrowed(handler) => handler(project, input),
        Handler::Shared(_) => Err(format!("tool {name} requires shared-project dispatch (call_shared)")),
    })
}

/// Runs against the current immutable effective snapshot and replaces it after annotation edits.
/// A snapshot acquisition failure is an error, never permission to read the old bytes.
pub fn call_shared(tools: &[Tool], project: &mut Arc<Project>, name: &str, input: Value) -> (String, bool) {
    call_shared_inner(tools, project, name, input, false, None, &mut None)
}

/// Like `call_shared`, but refuses to follow a newer snapshot before admitting the handler.
pub fn call_shared_bound(tools: &[Tool], project: &mut Arc<Project>, name: &str, input: Value) -> (String, bool) {
    let expected = project.annotation_revision().ok();
    call_shared_bound_revision(tools, project, name, input, expected.as_ref()).0
}

/// Compares held byte and annotation identities within one original project's snapshot lineage.
pub fn same_effective_revision(left: &Project, right: &Project) -> bool {
    Arc::ptr_eq(&left.patch_revision(), &right.patch_revision())
        && left
            .annotation_revision()
            .ok()
            .zip(right.annotation_revision().ok())
            .is_some_and(|(left, right)| Arc::ptr_eq(&left, &right))
}

/// Includes the exact validated annotation-view identity, not a later read of a live original project's map.
pub fn call_shared_bound_revision(
    tools: &[Tool],
    project: &mut Arc<Project>,
    name: &str,
    input: Value,
    expected_revision: Option<&Arc<()>>,
) -> ((String, bool), Option<Arc<()>>) {
    let mut revision = None;
    let result = call_shared_inner(tools, project, name, input, true, expected_revision, &mut revision);
    (result, revision)
}

fn call_shared_inner(
    tools: &[Tool],
    project: &mut Arc<Project>,
    name: &str,
    input: Value,
    bound: bool,
    expected_revision: Option<&Arc<()>>,
    revision: &mut Option<Arc<()>>,
) -> (String, bool) {
    dispatch(tools, name, input, |tool, input| {
        let current = project.effective_snapshot().map_err(|error| error_chain(&error))?;
        if bound
            && (!same_effective_revision(project, &current)
                || expected_revision.is_some_and(|expected| {
                    !current.annotation_revision().is_ok_and(|now| Arc::ptr_eq(&now, expected))
                }))
        {
            return Err("assistant snapshot changed before tool admission; no tool dispatched".to_owned());
        }
        *project = current;
        match &tool.handler {
            Handler::Shared(handler) => {
                let result = handler(project, input)?;
                if bound && tool.effect == Effect::Annotations {
                    if let (Some(expected), Some(transition)) = (expected_revision, &result.transition)
                        && Arc::ptr_eq(expected, &transition.before)
                        && project.annotation_revision().is_ok_and(|after| Arc::ptr_eq(&after, &transition.after))
                    {
                        *revision = Some(Arc::clone(&transition.after));
                    }
                } else {
                    *revision = project.annotation_revision().ok();
                }
                Ok(result.value)
            }
            Handler::Borrowed(handler) => {
                let before = (bound && tool.effect == Effect::Annotations && tool.name != "batch").then(|| {
                    (
                        serde_json::to_value(project.annotation_list()).expect("annotation JSON"),
                        project.patch_revision(),
                    )
                });
                let result = handler(project, input);
                if tool.effect != Effect::Annotations {
                    if result.is_ok() {
                        *revision = project.annotation_revision().ok();
                    }
                    return result;
                }
                if bound && tool.name == "batch" {
                    return result.map(|receipt| {
                        post_commit_refresh_unavailable(
                            receipt,
                            "batch outcome has no atomic run-attribution witness; \
                             retain the outcome and stop; do not automatically retry",
                        )
                    });
                }
                match project.effective_snapshot() {
                    Ok(current) => {
                        let stamp = match current.annotation_revision() {
                            Ok(stamp) => stamp,
                            Err(error) => {
                                return result
                                    .map(|receipt| post_commit_refresh_unavailable(receipt, &error_chain(&error)));
                            }
                        };
                        if let (Some((before, patches)), Ok(receipt)) = (&before, &result) {
                            let after = serde_json::to_value(current.annotation_list()).expect("annotation JSON");
                            if !Arc::ptr_eq(patches, &current.patch_revision())
                                || !exact_edit_transition(before, receipt, &after)
                                || !current.annotation_revision().is_ok_and(|now| Arc::ptr_eq(&now, &stamp))
                            {
                                return result.map(|receipt| {
                                    post_commit_refresh_unavailable(
                                        receipt,
                                        "annotation transition cannot be attributed exclusively to this run",
                                    )
                                });
                            }
                        }
                        *revision = Some(stamp);
                        *project = current;
                        result
                    }
                    Err(error) => result.map(|receipt| post_commit_refresh_unavailable(receipt, &error_chain(&error))),
                }
            }
        }
    })
}

fn exact_edit_transition(before: &Value, receipt: &Value, after: &Value) -> bool {
    if before == after {
        return true;
    }
    let mut expected = before.clone();
    let edits = receipt.as_array().cloned().unwrap_or_else(|| vec![receipt.clone()]);
    for edit in edits {
        let field = match edit["field"].as_str() {
            Some("name") => "names",
            Some("comment") => "comments",
            Some("signature") => "signatures",
            Some("types") => "types",
            Some("global") => "globals",
            _ => return false,
        };
        let Some(address) = edit.get("address").and_then(Value::as_str) else {
            return false;
        };
        let Some(value) = edit.get("value") else {
            return false;
        };
        let Some(rows) = expected[field].as_array_mut() else {
            return false;
        };
        rows.retain(|row| row["address"] != address);
        if !value.is_null() {
            let Some(text) = value.as_str() else {
                return false;
            };
            rows.push(serde_json::json!({ "address": address, "text": text }));
        }
        rows.sort_by_key(|row| {
            row["address"]
                .as_str()
                .and_then(|text| text.strip_prefix("0x"))
                .and_then(|text| u64::from_str_radix(text, 16).ok())
                .unwrap_or(0)
        });
    }
    expected == *after
}

fn post_commit_refresh_unavailable(receipt: Value, error: &str) -> Value {
    let value = serde_json::json!({
        "result": receipt,
        "post_commit_refresh": {
            "status": "unavailable", "handler_succeeded": true,
            "rollback_performed": false,
            "error": pdb_bounded_text(error, 256),
        },
    });
    fit_committed_result(value)
}

fn result_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn evidence_value(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).expect("JSON value serialization");
    if bytes.len() <= 1024 {
        value.clone()
    } else {
        serde_json::json!({
            "omitted": true, "json_bytes": bytes.len(), "sha256": result_digest(&bytes),
        })
    }
}

fn fit_committed_result(value: Value) -> Value {
    let bytes = serde_json::to_vec(&value).expect("JSON value serialization");
    if bytes.len() <= MAX_RESULT_CHARS {
        return value;
    }
    let original = value.get("result").unwrap_or(&value);
    let original_bytes = serde_json::to_vec(original).expect("JSON value serialization");
    let mut evidence = serde_json::Map::new();
    for field in [
        "address",
        "field",
        "changed",
        "value",
        "status",
        "apply_requested",
        "whole_apply_succeeded",
        "applied_total",
        "preserved_total",
        "imported_types_total",
        "receipt",
        "source_sha256",
        "effective_sha256",
        "revision_sha256",
        "active_ranges",
        "changed_bytes",
    ] {
        if let Some(value) = original.get(field) {
            evidence.insert(field.to_owned(), evidence_value(value));
        }
    }
    let entries = original.as_array().map(|items| {
        items
            .iter()
            .take(8)
            .map(|item| {
                let mut fields = serde_json::Map::new();
                for field in ["address", "field", "changed", "value"] {
                    if let Some(value) = item.get(field) {
                        fields.insert(field.to_owned(), evidence_value(value));
                    }
                }
                Value::Object(fields)
            })
            .collect::<Vec<_>>()
    });
    serde_json::json!({
        "handler_succeeded": true, "rollback_performed": false,
        "post_commit_refresh": value.get("post_commit_refresh").map(evidence_value).unwrap_or(Value::Null),
        "post_commit_refresh_status": if value["post_commit_refresh"]["status"] == "unavailable" {
            Value::String("unavailable".to_owned())
        } else { Value::Null },
        "result_representation": "commit_evidence_summary",
        "full_result_omitted": true,
        "full_result_json_bytes": original_bytes.len(),
        "full_result_sha256": result_digest(&original_bytes),
        "commit_evidence": evidence,
        "result_items": original.as_array().map(Vec::len),
        "entry_evidence": entries,
        "entry_evidence_omitted": original.as_array().map(|items| items.len().saturating_sub(8)),
    })
}

fn dispatch(
    tools: &[Tool],
    name: &str,
    input: Value,
    run: impl FnOnce(&Tool, Value) -> Result<Value, String>,
) -> (String, bool) {
    let Some(tool) = tools.iter().find(|tool| tool.name == name) else {
        return (format!("unknown tool {name}"), true);
    };
    let apply_requested = input
        .get("apply")
        .and_then(Value::as_bool)
        .or_else(|| (input.is_object() && input.get("apply").is_none()).then_some(false));
    if name == "import_debug_layouts"
        && let Err(error) = validate_debug_layout_arguments(&input)
    {
        return (debug_layout_import_error(&error, apply_requested), true);
    }
    match run(tool, input) {
        Ok(value) => {
            let value = if tool.effect == Effect::Annotations { fit_committed_result(value) } else { value };
            let mut text = value.to_string();
            if text.len() > MAX_RESULT_CHARS && tool.effect != Effect::Annotations && name != "import_debug_layouts" {
                let cut = (0..=MAX_RESULT_CHARS).rev().find(|&index| text.is_char_boundary(index)).unwrap_or(0);
                text.truncate(cut);
                text.push_str("... (truncated: ask for a narrower range, a smaller count, or a page)");
            }
            (text, false)
        }
        Err(error) if name == "import_pdb_names" => (pdb_import_error(&error, apply_requested), true),
        Err(error) if name == "import_debug_layouts" => (debug_layout_import_error(&error, apply_requested), true),
        Err(error) => (error, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleigh_input_budget_streams_escaped_bytes_and_stops_before_visiting_later_fields() {
        use serde::ser::SerializeSeq;
        use std::cell::Cell;

        struct CountedInput<'a> {
            escaped: &'a str,
            visits: &'a Cell<usize>,
        }
        impl Serialize for CountedInput<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(2))?;
                self.visits.set(self.visits.get() + 1);
                sequence.serialize_element(self.escaped)?;
                self.visits.set(self.visits.get() + 1);
                sequence.serialize_element("must not be visited after budget refusal")?;
                sequence.end()
            }
        }
        let escaped = "\"".repeat(MAX_SLEIGH_REQUEST_BYTES / 2 + 1);
        let visits = Cell::new(0);
        assert!(check_sleigh_input_budget(&CountedInput { escaped: &escaped, visits: &visits }).is_err());
        assert_eq!(visits.get(), 1);
        assert!(check_sleigh_input_budget(&serde_json::json!({"profile":"6502:LE:16:default"})).is_ok());
    }

    #[test]
    fn code_view_fits_large_details_without_truncating_code_or_hiding_recovery_evidence() {
        use rampage_decompiler::results::{
            FrameBaseConvention, FrameContext, RecoveryDiagnostics, RecoveryStatus, RecoveryWarning, Storage,
            StorageKind, StructuredResult, TypeInfo, Variable, VariableKind, WarningKind,
        };

        let mut structure = StructuredResult::empty();
        structure.variables = [
            ("stack_value", StorageKind::Spacebase, "stack", 4, 0xffff_fffc),
            ("register_value", StorageKind::Processor, "register", 8, 0x10),
        ]
        .into_iter()
        .map(|(name, kind, space, address_size_bytes, address)| Variable {
            name: name.to_owned(),
            data_type: TypeInfo { name: "int4".to_owned(), size: 4 },
            kind: VariableKind::Local,
            storage: vec![Storage {
                kind,
                space: Some(space.to_owned()),
                address_size_bytes: Some(address_size_bytes),
                address: Some(address),
                size: 4,
                use_ranges: Some(Vec::new()),
                dynamic_hash: None,
                symbol_offset: Some(0),
                is_piece: Some(false),
                join_logical_size: None,
                pieces: Vec::new(),
            }],
        })
        .collect();
        structure.diagnostics = Some(RecoveryDiagnostics {
            bad_data: true,
            unimplemented: false,
            unresolved_calls: 1,
            unresolved_indirect_jumps: 0,
            partial_jump_tables: 0,
            warnings: vec![RecoveryWarning {
                kind: WarningKind::Body,
                address: Some(0x1000),
                message: "uncertain boundary".to_owned(),
            }],
        });
        structure.frame_context = Some(FrameContext {
            stack_space: "stack".to_owned(),
            address_size_bytes: 4,
            base_convention: FrameBaseConvention::Unknown,
            base_register: None,
        });
        let variables = crate::variables::descriptors(&structure);
        let mut full = serde_json::to_value(crate::Decompilation {
            address: 0x1000,
            name: "partial_function".to_owned(),
            code: "int partial_function(void) { return 7; }".to_owned(),
            language_id: "AARCH64:LE:64:v8A:default".to_owned(),
            tokens: vec![crate::decompile::DecompiledToken {
                text: "x".repeat(MAX_RESULT_CHARS),
                kind: "comment".to_owned(),
                address: Some(0x1000),
                span: None,
            }],
            structure,
            recovery_status: RecoveryStatus::Incomplete,
            variables,
        })
        .unwrap();
        full["context"] = serde_json::json!({
            "scope":"exact_entry", "validation":"analyst_asserted", "full_image_mapping":true,
            "omissions":["bounded local context"],
        });
        let error = decompilation_view(full.clone(), DecompileView::Full).unwrap_err();
        assert!(error.to_string().contains("view=code"));
        let compact = decompilation_view(full.clone(), DecompileView::Code).unwrap();
        for field in ["address", "name", "code", "language_id", "context", "recovery_status", "variables"] {
            assert_eq!(compact[field], full[field], "code view changed {field}");
        }
        assert_eq!(compact["diagnostics"], full["structure"]["diagnostics"]);
        assert_eq!(compact["structure_metadata"]["frame_context"], full["structure"]["frame_context"]);
        assert_eq!(compact["structure_metadata"]["variables"], full["structure"]["variables"]);
        assert_eq!(compact["structure_metadata"]["variables"][0]["storage"][0]["address_size_bytes"], 4);
        assert_eq!(compact["structure_metadata"]["variables"][1]["storage"][0]["address_size_bytes"], 8);
        assert!(compact.to_string().len() <= MAX_RESULT_CHARS);
        for field in ["code", "structure", "context"] {
            let mut oversized = full.clone();
            match field {
                "code" => {
                    oversized["code"] =
                        serde_json::json!(format!("/*{}*/\nint f(void) {{ return 7; }}", "x".repeat(MAX_RESULT_CHARS)))
                }
                "structure" => {
                    oversized["structure"]["diagnostics"]["warnings"][0]["message"] =
                        Value::String("\"".repeat(MAX_RESULT_CHARS))
                }
                "context" => oversized["context"]["omissions"] = serde_json::json!(["\"".repeat(MAX_RESULT_CHARS)]),
                _ => unreachable!(),
            }
            let error = decompilation_view(oversized, DecompileView::Code).unwrap_err();
            assert!(error.to_string().contains("byte budget"), "{field}: {error}");
            assert!(!error.to_string().contains("native shape"), "{field}: {error}");
        }
    }

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
