use std::path::PathBuf;

use clap::Args;

pub(crate) const INSPECT_SLEIGH_ABOUT: &str = "Inspect explicit raw BYTE windows using the 20 closed bundled Sleigh IDs \
    (16 reviewed processor profiles plus four x86/A64 variants). Native metadata supplies code spaces/alignment: \
    never infer widths from CPU names or multiply AVR byte offsets by word size. This is not ordinary \
    native-image/Project admission, C ABI attestation, C decompilation or packet support. Hexagon helper \
    requirements, SuperH delay aggregation, and user-defined/context-mediated flow remain explicit unresolved \
    gates; valid gated entries are retained without successor/noreturn guesses. No target execution, annotations, \
    extraction or source writes. Native --arch and image selectors are unsupported; select the raw profile explicitly.";

#[derive(Args)]
pub(crate) struct InspectSleighArgs {
    pub(crate) file: PathBuf,
    /// Checked regular JSON request file (at most 1 MiB); no native executable header is required
    #[arg(long, required_unless_present = "request_json", conflicts_with = "request_json")]
    pub(crate) request: Option<PathBuf>,
    /// Literal JSON SleighWindowRequest: closed profile, source offset/length, BYTE base and optional seeds/work limits
    #[arg(long, required_unless_present = "request")]
    pub(crate) request_json: Option<String>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum OutputView {
    Summary,
    Code,
    Full,
}

impl From<OutputView> for rampage_api::ToolView {
    fn from(view: OutputView) -> Self {
        match view {
            OutputView::Summary => Self::Summary,
            OutputView::Code => Self::Code,
            OutputView::Full => Self::Full,
        }
    }
}

#[derive(Args)]
pub(crate) struct ViewedFileArgs {
    pub(crate) file: PathBuf,
    /// Select structured JSON: full (default), summary with explicit omissions, or code (not for metadata)
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
}

#[derive(Args)]
pub(crate) struct ViewedAtArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    /// Select full JSON, summary with exact omission receipts, or code with native control evidence
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
}

#[derive(Args)]
pub(crate) struct GraphArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    /// Select full JSON, summary with exact omission receipts, or code with native control evidence
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
    /// summary/code views: first block of a page (the previous page's blocks_next_offset)
    #[arg(long, default_value_t = 0)]
    pub(crate) block_offset: usize,
}

#[derive(Args)]
pub(crate) struct AnnotationBatchArgs {
    pub(crate) file: PathBuf,
    /// Bounded regular JSON request file: {"entries":[{"operation":"rename","at":"name","value":"new"}]}
    #[arg(long, required_unless_present = "entries_json", conflicts_with = "entries_json")]
    pub(crate) entries: Option<PathBuf>,
    /// Inline JSON request; value is required on every operation and null explicitly clears it
    #[arg(long, required_unless_present = "entries")]
    pub(crate) entries_json: Option<String>,
}

#[derive(Args)]
pub(crate) struct PatchReviewArgs {
    /// Original source SHA-256 from list-patches.receipt
    #[arg(long)]
    pub(crate) source_sha256: String,
    /// Reviewed revision SHA-256 from list-patches.receipt
    #[arg(long)]
    pub(crate) expected_revision: String,
}

#[derive(Args)]
pub(crate) struct PatchBytesArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    /// Original source bytes, not the current patched bytes; contiguous lowercase hex
    #[arg(long)]
    pub(crate) original_hex: String,
    #[arg(long)]
    pub(crate) replacement_hex: String,
    /// Explicit true/false consent to include eligible data payload
    #[arg(long, required = true, action = clap::ArgAction::Set)]
    pub(crate) allow_data: bool,
    #[command(flatten)]
    pub(crate) review: PatchReviewArgs,
}

#[derive(Args)]
pub(crate) struct RevertPatchArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    #[command(flatten)]
    pub(crate) review: PatchReviewArgs,
}

#[derive(Args)]
pub(crate) struct ListPatchesArgs {
    pub(crate) file: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=100))]
    pub(crate) limit: u64,
}

#[derive(Args)]
pub(crate) struct ExportPatchedArgs {
    pub(crate) file: PathBuf,
    /// New destination only; existing paths and the original source cannot be overwritten
    #[arg(long)]
    pub(crate) destination: PathBuf,
    #[command(flatten)]
    pub(crate) review: PatchReviewArgs,
}

#[derive(Args)]
pub(crate) struct AssembleArgs {
    pub(crate) file: PathBuf,
    /// Numeric address string or resolvable name for the proposal's base address
    #[arg(long)]
    pub(crate) at: String,
    /// Literal assembly, one instruction per line; never a source filename or shell command
    #[arg(long)]
    pub(crate) source: String,
}

#[derive(Args)]
pub(crate) struct SearchArgs {
    pub(crate) file: PathBuf,
    /// Bounded regular JSON SearchRequest file; see `search` MCP schema for the six typed mode selectors
    #[arg(long, required_unless_present = "query_json", conflicts_with = "query_json")]
    pub(crate) query: Option<PathBuf>,
    /// Inline JSON SearchRequest (explicitly JSON, never inferred as a filename); output is structured JSON
    #[arg(long, required_unless_present = "query")]
    pub(crate) query_json: Option<String>,
}

#[derive(Args)]
pub(crate) struct FileArgs {
    pub(crate) file: PathBuf,
}

#[derive(Args)]
pub(crate) struct ArchiveInventoryArgs {
    pub(crate) file: PathBuf,
    /// Matching central-directory records to skip (not a file or image byte offset)
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Records per page (1..=100), additionally bounded to 60000 JSON bytes
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=100))]
    pub(crate) limit: u64,
    /// Case-sensitive UTF-8 byte substring of the full raw member name, before display truncation
    #[arg(long)]
    pub(crate) contains: Option<String>,
}

#[derive(Args)]
pub(crate) struct PyInstallerArchiveArgs {
    pub(crate) file: PathBuf,
    /// TOC entries to skip, for paging
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// TOC entries per page (1..=100), additionally bounded to 60000 JSON bytes
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=100))]
    pub(crate) limit: u64,
}

#[derive(Args)]
pub(crate) struct WasmModuleArgs {
    pub(crate) file: PathBuf,
    /// Also page one list: imports, exports or functions
    #[arg(long, value_parser = parse_wasm_list)]
    pub(crate) list: Option<rampage_api::WasmList>,
    /// List items to skip, for paging
    #[arg(long, default_value_t = 0, requires = "list")]
    pub(crate) offset: usize,
    /// List items per page (1..=100), additionally bounded to 60000 JSON bytes
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=100))]
    pub(crate) limit: u64,
}

fn parse_wasm_list(text: &str) -> Result<rampage_api::WasmList, String> {
    text.parse()
}

#[derive(Args)]
pub(crate) struct QueryDebuggerArgs {
    /// Explicit absolute path to an operator-started LLDB Unix socket (no attach or discovery)
    #[arg(long)]
    pub(crate) socket: PathBuf,
    /// One bounded version 1 JSON read-only request; subsequent queries require expected_token
    #[arg(long)]
    pub(crate) request: String,
    /// End-to-end timeout in milliseconds
    #[arg(long, default_value_t = 3000, value_parser = clap::value_parser!(u64).range(1..=30000))]
    pub(crate) timeout_ms: u64,
}

#[derive(Args)]
pub(crate) struct DirectoryArgs {
    pub(crate) directory: PathBuf,
}

#[derive(Args)]
pub(crate) struct DisasmArgs {
    pub(crate) file: PathBuf,
    /// Start address (hex 0x..., decimal) or symbol name; defaults to the entry point
    #[arg(long)]
    pub(crate) at: Option<String>,
    /// Number of instructions
    #[arg(long, default_value_t = rampage_api::DEFAULT_INSTRUCTIONS)]
    pub(crate) count: usize,
    /// Structured JSON view; summary omits rendering with counts, code/full retain the complete listing
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
}

#[derive(Args)]
pub(crate) struct StringsArgs {
    pub(crate) file: PathBuf,
    /// Minimum length in characters
    #[arg(long, default_value_t = 4)]
    pub(crate) min_len: usize,
    /// Only strings containing this text (case-insensitive)
    #[arg(long)]
    pub(crate) contains: Option<String>,
}

#[derive(Args)]
pub(crate) struct FuncsArgs {
    pub(crate) file: PathBuf,
    /// Only list functions named by symbols, exports and the entry point, without analysis
    #[arg(long)]
    pub(crate) symbols_only: bool,
    /// Only functions whose name contains this text (case-insensitive)
    #[arg(long)]
    pub(crate) name: Option<String>,
}

#[derive(Args)]
pub(crate) struct DetectArgs {
    pub(crate) file: PathBuf,
    /// A user-supplied PeID userdb.txt, overlaid on the bundled database (with any packs' PeID signatures)
    #[arg(long)]
    pub(crate) peid: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct YaraArgs {
    pub(crate) file: PathBuf,
    /// Optional when a data pack holds YARA rules
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct CapaArgs {
    pub(crate) file: PathBuf,
    /// Optional when a data pack holds capa rules
    #[arg(long)]
    pub(crate) rules: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct AuditArgs {
    pub(crate) file: PathBuf,
    /// Run whole-program discovery and correlate candidates with bounded samples
    #[arg(long)]
    pub(crate) include_discovery: bool,
    /// Sample bounded metadata-declared entries without whole-program discovery
    #[arg(long, conflicts_with = "include_discovery")]
    pub(crate) entries: bool,
    /// Sample one exact address/name; requires --entries and does not verify a function boundary
    #[arg(long, requires = "entries")]
    pub(crate) at: Option<String>,
}

#[derive(Args)]
pub(crate) struct CarveArgs {
    pub(crate) file: PathBuf,
    /// Stop after this many candidates (1 to 4096)
    #[arg(
        long,
        default_value_t = rampage_loaders::carve::MAX_CANDIDATES,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new()
            .range(1..=rampage_loaders::carve::MAX_CANDIDATES as u64)
    )]
    pub(crate) max_candidates: usize,
}

#[derive(Args)]
pub(crate) struct AtArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
}

#[derive(Args)]
pub(crate) struct PseudocodeArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    #[arg(long)]
    pub(crate) structured: bool,
}

#[derive(Args)]
pub(crate) struct CompareArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) reference: PathBuf,
}

#[derive(Args)]
pub(crate) struct SignaturesArgs {
    pub(crate) file: PathBuf,
    /// Write the database here (JSON); defaults to standard output
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    /// Build a separate fuzzy database using a JSON FuzzyBuildRequest (explicit source names/provenance)
    #[arg(long)]
    pub(crate) fuzzy_request: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct IdentifyArgs {
    pub(crate) file: PathBuf,
    /// A signature database to apply first, before data packs' databases and the bundled starter one
    #[arg(long)]
    pub(crate) db: Option<PathBuf>,
    /// Separate fuzzy JSON database: suggestions only, never counted or applied as exact matches
    #[arg(long, requires = "fuzzy_request", conflicts_with = "no_bundled")]
    pub(crate) fuzzy_db: Option<PathBuf>,
    /// JSON FuzzySuggestRequest: cohort, numeric addresses (1..64), candidates_per_function (1..16)
    #[arg(long, requires = "fuzzy_db")]
    pub(crate) fuzzy_request: Option<PathBuf>,
    /// Do not apply the bundled starter database (needs --db or a data pack with a database for the architecture)
    #[arg(long)]
    pub(crate) no_bundled: bool,
    /// Save matched names for still-unnamed functions as user names
    #[arg(long)]
    pub(crate) apply: bool,
}

#[derive(Args)]
pub(crate) struct JumpTableArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    #[arg(long)]
    pub(crate) count: usize,
    #[arg(long)]
    pub(crate) relative_base: Option<String>,
}

#[derive(Args)]
pub(crate) struct CorrelateArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) original: PathBuf,
    #[arg(long)]
    pub(crate) module: String,
    #[arg(long)]
    pub(crate) at: String,
}

#[derive(Args)]
pub(crate) struct CompareRuntimeArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) original: PathBuf,
    /// Open the original Mach-O embedded at this file offset (hex 0x... or decimal), not the capture
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "original")]
    pub(crate) original_image_offset: Option<u64>,
    /// With --original-image-offset, the image's length in bytes; defaults to the extent its headers give
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "original_image_offset")]
    pub(crate) original_image_length: Option<u64>,
    #[arg(long)]
    pub(crate) module: String,
    #[arg(long, required = true)]
    pub(crate) range: Vec<String>,
}

#[derive(Args)]
pub(crate) struct ObserveIndirectBranchArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) start: String,
    #[arg(long)]
    pub(crate) at: String,
}

#[derive(Args)]
pub(crate) struct ImportsArgs {
    pub(crate) file: PathBuf,
    /// Only imports whose name or library contains this text (case-insensitive)
    #[arg(long)]
    pub(crate) contains: Option<String>,
}

#[derive(Args)]
pub(crate) struct ExportsArgs {
    pub(crate) file: PathBuf,
    /// Only exports whose name contains this text (case-insensitive)
    #[arg(long)]
    pub(crate) contains: Option<String>,
}

#[derive(Args)]
pub(crate) struct RenameArgs {
    pub(crate) file: PathBuf,
    /// Address or current name
    pub(crate) at: String,
    /// The new name
    #[arg(required_unless_present = "clear", conflicts_with = "clear")]
    pub(crate) name: Option<String>,
    /// Remove the user's name instead
    #[arg(long)]
    pub(crate) clear: bool,
}

#[derive(Args)]
pub(crate) struct CommentArgs {
    pub(crate) file: PathBuf,
    /// Address or name
    pub(crate) at: String,
    /// The comment
    #[arg(required_unless_present = "clear", conflicts_with = "clear")]
    pub(crate) text: Option<String>,
    /// Remove the comment instead
    #[arg(long)]
    pub(crate) clear: bool,
}

/// A lowercase JSON enum name, such as `unknown` for a ledger entry kind.
fn ledger_value<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).map_err(|error| error.to_string())
}

fn ledger_evidence(text: &str) -> Result<rampage_api::LedgerEvidence, String> {
    let (tool, detail) = text.split_once('=').ok_or("evidence must be TOOL=DETAIL")?;
    Ok(rampage_api::LedgerEvidence { tool: tool.to_owned(), detail: detail.to_owned() })
}

#[derive(Args)]
pub(crate) struct RecordFindingArgs {
    pub(crate) file: PathBuf,
    /// Update this entry instead of creating one; only the options given change
    #[arg(long)]
    pub(crate) id: Option<u64>,
    /// finding, unknown or question (required when creating)
    #[arg(long, value_parser = ledger_value::<rampage_api::LedgerKind>)]
    pub(crate) kind: Option<rampage_api::LedgerKind>,
    /// What was established or is unknown (required when creating)
    #[arg(long)]
    pub(crate) text: Option<String>,
    /// Address or name it concerns
    #[arg(long)]
    pub(crate) address: Option<String>,
    /// Address or name inside the function it concerns
    #[arg(long)]
    pub(crate) function: Option<String>,
    /// Supporting tool call as TOOL=DETAIL; repeat for several (replaces the list on update)
    #[arg(long, value_parser = ledger_evidence)]
    pub(crate) evidence: Vec<rampage_api::LedgerEvidence>,
    /// low, medium or high
    #[arg(long, value_parser = ledger_value::<rampage_api::LedgerConfidence>)]
    pub(crate) confidence: Option<rampage_api::LedgerConfidence>,
    /// open, resolved or rejected
    #[arg(long, value_parser = ledger_value::<rampage_api::LedgerStatus>)]
    pub(crate) status: Option<rampage_api::LedgerStatus>,
    /// How it was settled; an empty string clears it
    #[arg(long)]
    pub(crate) resolution: Option<String>,
}

#[derive(Args)]
pub(crate) struct TransferAnnotationsArgs {
    /// The new build that receives the annotations
    pub(crate) file: PathBuf,
    /// The analyzed build whose saved annotations are carried over (same architecture; its log is only read)
    #[arg(long, required = true)]
    pub(crate) from: PathBuf,
    /// Write the transfers as an undoable batch with a provenance ledger entry; omitted only previews
    #[arg(long)]
    pub(crate) apply: bool,
    /// Lowest match confidence whose annotations transfer, 0 to 1 (default 0.7)
    #[arg(long)]
    pub(crate) min_confidence: Option<f64>,
    /// Rows to page: transfers, matches, changed, added, removed or ambiguous
    #[arg(long, value_parser = ledger_value::<rampage_api::TransferList>)]
    pub(crate) list: Option<rampage_api::TransferList>,
    /// Rows to skip
    #[arg(long)]
    pub(crate) offset: Option<usize>,
    /// Rows per page (1..=1000, default 100)
    #[arg(long)]
    pub(crate) limit: Option<usize>,
}

#[derive(Args)]
pub(crate) struct ListFindingsArgs {
    pub(crate) file: PathBuf,
    /// finding, unknown or question
    #[arg(long, value_parser = ledger_value::<rampage_api::LedgerKind>)]
    pub(crate) kind: Option<rampage_api::LedgerKind>,
    /// open, resolved or rejected
    #[arg(long, value_parser = ledger_value::<rampage_api::LedgerStatus>)]
    pub(crate) status: Option<rampage_api::LedgerStatus>,
    /// Only entries at this address or name
    #[arg(long)]
    pub(crate) address: Option<String>,
    /// Only entries in the function containing this address or name
    #[arg(long)]
    pub(crate) function: Option<String>,
    /// Case-insensitive substring of the text or resolution
    #[arg(long)]
    pub(crate) contains: Option<String>,
    /// Matching entries to skip
    #[arg(long)]
    pub(crate) offset: Option<usize>,
    /// Entries per page (1..=100, default 50)
    #[arg(long)]
    pub(crate) limit: Option<usize>,
}

#[derive(Args)]
pub(crate) struct AnnotateBatchArgs {
    pub(crate) file: PathBuf,
    /// The JSON file of entries (at most 1000)
    pub(crate) entries: PathBuf,
}

#[derive(Args)]
pub(crate) struct CheckNamesArgs {
    pub(crate) file: PathBuf,
    #[arg(required = true)]
    pub(crate) names: Vec<String>,
}

#[derive(Args)]
pub(crate) struct DebugTypesArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) apply: bool,
}

#[derive(Args)]
pub(crate) struct ImportDebugLayoutsArgs {
    #[arg(value_name = "IMAGE")]
    pub(crate) file: PathBuf,
    /// Apply the complete reviewed dependency batch atomically; undo is same-process only, not after CLI exit
    #[arg(long, requires = "review_sha256")]
    pub(crate) apply: bool,
    /// Exact lowercase SHA-256 from a fresh preview; binds the complete review, not only this evidence page
    #[arg(long, requires = "apply", value_parser = rampage_api::tools::parse_debug_layout_review_sha256)]
    pub(crate) review_sha256: Option<String>,
    /// Evidence rows to skip; never selects which layouts or signatures are applied
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Evidence rows per page (1 to 1000); the 60000-byte receipt budget may shorten the page
    #[arg(
        long,
        default_value_t = 100,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1000)
    )]
    pub(crate) limit: usize,
}

#[derive(Args)]
pub(crate) struct TypeLayoutArgs {
    #[arg(value_name = "IMAGE")]
    pub(crate) file: PathBuf,
    /// Type name, optionally `struct NAME`; a typedef resolves to what it names
    pub(crate) name: String,
    /// Dotted member path such as `init.busy` or `aDb[1].pBt`; prints its offset, size and type
    #[arg(long, conflicts_with = "byte_offset")]
    pub(crate) member: Option<String>,
    /// Byte offset into the type (hex 0x... or decimal); prints the innermost member covering it
    #[arg(long)]
    pub(crate) byte_offset: Option<String>,
    /// Levels of by-value struct/union members to expand inline (0 to 4)
    #[arg(long, default_value_t = 0, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=4))]
    pub(crate) depth: usize,
    /// Members to skip
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Members per page (0 to 512); defaults to 128, or 0 with --member/--byte-offset
    #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(0..=512))]
    pub(crate) limit: Option<usize>,
}

#[derive(Args)]
pub(crate) struct ImportPdbNamesArgs {
    pub(crate) file: PathBuf,
    /// Explicit PDB file; no recorded path, sidecar discovery, symbol server or download is used
    #[arg(long, required = true)]
    pub(crate) pdb: PathBuf,
    /// Persist all eligible names as one atomic annotation batch; omitted only previews
    #[arg(long)]
    pub(crate) apply: bool,
    /// Details to skip (functions, then warnings); does not select which names are applied
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Details per page (1 to 1000); the byte budget may shorten the page further
    #[arg(
        long,
        default_value_t = 100,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1000)
    )]
    pub(crate) limit: usize,
}

#[derive(Args)]
pub(crate) struct McpArgs {
    /// List every tool group from the start, for clients that do not refresh their tool list
    #[arg(long)]
    pub(crate) all_tools: bool,
    /// Allow the debug tools to connect to an operator-started GDB remote stub at HOST:PORT or unix:/PATH, inspect
    /// it and control its execution (continue, step, interrupt, breakpoints; writes and kill only with the flags
    /// below). Repeatable; RAMPAGE_DEBUG_ENDPOINTS adds a comma-separated list. Without one there is no debug group
    #[arg(long = "debug-endpoint", value_name = "ENDPOINT")]
    pub(crate) debug_endpoints: Vec<String>,
    /// Also serve debug_write_memory and debug_write_register, which write a stopped target's memory and registers
    /// when called (never on their own). Needs a debug endpoint; RAMPAGE_DEBUG_WRITES=1 does the same
    #[arg(long)]
    pub(crate) debug_writes: bool,
    /// Also let debug_disconnect kill the target (kill: true) instead of detaching. Needs a debug endpoint;
    /// RAMPAGE_DEBUG_KILL=1 does the same
    #[arg(long)]
    pub(crate) debug_kill: bool,
    /// Decompile only in the supervised rampage-worker process: without one, decompile refuses instead of running
    /// in-process, inside this server
    #[arg(long)]
    pub(crate) require_worker: bool,
    #[command(flatten)]
    pub(crate) flywheel: FlywheelArgs,
}

/// The flywheel's opt-in tools (docs/flywheel.md).
#[derive(Args)]
pub(crate) struct FlywheelArgs {
    /// Serve only the improve group, over this built flywheel corpus (target/flywheel/corpus/<version>):
    /// training failures, candidate signature rows, the fast and held-out gates, and promotion. No analysis tool
    /// is served and no other group can be enabled, so a proposer cannot read the corpus's binaries
    #[arg(long, value_name = "DIR")]
    pub(crate) corpus: Option<PathBuf>,
    /// The flywheel working directory (default: two levels above a corpus in a corpus/ directory)
    #[arg(long, value_name = "DIR", requires = "corpus")]
    pub(crate) flywheel_dir: Option<PathBuf>,
    /// A TOML file overriding gate settings (min_f1_gain, max_slice_f1_drop, max_fp_increase, tp_per_fp,
    /// max_train_fp_increase, max_negative_matches, min_pattern_bytes, max_heldout_evaluations,
    /// require_novel_gain, min_novel_f1_gain)
    #[arg(long, value_name = "FILE", requires = "corpus")]
    pub(crate) gate: Option<PathBuf>,
    /// What candidates are gated against besides promoted rows: `arm` (the bundled databases plus the
    /// deterministic arm generated from the training truth; the default) or `bundled` (the bundled databases
    /// alone, for diagnostics)
    #[arg(long, value_name = "BASELINE", default_value = "arm", requires = "corpus")]
    pub(crate) flywheel_baseline: String,
    /// Require (true) or waive (false) a held-out F1 gain on novel bodies, overriding the gate file; by default
    /// it is required against the arm baseline only
    #[arg(long, value_name = "BOOL", requires = "corpus")]
    pub(crate) require_novel_gain: Option<bool>,
    /// Threads for corpus analysis and evaluation
    #[arg(long, default_value_t = 2, requires = "corpus")]
    pub(crate) flywheel_workers: usize,
    /// The proposer run this server serves; its tool events go to <flywheel-dir>/runs/<RUN>/events.jsonl
    #[arg(long, value_name = "RUN", requires = "corpus")]
    pub(crate) flywheel_run: Option<String>,
    /// Serve report_observation, recording evidence-backed observations into DIR (opt-in;
    /// RAMPAGE_OBSERVATIONS does the same). A DIR inside a flywheel directory refuses that directory's files
    #[arg(long, value_name = "DIR", conflicts_with = "corpus")]
    pub(crate) observations: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct InspectDataArgs {
    pub(crate) file: PathBuf,
    /// Image address or existing metadata name, not a runtime address or file offset
    #[arg(long)]
    pub(crate) at: String,
    /// Bytes to inspect (1..=1024); reduce on output-budget errors
    #[arg(long, default_value_t = 128, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1024))]
    pub(crate) size: usize,
    /// Word width in bytes (4 or 8); otherwise the architecture's pointer width
    #[arg(long)]
    pub(crate) word_size: Option<u8>,
    /// Structured JSON metadata view: summary or full; code is explicitly unsupported
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
}

#[derive(Args)]
pub(crate) struct InspectRawArgs {
    pub(crate) file: PathBuf,
    /// Explicit JSON mapping/range request, same fields as MCP inspect_raw_code except path; no defaults for mode/order/base
    #[arg(long)]
    pub(crate) request: String,
}

#[derive(Args)]
pub(crate) struct LayoutArgs {
    pub(crate) file: PathBuf,
    /// Original-file byte offset where the selection starts, in hex or decimal; default 0
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) offset: Option<u64>,
    /// Selected bytes, at most 64 MiB; default the rest of the file, at most 64 MiB
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) length: Option<u64>,
    /// Shortest run of one repeated byte reported as fill (8..=16777216, default 64)
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) min_fill_run: Option<u64>,
    /// Entropy block size in bytes (512..=16777216, default 4096)
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) block_size: Option<u64>,
    /// Shortest printable run counted as a string (4..=64, default 6)
    #[arg(long)]
    pub(crate) min_string_length: Option<usize>,
    /// Largest byte gap between strings of one cluster (1..=4096, default 64)
    #[arg(long)]
    pub(crate) cluster_gap: Option<u64>,
    /// Fewest strings a cluster needs (1..=64, default 3)
    #[arg(long)]
    pub(crate) cluster_min_strings: Option<usize>,
    /// Also cluster UTF-16LE strings
    #[arg(long)]
    pub(crate) utf16: bool,
    /// Leave out heuristic hints such as Cortex-M vector-table candidates
    #[arg(long)]
    pub(crate) no_hints: bool,
    /// Regions listed (1..=256, default 128)
    #[arg(long)]
    pub(crate) region_limit: Option<usize>,
    /// Per-block entropy values listed (1..=4096, default 1024)
    #[arg(long)]
    pub(crate) block_limit: Option<usize>,
    /// String clusters listed (1..=128, default 16)
    #[arg(long)]
    pub(crate) cluster_limit: Option<usize>,
}

impl LayoutArgs {
    pub(crate) fn request(&self) -> rampage_api::FileLayoutRequest {
        rampage_api::FileLayoutRequest {
            offset: self.offset.map(rampage_api::FileOffset),
            length: self.length.map(rampage_api::FileOffset),
            min_fill_run: self.min_fill_run,
            block_size: self.block_size,
            min_string_length: self.min_string_length,
            cluster_gap: self.cluster_gap,
            cluster_min_strings: self.cluster_min_strings,
            utf16: Some(self.utf16),
            hints: Some(!self.no_hints),
            region_limit: self.region_limit,
            block_limit: self.block_limit,
            cluster_limit: self.cluster_limit,
        }
    }
}

#[derive(Args)]
pub(crate) struct ProbeCompressionArgs {
    pub(crate) file: PathBuf,
    /// Original-file offset where the encoded stream is thought to start, in hex or decimal
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) offset: u64,
    /// Encoded bytes, at most 8 MiB
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) length: u64,
    /// The decoded size when known, at most 16 MiB; without it no candidate is confident
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) expected_output_size: Option<u64>,
    /// Candidates listed (1..=16, default 5)
    #[arg(long)]
    pub(crate) candidate_limit: Option<usize>,
    /// Cooperative sweep deadline (1..=30000 ms, default 15000)
    #[arg(long)]
    pub(crate) timeout_ms: Option<u64>,
    /// Decoded preview bytes per candidate (0..=128, default 48)
    #[arg(long)]
    pub(crate) preview_size: Option<usize>,
}

impl ProbeCompressionArgs {
    pub(crate) fn request(&self) -> rampage_api::ProbeCompressionRequest {
        rampage_api::ProbeCompressionRequest {
            offset: rampage_api::FileOffset(self.offset),
            length: rampage_api::FileOffset(self.length),
            expected_output_size: self.expected_output_size.map(rampage_api::FileOffset),
            candidate_limit: self.candidate_limit,
            timeout_ms: self.timeout_ms,
            preview_size: self.preview_size,
        }
    }
}

#[derive(Args)]
pub(crate) struct DecodeFileArgs {
    pub(crate) file: PathBuf,
    /// Explicit decoder selection: lzss-4k, lzss (with --lzss) or lz4-block (no format guessing)
    #[arg(long)]
    pub(crate) codec: rampage_api::ContentCodec,
    /// Codec lzss only: every variant parameter as JSON, as probe-compression prints it, e.g.
    /// {"window_bits":12,"min_match":3,"flag_order":"lsb_first","literal_bit":1,"reference_layout":"split_byte",
    /// "offset_mode":"ring_position"}
    #[arg(long)]
    pub(crate) lzss: Option<String>,
    /// Original-file byte offset, in hex or decimal
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) offset: u64,
    /// Encoded range length, at most 8 MiB
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) length: u64,
    /// Analyst-supplied decoded stopping size, at most 16 MiB (not a discovered stream boundary)
    #[arg(long, value_parser = rampage_api::parse_file_offset)]
    pub(crate) expected_output_size: u64,
    /// Initial ring write position; default 4078 (0xfee) for lzss-4k, zero otherwise
    #[arg(long)]
    pub(crate) initial_write_offset: Option<u16>,
    /// Dictionary initialization byte
    #[arg(long, default_value_t = 0)]
    pub(crate) dictionary_fill: u8,
    /// Cooperative decode-phase timeout; file I/O and hashes are not forcibly timed out
    #[arg(long, default_value_t = 3000)]
    pub(crate) timeout_ms: u64,
    /// Byte offset in decoded content, not in the original file
    #[arg(long, default_value = "0", value_parser = rampage_api::parse_file_offset)]
    pub(crate) preview_offset: u64,
    /// Preview bytes, at most 1024; zero returns hashes and metadata only
    #[arg(long, default_value_t = 256)]
    pub(crate) preview_size: usize,
}

impl DecodeFileArgs {
    pub(crate) fn request(&self) -> anyhow::Result<rampage_api::DecodeFileRequest> {
        let lzss = match &self.lzss {
            Some(json) => Some(
                serde_json::from_str::<rampage_api::LzssParameters>(json)
                    .map_err(|error| anyhow::anyhow!("--lzss is not valid lzss parameters: {error}"))
                    .and_then(|parameters| match parameters.literal_bit {
                        0 | 1 => Ok(parameters),
                        _ => Err(anyhow::anyhow!("--lzss literal_bit must be 0 or 1")),
                    })?,
            ),
            None => None,
        };
        Ok(rampage_api::DecodeFileRequest {
            codec: self.codec,
            lzss,
            offset: self.offset,
            length: usize::try_from(self.length).map_err(|_| anyhow::anyhow!("decode length exceeds host width"))?,
            expected_output_size: usize::try_from(self.expected_output_size)
                .map_err(|_| anyhow::anyhow!("decoded length exceeds host width"))?,
            initial_write_offset: self
                .initial_write_offset
                .unwrap_or_else(|| rampage_api::default_initial_write_offset(self.codec)),
            dictionary_fill: self.dictionary_fill,
            timeout_ms: self.timeout_ms,
            preview_offset: usize::try_from(self.preview_offset)
                .map_err(|_| anyhow::anyhow!("preview offset exceeds host width"))?,
            preview_size: self.preview_size,
        })
    }
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("direction").required(true)))]
pub(crate) struct XrefsArgs {
    pub(crate) file: PathBuf,
    /// List references to this address or name
    #[arg(long, group = "direction")]
    pub(crate) to: Option<String>,
    /// List references made by this function, or by the instruction at this address
    #[arg(long, group = "direction")]
    pub(crate) from: Option<String>,
}

#[derive(Args)]
pub(crate) struct DecompileArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    /// Override the format-selected Ghidra compiler ID (gcc, windows, apcs, macosx, ...)
    #[arg(long)]
    pub(crate) compiler: Option<String>,
    /// Isolate native decompilation in a supervised sibling rampage-worker process
    #[arg(long)]
    pub(crate) isolated: bool,
    /// Treat --at as an exact entry with bounded local context, not a containing-function query
    #[arg(long)]
    pub(crate) exact_entry: bool,
    /// Decompile even inside code judged encrypted or packed, which is refused by default
    #[arg(long)]
    pub(crate) explore_encrypted: bool,
    /// Structured JSON: full (default), code with native evidence, or summary with explicit omissions
    #[arg(long, value_enum)]
    pub(crate) view: Option<OutputView>,
}

#[derive(Args)]
pub(crate) struct ComparePointersArgs {
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) other: PathBuf,
    #[arg(long)]
    pub(crate) at: String,
    #[arg(long)]
    pub(crate) other_at: String,
}

#[derive(Args)]
pub(crate) struct ReportArgs {
    pub(crate) workflow: crate::report::Workflow,
    pub(crate) file: PathBuf,
    /// The second binary, for diff-builds
    #[arg(long)]
    pub(crate) other: Option<PathBuf>,
    /// diff-builds: open the executable embedded in --other at this file offset (hex 0x... or decimal), as
    /// --image-offset does for <FILE>
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "other")]
    pub(crate) other_image_offset: Option<u64>,
    /// With --other-image-offset, the embedded image's length in bytes; defaults to the extent its headers give
    #[arg(long, value_parser = rampage_api::parse_file_offset, requires = "other_image_offset")]
    pub(crate) other_image_length: Option<u64>,
    /// Findings kept per section (default 25, at most 200)
    #[arg(long)]
    pub(crate) limit: Option<usize>,
    /// find-main: skip the decompilation preview
    #[arg(long)]
    pub(crate) no_decompile: bool,
    /// Experimental triage-report component; findings remain plugin claims, with no builtin fallback
    #[arg(long)]
    pub(crate) component: Option<PathBuf>,
    /// Trusted component worker executable (otherwise the sibling rampage-plugin-worker)
    #[arg(long, requires = "component")]
    pub(crate) component_worker: Option<PathBuf>,
    /// Explicitly complete host discovery before preparing plugin facts; outside the component runtime limits
    #[arg(long, requires = "component")]
    pub(crate) prepare_analysis: bool,
}

#[derive(Args)]
pub(crate) struct BuildInfoArgs {
    pub(crate) file: PathBuf,
    /// Go dependency modules and Rust packages to skip, for paging (each list independently)
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Entries per page of each list
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) limit: u64,
}

#[derive(Args)]
pub(crate) struct DotnetArgs {
    pub(crate) file: PathBuf,
    /// The list to page: types, pinvokes, attributes or resources (metadata links only, never payloads)
    #[arg(long, default_value = "types", value_parser = parse_dotnet_list, conflicts_with = "il")]
    pub(crate) list: rampage_api::DotNetList,
    /// Only types whose full name or method/property name, P/Invoke imports whose method, DLL or import name, or
    /// attributes whose type or target, or resources whose name or File/AssemblyRef name contains this text
    /// (case-insensitive)
    #[arg(long)]
    pub(crate) contains: Option<String>,
    /// With --list attributes, only those applied to this metadata token (hex with 0x, or decimal)
    #[arg(long, value_parser = parse_token)]
    pub(crate) parent_token: Option<u32>,
    /// List one method's CIL instead: a MethodDef token (0x0600000d) or Namespace.Type::Name; --offset and
    /// --limit then page its instructions
    #[arg(long, conflicts_with_all = ["contains", "parent_token"])]
    pub(crate) il: Option<String>,
    /// Entries of the list (or instructions with --il) to skip, for paging
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// With --il, start at the instruction containing this IL offset (IL_0042, 0x42 or decimal) instead
    #[arg(long, requires = "il", conflicts_with = "offset", value_parser = rampage_api::parse_il_offset)]
    pub(crate) at: Option<u32>,
    /// Entries per page
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) limit: u64,
}

#[derive(Args)]
pub(crate) struct PeResourcesArgs {
    pub(crate) file: PathBuf,
    /// Only leaves of this type: RT_VERSION, VERSION, 16 or a string type name (case-insensitive)
    #[arg(long = "type")]
    pub(crate) type_filter: Option<String>,
    /// Matching leaves to skip, for paging
    #[arg(long, default_value_t = 0)]
    pub(crate) offset: usize,
    /// Leaves per page
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) limit: u64,
}

fn parse_dotnet_list(text: &str) -> Result<rampage_api::DotNetList, String> {
    text.parse()
}

fn parse_token(text: &str) -> Result<u32, String> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|error| format!("not a metadata token: {error}"))
}
