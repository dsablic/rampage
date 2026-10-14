use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub(crate) struct FileArgs {
    pub(crate) file: PathBuf,
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
}

#[derive(Args)]
pub(crate) struct IdentifyArgs {
    pub(crate) file: PathBuf,
    /// A signature database to apply first, before data packs' databases and the bundled starter one
    #[arg(long)]
    pub(crate) db: Option<PathBuf>,
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
pub(crate) struct McpArgs {
    /// List every tool group from the start, for clients that do not refresh their tool list
    #[arg(long)]
    pub(crate) all_tools: bool,
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
}

#[derive(Args)]
pub(crate) struct DotnetArgs {
    pub(crate) file: PathBuf,
    /// The list to page: types, pinvokes or attributes
    #[arg(long, default_value = "types", value_parser = parse_dotnet_list, conflicts_with = "il")]
    pub(crate) list: rampage_api::DotNetList,
    /// Only types whose full name or method/property name, P/Invoke imports whose method, DLL or import name, or
    /// attributes whose type or target contains this text (case-insensitive)
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
