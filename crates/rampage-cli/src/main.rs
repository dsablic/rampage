mod commands;
mod report;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rampage_api::{FunctionsQuery, ListQuery, Packs, StringsQuery};
use rampage_arch::Arch;

use crate::commands::Options;

#[derive(Parser)]
#[command(name = "rampage", version, about = "High-performance reverse engineering toolkit")]
struct Cli {
    /// Emit JSON instead of text
    #[arg(long, global = true)]
    json: bool,
    /// Architecture slice to load from a universal binary (x86, x86_64, aarch64, arm, mips, powerpc, riscv64, ...)
    #[arg(long, global = true, value_parser = parse_arch)]
    arch: Option<Arch>,
    /// Open the executable embedded at this file offset (hex 0x... or decimal), such as one `carve` found
    #[arg(long, global = true, value_parser = parse_offset)]
    image_offset: Option<u64>,
    /// A data pack directory (holding rampage-pack.toml) layered over the bundled heuristic databases; repeatable,
    /// earlier packs take precedence. Directories in RAMPAGE_PACKS (a path list) load after these
    #[arg(long = "pack", global = true, value_name = "DIR")]
    packs: Vec<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum PacksCommand {
    /// List every pack loaded with --pack or RAMPAGE_PACKS, then the built-in one (precedence order), with each
    /// content's status
    List,
    /// Validate one pack directory and report each content's status; fails when anything does not load
    Check { directory: PathBuf },
}

#[derive(Subcommand)]
enum Command {
    /// Show format, architecture, entry point, segments and sections
    Info { file: PathBuf },
    /// Disassemble instructions
    Disasm {
        file: PathBuf,
        /// Start address (hex 0x..., decimal) or symbol name; defaults to the entry point
        #[arg(long)]
        at: Option<String>,
        /// Number of instructions
        #[arg(long, default_value_t = rampage_api::DEFAULT_INSTRUCTIONS)]
        count: usize,
    },
    /// List printable ASCII and UTF-16LE strings
    Strings {
        file: PathBuf,
        /// Minimum length in characters
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        /// Only strings containing this text (case-insensitive)
        #[arg(long)]
        contains: Option<String>,
    },
    /// Discover functions by recursive descent from symbols, exports, the entry point and unwind metadata
    Funcs {
        file: PathBuf,
        /// Only list functions named by symbols, exports and the entry point, without analysis
        #[arg(long)]
        symbols_only: bool,
        /// Only functions whose name contains this text (case-insensitive)
        #[arg(long)]
        name: Option<String>,
    },
    /// Hashes, entropy, format details, overlay and hints of packing or weak hardening
    Triage { file: PathBuf },
    /// Likely behaviors inferred from imports and strings (triage evidence, not proof)
    Capabilities { file: PathBuf },
    /// .NET assembly metadata: identity, references, entry point, types with method signatures, P/Invoke, attributes
    Dotnet {
        file: PathBuf,
        /// The list to page: types, pinvokes or attributes
        #[arg(long, default_value = "types", value_parser = parse_dotnet_list, conflicts_with = "il")]
        list: rampage_api::DotNetList,
        /// Only types whose full name or a method name, P/Invoke imports whose method, DLL or import name, or
        /// attributes whose type or target contains this text (case-insensitive)
        #[arg(long)]
        contains: Option<String>,
        /// With --list attributes, only those applied to this metadata token (hex with 0x, or decimal)
        #[arg(long, value_parser = parse_token)]
        parent_token: Option<u32>,
        /// List one method's CIL instead: a MethodDef token (0x0600000d) or Namespace.Type::Name; --offset and
        /// --limit then page its instructions
        #[arg(long, conflicts_with_all = ["contains", "parent_token"])]
        il: Option<String>,
        /// Entries of the list (or instructions with --il) to skip, for paging
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Entries per page
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..))]
        limit: u64,
    },
    /// Identify the producing tool (packer/compiler/protector/installer) from heuristic signatures
    Detect {
        file: PathBuf,
        /// A user-supplied PeID userdb.txt, overlaid on the bundled database (with any packs' PeID signatures)
        #[arg(long)]
        peid: Option<PathBuf>,
    },
    /// Scan with user-supplied YARA rules (a .yar/.yara file or a directory of them) and those of data packs
    Yara {
        file: PathBuf,
        /// Optional when a data pack holds YARA rules
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Detect behaviors with a directory of Mandiant capa rules and those of data packs (file-scope feature subset)
    Capa {
        file: PathBuf,
        /// Optional when a data pack holds capa rules
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// List the data packs in effect, or check one pack directory
    Packs {
        #[command(subcommand)]
        action: PacksCommand,
    },
    /// Decode coverage and evidence that static disassembly may be unreliable
    Audit {
        file: PathBuf,
        /// Run whole-program discovery and correlate candidates with bounded samples
        #[arg(long)]
        include_discovery: bool,
    },
    /// Demangled symbols, named vtables/RTTI and Objective-C selector strings
    Metadata { file: PathBuf },
    /// Inventory binaries in a bundle or already-extracted package without executing it
    Inventory { directory: PathBuf },
    /// Scan any file for embedded executables and containers by validated header, without extracting anything
    Carve {
        file: PathBuf,
        /// Stop after this many candidates (1 to 4096)
        #[arg(
            long,
            default_value_t = rampage_loaders::carve::MAX_CANDIDATES,
            value_parser = clap::builder::RangedU64ValueParser::<usize>::new()
                .range(1..=rampage_loaders::carve::MAX_CANDIDATES as u64)
        )]
        max_candidates: usize,
    },
    /// Structural CFG and reference summary of a function (not decompiled source)
    Summarize {
        file: PathBuf,
        #[arg(long)]
        at: String,
    },
    /// Decompile a function to C with bundled Ghidra specifications
    Decompile {
        file: PathBuf,
        #[arg(long)]
        at: String,
        /// Override the format-selected Ghidra compiler ID (gcc, windows, apcs, macosx, ...)
        #[arg(long)]
        compiler: Option<String>,
        /// Isolate native decompilation in a supervised sibling rampage-worker process
        #[arg(long)]
        isolated: bool,
    },
    /// Partial ARM64 SSA pseudocode with explicit unknowns (not recovered C source)
    Pseudocode {
        file: PathBuf,
        #[arg(long)]
        at: String,
        #[arg(long)]
        structured: bool,
    },
    /// Compare function starts with a versioned, image-hash-matched reference export
    Compare {
        file: PathBuf,
        #[arg(long)]
        reference: PathBuf,
    },
    /// Build a library-function signature database from a binary whose functions are named, hashing each over its
    /// symbol size and its discovered extent, with callee keys for functions whose bodies collide
    Signatures {
        file: PathBuf,
        /// Write the database here (JSON); defaults to standard output
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Name functions by matching a signature database (FLIRT/Function-ID style); functions whose bodies collide
    /// are told apart by the names of the functions they call
    Identify {
        file: PathBuf,
        /// A signature database to apply, overlaid on the bundled starter database unless --no-bundled is set
        #[arg(long)]
        db: Option<PathBuf>,
        /// Do not apply the bundled starter database (requires --db)
        #[arg(long, requires = "db")]
        no_bundled: bool,
        /// Save matched names for still-unnamed functions as user names
        #[arg(long)]
        apply: bool,
    },
    /// Inspect an explicit ARM64 absolute64 or signed-relative32 jump table
    JumpTable {
        file: PathBuf,
        #[arg(long)]
        at: String,
        #[arg(long)]
        count: usize,
        #[arg(long)]
        relative_base: Option<String>,
    },
    /// Correlate a runtime snapshot address with an explicit UUID-matched original Mach-O
    Correlate {
        file: PathBuf,
        #[arg(long)]
        original: PathBuf,
        #[arg(long)]
        module: String,
        #[arg(long)]
        at: String,
    },
    /// Compare explicit captured ranges to a UUID-matched original without transferring annotations
    CompareRuntime {
        file: PathBuf,
        #[arg(long)]
        original: PathBuf,
        #[arg(long)]
        module: String,
        #[arg(long, required = true)]
        range: Vec<String>,
    },
    /// Observe one captured pointer without changing discovery or treating mutable data as proven flow
    ObservePointer {
        file: PathBuf,
        #[arg(long)]
        at: String,
    },
    /// Compare explicit slots in two captures without asserting chronology, correspondence or flow
    ComparePointers {
        file: PathBuf,
        #[arg(long)]
        other: PathBuf,
        #[arg(long)]
        at: String,
        #[arg(long)]
        other_at: String,
    },
    /// Link one captured ARM64 indirect branch to a slot load in an explicit bounded window
    ObserveIndirectBranch {
        file: PathBuf,
        #[arg(long)]
        start: String,
        #[arg(long)]
        at: String,
    },
    /// List imported functions with their libraries and import slots
    Imports {
        file: PathBuf,
        /// Only imports whose name or library contains this text (case-insensitive)
        #[arg(long)]
        contains: Option<String>,
    },
    /// List exported symbols
    Exports {
        file: PathBuf,
        /// Only exports whose name contains this text (case-insensitive)
        #[arg(long)]
        contains: Option<String>,
    },
    /// Name an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    Rename {
        file: PathBuf,
        /// Address or current name
        at: String,
        /// The new name
        #[arg(required_unless_present = "clear", conflicts_with = "clear")]
        name: Option<String>,
        /// Remove the user's name instead
        #[arg(long)]
        clear: bool,
    },
    /// Comment an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    Comment {
        file: PathBuf,
        /// Address or name
        at: String,
        /// The comment
        #[arg(required_unless_present = "clear", conflicts_with = "clear")]
        text: Option<String>,
        /// Remove the comment instead
        #[arg(long)]
        clear: bool,
    },
    /// Apply a JSON array of {at, name?, comment?} as one undo step; nothing is applied if any entry is invalid
    AnnotateBatch {
        file: PathBuf,
        /// The JSON file of entries (at most 1000)
        entries: PathBuf,
    },
    /// Report whether candidate names are valid identifiers, address-shaped, or already used
    CheckNames {
        file: PathBuf,
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// List the user's names and comments
    Annotations { file: PathBuf },
    /// Preview embedded DWARF scalar/pointer function signatures, optionally persist them
    DebugTypes {
        file: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Run a guided investigation workflow and print its bounded, evidence-backed report
    Report {
        workflow: report::Workflow,
        file: PathBuf,
        /// The second binary, for diff-builds
        #[arg(long)]
        other: Option<PathBuf>,
        /// Findings kept per section (default 25, at most 200)
        #[arg(long)]
        limit: Option<usize>,
        /// find-main: skip the decompilation preview
        #[arg(long)]
        no_decompile: bool,
    },
    /// Serve the Model Context Protocol over stdin/stdout for AI agents. Lists the core tools and enable_tools,
    /// which adds the other groups; RAMPAGE_MCP_TOOLS=all or a comma-separated list of groups serves more at once
    Mcp {
        /// List every tool group from the start, for clients that do not refresh their tool list
        #[arg(long)]
        all_tools: bool,
    },
    /// List code and data cross-references to or from an address, symbol or function
    #[command(group(clap::ArgGroup::new("direction").required(true)))]
    Xrefs {
        file: PathBuf,
        /// List references to this address or name
        #[arg(long, group = "direction")]
        to: Option<String>,
        /// List references made by this function, or by the instruction at this address
        #[arg(long, group = "direction")]
        from: Option<String>,
    },
    /// Export every function's block starts, CFG edges and outgoing code references as JSON, for comparing
    /// against another tool (tools/cfg-benchmark.py); unlike the MCP tools, the output is never truncated
    #[command(hide = true)]
    ExportCfg { file: PathBuf },
}

fn parse_arch(text: &str) -> Result<Arch, String> {
    text.parse()
}

fn parse_offset(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|error| format!("not a file offset: {error}"))
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Loaded on first use, so that commands which consult no heuristic database do not read any pack.
    let packs = Arc::new(Packs::lazy_with_env(&cli.packs));
    let warn = !matches!(cli.command, Command::Packs { .. });
    if let Command::Mcp { all_tools } = cli.command {
        return serve_mcp(all_tools, packs);
    }
    let options = Options { json: cli.json, arch: cli.arch, offset: cli.image_offset, packs: Arc::clone(&packs) };
    let mut out = BufWriter::new(io::stdout().lock());
    let result = match cli.command {
        Command::Info { file } => commands::info(&mut out, &file, &options),
        Command::Disasm { file, at, count } => commands::disasm(&mut out, &file, at.as_deref(), count, &options),
        Command::Strings { file, min_len, contains } => {
            let query = StringsQuery { min_len: Some(min_len), contains, ..StringsQuery::default() };
            commands::strings(&mut out, &file, &query, &options)
        }
        Command::Funcs { file, symbols_only, name } => {
            let query = FunctionsQuery { name_contains: name, ..FunctionsQuery::default() };
            commands::funcs(&mut out, &file, symbols_only, &query, &options)
        }
        Command::Xrefs { file, to, from } => {
            let query = match (&to, &from) {
                (Some(to), _) => commands::XrefTarget::To(to),
                (_, Some(from)) => commands::XrefTarget::From(from),
                (None, None) => unreachable!("clap requires --to or --from"),
            };
            commands::xrefs(&mut out, &file, query, &options)
        }
        Command::ExportCfg { file } => commands::export_cfg(&mut out, &file, &options),
        Command::Triage { file } => commands::triage(&mut out, &file, &options),
        Command::Capabilities { file } => commands::capabilities(&mut out, &file, &options),
        Command::Dotnet { file, il: Some(method), offset, limit, .. } => {
            let query = rampage_api::DotNetIlQuery {
                method,
                offset: Some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
            };
            commands::dotnet_il(&mut out, &file, &query, &options)
        }
        Command::Dotnet { file, list, contains, parent_token, offset, limit, il: None } => {
            let query = rampage_api::DotNetQuery {
                list,
                contains,
                parent_token,
                offset: Some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
            };
            commands::dotnet(&mut out, &file, &query, &options)
        }
        Command::Detect { file, peid } => commands::detect(&mut out, &file, peid.as_deref(), &options),
        Command::Yara { file, rules } => commands::yara(&mut out, &file, rules.as_deref(), &options),
        Command::Capa { file, rules } => commands::capa(&mut out, &file, rules.as_deref(), &options),
        Command::Packs { action: PacksCommand::List } => commands::packs_list(&mut out, &options),
        Command::Packs { action: PacksCommand::Check { directory } } => {
            commands::packs_check(&mut out, &directory, &options)
        }
        Command::Audit { file, include_discovery } => commands::audit(&mut out, &file, include_discovery, &options),
        Command::Metadata { file } => commands::metadata(&mut out, &file, &options),
        Command::Inventory { directory } => commands::inventory(&mut out, &directory, &options),
        Command::Carve { file, max_candidates } => commands::carve(&mut out, &file, max_candidates, &options),
        Command::Summarize { file, at } => commands::summarize(&mut out, &file, &at, &options),
        Command::Decompile { file, at, compiler, isolated } => {
            commands::decompile(&mut out, &file, &at, compiler.as_deref(), isolated, &options)
        }
        Command::Pseudocode { file, at, structured } => {
            commands::pseudocode(&mut out, &file, &at, structured, &options)
        }
        Command::Compare { file, reference } => commands::compare(&mut out, &file, &reference, &options),
        Command::Signatures { file, output } => commands::signatures(&mut out, &file, output.as_deref(), &options),
        Command::Identify { file, db, no_bundled, apply } => {
            commands::identify(&mut out, &file, db.as_deref(), no_bundled, apply, &options)
        }
        Command::JumpTable { file, at, count, relative_base } => {
            commands::jump_table(&mut out, &file, &at, count, relative_base.as_deref(), &options)
        }
        Command::Correlate { file, original, module, at } => {
            commands::correlate(&mut out, &file, &original, &module, &at, &options)
        }
        Command::CompareRuntime { file, original, module, range } => {
            commands::compare_runtime(&mut out, &file, &original, &module, &range, &options)
        }
        Command::ObservePointer { file, at } => commands::observe_pointer(&mut out, &file, &at, &options),
        Command::ComparePointers { file, other, at, other_at } => {
            commands::compare_pointers(&mut out, &file, &other, &at, &other_at, &options)
        }
        Command::ObserveIndirectBranch { file, start, at } => {
            commands::observe_indirect_branch(&mut out, &file, &start, &at, &options)
        }
        Command::Imports { file, contains } => {
            commands::imports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Exports { file, contains } => {
            commands::exports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Rename { file, at, name, .. } => commands::rename(&mut out, &file, &at, name.as_deref(), &options),
        Command::Comment { file, at, text, .. } => commands::comment(&mut out, &file, &at, text.as_deref(), &options),
        Command::AnnotateBatch { file, entries } => commands::annotate_batch(&mut out, &file, &entries, &options),
        Command::CheckNames { file, names } => commands::check_names(&mut out, &file, &names, &options),
        Command::Annotations { file } => commands::annotations(&mut out, &file, &options),
        Command::DebugTypes { file, apply } => commands::debug_types(&mut out, &file, apply, &options),
        Command::Report { workflow, file, other, limit, no_decompile } => {
            let report_options = report::ReportOptions { other, limit, no_decompile };
            report::report(&mut out, workflow, &file, &report_options, &options)
        }
        Command::Mcp { .. } => unreachable!("handled before opening stdout"),
    }
    .and_then(|()| out.flush().map_err(Into::into));

    if warn && packs.is_loaded() {
        for problem in packs.problems() {
            eprintln!("rampage: warning: {problem}");
        }
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rampage: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn serve_mcp(all_tools: bool, packs: Arc<Packs>) -> ExitCode {
    let env = std::env::var(rampage_mcp::TOOLS_ENV).ok();
    let groups = match rampage_mcp::initial_groups(all_tools, env.as_deref()) {
        Ok(groups) => groups,
        Err(error) => {
            eprintln!("rampage: {}: {error}", rampage_mcp::TOOLS_ENV);
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rampage: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(rampage_mcp::serve_stdio(groups, packs)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rampage: mcp server failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
}
