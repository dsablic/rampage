mod analyze;
mod args;
mod commands;
mod hierarchy;
mod report;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use rampage_api::{FunctionsQuery, ListQuery, Packs, StringsQuery};
use rampage_arch::Arch;

use crate::args::ArchiveInventoryArgs;
use crate::args::ImportDebugLayoutsArgs;
use crate::args::{
    AnnotateBatchArgs, AtArgs, AuditArgs, CapaArgs, CarveArgs, CheckNamesArgs, CommentArgs, CompareArgs,
    ComparePointersArgs, CompareRuntimeArgs, CorrelateArgs, DebugTypesArgs, DecompileArgs, DetectArgs, DirectoryArgs,
    DisasmArgs, DotnetArgs, ExportsArgs, FileArgs, FuncsArgs, IdentifyArgs, ImportPdbNamesArgs, ImportsArgs,
    JumpTableArgs, McpArgs, ObserveIndirectBranchArgs, PseudocodeArgs, QueryDebuggerArgs, RenameArgs, ReportArgs,
    SignaturesArgs, StringsArgs, XrefsArgs, YaraArgs,
};
use crate::commands::Options;
use crate::hierarchy::RootCommand;

#[derive(Parser)]
#[command(name = "rampage", version, about = "High-performance reverse engineering toolkit")]
struct Cli {
    /// Emit JSON instead of text
    #[arg(long, global = true)]
    json: bool,
    /// Architecture slice to load from a universal binary (x86, x86_64, aarch64, arm, mips, powerpc, riscv64, ...)
    #[arg(long, global = true, value_parser = parse_arch)]
    arch: Option<Arch>,
    /// Open the executable embedded at this file offset (hex 0x... or decimal), such as one `carve` found; for a
    /// universal Mach-O, the offset of its fat header, with --arch for the slice. Offset 0 alone opens the file
    #[arg(long, global = true, value_parser = rampage_api::parse_file_offset)]
    image_offset: Option<u64>,
    /// With --image-offset, the embedded image's length in bytes (hex 0x... or decimal); defaults to the extent its
    /// header tables give, so bytes after that (an overlay) are left out
    #[arg(long, global = true, value_parser = rampage_api::parse_file_offset)]
    image_length: Option<u64>,
    /// A data pack directory (holding rampage-pack.toml) layered over the bundled heuristic databases; repeatable,
    /// earlier packs take precedence. Directories in RAMPAGE_PACKS (a path list) load after these
    #[arg(long = "pack", value_name = "DIR")]
    packs: Vec<PathBuf>,
    #[command(subcommand)]
    command: RootCommand,
}

#[derive(Subcommand)]
enum PacksCommand {
    /// List every pack loaded with --pack or RAMPAGE_PACKS, then the built-in one (precedence order), with each
    /// content's status
    List,
    /// Validate one pack directory and report each content's status; fails when anything does not load
    Check(DirectoryArgs),
}

#[derive(Subcommand)]
enum Command {
    #[command(skip)]
    ArchiveInventory(ArchiveInventoryArgs),
    #[command(hide = true)]
    QueryDebugger(QueryDebuggerArgs),
    /// Run bounded workflows and selected decompilations as one multi-architecture analysis report
    #[command(hide = true)]
    Analyze(analyze::AnalyzeArgs),
    /// Show format, architecture, entry point, segments and sections
    #[command(hide = true)]
    Info(FileArgs),
    /// Disassemble instructions
    #[command(hide = true)]
    Disasm(DisasmArgs),
    /// List printable ASCII and UTF-16LE strings
    #[command(hide = true)]
    Strings(StringsArgs),
    /// Discover functions by recursive descent from symbols, exports, the entry point and unwind metadata
    #[command(hide = true)]
    Funcs(FuncsArgs),
    /// Hashes, entropy, format details, overlay and hints of packing or weak hardening
    #[command(hide = true)]
    Triage(FileArgs),
    /// Likely behaviors inferred from imports and strings (triage evidence, not proof)
    #[command(hide = true)]
    Capabilities(FileArgs),
    /// .NET metadata: identity, references, entry point, signatures, P/Invoke, attributes and resource links
    #[command(hide = true)]
    Dotnet(DotnetArgs),
    /// Identify the producing tools (packer/compiler/protector/installer/linker/runtime) from heuristic signatures
    #[command(hide = true)]
    Detect(DetectArgs),
    /// Scan with user-supplied YARA rules (a .yar/.yara file or a directory of them) and those of data packs
    #[command(hide = true)]
    Yara(YaraArgs),
    /// Detect behaviors with a directory of Mandiant capa rules and those of data packs (file-scope feature subset)
    #[command(hide = true)]
    Capa(CapaArgs),
    /// List the data packs in effect, or check one pack directory
    #[command(hide = true)]
    Packs {
        #[command(subcommand)]
        action: PacksCommand,
    },
    /// Decode coverage and evidence that static disassembly may be unreliable
    #[command(hide = true)]
    Audit(AuditArgs),
    /// Demangled symbols, named vtables/RTTI and Objective-C selector strings
    #[command(hide = true)]
    Metadata(FileArgs),
    /// Inventory binaries in a bundle or already-extracted package without executing it
    #[command(hide = true)]
    Inventory(DirectoryArgs),
    /// Scan any file for embedded executables and containers by validated header, without extracting anything
    #[command(hide = true)]
    Carve(CarveArgs),
    /// Structural CFG and reference summary of a function (not decompiled source)
    #[command(hide = true)]
    Summarize(AtArgs),
    /// Decompile a function to C with bundled Ghidra specifications
    #[command(hide = true)]
    Decompile(DecompileArgs),
    /// Partial ARM64 SSA pseudocode with explicit unknowns (not recovered C source)
    #[command(hide = true)]
    Pseudocode(PseudocodeArgs),
    /// Compare function starts with a versioned, image-hash-matched reference export
    #[command(hide = true)]
    Compare(CompareArgs),
    /// Build a library-function signature database from a binary whose functions are named, hashing each over its
    /// symbol size and its discovered extent, with callee keys for functions whose bodies collide
    #[command(hide = true)]
    Signatures(SignaturesArgs),
    /// Name functions by matching a signature database (FLIRT/Function-ID style); functions whose bodies collide
    /// are told apart by the names of the functions they call
    #[command(hide = true)]
    Identify(IdentifyArgs),
    /// Inspect an explicit ARM64 absolute64 or signed-relative32 jump table
    #[command(hide = true)]
    JumpTable(JumpTableArgs),
    /// Correlate a runtime snapshot address with an explicit UUID-matched original Mach-O
    #[command(hide = true)]
    Correlate(CorrelateArgs),
    /// Compare explicit captured ranges to a UUID-matched original without transferring annotations
    #[command(hide = true)]
    CompareRuntime(CompareRuntimeArgs),
    /// Observe one captured pointer without changing discovery or treating mutable data as proven flow
    #[command(hide = true)]
    ObservePointer(AtArgs),
    /// Compare explicit slots in two captures without asserting chronology, correspondence or flow
    #[command(hide = true)]
    ComparePointers(ComparePointersArgs),
    /// Link one captured ARM64 indirect branch to a slot load in an explicit bounded window
    #[command(hide = true)]
    ObserveIndirectBranch(ObserveIndirectBranchArgs),
    /// List imported functions with their libraries and import slots
    #[command(hide = true)]
    Imports(ImportsArgs),
    /// List exported symbols
    #[command(hide = true)]
    Exports(ExportsArgs),
    /// Name an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    #[command(hide = true)]
    Rename(RenameArgs),
    /// Comment an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    #[command(hide = true)]
    Comment(CommentArgs),
    /// Apply a JSON array of {at, name?, comment?} as one atomic annotation batch; nothing is applied if any entry
    /// is invalid
    #[command(hide = true)]
    AnnotateBatch(AnnotateBatchArgs),
    /// Report whether candidate names are valid identifiers, address-shaped, or already used
    #[command(hide = true)]
    CheckNames(CheckNamesArgs),
    /// List the user's names and comments
    #[command(hide = true)]
    Annotations(FileArgs),
    /// Preview embedded DWARF scalar/pointer function signatures, optionally persist them
    #[command(hide = true)]
    DebugTypes(DebugTypesArgs),
    #[command(skip)]
    ImportPdbNames(ImportPdbNamesArgs),
    #[command(skip)]
    ImportDebugLayouts(ImportDebugLayoutsArgs),
    /// Run a guided investigation workflow and print its bounded, evidence-backed report
    #[command(hide = true)]
    Report(ReportArgs),
    /// Serve the Model Context Protocol over stdin/stdout for AI agents. Lists the core tools and enable_tools,
    /// which adds the other groups; RAMPAGE_MCP_TOOLS=all or a comma-separated list of groups serves more at once
    #[command(hide = true)]
    Mcp(McpArgs),
    /// List code and data cross-references to or from an address, symbol or function
    #[command(hide = true)]
    Xrefs(XrefsArgs),
    /// Export every function's block starts, CFG edges and outgoing code references as JSON, for comparing
    /// against another tool (tools/cfg-benchmark.py); unlike the MCP tools, the output is never truncated
    #[command(hide = true)]
    ExportCfg(FileArgs),
}

fn parse_arch(text: &str) -> Result<Arch, String> {
    text.parse()
}

fn main() -> ExitCode {
    let mut parser = hierarchy::with_pack_arguments(Cli::command());
    let matches = parser.get_matches_mut();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    cli.packs = hierarchy::pack_paths(&matches);
    let action = cli.command.into_action();
    if cli.image_length.is_some() && cli.image_offset.is_none() {
        parser
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--image-length requires --image-offset <IMAGE_OFFSET>",
            )
            .exit();
    }
    let command = match action {
        Ok(command) => command,
        Err(error) => {
            eprintln!("rampage: {error}");
            return ExitCode::FAILURE;
        }
    };
    if matches!(&command, Command::ArchiveInventory(..))
        && (cli.arch.is_some() || cli.image_offset.is_some() || cli.image_length.is_some())
    {
        eprintln!("rampage: binary archive-inventory does not accept --arch, --image-offset or --image-length");
        return ExitCode::FAILURE;
    }
    if matches!(
        &command,
        Command::Dotnet(args) if args.parent_token.is_some() && args.list != rampage_api::DotNetList::Attributes
    ) {
        parser.error(clap::error::ErrorKind::ArgumentConflict, "--parent-token filters --list attributes only").exit();
    }
    if cli.arch.is_some() && matches!(&command, Command::Analyze(args) if args.all_architectures) {
        parser
            .error(clap::error::ErrorKind::ArgumentConflict, "--all-architectures conflicts with --arch <ARCH>")
            .exit();
    }
    if cli.image_offset.is_some()
        && let Some(command) = without_one_image(&command)
    {
        eprintln!("rampage: --image-offset does not apply to {command}, which does not open one embedded image");
        return ExitCode::FAILURE;
    }
    // Loaded on first use, so that commands which consult no heuristic database do not read any pack.
    let packs = Arc::new(Packs::lazy_with_env(&cli.packs));
    let warn = !matches!(command, Command::Packs { .. });
    if let Command::Mcp(McpArgs { all_tools }) = command {
        return serve_mcp(all_tools, packs);
    }
    let image = cli.image_offset.map(|offset| rampage_loaders::ImageAt::new(offset, cli.image_length));
    let options = Options { json: cli.json, arch: cli.arch, image, packs: Arc::clone(&packs) };
    let mut out = BufWriter::new(io::stdout().lock());
    let result = match command {
        Command::ArchiveInventory(args) => {
            let query = rampage_api::ArchiveQuery {
                offset: Some(args.offset),
                limit: Some(args.limit as usize),
                contains: args.contains,
            };
            commands::archive_inventory(&mut out, &args.file, &query, &options)
        }
        Command::QueryDebugger(args) => debugger_query(&mut out, args),
        Command::Analyze(args) => analyze::analyze(&mut out, &args, &options),
        Command::Info(FileArgs { file }) => commands::info(&mut out, &file, &options),
        Command::Disasm(DisasmArgs { file, at, count }) => {
            commands::disasm(&mut out, &file, at.as_deref(), count, &options)
        }
        Command::Strings(StringsArgs { file, min_len, contains }) => {
            let query = StringsQuery { min_len: Some(min_len), contains, ..StringsQuery::default() };
            commands::strings(&mut out, &file, &query, &options)
        }
        Command::Funcs(FuncsArgs { file, symbols_only, name }) => {
            let query = FunctionsQuery { name_contains: name, ..FunctionsQuery::default() };
            commands::funcs(&mut out, &file, symbols_only, &query, &options)
        }
        Command::Xrefs(XrefsArgs { file, to, from }) => {
            let query = match (&to, &from) {
                (Some(to), _) => commands::XrefTarget::To(to),
                (_, Some(from)) => commands::XrefTarget::From(from),
                (None, None) => unreachable!("clap requires --to or --from"),
            };
            commands::xrefs(&mut out, &file, query, &options)
        }
        Command::ExportCfg(FileArgs { file }) => commands::export_cfg(&mut out, &file, &options),
        Command::Triage(FileArgs { file }) => commands::triage(&mut out, &file, &options),
        Command::Capabilities(FileArgs { file }) => commands::capabilities(&mut out, &file, &options),
        Command::Dotnet(DotnetArgs { file, il: Some(method), offset, limit, at, .. }) => {
            let query = rampage_api::DotNetIlQuery {
                method,
                offset: at.is_none().then_some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
                at,
            };
            commands::dotnet_il(&mut out, &file, &query, &options)
        }
        Command::Dotnet(DotnetArgs { file, list, contains, parent_token, offset, limit, il: None, .. }) => {
            let query = rampage_api::DotNetQuery {
                list,
                contains,
                parent_token,
                offset: Some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
            };
            commands::dotnet(&mut out, &file, &query, &options)
        }
        Command::Detect(DetectArgs { file, peid }) => commands::detect(&mut out, &file, peid.as_deref(), &options),
        Command::Yara(YaraArgs { file, rules }) => commands::yara(&mut out, &file, rules.as_deref(), &options),
        Command::Capa(CapaArgs { file, rules }) => commands::capa(&mut out, &file, rules.as_deref(), &options),
        Command::Packs { action: PacksCommand::List } => commands::packs_list(&mut out, &options),
        Command::Packs { action: PacksCommand::Check(DirectoryArgs { directory }) } => {
            commands::packs_check(&mut out, &directory, &options)
        }
        Command::Audit(AuditArgs { file, include_discovery, entries, at }) => {
            commands::audit(&mut out, &file, include_discovery, entries, at.as_deref(), &options)
        }
        Command::Metadata(FileArgs { file }) => commands::metadata(&mut out, &file, &options),
        Command::Inventory(DirectoryArgs { directory }) => commands::inventory(&mut out, &directory, &options),
        Command::Carve(CarveArgs { file, max_candidates }) => {
            commands::carve(&mut out, &file, max_candidates, &options)
        }
        Command::Summarize(AtArgs { file, at }) => commands::summarize(&mut out, &file, &at, &options),
        Command::Decompile(DecompileArgs { file, at, compiler, isolated, exact_entry }) => {
            commands::decompile(&mut out, &file, &at, compiler.as_deref(), isolated, exact_entry, &options)
        }
        Command::Pseudocode(PseudocodeArgs { file, at, structured }) => {
            commands::pseudocode(&mut out, &file, &at, structured, &options)
        }
        Command::Compare(CompareArgs { file, reference }) => commands::compare(&mut out, &file, &reference, &options),
        Command::Signatures(SignaturesArgs { file, output }) => {
            commands::signatures(&mut out, &file, output.as_deref(), &options)
        }
        Command::Identify(IdentifyArgs { file, db, no_bundled, apply }) => {
            commands::identify(&mut out, &file, db.as_deref(), no_bundled, apply, &options)
        }
        Command::JumpTable(JumpTableArgs { file, at, count, relative_base }) => {
            commands::jump_table(&mut out, &file, &at, count, relative_base.as_deref(), &options)
        }
        Command::Correlate(CorrelateArgs { file, original, module, at }) => {
            commands::correlate(&mut out, &file, &original, &module, &at, &options)
        }
        Command::CompareRuntime(CompareRuntimeArgs {
            file,
            original,
            original_image_offset,
            original_image_length,
            module,
            range,
        }) => {
            let original_image =
                original_image_offset.map(|offset| rampage_loaders::ImageAt::new(offset, original_image_length));
            commands::compare_runtime(&mut out, &file, &original, original_image, &module, &range, &options)
        }
        Command::ObservePointer(AtArgs { file, at }) => commands::observe_pointer(&mut out, &file, &at, &options),
        Command::ComparePointers(ComparePointersArgs { file, other, at, other_at }) => {
            commands::compare_pointers(&mut out, &file, &other, &at, &other_at, &options)
        }
        Command::ObserveIndirectBranch(ObserveIndirectBranchArgs { file, start, at }) => {
            commands::observe_indirect_branch(&mut out, &file, &start, &at, &options)
        }
        Command::Imports(ImportsArgs { file, contains }) => {
            commands::imports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Exports(ExportsArgs { file, contains }) => {
            commands::exports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Rename(RenameArgs { file, at, name, .. }) => {
            commands::rename(&mut out, &file, &at, name.as_deref(), &options)
        }
        Command::Comment(CommentArgs { file, at, text, .. }) => {
            commands::comment(&mut out, &file, &at, text.as_deref(), &options)
        }
        Command::AnnotateBatch(AnnotateBatchArgs { file, entries }) => {
            commands::annotate_batch(&mut out, &file, &entries, &options)
        }
        Command::CheckNames(CheckNamesArgs { file, names }) => commands::check_names(&mut out, &file, &names, &options),
        Command::Annotations(FileArgs { file }) => commands::annotations(&mut out, &file, &options),
        Command::DebugTypes(DebugTypesArgs { file, apply }) => commands::debug_types(&mut out, &file, apply, &options),
        Command::ImportPdbNames(args) => commands::import_pdb_names(&mut out, &args, &options),
        Command::ImportDebugLayouts(args) => commands::import_debug_layouts(&mut out, &args, &options),
        Command::Report(ReportArgs {
            workflow,
            file,
            other,
            other_image_offset,
            other_image_length,
            limit,
            no_decompile,
        }) => {
            let other_image =
                other_image_offset.map(|offset| rampage_loaders::ImageAt::new(offset, other_image_length));
            let report_options = report::ReportOptions { other, other_image, limit, no_decompile };
            report::report(&mut out, workflow, &file, &report_options, &options)
        }
        Command::Mcp(..) => unreachable!("handled before opening stdout"),
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

/// The name of a command that opens no image, or more than one, so that --image-offset would be ignored or apply
/// to only one of its files.
fn without_one_image(command: &Command) -> Option<&'static str> {
    Some(match command {
        Command::Carve(..) => "carve",
        Command::Inventory(..) => "inventory",
        Command::ArchiveInventory(..) => "binary archive-inventory",
        Command::Packs { .. } => "packs",
        Command::Mcp(..) => "mcp (pass image_offset to each tool call instead)",
        Command::QueryDebugger(..) => "runtime debugger query (does not open an image)",
        Command::Correlate(..) => "correlate",
        Command::CompareRuntime(..) => "compare-runtime",
        Command::ComparePointers(..) => "compare-pointers",
        _ => return None,
    })
}

fn debugger_query(out: &mut impl Write, args: QueryDebuggerArgs) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(args.timeout_ms);
    let request = rampage_api::DebuggerRequest::from_json(&args.request)?;
    let response = rampage_api::query_debugger(&args.socket, &request, deadline)?;
    serde_json::to_writer(&mut *out, &response)?;
    writeln!(out)?;
    out.flush()?;
    if let Some(error) = response.error {
        anyhow::bail!("debugger {}: {}", error.code, error.message);
    }
    Ok(())
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
