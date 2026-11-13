mod analyze;
mod args;
mod commands;
mod hierarchy;
mod report;
mod report_plugin;

#[cfg(test)]
mod contract_tests;

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use rampage_api::{FunctionsQuery, ListQuery, Packs, RawProjectRequest, StringsQuery};
use rampage_arch::Arch;

use crate::args::ArchiveInventoryArgs;
use crate::args::ImportDebugLayoutsArgs;
use crate::args::{
    AnnotateBatchArgs, AtArgs, AuditArgs, CapaArgs, CarveArgs, CheckNamesArgs, CommentArgs, CompareArgs,
    ComparePointersArgs, CompareRuntimeArgs, CorrelateArgs, DebugTypesArgs, DecompileArgs, DetectArgs, DirectoryArgs,
    DisasmArgs, DotnetArgs, ExportsArgs, FileArgs, FuncsArgs, IdentifyArgs, ImportPdbNamesArgs, ImportsArgs,
    JumpTableArgs, McpArgs, ObserveIndirectBranchArgs, PseudocodeArgs, QueryDebuggerArgs, RenameArgs, ReportArgs,
    ObjcSendsArgs, SignaturesArgs, StringsArgs, TypeLayoutArgs, XrefsArgs, YaraArgs,
};
use crate::commands::Options;
use crate::hierarchy::RootCommand;

#[derive(Parser)]
#[command(name = "rampage", version, about = "Reverse engineering toolkit built for AI agents")]
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
    /// Open FILE as an ordinary Raw Project from a literal JSON RawProjectRequest (closed profile, offset, length,
    /// base_address, optional entry and seeds): an analyst assertion with memory-only annotations and no sidecars.
    /// Raw-capable commands only
    #[arg(
        long,
        global = true,
        value_name = "JSON",
        conflicts_with_all = ["arch", "image_offset", "image_length", "raw_request"]
    )]
    raw_json: Option<String>,
    /// Like --raw-json, reading the RawProjectRequest from a regular JSON file (at most 1 MiB)
    #[arg(long, global = true, value_name = "REQUEST", conflicts_with_all = ["arch", "image_offset", "image_length"])]
    raw_request: Option<PathBuf>,
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
    /// Write a pack directory (for example the flywheel's promoted pack) to one portable .rpack archive: its files
    /// in the existing pack formats and a manifest with the format version, the minimum rampage version, families, a content hash and
    /// each promoted entry's provenance, revert id and gate results
    Export {
        /// The pack directory
        directory: PathBuf,
        /// The archive to write
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Check an .rpack archive (format version, minimum rampage version, file hashes, content hash, entries) and install its
    /// pack as a directory, loaded there first; nothing is added unless every check passes. Load it with --pack
    Import {
        /// The .rpack archive
        archive: PathBuf,
        /// The pack directory to create; it must not exist or be empty (default: ./<pack name>)
        #[arg(long, value_name = "DIR")]
        into: Option<PathBuf>,
    },
    /// Check an .rpack archive and show what importing it would change: files, promoted entries and signature rows
    /// added or removed against an existing pack directory (or an empty one)
    Diff {
        /// The .rpack archive
        archive: PathBuf,
        /// The pack directory it would replace
        #[arg(long, value_name = "DIR")]
        against: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Inspect raw windows with 20 closed Sleigh IDs, not native-image/ABI/packet support
    #[command(hide = true, long_about = args::INSPECT_SLEIGH_ABOUT)]
    InspectSleigh(args::InspectSleighArgs),
    /// Atomically apply a checked heterogeneous annotation batch from explicit JSON
    #[command(name = "batch", hide = true)]
    AnnotationBatch(args::AnnotationBatchArgs),
    /// Native control-flow graph with an explicit full/summary/code JSON view
    #[command(hide = true)]
    Graph(args::GraphArgs),
    #[command(hide = true)]
    PatchBytes(args::PatchBytesArgs),
    #[command(hide = true)]
    RevertPatch(args::RevertPatchArgs),
    #[command(hide = true)]
    ListPatches(args::ListPatchesArgs),
    #[command(hide = true)]
    ExportPatched(args::ExportPatchedArgs),
    /// Assemble a read-only byte proposal; never execute or install the resulting bytes
    #[command(hide = true)]
    Assemble(args::AssembleArgs),
    /// Search retained bytes, Unicode text, instructions, immediates or native references
    #[command(hide = true)]
    Search(args::SearchArgs),
    #[command(skip)]
    ArchiveInventory(ArchiveInventoryArgs),
    #[command(skip)]
    RecordFinding(args::RecordFindingArgs),
    #[command(skip)]
    ListFindings(args::ListFindingsArgs),
    #[command(skip)]
    TransferAnnotations(args::TransferAnnotationsArgs),
    #[command(skip)]
    BuildInfo(args::BuildInfoArgs),
    #[command(skip)]
    PyInstallerArchive(args::PyInstallerArchiveArgs),
    #[command(skip)]
    WasmModule(args::WasmModuleArgs),
    #[command(skip)]
    FileLayout(args::LayoutArgs),
    #[command(skip)]
    ProbeCompression(args::ProbeCompressionArgs),
    #[command(hide = true)]
    QueryDebugger(QueryDebuggerArgs),
    /// Run bounded workflows and selected decompilations as one multi-architecture analysis report
    #[command(hide = true)]
    Analyze(analyze::AnalyzeArgs),
    /// Show format, architecture, entry point, segments and sections
    #[command(hide = true)]
    Info(args::ViewedFileArgs),
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
    #[command(skip)]
    PeResources(args::PeResourcesArgs),
    #[command(skip)]
    PeLoadConfig(FileArgs),
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
    /// List the data packs in effect, check one pack directory, or export, import and diff .rpack archives
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
    Summarize(args::ViewedAtArgs),
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
    /// Inspect native-image bytes and candidate words
    #[command(hide = true)]
    InspectData(args::InspectDataArgs),
    /// Inspect an explicitly mapped raw-code window
    #[command(hide = true)]
    InspectRaw(args::InspectRawArgs),
    /// Decode an explicit file range into transient bytes
    #[command(hide = true)]
    DecodeFile(args::DecodeFileArgs),
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
    TypeLayout(TypeLayoutArgs),
    #[command(skip)]
    ObjcSends(ObjcSendsArgs),
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
    if matches!(
        &command,
        Command::ArchiveInventory(..)
            | Command::DecodeFile(..)
            | Command::InspectRaw(..)
            | Command::PyInstallerArchive(..)
            | Command::WasmModule(..)
            | Command::FileLayout(..)
            | Command::ProbeCompression(..)
    ) && (cli.arch.is_some() || cli.image_offset.is_some() || cli.image_length.is_some())
    {
        let name = match &command {
            Command::DecodeFile(..) => "decode",
            Command::InspectRaw(..) => "inspect-raw (put architecture and mapping in --request)",
            Command::PyInstallerArchive(..) => "pyinstaller-archive",
            Command::WasmModule(..) => "wasm-module",
            Command::FileLayout(..) => "layout",
            Command::ProbeCompression(..) => "probe-compression",
            _ => "archive-inventory",
        };
        eprintln!("rampage: binary {name} does not accept --arch, --image-offset or --image-length");
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
    let raw = match raw_request(cli.raw_json.as_deref(), cli.raw_request.as_deref()) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!("rampage: {error:#}");
            return ExitCode::FAILURE;
        }
    };
    if raw.is_some() && raw_tool(&command).is_none() {
        eprintln!(
            "rampage: --raw-json and --raw-request apply only to {RAW_COMMANDS}; this command does not open a Raw \
             Project"
        );
        return ExitCode::FAILURE;
    }
    // Loaded on first use, so that commands which consult no heuristic database do not read any pack.
    let packs = Arc::new(Packs::lazy_with_env(&cli.packs));
    let warn = !matches!(command, Command::Packs { .. });
    if let Command::Mcp(McpArgs { all_tools, debug_endpoints, debug_writes, debug_kill, require_worker, flywheel }) =
        command
    {
        return serve_mcp(all_tools, &debug_endpoints, (debug_writes, debug_kill), require_worker, packs, flywheel);
    }
    let image = cli.image_offset.map(|offset| rampage_loaders::ImageAt::new(offset, cli.image_length));
    let options = Options { json: cli.json, arch: cli.arch, image, raw, packs: Arc::clone(&packs) };
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
        Command::PyInstallerArchive(args) => {
            commands::pyinstaller_archive(&mut out, &args.file, args.offset, args.limit as usize, &options)
        }
        Command::WasmModule(args) => {
            commands::wasm_module(&mut out, &args.file, args.list, args.offset, args.limit as usize, &options)
        }
        Command::FileLayout(args) => commands::file_layout(&mut out, &args.file, &args.request(), &options),
        Command::ProbeCompression(args) => commands::probe_compression(&mut out, &args.file, &args.request(), &options),
        Command::QueryDebugger(args) => debugger_query(&mut out, args),
        Command::Analyze(args) => analyze::analyze(&mut out, &args, &options),
        Command::Info(args::ViewedFileArgs { file, view }) => commands::info(&mut out, &file, view, &options),
        Command::Disasm(DisasmArgs { file, at, count, view }) => {
            commands::disasm(&mut out, &file, at.as_deref(), count, view, &options)
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
        Command::BuildInfo(args::BuildInfoArgs { file, offset, limit }) => {
            let query = rampage_api::BuildInfoQuery {
                offset: Some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
            };
            commands::build_info(&mut out, &file, &query, &options)
        }
        Command::PeResources(args::PeResourcesArgs { file, type_filter, offset, limit }) => {
            let query = rampage_api::PeResourcesQuery {
                type_filter,
                offset: Some(offset),
                limit: Some(usize::try_from(limit).unwrap_or(usize::MAX)),
            };
            commands::pe_resources(&mut out, &file, &query, &options)
        }
        Command::PeLoadConfig(FileArgs { file }) => commands::pe_load_config(&mut out, &file, &options),
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
        Command::Packs { action: PacksCommand::Export { directory, output } } => {
            commands::packs_export(&mut out, &directory, &output, &options)
        }
        Command::Packs { action: PacksCommand::Import { archive, into } } => {
            commands::packs_import(&mut out, &archive, into.as_deref(), &options)
        }
        Command::Packs { action: PacksCommand::Diff { archive, against } } => {
            commands::packs_diff(&mut out, &archive, against.as_deref(), &options)
        }
        Command::Audit(AuditArgs { file, include_discovery, entries, at }) => {
            commands::audit(&mut out, &file, include_discovery, entries, at.as_deref(), &options)
        }
        Command::Metadata(FileArgs { file }) => commands::metadata(&mut out, &file, &options),
        Command::Inventory(DirectoryArgs { directory }) => commands::inventory(&mut out, &directory, &options),
        Command::Carve(CarveArgs { file, max_candidates }) => {
            commands::carve(&mut out, &file, max_candidates, &options)
        }
        Command::Summarize(args::ViewedAtArgs { file, at, view }) => {
            commands::summarize(&mut out, &file, &at, view, &options)
        }
        Command::Decompile(args) => commands::decompile(&mut out, &args, &options),
        Command::Pseudocode(PseudocodeArgs { file, at, structured }) => {
            commands::pseudocode(&mut out, &file, &at, structured, &options)
        }
        Command::Compare(CompareArgs { file, reference }) => commands::compare(&mut out, &file, &reference, &options),
        Command::PatchBytes(args) => commands::patch_tool(
            &mut out,
            &args.file,
            "patch_bytes",
            serde_json::json!({
                "at": args.at, "original_hex": args.original_hex, "replacement_hex": args.replacement_hex,
                "allow_data": args.allow_data, "source_sha256": args.review.source_sha256,
                "expected_revision": args.review.expected_revision,
            }),
            &options,
        ),
        Command::RevertPatch(args) => commands::patch_tool(
            &mut out,
            &args.file,
            "revert_patch",
            serde_json::json!({
                "at": args.at, "source_sha256": args.review.source_sha256,
                "expected_revision": args.review.expected_revision,
            }),
            &options,
        ),
        Command::ListPatches(args) => commands::patch_tool(
            &mut out,
            &args.file,
            "list_patches",
            serde_json::json!({
                "offset": args.offset, "limit": args.limit,
            }),
            &options,
        ),
        Command::ExportPatched(args) => commands::patch_tool(
            &mut out,
            &args.file,
            "export_patched",
            serde_json::json!({
                "destination": args.destination, "source_sha256": args.review.source_sha256,
                "expected_revision": args.review.expected_revision,
            }),
            &options,
        ),
        Command::Search(args) => commands::search(&mut out, &args, &options),
        Command::InspectSleigh(args) => commands::inspect_sleigh(&mut out, &args, &options),
        Command::AnnotationBatch(args) => commands::annotation_batch(&mut out, &args, &options),
        Command::Graph(args::GraphArgs { file, at, view, block_offset }) => {
            commands::graph(&mut out, &file, &at, view, block_offset, &options)
        }
        Command::Assemble(args) => commands::assemble(&mut out, &args, &options),
        Command::Signatures(SignaturesArgs { file, output, fuzzy_request }) => {
            commands::signatures(&mut out, &file, output.as_deref(), fuzzy_request.as_deref(), &options)
        }
        Command::Identify(IdentifyArgs { file, db, fuzzy_db, fuzzy_request, no_bundled, apply }) => commands::identify(
            &mut out,
            &file,
            db.as_deref(),
            (fuzzy_db.as_deref(), fuzzy_request.as_deref()),
            no_bundled,
            apply,
            &options,
        ),
        Command::JumpTable(JumpTableArgs { file, at, count, relative_base }) => {
            commands::jump_table(&mut out, &file, &at, count, relative_base.as_deref(), &options)
        }
        Command::InspectData(args::InspectDataArgs { file, at, size, word_size, view }) => {
            commands::inspect_data(&mut out, &file, &at, size, word_size, view, &options)
        }
        Command::InspectRaw(args::InspectRawArgs { file, request }) => {
            commands::inspect_raw(&mut out, &file, &request, &options)
        }
        Command::DecodeFile(args) => {
            args.request().and_then(|request| commands::decode_range(&mut out, &args.file, &request, &options))
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
        Command::RecordFinding(args) => commands::record_finding(&mut out, &args, &options),
        Command::ListFindings(args) => commands::list_findings(&mut out, &args, &options),
        Command::TransferAnnotations(args) => commands::transfer_annotations(&mut out, &args, &options),
        Command::DebugTypes(DebugTypesArgs { file, apply }) => commands::debug_types(&mut out, &file, apply, &options),
        Command::ImportPdbNames(args) => commands::import_pdb_names(&mut out, &args, &options),
        Command::TypeLayout(args) => commands::type_layout(&mut out, &args, &options),
        Command::ObjcSends(args) => commands::objc_sends(&mut out, &args, &options),
        Command::ImportDebugLayouts(args) => commands::import_debug_layouts(&mut out, &args, &options),
        Command::Report(ReportArgs {
            workflow,
            file,
            other,
            other_image_offset,
            other_image_length,
            limit,
            no_decompile,
            component,
            component_worker,
            prepare_analysis,
        }) => {
            let other_image =
                other_image_offset.map(|offset| rampage_loaders::ImageAt::new(offset, other_image_length));
            let report_options = report::ReportOptions {
                other,
                other_image,
                limit,
                no_decompile,
                component,
                component_worker,
                prepare_analysis,
            };
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
        Command::PyInstallerArchive(..) => "binary pyinstaller-archive",
        Command::WasmModule(..) => "binary wasm-module",
        Command::FileLayout(..) => "binary layout",
        Command::ProbeCompression(..) => "binary probe-compression",
        Command::DecodeFile(..) => "binary decode",
        Command::InspectRaw(..) => "binary inspect-raw",
        Command::Packs { .. } => "packs",
        Command::Mcp(..) => "mcp (pass image_offset to each tool call instead)",
        Command::QueryDebugger(..) => "runtime debugger query (does not open an image)",
        Command::Correlate(..) => "correlate",
        Command::CompareRuntime(..) => "compare-runtime",
        Command::ComparePointers(..) => "compare-pointers",
        _ => return None,
    })
}

/// The largest --raw-json or --raw-request input; a request with the full 8192 seeds is far smaller.
const MAX_RAW_REQUEST_BYTES: u64 = 1024 * 1024;

/// The commands [`raw_tool`] admits, as `--help` names them.
const RAW_COMMANDS: &str = "binary inspect, binary audit, binary capabilities, binary search, function list, \
                            function disassemble, function graph, function xrefs and function decompile";

fn raw_request(json: Option<&str>, path: Option<&std::path::Path>) -> anyhow::Result<Option<RawProjectRequest>> {
    let text = match (json, path) {
        (None, None) => return Ok(None),
        (Some(json), None) => {
            anyhow::ensure!(json.len() as u64 <= MAX_RAW_REQUEST_BYTES, "--raw-json exceeds 1 MiB");
            json.to_owned()
        }
        (None, Some(path)) => rampage_api::read_bounded(path, MAX_RAW_REQUEST_BYTES, "Raw Project request")?,
        (Some(_), Some(_)) => anyhow::bail!("--raw-json conflicts with --raw-request"),
    };
    let request =
        serde_json::from_str(&text).map_err(|error| anyhow::anyhow!("invalid Raw Project request: {error}"))?;
    Ok(Some(request))
}

/// The raw-capable project tool a command runs, for the commands that may open a Raw Project. Annotation commands
/// are left out: Raw annotations are memory-only, so a one-shot CLI process would discard edits and could only ever
/// list nothing (the MCP server keeps them for its session).
fn raw_tool(command: &Command) -> Option<&'static str> {
    let tool = match command {
        Command::Info(..) => "binary_info",
        Command::Funcs(..) => "list_functions",
        Command::Disasm(..) => "disassemble",
        Command::Graph(..) => "function_graph",
        Command::Xrefs(..) => "xrefs",
        Command::Search(..) => "search",
        Command::Audit(args) if args.entries => "entry_diagnostics",
        Command::Audit(..) => "analysis_diagnostics",
        Command::Capabilities(..) => "capabilities",
        Command::Decompile(..) => "decompile",
        _ => return None,
    };
    debug_assert!(rampage_api::tools::raw_capable(tool), "{tool} is not raw-capable");
    Some(tool)
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

/// The improve context and observation store `flywheel` asks for.
type Flywheel = (Option<Arc<rampage_api::flywheel::Improve>>, Option<Arc<rampage_api::flywheel::ObservationStore>>);

fn flywheel_context(flywheel: args::FlywheelArgs) -> Result<Flywheel, String> {
    use rampage_api::flywheel::{GateConfig, Improve, ImproveOptions, OBSERVATIONS_VARIABLE, ObservationStore};
    let improve = match &flywheel.corpus {
        Some(corpus) => {
            let gate = match &flywheel.gate {
                Some(path) => {
                    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
                    GateConfig::from_toml(&text).map_err(|error| error.to_string())?
                }
                None => GateConfig::default(),
            };
            let gate =
                GateConfig { require_novel_gain: flywheel.require_novel_gain.or(gate.require_novel_gain), ..gate };
            let options = ImproveOptions {
                corpus: corpus.clone(),
                flywheel_dir: flywheel.flywheel_dir.clone(),
                gate,
                workers: flywheel.flywheel_workers.max(1),
                run: flywheel.flywheel_run.clone(),
                baseline: flywheel
                    .flywheel_baseline
                    .parse()
                    .map_err(|error| format!("--flywheel-baseline: {error}"))?,
            };
            Some(Arc::new(Improve::open(options).map_err(|error| format!("--corpus: {error}"))?))
        }
        None => None,
    };
    // A corpus server serves the improve group alone, without report_observation.
    if improve.is_some() {
        return Ok((improve, None));
    }
    let directory = flywheel
        .observations
        .clone()
        .or_else(|| std::env::var_os(OBSERVATIONS_VARIABLE).filter(|value| !value.is_empty()).map(PathBuf::from));
    let store = directory.map(|directory| {
        // A store inside a flywheel directory never reads that directory's corpus or caches.
        let flywheel = directory.parent().filter(|parent| parent.join("corpus").is_dir()).map(Path::to_path_buf);
        Arc::new(ObservationStore::new(directory).refusing(flywheel.into_iter().collect()))
    });
    Ok((None, store))
}

fn serve_mcp(
    all_tools: bool,
    debug_endpoints: &[String],
    consent: (bool, bool),
    require_worker: bool,
    packs: Arc<Packs>,
    flywheel: args::FlywheelArgs,
) -> ExitCode {
    let (improve, observations) = match flywheel_context(flywheel) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("rampage: {error}");
            return ExitCode::FAILURE;
        }
    };
    let debug_env = std::env::var(rampage_mcp::DEBUG_ENDPOINTS_ENV).ok();
    let writes_env = std::env::var(rampage_mcp::DEBUG_WRITES_ENV).ok();
    let kill_env = std::env::var(rampage_mcp::DEBUG_KILL_ENV).ok();
    let consent = rampage_mcp::debug_consent(consent.0, consent.1, writes_env.as_deref(), kill_env.as_deref())
        .and_then(|consent| rampage_mcp::debug_registry_with(debug_endpoints, debug_env.as_deref(), consent));
    let debug = match consent {
        Ok(debug) => debug,
        Err(error) => {
            eprintln!("rampage: {error}");
            return ExitCode::FAILURE;
        }
    };
    let env = std::env::var(rampage_mcp::TOOLS_ENV).ok();
    let groups = match rampage_mcp::initial_groups_with(all_tools, env.as_deref(), debug.is_some(), improve.is_some()) {
        Ok(groups) => groups,
        Err(error) => {
            eprintln!("rampage: {}: {error}", rampage_mcp::TOOLS_ENV);
            return ExitCode::FAILURE;
        }
    };
    // A corpus server serves no analysis tool, so nothing it serves decompiles.
    let required_worker = if improve.is_some() {
        None
    } else {
        let expected = std::env::current_exe()
            .map(|path| path.with_file_name(if cfg!(windows) { "rampage-worker.exe" } else { "rampage-worker" }))
            .unwrap_or_else(|_| PathBuf::from("rampage-worker"));
        let startup =
            rampage_mcp::decompiler_worker_startup(require_worker, rampage_api::find_decompiler_worker(), expected);
        if let Some(warning) = startup.warning {
            eprintln!("{warning}");
        }
        startup.required
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rampage: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(rampage_mcp::serve_stdio_with(groups, packs, debug, improve, observations, required_worker))
    {
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
