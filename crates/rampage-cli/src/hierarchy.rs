use std::path::PathBuf;

use clap::{Arg, ArgMatches, Subcommand};

use crate::args::ArchiveInventoryArgs;
use crate::args::DecodeFileArgs;
use crate::args::ImportDebugLayoutsArgs;
use crate::args::InspectDataArgs;
use crate::args::InspectRawArgs;
use crate::args::{
    AnnotateBatchArgs, AtArgs, AuditArgs, CapaArgs, CarveArgs, CheckNamesArgs, CommentArgs, CompareArgs,
    ComparePointersArgs, CompareRuntimeArgs, CorrelateArgs, DebugTypesArgs, DecompileArgs, DetectArgs, DirectoryArgs,
    DisasmArgs, DotnetArgs, ExportsArgs, FileArgs, FuncsArgs, IdentifyArgs, ImportPdbNamesArgs, ImportsArgs,
    JumpTableArgs, McpArgs, ObserveIndirectBranchArgs, PseudocodeArgs, QueryDebuggerArgs, RenameArgs, ReportArgs,
    SignaturesArgs, StringsArgs, XrefsArgs, YaraArgs,
};
use crate::{Command, PacksCommand};

pub(crate) fn with_pack_arguments(command: clap::Command) -> clap::Command {
    let pack = command.get_arguments().find(|argument| argument.get_id() == "packs").unwrap().clone();
    command.mut_subcommands(|command| add_pack_argument(command, &pack))
}

fn add_pack_argument(command: clap::Command, pack: &Arg) -> clap::Command {
    command.arg(pack.clone()).mut_subcommands(|command| add_pack_argument(command, pack))
}

pub(crate) fn pack_paths(matches: &ArgMatches) -> Vec<PathBuf> {
    std::iter::successors(Some(matches), |matches| matches.subcommand().map(|(_, matches)| matches))
        .filter_map(|matches| matches.get_many::<PathBuf>("packs"))
        .flatten()
        .cloned()
        .collect()
}

#[derive(Subcommand)]
pub(crate) enum RootCommand {
    /// Inspect, analyze and scan binaries
    #[command(subcommand)]
    Binary(BinaryCommand),
    /// Discover, disassemble, decompile and compare functions
    #[command(subcommand)]
    Function(FunctionCommand),
    /// List strings
    #[command(subcommand)]
    String(StringCommand),
    /// Inspect language metadata
    #[command(subcommand)]
    Language(LanguageCommand),
    /// Inspect and disassemble managed assemblies
    #[command(subcommand)]
    Managed(ManagedCommand),
    /// List and edit user annotations
    #[command(subcommand)]
    Annotation(AnnotationCommand),
    /// Import debug types and explicit PDB function names
    #[command(subcommand)]
    Type(TypeCommand),
    /// Inspect captured runtime state
    #[command(subcommand)]
    Runtime(RuntimeCommand),
    /// List or validate data packs
    #[command(subcommand)]
    Pack(PacksCommand),
    /// Run registered investigation workflows
    #[command(subcommand)]
    Workflow(WorkflowCommand),
    /// Serve AI agents over the Model Context Protocol
    #[command(subcommand)]
    Server(ServerCommand),
    #[command(flatten)]
    Legacy(Command),
}

impl RootCommand {
    pub(crate) fn into_action(self) -> Result<Command, &'static str> {
        Ok(match self {
            Self::Binary(BinaryCommand::InspectSleigh(args)) => Command::InspectSleigh(args),
            Self::Binary(BinaryCommand::PatchBytes(args)) => Command::PatchBytes(args),
            Self::Binary(BinaryCommand::RevertPatch(args)) => Command::RevertPatch(args),
            Self::Binary(BinaryCommand::ListPatches(args)) => Command::ListPatches(args),
            Self::Binary(BinaryCommand::ExportPatched(args)) => Command::ExportPatched(args),
            Self::Binary(BinaryCommand::Assemble(args)) => Command::Assemble(args),
            Self::Binary(BinaryCommand::Search(args)) => Command::Search(args),
            Self::Binary(BinaryCommand::Inspect(args)) => Command::Info(args),
            Self::Binary(BinaryCommand::InspectData(args)) => Command::InspectData(args),
            Self::Binary(BinaryCommand::InspectRaw(args)) => Command::InspectRaw(args),
            Self::Binary(BinaryCommand::Decode(args)) => Command::DecodeFile(args),
            Self::Binary(BinaryCommand::Triage(args)) => Command::Triage(args),
            Self::Binary(BinaryCommand::PeResources(args)) => Command::PeResources(args),
            Self::Binary(BinaryCommand::PeLoadConfig(args)) => Command::PeLoadConfig(args),
            Self::Binary(BinaryCommand::Analyze(args)) => Command::Analyze(args),
            Self::Binary(BinaryCommand::Detect(args)) => Command::Detect(args),
            Self::Binary(BinaryCommand::Capabilities(args)) => Command::Capabilities(args),
            Self::Binary(BinaryCommand::Audit(args)) => Command::Audit(args),
            Self::Binary(BinaryCommand::Carve(args)) => Command::Carve(args),
            Self::Binary(BinaryCommand::Inventory(args)) => Command::Inventory(args),
            Self::Binary(BinaryCommand::ArchiveInventory(args)) => Command::ArchiveInventory(args),
            Self::Binary(BinaryCommand::ListImports(args)) => Command::Imports(args),
            Self::Binary(BinaryCommand::ListExports(args)) => Command::Exports(args),
            Self::Binary(BinaryCommand::ScanYara(args)) => Command::Yara(args),
            Self::Binary(BinaryCommand::ScanCapa(args)) => Command::Capa(args),
            Self::Function(FunctionCommand::List(args)) => Command::Funcs(args),
            Self::Function(FunctionCommand::Disassemble(args)) => Command::Disasm(args),
            Self::Function(FunctionCommand::Decompile(args)) => Command::Decompile(args),
            Self::Function(FunctionCommand::Summarize(args)) => Command::Summarize(args),
            Self::Function(FunctionCommand::Graph(args)) => Command::Graph(args),
            Self::Function(FunctionCommand::Batch(args)) => Command::AnnotationBatch(args),
            Self::Function(FunctionCommand::Pseudocode(args)) => Command::Pseudocode(args),
            Self::Function(FunctionCommand::Xrefs(args)) => Command::Xrefs(args),
            Self::Function(FunctionCommand::Identify(args)) => Command::Identify(args),
            Self::Function(FunctionCommand::BuildSignatures(args)) => Command::Signatures(args),
            Self::Function(FunctionCommand::Compare(args)) => Command::Compare(args),
            Self::Function(FunctionCommand::InspectTable(args)) => Command::JumpTable(args),
            Self::String(StringCommand::List(args)) => Command::Strings(args),
            Self::Language(LanguageCommand::Inspect(args)) => Command::Metadata(args),
            Self::Annotation(AnnotationCommand::List(args)) => Command::Annotations(args),
            Self::Annotation(AnnotationCommand::Rename(args)) => Command::Rename(args),
            Self::Annotation(AnnotationCommand::Comment(args)) => Command::Comment(args),
            Self::Annotation(AnnotationCommand::ApplyBatch(args)) => Command::AnnotateBatch(args),
            Self::Annotation(AnnotationCommand::CheckNames(args)) => Command::CheckNames(args),
            Self::Type(TypeCommand::Debug(args)) => Command::DebugTypes(args),
            Self::Type(TypeCommand::DebugLayouts(args)) => Command::ImportDebugLayouts(args),
            Self::Type(TypeCommand::PdbNames(args)) => Command::ImportPdbNames(args),
            Self::Runtime(RuntimeCommand::Pointer(PointerCommand::Observe(args))) => Command::ObservePointer(args),
            Self::Runtime(RuntimeCommand::Pointer(PointerCommand::Compare(args))) => Command::ComparePointers(args),
            Self::Runtime(RuntimeCommand::Branch(BranchCommand::Inspect(args))) => Command::ObserveIndirectBranch(args),
            Self::Runtime(RuntimeCommand::Bytes(BytesCommand::Compare(args))) => Command::CompareRuntime(args),
            Self::Runtime(RuntimeCommand::Module(ModuleCommand::Correlate(args))) => Command::Correlate(args),
            Self::Runtime(RuntimeCommand::Debugger(DebuggerCommand::Query(args))) => Command::QueryDebugger(args),
            Self::Pack(action) => Command::Packs { action },
            Self::Workflow(WorkflowCommand::Run(args)) => Command::Report(args),
            Self::Server(ServerCommand::Serve(args)) => Command::Mcp(args),
            Self::Managed(ManagedCommand::Inspect(args)) => {
                if args.il.is_some() {
                    return Err(
                        "managed inspect does not accept --il; use managed disassemble --il for CIL disassembly",
                    );
                }
                Command::Dotnet(args)
            }
            Self::Managed(ManagedCommand::Disassemble(args)) => {
                if args.il.is_none() {
                    return Err("managed disassemble requires --il <METHOD>");
                }
                Command::Dotnet(args)
            }
            Self::Legacy(action) => action,
        })
    }
}

#[derive(Subcommand)]
pub(crate) enum BinaryCommand {
    /// Inspect raw byte windows with 20 closed Sleigh IDs, preserving unresolved flow gates
    #[command(long_about = crate::args::INSPECT_SLEIGH_ABOUT)]
    InspectSleigh(crate::args::InspectSleighArgs),
    /// Persist an explicitly reviewed equal-length original-byte patch; never modify or execute the source
    PatchBytes(crate::args::PatchBytesArgs),
    /// Remove one exact-start reviewed byte patch through annotation history
    RevertPatch(crate::args::RevertPatchArgs),
    /// Page active patches and obtain source/effective/revision hash receipts
    ListPatches(crate::args::ListPatchesArgs),
    /// Export reviewed effective bytes to a new file only, without execution or annotations
    ExportPatched(crate::args::ExportPatchedArgs),
    /// Assemble literal source into a read-only proposal, without executing or applying bytes
    Assemble(crate::args::AssembleArgs),
    /// Search retained bytes, text, instructions, immediates or references using a typed JSON request
    Search(crate::args::SearchArgs),
    /// Show format, architecture, entry point, segments and sections
    Inspect(crate::args::ViewedFileArgs),
    /// Inspect bounded image bytes and pointer candidates without discovery or annotation sidecars
    InspectData(InspectDataArgs),
    /// Inspect an explicitly mapped raw-code window using a JSON request; no native header is required
    InspectRaw(InspectRawArgs),
    /// Decode an explicitly selected file range into transient bytes; no extraction or native loading
    Decode(DecodeFileArgs),
    /// Hashes, entropy, format details, overlay and hints of packing or weak hardening
    Triage(FileArgs),
    /// PE resource leaves (type, name, language, location), with RT_VERSION and RT_MANIFEST decoded
    PeResources(crate::args::PeResourcesArgs),
    /// PE load config: security cookie, SafeSEH, CFG tables, CET and DllCharacteristics cross-checks
    PeLoadConfig(FileArgs),
    /// Run bounded workflows and selected decompilations as one multi-architecture analysis report
    Analyze(crate::analyze::AnalyzeArgs),
    /// Identify the producing tools (packer/compiler/protector/installer/linker/runtime) from heuristic signatures
    Detect(DetectArgs),
    /// Likely behaviors inferred from imports and strings (triage evidence, not proof)
    Capabilities(FileArgs),
    /// Decode coverage and evidence that static disassembly may be unreliable
    Audit(AuditArgs),
    /// Scan any file for embedded executables and containers by validated header, without extracting anything
    Carve(CarveArgs),
    /// Inventory binaries in a bundle or already-extracted package without executing it
    Inventory(DirectoryArgs),
    /// Inventory standalone single-disk ZIP32 metadata, without opening, extracting or probing members
    ArchiveInventory(ArchiveInventoryArgs),
    /// List imported functions with their libraries and import slots
    ListImports(ImportsArgs),
    /// List exported symbols
    ListExports(ExportsArgs),
    /// Scan with user-supplied YARA rules (a .yar/.yara file or a directory of them) and those of data packs
    ScanYara(YaraArgs),
    /// Detect behaviors with a directory of Mandiant capa rules and those of data packs (file-scope feature subset)
    ScanCapa(CapaArgs),
}

#[derive(Subcommand)]
pub(crate) enum FunctionCommand {
    /// Atomically apply checked rename/comment/signature/types/global operations from explicit JSON
    Batch(crate::args::AnnotationBatchArgs),
    /// Native control-flow graph with complete instructions or an explicit summary projection
    Graph(crate::args::ViewedAtArgs),
    /// Discover functions by recursive descent from symbols, exports, the entry point and unwind metadata
    List(FuncsArgs),
    /// Disassemble instructions
    Disassemble(DisasmArgs),
    /// Decompile a function to C with bundled Ghidra specifications
    Decompile(DecompileArgs),
    /// Structural CFG and reference summary of a function (not decompiled source)
    Summarize(crate::args::ViewedAtArgs),
    /// Partial ARM64 SSA pseudocode with explicit unknowns (not recovered C source)
    Pseudocode(PseudocodeArgs),
    /// List code and data cross-references to or from an address, symbol or function
    Xrefs(XrefsArgs),
    /// Name functions by matching a signature database (FLIRT/Function-ID style); functions whose bodies collide
    /// are told apart by the names of the functions they call
    Identify(IdentifyArgs),
    /// Build a library-function signature database from a binary whose functions are named, hashing each over its
    /// symbol size and its discovered extent, with callee keys for functions whose bodies collide
    BuildSignatures(SignaturesArgs),
    /// Compare function starts with a versioned, image-hash-matched reference export
    Compare(CompareArgs),
    /// Inspect an explicit ARM64 absolute64 or signed-relative32 jump table
    InspectTable(JumpTableArgs),
}

#[derive(Subcommand)]
pub(crate) enum StringCommand {
    /// List printable ASCII and UTF-16LE strings
    List(StringsArgs),
}

#[derive(Subcommand)]
pub(crate) enum LanguageCommand {
    /// Demangled symbols, named vtables/RTTI and Objective-C selector strings
    Inspect(FileArgs),
}

#[derive(Subcommand)]
pub(crate) enum AnnotationCommand {
    /// List the user's names and comments
    List(FileArgs),
    /// Name an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    Rename(RenameArgs),
    /// Comment an address; saved beside ordinary binaries, or in a capture-identity log for snapshots
    Comment(CommentArgs),
    /// Apply a JSON array of {at, name?, comment?} as one atomic annotation batch; nothing is applied if any entry
    /// is invalid
    ApplyBatch(AnnotateBatchArgs),
    /// Report whether candidate names are valid identifiers, address-shaped, or already used
    CheckNames(CheckNamesArgs),
}

#[derive(Subcommand)]
pub(crate) enum TypeCommand {
    /// Preview embedded DWARF scalar/pointer function signatures, optionally persist them
    #[command(name = "import-debug")]
    Debug(DebugTypesArgs),
    /// Review checked embedded DWARF layouts/signatures; apply only with --apply --review-sha256 from a fresh preview
    #[command(name = "import-debug-layouts")]
    DebugLayouts(ImportDebugLayoutsArgs),
    /// Preview names from an explicit identity-matched PDB, or apply all eligible names as one atomic annotation batch
    #[command(name = "import-pdb-names")]
    PdbNames(ImportPdbNamesArgs),
}

#[derive(Subcommand)]
pub(crate) enum RuntimeCommand {
    /// Query an explicitly supplied operator-started stopped debugger session (read-only)
    #[command(subcommand)]
    Debugger(DebuggerCommand),
    /// Compare explicit pointer slots in runtime captures
    #[command(subcommand)]
    Pointer(PointerCommand),
    /// Inspect captured indirect branches
    #[command(subcommand)]
    Branch(BranchCommand),
    /// Compare captured runtime bytes
    #[command(subcommand)]
    Bytes(BytesCommand),
    /// Correlate captured modules with an original image
    #[command(subcommand)]
    Module(ModuleCommand),
}

#[derive(Subcommand)]
pub(crate) enum DebuggerCommand {
    /// Send one typed read-only JSON request to a local LLDB socket; never attach or open an image
    Query(QueryDebuggerArgs),
}

#[derive(Subcommand)]
pub(crate) enum PointerCommand {
    /// Observe one captured pointer without changing discovery or treating mutable data as proven flow
    Observe(AtArgs),
    /// Compare explicit slots in two captures without asserting chronology, correspondence or flow
    Compare(ComparePointersArgs),
}

#[derive(Subcommand)]
pub(crate) enum BranchCommand {
    /// Link one captured ARM64 indirect branch to a slot load in an explicit bounded window
    Inspect(ObserveIndirectBranchArgs),
}

#[derive(Subcommand)]
pub(crate) enum BytesCommand {
    /// Compare explicit captured ranges to a UUID-matched original without transferring annotations
    Compare(CompareRuntimeArgs),
}

#[derive(Subcommand)]
pub(crate) enum ModuleCommand {
    /// Correlate a runtime snapshot address with an explicit UUID-matched original Mach-O
    Correlate(CorrelateArgs),
}

#[derive(Subcommand)]
pub(crate) enum WorkflowCommand {
    /// Run a guided investigation workflow and print its bounded, evidence-backed report
    Run(ReportArgs),
}

#[derive(Subcommand)]
pub(crate) enum ManagedCommand {
    /// .NET metadata: identity, references, entry point, signatures, P/Invoke, attributes and resource links
    Inspect(DotnetArgs),
    /// Disassemble one method's CIL instructions
    Disassemble(DotnetArgs),
}

#[derive(Subcommand)]
pub(crate) enum ServerCommand {
    /// Serve the Model Context Protocol over stdin/stdout for AI agents. Lists the core tools and enable_tools,
    /// which adds the other groups; RAMPAGE_MCP_TOOLS=all or a comma-separated list of groups serves more at once
    Serve(McpArgs),
}
