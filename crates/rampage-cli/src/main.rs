mod commands;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rampage_api::{FunctionsQuery, ListQuery, StringsQuery};
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
    #[command(subcommand)]
    command: Command,
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
    /// Build a library-function signature database from a binary whose functions are named
    Signatures {
        file: PathBuf,
        /// Write the database here (JSON); defaults to standard output
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Name functions by matching a signature database (FLIRT/Function-ID style)
    Identify {
        file: PathBuf,
        /// A signature database to apply, overlaid on the bundled starter database unless --no-bundled is set
        #[arg(long)]
        db: Option<PathBuf>,
        /// Do not apply the bundled starter database (requires --db)
        #[arg(long)]
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
    /// List the user's names and comments
    Annotations { file: PathBuf },
    /// Preview embedded DWARF scalar/pointer function signatures, optionally persist them
    DebugTypes {
        file: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Serve the Model Context Protocol over stdin/stdout for AI agents
    Mcp,
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
}

fn parse_arch(text: &str) -> Result<Arch, String> {
    text.parse()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Mcp = cli.command {
        return serve_mcp();
    }
    let options = Options { json: cli.json, arch: cli.arch };
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
        Command::Triage { file } => commands::triage(&mut out, &file, &options),
        Command::Capabilities { file } => commands::capabilities(&mut out, &file, &options),
        Command::Audit { file, include_discovery } => commands::audit(&mut out, &file, include_discovery, &options),
        Command::Metadata { file } => commands::metadata(&mut out, &file, &options),
        Command::Inventory { directory } => commands::inventory(&mut out, &directory, &options),
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
        Command::Annotations { file } => commands::annotations(&mut out, &file, &options),
        Command::DebugTypes { file, apply } => commands::debug_types(&mut out, &file, apply, &options),
        Command::Mcp => unreachable!("handled before opening stdout"),
    }
    .and_then(|()| out.flush().map_err(Into::into));

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rampage: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn serve_mcp() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rampage: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(rampage_mcp::serve_stdio()) {
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
