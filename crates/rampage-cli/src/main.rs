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
        #[arg(long, default_value_t = 32)]
        count: usize,
    },
    /// List printable ASCII and UTF-16LE strings
    Strings {
        file: PathBuf,
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
    /// Name an address; the name is saved beside the binary in <file>.rampage
    Rename {
        file: PathBuf,
        /// Address or current name
        at: String,
        /// The new name (omit with --clear)
        name: Option<String>,
        /// Remove the user's name instead
        #[arg(long)]
        clear: bool,
    },
    /// Comment an address; saved beside the binary in <file>.rampage
    Comment {
        file: PathBuf,
        /// Address or name
        at: String,
        /// The comment (omit with --clear)
        text: Option<String>,
        /// Remove the comment instead
        #[arg(long)]
        clear: bool,
    },
    /// List the user's names and comments
    Annotations { file: PathBuf },
    /// Serve the Model Context Protocol over stdin/stdout for AI agents
    Mcp,
    /// List code and data cross-references to or from an address, symbol or function
    #[command(group(clap::ArgGroup::new("direction").required(true)))]
    Xrefs {
        file: PathBuf,
        #[arg(long, group = "direction")]
        to: Option<String>,
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
        Command::Imports { file, contains } => {
            commands::imports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Exports { file, contains } => {
            commands::exports(&mut out, &file, &ListQuery { contains, ..ListQuery::default() }, &options)
        }
        Command::Rename { file, at, name, clear } => commands::rename(&file, &at, name.as_deref(), clear, &options),
        Command::Comment { file, at, text, clear } => commands::comment(&file, &at, text.as_deref(), clear, &options),
        Command::Annotations { file } => commands::annotations(&mut out, &file, &options),
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
