mod commands;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use rampage_arch::Arch;

use crate::commands::Options;

#[derive(Parser)]
#[command(name = "rampage", version, about = "High-performance reverse engineering toolkit")]
struct Cli {
    /// Emit JSON instead of text
    #[arg(long, global = true)]
    json: bool,
    /// Architecture slice to load from a universal binary
    #[arg(long, global = true, value_enum)]
    arch: Option<ArchArg>,
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
    },
    /// List functions known from symbols, exports and the entry point
    Funcs { file: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum ArchArg {
    X86,
    #[value(name = "x86_64", alias = "x64", alias = "amd64")]
    X86_64,
    #[value(alias = "arm64")]
    Aarch64,
}

impl From<ArchArg> for Arch {
    fn from(arch: ArchArg) -> Self {
        match arch {
            ArchArg::X86 => Arch::X86,
            ArchArg::X86_64 => Arch::X86_64,
            ArchArg::Aarch64 => Arch::Aarch64,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let options = Options { json: cli.json, arch: cli.arch.map(Arch::from) };
    let mut out = BufWriter::new(io::stdout().lock());
    let result = match cli.command {
        Command::Info { file } => commands::info(&mut out, &file, &options),
        Command::Disasm { file, at, count } => commands::disasm(&mut out, &file, at.as_deref(), count, &options),
        Command::Strings { file, min_len } => commands::strings(&mut out, &file, min_len, &options),
        Command::Funcs { file } => commands::funcs(&mut out, &file, &options),
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

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
}
