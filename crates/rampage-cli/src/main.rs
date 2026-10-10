mod commands;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rampage", version, about = "High-performance reverse engineering toolkit")]
struct Cli {
    /// Emit JSON instead of text
    #[arg(long, global = true)]
    json: bool,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = BufWriter::new(io::stdout().lock());
    let result = match cli.command {
        Command::Info { file } => commands::info(&mut out, &file, cli.json),
        Command::Disasm { file, at, count } => commands::disasm(&mut out, &file, at.as_deref(), count, cli.json),
        Command::Strings { file, min_len } => commands::strings(&mut out, &file, min_len, cli.json),
        Command::Funcs { file } => commands::funcs(&mut out, &file, cli.json),
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
