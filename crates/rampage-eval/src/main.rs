use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rampage_eval::Truth;
use rampage_loaders::{Binary, SymbolKind};

/// Self-supervised evaluation of rampage heuristics against strip-and-compare ground truth.
#[derive(Parser)]
#[command(name = "rampage-eval")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the ground truth ({"0x<address>": "<name>"}) taken from a symbolized binary's function symbols.
    Truth {
        symbolized: PathBuf,
        /// The stripped twin; every truth function's bytes must be identical in it, proving the same layout.
        #[arg(long)]
        stripped: Option<PathBuf>,
    },
    /// Write a copy of an ELF without debug sections and symbols, every loaded byte left at its address.
    Strip {
        input: PathBuf,
        output: PathBuf,
        /// Remove only the debug sections, keeping the symbol table (for a small symbolized reference).
        #[arg(long)]
        keep_symbols: bool,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Truth { symbolized, stripped } => truth(&symbolized, stripped.as_deref()),
        Command::Strip { input, output, keep_symbols } => strip(&input, &output, keep_symbols),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("rampage-eval: {message}");
            ExitCode::from(2)
        }
    }
}

fn open(path: &Path) -> Result<Binary, String> {
    Binary::open(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn truth(symbolized: &Path, stripped: Option<&Path>) -> Result<ExitCode, String> {
    let binary = open(symbolized)?;
    if let Some(stripped) = stripped {
        let twin = open(stripped)?;
        let functions = binary.symbols.iter().filter(|symbol| symbol.kind == SymbolKind::Function && symbol.size > 0);
        for symbol in functions {
            let ours = binary.read(symbol.address, symbol.size);
            if ours.is_none() || ours != twin.read(symbol.address, symbol.size) {
                return Err(format!(
                    "{} is not a twin of {}: {} at {:#x} differs",
                    stripped.display(),
                    symbolized.display(),
                    symbol.name,
                    symbol.address
                ));
            }
        }
    }
    print!("{}", Truth::from_binary(&binary).to_json());
    Ok(ExitCode::SUCCESS)
}

fn strip(input: &Path, output: &Path, keep_symbols: bool) -> Result<ExitCode, String> {
    let bytes = std::fs::read(input).map_err(|error| format!("{}: {error}", input.display()))?;
    let stripped =
        rampage_eval::strip(&bytes, keep_symbols).map_err(|error| format!("{}: {error}", input.display()))?;
    let written = |error: std::io::Error| format!("{}: {error}", output.display());
    std::fs::write(output, stripped).map_err(written)?;
    let permissions = std::fs::metadata(input).map_err(written)?.permissions();
    std::fs::set_permissions(output, permissions).map_err(written)?;
    Ok(ExitCode::SUCCESS)
}
