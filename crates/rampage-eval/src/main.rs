use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rampage_eval::Truth;
use rampage_loaders::{Binary, SymbolKind};
use rampage_signatures::SignatureDb;

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
    /// Identify a stripped target's functions and score them against its truth. Prints the report as JSON and
    /// a one-line summary on stderr; exits 1 when any name is wrong or spurious.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// A signature database (JSON) to identify with; repeatable, later ones win on a shared hash.
    #[arg(long = "db")]
    databases: Vec<PathBuf>,
    /// A symbolized reference binary to build signatures from; repeatable.
    #[arg(long = "ref")]
    references: Vec<PathBuf>,
    #[arg(long)]
    target: PathBuf,
    #[arg(long)]
    truth: PathBuf,
    /// The slice name in the summary; defaults to the target's architecture.
    #[arg(long)]
    slice: Option<String>,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Truth { symbolized, stripped } => truth(&symbolized, stripped.as_deref()),
        Command::Strip { input, output, keep_symbols } => strip(&input, &output, keep_symbols),
        Command::Run(args) => run(&args),
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

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn database(args: &RunArgs) -> Result<SignatureDb, String> {
    let mut combined: Option<SignatureDb> = None;
    for path in &args.references {
        let binary = open(path)?;
        match &mut combined {
            Some(db) => db.extend_from_binary(&binary),
            None => combined = Some(SignatureDb::from_binary(&binary)),
        }
    }
    for path in &args.databases {
        let db = SignatureDb::from_json(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))?;
        match &mut combined {
            Some(existing) => existing.merge(&db),
            None => combined = Some(db),
        }
    }
    combined.ok_or_else(|| "give at least one --db or --ref".to_owned())
}

fn run(args: &RunArgs) -> Result<ExitCode, String> {
    let db = database(args)?;
    let target = open(&args.target)?;
    let arch = target.arch.to_string();
    // A database for another architecture matches nothing, which would read as a clean (if useless) pass.
    if db.arch != arch {
        return Err(format!("database architecture {:?} does not match target architecture {arch:?}", db.arch));
    }
    let truth = Truth::from_json(&read(&args.truth)?).map_err(|error| format!("{}: {error}", args.truth.display()))?;
    let report =
        rampage_eval::evaluate(&db, &target, &truth).map_err(|_| format!("unsupported architecture {arch}"))?;
    println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
    eprintln!("{}: {}", args.slice.as_deref().unwrap_or(&arch), report.summary());
    Ok(if report.passes_gate() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
