use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rampage_eval::{Evaluation, Report, Truth};
use rampage_loaders::{Binary, SymbolKind};
use rampage_signatures::SignatureDb;
use serde::Deserialize;

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
    /// Identify stripped targets' functions and score them against their truth, per slice. Prints
    /// {"slices": {"<name>": report}} as JSON and a one-line summary per slice on stderr; exits 1 when any
    /// slice has a wrong or spurious name.
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
    #[arg(long, conflicts_with = "manifest")]
    target: Option<PathBuf>,
    #[arg(long, conflicts_with = "manifest")]
    truth: Option<PathBuf>,
    /// The slice name; defaults to the target's architecture.
    #[arg(long, conflicts_with = "manifest")]
    slice: Option<String>,
    /// Evaluate every slice of a manifest instead: {"slices": {"<name>": {"refs": [..], "dbs": [..],
    /// "target": "..", "truth": ".."}}}, paths relative to the manifest.
    #[arg(long, conflicts_with_all = ["databases", "references"])]
    manifest: Option<PathBuf>,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Truth { symbolized, stripped } => truth(&symbolized, stripped.as_deref()),
        Command::Strip { input, output, keep_symbols } => strip(&input, &output, keep_symbols),
        Command::Run(args) => run(args),
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

/// One slice to evaluate. In a manifest, relative paths resolve against the manifest's directory.
#[derive(Deserialize)]
struct Slice {
    #[serde(default)]
    refs: Vec<PathBuf>,
    #[serde(default)]
    dbs: Vec<PathBuf>,
    target: PathBuf,
    truth: PathBuf,
}

#[derive(Deserialize)]
struct Manifest {
    slices: BTreeMap<String, Slice>,
}

impl Slice {
    fn database(&self) -> Result<SignatureDb, String> {
        let mut combined: Option<SignatureDb> = None;
        for path in &self.refs {
            let binary = open(path)?;
            match &mut combined {
                Some(db) => db.extend_from_binary(&binary),
                None => combined = Some(SignatureDb::from_binary(&binary)),
            }
        }
        for path in &self.dbs {
            let db = SignatureDb::from_json(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))?;
            match &mut combined {
                Some(existing) => existing.merge(&db),
                None => combined = Some(db),
            }
        }
        combined.ok_or_else(|| format!("{}: give at least one --db or --ref", self.target.display()))
    }

    /// The slice's report, and its target's architecture (the default slice name).
    fn evaluate(&self) -> Result<(Report, String), String> {
        let db = self.database()?;
        let target = open(&self.target)?;
        let arch = target.arch.to_string();
        // A database for another architecture matches nothing, which would read as a clean (if useless) pass.
        if db.arch != arch {
            let target = self.target.display();
            return Err(format!("{target}: database architecture {:?} is not the target's {arch:?}", db.arch));
        }
        let truth =
            Truth::from_json(&read(&self.truth)?).map_err(|error| format!("{}: {error}", self.truth.display()))?;
        let report =
            rampage_eval::evaluate(&db, &target, &truth).map_err(|_| format!("unsupported architecture {arch}"))?;
        Ok((report, arch))
    }
}

fn manifest(path: &Path) -> Result<Vec<(Option<String>, Slice)>, String> {
    let manifest: Manifest =
        serde_json::from_str(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    let resolve = |paths: Vec<PathBuf>| paths.into_iter().map(|path| base.join(path)).collect();
    Ok(manifest
        .slices
        .into_iter()
        .map(|(name, slice)| {
            let slice = Slice {
                refs: resolve(slice.refs),
                dbs: resolve(slice.dbs),
                target: base.join(slice.target),
                truth: base.join(slice.truth),
            };
            (Some(name), slice)
        })
        .collect())
}

fn run(args: RunArgs) -> Result<ExitCode, String> {
    let slices = match args.manifest {
        Some(path) => manifest(&path)?,
        None => {
            let (Some(target), Some(truth)) = (args.target, args.truth) else {
                return Err("give --manifest, or --target and --truth".to_owned());
            };
            vec![(args.slice, Slice { refs: args.references, dbs: args.databases, target, truth })]
        }
    };
    let mut evaluation = Evaluation::default();
    for (name, slice) in slices {
        let (report, arch) = slice.evaluate()?;
        let name = name.unwrap_or(arch);
        eprintln!("{name}: {}", report.summary());
        evaluation.slices.insert(name, report);
    }
    println!("{}", serde_json::to_string_pretty(&evaluation).map_err(|error| error.to_string())?);
    Ok(if evaluation.passes_gate() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
