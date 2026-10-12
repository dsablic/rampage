use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use rampage_eval::{Evaluation, Gate, Report, Truth};
use rampage_loaders::Binary;
use rampage_signatures::{SignatureDb, named_functions};
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
        /// Keep only functions whose name this symbolized reference also has (repeatable): the library code a
        /// signature database built from the references could name, excluding the program's own functions.
        #[arg(long)]
        library: Vec<PathBuf>,
        /// Drop functions this object defines (repeatable): the target's and the references' own program code,
        /// which shares names such as `main` with the references but is never library code.
        #[arg(long, requires = "library")]
        program: Vec<PathBuf>,
    },
    /// Write a copy of an ELF without debug sections and symbols, every loaded byte left at its address.
    Strip {
        input: PathBuf,
        output: PathBuf,
        /// Remove only the debug sections, keeping the symbol table (for a small symbolized reference).
        #[arg(long)]
        keep_symbols: bool,
    },
    /// Score a heuristic family on stripped targets against their truth, per slice. Prints
    /// {"slices": {"<name>": report}, "gates": {..}} as JSON and a one-line summary per slice on stderr; exits 1
    /// when any slice fails its gate (any wrong answer; for libid any spurious name; recall below --min-recall).
    Run(RunArgs),
}

/// The heuristic family a slice evaluates.
#[derive(Clone, Copy, Default, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Family {
    /// Library-function identification: names proposed by a signature database.
    #[default]
    Libid,
    /// Function-start discovery: starts found by the analysis, no database.
    Discovery,
}

impl Family {
    fn tag(self) -> &'static str {
        match self {
            Family::Libid => "libid",
            Family::Discovery => "discovery",
        }
    }

    /// Discovery tolerates spurious starts: code without a sized symbol is still code.
    fn gate(self, min_recall: f64) -> Gate {
        Gate { allow_spurious: matches!(self, Family::Discovery), min_recall }
    }
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
    /// The slice name; defaults to <family>-<target architecture>.
    #[arg(long, conflicts_with = "manifest")]
    slice: Option<String>,
    #[arg(long, value_enum, default_value_t = Family::Libid, conflicts_with = "manifest")]
    family: Family,
    /// The recall baseline; a lower measured recall fails the gate.
    #[arg(long, default_value_t = 0.0, conflicts_with = "manifest")]
    min_recall: f64,
    /// Evaluate every slice of a manifest instead: {"slices": {"<name>": {"family": "libid"|"discovery",
    /// "refs": [..], "dbs": [..], "target": "..", "truth": "..", "min_recall": 0.0}}}, paths relative to the
    /// manifest; refs and dbs apply to libid only.
    #[arg(long, conflicts_with_all = ["databases", "references"])]
    manifest: Option<PathBuf>,
    /// Keep at most this many disagreements per slice in the JSON (the counts still cover all of them).
    #[arg(long, default_value_t = 200)]
    max_disagreements: usize,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Truth { symbolized, stripped, library, program } => {
            truth(&symbolized, stripped.as_deref(), &library, &program)
        }
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

fn truth(
    symbolized: &Path,
    stripped: Option<&Path>,
    library: &[PathBuf],
    program: &[PathBuf],
) -> Result<ExitCode, String> {
    let binary = open(symbolized)?;
    if let Some(stripped) = stripped {
        let twin = open(stripped)?;
        for symbol in named_functions(&binary) {
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
    let mut truth = Truth::from_binary(&binary);
    if !library.is_empty() {
        let names = |paths: &[PathBuf]| -> Result<BTreeSet<String>, String> {
            let mut all = BTreeSet::new();
            for path in paths {
                all.extend(rampage_eval::function_names(&open(path)?));
            }
            Ok(all)
        };
        truth = truth.identifiable(&names(library)?, &names(program)?);
    }
    print!("{}", truth.to_json());
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
    family: Family,
    #[serde(default)]
    min_recall: f64,
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
                // extend_from_binary() ignores another architecture; an eval must not drop an input silently.
                Some(db) if db.arch() != binary.arch => {
                    return Err(format!(
                        "{}: a {} reference cannot be combined with a {} database",
                        path.display(),
                        binary.arch,
                        db.arch()
                    ));
                }
                Some(db) => db.extend_from_binary(&binary),
                None => combined = Some(SignatureDb::from_binary(&binary)),
            }
        }
        for path in &self.dbs {
            let db = SignatureDb::from_json(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))?;
            match &mut combined {
                // merge() ignores an incompatible database; an eval must not drop an input silently.
                Some(existing) if !existing.can_merge(&db) => {
                    return Err(format!(
                        "{}: a {} scheme-{} database cannot be combined with a {} scheme-{} one",
                        path.display(),
                        db.arch(),
                        db.scheme(),
                        existing.arch(),
                        existing.scheme()
                    ));
                }
                Some(existing) => existing.merge(&db),
                None => combined = Some(db),
            }
        }
        combined.ok_or_else(|| format!("{}: give at least one --db or --ref", self.target.display()))
    }

    /// The slice's report, and its target's architecture (part of the default slice name).
    fn evaluate(&self) -> Result<(Report, String), String> {
        let target = open(&self.target)?;
        let arch = target.arch;
        let truth =
            Truth::from_json(&read(&self.truth)?).map_err(|error| format!("{}: {error}", self.truth.display()))?;
        let unsupported = |_| format!("unsupported architecture {arch}");
        let report = match self.family {
            Family::Libid => {
                let db = self.database()?;
                // A database for another architecture matches nothing, which would read as a clean (if useless)
                // pass.
                if db.arch() != arch {
                    let target = self.target.display();
                    return Err(format!("{target}: database architecture {} is not the target's {arch}", db.arch()));
                }
                rampage_eval::evaluate(&db, &target, &truth).map_err(unsupported)?
            }
            Family::Discovery => rampage_eval::evaluate_discovery(&target, &truth).map_err(unsupported)?,
        };
        Ok((report, arch.to_string()))
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
                family: slice.family,
                min_recall: slice.min_recall,
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
            let slice = Slice {
                family: args.family,
                min_recall: args.min_recall,
                refs: args.references,
                dbs: args.databases,
                target,
                truth,
            };
            vec![(args.slice, slice)]
        }
    };
    let mut evaluation = Evaluation::default();
    for (name, slice) in slices {
        let (mut report, arch) = slice.evaluate()?;
        let name = name.unwrap_or_else(|| format!("{}-{arch}", slice.family.tag()));
        eprintln!("{name}: {}", report.summary());
        report.truncate_disagreements(args.max_disagreements);
        evaluation.insert(name, report, slice.family.gate(slice.min_recall));
    }
    for (name, failures) in evaluation.failures() {
        eprintln!("{name}: FAIL {}", failures.join(", "));
    }
    println!("{}", serde_json::to_string_pretty(&evaluation).map_err(|error| error.to_string())?);
    Ok(if evaluation.passes_gate() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
