use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use rampage_eval::{Evaluation, Gate, Report, ToolTruth, Truth};
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
    /// when any slice fails its gate (any wrong answer; for libid any spurious name; recall or precision below
    /// --min-recall or --min-precision). A toolid slice takes no --target: its truth names the binaries.
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
    /// Producing-tool identification: the compilers, linkers and packers `detect_tools` names for each binary
    /// of a tool truth, against the toolchain that built it.
    Toolid,
}

impl Family {
    fn tag(self) -> &'static str {
        match self {
            Family::Libid => "libid",
            Family::Discovery => "discovery",
            Family::Toolid => "toolid",
        }
    }

    /// Discovery tolerates spurious starts: code without a sized symbol is still code. Tool identification's
    /// spurious detections are bounded by its precision floor, like discovery's.
    fn gate(self, min_recall: f64, min_precision: f64) -> Gate {
        Gate { allow_spurious: matches!(self, Family::Discovery | Family::Toolid), min_recall, min_precision }
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
    /// The slice name; defaults to <family>-<target architecture> (toolid: toolid).
    #[arg(long, conflicts_with = "manifest")]
    slice: Option<String>,
    #[arg(long, value_enum, default_value_t = Family::Libid, conflicts_with = "manifest")]
    family: Family,
    /// The recall baseline; a lower measured recall fails the gate.
    #[arg(long, default_value_t = 0.0, conflicts_with = "manifest")]
    min_recall: f64,
    /// The precision baseline; a lower measured precision fails the gate.
    #[arg(long, default_value_t = 0.0, conflicts_with = "manifest")]
    min_precision: f64,
    /// Evaluate every slice of a manifest instead: {"slices": {"<name>": {"family": "libid"|"discovery"|"toolid",
    /// "refs": [..], "dbs": [..], "target": "..", "truth": "..", "min_recall": 0.0, "min_precision": 0.0}}},
    /// paths relative to the manifest; refs and dbs apply to libid only, and toolid has no target.
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

fn extents(binary: &Binary, path: &Path) -> Result<BTreeMap<u64, u64>, String> {
    rampage_eval::discovered_extents(binary).map_err(|error| format!("{}: {error}", path.display()))
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
    min_precision: f64,
    #[serde(default)]
    refs: Vec<PathBuf>,
    #[serde(default)]
    dbs: Vec<PathBuf>,
    /// Required except for toolid, whose truth lists its binaries.
    target: Option<PathBuf>,
    truth: PathBuf,
}

#[derive(Deserialize)]
struct Manifest {
    slices: BTreeMap<String, Slice>,
}

impl Slice {
    fn database(&self, target: &Path) -> Result<SignatureDb, String> {
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
                Some(db) => db.extend_from_binary_with_extents(&binary, &extents(&binary, path)?),
                None => combined = Some(SignatureDb::from_binary_with_extents(&binary, &extents(&binary, path)?)),
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
        combined.ok_or_else(|| format!("{}: give at least one --db or --ref", target.display()))
    }

    /// The slice's report, and its default name.
    fn evaluate(&self) -> Result<(Report, String), String> {
        match (self.family, &self.target) {
            (Family::Toolid, None) => Ok((self.evaluate_tools()?, Family::Toolid.tag().to_owned())),
            (Family::Toolid, Some(target)) => {
                Err(format!("{}: a toolid slice takes its binaries from its truth", target.display()))
            }
            (family, None) => Err(format!("{}: a {} slice needs a target", self.truth.display(), family.tag())),
            (family, Some(target)) => self.evaluate_target(family, target),
        }
    }

    /// A libid or discovery slice, scored on its one target.
    fn evaluate_target(&self, family: Family, target_path: &Path) -> Result<(Report, String), String> {
        let target = open(target_path)?;
        let arch = target.arch;
        let truth =
            Truth::from_json(&read(&self.truth)?).map_err(|error| format!("{}: {error}", self.truth.display()))?;
        let unsupported = |_| format!("unsupported architecture {arch}");
        let report = if let Family::Libid = family {
            let db = self.database(target_path)?;
            // A database for another architecture matches nothing, which would read as a clean (if useless) pass.
            if db.arch() != arch {
                let target = target_path.display();
                return Err(format!("{target}: database architecture {} is not the target's {arch}", db.arch()));
            }
            rampage_eval::evaluate(&db, &target, &truth).map_err(unsupported)?
        } else {
            rampage_eval::evaluate_discovery(&target, &truth).map_err(unsupported)?
        };
        Ok((report, format!("{}-{arch}", family.tag())))
    }

    /// Detects the tools of every binary the truth scores, its paths relative to the truth file.
    fn evaluate_tools(&self) -> Result<Report, String> {
        let truth =
            ToolTruth::from_json(&read(&self.truth)?).map_err(|error| format!("{}: {error}", self.truth.display()))?;
        let base = self.truth.parent().unwrap_or(Path::new("."));
        let mut detections = BTreeMap::new();
        for path in truth.binaries.keys() {
            detections.insert(path.clone(), rampage_eval::detected_tools(&open(&base.join(path))?));
        }
        Ok(rampage_eval::score_tools(&detections, &truth))
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
                min_precision: slice.min_precision,
                refs: resolve(slice.refs),
                dbs: resolve(slice.dbs),
                target: slice.target.map(|target| base.join(target)),
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
            let Some(truth) = args.truth else {
                return Err("give --manifest, or --truth (and --target unless --family toolid)".to_owned());
            };
            let slice = Slice {
                family: args.family,
                min_recall: args.min_recall,
                min_precision: args.min_precision,
                refs: args.references,
                dbs: args.databases,
                target: args.target,
                truth,
            };
            vec![(args.slice, slice)]
        }
    };
    let mut evaluation = Evaluation::default();
    for (name, slice) in slices {
        let (mut report, default_name) = slice.evaluate()?;
        let name = name.unwrap_or(default_name);
        eprintln!("{name}: {}", report.summary());
        report.truncate_disagreements(args.max_disagreements);
        evaluation.insert(name, report, slice.family.gate(slice.min_recall, slice.min_precision));
    }
    for (name, failures) in evaluation.failures() {
        eprintln!("{name}: FAIL {}", failures.join(", "));
    }
    println!("{}", serde_json::to_string_pretty(&evaluation).map_err(|error| error.to_string())?);
    Ok(if evaluation.passes_gate() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

#[cfg(test)]
mod tests {
    use rampage_eval::{DetectedTool, score_tools};

    use super::*;

    const TRUTH: &str = r#"{
        "toolchains": {
            "cc": {
                "how": "cc hello.c",
                "expected": [
                    {"kind": "compiler", "name": "GCC", "why": "cc is GCC"},
                    {"kind": "linker", "name": "GNU ld", "why": "GCC links with GNU ld"}
                ],
                "absent": ["packer"]
            }
        },
        "binaries": {"a.elf": {"toolchain": "cc", "built": "build.sh"}},
        "excluded": {}
    }"#;

    fn tool(kind: &str, name: &str) -> DetectedTool {
        DetectedTool { kind: kind.to_owned(), name: name.to_owned(), evidence: vec![format!("{name} evidence")] }
    }

    #[test]
    fn the_toolid_gate_bounds_spurious_tools_by_precision_and_missed_ones_by_recall() {
        let truth = ToolTruth::from_json(TRUTH).unwrap();
        let detections = BTreeMap::from([(
            "a.elf".to_owned(),
            vec![tool("compiler", "GCC"), tool("linker", "GNU ld"), tool("compiler", "MinGW")],
        )]);
        let report = score_tools(&detections, &truth);
        assert_eq!((report.correct, report.missed, report.spurious), (2, 0, 1));
        assert!(Family::Toolid.gate(1.0, 0.6).check(&report).is_empty(), "spurious tools only lower precision");
        assert_eq!(Family::Toolid.gate(0.0, 1.0).check(&report), ["precision 0.6667 below baseline 1.0000"]);

        let partial = BTreeMap::from([("a.elf".to_owned(), vec![tool("compiler", "GCC")])]);
        let report = score_tools(&partial, &truth);
        assert!(Family::Toolid.gate(0.5, 1.0).check(&report).is_empty());
        assert_eq!(Family::Toolid.gate(0.75, 0.0).check(&report), ["recall 0.5000 below baseline 0.7500"]);
    }
}
