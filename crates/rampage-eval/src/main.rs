use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use object::{Object, ObjectSection, ObjectSymbol};
use rampage_eval::{Evaluation, Gate, Report, ToolTruth, Truth, TypeMetric, TypeTruth};
use rampage_loaders::Binary;
use rampage_signatures::{SignatureDb, named_functions};
use serde::Deserialize;

mod parity;
mod parity_graph_files;
mod parity_live;

/// Self-supervised evaluation of rampage heuristics against strip-and-compare ground truth.
#[derive(Parser)]
#[command(name = "rampage-eval")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect actual artifact headers, static/dynamic symbols and debug sections for corpus verification.
    ArtifactInfo { input: PathBuf },
    /// Compare actual Rampage and Ghidra graph exports bound to one explicit image/address context.
    GraphAgreement {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        rampage_export: PathBuf,
        #[arg(long)]
        ghidra_export: PathBuf,
    },
    /// Print the ground truth ({"0x<address>": "<name>"}) taken from a symbolized binary's function symbols.
    Truth {
        symbolized: PathBuf,
        /// Explicitly use concrete embedded DWARF subprogram ranges, checking every retained range in the twin.
        #[arg(long, conflicts_with_all = ["library", "program"])]
        dwarf: bool,
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
    /// Print the type truth ({"0x<address>": {"name", "return", "params", "variadic"}}) taken from a binary's
    /// embedded DWARF: each function's return and parameter type classes.
    TypeTruth {
        debug: PathBuf,
        /// The stripped twin; every function symbol's bytes must be identical in it, proving the same layout.
        #[arg(long)]
        stripped: Option<PathBuf>,
    },
    /// Write an ELF copy without debug sections and symbols; preserve code layout for twin verification.
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
    /// --min-recall or --min-precision). A toolid slice takes no --target: its truth names the binaries. A types
    /// slice decompiles every function of its type truth in the stripped target and scores one --metric.
    Run(Box<RunArgs>),
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
    /// Signature recovery: the parameter counts, returns and parameter type classes the decompiler infers for
    /// a stripped target, against its DWARF.
    Types,
}

impl Family {
    fn tag(self) -> &'static str {
        match self {
            Family::Libid => "libid",
            Family::Discovery => "discovery",
            Family::Toolid => "toolid",
            Family::Types => "types",
        }
    }

    /// Discovery tolerates spurious starts: code without a sized symbol is still code. Tool identification's
    /// spurious detections are bounded by its precision floor, like discovery's. A recovered type is often
    /// wrong in a way a stripped binary cannot avoid, so type recovery bounds wrong answers by its floors too.
    fn gate(self, min_recall: f64, min_precision: f64) -> Gate {
        Gate {
            allow_spurious: matches!(self, Family::Discovery | Family::Toolid | Family::Types),
            allow_wrong: matches!(self, Family::Types),
            min_recall,
            min_precision,
        }
    }
}

/// The part of a signature a types slice scores ([`TypeMetric`]).
#[derive(Clone, Copy, Default, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Metric {
    /// Each function's parameter count.
    #[default]
    Params,
    /// Each function's void-versus-value return.
    Return,
    /// Each parameter's type class.
    Classes,
}

impl From<Metric> for TypeMetric {
    fn from(metric: Metric) -> TypeMetric {
        match metric {
            Metric::Params => TypeMetric::Params,
            Metric::Return => TypeMetric::Return,
            Metric::Classes => TypeMetric::Classes,
        }
    }
}

#[derive(clap::Args)]
struct RunArgs {
    /// Produce the Phase 0 parity scorecard; unrun metrics remain explicit rather than inferred.
    #[arg(long, value_enum, conflicts_with_all = ["target", "truth", "slice", "family", "metric",
        "min_recall", "min_precision", "databases", "references"])]
    suite: Option<ParitySuite>,
    /// Task manifest directory for --suite parity; defaults to the owned evaluator task set.
    #[arg(long, requires = "suite")]
    tasks: Option<PathBuf>,
    /// Repository root used by repository-relative task fixture paths.
    #[arg(long, requires = "suite")]
    repository_root: Option<PathBuf>,
    /// Optional generated corpus inventory; unavailable/failed profiles remain visible in the scorecard.
    #[arg(long, requires = "suite")]
    corpus_inventory: Option<PathBuf>,
    /// Graph provenance/binding request; compare actual exports as a separate scorecard workload.
    #[arg(long, requires_all = ["suite", "rampage_graph", "ghidra_graph"])]
    graph_request: Option<PathBuf>,
    #[arg(long, requires = "graph_request")]
    rampage_graph: Option<PathBuf>,
    #[arg(long, requires = "graph_request")]
    ghidra_graph: Option<PathBuf>,
    /// Explicit model for opt-in MCP agent tasks (existing Anthropic transport); no model fallback.
    #[arg(long, requires = "suite")]
    agent_model: Option<String>,
    /// Task IDs to attempt with --agent-model; repeatable. Default selects the first bounded task subset.
    #[arg(long, requires = "agent_model")]
    agent_task: Vec<String>,
    /// Maximum live tasks attempted, default 1, at most 20. No model runs without --agent-model.
    #[arg(long, requires = "agent_model", default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=20))]
    agent_max_tasks: u64,
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
    /// What a types slice scores.
    #[arg(long, value_enum, default_value_t = Metric::Params, conflicts_with = "manifest")]
    metric: Metric,
    /// The recall baseline; a lower measured recall fails the gate.
    #[arg(long, default_value_t = 0.0, conflicts_with = "manifest")]
    min_recall: f64,
    /// The precision baseline; a lower measured precision fails the gate.
    #[arg(long, default_value_t = 0.0, conflicts_with = "manifest")]
    min_precision: f64,
    /// Evaluate every slice of a manifest instead: {"slices": {"<name>": {"family": "libid"|"discovery"|"toolid"
    /// |"types", "refs": [..], "dbs": [..], "target": "..", "truth": "..", "metric": "params"|"return"|"classes",
    /// "min_recall": 0.0, "min_precision": 0.0}}}, paths relative to the manifest; refs and dbs apply to libid
    /// only, metric to types only, and toolid has no target. Repeat to combine corpora with unique slice names.
    #[arg(long, conflicts_with_all = ["databases", "references"])]
    manifest: Vec<PathBuf>,
    /// Keep at most this many disagreements per slice in the JSON (the counts still cover all of them).
    #[arg(long, default_value_t = 200)]
    max_disagreements: usize,
}

#[derive(Clone, Copy, ValueEnum)]
enum ParitySuite {
    Parity,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::ArtifactInfo { input } => artifact_info(&input),
        Command::GraphAgreement { request, rampage_export, ghidra_export } => {
            parity_graph_files::print(&request, &rampage_export, &ghidra_export)
        }
        Command::Truth { symbolized, stripped, library, program, dwarf } => {
            truth(&symbolized, stripped.as_deref(), &library, &program, dwarf)
        }
        Command::TypeTruth { debug, stripped } => type_truth(&debug, stripped.as_deref()),
        Command::Strip { input, output, keep_symbols } => strip(&input, &output, keep_symbols),
        Command::Run(args) => run(*args),
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

fn artifact_info(path: &Path) -> Result<ExitCode, String> {
    let binary =
        Binary::open_image_metadata(path, None, None).map_err(|error| format!("{}: {error}", path.display()))?;
    let object = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
    let text_definition =
        |symbol: &object::Symbol<'_, '_>| symbol.kind() == object::SymbolKind::Text && symbol.is_definition();
    let function = |symbol: &object::Symbol<'_, '_>| {
        text_definition(symbol)
            && symbol.section_index().and_then(|index| object.section_by_index(index).ok()).is_some_and(|section| {
                symbol.address() >= section.address()
                    && symbol.address().checked_sub(section.address()).is_some_and(|offset| offset < section.size())
            })
    };
    let mut debug_sections = Vec::new();
    for section in object.sections() {
        let name = section.name().map_err(|error| error.to_string())?;
        if section.size() != 0
            && (section.kind() == object::SectionKind::Debug
                || name.starts_with(".debug")
                || name.starts_with(".zdebug")
                || name.starts_with("__debug")
                || name.starts_with("__zdebug")
                || matches!(name, ".stab" | ".stabstr"))
        {
            debug_sections.push(name.to_owned());
        }
    }
    debug_sections.sort();
    debug_sections.dedup();
    let info = serde_json::json!({
        "format": binary.format,
        "arch": binary.arch,
        "endianness": if binary.big_endian { "big" } else { "little" },
        "static_function_symbols": object.symbols().filter(function).count(),
        "static_text_symbols_outside_section": object.symbols()
            .filter(|symbol| text_definition(symbol) && !function(symbol)).count(),
        "dynamic_function_symbols": object.dynamic_symbols().filter(function).count(),
        "debug_sections": debug_sections,
        "thumb_ranges": binary.thumb.len(),
        "loader_warnings": binary.warnings,
    });
    println!("{}", serde_json::to_string(&info).map_err(|error| error.to_string())?);
    Ok(ExitCode::SUCCESS)
}

fn truth(
    symbolized: &Path,
    stripped: Option<&Path>,
    library: &[PathBuf],
    program: &[PathBuf],
    dwarf: bool,
) -> Result<ExitCode, String> {
    let binary = open(symbolized)?;
    if dwarf {
        let twin = stripped.map(open).transpose()?;
        let report = rampage_eval::dwarf_function_truth(binary.image_bytes(), &binary, twin.as_ref())?;
        if let Some(reason) = &report.no_truth_reason {
            return Err(format!("no usable embedded DWARF function truth: {reason}"));
        }
        eprintln!(
            "DWARF: {} function starts, {} exact ranges / {} bytes checked; twin_verified={}",
            report.truth.0.len(),
            report.exact_ranges_checked,
            report.checked_bytes,
            report.twin_verified
        );
        eprintln!(
            "DWARF: {} subprograms omitted ({} range-list entries), {} aliases; {} notes omitted",
            report.omitted_subprograms, report.unsupported_range_subprograms, report.aliased_addresses, report.omitted
        );
        for note in &report.notes {
            eprintln!("DWARF: {note}");
        }
        print!("{}", report.truth.to_json());
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(stripped) = stripped {
        check_twin(&binary, symbolized, stripped)?;
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

/// Every function symbol of `binary` (read from `path`) has the same bytes in the binary at `stripped`.
fn check_twin(binary: &Binary, path: &Path, stripped: &Path) -> Result<(), String> {
    let twin = open(stripped)?;
    for symbol in named_functions(binary) {
        let ours = binary.read(symbol.address, symbol.size);
        if ours.is_none() || ours != twin.read(symbol.address, symbol.size) {
            return Err(format!(
                "{} is not a twin of {}: {} at {:#x} differs",
                stripped.display(),
                path.display(),
                symbol.name,
                symbol.address
            ));
        }
    }
    Ok(())
}

fn type_truth(debug: &Path, stripped: Option<&Path>) -> Result<ExitCode, String> {
    if let Some(stripped) = stripped {
        check_twin(&open(debug)?, debug, stripped)?;
    }
    let bytes = std::fs::read(debug).map_err(|error| format!("{}: {error}", debug.display()))?;
    let (truth, notes) = TypeTruth::from_dwarf(&bytes).map_err(|error| format!("{}: {error}", debug.display()))?;
    for note in notes {
        eprintln!("{}: {note}", debug.display());
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
    metric: Metric,
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

/// Each types target's decompiled signatures, so the slices scoring other metrics of it decompile it once.
type Decompiled = BTreeMap<PathBuf, rampage_eval::SignatureRecoveryBatch>;

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
    fn evaluate(&self, decompiled: &mut Decompiled) -> Result<(Report, String), String> {
        match (self.family, &self.target) {
            (Family::Toolid, None) => Ok((self.evaluate_tools()?, Family::Toolid.tag().to_owned())),
            (Family::Toolid, Some(target)) => {
                Err(format!("{}: a toolid slice takes its binaries from its truth", target.display()))
            }
            (family, None) => Err(format!("{}: a {} slice needs a target", self.truth.display(), family.tag())),
            (Family::Types, Some(target)) => self.evaluate_types(target, decompiled),
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

    /// Decompiles (once per target) every truth function of the stripped target and scores the slice's metric.
    fn evaluate_types(&self, target_path: &Path, decompiled: &mut Decompiled) -> Result<(Report, String), String> {
        let truth =
            TypeTruth::from_json(&read(&self.truth)?).map_err(|error| format!("{}: {error}", self.truth.display()))?;
        let target = open(target_path)?;
        let name = format!("types-{}-{}", TypeMetric::from(self.metric).tag(), target.arch);
        if !decompiled.contains_key(target_path) {
            let signatures = rampage_eval::decompiled_signature_batch(target, truth.0.keys().copied());
            decompiled.insert(target_path.to_owned(), signatures);
        }
        let signatures = &decompiled[target_path].signatures;
        // A second truth for the same target names functions the cached run never decompiled.
        let missing = truth.0.keys().filter(|address| !signatures.contains_key(address)).count();
        if missing > 0 {
            let target = target_path.display();
            return Err(format!("{target}: {missing} truth functions were not decompiled; use one truth per target"));
        }
        Ok((rampage_eval::score_types(self.metric.into(), signatures, &truth), name))
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
                metric: slice.metric,
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
    if args.suite.is_some() {
        return parity::run(args);
    }
    let slices = if !args.manifest.is_empty() {
        combined_manifests(&args.manifest)?
    } else {
        let Some(truth) = args.truth else {
            return Err("give --manifest, or --truth (and --target unless --family toolid)".to_owned());
        };
        let slice = Slice {
            family: args.family,
            metric: args.metric,
            min_recall: args.min_recall,
            min_precision: args.min_precision,
            refs: args.references,
            dbs: args.databases,
            target: args.target,
            truth,
        };
        vec![(args.slice, slice)]
    };
    let (evaluation, _health) = evaluate_slices(slices, args.max_disagreements)?;
    println!("{}", serde_json::to_string_pretty(&evaluation).map_err(|error| error.to_string())?);
    Ok(if evaluation.passes_gate() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn combined_manifests(paths: &[PathBuf]) -> Result<Vec<(Option<String>, Slice)>, String> {
    let mut slices = Vec::new();
    let mut names = BTreeSet::new();
    for path in paths {
        for (name, slice) in manifest(path)? {
            if let Some(name) = &name
                && !names.insert(name.clone())
            {
                return Err(format!("duplicate slice {name:?} across manifests"));
            }
            slices.push((name, slice));
        }
    }
    Ok(slices)
}

fn evaluate_slices(
    slices: Vec<(Option<String>, Slice)>,
    max_disagreements: usize,
) -> Result<(Evaluation, serde_json::Value), String> {
    let mut evaluation = Evaluation::default();
    let mut decompiled = Decompiled::new();
    for (name, slice) in slices {
        let (mut report, default_name) = slice.evaluate(&mut decompiled)?;
        let name = name.unwrap_or(default_name);
        eprintln!("{name}: {}", report.summary());
        report.truncate_disagreements(max_disagreements);
        evaluation.insert(name, report, slice.family.gate(slice.min_recall, slice.min_precision));
    }
    for (name, failures) in evaluation.failures() {
        eprintln!("{name}: FAIL {}", failures.join(", "));
    }
    let targets: Vec<_> = decompiled.iter().map(|(path, batch)| {
        let returned = batch.observations.iter().filter(|entry| entry.status == "returned").count();
        let with_warnings = batch.observations.iter()
            .filter(|entry| entry.warning_count.is_some_and(|n| n > 0)).count();
        serde_json::json!({
            "target": path, "attempted": batch.observations.len(), "returned_exact_entry": returned,
            "errors": batch.observations.iter().filter(|entry| entry.status == "error").count(),
            "address_mismatches": batch.observations.iter().filter(|entry| entry.status == "address_mismatch").count(),
            "with_warnings": with_warnings,
            "diagnostics_unavailable": batch.observations.iter().filter(|entry| entry.warning_count.is_none()).count(),
            "bad_data": batch.observations.iter().filter(|entry| entry.bad_data == Some(true)).count(),
            "unimplemented": batch.observations.iter().filter(|entry| entry.unimplemented == Some(true)).count(),
            "timing_boundary": batch.timing_boundary, "functions": batch.observations,
        })
    }).collect();
    let attempts: usize = decompiled.values().map(|batch| batch.observations.len()).sum();
    let health = serde_json::json!({
        "status": if attempts == 0 { "not_run" } else { "measured" }, "attempted": attempts, "targets": targets,
        "limits": "Only type-truth-selected entries are timed. \
                   Returned C and no error do not establish correct recovery."
    });
    Ok((evaluation, health))
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
