//! The embedded set's operand tier: builds and gates the scheme-4 Thumb database
//! (`crates/rampage-signatures/data/embedded-thumb-operands.json.gz`), which names a firmware library function
//! whose structure offsets, stack slots or constants changed with a kernel configuration or a compiler release
//! while its code did not (docs/signature-corpus.md, "Embedded firmware set").
//!
//! ```sh
//! cargo build --release -p rampage-eval --example embedded_operands
//! E=target/release/examples/embedded_operands
//! # The shipped database: every training reference, with the negatives as tombstones.
//! $E build --output WORK/operands.json --gzip WORK/operands.json.gz --negatives WORK/negatives \
//!   WORK/refs/*.elf WORK/refs-hooks/*.elf
//! # Training gate: each training toolchain left out in turn (no false positive may be added).
//! $E loo --negatives WORK/negatives WORK/refs/*.elf WORK/refs-hooks/*.elf
//! # Dev gate: the product's identification with and without the tier (WORK/dev from `build.py dev`).
//! $E eval --candidate WORK/operands.json.gz [--call-graph CANDIDATE.json.gz] --negatives WORK/negatives \
//!   WORK/dev/*/*.stripped.elf
//! ```
//!
//! - **Built like the scheme-3 set** (`embedded_signatures`): every training reference function hashed over the
//!   extents discovery finds in the reference and in a stripped copy, collision-safe union (a hash two names share
//!   never answers; a callee key may then tell them apart), exact fallbacks withheld, symbol-size-only answers
//!   dropped; a body with no field scheme 4 masks is left out, since it would only repeat the scheme-3 set's
//!   answer. Scheme 4 ([`THUMB_OPERAND_SCHEME`]) masks Thumb load/store offsets and stack adjustments bit by bit,
//!   so it coarsens scheme 3: two bodies scheme 3 cannot tell apart, scheme 4 cannot either.
//! - **Negatives are tombstones.** The negative references (Thumb builds of libraries no embedded signature covers)
//!   are added under their own names and those names then removed, so a training body whose scheme-4 hash a
//!   negative function shares never answers, and no negative name ships.
//! - **The product's order.** Identification consults the bundled ARM corpus, the scheme-3 set, then the tier, and
//!   then propagates names with the embedded call graph, as `identify_functions` does on firmware. `eval` checks
//!   that its baseline equals `identify_functions` on every target before it reports.
//! - **The gate** (as the host arms are gated, docs/flywheel.md): training, each toolchain left out (scored over
//!   the extents discovery finds in each symbolized reference, since a stripped whole-archive link reaches few of
//!   its functions), may gain no false positive and lose F1 on no reference; dev must gain, with at most one more false positive per 100 names
//!   gained, F1 lost on no binary; negatives get no name they did not have.
//!
//! `eval` lists every changed function: run it on dev targets only. The held-out 14.3 fixtures are the final split.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::{Parser, Subcommand};
use rampage_api::{Packs, Project, call_graph_names, call_sequences};
use rampage_loaders::Binary;
use rampage_signatures::{
    CallGraph, LITERAL_POOL_SCHEME, MaskContext, SignatureDb, THUMB_OPERAND_SCHEME, canonical_functions,
    canonical_name, function_hash_scheme, identify_program_sources, thumb_operand_fields,
};
use serde_json::json;

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Builds the scheme-4 database from training references.
    Build {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        gzip: Option<PathBuf>,
        /// A directory of negative references (`*.elf`; tombstones only).
        #[arg(long)]
        negatives: Option<PathBuf>,
        /// The hash scheme (4; 3 rebuilds the scheme-3 set, to check the pipeline reproduces it).
        #[arg(long, default_value_t = THUMB_OPERAND_SCHEME)]
        scheme: u32,
        /// Symbolized training references.
        references: Vec<PathBuf>,
    },
    /// Training gate: each training toolchain left out in turn.
    Loo {
        #[arg(long)]
        negatives: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        references: Vec<PathBuf>,
    },
    /// Acceptance on input without truth: the names identification gives a firmware image (an ELF, or a Raw project
    /// described by `--raw`, a `RawProjectRequest` as JSON) with and without the candidate tier.
    Names {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        call_graph: Option<PathBuf>,
        #[arg(long)]
        raw: Option<String>,
        image: PathBuf,
    },
    /// Diagnostics: every discovered function of a binary with its extent and scheme-3 and scheme-4 hashes.
    Hashes { binary: PathBuf },
    /// Dev gate: identification with and without the candidate tier on stripped targets, each with its truth
    /// beside it (`X.stripped.elf` and `X.truth.json`), and on the negatives.
    Eval {
        /// The candidate scheme-4 tier (gzip), consulted after the scheme-3 set.
        #[arg(long)]
        candidate: Option<PathBuf>,
        /// A candidate scheme-3 set (gzip) in place of the bundled one.
        #[arg(long)]
        scheme3: Option<PathBuf>,
        /// A candidate embedded call graph (gzip) in place of the bundled one.
        #[arg(long)]
        call_graph: Option<PathBuf>,
        #[arg(long)]
        negatives: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        targets: Vec<PathBuf>,
    },
}

/// Compiler tags in reference file names that mark a held-out build (`build.py`: 14.3 is the final split; clang 23
/// built the held-out compiler-rt). Refused as training input.
const HELD_OUT: [&str; 2] = ["gcc14.3", "clang23"];

/// One symbolized reference, analysed: its extents as discovered in it and in a stripped copy, and its truth.
struct Reference {
    name: String,
    toolchain: String,
    binary: Binary,
    symbolized: BTreeMap<u64, u64>,
    stripped: BTreeMap<u64, u64>,
    /// Every canonical function name at each function address.
    truth: BTreeMap<u64, BTreeSet<String>>,
}

fn toolchain_of(name: &str) -> String {
    name.split('-')
        .find(|part| part.starts_with("gcc") || part.starts_with("clang"))
        .map(|part| part.splitn(3, '.').take(2).collect::<Vec<_>>().join("."))
        .unwrap_or_default()
}

fn analyse(path: &Path, scratch: &Path) -> Result<Reference, String> {
    let error = |error: String| format!("{}: {error}", path.display());
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let binary = Binary::open(path).map_err(|e| error(e.to_string()))?;
    let symbolized = rampage_eval::discovered_extents(&binary).map_err(|e| error(e.to_string()))?;
    let image = std::fs::read(path).map_err(|e| error(e.to_string()))?;
    let copy = scratch.join(format!("{name}.stripped"));
    std::fs::write(&copy, rampage_eval::strip(&image, false)?).map_err(|e| error(e.to_string()))?;
    let stripped = Binary::open(&copy).map_err(|e| error(e.to_string()))?;
    let stripped = rampage_eval::discovered_extents(&stripped).map_err(|e| error(e.to_string()))?;
    let _ = std::fs::remove_file(&copy);
    let mut truth: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for symbol in rampage_signatures::named_functions(&binary) {
        truth.entry(symbol.address).or_default().insert(canonical_name(&symbol.name).into_owned());
    }
    Ok(Reference { toolchain: toolchain_of(&name), name, binary, symbolized, stripped, truth })
}

/// Analyses `paths` on every core, in input order.
fn analyse_all(paths: &[PathBuf]) -> Result<Vec<Reference>, String> {
    let scratch = std::env::temp_dir().join(format!("rampage-embedded-operands-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|error| error.to_string())?;
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(4, |count| count.get());
    let mut results: Vec<(usize, Result<Reference, String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = paths.get(index) else { break };
                        done.push((index, analyse(path, &scratch)));
                    }
                    done
                })
            })
            .collect();
        handles.into_iter().flat_map(|handle| handle.join().expect("analysis worker")).collect()
    });
    let _ = std::fs::remove_dir_all(&scratch);
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The database `embedded_signatures` builds, under `scheme`, from `references`, with `negatives` as tombstones.
fn build_database(references: &[&Reference], negatives: &[&Reference], scheme: u32) -> Result<SignatureDb, String> {
    let mut database: Option<SignatureDb> = None;
    let (mut symbol_hashes, mut discovered_hashes) = (BTreeSet::new(), BTreeSet::new());
    let mut training_names = BTreeSet::new();
    for (reference, negative) in references.iter().map(|r| (r, false)).chain(negatives.iter().map(|r| (r, true))) {
        let binary = &reference.binary;
        let target = binary.target();
        let image = MaskContext::from_binary(binary);
        let hash = |address: u64, end: u64| {
            let bytes = binary.read(address, end.checked_sub(address)?)?;
            function_hash_scheme(scheme, &target, &image, bytes, address).map(|hash| hex(&hash))
        };
        for function in canonical_functions(binary).values() {
            if !negative {
                training_names.insert(function.name.clone());
            }
            let ends: Vec<u64> = [&reference.symbolized, &reference.stripped]
                .iter()
                .filter_map(|extents| extents.get(&function.address).copied())
                .collect();
            if ends.is_empty() {
                continue;
            }
            symbol_hashes.extend(hash(function.address, function.address.saturating_add(function.size)));
            discovered_hashes.extend(ends.into_iter().filter_map(|end| hash(function.address, end)));
        }
        // Under scheme 4, a body without operand fields would only repeat the scheme-3 set's answer.
        let kept = |extents: &BTreeMap<u64, u64>| -> BTreeMap<u64, u64> {
            extents
                .iter()
                .filter(|&(&address, &end)| {
                    scheme != THUMB_OPERAND_SCHEME
                        || binary
                            .read(address, end.saturating_sub(address))
                            .is_some_and(|bytes| thumb_operand_fields(&target, bytes, address))
                })
                .map(|(&address, &end)| (address, end))
                .collect()
        };
        let (symbolized, stripped) = (kept(&reference.symbolized), kept(&reference.stripped));
        match &mut database {
            Some(database) => database.extend_from_binary_with_extents(binary, &symbolized),
            None => database = Some(SignatureDb::from_binary_with_extents_in_scheme(binary, &symbolized, scheme)),
        }
        if let Some(database) = &mut database {
            database.extend_from_binary_with_extents(binary, &stripped);
        }
    }
    let mut database = database.ok_or("no references")?;
    database.withhold_exact_fallbacks();
    let mut value: serde_json::Value = serde_json::from_str(&database.to_json()).map_err(|error| error.to_string())?;
    let entries = value["entries"].as_object_mut().ok_or("database without entries")?;
    entries.retain(|hash, _| !symbol_hashes.contains(hash) || discovered_hashes.contains(hash));
    value.as_object_mut().ok_or("database is not an object")?.remove("ambiguous_exact");
    let text = serde_json::to_string(&value).map_err(|error| error.to_string())?;
    let mut database = SignatureDb::from_json(&text).map_err(|error| error.to_string())?;
    if !negatives.is_empty() {
        database.retain_names(&training_names);
    }
    Ok(database)
}

/// Outcome counts of one scored binary.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, serde::Serialize)]
struct Counts {
    correct: usize,
    wrong: usize,
    spurious: usize,
    missed: usize,
}

impl Counts {
    fn fp(&self) -> usize {
        self.wrong + self.spurious
    }

    fn f1(&self) -> f64 {
        let tp = self.correct as f64;
        let denominator = 2.0 * tp + (self.wrong + self.spurious) as f64 + (self.wrong + self.missed) as f64;
        if denominator == 0.0 { 1.0 } else { 2.0 * tp / denominator }
    }

    fn add(&mut self, other: Counts) {
        self.correct += other.correct;
        self.wrong += other.wrong;
        self.spurious += other.spurious;
        self.missed += other.missed;
    }
}

/// Scores `names` against `truth` (a name is correct when it is any of the truth's names at that address).
fn score(names: &BTreeMap<u64, String>, truth: &BTreeMap<u64, BTreeSet<String>>) -> Counts {
    let mut counts = Counts::default();
    for (address, expected) in truth {
        match names.get(address) {
            Some(name) if expected.contains(name) => counts.correct += 1,
            Some(_) => counts.wrong += 1,
            None => counts.missed += 1,
        }
    }
    counts.spurious = names.keys().filter(|address| !truth.contains_key(address)).count();
    counts
}

/// Signature names for the functions at `extents` of `binary`, from `databases` in order.
fn identify(binary: &Binary, extents: &BTreeMap<u64, u64>, databases: &[&SignatureDb]) -> BTreeMap<u64, String> {
    let bodies: Vec<(u64, &[u8])> = extents
        .iter()
        .filter_map(|(&address, &end)| Some((address, binary.read(address, end.checked_sub(address)?)?)))
        .collect();
    let image = MaskContext::from_binary(binary);
    identify_program_sources(databases, &binary.target(), &image, &bodies)
        .into_iter()
        .map(|(address, (_, name))| (address, name.into_owned()))
        .collect()
}

fn build(references: &[PathBuf], negative: &[PathBuf], scheme: u32) -> Result<SignatureDb, String> {
    refuse_held_out(references)?;
    let references = analyse_all(references)?;
    let negatives = analyse_all(negative)?;
    build_database(&references.iter().collect::<Vec<_>>(), &negatives.iter().collect::<Vec<_>>(), scheme)
}

fn refuse_held_out(references: &[PathBuf]) -> Result<(), String> {
    for path in references {
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        if HELD_OUT.iter().any(|tag| name.contains(tag)) {
            return Err(format!("{}: built by a held-out toolchain", path.display()));
        }
    }
    Ok(())
}

fn loo(references: &[PathBuf], negative: &[PathBuf]) -> Result<serde_json::Value, String> {
    refuse_held_out(references)?;
    let references = analyse_all(references)?;
    let negatives = analyse_all(negative)?;
    let negatives: Vec<&Reference> = negatives.iter().collect();
    let corpus = rampage_signatures::bundled_ref(rampage_arch::Arch::Arm);
    let folds: BTreeSet<&str> =
        references.iter().map(|r| r.toolchain.as_str()).filter(|tag| tag.starts_with("gcc")).collect();
    let mut report = Vec::new();
    let (mut before_total, mut after_total) = (Counts::default(), Counts::default());
    let mut regressions = Vec::new();
    for fold in folds {
        let training: Vec<&Reference> = references.iter().filter(|r| r.toolchain != fold).collect();
        let held: Vec<&Reference> = references.iter().filter(|r| r.toolchain == fold).collect();
        let scheme3 = build_database(&training, &[], LITERAL_POOL_SCHEME)?;
        let scheme4 = build_database(&training, &negatives, THUMB_OPERAND_SCHEME)?;
        let (mut before_fold, mut after_fold) = (Counts::default(), Counts::default());
        let mut fold_wrong = Vec::new();
        for reference in held {
            let base: Vec<&SignatureDb> = corpus.into_iter().chain([&scheme3]).collect();
            let with: Vec<&SignatureDb> = corpus.into_iter().chain([&scheme3, &scheme4]).collect();
            let before_names = identify(&reference.binary, &reference.symbolized, &base);
            let after_names = identify(&reference.binary, &reference.symbolized, &with);
            let (before, after) = (score(&before_names, &reference.truth), score(&after_names, &reference.truth));
            for (address, name) in &after_names {
                if before_names.get(address) != Some(name)
                    && !reference.truth.get(address).is_some_and(|names| names.contains(name))
                {
                    let expected = reference.truth.get(address).map(|names| names.iter().cloned().collect::<Vec<_>>());
                    fold_wrong.push(json!({"binary": reference.name, "address": format!("{address:#x}"),
                        "name": name, "truth": expected}));
                }
            }
            if after.f1() < before.f1() - 1e-12 {
                regressions.push(json!({"binary": reference.name, "before": before, "after": after}));
            }
            before_fold.add(before);
            after_fold.add(after);
        }
        eprintln!(
            "fold {fold}: correct {} -> {}, false positives {} -> {}",
            before_fold.correct,
            after_fold.correct,
            before_fold.fp(),
            after_fold.fp()
        );
        report.push(json!({"left_out": fold, "before": before_fold, "after": after_fold,
            "scheme4_entries": scheme4.len(), "new_false_names": fold_wrong}));
        before_total.add(before_fold);
        after_total.add(after_fold);
    }
    let passed = after_total.fp() <= before_total.fp() && regressions.is_empty();
    Ok(json!({"passed": passed, "before": before_total, "after": after_total, "folds": report,
        "slice_regressions": regressions}))
}

/// One target identified as the product does: the given databases, then the embedded call graph.
fn product_names(
    project: &Project,
    binary: &Binary,
    databases: &[&SignatureDb],
    graph: Option<&CallGraph>,
) -> Result<BTreeMap<u64, String>, String> {
    let program = rampage_analysis::functions::analyze(binary).map_err(|error| error.to_string())?;
    let extents: BTreeMap<u64, u64> = program.functions.iter().map(|f| (f.address, f.end())).collect();
    let mut names = identify(binary, &extents, databases);
    if let Some(graph) = graph.or_else(|| rampage_signatures::bundled_call_graph_for(binary)) {
        let existing: BTreeMap<u64, String> = program
            .functions
            .iter()
            .map(|function| (function.address, project.function_name(function.address)))
            .filter(|(address, name)| *name != format!("sub_{address:x}"))
            .map(|(address, name)| (address, canonical_name(&name).into_owned()))
            .collect();
        let calls = call_sequences(binary, &program);
        for (address, name) in call_graph_names(graph, &binary.arch.to_string(), &calls, &names, &existing) {
            names.entry(address).or_insert(name);
        }
    }
    Ok(names)
}

fn load_gzip(path: &Path) -> Result<SignatureDb, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    SignatureDb::from_gzip(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn eval(
    candidate: Option<&Path>,
    scheme3: Option<&Path>,
    call_graph: Option<&Path>,
    targets: &[PathBuf],
    negative: &[PathBuf],
) -> Result<serde_json::Value, String> {
    let tier = candidate.map(load_gzip).transpose()?;
    let replacement = scheme3.map(load_gzip).transpose()?;
    let graph = call_graph
        .map(|path| {
            let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            CallGraph::from_gzip(&bytes).map_err(|error| format!("{}: {error}", path.display()))
        })
        .transpose()?;
    let corpus = rampage_signatures::bundled_ref(rampage_arch::Arch::Arm);
    let mut rows = Vec::new();
    let (mut before_total, mut after_total) = (Counts::default(), Counts::default());
    let mut regressions = Vec::new();
    let mut mismatched_baselines = Vec::new();
    let inputs = targets.iter().map(|path| (path, false)).chain(negative.iter().map(|path| (path, true)));
    for (path, is_negative) in inputs {
        let error = |error: String| format!("{}: {error}", path.display());
        let binary = Binary::open(path).map_err(|e| error(e.to_string()))?;
        let embedded = rampage_signatures::bundled_embedded_for(&binary).ok_or_else(|| error("not firmware".into()))?;
        let truth: BTreeMap<u64, BTreeSet<String>> = if is_negative {
            BTreeMap::new()
        } else {
            let text = path.to_string_lossy().replace(".stripped.elf", ".truth.json");
            let text = std::fs::read_to_string(&text).map_err(|e| error(format!("{text}: {e}")))?;
            rampage_eval::Truth::from_json(&text)
                .map_err(|e| error(e.to_string()))?
                .0
                .into_iter()
                .map(|(address, name)| (address, BTreeSet::from([canonical_name(&name).into_owned()])))
                .collect()
        };
        let project = Project::new(Binary::open(path).map_err(|e| error(e.to_string()))?);
        project.set_packs(Arc::new(Packs::default()));
        let base: Vec<&SignatureDb> = corpus.into_iter().chain([embedded]).collect();
        let with: Vec<&SignatureDb> =
            corpus.into_iter().chain([replacement.as_ref().unwrap_or(embedded)]).chain(tier.as_ref()).collect();
        let before_names = product_names(&project, &binary, &base, None)?;
        let after_names = product_names(&project, &binary, &with, graph.as_ref())?;
        let shipped: BTreeMap<u64, String> = project
            .identify_functions(None, true, false)
            .map_err(|e| error(e.to_string()))?
            .matches
            .into_iter()
            .map(|matched| (matched.address, matched.name))
            .collect();
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        if shipped != before_names && shipped != after_names {
            mismatched_baselines.push(name.clone());
        }
        let (before, after) = if is_negative {
            let spurious = |names: &BTreeMap<u64, String>| Counts { spurious: names.len(), ..Counts::default() };
            (spurious(&before_names), spurious(&after_names))
        } else {
            (score(&before_names, &truth), score(&after_names, &truth))
        };
        let mut changes = Vec::new();
        for address in before_names.keys().chain(after_names.keys()).collect::<BTreeSet<_>>() {
            let (old, new) = (before_names.get(address), after_names.get(address));
            if old != new {
                let expected = truth.get(address).and_then(|names| names.iter().next());
                changes.push(json!({"address": format!("{address:#x}"), "before": old, "after": new,
                    "truth": expected, "correct": new.is_some_and(|new| Some(new) == expected)}));
            }
        }
        if after.f1() < before.f1() - 1e-12 || (is_negative && after.spurious > before.spurious) {
            regressions.push(name.clone());
        }
        eprintln!(
            "{name}: correct {} -> {}, false {} -> {}{}",
            before.correct,
            after.correct,
            before.fp(),
            after.fp(),
            if is_negative { " (negative)" } else { "" }
        );
        if is_negative {
            rows.push(json!({"binary": name, "negative": true, "before": before, "after": after}));
            // The shipped databases' own names on negatives, beside what the candidate changes.
            let row = rows.last_mut().expect("row");
            row["names"] = json!(after_names);
            row["changes"] = json!(changes);
            continue;
        }
        before_total.add(before);
        after_total.add(after);
        rows.push(json!({"binary": name, "before": before, "after": after, "changes": changes}));
    }
    let gained = after_total.correct.saturating_sub(before_total.correct);
    let allowance = gained / 100;
    let passed = gained > 0
        && after_total.fp() <= before_total.fp() + allowance
        && regressions.is_empty()
        && mismatched_baselines.is_empty();
    Ok(json!({"passed": passed, "gained": gained, "allowance": allowance, "false_before": before_total.fp(),
        "false_after": after_total.fp(), "before": before_total,
        "after": after_total, "regressions": regressions, "baseline_mismatches": mismatched_baselines,
        "tier_entries": tier.as_ref().map(SignatureDb::len), "binaries": rows}))
}

/// The `*.elf` files in `directory`, sorted (none without one).
fn elf_files(directory: Option<&PathBuf>) -> Result<Vec<PathBuf>, String> {
    let Some(directory) = directory else { return Ok(Vec::new()) };
    let entries = std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "elf"))
        .collect();
    files.sort();
    Ok(files)
}

fn write_report(out: Option<&PathBuf>, report: &serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
    match out {
        Some(path) => std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display())),
        None => {
            println!("{text}");
            Ok(())
        }
    }
}

fn run(arguments: Arguments) -> Result<(), String> {
    match arguments.command {
        Command::Build { output, gzip, negatives, scheme, references } => {
            let negative = elf_files(negatives.as_ref())?;
            let database = build(&references, &negative, scheme)?;
            std::fs::write(&output, database.to_json()).map_err(|error| format!("{}: {error}", output.display()))?;
            if let Some(path) = &gzip {
                let bytes = database.to_gzip().map_err(|error| error.to_string())?;
                std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
            }
            eprintln!(
                "{} references, {} negatives: {} signatures, {} callee keys (scheme {scheme})",
                references.len(),
                negative.len(),
                database.len(),
                database.callee_keys()
            );
            Ok(())
        }
        Command::Names { candidate, call_graph, raw, image } => {
            let open = || -> Result<Binary, String> {
                match &raw {
                    Some(json) => {
                        let request: rampage_api::RawProjectRequest =
                            serde_json::from_str(json).map_err(|error| format!("--raw: {error}"))?;
                        rampage_api::open_raw_binary(&image, &request).map_err(|error| error.to_string())
                    }
                    None => Binary::open(&image).map_err(|error| error.to_string()),
                }
            };
            let tier = load_gzip(&candidate)?;
            let graph = call_graph
                .map(|path| {
                    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
                    CallGraph::from_gzip(&bytes).map_err(|error| error.to_string())
                })
                .transpose()?;
            let binary = open()?;
            let embedded = rampage_signatures::bundled_embedded_for(&binary).ok_or("not firmware")?;
            let corpus = rampage_signatures::bundled_ref(rampage_arch::Arch::Arm);
            let project = Project::new(open()?);
            project.set_packs(Arc::new(Packs::default()));
            let base: Vec<&SignatureDb> = corpus.into_iter().chain([embedded]).collect();
            let with: Vec<&SignatureDb> = corpus.into_iter().chain([embedded, &tier]).collect();
            let before = product_names(&project, &binary, &base, None)?;
            let after = product_names(&project, &binary, &with, graph.as_ref())?;
            let changed: BTreeMap<String, (Option<&String>, Option<&String>)> = before
                .keys()
                .chain(after.keys())
                .filter(|address| before.get(address) != after.get(address))
                .map(|address| (format!("{address:#x}"), (before.get(address), after.get(address))))
                .collect();
            let functions = rampage_analysis::functions::analyze(&binary).map_or(0, |program| program.functions.len());
            let report =
                json!({"functions": functions, "before": before.len(), "after": after.len(), "changed": changed});
            println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
            Ok(())
        }
        Command::Hashes { binary } => {
            let opened = Binary::open(&binary).map_err(|error| format!("{}: {error}", binary.display()))?;
            let extents = rampage_eval::discovered_extents(&opened).map_err(|error| error.to_string())?;
            let (target, image) = (opened.target(), MaskContext::from_binary(&opened));
            for (address, end) in extents {
                let bytes = opened.read(address, end - address).unwrap_or_default();
                let hash =
                    |scheme| function_hash_scheme(scheme, &target, &image, bytes, address).map(|hash| hex(&hash[..8]));
                println!(
                    "{address:#x} {end:#x} {} {}",
                    hash(LITERAL_POOL_SCHEME).unwrap_or_else(|| "-".into()),
                    hash(THUMB_OPERAND_SCHEME).unwrap_or_else(|| "-".into())
                );
            }
            Ok(())
        }
        Command::Loo { negatives, out, references } => {
            let report = loo(&references, &elf_files(negatives.as_ref())?)?;
            eprintln!("training gate passed: {}", report["passed"]);
            write_report(out.as_ref(), &report)
        }
        Command::Eval { candidate, scheme3, call_graph, negatives, out, targets } => {
            let negatives = elf_files(negatives.as_ref())?;
            let report = eval(candidate.as_deref(), scheme3.as_deref(), call_graph.as_deref(), &targets, &negatives)?;
            eprintln!(
                "dev gate passed: {} (gained {}, false positives {} -> {})",
                report["passed"], report["gained"], report["false_before"], report["false_after"]
            );
            write_report(out.as_ref(), &report)
        }
    }
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("embedded operands: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
