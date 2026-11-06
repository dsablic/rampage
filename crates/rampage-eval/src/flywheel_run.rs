//! The flywheel's commands (docs/flywheel.md): `flywheel-eval` measures a corpus split with or without a pack,
//! `flywheel` runs the agent loop through the external runner against rampage's own MCP server started with
//! `--corpus`, and `flywheel-revert` removes a promoted entry.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

use rampage_api::flywheel::{
    Arm, Corpus, Engine, FAMILY, GateConfig, Layer, NOVEL_SLICE, Paths, PromotedSet, RECOGNISED_SLICE, Split,
    SplitEvaluation, arm_directory, build_id, evaluate_split, layer, pack_layer, promoted_layer, revert,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::agent_bench_run::{DEFAULT_RUNNER, Workdir};
use super::read;

/// The fixed system prompt of every flywheel round.
pub const SYSTEM_PROMPT: &str = "\
You improve rampage's library-identification signatures through rampage's MCP `improve` tools; you have no other \
tools. The corpus holds target libraries (zlib, lz4, cJSON) in an older version, which is the training split you \
can read, and their current version, which is held out: only the gate measures it. Negative binaries of unrelated \
code must never be named. Only the target libraries' own functions are scored, not libc or compiler runtime.

The bar is a deterministic generator, not the bundled databases. Unless corpus_failures' header says otherwise, \
the baseline already holds a row for every unambiguous training body (the deterministic arm), so a plain row \
copying a training body adds nothing, and the held-out gate also requires a gain on NOVEL held-out functions: \
ones whose code changed between versions, so their bodies differ from every training body. Only a row that still \
matches after small code changes can earn that.

Work in this loop:
1. corpus_failures lists the training bodies the baseline still misses or misnames, grouped by identical masked \
body; few are left, so use `outcome: \"all\"` to list every training library body, including those the baseline \
already names (the ones to generalise), and `proposable: true` to skip bodies too short for a row. With \
`variants: true` each group also lists the same function's other training bodies (other compilers and \
optimisation levels) with their case ids and, for same-length ones, how many bytes differ.
2. Generalise. A row is a PAT byte pattern: whole-byte wildcards (`..`) and an exact module length; a pattern \
shorter than the module leaves the rest unconstrained. In propose_heuristic, `merge_cases` wildcards every byte \
where same-length training variants differ; `wildcards` and `wildcard_spans` make chosen bytes wildcards (changed \
constants, displacements, register bytes); `keep_prefix` keeps only the first N bytes. Bytes that vary across \
configurations are the likeliest to vary across versions. A body of another length never matches, so code whose \
length changed cannot be reached.
3. Keep rows safe: at least 32 explicit bytes, fixed bytes in at least half the positions. More wildcards match \
more code: read each row's train_preview (matches whose truth is another name, or not library code, are false \
positives) and drop such rows.
4. evaluate_candidate (fast stage). It fails on any new false positive in training or any name on the negatives; \
read the cases (names on negatives are listed) and drop the rows responsible.
5. evaluate_candidate with stage \"heldout\". Held-out evaluations are limited per corpus across all rounds, so \
batch several good rows per candidate and do not probe.
6. promote_candidate only when the held-out gate passed. Never try to work around the gate. Zero promotions is an \
acceptable outcome.

End with a short plain-text summary: the candidates you tried, which wildcards or generalisations they used, their \
gate results, any promotion, and why rows did or did not carry over to changed code in the held-out versions.";

#[derive(clap::Args)]
pub struct FlywheelEvalArgs {
    /// The heuristic family; only libid exists so far.
    #[arg(long, default_value = FAMILY)]
    family: String,
    /// A built corpus (target/flywheel/corpus/<version>).
    #[arg(long)]
    corpus: PathBuf,
    /// A pack to layer over the bundled databases (a scratch candidate, the promoted pack or any data pack);
    /// repeatable, the first winning. Without one, the cached baseline is measured.
    #[arg(long)]
    pack: Vec<PathBuf>,
    #[arg(long, default_value = "heldout")]
    split: String,
    /// Threads for analysis and evaluation.
    #[arg(long, default_value_t = 2)]
    workers: usize,
    /// The flywheel working directory (default: two levels above the corpus).
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    /// Changed cases kept in the JSON. A held-out evaluation keeps none.
    #[arg(long, default_value_t = 50)]
    max_cases: usize,
    /// Also write the JSON here.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct FlywheelRevertArgs {
    /// The revert id promote_candidate returned (rv-...).
    id: String,
    #[arg(long, default_value = FAMILY)]
    family: String,
    /// The flywheel working directory.
    #[arg(long, default_value = "target/flywheel")]
    flywheel_dir: PathBuf,
}

#[derive(clap::Args)]
pub struct FlywheelArgs {
    #[arg(long, default_value = FAMILY)]
    family: String,
    /// A built corpus (target/flywheel/corpus/<version>).
    #[arg(long)]
    corpus: PathBuf,
    /// Agent sessions to run; each is one runner invocation against a fresh server.
    #[arg(long, default_value_t = 3)]
    rounds: u32,
    /// Stop before a round would start with less than --min-round-usd of this left.
    #[arg(long)]
    budget_usd: f64,
    /// A round is not started with less than this much budget left.
    #[arg(long, default_value_t = 0.40)]
    min_round_usd: f64,
    #[arg(long, default_value = "claude-sonnet-5-5")]
    model: String,
    #[arg(long, default_value_t = 40)]
    max_turns: u32,
    /// Wall-clock limit per round, in seconds.
    #[arg(long, default_value_t = 1200)]
    timeout_s: u64,
    /// The runner command, split on whitespace; a relative script path resolves against the repository root.
    #[arg(long, default_value = DEFAULT_RUNNER)]
    runner: String,
    #[arg(long)]
    repository_root: Option<PathBuf>,
    /// The `rampage` CLI whose MCP server the agent drives (default: target/release/rampage).
    #[arg(long)]
    rampage_bin: Option<PathBuf>,
    /// Threads the server uses for analysis and evaluation.
    #[arg(long, default_value_t = 2)]
    workers: usize,
    /// A gate settings file passed to the server.
    #[arg(long)]
    gate: Option<PathBuf>,
    /// What candidates are gated against besides promoted rows: `arm` (bundled databases plus the deterministic
    /// arm; the default) or `bundled` (bundled databases alone, for diagnostics only).
    #[arg(long, default_value = "arm")]
    baseline: String,
    /// Require (true) or waive (false) a novel-body gain at the held-out gate; by default required against the arm
    /// baseline only.
    #[arg(long)]
    require_novel_gain: Option<bool>,
    /// A name for the run (default: run-<unix seconds>).
    #[arg(long)]
    label: Option<String>,
}

#[derive(clap::Args)]
pub struct FlywheelBaselineArgs {
    /// The heuristic family; only libid exists so far.
    #[arg(long, default_value = FAMILY)]
    family: String,
    /// A built corpus (target/flywheel/corpus/<version>).
    #[arg(long)]
    corpus: PathBuf,
    /// Threads for analysis and evaluation.
    #[arg(long, default_value_t = 2)]
    workers: usize,
    /// The flywheel working directory (default: two levels above the corpus).
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    /// A gate settings file (the arm uses its min_pattern_bytes and is gated by its rules).
    #[arg(long)]
    gate: Option<PathBuf>,
    /// Generate the arm again even when one is saved for this corpus and build.
    #[arg(long)]
    regenerate: bool,
}

fn open_engine(corpus: &Path, flywheel_dir: Option<&Path>, workers: usize) -> Result<Engine, String> {
    let corpus = Corpus::open(corpus).map_err(|error| error.to_string())?;
    let paths = match flywheel_dir {
        Some(directory) => Paths::new(directory.to_owned()),
        None => Paths::for_corpus(&corpus.root).ok_or_else(|| {
            format!("{} is not inside a corpus/ directory; pass --flywheel-dir", corpus.root.display())
        })?,
    };
    Ok(Engine::new(corpus, paths, workers))
}

fn gate_config(path: Option<&Path>) -> Result<GateConfig, String> {
    match path {
        Some(path) => GateConfig::from_toml(&read(path)?).map_err(|error| error.to_string()),
        None => Ok(GateConfig::default()),
    }
}

fn family(name: &str) -> Result<(), String> {
    if name == FAMILY { Ok(()) } else { Err(format!("unknown family {name}; this version has {FAMILY}")) }
}

/// Per-slice metrics, the deltas and the changes of one evaluation, as the commands report them.
fn evaluation_json(evaluation: &SplitEvaluation, max_cases: usize, show_cases: bool) -> Value {
    let cases: Vec<_> = if show_cases { evaluation.cases.iter().take(max_cases).collect() } else { Vec::new() };
    json!({
        "split": evaluation.split,
        "binaries": evaluation.binaries,
        "reidentified": evaluation.reidentified,
        "elapsed_ms": evaluation.elapsed_ms,
        "slices": evaluation.metrics(),
        "baseline": evaluation.reference_metrics(),
        "deltas": evaluation.deltas(),
        "fixed": evaluation.fixed,
        "broken": evaluation.broken,
        "cases_total": evaluation.cases.len(),
        "cases": cases,
    })
}

pub fn eval(args: FlywheelEvalArgs) -> Result<ExitCode, String> {
    family(&args.family)?;
    let split: Split = args.split.parse()?;
    let engine = open_engine(&args.corpus, args.flywheel_dir.as_deref(), args.workers)?;
    let started = Instant::now();
    let indices = engine.corpus.indices(split);
    let load = engine.load_all(&indices).map_err(|error| error.to_string())?;
    let mut layers: Vec<Layer> = Vec::new();
    for pack in &args.pack {
        layers.extend(pack_layer(pack).map_err(|error| format!("{}: {error}", pack.display()))?);
    }
    let evaluation = evaluate_split(&engine, split, &layers, &[]).map_err(|error| error.to_string())?;
    let mut output = evaluation_json(&evaluation, args.max_cases, true);
    if split == Split::Heldout || split == Split::Train {
        let overlap = engine.heldout_overlap().map_err(|error| error.to_string())?;
        if let Some(warning) = overlap.warning() {
            eprintln!("{warning}");
        }
        output["heldout_overlap"] = json!(overlap);
    }
    if split == Split::Heldout && !layers.is_empty() {
        output["heldout_gains"] = json!(engine.heldout_gains(&layers).map_err(|error| error.to_string())?);
    }
    output["family"] = json!(FAMILY);
    output["corpus_version"] = json!(engine.corpus.version());
    output["build_id"] = json!(build_id());
    output["packs"] = json!(args.pack);
    output["load"] = json!(load);
    output["total_ms"] = json!(started.elapsed().as_millis() as u64);
    let text = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    if let Some(path) = &args.out {
        std::fs::write(path, format!("{text}\n")).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    println!("{text}");
    for (slice, metrics) in evaluation.metrics() {
        if slice.starts_with("cell:") {
            continue;
        }
        let delta = &evaluation.deltas()[&slice];
        eprintln!(
            "{slice}: tp={} fp={} fn={} P={:.4} R={:.4} F1={:.4} (dF1 {:+.6}, dtp {:+}, dfp {:+})",
            metrics.tp,
            metrics.fp,
            metrics.fn_,
            metrics.precision,
            metrics.recall,
            metrics.f1,
            delta.f1,
            delta.tp,
            delta.fp
        );
    }
    eprintln!(
        "{} binaries ({} loaded: {} truth and {} baselines cached, {} analysed, {} ms); evaluation {} ms, {} re-identified",
        evaluation.binaries,
        load.binaries,
        load.truth_cached,
        load.baseline_cached,
        load.analysed,
        load.elapsed_ms,
        evaluation.elapsed_ms,
        evaluation.reidentified
    );
    Ok(ExitCode::SUCCESS)
}

/// The slices every reference table shows: the gated scope, then novel and recognised held-out functions.
const REFERENCE_SLICES: [&str; 3] = ["all", NOVEL_SLICE, RECOGNISED_SLICE];

fn arm_summary(arm: &Arm) -> Value {
    json!({
        "rows": arm.rows.len(),
        "rows_hash": arm.hash(),
        "stats": arm.stats,
        "build_id": arm.build_id,
        "min_pattern_bytes": arm.min_pattern_bytes,
        "elapsed_ms": arm.elapsed_ms,
    })
}

/// One metrics row of a reference table.
fn metrics_row(label: &str, scope: &str, metrics: Option<&rampage_api::flywheel::SliceMetrics>) -> String {
    match metrics {
        Some(m) => format!(
            "| {label} | {scope} | {} | {} | {} | {:.4} | {:.4} | {:.4} |\n",
            m.tp, m.fp, m.fn_, m.precision, m.recall, m.f1
        ),
        None => format!("| {label} | {scope} | - | - | - | - | - | - |\n"),
    }
}

/// The reference rows every flywheel report carries: bundled only, bundled plus the deterministic arm, and the
/// promoted rows over the arm, held out, overall and split by novel and recognised functions.
fn reference_markdown(arm_eval: &SplitEvaluation, over_arm_eval: &SplitEvaluation, report: &Value) -> String {
    let mut text = format!(
        "\n## Reference: the deterministic arm\n\nBaseline for this run: `{}` (novel-body gain required: {}). The arm \
         holds {} rows generated from the training truth.\n\n",
        report["baseline"].as_str().unwrap_or("?"),
        report["require_novel_gain"],
        report["arm"]["rows"]
    );
    text.push_str("| State | Scope | TP | FP | FN | P | R | F1 |\n|---|---|---:|---:|---:|---:|---:|---:|\n");
    let bundled = arm_eval.reference_metrics();
    let arm = arm_eval.metrics();
    let promoted = over_arm_eval.metrics();
    for slice in REFERENCE_SLICES {
        text.push_str(&metrics_row("bundled", slice, bundled.get(slice)));
        text.push_str(&metrics_row("bundled + arm", slice, arm.get(slice)));
        text.push_str(&metrics_row("bundled + arm + promoted", slice, promoted.get(slice)));
    }
    let deltas = over_arm_eval.deltas();
    let novel = deltas.get(NOVEL_SLICE);
    text.push_str(&format!(
        "\nPromoted rows over the arm, held out: overall {}, novel {}.\n",
        deltas.get("all").map_or_else(|| "-".to_owned(), |d| format!("dTP {:+} dFP {:+} dF1 {:+.6}", d.tp, d.fp, d.f1)),
        novel.map_or_else(|| "-".to_owned(), |d| format!("dTP {:+} dFP {:+} dF1 {:+.6}", d.tp, d.fp, d.f1)),
    ));
    text
}

pub fn baseline(args: FlywheelBaselineArgs) -> Result<ExitCode, String> {
    family(&args.family)?;
    let gate = gate_config(args.gate.as_deref())?;
    let engine = open_engine(&args.corpus, args.flywheel_dir.as_deref(), args.workers)?;
    let started = Instant::now();
    let all: Vec<usize> = (0..engine.corpus.manifest.binaries.len()).collect();
    let load = engine.load_all(&all).map_err(|error| error.to_string())?;
    let directory = arm_directory(&engine, gate.min_pattern_bytes);
    if args.regenerate {
        let _ = std::fs::remove_file(directory.join(rampage_api::flywheel::ARM_FILE));
    }
    let arm_started = Instant::now();
    let arm = rampage_api::flywheel::arm(&engine, gate.min_pattern_bytes).map_err(|error| error.to_string())?;
    let arm_ms = arm_started.elapsed().as_millis() as u64;
    let layers: Vec<Layer> = layer("arm", &arm.rows).map_err(|error| error.to_string())?.into_iter().collect();
    let mut evaluations = BTreeMap::new();
    for split in [Split::Fast, Split::Train, Split::Negative, Split::Heldout] {
        let evaluation = evaluate_split(&engine, split, &layers, &[]).map_err(|error| error.to_string())?;
        evaluations.insert(split, evaluation);
    }
    let fast = gate.fast(&evaluations[&Split::Fast], &evaluations[&Split::Train], &evaluations[&Split::Negative]);
    let heldout = gate.heldout(&evaluations[&Split::Heldout], gate.novel_gain_required(false));
    let gains = engine.heldout_gains(&layers).map_err(|error| error.to_string())?;
    let overlap = engine.heldout_overlap().map_err(|error| error.to_string())?;
    let reach = engine.novel_reach().map_err(|error| error.to_string())?;
    let splits: BTreeMap<&str, Value> = evaluations
        .iter()
        .map(|(split, evaluation)| {
            let pick = |metrics: BTreeMap<String, rampage_api::flywheel::SliceMetrics>| -> BTreeMap<String, Value> {
                metrics
                    .into_iter()
                    .filter(|(slice, _)| !slice.starts_with("cell:"))
                    .map(|(slice, metrics)| (slice, json!(metrics)))
                    .collect()
            };
            (
                split.name(),
                json!({
                    "binaries": evaluation.binaries,
                    "elapsed_ms": evaluation.elapsed_ms,
                    "bundled": pick(evaluation.reference_metrics()),
                    "bundled_and_arm": pick(evaluation.metrics()),
                    "deltas": evaluation.deltas().into_iter().filter(|(slice, _)| !slice.starts_with("cell:")).collect::<BTreeMap<_, _>>(),
                }),
            )
        })
        .collect();
    let report = json!({
        "schema_version": 1,
        "family": FAMILY,
        "corpus_version": engine.corpus.version(),
        "corpus_identity": engine.corpus.identity(),
        "build_id": build_id(),
        "arm": arm_summary(&arm),
        "arm_directory": directory,
        "gate": gate,
        "fast_gate": fast,
        "heldout_gate": heldout,
        "heldout_gains": gains,
        "heldout_overlap": overlap,
        "novel_reach": reach,
        "splits": splits,
        "load": load,
        "arm_ms": arm_ms,
        "total_ms": started.elapsed().as_millis() as u64,
    });
    let mut text = format!(
        "# Flywheel baseline: the deterministic arm\n\nCorpus `{}`, build `{}`. The arm holds {} rows from {} \
         training library functions ({} distinct masked bodies; dropped: {} shorter than {} bytes, {} longer than \
         a row allows, {} ambiguous names, {} colliding with other training or negative code, {} refused by the \
         row schema; {} undiscovered and {} below the confidence gate). Generated or loaded in {:.1} s.\n\n",
        engine.corpus.version(),
        build_id(),
        arm.rows.len(),
        arm.stats.training_functions,
        arm.stats.bodies,
        arm.stats.too_short,
        arm.min_pattern_bytes,
        arm.stats.too_long,
        arm.stats.ambiguous,
        arm.stats.colliding,
        arm.stats.refused,
        arm.stats.undiscovered,
        arm.stats.below_gate,
        arm_ms as f64 / 1000.0,
    );
    text.push_str(
        "| Split | State | Scope | TP | FP | FN | P | R | F1 |\n|---|---|---|---:|---:|---:|---:|---:|---:|\n",
    );
    for split in [Split::Train, Split::Heldout, Split::Negative] {
        let evaluation = &evaluations[&split];
        let (bundled, armed) = (evaluation.reference_metrics(), evaluation.metrics());
        for slice in REFERENCE_SLICES {
            if split != Split::Heldout && slice != "all" {
                continue;
            }
            for (label, metrics) in [("bundled", &bundled), ("bundled + arm", &armed)] {
                text.push_str(&format!("| {} {}", split.name(), metrics_row(label, slice, metrics.get(slice))));
            }
        }
    }
    text.push_str(&format!(
        "\nGate on the arm against the bundled databases: fast {} ({}), held-out {} ({}).\n\
         Held-out functions the arm newly names: {} whose body training holds, {} novel.\n\
         Held-out overlap: {} of {} held-out library bodies ({:.1}%) also occur in training.\n\n\
         Novel reach (operator only; reads held-out truth): of {} novel held-out library functions, {} have a masked \
         body, {} a training body of the same name and architecture, {} one of exactly the same length (the only \
         ones a PAT row, which binds the module length, can reach), and {} would merge with it into a row the schema \
         accepts. Differing bytes against the closest same-length training body: {}.\n",
        if fast.passed { "passed" } else { "failed" },
        fast.checks
            .iter()
            .map(|check| format!("{} {}", check.rule, if check.passed { "ok" } else { "FAILED" }))
            .collect::<Vec<_>>()
            .join(", "),
        if heldout.passed { "passed" } else { "failed" },
        heldout.checks.iter().map(|check| format!("{}: {}", check.rule, check.detail)).collect::<Vec<_>>().join("; "),
        gains.seen_in_training,
        gains.novel,
        overlap.in_training,
        overlap.heldout_bodies,
        overlap.fraction * 100.0,
        reach.novel,
        reach.maskable,
        reach.same_name,
        reach.same_length,
        reach.mergeable,
        reach.differing_bytes.iter().map(|(bucket, count)| format!("{bucket}: {count}")).collect::<Vec<_>>().join(", "),
    ));
    let pretty = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    std::fs::write(directory.join("report.json"), format!("{pretty}\n")).map_err(|error| error.to_string())?;
    std::fs::write(directory.join("report.md"), &text).map_err(|error| error.to_string())?;
    println!("{text}");
    eprintln!("report: {}", directory.join("report.md").display());
    Ok(ExitCode::SUCCESS)
}

pub fn revert_entry(args: FlywheelRevertArgs) -> Result<ExitCode, String> {
    family(&args.family)?;
    let paths = Paths::new(args.flywheel_dir.clone());
    let entry = revert(&paths, &args.family, &args.id).map_err(|error| error.to_string())?;
    println!(
        "{}",
        json!({
            "reverted": entry.revert_id,
            "candidate": entry.candidate_id,
            "candidate_hash": entry.candidate_hash,
            "rows": entry.rows.len(),
            "pack": paths.promoted(&args.family),
        })
    );
    Ok(ExitCode::SUCCESS)
}

/// One JSON-RPC exchange with a `rampage mcp` child over stdio: initialize, then each call in turn.
fn mcp_session(command: &Path, args: &[String], calls: &[(&str, Value)]) -> Result<Vec<Value>, String> {
    let mut child = Command::new(command)
        .args(args)
        .env("RAMPAGE_MCP_TOOLS", "improve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("{}: {error}", command.display()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let mut stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let mut send = |message: Value| -> Result<(), String> {
        writeln!(stdin, "{message}").map_err(|error| error.to_string())?;
        stdin.flush().map_err(|error| error.to_string())
    };
    let mut receive = |id: u64| -> Result<Value, String> {
        let mut line = String::new();
        loop {
            line.clear();
            if stdout.read_line(&mut line).map_err(|error| error.to_string())? == 0 {
                return Err("the MCP server closed its output".to_owned());
            }
            let Ok(message) = serde_json::from_str::<Value>(&line) else { continue };
            if message.get("id") == Some(&json!(id)) {
                return Ok(message);
            }
        }
    };
    send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "rampage-eval", "version": "1"}}}))?;
    receive(0)?;
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    let mut results = Vec::new();
    for (index, (name, arguments)) in calls.iter().enumerate() {
        let id = index as u64 + 1;
        send(
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}),
        )?;
        results.push(receive(id)?);
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(results)
}

/// The text of a tool result, parsed as JSON when it is.
fn tool_output(response: &Value) -> (bool, Value) {
    let result = &response["result"];
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    let error = result["isError"].as_bool().unwrap_or(false);
    (error, serde_json::from_str(text).unwrap_or_else(|_| json!(text)))
}

fn events(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .map(|text| text.lines().filter_map(|line| serde_json::from_str(line).ok()).collect())
        .unwrap_or_default()
}

/// The rounds so far, in the words the next round's prompt gives them: only training-split facts and held-out
/// metrics, as the tools returned them.
fn history(rounds: &[Value]) -> String {
    if rounds.is_empty() {
        return "This is the first round.".to_owned();
    }
    let mut text = String::from("Earlier rounds (their candidates stay in the scratch area; promotions are live):\n");
    for round in rounds {
        text.push_str(&format!("- round {}:", round["round"]));
        let candidates = round["candidates"].as_array().cloned().unwrap_or_default();
        if candidates.is_empty() {
            text.push_str(" no candidate evaluated.");
        }
        for candidate in candidates {
            text.push_str(&format!(
                " candidate {} ({} rows): fast {}, heldout {}{};",
                candidate["candidate"].as_str().unwrap_or("?"),
                candidate["rows"],
                candidate["fast_passed"],
                candidate["heldout_passed"],
                candidate["promoted"].as_str().map(|id| format!(", promoted as {id}")).unwrap_or_default()
            ));
        }
        text.push('\n');
    }
    text
}

/// What one round did, read from the server's event log.
fn round_candidates(events: &[Value]) -> Vec<Value> {
    let mut candidates: BTreeMap<String, Value> = BTreeMap::new();
    for event in events {
        let detail = &event["detail"];
        let Some(id) = detail["candidate"].as_str() else { continue };
        let entry = candidates.entry(id.to_owned()).or_insert_with(|| json!({"candidate": id}));
        match event["tool"].as_str() {
            Some("propose_heuristic") => entry["rows"] = detail["rows"].clone(),
            Some("evaluate_candidate") => {
                entry["rows"] = detail["rows"].clone();
                entry["candidate_hash"] = detail["candidate_hash"].clone();
                entry["fast_passed"] = detail["fast"]["passed"].clone();
                entry["fast_deltas"] = detail["fast"]["deltas"].clone();
                entry["fast_elapsed_ms"] = detail["fast_elapsed_ms"].clone();
                if !detail["heldout"].is_null() {
                    entry["heldout_passed"] = detail["heldout"]["passed"].clone();
                    entry["heldout_checks"] = detail["heldout"]["checks"].clone();
                    entry["heldout_deltas"] = detail["heldout"]["deltas"].clone();
                    entry["heldout_elapsed_ms"] = detail["heldout"]["elapsed_ms"].clone();
                }
            }
            Some("promote_candidate") => match detail["revert_id"].as_str() {
                Some(revert) => entry["promoted"] = json!(revert),
                None => entry["promotion_refused"] = detail["refused"].clone(),
            },
            _ => {}
        }
    }
    candidates.into_values().collect()
}

/// Reverts, latest first, every promotion a round's proposer run made.
fn revert_round(paths: &Paths, run_id: &str) -> Result<Vec<String>, String> {
    let set = PromotedSet::load(paths, FAMILY).map_err(|error| error.to_string())?;
    let mut reverted = Vec::new();
    for entry in set.entries.iter().rev() {
        if entry.proposer_run.as_deref() != Some(run_id) {
            break;
        }
        revert(paths, FAMILY, &entry.revert_id).map_err(|error| error.to_string())?;
        reverted.push(entry.revert_id.clone());
    }
    Ok(reverted)
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

pub fn run(args: FlywheelArgs) -> Result<ExitCode, String> {
    family(&args.family)?;
    if !args.budget_usd.is_finite() || args.budget_usd <= 0.0 {
        return Err("--budget-usd must be positive".to_owned());
    }
    let root = args.repository_root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let root = std::fs::canonicalize(&root).map_err(|error| format!("{}: {error}", root.display()))?;
    let corpus_dir =
        std::fs::canonicalize(&args.corpus).map_err(|error| format!("{}: {error}", args.corpus.display()))?;
    let engine = open_engine(&corpus_dir, None, args.workers)?;
    let paths = engine.paths.clone();
    let rampage = args.rampage_bin.clone().unwrap_or_else(|| root.join("target/release/rampage"));
    let rampage = std::fs::canonicalize(&rampage).map_err(|error| format!("{}: {error}", rampage.display()))?;
    let label = args.label.clone().unwrap_or_else(|| {
        format!("run-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    });
    let out_dir = paths.runs().join(&label);
    std::fs::create_dir_all(&out_dir).map_err(|error| format!("{}: {error}", out_dir.display()))?;
    let started = Instant::now();
    let promoted_before: Vec<String> = PromotedSet::load(&paths, FAMILY)
        .map_err(|error| error.to_string())?
        .entries
        .iter()
        .map(|entry| entry.revert_id.clone())
        .collect();

    // The server arguments every round shares.
    let mut server_args = vec![
        "mcp".to_owned(),
        "--corpus".to_owned(),
        corpus_dir.display().to_string(),
        "--flywheel-workers".to_owned(),
        args.workers.to_string(),
    ];
    if let Some(gate) = &args.gate {
        let gate = std::fs::canonicalize(gate).map_err(|error| format!("{}: {error}", gate.display()))?;
        server_args.extend(["--gate".to_owned(), gate.display().to_string()]);
    }
    let baseline_kind: rampage_api::flywheel::Baseline = args.baseline.parse()?;
    server_args.extend(["--flywheel-baseline".to_owned(), baseline_kind.name().to_owned()]);
    if let Some(required) = args.require_novel_gain {
        server_args.extend(["--require-novel-gain".to_owned(), required.to_string()]);
    }
    let gate = gate_config(args.gate.as_deref())?;
    let gate = GateConfig { require_novel_gain: args.require_novel_gain.or(gate.require_novel_gain), ..gate };
    let arm_baseline = baseline_kind == rampage_api::flywheel::Baseline::Arm;

    // Warm the server's truth and baseline caches once, through the same MCP surface, before any model runs.
    let warm_started = Instant::now();
    let mut warm_args = server_args.clone();
    warm_args.extend(["--flywheel-run".to_owned(), format!("{label}/warmup")]);
    let warm = mcp_session(&rampage, &warm_args, &[("corpus_failures", json!({"limit": 5, "include_bytes": false}))])?;
    let (warm_error, warm_output) = tool_output(&warm[0]);
    if warm_error {
        return Err(format!("warm-up corpus_failures failed: {warm_output}"));
    }
    let warmup_ms = warm_started.elapsed().as_millis() as u64;
    eprintln!(
        "warm-up: {warmup_ms} ms; {} training failure groups, {} undiscovered, {} below the gate",
        warm_output["groups_total"], warm_output["undiscovered"], warm_output["below_gate"]
    );

    let system_path = out_dir.join("system.txt");
    std::fs::write(&system_path, SYSTEM_PROMPT).map_err(|error| error.to_string())?;
    let mut runner: Vec<PathBuf> = args.runner.split_whitespace().map(PathBuf::from).collect();
    if runner.is_empty() {
        return Err("empty runner command".to_owned());
    }
    for part in runner.iter_mut().skip(1) {
        if part.extension().is_some_and(|extension| extension == "py" || extension == "sh") && part.is_relative() {
            *part = root.join(&*part);
        }
    }
    let mut rounds: Vec<Value> = Vec::new();
    let mut spent = 0.0;
    let mut stop = "rounds exhausted".to_owned();
    for round in 1..=args.rounds {
        let left = args.budget_usd - spent;
        if left < args.min_round_usd {
            stop = format!("budget: ${left:.2} left, below the ${:.2} a round needs", args.min_round_usd);
            break;
        }
        let round_dir = out_dir.join(format!("round-{round}"));
        std::fs::create_dir_all(&round_dir).map_err(|error| error.to_string())?;
        let run_id = format!("{label}/round-{round}");
        let mut round_args = server_args.clone();
        round_args.extend(["--flywheel-run".to_owned(), run_id.clone()]);
        let config = json!({"mcpServers": {"rampage": {"type": "stdio", "command": rampage, "args": round_args,
            "env": {"RAMPAGE_MCP_TOOLS": "improve"}}}});
        let config_path = round_dir.join("mcp.json");
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        let prompt = format!(
            "Round {round} of {} of the library-identification flywheel. Budget left for the whole run: about \
             ${left:.2}. {}\nStart with corpus_failures, then follow the loop.",
            args.rounds,
            history(&rounds)
        );
        let prompt_path = round_dir.join("prompt.txt");
        std::fs::write(&prompt_path, &prompt).map_err(|error| error.to_string())?;
        // A private directory outside the repository, so the session sees no project file or memory.
        let workdir = Workdir::new()?;
        let result_path = round_dir.join("result.json");
        let round_started = Instant::now();
        let status = Command::new(&runner[0])
            .args(&runner[1..])
            .arg("--mcp-config")
            .arg(&config_path)
            .args(["--server-name", "rampage"])
            .arg("--prompt-file")
            .arg(&prompt_path)
            .arg("--system-file")
            .arg(&system_path)
            .args(["--model", &args.model])
            .args(["--max-turns", &args.max_turns.to_string()])
            .args(["--timeout-s", &args.timeout_s.to_string()])
            .args(["--max-budget-usd", &format!("{left:.4}")])
            .arg("--workdir")
            .arg(&workdir.path)
            .arg("--out")
            .arg(&result_path)
            .arg("--transcript")
            .arg(round_dir.join("transcript.jsonl"))
            .status()
            .map_err(|error| format!("runner {}: {error}", runner[0].display()))?;
        let wall_ms = round_started.elapsed().as_millis() as u64;
        let result: Value = read(&result_path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .ok_or_else(|| format!("runner exited {status} without a result"))?;
        let cost = result["cost_usd"].as_f64().unwrap_or(0.0);
        spent += cost;
        let calls = result["tool_calls"].as_array().cloned().unwrap_or_default();
        let mut by_tool: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
        for call in &calls {
            let name = call["name"].as_str().unwrap_or("?").trim_start_matches("mcp__rampage__").to_owned();
            let entry = by_tool.entry(name).or_default();
            entry.0 += 1;
            entry.1 += call["duration_ms"].as_u64().unwrap_or(0);
            entry.2 += u64::from(call["is_error"].as_bool().unwrap_or(false));
        }
        let tool_ms: u64 = by_tool.values().map(|(_, ms, _)| ms).sum();
        let round_events = events(&paths.runs().join(&run_id).join("events.jsonl"));
        let candidates = round_candidates(&round_events);
        let summary = json!({
            "round": round,
            "exit": result["exit"],
            "error": result["error"],
            "wall_ms": wall_ms,
            "tool_ms": tool_ms,
            "model_and_client_ms": wall_ms.saturating_sub(tool_ms),
            "cost_usd": cost,
            "usage": result["usage"],
            "turns": result["turns"],
            "calls": calls.len(),
            "calls_by_tool": by_tool.iter().map(|(name, (count, ms, errors))| (name.clone(), json!({"calls": count, "ms": ms, "errors": errors}))).collect::<BTreeMap<_, _>>(),
            "candidates": candidates,
            "answer": result["answer"].as_str().map(|text| text.chars().take(2000).collect::<String>()),
        });
        eprintln!(
            "round {round}: {} in {:.1}s, ${cost:.3} (total ${spent:.3}), {} calls, {} candidates",
            result["exit"].as_str().unwrap_or("?"),
            wall_ms as f64 / 1000.0,
            calls.len(),
            summary["candidates"].as_array().map_or(0, Vec::len)
        );
        let failed = result["exit"].as_str() != Some("ok");
        rounds.push(summary);
        if failed {
            // A round that did not finish cleanly, isolation failures included, keeps nothing it promoted.
            let reverted = revert_round(&paths, &run_id)?;
            if let Some(last) = rounds.last_mut() {
                last["reverted_promotions"] = json!(reverted);
            }
            stop = format!(
                "round {round} ended `{}` ({}); its {} promotions were reverted",
                result["exit"].as_str().unwrap_or("?"),
                result["error"].as_str().unwrap_or("no error text"),
                reverted.len()
            );
            break;
        }
        if spent >= args.budget_usd {
            stop = format!("budget: ${spent:.2} spent of ${:.2}", args.budget_usd);
            break;
        }
    }

    // The outcome, measured by the evaluator itself: held-out metrics with the promoted pack against the baseline.
    let promoted = PromotedSet::load(&paths, FAMILY).map_err(|error| error.to_string())?;
    let new_promotions: Vec<&rampage_api::flywheel::PromotedEntry> =
        promoted.entries.iter().filter(|entry| !promoted_before.contains(&entry.revert_id)).collect();
    let layers: Vec<Layer> = promoted_layer(&promoted).map_err(|error| error.to_string())?.into_iter().collect();
    let final_eval = evaluate_split(&engine, Split::Heldout, &layers, &[]).map_err(|error| error.to_string())?;
    // The reference row: the deterministic arm against the bundled databases, and the promoted rows on top of the
    // arm (what the gate measured them against when the arm is the baseline).
    let arm = rampage_api::flywheel::arm(&engine, gate.min_pattern_bytes).map_err(|error| error.to_string())?;
    let arm_layers: Vec<Layer> = layer("arm", &arm.rows).map_err(|error| error.to_string())?.into_iter().collect();
    let arm_eval = evaluate_split(&engine, Split::Heldout, &arm_layers, &[]).map_err(|error| error.to_string())?;
    let mut over_arm = arm.rows.clone();
    over_arm.extend(promoted.rows());
    let over_arm_layers: Vec<Layer> =
        layer("arm+promoted", &over_arm).map_err(|error| error.to_string())?.into_iter().collect();
    let over_arm_eval =
        evaluate_split(&engine, Split::Heldout, &over_arm_layers, &arm_layers).map_err(|error| error.to_string())?;
    let report = json!({
        "schema_version": 1,
        "family": FAMILY,
        "label": label,
        "corpus_version": engine.corpus.version(),
        "model": args.model,
        "runner": args.runner,
        "rampage_bin": rampage,
        "server_args": server_args,
        "system_prompt_sha256": hex(&Sha256::digest(SYSTEM_PROMPT.as_bytes())),
        "budget_usd": args.budget_usd,
        "spent_usd": spent,
        "rounds_requested": args.rounds,
        "rounds_run": rounds.len(),
        "stop": stop,
        "warmup_ms": warmup_ms,
        "heldout_overlap": engine.heldout_overlap().map_err(|error| error.to_string())?,
        "heldout_gains": engine.heldout_gains(&layers).map_err(|error| error.to_string())?,
        "total_ms": started.elapsed().as_millis() as u64,
        "rounds": rounds,
        "promotions": new_promotions.iter().map(|entry| json!({
            "revert_id": entry.revert_id, "candidate": entry.candidate_id, "rows": entry.rows.len(),
            "heldout_deltas": entry.heldout_deltas.get("all"), "heldout_checks": entry.heldout.checks,
        })).collect::<Vec<_>>(),
        "promoted_pack_heldout": evaluation_json(&final_eval, 0, false),
        "baseline": baseline_kind.name(),
        "require_novel_gain": gate.novel_gain_required(arm_baseline),
        "arm": arm_summary(&arm),
        "arm_heldout": evaluation_json(&arm_eval, 0, false),
        "promoted_over_arm_heldout": evaluation_json(&over_arm_eval, 0, false),
    });
    let pretty = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::write(out_dir.join("report.json"), format!("{pretty}\n")).map_err(|error| error.to_string())?;
    let mut markdown = markdown(&report, &final_eval);
    markdown.push_str(&reference_markdown(&arm_eval, &over_arm_eval, &report));
    std::fs::write(out_dir.join("report.md"), &markdown).map_err(|error| error.to_string())?;
    println!("{markdown}");
    eprintln!("report: {}", out_dir.join("report.md").display());
    Ok(ExitCode::SUCCESS)
}

fn markdown(report: &Value, final_eval: &SplitEvaluation) -> String {
    let mut text = format!(
        "# Flywheel run {}\n\nFamily `{}`, corpus `{}`, model `{}`. Spent ${:.3} of ${:.2} over {} of {} rounds; stopped: {}.\n\
         Warm-up (truth and baseline caches through the server) {:.1} s; whole run {:.1} s.\n\n",
        report["label"].as_str().unwrap_or("?"),
        report["family"].as_str().unwrap_or("?"),
        report["corpus_version"].as_str().unwrap_or("?"),
        report["model"].as_str().unwrap_or("?"),
        report["spent_usd"].as_f64().unwrap_or(0.0),
        report["budget_usd"].as_f64().unwrap_or(0.0),
        report["rounds_run"],
        report["rounds_requested"],
        report["stop"].as_str().unwrap_or("?"),
        report["warmup_ms"].as_f64().unwrap_or(0.0) / 1000.0,
        report["total_ms"].as_f64().unwrap_or(0.0) / 1000.0,
    );
    let overlap = &report["heldout_overlap"];
    text.push_str(&format!(
        "Held-out overlap: {} of {} held-out library bodies ({:.1}%) also occur in training (limit {:.0}%).\n\n",
        overlap["in_training"],
        overlap["heldout_bodies"],
        overlap["fraction"].as_f64().unwrap_or(0.0) * 100.0,
        overlap["limit"].as_f64().unwrap_or(0.0) * 100.0
    ));
    text.push_str("| Round | Exit | Wall s | Tool s | Cost $ | Calls | Candidates (fast / held-out / promoted) |\n");
    text.push_str("|---|---|---:|---:|---:|---:|---|\n");
    for round in report["rounds"].as_array().into_iter().flatten() {
        let candidates: Vec<String> = round["candidates"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|candidate| {
                format!(
                    "{} ({} rows): {} / {} / {}",
                    candidate["candidate"].as_str().unwrap_or("?"),
                    candidate["rows"],
                    candidate["fast_passed"],
                    candidate["heldout_passed"],
                    candidate["promoted"].as_str().unwrap_or("-")
                )
            })
            .collect();
        text.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.3} | {} | {} |\n",
            round["round"],
            round["exit"].as_str().unwrap_or("?"),
            round["wall_ms"].as_f64().unwrap_or(0.0) / 1000.0,
            round["tool_ms"].as_f64().unwrap_or(0.0) / 1000.0,
            round["cost_usd"].as_f64().unwrap_or(0.0),
            round["calls"],
            if candidates.is_empty() { "none".to_owned() } else { candidates.join("; ") }
        ));
    }
    let promotions = report["promotions"].as_array().cloned().unwrap_or_default();
    text.push_str(&format!("\nPromotions this run: {}.\n", promotions.len()));
    for promotion in &promotions {
        text.push_str(&format!(
            "- `{}` (candidate {}, {} rows): held-out {}\n",
            promotion["revert_id"].as_str().unwrap_or("?"),
            promotion["candidate"].as_str().unwrap_or("?"),
            promotion["rows"],
            promotion["heldout_deltas"]
        ));
    }
    let gains = &report["heldout_gains"];
    text.push_str(&format!(
        "\nHeld-out library functions newly named by the promoted pack: {} whose body training already held \
         (unchanged across versions) and {} novel bodies {}.\n",
        gains["seen_in_training"], gains["novel"], gains["novel_names"]
    ));
    text.push_str(
        "\nHeld-out split with the promoted pack against the bundled baseline. Gated slices score the target \
         libraries' functions plus every false name; `origin:` slices report every outcome by origin and are not \
         gated:\n\n",
    );
    text.push_str("| Slice | TP | FP | FN | F1 | dF1 | dTP | dFP |\n|---|---:|---:|---:|---:|---:|---:|---:|\n");
    let deltas = final_eval.deltas();
    for (slice, metrics) in final_eval.metrics() {
        if slice.starts_with("cell:") {
            continue;
        }
        let delta = &deltas[&slice];
        text.push_str(&format!(
            "| {slice} | {} | {} | {} | {:.4} | {:+.6} | {:+} | {:+} |\n",
            metrics.tp, metrics.fp, metrics.fn_, metrics.f1, delta.f1, delta.tp, delta.fp
        ));
    }
    text.push_str("\nRevert a promotion with `rampage-eval flywheel-revert <revert id>`.\n");
    text
}
