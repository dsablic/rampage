//! The code loop, unattended, as a source change (step 3 of docs/plans/2026-11-20-flywheel-next.md;
//! docs/flywheel.md, "The code loop"). `flywheel-code-run` gives an agent a fresh worktree of rampage at a base
//! commit, the training split with its truth, and a gate it can call; afterwards it runs the same gate
//! authoritatively on the change, and a full pass earns one ledgered read of the final split. `flywheel-code-names`
//! is the gate's identification step: the build under test names every binary of one split and nothing else.
//!
//! Trust: the harness process (this binary) holds the truth and scores. Everything the agent's code can influence
//! runs inside a macOS sandbox that cannot read the corpus or the flywheel directory: the session, the build and the
//! tests of its change, and identification with the changed matcher, which reads a corpus view holding only the
//! stripped binaries of the split it names (and the training split's truth).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rampage_api::flywheel::code::{SplitNames, proposals, split_names};
use rampage_api::flywheel::{
    Corpus, Engine, FAMILY, GateCheck, GateConfig, GateResult, Paths, Role, Split, SplitEvaluation, build_id, compare,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::agent_bench_run::DEFAULT_RUNNER;
use super::flywheel_code_workspace::{
    Diff, LIBID_ALLOWLIST, Sandbox, add_worktree, apply_diff, canonical, capture_diff, gate_client, git, make_view,
    output, policy_violations, remove_worktree, resolve_commit,
};
use super::flywheel_run::{gate_config, next_final_read, open_engine, record_final_read_with};

/// The most a run may spend on its family: the plan's $5 per family per run.
pub const MAX_BUDGET_USD: f64 = 5.0;

/// The splits the gate scores before a final read.
const GATED: [Split; 3] = [Split::Train, Split::Heldout, Split::Negative];

/// Changed training and negative cases an answer lists.
const MAX_CASES: usize = 40;

/// A family the code loop can run: what the agent may change and which crate's tests gate it.
struct Family {
    name: &'static str,
    allowlist: &'static [&'static str],
    test_crate: &'static str,
}

const LIBID: Family = Family { name: FAMILY, allowlist: LIBID_ALLOWLIST, test_crate: "rampage-signatures" };

fn family(name: &str) -> Result<&'static Family, String> {
    if name == LIBID.name { Ok(&LIBID) } else { Err(format!("unknown family {name}; the code loop has {FAMILY}")) }
}

#[derive(clap::Args)]
pub struct CodeNamesArgs {
    /// A corpus or a corpus view (see `flywheel-code-run`).
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long)]
    split: String,
    /// The names file to write.
    #[arg(long)]
    out: PathBuf,
    /// The working directory holding the discovery cache.
    #[arg(long)]
    flywheel_dir: PathBuf,
    /// Use the discovery the build with this id cached instead of analysing (a candidate reads the base's).
    #[arg(long)]
    discovery_key: Option<String>,
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

/// `flywheel-code-names`: this build's names for every binary of one split.
pub fn names(args: CodeNamesArgs) -> Result<ExitCode, String> {
    let split: Split = args.split.parse()?;
    let corpus = Corpus::open(&args.corpus).map_err(|error| error.to_string())?;
    let mut engine = Engine::new(corpus, Paths::new(args.flywheel_dir.clone()), args.workers);
    if let Some(key) = &args.discovery_key {
        engine = engine.with_discovery_key(key);
    }
    let started = Instant::now();
    let names = split_names(&engine, split).map_err(|error| error.to_string())?;
    let text = serde_json::to_string(&names).map_err(|error| error.to_string())?;
    std::fs::write(&args.out, text).map_err(|error| format!("{}: {error}", args.out.display()))?;
    eprintln!(
        "{} {} binaries named by {} in {} ms ({} call graph)",
        names.binaries.len(),
        split.name(),
        names.build_id,
        started.elapsed().as_millis(),
        names.call_graph
    );
    Ok(ExitCode::SUCCESS)
}

#[derive(clap::Args)]
pub struct CodeRunArgs {
    /// The heuristic family; only libid exists so far.
    #[arg(long, default_value = FAMILY)]
    family: String,
    /// A built corpus (target/flywheel/corpus/<version>).
    #[arg(long)]
    corpus: PathBuf,
    /// The commit the session's worktree starts from and the change is measured against.
    #[arg(long, default_value = "HEAD")]
    base: String,
    /// The session's cost cap (claude --max-budget-usd); at most $5, the plan's cap per family per run.
    #[arg(long, default_value_t = MAX_BUDGET_USD)]
    budget_usd: f64,
    #[arg(long, default_value = "claude-sonnet-5-5")]
    model: String,
    #[arg(long, default_value_t = 200)]
    max_turns: u32,
    /// The session's wall-clock cap, in seconds; the authoritative gate runs after it.
    #[arg(long, default_value_t = 5400)]
    timeout_s: u64,
    /// Gate calls the session may make; each answers with the dev verdict and overall delta, so they are bounded.
    #[arg(long, default_value_t = 8)]
    max_session_gates: usize,
    /// A gate settings file (defaults: dev gain 0.001 F1, one false positive per 100 correct names gained, none on
    /// training or the negatives, no slice losing F1).
    #[arg(long)]
    gate: Option<PathBuf>,
    /// Identification with the change may take at most this many times the base's on any binary...
    #[arg(long, default_value_t = 4.0)]
    time_ratio: f64,
    /// ...or the base's plus this many milliseconds, whichever is more.
    #[arg(long, default_value_t = 1000)]
    time_floor_ms: u64,
    /// Threads for analysis, identification and scoring.
    #[arg(long, default_value_t = 6)]
    workers: usize,
    /// A name for the run (default: code-<unix seconds>).
    #[arg(long)]
    label: Option<String>,
    /// The flywheel working directory (default: two levels above the corpus).
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    /// Where the session's worktree, target directory and training view go (default: the system temp directory).
    /// It must lie outside the corpus and the flywheel directory, which the session cannot read.
    #[arg(long)]
    session_root: Option<PathBuf>,
    /// The gate's directory, kept across runs so builds stay incremental: its worktree (`worktree/`, reset to the
    /// base at every run) and cargo target directory (`target/`). One run holds it at a time (default:
    /// <flywheel>/code-runs/gate).
    #[arg(long)]
    gate_dir: Option<PathBuf>,
    /// The runner command, split on whitespace; a relative script path resolves against the repository root.
    #[arg(long, default_value = DEFAULT_RUNNER)]
    runner: String,
    /// The repository the worktrees are made from (default: the one this binary was built from).
    #[arg(long)]
    repository_root: Option<PathBuf>,
    /// Instead of an agent session, run this shell script in the session's sandbox and worktree (it may apply a
    /// patch and call `flywheel-gate`). Spends nothing; implies --final-dry-run.
    #[arg(long)]
    session_script: Option<PathBuf>,
    /// After a full pass, report what the final read would read without reading it or writing the ledger.
    #[arg(long)]
    final_dry_run: bool,
    /// Appended to the reason the final ledger records.
    #[arg(long)]
    final_reason: Option<String>,
    /// More paths the session and the agent's code may not read (repeatable).
    #[arg(long)]
    deny_read: Vec<PathBuf>,
    /// Skip the fuzzy 0.95/0.05 reference column (it re-analyses every binary once per base).
    #[arg(long)]
    no_fuzzy_reference: bool,
    /// Keep the worktrees, views and binaries (for debugging the harness).
    #[arg(long)]
    keep_workspace: bool,
}

/// One gate stage's verdict.
#[derive(Debug, Clone, Serialize)]
struct Stage {
    stage: String,
    passed: bool,
    detail: String,
}

fn stage(name: &str, passed: bool, detail: impl Into<String>) -> Stage {
    Stage { stage: name.to_owned(), passed, detail: detail.into() }
}

/// One binary over the time bound.
#[derive(Debug, Clone, Serialize)]
struct Slow {
    split: String,
    binary: String,
    base_us: u64,
    candidate_us: u64,
    bound_us: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
struct TimeCheck {
    passed: bool,
    binaries: usize,
    base_total_us: u64,
    candidate_total_us: u64,
    /// The binary with the highest candidate-to-base ratio.
    worst: Option<Slow>,
    over: Vec<Slow>,
}

/// A gate run: the stages, and for the operator every split's evaluation and every rule's check.
#[derive(Debug, Clone, Serialize)]
struct GateRun {
    passed: bool,
    diff_sha256: String,
    paths: Vec<String>,
    stages: Vec<Stage>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    evaluations: BTreeMap<String, SplitEvaluation>,
    checks: Vec<GateCheck>,
    failing_slices: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<TimeCheck>,
    /// The end of a failed build's or test run's log.
    #[serde(skip_serializing_if = "Option::is_none")]
    log_tail: Option<String>,
    /// The candidate binary, when one was built.
    #[serde(skip)]
    binary: Option<PathBuf>,
    elapsed_ms: u64,
}

impl GateRun {
    fn new(diff: &Diff) -> GateRun {
        GateRun {
            passed: false,
            diff_sha256: diff.sha256(),
            paths: diff.paths.clone(),
            stages: Vec::new(),
            evaluations: BTreeMap::new(),
            checks: Vec::new(),
            failing_slices: Vec::new(),
            time: None,
            log_tail: None,
            binary: None,
            elapsed_ms: 0,
        }
    }

    fn failed_at(&self) -> Option<&str> {
        self.stages.iter().find(|stage| !stage.passed).map(|stage| stage.stage.as_str())
    }
}

/// Everything a gate run needs.
struct Harness<'a> {
    base: String,
    run_dir: PathBuf,
    gate_worktree: PathBuf,
    gate_target: PathBuf,
    views: Views,
    engine: &'a Engine,
    gate: GateConfig,
    base_names: BTreeMap<Split, SplitNames>,
    base_binary: PathBuf,
    sandbox: Sandbox,
    family: &'static Family,
    cargo: PathBuf,
    nextest: bool,
    time_ratio: f64,
    time_floor_us: u64,
    /// One gate at a time: they share the gate worktree.
    busy: Mutex<()>,
}

/// The `program` an absolute path names, or the first match on PATH.
fn find_program(program: &str) -> Result<PathBuf, String> {
    let path = Path::new(program);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let search = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&search)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{program} is not on PATH"))
}

/// Runs `command` with its output in `log`, stopping it (and its process group) after `limit`. Whether it
/// succeeded in time. Output goes through pipes this process copies: a sandboxed command may not write the log's
/// directory, and the sandbox checks writes to an inherited file too.
fn run_logged(command: &mut Command, log: &Path, limit: Duration) -> Result<bool, String> {
    use std::os::unix::process::CommandExt;
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let file = std::sync::Arc::new(Mutex::new(file));
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let shown = format!("{command:?}");
    let mut child = command.spawn().map_err(|error| format!("{shown}: {error}"))?;
    let copy = |mut source: Box<dyn std::io::Read + Send>| {
        let file = std::sync::Arc::clone(&file);
        std::thread::spawn(move || {
            use std::io::Write;
            let mut buffer = vec![0; 1 << 16];
            while let Ok(read) = source.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let mut file = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = file.write_all(&buffer[..read]);
            }
        })
    };
    let mut copiers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        copiers.push(copy(Box::new(stdout)));
    }
    if let Some(stderr) = child.stderr.take() {
        copiers.push(copy(Box::new(stderr)));
    }
    let started = Instant::now();
    let succeeded = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status.success();
        }
        if started.elapsed() > limit {
            kill_group(child.id());
            let _ = child.wait();
            let note = format!("\n[stopped after {} s]\n", limit.as_secs());
            let mut file = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = std::io::Write::write_all(&mut *file, note.as_bytes());
            break false;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    for copier in copiers {
        let _ = copier.join();
    }
    Ok(succeeded)
}

fn kill_group(pid: u32) {
    for signal in ["-TERM", "-KILL"] {
        let _ = Command::new("kill").arg(signal).arg(format!("-{pid}")).status();
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// The last `lines` lines of a log.
fn tail(log: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, format!("{text}\n")).map_err(|error| format!("{}: {error}", path.display()))
}

/// The corpus views of a run (one directory per split) and the discovery cache the builds under test share.
struct Views {
    root: PathBuf,
    workers: usize,
}

impl Views {
    fn dir(&self, split: Split) -> PathBuf {
        self.root.join(split.name())
    }

    fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }
}

/// One build of rampage-eval naming one split inside the sandbox, from the split's corpus view.
fn sandboxed_names(
    sandbox: &Sandbox,
    binary: &Path,
    views: &Views,
    split: Split,
    out_dir: &Path,
    discovery_key: Option<&str>,
) -> Result<SplitNames, String> {
    std::fs::create_dir_all(out_dir).map_err(|error| format!("{}: {error}", out_dir.display()))?;
    let (view, cache, workers) = (views.dir(split), views.cache(), views.workers);
    let (view, cache) = (view.as_path(), cache.as_path());
    let out = out_dir.join(format!("names-{}.json", split.name()));
    let log = out_dir.join(format!("names-{}.log", split.name()));
    let binary_dir = binary.parent().unwrap_or(Path::new("/"));
    let sandbox = sandbox.allowing(&[view, cache, out_dir, binary_dir]);
    let mut command = sandbox.command(&out_dir.join(format!("names-{}.sb", split.name())), binary)?;
    command
        .arg("flywheel-code-names")
        .arg("--corpus")
        .arg(view)
        .args(["--split", split.name()])
        .arg("--out")
        .arg(&out)
        .arg("--flywheel-dir")
        .arg(cache)
        .args(["--workers", &workers.to_string()]);
    if let Some(key) = discovery_key {
        command.args(["--discovery-key", key]);
    }
    if !run_logged(&mut command, &log, Duration::from_secs(3 * 3600))? {
        return Err(format!("naming the {} split failed: {}", split.name(), tail(&log, 20)));
    }
    read_json(&out)
}

impl Harness<'_> {
    fn cargo(&self, out_dir: &Path, log: &str, args: &[&str], limit: Duration) -> Result<(bool, PathBuf), String> {
        let log = out_dir.join(log);
        // The whole gate directory: cargo creates its target directory through a temporary sibling.
        let gate_dir = self.gate_target.parent().unwrap_or(&self.gate_target);
        let sandbox = self.sandbox.allowing(&[gate_dir, &self.gate_worktree, out_dir]);
        let mut command = sandbox.command(&out_dir.join("cargo.sb"), &self.cargo)?;
        command
            .args(args)
            .current_dir(&self.gate_worktree)
            .env("CARGO_TARGET_DIR", &self.gate_target)
            .env("CARGO_TERM_COLOR", "never");
        Ok((run_logged(&mut command, &log, limit)?, log))
    }

    /// The gate on `diff`: policy, build, the family crate's tests, names for `splits` (and the final split when
    /// it is among them) with the candidate, then the rules.
    fn run(&self, diff: &Diff, out_dir: &Path) -> Result<GateRun, String> {
        let started = Instant::now();
        std::fs::create_dir_all(out_dir).map_err(|error| format!("{}: {error}", out_dir.display()))?;
        std::fs::write(out_dir.join("change.diff"), &diff.patch).map_err(|error| error.to_string())?;
        let mut run = GateRun::new(diff);
        let violations = policy_violations(diff, self.family.allowlist);
        if !violations.is_empty() {
            run.stages.push(stage("policy", false, violations.join("; ")));
            run.elapsed_ms = started.elapsed().as_millis() as u64;
            return Ok(run);
        }
        run.stages.push(stage(
            "policy",
            true,
            if diff.is_empty() {
                "no change".to_owned()
            } else {
                format!("{} paths inside the allowlist", diff.paths.len())
            },
        ));
        let candidate: BTreeMap<Split, SplitNames> = if diff.is_empty() {
            run.stages.push(stage("build", true, "skipped: no change, the base is the candidate"));
            run.stages.push(stage("tests", true, "skipped: no change"));
            self.base_names.clone()
        } else {
            let _busy = self.busy.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            apply_diff(&self.gate_worktree, &self.base, diff, &out_dir.join("apply.patch"))?;
            let build = ["build", "--release", "--locked", "-p", "rampage-eval", "--bin", "rampage-eval"];
            let (built, log) = self.cargo(out_dir, "build.log", &build, Duration::from_secs(3600))?;
            if !built {
                run.stages.push(stage("build", false, "cargo build --release -p rampage-eval failed"));
                run.log_tail = Some(tail(&log, 60));
                run.elapsed_ms = started.elapsed().as_millis() as u64;
                return Ok(run);
            }
            run.stages.push(stage("build", true, "cargo build --release -p rampage-eval"));
            let bin_dir = out_dir.join("bin");
            std::fs::create_dir_all(&bin_dir).map_err(|error| error.to_string())?;
            let binary = bin_dir.join("rampage-eval");
            std::fs::copy(self.gate_target.join("release/rampage-eval"), &binary)
                .map_err(|error| format!("copying the candidate build: {error}"))?;
            run.binary = Some(binary.clone());
            let tests: Vec<&str> = if self.nextest {
                vec!["nextest", "run", "--locked", "--no-fail-fast", "-p", self.family.test_crate]
            } else {
                vec!["test", "--locked", "--no-fail-fast", "-p", self.family.test_crate]
            };
            let (tested, log) = self.cargo(out_dir, "tests.log", &tests, Duration::from_secs(3600))?;
            if !tested {
                run.stages.push(stage("tests", false, format!("{} tests failed", self.family.test_crate)));
                run.log_tail = Some(tail(&log, 60));
                run.elapsed_ms = started.elapsed().as_millis() as u64;
                return Ok(run);
            }
            run.stages.push(stage("tests", true, format!("{} tests pass", self.family.test_crate)));
            let mut names = BTreeMap::new();
            for split in GATED {
                match sandboxed_names(
                    &self.sandbox,
                    &binary,
                    &self.views,
                    split,
                    out_dir,
                    Some(&self.base_names[&split].build_id),
                ) {
                    Ok(named) => {
                        names.insert(split, named);
                    }
                    Err(error) => {
                        run.stages.push(stage("names", false, error));
                        run.elapsed_ms = started.elapsed().as_millis() as u64;
                        return Ok(run);
                    }
                }
            }
            names
        };
        self.score(&mut run, &candidate)?;
        run.elapsed_ms = started.elapsed().as_millis() as u64;
        Ok(run)
    }

    /// Scores the candidate's names against the base's on every gated split and applies the rules.
    fn score(&self, run: &mut GateRun, candidate: &BTreeMap<Split, SplitNames>) -> Result<(), String> {
        let engine = self.engine;
        let props = |names: &BTreeMap<Split, SplitNames>, split: Split, as_split: Split| {
            proposals(engine, as_split, &names[&split]).map_err(|error| error.to_string())
        };
        let mut evaluations = BTreeMap::new();
        for (split, from) in [
            (Split::Train, Split::Train),
            (Split::Fast, Split::Train),
            (Split::Heldout, Split::Heldout),
            (Split::Negative, Split::Negative),
        ] {
            let before = props(&self.base_names, from, split)?;
            let after = props(candidate, from, split)?;
            let evaluation = compare(engine, split, &before, &after).map_err(|error| error.to_string())?;
            evaluations.insert(split, evaluation);
        }
        let fast =
            self.gate.fast(&evaluations[&Split::Fast], &evaluations[&Split::Train], &evaluations[&Split::Negative]);
        let heldout = self.gate.heldout(&evaluations[&Split::Heldout], false);
        let check = |result: &GateResult, rule: &str| result.checks.iter().find(|check| check.rule == rule).cloned();
        let rules = |result: &GateResult, names: &[&str]| -> Vec<GateCheck> {
            names.iter().filter_map(|name| check(result, name)).collect()
        };
        let train = rules(&fast, &["train_fp_increase"]);
        let negatives = rules(&fast, &["negative_matches"]);
        let dev = rules(&heldout, &["heldout_f1_gain", "heldout_fp_increase"]);
        let slices: Vec<GateCheck> = rules(&fast, &["train_slice_regression"])
            .into_iter()
            .chain(rules(&heldout, &["heldout_slice_regression"]))
            .collect();
        let summary =
            |checks: &[GateCheck]| checks.iter().map(|check| check.detail.clone()).collect::<Vec<_>>().join("; ");
        let passed = |checks: &[GateCheck]| checks.iter().all(|check| check.passed);
        run.stages.push(stage("train", passed(&train), format!("leave one build out: {}", summary(&train))));
        run.stages.push(stage("negatives", passed(&negatives), summary(&negatives)));
        run.stages.push(stage("dev", passed(&dev), summary(&dev)));
        run.stages.push(stage("slices", passed(&slices), summary(&slices)));
        let time = self.time_check(candidate);
        run.stages.push(stage(
            "time",
            time.passed,
            format!(
                "{} binaries over max({}x the base, base + {} ms) of identification time; total {:.1} s against {:.1} s",
                time.over.len(),
                self.time_ratio,
                self.time_floor_us / 1000,
                time.candidate_total_us as f64 / 1e6,
                time.base_total_us as f64 / 1e6
            ),
        ));
        run.time = Some(time);
        run.failing_slices = fast
            .failing_slices
            .iter()
            .map(|slice| if slice.starts_with("train ") { slice.clone() } else { format!("fast {slice}") })
            .chain(heldout.failing_slices.iter().map(|slice| format!("dev {slice}")))
            .collect();
        run.checks = fast.checks.into_iter().chain(heldout.checks).collect();
        run.evaluations =
            evaluations.into_iter().map(|(split, evaluation)| (split.name().to_owned(), evaluation)).collect();
        run.passed = run.stages.iter().all(|stage| stage.passed);
        Ok(())
    }

    fn time_check(&self, candidate: &BTreeMap<Split, SplitNames>) -> TimeCheck {
        let mut check = TimeCheck { passed: true, ..TimeCheck::default() };
        let mut worst_ratio = 0.0;
        for split in GATED {
            let (Some(base), Some(cand)) = (self.base_names.get(&split), candidate.get(&split)) else { continue };
            for (id, named) in &cand.binaries {
                let Some(before) = base.binaries.get(id) else { continue };
                check.binaries += 1;
                check.base_total_us += before.identify_us;
                check.candidate_total_us += named.identify_us;
                let bound =
                    ((before.identify_us as f64 * self.time_ratio) as u64).max(before.identify_us + self.time_floor_us);
                let slow = Slow {
                    split: split.name().to_owned(),
                    binary: id.clone(),
                    base_us: before.identify_us,
                    candidate_us: named.identify_us,
                    bound_us: bound,
                };
                let ratio = named.identify_us as f64 / before.identify_us.max(1) as f64;
                if ratio > worst_ratio {
                    worst_ratio = ratio;
                    check.worst = Some(slow.clone());
                }
                if named.identify_us > bound {
                    check.passed = false;
                    check.over.push(slow);
                }
            }
        }
        check
    }
}

/// The overall gated delta of one evaluation.
fn overall_delta(evaluation: &SplitEvaluation) -> Value {
    let delta = evaluation.deltas().get("all").cloned();
    json!(delta.map(|delta| json!({"tp": delta.tp, "fp": delta.fp, "fn": delta.fn_, "f1": delta.f1})))
}

/// What the session sees of a gate run: every stage's verdict, training and negative cases, and for dev only the
/// verdict and the overall delta (no slice, no case, no per-library figure).
fn session_answer(run: &GateRun, call: usize, left: usize) -> Value {
    let stages: Vec<Value> = run
        .stages
        .iter()
        .map(|stage| {
            // Dev and slice details carry held-out figures beyond the overall delta.
            let detail = match stage.stage.as_str() {
                "dev" | "slices" => String::new(),
                _ => stage.detail.clone(),
            };
            json!({"stage": stage.stage, "passed": stage.passed, "detail": detail})
        })
        .collect();
    let mut answer = json!({
        "passed": run.passed,
        "gate_call": call,
        "gate_calls_left": left,
        "changed_paths": run.paths,
        "stages": stages,
    });
    let training_cases = |split: &str| -> Value {
        run.evaluations.get(split).map_or(Value::Null, |evaluation| {
            json!({
                "delta": overall_delta(evaluation),
                "fixed": evaluation.fixed,
                "broken": evaluation.broken,
                "cases_total": evaluation.cases.len(),
                "cases": evaluation.cases.iter().take(MAX_CASES).collect::<Vec<_>>(),
            })
        })
    };
    if !run.evaluations.is_empty() {
        answer["train"] = training_cases("train");
        answer["train"]["failing_slices"] =
            json!(run.failing_slices.iter().filter(|slice| !slice.starts_with("dev ")).collect::<Vec<_>>());
        answer["negatives"] = training_cases("negative");
        let dev_rules: Vec<Value> = run
            .checks
            .iter()
            .filter(|check| check.rule.starts_with("heldout_"))
            .map(|check| json!({"rule": check.rule, "passed": check.passed}))
            .collect();
        answer["dev"] = json!({
            "passed": run.stages.iter().any(|stage| stage.stage == "dev" && stage.passed),
            "delta": run.evaluations.get("heldout").map_or(Value::Null, overall_delta),
            "rules": dev_rules,
        });
    }
    if let Some(time) = &run.time {
        answer["time"] = json!({"passed": time.passed, "over": time.over.len(), "worst": time.worst});
    }
    if let Some(log) = &run.log_tail {
        answer["log_tail"] = json!(log);
    }
    answer
}

/// The library-identification session's prompt.
fn libid_prompt(
    base: &str,
    worktree: &Path,
    train: &Path,
    gate: &Path,
    max_gates: usize,
    allowlist: &[&str],
) -> String {
    let allowed: String = allowlist.iter().map(|path| format!("- `{path}`\n")).collect();
    let (worktree, train, gate) = (worktree.display(), train.display(), gate.display());
    format!(
        r#"# Improve rampage's library identification with a source change

Your working directory is a git worktree of rampage at commit {base} ({worktree}). Change the matcher code of
`rampage-signatures` so that `identify_functions` names more library functions in stripped static binaries without
naming anything wrongly. A gate on held-out library versions decides.

## What you may change

Only these paths; a change anywhere else, or any other file left in the worktree, fails the run:

{allowed}
Added lines may not touch files, the environment, processes or the network, and may not use `unsafe`,
`include_bytes!`/`include_str!`, `env!` or `#[path]` (a lexical check; it applies to comments too). The matcher
works from the binary and the compiled-in databases only. No new dependencies; keep the public API that
rampage-api and rampage-eval use compiling. Do not commit, branch, push or change git configuration: leave the
change in the worktree.

## How identification works now

The bundled signature databases name a discovered function by the hash of its masked body (with callee keys for
short forwarders) or by PAT rows (the flywheel arm, operand bytes wildcarded); then call-graph propagation names
callees of named functions by position from training call sequences. Entry points:
`identify_program_sources` and `SignatureDb::lookup` (lib.rs), `CallGraph::propagate` (callgraph.rs).
`crates/rampage-api/src/flywheel/engine.rs` (`identify_parts`) calls them as the product does; read it, do not
change it. There are no fuzzy references at identification time: a heuristic can use the binary, the bundled
databases and the call graph.

## Where the misses are

Measured on the dev split (docs/benchmarks/flywheel-headroom-2026-11-21.md): 20,497 reachable misses that no
existing rule or one-feature miner takes, out of 106,368 scored functions:

- novel bodies (code or length changed between library versions): 11,616 with a fuzzy descriptor, 4,461 refused
  by fuzzy; where fuzzy has a candidate, the right one is often on top but below 0.95, and no fixed threshold
  separates it from false positives;
- bodies shared by several names, with a named caller or callee: 2,336;
- tiny functions (1-3 instructions) with a named caller or callee, such as two-instruction wrappers: 1,190;
- bodies equal to a training body of the same name that every rule refuses: 894.

Precision matters more than reach: the bundled databases are at about 99% precision.

## Training data

`{train}` is the training split (older library versions) and the negatives: stripped `.elf` binaries, their
symbolized `.twin.elf`, the library objects and `manifest.json`. Measure any build on it with cases, for example
`cargo run --release -p rampage-eval -- flywheel-eval --corpus {train} --split train`. `CARGO_TARGET_DIR` is set.

## The gate

`{gate}` (also `flywheel-gate` on PATH) gates the worktree's current change in a clean copy: release build of
rampage-eval, `rampage-signatures` tests, then against the base commit:

- train: every training binary (call graph leaving its own library build out); no new false positive; changed
  cases are listed;
- negatives: no name added on binaries that link no target library;
- dev (held-out library versions): overall F1 up by at least 0.001, false positives up by at most one per 100
  correct names gained; you see the verdict and the overall delta only;
- slices: no architecture, compiler, optimisation, library or cell slice loses F1, on train or dev;
- time: identification per binary within 4x the base's, or the base's plus 1 s.

A gate call takes several minutes; run it with a long Bash timeout, or rerun `flywheel-gate --wait ID` when it
says it is still running. You have {max_gates} calls: use them on finished ideas, not probes. After you stop, the
harness runs the same gate on your change; only that verdict counts.

## Rules

- Do not try to read, find or infer the dev or final split's binaries, truth or results, through files, logs, git
  history, the gate or anything else. They are outside your sandbox, and attempts are recorded.
- Stop when the gate passes with a change you would defend in review, or when you have no idea left that you
  believe in. An unchanged worktree is an acceptable result.
- End with a short summary: the idea, the files changed, and the gate results.
"#
    )
}

/// The Claude Code settings for the session: the file tools and Bash only, path rules denying the sandbox's denied
/// paths, Claude Code's own sandbox off (the session already runs inside one, which cannot be nested), and the
/// environment the build and the gate client need.
fn session_settings(deny: &[PathBuf], environment: &BTreeMap<String, String>) -> Value {
    let mut rules = Vec::new();
    for path in deny {
        for tool in ["Read", "Edit", "Write", "Glob", "Grep"] {
            rules.push(format!("{tool}(/{}/**)", path.display()));
        }
    }
    json!({
        "permissions": {
            "allow": ["Bash", "Read", "Edit", "Write", "Glob", "Grep"],
            "deny": rules,
            "defaultMode": "dontAsk",
        },
        "sandbox": {"enabled": false},
        "env": environment,
        "includeCoAuthoredBy": false,
    })
}

/// The gate's worktree at `base`: the one earlier runs left, reset, when it is still a worktree of `repository`
/// (so an unchanged file keeps its timestamp and cargo its build), else a new one.
fn reuse_or_add_worktree(repository: &Path, worktree: &Path, base: &str) -> Result<(), String> {
    let common = |directory: &Path| {
        output(git(directory).args(["rev-parse", "--path-format=absolute", "--git-common-dir"]))
            .map(|text| canonical(Path::new(text.trim())))
    };
    if worktree.join(".git").exists() && common(worktree).ok() == common(repository).ok() {
        return apply_diff(worktree, base, &Diff::default(), Path::new("/dev/null"));
    }
    let _ = remove_worktree(repository, worktree);
    if worktree.exists() {
        std::fs::remove_dir_all(worktree).map_err(|error| format!("{}: {error}", worktree.display()))?;
    }
    add_worktree(repository, worktree, base)
}

/// Removes what a run made outside its run directory (and the large parts inside), even when it fails.
struct Cleanup {
    repository: PathBuf,
    worktrees: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    keep: bool,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for worktree in &self.worktrees {
            if let Err(error) = remove_worktree(&self.repository, worktree) {
                eprintln!("cleanup: {error}");
            }
        }
        for directory in &self.directories {
            if directory.exists()
                && let Err(error) = std::fs::remove_dir_all(directory)
            {
                eprintln!("cleanup: {}: {error}", directory.display());
            }
        }
    }
}

/// Pending gate requests in the spool, oldest first.
fn pending_requests(spool: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(spool.join("requests"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| !name.starts_with('.'))
        .filter_map(|name| name.strip_suffix(".json").map(str::to_owned))
        .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !id.is_empty())
        .filter(|id| !spool.join("responses").join(format!("{id}.status")).exists())
        .collect();
    ids.sort();
    ids
}

fn answer(spool: &Path, id: &str, value: &Value, passed: bool) -> Result<(), String> {
    write_json(&spool.join("responses").join(format!("{id}.json")), value)?;
    let status = spool.join("responses").join(format!("{id}.status"));
    std::fs::write(&status, if passed { "pass" } else { "fail" }).map_err(|error| error.to_string())
}

/// Answers the session's gate requests until `stop` is set; requests still pending then are answered as refused.
fn serve_gates(
    harness: &Harness<'_>,
    spool: &Path,
    worktree: &Path,
    max: usize,
    stop: &AtomicBool,
    calls: &Mutex<Vec<Value>>,
) {
    let mut served = 0;
    loop {
        let pending = pending_requests(spool);
        if pending.is_empty() && stop.load(Ordering::SeqCst) {
            return;
        }
        for id in pending {
            if stop.load(Ordering::SeqCst) {
                let _ = answer(spool, &id, &json!({"passed": false, "error": "the session ended"}), false);
                continue;
            }
            if served >= max {
                let refusal = json!({"passed": false, "error": format!("gate call limit ({max}) reached")});
                let _ = answer(spool, &id, &refusal, false);
                continue;
            }
            served += 1;
            let out = harness.run_dir.join("session-gates").join(served.to_string());
            let started = Instant::now();
            let result = capture_diff(worktree, &harness.base, &harness.run_dir.join("session-index"))
                .and_then(|diff| harness.run(&diff, &out));
            let (value, passed) = match &result {
                Ok(run) => (session_answer(run, served, max - served), run.passed),
                Err(error) => (json!({"passed": false, "error": format!("the gate failed to run: {error}")}), false),
            };
            if let Ok(run) = &result {
                let _ = write_json(&out.join("gate.json"), run);
            }
            let _ = write_json(&out.join("answer.json"), &value);
            let _ = answer(spool, &id, &value, passed);
            let summary = match &result {
                Ok(run) => json!({
                    "call": served, "id": id, "passed": run.passed, "failed_at": run.failed_at(),
                    "paths": run.paths, "diff_sha256": run.diff_sha256, "elapsed_ms": started.elapsed().as_millis() as u64,
                    "dev": run.evaluations.get("heldout").map(overall_delta),
                }),
                Err(error) => json!({"call": served, "id": id, "error": error}),
            };
            calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(summary);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Runs the session: the agent through the runner, or a script standing in for it. Returns the runner's result
/// (or the script's exit) as JSON.
fn run_session(setup: &SessionSetup<'_>) -> Result<Value, String> {
    let started = Instant::now();
    match setup.script {
        Some(script) => {
            let sandbox = setup.sandbox.allowing(&[script.parent().unwrap_or(Path::new("/"))]);
            let mut command = sandbox.command(&setup.dir.join("session.sb"), Path::new("/bin/sh"))?;
            command.arg(script).current_dir(setup.worktree);
            for (key, value) in setup.environment {
                command.env(key, value);
            }
            let transcript = setup.dir.join("transcript.txt");
            let ok = run_logged(&mut command, &transcript, Duration::from_secs(setup.timeout_s))?;
            Ok(json!({
                "exit": if ok { "ok" } else { "error" },
                "runner": {"name": "session-script", "script": script},
                "cost_usd": 0.0,
                "duration_ms": started.elapsed().as_millis() as u64,
                "transcript": transcript,
            }))
        }
        None => {
            let profile = setup.dir.join("session.sb");
            std::fs::write(&profile, setup.sandbox.profile()).map_err(|error| error.to_string())?;
            let settings = setup.dir.join("settings.json");
            write_json(&settings, &session_settings(&setup.sandbox.deny, setup.environment))?;
            let result_path = setup.dir.join("result.json");
            let mut command = Command::new(&setup.runner[0]);
            command
                .args(&setup.runner[1..])
                .args(["--profile", "code"])
                .arg("--workdir")
                .arg(setup.worktree)
                .arg("--prompt-file")
                .arg(setup.dir.join("prompt.md"))
                .args(["--model", setup.model])
                .args(["--max-turns", &setup.max_turns.to_string()])
                .args(["--timeout-s", &setup.timeout_s.to_string()])
                .args(["--max-budget-usd", &format!("{:.4}", setup.budget_usd)])
                .arg("--out")
                .arg(&result_path)
                .arg("--transcript")
                .arg(setup.dir.join("transcript.jsonl"))
                .arg("--sandbox-profile")
                .arg(&profile)
                .arg("--settings")
                .arg(&settings);
            for directory in setup.add_dirs {
                command.arg("--add-dir").arg(directory);
            }
            for (key, value) in setup.environment {
                command.arg("--env").arg(format!("{key}={value}"));
            }
            let status = command.status().map_err(|error| format!("runner {}: {error}", setup.runner[0].display()))?;
            read_json::<Value>(&result_path)
                .map_err(|error| format!("runner exited {status} without a result: {error}"))
        }
    }
}

struct SessionSetup<'a> {
    dir: &'a Path,
    worktree: &'a Path,
    sandbox: &'a Sandbox,
    environment: &'a BTreeMap<String, String>,
    add_dirs: &'a [PathBuf],
    script: Option<&'a Path>,
    runner: &'a [PathBuf],
    model: &'a str,
    max_turns: u32,
    timeout_s: u64,
    budget_usd: f64,
}

/// Bundled databases plus fuzzy matching at 0.95/0.05 over the base's names, on dev and the negatives: the best
/// matcher that failed the final split, reported beside the baseline. Cached per corpus, harness build and base.
fn fuzzy_reference(engine: &Engine, base: &BTreeMap<Split, SplitNames>, cache: &Path) -> Result<Value, String> {
    use rampage_api::flywheel::fuzzy_arm::{Names, measure};
    // The names alone: identification times differ from run to run.
    let mut key = String::new();
    for names in base.values() {
        for (id, binary) in &names.binaries {
            key.push_str(&format!(
                "{id}\0{}\0",
                serde_json::to_string(&binary.names).map_err(|error| error.to_string())?
            ));
        }
    }
    let digest = rampage_arch::hex::bytes(&<sha2::Sha256 as sha2::Digest>::digest(
        format!("{}\0{}\0{key}", engine.corpus.identity(), build_id()).as_bytes(),
    ));
    let path = cache.join(format!("fuzzy-{}.json", &digest[..16]));
    if let Ok(cached) = read_json::<Value>(&path) {
        return Ok(cached);
    }
    let mut names: Names = BTreeMap::new();
    for split in GATED {
        names.extend(proposals(engine, split, &base[&split]).map_err(|error| error.to_string())?.names);
    }
    let train = engine.corpus.indices(Split::Train);
    let queries: Vec<usize> = [engine.corpus.indices(Split::Heldout), engine.corpus.indices(Split::Negative)].concat();
    let measurement = measure(engine, &train, &queries, &names).map_err(|error| error.to_string())?;
    let mut fuzzy: Names = BTreeMap::new();
    for query in &measurement.queries {
        if !query.collision && query.score >= 0.95 && query.margin > 0.0 && query.margin >= 0.05 {
            fuzzy.entry(query.index).or_default().insert(query.address, query.name.clone());
        }
    }
    let mut out = json!({"threshold": 0.95, "margin": 0.05});
    for split in [Split::Heldout, Split::Negative] {
        let before = proposals(engine, split, &base[&split]).map_err(|error| error.to_string())?;
        let mut after = before.clone();
        for (index, names) in after.names.iter_mut() {
            for (address, name) in fuzzy.get(index).into_iter().flatten() {
                names.entry(*address).or_insert_with(|| name.clone());
            }
        }
        let evaluation = compare(engine, split, &before, &after).map_err(|error| error.to_string())?;
        out[split.name()] = json!({
            "baseline": evaluation.reference_metrics().get("all"),
            "with_fuzzy": evaluation.metrics().get("all"),
            "delta": overall_delta(&evaluation),
        });
    }
    write_json(&path, &out)?;
    Ok(out)
}

/// Metrics table rows for one split: base, candidate, delta.
fn metrics_rows(evaluation: &SplitEvaluation, label: &str) -> String {
    let base = evaluation.reference_metrics();
    let candidate = evaluation.metrics();
    let deltas = evaluation.deltas();
    let (Some(b), Some(c), Some(d)) = (base.get("all"), candidate.get("all"), deltas.get("all")) else {
        return format!("| {label} | - | - | - |\n");
    };
    format!(
        "| {label} | {} / {} / {} (F1 {:.4}) | {} / {} / {} (F1 {:.4}) | {:+} / {:+} / {:+} (F1 {:+.6}) |\n",
        b.tp, b.fp, b.fn_, b.f1, c.tp, c.fp, c.fn_, c.f1, d.tp, d.fp, d.fn_, d.f1
    )
}

fn report_markdown(run: &Value, gate: Option<&GateRun>, diff: &Diff) -> String {
    let mut text = format!(
        "# Code run {}\n\nFamily `{}`, base `{}`, corpus `{}`. Session: {}.\n\n",
        run["label"].as_str().unwrap_or("?"),
        run["family"].as_str().unwrap_or("?"),
        run["base"].as_str().unwrap_or("?"),
        run["corpus"].as_str().unwrap_or("?"),
        run["session"]["summary"].as_str().unwrap_or("?"),
    );
    let (added, removed) = diff.line_counts();
    text.push_str(&format!(
        "## Change\n\n{} paths, +{added} -{removed} lines (`candidate.diff`, SHA-256 `{}`):\n\n",
        diff.paths.len(),
        &diff.sha256()[..16]
    ));
    for path in &diff.paths {
        text.push_str(&format!("- `{path}`\n"));
    }
    if diff.paths.is_empty() {
        text.push_str("- none: the gate measures the base against itself\n");
    }
    text.push_str(&format!(
        "\n## Session gate calls\n\n{} of {} used.\n\n",
        run["session_gates"].as_array().map_or(0, Vec::len),
        run["max_session_gates"]
    ));
    for call in run["session_gates"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "- call {}: {} (failed at: {}), dev delta {}\n",
            call["call"],
            if call["passed"].as_bool() == Some(true) { "pass" } else { "fail" },
            call["failed_at"],
            call["dev"]
        ));
    }
    text.push_str("\n## Authoritative gate\n\n");
    match gate {
        None => text.push_str("Not run.\n"),
        Some(gate) => {
            text.push_str(&format!(
                "Verdict: **{}** ({:.0} s).\n\n| Stage | Passed | Detail |\n|---|---|---|\n",
                if gate.passed { "pass" } else { "fail" },
                gate.elapsed_ms as f64 / 1000.0
            ));
            for stage in &gate.stages {
                text.push_str(&format!(
                    "| {} | {} | {} |\n",
                    stage.stage,
                    if stage.passed { "yes" } else { "**no**" },
                    stage.detail.replace('|', "\\|")
                ));
            }
            if !gate.failing_slices.is_empty() {
                text.push_str(&format!("\nSlices losing F1: {}.\n", gate.failing_slices.join(", ")));
            }
            if !gate.evaluations.is_empty() {
                text.push_str(
                    "\nGated scope (target-library functions plus every false name), TP / FP / FN:\n\n\
                     | Split | Base (bundled databases as shipped) | Candidate | Delta |\n|---|---|---|---|\n",
                );
                for split in ["train", "fast", "heldout", "negative"] {
                    if let Some(evaluation) = gate.evaluations.get(split) {
                        let label = if split == "heldout" { "dev" } else { split };
                        text.push_str(&metrics_rows(evaluation, label));
                    }
                }
            }
            if let Some(log) = &gate.log_tail {
                text.push_str(&format!("\nLog tail:\n\n```\n{log}\n```\n"));
            }
        }
    }
    let fuzzy = &run["fuzzy_reference"];
    if fuzzy.is_object() {
        text.push_str("\n## Reference: fuzzy 0.95/0.05 over the base\n\n| Split | Base | With fuzzy | Delta |\n|---|---|---|---|\n");
        for (split, label) in [("heldout", "dev"), ("negative", "negative")] {
            let row = &fuzzy[split];
            let cell =
                |value: &Value| format!("{} / {} / {} (F1 {})", value["tp"], value["fp"], value["fn"], value["f1"]);
            text.push_str(&format!(
                "| {label} | {} | {} | {} |\n",
                cell(&row["baseline"]),
                cell(&row["with_fuzzy"]),
                row["delta"]
            ));
        }
    }
    text.push_str("\n## Final split\n\n");
    let final_read = &run["final"];
    text.push_str(&format!("{}\n", final_read["summary"].as_str().unwrap_or("Not earned.")));
    if let Some(branch) = run["branch"].as_str() {
        text.push_str(&format!("\nBranch for review: `{branch}`. Nothing was merged.\n"));
    }
    text
}

/// The session's budget: positive and at most [`MAX_BUDGET_USD`].
fn check_budget(budget_usd: f64) -> Result<(), String> {
    if budget_usd.is_finite() && budget_usd > 0.0 && budget_usd <= MAX_BUDGET_USD {
        Ok(())
    } else {
        Err(format!("--budget-usd must be above 0 and at most {MAX_BUDGET_USD} (the cap per family per run)"))
    }
}

/// `flywheel-code-run`.
pub fn run(args: CodeRunArgs) -> Result<ExitCode, String> {
    let family = family(&args.family)?;
    check_budget(args.budget_usd)?;
    let final_dry_run = args.final_dry_run || args.session_script.is_some();
    let repository =
        args.repository_root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let repository = canonical(Path::new(output(git(&repository).args(["rev-parse", "--show-toplevel"]))?.trim()));
    let base = resolve_commit(&repository, &args.base)?;
    let common = canonical(Path::new(
        output(git(&repository).args(["rev-parse", "--path-format=absolute", "--git-common-dir"]))?.trim(),
    ));
    let main_checkout = common.parent().map(Path::to_path_buf).unwrap_or_else(|| repository.clone());
    let corpus_dir = canonical(&args.corpus);
    let engine = open_engine(&corpus_dir, args.flywheel_dir.as_deref(), args.workers)?;
    let flywheel = canonical(engine.paths.root());
    let gate = gate_config(args.gate.as_deref())?;
    let label = args.label.clone().unwrap_or_else(|| {
        format!(
            "code-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
        )
    });
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(format!("label {label:?} must be a plain identifier"));
    }
    let run_dir = flywheel.join("code-runs").join(&label);
    if run_dir.exists() {
        return Err(format!("{} exists; choose another --label", run_dir.display()));
    }
    let session_root = canonical(
        &args.session_root.clone().unwrap_or_else(|| std::env::temp_dir().join("rampage-code-run")).join(&label),
    );
    let gate_dir = canonical(&args.gate_dir.clone().unwrap_or_else(|| flywheel.join("code-runs/gate")));
    let gate_target = gate_dir.join("target");
    std::fs::create_dir_all(&gate_target).map_err(|error| format!("{}: {error}", gate_target.display()))?;
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let uid = output(Command::new("id").arg("-u")).unwrap_or_default().trim().to_owned();
    // What no agent-influenced process may read: the corpus, the flywheel directory (caches, runs, the ledger, this
    // run's gate results), the repositories' target directories (and the flywheel directories in them), other
    // sessions' transcripts and scratch files, and anything the operator adds.
    let mut deny = vec![
        corpus_dir.clone(),
        flywheel.clone(),
        canonical(&main_checkout.join("target")),
        canonical(&repository.join("target")),
        canonical(&home.join(".claude/projects")),
    ];
    if !uid.is_empty() {
        deny.push(canonical(Path::new(&format!("/private/tmp/claude-{uid}"))));
    }
    deny.extend(args.deny_read.iter().map(|path| canonical(path)));
    deny.sort();
    deny.dedup();
    if let Some(denied) = deny.iter().find(|denied| session_root.starts_with(denied)) {
        return Err(format!(
            "the session root {} lies in {}, which the session may not read; pass --session-root",
            session_root.display(),
            denied.display()
        ));
    }
    let base_sandbox =
        Sandbox { deny: deny.clone(), protect: vec![main_checkout.clone(), repository.clone()], allow: Vec::new() };
    let cargo = find_program(&std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))?;
    let nextest = Command::new(&cargo).args(["nextest", "--version"]).output().is_ok_and(|out| out.status.success());
    let mut runner: Vec<PathBuf> = args.runner.split_whitespace().map(PathBuf::from).collect();
    if runner.is_empty() {
        return Err("empty runner command".to_owned());
    }
    for part in runner.iter_mut().skip(1) {
        if part.extension().is_some_and(|extension| extension == "py" || extension == "sh") && part.is_relative() {
            *part = repository.join(&*part);
        }
    }
    let script = args.session_script.as_deref().map(canonical);

    std::fs::create_dir_all(&run_dir).map_err(|error| format!("{}: {error}", run_dir.display()))?;
    let started = Instant::now();
    // One run at a time uses the gate's worktree and target directory.
    let _gate_lock =
        rampage_api::flywheel::FileLock::acquire(&gate_dir.join("lock")).map_err(|error| error.to_string())?;
    let gate_worktree = gate_dir.join("worktree");
    let session_worktree = session_root.join("worktree");
    let views = run_dir.join("views");
    let mut cleanup = Cleanup {
        repository: repository.clone(),
        worktrees: vec![session_worktree.clone()],
        directories: vec![session_root.clone(), views.clone(), run_dir.join("base/bin")],
        keep: args.keep_workspace,
    };
    eprintln!("code run {label}: base {base}, run directory {}", run_dir.display());

    // The scorer's truth and baseline analysis (this trusted build), before anything else.
    let indices: Vec<usize> = GATED.iter().flat_map(|split| engine.corpus.indices(*split)).collect();
    let load = engine.load_all(&indices).map_err(|error| error.to_string())?;
    eprintln!("scorer: {} binaries loaded ({} analysed, {} ms)", load.binaries, load.analysed, load.elapsed_ms);

    // Views: the stripped binaries of each split; the training split with its truth.
    for (split, roles, truth) in [
        (Split::Train, &[Role::Train][..], true),
        (Split::Heldout, &[Role::Heldout][..], false),
        (Split::Negative, &[Role::Negative][..], false),
    ] {
        make_view(&engine.corpus, roles, truth, &views.join(split.name()))?;
    }

    // The base build, in the gate worktree, and its names: the baseline every gate compares with.
    reuse_or_add_worktree(&repository, &gate_worktree, &base)?;
    std::fs::create_dir_all(run_dir.join("base/bin")).map_err(|error| error.to_string())?;
    let base_harness = Harness {
        base: base.clone(),
        run_dir: run_dir.clone(),
        gate_worktree: gate_worktree.clone(),
        gate_target: gate_target.clone(),
        views: Views { root: views.clone(), workers: args.workers },
        engine: &engine,
        gate: gate.clone(),
        base_names: BTreeMap::new(),
        base_binary: run_dir.join("base/bin/rampage-eval"),
        sandbox: base_sandbox.clone(),
        family,
        cargo: cargo.clone(),
        nextest,
        time_ratio: args.time_ratio,
        time_floor_us: args.time_floor_ms * 1000,
        busy: Mutex::new(()),
    };
    let base_dir = run_dir.join("base");
    let build = ["build", "--release", "--locked", "-p", "rampage-eval", "--bin", "rampage-eval"];
    let (built, log) = base_harness.cargo(&base_dir, "build.log", &build, Duration::from_secs(3600))?;
    if !built {
        return Err(format!("the base does not build:\n{}", tail(&log, 40)));
    }
    std::fs::copy(gate_target.join("release/rampage-eval"), &base_harness.base_binary)
        .map_err(|error| format!("copying the base build: {error}"))?;
    let mut base_names = BTreeMap::new();
    for split in GATED {
        let named =
            sandboxed_names(&base_sandbox, &base_harness.base_binary, &base_harness.views, split, &base_dir, None)
                .map_err(|error| format!("{error} (a base before the code-run harness cannot be gated)"))?;
        base_names.insert(split, named);
    }
    eprintln!("base names: {} ms since start", started.elapsed().as_millis());
    let harness = Harness { base_names, ..base_harness };
    let fuzzy = if args.no_fuzzy_reference {
        Value::Null
    } else {
        fuzzy_reference(&engine, &harness.base_names, &flywheel.join("code-runs/cache"))?
    };

    // The session's workspace: its worktree, private target directory, training view, gate spool and client.
    std::fs::create_dir_all(&session_root).map_err(|error| format!("{}: {error}", session_root.display()))?;
    add_worktree(&repository, &session_worktree, &base)?;
    let admin = canonical(Path::new(output(git(&session_worktree).args(["rev-parse", "--absolute-git-dir"]))?.trim()));
    let train_view = session_root.join("flywheel/corpus").join(format!("{}-train", engine.corpus.version()));
    make_view(&engine.corpus, &[Role::Train, Role::Negative], true, &train_view)?;
    let spool = session_root.join("gate");
    for directory in ["requests", "responses"] {
        std::fs::create_dir_all(spool.join(directory)).map_err(|error| error.to_string())?;
    }
    let bin = session_root.join("bin");
    std::fs::create_dir_all(&bin).map_err(|error| error.to_string())?;
    let client = bin.join("flywheel-gate");
    std::fs::write(&client, gate_client(&spool)).map_err(|error| error.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    }
    let session_dir = run_dir.join("session");
    std::fs::create_dir_all(&session_dir).map_err(|error| error.to_string())?;
    let prompt = libid_prompt(&base, &session_worktree, &train_view, &client, args.max_session_gates, family.allowlist);
    std::fs::write(session_dir.join("prompt.md"), &prompt).map_err(|error| error.to_string())?;
    let client_project = home.join(".claude/projects").join(
        session_worktree
            .to_string_lossy()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>(),
    );
    let session_sandbox = Sandbox {
        deny: deny.clone(),
        protect: base_sandbox.protect.clone(),
        allow: vec![session_root.clone(), common.join("objects"), admin.clone(), client_project],
    };
    let path = std::env::var("PATH").unwrap_or_default();
    let environment: BTreeMap<String, String> = [
        ("CARGO_TARGET_DIR", session_root.join("target").display().to_string()),
        ("CARGO_TERM_COLOR", "never".to_owned()),
        ("FLYWHEEL_GATE", client.display().to_string()),
        ("FLYWHEEL_TRAIN", train_view.display().to_string()),
        ("PATH", format!("{}:{path}", bin.display())),
        ("BASH_DEFAULT_TIMEOUT_MS", "1800000".to_owned()),
        ("BASH_MAX_TIMEOUT_MS", "3600000".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();

    // The session, with the gate served beside it.
    let calls = Mutex::new(Vec::new());
    let stop = AtomicBool::new(false);
    let add_dirs = [session_root.join("flywheel"), bin.clone()];
    let session = std::thread::scope(|scope| {
        let server =
            scope.spawn(|| serve_gates(&harness, &spool, &session_worktree, args.max_session_gates, &stop, &calls));
        let result = run_session(&SessionSetup {
            dir: &session_dir,
            worktree: &session_worktree,
            sandbox: &session_sandbox,
            environment: &environment,
            add_dirs: &add_dirs,
            script: script.as_deref(),
            runner: &runner,
            model: &args.model,
            max_turns: args.max_turns,
            timeout_s: args.timeout_s,
            budget_usd: args.budget_usd,
        });
        stop.store(true, Ordering::SeqCst);
        let _ = server.join();
        result
    });
    let session = session.unwrap_or_else(|error| json!({"exit": "error", "error": error}));
    let session_gates = calls.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);

    // The authoritative gate on what the session left.
    let diff = capture_diff(&session_worktree, &base, &run_dir.join("session-index"))?;
    std::fs::write(run_dir.join("candidate.diff"), &diff.patch).map_err(|error| error.to_string())?;
    let gate_run = harness.run(&diff, &run_dir.join("gate"))?;
    write_json(&run_dir.join("gate/gate.json"), &gate_run)?;

    let final_read = final_step(&harness, &gate_run, &diff, &label, final_dry_run, args.final_reason.as_deref())?;
    let branch = final_read.get("branch").and_then(Value::as_str).map(str::to_owned);
    let cost = session["cost_usd"].as_f64();
    let summary = format!(
        "{} ({}), {} s, cost {}",
        session["exit"].as_str().unwrap_or("?"),
        session["runner"]["name"].as_str().unwrap_or("?"),
        session["duration_ms"].as_u64().unwrap_or(0) / 1000,
        cost.map_or("unknown".to_owned(), |cost| format!("${cost:.2}"))
    );
    let mut session_record = session.clone();
    session_record["summary"] = json!(summary);
    let record = json!({
        "label": label,
        "family": family.name,
        "base": base,
        "corpus": engine.corpus.key(),
        "model": args.model,
        "budget_usd": args.budget_usd,
        "timeout_s": args.timeout_s,
        "max_session_gates": args.max_session_gates,
        "session": session_record,
        "session_gates": session_gates,
        "allowlist": family.allowlist,
        "sandbox": {"deny": deny, "session_allow": session_sandbox.allow, "protect": session_sandbox.protect},
        "gate": {
            "passed": gate_run.passed,
            "failed_at": gate_run.failed_at(),
            "stages": gate_run.stages,
            "deltas": gate_run.evaluations.iter().map(|(split, evaluation)| (split.clone(), overall_delta(evaluation))).collect::<BTreeMap<_, _>>(),
            "time": gate_run.time,
        },
        "fuzzy_reference": fuzzy,
        "final": final_read,
        "branch": branch,
        "total_ms": started.elapsed().as_millis() as u64,
    });
    write_json(&run_dir.join("run.json"), &record)?;
    let report = report_markdown(&record, Some(&gate_run), &diff);
    std::fs::write(run_dir.join("report.md"), &report).map_err(|error| error.to_string())?;
    // Binaries are large and rebuilt from the diff when needed.
    cleanup.directories.push(run_dir.join("gate/bin"));
    for entry in std::fs::read_dir(run_dir.join("session-gates")).into_iter().flatten().flatten() {
        cleanup.directories.push(entry.path().join("bin"));
    }
    drop(cleanup);
    eprintln!("{report}");
    eprintln!("run directory: {}", run_dir.display());
    Ok(if gate_run.passed { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// After the gate: nothing when it failed; with a pass, the ledgered final read (or, dry, what it would read), and
/// on a final pass a branch for review.
fn final_step(
    harness: &Harness<'_>,
    gate_run: &GateRun,
    diff: &Diff,
    label: &str,
    dry_run: bool,
    extra_reason: Option<&str>,
) -> Result<Value, String> {
    let engine = harness.engine;
    if !gate_run.passed {
        return Ok(json!({"earned": false, "summary": format!(
            "Not earned: the gate failed at `{}`. The final split was not read and the ledger is unchanged.",
            gate_run.failed_at().unwrap_or("?")
        )}));
    }
    let mut reason = format!(
        "flywheel-code-run {label} ({}): source change {} on base {}, after a full gate pass",
        harness.family.name,
        &diff.sha256()[..12],
        &harness.base[..12]
    );
    if let Some(extra) = extra_reason.map(str::trim).filter(|text| !text.is_empty()) {
        reason.push_str(&format!("; {extra}"));
    }
    let binaries = engine.corpus.indices(Split::Final).len();
    let ledger = engine.corpus.root.join("final-ledger.jsonl");
    if dry_run {
        let would = json!({
            "split": "final",
            "binaries": binaries,
            "corpus": engine.corpus.key(),
            "ledger": ledger,
            "next_read": next_final_read(engine)?,
            "reason": reason,
        });
        write_json(&harness.run_dir.join("final-dry-run.json"), &json!({"read": false, "would_read": would}))?;
        return Ok(json!({"earned": true, "read": false, "dry_run": true, "would_read": would, "summary": format!(
            "Earned, dry run: would read the final split ({binaries} binaries of {}) as read #{} of `{}`, reason \
             \"{reason}\". Nothing was read and the ledger is unchanged.",
            engine.corpus.key(), would["next_read"], ledger.display()
        )}));
    }
    if binaries == 0 {
        return Err("the corpus has no final split".to_owned());
    }
    let candidate_binary = gate_run.binary.clone();
    let code_run = json!({"code_run": {
        "label": label, "family": harness.family.name, "base": harness.base, "diff_sha256": diff.sha256(),
    }});
    let (read, entry) = record_final_read_with(engine, &reason, &[], Some(&code_run))?;
    write_json(&harness.run_dir.join("ledger-entry.json"), &entry)?;
    eprintln!("final read #{read} of corpus {} recorded in {}", engine.corpus.key(), ledger.display());
    make_view(&engine.corpus, &[Role::Final], false, &harness.views.dir(Split::Final))?;
    let out = harness.run_dir.join("final");
    let (sandbox, views) = (&harness.sandbox, &harness.views);
    let base = sandboxed_names(sandbox, &harness.base_binary, views, Split::Final, &out.join("base"), None);
    let candidate = match (&base, &candidate_binary) {
        (Ok(base), Some(binary)) => {
            sandboxed_names(sandbox, binary, views, Split::Final, &out.join("candidate"), Some(&base.build_id))
        }
        (Ok(base), None) => Ok(base.clone()),
        (Err(error), _) => Err(error.clone()),
    };
    let (base, candidate) = match (base, candidate) {
        (Ok(base), Ok(candidate)) => (base, candidate),
        (Err(error), _) | (_, Err(error)) => {
            return Ok(json!({"earned": true, "read": read, "error": error, "summary": format!(
                "Final read #{read} recorded, but naming the final split failed: {error}"
            )}));
        }
    };
    let before = proposals(engine, Split::Final, &base).map_err(|error| error.to_string())?;
    let after = proposals(engine, Split::Final, &candidate).map_err(|error| error.to_string())?;
    let evaluation = compare(engine, Split::Final, &before, &after).map_err(|error| error.to_string())?;
    let verdict = harness.gate.heldout(&evaluation, false);
    let metrics = json!({
        "read": read,
        "passed": verdict.passed,
        "checks": verdict.checks,
        "slices": evaluation.metrics(),
        "baseline": evaluation.reference_metrics(),
        "deltas": evaluation.deltas(),
    });
    write_json(&harness.run_dir.join("final.json"), &metrics)?;
    let delta = overall_delta(&evaluation);
    let mut result = json!({"earned": true, "read": read, "passed": verdict.passed, "delta": delta});
    if verdict.passed {
        let branch = format!("flywheel/code-{label}");
        let message = format!(
            "flywheel code run {label}: {} source change\n\nGate passed; final read #{read} passed with overall \
             delta {delta}. Produced unattended by `rampage-eval flywheel-code-run`; review before merging.\n",
            harness.family.name
        );
        let worktree = &harness.gate_worktree;
        apply_diff(worktree, &harness.base, diff, &harness.run_dir.join("branch.patch"))?;
        output(git(worktree).args(["add", "-A"]))?;
        let mut commit = git(worktree);
        if output(git(worktree).args(["config", "user.email"])).is_err() {
            commit.args(["-c", "user.name=rampage flywheel", "-c", "user.email=flywheel@localhost"]);
        }
        output(commit.args(["commit", "-q", "-m", &message]))?;
        output(git(worktree).args(["branch", &branch, "HEAD"]))?;
        result["branch"] = json!(branch);
    }
    result["summary"] = json!(format!(
        "Final read #{read}: **{}**, overall delta {delta}.{}",
        if verdict.passed { "pass" } else { "fail" },
        result.get("branch").map_or(String::new(), |branch| format!(" Branch `{}`.", branch.as_str().unwrap_or("")))
    ));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_api::flywheel::{CorpusBinary, CorpusManifest, SplitConfig};

    fn corpus(root: &Path) -> Corpus {
        let binary = |id: &str, split: Role| CorpusBinary {
            id: id.to_owned(),
            program: format!("zlib/{id}"),
            library: "zlib".to_owned(),
            library_version: if split == Role::Train { "1.2.13" } else { "1.2.12" }.to_owned(),
            split,
            arch: "x86_64".to_owned(),
            compiler: "zig".to_owned(),
            opt: "O2".to_owned(),
            stripped: format!("bin/{id}.elf"),
            twin: format!("bin/{id}.twin.elf"),
            program_object: None,
            library_object: None,
            program_names: Vec::new(),
            stripped_sha256: "00".repeat(32),
            twin_sha256: "11".repeat(32),
            program_object_sha256: None,
            library_object_sha256: None,
        };
        let manifest = CorpusManifest {
            schema_version: 2,
            family: "libid".to_owned(),
            name: "test".to_owned(),
            version: "libid-test".to_owned(),
            toolchains: Value::Null,
            libraries: Vec::new(),
            split: SplitConfig {
                rule: "version".to_owned(),
                unit: String::new(),
                fast_programs_per_library: 1,
                max_heldout_overlap: 0.5,
                refuse_heldout_overlap: 0.95,
                final_split: String::new(),
            },
            binaries: vec![binary("a", Role::Train), binary("f", Role::Final)],
        };
        Corpus::from_manifest(root.to_path_buf(), manifest).unwrap()
    }

    #[test]
    fn a_final_read_is_appended_to_the_ledger_with_its_reason_and_the_code_run() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let engine = Engine::new(corpus(&root), Paths::new(root.join("flywheel")), 1);
        assert_eq!(next_final_read(&engine).unwrap(), 1);
        std::fs::write(root.join("final-ledger.jsonl"), "{\"read\":1,\"reason\":\"arm v2 claim\"}\n").unwrap();
        assert_eq!(next_final_read(&engine).unwrap(), 2);
        let extra = json!({"code_run": {"label": "code-1", "base": "abc", "diff_sha256": "def"}});
        let (read, entry) = record_final_read_with(&engine, "code run claim", &[], Some(&extra)).unwrap();
        assert_eq!(read, 2);
        let text = std::fs::read_to_string(root.join("final-ledger.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "{\"read\":1,\"reason\":\"arm v2 claim\"}", "earlier reads are kept as they were");
        let written: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(written, entry);
        assert_eq!(written["read"], 2);
        assert_eq!(written["reason"], "code run claim");
        assert_eq!(written["code_run"]["label"], "code-1");
        assert_eq!(written["corpus_identity"], engine.corpus.identity());
        assert_eq!(next_final_read(&engine).unwrap(), 3);
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn evaluation(split: Split, before: (u64, u64, u64), after: (u64, u64, u64)) -> SplitEvaluation {
        let counts = |(correct, wrong, missed): (u64, u64, u64)| rampage_api::flywheel::Counts {
            correct,
            wrong,
            missed,
            spurious: 0,
        };
        SplitEvaluation {
            split,
            binaries: 1,
            reidentified: 0,
            elapsed_ms: 0,
            reference: BTreeMap::from([("all".to_owned(), counts(before)), ("arch:x86_64".to_owned(), counts(before))]),
            candidate: BTreeMap::from([("all".to_owned(), counts(after)), ("arch:x86_64".to_owned(), counts(after))]),
            fixed: 3,
            broken: 1,
            cases: Vec::new(),
        }
    }

    #[test]
    fn the_session_sees_dev_as_a_verdict_and_an_overall_delta_only() {
        let mut run = GateRun::new(&Diff::default());
        run.stages = vec![
            stage("policy", true, "no change"),
            stage("dev", false, "overall F1 +0.000100 (at least +0.001); false positives +7 (at most +0)"),
            stage("slices", false, "no gated slice may lose more than 0 F1"),
        ];
        run.evaluations.insert("train".to_owned(), evaluation(Split::Train, (10, 0, 5), (11, 0, 4)));
        run.evaluations.insert("heldout".to_owned(), evaluation(Split::Heldout, (100, 1, 50), (101, 8, 42)));
        run.failing_slices = vec!["train arch:x86_64".to_owned(), "dev arch:aarch64".to_owned()];
        run.checks = vec![
            GateCheck { rule: "heldout_f1_gain".to_owned(), passed: false, detail: "overall F1 +0.0001".to_owned() },
            GateCheck { rule: "train_fp_increase".to_owned(), passed: true, detail: "+0".to_owned() },
        ];
        let answer = session_answer(&run, 1, 7);
        let text = answer.to_string();
        assert!(!text.contains("aarch64"), "a dev slice name leaked: {text}");
        assert!(!text.contains("+7"), "a dev rule detail leaked: {text}");
        assert_eq!(answer["dev"]["delta"]["tp"], 1);
        assert_eq!(answer["dev"]["delta"]["fp"], 7);
        assert_eq!(answer["dev"]["rules"], json!([{"rule": "heldout_f1_gain", "passed": false}]));
        assert_eq!(answer["train"]["failing_slices"], json!(["train arch:x86_64"]));
        assert_eq!(answer["gate_calls_left"], 7);
        let mut dev_keys: Vec<&String> = answer["dev"].as_object().unwrap().keys().collect();
        dev_keys.sort();
        assert_eq!(dev_keys, ["delta", "passed", "rules"]);
    }

    #[test]
    fn session_settings_deny_the_sandbox_paths_to_every_file_tool() {
        let settings = session_settings(&[PathBuf::from("/data/flywheel")], &BTreeMap::new());
        let deny: Vec<&str> =
            settings["permissions"]["deny"].as_array().unwrap().iter().map(|rule| rule.as_str().unwrap()).collect();
        assert!(deny.contains(&"Read(//data/flywheel/**)") && deny.contains(&"Grep(//data/flywheel/**)"), "{deny:?}");
        assert_eq!(settings["sandbox"]["enabled"], false);
        assert_eq!(settings["permissions"]["defaultMode"], "dontAsk");
    }

    #[test]
    fn the_prompt_names_the_gate_the_allowlist_and_the_final_split_rule() {
        let prompt = libid_prompt(
            "abc123",
            Path::new("/s/worktree"),
            Path::new("/s/flywheel/corpus/libid-x-train"),
            Path::new("/s/bin/flywheel-gate"),
            8,
            LIBID_ALLOWLIST,
        );
        for needle in
            ["/s/bin/flywheel-gate", "crates/rampage-signatures/src/callgraph.rs", "final split", "20,497", "8 calls"]
        {
            assert!(prompt.contains(needle), "{needle}");
        }
    }

    /// A sandboxed command's output reaches a log the sandbox denies it: the harness copies it through pipes.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_sandboxed_command_logs_into_a_directory_it_cannot_write() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-log-{}", std::process::id()));
        let denied = root.join("flywheel");
        std::fs::create_dir_all(&denied).unwrap();
        let sandbox = Sandbox { deny: vec![denied.clone()], ..Sandbox::default() };
        let mut command = sandbox.command(&root.join("p.sb"), Path::new("/bin/sh")).unwrap();
        command.args(["-c", "echo out; echo err >&2; : > \"$0\" && echo WROTE"]).arg(denied.join("x"));
        let log = denied.join("session.log");
        assert!(run_logged(&mut command, &log, Duration::from_secs(30)).is_ok());
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("out") && text.contains("err") && !text.contains("WROTE"), "{text}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_budget_is_capped_per_family_per_run() {
        assert!(check_budget(5.0).is_ok() && check_budget(0.5).is_ok());
        for budget in [5.01, 0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(check_budget(budget).is_err(), "{budget}");
        }
        assert!(family("libid").is_ok() && family("toolid").is_err());
    }
}
