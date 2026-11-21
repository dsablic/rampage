//! The code loop, unattended, as a source change (step 3 of docs/plans/2026-11-20-flywheel-next.md;
//! docs/flywheel.md, "The code loop"). `flywheel-code-run` gives an agent an exported tree of rampage at a base
//! commit, the training split with its truth, and a gate it can call; afterwards it runs the same gate
//! authoritatively on the change and stops. `flywheel-code-final` makes the one ledgered read of the final split for
//! a run whose gate passed, when the operator asks after reviewing the change. `flywheel-code-names` and
//! `flywheel-code-generate` are the gate's steps that run the candidate's code: naming the binaries of one corpus view,
//! and generating the heuristics data from the training split.
//!
//! Trust: the harness process (this binary) holds the truth and scores. Everything the agent's code can influence
//! runs inside a macOS sandbox (`flywheel_code_sandbox`): the session, the build and the tests of its change,
//! generation and identification with the changed matcher. None of them can read the corpus or the flywheel
//! directory, write the operator's home or repository, or reach the network (the session reaches the model's API
//! host through the harness's proxy and nothing else). The harness never runs git, or anything else, in the session's
//! tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rampage_api::flywheel::code::{SplitNames, proposals, split_names, training_inputs};
use rampage_api::flywheel::{
    Corpus, Engine, FAMILY, GateCheck, GateConfig, GateResult, Paths, Role, Split, SplitEvaluation, build_id, compare,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::agent_bench_run::DEFAULT_RUNNER;
use super::flywheel_code_sandbox::{Network, Proxy, Sandbox, canonical, interrupt, run_logged};
use super::flywheel_code_workspace::{
    Diff, GENERATED, LIBID_ALLOWLIST, Limits, Repo, SESSION_EXCLUDED, add_worktree, apply_diff, capture, export_tree,
    gate_client, make_view, operator_repo, output, policy_violations, remove_worktree,
};
use super::flywheel_run::{gate_config, next_final_read, open_engine, record_final_read_with};

/// The most a run may spend on its family: the plan's $5 per family per run.
pub const MAX_BUDGET_USD: f64 = 5.0;

/// The splits the gate scores before a final read.
const GATED: [Split; 3] = [Split::Train, Split::Heldout, Split::Negative];

/// Changed training and negative cases an answer lists.
const MAX_CASES: usize = 40;

/// The hosts the session's proxy tunnels to by default: the model's API, nothing else.
const DEFAULT_HOSTS: &[&str] = &["api.anthropic.com:443"];

/// What Claude Code itself may write under the home directory, every other path of which the session may not write;
/// the rest of `~/.claude` (other sessions' transcripts, history, settings) it may not read either. A best guess at
/// the minimal set for Claude Code 2.1.x on macOS, not yet confirmed by a live run; `--claude-allow` adds paths.
const CLAUDE_HOME_WRITABLE: &[&str] = &[
    ".claude.json",
    ".claude.json.backup",
    ".claude.json.lock",
    ".claude/cache",
    ".claude/debug",
    ".claude/plugins",
    ".claude/session-env",
    ".claude/sessions",
    ".claude/shell-snapshots",
    ".claude/state",
    ".claude/statsig",
    ".claude/telemetry",
    ".claude/todos",
    ".claude/policy-limits.json",
    ".claude/remote-settings.json",
    "Library/Caches/claude-cli-nodejs",
    ".local/state/claude",
];

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
    /// A corpus view (see `flywheel-code-run`).
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long)]
    split: String,
    /// The names file to write.
    #[arg(long)]
    out: PathBuf,
    /// This process's working directory (its truth cache, and its discovery cache unless --discovery-dir).
    #[arg(long)]
    flywheel_dir: PathBuf,
    /// Use the discovery the build with this id cached instead of analysing (a candidate reads the base's).
    #[arg(long)]
    discovery_key: Option<String>,
    /// The cache directory that discovery is in (read only).
    #[arg(long)]
    discovery_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

fn view_engine(
    corpus: &Path,
    flywheel_dir: &Path,
    key: Option<&str>,
    dir: Option<&Path>,
    workers: usize,
) -> Result<Engine, String> {
    let corpus = Corpus::open(corpus).map_err(|error| error.to_string())?;
    let mut engine = Engine::new(corpus, Paths::new(flywheel_dir.to_path_buf()), workers);
    if let Some(key) = key {
        engine = engine.with_discovery_key(key);
    }
    if let Some(dir) = dir {
        engine = engine.with_discovery_dir(dir.to_path_buf());
    }
    Ok(engine)
}

/// `flywheel-code-names`: this build's names for every binary of one split.
pub fn names(args: CodeNamesArgs) -> Result<ExitCode, String> {
    let split: Split = args.split.parse()?;
    let engine = view_engine(
        &args.corpus,
        &args.flywheel_dir,
        args.discovery_key.as_deref(),
        args.discovery_dir.as_deref(),
        args.workers,
    )?;
    let names = split_names(&engine, split).map_err(|error| error.to_string())?;
    let text = serde_json::to_string(&names).map_err(|error| error.to_string())?;
    std::fs::write(&args.out, text).map_err(|error| format!("{}: {error}", args.out.display()))?;
    eprintln!("{} binaries named ({} call graph)", names.binaries.len(), names.call_graph);
    Ok(ExitCode::SUCCESS)
}

#[derive(clap::Args)]
pub struct CodeGenerateArgs {
    /// The training view.
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    flywheel_dir: PathBuf,
    #[arg(long)]
    discovery_key: String,
    #[arg(long)]
    discovery_dir: PathBuf,
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

/// `flywheel-code-generate`: this build's heuristics data, generated from the training split.
pub fn generate(args: CodeGenerateArgs) -> Result<ExitCode, String> {
    let engine = view_engine(
        &args.corpus,
        &args.flywheel_dir,
        Some(&args.discovery_key),
        Some(&args.discovery_dir),
        args.workers,
    )?;
    let inputs = training_inputs(&engine).map_err(|error| error.to_string())?;
    let data = rampage_signatures::heuristics::generate(&inputs);
    std::fs::write(&args.out, &data).map_err(|error| format!("{}: {error}", args.out.display()))?;
    eprintln!("{} bytes generated from {} training binaries", data.len(), inputs.len());
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
    /// The commit the session's tree is exported from and the change is measured against.
    #[arg(long, default_value = "HEAD")]
    base: String,
    /// The session's cost cap (claude --max-budget-usd); at most $5, the plan's cap per family per run.
    #[arg(long, default_value_t = MAX_BUDGET_USD)]
    budget_usd: f64,
    #[arg(long, default_value = "claude-sonnet-5-5")]
    model: String,
    #[arg(long, default_value_t = 200)]
    max_turns: u32,
    /// The session's wall-clock cap, in seconds; the harness stops the runner 15 minutes after it at the latest.
    #[arg(long, default_value_t = 5400)]
    timeout_s: u64,
    /// Gate calls the session may make; each answers with the dev verdict and overall delta, so they are bounded.
    #[arg(long, default_value_t = 8)]
    max_session_gates: usize,
    /// A gate settings file (defaults: dev gain 0.001 F1, one false positive per 100 correct names gained, none on
    /// training or the negatives, no slice losing F1).
    #[arg(long)]
    gate: Option<PathBuf>,
    #[command(flatten)]
    limits: LimitArgs,
    /// Threads for analysis, identification and scoring.
    #[arg(long, default_value_t = 6)]
    workers: usize,
    /// A name for the run (default: code-<unix seconds>).
    #[arg(long)]
    label: Option<String>,
    /// The flywheel working directory (default: two levels above the corpus).
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    /// Where the session's tree, target directory and training view go (default: the system temp directory).
    #[arg(long)]
    session_root: Option<PathBuf>,
    /// The gate's directory, kept across runs so builds stay incremental (default: <flywheel>/code-runs/gate).
    #[arg(long)]
    gate_dir: Option<PathBuf>,
    /// The runner command, split on whitespace; a relative script path resolves against the repository root.
    #[arg(long, default_value = DEFAULT_RUNNER)]
    runner: String,
    /// The repository the trees are exported from (default: the one this binary was built from).
    #[arg(long)]
    repository_root: Option<PathBuf>,
    /// Instead of an agent session, run this shell script in the session's sandbox and tree (it may apply a patch
    /// and call `flywheel-gate`). Spends nothing.
    #[arg(long)]
    session_script: Option<PathBuf>,
    /// More paths the session and the agent's code may not read (repeatable).
    #[arg(long)]
    deny_read: Vec<PathBuf>,
    /// `host:port` the session's proxy may tunnel to besides the model's API (repeatable).
    #[arg(long)]
    allow_host: Vec<String>,
    /// More paths under the home directory Claude Code may write (repeatable), for the first live runs.
    #[arg(long)]
    claude_allow: Vec<PathBuf>,
    /// Skip the fuzzy 0.95/0.05 reference column (it re-analyses every binary once per base).
    #[arg(long)]
    no_fuzzy_reference: bool,
    /// Keep the session directory, views and binaries (for debugging the harness).
    #[arg(long)]
    keep_workspace: bool,
}

#[derive(clap::Args, Clone, Copy)]
pub struct LimitArgs {
    /// Identification of a split with the change may take at most this many times the base's wall time...
    #[arg(long, default_value_t = 4.0)]
    time_ratio: f64,
    /// ...or the base's plus this many seconds, whichever is more.
    #[arg(long, default_value_t = 30)]
    time_floor_s: u64,
    /// Added lines a change may hold.
    #[arg(long, default_value_t = 800)]
    max_added_lines: usize,
    /// Added lines that are mostly literal data a change may hold.
    #[arg(long, default_value_t = 40)]
    max_literal_lines: usize,
}

#[derive(clap::Args)]
pub struct CodeFinalArgs {
    /// The corpus the run was gated on.
    #[arg(long)]
    corpus: PathBuf,
    /// The run's label.
    #[arg(long)]
    label: String,
    /// Why the read is made, recorded in the ledger beside the run, the change and the base.
    #[arg(long)]
    reason: String,
    #[arg(long, default_value_t = 6)]
    workers: usize,
    #[arg(long)]
    flywheel_dir: Option<PathBuf>,
    #[arg(long)]
    gate_dir: Option<PathBuf>,
    #[arg(long)]
    repository_root: Option<PathBuf>,
    #[arg(long)]
    gate: Option<PathBuf>,
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

/// One split's identification wall time, measured by the harness around the naming process.
#[derive(Debug, Clone, Serialize)]
struct SplitTime {
    split: String,
    base_ms: u64,
    candidate_ms: u64,
    bound_ms: u64,
    passed: bool,
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
    times: Vec<SplitTime>,
    /// The end of a failed build's or test run's log (the agent's own code; shown to the session).
    #[serde(skip_serializing_if = "Option::is_none")]
    log_tail: Option<String>,
    /// Details for the operator only (a naming failure's log, for one).
    operator_notes: Vec<String>,
    /// The size of the generated heuristics data.
    generated_bytes: usize,
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
            times: Vec::new(),
            log_tail: None,
            operator_notes: Vec::new(),
            generated_bytes: 0,
            binary: None,
            elapsed_ms: 0,
        }
    }

    fn failed_at(&self) -> Option<&str> {
        self.stages.iter().find(|stage| !stage.passed).map(|stage| stage.stage.as_str())
    }
}

/// The names one build gave a split (keyed by real binary id) and the wall time the naming process took.
#[derive(Debug, Clone)]
struct Named {
    names: SplitNames,
    wall_ms: u64,
}

/// One view's directory and its neutral ids' real ids (empty for training).
type View = (PathBuf, BTreeMap<String, String>);

/// The corpus views of a run: the training split under its real ids, and every other split under a random directory
/// name and neutral binary ids, so a candidate cannot tell dev from the negatives or the final split by its arguments,
/// paths or manifest.
struct Views {
    root: PathBuf,
    workers: usize,
    dirs: Mutex<BTreeMap<Split, View>>,
}

impl Views {
    fn new(root: PathBuf, workers: usize) -> Views {
        Views { root, workers, dirs: Mutex::new(BTreeMap::new()) }
    }

    /// The discovery cache the base writes and candidates read.
    fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// Makes the view of `split`.
    fn make(&self, corpus: &Corpus, split: Split) -> Result<(), String> {
        let (role, truth) = match split {
            Split::Train | Split::Fast => (Role::Train, true),
            Split::Heldout => (Role::Heldout, false),
            Split::Negative => (Role::Negative, false),
            Split::Final => (Role::Final, false),
        };
        let name = if truth {
            "train".to_owned()
        } else {
            let seed = format!("{}{:?}{:?}", self.root.display(), split, std::time::SystemTime::now());
            let digest = <sha2::Sha256 as sha2::Digest>::digest(seed.as_bytes());
            format!("v{}", &rampage_arch::hex::bytes(&digest)[..10])
        };
        let dir = self.root.join(name);
        let ids = make_view(corpus, &[role], truth, &dir)?;
        self.dirs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(split, (dir, ids));
        Ok(())
    }

    fn get(&self, split: Split) -> Result<View, String> {
        let dirs = self.dirs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        dirs.get(&split).cloned().ok_or_else(|| format!("no view of the {} split", split.name()))
    }
}

/// Everything a gate run needs.
struct Harness<'a> {
    base: String,
    run_dir: PathBuf,
    gate: Repo,
    /// The worktree a session's change is read into, apart from the one builds run in, so reading a change never
    /// touches a file the build target depends on.
    capture: Repo,
    gate_dir: PathBuf,
    views: Views,
    engine: &'a Engine,
    config: GateConfig,
    limits: LimitArgs,
    base_names: BTreeMap<Split, Named>,
    base_binary: PathBuf,
    base_build_id: String,
    /// What no agent-influenced process may read.
    deny: Vec<PathBuf>,
    family: &'static Family,
    cargo: PathBuf,
    nextest: bool,
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

fn create_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// The operator's cargo home (`CARGO_HOME`, else `~/.cargo`), whose registry cache the private registries copy.
fn operator_cargo_home(home: &Path) -> PathBuf {
    std::env::var_os("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".cargo"))
}

/// The registry packages a Cargo.lock pins: (name, version).
fn locked_packages(lock: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key} = \"")).and_then(|rest| rest.strip_suffix('"')))
        };
        if let (Some(name), Some(version), Some(source)) = (field("name"), field("version"), field("source"))
            && source.starts_with("registry+")
        {
            packages.push((name.to_owned(), version.to_owned()));
        }
    }
    packages
}

/// A private cargo home holding the crates.io index and exactly the `.crate` archives `tree`'s Cargo.lock pins, copied
/// from the operator's registry, configured to build offline. Builds unpack the archives into it as registry
/// packages, which cargo treats as immutable (vendored directory sources are not: a dependency whose build script
/// rewrites its own sources would then rebuild every time). Nothing else of the operator's cargo home comes along.
fn private_registry(operator: &Path, tree: &Path, home: &Path) -> Result<(), String> {
    let lock = std::fs::read_to_string(tree.join("Cargo.lock")).map_err(|error| format!("Cargo.lock: {error}"))?;
    let digest = rampage_arch::hex::bytes(&<sha2::Sha256 as sha2::Digest>::digest(lock.as_bytes()));
    let stamp = home.join(".lock-sha256");
    if std::fs::read_to_string(&stamp).ok().as_deref() == Some(digest.as_str()) {
        return Ok(());
    }
    let index_root = operator.join("registry/index");
    let index = std::fs::read_dir(&index_root)
        .map_err(|error| format!("{}: {error}", index_root.display()))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("index.crates.io-"))
        .ok_or_else(|| format!("no crates.io index in {}", index_root.display()))?;
    let own_index = home.join("registry/index").join(&index);
    if !own_index.exists() {
        create_dir(&home.join("registry/index"))?;
        output(Command::new("cp").args(["-c", "-R"]).arg(index_root.join(&index)).arg(&own_index))?;
    }
    let (cache, own_cache) = (operator.join("registry/cache").join(&index), home.join("registry/cache").join(&index));
    create_dir(&own_cache)?;
    for (name, version) in locked_packages(&lock) {
        let file = format!("{name}-{version}.crate");
        if !own_cache.join(&file).is_file() {
            std::fs::copy(cache.join(&file), own_cache.join(&file))
                .map_err(|error| format!("{file} is not in the operator's registry cache ({error}); fetch it once"))?;
        }
    }
    std::fs::write(home.join("config.toml"), "[net]\noffline = true\n").map_err(|error| error.to_string())?;
    std::fs::write(&stamp, digest).map_err(|error| error.to_string())
}

impl Harness<'_> {
    /// The gate's private registry, unpacked into by builds only.
    fn cargo_home(&self) -> PathBuf {
        self.gate_dir.join("cargo-home")
    }

    fn gate_tree(&self) -> PathBuf {
        self.gate.work_tree.clone().unwrap_or_default()
    }

    /// A sandbox for the agent's code: no network, no writes but `writable`, `readable` carved out of the denied paths.
    fn candidate_sandbox(&self, readable: &[&Path], writable: &[&Path]) -> Sandbox {
        Sandbox {
            deny: self.deny.clone(),
            protect: Vec::new(),
            deny_all_writes: true,
            read_only: readable.iter().map(|path| path.to_path_buf()).collect(),
            allow: writable.iter().map(|path| path.to_path_buf()).collect(),
            network: Network::Denied,
        }
    }

    /// cargo in the gate worktree with `target` as its target directory, offline from the gate's private registry, in
    /// the sandbox, its output in `out_dir/log`. Builds may write the registry (unpacking archives; some dependencies'
    /// build scripts generate code into their own sources); the candidate's tests, which run the agent's code, may
    /// write only cargo's lock files in it.
    fn cargo(
        &self,
        out_dir: &Path,
        log: &str,
        target: &Path,
        args: &[&str],
        registry_writable: bool,
    ) -> Result<(bool, PathBuf), String> {
        let home = self.cargo_home();
        let tmp = out_dir.join(format!("{log}.tmp"));
        create_dir(&tmp)?;
        create_dir(target)?;
        let tree = self.gate_tree();
        let sandbox = if registry_writable {
            self.candidate_sandbox(&[&tree], &[target, out_dir, &home])
        } else {
            let locks: Vec<PathBuf> = [".package-cache", ".package-cache-mutate", ".global-cache"]
                .iter()
                .map(|name| home.join(name))
                .collect();
            let mut writable: Vec<&Path> = vec![target, out_dir];
            writable.extend(locks.iter().map(PathBuf::as_path));
            self.candidate_sandbox(&[&tree, &home], &writable)
        };
        let mut command = sandbox.command(&out_dir.join(format!("{log}.sb")), &self.cargo)?;
        command
            .args(args)
            .current_dir(&tree)
            .env("CARGO_HOME", &home)
            .env("CARGO_TARGET_DIR", target)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("TMPDIR", &tmp);
        let log = out_dir.join(log);
        Ok((run_logged(&mut command, &log, Duration::from_secs(3600))?, log))
    }

    /// Builds rampage-eval in the gate worktree into the build target, which no candidate process writes, and copies
    /// the binary into `out_dir/bin`.
    fn build(&self, out_dir: &Path, log: &str) -> Result<Option<PathBuf>, String> {
        let target = self.gate_dir.join("target");
        let args = ["build", "--release", "--locked", "-p", "rampage-eval", "--bin", "rampage-eval"];
        let (built, _) = self.cargo(out_dir, log, &target, &args, true)?;
        if !built {
            return Ok(None);
        }
        let bin_dir = out_dir.join("bin");
        create_dir(&bin_dir)?;
        let binary = bin_dir.join("rampage-eval");
        std::fs::copy(target.join("release/rampage-eval"), &binary)
            .map_err(|error| format!("copying the build: {error}"))?;
        Ok(Some(binary))
    }

    /// One build naming one split in the sandbox, from the split's view, timed from here. The candidate reads the
    /// base's discovery and writes only its own cache and output; the base's first pass writes the discovery.
    fn names(&self, binary: &Path, split: Split, out_dir: &Path, discovery: Discovery) -> Result<Named, String> {
        let (view, ids) = self.views.get(split)?;
        let tag = if split == Split::Train {
            "train".to_owned()
        } else {
            view.file_name().unwrap_or_default().to_string_lossy().into_owned()
        };
        let out = out_dir.join(format!("names-{tag}.json"));
        let own = out_dir.join(format!("cache-{tag}"));
        create_dir(&own)?;
        let shared = self.views.cache();
        create_dir(&shared)?;
        let binary_dir = binary.parent().unwrap_or(Path::new("/"));
        let role = if split == Split::Train { "train" } else { "heldout" };
        let (sandbox, flywheel_dir) = match discovery {
            Discovery::Write => (self.candidate_sandbox(&[&view, binary_dir], &[&shared, out_dir]), shared.clone()),
            Discovery::Read(_) => {
                (self.candidate_sandbox(&[&view, binary_dir, &shared], &[&own, out_dir]), own.clone())
            }
        };
        let mut command = sandbox.command(&out_dir.join(format!("names-{tag}.sb")), binary)?;
        command
            .arg("flywheel-code-names")
            .arg("--corpus")
            .arg(&view)
            .args(["--split", role])
            .arg("--out")
            .arg(&out)
            .arg("--flywheel-dir")
            .arg(&flywheel_dir)
            .args(["--workers", &self.views.workers.to_string()])
            .env("TMPDIR", out_dir);
        if let Discovery::Read(key) = &discovery {
            command.args(["--discovery-key", key]).arg("--discovery-dir").arg(Paths::new(shared.clone()).cache());
        }
        let started = Instant::now();
        let ok = run_logged(&mut command, &out_dir.join(format!("names-{tag}.log")), Duration::from_secs(3 * 3600))?;
        let wall_ms = started.elapsed().as_millis() as u64;
        if !ok {
            return Err(format!(
                "naming {} failed; see {}",
                split.name(),
                out_dir.join(format!("names-{tag}.log")).display()
            ));
        }
        let mut names: SplitNames = read_json(&out)?;
        if !ids.is_empty() {
            names.binaries =
                names.binaries.into_iter().map(|(id, named)| (ids.get(&id).cloned().unwrap_or(id), named)).collect();
        }
        names.split = split;
        Ok(Named { names, wall_ms })
    }

    /// The base's names for `split`: a first pass writes its discovery, a second identifies timed the way a candidate
    /// is (reading that discovery), so both sides' times measure the same work.
    fn base_names(&self, split: Split, out_dir: &Path) -> Result<(Named, String), String> {
        let first = self.names(&self.base_binary, split, &out_dir.join("discovery"), Discovery::Write)?;
        let id = first.names.build_id;
        Ok((self.names(&self.base_binary, split, out_dir, Discovery::Read(id.clone()))?, id))
    }

    /// Generates the heuristics data with the candidate from the training view in the sandbox; when it differs from
    /// the worktree's, puts it there and builds again. The generated binary, or a failed stage.
    fn generate(&self, binary: PathBuf, out_dir: &Path, run: &mut GateRun) -> Result<Option<PathBuf>, String> {
        let (view, _) = self.views.get(Split::Train)?;
        let shared = self.views.cache();
        let own = out_dir.join("cache-generate");
        create_dir(&own)?;
        let data = out_dir.join("heuristics.bin");
        let binary_dir = binary.parent().unwrap_or(Path::new("/")).to_path_buf();
        let sandbox = self.candidate_sandbox(&[&view, &binary_dir, &shared], &[&own, out_dir]);
        let mut command = sandbox.command(&out_dir.join("generate.sb"), &binary)?;
        command
            .arg("flywheel-code-generate")
            .arg("--corpus")
            .arg(&view)
            .arg("--out")
            .arg(&data)
            .arg("--flywheel-dir")
            .arg(&own)
            .args(["--discovery-key", &self.base_build_id])
            .arg("--discovery-dir")
            .arg(Paths::new(shared.clone()).cache())
            .args(["--workers", &self.views.workers.to_string()])
            .env("TMPDIR", out_dir);
        if !run_logged(&mut command, &out_dir.join("generate.log"), Duration::from_secs(3600))? {
            run.stages.push(stage("generate", false, "generating the heuristics data from the training split failed"));
            run.log_tail = Some(tail(&out_dir.join("generate.log"), 40));
            return Ok(None);
        }
        let bytes = std::fs::read(&data).map_err(|error| error.to_string())?;
        run.generated_bytes = bytes.len();
        let max = rampage_signatures::heuristics::MAX_BYTES;
        if bytes.len() > max {
            run.stages.push(stage("generate", false, format!("{} bytes generated (at most {max})", bytes.len())));
            return Ok(None);
        }
        let current = self.gate_tree().join(GENERATED);
        if std::fs::read(&current).ok().as_deref() == Some(bytes.as_slice()) {
            run.stages.push(stage("generate", true, format!("{} bytes, as compiled in", bytes.len())));
            return Ok(Some(binary));
        }
        std::fs::write(&current, &bytes).map_err(|error| error.to_string())?;
        let Some(rebuilt) = self.build(&out_dir.join("generated"), "build.log")? else {
            run.stages.push(stage("generate", false, "the build with the generated data failed"));
            run.log_tail = Some(tail(&out_dir.join("generated/build.log"), 60));
            return Ok(None);
        };
        run.stages.push(stage("generate", true, format!("{} bytes generated from the training split", bytes.len())));
        Ok(Some(rebuilt))
    }

    /// Policy, then the candidate build: apply, build, generate, and (with `tests`) the family crate's tests in a
    /// fresh target directory of their own. The candidate binary, or `None` with the failed stage in `run`.
    fn prepare(&self, diff: &Diff, out_dir: &Path, run: &mut GateRun, tests: bool) -> Result<Option<PathBuf>, String> {
        let limits =
            Limits { max_added_lines: self.limits.max_added_lines, max_literal_lines: self.limits.max_literal_lines };
        let violations = policy_violations(diff, self.family.allowlist, limits);
        if !violations.is_empty() {
            run.stages.push(stage("policy", false, violations.join("; ")));
            return Ok(None);
        }
        run.stages.push(stage("policy", true, format!("{} paths inside the allowlist", diff.paths.len())));
        apply_diff(&self.gate, &self.base, diff, &out_dir.join("apply.patch"))?;
        let Some(binary) = self.build(out_dir, "build.log")? else {
            run.stages.push(stage("build", false, "cargo build --release -p rampage-eval failed"));
            run.log_tail = Some(tail(&out_dir.join("build.log"), 60));
            return Ok(None);
        };
        run.stages.push(stage("build", true, "cargo build --release -p rampage-eval"));
        let Some(binary) = self.generate(binary, out_dir, run)? else { return Ok(None) };
        if tests {
            let target = out_dir.join("test-target");
            let crate_name = self.family.test_crate;
            let args: Vec<&str> = if self.nextest {
                vec!["nextest", "run", "--locked", "--no-fail-fast", "-p", crate_name]
            } else {
                vec!["test", "--locked", "--no-fail-fast", "-p", crate_name]
            };
            let (tested, log) = self.cargo(out_dir, "tests.log", &target, &args, false)?;
            let _ = std::fs::remove_dir_all(&target);
            if !tested {
                run.stages.push(stage("tests", false, format!("{crate_name} tests failed")));
                run.log_tail = Some(tail(&log, 60));
                return Ok(None);
            }
            run.stages.push(stage("tests", true, format!("{crate_name} tests pass")));
        }
        Ok(Some(binary))
    }

    /// The gate on `diff`, its results in `out_dir`.
    fn run(&self, diff: &Diff, out_dir: &Path) -> Result<GateRun, String> {
        let started = Instant::now();
        create_dir(out_dir)?;
        std::fs::write(out_dir.join("change.diff"), &diff.patch).map_err(|error| error.to_string())?;
        let mut run = GateRun::new(diff);
        let candidate: BTreeMap<Split, Named> = if diff.is_empty() {
            run.stages.push(stage("policy", true, "no change"));
            run.stages.push(stage("build", true, "skipped: no change, the base is the candidate"));
            run.stages.push(stage("tests", true, "skipped: no change"));
            self.base_names.clone()
        } else {
            let _busy = self.busy.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(binary) = self.prepare(diff, out_dir, &mut run, true)? else {
                run.elapsed_ms = started.elapsed().as_millis() as u64;
                return Ok(run);
            };
            run.binary = Some(binary.clone());
            let mut names = BTreeMap::new();
            for split in GATED {
                match self.names(&binary, split, out_dir, Discovery::Read(self.base_build_id.clone())) {
                    Ok(named) => {
                        names.insert(split, named);
                    }
                    Err(error) => {
                        // The log is the candidate's output on a held-out split: the operator's only.
                        run.stages.push(stage("names", false, "naming a split with the change failed"));
                        run.operator_notes.push(error);
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
    fn score(&self, run: &mut GateRun, candidate: &BTreeMap<Split, Named>) -> Result<(), String> {
        let engine = self.engine;
        let props = |names: &BTreeMap<Split, Named>, from: Split, as_split: Split| {
            proposals(engine, as_split, &names[&from].names).map_err(|error| error.to_string())
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
            evaluations.insert(split, compare(engine, split, &before, &after).map_err(|error| error.to_string())?);
        }
        let fast =
            self.config.fast(&evaluations[&Split::Fast], &evaluations[&Split::Train], &evaluations[&Split::Negative]);
        let heldout = self.config.heldout(&evaluations[&Split::Heldout], false);
        let rules = |result: &GateResult, names: &[&str]| -> Vec<GateCheck> {
            result.checks.iter().filter(|check| names.contains(&check.rule.as_str())).cloned().collect()
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
        run.times = GATED.iter().filter_map(|split| self.time(*split, candidate)).collect();
        let slow: Vec<&SplitTime> = run.times.iter().filter(|time| !time.passed).collect();
        run.stages.push(stage(
            "time",
            slow.is_empty(),
            format!(
                "{} of {} splits over max({}x the base's naming wall time, base + {} s)",
                slow.len(),
                run.times.len(),
                self.limits.time_ratio,
                self.limits.time_floor_s
            ),
        ));
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

    fn time(&self, split: Split, candidate: &BTreeMap<Split, Named>) -> Option<SplitTime> {
        let (base, cand) = (self.base_names.get(&split)?, candidate.get(&split)?);
        let bound =
            ((base.wall_ms as f64 * self.limits.time_ratio) as u64).max(base.wall_ms + self.limits.time_floor_s * 1000);
        Some(SplitTime {
            split: split.name().to_owned(),
            base_ms: base.wall_ms,
            candidate_ms: cand.wall_ms,
            bound_ms: bound,
            passed: cand.wall_ms <= bound,
        })
    }
}

/// Whether a naming process writes the shared discovery (the base's first pass) or reads it (with that build id).
enum Discovery {
    Write,
    Read(String),
}

/// The overall gated delta of one evaluation.
fn overall_delta(evaluation: &SplitEvaluation) -> Value {
    let delta = evaluation.deltas().get("all").cloned();
    json!(delta.map(|delta| json!({"tp": delta.tp, "fp": delta.fp, "fn": delta.fn_, "f1": delta.f1})))
}

/// What the session sees of a gate run: every stage's verdict, training and negative cases, and for dev only the
/// verdict and the overall delta (no slice, no case, no per-library figure, no time). A naming failure says only that.
fn session_answer(run: &GateRun, call: usize, left: usize) -> Value {
    let stages: Vec<Value> = run
        .stages
        .iter()
        .map(|stage| {
            let detail = match stage.stage.as_str() {
                "dev" | "slices" | "time" | "names" => String::new(),
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

Your working directory ({worktree}) holds rampage's source at commit {base}, with a fresh git history of its own.
Change the matcher code of `rampage-signatures` so that `identify_functions` names more library functions in
stripped static binaries without naming anything wrongly. A gate on held-out library versions decides.

## What you may change

Only these paths; a change anywhere else, or any other file left in the tree, fails the run:

{allowed}
Added lines may not touch files, the environment, processes or the network, and may not use `unsafe`,
`include_bytes!`/`include_str!`, `env!` or `#[path]`. A change holds at most a few hundred added lines, and only a
few dozen of them may be literal data (tables of numbers or strings). No new dependencies; keep the public API that
rampage-api and rampage-eval use compiling. Commit in your own history if you like; only the files count.

## Data from the training split

A heuristic that needs data derived from training (references, tables, sequences) gets it through
`rampage_signatures::heuristics`: write `generate(&[TrainingBinary]) -> Vec<u8>` (at most 4 MiB) and read the result
with `heuristics::data()`. The gate runs your `generate` on the training split and compiles its output in; a data file
you leave in the tree is ignored. To measure with it yourself, write the file with
`cargo run --release -p rampage-eval -- flywheel-code-generate` (see its `--help`) into
`crates/rampage-signatures/data/heuristics/heuristics.bin`.

## How identification works now

The bundled signature databases name a discovered function by the hash of its masked body (with callee keys for
short forwarders) or by PAT rows (the flywheel arm, operand bytes wildcarded); then call-graph propagation names
callees of named functions by position from training call sequences. Entry points:
`identify_program_sources` and `SignatureDb::lookup` (lib.rs), `CallGraph::propagate` (callgraph.rs).
`crates/rampage-api/src/flywheel/engine.rs` (`identify_parts`) calls them as the product does; read it, do not
change it.

## Where the misses are

Measured on the dev split (docs/benchmarks/flywheel-headroom-2026-11-21.md): 20,497 reachable misses that no
existing rule or one-feature miner takes, out of 106,368 scored functions:

- novel bodies (code or length changed between library versions): 11,616 with a fuzzy descriptor, 4,461 refused
  by fuzzy; where fuzzy has a candidate, the right one is often on top but below 0.95, and no fixed threshold
  separates it from false positives;
- bodies shared by several names, with a named caller or callee: 2,336;
- tiny functions (1-3 instructions) with a named caller or callee, such as two-instruction wrappers: 1,190;
- bodies equal to a training body of the same name that every rule refuses: 894.

Precision matters more than reach: the bundled databases are at about 99% precision. Upward call-graph propagation
alone (naming a function after the one training caller whose named call sequence it matches) was tried: dev +2852
correct for +96 false names, which fails the allowance.

## Training data and tools

`{train}` is the training split (older library versions) and the negatives: stripped `.elf` binaries, their
symbolized `.twin.elf`, the library objects and `manifest.json`. Measure any build on it with cases, for example
`cargo run --release -p rampage-eval -- flywheel-eval --corpus {train} --split train`. Builds run offline from
a private registry of the locked dependencies (`CARGO_HOME` and `CARGO_TARGET_DIR` are set); there is no network.

## The gate

`{gate}` (also `flywheel-gate` on PATH) gates the tree's current change in a clean copy: release build of
rampage-eval, generation of the heuristics data, `rampage-signatures` tests, then against the base commit:

- train: every training binary (call graph leaving its own library build out); no new false positive; changed
  cases are listed;
- negatives: no name added on binaries that link no target library;
- dev (held-out library versions): overall F1 up by at least 0.001, false positives up by at most one per 100
  correct names gained; you see the verdict and the overall delta only;
- slices: no architecture, compiler, optimisation, library or cell slice loses F1, on train or dev;
- time: naming each split takes at most 4x the base's time, or the base's plus 30 s.

A gate call takes several minutes; run it with a long Bash timeout, or rerun `flywheel-gate --wait ID` when it
says it is still running. You have {max_gates} calls: use them on finished ideas, not probes. After you stop, the
harness runs the same gate on your change; only that verdict counts.

## Rules

- Do not try to read, find or infer the dev or final split's binaries, truth or results, through files, logs, git
  history, the gate or anything else. They are outside your sandbox, and attempts are recorded.
- Stop when the gate passes with a change you would defend in review, or when you have no idea left that you
  believe in. An unchanged tree is an acceptable result.
- End with a short summary: the idea, the files changed, and the gate results.
"#
    )
}

/// The Claude Code settings for the session: the file tools and Bash only, path rules denying the sandbox's denied
/// paths, Claude Code's own sandbox off (the session already runs inside one, which cannot be nested), and the
/// environment the build, the proxy and the gate client need.
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

/// The gate's worktree at `base`: the one earlier runs left, reset, when it is still recorded as a worktree of `repo`
/// (so an unchanged file keeps its timestamp and cargo its build), else a new one. Its git directory is recorded in
/// the gate directory, which no candidate process can write.
fn gate_worktree(repo: &Repo, gate_dir: &Path, name: &str, base: &str) -> Result<Repo, String> {
    let tree = gate_dir.join(name);
    let record = gate_dir.join(format!("{name}-git-dir"));
    if let Ok(text) = std::fs::read_to_string(&record) {
        let gate = Repo { git_dir: PathBuf::from(text.trim()), work_tree: Some(tree.clone()) };
        if gate.git_dir.starts_with(repo.git_dir.join("worktrees")) && gate.git_dir.is_dir() && tree.is_dir() {
            apply_diff(&gate, base, &Diff::default(), Path::new("/dev/null"))?;
            return Ok(gate);
        }
    }
    let _ = remove_worktree(repo, &tree);
    if tree.exists() {
        std::fs::remove_dir_all(&tree).map_err(|error| format!("{}: {error}", tree.display()))?;
    }
    let gate = add_worktree(repo, &tree, base)?;
    std::fs::write(&record, gate.git_dir.display().to_string()).map_err(|error| error.to_string())?;
    Ok(gate)
}

/// Removes what a run made outside its run directory (and the large parts inside), even when it fails.
#[derive(Clone)]
struct Cleanup {
    directories: Vec<PathBuf>,
    keep: bool,
}

impl Cleanup {
    fn run(&self) {
        if self.keep {
            return;
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
        .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !id.is_empty() && id.len() < 64)
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

/// Reads the session tree's change into the gate's worktree, under the gate lock.
fn read_change(harness: &Harness<'_>, session: &Path, reference: &Path) -> Result<Diff, String> {
    let _busy = harness.busy.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    capture(session, reference, &harness.capture, &harness.base, harness.family.allowlist)
}

/// Answers the session's gate requests until `stop` is set; requests still pending then are answered as refused.
fn serve_gates(
    harness: &Harness<'_>,
    spool: &Path,
    tree: (&Path, &Path),
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
            let result = read_change(harness, tree.0, tree.1).and_then(|diff| harness.run(&diff, &out));
            let (value, passed) = match &result {
                Ok(run) => (session_answer(run, served, max - served), run.passed),
                Err(_) => {
                    (json!({"passed": false, "error": "the gate failed to run; the operator has the details"}), false)
                }
            };
            match &result {
                Ok(run) => {
                    let _ = write_json(&out.join("gate.json"), run);
                }
                Err(error) => {
                    let _ = write_json(&out.join("error.json"), &json!({"error": error}));
                }
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

struct SessionSetup<'a> {
    dir: &'a Path,
    session_root: &'a Path,
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

/// Runs the session: the agent through the runner, or a script standing in for it, both inside the session's sandbox
/// and both stopped by the harness at the latest 15 minutes after the session's cap. Returns the runner's result (or
/// the script's exit) as JSON.
fn run_session(setup: &SessionSetup<'_>) -> Result<Value, String> {
    let started = Instant::now();
    let limit = Duration::from_secs(setup.timeout_s + 900);
    match setup.script {
        Some(script) => {
            let sandbox = setup.sandbox.reading(&[script.parent().unwrap_or(Path::new("/"))]);
            let mut command = sandbox.command(&setup.dir.join("session.sb"), Path::new("/bin/sh"))?;
            command.arg(script).current_dir(setup.worktree).env_clear();
            for key in ["HOME", "USER", "LOGNAME", "LANG", "SHELL", "TERM"] {
                if let Ok(value) = std::env::var(key) {
                    command.env(key, value);
                }
            }
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
            // Inside the session root: the sandboxed claude must be able to read its settings.
            let settings = setup.session_root.join("settings.json");
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
            let finished = run_logged(&mut command, &setup.dir.join("runner.log"), limit)?;
            read_json::<Value>(&result_path)
                .map_err(|error| format!("runner ended (in time: {finished}) without a result: {error}"))
        }
    }
}

/// Bundled databases plus fuzzy matching at 0.95/0.05 over the base's names, on dev and the negatives: the best
/// matcher that failed the final split, reported beside the baseline. Cached per corpus, harness build and base.
fn fuzzy_reference(engine: &Engine, base: &BTreeMap<Split, Named>, cache: &Path) -> Result<Value, String> {
    use rampage_api::flywheel::fuzzy_arm::{Names, measure};
    let mut key = String::new();
    for named in base.values() {
        for (id, binary) in &named.names.binaries {
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
        names.extend(proposals(engine, split, &base[&split].names).map_err(|error| error.to_string())?.names);
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
        let before = proposals(engine, split, &base[&split].names).map_err(|error| error.to_string())?;
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
            for note in &gate.operator_notes {
                text.push_str(&format!("\nOperator note: {note}\n"));
            }
            if !gate.failing_slices.is_empty() {
                let shown: Vec<&str> = gate.failing_slices.iter().take(20).map(String::as_str).collect();
                let more = gate.failing_slices.len().saturating_sub(shown.len());
                let rest = if more > 0 { format!(" and {more} more (`gate/gate.json`)") } else { String::new() };
                text.push_str(&format!("\nSlices losing F1: {}{rest}.\n", shown.join(", ")));
            }
            if !gate.times.is_empty() {
                text.push_str("\nNaming wall time per split (base, candidate, bound): ");
                let times: Vec<String> = gate
                    .times
                    .iter()
                    .map(|time| {
                        let label = if time.split == "heldout" { "dev" } else { time.split.as_str() };
                        format!(
                            "{label} {:.0}/{:.0}/{:.0} s",
                            time.base_ms as f64 / 1e3,
                            time.candidate_ms as f64 / 1e3,
                            time.bound_ms as f64 / 1e3
                        )
                    })
                    .collect();
                text.push_str(&format!("{}.\n", times.join(", ")));
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
    text.push_str(&format!("{}\n", run["final"]["summary"].as_str().unwrap_or("Not earned.")));
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

/// The repository, the base commit, the corpus engine and the gate directory every code-loop command starts from.
struct Setup {
    repo: Repo,
    checkout: PathBuf,
    main_checkout: PathBuf,
    base: String,
    engine: Engine,
    flywheel: PathBuf,
    gate_dir: PathBuf,
    cargo: PathBuf,
    nextest: bool,
    home: PathBuf,
}

fn setup(
    repository_root: Option<&Path>,
    base: &str,
    corpus: &Path,
    flywheel_dir: Option<&Path>,
    gate_dir: Option<&Path>,
    workers: usize,
) -> Result<Setup, String> {
    let root = repository_root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let (repo, checkout) = operator_repo(&root)?;
    let main_checkout = repo.git_dir.parent().map(Path::to_path_buf).unwrap_or_else(|| checkout.clone());
    let base = repo.resolve(base)?;
    let engine = open_engine(&canonical(corpus), flywheel_dir, workers)?;
    let flywheel = canonical(engine.paths.root());
    let gate_dir = canonical(&gate_dir.map(Path::to_path_buf).unwrap_or_else(|| flywheel.join("code-runs/gate")));
    create_dir(&gate_dir)?;
    let cargo = find_program(&std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))?;
    let nextest = Command::new(&cargo).args(["nextest", "--version"]).output().is_ok_and(|out| out.status.success());
    let home = canonical(&std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default());
    Ok(Setup { repo, checkout, main_checkout, base, engine, flywheel, gate_dir, cargo, nextest, home })
}

impl Setup {
    /// What no agent-influenced process may read: the corpus, the flywheel directory (caches, runs, the ledger, the
    /// gate's results), both checkouts (their target directories, other agents' worktrees, the git object store),
    /// Claude Code's per-user directory (transcripts, history), other sessions' scratch
    /// files, and anything the operator adds.
    fn deny(&self, extra: &[PathBuf]) -> Vec<PathBuf> {
        let uid = output(Command::new("id").arg("-u")).unwrap_or_default().trim().to_owned();
        let mut deny = vec![
            canonical(&self.engine.corpus.root),
            self.flywheel.clone(),
            self.main_checkout.clone(),
            self.checkout.clone(),
            canonical(&self.home.join(".claude")),
        ];
        if !uid.is_empty() {
            deny.push(canonical(&Path::new("/tmp").join(format!("claude-{uid}"))));
        }
        deny.extend(extra.iter().map(|path| canonical(path)));
        deny.sort();
        deny.dedup();
        deny
    }
}

/// `flywheel-code-run`.
pub fn run(args: CodeRunArgs) -> Result<ExitCode, String> {
    let family = family(&args.family)?;
    check_budget(args.budget_usd)?;
    interrupt::install();
    let setup = setup(
        args.repository_root.as_deref(),
        &args.base,
        &args.corpus,
        args.flywheel_dir.as_deref(),
        args.gate_dir.as_deref(),
        args.workers,
    )?;
    let config = gate_config(args.gate.as_deref())?;
    let label = args.label.clone().unwrap_or_else(|| {
        format!(
            "code-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
        )
    });
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        return Err(format!("label {label:?} must be a plain identifier"));
    }
    let run_dir = setup.flywheel.join("code-runs").join(&label);
    if run_dir.exists() {
        return Err(format!("{} exists; choose another --label", run_dir.display()));
    }
    let session_root = canonical(
        &args.session_root.clone().unwrap_or_else(|| std::env::temp_dir().join("rampage-code-run")).join(&label),
    );
    let deny = setup.deny(&args.deny_read);
    if let Some(denied) = deny.iter().find(|denied| session_root.starts_with(denied)) {
        return Err(format!(
            "the session root {} lies in {}, which the session may not read",
            session_root.display(),
            denied.display()
        ));
    }
    let mut runner: Vec<PathBuf> = args.runner.split_whitespace().map(PathBuf::from).collect();
    if runner.is_empty() {
        return Err("empty runner command".to_owned());
    }
    for part in runner.iter_mut().skip(1) {
        if part.extension().is_some_and(|extension| extension == "py" || extension == "sh") && part.is_relative() {
            *part = setup.checkout.join(&*part);
        }
    }
    let script = args.session_script.as_deref().map(canonical);

    create_dir(&run_dir)?;
    let started = Instant::now();
    let _gate_lock =
        rampage_api::flywheel::FileLock::acquire(&setup.gate_dir.join("lock")).map_err(|error| error.to_string())?;
    let views_root = run_dir.join("views");
    let cleanup = Cleanup {
        directories: vec![
            session_root.clone(),
            views_root.clone(),
            run_dir.join("base/bin"),
            run_dir.join("reference"),
        ],
        keep: args.keep_workspace,
    };
    let on_interrupt = cleanup.clone();
    interrupt::set_cleanup(Box::new(move || on_interrupt.run()));
    let result = code_run(
        &args,
        family,
        &setup,
        config,
        &label,
        &run_dir,
        &session_root,
        &deny,
        &runner,
        script.as_deref(),
        started,
    );
    cleanup.run();
    interrupt::clear_cleanup();
    result
}

#[allow(clippy::too_many_arguments)]
fn code_run(
    args: &CodeRunArgs,
    family: &'static Family,
    setup: &Setup,
    config: GateConfig,
    label: &str,
    run_dir: &Path,
    session_root: &Path,
    deny: &[PathBuf],
    runner: &[PathBuf],
    script: Option<&Path>,
    started: Instant,
) -> Result<ExitCode, String> {
    let engine = &setup.engine;
    eprintln!("code run {label}: base {}, run directory {}", setup.base, run_dir.display());

    // The scorer's truth and baseline analysis (this trusted build), before anything else.
    let indices: Vec<usize> = GATED.iter().flat_map(|split| engine.corpus.indices(*split)).collect();
    let load = engine.load_all(&indices).map_err(|error| error.to_string())?;
    eprintln!("scorer: {} binaries loaded ({} analysed, {} ms)", load.binaries, load.analysed, load.elapsed_ms);

    let gate = gate_worktree(&setup.repo, &setup.gate_dir, "worktree", &setup.base)?;
    let capture_tree = gate_worktree(&setup.repo, &setup.gate_dir, "capture", &setup.base)?;
    private_registry(
        &operator_cargo_home(&setup.home),
        gate.work_tree.as_deref().unwrap_or(Path::new(".")),
        &setup.gate_dir.join("cargo-home"),
    )?;
    let views = Views::new(run_dir.join("views"), args.workers);
    for split in GATED {
        views.make(&engine.corpus, split)?;
    }
    let base_dir = run_dir.join("base");
    let mut harness = Harness {
        base: setup.base.clone(),
        run_dir: run_dir.to_path_buf(),
        gate,
        capture: capture_tree,
        gate_dir: setup.gate_dir.clone(),
        views,
        engine,
        config,
        limits: args.limits,
        base_names: BTreeMap::new(),
        base_binary: base_dir.join("bin/rampage-eval"),
        base_build_id: String::new(),
        deny: deny.to_vec(),
        family,
        cargo: setup.cargo.clone(),
        nextest: setup.nextest,
        busy: Mutex::new(()),
    };
    // The base build and its names: the baseline every gate compares with.
    create_dir(&base_dir)?;
    let base_binary = harness
        .build(&base_dir, "build.log")?
        .ok_or_else(|| format!("the base does not build:\n{}", tail(&base_dir.join("build.log"), 40)))?;
    harness.base_binary = base_binary;
    for split in GATED {
        let (named, id) = harness
            .base_names(split, &base_dir)
            .map_err(|error| format!("{error} (a base before the code-run harness cannot be gated)"))?;
        harness.base_build_id = id;
        harness.base_names.insert(split, named);
    }
    eprintln!("base names: {} ms since start", started.elapsed().as_millis());
    let fuzzy = if args.no_fuzzy_reference {
        Value::Null
    } else {
        fuzzy_reference(engine, &harness.base_names, &setup.flywheel.join("code-runs/cache"))?
    };

    // The session's workspace: an export of the base (no tie to the repository), the harness's reference copy of it,
    // a private registry and temp directory, the training view, the gate spool and client.
    let worktree = session_root.join("worktree");
    let reference = run_dir.join("reference");
    export_tree(&setup.repo, &setup.base, &worktree, SESSION_EXCLUDED)?;
    export_tree(&setup.repo, &setup.base, &reference, SESSION_EXCLUDED)?;
    let session_git = Repo { git_dir: worktree.join(".git"), work_tree: Some(worktree.clone()) };
    output(
        Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["init", "-q"])
            .arg(&worktree),
    )?;
    output(session_git.git().args(["add", "-A"]))?;
    output(
        session_git
            .git()
            .args(["-c", "user.name=rampage flywheel", "-c", "user.email=flywheel@localhost", "commit", "-q", "-m"])
            .arg(format!("base {}", setup.base)),
    )?;
    let home = session_root.join("cargo-home");
    private_registry(&operator_cargo_home(&setup.home), &reference, &home)?;
    let tmp = session_root.join("tmp");
    create_dir(&tmp)?;
    let train_view = session_root.join("flywheel/corpus").join(format!("{}-train", engine.corpus.version()));
    make_view(&engine.corpus, &[Role::Train, Role::Negative], true, &train_view)?;
    let spool = session_root.join("gate");
    for directory in ["requests", "responses"] {
        create_dir(&spool.join(directory))?;
    }
    let bin = session_root.join("bin");
    create_dir(&bin)?;
    let client = bin.join("flywheel-gate");
    std::fs::write(&client, gate_client(&spool)).map_err(|error| error.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    }
    let session_dir = run_dir.join("session");
    create_dir(&session_dir)?;
    let prompt = libid_prompt(&setup.base, &worktree, &train_view, &client, args.max_session_gates, family.allowlist);
    std::fs::write(session_dir.join("prompt.md"), &prompt).map_err(|error| error.to_string())?;

    // The way out: the proxy, tunnelling to the model's API only.
    let mut hosts: Vec<String> = DEFAULT_HOSTS.iter().map(|host| (*host).to_owned()).collect();
    hosts.extend(args.allow_host.iter().cloned());
    let proxy = Proxy::start(hosts.clone(), session_dir.join("proxy.log"))?;
    let client_project = setup.home.join(".claude/projects").join(
        worktree.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>(),
    );
    let mut writable: Vec<PathBuf> = vec![session_root.to_path_buf(), client_project];
    writable.extend(CLAUDE_HOME_WRITABLE.iter().map(|path| setup.home.join(path)));
    writable.extend(args.claude_allow.iter().map(|path| canonical(path)));
    let session_sandbox = Sandbox {
        deny: deny.to_vec(),
        protect: vec![setup.home.clone()],
        deny_all_writes: false,
        read_only: Vec::new(),
        allow: writable,
        network: Network::Proxy(proxy.port),
    };
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let path = std::env::var("PATH").unwrap_or_default();
    let environment: BTreeMap<String, String> = [
        ("CARGO_HOME", home.display().to_string()),
        ("CARGO_TARGET_DIR", session_root.join("target").display().to_string()),
        ("CARGO_NET_OFFLINE", "true".to_owned()),
        ("CARGO_TERM_COLOR", "never".to_owned()),
        ("TMPDIR", tmp.display().to_string()),
        ("HTTPS_PROXY", proxy_url.clone()),
        ("HTTP_PROXY", proxy_url.clone()),
        ("https_proxy", proxy_url.clone()),
        ("http_proxy", proxy_url),
        ("NO_PROXY", String::new()),
        ("DISABLE_AUTOUPDATER", "1".to_owned()),
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
        let server = scope
            .spawn(|| serve_gates(&harness, &spool, (&worktree, &reference), args.max_session_gates, &stop, &calls));
        let result = run_session(&SessionSetup {
            dir: &session_dir,
            session_root,
            worktree: &worktree,
            sandbox: &session_sandbox,
            environment: &environment,
            add_dirs: &add_dirs,
            script,
            runner,
            model: &args.model,
            max_turns: args.max_turns,
            timeout_s: args.timeout_s,
            budget_usd: args.budget_usd,
        });
        stop.store(true, Ordering::SeqCst);
        let _ = server.join();
        result
    });
    drop(proxy);
    let session = session.unwrap_or_else(|error| json!({"exit": "error", "error": error}));
    let session_gates = calls.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);

    // The authoritative gate on what the session left.
    let diff = read_change(&harness, &worktree, &reference)?;
    std::fs::write(run_dir.join("candidate.diff"), &diff.patch).map_err(|error| error.to_string())?;
    let gate_run = harness.run(&diff, &run_dir.join("gate"))?;
    write_json(&run_dir.join("gate/gate.json"), &gate_run)?;

    let final_read = if gate_run.passed {
        let would = json!({
            "split": "final",
            "binaries": engine.corpus.indices(Split::Final).len(),
            "corpus": engine.corpus.key(),
            "ledger": engine.corpus.root.join("final-ledger.jsonl"),
            "next_read": next_final_read(engine)?,
        });
        write_json(&run_dir.join("final-plan.json"), &would)?;
        json!({"earned": true, "read": false, "would_read": would, "summary": format!(
            "Earned, not read: the gate passed. Review `candidate.diff`, then make the one ledgered read with \
             `rampage-eval flywheel-code-final --corpus {} --label {label} --reason TEXT` ({} final binaries, which \
             would be read #{} of the corpus's ledger). Nothing was read and the ledger is unchanged.",
            engine.corpus.root.display(), would["binaries"], would["next_read"]
        )})
    } else {
        json!({"earned": false, "summary": format!(
            "Not earned: the gate failed at `{}`. The final split was not read and the ledger is unchanged.",
            gate_run.failed_at().unwrap_or("?")
        )})
    };
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
        "base": setup.base,
        "corpus": engine.corpus.key(),
        "model": args.model,
        "budget_usd": args.budget_usd,
        "timeout_s": args.timeout_s,
        "max_session_gates": args.max_session_gates,
        "session": session_record,
        "session_gates": session_gates,
        "allowlist": family.allowlist,
        "proxy_hosts": hosts,
        "sandbox": {"deny": deny, "session_allow": session_sandbox.allow, "protect": session_sandbox.protect},
        "diff_sha256": diff.sha256(),
        "gate": {
            "passed": gate_run.passed,
            "failed_at": gate_run.failed_at(),
            "stages": gate_run.stages,
            "deltas": gate_run.evaluations.iter().map(|(split, evaluation)| (split.clone(), overall_delta(evaluation))).collect::<BTreeMap<_, _>>(),
            "times": gate_run.times,
        },
        "fuzzy_reference": fuzzy,
        "final": final_read,
        "total_ms": started.elapsed().as_millis() as u64,
    });
    write_json(&run_dir.join("run.json"), &record)?;
    let report = report_markdown(&record, Some(&gate_run), &diff);
    std::fs::write(run_dir.join("report.md"), &report).map_err(|error| error.to_string())?;
    // Binaries and test targets are large and rebuilt from the diff when needed.
    let mut large = vec![run_dir.join("gate/bin"), run_dir.join("gate/generated")];
    for entry in std::fs::read_dir(run_dir.join("session-gates")).into_iter().flatten().flatten() {
        large.push(entry.path().join("bin"));
        large.push(entry.path().join("generated"));
    }
    for directory in large {
        let _ = std::fs::remove_dir_all(directory);
    }
    eprintln!("{report}");
    eprintln!("run directory: {}", run_dir.display());
    Ok(if gate_run.passed { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// The ledger's earlier code-run reads of `diff_sha256` on `base`.
fn earlier_reads(ledger: &Path, diff_sha256: &str, base: &str) -> Vec<u64> {
    let text = std::fs::read_to_string(ledger).unwrap_or_default();
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["code_run"]["diff_sha256"] == diff_sha256 && entry["code_run"]["base"] == base)
        .filter_map(|entry| entry["read"].as_u64())
        .collect()
}

/// `flywheel-code-final`: the one ledgered read of the final split for a run whose gate passed.
pub fn final_read(args: CodeFinalArgs) -> Result<ExitCode, String> {
    if args.reason.trim().is_empty() {
        return Err("--reason must say why the read is made".to_owned());
    }
    interrupt::install();
    let probe = open_engine(&canonical(&args.corpus), args.flywheel_dir.as_deref(), 1)?;
    let run_dir = canonical(probe.paths.root()).join("code-runs").join(&args.label);
    let record: Value = read_json(&run_dir.join("run.json"))?;
    if record["gate"]["passed"].as_bool() != Some(true) {
        return Err(format!(
            "run {} did not pass its gate; the final split is read only after a full pass",
            args.label
        ));
    }
    let base = record["base"].as_str().ok_or("run.json has no base")?.to_owned();
    let patch =
        std::fs::read_to_string(run_dir.join("candidate.diff")).map_err(|error| format!("candidate.diff: {error}"))?;
    let mut diff = Diff { patch, paths: Vec::new(), special: Vec::new() };
    diff.paths = diff
        .patch
        .lines()
        .filter_map(|line| {
            line.strip_prefix("diff --git a/").and_then(|rest| rest.split_once(" b/")).map(|(_, b)| b.to_owned())
        })
        .collect();
    if record["diff_sha256"].as_str() != Some(diff.sha256().as_str()) {
        return Err("candidate.diff is not the change the run gated".to_owned());
    }
    let setup = setup(
        args.repository_root.as_deref(),
        &base,
        &args.corpus,
        args.flywheel_dir.as_deref(),
        args.gate_dir.as_deref(),
        args.workers,
    )?;
    let engine = &setup.engine;
    let ledger = engine.corpus.root.join("final-ledger.jsonl");
    let earlier = earlier_reads(&ledger, &diff.sha256(), &base);
    if !earlier.is_empty() {
        return Err(format!("this change on this base was already read (read {earlier:?}); a second read is refused"));
    }
    let family = family(record["family"].as_str().unwrap_or(FAMILY))?;
    let _gate_lock =
        rampage_api::flywheel::FileLock::acquire(&setup.gate_dir.join("lock")).map_err(|error| error.to_string())?;
    let out = run_dir.join("final");
    let cleanup =
        Cleanup { directories: vec![out.join("views"), out.join("base/bin"), out.join("candidate/bin")], keep: false };
    let on_interrupt = cleanup.clone();
    interrupt::set_cleanup(Box::new(move || on_interrupt.run()));
    let result = (|| -> Result<ExitCode, String> {
        let gate = gate_worktree(&setup.repo, &setup.gate_dir, "worktree", &base)?;
        let capture = gate_worktree(&setup.repo, &setup.gate_dir, "capture", &base)?;
        private_registry(
            &operator_cargo_home(&setup.home),
            gate.work_tree.as_deref().unwrap_or(Path::new(".")),
            &setup.gate_dir.join("cargo-home"),
        )?;
        let views = Views::new(out.join("views"), args.workers);
        views.make(&engine.corpus, Split::Train)?;
        let mut harness = Harness {
            base: base.clone(),
            run_dir: run_dir.clone(),
            gate,
            capture,
            gate_dir: setup.gate_dir.clone(),
            views,
            engine,
            config: gate_config(args.gate.as_deref())?,
            limits: LimitArgs {
                time_ratio: 4.0,
                time_floor_s: 30,
                max_added_lines: usize::MAX,
                max_literal_lines: usize::MAX,
            },
            base_names: BTreeMap::new(),
            base_binary: PathBuf::new(),
            base_build_id: String::new(),
            deny: setup.deny(&[]),
            family,
            cargo: setup.cargo.clone(),
            nextest: setup.nextest,
            busy: Mutex::new(()),
        };
        // Builds first: a change that no longer builds must not use up the read.
        let base_dir = out.join("base");
        create_dir(&base_dir)?;
        harness.base_binary = harness.build(&base_dir, "build.log")?.ok_or("the base does not build")?;
        // The training discovery, which generation reads, and the base build's id.
        let (_, id) = harness.base_names(Split::Train, &base_dir)?;
        harness.base_build_id = id;
        let cand_dir = out.join("candidate");
        create_dir(&cand_dir)?;
        let mut run = GateRun::new(&diff);
        let binary = harness
            .prepare(&diff, &cand_dir, &mut run, false)?
            .ok_or_else(|| format!("the candidate does not build again: {:?}", run.stages))?;
        let (read, entry) = record_final_read_with(
            engine,
            &format!(
                "flywheel-code-final {} ({}): source change {} on base {}; {}",
                args.label,
                family.name,
                &diff.sha256()[..12],
                &base[..12],
                args.reason.trim()
            ),
            &[],
            Some(
                &json!({"code_run": {"label": args.label, "family": family.name, "base": base, "diff_sha256": diff.sha256()}}),
            ),
        )?;
        write_json(&run_dir.join("ledger-entry.json"), &entry)?;
        eprintln!("final read #{read} recorded in {}", ledger.display());
        harness.views.make(&engine.corpus, Split::Final)?;
        let (base_named, _) = harness.base_names(Split::Final, &base_dir)?;
        let cand_named =
            harness.names(&binary, Split::Final, &cand_dir, Discovery::Read(harness.base_build_id.clone()))?;
        let before = proposals(engine, Split::Final, &base_named.names).map_err(|error| error.to_string())?;
        let after = proposals(engine, Split::Final, &cand_named.names).map_err(|error| error.to_string())?;
        let evaluation = compare(engine, Split::Final, &before, &after).map_err(|error| error.to_string())?;
        let verdict = harness.config.heldout(&evaluation, false);
        let delta = overall_delta(&evaluation);
        let mut result = json!({
            "read": read, "passed": verdict.passed, "checks": verdict.checks, "delta": delta,
            "slices": evaluation.metrics(), "baseline": evaluation.reference_metrics(), "deltas": evaluation.deltas(),
        });
        if verdict.passed {
            let branch = format!("flywheel/code-{}", args.label);
            let message = format!(
                "flywheel code run {}: {} source change\n\nGate passed; final read #{read} passed with overall delta \
                 {delta}. Produced unattended by `rampage-eval flywheel-code-run`; review before merging.\n",
                args.label, family.name
            );
            // The tree holds the change and its generated data, as measured.
            output(harness.gate.git().args(["add", "-A"]))?;
            output(harness.gate.git().args([
                "-c",
                "user.name=rampage flywheel",
                "-c",
                "user.email=flywheel@localhost",
                "commit",
                "-q",
                "-m",
                &message,
            ]))?;
            output(harness.gate.git().args(["branch", &branch, "HEAD"]))?;
            result["branch"] = json!(branch);
        }
        write_json(&run_dir.join("final.json"), &result)?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"read": read, "passed": verdict.passed, "delta": delta, "branch": result.get("branch")})
            )
            .map_err(|error| error.to_string())?
        );
        Ok(if verdict.passed { ExitCode::SUCCESS } else { ExitCode::from(1) })
    })();
    cleanup.run();
    interrupt::clear_cleanup();
    result
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
    fn a_final_read_is_appended_to_the_ledger_and_a_second_read_of_the_same_change_is_refused() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let engine = Engine::new(corpus(&root), Paths::new(root.join("flywheel")), 1);
        assert_eq!(next_final_read(&engine).unwrap(), 1);
        std::fs::write(root.join("final-ledger.jsonl"), "{\"read\":1,\"reason\":\"arm v2 claim\"}\n").unwrap();
        assert_eq!(next_final_read(&engine).unwrap(), 2);
        let ledger = root.join("final-ledger.jsonl");
        assert!(earlier_reads(&ledger, "def", "abc").is_empty());
        let extra = json!({"code_run": {"label": "code-1", "base": "abc", "diff_sha256": "def"}});
        let (read, entry) = record_final_read_with(&engine, "code run claim", &[], Some(&extra)).unwrap();
        assert_eq!(read, 2);
        let text = std::fs::read_to_string(&ledger).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "{\"read\":1,\"reason\":\"arm v2 claim\"}", "earlier reads are kept as they were");
        let written: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(written, entry);
        assert_eq!((written["read"].as_u64(), written["reason"].as_str()), (Some(2), Some("code run claim")));
        assert_eq!(written["code_run"]["label"], "code-1");
        assert_eq!(earlier_reads(&ledger, "def", "abc"), [2]);
        assert!(earlier_reads(&ledger, "def", "other-base").is_empty());
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
            stage("time", true, "0 of 3 splits over"),
        ];
        run.times =
            vec![SplitTime { split: "heldout".to_owned(), base_ms: 1, candidate_ms: 2, bound_ms: 3, passed: true }];
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
        assert!(!text.contains("+7") && !text.contains("splits over"), "a dev or time detail leaked: {text}");
        assert!(answer.get("time").is_none() && !text.contains("base_ms"), "{text}");
        assert_eq!(answer["dev"]["delta"]["tp"], 1);
        assert_eq!(answer["dev"]["rules"], json!([{"rule": "heldout_f1_gain", "passed": false}]));
        assert_eq!(answer["train"]["failing_slices"], json!(["train arch:x86_64"]));
        let mut keys: Vec<&String> = answer["dev"].as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["delta", "passed", "rules"]);
    }

    #[test]
    fn a_naming_failure_reaches_the_session_without_its_log() {
        let mut run = GateRun::new(&Diff::default());
        run.stages = vec![stage("policy", true, ""), stage("names", false, "naming a split with the change failed")];
        run.operator_notes = vec![
            "naming heldout failed; see /flywheel/code-runs/x/gate/names-v1234.log: panicked at zlib-1.3.1".to_owned(),
        ];
        let text = session_answer(&run, 1, 7).to_string();
        assert!(!text.contains("zlib-1.3.1") && !text.contains("names-v1234") && !text.contains("panicked"), "{text}");
        assert!(text.contains("\"names\""), "{text}");
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
    fn the_prompt_names_the_gate_the_allowlist_the_generator_and_the_final_split_rule() {
        let prompt = libid_prompt(
            "abc123",
            Path::new("/s/worktree"),
            Path::new("/s/flywheel/corpus/libid-x-train"),
            Path::new("/s/bin/flywheel-gate"),
            8,
            LIBID_ALLOWLIST,
        );
        for needle in [
            "/s/bin/flywheel-gate",
            "crates/rampage-signatures/src/callgraph.rs",
            "final split",
            "20,497",
            "8 calls",
            "heuristics::data()",
            "no network",
        ] {
            assert!(prompt.contains(needle), "{needle}");
        }
    }

    #[test]
    fn the_budget_is_capped_per_family_per_run() {
        assert!(check_budget(5.0).is_ok() && check_budget(0.5).is_ok());
        for budget in [5.01, 0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(check_budget(budget).is_err(), "{budget}");
        }
        assert!(family("libid").is_ok() && family("toolid").is_err());
    }

    /// The private registry holds the index and exactly the locked archives, and builds offline.
    #[test]
    fn a_private_registry_copies_only_the_locked_archives() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (operator, tree, home) = (root.join("operator"), root.join("tree"), root.join("home"));
        let index = "index.crates.io-0000";
        std::fs::create_dir_all(operator.join("registry/index").join(index).join(".cache")).unwrap();
        std::fs::create_dir_all(operator.join("registry/cache").join(index)).unwrap();
        for file in ["serde-1.0.0.crate", "zstd-sys-2.0.0.crate"] {
            std::fs::write(operator.join("registry/cache").join(index).join(file), file).unwrap();
        }
        std::fs::create_dir_all(&tree).unwrap();
        let lock = "version = 4\n\n[[package]]\nname = \"rampage\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\n\
                    version = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        std::fs::write(tree.join("Cargo.lock"), lock).unwrap();
        assert_eq!(locked_packages(lock), [("serde".to_owned(), "1.0.0".to_owned())]);
        private_registry(&operator, &tree, &home).unwrap();
        let cache = home.join("registry/cache").join(index);
        assert!(cache.join("serde-1.0.0.crate").is_file());
        assert!(!cache.join("zstd-sys-2.0.0.crate").exists(), "an unlocked crate was copied");
        assert!(home.join("registry/index").join(index).is_dir());
        assert!(std::fs::read_to_string(home.join("config.toml")).unwrap().contains("offline = true"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Views other than training hide which split they are: neutral ids, no version, the same role, random names.
    #[test]
    fn non_training_views_are_neutral() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-views-{}", std::process::id()));
        let source = root.join("corpus");
        std::fs::create_dir_all(source.join("bin")).unwrap();
        for id in ["a", "f"] {
            std::fs::write(source.join(format!("bin/{id}.elf")), id).unwrap();
            std::fs::write(source.join(format!("bin/{id}.twin.elf")), id).unwrap();
        }
        let views = Views::new(root.join("views"), 1);
        views.make(&corpus(&source), Split::Final).unwrap();
        views.make(&corpus(&source), Split::Train).unwrap();
        let (dir, ids) = views.get(Split::Final).unwrap();
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with('v') && !name.contains("final"), "{name}");
        assert_eq!(ids, BTreeMap::from([("b0001".to_owned(), "f".to_owned())]));
        let manifest = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        assert!(
            !manifest.contains("\"final\"") && !manifest.contains("1.2.12") && !manifest.contains("\"f\""),
            "{manifest}"
        );
        assert!(!dir.join("bin/f.twin.elf").exists() && dir.join("bin/b0001.elf").is_file());
        let (train, train_ids) = views.get(Split::Train).unwrap();
        assert!(train.ends_with("train") && train_ids.is_empty() && train.join("bin/a.twin.elf").is_file());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
