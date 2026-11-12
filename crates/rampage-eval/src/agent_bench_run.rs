//! `rampage-eval agent-bench`: run the canonical tasks through an external agent runner against each MCP
//! server, sequentially, and score the normalized results. See `rampage_eval::agent_bench`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_eval::agent_bench::{
    NeutralSuite, RunRow, RunnerResult, markdown_tables, rescored_report, score, summarize,
};
use rampage_eval::parity_tasks::{ParityTask, load_tasks};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::read;

/// Suite v3's REA Ghidra limits when the command line sets none.
pub const V3_REA_GHIDRA_STARTUP_TIMEOUT_MS: u64 = 3_600_000;
pub const V3_REA_GHIDRA_MAXMEM: &str = "16G";

pub const DEFAULT_RUNNER: &str = "python3 -I tools/agent-bench/claude-runner.py";

/// Which task set to run: the frozen canonical manifests with `tasks/h2h/neutral.toml`, or suite v2's (v3's)
/// manifests under `tasks/v2/` (`tasks/v3/`) with `tasks/h2h/neutral-v2.toml` (`neutral-v3.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Suite {
    Canonical,
    V2,
    V3,
}

impl Suite {
    fn paths(self, root: &Path) -> (PathBuf, PathBuf) {
        let tasks = root.join("crates/rampage-eval/tasks");
        match self {
            Self::Canonical => (tasks.clone(), tasks.join("h2h/neutral.toml")),
            Self::V2 => (tasks.join("v2"), tasks.join("h2h/neutral-v2.toml")),
            Self::V3 => (tasks.join("v3"), tasks.join("h2h/neutral-v3.toml")),
        }
    }
}

#[derive(clap::Args)]
pub struct AgentBenchArgs {
    /// The task set.
    #[arg(long, value_enum, default_value = "canonical")]
    suite: Suite,
    /// MCP servers to compare, in run order within each task.
    #[arg(long, value_delimiter = ',', default_value = "rampage,rea")]
    servers: Vec<String>,
    /// Task ids, or `all` for the canonical set.
    #[arg(long, value_delimiter = ',', default_value = "all")]
    tasks: Vec<String>,
    /// Runs per task and server; every repetition counts.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=20))]
    repeat: u32,
    #[arg(long, default_value = "claude-sonnet-5-5")]
    model: String,
    /// Model turn limit per run, unless the task sets its own.
    #[arg(long, default_value_t = 40)]
    max_turns: u32,
    /// Wall-clock limit per run in seconds, unless the task sets its own.
    #[arg(long, default_value_t = 900)]
    timeout_s: u64,
    /// Stop before starting another run once the reported model spend reaches this many US dollars, counting
    /// --spent-usd and every run so far; the report records the stop.
    #[arg(long)]
    cost_cap_usd: Option<f64>,
    /// Spend already used by earlier passes of the same workstream, counted against --cost-cap-usd.
    #[arg(long, default_value_t = 0.0, requires = "cost_cap_usd")]
    spent_usd: f64,
    /// REA_GHIDRA_STARTUP_TIMEOUT_MS for the REA server: how long REA lets Ghidra import and analyze before
    /// failing (REA's own default, 330000, applies when unset; suite v3 defaults to 3600000).
    #[arg(long)]
    rea_ghidra_startup_timeout_ms: Option<u64>,
    /// GHIDRA_HEADLESS_MAXMEM for the REA server: the Java heap REA gives headless Ghidra (REA's own default,
    /// 2G, applies when unset; suite v3 defaults to 16G), such as `16G`.
    #[arg(long)]
    rea_ghidra_maxmem: Option<String>,
    /// Measurements made outside the agent runs (NAME=PATH to a JSON file), embedded in the report under
    /// `attachments.NAME`.
    #[arg(long = "attach", value_parser = parse_attachment)]
    attachments: Vec<(String, PathBuf)>,
    /// The runner command, split on whitespace; a relative script path resolves against the repository root.
    #[arg(long, default_value = DEFAULT_RUNNER)]
    runner: String,
    #[arg(long)]
    repository_root: Option<PathBuf>,
    /// The `rampage` CLI whose `mcp` command is benchmarked (default: target/release/rampage).
    #[arg(long)]
    rampage_bin: Option<PathBuf>,
    /// REA's `scripts/rea.mjs` (default: target/bench/rea/src/scripts/rea.mjs).
    #[arg(long)]
    rea_entry: Option<PathBuf>,
    /// The install record written when REA was installed (default: target/bench/rea/install.json).
    #[arg(long)]
    rea_install_record: Option<PathBuf>,
    /// The Node.js executable REA runs under.
    #[arg(long, default_value = "node")]
    node: PathBuf,
    /// Ghidra's install directory (the one holding `Ghidra/application.properties`).
    #[arg(long, default_value = "/opt/homebrew/Cellar/ghidra/12.2/libexec")]
    ghidra_dir: PathBuf,
    #[arg(long, default_value = "/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home")]
    java_home: PathBuf,
    /// Run records, configs and private transcripts go here (default: target/bench/h2h/<label>).
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// A name for this run, used in the default output directory and the report.
    #[arg(long, default_value = "run")]
    label: String,
    /// Publishable report paths; they hold measurements only, never transcripts or answers.
    #[arg(long, requires = "report_md")]
    report_json: Option<PathBuf>,
    #[arg(long, requires = "report_json")]
    report_md: Option<PathBuf>,
    /// Spend no model usage: have the runner recompute each result in --out-dir from its recorded transcript
    /// (`--renormalize`), then score and report again. The earlier rows are kept as runs.before-rescore.jsonl.
    #[arg(long)]
    rescore: bool,
    /// Why the run is being rescored; recorded in the report's `rescore` block.
    #[arg(long, requires = "rescore", default_value = "rescored from the recorded transcripts")]
    rescore_reason: String,
    /// Run these runs again (TASK:SERVER:REPETITION, repeatable) in an existing --out-dir and keep every other
    /// recorded run: the earlier rows move to the report's `superseded_runs` and their directories to
    /// runs/superseded/. For runs a harness fault may have affected, never to retry an outcome.
    #[arg(long, conflicts_with = "rescore", requires = "rerun_reason")]
    rerun: Vec<String>,
    /// Why the runs are run again; recorded in the report's `rerun` block.
    #[arg(long)]
    rerun_reason: Option<String>,
    /// MAX_MCP_OUTPUT_TOKENS for every run, the same for every server.
    #[arg(long, default_value_t = 200_000)]
    max_mcp_output_tokens: u64,
    /// REA_MCP_TOOL_FAMILIES for the REA server; unset (REA's complete catalog) by default.
    #[arg(long)]
    rea_tool_families: Option<String>,
}

pub fn run(mut args: AgentBenchArgs) -> Result<ExitCode, String> {
    if args.suite == Suite::V3 {
        // Suite v3's Go fixture needs more than REA's defaults (suite v2 measured 708-2,355 s imports, and an
        // out-of-memory failure at 2G); its run recipe sets the remediations REA's own errors name.
        args.rea_ghidra_startup_timeout_ms.get_or_insert(V3_REA_GHIDRA_STARTUP_TIMEOUT_MS);
        args.rea_ghidra_maxmem.get_or_insert_with(|| V3_REA_GHIDRA_MAXMEM.to_owned());
    }
    let root = args.repository_root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let root = std::fs::canonicalize(&root).map_err(|error| format!("{}: {error}", root.display()))?;
    let (task_directory, suite_path) = args.suite.paths(&root);
    let mut tasks = load_tasks(&task_directory).map_err(|error| error.to_string())?;
    let suite_text = read(&suite_path)?;
    let suite = NeutralSuite::from_toml(&suite_text).map_err(|error| format!("{}: {error}", suite_path.display()))?;
    suite.check_against(&tasks, &args.servers)?;
    if args.tasks != ["all"] {
        if let Some(missing) = args.tasks.iter().find(|id| !tasks.iter().any(|task| &task.id == *id)) {
            return Err(format!("unknown task {missing}"));
        }
        tasks.retain(|task| args.tasks.contains(&task.id));
    }
    for server in &args.servers {
        if !matches!(server.as_str(), "rampage" | "rea") {
            return Err(format!("unknown server {server}; known: rampage, rea"));
        }
    }
    let absolute = |path: Option<&PathBuf>, default: &str| {
        let path = path.cloned().unwrap_or_else(|| root.join(default));
        std::fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))
    };
    let out_dir = args.out_dir.clone().unwrap_or_else(|| root.join("target/bench/h2h").join(&args.label));
    std::fs::create_dir_all(&out_dir).map_err(|error| format!("{}: {error}", out_dir.display()))?;
    let out_dir = std::fs::canonicalize(&out_dir).map_err(|error| error.to_string())?;
    let mut servers = BTreeMap::new();
    let mut versions = json!({});
    for server in &args.servers {
        let (config, version) = match server.as_str() {
            "rampage" => {
                let binary = absolute(args.rampage_bin.as_ref(), "target/release/rampage")?;
                let config = json!({"mcpServers": {"rampage": {"type": "stdio",
                    "command": binary, "args": ["mcp"], "env": {}}}});
                let worker = binary.with_file_name("rampage-worker");
                (
                    config,
                    json!({
                        "binary_sha256": hash_file(&binary)?,
                        "worker_beside_binary": worker.is_file(),
                        "commit": git(&root, &["rev-parse", "HEAD"]),
                        "worktree_dirty": git(&root, &["-c", "core.fsmonitor=false", "status", "--porcelain"])
                            .map(|status| !status.is_empty()),
                        "groups": "default (core plus enable_tools)",
                    }),
                )
            }
            _ => {
                let entry = absolute(args.rea_entry.as_ref(), "target/bench/rea/src/scripts/rea.mjs")?;
                let node = which(&args.node)?;
                let mut env = json!({"GHIDRA_INSTALL_DIR": args.ghidra_dir, "JAVA_HOME": args.java_home,
                    "REA_ANALYSIS_PROVIDER": "ghidra"});
                if let Some(families) = &args.rea_tool_families {
                    env["REA_MCP_TOOL_FAMILIES"] = json!(families);
                }
                if let Some(timeout) = args.rea_ghidra_startup_timeout_ms {
                    env["REA_GHIDRA_STARTUP_TIMEOUT_MS"] = json!(timeout.to_string());
                }
                if let Some(maxmem) = &args.rea_ghidra_maxmem {
                    env["GHIDRA_HEADLESS_MAXMEM"] = json!(maxmem);
                }
                let config = json!({"mcpServers": {"rea": {"type": "stdio",
                    "command": node, "args": [entry, "mcp"], "env": env}}});
                let record = absolute(args.rea_install_record.as_ref(), "target/bench/rea/install.json")?;
                let install: Value = serde_json::from_str(&read(&record)?).map_err(|error| error.to_string())?;
                let node_version = Command::new(&node)
                    .arg("--version")
                    .output()
                    .ok()
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .map(|text| text.trim().to_owned());
                (
                    config,
                    json!({"install": install, "node": node_version,
                    "ghidra": ghidra_version(&args.ghidra_dir), "java_home": args.java_home,
                    "provider": "ghidra",
                    "tool_families": args.rea_tool_families.as_deref().unwrap_or("default (complete catalog)"),
                    "ghidra_startup_timeout_ms": args.rea_ghidra_startup_timeout_ms
                        .map_or_else(|| json!("default (330000)"), |timeout| json!(timeout)),
                    "ghidra_headless_maxmem": args.rea_ghidra_maxmem.as_deref().unwrap_or("default (2G)")}),
                )
            }
        };
        let path = out_dir.join(format!("mcp-{server}.json"));
        write_private(&path, &serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?)?;
        servers.insert(server.clone(), path);
        versions[server] = version;
    }
    let system_path = out_dir.join("system.txt");
    write_private(&system_path, suite.system.trim().as_bytes())?;
    let mut runner = args.runner.split_whitespace().map(PathBuf::from).collect::<Vec<_>>();
    if runner.is_empty() {
        return Err("empty runner command".into());
    }
    for part in runner.iter_mut().skip(1) {
        if part.extension().is_some_and(|extension| extension == "py" || extension == "sh") && part.is_relative() {
            *part = root.join(&*part);
        }
    }
    let rows_path = out_dir.join("runs.jsonl");
    let mut recorded: Vec<RunRow> = Vec::new();
    if !args.rerun.is_empty() {
        for spec in &args.rerun {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() != 3 || parts[2].parse::<u32>().is_err() {
                return Err(format!("--rerun {spec}: expected TASK:SERVER:REPETITION"));
            }
        }
        // The first pass's rows stay in runs.before-rerun.jsonl; each pass starts from the current report.
        let kept = out_dir.join("runs.before-rerun.jsonl");
        if !kept.exists() {
            std::fs::copy(&rows_path, &kept).map_err(|error| format!("{}: {error}", rows_path.display()))?;
        }
        std::fs::copy(out_dir.join("report.json"), out_dir.join("report.before-rerun.json"))
            .map_err(|error| format!("no measured report to rerun into: {error}"))?;
        for line in read(&rows_path)?.lines().filter(|line| !line.trim().is_empty()) {
            recorded.push(serde_json::from_str(line).map_err(|error| format!("{}: {error}", rows_path.display()))?);
        }
        std::fs::remove_file(&rows_path).map_err(|error| error.to_string())?;
    }
    let mut superseded: Vec<Value> = Vec::new();
    let kept = out_dir.join("runs.before-rescore.jsonl");
    if args.rescore && rows_path.is_file() && !kept.exists() {
        std::fs::rename(&rows_path, &kept).map_err(|error| format!("{}: {error}", rows_path.display()))?;
    } else if args.rescore {
        let _ = std::fs::remove_file(&rows_path);
    }
    let mut rows_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rows_path)
        .map_err(|error| format!("{}: {error}", rows_path.display()))?;
    let mut rows = Vec::new();
    let total = args.repeat as usize * tasks.len() * args.servers.len();
    let mut stopped: Option<Value> = None;
    'runs: for repetition in 1..=args.repeat {
        for task in &tasks {
            for (position, server) in server_order(&args.servers, repetition).into_iter().enumerate() {
                if let Some(cap) = args.cost_cap_usd.filter(|_| !args.rescore) {
                    let spent = args.spent_usd + rows.iter().filter_map(|row: &RunRow| row.cost_usd).sum::<f64>();
                    if spent >= cap {
                        eprintln!("cost cap reached: ${spent:.2} of ${cap:.2}; stopping before {} {server}", task.id);
                        stopped = Some(json!({"reason": "cost cap", "cap_usd": cap, "spent_usd": spent,
                            "completed_runs": rows.len(), "planned_runs": total}));
                        break 'runs;
                    }
                }
                if !args.rerun.is_empty() {
                    let spec = format!("{}:{server}:{repetition}", task.id);
                    let earlier = recorded
                        .iter()
                        .find(|row| row.task_id == task.id && row.server == **server && row.repetition == repetition)
                        .cloned();
                    if !args.rerun.contains(&spec) {
                        if let Some(row) = earlier {
                            let line = serde_json::to_string(&row).map_err(|error| error.to_string())?;
                            writeln!(rows_file, "{line}").map_err(|error| error.to_string())?;
                            rows.push(row);
                        }
                        continue;
                    }
                    let Some(earlier) = earlier else { return Err(format!("--rerun {spec}: no recorded run")) };
                    let name = format!("{}-r{repetition}", task.id);
                    let from = out_dir.join("runs").join(server).join(&name);
                    // A run superseded twice keeps both earlier directories: name, name.2, ...
                    let mut to = out_dir.join("runs/superseded").join(server).join(&name);
                    let mut copy = 1;
                    while to.exists() {
                        copy += 1;
                        to = out_dir.join("runs/superseded").join(server).join(format!("{name}.{copy}"));
                    }
                    std::fs::create_dir_all(to.parent().expect("has a parent")).map_err(|error| error.to_string())?;
                    std::fs::rename(&from, &to).map_err(|error| format!("{}: {error}", from.display()))?;
                    let mut value = json!(earlier);
                    value["superseded_reason"] = json!(args.rerun_reason);
                    superseded.push(value);
                }
                let fixture = root.join(&task.fixture.path);
                let row = run_one(&RunSetup {
                    root: &root,
                    task,
                    suite: &suite,
                    server,
                    repetition,
                    position: position as u32,
                    fixture: &fixture,
                    config: &servers[server],
                    system: &system_path,
                    runner: &runner,
                    out_dir: &out_dir,
                    args: &args,
                })?;
                eprintln!(
                    "[{}/{total}] {} {server} r{repetition}: {:?}{} calls={} wall={:.1}s",
                    rows.len() + 1,
                    task.id,
                    row.outcome,
                    row.failure.map(|kind| format!(" ({kind:?})")).unwrap_or_default(),
                    row.tool_calls,
                    row.wall_ms as f64 / 1000.0
                );
                let line = serde_json::to_string(&row).map_err(|error| error.to_string())?;
                writeln!(rows_file, "{line}").map_err(|error| error.to_string())?;
                rows.push(row);
            }
        }
    }
    let summary = summarize(&rows);
    let runners: Vec<_> = {
        let mut seen: Vec<Value> = Vec::new();
        for row in &rows {
            let value = json!(row.runner);
            if !seen.contains(&value) {
                seen.push(value);
            }
        }
        seen
    };
    let report = json!({
        "schema_version": 1,
        "benchmark": "agent-h2h",
        "label": args.label,
        "run_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .ok().map(|duration| duration.as_millis() as u64),
        "protocol": {
            "model": args.model, "repeat": args.repeat, "max_turns": args.max_turns, "timeout_s": args.timeout_s,
            "servers": args.servers, "tasks": tasks.iter().map(|task| &task.id).collect::<Vec<_>>(),
            "order": "for each repetition, for each task, each server in turn, sequentially; the --servers order \
                on odd repetitions and its reverse on even ones",
            "max_mcp_output_tokens": args.max_mcp_output_tokens,
            "suite": format!("{:?}", args.suite).to_lowercase(),
            "task_limits": tasks.iter().map(|task| {
                let (max_turns, timeout_s) = limits(&suite, task, &args);
                (task.id.clone(), json!({"max_turns": max_turns, "timeout_s": timeout_s}))
            }).collect::<BTreeMap<_, _>>(),
            "cost_cap_usd": args.cost_cap_usd,
            "spent_before_usd": args.cost_cap_usd.map(|_| args.spent_usd),
            "neutral_suite_sha256": hex(&Sha256::digest(suite_text.as_bytes())),
            "task_definition_sha256": task_hashes(&task_directory, &tasks)?,
            "runner_command": args.runner,
            "fixture_name_in_workdir": "fixture.bin",
        },
        "runners": runners,
        "versions": versions,
        "stopped": stopped,
        "attachments": attachments(&args.attachments)?,
        "summary": summary,
        "runs": rows,
    });
    let report_path = out_dir.join("report.json");
    let report = if !args.rerun.is_empty() {
        let earlier: Value = serde_json::from_str(&read(&out_dir.join("report.before-rerun.json"))?)
            .map_err(|error| error.to_string())?;
        let mut report = report;
        for key in ["versions", "run_unix_ms", "protocol"] {
            if let Some(value) = earlier.get(key) {
                report[key] = value.clone();
            }
        }
        // Earlier attachments stay; this pass's --attach entries add to them or replace one of the same name.
        let mut attached = earlier["attachments"].as_object().cloned().unwrap_or_default();
        attached.extend(report["attachments"].as_object().cloned().unwrap_or_default());
        report["attachments"] = Value::Object(attached);
        let mut all_superseded = earlier["superseded_runs"].as_array().cloned().unwrap_or_default();
        all_superseded.extend(superseded);
        report["superseded_runs"] = json!(all_superseded);
        let mut reruns = match &earlier["rerun"] {
            Value::Array(passes) => passes.clone(),
            Value::Null => Vec::new(),
            pass => vec![pass.clone()],
        };
        reruns.push(json!({"reason": args.rerun_reason, "runs": args.rerun,
            "neutral_suite_sha256": hex(&Sha256::digest(suite_text.as_bytes())),
            "task_definition_sha256": task_hashes(&task_directory, &tasks)?,
            "commit": git(&root, &["rev-parse", "HEAD"]), "versions": versions,
            "run_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .ok().map(|duration| duration.as_millis() as u64)}));
        report["rerun"] = json!(reruns);
        report
    } else if args.rescore {
        // Each rescore starts from the current report, whose versions, time and protocol are the measurement's.
        let earlier_path = out_dir.join("report.before-rescore.json");
        std::fs::copy(&report_path, &earlier_path)
            .map_err(|error| format!("{}: no measured report to rescore: {error}", report_path.display()))?;
        let earlier: Value = serde_json::from_str(&read(&earlier_path)?).map_err(|error| error.to_string())?;
        rescored_report(&earlier, report, git(&root, &["rev-parse", "HEAD"]), &args.rescore_reason)
    } else {
        report
    };
    let pretty = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::write(&report_path, &pretty).map_err(|error| error.to_string())?;
    let markdown = markdown_tables(&report["summary"]);
    std::fs::write(out_dir.join("tables.md"), &markdown).map_err(|error| error.to_string())?;
    if let (Some(json_path), Some(md_path)) = (&args.report_json, &args.report_md) {
        std::fs::write(json_path, format!("{pretty}\n"))
            .map_err(|error| format!("{}: {error}", json_path.display()))?;
        std::fs::write(md_path, &markdown).map_err(|error| format!("{}: {error}", md_path.display()))?;
    }
    println!("{markdown}");
    Ok(ExitCode::SUCCESS)
}

/// The --servers order on odd repetitions and its reverse on even ones, so no server always runs first.
fn server_order(servers: &[String], repetition: u32) -> Vec<&String> {
    if repetition % 2 == 1 { servers.iter().collect() } else { servers.iter().rev().collect() }
}

struct RunSetup<'a> {
    root: &'a Path,
    task: &'a ParityTask,
    suite: &'a NeutralSuite,
    server: &'a str,
    repetition: u32,
    position: u32,
    fixture: &'a Path,
    config: &'a Path,
    system: &'a Path,
    runner: &'a [PathBuf],
    out_dir: &'a Path,
    args: &'a AgentBenchArgs,
}

fn run_one(setup: &RunSetup<'_>) -> Result<RunRow, String> {
    if setup.args.rescore {
        return rescore_one(setup);
    }
    let workdir = Workdir::new()?;
    let target = workdir.path.join("fixture.bin");
    std::fs::copy(setup.fixture, &target).map_err(|error| format!("{}: {error}", setup.fixture.display()))?;
    if hash_file(&target)? != setup.task.fixture.sha256 {
        return Err(format!("{}: fixture differs from its declared digest", setup.task.id));
    }
    let mut companions = Vec::new();
    for companion in &setup.task.fixture.companions {
        let source = setup.root.join(&companion.path);
        let copy = workdir.path.join(&companion.name);
        std::fs::copy(&source, &copy).map_err(|error| format!("{}: {error}", source.display()))?;
        if hash_file(&copy)? != companion.sha256 {
            return Err(format!("{}: companion {} differs from its declared digest", setup.task.id, companion.name));
        }
        companions.push((companion.name.clone(), copy.to_string_lossy().into_owned()));
    }
    let (max_turns, timeout_s) = limits(setup.suite, setup.task, setup.args);
    let run_dir =
        setup.out_dir.join("runs").join(setup.server).join(format!("{}-r{}", setup.task.id, setup.repetition));
    std::fs::create_dir_all(&run_dir).map_err(|error| error.to_string())?;
    let prompt = run_dir.join("prompt.txt");
    write_private(&prompt, setup.suite.prompt_with(setup.task, &target.to_string_lossy(), &companions).as_bytes())?;
    let result_path = run_dir.join("result.json");
    let _ = std::fs::remove_file(&result_path);
    let status = Command::new(&setup.runner[0])
        .args(&setup.runner[1..])
        .arg("--mcp-config")
        .arg(setup.config)
        .args(["--server-name", setup.server])
        .arg("--prompt-file")
        .arg(&prompt)
        .arg("--system-file")
        .arg(setup.system)
        .args(["--model", &setup.args.model])
        .args(["--max-turns", &max_turns.to_string()])
        .args(["--timeout-s", &timeout_s.to_string()])
        .args(["--max-mcp-output-tokens", &setup.args.max_mcp_output_tokens.to_string()])
        .arg("--workdir")
        .arg(&workdir.path)
        .arg("--out")
        .arg(&result_path)
        .arg("--transcript")
        .arg(run_dir.join("transcript.jsonl"))
        .status()
        .map_err(|error| format!("runner {}: {error}", setup.runner[0].display()))?;
    let text = read(&result_path).map_err(|error| format!("runner exited {status} without a result: {error}"))?;
    let result: RunnerResult =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", result_path.display()))?;
    score(setup.task, setup.suite, setup.server, setup.repetition, setup.position, &result)
}

fn rescore_one(setup: &RunSetup<'_>) -> Result<RunRow, String> {
    let run_dir =
        setup.out_dir.join("runs").join(setup.server).join(format!("{}-r{}", setup.task.id, setup.repetition));
    let result_path = run_dir.join("result.json");
    let (max_turns, timeout_s) = limits(setup.suite, setup.task, setup.args);
    let status = Command::new(&setup.runner[0])
        .args(&setup.runner[1..])
        .arg("--renormalize")
        .arg("--mcp-config")
        .arg(setup.config)
        .args(["--server-name", setup.server])
        .arg("--prompt-file")
        .arg(run_dir.join("prompt.txt"))
        .args(["--model", &setup.args.model])
        .args(["--max-turns", &max_turns.to_string()])
        .args(["--timeout-s", &timeout_s.to_string()])
        .arg("--workdir")
        .arg(&run_dir)
        .arg("--out")
        .arg(&result_path)
        .arg("--transcript")
        .arg(run_dir.join("transcript.jsonl"))
        .status()
        .map_err(|error| format!("runner {}: {error}", setup.runner[0].display()))?;
    let text = read(&result_path).map_err(|error| format!("runner exited {status} without a result: {error}"))?;
    let result: RunnerResult =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", result_path.display()))?;
    score(setup.task, setup.suite, setup.server, setup.repetition, setup.position, &result)
}

/// A fresh private directory outside the repository, so no project file or other run's output is visible.
pub(crate) struct Workdir {
    pub(crate) path: PathBuf,
}

impl Workdir {
    pub(crate) fn new() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "agent-bench-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let path = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
        Ok(Self { path })
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A task's turn and time limits: its own from the neutral suite, else the run's defaults.
fn limits(suite: &NeutralSuite, task: &ParityTask, args: &AgentBenchArgs) -> (u32, u64) {
    let neutral = &suite.tasks[&task.id];
    (neutral.max_turns.unwrap_or(args.max_turns), neutral.timeout_s.unwrap_or(args.timeout_s))
}

fn parse_attachment(text: &str) -> Result<(String, PathBuf), String> {
    let (name, path) = text.split_once('=').ok_or("expected NAME=PATH")?;
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
        return Err(format!("invalid attachment name {name:?}"));
    }
    Ok((name.to_owned(), PathBuf::from(path)))
}

fn attachments(items: &[(String, PathBuf)]) -> Result<Value, String> {
    let mut object = serde_json::Map::new();
    for (name, path) in items {
        let value: Value =
            serde_json::from_str(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))?;
        object.insert(name.clone(), value);
    }
    Ok(Value::Object(object))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

fn task_hashes(directory: &Path, tasks: &[ParityTask]) -> Result<BTreeMap<String, String>, String> {
    tasks
        .iter()
        .map(|task| {
            let text = read(&directory.join(format!("{}.toml", task.id)))?;
            Ok((task.id.clone(), hex(&Sha256::digest(text.as_bytes()))))
        })
        .collect()
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
}

fn which(program: &Path) -> Result<PathBuf, String> {
    if program.components().count() > 1 {
        return std::fs::canonicalize(program).map_err(|error| format!("{}: {error}", program.display()));
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{} is not on PATH", program.display()))
}

fn ghidra_version(directory: &Path) -> Option<String> {
    let text = std::fs::read_to_string(directory.join("Ghidra/application.properties")).ok()?;
    let field = |name: &str| {
        text.lines().find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix('='))).map(str::trim)
    };
    Some(
        format!("{} {}", field("application.version")?, field("application.release.name").unwrap_or(""))
            .trim()
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::server_order;

    #[test]
    fn server_order_alternates_by_repetition() {
        let servers = vec!["rampage".to_owned(), "rea".to_owned()];
        assert_eq!(server_order(&servers, 1), [&servers[0], &servers[1]]);
        assert_eq!(server_order(&servers, 2), [&servers[1], &servers[0]]);
        assert_eq!(server_order(&servers, 3), [&servers[0], &servers[1]]);
    }
}
