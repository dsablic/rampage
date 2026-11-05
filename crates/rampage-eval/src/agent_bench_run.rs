//! `rampage-eval agent-bench`: run the canonical tasks through an external agent runner against each MCP
//! server, sequentially, and score the normalized results. See `rampage_eval::agent_bench`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_eval::agent_bench::{NeutralSuite, RunRow, RunnerResult, markdown_tables, score, summarize};
use rampage_eval::parity_tasks::{ParityTask, load_tasks};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::read;

pub const DEFAULT_RUNNER: &str = "python3 -I tools/agent-bench/claude-runner.py";

#[derive(clap::Args)]
pub struct AgentBenchArgs {
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
    /// Model turn limit per run.
    #[arg(long, default_value_t = 40)]
    max_turns: u32,
    /// Wall-clock limit per run, in seconds.
    #[arg(long, default_value_t = 900)]
    timeout_s: u64,
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
}

pub fn run(args: AgentBenchArgs) -> Result<ExitCode, String> {
    let root = args.repository_root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let root = std::fs::canonicalize(&root).map_err(|error| format!("{}: {error}", root.display()))?;
    let task_directory = root.join("crates/rampage-eval/tasks");
    let mut tasks = load_tasks(&task_directory).map_err(|error| error.to_string())?;
    let suite_path = task_directory.join("h2h/neutral.toml");
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
                let config = json!({"mcpServers": {"rea": {"type": "stdio",
                    "command": node, "args": [entry, "mcp"],
                    "env": {"GHIDRA_INSTALL_DIR": args.ghidra_dir, "JAVA_HOME": args.java_home,
                        "REA_ANALYSIS_PROVIDER": "ghidra"}}}});
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
                    "provider": "ghidra", "tool_families": "default"}),
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
    let mut rows_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rows_path)
        .map_err(|error| format!("{}: {error}", rows_path.display()))?;
    let mut rows = Vec::new();
    let total = args.repeat as usize * tasks.len() * args.servers.len();
    for repetition in 1..=args.repeat {
        for task in &tasks {
            for server in &args.servers {
                let fixture = root.join(&task.fixture.path);
                let row = run_one(&RunSetup {
                    task,
                    suite: &suite,
                    server,
                    repetition,
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
            "order": "for each repetition, for each task, each server in turn; sequential",
            "neutral_suite_sha256": hex(&Sha256::digest(suite_text.as_bytes())),
            "task_definition_sha256": task_hashes(&task_directory, &tasks)?,
            "runner_command": args.runner,
            "fixture_name_in_workdir": "fixture.bin",
        },
        "runners": runners,
        "versions": versions,
        "summary": summary,
        "runs": rows,
    });
    let pretty = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    std::fs::write(out_dir.join("report.json"), &pretty).map_err(|error| error.to_string())?;
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

struct RunSetup<'a> {
    task: &'a ParityTask,
    suite: &'a NeutralSuite,
    server: &'a str,
    repetition: u32,
    fixture: &'a Path,
    config: &'a Path,
    system: &'a Path,
    runner: &'a [PathBuf],
    out_dir: &'a Path,
    args: &'a AgentBenchArgs,
}

fn run_one(setup: &RunSetup<'_>) -> Result<RunRow, String> {
    let workdir = Workdir::new()?;
    let target = workdir.path.join("fixture.bin");
    std::fs::copy(setup.fixture, &target).map_err(|error| format!("{}: {error}", setup.fixture.display()))?;
    if hash_file(&target)? != setup.task.fixture.sha256 {
        return Err(format!("{}: fixture differs from its declared digest", setup.task.id));
    }
    let run_dir =
        setup.out_dir.join("runs").join(setup.server).join(format!("{}-r{}", setup.task.id, setup.repetition));
    std::fs::create_dir_all(&run_dir).map_err(|error| error.to_string())?;
    let prompt = run_dir.join("prompt.txt");
    write_private(&prompt, setup.suite.prompt(setup.task, &target.to_string_lossy()).as_bytes())?;
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
        .args(["--max-turns", &setup.args.max_turns.to_string()])
        .args(["--timeout-s", &setup.args.timeout_s.to_string()])
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
    score(setup.task, setup.suite, setup.server, setup.repetition, &result)
}

/// A fresh private directory outside the repository, so no project file or other run's output is visible.
struct Workdir {
    path: PathBuf,
}

impl Workdir {
    fn new() -> Result<Self, String> {
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
