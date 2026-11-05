//! Head-to-head agent benchmark: tool-neutral task prompts, the external runner's result contract, scoring
//! and the per-task/per-server summary.
//!
//! An external runner (by default `tools/agent-bench/claude-runner.py`) drives one agent CLI against exactly
//! one MCP server and writes a [`RunnerResult`]. Nothing here knows which agent CLI produced it. Scoring reuses
//! the canonical task manifests' answer contracts ([`ParityTask`]); only the prompt wording comes from the
//! [`NeutralSuite`], because the frozen manifests and their published results stay unchanged as history.
//! Capability probes ask about the connected server's own tools, so their truth is per server.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::parity_tasks::{AnswerContract, ParityTask, TaskAttempt, TaskKind, TaskOutcome};

/// Tool-neutral prompts for the canonical tasks, keyed by task id.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralSuite {
    pub version: u32,
    /// The system prompt every run gets, whichever server is connected.
    pub system: String,
    pub tasks: BTreeMap<String, NeutralTask>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralTask {
    pub question: String,
    /// Report grouping, such as `cpp` or `scale`; tasks without one are reported as `uncategorized`.
    #[serde(default)]
    pub category: Option<String>,
    /// How the answer is scored, in words, for the published report; the contract is the manifest's.
    #[serde(default)]
    pub scoring: Option<String>,
    /// Per-task model turn limit, overriding the run's default.
    #[serde(default)]
    pub max_turns: Option<u32>,
    /// Per-task wall-clock limit in seconds, overriding the run's default.
    #[serde(default)]
    pub timeout_s: Option<u64>,
    /// Why the wording differs from the frozen manifest, when it does.
    #[serde(default)]
    pub change: Option<String>,
    /// Capability probes only: the `available` truth for each server, by MCP server name.
    #[serde(default)]
    pub truth: BTreeMap<String, ProbeTruth>,
    #[serde(default)]
    pub truth_evidence: BTreeMap<String, String>,
}

/// A capability probe's expected `available` for one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProbeTruth {
    Is(bool),
    /// The server advertises a general tool (such as a raw command runner) whose reach depends on the host, so
    /// either boolean is accepted. Spelled `"either"` in the suite.
    Either(EitherTag),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EitherTag {
    Either,
}

/// What a server's answer is scored against.
#[derive(Debug, Clone)]
pub enum Expected {
    Contract(AnswerContract),
    /// Exactly `{"available": <any boolean>}`.
    AnyAvailable,
}

impl Expected {
    pub fn matches(&self, answer: &Value) -> bool {
        match self {
            Self::Contract(contract) => contract.matches(answer),
            Self::AnyAvailable => answer
                .as_object()
                .is_some_and(|object| object.len() == 1 && object.get("available").is_some_and(Value::is_boolean)),
        }
    }
}

impl NeutralSuite {
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let suite: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        if suite.version != 1 {
            return Err(format!("unsupported neutral suite version {}", suite.version));
        }
        if suite.system.trim().is_empty() {
            return Err("system prompt must not be empty".into());
        }
        for (id, task) in &suite.tasks {
            if task.question.trim().is_empty() {
                return Err(format!("{id}: question must not be empty"));
            }
            if task.truth.keys().collect::<BTreeSet<_>>() != task.truth_evidence.keys().collect::<BTreeSet<_>>() {
                return Err(format!("{id}: every per-server truth needs evidence, and only those"));
            }
        }
        Ok(suite)
    }

    /// The suite must cover exactly the canonical tasks; probes need a truth for every benchmarked server.
    pub fn check_against(&self, tasks: &[ParityTask], servers: &[String]) -> Result<(), String> {
        let canonical: BTreeSet<_> = tasks.iter().map(|task| task.id.as_str()).collect();
        let neutral: BTreeSet<_> = self.tasks.keys().map(String::as_str).collect();
        if canonical != neutral {
            return Err(format!(
                "neutral suite does not cover exactly the canonical tasks; missing {:?}, extra {:?}",
                canonical.difference(&neutral).collect::<Vec<_>>(),
                neutral.difference(&canonical).collect::<Vec<_>>()
            ));
        }
        for task in tasks {
            let neutral = &self.tasks[&task.id];
            match task.kind {
                TaskKind::Analysis if !neutral.truth.is_empty() => {
                    return Err(format!("{}: analysis tasks score against the manifest contract", task.id));
                }
                TaskKind::Capability => {
                    let AnswerContract::Exact { fields, .. } = &task.answer else {
                        return Err(format!("{}: capability probes must have an exact contract", task.id));
                    };
                    if fields.keys().map(String::as_str).collect::<Vec<_>>() != ["available"] {
                        return Err(format!("{}: capability probes answer only `available`", task.id));
                    }
                    if let Some(server) = servers.iter().find(|server| !neutral.truth.contains_key(*server)) {
                        return Err(format!("{}: no capability truth for server {server}", task.id));
                    }
                }
                TaskKind::Analysis => {}
            }
        }
        Ok(())
    }

    pub fn prompt(&self, task: &ParityTask, opened_path: &str) -> String {
        self.prompt_with(task, opened_path, &[])
    }

    /// The prompt for a task whose companion files were copied to `companions` (name, path), in manifest order.
    pub fn prompt_with(&self, task: &ParityTask, opened_path: &str, companions: &[(String, String)]) -> String {
        let quote = |path: &str| serde_json::to_string(path).expect("path string is serializable");
        let path = quote(opened_path);
        let also = if companions.is_empty() {
            String::new()
        } else {
            let list: Vec<String> = companions.iter().map(|(_, path)| quote(path)).collect();
            format!(" The task also uses {}; refer to them as the question does.", list.join(" and "))
        };
        let read = if companions.is_empty() { "the file" } else { "the files" };
        format!(
            "Analyze the binary at {path}.{also} Use only the tools of the connected MCP server; there is no \
             other way to read {read}.\n\n{}\n\n\
             Finish with only one JSON object, without prose or code fences, holding exactly the requested \
             fields. If the evidence is insufficient, finish with {{\"status\":\"unknown\",\"reason\":\"...\"}}; \
             if the server cannot do what the question needs, finish with \
             {{\"status\":\"unsupported\",\"reason\":\"...\"}}.",
            self.tasks[&task.id].question.trim()
        )
    }

    /// What a server's answer is scored against.
    pub fn expected(&self, task: &ParityTask, server: &str) -> Result<Expected, String> {
        match task.kind {
            TaskKind::Analysis => Ok(Expected::Contract(task.answer.clone())),
            TaskKind::Capability => {
                let truth = self.tasks[&task.id]
                    .truth
                    .get(server)
                    .ok_or_else(|| format!("{}: no capability truth for server {server}", task.id))?;
                Ok(match truth {
                    ProbeTruth::Is(available) => Expected::Contract(AnswerContract::Exact {
                        fields: BTreeMap::from([("available".to_owned(), json!(available))]),
                        hex_integers: false,
                    }),
                    ProbeTruth::Either(_) => Expected::AnyAvailable,
                })
            }
        }
    }
}

/// The normalized result every runner writes, whichever agent CLI it drives.
#[derive(Debug, Clone, Deserialize)]
pub struct RunnerResult {
    pub answer: String,
    pub tool_calls: Vec<RunnerToolCall>,
    pub turns: u64,
    pub usage: RunnerUsage,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    pub duration_ms: u64,
    pub exit: RunnerExit,
    #[serde(default)]
    pub error: Option<String>,
    pub runner: RunnerIdentity,
    #[serde(default)]
    pub isolation_evidence: Option<Value>,
}

/// The client tool that loads deferred MCP tool schemas; its calls are not server tool calls.
pub const TOOL_SEARCH: &str = "ToolSearch";

#[derive(Debug, Clone, Deserialize)]
pub struct RunnerToolCall {
    pub name: String,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub is_error: bool,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// The client replaced the result with a preview or an error because it was too large.
    #[serde(default)]
    pub truncated: bool,
    /// The client refused the call (no such tool, or permission denied); nothing ran.
    #[serde(default)]
    pub rejected: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunnerUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunnerExit {
    Ok,
    Timeout,
    MaxTurns,
    Error,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunnerIdentity {
    pub name: String,
    pub version: Option<String>,
    pub model: Option<String>,
    pub isolation: Option<String>,
}

/// Why a run did not produce the expected answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Timeout,
    MaxTurns,
    RunnerError,
    AnswerFormat,
    Unknown,
    Unsupported,
    WrongAnswer,
}

/// How the final answer's JSON object was found. Only `Exact` follows the prompt to the letter; every kind is
/// scored the same, and the report counts the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extraction {
    /// The whole reply is one JSON object.
    Exact,
    /// The whole reply is one code fence holding one JSON object.
    Fenced,
    /// Prose, then one JSON object (alone or fenced) that ends the reply.
    Trailing,
}

fn object_or_fence(text: &str) -> Option<(Value, Extraction)> {
    let text = text.trim();
    if let Ok(value @ Value::Object(_)) = serde_json::from_str(text) {
        return Some((value, Extraction::Exact));
    }
    let inner = text.strip_prefix("```")?.strip_suffix("```")?;
    if inner.contains("```") {
        return None;
    }
    let inner = inner.strip_prefix("json").unwrap_or(inner);
    match serde_json::from_str(inner.trim()) {
        Ok(value @ Value::Object(_)) => Some((value, Extraction::Fenced)),
        _ => None,
    }
}

/// Parse the final answer: one JSON object, alone, as a single code fence, or ending the reply after prose.
/// A trailing object must start a line and nothing but whitespace may follow it.
pub fn extract_answer(text: &str) -> Result<(Value, Extraction), String> {
    if let Some(found) = object_or_fence(text) {
        return Ok(found);
    }
    let trimmed = text.trim_end();
    for (start, _) in trimmed.match_indices('\n').collect::<Vec<_>>().into_iter().rev() {
        if let Some((value, _)) = object_or_fence(&trimmed[start + 1..]) {
            return Ok((value, Extraction::Trailing));
        }
    }
    Err("the reply does not end with one JSON object".into())
}

/// Turn a runner result into the attempt the manifest contract checks.
pub fn attempt(result: &RunnerResult) -> (TaskAttempt, Option<FailureKind>, Option<Extraction>) {
    let failed = |kind, reason: String| (TaskAttempt::Failed { reason }, Some(kind), None);
    match result.exit {
        RunnerExit::Timeout => return failed(FailureKind::Timeout, "runner timeout".into()),
        RunnerExit::MaxTurns => return failed(FailureKind::MaxTurns, "turn limit reached".into()),
        RunnerExit::Error => {
            return failed(FailureKind::RunnerError, result.error.clone().unwrap_or_else(|| "runner error".into()));
        }
        RunnerExit::Ok => {}
    }
    let (answer, extraction) = match extract_answer(&result.answer) {
        Ok(found) => found,
        Err(reason) => return failed(FailureKind::AnswerFormat, reason),
    };
    if let Some(status @ ("unknown" | "unsupported")) = answer.get("status").and_then(Value::as_str) {
        let reason = answer.get("reason").and_then(Value::as_str).unwrap_or("").to_owned();
        return if status == "unknown" {
            (TaskAttempt::Unknown { reason }, Some(FailureKind::Unknown), Some(extraction))
        } else {
            (TaskAttempt::Unsupported { reason }, Some(FailureKind::Unsupported), Some(extraction))
        };
    }
    (TaskAttempt::Answer(answer), None, Some(extraction))
}

/// One scored run. Holds measurements and outcomes only: no answer text, transcript or binary content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRow {
    pub task_id: String,
    pub kind: TaskKind,
    /// The neutral suite's category for the task, or `uncategorized`.
    pub category: String,
    pub server: String,
    pub repetition: u32,
    pub outcome: TaskOutcome,
    pub failure: Option<FailureKind>,
    /// Partial credit for set answers (Jaccard index, defined before any run); `None` for exact contracts. A run
    /// without a scorable answer gets 0.
    pub partial: Option<f64>,
    /// Correct once an extra `"status": "ok"` field, a format slip, is dropped from the answer object; equals
    /// the strict outcome otherwise. A reporting variant beside the strict score, never instead of it.
    #[serde(default)]
    pub lenient: bool,
    /// How the answer object was found; `None` when there was none.
    pub extraction: Option<Extraction>,
    /// Calls to the server's tools that the client ran (refused calls and ToolSearch excluded).
    pub tool_calls: u64,
    /// Of those, the ones whose result was an error.
    pub tool_errors: u64,
    /// Of those, the ones whose result the client truncated or spilled to a file.
    pub truncated_results: u64,
    /// ToolSearch calls that loaded deferred tool schemas.
    pub tool_search_calls: u64,
    /// Calls the client refused: an unknown tool name, or a permission denial.
    pub rejected_calls: u64,
    /// 0 when this server ran first for its task and repetition, 1 when second.
    pub position: u32,
    pub turns: u64,
    pub usage: RunnerUsage,
    pub cost_usd: Option<f64>,
    pub wall_ms: u64,
    pub runner_exit: RunnerExit,
    /// Bounded runner error for runner failures; never the model's answer.
    pub runner_error: Option<String>,
    pub runner: RunnerIdentity,
}

pub fn score(
    task: &ParityTask,
    suite: &NeutralSuite,
    server: &str,
    repetition: u32,
    position: u32,
    result: &RunnerResult,
) -> Result<RunRow, String> {
    let expected = suite.expected(task, server)?;
    let (attempt, mut failure, extraction) = attempt(result);
    let server_calls: Vec<_> =
        result.tool_calls.iter().filter(|call| !call.rejected && call.name != TOOL_SEARCH).collect();
    let partial = match (&expected, task.kind) {
        (Expected::Contract(contract), TaskKind::Analysis) => match &attempt {
            TaskAttempt::Answer(answer) => contract.partial(answer),
            _ => contract.partial(&Value::Null),
        },
        _ => None,
    };
    let outcome = match &attempt {
        TaskAttempt::Answer(answer) if expected.matches(answer) => TaskOutcome::AnswerMatches,
        TaskAttempt::Answer(_) => {
            failure = Some(FailureKind::WrongAnswer);
            TaskOutcome::AnswerMismatch
        }
        other => task.check(other).outcome,
    };
    let lenient = outcome == TaskOutcome::AnswerMatches
        || matches!(&attempt, TaskAttempt::Answer(Value::Object(object))
        if object.get("status").and_then(Value::as_str) == Some("ok") && {
            let mut trimmed = object.clone();
            trimmed.remove("status");
            expected.matches(&Value::Object(trimmed))
        });
    Ok(RunRow {
        task_id: task.id.clone(),
        kind: task.kind,
        category: suite.tasks[&task.id].category.clone().unwrap_or_else(|| "uncategorized".to_owned()),
        server: server.to_owned(),
        repetition,
        outcome,
        failure,
        partial,
        lenient,
        extraction,
        tool_calls: server_calls.len() as u64,
        tool_errors: server_calls.iter().filter(|call| call.is_error).count() as u64,
        truncated_results: server_calls.iter().filter(|call| call.truncated).count() as u64,
        tool_search_calls: result.tool_calls.iter().filter(|call| call.name == TOOL_SEARCH).count() as u64,
        rejected_calls: result.tool_calls.iter().filter(|call| call.rejected).count() as u64,
        position,
        turns: result.turns,
        usage: result.usage,
        cost_usd: result.cost_usd,
        wall_ms: result.duration_ms,
        runner_exit: result.exit,
        runner_error: (result.exit == RunnerExit::Error)
            .then(|| bounded(result.error.as_deref().unwrap_or("runner error"), 300)),
        runner: result.runner.clone(),
    })
}

fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// Median (lower middle for even counts, so it is always an observed value) and range.
pub fn spread(values: impl IntoIterator<Item = u64>) -> Value {
    let mut values: Vec<u64> = values.into_iter().collect();
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_unstable();
    json!({"median": values[(values.len() - 1) / 2], "min": values[0], "max": values[values.len() - 1]})
}

fn group_summary(rows: &[&RunRow]) -> Value {
    let correct = rows.iter().filter(|row| row.outcome == TaskOutcome::AnswerMatches).count();
    let correct_lenient = rows.iter().filter(|row| row.lenient).count();
    let mut failures: BTreeMap<FailureKind, usize> = BTreeMap::new();
    for row in rows {
        if let Some(kind) = row.failure {
            *failures.entry(kind).or_default() += 1;
        }
    }
    let mut extractions: BTreeMap<Extraction, usize> = BTreeMap::new();
    for row in rows {
        if let Some(kind) = row.extraction {
            *extractions.entry(kind).or_default() += 1;
        }
    }
    let cost: Option<f64> = rows.iter().map(|row| row.cost_usd).sum();
    // Over the runs of tasks that define partial credit (set answers); `null` when there are none.
    let partials: Vec<f64> = rows.iter().filter_map(|row| row.partial).collect();
    let partial = (!partials.is_empty()).then(|| {
        let sum: f64 = partials.iter().sum();
        (sum / partials.len() as f64 * 1000.0).round() / 1000.0
    });
    let partial_runs = partials.len();
    let limits_hit =
        rows.iter().filter(|row| matches!(row.runner_exit, RunnerExit::Timeout | RunnerExit::MaxTurns)).count();
    json!({
        "correct": correct, "correct_lenient": correct_lenient, "runs": rows.len(), "partial_credit_mean": partial,
        "partial_credit_runs": partial_runs, "limits_hit": limits_hit,
        "tool_calls": spread(rows.iter().map(|row| row.tool_calls)),
        "tool_errors": spread(rows.iter().map(|row| row.tool_errors)),
        "turns": spread(rows.iter().map(|row| row.turns)),
        "input_tokens": spread(rows.iter().map(|row| row.usage.input)),
        "output_tokens": spread(rows.iter().map(|row| row.usage.output)),
        "cache_read_tokens": spread(rows.iter().map(|row| row.usage.cache_read)),
        "cache_write_tokens": spread(rows.iter().map(|row| row.usage.cache_write)),
        "wall_ms": spread(rows.iter().map(|row| row.wall_ms)),
        "failures": failures,
        "answer_extraction": extractions,
        "totals": {
            "tool_calls": rows.iter().map(|row| row.tool_calls).sum::<u64>(),
            "tool_errors": rows.iter().map(|row| row.tool_errors).sum::<u64>(),
            "truncated_results": rows.iter().map(|row| row.truncated_results).sum::<u64>(),
            "tool_search_calls": rows.iter().map(|row| row.tool_search_calls).sum::<u64>(),
            "rejected_calls": rows.iter().map(|row| row.rejected_calls).sum::<u64>(),
            "input_tokens": rows.iter().map(|row| row.usage.input).sum::<u64>(),
            "output_tokens": rows.iter().map(|row| row.usage.output).sum::<u64>(),
            "cache_read_tokens": rows.iter().map(|row| row.usage.cache_read).sum::<u64>(),
            "cache_write_tokens": rows.iter().map(|row| row.usage.cache_write).sum::<u64>(),
            "wall_ms": rows.iter().map(|row| row.wall_ms).sum::<u64>(),
            "cost_usd": cost,
        },
    })
}

/// Per task and server, then per server for analysis tasks and capability probes separately.
pub fn summarize(rows: &[RunRow]) -> Value {
    let mut by_task: BTreeMap<(&str, &str), Vec<&RunRow>> = BTreeMap::new();
    for row in rows {
        by_task.entry((row.task_id.as_str(), row.server.as_str())).or_default().push(row);
    }
    let tasks: Vec<Value> = by_task
        .iter()
        .map(|((task, server), rows)| {
            let mut summary = group_summary(rows);
            summary["task_id"] = json!(task);
            summary["server"] = json!(server);
            summary["kind"] = json!(rows[0].kind);
            summary["category"] = json!(rows[0].category);
            summary
        })
        .collect();
    let servers: BTreeSet<&str> = rows.iter().map(|row| row.server.as_str()).collect();
    let categories: BTreeSet<&str> = rows.iter().map(|row| row.category.as_str()).collect();
    let by_category: BTreeMap<&str, BTreeMap<&str, Value>> = categories
        .iter()
        .map(|category| {
            let per_server = servers
                .iter()
                .map(|server| {
                    let rows: Vec<&RunRow> = rows
                        .iter()
                        .filter(|row| {
                            row.server == *server && row.category == *category && row.kind == TaskKind::Analysis
                        })
                        .collect();
                    (*server, group_summary(&rows))
                })
                .collect();
            (*category, per_server)
        })
        .collect();
    let limits: Vec<Value> = rows
        .iter()
        .filter(|row| matches!(row.runner_exit, RunnerExit::Timeout | RunnerExit::MaxTurns))
        .map(|row| {
            json!({"task_id": row.task_id, "server": row.server, "repetition": row.repetition,
            "limit": row.runner_exit})
        })
        .collect();
    let aggregates: BTreeMap<&str, Value> = servers
        .iter()
        .map(|server| {
            let of_kind = |kind| -> Vec<&RunRow> {
                rows.iter().filter(|row| row.server == *server && row.kind == kind).collect()
            };
            (
                *server,
                json!({
                    "analysis": group_summary(&of_kind(TaskKind::Analysis)),
                    "capability_probes": group_summary(&of_kind(TaskKind::Capability)),
                }),
            )
        })
        .collect();
    json!({"tasks": tasks, "servers": aggregates, "categories": by_category, "limits_hit": limits})
}

/// The markdown tables of a summary; the caller adds provenance and limitations around them.
pub fn markdown_tables(summary: &Value) -> String {
    let cell = |value: &Value| match (value["median"].as_u64(), value["min"].as_u64(), value["max"].as_u64()) {
        (Some(median), Some(min), Some(max)) if min == max => format!("{median}"),
        (Some(median), Some(min), Some(max)) => format!("{median} ({min}–{max})"),
        _ => "–".to_owned(),
    };
    let seconds = |value: &Value| match (value["median"].as_u64(), value["min"].as_u64(), value["max"].as_u64()) {
        (Some(median), Some(min), Some(max)) => {
            format!("{:.1} ({:.1}–{:.1})", median as f64 / 1000.0, min as f64 / 1000.0, max as f64 / 1000.0)
        }
        _ => "–".to_owned(),
    };
    let failures = |value: &Value| {
        let text = value
            .as_object()
            .map(|failures| failures.iter().map(|(kind, count)| format!("{kind} {count}")).collect::<Vec<_>>())
            .unwrap_or_default()
            .join(", ");
        if text.is_empty() { "–".to_owned() } else { text }
    };
    let mut output = String::new();
    output.push_str("| Server | Analysis correct | Probes correct | Tool calls | Input tokens | Output tokens | ");
    output.push_str("Cache read | Cache write | Wall s | Tool errors | Truncated | Analysis failures |\n");
    output.push_str("| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --- |\n");
    if let Some(servers) = summary["servers"].as_object() {
        for (server, aggregate) in servers {
            let analysis = &aggregate["analysis"];
            let probes = &aggregate["capability_probes"];
            output.push_str(&format!(
                "| {server} | {}/{} | {}/{} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                analysis["correct"],
                analysis["runs"],
                probes["correct"],
                probes["runs"],
                cell(&analysis["tool_calls"]),
                cell(&analysis["input_tokens"]),
                cell(&analysis["output_tokens"]),
                cell(&analysis["cache_read_tokens"]),
                cell(&analysis["cache_write_tokens"]),
                seconds(&analysis["wall_ms"]),
                analysis["totals"]["tool_errors"],
                analysis["totals"]["truncated_results"],
                failures(&analysis["failures"]),
            ));
        }
    }
    if let Some(categories) = summary["categories"]
        .as_object()
        .filter(|categories| categories.len() > 1 || categories.keys().any(|category| category != "uncategorized"))
    {
        output.push_str("\nPer category (analysis tasks):\n\n");
        output
            .push_str("| Category | Server | Correct | Lenient format | Partial credit, mean | Tool calls | Wall s | ");
        output.push_str("Failures |\n| --- | --- | --: | --: | --: | --: | --: | --- |\n");
        for (category, servers) in categories {
            for (server, group) in servers.as_object().into_iter().flatten() {
                output.push_str(&format!(
                    "| {category} | {server} | {}/{} | {}/{} | {} | {} | {} | {} |\n",
                    group["correct"],
                    group["runs"],
                    group["correct_lenient"],
                    group["runs"],
                    group["partial_credit_mean"].as_f64().map_or("–".to_owned(), |value| format!("{value:.3}")),
                    cell(&group["tool_calls"]),
                    seconds(&group["wall_ms"]),
                    failures(&group["failures"]),
                ));
            }
        }
    }
    let limits = summary["limits_hit"].as_array().cloned().unwrap_or_default();
    if !limits.is_empty() {
        output.push_str("\nRuns that hit a limit:\n\n");
        for limit in &limits {
            output.push_str(&format!(
                "- {} {} r{}: {}\n",
                limit["task_id"].as_str().unwrap_or(""),
                limit["server"].as_str().unwrap_or(""),
                limit["repetition"],
                limit["limit"].as_str().unwrap_or("")
            ));
        }
    }
    output.push_str("\nPer task (median and range over repetitions):\n\n");
    output.push_str("| Task | Server | Correct | Tool calls | Input tokens | Output tokens | Cache read | ");
    output.push_str("Cache write | Wall s | Failures |\n");
    output.push_str("| --- | --- | --: | --: | --: | --: | --: | --: | --: | --- |\n");
    for task in summary["tasks"].as_array().into_iter().flatten() {
        let probe = if task["kind"] == "capability" { " (probe)" } else { "" };
        output.push_str(&format!(
            "| {}{probe} | {} | {}/{} | {} | {} | {} | {} | {} | {} | {} |\n",
            task["task_id"].as_str().unwrap_or(""),
            task["server"].as_str().unwrap_or(""),
            task["correct"],
            task["runs"],
            cell(&task["tool_calls"]),
            cell(&task["input_tokens"]),
            cell(&task["output_tokens"]),
            cell(&task["cache_read_tokens"]),
            cell(&task["cache_write_tokens"]),
            seconds(&task["wall_ms"]),
            failures(&task["failures"]),
        ));
    }
    output
}

/// Carry the measured run's provenance into a rescored report and record what the rescore changed.
///
/// `earlier` is the report the run wrote; `rescored` is the freshly scored one. The rescore changes only
/// outcomes, failures and extraction kinds, so `versions`, `run_unix_ms` and `protocol` stay those of the
/// measurement, as do the attachments, a cost-cap stop and any rerun record with its superseded runs.
pub fn rescored_report(earlier: &Value, mut rescored: Value, commit: Option<String>, reason: &str) -> Value {
    for key in ["versions", "run_unix_ms", "protocol", "attachments", "stopped", "rerun", "superseded_runs"] {
        if let Some(value) = earlier.get(key) {
            rescored[key] = value.clone();
        }
    }
    let empty = Vec::new();
    let before = earlier["runs"].as_array().unwrap_or(&empty);
    let after = rescored["runs"].as_array().unwrap_or(&empty);
    let key = |run: &Value| (run["task_id"].clone(), run["server"].clone(), run["repetition"].clone());
    let changed: Vec<Value> = after
        .iter()
        .filter_map(|run| {
            let old = before.iter().find(|old| key(old) == key(run))?;
            let fields = ["outcome", "failure", "extraction"];
            (fields.iter().any(|field| old[*field] != run[*field])).then(|| {
                json!({"task_id": run["task_id"], "server": run["server"], "repetition": run["repetition"],
                    "before": {"outcome": old["outcome"], "failure": old["failure"], "extraction": old["extraction"]},
                    "after": {"outcome": run["outcome"], "failure": run["failure"], "extraction": run["extraction"]}})
            })
        })
        .collect();
    rescored["rescore"] = json!({"commit": commit, "reason": reason, "changed_runs": changed,
        "earlier_rescore": earlier.get("rescore")});
    rescored
}
