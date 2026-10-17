use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use rampage_eval::parity_agent::ModelSource;
use rampage_eval::parity_tasks::{TaskAttempt, TaskKind, TaskOutcome, load_tasks};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Family, Metric, RunArgs, combined_manifests, evaluate_slices, read};

pub(super) fn run(args: RunArgs) -> Result<ExitCode, String> {
    let started = Instant::now();
    let root = args.repository_root.unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let task_directory = args.tasks.unwrap_or_else(|| root.join("crates/rampage-eval/tasks"));
    let tasks = load_tasks(&task_directory).map_err(|error| error.to_string())?;
    let selected: BTreeSet<_> = if args.agent_model.is_none() {
        BTreeSet::new()
    } else if args.agent_task.is_empty() {
        tasks.iter().take(args.agent_max_tasks as usize).map(|task| task.id.clone()).collect()
    } else {
        if args.agent_task.len() > args.agent_max_tasks as usize {
            return Err("selected agent tasks exceed --agent-max-tasks".into());
        }
        let selected: BTreeSet<_> = args.agent_task.iter().cloned().collect();
        if selected.len() != args.agent_task.len() || selected.iter().any(|id| !tasks.iter().any(|task| &task.id == id))
        {
            return Err("agent task IDs must be unique members of the task suite".into());
        }
        selected
    };
    let manifest_paths = if args.manifest.is_empty() {
        vec![root.join("tests/fixtures/data/eval-manifest.json")]
    } else {
        args.manifest
    };
    let manifest_receipts: Vec<_> = manifest_paths
        .iter()
        .map(|path| Ok::<_, String>(json!({"path":path, "sha256": hash_file(path)?})))
        .collect::<Result<_, _>>()?;
    let slices = combined_manifests(&manifest_paths)?;
    if slices.is_empty() {
        return Err("parity requires a nonempty static manifest; no vacuous baseline pass".into());
    }
    let discovery = slices.iter().any(|(_, slice)| matches!(slice.family, Family::Discovery));
    let library_names = slices.iter().any(|(_, slice)| matches!(slice.family, Family::Libid));
    let params =
        slices.iter().any(|(_, slice)| matches!((slice.family, slice.metric), (Family::Types, Metric::Params)));
    let returns =
        slices.iter().any(|(_, slice)| matches!((slice.family, slice.metric), (Family::Types, Metric::Return)));
    let classes =
        slices.iter().any(|(_, slice)| matches!((slice.family, slice.metric), (Family::Types, Metric::Classes)));
    let (evaluation, decompiler_health) = evaluate_slices(slices, args.max_disagreements)?;
    let graph_agreement = args
        .graph_request
        .as_ref()
        .map(|request| {
            super::parity_graph_files::compare(
                request,
                args.rampage_graph.as_deref().expect("required graph export"),
                args.ghidra_graph.as_deref().expect("required Ghidra export"),
            )
        })
        .transpose()?;
    let mut digests: BTreeMap<PathBuf, Result<String, String>> = BTreeMap::new();
    let mut task_rows = Vec::new();
    let mut fixture_failures = 0;
    let mut measured_analysis = 0;
    let mut analysis_matches = 0;
    let mut provider_tasks_started = 0;
    let mut mcp_connected = false;
    let mut live_checks_pass = args.agent_model.is_none();
    let mut live_failures = 0;
    for task in &tasks {
        let path = root.join(&task.fixture.path);
        let actual = digests.entry(path.clone()).or_insert_with(|| hash_file(&path));
        let (status, digest, fixture_error) = match actual {
            Ok(digest) if task.matches_fixture_digest(digest) => ("matches", Some(digest.clone()), None),
            Ok(digest) => {
                fixture_failures += 1;
                ("mismatch", Some(digest.clone()), Some("fixture digest mismatch".to_owned()))
            }
            Err(error) => {
                fixture_failures += 1;
                ("unavailable", None, Some(error.clone()))
            }
        };
        let agent = if status == "matches" && selected.contains(&task.id) {
            Some(super::parity_live::run(task, &path, args.agent_model.as_deref().expect("selected model"))?)
        } else {
            None
        };
        let attempt = agent.as_ref().map_or(TaskAttempt::Unmeasured, |run| run.task_attempt());
        let check = task.check(&attempt);
        let provider_started =
            agent.as_ref().is_some_and(|run| run.model_source == Some(ModelSource::Provider) && run.model_turns > 0);
        mcp_connected |= agent.as_ref().is_some_and(|run| run.model_source == Some(ModelSource::Provider));
        provider_tasks_started += usize::from(provider_started);
        if provider_started && task.kind == TaskKind::Analysis {
            measured_analysis += 1;
            analysis_matches += usize::from(check.outcome == TaskOutcome::AnswerMatches);
        }
        if selected.contains(&task.id) && (!provider_started || check.outcome != TaskOutcome::AnswerMatches) {
            live_failures += 1;
        }
        let returned_models =
            agent.as_ref().map(|run| run.turns.iter().map(|turn| &turn.returned_model).collect::<Vec<_>>());
        task_rows.push(json!({
            "task_id": task.id, "kind": task.kind, "fixture_id": task.fixture.id,
            "fixture_path": task.fixture.path, "expected_sha256": task.fixture.sha256,
            "actual_sha256": digest, "fixture_status": status,
            "implementation_inventory": task.capability_status,
            "required_capabilities": task.required_capabilities,
            "fixture_error": fixture_error,
            "run_kind": if provider_started { "mcp_model" } else { "not_run" }, "check": check,
            "requested_model": agent.as_ref().map(|run| &run.requested_model),
            "returned_models": returned_models,
            "mcp_tool_calls": agent.as_ref().filter(|run| run.model_source.is_some()).map(|run| run.tool_calls),
            "input_tokens": agent.as_ref().and_then(|run| run.usage.input_tokens),
            "output_tokens": agent.as_ref().and_then(|run| run.usage.output_tokens),
            "cache_tokens": agent.as_ref().map(|run| json!({"read":run.usage.cache_read_input_tokens,
                "creation":run.usage.cache_creation_input_tokens})),
            "wall_time_ms": agent.as_ref().and_then(|run| run.wall_time_ms),
            "agent_run": agent,
        }));
    }
    if args.agent_model.is_some() {
        live_checks_pass = provider_tasks_started > 0 && live_failures == 0;
    }
    let corpus_inventory = args
        .corpus_inventory
        .as_ref()
        .map(|path| serde_json::from_str::<Value>(&read(path)?).map_err(|error| format!("{}: {error}", path.display())))
        .transpose()?;
    let report = json!({
        "schema_version": 1, "suite": "parity", "scope": "phase0_pilot", "phase0_complete": false,
        "evaluator": evaluator_observation(&root),
        "run_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .ok().and_then(|duration| u64::try_from(duration.as_millis()).ok()),
        "static_manifests": manifest_receipts,
        "static_evaluation": evaluation,
        "decompiler_health": decompiler_health,
        "graph_agreement": graph_agreement,
        "static_metric_status": {
            "function_starts": if discovery { "scored" } else { "not_run" },
            "library_names": if library_names { "scored" } else { "not_run" },
            "parameter_counts": if params { "scored" } else { "not_run" },
            "return_classes": if returns { "scored" } else { "not_run" },
            "parameter_classes": if classes { "scored" } else { "not_run" }
        },
        "corpus_inventory": corpus_inventory,
        "agent_tasks": {
            "status": if provider_tasks_started > 0 { "attempted" } else { "not_run" },
            "transport": if mcp_connected { "in_memory_mcp_jsonrpc" } else { "not_connected" },
            "configured_transport": args.agent_model.as_ref().map(|_| "in_memory_mcp_jsonrpc"),
            "measured_analysis_tasks": measured_analysis,
            "analysis_answer_matches": analysis_matches, "provider_tasks_started": provider_tasks_started,
            "requested_model": args.agent_model, "selected_tasks": selected,
            "defined_analysis_tasks": tasks.iter().filter(|task| task.kind == TaskKind::Analysis).count(),
            "defined_capability_probes": tasks.iter().filter(|task| task.kind == TaskKind::Capability).count(),
            "fixture_failures": fixture_failures, "tasks": task_rows,
            "limits": "Only provider-backed MCP/model attempts count; \
                       scripted contracts and inventory are not AI task success."
        },
        "unmeasured": [if graph_agreement.is_some() { "whole-corpus CFG/call-graph agreement coverage" }
            else { "CFG/call-graph agreement" }, "whole-corpus decompiler health/time coverage",
            if provider_tasks_started == 0 { "fixed-model MCP task success/tool calls/tokens/wall time" }
            else { "suite-wide fixed-model benchmarking (recorded pilot attempts are reported separately)" },
            "Ghidra MCP comparison"],
        "scorecard_wall_time_ms": started.elapsed().as_millis(),
        "limits": ["Static gates are existing slice gates, not overall parity acceptance.",
            "Unavailable or failed corpus selections are not successes; optional inventory is retained verbatim.",
            "Type-recovery scores do not substitute for decompiler health or agent-task results."]
    });
    println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
    Ok(if evaluation.passes_gate() && fixture_failures == 0 && live_checks_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(rampage_arch::hex::bytes(&Sha256::digest(&bytes)))
}

fn evaluator_observation(root: &Path) -> Value {
    let executable = std::env::current_exe().ok();
    let digest = executable.as_ref().and_then(|path| hash_file(path).ok());
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
    };
    json!({
        "executable": executable, "sha256": digest, "package_version": env!("CARGO_PKG_VERSION"),
        "repository_revision": git(&["rev-parse", "HEAD"]).map(|value| value.trim().to_owned()),
        "worktree_dirty": git(&["-c", "core.fsmonitor=false", "status", "--porcelain"])
            .map(|status| !status.trim().is_empty()),
        "note": "The executable digest identifies the evaluator; a dirty checkout is not identified by HEAD alone."
    })
}
