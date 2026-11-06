use std::path::Path;

use rampage_eval::agent_bench::{
    Extraction, FailureKind, NeutralSuite, RunnerResult, extract_answer, markdown_tables, rescored_report, score,
    spread, summarize,
};
use rampage_eval::parity_tasks::{TaskKind, TaskOutcome, load_tasks};
use serde_json::{Value, json};

const NEUTRAL: &str = include_str!("../tasks/h2h/neutral.toml");

fn servers() -> Vec<String> {
    vec!["rampage".to_owned(), "rea".to_owned()]
}

fn canonical() -> Vec<rampage_eval::parity_tasks::ParityTask> {
    load_tasks(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tasks")).unwrap()
}

fn result(answer: &str, exit: &str) -> RunnerResult {
    serde_json::from_value(json!({
        "answer": answer,
        "tool_calls": [
            {"name": "mcp__rampage__find_main", "input_bytes": 20, "output_bytes": 300, "is_error": false,
             "duration_ms": 40},
            {"name": "mcp__rampage__disassemble", "input_bytes": 30, "output_bytes": 900, "is_error": true}
        ],
        "turns": 3,
        "usage": {"input": 10, "output": 20, "cache_read": 300, "cache_write": 40},
        "cost_usd": 0.5,
        "duration_ms": 1200,
        "exit": exit,
        "error": if exit == "ok" { Value::Null } else { json!("boom") },
        "runner": {"name": "claude-code", "version": "2.1.318", "model": "claude-sonnet-5-5",
                   "isolation": "setting-sources-none"}
    }))
    .unwrap()
}

#[test]
fn neutral_suite_covers_the_canonical_tasks_with_per_server_probe_truth() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    let tasks = canonical();
    assert_eq!(tasks.len(), 20);
    suite.check_against(&tasks, &servers()).unwrap();
    let probes = tasks.iter().filter(|task| task.kind == TaskKind::Capability).count();
    assert_eq!(probes, 3);
    let error = suite.check_against(&tasks, &["ghidra-mcp".to_owned()]).unwrap_err();
    assert!(error.contains("no capability truth for server ghidra-mcp"), "{error}");
}

#[test]
fn neutral_prompts_name_no_rampage_tool_or_concept() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    for task in canonical() {
        let prompt = suite.prompt(&task, "/tmp/work/fixture.bin");
        for word in
            ["rampage", "enable_tools", "enableable", "groups", "find_main", "class_evidence", "language_metadata"]
        {
            assert!(!prompt.to_lowercase().contains(word), "{}: {word}", task.id);
        }
        assert!(prompt.contains("\"/tmp/work/fixture.bin\""));
        assert!(!suite.system.to_lowercase().contains("rampage"));
    }
}

#[test]
fn neutral_suite_must_match_the_canonical_ids() {
    let mut text = NEUTRAL.replace("[tasks.format-x64-pe]", "[tasks.format-x64-pe-renamed]");
    let suite = NeutralSuite::from_toml(&text).unwrap();
    let error = suite.check_against(&canonical(), &servers()).unwrap_err();
    assert!(error.contains("format-x64-pe"), "{error}");
    text = NEUTRAL.replace("[tasks.arithmetic-arm64-elf]", "[tasks.arithmetic-arm64-elf]\ntruth = { rea = true }");
    assert!(NeutralSuite::from_toml(&text).is_err(), "truth without evidence");
}

#[test]
fn answers_are_one_json_object_alone_fenced_or_ending_the_reply() {
    let object = json!({"a": 1});
    assert_eq!(extract_answer(" {\"a\":1}\n").unwrap(), (object.clone(), Extraction::Exact));
    assert_eq!(extract_answer("```json\n{\"a\":1}\n```").unwrap(), (object.clone(), Extraction::Fenced));
    assert_eq!(extract_answer("```\n{\"a\":1}\n```").unwrap(), (object.clone(), Extraction::Fenced));
    assert_eq!(extract_answer("So 3*7 = 21.\n\n{\"a\":1}\n").unwrap(), (object.clone(), Extraction::Trailing));
    assert_eq!(extract_answer("Done.\n```json\n{\"a\":\n 1}\n```").unwrap(), (object.clone(), Extraction::Trailing));
    for text in ["The answer is {\"a\":1}", "[1]", "{\"a\":1}\nThat is all.", "Prose.\n{\"a\":1} and more", ""] {
        assert!(extract_answer(text).is_err(), "{text}");
    }
}

#[test]
fn scoring_uses_the_frozen_contract_and_per_server_probe_truth() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    let tasks = canonical();
    let task = |id: &str| tasks.iter().find(|task| task.id == id).unwrap();
    let main = task("main-return-x64-elf");
    let row = score(main, &suite, "rampage", 1, 0, &result("{\"return_value\":5}", "ok")).unwrap();
    assert_eq!(row.outcome, TaskOutcome::AnswerMatches);
    assert_eq!((row.tool_calls, row.tool_errors, row.failure), (2, 1, None));
    assert_eq!(row.extraction, Some(Extraction::Exact));
    let row = score(main, &suite, "rea", 1, 0, &result("{\"return_value\":6}", "ok")).unwrap();
    assert_eq!((row.outcome, row.failure), (TaskOutcome::AnswerMismatch, Some(FailureKind::WrongAnswer)));
    let patch = task("capability-patch-export");
    let yes = result("{\"available\":true}", "ok");
    assert_eq!(score(patch, &suite, "rampage", 1, 0, &yes).unwrap().outcome, TaskOutcome::AnswerMatches);
    let no = result("{\"available\":false}", "ok");
    assert_eq!(score(patch, &suite, "rampage", 1, 0, &no).unwrap().outcome, TaskOutcome::AnswerMismatch);
    // REA advertises raw Rizin/Cutter command runners, so either boolean is accepted, but only that field.
    assert_eq!(score(patch, &suite, "rea", 1, 0, &yes).unwrap().outcome, TaskOutcome::AnswerMatches);
    assert_eq!(score(patch, &suite, "rea", 1, 0, &no).unwrap().outcome, TaskOutcome::AnswerMatches);
    let extra = result("{\"available\":true,\"via\":\"rizin\"}", "ok");
    assert_eq!(score(patch, &suite, "rea", 1, 0, &extra).unwrap().outcome, TaskOutcome::AnswerMismatch);
    let decompile = task("capability-decompile");
    assert_eq!(score(decompile, &suite, "rea", 1, 0, &no).unwrap().outcome, TaskOutcome::AnswerMismatch);
    for (answer, exit, kind) in [
        ("{\"return_value\":5}", "timeout", FailureKind::Timeout),
        ("", "max_turns", FailureKind::MaxTurns),
        ("", "error", FailureKind::RunnerError),
        ("five", "ok", FailureKind::AnswerFormat),
        ("{\"status\":\"unknown\",\"reason\":\"no main\"}", "ok", FailureKind::Unknown),
        ("{\"status\":\"unsupported\",\"reason\":\"no tool\"}", "ok", FailureKind::Unsupported),
    ] {
        let row = score(main, &suite, "rea", 1, 0, &result(answer, exit)).unwrap();
        assert_eq!(row.failure, Some(kind), "{answer} {exit}");
        assert_ne!(row.outcome, TaskOutcome::AnswerMatches);
    }
    let error = score(main, &suite, "rea", 1, 0, &result("", "error")).unwrap();
    assert_eq!(error.runner_error.as_deref(), Some("boom"));
}

#[test]
fn summaries_report_accuracy_spread_and_failures_per_task_and_server() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    let tasks = canonical();
    let main = tasks.iter().find(|task| task.id == "main-return-x64-elf").unwrap();
    let probe = tasks.iter().find(|task| task.id == "capability-decompile").unwrap();
    let rows = vec![
        score(main, &suite, "rampage", 1, 0, &result("{\"return_value\":5}", "ok")).unwrap(),
        score(main, &suite, "rampage", 2, 0, &result("{\"return_value\":4}", "ok")).unwrap(),
        score(main, &suite, "rampage", 3, 0, &result("", "timeout")).unwrap(),
        score(probe, &suite, "rampage", 1, 0, &result("{\"available\":true}", "ok")).unwrap(),
    ];
    let summary = summarize(&rows);
    let task = &summary["tasks"][1];
    assert_eq!(task["task_id"], "main-return-x64-elf");
    assert_eq!((task["correct"].as_u64(), task["runs"].as_u64()), (Some(1), Some(3)));
    assert_eq!(task["failures"], json!({"timeout": 1, "wrong_answer": 1}));
    assert_eq!(task["wall_ms"], json!({"median": 1200, "min": 1200, "max": 1200}));
    let analysis = &summary["servers"]["rampage"]["analysis"];
    assert_eq!((analysis["correct"].as_u64(), analysis["runs"].as_u64()), (Some(1), Some(3)));
    assert_eq!(summary["servers"]["rampage"]["capability_probes"]["correct"], 1);
    assert_eq!(analysis["totals"]["cache_read_tokens"], 900);
    let tables = markdown_tables(&summary);
    assert!(tables.contains("| rampage | 1/3 | 1/1 |"), "{tables}");
    assert!(tables.contains("| capability-decompile (probe) | rampage | 1/1 |"), "{tables}");
}

#[test]
fn spread_takes_an_observed_median() {
    assert_eq!(spread([4, 1, 3, 2]), json!({"median": 2, "min": 1, "max": 4}));
    assert_eq!(spread([]), Value::Null);
}

#[test]
fn server_calls_exclude_tool_search_and_refused_calls() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    let tasks = canonical();
    let main = tasks.iter().find(|task| task.id == "main-return-x64-elf").unwrap();
    let mut run = result("{\"return_value\":5}", "ok");
    run.tool_calls[1].truncated = true;
    let mut search = run.tool_calls[0].clone();
    search.name = "ToolSearch".to_owned();
    let mut refused = run.tool_calls[0].clone();
    refused.name = "enable_tools".to_owned();
    refused.is_error = true;
    refused.rejected = true;
    run.tool_calls.extend([search, refused]);
    let row = score(main, &suite, "rampage", 2, 1, &run).unwrap();
    assert_eq!(
        (row.tool_calls, row.tool_errors, row.truncated_results, row.tool_search_calls, row.rejected_calls),
        (2, 1, 1, 1, 1)
    );
    assert_eq!(row.position, 1);
}

#[test]
fn a_rescored_report_keeps_the_measured_provenance_and_lists_changed_runs() {
    let earlier = json!({
        "versions": {"rampage": {"commit": "measured"}}, "run_unix_ms": 7, "protocol": {"repeat": 3},
        "runs": [
            {"task_id": "a", "server": "rea", "repetition": 1, "outcome": "failed", "failure": "runner_error",
             "extraction": null},
            {"task_id": "b", "server": "rea", "repetition": 1, "outcome": "answer_matches", "failure": null,
             "extraction": "exact"}
        ]
    });
    let rescored = json!({
        "versions": {"rampage": {"commit": "later", "worktree_dirty": true}}, "run_unix_ms": 99,
        "protocol": {"repeat": 3, "changed": true},
        "runs": [
            {"task_id": "a", "server": "rea", "repetition": 1, "outcome": "answer_matches", "failure": null,
             "extraction": "exact"},
            {"task_id": "b", "server": "rea", "repetition": 1, "outcome": "answer_matches", "failure": null,
             "extraction": "exact"}
        ]
    });
    let report = rescored_report(&earlier, rescored, Some("abc".to_owned()), "rule fixed");
    assert_eq!(report["versions"], earlier["versions"]);
    assert_eq!(report["run_unix_ms"], 7);
    assert_eq!(report["protocol"], earlier["protocol"]);
    assert_eq!(report["rescore"]["commit"], "abc");
    assert_eq!(report["rescore"]["reason"], "rule fixed");
    let changed = report["rescore"]["changed_runs"].as_array().unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["task_id"], "a");
    assert_eq!(changed[0]["before"]["failure"], "runner_error");
    assert_eq!(changed[0]["after"]["outcome"], "answer_matches");
}
