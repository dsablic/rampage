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

const NEUTRAL_V2: &str = include_str!("../tasks/h2h/neutral-v2.toml");

fn suite_v2() -> Vec<rampage_eval::parity_tasks::ParityTask> {
    load_tasks(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tasks/v2")).unwrap()
}

#[test]
fn suite_v2_covers_its_manifests_with_categories_scoring_and_neutral_prompts() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V2).unwrap();
    let tasks = suite_v2();
    assert_eq!(tasks.len(), 15);
    suite.check_against(&tasks, &servers()).unwrap();
    assert_eq!(suite.system, NeutralSuite::from_toml(NEUTRAL).unwrap().system, "same system prompt as v1");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for task in &tasks {
        assert_eq!(task.kind, TaskKind::Analysis, "{}", task.id);
        let neutral = &suite.tasks[&task.id];
        let category = neutral.category.as_deref().unwrap_or_default();
        assert!(
            ["cpp", "typing", "investigation", "scale", "firmware", "diffing"].contains(&category),
            "{}: {category}",
            task.id
        );
        assert!(neutral.scoring.as_deref().is_some_and(|text| !text.trim().is_empty()), "{}", task.id);
        assert_eq!(neutral.question.trim(), task.question.trim(), "{}: the manifest holds the asked wording", task.id);
        let companions: Vec<(String, String)> = task
            .fixture
            .companions
            .iter()
            .map(|companion| (companion.name.clone(), format!("/tmp/work/{}", companion.name)))
            .collect();
        let prompt = suite.prompt_with(task, "/tmp/work/fixture.bin", &companions).to_lowercase();
        // Neither server's tool names or concepts: rampage's, then REA's.
        for word in [
            "rampage",
            "enable_tools",
            "class_evidence",
            "language_metadata",
            "find_main",
            "xrefs_to",
            "rea ",
            "ghidra",
            "procedure",
            "open_binary",
            "inspect_",
        ] {
            assert!(!prompt.contains(word), "{}: {word}", task.id);
        }
        for (_, path) in &companions {
            assert!(prompt.contains(&format!("\"{path}\"")), "{}", task.id);
        }
        // Owned fixtures are committed; the scale fixture is built into target/ by its script.
        let fixture = root.join(&task.fixture.path);
        if !task.fixture.path.starts_with("target") {
            let bytes = std::fs::read(&fixture).unwrap();
            assert_eq!(
                rampage_arch::hex::bytes(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
                task.fixture.sha256,
                "{}",
                task.id
            );
        }
        if category == "scale" {
            assert!(neutral.timeout_s.is_some_and(|timeout| timeout >= 1800), "{}", task.id);
        }
    }
}

const NEUTRAL_V3: &str = include_str!("../tasks/h2h/neutral-v3.toml");

#[test]
fn suite_v3_covers_its_manifests_with_categories_scoring_and_neutral_prompts() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V3).unwrap();
    let tasks = load_tasks(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tasks/v3")).unwrap();
    assert_eq!(tasks.len(), 21);
    suite.check_against(&tasks, &servers()).unwrap();
    assert_eq!(suite.system, NeutralSuite::from_toml(NEUTRAL).unwrap().system, "same system prompt as v1");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut categories = std::collections::BTreeMap::<&str, usize>::new();
    for task in &tasks {
        assert_eq!(task.kind, TaskKind::Analysis, "{}", task.id);
        assert!(task.fixture.companions.is_empty(), "{}", task.id);
        let neutral = &suite.tasks[&task.id];
        let category = neutral.category.as_deref().unwrap_or_default();
        assert!(
            ["symbols", "semantics", "typing", "switch", "callconv", "go", "msvc"].contains(&category),
            "{}: {category}",
            task.id
        );
        *categories.entry(category).or_default() += 1;
        assert!(neutral.scoring.as_deref().is_some_and(|text| !text.trim().is_empty()), "{}", task.id);
        assert_eq!(neutral.question.trim(), task.question.trim(), "{}: the manifest holds the asked wording", task.id);
        let prompt = suite.prompt(task, "/tmp/work/fixture.bin").to_lowercase();
        // Neither server's tool names or concepts: rampage's, then REA's.
        for word in [
            "rampage",
            "enable_tools",
            "class_evidence",
            "language_metadata",
            "find_main",
            "xrefs_to",
            "rea ",
            "ghidra",
            "procedure",
            "open_binary",
            "inspect_",
            "rizin",
            "decompile",
        ] {
            assert!(!prompt.contains(word), "{}: {word}", task.id);
        }
        // Owned fixtures are committed with their digests; the pinned and MSVC-ABI fixtures are built into target/
        // by their scripts, which must exist.
        if task.fixture.path.starts_with("target") {
            assert!(root.join(&task.fixture.build).is_file(), "{}", task.id);
        } else {
            let bytes = std::fs::read(root.join(&task.fixture.path)).unwrap();
            assert_eq!(
                rampage_arch::hex::bytes(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
                task.fixture.sha256,
                "{}",
                task.id
            );
        }
        if category == "go" {
            assert!(neutral.timeout_s.is_some_and(|timeout| timeout >= 1800), "{}", task.id);
        }
    }
    assert!(categories.len() == 7 && categories.values().all(|count| *count >= 2), "{categories:?}");
}

#[test]
fn declared_spellings_count_only_in_the_lenient_variant() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V3).unwrap();
    let tasks = load_tasks(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tasks/v3")).unwrap();
    let task = tasks.iter().find(|task| task.id == "callconv-member-x86-pe").unwrap();
    let row = |answer: &str| score(task, &suite, "rea", 1, 0, &result(answer, "ok")).unwrap();
    let exact = row(r#"{"convention":"thiscall","parameters":3}"#);
    assert_eq!(exact.outcome, TaskOutcome::AnswerMatches);
    let spelled = row(r#"{"convention":"__THISCALL","parameters":3}"#);
    assert_eq!(spelled.outcome, TaskOutcome::AnswerMismatch);
    assert!(spelled.lenient);
    let both = row(r#"{"status":"ok","convention":"__thiscall","parameters":3}"#);
    assert!(both.lenient);
    assert!(!row(r#"{"convention":"__stdcall","parameters":3}"#).lenient, "a variant of another answer");
    assert!(!row(r#"{"convention":"this call","parameters":3}"#).lenient, "only declared variants");
    let other = tasks.iter().find(|task| task.id == "switch-pic-x64-so").unwrap();
    assert!(suite.tasks[&other.id].lenient_spellings.is_empty());
    let hierarchy = tasks.iter().find(|task| task.id == "msvc-rtti-hierarchy-x64-pe").unwrap();
    let mut edges: Vec<Value> = match &hierarchy.answer {
        rampage_eval::parity_tasks::AnswerContract::TupleSet { values, .. } => {
            values.iter().map(|edge| json!(edge)).collect()
        }
        _ => unreachable!(),
    };
    edges[0] = json!(
        edges[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| format!("engine::{}", name.as_str().unwrap()))
            .collect::<Vec<_>>()
    );
    let qualified = score(hierarchy, &suite, "rea", 1, 0, &result(&json!({"edges": edges}).to_string(), "ok")).unwrap();
    assert_eq!(qualified.outcome, TaskOutcome::AnswerMismatch);
    assert!(qualified.lenient);
}

#[test]
fn canonical_prompts_are_unchanged_by_companion_support() {
    let suite = NeutralSuite::from_toml(NEUTRAL).unwrap();
    let task = &canonical()[0];
    let prompt = suite.prompt(task, "/tmp/work/fixture.bin");
    assert!(prompt.starts_with(
        "Analyze the binary at \"/tmp/work/fixture.bin\". Use only the tools of the connected MCP server; there is \
         no other way to read the file.\n\n"
    ));
}

#[test]
fn tuple_sets_and_hex_integers_score_strictly_with_partial_credit_for_sets() {
    let task = |answer: &str| {
        rampage_eval::parity_tasks::ParityTask::from_toml(&format!(
            r#"
version = 1
id = "t"
kind = "analysis"
question = "q"
truth_reference = "r"
required_capabilities = ["x"]
capability_status = "unknown"
capability_evidence = "e"
[fixture]
id = "f"
path = "a/b"
sha256 = "{}"
source = "a/c"
build = "a/d"
{answer}"#,
            "0".repeat(64)
        ))
        .unwrap()
    };
    let pairs =
        task("[answer]\nkind = \"tuple_set\"\nfield = \"fields\"\nhex_integers = true\nvalues = [[8, 1], [16, 8]]");
    assert!(pairs.answer.matches(&json!({"fields": [[16, 8], ["0x8", 1]]})));
    assert!(!pairs.answer.matches(&json!({"fields": [[16, 8]]})));
    assert!(!pairs.answer.matches(&json!({"fields": [[16, 8], [8, 1], [8, 1]]})), "duplicates");
    assert!(!pairs.answer.matches(&json!({"fields": [[16, 8], [8, 1]], "extra": 1})));
    assert_eq!(pairs.answer.partial(&json!({"fields": [[16, 8], [24, 4]]})), Some(1.0 / 3.0));
    assert_eq!(pairs.answer.partial(&json!({"fields": [[16, 8], [16, 8]]})), Some(0.0));
    assert_eq!(pairs.answer.partial(&json!("nonsense")), Some(0.0));
    let edges = task("[answer]\nkind = \"tuple_set\"\nfield = \"edges\"\nvalues = [[\"A\", \"B\"]]");
    assert!(edges.answer.matches(&json!({"edges": [["A", "B"]]})));
    assert!(!edges.answer.matches(&json!({"edges": [["B", "A"]]})), "tuples are ordered");
    let exact =
        task("[answer]\nkind = \"exact\"\nhex_integers = true\n[answer.fields]\nchain = [4096, 8192]\nname = \"x\"");
    assert!(exact.answer.matches(&json!({"chain": ["0x1000", 8192], "name": "x"})));
    assert!(exact.answer.matches(&json!({"chain": ["0X1000", "0x2000"], "name": "x"})));
    assert!(!exact.answer.matches(&json!({"chain": [8192, 4096], "name": "x"})), "ordered");
    assert!(!exact.answer.matches(&json!({"chain": ["4096", 8192], "name": "x"})), "decimal strings are not integers");
    assert_eq!(exact.answer.partial(&json!({})), None);
    let strict = task("[answer]\nkind = \"exact\"\n[answer.fields]\nvalue = 16");
    assert!(!strict.answer.matches(&json!({"value": "0x10"})), "hex strings need hex_integers");
    let names = task("[answer]\nkind = \"string_set\"\nfield = \"names\"\nvalues = [\"a\", \"b\", \"c\"]");
    assert_eq!(names.answer.partial(&json!({"names": ["a", "b", "d"]})), Some(0.5));
    assert!(
        rampage_eval::parity_tasks::ParityTask::from_toml(&format!(
            "version = 1\nid = \"t\"\nkind = \"analysis\"\nquestion = \"q\"\ntruth_reference = \"r\"\n\
         required_capabilities = [\"x\"]\ncapability_status = \"unknown\"\ncapability_evidence = \"e\"\n\
         [fixture]\nid = \"f\"\npath = \"a/b\"\nsha256 = \"{0}\"\nsource = \"a/c\"\nbuild = \"a/d\"\n\
         [[fixture.companions]]\nname = \"../x\"\npath = \"a/e\"\nsha256 = \"{0}\"\n\
         [answer]\nkind = \"exact\"\n[answer.fields]\nv = 1",
            "0".repeat(64)
        ))
        .is_err()
    );
}

#[test]
fn rows_carry_category_and_partial_credit_into_the_summary() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V2).unwrap();
    let tasks = suite_v2();
    let task = tasks.iter().find(|task| task.id == "cpp-hierarchy-x64-elf").unwrap();
    let answer = r#"{"edges": [["Node", "Widget"], ["Widget", "Button"], ["Widget", "Slider"]]}"#;
    let partial = score(task, &suite, "rea", 1, 0, &result(answer, "ok")).unwrap();
    assert_eq!(partial.category, "cpp");
    assert_eq!(partial.outcome, TaskOutcome::AnswerMismatch);
    assert_eq!(partial.partial, Some(0.5));
    let timeout = score(task, &suite, "rampage", 1, 1, &result("", "timeout")).unwrap();
    assert_eq!(timeout.partial, Some(0.0));
    let summary = summarize(&[partial, timeout]);
    assert_eq!(summary["categories"]["cpp"]["rea"]["partial_credit_mean"], 0.5);
    assert_eq!(summary["limits_hit"][0]["server"], "rampage");
    let tables = markdown_tables(&summary);
    assert!(tables.contains("| cpp | rea | 0/1 | 0/1 | 0.500 |"), "{tables}");
    assert!(tables.contains("- cpp-hierarchy-x64-elf rampage r1: timeout"), "{tables}");
}

#[test]
fn a_status_ok_extra_field_counts_only_in_the_lenient_variant() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V2).unwrap();
    let tasks = suite_v2();
    let task = tasks.iter().find(|task| task.id == "option-bit-x64-elf").unwrap();
    let slip = score(task, &suite, "rea", 1, 0, &result(r#"{"status":"ok","option":"--snapshot"}"#, "ok")).unwrap();
    assert_eq!(slip.outcome, TaskOutcome::AnswerMismatch);
    assert!(slip.lenient);
    let wrong = score(task, &suite, "rea", 2, 0, &result(r#"{"status":"ok","option":"--archive"}"#, "ok")).unwrap();
    assert!(!wrong.lenient);
    let other = score(task, &suite, "rea", 3, 0, &result(r#"{"note":"x","option":"--snapshot"}"#, "ok")).unwrap();
    assert!(!other.lenient, "only the status field is forgiven");
    let right = score(task, &suite, "rampage", 1, 0, &result(r#"{"option":"--snapshot"}"#, "ok")).unwrap();
    assert!(right.lenient);
    let summary = summarize(&[slip, wrong, other, right]);
    assert_eq!(summary["servers"]["rea"]["analysis"]["correct"], 0);
    assert_eq!(summary["servers"]["rea"]["analysis"]["correct_lenient"], 1);
}

#[test]
fn recorded_rows_read_back_unchanged_for_reruns() {
    let suite = NeutralSuite::from_toml(NEUTRAL_V2).unwrap();
    let tasks = suite_v2();
    let row = score(&tasks[0], &suite, "rea", 2, 1, &result("{\"chain\": []}", "ok")).unwrap();
    let line = serde_json::to_string(&row).unwrap();
    let back: rampage_eval::agent_bench::RunRow = serde_json::from_str(&line).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), line);
}
