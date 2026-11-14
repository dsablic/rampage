//! Suite v4 of the head-to-head benchmark: its manifests and neutral prompts, every checker against hand-written
//! correct and incorrect replies (tools/agent-bench/v4/checker-cases.json), and the image checks of the export
//! tasks against a real export and near misses.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rampage_eval::agent_bench::{
    FailureKind, NeutralSuite, RunnerResult, contamination, mark_contaminated, score, score_with_artifact,
};
use rampage_eval::parity_tasks::{ParityTask, TaskKind, TaskOutcome, load_tasks};
use serde_json::{Value, json};

const NEUTRAL: &str = include_str!("../tasks/h2h/neutral.toml");
const NEUTRAL_V3: &str = include_str!("../tasks/h2h/neutral-v3.toml");
const NEUTRAL_V4: &str = include_str!("../tasks/h2h/neutral-v4.toml");
const CHECKER_CASES: &str = include_str!("../../../tools/agent-bench/v4/checker-cases.json");
const REGRESSION: [&str; 4] =
    ["semantics-wide-x86-elf", "switch-pic-x86-so", "callconv-arguments-x86-pe", "type-indirect-offsets-arm64-elf"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn suite_v4() -> (NeutralSuite, Vec<ParityTask>) {
    let suite = NeutralSuite::from_toml(NEUTRAL_V4).unwrap();
    let tasks = load_tasks(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tasks/v4")).unwrap();
    (suite, tasks)
}

fn reply(answer: &str) -> RunnerResult {
    serde_json::from_value(json!({
        "answer": answer,
        "tool_calls": [{"name": "mcp__rea__decompile", "input_bytes": 20, "output_bytes": 300, "is_error": false}],
        "turns": 3,
        "usage": {"input": 10, "output": 20, "cache_read": 300, "cache_write": 40},
        "cost_usd": 0.1,
        "duration_ms": 1200,
        "exit": "ok",
        "runner": {"name": "claude-code", "version": "2.1.323", "model": "claude-sonnet-5-5", "isolation": "bare"}
    }))
    .unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&<sha2::Sha256 as sha2::Digest>::digest(bytes))
}

#[test]
fn suite_v4_covers_its_manifests_with_categories_scoring_and_neutral_prompts() {
    let (suite, tasks) = suite_v4();
    assert_eq!(tasks.len(), 20);
    suite.check_against(&tasks, &["rampage".to_owned(), "rea".to_owned()]).unwrap();
    assert_eq!(suite.system, NeutralSuite::from_toml(NEUTRAL).unwrap().system, "same system prompt as v1");
    let v3 = NeutralSuite::from_toml(NEUTRAL_V3).unwrap();
    let mut categories = BTreeMap::<&str, usize>::new();
    for task in &tasks {
        assert_eq!(task.kind, TaskKind::Analysis, "{}", task.id);
        let neutral = &suite.tasks[&task.id];
        let category = neutral.category.as_deref().unwrap_or_default();
        assert!(
            ["emulation", "strings", "peripherals", "patching", "locks", "libraries", "regression"].contains(&category),
            "{}: {category}",
            task.id
        );
        *categories.entry(category).or_default() += 1;
        assert!(neutral.scoring.as_deref().is_some_and(|text| !text.trim().is_empty()), "{}", task.id);
        assert_eq!(neutral.question.trim(), task.question.trim(), "{}: the manifest holds the asked wording", task.id);
        let companions: Vec<(String, String)> = task
            .fixture
            .companions
            .iter()
            .map(|companion| (companion.name.clone(), format!("/tmp/work/{}", companion.name)))
            .collect();
        let prompt = suite.prompt_with(task, "/tmp/work/fixture.bin", &companions);
        // Neither server's tool names or concepts (rampage's, then REA's), nor a hint at either's route.
        for word in [
            "rampage",
            "enable_tools",
            "evaluate_function",
            "string_decoding",
            "import_svd",
            "peripheral_access",
            "integrity_checks",
            "export_image",
            "patch_bytes",
            "identify_functions",
            "lock_mechanisms",
            "debug_snapshot",
            "emulat",
            "signature",
            "rea ",
            "ghidra",
            "rizin",
            "open_binary",
            "procedure",
            "inspect_",
            "decompile",
            "{output}",
        ] {
            assert!(!prompt.to_lowercase().contains(word), "{}: {word}", task.id);
        }
        for (_, path) in &companions {
            assert!(prompt.contains(&format!("\"{path}\"")), "{}", task.id);
        }
        // A prompt never trips the contamination screen by itself.
        let line = json!({"type": "user", "message": {"content": prompt}}).to_string();
        assert_eq!(contamination(&line, &root()), None, "{}", task.id);
        if let Some(output) = &neutral.output {
            assert!(prompt.contains(&format!("\"/tmp/work/{}\"", output.name)), "{}", task.id);
            assert_eq!(category, "patching", "{}", task.id);
            output.expected_memory(&root()).unwrap();
        }
        for path in std::iter::once((&task.fixture.path, &task.fixture.sha256))
            .chain(task.fixture.companions.iter().map(|companion| (&companion.path, &companion.sha256)))
        {
            assert!(!path.0.starts_with("target"), "{}: v4 fixtures are committed", task.id);
            assert_eq!(&sha256(&std::fs::read(root().join(path.0)).unwrap()), path.1, "{}", task.id);
        }
        if category == "regression" {
            assert!(REGRESSION.contains(&task.id.as_str()), "{}", task.id);
            let v3_manifest = root().join(format!("crates/rampage-eval/tasks/v3/{}.toml", task.id));
            let v4_manifest = root().join(format!("crates/rampage-eval/tasks/v4/{}.toml", task.id));
            assert_eq!(std::fs::read(v3_manifest).unwrap(), std::fs::read(v4_manifest).unwrap(), "{}", task.id);
            assert_eq!(neutral.question, v3.tasks[&task.id].question, "{}", task.id);
            assert_eq!(neutral.scoring, v3.tasks[&task.id].scoring, "{}", task.id);
        }
    }
    let expected = BTreeMap::from([
        ("emulation", 4),
        ("strings", 2),
        ("peripherals", 3),
        ("patching", 3),
        ("locks", 2),
        ("libraries", 2),
        ("regression", 4),
    ]);
    assert_eq!(categories, expected);
}

#[test]
fn suite_v4_checkers_accept_correct_and_reject_incorrect_replies() {
    let (suite, tasks) = suite_v4();
    let cases: Value = serde_json::from_str(CHECKER_CASES).unwrap();
    let covered: Vec<&String> = cases.as_object().unwrap().keys().filter(|key| !key.starts_with('_')).collect();
    assert_eq!(covered.len(), tasks.len(), "one case set per task");
    for task in &tasks {
        let case = &cases[&task.id];
        let correct = case["correct"].as_array().unwrap_or_else(|| panic!("{}: no correct replies", task.id));
        let incorrect = case["incorrect"].as_array().unwrap_or_else(|| panic!("{}: no incorrect replies", task.id));
        assert!(!correct.is_empty() && incorrect.len() >= 2, "{}", task.id);
        let verdict = suite.tasks[&task.id].output.as_ref().map(|_| Ok(()));
        let row = |text: &str| score_with_artifact(task, &suite, "rea", 1, 0, &reply(text), verdict.as_ref()).unwrap();
        for text in correct {
            let text = text.as_str().unwrap();
            assert_eq!(row(text).outcome, TaskOutcome::AnswerMatches, "{}: {text}", task.id);
        }
        for text in incorrect {
            let text = text.as_str().unwrap();
            assert_ne!(row(text).outcome, TaskOutcome::AnswerMatches, "{}: {text}", task.id);
        }
    }
}

#[test]
fn runs_that_reach_the_suites_own_files_are_scored_wrong() {
    let (suite, tasks) = suite_v4();
    let root = root();
    let call = |path: String| {
        json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "disassemble",
               "input": {"path": path}}]}})
        .to_string()
    };
    let workdir = "/private/var/tmp/agent-bench-1-0/fixture.bin".to_owned();
    assert_eq!(contamination(&call(workdir), &root), None);
    for path in [
        root.join("tests/fixtures/bench-v4/twins/emulate-thumb.elf").to_string_lossy().into_owned(),
        "../../tests/fixtures/bench-v4/truth/patch-export-bin-cm4-raw.bin".to_owned(),
        "/x/tools/agent-bench/v4/derive-truth.py".to_owned(),
        root.join("README.md").to_string_lossy().into_owned(),
    ] {
        assert!(contamination(&call(path.clone()), &root).is_some(), "{path}");
    }
    // The client's own setup lines (the configured server's path) are not the agent's doing.
    let setup = json!({"type": "system", "subtype": "init", "cwd": root.join("x")}).to_string();
    assert_eq!(contamination(&setup, &root), None);

    let task = tasks.iter().find(|task| task.id == "emulate-control-thumb-elf").unwrap();
    let mut row = score(task, &suite, "rea", 1, 0, &reply(r#"{"result": 2568817383}"#)).unwrap();
    assert_eq!(row.outcome, TaskOutcome::AnswerMatches);
    mark_contaminated(&mut row, "transcript line 3 mentions \"twins\"".into());
    assert_eq!((row.outcome, row.failure), (TaskOutcome::AnswerMismatch, Some(FailureKind::Contaminated)));
    assert!(!row.lenient && row.contamination.is_some());
}

#[test]
fn suite_v4_export_runs_count_only_with_a_passing_file() {
    let (suite, tasks) = suite_v4();
    let exports: Vec<&ParityTask> = tasks.iter().filter(|task| suite.tasks[&task.id].output.is_some()).collect();
    assert_eq!(exports.len(), 2);
    for task in exports {
        let answer = reply(r#"{"written": true}"#);
        let passed = score_with_artifact(task, &suite, "rampage", 1, 0, &answer, Some(&Ok(()))).unwrap();
        assert_eq!(passed.outcome, TaskOutcome::AnswerMatches);
        assert_eq!(passed.artifact.as_deref(), Some("ok"));
        let failed =
            score_with_artifact(task, &suite, "rampage", 1, 0, &answer, Some(&Err("2 bytes differ".into()))).unwrap();
        assert_eq!((failed.outcome, failed.failure), (TaskOutcome::AnswerMismatch, Some(FailureKind::WrongArtifact)));
        assert!(!failed.lenient);
        assert_eq!(failed.artifact.as_deref(), Some("2 bytes differ"));
        assert!(score(task, &suite, "rampage", 1, 0, &answer).is_err(), "an export run needs its file's verdict");
        let slip =
            score_with_artifact(task, &suite, "rea", 1, 0, &reply(r#"{"status":"ok","written":true}"#), Some(&Ok(())))
                .unwrap();
        assert!(slip.lenient && slip.outcome == TaskOutcome::AnswerMismatch);
    }
    let other = tasks.iter().find(|task| task.id == "patch-values-cm4-hex").unwrap();
    assert!(score_with_artifact(other, &suite, "rea", 1, 0, &reply("{}"), Some(&Ok(()))).is_err());
}

#[test]
fn suite_v4_image_checks_accept_a_real_export_and_reject_near_misses() {
    let (suite, _) = suite_v4();
    let root = root();
    let srec = suite.tasks["patch-export-srec-cm4-srec"].output.clone().unwrap();
    let binary = suite.tasks["patch-export-bin-cm4-raw"].output.clone().unwrap();
    let cases = root.join("tools/agent-bench/v4/artifact-cases");
    let fixtures = root.join("tests/fixtures/bench-v4");
    // An S-record file written by an encoder other than the checker's (an export of the patched image).
    srec.check(&root, &cases.join("srec-exported-correct.srec")).unwrap();
    let unpatched = srec.check(&root, &fixtures.join("bin/boot-cm4.srec")).unwrap_err();
    assert!(unpatched.contains("bytes differ"), "{unpatched}");
    assert!(srec.check(&root, &cases.join("absent.srec")).unwrap_err().contains("no file"));
    assert!(srec.check(&root, &fixtures.join("bin/boot-cm4.hex")).is_err(), "Intel HEX where S-records were asked");
    binary.check(&root, &root.join(&binary.expected)).unwrap();
    assert!(binary.check(&root, &fixtures.join("bin/boot-cm4.bin")).unwrap_err().contains("bytes differ"));

    let scratch = std::env::temp_dir().join(format!("bench-v4-artifacts-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let text = std::fs::read_to_string(cases.join("srec-exported-correct.srec")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let write = |name: &str, body: String| {
        let path = scratch.join(name);
        std::fs::write(&path, body).unwrap();
        path
    };
    // One data record dropped: its 16 addresses are missing.
    let dropped = write("dropped.srec", [&lines[..5], &lines[6..]].concat().join("\n"));
    assert!(srec.check(&root, &dropped).unwrap_err().contains("16 expected addresses missing"));
    // One data digit changed without fixing the record checksum.
    let mut flipped = lines.iter().map(|line| (*line).to_owned()).collect::<Vec<_>>();
    let digit = if flipped[5].as_bytes()[12] == b'0' { "1" } else { "0" };
    flipped[5].replace_range(12..13, digit);
    assert!(srec.check(&root, &write("flipped.srec", flipped.join("\n"))).unwrap_err().contains("checksum"));
    // The termination record missing.
    let open = write("open.srec", lines[..lines.len() - 1].join("\n"));
    assert!(srec.check(&root, &open).unwrap_err().contains("termination"));
    // A non-ASCII character in a record (where its type digit goes) is a wrong file, not a scorer panic.
    let mut accented = lines.iter().map(|line| (*line).to_owned()).collect::<Vec<_>>();
    accented[5].replace_range(1..2, "\u{e9}");
    assert!(srec.check(&root, &write("accented.srec", accented.join("\n"))).unwrap_err().contains("ASCII"));
    // A symbolic link to the expected file is not a file the agent wrote.
    #[cfg(unix)]
    {
        let link = scratch.join("linked.srec");
        std::os::unix::fs::symlink(cases.join("srec-exported-correct.srec"), &link).unwrap();
        assert!(srec.check(&root, &link).unwrap_err().contains("not a regular file"));
    }
    // A flat image one byte short, and one byte long.
    let expected = std::fs::read(root.join(&binary.expected)).unwrap();
    let short = write("short.bin", String::new());
    std::fs::write(&short, &expected[..expected.len() - 1]).unwrap();
    assert!(binary.check(&root, &short).unwrap_err().contains("missing"));
    let long = scratch.join("long.bin");
    std::fs::write(&long, [&expected[..], &[0xff]].concat()).unwrap();
    assert!(binary.check(&root, &long).unwrap_err().contains("outside"));
    std::fs::remove_dir_all(&scratch).unwrap();
}
