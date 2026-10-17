use std::path::Path;

use rampage_eval::parity_tasks::{
    CapabilityStatus, ParityTask, TaskAttempt, TaskKind, TaskOutcome, parse_task_documents,
};
use serde_json::json;

const ARITHMETIC: &str = include_str!("../tasks/arithmetic-arm64-elf.toml");
const CLASSES: &str = include_str!("../tasks/cpp-class-names-arm64-macho.toml");
const UNSUPPORTED: &str = include_str!("../tasks/capability-patch-export.toml");

#[test]
fn malformed_toml_is_an_error_with_its_origin() {
    let error = parse_task_documents([("broken.toml", "version = [")]).unwrap_err();
    assert_eq!(error.path, Path::new("broken.toml"));
    assert!(!error.message.is_empty());
}

#[test]
fn duplicate_ids_are_rejected_across_documents() {
    let error = parse_task_documents([("first.toml", ARITHMETIC), ("second.toml", ARITHMETIC)]).unwrap_err();
    assert_eq!(error.path, Path::new("second.toml"));
    assert!(error.message.contains("duplicate task id"), "{error}");
}

#[test]
fn unknown_contracts_and_unknown_manifest_fields_are_rejected() {
    for text in [
        ARITHMETIC.replace("kind = \"exact\"", "kind = \"run_script\""),
        ARITHMETIC.replace("version = 1", "version = 1\nunexpected = true"),
        ARITHMETIC.replace("kind = \"exact\"", "kind = \"exact\"\nscript = \"echo 18\""),
    ] {
        assert!(ParityTask::from_toml(&text).is_err(), "accepted unknown schema: {text}");
    }
}

#[test]
fn invalid_versions_ids_paths_digests_and_requirements_are_rejected() {
    for text in [
        ARITHMETIC.replace("version = 1", "version = 2"),
        ARITHMETIC.replace("id = \"arithmetic-arm64-elf\"", "id = \"Not an ID\""),
        ARITHMETIC.replace("tests/fixtures/bin/hello-arm64.elf", "../hello-arm64.elf"),
        ARITHMETIC.replace("tests/fixtures/bin/hello-arm64.elf", "/hello-arm64.elf"),
        ARITHMETIC.replace("b47331c6", "B47331c6"),
        ARITHMETIC.replace("required_capabilities = [\"disassemble\"]", "required_capabilities = []"),
        ARITHMETIC.replace(
            "required_capabilities = [\"disassemble\"]",
            "required_capabilities = [\"disassemble\", \"disassemble\"]",
        ),
    ] {
        assert!(ParityTask::from_toml(&text).is_err(), "accepted invalid manifest: {text}");
    }
}

#[test]
fn missing_contract_and_blank_question_are_rejected() {
    let before_answer = ARITHMETIC.split("[answer]").next().unwrap();
    assert!(ParityTask::from_toml(before_answer).is_err());
    let mut task = ParityTask::from_toml(ARITHMETIC).unwrap();
    task.question = " \n\t ".to_owned();
    assert!(task.validate().is_err());
}

#[test]
fn empty_or_duplicate_expected_sets_are_rejected() {
    for text in [
        CLASSES.replace("[\"Circle\", \"Printable\", \"Shape\", \"Square\"]", "[]"),
        CLASSES.replace("[\"Circle\", \"Printable\", \"Shape\", \"Square\"]", "[\"Circle\", \"Circle\"]"),
    ] {
        assert!(ParityTask::from_toml(&text).is_err());
    }
}

#[test]
fn one_fixture_id_cannot_silently_refer_to_different_bytes() {
    let conflicting =
        ARITHMETIC.replace("id = \"arithmetic-arm64-elf\"", "id = \"another-task\"").replace("b47331c6", "a47331c6");
    let error = parse_task_documents([("first.toml", ARITHMETIC), ("second.toml", &conflicting)]).unwrap_err();
    assert!(error.message.contains("conflicting fixture identity"), "{error}");
}

#[test]
fn one_fixture_path_cannot_silently_acquire_a_second_identity() {
    let conflicting = ARITHMETIC
        .replace("id = \"arithmetic-arm64-elf\"", "id = \"another-task\"")
        .replace("id = \"hello-arm64-elf\"", "id = \"another-fixture\"");
    let error = parse_task_documents([("first.toml", ARITHMETIC), ("second.toml", &conflicting)]).unwrap_err();
    assert!(error.message.contains("conflicting fixture path"), "{error}");
}

#[test]
fn exact_answers_reject_wrong_types_partial_answers_and_extra_claims() {
    let task = ParityTask::from_toml(ARITHMETIC).unwrap();
    assert_eq!(task.check(&TaskAttempt::Answer(json!({"return_value": 18}))).outcome, TaskOutcome::AnswerMatches);
    for answer in [
        json!({"return_value": 19}),
        json!({"return_value": "18"}),
        json!({"return_value": null}),
        json!({"return_value": 18, "guess": true}),
        json!({}),
        json!([18]),
        json!("It returns 18, or perhaps 19"),
    ] {
        assert_eq!(task.check(&TaskAttempt::Answer(answer)).outcome, TaskOutcome::AnswerMismatch);
    }
}

#[test]
fn sets_ignore_order_but_reject_omissions_duplicates_and_non_strings() {
    let task = ParityTask::from_toml(CLASSES).unwrap();
    let correct = json!({"classes": ["Square", "Shape", "Printable", "Circle"]});
    assert_eq!(task.check(&TaskAttempt::Answer(correct)).outcome, TaskOutcome::AnswerMatches);
    for answer in [
        json!({"classes": ["Shape", "Printable", "Circle"]}),
        json!({"classes": ["Shape", "Printable", "Circle", "Triangle"]}),
        json!({"classes": ["Square", "Shape", "Printable", "Circle", "Circle"]}),
        json!({"classes": ["Square", "Shape", "Printable", 42]}),
        json!({"classes": ["Square", "Shape", "Printable", "Circle"], "other": []}),
        json!({"classes": "Square Shape Printable Circle"}),
    ] {
        assert_eq!(task.check(&TaskAttempt::Answer(answer)).outcome, TaskOutcome::AnswerMismatch);
    }
}

#[test]
fn unmeasured_unknown_unsupported_and_failed_never_become_matching_answers() {
    let task = ParityTask::from_toml(ARITHMETIC).unwrap();
    let cases = [
        (TaskAttempt::Unmeasured, TaskOutcome::Unmeasured),
        (TaskAttempt::Unknown { reason: "insufficient evidence".into() }, TaskOutcome::Unknown),
        (TaskAttempt::Unsupported { reason: "missing MCP capability".into() }, TaskOutcome::Unsupported),
        (TaskAttempt::Failed { reason: "tool request timed out".into() }, TaskOutcome::Failed),
    ];
    for (attempt, expected) in cases {
        let check = task.check(&attempt);
        assert_eq!(check.outcome, expected);
        assert_eq!(check.task_id, task.id);
        assert!(!check.reason.is_empty());
    }
}

#[test]
fn capability_probe_answers_are_checked_independently_of_inventory() {
    let mut task = ParityTask::from_toml(UNSUPPORTED).unwrap();
    for status in [CapabilityStatus::Unsupported, CapabilityStatus::Unknown, CapabilityStatus::Supported] {
        task.capability_status = status;
        let correct = task.check(&TaskAttempt::Answer(json!({"available": false})));
        assert_eq!(correct.outcome, TaskOutcome::AnswerMatches, "inventory: {status:?}");
        assert_eq!(correct.kind, TaskKind::Capability);
        let wrong = task.check(&TaskAttempt::Answer(json!({"available": true})));
        assert_eq!(wrong.outcome, TaskOutcome::AnswerMismatch, "inventory: {status:?}");
        assert_eq!(wrong.kind, TaskKind::Capability);
        assert_eq!(task.capability_status, status);
    }
}

#[test]
fn unknown_inventory_does_not_prevent_checking_an_analysis_answer() {
    let mut task = ParityTask::from_toml(ARITHMETIC).unwrap();
    task.capability_status = CapabilityStatus::Unknown;
    assert_eq!(task.check(&TaskAttempt::Answer(json!({"return_value": 18}))).outcome, TaskOutcome::AnswerMatches);
    assert_eq!(task.check(&TaskAttempt::Answer(json!({"return_value": 19}))).outcome, TaskOutcome::AnswerMismatch);
}

#[test]
fn prompt_exposes_the_question_and_opened_path_but_not_truth() {
    let task = ParityTask::from_toml(CLASSES).unwrap();
    let prompt = task.agent_prompt(Path::new("/isolated/input image"));
    assert!(prompt.contains("/isolated/input image"));
    assert!(prompt.contains(task.question.trim()));
    for secret in ["Circle", "Square", "Printable", "Shape", "classes.cpp", &task.fixture.sha256] {
        assert!(!prompt.contains(secret), "prompt leaked {secret}");
    }
    assert!(!prompt.contains(&task.truth_reference));
}

#[test]
fn fixture_digest_comparison_cannot_accept_a_different_artifact() {
    let task = ParityTask::from_toml(ARITHMETIC).unwrap();
    assert!(task.matches_fixture_digest("b47331c6dc05c7eee4e90021a3433e36a3b7d3c212823677cbb8522b3fd07725"));
    assert!(!task.matches_fixture_digest("d13dbc8113fd99bb5a6bfa8413892b6937232ba25e1ef06c41d55a2126b0b987"));
    assert!(!task.matches_fixture_digest(""));
}

#[test]
fn empty_suites_are_errors_instead_of_vacuous_passes() {
    assert!(parse_task_documents(Vec::<(&str, &str)>::new()).is_err());
}

#[test]
fn owned_suite_parses_atomically_and_sorts_without_marking_any_task_measured() {
    let documents = [
        ("format-x64-elf.toml", include_str!("../tasks/format-x64-elf.toml")),
        ("format-arm64-elf.toml", include_str!("../tasks/format-arm64-elf.toml")),
        ("format-arm64-macho.toml", include_str!("../tasks/format-arm64-macho.toml")),
        ("format-x64-pe.toml", include_str!("../tasks/format-x64-pe.toml")),
        ("format-thumb-elf.toml", include_str!("../tasks/format-thumb-elf.toml")),
        ("format-mips-be-elf.toml", include_str!("../tasks/format-mips-be-elf.toml")),
        ("greeting-x64-elf.toml", include_str!("../tasks/greeting-x64-elf.toml")),
        ("greeting-x64-pe.toml", include_str!("../tasks/greeting-x64-pe.toml")),
        ("main-return-x64-elf.toml", include_str!("../tasks/main-return-x64-elf.toml")),
        ("main-return-arm64-macho.toml", include_str!("../tasks/main-return-arm64-macho.toml")),
        ("arithmetic-arm64-elf.toml", ARITHMETIC),
        ("helper-arithmetic-x64-elf.toml", include_str!("../tasks/helper-arithmetic-x64-elf.toml")),
        ("helper-plt-result-x64-elf.toml", include_str!("../tasks/helper-plt-result-x64-elf.toml")),
        ("cpp-class-names-arm64-macho.toml", CLASSES),
        (
            "cpp-multiple-inheritance-arm64-macho.toml",
            include_str!("../tasks/cpp-multiple-inheritance-arm64-macho.toml"),
        ),
        ("go-package-functions-x64-elf.toml", include_str!("../tasks/go-package-functions-x64-elf.toml")),
        ("objc-superclasses-arm64-macho.toml", include_str!("../tasks/objc-superclasses-arm64-macho.toml")),
        ("capability-decompile.toml", include_str!("../tasks/capability-decompile.toml")),
        ("capability-local-variable-rename.toml", include_str!("../tasks/capability-local-variable-rename.toml")),
        ("capability-patch-export.toml", include_str!("../tasks/capability-patch-export.toml")),
    ];
    let tasks = parse_task_documents(documents).unwrap();
    assert!(tasks.windows(2).all(|pair| pair[0].id < pair[1].id));
    assert!(tasks.iter().any(|task| task.kind == TaskKind::Analysis));
    assert!(tasks.iter().any(|task| task.kind == TaskKind::Capability));
    for task in tasks {
        assert_eq!(task.check(&TaskAttempt::Unmeasured).outcome, TaskOutcome::Unmeasured);
    }
}
