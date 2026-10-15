#[path = "../../rampage-api/tests/support/debug_layout_tools.rs"]
#[allow(dead_code)]
mod support;

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use support::{TempFiles, log_bytes, open, wrong_digest};

fn command() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command
        .env_remove("RAMPAGE_PACKS")
        .env_remove("RAMPAGE_MCP_TOOLS")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .write_stdin("");
    command
}

fn import(path: &Path, extra: &[&str]) -> Output {
    command().args(["type", "import-debug-layouts"]).arg(path).args(extra).output().unwrap()
}

fn receipt(output: &Output, success: bool) -> Value {
    assert_eq!(output.status.success(), success, "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.len() <= 60_000);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn apply_digest_and_page_arguments_are_strict_before_any_image_or_sidecar_io() {
    let files = TempFiles::new();
    let path = files.negative();
    let project = open(&path);
    project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
    let before = log_bytes(&path);
    let valid = "a".repeat(64);
    let uppercase = "A".repeat(64);
    for arguments in [
        vec!["--apply"],
        vec!["--review-sha256", &valid],
        vec!["--apply", "--review-sha256", &uppercase],
        vec!["--apply", "--review-sha256", "abc"],
        vec!["--limit", "0"],
        vec!["--limit", "1001"],
        vec!["--offset", "18446744073709551616"],
        vec!["--limit", "18446744073709551616"],
        vec!["--apply", "--review-sha256", &valid, "--confirm"],
        vec!["--arch", "invalid-architecture"],
    ] {
        for image in [&path, &path.with_file_name("missing.elf")] {
            let output = import(image, &arguments);
            assert_eq!(output.status.code(), Some(2), "{arguments:?}: {}", String::from_utf8_lossy(&output.stderr));
            assert!(output.stdout.is_empty());
            assert_eq!(log_bytes(&path), before);
            assert!(!support::sidecar(&path.with_file_name("missing.elf")).exists());
        }
    }
}

#[test]
fn negative_preview_is_read_only_and_wrong_digest_or_missing_image_returns_json_failure_with_nonzero_exit() {
    let files = TempFiles::new();
    let path = files.negative();
    let project = open(&path);
    project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
    let before = log_bytes(&path);
    let preview = receipt(&import(&path, &["--json", "--limit", "1"]), true);
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["approved_total"], 0, "negative fixture must not establish positive layout proof");
    assert_eq!(log_bytes(&path), before);
    let wrong = wrong_digest(preview["review_sha256"].as_str().unwrap());
    for image in [&path, &path.with_file_name("missing.elf")] {
        let output = import(image, &["--json", "--apply", "--review-sha256", &wrong]);
        let rejected = receipt(&output, false);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(rejected["ok"], false);
        assert_eq!(rejected["status"], "rejected");
        assert_eq!(rejected["apply_requested"], true);
        assert_eq!(rejected["whole_apply_succeeded"], false);
        assert_eq!(rejected["applied_total"], 0);
        assert!(rejected["error"].is_string());
        assert!(rejected["error_truncated"].is_boolean());
        assert_eq!(log_bytes(&path), before);
    }
    let human = import(&path, &["--limit", "1"]);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    for phrase in ["preview only", "review_sha256:", "--apply --review-sha256", "same-process only"] {
        assert!(text.contains(phrase), "{phrase}: {text}");
    }
    assert!(open(&path).annotation_list().types.is_empty());
    assert!(open(&path).annotation_list().signatures.is_empty());
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn two_distinct_cli_preview_processes_share_a_hash_then_a_third_process_applies_and_fresh_reopen_has_no_undo() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let files = TempFiles::new();
        let path = files.generated(variant, "flat");
        let project = open(&path);
        project.comment(project.binary.entry.unwrap(), Some("keep analyst comment")).unwrap();
        let expected = support::expected_functions(&project);
        let before = log_bytes(&path);

        let first = receipt(&import(&path, &["--json", "--limit", "1"]), true);
        let second = receipt(&import(&path, &["--json", "--offset", "1", "--limit", "3"]), true);
        assert_eq!(first["review_sha256"], second["review_sha256"]);
        assert_eq!(first["image_sha256"], second["image_sha256"]);
        assert_eq!(first["compiler_spec_sha256"], second["compiler_spec_sha256"]);
        assert_eq!(first["approved_total"], expected.len());
        assert_eq!(first["details"].as_array().unwrap().len(), 1);
        assert_eq!(second["details"][0]["kind"], "field");
        assert_eq!(first["whole_apply_succeeded"], false);
        assert_eq!(second["whole_apply_succeeded"], false);
        assert_eq!(log_bytes(&path), before, "both distinct preview processes leave annotation bytes unchanged");

        let digest = first["review_sha256"].as_str().unwrap();
        let maximum = usize::MAX.to_string();
        let applied = receipt(
            &import(&path, &["--json", "--apply", "--review-sha256", digest, "--offset", &maximum, "--limit", "1"]),
            true,
        );
        assert_eq!(applied["status"], "applied");
        assert_eq!(applied["whole_apply_succeeded"], true);
        assert_eq!(applied["review_sha256"], first["review_sha256"]);
        assert_eq!(applied["applied_total"], expected.len());
        assert_eq!(applied["imported_types_total"], 1);
        assert_eq!(applied["details"], json!([]));
        support::assert_atomic_append(&path, &before, expected.len() + 1, first["image_sha256"].as_str().unwrap());
        let reopened = open(&path);
        support::assert_source_signatures(&reopened);
        let persisted = log_bytes(&path);
        assert!(reopened.undo().unwrap().is_empty(), "CLI exit does not recover same-process undo history");
        assert_eq!(log_bytes(&path), persisted);
        assert_eq!(reopened.comment_at(project.binary.entry.unwrap()).as_deref(), Some("keep analyst comment"));

        let stale = receipt(&import(&path, &["--json", "--apply", "--review-sha256", digest]), false);
        assert_eq!(stale["whole_apply_succeeded"], false);
        assert_eq!(stale["applied_total"], 0);
        assert_eq!(log_bytes(&path), persisted);
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn readable_cli_evidence_names_checked_types_fields_and_functions_with_review_and_paging_controls() {
    let files = TempFiles::new();
    let path = files.generated("dwarf5-o2", "flat");
    let first = import(&path, &["--limit", "2"]);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let text = String::from_utf8(first.stdout).unwrap();
    for phrase in ["review_sha256:", "type debug_layout_", "field debug_layout_", "checked/verified", "more evidence:"]
    {
        assert!(text.contains(phrase), "{phrase}: {text}");
    }
    let offset = (1 + support::oracle()["flat"]["fields"].as_array().unwrap().len()).to_string();
    let functions = import(&path, &["--offset", &offset, "--limit", "1"]);
    assert!(functions.status.success());
    let text = String::from_utf8(functions.stdout).unwrap();
    assert!(text.contains("checked/approved"), "{text}");
    assert!(text.contains("debug_flat_read_"), "{text}");
    assert!(log_bytes(&path).is_empty());
}
