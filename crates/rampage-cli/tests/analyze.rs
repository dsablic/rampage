use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn workflows_across_universal_slices_share_source_identity_and_keep_slice_hashes() {
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args([
            "--json",
            "analyze",
            "--all-architectures",
            "--workflow",
            "triage-report",
            "--workflow",
            "network-surface",
            "--no-decompile",
            "--limit",
            "2",
        ])
        .arg(fixture("hello-universal.macho"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema"], "rampage-analysis-batch-v1");
    let targets = report["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_ne!(targets[0]["arch"], targets[1]["arch"]);
    assert_ne!(targets[0]["image_sha256"], targets[1]["image_sha256"]);
    assert_eq!(targets[0]["source_sha256"], targets[1]["source_sha256"]);
    assert_eq!(report["completed_tasks"], 4);
    assert_eq!(report["failed_tasks"], 0);
    for task in report["tasks"].as_array().unwrap() {
        assert_eq!(task["status"], "completed");
        assert!(task["result"]["limitations"].is_array());
    }
}

#[test]
fn missing_workers_and_unknown_functions_remain_failed_tasks_without_native_fallback() {
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .env("RAMPAGE_WORKER", "/nonexistent/rampage-worker")
        .args(["--json", "analyze", "--function", "main", "--function", "no_such_function", "--no-decompile"])
        .arg(fixture("hello-x64.elf"))
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["completed_tasks"], 1);
    assert_eq!(report["failed_tasks"], 2);
    let tasks = report["tasks"].as_array().unwrap();
    assert_eq!(tasks[0]["status"], "completed");
    for task in &tasks[1..] {
        assert_eq!(task["status"], "failed");
        assert!(task["result"].is_null());
        assert!(!task["error"].as_str().unwrap().is_empty());
    }
    assert!(tasks[1]["error"].as_str().unwrap().contains("worker"));
}

#[test]
fn incompatible_selectors_and_unbounded_function_requests_are_rejected() {
    for args in [
        vec!["--arch", "aarch64", "analyze", "--all-architectures"],
        vec!["analyze", "--workflow", "diff-builds"],
        vec!["analyze", "--other", "missing"],
        vec!["analyze", "--decompile-timeout-ms", "0"],
    ] {
        Command::cargo_bin("rampage").unwrap().args(args).arg(fixture("hello-x64.elf")).assert().failure();
    }
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.arg("analyze").arg(fixture("hello-x64.elf"));
    for _ in 0..17 {
        command.args(["--function", "main"]);
    }
    command.assert().failure();
}

#[test]
fn architecture_conflicts_have_parse_errors_at_every_command_depth() {
    for args in [
        vec!["--arch", "x86_64", "analyze", "missing", "--all-architectures"],
        vec!["binary", "--arch", "x86_64", "analyze", "missing", "--all-architectures"],
        vec!["binary", "analyze", "missing", "--all-architectures", "--arch", "x86_64"],
    ] {
        Command::cargo_bin("rampage").unwrap().args(args).assert().code(2);
    }
}

#[test]
fn diff_builds_runs_in_a_batch_only_with_explicit_second_input() {
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "analyze", "--workflow", "diff-builds"])
        .arg(fixture("hello-x64.elf"))
        .arg("--other")
        .arg(fixture("hello-x64.elf"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["completed_tasks"], 1);
    assert_eq!(report["tasks"][0]["result"]["workflow"], "diff_builds");
    assert_eq!(report["tasks"][0]["result"]["target"]["sha256"], report["tasks"][0]["result"]["other"]["sha256"]);
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rampage-analyze-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    Scratch(path)
}

#[test]
fn a_broken_preferred_slice_does_not_hide_other_architecture_results() {
    let scratch = scratch();
    let mut bytes = std::fs::read(fixture("hello-universal.macho")).unwrap();
    assert_eq!(&bytes[..4], &0xcafe_babeu32.to_be_bytes());
    let count = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let entry = (0..count as usize)
        .map(|index| 8 + index * 20)
        .find(|&entry| u32::from_be_bytes(bytes[entry..entry + 4].try_into().unwrap()) == 0x0100_0007)
        .unwrap();
    let offset = u32::from_be_bytes(bytes[entry + 8..entry + 12].try_into().unwrap()) as usize;
    bytes[offset..offset + 4].fill(0);
    let path = scratch.0.join("broken-preferred.macho");
    std::fs::write(&path, bytes).unwrap();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "analyze", "--all-architectures", "--no-decompile"])
        .arg(path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["completed_tasks"], 1);
    assert_eq!(report["failed_tasks"], 1);
    let tasks = report["tasks"].as_array().unwrap();
    assert!(tasks.iter().any(|task| task["arch"] == "x86_64" && task["status"] == "failed"));
    assert!(tasks.iter().any(|task| task["arch"] == "aarch64" && task["status"] == "completed"));
}

#[test]
fn text_workflow_reports_show_failed_previews_instead_of_just_completion() {
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .env("RAMPAGE_WORKER", "/nonexistent/rampage-worker")
        .args(["analyze", "--workflow", "find-main"])
        .arg(fixture("hello-x64.elf"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("decompilation failed"), "{text}");
    assert!(text.contains("worker"), "{text}");
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_input_paths_work_in_text_and_have_an_explicit_lossy_json_label() {
    use std::os::unix::ffi::OsStringExt;
    let scratch = scratch();
    let path = scratch.0.join(std::ffi::OsString::from_vec(b"fixture-\xff.elf".to_vec()));
    std::fs::copy(fixture("hello-x64.elf"), &path).unwrap();
    Command::cargo_bin("rampage").unwrap().args(["analyze", "--no-decompile"]).arg(&path).assert().success();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "analyze", "--no-decompile"])
        .arg(path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["file_display_lossy"], true);
    assert_eq!(report["completed_tasks"], 1);
}
