use std::path::PathBuf;

use assert_cmd::Command;
use rampage_eval::{Evaluation, Truth};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn eval() -> Command {
    Command::cargo_bin("rampage-eval").unwrap()
}

#[test]
fn truth_prints_the_symbol_table_as_json() {
    let output = eval().arg("truth").arg(fixture("hello-x64.elf")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let truth = Truth::from_json(&String::from_utf8(output.stdout).unwrap()).unwrap();
    assert!(truth.0.values().any(|name| name == "main"));
}

#[test]
fn truth_rejects_a_stripped_twin_with_different_code() {
    let output = eval()
        .arg("truth")
        .arg(fixture("hello-x64.elf"))
        .arg("--stripped")
        .arg(fixture("musl-static-x86_64.elf"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a twin"), "{output:?}");
}

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/data").join(name)
}

fn run_x86_64(truth: &std::path::Path, target: &str, extra: &[&str]) -> std::process::Output {
    eval()
        .args(["run", "--ref"])
        .arg(fixture("eval-ref-x86_64.elf"))
        .arg("--target")
        .arg(fixture(target))
        .arg("--truth")
        .arg(truth)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn run_prints_the_report_and_a_summary_and_passes_the_gate() {
    let output = run_x86_64(&data("eval-truth-cross-x86_64.json"), "eval-target-x86_64.elf", &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("libid-x86_64: correct=58 wrong=0 missed=5 spurious=0"), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["libid-x86_64"];
    assert_eq!((report.correct, report.wrong, report.spurious), (58, 0, 0));
}

/// The committed manifest names every slice; the gate reads each slice on its own, so a change that helps one
/// architecture or target and regresses another is visible.
#[test]
fn run_manifest_reports_every_slice() {
    let output = eval().arg("run").arg("--manifest").arg(data("eval-manifest.json")).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    for line in [
        "libid-twin-x86_64: correct=160 wrong=0 missed=14 spurious=0",
        "libid-cross-x86_64: correct=58 wrong=0 missed=5 spurious=0",
        "libid-twin-aarch64: correct=168 wrong=0 missed=25 spurious=0",
        "libid-cross-aarch64: correct=66 wrong=0 missed=13 spurious=0",
        "discovery-x86_64: correct=174 wrong=0 missed=0 spurious=2",
        "discovery-aarch64: correct=193 wrong=0 missed=0 spurious=69",
    ] {
        assert!(stderr.contains(line), "{line} not in {stderr}");
    }
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let names: Vec<&str> = evaluation.slices.keys().map(String::as_str).collect();
    let expected = [
        "discovery-aarch64",
        "discovery-x86_64",
        "libid-cross-aarch64",
        "libid-cross-x86_64",
        "libid-twin-aarch64",
        "libid-twin-x86_64",
    ];
    assert_eq!(names, expected);
    for (name, gate) in &evaluation.gates {
        assert!(gate.min_recall > 0.0, "{name} has no recall baseline");
        assert_eq!(gate.allow_spurious, name.starts_with("discovery-"), "{name}");
    }
    assert!(evaluation.passes_gate());
}

/// Discovery needs no database, and its spurious starts do not fail the run; a recall drop does.
#[test]
fn run_discovery_gates_recall_not_spurious_starts() {
    let discovery = |truth: &std::path::Path, min_recall: &str| {
        eval()
            .args(["run", "--family", "discovery", "--min-recall", min_recall, "--target"])
            .arg(fixture("eval-twin-aarch64.elf"))
            .arg("--truth")
            .arg(truth)
            .output()
            .unwrap()
    };
    let output = discovery(&data("eval-truth-twin-aarch64.json"), "1.0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("discovery-aarch64: correct=193 wrong=0 missed=0 spurious=69"), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["discovery-aarch64"];
    let spurious = report.disagreements.iter().filter(|entry| entry.outcome == rampage_eval::Outcome::Spurious);
    assert!(spurious.clone().all(|entry| entry.proposed.is_none() && entry.truth.is_none()));
    assert_eq!(spurious.count(), 69);

    let scratch = std::env::temp_dir().join(format!("rampage-eval-discovery-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let unreachable = scratch.join("truth.json");
    std::fs::write(&unreachable, "{\"0x10\": \"nowhere\"}").unwrap();
    let output = discovery(&unreachable, "0.5");
    std::fs::remove_dir_all(&scratch).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("discovery-aarch64: FAIL recall 0.0000 below baseline 0.5000"), "{stderr}");
    assert!(!stderr.contains("spurious, "), "{stderr}");
}

fn truth_output(args: &[PathBuf]) -> Truth {
    let output = eval().arg("truth").args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Truth::from_json(&String::from_utf8(output.stdout).unwrap()).unwrap()
}

fn committed(name: &str) -> Truth {
    Truth::from_json(&std::fs::read_to_string(data(name)).unwrap()).unwrap()
}

/// The committed truths are what `rampage-eval truth` derives from the committed binaries, twin checks included.
#[test]
fn committed_truths_are_reproducible() {
    for arch in ["x86_64", "aarch64"] {
        let reference = fixture(&format!("eval-ref-{arch}.elf"));
        let twin = truth_output(&[reference.clone(), "--stripped".into(), fixture(&format!("eval-twin-{arch}.elf"))]);
        assert_eq!(twin, committed(&format!("eval-truth-twin-{arch}.json")), "{arch}");

        let cross = truth_output(&[
            fixture(&format!("eval-target-sym-{arch}.elf")),
            "--stripped".into(),
            fixture(&format!("eval-target-{arch}.elf")),
            "--library".into(),
            reference,
            "--program".into(),
            fixture(&format!("eval-program-corpus-{arch}.o")),
            "--program".into(),
            fixture(&format!("eval-program-target-{arch}.o")),
        ]);
        assert_eq!(cross, committed(&format!("eval-truth-cross-{arch}.json")), "{arch}");
    }
}

/// Every program defines `main`, so the name filter alone keeps it; the program objects drop it.
#[test]
fn cross_truth_excludes_the_programs_own_functions() {
    let symbolized = fixture("eval-target-sym-x86_64.elf");
    let library = [symbolized.clone(), "--library".into(), fixture("eval-ref-x86_64.elf")];
    let by_name = truth_output(&library);
    assert!(by_name.0.values().any(|name| name == "main"));
    let program = [library.as_slice(), &["--program".into(), fixture("eval-program-target-x86_64.o")]].concat();
    let identifiable = truth_output(&program);
    assert!(!identifiable.0.values().any(|name| name == "main"));
    assert_eq!(identifiable.0.len(), by_name.0.len() - 1);
    // printf is in the target but the corpus reference only calls fprintf and snprintf.
    let everything = truth_output(&[symbolized]);
    assert!(everything.0.values().any(|name| name == "printf"));
    assert!(!identifiable.0.values().any(|name| name == "printf"));
}

#[test]
fn run_exits_one_when_a_name_is_spurious() {
    let scratch = std::env::temp_dir().join(format!("rampage-eval-cli-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let empty = scratch.join("empty-truth.json");
    std::fs::write(&empty, "{}").unwrap();
    let output = run_x86_64(&empty, "eval-target-x86_64.elf", &[]);
    std::fs::remove_dir_all(&scratch).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("spurious=58"), "{stderr}");
}

#[test]
fn run_refuses_a_database_for_another_architecture() {
    let output = run_x86_64(&data("eval-truth-cross-x86_64.json"), "musl-static-aarch64.elf", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("architecture"), "{output:?}");
}

#[test]
fn run_refuses_a_reference_for_another_architecture() {
    let output = run_x86_64(
        &data("eval-truth-cross-x86_64.json"),
        "eval-target-x86_64.elf",
        &["--ref", fixture("eval-ref-aarch64.elf").to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("a aarch64 reference cannot be combined with a x86_64 database"), "{stderr}");
}

#[test]
fn run_refuses_an_unknown_hash_scheme() {
    let scratch = std::env::temp_dir().join(format!("rampage-eval-scheme-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let future = scratch.join("future.json");
    std::fs::write(&future, r#"{"arch":"x86_64","scheme":3,"entries":{}}"#).unwrap();
    let output = eval()
        .args(["run", "--db"])
        .arg(&future)
        .arg("--target")
        .arg(fixture("eval-target-x86_64.elf"))
        .arg("--truth")
        .arg(data("eval-truth-cross-x86_64.json"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(&scratch).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("unknown signature hash scheme 3"), "{stderr}");
}

#[test]
fn run_fails_a_slice_below_its_recall_baseline() {
    let output = run_x86_64(&data("eval-truth-cross-x86_64.json"), "eval-target-x86_64.elf", &["--min-recall", "0.95"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("libid-x86_64: FAIL recall 0.9206 below baseline 0.9500"), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(evaluation.gates["libid-x86_64"].min_recall, 0.95);
}

/// The counts keep covering every disagreement when the list itself is bounded.
#[test]
fn run_bounds_the_disagreement_list() {
    let output =
        run_x86_64(&data("eval-truth-cross-x86_64.json"), "eval-target-x86_64.elf", &["--max-disagreements", "3"]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["libid-x86_64"];
    assert_eq!((report.disagreements.len(), report.omitted, report.missed), (3, 2, 5));
}
