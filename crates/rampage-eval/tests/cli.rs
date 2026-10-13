use std::path::PathBuf;

use assert_cmd::Command;
use rampage_eval::{Evaluation, Outcome, ToolTruth, Truth};

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

/// The cross-program x86-64 slice, run alone: its report and the number of truth functions.
fn cross_x86_64(extra: &[&str]) -> (std::process::Output, usize) {
    let truth = data("eval-truth-cross-x86_64.json");
    let size = committed("eval-truth-cross-x86_64.json").0.len();
    (run_x86_64(&truth, "eval-target-x86_64.elf", extra), size)
}

#[test]
fn run_prints_the_report_and_a_summary_and_passes_the_gate() {
    let (output, size) = cross_x86_64(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["libid-x86_64"];
    assert!(stderr.contains(&format!("libid-x86_64: {}", report.summary())), "{stderr}");
    assert!(report.correct > 0 && report.correct + report.missed == size, "{}", report.summary());
    assert_eq!((report.wrong, report.spurious), (0, 0));
}

/// The committed manifest is the one place eval baselines live: each slice's recall floor (and, for discovery,
/// whose spurious starts are tolerated, its precision floor). Every slice must meet its floors, and a floor must
/// be ratcheted when a measured improvement lands, so the committed numbers stay the measured ones. Slices are
/// gated on their own, so a change that helps one architecture or target and regresses another is visible.
///
/// libid-twin identifies the corpus reference's own stripped twin: identical bytes, the best case. libid-cross
/// identifies a different program linking the same static musl, scored only on functions the reference defines;
/// it is what identifying a real binary looks like, and functions whose masked hash still encodes a
/// layout-dependent value are its misses. discovery finds the twin's function starts; its spurious starts are
/// unsized assembly the truth leaves out (`_start`, `__set_thread_area`). toolid names the producing tools of
/// every committed fixture with a recorded build; like discovery it tolerates spurious answers and gates precision.
#[test]
fn run_manifest_reports_every_slice_at_its_baseline() {
    let output = eval().arg("run").arg("--manifest").arg(data("eval-manifest.json")).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    for (name, report) in &evaluation.slices {
        let gate = evaluation.gates[name];
        let stale = |measured: f64, floor: f64| measured >= floor + 1e-4;
        assert!(!stale(report.recall, gate.min_recall), "{name}: recall rose to {:.4}; ratchet it", report.recall);
        if gate.allow_spurious {
            let precision = report.precision;
            assert!(!stale(precision, gate.min_precision), "{name}: precision rose to {precision:.4}; ratchet it");
        }
    }
    let names: Vec<&str> = evaluation.slices.keys().map(String::as_str).collect();
    let expected = [
        "discovery-aarch64",
        "discovery-x86_64",
        "libid-cross-aarch64",
        "libid-cross-x86_64",
        "libid-twin-aarch64",
        "libid-twin-x86_64",
        "toolid",
    ];
    assert_eq!(names, expected);
    for (name, gate) in &evaluation.gates {
        assert!(gate.min_recall > 0.0, "{name} has no recall baseline");
        assert_eq!(gate.allow_spurious, name.starts_with("discovery-") || name == "toolid", "{name}");
    }
    assert!(evaluation.passes_gate());
}

/// Discovery needs no database, and its spurious starts do not fail the run; a recall or precision drop does.
#[test]
fn run_discovery_gates_recall_and_precision_not_each_spurious_start() {
    let discovery = |truth: &std::path::Path, extra: &[&str]| {
        eval()
            .args(["run", "--family", "discovery", "--target"])
            .arg(fixture("eval-twin-aarch64.elf"))
            .arg("--truth")
            .arg(truth)
            .args(extra)
            .output()
            .unwrap()
    };
    let output = discovery(&data("eval-truth-twin-aarch64.json"), &["--min-recall", "1.0"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["discovery-aarch64"];
    assert!(report.spurious > 0, "{}", report.summary());
    let spurious = report.disagreements.iter().filter(|entry| entry.outcome == rampage_eval::Outcome::Spurious);
    assert!(spurious.clone().all(|entry| entry.proposed.is_none() && entry.truth.is_none()));
    assert_eq!(spurious.count(), report.spurious);

    let output = discovery(&data("eval-truth-twin-aarch64.json"), &["--min-precision", "1.0"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("below baseline 1.0000") && stderr.contains("FAIL precision "), "{stderr}");

    let scratch = std::env::temp_dir().join(format!("rampage-eval-discovery-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let unreachable = scratch.join("truth.json");
    std::fs::write(&unreachable, "{\"0x10\": \"nowhere\"}").unwrap();
    let output = discovery(&unreachable, &["--min-recall", "0.5"]);
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
    // Every name the real truth scores correct is now a library name where the truth has none.
    let (scored, _) = cross_x86_64(&[]);
    let correct = serde_json::from_slice::<Evaluation>(&scored.stdout).unwrap().slices["libid-x86_64"].correct;
    assert!(stderr.contains(&format!("spurious={correct} ")), "{stderr}");
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
    let (output, _) = cross_x86_64(&["--min-recall", "1.0"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let recall = evaluation.slices["libid-x86_64"].recall;
    assert!(stderr.contains(&format!("libid-x86_64: FAIL recall {recall:.4} below baseline 1.0000")), "{stderr}");
    assert_eq!(evaluation.gates["libid-x86_64"].min_recall, 1.0);
}

/// The counts keep covering every disagreement when the list itself is bounded.
#[test]
fn run_bounds_the_disagreement_list() {
    let (output, _) = cross_x86_64(&["--max-disagreements", "1"]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["libid-x86_64"];
    assert!(report.missed > 1, "{}", report.summary());
    assert_eq!((report.disagreements.len(), report.omitted), (1, report.missed - 1));
}

fn toolid(extra: &[&str]) -> std::process::Output {
    eval()
        .args(["run", "--family", "toolid", "--truth"])
        .arg(data("eval-truth-toolid.json"))
        .args(extra)
        .output()
        .unwrap()
}

fn tool_truth() -> ToolTruth {
    ToolTruth::from_json(&std::fs::read_to_string(data("eval-truth-toolid.json")).unwrap()).unwrap()
}

/// The tool truth's binaries come from the truth file, so the slice needs no target; spurious detections are
/// listed with the evidence that fired and fail the run only through the precision floor.
#[test]
fn run_toolid_scores_every_truth_binary_and_lists_disagreements() {
    let output = toolid(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let evaluation: Evaluation = serde_json::from_slice(&output.stdout).unwrap();
    let report = &evaluation.slices["toolid"];
    assert!(stderr.contains(&format!("toolid: {}", report.summary())), "{stderr}");
    assert!(report.disagreements.is_empty());
    assert_eq!(report.tool_disagreements.len(), report.missed + report.spurious);
    let truth = tool_truth();
    let expected: usize =
        truth.binaries.values().map(|binary| truth.toolchains[&binary.toolchain].expected.len()).sum();
    assert_eq!(report.correct + report.missed, expected);
    assert!(!report.tool_disagreements.iter().any(|entry| entry.binary.contains("hello-go-")), "Go is identified");
    for entry in &report.tool_disagreements {
        match entry.outcome {
            Outcome::Spurious => assert!(!entry.evidence.is_empty(), "{entry:?}"),
            Outcome::Missed => assert!(entry.why.is_some(), "{entry:?}"),
            _ => panic!("{entry:?}"),
        }
    }

    let output = toolid(&["--min-precision", "1.0"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("toolid: FAIL precision ") && !stderr.contains("spurious, "), "{stderr}");
}

#[test]
fn run_toolid_refuses_a_target_and_other_families_need_one() {
    let output = toolid(&["--target", fixture("hello-x64.elf").to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("takes its binaries from its truth"), "{output:?}");
    let truth = data("eval-truth-twin-x86_64.json");
    let output = eval().args(["run", "--family", "discovery", "--truth"]).arg(truth).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("a discovery slice needs a target"), "{output:?}");
}

/// Every committed fixture binary is either scored by the tool truth or excluded with a reason, so a new fixture
/// cannot silently go unmeasured.
#[test]
fn tool_truth_covers_every_committed_fixture() {
    let truth = tool_truth();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Each fixture directory, and how the truth file (in tests/fixtures/data) spells it.
    let directories = [
        ("tests/fixtures/bin", "../bin"),
        ("crates/rampage-api/tests/fixtures", "../../../crates/rampage-api/tests/fixtures"),
    ];
    let mut unknown = Vec::new();
    for (directory, spelled) in directories {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            // The API fixtures' sources and build script sit beside them.
            let source = name.ends_with(".c") || name.ends_with(".sh");
            let path = format!("{spelled}/{name}");
            if !source && !truth.binaries.contains_key(&path) && !truth.excluded.contains_key(&path) {
                unknown.push(path);
            }
        }
    }
    assert!(unknown.is_empty(), "add to eval-truth-toolid.json: {unknown:?}");
    for path in truth.binaries.keys().chain(truth.excluded.keys()) {
        assert!(data(path).exists(), "{path} does not exist");
    }
}
