//! The committed baselines, one per slice of tests/fixtures/data/eval-manifest.json (see tools/eval-corpus.sh).
//! Library identification builds a signature database from the symbolized corpus reference and identifies:
//! - twin: the reference's own stripped twin. Identical bytes, so this is the best case.
//! - cross: a different program linking the same static musl, whose truth holds only the functions the
//!   reference also defines (its own `main` excluded). This is what identification of a real binary looks like.
//!   Its library copies sit at other addresses, so a function whose masked hash still encodes one (absolute
//!   addresses in non-PIE x86 code, the low 12 bits after an AArch64 ADRP) is missed; the gap to the twin is
//!   that cost.
//!
//! `wrong` and `spurious` must stay zero; `correct` must not fall below the floor. Raise a floor only when a
//! measured improvement lands.
//!
//! Function discovery runs on the twin and is scored against its sized function symbols. There `correct` has a
//! floor too, but spurious starts are allowed: unsized code is real code, so they are measured, not gated.

use std::path::PathBuf;

use rampage_eval::{Report, Truth, evaluate, evaluate_discovery};
use rampage_loaders::Binary;
use rampage_signatures::SignatureDb;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn binary(name: &str) -> Binary {
    Binary::open(fixtures().join("bin").join(name)).unwrap()
}

fn truth(name: &str) -> Truth {
    Truth::from_json(&std::fs::read_to_string(fixtures().join("data").join(name)).unwrap()).unwrap()
}

/// `kind` is `twin` or `cross`.
fn libid(kind: &str, arch: &str) -> Report {
    let db = SignatureDb::from_binary(&binary(&format!("eval-ref-{arch}.elf")));
    let target = if kind == "twin" { format!("eval-twin-{arch}.elf") } else { format!("eval-target-{arch}.elf") };
    evaluate(&db, &binary(&target), &truth(&format!("eval-truth-{kind}-{arch}.json"))).unwrap()
}

fn assert_libid(kind: &str, arch: &str, floor: usize) -> Report {
    let report = libid(kind, arch);
    let detail = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("libid-{kind}-{arch}: {}", report.summary());
    assert_eq!(report.wrong, 0, "{arch}: wrong names\n{detail}");
    assert_eq!(report.spurious, 0, "{arch}: library names where there is none\n{detail}");
    assert!(report.correct >= floor, "{arch}: correct {} below floor {floor}\n{detail}", report.correct);
    report
}

#[test]
fn x86_64_twin_baseline_holds() {
    assert_libid("twin", "x86_64", 160);
}

#[test]
fn x86_64_cross_baseline_holds() {
    assert_libid("cross", "x86_64", 58);
}

#[test]
fn aarch64_twin_baseline_holds() {
    assert_libid("twin", "aarch64", 168);
}

#[test]
fn aarch64_cross_baseline_holds() {
    assert_libid("cross", "aarch64", 65);
}

/// Discovery on the stripped twin against its sized function symbols. Only recall is gated: spurious starts
/// are measured (precision, the disagreement set) but tolerated, see `Gate::allow_spurious`.
fn assert_discovery(arch: &str, floor: usize) {
    let target = binary(&format!("eval-twin-{arch}.elf"));
    let report = evaluate_discovery(&target, &truth(&format!("eval-truth-twin-{arch}.json"))).unwrap();
    let detail = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("discovery-{arch}: {}", report.summary());
    assert_eq!(report.wrong, 0);
    assert!(report.correct >= floor, "{arch}: correct {} below floor {floor}\n{detail}", report.correct);
}

/// Measured: 174 of 174, plus 2 spurious starts, `_start` and `__set_thread_area`: assembly without `.size`,
/// real but unsized.
#[test]
fn x86_64_discovery_baseline_holds() {
    assert_discovery("x86_64", 174);
}

/// Measured: 193 of 193, plus 69 spurious starts: the same two unsized assembly functions and 67 interior blocks
/// of `printf_core` (45), `vfscanf` (19), `sysconf`, `pop_arg` and `__strftime_fmt_1` taken for functions.
#[test]
fn aarch64_discovery_baseline_holds() {
    assert_discovery("aarch64", 193);
}
