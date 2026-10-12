//! The committed library-identification baseline: a signature database built from the symbolized reference
//! fixture, evaluated against the stripped matched-pair target and its truth (see tools/eval-corpus.sh).
//! `wrong` and `spurious` must stay zero; `correct` must not fall below the floor. Raise a floor only when a
//! measured improvement lands.

use std::path::PathBuf;

use rampage_eval::{Report, Truth, evaluate};
use rampage_loaders::Binary;
use rampage_signatures::SignatureDb;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn measure(arch: &str) -> Report {
    let reference = Binary::open(fixtures().join(format!("bin/eval-ref-{arch}.elf"))).unwrap();
    let target = Binary::open(fixtures().join(format!("bin/eval-target-{arch}.elf"))).unwrap();
    let truth = std::fs::read_to_string(fixtures().join(format!("data/eval-truth-{arch}.json"))).unwrap();
    let truth = Truth::from_json(&truth).unwrap();
    let db = SignatureDb::from_binary(&reference);
    evaluate(&db, &target, &truth).unwrap()
}

fn assert_baseline(arch: &str, floor: usize) {
    let report = measure(arch);
    let detail = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("{arch}: {}", report.summary());
    assert_eq!(report.wrong, 0, "{arch}: wrong names\n{detail}");
    assert_eq!(report.spurious, 0, "{arch}: library names where there is none\n{detail}");
    assert!(report.correct >= floor, "{arch}: correct {} below floor {floor}\n{detail}", report.correct);
}

#[test]
fn x86_64_baseline_holds() {
    assert_baseline("x86_64", 47);
}

#[test]
fn aarch64_baseline_holds() {
    assert_baseline("aarch64", 47);
}
