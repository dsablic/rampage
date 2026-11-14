//! lock_mechanisms on owned fixtures built from tests/fixtures/firmware/locks: a Cortex-M3 firmware for the
//! synthetic device of tests/fixtures/svd/lock-device.svd and an x86-64 Linux program. The truth file
//! (tests/fixtures/firmware/locks/truth.json) names, per fixture, the function whose code decides each mechanism
//! and the negative controls; precision and recall are measured per category against it. Ordinary programs among
//! the repository's fixtures must report no mechanism.

use std::collections::BTreeMap;

use rampage_api::{ImportSvdRequest, LockQuery, LockReport, Project};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};
use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/");

fn firmware(svd: bool) -> Project {
    let image = std::fs::read(format!("{FIXTURES}firmware/raw-cortex-m-locks.bin")).unwrap();
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    let project = Project::new(Binary::from_raw_code(image, options).unwrap());
    if svd {
        let request = ImportSvdRequest { svd: format!("{FIXTURES}svd/lock-device.svd").into(), apply: true };
        project.import_svd(&request).unwrap();
    }
    project
}

fn report(project: &Project) -> LockReport {
    project.lock_mechanisms(&LockQuery { category: None, offset: 0, limit: 50 }).unwrap()
}

/// Function name to its address range, from a symbol-carrying build.
fn ranges(symbols: &str) -> BTreeMap<String, (u64, u64)> {
    let binary = Binary::open(format!("{FIXTURES}firmware/{symbols}")).unwrap();
    binary
        .symbols
        .iter()
        .filter(|symbol| symbol.size > 0)
        .map(|symbol| (symbol.name.clone(), (symbol.address & !1, (symbol.address & !1) + symbol.size)))
        .collect()
}

fn inside(ranges: &BTreeMap<String, (u64, u64)>, function: &str, at: u64) -> bool {
    let (start, end) = ranges[function];
    (start..end).contains(&at)
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// Every address a mechanism decides at: its decision and its inner decisions.
fn decision_sites(mechanism: &Value) -> Vec<u64> {
    let mut sites: Vec<u64> =
        mechanism["decision"]["at"].as_str().map(|_| hex(&mechanism["decision"]["at"])).into_iter().collect();
    for related in mechanism["related"].as_array().unwrap() {
        if matches!(related["role"].as_str(), Some("inner_decision" | "decision" | "configures")) {
            sites.push(hex(&related["at"]));
        }
    }
    sites
}

#[derive(Default, Debug)]
struct Score {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
}

/// Scores `report` against one fixture's truth, per category; asserts the negative controls and not-locks.
fn score(report: &LockReport, truth: &Value, scores: &mut BTreeMap<String, Score>) {
    let ranges = ranges(truth["symbols"].as_str().unwrap());
    let report = serde_json::to_value(report).unwrap();
    let mechanisms = report["mechanisms"].as_array().unwrap();
    let expected = truth["mechanisms"].as_array().unwrap();
    let mut matched = vec![false; mechanisms.len()];
    for want in expected {
        let category = want["category"].as_str().unwrap();
        let function = want["function"].as_str().unwrap();
        let found = mechanisms.iter().enumerate().position(|(index, mechanism)| {
            !matched[index]
                && mechanism["category"] == category
                && decision_sites(mechanism).iter().any(|&at| inside(&ranges, function, at))
        });
        let entry = scores.entry(category.to_owned()).or_default();
        match found {
            Some(index) => {
                matched[index] = true;
                entry.true_positives += 1;
                if let Some(failure) = want["failure"].as_str() {
                    let mechanism = &mechanisms[index];
                    let path = mechanism["failure_path"].as_str().unwrap();
                    let outcome =
                        mechanism["outcomes"].as_array().unwrap().iter().find(|outcome| outcome["path"] == path);
                    assert_eq!(
                        outcome.map(|outcome| outcome["effect"].as_str().unwrap()),
                        Some(failure),
                        "{category} in {function}: {mechanism:#}"
                    );
                }
            }
            None => {
                entry.false_negatives += 1;
                eprintln!("missed {category} in {function}");
            }
        }
    }
    for (index, mechanism) in mechanisms.iter().enumerate() {
        if !matched[index] {
            scores.entry(mechanism["category"].as_str().unwrap().to_owned()).or_default().false_positives += 1;
            eprintln!("unexpected: {mechanism:#}");
        }
        for negative in truth["negatives"].as_array().unwrap() {
            let negative = negative.as_str().unwrap();
            assert!(
                !decision_sites(mechanism).iter().any(|&at| inside(&ranges, negative, at)),
                "negative control {negative} reported as a lock: {mechanism:#}"
            );
        }
    }
    let not_locks = report["not_locks"].as_array().unwrap();
    for want in truth["not_locks"].as_array().unwrap() {
        let function = want["function"].as_str().unwrap();
        assert!(
            not_locks.iter().any(|row| row["kind"] == want["kind"] && inside(&ranges, function, hex(&row["at"]))),
            "{want} not among {not_locks:#?}"
        );
    }
}

#[test]
fn fixtures_score_full_precision_and_recall_per_category() {
    let truth: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURES}firmware/locks/truth.json")).unwrap())
            .unwrap();
    let mut scores: BTreeMap<String, Score> = BTreeMap::new();
    for fixture in truth["fixtures"].as_array().unwrap() {
        let project = if fixture["svd"].is_string() {
            firmware(true)
        } else {
            Project::new(Binary::open(format!("{FIXTURES}firmware/{}", fixture["image"].as_str().unwrap())).unwrap())
        };
        let report = report(&project);
        assert!(report.supported && !report.coverage.incomplete, "{:?}", report.coverage);
        score(&report, fixture, &mut scores);
    }
    for (category, score) in &scores {
        let precision = score.true_positives as f64 / (score.true_positives + score.false_positives).max(1) as f64;
        let recall = score.true_positives as f64 / (score.true_positives + score.false_negatives).max(1) as f64;
        eprintln!("{category}: precision {precision:.2}, recall {recall:.2} ({score:?})");
        assert_eq!((score.false_positives, score.false_negatives), (0, 0), "{category}: {score:?}");
    }
    assert_eq!(scores.len(), 6, "{scores:?}");
}

#[test]
fn explanations_name_what_is_checked_and_where_it_fails() {
    let project = firmware(true);
    let report = report(&project);
    let ranges = ranges("raw-cortex-m-locks.elf");
    let signature = report.mechanisms.iter().find(|mechanism| mechanism.category == "signature_verification").unwrap();
    let json = serde_json::to_value(signature).unwrap();
    assert_eq!(signature.confidence, "high", "{json:#}");
    assert!(signature.summary.contains("P-256"), "{json:#}");
    assert!(signature.consults.iter().any(|row| row.kind == "public_key_algorithm" && row.name == "P-256"));
    assert!(signature.consults.iter().any(|row| row.kind == "digest_algorithm" && row.name == "SHA-256"));
    // The key the verifier receives is pointed at by address, never read out.
    let key = ranges["test_p256_public_key"].0;
    assert!(signature.consults.iter().any(|row| row.kind == "constant_data" && row.at == Some(key)), "{json:#}");
    assert!(
        signature
            .related
            .iter()
            .any(|row| row.role == "inner_decision" && inside(&ranges, "verify_application", row.at))
    );
    // The challenge-response unlock sets a flag another function tests.
    let unlock = report.mechanisms.iter().find(|mechanism| mechanism.category == "challenge_response").unwrap();
    let json = serde_json::to_value(unlock).unwrap();
    assert!(unlock.consults.iter().any(|row| row.kind == "random" && row.name == "RNG.DR"), "{json:#}");
    assert!(unlock.consults.iter().any(|row| row.kind == "mac_algorithm" && row.name.starts_with("HMAC")), "{json:#}");
    assert!(unlock.outcomes.iter().any(|outcome| outcome.effect == "writes"), "{json:#}");
    assert!(unlock.related.iter().any(|row| row.role == "flag_consumer"), "{json:#}");
    // No suggestion to patch anything, anywhere.
    let text = serde_json::to_string(&report).unwrap().to_lowercase();
    for word in ["patch", "bypass", "nop", "disable the"] {
        assert!(!text.contains(word), "{word:?} in the report");
    }
}

#[test]
fn without_an_svd_register_roles_are_unknown() {
    let report = report(&firmware(false));
    let categories: Vec<&str> = report.mechanisms.iter().map(|mechanism| mechanism.category).collect();
    assert!(categories.contains(&"signature_verification"), "{categories:?}");
    assert!(
        categories.contains(&"debug_lock"),
        "the architectural debug status is named without a map: {categories:?}"
    );
    for unknown in ["device_binding", "anti_rollback", "feature_lock", "challenge_response"] {
        assert!(!categories.contains(&unknown), "{unknown} without register names: {categories:?}");
    }
    assert!(report.limitations.iter().any(|text| text.contains("import_svd")), "{:?}", report.limitations);
}

#[test]
fn categories_filter_and_pages() {
    let project = firmware(true);
    let all = report(&project);
    let page = project.lock_mechanisms(&LockQuery { category: None, offset: 1, limit: 2 }).unwrap();
    assert_eq!((page.total, page.mechanisms.len(), page.next_offset), (all.total, 2, Some(3)));
    assert_eq!(page.mechanisms[0].summary, all.mechanisms[1].summary);
    let filtered =
        project.lock_mechanisms(&LockQuery { category: Some("feature_lock".into()), offset: 0, limit: 0 }).unwrap();
    assert_eq!(filtered.total, 2);
    assert!(filtered.mechanisms.iter().all(|mechanism| mechanism.category == "feature_lock"));
    let error = project.lock_mechanisms(&LockQuery { category: Some("drm".into()), offset: 0, limit: 0 }).unwrap_err();
    assert!(error.to_string().contains("signature_verification"), "{error}");
}

#[test]
fn ordinary_programs_report_no_locks() {
    let bin = format!("{FIXTURES}bin/");
    let mut checked = 0;
    for name in [
        "hello-x64.elf",
        "hello-x64-dyn.elf",
        "hello-arm.elf",
        "hello-thumb.elf",
        "hello-arm64.elf",
        "hello-x64.exe",
        "hello-x64.macho",
        "hello-arm64.macho",
        "musl-static-x86_64.elf",
        "musl-static-aarch64.elf",
        "debug-x64.elf",
        "libhelper-x64.so",
        "eval-target-x86_64.elf",
        "eval-target-aarch64.elf",
        "hello-go-x64.elf",
    ] {
        let project = Project::new(Binary::open(format!("{bin}{name}")).unwrap());
        let report = report(&project);
        assert_eq!(report.total, 0, "{name}: {:#?}", report.mechanisms);
        checked += 1;
    }
    for firmware in ["raw-cortex-m-crc", "raw-cortex-m-svd", "embedded-libs-m4f", "embedded-libs-m0"] {
        let project = Project::new(Binary::open(format!("{FIXTURES}firmware/{firmware}.elf")).unwrap());
        let report = report(&project);
        assert_eq!(report.total, 0, "{firmware}: {:#?}", report.mechanisms);
        checked += 1;
    }
    assert_eq!(checked, 19);
}
