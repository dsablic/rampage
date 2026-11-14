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

/// The address of a mechanism's decision, if it has one.
fn decision_at(mechanism: &Value) -> Option<u64> {
    mechanism["decision"]["at"].as_str().map(|_| hex(&mechanism["decision"]["at"]))
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
        // The decision itself lies in the named function; a mechanism without a branch (protection configured
        // by writes alone) matches by the function it was found in.
        let found = mechanisms.iter().enumerate().position(|(index, mechanism)| {
            let site = decision_at(mechanism)
                .or_else(|| mechanism["related"][0]["at"].as_str().map(|_| hex(&mechanism["related"][0]["at"])));
            !matched[index] && mechanism["category"] == category && site.is_some_and(|at| inside(&ranges, function, at))
        });
        let entry = scores.entry(category.to_owned()).or_default();
        match found {
            Some(index) => {
                matched[index] = true;
                entry.true_positives += 1;
                let mechanism = &mechanisms[index];
                let failure = want["failure"].as_str().expect("every truth entry states the refusal's effect");
                let path = mechanism["failure_path"].as_str().unwrap();
                let effect = match path {
                    "unknown" => Some("unknown"),
                    _ => mechanism["outcomes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|outcome| outcome["path"] == path)
                        .map(|outcome| outcome["effect"].as_str().unwrap()),
                };
                assert_eq!(effect, Some(failure), "{category} in {function}: {mechanism:#}");
                if let Some(inner) = want["inner"].as_str() {
                    let folded = mechanism["related"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row["role"] == "inner_decision" && inside(&ranges, inner, hex(&row["at"])));
                    assert!(folded, "{category} in {function}: no inner decision in {inner}: {mechanism:#}");
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
    let mut checked = 0;
    for fixture in truth["fixtures"].as_array().unwrap() {
        let project = if fixture["svd"].is_string() {
            firmware(true)
        } else {
            Project::new(Binary::open(format!("{FIXTURES}firmware/{}", fixture["image"].as_str().unwrap())).unwrap())
        };
        let report = report(&project);
        eprintln!("fixture {}", fixture["image"]);
        assert!(report.supported && !report.coverage.incomplete, "{:?}", report.coverage);
        score(&report, fixture, &mut scores);
        checked += 1;
    }
    assert_eq!(checked, 5);
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
    // No suggestion to patch anything, and no route to the patch tools.
    let text = serde_json::to_string(&report).unwrap().to_lowercase();
    for word in ["patch", "bypass", "nop", "disable the", "integrity_checks", "export_image"] {
        assert!(!text.contains(word), "{word:?} in the report");
    }
}

/// Values the firmware writes or holds that could be key material never appear in a report: the option-byte unlock
/// sequence it writes, and any word of the synthetic keys in its read-only data.
#[test]
fn reports_leak_no_key_values() {
    let project = firmware(true);
    let mut pages = Vec::new();
    let all = report(&project);
    pages.push(serde_json::to_string(&all).unwrap().to_lowercase());
    for category in ["debug_lock", "challenge_response", "signature_verification"] {
        let query = LockQuery { category: Some(category.into()), offset: 0, limit: 50 };
        pages.push(serde_json::to_string(&project.lock_mechanisms(&query).unwrap()).unwrap().to_lowercase());
    }
    let text = pages.join("\n");
    assert!(text.contains("flashc.optkeyr"), "the key register write is still explained");
    for key in ["13572468", "24681357", "324478056", "610800471"] {
        assert!(!text.contains(key), "{key} in the report");
    }
    // Every 32-bit word of the synthetic keys, in both byte orders, as hex and decimal.
    let elf = Binary::open(format!("{FIXTURES}firmware/raw-cortex-m-locks.elf")).unwrap();
    let mut words = 0;
    for symbol in ["test_p256_public_key", "service_key"] {
        let symbol = elf.symbol_by_name(symbol).unwrap();
        let bytes = elf.read(symbol.address, symbol.size).unwrap();
        for &chunk in bytes.as_chunks::<4>().0 {
            for word in [u32::from_le_bytes(chunk), u32::from_be_bytes(chunk)] {
                if word > 0xffff {
                    words += 1;
                    assert!(!text.contains(&format!("{word:x}")), "{word:#x} of a key in the report");
                    assert!(!text.contains(&word.to_string()), "{word} of a key in the report");
                }
            }
        }
    }
    assert!(words >= 24, "{words}");
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
    // The fault handler's debugger check is not a lock with or without the map.
    assert!(report.not_locks.iter().any(|row| row.kind == "debugger_presence_check"), "{:?}", report.not_locks);
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

/// A measurement probe for binaries outside the repository: `LOCK_PROBE=/usr/bin/ssh:/usr/bin/curl cargo nextest
/// run -p rampage-api --run-ignored only -E 'test(/lock_mechanisms::probe/)' --no-capture`. Universal Mach-O files
/// are read as their arm64 slice.
#[test]
#[ignore = "reads binaries named in LOCK_PROBE"]
fn probe() {
    let paths = std::env::var("LOCK_PROBE").unwrap_or_default();
    for path in paths.split(':').filter(|path| !path.is_empty()) {
        let binary = Binary::open(path)
            .or_else(|_| Binary::open_with(path, Some(rampage_arch::Arch::Aarch64)))
            .or_else(|_| Binary::open_with(path, Some(rampage_arch::Arch::X86_64)));
        let Ok(binary) = binary else {
            eprintln!("PROBE {path}: cannot open");
            continue;
        };
        let start = std::time::Instant::now();
        let project = Project::new(binary);
        let report = report(&project);
        let mut all = report.mechanisms.clone();
        while all.len() < report.total {
            let query = LockQuery { category: None, offset: all.len(), limit: 50 };
            all.extend(project.lock_mechanisms(&query).unwrap().mechanisms);
        }
        let mut categories: BTreeMap<&str, usize> = BTreeMap::new();
        for mechanism in &all {
            *categories.entry(mechanism.category).or_default() += 1;
        }
        eprintln!(
            "PROBE {path}: {} mechanisms {categories:?}, {} not locks, {} functions, incomplete {} ({:?})",
            report.total,
            report.not_locks_total,
            report.coverage.functions_analyzed,
            report.coverage.incomplete,
            start.elapsed()
        );
        if std::env::var("LOCK_PROBE_VERBOSE").is_ok() {
            for mechanism in &all {
                eprintln!("   {} {} {}", mechanism.category, mechanism.confidence, mechanism.summary);
            }
        }
    }
}
