use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_eval::{Outcome, Truth, evaluate, proposals};
use rampage_loaders::Binary;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn truth_from_binary_keeps_sized_function_symbols() {
    let binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    let truth = Truth::from_binary(&binary);
    assert!(truth.0.values().any(|name| name == "main"), "no main in {} entries", truth.0.len());
    for (address, name) in &truth.0 {
        let symbol = binary.symbols.iter().find(|symbol| symbol.address == *address && &symbol.name == name);
        let symbol = symbol.unwrap_or_else(|| panic!("{name} at {address:#x} is not a symbol"));
        assert!(symbol.size > 0, "{name} has zero size");
    }
}

#[test]
fn stripped_binary_has_empty_truth() {
    let binary = Binary::open(fixture("musl-static-x86_64.elf")).unwrap();
    assert!(Truth::from_binary(&binary).0.is_empty());
}

/// Builds a truth whose outcome per address is known from what the database actually proposes, so every
/// category is exercised end to end on a real binary: one correct, one wrong, one missed (discovered but
/// unproposed), one missed (never discovered) and every remaining proposal spurious.
#[test]
fn evaluate_scores_a_real_binary_against_a_constructed_truth() {
    let target = Binary::open(fixture("musl-static-x86_64.elf")).unwrap();
    let db = rampage_signatures::bundled(Arch::X86_64).unwrap();
    let all = proposals(&db, &target).unwrap();
    let named: Vec<(u64, String)> =
        all.iter().filter_map(|(address, name)| Some((*address, name.clone()?))).collect();
    let unnamed = all.iter().find(|(_, name)| name.is_none()).unwrap().0;
    assert!(named.len() >= 3, "only {} proposals", named.len());

    let mut truth = Truth::default();
    truth.0.insert(named[0].0, named[0].1.clone());
    truth.0.insert(named[1].0, format!("not_{}", named[1].1));
    truth.0.insert(unnamed, "user_function".to_owned());
    truth.0.insert(0xdead_0000, "undiscovered".to_owned());

    let report = evaluate(&db, &target, &truth).unwrap();
    assert_eq!(report.correct, 1);
    assert_eq!(report.wrong, 1);
    assert_eq!(report.missed, 2);
    assert_eq!(report.spurious, named.len() - 2);
    let wrong = report.disagreements.iter().find(|entry| entry.outcome == Outcome::Wrong).unwrap();
    assert_eq!(wrong.address, named[1].0);
    assert!(!report.disagreements.iter().any(|entry| entry.outcome == Outcome::Correct));
}
