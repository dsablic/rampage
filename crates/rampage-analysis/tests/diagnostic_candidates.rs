use rampage_analysis::diagnostics::{DecodeRegion, DecodeSignal, Diagnostics};
use rampage_analysis::discover::{DiscoveredFunction, Program};

fn sample(address: u64, size: usize, signals: Vec<DecodeSignal>) -> DecodeRegion {
    DecodeRegion {
        name: "sample".to_owned(),
        address,
        bytes_sampled: size,
        instructions: 20,
        invalid: 0,
        indirect_transfers: 0,
        external_branches: 0,
        entropy: 0.0,
        assessment: "test sample",
        signals,
        discovery: None,
    }
}

#[test]
fn evidence_is_sample_scoped_and_does_not_remove_tiny_or_unassessed_candidates() {
    let functions: Vec<_> = [(0x1010, 2), (0x1000, 20), (0x1011, 1), (0x2000, 3)]
        .into_iter()
        .map(|(address, instruction_count)| DiscoveredFunction { address, instruction_count, blocks: Vec::new() })
        .collect();
    let program = Program { functions, ..Default::default() };
    let original = program.functions.clone();
    let audit = Diagnostics {
        regions: vec![sample(0x1000, 0x10, vec![DecodeSignal::HighEntropy]), sample(0x2000, 4, vec![])],
        discovery: None,
        limitations: Vec::new(),
    }
    .with_discovery(&program.functions);
    let evidence = audit.discovery.unwrap();
    assert_eq!(evidence.total_candidates, 4);
    assert_eq!(evidence.tiny_candidates, 3);
    assert_eq!(evidence.candidates_in_sampled_ranges, 2);
    assert_eq!(evidence.candidates_in_flagged_sampled_ranges, 1);
    assert_eq!(evidence.tiny_candidates_in_flagged_sampled_ranges, 0);
    assert_eq!(evidence.candidates_outside_sampled_ranges, 2);
    assert_eq!(program.functions, original);
}

#[test]
fn overlapping_samples_do_not_double_count_candidate_entries() {
    let functions = [DiscoveredFunction { address: u64::MAX - 1, instruction_count: 1, blocks: Vec::new() }];
    let audit = Diagnostics {
        regions: vec![sample(u64::MAX - 3, 3, vec![]), sample(u64::MAX - 2, 2, vec![DecodeSignal::HighInvalidRate])],
        discovery: None,
        limitations: Vec::new(),
    }
    .with_discovery(&functions);
    assert_eq!(audit.regions[0].discovery.as_ref().unwrap().candidates, 1);
    assert_eq!(audit.regions[1].discovery.as_ref().unwrap().candidates, 1);
    let evidence = audit.discovery.unwrap();
    assert_eq!(evidence.candidates_in_sampled_ranges, 1);
    assert_eq!(evidence.candidates_in_flagged_sampled_ranges, 1);
    assert_eq!(evidence.tiny_candidates_in_flagged_sampled_ranges, 1);
    assert_eq!(evidence.candidates_outside_sampled_ranges, 0);
}
