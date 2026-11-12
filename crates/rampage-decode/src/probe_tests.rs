use super::*;

/// A passing candidate whose tokens are identified by `consumed` and `references`.
fn passing(window_bits: u8, consumed: usize, references: u64, score: f64, fingerprint: u64) -> Candidate {
    Candidate {
        codec: Codec::Lzss(Lzss { window_bits, ..Lzss::classic_4k(0, 0) }),
        output_size: 1000,
        consumed,
        trailing: 0,
        trailing_padding: true,
        end: ScanEnd::OutputLimit,
        literals: 100,
        references,
        input_entropy: 7.5,
        output_entropy: 5.0,
        length_skew: 0.3,
        near_fraction: 0.5,
        unwritten_fraction: 0.0,
        printable_fraction: 0.0,
        extendable_fraction: 0.0,
        extendable_matches: 0,
        fill_exercised: false,
        write_offset_alternatives: 1,
        checks: Vec::new(),
        parse_equivalents: 0,
        output_fingerprint: fingerprint,
        same_output_variants: 0,
        score,
        passes_checks: true,
        verdict: Verdict::Weak,
    }
}

#[test]
fn a_passing_rival_with_another_parse_and_a_near_score_blocks_confidence() {
    let mut candidates = vec![passing(12, 900, 300, 0.90, 1), passing(11, 880, 310, 0.88, 2)];
    rank(&mut candidates, true);
    assert_eq!(candidates[0].score, 0.90);
    assert_eq!(candidates[0].verdict, Verdict::Plausible);
    assert_eq!(candidates[0].parse_equivalents, 0);

    let mut candidates = vec![passing(12, 900, 300, 0.90, 1), passing(11, 880, 310, 0.70, 2)];
    rank(&mut candidates, true);
    assert_eq!(candidates[0].verdict, Verdict::Confident);

    // A rival that fails a check does not block it, however close its score.
    let mut rival = passing(11, 880, 310, 0.89, 2);
    rival.passes_checks = false;
    let mut candidates = vec![passing(12, 900, 300, 0.90, 1), rival];
    rank(&mut candidates, true);
    assert_eq!((candidates[0].verdict, candidates[1].verdict), (Verdict::Confident, Verdict::Weak));
}
