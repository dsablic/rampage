use rampage_decode::{DecodeError, DecodeOptions, Decoded, Decoder, Lzss4k};

fn provider(start: u16, fill: u8) -> Lzss4k {
    Lzss4k { initial_write_offset: start, dictionary_fill: fill }
}

fn options(expected: usize) -> DecodeOptions {
    DecodeOptions { expected_output_size: expected, max_output_size: 8192, max_expansion_ratio: 32, max_steps: 32768 }
}

fn decode(input: &[u8], expected: usize) -> Result<Decoded, DecodeError> {
    provider(0, 0).decode(input, &options(expected), &mut || false)
}

#[test]
fn literal_flags_are_lsb_first_and_reload_after_eight_tokens() {
    let input = [0xff, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 1, b'i'];
    let decoder: &dyn Decoder = &provider(0, 0);
    assert_eq!(decoder.id(), "lzss-4k");
    let result = decoder.decode(&input, &options(9), &mut || false).unwrap();
    assert_eq!(result.bytes, b"abcdefghi");
    assert_eq!(result.consumed, input.len());
    assert_eq!(result.steps, 18);
}

#[test]
fn dictionary_fill_is_read_before_any_literals() {
    let result = provider(0xfee, b' ').decode(&[0, 0, 0x0f], &options(18), &mut || false).unwrap();
    assert_eq!(result.bytes, vec![b' '; 18]);
    assert_eq!(result.steps, 19);
}

#[test]
fn caller_start_and_high_position_bits_select_written_dictionary_bytes() {
    let input = [0x03, b'A', b'B', 0xee, 0xf3];
    let result = provider(0xfee, b'.').decode(&input, &options(8), &mut || false).unwrap();
    assert_eq!(result.bytes, b"ABABABAB");
    assert_eq!(result.steps, 11);
}

#[test]
fn overlapping_reference_repeats_bytes_written_by_the_same_token() {
    let result = decode(&[0x01, b'x', 0, 0x0f], 19).unwrap();
    assert_eq!(result.bytes, vec![b'x'; 19]);
    assert_eq!(result.steps, 21);
}

#[test]
fn read_and_write_positions_wrap_around_the_ring() {
    let input = [0x03, b'A', b'B', 0xff, 0xf3];
    let result = provider(4095, b'.').decode(&input, &options(8), &mut || false).unwrap();
    assert_eq!(result.bytes, b"ABABABAB");
    assert_eq!(result.consumed, 5);
}

#[test]
fn exact_consumption_leaves_trailing_bytes_and_unused_flags_untouched() {
    let result = decode(&[0xff, b'A', b'B', 0, 0], 1).unwrap();
    assert_eq!(result.bytes, b"A");
    assert_eq!(result.consumed, 2);
    assert_eq!(result.steps, 2);
    let result = decode(&[0, 0, 0, 0xff], 3).unwrap();
    assert_eq!(result.bytes, vec![0; 3]);
    assert_eq!(result.consumed, 3);
}

#[test]
fn empty_output_consumes_nothing_and_needs_no_work_or_output_budget() {
    let mut limits = options(0);
    limits.max_output_size = 0;
    limits.max_steps = 0;
    for input in [&[][..], &[0xff, b'x'][..]] {
        let result = provider(0, 0).decode(input, &limits, &mut || false).unwrap();
        assert!(result.bytes.is_empty());
        assert_eq!(result.consumed, 0);
        assert_eq!(result.steps, 0);
    }
}

#[test]
fn missing_literal_reference_bytes_and_next_flags_are_truncated() {
    let cases: &[(&[u8], usize)] =
        &[(&[1], 1), (&[0], 3), (&[0, 0], 3), (&[0xff, b'A'], 2), (&[0xff, 1, 2, 3, 4, 5, 6, 7, 8], 9)];
    for &(input, expected) in cases {
        assert_eq!(decode(input, expected), Err(DecodeError::TruncatedInput));
    }
}

#[test]
fn reference_cannot_be_shortened_to_fit_expected_output() {
    for (input, expected) in [(&[0, 0, 0][..], 2), (&[1, b'A', 0, 0][..], 3), (&[0, 0, 0x0f][..], 17)] {
        assert_eq!(decode(input, expected), Err(DecodeError::OutputSizeMismatch));
    }
    assert_eq!(decode(&[0, 0, 0], 3).unwrap().bytes, vec![0; 3]);
}

#[test]
fn invalid_ring_start_is_rejected_instead_of_masked() {
    for start in [4096, u16::MAX] {
        assert_eq!(provider(start, 0).decode(&[], &options(0), &mut || false), Err(DecodeError::InvalidParameters));
    }
}

#[test]
fn zero_ratio_is_an_invalid_budget_even_for_empty_output() {
    let mut limits = options(0);
    limits.max_expansion_ratio = 0;
    assert_eq!(provider(0, 0).decode(&[], &limits, &mut || false), Err(DecodeError::InvalidBudget));
}

#[test]
fn output_and_impossible_work_budgets_are_rejected_before_allocation_or_cancellation() {
    let mut limits = options(usize::MAX);
    let mut unexpected_poll = || panic!("invalid budgets must be rejected before allocation or cancellation");
    assert_eq!(provider(0, 0).decode(&[0], &limits, &mut unexpected_poll), Err(DecodeError::OutputLimitExceeded));
    limits.max_output_size = usize::MAX;
    limits.max_expansion_ratio = usize::MAX;
    limits.max_steps = 0;
    assert_eq!(provider(0, 0).decode(&[0], &limits, &mut unexpected_poll), Err(DecodeError::WorkLimitExceeded));
}

#[test]
fn expansion_uses_full_input_length_and_accepts_exact_ratio() {
    let mut limits = options(6);
    limits.max_expansion_ratio = 2;
    let result = provider(0, 0).decode(&[0, 0, 3], &limits, &mut || false).unwrap();
    assert_eq!(result.bytes, vec![0; 6]);
    limits.expected_output_size = 7;
    assert_eq!(provider(0, 0).decode(&[0, 0, 4], &limits, &mut || false), Err(DecodeError::ExpansionLimitExceeded));
    limits.expected_output_size = 6;
    limits.max_expansion_ratio = 1;
    assert_eq!(provider(0, 0).decode(&[0, 0, 3], &limits, &mut || false), Err(DecodeError::ExpansionLimitExceeded));
    let result = provider(0, 0).decode(&[0, 0, 3, 9, 9, 9], &limits, &mut || false).unwrap();
    assert_eq!(result.bytes, vec![0; 6]);
    assert_eq!(result.consumed, 3);
    assert_eq!(decode(&[], 1), Err(DecodeError::ExpansionLimitExceeded));
}

#[test]
fn expansion_multiplication_cannot_overflow_into_a_false_rejection() {
    let mut limits = options(1);
    limits.max_expansion_ratio = usize::MAX;
    let result = provider(0, 0).decode(&[1, b'A'], &limits, &mut || false).unwrap();
    assert_eq!(result.bytes, b"A");
}

#[test]
fn exact_work_budget_succeeds_and_token_and_output_work_both_count() {
    let mut limits = options(3);
    limits.max_steps = 4;
    let result = provider(0, 0).decode(&[0, 0, 0], &limits, &mut || false).unwrap();
    assert_eq!(result.steps, 4);
    for max_steps in [0, 3, 4, 5] {
        limits.max_steps = max_steps;
        assert_eq!(
            provider(0, 0).decode(&[7, b'A', b'B', b'C'], &limits, &mut || false),
            Err(DecodeError::WorkLimitExceeded)
        );
    }
    limits.max_steps = 6;
    let result = provider(0, 0).decode(&[7, b'A', b'B', b'C'], &limits, &mut || false).unwrap();
    assert_eq!(result.steps, 6);
}

#[test]
fn work_limit_is_enforced_inside_a_reference_after_preflight_succeeds() {
    let mut limits = options(18);
    limits.max_steps = 19;
    let input = [0, 0, 0, 0, 12];
    assert_eq!(provider(0, 0).decode(&input, &limits, &mut || false), Err(DecodeError::WorkLimitExceeded));
    limits.max_steps = 20;
    let result = provider(0, 0).decode(&input, &limits, &mut || false).unwrap();
    assert_eq!(result.bytes, vec![0; 18]);
    assert_eq!(result.steps, 20);
    limits.max_steps = u64::MAX;
    assert_eq!(provider(0, 0).decode(&input, &limits, &mut || false), Ok(result));
}

#[test]
fn cancellation_is_checked_before_allocation_even_for_empty_output() {
    for expected in [0, 1] {
        assert_eq!(provider(0, 0).decode(&[1, b'A'], &options(expected), &mut || true), Err(DecodeError::Cancelled));
    }
}

#[test]
fn cancellation_is_checked_during_reference_copy_and_literal_tokens() {
    for (input, expected, cancel_on_poll) in [
        (&[0, 0, 0x0f][..], 18, 6),
        (&[0, 0, 0x0f][..], 18, 20),
        (&[7, b'A', b'B', b'C'][..], 3, 4),
        (&[7, b'A', b'B', b'C'][..], 3, 7),
    ] {
        let mut polls = 0;
        let result = provider(0, 0).decode(input, &options(expected), &mut || {
            polls += 1;
            polls == cancel_on_poll
        });
        assert_eq!(result, Err(DecodeError::Cancelled));
        assert_eq!(polls, cancel_on_poll);
    }
}

#[test]
fn impossible_vec_capacity_is_reported_as_allocation_failure() {
    let expected = (isize::MAX as usize) + 1;
    let limits = DecodeOptions {
        expected_output_size: expected,
        max_output_size: usize::MAX,
        max_expansion_ratio: usize::MAX,
        max_steps: u64::MAX,
    };
    assert_eq!(provider(0, 0).decode(&[1], &limits, &mut || true), Err(DecodeError::Cancelled));
    assert_eq!(provider(0, 0).decode(&[1], &limits, &mut || false), Err(DecodeError::AllocationFailure));
}

#[test]
fn errors_implement_standard_error_without_payloads() {
    let error: &dyn std::error::Error = &DecodeError::TruncatedInput;
    assert!(error.source().is_none());
    assert!(!error.to_string().is_empty());
}
