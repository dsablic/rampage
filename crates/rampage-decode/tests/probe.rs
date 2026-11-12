use rampage_decode::encode::{self, Random};
use rampage_decode::probe::{Codec, ProbeOptions, Verdict, probe};
use rampage_decode::{DecodeOptions, Decoder, FlagOrder, Lz4Block, Lzss, OffsetMode, ReferenceLayout, ScanEnd};

fn options(expected: Option<usize>) -> ProbeOptions {
    ProbeOptions { expected_output_size: expected, max_output_size: expected.unwrap_or(1 << 22), max_steps: 1 << 28 }
}

fn decodes_to(codec: Codec, stream: &[u8], original: &[u8]) -> bool {
    let options = DecodeOptions {
        expected_output_size: original.len(),
        max_output_size: 1 << 22,
        max_expansion_ratio: 1024,
        max_steps: u64::MAX,
    };
    let decoded = match codec {
        Codec::Lzss(lzss) => lzss.decode(stream, &options, &mut || false),
        Codec::Lz4Block => Lz4Block.decode(stream, &options, &mut || false),
    };
    decoded.is_ok_and(|decoded| decoded.bytes == original)
}

#[test]
fn a_supplied_size_makes_the_right_variant_confident_for_distance_variants_and_lz4() {
    let original = encode::synthetic_firmware(24 << 10, 31);
    let classic = Lzss::classic_4k(0, 0);
    let variants = [
        Lzss { offset_mode: OffsetMode::Distance, ..classic },
        Lzss {
            window_bits: 13,
            flag_order: FlagOrder::MsbFirst,
            literal_flag: false,
            layout: ReferenceLayout::Be16OffsetLow,
            offset_mode: OffsetMode::DistanceMinusOne,
            ..classic
        },
        Lzss {
            window_bits: 10,
            min_match: 2,
            layout: ReferenceLayout::Le16LengthLow,
            offset_mode: OffsetMode::Distance,
            ..classic
        },
    ];
    for variant in variants {
        let stream = encode::lzss(&variant, &original);
        let report = probe(&stream, &options(Some(original.len())), &mut || false);
        let best = &report.candidates[0];
        assert_eq!(best.verdict, Verdict::Confident, "{variant:?}: {:#?}", &report.candidates[..2]);
        assert!(decodes_to(best.codec, &stream, &original), "{variant:?}");
        assert!(report.size_fits >= 1 && report.stopped_early.is_none());
    }
    let stream = encode::lz4_block(&original);
    let report = probe(&stream, &options(Some(original.len())), &mut || false);
    assert_eq!((report.candidates[0].codec, report.candidates[0].verdict), (Codec::Lz4Block, Verdict::Confident));
}

#[test]
fn ring_variants_find_the_parameters_and_report_fill_and_start_ambiguity_instead_of_guessing() {
    // Text, unlike firmware, has few runs of the fill byte, so the ring start is decidable.
    let words = ["status", "ready", "buffer", "timeout", "channel", "update", "firmware", "invalid", "device"];
    let mut random = Random(17);
    let original: Vec<u8> =
        (0..4000).flat_map(|_| [words[random.below(words.len())].as_bytes(), b" "].concat()).collect();
    let variant = Lzss { initial_write_offset: 1500, dictionary_fill: 0x20, ..Lzss::classic_4k(0, 0) };
    let stream = encode::lzss(&variant, &original);
    let report = probe(&stream, &options(Some(original.len())), &mut || false);
    let right = report.candidates.iter().position(|candidate| decodes_to(candidate.codec, &stream, &original));
    let right = right.expect("the right parameters are among the candidates");
    let best = &report.candidates[0];
    if best.verdict == Verdict::Confident {
        assert_eq!(right, 0, "{:#?}", &report.candidates[..2]);
    } else {
        assert!(best.parse_equivalents > 0 && right <= best.parse_equivalents, "{right} {:#?}", report.candidates);
    }
}

#[test]
fn uncompressed_and_random_inputs_get_no_passing_candidate() {
    let code = encode::synthetic_firmware(32 << 10, 2);
    let noise = Random(9).bytes(32 << 10);
    for input in [&code, &noise] {
        for expected in [None, Some(100_000)] {
            let report = probe(input, &options(expected), &mut || false);
            assert!(
                report.candidates.iter().all(|candidate| candidate.verdict == Verdict::Weak),
                "{:#?}",
                report.candidates
            );
        }
    }
}

#[test]
fn work_budget_and_cancellation_end_the_sweep_early_and_say_so() {
    let original = encode::synthetic_firmware(8 << 10, 4);
    let stream = encode::lzss(&Lzss::classic_4k(4078, 0), &original);
    let tight = ProbeOptions { max_steps: 50_000, ..options(None) };
    let report = probe(&stream, &tight, &mut || false);
    // A decode that runs out of budget counts its steps too.
    assert_eq!((report.stopped_early, report.steps), (Some("work_budget"), 50_000));
    let mut polls = 0;
    let report = probe(&stream, &options(None), &mut || {
        polls += 1;
        polls > 1000
    });
    assert_eq!(report.stopped_early, Some("cancelled"));
    assert!(report.steps > 0 && report.steps <= 1000, "{}", report.steps);
}

#[test]
fn an_lz4_block_followed_by_padding_is_found_without_a_size() {
    let original = encode::synthetic_firmware(16 << 10, 8);
    let mut stream = encode::lz4_block(&original);
    let block = stream.len();
    stream.extend([0; 300]);
    let scan = Lz4Block.decode_available(&stream, 1 << 22, u64::MAX, &mut || false).unwrap();
    assert_eq!((scan.bytes.len(), scan.consumed), (original.len(), block));
    let report = probe(&stream, &options(None), &mut || false);
    let lz4 = report.candidates.iter().find(|candidate| candidate.codec == Codec::Lz4Block).expect("an LZ4 candidate");
    assert_eq!((lz4.output_size, lz4.consumed), (original.len(), block));
    for name in ["input_consumed", "block_ends_with_input"] {
        assert!(lz4.checks.iter().any(|check| check.name == name && check.passed), "{name}: {:#?}", lz4.checks);
    }
    assert!(decodes_to(lz4.codec, &stream, &original));
}

#[test]
fn a_rejected_lz4_sequence_leaves_no_literals_behind_in_a_scan() {
    // A sequence of four literals and a four-byte match, then one whose literals precede a zero distance.
    let mut stream = vec![0x40, b'a', b'b', b'c', b'd', 4, 0];
    stream.extend([0x30, b'x', b'y', b'z', 0, 0, 0x55]);
    let scan = Lz4Block.decode_available(&stream, 1 << 20, u64::MAX, &mut || false).unwrap();
    assert_eq!((scan.bytes.as_slice(), scan.consumed, scan.end), (&b"abcdabcd"[..], 7, ScanEnd::InvalidToken));
    assert_eq!(scan.stats.literals, 4);
}

#[test]
fn a_deadline_during_the_lzss_sweep_still_leaves_the_lz4_attempt() {
    let original = encode::synthetic_firmware(8 << 10, 3);
    let stream = encode::lz4_block(&original);
    let lz4_steps = Lz4Block.decode_available(&stream, 1 << 22, u64::MAX, &mut || false).unwrap().steps;
    let mut polls = 0;
    let report = probe(&stream, &options(Some(original.len())), &mut || {
        polls += 1;
        polls > lz4_steps + 100
    });
    assert_eq!(report.stopped_early, Some("cancelled"));
    assert_eq!(report.candidates[0].codec, Codec::Lz4Block);
    assert!(decodes_to(report.candidates[0].codec, &stream, &original));
}
