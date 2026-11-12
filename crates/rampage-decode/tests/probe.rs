use rampage_decode::encode::{self, Random};
use rampage_decode::probe::{Codec, ProbeOptions, Verdict, probe};
use rampage_decode::{DecodeOptions, Decoder, FlagOrder, Lz4Block, Lzss, OffsetMode, ReferenceLayout};

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
    assert_eq!(probe(&stream, &tight, &mut || false).stopped_early, Some("work_budget"));
    let mut polls = 0;
    let report = probe(&stream, &options(None), &mut || {
        polls += 1;
        polls > 1000
    });
    assert_eq!(report.stopped_early, Some("cancelled"));
}
