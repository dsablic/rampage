//! The AArch32 decoders against llvm-mc 22, on words sampled across every A32 and T32 encoding.
//!
//! Most remaining differences are rare instructions (VEXT element sizes, half-precision VFMAL lanes) and
//! encodings LLVM spells unusually; the thresholds catch regressions while those are worked through.

use rampage_arch::aarch32::{ItState, LabelStyle, decode_a32, decode_t32, format};

fn agreement(golden: &str, decode: impl Fn(u32) -> Option<String>) -> (usize, usize, Vec<String>) {
    let mut checked = 0;
    let mut matched = 0;
    let mut failures = Vec::new();
    for line in golden.lines().filter(|line| !line.starts_with('#')) {
        let (word, expected) = line.split_once('\t').expect("word<TAB>text");
        let actual = decode(u32::from_str_radix(word, 16).expect("hex word")).unwrap_or_default();
        checked += 1;
        if actual == expected {
            matched += 1;
        } else if failures.len() < 20 {
            failures.push(format!("{word}: expected {expected:?}, got {actual:?}"));
        }
    }
    (matched, checked, failures)
}

fn check(golden: &str, minimum: f64, decode: impl Fn(u32) -> Option<String>) {
    let (matched, checked, failures) = agreement(golden, decode);
    let rate = matched as f64 / checked as f64;
    eprintln!("{matched}/{checked} match ({:.2}%)", rate * 100.0);
    assert!(checked > 500, "golden file has only {checked} entries");
    assert!(rate >= minimum, "{matched} of {checked} match ({:.2}%):\n{}", rate * 100.0, failures.join("\n"));
}

#[test]
fn a32_matches_llvm() {
    check(include_str!("data/a32_golden.tsv"), 0.975, |word| {
        decode_a32(word).and_then(|decoded| format(&decoded, 0, LabelStyle::Relative))
    });
}

#[test]
fn t16_matches_llvm() {
    check(include_str!("data/t16_golden.tsv"), 1.0, |word| {
        decode_t32(word as u16, None, ItState::default()).and_then(|decoded| format(&decoded, 0, LabelStyle::Relative))
    });
}

#[test]
fn t32_matches_llvm() {
    check(include_str!("data/t32_golden.tsv"), 0.97, |word| {
        decode_t32((word >> 16) as u16, Some(word as u16), ItState::default())
            .and_then(|decoded| format(&decoded, 0, LabelStyle::Relative))
    });
}

#[test]
fn it_blocks_make_conditions_explicit() {
    // ITE EQ; then ADDS r0, r1 (16-bit) is ADDEQ inside the block.
    let it = ItState::new(0b0000, 0b1100);
    let decoded = decode_t32(0x1840, None, it).unwrap();
    assert_eq!(format(&decoded, 0, LabelStyle::Relative).as_deref(), Some("addeq r0, r0, r1"));
    let decoded = decode_t32(0x1840, None, ItState::default()).unwrap();
    assert_eq!(format(&decoded, 0, LabelStyle::Relative).as_deref(), Some("adds r0, r0, r1"));
}

#[test]
fn absolute_labels_resolve_against_pc() {
    // A32 bl #8 at 0x1000 targets 0x1000 + 8 + 8; Thumb b #4 at 0x2000 targets 0x2000 + 4 + 4.
    let decoded = decode_a32(0xeb00_0002).unwrap();
    assert_eq!(format(&decoded, 0x1000, LabelStyle::Absolute).as_deref(), Some("bl 0x1010"));
    let decoded = decode_t32(0xe002, None, ItState::default()).unwrap();
    assert_eq!(format(&decoded, 0x2000, LabelStyle::Absolute).as_deref(), Some("b 0x2008"));
}

#[test]
fn hints_and_vector_conversions_match_llvm() {
    for (word, expected) in [
        (0xe320_f016, "hint #22"),
        (0xf3bb_0601, "vcvt.f32.s32 d0, d1"),
        (0xf3bb_0701, "vcvt.s32.f32 d0, d1"),
        (0xf3bb_0681, "vcvt.f32.u32 d0, d1"),
        (0xf3bb_0781, "vcvt.u32.f32 d0, d1"),
        (0xf3b7_0601, "vcvt.f16.s16 d0, d1"),
        (0xf3b7_0701, "vcvt.s16.f16 d0, d1"),
        (0xf2b8_0e52, "vcvt.f32.s32 q0, q1, #8"),
        (0xf2af_0f52, "vcvt.s32.f32 q0, q1, #17"),
        (0xf3a0_0e11, "vcvt.f32.u32 d0, d1, #32"),
        (0xf3bf_0f11, "vcvt.u32.f32 d0, d1, #1"),
    ] {
        let decoded = decode_a32(word).unwrap();
        assert_eq!(format(&decoded, 0, LabelStyle::Relative).as_deref(), Some(expected), "{word:08x}");
    }
    let decoded = decode_t32(0xf3af, Some(0x8016), ItState::default()).unwrap();
    assert_eq!(format(&decoded, 0, LabelStyle::Relative).as_deref(), Some("hint.w #22"));
    for (word, expected) in [
        (0xffbb_0601u32, "vcvt.f32.s32 d0, d1"),
        (0xffbb_0701, "vcvt.s32.f32 d0, d1"),
        (0xffbb_0681, "vcvt.f32.u32 d0, d1"),
        (0xffbb_0781, "vcvt.u32.f32 d0, d1"),
        (0xefb8_0e52, "vcvt.f32.s32 q0, q1, #8"),
        (0xefaf_0f52, "vcvt.s32.f32 q0, q1, #17"),
        (0xffa0_0e11, "vcvt.f32.u32 d0, d1, #32"),
        (0xffbf_0f11, "vcvt.u32.f32 d0, d1, #1"),
    ] {
        let decoded = decode_t32((word >> 16) as u16, Some(word as u16), ItState::default()).unwrap();
        assert_eq!(format(&decoded, 0, LabelStyle::Relative).as_deref(), Some(expected), "{word:08x}");
    }
}

#[test]
fn fixed_vector_conversions_cover_every_fraction_width() {
    for thumb in [false, true] {
        for unsigned in [false, true] {
            for to_integer in [false, true] {
                for wide in [false, true] {
                    for fraction in 1..=32u32 {
                        let base = match (thumb, unsigned) {
                            (false, false) => 0xf280_0e11,
                            (false, true) => 0xf380_0e11,
                            (true, false) => 0xef80_0e11,
                            (true, true) => 0xff80_0e11,
                        };
                        let word = (base & !0xf)
                            | (64 - fraction) << 16
                            | u32::from(to_integer) << 8
                            | if wide { 0x42 } else { 1 };
                        let decoded = if thumb {
                            decode_t32((word >> 16) as u16, Some(word as u16), ItState::default())
                        } else {
                            decode_a32(word)
                        }
                        .unwrap();
                        let integer = if unsigned { "u32" } else { "s32" };
                        let (destination, source) = if to_integer { (integer, "f32") } else { ("f32", integer) };
                        let (rd, rm) = if wide { ("q0", "q1") } else { ("d0", "d1") };
                        let expected = format!("vcvt.{destination}.{source} {rd}, {rm}, #{fraction}");
                        assert_eq!(format(&decoded, 0, LabelStyle::Relative), Some(expected), "{word:08x}");
                    }
                }
            }
        }
    }
}
