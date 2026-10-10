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
