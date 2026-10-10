//! A64 disassembly against outputs verified with llvm-mc.

use rampage_arch::a64::{LabelStyle, format_word};

#[test]
fn matches_golden_disassembly() {
    let golden = include_str!("data/a64_golden.tsv");
    let mut failures = Vec::new();
    let mut checked = 0;
    for line in golden.lines().filter(|line| !line.starts_with('#')) {
        let (word, expected) = line.split_once('\t').expect("word<TAB>text");
        let value = u32::from_str_radix(word, 16).expect("hex word");
        let actual = format_word(value, 0, LabelStyle::Relative).unwrap_or_default();
        checked += 1;
        if actual != expected {
            failures.push(format!("{word}: expected {expected:?}, got {actual:?}"));
        }
    }
    assert!(checked > 6000, "golden file has only {checked} entries");
    assert!(
        failures.is_empty(),
        "{} of {checked} differ:\n{}",
        failures.len(),
        failures[..failures.len().min(40)].join("\n")
    );
}

#[test]
fn absolute_labels_resolve_against_the_instruction_address() {
    // bl #16 at 0x1000; b.ne #-24; adrp x8, page +1; tbz w8, #31, #20
    assert_eq!(format_word(0x9400_0004, 0x1000, LabelStyle::Absolute).as_deref(), Some("bl 0x1010"));
    assert_eq!(format_word(0x54ff_ff41, 0x1000, LabelStyle::Absolute).as_deref(), Some("b.ne 0xfe8"));
    assert_eq!(format_word(0xb000_0008, 0x1234, LabelStyle::Absolute).as_deref(), Some("adrp x8, 0x2000"));
    assert_eq!(format_word(0x36f8_00a8, 0x1000, LabelStyle::Absolute).as_deref(), Some("tbz w8, #31, 0x1014"));
}

/// A small deterministic generator so the sweep covers the same words on every run.
fn words(seed: u64, count: usize) -> impl Iterator<Item = u32> {
    let mut state = seed;
    (0..count).map(move |_| {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 32) as u32
    })
}

#[test]
fn formatting_never_panics() {
    // Debug builds trap arithmetic overflow, so this sweeps the operand code for it.
    for word in words(1, 200_000) {
        let _ = format_word(word, 0xffff_ffff_ffff_f000, LabelStyle::Absolute);
        let _ = format_word(word, 0, LabelStyle::Relative);
    }
}
