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

#[test]
fn operand_forms_found_in_review() {
    let cases = [
        (0xd503_42df, "msr DAIFSet, #2"),
        // Arm's preferred alias; LLVM prints `bfi w0, wzr, #3, #2`.
        (0x331d_07e0, "bfc w0, #3, #2"),
        (0x4f3f_1923, "fmla v3.8h, v9.8h, v15.h[7]"),
        (0x6f7c_1973, "fcmla v19.8h, v11.8h, v28.h[3], #0"),
        (0x693e_6d5d, "stgp x29, x27, [x10, #-64]"),
        (0xd966_009a, "ldg x26, [x4, #1536]"),
        (0xd182_2d98, "subg x24, x12, #32, #11"),
        (0xd503_3a3f, "dsb ishnxs"),
        (0xf8b1_4bfd, "rprfm pststrm, x17, [sp]"),
        (0xd548_7720, "sysp #0, c7, c7, #1, x0, x1"),
        (0xd508_831f, "tlbi vmalle1is"),
        (0xba1d_07e1, "rmif xzr, #58, #1"),
        (0x0e30_f847, "fmaxv h7, v2.4h"),
        (0xd503_3f5f, "clrex"),
    ];
    for (word, expected) in cases {
        assert_eq!(format_word(word, 0, LabelStyle::Relative).as_deref(), Some(expected), "{word:#010x}");
    }
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
