//! Bounds carried on the actual successor edge, and comparisons surviving only audited scheduling effects.

use rampage_arch::{Arch, Disassembler, Flow, JumpTable, RegisterFacts, decoder_for};

const CMP_W0_3: u32 = 0x7100_0c1f;
const CMP_X0_3: u32 = 0xf100_0c1f;
const NOP: u32 = 0xd503_201f;
const LOAD_W_INDEX: u32 = 0xf860_592b;
const LOAD_X_INDEX: u32 = 0xf860_792b;

fn decode(decoder: &mut dyn Disassembler, word: u32, address: u64) {
    let insn = decoder.decode(&word.to_le_bytes(), address);
    assert_ne!(insn.flow, Flow::Invalid, "{word:#010x}");
}

fn edges(compare: u32, scheduled: &[u32], condition: u32) -> (RegisterFacts, RegisterFacts) {
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decode(decoder.as_mut(), compare, 0x1000);
    for (index, &word) in scheduled.iter().enumerate() {
        decode(decoder.as_mut(), word, 0x1004 + 4 * index as u64);
    }
    decode(decoder.as_mut(), 0x5400_0800 | condition, 0x1004 + 4 * scheduled.len() as u64);
    (decoder.facts().unwrap(), decoder.taken_facts().unwrap())
}

fn dispatch(facts: &RegisterFacts, before_load: &[u32], load: u32) -> Option<JumpTable> {
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decoder.assume(facts);
    let words: Vec<_> = before_load.iter().copied().chain([0x1000_8009, load, 0xd61f_0160]).collect();
    for (index, word) in words.into_iter().enumerate() {
        decode(decoder.as_mut(), word, 0x2000 + 4 * index as u64);
    }
    decoder.jump_table()
}

#[test]
fn inverse_unsigned_conditions_bound_only_the_taken_edge() {
    for compare in [CMP_W0_3, CMP_X0_3] {
        for (condition, taken, entries) in [(8, false, 4), (2, false, 3), (9, true, 4), (3, true, 3)] {
            let (fall, branch) = edges(compare, &[], condition);
            let (bounded, unbounded) = if taken { (&branch, &fall) } else { (&fall, &branch) };
            let table = dispatch(bounded, &[], LOAD_W_INDEX).expect("bounded edge");
            assert_eq!((table.entries, table.guard, table.alignment), (entries, 0x1000, 4));
            assert_eq!(dispatch(unbounded, &[], LOAD_W_INDEX), None);
            assert_eq!(dispatch(bounded, &[], LOAD_X_INDEX).is_some(), compare == CMP_X0_3);
        }
    }
}

#[test]
fn inverse_w_bounds_cover_x_indices_only_when_every_path_zeroed_the_upper_half() {
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decode(decoder.as_mut(), 0x2a00_03e0, 0xffc); // mov w0, w0
    decode(decoder.as_mut(), CMP_W0_3, 0x1000);
    decode(decoder.as_mut(), 0x5400_0809, 0x1004); // b.ls
    let zeroed = decoder.taken_facts().unwrap();
    assert!(dispatch(&zeroed, &[], LOAD_X_INDEX).is_some());
    let (_, only_w) = edges(CMP_W0_3, &[], 9);
    let joined = zeroed.meet(&only_w);
    assert_eq!(dispatch(&joined, &[], LOAD_X_INDEX), None);
    assert!(dispatch(&joined, &[], LOAD_W_INDEX).is_some());
}

#[test]
fn scheduled_flag_preserving_instructions_keep_the_original_guard() {
    let scheduled = [
        NOP,
        0x1000_0041, // adr x1, .+8
        0x9100_0421, // add x1, x1, #1
        0x2a02_03e1, // mov w1, w2
        0xb940_0041, // ldr w1, [x2]
        0xb900_0041, // str w1, [x2]
        0x5300_1c41, // uxtb w1, w2
        0x1a83_0041, // csel w1, w2, w3, eq
    ];
    for (condition, taken) in [(8, false), (2, false), (9, true), (3, true)] {
        let (fall, branch) = edges(CMP_W0_3, &scheduled, condition);
        let table = dispatch(if taken { &branch } else { &fall }, &[], LOAD_W_INDEX).expect("scheduled compare");
        assert_eq!(table.guard, 0x1000);
    }
}

#[test]
fn scheduled_flag_writes_calls_and_unknown_effects_forget_comparisons() {
    let clobbers = [
        0x3100_0421, // adds w1, w1, #1
        0x6a02_003f, // tst w1, w2
        0x7100_0c3f, // cmp w1, #3: replaces, rather than preserving, the comparison
        0x7a40_0800, // ccmp w0, #0, #0, eq
        0x1e60_2000, // fcmp d0, d0
        0xd51b_4201, // msr NZCV, x1
        0xba00_0401, // rmif x0, #0, #1
        0x3a00_080d, // setf8 w0
        0x9400_0004, // bl .+16
        0xd400_0001, // svc #0
        0xd503_2fff, // unmodelled hint #0x7f
    ];
    for word in clobbers {
        for condition in [8, 9] {
            let (fall, taken) = edges(CMP_W0_3, &[word, NOP], condition);
            assert_eq!(dispatch(&fall, &[], LOAD_W_INDEX), None, "{word:#010x}");
            assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX), None, "{word:#010x}");
        }
    }
    // Calls also destroy NZCV when the compared register itself is callee-saved.
    let (fall, _) = edges(0x7100_0e9f, &[0x9400_0004], 8); // cmp w20, #3
    assert_eq!(dispatch(&fall, &[], LOAD_W_INDEX | 20 << 16), None);
}

#[test]
fn writes_to_either_register_view_or_a_writeback_base_forget_the_comparison() {
    let writes = [
        0x9100_0400, // add x0, x0, #1
        0x1100_0400, // add w0, w0, #1
        0x2a00_03e0, // mov w0, w0: zeroing the upper half still writes the compared value
        0xb940_0040, // ldr w0, [x2]
        0xa940_03e1, // ldp x1, x0, [sp]
        0xf840_8401, // ldr x1, [x0], #8
    ];
    for compare in [CMP_W0_3, CMP_X0_3] {
        for word in writes {
            let (fall, taken) = edges(compare, &[word], 9);
            assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX), None, "{compare:#x} {word:#x}");
            assert_eq!(dispatch(&fall, &[], LOAD_W_INDEX), None);
        }
    }
}

#[test]
fn joins_keep_only_the_bound_and_comparison_proven_on_both_paths() {
    let (fall, taken) = edges(CMP_W0_3, &[NOP], 9);
    assert!(dispatch(&taken.meet(&taken), &[], LOAD_W_INDEX).is_some());
    assert_eq!(dispatch(&taken.meet(&fall), &[], LOAD_W_INDEX), None);
    let (_, other_guard) = edges(CMP_W0_3, &[NOP], 3);
    // The same guard, with upper bounds 2 and 3, joins to their union (four entries, not three).
    assert_eq!(dispatch(&taken.meet(&other_guard), &[], LOAD_W_INDEX).unwrap().entries, 4);
    let (_, changed_register) = edges(CMP_W0_3, &[0x1100_0400], 9);
    assert_eq!(dispatch(&taken.meet(&changed_register), &[], LOAD_W_INDEX), None);
    let (_, other_compare) = edges(0x7100_0c3f, &[], 9);
    assert_eq!(dispatch(&taken.meet(&other_compare), &[], LOAD_W_INDEX), None);
}

#[test]
fn zero_and_oversized_inverse_bounds_do_not_wrap_into_table_lengths() {
    for condition in [2, 3] {
        let (fall, taken) = edges(0x7100_001f, &[], condition); // cmp w0, #0
        assert_eq!(dispatch(&fall, &[], LOAD_W_INDEX), None);
        assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX), None);
    }
    for (compare, condition, entries) in [
        (0x713f_fc1f, 9, Some(4096)), // cmp w0, #4095; b.ls
        (0x7140_041f, 9, None),       // cmp w0, #4096; b.ls
        (0x7140_041f, 3, Some(4096)), // cmp w0, #4096; b.lo
        (0x717f_fc1f, 3, None),       // cmp w0, #4095, lsl #12; b.lo
    ] {
        let (_, taken) = edges(compare, &[], condition);
        assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX).map(|table| table.entries), entries);
    }
}

#[test]
fn a_later_guard_keeps_an_earlier_bound_on_its_other_edge() {
    let (fall, _) = edges(CMP_W0_3, &[], 8);
    for condition in [8, 9] {
        let mut decoder = decoder_for(Arch::Aarch64).unwrap();
        decoder.assume(&fall);
        decode(decoder.as_mut(), 0x7100_041f, 0x1010); // cmp w0, #1
        decode(decoder.as_mut(), 0x5400_0800 | condition, 0x1014);
        let (fall, taken) = (decoder.facts().unwrap(), decoder.taken_facts().unwrap());
        let (new, old) = if condition == 8 { (&fall, &taken) } else { (&taken, &fall) };
        let new = dispatch(new, &[], LOAD_W_INDEX).unwrap();
        let old = dispatch(old, &[], LOAD_W_INDEX).unwrap();
        assert_eq!((new.entries, new.guard), (2, 0x1010));
        assert_eq!((old.entries, old.guard), (4, 0x1000));
    }
}

#[test]
fn later_weaker_bounds_keep_the_existing_limit_width_and_guard_on_both_edges() {
    for (old_compare, new_compare) in [
        (CMP_W0_3, 0x7140_041f), // W <= 3, then W <= 4096
        (CMP_X0_3, 0x7140_041f), // X <= 3, then W <= 4096
        (CMP_X0_3, 0x7100_041f), // X <= 3, then W <= 1: do not discard the whole-X proof
        (CMP_X0_3, CMP_X0_3),    // Equal bounds retain the original guard
    ] {
        let (old, _) = edges(old_compare, &[], 8);
        for condition in [8, 9, 2, 3] {
            let mut decoder = decoder_for(Arch::Aarch64).unwrap();
            decoder.assume(&old);
            decode(decoder.as_mut(), new_compare, 0x1010);
            decode(decoder.as_mut(), 0x5400_0800 | condition, 0x1014);
            let fall = decoder.facts().unwrap();
            let taken = decoder.taken_facts().unwrap();
            // Strict X < 3 is independently tighter than X <= 3 and legitimately selects the newer guard.
            let tighter = new_compare == CMP_X0_3 && matches!(condition, 2 | 3);
            for (edge, bounded) in [(&fall, matches!(condition, 8 | 2)), (&taken, matches!(condition, 9 | 3))] {
                let table = dispatch(edge, &[], LOAD_W_INDEX).unwrap();
                let wanted = if tighter && bounded { (3, 0x1010) } else { (4, 0x1000) };
                assert_eq!((table.entries, table.guard), wanted, "{old_compare:#x} {new_compare:#x} {condition}");
                assert_eq!(dispatch(edge, &[], LOAD_X_INDEX).is_some(), old_compare == CMP_X0_3);
            }
            if !tighter {
                let joined = fall.meet(&taken).meet(&old);
                let table = dispatch(&joined, &[], LOAD_W_INDEX).unwrap();
                assert_eq!((table.entries, table.guard), (4, 0x1000));
            }
        }
    }
}

#[test]
fn tighter_bounds_replace_the_complete_proof_without_mixing_guards_at_joins() {
    let (old, _) = edges(CMP_W0_3, &[], 8);
    for new_compare in [0x7100_041f, 0xf100_041f] {
        // cmp w0 / x0, #1
        let mut decoder = decoder_for(Arch::Aarch64).unwrap();
        decoder.assume(&old);
        decode(decoder.as_mut(), new_compare, 0x1010);
        decode(decoder.as_mut(), 0x5400_0809, 0x1014);
        let taken = decoder.taken_facts().unwrap();
        let table = dispatch(&taken, &[], LOAD_W_INDEX).unwrap();
        assert_eq!((table.entries, table.guard), (2, 0x1010));
        assert_eq!(dispatch(&taken, &[], LOAD_X_INDEX).is_some(), new_compare == 0xf100_041f);
        assert_eq!(dispatch(&taken.meet(&old), &[], LOAD_W_INDEX), None);
    }
    let mut different_guard = decoder_for(Arch::Aarch64).unwrap();
    decode(different_guard.as_mut(), CMP_W0_3, 0x1020);
    decode(different_guard.as_mut(), 0x5400_0808, 0x1024);
    let other = different_guard.facts().unwrap();
    assert_eq!(dispatch(&old.meet(&other), &[], LOAD_W_INDEX), None);
    let after_weaker = |facts: &RegisterFacts, guard| {
        let mut decoder = decoder_for(Arch::Aarch64).unwrap();
        decoder.assume(facts);
        decode(decoder.as_mut(), 0x7140_041f, 0x1040); // cmp w0, #4096
        decode(decoder.as_mut(), 0x5400_0809, 0x1044);
        let taken = decoder.taken_facts().unwrap();
        assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX).unwrap().guard, guard);
        taken
    };
    let old = after_weaker(&old, 0x1000);
    let other = after_weaker(&other, 0x1020);
    assert_eq!(dispatch(&old.meet(&other), &[], LOAD_W_INDEX), None);
}

#[test]
fn inverse_table_addresses_do_not_wrap_when_computing_slots() {
    let (_, facts) = edges(CMP_X0_3, &[], 9);
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decoder.assume(&facts);
    // movz x9, #0xfff8; movk x9, #0xffff, lsl #16/#32/#48; ldr x11, [x9, x0, lsl #3]; br x11
    let words = [0xd29f_ff09, 0xf2bf_ffe9, 0xf2df_ffe9, 0xf2ff_ffe9, LOAD_X_INDEX, 0xd61f_0160];
    for (index, word) in words.into_iter().enumerate() {
        decode(decoder.as_mut(), word, 0x2000 + 4 * index as u64);
    }
    let table = decoder.jump_table().unwrap();
    assert_eq!(table.slot(0), Some(u64::MAX - 7));
    assert_eq!(table.slot(1), None);
}

fn register_move(wide: bool, destination: u32, source: u32) -> u32 {
    (if wide { 0xaa00_03e0 } else { 0x2a00_03e0 }) | source << 16 | destination
}

fn after(facts: &RegisterFacts, words: &[u32]) -> RegisterFacts {
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decoder.assume(facts);
    for (index, &word) in words.iter().enumerate() {
        decode(decoder.as_mut(), word, 0x1800 + 4 * index as u64);
    }
    decoder.facts().unwrap()
}

#[test]
fn register_copies_keep_the_guard_limit_and_bounded_successor() {
    for compare in [CMP_W0_3, CMP_X0_3] {
        for (condition, taken, entries) in [(8, false, 4), (2, false, 3), (9, true, 4), (3, true, 3)] {
            let (fall, branch) = edges(compare, &[0x1100_0442, 0xb900_0442], condition);
            let (bounded, unbounded) = if taken { (&branch, &fall) } else { (&fall, &branch) };
            for wide in [false, true] {
                let copies = [register_move(wide, 8, 0), register_move(wide, 12, 8), register_move(wide, 8, 12)];
                let copied = after(bounded, &copies);
                let table = dispatch(&copied, &[], LOAD_W_INDEX | 8 << 16).expect("copied index is bounded");
                assert_eq!((table.entries, table.guard, table.alignment), (entries, 0x1000, 4));
                assert_eq!(
                    dispatch(&copied, &[], LOAD_X_INDEX | 8 << 16).is_some(),
                    !wide || compare == CMP_X0_3,
                    "an X copy must not widen a W-only proof"
                );
                let other = after(unbounded, &copies);
                assert_eq!(dispatch(&other, &[], LOAD_W_INDEX | 8 << 16), None);
                assert_eq!(dispatch(&copied.meet(&other), &[], LOAD_W_INDEX | 8 << 16), None);
            }
        }
    }
}

#[test]
fn w_copies_zero_only_the_destination_and_x_copies_preserve_that_proof() {
    let (bounded, _) = edges(CMP_W0_3, &[], 8);
    let copied = after(&bounded, &[register_move(false, 8, 0), register_move(true, 12, 8)]);
    for index in [8, 12] {
        let table = dispatch(&copied, &[], LOAD_X_INDEX | index << 16).unwrap();
        assert_eq!((table.entries, table.guard), (4, 0x1000));
    }
    assert_eq!(dispatch(&copied, &[], LOAD_X_INDEX), None);
    let self_copy = after(&bounded, &[register_move(false, 0, 0)]);
    assert!(dispatch(&self_copy, &[], LOAD_X_INDEX).is_some());

    // A fresh W comparison also relies on the zeroing that survived the X copy.
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decoder.assume(&copied);
    decode(decoder.as_mut(), 0x7100_059f, 0x1900); // cmp w12, #1
    decode(decoder.as_mut(), 0x5400_0809, 0x1904);
    let table = dispatch(&decoder.taken_facts().unwrap(), &[], LOAD_X_INDEX | 12 << 16).unwrap();
    assert_eq!((table.entries, table.guard), (2, 0x1900));

    let foreign_width = after(&bounded, &[register_move(true, 8, 0), register_move(true, 12, 8)]);
    assert_eq!(dispatch(&foreign_width, &[], LOAD_X_INDEX | 12 << 16), None);
    let joined = copied.meet(&foreign_width);
    assert_eq!(dispatch(&joined, &[], LOAD_X_INDEX | 12 << 16), None);
    assert!(dispatch(&joined, &[], LOAD_W_INDEX | 12 << 16).is_some());
}

#[test]
fn copying_over_a_bounded_destination_replaces_rather_than_refines_its_facts() {
    let (bounded, _) = edges(CMP_W0_3, &[], 8);
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decoder.assume(&bounded);
    decode(decoder.as_mut(), 0x7100_051f, 0x1100); // cmp w8, #1
    decode(decoder.as_mut(), 0x5400_0808, 0x1104);
    let two_bounds = decoder.facts().unwrap();
    assert_eq!(dispatch(&two_bounds, &[], LOAD_W_INDEX | 8 << 16).unwrap().entries, 2);
    for wide in [false, true] {
        let overwritten = after(&two_bounds, &[register_move(wide, 8, 0)]);
        let table = dispatch(&overwritten, &[], LOAD_W_INDEX | 8 << 16).unwrap();
        assert_eq!((table.entries, table.guard), (4, 0x1000));
        let unbounded = after(&two_bounds, &[register_move(wide, 8, 1), register_move(wide, 12, 8)]);
        for index in [8, 12] {
            assert_eq!(dispatch(&unbounded, &[], LOAD_W_INDEX | index << 16), None);
        }
    }
}

#[test]
fn copied_bounds_survive_source_writes_but_not_destination_clobbers() {
    let (bounded, _) = edges(CMP_W0_3, &[], 8);
    let copied = after(&bounded, &[register_move(false, 8, 0)]);
    let source_changed = after(&copied, &[0x1100_0400, register_move(true, 12, 8)]); // add w0, w0, #1
    assert_eq!(dispatch(&source_changed, &[], LOAD_W_INDEX), None);
    assert_eq!(dispatch(&source_changed, &[], LOAD_X_INDEX | 12 << 16).unwrap().guard, 0x1000);
    for clobber in [
        0x1100_0508, // add w8, w8, #1
        0x9100_0508, // add x8, x8, #1
        0xb940_0028, // ldr w8, [x1]
        0xf840_8501, // ldr x1, [x8], #8
        0xf280_0028, // movk x8, #1
        register_move(false, 8, 1),
        register_move(true, 8, 1),
        0x9400_0004, // bl .+16
        0xd503_2fff, // unmodelled hint
    ] {
        let changed = after(&copied, &[clobber, register_move(true, 12, 8)]);
        for index in [8, 12] {
            assert_eq!(dispatch(&changed, &[], LOAD_W_INDEX | index << 16), None, "{clobber:#x}");
            assert_eq!(dispatch(&changed, &[], LOAD_X_INDEX | index << 16), None, "{clobber:#x}");
        }
    }
}

#[test]
fn shifted_inverted_and_arithmetic_moves_do_not_copy_bounds() {
    let (bounded, _) = edges(CMP_X0_3, &[], 8);
    for transformed in [
        register_move(false, 8, 0) | 1 << 10, // lsl #1
        register_move(true, 8, 0) | 1 << 22,  // lsr #0, not the audited mov form
        0x2a00_0028,                          // orr w8, w1, w0
        0x2a20_03e8,                          // mvn w8, w0
        0xcb00_03e8,                          // neg x8, x0
        0x9340_7c08,                          // sxtw x8, w0
    ] {
        assert_eq!(dispatch(&bounded, &[transformed], LOAD_W_INDEX | 8 << 16), None, "{transformed:#x}");
        assert_eq!(dispatch(&bounded, &[transformed], LOAD_X_INDEX | 8 << 16), None, "{transformed:#x}");
    }
    // Signed guards admit negative selectors; zeroing a copy must not turn them into table bounds.
    for condition in [10, 11, 12, 13] {
        let (fall, taken) = edges(CMP_W0_3, &[], condition);
        for facts in [fall, taken] {
            assert_eq!(dispatch(&facts, &[register_move(false, 8, 0)], LOAD_X_INDEX | 8 << 16), None);
        }
    }
}

#[test]
fn zero_register_copies_neither_inherit_nor_leave_stale_bounds() {
    let (bounded, _) = edges(CMP_W0_3, &[], 8);
    for wide in [false, true] {
        let overwritten = after(&bounded, &[register_move(false, 8, 0), register_move(wide, 8, 31)]);
        assert_eq!(dispatch(&overwritten, &[], LOAD_W_INDEX | 8 << 16), None);
        assert_eq!(dispatch(&overwritten, &[register_move(true, 12, 8)], LOAD_X_INDEX | 12 << 16), None);
        let discarded = after(&bounded, &[register_move(wide, 31, 0), register_move(wide, 8, 31)]);
        assert_eq!(dispatch(&discarded, &[], LOAD_W_INDEX | 31 << 16), None);
        assert_eq!(dispatch(&discarded, &[], LOAD_W_INDEX | 8 << 16), None);
        assert_eq!(dispatch(&discarded, &[], LOAD_W_INDEX).unwrap().guard, 0x1000);
    }
}

#[test]
fn index_copies_do_not_revive_clobbered_addresses_or_create_pointer_references() {
    for overwrite in [register_move(false, 8, 0), register_move(true, 8, 0), register_move(false, 8, 8)] {
        let mut decoder = decoder_for(Arch::Aarch64).unwrap();
        decode(decoder.as_mut(), 0x1000_8008, 0x1000); // adr x8, 0x2000
        for (index, word) in
            [overwrite, register_move(true, 12, 8), register_move(true, 13, 12)].into_iter().enumerate()
        {
            let instruction = decoder.decode(&word.to_le_bytes(), 0x1004 + index as u64 * 4);
            assert_eq!(instruction.flow, Flow::Next);
            assert_eq!((instruction.data_ref, instruction.accesses, instruction.immediate), (None, false, None));
        }
        assert_eq!(decoder.decode(&0xd61f_01a0u32.to_le_bytes(), 0x1010).flow, Flow::IndirectJump); // br x13
        assert_eq!(decoder.indirect_jump_base(), None);
    }
    // Exact X copies still resolve a genuinely known code pointer, without claiming a data access.
    let mut decoder = decoder_for(Arch::Aarch64).unwrap();
    decode(decoder.as_mut(), 0xd284_0008, 0x1000); // movz x8, #0x2000
    decode(decoder.as_mut(), register_move(true, 12, 8), 0x1004);
    decode(decoder.as_mut(), register_move(true, 13, 12), 0x1008);
    assert_eq!(decoder.decode(&0xd61f_01a0u32.to_le_bytes(), 0x100c).flow, Flow::Jump(0x2000));

    for first_copy in [register_move(false, 12, 8), register_move(false, 8, 8)] {
        decoder.begin_run();
        decode(decoder.as_mut(), 0xd284_0008, 0x1000);
        decode(decoder.as_mut(), first_copy, 0x1004);
        let source = if first_copy & 31 == 8 { 8 } else { 12 };
        decode(decoder.as_mut(), register_move(true, 13, source), 0x1008);
        assert_eq!(decoder.decode(&0xd61f_01a0u32.to_le_bytes(), 0x100c).flow, Flow::IndirectJump);
        assert_eq!(decoder.indirect_jump_base(), None);
    }
}

#[test]
fn a_copy_before_the_guard_does_not_gain_a_retroactive_bound() {
    for wide in [false, true] {
        let (fall, taken) = edges(CMP_W0_3, &[register_move(wide, 8, 0)], 9);
        assert_eq!(dispatch(&fall, &[], LOAD_W_INDEX | 8 << 16), None);
        assert_eq!(dispatch(&taken, &[], LOAD_W_INDEX | 8 << 16), None);
        assert!(dispatch(&taken, &[], LOAD_W_INDEX).is_some());
        assert_eq!(dispatch(&taken, &[], LOAD_X_INDEX), None);
    }
}

#[test]
fn compiled_dispatch_shapes_keep_the_table_and_target_base() {
    // Dispatch words from the freestanding switch_pic C fixtures, with their original PC-relative addresses.
    let inverse =
        [0x2a00_03e9, 0xd503_201f, 0x10f7_fcca, 0xb940_0028, 0x1000_008b, 0x3869_694c, 0x8b0c_096b, 0xd61f_0160];
    let scheduled = [0x2a00_03e8, 0xd503_201f, 0x10f7_fce9, 0x1000_008a, 0x3868_692b, 0x8b0b_094a, 0xd61f_0140];
    for (condition, scheduling, words, start, base) in [
        (9, &[][..], &inverse[..], 0x102d4, 0x102f4),
        (8, &[0x1101_ed08, 0xb900_0428][..], &scheduled[..], 0x102d0, 0x102ec),
    ] {
        let (fall, taken) = edges(0x7100_1c1f, scheduling, condition); // cmp w0, #7
        let mut decoder = decoder_for(Arch::Aarch64).unwrap();
        decoder.assume(if condition == 9 { &taken } else { &fall });
        for (index, &word) in words.iter().enumerate() {
            decode(decoder.as_mut(), word, start + index as u64 * 4);
        }
        assert_eq!(
            decoder.jump_table(),
            Some(JumpTable {
                guard: 0x1000,
                table: 0x274,
                entry_size: 1,
                entries: 8,
                signed: false,
                base: Some(base),
                shift: 2,
                alignment: 4,
                target_width: rampage_arch::TargetWidth::Bits64,
            })
        );
        assert_eq!(decoder.indirect_jump_base(), Some(base));
        assert_eq!(decoder.resolved_flow(), Some(Flow::IndirectJump));
    }
}
