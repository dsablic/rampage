use rampage_arch::{Arch, Flow, Target, decoder};

fn run(words: &[u32], read: &dyn Fn(u64, u8) -> Option<u64>) -> Vec<Flow> {
    let mut decoder = decoder(&Target::new(Arch::Aarch64)).unwrap();
    words
        .iter()
        .enumerate()
        .map(|(index, word)| decoder.decode_with_memory(&word.to_le_bytes(), 0x1000 + index as u64 * 4, read).flow)
        .collect()
}

#[test]
fn aarch64_follows_adr_load_and_register_branch_only_with_readable_memory() {
    let words = [0x1001_0008, 0xf940_0108, 0xd61f_0100];
    let flows = run(&words, &|at, size| (at == 0x3000 && size == 8).then_some(0x4000));
    assert_eq!(flows[2], Flow::Jump(0x4000));
    for value in [None, Some(0), Some(0x4001)] {
        assert_eq!(run(&words, &|_, _| value)[2], Flow::IndirectJump);
    }
}

#[test]
fn aarch64_follows_constant_moves_but_forgets_clobbered_registers() {
    // mov x8,#0x1010; mov x9,x8; blr x9; br x8
    let flows = run(&[0xd282_0208, 0xaa08_03e9, 0xd63f_0120, 0xd61f_0100], &|_, _| None);
    assert_eq!(flows[2], Flow::Call(0x1010));
    assert_eq!(flows[3], Flow::IndirectJump);
    // mov x8,#0x1010; add x8,x0,x1; br x8
    assert_eq!(run(&[0xd282_0208, 0x8b01_0008, 0xd61f_0100], &|_, _| None)[2], Flow::IndirectJump);
}

#[test]
fn stores_invalidate_captured_memory_before_later_loads() {
    let flows = run(&[0x1001_0008, 0xd282_0409, 0xf900_0109, 0xf940_010a, 0xd61f_0140], &|_, _| Some(0x4000));
    assert_eq!(flows[4], Flow::IndirectJump);
}

#[test]
fn atomic_writes_also_invalidate_captured_memory() {
    assert_eq!(
        run(&[0x1001_0008, 0xd280_0029, 0xf829_010b, 0xf940_010a, 0xd61f_0140], &|_, _| Some(0x4000))[4],
        Flow::IndirectJump
    );
}

#[test]
fn vector_stores_invalidate_memory_inference() {
    assert_eq!(run(&[0x1001_0008, 0xe580_4100, 0xf940_010a, 0xd61f_0140], &|_, _| Some(0x4000))[3], Flow::IndirectJump);
}

#[test]
fn aarch64_literal_loads_access_their_slot_and_yield_the_constant_read_there() {
    let mut decoder = decoder(&Target::new(Arch::Aarch64)).unwrap();
    let read = |at: u64, size: u8| (at == 0x1008 && size == 8).then_some(0x4000);
    // ldr x0, 0x1008; adr x0, 0x100c; ldr x1, [x0, #8]
    let insns: Vec<_> = [0x5800_0040u32, 0x1000_0040, 0xf940_0401]
        .iter()
        .enumerate()
        .map(|(index, word)| decoder.decode_with_memory(&word.to_le_bytes(), 0x1000 + index as u64 * 4, &read))
        .collect();
    assert_eq!((insns[0].data_ref, insns[0].accesses, insns[0].immediate), (Some(0x1008), true, Some(0x4000)));
    assert_eq!((insns[1].data_ref, insns[1].accesses, insns[1].immediate), (Some(0x100c), false, None));
    assert_eq!((insns[2].data_ref, insns[2].accesses), (Some(0x1014), true));
}

#[test]
fn block_resets_do_not_restore_memory_trust_but_new_runs_do() {
    let mut decoder = decoder(&Target::new(Arch::Aarch64)).unwrap();
    decoder.decode(&0xf900_0109u32.to_le_bytes(), 0x1000);
    decoder.reset();
    let sequence = [0x1001_0008u32, 0xf940_010a, 0xd61f_0140];
    for (index, word) in sequence.iter().enumerate() {
        let insn = decoder.decode_with_memory(&word.to_le_bytes(), 0x1000 + index as u64 * 4, &|_, _| Some(0x4000));
        if index == 2 {
            assert_eq!(insn.flow, Flow::IndirectJump);
        }
    }
    decoder.begin_run();
    for (index, word) in sequence.iter().enumerate() {
        let insn = decoder.decode_with_memory(&word.to_le_bytes(), 0x1000 + index as u64 * 4, &|_, _| Some(0x4000));
        if index == 2 {
            assert_eq!(insn.flow, Flow::Jump(0x4000));
        }
    }
}

/// Decodes `words` from 0x1000 in one run, resetting before the word at `reset`, and returns the switch table the
/// last one dispatches through.
fn jump_table(words: &[u32], reset: Option<usize>) -> Option<rampage_arch::JumpTable> {
    let mut decoder = decoder(&Target::new(Arch::Aarch64)).unwrap();
    for (index, word) in words.iter().enumerate() {
        if reset == Some(index) {
            decoder.reset();
        }
        decoder.decode(&word.to_le_bytes(), 0x1000 + index as u64 * 4);
    }
    decoder.jump_table()
}

#[test]
fn aarch64_describes_the_bounded_switch_table_a_register_jump_dispatches_through() {
    // sub w9, w9, #1; cmp w9, #12; b.hi 0x1100; adr x8, 0x200c; adr x10, 0x1010; ldrsw x11, [x8, x9, lsl #2];
    // add x10, x10, x11; br x10
    let words =
        [0x5100_0529, 0x7100_313f, 0x5400_07c8, 0x1000_8008, 0x1000_000a, 0xb8a9_790b, 0x8b0b_014a, 0xd61f_0140];
    let table = jump_table(&words, None).unwrap();
    let expected = rampage_arch::JumpTable {
        guard: 0x1004,
        table: 0x200c,
        entry_size: 4,
        entries: 13,
        signed: true,
        base: Some(0x1010),
        shift: 0,
        alignment: 4,
        target_width: rampage_arch::TargetWidth::Bits64,
    };
    assert_eq!(table, expected);
    assert_eq!(table.target(0xffff_fff0), Some(0x1000));
    assert_eq!(table.target(2), None);
    assert_eq!(table.slot(12), Some(0x203c));
    // A join after the conditional branch forgets the bound.
    assert_eq!(jump_table(&words, Some(3)), None);
    // Without the subtraction, x9's upper half is unknown and the comparison bounds only w9.
    assert_eq!(jump_table(&words[1..], None), None);
    // cmp w9, #4096 allows more entries than are ever read.
    let mut huge = words;
    huge[1] = 0x7140_053f;
    assert_eq!(jump_table(&huge, None), None);
    huge[1] = 0x713f_fd3f;
    assert_eq!(jump_table(&huge, None).map(|table| table.entries), Some(4096));
}

/// A switch on `w<index>` with `between` after its bounding branch: `sub; cmp; b.hi; between; adr x8; adr x10;
/// ldrsw x11, [x8, x<index>, lsl #2]; add x10, x10, x11; br x10`.
fn switch_with(index: u32, between: u32) -> Option<rampage_arch::JumpTable> {
    let bound = [0x5100_0400 | index << 5 | index, 0x7100_301f | index << 5, 0x5400_07c8];
    let dispatch = [0x1000_8008, 0x1000_000a, 0xb8a0_790b | index << 16, 0x8b0b_014a, 0xd61f_0140];
    let words: Vec<u32> = bound.into_iter().chain([between]).chain(dispatch).collect();
    jump_table(&words, None)
}

#[test]
fn instructions_writing_the_index_without_naming_it_forget_its_bound() {
    const NOP: u32 = 0xd503_201f;
    for index in [2, 9, 16, 17, 30] {
        assert!(switch_with(index, NOP).is_some(), "x{index}");
    }
    let forms = [
        (9, 0xf83f_d002, "ld64b x2, [x0] writes x2..x9"),
        (9, 0x1929_8001, "swpp x1, x9, [x0]"),
        (9, 0x1929_a001, "rcwswpp x1, x9, [x0]"),
        (9, 0xd52b_7769, "gcsss2 x9"),
        (16, 0xd503_251f, "chkfeat x16"),
        (17, 0xd503_211f, "pacia1716"),
        (30, 0xd503_233f, "paciasp"),
        (30, 0xd503_20ff, "xpaclri"),
        (9, 0xd9c0_0923, "ldapr x3, [x9], #8"),
        (9, 0xd944_0923, "ldiapp x3, x4, [x9], #16"),
    ];
    let kept: Vec<_> = forms.iter().filter(|(index, word, _)| switch_with(*index, *word).is_some()).collect();
    assert!(kept.is_empty(), "{kept:?}");
}

#[test]
fn instructions_with_unmodelled_register_writes_forget_every_bound() {
    let forms = [(0xd503_2fff, "hint #0x7f"), (0xd4a0_0001, "dcps1"), (0xd4e0_0000, "tenter #0")];
    let kept: Vec<_> = forms.iter().filter(|(word, _)| switch_with(2, *word).is_some()).collect();
    assert!(kept.is_empty(), "{kept:?}");
    // Audited hints and system instructions that write nothing keep it.
    for (word, form) in [(0xd503_241f, "bti"), (0xd508_7500, "ic iallu"), (0xd503_3fdf, "isb")] {
        assert!(switch_with(2, word).is_some(), "{form}");
    }
}
