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
