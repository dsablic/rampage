use super::*;
use crate::{Arch, Got};

const GP: u64 = 0x19030;

fn target() -> Target {
    let mut entries = vec![0u64; 16];
    // At -32728($gp) a local entry holds a MIPS16e function (odd), at -32724($gp) a MIPS32 one.
    entries[6] = 0x1021;
    entries[7] = 0x1040;
    Target {
        big_endian: true,
        data_big_endian: true,
        global_pointer: Some(GP),
        got: Some(Got { address: GP - 0x7ff0, entries: entries.into(), local_entries: 13 }),
        mips16: true,
        ..Target::new(Arch::Mips)
    }
}

fn halves(halfwords: &[u16]) -> Vec<u8> {
    halfwords.iter().flat_map(|half| half.to_be_bytes()).collect()
}

#[test]
fn jalx_switches_the_instruction_set_both_ways() {
    let mut decoder = MipsDisassembler::new(&target()).unwrap();
    // MIPS32 `jalx 0x1010`.
    let insn = decoder.decode(&0x7400_0404u32.to_be_bytes(), 0x1000);
    assert_eq!((insn.flow, insn.len), (Flow::Call(0x1010), 4));
    assert_eq!(decoder.code_modes(), [(0x1010, true)]);
    assert_eq!((decoder.instruction_mode(), decoder.instruction_delay_slots()), (Some(false), None));
    // The delay slot is MIPS32 too.
    assert_eq!(decoder.code_mode_at(0x1004), Some(false));

    decoder.set_code_modes(&[(0x1010, true)]);
    decoder.begin_run();
    // MIPS16e `jalx 0x1000`, then its delay slot `nop`, then `jrc $ra`.
    let code = halves(&[0x1c00, 0x0400, 0x6500, 0xe8a0]);
    let insn = decoder.decode(&code, 0x1010);
    assert_eq!((insn.flow, insn.len), (Flow::Call(0x1000), 4));
    assert_eq!(decoder.code_modes(), [(0x1000, false)]);
    assert_eq!((decoder.instruction_mode(), decoder.instruction_delay_slots()), (Some(true), Some(1)));
    assert_eq!(decoder.format(&code, 0x1010), "jalx 0x1000");
    let slot = decoder.decode(&code[4..], 0x1014);
    assert_eq!((slot.flow, slot.len, decoder.instruction_mode()), (Flow::Next, 2, Some(true)));
    let ret = decoder.decode(&code[6..], 0x1016);
    assert_eq!((ret.flow, decoder.instruction_delay_slots()), (Flow::Return, Some(0)));
}

#[test]
fn a_call_through_a_got_entry_enters_the_mode_its_low_bit_names() {
    let mut decoder = MipsDisassembler::new(&target()).unwrap();
    for (offset, callee, mips16) in [(0x9a48u16, 0x1020, true), (0x9a4c, 0x1040, false)] {
        decoder.set_code_modes(&[(0x2000, true)]);
        decoder.begin_function(0x2000);
        // move $v0, $gp; lw $v0, -32728($v0) (or -32724); jalr $v0; move $t9, $v0
        let code = halves(&[0x675c, 0xf030, offset, 0xea40, 0x653a]);
        assert_eq!(decoder.decode(&code, 0x2000).flow, Flow::Next);
        // A local entry holding a function's address is the address the code takes, as for MIPS32.
        let load = decoder.decode(&code[2..], 0x2002);
        assert_eq!((load.data_ref, load.accesses), (Some(callee | u64::from(mips16)), false));
        let call = decoder.decode(&code[6..], 0x2006);
        assert_eq!(call.flow, Flow::Call(callee), "{offset:#x}");
        assert_eq!(decoder.code_modes(), [(callee, mips16)]);
    }
}

#[test]
fn a_mips16e_branch_has_no_delay_slot_and_keeps_its_mode() {
    let mut decoder = MipsDisassembler::new(&target()).unwrap();
    decoder.set_code_modes(&[(0x9a6, true)]);
    decoder.begin_run();
    let insn = decoder.decode(&halves(&[0x2302]), 0x9a6);
    assert_eq!(insn.flow, Flow::ConditionalJump(0x9ac));
    assert_eq!(decoder.instruction_delay_slots(), Some(0));
    assert_eq!(decoder.code_modes(), [(0x9a8, true), (0x9ac, true)]);
}

#[test]
fn a_literal_pool_word_is_data_and_its_value_an_immediate() {
    let mut decoder = MipsDisassembler::new(&target()).unwrap();
    decoder.set_code_modes(&[(0x9a8, true)]);
    decoder.begin_run();
    let insn = decoder.decode_with_memory(&halves(&[0xb306]), 0x9a8, &|address, size| {
        (address == 0x9c0 && size == 4).then_some(0xedb8_8320)
    });
    assert_eq!((insn.data_ref, insn.accesses, insn.immediate), (Some(0x9c0), true, Some(0xedb8_8320)));
}

#[test]
fn the_pc_relative_global_pointer_sequence_resolves_got_loads() {
    let mut decoder = MipsDisassembler::new(&target()).unwrap();
    decoder.set_code_modes(&[(0x980, true)]);
    decoder.begin_function(0x980);
    // li $v0, 2; addiu $v1, $pc, -0x7954; sll $v0, $v0, 16; addu $v0, $v0, $v1 (the global pointer, computed
    // without `$t9`); move $s0, $v0; lw $a2, -0x7fe4($s0)
    let code = halves(&[0xf000, 0x6a02, 0xf6b0, 0x0b0c, 0xf400, 0x3240, 0xe269, 0x6512, 0xf010, 0x98dc]);
    let (mut address, mut offset, mut last) = (0x980, 0, None);
    while offset < code.len() {
        let insn = decoder.decode(&code[offset..], address);
        assert_ne!(insn.flow, Flow::Invalid, "{address:#x}");
        offset += usize::from(insn.len);
        address += u64::from(insn.len);
        last = Some(insn);
    }
    assert_eq!(decoder.format(&code[16..], 0x990), "lw $a2, -0x7fe4($s0)");
    assert_eq!(last.unwrap().data_ref, Some(GP - 0x7fe4));
}
