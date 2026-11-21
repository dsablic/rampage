use super::*;

fn bytes(halfwords: &[u16], big_endian: bool) -> Vec<u8> {
    halfwords.iter().flat_map(|&half| if big_endian { half.to_be_bytes() } else { half.to_le_bytes() }).collect()
}

fn text(halfwords: &[u16], address: u64) -> String {
    let decoded = decode(&bytes(halfwords, true), address, true, None).unwrap();
    assert_eq!(usize::from(decoded.len), halfwords.len() * 2, "{halfwords:04x?}");
    // The byte order is the image's: little-endian bytes decode the same instruction.
    assert_eq!(decode(&bytes(halfwords, false), address, false, None).unwrap(), decoded);
    decoded.text()
}

/// Each instruction as GCC 12 emitted it (`-mips16`) and GNU objdump 2.40 disassembles it, in rampage's register and
/// immediate spelling.
#[test]
fn instructions_match_gnu_objdump() {
    let cases: &[(u64, &[u16], &str)] = &[
        (0x980, &[0xf000, 0x6a02], "li $v0, 2"),
        (0x984, &[0xf6b0, 0x0b0c], "addiu $v1, $pc, -0x7954"),
        (0x988, &[0xf400, 0x3240], "sll $v0, $v0, 0x10"),
        (0x98c, &[0xe269], "addu $v0, $v0, $v1"),
        (0x98e, &[0x659a], "move $gp, $v0"),
        (0x990, &[0x67dc], "move $a2, $gp"),
        (0x992, &[0x6d00], "li $a1, 0"),
        (0x994, &[0xf010, 0x9edc], "lw $a2, -0x7fe4($a2)"),
        (0x998, &[0xf0c2, 0x4e00], "addiu $a2, 0x10c0"),
        (0x9a2, &[0xeb4c], "and $v1, $v0"),
        (0x9a4, &[0x3246], "srl $v0, $v0, 1"),
        (0x9a6, &[0x2302], "beqz $v1, 0x9ac"),
        (0x9a8, &[0xb306], "lw $v1, 0x18($pc)"),
        (0x9aa, &[0xea6e], "xor $v0, $v1"),
        (0x9ac, &[0x4cff], "addiu $a0, -1"),
        (0x9ae, &[0x2cf8], "bnez $a0, 0x9a0"),
        (0x9b2, &[0xde40], "sw $v0, 0($a2)"),
        (0x9b6, &[0xf100, 0x7500], "cmpi $a1, 0x100"),
        (0x9ba, &[0x61f0], "btnez 0x99c"),
        (0x9bc, &[0xe8a0], "jrc $ra"),
        (0x9be, &[0x6500], "nop"),
        (0xa1c, &[0x3384], "sll $v1, $a0, 1"),
        (0xa22, &[0xe820], "jr $ra"),
        (0xa24, &[0xe3cb], "subu $v0, $v1, $a2"),
        (0xa70, &[0x64f5], "save 40, $ra, $s0-$s1"),
        (0xa72, &[0x671c], "move $s0, $gp"),
        (0xa7c, &[0xd204], "sw $v0, 0x10($sp)"),
        (0xa82, &[0xf3a1, 0x4d08], "addiu $a1, 0xba8"),
        (0xa86, &[0xea40], "jalr $v0"),
        (0xa88, &[0x653a], "move $t9, $v0"),
        (0xa8a, &[0x9604], "lw $a2, 0x10($sp)"),
        (0xac0, &[0x6475], "restore 40, $ra, $s0-$s1"),
        (0xac2, &[0xf180, 0x6a14], "li $v0, 0x194"),
        (0xae4, &[0x41a7], "addiu $a1, $s1, 7"),
        (0xabc, &[0xe840], "jalr $s0"),
        (0x73e, &[0xf004, 0x64fa], "save $a0, 80, $ra, $s0-$s1"),
        (0x756, &[0x5202], "slti $v0, 2"),
        (0x75a, &[0x614a], "btnez 0x7f0"),
        (0x7b8, &[0xe879], "multu $s0, $v1"),
        (0x7c2, &[0xed10], "mfhi $a1"),
        (0x7e8, &[0xea0a], "cmp $v0, $s0"),
        (0x4005b8, &[0x1a00, 0x01e0], "jal 0x400780"),
        (0x4005e8, &[0x1e00, 0x01ec], "jalx 0x4007b0"),
    ];
    for &(address, halfwords, expected) in cases {
        assert_eq!(text(halfwords, address), expected, "{address:#x}");
    }
}

#[test]
fn pc_relative_instructions_take_the_aligned_address_or_the_jump_in_whose_delay_slot_they_are() {
    let la = decode(&bytes(&[0xf6b0, 0x0b0c], true), 0x984, true, None).unwrap();
    assert_eq!(la.effect, Effect::PcAddress { to: 3, address: 0xffff_9030 });
    let literal = decode(&bytes(&[0xb306], true), 0x9a8, true, None).unwrap();
    assert_eq!(literal.effect, Effect::PcLoad { to: 3, address: 0x9c0 });
    // At 0x9aa the base would be 0x9a8 as well; in the delay slot of a jump at 0x9a2 it is 0x9a0.
    let in_slot = decode(&bytes(&[0xb306], true), 0x9aa, true, Some(0x9a2)).unwrap();
    assert_eq!(in_slot.effect, Effect::PcLoad { to: 3, address: 0x9b8 });
}

#[test]
fn control_flow_and_delay_slots() {
    let decoded = |halfwords: &[u16], address| decode(&bytes(halfwords, true), address, true, None).unwrap();
    let jal = decoded(&[0x1a00, 0x01e0], 0x4005b8);
    assert_eq!((jal.control, jal.delay_slots), (Control::Call { target: 0x400780, exchange: false }, 1));
    let jalx = decoded(&[0x1e00, 0x01ec], 0x4005e8);
    assert_eq!(jalx.control, Control::Call { target: 0x4007b0, exchange: true });
    assert_eq!((decoded(&[0xe8a0], 0).control, decoded(&[0xe8a0], 0).delay_slots), (Control::Return, 0));
    assert_eq!((decoded(&[0xe820], 0).control, decoded(&[0xe820], 0).delay_slots), (Control::Return, 1));
    let jalr = decoded(&[0xea40], 0);
    assert_eq!((jalr.control, jalr.delay_slots), (Control::Register { register: 2, link: true }, 1));
    let branch = decoded(&[0x2302], 0x9a6);
    assert_eq!((branch.control, branch.delay_slots), (Control::Branch { target: 0x9ac, conditional: true }, 0));
    let b = decoded(&[0x17fe], 0x100);
    assert_eq!(b.control, Control::Branch { target: 0x100 - 2, conditional: false });
}

#[test]
fn reserved_and_64_bit_encodings_do_not_decode() {
    for halfwords in [
        &[0x3801][..],     // ld (64-bit)
        &[0x7800],         // sd
        &[0xf800],         // I64
        &[0xe000],         // daddu
        &[0x6600],         // reserved I8 function 6
        &[0xe8e0],         // jalrc through $ra
        &[0xf000, 0xf000], // EXTEND before EXTEND
        &[0xf000, 0x1a00], // EXTEND before jal
        &[0xf000, 0xe269], // EXTEND before addu
        &[0xf000, 0x6a22], // extended li with bits 7:5 set
        &[0xf000],         // a lone EXTEND at the end of the bytes
        &[0x1a00],         // a lone jal half
    ] {
        assert_eq!(decode(&bytes(halfwords, true), 0x1000, true, None), None, "{halfwords:04x?}");
    }
}

/// Every 16-bit value, alone and after an `EXTEND`, decodes or is refused without panicking, and a decoded
/// instruction always has a length the bytes hold.
#[test]
fn every_encoding_decodes_or_is_refused() {
    for first in 0..=u16::MAX {
        for second in [0x0000, 0x6a02, 0xffff, first] {
            let data = bytes(&[first, second], true);
            if let Some(decoded) = decode(&data, 0x7fff_fffe, true, None) {
                assert!(matches!(decoded.len, 2 | 4));
                assert!(!decoded.text().is_empty());
            }
        }
    }
}
