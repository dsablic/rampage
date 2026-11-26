//! Control flow and address tracking of the 32-bit ARM, Thumb and Capstone-backed decoders. Encodings were
//! checked with llvm-mc 22 (m68k, which llvm-mc lacks, against the 68000 manual); each is decoded at 0x1000.

use rampage_arch::{Arch, Flow, Target, decoder};

const AT: u64 = 0x1000;

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap()).collect()
}

fn check(target: Target, cases: &[(&str, Flow)]) {
    let mut decoder = decoder(&target).unwrap();
    for &(hex, expected) in cases {
        decoder.reset();
        let code = bytes(hex);
        let insn = decoder.decode(&code, AT);
        let text = decoder.format(&code, AT);
        assert_eq!(insn.flow, expected, "{:?} {hex} ({text})", target.arch);
        assert_eq!(usize::from(insn.len), code.len(), "{:?} {hex} ({text})", target.arch);
    }
}

fn big_endian(arch: Arch) -> Target {
    Target { big_endian: true, data_big_endian: true, ..Target::new(arch) }
}

#[test]
fn arm() {
    use Flow::*;
    check(
        Target::new(Arch::Arm),
        &[
            ("000000ba", ConditionalJump(0x1008)), // blt
            ("000000eb", Call(0x1008)),            // bl
            ("1eff2fe1", Return),                  // bx lr
            ("1eff2f01", Next),                    // bxeq lr
            ("33ff2fe1", IndirectCall),            // blx r3
            ("1080bde8", Return),                  // pop {r4, pc}
            ("0ef0a0e1", Return),                  // mov pc, lr
            ("03f0a0e1", IndirectJump),            // mov pc, r3
            ("04f05ee2", Return),                  // subs pc, lr, #4
            ("04f05e02", Next),                    // subseq pc, lr, #4
            ("00f1a0e1", IndirectJump),            // lsl pc, r0, #2
            ("0ef1b0e1", IndirectJump),            // lsls pc, lr, #2
            ("028090e8", IndirectJump),            // ldm r0, {r1, pc}
            ("04f09fe5", IndirectJump),            // ldr pc, [pc, #4]
            ("04f09de4", Return),                  // ldr pc, [sp], #4
            ("f000f0e7", Halt),                    // udf
            ("7b0a20e1", Next),                    // bkpt #0xab
            ("70000fe1", Next),                    // hlt #0xf000
        ],
    );
}

#[test]
fn arm_literal_loads() {
    let mut decoder = decoder(&Target::new(Arch::Arm)).unwrap();
    assert_eq!(decoder.decode(&bytes("04009fe5"), AT).data_ref, Some(0x100c)); // ldr r0, [pc, #4]
    assert_eq!(decoder.decode(&bytes("01009fe7"), AT).data_ref, None); // ldr r0, [pc, r1]
}

fn thumb() -> Target {
    Target { thumb: std::iter::once(0..0x10000).collect(), ..Target::new(Arch::Arm) }
}

#[test]
fn thumb_branches() {
    use Flow::*;
    check(
        thumb(),
        &[
            ("00db", ConditionalJump(0x1004)), // blt
            ("00f002f8", Call(0x1008)),        // bl
            ("7047", Return),                  // bx lr
            ("10bd", Return),                  // pop {r4, pc}
            ("00b1", ConditionalJump(0x1004)), // cbz r0
            ("00e0", Jump(0x1004)),            // b
            ("9847", IndirectCall),            // blx r3
            ("5df804fb", Return),              // ldr pc, [sp], #4
            ("f746", Return),                  // mov pc, lr
            ("8746", IndirectJump),            // mov pc, r0
            ("9f44", IndirectJump),            // add pc, r3
            ("def3048f", Return),              // subs pc, lr, #4
            ("90e80280", IndirectJump),        // ldm r0, {r1, pc}
        ],
    );
}

/// A call whose target is the next instruction reads the PC only when the code there takes the return address
/// from the link register; otherwise a function just happens to follow (hello-thumb `bl _Exit`, hello-ppc
/// `bl _start_c`, whose prologue saves the link register through r0).
#[test]
fn a_call_to_the_next_instruction_is_a_call_unless_the_code_there_reads_the_link_register() {
    let cases = [
        (thumb(), "00f000f880b5", Flow::Call(0x1004)), // bl; push {r7, lr}
        (Target::new(Arch::Arm), "ffffffeb", Flow::Call(0x1004)), // bl
        (Target::new(Arch::Arm), "ffffffeb0e00a0e1", Flow::Next), // bl; mov r0, lr
        (Target::new(Arch::Arm), "ffffffeb04e02de5", Flow::Call(0x1004)), // bl; str lr, [sp, #-4]!
        (thumb(), "00f000f87046", Flow::Next),         // bl; mov r0, lr
        (thumb(), "00f000f800bf7046", Flow::Next),     // bl; nop; mov r0, lr
        (big_endian(Arch::PowerPc), "480000057c0802a6", Flow::Call(0x1004)), // bl; mflr r0
        (big_endian(Arch::PowerPc), "480000057fc802a6", Flow::Next), // bl; mflr r30
        (big_endian(Arch::PowerPc), "4800000560000000", Flow::Call(0x1004)), // bl; nop
    ];
    for (target, hex, expected) in cases {
        let mut decoder = decoder(&target).unwrap();
        let code = bytes(hex);
        assert_eq!(decoder.decode(&code, AT).flow, expected, "{:?} {hex} ({})", target.arch, decoder.format(&code, AT));
    }
}

/// With a delay slot, the instruction after a call is the slot's successor: hello-mips `__start` reads the PC with
/// `bal 1f; nop; 1: lui $gp, 2; addiu $gp, $gp, -0x7f4c; addu $gp, $gp, $ra`.
#[test]
fn a_call_past_its_delay_slot_is_to_the_next_instruction() {
    let cases = [
        (big_endian(Arch::Mips), "0411000100000000", "3c1c0002279c80b4039fe021", Flow::Next),
        (big_endian(Arch::Mips), "0411000100000000", "27bdffe0afbf001c", Flow::Call(0x1008)), // sw $ra, 0x1c($sp)
        (big_endian(Arch::Mips), "0411000100000000", "8ffc0000", Flow::Next),                 // lw $gp, 0($ra)
        (big_endian(Arch::Mips), "04110001", "03e0e02127bdffe0", Flow::Next), // delay slot: addu $gp, $ra, $zero
        (big_endian(Arch::Sparc), "4000000201000000", "ae03c017", Flow::Next), // add %o7, %l7, %l7
        (big_endian(Arch::Sparc), "4000000201000000", "9de3bfa0", Flow::Call(0x1008)), // save %sp, -0x60, %sp
    ];
    for (target, call, after, expected) in cases {
        let mut decoder = decoder(&target).unwrap();
        let code = bytes(&format!("{call}{after}"));
        assert_eq!(decoder.decode(&code, AT).flow, expected, "{:?} {call} {after}", target.arch);
    }
}

#[test]
fn thumb_it_blocks_make_their_instructions_conditional() {
    let mut decoder = decoder(&thumb()).unwrap();
    let code = bytes("08bf7047"); // it eq; bxeq lr
    assert_eq!(decoder.decode(&code, AT).flow, Flow::Next);
    assert_eq!(decoder.decode(&code[2..], AT + 2).flow, Flow::Next);
    // Outside the block the same instruction returns.
    assert_eq!(decoder.decode(&code[2..], AT + 0x10).flow, Flow::Return);
}

/// Calls, returns and register-indirect jumps that happen only under a condition say so: a conditional call may
/// not be made, and a conditional return (its flow is `Next`) may leave the function.
#[test]
fn conditional_calls_returns_and_indirect_jumps_are_marked() {
    use Flow::*;
    let cases = [
        (Target::new(Arch::Arm), "0d00001b", Call(0x103c), true), // blne
        (Target::new(Arch::Arm), "0d0000eb", Call(0x103c), false), // bl
        (Target::new(Arch::Arm), "1eff2f01", Next, true),         // bxeq lr
        (Target::new(Arch::Arm), "1eff2fe1", Return, false),      // bx lr
        (Target::new(Arch::Arm), "33ff2f11", IndirectCall, true), // blxne r3
        (Target::new(Arch::Arm), "13ff2f11", Next, true),         // bxne r3
        (Target::new(Arch::Arm), "000000ba", ConditionalJump(0x1008), false), // blt
        (Target::new(Arch::Arm), "0000a013", Next, false),        // movne r0, #0
        (thumb(), "18bf8047", Next, false),                       // it ne (the IT itself)
        (big_endian(Arch::PowerPc), "4c820020", Next, true),      // bnelr
        (big_endian(Arch::PowerPc), "4c820420", Next, true),      // bnectr
        (big_endian(Arch::PowerPc), "4c820421", IndirectCall, true), // bnectrl
        (big_endian(Arch::PowerPc), "4e800421", IndirectCall, false), // bctrl
        (big_endian(Arch::PowerPc), "42400103", Call(0x100), true), // bdzla 0x100
        (big_endian(Arch::PowerPc), "429f0005", Next, false),     // bcl 20, 31, .+4 (reads the PC)
        (big_endian(Arch::Mips), "04910002", Call(0x100c), true), // bgezal $4
        (big_endian(Arch::Mips), "04110002", Call(0x100c), false), // bal
        (big_endian(Arch::S390x), "078e", Next, true),            // ber %r14
        (big_endian(Arch::S390x), "ec18e00064fe", Next, true),    // cibe %r1, 100, 0(%r14)
        (big_endian(Arch::S390x), "07fe", Return, false),         // br %r14
        (big_endian(Arch::S390x), "0700", Next, false),           // bcr 0, %r0 (a nop)
    ];
    for (target, hex, flow, conditional) in cases {
        let mut decoder = decoder(&target).unwrap();
        let code = bytes(hex);
        let insn = decoder.decode(&code, AT);
        let text = decoder.format(&code, AT);
        assert_eq!((insn.flow, insn.conditional), (flow, conditional), "{:?} {hex} ({text})", target.arch);
    }
    // Inside an IT block, Thumb's `bl` and `bx lr` are conditional too.
    let mut decoder = decoder(&thumb()).unwrap();
    let code = bytes("18bf00f002f87047"); // it ne; blne 0x100c; bx lr (outside the one-instruction block)
    assert!(!decoder.decode(&code, AT).conditional);
    let call = decoder.decode(&code[2..], AT + 2);
    assert_eq!((call.flow, call.conditional), (Call(0x100a), true));
    let after = decoder.decode(&code[6..], AT + 6);
    assert_eq!((after.flow, after.conditional), (Return, false));
}

#[test]
fn mips() {
    use Flow::*;
    check(
        big_endian(Arch::Mips),
        &[
            ("0c000402", Call(0x1008)),            // jal
            ("03e00008", Return),                  // jr $ra
            ("0320f809", IndirectCall),            // jalr $25
            ("04110002", Call(0x100c)),            // bal
            ("10800002", ConditionalJump(0x100c)), // beqz $4
            ("10000002", Jump(0x100c)),            // b
            ("04910002", Call(0x100c)),            // bgezal $4
            ("0000000d", Next),                    // break
            ("08000402", Jump(0x1008)),            // j
            ("00800008", IndirectJump),            // jr $4
            ("74000402", IndirectCall),            // jalx 0x1008: MIPS16e or microMIPS, not followed
        ],
    );
}

#[test]
fn powerpc() {
    use Flow::*;
    check(
        big_endian(Arch::PowerPc),
        &[
            ("48000009", Call(0x1008)),            // bl
            ("48000008", Jump(0x1008)),            // b
            ("4e800020", Return),                  // blr
            ("4e800421", IndirectCall),            // bctrl
            ("4e800420", IndirectJump),            // bctr
            ("4c820020", Next),                    // bnelr
            ("41820008", ConditionalJump(0x1008)), // beq
            ("4e800021", IndirectCall),            // blrl
            ("7fe00008", Halt),                    // trap
            ("429f0005", Next),                    // bcl 20, 31, .+4 (reads the PC)
            ("4c820420", Next),                    // bnectr
            ("42400103", Call(0x100)),             // bdzla 0x100
        ],
    );
}

#[test]
fn riscv() {
    use Flow::*;
    check(
        Target::new(Arch::Riscv64),
        &[
            ("ef008000", Call(0x1008)),            // jal ra, 8
            ("ef028000", Call(0x1008)),            // jal t0, 8
            ("6f008000", Jump(0x1008)),            // j 8
            ("67000500", IndirectJump),            // jr a0
            ("e7000500", IndirectCall),            // jalr a0
            ("e7024500", IndirectCall),            // jalr t0, 4(a0)
            ("67030e00", IndirectJump),            // jalr t1, t3, 0 (a PLT stub passing t1)
            ("67800000", Return),                  // ret
            ("6304b500", ConditionalJump(0x1008)), // beq a0, a1, 8
            ("73001000", Next),                    // ebreak
            ("731000c0", Halt),                    // unimp
            ("21a0", Jump(0x1008)),                // c.j 8
            ("8280", Return),                      // c.jr ra
            ("0295", IndirectCall),                // c.jalr a0
            ("0285", IndirectJump),                // c.jr a0
            ("0290", Next),                        // c.ebreak
        ],
    );
    // Zero padding must not decode as code that continues.
    let mut decoder = decoder(&Target::new(Arch::Riscv64)).unwrap();
    assert!(matches!(decoder.decode(&[0, 0], AT).flow, Halt | Invalid));
}

#[test]
fn riscv_branches_render_their_target_address() {
    let mut decoder = decoder(&Target::new(Arch::Riscv64)).unwrap();
    let cases = [
        ("8dc1", "c.beqz a1, 0x1022"),
        ("21a0", "c.j 0x1008"),
        ("e39a54ff", "bne s1, s5, 0xff4"),
        ("ef008000", "jal 0x1008"),
        ("82808280", "c.jr ra"),
    ];
    for (hex, expected) in cases {
        assert_eq!(decoder.format(&bytes(hex), AT), expected, "{hex}");
    }
}

#[test]
fn sparc() {
    use Flow::*;
    check(
        big_endian(Arch::Sparc),
        &[
            ("40000002", Call(0x1008)),            // call
            ("10800002", Jump(0x1008)),            // ba
            ("02800002", ConditionalJump(0x1008)), // be
            ("00800002", Next),                    // bn
            ("9fc04000", IndirectCall),            // call %g1
            ("81c04000", IndirectJump),            // jmp %g1
            ("81c7e008", Return),                  // ret
            ("81c3e008", Return),                  // retl
            ("00000000", Halt),                    // unimp 0
        ],
    );
}

#[test]
fn sparc64_return() {
    check(big_endian(Arch::Sparc64), &[("81cfe008", Flow::Return)]); // return %i7+8
}

#[test]
fn s390x() {
    use Flow::*;
    check(
        big_endian(Arch::S390x),
        &[
            ("c0e500000004", Call(0x1008)),            // brasl %r14
            ("a7e50004", Call(0x1008)),                // bras %r14
            ("0de1", IndirectCall),                    // basr %r14, %r1
            ("07fe", Return),                          // br %r14
            ("078e", Next),                            // ber %r14
            ("07f1", IndirectJump),                    // br %r1
            ("a7f40004", Jump(0x1008)),                // j
            ("c0f400000004", Jump(0x1008)),            // jg
            ("a7840004", ConditionalJump(0x1008)),     // je
            ("0700", Next),                            // bcr 0, %r0 (a nop)
            ("ec18e00064fe", Next),                    // cibe %r1, 100, 0(%r14)
            ("ec1200048076", ConditionalJump(0x1008)), // crje %r1, %r2, 8
        ],
    );
}

#[test]
fn m68k() {
    use Flow::*;
    check(
        big_endian(Arch::M68k),
        &[
            ("61000006", Call(0x1008)),            // bsr.w
            ("6006", Jump(0x1008)),                // bra.b
            ("6706", ConditionalJump(0x1008)),     // beq.b
            ("51c80006", ConditionalJump(0x1008)), // dbra d0
            ("4e75", Return),                      // rts
            ("4e73", Return),                      // rte
            ("4e90", IndirectCall),                // jsr (a0)
            ("4ed0", IndirectJump),                // jmp (a0)
            ("4e4f", Next),                        // trap #15
            ("4afc", Halt),                        // illegal
        ],
    );
}

/// Decodes `hex` as consecutive instructions from 0x1000 with one decoder, like a straight-line run, and returns
/// each instruction's (flow, data reference, immediate).
fn run(target: Target, hex: &str, lengths: &[usize]) -> Vec<(Flow, Option<u64>, Option<u64>)> {
    let mut decoder = decoder(&target).unwrap();
    let code = bytes(hex);
    let mut offset = 0;
    let mut results = Vec::new();
    for &len in lengths {
        let insn = decoder.decode(&code[offset..], AT + offset as u64);
        assert_eq!(usize::from(insn.len), len, "{:?} at +{offset:#x}", target.arch);
        results.push((insn.flow, insn.data_ref, insn.immediate));
        offset += len;
    }
    results
}

/// Each instruction's data reference and whether it loads from or stores to it, rather than forming it.
fn accesses(target: Target, hex: &str, lengths: &[usize]) -> Vec<(Option<u64>, bool)> {
    let mut decoder = decoder(&target).unwrap();
    let code = bytes(hex);
    let mut offset = 0;
    let mut results = Vec::new();
    for &len in lengths {
        let insn = decoder.decode(&code[offset..], AT + offset as u64);
        results.push((insn.data_ref, insn.accesses));
        offset += len;
    }
    results
}

#[test]
fn loads_and_stores_access_their_address_while_formed_addresses_may_be_code() {
    // A32: ldr r0, [pc, #4]; adr r1, 0x1010; str r2, [r1, #4]; .word 0x2000, the value the load reads
    let target = Target::new(Arch::Arm);
    assert_eq!(
        accesses(target.clone(), "04009fe504108fe2042081e500200000", &[4, 4, 4]),
        [(Some(0x100c), true), (Some(0x1010), false), (Some(0x1014), true)]
    );
    assert_eq!(run(target, "04009fe504108fe2042081e500200000", &[4])[0].2, Some(0x2000));
    // Thumb: ldr r0, [pc, #4]; add r0, pc (a pool offset made an address)
    assert_eq!(accesses(thumb(), "0148784400bf00bf00010000", &[2, 2]), [(Some(0x1008), true), (Some(0x1106), false)]);
    // lui $2, 0x41; lw $3, 8($2)
    assert_eq!(accesses(big_endian(Arch::Mips), "3c0200418c430008", &[4, 4])[1], (Some(0x41_0008), true));
    // auipc a0, 1; addi a0, a0, 16; ld a1, 8(a0)
    let results = accesses(Target::new(Arch::Riscv64), "171500001305050183358500", &[4, 4, 4]);
    assert_eq!(results[1..], [(Some(0x2010), false), (Some(0x2018), true)]);
    // larl %r2, 0x1010; lgrl %r2, 0x1010
    let results = accesses(big_endian(Arch::S390x), "c02000000008c42800000008", &[6, 6]);
    assert_eq!(results, [(Some(0x1010), false), (Some(0x1016), true)]);
}

#[test]
fn arm_plt_entries_resolve_their_got_slot() {
    // add ip, pc, #0, #12; add ip, ip, #0x11000; ldr pc, [ip, #0xbe8]!
    let results = run(Target::new(Arch::Arm), "00c08fe211ca8ce2e8fbbce5", &[4, 4, 4]);
    assert_eq!(results[2], (Flow::IndirectJump, Some(0x1008 + 0x11000 + 0xbe8), None));
}

#[test]
fn arm_literal_pool_offsets_become_addresses() {
    // Thumb: ldr r0, [pc, #4]; add r0, pc; nop; nop; .word 0x100
    let results = run(thumb(), "0148784400bf00bf00010000", &[2, 2]);
    assert_eq!(results[0], (Flow::Next, Some(0x1008), Some(0x100)));
    assert_eq!(results[1], (Flow::Next, Some(0x1006 + 0x100), None));
    // A32: movw r0, #0x1234; movt r0, #0x5678
    let results = run(Target::new(Arch::Arm), "340201e3780645e3", &[4, 4]);
    assert_eq!(results[1].2, Some(0x5678_1234));
}

#[test]
fn mips_address_pairs_and_the_global_pointer() {
    // lui $2, 0x41; addiu $2, $2, 0x10; lw $3, 8($2)
    let results = run(big_endian(Arch::Mips), "3c020041244200108c430008", &[4, 4, 4]);
    assert_eq!((results[1].2, results[2].1), (Some(0x41_0010), Some(0x41_0018)));
    // lui $2, 0x41; addu $2, $3, $4; lw $3, 8($2): the add makes $2 unknown.
    let results = run(big_endian(Arch::Mips), "3c020041006410218c430008", &[4, 4, 4]);
    assert_eq!(results[2].1, None);
    // lw $25, -32752($gp) reads a GOT slot.
    let target = Target { global_pointer: Some(0x41_8ff0), ..big_endian(Arch::Mips) };
    assert_eq!(run(target, "8f998010", &[4])[0].1, Some(0x41_1000));
}

/// MIPS PIC code: a run started at a function's entry knows `$t9`, so the `_gp_disp` prologue gives the global
/// pointer, which its callee-saved copy keeps across blocks, calls and a stack spill. Local GOT entries hold pages
/// (completed by `%lo`) or the address itself; a call through an import's entry references the entry.
#[test]
fn mips_pic_global_pointer_follows_the_function() {
    let got = rampage_arch::Got {
        address: 0x11000,
        entries: vec![0, 0x8000_0000, 0x2_0000, 0x2345, 0].into(),
        local_entries: 4,
    };
    let target = Target { global_pointer: Some(0x1_8ff0), got: Some(got), ..big_endian(Arch::Mips) };
    let mut decoder = decoder(&target).unwrap();
    let mut at = AT;
    let mut step = |decoder: &mut Box<dyn rampage_arch::Disassembler>, hex: &str| {
        let insn = decoder.decode(&bytes(hex), at);
        at += 4;
        (insn.flow, insn.data_ref, insn.accesses)
    };
    decoder.begin_function(AT);
    // lui $v0, 1; addiu $v0, $v0, 0x7ff0; addu $s0, $v0, $t9; sw $s0, 16($sp)
    for hex in ["3c020001", "24427ff0", "00598021", "afb00010"] {
        step(&mut decoder, hex);
    }
    // Another block: lw $at, %got(page)($s0); addiu $a0, $at, 0x123
    decoder.reset();
    assert_eq!(step(&mut decoder, "8e018018"), (Flow::Next, Some(0x11008), true));
    assert_eq!(step(&mut decoder, "24240123"), (Flow::Next, Some(0x2_0123), false));
    // lw $a0, %got(local)($s0): the entry holds the address itself.
    assert_eq!(step(&mut decoder, "8e04801c"), (Flow::Next, Some(0x2345), false));
    // lw $t9, %call16(import)($s0); jalr $t9; nop
    assert_eq!(step(&mut decoder, "8e198020"), (Flow::Next, Some(0x11010), true));
    assert_eq!(step(&mut decoder, "0320f809"), (Flow::IndirectCall, Some(0x11010), true));
    step(&mut decoder, "00000000");
    // $s0 survives the call; a reload of the spilled copy is the global pointer too.
    assert_eq!(step(&mut decoder, "8e018018"), (Flow::Next, Some(0x11008), true));
    decoder.reset();
    assert_eq!(step(&mut decoder, "8fa30010").1, None);
    assert_eq!(step(&mut decoder, "8c618018"), (Flow::Next, Some(0x11008), true));
    // The slot is forgotten by an overlapping narrower store (sb $zero, 17($sp)), by a store through $fp, which may
    // alias $sp (sw $zero, 16($fp)), and by a change of its base register (addiu $sp, $sp, -8).
    for clobber in ["a3a00011", "afc00010", "27bdfff8"] {
        step(&mut decoder, "afb00010");
        step(&mut decoder, clobber);
        step(&mut decoder, "8fa30010");
        assert_eq!(step(&mut decoder, "8c618018").1, None, "after {clobber}");
    }
    // A new function forgets them all.
    decoder.begin_run();
    assert_eq!(step(&mut decoder, "8e018018").1, None);
}

/// A run that starts at a block (search, signatures) assumes nothing about `$t9`: GCC's `jr $t9` after a GOT load
/// and a null check stays an indirect jump, not a jump to the block itself; nor does a function run whose first
/// instruction is not its entry.
#[test]
fn mips_block_runs_assume_no_entry_t9() {
    let target = Target { global_pointer: Some(0x1_8ff0), ..big_endian(Arch::Mips) };
    let mut decoder = decoder(&target).unwrap();
    for begin in [None, Some(AT - 0x20)] {
        match begin {
            None => decoder.begin_run(),
            Some(entry) => decoder.begin_function(entry),
        }
        // jr $t9; nop
        assert_eq!(decoder.decode(&bytes("03200008"), AT).flow, Flow::IndirectJump);
    }
    decoder.begin_function(AT);
    assert_eq!(decoder.decode(&bytes("03200008"), AT).flow, Flow::Jump(AT));
}

#[test]
fn riscv_auipc_pairs_and_far_calls() {
    // auipc a0, 1; addi a0, a0, 16; ld a1, 8(a0)
    let results = run(Target::new(Arch::Riscv64), "171500001305050183358500", &[4, 4, 4]);
    assert_eq!((results[1].1, results[2].1), (Some(0x2010), Some(0x2018)));
    // auipc ra, 0; jalr ra, 16(ra)
    let results = run(Target::new(Arch::Riscv64), "97000000e7800001", &[4, 4]);
    assert_eq!(results[1].0, Flow::Call(0x1010));
}

#[test]
fn powerpc_sparc_and_s390x_address_pairs() {
    // lis r3, 0x1001; addi r3, r3, 0x10; lwz r4, 8(r3)
    let results = run(big_endian(Arch::PowerPc), "3c6010013863001080830008", &[4, 4, 4]);
    assert_eq!((results[1].2, results[2].1), (Some(0x1001_0010), Some(0x1001_0018)));
    // sethi %hi(0x12345678), %o0; or %o0, 0x78, %o0; ld [%o0+8], %o1
    let results = run(big_endian(Arch::Sparc), "11048d1590122078d2022008", &[4, 4, 4]);
    assert_eq!((results[1].2, results[2].1), (Some(0x1234_5478), Some(0x1234_5480)));
    // larl %r2, 0x1010
    assert_eq!(run(big_endian(Arch::S390x), "c02000000008", &[6])[0].1, Some(0x1010));
}

#[test]
fn thumb_high_registers_track_the_complete_operand() {
    // movw r1, #0x100; mov r8, r1; add r8, pc; ldr.w r0, [r8, #4]
    let results = run(thumb(), "40f200118846f844d8f80400", &[4, 2, 2, 4]);
    assert_eq!(results[2].1, Some(0x110a));
    assert_eq!(results[3].1, Some(0x110e));
}

#[test]
fn thumb_register_constants_follow_moves_and_calls_but_not_branches() {
    // movs r4, #0x40; str r5, [r4]: a constant base makes the store's address.
    assert_eq!(accesses(thumb(), "40242560", &[2, 2])[1], (Some(0x40), true));
    // movs r4, #0x40; bl; str r5, [r4]: a call preserves r4.
    assert_eq!(accesses(thumb(), "402400f000f82560", &[2, 4, 2])[2], (Some(0x40), true));
    // movs r4, #0x40; b .; str r5, [r4]: the store is reached from elsewhere, with another r4.
    assert_eq!(accesses(thumb(), "4024fee72560", &[2, 2, 2])[2], (None, false));
    // movs r0, #0x40; bl; str r5, [r0]: a call may change r0.
    assert_eq!(accesses(thumb(), "402000f000f80560", &[2, 4, 2])[2], (None, false));
}

#[test]
fn arm_unknown_writes_forget_all_destinations() {
    // movw r0, #0x100; movw r1, #0x200; <write>; add r2, pc, r0; add r2, pc, r1
    for (hex, cleared) in [
        ("920381e0", [true, true]),  // umull r0, r1, r2, r3
        ("100f11ee", [true, false]), // mrc p15, #0, r0, c1, c0, #0
        ("100b51ec", [true, true]),  // vmov r0, r1, d0
        ("910f82e1", [true, false]), // strex r0, r1, [r2]
        ("d800cfe1", [true, true]),  // ldrd r0, r1, [pc, #8]
    ] {
        let code = format!("000100e3001200e3{hex}00208fe001208fe0");
        let results = run(Target::new(Arch::Arm), &code, &[4, 4, 4, 4, 4]);
        for (index, cleared) in cleared.into_iter().enumerate() {
            assert_eq!(results[3 + index].1.is_none(), cleared, "{hex} r{index}");
        }
    }
    // Stores and MCR read Rt, rather than writing it.
    for hex in ["000082e5", "100f01ee"] {
        let code = format!("000100e3{hex}00208fe0");
        assert!(run(Target::new(Arch::Arm), &code, &[4, 4, 4])[2].1.is_some(), "{hex}");
    }
}

#[test]
fn thumb_double_loads_forget_the_explicit_second_register() {
    // movw r0, #0x100; movw r4, #0x200; ldrd r0, r4, [r2, #12]; add r0, pc; add r4, pc
    let results = run(thumb(), "40f2001040f20024d2e9030478447c44", &[4, 4, 4, 2, 2]);
    assert_eq!((results[3].1, results[4].1), (None, None));
}

#[test]
fn thumb_list_instructions_forget_the_writeback_base() {
    for list in ["02c8", "02c0", "01c8"] {
        // movw r0, #0x100; ldm/stm r0!, {...}; add r0, pc
        let results = run(thumb(), &format!("40f20010{list}7844"), &[4, 2, 2]);
        assert_eq!(results[2].1, None, "{list}");
    }
}

#[test]
fn thumb_memory_offsets_scale_by_the_access_size() {
    for (hex, size, offset) in [
        ("d068", 2, 12),
        ("d060", 2, 12),
        ("d088", 2, 6),
        ("d080", 2, 6),
        ("d078", 2, 3),
        ("d070", 2, 3),
        ("d2e90304", 4, 12),
        ("c2e90301", 4, 12),
        ("52e8030f", 4, 12),
    ] {
        // movw r2, #0x100; access through r2
        let results = run(thumb(), &format!("40f20012{hex}"), &[4, size]);
        assert_eq!(results[1].1, Some(0x100 + offset), "{hex}");
    }
    for hex in ["0398", "0390"] {
        // movw r2, #0x100; mov sp, r2; access through sp: SP is never known, so a stack slot is no address.
        let results = run(thumb(), &format!("40f200129546{hex}"), &[4, 2, 2]);
        assert_eq!(results[2].1, None, "{hex}");
    }
}

#[test]
fn arm_register_add_tracks_only_unconditional_unshifted_offsets() {
    for (hex, expected) in [
        ("01008fe0", Some(0x110c)), // add r0, pc, r1
        ("01018fe0", None),         // add r0, pc, r1, lsl #2
        ("61008fe0", None),         // add r0, pc, r1, rrx
        ("01008f00", None),         // addeq r0, pc, r1
    ] {
        let results = run(Target::new(Arch::Arm), &format!("001100e3{hex}00208fe0"), &[4, 4, 4]);
        assert_eq!(results[1].1, expected, "{hex}");
        assert_eq!(results[2].1.is_some(), expected.is_some(), "{hex}");
    }
}

#[test]
fn literal_pools_use_data_byte_order_independently_of_code() {
    for (code_big, data_big) in [(false, false), (true, true), (false, true), (true, false)] {
        let target = Target { big_endian: code_big, data_big_endian: data_big, ..Target::new(Arch::Arm) };
        let load = if code_big { "e59f0000e080000f" } else { "00009fe50f0080e0" };
        let pool = if data_big { "00000100" } else { "00010000" };
        let results = run(target, &format!("{load}{pool}"), &[4, 4]);
        assert_eq!(results[0].2, Some(0x100));
        assert_eq!(results[1].1, Some(0x110c));
    }
}

#[test]
fn literal_loads_to_pc_resolve_jumps_and_instruction_sets() {
    for (target, load, pointer) in [
        (Target::new(Arch::Arm), "00f09fe5", 0x2000u32),
        (Target::new(Arch::Arm), "00f09fe5", 0x2001u32),
        (thumb(), "dff804f0", 0x2000u32),
        (thumb(), "dff804f0", 0x2001u32),
    ] {
        let mut decoder = decoder(&target).unwrap();
        let mut code = bytes(load);
        code.extend_from_slice(&[0; 4]);
        code.extend_from_slice(&pointer.to_le_bytes());
        let insn = decoder.decode(&code, AT);
        assert_eq!(insn.flow, Flow::Jump(0x2000));
        decoder.reset();
        let ret = if pointer & 1 != 0 { bytes("7047") } else { bytes("1eff2fe1") };
        assert_eq!(decoder.decode(&ret, 0x2000).flow, Flow::Return);
    }
}

#[test]
fn powerpc64_toc_pairs_report_only_the_completed_address() {
    let target = Target { global_pointer: Some(0x1000_0000), ..big_endian(Arch::PowerPc64) };
    // addis r3, r2, 1; addi r3, r3, 16
    let results = run(target, "3c62000138630010", &[4, 4]);
    assert_eq!(results[0], (Flow::Next, None, None));
    assert_eq!(results[1], (Flow::Next, Some(0x1001_0010), None));
}

#[test]
fn instruction_addresses_wrap_without_panicking() {
    for (target, code) in [
        (Target::new(Arch::Arm), "0000a0e1"),
        (Target { thumb: std::iter::once(0..u64::MAX).collect(), ..thumb() }, "00bf"),
        (big_endian(Arch::PowerPc), "60000000"),
    ] {
        let mut decoder = decoder(&target).unwrap();
        let code = bytes(code);
        assert_eq!(decoder.decode(&code, u64::MAX - 1).flow, Flow::Next);
        assert!(!decoder.format(&code, u64::MAX - 1).is_empty());
    }
}

#[test]
fn conditional_thumb_adds_forget_the_written_address() {
    // movw r0, #0x100; it eq; addeq r0, pc; add r0, pc
    let results = run(thumb(), "40f2001008bf78447844", &[4, 2, 2, 2]);
    assert_eq!((results[2].1, results[3].1), (None, None));
}

#[test]
fn unreadable_literal_jump_targets_stay_indirect() {
    for target in [Target::new(Arch::Arm), thumb()] {
        let code = if target.is_thumb(AT) { "dff804f0" } else { "00f09fe5" };
        for trailing in 0..8 {
            let mut bytes = bytes(code);
            bytes.resize(bytes.len() + trailing, 0);
            let mut decoder = decoder(&target).unwrap();
            let insn = decoder.decode(&bytes, AT);
            assert_eq!(insn.flow, Flow::IndirectJump, "{code}, {trailing} trailing bytes");
            assert_eq!(insn.immediate, None);
        }
    }
}

#[test]
fn arm_register_moves_do_not_preserve_shifted_values() {
    // movw r1, #0x100; mov/shift r0, r1; add r0, pc
    for (instruction, preserved) in [("0100a0e1", true), ("6100a0e1", false), ("0101a0e1", false)] {
        let results = run(Target::new(Arch::Arm), &format!("001100e3{instruction}0f0080e0"), &[4, 4, 4]);
        assert_eq!(results[2].1.is_some(), preserved, "{instruction}");
    }
}

#[test]
fn every_thumb_halfword_decodes_safely_at_the_address_boundary() {
    for big_endian in [false, true] {
        let target = Target {
            big_endian,
            data_big_endian: big_endian,
            thumb: std::iter::once(0..u64::MAX).collect(),
            ..Target::new(Arch::Arm)
        };
        let mut decoder = decoder(&target).unwrap();
        for halfword in 0..=u16::MAX {
            let code = if big_endian { halfword.to_be_bytes() } else { halfword.to_le_bytes() };
            decoder.reset();
            decoder.set_code_modes(&[]);
            let insn = decoder.decode(&code, u64::MAX - 1);
            assert!(matches!(insn.len, 2 | 4));
            let _ = decoder.format(&code, u64::MAX - 1);
        }
    }
}

#[test]
fn thumb_high_register_writes_and_comparisons_leave_low_registers_known() {
    // movw r0, #256; movw r8, #512; add r8, pc / cmp r0, r8; add r0, pc
    for instruction in ["f844", "4045"] {
        let results = run(thumb(), &format!("40f2001040f20028{instruction}7844"), &[4, 4, 2, 2]);
        assert_eq!(results[3].1, Some(0x110e), "{instruction}");
    }
}

#[test]
fn vector_and_system_register_writes_preserve_their_core_sources() {
    // movw r0, #256; vmov/vmsr from r0; add r2, pc, r0
    for instruction in ["100a00ee", "100b41ec", "100ae1ee"] {
        let results = run(Target::new(Arch::Arm), &format!("000100e3{instruction}00208fe0"), &[4, 4, 4]);
        assert_eq!(results[2].1, Some(0x1110), "{instruction}");
    }
}

#[test]
fn blx_to_the_next_address_still_switches_instruction_sets() {
    let mut decoder = decoder(&Target::new(Arch::Arm)).unwrap();
    assert_eq!(decoder.decode(&bytes("fffffffa"), AT).flow, Flow::Call(AT + 4));
    assert_eq!(decoder.decode(&bytes("7047"), AT + 4).flow, Flow::Return);
}

#[test]
fn sequential_thumb_decoding_formats_in_its_original_mode() {
    let mut decoder = decoder(&Target::new(Arch::Arm)).unwrap();
    decoder.set_code_modes(&[(0x2000, true)]);
    decoder.decode(&bytes("00bf"), 0x2000);
    assert_eq!(decoder.decode(&bytes("7047"), 0x2002).flow, Flow::Return);
    assert_eq!(decoder.format(&bytes("7047"), 0x2002), "bx lr");
}

#[test]
fn sequential_decoding_respects_loader_mode_boundaries() {
    let target = Target { thumb: std::iter::once(0x1000..0x1004).collect(), ..Target::new(Arch::Arm) };
    for instruction in ["7047", "00bf", "01d0"] {
        let mut decoder = decoder(&target).unwrap();
        decoder.decode(&bytes("00bf"), 0x1000);
        decoder.decode(&bytes(instruction), 0x1002);
        assert_eq!(decoder.decode(&bytes("1eff2fe1"), 0x1004).flow, Flow::Return);
    }
}

#[test]
fn thumb_sp_add_reads_the_high_destination_and_forgets_its_unknown_sum() {
    // movw r0,#256; movw r8,#512; add r8,sp,r8; add r0,pc; add r8,pc
    let results = run(thumb(), "40f2001040f20028e8447844f844", &[4, 4, 2, 2, 2]);
    assert_eq!(results[3].1, Some(0x110e));
    assert_eq!(results[4].1, None);
}

#[test]
fn vector_duplicate_preserves_its_core_register_source() {
    let results = run(Target::new(Arch::Arm), "000100e3100bc0ee00208fe0", &[4, 4, 4]);
    assert_eq!(results[2].1, Some(0x1110));
}

#[test]
fn implicit_sp_writes_do_not_reuse_the_old_stack_address() {
    // movw r2,#256; mov sp,r2; add/sub sp,#4 or push/pop; ldr r0,[sp]
    for instruction in ["01b0", "81b0", "01b4", "01bc"] {
        let results = run(thumb(), &format!("40f200129546{instruction}0098"), &[4, 2, 2, 2]);
        assert_eq!(results[3].1, None, "{instruction}");
    }
}

#[test]
fn invalid_thumb_instructions_keep_the_mode_for_formatting_and_the_next_address() {
    let mut decoder = decoder(&Target::new(Arch::Arm)).unwrap();
    decoder.set_code_modes(&[(0x2000, true)]);
    decoder.decode(&bytes("00bf"), 0x2000);
    let code = bytes("00b87047");
    let invalid = decoder.decode(&code, 0x2002);
    assert_eq!((invalid.flow, invalid.len), (Flow::Invalid, 2));
    assert_eq!(decoder.format(&code, 0x2002), "(bad)");
    assert_eq!(decoder.decode(&code[2..], 0x2004).flow, Flow::Return);
}

#[test]
fn invalid_thumb_instructions_advance_the_remaining_it_slots() {
    let mut decoder = decoder(&thumb()).unwrap();
    decoder.decode(&bytes("04bf"), AT);
    assert_eq!(decoder.decode(&bytes("00b8"), AT + 2).flow, Flow::Invalid);
    assert_eq!(decoder.decode(&bytes("7047"), AT + 4).flow, Flow::Next);
    assert_eq!(decoder.format(&bytes("7047"), AT + 4), "bxeq lr");
}

/// Each instruction's base-relative access: the base register's origin when its address is a known base plus an
/// immediate offset.
fn base_accesses(target: Target, hex: &str, lengths: &[usize]) -> Vec<Option<rampage_arch::BaseAccess>> {
    let mut decoder = decoder(&target).unwrap();
    let code = bytes(hex);
    let mut offset = 0;
    let mut results = Vec::new();
    for &len in lengths {
        decoder.decode(&code[offset..], AT + offset as u64);
        results.push(decoder.base_access());
        offset += len;
    }
    results
}

#[test]
fn loads_and_stores_through_a_pool_base_name_the_base_and_its_origin() {
    use rampage_arch::BaseAccess;
    // ldr r1, [pc, #4] (0x20000100); ldrb r0, [r1, #11]; strb r0, [r1, #4]; nop; .word 0x20000100
    let code = "0149c87a087100bf00010020";
    let base = |write| Some(BaseAccess { site: AT, base: 0x2000_0100, write, width: 1 });
    assert_eq!(base_accesses(thumb(), code, &[2, 2, 2]), [None, base(false), base(true)]);
    assert_eq!(accesses(thumb(), code, &[2, 2, 2])[1..], [(Some(0x2000_010b), true), (Some(0x2000_0104), true)]);
    // ldr r1, [pc, #4]; adds r1, #8; ldrh r0, [r1, #2]: the base moves with the add, its origin stays the load.
    let results = base_accesses(thumb(), "014908314888000000010020", &[2, 2, 2]);
    assert_eq!(results[2], Some(BaseAccess { site: AT, base: 0x2000_0108, write: false, width: 2 }));
    // movw r1, #0x100; movt r1, #0x2000; ldr r0, [r1, #8]: the MOVT completes the base.
    let results = base_accesses(thumb(), "40f20011c2f20001886800bf", &[4, 4, 2]);
    assert_eq!(results[2], Some(BaseAccess { site: AT + 4, base: 0x2000_0100, write: false, width: 4 }));
    // movs r1, #64; ldrb r0, [r1, #11]: a small constant is no base; ldr r0, [sp, #4] is a stack slot.
    assert_eq!(base_accesses(thumb(), "4021c87a0198", &[2, 2, 2]), [None, None, None]);
    // ldr r1, [pc, #4]; ldr r1, [r2]; ldrb r0, [r1, #11]: the base is overwritten first.
    assert_eq!(base_accesses(thumb(), "01491168c87a00bf00010020", &[2, 2, 2])[2], None);
    // MIPS: lui $2, 0x41; addiu $2, $2, 0x10; lw $3, 8($2): the completed pair is a base; lui alone is half of one.
    let results = base_accesses(big_endian(Arch::Mips), "3c020041244200108c430008", &[4, 4, 4]);
    assert_eq!(results[2], Some(BaseAccess { site: AT + 4, base: 0x41_0010, write: false, width: 4 }));
    assert_eq!(base_accesses(big_endian(Arch::Mips), "3c0200418c430008", &[4, 4])[1], None);
    // RISC-V: auipc a0, 1; addi a0, a0, 16; ld a1, 8(a0).
    let results = base_accesses(Target::new(Arch::Riscv64), "171500001305050183358500", &[4, 4, 4]);
    assert_eq!(results[2], Some(BaseAccess { site: AT + 4, base: 0x2010, write: false, width: 8 }));
}

/// A load from the pool base 0x20000100 that the literal-pool load at `site` set, `width` bytes.
fn pool_read(site: u64, width: u8) -> Option<rampage_arch::BaseAccess> {
    Some(rampage_arch::BaseAccess { site, base: 0x2000_0100, write: false, width })
}

#[test]
fn writeback_and_post_indexed_accesses_through_a_base() {
    // T32: ldr r1, =0x20000100; ldr r0, [r1, #4]! (accesses base+4, then the base moves); ldrb r2, [r1, #11]
    let results = base_accesses(thumb(), "014951f8040dca7a00010020", &[2, 4, 2]);
    assert_eq!(results, [None, pool_read(AT, 4), None]);
    // T32 post-indexed: ldr r0, [r1], #4 reads the base itself, not base+4, and moves it.
    assert_eq!(base_accesses(thumb(), "014951f8040bca7a00010020", &[2, 4, 2]), [None, None, None]);
    // A32: ldr r1, [pc, #4]; ldr r0, [r1, #4]!; ldrb r2, [r1, #11]; .word 0x20000100
    let results = base_accesses(Target::new(Arch::Arm), "04109fe50400b1e50b20d1e500010020", &[4, 4, 4]);
    assert_eq!(results, [None, pool_read(AT, 4), None]);
}

#[test]
fn a_call_keeps_callee_saved_bases_and_forgets_the_others() {
    // ldr r4, =0x20000100; ldr r0, =0x20000200; bl; ldrb r2, [r4, #11]; ldrb r2, [r0, #11]
    let code = "024c034800f000f8e27ac27a0001002000020020";
    let results = base_accesses(thumb(), code, &[2, 2, 4, 2, 2]);
    assert_eq!(results[3..], [pool_read(AT, 1), None]);
}

#[test]
fn bases_a_conditional_load_or_a_register_list_sets_are_not_known() {
    // it eq; ldreq r1, =0x20000100; ldrb r0, [r1, #11]
    assert_eq!(base_accesses(thumb(), "08bf0149c87a00bf00010020", &[2, 2, 2])[2], None);
    // ldr r1, =0x20000100; pop {r1} / ldm r2!, {r1}; ldrb r0, [r1, #11]
    for list in ["02bc", "02ca"] {
        let results = base_accesses(thumb(), &format!("0149{list}c87a00bf00010020"), &[2, 2, 2]);
        assert_eq!(results[2], None, "{list}");
    }
}

#[test]
fn negative_offsets_reach_below_the_base() {
    // T32: ldr r1, =0x20000100; ldrb.w r0, [r1, #-4]
    let code = "014911f8040c00bf00010020";
    assert_eq!(base_accesses(thumb(), code, &[2, 4])[1], pool_read(AT, 1));
    assert_eq!(accesses(thumb(), code, &[2, 4])[1], (Some(0x2000_00fc), true));
    // A32: ldr r1, [pc, #0]; ldrb r0, [r1, #-4] (U=0); .word 0x20000100
    let code = "00109fe5040051e500010020";
    assert_eq!(base_accesses(Target::new(Arch::Arm), code, &[4, 4])[1], pool_read(AT, 1));
    assert_eq!(accesses(Target::new(Arch::Arm), code, &[4, 4])[1], (Some(0x2000_00fc), true));
}

#[test]
fn doubleword_and_exclusive_accesses_have_their_widths() {
    use rampage_arch::BaseAccess;
    // ldr r1, =0x20000100; ldrd r2, r3, [r1, #8]; strd r2, r3, [r1, #8]; ldrex r0, [r1, #4]; strex r2, r0, [r1, #4]
    let code = "0449d1e90223c1e9022351e8010f41e8010200bf00010020";
    let results = base_accesses(thumb(), code, &[2, 4, 4, 4, 4]);
    let at = |write, width| Some(BaseAccess { site: AT, base: 0x2000_0100, write, width });
    assert_eq!(results[1..], [at(false, 8), at(true, 8), at(false, 4), at(true, 4)]);
    let addresses: Vec<Option<u64>> =
        accesses(thumb(), code, &[2, 4, 4, 4, 4])[1..].iter().map(|(address, _)| *address).collect();
    assert_eq!(addresses, [Some(0x2000_0108), Some(0x2000_0108), Some(0x2000_0104), Some(0x2000_0104)]);
}

#[test]
fn the_stack_pointer_is_never_a_base() {
    // ldr r0, =0x20001000; mov sp, r0; mov r1, sp; ldrb r2, [r1, #11]; ldrb r2, [sp, #12] (T32)
    let code = "024885466946ca7a9df80c2000100020";
    assert_eq!(base_accesses(thumb(), code, &[2, 2, 2, 2, 4]), [None, None, None, None, None]);
    assert_eq!(accesses(thumb(), code, &[2, 2, 2, 2, 4])[3..], [(None, false), (None, false)]);
}

#[test]
fn thumb_sums_of_plain_constants_are_not_kept() {
    // movs r1, #64; adds r1, #8; ldrb r0, [r1, #3]: no base, and no address either.
    assert_eq!(accesses(thumb(), "40210831c878", &[2, 2, 2])[2], (None, false));
}
