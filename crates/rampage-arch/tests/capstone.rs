//! Control flow of the Capstone-backed architectures. Encodings were checked with llvm-mc 22 (m68k, which llvm-mc
//! lacks, against the 68000 manual); every instruction is decoded at 0x1000.

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
    Target { big_endian: true, ..Target::new(arch) }
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
            ("04f09fe5", IndirectJump),            // ldr pc, [pc, #4]
            ("04f09de4", Return),                  // ldr pc, [sp], #4
            ("f000f0e7", Halt),                    // udf
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
        ],
    );
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
            ("0000000d", Halt),                    // break
            ("08000402", Jump(0x1008)),            // j
            ("00800008", IndirectJump),            // jr $4
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
            ("73001000", Halt),                    // ebreak
            ("21a0", Jump(0x1008)),                // c.j 8
            ("8280", Return),                      // c.jr ra
            ("0295", IndirectCall),                // c.jalr a0
            ("0285", IndirectJump),                // c.jr a0
            ("0290", Halt),                        // c.ebreak
        ],
    );
    // Zero padding must not decode as code that continues.
    let mut decoder = decoder(&Target::new(Arch::Riscv64)).unwrap();
    assert!(matches!(decoder.decode(&[0, 0], AT).flow, Halt | Invalid));
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
