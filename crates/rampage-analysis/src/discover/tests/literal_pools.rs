use rampage_arch::{Arch, decoder_for};

use crate::discover::{Program, Xref, XrefKind, discover};
use crate::memory::FlatMemory;

const BASE: u64 = 0x10000;
const BX_LR: u32 = 0xe12f_ff1e;

/// A32 code at `BASE`, which images based this high treat immediates in as possible addresses.
fn run(words: &[u32]) -> Program {
    let bytes = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    discover(&FlatMemory { base: BASE, bytes }, || decoder_for(Arch::Arm).unwrap(), &[BASE])
}

#[test]
fn a_literal_load_seeds_the_function_its_pool_word_points_at_but_not_the_pool() {
    // 0: ldr r0, [pc, #4]; 4: bx lr; 8: 0; c: .word 0x10010 (decodes as `andeq`); 10: bx lr
    let program = run(&[0xe59f_0004, BX_LR, 0, 0x0001_0010, BX_LR]);
    assert!(program.function_at(BASE + 0x10).is_some());
    assert!(program.function_at(BASE + 0xc).is_none());
    assert!(program.xrefs_to(BASE + 0xc).contains(&Xref { to: BASE + 0xc, from: BASE, kind: XrefKind::Data }));
}

#[test]
fn an_address_formed_into_code_still_seeds_a_function() {
    // 0: adr r0, 0x10010; 4: bx lr; 8, c: 0; 10: bx lr
    let program = run(&[0xe28f_0008, BX_LR, 0, 0, BX_LR]);
    assert!(program.function_at(BASE + 0x10).is_some());
}

#[test]
fn an_address_formed_into_a_pool_the_function_loads_from_is_data() {
    // 0: adr r2, 0x1000c; 4: ldr r1, [pc, #0] (0x1000c); 8: bx lr; c: .word 0 (decodes as `andeq`)
    let program = run(&[0xe28f_2004, 0xe59f_1000, BX_LR, 0]);
    assert!(program.function_at(BASE + 0xc).is_none());
    assert_eq!(program.xrefs_to(BASE + 0xc).len(), 2);
}
