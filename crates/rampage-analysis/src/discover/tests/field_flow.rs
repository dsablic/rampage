//! Structure-field bases carried across a function's blocks.

use rampage_arch::{Arch, Target, decoder};

use crate::discover::{Program, discover};
use crate::memory::{FlatMemory, Memory};

const BASE: u64 = 0x0800_0000;

/// Thumb code at `BASE`, with mapped (not executable) RAM at 0x20000000.
struct WithRam(FlatMemory);

impl Memory for WithRam {
    fn code_from(&self, address: u64) -> Option<&[u8]> {
        self.0.code_from(address)
    }
    fn is_mapped(&self, address: u64) -> bool {
        self.0.is_mapped(address) || (0x2000_0000..0x2000_1000).contains(&address)
    }
    fn is_executable(&self, address: u64) -> bool {
        self.0.is_executable(address)
    }
    fn immediates_may_be_addresses(&self) -> bool {
        true
    }
    fn code_address(&self, address: u64) -> u64 {
        address & !1
    }
}

fn run(hex: &str) -> Program {
    let bytes = (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()).collect();
    let target = Target { m_profile: true, ..Target::new(Arch::Arm) };
    discover(&WithRam(FlatMemory { base: BASE, bytes }), || decoder(&target).unwrap(), &[BASE])
}

/// push {r4, lr}; ldr r4, =0x20000100; 4: ldrb r0, [r4, #11]; `step`; cmp r0, #0; bne 4; pop {r4, pc}
fn loop_with(step: &str) -> Program {
    run(&format!("10b5034ce07a{step}0028fbd110bd00bf00010020"))
}

#[test]
fn a_base_loaded_before_a_loop_reaches_the_access_inside_it() {
    let program = loop_with("00bf");
    let field = program.field_ref(BASE + 4, 0x2000_010b).expect("the read inside the loop");
    assert_eq!((field.base_site, field.base, field.write, field.width), (BASE + 2, 0x2000_0100, false, 1));
}

#[test]
fn a_base_the_loop_changes_disagrees_at_its_head() {
    // adds r4, #1 in the loop: the back edge brings another base, so the head knows none.
    let program = loop_with("0134");
    assert!(program.field_refs.iter().all(|field| field.from != BASE + 4), "{:?}", program.field_refs);
    assert!(program.xrefs.iter().all(|xref| xref.from != BASE + 4), "{:?}", program.xrefs);
}

#[test]
fn both_arms_of_a_branch_loading_the_same_base_agree_on_it() {
    // push {r4, lr}; cbz r0, a; ldr r4, =X; movs r1, #0; b e; a: ldr r4, =X; movs r1, #1;
    // e: ldrb r0, [r4, #11]; pop {r4, pc}; padding; .word 0x20000100
    let program = run("10b510b1044c002101e0034c0121e07a10bd00bf00bf00bf00010020");
    let field = program.field_ref(BASE + 0xe, 0x2000_010b).expect("the read after the join");
    // Either arm's load set the base; the lower site is reported.
    assert_eq!((field.base_site, field.base), (BASE + 4, 0x2000_0100));
}
