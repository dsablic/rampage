//! Inverse bounds and scheduled comparisons through discovery's must-dataflow.

use rampage_arch::{Arch, MAX_JUMP_TABLE_ENTRIES, decoder_for};

use super::{DATA, Image, NOP, RET, RODATA, adr};
use crate::discover::{Program, Xref, XrefKind, discover};

fn branch(from: u64, to: u64, condition: u32) -> u32 {
    0x5400_0000 | ((to.wrapping_sub(from) as u32 >> 2) & 0x7_ffff) << 5 | condition
}

fn jump(from: u64, to: u64) -> u32 {
    0x1400_0000 | ((to.wrapping_sub(from) as u32 >> 2) & 0x3ff_ffff)
}

fn code(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn run(image: &Image) -> Program {
    discover(image, || decoder_for(Arch::Aarch64).unwrap(), &[0])
}

struct Fixture {
    image: Image,
    jump: u64,
    dispatch: u64,
    cases: [u64; 4],
}

impl Fixture {
    fn new(compare: u32, condition: u32, scheduled: &[u32], after_guard: &[u32]) -> Self {
        let inverse = matches!(condition, 3 | 9);
        let mut words = vec![compare];
        words.extend_from_slice(scheduled);
        let guard_branch = words.len();
        words.push(NOP);
        if inverse {
            words.push(RET);
        }
        words.extend_from_slice(after_guard);
        let dispatch = words.len() as u64 * 4;
        let cases = std::array::from_fn(|index| dispatch + 20 + index as u64 * 4);
        words.extend([
            adr(9, dispatch, RODATA),
            adr(10, dispatch + 4, cases[0]),
            0x3860_492b, // ldrb w11, [x9, w0, uxtw]
            0x8b0b_094a, // add x10, x10, x11, lsl #2
            0xd61f_0140, // br x10
        ]);
        words.extend([RET; 4]);
        let default = words.len() as u64 * 4;
        words.push(RET);
        let target = if inverse { (guard_branch as u64 + 2) * 4 } else { default };
        words[guard_branch] = branch(guard_branch as u64 * 4, target, condition);
        Self {
            image: Image { code: code(&words), rodata: vec![0, 1, 2, 3], data: vec![] },
            jump: dispatch + 16,
            dispatch,
            cases,
        }
    }

    fn put(&mut self, at: u64, word: u32) {
        let at = at as usize;
        self.image.code[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }

    fn resolved(&self) -> bool {
        run(&self.image).function_at(0).unwrap().switch_cases(self.jump).is_some()
    }
}

#[test]
fn a64_inverse_bounds_resolve_taken_dispatches_and_keep_guard_and_table_order() {
    for (compare, condition) in [(0x7100_0c1f, 9), (0x7100_101f, 3), (0xf100_0c1f, 9), (0xf100_101f, 3)] {
        let mut fixture = Fixture::new(compare, condition, &[NOP, 0x9100_0421], &[]);
        fixture.image.rodata = vec![2, 0, 2, 3];
        let program = run(&fixture.image);
        let function = program.function_at(0).unwrap();
        let switch = function.switches.iter().find(|switch| switch.jump == fixture.jump).expect("inverse bound");
        let cases = fixture.cases;
        assert_eq!(switch.table, [cases[2], cases[0], cases[2], cases[3]]);
        assert_eq!(switch.cases, [cases[0], cases[2], cases[3]]);
        assert_eq!(switch.guard, 0);
        for &case in &switch.cases {
            assert!(function.contains(case) || program.function_at(case).is_some());
            assert!(program.xrefs.contains(&Xref { to: case, from: fixture.jump, kind: XrefKind::Jump }));
        }
    }
}

#[test]
fn a64_scheduled_comparisons_resolve_but_flags_and_alias_writes_invalidate_them() {
    for condition in [8, 9] {
        assert!(Fixture::new(0x7100_0c1f, condition, &[NOP, 0x9100_0421], &[]).resolved());
        for scheduled in [
            0x3100_0421, // adds w1, w1, #1
            0x1e60_2000, // fcmp d0, d0
            0xd51b_4201, // msr NZCV, x1
            0x7100_0c3f, // cmp w1, #3
            0x1100_0400, // add w0, w0, #1
            0x9100_0400, // add x0, x0, #1
            0xf840_8401, // ldr x1, [x0], #8
            0x9400_0001, // bl .+4, without a get-PC read
            0xd503_2fff, // unknown hint
        ] {
            assert!(!Fixture::new(0x7100_0c1f, condition, &[scheduled, NOP], &[]).resolved(), "{scheduled:#x}");
        }
        // Once the edge proved a bound, a later flags write does not revoke it; an index write does.
        assert!(Fixture::new(0x7100_0c1f, condition, &[], &[0x3100_0421]).resolved());
        for write in [0x1100_0400, 0x9100_0400] {
            assert!(!Fixture::new(0x7100_0c1f, condition, &[], &[write]).resolved());
        }
    }
}

#[test]
fn a64_inverse_bounds_cannot_leak_to_a_default_edge_joining_the_dispatch() {
    for condition in [9, 3] {
        let compare = if condition == 9 { 0x7100_0c1f } else { 0x7100_101f };
        let mut fixture = Fixture::new(compare, condition, &[], &[]);
        assert!(fixture.resolved());
        // The out-of-range fall-through at 8 also enters the dispatch. Only one incoming edge is bounded.
        fixture.put(8, jump(8, fixture.dispatch));
        assert!(!fixture.resolved());
        // Both outcomes of the conditional branch now enter the same block directly.
        fixture.put(4, branch(4, 8, condition));
        assert!(!fixture.resolved());
    }
}

#[test]
fn a64_a_weaker_inverse_guard_preserves_the_existing_four_entry_switch() {
    for (condition, branch) in [(9, 0x5400_0049), (3, 0x5400_0043)] {
        for (compare, load) in [(0x7100_0c1f, 0x3860_492b), (0xf100_0c1f, 0x3860_692b)] {
            let mut fixture = Fixture::new(compare, 8, &[], &[0x7140_041f, branch, RET]);
            fixture.put(fixture.dispatch + 8, load);
            assert!(fixture.resolved(), "{compare:#x} condition {condition}");
            let program = run(&fixture.image);
            let switch = program.function_at(0).unwrap().switches.iter().find(|s| s.jump == fixture.jump).unwrap();
            assert_eq!(switch.guard, 0);
            assert_eq!(switch.table, fixture.cases);
        }
    }
    // A tighter W-view limit must not replace the proof that the whole X index is bounded.
    let mut fixture = Fixture::new(0xf100_0c1f, 8, &[], &[0x7100_041f, 0x5400_0049, RET]);
    fixture.put(fixture.dispatch + 8, 0x3860_692b); // ldrb w11, [x9, x0]
    assert!(fixture.resolved());
    assert_eq!(run(&fixture.image).function_at(0).unwrap().switches[0].guard, 0);
}

#[test]
fn a64_pending_comparisons_cross_blocks_only_when_identical_on_every_path() {
    // cmp w0, #3; cbz w1, 0x10; other; b 0x14; nop; b.ls 0x20; ret; nop; dispatch; cases.
    let cases = [0x34, 0x38, 0x3c, 0x40];
    let run_other = |other: u32| {
        let words = [
            0x7100_0c1f,
            0x3400_0061,
            other,
            jump(0xc, 0x14),
            NOP,
            branch(0x14, 0x20, 9),
            RET,
            NOP,
            adr(9, 0x20, RODATA),
            adr(10, 0x24, cases[0]),
            0x3860_492b,
            0x8b0b_094a,
            0xd61f_0140,
            RET,
            RET,
            RET,
            RET,
        ];
        run(&Image { code: code(&words), rodata: vec![0, 1, 2, 3], data: vec![] })
    };
    let program = run_other(NOP);
    let switch = &program.function_at(0).unwrap().switches[0];
    assert_eq!((switch.guard, switch.jump), (0, 0x30));
    assert_eq!(switch.table, cases);
    for other in [0x3100_0442, 0x7100_081f, 0x1100_0400, 0x9100_0400] {
        // Flag write, conflicting comparison, or W/X index write on only one of the incoming paths.
        assert!(run_other(other).function_at(0).unwrap().switches.is_empty(), "{other:#x}");
    }
}

#[test]
fn a64_inverse_bounds_and_bases_must_survive_all_dispatch_paths() {
    let cases = [0x28, 0x2c, 0x30, 0x34];
    let run_other = |other: u32| {
        let words = [
            0x7100_0c1f,
            branch(4, 0xc, 9),
            RET,
            adr(9, 0xc, RODATA),
            0x3400_0041, // cbz w1, 0x18
            other,
            adr(10, 0x18, cases[0]),
            0x3860_492b,
            0x8b0b_094a,
            0xd61f_0140,
            RET,
            RET,
            RET,
            RET,
        ];
        let rodata = [vec![0, 1, 2, 3], vec![0; 12], vec![0, 1, 2, 3]].concat();
        run(&Image { code: code(&words), rodata, data: vec![] })
    };
    assert_eq!(run_other(NOP).function_at(0).unwrap().switch_cases(0x24), Some(&cases[..]));
    for other in [adr(9, 0x14, RODATA + 16), 0x1100_0400, 0x9100_0400] {
        assert_eq!(run_other(other).function_at(0).unwrap().switch_cases(0x24), None, "{other:#x}");
    }
}

#[test]
fn a64_inverse_bounds_are_rechecked_after_case_backedges_are_discovered() {
    // cmp w0, #3; b.ls dispatch; ret; dispatch; four cases; case 0 loops to dispatch.
    let cases = [0x20, 0x28, 0x2c, 0x30];
    let run_case = |write: u32| {
        let words = [
            0x7100_0c1f,
            branch(4, 0xc, 9),
            RET,
            adr(9, 0xc, RODATA),
            adr(10, 0x10, 0),
            0x3860_492b,
            0x8b0b_094a,
            0xd61f_0140,
            write,
            jump(0x24, 0xc),
            RET,
            RET,
            RET,
        ];
        let rodata = cases.iter().map(|case| (case / 4) as u8).collect();
        run(&Image { code: code(&words), rodata, data: vec![] })
    };
    assert_eq!(run_case(NOP).function_at(0).unwrap().switch_cases(0x1c), Some(&cases[..]));
    for write in [0x1100_0400, 0x9100_0400] {
        assert_eq!(run_case(write).function_at(0).unwrap().switch_cases(0x1c), None, "{write:#x}");
    }
}

#[test]
fn a64_inverse_tables_require_readonly_backing_and_every_aligned_code_target() {
    let fixture = || Fixture::new(0x7100_0c1f, 9, &[NOP], &[]);
    let mut writable = fixture();
    writable.put(writable.dispatch, adr(9, writable.dispatch, DATA));
    writable.image.data = std::mem::take(&mut writable.image.rodata);
    assert!(!writable.resolved());
    let mut truncated = fixture();
    truncated.image.rodata.pop();
    assert!(!truncated.resolved());
    let mut outside = fixture();
    outside.image.rodata[3] = 0xff;
    assert!(!outside.resolved());
    let mut undecodable = fixture();
    undecodable.put(undecodable.cases[3], 0xffff_ffff);
    assert!(!undecodable.resolved());
    for bad in [1, u64::MAX - 1, 0x10000] {
        let mut absolute = fixture();
        absolute.put(absolute.dispatch + 8, 0xf860_592b); // ldr x11, [x9, w0, uxtw #3]
        absolute.put(absolute.dispatch + 12, NOP);
        absolute.put(absolute.jump, 0xd61f_0160); // br x11
        absolute.image.rodata = absolute.cases.iter().flat_map(|case| case.to_le_bytes()).collect();
        assert!(absolute.resolved());
        absolute.image.rodata[24..32].copy_from_slice(&bad.to_le_bytes());
        assert!(!absolute.resolved(), "{bad:#x}");
    }
}

#[test]
fn a64_inverse_bounds_enforce_the_entry_budget_without_unsigned_underflow() {
    for (compare, condition, resolves) in [
        (0x713f_fc1f, 9, true),  // <= 4095: 4096 entries
        (0x7140_041f, 9, false), // <= 4096: over budget
        (0x7140_041f, 3, true),  // < 4096: 4096 entries
        (0x717f_fc1f, 3, false), // < (4095 << 12): over budget
        (0x7100_001f, 3, false), // < 0: no wrapping subtraction
    ] {
        let mut fixture = Fixture::new(compare, condition, &[NOP], &[]);
        fixture.image.rodata = vec![0; MAX_JUMP_TABLE_ENTRIES as usize + 1];
        assert_eq!(fixture.resolved(), resolves, "{compare:#x} condition {condition}");
    }
}
