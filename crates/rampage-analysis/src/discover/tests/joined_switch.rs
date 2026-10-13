//! Switches whose index bound, index copy or table base is set up in another block than the jump.

use std::collections::HashMap;

use rampage_arch::{Arch, decoder_for};

use super::{BOUND, Image, NOP as A64_NOP, RET as A64_RET, RODATA, adr, relative_entries};
use crate::discover::{Program, discover};

/// x86 code assembled from byte pieces, with rel32 branches and RIP-relative operands patched to labels.
#[derive(Default)]
struct Asm {
    code: Vec<u8>,
    labels: HashMap<&'static str, u64>,
    branches: Vec<(usize, &'static str)>,
}

impl Asm {
    fn bytes(mut self, bytes: &[u8]) -> Self {
        self.code.extend_from_slice(bytes);
        self
    }

    fn label(mut self, name: &'static str) -> Self {
        self.labels.insert(name, self.code.len() as u64);
        self
    }

    /// `opcode` followed by a rel32 to `label`.
    fn branch(mut self, opcode: &[u8], label: &'static str) -> Self {
        self.code.extend_from_slice(opcode);
        self.branches.push((self.code.len(), label));
        self.code.extend([0; 4]);
        self
    }

    /// `opcode` followed by a disp32 that a RIP-relative operand turns into `target`.
    fn rip(mut self, opcode: &[u8], target: u64) -> Self {
        let end = (self.code.len() + opcode.len() + 4) as u64;
        self.code.extend_from_slice(opcode);
        self.code.extend((target.wrapping_sub(end) as u32).to_le_bytes());
        self
    }

    /// Four cases and the default, each a `ret`.
    fn cases(self) -> Self {
        CASES.iter().fold(self, |asm, &case| asm.label(case).bytes(&[0xc3])).label("default").bytes(&[0xc3])
    }

    fn at(&self, label: &str) -> u64 {
        self.labels[label]
    }

    fn assemble(mut self) -> (Vec<u8>, HashMap<&'static str, u64>) {
        for &(at, label) in &self.branches {
            let offset = self.labels[label].wrapping_sub(at as u64 + 4) as u32;
            self.code[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        (self.code, self.labels)
    }
}

const CASES: [&str; 4] = ["case0", "case1", "case2", "case3"];
const JA: [u8; 2] = [0x0f, 0x87];
const JE: [u8; 2] = [0x0f, 0x84];
const JMP: [u8; 1] = [0xe9];
const CALL: [u8; 1] = [0xe8];
const RET: u8 = 0xc3;
const NOP: u8 = 0x90;
/// test esi, esi
const TEST: [u8; 2] = [0x85, 0xf6];
/// mov edi, edi
const ZERO_EXTEND: [u8; 2] = [0x89, 0xff];
/// cmp edi, 3
const CMP_EDI: [u8; 3] = [0x83, 0xff, 3];
/// jmp qword [rdi*8 + RODATA]
const JMP_RDI: [u8; 7] = [0xff, 0x24, 0xfd, 0, 0, 1, 0];
/// lea r15, [rip + ...]
const LEA_R15: [u8; 3] = [0x4c, 0x8d, 0x3d];
/// movsxd rax, dword [r15 + rdi*4]; add rax, r15
const RELATIVE_R15: [u8; 7] = [0x49, 0x63, 0x04, 0xbf, 0x4c, 0x01, 0xf8];
/// lea r11, [rip + ...]
const LEA_R11: [u8; 3] = [0x4c, 0x8d, 0x1d];
/// movsxd rax, dword [r11 + rdi*4]; add rax, r11
const RELATIVE_R11: [u8; 7] = [0x49, 0x63, 0x04, 0xbb, 0x4c, 0x01, 0xd8];
/// jmp rax
const JMP_RAX: [u8; 2] = [0xff, 0xe0];

/// The resolved case targets of the jump at `label` in the function at 0.
fn cases(arch: Arch, asm: Asm, rodata: impl Fn(&HashMap<&str, u64>) -> Vec<u8>, jump: &str) -> Option<Vec<u64>> {
    let jump = asm.at(jump);
    let (code, labels) = asm.assemble();
    let image = Image { code, rodata: rodata(&labels), data: vec![] };
    let program: Program = discover(&image, || decoder_for(arch).unwrap(), &[0]);
    program.function_at(0).unwrap().switch_cases(jump).map(<[u64]>::to_vec)
}

fn expected(labels: &HashMap<&str, u64>) -> Vec<u64> {
    CASES.iter().map(|case| labels[case]).collect()
}

fn absolute(labels: &HashMap<&str, u64>) -> Vec<u8> {
    CASES.iter().flat_map(|case| labels[case].to_le_bytes()).collect()
}

fn relative(labels: &HashMap<&str, u64>) -> Vec<u8> {
    CASES.iter().flat_map(|case| (labels[case].wrapping_sub(RODATA) as u32).to_le_bytes()).collect()
}

/// printf_core's shape: `mov r12d, edi; mov r13d, edi`, a join, then `cmp r12d, 3; ja default` and a jump through
/// r13. `before_join` runs on the fall-through path into the join, `after_guard` between a second join and the jump.
fn copied_index(before_join: &[u8], after_guard: &[u8]) -> Asm {
    Asm::default()
        .bytes(&[0x41, 0x89, 0xfc, 0x41, 0x89, 0xfd])
        .bytes(&TEST)
        .branch(&JE, "join")
        .bytes(before_join)
        .label("join")
        .bytes(&[0x41, 0x83, 0xfc, 3])
        .branch(&JA, "default")
        .bytes(&TEST)
        .branch(&JE, "dispatch")
        .bytes(after_guard)
        .label("dispatch")
        .bytes(&[0x42, 0xff, 0x24, 0xed, 0, 0, 1, 0])
        .cases()
}

#[test]
fn an_aarch64_table_base_formed_before_a_join_reaches_the_jump_when_every_path_forms_it() {
    use super::CASES;
    // 0: adr x9, table; 4: adr x10, 0x28; 8: cbz w1, 0x10; c: `other`; 10: cmp w0, #3; 14: b.hi 0x38;
    // 18: ldrb w11, [x9, w0, uxtw]; 1c: add x10, x10, w11, lsl #2; 20: br x10; 24: nop; 28..3c: ret.
    let cases = |other: u32| {
        let mut words = vec![adr(9, 0, RODATA), adr(10, 4, CASES[0]), 0x3400_0001 | 2 << 5, other];
        words.extend([BOUND[0], 0x5400_0128, 0x3860_492b, 0x8b0b_094a, 0xd61f_0140, A64_NOP]);
        words.extend([A64_RET; 5]);
        let code = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let table = relative_entries(CASES[0], 2, 1);
        let image = Image { code, rodata: [&table[..], &[0; 12], &table].concat(), data: vec![] };
        let program = discover(&image, || decoder_for(Arch::Aarch64).unwrap(), &[0]);
        program.function_at(0).unwrap().switch_cases(0x20).map(<[u64]>::to_vec)
    };
    assert_eq!(cases(A64_NOP), Some(CASES.to_vec()));
    // adr x9, a second copy of the table on one path: the base differs on one edge into the join.
    assert_eq!(cases(adr(9, 0xc, RODATA + 16)), None);
}

#[test]
fn a_switch_resolved_across_joins_keeps_its_table_order_and_its_guard_in_an_earlier_block() {
    let asm = copied_index(&[NOP], &[NOP]);
    let (guard, jump) = (asm.at("join"), asm.at("dispatch"));
    let (code, labels) = asm.assemble();
    let order = ["case2", "case0", "case0", "case3"];
    let rodata = order.iter().flat_map(|case| labels[case].to_le_bytes()).collect();
    let image = Image { code, rodata, data: vec![] };
    let program = discover(&image, || decoder_for(Arch::X86_64).unwrap(), &[0]);
    let function = program.function_at(0).unwrap();
    let switch = function.switches.iter().find(|switch| switch.jump == jump).expect("resolved");
    assert_eq!(switch.table, order.map(|case| labels[case]));
    assert_eq!(switch.cases, ["case0", "case2", "case3"].map(|case| labels[case]));
    // cmp r12d, 3 starts the block after the first join; the jump follows a second join.
    assert_eq!(switch.guard, guard);
}

#[test]
fn a_bound_on_one_copy_of_the_index_reaches_a_jump_through_another_across_joins() {
    let jump = |before_join: &[u8], after_guard: &[u8]| {
        let asm = copied_index(before_join, after_guard);
        let (_, labels) = copied_index(before_join, after_guard).assemble();
        cases(Arch::X86_64, asm, absolute, "dispatch").map(|cases| (cases, expected(&labels)))
    };
    let (found, wanted) = jump(&[NOP], &[NOP]).expect("resolved");
    assert_eq!(found, wanted);
    // mov r13d, esi on one path into the first join: r13 is not a copy of r12 on every path.
    assert_eq!(jump(&[0x41, 0x89, 0xf5], &[NOP]), None);
    // inc r13d between the guard and the jump, on one path.
    assert_eq!(jump(&[NOP], &[0x41, 0xff, 0xc5]), None);
    // mov r12d, esi redefines the compared copy before the guard on one path; r13 is no longer bounded through it.
    assert_eq!(jump(&[0x41, 0x89, 0xf4], &[NOP]), None);
}

#[test]
fn a_branch_from_another_function_into_the_dispatch_path_keeps_the_switch_unresolved() {
    let asm = copied_index(&[NOP], &[NOP]).label("other").branch(&JMP, "dispatch");
    let other = asm.at("other");
    let jump = asm.at("dispatch");
    let (code, labels) = asm.assemble();
    let image = Image { code, rodata: absolute(&labels), data: vec![] };
    let program = discover(&image, || decoder_for(Arch::X86_64).unwrap(), &[0, other]);
    assert_eq!(program.function_at(0).unwrap().switch_cases(jump), None);
}

/// A table base loaded into r15 on each of two paths into a join, followed by a bounded relative dispatch.
fn joined_base(second_table: u64) -> Asm {
    Asm::default()
        .bytes(&ZERO_EXTEND)
        .rip(&LEA_R15, RODATA)
        .bytes(&TEST)
        .branch(&JE, "join")
        .rip(&LEA_R15, second_table)
        .label("join")
        .bytes(&CMP_EDI)
        .branch(&JA, "default")
        .bytes(&RELATIVE_R15)
        .label("dispatch")
        .bytes(&JMP_RAX)
        .cases()
}

#[test]
fn a_table_base_must_be_the_same_on_every_path_into_the_dispatch() {
    let jump = |second_table: u64| {
        let (_, labels) = joined_base(second_table).assemble();
        let rodata = |labels: &HashMap<&str, u64>| [relative(labels), relative(labels)].concat();
        cases(Arch::X86_64, joined_base(second_table), rodata, "dispatch").map(|cases| (cases, expected(&labels)))
    };
    let (found, wanted) = jump(RODATA).expect("resolved");
    assert_eq!(found, wanted);
    // The other path loads a second, equally valid copy of the table: the base differs on one incoming edge.
    assert_eq!(jump(RODATA + 16), None);
}

/// hello-x64.exe's shape: a table base loaded before a loop whose body calls a function, bounded inside the loop.
fn base_before_loop(base: (&[u8], &[u8]), case0: &[u8]) -> Asm {
    Asm::default()
        .rip(base.0, RODATA)
        .label("loop")
        .branch(&CALL, "helper")
        // mov edi, eax
        .bytes(&[0x89, 0xc7])
        .bytes(&CMP_EDI)
        .branch(&JA, "default")
        .bytes(base.1)
        .label("dispatch")
        .bytes(&JMP_RAX)
        .label("case0")
        .bytes(case0)
        .branch(&JMP, "loop")
        .label("case1")
        .bytes(&[RET])
        .label("case2")
        .bytes(&[RET])
        .label("case3")
        .bytes(&[RET])
        .label("default")
        .bytes(&[RET])
        .label("helper")
        .bytes(&[RET])
}

#[test]
fn a_table_base_set_before_a_loop_survives_calls_in_callee_saved_registers() {
    let r15 = (&LEA_R15[..], &RELATIVE_R15[..]);
    let jump = |base: (&[u8], &[u8]), case0: &[u8]| {
        let (_, labels) = base_before_loop(base, case0).assemble();
        cases(Arch::X86_64, base_before_loop(base, case0), relative, "dispatch").map(|cases| (cases, expected(&labels)))
    };
    let (found, wanted) = jump(r15, &[NOP]).expect("resolved");
    assert_eq!(found, wanted);
    // A case that loops back after `mov r15d, 5` changes the base on the back edge.
    assert_eq!(jump(r15, &[0x41, 0xbf, 5, 0, 0, 0]), None);
    // A base in r11, which a call may change.
    assert_eq!(jump((&LEA_R11, &RELATIVE_R11), &[NOP]), None);
}

/// `mov edi, edi; cmp edi, 3; ja default`, then a loop head that jumps through the table; case 0 runs `case0` and
/// jumps back to the loop head.
fn guard_before_loop(case0: &[u8]) -> Asm {
    Asm::default()
        .bytes(&ZERO_EXTEND)
        .bytes(&CMP_EDI)
        .branch(&JA, "default")
        .label("dispatch")
        .bytes(&JMP_RDI)
        .label("case0")
        .bytes(case0)
        .branch(&JMP, "dispatch")
        .label("case1")
        .bytes(&[RET])
        .label("case2")
        .bytes(&[RET])
        .label("case3")
        .bytes(&[RET])
        .label("default")
        .bytes(&[RET])
}

#[test]
fn a_loop_carried_index_needs_its_guard_inside_the_loop() {
    let jump = |case0: &[u8]| {
        let asm = guard_before_loop(case0);
        let (_, labels) = guard_before_loop(case0).assemble();
        cases(Arch::X86_64, asm, absolute, "dispatch").map(|cases| (cases, expected(&labels)))
    };
    // The loop leaves edi alone, so the bound from before the loop holds on the back edge too.
    let (found, wanted) = jump(&[NOP, NOP]).expect("resolved");
    assert_eq!(found, wanted);
    // dec edi on the back edge: the guard before the loop no longer bounds the index. Only exploring the case
    // shows the back edge, so the table first proven without it is dropped.
    assert_eq!(jump(&[0xff, 0xcf]), None);
}

/// A PIC i386 switch: `push ebx` and `get_pc` put the PC in ebx, `add ebx, GOT - PC` makes it the GOT, and after a
/// join `cmp eax, 3; ja default; mov eax, [ebx + eax*4 + table - GOT]; add eax, ebx; jmp eax`. `thunk` is the
/// function `get_pc` may call.
fn pic(get_pc: &dyn Fn(Asm) -> Asm, thunk: &[u8]) -> (Asm, u64) {
    let got = RODATA + 0x1000;
    let asm = get_pc(Asm::default().bytes(&[0x53]));
    // The address after `push ebx; call ...`.
    let pc = 6;
    let asm = asm
        .bytes(&[0x81, 0xc3])
        .bytes(&(got.wrapping_sub(pc) as u32).to_le_bytes())
        .bytes(&TEST)
        .branch(&JE, "join")
        .bytes(&[NOP])
        .label("join")
        .bytes(&[0x83, 0xf8, 3])
        .branch(&JA, "default")
        .bytes(&[0x8b, 0x84, 0x83])
        .bytes(&(RODATA.wrapping_sub(got) as u32).to_le_bytes())
        .bytes(&[0x01, 0xd8])
        .label("dispatch")
        .bytes(&[0xff, 0xe0])
        .cases()
        .label("thunk")
        .bytes(thunk);
    (asm, got)
}

#[test]
fn pic_i386_tables_are_relative_to_the_got_a_get_pc_thunk_located() {
    let call = |asm: Asm| asm.branch(&CALL, "thunk");
    // call 1f; 1: pop ebx
    let inline = |asm: Asm| asm.bytes(&[0xe8, 0, 0, 0, 0, 0x5b]);
    // mov ebx, [esp]; ret
    let get_pc_thunk = [0x8b, 0x1c, 0x24, RET];
    let jump = |get_pc: &dyn Fn(Asm) -> Asm, thunk: &[u8]| {
        let (asm, got) = pic(get_pc, thunk);
        let (_, labels) = pic(get_pc, thunk).0.assemble();
        let rodata = |labels: &HashMap<&str, u64>| {
            CASES.iter().flat_map(|case| (labels[case].wrapping_sub(got) as u32).to_le_bytes()).collect()
        };
        cases(Arch::X86, asm, rodata, "dispatch").map(|cases| (cases, expected(&labels)))
    };
    for get_pc in [&call as &dyn Fn(Asm) -> Asm, &inline] {
        let (found, wanted) = jump(get_pc, &get_pc_thunk).expect("resolved");
        assert_eq!(found, wanted);
    }
    // mov ebx, [esp + 4]; ret returns an argument, not the PC.
    assert_eq!(jump(&call, &[0x8b, 0x5c, 0x24, 4, RET]), None);
}
