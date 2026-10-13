use rampage_arch::{Arch, MAX_JUMP_TABLE_ENTRIES, decoder_for};

use super::{DATA, Image, RODATA};
use crate::discover::{Program, Xref, XrefKind, discover};

const NOPS: [u8; 6] = [0x90; 6];
/// cmp edi, 3
const CMP: [u8; 6] = [0x81, 0xff, 3, 0, 0, 0];
/// ja 0x34 (the default case), from 8
const JA: [u8; 2] = [0x77, 0x2a];
/// mov edi, edi
const ZERO_EXTEND: [u8; 2] = [0x89, 0xff];
const DISPATCH: u64 = 0xc;
const CASES: [u64; 4] = [0x30, 0x31, 0x32, 0x33];

/// A switch on edi: `0: prefix; 2: cmp; 8: ja; a: gap; c: dispatch; 30..34: four cases; 34: default`. Every case
/// and the default is a `ret`.
#[derive(Clone)]
struct Switch {
    arch: Arch,
    prefix: [u8; 2],
    compare: [u8; 6],
    branch: [u8; 2],
    gap: [u8; 2],
    dispatch: Vec<u8>,
}

impl Switch {
    fn new(dispatch: Vec<u8>) -> Switch {
        Switch { arch: Arch::X86_64, prefix: [0x90; 2], compare: CMP, branch: JA, gap: ZERO_EXTEND, dispatch }
    }

    fn discover(&self, rodata: Vec<u8>, data: Vec<u8>) -> Program {
        let mut code = [&self.prefix[..], &self.compare, &self.branch, &self.gap, &self.dispatch].concat();
        assert!(code.len() <= CASES[0] as usize);
        code.resize(CASES[0] as usize, 0xcc);
        code.extend([0xc3; 5]);
        let image = Image { code, rodata, data };
        let arch = self.arch;
        discover(&image, || decoder_for(arch).unwrap(), &[0])
    }
}

/// jmp qword [rdi*8 + table]
fn absolute(table: u64) -> Vec<u8> {
    [&[0xff, 0x24, 0xfd][..], &(table as u32).to_le_bytes()].concat()
}

/// lea rcx, [rip + table]; movsxd rax, dword [rcx + rdi*4]; then `add`
fn relative(add: &[u8]) -> Vec<u8> {
    let lea_end = DISPATCH + 7;
    let lea = [&[0x48, 0x8d, 0x0d][..], &(RODATA.wrapping_sub(lea_end) as u32).to_le_bytes()].concat();
    [&lea[..], &[0x48, 0x63, 0x04, 0xb9], add].concat()
}

/// add rax, rcx; jmp rax
const ADD_JMP: [u8; 5] = [0x48, 0x01, 0xc8, 0xff, 0xe0];

fn entries(values: impl Fn(u64) -> u64, size: usize) -> Vec<u8> {
    CASES.iter().flat_map(|&case| values(case).to_le_bytes()[..size].to_vec()).collect()
}

fn absolute_entries() -> Vec<u8> {
    entries(|case| case, 8)
}

fn relative_entries() -> Vec<u8> {
    entries(|case| case.wrapping_sub(RODATA), 4)
}

fn resolved(program: &Program) -> bool {
    let function = program.function_at(0).unwrap();
    let reached = CASES.iter().filter(|&&case| function.contains(case)).count();
    assert!(reached == 0 || reached == CASES.len(), "{function:?}");
    reached == CASES.len()
}

#[test]
fn bounded_x86_switch_tables_of_every_form_reach_their_cases() {
    // mov ecx, [rcx + rdi*4 + table] with rcx = 0 (MSVC's image base) and unsigned image-relative entries.
    let lea_base = [&[0x48, 0x8d, 0x0d][..], &(0u64.wrapping_sub(DISPATCH + 7) as u32).to_le_bytes()].concat();
    let msvc = [&lea_base[..], &[0x8b, 0x84, 0xb9], &(RODATA as u32).to_le_bytes(), &ADD_JMP].concat();
    let forms = [
        (absolute(RODATA), absolute_entries(), DISPATCH),
        // mov rax, [rdi*8 + table]; jmp rax
        (
            [&[0x48, 0x8b, 0x04, 0xfd][..], &(RODATA as u32).to_le_bytes(), &[0xff, 0xe0]].concat(),
            absolute_entries(),
            0x14,
        ),
        (relative(&ADD_JMP), relative_entries(), 0x1a),
        // add rcx, rax; jmp rcx
        (relative(&[0x48, 0x01, 0xc1, 0xff, 0xe1]), relative_entries(), 0x1a),
        (msvc, entries(|case| case, 4), 0x1d),
    ];
    for (dispatch, table, jump) in forms {
        let program = Switch::new(dispatch.clone()).discover(table, vec![]);
        assert!(resolved(&program), "{dispatch:x?}");
        let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(addresses, [0]);
        for case in CASES {
            assert!(program.xrefs.contains(&Xref { to: case, from: jump, kind: XrefKind::Jump }), "{dispatch:x?}");
        }
        assert_eq!(program.function_at(0).unwrap().switch_cases(jump), Some(&CASES[..]));
    }
    // i386: jmp dword [edi*4 + table], where the 32-bit comparison bounds the whole index.
    let i386 = Switch { arch: Arch::X86, gap: [0x90; 2], ..Switch::new(vec![0xff, 0x24, 0xbd, 0, 0, 1, 0]) };
    assert!(resolved(&i386.discover(entries(|case| case, 4), vec![])));
}

#[test]
fn an_x86_switch_needs_an_unsigned_bound_on_every_path_to_its_jump() {
    let switch = || Switch::new(absolute(RODATA));
    assert!(resolved(&switch().discover(absolute_entries(), vec![])));
    // No comparison.
    let unbounded = Switch { compare: NOPS, ..switch() };
    assert!(!resolved(&unbounded.discover(absolute_entries(), vec![])));
    // jg is a signed bound: a negative index passes it.
    let signed = Switch { branch: [0x7f, JA[1]], ..switch() };
    assert!(!resolved(&signed.discover(absolute_entries(), vec![])));
    // cmp esi, 3 bounds another register.
    let other = Switch { compare: [0x81, 0xfe, 3, 0, 0, 0], ..switch() };
    assert!(!resolved(&other.discover(absolute_entries(), vec![])));
    // je 0xc joins the run between the comparison and the jump, on a path where edi is unbounded.
    let joined = Switch { prefix: [0x74, 0x0a], ..switch() };
    assert!(!resolved(&joined.discover(absolute_entries(), vec![])));
    // inc edi redefines the index after the comparison.
    let redefined = Switch { gap: [0xff, 0xc7], ..switch() };
    assert!(!resolved(&redefined.discover(absolute_entries(), vec![])));
    // Without mov edi, edi the comparison bounds only edi, and rdi's upper half is whatever it held on entry.
    let narrow = Switch { gap: [0x90; 2], ..switch() };
    assert!(!resolved(&narrow.discover(absolute_entries(), vec![])));
    // mov edi, edi before the comparison zeroes it as well.
    let zeroed = Switch { prefix: ZERO_EXTEND, ..narrow };
    assert!(resolved(&zeroed.discover(absolute_entries(), vec![])));
    // jae bounds the index below its limit: cmp edi, 4; jae DEFAULT.
    let below = Switch { compare: [0x81, 0xff, 4, 0, 0, 0], branch: [0x73, JA[1]], ..switch() };
    assert!(resolved(&below.discover(absolute_entries(), vec![])));
    // movsxd rax, edi sign-extends the bounded index into rax; movsxd ax, di leaves rax's upper bits as they were.
    let jump_rax = [0xff, 0x24, 0xc5, 0, 0, 1, 0];
    let extended = Switch { gap: [0x90; 2], ..Switch::new([&[0x48, 0x63, 0xc7][..], &jump_rax].concat()) };
    assert!(resolved(&extended.discover(absolute_entries(), vec![])));
    let halfword = Switch { gap: [0x90; 2], ..Switch::new([&[0x66, 0x63, 0xc7][..], &jump_rax].concat()) };
    assert!(!resolved(&halfword.discover(absolute_entries(), vec![])));
    // and edi, 3 masks the index.
    let masked = Switch { compare: [0x83, 0xe7, 3, 0x90, 0x90, 0x90], branch: [0x90; 2], ..switch() };
    assert!(resolved(&masked.discover(absolute_entries(), vec![])));
    // and edi, 5 leaves 0, 1, 4 and 5, not the six dense indices 0..=5; and edi, 7 bounds eight.
    let eight: Vec<u8> = [&absolute_entries()[..], &absolute_entries()].concat();
    let sparse = Switch { compare: [0x83, 0xe7, 5, 0x90, 0x90, 0x90], ..masked.clone() };
    assert!(!resolved(&sparse.discover(eight.clone(), vec![])));
    let dense = Switch { compare: [0x83, 0xe7, 7, 0x90, 0x90, 0x90], ..masked };
    assert!(resolved(&dense.discover(eight, vec![])));
}

#[test]
fn x86_switch_tables_must_be_read_only_data_selecting_code() {
    let switch = Switch::new(absolute(RODATA));
    assert!(resolved(&switch.discover(absolute_entries(), vec![])));
    assert!(!resolved(&Switch::new(absolute(DATA)).discover(vec![], absolute_entries())));
    // One entry short of the bound.
    assert!(!resolved(&switch.discover(absolute_entries()[..24].to_vec(), vec![])));
    // An entry past the end of the code.
    let mut outside = absolute_entries();
    outside[24] = 0x40;
    assert!(!resolved(&switch.discover(outside, vec![])));
    let relative = Switch::new(relative(&ADD_JMP));
    assert!(resolved(&relative.discover(relative_entries(), vec![])));
    let mut outside = relative_entries();
    outside[12..].copy_from_slice(&0x40u32.wrapping_sub(RODATA as u32).to_le_bytes());
    assert!(!resolved(&relative.discover(outside, vec![])));
}

#[test]
fn a_hostile_x86_switch_bound_is_capped() {
    let switch = |limit: u32| {
        let mut compare = CMP;
        compare[2..].copy_from_slice(&limit.to_le_bytes());
        Switch { compare, ..Switch::new(absolute(RODATA)) }
    };
    let entries: Vec<u8> = (0..=MAX_JUMP_TABLE_ENTRIES).flat_map(|_| CASES[0].to_le_bytes()).collect();
    let largest = switch(0xfff).discover(entries.clone(), vec![]);
    assert!(largest.function_at(0).unwrap().contains(CASES[0]));
    let hostile = switch(0x1000).discover(entries, vec![]);
    assert!(!hostile.function_at(0).unwrap().contains(CASES[0]));
}

/// Discovers `code`, padded with `int3` up to the cases, which with the default after them are each a `ret`.
fn discover_code(mut code: Vec<u8>, rodata: Vec<u8>) -> Program {
    assert!(code.len() <= CASES[0] as usize);
    code.resize(CASES[0] as usize, 0xcc);
    code.extend([0xc3; 5]);
    discover(&Image { code, rodata, data: vec![] }, || decoder_for(Arch::X86_64).unwrap(), &[0])
}

#[test]
fn facts_established_before_a_join_ahead_of_the_comparison_do_not_reach_the_jump() {
    // 0: test esi, esi; 2: jne JOIN; 4: mov edi, edi; 6: cmp edi, 3; c: ja 0x34; e: jmp [rdi*8 + table]. Through
    // a join at 6, rdi's upper half is whatever it held on entry.
    let zero_extended = |join: u8| {
        let code = [&[0x85, 0xf6, 0x75, join - 4][..], &ZERO_EXTEND, &CMP, &[0x77, 0x26], &absolute(RODATA)].concat();
        discover_code(code, absolute_entries())
    };
    assert!(!resolved(&zero_extended(6)));
    assert!(resolved(&zero_extended(4)));

    // 0: test esi, esi; 2: jne JOIN; 4: lea rcx, [rip + table]; b: mov eax, edi; d: cmp eax, 3; 10: ja 0x34;
    // 12: movsxd rax, [rcx + rax*4]; 16: add rax, rcx; 19: jmp rax. Through a join at b, rcx is not the table.
    let based = |join: u8| {
        let lea = [&[0x48, 0x8d, 0x0d][..], &(RODATA.wrapping_sub(0xb) as u32).to_le_bytes()].concat();
        let index = [0x89, 0xf8, 0x83, 0xf8, 3, 0x77, 0x22, 0x48, 0x63, 0x04, 0x81];
        let code = [&[0x85, 0xf6, 0x75, join - 4][..], &lea, &index, &ADD_JMP].concat();
        discover_code(code, relative_entries())
    };
    assert!(!resolved(&based(0xb)));
    assert!(resolved(&based(4)));
}
