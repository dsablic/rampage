//! Recursive-descent function discovery.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::{Disassembler, Flow};
use rayon::prelude::*;
use serde::Serialize;

use crate::memory::Memory;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Block {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredFunction {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub blocks: Vec<Block>,
    pub instruction_count: usize,
}

impl DiscoveredFunction {
    pub fn contains(&self, address: u64) -> bool {
        self.blocks.iter().any(|block| (block.start..block.end).contains(&address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Xref {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub to: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Program {
    /// Sorted by address.
    pub functions: Vec<DiscoveredFunction>,
    /// Sorted by target, then source.
    pub xrefs: Vec<Xref>,
}

impl Program {
    pub fn function_at(&self, address: u64) -> Option<&DiscoveredFunction> {
        let index = self.functions.binary_search_by_key(&address, |function| function.address).ok()?;
        Some(&self.functions[index])
    }

    /// Every function whose blocks include `address` (shared tails can belong to several).
    pub fn functions_containing(&self, address: u64) -> impl Iterator<Item = &DiscoveredFunction> {
        self.functions.iter().filter(move |function| function.contains(address))
    }

    pub fn xrefs_to(&self, address: u64) -> &[Xref] {
        let start = self.xrefs.partition_point(|xref| xref.to < address);
        let end = self.xrefs.partition_point(|xref| xref.to <= address);
        &self.xrefs[start..end]
    }
}

/// Discovers functions reachable from `seeds` in two phases.
///
/// Phase 1 finds the complete set of function starts: rounds explore newly found functions in parallel and add
/// their call targets, code pointers, and any jump target reached from two or more different functions (a shared
/// tail, which would otherwise be copied into every caller). Phase 2 then builds every function's blocks against
/// that final set, so whether a jump is a tail call does not depend on the round its target was found in.
/// Merges are ordered by address, so the result does not depend on thread count or scheduling.
pub fn discover<M, F>(memory: &M, new_decoder: F, seeds: &[u64]) -> Program
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    let explore_all = |starts: &[u64], known: &BTreeSet<u64>, joins: Option<&[u64]>| -> Vec<Explored> {
        starts
            .par_iter()
            .map_init(&new_decoder, |decoder, &start| explore(memory, decoder.as_mut(), known, joins, start))
            .collect()
    };

    let mut known: BTreeSet<u64> = seeds.iter().copied().filter(|&seed| memory.is_executable(seed)).collect();
    let mut pending: Vec<u64> = known.iter().copied().collect();
    let mut first_jumper: HashMap<u64, u64> = HashMap::new();
    let mut empty = BTreeSet::new();
    let mut branch_targets = Vec::new();
    while !pending.is_empty() {
        let mut next = BTreeSet::new();
        for result in explore_all(&pending, &known, None) {
            branch_targets.extend_from_slice(&result.branch_targets);
            let start = result.function.address;
            if result.function.blocks.is_empty() {
                empty.insert(start);
            }
            for &target in &result.new_seeds {
                if !known.contains(&target) && memory.is_executable(target) {
                    next.insert(target);
                }
            }
            for &target in &result.jump_targets {
                let first = *first_jumper.entry(target).or_insert(start);
                if first != start && !known.contains(&target) {
                    next.insert(target);
                }
            }
        }
        known.extend(next.iter().copied());
        pending = next.into_iter().collect();
    }
    known.retain(|start| !empty.contains(start));

    // Phase 1 saw every branch; a fall-through that is also a branch target joins paths and starts afresh.
    branch_targets.sort_unstable();
    branch_targets.dedup();
    let starts: Vec<u64> = known.iter().copied().collect();
    let mut functions = Vec::with_capacity(starts.len());
    let mut xrefs = Vec::new();
    for result in explore_all(&starts, &known, Some(&branch_targets)) {
        xrefs.extend(result.xrefs);
        functions.push(result.function);
    }
    xrefs.sort_unstable();
    xrefs.dedup();
    Program { functions, xrefs }
}

struct Explored {
    function: DiscoveredFunction,
    xrefs: Vec<Xref>,
    new_seeds: Vec<u64>,
    /// Targets of unconditional jumps that leave for code outside this function's known starts.
    jump_targets: Vec<u64>,
    /// Targets of every branch taken while exploring.
    branch_targets: Vec<u64>,
}

/// Explores the function at `start`. `joins`, when given, lists every branch target in the program: a conditional
/// branch's fall-through keeps the decoder state (AArch64 ADRP pages) of the path into it unless it is one.
fn explore(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    known: &BTreeSet<u64>,
    joins: Option<&[u64]>,
    start: u64,
) -> Explored {
    let is_other_function = |address: u64| address != start && known.contains(&address);
    let trust_immediates = memory.immediates_may_be_addresses();
    let mut blocks: BTreeMap<u64, u64> = BTreeMap::new();
    let mut instructions: BTreeSet<u64> = BTreeSet::new();
    let mut xrefs = Vec::new();
    let mut new_seeds = Vec::new();
    let mut jump_targets = Vec::new();
    let mut branch_targets = Vec::new();
    let mut worklist = vec![start];
    // A conditional branch's fall-through is explored next; it keeps the decoder state only when no branch joins
    // it there.
    let mut fall_through = None;
    let carries_state = |address: u64| joins.is_some_and(|joins| joins.binary_search(&address).is_err());

    loop {
        let block_start = match fall_through.take() {
            Some(next) => {
                if !carries_state(next) {
                    decoder.reset();
                }
                next
            }
            None => {
                let Some(next) = worklist.pop() else { break };
                decoder.reset();
                next
            }
        };
        if blocks.contains_key(&block_start) {
            continue;
        }
        if instructions.contains(&block_start) {
            split_block(&mut blocks, block_start);
            continue;
        }
        let mut address = block_start;
        loop {
            if address != block_start && (instructions.contains(&address) || is_other_function(address)) {
                split_block(&mut blocks, address);
                break;
            }
            let Some(bytes) = memory.code_from(address) else { break };
            let insn = decoder.decode(bytes, address);
            if insn.flow == Flow::Invalid {
                break;
            }
            instructions.insert(address);
            let Some(next) = address.checked_add(u64::from(insn.len)) else { break };
            let immediate = insn.immediate.filter(|_| trust_immediates);
            for target in insn.data_ref.into_iter().chain(immediate).filter(|&target| memory.is_mapped(target)) {
                xrefs.push(Xref { to: target, from: address, kind: XrefKind::Data });
                if memory.is_executable(target) {
                    new_seeds.push(target);
                }
            }
            match insn.flow {
                Flow::Next | Flow::IndirectCall => address = next,
                Flow::Call(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Call });
                    new_seeds.push(target);
                    address = next;
                }
                Flow::ConditionalJump(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                    branch_targets.push(target);
                    if !is_other_function(target) {
                        worklist.push(target);
                    }
                    if !is_other_function(next) {
                        fall_through = Some(next);
                    }
                    address = next;
                    break;
                }
                Flow::Jump(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                    branch_targets.push(target);
                    if !is_other_function(target) {
                        worklist.push(target);
                        jump_targets.push(target);
                    }
                    address = next;
                    break;
                }
                Flow::IndirectJump | Flow::Return | Flow::Halt | Flow::Invalid => {
                    address = next;
                    break;
                }
            }
        }
        if address > block_start {
            blocks.insert(block_start, address);
        }
    }

    jump_targets.retain(|target| *target != start);
    jump_targets.sort_unstable();
    jump_targets.dedup();
    let blocks = blocks.into_iter().map(|(start, end)| Block { start, end }).collect();
    let function = DiscoveredFunction { address: start, blocks, instruction_count: instructions.len() };
    Explored { function, xrefs, new_seeds, jump_targets, branch_targets }
}

/// Splits the block containing `address` so that a new block starts there. Misaligned decoding can leave smaller
/// overlapping blocks just before `address`, so this looks back for the block that actually spans it.
fn split_block(blocks: &mut BTreeMap<u64, u64>, address: u64) {
    let Some((&start, &end)) = blocks.range(..address).rev().find(|&(_, &end)| address < end) else { return };
    blocks.insert(start, address);
    blocks.insert(address, end);
}

#[cfg(test)]
mod tests {
    use rampage_arch::{Arch, decoder_for};

    use super::*;
    use crate::memory::FlatMemory;

    fn run(bytes: &[u8], seeds: &[u64]) -> Program {
        let memory = FlatMemory { base: 0, bytes: bytes.to_vec() };
        discover(&memory, || decoder_for(Arch::X86_64).unwrap(), seeds)
    }

    fn blocks(program: &Program, address: u64) -> Vec<(u64, u64)> {
        program.function_at(address).unwrap().blocks.iter().map(|block| (block.start, block.end)).collect()
    }

    #[test]
    fn adrp_pages_reach_a_conditional_branchs_fall_through() {
        // 0: adrp x8, 0; 4: cbz w0, 0x10; 8: ldr x1, [x8, #0x18]; c: ret; 10: ret
        let words: [u32; 5] = [0x9000_0008, 0x3400_0060, 0xf940_0d01, 0xd65f_03c0, 0xd65f_03c0];
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.resize(0x20, 0);
        let memory = FlatMemory { base: 0, bytes };
        let program = discover(&memory, || decoder_for(Arch::Aarch64).unwrap(), &[0]);
        assert!(program.xrefs.contains(&Xref { to: 0x18, from: 8, kind: XrefKind::Data }), "{:?}", program.xrefs);
    }

    #[test]
    fn a_fall_through_that_is_also_a_branch_target_starts_afresh() {
        // 0: adrp x8, 0x1000; 4: cbz w0, 0x10; 8: adrp x8, 0; c: cbz w1, 0x18; 10: ldr x1, [x8, #0x18]; 14: ret
        let words: [u32; 7] =
            [0xb000_0008, 0x3400_0060, 0x9000_0008, 0x3400_0061, 0xf940_0d01, 0xd65f_03c0, 0xd65f_03c0];
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.resize(0x2000, 0);
        let memory = FlatMemory { base: 0, bytes };
        let program = discover(&memory, || decoder_for(Arch::Aarch64).unwrap(), &[0]);
        let from_load: Vec<_> = program.xrefs.iter().filter(|xref| xref.from == 0x10).collect();
        assert!(from_load.is_empty(), "{from_load:?}");
    }

    #[test]
    fn straight_line_function_is_one_block() {
        let program = run(&[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3], &[0]);
        assert_eq!(blocks(&program, 0), [(0, 6)]);
        assert_eq!(program.function_at(0).unwrap().instruction_count, 4);
    }

    #[test]
    fn diamond_has_four_blocks() {
        // 0: je 5; 2: nop; 3: jmp 6; 5: nop; 6: ret
        let program = run(&[0x74, 0x03, 0x90, 0xeb, 0x01, 0x90, 0xc3], &[0]);
        assert_eq!(blocks(&program, 0), [(0, 2), (2, 5), (5, 6), (6, 7)]);
    }

    #[test]
    fn backward_jump_splits_loop_header() {
        // 0: xor eax, eax; 2: inc eax; 4: cmp eax, 10; 7: jne 2; 9: ret
        let program = run(&[0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x0a, 0x75, 0xf9, 0xc3], &[0]);
        assert_eq!(blocks(&program, 0), [(0, 2), (2, 9), (9, 10)]);
    }

    #[test]
    fn call_target_becomes_a_function() {
        // 0: call 0xa; 5: ret; 6..a: int3 padding; a: ret
        let program = run(&[0xe8, 0x05, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xc3], &[0]);
        let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(addresses, [0, 0xa]);
        assert_eq!(program.xrefs_to(0xa), [Xref { to: 0xa, from: 0, kind: XrefKind::Call }]);
    }

    #[test]
    fn jump_to_known_function_is_a_tail_call() {
        let mut bytes = vec![0xeb, 0x0e];
        bytes.resize(0x10, 0xcc);
        bytes.push(0xc3);
        let program = run(&bytes, &[0, 0x10]);
        assert_eq!(blocks(&program, 0), [(0, 2)]);
        assert_eq!(blocks(&program, 0x10), [(0x10, 0x11)]);
        assert_eq!(program.xrefs_to(0x10)[0].kind, XrefKind::Jump);
    }

    #[test]
    fn invalid_instruction_ends_the_block() {
        let program = run(&[0x90, 0x06, 0xc3], &[0]);
        assert_eq!(blocks(&program, 0), [(0, 1)]);
    }

    #[test]
    fn falling_into_another_function_ends_the_block() {
        let program = run(&[0x90, 0x90, 0xc3], &[0, 2]);
        assert_eq!(blocks(&program, 0), [(0, 2)]);
    }

    #[test]
    fn code_pointer_becomes_a_function_and_data_xref() {
        // 0: lea rax, [rip+3] -> 0xa; 7: ret; 8: int3 x2; a: ret
        let program = run(&[0x48, 0x8d, 0x05, 0x03, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xc3], &[0]);
        assert!(program.function_at(0xa).is_some());
        assert_eq!(program.xrefs_to(0xa), [Xref { to: 0xa, from: 0, kind: XrefKind::Data }]);
    }

    fn run_at(base: u64, bytes: &[u8], seeds: &[u64]) -> Program {
        let memory = FlatMemory { base, bytes: bytes.to_vec() };
        discover(&memory, || decoder_for(Arch::X86_64).unwrap(), seeds)
    }

    /// 0: mov esi, base+0x1000; 5: ret; then padding and a `ret` at base+0x1000.
    fn moves_code_address(base: u64) -> Vec<u8> {
        let target = u32::try_from(base + 0x1000).unwrap().to_le_bytes();
        let mut bytes = vec![0xbe, target[0], target[1], target[2], target[3], 0xc3];
        bytes.resize(0x1000, 0xcc);
        bytes.push(0xc3);
        bytes
    }

    #[test]
    fn immediate_code_address_is_a_seed_in_an_image_based_high() {
        let base = 0x400000;
        let program = run_at(base, &moves_code_address(base), &[base]);
        assert!(program.function_at(base + 0x1000).is_some());
        assert_eq!(program.xrefs_to(base + 0x1000)[0].kind, XrefKind::Data);
    }

    #[test]
    fn immediates_are_just_numbers_in_an_image_based_at_zero() {
        let program = run_at(0, &moves_code_address(0), &[0]);
        assert!(program.function_at(0x1000).is_none());
        assert!(program.xrefs_to(0x1000).is_empty());
    }

    #[test]
    fn jump_into_an_instruction_inside_an_overlapping_region_still_starts_a_block() {
        // 0: je 10; 2: mov eax, 0xc390 (hides 3: nop, 4: ret); 7: nop; 8: jmp 3; 10: jmp 7
        let program = run(&[0x74, 0x08, 0xb8, 0x90, 0xc3, 0, 0, 0x90, 0xeb, 0xf9, 0xeb, 0xfb], &[0]);
        assert!(blocks(&program, 0).iter().any(|&(start, _)| start == 7), "{:?}", blocks(&program, 0));
    }

    #[test]
    fn conditional_fallthrough_into_another_function_ends_the_function() {
        // 0: jne 0; 2: ret (a separate function)
        let program = run(&[0x75, 0xfe, 0xc3], &[0, 2]);
        assert_eq!(blocks(&program, 0), [(0, 2)]);
    }

    #[test]
    fn tail_call_to_a_function_found_later_is_still_a_tail_call() {
        // A at 0: jmp 0x20. B at 0x10: call 0x20; ret. X at 0x20: ret, found only through B's call.
        let mut bytes = vec![0xcc; 0x21];
        bytes[..2].copy_from_slice(&[0xeb, 0x1e]);
        bytes[0x10] = 0xe8;
        bytes[0x11..0x15].copy_from_slice(&(0x20i32 - 0x15).to_le_bytes());
        bytes[0x15] = 0xc3;
        bytes[0x20] = 0xc3;
        let program = run(&bytes, &[0, 0x10]);
        assert_eq!(blocks(&program, 0), [(0, 2)]);
        assert!(program.function_at(0x20).is_some());
    }

    #[test]
    fn body_jumped_to_from_several_functions_becomes_one_function() {
        let callers = 50u64;
        let body = callers * 8;
        let mut bytes = vec![0xcc; body as usize];
        for caller in 0..callers {
            let at = (caller * 8) as usize;
            bytes[at] = 0xe9;
            bytes[at + 1..at + 5].copy_from_slice(&((body as i64 - (at as i64 + 5)) as i32).to_le_bytes());
        }
        bytes.extend(std::iter::repeat_n(0x90, 100));
        bytes.push(0xc3);
        let seeds: Vec<u64> = (0..callers).map(|caller| caller * 8).collect();
        let program = run(&bytes, &seeds);
        assert_eq!(program.function_at(body).unwrap().instruction_count, 101);
        let total: usize = program.functions.iter().map(|function| function.instruction_count).sum();
        assert_eq!(total, 101 + callers as usize);
    }

    #[test]
    fn seed_on_invalid_bytes_is_dropped() {
        let program = run(&[0x06, 0xc3], &[0, 1]);
        assert!(program.function_at(0).is_none());
        assert!(program.function_at(1).is_some());
    }

    #[test]
    fn running_off_the_end_of_memory_is_not_a_panic() {
        let program = run(&[0x90, 0x90], &[0, 1, 0x1000]);
        assert_eq!(blocks(&program, 0), [(0, 1)]);
        assert!(program.function_at(0x1000).is_none());
    }
}
