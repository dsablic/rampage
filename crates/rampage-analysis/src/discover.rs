//! Recursive-descent function discovery.

use std::collections::{BTreeMap, BTreeSet};

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

/// Discovers functions reachable from `seeds`. Each round explores the newly found functions in parallel and
/// collects their call targets and code pointers as the next round's seeds. The merge is ordered by address,
/// so the result does not depend on thread count or scheduling.
pub fn discover<M, F>(memory: &M, new_decoder: F, seeds: &[u64]) -> Program
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    let mut known: BTreeSet<u64> = seeds.iter().copied().filter(|&seed| memory.is_executable(seed)).collect();
    let mut pending: Vec<u64> = known.iter().copied().collect();
    let mut functions = Vec::new();
    let mut xrefs = Vec::new();

    while !pending.is_empty() {
        let explored: Vec<Explored> = pending
            .par_iter()
            .map_init(&new_decoder, |decoder, &start| explore(memory, decoder.as_mut(), &known, start))
            .collect();
        let mut next = BTreeSet::new();
        for result in explored {
            for &target in &result.new_seeds {
                if memory.is_executable(target) && !known.contains(&target) {
                    next.insert(target);
                }
            }
            xrefs.extend(result.xrefs);
            functions.push(result.function);
        }
        known.extend(next.iter().copied());
        pending = next.into_iter().collect();
    }

    functions.sort_unstable_by_key(|function| function.address);
    xrefs.sort_unstable();
    xrefs.dedup();
    Program { functions, xrefs }
}

struct Explored {
    function: DiscoveredFunction,
    xrefs: Vec<Xref>,
    new_seeds: Vec<u64>,
}

fn explore(memory: &impl Memory, decoder: &mut dyn Disassembler, known: &BTreeSet<u64>, start: u64) -> Explored {
    let is_other_function = |address: u64| address != start && known.contains(&address);
    let mut blocks: BTreeMap<u64, u64> = BTreeMap::new();
    let mut instructions: BTreeSet<u64> = BTreeSet::new();
    let mut xrefs = Vec::new();
    let mut new_seeds = Vec::new();
    let mut worklist = vec![start];

    while let Some(block_start) = worklist.pop() {
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
            let Some(bytes) = memory.bytes_from(address) else { break };
            let insn = decoder.decode(bytes, address);
            if insn.flow == Flow::Invalid {
                break;
            }
            instructions.insert(address);
            let next = address + u64::from(insn.len);
            if let Some(target) = insn.data_ref.filter(|&target| memory.is_mapped(target)) {
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
                    if !is_other_function(target) {
                        worklist.push(target);
                    }
                    worklist.push(next);
                    address = next;
                    break;
                }
                Flow::Jump(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                    if !is_other_function(target) {
                        worklist.push(target);
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

    let blocks = blocks.into_iter().map(|(start, end)| Block { start, end }).collect();
    let function = DiscoveredFunction { address: start, blocks, instruction_count: instructions.len() };
    Explored { function, xrefs, new_seeds }
}

/// Splits the block containing `address` so that a new block starts there.
fn split_block(blocks: &mut BTreeMap<u64, u64>, address: u64) {
    let Some((&start, &end)) = blocks.range(..address).next_back() else { return };
    if address < end {
        blocks.insert(start, address);
        blocks.insert(address, end);
    }
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

    #[test]
    fn running_off_the_end_of_memory_is_not_a_panic() {
        let program = run(&[0x90, 0x90], &[0, 1, 0x1000]);
        assert_eq!(blocks(&program, 0), [(0, 1)]);
        assert!(program.function_at(0x1000).is_none());
    }
}
