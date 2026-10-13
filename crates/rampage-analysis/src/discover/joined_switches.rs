//! Switch jump tables whose index bound, index copy or table base is set up in an earlier block.
//!
//! The decoder proves a switch's facts along one straight-line run and forgets them where a branch joins it. Once a
//! function's blocks are known, this carries the decoder's register facts across its control-flow graph instead:
//! a must-dataflow whose facts at a block's start are those that hold at the end of every edge into it. A path
//! that enters from outside the function, or at its entry, contributes nothing, so only facts established inside the
//! function on every path to the jump survive. A bound holds only on the successor edge that proved it: the
//! fall-through of `ja` / AArch64 `b.hi`, or the taken edge of AArch64 `b.ls`.
//!
//! A table resolved this way adds case edges, which may join the paths it was proven on, so discovery explores the
//! function again assuming it and keeps it only if the facts still prove the same table over the larger graph
//! (see [`resolve`]). Like the straight-line rule, this trusts that no unresolved indirect jump lands on those
//! paths, and that calls keep the registers every calling convention preserves.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::{Disassembler, Flow, JumpTable, RegisterFacts};
use rayon::prelude::*;

use super::{Explored, XrefKind, switch_targets};
use crate::memory::Memory;

/// Switch tables proven across joins, by function entry and jump address.
pub(super) type Assumed = BTreeMap<(u64, u64), JumpTable>;

/// Most block visits per block before a function's dataflow gives up; meets only lose facts, so it settles well
/// before this.
const VISITS_PER_BLOCK: usize = 32;

/// For each function in `results`, the tables of the register-indirect jumps it left unresolved, and of the jumps
/// it resolved by assuming `assumed`, that its register facts prove on every path through its current blocks.
pub(super) fn resolve<M, F>(
    memory: &M,
    new_decoder: &F,
    results: &BTreeMap<u64, Explored>,
    assumed: &Assumed,
) -> Assumed
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    let pending: Vec<(&Explored, Vec<u64>)> = results
        .values()
        .filter_map(|result| {
            let start = result.function.address;
            let assumed_here = assumed.range((start, 0)..=(start, u64::MAX)).map(|(&(_, jump), _)| jump);
            let jumps: Vec<u64> = result.unresolved_jumps.iter().copied().chain(assumed_here).collect();
            (!jumps.is_empty()).then_some((result, jumps))
        })
        .collect();
    if pending.is_empty() || new_decoder().facts().is_none() {
        return Assumed::new();
    }
    let mut entries: HashMap<u64, Vec<u64>> = HashMap::new();
    for xref in results.values().flat_map(|result| &result.xrefs).filter(|xref| xref.kind == XrefKind::Jump) {
        entries.entry(xref.to).or_default().push(xref.from);
    }
    pending
        .par_iter()
        .map_init(new_decoder, |decoder, (result, jumps)| {
            function_tables(memory, decoder.as_mut(), result, jumps, &entries)
                .into_iter()
                .map(|(jump, table)| ((result.function.address, jump), table))
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect()
}

/// How the last instruction of a block leaves it.
struct Exit {
    address: u64,
    flow: Flow,
    end: u64,
    fall_through: Option<RegisterFacts>,
    taken: Option<RegisterFacts>,
}

/// The tables of `jumps` in `result`'s function that hold with facts carried across its blocks. `entries` lists,
/// for every branch target in the program, the branches that reach it.
fn function_tables(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    result: &Explored,
    jumps: &[u64],
    entries: &HashMap<u64, Vec<u64>>,
) -> Vec<(u64, JumpTable)> {
    let function = &result.function;
    decoder.begin_run();
    let Some(nothing) = decoder.facts() else { return Vec::new() };
    let blocks = &function.blocks;
    let block_at = |address: u64| blocks.binary_search_by_key(&address, |block| block.start).ok();
    let read = |at: u64, size: u8| memory.read_pointer(at, size);

    // Pass 1: the instructions of every block, so branches from outside the function can be told apart.
    let mut instructions = BTreeSet::new();
    for block in blocks {
        let mut address = block.start;
        while address < block.end {
            let Some(bytes) = memory.code_from(address) else { break };
            let insn = decoder.decode(bytes, address);
            if insn.flow == Flow::Invalid {
                break;
            }
            instructions.insert(address);
            address += u64::from(insn.len);
        }
    }
    let entered_from_outside = |address: u64| {
        entries.get(&address).is_some_and(|sources| sources.iter().any(|source| !instructions.contains(source)))
    };

    let mut facts: Vec<Option<RegisterFacts>> = vec![None; blocks.len()];
    let mut worklist = BTreeSet::new();
    for (index, block) in blocks.iter().enumerate() {
        if block.start == function.address || entered_from_outside(block.start) {
            facts[index] = Some(nothing.clone());
            worklist.insert(index);
        }
    }
    let wanted: BTreeSet<u64> = jumps.iter().copied().collect();
    let mut tables = BTreeMap::new();
    let mut budget = blocks.len().saturating_mul(VISITS_PER_BLOCK);
    while let Some(index) = worklist.pop_first() {
        let Some(budget_left) = budget.checked_sub(1) else { return Vec::new() };
        budget = budget_left;
        let Some(start_facts) = facts[index].clone() else { continue };
        let block = blocks[index];
        decoder.reset();
        decoder.assume(&start_facts);
        let mut exit = None;
        let mut address = block.start;
        while address < block.end {
            let Some(bytes) = memory.code_from(address) else { break };
            if address != block.start && entered_from_outside(address) {
                decoder.join();
            }
            let insn = decoder.decode_with_memory(bytes, address, &read);
            if insn.flow == Flow::Invalid {
                break;
            }
            let end = address + u64::from(insn.len);
            if end >= block.end {
                if insn.flow == Flow::IndirectJump && wanted.contains(&address) {
                    tables.insert(address, decoder.jump_table());
                }
                let taken = matches!(insn.flow, Flow::ConditionalJump(_)).then(|| decoder.taken_facts()).flatten();
                exit = Some(Exit { address, flow: insn.flow, end, fall_through: decoder.facts(), taken });
            }
            address = end;
        }
        let Some(exit) = exit else { continue };
        for (target, edge_facts) in successors(function, &exit) {
            let (Some(successor), Some(edge_facts)) = (block_at(target), edge_facts) else { continue };
            let met = match &facts[successor] {
                Some(old) => old.meet(edge_facts),
                None => edge_facts.clone(),
            };
            if facts[successor].as_ref() != Some(&met) {
                facts[successor] = Some(met);
                worklist.insert(successor);
            }
        }
    }

    tables
        .into_iter()
        .filter_map(|(jump, table)| {
            let table = table?;
            switch_targets(memory, decoder, &table)?;
            Some((jump, table))
        })
        .collect()
}

/// The blocks a block's last instruction can continue at inside `function`, with the facts on each edge. Edges to
/// addresses that start no block of the function lead elsewhere and are dropped by the caller.
fn successors<'a>(function: &super::DiscoveredFunction, exit: &'a Exit) -> Vec<(u64, Option<&'a RegisterFacts>)> {
    let fall_through = exit.fall_through.as_ref();
    match exit.flow {
        Flow::ConditionalJump(target) => vec![(target, exit.taken.as_ref()), (exit.end, fall_through)],
        Flow::Jump(target) => vec![(target, fall_through)],
        Flow::IndirectJump => {
            let cases = function.switch_cases(exit.address).unwrap_or_default();
            cases.iter().map(|&case| (case, fall_through)).collect()
        }
        // A block also ends where another starts, or after a call that does not return; the edge to the next block
        // in the latter case only weakens the facts there.
        Flow::Next | Flow::Call(_) | Flow::IndirectCall => vec![(exit.end, fall_through)],
        Flow::Return | Flow::Halt | Flow::Invalid => Vec::new(),
    }
}
