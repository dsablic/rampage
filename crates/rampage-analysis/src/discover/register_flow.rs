//! A decoder's register facts carried across one function's control-flow graph, for the passes that need facts
//! set in an earlier block: switch tables ([`super::joined_switches`]) and structure-field bases
//! ([`super::field_flow`]).
//!
//! It is a must-dataflow: a block starts with the facts that hold at the end of every edge into it. A path that
//! enters from outside the function (a branch from another function's code, or a block start another function's
//! body also holds, which it may fall into), or at the function's entry, contributes nothing, so only facts
//! established inside the function on every path survive. A block that ends without a known exit (a decode gate,
//! undecodable bytes) gives nothing to the block after it.

use std::collections::{BTreeSet, HashMap, HashSet};

use rampage_arch::{Disassembler, Flow, Insn, RegisterFacts};

use super::{DiscoveredFunction, Xref, XrefKind};
use crate::memory::Memory;

/// Most block visits per block before a function's dataflow gives up; meets only lose facts, so it settles well
/// before this.
const VISITS_PER_BLOCK: usize = 32;

/// Where paths from outside a function may join it: the branches that reach each branch target, and the block
/// starts more than one function holds.
pub(super) struct Joins {
    entries: HashMap<u64, Vec<u64>>,
    shared: HashSet<u64>,
}

impl Joins {
    pub(super) fn new<'a>(
        functions: impl IntoIterator<Item = &'a DiscoveredFunction>,
        xrefs: impl IntoIterator<Item = &'a Xref>,
    ) -> Self {
        let mut entries: HashMap<u64, Vec<u64>> = HashMap::new();
        for xref in xrefs.into_iter().filter(|xref| xref.kind == XrefKind::Jump) {
            entries.entry(xref.to).or_default().push(xref.from);
        }
        let mut seen = HashSet::new();
        let mut shared = HashSet::new();
        for function in functions {
            for block in &function.blocks {
                if !seen.insert(block.start) {
                    shared.insert(block.start);
                }
            }
        }
        Joins { entries, shared }
    }

    /// Whether a path from outside `function` may reach `address`.
    fn entered_from_outside(&self, function: &DiscoveredFunction, address: u64) -> bool {
        self.shared.contains(&address)
            || self.entries.get(&address).is_some_and(|sources| sources.iter().any(|&source| !holds(function, source)))
    }
}

/// Whether `address` lies in one of `function`'s blocks, which are sorted and do not overlap.
fn holds(function: &DiscoveredFunction, address: u64) -> bool {
    let blocks = &function.blocks;
    let after = blocks.partition_point(|block| block.start <= address);
    after > 0 && address < blocks[after - 1].end
}

/// How the last instruction of a block leaves it.
struct Exit {
    address: u64,
    flow: Flow,
    end: u64,
    fall_through: Option<RegisterFacts>,
    taken: Option<RegisterFacts>,
}

/// Runs the dataflow over `function`, calling `visit` with each instruction decoded on each block visit, after the
/// decoder has decoded it from the block's start facts (which `visit` also receives). A block is visited again
/// whenever its start facts weaken, so the last visit of each block saw its settled facts. Returns `false` when
/// the dataflow does not settle within its budget, or the decoder carries no facts; what `visit` saw is then
/// unproven.
pub(super) fn walk(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    function: &DiscoveredFunction,
    joins: &Joins,
    mut visit: impl FnMut(usize, &RegisterFacts, &Insn, &dyn Disassembler),
) -> bool {
    decoder.begin_run();
    decoder.reset();
    let Some(nothing) = decoder.facts() else { return false };
    let blocks = &function.blocks;
    let block_at = |address: u64| blocks.binary_search_by_key(&address, |block| block.start).ok();
    let read = |at: u64, size: u8| memory.read_pointer(at, size);

    let mut facts: Vec<Option<RegisterFacts>> = vec![None; blocks.len()];
    let mut worklist = BTreeSet::new();
    for (index, block) in blocks.iter().enumerate() {
        if block.start == function.address || joins.entered_from_outside(function, block.start) {
            facts[index] = Some(nothing.clone());
            worklist.insert(index);
        }
    }
    let mut budget = blocks.len().saturating_mul(VISITS_PER_BLOCK);
    while let Some(index) = worklist.pop_first() {
        let Some(budget_left) = budget.checked_sub(1) else { return false };
        budget = budget_left;
        let Some(start_facts) = facts[index].clone() else { continue };
        let block = blocks[index];
        decoder.reset();
        decoder.assume(&start_facts);
        let mut exit = None;
        let mut address = block.start;
        while address < block.end {
            let Some(bytes) = memory.code_from(address) else { break };
            if address != block.start && joins.entered_from_outside(function, address) {
                decoder.join();
            }
            let insn = decoder.decode_with_memory(bytes, address, &read);
            if decoder.decode_gate().is_some() || insn.flow == Flow::Invalid {
                break;
            }
            visit(index, &start_facts, &insn, &*decoder);
            let end = address + u64::from(insn.len);
            if end >= block.end {
                let taken = matches!(insn.flow, Flow::ConditionalJump(_)).then(|| decoder.taken_facts()).flatten();
                exit = Some(Exit { address, flow: insn.flow, end, fall_through: decoder.facts(), taken });
            }
            address = end;
        }
        let edges = match &exit {
            Some(exit) => successors(function, exit),
            // Without a known exit, the block after it may still be reached from it, with nothing known.
            None => vec![(block.end, Some(&nothing))],
        };
        for (target, edge_facts) in edges {
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
    true
}

/// The blocks a block's last instruction can continue at inside `function`, with the facts on each edge. Edges to
/// addresses that start no block of the function lead elsewhere and are dropped by the caller.
fn successors<'a>(function: &DiscoveredFunction, exit: &'a Exit) -> Vec<(u64, Option<&'a RegisterFacts>)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::Block;

    fn function(address: u64, blocks: &[(u64, u64)]) -> DiscoveredFunction {
        let blocks = blocks.iter().map(|&(start, end)| Block { start, end }).collect();
        DiscoveredFunction { address, blocks, instruction_count: 0, switches: Vec::new() }
    }

    #[test]
    fn a_block_start_another_function_also_holds_is_entered_from_outside() {
        // Both functions hold the block at 0x30; no branch reaches it, as when another function falls into it.
        let first = function(0x10, &[(0x10, 0x20), (0x30, 0x40)]);
        let second = function(0x50, &[(0x30, 0x40), (0x50, 0x60)]);
        let inside = Xref { to: 0x18, from: 0x14, kind: XrefKind::Jump };
        let joins = Joins::new([&first, &second], [&inside]);
        assert!(joins.entered_from_outside(&first, 0x30));
        assert!(!joins.entered_from_outside(&first, 0x18));
        // A branch from outside the function's blocks also enters it.
        let outside = Xref { to: 0x18, from: 0x54, kind: XrefKind::Jump };
        let joins = Joins::new([&first, &second], [&outside]);
        assert!(joins.entered_from_outside(&first, 0x18));
    }
}
