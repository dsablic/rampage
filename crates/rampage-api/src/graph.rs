//! A function's control-flow graph: its basic blocks and the branches between them.

use std::collections::HashMap;

use rampage_arch::Flow;
use serde::Serialize;

use crate::listing::DisassemblyLine;
use crate::{ApiError, Project};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// An unconditional jump, or falling through into a block that a branch also reaches.
    Unconditional,
    /// A conditional branch, taken.
    Taken,
    /// A conditional branch, not taken: the fall-through.
    NotTaken,
    /// A register-indirect jump to one case of a bounded switch table.
    Switch,
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    /// Index of the source block.
    pub from: usize,
    /// Index of the target block.
    pub to: usize,
    pub kind: EdgeKind,
}

#[derive(Debug, Serialize)]
pub struct GraphBlock {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    pub lines: Vec<DisassemblyLine>,
}

/// A function's basic blocks in address order (the entry is the block at `address`) and its edges.
#[derive(Debug, Serialize)]
pub struct FunctionGraph {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    pub blocks: Vec<GraphBlock>,
    pub edges: Vec<Edge>,
}

impl FunctionGraph {
    /// The index of the entry block.
    pub fn entry(&self) -> Option<usize> {
        self.blocks.iter().position(|block| block.start == self.address)
    }
}

impl Project {
    /// The control-flow graph of the function containing `address`.
    pub fn function_graph(&self, address: u64) -> Result<FunctionGraph, ApiError> {
        let listing = self.function_listing(address)?;
        let program = &self.analysis()?.program;
        let function = program.function_at(listing.address).expect("listing names a function");
        let ends: HashMap<_, _> = function.blocks.iter().map(|block| (block.start, block.end)).collect();
        let delay_slots = usize::from(self.binary.arch.delay_slots());
        let blocks: Vec<GraphBlock> = listing
            .blocks
            .into_iter()
            .filter_map(|lines| Some(GraphBlock { start: lines.first()?.address, lines }))
            .collect();
        let starts: HashMap<u64, usize> =
            blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();
        let index_of = |address: u64| starts.get(&address).copied();
        let mut edges = Vec::new();
        for (from, block) in blocks.iter().enumerate() {
            let Some(last) = block.lines.last() else { continue };
            // With delay slots, the branch sits before its slot at the end of the block, unless the slot is a
            // branch target and so starts a block of its own.
            let branches = |line: &&DisassemblyLine| !matches!(line.flow, Flow::Next | Flow::Invalid);
            let before_slot = block.lines.len().checked_sub(1 + delay_slots).and_then(|index| block.lines.get(index));
            let branch = before_slot.filter(|_| delay_slots > 0).filter(branches).unwrap_or(last);
            let end = ends[&block.start];
            let mut add = |to: Option<usize>, kind| {
                if let Some(to) = to {
                    edges.push(Edge { from, to, kind });
                }
            };
            match branch.flow {
                Flow::Jump(target) => add(index_of(target), EdgeKind::Unconditional),
                Flow::ConditionalJump(target) => {
                    add(index_of(target), EdgeKind::Taken);
                    add(index_of(end), EdgeKind::NotTaken);
                }
                // Cases in other functions are tail calls, not edges.
                Flow::IndirectJump => {
                    for &case in function.switch_cases(branch.address).unwrap_or_default() {
                        add(index_of(case), EdgeKind::Switch);
                    }
                }
                Flow::Return | Flow::Halt | Flow::Invalid => {}
                Flow::Call(_) | Flow::IndirectCall if program.is_noreturn_call(branch.address) => {}
                // A block that ends without a branch runs into the next one.
                Flow::Next | Flow::Call(_) | Flow::IndirectCall => add(index_of(end), EdgeKind::Unconditional),
            }
        }
        Ok(FunctionGraph { address: listing.address, name: listing.name, blocks, edges })
    }
}
