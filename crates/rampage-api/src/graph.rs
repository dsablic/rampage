//! A function's control-flow graph: its basic blocks and the branches between them.

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
        let delay_slots = usize::from(self.binary.arch.delay_slots());
        let blocks: Vec<GraphBlock> = listing
            .blocks
            .into_iter()
            .filter_map(|lines| Some(GraphBlock { start: lines.first()?.address, lines }))
            .collect();
        let index_of = |address: u64| blocks.iter().position(|block| block.start == address);
        let mut edges = Vec::new();
        for (from, block) in blocks.iter().enumerate() {
            let Some(last) = block.lines.last() else { continue };
            // With delay slots, the branch sits before its slot at the end of the block.
            let branch = block.lines.len().checked_sub(1 + delay_slots).and_then(|index| block.lines.get(index));
            let flow = branch.map_or(last.flow, |line| line.flow);
            let end = last.address + (last.bytes.len() / 2) as u64;
            let mut add = |to: Option<usize>, kind| {
                if let Some(to) = to {
                    edges.push(Edge { from, to, kind });
                }
            };
            match flow {
                Flow::Jump(target) => add(index_of(target), EdgeKind::Unconditional),
                Flow::ConditionalJump(target) => {
                    add(index_of(target), EdgeKind::Taken);
                    add(index_of(end), EdgeKind::NotTaken);
                }
                Flow::Return | Flow::IndirectJump | Flow::Halt | Flow::Invalid => {}
                // A block that ends without a branch runs into the next one.
                Flow::Next | Flow::Call(_) | Flow::IndirectCall => add(index_of(end), EdgeKind::Unconditional),
            }
        }
        Ok(FunctionGraph { address: listing.address, name: listing.name, blocks, edges })
    }
}
