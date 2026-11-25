//! Structure-field references whose base register is set in an earlier block.
//!
//! Discovery resolves a load or store through a base register only along the straight-line run that loaded the
//! base, and forgets registers where a branch joins the run. Code commonly loads a structure's address once (a
//! literal-pool load into a callee-saved register) and reads its fields inside a loop or after a branch. Once a
//! function's blocks are known, this carries the decoder's register values across its control-flow graph, as
//! [`super::joined_switches`] does for switch facts: a must-dataflow in which a block starts with the values every
//! edge into it agrees on. A path entering from outside the function, or at its entry, contributes nothing, so only
//! bases set inside the function on every path reach an access. Like the straight-line rule, this trusts that calls
//! keep the registers the calling convention preserves.

use std::collections::{BTreeSet, HashMap};

use rampage_arch::{Disassembler, Flow, RegisterFacts};
use rayon::prelude::*;

use super::joined_switches::{Exit, successors};
use super::{DiscoveredFunction, FieldRef, Program, Xref, XrefKind, field_ref};
use crate::memory::Memory;

/// Most block visits per block before a function's dataflow gives up; meets only lose values, so it settles well
/// before this.
const VISITS_PER_BLOCK: usize = 32;

/// Adds to `program` the field references that hold with register values carried across each function's blocks,
/// with a data xref for each. Only decoders whose facts carry bases (AArch32) take part.
pub(super) fn add<M, F, E>(memory: &M, new_decoder: &F, program: &mut Program) -> Result<(), E>
where
    M: Memory,
    F: Fn() -> Result<Box<dyn Disassembler>, E> + Sync,
    E: Send,
{
    if !new_decoder()?.facts().is_some_and(|facts| facts.carries_bases()) {
        return Ok(());
    }
    let mut entries: HashMap<u64, Vec<u64>> = HashMap::new();
    for xref in program.xrefs.iter().filter(|xref| xref.kind == XrefKind::Jump) {
        entries.entry(xref.to).or_default().push(xref.from);
    }
    let modes = &program.code_modes;
    let found: Result<Vec<Vec<FieldRef>>, E> = program
        .functions
        .par_iter()
        .filter(|function| function.blocks.len() > 1)
        .map_init(
            || None::<Box<dyn Disassembler>>,
            |cached, function| {
                let mut decoder = match cached.take() {
                    Some(decoder) => decoder,
                    None => {
                        let mut decoder = new_decoder()?;
                        decoder.set_code_modes(modes);
                        decoder
                    }
                };
                let fields = function_fields(memory, decoder.as_mut(), function, &entries);
                *cached = Some(decoder);
                Ok(fields)
            },
        )
        .collect();
    let mut added = false;
    for field in found?.into_iter().flatten() {
        if program.field_ref(field.from, field.to).is_none() {
            program.xrefs.push(Xref { to: field.to, from: field.from, kind: XrefKind::Data });
            program.field_refs.push(field);
            added = true;
        }
    }
    if added {
        program.xrefs.sort_unstable();
        program.xrefs.dedup();
        program.field_refs.sort_unstable();
        program.field_refs.dedup_by_key(|field| (field.to, field.from));
    }
    Ok(())
}

/// The field references in `function` with register values carried across its blocks; none when the dataflow
/// does not settle within its budget. `entries` lists, for every branch target in the program, the branches that
/// reach it.
fn function_fields(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    function: &DiscoveredFunction,
    entries: &HashMap<u64, Vec<u64>>,
) -> Vec<FieldRef> {
    decoder.begin_run();
    decoder.reset();
    let Some(nothing) = decoder.facts() else { return Vec::new() };
    let blocks = &function.blocks;
    let block_at = |address: u64| blocks.binary_search_by_key(&address, |block| block.start).ok();
    let read = |at: u64, size: u8| memory.read_pointer(at, size);

    // The instructions of every block, so branches from outside the function can be told apart.
    let mut instructions = BTreeSet::new();
    for block in blocks {
        let mut address = block.start;
        while address < block.end {
            let Some(bytes) = memory.code_from(address) else { break };
            let insn = decoder.decode(bytes, address);
            if decoder.decode_gate().is_some() || insn.flow == Flow::Invalid {
                instructions.insert(address);
                break;
            }
            instructions.insert(address);
            address += u64::from(insn.len);
        }
    }
    let entered_from_outside = |address: u64| {
        entries.get(&address).is_some_and(|sources| sources.iter().any(|source| !instructions.contains(source)))
    };

    // Decodes a block from `start_facts`: how it leaves, and the field references it makes.
    let run_block = |decoder: &mut dyn Disassembler, index: usize, start_facts: &RegisterFacts| {
        let block = blocks[index];
        decoder.reset();
        decoder.assume(start_facts);
        let mut exit = None;
        let mut fields = Vec::new();
        let mut address = block.start;
        while address < block.end {
            let Some(bytes) = memory.code_from(address) else { break };
            if address != block.start && entered_from_outside(address) {
                decoder.join();
            }
            let insn = decoder.decode_with_memory(bytes, address, &read);
            if decoder.decode_gate().is_some() || insn.flow == Flow::Invalid {
                break;
            }
            fields.extend(field_ref(memory, &insn, decoder.base_access()));
            let end = address + u64::from(insn.len);
            if end >= block.end {
                let taken = matches!(insn.flow, Flow::ConditionalJump(_)).then(|| decoder.taken_facts()).flatten();
                exit = Some(Exit { address, flow: insn.flow, end, fall_through: decoder.facts(), taken });
            }
            address = end;
        }
        (exit, fields)
    };

    let mut facts: Vec<Option<RegisterFacts>> = vec![None; blocks.len()];
    let mut worklist = BTreeSet::new();
    for (index, block) in blocks.iter().enumerate() {
        if block.start == function.address || entered_from_outside(block.start) {
            facts[index] = Some(nothing.clone());
            worklist.insert(index);
        }
    }
    let mut budget = blocks.len().saturating_mul(VISITS_PER_BLOCK);
    while let Some(index) = worklist.pop_first() {
        let Some(budget_left) = budget.checked_sub(1) else { return Vec::new() };
        budget = budget_left;
        let Some(start_facts) = facts[index].clone() else { continue };
        let (Some(exit), _) = run_block(decoder, index, &start_facts) else { continue };
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
    // The settled values at each block's start give every access it makes.
    let mut fields = Vec::new();
    for (index, start_facts) in facts.iter().enumerate() {
        if let Some(start_facts) = start_facts {
            fields.extend(run_block(decoder, index, start_facts).1);
        }
    }
    fields
}
