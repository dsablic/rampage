//! Structure-field references whose base register is set in an earlier block.
//!
//! Discovery resolves a load or store through a base register only along the straight-line run that loaded the
//! base, and forgets registers where a branch joins the run. Code commonly loads a structure's address once (a
//! literal-pool load into a callee-saved register) and reads its fields inside a loop or after a branch. Once a
//! function's blocks are known, this carries the decoder's register values across its control-flow graph
//! ([`super::register_flow`]): a block starts with the values every edge into it agrees on, so only bases set
//! inside the function on every path reach an access. Like the straight-line rule, this trusts that calls keep the
//! registers the calling convention preserves.

use rampage_arch::Disassembler;
use rayon::prelude::*;

use super::register_flow::{Joins, walk};
use super::{DiscoveredFunction, FieldRef, Program, Xref, XrefKind, field_ref};
use crate::memory::Memory;

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
    let joins = Joins::new(&program.functions, &program.xrefs);
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
                let fields = function_fields(memory, decoder.as_mut(), function, &joins);
                *cached = Some(decoder);
                Ok(fields)
            },
        )
        .collect();
    let found: Vec<FieldRef> = found?.into_iter().flatten().collect();
    if found.is_empty() {
        return Ok(());
    }
    program.xrefs.extend(found.iter().map(|field| Xref { to: field.to, from: field.from, kind: XrefKind::Data }));
    program.xrefs.sort_unstable();
    program.xrefs.dedup();
    program.field_refs.extend(found);
    program.field_refs.sort_unstable();
    program.field_refs.dedup_by_key(|field| (field.to, field.from));
    Ok(())
}

/// The field references in `function` that only register values carried across its blocks give: those of blocks
/// that start with a base known (the straight-line pass found the rest). None when the dataflow does not settle.
fn function_fields(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    function: &DiscoveredFunction,
    joins: &Joins,
) -> Vec<FieldRef> {
    // Each block's references from its latest visit, whose start values are the settled ones.
    let mut fields: Vec<Vec<FieldRef>> = vec![Vec::new(); function.blocks.len()];
    let mut carries = vec![false; function.blocks.len()];
    let settled = walk(memory, decoder, function, joins, |index, start, insn, decoder| {
        if insn.address == function.blocks[index].start {
            fields[index].clear();
            carries[index] = start.has_bases();
        }
        if carries[index] {
            fields[index].extend(field_ref(memory, insn, decoder.base_access()));
        }
    });
    if !settled {
        return Vec::new();
    }
    fields.into_iter().flatten().collect()
}
