//! Switch jump tables whose index bound, index copy or table base is set up in an earlier block.
//!
//! The decoder proves a switch's facts along one straight-line run and forgets them where a branch joins it. Once a
//! function's blocks are known, this carries the decoder's register facts across its control-flow graph instead
//! ([`super::register_flow`]): only facts established inside the function on every path to the jump survive. A
//! bound holds only on the successor edge that proved it: the fall-through of `ja` / AArch64 `b.hi`, or the taken
//! edge of AArch64 `b.ls`.
//!
//! A table resolved this way adds case edges, which may join the paths it was proven on, so discovery explores the
//! function again assuming it and keeps it only if the facts still prove the same table over the larger graph
//! (see [`resolve`]). Like the straight-line rule, this trusts that no unresolved indirect jump lands on those
//! paths, and that calls keep the registers every calling convention preserves.

use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::{Disassembler, Flow, JumpTable};
use rayon::prelude::*;

use super::register_flow::{Joins, walk};
use super::{Explored, switch_targets};
use crate::memory::Memory;

/// Switch tables proven across joins, by function entry and jump address.
pub(super) type Assumed = BTreeMap<(u64, u64), JumpTable>;

/// For each function in `results`, the tables of the register-indirect jumps it left unresolved, and of the jumps
/// it resolved by assuming `assumed`, that its register facts prove on every path through its current blocks.
pub(super) fn resolve<M, F, E>(
    memory: &M,
    new_decoder: &F,
    results: &BTreeMap<u64, Explored>,
    assumed: &Assumed,
) -> Result<Assumed, E>
where
    M: Memory,
    F: Fn() -> Result<Box<dyn Disassembler>, E> + Sync,
    E: Send,
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
    if pending.is_empty() {
        return Ok(Assumed::new());
    }
    if !new_decoder()?.facts().is_some_and(|facts| facts.resolves_switches()) {
        return Ok(Assumed::new());
    }
    let joins =
        Joins::new(results.values().map(|result| &result.function), results.values().flat_map(|result| &result.xrefs));
    let tables: Result<Vec<Vec<_>>, E> = pending
        .par_iter()
        .map_init(
            || None::<Box<dyn Disassembler>>,
            |cached, (result, jumps)| {
                let mut decoder = match cached.take() {
                    Some(decoder) => decoder,
                    None => new_decoder()?,
                };
                let tables = function_tables(memory, decoder.as_mut(), result, jumps, &joins)
                    .into_iter()
                    .map(|(jump, table)| ((result.function.address, jump), table))
                    .collect();
                *cached = Some(decoder);
                Ok(tables)
            },
        )
        .collect();
    Ok(tables?.into_iter().flatten().collect())
}

/// The tables of `jumps` in `result`'s function that hold with facts carried across its blocks.
fn function_tables(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    result: &Explored,
    jumps: &[u64],
    joins: &Joins,
) -> Vec<(u64, JumpTable)> {
    let function = &result.function;
    let wanted: BTreeSet<u64> = jumps.iter().copied().collect();
    let mut tables = BTreeMap::new();
    let settled = walk(memory, decoder, function, joins, |index, _, insn, decoder| {
        let ends_block = insn.address + u64::from(insn.len) >= function.blocks[index].end;
        if ends_block && insn.flow == Flow::IndirectJump && wanted.contains(&insn.address) {
            tables.insert(insn.address, decoder.jump_table());
        }
    });
    if !settled {
        return Vec::new();
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
