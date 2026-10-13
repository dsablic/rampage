//! Recursive-descent function discovery.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::{Disassembler, Flow, JumpTable, MAX_JUMP_TABLE_ENTRIES};
use rampage_loaders::Binary;
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
    /// Register-indirect jumps resolved through bounded switch tables, sorted by jump address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<Switch>,
}

/// A register-indirect jump whose successors are the cases of a bounded switch table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Switch {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub jump: u64,
    /// Sorted and distinct. A case may be another function's entry.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub cases: Vec<u64>,
    /// The target of each table entry in table order: entry `i` is selected by switch index `i`.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub table: Vec<u64>,
    /// The comparison that bounds the index; out-of-range indices take its branch instead of the table.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub guard: u64,
}

impl DiscoveredFunction {
    /// The case targets of the switch that the register-indirect jump at `jump` was resolved to, if it was.
    pub fn switch_cases(&self, jump: u64) -> Option<&[u64]> {
        let index = self.switches.binary_search_by_key(&jump, |switch| switch.jump).ok()?;
        Some(&self.switches[index].cases)
    }

    pub fn contains(&self, address: u64) -> bool {
        self.blocks.iter().any(|block| (block.start..block.end).contains(&address))
    }

    /// Exclusive end of the body extent: the largest block end, or the start when there are no blocks. The extent
    /// `address..end()` also spans any gaps between blocks.
    pub fn end(&self) -> u64 {
        self.blocks.iter().map(|block| block.end).max().unwrap_or(self.address)
    }

    /// The image bytes of the body extent `address..end()`, or `None` when it is empty or not fully mapped.
    pub fn body<'a>(&self, binary: &'a Binary) -> Option<&'a [u8]> {
        let length = self.end().checked_sub(self.address).filter(|&length| length > 0)?;
        binary.read(self.address, length)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

impl XrefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Data => "data",
        }
    }
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_modes: Vec<(u64, bool)>,
    #[serde(skip)]
    pub resolved_flows: Vec<ResolvedFlow>,
    /// Functions, import stubs and import slots known by name or inferred never to return, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "rampage_arch::hex::addresses")]
    pub noreturn: Vec<u64>,
    /// The [`Program::noreturn`] functions that discovery inferred, rather than knew by name, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "rampage_arch::hex::addresses")]
    pub inferred_noreturn: Vec<u64>,
    /// Calls to a [`Program::noreturn`] callee, sorted: each ends its block with no fall-through.
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "rampage_arch::hex::addresses")]
    pub noreturn_calls: Vec<u64>,
}

/// Why a call is taken never to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NoreturnEvidence {
    /// The callee's name is on the list of functions documented never to return.
    Listed,
    /// Discovery inferred it: no path through the callee returns, and one ends in a noreturn call or a trap.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedFlow {
    pub function: u64,
    pub address: u64,
    pub flow: Flow,
}

impl Program {
    pub fn function_at(&self, address: u64) -> Option<&DiscoveredFunction> {
        let index = self.functions.binary_search_by_key(&address, |function| function.address).ok()?;
        Some(&self.functions[index])
    }

    /// Whether the call at `address` never returns, so nothing falls through after it.
    pub fn is_noreturn_call(&self, address: u64) -> bool {
        self.noreturn_calls.binary_search(&address).is_ok()
    }

    /// Why the call at `address`, which may reach `callees` (its target, or the import slot it goes through), never
    /// returns; `None` when it may.
    pub fn noreturn_evidence(&self, address: u64, callees: &[u64]) -> Option<NoreturnEvidence> {
        if !self.is_noreturn_call(address) {
            return None;
        }
        let listed = callees.iter().any(|callee| {
            self.noreturn.binary_search(callee).is_ok() && self.inferred_noreturn.binary_search(callee).is_err()
        });
        Some(if listed { NoreturnEvidence::Listed } else { NoreturnEvidence::Inferred })
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
/// their call targets, code pointers, and any unconditional jump target reached from two or more functions (a shared
/// tail, which would otherwise be copied into every caller). Phase 2 then builds every function's blocks against
/// that final set, so whether a jump is a tail call does not depend on the round its target was found in.
/// Merges are ordered by address, so the result does not depend on thread count or scheduling.
///
/// No callee is known not to return beyond what discovery infers; see [`discover_with_noreturn`].
pub fn discover<M, F>(memory: &M, new_decoder: F, seeds: &[u64]) -> Program
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    discover_with_noreturn(memory, new_decoder, seeds, &ReturnFacts::default())
}

/// What is known, before discovery, about whether callees return.
#[derive(Debug, Clone, Default)]
pub struct ReturnFacts {
    /// Functions, import stubs and import slots that never return.
    pub noreturn: BTreeSet<u64>,
    /// Functions never inferred noreturn: they resume their caller through a saved context, not a return.
    pub returns: BTreeSet<u64>,
}

/// [`discover`], where a call to an address in `facts.noreturn` (a function, or the import slot an indirect call
/// goes through) ends its block with no fall-through. A function is inferred not to return when no path through it
/// returns and at least one ends in a noreturn call or a trap. Anything unknown on a path (an unresolved indirect
/// jump, undecodable bytes, a tail call to a function that may return) counts as returning, and nothing in
/// `facts.returns` is inferred.
///
/// Each discovery infers to a fixpoint by re-exploring only the functions that reach a newly inferred one. Ending
/// those calls can drop code, and so function starts and branch targets, that the discovery was built on; it is
/// repeated with everything inferred until it infers nothing more, which the growing noreturn set guarantees.
pub fn discover_with_noreturn<M, F>(memory: &M, new_decoder: F, seeds: &[u64], facts: &ReturnFacts) -> Program
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    let mut noreturn = facts.noreturn.clone();
    loop {
        let (mut program, inferred) = discover_round(memory, &new_decoder, seeds, &noreturn, &facts.returns);
        if inferred.is_subset(&noreturn) {
            program.inferred_noreturn = noreturn.difference(&facts.noreturn).copied().collect();
            program.noreturn = noreturn.into_iter().collect();
            return program;
        }
        noreturn.extend(inferred);
    }
}

/// One discovery with the callees in `noreturn` known not to return. Returns it with `noreturn` and every function
/// inferred from it; when nothing new is inferred the discovery is exact for `noreturn`.
fn discover_round<M, F>(
    memory: &M,
    new_decoder: &F,
    seeds: &[u64],
    noreturn: &BTreeSet<u64>,
    returns: &BTreeSet<u64>,
) -> (Program, BTreeSet<u64>)
where
    M: Memory,
    F: Fn() -> Box<dyn Disassembler> + Sync,
{
    let explore_with = |starts: &[u64],
                        known: &BTreeSet<u64>,
                        branch_targets: Option<&[u64]>,
                        modes: &[(u64, bool)],
                        noreturn: &BTreeSet<u64>|
     -> Vec<Explored> {
        starts
            .par_iter()
            .map_init(new_decoder, |decoder, &start| {
                decoder.set_code_modes(modes);
                explore(memory, decoder.as_mut(), known, branch_targets, noreturn, start)
            })
            .collect()
    };
    let explore_all = |starts: &[u64], known: &BTreeSet<u64>, branch_targets: Option<&[u64]>, modes: &[(u64, bool)]| {
        explore_with(starts, known, branch_targets, modes, noreturn)
    };

    let initial_seeds: BTreeSet<u64> = seeds.iter().copied().filter(|&seed| memory.is_executable(seed)).collect();
    let mut code_modes = BTreeMap::new();
    let mut seen_modes = BTreeSet::new();
    let mut ambiguous_modes = BTreeSet::new();
    let mut previous_contributions = Vec::new();
    let mut previous_instruction_modes = BTreeMap::new();
    let mut previous_instruction_owners = BTreeMap::new();
    seen_modes.insert(Vec::<(u64, bool)>::new());
    // Starts whose first instruction does not decode are not functions, in either phase.
    let (mut known, mut branch_targets, mut undecodable) = loop {
        let mut known = initial_seeds.clone();
        let mut pending: Vec<_> = known.iter().copied().collect();
        let mut first_jumper: HashMap<u64, u64> = HashMap::new();
        let mut empty = BTreeSet::new();
        let mut branch_targets = Vec::new();
        let mut contributions = Vec::new();
        let mut instruction_modes = BTreeMap::new();
        let mut instruction_owners = BTreeMap::new();
        let modes: Vec<_> = code_modes.iter().map(|(&at, &thumb)| (at, thumb)).collect();
        while !pending.is_empty() {
            let mut next = BTreeSet::new();
            for result in explore_all(&pending, &known, None, &modes) {
                contributions.extend(result.mode_hints);
                instruction_owners
                    .extend(result.instruction_modes.iter().map(|&(at, _)| (at, result.function.address)));
                instruction_modes.extend(result.instruction_modes);
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
        let mut merged = BTreeMap::new();
        for &(source, at, thumb) in &contributions {
            if !ambiguous_modes.contains(&source) {
                merged.entry(at).or_insert(thumb);
            }
        }
        if merged == code_modes {
            known.retain(|start| !empty.contains(start));
            break (known, branch_targets, empty);
        }
        let state: Vec<_> = merged.iter().map(|(&at, &thumb)| (at, thumb)).collect();
        if !seen_modes.insert(state) {
            for &at in merged.keys().chain(code_modes.keys()) {
                if merged.get(&at) != code_modes.get(&at) {
                    for &(source, target, _) in contributions.iter().chain(&previous_contributions) {
                        let changed = match (instruction_modes.get(&source), previous_instruction_modes.get(&source)) {
                            (Some(current), Some(previous)) => current != previous,
                            (Some(_), None) | (None, Some(_)) => {
                                let owner = instruction_owners
                                    .get(&source)
                                    .or_else(|| previous_instruction_owners.get(&source));
                                let target_owner = instruction_owners
                                    .get(&target)
                                    .or_else(|| previous_instruction_owners.get(&target));
                                owner.is_some() && owner == target_owner
                            }
                            _ => false,
                        };
                        if target == at && changed {
                            ambiguous_modes.insert(source);
                        }
                    }
                }
            }
            merged.clear();
            for &(source, at, thumb) in &contributions {
                if !ambiguous_modes.contains(&source) {
                    merged.entry(at).or_insert(thumb);
                }
            }
            seen_modes.clear();
            seen_modes.insert(merged.iter().map(|(&at, &thumb)| (at, thumb)).collect());
        }
        previous_contributions = contributions;
        previous_instruction_modes = instruction_modes;
        previous_instruction_owners = instruction_owners;
        code_modes = merged;
    };

    // Phase 1 saw every branch; a fall-through that is also a branch target joins paths and starts afresh.
    branch_targets.sort_unstable();
    branch_targets.dedup();
    let (mut results, modes) = loop {
        let starts: Vec<u64> = known.iter().copied().collect();
        let mut results = BTreeMap::new();
        let mut added = BTreeSet::new();
        let mut targets = branch_targets.clone();
        let mut jump_owners = HashMap::new();
        let modes: Vec<_> = code_modes.iter().map(|(&at, &thumb)| (at, thumb)).collect();
        for result in explore_all(&starts, &known, Some(&branch_targets), &modes) {
            if result.function.blocks.is_empty() {
                undecodable.insert(result.function.address);
                continue;
            }
            for target in &result.jump_targets {
                if let Some(owner) = jump_owners.insert(*target, result.function.address)
                    && owner != result.function.address
                    && !known.contains(target)
                {
                    added.insert(*target);
                }
            }
            code_modes.extend(result.instruction_modes.iter().copied());
            for &(_, at, thumb) in &result.mode_hints {
                code_modes.entry(at).or_insert(thumb);
            }
            added.extend(
                result
                    .new_seeds
                    .iter()
                    .copied()
                    .filter(|&at| !known.contains(&at) && !undecodable.contains(&at) && memory.is_executable(at)),
            );
            targets.extend_from_slice(&result.branch_targets);
            results.insert(result.function.address, result);
        }
        targets.sort_unstable();
        targets.dedup();
        let explored = known.len();
        known.retain(|start| !undecodable.contains(start));
        if added.is_empty() && targets == branch_targets && known.len() == explored {
            break (results, modes);
        }
        known.extend(added);
        branch_targets = targets;
    };

    // Infer to a fixpoint over this set of functions: a newly inferred function changes only the functions that
    // call it, jump to it, point at it or run into it.
    let mut noreturn = noreturn.clone();
    loop {
        let newly: BTreeSet<u64> = results
            .values()
            .filter(|result| result.never_returns)
            .map(|result| result.function.address)
            .filter(|address| !returns.contains(address) && !noreturn.contains(address))
            .collect();
        if newly.is_empty() {
            break;
        }
        noreturn.extend(&newly);
        let affected: Vec<u64> =
            results.values().filter(|result| result.reaches(&newly)).map(|result| result.function.address).collect();
        for result in explore_with(&affected, &known, Some(&branch_targets), &modes, &noreturn) {
            results.insert(result.function.address, result);
        }
    }

    let mut functions = Vec::with_capacity(results.len());
    let (mut xrefs, mut resolved_flows, mut noreturn_calls) = (Vec::new(), Vec::new(), Vec::new());
    for result in results.into_values() {
        xrefs.extend(result.xrefs);
        resolved_flows.extend(result.resolved_flows);
        noreturn_calls.extend(result.noreturn_calls);
        functions.push(result.function);
    }
    xrefs.sort_unstable();
    xrefs.dedup();
    resolved_flows.sort_by_key(|flow| (flow.function, flow.address));
    noreturn_calls.sort_unstable();
    noreturn_calls.dedup();
    let code_modes = code_modes.into_iter().collect();
    let program = Program { functions, xrefs, code_modes, resolved_flows, noreturn_calls, ..Program::default() };
    (program, noreturn)
}

struct Explored {
    resolved_flows: Vec<ResolvedFlow>,
    mode_hints: Vec<(u64, u64, bool)>,
    instruction_modes: Vec<(u64, bool)>,
    function: DiscoveredFunction,
    xrefs: Vec<Xref>,
    new_seeds: Vec<u64>,
    /// Targets of unconditional jumps to code outside this function's known starts; one reached from two
    /// functions is a shared tail and becomes a function of its own. Code shared through conditional branches
    /// stays in each function that reaches it (as IDA's function chunks do): promoting it cascades, splitting the
    /// owner's own blocks into fragments.
    jump_targets: Vec<u64>,
    /// Targets of every branch taken while exploring.
    branch_targets: Vec<u64>,
    /// Calls that end their block because the callee never returns.
    noreturn_calls: Vec<u64>,
    /// No path through the function returns, and at least one ends in a noreturn call or a trap.
    never_returns: bool,
}

/// Explores the function at `start`. `all_branch_targets`, when given, lists every branch target in the program:
/// a conditional branch's fall-through keeps the decoder state (AArch64 ADRP pages) of the path into it unless a
/// branch also lands there.
fn explore(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    known: &BTreeSet<u64>,
    all_branch_targets: Option<&[u64]>,
    noreturn: &BTreeSet<u64>,
    start: u64,
) -> Explored {
    decoder.begin_run();
    let is_other_function = |address: u64| address != start && known.contains(&address);
    let mut exits = Exits::default();
    let mut noreturn_calls = Vec::new();
    // A conditional call may be skipped, so only an unconditional one ends its block.
    let never_returns = |insn: &rampage_arch::Insn, resolved: Option<Flow>| match insn.flow {
        _ if insn.conditional => false,
        Flow::Call(target) => noreturn.contains(&target),
        Flow::IndirectCall | Flow::IndirectJump => {
            let resolved = resolved.and_then(|flow| match flow {
                Flow::Call(target) | Flow::Jump(target) => Some(target),
                _ => None,
            });
            insn.data_ref.into_iter().chain(resolved).any(|target| noreturn.contains(&target))
        }
        _ => false,
    };
    let trust_immediates = memory.immediates_may_be_addresses();
    let delay_slots = decoder.delay_slots();
    // Data references and code pointers an instruction contributes.
    let record_refs = |insn: &rampage_arch::Insn, xrefs: &mut Vec<Xref>, code_pointers: &mut Vec<u64>| {
        let immediate = insn.immediate.filter(|_| trust_immediates);
        for target in insn.data_ref.into_iter().chain(immediate).filter(|&target| memory.is_mapped(target)) {
            xrefs.push(Xref { to: target, from: insn.address, kind: XrefKind::Data });
            let code = memory.code_address(target);
            if memory.is_executable(code) {
                code_pointers.push(code);
            }
        }
    };
    let mut blocks: BTreeMap<u64, u64> = BTreeMap::new();
    let mut instructions: BTreeSet<u64> = BTreeSet::new();
    let mut xrefs = Vec::new();
    let mut new_seeds = Vec::new();
    let mut code_pointers = Vec::new();
    let mut jump_bases = Vec::new();
    let mut jump_targets = Vec::new();
    let mut branch_targets = Vec::new();
    let mut instruction_modes = Vec::new();
    let mut mode_hints = Vec::new();
    let mut resolved_flows = Vec::new();
    let mut switches = Vec::new();
    let mut worklist = vec![start];
    // A conditional branch's fall-through is explored next; it keeps the decoder state only when no branch joins
    // it there.
    let mut fall_through = None;
    let carries_state =
        |address: u64| all_branch_targets.is_some_and(|targets| targets.binary_search(&address).is_err());
    let joins_run = |address: u64| all_branch_targets.is_some_and(|targets| targets.binary_search(&address).is_ok());

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
            if is_other_function(address) || address != block_start && instructions.contains(&address) {
                if is_other_function(address) {
                    exits.leave_to(address, noreturn);
                }
                if let Some(thumb) = decoder.code_mode_at(address) {
                    mode_hints.push((block_start, address, thumb));
                }
                split_block(&mut blocks, address);
                break;
            }
            let Some(bytes) = memory.code_from(address) else {
                exits.returns = true;
                break;
            };
            // Facts proven earlier in the run (a switch's table base, an index's zeroed upper half) do not hold on
            // a path that branches in here.
            if address != block_start && joins_run(address) {
                decoder.join();
            }
            let insn = decoder.decode_with_memory(bytes, address, &|at, size| memory.read_pointer(at, size));
            let resolved = decoder.resolved_flow();
            if let Some(flow) = resolved {
                resolved_flows.push(ResolvedFlow { function: start, address, flow });
            }
            jump_bases.extend(decoder.indirect_jump_base());
            let jump_table = decoder.jump_table();
            mode_hints.extend(decoder.code_modes().into_iter().map(|(at, thumb)| (address, at, thumb)));
            if insn.flow == Flow::Invalid {
                exits.returns = true;
                break;
            }
            instructions.insert(address);
            if let Some(thumb) = decoder.instruction_mode() {
                instruction_modes.push((address, thumb));
            }
            let Some(mut next) = address.checked_add(u64::from(insn.len)) else {
                exits.returns = true;
                break;
            };
            // MIPS and SPARC execute the instruction after a branch before the branch takes effect: it belongs to
            // the branch's block, and execution falls through past it.
            if delay_slots > 0 && !matches!(insn.flow, Flow::Next | Flow::Invalid | Flow::Halt) {
                for _ in 0..delay_slots {
                    let Some(bytes) = memory.code_from(next) else { break };
                    let slot = decoder.decode_with_memory(bytes, next, &|at, size| memory.read_pointer(at, size));
                    if slot.flow == Flow::Invalid {
                        break;
                    }
                    instructions.insert(next);
                    record_refs(&slot, &mut xrefs, &mut code_pointers);
                    next = next.saturating_add(u64::from(slot.len));
                }
            }
            record_refs(&insn, &mut xrefs, &mut code_pointers);
            let stops = never_returns(&insn, resolved);
            match insn.flow {
                Flow::Next => {
                    // A conditional return or indirect jump may leave the function here.
                    exits.returns |= insn.conditional;
                    address = next;
                }
                Flow::Call(_) | Flow::IndirectCall => {
                    if let Flow::Call(target) = insn.flow {
                        xrefs.push(Xref { to: target, from: address, kind: XrefKind::Call });
                        new_seeds.push(target);
                    }
                    let call = address;
                    address = next;
                    if stops {
                        exits.stops = true;
                        noreturn_calls.push(call);
                        break;
                    }
                }
                Flow::ConditionalJump(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                    branch_targets.push(target);
                    if is_other_function(target) {
                        exits.leave_to(target, noreturn);
                    } else {
                        worklist.push(target);
                    }
                    if is_other_function(next) {
                        exits.leave_to(next, noreturn);
                    } else {
                        fall_through = Some(next);
                    }
                    address = next;
                    break;
                }
                Flow::Jump(target) => {
                    xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                    branch_targets.push(target);
                    if is_other_function(target) {
                        exits.leave_to(target, noreturn);
                    } else {
                        worklist.push(target);
                        jump_targets.push(target);
                    }
                    address = next;
                    break;
                }
                Flow::IndirectJump => {
                    let resolved = jump_table.and_then(|table| {
                        let entries = switch_targets(memory, decoder, &table, address, all_branch_targets?)?;
                        Some((table.guard, entries))
                    });
                    if let Some((guard, table)) = resolved {
                        let mut cases = table.clone();
                        cases.sort_unstable();
                        cases.dedup();
                        for &target in &cases {
                            xrefs.push(Xref { to: target, from: address, kind: XrefKind::Jump });
                            branch_targets.push(target);
                            if is_other_function(target) {
                                exits.leave_to(target, noreturn);
                            } else {
                                worklist.push(target);
                            }
                        }
                        switches.push(Switch { jump: address, cases, table, guard });
                    } else if stops {
                        exits.stops = true;
                    } else {
                        exits.returns = true;
                    }
                    address = next;
                    break;
                }
                Flow::Return | Flow::Invalid => {
                    exits.returns = true;
                    address = next;
                    break;
                }
                Flow::Halt => {
                    exits.stops = true;
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
    switches.sort_unstable_by_key(|switch: &Switch| switch.jump);
    let function = DiscoveredFunction { address: start, blocks, instruction_count: instructions.len(), switches };
    // The base an AArch64 switch adds its jump-table offsets to is a label inside the function, not another
    // function's entry. Other code addresses formed inside the extent may be: it can run past a noreturn call.
    let end = function.end();
    let is_local_jump_base = |target: u64| start < target && target < end && jump_bases.contains(&target);
    new_seeds.extend(code_pointers.into_iter().filter(|&target| !is_local_jump_base(target)));
    Explored {
        function,
        xrefs,
        new_seeds,
        jump_targets,
        branch_targets,
        mode_hints,
        instruction_modes,
        resolved_flows,
        noreturn_calls,
        never_returns: exits.stops && !exits.returns,
    }
}

impl Explored {
    /// Whether a call, jump, code pointer, resolved indirect transfer or fall-through of this function reaches one
    /// of `functions`.
    fn reaches(&self, functions: &BTreeSet<u64>) -> bool {
        self.xrefs.iter().any(|xref| functions.contains(&xref.to))
            || self.resolved_flows.iter().any(|flow| match flow.flow {
                Flow::Call(target) | Flow::Jump(target) => functions.contains(&target),
                _ => false,
            })
            || self.function.blocks.iter().any(|block| functions.contains(&block.end))
    }
}

/// How the paths through a function leave it.
#[derive(Default)]
struct Exits {
    /// Some path returns, or leaves through something unknown that may.
    returns: bool,
    /// Some path ends in a noreturn call or a trap.
    stops: bool,
}

impl Exits {
    /// A path that runs into, or tail-calls, the function at `target`.
    fn leave_to(&mut self, target: u64, noreturn: &BTreeSet<u64>) {
        if noreturn.contains(&target) {
            self.stops = true;
        } else {
            self.returns = true;
        }
    }
}

/// The entry targets, in table order, of the switch whose register-indirect jump at `jump` dispatches through
/// `table`, or `None` to leave the jump unresolved. The decoder proved the index bound along the straight-line run
/// from the comparison, so it holds only if no branch joins that run after the comparison. Every entry must be read
/// from read-only image data and select an instruction in code.
fn switch_targets(
    memory: &impl Memory,
    decoder: &mut dyn Disassembler,
    table: &JumpTable,
    jump: u64,
    joins: &[u64],
) -> Option<Vec<u64>> {
    let after_guard = joins.partition_point(|&target| target <= table.guard);
    let joined = joins.get(after_guard).is_some_and(|&target| target <= jump);
    if joined || table.entries > MAX_JUMP_TABLE_ENTRIES {
        return None;
    }
    (0..table.entries)
        .map(|index| {
            let raw = memory.read_constant(table.slot(index)?, table.entry_size)?;
            let target = table.target(raw)?;
            let bytes = memory.code_from(target)?;
            (decoder.decode(bytes, target).flow != Flow::Invalid).then_some(target)
        })
        .collect::<Option<Vec<_>>>()
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
    mod x86_switch;

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
    fn a_code_pointer_to_undecodable_bytes_is_not_a_function() {
        // 0: lea rax, [rip + 1] (0x8); 7: ret; 8: an opcode invalid in 64-bit mode (hello-arm.elf's literal 0x2036c)
        let program = run(&[0x48, 0x8d, 0x05, 0x01, 0, 0, 0, 0xc3, 0x06], &[0]);
        let starts: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(starts, [0]);
    }

    #[test]
    fn a_jump_table_base_inside_the_function_is_not_a_function() {
        // 0: cbz w0, 0x10; 4: adr x9, 0xc; 8: br x9; c: ret (a case reached only through x9); 10: ret
        let words: [u32; 5] = [0x3400_0080, 0x1000_0049, 0xd61f_0120, 0xd65f_03c0, 0xd65f_03c0];
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let memory = FlatMemory { base: 0, bytes };
        let program = discover(&memory, || decoder_for(Arch::Aarch64).unwrap(), &[0]);
        let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(addresses, [0]);
        assert!(program.xrefs.contains(&Xref { to: 0xc, from: 4, kind: XrefKind::Data }), "{:?}", program.xrefs);
    }

    #[test]
    fn code_addresses_formed_inside_the_extent_still_seed_functions() {
        // 0: lea rdi, [0xc]; 7: call 0x20; c: xor eax, eax; f: ret; 20: ret. The call may not return, so the
        // extent runs on into the function at 0xc.
        let mut bytes = vec![0x48, 0x8d, 0x3d, 0x05, 0, 0, 0, 0xe8, 0x14, 0, 0, 0, 0x31, 0xc0, 0xc3];
        bytes.resize(0x21, 0xcc);
        bytes[0x20] = 0xc3;
        let program = run(&bytes, &[0]);
        assert_eq!(blocks(&program, 0), [(0, 0xc)]);
        assert_eq!(blocks(&program, 0xc), [(0xc, 0xf)]);
        assert_eq!(blocks(&program, 0x20), [(0x20, 0x21)]);

        // 0: lea rdi, [0x20]; 7: jmp 0x40; 20: ret; 40: ret. The jump target is folded into the function at 0,
        // whose extent then spans the callback at 0x20.
        let mut bytes = vec![0x48, 0x8d, 0x3d, 0x19, 0, 0, 0, 0xe9, 0x34, 0, 0, 0];
        bytes.resize(0x41, 0xcc);
        bytes[0x20] = 0xc3;
        bytes[0x40] = 0xc3;
        let program = run(&bytes, &[0]);
        let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(addresses, [0, 0x20]);
    }

    #[test]
    fn a_switch_base_offset_by_a_table_entry_is_not_a_function() {
        // 0: cbz w0, 0x14; 4: adr x9, 0x10; 8: add x9, x9, x0, lsl #2; c: br x9; 10: ret (case 0); 14: ret
        let words: [u32; 6] = [0x3400_00a0, 0x1000_0069, 0x8b00_0929, 0xd61f_0120, 0xd65f_03c0, 0xd65f_03c0];
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let memory = FlatMemory { base: 0, bytes };
        let program = discover(&memory, || decoder_for(Arch::Aarch64).unwrap(), &[0]);
        let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
        assert_eq!(addresses, [0]);
    }

    /// AArch64 code at 0, read-only data at `RODATA` and writable data at `DATA`.
    struct Image {
        code: Vec<u8>,
        rodata: Vec<u8>,
        data: Vec<u8>,
    }

    const RODATA: u64 = 0x10000;
    const DATA: u64 = 0x20000;

    impl Image {
        fn region(&self, address: u64) -> Option<(&[u8], usize)> {
            [(0, &self.code), (RODATA, &self.rodata), (DATA, &self.data)].into_iter().find_map(|(base, bytes)| {
                let offset = usize::try_from(address.checked_sub(base)?).ok()?;
                (offset < bytes.len()).then_some((bytes.as_slice(), offset))
            })
        }
    }

    impl Memory for Image {
        fn code_from(&self, address: u64) -> Option<&[u8]> {
            self.code.get(usize::try_from(address).ok()?..).filter(|rest| !rest.is_empty())
        }
        fn is_mapped(&self, address: u64) -> bool {
            self.region(address).is_some()
        }
        fn is_executable(&self, address: u64) -> bool {
            self.code_from(address).is_some()
        }
        fn immediates_may_be_addresses(&self) -> bool {
            false
        }
        fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
            let (bytes, offset) = self.region(address).filter(|_| (RODATA..DATA).contains(&address))?;
            rampage_arch::bytes::read_uint(bytes, offset, usize::from(size), false)
        }
    }

    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    /// cmp w0, #3; b.hi 0x38 (the default case, from 0xc)
    const BOUND: [u32; 2] = [0x7100_0c1f, 0x5400_0168];
    const CASES: [u64; 4] = [0x28, 0x2c, 0x30, 0x34];
    const DEFAULT: u64 = 0x38;

    fn adr(rd: u32, from: u64, to: u64) -> u32 {
        let offset = to.wrapping_sub(from) as u32;
        0x1000_0000 | (offset & 3) << 29 | (offset >> 2 & 0x7_ffff) << 5 | rd
    }

    /// A switch on w0: `0: prefix; 8: bound; 10: gap; 14: adr x9, table; 18: adr x10, anchor; 1c: load; 20: add;
    /// 24: br; 28..38: four cases; 38: default`. Every case and the default is a `ret`.
    struct Switch {
        prefix: [u32; 2],
        bound: [u32; 2],
        gap: u32,
        table: u64,
        anchor: u64,
        load: u32,
        add: u32,
        jump: u32,
    }

    impl Switch {
        fn new(load: u32, add: u32, anchor: u64) -> Switch {
            Switch { prefix: [NOP, NOP], bound: BOUND, gap: NOP, table: RODATA, anchor, load, add, jump: 0xd61f_0140 }
        }

        fn discover(&self, rodata: Vec<u8>, data: Vec<u8>) -> Program {
            let mut words = vec![self.prefix[0], self.prefix[1], self.bound[0], self.bound[1], self.gap];
            words.extend([adr(9, 0x14, self.table), adr(10, 0x18, self.anchor), self.load, self.add, self.jump]);
            words.extend([RET; 5]);
            let code = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let image = Image { code, rodata, data };
            discover(&image, || decoder_for(Arch::Aarch64).unwrap(), &[0])
        }
    }

    fn resolved(program: &Program) -> bool {
        let function = program.function_at(0).unwrap();
        let reached = CASES.iter().filter(|&&case| function.contains(case)).count();
        assert!(reached == 0 || reached == CASES.len(), "{function:?}");
        reached == CASES.len()
    }

    /// Entries for `CASES` relative to `anchor`, scaled down by `shift`, as `size`-byte little-endian values.
    fn relative_entries(anchor: u64, shift: u32, size: usize) -> Vec<u8> {
        let entry = |case: u64| (case.wrapping_sub(anchor) as i64 >> shift).to_le_bytes();
        CASES.iter().flat_map(|&case| entry(case)[..size].to_vec()).collect()
    }

    #[test]
    fn bounded_switch_tables_of_every_entry_form_reach_their_cases() {
        const ADD_LSL2: u32 = 0x8b0b_094a;
        const ADD: u32 = 0x8b0b_014a;
        // (load, add, anchor, entry shift, entry size): unsigned forms use the first case as the anchor, signed
        // forms the default after the cases, so their entries are negative.
        let forms = [
            (0x3860_492b, ADD_LSL2, CASES[0], 2, 1),   // ldrb w11, [x9, w0, uxtw]
            (0x38a0_492b, ADD_LSL2, DEFAULT, 2, 1),    // ldrsb x11, [x9, w0, uxtw]
            (0x3860_492b, 0x8b2b_894a, DEFAULT, 2, 1), // ldrb w11, ...; add x10, x10, w11, sxtb #2
            (0x7860_592b, ADD_LSL2, CASES[0], 2, 2),   // ldrh w11, [x9, w0, uxtw #1]
            (0x78a0_592b, ADD_LSL2, DEFAULT, 2, 2),    // ldrsh x11, [x9, w0, uxtw #1]
            (0x7860_592b, 0x8b2b_a94a, DEFAULT, 2, 2), // ldrh w11, ...; add x10, x10, w11, sxth #2
            (0xb860_592b, ADD, CASES[0], 0, 4),        // ldr w11, [x9, w0, uxtw #2]
            (0xb8a0_592b, ADD, DEFAULT, 0, 4),         // ldrsw x11, [x9, w0, uxtw #2]
            (0xb8a0_592b, 0x8b2b_c14a, DEFAULT, 0, 4), // ldrsw x11, ...; add x10, x10, w11, sxtw
        ];
        for (load, add, anchor, shift, size) in forms {
            let program = Switch::new(load, add, anchor).discover(relative_entries(anchor, shift, size), vec![]);
            assert!(resolved(&program), "{load:#x} {add:#x}");
            let addresses: Vec<_> = program.functions.iter().map(|function| function.address).collect();
            assert_eq!(addresses, [0]);
            for case in CASES {
                assert!(program.xrefs.contains(&Xref { to: case, from: 0x24, kind: XrefKind::Jump }));
            }
            let function = program.function_at(0).unwrap();
            assert_eq!(function.switch_cases(0x24), Some(&CASES[..]));
            assert_eq!(function.switch_cases(0x20), None);
        }
        // ldr x11, [x9, w0, uxtw #3]; br x11: absolute entries.
        let absolute = Switch { add: NOP, jump: 0xd61f_0160, ..Switch::new(0xf860_592b, NOP, 0) };
        assert!(resolved(&absolute.discover(relative_entries(0, 0, 8), vec![])));
        // ldrsb x11; add x10, x10, w11, uxtb #2 zero-extends the entries again, selecting addresses past the code.
        let mismatched = Switch::new(0x38a0_492b, 0x8b2b_094a, DEFAULT);
        assert!(!resolved(&mismatched.discover(relative_entries(DEFAULT, 2, 1), vec![])));
    }

    #[test]
    fn a_switch_keeps_its_entries_in_table_order_and_its_guard() {
        // ldrb entries selecting 0x30, 0x28, 0x30, 0x34 for indices 0..4.
        let rodata = [0x30u64, 0x28, 0x30, 0x34].map(|case| ((case - CASES[0]) >> 2) as u8).to_vec();
        let program = Switch::new(0x3860_492b, 0x8b0b_094a, CASES[0]).discover(rodata, vec![]);
        let switch = &program.function_at(0).unwrap().switches[0];
        assert_eq!(switch.table, [0x30, 0x28, 0x30, 0x34]);
        assert_eq!(switch.cases, [0x28, 0x30, 0x34]);
        assert_eq!(switch.guard, 8);
    }

    #[test]
    fn a_switch_needs_a_bound_proven_on_every_path_to_its_jump() {
        let ldrb = 0x3860_492b;
        let entries = relative_entries(CASES[0], 2, 1);
        let switch = || Switch::new(ldrb, 0x8b0b_094a, CASES[0]);
        assert!(resolved(&switch().discover(entries.clone(), vec![])));
        // No comparison.
        let unbounded = Switch { bound: [NOP, NOP], ..switch() };
        assert!(!resolved(&unbounded.discover(entries.clone(), vec![])));
        // cmp w1, #3 bounds another register.
        let other = Switch { bound: [0x7100_0c3f, BOUND[1]], ..switch() };
        assert!(!resolved(&other.discover(entries.clone(), vec![])));
        // b.ne proves no upper bound.
        let inequality = Switch { bound: [BOUND[0], 0x5400_0161], ..switch() };
        assert!(!resolved(&inequality.discover(entries.clone(), vec![])));
        // cbz w1, 0x14 joins the run after the comparison, on a path where w0 is unbounded.
        let joined = Switch { prefix: [0x3400_00a1, NOP], ..switch() };
        assert!(!resolved(&joined.discover(entries.clone(), vec![])));
        // add x0, x0, #1 redefines the index after the comparison.
        let redefined = Switch { gap: 0x9100_0400, ..switch() };
        assert!(!resolved(&redefined.discover(entries.clone(), vec![])));
        // b.hs bounds the index below its limit: cmp w0, #4; b.hs 0x38.
        let below = Switch { bound: [0x7100_101f, 0x5400_0162], ..switch() };
        assert!(resolved(&below.discover(entries.clone(), vec![])));
    }

    #[test]
    fn a_32_bit_bound_covers_an_x_index_only_when_its_upper_half_is_zero() {
        // ldrb w11, [x9, x0]: the comparison bounds w0, but x0's upper half is whatever it held on entry.
        let switch = Switch::new(0x3860_692b, 0x8b0b_094a, CASES[0]);
        let entries = relative_entries(CASES[0], 2, 1);
        assert!(!resolved(&switch.discover(entries.clone(), vec![])));
        // mov w0, w0 zeroes it.
        let zeroed = Switch { prefix: [0x2a00_03e0, NOP], ..switch };
        assert!(resolved(&zeroed.discover(entries, vec![])));
    }

    #[test]
    fn addresses_formed_before_a_join_ahead_of_the_comparison_do_not_reach_the_jump() {
        // 0: cbz w1, JOIN; 4: adr x9, table; 8: adr x10, 0x28; c: nop; 10: cmp w0, #3; 14: b.hi 0x38;
        // 18: ldrb w11, [x9, w0, uxtw]; 1c: add x10, x10, w11, lsl #2; 20: br x10; 24: nop. Through a join at c,
        // neither x9 nor x10 holds the address formed on the fall-through path.
        let switch = |join: u32| {
            let mut words = vec![0x3400_0001 | (join / 4) << 5, adr(9, 4, RODATA), adr(10, 8, CASES[0]), NOP];
            words.extend([BOUND[0], 0x5400_0128, 0x3860_492b, 0x8b0b_094a, 0xd61f_0140, NOP]);
            words.extend([RET; 5]);
            let code = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let image = Image { code, rodata: relative_entries(CASES[0], 2, 1), data: vec![] };
            discover(&image, || decoder_for(Arch::Aarch64).unwrap(), &[0])
        };
        let cases = |join: u32| switch(join).function_at(0).unwrap().switch_cases(0x20).map(<[u64]>::to_vec);
        assert_eq!(cases(0xc), None);
        assert_eq!(cases(4), Some(CASES.to_vec()));
    }

    #[test]
    fn switch_tables_must_be_read_only_data_selecting_code() {
        let switch = || Switch::new(0x3860_492b, 0x8b0b_094a, CASES[0]);
        let entries = relative_entries(CASES[0], 2, 1);
        // The same table in writable data.
        let writable = Switch { table: DATA, ..switch() };
        assert!(!resolved(&writable.discover(vec![], entries.clone())));
        // A table one entry short of the bound.
        assert!(!resolved(&switch().discover(entries[..3].to_vec(), vec![])));
        // An entry pointing past the end of the code.
        let mut outside = entries.clone();
        outside[3] = 0x40;
        assert!(!resolved(&switch().discover(outside, vec![])));
        // An absolute entry selecting the word at 4, which does not decode (0: b 0x8).
        let absolute = Switch { add: NOP, jump: 0xd61f_0160, ..Switch::new(0xf860_592b, NOP, 0) };
        assert!(resolved(&absolute.discover(relative_entries(0, 0, 8), vec![])));
        let undecodable = Switch { prefix: [0x1400_0002, 0xffff_ffff], ..absolute };
        let mut entries = relative_entries(0, 0, 8);
        entries[24] = 4;
        assert!(!resolved(&undecodable.discover(entries, vec![])));
    }

    #[test]
    fn a_hostile_switch_bound_is_capped() {
        // ldrb with a byte table of 4097 entries, all selecting the first case.
        let switch =
            |bound: u32| Switch { bound: [bound, BOUND[1]], ..Switch::new(0x3860_492b, 0x8b0b_094a, CASES[0]) };
        let entries = vec![0; MAX_JUMP_TABLE_ENTRIES as usize + 1];
        // cmp w0, #0xfff: exactly the most entries read.
        let largest = switch(0x713f_fc1f).discover(entries.clone(), vec![]);
        assert!(largest.function_at(0).unwrap().contains(CASES[0]));
        // cmp w0, #1, lsl #12: one more is left unresolved.
        let hostile = switch(0x7140_041f).discover(entries, vec![]);
        assert!(!hostile.function_at(0).unwrap().contains(CASES[0]));
    }

    fn run_noreturn(arch: Arch, bytes: Vec<u8>, seeds: &[u64], noreturn: &[u64]) -> Program {
        let memory = FlatMemory { base: 0, bytes };
        let facts = ReturnFacts { noreturn: noreturn.iter().copied().collect(), ..Default::default() };
        discover_with_noreturn(&memory, || decoder_for(arch).unwrap(), seeds, &facts)
    }

    /// `call target` at `at` in x86-64 code.
    fn put_call(bytes: &mut [u8], at: usize, target: usize) {
        bytes[at] = 0xe8;
        bytes[at + 1..at + 5].copy_from_slice(&((target as i32) - (at as i32 + 5)).to_le_bytes());
    }

    #[test]
    fn a_call_to_a_noreturn_callee_has_no_fall_through() {
        // 0: call 0x40 (exit); 5: xor eax, eax; 7: ret (code nothing else reaches); 40: ret
        let mut bytes = vec![0xcc; 0x41];
        put_call(&mut bytes, 0, 0x40);
        bytes[5..8].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes[0x40] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes.clone(), &[0], &[0x40]);
        assert_eq!(blocks(&program, 0), [(0, 5)]);
        assert_eq!(program.noreturn_calls, [0]);
        assert!(program.is_noreturn_call(0));
        assert!(program.noreturn.contains(&0x40));
        assert!(program.xrefs.contains(&Xref { to: 0x40, from: 0, kind: XrefKind::Call }));
        // Without the knowledge, the caller runs on into the following code.
        let program = run_noreturn(Arch::X86_64, bytes, &[0], &[]);
        assert_eq!(blocks(&program, 0), [(0, 8)]);
        assert!(program.noreturn_calls.is_empty());
    }

    #[test]
    fn a_call_through_a_noreturn_import_slot_has_no_fall_through() {
        // 0: call [rip+0x3a] (slot 0x40); 6: ret
        let mut bytes = vec![0xff, 0x15, 0x3a, 0, 0, 0, 0xc3];
        bytes.resize(0x48, 0);
        let program = run_noreturn(Arch::X86_64, bytes, &[0], &[0x40]);
        assert_eq!(blocks(&program, 0), [(0, 6)]);
        assert_eq!(program.noreturn_calls, [0]);
    }

    #[test]
    fn a_wrapper_whose_every_path_calls_a_noreturn_callee_is_inferred_noreturn() {
        // 0: call 0x10; 5: xor eax, eax; 7: ret. 10: test edi, edi; 12: je 0x19; 14: call 0x40 (abort);
        // 19: call 0x40 (abort). 40: ret
        let mut bytes = vec![0xcc; 0x41];
        put_call(&mut bytes, 0, 0x10);
        bytes[5..8].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes[0x10..0x14].copy_from_slice(&[0x85, 0xff, 0x74, 0x05]);
        put_call(&mut bytes, 0x14, 0x40);
        put_call(&mut bytes, 0x19, 0x40);
        bytes[0x40] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes.clone(), &[0], &[0x40]);
        // The caller's only path calls the wrapper, so it never returns either.
        assert_eq!(program.noreturn, [0, 0x10, 0x40]);
        assert_eq!(blocks(&program, 0), [(0, 5)]);
        assert_eq!(program.noreturn_calls, [0, 0x14, 0x19]);

        // 19: ret instead: one path returns, so neither the wrapper nor its caller's call is noreturn.
        bytes[0x19] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes, &[0], &[0x40]);
        assert_eq!(program.noreturn, [0x40]);
        assert_eq!(blocks(&program, 0), [(0, 8)]);
        assert_eq!(program.noreturn_calls, [0x14]);
    }

    #[test]
    fn unknown_exits_count_as_returning() {
        // 10: test edi, edi; 12: je 0x19; 14: call 0x40 (abort); 19: jmp rax. And then 19: undecodable bytes.
        let mut bytes = vec![0xcc; 0x41];
        put_call(&mut bytes, 0, 0x10);
        bytes[5..8].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes[0x10..0x14].copy_from_slice(&[0x85, 0xff, 0x74, 0x05]);
        put_call(&mut bytes, 0x14, 0x40);
        bytes[0x19..0x1b].copy_from_slice(&[0xff, 0xe0]);
        bytes[0x40] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes.clone(), &[0], &[0x40]);
        assert_eq!(program.noreturn, [0x40]);
        bytes[0x19] = 0x06;
        let program = run_noreturn(Arch::X86_64, bytes, &[0], &[0x40]);
        assert_eq!(program.noreturn, [0x40]);
    }

    #[test]
    fn a_function_ending_in_a_trap_is_noreturn_and_tail_calls_carry_it() {
        // 0: call 0x10; 5: ret. 10: jmp 0x20 (a tail call: 0x20 is also called from 0x30). 20: ud2.
        // 30: call 0x20; 35: ret
        let mut bytes = vec![0xcc; 0x36];
        put_call(&mut bytes, 0, 0x10);
        bytes[5] = 0xc3;
        bytes[0x10..0x12].copy_from_slice(&[0xeb, 0x0e]);
        bytes[0x20..0x22].copy_from_slice(&[0x0f, 0x0b]);
        put_call(&mut bytes, 0x30, 0x20);
        bytes[0x35] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes, &[0, 0x30], &[]);
        assert_eq!(program.noreturn, [0, 0x10, 0x20, 0x30]);
        assert_eq!(program.noreturn_calls, [0, 0x30]);
        assert_eq!(blocks(&program, 0x30), [(0x30, 0x35)]);
    }

    #[test]
    fn long_wrapper_chains_are_inferred_to_the_end() {
        // f_i at 0x10 * i: call f_(i+1); xor eax, eax; ret, for twelve wrappers; f_12 at 0xc0: ud2. Each wrapper
        // never returns once the one it calls is known not to, however deep the chain.
        let mut bytes = vec![0xcc; 0xc2];
        for i in 0..12 {
            put_call(&mut bytes, 0x10 * i, 0x10 * (i + 1));
            bytes[0x10 * i + 5..0x10 * i + 8].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        }
        bytes[0xc0..0xc2].copy_from_slice(&[0x0f, 0x0b]);
        let program = run_noreturn(Arch::X86_64, bytes, &[0], &[]);
        assert_eq!(program.noreturn, (0..=12).map(|i| 0x10 * i).collect::<Vec<u64>>());
        assert_eq!(program.noreturn_calls, (0..12).map(|i| 0x10 * i).collect::<Vec<u64>>());
        assert_eq!(blocks(&program, 0), [(0, 5)]);
    }

    #[test]
    fn recursion_reaches_a_fixpoint() {
        // f at 0x10: call 0x20 (g); 15: ret. g at 0x20: call 0x10 (f); 25: ud2. g never returns, so neither does
        // f once that is known, and then g's call to f is noreturn too.
        let mut bytes = vec![0xcc; 0x30];
        put_call(&mut bytes, 0x10, 0x20);
        bytes[0x15] = 0xc3;
        put_call(&mut bytes, 0x20, 0x10);
        bytes[0x25..0x27].copy_from_slice(&[0x0f, 0x0b]);
        let program = run_noreturn(Arch::X86_64, bytes.clone(), &[0x10], &[]);
        assert_eq!(program.noreturn, [0x10, 0x20]);
        assert_eq!(blocks(&program, 0x10), [(0x10, 0x15)]);
        assert_eq!(blocks(&program, 0x20), [(0x20, 0x25)]);
        // g resumes its caller through a saved context (like Go's mcall), so nothing is inferred from it.
        let memory = FlatMemory { base: 0, bytes };
        let facts = ReturnFacts { returns: [0x20].into(), ..Default::default() };
        let program = discover_with_noreturn(&memory, || decoder_for(Arch::X86_64).unwrap(), &[0x10], &facts);
        assert!(program.noreturn.is_empty());
        assert_eq!(blocks(&program, 0x10), [(0x10, 0x16)]);

        // f at 0x10: test edi, edi; je 0x19; call 0x10 (itself); 19: ret. A recursive function that returns.
        let mut bytes = vec![0xcc; 0x20];
        bytes[0x10..0x14].copy_from_slice(&[0x85, 0xff, 0x74, 0x05]);
        put_call(&mut bytes, 0x14, 0x10);
        bytes[0x19] = 0xc3;
        let program = run_noreturn(Arch::X86_64, bytes, &[0x10], &[]);
        assert!(program.noreturn.is_empty());
        assert!(program.function_at(0x10).unwrap().contains(0x19));
    }

    fn arm(words: &[(usize, u32)], size: usize) -> Vec<u8> {
        let mut bytes = vec![0; size];
        for &(at, word) in words {
            bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn a_conditional_call_to_a_noreturn_callee_falls_through() {
        // 0: cmp r0, #0; 4: blne 0x40 (abort); 8: mov r0, #1; c: bx lr. 40: bx lr
        let words = [(0, 0xe350_0000), (4, 0x1b00_000d), (8, 0xe3a0_0001), (0xc, 0xe12f_ff1e), (0x40, 0xe12f_ff1e)];
        let program = run_noreturn(Arch::Arm, arm(&words, 0x44), &[0], &[0x40]);
        assert_eq!(blocks(&program, 0), [(0, 0x10)]);
        assert!(program.noreturn_calls.is_empty());
        assert_eq!(program.noreturn, [0x40]);
    }

    #[test]
    fn a_conditional_return_is_a_way_out() {
        // f at 0: cmp r0, #0; 4: bxeq lr; 8: bl 0x40 (abort). g at 0x20: bl 0; 24: mov r0, #1; 28: bx lr.
        // 40: bx lr
        let words = [
            (0, 0xe350_0000),
            (4, 0x012f_ff1e),
            (8, 0xeb00_000c),
            (0x20, 0xebff_fff6),
            (0x24, 0xe3a0_0001),
            (0x28, 0xe12f_ff1e),
            (0x40, 0xe12f_ff1e),
        ];
        let program = run_noreturn(Arch::Arm, arm(&words, 0x44), &[0x20], &[0x40]);
        assert_eq!(program.noreturn, [0x40]);
        assert_eq!(program.noreturn_calls, [8]);
        assert_eq!(blocks(&program, 0x20), [(0x20, 0x2c)]);
    }

    #[test]
    fn debugger_and_semihosting_traps_resume() {
        // f at 0: bkpt #0xab; 4: bx lr. g at 0x20: bl 0; 24: mov r0, #1; 28: bx lr
        let words = [(0, 0xe120_0a7b), (4, 0xe12f_ff1e), (0x20, 0xebff_fff6), (0x24, 0xe3a0_0001), (0x28, 0xe12f_ff1e)];
        let program = run_noreturn(Arch::Arm, arm(&words, 0x2c), &[0x20], &[]);
        assert!(program.noreturn.is_empty());
        assert_eq!(blocks(&program, 0), [(0, 8)]);
        assert_eq!(blocks(&program, 0x20), [(0x20, 0x2c)]);
        // 0: hlt #0xf000; 4: ret. 10: brk #0xf000; 14: ret
        let words = [(0, 0xd45e_0000), (4, RET), (0x10, 0xd43e_0000), (0x14, RET)];
        let program = run_noreturn(Arch::Aarch64, arm(&words, 0x18), &[0, 0x10], &[]);
        assert!(program.noreturn.is_empty());
        assert_eq!(blocks(&program, 0x10), [(0x10, 0x18)]);
    }

    #[test]
    fn aarch64_calls_to_noreturn_callees_and_trapping_wrappers_end_their_blocks() {
        let bl = |from: u32, to: u32| 0x9400_0000 | ((to.wrapping_sub(from) / 4) & 0x3ff_ffff);
        // 0: bl 0x40 (exit); 4: ret. 10: bl 0x20; 14: ret. 20: brk #1. 40: ret
        let mut words = [NOP; 0x11];
        words[0] = bl(0, 0x40);
        words[1] = RET;
        words[4] = bl(0x10, 0x20);
        words[5] = RET;
        words[8] = 0xd420_0020;
        words[0x10] = RET;
        let bytes = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let program = run_noreturn(Arch::Aarch64, bytes, &[0, 0x10], &[0x40]);
        assert_eq!(blocks(&program, 0), [(0, 4)]);
        assert_eq!(blocks(&program, 0x10), [(0x10, 0x14)]);
        assert_eq!(program.noreturn, [0, 0x10, 0x20, 0x40]);
        assert_eq!(program.noreturn_calls, [0, 0x10]);
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

    #[test]
    fn arm_interworking_modes_survive_parallel_discovery_rounds() {
        for (thumb_source, call, ret_source, ret_target) in [
            (true, vec![0x00, 0xf0, 0x06, 0xe8], vec![0x70, 0x47], vec![0x1e, 0xff, 0x2f, 0xe1]),
            (false, vec![0x02, 0x00, 0x00, 0xfa], vec![0x1e, 0xff, 0x2f, 0xe1], vec![0x70, 0x47]),
        ] {
            let mut bytes = call;
            bytes.extend(ret_source);
            bytes.resize(16, 0);
            bytes.extend(ret_target);
            let memory = FlatMemory { base: 0x1000, bytes };
            let target = rampage_arch::Target {
                thumb: if thumb_source { std::iter::once(0x1000..0x1020).collect() } else { Default::default() },
                ..rampage_arch::Target::new(Arch::Arm)
            };
            let mut expected = None;
            for threads in [1, 4] {
                for seeds in [&[0x1000][..], &[0x1010, 0x1000][..]] {
                    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
                    let program = pool.install(|| discover(&memory, || rampage_arch::decoder(&target).unwrap(), seeds));
                    assert_eq!(program.function_at(0x1010).unwrap().instruction_count, 1);
                    assert!(program.xrefs.contains(&Xref { to: 0x1010, from: 0x1000, kind: XrefKind::Call }));
                    assert!(program.code_modes.contains(&(0x1010, !thumb_source)));
                    if let Some(expected) = &expected {
                        assert_eq!(&program, expected);
                    } else {
                        expected = Some(program);
                    }
                }
            }
        }
    }

    #[test]
    fn interworking_conditional_fallthrough_discovers_its_calls() {
        let mut bytes = vec![0x02, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1];
        bytes.resize(0x10, 0);
        // Thumb: beq 0x101a; bl 0x1030; bx lr; nop; bx lr
        bytes.extend([0x03, 0xd0, 0x00, 0xf0, 0x0d, 0xf8, 0x70, 0x47, 0x00, 0xbf, 0x70, 0x47]);
        bytes.resize(0x30, 0);
        bytes.extend([0x70, 0x47]);
        let memory = FlatMemory { base: 0x1000, bytes };
        let program = discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000]);
        assert!(program.function_at(0x1030).is_some());
        assert!(program.code_modes.contains(&(0x1030, true)));
    }

    #[test]
    fn correcting_an_entry_mode_discards_hints_from_its_old_decode() {
        let mut bytes = vec![0x02, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1];
        bytes.resize(0x10, 0);
        bytes.extend([0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0xff, 0xe7, 0x70, 0x47]);
        let memory = FlatMemory { base: 0x1000, bytes };
        let expected = discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000]);
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            let program = pool.install(|| discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000, 0x1010]));
            assert_eq!(program, expected);
        }
    }

    #[test]
    fn correcting_an_entry_mode_discards_functions_from_its_old_decode() {
        let mut bytes = vec![0x02, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1];
        bytes.resize(0x10, 0);
        bytes.extend([0x02, 0x00, 0x00, 0xeb, 0x00, 0x00, 0xff, 0xe7, 0x70, 0x47]);
        bytes.resize(0x20, 0);
        bytes.extend([0x1e, 0xff, 0x2f, 0xe1]);
        let memory = FlatMemory { base: 0x1000, bytes };
        let expected = discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000]);
        assert!(expected.function_at(0x1020).is_none());
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            let program = pool.install(|| discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000, 0x1010]));
            assert_eq!(program, expected);
        }
    }

    #[test]
    fn contradictory_interworking_modes_terminate_without_an_unbounded_loop() {
        let memory = FlatMemory { base: 0x1000, bytes: 0xfaff_fffeu32.to_le_bytes().to_vec() };
        let decoders = std::sync::atomic::AtomicUsize::new(0);
        let program = discover(
            &memory,
            || {
                let count = decoders.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                assert!(count < 32, "mode discovery did not converge");
                decoder_for(Arch::Arm).unwrap()
            },
            &[0x1000],
        );
        assert!(program.function_at(0x1000).is_some());
        assert!(program.code_modes.contains(&(0x1000, false)));
    }

    #[test]
    fn a_known_seed_inherits_the_mode_of_its_incoming_straight_line_run() {
        let mut bytes = vec![0x02, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1];
        bytes.resize(0x10, 0);
        bytes.extend([0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x70, 0x47]);
        let memory = FlatMemory { base: 0x1000, bytes };
        let program = discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000, 0x1014]);
        assert_eq!(program.function_at(0x1014).unwrap().instruction_count, 2, "{program:?}");
        assert!(program.code_modes.contains(&(0x1014, true)));
    }

    #[test]
    fn an_oscillating_branch_does_not_suppress_valid_downstream_modes() {
        let mut bytes = vec![
            0xfe, 0xff, 0xff, 0xfa, // blx 0x1000
            0x01, 0x00, 0x00, 0xfa, // blx 0x1010
            0x1e, 0xff, 0x2f, 0xe1,
        ];
        bytes.resize(0x10, 0);
        bytes.extend([0x00, 0xf0, 0x00, 0xe8, 0x1e, 0xff, 0x2f, 0xe1]);
        let memory = FlatMemory { base: 0x1000, bytes };
        let program = discover(&memory, || decoder_for(Arch::Arm).unwrap(), &[0x1000]);
        assert!(program.code_modes.contains(&(0x1010, true)), "{program:?}");
        assert!(program.code_modes.contains(&(0x1014, false)));
        assert!(program.xrefs.contains(&Xref { to: 0x1014, from: 0x1010, kind: XrefKind::Call }));
    }

    #[test]
    fn sequential_sources_of_oscillating_mode_hints_terminate() {
        let memory = FlatMemory {
            base: 0x1000,
            bytes: [0xe1a0_0000u32, 0xfaff_fffdu32].into_iter().flat_map(u32::to_le_bytes).collect(),
        };
        let decoders = std::sync::atomic::AtomicUsize::new(0);
        let program = discover(
            &memory,
            || {
                assert!(decoders.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 32);
                decoder_for(Arch::Arm).unwrap()
            },
            &[0x1000],
        );
        assert_eq!(program.function_at(0x1000).unwrap().instruction_count, 2);
    }

    #[test]
    fn interior_interworking_cycles_terminate() {
        let memory = FlatMemory {
            base: 0x1000,
            bytes: [0xe1a0_0000u32, 0xe1a0_0000, 0xe59f_f000, 0, 0x1005]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        };
        let decoders = std::sync::atomic::AtomicUsize::new(0);
        let program = discover(
            &memory,
            || {
                assert!(decoders.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 32);
                decoder_for(Arch::Arm).unwrap()
            },
            &[0x1000],
        );
        assert!(program.function_at(0x1000).is_some());
    }
}
