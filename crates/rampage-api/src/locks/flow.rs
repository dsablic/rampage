//! Per-function p-code dataflow for `lock_mechanisms`: which values a function's branch decisions, return value and
//! stores derive from.
//!
//! Each function's instructions are lifted with the target's Sleigh specification. A forward analysis tracks, at
//! every point, known values (constants, stack-relative addresses, and pointers into a constant base with an
//! unknown index) and taint: the set of sources a value derives from. Sources are a call's result (and the buffers
//! it may write through pointer arguments) and a load from a constant address that is not read-only image data
//! (memory-mapped registers, RAM, flash outside the image). Taint flows through arithmetic, comparisons, stack
//! slots and conditionally executed instructions (ARM IT blocks), so a register test such as
//! `if (OTP->FEATURES & 8)` or `cmp r0, #0; it ne; popne {pc}` records which sources decide it.
//!
//! Recorded per function: every conditional branch whose condition is tainted (a gate), returns with their
//! value's taint, stores to constant addresses, call sites with their argument values, and indirect transfers.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_analysis::discover::DiscoveredFunction;
use rampage_decompiler::sleigh_decode::{DecodeStatus, PcodeOp, SleighDecoder, Varnode};
use rampage_loaders::Binary;

/// Sources tracked per function; later ones share the last bit.
pub(super) const MAX_SOURCES: usize = 64;
/// Bytes of a buffer a pointer argument is taken to cover (read from and written to by the callee).
const BUFFER_SPAN: i64 = 64;
/// Bytes past a base address an indexed access is taken to cover.
const INDEX_SPAN: i64 = 256;
/// Constants recorded per function (addresses it forms or loads), for crypto-table references.
const MAX_CONSTANTS: usize = 1024;

/// A register or temporary: (space, offset, size).
pub(super) type Key = (u32, u64, u32);

/// A known value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Val {
    Const(u64),
    /// Entry stack pointer plus an offset.
    Stack(i64),
    /// Somewhere at or after this stack offset (a stack buffer indexed by an unknown value).
    StackFrom(i64),
    /// Somewhere at or after this constant address (a table or buffer indexed by an unknown value).
    AbsFrom(u64),
}

/// How a condition was formed, as bits.
pub(super) mod flags {
    pub const ZERO: u8 = 1;
    pub const EQ_CONST: u8 = 2;
    pub const EQ_VALUE: u8 = 4;
    pub const ORDERED: u8 = 8;
    pub const BIT: u8 = 16;
    pub const SUB_CONST: u8 = 32;
    pub const SUB_VALUE: u8 = 64;
    pub const AND_CONST: u8 = 128;
}

/// The sources a value derives from (one bit per source) and how it was compared.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Taint {
    pub mask: u64,
    pub flags: u8,
}

impl Taint {
    fn source(bit: usize) -> Self {
        Self { mask: 1 << bit.min(MAX_SOURCES - 1), flags: 0 }
    }

    pub fn is_empty(self) -> bool {
        self.mask == 0
    }

    fn union(self, other: Self) -> Self {
        Self { mask: self.mask | other.mask, flags: self.flags | other.flags }
    }

    pub fn bits(self) -> impl Iterator<Item = usize> {
        (0..MAX_SOURCES).filter(move |bit| self.mask & (1 << bit) != 0)
    }

    /// The comparison the flags describe, most specific first.
    pub fn condition(self) -> &'static str {
        use flags::*;
        if self.flags & EQ_CONST != 0 {
            "equality with a constant"
        } else if self.flags & EQ_VALUE != 0 {
            "equality with another value"
        } else if self.flags & (BIT | AND_CONST) != 0 {
            "bit test"
        } else if self.flags & ORDERED != 0 {
            "ordered comparison"
        } else {
            "zero or nonzero test"
        }
    }
}

/// What a tainted value derives from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Source {
    /// The result of a call (and what it writes through its pointer arguments); `None` when the target is unknown.
    Call(Option<u64>),
    /// A load from a constant address outside read-only image data, or an indexed load from a constant base.
    Load(u64),
    /// Memory a pointer argument with this constant address refers to, as passed to a call.
    Pointer(u64),
    /// The function's own argument (by position).
    Param(usize),
}

/// A memory location tracked for taint: stack offsets and constant addresses, word aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Loc {
    Stack(i64),
    Abs(u64),
}

#[derive(Debug, Clone, Default, PartialEq)]
struct State {
    values: HashMap<Key, Val>,
    taint: HashMap<Key, Taint>,
    stack_values: HashMap<i64, Val>,
    memory: BTreeMap<Loc, Taint>,
    /// Values written by conditionally executed instructions, by the condition's signature: an instruction under the
    /// same condition (the rest of an ARM IT block) sees them.
    conditional_values: HashMap<Key, (u64, Val)>,
    /// The condition signature of the instruction being stepped, once its condition is known.
    condition: Option<u64>,
}

impl State {
    fn merge(&self, other: &State) -> State {
        let conditional_values = self
            .conditional_values
            .iter()
            .filter(|(key, value)| other.conditional_values.get(key) == Some(value))
            .map(|(k, v)| (*k, *v))
            .collect();
        let values = self
            .values
            .iter()
            .filter(|(key, value)| other.values.get(key) == Some(value))
            .map(|(k, v)| (*k, *v))
            .collect();
        let stack_values = self
            .stack_values
            .iter()
            .filter(|(key, value)| other.stack_values.get(key) == Some(value))
            .map(|(k, v)| (*k, *v))
            .collect();
        let mut taint = self.taint.clone();
        for (key, value) in &other.taint {
            let entry = taint.entry(*key).or_default();
            *entry = entry.union(*value);
        }
        let mut memory = self.memory.clone();
        for (key, value) in &other.memory {
            let entry = memory.entry(*key).or_default();
            *entry = entry.union(*value);
        }
        State { values, taint, stack_values, memory, conditional_values, condition: None }
    }

    fn memory_range(&self, from: Loc, span: i64) -> Taint {
        let to = match from {
            Loc::Stack(offset) => Loc::Stack(offset.saturating_add(span)),
            Loc::Abs(address) => Loc::Abs(address.saturating_add(span as u64)),
        };
        self.memory.range(from..to).fold(Taint::default(), |acc, (_, taint)| acc.union(*taint))
    }

    fn taint_memory_range(&mut self, from: Loc, span: i64, taint: Taint) {
        let step = |loc: Loc, delta: i64| match loc {
            Loc::Stack(offset) => Loc::Stack(offset + delta),
            Loc::Abs(address) => Loc::Abs(address.wrapping_add(delta as u64)),
        };
        let base = align(from);
        for delta in (0..span).step_by(4) {
            let entry = self.memory.entry(step(base, delta)).or_default();
            *entry = entry.union(taint);
        }
    }
}

fn align(loc: Loc) -> Loc {
    match loc {
        Loc::Stack(offset) => Loc::Stack(offset & !3),
        Loc::Abs(address) => Loc::Abs(address & !3),
    }
}

/// A conditional branch decided by a tainted condition.
#[derive(Debug, Clone)]
pub(super) struct Gate {
    pub at: u64,
    pub taint: Taint,
    /// The branch target, or `None` for a conditionally executed instruction (whose effect is in `effect`).
    pub target: Option<u64>,
    /// The next instruction.
    pub next: u64,
    /// For a conditionally executed instruction: what it does when it executes.
    pub effect: Option<Effect>,
}

/// What a conditionally executed instruction does.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Effect {
    Returns(Option<Val>),
    Branches(u64),
    Stores { address: u64, value: Option<u64> },
    Sets,
}

#[derive(Debug, Clone)]
pub(super) struct CallSite {
    pub at: u64,
    pub target: Option<u64>,
    /// Known values of the argument registers, in order.
    pub arguments: Vec<Option<Val>>,
    /// The taint of the call's result.
    pub result: Taint,
}

#[derive(Debug, Clone)]
pub(super) struct Store {
    pub at: u64,
    /// A constant address, or the base of an indexed store.
    pub address: u64,
    pub indexed: bool,
    pub value: Option<u64>,
    pub taint: Taint,
    /// Written by a call through a pointer argument, not by a store instruction.
    pub by_call: bool,
    /// Bytes the store may cover.
    pub span: u64,
}

#[derive(Debug, Clone)]
pub(super) struct Return {
    pub at: u64,
    pub value: Option<Val>,
    pub taint: Taint,
}

/// One decoded instruction and its p-code.
struct Instruction {
    address: u64,
    next: u64,
    ops: Vec<PcodeOp>,
}

/// One basic block as decoded.
pub(super) struct DecodedBlock {
    pub start: u64,
    instructions: Vec<Instruction>,
    pub successors: Vec<u64>,
}

impl DecodedBlock {
    pub fn end(&self) -> u64 {
        self.instructions.last().map_or(self.start, |instruction| instruction.next)
    }
}

/// Everything recorded about one function.
pub(super) struct FunctionFlow {
    pub sources: Vec<Source>,
    pub gates: Vec<Gate>,
    pub calls: Vec<CallSite>,
    pub stores: Vec<Store>,
    pub returns: Vec<Return>,
    /// Indirect calls whose target is unknown.
    pub indirect_calls: Vec<u64>,
    /// Indirect branches that are not a return or a resolved switch (an import stub's jump, a computed jump).
    pub indirect_jumps: Vec<u64>,
    /// Blocks that only branch to themselves.
    pub self_loops: Vec<u64>,
    /// Constants the function forms or loads (addresses and immediates of at least 0x100), capped.
    pub constants: BTreeSet<u64>,
    pub blocks: Vec<DecodedBlock>,
    /// The taint of the value the function returns, including the gates that select between different returns.
    pub returned: Taint,
    /// HMAC pad bytes (0x36, 0x5c) the function XORs with.
    pads: BTreeSet<u64>,
    /// The arguments (by position, as bits) the returned value derives from.
    pub parameters: u64,
}

impl FunctionFlow {
    pub fn source_of(&self, bit: usize) -> Option<Source> {
        self.sources.get(bit).copied()
    }
}

/// What the analysis of one function consults: the function, every function start (for tail calls) and the
/// arguments each analyzed callee's result derives from.
pub(super) struct Scope<'s> {
    pub function: &'s DiscoveredFunction,
    pub starts: &'s [u64],
    pub summaries: &'s HashMap<u64, u64>,
}

/// The calling convention registers of an architecture.
pub(super) struct Convention {
    pub result: Key,
    pub arguments: Vec<Key>,
    pub preserved: Vec<Key>,
    pub stack_pointer: Key,
    /// Where stack-passed arguments start above the stack pointer at the call, and the slot size.
    pub stack_arguments: i64,
    pub word: i64,
}

/// Lifts and analyzes functions of one binary.
pub(super) struct Lifter<'a> {
    binary: &'a Binary,
    decoder: SleighDecoder,
    constant: u32,
    register: u32,
    ram: u32,
    convention: Convention,
    arm: bool,
    current_mode: Option<bool>,
    pub instructions: usize,
}

impl<'a> Lifter<'a> {
    /// A lifter for `binary`, or why it cannot analyze it: only ARM (and Thumb), AArch64 and x86-64 have a
    /// calling convention here.
    pub fn new(binary: &'a Binary) -> Result<Self, String> {
        let target = binary.target();
        let mut decoder = SleighDecoder::for_emulation(&target).map_err(|error| format!("decoder: {error}"))?;
        let metadata = decoder.metadata().clone();
        let space = |name: &str| metadata.spaces.iter().find(|space| space.name == name).map(|space| space.id);
        let constant = space("const").ok_or("decoder lacks a constant space")?;
        let register = space("register").ok_or("decoder lacks a register space")?;
        let key = |decoder: &SleighDecoder, name: &str| {
            decoder.register(name).map(|storage| (register, storage.offset, storage.size))
        };
        let names = |decoder: &SleighDecoder, list: &[&str]| -> Vec<Key> {
            list.iter().filter_map(|name| key(decoder, name)).collect()
        };
        let arch = binary.arch;
        let (stack_arguments, word) = match arch {
            rampage_arch::Arch::X86_64 => (8, 8),
            rampage_arch::Arch::Aarch64 => (0, 8),
            _ => (0, 4),
        };
        let (result, arguments, preserved, stack) = match arch {
            rampage_arch::Arch::Arm => (
                "r0",
                names(&decoder, &["r0", "r1", "r2", "r3"]),
                names(&decoder, &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"]),
                "sp",
            ),
            rampage_arch::Arch::Aarch64 => (
                "x0",
                names(&decoder, &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]),
                names(&decoder, &["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"]),
                "sp",
            ),
            rampage_arch::Arch::X86_64 => (
                "RAX",
                names(&decoder, &["RDI", "RSI", "RDX", "RCX", "R8", "R9"]),
                names(&decoder, &["RBX", "RBP", "R12", "R13", "R14", "R15"]),
                "RSP",
            ),
            other => return Err(format!("gate tracing does not support {other:?}")),
        };
        let convention = Convention {
            result: key(&decoder, result).ok_or("no result register")?,
            arguments,
            preserved,
            stack_pointer: key(&decoder, stack).ok_or("no stack pointer")?,
            stack_arguments,
            word,
        };
        let arm = arch == rampage_arch::Arch::Arm;
        if arm {
            decoder.keep_context_commits(true);
        }
        Ok(Self {
            binary,
            decoder,
            constant,
            register,
            ram: metadata.code_space,
            convention,
            arm,
            current_mode: None,
            instructions: 0,
        })
    }

    /// Lifts `function`'s blocks, decoding at most `budget` instructions in total across calls; `None` when the
    /// budget ran out inside it.
    pub fn lift(
        &mut self,
        function: &DiscoveredFunction,
        modes: &[(u64, bool)],
        noreturn: &[u64],
        budget: usize,
    ) -> Option<Vec<DecodedBlock>> {
        let target = self.binary.target();
        let mut blocks = Vec::with_capacity(function.blocks.len());
        for block in &function.blocks {
            let thumb = self.arm
                && modes
                    .binary_search_by_key(&block.start, |&(address, _)| address)
                    .map_or_else(|_| self.binary.m_profile() || target.is_thumb(block.start), |index| modes[index].1);
            if self.arm && self.current_mode != Some(thumb) {
                self.decoder.set_context_variable("TMode", u32::from(thumb));
                self.current_mode = Some(thumb);
            }
            let mut decoded = DecodedBlock { start: block.start, instructions: Vec::new(), successors: Vec::new() };
            let mut address = block.start;
            let mut falls_through = true;
            while address < block.end {
                self.instructions += 1;
                if self.instructions > budget {
                    return None;
                }
                let Some(bytes) = self.binary.read_to_segment_end(address) else { break };
                let instruction = self.decoder.decode_instruction(&bytes[..bytes.len().min(16)], address);
                if instruction.status != DecodeStatus::Valid || instruction.length == 0 {
                    break;
                }
                let next = address + u64::from(instruction.length);
                falls_through = true;
                for op in &instruction.pcode {
                    match op.name.as_str() {
                        "BRANCH" | "CBRANCH" => {
                            if let Some(target) = op.inputs.first().filter(|node| node.space == self.ram)
                                && let Some(offset) = target.offset
                                && offset != next
                            {
                                decoded.successors.push(offset);
                            }
                            if op.name == "BRANCH" && !self.conditional_before(&instruction.pcode, op) {
                                falls_through = false;
                            }
                        }
                        "RETURN" | "BRANCHIND" if !self.conditional_before(&instruction.pcode, op) => {
                            falls_through = false;
                        }
                        "CALL" => {
                            if let Some(target) = op.inputs.first().and_then(|node| node.offset)
                                && noreturn.binary_search(&target).is_ok()
                            {
                                falls_through = false;
                            }
                        }
                        _ => {}
                    }
                }
                decoded.instructions.push(Instruction { address, next, ops: instruction.pcode });
                address = next;
            }
            if let Some(cases) = decoded.instructions.last().and_then(|last| function.switch_cases(last.address)) {
                decoded.successors.extend_from_slice(cases);
            }
            if falls_through {
                decoded.successors.push(decoded.end());
            }
            blocks.push(decoded);
        }
        blocks.sort_by_key(|block| block.start);
        Some(blocks)
    }

    fn conditional_before(&self, ops: &[PcodeOp], op: &PcodeOp) -> bool {
        ops.iter().take_while(|other| !std::ptr::eq(*other, op)).any(|other| other.name == "CBRANCH")
    }

    /// Analyzes `function` (lifted into `blocks`): a forward fixpoint, then one recording pass.
    pub fn analyze(&self, scope: &Scope, blocks: Vec<DecodedBlock>) -> FunctionFlow {
        let function = scope.function;
        let index_of = |address: u64| blocks.binary_search_by_key(&address, |block| block.start).ok();
        let mut sources: Vec<Source> = Vec::new();
        let mut entry: Vec<Option<State>> = (0..blocks.len()).map(|_| None).collect();
        let mut initial = State::default();
        initial.values.insert(self.convention.stack_pointer, Val::Stack(0));
        for (index, &key) in self.convention.arguments.iter().enumerate() {
            let taint = self.source(&mut sources, Source::Param(index));
            initial.taint.insert(key, taint);
        }
        if let Some(first) = index_of(function.address) {
            entry[first] = Some(initial);
        }
        let mut work: BTreeSet<usize> =
            entry.iter().enumerate().filter(|(_, state)| state.is_some()).map(|(index, _)| index).collect();
        let mut budget = blocks.len().saturating_mul(24).max(64);
        let mut sink = Recorder::default();
        while let Some(index) = work.pop_first() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let mut state = entry[index].clone().unwrap_or_default();
            for instruction in &blocks[index].instructions {
                self.step(scope, instruction, &mut state, &mut sources, &mut sink, false);
            }
            for &successor in &blocks[index].successors {
                let Some(next) = index_of(successor) else { continue };
                let merged = match &entry[next] {
                    None => state.clone(),
                    Some(known) => known.merge(&state),
                };
                if entry[next].as_ref() != Some(&merged) {
                    entry[next] = Some(merged);
                    work.insert(next);
                }
            }
        }
        let mut recorder = Recorder::default();
        for (index, block) in blocks.iter().enumerate() {
            let mut state = entry[index].clone().unwrap_or_default();
            if block.successors.len() == 1 && block.successors[0] == block.start {
                recorder.self_loops.push(block.start);
            }
            for instruction in &block.instructions {
                self.step(scope, instruction, &mut state, &mut sources, &mut recorder, true);
            }
        }
        let mut returned = recorder.returns.iter().fold(Taint::default(), |acc, ret| acc.union(ret.taint));
        // Different return values selected by gates make the result depend on those gates.
        let distinct: BTreeSet<Option<u64>> = recorder
            .returns
            .iter()
            .map(|ret| match ret.value {
                Some(Val::Const(value)) => Some(value),
                _ => None,
            })
            .collect();
        // A returned value that is unknown yet derives from nothing is a merge of constants the paths chose.
        let merged = recorder.returns.iter().any(|ret| ret.value.is_none() && ret.taint.is_empty());
        if distinct.len() > 1 || merged {
            returned = recorder.gates.iter().fold(returned, |acc, gate| acc.union(gate.taint));
        }
        let parameters = returned
            .bits()
            .filter_map(|bit| match sources.get(bit) {
                Some(Source::Param(index)) => Some(1u64 << index),
                _ => None,
            })
            .fold(0, |acc, bit| acc | bit);
        FunctionFlow {
            parameters,
            sources,
            gates: recorder.gates,
            calls: recorder.calls,
            stores: recorder.stores,
            returns: recorder.returns,
            indirect_calls: recorder.indirect_calls,
            indirect_jumps: recorder.indirect_jumps,
            self_loops: recorder.self_loops,
            constants: recorder.constants,
            blocks,
            returned,
            pads: recorder.pads,
        }
    }

    fn value(&self, node: &Varnode, state: &State) -> Option<Val> {
        let offset = node.offset?;
        if node.space == self.constant {
            return Some(Val::Const(mask(offset, node.size)));
        }
        if node.space == self.ram {
            return self.binary.read_constant(offset, u8::try_from(node.size).ok()?).map(Val::Const);
        }
        if let Some(condition) = state.condition
            && let Some(&(written, value)) = state.conditional_values.get(&(node.space, offset, node.size))
            && written == condition
        {
            return Some(value);
        }
        if let Some(value) = state.values.get(&(node.space, offset, node.size)) {
            return Some(*value);
        }
        // A narrower read of a wider known register (w0 of x0, EAX of RAX), little endian.
        state.values.iter().find_map(|(&(space, start, size), value)| match value {
            Val::Const(constant) if space == node.space && start == offset && size > node.size => {
                Some(Val::Const(mask(*constant, node.size)))
            }
            _ => None,
        })
    }

    fn taint(&self, node: &Varnode, state: &State) -> Taint {
        let Some(offset) = node.offset else { return Taint::default() };
        if node.space == self.constant {
            return Taint::default();
        }
        if node.space == self.ram {
            return state.memory_range(Loc::Abs(offset & !3), i64::from(node.size.max(4)));
        }
        let end = offset.saturating_add(u64::from(node.size));
        state
            .taint
            .iter()
            .filter(|&(&(space, start, size), _)| {
                space == node.space && start < end && offset < start.saturating_add(u64::from(size))
            })
            .fold(Taint::default(), |acc, (_, taint)| acc.union(*taint))
    }

    fn write(&self, node: &Varnode, value: Option<Val>, taint: Taint, state: &mut State) {
        let Some(offset) = node.offset else { return };
        if node.space == self.ram || node.space == self.constant {
            return;
        }
        let end = offset.saturating_add(u64::from(node.size));
        let overlaps = |&(space, start, size): &Key| {
            space == node.space && start < end && offset < start.saturating_add(u64::from(size))
        };
        state.values.retain(|key, _| !overlaps(key));
        state.taint.retain(|key, _| !overlaps(key));
        state.conditional_values.retain(|key, _| !overlaps(key));
        let key = (node.space, offset, node.size);
        if let Some(value) = value {
            state.values.insert(key, value);
        }
        if !taint.is_empty() {
            state.taint.insert(key, taint);
        }
    }

    fn source(&self, sources: &mut Vec<Source>, source: Source) -> Taint {
        let bit = sources.iter().position(|known| *known == source).unwrap_or_else(|| {
            if sources.len() < MAX_SOURCES {
                sources.push(source);
            }
            sources.len() - 1
        });
        Taint::source(bit)
    }

    /// Whether `address` is constant data the image maps read-only (its loads fold to constants).
    fn writable_or_unmapped(&self, address: u64) -> bool {
        self.binary.read_constant(address, 1).is_none()
    }

    /// The taint of the memory a pointer value refers to (a buffer of `span` bytes).
    fn pointee(&self, value: Option<Val>, span: i64, state: &State, sources: &mut Vec<Source>) -> Taint {
        match value {
            Some(Val::Stack(offset)) => state.memory_range(Loc::Stack(offset & !3), span),
            Some(Val::StackFrom(offset)) => state.memory_range(Loc::Stack(offset & !3), INDEX_SPAN),
            Some(Val::Const(address)) if address >= 0x1000 && self.writable_or_unmapped(address) => {
                let local = state.memory_range(Loc::Abs(address & !3), span);
                local.union(self.source(sources, Source::Pointer(address)))
            }
            Some(Val::AbsFrom(address)) if self.writable_or_unmapped(address) => {
                let local = state.memory_range(Loc::Abs(address & !3), INDEX_SPAN);
                local.union(self.source(sources, Source::Pointer(address)))
            }
            _ => Taint::default(),
        }
    }

    fn step(
        &self,
        scope: &Scope,
        instruction: &Instruction,
        state: &mut State,
        sources: &mut Vec<Source>,
        recorder: &mut Recorder,
        record: bool,
    ) {
        let function = scope.function;
        let entry_stack = state.values.get(&self.convention.stack_pointer).copied();
        // After a CBRANCH inside the instruction (conditional execution), what it writes may not happen: values
        // become unknown and outputs keep their old taint plus the condition's.
        let mut conditional: Option<Taint> = None;
        let mut gate_index: Option<usize> = None;
        // The condition of a conditionally executed instruction is known before its first op: values written
        // earlier under the same condition apply to every read in it, including address arithmetic before the test.
        state.condition = instruction
            .ops
            .iter()
            .find(|op| {
                op.name == "CBRANCH"
                    && op
                        .inputs
                        .first()
                        .is_some_and(|node| node.space != self.ram || node.offset == Some(instruction.next))
            })
            .map(|branch| condition_signature(&instruction.ops, branch, self.register));
        for op in &instruction.ops {
            // Memory operands at a constant address appear as direct varnodes (x86 RIP-relative operands): a read
            // of writable or unmapped memory is a load source, first read before any store.
            let targets = usize::from(matches!(op.name.as_str(), "BRANCH" | "CBRANCH" | "CALL"));
            for node in op.inputs.iter().skip(targets).filter(|node| node.space == self.ram) {
                let Some(at) = node.offset else { continue };
                if self.writable_or_unmapped(at) {
                    let source = self.source(sources, Source::Load(at));
                    state.memory.entry(Loc::Abs(at & !3)).or_insert(source);
                } else if record {
                    self.wide_pad(at, node.size, recorder);
                }
            }
            let input = |index: usize, state: &State| op.inputs.get(index).and_then(|node| self.value(node, state));
            let taint_of = |index: usize, state: &State| {
                op.inputs.get(index).map_or(Taint::default(), |node| self.taint(node, state))
            };
            let size = op.output.as_ref().map_or(8, |node| node.size);
            let mut out_taint: Taint;
            let mut out_value: Option<Val> = None;
            match op.name.as_str() {
                "CBRANCH" => {
                    let condition = taint_of(1, state);
                    let target = op.inputs.first().filter(|node| node.space == self.ram).and_then(|node| node.offset);
                    let internal = target.is_none_or(|target| target == instruction.next);
                    if internal {
                        conditional = Some(conditional.unwrap_or_default().union(condition));
                    }
                    if record && !condition.is_empty() {
                        recorder.gates.push(Gate {
                            at: instruction.address,
                            taint: condition,
                            target: if internal { None } else { target },
                            next: instruction.next,
                            effect: None,
                        });
                        if internal {
                            gate_index = Some(recorder.gates.len() - 1);
                        }
                    }
                    continue;
                }
                "BRANCH" => {
                    // A branch to another function's entry is a tail call.
                    if let Some(target) = op.inputs.first().filter(|node| node.space == self.ram).and_then(|n| n.offset)
                        && !function.contains(target)
                        && scope.starts.binary_search(&target).is_ok()
                    {
                        let result =
                            self.call(scope, Some(target), instruction.address, state, sources, recorder, record);
                        if record {
                            recorder.returns.push(Return { at: instruction.address, value: None, taint: result });
                        }
                    } else if let Some(index) = gate_index
                        && let Some(target) = op.inputs.first().and_then(|node| node.offset)
                    {
                        recorder.gates[index].effect = Some(Effect::Branches(target));
                    }
                    continue;
                }
                "RETURN" => {
                    if record {
                        let node = self.result_node();
                        let value = self.value(&node, state);
                        let taint = self.taint(&node, state).union(conditional.unwrap_or_default());
                        recorder.returns.push(Return { at: instruction.address, value, taint });
                        if let Some(index) = gate_index {
                            recorder.gates[index].effect = Some(Effect::Returns(value));
                        }
                    }
                    continue;
                }
                "BRANCHIND" => {
                    if record && function.switch_cases(instruction.address).is_none() {
                        recorder.indirect_jumps.push(instruction.address);
                    }
                    continue;
                }
                "CALL" | "CALLIND" => {
                    let target = if op.name == "CALL" {
                        op.inputs.first().and_then(|node| node.offset)
                    } else {
                        match input(0, state) {
                            Some(Val::Const(target)) => Some(target),
                            _ => {
                                if record {
                                    recorder.indirect_calls.push(instruction.address);
                                }
                                None
                            }
                        }
                    };
                    self.call(scope, target, instruction.address, state, sources, recorder, record);
                    // The callee returns with the stack as it was before this instruction (x86 pushes the return
                    // address in the same instruction).
                    if let Some(stack) = entry_stack {
                        state.values.insert(self.convention.stack_pointer, stack);
                    }
                    continue;
                }
                "LOAD" => {
                    let address = input(1, state);
                    let pointer_taint = taint_of(1, state);
                    out_taint = pointer_taint;
                    match address {
                        Some(Val::Const(at)) => {
                            if record {
                                self.wide_pad(at, size, recorder);
                            }
                            if let Some(value) = self.binary.read_constant(at, u8::try_from(size).unwrap_or(0)) {
                                out_value = Some(Val::Const(value));
                                if record && value >= 0x100 && recorder.constants.len() < MAX_CONSTANTS {
                                    recorder.constants.insert(value);
                                }
                            } else {
                                out_taint = out_taint
                                    .union(self.source(sources, Source::Load(at)))
                                    .union(state.memory_range(Loc::Abs(at & !3), 4));
                            }
                            if record && at >= 0x100 && recorder.constants.len() < MAX_CONSTANTS {
                                recorder.constants.insert(at);
                            }
                        }
                        Some(Val::Stack(offset)) => {
                            out_value = state.stack_values.get(&offset).copied();
                            out_taint = out_taint.union(state.memory_range(Loc::Stack(offset & !3), 4));
                        }
                        Some(Val::StackFrom(offset)) => {
                            out_taint = out_taint.union(state.memory_range(Loc::Stack(offset & !3), INDEX_SPAN));
                        }
                        Some(Val::AbsFrom(base)) if self.writable_or_unmapped(base) => {
                            out_taint = out_taint
                                .union(self.source(sources, Source::Load(base)))
                                .union(state.memory_range(Loc::Abs(base & !3), INDEX_SPAN));
                        }
                        _ => {}
                    }
                }
                "STORE" => {
                    let address = input(1, state);
                    let value = input(2, state);
                    let taint = taint_of(2, state).union(conditional.unwrap_or_default());
                    let bytes = op.inputs.get(2).map_or(4, |node| node.size);
                    let whole = bytes >= 4 && conditional.is_none();
                    match address {
                        Some(Val::Const(at)) => {
                            if whole {
                                state.memory.insert(Loc::Abs(at & !3), taint);
                            } else {
                                state.taint_memory_range(Loc::Abs(at), 1, taint);
                            }
                            if record {
                                let constant = match value {
                                    Some(Val::Const(constant)) => Some(constant),
                                    _ => None,
                                };
                                recorder.stores.push(Store {
                                    at: instruction.address,
                                    address: at,
                                    indexed: false,
                                    value: constant,
                                    taint,
                                    by_call: false,
                                    span: u64::from(bytes),
                                });
                                if let Some(index) = gate_index {
                                    let value = match value {
                                        Some(Val::Const(constant)) => Some(constant),
                                        _ => None,
                                    };
                                    recorder.gates[index].effect = Some(Effect::Stores { address: at, value });
                                }
                            }
                        }
                        Some(Val::Stack(offset)) => {
                            match value {
                                Some(value) if conditional.is_none() && matches!(bytes, 4 | 8) => {
                                    state.stack_values.insert(offset, value);
                                }
                                _ => {
                                    state.stack_values.remove(&offset);
                                }
                            }
                            if whole {
                                state.memory.insert(Loc::Stack(offset & !3), taint);
                                if bytes == 8 {
                                    state.memory.insert(Loc::Stack((offset & !3) + 4), taint);
                                }
                            } else {
                                state.taint_memory_range(Loc::Stack(offset), 1, taint);
                            }
                        }
                        Some(Val::StackFrom(offset)) => {
                            state.taint_memory_range(Loc::Stack(offset), 4, taint);
                        }
                        Some(Val::AbsFrom(base)) => {
                            state.taint_memory_range(Loc::Abs(base), 4, taint);
                            if record && self.writable_or_unmapped(base) {
                                recorder.stores.push(Store {
                                    at: instruction.address,
                                    address: base,
                                    indexed: true,
                                    value: None,
                                    taint,
                                    by_call: false,
                                    span: 32,
                                });
                            }
                        }
                        None => {}
                    }
                    continue;
                }
                "INT_EQUAL" | "INT_NOTEQUAL" => {
                    let (a, b) = (input(0, state), input(1, state));
                    let (ta, tb) = (taint_of(0, state), taint_of(1, state));
                    out_taint = ta.union(tb);
                    let zero = matches!(a, Some(Val::Const(0))) || matches!(b, Some(Val::Const(0)));
                    let constant = matches!(a, Some(Val::Const(_))) || matches!(b, Some(Val::Const(_)));
                    let from_sub = out_taint.flags;
                    out_taint.flags |= if zero {
                        flags::ZERO
                            | if from_sub & flags::SUB_CONST != 0 { flags::EQ_CONST } else { 0 }
                            | if from_sub & flags::SUB_VALUE != 0 { flags::EQ_VALUE } else { 0 }
                            | if from_sub & flags::AND_CONST != 0 { flags::BIT } else { 0 }
                    } else if constant {
                        flags::EQ_CONST
                    } else {
                        flags::EQ_VALUE
                    };
                    if let (Some(Val::Const(x)), Some(Val::Const(y))) = (a, b) {
                        out_value = Some(Val::Const(u64::from((x == y) == (op.name == "INT_EQUAL"))));
                    }
                }
                "INT_LESS" | "INT_SLESS" | "INT_LESSEQUAL" | "INT_SLESSEQUAL" | "INT_CARRY" | "INT_SCARRY"
                | "INT_SBORROW" => {
                    out_taint = taint_of(0, state).union(taint_of(1, state));
                    out_taint.flags |= flags::ORDERED;
                }
                _ => {
                    let (a, b) = (input(0, state), input(1, state));
                    out_taint = op
                        .inputs
                        .iter()
                        .map(|node| self.taint(node, state))
                        .fold(Taint::default(), |acc, taint| acc.union(taint));
                    let signed = |constant: u64, size: u32| -> i64 {
                        let bits = 8 * size.clamp(1, 8);
                        ((constant << (64 - bits)) as i64) >> (64 - bits)
                    };
                    let in_size = op.inputs.first().map_or(8, |node| node.size);
                    out_value = match (op.name.as_str(), a, b) {
                        ("COPY" | "INT_ZEXT", Some(value), _) => Some(value),
                        ("INT_SEXT", Some(Val::Const(value)), _) => Some(Val::Const(signed(value, in_size) as u64)),
                        ("INT_SEXT", Some(value), _) => Some(value),
                        ("INT_ADD", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x.wrapping_add(y))),
                        ("INT_ADD", Some(Val::Stack(x)), Some(Val::Const(y)))
                        | ("INT_ADD", Some(Val::Const(y)), Some(Val::Stack(x))) => {
                            Some(Val::Stack(x.wrapping_add(signed(y, size))))
                        }
                        ("INT_ADD", Some(Val::Stack(x) | Val::StackFrom(x)), _)
                        | ("INT_ADD", _, Some(Val::Stack(x) | Val::StackFrom(x))) => Some(Val::StackFrom(x)),
                        ("INT_ADD", Some(Val::AbsFrom(x)), _) | ("INT_ADD", _, Some(Val::AbsFrom(x))) => {
                            Some(Val::AbsFrom(x))
                        }
                        ("INT_ADD", Some(Val::Const(x)), None) | ("INT_ADD", None, Some(Val::Const(x)))
                            if x >= 0x10000 =>
                        {
                            Some(Val::AbsFrom(x))
                        }
                        ("INT_SUB", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x.wrapping_sub(y))),
                        ("INT_SUB", Some(Val::Stack(x)), Some(Val::Const(y))) => {
                            Some(Val::Stack(x.wrapping_sub(signed(y, size))))
                        }
                        ("INT_AND", Some(Val::Stack(x)), Some(Val::Const(_))) => Some(Val::Stack(x)),
                        ("INT_AND", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x & y)),
                        ("INT_OR", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x | y)),
                        ("INT_XOR", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x ^ y)),
                        ("INT_LEFT", Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(if y < 64 { x << y } else { 0 }))
                        }
                        ("INT_RIGHT", Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(if y < 64 { x >> y } else { 0 }))
                        }
                        ("INT_MULT", Some(Val::Const(x)), Some(Val::Const(y))) => Some(Val::Const(x.wrapping_mul(y))),
                        ("INT_NEGATE", Some(Val::Const(x)), _) => Some(Val::Const(!x)),
                        ("SUBPIECE", Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(if y < 8 { x >> (8 * y) } else { 0 }))
                        }
                        ("SUBPIECE", Some(value @ (Val::Stack(_) | Val::StackFrom(_))), Some(Val::Const(0))) => {
                            Some(value)
                        }
                        _ => None,
                    };
                    let constant = matches!(a, Some(Val::Const(_))) || matches!(b, Some(Val::Const(_)));
                    match op.name.as_str() {
                        "INT_SUB" | "INT_ADD" if !out_taint.is_empty() => {
                            out_taint.flags |= if constant { flags::SUB_CONST } else { flags::SUB_VALUE };
                        }
                        "INT_AND" if !out_taint.is_empty() && constant => out_taint.flags |= flags::AND_CONST,
                        "INT_XOR" => {
                            for value in [a, b].into_iter().flatten() {
                                if let Val::Const(constant) = value
                                    && record
                                    && is_pad(constant)
                                {
                                    recorder.pads.insert(constant & 0xff);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            let Some(output) = &op.output else { continue };
            if let Some(Val::Const(constant)) = out_value
                && record
                && constant >= 0x100
                && recorder.constants.len() < MAX_CONSTANTS
            {
                recorder.constants.insert(constant);
            }
            let out_value = out_value.map(|value| match value {
                Val::Const(constant) => Val::Const(mask(constant, size)),
                other => other,
            });
            if output.space == self.ram
                && let Some(at) = output.offset
            {
                // A store to a constant address written as a direct varnode.
                let taint = out_taint.union(conditional.unwrap_or_default());
                state.memory.insert(Loc::Abs(at & !3), taint);
                if record {
                    let value = match out_value {
                        Some(Val::Const(value)) if conditional.is_none() => Some(mask(value, size)),
                        _ => None,
                    };
                    recorder.stores.push(Store {
                        at: instruction.address,
                        address: at,
                        indexed: false,
                        value,
                        taint,
                        by_call: false,
                        span: u64::from(output.size),
                    });
                    if let Some(index) = gate_index {
                        recorder.gates[index].effect = Some(Effect::Stores { address: at, value });
                    }
                }
                continue;
            }
            if let Some(condition) = conditional {
                let old = self.taint(output, state);
                if let Some(index) = gate_index
                    && recorder.gates.get(index).is_some_and(|gate| gate.effect.is_none())
                    && output.space == self.register
                {
                    recorder.gates[index].effect = Some(Effect::Sets);
                }
                let known = out_value.zip(state.condition);
                self.write(output, None, out_taint.union(old).union(condition), state);
                if let (Some((value, signature)), Some(offset)) = (known, output.offset) {
                    state.conditional_values.insert((output.space, offset, output.size), (signature, value));
                }
            } else {
                self.write(output, out_value, out_taint, state);
            }
        }
        // Temporaries do not outlive the instruction.
        state.values.retain(|&(space, _, _), _| space == self.register);
        state.taint.retain(|&(space, _, _), _| space == self.register);
        state.conditional_values.retain(|&(space, _, _), _| space == self.register);
        state.condition = None;
    }

    /// Records an HMAC pad when `size` (more than 8) bytes of read-only data at `at` repeat one pad byte, as a
    /// vector constant does.
    fn wide_pad(&self, at: u64, size: u32, recorder: &mut Recorder) {
        if size > 8
            && self.binary.read_constant(at, 1).is_some()
            && let Some(bytes) = self.binary.read(at, u64::from(size))
            && let Some(&first) = bytes.first()
            && matches!(first, 0x36 | 0x5c | 0x6a)
            && bytes.iter().all(|&byte| byte == first)
        {
            recorder.pads.insert(u64::from(first));
        }
    }

    fn result_node(&self) -> Varnode {
        let (space, offset, size) = self.convention.result;
        Varnode { space, size, address_size: 0, word_size: 1, offset: Some(offset), selected_space: None }
    }

    fn node(&self, (space, offset, size): Key) -> Varnode {
        Varnode { space, size, address_size: 0, word_size: 1, offset: Some(offset), selected_space: None }
    }

    /// Applies a call: the result and the buffers pointer arguments refer to derive from the call and from what
    /// was passed; registers the callee may change are forgotten.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        scope: &Scope,
        target: Option<u64>,
        at: u64,
        state: &mut State,
        sources: &mut Vec<Source>,
        recorder: &mut Recorder,
        record: bool,
    ) -> Taint {
        let arguments: Vec<Option<Val>> =
            self.convention.arguments.iter().map(|&key| self.value(&self.node(key), state)).collect();
        // An analyzed callee's result derives from the arguments it uses; an unknown callee's from all of them.
        let used = target.and_then(|target| scope.summaries.get(&target).copied()).unwrap_or(u64::MAX);
        let mut passed = Taint::default();
        let mut buffers = Taint::default();
        for (index, (&key, value)) in self.convention.arguments.iter().zip(&arguments).enumerate() {
            let pointee = self.pointee(*value, BUFFER_SPAN, state, sources);
            let direct = self.taint(&self.node(key), state);
            buffers = buffers.union(pointee);
            if used & (1 << index) != 0 {
                passed = passed.union(direct).union(pointee);
            }
        }
        // Arguments past the registers: the words at the stack pointer (above the return address on x86-64).
        let stacked: Vec<Option<Val>> = match state.values.get(&self.convention.stack_pointer) {
            Some(&Val::Stack(top)) => (0..4)
                .map(|slot| {
                    let offset = top + self.convention.stack_arguments + slot * self.convention.word;
                    state.stack_values.get(&offset).copied()
                })
                .collect(),
            _ => Vec::new(),
        };
        for value in &stacked {
            let pointee = self.pointee(*value, BUFFER_SPAN, state, sources);
            buffers = buffers.union(pointee);
            passed = passed.union(pointee);
        }
        let call = self.source(sources, Source::Call(target));
        let result = call.union(Taint { mask: passed.mask, flags: 0 });
        // What a callee writes through a pointer argument derives from the call and what it was given.
        let written = call.union(Taint { mask: buffers.mask | passed.mask, flags: 0 });
        let all: Vec<Option<Val>> = arguments.iter().chain(&stacked).copied().collect();
        for (index, value) in all.iter().enumerate() {
            // A (pointer, length) pair gives the buffer's size; otherwise a small buffer is assumed.
            let span = match all.get(index + 1) {
                Some(Some(Val::Const(length))) if (1..=4096).contains(length) => *length as i64,
                _ => 16,
            };
            match value {
                Some(Val::Stack(offset) | Val::StackFrom(offset)) => {
                    state.taint_memory_range(Loc::Stack(*offset), BUFFER_SPAN, written);
                    state.stack_values.retain(|key, _| !(*offset..offset + BUFFER_SPAN).contains(key));
                }
                Some(Val::Const(address) | Val::AbsFrom(address))
                    if *address >= 0x1000 && self.writable_or_unmapped(*address) =>
                {
                    state.taint_memory_range(Loc::Abs(*address), span, written);
                    if record {
                        recorder.stores.push(Store {
                            at,
                            address: *address,
                            indexed: true,
                            value: None,
                            taint: written,
                            by_call: true,
                            span: span as u64,
                        });
                    }
                }
                _ => {}
            }
        }
        let stack = self.convention.stack_pointer;
        let keep = |key: &Key| *key == stack || self.convention.preserved.contains(key);
        state.values.retain(|key, _| key.0 != self.register || keep(key));
        state.taint.retain(|key, _| key.0 != self.register || keep(key));
        state.taint.insert(self.convention.result, result);
        if record {
            recorder.calls.push(CallSite { at, target, arguments, result });
        }
        result
    }
}

/// A signature of the condition a conditionally executed instruction tests: the operations computing it and the
/// registers they read, so the instructions of one IT block that share a condition share a signature.
fn condition_signature(ops: &[PcodeOp], branch: &PcodeOp, register: u32) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // The backward slice of the branch condition within the instruction: the ops that compute it.
    let key = |node: &Varnode| (node.space, node.offset, node.size);
    let mut needed: Vec<(u32, Option<u64>, u32)> = branch.inputs.get(1).map(key).into_iter().collect();
    let before: Vec<&PcodeOp> = ops.iter().take_while(|op| !std::ptr::eq(*op, branch)).collect();
    for op in before.iter().rev() {
        let Some(output) = &op.output else { continue };
        if !needed.contains(&key(output)) {
            continue;
        }
        op.name.hash(&mut hasher);
        for node in &op.inputs {
            if node.space == register {
                (node.offset, node.size).hash(&mut hasher);
            } else {
                needed.push(key(node));
            }
        }
    }
    if let Some(condition) = branch.inputs.get(1).filter(|node| node.space == register) {
        (condition.offset, condition.size).hash(&mut hasher);
    }
    hasher.finish()
}

/// Whether `constant` is an HMAC pad byte (0x36 or 0x5c), alone or repeated across a word.
fn is_pad(constant: u64) -> bool {
    let byte = constant & 0xff;
    // 0x6a is 0x36 ^ 0x5c: the outer pad applied over the inner one.
    (byte == 0x36 || byte == 0x5c || byte == 0x6a)
        && [1u32, 2, 4, 8].iter().any(|&width| {
            let repeated = (0..width).fold(0u64, |acc, index| acc | (byte << (8 * index)));
            constant == repeated
        })
}

fn mask(value: u64, size: u32) -> u64 {
    if size >= 8 { value } else { value & ((1u64 << (8 * size)) - 1) }
}

#[derive(Default)]
struct Recorder {
    gates: Vec<Gate>,
    calls: Vec<CallSite>,
    stores: Vec<Store>,
    returns: Vec<Return>,
    indirect_calls: Vec<u64>,
    indirect_jumps: Vec<u64>,
    self_loops: Vec<u64>,
    constants: BTreeSet<u64>,
    pads: BTreeSet<u64>,
}

impl FunctionFlow {
    /// Whether the function XORs with both HMAC pad bytes (0x36 and 0x5c).
    pub fn hmac_pads(&self) -> bool {
        self.pads.contains(&0x36) && (self.pads.contains(&0x5c) || self.pads.contains(&0x6a))
    }
}
