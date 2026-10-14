//! Prototypes for Go's register ABI on x86-64 and AArch64, so decompiled Go code passes arguments and results
//! between calls.
//!
//! Inputs come from each function's ArgInfo (the loader's `go_arguments`). A stripped binary records nothing
//! about results, so they are inferred from callers: Go code never reads an argument register that a call
//! clobbered unless the callee returned a value in it, so the result registers live after a call bound how many
//! results the callee has. A register can stay live by being passed straight to another call (that callee's
//! inputs) or returned again (the caller's own results), so liveness runs to a fixpoint over the call graph.
//! A result nothing reads is not found, and its function declares fewer results than it has.
//!
//! ArgInfo does not say which inputs are floats. Go's stack-growth path spills every register input, so a
//! function whose entry reads a float argument register, or whose callers read a float result register, gets no
//! prototype; neither does one whose entry reads more integer argument registers than its ArgInfo describes. At
//! a call, the callee's inputs are the registers its entry actually reads, so a float passed in a float register
//! is not taken for the integer register ArgInfo would assign, which would make the previous call's results look
//! read.

use std::collections::{BTreeMap, HashMap};

use rampage_arch::Arch;
use rampage_arch::Flow;
use rampage_arch::registers::{RegisterAccess, X86Registers, gpr, v, x, xmm};
use rampage_decompiler::DecompilerOptions;
use rampage_decompiler::worker::WorkerOperation;
use rampage_loaders::gopclntab::GoArguments;

use crate::Project;

/// Rounds of the call-graph fixpoint; each round can only raise result counts, which are bounded.
const MAX_ROUNDS: usize = 24;

/// One architecture's Go register ABI, as [`RegisterAccess`] bits.
struct Abi {
    /// Integer argument and result registers in assignment order.
    integers: &'static [u64],
    /// Float argument and result registers.
    floats: u64,
    /// Everything a call may change.
    clobbered: u64,
}

impl Abi {
    fn integers(&self, count: usize) -> u64 {
        self.integers.iter().take(count).fold(0, |mask, bit| mask | bit)
    }

    /// How many integer result registers `live` reaches into.
    fn result_count(&self, live: u64) -> usize {
        self.integers.iter().rposition(|&bit| live & bit != 0).map_or(0, |index| index + 1)
    }
}

/// RAX, RBX, RCX, RDI, RSI, R8 to R11; X0 to X14 (X15 is Go's fixed zero). A call keeps RSP, RBP and R14 (the
/// goroutine).
const AMD64: Abi = Abi {
    integers: &[gpr(0), gpr(3), gpr(1), gpr(7), gpr(6), gpr(8), gpr(9), gpr(10), gpr(11)],
    floats: xmm(0) * ((1 << 15) - 1),
    clobbered: (0xffff & !(gpr(4) | gpr(5) | gpr(14))) | (xmm(0) * ((1 << 15) - 1)),
};

/// X0 to X15 and V0 to V15. A call keeps SP, X28 (the goroutine) and X29 (the frame pointer); Go keeps nothing
/// else across calls, the link register X30 included.
const ARM64: Abi = Abi {
    integers: &[x(0), x(1), x(2), x(3), x(4), x(5), x(6), x(7), x(8), x(9), x(10), x(11), x(12), x(13), x(14), x(15)],
    floats: v(0) * 0xffff,
    clobbered: ((x(31) - 1) & !(x(28) | x(29))) | (v(0) * 0xffff_ffff),
};

/// Decodes an architecture's instructions for their register access.
enum Registers {
    X86(Box<X86Registers>),
    A64,
}

impl Registers {
    fn access(&mut self, bytes: &[u8], address: u64) -> Option<RegisterAccess> {
        match self {
            Registers::X86(registers) => registers.go_access(bytes, address).map(|(_, access)| access),
            Registers::A64 => rampage_arch::registers::a64_access(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?)),
        }
    }
}

/// The derived prototypes of one binary, ready to hand to the decompiler.
#[derive(Debug, Default)]
pub(crate) struct GoPrototypes {
    /// C declarations by function address.
    pub(crate) declarations: BTreeMap<u64, String>,
    /// The result structs the declarations use, one declaration each.
    pub(crate) types: Vec<String>,
}

struct Instruction {
    flow: Flow,
    access: RegisterAccess,
}

struct Block {
    instructions: Vec<Instruction>,
    successors: Vec<usize>,
}

struct Body {
    blocks: Vec<Block>,
    entry: usize,
}

/// What liveness over every caller found about each callee.
#[derive(Default)]
struct CalleeUse {
    results: usize,
    float_results: bool,
}

impl Project {
    pub(crate) fn go_prototypes(&self) -> &GoPrototypes {
        self.go_prototypes.get_or_init(|| derive(self).unwrap_or_default())
    }
}

/// The operations declaring derived prototypes, when the decompiler uses Go's register ABI. Addresses that
/// carry a user signature keep it.
pub(super) fn plan(
    project: &Project,
    annotations: &crate::annotations::Annotations,
    options: &DecompilerOptions,
) -> Vec<WorkerOperation> {
    if options.compiler.as_deref() != Some("golang") {
        return Vec::new();
    }
    let prototypes = project.go_prototypes();
    if prototypes.declarations.is_empty() {
        return Vec::new();
    }
    let mut operations: Vec<WorkerOperation> = prototypes
        .types
        .iter()
        .map(|declaration| WorkerOperation::ParseTypes { declarations: declaration.clone() })
        .collect();
    for (&address, declaration) in &prototypes.declarations {
        if annotations.signatures().contains_key(&address) {
            continue;
        }
        operations.push(WorkerOperation::Symbol { address, name: project.function_name_in(annotations, address) });
        operations.push(WorkerOperation::Prototype { address, indirect: false, declaration: declaration.clone() });
    }
    operations
}

fn derive(project: &Project) -> Option<GoPrototypes> {
    let binary = &project.binary;
    let (abi, mut registers) = match binary.arch {
        Arch::X86_64 => (&AMD64, Registers::X86(Box::default())),
        Arch::Aarch64 if !binary.big_endian => (&ARM64, Registers::A64),
        _ => return None,
    };
    if binary.go_arguments.is_empty() {
        return None;
    }
    let program = &project.analysis().ok()?.program;
    let mut decoder = rampage_arch::decoder(&binary.target()).ok()?;
    let bodies: HashMap<u64, Body> = program
        .functions
        .iter()
        .filter(|function| binary.go_arguments.contains_key(&function.address))
        .filter_map(|function| Some((function.address, body(project, function, &mut *decoder, &mut registers)?)))
        .collect();
    // What each callee reads on entry, before any results are known: the ArgInfo integer registers it uses and
    // any float argument registers. A float input is then live as itself, not as the integer register ArgInfo
    // would assign it, so it does not make the previous call's results look read.
    let described = |address: u64| binary.go_arguments.get(&address).map_or(0, |arguments| input_mask(abi, arguments));
    let entries: HashMap<u64, u64> = bodies
        .iter()
        .map(|(&address, body)| {
            let entry = liveness(abi, body, 0, &described, &bodies, &mut |_, _| {})[body.entry];
            (address, entry & (described(address) | abi.floats))
        })
        .collect();
    let inputs = |address: u64| entries.get(&address).copied().unwrap_or(0);

    let mut results: HashMap<u64, usize> = HashMap::new();
    let mut uses: HashMap<u64, CalleeUse> = HashMap::new();
    for _ in 0..MAX_ROUNDS {
        uses.clear();
        for (&address, body) in &bodies {
            let own = abi.integers(results.get(&address).copied().unwrap_or(0));
            liveness(abi, body, own, &inputs, &bodies, &mut |callee, live| {
                let used = uses.entry(callee).or_default();
                used.results = used.results.max(abi.result_count(live));
                used.float_results |= live & abi.floats != 0;
            });
        }
        let mut changed = false;
        for (&callee, used) in &uses {
            let known = results.entry(callee).or_default();
            if used.results > *known {
                *known = used.results;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut prototypes = GoPrototypes::default();
    let mut widths = std::collections::BTreeSet::new();
    for (&address, body) in &bodies {
        let arguments = &binary.go_arguments[&address];
        let own = abi.integers(results.get(&address).copied().unwrap_or(0));
        let entry = liveness(abi, body, own, &inputs, &bodies, &mut |_, _| {})[body.entry];
        let components: usize = arguments.inputs.iter().map(Vec::len).sum();
        let float_results = uses.get(&address).is_some_and(|used| used.float_results);
        let undescribed = entry & abi.integers(abi.integers.len()) & !abi.integers(components);
        if entry & abi.floats != 0 || float_results || undescribed != 0 {
            continue;
        }
        let count = results.get(&address).copied().unwrap_or(0);
        if count > 1 {
            widths.insert(count);
        }
        prototypes.declarations.insert(address, declaration(arguments, count));
    }
    prototypes.types = widths
        .into_iter()
        .map(|count| {
            let fields: String = (0..count).map(|index| format!(" xunknown8 r{index};")).collect();
            format!("typedef struct {{{fields} }} go_results_{count};")
        })
        .collect();
    Some(prototypes)
}

/// The integer registers that carry a function's inputs, or none when they do not all fit in registers.
fn input_mask(abi: &Abi, arguments: &GoArguments) -> u64 {
    let components: usize = arguments.inputs.iter().map(Vec::len).sum();
    if components > abi.integers.len() { 0 } else { abi.integers(components) }
}

/// A C declaration: each input component as a parameter of its size, and the results as one register, a struct
/// of registers, or nothing.
fn declaration(arguments: &GoArguments, results: usize) -> String {
    let parameters: Vec<String> =
        arguments.inputs.iter().flatten().map(|slot| format!("xunknown{}", slot.size)).collect();
    let returns = match results {
        0 => "void".to_owned(),
        1 => "xunknown8".to_owned(),
        count => format!("go_results_{count}"),
    };
    let parameters = if parameters.is_empty() { "void".to_owned() } else { parameters.join(", ") };
    format!("{returns} go_function({parameters});")
}

/// Decodes a function's blocks and links them as `graph.rs` does: direct and switch jumps within the function,
/// fall-through after everything but returns, halts and calls that never return.
fn body(
    project: &Project,
    function: &rampage_analysis::discover::DiscoveredFunction,
    decoder: &mut dyn rampage_arch::Disassembler,
    registers: &mut Registers,
) -> Option<Body> {
    let program = &project.analysis().ok()?.program;
    let starts: HashMap<u64, usize> =
        function.blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();
    let mut blocks = Vec::with_capacity(function.blocks.len());
    for block in &function.blocks {
        decoder.reset();
        let mut instructions = Vec::new();
        let mut address = block.start;
        let mut last = Flow::Next;
        let mut last_address = address;
        while address < block.end {
            let bytes = project.binary.code_from(address)?;
            let insn = decoder.decode(bytes, address);
            let access = registers.access(bytes, address)?;
            if insn.len == 0 {
                return None;
            }
            instructions.push(Instruction { flow: insn.flow, access });
            last = insn.flow;
            last_address = address;
            address += u64::from(insn.len);
        }
        let index_of = |address: u64| starts.get(&address).copied();
        let noreturn = program.noreturn_calls.binary_search(&last_address).is_ok();
        let successors: Vec<usize> = match last {
            Flow::Jump(target) => index_of(target).into_iter().collect(),
            Flow::ConditionalJump(target) => index_of(target).into_iter().chain(index_of(block.end)).collect(),
            Flow::IndirectJump => function
                .switch_cases(last_address)
                .unwrap_or_default()
                .iter()
                .filter_map(|&case| index_of(case))
                .collect(),
            Flow::Return | Flow::Halt | Flow::Invalid => Vec::new(),
            Flow::Call(_) | Flow::IndirectCall if noreturn => Vec::new(),
            Flow::Next | Flow::Call(_) | Flow::IndirectCall => index_of(block.end).into_iter().collect(),
        };
        blocks.push(Block { instructions, successors });
    }
    let entry = *starts.get(&function.address)?;
    Some(Body { blocks, entry })
}

/// Backward liveness of registers over `body`, returning each block's live-in set. `results` is live at each
/// return. At a direct call the callee's inputs become live, and `observe` sees the registers live just after
/// it; a jump to another function's entry is a tail call that passes on the caller's results.
fn liveness(
    abi: &Abi,
    body: &Body,
    results: u64,
    inputs: &dyn Fn(u64) -> u64,
    bodies: &HashMap<u64, Body>,
    observe: &mut dyn FnMut(u64, u64),
) -> Vec<u64> {
    let mut live_in = vec![0u64; body.blocks.len()];
    loop {
        let mut changed = false;
        for (index, block) in body.blocks.iter().enumerate().rev() {
            let mut live = block.successors.iter().fold(0, |live, &successor| live | live_in[successor]);
            for instruction in block.instructions.iter().rev() {
                live = match instruction.flow {
                    Flow::Return => results | instruction.access.reads,
                    Flow::Call(target) => {
                        if bodies.contains_key(&target) {
                            observe(target, live);
                        }
                        (live & !abi.clobbered) | inputs(target) | (instruction.access.reads & !abi.clobbered)
                    }
                    Flow::IndirectCall => (live & !abi.clobbered) | instruction.access.reads,
                    Flow::Jump(target) if block.successors.is_empty() && bodies.contains_key(&target) => {
                        observe(target, results);
                        inputs(target)
                    }
                    _ => (live & !instruction.access.writes) | instruction.access.reads,
                };
            }
            if live != live_in[index] {
                live_in[index] = live;
                changed = true;
            }
        }
        if !changed {
            return live_in;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_keep_only_the_stack_frame_and_goroutine_registers() {
        assert_eq!(AMD64.clobbered & (gpr(4) | gpr(5) | gpr(14) | xmm(15)), 0);
        assert_eq!(AMD64.clobbered & AMD64.integers(9), AMD64.integers(9));
        assert_eq!(AMD64.floats & xmm(14), xmm(14));
        assert_eq!(ARM64.clobbered & (x(31) | x(28) | x(29)), 0);
        assert_eq!(
            ARM64.clobbered & (ARM64.integers(16) | x(30) | ARM64.floats),
            ARM64.integers(16) | x(30) | ARM64.floats
        );
        assert_eq!(ARM64.floats, (0..16).fold(0, |mask, number| mask | v(number)));
    }
}
