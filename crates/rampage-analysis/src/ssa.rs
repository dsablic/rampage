use std::collections::{BTreeSet, VecDeque};

use rampage_arch::Flow;
use rampage_arch::ir::{Effect, FlagOperation, LiftedInstruction, Operation, UnaryOperation, Value};
use serde::Serialize;

const VARIABLES: usize = 34;
const MEMORY: usize = 32;
const FLAGS: usize = 33;
const MAX_BLOCKS: usize = 512;
const MAX_INSTRUCTIONS: usize = 20_000;
const MAX_DEFINITIONS: usize = 20_000;
const MAX_VALUE_NODES: usize = 80_000;

#[derive(Debug, Clone)]
pub struct InputBlock {
    pub address: u64,
    pub instructions: Vec<LiftedInstruction>,
}

#[derive(Debug, Serialize)]
pub struct Ssa {
    pub entry: usize,
    pub blocks: Vec<Block>,
    pub definitions: Vec<Definition>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Block {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub reachable: bool,
    pub predecessors: Vec<usize>,
    pub phis: Vec<usize>,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Serialize)]
pub struct Statement {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub flow: Flow,
    pub bits: u8,
    pub definitions: Vec<usize>,
    /// Recovered memory-read results alias values, but do not grant entry-SP address provenance.
    /// In definition order, paired with the equally ordered suffix of retained load observations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovered_loads: Vec<usize>,
    pub observations: Vec<Expression>,
    pub barrier: bool,
    /// A call that never returns, so its block ends here with no successor. [`build`] leaves it unset; the caller
    /// marks the calls that discovery found noreturn.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub noreturn: bool,
}

impl Statement {
    /// Whether control never continues past this statement: a return, a trap, undecodable bytes, or a call that
    /// never returns.
    pub fn is_terminal(&self) -> bool {
        matches!(self.flow, Flow::Return | Flow::Halt | Flow::Invalid) || self.noreturn
    }
}

#[derive(Debug, Serialize)]
pub struct Definition {
    pub id: usize,
    pub variable: Variable,
    pub expression: Expression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Variable {
    Register { number: u8 },
    StackPointer,
    Memory,
    Flags,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expression {
    IndirectBranch {
        target: Box<Expression>,
    },
    Extend {
        value: Box<Expression>,
        from_bits: u8,
        to_bits: u8,
        signed: bool,
    },
    Return {
        target: Box<Expression>,
        integer_values: [usize; 2],
        memory: usize,
    },
    Select {
        flags: usize,
        condition: u8,
        when_true: Box<Expression>,
        when_false: Box<Expression>,
    },
    Binary {
        operation: Operation,
        left: Box<Expression>,
        right: Box<Expression>,
        bits: u8,
    },
    Unary {
        operation: UnaryOperation,
        value: Box<Expression>,
        bits: u8,
    },
    Flags {
        operation: FlagOperation,
        left: Box<Expression>,
        right: Box<Expression>,
        bits: u8,
    },
    FlagsCondition {
        flags: usize,
        condition: u8,
    },
    Call {
        target: Box<Expression>,
        arguments: Vec<usize>,
        memory: usize,
        return_address: u64,
        result_buffer: usize,
        stack_pointer: usize,
    },
    Input,
    Unknown {
        reason: String,
    },
    Reference {
        definition: usize,
    },
    Constant {
        #[serde(serialize_with = "rampage_arch::hex::address")]
        value: u64,
    },
    Add {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Subtract {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Low32 {
        value: Box<Expression>,
    },
    Condition {
        value: Box<Expression>,
        nonzero: bool,
        bit: Option<u8>,
    },
    Phi {
        inputs: Vec<PhiInput>,
    },
    Load {
        memory: usize,
        address: Box<Expression>,
        bits: u8,
    },
    Store {
        memory: usize,
        address: Box<Expression>,
        value: Box<Expression>,
        bits: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhiInput {
    /// None denotes the external entry edge, including when entry has a loop backedge.
    pub predecessor: Option<usize>,
    pub definition: usize,
}

fn variable(index: usize) -> Variable {
    match index {
        31 => Variable::StackPointer,
        MEMORY => Variable::Memory,
        FLAGS => Variable::Flags,
        _ => Variable::Register { number: index as u8 },
    }
}

fn destination(value: &Value) -> Option<usize> {
    match value {
        Value::Register { number } if *number < 31 => Some(usize::from(*number)),
        Value::StackPointer => Some(31),
        _ => None,
    }
}

fn expression(value: &Value, state: &[usize; VARIABLES], depth: usize) -> Result<Expression, String> {
    if depth > 64 {
        return Err("IR expression nesting exceeds 64 levels".to_owned());
    }
    Ok(match value {
        Value::Low32 { value } => Expression::Low32 { value: Box::new(expression(value, state, depth + 1)?) },
        Value::Binary { operation, left, right, bits } => Expression::Binary {
            operation: *operation,
            left: Box::new(expression(left, state, depth + 1)?),
            right: Box::new(expression(right, state, depth + 1)?),
            bits: *bits,
        },
        Value::Unary { operation, value, bits } => Expression::Unary {
            operation: *operation,
            value: Box::new(expression(value, state, depth + 1)?),
            bits: *bits,
        },
        Value::Register { number } if *number < 31 => Expression::Reference { definition: state[*number as usize] },
        Value::Register { .. } => return Err("IR register number must be below 31".to_owned()),
        Value::StackPointer => Expression::Reference { definition: state[31] },
        Value::Constant { value } => Expression::Constant { value: *value },
        Value::Add { left, right } => Expression::Add {
            left: Box::new(expression(left, state, depth + 1)?),
            right: Box::new(expression(right, state, depth + 1)?),
        },
        Value::Subtract { left, right } => Expression::Subtract {
            left: Box::new(expression(left, state, depth + 1)?),
            right: Box::new(expression(right, state, depth + 1)?),
        },
    })
}

const CARRY_SET: u8 = 2;

fn not(value: Expression, bits: u8) -> Expression {
    Expression::Binary {
        operation: Operation::Xor,
        left: Box::new(value),
        right: Box::new(Expression::Constant { value: u64::MAX }),
        bits,
    }
}

/// `left + right + C`, or `left - right - !C`, selected on the incoming carry.
fn carry_result(flags: usize, left: Expression, right: Expression, subtract: bool) -> Expression {
    let (left, right) = (Box::new(left), Box::new(right));
    let one = Box::new(Expression::Constant { value: 1 });
    let (when_true, when_false) = if subtract {
        let difference = Expression::Subtract { left, right };
        (difference.clone(), Expression::Subtract { left: Box::new(difference), right: one })
    } else {
        let sum = Expression::Add { left, right };
        (Expression::Add { left: Box::new(sum.clone()), right: one }, sum)
    };
    Expression::Select { flags, condition: CARRY_SET, when_true: Box::new(when_true), when_false: Box::new(when_false) }
}

/// AddWithCarry(x, y, 1) has the flags of x - NOT(y), and AddWithCarry(x, y, 0) those of x + y; subtraction
/// passes y = NOT(right).
fn carry_flags(flags: usize, left: Expression, right: Expression, subtract: bool, bits: u8) -> Expression {
    let computed =
        |operation, right| Expression::Flags { operation, left: Box::new(left.clone()), right: Box::new(right), bits };
    let (when_true, when_false) = if subtract {
        (computed(FlagOperation::Subtract, right.clone()), computed(FlagOperation::Add, not(right, bits)))
    } else {
        (computed(FlagOperation::Subtract, not(right.clone(), bits)), computed(FlagOperation::Add, right))
    };
    Expression::Select { flags, condition: CARRY_SET, when_true: Box::new(when_true), when_false: Box::new(when_false) }
}

fn narrow(value: Expression, bits: u8) -> Expression {
    if bits == 32 { Expression::Low32 { value: Box::new(value) } } else { value }
}

fn define(definitions: &mut Vec<Definition>, state: &mut [usize; VARIABLES], index: usize, value: Expression) -> usize {
    let id = definitions.len();
    definitions.push(Definition { id, variable: variable(index), expression: value });
    state[index] = id;
    id
}

/// A `bits`-wide load from `address` in the current memory state.
fn load(address: &Value, state: &[usize; VARIABLES], bits: u8) -> Result<Expression, String> {
    Ok(Expression::Load { memory: state[MEMORY], address: Box::new(expression(address, state, 0)?), bits })
}

/// Records `load` into `target`: an observation for the zero register, otherwise a definition of `target` as the
/// load extended from `bits` to `result_bits`.
fn define_load(
    statement: &mut Statement,
    definitions: &mut Vec<Definition>,
    state: &mut [usize; VARIABLES],
    target: &Value,
    load: Expression,
    (bits, result_bits, signed): (u8, u8, bool),
) -> Result<(), String> {
    if matches!(target, Value::Constant { value: 0 }) {
        statement.observations.push(load);
    } else {
        let index = destination(target).ok_or("memory load destination is not writable")?;
        let value = Expression::Extend { value: Box::new(load), from_bits: bits, to_bits: result_bits, signed };
        statement.definitions.push(define(definitions, state, index, value));
    }
    Ok(())
}

pub(crate) fn references(value: &Expression, out: &mut Vec<usize>) {
    match value {
        Expression::IndirectBranch { target } => references(target, out),
        Expression::Return { target, integer_values, memory } => {
            references(target, out);
            out.extend(integer_values);
            out.push(*memory);
        }
        Expression::Select { flags, when_true, when_false, .. } => {
            out.push(*flags);
            references(when_true, out);
            references(when_false, out);
        }
        Expression::Reference { definition } => out.push(*definition),
        Expression::Add { left, right }
        | Expression::Subtract { left, right }
        | Expression::Binary { left, right, .. }
        | Expression::Flags { left, right, .. } => {
            references(left, out);
            references(right, out);
        }
        Expression::Low32 { value }
        | Expression::Condition { value, .. }
        | Expression::Extend { value, .. }
        | Expression::Unary { value, .. } => references(value, out),
        Expression::FlagsCondition { flags, .. } => out.push(*flags),
        Expression::Call { target, arguments, memory, result_buffer, stack_pointer, .. } => {
            references(target, out);
            out.extend(arguments);
            out.push(*memory);
            out.extend([*result_buffer, *stack_pointer]);
        }
        Expression::Phi { inputs } => out.extend(inputs.iter().map(|input| input.definition)),
        Expression::Load { memory, address, .. } => {
            out.push(*memory);
            references(address, out);
        }
        Expression::Store { memory, address, value, .. } => {
            out.push(*memory);
            references(address, out);
            references(value, out);
        }
        _ => {}
    }
}

fn validate_values(values: &[&Value], nodes: &mut usize) -> Result<(), String> {
    for value in values {
        let mut stack = vec![(*value, 0usize)];
        while let Some((value, depth)) = stack.pop() {
            *nodes += 1;
            if *nodes > MAX_VALUE_NODES {
                return Err("SSA value-node limit exceeded (80,000)".to_owned());
            }
            if depth > 64 {
                return Err("IR expression nesting exceeds 64 levels".to_owned());
            }
            match value {
                Value::Add { left, right } | Value::Subtract { left, right } | Value::Binary { left, right, .. } => {
                    stack.push((right, depth + 1));
                    stack.push((left, depth + 1));
                }
                Value::Low32 { value } | Value::Unary { value, .. } => stack.push((value, depth + 1)),
                _ => {}
            }
        }
    }
    Ok(())
}

fn budget(input: &[InputBlock]) -> Result<(), String> {
    let mut definitions = VARIABLES * (1 + input.len());
    let mut nodes = 0;
    for insn in input.iter().flat_map(|block| &block.instructions) {
        let barrier = !insn.complete
            || matches!(insn.flow, Flow::Invalid)
            || matches!(insn.flow, Flow::Call(_) | Flow::IndirectCall)
                && !insn.effects.iter().any(|effect| matches!(effect, Effect::Call { .. }))
            || insn.effects.iter().any(|effect| matches!(effect, Effect::Barrier { .. }));
        if barrier {
            definitions += VARIABLES;
        }
        for effect in &insn.effects {
            match effect {
                Effect::IndirectBranch { target } => {
                    if !matches!(insn.flow, Flow::Jump(_) | Flow::IndirectJump) {
                        return Err("indirect branch effect requires jump flow".to_owned());
                    }
                    validate_values(&[target], &mut nodes)?;
                }
                Effect::MemoryLoad { destination, address, bits, result_bits, signed } => {
                    if rampage_arch::ir::extend(0, *bits, *result_bits, *signed).is_none() {
                        return Err("invalid memory load widths".to_owned());
                    }
                    if !barrier && !matches!(destination, Value::Constant { value: 0 }) {
                        definitions += 1;
                    }
                    validate_values(&[destination, address], &mut nodes)?;
                }
                Effect::MemoryLoadPair { destinations, addresses, bits, result_bits, signed } => {
                    if rampage_arch::ir::extend(0, *bits, *result_bits, *signed).is_none() {
                        return Err("invalid memory load widths".to_owned());
                    }
                    if destinations[0] == destinations[1] {
                        return Err("pair load destinations must differ".to_owned());
                    }
                    if !barrier {
                        definitions += destinations
                            .iter()
                            .filter(|destination| !matches!(destination, Value::Constant { value: 0 }))
                            .count();
                    }
                    validate_values(&[&destinations[0], &destinations[1], &addresses[0], &addresses[1]], &mut nodes)?;
                }
                Effect::MemoryStore { address, value, bits } => {
                    if !matches!(bits, 8 | 16 | 32 | 64) {
                        return Err("invalid memory store width".to_owned());
                    }
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[address, value], &mut nodes)?;
                }
                Effect::Return { target } => {
                    if insn.flow != Flow::Return {
                        return Err("return effect requires return flow".to_owned());
                    }
                    validate_values(&[target], &mut nodes)?;
                }
                Effect::Select { destination, condition, when_true, when_false } => {
                    if *condition > 15 {
                        return Err("invalid select condition".to_owned());
                    }
                    if !barrier && !matches!(destination, Value::Constant { value: 0 }) {
                        definitions += 1;
                    }
                    validate_values(&[destination, when_true, when_false], &mut nodes)?;
                }
                Effect::Assign { destination, value } => {
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[destination, value], &mut nodes)?;
                }
                Effect::Load { destination, address } => {
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[destination, address], &mut nodes)?;
                }
                Effect::Store { address, value } => {
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[address, value], &mut nodes)?;
                }
                Effect::Discard { value } | Effect::ConditionalControl { value, .. } => {
                    validate_values(&[value], &mut nodes)?;
                }
                Effect::LoadDiscard { address } => validate_values(&[address], &mut nodes)?,
                Effect::Control { inputs } => {
                    if inputs.len() > MAX_VALUE_NODES.saturating_sub(nodes) {
                        return Err("SSA value-node limit exceeded (80,000)".to_owned());
                    }
                    for value in inputs {
                        validate_values(&[value], &mut nodes)?;
                    }
                }
                Effect::Barrier { .. } => {}
                Effect::SetFlags { left, right, .. } => {
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[left, right], &mut nodes)?;
                }
                Effect::FlagsConditional { condition } => {
                    if *condition > 15 {
                        return Err("invalid flag condition".to_owned());
                    }
                }
                Effect::CarryArithmetic { destination, left, right, set_flags, .. } => {
                    if !barrier {
                        definitions += usize::from(!matches!(destination, Value::Constant { value: 0 }));
                        definitions += usize::from(*set_flags);
                    }
                    // Each operand is expanded into both carry arms of the result and of the flags.
                    for _ in 0..if *set_flags { 4 } else { 2 } {
                        validate_values(&[left, right], &mut nodes)?;
                    }
                    validate_values(&[destination], &mut nodes)?;
                }
                Effect::ConditionalFlags { condition, nzcv, left, right, .. } => {
                    if *condition > 15 || *nzcv > 15 {
                        return Err("invalid conditional flags".to_owned());
                    }
                    if !barrier {
                        definitions += 1;
                    }
                    validate_values(&[left, right], &mut nodes)?;
                }
                Effect::Call { target, .. } => {
                    if !barrier {
                        definitions += 22;
                    }
                    validate_values(&[target], &mut nodes)?;
                }
            }
            if definitions > MAX_DEFINITIONS {
                return Err("SSA definition limit exceeded (20,000)".to_owned());
            }
        }
        if definitions > MAX_DEFINITIONS {
            return Err("SSA definition limit exceeded (20,000)".to_owned());
        }
    }
    Ok(())
}

/// Block-parameter SSA: every block starts with phi parameters, with predecessor values wired after translation.
pub fn build(input: &[InputBlock], edges: &[(usize, usize)], entry: usize) -> Result<Ssa, String> {
    if input.is_empty() || input.len() > MAX_BLOCKS || entry >= input.len() || edges.len() > 4096 {
        return Err("SSA requires 1–512 blocks, a valid entry and at most 4096 edges".to_owned());
    }
    let instructions: usize = input.iter().map(|block| block.instructions.len()).sum();
    if instructions > MAX_INSTRUCTIONS {
        return Err("SSA instruction limit exceeded (20,000)".to_owned());
    }
    let effects: usize = input.iter().flat_map(|block| &block.instructions).map(|insn| insn.effects.len()).sum();
    if effects > MAX_INSTRUCTIONS * 4 {
        return Err("SSA effect limit exceeded (80,000)".to_owned());
    }
    budget(input)?;
    let mut predecessors = vec![Vec::new(); input.len()];
    let mut successors = vec![Vec::new(); input.len()];
    for &(from, to) in edges {
        if from >= input.len() || to >= input.len() {
            return Err("SSA edge refers to a nonexistent block".to_owned());
        }
        predecessors[to].push(from);
        successors[from].push(to);
    }
    for list in predecessors.iter_mut().chain(successors.iter_mut()) {
        list.sort_unstable();
        list.dedup();
    }
    let mut reachable = vec![false; input.len()];
    let mut queue = VecDeque::from([entry]);
    while let Some(block) = queue.pop_front() {
        if !std::mem::replace(&mut reachable[block], true) {
            queue.extend(&successors[block]);
        }
    }
    let mut definitions = Vec::new();
    let mut initial = [0; VARIABLES];
    for index in 0..VARIABLES {
        define(&mut definitions, &mut initial, index, Expression::Input);
    }
    let mut parameters = vec![[0; VARIABLES]; input.len()];
    for (_, state) in parameters.iter_mut().enumerate().filter(|(block, _)| reachable[*block]) {
        for index in 0..VARIABLES {
            define(&mut definitions, state, index, Expression::Phi { inputs: Vec::new() });
        }
    }
    let mut blocks = Vec::with_capacity(input.len());
    let mut outgoing = parameters.clone();
    for (index, source) in input.iter().enumerate() {
        let mut block = Block {
            address: source.address,
            reachable: reachable[index],
            predecessors: predecessors[index].iter().copied().filter(|&from| reachable[from]).collect(),
            phis: Vec::new(),
            statements: Vec::new(),
        };
        if !reachable[index] {
            blocks.push(block);
            continue;
        }
        let state = &mut outgoing[index];
        for insn in &source.instructions {
            if !matches!(insn.bits, 32 | 64) {
                return Err("SSA supports 32/64-bit instruction widths only".to_owned());
            }
            let mut statement = Statement {
                address: insn.address,
                flow: insn.flow,
                bits: insn.bits,
                definitions: Vec::new(),
                recovered_loads: Vec::new(),
                observations: Vec::new(),
                barrier: !insn.complete
                    || matches!(insn.flow, Flow::Invalid)
                    || matches!(insn.flow, Flow::Call(_) | Flow::IndirectCall)
                        && !insn.effects.iter().any(|effect| matches!(effect, Effect::Call { .. }))
                    || insn.effects.iter().any(|effect| matches!(effect, Effect::Barrier { .. })),
                noreturn: false,
            };
            if statement.barrier {
                for index in 0..VARIABLES {
                    statement.definitions.push(define(
                        &mut definitions,
                        state,
                        index,
                        Expression::Unknown { reason: "unsupported instruction semantics".to_owned() },
                    ));
                }
            } else {
                for effect in &insn.effects {
                    match effect {
                        Effect::IndirectBranch { target } => statement
                            .observations
                            .push(Expression::IndirectBranch { target: Box::new(expression(target, state, 0)?) }),
                        Effect::MemoryLoad { destination: target, address, bits, result_bits, signed } => {
                            let load = load(address, state, *bits)?;
                            let widths = (*bits, *result_bits, *signed);
                            define_load(&mut statement, &mut definitions, state, target, load, widths)?;
                        }
                        Effect::MemoryLoadPair { destinations, addresses, bits, result_bits, signed } => {
                            // Resolve both addresses before either destination changes the register state.
                            let loads = [load(&addresses[0], state, *bits)?, load(&addresses[1], state, *bits)?];
                            let widths = (*bits, *result_bits, *signed);
                            for (target, load) in destinations.iter().zip(loads) {
                                define_load(&mut statement, &mut definitions, state, target, load, widths)?;
                            }
                        }
                        Effect::MemoryStore { address, value, bits } => {
                            let value = Expression::Store {
                                memory: state[MEMORY],
                                address: Box::new(expression(address, state, 0)?),
                                value: Box::new(Expression::Binary {
                                    operation: Operation::And,
                                    left: Box::new(expression(value, state, 0)?),
                                    right: Box::new(Expression::Constant {
                                        value: if *bits == 64 { u64::MAX } else { (1u64 << bits) - 1 },
                                    }),
                                    bits: 64,
                                }),
                                bits: *bits,
                            };
                            statement.definitions.push(define(&mut definitions, state, MEMORY, value));
                        }
                        Effect::Return { target } => statement.observations.push(Expression::Return {
                            target: Box::new(expression(target, state, 0)?),
                            integer_values: [state[0], state[1]],
                            memory: state[MEMORY],
                        }),
                        Effect::Select { destination: target, condition, when_true, when_false } => {
                            let value = narrow(
                                Expression::Select {
                                    flags: state[FLAGS],
                                    condition: *condition,
                                    when_true: Box::new(expression(when_true, state, 0)?),
                                    when_false: Box::new(expression(when_false, state, 0)?),
                                },
                                insn.bits,
                            );
                            if matches!(target, Value::Constant { value: 0 }) {
                                statement.observations.push(value);
                            } else {
                                let index = destination(target).ok_or("IR select destination is not writable")?;
                                statement.definitions.push(define(&mut definitions, state, index, value));
                            }
                        }
                        Effect::Assign { destination: target, value } => {
                            let value = narrow(expression(value, state, 0)?, insn.bits);
                            let index = destination(target).ok_or("IR assignment destination is not writable")?;
                            statement.definitions.push(define(&mut definitions, state, index, value));
                        }
                        Effect::Load { destination: target, address } => {
                            let value = Expression::Load {
                                memory: state[MEMORY],
                                address: Box::new(expression(address, state, 0)?),
                                bits: insn.bits,
                            };
                            let index = destination(target).ok_or("IR load destination is not writable")?;
                            statement.definitions.push(define(
                                &mut definitions,
                                state,
                                index,
                                narrow(value, insn.bits),
                            ));
                        }
                        Effect::Store { address, value } => {
                            let value = Expression::Store {
                                memory: state[MEMORY],
                                address: Box::new(expression(address, state, 0)?),
                                value: Box::new(narrow(expression(value, state, 0)?, insn.bits)),
                                bits: insn.bits,
                            };
                            statement.definitions.push(define(&mut definitions, state, MEMORY, value));
                        }
                        Effect::Discard { value } => {
                            statement.observations.push(narrow(expression(value, state, 0)?, insn.bits));
                        }
                        Effect::LoadDiscard { address } => statement.observations.push(Expression::Load {
                            memory: state[MEMORY],
                            address: Box::new(expression(address, state, 0)?),
                            bits: insn.bits,
                        }),
                        Effect::ConditionalControl { value, nonzero, bit } => {
                            if bit.is_some_and(|bit| bit >= insn.bits) {
                                return Err("conditional-control bit exceeds register width".to_owned());
                            }
                            statement.observations.push(Expression::Condition {
                                value: Box::new(narrow(expression(value, state, 0)?, insn.bits)),
                                nonzero: *nonzero,
                                bit: *bit,
                            });
                        }
                        Effect::Control { inputs } => {
                            for value in inputs {
                                statement.observations.push(narrow(expression(value, state, 0)?, insn.bits));
                            }
                        }
                        Effect::Barrier { .. } => unreachable!(),
                        Effect::SetFlags { operation, left, right } => {
                            let value = Expression::Flags {
                                operation: *operation,
                                bits: insn.bits,
                                left: Box::new(expression(left, state, 0)?),
                                right: Box::new(expression(right, state, 0)?),
                            };
                            statement.definitions.push(define(&mut definitions, state, FLAGS, value));
                        }
                        Effect::CarryArithmetic { destination: target, left, right, subtract, set_flags } => {
                            let flags = state[FLAGS];
                            let (left, right) = (expression(left, state, 0)?, expression(right, state, 0)?);
                            if *set_flags {
                                let value = carry_flags(flags, left.clone(), right.clone(), *subtract, insn.bits);
                                statement.definitions.push(define(&mut definitions, state, FLAGS, value));
                            }
                            let value = narrow(carry_result(flags, left, right, *subtract), insn.bits);
                            if matches!(target, Value::Constant { value: 0 }) {
                                statement.observations.push(value);
                            } else {
                                let index = destination(target).ok_or("IR carry destination is not writable")?;
                                statement.definitions.push(define(&mut definitions, state, index, value));
                            }
                        }
                        Effect::ConditionalFlags { condition, operation, left, right, nzcv } => {
                            let value = Expression::Select {
                                flags: state[FLAGS],
                                condition: *condition,
                                when_true: Box::new(Expression::Flags {
                                    operation: *operation,
                                    bits: insn.bits,
                                    left: Box::new(expression(left, state, 0)?),
                                    right: Box::new(expression(right, state, 0)?),
                                }),
                                when_false: Box::new(Expression::Constant { value: u64::from(*nzcv) }),
                            };
                            statement.definitions.push(define(&mut definitions, state, FLAGS, value));
                        }
                        Effect::FlagsConditional { condition } => statement
                            .observations
                            .push(Expression::FlagsCondition { flags: state[FLAGS], condition: *condition }),
                        Effect::Call { target, return_address } => {
                            statement.observations.push(Expression::Call {
                                target: Box::new(expression(target, state, 0)?),
                                arguments: state[..8].to_vec(),
                                memory: state[MEMORY],
                                return_address: *return_address,
                                result_buffer: state[8],
                                stack_pointer: state[31],
                            });
                            for index in (0..19).chain([30, MEMORY, FLAGS]) {
                                let value = Expression::Unknown { reason: "AAPCS64 call clobber".to_owned() };
                                statement.definitions.push(define(&mut definitions, state, index, value));
                            }
                        }
                    }
                }
            }
            block.statements.push(statement);
        }
        blocks.push(block);
    }
    for (block, state) in parameters.iter().enumerate().filter(|(block, _)| reachable[*block]) {
        for index in 0..VARIABLES {
            let mut inputs: Vec<_> = predecessors[block]
                .iter()
                .copied()
                .filter(|&from| reachable[from])
                .map(|from| PhiInput { predecessor: Some(from), definition: outgoing[from][index] })
                .collect();
            if block == entry {
                inputs.insert(0, PhiInput { predecessor: None, definition: initial[index] });
            }
            definitions[state[index]].expression = Expression::Phi { inputs };
        }
    }
    // Keep phi nodes on demand: unused register parameters need not fill the serialized graph.
    let mut live = vec![false; definitions.len()];
    let mut work = Vec::new();
    for statement in blocks.iter().flat_map(|block| &block.statements) {
        work.extend(&statement.definitions);
        for observation in &statement.observations {
            references(observation, &mut work);
        }
    }
    while let Some(id) = work.pop() {
        if !std::mem::replace(&mut live[id], true) {
            references(&definitions[id].expression, &mut work);
        }
    }
    let mut remap = vec![0; definitions.len()];
    let mut count = 0;
    for (id, &needed) in live.iter().enumerate() {
        if needed {
            remap[id] = count;
            count += 1;
        }
    }
    for (index, block) in blocks.iter_mut().enumerate().filter(|(_, block)| block.reachable) {
        block.phis = parameters[index].iter().copied().filter(|&id| live[id]).map(|id| remap[id]).collect();
        for statement in &mut block.statements {
            for id in &mut statement.definitions {
                *id = remap[*id];
            }
            for observation in &mut statement.observations {
                rewrite(observation, &remap);
            }
        }
    }
    let definitions = definitions
        .into_iter()
        .filter(|definition| live[definition.id])
        .map(|mut definition| {
            definition.id = remap[definition.id];
            rewrite(&mut definition.expression, &remap);
            definition
        })
        .collect();
    let mut ssa = Ssa {
        entry,
        blocks,
        definitions,
        limitations: vec![
            "Register and memory SSA only; block parameters may include redundant phi nodes.".to_owned(),
            "Unsupported semantics invalidate all registers and memory; no general alias analysis or decompilation."
                .to_owned(),
            "Exact-width entry-SP spills alias only finite SSA values agreed across acyclic paths; \
             original memory reads are retained. Proofs stop at 64 levels, 64 stores, \
             200,000 visits and the value-node budget, without iterative pointer recovery."
                .to_owned(),
            "32-bit results are low-32-bit values zero-extended into architectural registers.".to_owned(),
        ],
    };
    recover_stack_spills(&mut ssa);
    Ok(ssa)
}

struct SpillProof<'a> {
    definitions: &'a [Definition],
    constants: &'a [crate::dataflow::Known],
    visiting: BTreeSet<usize>,
    remaining: &'a mut usize,
}

impl SpillProof<'_> {
    fn visit(&mut self, depth: usize) -> Option<()> {
        if depth > 64 || *self.remaining == 0 {
            return None;
        }
        *self.remaining -= 1;
        Some(())
    }

    fn address(&mut self, value: &Expression, depth: usize) -> Option<crate::dataflow::Known> {
        use crate::dataflow::Known::{Constant, Stack};
        self.visit(depth)?;
        match value {
            Expression::Constant { value } => Some(Constant(*value)),
            Expression::Reference { definition: id } => {
                if !self.visiting.insert(*id) {
                    return None;
                }
                let definition = &self.definitions[*id];
                let result = if definition.variable == Variable::StackPointer
                    && matches!(definition.expression, Expression::Input)
                {
                    Some(Stack(0))
                } else {
                    self.address(&definition.expression, depth + 1)
                };
                self.visiting.remove(id);
                result
            }
            Expression::Phi { inputs } if !inputs.is_empty() => {
                let mut agreed = None;
                for input in inputs {
                    let value = self.address(&Expression::Reference { definition: input.definition }, depth + 1)?;
                    if agreed.is_some_and(|existing| existing != value) {
                        return None;
                    }
                    agreed = Some(value);
                }
                agreed
            }
            Expression::Add { left, right } | Expression::Subtract { left, right } => {
                let subtract = matches!(value, Expression::Subtract { .. });
                match (self.address(left, depth + 1)?, self.address(right, depth + 1)?) {
                    (Constant(a), Constant(b)) => {
                        Some(Constant(if subtract { a.wrapping_sub(b) } else { a.wrapping_add(b) }))
                    }
                    (Stack(a), Constant(b)) => {
                        if subtract { a.checked_sub(b as i64) } else { a.checked_add(b as i64) }.map(Stack)
                    }
                    (Constant(a), Stack(b)) if !subtract => b.checked_add(a as i64).map(Stack),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn finite_value(&mut self, value: &Expression, depth: usize) -> Option<()> {
        self.visit(depth)?;
        match value {
            Expression::Input | Expression::Constant { .. } => Some(()),
            Expression::Reference { definition } => self.value_alias(*definition, depth + 1).map(|_| ()),
            Expression::Add { left, right }
            | Expression::Subtract { left, right }
            | Expression::Binary { left, right, .. }
            | Expression::Flags { left, right, .. } => {
                self.finite_value(left, depth + 1)?;
                self.finite_value(right, depth + 1)
            }
            Expression::Low32 { value } | Expression::Extend { value, .. } | Expression::Unary { value, .. } => {
                self.finite_value(value, depth + 1)
            }
            Expression::Select { flags, when_true, when_false, .. } => {
                self.value_alias(*flags, depth + 1)?;
                self.finite_value(when_true, depth + 1)?;
                self.finite_value(when_false, depth + 1)
            }
            _ => None,
        }
    }

    fn value_alias(&mut self, id: usize, depth: usize) -> Option<usize> {
        self.visit(depth)?;
        if !self.visiting.insert(id) {
            return None;
        }
        let result = match &self.definitions[id].expression {
            Expression::Reference { definition } => self.value_alias(*definition, depth + 1),
            Expression::Phi { inputs } if !inputs.is_empty() => {
                let mut agreed = None;
                let mut different = false;
                for input in inputs {
                    let Some(value) = self.value_alias(input.definition, depth + 1) else {
                        self.visiting.remove(&id);
                        return None;
                    };
                    different |= agreed.is_some_and(|existing| existing != value);
                    agreed = Some(value);
                }
                if different { Some(id) } else { agreed }
            }
            value => self.finite_value(value, depth + 1).map(|_| id),
        };
        self.visiting.remove(&id);
        result
    }

    fn stored_alias(&mut self, value: &Expression, bits: u8, depth: usize) -> Option<usize> {
        self.visit(depth)?;
        match value {
            Expression::Reference { definition } => {
                let id = self.value_alias(*definition, depth + 1)?;
                if matches!(self.constants[id], crate::dataflow::Known::Constant(_)) { None } else { Some(id) }
            }
            Expression::Low32 { value } if bits <= 32 => self.stored_alias(value, bits, depth + 1),
            Expression::Binary { operation: Operation::And, left, right, bits: 64 }
                if matches!(right.as_ref(), Expression::Constant { value }
                    if *value == if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }) =>
            {
                self.stored_alias(left, bits, depth + 1)
            }
            _ => None,
        }
    }

    fn reaching_value(
        &mut self,
        memory: usize,
        offset: i64,
        bits: u8,
        stores: &mut BTreeSet<usize>,
        depth: usize,
    ) -> Option<usize> {
        self.visit(depth)?;
        if !self.visiting.insert(memory) {
            return None;
        }
        let result = if self.definitions[memory].variable != Variable::Memory {
            None
        } else {
            match &self.definitions[memory].expression {
                Expression::Reference { definition } => {
                    self.reaching_value(*definition, offset, bits, stores, depth + 1)
                }
                Expression::Store { memory: previous, address, value, bits: written_bits } => {
                    match self.address(address, depth + 1) {
                        Some(crate::dataflow::Known::Stack(written))
                            if written.checked_add(i64::from(written_bits / 8)).is_some() =>
                        {
                            if written == offset && *written_bits == bits {
                                stores.insert(memory);
                                if stores.len() > 64 { None } else { self.stored_alias(value, bits, depth + 1) }
                            } else if written + i64::from(written_bits / 8) <= offset
                                || offset + i64::from(bits / 8) <= written
                            {
                                self.reaching_value(*previous, offset, bits, stores, depth + 1)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                }
                Expression::Phi { inputs } if !inputs.is_empty() => {
                    let mut agreed = None;
                    for input in inputs {
                        let Some(value) = self.reaching_value(input.definition, offset, bits, stores, depth + 1) else {
                            self.visiting.remove(&memory);
                            return None;
                        };
                        if agreed.is_some_and(|existing| existing != value) {
                            self.visiting.remove(&memory);
                            return None;
                        }
                        agreed = Some(value);
                    }
                    agreed
                }
                _ => None,
            }
        };
        self.visiting.remove(&memory);
        result
    }
}

fn spill_load(value: &Expression) -> Option<(usize, &Expression, u8)> {
    match value {
        Expression::Load { memory, address, bits } => Some((*memory, address, *bits)),
        Expression::Extend { value, .. } | Expression::Low32 { value } => spill_load(value),
        _ => None,
    }
}

fn replace_spill_load(value: &mut Expression, definition: usize, bits: u8) -> Expression {
    match value {
        Expression::Extend { value, .. } | Expression::Low32 { value } => replace_spill_load(value, definition, bits),
        _ => {
            let reference = Expression::Reference { definition };
            let replacement = if bits == 64 {
                reference
            } else {
                Expression::Extend { value: Box::new(reference), from_bits: bits, to_bits: 64, signed: false }
            };
            std::mem::replace(value, replacement)
        }
    }
}

fn recover_stack_spills(ssa: &mut Ssa) {
    if !ssa.definitions.iter().any(|definition| spill_load(&definition.expression).is_some()) {
        return;
    }
    let constants =
        crate::dataflow::solve(ssa, &vec![None; ssa.definitions.len()], &vec![false; ssa.definitions.len()]);
    let mut nodes = 0;
    let mut expressions: Vec<_> = ssa.definitions.iter().map(|definition| &definition.expression).collect();
    expressions
        .extend(ssa.blocks.iter().flat_map(|block| &block.statements).flat_map(|statement| &statement.observations));
    while let Some(value) = expressions.pop() {
        nodes += 1;
        match value {
            Expression::Phi { inputs } => nodes += inputs.len(),
            Expression::Add { left, right }
            | Expression::Subtract { left, right }
            | Expression::Binary { left, right, .. }
            | Expression::Flags { left, right, .. } => expressions.extend([left.as_ref(), right.as_ref()]),
            Expression::Select { when_true, when_false, .. } => {
                expressions.extend([when_true.as_ref(), when_false.as_ref()]);
            }
            Expression::Store { address, value, .. } => expressions.extend([address.as_ref(), value.as_ref()]),
            Expression::Load { address, .. } => expressions.push(address),
            Expression::Low32 { value }
            | Expression::Extend { value, .. }
            | Expression::Unary { value, .. }
            | Expression::Condition { value, .. } => expressions.push(value),
            Expression::IndirectBranch { target }
            | Expression::Return { target, .. }
            | Expression::Call { target, .. } => expressions.push(target),
            _ => {}
        }
    }
    let mut spare_nodes = MAX_VALUE_NODES.saturating_sub(nodes);
    let mut remaining = 200_000;
    let mut recovered = vec![None; ssa.definitions.len()];
    for definition in &ssa.definitions {
        let Some((memory, address, bits)) = spill_load(&definition.expression) else { continue };
        let added = if bits == 64 { 1 } else { 2 };
        if spare_nodes < added {
            continue;
        }
        let mut proof = SpillProof {
            definitions: &ssa.definitions,
            constants: &constants,
            visiting: BTreeSet::new(),
            remaining: &mut remaining,
        };
        let Some(crate::dataflow::Known::Stack(offset)) = proof.address(address, 0) else { continue };
        if offset.checked_add(i64::from(bits / 8)).is_none() {
            continue;
        }
        if let Some(source) = proof.reaching_value(memory, offset, bits, &mut BTreeSet::new(), 0) {
            spare_nodes -= added;
            recovered[definition.id] = Some((source, bits));
        }
    }
    // Prove against the original graph: recovered pointers cannot start another memory-inference chain.
    for statement in ssa.blocks.iter_mut().flat_map(|block| &mut block.statements) {
        for &id in &statement.definitions {
            if let Some((source, bits)) = recovered[id] {
                let access = replace_spill_load(&mut ssa.definitions[id].expression, source, bits);
                statement.recovered_loads.push(id);
                statement.observations.push(access);
            }
        }
    }
}

pub(crate) fn recovered_load_definitions(ssa: &Ssa) -> Result<Vec<bool>, String> {
    let mut recovered = vec![false; ssa.definitions.len()];
    let mut owners = vec![0; ssa.definitions.len()];
    for (index, statement) in ssa.blocks.iter().flat_map(|block| &block.statements).enumerate() {
        for &id in &statement.definitions {
            *owners.get_mut(id).ok_or("invalid recovered-load definition owner")? = index + 1;
        }
        let accesses = statement.observations.iter().filter(|value| matches!(value, Expression::Load { .. })).count();
        if statement.recovered_loads.len() > accesses {
            return Err("recovered loads require retained memory-access observations".to_owned());
        }
        let retained_start = statement.observations.len() - statement.recovered_loads.len();
        let recovered_ids: BTreeSet<_> = statement.recovered_loads.iter().copied().collect();
        if statement.observations[retained_start..].iter().any(|value| !matches!(value, Expression::Load { .. }))
            || statement
                .definitions
                .iter()
                .filter(|id| recovered_ids.contains(*id))
                .copied()
                .ne(statement.recovered_loads.iter().copied())
        {
            return Err("recovered loads require ordered definitions and a retained-load observation suffix".to_owned());
        }
        for &id in &statement.recovered_loads {
            if owners.get(id) != Some(&(index + 1))
                || std::mem::replace(recovered.get_mut(id).ok_or("invalid recovered-load definition")?, true)
            {
                return Err("recovered load must uniquely name a definition owned by its statement".to_owned());
            }
            let mut value = &ssa.definitions[id].expression;
            while let Expression::Extend { value: inner, .. } | Expression::Low32 { value: inner } = value {
                value = inner;
            }
            if !matches!(value, Expression::Reference { .. }) {
                return Err("recovered load must alias an SSA value".to_owned());
            }
        }
    }
    Ok(recovered)
}

fn rewrite(value: &mut Expression, remap: &[usize]) {
    match value {
        Expression::IndirectBranch { target } => rewrite(target, remap),
        Expression::Return { target, integer_values, memory } => {
            rewrite(target, remap);
            for value in integer_values {
                *value = remap[*value];
            }
            *memory = remap[*memory];
        }
        Expression::Select { flags, when_true, when_false, .. } => {
            *flags = remap[*flags];
            rewrite(when_true, remap);
            rewrite(when_false, remap);
        }
        Expression::Reference { definition } => *definition = remap[*definition],
        Expression::Add { left, right }
        | Expression::Subtract { left, right }
        | Expression::Binary { left, right, .. }
        | Expression::Flags { left, right, .. } => {
            rewrite(left, remap);
            rewrite(right, remap);
        }
        Expression::Low32 { value }
        | Expression::Condition { value, .. }
        | Expression::Extend { value, .. }
        | Expression::Unary { value, .. } => rewrite(value, remap),
        Expression::FlagsCondition { flags, .. } => *flags = remap[*flags],
        Expression::Call { target, arguments, memory, result_buffer, stack_pointer, .. } => {
            rewrite(target, remap);
            for argument in arguments {
                *argument = remap[*argument];
            }
            *memory = remap[*memory];
            *result_buffer = remap[*result_buffer];
            *stack_pointer = remap[*stack_pointer];
        }
        Expression::Phi { inputs } => {
            for input in inputs {
                input.definition = remap[input.definition];
            }
        }
        Expression::Load { memory, address, .. } => {
            *memory = remap[*memory];
            rewrite(address, remap);
        }
        Expression::Store { memory, address, value, .. } => {
            *memory = remap[*memory];
            rewrite(address, remap);
            rewrite(value, remap);
        }
        _ => {}
    }
}

fn representative(aliases: &mut [usize], id: usize) -> usize {
    let mut root = id;
    while aliases[root] != root {
        root = aliases[root];
    }
    let mut at = id;
    while aliases[at] != at {
        let next = aliases[at];
        aliases[at] = root;
        at = next;
    }
    root
}

/// Removes phi aliases without substituting expression trees or merging distinct predecessor values.
pub fn simplify(ssa: &mut Ssa) -> Result<usize, String> {
    crate::pseudocode::validate(ssa, &[])?;
    recovered_load_definitions(ssa)?;
    let count = ssa.definitions.len();
    let mut aliases: Vec<_> = (0..count).collect();
    let mut users = vec![Vec::new(); count];
    let mut statement_owned = vec![false; count];
    for statement in ssa.blocks.iter().flat_map(|block| &block.statements) {
        for &id in &statement.definitions {
            statement_owned[id] = true;
        }
    }
    for definition in &ssa.definitions {
        if let Expression::Phi { inputs } = &definition.expression {
            for input in inputs {
                users[input.definition].push(definition.id);
            }
        }
    }
    let mut queue: VecDeque<_> = ssa
        .definitions
        .iter()
        .filter(|definition| !statement_owned[definition.id] && matches!(definition.expression, Expression::Phi { .. }))
        .map(|definition| definition.id)
        .collect();
    let mut queued = vec![false; count];
    for &id in &queue {
        queued[id] = true;
    }
    let mut removed = 0;
    while let Some(id) = queue.pop_front() {
        queued[id] = false;
        if aliases[id] != id || statement_owned[id] {
            continue;
        }
        let Expression::Phi { inputs } = &ssa.definitions[id].expression else { continue };
        let mut candidate = None;
        let mut conflict = false;
        for input in inputs {
            let value = representative(&mut aliases, input.definition);
            if value == id {
                continue;
            }
            if candidate.is_some_and(|candidate| candidate != value) {
                conflict = true;
                break;
            }
            candidate = Some(value);
        }
        let Some(target) = candidate else { continue };
        if conflict || ssa.definitions[id].variable != ssa.definitions[target].variable {
            continue;
        }
        aliases[id] = target;
        removed += 1;
        let mut affected = std::mem::take(&mut users[id]);
        affected.retain(|&user| aliases[user] == user && !statement_owned[user]);
        affected.sort_unstable();
        affected.dedup();
        for &user in &affected {
            if !queued[user] {
                queued[user] = true;
                queue.push_back(user);
            }
        }
        users[target].extend(affected);
    }
    if removed == 0 {
        return Ok(0);
    }
    for id in 0..count {
        representative(&mut aliases, id);
    }
    let mut compact = vec![0; count];
    let mut next = 0;
    for (id, &root) in aliases.iter().enumerate() {
        if id == root {
            compact[id] = next;
            next += 1;
        }
    }
    let remap: Vec<_> = aliases.iter().map(|&root| compact[root]).collect();
    for block in &mut ssa.blocks {
        block.phis.retain(|&id| aliases[id] == id);
        for id in &mut block.phis {
            *id = remap[*id];
        }
        for statement in &mut block.statements {
            for id in &mut statement.definitions {
                *id = remap[*id];
            }
            for id in &mut statement.recovered_loads {
                *id = remap[*id];
            }
            for observation in &mut statement.observations {
                rewrite(observation, &remap);
            }
        }
    }
    ssa.definitions.retain(|definition| aliases[definition.id] == definition.id);
    for definition in &mut ssa.definitions {
        definition.id = remap[definition.id];
        rewrite(&mut definition.expression, &remap);
    }
    Ok(removed)
}
