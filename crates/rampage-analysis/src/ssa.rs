use std::collections::VecDeque;

use rampage_arch::Flow;
use rampage_arch::ir::{Effect, FlagOperation, LiftedInstruction, Operation, Value};
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
    pub observations: Vec<Expression>,
    pub barrier: bool,
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

fn narrow(value: Expression, bits: u8) -> Expression {
    if bits == 32 { Expression::Low32 { value: Box::new(value) } } else { value }
}

fn define(definitions: &mut Vec<Definition>, state: &mut [usize; VARIABLES], index: usize, value: Expression) -> usize {
    let id = definitions.len();
    definitions.push(Definition { id, variable: variable(index), expression: value });
    state[index] = id;
    id
}

pub(crate) fn references(value: &Expression, out: &mut Vec<usize>) {
    match value {
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
        Expression::Low32 { value } | Expression::Condition { value, .. } | Expression::Extend { value, .. } => {
            references(value, out)
        }
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
                Value::Low32 { value } => stack.push((value, depth + 1)),
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
                Effect::MemoryLoad { destination, address, bits, result_bits, signed } => {
                    if rampage_arch::ir::extend(0, *bits, *result_bits, *signed).is_none() {
                        return Err("invalid memory load widths".to_owned());
                    }
                    if !barrier && !matches!(destination, Value::Constant { value: 0 }) {
                        definitions += 1;
                    }
                    validate_values(&[destination, address], &mut nodes)?;
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
                observations: Vec::new(),
                barrier: !insn.complete
                    || matches!(insn.flow, Flow::Invalid)
                    || matches!(insn.flow, Flow::Call(_) | Flow::IndirectCall)
                        && !insn.effects.iter().any(|effect| matches!(effect, Effect::Call { .. }))
                    || insn.effects.iter().any(|effect| matches!(effect, Effect::Barrier { .. })),
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
                        Effect::MemoryLoad { destination: target, address, bits, result_bits, signed } => {
                            let load = Expression::Load {
                                memory: state[MEMORY],
                                address: Box::new(expression(address, state, 0)?),
                                bits: *bits,
                            };
                            if matches!(target, Value::Constant { value: 0 }) {
                                statement.observations.push(load);
                            } else {
                                let index = destination(target).ok_or("memory load destination is not writable")?;
                                let value = Expression::Extend {
                                    value: Box::new(load),
                                    from_bits: *bits,
                                    to_bits: *result_bits,
                                    signed: *signed,
                                };
                                statement.definitions.push(define(&mut definitions, state, index, value));
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
    Ok(Ssa {
        entry,
        blocks,
        definitions,
        limitations: vec![
            "Register and memory SSA only; block parameters may include redundant phi nodes.".to_owned(),
            "Unsupported semantics invalidate all registers and memory; no alias analysis or decompilation.".to_owned(),
            "32-bit results are low-32-bit values zero-extended into architectural registers.".to_owned(),
        ],
    })
}

fn rewrite(value: &mut Expression, remap: &[usize]) {
    match value {
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
        Expression::Low32 { value } | Expression::Condition { value, .. } | Expression::Extend { value, .. } => {
            rewrite(value, remap)
        }
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
