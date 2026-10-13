use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::ir;
use serde::Serialize;

use crate::ssa::{Expression, Ssa, Variable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    Pending,
    Constant(u64),
    Stack(i64),
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct DataFlow {
    pub constants: Vec<Constant>,
    pub stack_slots: Vec<StackSlot>,
    pub argument_registers: Vec<u8>,
    pub integer_returns: Vec<IntegerReturn>,
    pub forwarded_loads: Vec<ForwardedLoad>,
    pub indirect_targets: Vec<IndirectTarget>,
    pub incomplete_instructions: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IndirectTarget {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub target: u64,
    pub call: bool,
    pub input_definitions: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct ForwardedLoad {
    pub definition: usize,
    pub store_definitions: Vec<usize>,
    pub bits: u8,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct IntegerReturn {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub definitions: [usize; 2],
    pub constant_values: [Option<String>; 2],
}

#[derive(Debug, Serialize)]
pub struct Constant {
    pub definition: usize,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct StackSlot {
    pub offset: i64,
    pub bits: u8,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub reads: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub writes: Vec<u64>,
}

fn merge(left: Known, right: Known) -> Known {
    match (left, right) {
        (Known::Pending, value) | (value, Known::Pending) => value,
        (a, b) if a == b => a,
        _ => Known::Unknown,
    }
}

pub(crate) fn evaluate(expr: &Expression, values: &[Known]) -> Known {
    use Known::*;
    match expr {
        Expression::Extend { value, from_bits, to_bits, signed } => match evaluate(value, values) {
            Constant(value) => ir::extend(value, *from_bits, *to_bits, *signed).map_or(Unknown, Constant),
            Pending => Pending,
            _ => Unknown,
        },
        Expression::Select { flags: _, condition, when_true, when_false: _ } if *condition >= 14 => {
            evaluate(when_true, values)
        }
        Expression::Select { flags, condition, when_true, when_false } => match values[*flags] {
            Pending => Pending,
            Constant(flags) => match ir::condition(flags, *condition) {
                Some(true) => evaluate(when_true, values),
                Some(false) => evaluate(when_false, values),
                _ => Unknown,
            },
            _ => merge(evaluate(when_true, values), evaluate(when_false, values)),
        },
        Expression::Reference { definition } => values[*definition],
        Expression::Constant { value } => Constant(*value),
        Expression::Phi { inputs } => {
            inputs.iter().fold(Pending, |value, input| merge(value, values[input.definition]))
        }
        Expression::Low32 { value } => match evaluate(value, values) {
            Constant(value) => Constant(value & 0xffff_ffff),
            Pending => Pending,
            _ => Unknown,
        },
        Expression::Add { left, right } | Expression::Subtract { left, right } => {
            let sub = matches!(expr, Expression::Subtract { .. });
            match (evaluate(left, values), evaluate(right, values)) {
                (Pending, _) | (_, Pending) => Pending,
                (Constant(a), Constant(b)) => Constant(if sub { a.wrapping_sub(b) } else { a.wrapping_add(b) }),
                (Stack(a), Constant(b)) => {
                    if sub { a.checked_sub(b as i64) } else { a.checked_add(b as i64) }.map_or(Unknown, Stack)
                }
                (Constant(a), Stack(b)) if !sub => b.checked_add(a as i64).map_or(Unknown, Stack),
                _ => Unknown,
            }
        }
        Expression::Binary { operation, left, right, bits } => {
            match (evaluate(left, values), evaluate(right, values)) {
                (Constant(a), Constant(b)) => ir::binary(*operation, a, b, *bits).map_or(Unknown, Constant),
                (Pending, _) | (_, Pending) => Pending,
                _ => Unknown,
            }
        }
        Expression::Unary { operation, value, bits } => match evaluate(value, values) {
            Constant(value) => ir::unary(*operation, value, *bits).map_or(Unknown, Constant),
            Pending => Pending,
            _ => Unknown,
        },
        Expression::Flags { operation, left, right, bits } => match (evaluate(left, values), evaluate(right, values)) {
            (Constant(a), Constant(b)) => ir::flags(*operation, a, b, *bits).map_or(Unknown, Constant),
            (Pending, _) | (_, Pending) => Pending,
            _ => Unknown,
        },
        _ => Unknown,
    }
}

fn load(expr: &Expression) -> Option<(&Expression, usize, &Expression, u8)> {
    match expr {
        Expression::Load { memory, address, bits } => Some((expr, *memory, address, *bits)),
        Expression::Extend { value, .. } | Expression::Low32 { value } => load(value),
        _ => None,
    }
}

fn loaded(expr: &Expression, value: u64) -> Known {
    match expr {
        Expression::Load { .. } => Known::Constant(value),
        Expression::Low32 { value: inner } => match loaded(inner, value) {
            Known::Constant(value) => Known::Constant(value & 0xffff_ffff),
            _ => Known::Unknown,
        },
        Expression::Extend { value: inner, from_bits, to_bits, signed } => match loaded(inner, value) {
            Known::Constant(value) => {
                ir::extend(value, *from_bits, *to_bits, *signed).map_or(Known::Unknown, Known::Constant)
            }
            _ => Known::Unknown,
        },
        _ => Known::Unknown,
    }
}

pub(crate) fn solve(ssa: &Ssa, forwarded: &[Option<u64>], recovered: &[bool]) -> Vec<Known> {
    let mut values = vec![Known::Pending; ssa.definitions.len()];
    let mut users = vec![Vec::new(); values.len()];
    for definition in &ssa.definitions {
        let mut refs = Vec::new();
        crate::ssa::references(&definition.expression, &mut refs);
        for id in refs {
            users[id].push(definition.id);
        }
    }
    let mut queue: std::collections::VecDeque<_> = (0..values.len()).collect();
    let mut queued = vec![true; values.len()];
    while let Some(id) = queue.pop_front() {
        queued[id] = false;
        let definition = &ssa.definitions[id];
        let next = if let Some(value) = forwarded[id] {
            loaded(&definition.expression, value)
        } else if matches!(definition.expression, Expression::Input) {
            if definition.variable == Variable::StackPointer { Known::Stack(0) } else { Known::Unknown }
        } else {
            evaluate(&definition.expression, &values)
        };
        let next = if recovered[id] && matches!(next, Known::Stack(_)) { Known::Unknown } else { next };
        let next = merge(values[id], next);
        if values[id] != next {
            values[id] = next;
            for &user in &users[id] {
                if !queued[user] {
                    queued[user] = true;
                    queue.push_back(user);
                }
            }
        }
    }
    values
}

pub fn analyze(ssa: &Ssa) -> Result<DataFlow, String> {
    crate::pseudocode::validate(ssa, &[])?;
    let recovered = crate::ssa::recovered_load_definitions(ssa)?;
    let mut forwarded = vec![None; ssa.definitions.len()];
    let mut values = solve(ssa, &forwarded, &recovered);
    let mut remaining = 200_000;
    let mut forwarded_loads = Vec::new();
    for _ in 0..8 {
        let mut changed = false;
        for definition in &ssa.definitions {
            if forwarded[definition.id].is_some() {
                continue;
            }
            let Some((_, memory, address, bits)) = load(&definition.expression) else { continue };
            if let Some(resolution) =
                crate::reaching_store::resolve(ssa, &values, memory, address, bits, &mut remaining)
            {
                forwarded[definition.id] = Some(resolution.value);
                forwarded_loads.push(ForwardedLoad {
                    definition: definition.id,
                    store_definitions: resolution.stores.into_iter().collect(),
                    bits,
                    value: resolution.value,
                });
                changed = true;
            }
        }
        if !changed {
            break;
        }
        values = solve(ssa, &forwarded, &recovered);
    }
    let mut slots: BTreeMap<(i64, u8), StackSlot> = BTreeMap::new();
    let mut accessed = |expr: &Expression, at| {
        let (address, bits, write) = match expr {
            Expression::Load { address, bits, .. } => (address, *bits, false),
            Expression::Store { address, bits, .. } => (address, *bits, true),
            _ => return,
        };
        if let Known::Stack(offset) = evaluate(address, &values) {
            let slot = slots.entry((offset, bits)).or_insert(StackSlot {
                offset,
                bits,
                reads: Vec::new(),
                writes: Vec::new(),
            });
            if write {
                slot.writes.push(at);
            } else {
                slot.reads.push(at);
            }
        }
    };
    for statement in ssa.blocks.iter().flat_map(|block| &block.statements) {
        for &id in &statement.definitions {
            let expression = &ssa.definitions[id].expression;
            accessed(expression, statement.address);
            if let Expression::Low32 { value } | Expression::Extend { value, .. } = expression {
                accessed(value, statement.address);
            }
        }
        for expression in &statement.observations {
            accessed(expression, statement.address);
        }
    }
    let mut arguments = BTreeSet::new();
    let mut work = Vec::new();
    for statement in ssa.blocks.iter().filter(|block| block.reachable).flat_map(|block| &block.statements) {
        work.extend(&statement.definitions);
        for observation in &statement.observations {
            match observation {
                Expression::Return { target, memory, .. } => {
                    crate::ssa::references(target, &mut work);
                    work.push(*memory);
                }
                _ => crate::ssa::references(observation, &mut work),
            }
        }
    }
    let mut visited = vec![false; ssa.definitions.len()];
    while let Some(id) = work.pop() {
        if std::mem::replace(&mut visited[id], true) {
            continue;
        }
        let definition = &ssa.definitions[id];
        if matches!(definition.expression, Expression::Input) {
            if let Variable::Register { number } = definition.variable
                && number < 8
            {
                arguments.insert(number);
            }
        } else {
            crate::ssa::references(&definition.expression, &mut work);
        }
    }
    let integer_returns = ssa
        .blocks
        .iter()
        .filter(|block| block.reachable)
        .flat_map(|block| &block.statements)
        .flat_map(|statement| {
            statement.observations.iter().filter_map(|observation| {
                let Expression::Return { integer_values, .. } = observation else { return None };
                Some(IntegerReturn {
                    address: statement.address,
                    definitions: *integer_values,
                    constant_values: integer_values.map(|id| match values[id] {
                        Known::Constant(value) => Some(format!("{value:#x}")),
                        _ => None,
                    }),
                })
            })
        })
        .collect();
    let mut indirect_targets = Vec::new();
    for statement in ssa.blocks.iter().filter(|block| block.reachable).flat_map(|block| &block.statements) {
        if statement.barrier {
            continue;
        }
        let (input, call) = match statement.flow {
            rampage_arch::Flow::IndirectJump => (
                statement.observations.iter().find_map(|observation| match observation {
                    Expression::IndirectBranch { target } => Some(target.as_ref()),
                    _ => None,
                }),
                false,
            ),
            rampage_arch::Flow::IndirectCall => (
                statement.observations.iter().find_map(|observation| match observation {
                    Expression::Call { target, .. } => Some(target.as_ref()),
                    _ => None,
                }),
                true,
            ),
            _ => continue,
        };
        let Some(input) = input else { continue };
        if let Known::Constant(target) = evaluate(input, &values) {
            let mut input_definitions = Vec::new();
            crate::ssa::references(input, &mut input_definitions);
            input_definitions.sort_unstable();
            input_definitions.dedup();
            indirect_targets.push(IndirectTarget { address: statement.address, target, call, input_definitions });
        }
    }
    Ok(DataFlow {
        constants: values
            .iter()
            .enumerate()
            .filter_map(|(definition, value)| match value {
                Known::Constant(value) => Some(Constant { definition, value: *value }),
                _ => None,
            })
            .collect(),
        stack_slots: slots.into_values().collect(),
        argument_registers: arguments.into_iter().collect(),
        integer_returns,
        forwarded_loads,
        indirect_targets,
        incomplete_instructions: ssa
            .blocks
            .iter()
            .flat_map(|block| &block.statements)
            .filter(|statement| statement.barrier)
            .count(),
        limitations: vec![
            "Argument registers are input-use evidence excluding speculative return candidates, \
             not a recovered signature."
                .to_owned(),
            "X0/X1 at RET are possible integer return values; void, aggregate and FP/SIMD signatures remain unknown."
                .to_owned(),
            "Constant memory forwarding uses only exact-width stores agreed across paths; \
             partial overlaps, calls and unknown aliases stop inference."
                .to_owned(),
            "Recovered nonconstant loads preserve SSA values, not stack-address provenance \
             for further memory inference."
                .to_owned(),
            "Memory forwarding is bounded to eight passes, 200,000 memory visits, \
             64 levels and 64 source stores per load."
                .to_owned(),
            "Conflicting values and unsupported semantics remain unknown; no pointer alias analysis.".to_owned(),
            "Indirect targets are constant-value evidence only; code mapping and alignment require image validation."
                .to_owned(),
        ],
    })
}
