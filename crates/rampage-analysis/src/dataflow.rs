use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::ir;
use serde::Serialize;

use crate::ssa::{Expression, Ssa, Variable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Known {
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
    pub incomplete_instructions: usize,
    pub limitations: Vec<String>,
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

fn evaluate(expr: &Expression, values: &[Known]) -> Known {
    use Known::*;
    match expr {
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
        Expression::Flags { operation, left, right, bits } => match (evaluate(left, values), evaluate(right, values)) {
            (Constant(a), Constant(b)) => ir::flags(*operation, a, b, *bits).map_or(Unknown, Constant),
            (Pending, _) | (_, Pending) => Pending,
            _ => Unknown,
        },
        _ => Unknown,
    }
}

pub fn analyze(ssa: &Ssa) -> Result<DataFlow, String> {
    crate::pseudocode::validate(ssa, &[])?;
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
        let next = if matches!(definition.expression, Expression::Input) {
            if definition.variable == Variable::StackPointer { Known::Stack(0) } else { Known::Unknown }
        } else {
            evaluate(&definition.expression, &values)
        };
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
            if let Expression::Low32 { value } = expression {
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
            "Loads are not constant-folded; stack offsets require agreement at joins and may be unknown.".to_owned(),
            "Conflicting values and unsupported semantics remain unknown; no pointer alias analysis.".to_owned(),
        ],
    })
}
