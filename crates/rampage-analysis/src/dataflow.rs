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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_registers: Vec<StackRegisterEvidence>,
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

#[derive(Debug, Serialize)]
pub struct StackRegisterEvidence {
    pub register: u8,
    /// Relative to SP at function entry, independent of native decompiler storage coordinates.
    #[serde(serialize_with = "decimal_offset")]
    pub offset: i64,
    pub bits: u8,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub stores: Vec<u64>,
    /// Load sites; reload_candidate records do not prove restoration of the entry value.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub restores: Vec<u64>,
    pub classification: &'static str,
    pub evidence: Vec<&'static str>,
    pub confidence: &'static str,
}

fn decimal_offset<S: serde::Serializer>(offset: &i64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&offset.to_string())
}

pub(crate) fn entry_register(ssa: &Ssa, expression: &Expression, remaining: &mut usize) -> Option<u8> {
    fn source(ssa: &Ssa, expression: &Expression, remaining: &mut usize, depth: usize) -> Option<u8> {
        if depth > 32 || *remaining == 0 {
            return None;
        }
        *remaining -= 1;
        match expression {
            Expression::Reference { definition } => {
                let definition = ssa.definitions.get(*definition)?;
                if matches!(definition.expression, Expression::Input) {
                    match definition.variable {
                        Variable::Register { number } if number < 31 => Some(number),
                        _ => None,
                    }
                } else {
                    source(ssa, &definition.expression, remaining, depth + 1)
                }
            }
            Expression::Extend { value, from_bits: 64, to_bits: 64, .. } => source(ssa, value, remaining, depth + 1),
            Expression::Binary { operation: ir::Operation::And, left, right, bits: 64 }
                if matches!(right.as_ref(), Expression::Constant { value: u64::MAX }) =>
            {
                source(ssa, left, remaining, depth + 1)
            }
            Expression::Phi { inputs } if !inputs.is_empty() => {
                let mut register = None;
                for input in inputs {
                    let value =
                        source(ssa, &Expression::Reference { definition: input.definition }, remaining, depth + 1)?;
                    if register.is_some_and(|register| register != value) {
                        return None;
                    }
                    register = Some(value);
                }
                register
            }
            _ => None,
        }
    }
    source(ssa, expression, remaining, 0)
}

fn whole_register_load(expression: &Expression) -> Option<(usize, &Expression)> {
    match expression {
        Expression::Load { memory, address, bits: 64 } => Some((*memory, address)),
        Expression::Extend { value, from_bits: 64, to_bits: 64, .. } => whole_register_load(value),
        _ => None,
    }
}

fn register_load<'a>(expression: &'a Expression, retained: Option<&'a Expression>) -> Option<(usize, &'a Expression)> {
    if let Some(load) = whole_register_load(expression) {
        return Some(load);
    }
    let mut value = expression;
    while let Expression::Extend { value: inner, from_bits: 64, to_bits: 64, .. } = value {
        value = inner;
    }
    if !matches!(value, Expression::Reference { .. }) {
        return None;
    }
    whole_register_load(retained?)
}

fn stack_registers(ssa: &Ssa, values: &[Known], remaining: &mut usize) -> Vec<StackRegisterEvidence> {
    let mut evidence: BTreeMap<(u8, i64, &'static str), StackRegisterEvidence> = BTreeMap::new();
    let mut store_addresses = BTreeMap::new();
    for statement in ssa.blocks.iter().filter(|block| block.reachable).flat_map(|block| &block.statements) {
        if statement.barrier {
            continue;
        }
        for &id in &statement.definitions {
            if matches!(ssa.definitions[id].expression, Expression::Store { bits: 64, .. }) {
                store_addresses.entry(id).or_insert_with(BTreeSet::new).insert(statement.address);
            }
        }
    }
    for statement in ssa.blocks.iter().filter(|block| block.reachable).flat_map(|block| &block.statements) {
        if statement.barrier {
            continue;
        }
        let retained_start = statement.observations.len() - statement.recovered_loads.len();
        let mut recovered_loads =
            statement.recovered_loads.iter().copied().zip(&statement.observations[retained_start..]).peekable();
        for &id in &statement.definitions {
            let definition = &ssa.definitions[id];
            let retained = if recovered_loads.peek().is_some_and(|&(definition, _)| definition == id) {
                recovered_loads.next().map(|(_, expression)| expression)
            } else {
                None
            };
            if let Expression::Store { address, value, bits: 64, .. } = &definition.expression {
                let Known::Stack(offset) = evaluate(address, values) else { continue };
                if offset.checked_add(8).is_none() {
                    continue;
                }
                let Some(register) = entry_register(ssa, value, remaining) else { continue };
                evidence
                    .entry((register, offset, "entry_register_store"))
                    .or_insert_with(|| StackRegisterEvidence {
                        register,
                        offset,
                        bits: 64,
                        stores: Vec::new(),
                        restores: Vec::new(),
                        classification: "entry_register_store",
                        evidence: vec!["entry_register_store"],
                        confidence: "ssa_proven",
                    })
                    .stores
                    .push(statement.address);
                continue;
            }
            let Variable::Register { number: register } = definition.variable else { continue };
            let Some((memory, address)) = register_load(&definition.expression, retained) else { continue };
            let Known::Stack(offset) = evaluate(address, values) else { continue };
            if offset.checked_add(8).is_none() {
                continue;
            }
            let stores = crate::reaching_store::resolve_register(ssa, values, memory, offset, register, remaining)
                .filter(|stores| stores.iter().all(|id| store_addresses.contains_key(id)));
            let classification = if stores.is_some() { "matching_register_reload" } else { "reload_candidate" };
            let record = evidence.entry((register, offset, classification)).or_insert_with(|| StackRegisterEvidence {
                register,
                offset,
                bits: 64,
                stores: Vec::new(),
                restores: Vec::new(),
                classification,
                evidence: if stores.is_some() {
                    vec!["entry_register_store", "matching_register_reload"]
                } else {
                    vec!["load_to_register", "entry_register_value_not_proven"]
                },
                confidence: if stores.is_some() { "ssa_proven" } else { "conditional" },
            });
            if let Some(stores) = stores {
                for store in stores {
                    record.stores.extend(&store_addresses[&store]);
                }
            }
            record.restores.push(statement.address);
        }
    }
    for record in evidence.values_mut() {
        record.stores.sort_unstable();
        record.stores.dedup();
        record.restores.sort_unstable();
        record.restores.dedup();
    }
    let matched_stores: Vec<_> = evidence
        .iter()
        .filter(|((_, _, classification), _)| *classification == "matching_register_reload")
        .map(|(&(register, offset, _), record)| {
            (register, offset, record.stores.iter().copied().collect::<BTreeSet<_>>())
        })
        .collect();
    for (register, offset, stores) in matched_stores {
        if let Some(record) = evidence.get_mut(&(register, offset, "entry_register_store")) {
            record.stores.retain(|address| !stores.contains(address));
        }
    }
    evidence.retain(|_, record| !record.stores.is_empty() || !record.restores.is_empty());
    evidence.into_values().collect()
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
    let stack_registers = stack_registers(ssa, &values, &mut remaining);
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
        stack_registers,
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
            "Stack-register offsets are entry-SP-relative, not native storage coordinates. Entry stores and matching \
             reloads are SSA evidence, not proof of ABI callee-save roles or a complete frame; reload_candidate \
             records are conditional loads with no proven entry-value match."
                .to_owned(),
            "Stack-register provenance follows only whole-width copies and agreeing phis for at most 32 levels, \
             sharing the 200,000-visit memory budget; unknown aliases, slot reuse and incomplete semantics \
             stop matches."
                .to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_arch::{
        Flow,
        ir::{Effect, LiftedInstruction, Value},
    };

    #[test]
    fn exhausted_work_budget_keeps_only_conditional_load_evidence() {
        for load_count in [1, 10_000] {
            let effects = (0..load_count)
                .map(|_| Effect::MemoryLoad {
                    address: Value::StackPointer,
                    destination: Value::Register { number: 19 },
                    bits: 64,
                    result_bits: 64,
                    signed: false,
                })
                .collect();
            let instructions = vec![
                LiftedInstruction {
                    address: 0,
                    bits: 64,
                    flow: Flow::Next,
                    complete: true,
                    effects: vec![Effect::MemoryStore {
                        address: Value::StackPointer,
                        value: Value::Register { number: 19 },
                        bits: 64,
                    }],
                },
                LiftedInstruction { address: 4, bits: 64, flow: Flow::Next, complete: true, effects },
            ];
            let ssa = crate::ssa::build(&[crate::ssa::InputBlock { address: 0, instructions }], &[], 0).unwrap();
            assert_eq!(ssa.blocks[0].statements[1].recovered_loads.len(), load_count);
            crate::pseudocode::validate(&ssa, &[]).unwrap();
            let recovered = crate::ssa::recovered_load_definitions(&ssa).unwrap();
            let values = solve(&ssa, &vec![None; ssa.definitions.len()], &recovered);
            let mut remaining = 0;
            let records = stack_registers(&ssa, &values, &mut remaining);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].classification, "reload_candidate");
            assert_eq!(records[0].confidence, "conditional");
            assert!(records[0].stores.is_empty());
            assert_eq!(records[0].restores, [4]);
            assert_eq!(remaining, 0);
        }
    }
}
