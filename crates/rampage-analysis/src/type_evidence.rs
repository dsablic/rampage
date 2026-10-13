use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::ssa::{Expression, Ssa};

#[derive(Debug, Serialize)]
pub struct TypeEvidence {
    pub definitions: Vec<DefinitionUses>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct DefinitionUses {
    pub definition: usize,
    pub integer_widths: BTreeSet<u8>,
    pub address_operand: bool,
    pub code_target: bool,
    pub signed_operand: bool,
    pub unsigned_operand: bool,
    pub integer_return_candidate: bool,
}

#[derive(Clone, Copy, Default)]
struct Use {
    bits: Option<u8>,
    address: bool,
    code: bool,
    signed: bool,
    unsigned: bool,
}

fn observe(
    root: &Expression,
    initial: Use,
    facts: &mut BTreeMap<usize, DefinitionUses>,
    remaining: &mut usize,
) -> Result<(), String> {
    let mut work = vec![(root, initial)];
    while let Some((expression, context)) = work.pop() {
        *remaining = remaining.checked_sub(1).ok_or("type-evidence traversal budget exceeded")?;
        match expression {
            Expression::Reference { definition } => {
                let fact = facts
                    .entry(*definition)
                    .or_insert_with(|| DefinitionUses { definition: *definition, ..Default::default() });
                if let Some(bits) = context.bits {
                    fact.integer_widths.insert(bits);
                }
                fact.address_operand |= context.address;
                fact.code_target |= context.code;
                fact.signed_operand |= context.signed;
                fact.unsigned_operand |= context.unsigned;
            }
            Expression::Add { left, right } | Expression::Subtract { left, right } => {
                work.push((left, context));
                work.push((right, context));
            }
            Expression::Binary { left, right, bits, operation } => {
                let signed = matches!(
                    operation,
                    rampage_arch::ir::Operation::SignedDivide
                        | rampage_arch::ir::Operation::ArithmeticShiftRight
                        | rampage_arch::ir::Operation::SignedMultiplyHigh
                );
                let unsigned = matches!(
                    operation,
                    rampage_arch::ir::Operation::UnsignedDivide
                        | rampage_arch::ir::Operation::ShiftRight
                        | rampage_arch::ir::Operation::UnsignedMultiplyHigh
                );
                let context = Use { bits: Some(*bits), signed, unsigned, ..context };
                work.push((left, context));
                let count = matches!(
                    operation,
                    rampage_arch::ir::Operation::ShiftLeft
                        | rampage_arch::ir::Operation::ShiftRight
                        | rampage_arch::ir::Operation::ArithmeticShiftRight
                        | rampage_arch::ir::Operation::RotateRight
                );
                work.push((right, if count { Use { bits: Some(*bits), ..Default::default() } } else { context }));
            }
            Expression::Low32 { value } => work.push((value, Use { bits: Some(32), ..context })),
            Expression::Unary { value, bits, .. } => {
                work.push((value, Use { bits: Some(*bits), ..Default::default() }))
            }
            Expression::Extend { value, from_bits, signed, .. } => {
                work.push((value, Use { bits: Some(*from_bits), signed: *signed, unsigned: !signed, ..context }));
            }
            Expression::Load { address, .. } => {
                work.push((address, Use { address: true, bits: Some(64), ..Default::default() }))
            }
            Expression::Store { address, value, bits, .. } => {
                work.push((address, Use { address: true, bits: Some(64), ..Default::default() }));
                work.push((value, Use { bits: Some(*bits), ..Default::default() }));
            }
            Expression::Call { target, .. }
            | Expression::Return { target, .. }
            | Expression::IndirectBranch { target } => {
                work.push((target, Use { code: true, address: true, bits: Some(64), ..Default::default() }));
            }
            Expression::Condition { value, .. } => work.push((value, context)),
            Expression::Flags { left, right, bits, .. } => {
                let context = Use { bits: Some(*bits), ..Default::default() };
                work.push((left, context));
                work.push((right, context));
            }
            Expression::Select { when_true, when_false, .. } => {
                work.push((when_true, context));
                work.push((when_false, context));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Records local operand roles without forcing incompatible uses into a guessed source type.
pub fn analyze(ssa: &Ssa) -> Result<TypeEvidence, String> {
    crate::pseudocode::validate(ssa, &[])?;
    let mut facts = BTreeMap::new();
    let mut remaining = 100_000;
    for statement in ssa.blocks.iter().filter(|block| block.reachable).flat_map(|block| &block.statements) {
        for &id in &statement.definitions {
            observe(
                &ssa.definitions[id].expression,
                Use { bits: Some(statement.bits), ..Default::default() },
                &mut facts,
                &mut remaining,
            )?;
        }
        for observation in &statement.observations {
            observe(observation, Use { bits: Some(statement.bits), ..Default::default() }, &mut facts, &mut remaining)?;
            if let Expression::Return { integer_values, .. } = observation {
                for &definition in integer_values {
                    facts
                        .entry(definition)
                        .or_insert_with(|| DefinitionUses { definition, ..Default::default() })
                        .integer_return_candidate = true;
                }
            }
        }
    }
    Ok(TypeEvidence {
        definitions: facts.into_values().collect(),
        limitations: vec![
            "Local operand-use evidence only, not recovered source types, pointer validity or signedness declarations."
                .to_owned(),
            "Address operands may be base pointers or integer indices; \
             incompatible roles are retained rather than unified."
                .to_owned(),
            "No interprocedural propagation or class/struct layout reconstruction.".to_owned(),
        ],
    })
}
