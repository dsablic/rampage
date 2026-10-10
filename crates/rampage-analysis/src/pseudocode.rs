use std::fmt::Write;

use rampage_arch::{
    Flow,
    ir::{FlagOperation, Operation},
};
use serde::Serialize;

use crate::ssa::{Expression, Ssa, Variable};

#[derive(Debug, Serialize)]
pub struct Pseudocode {
    pub text: String,
    pub structured: bool,
    pub limitations: Vec<String>,
}

pub(crate) fn validate(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<(), String> {
    if ssa.blocks.is_empty()
        || ssa.entry >= ssa.blocks.len()
        || ssa.blocks.len() > 512
        || ssa.definitions.len() > 20_000
        || edges.len() > 4096
    {
        return Err("invalid or oversized SSA graph".to_owned());
    }
    if !ssa.blocks[ssa.entry].reachable {
        return Err("SSA entry must be reachable".to_owned());
    }
    if edges.iter().any(|&(from, to)| from >= ssa.blocks.len() || to >= ssa.blocks.len()) {
        return Err("pseudocode edge outside graph".to_owned());
    }
    let mut nodes = 0usize;
    let mut check = |root: &Expression| -> Result<(), String> {
        let mut stack = vec![(root, 0usize)];
        while let Some((expr, depth)) = stack.pop() {
            nodes += 1;
            if nodes > 100_000 || depth > 64 {
                return Err("pseudocode expression budget exceeded".to_owned());
            }
            let valid = |id: usize| id < ssa.definitions.len();
            match expr {
                Expression::Select { flags, when_true, when_false, .. } => {
                    if !valid(*flags) {
                        return Err("invalid select flags".to_owned());
                    }
                    stack.push((when_true, depth + 1));
                    stack.push((when_false, depth + 1));
                }
                Expression::Reference { definition } if !valid(*definition) => {
                    return Err("invalid definition reference".to_owned());
                }
                Expression::Add { left, right }
                | Expression::Subtract { left, right }
                | Expression::Binary { left, right, .. }
                | Expression::Flags { left, right, .. } => {
                    stack.push((left, depth + 1));
                    stack.push((right, depth + 1));
                }
                Expression::Low32 { value } | Expression::Condition { value, .. } => stack.push((value, depth + 1)),
                Expression::FlagsCondition { flags, .. } if !valid(*flags) => {
                    return Err("invalid flag definition".to_owned());
                }
                Expression::Phi { inputs } => {
                    if inputs.len() > 4097 {
                        return Err("pseudocode phi budget exceeded".to_owned());
                    }
                    for input in inputs {
                        if !valid(input.definition) || input.predecessor.is_some_and(|id| id >= ssa.blocks.len()) {
                            return Err("invalid phi input".to_owned());
                        }
                    }
                    nodes += inputs.len();
                }
                Expression::Load { memory, address, .. } => {
                    if !valid(*memory) {
                        return Err("invalid memory definition".to_owned());
                    }
                    stack.push((address, depth + 1));
                }
                Expression::Store { memory, address, value, .. } => {
                    if !valid(*memory) {
                        return Err("invalid memory definition".to_owned());
                    }
                    stack.push((address, depth + 1));
                    stack.push((value, depth + 1));
                }
                Expression::Call { target, arguments, memory, result_buffer, stack_pointer, .. } => {
                    if arguments.len() > 8
                        || !valid(*memory)
                        || !valid(*result_buffer)
                        || !valid(*stack_pointer)
                        || arguments.iter().any(|id| !valid(*id))
                    {
                        return Err("invalid call inputs".to_owned());
                    }
                    nodes += arguments.len();
                    stack.push((target, depth + 1));
                }
                _ => {}
            }
        }
        Ok(())
    };
    for (id, definition) in ssa.definitions.iter().enumerate() {
        if definition.id != id {
            return Err("inconsistent SSA definition id".to_owned());
        }
        check(&definition.expression)?;
    }
    let mut statements = 0;
    for block in &ssa.blocks {
        if block.phis.iter().any(|&id| id >= ssa.definitions.len()) {
            return Err("invalid block phi".to_owned());
        }
        for statement in &block.statements {
            statements += 1;
            if statements > 20_000 || statement.definitions.iter().any(|&id| id >= ssa.definitions.len()) {
                return Err("invalid or oversized statement definitions".to_owned());
            }
            for observation in &statement.observations {
                check(observation)?;
            }
        }
    }
    Ok(())
}

struct Output(String);

impl Write for Output {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        if self.0.len().saturating_add(value.len()) > 1024 * 1024 {
            return Err(std::fmt::Error);
        }
        self.0.push_str(value);
        Ok(())
    }
}

macro_rules! line {
    ($output:expr, $($args:tt)*) => {
        writeln!($output, $($args)*).map_err(|_| "pseudocode output exceeds 1 MiB".to_owned())?
    };
}

fn name(id: usize, ssa: &Ssa) -> String {
    match ssa.definitions[id].variable {
        Variable::Register { number } => format!("x{number}_{id}"),
        Variable::StackPointer => format!("sp_{id}"),
        Variable::Memory => format!("mem_{id}"),
        Variable::Flags => format!("nzcv_{id}"),
    }
}

fn expression(expr: &Expression, ssa: &Ssa, remaining: &mut usize) -> Result<String, String> {
    *remaining = remaining.checked_sub(1).ok_or("pseudocode expression budget exceeded")?;
    Ok(match expr {
        Expression::Select { flags, condition, when_true, when_false } => format!(
            "(condition({}, {condition}) ? {} : {})",
            name(*flags, ssa),
            expression(when_true, ssa, remaining)?,
            expression(when_false, ssa, remaining)?
        ),
        Expression::Input => "input".to_owned(),
        Expression::Unknown { .. } => "unknown".to_owned(),
        Expression::Constant { value } => format!("0x{value:x}"),
        Expression::Reference { definition } => name(*definition, ssa),
        Expression::Add { left, right } | Expression::Subtract { left, right } => {
            let op = if matches!(expr, Expression::Add { .. }) { "+" } else { "-" };
            format!("({} {op} {})", expression(left, ssa, remaining)?, expression(right, ssa, remaining)?)
        }
        Expression::Binary { operation, left, right, bits } => {
            let op = match operation {
                Operation::And => "and",
                Operation::Or => "or",
                Operation::Xor => "xor",
                Operation::ShiftLeft => "lsl",
                Operation::ShiftRight => "lsr",
                Operation::ArithmeticShiftRight => "asr",
                Operation::RotateRight => "ror",
                Operation::Multiply => "mul",
                Operation::UnsignedDivide => "udiv",
                Operation::SignedDivide => "sdiv",
            };
            format!("{op}{bits}({}, {})", expression(left, ssa, remaining)?, expression(right, ssa, remaining)?)
        }
        Expression::Flags { operation, left, right, bits } => {
            let op = match operation {
                FlagOperation::Add => "add",
                FlagOperation::Subtract => "sub",
                FlagOperation::And => "and",
            };
            format!("flags_{op}{bits}({}, {})", expression(left, ssa, remaining)?, expression(right, ssa, remaining)?)
        }
        Expression::FlagsCondition { flags, condition } => format!("condition({}, {condition})", name(*flags, ssa)),
        Expression::Low32 { value } => format!("zext32({})", expression(value, ssa, remaining)?),
        Expression::Condition { value, nonzero, bit } => {
            let value = expression(value, ssa, remaining)?;
            let value = bit.map_or(value.clone(), |bit| format!("bit({value}, {bit})"));
            format!("({value} {} 0)", if *nonzero { "!=" } else { "==" })
        }
        Expression::Phi { inputs } => {
            if inputs.len() > *remaining {
                return Err("pseudocode phi budget exceeded".to_owned());
            }
            *remaining -= inputs.len();
            let inputs: Vec<_> = inputs
                .iter()
                .map(|input| {
                    let edge = input.predecessor.map_or_else(|| "entry".to_owned(), |block| format!("bb{block}"));
                    format!("{edge}: {}", name(input.definition, ssa))
                })
                .collect();
            format!("phi({})", inputs.join(", "))
        }
        Expression::Load { memory, address, bits } => {
            format!("load{bits}({}, {})", name(*memory, ssa), expression(address, ssa, remaining)?)
        }
        Expression::Store { memory, address, value, bits } => format!(
            "store{bits}({}, {}, {})",
            name(*memory, ssa),
            expression(address, ssa, remaining)?,
            expression(value, ssa, remaining)?
        ),
        Expression::Call { target, arguments, memory, result_buffer, stack_pointer, .. } => {
            let args: Vec<_> = arguments.iter().map(|&id| name(id, ssa)).collect();
            format!(
                "call({}, [{}], {}, result_buffer={}, sp={})",
                expression(target, ssa, remaining)?,
                args.join(", "),
                name(*memory, ssa),
                name(*result_buffer, ssa),
                name(*stack_pointer, ssa)
            )
        }
    })
}

/// Bounded SSA pseudocode, with explicit labels and phi nodes rather than claiming recovered C source.
pub fn render(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<Pseudocode, String> {
    validate(ssa, edges)?;
    let mut text = Output(String::from("// Partial ARM64 SSA pseudocode; unknowns and phi nodes are explicit.\n"));
    let mut remaining = 100_000;
    for definition in &ssa.definitions {
        if matches!(definition.expression, Expression::Input) {
            line!(text, "{} = input;", name(definition.id, ssa));
        }
    }
    line!(text, "goto bb{};", ssa.entry);
    for (index, block) in ssa.blocks.iter().enumerate().filter(|(_, block)| block.reachable) {
        line!(text, "bb{index}: // {:#x}", block.address);
        for &id in &block.phis {
            line!(text, "  {} = {};", name(id, ssa), expression(&ssa.definitions[id].expression, ssa, &mut remaining)?);
        }
        for statement in &block.statements {
            if statement.barrier {
                line!(text, "  // semantic barrier at {:#x}", statement.address);
            }
            for &id in &statement.definitions {
                line!(
                    text,
                    "  {} = {};",
                    name(id, ssa),
                    expression(&ssa.definitions[id].expression, ssa, &mut remaining)?
                );
            }
            for value in &statement.observations {
                if matches!(value, Expression::Load { .. } | Expression::Call { .. }) {
                    line!(text, "  {};", expression(value, ssa, &mut remaining)?);
                }
            }
            match statement.flow {
                Flow::ConditionalJump(target) => {
                    let condition = statement.observations.iter().find(|value| {
                        matches!(value, Expression::Condition { .. } | Expression::FlagsCondition { .. })
                    });
                    let condition = condition
                        .map(|value| expression(value, ssa, &mut remaining))
                        .transpose()?
                        .unwrap_or_else(|| "unknown_condition".to_owned());
                    let label = ssa
                        .blocks
                        .iter()
                        .position(|block| block.address == target)
                        .map_or_else(|| format!("external_{target:x}"), |index| format!("bb{index}"));
                    line!(text, "  if ({condition}) goto {label};");
                }
                Flow::Jump(target) => {
                    let label = ssa
                        .blocks
                        .iter()
                        .position(|block| block.address == target)
                        .map_or_else(|| format!("external_{target:x}"), |index| format!("bb{index}"));
                    line!(text, "  goto {label};");
                }
                Flow::Return => {
                    line!(text, "  return; // return value/type not inferred");
                }
                Flow::IndirectJump => {
                    line!(text, "  goto unknown_target;");
                }
                Flow::Halt | Flow::Invalid => {
                    line!(text, "  stop;");
                }
                _ => {}
            }
        }
        if let Some(statement) = block.statements.last()
            && matches!(statement.flow, Flow::Next | Flow::Call(_) | Flow::IndirectCall | Flow::ConditionalJump(_))
        {
            let taken = match statement.flow {
                Flow::ConditionalJump(target) => Some(target),
                _ => None,
            };
            let next: Vec<_> = edges
                .iter()
                .filter(|&&(from, to)| from == index && Some(ssa.blocks[to].address) != taken)
                .map(|&(_, to)| to)
                .collect();
            if next.len() == 1 {
                line!(text, "  goto bb{};", next[0]);
            } else {
                line!(text, "  goto unknown_fallthrough;");
            }
        }
    }
    Ok(Pseudocode {
        text: text.0,
        structured: false,
        limitations: vec![
            "SSA-style pseudocode only: labels, phi nodes and semantic barriers are retained.".to_owned(),
            "No recovered source types, return signatures or structured loops; unknowns are not reconstructed."
                .to_owned(),
        ],
    })
}
