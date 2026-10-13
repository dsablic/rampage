use std::fmt::Write;

use rampage_arch::{
    Flow,
    ir::{FlagOperation, Operation, UnaryOperation},
};
use serde::Serialize;

use crate::{
    discover::Switch,
    ssa::{Expression, Ssa, Variable},
};

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
    let mut check = |root: &Expression, allow_return: bool| -> Result<(), String> {
        let mut stack = vec![(root, 0usize)];
        while let Some((expr, depth)) = stack.pop() {
            nodes += 1;
            if nodes > 100_000 || depth > 64 {
                return Err("pseudocode expression budget exceeded".to_owned());
            }
            let valid = |id: usize| id < ssa.definitions.len();
            match expr {
                Expression::IndirectBranch { target } => stack.push((target, depth + 1)),
                Expression::Extend { value, from_bits, to_bits, signed } => {
                    if rampage_arch::ir::extend(0, *from_bits, *to_bits, *signed).is_none() {
                        return Err("invalid extension widths".to_owned());
                    }
                    stack.push((value, depth + 1));
                }
                Expression::Return { target, integer_values, memory } => {
                    if !allow_return || depth != 0 {
                        return Err("return must be a return-statement observation".to_owned());
                    }
                    if !valid(*memory) || integer_values.iter().any(|&id| !valid(id)) {
                        return Err("invalid return inputs".to_owned());
                    }
                    nodes += integer_values.len();
                    stack.push((target, depth + 1));
                }
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
                Expression::Low32 { value } | Expression::Condition { value, .. } | Expression::Unary { value, .. } => {
                    stack.push((value, depth + 1))
                }
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
                Expression::Load { memory, address, bits } => {
                    if !matches!(bits, 8 | 16 | 32 | 64) {
                        return Err("invalid load width".to_owned());
                    }
                    if !valid(*memory) {
                        return Err("invalid memory definition".to_owned());
                    }
                    stack.push((address, depth + 1));
                }
                Expression::Store { memory, address, value, bits } => {
                    if !matches!(bits, 8 | 16 | 32 | 64) {
                        return Err("invalid store width".to_owned());
                    }
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
        check(&definition.expression, false)?;
    }
    let mut statements = 0;
    let mut phi_owners = vec![false; ssa.definitions.len()];
    for (index, block) in ssa.blocks.iter().enumerate() {
        if block.phis.iter().any(|&id| id >= ssa.definitions.len()) {
            return Err("invalid block phi".to_owned());
        }
        if block.predecessors.len() > 4096 || block.predecessors.iter().any(|&id| id >= ssa.blocks.len()) {
            return Err("invalid block predecessors".to_owned());
        }
        let mut expected: Vec<_> = block.predecessors.iter().copied().map(Some).collect();
        if index == ssa.entry {
            expected.push(None);
        }
        expected.sort_unstable();
        if expected.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("duplicate block predecessor".to_owned());
        }
        for &id in &block.phis {
            if std::mem::replace(&mut phi_owners[id], true) {
                return Err("phi belongs to multiple blocks".to_owned());
            }
            let Expression::Phi { inputs } = &ssa.definitions[id].expression else {
                return Err("block phi must refer to a phi definition".to_owned());
            };
            let mut actual: Vec<_> = inputs.iter().map(|input| input.predecessor).collect();
            actual.sort_unstable();
            if actual != expected {
                return Err("phi must cover every predecessor exactly once".to_owned());
            }
        }
        for statement in &block.statements {
            statements += 1;
            if statements > 20_000 || statement.definitions.iter().any(|&id| id >= ssa.definitions.len()) {
                return Err("invalid or oversized statement definitions".to_owned());
            }
            for observation in &statement.observations {
                check(observation, statement.flow == Flow::Return)?;
            }
        }
    }
    if ssa
        .definitions
        .iter()
        .any(|definition| matches!(definition.expression, Expression::Phi { .. }) && !phi_owners[definition.id])
    {
        return Err("phi definition has no owning block".to_owned());
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
        Expression::IndirectBranch { target } => format!("indirect_target({})", expression(target, ssa, remaining)?),
        Expression::Extend { value, from_bits, to_bits, signed } => format!(
            "{}ext{from_bits}_to{to_bits}({})",
            if *signed { "s" } else { "z" },
            expression(value, ssa, remaining)?
        ),
        Expression::Return { target, integer_values, memory } => format!(
            "integer_return_candidates([{}, {}], memory={}, target={})",
            name(integer_values[0], ssa),
            name(integer_values[1], ssa),
            name(*memory, ssa),
            expression(target, ssa, remaining)?
        ),
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
                Operation::UnsignedMultiplyHigh => "umulh",
                Operation::SignedMultiplyHigh => "smulh",
            };
            format!("{op}{bits}({}, {})", expression(left, ssa, remaining)?, expression(right, ssa, remaining)?)
        }
        Expression::Unary { operation, value, bits } => {
            let op = match operation {
                UnaryOperation::CountLeadingZeros => "clz",
                UnaryOperation::CountLeadingSignBits => "cls",
                UnaryOperation::ReverseBits => "rbit",
                UnaryOperation::ReverseBytes => "rev",
                UnaryOperation::ReverseBytesInHalfwords => "rev16_",
                UnaryOperation::ReverseBytesInWords => "rev32_",
            };
            format!("{op}{bits}({})", expression(value, ssa, remaining)?)
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

/// `case` labels for ascending table indices; runs of three or more become a range.
fn case_labels(values: &[u64]) -> String {
    let mut labels = Vec::new();
    let mut rest = values;
    while let [first, ..] = *rest {
        let run = rest.iter().zip(first..).take_while(|&(&value, expected)| value == expected).count();
        if run >= 3 {
            labels.push(format!("case {first} ... {}:", rest[run - 1]));
        } else {
            labels.extend(rest[..run].iter().map(|value| format!("case {value}:")));
        }
        rest = &rest[run..];
    }
    labels.join(" ")
}

fn switch_index(index: Option<&Expression>, ssa: &Ssa, remaining: &mut usize) -> Result<String, String> {
    index.map_or_else(|| Ok("unrecovered_index".to_owned()), |index| expression(index, ssa, remaining))
}

/// Bounded SSA pseudocode, with explicit labels and phi nodes rather than claiming recovered C source.
pub fn render(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<Pseudocode, String> {
    render_with_switches(ssa, edges, &[])
}

/// Like [`render`], printing the register-indirect jumps that `switches` resolved as `switch` statements.
pub fn render_with_switches(ssa: &Ssa, edges: &[(usize, usize)], switches: &[Switch]) -> Result<Pseudocode, String> {
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
                    let candidates =
                        statement.observations.iter().find(|value| matches!(value, Expression::Return { .. }));
                    if let Some(candidates) = candidates {
                        line!(text, "  {};", expression(candidates, ssa, &mut remaining)?);
                    }
                    line!(text, "  return; // return value/type not inferred");
                }
                Flow::IndirectJump => match crate::structure::dispatch(ssa, edges, switches, index) {
                    Some(dispatch) => {
                        let index = switch_index(dispatch.index.as_ref(), ssa, &mut remaining)?;
                        line!(text, "  switch ({index}) {{ // jump table at {:#x}", statement.address);
                        for (values, target) in &dispatch.cases {
                            let label = match target {
                                Ok(block) => format!("bb{block}"),
                                Err(address) => format!("external_{address:x}"),
                            };
                            line!(text, "  {} goto {label};", case_labels(values));
                        }
                        if let Some(default) = dispatch.default {
                            line!(text, "  default: goto bb{default}; // taken at the bounding comparison");
                        }
                        line!(text, "  }}");
                    }
                    None => line!(text, "  goto unknown_target;"),
                },
                Flow::Halt | Flow::Invalid => {
                    line!(text, "  stop;");
                }
                Flow::Call(_) | Flow::IndirectCall if statement.noreturn => {
                    line!(text, "  stop; // the call never returns");
                }
                _ => {}
            }
        }
        if let Some(statement) = block.statements.last()
            && matches!(statement.flow, Flow::Next | Flow::Call(_) | Flow::IndirectCall | Flow::ConditionalJump(_))
            && !statement.noreturn
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

fn structured_block(
    text: &mut Output,
    ssa: &Ssa,
    index: usize,
    indentation: usize,
    remaining: &mut usize,
) -> Result<(), String> {
    let prefix = "  ".repeat(indentation);
    let block = &ssa.blocks[index];
    line!(text, "{prefix}// bb{index}: {:#x}; phi nodes select the incoming predecessor", block.address);
    if !block.phis.is_empty() {
        line!(text, "{prefix}parallel_phi_bindings {{");
    }
    for &id in &block.phis {
        line!(
            text,
            "{prefix}  {} = phi_from(predecessor, {});",
            name(id, ssa),
            expression(&ssa.definitions[id].expression, ssa, remaining)?
        );
    }
    if !block.phis.is_empty() {
        line!(text, "{prefix}}}");
    }
    for statement in &block.statements {
        if statement.barrier {
            line!(text, "{prefix}// semantic barrier at {:#x}", statement.address);
        }
        for &id in &statement.definitions {
            line!(
                text,
                "{prefix}{} = {};",
                name(id, ssa),
                expression(&ssa.definitions[id].expression, ssa, remaining)?
            );
        }
        for observation in &statement.observations {
            if matches!(observation, Expression::Load { .. } | Expression::Call { .. } | Expression::Return { .. }) {
                line!(text, "{prefix}{};", expression(observation, ssa, remaining)?);
            }
        }
        match statement.flow {
            Flow::Return => {
                line!(text, "{prefix}return; // signature remains unknown");
            }
            Flow::Halt | Flow::Invalid => {
                line!(text, "{prefix}stop;");
            }
            Flow::Call(_) | Flow::IndirectCall if statement.noreturn => {
                line!(text, "{prefix}stop; // the call never returns");
            }
            _ => {}
        }
    }
    line!(text, "{prefix}predecessor = bb{index};");
    Ok(())
}

fn structured_region(
    text: &mut Output,
    ssa: &Ssa,
    region: &crate::structure::Region,
    indentation: usize,
    remaining: &mut usize,
) -> Result<(), String> {
    use crate::structure::Region;
    if indentation > 64 {
        return Err("structured pseudocode nesting exceeds 64 levels".to_owned());
    }
    let prefix = "  ".repeat(indentation);
    match region {
        Region::Sequence { regions } => {
            for region in regions {
                structured_region(text, ssa, region, indentation, remaining)?;
            }
        }
        Region::Block { block } => structured_block(text, ssa, *block, indentation, remaining)?,
        Region::If { condition, taken, not_taken } => {
            line!(text, "{prefix}if ({}) {{", expression(condition, ssa, remaining)?);
            structured_region(text, ssa, taken, indentation + 1, remaining)?;
            line!(text, "{prefix}}} else {{");
            structured_region(text, ssa, not_taken, indentation + 1, remaining)?;
            line!(text, "{prefix}}}");
        }
        Region::Loop { header, condition, body_when_true, body } => {
            line!(text, "{prefix}while (true) {{");
            structured_block(text, ssa, *header, indentation + 1, remaining)?;
            let condition = expression(condition, ssa, remaining)?;
            line!(text, "{prefix}  if ({}({condition})) break;", if *body_when_true { "!" } else { "" });
            structured_region(text, ssa, body, indentation + 1, remaining)?;
            line!(text, "{prefix}}}");
        }
        Region::Switch { dispatch, index, cases } => {
            let index = switch_index(index.as_ref(), ssa, remaining)?;
            line!(text, "{prefix}switch ({index}) {{ // bb{dispatch}'s jump table; the bound check already passed");
            for case in cases {
                line!(text, "{prefix}{}", case_labels(&case.values));
                structured_region(text, ssa, &case.body, indentation + 1, remaining)?;
                line!(text, "{prefix}  break;");
            }
            line!(text, "{prefix}}}");
        }
    }
    Ok(())
}

/// Prints only graph shapes accepted by conservative control structuring; expressions remain explicit SSA.
pub fn render_structured(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<Pseudocode, String> {
    render_structured_with_switches(ssa, edges, &[])
}

/// Like [`render_structured`], also structuring the register-indirect jumps that `switches` resolved.
pub fn render_structured_with_switches(
    ssa: &Ssa,
    edges: &[(usize, usize)],
    switches: &[Switch],
) -> Result<Pseudocode, String> {
    validate(ssa, edges)?;
    let structure = crate::structure::analyze_with_switches(ssa, edges, switches)?;
    let mut text = Output(String::from("// Partial structured ARM64 SSA pseudocode, not typed source.\n"));
    let mut remaining = 100_000;
    for definition in &ssa.definitions {
        if matches!(definition.expression, Expression::Input) {
            line!(text, "{} = input;", name(definition.id, ssa));
        }
    }
    line!(text, "predecessor = entry;");
    structured_region(&mut text, ssa, &structure.body, 0, &mut remaining)?;
    Ok(Pseudocode {
        text: text.0,
        structured: true,
        limitations: vec![
            "Structured control only; values remain SSA definitions, not recovered typed source variables.".to_owned(),
            "phi_from selects the matching incoming predecessor; all block phis bind simultaneously.".to_owned(),
            "Unknown semantics and return signatures remain explicit; unsupported graph shapes are rejected."
                .to_owned(),
        ],
    })
}
