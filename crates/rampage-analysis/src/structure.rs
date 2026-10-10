use std::collections::BTreeSet;

use rampage_arch::Flow;
use serde::Serialize;

use crate::{
    control,
    ssa::{Expression, Ssa},
};

#[derive(Debug, Serialize)]
pub struct StructuredControl {
    pub body: Region,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Region {
    Sequence {
        regions: Vec<Region>,
    },
    Block {
        block: usize,
    },
    If {
        condition: Expression,
        taken: Box<Region>,
        not_taken: Box<Region>,
    },
    /// Header effects/phis execute on every iteration before the condition is tested.
    Loop {
        header: usize,
        condition: Expression,
        body_when_true: bool,
        body: Box<Region>,
    },
}

struct Context<'a> {
    ssa: &'a Ssa,
    successors: Vec<Vec<usize>>,
    loops: control::ControlFlow,
    used: BTreeSet<usize>,
}

impl Context<'_> {
    fn condition(&self, block: usize) -> Result<Expression, String> {
        let statement = self.ssa.blocks[block].statements.last().ok_or("empty conditional block")?;
        if statement.barrier {
            return Err("conditional block has unknown semantics".to_owned());
        }
        statement
            .observations
            .iter()
            .find(|value| matches!(value, Expression::Condition { .. } | Expression::FlagsCondition { .. }))
            .cloned()
            .ok_or_else(|| "conditional block has no explicit condition".to_owned())
    }

    fn linear_path(&self, start: usize, stop: Option<usize>) -> Vec<usize> {
        let mut path = Vec::new();
        let mut block = start;
        while !path.contains(&block) && Some(block) != stop {
            path.push(block);
            let [next] = self.successors[block].as_slice() else { break };
            block = *next;
        }
        if let Some(stop) = stop {
            path.push(stop);
        }
        path
    }

    fn sequence(&mut self, start: usize, stop: Option<usize>, depth: usize) -> Result<Region, String> {
        if depth > 64 {
            return Err("structured-control nesting exceeds 64 levels".to_owned());
        }
        let mut regions = Vec::new();
        let mut at = start;
        while Some(at) != stop {
            if !self.used.insert(at) {
                return Err("control region has overlapping or irreducible paths".to_owned());
            }
            if let Some(natural) = self.loops.loops.iter().find(|natural| natural.header == at) {
                let members = natural.blocks.clone();
                let exits = natural.exits.clone();
                if members.len() != 2 || exits.len() != 1 || exits[0].0 != at {
                    return Err("only single-header, single-body loops are currently structured".to_owned());
                }
                let body = *members.iter().find(|&&member| member != at).unwrap();
                let exit = exits[0].1;
                if self.successors[body] != [at] || self.successors[at].len() != 2 {
                    return Err("loop body has noncanonical transfers".to_owned());
                }
                let body_flow = self.ssa.blocks[body].statements.last().ok_or("empty loop body")?.flow;
                match body_flow {
                    Flow::Jump(target) if target == self.ssa.blocks[at].address => {}
                    Flow::Next => {}
                    _ => return Err("loop body has conditional, external or unknown terminal transfer".to_owned()),
                }
                let Flow::ConditionalJump(target) =
                    self.ssa.blocks[at].statements.last().ok_or("empty loop header")?.flow
                else {
                    return Err("loop header must be an explicit conditional".to_owned());
                };
                let body_when_true = target == self.ssa.blocks[body].address;
                if !body_when_true && target != self.ssa.blocks[exit].address {
                    return Err("loop condition target is not body or exit".to_owned());
                }
                if !self.used.insert(body) {
                    return Err("overlapping loop body".to_owned());
                }
                regions.push(Region::Loop {
                    header: at,
                    condition: self.condition(at)?,
                    body_when_true,
                    body: Box::new(Region::Block { block: body }),
                });
                at = exit;
                continue;
            }
            regions.push(Region::Block { block: at });
            let statement = self.ssa.blocks[at].statements.last().ok_or("empty control block")?;
            match statement.flow {
                Flow::ConditionalJump(target) => {
                    let successors = self.successors[at].clone();
                    if successors.len() != 2 {
                        return Err("conditional has external or coincident successors".to_owned());
                    }
                    let taken = successors
                        .iter()
                        .copied()
                        .find(|&block| self.ssa.blocks[block].address == target)
                        .ok_or("conditional target is outside the internal graph")?;
                    let other = *successors.iter().find(|&&block| block != taken).unwrap();
                    let left = self.linear_path(taken, stop);
                    let right = self.linear_path(other, stop);
                    let join = left.iter().copied().find(|block| right.contains(block));
                    let condition = self.condition(at)?;
                    let taken = self.sequence(taken, join, depth + 1)?;
                    let not_taken = self.sequence(other, join, depth + 1)?;
                    regions.push(Region::If { condition, taken: Box::new(taken), not_taken: Box::new(not_taken) });
                    if let Some(join) = join {
                        at = join;
                    } else {
                        break;
                    }
                }
                Flow::Return | Flow::Halt | Flow::Invalid => {
                    if !self.successors[at].is_empty() {
                        return Err("terminal block has internal successors".to_owned());
                    }
                    break;
                }
                Flow::IndirectJump => return Err("unknown indirect transfer cannot be structured".to_owned()),
                Flow::Next | Flow::Jump(_) | Flow::Call(_) | Flow::IndirectCall => {
                    let [next] = self.successors[at].as_slice() else {
                        return Err("nonterminal transfer does not have one internal successor".to_owned());
                    };
                    if let Flow::Jump(target) = statement.flow
                        && target != self.ssa.blocks[*next].address
                    {
                        return Err("unconditional jump target disagrees with graph successor".to_owned());
                    }
                    at = *next;
                }
            }
        }
        Ok(Region::Sequence { regions })
    }
}

/// Structures selected reducible graph shapes without hiding SSA phis or unknown instruction effects.
pub fn analyze(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<StructuredControl, String> {
    crate::pseudocode::validate(ssa, edges)?;
    let loops = control::analyze(ssa, edges)?;
    let mut successors = vec![Vec::new(); ssa.blocks.len()];
    for &(from, to) in edges {
        successors[from].push(to);
    }
    for list in &mut successors {
        list.sort_unstable();
        list.dedup();
    }
    let mut context = Context { ssa, successors, loops, used: BTreeSet::new() };
    let body = context.sequence(ssa.entry, None, 0)?;
    if ssa.blocks.iter().enumerate().any(|(block, data)| data.reachable && !context.used.contains(&block)) {
        return Err("structured regions do not cover every reachable block".to_owned());
    }
    Ok(StructuredControl {
        body,
        limitations: vec![
            "Structured control over SSA block references, not recovered typed source.".to_owned(),
            "Phi bindings select the executed predecessor edge; loop header effects execute on every iteration."
                .to_owned(),
            "Only selected reducible sequences, branches and single-body loops are supported.".to_owned(),
        ],
    })
}
