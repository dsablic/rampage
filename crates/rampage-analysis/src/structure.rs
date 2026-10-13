use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::Flow;
use serde::Serialize;

use crate::{
    control,
    discover::Switch,
    ssa::{Expression, Ssa, Variable},
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
    /// The jump-table dispatch that ends block `dispatch`, which the enclosing sequence already holds. Every table
    /// entry has a case, and each case leaves only for the block after the switch: no case falls into another.
    Switch {
        dispatch: usize,
        /// The bounded value; `None` when the bounding comparison's operand was not recovered.
        index: Option<Expression>,
        cases: Vec<SwitchCase>,
    },
}

#[derive(Debug, Serialize)]
pub struct SwitchCase {
    /// The table entry indices that select this case, ascending.
    pub values: Vec<u64>,
    /// Empty when the case goes straight to the block after the switch.
    pub body: Region,
}

/// A resolved switch's dispatch over SSA blocks.
pub(crate) struct Dispatch {
    pub index: Option<Expression>,
    /// Case values grouped by target, ordered by first value. A target is a block, or an address outside the
    /// graph (a tail call).
    pub cases: Vec<(Vec<u64>, Result<usize, u64>)>,
    /// The block the bounding comparison sends out-of-range indices to.
    pub default: Option<usize>,
}

fn block_at(ssa: &Ssa, address: u64) -> Option<usize> {
    ssa.blocks.iter().position(|block| block.address == address)
}

fn single_successor(edges: &[(usize, usize)], block: usize) -> Option<usize> {
    let mut next = edges.iter().filter(|edge| edge.0 == block).map(|edge| edge.1);
    let first = next.next()?;
    next.all(|other| other == first).then_some(first)
}

/// The switch whose register-indirect jump ends `block`, over SSA blocks; `None` leaves the jump unknown.
pub(crate) fn dispatch(ssa: &Ssa, edges: &[(usize, usize)], switches: &[Switch], block: usize) -> Option<Dispatch> {
    let jump = ssa.blocks.get(block)?.statements.last().filter(|statement| statement.flow == Flow::IndirectJump)?;
    let switch = switches.iter().find(|switch| switch.jump == jump.address)?;
    if switch.table.is_empty() || switch.table.len() as u64 > rampage_arch::MAX_JUMP_TABLE_ENTRIES {
        return None;
    }
    let mut cases: Vec<(Vec<u64>, Result<usize, u64>)> = Vec::new();
    for (value, &target) in (0u64..).zip(&switch.table) {
        let target = block_at(ssa, target).ok_or(target);
        match cases.iter_mut().find(|(_, existing)| *existing == target) {
            Some((values, _)) => values.push(value),
            None => cases.push((vec![value], target)),
        }
    }
    let guard = ssa.blocks.iter().enumerate().find_map(|(index, data)| {
        let position = data.statements.iter().position(|statement| statement.address == switch.guard)?;
        Some((index, position))
    });
    let index = guard.and_then(|(guard_block, position)| {
        ssa.blocks[guard_block].statements[position].definitions.iter().find_map(|&id| {
            let definition = ssa.definitions.get(id).filter(|definition| definition.variable == Variable::Flags)?;
            let Expression::Flags { left, bits, .. } = &definition.expression else { return None };
            Some(match left.as_ref() {
                Expression::Low32 { .. } => left.as_ref().clone(),
                _ if *bits == 32 => Expression::Low32 { value: left.clone() },
                _ => left.as_ref().clone(),
            })
        })
    });
    // The comparison's branch has one successor that runs on to the jump and one that is the default.
    let default = guard.and_then(|(guard_block, _)| {
        let last = ssa.blocks[guard_block].statements.last()?;
        if !matches!(last.flow, Flow::ConditionalJump(_)) {
            return None;
        }
        let mut successors: Vec<_> = edges.iter().filter(|edge| edge.0 == guard_block).map(|edge| edge.1).collect();
        successors.sort_unstable();
        successors.dedup();
        let reaches = |mut at: usize| {
            for _ in 0..ssa.blocks.len() {
                if at == block {
                    return true;
                }
                let Some(next) = single_successor(edges, at) else { return false };
                at = next;
            }
            false
        };
        match *successors.as_slice() {
            [first, second] => match (reaches(first), reaches(second)) {
                (true, false) => Some(second),
                (false, true) => Some(first),
                _ => None,
            },
            _ => None,
        }
    });
    Some(Dispatch { index, cases, default })
}

struct Context<'a> {
    ssa: &'a Ssa,
    edges: &'a [(usize, usize)],
    switches: &'a [Switch],
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    loops: control::ControlFlow,
    used: BTreeSet<usize>,
    /// Dominance steps left for checking switch cases.
    budget: usize,
    shapes: BTreeMap<usize, Result<SwitchShape, String>>,
}

/// A switch whose cases were checked to leave only for one follow block.
#[derive(Clone)]
struct SwitchShape {
    index: Option<Expression>,
    cases: Vec<(Vec<u64>, usize)>,
    follow: Option<usize>,
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

    fn dominates(&mut self, dominator: usize, mut block: usize) -> Result<bool, String> {
        loop {
            self.budget = self.budget.checked_sub(1).ok_or("switch structuring budget exceeded")?;
            if block == dominator {
                return Ok(true);
            }
            let Some(parent) = self.loops.immediate_dominators.get(block).copied().flatten() else { return Ok(false) };
            block = parent;
        }
    }

    /// Checks that each case of the switch ending `dispatch` is a region of its own that leaves only for one
    /// follow block. Fall-through into another case, case bodies also reached from elsewhere and cases outside the
    /// graph are rejected rather than structured.
    fn switch_shape(&mut self, dispatch: usize) -> Result<SwitchShape, String> {
        if let Some(shape) = self.shapes.get(&dispatch) {
            return shape.clone();
        }
        let shape = self.check_switch(dispatch);
        self.shapes.insert(dispatch, shape.clone());
        shape
    }

    fn check_switch(&mut self, dispatch: usize) -> Result<SwitchShape, String> {
        let Dispatch { index, cases, .. } = crate::structure::dispatch(self.ssa, self.edges, self.switches, dispatch)
            .ok_or("unknown indirect transfer cannot be structured")?;
        let cases: Vec<(Vec<u64>, usize)> = cases
            .into_iter()
            .map(|(values, target)| target.map(|block| (values, block)))
            .collect::<Result<_, _>>()
            .map_err(|_| "a switch case leaves the function".to_owned())?;
        let mut targets: Vec<_> = cases.iter().map(|&(_, block)| block).collect();
        targets.sort_unstable();
        if targets != self.successors[dispatch] {
            return Err("switch cases disagree with the control-flow graph".to_owned());
        }
        let mut follows = BTreeSet::new();
        for &case in &targets {
            if self.predecessors[case] != [dispatch] {
                // Reached from elsewhere too, so it can only be the block after the switch.
                follows.insert(case);
                continue;
            }
            for block in 0..self.ssa.blocks.len() {
                if !self.ssa.blocks[block].reachable || !self.dominates(case, block)? {
                    continue;
                }
                for successor in self.successors[block].clone() {
                    if !self.dominates(case, successor)? {
                        follows.insert(successor);
                    }
                }
            }
        }
        if follows.len() > 1 {
            let follows: Vec<_> = follows.iter().map(|block| format!("bb{block}")).collect();
            return Err(format!(
                "switch cases fall through or do not converge on one follow block (they leave for {})",
                follows.join(", ")
            ));
        }
        Ok(SwitchShape { index, cases, follow: follows.pop_first() })
    }

    fn linear_path(&mut self, start: usize, stop: Option<usize>) -> Vec<usize> {
        let mut path = Vec::new();
        let mut block = start;
        while !path.contains(&block) && Some(block) != stop {
            path.push(block);
            block = match self.successors[block].as_slice() {
                [next] => *next,
                // A well-formed switch runs on at its follow block.
                [_, _, ..] => match self.switch_shape(block) {
                    Ok(SwitchShape { follow: Some(follow), .. }) => follow,
                    _ => break,
                },
                _ => break,
            };
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
                _ if statement.is_terminal() => {
                    if !self.successors[at].is_empty() {
                        return Err("terminal block has internal successors".to_owned());
                    }
                    break;
                }
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
                Flow::IndirectJump => {
                    let SwitchShape { index, cases, follow } = self.switch_shape(at)?;
                    let mut structured = Vec::with_capacity(cases.len());
                    for (values, target) in cases {
                        let body = if Some(target) == follow {
                            Region::Sequence { regions: Vec::new() }
                        } else {
                            self.sequence(target, follow, depth + 1)?
                        };
                        structured.push(SwitchCase { values, body });
                    }
                    regions.push(Region::Switch { dispatch: at, index, cases: structured });
                    match follow {
                        Some(follow) => at = follow,
                        None => break,
                    }
                }
                // A fall-through, jump or call that returns.
                _ => {
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
    analyze_with_switches(ssa, edges, &[])
}

/// Like [`analyze`], also structuring the register-indirect jumps that `switches` resolved.
pub fn analyze_with_switches(
    ssa: &Ssa,
    edges: &[(usize, usize)],
    switches: &[Switch],
) -> Result<StructuredControl, String> {
    crate::pseudocode::validate(ssa, edges)?;
    let loops = control::analyze(ssa, edges)?;
    let mut successors = vec![Vec::new(); ssa.blocks.len()];
    let mut predecessors = vec![Vec::new(); ssa.blocks.len()];
    for &(from, to) in edges {
        successors[from].push(to);
        if ssa.blocks[from].reachable {
            predecessors[to].push(from);
        }
    }
    for list in successors.iter_mut().chain(&mut predecessors) {
        list.sort_unstable();
        list.dedup();
    }
    let mut context = Context {
        ssa,
        edges,
        switches,
        successors,
        predecessors,
        loops,
        used: BTreeSet::new(),
        budget: 4_000_000,
        shapes: BTreeMap::new(),
    };
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
            "Only selected reducible sequences, branches, single-body loops and switches whose cases do not fall \
             through are supported."
                .to_owned(),
        ],
    })
}
