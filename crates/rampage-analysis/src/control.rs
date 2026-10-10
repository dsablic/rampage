use std::collections::BTreeSet;

use serde::Serialize;

use crate::ssa::Ssa;

#[derive(Debug, Serialize)]
pub struct ControlFlow {
    pub entry: usize,
    pub immediate_dominators: Vec<Option<usize>>,
    pub loops: Vec<NaturalLoop>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NaturalLoop {
    pub header: usize,
    pub backedges: Vec<usize>,
    pub blocks: Vec<usize>,
    pub exits: Vec<(usize, usize)>,
}

fn bit(set: &[u64; 8], index: usize) -> bool {
    set[index / 64] & (1 << (index % 64)) != 0
}
fn include(set: &mut [u64; 8], index: usize) {
    set[index / 64] |= 1 << (index % 64);
}

pub fn analyze(ssa: &Ssa, edges: &[(usize, usize)]) -> Result<ControlFlow, String> {
    let count = ssa.blocks.len();
    if count == 0 || count > 512 || ssa.entry >= count || !ssa.blocks[ssa.entry].reachable || edges.len() > 4096 {
        return Err("control-flow analysis requires a bounded graph with a reachable entry".to_owned());
    }
    let mut parents = vec![Vec::new(); count];
    let mut successors = vec![Vec::new(); count];
    for &(from, to) in edges {
        if from >= count || to >= count {
            return Err("control-flow edge outside graph".to_owned());
        }
        parents[to].push(from);
        successors[from].push(to);
    }
    for list in parents.iter_mut().chain(successors.iter_mut()) {
        list.sort_unstable();
        list.dedup();
    }
    let mut visited = vec![false; count];
    let mut work = vec![ssa.entry];
    while let Some(block) = work.pop() {
        if !std::mem::replace(&mut visited[block], true) {
            work.extend(&successors[block]);
        }
    }
    if visited.iter().zip(&ssa.blocks).any(|(visited, block)| *visited != block.reachable) {
        return Err("SSA reachability disagrees with control-flow edges".to_owned());
    }
    for parents in &mut parents {
        parents.retain(|&from| visited[from]);
    }
    let mut reachable = [0u64; 8];
    for (index, block) in ssa.blocks.iter().enumerate() {
        if block.reachable {
            include(&mut reachable, index);
        }
    }
    let mut dominance = vec![[0; 8]; count];
    for (index, block) in ssa.blocks.iter().enumerate() {
        if block.reachable {
            dominance[index] = reachable;
        }
    }
    dominance[ssa.entry] = [0; 8];
    include(&mut dominance[ssa.entry], ssa.entry);
    for _ in 0..512 {
        let mut changed = false;
        for (index, _) in ssa.blocks.iter().enumerate().filter(|(index, block)| *index != ssa.entry && block.reachable)
        {
            let Some(&first) = parents[index].first() else {
                return Err("reachable block has no predecessor".to_owned());
            };
            let mut next = dominance[first];
            for &parent in &parents[index][1..] {
                for (chunk, other) in next.iter_mut().zip(dominance[parent]) {
                    *chunk &= other;
                }
            }
            include(&mut next, index);
            changed |= next != dominance[index];
            dominance[index] = next;
        }
        if !changed {
            break;
        }
    }
    let mut immediate_dominators = vec![None; count];
    for (index, _) in ssa.blocks.iter().enumerate().filter(|(index, block)| *index != ssa.entry && block.reachable) {
        let strict: Vec<_> =
            (0..count).filter(|&candidate| candidate != index && bit(&dominance[index], candidate)).collect();
        immediate_dominators[index] = strict
            .iter()
            .copied()
            .max_by_key(|&candidate| dominance[candidate].iter().map(|word| word.count_ones()).sum::<u32>());
    }
    let mut headers: std::collections::BTreeMap<usize, (BTreeSet<usize>, BTreeSet<usize>)> = Default::default();
    for &(from, header) in edges {
        if !ssa.blocks[from].reachable || !ssa.blocks[header].reachable || !bit(&dominance[from], header) {
            continue;
        }
        let (backedges, members) = headers.entry(header).or_default();
        backedges.insert(from);
        members.insert(header);
        let mut work = vec![from];
        while let Some(block) = work.pop() {
            if members.insert(block) {
                work.extend(&parents[block]);
            }
        }
    }
    let loops = headers
        .into_iter()
        .map(|(header, (backedges, blocks))| {
            let exits: BTreeSet<_> =
                edges.iter().copied().filter(|(from, to)| blocks.contains(from) && !blocks.contains(to)).collect();
            NaturalLoop {
                header,
                backedges: backedges.into_iter().collect(),
                blocks: blocks.into_iter().collect(),
                exits: exits.into_iter().collect(),
            }
        })
        .collect();
    Ok(ControlFlow {
        entry: ssa.entry,
        immediate_dominators,
        loops,
        limitations: vec![
            "Natural-loop/dominator structure only; irreducible cycles are not fabricated as structured loops."
                .to_owned(),
            "Unknown dispatch and external transfers remain outside the internal graph.".to_owned(),
        ],
    })
}
