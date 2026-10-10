//! Builds a decision tree over the encodings: each switch node selects a child by a run of instruction bits
//! that its candidates fix, and each leaf lists the few candidates still left to test in full.

use std::fmt::Write;

use crate::Encoding;

/// Stop splitting when this few candidates remain.
const LEAF_SIZE: usize = 3;
/// The widest bit run a single switch consumes.
const MAX_SWITCH_BITS: u32 = 8;

#[derive(Clone, Copy)]
pub enum Node {
    Switch { shift: u32, bits: u32, first: usize },
    Leaf { first: usize, count: usize },
}

pub struct Tree {
    pub nodes: Vec<Node>,
    pub candidates: Vec<usize>,
}

pub fn build(encodings: &[Encoding]) -> Tree {
    let mut tree = Tree { nodes: vec![Node::Leaf { first: 0, count: 0 }], candidates: Vec::new() };
    let all: Vec<usize> = (0..encodings.len()).collect();
    let root = tree.split(encodings, all, 0);
    tree.nodes[0] = root;
    tree
}

/// The longest run of set bits in `mask`, as (shift, width), capped at `MAX_SWITCH_BITS`.
fn longest_run(mask: u32) -> Option<(u32, u32)> {
    let mut best: Option<(u32, u32)> = None;
    let mut bit = 0;
    while bit < 32 {
        if mask & (1 << bit) == 0 {
            bit += 1;
            continue;
        }
        let start = bit;
        while bit < 32 && mask & (1 << bit) != 0 {
            bit += 1;
        }
        let width = bit - start;
        if best.is_none_or(|(_, w)| width > w) {
            best = Some((start, width));
        }
    }
    // Keep the most significant bits of a long run: they separate encoding classes best.
    best.map(|(start, width)| {
        let bits = width.min(MAX_SWITCH_BITS);
        (start + width - bits, bits)
    })
}

impl Tree {
    fn split(&mut self, encodings: &[Encoding], mut set: Vec<usize>, used: u32) -> Node {
        let leaf = |tree: &mut Tree, mut set: Vec<usize>| {
            // Most specific first, so overlapping patterns resolve to the narrower encoding.
            set.sort_by_key(|&i| std::cmp::Reverse(encodings[i].mask.count_ones()));
            let first = tree.candidates.len();
            tree.candidates.extend(&set);
            Node::Leaf { first, count: set.len() }
        };
        if set.len() <= LEAF_SIZE {
            return leaf(self, set);
        }

        let common = set.iter().fold(!used, |acc, &i| acc & encodings[i].mask);
        let (shift, bits) = match longest_run(common) {
            Some(run) => run,
            None => {
                // No bit is fixed by every candidate: split on the bit fixed by the most of them, and send
                // candidates that leave it open down both sides.
                let best = (0..32)
                    .filter(|bit| used & (1 << bit) == 0)
                    .max_by_key(|&bit| set.iter().filter(|&&i| encodings[i].mask & (1 << bit) != 0).count());
                match best {
                    Some(bit) if set.iter().any(|&i| encodings[i].mask & (1 << bit) != 0) => (bit, 1),
                    _ => return leaf(self, set),
                }
            }
        };

        let field_mask = ((1u64 << bits) - 1) as u32;
        let first = self.nodes.len();
        let count = 1usize << bits;
        self.nodes.extend(std::iter::repeat_n(Node::Leaf { first: 0, count: 0 }, count));
        set.sort_unstable();
        for value in 0..count as u32 {
            let subset: Vec<usize> = set
                .iter()
                .copied()
                .filter(|&i| {
                    let encoding = &encodings[i];
                    let fixed = (encoding.mask >> shift) & field_mask;
                    (encoding.value >> shift) & fixed == value & fixed
                })
                .collect();
            let child = self.split(encodings, subset, used | (field_mask << shift));
            self.nodes[first + value as usize] = child;
        }
        Node::Switch { shift, bits, first }
    }

    pub fn emit(&self, out: &mut String) -> std::fmt::Result {
        writeln!(out, "pub static NODES: [Node; {}] = [", self.nodes.len())?;
        for node in &self.nodes {
            match *node {
                Node::Switch { shift, bits, first } => writeln!(out, "    sw({shift}, {bits}, {first}),")?,
                Node::Leaf { first, count } => writeln!(out, "    leaf({first}, {count}),")?,
            }
        }
        writeln!(out, "];")?;
        writeln!(out)?;
        writeln!(out, "pub static CANDIDATES: [u16; {}] = {:?};", self.candidates.len(), self.candidates)
    }
}
