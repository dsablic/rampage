//! Call-graph propagation: naming a function from where an already-named caller calls it.
//!
//! The data is each training library function's call sequence: its direct calls and unconditional tail jumps to
//! other functions,
//! in call-site order, as the callees' names (or `None` for a callee that is no library or runtime function). A
//! named caller in a target whose sequence fits a training sequence of the same name and architecture names its
//! unnamed callees by position. Measured on the flywheel corpus (docs/plans/2026-11-05-flywheel-fast-loop.md,
//! "Call-graph propagation").
//!
//! A callee is named only when:
//! - every usable training sequence of the caller's name with the target's length agrees with the caller's
//!   already-named callees, and all of them give the same name at the callee's position;
//! - the callee's own call sequence fits a training sequence of that name (two-sided), and, when it calls anything,
//!   one of its calls is already named and agrees (anchored), so an inlined wrapper's position is not enough;
//! - no other function has that name, no other callee is offered it, and the callee is offered no other name.
//!
//! The rule repeats until nothing changes. It never renames a function that already has a name.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::SignatureDbError;

const SCHEMA: u32 = 1;

/// One training call sequence of a caller name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallSequence {
    /// The callees' names in call-site order; `None` for a callee that is no library or runtime function.
    pub callees: Vec<Option<String>>,
    /// The training builds the sequence occurs in, for measurement that leaves a build out. Empty in shipped data.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub builds: BTreeSet<String>,
}

/// Training call sequences by architecture and caller name, with provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallGraph {
    pub schema: u32,
    /// Where the sequences come from (a flywheel corpus identity, or empty for none).
    pub source: String,
    /// The SPDX licence expression of the code the names were read from.
    pub license: String,
    /// Architecture name -> caller name -> distinct sequences.
    pub arches: BTreeMap<String, BTreeMap<String, Vec<CallSequence>>>,
}

impl CallGraph {
    pub fn new(source: &str, license: &str) -> CallGraph {
        CallGraph { schema: SCHEMA, source: source.to_owned(), license: license.to_owned(), arches: BTreeMap::new() }
    }

    /// Records one caller's sequence, seen in `build` (for leave-one-build-out measurement) or none.
    pub fn insert(&mut self, arch: &str, caller: &str, callees: Vec<Option<String>>, build: Option<&str>) {
        let sequences = self.arches.entry(arch.to_owned()).or_default().entry(caller.to_owned()).or_default();
        let index = match sequences.iter().position(|sequence| sequence.callees == callees) {
            Some(index) => index,
            None => {
                sequences.push(CallSequence { callees, builds: BTreeSet::new() });
                sequences.len() - 1
            }
        };
        if let Some(build) = build {
            sequences[index].builds.insert(build.to_owned());
        }
    }

    /// The same sequences without their builds, sorted: what ships.
    pub fn without_builds(&self) -> CallGraph {
        let mut graph = CallGraph::new(&self.source, &self.license);
        for (arch, callers) in &self.arches {
            for (caller, sequences) in callers {
                for sequence in sequences {
                    graph.insert(arch, caller, sequence.callees.clone(), None);
                }
            }
        }
        for callers in graph.arches.values_mut() {
            for sequences in callers.values_mut() {
                sequences.sort();
            }
        }
        graph
    }

    /// How many caller names the graph holds over every architecture.
    pub fn callers(&self) -> usize {
        self.arches.values().map(BTreeMap::len).sum()
    }

    pub fn from_gzip(bytes: &[u8]) -> Result<CallGraph, SignatureDbError> {
        let json = crate::compressed::decode_gzip(bytes)?;
        let graph: CallGraph =
            serde_json::from_slice(&json).map_err(|_| SignatureDbError::InvalidDatabase("call graph JSON"))?;
        if graph.schema != SCHEMA {
            return Err(SignatureDbError::InvalidDatabase("call graph schema"));
        }
        Ok(graph)
    }

    pub fn to_gzip(&self) -> Vec<u8> {
        use std::io::Write;
        let json = serde_json::to_vec(self).expect("a call graph serializes");
        let mut encoder = flate2::GzBuilder::new().mtime(0).write(Vec::new(), flate2::Compression::best());
        encoder.write_all(&json).expect("writing to memory");
        encoder.finish().expect("writing to memory")
    }

    /// The names propagation adds to `names` on one binary of `arch`, where `calls` holds each discovered
    /// function's call targets (function starts, in call-site order). Sequences seen only in `exclude` are not
    /// used (a measurement leaving that build out). See the module documentation for the rule.
    pub fn propagate(
        &self,
        arch: &str,
        calls: &BTreeMap<u64, Vec<u64>>,
        names: &BTreeMap<u64, String>,
        exclude: Option<&str>,
    ) -> BTreeMap<u64, String> {
        let Some(callers) = self.arches.get(arch) else { return BTreeMap::new() };
        let usable = |sequence: &CallSequence| {
            sequence.builds.is_empty() || sequence.builds.iter().any(|build| Some(build.as_str()) != exclude)
        };
        let agrees = |names: &BTreeMap<u64, String>, targets: &[u64], sequence: &CallSequence| {
            sequence.callees.len() == targets.len()
                && targets.iter().zip(&sequence.callees).all(|(target, expected)| match names.get(target) {
                    Some(known) => expected.as_deref() == Some(known.as_str()),
                    None => true,
                })
        };
        // Whether a callee's own calls fit a training sequence of `name`, anchored by an already-named call.
        let fits = |names: &BTreeMap<u64, String>, name: &str, targets: &[u64]| {
            let anchored = targets.is_empty() || targets.iter().any(|target| names.contains_key(target));
            anchored
                && callers.get(name).is_some_and(|sequences| {
                    sequences
                        .iter()
                        .filter(|sequence| usable(sequence))
                        .any(|sequence| agrees(names, targets, sequence))
                })
        };
        let mut names = names.clone();
        let mut added = BTreeMap::new();
        let mut refused: BTreeSet<u64> = BTreeSet::new();
        // Names two callees were offered at once: ambiguous for good, not only for that round.
        let mut refused_names: BTreeSet<String> = BTreeSet::new();
        loop {
            let used: BTreeSet<&String> = names.values().collect();
            let mut offers: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
            for (caller, targets) in calls {
                let Some(sequences) = names.get(caller).and_then(|name| callers.get(name)) else { continue };
                if targets.iter().all(|target| names.contains_key(target)) {
                    continue;
                }
                let matching: Vec<&CallSequence> =
                    sequences.iter().filter(|sequence| usable(sequence) && agrees(&names, targets, sequence)).collect();
                if matching.is_empty() {
                    continue;
                }
                for (position, target) in targets.iter().enumerate() {
                    if names.contains_key(target) || refused.contains(target) {
                        continue;
                    }
                    let proposed: BTreeSet<Option<&str>> =
                        matching.iter().map(|sequence| sequence.callees[position].as_deref()).collect();
                    let [Some(name)] = proposed.into_iter().collect::<Vec<_>>()[..] else { continue };
                    let own = calls.get(target).map(Vec::as_slice).unwrap_or_default();
                    if !used.contains(&name.to_owned()) && !refused_names.contains(name) && fits(&names, name, own) {
                        offers.entry(*target).or_default().insert(name.to_owned());
                    }
                }
            }
            let mut claimed: BTreeMap<String, Vec<u64>> = BTreeMap::new();
            for (target, offered) in offers {
                match offered.len() {
                    1 => claimed.entry(offered.into_iter().next().unwrap_or_default()).or_default().push(target),
                    _ => {
                        refused.insert(target);
                    }
                }
            }
            let mut changed = false;
            for (name, targets) in claimed {
                if let [target] = targets[..] {
                    names.insert(target, name.clone());
                    added.insert(target, name);
                    changed = true;
                } else {
                    refused.extend(targets);
                    refused_names.insert(name);
                }
            }
            if !changed {
                return added;
            }
        }
    }
}

/// The compressed call graph shipped with rampage (`data/callgraph.json.gz`).
pub const BUNDLED_BYTES: &[u8] = include_bytes!("../data/callgraph.json.gz");

static BUNDLED: OnceLock<Result<CallGraph, SignatureDbError>> = OnceLock::new();

/// The call graph shipped with rampage, or `None` when it does not load or holds no sequence.
pub fn bundled_call_graph() -> Option<&'static CallGraph> {
    BUNDLED.get_or_init(|| CallGraph::from_gzip(BUNDLED_BYTES)).as_ref().ok().filter(|graph| graph.callers() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> CallGraph {
        let mut graph = CallGraph::new("test", "MIT");
        let some = |name: &str| Some(name.to_owned());
        graph.insert("x86_64", "outer", vec![some("helper"), some("leaf"), None], Some("a"));
        graph.insert("x86_64", "helper", vec![some("leaf")], Some("a"));
        graph.insert("x86_64", "leaf", vec![], Some("a"));
        graph
    }

    fn names(pairs: &[(u64, &str)]) -> BTreeMap<u64, String> {
        pairs.iter().map(|(address, name)| (*address, (*name).to_owned())).collect()
    }

    #[test]
    fn a_named_caller_names_its_callees_by_position_to_a_fixed_point() {
        // outer (0x10) calls helper (0x20), leaf (0x30) and program code (0x40); helper calls leaf.
        let calls: BTreeMap<u64, Vec<u64>> =
            [(0x10, vec![0x20, 0x30, 0x40]), (0x20, vec![0x30]), (0x30, vec![]), (0x40, vec![])].into();
        let added = graph().propagate("x86_64", &calls, &names(&[(0x10, "outer")]), None);
        // leaf first (it calls nothing), then helper, whose own call is now named and agrees.
        assert_eq!(added, names(&[(0x20, "helper"), (0x30, "leaf")]));
        // Another architecture, or the only build left out, gives nothing.
        assert!(graph().propagate("aarch64", &calls, &names(&[(0x10, "outer")]), None).is_empty());
        assert!(graph().propagate("x86_64", &calls, &names(&[(0x10, "outer")]), Some("a")).is_empty());
    }

    #[test]
    fn disagreement_length_and_used_names_block_propagation() {
        let calls: BTreeMap<u64, Vec<u64>> =
            [(0x10, vec![0x20, 0x30, 0x40]), (0x20, vec![0x30]), (0x30, vec![]), (0x40, vec![])].into();
        // A named callee that disagrees with training: the sequence does not fit.
        assert!(graph().propagate("x86_64", &calls, &names(&[(0x10, "outer"), (0x30, "other")]), None).is_empty());
        // A different length does not fit either.
        let short: BTreeMap<u64, Vec<u64>> = [(0x10, vec![0x20, 0x30]), (0x20, vec![0x30])].into();
        assert!(graph().propagate("x86_64", &short, &names(&[(0x10, "outer")]), None).is_empty());
        // A name some other function already has is not given again.
        let added = graph().propagate("x86_64", &calls, &names(&[(0x10, "outer"), (0x99, "leaf")]), None);
        assert!(!added.values().any(|name| name == "leaf"));
    }

    #[test]
    fn a_callee_must_fit_its_own_name_and_be_anchored() {
        // helper's position, but the function there calls an unnamed function: not anchored, so not named.
        let calls: BTreeMap<u64, Vec<u64>> = [(0x10, vec![0x20, 0x30, 0x40]), (0x20, vec![0x50])].into();
        let added = graph().propagate("x86_64", &calls, &names(&[(0x10, "outer")]), None);
        assert!(!added.contains_key(&0x20));
        // leaf's position, but the function there makes a call while leaf makes none: two-sided check fails.
        let calls: BTreeMap<u64, Vec<u64>> = [(0x10, vec![0x20, 0x30, 0x40]), (0x30, vec![0x10])].into();
        let added = graph().propagate("x86_64", &calls, &names(&[(0x10, "outer")]), None);
        assert!(!added.contains_key(&0x30));
    }

    #[test]
    fn gzip_round_trip_and_shipped_data_load() {
        let graph = graph().without_builds();
        assert!(graph.arches["x86_64"]["outer"][0].builds.is_empty());
        assert_eq!(CallGraph::from_gzip(&graph.to_gzip()).unwrap(), graph);
        assert!(CallGraph::from_gzip(BUNDLED_BYTES).is_ok());
    }
}
