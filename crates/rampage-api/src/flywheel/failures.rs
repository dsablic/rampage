//! The training split's disagreement set, grouped by masked body: every training binary where the same body (same
//! architecture, length and fixed bytes) was missed, named wrongly or named spuriously becomes one group, with
//! the bytes a signature row for it would match. Held-out binaries never enter it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::corpus::Split;
use super::engine::{Engine, Layer, Outcome};
use super::{FlywheelError, sha256_text};
use crate::flywheel::candidate::format_pattern;

/// Where the truth of every failure comes from.
pub const TRUTH_SOURCE: &str =
    "symbol table of the binary's symbolized twin (same linked image), program functions excluded";

/// The id of a training body: its architecture and masked pattern, hashed. The same body always has the same
/// id, whether it is a failure group, a variant or a deterministic-arm row.
pub fn case_id(arch: &str, pattern: &str) -> String {
    format!("f{}", &sha256_text(&format!("{arch}\0{pattern}"))[..15])
}

/// One group of training failures sharing a masked body.
#[derive(Debug, Clone, Serialize)]
pub struct FailureGroup {
    /// The id `propose_heuristic` takes to build a row from this body.
    pub case: String,
    pub arch: String,
    pub length: usize,
    /// Whether a row can hold the body: at least the gate's minimum pattern length and at most
    /// `MAX_PATTERN_BYTES`.
    pub proposable: bool,
    /// How often each outcome occurred across the group's binaries.
    pub missed: usize,
    pub wrong: usize,
    pub spurious: usize,
    /// Training binaries holding the body.
    pub occurrences: usize,
    /// The truth names at these addresses; more than one means the body is not one function's.
    pub truth_names: Vec<String>,
    /// Names the current databases give these addresses (for wrong and spurious ones).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proposed_names: Vec<String>,
    /// The truth functions' origin: their library, or `runtime`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,
    /// The architecture/compiler/opt configurations it was seen in.
    pub configurations: Vec<String>,
    /// The libraries of the programs it was seen in.
    pub libraries: Vec<String>,
    pub example: Example,
    /// The body with `..` for every byte scheme 2 masks as position-dependent.
    pub masked_bytes: String,
    pub wildcards: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Example {
    pub binary: String,
    pub address: String,
}

/// The training failures under one state of the promoted pack.
#[derive(Debug, Clone, Serialize)]
pub struct FailureSet {
    pub groups: Vec<FailureGroup>,
    /// Missed truth functions discovery never found: a signature cannot name them.
    pub undiscovered: usize,
    /// Missed bodies too small or uniform for the confidence gate: no signature can name them either.
    pub below_gate: usize,
    pub binaries: usize,
}

struct Building {
    arch: String,
    pattern: Vec<Option<u8>>,
    counts: BTreeMap<Outcome, usize>,
    binaries: BTreeSet<usize>,
    truth: BTreeSet<String>,
    proposed: BTreeSet<String>,
    origins: BTreeSet<String>,
    configurations: BTreeSet<String>,
    libraries: BTreeSet<String>,
    example: (usize, u64),
}

impl FailureSet {
    /// The training split's failures under `layers` (the current promoted state over the bundled databases), for
    /// the target libraries' functions and false names: runtime functions are not gated, so they are not listed.
    pub fn compute(engine: &Engine, layers: &[Layer], min_bytes: usize) -> Result<FailureSet, FlywheelError> {
        let indices = engine.corpus.indices(Split::Train);
        let proposals = engine.propose(&indices, layers)?;
        let mut groups: BTreeMap<(String, String), Building> = BTreeMap::new();
        let (mut undiscovered, mut below_gate) = (0, 0);
        for &index in &indices {
            let entry = engine.binary(index);
            let loaded = engine.get(index)?;
            let empty = BTreeMap::new();
            let names = proposals.names.get(&index).unwrap_or(&empty);
            let target = loaded.binary.target();
            for (address, outcome) in loaded.outcomes(names) {
                if outcome == Outcome::Correct
                    || loaded.truth.get(&address).is_some_and(|truth| truth.origin == super::engine::RUNTIME)
                {
                    continue;
                }
                if !loaded.discovered(address) {
                    undiscovered += 1;
                    continue;
                }
                let Some(body) = loaded.body(address) else {
                    undiscovered += 1;
                    continue;
                };
                let Some(pattern) = rampage_signatures::masked_body_in(&target, &loaded.image, body, address) else {
                    below_gate += 1;
                    continue;
                };
                let key = (entry.arch.clone(), format_pattern(&pattern));
                let group = groups.entry(key).or_insert_with(|| Building {
                    arch: entry.arch.clone(),
                    pattern: pattern.clone(),
                    counts: BTreeMap::new(),
                    binaries: BTreeSet::new(),
                    truth: BTreeSet::new(),
                    proposed: BTreeSet::new(),
                    origins: BTreeSet::new(),
                    configurations: BTreeSet::new(),
                    libraries: BTreeSet::new(),
                    example: (index, address),
                });
                *group.counts.entry(outcome).or_default() += 1;
                group.binaries.insert(index);
                if let Some(truth) = loaded.truth.get(&address) {
                    group.truth.insert(truth.name.clone());
                    group.origins.insert(truth.origin.clone());
                }
                if let Some(name) = names.get(&address) {
                    group.proposed.insert(name.clone());
                }
                group.configurations.insert(entry.configuration());
                group.libraries.insert(entry.library.clone());
            }
        }
        let mut groups: Vec<FailureGroup> = groups
            .into_values()
            .map(|group| {
                let pattern = format_pattern(&group.pattern);
                let count = |outcome| group.counts.get(&outcome).copied().unwrap_or(0);
                FailureGroup {
                    case: case_id(&group.arch, &pattern),
                    arch: group.arch,
                    length: group.pattern.len(),
                    proposable: (min_bytes..=crate::flywheel::MAX_PATTERN_BYTES).contains(&group.pattern.len()),
                    missed: count(Outcome::Missed),
                    wrong: count(Outcome::Wrong),
                    spurious: count(Outcome::Spurious),
                    occurrences: group.binaries.len(),
                    truth_names: group.truth.into_iter().collect(),
                    proposed_names: group.proposed.into_iter().collect(),
                    origins: group.origins.into_iter().collect(),
                    configurations: group.configurations.into_iter().collect(),
                    libraries: group.libraries.into_iter().collect(),
                    example: Example {
                        binary: engine.binary(group.example.0).id.clone(),
                        address: format!("{:#x}", group.example.1),
                    },
                    wildcards: group.pattern.iter().filter(|byte| byte.is_none()).count(),
                    masked_bytes: pattern,
                }
            })
            .collect();
        groups.sort_by(|a, b| b.occurrences.cmp(&a.occurrences).then_with(|| a.case.cmp(&b.case)));
        Ok(FailureSet { groups, undiscovered, below_gate, binaries: indices.len() })
    }

    pub fn find(&self, case: &str) -> Option<&FailureGroup> {
        self.groups.iter().find(|group| group.case == case)
    }
}
