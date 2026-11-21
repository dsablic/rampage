//! The names a rampage build gives every binary of one corpus split, for gating a source change
//! (docs/flywheel.md, "The code loop"). The build under test only identifies: it writes names per binary and the
//! time identification took, and never reads truth outside the training split. A separate, trusted process scores
//! the names of the base build and of the candidate build against truth ([`proposals`] and
//! [`super::evaluation::compare`]).
//!
//! Identification is production's ([`super::engine::identify_parts`]): the compiled-in databases, then call-graph
//! propagation. Discovery (function extents, call sequences, loader names) is the base build's, read from its cache
//! ([`Engine::with_discovery_key`]), so base and candidate identify exactly the same bodies. On the training split
//! the call graph is made from the training truth with each binary's own library build left out, since the shipped
//! graph is that split's sequences and would answer its own binaries in-sample.

use std::collections::BTreeMap;
use std::time::Instant;

use rampage_signatures::{CallGraph, MaskContext};
use serde::{Deserialize, Serialize};

use super::FlywheelError;
use super::corpus::Split;
use super::engine::{Engine, Parts, Proposals, identify_parts};
use super::fuzzy_arm::build_key;

/// How a split's call graph was chosen.
pub const PRODUCTION_GRAPH: &str = "production";
/// The training split's graph, each binary's own build left out.
pub const LEAVE_ONE_BUILD_OUT: &str = "leave-one-build-out";

/// One binary's names and how long identifying it took.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryNames {
    pub names: BTreeMap<u64, String>,
    /// Identification alone (databases and propagation), not discovery, in microseconds.
    pub identify_us: u64,
}

/// The names one build gave every binary of a split, keyed by binary id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SplitNames {
    pub split: Split,
    /// The build that identified ([`super::build_id`]).
    pub build_id: String,
    /// The build whose discovery was used.
    pub discovery_key: String,
    /// [`PRODUCTION_GRAPH`] or [`LEAVE_ONE_BUILD_OUT`].
    pub call_graph: String,
    pub binaries: BTreeMap<String, BinaryNames>,
}

/// Identifies every binary of `split` with this build. Only the training split reads truth (for its call graph).
pub fn split_names(engine: &Engine, split: Split) -> Result<SplitNames, FlywheelError> {
    let indices = engine.corpus.indices(split);
    let graph = if split == Split::Train || split == Split::Fast { Some(training_graph(engine)?) } else { None };
    let results = engine.parallel(&indices, |index| {
        let entry = engine.binary(index);
        let path = engine.corpus.path(&entry.stripped);
        let binary = rampage_loaders::Binary::open(&path).map_err(|error| FlywheelError::io_text(&path, error))?;
        let (functions, _, calls, existing) = engine.baseline(index)?;
        let image = MaskContext::from_binary(&binary);
        let bodies: Vec<(u64, &[u8])> = functions
            .iter()
            .filter_map(|&(start, end)| Some((start, binary.read(start, end.checked_sub(start)?)?)))
            .collect();
        let build = build_key(engine, index);
        let chosen = match (&graph, rampage_signatures::bundled_embedded_for(&binary)) {
            (_, Some(_)) => rampage_signatures::bundled_embedded_call_graph().map(|graph| (graph, None)),
            (Some(graph), None) => Some((graph, Some(build.as_str()))),
            (None, None) => rampage_signatures::bundled_call_graph_for(&binary).map(|graph| (graph, None)),
        };
        let parts = Parts { binary: &binary, image: &image, bodies: &bodies, calls: &calls, existing: &existing };
        let started = Instant::now();
        let names = identify_parts(&parts, &[], None, chosen);
        let identify_us = started.elapsed().as_micros() as u64;
        Ok((entry.id.clone(), BinaryNames { names, identify_us }))
    })?;
    Ok(SplitNames {
        split,
        build_id: super::build_id().to_owned(),
        discovery_key: engine.discovery_key().to_owned(),
        call_graph: if graph.is_some() { LEAVE_ONE_BUILD_OUT } else { PRODUCTION_GRAPH }.to_owned(),
        binaries: results.into_iter().collect(),
    })
}

/// Each training library function's call sequence (callee names from the truth), with the library build it was
/// seen in, as `rampage-eval bundle --call-graph` makes the shipped graph but keeping the builds.
pub fn training_graph(engine: &Engine) -> Result<CallGraph, FlywheelError> {
    let mut graph = CallGraph::new(engine.corpus.identity(), &engine.corpus.license());
    let train = engine.corpus.indices(Split::Train);
    engine.load_all(&train)?;
    for index in train {
        let loaded = engine.get(index)?;
        let arch = loaded.binary.arch.to_string();
        let build = build_key(engine, index);
        for (caller, targets) in &loaded.calls {
            let Some(truth) = loaded.truth.get(caller) else { continue };
            let callees = targets.iter().map(|target| loaded.truth.get(target).map(|truth| truth.name.clone()));
            graph.insert(&arch, &truth.name, callees.collect(), Some(&build));
        }
    }
    Ok(graph)
}

/// `names` as the proposals [`super::evaluation::compare`] scores, by corpus index. A binary of the split that
/// `names` lacks is an error: a names file from another corpus or split must not score as "named nothing".
pub fn proposals(engine: &Engine, split: Split, names: &SplitNames) -> Result<Proposals, FlywheelError> {
    let mut out = BTreeMap::new();
    for index in engine.corpus.indices(split) {
        let id = &engine.binary(index).id;
        let binary = names
            .binaries
            .get(id)
            .ok_or_else(|| FlywheelError::Corpus(format!("the {} names have no binary {id}", split.name())))?;
        out.insert(index, binary.names.clone());
    }
    Ok(Proposals { names: out, reidentified: 0, elapsed_ms: 0 })
}
