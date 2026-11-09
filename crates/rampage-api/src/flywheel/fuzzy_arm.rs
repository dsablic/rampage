//! Measurement only: the existing fuzzy matcher (`rampage_signatures::fuzzy`) as a third deterministic arm after the
//! bundled databases (docs/plans/2026-11-08-flywheel-code-candidates.md, step 1). References are the training
//! split's truth functions; queries are the discovered functions the bundled databases leave unnamed. Nothing here
//! is promoted or shipped.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rampage_signatures::fuzzy::{
    CalleeProvenance, FuzzyDb, FuzzyFeatures, FuzzyReference, KnownCallee, ReferenceProvenance,
};
use serde::Serialize;

use super::FlywheelError;
use super::engine::{Engine, Loaded};
use crate::{Packs, Project, fuzzy_code_projection};

/// One discovered function's descriptor, with the known callees taken from the bundled databases' names.
struct Described {
    address: u64,
    features: FuzzyFeatures,
}

/// Why a discovered function has no descriptor, with its size.
#[derive(Debug, Clone, Serialize)]
pub struct Refusal {
    pub reason: String,
    pub instructions: usize,
    pub blocks: usize,
}

/// (architecture, caller name).
pub type CallerKey = (String, String);

/// Per function: its call targets in call-site order.
type Calls = BTreeMap<u64, Vec<u64>>;

/// One analysed corpus binary: descriptors, refusals and call sequences.
struct Analysed {
    described: Vec<Described>,
    refused: BTreeMap<u64, Refusal>,
    calls: Calls,
}

/// Each discovered function's fuzzy descriptor in one corpus binary, the refused ones, and the call sequences.
fn describe(engine: &Engine, index: usize, names: &BTreeMap<u64, String>) -> Result<Analysed, FlywheelError> {
    let entry = engine.binary(index);
    let path = engine.corpus.path(&entry.stripped);
    let binary = rampage_loaders::Binary::open(&path).map_err(|error| FlywheelError::io_text(&path, error))?;
    let project = Project::new(binary);
    project.set_packs(Arc::new(Packs::default()));
    let analysis = project.analysis().map_err(|error| FlywheelError::Corpus(format!("{}: {error}", entry.id)))?;
    let mut known: BTreeMap<u64, KnownCallee> = names
        .iter()
        .map(|(&address, name)| {
            (address, KnownCallee { name: name.clone(), provenance: CalleeProvenance::ExactSignatureProposal })
        })
        .collect();
    for (address, name) in rampage_analysis::functions::stub_names(&project.binary) {
        known.entry(address).or_insert(KnownCallee { name, provenance: CalleeProvenance::Import });
    }
    let mut described = Vec::new();
    let mut refused = BTreeMap::new();
    for function in &analysis.program.functions {
        let features = fuzzy_code_projection(&project.binary, &analysis.program, function)
            .map_err(|error| error.to_string())
            .and_then(|projection| {
                rampage_signatures::fuzzy::extract_features(&project.binary, &projection, &known)
                    .map_err(|error| error.to_string())
            });
        match features {
            Ok(features) => described.push(Described { address: function.address, features }),
            Err(reason) => {
                refused.insert(
                    function.address,
                    Refusal { reason, instructions: function.instruction_count, blocks: function.blocks.len() },
                );
            }
        }
    }
    let calls = crate::signatures::call_sequences(&project.binary, &analysis.program);
    Ok(Analysed { described, refused, calls })
}

/// One query's best reference: the top-ranked name, its score and its margin to the next name.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzyQuery {
    pub index: usize,
    pub address: u64,
    pub name: String,
    pub score: f64,
    pub margin: f64,
    pub collision: bool,
}

/// What the measurement found: queries per binary, plus coverage counters.
#[derive(Debug, Default, Serialize)]
pub struct FuzzyMeasurement {
    pub references: usize,
    pub reference_refused: usize,
    /// Dev and negative queries against every training reference; training queries (leave one build out) against
    /// the references of the other training builds.
    pub queries: Vec<FuzzyQuery>,
    /// Unnamed discovered functions with no descriptor (too small, too few blocks or constants, or refused).
    pub query_refused: usize,
    /// Unnamed functions with a descriptor but no compatible reference.
    pub query_unmatched: usize,
    /// Per query binary: truth addresses with a descriptor (reach).
    pub described: BTreeMap<usize, Vec<u64>>,
    /// Training call sequences by architecture and caller truth name, with the builds each occurs in.
    #[serde(skip)]
    pub train_calls: rampage_signatures::CallGraph,
    /// Per query binary: each discovered function's call targets.
    #[serde(skip)]
    pub query_calls: BTreeMap<usize, Calls>,
    /// Per query binary: truth addresses without one, and why.
    pub refusals: BTreeMap<usize, BTreeMap<u64, Refusal>>,
}

/// The build a corpus binary's library code comes from: binaries sharing it share the library's bodies.
pub fn build_key(engine: &Engine, index: usize) -> String {
    let entry = engine.binary(index);
    entry.library_object_sha256.clone().unwrap_or_else(|| entry.id.clone())
}

fn database(
    references: &[(String, String, FuzzyFeatures)],
    exclude: Option<&str>,
) -> Result<(FuzzyDb, usize), FlywheelError> {
    let mut seen = BTreeSet::new();
    let mut chosen = Vec::new();
    for (build, name, features) in references {
        if exclude == Some(build.as_str()) {
            continue;
        }
        let key = (name.clone(), serde_json::to_string(features).map_err(FlywheelError::json)?);
        if seen.insert(key) {
            chosen.push(FuzzyReference {
                name: name.clone(),
                provenance: ReferenceProvenance {
                    library: "flywheel".to_owned(),
                    source: "train".to_owned(),
                    cohort: "train".to_owned(),
                    image_sha256: None,
                    executable_sha256: None,
                },
                features: features.clone(),
            });
        }
    }
    let count = chosen.len();
    Ok((FuzzyDb::new(chosen).map_err(|error| FlywheelError::Corpus(error.to_string()))?, count))
}

/// What one query binary contributes to the measurement.
type QueryResult = (usize, Vec<FuzzyQuery>, usize, usize, Vec<u64>, BTreeMap<u64, Refusal>, Calls);

fn query(
    index: usize,
    loaded: &Loaded,
    names: &BTreeMap<u64, String>,
    analysed: Analysed,
    database: &FuzzyDb,
) -> QueryResult {
    let Analysed { described, refused, calls } = analysed;
    let mut found = Vec::new();
    let mut unmatched = 0;
    let mut reach = Vec::new();
    let mut unnamed_refused = refused.len();
    let refusals: BTreeMap<u64, Refusal> =
        refused.into_iter().filter(|(address, _)| loaded.truth.contains_key(address)).collect();
    for function in described {
        if loaded.truth.contains_key(&function.address) {
            reach.push(function.address);
        }
        if names.contains_key(&function.address) {
            continue;
        }
        let Ok(report) = database.candidates(&function.features, "query", 2) else {
            unnamed_refused += 1;
            continue;
        };
        match report.candidates.first() {
            Some(top) => found.push(FuzzyQuery {
                index,
                address: function.address,
                name: top.name.clone(),
                score: top.score.total,
                margin: top.margin_to_next_name,
                collision: top.identical_feature_collision,
            }),
            None => unmatched += 1,
        }
    }
    (index, found, unnamed_refused, unmatched, reach, refusals, calls)
}

/// Builds references from `train` (truth names, one per distinct descriptor) and ranks every unnamed discovered
/// function of `queries` against them, and of each training binary against the other training builds'.
/// The names a query binary starts from: `base`'s, or the bundled databases' (the cached baseline).
pub fn base_names<'a>(loaded: &'a Loaded, base: &'a Names, index: usize) -> &'a BTreeMap<u64, String> {
    base.get(&index).unwrap_or(&loaded.baseline)
}

/// Names per corpus binary.
pub type Names = BTreeMap<usize, BTreeMap<u64, String>>;

/// `base` holds the names each query binary starts from (bundled plus earlier arms); a binary it lacks starts from
/// the bundled databases' names. Training binaries always start from the bundled names.
pub fn measure(
    engine: &Engine,
    train: &[usize],
    queries: &[usize],
    base: &Names,
) -> Result<FuzzyMeasurement, FlywheelError> {
    let analysed = engine.parallel(train, |index| {
        let loaded = engine.get(index)?;
        let build = build_key(engine, index);
        let analysed = describe(engine, index, &loaded.baseline)?;
        let references: Vec<(String, String, FuzzyFeatures)> = analysed
            .described
            .iter()
            .filter_map(|function| {
                // Target-library functions only: the runtime (libc, compiler runtime) earns nothing in the gated
                // score, and its near-identical siblings are where fuzzy matching goes wrong.
                let truth =
                    loaded.truth.get(&function.address).filter(|truth| truth.origin != super::engine::RUNTIME)?;
                Some((build.clone(), truth.name.clone(), function.features.clone()))
            })
            .collect();
        let sequences: Vec<(CallerKey, Vec<Option<String>>)> = analysed
            .calls
            .iter()
            .filter_map(|(caller, targets)| {
                let name = loaded.truth.get(caller)?.name.clone();
                let named = targets.iter().map(|target| loaded.truth.get(target).map(|truth| truth.name.clone()));
                Some(((loaded.binary.arch.to_string(), name), named.collect()))
            })
            .collect();
        Ok((index, analysed, references, sequences))
    })?;
    let mut measurement = FuzzyMeasurement::default();
    let mut references = Vec::new();
    let mut train_analyses = BTreeMap::new();
    for (index, analysed, list, sequences) in analysed {
        measurement.reference_refused += analysed.refused.len();
        let build = build_key(engine, index);
        for (key, sequence) in sequences {
            measurement.train_calls.insert(&key.0, &key.1, sequence, Some(&build));
        }
        references.extend(list);
        train_analyses.insert(index, analysed);
    }
    let (full, count) = database(&references, None)?;
    measurement.references = count;
    let mut results = engine.parallel(queries, |index| {
        let loaded = engine.get(index)?;
        let names = base_names(&loaded, base, index);
        let analysed = describe(engine, index, names)?;
        Ok(query(index, &loaded, names, analysed, &full))
    })?;
    let builds: BTreeSet<String> = train.iter().map(|&index| build_key(engine, index)).collect();
    let builds: Vec<String> = builds.into_iter().collect();
    let databases = engine.parallel(&(0..builds.len()).collect::<Vec<_>>(), |position| {
        Ok((builds[position].clone(), database(&references, Some(&builds[position]))?.0))
    })?;
    let databases: BTreeMap<String, FuzzyDb> = databases.into_iter().collect();
    let train_analyses = std::sync::Mutex::new(train_analyses);
    results.extend(engine.parallel(train, |index| {
        let loaded = engine.get(index)?;
        let analysed = train_analyses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&index)
            .ok_or_else(|| FlywheelError::Corpus("training analysis missing".to_owned()))?;
        let database = &databases[&build_key(engine, index)];
        Ok(query(index, &loaded, &loaded.baseline, analysed, database))
    })?);
    for (index, found, refused, unmatched, reach, refusals, calls) in results {
        measurement.query_calls.insert(index, calls);
        measurement.refusals.insert(index, refusals);
        measurement.queries.extend(found);
        measurement.query_refused += refused;
        measurement.query_unmatched += unmatched;
        measurement.described.insert(index, reach);
    }
    Ok(measurement)
}

/// The names call-graph propagation (`rampage_signatures::callgraph`) adds to `names` on one corpus binary, from the
/// training call sequences; a training binary uses only the other training builds' sequences.
pub fn propagate(
    engine: &Engine,
    measurement: &FuzzyMeasurement,
    index: usize,
    names: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    let Some(calls) = measurement.query_calls.get(&index) else { return BTreeMap::new() };
    let own = build_key(engine, index);
    measurement.train_calls.propagate(&engine.binary(index).arch, calls, names, Some(&own))
}
