//! Measurement only: the existing fuzzy matcher (`rampage_signatures::fuzzy`) as a third deterministic arm after the
//! bundled databases (docs/plans/2026-11-08-flywheel-code-candidates.md, step 1). References are the training
//! split's truth functions; queries are the discovered functions the bundled databases leave unnamed. Nothing here
//! is promoted or shipped.

use std::collections::BTreeMap;
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

/// Each discovered function's fuzzy descriptor in one corpus binary, and how many were refused by extraction.
fn describe(engine: &Engine, index: usize, loaded: &Loaded) -> Result<(Vec<Described>, usize), FlywheelError> {
    let entry = engine.binary(index);
    let path = engine.corpus.path(&entry.stripped);
    let binary = rampage_loaders::Binary::open(&path).map_err(|error| FlywheelError::io_text(&path, error))?;
    let project = Project::new(binary);
    project.set_packs(Arc::new(Packs::default()));
    let analysis = project.analysis().map_err(|error| FlywheelError::Corpus(format!("{}: {error}", entry.id)))?;
    let mut known: BTreeMap<u64, KnownCallee> = loaded
        .baseline
        .iter()
        .map(|(&address, name)| {
            (address, KnownCallee { name: name.clone(), provenance: CalleeProvenance::ExactSignatureProposal })
        })
        .collect();
    for (address, name) in rampage_analysis::functions::stub_names(&project.binary) {
        known.entry(address).or_insert(KnownCallee { name, provenance: CalleeProvenance::Import });
    }
    let mut described = Vec::new();
    let mut refused = 0;
    for function in &analysis.program.functions {
        let features =
            fuzzy_code_projection(&project.binary, &analysis.program, function).ok().and_then(|projection| {
                rampage_signatures::fuzzy::extract_features(&project.binary, &projection, &known).ok()
            });
        match features {
            Some(features) => described.push(Described { address: function.address, features }),
            None => refused += 1,
        }
    }
    Ok((described, refused))
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
    pub queries: Vec<FuzzyQuery>,
    /// Unnamed discovered functions with no descriptor (too small, too few blocks or constants, or refused).
    pub query_refused: usize,
    /// Unnamed functions with a descriptor but no compatible reference.
    pub query_unmatched: usize,
    /// Per query binary: truth address -> whether it has a descriptor (reach).
    pub described: BTreeMap<usize, Vec<u64>>,
}

/// Builds references from `train` (truth names, one per distinct descriptor) and ranks every unnamed discovered
/// function of `queries` against them.
pub fn measure(engine: &Engine, train: &[usize], queries: &[usize]) -> Result<FuzzyMeasurement, FlywheelError> {
    let described = engine.parallel(train, |index| {
        let loaded = engine.get(index)?;
        let (described, refused) = describe(engine, index, &loaded)?;
        let references: Vec<(String, FuzzyFeatures)> = described
            .into_iter()
            .filter_map(|function| Some((loaded.truth.get(&function.address)?.name.clone(), function.features)))
            .collect();
        Ok((references, refused))
    })?;
    let mut measurement = FuzzyMeasurement::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut references = Vec::new();
    for (list, refused) in described {
        measurement.reference_refused += refused;
        for (name, features) in list {
            let key = (name.clone(), serde_json::to_string(&features).map_err(FlywheelError::json)?);
            if seen.insert(key) {
                references.push(FuzzyReference {
                    name,
                    provenance: ReferenceProvenance {
                        library: "flywheel".to_owned(),
                        source: "train".to_owned(),
                        cohort: "train".to_owned(),
                        image_sha256: None,
                        executable_sha256: None,
                    },
                    features,
                });
            }
        }
    }
    measurement.references = references.len();
    let database = FuzzyDb::new(references).map_err(|error| FlywheelError::Corpus(error.to_string()))?;
    let results = engine.parallel(queries, |index| {
        let loaded = engine.get(index)?;
        let (described, refused) = describe(engine, index, &loaded)?;
        let mut found = Vec::new();
        let mut unmatched = 0;
        let mut reach = Vec::new();
        let mut unnamed_refused = refused;
        for function in described {
            if loaded.truth.contains_key(&function.address) {
                reach.push(function.address);
            }
            if loaded.baseline.contains_key(&function.address) {
                continue;
            }
            let report = database.candidates(&function.features, "query", 2);
            let Ok(report) = report else {
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
        Ok((index, found, unnamed_refused, unmatched, reach))
    })?;
    for (index, found, refused, unmatched, reach) in results {
        measurement.queries.extend(found);
        measurement.query_refused += refused;
        measurement.query_unmatched += unmatched;
        measurement.described.insert(index, reach);
    }
    Ok(measurement)
}
