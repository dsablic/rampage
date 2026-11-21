//! Measurement only: how much of what the bundled embedded firmware set misses on the held-out GCC 14.3 firmware
//! fixtures is reachable in principle, and how much of that a trivial deterministic baseline already takes
//! (docs/plans/2026-11-20-flywheel-next.md, step 2; report in docs/benchmarks/flywheel-headroom-2026-11-21.md).
//!
//! ```sh
//! cargo run --release -p rampage-eval --example embedded_headroom -- --out OUT.json \
//!   --target tests/fixtures/firmware/embedded-libs-m4f.elf --truth tests/fixtures/data/eval-truth-embedded-m4f.json \
//!   WORK/refs/*.elf
//! ```
//!
//! The references are the training toolchains' symbolized reference ELFs (`tools/embedded-signatures/build.py
//! refs`), never the held-out 14.3 ones. The baseline is `identify_functions` with the bundled databases, as the
//! product runs it. Each truth function the baseline does not name correctly is classified, in this order:
//! `undiscovered`; `absent` (no reference defines the name); `shared_body` (its scheme-3 masked hash is a reference
//! body of another name); `tiny` (1–3 instructions); `below_gate` (4–5 instructions, under the embedded set's
//! six-instruction gate); the last three split by context (a named caller or callee). Unreachable: `undiscovered`,
//! `absent`, and the context-free `shared_body` and `tiny`. Everything else is reachable in principle.
//!
//! Baselines over the unnamed functions: call-graph propagation from the references' call sequences (the shipped
//! rule, which has never been run on firmware), fuzzy matching at 0.95/0.05 against the references, and the same
//! one-feature miners as `flywheel_headroom` (body length, named-callee sequence, named callers; a value names a
//! function when every reference occurrence carries one name, in at least two references).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rampage_api::{Packs, Project, call_sequences, fuzzy_code_projection};
use rampage_loaders::Binary;
use rampage_signatures::fuzzy::{
    CalleeProvenance, FuzzyDb, FuzzyFeatures, FuzzyReference, KnownCallee, ReferenceProvenance,
};
use rampage_signatures::{CallGraph, LITERAL_POOL_SCHEME, MaskContext, canonical_functions, canonical_name};
use serde_json::json;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    out: PathBuf,
    /// The stripped held-out firmware ELF.
    #[arg(long)]
    target: PathBuf,
    /// Its truth ({"0x<address>": "<name>"}): library functions only.
    #[arg(long)]
    truth: PathBuf,
    /// Training reference ELFs (symbolized).
    references: Vec<PathBuf>,
}

/// A one-feature rule table: feature value → (names seen, references seen).
type Table = BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Feature {
    Length,
    Callees,
    Callers,
}

const FEATURES: [Feature; 3] = [Feature::Length, Feature::Callees, Feature::Callers];

impl Feature {
    fn tag(self) -> &'static str {
        match self {
            Feature::Length => "length",
            Feature::Callees => "callees",
            Feature::Callers => "callers",
        }
    }
}

/// One analysed binary: discovered extents, instruction counts, calls and callers, masked hashes.
struct Analysed {
    binary: Binary,
    program: rampage_analysis::discover::Program,
    extents: BTreeMap<u64, u64>,
    instructions: BTreeMap<u64, usize>,
    calls: BTreeMap<u64, Vec<u64>>,
    callers: BTreeMap<u64, BTreeSet<u64>>,
    hashes: BTreeMap<u64, String>,
}

fn analyse(path: &PathBuf) -> Result<Analysed, String> {
    let binary = Binary::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let program =
        rampage_analysis::functions::analyze(&binary).map_err(|error| format!("{}: {error}", path.display()))?;
    let extents: BTreeMap<u64, u64> = program.functions.iter().map(|f| (f.address, f.end())).collect();
    let instructions = program.functions.iter().map(|f| (f.address, f.instruction_count)).collect();
    let calls = call_sequences(&binary, &program);
    let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (caller, targets) in &calls {
        for target in targets {
            callers.entry(*target).or_default().insert(*caller);
        }
    }
    let target = binary.target();
    let image = MaskContext::from_binary(&binary);
    let mut hashes = BTreeMap::new();
    for (&address, &end) in &extents {
        let Some(bytes) = end.checked_sub(address).and_then(|size| binary.read(address, size)) else {
            continue;
        };
        if let Some(hash) =
            rampage_signatures::function_hash_scheme(LITERAL_POOL_SCHEME, &target, &image, bytes, address)
        {
            hashes.insert(address, hash.iter().map(|byte| format!("{byte:02x}")).collect());
        }
    }
    Ok(Analysed { binary, program, extents, instructions, calls, callers, hashes })
}

fn fuzzy_features(analysed: &Analysed, known: &BTreeMap<u64, String>) -> BTreeMap<u64, Result<FuzzyFeatures, String>> {
    let known: BTreeMap<u64, KnownCallee> = known
        .iter()
        .map(|(&address, name)| {
            (address, KnownCallee { name: name.clone(), provenance: CalleeProvenance::ExactSignatureProposal })
        })
        .collect();
    analysed
        .program
        .functions
        .iter()
        .map(|function| {
            let features = fuzzy_code_projection(&analysed.binary, &analysed.program, function)
                .map_err(|error| error.to_string())
                .and_then(|projection| {
                    rampage_signatures::fuzzy::extract_features(&analysed.binary, &projection, &known)
                        .map_err(|error| error.to_string())
                });
            (function.address, features)
        })
        .collect()
}

fn feature(kind: Feature, analysed: &Analysed, names: &dyn Fn(u64) -> Option<String>, address: u64) -> Option<String> {
    match kind {
        Feature::Length => analysed.extents.get(&address).map(|end| format!("{}", end - address)),
        Feature::Callees => {
            let named: Vec<Option<String>> =
                analysed.calls.get(&address)?.iter().map(|target| names(*target)).collect();
            named.iter().any(Option::is_some).then(|| format!("{named:?}"))
        }
        Feature::Callers => {
            let named: BTreeSet<String> =
                analysed.callers.get(&address)?.iter().filter_map(|caller| names(*caller)).collect();
            (!named.is_empty()).then(|| format!("{named:?}"))
        }
    }
}

fn main() -> Result<(), String> {
    let arguments = Arguments::parse();
    let truth_text = std::fs::read_to_string(&arguments.truth).map_err(|error| error.to_string())?;
    let truth: BTreeMap<String, String> = serde_json::from_str(&truth_text).map_err(|error| error.to_string())?;
    let truth: BTreeMap<u64, String> = truth
        .into_iter()
        .map(|(address, name)| u64::from_str_radix(address.trim_start_matches("0x"), 16).map(|address| (address, name)))
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?;

    // The references: names, masked hashes, call sequences, fuzzy references and one-feature tables.
    let mut reference_names: BTreeSet<String> = BTreeSet::new();
    // The reference bodies (discovered extents) of the names the truth holds, for the shape comparison.
    let wanted: BTreeSet<&String> = truth.values().collect();
    let mut reference_bodies: BTreeMap<String, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut hash_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut graph = CallGraph::new("embedded-references", "measurement");
    let mut fuzzy_references: BTreeMap<(String, String), FuzzyReference> = BTreeMap::new();
    let mut tables: BTreeMap<Feature, Table> = BTreeMap::new();
    let mut arch = String::new();
    let mut fuzzy_refusals: BTreeMap<String, u64> = BTreeMap::new();
    for path in &arguments.references {
        let analysed = analyse(path)?;
        let build = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        arch = analysed.binary.arch.to_string();
        let symbols: BTreeMap<u64, String> = canonical_functions(&analysed.binary)
            .into_iter()
            .map(|(address, symbol)| (address, canonical_name(&symbol.name).into_owned()))
            .collect();
        let name_of = |address: u64| symbols.get(&address).cloned();
        for (address, name) in &symbols {
            reference_names.insert(name.clone());
            if wanted.contains(name)
                && let Some(end) = analysed.extents.get(address)
                && let Some(bytes) = analysed.binary.read(*address, end - address)
            {
                reference_bodies.entry(name.clone()).or_default().insert(bytes.to_vec());
            }
            if let Some(hash) = analysed.hashes.get(address) {
                hash_names.entry(hash.clone()).or_default().insert(name.clone());
            }
            if !analysed.extents.contains_key(address) {
                continue;
            }
            for kind in FEATURES {
                if let Some(value) = feature(kind, &analysed, &name_of, *address) {
                    let entry = tables.entry(kind).or_default().entry(value).or_default();
                    entry.0.insert(name.clone());
                    entry.1.insert(build.clone());
                }
            }
        }
        for (caller, targets) in &analysed.calls {
            if let Some(name) = symbols.get(caller) {
                graph.insert(&arch, name, targets.iter().map(|target| name_of(*target)).collect(), Some(&build));
            }
        }
        for (address, features) in fuzzy_features(&analysed, &symbols) {
            let features = match features {
                Ok(features) => features,
                Err(reason) => {
                    *fuzzy_refusals.entry(reason.chars().take(80).collect()).or_default() += 1;
                    continue;
                }
            };
            let Some(name) = symbols.get(&address) else { continue };
            let key = (name.clone(), serde_json::to_string(&features).map_err(|error| error.to_string())?);
            fuzzy_references.entry(key).or_insert_with(|| FuzzyReference {
                name: name.clone(),
                provenance: ReferenceProvenance {
                    library: "embedded".to_owned(),
                    source: "train".to_owned(),
                    cohort: "train".to_owned(),
                    image_sha256: None,
                    executable_sha256: None,
                },
                features,
            });
        }
    }
    // The fuzzy database holds at most 100 000 references: keep up to eight distinct descriptors per name.
    let mut per_name: BTreeMap<String, usize> = BTreeMap::new();
    let chosen: Vec<FuzzyReference> = fuzzy_references
        .into_values()
        .filter(|reference| {
            let count = per_name.entry(reference.name.clone()).or_default();
            *count += 1;
            *count <= 8
        })
        .collect();
    let fuzzy_count = chosen.len();
    eprintln!("{fuzzy_count} fuzzy references over {} names", per_name.len());
    // Thumb descriptors may all be refused; fuzzy then proposes nothing and the refusals are reported.
    let fuzzy = if chosen.is_empty() { None } else { Some(FuzzyDb::new(chosen).map_err(|error| error.to_string())?) };
    let rule = |kind: Feature, value: &str| -> Option<String> {
        let (names, builds) = tables.get(&kind)?.get(value)?;
        (names.len() == 1 && builds.len() >= 2).then(|| names.iter().next().cloned()).flatten()
    };

    // The target and its baseline.
    let target = analyse(&arguments.target)?;
    let project = Project::new(Binary::open(&arguments.target).map_err(|error| error.to_string())?);
    project.set_packs(Arc::new(Packs::default()));
    let application = project.identify_functions(None, true, false).map_err(|error| error.to_string())?;
    let mut known: BTreeMap<u64, String> = BTreeMap::new();
    for function in &target.program.functions {
        let name = project.function_name(function.address);
        if !name.starts_with("sub_") {
            known.insert(function.address, canonical_name(&name).into_owned());
        }
    }
    let baseline: BTreeMap<u64, String> =
        application.matches.iter().map(|matched| (matched.address, matched.name.clone())).collect();
    known.extend(baseline.clone());
    let named = |address: u64| known.get(&address).cloned();
    let unnamed: Vec<u64> = target.extents.keys().copied().filter(|address| !known.contains_key(address)).collect();

    let mut proposals: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
    let propagated = graph.propagate(&arch, &target.calls, &known, None);
    proposals.insert("callgraph".into(), propagated.clone());
    let features = fuzzy_features(&target, &known);
    let mut fuzzy_names = BTreeMap::new();
    let mut fuzzy_top = BTreeMap::new();
    for &address in &unnamed {
        let Some(Ok(features)) = features.get(&address) else { continue };
        let Some(Ok(report)) = fuzzy.as_ref().map(|fuzzy| fuzzy.candidates(features, "query", 2)) else { continue };
        if let Some(top) = report.candidates.first() {
            fuzzy_top.insert(address, (top.name.clone(), top.score.total, top.margin_to_next_name));
            if !top.identical_feature_collision
                && top.score.total >= 0.95
                && top.margin_to_next_name > 0.0
                && top.margin_to_next_name >= 0.05
            {
                fuzzy_names.insert(address, top.name.clone());
            }
        }
    }
    proposals.insert("fuzzy".into(), fuzzy_names.clone());
    let mut seeded = known.clone();
    seeded.extend(fuzzy_names.clone());
    let mut fuzzy_then_graph = fuzzy_names.clone();
    fuzzy_then_graph.extend(graph.propagate(&arch, &target.calls, &seeded, None));
    proposals.insert("fuzzy+callgraph".into(), fuzzy_then_graph);
    let mut union = BTreeMap::new();
    for kind in FEATURES {
        let mut found = BTreeMap::new();
        for &address in &unnamed {
            if let Some(value) = feature(kind, &target, &named, address)
                && let Some(name) = rule(kind, &value)
            {
                found.insert(address, name);
            }
        }
        for (address, name) in &found {
            union.entry(*address).or_insert_with(|| name.clone());
        }
        proposals.insert(format!("miner:{}", kind.tag()), found);
    }
    proposals.insert("miner:any".into(), union);

    let mut scores = serde_json::Map::new();
    for (label, names) in &proposals {
        let (mut correct, mut wrong, mut spurious) = (0, 0, 0);
        for (address, name) in names {
            match truth.get(address) {
                Some(expected) if expected == name => correct += 1,
                Some(_) => wrong += 1,
                None => spurious += 1,
            }
        }
        scores.insert(label.clone(), json!({"correct": correct, "wrong": wrong, "spurious": spurious}));
    }

    let (mut correct, mut wrong_names, mut spurious) = (0, 0, 0);
    for (address, name) in &baseline {
        match truth.get(address) {
            Some(expected) if expected == name => correct += 1,
            Some(_) => wrong_names += 1,
            None => spurious += 1,
        }
    }
    let mut categories: BTreeMap<String, u64> = BTreeMap::new();
    let mut taken: BTreeMap<String, u64> = BTreeMap::new();
    let mut reachable = 0u64;
    let mut misses = Vec::new();
    for (address, name) in &truth {
        if baseline.get(address) == Some(name) {
            continue;
        }
        let context = target.callers.get(address).is_some_and(|set| set.iter().any(|c| known.contains_key(c)))
            || target.calls.get(address).is_some_and(|targets| targets.iter().any(|t| known.contains_key(t)));
        let instructions = target.instructions.get(address).copied();
        let names_of_body = target.hashes.get(address).and_then(|hash| hash_names.get(hash));
        let shared = names_of_body.is_some_and(|names| names.iter().any(|other| other != name));
        let same_body = names_of_body.is_some_and(|names| names.len() == 1 && names.contains(name));
        // Shape: the best share of identical 16-bit units against a same-length reference body of this name, an
        // upper bound on what wildcarding operand fields could match; `None` when no reference has its length.
        let body = target.extents.get(address).and_then(|end| target.binary.read(*address, end - address));
        let shape = body.and_then(|body| {
            reference_bodies
                .get(name)?
                .iter()
                .filter(|other| other.len() == body.len())
                .map(|other| {
                    let units = body.len().div_ceil(2).max(1);
                    let same = body.chunks(2).zip(other.chunks(2)).filter(|(a, b)| a == b).count();
                    same as f64 / units as f64
                })
                .fold(None, |best: Option<f64>, share| Some(best.map_or(share, |best| best.max(share))))
        });
        let with = |kind: &str| format!("{kind}/{}", if context { "context" } else { "no_context" });
        let category = if !target.extents.contains_key(address) {
            "undiscovered".to_owned()
        } else if !reference_names.contains(name) {
            "absent".to_owned()
        } else if shared {
            with("shared_body")
        } else if instructions.is_some_and(|count| count <= 3) {
            with("tiny")
        } else if instructions.is_some_and(|count| count <= 5) {
            with("below_gate")
        } else if same_body {
            "body_as_trained".to_owned()
        } else {
            "body_changed".to_owned()
        };
        *categories.entry(category.clone()).or_default() += 1;
        let is_reachable =
            !matches!(category.as_str(), "undiscovered" | "absent" | "shared_body/no_context" | "tiny/no_context");
        let mut by = Vec::new();
        if is_reachable {
            reachable += 1;
            for (label, names) in &proposals {
                if names.get(address) == Some(name) {
                    *taken.entry(label.clone()).or_default() += 1;
                    by.push(label.clone());
                }
            }
            if by.is_empty() {
                *taken.entry("untaken".into()).or_default() += 1;
            }
        }
        misses.push(json!({
            "address": format!("{address:#x}"), "truth": name, "baseline": baseline.get(address),
            "category": category, "reachable": is_reachable, "instructions": instructions, "taken_by": by,
            "fuzzy_top": fuzzy_top.get(address), "same_length_share": shape,
            "length": body.map(<[u8]>::len),
        }));
    }
    let report = json!({
        "target": arguments.target, "references": arguments.references.len(), "fuzzy_references": fuzzy_count, "fuzzy_refusals": fuzzy_refusals,
        "truth": truth.len(),
        "baseline": {"correct": correct, "wrong": wrong_names, "spurious": spurious},
        "categories": categories, "reachable_missed": reachable, "reachable_taken": taken,
        "scores": scores, "misses": misses,
    });
    std::fs::write(&arguments.out, serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    Ok(())
}
