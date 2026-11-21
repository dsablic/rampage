//! Measurement only: how much of what the bundled databases still miss on the libid corpus's dev split is
//! reachable in principle, and how much of that a trivial deterministic baseline already takes
//! (docs/plans/2026-11-20-flywheel-next.md, step 2; report in docs/benchmarks/flywheel-headroom-2026-11-21.md).
//!
//! `cargo run --release -p rampage-eval --example flywheel_headroom -- CORPUS OUT.json [WORKERS]`
//!
//! The starting point is each binary's cached baseline: the bundled signature databases (with the arm and the zstd
//! and Lua rows) and the bundled call graph, as `identify_functions` ships them. Every target-library truth function
//! of the dev (held-out) split the baseline does not name correctly is classified, in this order:
//!
//! - `undiscovered`: function discovery finds no function there, so no naming heuristic can reach it;
//! - `absent`: no training binary of that architecture has a function of that name;
//! - `shared_body`: its masked body equals a training body that carries another name;
//! - `tiny`: 1–3 instructions;
//!
//! and the last two are split by context: a function with a named caller or a named callee (baseline names and the
//! loader's own) can still be told apart, one without cannot. Unreachable: `undiscovered`, `absent`, and
//! `shared_body` or `tiny` without context. Everything else is reachable in principle.
//!
//! Baselines over the unnamed functions, each scored on dev and negatives:
//! - fuzzy at 0.95/0.05 (training-calibrated, failed final as a shipped arm), then call-graph propagation over it;
//! - the deterministic arm generated from this corpus's training split, layered over the bundled databases;
//! - one-feature miners: a feature value names a function when every training occurrence of it carries one name,
//!   in at least two builds. Features: body length; the masked body (the arm without its length and collision
//!   guards); the named-callee sequence; the set of named callers.
//!
//! The final split is never read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rampage_api::flywheel::fuzzy_arm::{FuzzyQuery, Names, build_key, measure, propagate};
use rampage_api::flywheel::{ARM_WILDCARDS, Corpus, Engine, GateConfig, Loaded, Paths, Split, format_pattern, layer};
use serde_json::json;

const RUNTIME: &str = "runtime";

/// The matchers built for the gate (the arm and fuzzy), as against the one-feature miners.
const PRECISE: [&str; 3] = ["arm", "fuzzy", "fuzzy+propagation"];

/// A one-feature rule table: feature value → (names seen, builds seen).
type Table = BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Feature {
    Length,
    Body,
    Callees,
    Callers,
}

const FEATURES: [Feature; 4] = [Feature::Length, Feature::Body, Feature::Callees, Feature::Callers];

impl Feature {
    fn tag(self) -> &'static str {
        match self {
            Feature::Length => "length",
            Feature::Body => "body",
            Feature::Callees => "callees",
            Feature::Callers => "callers",
        }
    }
}

/// Each function's callers, from the call sequences.
fn callers_of(calls: &BTreeMap<u64, Vec<u64>>) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (caller, targets) in calls {
        for target in targets {
            callers.entry(*target).or_default().insert(*caller);
        }
    }
    callers
}

/// The feature value of the function at `address`, with `names` naming its neighbours; `None` when the feature
/// says nothing (no body, no named callee, no named caller).
fn feature(
    feature: Feature,
    arch: &str,
    loaded: &Loaded,
    callers: &BTreeMap<u64, BTreeSet<u64>>,
    names: &dyn Fn(u64) -> Option<String>,
    address: u64,
) -> Option<String> {
    match feature {
        Feature::Length => loaded.body(address).map(|body| format!("{arch}|{}", body.len())),
        Feature::Body => loaded.masked(address).map(|masked| format!("{arch}|{}", format_pattern(&masked))),
        Feature::Callees => {
            let targets = loaded.calls.get(&address)?;
            let named: Vec<Option<String>> = targets.iter().map(|target| names(*target)).collect();
            named.iter().any(Option::is_some).then(|| format!("{arch}|{named:?}"))
        }
        Feature::Callers => {
            let named: BTreeSet<String> = callers.get(&address)?.iter().filter_map(|caller| names(*caller)).collect();
            (!named.is_empty()).then(|| format!("{arch}|{named:?}"))
        }
    }
}

#[derive(Default, Clone)]
struct Score {
    correct: u64,
    wrong: u64,
    spurious: u64,
}

impl Score {
    fn json(&self) -> serde_json::Value {
        let answered = self.correct + self.wrong + self.spurious;
        let precision = if answered == 0 { 1.0 } else { self.correct as f64 / answered as f64 };
        json!({"correct": self.correct, "wrong": self.wrong, "spurious": self.spurious, "precision": precision})
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let corpus_path = PathBuf::from(args.next().ok_or("CORPUS")?);
    let out = PathBuf::from(args.next().ok_or("OUT.json")?);
    let workers: usize = args.next().map(|text| text.parse()).transpose()?.unwrap_or(8);
    let corpus = Corpus::open(&corpus_path)?;
    let paths = Paths::for_corpus(&corpus.root).ok_or("corpus is not inside corpus/")?;
    let engine = Engine::new(corpus, paths, workers);
    let train = engine.corpus.indices(Split::Train);
    let dev = engine.corpus.indices(Split::Heldout);
    let negative = engine.corpus.indices(Split::Negative);
    engine.load_all(&[train.clone(), dev.clone(), negative.clone()].concat())?;
    let started = std::time::Instant::now();

    // Training: names per architecture, masked bodies with their names, and the one-feature tables.
    let mut train_names: BTreeSet<(String, String)> = BTreeSet::new();
    let mut bodies: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut tables: BTreeMap<Feature, Table> = BTreeMap::new();
    for &index in &train {
        let loaded = engine.get(index)?;
        let arch = engine.binary(index).arch.clone();
        let build = build_key(&engine, index);
        let target = loaded.binary.target();
        let callers = callers_of(&loaded.calls);
        let truth_name = |address: u64| loaded.truth.get(&address).map(|truth| truth.name.clone());
        for (address, truth) in &loaded.truth {
            if let Some(body) = loaded.body(*address)
                && let Some(masked) = rampage_signatures::masked_body_in(&target, &loaded.image, body, *address)
            {
                bodies.entry((arch.clone(), format_pattern(&masked))).or_default().insert(truth.name.clone());
            }
            // Runtime functions enter the tables too, so a value they share is no rule.
            for kind in FEATURES {
                if let Some(value) = feature(kind, &arch, &loaded, &callers, &truth_name, *address) {
                    let entry = tables.entry(kind).or_default().entry(value).or_default();
                    entry.0.insert(truth.name.clone());
                    entry.1.insert(build.clone());
                }
            }
            if truth.origin != RUNTIME {
                train_names.insert((arch.clone(), truth.name.clone()));
            }
        }
    }
    let rule = |kind: Feature, value: &str| -> Option<String> {
        let (names, builds) = tables.get(&kind)?.get(value)?;
        (names.len() == 1 && builds.len() >= 2).then(|| names.iter().next().cloned()).flatten()
    };

    // Fuzzy descriptors and instruction counts (refusals), over the baseline names.
    let queries_at: Vec<usize> = [dev.clone(), negative.clone()].concat();
    let measurement = measure(&engine, &train, &queries_at, &Names::new())?;
    let top: BTreeMap<(usize, u64), &FuzzyQuery> =
        measurement.queries.iter().map(|query| ((query.index, query.address), query)).collect();

    // The deterministic arm generated from this corpus's training split (exact rows and operand wildcarding), as a
    // layer over the bundled databases: the generator's reach, of which only the zstd and Lua rows ship.
    let arm = rampage_api::flywheel::arm_with(&engine, GateConfig::default().min_pattern_bytes, &ARM_WILDCARDS)?;
    let layers: Vec<_> = layer("arm", &arm.rows)?.into_iter().collect();
    let with_arm = engine.propose(&queries_at, &layers)?.names;

    // Baseline names per query binary: the arm, fuzzy 0.95/0.05 then propagation, and each miner.
    let mut proposals: BTreeMap<String, BTreeMap<usize, BTreeMap<u64, String>>> = BTreeMap::new();
    for &index in &queries_at {
        let loaded = engine.get(index)?;
        let arch = engine.binary(index).arch.clone();
        let mut known = loaded.existing.clone();
        known.extend(loaded.baseline.clone());
        let callers = callers_of(&loaded.calls);
        let named = |address: u64| known.get(&address).cloned();
        let unnamed: Vec<u64> =
            loaded.functions.iter().map(|&(start, _)| start).filter(|start| !known.contains_key(start)).collect();
        let arm_names: BTreeMap<u64, String> = with_arm
            .get(&index)
            .into_iter()
            .flatten()
            .filter(|(address, _)| !known.contains_key(address))
            .map(|(address, name)| (*address, name.clone()))
            .collect();
        proposals.entry("arm".into()).or_default().insert(index, arm_names);
        let mut fuzzy = BTreeMap::new();
        for &address in &unnamed {
            if let Some(query) = top.get(&(index, address))
                && !query.collision
                && query.score >= 0.95
                && query.margin > 0.0
                && query.margin >= 0.05
            {
                fuzzy.insert(address, query.name.clone());
            }
        }
        let mut with_fuzzy = known.clone();
        with_fuzzy.extend(fuzzy.clone());
        let mut fuzzy_propagated = fuzzy.clone();
        fuzzy_propagated.extend(propagate(&engine, &measurement, index, &with_fuzzy));
        proposals.entry("fuzzy".into()).or_default().insert(index, fuzzy);
        proposals.entry("fuzzy+propagation".into()).or_default().insert(index, fuzzy_propagated);
        let mut union = BTreeMap::new();
        for kind in FEATURES {
            let mut found = BTreeMap::new();
            for &address in &unnamed {
                if let Some(value) = feature(kind, &arch, &loaded, &callers, &named, address)
                    && let Some(name) = rule(kind, &value)
                {
                    found.insert(address, name);
                }
            }
            for (address, name) in &found {
                union.entry(*address).or_insert_with(|| name.clone());
            }
            proposals.entry(format!("miner:{}", kind.tag())).or_default().insert(index, found);
        }
        proposals.entry("miner:any".into()).or_default().insert(index, union);
    }

    // Classify dev misses; score each baseline on the reachable ones and everywhere.
    let mut categories: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_library: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut reachable_detail: BTreeMap<String, u64> = BTreeMap::new();
    let mut reachable_taken: BTreeMap<String, u64> = BTreeMap::new();
    let mut untaken_precise_detail: BTreeMap<String, u64> = BTreeMap::new();
    let mut untaken_detail: BTreeMap<String, u64> = BTreeMap::new();
    let mut reachable_total = 0u64;
    let mut untaken_examples: Vec<serde_json::Value> = Vec::new();
    let mut baseline_counts = (0u64, 0u64, 0u64); // correct, wrong, missed (target-library functions)
    let mut scores: BTreeMap<String, (Score, Score)> = BTreeMap::new(); // (dev, negative)
    for &index in &queries_at {
        let loaded = engine.get(index)?;
        let entry = engine.binary(index);
        let is_dev = entry.split == rampage_api::flywheel::Role::Heldout;
        for (label, per_binary) in &proposals {
            let score = scores.entry(label.clone()).or_default();
            let score = if is_dev { &mut score.0 } else { &mut score.1 };
            for (address, name) in per_binary.get(&index).into_iter().flatten() {
                // As the gate scores: runtime functions (libc, compiler runtime) earn and cost nothing.
                match loaded.truth.get(address) {
                    Some(truth) if truth.origin == RUNTIME => {}
                    Some(truth) if truth.name == *name => score.correct += 1,
                    Some(_) => score.wrong += 1,
                    None => score.spurious += 1,
                }
            }
        }
        if !is_dev {
            continue;
        }
        let novelty = engine.novelty(index)?;
        let callers = callers_of(&loaded.calls);
        let mut known = loaded.existing.clone();
        known.extend(loaded.baseline.clone());
        let refusals = measurement.refusals.get(&index);
        let target = loaded.binary.target();
        for (address, truth) in &loaded.truth {
            if truth.origin == RUNTIME {
                continue;
            }
            let outcome = match loaded.baseline.get(address) {
                Some(name) if *name == truth.name => {
                    baseline_counts.0 += 1;
                    continue;
                }
                Some(_) => {
                    baseline_counts.1 += 1;
                    "wrong"
                }
                None => {
                    baseline_counts.2 += 1;
                    "missed"
                }
            };
            let context = callers.get(address).is_some_and(|set| set.iter().any(|caller| known.contains_key(caller)))
                || loaded.calls.get(address).is_some_and(|targets| targets.iter().any(|t| known.contains_key(t)));
            let instructions = refusals.and_then(|refusals| refusals.get(address)).map(|refusal| refusal.instructions);
            let masked = loaded
                .body(*address)
                .and_then(|body| rampage_signatures::masked_body_in(&target, &loaded.image, body, *address));
            let names_of_body =
                masked.as_ref().and_then(|masked| bodies.get(&(entry.arch.clone(), format_pattern(masked))));
            let shared = names_of_body.is_some_and(|names| names.iter().any(|name| *name != truth.name));
            let same_body = names_of_body.is_some_and(|names| names.len() == 1 && names.contains(&truth.name));
            let category = if !loaded.discovered(*address) {
                "undiscovered".to_owned()
            } else if !train_names.contains(&(entry.arch.clone(), truth.name.clone())) {
                "absent".to_owned()
            } else if shared {
                format!("shared_body/{}", if context { "context" } else { "no_context" })
            } else if instructions.is_some_and(|count| count <= 3) {
                format!("tiny/{}", if context { "context" } else { "no_context" })
            } else {
                "other".to_owned()
            };
            let reachable = matches!(category.as_str(), "shared_body/context" | "tiny/context" | "other");
            let key = format!("{outcome}/{category}");
            *categories.entry(key.clone()).or_default() += 1;
            *by_library.entry(entry.library.clone()).or_default().entry(key).or_default() += 1;
            if !reachable || outcome == "wrong" {
                continue;
            }
            reachable_total += 1;
            let novel = novelty.get(address).copied().unwrap_or(true);
            let size = match instructions {
                Some(count) => format!("refused {}", if count < 12 { "<12 insns" } else { ">=12 insns" }),
                None => "described".to_owned(),
            };
            let detail = format!(
                "{category} | {} | {size} | {}",
                if novel { "novel" } else { "recognised" },
                if same_body { "body as trained" } else { "body changed" }
            );
            *reachable_detail.entry(detail.clone()).or_default() += 1;
            let mut taken_by_any = false;
            let mut taken_precisely = false;
            for (label, per_binary) in &proposals {
                if per_binary.get(&index).and_then(|names| names.get(address)) == Some(&truth.name) {
                    *reachable_taken.entry(label.clone()).or_default() += 1;
                    taken_by_any = true;
                    taken_precisely |= PRECISE.contains(&label.as_str());
                }
            }
            if !taken_precisely {
                *reachable_taken.entry("untaken_by_precise".into()).or_default() += 1;
                *untaken_precise_detail.entry(detail.clone()).or_default() += 1;
            }
            if !taken_by_any {
                *reachable_taken.entry("untaken".into()).or_default() += 1;
                *untaken_detail.entry(detail.clone()).or_default() += 1;
                if untaken_examples.len() < 400 && index % 7 == 0 && !taken_precisely {
                    untaken_examples.push(json!({
                        "binary": entry.id, "address": format!("{address:#x}"), "truth": truth.name,
                        "category": category, "context": context, "instructions": instructions,
                        "fuzzy_top": top.get(&(index, *address)).map(|query| json!({
                            "name": query.name, "score": query.score, "margin": query.margin})),
                    }));
                }
            }
        }
    }
    let report = json!({
        "elapsed_s": started.elapsed().as_secs_f64(),
        "dev_binaries": dev.len(),
        "baseline": {"correct": baseline_counts.0, "wrong": baseline_counts.1, "missed": baseline_counts.2},
        "categories": categories,
        "by_library": by_library,
        "reachable_missed": reachable_total,
        "reachable_detail": reachable_detail,
        "reachable_taken": reachable_taken,
        "untaken_by_precise_detail": untaken_precise_detail,
        "untaken_detail": untaken_detail,
        "scores": scores.iter().map(|(label, (dev, negative))| {
            (label.clone(), json!({"dev": dev.json(), "negative": negative.json()}))
        }).collect::<serde_json::Map<_, _>>(),
        "untaken_examples": untaken_examples,
    });
    std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
