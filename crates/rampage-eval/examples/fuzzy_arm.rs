//! Measurement only: the fuzzy matcher as a third arm after the bundled databases (which now carry arm v2).
//!
//! `cargo run --release -p rampage-eval --example fuzzy_arm -- CORPUS OUT.json [WORKERS]`
//!
//! References are the training split's truth functions. Every discovered function the bundled databases leave
//! unnamed on the dev (held-out) and negative splits is ranked against them, and each operating point
//! (threshold, margin) is scored as bundled + fuzzy. The final split is never read.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rampage_api::flywheel::fuzzy_arm::{FuzzyQuery, measure};
use rampage_api::flywheel::{Corpus, Counts, Engine, Outcome, Paths, Split, slice_counts};
use serde_json::json;

const THRESHOLDS: &[f64] = &[0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95];
const MARGINS: &[f64] = &[0.0, 0.02, 0.05, 0.10, 0.15];

fn counts(
    engine: &Engine,
    indices: &[usize],
    fuzzy: &BTreeMap<usize, BTreeMap<u64, String>>,
) -> BTreeMap<String, Counts> {
    let mut outcomes: BTreeMap<usize, BTreeMap<u64, Outcome>> = BTreeMap::new();
    for &index in indices {
        let loaded = engine.get(index).expect("loaded");
        let mut names = loaded.baseline.clone();
        if let Some(extra) = fuzzy.get(&index) {
            for (address, name) in extra {
                names.entry(*address).or_insert_with(|| name.clone());
            }
        }
        outcomes.insert(index, loaded.outcomes(&names));
    }
    slice_counts(engine, &outcomes).expect("slices")
}

fn pick(queries: &[FuzzyQuery], threshold: f64, margin: f64) -> BTreeMap<usize, BTreeMap<u64, String>> {
    let mut out: BTreeMap<usize, BTreeMap<u64, String>> = BTreeMap::new();
    for query in queries {
        if !query.collision && query.score >= threshold && query.margin > 0.0 && query.margin >= margin {
            out.entry(query.index).or_default().insert(query.address, query.name.clone());
        }
    }
    out
}

fn row(slices: &BTreeMap<String, Counts>, slice: &str) -> serde_json::Value {
    let counts = slices.get(slice).cloned().unwrap_or_default();
    json!({"tp": counts.tp(), "fp": counts.fp(), "fn": counts.fn_(), "f1": counts.f1()})
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
    let queries: Vec<usize> = [dev.clone(), negative.clone()].concat();
    let measurement = measure(&engine, &train, &queries)?;
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "{} references ({} train functions refused), {} queries, {} refused, {} unmatched, {elapsed:.0}s",
        measurement.references,
        measurement.reference_refused,
        measurement.queries.len(),
        measurement.query_refused,
        measurement.query_unmatched
    );
    // Reach: dev truth functions the bundled databases miss, and how many of them have a descriptor at all.
    let mut reach = BTreeMap::<&str, (u64, u64, u64)>::new();
    let top: BTreeMap<(usize, u64), &FuzzyQuery> =
        measurement.queries.iter().map(|query| ((query.index, query.address), query)).collect();
    for &index in &dev {
        let loaded = engine.get(index)?;
        let novelty = engine.novelty(index)?;
        let described: std::collections::BTreeSet<u64> =
            measurement.described.get(&index).into_iter().flatten().copied().collect();
        for (address, truth) in &loaded.truth {
            if truth.origin == "runtime" || loaded.baseline.contains_key(address) {
                continue;
            }
            let slice = if novelty.get(address).copied().unwrap_or(false) { "novel" } else { "recognised" };
            let entry = reach.entry(slice).or_default();
            entry.0 += 1;
            if described.contains(address) {
                entry.1 += 1;
            }
            if top.get(&(index, *address)).is_some_and(|query| query.name == truth.name) {
                entry.2 += 1;
            }
        }
    }
    let baseline_dev = counts(&engine, &dev, &BTreeMap::new());
    let baseline_negative = counts(&engine, &negative, &BTreeMap::new());
    let mut points = Vec::new();
    for &threshold in THRESHOLDS {
        for &margin in MARGINS {
            let chosen = pick(&measurement.queries, threshold, margin);
            let dev_slices = counts(&engine, &dev, &chosen);
            let negative_slices = counts(&engine, &negative, &chosen);
            points.push(json!({
                "threshold": threshold, "margin": margin,
                "dev": row(&dev_slices, "all"),
                "dev_novel": row(&dev_slices, "novelty:novel"),
                "dev_recognised": row(&dev_slices, "novelty:recognised"),
                "negative": row(&negative_slices, "all"),
            }));
        }
    }
    let report = json!({
        "references": measurement.references,
        "reference_refused": measurement.reference_refused,
        "queries": measurement.queries.len(),
        "query_refused": measurement.query_refused,
        "query_unmatched": measurement.query_unmatched,
        "elapsed_s": elapsed,
        "reach": reach.iter().map(|(slice, (missed, described, top_correct))| {
            (slice.to_string(), json!({"missed": missed, "described": described, "top1_correct": top_correct}))
        }).collect::<serde_json::Map<_, _>>(),
        "baseline": {"dev": row(&baseline_dev, "all"), "dev_novel": row(&baseline_dev, "novelty:novel"),
                     "dev_recognised": row(&baseline_dev, "novelty:recognised"),
                     "negative": row(&baseline_negative, "all")},
        "points": points,
    });
    std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
