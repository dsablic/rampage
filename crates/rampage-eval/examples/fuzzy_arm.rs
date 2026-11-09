//! Measurement only: the fuzzy matcher as a third arm after the bundled databases (which now carry arm v2).
//!
//! `cargo run --release -p rampage-eval --example fuzzy_arm -- CORPUS OUT.json [WORKERS]`
//!
//! References are the training split's truth functions. Every discovered function the bundled databases leave
//! unnamed on the dev (held-out) and negative splits is ranked against them, and each operating point
//! (threshold, margin) is scored as bundled + fuzzy. The final split is never read.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rampage_api::flywheel::fuzzy_arm::{FuzzyMeasurement, FuzzyQuery, Names, base_names, measure, propagate};
use rampage_api::flywheel::{
    ARM_WILDCARDS, Corpus, Counts, Engine, GateConfig, Outcome, Paths, Split, layer, slice_counts,
};
use serde_json::json;

const THRESHOLDS: &[f64] = &[0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95];
const MARGINS: &[f64] = &[0.0, 0.02, 0.05, 0.10, 0.15];

fn counts(
    engine: &Engine,
    base: &Names,
    indices: &[usize],
    fuzzy: &BTreeMap<usize, BTreeMap<u64, String>>,
) -> BTreeMap<String, Counts> {
    let mut outcomes: BTreeMap<usize, BTreeMap<u64, Outcome>> = BTreeMap::new();
    for &index in indices {
        let loaded = engine.get(index).expect("loaded");
        let mut names = base_names(&loaded, base, index).clone();
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

/// The fuzzy names plus the names call-graph propagation adds over bundled + fuzzy.
fn with_propagation(
    engine: &Engine,
    measurement: &FuzzyMeasurement,
    base: &Names,
    indices: &[usize],
    fuzzy: &BTreeMap<usize, BTreeMap<u64, String>>,
) -> BTreeMap<usize, BTreeMap<u64, String>> {
    let mut out = BTreeMap::new();
    for &index in indices {
        let loaded = engine.get(index).expect("loaded");
        let mut names = base_names(&loaded, base, index).clone();
        let extra = fuzzy.get(&index).cloned().unwrap_or_default();
        for (address, name) in &extra {
            names.entry(*address).or_insert_with(|| name.clone());
        }
        let mut added = extra;
        added.extend(propagate(engine, measurement, index, &names));
        out.insert(index, added);
    }
    out
}

fn row(slices: &BTreeMap<String, Counts>, slice: &str) -> serde_json::Value {
    let counts = slices.get(slice).cloned().unwrap_or_default();
    json!({"tp": counts.tp(), "fp": counts.fp(), "fn": counts.fn_(), "f1": counts.f1()})
}

/// Appends one read to the corpus's final ledger, in the format `rampage-eval flywheel-eval --split final` uses.
fn record_final_read(engine: &Engine, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let path = engine.corpus.root.join("final-ledger.jsonl");
    let _lock = rampage_api::flywheel::FileLock::acquire(&path.with_extension("lock"))?;
    let previous =
        std::fs::read_to_string(&path).map_or(0, |text| text.lines().filter(|line| !line.trim().is_empty()).count());
    let entry = json!({
        "read": previous + 1,
        "unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64,
        "corpus_identity": engine.corpus.identity(),
        "build_id": rampage_api::flywheel::build_id(),
        "reason": reason,
        "packs": [],
    });
    writeln!(std::fs::OpenOptions::new().create(true).append(true).open(&path)?, "{entry}")?;
    eprintln!("final read #{} recorded", previous + 1);
    Ok(())
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
    // `FUZZY_ARM_FINAL=<reason>`: score the final split in place of dev, for the one configuration fixed in advance
    // (fuzzy 0.95/0.05 and call-graph propagation), after recording the read in the corpus's final ledger.
    let final_reason = std::env::var("FUZZY_ARM_FINAL").ok();
    let dev = match &final_reason {
        Some(reason) => {
            record_final_read(&engine, reason)?;
            engine.corpus.indices(Split::Final)
        }
        None => engine.corpus.indices(Split::Heldout),
    };
    let negative = engine.corpus.indices(Split::Negative);
    engine.load_all(&[train.clone(), dev.clone(), negative.clone()].concat())?;
    let started = std::time::Instant::now();
    let queries: Vec<usize> = [dev.clone(), negative.clone()].concat();
    // Dev, negatives (and final) start from the bundled databases plus the deterministic arm; training from the
    // bundled databases, since the arm holds every training body.
    let arm = rampage_api::flywheel::arm_with(&engine, GateConfig::default().min_pattern_bytes, &ARM_WILDCARDS)?;
    let layers: Vec<_> = layer("arm", &arm.rows)?.into_iter().collect();
    let base: Names = engine.propose(&queries, &layers)?.names;
    if std::env::var("FUZZY_ARM_SLICES").is_ok() {
        // Diagnosis: the dev slices the arm alone makes worse than the bundled databases.
        let before = counts(&engine, &Names::new(), &dev, &BTreeMap::new());
        let after = counts(&engine, &base, &dev, &BTreeMap::new());
        for (slice, counts) in &after {
            let old = before.get(slice).cloned().unwrap_or_default();
            if counts.f1() + 1e-12 < old.f1() && rampage_api::flywheel::gated_slice(slice) {
                eprintln!(
                    "{slice}: F1 {:.6} -> {:.6} (tp {} -> {}, fp {} -> {})",
                    old.f1(),
                    counts.f1(),
                    old.tp(),
                    counts.tp(),
                    old.fp(),
                    counts.fp()
                );
            }
        }
        for &index in &dev {
            let loaded = engine.get(index)?;
            let entry = engine.binary(index);
            if entry.library != "lz4" || entry.opt != "O0" {
                continue;
            }
            for (address, name) in base_names(&loaded, &base, index) {
                let truth = loaded.truth.get(address);
                let bundled = loaded.baseline.get(address);
                if truth.is_none_or(|truth| truth.name != *name) && bundled != Some(name) {
                    eprintln!(
                        "{} {address:#x}: {name} (bundled {:?}, truth {:?})",
                        entry.id,
                        bundled,
                        truth.map(|t| &t.name)
                    );
                }
            }
        }
        return Ok(());
    }
    let measurement = measure(&engine, &train, &queries, &base)?;
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
    // Novel misses without a descriptor: (reason, instruction bucket) -> count.
    let mut residue = BTreeMap::<String, u64>::new();
    let top: BTreeMap<(usize, u64), &FuzzyQuery> =
        measurement.queries.iter().map(|query| ((query.index, query.address), query)).collect();
    for &index in &dev {
        let loaded = engine.get(index)?;
        let novelty = engine.novelty(index)?;
        let described: std::collections::BTreeSet<u64> =
            measurement.described.get(&index).into_iter().flatten().copied().collect();
        for (address, truth) in &loaded.truth {
            if truth.origin == "runtime" || base_names(&loaded, &base, index).contains_key(address) {
                continue;
            }
            let slice = if novelty.get(address).copied().unwrap_or(false) { "novel" } else { "recognised" };
            let entry = reach.entry(slice).or_default();
            entry.0 += 1;
            if described.contains(address) {
                entry.1 += 1;
            }
            if slice == "novel" && !described.contains(address) {
                let refusal = measurement.refusals.get(&index).and_then(|refusals| refusals.get(address));
                let key = match refusal {
                    Some(refusal) => {
                        let bucket = match refusal.instructions {
                            0..=3 => "1-3",
                            4..=7 => "4-7",
                            8..=11 => "8-11",
                            12..=23 => "12-23",
                            _ => "24+",
                        };
                        format!("{} | insns {bucket} | blocks {}", refusal.reason, refusal.blocks.min(3))
                    }
                    None => "undiscovered".to_owned(),
                };
                *residue.entry(key).or_default() += 1;
            }
            if top.get(&(index, *address)).is_some_and(|query| query.name == truth.name) {
                entry.2 += 1;
            }
        }
    }
    let baseline_dev = counts(&engine, &base, &dev, &BTreeMap::new());
    let baseline_negative = counts(&engine, &base, &negative, &BTreeMap::new());
    let baseline_train = counts(&engine, &base, &train, &BTreeMap::new());
    // Each fuzzy point (threshold 2.0: no fuzzy names), without and with call-graph propagation over its names.
    let mut points = Vec::new();
    let thresholds: Vec<f64> = THRESHOLDS.iter().copied().chain([2.0]).collect();
    for &threshold in &thresholds {
        for &margin in MARGINS {
            if threshold > 1.0 && margin > 0.0 {
                continue;
            }
            if final_reason.is_some() && threshold <= 1.0 && (threshold, margin) != (0.95, 0.05) {
                continue;
            }
            let chosen = pick(&measurement.queries, threshold, margin);
            for propagated in [false, true] {
                let score = |indices: &[usize]| {
                    let names = if propagated {
                        with_propagation(&engine, &measurement, &base, indices, &chosen)
                    } else {
                        chosen.clone()
                    };
                    counts(&engine, &base, indices, &names)
                };
                let (train_slices, dev_slices, negative_slices) = (score(&train), score(&dev), score(&negative));
                points.push(json!({
                    "threshold": threshold, "margin": margin, "propagated": propagated,
                    "train": row(&train_slices, "all"),
                    "dev": row(&dev_slices, "all"),
                    "dev_novel": row(&dev_slices, "novelty:novel"),
                    "dev_recognised": row(&dev_slices, "novelty:recognised"),
                    "negative": row(&negative_slices, "all"),
                }));
            }
        }
    }
    // The false positives of call-graph propagation alone and of fuzzy 0.95/0.05 alone, for diagnosis.
    let mut false_positives = Vec::new();
    let diagnoses = if final_reason.is_some() {
        &[][..]
    } else {
        &[("propagation", true, 2.0, 0.0), ("fuzzy", false, 0.95, 0.05)][..]
    };
    for &(label, propagated, threshold, margin) in diagnoses {
        let chosen = pick(&measurement.queries, threshold, margin);
        for indices in [&train, &dev, &negative] {
            let names = if propagated {
                with_propagation(&engine, &measurement, &base, indices, &chosen)
            } else {
                chosen.clone()
            };
            for (index, added) in &names {
                let loaded = engine.get(*index)?;
                for (address, name) in added {
                    let truth = loaded.truth.get(address);
                    if truth.is_some_and(|truth| truth.name == *name) {
                        continue;
                    }
                    false_positives.push(json!({
                        "kind": label, "binary": engine.binary(*index).id, "split": engine.binary(*index).split,
                        "address": format!("{address:#x}"), "proposed": name,
                        "truth": truth.map(|truth| format!("{} ({})", truth.name, truth.origin)),
                    }));
                }
            }
        }
    }
    let report = json!({
        "false_positives": false_positives,
        "references": measurement.references,
        "reference_refused": measurement.reference_refused,
        "queries": measurement.queries.len(),
        "query_refused": measurement.query_refused,
        "query_unmatched": measurement.query_unmatched,
        "elapsed_s": elapsed,
        "reach": reach.iter().map(|(slice, (missed, described, top_correct))| {
            (slice.to_string(), json!({"missed": missed, "described": described, "top1_correct": top_correct}))
        }).collect::<serde_json::Map<_, _>>(),
        "residue": residue,
        "baseline": {"train": row(&baseline_train, "all"), "dev": row(&baseline_dev, "all"), "dev_novel": row(&baseline_dev, "novelty:novel"),
                     "dev_recognised": row(&baseline_dev, "novelty:recognised"),
                     "negative": row(&baseline_negative, "all")},
        "points": points,
    });
    std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
