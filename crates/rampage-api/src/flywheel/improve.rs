//! The `improve` MCP group: an agent reads training failures, proposes signature rows into a scratch candidate,
//! evaluates it through the fast and held-out gates, and promotes it only after a passing held-out result for the
//! same candidate hash, corpus version and baseline. It exists only on a server started with `--corpus`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::candidate::{CANDIDATE_FILE, Candidate, Row, RowSource, format_pattern, layer, parse_pattern, write_pack};
use super::corpus::{Corpus, Split};
use super::engine::{Engine, Layer, Overlap, SliceMetrics, bundled_hash, pattern_matches};
use super::evaluation::{GateConfig, GateResult, SplitEvaluation, evaluate_split};
use super::failures::{FailureGroup, FailureSet, TRUTH_SOURCE};
use super::promote::{PromotedEntry, PromotedSet, promoted_layer, revert_id};
use super::{FileLock, FlywheelError, Paths, build_id, now_ms, read_bounded, sha256_text, write_atomic};
use crate::rows::{FittedPage, item_budget};

/// The heuristic family the loop improves.
pub const FAMILY: &str = "libid";
const DEFAULT_FAILURES: usize = 20;
const MAX_FAILURES: usize = 200;
const MAX_ROWS_PER_CALL: usize = 32;
const DEFAULT_CASES: usize = 20;
const MAX_CASES: usize = 200;
/// Distinct names listed in a row's training preview.
const MAX_PREVIEW_NAMES: usize = 8;
const MAX_LISTED: usize = 8;

/// How to open the improve context.
pub struct ImproveOptions {
    /// A built corpus directory (`target/flywheel/corpus/<version>`).
    pub corpus: PathBuf,
    /// The flywheel working directory; by default two levels above a corpus in a `corpus/` directory.
    pub flywheel_dir: Option<PathBuf>,
    pub gate: GateConfig,
    /// Threads for analysis and evaluation.
    pub workers: usize,
    /// The proposer run this server serves, recorded in candidates, promotions and the run's event log.
    pub run: Option<String>,
}

/// One server's improve context.
pub struct Improve {
    engine: Engine,
    gate: GateConfig,
    run: Option<String>,
    state: Mutex<State>,
    /// Serializes candidate and promoted-pack writes.
    writes: Mutex<()>,
    /// The held-out split's overlap with training, checked when the context opened.
    overlap: Overlap,
}

#[derive(Default)]
struct State {
    /// The training failures, keyed by the promoted rows' hash they were computed under.
    failures: Option<(String, Arc<FailureSet>)>,
}

/// A candidate's cached gate results, keyed by (candidate hash, corpus identity, baseline hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvaluationRecord {
    candidate_hash: String,
    corpus_version: String,
    corpus_identity: String,
    baseline_hash: String,
    fast: StageRecord,
    /// The fast stage's checks on the full training split and the negatives.
    train: SplitEvaluation,
    negative: SplitEvaluation,
    #[serde(default)]
    heldout: Option<StageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StageRecord {
    evaluation: SplitEvaluation,
    gate: GateResult,
}

/// Held-out evaluations used for one corpus, across every server.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Budget {
    used: usize,
}

impl Improve {
    pub fn open(options: ImproveOptions) -> Result<Improve, FlywheelError> {
        let corpus = Corpus::open(&options.corpus)?;
        let paths = match options.flywheel_dir {
            Some(directory) => Paths::new(directory),
            None => Paths::for_corpus(&corpus.root).ok_or_else(|| {
                FlywheelError::Invalid(format!(
                    "{} is not inside a `corpus/` directory; give the flywheel directory explicitly",
                    corpus.root.display()
                ))
            })?,
        };
        if let Some(run) = &options.run
            && (run.is_empty()
                || run.len() > 128
                || !run.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
                || run.split('/').any(|part| part.is_empty() || part == "." || part == ".."))
        {
            return Err(FlywheelError::Invalid(format!(
                "run id {run:?} must be plain path segments of A-Z a-z 0-9 - _ ."
            )));
        }
        let engine = Engine::new(corpus, paths, options.workers);
        // A held-out split that training already covers would measure recognition, not generalisation.
        let overlap = engine.heldout_overlap()?;
        if overlap.fraction > overlap.refused_above {
            return Err(FlywheelError::Corpus(format!(
                "{} of {} held-out library bodies ({:.1}%) also occur in training, above {:.0}%: the held-out split \
                 is essentially the training build again; rebuild the corpus with a stricter hold-out",
                overlap.in_training,
                overlap.heldout_bodies,
                overlap.fraction * 100.0,
                overlap.refused_above * 100.0
            )));
        }
        if let Some(warning) = overlap.warning() {
            eprintln!("rampage flywheel: {warning}");
        }
        PromotedSet::load_repaired(&engine.paths, FAMILY, &engine.corpus.license())?;
        Ok(Improve {
            engine,
            gate: options.gate,
            run: options.run,
            state: Mutex::new(State::default()),
            writes: Mutex::new(()),
            overlap,
        })
    }

    /// The held-out split's overlap with training, as checked when the context opened.
    pub fn overlap(&self) -> &Overlap {
        &self.overlap
    }

    fn budget_path(&self) -> PathBuf {
        self.paths().evaluations(FAMILY).join(self.corpus().key()).join("heldout-budget.json")
    }

    /// Held-out evaluations left for this corpus.
    pub fn heldout_left(&self) -> usize {
        let used = std::fs::read_to_string(self.budget_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Budget>(&text).ok())
            .map_or(0, |budget| budget.used);
        self.gate.max_heldout_evaluations.saturating_sub(used)
    }

    /// Takes one held-out evaluation from the corpus's persistent budget, or refuses when none is left.
    fn spend_heldout(&self) -> Result<(), FlywheelError> {
        let path = self.budget_path();
        let _lock = FileLock::acquire(&path.with_extension("lock"))?;
        let mut budget: Budget =
            std::fs::read_to_string(&path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default();
        if budget.used >= self.gate.max_heldout_evaluations {
            return Err(FlywheelError::Refused(format!(
                "this corpus's {} held-out evaluations are used up; nothing was run",
                self.gate.max_heldout_evaluations
            )));
        }
        budget.used += 1;
        write_atomic(&path, serde_json::to_string(&budget).map_err(FlywheelError::json)?.as_bytes())
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn paths(&self) -> &Paths {
        &self.engine.paths
    }

    pub fn corpus(&self) -> &Corpus {
        &self.engine.corpus
    }

    pub fn gate(&self) -> &GateConfig {
        &self.gate
    }

    fn promoted(&self) -> Result<PromotedSet, FlywheelError> {
        PromotedSet::load(self.paths(), FAMILY)
    }

    /// The state every evaluation is relative to: this build, the bundled databases, the promoted rows and the
    /// gate settings. A change to any of them makes earlier gate results stale.
    pub fn baseline_hash(&self, promoted: &PromotedSet) -> String {
        let mut parts = vec![build_id().to_owned()];
        for arch in self.corpus().arches() {
            let hash = arch.parse().map(bundled_hash).unwrap_or_default();
            parts.push(format!("{arch}={hash}"));
        }
        parts.push(promoted.hash());
        parts.push(self.gate.fingerprint());
        sha256_text(&parts.join("\0"))
    }

    fn failures(&self, promoted: &PromotedSet) -> Result<Arc<FailureSet>, FlywheelError> {
        let key = promoted.hash();
        if let Some((cached, failures)) = &self.lock().failures
            && *cached == key
        {
            return Ok(Arc::clone(failures));
        }
        let current: Vec<Layer> = promoted_layer(promoted)?.into_iter().collect();
        let failures = Arc::new(FailureSet::compute(&self.engine, &current, self.gate.min_pattern_bytes)?);
        self.lock().failures = Some((key, Arc::clone(&failures)));
        Ok(failures)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn candidate_directory(&self, id: &str) -> Result<PathBuf, FlywheelError> {
        if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(FlywheelError::Invalid(format!("candidate id {id:?} is not one this server issued")));
        }
        Ok(self.paths().scratch(FAMILY).join(id))
    }

    pub fn load_candidate(&self, id: &str) -> Result<Candidate, FlywheelError> {
        let path = self.candidate_directory(id)?.join(CANDIDATE_FILE);
        if !path.is_file() {
            return Err(FlywheelError::Unknown(format!("no candidate {id}; propose_heuristic creates one")));
        }
        let text = read_bounded(&path, 16 * 1024 * 1024)?;
        serde_json::from_str(&text).map_err(|error| FlywheelError::Io(format!("{}: {error}", path.display())))
    }

    fn save_candidate(&self, candidate: &Candidate) -> Result<PathBuf, FlywheelError> {
        let directory = self.candidate_directory(&candidate.id)?;
        let text = serde_json::to_string_pretty(candidate).map_err(FlywheelError::json)?;
        write_atomic(&directory.join(CANDIDATE_FILE), text.as_bytes())?;
        write_pack(
            &directory,
            &format!("flywheel-candidate-{}", candidate.id),
            &format!("0.0.0-{}", &candidate.hash()[..12]),
            &self.corpus().license(),
            &format!("rampage flywheel scratch candidate {} (corpus {})", candidate.id, self.corpus().version()),
            "Scratch candidate: evaluated by the flywheel gate only, never applied elsewhere.",
            &candidate.rows,
        )?;
        Ok(directory)
    }

    fn event(&self, tool: &str, detail: Value) {
        let Some(run) = &self.run else { return };
        let path = self.paths().runs().join(run).join("events.jsonl");
        let line = json!({ "unix_ms": now_ms(), "tool": tool, "detail": detail }).to_string();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{line}");
        }
    }

    /// `corpus_failures`.
    pub fn corpus_failures(&self, input: Value) -> Result<Value, FlywheelError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            arch: Option<String>,
            compiler: Option<String>,
            opt: Option<String>,
            library: Option<String>,
            origin: Option<String>,
            outcome: Option<String>,
            name_contains: Option<String>,
            min_occurrences: Option<usize>,
            offset: Option<usize>,
            limit: Option<usize>,
            include_bytes: Option<bool>,
        }
        let input: Input = parse(input)?;
        if let Some(outcome) = &input.outcome
            && !["missed", "wrong", "spurious"].contains(&outcome.as_str())
        {
            return Err(FlywheelError::Invalid(format!("outcome {outcome:?} must be missed, wrong or spurious")));
        }
        let failures = self.failures(&self.promoted()?)?;
        let needle = input.name_contains.as_deref().map(str::to_lowercase);
        let configuration = |group: &FailureGroup, field: usize, want: &Option<String>| {
            want.as_ref().is_none_or(|want| {
                group.configurations.iter().any(|entry| entry.split('/').nth(field) == Some(want.as_str()))
            })
        };
        let selected: Vec<&FailureGroup> = failures
            .groups
            .iter()
            .filter(|group| input.arch.as_ref().is_none_or(|arch| group.arch == *arch))
            .filter(|group| configuration(group, 1, &input.compiler) && configuration(group, 2, &input.opt))
            .filter(|group| input.library.as_ref().is_none_or(|library| group.libraries.contains(library)))
            .filter(|group| input.origin.as_ref().is_none_or(|origin| group.origins.contains(origin)))
            .filter(|group| match input.outcome.as_deref() {
                Some("missed") => group.missed > 0,
                Some("wrong") => group.wrong > 0,
                Some("spurious") => group.spurious > 0,
                _ => true,
            })
            .filter(|group| group.occurrences >= input.min_occurrences.unwrap_or(1))
            .filter(|group| {
                needle.as_ref().is_none_or(|needle| {
                    group
                        .truth_names
                        .iter()
                        .chain(&group.proposed_names)
                        .any(|name| name.to_lowercase().contains(needle))
                })
            })
            .collect();
        let include_bytes = input.include_bytes.unwrap_or(true);
        let items: Vec<Value> = selected
            .iter()
            .map(|group| {
                let mut item = serde_json::to_value(bounded(group)).unwrap_or(Value::Null);
                if !include_bytes && let Some(object) = item.as_object_mut() {
                    object.remove("masked_bytes");
                }
                item
            })
            .collect();
        let limit = input.limit.unwrap_or(DEFAULT_FAILURES).clamp(1, MAX_FAILURES);
        let header = json!({
            "family": FAMILY,
            "corpus_version": self.corpus().version(),
            "split": "train",
            "binaries": failures.binaries,
            "truth_source": TRUTH_SOURCE,
            "undiscovered": failures.undiscovered,
            "below_gate": failures.below_gate,
            "groups_total": failures.groups.len(),
            "min_pattern_bytes": self.gate.min_pattern_bytes,
            "heldout_overlap": self.overlap,
            "warning": self.overlap.warning(),
            "hint": "Each group is one masked body of a target library (training versions) missed or misnamed \
                     across training binaries; runtime functions are not gated and not listed. The held-out split \
                     is the libraries' newer versions: rows that only recognise the training build gain nothing. \
                     Propose rows from `case` with the function's name; avoid groups with several truth_names.",
        });
        let budget = item_budget(&header).map_err(|error| FlywheelError::Invalid(error.to_string()))?;
        let page = FittedPage::of(items, input.offset, Some(limit), budget)
            .map_err(|error| FlywheelError::Invalid(error.to_string()))?;
        let mut output = header;
        output["total"] = json!(page.total);
        output["offset"] = json!(page.offset);
        output["next_offset"] = json!(page.next_offset);
        output["byte_capped"] = json!(page.byte_capped);
        output["groups"] = json!(page.items);
        Ok(output)
    }

    /// `propose_heuristic`.
    pub fn propose_heuristic(&self, input: Value) -> Result<Value, FlywheelError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            candidate: Option<String>,
            rows: Vec<RowInput>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RowInput {
            case: Option<String>,
            pattern: Option<String>,
            arch: Option<String>,
            name: String,
            library: Option<String>,
            #[serde(default)]
            wildcards: Vec<usize>,
        }
        let input: Input = parse(input)?;
        if input.rows.is_empty() || input.rows.len() > MAX_ROWS_PER_CALL {
            return Err(FlywheelError::Invalid(format!("give 1 to {MAX_ROWS_PER_CALL} rows")));
        }
        let promoted = self.promoted()?;
        let arches = self.corpus().arches();
        let mut rows = Vec::new();
        for (index, row) in input.rows.into_iter().enumerate() {
            let at = |message: String| FlywheelError::Invalid(format!("rows[{index}]: {message}"));
            let (arch, mut bytes, source) = match (&row.case, &row.pattern) {
                (Some(case), None) => {
                    let failures = self.failures(&promoted)?;
                    let group = failures.find(case).ok_or_else(|| {
                        FlywheelError::Unknown(format!(
                            "rows[{index}]: no training failure group {case}; corpus_failures lists them"
                        ))
                    })?;
                    if row.arch.as_ref().is_some_and(|arch| *arch != group.arch) {
                        return Err(at(format!("case {case} is {}, not {}", group.arch, row.arch.unwrap_or_default())));
                    }
                    let source = RowSource {
                        case: case.clone(),
                        binary: group.example.binary.clone(),
                        address: group.example.address.clone(),
                    };
                    (group.arch.clone(), parse_pattern(&group.masked_bytes).map_err(at)?, Some(source))
                }
                (None, Some(pattern)) => {
                    let arch = row.arch.clone().ok_or_else(|| at("a `pattern` row needs `arch`".to_owned()))?;
                    (arch, parse_pattern(pattern).map_err(at)?, None)
                }
                _ => return Err(at("give exactly one of `case` and `pattern`".to_owned())),
            };
            for &offset in &row.wildcards {
                let slot =
                    bytes.get_mut(offset).ok_or_else(|| at(format!("wildcard offset {offset} is past the pattern")))?;
                *slot = None;
            }
            let row = Row { arch, name: row.name, library: row.library, pattern: format_pattern(&bytes), source };
            row.validate(&arches, self.gate.min_pattern_bytes).map_err(|error| at(error.message().to_owned()))?;
            rows.push(row);
        }
        let _guard = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let mut candidate = match &input.candidate {
            Some(id) => self.load_candidate(id)?,
            None => Candidate {
                id: format!(
                    "c-{}",
                    &sha256_text(&format!("{}\0{}\0{:?}", now_ms(), std::process::id(), std::time::Instant::now()))
                        [..10]
                ),
                family: FAMILY.to_owned(),
                created_unix_ms: now_ms(),
                run: self.run.clone(),
                rows: Vec::new(),
            },
        };
        let mut added = Vec::new();
        for row in rows {
            let same = |other: &Row| other.arch == row.arch && other.name == row.name && other.pattern == row.pattern;
            if candidate.rows.iter().any(same) {
                continue;
            }
            if candidate.rows.len() >= super::MAX_ROWS {
                return Err(FlywheelError::Refused(format!("a candidate holds at most {} rows", super::MAX_ROWS)));
            }
            added.push(self.preview(&row)?);
            candidate.rows.push(row);
        }
        let directory = self.save_candidate(&candidate)?;
        let hash = candidate.hash();
        self.event("propose_heuristic", json!({ "candidate": candidate.id, "candidate_hash": hash, "rows": candidate.rows.len(), "added": added.len() }));
        Ok(json!({
            "candidate": candidate.id,
            "candidate_hash": hash,
            "rows": candidate.rows.len(),
            "added": added,
            "pack": directory,
            "next": "evaluate_candidate with this candidate runs the fast gate; stage \"heldout\" then runs the held-out gate.",
        }))
    }

    /// What one row would do on the training split alone: how many training functions its pattern matches and
    /// what their truth names are. The same rows over the bundled databases decide; this is a preview.
    fn preview(&self, row: &Row) -> Result<Value, FlywheelError> {
        let pattern = parse_pattern(&row.pattern).map_err(FlywheelError::Invalid)?;
        let mut matches = 0;
        let (mut same_name, mut other_name, mut not_library) = (0, 0, 0);
        let mut others = BTreeSet::new();
        let indices: Vec<usize> = self
            .corpus()
            .indices(Split::Train)
            .into_iter()
            .filter(|&index| self.engine.binary(index).arch == row.arch)
            .collect();
        for index in indices {
            let loaded = self.engine.get(index)?;
            for (address, body) in loaded.bodies() {
                if !pattern_matches(&pattern, body) {
                    continue;
                }
                matches += 1;
                match loaded.truth.get(&address) {
                    Some(truth) if truth.name == row.name => same_name += 1,
                    Some(truth) => {
                        other_name += 1;
                        others.insert(truth.name.clone());
                    }
                    None => not_library += 1,
                }
            }
        }
        Ok(json!({
            "name": row.name,
            "arch": row.arch,
            "length": pattern.len(),
            "wildcards": pattern.iter().filter(|byte| byte.is_none()).count(),
            "pat": row.pat_line()?,
            "train_preview": {
                "matches": matches,
                "truth_is_this_name": same_name,
                "truth_is_another_name": other_name,
                "not_library_code": not_library,
                "other_names": others.into_iter().take(MAX_PREVIEW_NAMES).collect::<Vec<_>>(),
            },
        }))
    }

    fn record_path(&self, key: &str) -> PathBuf {
        self.paths().evaluations(FAMILY).join(self.corpus().key()).join(format!("{key}.json"))
    }

    /// The key of a candidate's gate results: its rows, the corpus identity (version, split and binary hashes) and
    /// the baseline.
    fn record_key(&self, candidate_hash: &str, baseline_hash: &str) -> String {
        sha256_text(&format!("{candidate_hash}\0{}\0{baseline_hash}", self.corpus().identity()))
    }

    fn load_record(&self, key: &str) -> Option<EvaluationRecord> {
        let text = std::fs::read_to_string(self.record_path(key)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Runs the fast gate and, when `heldout`, the held-out gate on `candidate` against the current promoted
    /// state, reusing a cached result for the same (candidate hash, corpus version, baseline hash).
    fn evaluate(&self, candidate: &Candidate, heldout: bool) -> Result<(EvaluationRecord, bool), FlywheelError> {
        let promoted = self.promoted()?;
        let candidate_hash = candidate.hash();
        let baseline_hash = self.baseline_hash(&promoted);
        let key = self.record_key(&candidate_hash, &baseline_hash);
        let cached = self.load_record(&key);
        if let Some(record) = &cached
            && (!heldout || record.heldout.is_some() || !record.fast.gate.passed)
        {
            return Ok((record.clone(), true));
        }
        // The candidate is evaluated exactly as it would be promoted: its rows merged with the promoted ones.
        let reference: Vec<Layer> = promoted_layer(&promoted)?.into_iter().collect();
        let mut merged = promoted.rows();
        merged.extend(candidate.rows.iter().cloned());
        let layers: Vec<Layer> = layer("candidate", &merged)?.into_iter().collect();
        let mut record = match cached {
            Some(record) => record,
            None => {
                let fast = evaluate_split(&self.engine, Split::Fast, &layers, &reference)?;
                let mut train = evaluate_split(&self.engine, Split::Train, &layers, &reference)?;
                let negative = evaluate_split(&self.engine, Split::Negative, &layers, &reference)?;
                let gate = self.gate.fast(&fast, &train, &negative);
                // The fast slice's cases are kept; the training split only contributes its counts.
                train.cases.clear();
                EvaluationRecord {
                    candidate_hash,
                    corpus_version: self.corpus().version().to_owned(),
                    corpus_identity: self.corpus().identity().to_owned(),
                    baseline_hash,
                    fast: StageRecord { evaluation: fast, gate },
                    train,
                    negative,
                    heldout: None,
                }
            }
        };
        if heldout && record.fast.gate.passed {
            self.spend_heldout()?;
            // An error could name a held-out binary: the detail goes to the operator's log, not the proposer.
            let evaluation = evaluate_split(&self.engine, Split::Heldout, &layers, &reference).map_err(|error| {
                eprintln!("rampage flywheel: held-out evaluation failed: {error}");
                FlywheelError::Corpus(
                    "the held-out evaluation failed; the operator's server log has the detail".to_owned(),
                )
            })?;
            debug_assert!(evaluation.cases.is_empty());
            record.heldout = Some(StageRecord { gate: self.gate.heldout(&evaluation), evaluation });
        }
        let text = serde_json::to_string(&record).map_err(FlywheelError::json)?;
        write_atomic(&self.record_path(&key), text.as_bytes())?;
        Ok((record, false))
    }

    /// `evaluate_candidate`.
    pub fn evaluate_candidate(&self, input: Value) -> Result<Value, FlywheelError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            candidate: String,
            stage: Option<String>,
            cases_offset: Option<usize>,
            cases_limit: Option<usize>,
        }
        let input: Input = parse(input)?;
        let heldout = match input.stage.as_deref() {
            None | Some("fast") => false,
            Some("heldout") => true,
            Some(other) => return Err(FlywheelError::Invalid(format!("stage {other:?} must be fast or heldout"))),
        };
        let candidate = self.load_candidate(&input.candidate)?;
        if candidate.rows.is_empty() {
            return Err(FlywheelError::Invalid(format!("candidate {} has no rows", candidate.id)));
        }
        let (record, cached) = self.evaluate(&candidate, heldout)?;
        let fast = &record.fast;
        let heldout_value = match &record.heldout {
            Some(stage) => heldout_summary(stage),
            None if !fast.gate.passed => json!({ "status": "not_run", "reason": "the fast gate failed" }),
            None => json!({ "status": "not_run", "reason": "call again with stage \"heldout\"" }),
        };
        let promotable = record.heldout.as_ref().is_some_and(|stage| stage.gate.passed);
        let left = self.heldout_left();
        let mut header = json!({
            "candidate": candidate.id,
            "candidate_hash": record.candidate_hash,
            "corpus_version": record.corpus_version,
            "baseline_hash": record.baseline_hash,
            "cached": cached,
            "promotable": promotable,
            "heldout_evaluations_left": left,
            "fast": fast_summary(&record),
            "heldout": heldout_value,
        });
        self.event(
            "evaluate_candidate",
            json!({
                "candidate": candidate.id,
                "candidate_hash": record.candidate_hash,
                "rows": candidate.rows.len(),
                "cached": cached,
                "fast": { "passed": fast.gate.passed, "deltas": fast.evaluation.deltas().get("all") },
                "heldout": record.heldout.as_ref().map(|stage| json!({
                    "passed": stage.gate.passed,
                    "checks": stage.gate.checks,
                    "deltas": stage.evaluation.deltas().get("all"),
                    "elapsed_ms": stage.evaluation.elapsed_ms,
                })),
                "fast_elapsed_ms": fast.evaluation.elapsed_ms,
            }),
        );
        let limit = input.cases_limit.unwrap_or(DEFAULT_CASES).clamp(1, MAX_CASES);
        // Fast-slice cases first, then every name the candidate gives on the negatives.
        let mut cases = fast.evaluation.cases.clone();
        cases.extend(record.negative.cases.iter().cloned());
        let budget = item_budget(&header).map_err(|error| FlywheelError::Invalid(error.to_string()))?;
        let page = FittedPage::of(cases, input.cases_offset, Some(limit), budget)
            .map_err(|error| FlywheelError::Invalid(error.to_string()))?;
        header["fast"]["cases_total"] = json!(page.total);
        header["fast"]["cases_offset"] = json!(page.offset);
        header["fast"]["cases_next_offset"] = json!(page.next_offset);
        header["fast"]["cases"] = json!(page.items);
        Ok(header)
    }

    /// `promote_candidate`.
    pub fn promote_candidate(&self, input: Value) -> Result<Value, FlywheelError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            candidate: String,
        }
        let input: Input = parse(input)?;
        let _guard = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let _lock = super::promote::lock(self.paths(), FAMILY)?;
        let candidate = self.load_candidate(&input.candidate)?;
        let mut promoted = self.promoted()?;
        let candidate_hash = candidate.hash();
        let baseline_hash = self.baseline_hash(&promoted);
        let key = self.record_key(&candidate_hash, &baseline_hash);
        let record = self.load_record(&key);
        let heldout = record.as_ref().and_then(|record| record.heldout.as_ref());
        let Some(heldout) = heldout.filter(|stage| stage.gate.passed) else {
            let why = match heldout {
                Some(_) => "its held-out gate failed",
                None => {
                    "it has no held-out result for its current rows, this corpus and the current baseline \
                         (promotions since change the baseline)"
                }
            };
            self.event(
                "promote_candidate",
                json!({ "candidate": candidate.id, "candidate_hash": candidate_hash, "refused": why }),
            );
            return Err(FlywheelError::Refused(format!(
                "candidate {} cannot be promoted: {why}; evaluate_candidate with stage \"heldout\" decides",
                candidate.id
            )));
        };
        let record = record.as_ref().expect("a held-out stage has a record");
        let revert = revert_id(&candidate_hash, self.corpus().version(), &baseline_hash);
        let dimension = |metrics: BTreeMap<String, SliceMetrics>| -> BTreeMap<String, SliceMetrics> {
            metrics.into_iter().filter(|(slice, _)| !slice.starts_with("cell:")).collect()
        };
        let entry = PromotedEntry {
            revert_id: revert.clone(),
            family: FAMILY.to_owned(),
            candidate_id: candidate.id.clone(),
            candidate_hash: candidate_hash.clone(),
            rows: candidate.rows.clone(),
            driving_cases: candidate.rows.iter().filter_map(|row| row.source.clone()).collect(),
            corpus_version: self.corpus().version().to_owned(),
            split: Split::Heldout.name().to_owned(),
            baseline_hash: baseline_hash.clone(),
            build_id: build_id().to_owned(),
            gate: self.gate.clone(),
            fast: record.fast.gate.clone(),
            heldout: heldout.gate.clone(),
            heldout_reference: dimension(heldout.evaluation.reference_metrics()),
            heldout_candidate: dimension(heldout.evaluation.metrics()),
            heldout_deltas: heldout
                .evaluation
                .deltas()
                .into_iter()
                .filter(|(slice, _)| !slice.starts_with("cell:"))
                .collect(),
            proposer_run: candidate.run.clone().or_else(|| self.run.clone()),
            promoted_unix_ms: now_ms(),
        };
        promoted.entries.push(entry.clone());
        promoted.save(self.paths(), &self.corpus().license())?;
        self.lock().failures = None;
        self.event(
            "promote_candidate",
            json!({ "candidate": candidate.id, "candidate_hash": candidate_hash, "revert_id": revert, "rows": candidate.rows.len(), "heldout_deltas": entry.heldout_deltas.get("all") }),
        );
        Ok(json!({
            "promoted": true,
            "revert_id": revert,
            "candidate": candidate.id,
            "candidate_hash": candidate_hash,
            "rows": candidate.rows.len(),
            "pack": self.paths().promoted(FAMILY),
            "heldout_delta": overall_delta(&heldout.evaluation),
            "revert": format!("rampage-eval flywheel-revert {revert}"),
            "note": "Later candidates are gated against this promotion; their earlier gate results are stale.",
        }))
    }
}

fn parse<T: serde::de::DeserializeOwned>(input: Value) -> Result<T, FlywheelError> {
    let input = if input.is_null() { json!({}) } else { input };
    serde_json::from_value(input).map_err(|error| FlywheelError::Invalid(error.to_string()))
}

/// A failure group with its lists bounded for a tool result.
fn bounded(group: &FailureGroup) -> FailureGroup {
    let mut group = group.clone();
    for list in [&mut group.truth_names, &mut group.proposed_names, &mut group.configurations, &mut group.libraries] {
        if list.len() > MAX_LISTED {
            let more = list.len() - MAX_LISTED;
            list.truncate(MAX_LISTED);
            list.push(format!("... {more} more"));
        }
    }
    group
}

/// Slices along one dimension (arch, compiler, opt, program library, origin) and overall: cells are left to the
/// gate.
fn dimension_slices<T: Clone>(map: &BTreeMap<String, T>) -> BTreeMap<String, T> {
    map.iter()
        .filter(|(slice, _)| !slice.starts_with("cell:"))
        .map(|(slice, value)| (slice.clone(), value.clone()))
        .collect()
}

/// The gated scope's change: true positives, false positives, false negatives and F1.
fn overall_delta(evaluation: &SplitEvaluation) -> Value {
    let delta = evaluation.deltas().remove("all");
    json!(delta)
}

fn fast_summary(record: &EvaluationRecord) -> Value {
    let stage = &record.fast;
    let evaluation = &stage.evaluation;
    let reference = evaluation.reference_metrics();
    let candidate = evaluation.metrics();
    json!({
        "passed": stage.gate.passed,
        "checks": stage.gate.checks,
        "failing_slices": stage.gate.failing_slices,
        "binaries": evaluation.binaries,
        "reidentified": evaluation.reidentified + record.train.reidentified + record.negative.reidentified,
        "elapsed_ms": evaluation.elapsed_ms + record.train.elapsed_ms + record.negative.elapsed_ms,
        "overall": { "before": reference.get("all"), "after": candidate.get("all") },
        "deltas": dimension_slices(&evaluation.deltas()),
        "fixed": evaluation.fixed,
        "broken": evaluation.broken,
        "train": { "binaries": record.train.binaries, "delta": overall_delta(&record.train) },
        "negatives": { "binaries": record.negative.binaries, "new_names": record.negative.cases.len() },
    })
}

/// The held-out result: the verdict and the overall delta only. Per-slice deltas and counts of fixed or broken
/// functions would tell a proposer which held-out code its rows touch.
fn heldout_summary(stage: &StageRecord) -> Value {
    let checks: Vec<Value> = stage
        .gate
        .checks
        .iter()
        .map(|check| {
            let detail = matches!(check.rule.as_str(), "heldout_f1_gain" | "heldout_fp_increase");
            json!({ "rule": check.rule, "passed": check.passed, "detail": detail.then_some(&check.detail) })
        })
        .collect();
    json!({
        "status": "run",
        "passed": stage.gate.passed,
        "checks": checks,
        "overall_delta": overall_delta(&stage.evaluation),
        "elapsed_ms": stage.evaluation.elapsed_ms,
    })
}

/// One `improve` tool.
pub struct ImproveTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    handler: fn(&Improve, Value) -> Result<Value, FlywheelError>,
}

impl ImproveTool {
    /// Runs the tool; an error is the JSON `{"error": kind, "message": ...}`.
    pub fn call(&self, improve: &Improve, input: Value) -> Result<Value, String> {
        (self.handler)(improve, input).map_err(|error| error.to_json())
    }
}

/// The `improve` group's tools, in the order an agent uses them.
pub fn improve_tools() -> Vec<ImproveTool> {
    vec![
        ImproveTool {
            name: "corpus_failures",
            description: "Library-identification failures on the flywheel corpus's TRAINING split (held-out \
                binaries are never shown), grouped by masked body: each group is one function body (same \
                architecture, length and fixed bytes) that the bundled and promoted signatures miss, name wrongly \
                or name spuriously, with its truth names (from the symbolized twin), occurrences, configurations \
                (arch/compiler/opt), program libraries, an example binary/address and `masked_bytes` (hex, `..` \
                for position-dependent bytes). Only target-library functions and false names are listed. Sorted by \
                occurrences. Filters: arch, compiler, opt, library (the program's), origin, outcome (missed, wrong, \
                spurious), name_contains, min_occurrences. Paged with offset/limit (default 20, at most 200) and \
                fitted to the result size.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "arch": { "type": "string" },
                    "compiler": { "type": "string" },
                    "opt": { "type": "string" },
                    "library": { "type": "string", "description": "The program's library, e.g. zlib." },
                    "origin": { "type": "string", "description": "The truth function's origin: a library or runtime." },
                    "outcome": { "type": "string", "enum": ["missed", "wrong", "spurious"] },
                    "name_contains": { "type": "string" },
                    "min_occurrences": { "type": "integer", "minimum": 1 },
                    "offset": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                    "include_bytes": { "type": "boolean", "description": "Include masked_bytes (default true)." }
                },
                "additionalProperties": false
            }),
            handler: Improve::corpus_failures,
        },
        ImproveTool {
            name: "propose_heuristic",
            description: "Add signature rows to a scratch candidate (a data pack under target/flywheel/scratch/; \
                data only, never applied outside evaluation). Each row is a whole-function byte pattern, a name \
                and an optional library tag, stored as a PAT record: give `case` (a corpus_failures group: its \
                masked_bytes become the pattern) or `pattern` (hex, `..` wildcards) with `arch`; `wildcards` adds \
                wildcard byte offsets. A body matches only at the pattern's exact length. Rows are schema-checked \
                (at least the gate's minimum length, 32 bytes by default, and enough fixed bytes to ever answer). Omit `candidate` to start a new one. Returns the candidate id \
                and hash and, per row, a training-split preview: how many training functions it matches and \
                whether their truth is this name.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "candidate": { "type": "string", "description": "An existing candidate to add to." },
                    "rows": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_ROWS_PER_CALL,
                        "items": {
                            "type": "object",
                            "properties": {
                                "case": { "type": "string", "description": "A corpus_failures group id." },
                                "pattern": { "type": "string", "description": "Hex bytes with `..` wildcards." },
                                "arch": { "type": "string" },
                                "name": { "type": "string", "description": "The function name a match gives." },
                                "library": { "type": "string" },
                                "wildcards": { "type": "array", "items": { "type": "integer", "minimum": 0 } }
                            },
                            "required": ["name"],
                            "additionalProperties": false
                        }
                    }
                },
                "required": ["rows"],
                "additionalProperties": false
            }),
            handler: Improve::propose_heuristic,
        },
        ImproveTool {
            name: "evaluate_candidate",
            description: "Gate a candidate, merged with the promoted rows, against the current state (bundled and \
                promoted signatures). Only the target libraries' own functions are scored; any false name counts. \
                stage \"fast\" (default) runs on training data and negatives: no new false positive on the full \
                training split, no name at all on the negative binaries (unrelated code), no gated slice losing F1; \
                it returns the fast slice's per-slice deltas and its changed cases plus every name given on the \
                negatives, paged with cases_offset/cases_limit. stage \"heldout\" runs the fast gate and, if it \
                passes, the held-out gate on the libraries' newer versions (overall F1 gain of at least the minimum, \
                no new false positive, no slice regression): pass/fail and the overall delta only. Results are \
                cached by (candidate hash, corpus identity, baseline hash); held-out evaluations per corpus are \
                limited across all servers.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "candidate": { "type": "string" },
                    "stage": { "type": "string", "enum": ["fast", "heldout"] },
                    "cases_offset": { "type": "integer", "minimum": 0 },
                    "cases_limit": { "type": "integer", "minimum": 1, "maximum": 200 }
                },
                "required": ["candidate"],
                "additionalProperties": false
            }),
            handler: Improve::evaluate_candidate,
        },
        ImproveTool {
            name: "promote_candidate",
            description: "Promote a candidate into the promoted pack (target/flywheel/promoted/libid/, loadable \
                with --pack) with full provenance: rows, driving cases, held-out metric deltas, gate settings, \
                corpus version and proposer run. Refused unless evaluate_candidate recorded a passing held-out \
                gate for this candidate's exact rows, this corpus version and the current baseline. Returns a \
                revert id (`rampage-eval flywheel-revert <id>` removes the entry).",
            input_schema: json!({
                "type": "object",
                "properties": { "candidate": { "type": "string" } },
                "required": ["candidate"],
                "additionalProperties": false
            }),
            handler: Improve::promote_candidate,
        },
    ]
}
