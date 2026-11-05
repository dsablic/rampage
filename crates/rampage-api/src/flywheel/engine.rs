//! The evaluator: truth and baseline analysis per corpus binary, both cached on disk, and identification of each
//! binary's discovered functions under a candidate's layers, re-run only where a layer could change an answer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use rampage_arch::Arch;
use rampage_loaders::Binary;
use rampage_signatures::{MaskContext, SignatureDb, canonical_functions, identify_program_sources, named_functions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::corpus::{Corpus, CorpusBinary};
use super::{FlywheelError, Paths, hex, write_atomic};
use crate::{Packs, Project};

/// Bumped when the cached truth or baseline format or meaning changes, so old entries are not reused.
const CACHE_FORMAT: &str = "flywheel-cache-v1";

/// One truth function: its name in the symbolized twin and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthFunction {
    pub name: String,
    /// The library that defines it, or `runtime` (libc, compiler runtime) when the library object does not.
    pub origin: String,
}

/// How one scored address came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Correct,
    /// A name at a truth function that is not its name: a false positive and a miss at once.
    Wrong,
    /// A truth function without a name.
    Missed,
    /// A name where the truth has no library function (the program's own code, or no function).
    Spurious,
}

/// One corpus binary ready to evaluate.
pub struct Loaded {
    pub binary: Binary,
    pub image: MaskContext,
    pub truth: BTreeMap<u64, TruthFunction>,
    /// Each discovered function with a body: start and exclusive end.
    pub functions: Vec<(u64, u64)>,
    /// The names the bundled databases alone give: the cached baseline.
    pub baseline: BTreeMap<u64, String>,
}

impl Loaded {
    /// The discovered functions' bodies, as identification hashes them.
    pub fn bodies(&self) -> Vec<(u64, &[u8])> {
        self.functions
            .iter()
            .filter_map(|&(start, end)| Some((start, self.binary.read(start, end.checked_sub(start)?)?)))
            .collect()
    }

    pub fn body(&self, start: u64) -> Option<&[u8]> {
        let index = self.functions.binary_search_by_key(&start, |&(start, _)| start).ok()?;
        let (start, end) = self.functions[index];
        self.binary.read(start, end.checked_sub(start)?)
    }

    /// Each scored address's outcome under `names`.
    pub fn outcomes(&self, names: &BTreeMap<u64, String>) -> BTreeMap<u64, Outcome> {
        let mut outcomes = BTreeMap::new();
        for (address, truth) in &self.truth {
            let outcome = match names.get(address) {
                Some(name) if *name == truth.name => Outcome::Correct,
                Some(_) => Outcome::Wrong,
                None => Outcome::Missed,
            };
            outcomes.insert(*address, outcome);
        }
        for address in names.keys().filter(|address| !self.truth.contains_key(address)) {
            outcomes.insert(*address, Outcome::Spurious);
        }
        outcomes
    }

    pub fn discovered(&self, address: u64) -> bool {
        self.functions.binary_search_by_key(&address, |&(start, _)| start).is_ok()
    }
}

/// A layer of signature databases over the bundled ones, as a candidate or the promoted pack contributes it.
pub struct Layer {
    pub name: String,
    pub databases: Vec<SignatureDb>,
    /// When every database is pattern-only, the patterns (architecture, wildcarded bytes): a body none of them
    /// matches cannot get a new name from this layer, so a binary without such a body keeps its baseline answers.
    pub patterns: Option<Vec<(Arch, Vec<Option<u8>>)>>,
}

impl Layer {
    fn could_change(&self, arch: Arch, loaded: &Loaded) -> bool {
        let Some(patterns) = &self.patterns else { return true };
        let relevant: Vec<&Vec<Option<u8>>> =
            patterns.iter().filter(|(pattern_arch, _)| *pattern_arch == arch).map(|(_, bytes)| bytes).collect();
        if relevant.is_empty() {
            return false;
        }
        loaded.bodies().iter().any(|(_, body)| relevant.iter().any(|pattern| pattern_matches(pattern, body)))
    }
}

/// Whether `body` has exactly `pattern`'s length and every fixed byte.
pub fn pattern_matches(pattern: &[Option<u8>], body: &[u8]) -> bool {
    pattern.len() == body.len() && pattern.iter().zip(body).all(|(want, have)| want.is_none_or(|want| want == *have))
}

/// The names one evaluation gave each binary.
pub struct Proposals {
    pub names: BTreeMap<usize, BTreeMap<u64, String>>,
    /// Binaries identified again rather than answered from the baseline.
    pub reidentified: usize,
    pub elapsed_ms: u64,
}

/// Loads corpus binaries on demand, caching truth and baseline on disk, and evaluates layers over them.
pub struct Engine {
    pub corpus: Corpus,
    pub paths: Paths,
    workers: usize,
    loaded: Vec<OnceLock<Result<Arc<Loaded>, String>>>,
}

/// Counters of one engine's cache use, for timing reports.
#[derive(Debug, Default, Clone, Serialize)]
pub struct LoadReport {
    pub binaries: usize,
    pub truth_cached: usize,
    pub baseline_cached: usize,
    pub analysed: usize,
    pub elapsed_ms: u64,
}

impl Engine {
    pub fn new(corpus: Corpus, paths: Paths, workers: usize) -> Engine {
        let loaded = corpus.manifest.binaries.iter().map(|_| OnceLock::new()).collect();
        Engine { corpus, paths, workers: workers.max(1), loaded }
    }

    pub fn workers(&self) -> usize {
        self.workers
    }

    pub fn binary(&self, index: usize) -> &CorpusBinary {
        &self.corpus.manifest.binaries[index]
    }

    /// The loaded binary at `index`.
    pub fn get(&self, index: usize) -> Result<Arc<Loaded>, FlywheelError> {
        self.loaded[index]
            .get_or_init(|| self.load(index).map(Arc::new).map_err(|error| error.to_string()))
            .clone()
            .map_err(FlywheelError::Corpus)
    }

    /// Loads every binary of `indices` with the configured workers, reporting what came from the caches.
    pub fn load_all(&self, indices: &[usize]) -> Result<LoadReport, FlywheelError> {
        let started = Instant::now();
        let pending: Vec<usize> = indices.iter().copied().filter(|&index| self.loaded[index].get().is_none()).collect();
        let before = self.cache_counts(&pending);
        self.parallel(&pending, |index| self.get(index).map(|_| ()))?;
        let after = self.cache_counts(&pending);
        Ok(LoadReport {
            binaries: pending.len(),
            truth_cached: before.0,
            baseline_cached: before.1,
            analysed: after.1.saturating_sub(before.1),
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }

    fn cache_counts(&self, indices: &[usize]) -> (usize, usize) {
        let truth = indices.iter().filter(|&&index| self.truth_path(index).is_file()).count();
        let baseline =
            indices.iter().filter(|&&index| self.baseline_path(index).is_ok_and(|path| path.is_file())).count();
        (truth, baseline)
    }

    /// Runs `work` over `indices` with at most the configured number of threads, stopping at the first error.
    pub fn parallel<T: Send>(
        &self,
        indices: &[usize],
        work: impl Fn(usize) -> Result<T, FlywheelError> + Sync,
    ) -> Result<Vec<T>, FlywheelError> {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<std::sync::Mutex<Option<Result<T, FlywheelError>>>> =
            indices.iter().map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|scope| {
            for _ in 0..self.workers.min(indices.len().max(1)) {
                scope.spawn(|| {
                    loop {
                        let position = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&index) = indices.get(position) else { break };
                        let result = work(index);
                        let failed = result.is_err();
                        *results[position].lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
                        if failed {
                            next.store(indices.len(), std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        let mut out = Vec::with_capacity(indices.len());
        for slot in results {
            match slot.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner) {
                Some(Ok(value)) => out.push(value),
                Some(Err(error)) => return Err(error),
                None => {}
            }
        }
        if out.len() != indices.len() {
            return Err(FlywheelError::Corpus("an evaluation worker stopped early".to_owned()));
        }
        Ok(out)
    }

    /// Identifies every binary of `indices` under `layers` over the bundled databases. A binary none of the layers
    /// could change keeps its cached baseline answers without being identified again.
    pub fn propose(&self, indices: &[usize], layers: &[Layer]) -> Result<Proposals, FlywheelError> {
        let started = Instant::now();
        let results = self.parallel(indices, |index| {
            let loaded = self.get(index)?;
            let arch = loaded.binary.arch;
            if !layers.iter().any(|layer| layer.could_change(arch, &loaded)) {
                return Ok((index, loaded.baseline.clone(), false));
            }
            let mut databases: Vec<&SignatureDb> = layers
                .iter()
                .flat_map(|layer| layer.databases.iter().filter(move |database| database.arch() == arch))
                .collect();
            databases.extend(rampage_signatures::bundled_ref(arch));
            let bodies = loaded.bodies();
            let names = identify_program_sources(&databases, &loaded.binary.target(), &loaded.image, &bodies);
            Ok((index, names.into_iter().map(|(address, (_, name))| (address, name.to_owned())).collect(), true))
        })?;
        let reidentified = results.iter().filter(|(_, _, again)| *again).count();
        Ok(Proposals {
            names: results.into_iter().map(|(index, names, _)| (index, names)).collect(),
            reidentified,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }

    fn load(&self, index: usize) -> Result<Loaded, FlywheelError> {
        let entry = self.binary(index);
        let stripped_path = self.corpus.path(&entry.stripped);
        let binary = Binary::open(&stripped_path).map_err(|error| FlywheelError::io_text(&stripped_path, error))?;
        if binary.arch.to_string() != entry.arch {
            return Err(FlywheelError::Corpus(format!(
                "{}: the binary is {}, the manifest says {}",
                entry.id, binary.arch, entry.arch
            )));
        }
        let truth = self.truth(index, &binary)?;
        let (functions, baseline) = self.baseline(index)?;
        let image = MaskContext::from_binary(&binary);
        Ok(Loaded { binary, image, truth, functions, baseline })
    }

    fn truth_path(&self, index: usize) -> PathBuf {
        let entry = self.binary(index);
        let mut hasher = Sha256::new();
        for part in [
            CACHE_FORMAT,
            &entry.stripped_sha256,
            &entry.twin_sha256,
            entry.program_object_sha256.as_deref().unwrap_or(""),
            entry.library_object_sha256.as_deref().unwrap_or(""),
            &entry.library,
            &entry.program_names.join("\n"),
        ] {
            hasher.update(part.as_bytes());
            hasher.update([0]);
        }
        self.paths.cache().join("truth").join(format!("{}.json", hex(&hasher.finalize())))
    }

    /// The binary's library functions from its symbolized twin, cached by the hashes of the files it comes from.
    fn truth(&self, index: usize, stripped: &Binary) -> Result<BTreeMap<u64, TruthFunction>, FlywheelError> {
        let path = self.truth_path(index);
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(cached) = serde_json::from_str::<CachedTruth>(&text)
        {
            return Ok(cached.functions.into_iter().map(|function| (function.address, function.truth)).collect());
        }
        let entry = self.binary(index);
        let truth = derive_truth(&self.corpus, entry, stripped)?;
        let cached = CachedTruth {
            binary: entry.id.clone(),
            functions: truth
                .iter()
                .map(|(&address, truth)| CachedTruthFunction { address, truth: truth.clone() })
                .collect(),
        };
        write_atomic(&path, serde_json::to_string(&cached).map_err(FlywheelError::json)?.as_bytes())?;
        Ok(truth)
    }

    fn baseline_path(&self, index: usize) -> Result<PathBuf, FlywheelError> {
        let entry = self.binary(index);
        let arch: Arch = entry.arch.parse().map_err(FlywheelError::Corpus)?;
        let mut hasher = Sha256::new();
        for part in [CACHE_FORMAT, &entry.stripped_sha256, &bundled_hash(arch), super::build_id()] {
            hasher.update(part.as_bytes());
            hasher.update([0]);
        }
        Ok(self.paths.cache().join("baseline").join(format!("{}.json", hex(&hasher.finalize()))))
    }

    /// Discovery and bundled-only identification of the stripped binary, through the same project analysis and
    /// identification the API serves, cached by (binary hash, bundled database hash, rampage build id).
    fn baseline(&self, index: usize) -> Result<Baseline, FlywheelError> {
        let path = self.baseline_path(index)?;
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(cached) = serde_json::from_str::<CachedBaseline>(&text)
        {
            return Ok((cached.functions, cached.names.into_iter().collect()));
        }
        let entry = self.binary(index);
        let stripped_path = self.corpus.path(&entry.stripped);
        let started = Instant::now();
        let binary = Binary::open(&stripped_path).map_err(|error| FlywheelError::io_text(&stripped_path, error))?;
        let project = Project::new(binary);
        // Only the bundled databases: never a pack from the environment.
        project.set_packs(Arc::new(Packs::default()));
        let analysis = project.analysis().map_err(|error| FlywheelError::Corpus(format!("{}: {error}", entry.id)))?;
        let mut functions: Vec<(u64, u64)> = analysis
            .program
            .functions
            .iter()
            .filter(|function| function.body(&project.binary).is_some())
            .map(|function| (function.address, function.end()))
            .collect();
        functions.sort_unstable();
        functions.dedup_by_key(|(start, _)| *start);
        let application = project
            .identify_functions(None, true, false)
            .map_err(|error| FlywheelError::Corpus(format!("{}: {error}", entry.id)))?;
        let names: BTreeMap<u64, String> =
            application.matches.into_iter().map(|matched| (matched.address, matched.name)).collect();
        let cached = CachedBaseline {
            binary: entry.id.clone(),
            analysis_ms: started.elapsed().as_millis() as u64,
            functions: functions.clone(),
            names: names.iter().map(|(&address, name)| (address, name.clone())).collect(),
        };
        write_atomic(&path, serde_json::to_string(&cached).map_err(FlywheelError::json)?.as_bytes())?;
        Ok((functions, names))
    }
}

/// Discovered extents and the bundled-only names of one binary.
type Baseline = (Vec<(u64, u64)>, BTreeMap<u64, String>);

#[derive(Serialize, Deserialize)]
struct CachedTruth {
    binary: String,
    functions: Vec<CachedTruthFunction>,
}

#[derive(Serialize, Deserialize)]
struct CachedTruthFunction {
    address: u64,
    #[serde(flatten)]
    truth: TruthFunction,
}

#[derive(Serialize, Deserialize)]
struct CachedBaseline {
    binary: String,
    analysis_ms: u64,
    functions: Vec<(u64, u64)>,
    names: Vec<(u64, String)>,
}

/// The SHA-256 of the bundled signature asset for `arch` (empty when none ships), part of the baseline key.
pub fn bundled_hash(arch: Arch) -> String {
    match SignatureDb::bundled_metadata(arch) {
        Ok(Some(metadata)) => metadata.gzip_sha256.clone(),
        Ok(None) => "none".to_owned(),
        Err(_) => "invalid".to_owned(),
    }
}

/// Every function of the symbolized twin except the program's own, each tagged with the library that defines
/// it: the existing strip-and-compare truth (`rampage-eval truth --library <twin> --program <object>`), after
/// checking that every truth function's bytes are identical in the stripped binary.
fn derive_truth(
    corpus: &Corpus,
    entry: &CorpusBinary,
    stripped: &Binary,
) -> Result<BTreeMap<u64, TruthFunction>, FlywheelError> {
    let open = |relative: &str| -> Result<Binary, FlywheelError> {
        let path = corpus.path(relative);
        Binary::open(&path).map_err(|error| FlywheelError::io_text(&path, error))
    };
    let twin = open(&entry.twin)?;
    for symbol in named_functions(&twin) {
        let ours = twin.read(symbol.address, symbol.size);
        if ours.is_none() || ours != stripped.read(symbol.address, symbol.size) {
            return Err(FlywheelError::Corpus(format!(
                "{}: the stripped binary is not a twin: {} at {:#x} differs",
                entry.id, symbol.name, symbol.address
            )));
        }
    }
    let names =
        |binary: &Binary| -> BTreeSet<String> { named_functions(binary).map(|symbol| symbol.name.clone()).collect() };
    let mut program: BTreeSet<String> = entry.program_names.iter().cloned().collect();
    if let Some(object) = &entry.program_object {
        program.extend(names(&open(object)?));
    }
    let library = match &entry.library_object {
        Some(object) => Some(names(&open(object)?)),
        None => None,
    };
    let mut aliases: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for symbol in named_functions(&twin) {
        aliases.entry(symbol.address).or_default().push(symbol.name.as_str());
    }
    let mut truth = BTreeMap::new();
    for (address, symbol) in canonical_functions(&twin) {
        let aliases = aliases.get(&address).map(Vec::as_slice).unwrap_or_default();
        // Any alias of a program function marks the address as program code.
        if aliases.iter().any(|alias| program.contains(*alias)) {
            continue;
        }
        let origin = match &library {
            Some(library) if aliases.iter().any(|alias| library.contains(*alias)) => entry.library.clone(),
            _ => "runtime".to_owned(),
        };
        truth.insert(address, TruthFunction { name: symbol.name.clone(), origin });
    }
    Ok(truth)
}

/// Per-slice true/false positives and negatives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub correct: u64,
    pub wrong: u64,
    pub missed: u64,
    pub spurious: u64,
}

impl Counts {
    pub fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Correct => self.correct += 1,
            Outcome::Wrong => self.wrong += 1,
            Outcome::Missed => self.missed += 1,
            Outcome::Spurious => self.spurious += 1,
        }
    }

    pub fn tp(&self) -> u64 {
        self.correct
    }

    /// Wrong and spurious names.
    pub fn fp(&self) -> u64 {
        self.wrong + self.spurious
    }

    /// Missed truth functions and those named wrongly.
    pub fn fn_(&self) -> u64 {
        self.missed + self.wrong
    }

    pub fn precision(&self) -> f64 {
        ratio(self.tp(), self.tp() + self.fp())
    }

    pub fn recall(&self) -> f64 {
        ratio(self.tp(), self.tp() + self.fn_())
    }

    pub fn f1(&self) -> f64 {
        ratio(2 * self.tp(), 2 * self.tp() + self.fp() + self.fn_())
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 }
}

/// One slice's metrics as reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SliceMetrics {
    pub tp: u64,
    pub fp: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub counts: Counts,
}

impl From<Counts> for SliceMetrics {
    fn from(counts: Counts) -> SliceMetrics {
        SliceMetrics {
            tp: counts.tp(),
            fp: counts.fp(),
            fn_: counts.fn_(),
            precision: round(counts.precision()),
            recall: round(counts.recall()),
            f1: round(counts.f1()),
            counts,
        }
    }
}

/// Six decimals: enough to see one function in a million, and stable in JSON.
pub fn round(value: f64) -> f64 {
    (value * 1e6).round() / 1e6
}

/// Each slice's counts over a set of binaries.
pub fn slice_counts(engine: &Engine, outcomes: &BTreeMap<usize, BTreeMap<u64, Outcome>>) -> BTreeMap<String, Counts> {
    let mut slices: BTreeMap<String, Counts> = BTreeMap::new();
    for (&index, outcomes) in outcomes {
        let keys = engine.binary(index).slices();
        for outcome in outcomes.values() {
            for key in &keys {
                slices.entry(key.clone()).or_default().add(*outcome);
            }
        }
    }
    slices
}
