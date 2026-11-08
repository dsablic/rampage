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

/// The origin of truth functions no target library object defines: libc and the compiler runtime.
pub const RUNTIME: &str = "runtime";

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

    /// The discovered function at `address` as scheme 2 masks it (`..` for position-dependent bytes), `None` when
    /// there is none or it fails the confidence gate: the pattern a row for it starts from.
    pub fn masked(&self, address: u64) -> Option<Vec<Option<u8>>> {
        let body = self.body(address)?;
        rampage_signatures::masked_body_in(&self.binary.target(), &self.image, body, address)
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

/// A masked body as a signature sees it: its architecture and canonical pattern (`format_pattern`).
pub type BodyKey = (String, String);

/// Signature databases standing in for the bundled ones (one per architecture): a regenerated bundled asset measured
/// before it is compiled in (`rampage-eval bundle`).
pub type Bundled = Vec<SignatureDb>;

/// The names one evaluation gave each binary.
#[derive(Debug, Clone)]
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
    /// The training split's masked library bodies, once computed.
    training: OnceLock<Result<Arc<BTreeSet<BodyKey>>, String>>,
    /// Per held-out binary: each target-library truth function and whether its body is novel.
    novelty: Vec<OnceLock<Arc<BTreeMap<u64, bool>>>>,
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
        let novelty = corpus.manifest.binaries.iter().map(|_| OnceLock::new()).collect();
        Engine { corpus, paths, workers: workers.max(1), loaded, training: OnceLock::new(), novelty }
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
        self.propose_in(indices, layers, None)
    }

    /// [`Engine::propose`] with `bundled` standing in for the bundled databases: then every binary is identified
    /// again, since the cached baseline is the compiled-in databases' answer.
    pub fn propose_in(
        &self,
        indices: &[usize],
        layers: &[Layer],
        bundled: Option<&Bundled>,
    ) -> Result<Proposals, FlywheelError> {
        let started = Instant::now();
        let results = self.parallel(indices, |index| {
            let loaded = self.get(index)?;
            let arch = loaded.binary.arch;
            if bundled.is_none() && !layers.iter().any(|layer| layer.could_change(arch, &loaded)) {
                return Ok((index, loaded.baseline.clone(), false));
            }
            Ok((index, self.identify(&loaded, layers, bundled), true))
        })?;
        let reidentified = results.iter().filter(|(_, _, again)| *again).count();
        Ok(Proposals {
            names: results.into_iter().map(|(index, names, _)| (index, names)).collect(),
            reidentified,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }

    /// The names `layers` over the bundled databases (or `bundled`) give one binary's discovered functions.
    fn identify(&self, loaded: &Loaded, layers: &[Layer], bundled: Option<&Bundled>) -> BTreeMap<u64, String> {
        let arch = loaded.binary.arch;
        let mut databases: Vec<&SignatureDb> = layers
            .iter()
            .flat_map(|layer| layer.databases.iter().filter(move |database| database.arch() == arch))
            .collect();
        match bundled {
            Some(bundled) => databases.extend(bundled.iter().find(|database| database.arch() == arch)),
            None => databases.extend(rampage_signatures::bundled_ref(arch)),
        }
        let bodies = loaded.bodies();
        let names = identify_program_sources(&databases, &loaded.binary.target(), &loaded.image, &bodies);
        names.into_iter().map(|(address, (_, name))| (address, name.to_owned())).collect()
    }

    /// The names under `layers`, where `layers` are the layers `before` was proposed under plus the rows of
    /// `delta`: a binary none of `delta`'s patterns can match keeps its answers from `before`, since every body's
    /// match is then the same. Exact, and much cheaper than [`Engine::propose`] when the reference layers are large
    /// (the deterministic arm) and the candidate is a few rows.
    pub fn propose_delta(
        &self,
        indices: &[usize],
        layers: &[Layer],
        before: &Proposals,
        delta: &Layer,
    ) -> Result<Proposals, FlywheelError> {
        let started = Instant::now();
        let results = self.parallel(indices, |index| {
            let loaded = self.get(index)?;
            if let Some(names) = before.names.get(&index)
                && !delta.could_change(loaded.binary.arch, &loaded)
            {
                return Ok((index, names.clone(), false));
            }
            Ok((index, self.identify(&loaded, layers, None), true))
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
            _ => RUNTIME.to_owned(),
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
///
/// The gated slices (`all`, `arch:`, `compiler:`, `opt:`, `program_library:`, `cell:`) score the target
/// libraries' own functions: runtime functions (libc, compiler runtime) are the same build in every program and
/// would reward recognising it again. A wrong name on a runtime function still counts there as a false positive,
/// and so does every name where the truth has no function. `origin:<library>`, `origin:runtime` and `origin:none`
/// (names where the truth has no function) report every outcome by where the function comes from; they are
/// never gated.
///
/// On the held-out split, `novelty:novel` and `novelty:recognised` score the target libraries' functions by
/// whether training holds their masked body ([`Engine::novelty`]); they are gated like the dimension slices.
pub fn slice_counts(
    engine: &Engine,
    outcomes: &BTreeMap<usize, BTreeMap<u64, Outcome>>,
) -> Result<BTreeMap<String, Counts>, FlywheelError> {
    let mut slices: BTreeMap<String, Counts> = BTreeMap::new();
    for (&index, outcomes) in outcomes {
        let keys = engine.binary(index).slices();
        let loaded = engine.get(index).ok();
        let novelty = engine.novelty(index)?;
        for (address, outcome) in outcomes {
            let origin = loaded.as_ref().and_then(|loaded| loaded.truth.get(address)).map(|truth| truth.origin.clone());
            let origin_key = format!("origin:{}", origin.as_deref().unwrap_or("none"));
            slices.entry(origin_key).or_default().add(*outcome);
            if let Some(&novel) = novelty.get(address) {
                let slice = if novel { super::evaluation::NOVEL_SLICE } else { super::evaluation::RECOGNISED_SLICE };
                slices.entry(slice.to_owned()).or_default().add(*outcome);
            }
            let gated = match origin.as_deref() {
                Some(RUNTIME) if *outcome == Outcome::Wrong => Some(Outcome::Spurious),
                Some(RUNTIME) => None,
                _ => Some(*outcome),
            };
            if let Some(gated) = gated {
                for key in &keys {
                    slices.entry(key.clone()).or_default().add(gated);
                }
            }
        }
    }
    Ok(slices)
}

/// Whether a slice is gated: the `origin:` slices only report.
pub fn gated_slice(slice: &str) -> bool {
    !slice.starts_with("origin:")
}

/// How many held-out library bodies (masked, as a signature would see them) also occur in training.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlap {
    /// Held-out functions of the target libraries whose bodies pass the confidence gate.
    pub heldout_bodies: usize,
    /// Of those, the ones whose masked body some training library function also has.
    pub in_training: usize,
    pub fraction: f64,
    /// The corpus's `split.max_heldout_overlap`: above it, servers warn.
    pub limit: f64,
    /// The corpus's `split.refuse_heldout_overlap`: above it, servers refuse the corpus.
    pub refused_above: f64,
}

impl Overlap {
    /// The loud warning a share above the limit deserves, if it is above.
    pub fn warning(&self) -> Option<String> {
        (self.fraction > self.limit).then(|| {
            format!(
                "WARNING: {} of {} held-out library bodies ({:.1}%) also occur in training (limit {:.0}%): most \
                 held-out gains can only be recognition of code unchanged between versions, not generalisation",
                self.in_training,
                self.heldout_bodies,
                self.fraction * 100.0,
                self.limit * 100.0
            )
        })
    }
}

impl Engine {
    /// Each target-library truth function of the binary at `index` with a body passing the confidence gate, keyed
    /// by (architecture, masked body).
    fn library_keys(&self, index: usize) -> Result<Vec<(u64, BodyKey)>, FlywheelError> {
        let loaded = self.get(index)?;
        let target = loaded.binary.target();
        let mut keys = Vec::new();
        for (address, truth) in &loaded.truth {
            if truth.origin == RUNTIME {
                continue;
            }
            let Some(body) = loaded.body(*address) else { continue };
            if let Some(masked) = rampage_signatures::masked_body_in(&target, &loaded.image, body, *address) {
                keys.push((*address, (self.binary(index).arch.clone(), super::candidate::format_pattern(&masked))));
            }
        }
        Ok(keys)
    }

    /// The held-out split's library bodies that training already holds: a high share means the split measures
    /// recognition of the same code, not generalisation.
    pub fn heldout_overlap(&self) -> Result<Overlap, FlywheelError> {
        let training = self.training_bodies()?;
        let indices = self.corpus.indices(super::corpus::Split::Heldout);
        let lists = self.parallel(&indices, |index| self.library_keys(index))?;
        let heldout: Vec<(String, String)> = lists.into_iter().flatten().map(|(_, key)| key).collect();
        let in_training = heldout.iter().filter(|key| training.contains(*key)).count();
        Ok(Overlap {
            heldout_bodies: heldout.len(),
            in_training,
            fraction: if heldout.is_empty() { 0.0 } else { in_training as f64 / heldout.len() as f64 },
            limit: self.corpus.manifest.split.max_heldout_overlap,
            refused_above: self.corpus.manifest.split.refuse_heldout_overlap,
        })
    }

    /// The training split's masked library bodies, by architecture and pattern, computed once.
    pub fn training_bodies(&self) -> Result<Arc<BTreeSet<BodyKey>>, FlywheelError> {
        self.training
            .get_or_init(|| {
                let indices = self.corpus.indices(super::corpus::Split::Train);
                let lists =
                    self.parallel(&indices, |index| self.library_keys(index)).map_err(|error| error.to_string())?;
                Ok(Arc::new(lists.into_iter().flatten().map(|(_, key)| key).collect()))
            })
            .clone()
            .map_err(FlywheelError::Corpus)
    }

    /// Each target-library truth function of the held-out or final binary at `index` and whether it is novel: its
    /// masked body is not one training holds (a body failing the confidence gate is novel too, since no training
    /// body can equal it). Empty for a binary outside those splits. For scoring only: it reads held-out truth.
    pub fn novelty(&self, index: usize) -> Result<Arc<BTreeMap<u64, bool>>, FlywheelError> {
        if let Some(novelty) = self.novelty[index].get() {
            return Ok(Arc::clone(novelty));
        }
        let mut novelty = BTreeMap::new();
        if matches!(self.binary(index).split, super::corpus::Role::Heldout | super::corpus::Role::Final) {
            let training = self.training_bodies()?;
            let loaded = self.get(index)?;
            for (address, truth) in &loaded.truth {
                if truth.origin != RUNTIME {
                    novelty.insert(*address, true);
                }
            }
            for (address, key) in self.library_keys(index)? {
                novelty.insert(address, !training.contains(&key));
            }
        }
        Ok(Arc::clone(self.novelty[index].get_or_init(|| Arc::new(novelty))))
    }

    /// The held-out library functions `layers` newly name correctly (against the bundled baseline), split into
    /// those whose masked body training also holds (recognition of unchanged code) and the novel ones
    /// (generalisation). For the operator's reports only: it reads held-out truth.
    pub fn heldout_gains(&self, layers: &[Layer]) -> Result<Gains, FlywheelError> {
        let training = self.training_bodies()?;
        let indices = self.corpus.indices(super::corpus::Split::Heldout);
        let proposals = self.propose(&indices, layers)?;
        let mut gains = Gains::default();
        for &index in &indices {
            let loaded = self.get(index)?;
            let target = loaded.binary.target();
            for (address, name) in &proposals.names[&index] {
                let Some(truth) = loaded.truth.get(address) else { continue };
                if truth.origin == RUNTIME || &truth.name != name || loaded.baseline.get(address) == Some(name) {
                    continue;
                }
                let seen = loaded
                    .body(*address)
                    .and_then(|body| rampage_signatures::masked_body_in(&target, &loaded.image, body, *address));
                let key =
                    seen.map(|masked| (self.binary(index).arch.clone(), super::candidate::format_pattern(&masked)));
                if key.is_some_and(|key| training.contains(&key)) {
                    gains.seen_in_training += 1;
                } else {
                    gains.novel += 1;
                    gains.novel_names.insert(name.clone());
                }
            }
        }
        Ok(gains)
    }
}

/// Held-out gains split by whether training already held the body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Gains {
    pub seen_in_training: usize,
    pub novel: usize,
    pub novel_names: BTreeSet<String>,
}

/// How far a byte pattern made from training could reach the novel held-out functions: an operator's ceiling,
/// read from held-out truth, never shown to a proposer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NovelReach {
    /// Novel held-out target-library functions (bodies training does not hold, or failing the confidence gate).
    pub novel: usize,
    /// Of those, with a masked body (passing the confidence gate).
    pub maskable: usize,
    /// With a training body of the same name and architecture at all.
    pub same_name: usize,
    /// With one of exactly the same length: the only ones a PAT row, which binds the module length, can reach.
    pub same_length: usize,
    /// Of those, the best-merging training body leaves a row the schema accepts (fixed bytes in at least half the
    /// positions, at least six): an oracle that knew which bytes change could name them.
    pub mergeable: usize,
    /// For the same-length ones: how many byte positions differ from the closest training body, in buckets.
    pub differing_bytes: BTreeMap<String, usize>,
    /// The operand classes the widened counts below wildcard.
    pub wildcards: Vec<rampage_signatures::OperandClass>,
    /// Of the same-length ones, those a training body's widened pattern (its masked body with the operand bytes of
    /// `wildcards` wildcarded, the arm's widened row) matches: the reach of operand wildcarding before collisions.
    pub widened_matches: usize,
}

impl Engine {
    /// [`NovelReach`] over the held-out split, with widened patterns wildcarding `wildcards`.
    pub fn novel_reach(&self, wildcards: &[rampage_signatures::OperandClass]) -> Result<NovelReach, FlywheelError> {
        let wildcards = super::arm::wildcard_set(wildcards);
        // Each training body by (architecture, name): its masked and widened patterns.
        type Bodies = Vec<(Vec<Option<u8>>, Vec<Option<u8>>)>;
        let mut training: BTreeMap<(String, String), Bodies> = BTreeMap::new();
        for index in self.corpus.indices(super::corpus::Split::Train) {
            let loaded = self.get(index)?;
            let target = loaded.binary.target();
            for (address, truth) in &loaded.truth {
                if truth.origin == RUNTIME {
                    continue;
                }
                if let Some(masked) = loaded.masked(*address) {
                    let classes = loaded
                        .body(*address)
                        .and_then(|body| rampage_signatures::operand_classes(&target, &loaded.image, body, *address));
                    let widened = super::arm::widen(&masked, classes.as_deref(), &wildcards);
                    let bodies = training.entry((self.binary(index).arch.clone(), truth.name.clone())).or_default();
                    if !bodies.iter().any(|(known, _)| *known == masked) {
                        bodies.push((masked, widened));
                    }
                }
            }
        }
        let mut reach = NovelReach { wildcards: wildcards.clone(), ..NovelReach::default() };
        for index in self.corpus.indices(super::corpus::Split::Heldout) {
            let loaded = self.get(index)?;
            let arch = &self.binary(index).arch;
            for (address, novel) in self.novelty(index)?.iter() {
                if !novel {
                    continue;
                }
                reach.novel += 1;
                let Some(masked) = loaded.masked(*address) else { continue };
                reach.maskable += 1;
                let name = &loaded.truth[address].name;
                let Some(bodies) = training.get(&(arch.clone(), name.clone())) else { continue };
                reach.same_name += 1;
                // The closest same-length training body: fewest differing positions, and the fixed bytes a row
                // merging the two would keep.
                let closest = bodies
                    .iter()
                    .map(|(body, _)| body)
                    .filter(|body| body.len() == masked.len())
                    .map(|body| {
                        let differing = body.iter().zip(&masked).filter(|(a, b)| a != b).count();
                        let fixed = body.iter().zip(&masked).filter(|(a, b)| a == b && a.is_some()).count();
                        (differing, std::cmp::Reverse(fixed))
                    })
                    .min();
                let Some((differing, std::cmp::Reverse(fixed))) = closest else { continue };
                reach.same_length += 1;
                if let Some(raw) = loaded.body(*address)
                    && bodies.iter().any(|(_, widened)| pattern_matches(widened, raw))
                {
                    reach.widened_matches += 1;
                }
                if fixed >= 6 && fixed * 2 >= masked.len() {
                    reach.mergeable += 1;
                }
                let bucket = match differing {
                    0 => "0",
                    1..=2 => "1-2",
                    3..=8 => "3-8",
                    9..=32 => "9-32",
                    _ => "33+",
                };
                *reach.differing_bytes.entry(bucket.to_owned()).or_default() += 1;
            }
        }
        Ok(reach)
    }
}
