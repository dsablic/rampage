//! The heuristic flywheel's fast loop (docs/plans/2026-11-05-flywheel-fast-loop.md, docs/flywheel.md): a prebuilt
//! library-identification corpus with a deterministic program-level train/held-out split, an evaluator with cached
//! truth and baseline analysis, a two-stage gate, candidate signature rows written as scratch data packs, and
//! promotion into a promoted pack with provenance and revert ids.
//!
//! An agent drives it through the opt-in `improve` MCP group ([`Improve`]): `corpus_failures` (training split
//! only), `propose_heuristic`, `evaluate_candidate` and `promote_candidate`. `report_observation`
//! ([`ObservationStore`]) records evidence-backed observations from ordinary sessions; it never promotes anything.
//!
//! Candidates are data only: pattern rows in the existing signature pack format, never code. The held-out split is
//! measured but never shown: no tool returns a held-out binary, function, name or truth, only metrics.

mod arm;
mod candidate;
mod corpus;
mod engine;
mod evaluation;
mod failures;
mod improve;
mod observations;
mod promote;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub use arm::{ARM_FILE, Arm, ArmStats};
pub use candidate::{
    Candidate, MAX_MODULE_BYTES, MAX_PATTERN_BYTES, MAX_ROWS, Row, RowSource, databases, format_pattern, layer,
    parse_pattern, rows_hash, write_pack,
};
pub use corpus::{Corpus, CorpusBinary, CorpusManifest, Split, SplitConfig};
pub use engine::{
    BodyKey, Bundled, Counts, Engine, Gains, Layer, Loaded, NovelReach, Outcome, Overlap, Proposals, SliceMetrics,
    TruthFunction,
};
pub use evaluation::{
    ChangedCase, GateCheck, GateConfig, GateResult, NOVEL_SLICE, RECOGNISED_SLICE, SliceDelta, SplitEvaluation,
    compare, evaluate_split,
};
pub use failures::{FailureGroup, FailureSet};
pub use improve::{Baseline, FAMILY, Improve, ImproveOptions, ImproveTool, improve_tools};
pub use observations::{OBSERVATIONS_VARIABLE, ObservationStore, ObservationTool, observation_tool};
pub use promote::{ENTRIES_FILE, PromotedEntry, PromotedSet, pack_layer, promoted_layer, revert};

/// The deterministic arm for a corpus: loaded when generated before for this corpus, build and minimum pattern
/// length, else generated from the training split and saved.
pub fn arm(engine: &Engine, min_pattern_bytes: usize) -> Result<Arm, FlywheelError> {
    arm::load_or_generate(engine, min_pattern_bytes)
}

/// The directory the arm for `engine`'s corpus and `min_pattern_bytes` is kept in (its record and data pack).
pub fn arm_directory(engine: &Engine, min_pattern_bytes: usize) -> PathBuf {
    arm::directory(engine, min_pattern_bytes)
}

/// The flywheel's working directory (by default `target/flywheel`): scratch candidates, promoted packs, caches,
/// evaluation records, observations and run reports.
#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn new(root: PathBuf) -> Paths {
        Paths { root }
    }

    /// The working directory for a corpus at `corpus`: two levels up when it sits in a `corpus/` directory
    /// (`target/flywheel/corpus/<version>` gives `target/flywheel`), else `None` and the caller must say.
    pub fn for_corpus(corpus: &Path) -> Option<Paths> {
        let parent = corpus.parent()?;
        if parent.file_name()? != "corpus" {
            return None;
        }
        Some(Paths::new(parent.parent()?.to_owned()))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scratch(&self, family: &str) -> PathBuf {
        self.root.join("scratch").join(family)
    }

    pub fn promoted(&self, family: &str) -> PathBuf {
        self.root.join("promoted").join(family)
    }

    pub fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }

    pub fn evaluations(&self, family: &str) -> PathBuf {
        self.root.join("evaluations").join(family)
    }

    pub fn observations(&self) -> PathBuf {
        self.root.join("observations")
    }

    pub fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }
}

/// Why a flywheel operation failed, with a stable kind an agent can branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlywheelError {
    /// An argument is missing, malformed or out of range.
    Invalid(String),
    /// A candidate, case or revert id names nothing.
    Unknown(String),
    /// The gate has not passed, or another rule refuses the action.
    Refused(String),
    /// The corpus is missing, inconsistent or cannot be analysed.
    Corpus(String),
    /// Reading or writing the flywheel's files failed.
    Io(String),
}

impl FlywheelError {
    pub fn kind(&self) -> &'static str {
        match self {
            FlywheelError::Invalid(_) => "invalid_argument",
            FlywheelError::Unknown(_) => "not_found",
            FlywheelError::Refused(_) => "refused",
            FlywheelError::Corpus(_) => "corpus",
            FlywheelError::Io(_) => "io",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            FlywheelError::Invalid(message)
            | FlywheelError::Unknown(message)
            | FlywheelError::Refused(message)
            | FlywheelError::Corpus(message)
            | FlywheelError::Io(message) => message,
        }
    }

    /// The JSON text a tool returns for this error: `{"error": kind, "message": ...}`.
    pub fn to_json(&self) -> String {
        serde_json::json!({ "error": self.kind(), "message": self.message() }).to_string()
    }

    pub(crate) fn io(path: &Path, error: std::io::Error) -> FlywheelError {
        FlywheelError::Io(format!("{}: {error}", path.display()))
    }

    pub(crate) fn io_text(path: &Path, error: impl std::fmt::Display) -> FlywheelError {
        FlywheelError::Corpus(format!("{}: {error}", path.display()))
    }

    pub(crate) fn json(error: serde_json::Error) -> FlywheelError {
        FlywheelError::Io(format!("JSON: {error}"))
    }
}

impl std::fmt::Display for FlywheelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.kind(), self.message())
    }
}

impl std::error::Error for FlywheelError {}

pub(crate) fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

/// The SHA-256 of `text`, as lowercase hex.
pub(crate) fn sha256_text(text: &str) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(text.as_bytes()))
}

/// The SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> Result<String, FlywheelError> {
    use sha2::Digest;
    let mut file = std::fs::File::open(path).map_err(|error| FlywheelError::io(path, error))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0; 1 << 16];
    loop {
        let read = file.read(&mut buffer).map_err(|error| FlywheelError::io(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// A text file of at most `limit` bytes.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<String, FlywheelError> {
    let file = std::fs::File::open(path).map_err(|error| FlywheelError::io(path, error))?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text).map_err(|error| FlywheelError::io(path, error))?;
    if text.len() as u64 > limit {
        return Err(FlywheelError::Io(format!("{}: larger than {limit} bytes", path.display())));
    }
    Ok(text)
}

/// Writes `bytes` to `path` through a temporary sibling and a rename, so a reader never sees half a file.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FlywheelError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or_else(|| FlywheelError::Io(format!("{}: no parent", path.display())))?;
    std::fs::create_dir_all(parent).map_err(|error| FlywheelError::io(parent, error))?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("file"),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&temporary, bytes).map_err(|error| FlywheelError::io(&temporary, error))?;
    std::fs::rename(&temporary, path).map_err(|error| FlywheelError::io(path, error))
}

/// An exclusive advisory lock on a file, held across processes until dropped.
pub(crate) struct FileLock(std::fs::File);

impl FileLock {
    /// Waits for the exclusive lock on `path`, creating the file (and its directory) when missing.
    pub(crate) fn acquire(path: &Path) -> Result<FileLock, FlywheelError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| FlywheelError::io(parent, error))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|error| FlywheelError::io(path, error))?;
        file.lock().map_err(|error| FlywheelError::io(path, error))?;
        Ok(FileLock(file))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_millis() as u64)
}

/// The running rampage build: the SHA-256 of this executable, so a cached analysis is never reused by a build
/// whose analysis could differ. Two executables (the `rampage` CLI and `rampage-eval`) keep separate caches.
pub fn build_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let executable = std::env::current_exe().ok();
        let digest = executable.as_deref().and_then(|path| sha256_file(path).ok());
        match digest {
            Some(digest) => format!("{}-{}", env!("CARGO_PKG_VERSION"), &digest[..16]),
            None => format!("{}-unknown-{}", env!("CARGO_PKG_VERSION"), std::process::id()),
        }
    })
}
