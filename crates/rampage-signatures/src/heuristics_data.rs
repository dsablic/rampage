//! The fixed half of [`crate::heuristics`]: the training inputs a generator receives and the data file compiled in.
//! The code loop's agent may not change this file (docs/flywheel.md, "The code loop"); the harness regenerates
//! `data/heuristics/heuristics.bin` from the training split with the agent's [`crate::heuristics::generate`], so the
//! compiled-in data derives from training only.

/// The most bytes the generated data file may hold.
pub const MAX_BYTES: usize = 4 * 1024 * 1024;

/// The generated data, as the last generation wrote it (empty at rest).
pub const BYTES: &[u8] = include_bytes!("../data/heuristics/heuristics.bin");

/// One discovered function of a training binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingFunction {
    pub address: u64,
    /// The function's bytes as discovered.
    pub bytes: Vec<u8>,
    /// Its name in the training truth, when the truth has one.
    pub name: Option<String>,
    /// Whether the truth tags it as the target library's own (not libc or compiler runtime).
    pub library: bool,
    /// Its call targets (function starts), in call-site order.
    pub calls: Vec<u64>,
}

/// One training binary: its architecture name (`x86_64`, `aarch64`) and discovered functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingBinary {
    pub id: String,
    pub arch: String,
    pub functions: Vec<TrainingFunction>,
}
