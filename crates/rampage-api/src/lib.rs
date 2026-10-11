//! The single command and query surface shared by the CLI, the MCP server and the UI.

pub mod annotations;
mod benchmark;
mod branch_observation;
mod correlation;
mod debug_import;
mod decompile;
mod diagnostics;
mod graph;
mod jumptable;
mod listing;
mod pointer_observation;
mod project;
mod rows;
mod runtime_compare;
mod session;
mod signatures;
mod summary;
pub mod tools;
mod xrefs;

use std::path::PathBuf;

use rampage_arch::UnsupportedArch;
use rampage_loaders::LoadError;

pub use benchmark::{Comparison, ReferenceAnalysis};
pub use branch_observation::{BranchObservation, BranchSlotStatus};
pub use correlation::RuntimeCorrelation;
pub use debug_import::DebugImport;
pub use decompile::Decompilation;
pub use graph::{Edge, EdgeKind, FunctionGraph, GraphBlock};
pub use jumptable::{JumpTable, JumpTableEntry};
pub use listing::{DisassemblyLine, FunctionListing};
pub use pointer_observation::{PointerAssessment, PointerObservation};
pub use project::Project;
pub use rampage_analysis::triage::Triage;
pub use rampage_decompiler::results::RecoveryStatus;
pub use rampage_decompiler::worker::WorkerConfig as DecompilerWorkerConfig;
pub use rampage_decompiler::{DecompilerOptions, Platform as DecompilerPlatform};
pub use rampage_signatures::SignatureDb;
pub use rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Page, StringsQuery,
    Summary,
};
pub use runtime_compare::{ByteComparison, ComparedSpan, RuntimeComparison, RuntimeRange};
pub use session::Session;
pub use signatures::{SignatureApplication, SignatureMatch};
pub use summary::FunctionSummary;
pub use xrefs::{XrefQuery, XrefRow};

/// How many instructions a disassembly shows unless asked for another count.
pub const DEFAULT_INSTRUCTIONS: usize = 40;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{path}")]
    Load { path: PathBuf, source: LoadError },
    #[error(transparent)]
    Unsupported(#[from] UnsupportedArch),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    /// A capability that needs an external resource (such as the decompiler's Ghidra specifications) is not
    /// available in this environment.
    #[error("{0}")]
    Unavailable(String),
}
