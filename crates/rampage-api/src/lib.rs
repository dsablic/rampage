//! The single command and query surface shared by the CLI, the MCP server and the UI.

pub mod annotations;
mod batch;
mod benchmark;
mod branch_observation;
mod capabilities;
mod carve;
mod correlation;
mod debug_import;
mod decompile;
mod detect;
mod diagnostics;
mod dotnet;
mod files;
mod graph;
mod jumptable;
mod listing;
pub mod packs;
mod pointer_compare;
mod pointer_observation;
mod project;
mod rows;
mod runtime_compare;
mod session;
mod signatures;
mod summary;
pub mod tools;
pub mod workflows;
mod xrefs;

use std::path::PathBuf;

use rampage_arch::UnsupportedArch;
use rampage_loaders::LoadError;

pub use batch::{BatchEntry, BatchOutcome, BatchResult, MAX_BATCH, NameCheck};
pub use benchmark::{Comparison, ReferenceAnalysis};
pub use branch_observation::{BranchObservation, BranchSlotStatus};
pub use carve::{CarvingPage, MAX_CARVE_PAGE, carve, carve_page};
pub use correlation::RuntimeCorrelation;
pub use debug_import::DebugImport;
pub use decompile::Decompilation;
pub use detect::ToolDetections;
pub use dotnet::{DotNetCounts, DotNetIl, DotNetIlQuery, DotNetList, DotNetQuery, DotNetSummary};
pub use files::{MAX_PACK_MANIFEST_BYTES, MAX_PEID_BYTES, MAX_RULE_FILE_BYTES, MAX_SIGNATURE_DB_BYTES, read_bounded};
pub use graph::{Edge, EdgeKind, FunctionGraph, GraphBlock};
pub use jumptable::{JumpTable, JumpTableEntry};
pub use listing::{DisassemblyLine, FunctionListing};
pub use packs::{ContentInfo, ContentStatus, PackInfo, PackManifest, Packs};
pub use pointer_compare::{PointerChange, PointerComparison};
pub use pointer_observation::{PointerAssessment, PointerObservation};
pub use project::Project;
pub use rampage_analysis::triage::Triage;
pub use rampage_capabilities::Capability;
pub use rampage_decompiler::results::RecoveryStatus;
pub use rampage_decompiler::worker::WorkerConfig as DecompilerWorkerConfig;
pub use rampage_decompiler::{DecompilerOptions, Platform as DecompilerPlatform};
pub use rampage_detect::{Confidence as DetectionConfidence, Detection, Kind as DetectionKind};
pub use rampage_signatures::SignatureDb;
pub use rampage_yara::{MatchedString, YaraMatch};
pub use rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Page, StringsQuery,
    Summary, label,
};
pub use runtime_compare::{ByteComparison, ComparedSpan, RuntimeComparison, RuntimeRange};
pub use session::Session;
pub use signatures::{SignatureApplication, SignatureMatch, USER_SIGNATURES};
pub use summary::FunctionSummary;
pub use workflows::{
    Confidence as FindingConfidence, Excerpt, Finding, NextStep, ReportLimits, ReportTarget, Section, WorkflowReport,
};
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
