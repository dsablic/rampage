//! The single command and query surface shared by the CLI, the MCP server and the UI.

pub mod annotations;
mod listing;
mod project;
mod rows;
mod session;
mod xrefs;

use std::path::PathBuf;

use rampage_arch::UnsupportedArch;
use rampage_loaders::LoadError;

pub use listing::{DisassemblyLine, FunctionListing};
pub use project::Project;
pub use rampage_analysis::triage::Triage;
pub use rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Page, StringsQuery,
    Summary,
};
pub use session::Session;
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
}
