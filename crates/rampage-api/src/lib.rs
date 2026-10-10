//! The single command and query surface shared by the CLI, the MCP server and future clients.

mod project;

pub use project::{
    ApiError, DisassemblyLine, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Page, Project, Session, StringsQuery,
    Summary, XrefQuery, XrefRow,
};
pub use rampage_analysis::triage::Triage;
