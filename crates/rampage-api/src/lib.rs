//! The single command and query surface shared by the CLI, the MCP server and future clients.

mod project;

pub use project::{
    ApiError, DisassemblyLine, FunctionRow, FunctionsQuery, Page, Project, Session, StringsQuery, Summary, XrefQuery,
    XrefRow,
};
