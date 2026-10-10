//! MCP server exposing rampage analysis to AI agents.

use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{
    ApiError, DEFAULT_INSTRUCTIONS, FunctionsQuery, ListQuery, Project, Session, StringsQuery, XrefQuery,
};
use rampage_arch::Arch;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 1000;
const MAX_INSTRUCTIONS: usize = 2000;

const INSTRUCTIONS: &str = "\
rampage analyzes PE, ELF and Mach-O binaries for x86, x86-64, AArch64, 32-bit ARM and Thumb, MIPS, PowerPC, \
RISC-V, SPARC, s390x and m68k. Every tool takes the binary's file \
path; the first call that needs analysis runs it once and caches the result, so later calls are fast. Addresses \
are hex strings like \"0x401000\". Wherever a tool takes an address you may also pass a symbol, export or import \
name (an import name finds its stub) or a sub_<hex> name. Start with triage for hashes, entropy, hardening and \
packing hints, or binary_info for the layout; then list_functions (filter with name_contains, page with \
offset/limit), disassemble a function, and follow references with xrefs. list_imports and list_strings are good \
starting points for finding behavior. Record findings with rename and set_comment: they persist beside the binary \
and every client of the same binary, including the rampage UI, picks them up.";

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BinaryArgs {
    /// Path to the binary file.
    pub path: String,
    /// Slice to load from a universal Mach-O (x86, x86_64, aarch64, arm, powerpc, ...). Defaults to x86_64, then
    /// aarch64, then x86, when present.
    pub arch: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionsArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    #[serde(flatten)]
    pub query: FunctionsQuery,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StringsArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    #[serde(flatten)]
    pub query: StringsQuery,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    #[serde(flatten)]
    pub query: ListQuery,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenameArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    /// The address or current name to rename.
    pub at: String,
    /// The new name. Required unless `clear` is set.
    pub name: Option<String>,
    /// Remove the user's name instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CommentArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    /// The address or name to comment.
    pub at: String,
    /// The comment. Required unless `clear` is set.
    pub text: Option<String>,
    /// Remove the comment instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

/// The value an edit sets: `value`, or nothing with `clear`; exactly one must be given.
fn edit_value(value: Option<String>, clear: bool, what: &str) -> Result<Option<String>, ApiError> {
    match (value, clear) {
        (Some(value), false) => Ok(Some(value)),
        (None, true) => Ok(None),
        _ => Err(ApiError::Invalid(format!("pass either `{what}` or `clear: true`"))),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisassembleArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    /// Start address or name; defaults to the entry point.
    pub at: Option<String>,
    /// Number of instructions (default 40, at most 2000).
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GraphArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    /// An address or name inside the function.
    pub at: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct XrefsArgs {
    #[serde(flatten)]
    pub binary: BinaryArgs,
    /// List references whose target is this address or name (callers, readers).
    pub to: Option<String>,
    /// List references made by the function starting at this address or name, or by the instruction at it.
    pub from: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return.
    pub limit: Option<usize>,
}

#[derive(Clone)]
pub struct RampageServer {
    session: Arc<Session>,
    tool_router: ToolRouter<Self>,
}

impl Default for RampageServer {
    fn default() -> Self {
        Self { session: Arc::default(), tool_router: Self::tool_router() }
    }
}

fn clamp_page(limit: Option<usize>) -> Option<usize> {
    Some(limit.unwrap_or(DEFAULT_PAGE).min(MAX_PAGE))
}

impl RampageServer {
    /// Runs blocking analysis work off the async runtime and reports failures as tool errors the caller sees.
    async fn run<T, F>(&self, binary: BinaryArgs, work: F) -> Result<CallToolResult, ErrorData>
    where
        T: Serialize,
        F: FnOnce(&Project) -> Result<T, ApiError> + Send + 'static,
        T: Send + 'static,
    {
        let session = Arc::clone(&self.session);
        let outcome = tokio::task::spawn_blocking(move || -> Result<T, String> {
            let arch = binary.arch.as_deref().map(str::parse::<Arch>).transpose()?;
            let project = session.open(&PathBuf::from(&binary.path), arch).map_err(|error| error_text(&error))?;
            // Other clients (the UI, the CLI) may have saved names since the last call.
            project.refresh_annotations().map_err(|error| error_text(&error))?;
            work(&project).map_err(|error| error_text(&error))
        })
        .await
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        match outcome {
            Ok(value) => Ok(CallToolResult::success(vec![ContentBlock::json(value)?])),
            Err(message) => Ok(CallToolResult::error(vec![ContentBlock::text(message)])),
        }
    }
}

fn error_text(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[tool_router]
impl RampageServer {
    #[tool(description = "Format, architecture, entry point, segments, sections and symbol counts of a binary.")]
    async fn binary_info(&self, Parameters(args): Parameters<BinaryArgs>) -> Result<CallToolResult, ErrorData> {
        self.run(args, |project| Ok(serde_json::to_value(project.summary()).expect("summary serializes"))).await
    }

    #[tool(description = "First look at a binary: MD5/SHA-1/SHA-256, entropy (overall, per section, and a profile \
                          across the file), format details (PE build time, mitigations and Rich header; ELF \
                          interpreter, libraries, NX/RELRO/PIE; Mach-O dylibs, platform, signing), PE imphash, \
                          overlay, and hints of packing or weak hardening.")]
    async fn triage(&self, Parameters(args): Parameters<BinaryArgs>) -> Result<CallToolResult, ErrorData> {
        self.run(args, |project| Ok(serde_json::to_value(project.triage()).expect("triage serializes"))).await
    }

    #[tool(description = "Imported functions with their libraries and the slot the loader fills with each \
                          address. Filter with `contains` (name or library); paginated like list_functions.")]
    async fn list_imports(&self, Parameters(args): Parameters<ListArgs>) -> Result<CallToolResult, ErrorData> {
        let mut query = args.query;
        query.limit = clamp_page(query.limit);
        self.run(args.binary, move |project| Ok(project.imports(&query))).await
    }

    #[tool(description = "Exported symbols with their addresses. Filter with `contains`; paginated like \
                          list_functions.")]
    async fn list_exports(&self, Parameters(args): Parameters<ListArgs>) -> Result<CallToolResult, ErrorData> {
        let mut query = args.query;
        query.limit = clamp_page(query.limit);
        self.run(args.binary, move |project| Ok(project.exports(&query))).await
    }

    #[tool(description = "Name a function, label or data address. Names show up everywhere (listings, \
                          disassembly, xrefs) for every client and are saved beside the binary in \
                          <file>.rampage, so record what you learn as you go. Names must be unique identifiers.")]
    async fn rename(&self, Parameters(args): Parameters<RenameArgs>) -> Result<CallToolResult, ErrorData> {
        let (at, name, clear) = (args.at, args.name, args.clear);
        self.run(args.binary, move |project| {
            let name = edit_value(name, clear, "name")?;
            project.rename(project.resolve(&at)?, name.as_deref())
        })
        .await
    }

    #[tool(description = "Comment an instruction or data address. Comments appear in disassembly (`note`) and are \
                          saved beside the binary.")]
    async fn set_comment(&self, Parameters(args): Parameters<CommentArgs>) -> Result<CallToolResult, ErrorData> {
        let (at, text, clear) = (args.at, args.text, args.clear);
        self.run(args.binary, move |project| {
            let text = edit_value(text, clear, "text")?;
            project.comment(project.resolve(&at)?, text.as_deref())
        })
        .await
    }

    #[tool(description = "Undo the last rename or comment made in this session. Returns the edit undone, or null.")]
    async fn undo(&self, Parameters(args): Parameters<BinaryArgs>) -> Result<CallToolResult, ErrorData> {
        self.run(args, |project| project.undo()).await
    }

    #[tool(description = "Redo the last edit undone in this session. Returns the edit redone, or null.")]
    async fn redo(&self, Parameters(args): Parameters<BinaryArgs>) -> Result<CallToolResult, ErrorData> {
        self.run(args, |project| project.redo()).await
    }

    #[tool(description = "All user names and comments of a binary, by address.")]
    async fn list_annotations(&self, Parameters(args): Parameters<BinaryArgs>) -> Result<CallToolResult, ErrorData> {
        self.run(args, |project| Ok(project.annotation_list())).await
    }

    #[tool(description = "Functions found by recursive-descent analysis, sorted by address, with size, block and \
                          instruction counts. Paginated: default 100, at most 1000 per call; `total` is the full \
                          count.")]
    async fn list_functions(&self, Parameters(args): Parameters<FunctionsArgs>) -> Result<CallToolResult, ErrorData> {
        let mut query = args.query;
        query.limit = clamp_page(query.limit);
        self.run(args.binary, move |project| project.functions(&query)).await
    }

    #[tool(description = "Disassemble instructions starting at an address or name, with control flow, referenced \
                          addresses and labels.")]
    async fn disassemble(&self, Parameters(args): Parameters<DisassembleArgs>) -> Result<CallToolResult, ErrorData> {
        let count = args.count.unwrap_or(DEFAULT_INSTRUCTIONS).min(MAX_INSTRUCTIONS);
        let at = args.at;
        self.run(args.binary, move |project| project.disassemble(at.as_deref(), count)).await
    }

    #[tool(description = "The control-flow graph of the function containing an address or name: its basic blocks \
                          (with disassembly) and the edges between them, each unconditional, taken or not_taken. \
                          Edges index into `blocks`.")]
    async fn function_graph(&self, Parameters(args): Parameters<GraphArgs>) -> Result<CallToolResult, ErrorData> {
        let at = args.at;
        self.run(args.binary, move |project| project.function_graph(project.resolve(&at)?)).await
    }

    #[tool(description = "Printable ASCII and UTF-16LE strings with their addresses. Filter with `contains`; \
                          paginated like list_functions.")]
    async fn list_strings(&self, Parameters(args): Parameters<StringsArgs>) -> Result<CallToolResult, ErrorData> {
        let mut query = args.query;
        query.limit = clamp_page(query.limit);
        self.run(args.binary, move |project| Ok(project.strings(&query))).await
    }

    #[tool(description = "Cross-references (call, jump, data). Pass `to` to find who calls or reads an address, or \
                          `from` to list what a function references. Exactly one of `to` and `from` is required. \
                          Paginated like list_functions.")]
    async fn xrefs(&self, Parameters(args): Parameters<XrefsArgs>) -> Result<CallToolResult, ErrorData> {
        let (to, from, offset, limit) = (args.to, args.from, args.offset, clamp_page(args.limit));
        self.run(args.binary, move |project| {
            let query = match (to, from) {
                (Some(to), None) => XrefQuery::To(project.resolve(&to)?),
                (None, Some(from)) => XrefQuery::From(project.resolve(&from)?),
                _ => return Err(ApiError::Invalid("pass exactly one of `to` and `from`".to_owned())),
            };
            project.xrefs(query, offset, limit)
        })
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RampageServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rampage", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

/// Serves MCP over stdin/stdout until the client disconnects.
pub async fn serve_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    RampageServer::default().serve(rmcp::transport::stdio()).await?.waiting().await?;
    Ok(())
}
