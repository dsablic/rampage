//! MCP server exposing rampage analysis to AI agents. It serves the tools of `rampage_api::tools`, the same ones
//! the UI's assistant uses, with each taking the path of the binary to work on.

use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::tools::{self, FileTool, Tool};
use rampage_api::{Project, Session};
use rampage_arch::Arch;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Map, Value, json};

const INSTRUCTIONS: &str = "\
rampage analyzes PE, ELF and Mach-O binaries for x86, x86-64, AArch64, 32-bit ARM and Thumb, MIPS, PowerPC, \
RISC-V, SPARC, s390x and m68k. Every tool takes the binary's file path; the first call that needs analysis runs it \
once and caches the result, so later calls are fast. Addresses are hex strings like \"0x401000\". Wherever a tool \
takes an address (except comparison slots/ranges and branch observation windows) you may also pass a symbol, \
export or import name \
(an import name finds its stub) or a sub_<hex> \
name. Start with triage_report: one bounded overview (layout, triage hints, producing toolchain, capability \
tags, imports, notable strings, library functions) that ends with concrete next tool calls. The other guided \
workflows compose the primitives the same way: find_main (the program's own entry logic), network_surface, \
find_crypto (algorithm constants and crypto APIs with the code that uses them), persistence_surface (autostart \
locations, service and registry APIs), string_decoding (candidate byte-decoding loops with their call sites and \
encoded-looking data) and diff_builds. Every workflow \
finding carries its evidence, source tool and confidence, and every report states its limitations: treat findings \
as evidence, not verdicts. Heuristic databases: detect_tools (packer/compiler/protector), identify_functions \
(library code by signature, bundled databases applied), capabilities, yara_scan and capa_detect (user-supplied \
rules). For a single question use triage or binary_info, then \
list_functions (filter with name_contains, page with offset/limit), then decompile a function to C to understand \
it (the best starting point; falls back to function_summary where no decompiler specification is available), or \
disassemble or function_graph it, and follow references with xrefs. list_imports and list_strings are good \
starting points for finding behavior. Record \
findings with rename and set_comment: they persist beside the binary and every client of the same binary, \
including the rampage UI, picks them up. Memory snapshots and bundle directories use the same tools. \
analysis_diagnostics reports decode confidence limits; language_metadata exposes demangled names and bounded \
metadata; function_summary returns a structural CFG/reference summary, not decompiled source. \
compare_runtime_bytes takes an explicit original path, module UUID and hexadecimal runtime ranges, returning paginated \
byte evidence without sidecars or annotation transfer. Verify identities when combining pages. \
observe_indirect_branch takes explicit hexadecimal start/at addresses for a bounded ARM64 branch window; \
slot links are conditional decoding evidence, not proof of execution or a call edge. \
compare_pointer_observations takes another explicit capture path and hexadecimal at/other_at slots; \
before/after ordering and slot correspondence are supplied by the analyst, not independently verified. \
carve scans any file (firmware, installer, archive) for embedded executables and containers by validated header, \
with offsets and header-estimated extents; it extracts and decompresses nothing.";

/// A tool's schema with the arguments every tool takes besides its own: which binary, and which slice of a
/// universal one.
fn with_binary_arguments(schema: &Value) -> Map<String, Value> {
    let mut schema = schema.as_object().cloned().unwrap_or_default();
    let properties = schema.entry("properties").or_insert_with(|| json!({}));
    if let Some(properties) = properties.as_object_mut() {
        properties.insert("path".to_owned(), json!({ "type": "string", "description": "Path to the binary file." }));
        properties.insert(
            "arch".to_owned(),
            json!({
                "type": ["string", "null"],
                "description": "Slice to load from a universal Mach-O (x86, x86_64, aarch64, arm, powerpc, ...). \
                                Defaults to x86_64, then aarch64, then x86, when present."
            }),
        );
    }
    let required = schema.entry("required").or_insert_with(|| json!([]));
    if let Some(required) = required.as_array_mut() {
        required.push(json!("path"));
    }
    schema
}

#[derive(Clone)]
pub struct RampageServer {
    session: Arc<Session>,
    tools: Arc<Vec<Tool>>,
    file_tools: Arc<Vec<FileTool>>,
}

impl Default for RampageServer {
    fn default() -> Self {
        // Without a person's view of the binary, tools that act on one have nothing to do.
        let tools = tools::tools().into_iter().filter(|tool| !tool.interactive).collect();
        Self { session: Arc::default(), tools: Arc::new(tools), file_tools: Arc::new(tools::file_tools()) }
    }
}

impl RampageServer {
    /// Runs a tool on the binary its arguments name. Failures are results the caller sees, not protocol errors.
    fn run(&self, name: &str, mut arguments: Map<String, Value>) -> CallToolResult {
        if let Some(tool) = self.file_tools.iter().find(|tool| tool.name == name) {
            return match tool.call(Value::Object(arguments)) {
                Ok(output) => CallToolResult::success(vec![ContentBlock::text(output.to_string())]),
                Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
            };
        }
        let path = arguments.remove("path");
        let arch = arguments.remove("arch");
        let outcome = (|| -> Result<String, String> {
            let tool =
                self.tools.iter().find(|tool| tool.name == name).ok_or_else(|| format!("unknown tool {name}"))?;
            let path = path.as_ref().and_then(Value::as_str).ok_or("`path` is required")?;
            let arch = arch.as_ref().and_then(Value::as_str).map(str::parse::<Arch>).transpose()?;
            let project = if tool.reads_annotations {
                let project = self.session.open(&PathBuf::from(path), arch).map_err(|error| error_text(&error))?;
                // Other clients (the UI, the CLI) may have saved names since the last call.
                project.refresh_annotations().map_err(|error| error_text(&error))?;
                project
            } else {
                Arc::new(Project::new(
                    rampage_loaders::Binary::open_with(path, arch).map_err(|error| error_text(&error))?,
                ))
            };
            match tools::call(&self.tools, &project, name, Value::Object(arguments)) {
                (output, false) => Ok(output),
                (error, true) => Err(error),
            }
        })();
        match outcome {
            Ok(output) => CallToolResult::success(vec![ContentBlock::text(output)]),
            Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
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

impl ServerHandler for RampageServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rampage", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let file_tools = self.file_tools.iter().map(|tool| {
            let schema = tool.input_schema.as_object().cloned().unwrap_or_default();
            rmcp::model::Tool::new(tool.name, tool.description, schema)
        });
        let tools = self
            .tools
            .iter()
            .map(|tool| rmcp::model::Tool::new(tool.name, tool.description, with_binary_arguments(&tool.input_schema)))
            .chain(file_tools)
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let server = self.clone();
        let name = request.name.into_owned();
        let arguments = request.arguments.unwrap_or_default();
        // Analysis is blocking work; keep it off the async runtime.
        let result = tokio::task::spawn_blocking(move || server.run(&name, arguments))
            .await
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        Ok(result.into())
    }
}

/// Serves MCP over stdin/stdout until the client disconnects.
pub async fn serve_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    RampageServer::default().serve(rmcp::transport::stdio()).await?.waiting().await?;
    Ok(())
}
