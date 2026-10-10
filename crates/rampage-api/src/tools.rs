//! The analysis tools AI models call, shared by the MCP server and the UI's assistant: each has a name, a
//! description, a JSON schema for its input, and a handler that runs it against a project.

use crate::{ApiError, FunctionsQuery, ListQuery, Project, StringsQuery, XrefQuery};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Results longer than this are cut, so that one large answer cannot crowd out the conversation.
const MAX_RESULT_CHARS: usize = 60_000;
const DEFAULT_PAGE: usize = 100;

type Handler = Box<dyn Fn(&Project, Value) -> Result<Value, String> + Send + Sync>;

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    /// Acts on a person's view of the binary (`show_address`), so only clients with one offer it.
    pub interactive: bool,
    handler: Handler,
}

impl Tool {
    fn interactive(self) -> Self {
        Self { interactive: true, ..self }
    }

    /// The tool as the Anthropic Messages API describes one.
    pub fn definition(&self) -> Value {
        serde_json::json!({ "name": self.name, "description": self.description, "input_schema": self.input_schema })
    }
}

fn schema<A: JsonSchema>() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(A)).unwrap_or_default();
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("title");
        object.entry("properties").or_insert_with(|| serde_json::json!({}));
    }
    schema
}

fn tool<A, R>(name: &'static str, description: &'static str, run: fn(&Project, A) -> Result<R, ApiError>) -> Tool
where
    A: DeserializeOwned + JsonSchema + 'static,
    R: Serialize + 'static,
{
    let handler = move |project: &Project, input: Value| -> Result<Value, String> {
        let arguments: A = serde_json::from_value(input).map_err(|error| format!("invalid arguments: {error}"))?;
        let result = run(project, arguments).map_err(|error| error.to_string())?;
        serde_json::to_value(result).map_err(|error| error.to_string())
    };
    Tool { name, description, input_schema: schema::<A>(), interactive: false, handler: Box::new(handler) }
}

/// No arguments.
#[derive(serde::Deserialize, JsonSchema)]
pub struct Nothing {}

#[derive(serde::Deserialize, JsonSchema)]
pub struct At {
    /// An address (`0x401000`) or a name: symbol, export, import, user name, or `sub_<hex>`.
    pub at: String,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Start address or name; defaults to the entry point.
    pub at: Option<String>,
    /// Number of instructions (default 40, at most 1000).
    pub count: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct XrefsArgs {
    /// List references to this address or name (callers, readers).
    pub to: Option<String>,
    /// List references made by the function at this address or name.
    pub from: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return (default 100).
    pub limit: Option<usize>,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct RenameArgs {
    /// The address or current name to rename.
    pub at: String,
    /// The new name, an identifier not used elsewhere. Required unless `clear` is set.
    pub name: Option<String>,
    /// Remove the user's name instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

#[derive(serde::Deserialize, JsonSchema)]
pub struct CommentArgs {
    /// The address or name to comment.
    pub at: String,
    /// The comment. Required unless `clear` is set.
    pub text: Option<String>,
    /// Remove the comment instead of setting one.
    #[serde(default)]
    pub clear: bool,
}

/// The value an edit sets: `value`, or nothing with `clear`; exactly one must be given, so that a forgotten
/// argument never erases a name.
fn edit_value(value: Option<String>, clear: bool, what: &str) -> Result<Option<String>, ApiError> {
    match (value, clear) {
        (Some(value), false) => Ok(Some(value)),
        (None, true) => Ok(None),
        _ => Err(ApiError::Invalid(format!("pass either `{what}` or `clear: true`"))),
    }
}

fn page_limit(limit: Option<usize>) -> Option<usize> {
    Some(limit.unwrap_or(DEFAULT_PAGE).min(1000))
}

/// Every tool, in the order the model sees them.
pub fn tools() -> Vec<Tool> {
    vec![
        tool(
            "binary_info",
            "Format, architecture, entry point, segments and sections of the binary.",
            |project, _: Nothing| {
                serde_json::to_value(project.summary()).map_err(|error| ApiError::Invalid(error.to_string()))
            },
        ),
        tool(
            "triage",
            "Hashes, entropy, format details (build time, libraries, hardening), overlay and hints of packing.",
            |project, _: Nothing| Ok(project.triage().clone()),
        ),
        tool(
            "list_functions",
            "Functions found by analysis, sorted by address, with size, blocks and instruction counts. Filter with \
             name_contains; paginated with offset and limit (default 100).",
            |project, mut query: FunctionsQuery| {
                query.limit = page_limit(query.limit);
                project.functions(&query)
            },
        ),
        tool(
            "disassemble",
            "Disassemble instructions from an address or name, with control flow, references and names.",
            |project, arguments: DisassembleArgs| {
                let count = arguments.count.unwrap_or(crate::DEFAULT_INSTRUCTIONS).min(1000);
                project.disassemble(arguments.at.as_deref(), count)
            },
        ),
        tool(
            "function_graph",
            "The control-flow graph of the function containing an address or name: its basic blocks with \
             disassembly, and edges (unconditional, taken, not_taken) indexing into the blocks.",
            |project, arguments: At| project.function_graph(project.resolve(&arguments.at)?),
        ),
        tool(
            "xrefs",
            "Cross-references: pass `to` for who calls or reads an address, or `from` for what a function \
             references. Paginated.",
            |project, arguments: XrefsArgs| {
                let query = match (arguments.to, arguments.from) {
                    (Some(to), None) => XrefQuery::To(project.resolve(&to)?),
                    (None, Some(from)) => XrefQuery::From(project.resolve(&from)?),
                    _ => return Err(ApiError::Invalid("pass exactly one of `to` and `from`".to_owned())),
                };
                project.xrefs(query, arguments.offset, page_limit(arguments.limit))
            },
        ),
        tool(
            "list_strings",
            "Printable strings with their addresses. Filter with `contains`; paginated.",
            |project, mut query: StringsQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.strings(&query))
            },
        ),
        tool(
            "list_imports",
            "Imported functions with their libraries and import slots. Filter with `contains`; paginated.",
            |project, mut query: ListQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.imports(&query))
            },
        ),
        tool(
            "list_exports",
            "Exported symbols with their addresses. Filter with `contains`; paginated.",
            |project, mut query: ListQuery| {
                query.limit = page_limit(query.limit);
                Ok(project.exports(&query))
            },
        ),
        tool(
            "rename",
            "Name a function or address. Names show everywhere and are saved beside the binary; record what you \
             learn as you go.",
            |project, arguments: RenameArgs| {
                let name = edit_value(arguments.name, arguments.clear, "name")?;
                project.rename(project.resolve(&arguments.at)?, name.as_deref())
            },
        ),
        tool(
            "set_comment",
            "Comment an instruction or address; comments show in the disassembly and are saved beside the binary.",
            |project, arguments: CommentArgs| {
                let text = edit_value(arguments.text, arguments.clear, "text")?;
                project.comment(project.resolve(&arguments.at)?, text.as_deref())
            },
        ),
        tool("list_annotations", "Every user name and comment, by address.", |project, _: Nothing| {
            Ok(project.annotation_list())
        }),
        tool(
            "show_address",
            "Move the user's view to an address or name, to point out what you are discussing.",
            |project, arguments: At| {
                Ok(serde_json::json!({ "address": format!("{:#x}", project.resolve(&arguments.at)?) }))
            },
        )
        .interactive(),
        tool(
            "undo",
            "Undo the last rename or comment made in this session. Returns the edit, or null.",
            |project, _: Nothing| project.undo(),
        ),
        tool("redo", "Redo the last edit undone in this session. Returns the edit, or null.", |project, _: Nothing| {
            project.redo()
        }),
    ]
}

/// Runs the tool `name` with `input`, returning its result as text for the model and whether it failed.
pub fn call(tools: &[Tool], project: &Project, name: &str, input: Value) -> (String, bool) {
    let Some(tool) = tools.iter().find(|tool| tool.name == name) else {
        return (format!("unknown tool {name}"), true);
    };
    match (tool.handler)(project, input) {
        Ok(value) => {
            let mut text = value.to_string();
            if text.len() > MAX_RESULT_CHARS {
                let cut = (0..=MAX_RESULT_CHARS).rev().find(|&index| text.is_char_boundary(index)).unwrap_or(0);
                text.truncate(cut);
                text.push_str("... (truncated: ask for a narrower range, a smaller count, or a page)");
            }
            (text, false)
        }
        Err(error) => (error, true),
    }
}
