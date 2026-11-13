//! Output-only projections of already serialized native results. No analysis or target execution occurs here.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::io::{self, Write};

use crate::ApiError;

pub const MAX_TOOL_VIEW_BYTES: usize = 60_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolView {
    Summary,
    Code,
    #[default]
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolViewKind {
    Decompile,
    FunctionSummary,
    Disassemble,
    FunctionGraph,
    BinaryInfo,
    InspectData,
}

/// Full preserves the original JSON value. Other views omit only named, known payloads and retain unknown fields.
/// The complete serialized result, including omission receipts, must fit the byte budget or the call refuses.
pub fn project_tool_view(value: Value, kind: ToolViewKind, view: ToolView) -> Result<Value, ApiError> {
    let value = project(value, kind, view)?;
    checked(value, kind, view)
}

/// The view projection of `value` before its byte budget is checked.
fn project(mut value: Value, kind: ToolViewKind, view: ToolView) -> Result<Value, ApiError> {
    if view == ToolView::Full {
        return Ok(value);
    }
    if view == ToolView::Code && matches!(kind, ToolViewKind::BinaryInfo | ToolViewKind::InspectData) {
        return Err(ApiError::Invalid(format!(
            "view=code is unsupported for {}; use view=summary or view=full for metadata",
            kind_name(kind),
        )));
    }
    validate_native_shape(&value, kind)?;
    let mut projection = Projection::default();
    match kind {
        ToolViewKind::Decompile => decompile(&mut value, view, &mut projection)?,
        ToolViewKind::FunctionSummary => function_summary(&mut value, view, &mut projection)?,
        ToolViewKind::Disassemble => {
            if view == ToolView::Summary {
                value = instruction_summary(&value, "", &mut projection)?;
            } else {
                // The native listing is already the code representation: do not reconstruct instruction text.
                value.as_array().ok_or_else(|| invalid("disassembly is not an instruction array"))?;
                return Ok(value);
            }
        }
        ToolViewKind::FunctionGraph => graph(&mut value, view, "", &mut projection)?,
        ToolViewKind::BinaryInfo => binary_info(&mut value, &mut projection)?,
        ToolViewKind::InspectData => inspect_data(&mut value, &mut projection)?,
    }
    let object = object(&mut value, "projected result")?;
    if object.contains_key("view_projection") {
        return Err(invalid("view_projection is reserved for the output projection receipt"));
    }
    object.insert(
        "view_projection".into(),
        json!({
            "kind": kind, "view": view, "omissions": projection.omissions,
            "code_kind": match kind {
                ToolViewKind::Decompile => "native_recovered_c",
                ToolViewKind::FunctionSummary => "native_instructions_and_optional_partial_structural_pseudocode",
                ToolViewKind::Disassemble | ToolViewKind::FunctionGraph => "native_instructions",
                ToolViewKind::BinaryInfo | ToolViewKind::InspectData => "not_code",
            },
        }),
    );
    Ok(value)
}

/// Where the pages of a fitted function summary's long lists start.
#[derive(Debug, Clone, Copy, Default)]
pub struct SummaryPages {
    pub block_offset: usize,
    pub reference_offset: usize,
    pub callee_offset: usize,
}

/// Bytes kept free for the paging fields a fitted summary adds.
const SUMMARY_PAGING_SLACK: usize = 1024;

/// Projects a function summary like [`project_tool_view`], adding `callees` (the distinct call targets among its
/// references) to the summary and code views. A summary or code view too large for the byte budget, or asked for
/// a later page, is fitted instead of refused: the graph blocks, references and callees are paged as whole rows
/// with `*_offset`/`*_next_offset` fields, and bulky optional analyses that still do not fit are omitted with
/// receipts. view=full keeps its exact-or-refuse contract.
pub fn project_function_summary(value: Value, view: ToolView, pages: SummaryPages) -> Result<Value, ApiError> {
    if view == ToolView::Full {
        return project_tool_view(value, ToolViewKind::FunctionSummary, view);
    }
    let callees = summary_callees(&value);
    let mut value = project(value, ToolViewKind::FunctionSummary, view)?;
    object(&mut value, "function summary")?.insert("callees".into(), Value::Array(callees));
    // Reference rows are paged by items_offset in these views; the native page offset would read as a second one.
    if let Some(references) = value.get_mut("references").and_then(Value::as_object_mut)
        && let Some(offset) = references.remove("offset")
    {
        references.insert("items_offset".into(), offset);
    }
    let paged = pages.block_offset != 0 || pages.reference_offset != 0 || pages.callee_offset != 0;
    if !paged && fits(&value) {
        return Ok(value);
    }
    fit_summary(value, view, pages)
}

fn fits(value: &Value) -> bool {
    let mut counter = JsonByteCounter::new(Some(MAX_TOOL_VIEW_BYTES));
    serde_json::to_writer(&mut counter, value).is_ok()
}

fn json_bytes(value: &Value) -> usize {
    let mut counter = JsonByteCounter::new(None);
    serde_json::to_writer(&mut counter, value).map_or(usize::MAX, |()| counter.bytes)
}

/// The distinct call targets among a native summary's references, in first-call order, with their call counts.
fn summary_callees(value: &Value) -> Vec<Value> {
    let mut callees: Vec<(Value, Value, u64)> = Vec::new();
    let items = value.get("references").and_then(|references| references.get("items")).and_then(Value::as_array);
    for item in items.into_iter().flatten().filter(|item| item.get("kind") == Some(&json!("call"))) {
        let target = item.get("to").cloned().unwrap_or(Value::Null);
        match callees.iter_mut().find(|(address, _, _)| *address == target) {
            Some((_, _, calls)) => *calls += 1,
            None => callees.push((target, item.get("to_name").cloned().unwrap_or(Value::Null), 1)),
        }
    }
    callees
        .into_iter()
        .map(|(address, name, calls)| json!({ "address": address, "name": name, "calls": calls }))
        .collect()
}

/// Takes the list at `path` out of `value`, leaving an empty one in its place.
fn take_list(value: &mut Value, path: &[&str]) -> Vec<Value> {
    let Some(list) = path.iter().try_fold(&mut *value, |at, key| at.get_mut(*key)) else { return Vec::new() };
    match list.take() {
        Value::Array(items) => {
            *list = Value::Array(Vec::new());
            items
        }
        other => {
            *list = other;
            Vec::new()
        }
    }
}

/// The whole rows of `items` from `offset` that fit `share` JSON bytes, charged to `budget`: the rows, the clamped
/// offset, where the next page starts, and whether the bytes (not the list's end) ended the page.
fn fitted_list(
    items: Vec<Value>,
    offset: usize,
    share: usize,
    budget: &mut usize,
) -> (Vec<Value>, usize, Option<usize>, bool) {
    let total = items.len();
    let offset = offset.min(total);
    let mut rows = Vec::new();
    let mut used = 0;
    for item in items.into_iter().skip(offset) {
        let size = json_bytes(&item) + 1;
        if used + size > share {
            break;
        }
        used += size;
        rows.push(item);
    }
    *budget -= used;
    let next = offset + rows.len();
    let more = next < total;
    (rows, offset, more.then_some(next), more)
}

/// Takes the blocks and edges out of the graph object at `graph`: each block paired with the edges leaving it
/// (which keep their whole-function block indices), and the edges that leave no listed block.
fn graph_units(value: &mut Value, graph: &[&str]) -> (Vec<Value>, Vec<Value>) {
    let path = |list: &'static str| graph.iter().copied().chain([list]).collect::<Vec<_>>();
    let blocks = take_list(value, &path("blocks"));
    let mut outgoing: Vec<Vec<Value>> = vec![Vec::new(); blocks.len()];
    let mut stray_edges = Vec::new();
    for edge in take_list(value, &path("edges")) {
        match edge.get("from").and_then(Value::as_u64).and_then(|from| outgoing.get_mut(from as usize)) {
            Some(edges) => edges.push(edge),
            None => stray_edges.push(edge),
        }
    }
    let units =
        blocks.into_iter().zip(outgoing).map(|(block, edges)| Value::Array(vec![block, Value::Array(edges)])).collect();
    (units, stray_edges)
}

/// A summary view records one omission receipt per graph block under `blocks` (e.g. `/graph/blocks/`); a paged
/// result sums them into one.
fn merge_block_receipts(value: &mut Value, blocks: &str) {
    let Some(omissions) = value.pointer_mut("/view_projection/omissions").and_then(Value::as_array_mut) else {
        return;
    };
    let per_block = |receipt: &Value| receipt["path"].as_str().is_some_and(|path| path.starts_with(blocks));
    let (blocks_count, bytes, items) = omissions.iter().filter(|receipt| per_block(receipt)).fold(
        (0u64, 0u64, 0u64),
        |(count, bytes, items), receipt| {
            (
                count + 1,
                bytes + receipt["json_bytes"].as_u64().unwrap_or(0),
                items + receipt["items"].as_u64().unwrap_or(0),
            )
        },
    );
    if blocks_count != 0 {
        omissions.retain(|receipt| !per_block(receipt));
        omissions.push(json!({
            "path": format!("{blocks}*/lines"), "blocks": blocks_count, "items": items, "json_bytes": bytes,
            "reason": "instruction text/bytes omitted; bounds, counts and non-rendering evidence retained",
        }));
    }
}

/// Puts one page of [`graph_units`] back into `graph` with its offsets; every page repeats the stray edges.
fn insert_graph_page(
    graph: &mut Map<String, Value>,
    units: Vec<Value>,
    stray_edges: &[Value],
    offset: usize,
    next: Option<usize>,
) {
    let (mut page_blocks, mut page_edges) = (Vec::new(), stray_edges.to_vec());
    for unit in units {
        if let Value::Array(mut parts) = unit {
            if let Some(Value::Array(edges)) = parts.pop() {
                page_edges.extend(edges);
            }
            page_blocks.extend(parts.pop());
        }
    }
    graph.insert("edges".into(), Value::Array(page_edges));
    graph.insert("blocks".into(), Value::Array(page_blocks));
    graph.insert("blocks_offset".into(), json!(offset));
    graph.insert("blocks_next_offset".into(), json!(next));
}

/// Projects a function graph like [`project_tool_view`]. A summary or code view too large for the byte budget, or
/// asked for a later page (`block_offset`), is paged instead of refused: whole blocks with the edges leaving them,
/// `blocks_offset`/`blocks_next_offset`, and a `fitted` receipt. Edges index blocks by their position in the whole
/// function, so every page's edges stay valid. view=full keeps its exact-or-refuse contract.
pub fn project_function_graph(value: Value, view: ToolView, block_offset: usize) -> Result<Value, ApiError> {
    if view == ToolView::Full {
        return project_tool_view(value, ToolViewKind::FunctionGraph, view);
    }
    let mut value = project(value, ToolViewKind::FunctionGraph, view)?;
    if block_offset == 0 && fits(&value) {
        return Ok(value);
    }
    let (blocks, stray_edges) = graph_units(&mut value, &[]);
    merge_block_receipts(&mut value, "/blocks/");
    let mut slack = SUMMARY_PAGING_SLACK;
    loop {
        let mut budget = MAX_TOOL_VIEW_BYTES.saturating_sub(json_bytes(&value) + slack);
        let (units, offset, next, byte_capped) = fitted_list(blocks.clone(), block_offset, budget, &mut budget);
        if units.is_empty() && next.is_some() {
            return Err(invalid(&format!(
                "function_graph {view:?} view: block {offset} alone exceeds the tool JSON byte budget; retry with \
                 view=summary or use disassemble with a smaller count"
            )));
        }
        let mut page = value.clone();
        let graph = object(&mut page, "function graph")?;
        insert_graph_page(graph, units, &stray_edges, offset, next);
        graph.insert(
            "fitted".into(),
            json!({
                "byte_budget": MAX_TOOL_VIEW_BYTES,
                "byte_capped": byte_capped,
                "continue_with": "pass block_offset set to blocks_next_offset for the next page; a page holds the \
                                  edges leaving its blocks, which index blocks by their position in the whole function",
            }),
        );
        if fits(&page) || slack >= MAX_TOOL_VIEW_BYTES {
            return checked(page, ToolViewKind::FunctionGraph, view);
        }
        slack *= 2;
    }
}

fn fit_summary(mut value: Value, view: ToolView, pages: SummaryPages) -> Result<Value, ApiError> {
    let (blocks, stray_edges) = graph_units(&mut value, &["graph"]);
    let references = take_list(&mut value, &["references", "items"]);
    let callees = take_list(&mut value, &["callees"]);
    merge_block_receipts(&mut value, "/graph/blocks/");
    // Bulky optional analyses go, largest first, only while the result without its lists still does not fit.
    let mut omitted = Vec::new();
    while json_bytes(&value) + SUMMARY_PAGING_SLACK > MAX_TOOL_VIEW_BYTES {
        let object = object(&mut value, "function summary")?;
        // Everything but the identity, the paged lists' holders, limitations and the projection receipt may go.
        let largest = object
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "graph" | "references" | "limitations" | "view_projection"))
            .map(|(key, field)| (json_bytes(field), key.clone()))
            .max();
        let Some((bytes, key)) = largest else {
            return Err(invalid(
                "function_summary fixed fields exceed the tool JSON byte budget even without its lists",
            ));
        };
        object.remove(&key);
        omitted.push(
            json!({ "path": format!("/{key}"), "reason": "omitted to fit the byte budget", "json_bytes": bytes }),
        );
    }
    // The paging fields and receipt are measured once built; a page that overruns is rebuilt with more room.
    let mut slack = SUMMARY_PAGING_SLACK;
    loop {
        let mut budget = MAX_TOOL_VIEW_BYTES.saturating_sub(json_bytes(&value) + slack);
        // Callees, the compact answer, may take a quarter; references half of what is left; blocks the rest.
        let callees = fitted_list(callees.clone(), pages.callee_offset, budget / 4, &mut budget);
        let references = fitted_list(references.clone(), pages.reference_offset, budget / 2, &mut budget);
        let blocks = fitted_list(blocks.clone(), pages.block_offset, budget, &mut budget);
        if blocks.0.is_empty() && blocks.2.is_some() {
            return Err(invalid(&format!(
                "function_summary {view:?} view: graph block {} alone exceeds the tool JSON byte budget; retry \
                 with view=summary or use disassemble with a smaller count",
                blocks.1
            )));
        }
        let mut page = value.clone();
        let object = object(&mut page, "function summary")?;
        object.insert("callees".into(), Value::Array(callees.0));
        object.insert("callees_offset".into(), json!(callees.1));
        object.insert("callees_next_offset".into(), json!(callees.2));
        if let Some(references_object) = object.get_mut("references").and_then(Value::as_object_mut) {
            references_object.insert("items".into(), Value::Array(references.0));
            references_object.insert("items_offset".into(), json!(references.1));
            references_object.insert("items_next_offset".into(), json!(references.2));
        }
        if let Some(graph) = object.get_mut("graph").and_then(Value::as_object_mut) {
            insert_graph_page(graph, blocks.0, &stray_edges, blocks.1, blocks.2);
        }
        object.insert(
            "fitted".into(),
            json!({
                "byte_budget": MAX_TOOL_VIEW_BYTES,
                "byte_capped": callees.3 || references.3 || blocks.3,
                "omitted": omitted,
                "continue_with": "pass block_offset, reference_offset or callee_offset set to the matching \
                                  *_next_offset for the next page of that list; a page holds the edges leaving its \
                                  blocks, which index blocks by their position in the whole function",
            }),
        );
        if fits(&page) || slack >= MAX_TOOL_VIEW_BYTES {
            return checked(page, ToolViewKind::FunctionSummary, view);
        }
        slack *= 2;
    }
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn kind_name(kind: ToolViewKind) -> &'static str {
    match kind {
        ToolViewKind::Decompile => "decompile",
        ToolViewKind::FunctionSummary => "function_summary",
        ToolViewKind::Disassemble => "disassemble",
        ToolViewKind::FunctionGraph => "function_graph",
        ToolViewKind::BinaryInfo => "binary_info",
        ToolViewKind::InspectData => "inspect_data",
    }
}

fn checked(value: Value, kind: ToolViewKind, view: ToolView) -> Result<Value, ApiError> {
    let mut counter = JsonByteCounter::new(Some(MAX_TOOL_VIEW_BYTES));
    if let Err(error) = serde_json::to_writer(&mut counter, &value) {
        if !counter.exceeded {
            return Err(invalid(&format!("view serialization: {error}")));
        }
        let recovery = match view {
            ToolView::Full => "retry with view=summary or, for code tools, view=code; use paging/range arguments",
            ToolView::Code => "retry with view=summary or smaller paging/range arguments; use the API for full code",
            ToolView::Summary => {
                "essential evidence exceeds the budget; use smaller paging/range arguments or the complete API result"
            }
        };
        return Err(invalid(&format!(
            "{} {view:?} view exceeds the tool JSON byte budget (> {MAX_TOOL_VIEW_BYTES}); \
             {recovery}; no strings were truncated",
            kind_name(kind),
        )));
    }
    Ok(value)
}

struct JsonByteCounter {
    bytes: usize,
    limit: Option<usize>,
    exceeded: bool,
}

impl JsonByteCounter {
    fn new(limit: Option<usize>) -> Self {
        Self { bytes: 0, limit, exceeded: false }
    }
}

impl Write for JsonByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self.bytes.checked_add(buffer.len()).ok_or_else(|| io::Error::other("JSON byte count overflow"))?;
        if self.limit.is_some_and(|limit| next > limit) {
            self.exceeded = true;
            return Err(io::Error::other("JSON byte budget exceeded"));
        }
        self.bytes = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn object<'a>(value: &'a mut Value, what: &str) -> Result<&'a mut Map<String, Value>, ApiError> {
    value.as_object_mut().ok_or_else(|| invalid(&format!("{what} is not an object")))
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    Object,
    Array,
    String,
    Unsigned,
    Bool,
}

impl Shape {
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::String => value.is_string(),
            Self::Unsigned => value.as_u64().is_some(),
            Self::Bool => value.is_boolean(),
        }
    }
}

fn fields(value: &Value, path: &str, required: &[(&str, Shape)], optional: &[(&str, Shape)]) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(|| invalid(&format!("native shape {path}: expected object")))?;
    for (key, shape) in required {
        if !object.get(*key).is_some_and(|value| shape.matches(value)) {
            return Err(invalid(&format!(
                "native shape {path}/{key}: required {shape:?} field is missing or malformed"
            )));
        }
    }
    for (key, shape) in optional {
        if object.get(*key).is_some_and(|value| !value.is_null() && !shape.matches(value)) {
            return Err(invalid(&format!("native shape {path}/{key}: optional field must be {shape:?} or null")));
        }
    }
    Ok(())
}

fn rows(value: &Value, path: &str, validate: impl Fn(&Value, &str) -> Result<(), ApiError>) -> Result<(), ApiError> {
    let rows = value.as_array().ok_or_else(|| invalid(&format!("native shape {path}: expected array")))?;
    for (index, row) in rows.iter().enumerate() {
        validate(row, &format!("{path}/{index}"))?;
    }
    Ok(())
}

fn string_rows(value: &Value, path: &str) -> Result<(), ApiError> {
    rows(value, path, |value, path| {
        if value.is_string() { Ok(()) } else { Err(invalid(&format!("native shape {path}: expected string"))) }
    })
}

fn validate_native_shape(value: &Value, kind: ToolViewKind) -> Result<(), ApiError> {
    use Shape::*;
    match kind {
        ToolViewKind::Decompile => {
            fields(
                value,
                "",
                &[
                    ("address", String),
                    ("name", String),
                    ("code", String),
                    ("language_id", String),
                    ("tokens", Array),
                    ("structure", Object),
                    ("recovery_status", String),
                    ("variables", Array),
                ],
                &[("context", Object)],
            )?;
            rows(&value["tokens"], "/tokens", |token, path| {
                fields(token, path, &[("text", String), ("kind", String)], &[("address", String), ("span", Array)])
            })?;
            rows(&value["variables"], "/variables", |variable, path| {
                fields(
                    variable,
                    path,
                    &[("name", String), ("data_type", Object), ("kind", String), ("editable", Bool)],
                    &[("key", String), ("storage", Object), ("unavailable_reason", String)],
                )
            })?;
            let structure = &value["structure"];
            fields(
                structure,
                "/structure",
                &[
                    ("provenance", String),
                    ("signature", Object),
                    ("variables", Array),
                    ("blocks", Array),
                    ("calls", Array),
                    ("jump_tables", Array),
                ],
                &[("diagnostics", Object), ("frame_context", Object)],
            )?;
            rows(&structure["variables"], "/structure/variables", |variable, path| {
                fields(
                    variable,
                    path,
                    &[("name", String), ("data_type", Object), ("kind", String), ("storage", Array)],
                    &[],
                )?;
                rows(&variable["storage"], &format!("{path}/storage"), validate_raw_storage)
            })?;
            fields(
                &structure["signature"],
                "/structure/signature",
                &[("return_type", Object), ("variadic", Bool), ("parameters", Array)],
                &[("calling_convention", String)],
            )?;
            if let Some(diagnostics) = structure.get("diagnostics").filter(|value| !value.is_null()) {
                fields(
                    diagnostics,
                    "/structure/diagnostics",
                    &[
                        ("bad_data", Bool),
                        ("unimplemented", Bool),
                        ("unresolved_calls", Unsigned),
                        ("unresolved_indirect_jumps", Unsigned),
                        ("partial_jump_tables", Unsigned),
                        ("warnings", Array),
                    ],
                    &[],
                )?;
            }
        }
        ToolViewKind::FunctionGraph => validate_graph(value, "")?,
        ToolViewKind::Disassemble => rows(value, "", validate_instruction)?,
        ToolViewKind::FunctionSummary => {
            fields(
                value,
                "",
                &[
                    ("graph", Object),
                    ("references", Object),
                    ("limitations", Array),
                    ("ir", Array),
                    ("lifted_instructions", Unsigned),
                    ("validated_indirect_targets", Array),
                ],
                &[
                    ("ssa", Object),
                    ("dataflow", Object),
                    ("pseudocode", Object),
                    ("control", Object),
                    ("structured_control", Object),
                    ("structured_pseudocode", Object),
                    ("type_evidence", Object),
                ],
            )?;
            validate_graph(&value["graph"], "/graph")?;
            fields(
                &value["references"],
                "/references",
                &[("total", Unsigned), ("offset", Unsigned), ("items", Array)],
                &[],
            )?;
            rows(&value["ir"], "/ir", |instruction, path| {
                fields(
                    instruction,
                    path,
                    &[
                        ("address", String),
                        ("bits", Unsigned),
                        ("effects", Array),
                        ("flow", Object),
                        ("complete", Bool),
                    ],
                    &[],
                )
            })?;
            for key in ["pseudocode", "structured_pseudocode"] {
                if let Some(pseudocode) = value.get(key).filter(|value| !value.is_null()) {
                    fields(
                        pseudocode,
                        &format!("/{key}"),
                        &[("text", String), ("structured", Bool), ("limitations", Array)],
                        &[],
                    )?;
                }
            }
            if let Some(ssa) = value.get("ssa").filter(|value| !value.is_null()) {
                fields(
                    ssa,
                    "/ssa",
                    &[("entry", Unsigned), ("blocks", Array), ("definitions", Array), ("limitations", Array)],
                    &[],
                )?;
                rows(&ssa["blocks"], "/ssa/blocks", |block, path| {
                    fields(
                        block,
                        path,
                        &[
                            ("address", String),
                            ("reachable", Bool),
                            ("predecessors", Array),
                            ("phis", Array),
                            ("statements", Array),
                        ],
                        &[],
                    )?;
                    rows(&block["statements"], &format!("{path}/statements"), |statement, path| {
                        fields(
                            statement,
                            path,
                            &[
                                ("address", String),
                                ("flow", Object),
                                ("bits", Unsigned),
                                ("definitions", Array),
                                ("observations", Array),
                                ("barrier", Bool),
                            ],
                            &[("noreturn", Bool), ("recovered_loads", Array)],
                        )
                    })
                })?;
            }
            if let Some(dataflow) = value.get("dataflow").filter(|value| !value.is_null()) {
                fields(
                    dataflow,
                    "/dataflow",
                    &[
                        ("constants", Array),
                        ("stack_slots", Array),
                        ("argument_registers", Array),
                        ("integer_returns", Array),
                        ("forwarded_loads", Array),
                        ("indirect_targets", Array),
                        ("incomplete_instructions", Unsigned),
                        ("limitations", Array),
                    ],
                    &[("stack_registers", Array)],
                )?;
            }
        }
        ToolViewKind::BinaryInfo => {
            fields(
                value,
                "",
                &[
                    ("format", String),
                    ("arch", String),
                    ("slices", Array),
                    ("segments", Array),
                    ("sections", Array),
                    ("symbols", Unsigned),
                    ("imports", Unsigned),
                    ("exports", Unsigned),
                    ("function_starts", Unsigned),
                    ("warnings", Array),
                ],
                &[
                    ("entry", String),
                    ("embedded", Object),
                    ("provenance", String),
                    ("snapshot_modules", Array),
                    ("snapshot_registers", Array),
                    ("snapshot_target", Object),
                ],
            )?;
            string_rows(&value["slices"], "/slices")?;
            string_rows(&value["warnings"], "/warnings")?;
            rows(&value["segments"], "/segments", |segment, path| {
                fields(
                    segment,
                    path,
                    &[
                        ("name", String),
                        ("address", String),
                        ("size", Unsigned),
                        ("file_offset", Unsigned),
                        ("file_size", Unsigned),
                        ("perms", Object),
                    ],
                    &[],
                )
            })?;
            rows(&value["sections"], "/sections", |section, path| {
                fields(
                    section,
                    path,
                    &[
                        ("name", String),
                        ("address", String),
                        ("size", Unsigned),
                        ("kind", String),
                        ("file_size", Unsigned),
                    ],
                    &[("file_offset", Unsigned)],
                )
            })?;
        }
        ToolViewKind::InspectData => {
            fields(
                value,
                "",
                &[
                    ("format", String),
                    ("arch", String),
                    ("selected_image_size", Unsigned),
                    ("backing_metadata_checked", Bool),
                    ("loader_diagnostics", Object),
                    ("pointer_targets_suppressed", Bool),
                    ("address", String),
                    ("size", Unsigned),
                    ("word_size", Unsigned),
                    ("data_big_endian", Bool),
                    ("trailing_bytes", Unsigned),
                    ("spans", Array),
                    ("words", Array),
                    ("limitations", Array),
                ],
                &[("module_uuid", String), ("selected_image_file_offset", Unsigned)],
            )?;
            fields(
                &value["loader_diagnostics"],
                "/loader_diagnostics",
                &[
                    ("warnings_total", Unsigned),
                    ("warnings_omitted", Unsigned),
                    ("truncated", Bool),
                    ("warnings", Array),
                ],
                &[],
            )?;
            rows(&value["spans"], "/spans", |span, path| {
                fields(
                    span,
                    path,
                    &[("address", String), ("size", Unsigned), ("status", String)],
                    &[
                        ("image_offset", Unsigned),
                        ("file_offset", Unsigned),
                        ("permissions", Object),
                        ("hex", String),
                        ("ascii", String),
                    ],
                )
            })?;
            rows(&value["words"], "/words", |word, path| {
                fields(
                    word,
                    path,
                    &[("address", String), ("interpretation", String)],
                    &[("raw_value", String), ("import", Object), ("candidate", Object)],
                )?;
                if let Some(candidate) = word.get("candidate").filter(|value| !value.is_null()) {
                    fields(
                        candidate,
                        &format!("{path}/candidate"),
                        &[
                            ("address", String),
                            ("evidence", String),
                            ("permissions", Object),
                            ("code_range", Bool),
                            ("declared_function_start", Bool),
                            ("labels", Array),
                            ("ascii_terminated", Bool),
                        ],
                        &[("address_adjustment", String), ("ascii_preview", String)],
                    )?;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

fn validate_raw_storage(value: &Value, path: &str) -> Result<(), ApiError> {
    use Shape::*;
    fields(
        value,
        path,
        &[("kind", String), ("size", Unsigned)],
        &[
            ("space", String),
            ("address_size_bytes", Unsigned),
            ("address", String),
            ("use_ranges", Array),
            ("dynamic_hash", Unsigned),
            ("symbol_offset", Unsigned),
            ("is_piece", Bool),
            ("join_logical_size", Unsigned),
            ("pieces", Array),
        ],
    )?;
    if let Some(pieces) = value.get("pieces").filter(|value| !value.is_null()) {
        rows(pieces, &format!("{path}/pieces"), |piece, path| {
            fields(
                piece,
                path,
                &[
                    ("kind", String),
                    ("space", String),
                    ("address", String),
                    ("size", Unsigned),
                    ("logical_offset", Unsigned),
                ],
                &[("address_size_bytes", Unsigned)],
            )
        })?;
    }
    Ok(())
}

fn validate_graph(value: &Value, path: &str) -> Result<(), ApiError> {
    use Shape::*;
    fields(value, path, &[("address", String), ("name", String), ("blocks", Array), ("edges", Array)], &[])?;
    rows(&value["blocks"], &format!("{path}/blocks"), |block, path| {
        fields(block, path, &[("start", String), ("lines", Array)], &[])?;
        rows(&block["lines"], &format!("{path}/lines"), validate_instruction)
    })?;
    rows(&value["edges"], &format!("{path}/edges"), |edge, path| {
        fields(edge, path, &[("from", Unsigned), ("to", Unsigned), ("kind", String)], &[])
    })
}

fn validate_instruction(value: &Value, path: &str) -> Result<(), ApiError> {
    use Shape::*;
    fields(
        value,
        path,
        &[("address", String), ("bytes", String), ("text", String), ("flow", Object)],
        &[
            ("data_ref", String),
            ("accesses", Bool),
            ("immediate", String),
            ("label", String),
            ("comment", String),
            ("note", String),
            ("noreturn", String),
            ("operand_annotations", Array),
            ("decode_gate", Object),
        ],
    )?;
    fields(&value["flow"], &format!("{path}/flow"), &[("kind", String)], &[("target", String)])?;
    if let Some(gate) = value.get("decode_gate") {
        fields(
            gate,
            &format!("{path}/decode_gate"),
            &[("backend", String), ("profile", String), ("address", String), ("reason", String)],
            &[],
        )?;
    }
    Ok(())
}

fn derived(object: &mut Map<String, Value>, key: &str, value: Value) -> Result<(), ApiError> {
    if object.get(key).is_some_and(|existing| *existing != value) {
        return Err(invalid(&format!("projection field {key} conflicts with retained evidence")));
    }
    object.insert(key.into(), value);
    Ok(())
}

#[derive(Default)]
struct Projection {
    omissions: Vec<Value>,
}

impl Projection {
    fn record(&mut self, path: &str, value: &Value, reason: &str) -> Result<(), ApiError> {
        let mut counter = JsonByteCounter::new(None);
        serde_json::to_writer(&mut counter, value)
            .map_err(|error| invalid(&format!("omission byte count for {path}: {error}")))?;
        let mut receipt = json!({ "path": path, "reason": reason, "json_bytes": counter.bytes });
        if let Some(items) = value.as_array() {
            receipt["items"] = json!(items.len());
        }
        if let Some(text) = value.as_str() {
            receipt["utf8_bytes"] = json!(text.len());
        }
        self.omissions.push(receipt);
        Ok(())
    }

    fn array(&mut self, object: &mut Map<String, Value>, key: &str, path: &str) -> Result<(), ApiError> {
        if object.get(key).is_some_and(Value::is_array) && !object.contains_key(&format!("{key}_count")) {
            let value = object.remove(key).expect("array checked above");
            object.insert(format!("{key}_count"), json!(value.as_array().expect("checked array").len()));
            self.record(path, &value, "row payload omitted; count retained")?;
        }
        Ok(())
    }

    fn text(&mut self, object: &mut Map<String, Value>, key: &str, path: &str) -> Result<(), ApiError> {
        if object.get(key).is_some_and(Value::is_string) && !object.contains_key(&format!("{key}_utf8_bytes")) {
            let value = object.remove(key).expect("string checked above");
            object.insert(format!("{key}_utf8_bytes"), json!(value.as_str().expect("checked string").len()));
            self.record(path, &value, "text omitted without truncation")?;
        }
        Ok(())
    }
}

fn decompile(value: &mut Value, view: ToolView, projection: &mut Projection) -> Result<(), ApiError> {
    let object = object(value, "decompilation")?;
    projection.array(object, "tokens", "/tokens")?;
    if let Some(mut structure) = object.remove("structure") {
        if let Some(fields) = structure.as_object_mut() {
            if let Some(diagnostics) = fields.remove("diagnostics") {
                // A pre-existing field is evidence too; refuse ambiguous promotion instead of overwriting it.
                if object.get("diagnostics").is_some_and(|existing| *existing != diagnostics) {
                    return Err(invalid("conflicting root and native structure diagnostics"));
                }
                object.insert("diagnostics".into(), diagnostics);
            }
            for key in ["blocks", "calls", "jump_tables"] {
                projection.array(fields, key, &format!("/structure/{key}"))?;
            }
        }
        if object.contains_key("structure_metadata") {
            return Err(invalid("structure_metadata is reserved for retained native structure evidence"));
        }
        object.insert("structure_metadata".into(), structure);
    }
    if view == ToolView::Summary {
        projection.text(object, "code", "/code")?;
    }
    // Native variable descriptors, language_id, exact-entry context and recovery status remain untouched.
    Ok(())
}

fn function_summary(value: &mut Value, view: ToolView, projection: &mut Projection) -> Result<(), ApiError> {
    let object = object(value, "function summary")?;
    if let Some(graph_value) = object.get_mut("graph") {
        graph(graph_value, view, "/graph", projection)?;
    }
    if let Some(ir) = object.get("ir").and_then(Value::as_array) {
        let complete = ir.iter().filter(|instruction| instruction.get("complete") == Some(&Value::Bool(true))).count();
        derived(object, "ir_complete_count", json!(complete))?;
    }
    projection.array(object, "ir", "/ir")?;
    if let Some(ssa) = object.get_mut("ssa").and_then(Value::as_object_mut) {
        projection.array(ssa, "definitions", "/ssa/definitions")?;
        // Keep statements and their observations: indirect transfers and noreturn facts are not disposable IR noise.
    }
    for key in ["pseudocode", "structured_pseudocode"] {
        if let Some(pseudocode) = object.get_mut(key).and_then(Value::as_object_mut) {
            if pseudocode.contains_key("code_kind") {
                return Err(invalid("pseudocode code_kind is reserved for the output projection label"));
            }
            pseudocode.insert("code_kind".into(), json!("partial_structural_pseudocode_not_native_recovered_c"));
            if view == ToolView::Summary {
                projection.text(pseudocode, "text", &format!("/{key}/text"))?;
            }
        }
    }
    if let Some(references) = object.get_mut("references").and_then(Value::as_object_mut)
        && let Some(items) = references.get("items").and_then(Value::as_array)
    {
        let count = items.len();
        derived(references, "returned_count", json!(count))?;
    }
    // Dataflow, control, validated indirect targets, type evidence and reference page totals stay complete.
    Ok(())
}

fn graph(value: &mut Value, view: ToolView, path: &str, projection: &mut Projection) -> Result<(), ApiError> {
    let object = object(value, "function graph")?;
    if let Some(edges) = object.get("edges").and_then(Value::as_array) {
        let count = edges.len();
        derived(object, "edges_count", json!(count))?;
    }
    if let Some(blocks) = object.get_mut("blocks").and_then(Value::as_array_mut) {
        let blocks_count = blocks.len();
        let mut instructions_count = 0;
        for (index, block) in blocks.iter_mut().enumerate() {
            let block = object_mut_block(block)?;
            if let Some(lines) = block.get("lines").and_then(Value::as_array) {
                instructions_count += lines.len();
            }
            if view == ToolView::Summary
                && let Some(lines) = block.remove("lines")
            {
                let summary = instruction_summary(&lines, &format!("{path}/blocks/{index}/lines"), projection)?;
                if block.insert("instruction_summary".into(), summary).is_some() {
                    return Err(invalid("instruction_summary is reserved for the output projection"));
                }
            }
        }
        derived(object, "blocks_count", json!(blocks_count))?;
        derived(object, "instructions_count", json!(instructions_count))?;
    }
    Ok(())
}

fn object_mut_block(value: &mut Value) -> Result<&mut Map<String, Value>, ApiError> {
    object(value, "graph block")
}

fn instruction_summary(value: &Value, path: &str, projection: &mut Projection) -> Result<Value, ApiError> {
    let lines = value.as_array().ok_or_else(|| invalid("disassembly is not an instruction array"))?;
    let mut flows = Map::new();
    let mut facts = Vec::new();
    for line in lines {
        let evidence: Map<String, Value> = line
            .as_object()
            .ok_or_else(|| invalid("instruction is not an object"))?
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "text" | "bytes"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let flow_kind =
            evidence.get("flow").and_then(|flow| flow.get("kind")).and_then(Value::as_str).map(str::to_owned);
        if let Some(flow_kind) = &flow_kind {
            let count = flows.get(flow_kind).and_then(Value::as_u64).unwrap_or(0) + 1;
            flows.insert(flow_kind.clone(), json!(count));
        }
        // Preserve every non-rendering field, including future evidence, annotations and control-flow facts.
        // The receipt below names the two bulk rendering fields explicitly.
        if evidence.get("flow") != Some(&json!({"kind": "next"}))
            || evidence.keys().any(|key| !matches!(key.as_str(), "address" | "flow"))
        {
            facts.push(Value::Object(evidence));
        }
    }
    projection.record(
        path,
        value,
        "instruction text/bytes omitted; bounds, counts and non-rendering evidence retained",
    )?;
    Ok(json!({
        "instructions_count": lines.len(),
        "first_address": lines.first().and_then(|line| line.get("address")),
        "last_address": lines.last().and_then(|line| line.get("address")),
        "flow_counts": flows,
        "control_and_annotation_facts": facts,
    }))
}

fn binary_info(value: &mut Value, projection: &mut Projection) -> Result<(), ApiError> {
    let object = object(value, "binary info")?;
    for key in ["segments", "sections", "snapshot_modules", "snapshot_registers"] {
        projection.array(object, key, &format!("/{key}"))?;
    }
    Ok(())
}

fn inspect_data(value: &mut Value, projection: &mut Projection) -> Result<(), ApiError> {
    let object = object(value, "data inspection")?;
    if let Some(spans) = object.get_mut("spans").and_then(Value::as_array_mut) {
        let mut statuses = Map::new();
        let count = spans.len();
        for (index, span) in spans.iter_mut().enumerate() {
            let span = span.as_object_mut().ok_or_else(|| invalid("data span is not an object"))?;
            if let Some(status) = span.get("status").and_then(Value::as_str) {
                let count = statuses.get(status).and_then(Value::as_u64).unwrap_or(0) + 1;
                statuses.insert(status.into(), json!(count));
            }
            projection.text(span, "hex", &format!("/spans/{index}/hex"))?;
            projection.text(span, "ascii", &format!("/spans/{index}/ascii"))?;
        }
        derived(object, "spans_count", json!(count))?;
        derived(object, "span_status_counts", Value::Object(statuses))?;
    }
    if let Some(words) = object.get_mut("words").and_then(Value::as_array_mut) {
        let count = words.len();
        for (index, word) in words.iter_mut().enumerate() {
            if let Some(candidate) = word.get_mut("candidate").and_then(Value::as_object_mut) {
                projection.text(candidate, "ascii_preview", &format!("/words/{index}/candidate/ascii_preview"))?;
            }
        }
        derived(object, "words_count", json!(count))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_analysis::discover::NoreturnEvidence;
    use rampage_arch::{Arch, Flow};
    use rampage_decompiler::results::{
        FrameBaseConvention, FrameContext, RecoveryDiagnostics, RecoveryStatus, StructuredResult, TypeInfo,
        VariableKind,
    };
    use rampage_loaders::{Format, Perms};

    fn native_line(address: u64, flow: Flow) -> crate::DisassemblyLine {
        crate::DisassemblyLine {
            address,
            bytes: "d65f03c0".into(),
            text: "ret".into(),
            flow,
            data_ref: None,
            accesses: false,
            immediate: None,
            label: None,
            comment: None,
            note: None,
            noreturn: None,
            decode_gate: None,
            operand_annotations: Vec::new(),
        }
    }

    fn native_graph() -> crate::FunctionGraph {
        let mut annotated = native_line(0x1000, Flow::Call(0x2000));
        annotated.bytes = "94000400".into();
        annotated.text = "bl #0x2000".into();
        annotated.label = Some("entry_λ".into());
        annotated.comment = Some("abort".into());
        annotated.note = Some("analyst: observed, not executed".into());
        annotated.noreturn = Some(NoreturnEvidence::Listed);
        annotated.operand_annotations.push(crate::OperandAnnotationDisplay {
            operand: 0,
            kind: crate::annotations::OperandTypeKind::Enum,
            type_name: "Mode".into(),
            display: "Mode::Stop".into(),
            matched: true,
            immediate: Some(1),
            width_bits: Some(32),
            field_path: None,
            base: None,
            displacement: None,
            access_size: None,
            limitation: "analyst assertion, not producer proof",
        });
        crate::FunctionGraph {
            address: 0x1000,
            name: "entry_λ".into(),
            blocks: vec![crate::GraphBlock {
                start: 0x1000,
                lines: vec![
                    annotated,
                    native_line(0x1004, Flow::IndirectJump),
                    native_line(0x1008, Flow::Return),
                    native_line(0x100c, Flow::Invalid),
                ],
            }],
            edges: Vec::new(),
        }
    }

    fn native_decompilation() -> Value {
        let mut structure = StructuredResult::empty();
        structure.variables = native_raw_variables();
        structure.diagnostics = Some(RecoveryDiagnostics {
            bad_data: true,
            unimplemented: false,
            unresolved_calls: 1,
            unresolved_indirect_jumps: 2,
            partial_jump_tables: 1,
            warnings: Vec::new(),
        });
        structure.frame_context = Some(FrameContext {
            stack_space: "stack".into(),
            address_size_bytes: 4,
            base_convention: FrameBaseConvention::Unknown,
            base_register: None,
        });
        let variables = crate::variables::descriptors(&structure);
        let result = crate::Decompilation {
            address: 0x1000,
            name: "partial_λ".into(),
            code: "  int partial_λ(void) {\n    return 7;\n}\n".into(),
            language_id: "AARCH64:LE:64:v8A:default".into(),
            tokens: vec![crate::decompile::DecompiledToken {
                text: "partial_λ".into(),
                kind: "function".into(),
                address: Some(0x1000),
                span: Some((6, 16)),
            }],
            structure,
            recovery_status: RecoveryStatus::Incomplete,
            variables,
        };
        let mut value = serde_json::to_value(result).unwrap();
        // EntryDecompilation flattens native decompilation; its context must not be treated as optional bulk.
        value["context"] = json!({
            "scope": "exact_entry", "mapped_backing_checked": false,
            "omissions": ["bounded local context"], "execution": "supervised_worker",
        });
        value
    }

    fn native_raw_variables() -> Vec<rampage_decompiler::results::Variable> {
        use rampage_decompiler::results::{Storage, StorageKind, StoragePiece, StorageUseRange, Variable};
        let stack = Storage {
            kind: StorageKind::Spacebase,
            space: Some("stack".into()),
            address_size_bytes: Some(4),
            address: Some(0xffff_fffc),
            size: 4,
            use_ranges: Some(vec![StorageUseRange { space: "ram".into(), start: 0x1000, end: 0x1004 }]),
            dynamic_hash: None,
            symbol_offset: Some(0),
            is_piece: Some(false),
            join_logical_size: None,
            pieces: Vec::new(),
        };
        let register = Storage {
            kind: StorageKind::Processor,
            space: Some("register".into()),
            address_size_bytes: Some(8),
            address: Some(0x10),
            size: 4,
            use_ranges: Some(Vec::new()),
            dynamic_hash: None,
            symbol_offset: Some(0),
            is_piece: Some(false),
            join_logical_size: None,
            pieces: Vec::new(),
        };
        let join = Storage {
            kind: StorageKind::Join,
            space: Some("join".into()),
            address_size_bytes: Some(8),
            address: Some(0x20),
            size: 8,
            use_ranges: None,
            dynamic_hash: None,
            symbol_offset: Some(0),
            is_piece: Some(false),
            join_logical_size: Some(8),
            pieces: vec![
                StoragePiece {
                    kind: StorageKind::Processor,
                    space: "register".into(),
                    address_size_bytes: Some(8),
                    address: 0x10,
                    size: 4,
                    logical_offset: 0,
                },
                StoragePiece {
                    kind: StorageKind::Spacebase,
                    space: "stack".into(),
                    address_size_bytes: Some(4),
                    address: 0xffff_fffc,
                    size: 4,
                    logical_offset: 4,
                },
            ],
        };
        [
            ("stack_λ", vec![stack]),
            ("register_λ", vec![register]),
            ("unsupported_join_λ", vec![join]),
            ("missing_mapping_λ", Vec::new()),
        ]
        .into_iter()
        .map(|(name, storage)| Variable {
            name: name.into(),
            data_type: TypeInfo { name: "int".into(), size: 4 },
            kind: VariableKind::Local,
            storage,
        })
        .collect()
    }

    fn native_function_summary() -> Value {
        use rampage_analysis::{dataflow, pseudocode, ssa};
        let result = crate::FunctionSummary {
            graph: native_graph(),
            references: crate::Page { total: 25, offset: 3, items: Vec::new() },
            limitations: vec!["structural only; not decompiled source".into()],
            ir: vec![rampage_arch::ir::LiftedInstruction {
                address: 0x1000,
                bits: 64,
                effects: Vec::new(),
                flow: Flow::IndirectJump,
                complete: false,
            }],
            lifted_instructions: 0,
            ssa: Some(ssa::Ssa {
                entry: 0,
                blocks: vec![ssa::Block {
                    address: 0x1000,
                    reachable: true,
                    predecessors: Vec::new(),
                    phis: Vec::new(),
                    statements: vec![ssa::Statement {
                        address: 0x1000,
                        flow: Flow::IndirectCall,
                        bits: 64,
                        definitions: Vec::new(),
                        recovered_loads: Vec::new(),
                        observations: vec![ssa::Expression::IndirectBranch {
                            target: Box::new(ssa::Expression::Constant { value: 0x2000 }),
                        }],
                        barrier: true,
                        noreturn: true,
                    }],
                }],
                definitions: Vec::new(),
                limitations: vec!["incomplete lift".into()],
            }),
            dataflow: Some(dataflow::DataFlow {
                constants: Vec::new(),
                stack_slots: Vec::new(),
                stack_registers: Vec::new(),
                argument_registers: vec![0],
                integer_returns: Vec::new(),
                forwarded_loads: Vec::new(),
                indirect_targets: vec![dataflow::IndirectTarget {
                    address: 0x1000,
                    target: 0x2000,
                    call: true,
                    input_definitions: vec![1],
                }],
                incomplete_instructions: 1,
                limitations: vec!["not runtime proof".into()],
            }),
            pseudocode: Some(pseudocode::Pseudocode {
                text: "  block_0: indirect_call(x0);\n".into(),
                structured: false,
                limitations: vec!["partial SSA semantics".into()],
            }),
            control: None,
            structured_control: None,
            structured_pseudocode: None,
            type_evidence: None,
            validated_indirect_targets: Vec::new(),
        };
        serde_json::to_value(result).unwrap()
    }

    /// function_graph refused oversized summary/code views; it now pages whole blocks with the edges leaving them.
    #[test]
    fn oversized_function_graphs_are_paged_not_refused() {
        let mut graph = native_graph();
        graph.blocks = (0..300u64)
            .map(|block| crate::GraphBlock {
                start: 0x1000 + block * 0x100,
                lines: (0..8u64)
                    .map(|line| {
                        let address = 0x1000 + block * 0x100 + line * 4;
                        let mut call = native_line(address, Flow::Call(0x9000 + block * 8 + line));
                        call.comment = Some(format!("github.com/example/module/package.(*Type).callee_{block:04}"));
                        call
                    })
                    .collect(),
            })
            .collect();
        // Every block falls through, and the last jumps back to the first.
        graph.edges =
            (0..300).map(|from| crate::Edge { from, to: (from + 1) % 300, kind: crate::EdgeKind::Taken }).collect();
        let graph = serde_json::to_value(graph).unwrap();
        for view in [ToolView::Summary, ToolView::Code] {
            assert!(project_tool_view(graph.clone(), ToolViewKind::FunctionGraph, view).is_err());
            let (mut offset, mut blocks, mut pages) = (0, 0, 0);
            loop {
                let page = project_function_graph(graph.clone(), view, offset).unwrap();
                assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_TOOL_VIEW_BYTES);
                assert_eq!(page["blocks_offset"], json!(offset));
                assert_eq!(page["blocks_count"], json!(300), "{view:?}");
                let page_blocks = page["blocks"].as_array().unwrap();
                assert!(!page_blocks.is_empty());
                assert_eq!(page_blocks[0]["start"], graph["blocks"][offset]["start"]);
                // A page carries exactly the edges leaving its blocks, by whole-function index.
                let edges: Vec<(u64, u64)> = page["edges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|edge| (edge["from"].as_u64().unwrap(), edge["to"].as_u64().unwrap()))
                    .collect();
                let first = offset as u64;
                let expected: Vec<(u64, u64)> =
                    (first..first + page_blocks.len() as u64).map(|from| (from, (from + 1) % 300)).collect();
                assert_eq!(edges, expected, "{view:?}");
                blocks += page_blocks.len();
                pages += 1;
                match page["blocks_next_offset"].as_u64() {
                    Some(next) => offset = next as usize,
                    None => break,
                }
            }
            assert_eq!(blocks, 300, "{view:?}");
            assert!(pages > 1, "{view:?}");
        }
        // A graph that fits is the plain projection; full keeps exact-or-refuse.
        let small = serde_json::to_value(native_graph()).unwrap();
        for view in [ToolView::Summary, ToolView::Code, ToolView::Full] {
            assert_eq!(
                project_function_graph(small.clone(), view, 0).unwrap(),
                project_tool_view(small.clone(), ToolViewKind::FunctionGraph, view).unwrap()
            );
        }
        assert!(project_function_graph(graph, ToolView::Full, 0).is_err());
    }

    /// Benchmark v2: function_summary on Hugo's `images.DecodeImageConfig` (94 blocks, 747 instructions, long Go
    /// names) exceeded the 60000-byte budget in both summary and code views in every scale-callees run. A summary
    /// as large is fitted: whole pages of blocks, references and callees with next offsets, never a refusal.
    #[test]
    fn oversized_function_summaries_are_paged_not_refused() {
        let name = |index: usize| format!("github.com/gohugoio/hugo/resources/images.(*Decoder).callee_{index:04}");
        let mut graph = native_graph();
        graph.blocks = (0..120u64)
            .map(|block| crate::GraphBlock {
                start: 0x1000 + block * 0x100,
                lines: (0..8u64)
                    .map(|line| {
                        let address = 0x1000 + block * 0x100 + line * 4;
                        let mut call = native_line(address, Flow::Call(0x9000 + block * 8 + line));
                        call.comment = Some(name((block * 8 + line) as usize));
                        call
                    })
                    .collect(),
            })
            .collect();
        graph.edges = (0..119).map(|from| crate::Edge { from, to: from + 1, kind: crate::EdgeKind::Taken }).collect();
        let items: Vec<crate::XrefRow> = (0..960u64)
            .map(|index| crate::XrefRow {
                from: 0x1000 + index * 4,
                to: 0x9000 + index,
                kind: rampage_analysis::discover::XrefKind::Call,
                from_function: Some("github.com/gohugoio/hugo/resources/images.DecodeImageConfig".into()),
                to_name: Some(name(index as usize)),
            })
            .collect();
        let mut summary: Value = native_function_summary();
        summary["graph"] = serde_json::to_value(graph).unwrap();
        summary["references"] = json!({ "total": 960, "offset": 0, "items": items });
        for view in [ToolView::Summary, ToolView::Code] {
            assert!(project_tool_view(summary.clone(), ToolViewKind::FunctionSummary, view).is_err());
            let mut pages = SummaryPages::default();
            let (mut blocks, mut references, mut callees) = (0, 0, 0);
            loop {
                let page = project_function_summary(summary.clone(), view, pages).unwrap();
                assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_TOOL_VIEW_BYTES);
                assert_eq!(page["graph"]["blocks_offset"], json!(pages.block_offset));
                let page_blocks = page["graph"]["blocks"].as_array().unwrap().len();
                // A page carries exactly the edges leaving its blocks, by whole-function index.
                let edges: Vec<u64> = page["graph"]["edges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|edge| edge["from"].as_u64().unwrap())
                    .collect();
                let first = pages.block_offset.min(120) as u64;
                let expected: Vec<u64> = (first..first + page_blocks as u64).filter(|from| *from < 119).collect();
                assert_eq!(edges, expected, "{view:?}");
                blocks += page_blocks;
                references += page["references"]["items"].as_array().unwrap().len();
                callees += page["callees"].as_array().unwrap().len();
                if let Some(callee) = page["callees"].get(0) {
                    assert_eq!(callee["calls"], 1, "{view:?}");
                }
                let next = |value: &Value| value.as_u64().map(|next| next as usize);
                let (block, reference, callee) = (
                    next(&page["graph"]["blocks_next_offset"]),
                    next(&page["references"]["items_next_offset"]),
                    next(&page["callees_next_offset"]),
                );
                if block.is_none() && reference.is_none() && callee.is_none() {
                    break;
                }
                pages = SummaryPages {
                    block_offset: block.unwrap_or(120),
                    reference_offset: reference.unwrap_or(960),
                    callee_offset: callee.unwrap_or(960),
                };
            }
            assert_eq!((blocks, references, callees), (120, 960, 960), "{view:?}");
        }
        // A summary that fits is unchanged apart from its callee list.
        let small = project_function_summary(native_function_summary(), ToolView::Summary, SummaryPages::default());
        let small = small.unwrap();
        assert_eq!(small["callees"], json!([]));
        assert!(small.get("fitted").is_none());
        // Exactly the shared projection plus callees, with the references page offset named items_offset.
        for view in [ToolView::Summary, ToolView::Code] {
            let mut expected =
                project_tool_view(native_function_summary(), ToolViewKind::FunctionSummary, view).unwrap();
            expected["callees"] = json!([]);
            let references = expected["references"].as_object_mut().unwrap();
            let offset = references.remove("offset").unwrap();
            references.insert("items_offset".into(), offset);
            let actual = project_function_summary(native_function_summary(), view, SummaryPages::default());
            assert_eq!(actual.unwrap(), expected, "{view:?}");
        }
    }

    #[test]
    fn full_preserves_complete_json_values_for_every_kind() {
        let values = [native_decompilation(), native_function_summary(), json!([null]), json!({"future": "λ"})];
        for kind in [
            ToolViewKind::Decompile,
            ToolViewKind::FunctionSummary,
            ToolViewKind::Disassemble,
            ToolViewKind::FunctionGraph,
            ToolViewKind::BinaryInfo,
            ToolViewKind::InspectData,
        ] {
            for value in &values {
                assert_eq!(project_tool_view(value.clone(), kind, ToolView::Full).unwrap(), *value);
            }
        }
    }

    #[test]
    fn native_c_view_retains_exact_code_variables_context_diagnostics_and_specification() {
        let mut original = native_decompilation();
        original["tokens"][0]["text"] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES));
        original["structure"]["future_native_evidence"] = json!({"source_coordinate": "native_space"});
        let result = project_tool_view(original.clone(), ToolViewKind::Decompile, ToolView::Code).unwrap();
        for key in ["address", "name", "code", "variables", "context", "recovery_status", "language_id"] {
            assert_eq!(result[key], original[key], "{key}");
        }
        assert_eq!(result["diagnostics"], original["structure"]["diagnostics"]);
        assert_eq!(
            result["structure_metadata"]["future_native_evidence"],
            original["structure"]["future_native_evidence"]
        );
        assert_eq!(result["structure_metadata"]["provenance"], "engine_recovered");
        assert_eq!(result["structure_metadata"]["frame_context"], original["structure"]["frame_context"]);
        assert_eq!(result["view_projection"]["code_kind"], "native_recovered_c");
        assert!(result.get("tokens").is_none());
        assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_TOOL_VIEW_BYTES);
    }

    #[test]
    fn reduced_native_c_keeps_raw_storage_widths_join_pieces_and_missing_mapping_evidence() {
        let mut original = native_decompilation();
        original["structure"]["variables"][0]["storage"][0]["future_coordinate_evidence"] =
            json!({"backing_status": "unavailable", "source_coordinate": "native_stack_space"});
        assert!(original["variables"][0]["storage"].get("address_size_bytes").is_none());
        assert!(original["variables"][2]["storage"].is_null());
        for view in [ToolView::Code, ToolView::Summary] {
            let result = project_tool_view(original.clone(), ToolViewKind::Decompile, view).unwrap();
            let variables = &result["structure_metadata"]["variables"];
            assert_eq!(*variables, original["structure"]["variables"]);
            assert_eq!(variables[0]["storage"][0]["address_size_bytes"], 4);
            assert_eq!(variables[0]["storage"][0]["address"], "0xfffffffc");
            assert_eq!(variables[0]["storage"][0]["use_ranges"][0]["start"], "0x1000");
            assert_eq!(variables[1]["storage"][0]["address_size_bytes"], 8);
            assert_eq!(variables[2]["storage"][0]["pieces"][0]["address_size_bytes"], 8);
            assert_eq!(variables[2]["storage"][0]["pieces"][1]["address_size_bytes"], 4);
            assert_eq!(variables[3]["storage"], json!([]));
            assert_eq!(result["variables"], original["variables"]);
        }
    }

    #[test]
    fn summary_uses_utf8_bytes_without_trimming_whitespace_or_claiming_semantics() {
        for code in ["", " \n\t ", "λ\n界"] {
            let mut original = native_decompilation();
            original["code"] = json!(code);
            let result = project_tool_view(original.clone(), ToolViewKind::Decompile, ToolView::Summary).unwrap();
            assert!(result.get("code").is_none());
            assert_eq!(result["code_utf8_bytes"], code.len());
            assert_eq!(result["variables"], original["variables"]);
            assert_eq!(result["recovery_status"], "incomplete");
            assert_eq!(result["diagnostics"]["unresolved_indirect_jumps"], 2);
            assert!(
                result["view_projection"]["omissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|receipt| { receipt["path"] == "/code" && receipt["utf8_bytes"] == code.len() })
            );
        }
    }

    #[test]
    fn native_listing_code_is_unchanged_and_graph_code_keeps_all_instruction_evidence() {
        let original = serde_json::to_value(native_graph()).unwrap();
        let rows = original["blocks"][0]["lines"].clone();
        assert_eq!(project_tool_view(rows.clone(), ToolViewKind::Disassemble, ToolView::Code).unwrap(), rows);
        let result = project_tool_view(original.clone(), ToolViewKind::FunctionGraph, ToolView::Code).unwrap();
        assert_eq!(result["blocks"], original["blocks"]);
        assert_eq!(result["edges"], original["edges"]);
        assert_eq!(result["instructions_count"], 4);
        assert_eq!(result["blocks"][0]["lines"][0]["noreturn"], "listed");
    }

    #[test]
    fn native_graph_summary_counts_actual_flows_and_keeps_annotations_and_bounds() {
        let original = serde_json::to_value(native_graph()).unwrap();
        let result = project_tool_view(original.clone(), ToolViewKind::FunctionGraph, ToolView::Summary).unwrap();
        let summary = &result["blocks"][0]["instruction_summary"];
        assert_eq!(summary["instructions_count"], 4);
        assert_eq!(summary["first_address"], "0x1000");
        assert_eq!(summary["last_address"], "0x100c");
        for kind in ["call", "indirect_jump", "return", "invalid"] {
            assert_eq!(summary["flow_counts"][kind], 1, "{kind}");
        }
        let fact = &summary["control_and_annotation_facts"][0];
        for key in ["address", "flow", "label", "comment", "note", "noreturn", "operand_annotations"] {
            assert_eq!(fact[key], original["blocks"][0]["lines"][0][key], "{key}");
        }
        assert!(fact.get("text").is_none());
        assert!(fact.get("bytes").is_none());
        let rows = original["blocks"][0]["lines"].clone();
        let listing = project_tool_view(rows, ToolViewKind::Disassemble, ToolView::Summary).unwrap();
        assert_eq!(listing["flow_counts"], summary["flow_counts"]);
    }

    #[test]
    fn native_function_summary_does_not_confuse_partial_pseudocode_with_recovered_c() {
        let mut original = native_function_summary();
        original["structured_pseudocode"] = serde_json::to_value(rampage_analysis::pseudocode::Pseudocode {
            text: "  if (partial_condition) { indirect_call(x0); }\n".into(),
            structured: true,
            limitations: vec!["structuring does not complete missing semantics".into()],
        })
        .unwrap();
        for view in [ToolView::Code, ToolView::Summary] {
            let result = project_tool_view(original.clone(), ToolViewKind::FunctionSummary, view).unwrap();
            for key in ["dataflow", "validated_indirect_targets", "limitations", "lifted_instructions"] {
                assert_eq!(result[key], original[key], "{key}");
            }
            assert_eq!(result["ssa"]["blocks"], original["ssa"]["blocks"]);
            assert_eq!(result["references"]["total"], 25);
            assert_eq!(result["references"]["offset"], 3);
            assert_eq!(result["references"]["returned_count"], 0);
            assert_eq!(result["ir_count"], 1);
            assert_eq!(result["ir_complete_count"], 0);
            assert_eq!(result["pseudocode"]["limitations"], original["pseudocode"]["limitations"]);
            assert_eq!(result["pseudocode"]["code_kind"], "partial_structural_pseudocode_not_native_recovered_c");
            if view == ToolView::Code {
                assert_eq!(result["pseudocode"]["text"], original["pseudocode"]["text"]);
                assert_eq!(result["structured_pseudocode"]["text"], original["structured_pseudocode"]["text"]);
            } else {
                assert!(result["pseudocode"].get("text").is_none());
                assert!(result["structured_pseudocode"].get("text").is_none());
            }
            assert_eq!(
                result["structured_pseudocode"]["limitations"],
                original["structured_pseudocode"]["limitations"]
            );
        }
    }

    fn native_binary_info() -> Value {
        use rampage_loaders::snapshot::{SnapshotModule, SnapshotPlatform, SnapshotRegister, SnapshotTarget};
        let modules = [SnapshotModule {
            name: "owned_fixture".into(),
            path: "owned_fixture".into(),
            uuid: "fixture-uuid".into(),
            image_base: "0x1000".into(),
            runtime_base: "0x2000".into(),
        }];
        let registers = [SnapshotRegister { thread_id: "0x1".into(), name: "pc".into(), value: "0x2000".into() }];
        let target = SnapshotTarget { platform: SnapshotPlatform::Darwin, compiler: Some("default".into()) };
        let segments = [rampage_loaders::Segment {
            name: "code".into(),
            address: 0x1000,
            size: 4,
            file_offset: 0,
            file_size: 4,
            perms: Perms { read: true, execute: true, write: false },
        }];
        let sections = [rampage_loaders::Section {
            name: "code".into(),
            address: 0x1000,
            size: 4,
            kind: rampage_loaders::SectionKind::Code,
            file_offset: Some(0),
            file_size: 4,
        }];
        let summary = crate::Summary {
            format: Format::Snapshot,
            arch: Arch::Aarch64,
            slices: &[Arch::Aarch64],
            embedded: Some(rampage_loaders::Embedded { offset: 64, size: 128, file_size: 256, trailing: 64 }),
            entry: Some(0x1000),
            segments: &segments,
            sections: &sections,
            symbols: 1,
            imports: 2,
            exports: 3,
            function_starts: 4,
            warnings: &["partial capture".into()],
            provenance: Some("owned test capture"),
            snapshot_modules: &modules,
            snapshot_registers: &registers,
            snapshot_target: Some(&target),
            raw: None,
        };
        serde_json::to_value(summary).unwrap()
    }

    #[test]
    fn native_binary_summary_keeps_schema_identity_embedding_warnings_and_snapshot_target() {
        let original = native_binary_info();
        let result = project_tool_view(original.clone(), ToolViewKind::BinaryInfo, ToolView::Summary).unwrap();
        for key in ["format", "arch", "slices", "embedded", "entry", "warnings", "provenance", "snapshot_target"] {
            assert_eq!(result[key], original[key], "{key}");
        }
        assert_eq!(result["format"], "snapshot");
        for key in ["segments", "sections", "snapshot_modules", "snapshot_registers"] {
            assert!(result.get(key).is_none(), "{key}");
            assert_eq!(result[format!("{key}_count")], 1);
        }
    }

    fn native_data_inspection() -> Value {
        let inspection = crate::DataInspection {
            format: Format::MachO,
            arch: Arch::Aarch64,
            module_uuid: Some("owned-uuid".into()),
            selected_image_file_offset: Some(64),
            selected_image_size: 256,
            backing_metadata_checked: false,
            loader_diagnostics: crate::data::DataLoaderDiagnostics {
                warnings_total: 2,
                warnings_omitted: 1,
                truncated: true,
                warnings: vec![crate::data::DataLoaderWarning {
                    message: "missing backing".into(),
                    text_truncated: false,
                }],
            },
            pointer_targets_suppressed: true,
            address: 0x1000,
            size: 16,
            word_size: 8,
            data_big_endian: true,
            trailing_bytes: 0,
            spans: vec![
                crate::DataSpan {
                    address: 0x1000,
                    size: 8,
                    status: crate::DataStatus::Stored,
                    image_offset: Some(8),
                    file_offset: Some(72),
                    permissions: Some(Perms::default()),
                    hex: Some("0000000000000000".into()),
                    ascii: Some("........".into()),
                },
                crate::DataSpan {
                    address: 0x1008,
                    size: 8,
                    status: crate::DataStatus::Unavailable,
                    image_offset: Some(16),
                    file_offset: None,
                    permissions: None,
                    hex: None,
                    ascii: None,
                },
            ],
            words: vec![crate::DataWord {
                address: 0x1000,
                raw_value: None,
                interpretation: "unavailable",
                import: Some(crate::DataImport { name: "owned_name".into(), library: None }),
                candidate: None,
            }],
            limitations: vec!["metadata only; not execution evidence"],
        };
        serde_json::to_value(inspection).unwrap()
    }

    #[test]
    fn native_data_summary_preserves_backing_offsets_statuses_names_and_suppression_truth() {
        let original = native_data_inspection();
        let result = project_tool_view(original.clone(), ToolViewKind::InspectData, ToolView::Summary).unwrap();
        for key in [
            "format",
            "arch",
            "module_uuid",
            "selected_image_file_offset",
            "selected_image_size",
            "backing_metadata_checked",
            "loader_diagnostics",
            "pointer_targets_suppressed",
            "word_size",
            "data_big_endian",
            "trailing_bytes",
            "limitations",
            "words",
        ] {
            assert_eq!(result[key], original[key], "{key}");
        }
        assert_eq!(result["span_status_counts"]["stored"], 1);
        assert_eq!(result["span_status_counts"]["unavailable"], 1);
        assert_eq!(result["spans"][0]["file_offset"], 72);
        assert_eq!(result["spans"][1], original["spans"][1]);
        assert!(result["spans"][0].get("hex").is_none());
        assert_eq!(result["spans"][0]["hex_utf8_bytes"], 16);
    }

    #[test]
    fn missing_required_shapes_refuse_without_inventing_empty_results() {
        for kind in [
            ToolViewKind::Decompile,
            ToolViewKind::FunctionSummary,
            ToolViewKind::FunctionGraph,
            ToolViewKind::BinaryInfo,
            ToolViewKind::InspectData,
        ] {
            let error = project_tool_view(json!({}), kind, ToolView::Summary).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)));
            assert!(error.to_string().contains("native shape"));
        }
        let result = project_tool_view(json!([]), ToolViewKind::Disassemble, ToolView::Summary).unwrap();
        assert_eq!(result["instructions_count"], 0);
        assert_eq!(result["first_address"], Value::Null);
        assert_eq!(result["last_address"], Value::Null);
        let mut original = native_decompilation();
        original["code"] = json!("");
        original["structure"]["diagnostics"] = Value::Null;
        original["recovery_status"] = json!("unavailable");
        let result = project_tool_view(original, ToolViewKind::Decompile, ToolView::Code).unwrap();
        assert_eq!(result["diagnostics"], Value::Null);
        assert_eq!(result["recovery_status"], "unavailable");
    }

    #[test]
    fn malformed_required_native_payloads_refuse_before_reduced_projection() {
        let mut malformed_graph = serde_json::to_value(native_graph()).unwrap();
        malformed_graph["blocks"][0]["lines"] = json!("not an array");
        for view in [ToolView::Code, ToolView::Summary] {
            let error = project_tool_view(malformed_graph.clone(), ToolViewKind::FunctionGraph, view).unwrap_err();
            assert!(error.to_string().contains("native shape /blocks/0/lines"));
        }
        let mut missing_structure = native_decompilation();
        missing_structure.as_object_mut().unwrap().remove("structure");
        let mut malformed_tokens = native_decompilation();
        malformed_tokens["tokens"] = json!({"text": "not a token array"});
        let mut malformed_ir = native_function_summary();
        malformed_ir["ir"][0].as_object_mut().unwrap().remove("complete");
        let mut malformed_spans = native_data_inspection();
        malformed_spans["spans"] = json!("not an array");
        let mut malformed_segments = native_binary_info();
        malformed_segments["segments"][0]["size"] = json!("not a size");
        for (value, kind) in [
            (missing_structure, ToolViewKind::Decompile),
            (malformed_tokens, ToolViewKind::Decompile),
            (malformed_ir, ToolViewKind::FunctionSummary),
            (malformed_spans, ToolViewKind::InspectData),
            (malformed_segments, ToolViewKind::BinaryInfo),
        ] {
            let error = project_tool_view(value, kind, ToolView::Summary).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)));
            assert!(error.to_string().contains("native shape"));
        }
    }

    #[test]
    fn valid_empty_native_collections_and_absent_optional_fields_stay_distinct_from_missing_required_fields() {
        let mut decompilation = native_decompilation();
        decompilation.as_object_mut().unwrap().remove("context");
        for key in ["diagnostics", "frame_context"] {
            decompilation["structure"].as_object_mut().unwrap().remove(key);
        }
        for key in ["tokens", "variables"] {
            decompilation[key] = json!([]);
        }
        for key in ["variables", "blocks", "calls", "jump_tables"] {
            decompilation["structure"][key] = json!([]);
        }
        decompilation["recovery_status"] = json!("unavailable");
        let result = project_tool_view(decompilation, ToolViewKind::Decompile, ToolView::Code).unwrap();
        assert_eq!(result["tokens_count"], 0);
        assert_eq!(result["structure_metadata"]["variables"], json!([]));
        assert!(result.get("diagnostics").is_none());
        let mut summary = native_function_summary();
        for key in
            ["ssa", "dataflow", "pseudocode", "structured_pseudocode", "control", "structured_control", "type_evidence"]
        {
            summary.as_object_mut().unwrap().remove(key);
        }
        let result = project_tool_view(summary, ToolViewKind::FunctionSummary, ToolView::Summary).unwrap();
        assert!(result.get("ssa").is_none());
        assert!(result.get("pseudocode").is_none());
        let graph = serde_json::to_value(crate::FunctionGraph {
            address: 0x1000,
            name: "empty_native_fixture".into(),
            blocks: Vec::new(),
            edges: Vec::new(),
        })
        .unwrap();
        let result = project_tool_view(graph, ToolViewKind::FunctionGraph, ToolView::Summary).unwrap();
        assert_eq!(result["instructions_count"], 0);
        assert_eq!(result["blocks_count"], 0);
    }

    #[test]
    fn metadata_code_views_and_invalid_enum_values_refuse_explicitly() {
        for kind in [ToolViewKind::BinaryInfo, ToolViewKind::InspectData] {
            let error = project_tool_view(json!({}), kind, ToolView::Code).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)));
            assert!(error.to_string().contains("unsupported"));
            assert!(error.to_string().contains("view=summary"));
        }
        for text in ["\"compact\"", "\"CODE\"", "null", "3"] {
            assert!(serde_json::from_str::<ToolView>(text).is_err());
        }
    }

    #[test]
    fn byte_limit_is_inclusive_and_counts_utf8_and_json_escaping() {
        let overhead = serde_json::to_vec(&json!({"data": ""})).unwrap().len();
        let at_limit = json!({"data": "x".repeat(MAX_TOOL_VIEW_BYTES - overhead)});
        assert_eq!(serde_json::to_vec(&at_limit).unwrap().len(), MAX_TOOL_VIEW_BYTES);
        assert!(project_tool_view(at_limit, ToolViewKind::BinaryInfo, ToolView::Full).is_ok());
        for text in
            ["x".repeat(MAX_TOOL_VIEW_BYTES), "λ".repeat(MAX_TOOL_VIEW_BYTES / 2), "\"".repeat(MAX_TOOL_VIEW_BYTES / 2)]
        {
            let original = json!({"data": text});
            let error = project_tool_view(original, ToolViewKind::BinaryInfo, ToolView::Full).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)));
            assert!(error.to_string().contains("view=summary"));
            assert!(error.to_string().contains("no strings were truncated"));
        }
    }

    #[test]
    fn essential_summary_evidence_overflow_refuses_instead_of_hiding_warnings() {
        for key in ["diagnostics", "context", "variables", "native_variables", "future_evidence"] {
            let mut original = native_decompilation();
            match key {
                "diagnostics" => {
                    original["structure"]["diagnostics"]["future_evidence"] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES))
                }
                "context" => original["context"]["future_evidence"] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES)),
                "variables" => original["variables"][0]["name"] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES)),
                "native_variables" => {
                    original["structure"]["variables"][0]["name"] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES))
                }
                _ => original[key] = json!("λ".repeat(MAX_TOOL_VIEW_BYTES)),
            }
            let error = project_tool_view(original, ToolViewKind::Decompile, ToolView::Summary).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)));
            assert!(error.to_string().contains("essential evidence"));
        }
        let mut original = native_binary_info();
        original["warnings"] = json!(["x".repeat(MAX_TOOL_VIEW_BYTES)]);
        let error = project_tool_view(original, ToolViewKind::BinaryInfo, ToolView::Summary).unwrap_err();
        assert!(error.to_string().contains("essential evidence"));
    }

    #[test]
    fn oversized_code_refuses_but_summary_can_omit_the_complete_text_with_a_byte_receipt() {
        let mut original = native_decompilation();
        original["code"] = json!("界".repeat(MAX_TOOL_VIEW_BYTES));
        let error = project_tool_view(original.clone(), ToolViewKind::Decompile, ToolView::Code).unwrap_err();
        assert!(matches!(error, ApiError::Invalid(_)));
        assert!(error.to_string().contains("view=summary"));
        let summary = project_tool_view(original, ToolViewKind::Decompile, ToolView::Summary).unwrap();
        assert_eq!(summary["code_utf8_bytes"], MAX_TOOL_VIEW_BYTES * "界".len());
        assert!(summary.get("code").is_none());
    }

    #[test]
    fn summary_retains_unknown_flow_evidence_even_on_an_ordinary_next_instruction() {
        let mut line = serde_json::to_value(native_line(0x1000, Flow::Next)).unwrap();
        line["flow"]["future_conditional_evidence"] = json!({"status": "partial"});
        let result = project_tool_view(json!([line.clone()]), ToolViewKind::Disassemble, ToolView::Summary).unwrap();
        assert_eq!(result["control_and_annotation_facts"][0]["flow"], line["flow"]);
    }

    #[test]
    fn counting_writer_matches_escaped_unicode_json_and_stops_at_its_cap() {
        let value = json!({"text": "λ\n\"\\界\t\u{0000}", "rows": [1, true, null]});
        let mut exact = JsonByteCounter::new(None);
        serde_json::to_writer(&mut exact, &value).unwrap();
        assert_eq!(exact.bytes, serde_json::to_vec(&value).unwrap().len());
        let mut at_limit = JsonByteCounter::new(Some(exact.bytes));
        serde_json::to_writer(&mut at_limit, &value).unwrap();
        assert_eq!(at_limit.bytes, exact.bytes);
        assert!(!at_limit.exceeded);
        let mut capped = JsonByteCounter::new(Some(MAX_TOOL_VIEW_BYTES));
        let oversized = Value::String("\"".repeat(MAX_TOOL_VIEW_BYTES * 2));
        assert!(serde_json::to_writer(&mut capped, &oversized).is_err());
        assert!(capped.exceeded);
        assert!(capped.bytes <= MAX_TOOL_VIEW_BYTES);
        assert!(capped.write_all(b"more").is_err());
    }

    #[test]
    fn escaped_64_mib_token_omission_counts_exactly_without_serializing_into_an_output_buffer() {
        let mut original = native_decompilation();
        original["tokens"][0]["text"] = json!("");
        let empty_token_bytes = serde_json::to_vec(&original["tokens"]).unwrap().len();
        let text_bytes = 64 * 1024 * 1024;
        original["tokens"][0]["text"] = Value::String("\"".repeat(text_bytes));
        let result = project_tool_view(original, ToolViewKind::Decompile, ToolView::Code).unwrap();
        assert_eq!(result["tokens_count"], 1);
        let omissions = result["view_projection"]["omissions"].as_array().unwrap();
        let receipt = omissions.iter().find(|receipt| receipt["path"] == "/tokens").unwrap();
        assert_eq!(receipt["json_bytes"], empty_token_bytes + text_bytes * 2);
        assert!(result.get("tokens").is_none());
    }

    #[test]
    fn future_evidence_is_retained_and_reserved_field_collisions_do_not_overwrite_it() {
        let mut original = serde_json::to_value(native_graph()).unwrap();
        original["language_bits"] = json!(64);
        original["mode"] = json!("captured_native");
        original["blocks"][0]["lines"][1]["future_control_evidence"] = json!({"backing_status": "unavailable"});
        let result = project_tool_view(original.clone(), ToolViewKind::FunctionGraph, ToolView::Summary).unwrap();
        assert_eq!(result["language_bits"], original["language_bits"]);
        assert_eq!(result["mode"], original["mode"]);
        assert_eq!(
            result["blocks"][0]["instruction_summary"]["control_and_annotation_facts"][1]["future_control_evidence"],
            original["blocks"][0]["lines"][1]["future_control_evidence"]
        );
        original["instructions_count"] = json!("producer evidence, not a projection count");
        assert!(project_tool_view(original, ToolViewKind::FunctionGraph, ToolView::Summary).is_err());
        let mut original = native_decompilation();
        original["code_utf8_bytes"] = json!("future producer value");
        let result = project_tool_view(original.clone(), ToolViewKind::Decompile, ToolView::Summary).unwrap();
        assert_eq!(result["code"], original["code"]);
        assert_eq!(result["code_utf8_bytes"], original["code_utf8_bytes"]);
    }
}
