//! Argument checks shared by every client that dispatches the model-facing tools (MCP, the agent and the UI
//! assistant): arguments a tool's schema does not list, and missing required ones, are refused before anything
//! runs, with a one-line error naming the tool's arguments.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::Tool;

/// Unknown argument names listed in one error; the rest are counted.
const MAX_LISTED_UNKNOWN: usize = 8;
/// Characters of one unknown argument name shown in an error.
const MAX_NAME_CHARS: usize = 64;

fn shorten(name: &str) -> String {
    match name.char_indices().nth(MAX_NAME_CHARS) {
        Some((cut, _)) => format!("{}...", &name[..cut]),
        None => name.to_owned(),
    }
}

/// Checks `input` against the schema of the tool `name` among `tools`, as the agent and UI assistant send it.
/// An unknown tool or a non-object input is left to dispatch, which refuses it.
pub fn check_tool_arguments(tools: &[Tool], name: &str, input: &Value) -> Result<(), String> {
    match (tools.iter().find(|tool| tool.name == name), input.as_object()) {
        (Some(tool), Some(arguments)) => check_arguments(name, &tool.input_schema, arguments),
        _ => Ok(()),
    }
}

/// The top-level argument names `schema` admits, or `None` when it admits arbitrary names (an open object, or a
/// union member without listed properties).
pub fn admitted_arguments(schema: &Value) -> Option<BTreeSet<String>> {
    fn collect(schema: &Value, root: &Value, names: &mut BTreeSet<String>, depth: usize) -> Option<()> {
        let object = schema.as_object()?;
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let target = reference.strip_prefix("#/")?.split('/').try_fold(root, |at, key| at.get(key))?;
            return collect(target, root, names, depth.checked_sub(1)?);
        }
        if object.get("additionalProperties").is_some_and(|value| *value != Value::Bool(false))
            || object.contains_key("patternProperties")
        {
            return None;
        }
        let properties = object.get("properties").and_then(Value::as_object);
        names.extend(properties.into_iter().flat_map(|properties| properties.keys().cloned()));
        let mut unions = false;
        for key in ["oneOf", "anyOf", "allOf"] {
            for member in object.get(key).and_then(Value::as_array).into_iter().flatten() {
                unions = true;
                // A `null` or plain-typed member adds no names.
                if member.get("type").and_then(Value::as_str).is_some_and(|kind| kind != "object") {
                    continue;
                }
                collect(member, root, names, depth.checked_sub(1)?)?;
            }
        }
        (properties.is_some() || unions).then_some(())
    }
    let mut names = BTreeSet::new();
    collect(schema, schema, &mut names, 8)?;
    Some(names)
}

/// Unknown argument names that can only mean one admitted argument, so they are taken as that argument instead of
/// costing the caller a refused call (agents often call before the schema is loaded).
const ALIASES: [(&str, &str); 9] = [
    ("address", "at"),
    ("addr", "at"),
    ("ea", "at"),
    ("length", "size"),
    ("len", "size"),
    ("file", "path"),
    ("file_path", "path"),
    ("filename", "path"),
    ("binary", "path"),
];

/// Unknown argument names that mean one admitted argument of one tool only: (tool, alias, admitted argument).
const TOOL_ALIASES: [(&str, &str, &str); 4] = [
    // References to a target; `from` lists the references a function makes.
    ("xrefs", "target", "to"),
    // A count of bytes, or of words when word_size is given (see [`normalize_arguments`]).
    ("inspect_data", "count", "size"),
    // `peripheral` takes a name or any address inside the peripheral.
    ("peripheral_access", "at", "peripheral"),
    // The function's arguments.
    ("evaluate_function", "arguments", "args"),
];

/// Repairs the argument mistakes of a caller working without the schema, before [`check_arguments`]: an unknown
/// name in [`ALIASES`], or in [`TOOL_ALIASES`] for the tool `name`, becomes its admitted argument when that one is
/// not also given, and a string holding a decimal or `0x` hex number becomes that number where the schema admits
/// only numbers, and a string holding a JSON list becomes that list where the schema admits only lists. Booleans
/// stay strict: they gate writes (`apply`, `force`). Aliases add nothing to the schema.
/// inspect_data's `count` counts words of `word_size` bytes when that is a width it reads (4 or 8), bytes otherwise.
pub fn normalize_arguments(name: &str, schema: &Value, arguments: &mut Map<String, Value>) {
    let words = name == "inspect_data" && arguments.contains_key("count") && !arguments.contains_key("size");
    if let Some(admitted) = admitted_arguments(schema) {
        let tool_aliases =
            TOOL_ALIASES.iter().filter(|(tool, ..)| *tool == name).map(|&(_, alias, meant)| (alias, meant));
        for (alias, meant) in ALIASES.into_iter().chain(tool_aliases) {
            if !admitted.contains(alias)
                && admitted.contains(meant)
                && !arguments.contains_key(meant)
                && let Some(value) = arguments.remove(alias)
            {
                arguments.insert(meant.to_owned(), value);
            }
        }
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else { return };
    for (key, value) in arguments.iter_mut() {
        let Some(text) = value.as_str() else { continue };
        let types: Vec<&str> = match properties.get(key).and_then(|property| property.get("type")) {
            Some(Value::String(kind)) => vec![kind.as_str()],
            Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => continue,
        };
        if types.contains(&"string") {
            continue;
        }
        // A list sent as the JSON text of one, as some clients send nested arguments.
        if types.contains(&"array") {
            if let Ok(list @ Value::Array(_)) = serde_json::from_str::<Value>(text) {
                *value = list;
            }
            continue;
        }
        if !types.contains(&"integer") && !types.contains(&"number") {
            continue;
        }
        let text = text.trim().trim_matches('"').trim();
        let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16).ok().map(Value::from),
            None => text.parse::<u64>().map(Value::from).or_else(|_| text.parse::<i64>().map(Value::from)).ok(),
        };
        if let Some(number) = parsed {
            *value = number;
        }
    }
    if words
        && let Some(word_size) =
            arguments.get("word_size").and_then(Value::as_u64).filter(|width| matches!(width, 4 | 8))
        && let Some(count) = arguments.get("size").and_then(Value::as_u64)
    {
        arguments.insert("size".to_owned(), Value::from(count.saturating_mul(word_size)));
    }
}

/// The admitted argument an unknown `name` most likely meant, from the names agents reach for out of habit.
fn likely_argument(name: &str, admitted: &BTreeSet<String>) -> Option<&'static str> {
    let candidates: &[&'static str] = match name.to_ascii_lowercase().as_str() {
        // xrefs takes `to` (references to an address) and `from`; `to` is what an address argument usually means.
        "address" | "addr" | "ea" | "va" | "location" | "function" | "func" | "start" | "name" | "target" | "at" => {
            &["at", "address", "target", "to"]
        }
        "length" | "len" | "count" | "size" | "bytes" | "n" | "num" | "number" | "max" => {
            &["size", "count", "length", "limit"]
        }
        "query" | "pattern" | "text" | "string" | "needle" | "search" | "filter" | "contains" => {
            &["contains", "name_contains", "mode", "pattern", "query"]
        }
        "file" | "binary" | "filename" | "file_path" => &["path"],
        "skip" | "page" | "start_index" => &["offset"],
        "language" | "language_id" | "processor" | "profile" | "arch" => &["profile", "arch"],
        _ => &[],
    };
    candidates.iter().copied().find(|candidate| *candidate != name && admitted.contains(*candidate))
}

/// Refuses arguments `schema` does not admit and missing required ones, naming the tool's arguments in one line so
/// a caller without the schema can correct the call. A `raw` selector the tool does not list is left to its own
/// refusal.
pub fn check_arguments(name: &str, schema: &Value, arguments: &Map<String, Value>) -> Result<(), String> {
    let listed = |key: &str| schema.get("properties").and_then(|properties| properties.get(key)).is_some();
    if arguments.get("raw").is_some_and(|raw| !raw.is_null()) && !listed("raw") {
        return Ok(());
    }
    let required: Vec<&str> =
        schema.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    let admitted = admitted_arguments(schema);
    let listing = || {
        let Some(admitted) = &admitted else { return String::new() };
        let names: Vec<String> = admitted
            .iter()
            .map(|argument| {
                if required.contains(&argument.as_str()) {
                    format!("`{argument}` (required)")
                } else {
                    format!("`{argument}`")
                }
            })
            .collect();
        format!(" Arguments of {name}: {}.", names.join(", "))
    };
    if let Some(admitted) = &admitted {
        let unknown: Vec<&String> =
            arguments.keys().filter(|key| key.as_str() != "raw" && !admitted.contains(key.as_str())).collect();
        if !unknown.is_empty() {
            let mut described: Vec<String> = unknown
                .iter()
                .take(MAX_LISTED_UNKNOWN)
                .map(|key| match likely_argument(key, admitted) {
                    Some(meant) => format!("`{}` (did you mean `{meant}`?)", shorten(key)),
                    None => format!("`{}`", shorten(key)),
                })
                .collect();
            if unknown.len() > MAX_LISTED_UNKNOWN {
                described.push(format!("and {} more", unknown.len() - MAX_LISTED_UNKNOWN));
            }
            let hints: String =
                unknown.iter().filter_map(|key| unknown_hint(name, key)).map(|hint| format!(" {hint}")).collect();
            return Err(format!(
                "invalid arguments: unknown field{} {}; nothing was run.{hints}{}",
                if unknown.len() == 1 { "" } else { "s" },
                described.join(", "),
                listing()
            ));
        }
    }
    let missing: Vec<&str> =
        required.iter().copied().filter(|key| arguments.get(*key).is_none_or(Value::is_null)).collect();
    if !missing.is_empty() {
        let hint = missing_hint(name, &missing, arguments).map(|hint| format!(" {hint}")).unwrap_or_default();
        let missing: Vec<String> = missing.iter().map(|key| format!("`{key}`")).collect();
        return Err(format!(
            "invalid arguments: missing field{} {}; nothing was run.{hint}{}",
            if missing.len() == 1 { "" } else { "s" },
            missing.join(", "),
            listing()
        ));
    }
    Ok(())
}

/// The call an unknown argument of the tool `name` shows the caller meant, where that is another tool or an
/// argument this tool does not have.
fn unknown_hint(name: &str, argument: &str) -> Option<&'static str> {
    Some(match (name, argument) {
        ("peripheral_access", "svd") => {
            "peripheral_access reads the peripherals import_svd stored: run import_svd with svd=<the .svd file> and \
             apply=true on the same path (and raw) first, then peripheral_access with peripheral=<name or address>."
        }
        ("class_evidence", "class_name" | "class" | "name") => {
            "class_evidence has no class filter: it lists every class, paged with rtti_class_offset/rtti_class_limit \
             and vftable_offset/vftable_limit; find the class in its rtti_classes and vftables."
        }
        _ => return None,
    })
}

/// What a call to the tool `name` missing `missing` arguments most likely meant.
fn missing_hint(name: &str, missing: &[&str], arguments: &Map<String, Value>) -> Option<&'static str> {
    let path = arguments.get("path").and_then(Value::as_str).unwrap_or_default();
    (name == "import_svd" && missing.contains(&"svd") && path.to_ascii_lowercase().ends_with(".svd")).then_some(
        "`path` is the firmware image the map applies to and `svd` the .svd file: import_svd with path=<image> \
         svd=<the .svd file>.",
    )
}
