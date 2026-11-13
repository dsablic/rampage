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

/// Repairs the argument mistakes of a caller working without the schema, before [`check_arguments`]: an unknown
/// name in [`ALIASES`] becomes its admitted argument when that one is not also given, and a string holding a
/// decimal or `0x` hex number becomes that number where the schema admits only numbers. Booleans stay strict:
/// they gate writes (`apply`, `force`).
pub fn normalize_arguments(schema: &Value, arguments: &mut Map<String, Value>) {
    if let Some(admitted) = admitted_arguments(schema) {
        for (alias, meant) in ALIASES {
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
            return Err(format!(
                "invalid arguments: unknown field{} {}; nothing was run.{}",
                if unknown.len() == 1 { "" } else { "s" },
                described.join(", "),
                listing()
            ));
        }
    }
    let missing: Vec<&str> =
        required.iter().copied().filter(|key| arguments.get(*key).is_none_or(Value::is_null)).collect();
    if !missing.is_empty() {
        let missing: Vec<String> = missing.iter().map(|key| format!("`{key}`")).collect();
        return Err(format!(
            "invalid arguments: missing field{} {}; nothing was run.{}",
            if missing.len() == 1 { "" } else { "s" },
            missing.join(", "),
            listing()
        ));
    }
    Ok(())
}
