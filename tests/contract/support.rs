//! The stable-surface contract checks shared by the MCP and CLI tests (docs/stability.md). Each test builds the
//! live surface as JSON, compares it with a snapshot committed under `tests/contract/`, and classifies every
//! difference as additive (a new tool, command, optional argument, flag or result field; a widened type) or
//! breaking (anything removed or renamed, a new required argument, a narrowed type).
//!
//! - No difference: the test passes.
//! - Additive differences only: the test fails until the snapshot is updated with
//!   `RAMPAGE_UPDATE_CONTRACT=1 cargo nextest run --workspace -E 'test(/contract/)'`, which rewrites it.
//! - Any breaking difference: the test fails, and `RAMPAGE_UPDATE_CONTRACT=1` does not rewrite the snapshot. Keep
//!   the old name working (a deprecation alias) or, for a major release, record the break with
//!   `RAMPAGE_UPDATE_CONTRACT=breaking`.

// Each test crate includes this file and uses part of it.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

/// The environment variable that rewrites a snapshot: `1` for additive changes, `breaking` for any.
pub const UPDATE_VARIABLE: &str = "RAMPAGE_UPDATE_CONTRACT";

/// One difference between the committed snapshot and the live surface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    pub breaking: bool,
    pub text: String,
}

impl Change {
    pub fn additive(text: impl Into<String>) -> Self {
        Self { breaking: false, text: text.into() }
    }

    pub fn breaking(text: impl Into<String>) -> Self {
        Self { breaking: true, text: text.into() }
    }
}

/// The committed snapshot `name` under `tests/contract/`.
pub fn snapshot_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/contract").join(name)
}

/// Compares `live` with the committed snapshot `name` using `compare`, then passes, rewrites the snapshot (when
/// [`UPDATE_VARIABLE`] allows it) or fails naming every change and what to do about it.
pub fn check(name: &str, live: &Value, compare: impl Fn(&Value, &Value) -> Vec<Change>) {
    let path = snapshot_path(name);
    let committed = std::fs::read_to_string(&path)
        .ok()
        .map(|text| serde_json::from_str::<Value>(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display())));
    let mut changes = match &committed {
        Some(committed) => compare(committed, live),
        None => vec![Change::additive(format!("{name} has no committed snapshot yet"))],
    };
    if changes.is_empty() && committed.as_ref() != Some(live) {
        // Something the comparison does not classify (such as a tool moving to another group's ordering) changed.
        changes.push(Change::additive("the snapshot differs in detail the comparison does not classify"));
    }
    if changes.is_empty() {
        return;
    }
    changes.sort();
    changes.dedup();
    let breaking = changes.iter().any(|change| change.breaking);
    let mode = std::env::var(UPDATE_VARIABLE).unwrap_or_default();
    if mode == "breaking" || (mode == "1" && !breaking) {
        let text = serde_json::to_string_pretty(live).unwrap() + "\n";
        std::fs::write(&path, text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        return;
    }
    let listed: Vec<String> = changes
        .iter()
        .map(|change| format!("  {} {}", if change.breaking { "BREAKING" } else { "additive" }, change.text))
        .collect();
    let advice = if breaking {
        format!(
            "These changes break the stable surface (docs/stability.md). Keep the old name or shape working as a \
             deprecated alias, or, for a major release, bump the major version and record the break with \
             {UPDATE_VARIABLE}=breaking."
        )
    } else {
        format!(
            "These changes are additive. Record them in the snapshot with \
             {UPDATE_VARIABLE}=1 cargo nextest run --workspace -E 'test(/contract/)' and commit tests/contract/{name}."
        )
    };
    panic!("the stable surface in tests/contract/{name} changed:\n{}\n{advice}", listed.join("\n"));
}

/// An object's entries, or none.
fn entries(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// The strings of an array, or none.
fn strings(value: &Value) -> BTreeSet<String> {
    value.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect()
}

/// The JSON types an input schema accepts, as a sorted `|`-joined list (`string|null`), resolving `$ref`s against
/// `root` and flattening `anyOf`/`oneOf`. Enumerated strings are `string`; anything unrecognised is `any`.
pub fn schema_type(schema: &Value, root: &Value) -> String {
    fn collect(schema: &Value, root: &Value, depth: usize, out: &mut BTreeSet<String>) {
        if depth > 16 {
            out.insert("any".to_owned());
            return;
        }
        let Some(object) = schema.as_object() else {
            out.insert(if schema == &Value::Bool(false) { "never" } else { "any" }.to_owned());
            return;
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let target = reference.strip_prefix('#').map(|pointer| root.pointer(pointer)).unwrap_or_default();
            match target {
                Some(target) => collect(target, root, depth + 1, out),
                None => {
                    out.insert("any".to_owned());
                }
            }
            return;
        }
        let mut found = false;
        match object.get("type") {
            Some(Value::String(kind)) => {
                out.insert(kind.clone());
                found = true;
            }
            Some(Value::Array(kinds)) => {
                out.extend(kinds.iter().filter_map(Value::as_str).map(str::to_owned));
                found = true;
            }
            _ => {}
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(Value::Array(members)) = object.get(key) {
                for member in members {
                    collect(member, root, depth + 1, out);
                }
                found = true;
            }
        }
        if !found {
            if let Some(Value::Array(values)) = object.get("enum") {
                for value in values {
                    out.insert(json_type(value).to_owned());
                }
            } else if let Some(value) = object.get("const") {
                out.insert(json_type(value).to_owned());
            } else {
                out.insert("any".to_owned());
            }
        }
    }
    let mut types = BTreeSet::new();
    collect(schema, root, 0, &mut types);
    if types.contains("integer") && types.contains("number") {
        types.remove("integer");
    }
    if types.contains("any") {
        return "any".to_owned();
    }
    types.into_iter().collect::<Vec<_>>().join("|")
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Whether a value of type `new` accepts every value `old` did (the same type, or a wider union).
fn widens(old: &str, new: &str) -> bool {
    if new == "any" || old == new {
        return true;
    }
    let new: BTreeSet<&str> = new.split('|').collect();
    old.split('|').all(|kind| new.contains(kind) || (kind == "integer" && new.contains("number")))
}

/// An input schema's arguments: each name with its type and whether it is required.
pub fn arguments(schema: &Value) -> Value {
    arguments_in(schema, schema, 0)
}

/// [`arguments`] of an object schema inside `root`; an argument that is itself an object with properties (such as
/// the `raw` selector) lists its own arguments under `fields`.
fn arguments_in(schema: &Value, root: &Value, depth: usize) -> Value {
    let required = strings(&schema["required"]);
    let mut arguments = BTreeMap::new();
    for (name, property) in entries(&schema["properties"]) {
        let mut argument =
            serde_json::json!({ "type": schema_type(&property, root), "required": required.contains(&name) });
        let resolved = match property.get("$ref").and_then(Value::as_str) {
            Some(reference) => {
                reference.strip_prefix('#').and_then(|pointer| root.pointer(pointer)).unwrap_or(&property)
            }
            None => &property,
        };
        if depth < 4 && resolved["properties"].is_object() {
            argument["fields"] = arguments_in(resolved, root, depth + 1);
        }
        arguments.insert(name.clone(), argument);
    }
    serde_json::to_value(arguments).unwrap()
}

/// Compares two tool-schema snapshots: `{"tools": {name: {"group", "experimental"?, "arguments": {name: {"type",
/// "required"}}}}}`. Changes to a tool the old snapshot marks experimental are never breaking.
pub fn compare_tools(old: &Value, new: &Value) -> Vec<Change> {
    let (old_tools, new_tools) = (entries(&old["tools"]), entries(&new["tools"]));
    let mut changes = Vec::new();
    for (name, old_tool) in &old_tools {
        let mut tool_changes = Vec::new();
        match new_tools.get(name) {
            None => tool_changes.push(Change::breaking(format!("tool `{name}` was removed or renamed"))),
            Some(new_tool) => {
                if old_tool["group"] != new_tool["group"] {
                    tool_changes.push(Change::breaking(format!(
                        "tool `{name}` moved from group {} to {}",
                        old_tool["group"], new_tool["group"]
                    )));
                }
                tool_changes.extend(compare_arguments(
                    &format!("tool `{name}`"),
                    &old_tool["arguments"],
                    &new_tool["arguments"],
                ));
            }
        }
        // Experimental tools are pinned so that changes to them are seen, but they may change in any release.
        if old_tool["experimental"] == true {
            for change in &mut tool_changes {
                change.breaking = false;
                change.text.push_str(" (experimental)");
            }
        }
        changes.extend(tool_changes);
    }
    for (name, new_tool) in &new_tools {
        if !old_tools.contains_key(name) {
            let required: Vec<String> = entries(&new_tool["arguments"])
                .iter()
                .filter(|(_, argument)| argument["required"] == true)
                .map(|(name, _)| name.clone())
                .collect();
            changes.push(Change::additive(format!(
                "tool `{name}` was added (group {}, required: {})",
                new_tool["group"],
                required.join(", ")
            )));
        }
    }
    changes
}

/// Compares argument maps `{name: {"type", "required"}}` of one tool or command.
pub fn compare_arguments(owner: &str, old: &Value, new: &Value) -> Vec<Change> {
    let (old, new) = (entries(old), entries(new));
    let mut changes = Vec::new();
    for (name, old_argument) in &old {
        let Some(new_argument) = new.get(name) else {
            changes.push(Change::breaking(format!("{owner}: argument `{name}` was removed or renamed")));
            continue;
        };
        let (old_type, new_type) =
            (old_argument["type"].as_str().unwrap_or("any"), new_argument["type"].as_str().unwrap_or("any"));
        if !widens(old_type, new_type) {
            changes.push(Change::breaking(format!(
                "{owner}: argument `{name}` changed type from {old_type} to {new_type}"
            )));
        } else if old_type != new_type {
            changes.push(Change::additive(format!("{owner}: argument `{name}` widened from {old_type} to {new_type}")));
        }
        match (old_argument["required"] == true, new_argument["required"] == true) {
            (false, true) => changes.push(Change::breaking(format!("{owner}: argument `{name}` became required"))),
            (true, false) => changes.push(Change::additive(format!("{owner}: argument `{name}` became optional"))),
            _ => {}
        }
        match (old_argument["repeated"] == true, new_argument["repeated"] == true) {
            (true, false) => changes.push(Change::breaking(format!("{owner}: argument `{name}` no longer repeats"))),
            (false, true) => changes.push(Change::additive(format!("{owner}: argument `{name}` now repeats"))),
            _ => {}
        }
        match (old_argument.get("fields"), new_argument.get("fields")) {
            (Some(old_fields), Some(new_fields)) => {
                changes.extend(compare_arguments(&format!("{owner}: argument `{name}`"), old_fields, new_fields));
            }
            (None, Some(_)) => {
                changes.push(Change::additive(format!("{owner}: argument `{name}` now pins its fields")));
            }
            (Some(_), None) => {
                changes.push(Change::breaking(format!("{owner}: argument `{name}` no longer lists its fields")));
            }
            (None, None) => {}
        }
    }
    for (name, new_argument) in &new {
        if !old.contains_key(name) {
            if new_argument["required"] == true {
                changes.push(Change::breaking(format!("{owner}: new argument `{name}` is required")));
            } else {
                changes.push(Change::additive(format!("{owner}: optional argument `{name}` was added")));
            }
        }
    }
    changes
}

/// Every field path in a JSON result: object keys joined with `.`, array elements as `[]`. The values of
/// map-like objects (keys that are addresses, names or numbers rather than field names) collapse to `{*}`.
pub fn field_paths(value: &Value) -> BTreeSet<String> {
    fn data_key(key: &str) -> bool {
        key.is_empty()
            || key.starts_with("0x")
            || key.chars().next().is_some_and(|c| c.is_ascii_digit())
            || key.chars().any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
    }
    fn walk(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let segment = if data_key(key) { "{*}" } else { key.as_str() };
                    let path = if prefix.is_empty() { segment.to_owned() } else { format!("{prefix}.{segment}") };
                    out.insert(path.clone());
                    walk(value, &path, out);
                }
            }
            Value::Array(items) => {
                let path = format!("{prefix}[]");
                for item in items {
                    walk(item, &path, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    walk(value, "", &mut out);
    out
}

/// Compares observed result-field snapshots `{owner: [path, ...]}`: a path that is no longer observed is breaking,
/// a new one additive. An owner (tool or command) that is no longer exercised is breaking too.
pub fn compare_fields(old: &Value, new: &Value) -> Vec<Change> {
    let (old, new) = (entries(old), entries(new));
    let mut changes = Vec::new();
    for (owner, old_paths) in &old {
        let Some(new_paths) = new.get(owner) else {
            changes.push(Change::breaking(format!("`{owner}` is no longer exercised")));
            continue;
        };
        let (old_paths, new_paths) = (strings(old_paths), strings(new_paths));
        for path in old_paths.difference(&new_paths) {
            changes.push(Change::breaking(format!(
                "`{owner}`: result field `{path}` is gone (if it still exists but the fixture no longer produces it, \
                 make the fixture produce it again)"
            )));
        }
        for path in new_paths.difference(&old_paths) {
            changes.push(Change::additive(format!("`{owner}`: result field `{path}` was added")));
        }
    }
    for owner in new.keys().filter(|owner| !old.contains_key(*owner)) {
        changes.push(Change::additive(format!("`{owner}` is now exercised")));
    }
    changes
}

/// A field snapshot from observed results: `{owner: [path, ...]}`, sorted.
pub fn field_snapshot(observed: &BTreeMap<String, BTreeSet<String>>) -> Value {
    serde_json::to_value(observed).unwrap()
}

/// A small headerless image that produces every `file_layout` result field: a Cortex-M-like vector table,
/// ASCII and UTF-16LE strings, 0xff and 0x00 fill, and high-entropy bytes behind a header that a
/// compressed-component candidate checks: a load-address-like word, the payload length, a larger size and the
/// payload's 32-bit byte sum.
pub fn layout_fixture() -> Vec<u8> {
    let mut words = vec![0x2000_2000u32, 0x0000_0101, 0x0000_0141, 0x0000_0143];
    words.extend([0; 7]);
    words.extend([0x0000_0145, 0, 0, 0x0000_0147, 0x0000_0149]);
    let mut bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    for text in ["rampage layout fixture", "Version 1.0.0", "Copyright example"] {
        bytes.extend(text.as_bytes());
        bytes.push(0);
    }
    for text in ["Settings", "Network", "Password"] {
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0, 0]);
    }
    bytes.extend([0xff; 512]);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let sum = payload.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
    for word in [0x2000_0000, payload.len() as u32, 3 * payload.len() as u32, sum] {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend(payload);
    bytes.extend([0; 512]);
    bytes
}

#[cfg(test)]
mod classification {
    use serde_json::json;

    use super::*;

    #[test]
    fn contract_classifies_tool_changes() {
        let old = json!({"tools": {
            "a": {"group": "core", "arguments": {"path": {"type": "string", "required": true},
                                                  "limit": {"type": "integer|null", "required": false}}},
            "b": {"group": "core", "arguments": {}}
        }});
        assert!(compare_tools(&old, &old).is_empty());
        let mut new = old.clone();
        new["tools"]["c"] = json!({"group": "types", "arguments": {}});
        new["tools"]["a"]["arguments"]["extra"] = json!({"type": "boolean", "required": false});
        new["tools"]["a"]["arguments"]["limit"]["type"] = json!("integer|null|string");
        assert!(compare_tools(&old, &new).iter().all(|change| !change.breaking));

        let mut renamed = old.clone();
        renamed["tools"]["a"]["arguments"]["limit2"] = renamed["tools"]["a"]["arguments"]["limit"].take();
        renamed["tools"]["a"]["arguments"].as_object_mut().unwrap().remove("limit");
        assert!(compare_tools(&old, &renamed).iter().any(|change| change.breaking));

        let mut required = old.clone();
        required["tools"]["b"]["arguments"]["needed"] = json!({"type": "string", "required": true});
        assert!(compare_tools(&old, &required).iter().any(|change| change.breaking));

        let mut narrowed = old.clone();
        narrowed["tools"]["a"]["arguments"]["limit"]["type"] = json!("integer");
        assert!(compare_tools(&old, &narrowed).iter().any(|change| change.breaking));

        let mut removed = old.clone();
        removed["tools"].as_object_mut().unwrap().remove("b");
        assert!(compare_tools(&old, &removed).iter().any(|change| change.breaking));
    }

    #[test]
    fn contract_classifies_field_changes_and_collapses_data_keys() {
        let paths = field_paths(&json!({"items": [{"name": "x", "0x401000": 1}], "by_name": {"Main": 1}}));
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            ["by_name", "by_name.{*}", "items", "items[].name", "items[].{*}"]
        );
        let old = json!({"t": ["a", "b"]});
        assert!(compare_fields(&old, &json!({"t": ["a", "b", "c"]})).iter().all(|change| !change.breaking));
        assert!(compare_fields(&old, &json!({"t": ["a"]})).iter().any(|change| change.breaking));
    }
}
