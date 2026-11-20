//! `diff_firmware`: what changed between two update files for one device. Each side is taken apart into components
//! (the executable itself, a compressed stream's decoded image, an ESP partition, a filesystem image or a directory
//! tree, an embedded image), components are paired across the versions, and each pair is compared at the level it
//! supports: digests and container facts for data, files by path and content hash for filesystems (with changed
//! files taken apart again), and for code the function matching of `transfer_annotations` with the strings, version
//! identifiers, endpoints, lock mechanisms, integrity checks and capture sources that were added or removed.
//!
//! Everything is budgeted (time, code images analysed, bytes read) and what was not compared is listed with the
//! reason. Results are deterministic: components, files and functions are reported in a fixed order.
//! Design: docs/plans/2026-11-20-firmware-diffing.md.

mod code;
mod inputs;
mod matching;
mod tree;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::Packs;
pub use inputs::SideInput;
pub(crate) use inputs::{Component, Opener};

/// Default and largest time budget of one call.
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
/// Default and largest number of changed code-image pairs analysed per call.
const DEFAULT_MAX_IMAGES: usize = 8;
const MAX_IMAGES: usize = 64;
/// Bytes read from the inputs for hashing, decoding and taking images apart, per call.
const DEFAULT_MAX_BYTES: u64 = 2 << 30;
/// Rows each list holds in the summary, and at most per page.
const SUMMARY_ROWS: usize = 20;
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;
/// JSON bytes a result may take; lists are halved until it fits.
const RESULT_BYTES: usize = 56_000;
/// Filesystem nesting levels taken apart below the inputs (an image file inside an image).
const MAX_TREE_DEPTH: usize = 3;

/// What `diff_firmware` compares and how much of it to return.
#[derive(Debug, Clone, Default)]
pub struct FirmwareDiffQuery {
    /// The older version.
    pub old: SideInput,
    /// The newer version: "added" means only here.
    pub new: SideInput,
    /// One component pair (an `id` of a previous result) to return in full, page or diff a function of.
    pub component: Option<String>,
    /// With `component`: `changed`, `added`, `removed` or `unchanged` functions, `strings`, `files` or `endpoints`.
    pub list: Option<String>,
    /// With `component`: one function (old address or name, or `new:` and a new address or name) to diff.
    pub function: Option<String>,
    pub offset: usize,
    pub limit: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub max_images: Option<usize>,
    /// Bytes read from the inputs (hashing, decoding, taking images apart); default 2 GiB.
    pub max_bytes: Option<u64>,
}

/// The work one call may still do, and what it did.
pub(crate) struct Budget {
    started: Instant,
    deadline: Instant,
    pub(crate) images_left: usize,
    pub(crate) bytes_left: u64,
    pub(crate) images_diffed: usize,
    pub(crate) images_skipped: usize,
    pub(crate) bytes_read: u64,
    pub(crate) files_hashed: usize,
    pub(crate) functions_matched: usize,
    /// Why work stopped early: `time`, `images` or `bytes`.
    pub(crate) stopped: Option<&'static str>,
    pub(crate) packs: Arc<Packs>,
    /// Raw projects of this call; dropped with it.
    pub(crate) session: crate::Session,
}

impl Budget {
    fn new(timeout_ms: u64, max_images: usize, max_bytes: u64, packs: Arc<Packs>) -> Self {
        let started = Instant::now();
        Self {
            started,
            deadline: started + Duration::from_millis(timeout_ms),
            images_left: max_images,
            bytes_left: max_bytes,
            images_diffed: 0,
            images_skipped: 0,
            bytes_read: 0,
            files_hashed: 0,
            functions_matched: 0,
            stopped: None,
            session: crate::Session::default().with_packs(Arc::clone(&packs)),
            packs,
        }
    }

    /// Whether time is left; records the stop the first time it is not.
    pub(crate) fn time_left(&mut self) -> bool {
        if Instant::now() < self.deadline {
            return true;
        }
        self.stopped.get_or_insert("time");
        false
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Charges `count` bytes read; false (and a recorded stop) when the byte budget cannot cover them.
    pub(crate) fn charge(&mut self, count: u64) -> bool {
        if count > self.bytes_left {
            self.stopped.get_or_insert("bytes");
            return false;
        }
        self.bytes_left -= count;
        self.bytes_read += count;
        true
    }

    /// Takes one image analysis from the budget; false (and a recorded stop) when none or no time is left.
    pub(crate) fn take_image(&mut self) -> bool {
        if !self.time_left() {
            self.images_skipped += 1;
            return false;
        }
        if self.images_left == 0 {
            self.stopped.get_or_insert("images");
            self.images_skipped += 1;
            return false;
        }
        self.images_left -= 1;
        self.images_diffed += 1;
        true
    }

    fn report(&self, max_images: usize, timeout_ms: u64) -> Value {
        json!({
            "elapsed_ms": self.started.elapsed().as_millis() as u64,
            "timeout_ms": timeout_ms,
            "images_diffed": self.images_diffed,
            "images_skipped": self.images_skipped,
            "max_images": max_images,
            "bytes_read": self.bytes_read,
            "files_hashed": self.files_hashed,
            "functions_matched": self.functions_matched,
            "stopped": self.stopped,
        })
    }
}

/// A private directory for one call's materialised files, removed when dropped.
pub(crate) struct Scratch {
    root: PathBuf,
    next: u64,
}

impl Scratch {
    pub(crate) fn new() -> Result<Self, String> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let root = std::env::temp_dir().join(format!("rampage-diff-{}-{unique}-{nanos}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&root).map_err(|error| format!("create a scratch directory: {error}"))?;
        Ok(Self { root, next: 0 })
    }

    /// A new file path in the scratch directory that keeps `name`'s last component (sanitised), so tools that look
    /// at extensions still see them.
    pub(crate) fn file(&mut self, name: &str) -> PathBuf {
        self.next += 1;
        let base = name.rsplit('/').next().unwrap_or_default();
        let clean: String = base
            .chars()
            .take(64)
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
            .collect();
        self.root.join(format!("{}-{clean}", self.next))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Something one side has and the other lacks, or a pair that differs, as rows with totals.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub(crate) struct Delta {
    pub(crate) added_total: usize,
    pub(crate) removed_total: usize,
    pub(crate) added: Vec<Value>,
    pub(crate) removed: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) changed_total: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) changed: Vec<Value>,
}

impl Delta {
    pub(crate) fn of(added: Vec<Value>, removed: Vec<Value>) -> Self {
        Self { added_total: added.len(), removed_total: removed.len(), added, removed, ..Self::default() }
    }

    pub(crate) fn with_changed(mut self, changed: Vec<Value>) -> Self {
        self.changed_total = Some(changed.len());
        self.changed = changed;
        self
    }
}

/// One compared component pair.
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct ComponentDiff {
    pub(crate) id: String,
    /// `unchanged`, `changed`, `added`, `removed` or `not_compared`.
    pub(crate) status: &'static str,
    pub(crate) role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) old: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) new: Option<Value>,
    /// Container-level facts that differ, as `field: old -> new`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) changes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) files: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) android: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) notes: Vec<String>,
}

/// What was left out, and why.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Skipped {
    pub(crate) what: String,
    pub(crate) why: String,
}

/// The state of one call: the budget, scratch space, and everything found so far.
pub(crate) struct Run {
    pub(crate) budget: Budget,
    pub(crate) scratch: Scratch,
    pub(crate) components: Vec<ComponentDiff>,
    pub(crate) not_compared: Vec<Skipped>,
    /// Rows per list kept in the result.
    pub(crate) rows: usize,
}

impl Run {
    pub(crate) fn skip(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.not_compared.push(Skipped { what: what.into(), why: why.into() });
    }
}

fn clamp_limit(limit: Option<usize>) -> Result<usize, String> {
    let limit = limit.unwrap_or(DEFAULT_PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_PAGE}"));
    }
    Ok(limit)
}

/// Compares two firmware update files (or directories, filesystem images, executables): see the module docs.
pub fn diff_firmware(query: &FirmwareDiffQuery, packs: Arc<Packs>) -> Result<Value, String> {
    let timeout_ms = query.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(format!("timeout_ms must be in 1..={MAX_TIMEOUT_MS}"));
    }
    let max_images = query.max_images.unwrap_or(DEFAULT_MAX_IMAGES);
    if max_images > MAX_IMAGES {
        return Err(format!("max_images must be in 0..={MAX_IMAGES}"));
    }
    if query.component.is_none() && (query.list.is_some() || query.function.is_some()) {
        return Err("`list` and `function` need `component` (an id from a previous diff_firmware result)".to_owned());
    }
    if query.list.is_some() && query.function.is_some() {
        return Err("give `list` or `function`, not both".to_owned());
    }
    let limit = clamp_limit(query.limit)?;
    for side in [&query.old, &query.new] {
        side.validate()?;
    }
    let mut run = Run {
        budget: Budget::new(timeout_ms, max_images, query.max_bytes.unwrap_or(DEFAULT_MAX_BYTES), packs),
        scratch: Scratch::new()?,
        components: Vec::new(),
        not_compared: Vec::new(),
        rows: if query.component.is_some() { limit.max(SUMMARY_ROWS) } else { SUMMARY_ROWS },
    };
    let (old_layout, new_layout) = inputs::layouts(&query.old, &query.new, &mut run)?;
    let mut output = Map::new();
    output.insert("old".to_owned(), old_layout.summary());
    output.insert("new".to_owned(), new_layout.summary());
    let identical =
        old_layout.digest.is_some() && old_layout.digest == new_layout.digest && query.old.same_selection(&query.new);

    if let Some(id) = &query.component {
        let value = drill_down(query, id, old_layout, new_layout, &mut run, limit)?;
        output.extend(value);
        output.insert("budget".to_owned(), run.budget.report(max_images, timeout_ms));
        return Ok(fitted(Value::Object(output)));
    }

    if identical {
        output.insert("identical".to_owned(), json!(true));
        output.insert(
            "summary".to_owned(),
            json!(["The two inputs are byte-identical (same SHA-256): nothing changed."]),
        );
        output.insert("components".to_owned(), json!([]));
        output.insert("not_compared".to_owned(), json!([]));
        output.insert("budget".to_owned(), run.budget.report(max_images, timeout_ms));
        return Ok(Value::Object(output));
    }
    let container = inputs::container_changes(&old_layout, &new_layout);
    let pairs = inputs::pair(old_layout.components, new_layout.components);
    for (id, old, new) in pairs {
        compare(&mut run, id, old, new, 0);
    }
    run.components.sort_by(|a, b| a.id.cmp(&b.id));
    output.insert("identical".to_owned(), json!(false));
    output.insert("summary".to_owned(), json!(summary(&run, &container)));
    if !container.is_empty() {
        output.insert("container".to_owned(), json!(container));
    }
    output.insert("next".to_owned(), json!(next_steps(query, &run)));
    let components = std::mem::take(&mut run.components);
    output.insert("components".to_owned(), serde_json::to_value(&components).unwrap_or_default());
    output.insert("not_compared".to_owned(), serde_json::to_value(&run.not_compared).unwrap_or_default());
    output.insert("budget".to_owned(), run.budget.report(max_images, timeout_ms));
    Ok(fitted(Value::Object(output)))
}

/// Compares one component pair, appending its result (and those of components found inside it) to `run`.
pub(crate) fn compare(run: &mut Run, id: String, old: Option<Component>, new: Option<Component>, depth: usize) {
    let role = old.as_ref().or(new.as_ref()).map_or("data", |component| component.role);
    let mut diff = ComponentDiff {
        id: id.clone(),
        role,
        old: old.as_ref().map(Component::facts_value),
        new: new.as_ref().map(Component::facts_value),
        ..ComponentDiff::default()
    };
    let (old, new) = match (old, new) {
        (Some(old), Some(new)) => (old, new),
        (old, new) => {
            diff.status = if old.is_some() { "removed" } else { "added" };
            let component = old.as_ref().or(new.as_ref()).expect("one side");
            if let Opener::Tree(_) = component.open {
                diff.notes.push("only on one side: its files are not listed one by one".to_owned());
            }
            run.components.push(diff);
            return;
        }
    };
    diff.changes = inputs::fact_changes(&old, &new);
    if old.digest.is_some() && old.digest == new.digest {
        diff.status = "unchanged";
        run.components.push(diff);
        return;
    }
    diff.status = "changed";
    match (&old.open, &new.open) {
        (Opener::Tree(old_tree), Opener::Tree(new_tree)) => {
            if depth >= MAX_TREE_DEPTH {
                run.skip(&id, format!("filesystems nested deeper than {MAX_TREE_DEPTH} levels are not taken apart"));
            } else {
                let before = run.components.len();
                tree::compare_trees(run, &id, old_tree, new_tree, &mut diff, depth);
                // A tree without a digest (a directory) whose files all match is unchanged.
                let files = diff.files.as_ref();
                let quiet = files.is_some_and(|files| {
                    ["changed_total", "added_total", "removed_total", "metadata_changed_total"]
                        .iter()
                        .all(|key| files[key].as_u64() == Some(0))
                        && files.get("not_hashed").is_none()
                });
                if quiet && run.components.len() == before {
                    diff.status = "unchanged";
                }
            }
            if old.android || new.android {
                diff.android = tree::android_changes(&old, &new);
            }
        }
        (Opener::Dex, Opener::Dex) => diff.android = tree::android_changes(&old, &new),
        (old_open, new_open) if old_open.is_code() && new_open.is_code() => {
            if run.budget.take_image() {
                match code::compare_code(run, &old, &new) {
                    Ok(value) => diff.code = Some(value),
                    Err(error) => {
                        diff.status = "not_compared";
                        diff.notes.push(format!("code not compared: {error}"));
                        run.skip(&id, format!("code not compared: {error}"));
                    }
                }
            } else {
                run.skip(&id, budget_reason(&run.budget));
            }
        }
        (Opener::Data, Opener::Data) => {}
        _ => diff.notes.push("the two versions hold different kinds of content; compared by digest only".to_owned()),
    }
    run.components.push(diff);
}

fn budget_reason(budget: &Budget) -> String {
    match budget.stopped {
        Some("time") => {
            "the time budget (timeout_ms) ran out before this image; ask for it with `component`".to_owned()
        }
        Some("bytes") => "the byte budget ran out before this image".to_owned(),
        _ => "max_images code images were already analysed; ask for this one with `component`, or raise max_images"
            .to_owned(),
    }
}

/// The summary sentences: counts per component status, then the headline changes.
fn summary(run: &Run, container: &[String]) -> Vec<String> {
    let mut lines = Vec::new();
    let count = |status: &str| run.components.iter().filter(|component| component.status == status).count();
    lines.push(format!(
        "{} components: {} changed, {} added, {} removed, {} unchanged, {} not compared.",
        run.components.len(),
        count("changed"),
        count("added"),
        count("removed"),
        count("unchanged"),
        count("not_compared")
    ));
    if !container.is_empty() {
        lines.push(format!("Container: {}.", container.join("; ")));
    }
    for component in &run.components {
        let mut parts = Vec::new();
        if let Some(code) = &component.code {
            let functions = &code["functions"];
            parts.push(format!(
                "functions {} changed, {} added, {} removed",
                functions["changed"], functions["added"], functions["removed"]
            ));
            for (key, label) in [
                ("endpoints", "endpoints"),
                ("versions", "version strings"),
                ("locks", "lock mechanisms"),
                ("integrity", "integrity checks"),
                ("capture", "capture sources"),
            ] {
                let delta = &code[key];
                let (added, removed) = (delta["added_total"].as_u64(), delta["removed_total"].as_u64());
                let changed = delta["changed_total"].as_u64().unwrap_or(0);
                if added.unwrap_or(0) + removed.unwrap_or(0) + changed > 0 {
                    let mut text = format!("{label} +{} -{}", added.unwrap_or(0), removed.unwrap_or(0));
                    if changed > 0 {
                        text.push_str(&format!(" ~{changed}"));
                    }
                    parts.push(text);
                }
            }
        }
        if let Some(files) = &component.files {
            parts.push(format!(
                "files {} changed, {} added, {} removed",
                files["changed_total"], files["added_total"], files["removed_total"]
            ));
            let endpoints = &files["endpoints"];
            if endpoints["added_total"].as_u64().unwrap_or(0) + endpoints["removed_total"].as_u64().unwrap_or(0) > 0 {
                parts.push(format!("endpoints +{} -{}", endpoints["added_total"], endpoints["removed_total"]));
            }
        }
        if let Some(android) = &component.android
            && let Some(object) = android.as_object()
        {
            let changed: Vec<&str> = object.keys().map(String::as_str).collect();
            if !changed.is_empty() {
                parts.push(format!("Android {} changed", changed.join(", ")));
            }
        }
        if !parts.is_empty() {
            lines.push(format!("`{}` ({}): {}.", component.id, component.status, parts.join("; ")));
        }
    }
    if !run.not_compared.is_empty() {
        lines.push(format!("{} items were not compared; `not_compared` says why.", run.not_compared.len()));
    }
    lines
}

/// Calls that read further: each changed code image's functions, and its first changed function side by side.
fn next_steps(query: &FirmwareDiffQuery, run: &Run) -> Vec<Value> {
    let mut steps = Vec::new();
    let base = query_arguments(query);
    for component in run.components.iter().filter(|component| component.status == "changed") {
        if let Some(code) = &component.code {
            let first = code["changed"].as_array().and_then(|rows| rows.first());
            if let Some(name) = first.and_then(|row| row["old"].as_str()) {
                let mut arguments = base.clone();
                arguments["component"] = json!(component.id);
                arguments["function"] = json!(name);
                steps.push(json!({
                    "tool": "diff_firmware",
                    "arguments": arguments,
                    "why": "the first changed function, instruction by instruction with addresses normalised",
                }));
            }
            let mut arguments = base.clone();
            arguments["component"] = json!(component.id);
            arguments["list"] = json!("changed");
            steps.push(json!({
                "tool": "diff_firmware",
                "arguments": arguments,
                "why": "every changed function of this image, paged",
            }));
        }
        if steps.len() >= 6 {
            break;
        }
    }
    for component in run.components.iter().filter(|component| component.files.is_some()) {
        let total = component.files.as_ref().map_or(0, |files| {
            ["changed_total", "added_total", "removed_total"]
                .iter()
                .map(|key| files[key].as_u64().unwrap_or(0))
                .sum::<u64>()
        });
        if total as usize > run.rows {
            let mut arguments = base.clone();
            arguments["component"] = json!(component.id);
            arguments["list"] = json!("files");
            steps.push(json!({"tool": "diff_firmware", "arguments": arguments, "why": "every changed file, paged"}));
        }
    }
    steps
}

/// The arguments that select the same two inputs again.
fn query_arguments(query: &FirmwareDiffQuery) -> Value {
    let mut arguments = json!({});
    query.old.write_arguments(&mut arguments, "");
    query.new.write_arguments(&mut arguments, "other_");
    arguments
}

/// The answer for one component pair: in full, one list paged, or one function diffed.
fn drill_down(
    query: &FirmwareDiffQuery,
    id: &str,
    old_layout: inputs::Layout,
    new_layout: inputs::Layout,
    run: &mut Run,
    limit: usize,
) -> Result<Map<String, Value>, String> {
    let (old, new) = inputs::resolve(id, old_layout, new_layout, run)?;
    let mut output = Map::new();
    output.insert("component".to_owned(), json!(id));
    if let Some(function) = &query.function {
        let (Some(old), Some(new)) = (old, new) else {
            return Err(format!("`{id}` is on one side only; there is no function pair to diff"));
        };
        if !old.open.is_code() || !new.open.is_code() {
            return Err(format!("`{id}` is not a code image on both sides"));
        }
        output.extend(code::function_diff(run, &old, &new, function)?);
        return Ok(output);
    }
    // The whole comparison of this pair, with every list at least a page long.
    run.rows = (query.offset + limit).max(SUMMARY_ROWS);
    run.budget.images_left = run.budget.images_left.max(1);
    compare(run, id.to_owned(), old, new, 0);
    let mut components = std::mem::take(&mut run.components);
    let index = components.iter().position(|component| component.id == id).unwrap_or(0);
    let found = components.remove(index);
    match query.list.as_deref() {
        None => {
            output.insert("result".to_owned(), serde_json::to_value(&found).unwrap_or_default());
            if !components.is_empty() {
                components.sort_by(|a, b| a.id.cmp(&b.id));
                output.insert("inside".to_owned(), serde_json::to_value(&components).unwrap_or_default());
            }
        }
        Some(list) => {
            // Each list holds at least offset + limit rows, so the first of them are exact; the totals count all.
            let (rows, total) = list_rows(&found, list)?;
            let page: Vec<Value> = rows.into_iter().skip(query.offset).take(limit).collect();
            let next = (query.offset + page.len() < total).then_some(query.offset + page.len());
            output.insert("list".to_owned(), json!(list));
            output.insert("total".to_owned(), json!(total));
            output.insert("rows".to_owned(), json!(page));
            output.insert("next_offset".to_owned(), json!(next));
        }
    }
    output.insert("not_compared".to_owned(), serde_json::to_value(&run.not_compared).unwrap_or_default());
    Ok(output)
}

/// The rows of `list` in one component's result, and how many the list holds in all.
fn list_rows(found: &ComponentDiff, list: &str) -> Result<(Vec<Value>, usize), String> {
    let total = |value: &Value, keys: &[&str]| -> usize {
        keys.iter().map(|key| value[format!("{key}_total")].as_u64().unwrap_or(0) as usize).sum()
    };
    let rows = |value: &Value, key: &str| value[key].as_array().cloned().unwrap_or_default();
    let tagged = |value: &Value, keys: &[&str]| -> Vec<Value> {
        keys.iter()
            .flat_map(|key| {
                rows(value, key).into_iter().map(move |mut row| {
                    if let Some(object) = row.as_object_mut() {
                        object.insert("change".to_owned(), json!(key));
                    } else {
                        row = json!({"change": key, "value": row});
                    }
                    row
                })
            })
            .collect()
    };
    match list {
        "changed" | "added" | "removed" | "unchanged" => {
            let code = found.code.as_ref().ok_or_else(|| format!("`{}` has no function comparison", found.id))?;
            Ok((rows(code, list), code["functions"][list].as_u64().unwrap_or(0) as usize))
        }
        "strings" | "endpoints" => {
            if let Some(code) = &found.code {
                return Ok((tagged(&code[list], &["added", "removed"]), total(&code[list], &["added", "removed"])));
            }
            if list == "endpoints"
                && let Some(files) = &found.files
            {
                let endpoints = &files["endpoints"];
                return Ok((tagged(endpoints, &["added", "removed"]), total(endpoints, &["added", "removed"])));
            }
            Err(format!("`{}` has no {list} comparison", found.id))
        }
        "files" => {
            let files = found.files.as_ref().ok_or_else(|| format!("`{}` is not a filesystem", found.id))?;
            let keys = ["changed", "added", "removed", "metadata_changed"];
            Ok((tagged(files, &keys), total(files, &keys)))
        }
        other => Err(format!(
            "unknown list `{other}` (expected changed, added, removed, unchanged, strings, endpoints or files)"
        )),
    }
}

/// `value` with its longest lists halved until it fits [`RESULT_BYTES`], and a note when anything was cut.
fn fitted(mut value: Value) -> Value {
    let size = |value: &Value| serde_json::to_string(value).map_or(0, |text| text.len());
    if size(&value) <= RESULT_BYTES {
        return value;
    }
    while size(&value) > RESULT_BYTES {
        if !halve_longest(&mut value) {
            break;
        }
    }
    value["truncated"] =
        json!("Lists were cut to fit the result; each keeps its *_total. Page one with `component` and `list`.");
    value
}

/// Halves the longest array of more than one element, leaving the component list and the summary whole while
/// anything else can be cut; false when nothing is left to cut.
fn halve_longest(value: &mut Value) -> bool {
    #[derive(Clone)]
    enum Step {
        Key(String),
        Index(usize),
    }
    fn find(value: &Value, path: &mut Vec<Step>, best: &mut Option<(usize, Vec<Step>)>, protect: bool) {
        match value {
            Value::Array(items) => {
                let length = items.len();
                if length > 1 && best.as_ref().is_none_or(|(size, _)| length > *size) && !protect {
                    *best = Some((length, path.clone()));
                }
                for (index, item) in items.iter().enumerate() {
                    path.push(Step::Index(index));
                    find(item, path, best, false);
                    path.pop();
                }
            }
            Value::Object(map) => {
                for (key, child) in map {
                    path.push(Step::Key(key.clone()));
                    let protected = path.len() == 1 && matches!(key.as_str(), "components" | "summary");
                    find(child, path, best, protected);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut best = None;
    find(value, &mut Vec::new(), &mut best, false);
    if best.is_none() {
        // Only the protected lists are left: cut the component list itself.
        if let Some(Value::Array(items)) = value.get_mut("components")
            && items.len() > 1
        {
            items.truncate(items.len() / 2);
            return true;
        }
        return false;
    }
    let (_, path) = best.expect("found");
    let mut target = value;
    for step in path {
        target = match step {
            Step::Key(key) => &mut target[key.as_str()],
            Step::Index(index) => &mut target[index],
        };
    }
    if let Value::Array(items) = target {
        items.truncate(items.len() / 2);
        return true;
    }
    false
}

/// The path text a result names a side by.
pub(crate) fn display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests;
