//! Comparing two versions of one code image: matched, changed, added and removed functions (the matching of
//! `transfer_annotations`), then what each version names or checks that the other does not: strings, version
//! identifiers, endpoints, lock mechanisms, integrity checks and capture sources. And one function pair side by
//! side, instruction by instruction with addresses normalised.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use super::inputs::{Component, Opener};
use super::matching::{Code, Labels, Matched, match_pair, pair_name};
use super::{Delta, Run};
use crate::{DisassemblyLine, Project};

/// Images larger than this are not analysed.
const MAX_IMAGE_BYTES: usize = 64 << 20;
/// Strings shorter than this are too common to diff.
const MIN_STRING: usize = 6;
/// Lock mechanisms read per side.
const MAX_LOCKS: usize = 50;
/// Rows of a function diff.
const MAX_DIFF_ROWS: usize = 400;

static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+\.\d+(?:\.\d+){0,3}").expect("version pattern"));
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").expect("IPv4 pattern"));
use super::matching::HEX;

/// Opens a code component as a project.
pub(crate) fn open_project(run: &Run, component: &Component) -> Result<Arc<Project>, String> {
    let project = match &component.open {
        Opener::Native { path, image } => {
            let binary = rampage_loaders::Binary::open_image(path, *image, None).map_err(|error| error.to_string())?;
            let project = Project::new(binary);
            project.set_packs(Arc::clone(&run.budget.packs));
            Arc::new(project)
        }
        Opener::Raw { path, request } => {
            let request: crate::RawProjectRequest =
                serde_json::from_value(request.clone()).map_err(|error| format!("Raw selector: {error}"))?;
            run.budget.session.open_raw(path, &request).map_err(|error| crate::tools::error_chain(&error))?
        }
        _ => return Err("not a code image".to_owned()),
    };
    if project.binary.image_bytes().len() > MAX_IMAGE_BYTES {
        return Err(format!("the image is larger than {MAX_IMAGE_BYTES} bytes"));
    }
    Ok(project)
}

fn hex(address: u64) -> String {
    format!("{address:#x}")
}

/// `rows` cut to `keep`, the rows kept.
fn keep(mut rows: Vec<Value>, keep: usize) -> Vec<Value> {
    rows.truncate(keep);
    rows
}

/// Compares two code components: see the module documentation.
pub(crate) fn compare_code(run: &mut Run, old: &Component, new: &Component) -> Result<Value, String> {
    let (old_project, new_project) = (open_project(run, old)?, open_project(run, new)?);
    let (a, b) = (&*old_project, &*new_project);
    if a.binary.arch != b.binary.arch {
        return Err(format!("the architectures differ ({} and {})", a.binary.arch, b.binary.arch));
    }
    let matched = match_pair(a, b)?;
    run.budget.functions_matched += matched.pairs.len();
    let rows = run.rows;
    let mut by_method: BTreeMap<&str, usize> = BTreeMap::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    for pair in &matched.pairs {
        *by_method.entry(pair.method).or_default() += 1;
        let mut row = json!({
            "name": pair_name(a, b, pair.old, pair.new),
            "old": hex(pair.old),
            "new": hex(pair.new),
            "method": pair.method,
            "confidence": pair.confidence,
        });
        if pair.changed {
            row["old_size"] = json!(matched.sizes_old.get(&pair.old));
            row["new_size"] = json!(matched.sizes_new.get(&pair.new));
            changed.push(row);
        } else {
            if pair.normalised {
                row["same_after_normalisation"] = json!(true);
            }
            unchanged.push(row);
        }
    }
    let added: Vec<Value> = matched
        .added
        .iter()
        .map(|&address| json!({"name": b.function_name(address), "new": hex(address), "size": matched.sizes_new.get(&address)}))
        .collect();
    let removed: Vec<Value> = matched
        .removed
        .iter()
        .map(|&address| json!({"name": a.function_name(address), "old": hex(address), "size": matched.sizes_old.get(&address)}))
        .collect();
    let mut notes = matched.notes.clone();
    let functions = json!({
        "old": matched.sizes_old.len(),
        "new": matched.sizes_new.len(),
        "unchanged": unchanged.len(),
        "changed": changed.len(),
        "added": added.len(),
        "removed": removed.len(),
        "by_method": by_method,
    });

    let strings = strings_delta(a, b, rows);
    let versions = versions_delta(a, b, rows);
    let endpoints = endpoints_delta(a, b, rows);
    let locks = if run.budget.time_left() {
        locks_delta(a, b, &matched, rows, &mut notes)
    } else {
        notes.push("lock mechanisms not compared: the time budget ran out".to_owned());
        json!(null)
    };
    let integrity = if run.budget.time_left() {
        integrity_delta(&old_project, &new_project, rows, &mut notes)
    } else {
        notes.push("integrity checks not compared: the time budget ran out".to_owned());
        json!(null)
    };
    let capture = if run.budget.time_left() {
        capture_delta(a, b, rows, &mut notes)
    } else {
        notes.push("capture sources not compared: the time budget ran out".to_owned());
        json!(null)
    };
    let mut value = json!({
        "arch": a.binary.arch.to_string(),
        "functions": functions,
        "changed": keep(changed, rows),
        "added": keep(added, rows),
        "removed": keep(removed, rows),
        "unchanged": keep(unchanged, rows),
        "strings": strings,
        "versions": versions,
        "endpoints": endpoints,
        "locks": locks,
        "integrity": integrity,
        "capture": capture,
    });
    if !notes.is_empty() {
        value["notes"] = json!(notes);
    }
    Ok(value)
}

/// Strings in data, and NUL-terminated ones in code (see [`super::matching::strings`]), joined with the strings
/// the project's own scan finds (UTF-16 among them).
fn string_set(project: &Project, minimum: usize) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = super::matching::strings(project, minimum).into_values().collect();
    set.extend(
        project
            .scanned_strings()
            .iter()
            .filter(|found| found.text.chars().count() >= minimum)
            .map(|found| found.text.clone()),
    );
    set
}

/// Strings of at least [`MIN_STRING`] characters in one version only; notable ones (URLs, paths, keys) first.
fn strings_delta(old: &Project, new: &Project, rows: usize) -> Value {
    let (a, b) = (string_set(old, MIN_STRING), string_set(new, MIN_STRING));
    let ordered = |set: &BTreeSet<String>, other: &BTreeSet<String>| -> Vec<Value> {
        let mut texts: Vec<&String> = set.difference(other).collect();
        texts.sort_by_key(|text| (crate::workflows::classify(text).is_none(), (*text).clone()));
        texts.into_iter().map(|text| json!(text)).collect()
    };
    let delta = Delta::of(ordered(&b, &a), ordered(&a, &b));
    capped(delta, rows)
}

fn capped(mut delta: Delta, rows: usize) -> Value {
    delta.added.truncate(rows);
    delta.removed.truncate(rows);
    delta.changed.truncate(rows);
    serde_json::to_value(delta).unwrap_or_default()
}

/// Whether `text` holds a version-like number (`1.4.2`, `v2.0`) that is not an IPv4 address.
fn version_like(text: &str) -> bool {
    text.len() <= 120 && !text.contains('%') && VERSION.find_iter(text).any(|found| !IPV4.is_match(found.as_str()))
}

/// Version identifiers: strings of any scanned length holding a version-like number, in one version only.
fn versions_delta(old: &Project, new: &Project, rows: usize) -> Value {
    let pick = |project: &Project| -> BTreeSet<String> {
        string_set(project, 3).into_iter().filter(|text| version_like(text)).collect()
    };
    let (a, b) = (pick(old), pick(new));
    let list = |set: &BTreeSet<String>, other: &BTreeSet<String>| -> Vec<Value> {
        set.difference(other).map(|text| json!(text)).collect()
    };
    capped(Delta::of(list(&b, &a), list(&a, &b)), rows)
}

/// Endpoints (URLs, hosts, IPs, pins, certificates) named in one version only.
fn endpoints_delta(old: &Project, new: &Project, rows: usize) -> Value {
    let rows_of = |project: &Project| -> BTreeMap<(String, String), Value> {
        let mut inventory = crate::endpoints::Inventory::default();
        crate::endpoints::scan_project(project, "image", false, false, &mut inventory);
        let mut found: BTreeMap<(String, String), Value> = inventory
            .rows
            .into_values()
            .map(|row| {
                let mut value = json!({"kind": row.kind.name(), "value": row.value});
                if let Some(reason) = row.reason {
                    value["local"] = json!(reason);
                }
                ((row.kind.name().to_owned(), row.value), value)
            })
            .collect();
        // Strings beside the code, which the scan of the project's string list may not see.
        for text in string_set(project, 4) {
            for candidate in crate::endpoints::extract(&text).found {
                let key = (candidate.kind.name().to_owned(), candidate.value.clone());
                found.entry(key).or_insert_with(|| {
                    let mut value = json!({"kind": candidate.kind.name(), "value": candidate.value});
                    if let Some(reason) = candidate.reason {
                        value["local"] = json!(reason);
                    }
                    value
                });
            }
        }
        found
    };
    let (a, b) = (rows_of(old), rows_of(new));
    let only = |set: &BTreeMap<(String, String), Value>, other: &BTreeMap<(String, String), Value>| -> Vec<Value> {
        set.iter().filter(|(key, _)| !other.contains_key(*key)).map(|(_, value)| value.clone()).collect()
    };
    capped(Delta::of(only(&b, &a), only(&a, &b)), rows)
}

/// A lock mechanism's identity across versions: its category and decision function, the older version's function
/// mapped to its newer counterpart; without a decision, its summary without addresses.
fn lock_key(mechanism: &crate::LockMechanism, map: &dyn Fn(u64) -> Option<u64>) -> (String, String) {
    let place = match &mechanism.decision {
        Some(decision) => map(decision.function).map_or_else(|| format!("unmatched {}", hex(decision.function)), hex),
        None => HEX.replace_all(&mechanism.summary, "<addr>").into_owned(),
    };
    (mechanism.category.to_owned(), place)
}

fn lock_row(mechanism: &crate::LockMechanism) -> Value {
    let mut row = json!({
        "category": mechanism.category,
        "confidence": mechanism.confidence,
        "failure_path": mechanism.failure_path,
        "summary": mechanism.summary,
    });
    if let Some(decision) = &mechanism.decision {
        row["function"] = json!(decision.function_name);
        row["decision"] = json!(hex(decision.at));
        row["condition"] = json!(decision.condition);
    }
    row
}

/// Lock mechanisms in one version only, and those whose deciding function changed or whose decision differs.
fn locks_delta(old: &Project, new: &Project, matched: &Matched, rows: usize, notes: &mut Vec<String>) -> Value {
    let query = crate::LockQuery { category: None, offset: 0, limit: MAX_LOCKS };
    let (a, b) = match (old.lock_mechanisms(&query), new.lock_mechanisms(&query)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => {
            notes.push(format!("lock mechanisms not compared: {error}"));
            return json!(null);
        }
    };
    if !a.supported && !b.supported {
        return json!({"supported": false});
    }
    if a.total > a.mechanisms.len() || b.total > b.mechanisms.len() {
        notes.push(format!("lock mechanisms: the first {MAX_LOCKS} of each version were compared"));
    }
    let old_to_new = matched.old_to_new();
    let changed_old = matched.changed_old();
    let map_old = |address: u64| old_to_new.get(&address).copied();
    let identity = |address: u64| Some(address);
    let mut old_keys: BTreeMap<(String, String), Vec<&crate::LockMechanism>> = BTreeMap::new();
    for mechanism in &a.mechanisms {
        old_keys.entry(lock_key(mechanism, &map_old)).or_default().push(mechanism);
    }
    let mut new_keys: BTreeMap<(String, String), Vec<&crate::LockMechanism>> = BTreeMap::new();
    for mechanism in &b.mechanisms {
        new_keys.entry(lock_key(mechanism, &identity)).or_default().push(mechanism);
    }
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    for (key, olds) in &old_keys {
        let news = new_keys.get(key).map(Vec::as_slice).unwrap_or_default();
        for (index, mechanism) in olds.iter().enumerate() {
            let Some(counterpart) = news.get(index) else {
                removed.push(lock_row(mechanism));
                continue;
            };
            let mut what = Vec::new();
            if let Some(decision) = &mechanism.decision
                && changed_old.contains(&decision.function)
            {
                what.push("the deciding function changed".to_owned());
            }
            if mechanism.failure_path != counterpart.failure_path {
                what.push(format!("failure path {} -> {}", mechanism.failure_path, counterpart.failure_path));
            }
            if mechanism.consults != counterpart.consults {
                what.push("it consults other data".to_owned());
            }
            if !what.is_empty() {
                changed.push(json!({"old": lock_row(mechanism), "new": lock_row(counterpart), "what": what}));
            }
        }
    }
    for (key, news) in &new_keys {
        let olds = old_keys.get(key).map_or(0, Vec::len);
        added.extend(news.iter().skip(olds).map(|mechanism| lock_row(mechanism)));
    }
    let mut value = capped(Delta::of(added, removed).with_changed(changed), rows);
    value["supported"] = json!(true);
    value
}

fn integrity_row(check: &crate::integrity::IntegrityCheck) -> Value {
    json!({
        "algorithm": check.algorithm,
        "stored": hex(check.stored.address),
        "stored_size": check.stored.size,
        "ranges": check.ranges.iter().map(|range| format!("{}..{}", hex(range.start), hex(range.end))).collect::<Vec<_>>(),
        "covered_bytes": covered(check),
        "valid": check.valid,
        "confidence": check.confidence,
    })
}

fn covered(check: &crate::integrity::IntegrityCheck) -> u64 {
    check.ranges.iter().map(|range| range.end.saturating_sub(range.start)).sum()
}

/// Integrity checks (stored checksums and digests over image ranges) per algorithm, paired in address order:
/// added, removed, and changed in covered length, stored field size, parameters or validity. Low-confidence checks
/// are left out: they match by chance as easily in one version as in the other.
fn integrity_delta(old: &Arc<Project>, new: &Arc<Project>, rows: usize, notes: &mut Vec<String>) -> Value {
    let request = crate::IntegrityRequest::default();
    let (a, b) = match (old.integrity_checks(&request), new.integrity_checks(&request)) {
        (Ok(a), Ok(b)) => (a.report, b.report),
        (Err(error), _) | (_, Err(error)) => {
            notes.push(format!("integrity checks not compared: {error}"));
            return json!(null);
        }
    };
    if a.search.budget_exhausted || b.search.budget_exhausted {
        notes.push("the integrity search ran out of budget on one side; checks may be missing".to_owned());
    }
    let group = |checks: &[crate::integrity::IntegrityCheck]| {
        let mut groups: BTreeMap<(&str, &str), Vec<crate::integrity::IntegrityCheck>> = BTreeMap::new();
        for check in checks.iter().filter(|check| check.confidence != "low") {
            groups.entry((check.algorithm, check.space)).or_default().push(check.clone());
        }
        for checks in groups.values_mut() {
            checks.sort_by_key(|check| check.stored.address);
        }
        groups
    };
    let (old_groups, new_groups) = (group(&a.checks), group(&b.checks));
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    let keys: BTreeSet<(&str, &str)> = old_groups.keys().chain(new_groups.keys()).copied().collect();
    for key in keys {
        let olds = old_groups.get(&key).map(Vec::as_slice).unwrap_or_default();
        let news = new_groups.get(&key).map(Vec::as_slice).unwrap_or_default();
        for index in 0..olds.len().max(news.len()) {
            match (olds.get(index), news.get(index)) {
                (Some(x), Some(y)) => {
                    let mut what = Vec::new();
                    if covered(x) != covered(y) {
                        what.push(format!("covered bytes {} -> {}", covered(x), covered(y)));
                    }
                    if x.stored.size != y.stored.size {
                        what.push(format!("stored field size {} -> {}", x.stored.size, y.stored.size));
                    }
                    if x.parameters != y.parameters {
                        what.push("algorithm parameters differ".to_owned());
                    }
                    if x.valid != y.valid {
                        what.push(format!("valid {} -> {}", x.valid, y.valid));
                    }
                    if !what.is_empty() {
                        changed.push(json!({"old": integrity_row(x), "new": integrity_row(y), "what": what}));
                    }
                }
                (Some(x), None) => removed.push(integrity_row(x)),
                (None, Some(y)) => added.push(integrity_row(y)),
                (None, None) => {}
            }
        }
    }
    capped(Delta::of(added, removed).with_changed(changed), rows)
}

/// Capture sources (`privacy_surface`'s microphone, camera, screen and input findings) in one version only, by
/// what is captured and how, without the function names; only when either version may capture at all.
fn capture_delta(old: &Project, new: &Project, rows: usize, notes: &mut Vec<String>) -> Value {
    let may = |project: &Project| crate::workflows::may_capture(&project.binary, project.binary.image_bytes());
    if !may(old) && !may(new) {
        return json!({"applies": false});
    }
    let sources = |project: &Project| -> Result<BTreeMap<String, usize>, String> {
        let report = project
            .privacy_surface(crate::workflows::ReportLimits::new(Some(200)))
            .map_err(|error| error.to_string())?;
        let mut counts = BTreeMap::new();
        for section in report.sections.iter().filter(|section| section.title == "Capture sources") {
            for finding in &section.findings {
                // "`name` what (medium)": the function's name differs between builds, the rest does not.
                let text = finding.observation.split_once("` ").map_or(finding.observation.as_str(), |(_, rest)| rest);
                *counts.entry(text.to_owned()).or_default() += 1;
            }
        }
        Ok(counts)
    };
    let (a, b) = match (sources(old), sources(new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => {
            notes.push(format!("capture sources not compared: {error}"));
            return json!(null);
        }
    };
    let more = |x: &BTreeMap<String, usize>, y: &BTreeMap<String, usize>| -> Vec<Value> {
        x.iter()
            .filter(|(text, count)| y.get(*text).copied().unwrap_or(0) < **count)
            .map(|(text, _)| json!(text))
            .collect()
    };
    let mut value = capped(Delta::of(more(&b, &a), more(&a, &b)), rows);
    value["applies"] = json!(true);
    value
}

/// One function pair side by side: see the module documentation.
pub(crate) fn function_diff(
    run: &mut Run,
    old: &Component,
    new: &Component,
    function: &str,
) -> Result<Map<String, Value>, String> {
    let (old_project, new_project) = (open_project(run, old)?, open_project(run, new)?);
    let (a, b) = (&*old_project, &*new_project);
    if a.binary.arch != b.binary.arch {
        return Err(format!("the architectures differ ({} and {})", a.binary.arch, b.binary.arch));
    }
    let matched = match_pair(a, b)?;
    let start = |project: &Project, text: &str| -> Result<u64, String> {
        let address = project.resolve(text).map_err(|error| error.to_string())?;
        project
            .function_containing(address)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("no discovered function contains `{text}`"))
    };
    let pairs: Vec<(u64, u64, &str, f64, bool)> =
        matched.pairs.iter().map(|pair| (pair.old, pair.new, pair.method, pair.confidence, pair.changed)).collect();
    let (old_address, new_address, method) = match function.strip_prefix("new:") {
        Some(text) => {
            let address = start(b, text)?;
            match pairs.iter().find(|pair| pair.1 == address) {
                Some(pair) => (Some(pair.0), Some(address), Some(*pair)),
                None => (None, Some(address), None),
            }
        }
        None => {
            let address = start(a, function)?;
            match pairs.iter().find(|pair| pair.0 == address) {
                Some(pair) => (Some(address), Some(pair.1), Some(*pair)),
                None => (Some(address), None, None),
            }
        }
    };
    let mut labels = Labels::new(a, b, &matched.sizes_old, &matched.sizes_new);
    for pair in &matched.pairs {
        labels.pair(pair.old, pair.new);
    }
    let (code_old, code_new) = (Code::new(a, &matched.sizes_old), Code::new(b, &matched.sizes_new));
    let lines = |code: &Code, address: Option<u64>| match address {
        Some(address) => code.listing(address),
        None => Ok(Vec::new()),
    };
    let old_lines: Vec<DisassemblyLine> = lines(&code_old, old_address)?;
    let new_lines: Vec<DisassemblyLine> = lines(&code_new, new_address)?;
    let old_text = code_old.normalised(&old_lines, &|target| labels.label(true, target));
    let new_text = code_new.normalised(&new_lines, &|target| labels.label(false, target));
    let (rows, truncated) = diff_rows(&old_lines, &new_lines, &old_text, &new_text);
    let mut output = Map::new();
    let mut header = json!({
        "name": match (old_address, new_address) {
            (Some(x), Some(y)) => pair_name(a, b, x, y),
            (Some(x), None) => a.function_name(x),
            (None, Some(y)) => b.function_name(y),
            (None, None) => String::new(),
        },
        "old": old_address.map(hex),
        "new": new_address.map(hex),
    });
    match method {
        Some((_, _, method, confidence, changed)) => {
            header["method"] = json!(method);
            header["confidence"] = json!(confidence);
            header["changed"] = json!(changed);
        }
        None if old_address.is_some() => header["only_in"] = json!("old"),
        None => header["only_in"] = json!("new"),
    }
    output.insert("function".to_owned(), header);
    output.insert("old_instructions".to_owned(), json!(old_lines.len()));
    output.insert("new_instructions".to_owned(), json!(new_lines.len()));
    let differing = rows.iter().filter(|row| row.get("op").is_some()).count();
    output.insert("differing_rows".to_owned(), json!(differing));
    output.insert("rows".to_owned(), json!(rows));
    if truncated {
        output.insert("rows_truncated".to_owned(), json!(true));
    }
    output.insert(
        "normalised".to_owned(),
        json!(
            "branch and call targets read as the older version's function names (new: for functions only in the \
               newer one), other addresses as <addr>, and PC-relative references by what they load"
        ),
    );
    let mut decompile = Vec::new();
    for (component, address) in [(old, old_address), (new, new_address)] {
        if let (Some(mut arguments), Some(address), false) =
            (component.open.tool_arguments(), address, component.ephemeral)
        {
            arguments["at"] = json!(hex(address));
            decompile.push(json!({"tool": "decompile", "arguments": arguments}));
        }
    }
    if decompile.is_empty() {
        output.insert(
            "decompile".to_owned(),
            json!("these images live inside a filesystem: extract them with fs_extract to decompile them"),
        );
    } else {
        output.insert("decompile".to_owned(), json!(decompile));
    }
    Ok(output)
}

/// The longest common subsequence of the two normalised listings as rows: runs of equal instructions folded into
/// `{"same": n}`, and each differing instruction as `-` (only in the older version) or `+`.
fn diff_rows(old: &[DisassemblyLine], new: &[DisassemblyLine], a: &[String], b: &[String]) -> (Vec<Value>, bool) {
    let (n, m) = (a.len(), b.len());
    let width = m + 1;
    let mut table = vec![0u16; (n + 1) * width];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    let mut rows = Vec::new();
    let mut same: Option<(usize, u64, u64)> = None;
    let flush = |same: &mut Option<(usize, u64, u64)>, rows: &mut Vec<Value>| {
        if let Some((count, x, y)) = same.take() {
            rows.push(json!({"same": count, "old": hex(x), "new": hex(y)}));
        }
    };
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            match &mut same {
                Some((count, _, _)) => *count += 1,
                None => same = Some((1, old[i].address, new[j].address)),
            }
            i += 1;
            j += 1;
        } else if i < n && (j == m || table[(i + 1) * width + j] >= table[i * width + j + 1]) {
            flush(&mut same, &mut rows);
            rows.push(json!({"op": "-", "old": hex(old[i].address), "text": a[i]}));
            i += 1;
        } else {
            flush(&mut same, &mut rows);
            rows.push(json!({"op": "+", "new": hex(new[j].address), "text": b[j]}));
            j += 1;
        }
    }
    flush(&mut same, &mut rows);
    let truncated = rows.len() > MAX_DIFF_ROWS;
    rows.truncate(MAX_DIFF_ROWS);
    (rows, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_like_strings_are_versions_but_addresses_are_not() {
        assert!(version_like("fw-version 2.1.0"));
        assert!(version_like("v5.4-fixture"));
        assert!(!version_like("http://10.0.0.1/metrics"));
        assert!(!version_like("%d.%d"));
        assert!(!version_like("image check failed"));
    }

    #[test]
    fn match_methods_have_names() {
        assert_eq!(crate::build_match::MatchMethod::ExactBytes.name(), "exact_bytes");
    }
}
