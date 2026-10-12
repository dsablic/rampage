//! `diff_builds`: compares this binary with another build of the same architecture. Functions are paired by symbol
//! name, by masked signature hash (`rampage_signatures::function_hash_in`) and by identical bytes at an unchanged
//! address, then imports and strings are diffed.
//! Hash equality is signature-level (same instructions after masking addresses), not semantic equivalence.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use rampage_loaders::Binary;
use rampage_signatures::{FunctionHash, MaskContext, function_hash_in};
use serde_json::json;

use super::{
    Confidence, Finding, ReportLimits, ReportTarget, Section, WorkflowReport, classify, is_default_name, quote,
};
use crate::{ApiError, Project};

/// Strings shorter than this are too common to be worth diffing.
const MIN_DIFF_STRING: usize = 6;
/// Changed functions suggested for side-by-side decompilation.
const SUGGESTED_FUNCTIONS: usize = 2;

struct Function {
    address: u64,
    name: String,
    hash: Option<FunctionHash>,
    size: u64,
}

impl Function {
    fn named(&self) -> bool {
        !is_default_name(&self.name)
    }
}

/// Every discovered function with its masked hash, or `None` where the architecture or bytes allow none.
fn inventory(project: &Project) -> Result<Vec<Function>, ApiError> {
    let analysis = project.analysis()?;
    let target = project.binary.target();
    let image = MaskContext::from_binary(&project.binary);
    Ok(analysis
        .program
        .functions
        .iter()
        .map(|function| {
            let end = function.blocks.iter().map(|block| block.end).max().unwrap_or(function.address);
            let size = end.saturating_sub(function.address);
            let hash = project
                .binary
                .read(function.address, size)
                .filter(|_| size > 0)
                .and_then(|bytes| function_hash_in(&target, &image, bytes, function.address));
            Function { address: function.address, name: project.function_name(function.address), hash, size }
        })
        .collect())
}

/// Names that occur exactly once, so a name pairs exactly one function per side.
fn unique_names(functions: &[Function]) -> HashMap<&str, usize> {
    let mut counts: HashMap<&str, (usize, usize)> = HashMap::new();
    for (index, function) in functions.iter().enumerate().filter(|(_, function)| function.named()) {
        counts.entry(&function.name).or_insert((0, index)).0 += 1;
    }
    counts.into_iter().filter(|(_, (count, _))| *count == 1).map(|(name, (_, index))| (name, index)).collect()
}

/// Hashes that occur exactly once among the still-unpaired functions.
fn unique_hashes(functions: &[Function], paired: &BTreeSet<usize>) -> HashMap<FunctionHash, usize> {
    let mut counts: HashMap<FunctionHash, (usize, usize)> = HashMap::new();
    for (index, function) in functions.iter().enumerate().filter(|(index, _)| !paired.contains(index)) {
        if let Some(hash) = function.hash {
            counts.entry(hash).or_insert((0, index)).0 += 1;
        }
    }
    counts.into_iter().filter(|(_, (count, _))| *count == 1).map(|(hash, (_, index))| (hash, index)).collect()
}

/// How often each name occurs.
fn name_counts(functions: &[Function]) -> HashMap<&str, usize> {
    let mut counts = HashMap::new();
    for function in functions {
        *counts.entry(function.name.as_str()).or_default() += 1;
    }
    counts
}

/// Why `function` stayed unpaired, given how often its name occurs on its own side (`here`) and the other (`there`).
fn unpaired(function: &Function, here: usize, there: usize) -> (Confidence, String) {
    let name = &function.name;
    if !function.named() {
        let observation = format!("unnamed `{name}` has no counterpart by unique hash; it may be a changed function");
        return (Confidence::Low, observation);
    }
    if there == 0 {
        return (Confidence::Medium, format!("`{name}` has no counterpart by name or hash"));
    }
    let times = |count: usize| if count == 1 { "once".to_owned() } else { format!("{count} times") };
    let observation = format!(
        "`{name}` occurs {} here and {} in the other build, so the name cannot pair it, and no unique hash or \
         identical bytes did",
        times(here),
        times(there)
    );
    (Confidence::Low, observation)
}

fn imports(binary: &Binary) -> BTreeSet<(String, String)> {
    binary
        .imports
        .iter()
        .map(|import| (import.library.as_deref().unwrap_or("").to_ascii_lowercase(), import.name.clone()))
        .collect()
}

fn strings(project: &Project) -> BTreeMap<String, u64> {
    project
        .scanned_strings()
        .iter()
        .filter(|found| found.text.chars().count() >= MIN_DIFF_STRING)
        .map(|found| (found.text.clone(), found.address))
        .collect()
}

impl Project {
    /// Compares this binary (the base) with the build at `other_path` (the new one): "added" means present only
    /// in the other build, "removed" only in this one.
    pub fn diff_builds(&self, other_path: &Path, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let other = self.open_peer(other_path)?;
        let other_label = other_path.display().to_string();
        let mut report = WorkflowReport::new("diff_builds", self);
        let other_target = ReportTarget::of(&other);
        if other_target.sha256 == report.target.sha256 {
            report.summary.push("The two images are byte-identical (same SHA-256).".to_owned());
        }
        report.other = Some(other_target);

        let base = inventory(self)?;
        let new = inventory(&other)?;
        let hashed = base.iter().chain(&new).filter(|function| function.hash.is_some()).count();
        if hashed == 0 {
            report.limitation(format!(
                "Masked hashing does not support {}; functions are paired by name only.",
                self.binary.arch
            ));
        }

        let mut paired_base = BTreeSet::new();
        let mut paired_new = BTreeSet::new();
        let mut identical = Section::new("Identical functions", limits);
        let mut changed = Section::new("Changed functions", limits);
        let mut rehomed = Section::new("Functions matched by hash", limits);
        let mut name_only = Section::new("Functions matched by name only", limits);
        let mut changed_names = Vec::new();

        let new_unique_names = unique_names(&new);
        let mut by_name: Vec<(usize, usize)> = unique_names(&base)
            .into_iter()
            .filter_map(|(name, index)| new_unique_names.get(name).map(|&other| (index, other)))
            .collect();
        by_name.sort_unstable();
        for (index, other_index) in by_name {
            let (a, b) = (&base[index], &new[other_index]);
            paired_base.insert(index);
            paired_new.insert(other_index);
            let place = format!("{:#x} -> {:#x}", a.address, b.address);
            match (a.hash, b.hash) {
                (Some(x), Some(y)) if x == y => identical.push(
                    Finding::new(
                        "identify_functions",
                        Confidence::High,
                        format!("`{}` has the same masked hash", a.name),
                    )
                    .at(a.address)
                    .evidence([place]),
                ),
                (Some(_), Some(_)) => {
                    changed_names.push(a.name.clone());
                    changed.push(
                        Finding::new(
                            "identify_functions",
                            Confidence::Medium,
                            format!("`{}` is named in both builds but its masked hash differs", a.name),
                        )
                        .at(a.address)
                        .evidence([place, format!("size {} -> {} bytes", a.size, b.size)]),
                    );
                }
                _ => name_only.push(
                    Finding::new(
                        "list_functions",
                        Confidence::Low,
                        format!(
                            "`{}` is named in both builds; too small or undecodable to hash, so its body was not \
                             compared",
                            a.name
                        ),
                    )
                    .at(a.address)
                    .evidence([place]),
                ),
            }
        }

        let new_hashes = unique_hashes(&new, &paired_new);
        let mut by_hash: Vec<(usize, usize)> = unique_hashes(&base, &paired_base)
            .into_iter()
            .filter_map(|(hash, index)| new_hashes.get(&hash).map(|&other| (index, other)))
            .collect();
        by_hash.sort_unstable();
        for (index, other_index) in by_hash {
            let (a, b) = (&base[index], &new[other_index]);
            paired_base.insert(index);
            paired_new.insert(other_index);
            rehomed.push(
                Finding::new(
                    "identify_functions",
                    Confidence::Medium,
                    format!("`{}` and `{}` share a masked hash found once in each build", a.name, b.name),
                )
                .at(a.address)
                .evidence([format!("{:#x} -> {:#x}, {} bytes", a.address, b.address, a.size)]),
            );
        }

        // A hash that recurs (small stubs) cannot pair functions alone, but the same hash at the same address can.
        let new_placed: HashMap<(FunctionHash, u64), usize> = new
            .iter()
            .enumerate()
            .filter(|(index, _)| !paired_new.contains(index))
            .filter_map(|(index, function)| Some(((function.hash?, function.address), index)))
            .collect();
        for (index, function) in base.iter().enumerate() {
            let Some(hash) = function.hash.filter(|_| !paired_base.contains(&index)) else { continue };
            let Some(&other_index) = new_placed.get(&(hash, function.address)) else { continue };
            paired_base.insert(index);
            paired_new.insert(other_index);
            rehomed.push(
                Finding::new(
                    "identify_functions",
                    Confidence::Medium,
                    format!(
                        "`{}` and `{}` share a recurring masked hash at the same address",
                        function.name, new[other_index].name
                    ),
                )
                .at(function.address)
                .evidence([format!("{:#x}, {} bytes", function.address, function.size)]),
            );
        }

        // Bodies too small to hash and without a unique name still pair exactly when the same address holds the
        // same bytes on both sides; without this, diffing a file against itself would report added/removed.
        let new_by_address: HashMap<u64, usize> = new
            .iter()
            .enumerate()
            .filter(|(index, _)| !paired_new.contains(index))
            .map(|(index, function)| (function.address, index))
            .collect();
        for (index, function) in base.iter().enumerate() {
            if paired_base.contains(&index) || function.size == 0 {
                continue;
            }
            let Some(&other_index) = new_by_address.get(&function.address) else { continue };
            if new[other_index].size != function.size {
                continue;
            }
            let Some(bytes) = self.binary.read(function.address, function.size) else { continue };
            if other.binary.read(function.address, function.size) != Some(bytes) {
                continue;
            }
            paired_base.insert(index);
            paired_new.insert(other_index);
            identical.push(
                Finding::new(
                    "list_functions",
                    Confidence::Observed,
                    format!("`{}` is byte-identical at the same address", function.name),
                )
                .at(function.address)
                .evidence([format!("{:#x}, {} bytes", function.address, function.size)]),
            );
        }

        let (base_names, new_names) = (name_counts(&base), name_counts(&new));
        let leftover = |functions: &[Function],
                        paired: &BTreeSet<usize>,
                        names: &HashMap<&str, usize>,
                        other_names: &HashMap<&str, usize>,
                        label: &str| {
            let mut section = Section::new(label, limits);
            for (_, function) in functions.iter().enumerate().filter(|(index, _)| !paired.contains(index)) {
                let count = |counts: &HashMap<&str, usize>| counts.get(function.name.as_str()).copied().unwrap_or(0);
                let (confidence, observation) = unpaired(function, count(names), count(other_names));
                section.push(
                    Finding::new("list_functions", confidence, observation)
                        .at(function.address)
                        .evidence([format!("{} bytes", function.size)]),
                );
            }
            section
        };
        let added = leftover(&new, &paired_new, &new_names, &base_names, "Added functions");
        let removed = leftover(&base, &paired_base, &base_names, &new_names, "Removed functions");

        let (base_imports, new_imports) = (imports(&self.binary), imports(&other.binary));
        let mut import_changes = Section::new("Import differences", limits);
        for (change, set, against) in [("added", &new_imports, &base_imports), ("removed", &base_imports, &new_imports)]
        {
            for (library, name) in set.difference(against) {
                let from = if library.is_empty() { String::new() } else { format!(" from {library}") };
                import_changes.push(Finding::new(
                    "list_imports",
                    Confidence::Observed,
                    format!("{change}: `{name}`{from}"),
                ));
            }
        }

        let (base_strings, new_strings) = (strings(self), strings(&other));
        let mut string_changes = Section::new("String differences", limits);
        let mut differences: Vec<(bool, &str, &str, u64)> = Vec::new();
        for (change, set, against) in [("added", &new_strings, &base_strings), ("removed", &base_strings, &new_strings)]
        {
            for (text, &address) in set.iter().filter(|(text, _)| !against.contains_key(*text)) {
                differences.push((classify(text).is_none(), change, text, address));
            }
        }
        // Notable strings (URLs, paths, keys) first: they say most about a behavioral change.
        differences.sort_by_key(|&(plain, change, text, _)| (plain, change, text));
        for (plain, change, text, address) in differences {
            let kind = if plain { String::new() } else { " (notable)".to_owned() };
            string_changes.push(
                Finding::new("list_strings", Confidence::Observed, format!("{change}{kind}: {}", quote(text)))
                    .evidence([format!(
                        "at {address:#x} in the {} build",
                        if change == "added" { "other" } else { "base" }
                    )]),
            );
        }

        report.summary.push(format!(
            "{} functions here, {} in the other build: {} identical (same masked hash under one name, or the same \
             bytes at the same address), {} changed, {} paired by hash, {} paired by name only, {} added, {} \
             removed.",
            base.len(),
            new.len(),
            identical.total,
            changed.total,
            rehomed.total,
            name_only.total,
            added.total,
            removed.total
        ));
        report.summary.push(format!(
            "{} import differences and {} string differences (strings of at least {MIN_DIFF_STRING} characters).",
            import_changes.total, string_changes.total
        ));
        for name in changed_names.iter().take(SUGGESTED_FUNCTIONS) {
            report.step("decompile", json!({ "at": name }), format!("Read `{name}` as it is in this build."));
            report.step(
                "decompile",
                json!({ "path": other_label, "at": name }),
                format!("Read `{name}` in the other build and compare."),
            );
        }
        let first_added =
            new.iter().enumerate().find(|(index, function)| !paired_new.contains(index) && function.named());
        if let Some((_, function)) = first_added {
            report.step(
                "decompile",
                json!({ "path": other_label, "at": function.name }),
                format!("`{}` appears only in the other build.", function.name),
            );
        }
        report.sections.extend([
            changed,
            rehomed,
            added,
            removed,
            import_changes,
            string_changes,
            identical,
            name_only,
        ]);

        report.limitation(
            "Hash matching is signature-level: equal masked hashes mean the same instructions once addresses and \
             relative offsets are masked, not proven semantic equivalence; a differing hash can come from \
             compiler or layout changes as well as from logic changes.",
        );
        report.limitation(
            "Pairing uses unique names first, then hashes that occur once per build, then a recurring hash at an \
             unchanged address, then identical bytes at an unchanged address; other functions with duplicate names \
             or shared hashes (such as small stubs) stay unpaired and show as added or removed.",
        );
        report.limitation(
            "Functions matched by name only were too small or undecodable to hash: their bodies were not compared, \
             so they may differ.",
        );
        report.limitation(
            "Only discovered functions are compared; code that analysis did not reach, and data changes other than \
             readable strings, are not covered.",
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str) -> Function {
        Function { address: 0x1000, name: name.to_owned(), hash: None, size: 4 }
    }

    #[test]
    fn unpaired_functions_say_why() {
        assert_eq!(unpaired(&function("gone"), 1, 0).1, "`gone` has no counterpart by name or hash");
        let (confidence, observation) = unpaired(&function("dup"), 1, 2);
        assert_eq!(confidence, Confidence::Low);
        assert!(observation.contains("occurs once here and 2 times in the other build"), "{observation}");
        assert!(unpaired(&function("sub_1000"), 1, 1).1.starts_with("unnamed"));
    }
}
