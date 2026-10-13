//! Self-supervised evaluation of rampage heuristics against strip-and-compare ground truth.
//!
//! A symbolized build and a stripped twin come from the same source and toolchain, so the symbolized twin's
//! symbol table is ground truth ([`Truth`]) for the stripped one. Each heuristic family scores into the same
//! family-agnostic [`Report`]: precision/recall plus a machine-readable disagreement set.
//!
//! - Library identification ([`evaluate`]): discover the stripped target's functions, ask a [`SignatureDb`] to
//!   name each, and compare every proposed name with the truth.
//! - Function discovery ([`evaluate_discovery`]): compare the discovered function starts with the truth's
//!   addresses; names only label the disagreements.
//! - Tool identification ([`score_tools`]): compare the compilers, linkers and packers `detect_tools` names for
//!   each committed fixture with the toolchain its build script used ([`ToolTruth`]).
//!
//! Whether a report is acceptable depends on the family, so the pass/fail rule is a separate [`Gate`].

mod toolid;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::UnsupportedArch;
use rampage_loaders::Binary;
use rampage_signatures::{MaskContext, SignatureDb, canonical_functions, identify_program, named_functions};
use serde::{Deserialize, Serialize};
pub use toolid::{
    DetectedTool, ExpectedTool, TOOL_KINDS, ToolBinary, ToolDisagreement, ToolTruth, Toolchain, detected_tools,
    kind_tag, score_tools,
};

/// Known function names by address, taken from a symbolized twin of the evaluated binary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Truth(pub BTreeMap<u64, String>);

impl Truth {
    /// Every function symbol with a nonzero size. Where several names share an address, the public spelling
    /// wins (musl exports `strchrnul` as a weak alias of `__strchrnul`): no leading underscore, then shortest,
    /// then alphabetical, so the choice is deterministic.
    pub fn from_binary(binary: &Binary) -> Truth {
        Truth(canonical_functions(binary).into_iter().map(|(address, symbol)| (address, symbol.name.clone())).collect())
    }

    /// Only what a signature database built from library references could name: entries whose name is in
    /// `library` (see [`function_names`]) and not in `program`. A cross-program target also contains its own
    /// code that no library signature describes; counting it as missed would measure the program, not the
    /// heuristic. A name match alone is not enough to exclude it, since every program defines `main`, so the
    /// programs' own functions (taken from their compiled objects) are dropped explicitly.
    pub fn identifiable(&self, library: &BTreeSet<String>, program: &BTreeSet<String>) -> Truth {
        let keep = |name: &String| library.contains(name) && !program.contains(name);
        Truth(self.0.iter().filter(|(_, name)| keep(name)).map(|(address, name)| (*address, name.clone())).collect())
    }

    /// Parses `{ "0x<address>": "<name>" }`.
    pub fn from_json(text: &str) -> Result<Truth, serde_json::Error> {
        let raw: BTreeMap<String, String> = serde_json::from_str(text)?;
        let mut entries = BTreeMap::new();
        for (key, name) in raw {
            let address = key
                .strip_prefix("0x")
                .and_then(|digits| u64::from_str_radix(digits, 16).ok())
                .ok_or_else(|| serde::de::Error::custom(format!("truth key {key:?} is not a 0x address")))?;
            entries.insert(address, name);
        }
        Ok(Truth(entries))
    }

    /// Serializes as `{ "0x<address>": "<name>" }`, one entry per line so diffs of a committed truth stay small.
    /// Entries are in numeric address order, which a string-keyed map would not keep.
    pub fn to_json(&self) -> String {
        let lines: Vec<String> = self
            .0
            .iter()
            .map(|(address, name)| format!("  \"{address:#x}\": {}", serde_json::Value::from(name.as_str())))
            .collect();
        if lines.is_empty() { "{}\n".to_owned() } else { format!("{{\n{}\n}}\n", lines.join(",\n")) }
    }
}

/// Every sized function symbol's name in `binary`, aliases included. Unlike [`Truth::from_binary`] this keeps
/// every spelling and is not keyed by address, so it also works on a relocatable object, where functions in
/// different sections share address zero.
pub fn function_names(binary: &Binary) -> BTreeSet<String> {
    named_functions(binary).map(|symbol| symbol.name.clone()).collect()
}

/// How one scored address came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Correct,
    Wrong,
    Missed,
    Spurious,
}

/// One address where the heuristic and the truth do not agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disagreement {
    #[serde(
        serialize_with = "rampage_arch::hex::address",
        deserialize_with = "rampage_arch::hex::deserialize_address"
    )]
    pub address: u64,
    pub proposed: Option<String>,
    pub truth: Option<String>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub precision: f64,
    pub recall: f64,
    pub correct: usize,
    pub wrong: usize,
    pub missed: usize,
    pub spurious: usize,
    /// Every non-correct address, sorted by address, unless bounded by [`Report::truncate_disagreements`].
    pub disagreements: Vec<Disagreement>,
    /// Tool identification's disagreements, which name a binary and a tool rather than an address; sorted by
    /// binary, kind and name, and bounded like `disagreements`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_disagreements: Vec<ToolDisagreement>,
    /// How many disagreements were dropped from the end of the lists; the counts above still cover them.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted: usize,
}

impl Report {
    /// Keeps at most `limit` entries in each disagreement list, preferring wrong, then missed, then spurious ones
    /// (the order a reviewer acts on them), each kind in the list's own order.
    pub fn truncate_disagreements(&mut self, limit: usize) {
        self.omitted += keep_most_actionable(
            &mut self.disagreements,
            limit,
            |entry| entry.outcome,
            |a, b| a.address.cmp(&b.address),
        );
        self.omitted +=
            keep_most_actionable(&mut self.tool_disagreements, limit, |entry| entry.outcome, ToolDisagreement::order);
    }

    pub fn summary(&self) -> String {
        format!(
            "correct={} wrong={} missed={} spurious={} precision={:.3} recall={:.3}",
            self.correct, self.wrong, self.missed, self.spurious, self.precision, self.recall
        )
    }
}

/// What a slice's [`Report`] must satisfy. `wrong` must always be zero: a confidently wrong answer misleads.
/// The default is the library-identification gate: no spurious names either, and no recall floor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Gate {
    /// Spurious answers are tolerated. Function discovery sets this: a binary legitimately contains code with no
    /// sized symbol (assembly entry points such as `_start` have no `.size`), so a start the truth lacks is not
    /// necessarily wrong. Spurious starts still lower precision and are listed for review; failing on each one
    /// would make the gate fire on correct discoveries, so [`Gate::min_precision`] bounds them instead.
    #[serde(default)]
    pub allow_spurious: bool,
    /// The committed recall baseline; a measured recall below it fails. Raise it only when a measured
    /// improvement lands.
    #[serde(default)]
    pub min_recall: f64,
    /// The committed precision baseline, for slices that allow spurious answers (with none allowed, precision is
    /// already 1 or there is no answer at all).
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub min_precision: f64,
}

impl Gate {
    /// Why `report` fails this gate; empty when it passes.
    pub fn check(&self, report: &Report) -> Vec<String> {
        let mut failures = Vec::new();
        if report.wrong > 0 {
            failures.push(format!("{} wrong", report.wrong));
        }
        if report.spurious > 0 && !self.allow_spurious {
            failures.push(format!("{} spurious", report.spurious));
        }
        // Tolerates the float noise of a baseline written with a few decimals.
        if report.recall + 1e-9 < self.min_recall {
            failures.push(format!("recall {:.4} below baseline {:.4}", report.recall, self.min_recall));
        }
        if report.precision + 1e-9 < self.min_precision {
            failures.push(format!("precision {:.4} below baseline {:.4}", report.precision, self.min_precision));
        }
        failures
    }
}

/// Reports keyed by slice (a heuristic family on an architecture, a compiler, an optimization level). Kept per
/// slice rather than pooled so a change that helps one slice cannot hide a regression in another.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Evaluation {
    pub slices: BTreeMap<String, Report>,
    /// Each slice's gate; a slice without one is held to [`Gate::default`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gates: BTreeMap<String, Gate>,
}

impl Evaluation {
    pub fn insert(&mut self, slice: String, report: Report, gate: Gate) {
        self.gates.insert(slice.clone(), gate);
        self.slices.insert(slice, report);
    }

    /// Each failing slice with the reasons it fails its gate.
    pub fn failures(&self) -> BTreeMap<&str, Vec<String>> {
        self.slices
            .iter()
            .map(|(name, report)| (name.as_str(), self.gates.get(name).copied().unwrap_or_default().check(report)))
            .filter(|(_, failures)| !failures.is_empty())
            .collect()
    }

    /// Every slice passes its gate.
    pub fn passes_gate(&self) -> bool {
        self.failures().is_empty()
    }
}

/// Classifies one address, or `None` when neither side names it (nothing to score).
pub fn classify(proposed: Option<&str>, truth: Option<&str>) -> Option<Outcome> {
    match (proposed, truth) {
        (Some(proposed), Some(truth)) if proposed == truth => Some(Outcome::Correct),
        (Some(_), Some(_)) => Some(Outcome::Wrong),
        (None, Some(_)) => Some(Outcome::Missed),
        (Some(_), None) => Some(Outcome::Spurious),
        (None, None) => None,
    }
}

/// Scores `proposals` (one per discovered function: its address and the proposed name, if any) against `truth`.
/// A truth address with no proposal entry at all -- a function discovery never found -- counts as missed, so
/// recall reflects discovery gaps rather than hiding them.
pub fn score(proposals: impl IntoIterator<Item = (u64, Option<String>)>, truth: &Truth) -> Report {
    let mut proposed: BTreeMap<u64, Option<String>> = proposals.into_iter().collect();
    for address in truth.0.keys() {
        proposed.entry(*address).or_insert(None);
    }

    let (mut correct, mut wrong, mut missed, mut spurious) = (0, 0, 0, 0);
    let mut disagreements = Vec::new();
    for (address, proposal) in proposed {
        let known = truth.0.get(&address);
        let Some(outcome) = classify(proposal.as_deref(), known.map(String::as_str)) else { continue };
        match outcome {
            Outcome::Correct => {
                correct += 1;
                continue;
            }
            Outcome::Wrong => wrong += 1,
            Outcome::Missed => missed += 1,
            Outcome::Spurious => spurious += 1,
        }
        disagreements.push(Disagreement { address, proposed: proposal, truth: known.cloned(), outcome });
    }
    Report {
        precision: ratio(correct, correct + wrong + spurious),
        recall: ratio(correct, correct + missed),
        correct,
        wrong,
        missed,
        spurious,
        disagreements,
        tool_disagreements: Vec::new(),
        omitted: 0,
    }
}

/// Scores discovered function starts against `truth`'s addresses: a discovered truth address is correct, an
/// undiscovered one missed, and a discovered start the truth lacks spurious (with no name on either side). A
/// discovery answer cannot be wrong, only absent or extra.
pub fn score_discovery(starts: impl IntoIterator<Item = u64>, truth: &Truth) -> Report {
    let starts: BTreeSet<u64> = starts.into_iter().collect();
    let mut disagreements: Vec<Disagreement> = truth
        .0
        .iter()
        .filter(|(address, _)| !starts.contains(address))
        .map(|(&address, name)| Disagreement {
            address,
            proposed: None,
            truth: Some(name.clone()),
            outcome: Outcome::Missed,
        })
        .collect();
    let missed = disagreements.len();
    disagreements.extend(starts.iter().filter(|address| !truth.0.contains_key(address)).map(|&address| Disagreement {
        address,
        proposed: None,
        truth: None,
        outcome: Outcome::Spurious,
    }));
    let spurious = disagreements.len() - missed;
    disagreements.sort_by_key(|entry| entry.address);
    let correct = truth.0.len() - missed;
    Report {
        precision: ratio(correct, correct + spurious),
        recall: ratio(correct, correct + missed),
        correct,
        wrong: 0,
        missed,
        spurious,
        disagreements,
        tool_disagreements: Vec::new(),
        omitted: 0,
    }
}

/// Every function start discovery finds in `target`, the same analysis the API and the eval's proposals use.
pub fn discovered_starts(target: &Binary) -> Result<Vec<u64>, UnsupportedArch> {
    Ok(rampage_analysis::functions::analyze(target)?.functions.iter().map(|function| function.address).collect())
}

/// Discovers `target`'s functions and scores their starts against `truth`.
pub fn evaluate_discovery(target: &Binary, truth: &Truth) -> Result<Report, UnsupportedArch> {
    Ok(score_discovery(discovered_starts(target)?, truth))
}

/// The name `db` proposes for each function discovered in `target`, in address order.
pub fn proposals(db: &SignatureDb, target: &Binary) -> Result<Vec<(u64, Option<String>)>, UnsupportedArch> {
    let program = rampage_analysis::functions::analyze(target)?;
    // The same bodies (`DiscoveredFunction::body`) and the same program-wide identification `rampage identify`
    // uses, so the eval measures what users get.
    let bodies: Vec<(u64, &[u8])> =
        program.functions.iter().filter_map(|function| Some((function.address, function.body(target)?))).collect();
    let names = identify_program(&[db], &target.target(), &MaskContext::from_binary(target), &bodies);
    Ok(program
        .functions
        .iter()
        .map(|function| (function.address, names.get(&function.address).map(|name| name.to_string())))
        .collect())
}

/// Each function discovery finds in `binary`, its start mapped to the end of its body: the reference extents a
/// signature database is also built over (`SignatureDb::from_binary_with_extents`). Identification hashes the
/// extents discovery finds in the target, which match these only where discovery stops at the same place in both.
pub fn discovered_extents(binary: &Binary) -> Result<BTreeMap<u64, u64>, UnsupportedArch> {
    let program = rampage_analysis::functions::analyze(binary)?;
    Ok(program.functions.iter().map(|function| (function.address, function.end())).collect())
}

/// Discovers `target`'s functions, identifies them with `db` and scores the result against `truth`.
pub fn evaluate(db: &SignatureDb, target: &Binary, truth: &Truth) -> Result<Report, UnsupportedArch> {
    Ok(score(proposals(db, target)?, truth))
}

/// Rewrites an ELF without its debug sections and, unless `keep_symbols`, without its symbol table, leaving
/// every loaded byte at its original address. Linking a second time with `--strip-all` is not equivalent: zig
/// then builds libc without debug info and the code shifts, so the symbolized twin would no longer describe it.
pub fn strip(elf: &[u8], keep_symbols: bool) -> Result<Vec<u8>, String> {
    let mut builder = object::build::elf::Builder::read(elf).map_err(|error| error.to_string())?;
    for section in builder.sections.iter_mut() {
        let name: &[u8] = &section.name;
        let symbols = matches!(name, b".symtab" | b".strtab" | b".symtab_shndx");
        if name.starts_with(b".debug") || (symbols && !keep_symbols) {
            section.delete = true;
        }
    }
    if !keep_symbols {
        for symbol in builder.symbols.iter_mut() {
            symbol.delete = true;
        }
    }
    let mut output = Vec::new();
    builder.write(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}

/// Truncates `entries` to `limit`, dropping the least actionable first, and returns how many were dropped.
fn keep_most_actionable<T>(
    entries: &mut Vec<T>,
    limit: usize,
    outcome: impl Fn(&T) -> Outcome,
    order: impl Fn(&T, &T) -> Ordering,
) -> usize {
    if entries.len() <= limit {
        return 0;
    }
    let severity =
        |entry: &T| [Outcome::Wrong, Outcome::Missed, Outcome::Spurious].iter().position(|o| *o == outcome(entry));
    entries.sort_by(|a, b| severity(a).cmp(&severity(b)).then_with(|| order(a, b)));
    let dropped = entries.len() - limit;
    entries.truncate(limit);
    entries.sort_by(order);
    dropped
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 }
}

#[cfg(test)]
mod tests {
    use rampage_signatures::alias_rank;

    use super::*;

    fn truth(entries: &[(u64, &str)]) -> Truth {
        Truth(entries.iter().map(|&(address, name)| (address, name.to_owned())).collect())
    }

    fn named(address: u64, name: &str) -> (u64, Option<String>) {
        (address, Some(name.to_owned()))
    }

    #[test]
    fn classify_covers_every_outcome() {
        assert_eq!(classify(Some("a"), Some("a")), Some(Outcome::Correct));
        assert_eq!(classify(Some("a"), Some("b")), Some(Outcome::Wrong));
        assert_eq!(classify(None, Some("b")), Some(Outcome::Missed));
        assert_eq!(classify(Some("a"), None), Some(Outcome::Spurious));
        assert_eq!(classify(None, None), None);
    }

    #[test]
    fn score_counts_each_category_and_computes_rates() {
        let truth = truth(&[(0x10, "memcpy"), (0x20, "strlen"), (0x30, "free"), (0x40, "main")]);
        let proposals =
            vec![named(0x10, "memcpy"), named(0x20, "strnlen"), (0x30, None), named(0x50, "malloc"), (0x60, None)];
        let report = score(proposals, &truth);
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (1, 1, 2, 1));
        assert!((report.precision - 1.0 / 3.0).abs() < 1e-12);
        assert!((report.recall - 1.0 / 3.0).abs() < 1e-12);
        let outcomes: Vec<(u64, Outcome)> =
            report.disagreements.iter().map(|entry| (entry.address, entry.outcome)).collect();
        assert_eq!(
            outcomes,
            [(0x20, Outcome::Wrong), (0x30, Outcome::Missed), (0x40, Outcome::Missed), (0x50, Outcome::Spurious)]
        );
        assert_eq!(report.disagreements[0].proposed.as_deref(), Some("strnlen"));
        assert_eq!(report.disagreements[0].truth.as_deref(), Some("strlen"));
    }

    #[test]
    fn rates_are_zero_not_nan_when_there_is_nothing_to_divide() {
        let report = score(Vec::new(), &Truth::default());
        assert_eq!((report.precision, report.recall), (0.0, 0.0));
        assert!(report.disagreements.is_empty());

        let report = score(vec![(0x10, None)], &truth(&[(0x10, "main")]));
        assert_eq!((report.precision, report.recall, report.missed), (0.0, 0.0, 1));
    }

    #[test]
    fn one_failing_slice_fails_the_whole_evaluation() {
        let clean = score(vec![named(0x10, "memcpy")], &truth(&[(0x10, "memcpy")]));
        let spurious = score(vec![named(0x10, "memcpy")], &Truth::default());
        let mut evaluation = Evaluation::default();
        evaluation.slices.insert("x86_64".to_owned(), clean);
        assert!(evaluation.passes_gate());
        evaluation.slices.insert("aarch64".to_owned(), spurious);
        assert!(!evaluation.passes_gate());
    }

    #[test]
    fn identifiable_keeps_library_names_the_program_does_not_define() {
        let names = |names: &[&str]| names.iter().map(|name| name.to_string()).collect::<BTreeSet<String>>();
        let target = truth(&[(0x10, "memcpy"), (0x20, "main"), (0x30, "strchrnul"), (0x40, "helper")]);
        let library = names(&["memcpy", "main", "__strchrnul", "strchrnul", "malloc"]);
        let program = names(&["main", "helper"]);
        assert_eq!(target.identifiable(&library, &program), truth(&[(0x10, "memcpy"), (0x30, "strchrnul")]));
        assert_eq!(target.identifiable(&library, &BTreeSet::new()).0.len(), 3);
        assert_eq!(target.identifiable(&BTreeSet::new(), &program), Truth::default());
    }

    #[test]
    fn score_discovery_counts_found_missed_and_extra_starts() {
        let truth = truth(&[(0x10, "main"), (0x20, "helper"), (0x30, "memcpy")]);
        let report = score_discovery([0x30, 0x10, 0x15, 0x40], &truth);
        assert_eq!((report.correct, report.wrong, report.missed, report.spurious), (2, 0, 1, 2));
        assert!((report.precision - 0.5).abs() < 1e-12);
        assert!((report.recall - 2.0 / 3.0).abs() < 1e-12);
        let entries: Vec<(u64, Outcome, Option<&str>)> =
            report.disagreements.iter().map(|entry| (entry.address, entry.outcome, entry.truth.as_deref())).collect();
        assert_eq!(
            entries,
            [(0x15, Outcome::Spurious, None), (0x20, Outcome::Missed, Some("helper")), (0x40, Outcome::Spurious, None)]
        );
        assert!(report.disagreements.iter().all(|entry| entry.proposed.is_none()));
        assert_eq!(score_discovery([], &Truth::default()).recall, 0.0);
    }

    #[test]
    fn truncation_keeps_the_most_actionable_disagreements_and_counts_the_rest() {
        let truth = truth(&[(0x10, "a"), (0x20, "b"), (0x30, "c")]);
        let mut report = score(vec![named(0x05, "x"), named(0x10, "z"), (0x20, None), named(0x40, "y")], &truth);
        assert_eq!(report.disagreements.len(), 5);
        report.truncate_disagreements(5);
        assert_eq!(report.omitted, 0);
        report.truncate_disagreements(2);
        let kept: Vec<(u64, Outcome)> =
            report.disagreements.iter().map(|entry| (entry.address, entry.outcome)).collect();
        assert_eq!(kept, [(0x10, Outcome::Wrong), (0x20, Outcome::Missed)]);
        assert_eq!((report.omitted, report.spurious, report.missed), (3, 2, 2));
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"omitted\":3"), "{json}");
        assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);
    }

    #[test]
    fn gate_rules_follow_the_family() {
        let truth = truth(&[(0x10, "a"), (0x20, "b")]);
        let discovery = score_discovery([0x10, 0x15], &truth);
        assert_eq!(Gate::default().check(&discovery), ["1 spurious"]);
        let tolerant = Gate { allow_spurious: true, min_recall: 0.5, min_precision: 0.5 };
        assert!(tolerant.check(&discovery).is_empty());
        let raised = Gate { allow_spurious: true, min_recall: 0.75, min_precision: 0.6 };
        assert_eq!(
            raised.check(&discovery),
            ["recall 0.5000 below baseline 0.7500", "precision 0.5000 below baseline 0.6000"]
        );
        let tolerant = Gate { min_precision: 0.0, ..tolerant };
        let wrong = score(vec![named(0x10, "z")], &truth);
        assert_eq!(tolerant.check(&wrong), ["1 wrong", "recall 0.0000 below baseline 0.5000"]);

        let mut evaluation = Evaluation::default();
        evaluation.insert("discovery-x".to_owned(), discovery.clone(), tolerant);
        assert!(evaluation.passes_gate());
        evaluation.insert("libid-x".to_owned(), discovery, Gate::default());
        assert_eq!(evaluation.failures().keys().collect::<Vec<_>>(), [&"libid-x"]);
        let json = serde_json::to_string(&evaluation).unwrap();
        assert_eq!(serde_json::from_str::<Evaluation>(&json).unwrap(), evaluation);
    }

    #[test]
    fn alias_preference_picks_the_public_spelling() {
        let mut names = ["__strchrnul", "strchrnul", "__libc_strchrnul"];
        names.sort_by_key(|name| alias_rank(name));
        assert_eq!(names[0], "strchrnul");
        assert!(alias_rank("free") < alias_rank("cfree"));
        assert!(alias_rank("abs") < alias_rank("abt"));
    }

    #[test]
    fn truth_round_trips_through_hex_keyed_json() {
        let original = truth(&[(0x1000, "memcpy"), (0xffff_ffff_ffff_0000, "high")]);
        let json = original.to_json();
        assert!(json.contains("\"0x1000\": \"memcpy\""), "{json}");
        assert!(json.find("0x1000") < json.find("0xffff"), "not in address order: {json}");
        assert_eq!(Truth::from_json(&json).unwrap(), original);
        assert!(Truth::from_json("{\"1000\":\"x\"}").is_err());
    }

    #[test]
    fn report_serializes_addresses_as_hex_and_round_trips() {
        let report = score(vec![named(0x2a, "x")], &Truth::default());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"address\":\"0x2a\""), "{json}");
        assert!(json.contains("\"outcome\":\"spurious\""), "{json}");
        assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);
    }
}
