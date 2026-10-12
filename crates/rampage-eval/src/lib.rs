//! Self-supervised evaluation of library-function identification.
//!
//! Strip-and-compare: a symbolized build and a stripped twin come from the same source and toolchain, so the
//! symbolized twin's symbol table is ground truth ([`Truth`]) for the stripped one. [`evaluate`] discovers the
//! stripped target's functions, asks a [`SignatureDb`] to name each, and scores every proposal against the truth
//! into a [`Report`]: precision/recall plus a machine-readable disagreement set. `Report` and [`Disagreement`]
//! are deliberately family-agnostic so other heuristics (discovery, type recovery) can share one gate.

use std::collections::BTreeMap;

use rampage_arch::UnsupportedArch;
use rampage_loaders::{Binary, SymbolKind};
use rampage_signatures::{SignatureDb, alias_rank};
use serde::{Deserialize, Serialize};

/// Known function names by address, taken from a symbolized twin of the evaluated binary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Truth(pub BTreeMap<u64, String>);

impl Truth {
    /// Every function symbol with a nonzero size. Where several names share an address, the public spelling
    /// wins (musl exports `strchrnul` as a weak alias of `__strchrnul`): no leading underscore, then shortest,
    /// then alphabetical, so the choice is deterministic.
    pub fn from_binary(binary: &Binary) -> Truth {
        let mut names: BTreeMap<u64, &str> = BTreeMap::new();
        let functions = binary
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == SymbolKind::Function && symbol.size > 0 && !symbol.name.is_empty());
        for symbol in functions {
            let slot = names.entry(symbol.address).or_insert(&symbol.name);
            if alias_rank(&symbol.name) < alias_rank(slot) {
                *slot = &symbol.name;
            }
        }
        Truth(names.into_iter().map(|(address, name)| (address, name.to_owned())).collect())
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
    /// Every non-correct address, sorted by address.
    pub disagreements: Vec<Disagreement>,
}

impl Report {
    /// The hard gate: no wrong name and no library name where there is none. Missed names lower recall but
    /// never fail, since a heuristic declining to answer is safe.
    pub fn passes_gate(&self) -> bool {
        self.wrong == 0 && self.spurious == 0
    }

    pub fn summary(&self) -> String {
        format!(
            "correct={} wrong={} missed={} spurious={} precision={:.3} recall={:.3}",
            self.correct, self.wrong, self.missed, self.spurious, self.precision, self.recall
        )
    }
}

/// Reports keyed by slice (an architecture, a compiler, an optimization level). Kept per slice rather than
/// pooled so a change that helps one slice cannot hide a regression in another.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Evaluation {
    pub slices: BTreeMap<String, Report>,
}

impl Evaluation {
    /// Every slice passes [`Report::passes_gate`].
    pub fn passes_gate(&self) -> bool {
        self.slices.values().all(Report::passes_gate)
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
    }
}

/// The name `db` proposes for each function discovered in `target`, in address order.
pub fn proposals(db: &SignatureDb, target: &Binary) -> Result<Vec<(u64, Option<String>)>, UnsupportedArch> {
    let program = rampage_analysis::functions::analyze(target)?;
    let arch = target.target();
    Ok(program
        .functions
        .iter()
        .map(|function| {
            // Same body extent `rampage identify` hashes, so the eval measures what users get.
            let end = function.blocks.iter().map(|block| block.end).max().unwrap_or(function.address);
            let name = end
                .checked_sub(function.address)
                .filter(|&length| length > 0)
                .and_then(|length| target.read(function.address, length))
                .and_then(|bytes| db.identify(&arch, bytes, function.address))
                .map(str::to_owned);
            (function.address, name)
        })
        .collect())
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

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 { 0.0 } else { numerator as f64 / denominator as f64 }
}

#[cfg(test)]
mod tests {
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
