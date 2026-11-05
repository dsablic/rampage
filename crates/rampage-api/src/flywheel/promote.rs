//! The promoted pack: every candidate that passed the held-out gate, with its provenance, as one data pack under
//! `promoted/<family>/` that `--pack` loads like any other. Each entry has a revert id; reverting rewrites the
//! pack without it, which restores exactly the state before it was promoted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::candidate::{Row, RowSource, layer, rows_hash, write_pack};
use super::engine::{Layer, SliceMetrics};
use super::evaluation::{GateConfig, GateResult, SliceDelta};
use super::{FlywheelError, Paths, read_bounded, sha256_text, write_atomic};

/// The provenance file beside the promoted pack's manifest.
pub const ENTRIES_FILE: &str = "entries.json";
const MAX_ENTRIES_BYTES: u64 = 64 * 1024 * 1024;

/// One promoted candidate with everything needed to reproduce or revert it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotedEntry {
    pub revert_id: String,
    pub family: String,
    pub candidate_id: String,
    pub candidate_hash: String,
    pub rows: Vec<Row>,
    /// The training cases the rows were made from.
    pub driving_cases: Vec<RowSource>,
    pub corpus_version: String,
    /// The split the promotion was gated on.
    pub split: String,
    /// The state it was gated against: build, bundled databases, earlier promotions and gate settings.
    pub baseline_hash: String,
    pub build_id: String,
    pub gate: GateConfig,
    pub fast: GateResult,
    pub heldout: GateResult,
    /// Held-out metrics before and after, and their deltas, per slice (not per cell).
    pub heldout_reference: BTreeMap<String, SliceMetrics>,
    pub heldout_candidate: BTreeMap<String, SliceMetrics>,
    pub heldout_deltas: BTreeMap<String, SliceDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer_run: Option<String>,
    pub promoted_unix_ms: u64,
}

/// Every promoted entry of a family, in promotion order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotedSet {
    pub schema_version: u32,
    pub family: String,
    pub entries: Vec<PromotedEntry>,
}

impl PromotedSet {
    pub fn load(paths: &Paths, family: &str) -> Result<PromotedSet, FlywheelError> {
        let path = paths.promoted(family).join(ENTRIES_FILE);
        if !path.is_file() {
            return Ok(PromotedSet { schema_version: 1, family: family.to_owned(), entries: Vec::new() });
        }
        let text = read_bounded(&path, MAX_ENTRIES_BYTES)?;
        serde_json::from_str(&text).map_err(|error| FlywheelError::Io(format!("{}: {error}", path.display())))
    }

    /// Every promoted row, in promotion order.
    pub fn rows(&self) -> Vec<Row> {
        self.entries.iter().flat_map(|entry| entry.rows.iter().cloned()).collect()
    }

    /// The SHA-256 of the promoted rows, part of every evaluation's baseline key.
    pub fn hash(&self) -> String {
        rows_hash(&self.rows())
    }

    /// Writes the provenance file and regenerates the pack from it.
    pub fn save(&self, paths: &Paths, license: &str) -> Result<(), FlywheelError> {
        let directory = paths.promoted(&self.family);
        let rows = self.rows();
        let description = format!(
            "Library-identification signature rows promoted by the rampage flywheel after a passing held-out gate; \
             {} entries with provenance in {ENTRIES_FILE}",
            self.entries.len()
        );
        write_pack(
            &directory,
            &format!("flywheel-promoted-{}", self.family),
            &format!("0.{}.0", self.entries.len()),
            license,
            "rampage flywheel promotions (see entries.json for each entry's corpus, gate result and revert id)",
            &description,
            &rows,
        )?;
        let text = serde_json::to_string_pretty(self).map_err(FlywheelError::json)?;
        write_atomic(&directory.join(ENTRIES_FILE), text.as_bytes())
    }
}

/// The promoted rows as one evaluation layer, `None` when nothing is promoted.
pub fn promoted_layer(set: &PromotedSet) -> Result<Option<Layer>, FlywheelError> {
    layer("promoted", &set.rows())
}

/// The revert id of a promotion: stable for the same candidate, corpus and baseline.
pub fn revert_id(candidate_hash: &str, corpus_version: &str, baseline_hash: &str) -> String {
    format!("rv-{}", &sha256_text(&format!("{candidate_hash}\0{corpus_version}\0{baseline_hash}"))[..12])
}

/// Removes the entry `id` from the promoted pack of `family`, regenerating the pack (under its existing licence
/// declaration), and returns it.
pub fn revert(paths: &Paths, family: &str, id: &str) -> Result<PromotedEntry, FlywheelError> {
    let manifest = paths.promoted(family).join(crate::packs::MANIFEST_FILE);
    let license = std::fs::read_to_string(&manifest)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
        .and_then(|table| table.get("license").and_then(|value| value.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "NOASSERTION".to_owned());
    let mut set = PromotedSet::load(paths, family)?;
    let Some(position) = set.entries.iter().position(|entry| entry.revert_id == id) else {
        let known: Vec<&str> = set.entries.iter().map(|entry| entry.revert_id.as_str()).collect();
        return Err(FlywheelError::Unknown(format!(
            "no promoted {family} entry has revert id {id} (promoted: {})",
            if known.is_empty() { "none".to_owned() } else { known.join(", ") }
        )));
    };
    let entry = set.entries.remove(position);
    set.save(paths, &license)?;
    Ok(entry)
}

/// An evaluation layer from any pack directory: a scratch candidate or the promoted pack by their rows (so only
/// binaries a row could match are identified again), any other pack by its signature databases (every binary is
/// identified again).
pub fn pack_layer(directory: &std::path::Path) -> Result<Option<Layer>, FlywheelError> {
    let name = directory.display().to_string();
    let candidate = directory.join(super::candidate::CANDIDATE_FILE);
    if candidate.is_file() {
        let text = read_bounded(&candidate, 16 * 1024 * 1024)?;
        let candidate: super::Candidate =
            serde_json::from_str(&text).map_err(|error| FlywheelError::Io(format!("{}: {error}", name)))?;
        return layer(&name, &candidate.rows);
    }
    let entries = directory.join(ENTRIES_FILE);
    if entries.is_file() {
        let text = read_bounded(&entries, MAX_ENTRIES_BYTES)?;
        let set: PromotedSet =
            serde_json::from_str(&text).map_err(|error| FlywheelError::Io(format!("{}: {error}", name)))?;
        return layer(&name, &set.rows());
    }
    let packs = crate::Packs::load(&[directory.to_owned()]);
    let problems = packs.problems();
    if !problems.is_empty() {
        return Err(FlywheelError::Invalid(problems.join("; ")));
    }
    let mut databases = Vec::new();
    for arch in
        [rampage_arch::Arch::X86_64, rampage_arch::Arch::Aarch64, rampage_arch::Arch::X86, rampage_arch::Arch::Arm]
    {
        databases.extend(packs.signatures_for(arch).map(|(_, database)| database.clone()));
    }
    Ok((!databases.is_empty()).then_some(Layer { name, databases, patterns: None }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flywheel::evaluation::GateCheck;

    fn entry(revert: &str, name: &str, pattern: &str) -> PromotedEntry {
        let gate = GateResult {
            stage: "heldout".to_owned(),
            passed: true,
            checks: vec![GateCheck { rule: "heldout_f1_gain".to_owned(), passed: true, detail: String::new() }],
            failing_slices: vec![],
        };
        let source = RowSource { case: "f1".to_owned(), binary: "zlib-z1".to_owned(), address: "0x401000".to_owned() };
        let row = Row {
            arch: "x86_64".to_owned(),
            name: name.to_owned(),
            library: Some("zlib".to_owned()),
            pattern: pattern.to_owned(),
            source: Some(source.clone()),
        };
        PromotedEntry {
            revert_id: revert.to_owned(),
            family: "libid".to_owned(),
            candidate_id: format!("c-{name}"),
            candidate_hash: rows_hash(std::slice::from_ref(&row)),
            rows: vec![row],
            driving_cases: vec![source],
            corpus_version: "libid-test".to_owned(),
            split: "heldout".to_owned(),
            baseline_hash: "b".to_owned(),
            build_id: "test".to_owned(),
            gate: GateConfig::default(),
            fast: GateResult { stage: "fast".to_owned(), ..gate.clone() },
            heldout: gate,
            heldout_reference: BTreeMap::new(),
            heldout_candidate: BTreeMap::new(),
            heldout_deltas: BTreeMap::new(),
            proposer_run: Some("run/round-1".to_owned()),
            promoted_unix_ms: 1,
        }
    }

    #[test]
    fn promotions_keep_provenance_and_a_revert_restores_the_earlier_pack_exactly() {
        let directory = std::env::temp_dir().join(format!("rampage-promote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let paths = Paths::new(directory.clone());
        let first = entry("rv-first", "inflate", "554889e5b834120000005dc3");
        let mut set = PromotedSet { schema_version: 1, family: "libid".to_owned(), entries: vec![first.clone()] };
        set.save(&paths, "Zlib").unwrap();
        let before = std::fs::read(paths.promoted("libid").join("sigs/x86_64.json")).unwrap();
        let before_hash = set.hash();

        set.entries.push(entry("rv-second", "deflate", "554889e5b835120000005dc3"));
        set.save(&paths, "Zlib").unwrap();
        let loaded = PromotedSet::load(&paths, "libid").unwrap();
        assert_eq!(loaded, set, "entries.json round-trips with every provenance field");
        assert!(crate::Packs::check(&paths.promoted("libid")).error.is_none(), "the promoted pack loads");

        let removed = revert(&paths, "libid", "rv-second").unwrap();
        assert_eq!(removed.candidate_id, "c-deflate");
        let after = PromotedSet::load(&paths, "libid").unwrap();
        assert_eq!(after.entries, vec![first]);
        assert_eq!(after.hash(), before_hash);
        let bytes = std::fs::read(paths.promoted("libid").join("sigs/x86_64.json")).unwrap();
        assert_eq!(bytes, before, "the same pack bytes as before the second promotion");
        let manifest = std::fs::read_to_string(paths.promoted("libid").join("rampage-pack.toml")).unwrap();
        assert!(manifest.contains("license = \"Zlib\""), "{manifest}");

        assert_eq!(revert(&paths, "libid", "rv-second").unwrap_err().kind(), "not_found");
        revert(&paths, "libid", "rv-first").unwrap();
        assert!(promoted_layer(&PromotedSet::load(&paths, "libid").unwrap()).unwrap().is_none());
        assert!(!paths.promoted("libid").join("sigs/x86_64.json").exists(), "an empty pack holds no database");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn revert_ids_are_stable_for_the_same_candidate_corpus_and_baseline() {
        assert_eq!(revert_id("h", "v1", "b"), revert_id("h", "v1", "b"));
        assert_ne!(revert_id("h", "v1", "b"), revert_id("h", "v2", "b"));
        assert_ne!(revert_id("h", "v1", "b"), revert_id("h", "v1", "c"));
    }
}
