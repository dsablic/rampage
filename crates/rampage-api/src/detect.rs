//! Heuristic-database detection over a loaded binary: producing-tool identification (`rampage-detect`), YARA
//! scanning (`rampage-yara`) and capa-rule evaluation (`rampage-capabilities`). Every result is triage evidence,
//! not proof.

use std::path::Path;

use rampage_capabilities::{CapaRuleSet, Capability};
use rampage_detect::{Detection, SignatureDb, identify};
use rampage_yara::YaraMatch;
use serde::Serialize;

use crate::{ApiError, Project};

/// PeID warnings reported individually; the rest are counted, so a huge broken database cannot flood the output.
const MAX_PEID_WARNINGS: usize = 20;

#[derive(Debug, Serialize)]
pub struct ToolDetections {
    pub detections: Vec<Detection>,
    /// PeID database entries and lines that were skipped, so that a partly broken database is not silently
    /// treated as complete. At most [`MAX_PEID_WARNINGS`] are listed, followed by a count of the rest.
    pub warnings: Vec<String>,
}

impl Project {
    /// Identify the tools that likely produced this binary (packer, compiler, protector, installer, linker) from
    /// the bundled heuristic database, optionally extended with user-supplied PeID `userdb.txt` text.
    /// PeID signatures from data packs are overlaid too.
    pub fn detect_tools(&self, peid: Option<&str>) -> Result<ToolDetections, ApiError> {
        let mut db = SignatureDb::bundled();
        db.signatures.extend(self.packs().peid().signatures.iter().cloned());
        let mut warnings = Vec::new();
        if let Some(text) = peid {
            let skipped = db.load_peid(text).map_err(|error| ApiError::Invalid(format!("PeID database: {error}")))?;
            warnings.extend(skipped.iter().take(MAX_PEID_WARNINGS).map(|warning| format!("PeID database: {warning}")));
            if skipped.len() > MAX_PEID_WARNINGS {
                let more = skipped.len() - MAX_PEID_WARNINGS;
                warnings.push(format!("PeID database: ... and {more} more problems skipped"));
            }
        }
        Ok(ToolDetections { detections: identify(&self.binary, &db), warnings })
    }

    /// Scan this binary's image bytes with the given YARA rule source, then with the data packs' rules, returning
    /// the matching rules. The rules are user-supplied; a compile error is reported, not swallowed.
    pub fn yara_scan(&self, rules_source: &str) -> Result<Vec<YaraMatch>, ApiError> {
        let rules =
            rampage_yara::compile(rules_source).map_err(|error| ApiError::Invalid(format!("YARA rules: {error}")))?;
        self.yara_scan_with(Some(&rules))
    }

    /// Scan this binary with YARA rules read from a path (a single `.yar`/`.yara` file, or a directory of them),
    /// then with the data packs' rules.
    pub fn yara_scan_path(&self, path: &Path) -> Result<Vec<YaraMatch>, ApiError> {
        let rules = if path.is_dir() { rampage_yara::compile_dir(path) } else { rampage_yara::compile_files(&[path]) }
            .map_err(|error| ApiError::Invalid(format!("YARA rules: {error}")))?;
        self.yara_scan_with(Some(&rules))
    }

    /// Scan this binary with the data packs' YARA rules alone; an error when no pack holds any.
    pub fn yara_scan_packs(&self) -> Result<Vec<YaraMatch>, ApiError> {
        self.yara_scan_with(None)
    }

    fn yara_scan_with(&self, user: Option<&rampage_yara::Rules>) -> Result<Vec<YaraMatch>, ApiError> {
        let packs = self.packs();
        if user.is_none() && packs.yara().is_empty() {
            return Err(ApiError::Invalid("no YARA rules: pass rules or load a pack with yara contents".to_owned()));
        }
        let mut matches = Vec::new();
        for rules in user.into_iter().chain(packs.yara()) {
            let found = rampage_yara::scan_binary(rules, &self.binary)
                .map_err(|error| ApiError::Invalid(format!("YARA scan: {error}")))?;
            matches.extend(found);
        }
        Ok(matches)
    }

    /// Evaluate the capa rules under `rules_dir`, then the data packs' capa rules, against this binary's imports,
    /// exports and strings. Only the file-scope feature subset rampage can assess is evaluated (see
    /// `rampage_capabilities::capa`).
    pub fn detect_capa(&self, rules_dir: &Path) -> Result<Vec<Capability>, ApiError> {
        let rules = rampage_capabilities::load_capa_rules(rules_dir)
            .map_err(|error| ApiError::Invalid(format!("capa rules: {error}")))?;
        self.detect_capa_with(Some(&rules))
    }

    /// Evaluate the data packs' capa rules alone; an error when no pack holds any.
    pub fn detect_capa_packs(&self) -> Result<Vec<Capability>, ApiError> {
        self.detect_capa_with(None)
    }

    fn detect_capa_with(&self, user: Option<&CapaRuleSet>) -> Result<Vec<Capability>, ApiError> {
        let packs = self.packs();
        if user.is_none() && packs.capa().is_empty() {
            return Err(ApiError::Invalid(
                "no capa rules: pass a rule directory or load a pack with capa contents".to_owned(),
            ));
        }
        let (imports, strings) = self.capability_inputs();
        let exports: Vec<String> = self.binary.exports.iter().map(|export| export.name.clone()).collect();
        Ok(user
            .into_iter()
            .chain(packs.capa())
            .flat_map(|rules| rampage_capabilities::detect_capa_with_exports(rules, &imports, &exports, &strings))
            .collect())
    }
}
