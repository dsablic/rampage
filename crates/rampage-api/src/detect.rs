//! Heuristic-database detection over a loaded binary: producing-tool identification (`rampage-detect`), YARA
//! scanning (`rampage-yara`) and capa-rule evaluation (`rampage-capabilities`). Every result is triage evidence,
//! not proof.

use std::path::Path;

use rampage_capabilities::Capability;
use rampage_detect::{Detection, SignatureDb, identify};
use rampage_yara::YaraMatch;
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct ToolDetections {
    pub detections: Vec<Detection>,
    /// PeID database entries and lines that were skipped, so that a partly broken database is not silently
    /// treated as complete.
    pub warnings: Vec<String>,
}

impl Project {
    /// Identify the tools that likely produced this binary (packer, compiler, protector, installer, linker) from
    /// the bundled heuristic database, optionally extended with user-supplied PeID `userdb.txt` text.
    pub fn detect_tools(&self, peid: Option<&str>) -> Result<ToolDetections, ApiError> {
        let mut db = SignatureDb::bundled();
        let mut warnings = Vec::new();
        if let Some(text) = peid {
            let skipped = db.load_peid(text).map_err(|error| ApiError::Invalid(format!("PeID database: {error}")))?;
            warnings.extend(skipped.iter().map(|warning| format!("PeID database: {warning}")));
        }
        Ok(ToolDetections { detections: identify(&self.binary, &db), warnings })
    }

    /// Scan this binary's image bytes with the given YARA rule source, returning the matching rules. The rules
    /// are user-supplied; a compile error is reported, not swallowed.
    pub fn yara_scan(&self, rules_source: &str) -> Result<Vec<YaraMatch>, ApiError> {
        let rules =
            rampage_yara::compile(rules_source).map_err(|error| ApiError::Invalid(format!("YARA rules: {error}")))?;
        rampage_yara::scan_binary(&rules, &self.binary)
            .map_err(|error| ApiError::Invalid(format!("YARA scan: {error}")))
    }

    /// Scan this binary with YARA rules read from a path: a single `.yar`/`.yara` file, or a directory of them.
    pub fn yara_scan_path(&self, path: &Path) -> Result<Vec<YaraMatch>, ApiError> {
        let rules = if path.is_dir() { rampage_yara::compile_dir(path) } else { rampage_yara::compile_files(&[path]) }
            .map_err(|error| ApiError::Invalid(format!("YARA rules: {error}")))?;
        rampage_yara::scan_binary(&rules, &self.binary)
            .map_err(|error| ApiError::Invalid(format!("YARA scan: {error}")))
    }

    /// Evaluate the capa rules under `rules_dir` against this binary's imports and strings. Only the file-scope
    /// feature subset rampage can assess is evaluated (see `rampage_capabilities::capa`).
    pub fn detect_capa(&self, rules_dir: &Path) -> Result<Vec<Capability>, ApiError> {
        let rules = rampage_capabilities::load_capa_rules(rules_dir)
            .map_err(|error| ApiError::Invalid(format!("capa rules: {error}")))?;
        let (imports, strings) = self.capability_inputs();
        Ok(rampage_capabilities::detect_capa(&rules, &imports, &strings))
    }
}
