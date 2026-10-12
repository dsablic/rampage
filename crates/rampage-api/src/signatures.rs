//! Library-function identification: build a signature database from a binary whose functions are named, and
//! apply one to name the matching functions of another binary (see `rampage-signatures`).

use rampage_signatures::{MaskContext, SignatureDb};
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct SignatureMatch {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The name the signature database proposes.
    pub name: String,
    /// Whether the function is currently unnamed (a `sub_<hex>` default), so naming it adds information.
    pub unnamed: bool,
}

#[derive(Debug, Serialize)]
pub struct SignatureApplication {
    pub matched: usize,
    pub applied: usize,
    pub matches: Vec<SignatureMatch>,
}

impl Project {
    /// Builds a signature database from this binary's named functions.
    pub fn build_signatures(&self) -> SignatureDb {
        SignatureDb::from_binary(&self.binary)
    }

    /// Identifies discovered functions against `database`. When `apply` is set, matches for functions that are
    /// still unnamed are saved as user names (existing names and user edits are never overwritten).
    pub fn apply_signatures(&self, database: &SignatureDb, apply: bool) -> Result<SignatureApplication, ApiError> {
        self.apply_layered_signatures(&[database], apply)
    }

    /// Identifies discovered functions against each database in order; the first that names a function wins.
    /// Layering instead of merging lets databases built with different hash schemes coexist.
    fn apply_layered_signatures(
        &self,
        databases: &[&SignatureDb],
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        if databases.is_empty() {
            return Ok(SignatureApplication { matched: 0, applied: 0, matches: Vec::new() });
        }
        let analysis = self.analysis()?;
        let target = self.binary.target();
        let image = MaskContext::from_binary(&self.binary);
        let mut matches = Vec::new();
        for function in &analysis.program.functions {
            let end = function.blocks.iter().map(|block| block.end).max().unwrap_or(function.address);
            let Some(length) = end.checked_sub(function.address).filter(|&length| length > 0) else { continue };
            let Some(bytes) = self.binary.read(function.address, length) else { continue };
            let identified =
                databases.iter().find_map(|database| database.identify_in(&target, &image, bytes, function.address));
            let Some(name) = identified else { continue };
            let current = self.function_name(function.address);
            matches.push(SignatureMatch {
                address: function.address,
                name: name.to_owned(),
                unnamed: current.starts_with("sub_"),
            });
        }

        let mut applied = 0;
        if apply {
            for candidate in matches.iter().filter(|candidate| candidate.unnamed) {
                // Skip a name already in use elsewhere, so renaming cannot collide.
                if self.rename(candidate.address, Some(&candidate.name)).is_ok() {
                    applied += 1;
                }
            }
        }
        Ok(SignatureApplication { matched: matches.len(), applied, matches })
    }

    /// The starter signature database bundled for this binary's architecture, or `None` when none ships for it.
    pub fn bundled_signatures(&self) -> Option<SignatureDb> {
        rampage_signatures::bundled(self.binary.arch)
    }

    /// Identifies functions against an optional `user` database first, then the bundled starter database for this
    /// architecture (so user names win). With neither database, nothing matches.
    pub fn apply_signatures_default(
        &self,
        user: Option<&SignatureDb>,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        let bundled = self.bundled_signatures();
        let databases: Vec<&SignatureDb> = user.into_iter().chain(bundled.as_ref()).collect();
        self.apply_layered_signatures(&databases, apply)
    }
}
