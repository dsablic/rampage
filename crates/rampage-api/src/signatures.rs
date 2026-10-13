//! Library-function identification: build a signature database from a binary whose functions are named, and
//! apply one to name the matching functions of another binary (see `rampage-signatures`).

use std::collections::BTreeMap;

use rampage_signatures::{MaskContext, SignatureDb, identify_program};
use serde::Serialize;

use crate::workflows::is_default_name;
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
    /// Builds a signature database from this binary's named functions, over both their symbol sizes and the
    /// extents discovery finds for them here. Identification hashes the extents discovery finds in a stripped
    /// target, which match these only where discovery cuts both copies of a function short in the same place.
    pub fn build_signatures(&self) -> SignatureDb {
        let extents = match self.analysis() {
            Ok(analysis) => {
                analysis.program.functions.iter().map(|function| (function.address, function.end())).collect()
            }
            Err(_) => BTreeMap::new(),
        };
        SignatureDb::from_binary_with_extents(&self.binary, &extents)
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
        let bodies: Vec<(u64, &[u8])> = analysis
            .program
            .functions
            .iter()
            .filter_map(|function| Some((function.address, function.body(&self.binary)?)))
            .collect();
        let image = MaskContext::from_binary(&self.binary);
        let names = identify_program(databases, &self.binary.target(), &image, &bodies);
        let mut matches = Vec::new();
        for (address, name) in names {
            let current = self.function_name(address);
            matches.push(SignatureMatch {
                address,
                name: name.to_owned(),
                unnamed: is_default_name(&current, address),
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
        self.identify_functions(user, true, apply)
    }

    /// Identifies functions against an optional `user` database first, then, with `bundled`, the bundled starter
    /// database. Leaving out the bundled database needs a `user` one, so that the request is never silently empty.
    pub fn identify_functions(
        &self,
        user: Option<&SignatureDb>,
        bundled: bool,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        if !bundled && user.is_none() {
            return Err(ApiError::Invalid("leaving out the bundled signatures needs a signature database".to_owned()));
        }
        let bundled = if bundled { self.bundled_signatures() } else { None };
        let databases: Vec<&SignatureDb> = user.into_iter().chain(bundled.as_ref()).collect();
        self.apply_layered_signatures(&databases, apply)
    }
}
