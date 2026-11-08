//! Library-function identification: build a signature database from a binary whose functions are named, and
//! apply one to name the matching functions of another binary (see `rampage-signatures`).

use std::collections::BTreeMap;

use rampage_signatures::{MaskContext, SignatureDb, identify_program_sources};
use serde::Serialize;

use crate::packs::BUILTIN_PACK;
use crate::workflows::is_default_name;
use crate::{ApiError, Project};

/// The [`SignatureMatch::source`] of a match from a database the caller supplied (`--db`, `database`).
pub const USER_SIGNATURES: &str = "user database";

#[derive(Debug, Serialize)]
pub struct SignatureMatch {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The name the signature database proposes.
    pub name: String,
    /// Whether the function is currently unnamed (a `sub_<hex>` default), so naming it adds information.
    pub unnamed: bool,
    /// The database that named it: [`USER_SIGNATURES`], the name of the data pack that holds it, or
    /// [`BUILTIN_PACK`] for the starter database bundled with rampage.
    pub source: String,
}

impl SignatureMatch {
    /// The database that named the function, for prose: "the bundled starter database", "data pack `x`".
    pub fn origin(&self) -> String {
        signature_origin(&self.source)
    }
}

/// [`SignatureMatch::origin`] for a match `source`.
pub(crate) fn signature_origin(source: &str) -> String {
    match source {
        BUILTIN_PACK => "the bundled starter database".to_owned(),
        USER_SIGNATURES => "the user-supplied database".to_owned(),
        pack => format!("data pack `{pack}`"),
    }
}

#[derive(Debug, Serialize)]
pub struct SignatureApplication {
    pub matched: usize,
    pub applied: usize,
    pub matches: Vec<SignatureMatch>,
    /// Data-pack problems bearing on signatures (a rejected pack, a signature database that did not load), so that
    /// a partly loaded set of databases is not taken for a complete one.
    pub warnings: Vec<String>,
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
        self.apply_layered_signatures(&[(USER_SIGNATURES, database)], apply)
    }

    /// Identifies discovered functions against each database in order; the first that names a function wins.
    /// Layering instead of merging lets databases built with different hash schemes coexist.
    fn apply_layered_signatures(
        &self,
        databases: &[(&str, &SignatureDb)],
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.apply_layered_signatures_with_preflight(databases, apply, Vec::new(), |_| Ok(()))
    }

    fn apply_layered_signatures_with_preflight(
        &self,
        databases: &[(&str, &SignatureDb)],
        apply: bool,
        warnings: Vec<String>,
        preflight: impl FnOnce(&SignatureApplication) -> Result<(), ApiError>,
    ) -> Result<SignatureApplication, ApiError> {
        for (_, database) in databases {
            database.ensure_byte_matching_supported().map_err(|error| ApiError::Invalid(error.to_string()))?;
        }
        if databases.is_empty() {
            let application = SignatureApplication { matched: 0, applied: 0, matches: Vec::new(), warnings };
            preflight(&application)?;
            return Ok(application);
        }
        let analysis = self.analysis()?;
        let bodies: Vec<(u64, &[u8])> = analysis
            .program
            .functions
            .iter()
            .filter_map(|function| Some((function.address, function.body(&self.binary)?)))
            .collect();
        let image = MaskContext::from_binary(&self.binary);
        let only: Vec<&SignatureDb> = databases.iter().map(|&(_, database)| database).collect();
        let names = identify_program_sources(&only, &self.binary.target(), &image, &bodies);
        let mut matches = Vec::new();
        for (address, (index, name)) in names {
            let current = self.function_name(address);
            matches.push(SignatureMatch {
                address,
                name: name.into_owned(),
                unnamed: is_default_name(&current, address),
                source: databases[index].0.to_owned(),
            });
        }

        let mut application = SignatureApplication { matched: matches.len(), applied: 0, matches, warnings };
        preflight(&application)?;
        if apply {
            // Several matches can share a name: instances of one generic Zig declaration, once their counters
            // are dropped (`canonical_name`). Each later one is applied as `name@2`, `name@3`, in address order.
            let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
            for candidate in application.matches.iter().filter(|candidate| candidate.unnamed) {
                let count = seen.entry(candidate.name.as_str()).or_insert(0);
                *count += 1;
                let name = match *count {
                    1 => candidate.name.clone(),
                    count => format!("{}@{count}", candidate.name),
                };
                // Skip a name already in use elsewhere, so renaming cannot collide.
                if self.rename_if_default(candidate.address, &name).unwrap_or(false) {
                    application.applied += 1;
                }
            }
        }
        Ok(application)
    }

    /// The starter signature database bundled for this binary's architecture, or `None` when none ships for it.
    pub fn bundled_signatures(&self) -> Option<SignatureDb> {
        rampage_signatures::bundled(self.binary.arch)
    }

    /// Identifies functions against an optional `user` database first, then the data packs' databases for this
    /// architecture in pack order, then the bundled starter database (so user names win). With no database,
    /// nothing matches.
    pub fn apply_signatures_default(
        &self,
        user: Option<&SignatureDb>,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.identify_functions(user, true, apply)
    }

    /// Identifies functions against an optional `user` database first, then the data packs' databases for this
    /// architecture in pack order, then, with `bundled`, the bundled starter database. Leaving out the bundled
    /// database needs a `user` or pack one, so that the request is never silently empty.
    pub fn identify_functions(
        &self,
        user: Option<&SignatureDb>,
        bundled: bool,
        apply: bool,
    ) -> Result<SignatureApplication, ApiError> {
        self.identify_functions_with_preflight(user, bundled, apply, |_| Ok(()))
    }

    /// Plans the full identification, including pack warnings, then calls `preflight` once before any rename.
    /// A rejected preflight writes nothing. The callback never restricts which matches an apply considers.
    pub fn identify_functions_with_preflight(
        &self,
        user: Option<&SignatureDb>,
        bundled: bool,
        apply: bool,
        preflight: impl FnOnce(&SignatureApplication) -> Result<(), ApiError>,
    ) -> Result<SignatureApplication, ApiError> {
        let packs = self.packs();
        let packed: Vec<(&str, &SignatureDb)> = packs.signatures_for(self.binary.arch).collect();
        if !bundled && user.is_none() && packed.is_empty() {
            return Err(ApiError::Invalid(
                "leaving out the bundled signatures needs a signature database or a pack with one for this \
                 architecture"
                    .to_owned(),
            ));
        }
        let bundled = if bundled { rampage_signatures::bundled_ref(self.binary.arch) } else { None };
        let user = user.map(|database| (USER_SIGNATURES, database));
        let bundled = bundled.map(|database| (BUILTIN_PACK, database));
        let databases: Vec<(&str, &SignatureDb)> = user.into_iter().chain(packed).chain(bundled).collect();
        self.apply_layered_signatures_with_preflight(&databases, apply, packs.problems_for("signatures"), preflight)
    }
}
