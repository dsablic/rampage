//! Explicit trusted-host FID import/query. Nothing here applies annotations or discovers host tools.

use std::collections::BTreeMap;
use std::path::Path;

use rampage_signatures::SignatureDb;
pub use rampage_signatures::fid::{FidHostAdapter, FidReader};
use rampage_signatures::fid::{FidMatchState, FidProgramFeatures};
use serde::Serialize;

use crate::{ApiError, Project};

pub const MAX_FID_QUERY_ROWS: usize = 256;
pub const MAX_FID_REPORT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FidSignatureStatus {
    Named,
    NoMatch,
    Ambiguous,
    Suppressed,
    RejectedByGate,
    UnsupportedNativeExtent,
    ResourceLimit,
}

#[derive(Debug, Serialize)]
pub struct FidSignatureRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub status: FidSignatureStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_variant: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FidSignatureReport {
    pub profile: &'static str,
    pub source_sha256: String,
    pub read_only: bool,
    pub automatic_application_supported: bool,
    pub total: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub rows: Vec<FidSignatureRow>,
    pub limitations: &'static [&'static str],
}

impl Project {
    /// Explicitly imports an operator-selected genuine `.fidbf` into a persisted SignatureDb FID
    /// namespace. Host paths are trusted executable/classpath configuration, never metadata or target
    /// input. No host discovery/downloads, target execution, annotations or project writes occur.
    pub fn import_fid_signatures(&self, path: &Path, reader: &FidReader) -> Result<SignatureDb, ApiError> {
        SignatureDb::from_fidbf(self.binary.arch, path, reader).map_err(fid_error)
    }

    /// Executes the fixed owned static-analysis exporter under an explicitly configured trusted host
    /// Ghidra 12.1.4/JDK. The target never runs. This is not a sandbox for untrusted host installations.
    /// Results are suggestions only; existing exact-signature application cannot consume this namespace.
    pub fn query_fid_signatures(
        &self,
        database: &SignatureDb,
        host: &FidHostAdapter,
        offset: usize,
        limit: usize,
    ) -> Result<FidSignatureReport, ApiError> {
        if !database.requires_fid_adapter() {
            return Err(ApiError::Invalid("query requires a FID namespace".into()));
        }
        validate_page(offset, limit)?;
        self.binary.validate_available_backing_source().map_err(|error| ApiError::Invalid(error.to_string()))?;
        let features = host.analyze(&self.binary).map_err(fid_error)?;
        self.binary.validate_available_backing_source().map_err(|error| ApiError::Invalid(error.to_string()))?;
        let report = self.fid_report(database, &features, offset, limit)?;
        self.binary.validate_available_backing_source().map_err(|error| ApiError::Invalid(error.to_string()))?;
        Ok(report)
    }

    fn fid_report(
        &self,
        database: &SignatureDb,
        features: &FidProgramFeatures,
        offset: usize,
        limit: usize,
    ) -> Result<FidSignatureReport, ApiError> {
        validate_page(offset, limit)?;
        // Production discovery is independent of Ghidra: no host body ranges or target names are
        // supplied as discovery seeds, annotations, callee names, or replacement native extents.
        let extents: BTreeMap<_, _> =
            self.analysis()?.program.functions.iter().map(|function| (function.address, function.end())).collect();
        let matched = database.identify_fid_program(&self.binary, &extents, features).map_err(fid_error)?;
        let total = matched.len();
        let mut rows = Vec::new();
        let mut bytes = 4096usize;
        for matched in matched.into_iter().skip(offset).take(limit) {
            let mut row = FidSignatureRow {
                address: matched.address,
                status: FidSignatureStatus::NoMatch,
                name: None,
                library_family: None,
                library_version: None,
                library_variant: None,
            };
            row.status = match matched.state {
                FidMatchState::Named { function, library } => {
                    row.name = Some(function.name.clone());
                    row.library_family = Some(library.family.clone());
                    row.library_version = Some(library.version.clone());
                    row.library_variant = Some(library.variant.clone());
                    FidSignatureStatus::Named
                }
                FidMatchState::NoMatch => FidSignatureStatus::NoMatch,
                FidMatchState::Ambiguous => FidSignatureStatus::Ambiguous,
                FidMatchState::Suppressed => FidSignatureStatus::Suppressed,
                FidMatchState::RejectedByGate => FidSignatureStatus::RejectedByGate,
                FidMatchState::UnsupportedBody => FidSignatureStatus::UnsupportedNativeExtent,
                FidMatchState::ResourceLimit => FidSignatureStatus::ResourceLimit,
            };
            bytes += serde_json::to_vec(&row).map_err(|error| ApiError::Invalid(error.to_string()))?.len() + 1;
            if bytes > MAX_FID_REPORT_BYTES {
                break;
            }
            rows.push(row);
        }
        let next_offset = (offset.saturating_add(rows.len()) < total).then_some(offset + rows.len());
        Ok(FidSignatureReport {
            profile: "ghidra-12.1.4-fid6-x86-elf-minimal-v1",
            source_sha256: features.source_sha256().iter().map(|byte| format!("{byte:02x}")).collect(),
            read_only: true,
            automatic_application_supported: false,
            total,
            offset,
            next_offset,
            rows,
            limitations: &[
                "Explicit trusted Ghidra/JDK static analysis is not a sandbox; the target is never executed.",
                "Default analysis and external libraries are disabled; only the fixed script's audited in-memory analyzers run.",
                "FID and native scheme-1/2 hashes remain separate; mixed native/PAT/FID databases are unsupported.",
                "Source SHA-256 binds exact input bytes; producer/library/version metadata is not authentication.",
                "FID is non-cryptographic and deliberately omits some scalar values; matching hashes are not semantic identity.",
                "Native discovery extents and existing confidence gates must agree; unsupported extents are reported.",
                "Target function names are never exported as features or used to satisfy call relationships.",
                "Suggestions only: no annotation, name application, project sidecar or source-file writes.",
            ],
        })
    }
}

fn validate_page(offset: usize, limit: usize) -> Result<(), ApiError> {
    if limit == 0 || limit > MAX_FID_QUERY_ROWS || offset > 100_000 {
        return Err(ApiError::Invalid("FID query needs offset <=100000 and limit 1..=256".into()));
    }
    Ok(())
}

fn fid_error(error: rampage_signatures::fid::FidError) -> ApiError {
    ApiError::Invalid(format!("FID import/query failed: {}", error.to_string().escape_debug()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_loaders::Binary;
    use rampage_signatures::fid::FidDb;

    #[test]
    fn production_native_consumer_names_real_stripped_fid_functions_read_only() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signatures/fid");
        let project = Project::new(Binary::open(root.join("native-heldout.elf")).unwrap());
        let features = FidProgramFeatures::from_export(include_bytes!(
            "../../../tests/fixtures/signatures/fid/native-heldout.features"
        ))
        .unwrap();
        let fid = FidDb::from_export(include_bytes!("../../../tests/fixtures/signatures/fid/native.export")).unwrap();
        let database = SignatureDb::from_fid_db(project.binary.arch, fid).unwrap();
        let before = project.annotation_list();
        assert!(project.apply_signatures(&database, false).is_err());
        assert!(project.apply_signatures(&database, true).is_err());
        let report = project.fid_report(&database, &features, 0, MAX_FID_QUERY_ROWS).unwrap();
        let names: std::collections::BTreeSet<_> = report.rows.iter().filter_map(|row| row.name.as_deref()).collect();
        assert_eq!(names, std::collections::BTreeSet::from(["owned_fid_leaf", "owned_fid_mix"]));
        assert!(report.read_only);
        assert!(!report.automatic_application_supported);
        assert_eq!(serde_json::to_value(before).unwrap(), serde_json::to_value(project.annotation_list()).unwrap());
    }

    #[test]
    #[ignore = "requires explicitly configured trusted Ghidra 12.1.4/JDK and temporary root"]
    fn explicit_project_host_import_and_query_are_read_only_for_positive_and_negative() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signatures/fid");
        let java = std::env::var_os("RAMPAGE_FID_JAVA").unwrap();
        let ghidra = std::env::var_os("RAMPAGE_FID_GHIDRA_HOME").unwrap();
        let temporary = std::env::var_os("RAMPAGE_FID_TEMP_ROOT").unwrap();
        let reader = FidReader {
            java_executable: java.clone().into(),
            ghidra_home: ghidra.clone().into(),
            temporary_root: temporary.clone().into(),
            timeout: std::time::Duration::from_secs(30),
        };
        let host = FidHostAdapter {
            java_executable: java.into(),
            ghidra_home: ghidra.into(),
            temporary_root: temporary.into(),
            timeout: std::time::Duration::from_secs(90),
        };
        let positive = Project::new(Binary::open(root.join("native-heldout.elf")).unwrap());
        let before = positive.annotation_revision().unwrap();
        let db = positive.import_fid_signatures(&root.join("native.fidbf"), &reader).unwrap();
        let db = SignatureDb::from_gzip(&db.to_gzip().unwrap()).unwrap();
        let report = positive.query_fid_signatures(&db, &host, 0, MAX_FID_QUERY_ROWS).unwrap();
        let names: std::collections::BTreeSet<_> = report.rows.iter().filter_map(|row| row.name.as_deref()).collect();
        assert_eq!(names, std::collections::BTreeSet::from(["owned_fid_leaf", "owned_fid_mix"]));
        assert!(std::sync::Arc::ptr_eq(&before, &positive.annotation_revision().unwrap()));
        let negative = Project::new(Binary::open(root.join("native-negative.elf")).unwrap());
        let before = negative.annotation_revision().unwrap();
        let report = negative.query_fid_signatures(&db, &host, 0, MAX_FID_QUERY_ROWS).unwrap();
        assert!(report.rows.iter().all(|row| row.name.is_none()));
        assert!(std::sync::Arc::ptr_eq(&before, &negative.annotation_revision().unwrap()));
        assert!(positive.annotations().persistent_path().is_none());
        assert!(negative.annotations().persistent_path().is_none());
    }
}
