//! Small generated indexes; provenance declarations are not source authentication or version attribution.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SignatureDb, SignatureDbError};

const MAX_INDEX_BYTES: usize = 128 * 1024;
const MAX_PROFILES: usize = 128;
const RECOGNITION: &str = "same_build";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledMetadata {
    pub schema_version: u32,
    pub arch: String,
    pub scheme: u32,
    pub asset: String,
    pub gzip_sha256: String,
    pub compressed_bytes: usize,
    pub json_bytes: usize,
    pub signatures: usize,
    pub callee_keys: usize,
    /// Matching evidence concerns the same build, not identification of a library version.
    pub recognition: String,
    /// Only profiles actually included in this asset belong here, not planned or unavailable profiles.
    pub profiles: Vec<BundledProfile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundledProfile {
    pub id: String,
    pub library: String,
    pub version: String,
    pub target: String,
    pub compiler: String,
    pub optimization: String,
    /// A textual upstream license declaration, not a legal or authenticity verdict.
    pub license: String,
    pub source: String,
    pub source_recipe: String,
    pub archive_sha256: Option<String>,
    /// Frozen legacy inputs did not record archive identities; never invent one during promotion.
    pub archive_identity_unavailable: Option<String>,
}

fn invalid(reason: &'static str) -> SignatureDbError {
    SignatureDbError::InvalidDatabase(reason)
}

fn digest(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_profiles(profiles: &[BundledProfile]) -> Result<(), SignatureDbError> {
    if profiles.is_empty() || profiles.len() > MAX_PROFILES {
        return Err(invalid("bundled profile count"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for profile in profiles {
        for field in [
            &profile.id,
            &profile.library,
            &profile.version,
            &profile.target,
            &profile.compiler,
            &profile.optimization,
            &profile.license,
            &profile.source,
            &profile.source_recipe,
        ] {
            if field.trim().is_empty() || field.len() > 4096 || field.chars().any(char::is_control) {
                return Err(invalid("bundled profile text"));
            }
        }
        if !ids.insert(&profile.id) {
            return Err(invalid("duplicate bundled profile"));
        }
        match (&profile.archive_sha256, &profile.archive_identity_unavailable) {
            (Some(hash), None) if valid_digest(hash) => {}
            (None, Some(reason))
                if matches!(profile.id.as_str(), "legacy-musl-x86_64" | "legacy-musl-aarch64")
                    && !reason.trim().is_empty()
                    && reason.len() <= 4096
                    && !reason.chars().any(char::is_control) => {}
            _ => return Err(invalid("bundled profile archive identity")),
        }
    }
    Ok(())
}

impl BundledMetadata {
    pub(super) fn parse(index: &str) -> Result<Self, SignatureDbError> {
        if index.len() > MAX_INDEX_BYTES {
            return Err(SignatureDbError::LimitExceeded("bundled index bytes"));
        }
        let metadata: Self = serde_json::from_str(index).map_err(|_| invalid("bundled index JSON"))?;
        if metadata.schema_version != 1
            || ![crate::LEGACY_SCHEME, crate::CURRENT_SCHEME].contains(&metadata.scheme)
            || metadata.recognition != RECOGNITION
            || !valid_digest(&metadata.gzip_sha256)
            || metadata.compressed_bytes < 18
            || metadata.compressed_bytes > 64 * 1024 * 1024
            || metadata.json_bytes > 256 * 1024 * 1024
            || metadata.signatures > 1_000_000
            || metadata.callee_keys > 1_000_000
        {
            return Err(invalid("bundled index metadata"));
        }
        let arch: rampage_arch::Arch = metadata.arch.parse().map_err(|_| invalid("bundled index architecture"))?;
        if metadata.arch != arch.to_string()
            || metadata.asset.len() > 128
            || !metadata.asset.ends_with(".json.gz")
            || !metadata.asset.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(invalid("bundled index asset"));
        }
        validate_profiles(&metadata.profiles)?;
        Ok(metadata)
    }

    pub(super) fn load(&self, gzip: &[u8]) -> Result<SignatureDb, SignatureDbError> {
        if gzip.len() != self.compressed_bytes || digest(gzip) != self.gzip_sha256 {
            return Err(invalid("bundled gzip digest or length mismatch"));
        }
        // The strict decoder verifies ISIZE; its 256 MiB output cap excludes modulo-2^32 ambiguity.
        let size = gzip.get(gzip.len().saturating_sub(4)..).and_then(|bytes| bytes.try_into().ok());
        if size.map(u32::from_le_bytes).map(|size| size as usize) != Some(self.json_bytes) {
            return Err(invalid("bundled JSON length mismatch"));
        }
        let database = SignatureDb::from_gzip(gzip)?;
        if database.arch().to_string() != self.arch
            || database.scheme() != self.scheme
            || database.len() != self.signatures
            || database.callee_keys() != self.callee_keys
        {
            return Err(invalid("bundled database metadata mismatch"));
        }
        Ok(database)
    }
}

impl SignatureDb {
    /// Generates a bounded index for an already verified, collision-safe aggregate gzip asset.
    /// `profiles_json` is an array of shipped profile declarations; this does not validate evaluation gates,
    /// authenticate sources, combine databases, or write/promote files. Keep the original musl inputs frozen.
    pub fn bundled_index(gzip: &[u8], asset: &str, profiles_json: &str) -> Result<String, SignatureDbError> {
        if profiles_json.len() > MAX_INDEX_BYTES {
            return Err(SignatureDbError::LimitExceeded("bundled profile bytes"));
        }
        if asset.len() > 128 {
            return Err(invalid("bundled index asset"));
        }
        let profiles: Vec<BundledProfile> =
            serde_json::from_str(profiles_json).map_err(|_| invalid("bundled profiles JSON"))?;
        validate_profiles(&profiles)?;
        let database = Self::from_gzip(gzip)?;
        let metadata = BundledMetadata {
            schema_version: 1,
            arch: database.arch().to_string(),
            scheme: database.scheme(),
            asset: asset.to_owned(),
            gzip_sha256: digest(gzip),
            compressed_bytes: gzip.len(),
            json_bytes: crate::compressed::decode_gzip(gzip)?.len(),
            signatures: database.len(),
            callee_keys: database.callee_keys(),
            recognition: RECOGNITION.to_owned(),
            profiles,
        };
        let json = format!(
            "{}\n",
            serde_json::to_string_pretty(&metadata).map_err(|_| invalid("bundled index serialization"))?
        );
        BundledMetadata::parse(&json)?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = include_str!("../data/musl-x86_64.index.json");
    const GZIP: &[u8] = include_bytes!("../data/musl-x86_64.json.gz");

    #[test]
    fn generated_index_round_trips_actual_asset_metadata() {
        let original = BundledMetadata::parse(INDEX).unwrap();
        let profiles = serde_json::to_string(&original.profiles).unwrap();
        let generated = SignatureDb::bundled_index(GZIP, &original.asset, &profiles).unwrap();
        let regenerated = BundledMetadata::parse(&generated).unwrap();
        assert_eq!(serde_json::to_value(original).unwrap(), serde_json::to_value(&regenerated).unwrap());
        assert!(regenerated.load(GZIP).is_ok());
    }

    #[test]
    fn stale_or_corrupt_assets_are_rejected() {
        let mut metadata = BundledMetadata::parse(INDEX).unwrap();
        let mut damaged = GZIP.to_vec();
        damaged[12] ^= 1;
        assert!(metadata.load(&damaged).is_err());
        metadata.signatures += 1;
        assert!(metadata.load(GZIP).is_err());
        metadata.signatures -= 1;
        metadata.json_bytes += 1;
        assert!(metadata.load(GZIP).is_err());
    }

    #[test]
    fn metadata_is_bounded_and_requires_explicit_archive_provenance() {
        assert!(BundledMetadata::parse(&" ".repeat(MAX_INDEX_BYTES + 1)).is_err());
        let mut metadata: serde_json::Value = serde_json::from_str(INDEX).unwrap();
        metadata["profiles"][0]["id"] = "new-profile".into();
        assert!(BundledMetadata::parse(&metadata.to_string()).is_err());
        metadata["profiles"][0]["archive_sha256"] = "not-a-digest".into();
        metadata["profiles"][0]["archive_identity_unavailable"] = serde_json::Value::Null;
        assert!(BundledMetadata::parse(&metadata.to_string()).is_err());
        assert!(SignatureDb::bundled_index(GZIP, "../outside.json.gz", "[]").is_err());
    }
}
