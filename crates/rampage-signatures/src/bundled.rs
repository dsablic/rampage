//! Lazily loaded public-source signature corpora. Recognition concerns the same library build, not
//! version identification. Frozen musl JSON/gzip inputs remain independent regression baselines.

#[path = "catalog.rs"]
mod catalog;

pub use catalog::BundledMetadata;

use rampage_arch::Arch;
use std::sync::OnceLock;

use crate::{SignatureDb, SignatureDbError};

struct Entry {
    arch: Arch,
    gzip: &'static [u8],
    index: &'static str,
    metadata: OnceLock<Result<BundledMetadata, SignatureDbError>>,
    database: OnceLock<Result<SignatureDb, SignatureDbError>>,
}

impl Entry {
    const fn new(arch: Arch, gzip: &'static [u8], index: &'static str) -> Self {
        Self { arch, gzip, index, metadata: OnceLock::new(), database: OnceLock::new() }
    }

    fn metadata(&self) -> Result<&BundledMetadata, &SignatureDbError> {
        self.metadata
            .get_or_init(|| {
                let metadata = BundledMetadata::parse(self.index)?;
                if metadata.arch != self.arch.to_string() {
                    return Err(SignatureDbError::InvalidDatabase("bundled registration architecture mismatch"));
                }
                Ok(metadata)
            })
            .as_ref()
    }

    fn database(&self) -> Result<&SignatureDb, &SignatureDbError> {
        self.database
            .get_or_init(|| {
                let metadata = self
                    .metadata()
                    .map_err(|_| SignatureDbError::InvalidDatabase("invalid bundled registration index"))?;
                metadata.load(self.gzip)
            })
            .as_ref()
    }
}

static CATALOG: [Entry; 4] = [
    Entry::new(
        Arch::X86_64,
        include_bytes!("../data/corpus-x86_64.json.gz"),
        include_str!("../data/corpus-x86_64.index.json"),
    ),
    Entry::new(
        Arch::Aarch64,
        include_bytes!("../data/corpus-aarch64.json.gz"),
        include_str!("../data/corpus-aarch64.index.json"),
    ),
    Entry::new(Arch::X86, include_bytes!("../data/corpus-x86.json.gz"), include_str!("../data/corpus-x86.index.json")),
    Entry::new(Arch::Arm, include_bytes!("../data/corpus-arm.json.gz"), include_str!("../data/corpus-arm.index.json")),
];

fn entry(arch: Arch) -> Option<&'static Entry> {
    CATALOG.iter().find(|entry| entry.arch == arch)
}

/// Cached signature/callee counts from a small generated index; never decompresses a database.
pub fn bundled_counts(arch: Arch) -> Option<(usize, usize)> {
    let metadata = SignatureDb::bundled_metadata(arch).ok()??;
    Some((metadata.signatures, metadata.callee_keys))
}

impl SignatureDb {
    /// Metadata for a shipped architecture, without loading its signature database or other architectures.
    /// Errors remain distinguishable from architectures for which no asset ships.
    pub fn bundled_metadata(arch: Arch) -> Result<Option<&'static BundledMetadata>, &'static SignatureDbError> {
        entry(arch).map(Entry::metadata).transpose()
    }
}

/// An owned copy of the bundled corpus for `arch`; prefer [`bundled_ref`] for lookup.
pub fn bundled(arch: Arch) -> Option<SignatureDb> {
    bundled_ref(arch).cloned()
}

/// The shared corpus for `arch`. Each architecture's success or error is cached independently.
/// Builtin corruption is checked by catalog validation tests; no partial or baseline fallback is returned.
pub fn bundled_ref(arch: Arch) -> Option<&'static SignatureDb> {
    entry(arch)?.database().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_asset_matches_its_generated_index() {
        let mut arches = std::collections::BTreeSet::new();
        let mut assets = std::collections::BTreeSet::new();
        for entry in &CATALOG {
            assert!(arches.insert(entry.arch.to_string()));
            let metadata = entry.metadata().expect("valid builtin metadata");
            assert!(assets.insert(&metadata.asset));
            let database = entry.database().expect("builtin asset must decode and match its index");
            assert_eq!(database.arch(), entry.arch);
            assert!(!database.is_empty());
            assert_eq!(bundled_counts(entry.arch), Some((database.len(), database.callee_keys())));
            assert_eq!(crate::compressed::decode_gzip(entry.gzip).unwrap().len(), metadata.json_bytes);
        }
    }

    #[test]
    fn no_database_ships_for_unsupported_arches() {
        assert!(bundled(Arch::S390x).is_none());
        assert!(bundled_ref(Arch::S390x).is_none());
        assert!(bundled_counts(Arch::S390x).is_none());
        assert!(SignatureDb::bundled_metadata(Arch::S390x).unwrap().is_none());
    }

    #[test]
    fn frozen_musl_gzip_preserves_the_original_json_bytes() {
        for (gzip, original) in [
            (
                include_bytes!("../data/musl-x86_64.json.gz").as_slice(),
                include_bytes!("../data/musl-x86_64.json").as_slice(),
            ),
            (
                include_bytes!("../data/musl-aarch64.json.gz").as_slice(),
                include_bytes!("../data/musl-aarch64.json").as_slice(),
            ),
        ] {
            assert_eq!(crate::compressed::decode_gzip(gzip).unwrap(), original);
        }
    }

    #[test]
    fn default_corpora_withhold_raw_exact_and_reference_only_answers() {
        for entry in &CATALOG {
            let database = entry.database().unwrap();
            assert!(database.exact.is_empty(), "{}: raw exact fallbacks must not ship", entry.arch);
            assert!(
                database
                    .entries
                    .values()
                    .chain(database.calls.values())
                    .all(|name| !name.starts_with("__rampage_corpus_negative_"))
            );
        }
    }

    #[test]
    fn repeated_borrowed_lookups_reuse_the_actual_cached_database() {
        for entry in &CATALOG {
            let first = bundled_ref(entry.arch).unwrap();
            let second = bundled_ref(entry.arch).unwrap();
            assert!(std::ptr::eq(first, second));
            assert!(std::ptr::eq(first, entry.database.get().unwrap().as_ref().unwrap()));
            let first = SignatureDb::bundled_metadata(entry.arch).unwrap().unwrap();
            let second = SignatureDb::bundled_metadata(entry.arch).unwrap().unwrap();
            assert!(std::ptr::eq(first, second));
        }
    }

    #[test]
    fn metadata_only_initializes_its_own_small_index() {
        let entry =
            Entry::new(Arch::X86_64, b"deliberately not a gzip stream", include_str!("../data/musl-x86_64.index.json"));
        assert!(entry.metadata().is_ok());
        assert!(entry.database.get().is_none());
        assert!(entry.database().is_err());
        assert!(entry.database.get().unwrap().is_err());
    }

    #[test]
    fn corpus_union_never_changes_a_surviving_baseline_answer() {
        for (arch, json) in [
            (Arch::X86_64, include_str!("../data/musl-x86_64.json")),
            (Arch::Aarch64, include_str!("../data/musl-aarch64.json")),
        ] {
            let baseline = SignatureDb::from_json(json).unwrap();
            let corpus = bundled_ref(arch).unwrap();
            for (original, actual, tombstones) in [
                (&baseline.entries, &corpus.entries, &corpus.ambiguous),
                (&baseline.exact, &corpus.exact, &corpus.ambiguous_exact),
                (&baseline.calls, &corpus.calls, &corpus.ambiguous_calls),
            ] {
                for (key, name) in original {
                    if let Some(answer) = actual.get(key) {
                        assert_eq!(answer, name, "{arch}: corpus must be a union, not an overlay");
                    } else {
                        assert!(tombstones.contains(key), "{arch}: baseline key lost without collision evidence");
                    }
                }
            }
        }
    }
}
