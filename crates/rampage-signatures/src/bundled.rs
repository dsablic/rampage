//! Lazily loaded public-source signature corpora. Recognition concerns the same library build, not
//! version identification. Frozen musl JSON/gzip inputs remain independent regression baselines.

#[path = "catalog.rs"]
mod catalog;

pub use catalog::{BundledMetadata, BundledProfile, FLYWHEEL_PROFILE_PREFIX};

use rampage_arch::Arch;
use std::sync::OnceLock;

use rampage_loaders::{Binary, Details};

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

/// Supplementary sets identification consults after an architecture's corpus: the embedded firmware library
/// signatures (scheme 3; newlib, libgcc, FreeRTOS and an STM32 HAL for Cortex-M), built by
/// `tools/embedded-signatures`.
static EMBEDDED: [Entry; 1] = [Entry::new(
    Arch::Arm,
    include_bytes!("../data/embedded-thumb.json.gz"),
    include_str!("../data/embedded-thumb.index.json"),
)];

fn entry(arch: Arch) -> Option<&'static Entry> {
    CATALOG.iter().find(|entry| entry.arch == arch)
}

fn embedded_entry(arch: Arch) -> Option<&'static Entry> {
    EMBEDDED.iter().find(|entry| entry.arch == arch)
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

    /// Metadata for the embedded firmware set shipped for `arch`, without loading it.
    pub fn bundled_embedded_metadata(
        arch: Arch,
    ) -> Result<Option<&'static BundledMetadata>, &'static SignatureDbError> {
        embedded_entry(arch).map(Entry::metadata).transpose()
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

/// The embedded firmware library set for `arch` (Thumb only), cached like [`bundled_ref`].
pub fn bundled_embedded_ref(arch: Arch) -> Option<&'static SignatureDb> {
    embedded_entry(arch)?.database().ok()
}

/// The embedded firmware set for `binary`, when it looks like firmware ([`firmware_like`]); identification
/// consults it after the corpus ([`bundled_ref`]). They use different hash schemes, so they are layered, never
/// merged.
pub fn bundled_embedded_for(binary: &Binary) -> Option<&'static SignatureDb> {
    if firmware_like(binary) { bundled_embedded_ref(binary.arch) } else { None }
}

/// Whether `binary` looks like bare-metal firmware, the code the embedded set was built from: a Raw project with an
/// M-profile (Cortex-M) profile, or a statically linked ELF executable (`ET_EXEC`, no interpreter, no dynamic
/// section). A Linux PIE, shared object or dynamically linked armhf program is not, so its Thumb code never
/// meets firmware library names.
pub fn firmware_like(binary: &Binary) -> bool {
    if binary.raw_code_image().is_some() {
        return binary.m_profile();
    }
    match &binary.details {
        Details::Elf(elf) => {
            elf.kind == "executable"
                && elf.interpreter.is_none()
                && elf.needed.is_empty()
                && !binary.sections.iter().any(|section| section.name == ".dynamic")
        }
        _ => false,
    }
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
        for entry in &EMBEDDED {
            let metadata = entry.metadata().expect("valid embedded metadata");
            assert!(assets.insert(&metadata.asset));
            let database = entry.database().expect("embedded asset must decode and match its index");
            assert_eq!(database.arch(), entry.arch);
            assert_eq!(database.scheme(), crate::LITERAL_POOL_SCHEME);
            assert!(!database.is_empty());
            assert!(std::ptr::eq(bundled_embedded_ref(entry.arch).unwrap(), database));
        }
    }

    #[test]
    fn no_database_ships_for_unsupported_arches() {
        assert!(bundled(Arch::S390x).is_none());
        assert!(bundled_ref(Arch::S390x).is_none());
        assert!(bundled_counts(Arch::S390x).is_none());
        assert!(SignatureDb::bundled_metadata(Arch::S390x).unwrap().is_none());
        assert!(bundled_embedded_ref(Arch::X86_64).is_none());
    }

    fn fixture(path: &str) -> Binary {
        Binary::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(path)).unwrap()
    }

    /// The embedded firmware set and call graph are consulted for statically linked firmware only, never for a
    /// dynamically linked armhf Linux program, whose Thumb code is no microcontroller's.
    #[test]
    fn the_embedded_set_applies_to_firmware_only() {
        let firmware = fixture("firmware/embedded-libs-m4f.elf");
        assert!(firmware_like(&firmware));
        assert!(bundled_embedded_for(&firmware).is_some());
        // So is the embedded call graph, in place of the host-library one.
        let embedded = crate::bundled_embedded_call_graph().map(std::ptr::from_ref);
        assert!(embedded.is_some());
        assert_eq!(crate::bundled_call_graph_for(&firmware).map(std::ptr::from_ref), embedded);
        // A dynamically linked armhf program (interpreter, DT_NEEDED, .dynamic). Its fixture is A32; built for Thumb
        // (the armhf default) only its code ranges differ, so mark them Thumb.
        let mut linux = fixture("bin/hello-arm.elf");
        assert_eq!(linux.arch, Arch::Arm);
        linux.thumb = linux.segments.iter().map(|segment| segment.address..segment.address + segment.size).collect();
        assert!(linux.target().is_thumb(linux.entry.unwrap()));
        assert!(!firmware_like(&linux));
        assert!(bundled_embedded_for(&linux).is_none());
        assert!(bundled_ref(Arch::Arm).is_some(), "the corpus still applies");
        let host = crate::bundled_call_graph().map(std::ptr::from_ref);
        assert_eq!(crate::bundled_call_graph_for(&linux).map(std::ptr::from_ref), host);
    }

    /// Every notice the index names exists with its recorded digest, and every file beside it is named.
    #[test]
    fn the_notice_index_names_every_notice_file_with_its_digest() {
        use sha2::Digest;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/notices");
        let index: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(directory.join("index.json")).unwrap()).unwrap();
        let mut named = std::collections::BTreeSet::new();
        for notice in index["notices"].as_array().unwrap() {
            let file = notice["notice"].as_str().unwrap();
            let bytes = std::fs::read(directory.join(file)).unwrap_or_else(|error| panic!("{file}: {error}"));
            assert_eq!(crate::hex(&sha2::Sha256::digest(&bytes)), notice["notice_sha256"].as_str().unwrap(), "{file}");
            named.insert(file.to_owned());
            for related in notice["related_notices"].as_array().into_iter().flatten() {
                let related = related.as_str().unwrap();
                assert!(directory.join(related).is_file(), "{related}");
                named.insert(related.to_owned());
            }
        }
        for entry in std::fs::read_dir(&directory).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(name == "index.json" || named.contains(&name), "{name} is in data/notices but not in the index");
        }
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
        for entry in CATALOG.iter().chain(&EMBEDDED) {
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
