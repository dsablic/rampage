//! Starter signature databases shipped with rampage, so `identify` names common library functions out of the
//! box. Each database is generated from a static musl libc build by `tools/gen-signatures.sh`; a
//! database matches only the exact library build it was made from, so these cover musl-linked binaries and the
//! set grows as more corpora are added.

use rampage_arch::Arch;
use std::sync::OnceLock;

use crate::{SignatureDb, SignatureDbError};

static X86_64: OnceLock<Result<SignatureDb, SignatureDbError>> = OnceLock::new();
static AARCH64: OnceLock<Result<SignatureDb, SignatureDbError>> = OnceLock::new();

const X86_64_GZIP: &[u8] = include_bytes!("../data/musl-x86_64.json.gz");
const AARCH64_GZIP: &[u8] = include_bytes!("../data/musl-aarch64.json.gz");

/// Counts of function signatures (masked plus exact) and callee keys from the generated starter indexes.
/// Listing these counts parses only two decimal numbers, never a signature database.
pub fn bundled_counts(arch: Arch) -> Option<(usize, usize)> {
    let index = match arch {
        Arch::X86_64 => include_str!("../data/musl-x86_64.counts"),
        Arch::Aarch64 => include_str!("../data/musl-aarch64.counts"),
        _ => return None,
    };
    let mut fields = index.split_ascii_whitespace();
    let mut next_count = || {
        let field = fields.next()?;
        if !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        field.parse::<usize>().ok()
    };
    let counts = (next_count()?, next_count()?);
    if fields.next().is_some() {
        return None;
    }
    Some(counts)
}

/// The starter signature database bundled for `arch`, or `None` when none ships for it.
/// Clones the cached database for callers that need ownership; prefer [`bundled_ref`] for lookup.
pub fn bundled(arch: Arch) -> Option<SignatureDb> {
    bundled_ref(arch).cloned()
}

/// The shared starter database for `arch`. Each architecture's actual parse result, including an error,
/// is initialized once independently; requesting one architecture does not load the others.
pub fn bundled_ref(arch: Arch) -> Option<&'static SignatureDb> {
    let (cache, gzip) = match arch {
        Arch::X86_64 => (&X86_64, X86_64_GZIP),
        Arch::Aarch64 => (&AARCH64, AARCH64_GZIP),
        _ => return None,
    };
    cache.get_or_init(|| SignatureDb::from_gzip(gzip)).as_ref().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_databases_parse_and_carry_signatures() {
        for (arch, json) in [
            (Arch::X86_64, include_str!("../data/musl-x86_64.json")),
            (Arch::Aarch64, include_str!("../data/musl-aarch64.json")),
        ] {
            let db = bundled(arch).expect("a database ships for this arch");
            let original = SignatureDb::from_json(json).expect("original starter JSON is valid");
            assert_eq!(db.arch(), arch);
            assert!(db.len() > 50, "{arch} starter database is unexpectedly small: {}", db.len());
            assert_eq!(bundled_counts(arch), Some((db.len(), db.callee_keys())));
            assert_eq!(bundled_counts(arch), Some((original.len(), original.callee_keys())));
        }
    }

    #[test]
    fn no_database_ships_for_unsupported_arches() {
        assert!(bundled(Arch::S390x).is_none());
        assert!(bundled_ref(Arch::S390x).is_none());
        assert!(bundled_counts(Arch::S390x).is_none());
    }

    #[test]
    fn gzip_assets_preserve_the_original_json_bytes() {
        for (gzip, original) in [
            (X86_64_GZIP, include_bytes!("../data/musl-x86_64.json").as_slice()),
            (AARCH64_GZIP, include_bytes!("../data/musl-aarch64.json").as_slice()),
        ] {
            assert_eq!(crate::compressed::decode_gzip(gzip).unwrap(), original);
        }
    }

    #[test]
    fn repeated_borrowed_lookups_reuse_the_actual_cached_database() {
        for (arch, cache) in [(Arch::X86_64, &X86_64), (Arch::Aarch64, &AARCH64)] {
            let first = bundled_ref(arch).unwrap();
            let second = bundled_ref(arch).unwrap();
            assert!(std::ptr::eq(first, second));
            assert!(std::ptr::eq(first, cache.get().unwrap().as_ref().unwrap()));
        }
    }
}
