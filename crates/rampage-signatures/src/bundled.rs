//! Starter signature databases shipped with rampage, so `identify` names common library functions out of the
//! box. Each database is generated from a static musl libc build by `tools/signatures/gen-signatures.sh`; a
//! database matches only the exact library build it was made from, so these cover musl-linked binaries and the
//! set grows as more corpora are added.

use rampage_arch::Arch;

use crate::SignatureDb;

/// The starter signature database bundled for `arch`, or `None` when none ships for it.
pub fn bundled(arch: Arch) -> Option<SignatureDb> {
    let json = match arch {
        Arch::X86_64 => include_str!("../data/musl-x86_64.json"),
        Arch::Aarch64 => include_str!("../data/musl-aarch64.json"),
        _ => return None,
    };
    SignatureDb::from_json(json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_databases_parse_and_carry_signatures() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let db = bundled(arch).expect("a database ships for this arch");
            assert_eq!(db.arch(), arch);
            assert!(db.len() > 50, "{arch} starter database is unexpectedly small: {}", db.len());
        }
    }

    #[test]
    fn no_database_ships_for_unsupported_arches() {
        assert!(bundled(Arch::S390x).is_none());
    }
}
