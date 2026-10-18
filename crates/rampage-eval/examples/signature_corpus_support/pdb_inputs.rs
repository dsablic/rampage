use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rampage_eval::Truth;
use rampage_loaders::pdb::{MAX_PDB_BYTES, PdbProvenance, matched_procedures_checked};
use rampage_loaders::{Binary, Symbol, SymbolKind};

use super::{digest, index_hashes, read_bounded, resolve_hash};

pub(super) struct BoundPdb {
    pub path: PathBuf,
    pub sha256: String,
    provenance: PdbProvenance,
}

impl BoundPdb {
    pub fn validate_current(&self) -> Result<(), String> {
        self.provenance.validate_current().map_err(|error| error.to_string())?;
        if digest(&read_bounded(&self.path, MAX_PDB_BYTES as u64)?) != self.sha256 {
            return Err("PDB source changed before publication".into());
        }
        Ok(())
    }
}

pub(super) struct PdbInputs {
    by_hash: BTreeMap<String, PathBuf>,
    used: BTreeSet<String>,
    pub evidence: Vec<(String, PathBuf)>,
}

impl PdbInputs {
    pub fn new(paths: &[PathBuf]) -> Result<Self, String> {
        if paths.len() > 128 {
            return Err("at most 128 explicit PDB inputs are supported".into());
        }
        let evidence = paths
            .iter()
            .map(|path| Ok((digest(&read_bounded(path, MAX_PDB_BYTES as u64)?), path.clone())))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { by_hash: index_hashes(evidence.iter().cloned())?, used: BTreeSet::new(), evidence })
    }

    pub fn attach(&mut self, binary: &mut Binary, expected: &str, owned: Option<&Truth>) -> Result<BoundPdb, String> {
        let path = resolve_hash(&self.by_hash, expected)?.to_owned();
        let (procedures, provenance) = matched_procedures_checked(binary, &path).map_err(|error| error.to_string())?;
        if rampage_arch::hex::bytes(provenance.sha256()) != expected {
            return Err("checked PDB source SHA-256 differs from the frozen case".into());
        }
        if procedures.is_empty() {
            return Err("matched PDB contains no concrete producer procedures".into());
        }
        if let Some(owned) = owned {
            let globals: BTreeMap<_, _> = procedures
                .iter()
                .filter(|procedure| procedure.global)
                .map(|procedure| (procedure.address, procedure.name.as_str()))
                .collect();
            for (address, name) in &owned.0 {
                if globals.get(address).copied() != Some(name.as_str()) {
                    return Err(format!("owned truth at {address:#x} is not a matching global PDB procedure"));
                }
            }
        }
        binary.symbols = procedures
            .into_iter()
            .map(|procedure| Symbol {
                address: procedure.address,
                size: procedure.size,
                name: procedure.name,
                kind: SymbolKind::Function,
            })
            .collect();
        self.used.insert(expected.to_owned());
        Ok(BoundPdb { path, sha256: expected.to_owned(), provenance })
    }

    pub fn validate_used(&self) -> Result<(), String> {
        if self.used.len() != self.by_hash.len() {
            return Err("unused PDB input; every association must be an exact SHA-256 match".into());
        }
        Ok(())
    }

    pub fn validate_current(&self) -> Result<(), String> {
        for (hash, path) in &self.evidence {
            if digest(&read_bounded(path, MAX_PDB_BYTES as u64)?) != *hash {
                return Err("explicit PDB input changed before publication".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_support::{TempFiles, fixture};

    #[test]
    fn explicit_pdb_inputs_reject_missing_unused_changed_and_nonglobal_owned_truth() {
        let original = std::fs::read(fixture("fixture.pdb")).unwrap();
        let files = TempFiles::new();
        let path = files.write("selected.pdb", &original);
        let hash = digest(&original);
        let mut inputs = PdbInputs::new(std::slice::from_ref(&path)).unwrap();
        assert!(inputs.validate_used().is_err());
        let mut binary = Binary::open(fixture("fixture.exe")).unwrap();
        assert!(inputs.attach(&mut binary, &"0".repeat(64), None).is_err());
        let local = Truth(BTreeMap::from([(0x140001020, "pdb_local".into())]));
        assert!(inputs.attach(&mut binary, &hash, Some(&local)).is_err());
        let wrong = Truth(BTreeMap::from([(0x140001000, "wrong_name".into())]));
        assert!(inputs.attach(&mut binary, &hash, Some(&wrong)).is_err());
        let global = Truth(BTreeMap::from([(0x140001000, "pdb_mix".into())]));
        let bound = inputs.attach(&mut binary, &hash, Some(&global)).unwrap();
        assert_eq!(binary.symbols.len(), 4);
        assert!(binary.symbols.iter().any(|symbol| symbol.name == "pdb_local" && symbol.size == 15));
        inputs.validate_used().unwrap();
        bound.validate_current().unwrap();
        let mut changed = original;
        changed[0] ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(inputs.validate_current().is_err());
        assert!(bound.validate_current().is_err());
        assert!(inputs.attach(&mut binary, &hash, None).is_err());
        PdbInputs::new(&[]).unwrap().validate_used().unwrap();
    }
}
