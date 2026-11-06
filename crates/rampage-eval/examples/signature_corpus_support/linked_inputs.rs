use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rampage_loaders::Binary;

use super::{ownership, signature_corpus_support::digest};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberReceipt {
    archive_path: String,
    archive_sha256: String,
    member_ordinal: usize,
    original_name: String,
    object_path: String,
    object_sha256: String,
    size: usize,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum MemberDocument {
    Rows(Vec<MemberReceipt>),
    Runtime { archive_member_receipts: Vec<MemberReceipt> },
}

fn receipt_rows(bytes: &[u8], objects: &[PathBuf]) -> Result<Vec<MemberReceipt>, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("member receipts exceed 1 MiB".into());
    }
    let document: MemberDocument = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let rows = match document {
        MemberDocument::Rows(rows) | MemberDocument::Runtime { archive_member_receipts: rows } => rows,
    };
    if rows.is_empty()
        || rows.len() > super::signature_corpus_support::MAX_LIBRARY_OBJECTS
        || rows.len() != objects.len()
    {
        return Err("member receipts must cover exactly 1..2048 explicit --object inputs".into());
    }
    let supplied =
        objects.iter().map(|path| path.to_str().ok_or("non-UTF-8 object path")).collect::<Result<BTreeSet<_>, _>>()?;
    let claimed: BTreeSet<_> = rows.iter().map(|row| row.object_path.as_str()).collect();
    if supplied.len() != objects.len() || claimed.len() != rows.len() || supplied != claimed {
        return Err("--object paths must match member receipt paths exactly, without duplicates or aliases".into());
    }
    Ok(rows)
}

pub(super) struct LinkedInputs {
    reference_map_path: PathBuf,
    target_map_path: PathBuf,
    member_receipts_path: PathBuf,
    reference_map: Vec<u8>,
    target_map: Vec<u8>,
    member_receipts: Vec<u8>,
    rows: Vec<MemberReceipt>,
    objects: BTreeMap<String, Vec<u8>>,
    archives: BTreeMap<String, Vec<u8>>,
}

impl LinkedInputs {
    pub(super) fn load(
        objects: &[PathBuf],
        reference_map: &Path,
        target_map: &Path,
        member_receipts: &Path,
    ) -> Result<Self, String> {
        let bytes = super::read_bounded(member_receipts, 1024 * 1024)?;
        let rows = receipt_rows(&bytes, objects)?;
        let mut input = Self {
            reference_map_path: reference_map.into(),
            target_map_path: target_map.into(),
            member_receipts_path: member_receipts.into(),
            reference_map: super::read_bounded(reference_map, 64 * 1024 * 1024)?,
            target_map: super::read_bounded(target_map, 64 * 1024 * 1024)?,
            member_receipts: bytes,
            rows,
            objects: BTreeMap::new(),
            archives: BTreeMap::new(),
        };
        let mut object_files = BTreeSet::new();
        let mut archive_files = BTreeSet::new();
        let (mut object_bytes, mut archive_bytes) = (0u64, 0u64);
        for row in &input.rows {
            let path = Path::new(&row.object_path);
            if !object_files.insert(std::fs::canonicalize(path).map_err(|error| error.to_string())?) {
                return Err("object receipt paths alias the same source file".into());
            }
            let bytes = super::read_bounded(path, 256 * 1024 * 1024 - object_bytes)?;
            object_bytes += bytes.len() as u64;
            if object_bytes > 256 * 1024 * 1024 || bytes.len() != row.size || digest(&bytes) != row.object_sha256 {
                return Err("object receipt size/hash mismatch or total byte budget exceeded".into());
            }
            input.objects.insert(row.object_path.clone(), bytes);
            if !input.archives.contains_key(&row.archive_path) {
                let path = Path::new(&row.archive_path);
                if !archive_files.insert(std::fs::canonicalize(path).map_err(|error| error.to_string())?) {
                    return Err("archive receipt paths alias the same source file".into());
                }
                let bytes = super::read_bounded(path, 512 * 1024 * 1024 - archive_bytes)?;
                archive_bytes += bytes.len() as u64;
                if archive_bytes > 512 * 1024 * 1024 {
                    return Err("total archive bytes exceed 512 MiB".into());
                }
                input.archives.insert(row.archive_path.clone(), bytes);
            }
        }
        Ok(input)
    }

    pub(super) fn collect(&self, linked: &Binary, reference: bool) -> Result<ownership::OwnershipReceipt, String> {
        let objects: Vec<_> = self
            .rows
            .iter()
            .map(|row| ownership::OwnedObject {
                archive_path: &row.archive_path,
                archive_sha256: &row.archive_sha256,
                archive_bytes: &self.archives[&row.archive_path],
                member_ordinal: row.member_ordinal,
                original_name: &row.original_name,
                object_path: &row.object_path,
                object_sha256: &row.object_sha256,
                object_bytes: &self.objects[&row.object_path],
            })
            .collect();
        ownership::linked_definitions(if reference { &self.reference_map } else { &self.target_map }, linked, &objects)
    }

    pub(super) fn object_hashes(&self) -> Vec<String> {
        self.objects.values().map(|bytes| digest(bytes)).collect()
    }

    pub(super) fn receipt_sha256(&self) -> String {
        digest(&self.member_receipts)
    }

    pub(super) fn validate_current(&self) -> Result<(), String> {
        let fixed = [
            (&self.reference_map_path, &self.reference_map, 64 * 1024 * 1024),
            (&self.target_map_path, &self.target_map, 64 * 1024 * 1024),
            (&self.member_receipts_path, &self.member_receipts, 1024 * 1024),
        ];
        for (path, bytes, limit) in fixed {
            if super::read_bounded(path, limit)? != *bytes {
                return Err("ownership map/member receipts changed before publication".into());
            }
        }
        for (path, bytes) in self.objects.iter().chain(self.archives.iter()) {
            let limit = if self.archives.contains_key(path) { 512 * 1024 * 1024 } else { 256 * 1024 * 1024 };
            if digest(&super::read_bounded(Path::new(path), limit)?) != digest(bytes) {
                return Err("owned object/archive changed before publication".into());
            }
        }
        Ok(())
    }
}

pub(super) fn apply_definitions(binary: &mut Binary, receipt: &ownership::OwnershipReceipt) {
    binary.symbols = receipt
        .definitions
        .iter()
        .map(|definition| rampage_loaders::Symbol {
            name: definition.raw_name.clone(),
            address: definition.address,
            size: definition.size,
            kind: rampage_loaders::SymbolKind::Function,
        })
        .collect();
}

pub(super) fn frozen_starter(arch: rampage_arch::Arch) -> Result<Option<&'static str>, String> {
    let (source, expected) = match arch {
        rampage_arch::Arch::X86_64 => (
            include_str!("../../../rampage-signatures/data/musl-x86_64.json"),
            "9bb19340d0d816c556d3dafb45102198a129168dceeb54668ee21d4ac31c5c95",
        ),
        rampage_arch::Arch::Aarch64 => (
            include_str!("../../../rampage-signatures/data/musl-aarch64.json"),
            "021d84fec9ae0a09dd9d00cbadc088a5f67f6389caf304290d6c922eb574be11",
        ),
        _ => return Ok(None),
    };
    if digest(source.as_bytes()) != expected {
        return Err("frozen starter JSON baseline changed".into());
    }
    Ok(Some(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn musl_sized_member_set_keeps_exact_path_completeness() {
        let objects: Vec<_> = (0..1053).map(|index| PathBuf::from(format!("owned/{index}.o"))).collect();
        let rows: Vec<_> = objects
            .iter()
            .enumerate()
            .map(|(index, path)| {
                serde_json::json!({
                    "archive_path":"libc.a", "archive_sha256":"a".repeat(64),
                    "member_ordinal":index, "original_name":format!("{index}.o"),
                    "object_path":path, "object_sha256":"b".repeat(64), "size":16,
                })
            })
            .collect();
        let bytes = serde_json::to_vec(&rows).unwrap();
        assert_eq!(receipt_rows(&bytes, &objects).unwrap().len(), objects.len());
        assert!(receipt_rows(&bytes, &objects[..objects.len() - 1]).is_err());
    }

    #[test]
    fn member_receipts_require_exact_object_list_and_reject_path_mutations() {
        let row = serde_json::json!({
            "archive_path":"lib.a", "archive_sha256":"claim", "member_ordinal":0,
            "original_name":"lib.o", "object_path":"lib.o", "object_sha256":"claim", "size":4,
        });
        let bytes = serde_json::to_vec(&vec![row.clone()]).unwrap();
        let objects = [PathBuf::from("lib.o")];
        assert!(receipt_rows(&bytes, &objects).is_ok());
        let runtime = serde_json::to_vec(&serde_json::json!({"archive_member_receipts":[row.clone()]})).unwrap();
        assert!(receipt_rows(&runtime, &objects).is_ok());
        assert!(receipt_rows(&bytes, &[PathBuf::from("./lib.o")]).is_err());
        assert!(receipt_rows(&bytes, &[PathBuf::from("lib.o"), PathBuf::from("extra.o")]).is_err());
        assert!(receipt_rows(&serde_json::to_vec(&vec![row.clone(), row]).unwrap(), &objects).is_err());
        let mut mutated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        mutated[0]["object_path"] = serde_json::json!("other.o");
        assert!(receipt_rows(&serde_json::to_vec(&mutated).unwrap(), &objects).is_err());
        assert!(receipt_rows(&vec![b' '; 1024 * 1024 + 1], &objects).is_err());
    }
}
