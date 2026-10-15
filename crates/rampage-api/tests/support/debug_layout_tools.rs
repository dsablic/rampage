use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{Project, Session};
use serde_json::Value;

pub struct TempFiles(PathBuf);

impl TempFiles {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-debug-layout-tools-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    pub fn negative(&self) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        self.copy("negative.elf", &source)
    }

    pub fn generated(&self, variant: &str, group: &str) -> PathBuf {
        let root = std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES")
            .expect("requires tools/ci/debug-layout-oracle.sh --check wrapper");
        let source = PathBuf::from(root).join(variant).join(format!("{group}.debug.elf"));
        let maximum = oracle()["target"]["max_binary_bytes"].as_u64().unwrap();
        let mut bytes = Vec::new();
        std::fs::File::open(&source).unwrap().take(maximum + 1).read_to_end(&mut bytes).unwrap();
        assert!(bytes.len() as u64 <= maximum);
        let path = self.0.join(format!("{variant}-{group}.elf"));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn copy(&self, name: &str, source: &Path) -> PathBuf {
        let path = self.0.join(name);
        std::fs::copy(source, &path).unwrap();
        path
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&self.0).unwrap();
    }
}

pub fn oracle() -> Value {
    serde_json::from_str(include_str!("../../../../tests/fixtures/debug-layouts/oracle.json")).unwrap()
}

pub fn open(path: &Path) -> std::sync::Arc<Project> {
    Session::default().open(path, None).unwrap()
}

pub fn sidecar(path: &Path) -> PathBuf {
    path.with_file_name(format!("{}.rampage", path.file_name().unwrap().to_str().unwrap()))
}

pub fn log_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(sidecar(path)).unwrap_or_default()
}

pub fn expected_functions(project: &Project) -> BTreeSet<u64> {
    oracle()["groups"]["flat"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| project.resolve(name.as_str().unwrap()).unwrap())
        .collect()
}

fn image_identity(record: &Value) -> Option<&str> {
    let image = record.get("image")?;
    assert_eq!(record.as_object().unwrap().len(), 1, "identity line has exactly one key");
    let image = image.as_str().expect("image identity is a string");
    assert_eq!(image.len(), 64);
    assert!(image.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    Some(image)
}

pub fn assert_atomic_append(path: &Path, before: &[u8], edits: usize, image_sha256: &str) {
    let after = log_bytes(path);
    let appended = after.strip_prefix(before).expect("existing annotation bytes preserved");
    let previous: Vec<Value> =
        std::str::from_utf8(before).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let needs_identity = previous.iter().rev().find_map(image_identity) != Some(image_sha256);
    let records: Vec<Value> =
        std::str::from_utf8(appended).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let records = if needs_identity {
        let (identity, batch) = records.split_first().expect("required image identity before the batch");
        assert_eq!(image_identity(identity), Some(image_sha256), "identity matches the reviewed image");
        batch
    } else {
        records.as_slice()
    };
    assert_eq!(records.len(), edits + 1);
    assert_eq!(records[0].as_object().unwrap().len(), 2, "one exact batch header");
    assert_eq!(records[0]["edits"], edits);
    let batch = records[0]["batch"].as_str().expect("batch header id");
    assert!(!batch.is_empty());
    for record in &records[1..] {
        let member = record.as_object().expect("batch member is an edit object");
        assert_eq!(member.len(), 5, "batch member has only the edit fields and batch id");
        for key in ["field", "address", "value", "previous", "batch"] {
            assert!(member.contains_key(key), "batch member missing {key}");
        }
        assert_eq!(record["batch"].as_str(), Some(batch));
        serde_json::from_value::<rampage_api::annotations::Edit>(record.clone()).expect("valid batch edit");
    }
}

pub fn assert_source_signatures(project: &Project) {
    let actual: BTreeSet<_> = project.annotation_list().signatures.iter().map(|row| row.address).collect();
    assert_eq!(actual, expected_functions(project));
    assert_eq!(project.annotation_list().types.len(), 1);
    let address = project.resolve("debug_flat_read_interior").unwrap();
    assert!(project.decompile(address).unwrap().code.contains("->count"));
}

pub fn wrong_digest(digest: &str) -> String {
    let mut wrong = digest.to_owned();
    wrong.replace_range(..1, if digest.starts_with('0') { "1" } else { "0" });
    wrong
}
