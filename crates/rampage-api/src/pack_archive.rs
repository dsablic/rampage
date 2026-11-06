//! Portable pack archives (`.rpack`): one file that carries a data pack from the machine that made it to another,
//! checked before anything is added (docs/packs.md, "Export and import").
//!
//! An archive is one gzip member holding one JSON document: a manifest and the pack's files, each as text, in the
//! existing pack formats (`rampage-pack.toml`, the signature databases its contents name, and a flywheel pack's
//! `entries.json`). The manifest records:
//! - the archive format and version, and the rampage versions that can load it (`min` inclusive, `max_exclusive`);
//! - the pack's own declarations (name, version, licence, source, description);
//! - the heuristic families it holds (`libid`, ...), each file's SHA-256 and size, and a content hash over all of
//!   it;
//! - per entry of a flywheel pack: its revert id, family, candidate hash, row count, corpus version and split, what
//!   it was gated against, both gate verdicts and the held-out delta.
//!
//! Import refuses an archive whose format, version range, file list, file hashes, content hash or entry list does
//! not check out, then writes the pack to a staging directory, loads it as `--pack` would, and only then moves it
//! into place. Nothing in an archive is executed: it is data, like any pack.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::flywheel::{ENTRIES_FILE, GateResult, PromotedSet, Row, SliceDelta};
use crate::packs::{ContentStatus, MANIFEST_FILE, Packs};

/// The `format` every archive manifest carries.
pub const ARCHIVE_FORMAT: &str = "rampage-pack-archive";
/// The archive format version this build writes and reads.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;
/// The usual file extension.
pub const ARCHIVE_EXTENSION: &str = "rpack";
const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 512;
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATH_CHARS: usize = 256;

/// Why an archive could not be written, read or imported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackArchiveError {
    /// The pack directory does not load cleanly, or holds a content an archive cannot carry.
    #[error("pack: {0}")]
    Pack(String),
    /// The archive is not a well-formed archive of a version this build reads.
    #[error("archive: {0}")]
    Format(String),
    /// A hash does not match: the archive was changed after export, or damaged.
    #[error("integrity: {0}")]
    Integrity(String),
    /// This rampage is outside the archive's version range.
    #[error("version: {0}")]
    Version(String),
    /// The destination is not usable.
    #[error("destination: {0}")]
    Destination(String),
    #[error("{0}")]
    Io(String),
}

fn io(path: &Path, error: impl std::fmt::Display) -> PackArchiveError {
    PackArchiveError::Io(format!("{}: {error}", path.display()))
}

/// The rampage versions an archive loads in: `min` inclusive, `max_exclusive` exclusive, both `MAJOR.MINOR.PATCH`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub min: String,
    pub max_exclusive: String,
}

impl VersionRange {
    /// The range a build exports: from its own version up to its next breaking version (the next minor while the
    /// major is 0, else the next major).
    pub fn for_version(version: &str) -> Result<VersionRange, PackArchiveError> {
        let (major, minor, patch) = parse_version(version)?;
        let max = if major == 0 { format!("0.{}.0", minor + 1) } else { format!("{}.0.0", major + 1) };
        Ok(VersionRange { min: format!("{major}.{minor}.{patch}"), max_exclusive: max })
    }

    pub fn contains(&self, version: &str) -> Result<bool, PackArchiveError> {
        let version = parse_version(version)?;
        Ok(parse_version(&self.min)? <= version && version < parse_version(&self.max_exclusive)?)
    }
}

/// `MAJOR.MINOR.PATCH`, ignoring a pre-release or build suffix after `-` or `+`.
fn parse_version(text: &str) -> Result<(u64, u64, u64), PackArchiveError> {
    let core = text.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    let invalid = || PackArchiveError::Format(format!("version {text:?} is not MAJOR.MINOR.PATCH"));
    if parts.len() != 3 {
        return Err(invalid());
    }
    let number = |part: &str| part.parse::<u64>().map_err(|_| invalid());
    Ok((number(parts[0])?, number(parts[1])?, number(parts[2])?))
}

/// The pack's own declarations, as its `rampage-pack.toml` makes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivePack {
    pub name: String,
    pub version: String,
    pub license: String,
    pub source: String,
    pub description: String,
}

/// One file of the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveFile {
    /// Relative to the pack directory, `/`-separated.
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

/// One promoted entry of a flywheel pack, as the manifest summarises it; `entries.json` holds the full record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEntry {
    /// The revert id: the entry's provenance id, which `rampage-eval bundle --remove` takes.
    pub id: String,
    pub family: String,
    pub candidate_hash: String,
    pub rows: usize,
    pub corpus_version: String,
    pub split: String,
    /// What it was gated against besides earlier promotions: `arm:<hash>` or `bundled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// Whether both gate stages passed.
    pub gate_passed: bool,
    pub fast: GateResult,
    pub heldout: GateResult,
    /// The held-out change of the gated scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heldout_delta: Option<SliceDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer_run: Option<String>,
    pub promoted_unix_ms: u64,
}

/// An archive's manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub format: String,
    pub format_version: u32,
    pub rampage_version: VersionRange,
    /// The rampage that wrote it.
    pub exported_by: String,
    pub pack: ArchivePack,
    /// The heuristic families the pack holds: the flywheel families of its entries, else its content kinds.
    pub families: Vec<String>,
    /// The SHA-256 over the version range, pack declarations, families, file list and entries.
    pub content_sha256: String,
    pub files: Vec<ArchiveFile>,
    #[serde(default)]
    pub entries: Vec<ArchiveEntry>,
}

impl ArchiveManifest {
    /// The content hash of everything the manifest asserts except the hash itself and who wrote it.
    pub fn compute_hash(&self) -> String {
        let covered = serde_json::json!({
            "format": self.format,
            "format_version": self.format_version,
            "rampage_version": self.rampage_version,
            "pack": self.pack,
            "families": self.families,
            "files": self.files,
            "entries": self.entries,
        });
        hex(&Sha256::digest(covered.to_string().as_bytes()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    manifest: ArchiveManifest,
    files: BTreeMap<String, String>,
}

/// A read and fully checked archive.
#[derive(Debug, Clone)]
pub struct Archive {
    pub manifest: ArchiveManifest,
    pub files: BTreeMap<String, String>,
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

fn sha256(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// A relative, `/`-separated path of plain components that stays inside the pack directory.
fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_CHARS
        && !path.starts_with('/')
        && path.chars().all(|c| c.is_ascii_alphanumeric() || "-_./+".contains(c))
        && path.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
}

/// The manifest entry of each promoted entry.
fn entries_of(set: &PromotedSet) -> Vec<ArchiveEntry> {
    set.entries
        .iter()
        .map(|entry| ArchiveEntry {
            id: entry.revert_id.clone(),
            family: entry.family.clone(),
            candidate_hash: entry.candidate_hash.clone(),
            rows: entry.rows.len(),
            corpus_version: entry.corpus_version.clone(),
            split: entry.split.clone(),
            baseline: entry.baseline.clone(),
            gate_passed: entry.fast.passed && entry.heldout.passed,
            fast: entry.fast.clone(),
            heldout: entry.heldout.clone(),
            heldout_delta: entry.heldout_deltas.get("all").cloned(),
            proposer_run: entry.proposer_run.clone(),
            promoted_unix_ms: entry.promoted_unix_ms,
        })
        .collect()
}

fn read_text(path: &Path) -> Result<String, PackArchiveError> {
    let file = std::fs::File::open(path).map_err(|error| io(path, error))?;
    let mut text = String::new();
    file.take(MAX_FILE_BYTES as u64 + 1).read_to_string(&mut text).map_err(|error| io(path, error))?;
    if text.len() > MAX_FILE_BYTES {
        return Err(PackArchiveError::Pack(format!("{}: larger than {MAX_FILE_BYTES} bytes", path.display())));
    }
    Ok(text)
}

/// Builds the archive of the pack in `directory` for rampage `version`. The pack must load cleanly and hold only
/// file contents.
pub fn build(directory: &Path, version: &str) -> Result<Archive, PackArchiveError> {
    let info = Packs::check(directory);
    if let Some(error) = &info.error {
        return Err(PackArchiveError::Pack(format!("{}: {error}", directory.display())));
    }
    let manifest = info.manifest.clone().ok_or_else(|| PackArchiveError::Pack("no manifest".to_owned()))?;
    let mut paths = vec![MANIFEST_FILE.to_owned()];
    let mut kinds = BTreeSet::new();
    for content in &info.contents {
        if content.status != ContentStatus::Loaded {
            return Err(PackArchiveError::Pack(format!(
                "{} {} does not load: {}",
                content.kind, content.path, content.detail
            )));
        }
        let path = content.path.trim_start_matches("./").to_owned();
        if !safe_path(&path) || !directory.join(&path).is_file() {
            return Err(PackArchiveError::Pack(format!(
                "{} {}: an archive carries file contents with plain relative paths only",
                content.kind, content.path
            )));
        }
        kinds.insert(content.kind.to_owned());
        paths.push(path);
    }
    let entries_path = directory.join(ENTRIES_FILE);
    let mut entries = Vec::new();
    let mut families: BTreeSet<String> = BTreeSet::new();
    if entries_path.is_file() {
        let text = read_text(&entries_path)?;
        let set: PromotedSet = serde_json::from_str(&text)
            .map_err(|error| PackArchiveError::Pack(format!("{}: {error}", entries_path.display())))?;
        entries = entries_of(&set);
        families.extend(set.entries.iter().map(|entry| entry.family.clone()));
        families.insert(set.family.clone());
        paths.push(ENTRIES_FILE.to_owned());
    }
    if families.is_empty() {
        families = kinds;
    }
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_FILES {
        return Err(PackArchiveError::Pack(format!("more than {MAX_FILES} files")));
    }
    let mut files = BTreeMap::new();
    let mut listed = Vec::new();
    for path in paths {
        let text = read_text(&directory.join(&path))?;
        listed.push(ArchiveFile { path: path.clone(), sha256: sha256(&text), bytes: text.len() });
        files.insert(path, text);
    }
    let mut manifest = ArchiveManifest {
        format: ARCHIVE_FORMAT.to_owned(),
        format_version: ARCHIVE_FORMAT_VERSION,
        rampage_version: VersionRange::for_version(version)?,
        exported_by: format!("rampage {version}"),
        pack: ArchivePack {
            name: manifest.name,
            version: manifest.version,
            license: manifest.license,
            source: manifest.source,
            description: manifest.description,
        },
        families: families.into_iter().collect(),
        content_sha256: String::new(),
        files: listed,
        entries,
    };
    manifest.content_sha256 = manifest.compute_hash();
    Ok(Archive { manifest, files })
}

impl Archive {
    /// The archive's bytes: one gzip member (mtime zero, no name) of its JSON.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PackArchiveError> {
        let wire = Wire { manifest: self.manifest.clone(), files: self.files.clone() };
        let json = serde_json::to_vec(&wire).map_err(|error| PackArchiveError::Format(error.to_string()))?;
        let mut encoder = flate2::GzBuilder::new().mtime(0).write(Vec::new(), flate2::Compression::best());
        encoder.write_all(&json).map_err(|error| PackArchiveError::Io(error.to_string()))?;
        encoder.finish().map_err(|error| PackArchiveError::Io(error.to_string()))
    }

    /// Reads archive bytes and checks everything that can be checked without a destination: the format, every
    /// path, every file's hash and size, the content hash, the entry list against `entries.json`, and that
    /// rampage `version` is in the archive's range.
    pub fn from_bytes(bytes: &[u8], version: &str) -> Result<Archive, PackArchiveError> {
        if bytes.len() as u64 > MAX_COMPRESSED_BYTES {
            return Err(PackArchiveError::Format(format!("larger than {MAX_COMPRESSED_BYTES} bytes")));
        }
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .take(MAX_JSON_BYTES + 1)
            .read_to_end(&mut json)
            .map_err(|error| PackArchiveError::Format(format!("not a gzip archive: {error}")))?;
        if json.len() as u64 > MAX_JSON_BYTES {
            return Err(PackArchiveError::Format(format!("expands past {MAX_JSON_BYTES} bytes")));
        }
        let wire: Wire = serde_json::from_slice(&json)
            .map_err(|error| PackArchiveError::Format(format!("not a pack archive: {error}")))?;
        let archive = Archive { manifest: wire.manifest, files: wire.files };
        archive.check(version)?;
        Ok(archive)
    }

    fn check(&self, version: &str) -> Result<(), PackArchiveError> {
        let manifest = &self.manifest;
        if manifest.format != ARCHIVE_FORMAT {
            return Err(PackArchiveError::Format(format!("format {:?} is not {ARCHIVE_FORMAT}", manifest.format)));
        }
        if manifest.format_version != ARCHIVE_FORMAT_VERSION {
            return Err(PackArchiveError::Format(format!(
                "format version {} (this rampage reads {ARCHIVE_FORMAT_VERSION})",
                manifest.format_version
            )));
        }
        if manifest.files.len() > MAX_FILES || manifest.files.is_empty() {
            return Err(PackArchiveError::Format(format!("an archive holds 1 to {MAX_FILES} files")));
        }
        let listed: BTreeSet<&str> = manifest.files.iter().map(|file| file.path.as_str()).collect();
        let carried: BTreeSet<&str> = self.files.keys().map(String::as_str).collect();
        if listed.len() != manifest.files.len() || listed != carried {
            return Err(PackArchiveError::Integrity(
                "the files carried differ from the files the manifest lists".to_owned(),
            ));
        }
        if !listed.contains(MANIFEST_FILE) {
            return Err(PackArchiveError::Format(format!("no {MANIFEST_FILE}")));
        }
        for file in &manifest.files {
            if !safe_path(&file.path) {
                return Err(PackArchiveError::Format(format!("path {:?} leaves the pack directory", file.path)));
            }
            let text = &self.files[&file.path];
            if text.len() > MAX_FILE_BYTES || text.len() != file.bytes || sha256(text) != file.sha256 {
                return Err(PackArchiveError::Integrity(format!(
                    "{}: SHA-256 or size differs from the manifest",
                    file.path
                )));
            }
        }
        if manifest.compute_hash() != manifest.content_sha256 {
            return Err(PackArchiveError::Integrity("the content hash differs from the manifest's".to_owned()));
        }
        match self.files.get(ENTRIES_FILE) {
            Some(text) => {
                let set: PromotedSet = serde_json::from_str(text)
                    .map_err(|error| PackArchiveError::Format(format!("{ENTRIES_FILE}: {error}")))?;
                if entries_of(&set) != manifest.entries {
                    return Err(PackArchiveError::Integrity(format!(
                        "the manifest's entries differ from {ENTRIES_FILE}"
                    )));
                }
                if let Some(bad) = set.entries.iter().find(|entry| !(entry.fast.passed && entry.heldout.passed)) {
                    return Err(PackArchiveError::Integrity(format!(
                        "entry {} has no passing gate result",
                        bad.revert_id
                    )));
                }
            }
            None if !manifest.entries.is_empty() => {
                return Err(PackArchiveError::Integrity(format!("entries are listed but {ENTRIES_FILE} is missing")));
            }
            None => {}
        }
        if !manifest.rampage_version.contains(version)? {
            return Err(PackArchiveError::Version(format!(
                "this rampage is {version}; the archive loads in {} up to (not including) {}",
                manifest.rampage_version.min, manifest.rampage_version.max_exclusive
            )));
        }
        Ok(())
    }

    /// The promoted entries the archive carries, with their rows.
    pub fn promoted(&self) -> Result<Option<PromotedSet>, PackArchiveError> {
        self.files
            .get(ENTRIES_FILE)
            .map(|text| serde_json::from_str(text).map_err(|error| PackArchiveError::Format(error.to_string())))
            .transpose()
    }
}

/// Writes the archive of the pack in `directory` to `output` (atomically) and returns its manifest.
pub fn export(directory: &Path, output: &Path, version: &str) -> Result<ArchiveManifest, PackArchiveError> {
    let archive = build(directory, version)?;
    let bytes = archive.to_bytes()?;
    let parent = output.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    let staging = parent.join(format!(
        ".{}.{}.tmp",
        output.file_name().and_then(|name| name.to_str()).unwrap_or("pack"),
        std::process::id()
    ));
    std::fs::write(&staging, &bytes).map_err(|error| io(&staging, error))?;
    std::fs::rename(&staging, output).map_err(|error| io(output, error))?;
    Ok(archive.manifest)
}

/// Reads and checks the archive at `path`.
pub fn read(path: &Path, version: &str) -> Result<Archive, PackArchiveError> {
    let file = std::fs::File::open(path).map_err(|error| io(path, error))?;
    let mut bytes = Vec::new();
    file.take(MAX_COMPRESSED_BYTES + 1).read_to_end(&mut bytes).map_err(|error| io(path, error))?;
    Archive::from_bytes(&bytes, version)
}

/// What an import did.
#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub directory: PathBuf,
    pub manifest: ArchiveManifest,
    /// Load with `--pack <directory>` or `RAMPAGE_PACKS`.
    pub load_with: String,
}

/// Checks the archive at `archive` and installs its pack as the directory `destination`, which must not exist or
/// be empty. The pack is written to a staging directory beside it and loaded there first; a pack that does not load
/// cleanly is removed and refused.
pub fn import(archive: &Path, destination: &Path, version: &str) -> Result<ImportReport, PackArchiveError> {
    let archive = read(archive, version)?;
    if destination.exists() {
        let empty = destination.is_dir()
            && std::fs::read_dir(destination).map_err(|error| io(destination, error))?.next().is_none();
        if !empty {
            return Err(PackArchiveError::Destination(format!(
                "{} exists and is not an empty directory; nothing was changed",
                destination.display()
            )));
        }
    }
    let parent = destination.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    let staging = parent.join(format!(
        ".{}.importing.{}",
        destination.file_name().and_then(|name| name.to_str()).unwrap_or("pack"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&staging);
    let result = (|| {
        for (path, text) in &archive.files {
            let target = staging.join(path);
            if let Some(directory) = target.parent() {
                std::fs::create_dir_all(directory).map_err(|error| io(directory, error))?;
            }
            std::fs::write(&target, text).map_err(|error| io(&target, error))?;
        }
        let info = Packs::check(&staging);
        if let Some(error) = &info.error {
            return Err(PackArchiveError::Pack(error.clone()));
        }
        if let Some(content) = info.contents.iter().find(|content| content.status != ContentStatus::Loaded) {
            return Err(PackArchiveError::Pack(format!("{} {}: {}", content.kind, content.path, content.detail)));
        }
        if destination.exists() {
            std::fs::remove_dir(destination).map_err(|error| io(destination, error))?;
        }
        std::fs::rename(&staging, destination).map_err(|error| io(destination, error))
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result?;
    Ok(ImportReport {
        directory: destination.to_owned(),
        load_with: format!("--pack {}", destination.display()),
        manifest: archive.manifest,
    })
}

/// What importing an archive over an existing pack directory would change.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ArchiveDiff {
    pub pack: String,
    pub files_added: Vec<String>,
    pub files_changed: Vec<String>,
    pub files_removed: Vec<String>,
    pub files_unchanged: usize,
    pub entries_added: Vec<String>,
    pub entries_removed: Vec<String>,
    pub entries_kept: usize,
    /// Signature rows (architecture, name, pattern) added and removed, for flywheel packs.
    pub rows_added: Vec<String>,
    pub rows_removed: Vec<String>,
}

fn row_label(row: &Row) -> String {
    let length = row.length.map(|length| format!(" length {length}")).unwrap_or_default();
    format!("{} {} {}{length}", row.arch, row.name, row.pattern)
}

/// Checks the archive at `archive` and lists what importing it in place of the pack in `current` (or into an
/// empty directory) would change, file by file, entry by entry and row by row.
pub fn diff(archive: &Path, current: Option<&Path>, version: &str) -> Result<ArchiveDiff, PackArchiveError> {
    let archive = read(archive, version)?;
    let mut diff = ArchiveDiff {
        pack: format!("{} {}", archive.manifest.pack.name, archive.manifest.pack.version),
        ..ArchiveDiff::default()
    };
    let mut existing: BTreeMap<String, String> = BTreeMap::new();
    let mut existing_set = None;
    if let Some(current) = current {
        let current_archive = build(current, version)?;
        existing_set = current_archive.promoted()?;
        existing = current_archive.files;
    }
    for (path, text) in &archive.files {
        match existing.get(path) {
            None => diff.files_added.push(path.clone()),
            Some(old) if old != text => diff.files_changed.push(path.clone()),
            Some(_) => diff.files_unchanged += 1,
        }
    }
    diff.files_removed = existing.keys().filter(|path| !archive.files.contains_key(*path)).cloned().collect();
    let new_set = archive.promoted()?;
    let ids = |set: &Option<PromotedSet>| -> BTreeSet<String> {
        set.iter().flat_map(|set| set.entries.iter().map(|entry| entry.revert_id.clone())).collect()
    };
    let rows = |set: &Option<PromotedSet>| -> BTreeSet<String> {
        set.iter().flat_map(|set| set.rows()).map(|row| row_label(&row)).collect()
    };
    let (old_ids, new_ids) = (ids(&existing_set), ids(&new_set));
    diff.entries_added = new_ids.difference(&old_ids).cloned().collect();
    diff.entries_removed = old_ids.difference(&new_ids).cloned().collect();
    diff.entries_kept = new_ids.intersection(&old_ids).count();
    let (old_rows, new_rows) = (rows(&existing_set), rows(&new_set));
    diff.rows_added = new_rows.difference(&old_rows).cloned().collect();
    diff.rows_removed = old_rows.difference(&new_rows).cloned().collect();
    Ok(diff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ranges_follow_the_next_breaking_version() {
        let range = VersionRange::for_version("0.1.0").unwrap();
        assert_eq!(range, VersionRange { min: "0.1.0".to_owned(), max_exclusive: "0.2.0".to_owned() });
        assert!(range.contains("0.1.7").unwrap());
        assert!(!range.contains("0.2.0").unwrap());
        assert!(!range.contains("0.0.9").unwrap());
        assert_eq!(VersionRange::for_version("2.3.4").unwrap().max_exclusive, "3.0.0");
        assert!(range.contains("0.1.1-dev+abc").unwrap());
        assert!(VersionRange::for_version("1.2").is_err());
    }

    use crate::flywheel::{GateCheck, GateConfig, Paths, PromotedEntry, RowSource};

    fn entry(revert: &str, name: &str, pattern: &str) -> PromotedEntry {
        let passed = |stage: &str| GateResult {
            stage: stage.to_owned(),
            passed: true,
            checks: vec![GateCheck { rule: "heldout_f1_gain".to_owned(), passed: true, detail: "+0.01".to_owned() }],
            failing_slices: vec![],
        };
        let source = RowSource { case: "f1".to_owned(), binary: "zlib-z1".to_owned(), address: "0x401000".to_owned() };
        let row = Row {
            arch: "x86_64".to_owned(),
            name: name.to_owned(),
            library: Some("zlib".to_owned()),
            pattern: pattern.to_owned(),
            length: None,
            source: Some(source.clone()),
        };
        PromotedEntry {
            revert_id: revert.to_owned(),
            family: "libid".to_owned(),
            candidate_hash: crate::flywheel::rows_hash(std::slice::from_ref(&row)),
            candidate_id: format!("c-{name}"),
            rows: vec![row],
            driving_cases: vec![source],
            corpus_version: "libid-test".to_owned(),
            split: "heldout".to_owned(),
            baseline_hash: "b".to_owned(),
            build_id: "test".to_owned(),
            gate: GateConfig::default(),
            fast: passed("fast"),
            heldout: passed("heldout"),
            heldout_reference: BTreeMap::new(),
            heldout_candidate: BTreeMap::new(),
            heldout_deltas: BTreeMap::new(),
            proposer_run: Some("run/round-1".to_owned()),
            promoted_unix_ms: 1,
            baseline: Some("arm:0123456789ab".to_owned()),
            require_novel_gain: Some(true),
        }
    }

    /// A promoted flywheel pack with two entries, in a fresh directory.
    fn promoted_pack(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("rampage-rpack-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths::new(root.clone());
        let set = PromotedSet {
            schema_version: 1,
            family: "libid".to_owned(),
            entries: vec![
                entry("rv-first", "inflate", "554889e5b834120000005dc3"),
                entry("rv-second", "deflate", "554889e5b835120000005dc3"),
            ],
        };
        set.save(&paths, "Zlib").unwrap();
        (root.clone(), paths.promoted("libid"))
    }

    fn rewrite(archive: &Path, change: impl FnOnce(&mut Wire)) -> PathBuf {
        let bytes = std::fs::read(archive).unwrap();
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..]).read_to_end(&mut json).unwrap();
        let mut wire: Wire = serde_json::from_slice(&json).unwrap();
        change(&mut wire);
        let tampered = archive.with_extension("tampered.rpack");
        let archive = Archive { manifest: wire.manifest, files: wire.files };
        std::fs::write(&tampered, archive.to_bytes().unwrap()).unwrap();
        tampered
    }

    #[test]
    fn a_promoted_pack_round_trips_through_an_archive_and_tampering_is_refused() {
        let (root, pack) = promoted_pack("roundtrip");
        let archive = root.join("libid.rpack");
        let manifest = export(&pack, &archive, "0.1.0").unwrap();
        assert_eq!(manifest.families, ["libid"]);
        assert_eq!(
            manifest.entries.iter().map(|entry| entry.id.as_str()).collect::<Vec<_>>(),
            ["rv-first", "rv-second"]
        );
        assert!(manifest.entries.iter().all(|entry| entry.gate_passed && entry.baseline.is_some()));
        let paths: Vec<&str> = manifest.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, ["entries.json", "rampage-pack.toml", "sigs/x86_64.json"]);
        assert_eq!(
            manifest.rampage_version,
            VersionRange { min: "0.1.0".to_owned(), max_exclusive: "0.2.0".to_owned() }
        );

        // A clean import reproduces the pack byte for byte, and it loads as a pack.
        let installed = root.join("clean").join("imported");
        let report = import(&archive, &installed, "0.1.3").unwrap();
        assert_eq!(report.manifest, manifest);
        for file in ["entries.json", "rampage-pack.toml", "sigs/x86_64.json"] {
            assert_eq!(std::fs::read(installed.join(file)).unwrap(), std::fs::read(pack.join(file)).unwrap(), "{file}");
        }
        let loaded = Packs::load(std::slice::from_ref(&installed));
        assert!(loaded.problems().is_empty(), "{:?}", loaded.problems());
        assert_eq!(loaded.signatures_for(rampage_arch::Arch::X86_64).count(), 1);

        // The diff against the installed copy is empty; against nothing, everything is added.
        let same = diff(&archive, Some(&installed), "0.1.0").unwrap();
        assert!(same.files_added.is_empty() && same.files_changed.is_empty() && same.entries_added.is_empty());
        assert_eq!((same.files_unchanged, same.entries_kept), (3, 2));
        let fresh = diff(&archive, None, "0.1.0").unwrap();
        assert_eq!(fresh.entries_added, ["rv-first", "rv-second"]);
        assert_eq!(fresh.rows_added.len(), 2);

        // An occupied destination is refused, and nothing is written.
        let refused = import(&archive, &installed, "0.1.0").unwrap_err();
        assert!(matches!(refused, PackArchiveError::Destination(_)), "{refused}");

        // Tampering: a file changed after export, a forged content hash, a widened version range, a dropped
        // entry, and a path leaving the pack are each refused before anything is written.
        let changed = rewrite(&archive, |wire| {
            wire.files.get_mut("sigs/x86_64.json").unwrap().push(' ');
        });
        assert!(matches!(read(&changed, "0.1.0").unwrap_err(), PackArchiveError::Integrity(_)));
        let rehashed = rewrite(&archive, |wire| {
            let text = wire.files.get_mut("sigs/x86_64.json").unwrap();
            text.push(' ');
            let file = wire.manifest.files.iter_mut().find(|file| file.path == "sigs/x86_64.json").unwrap();
            file.sha256 = sha256(text);
            file.bytes = text.len();
        });
        let error = read(&rehashed, "0.1.0").unwrap_err();
        assert!(error.to_string().contains("content hash"), "{error}");
        let widened = rewrite(&archive, |wire| wire.manifest.rampage_version.max_exclusive = "9.0.0".to_owned());
        assert!(matches!(read(&widened, "0.5.0").unwrap_err(), PackArchiveError::Integrity(_)));
        let dropped = rewrite(&archive, |wire| {
            wire.manifest.entries.pop();
            wire.manifest.content_sha256 = wire.manifest.compute_hash();
        });
        let error = read(&dropped, "0.1.0").unwrap_err();
        assert!(error.to_string().contains("entries differ"), "{error}");
        let escaping = rewrite(&archive, |wire| {
            let text = wire.files.remove("sigs/x86_64.json").unwrap();
            wire.files.insert("../x86_64.json".to_owned(), text);
            wire.manifest.files.iter_mut().find(|file| file.path == "sigs/x86_64.json").unwrap().path =
                "../x86_64.json".to_owned();
            wire.manifest.content_sha256 = wire.manifest.compute_hash();
        });
        assert!(matches!(read(&escaping, "0.1.0").unwrap_err(), PackArchiveError::Format(_)));
        let nowhere = root.join("tampered-install");
        assert!(import(&changed, &nowhere, "0.1.0").is_err());
        assert!(!nowhere.exists(), "a refused import writes nothing");

        // An honest archive for another rampage is refused by its version range.
        let other = root.join("other.rpack");
        export(&pack, &other, "0.3.1").unwrap();
        let error = read(&other, "0.1.0").unwrap_err();
        assert!(matches!(error, PackArchiveError::Version(_)), "{error}");
        assert!(read(&other, "0.3.9").is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn archive_paths_stay_inside_the_pack() {
        for good in ["rampage-pack.toml", "sigs/x86_64.json", "entries.json"] {
            assert!(safe_path(good), "{good}");
        }
        for bad in ["", "/etc/passwd", "../x", "sigs/../../x", "a//b", "./a", "a\\b", "C:x"] {
            assert!(!safe_path(bad), "{bad}");
        }
    }
}
