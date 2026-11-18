//! `fs_list` and `fs_extract`: firmware filesystem images (SquashFS, ext2/3/4, Android sparse, OTA payloads, cpio,
//! tar, ZIP, UBI, UBIFS) listed and extracted through `rampage-unpack`, with JSON pages bounded like the other file tools.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rampage_unpack::{Format, Limits};
use serde_json::{Value, json};

/// Entries a page holds at most, and the JSON bytes its entries may take.
pub const MAX_FS_PAGE: usize = 1000;
const DEFAULT_FS_PAGE: usize = 200;
const PAGE_BYTES: usize = 50_000;
/// `inner` chain links and `paths` selections a call may give.
const MAX_INNER: usize = 8;
const MAX_SELECTION: usize = 1000;

pub struct FsListQuery {
    pub path: PathBuf,
    pub at: rampage_unpack::At,
    pub inner: Vec<String>,
    /// Only entries at or below this path.
    pub prefix: Option<String>,
    pub offset: usize,
    pub limit: Option<usize>,
}

pub struct FsExtractQuery {
    pub path: PathBuf,
    pub at: rampage_unpack::At,
    pub inner: Vec<String>,
    pub output_dir: PathBuf,
    pub paths: Vec<String>,
    pub max_bytes: Option<u64>,
    pub max_files: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub max_ratio: Option<u64>,
}

fn check_inner(inner: &[String]) -> Result<(), String> {
    if inner.len() > MAX_INNER || inner.iter().any(|path| path.len() > 4096) {
        return Err(format!("inner takes at most {MAX_INNER} paths of at most 4096 bytes"));
    }
    Ok(())
}

fn under(path: &str, prefix: &str) -> bool {
    let prefix = rampage_unpack::normalize(prefix);
    let path = rampage_unpack::normalize(path);
    prefix.is_empty() || path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// A page of the entries of the image `query` selects, with the layers that lead to it and counts by type.
pub fn fs_list(query: &FsListQuery) -> Result<Value, String> {
    check_inner(&query.inner)?;
    let limit = query.limit.unwrap_or(DEFAULT_FS_PAGE);
    if !(1..=MAX_FS_PAGE).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_FS_PAGE}"));
    }
    let listing = rampage_unpack::list(&query.path, query.at, &query.inner, Limits::default())
        .map_err(|error| error.to_string())?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &listing.entries {
        let kind = serde_json::to_value(entry.kind).map_err(|error| error.to_string())?;
        *counts.entry(kind.as_str().unwrap_or("other").to_owned()).or_default() += 1;
    }
    let matching: Vec<_> = match &query.prefix {
        Some(prefix) => listing.entries.iter().filter(|entry| under(&entry.path, prefix)).collect(),
        None => listing.entries.iter().collect(),
    };
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    let mut byte_capped = false;
    for entry in matching.iter().skip(query.offset).take(limit) {
        let value = serde_json::to_value(entry).map_err(|error| error.to_string())?;
        let size = value.to_string().len() + 1;
        if bytes + size > PAGE_BYTES && !entries.is_empty() {
            byte_capped = true;
            break;
        }
        bytes += size;
        entries.push(value);
    }
    let end = query.offset.saturating_add(entries.len());
    let next_offset = (end < matching.len()).then_some(end);
    let last = listing.layers.last().map(|layer| layer.format);
    let hint = match last {
        Some(Format::OtaPayload) => "partitions (type image) open with inner: [\"<name>.img\"]; fs_extract writes them",
        Some(Format::Ubi) => "volumes (type image) open with inner: [\"<name>.img\"]; fs_extract writes them",
        _ if listing.entries.iter().any(|entry| entry.kind == rampage_unpack::EntryKind::Image) => {
            "type image entries open with inner: [path]"
        }
        _ => "fs_extract writes files to a new output_dir and returns the executables to open by path",
    };
    Ok(json!({
        "path": query.path,
        "image_offset": query.at.offset,
        "layers": listing.layers,
        "counts": counts,
        "total": matching.len(),
        "offset": query.offset,
        "entries": entries,
        "next_offset": next_offset,
        "byte_capped": byte_capped,
        "hint": hint,
    }))
}

/// Extracts the image `query` selects into its output directory.
pub fn fs_extract(query: &FsExtractQuery) -> Result<Value, String> {
    check_inner(&query.inner)?;
    if query.paths.len() > MAX_SELECTION {
        return Err(format!("paths takes at most {MAX_SELECTION} entries"));
    }
    let defaults = Limits::default();
    let limits = Limits {
        max_total_bytes: query.max_bytes.unwrap_or(defaults.max_total_bytes),
        max_files: query.max_files.unwrap_or(defaults.max_files),
        max_file_bytes: query.max_file_bytes.unwrap_or(defaults.max_file_bytes),
        max_ratio: query.max_ratio.unwrap_or(defaults.max_ratio),
        ..defaults
    }
    .clamped();
    if !query.output_dir.is_absolute() {
        return Err("output_dir must be an absolute path".to_owned());
    }
    if std::fs::symlink_metadata(&query.output_dir).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("output_dir is a symlink; name the real directory (it must be new or empty)".to_owned());
    }
    let extraction =
        rampage_unpack::extract(&query.path, query.at, &query.inner, &query.output_dir, &query.paths, limits).map_err(
            |error| format!("{error} (files written before the refusal stay in {})", query.output_dir.display()),
        )?;
    let report = extraction.report;
    let root: &Path = &report.output_dir;
    let executables: Vec<Value> = report
        .executables
        .iter()
        .map(|executable| json!({"path": root.join(&executable.path), "format": executable.format}))
        .collect();
    Ok(json!({
        "output_dir": report.output_dir,
        "layers": extraction.layers,
        "files": report.files,
        "dirs": report.dirs,
        "symlinks": report.symlinks,
        "bytes": report.bytes,
        "executables": executables,
        "executables_total": report.executables_total,
        "skipped": report.skipped,
        "skipped_total": report.skipped_total,
        "limits": {
            "max_bytes": limits.max_total_bytes,
            "max_files": limits.max_files,
            "max_file_bytes": limits.max_file_bytes,
            "max_ratio": limits.max_ratio,
            "max_depth": limits.max_depth,
        },
        "hint": "open an executable by its path with triage_report or any binary tool",
    }))
}

/// A sentence for a file that is a filesystem image rather than an executable, naming the tools that read it.
pub fn filesystem_guidance(path: &Path) -> Option<String> {
    let format = rampage_unpack::sniff(path)?;
    if format == Format::Zip {
        return Some(
            "The file is a ZIP archive. An APK, AAB or JAR opens with dex_metadata (group `android`); fs_list and \
             fs_extract (group `carve`) list and extract any ZIP, so its native libraries can be opened by path."
                .to_owned(),
        );
    }
    let what = match format {
        Format::Squashfs => "a SquashFS filesystem image",
        Format::Ext => "an ext2/3/4 filesystem image",
        Format::AndroidSparse => "an Android sparse image",
        Format::OtaPayload => "an Android OTA payload",
        Format::Cpio => "a cpio archive",
        Format::Tar => "a tar archive",
        Format::Ubi => "a UBI flash image",
        Format::Ubifs => "a UBIFS filesystem image",
        Format::Zip => return None,
    };
    Some(format!(
        "The file is {what}: list it with fs_list and extract it with fs_extract (group `carve`), then open the \
         extracted executables by path."
    ))
}
