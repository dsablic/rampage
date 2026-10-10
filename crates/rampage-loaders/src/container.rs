use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{Binary, LoadError};

pub fn resolve_executable(path: &Path) -> Result<PathBuf, LoadError> {
    if !path.is_dir() {
        return Ok(path.to_owned());
    }
    let directory = path.join("Contents/MacOS");
    let root = path.canonicalize().map_err(|source| LoadError::Io { path: path.to_owned(), source })?;
    let canonical = directory.canonicalize().map_err(|source| LoadError::Io { path: directory.clone(), source })?;
    if !canonical.starts_with(&root) {
        return Err(LoadError::Malformed("bundle executable directory escapes the bundle".to_owned()));
    }
    let plist = path.join("Contents/Info.plist");
    if plist.exists() {
        let metadata =
            std::fs::symlink_metadata(&plist).map_err(|source| LoadError::Io { path: plist.clone(), source })?;
        if !metadata.file_type().is_file() {
            return Err(LoadError::Malformed("bundle Info.plist must be a regular file".to_owned()));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(LoadError::Malformed("bundle Info.plist exceeds 1 MiB".to_owned()));
        }
        let value = plist::Value::from_file(&plist)
            .map_err(|error| LoadError::Malformed(format!("invalid bundle Info.plist: {error}")))?;
        let executable = value
            .as_dictionary()
            .and_then(|dict| dict.get("CFBundleExecutable"))
            .and_then(plist::Value::as_string)
            .ok_or_else(|| LoadError::Malformed("bundle Info.plist has no CFBundleExecutable".to_owned()))?;
        if executable.is_empty() || Path::new(executable).components().count() != 1 || executable.contains(['/', '\\'])
        {
            return Err(LoadError::Malformed("invalid CFBundleExecutable filename".to_owned()));
        }
        let candidate = directory.join(executable);
        let file = std::fs::symlink_metadata(&candidate)
            .map_err(|source| LoadError::Io { path: candidate.clone(), source })?;
        if !file.is_file() || file.file_type().is_symlink() {
            return Err(LoadError::Malformed("bundle executable is not a regular file".to_owned()));
        }
        return Ok(candidate);
    }
    let entries = std::fs::read_dir(&directory).map_err(|source| LoadError::Io { path: directory.clone(), source })?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| LoadError::Io { path: directory.clone(), source })?;
        if entry.file_type().map_err(|source| LoadError::Io { path: entry.path(), source })?.is_file() {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    if candidates.len() == 1 {
        return Ok(candidates.remove(0));
    }
    let stem = path.file_stem().unwrap_or_default();
    if let Some(candidate) = candidates.iter().find(|path| path.file_name() == Some(stem)) {
        return Ok(candidate.clone());
    }
    Err(LoadError::Malformed("bundle has no unique executable; select a file under Contents/MacOS".to_owned()))
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub binaries: Vec<InventoryBinary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct InventoryBinary {
    pub path: PathBuf,
    pub architecture: String,
    pub slices: Vec<String>,
}

pub fn inventory(root: &Path) -> Result<Inventory, LoadError> {
    if !root.is_dir() {
        return Err(LoadError::Malformed("inventory requires an extracted package or directory".to_owned()));
    }
    let mut directories = vec![(root.to_owned(), 0)];
    let mut found = Inventory { binaries: Vec::new(), warnings: Vec::new() };
    let mut visited = 0;
    while let Some((directory, depth)) = directories.pop() {
        if visited >= 20_000 {
            found.warnings.push("inventory limit reached (32 levels or 20,000 entries)".to_owned());
            break;
        }
        if depth > 32 {
            found.warnings.push(format!("inventory depth limit reached at {}", directory.display()));
            continue;
        }
        let entries =
            std::fs::read_dir(&directory).map_err(|source| LoadError::Io { path: directory.clone(), source })?;
        for entry in entries {
            visited += 1;
            if visited >= 20_000 {
                found.warnings.push("inventory entry limit reached (20,000 entries)".to_owned());
                break;
            }
            let entry = entry.map_err(|source| LoadError::Io { path: directory.clone(), source })?;
            let kind = entry.file_type().map_err(|source| LoadError::Io { path: entry.path(), source })?;
            if kind.is_dir() {
                directories.push((entry.path(), depth + 1));
            } else if kind.is_file()
                && let Ok(binary) = Binary::open(entry.path())
            {
                found.binaries.push(InventoryBinary {
                    path: entry.path(),
                    architecture: binary.arch.to_string(),
                    slices: binary.slices.iter().map(ToString::to_string).collect(),
                });
            }
        }
    }
    found.binaries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(found)
}
