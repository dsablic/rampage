//! Writing an image's entries under an output directory, treating every name and link as hostile.
//!
//! - Paths are checked component by component: empty, `.`, `..` and NUL-bearing components are refused, a leading
//!   `/` is dropped. Nothing is normalised away silently.
//! - Every directory on the way to an entry must be a real directory (never a symlink), and files are created with
//!   `O_CREAT | O_EXCL`, so nothing already on disk, a symlink included, is ever written through.
//! - Symlinks are created last, only when their target stays inside the output root; absolute targets are rewritten
//!   relative to the root. They are never followed.
//! - Device nodes, FIFOs and sockets are skipped; written modes are 0644 or 0755 (no setuid, setgid or sticky).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Result, UnpackError};
use crate::image::{EntryKind, Image, normalize};
use crate::limits::Budget;

/// Skipped entries and executables listed in a report; the totals count all of them.
const MAX_LISTED: usize = 200;

/// An entry not written, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

/// A written file whose header names an executable format, ready to open as an analysis target.
#[derive(Debug, Clone, Serialize)]
pub struct Executable {
    /// The path relative to the output directory.
    pub path: String,
    pub format: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExtractReport {
    pub output_dir: PathBuf,
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub executables: Vec<Executable>,
    pub executables_total: u64,
    pub skipped: Vec<Skipped>,
    pub skipped_total: u64,
}

impl ExtractReport {
    fn skip(&mut self, path: &str, reason: impl Into<String>) {
        self.skipped_total += 1;
        if self.skipped.len() < MAX_LISTED {
            self.skipped.push(Skipped { path: path.to_owned(), reason: reason.into() });
        }
    }
}

/// The components of an entry path that is safe to write, or why it is not.
pub fn safe_components(path: &str) -> std::result::Result<Vec<&str>, &'static str> {
    let trimmed = path.trim_start_matches('/');
    let mut components = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => continue,
            ".." => return Err("path traversal (`..`)"),
            _ if component.contains('\0') => return Err("NUL in path"),
            _ if component.len() > 255 => return Err("path component longer than 255 bytes"),
            _ => components.push(component),
        }
    }
    if components.is_empty() {
        return Err("empty path");
    }
    Ok(components)
}

/// Where `target`, a symlink at `components` (relative to the root), points, as components below the root, or
/// `None` when it climbs out of the root. Absolute targets are taken relative to the image root.
fn resolve_link<'a>(components: &[&'a str], target: &'a str) -> Option<Vec<&'a str>> {
    let mut resolved: Vec<&str> =
        if target.starts_with('/') { Vec::new() } else { components[..components.len() - 1].to_vec() };
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                resolved.pop()?;
            }
            _ if component.contains('\0') => return None,
            _ => resolved.push(component),
        }
    }
    Some(resolved)
}

/// A relative link text from the directory holding the link at `components` to `resolved`.
fn relative_target(components: &[&str], resolved: &[&str]) -> String {
    let parent = &components[..components.len() - 1];
    let common = parent.iter().zip(resolved).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<&str> = vec![".."; parent.len() - common];
    parts.extend(&resolved[common..]);
    if parts.is_empty() { ".".to_owned() } else { parts.join("/") }
}

/// Makes `components` under `root` exist as real directories, refusing to pass through anything else.
fn ensure_dirs(root: &Path, components: &[&str], budget: &mut Budget, report: &mut ExtractReport) -> Result<()> {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(UnpackError::Invalid(format!("`{}` exists and is not a directory", path.display())));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                budget.charge_file()?;
                create_dir(&path).map_err(|error| UnpackError::io(format!("create {}", path.display()), error))?;
                report.dirs += 1;
            }
            Err(error) => return Err(UnpackError::io(format!("inspect {}", path.display()), error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o755).create(path)
}

#[cfg(not(unix))]
fn create_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

/// Creates a new file, never following or replacing anything already there: `create_new` is `O_CREAT | O_EXCL`,
/// which fails on any existing name, a symlink (even a dangling one) included.
fn create_file(path: &Path, executable: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    options.open(path)
}

/// The executable format a file's first bytes announce.
pub fn executable_format(head: &[u8]) -> Option<&'static str> {
    let magic = head.get(..4)?;
    Some(match magic {
        [0x7f, b'E', b'L', b'F'] => "elf",
        [b'M', b'Z', ..] => "pe",
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => "macho",
        [0xca, 0xfe, 0xba, 0xbe]
            if head.get(4..8).is_some_and(|n| u32::from_be_bytes([n[0], n[1], n[2], n[3]]) < 64) =>
        {
            "macho_universal"
        }
        [b'd', b'e', b'x', b'\n'] => "dex",
        [0x00, b'a', b's', b'm'] => "wasm",
        _ => return None,
    })
}

/// Prepares `output_dir`: it must not exist yet (its parent must) or be an empty directory, so no earlier content
/// (a planted symlink) is ever written through.
pub fn prepare_output(output_dir: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(output_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            let mut contents =
                std::fs::read_dir(output_dir).map_err(|error| UnpackError::io("read output_dir", error))?;
            if contents.next().is_some() {
                return Err(UnpackError::Invalid("output_dir must be new or empty".to_owned()));
            }
        }
        Ok(_) => return Err(UnpackError::Invalid("output_dir exists and is not a directory".to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_dir(output_dir)
                .map_err(|error| UnpackError::io("create output_dir (its parent must exist)", error))?;
        }
        Err(error) => return Err(UnpackError::io("inspect output_dir", error)),
    }
    output_dir.canonicalize().map_err(|error| UnpackError::io("resolve output_dir", error))
}

/// Whether `path` is one of `selection` or inside one of them; an empty selection takes everything.
fn selected(path: &str, selection: &[String]) -> bool {
    selection.is_empty()
        || selection.iter().any(|wanted| {
            let wanted = normalize(wanted);
            wanted.is_empty() || path == wanted || path.strip_prefix(wanted).is_some_and(|rest| rest.starts_with('/'))
        })
}

/// Writes the entries of `image` chosen by `selection` (exact paths or directories; empty for all) under the empty
/// or new `output_dir`.
pub fn extract(
    image: &dyn Image,
    output_dir: &Path,
    selection: &[String],
    budget: &mut Budget,
) -> Result<ExtractReport> {
    let root = prepare_output(output_dir)?;
    let mut report = ExtractReport { output_dir: root.clone(), ..ExtractReport::default() };
    let mut links = Vec::new();
    let mut matched = false;
    for (index, entry) in image.entries().iter().enumerate() {
        let path = normalize(&entry.path);
        if !selected(path, selection) {
            continue;
        }
        matched = true;
        let components = match safe_components(&entry.path) {
            Ok(components) => components,
            Err(reason) => {
                report.skip(&entry.path, reason);
                continue;
            }
        };
        if components.len() > budget.limits.max_path_depth {
            report.skip(&entry.path, "path too deep");
            continue;
        }
        let parents = &components[..components.len() - 1];
        match entry.kind {
            EntryKind::Dir => {
                if let Err(error) = ensure_dirs(&root, &components, budget, &mut report) {
                    match error {
                        UnpackError::Limit(_) => return Err(error),
                        other => report.skip(&entry.path, other.to_string()),
                    }
                }
            }
            EntryKind::File | EntryKind::Image => {
                if let Err(error) = ensure_dirs(&root, parents, budget, &mut report) {
                    match error {
                        UnpackError::Limit(_) => return Err(error),
                        other => report.skip(&entry.path, other.to_string()),
                    }
                    continue;
                }
                budget.charge_file()?;
                let target = root.join(components.join("/"));
                let executable = entry.mode & 0o111 != 0;
                let mut file = match create_file(&target, executable) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        report.skip(&entry.path, "already written (a duplicate, or a case-insensitive name clash)");
                        continue;
                    }
                    Err(error) => {
                        report.skip(&entry.path, format!("cannot create: {error}"));
                        continue;
                    }
                };
                let mut head = Vec::new();
                let mut written = 0u64;
                let limit = budget.limits.max_file_bytes;
                image.read(index, limit, &mut |chunk| {
                    budget.charge_bytes(chunk.len() as u64)?;
                    if head.len() < 8 {
                        head.extend_from_slice(&chunk[..chunk.len().min(8 - head.len())]);
                    }
                    written += chunk.len() as u64;
                    file.write_all(chunk).map_err(|error| UnpackError::io(format!("write {}", target.display()), error))
                })?;
                report.files += 1;
                report.bytes += written;
                if let Some(format) = executable_format(&head) {
                    report.executables_total += 1;
                    if report.executables.len() < MAX_LISTED {
                        report.executables.push(Executable { path: components.join("/"), format });
                    }
                }
            }
            EntryKind::Symlink => links.push((entry.path.clone(), entry.link.clone().unwrap_or_default())),
            EntryKind::CharDevice | EntryKind::BlockDevice => report.skip(&entry.path, "device node not written"),
            EntryKind::Fifo => report.skip(&entry.path, "FIFO not written"),
            EntryKind::Socket => report.skip(&entry.path, "socket not written"),
            EntryKind::Other => report.skip(&entry.path, "entry type not written"),
        }
    }
    if !matched && !selection.is_empty() {
        return Err(UnpackError::Invalid("no entry matches `paths`".to_owned()));
    }
    for (path, target) in links {
        let components = safe_components(&path).expect("checked above");
        let Some(resolved) = resolve_link(&components, &target) else {
            report.skip(&path, format!("symlink to `{target}` escapes the output directory"));
            continue;
        };
        if target.is_empty() {
            report.skip(&path, "empty symlink target");
            continue;
        }
        if let Err(error) = ensure_dirs(&root, &components[..components.len() - 1], budget, &mut report) {
            match error {
                UnpackError::Limit(_) => return Err(error),
                other => report.skip(&path, other.to_string()),
            }
            continue;
        }
        budget.charge_file()?;
        let link_text = relative_target(&components, &resolved);
        match make_symlink(&link_text, &root.join(components.join("/"))) {
            Ok(()) => report.symlinks += 1,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                report.skip(&path, "already written (a duplicate, or a case-insensitive name clash)");
            }
            Err(error) => report.skip(&path, format!("cannot create symlink: {error}")),
        }
    }
    Ok(report)
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn make_symlink(_: &str, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "symlinks are not created on this host"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_and_empty_paths_are_refused() {
        assert_eq!(safe_components("/etc/passwd").unwrap(), ["etc", "passwd"]);
        assert_eq!(safe_components("./a//b/").unwrap(), ["a", "b"]);
        assert!(safe_components("a/../../etc").is_err());
        assert!(safe_components("..").is_err());
        assert!(safe_components("/").is_err());
        assert!(safe_components("a/\0b").is_err());
    }

    #[test]
    fn links_resolve_inside_the_root_only() {
        let at = ["bin", "sh"];
        assert_eq!(resolve_link(&at, "busybox").unwrap(), ["bin", "busybox"]);
        assert_eq!(resolve_link(&at, "/bin/busybox").unwrap(), ["bin", "busybox"]);
        assert_eq!(resolve_link(&at, "../lib/x").unwrap(), ["lib", "x"]);
        assert!(resolve_link(&at, "../../etc/passwd").is_none());
        assert_eq!(relative_target(&at, &["bin", "busybox"]), "busybox");
        assert_eq!(relative_target(&at, &["lib", "x"]), "../lib/x");
        assert_eq!(relative_target(&["a"], &["b", "c"]), "b/c");
    }

    #[test]
    fn selection_matches_paths_and_directories() {
        let selection = vec!["/usr/bin".to_owned()];
        assert!(selected("usr/bin", &selection));
        assert!(selected("usr/bin/x", &selection));
        assert!(!selected("usr/binx", &selection));
        assert!(selected("anything", &[]));
    }
}
