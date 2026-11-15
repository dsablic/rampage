//! Files a tool writes at a caller-named absolute path. [`check_new_output`] and [`write_new`] create a new file
//! only: a canonical directory, exclusive creation, no symlink, mode 0644. [`check_output`] and [`write_atomically`]
//! replace a file the tool wrote (or any regular file with `overwrite`) through a temporary file renamed over it.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Where a file goes: the output's directory resolved once (symlinks in it followed), and the file name in it.
pub(crate) struct Target {
    directory: PathBuf,
    name: std::ffi::OsString,
    /// The permission bits of the file being replaced, kept on the new one.
    replaced_mode: Option<u32>,
}

impl Target {
    pub(crate) fn path(&self) -> PathBuf {
        self.directory.join(&self.name)
    }

    /// Whether an existing file is being replaced.
    pub(crate) fn replaces(&self) -> bool {
        self.replaced_mode.is_some()
    }
}

/// Checks `output` (called `what` in refusals): absolute, naming a file that is new, one `ours` says this tool
/// wrote, or (with `overwrite`) any regular file, never a symlink, in an existing directory. The directory is
/// resolved to its canonical path here, and the file is written there.
pub(crate) fn check_output(
    what: &str,
    output: &Path,
    overwrite: bool,
    ours: impl Fn(&Path) -> bool,
) -> Result<Target, String> {
    if !output.is_absolute() {
        return Err(format!("{what} must be an absolute path"));
    }
    let name = match output.components().next_back() {
        Some(std::path::Component::Normal(name)) => name.to_owned(),
        _ => return Err(format!("{what} must name a file")),
    };
    let parent =
        output.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or(format!("{what} has no directory"))?;
    let directory = parent
        .canonicalize()
        .ok()
        .filter(|directory| directory.is_dir())
        .ok_or_else(|| format!("{what}'s directory {} does not exist", parent.display()))?;
    let mut target = Target { directory, name, replaced_mode: None };
    let path = target.path();
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("{what} is a symlink; name a regular file"));
        }
        Ok(metadata) if !metadata.is_file() => return Err(format!("{what} exists and is not a regular file")),
        Ok(metadata) => {
            if !overwrite && !ours(&path) {
                return Err(format!(
                    "{what} {} exists and is not a file this tool wrote; pass overwrite: true to replace it",
                    path.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                target.replaced_mode = Some(metadata.permissions().mode() & 0o7777);
            }
            #[cfg(not(unix))]
            let _ = metadata;
        }
        Err(_) => {}
    }
    Ok(target)
}

/// Checks `output` (called `what` in refusals) for a file that must be new: absolute, in an existing directory named
/// by its canonical path (so no symlink anywhere in it), and no entry of that name, not even a symlink.
pub(crate) fn check_new_output(what: &str, output: &Path) -> Result<Target, String> {
    if !output.is_absolute() {
        return Err(format!("{what} must be an absolute path"));
    }
    let name = match output.components().next_back() {
        Some(std::path::Component::Normal(name)) => name.to_owned(),
        _ => return Err(format!("{what} must name a file")),
    };
    let parent =
        output.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or(format!("{what} has no directory"))?;
    let directory = parent
        .canonicalize()
        .ok()
        .filter(|directory| directory.is_dir())
        .ok_or_else(|| format!("{what}'s directory {} does not exist", parent.display()))?;
    if directory != parent {
        return Err(format!(
            "{what}'s directory {} is reached through a symlink or `..`; name it by its canonical path {}",
            parent.display(),
            directory.display()
        ));
    }
    let target = Target { directory, name, replaced_mode: None };
    if std::fs::symlink_metadata(target.path()).is_ok() {
        return Err(format!("{what} {} exists; this tool writes only new files", target.path().display()));
    }
    Ok(target)
}

/// Creates the target as a new file (mode 0644 before the umask, never executable) and writes `bytes` to it. The
/// file is created exclusively, without following a symlink, through the opened directory; on failure it is
/// removed again.
#[cfg(unix)]
pub(crate) fn write_new(target: &Target, bytes: &[u8]) -> Result<(), String> {
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, openat, unlinkat};
    let failed = |error: &dyn std::fmt::Display| format!("write {}: {error}", target.path().display());
    let directory = openat(
        CWD,
        &target.directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| failed(&error))?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = openat(&directory, &target.name, flags, Mode::from_bits_truncate(0o644)).map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            format!("{} exists; this tool writes only new files", target.path().display())
        } else {
            failed(&error)
        }
    })?;
    let mut file = std::fs::File::from(file);
    let written = file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|error| failed(&error));
    if written.is_err() {
        let _ = unlinkat(&directory, &target.name, AtFlags::empty());
    }
    written
}

#[cfg(not(unix))]
pub(crate) fn write_new(target: &Target, bytes: &[u8]) -> Result<(), String> {
    let output = target.path();
    let failed = |error: std::io::Error| format!("write {}: {error}", output.display());
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&output).map_err(failed)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all()).map_err(failed);
    if written.is_err() {
        let _ = std::fs::remove_file(&output);
    }
    written
}

/// Writes `bytes` to a new temporary file in the target's directory and renames it over the target, checking right
/// before the rename that the name is still not a symlink or anything but a regular file. On Unix every step goes
/// through the opened directory, so a directory swapped in the path meanwhile is not followed.
#[cfg(unix)]
pub(crate) fn write_atomically(target: &Target, bytes: &[u8]) -> Result<(), String> {
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, fchmod, openat, renameat, statat, unlinkat};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let failed = |error: &dyn std::fmt::Display| format!("write {}: {error}", target.path().display());
    let directory = openat(CWD, &target.directory, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| failed(&error))?;
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(&target.name);
    temporary.push(format!(".rampage-{}-{serial}.tmp", std::process::id()));
    let mode = Mode::from_bits_truncate(target.replaced_mode.unwrap_or(0o644) as _);
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = openat(&directory, &temporary, flags, mode).map_err(|error| failed(&error))?;
    let written = (|| -> Result<(), String> {
        // The umask may have narrowed the mode; a replaced file keeps exactly its own.
        if target.replaced_mode.is_some() {
            fchmod(&file, mode).map_err(|error| failed(&error))?;
        }
        let mut file = std::fs::File::from(file);
        file.write_all(bytes).map_err(|error| failed(&error))?;
        file.sync_all().map_err(|error| failed(&error))?;
        match statat(&directory, &target.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode as _) != FileType::RegularFile => {
                return Err(format!(
                    "{} changed into a symlink or non-file; nothing was written",
                    target.path().display()
                ));
            }
            Ok(_) if target.replaced_mode.is_none() => {
                return Err(format!("{} appeared while writing; nothing was written", target.path().display()));
            }
            _ => {}
        }
        renameat(&directory, &temporary, &directory, &target.name).map_err(|error| failed(&error))
    })();
    if written.is_err() {
        let _ = unlinkat(&directory, &temporary, AtFlags::empty());
    }
    written
}

#[cfg(not(unix))]
pub(crate) fn write_atomically(target: &Target, bytes: &[u8]) -> Result<(), String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let output = target.path();
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(&target.name);
    temporary.push(format!(".rampage-{}-{serial}.tmp", std::process::id()));
    let temporary = target.directory.join(temporary);
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if std::fs::symlink_metadata(&output).is_ok_and(|metadata| !metadata.is_file()) {
            return Err(std::io::Error::other("the output changed into a symlink or non-file"));
        }
        std::fs::rename(&temporary, &output)
    })();
    written.map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("write {}: {error}", output.display())
    })
}
