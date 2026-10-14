use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/bundled_specs.rs"));

/// Locates an explicit override or materializes embedded specifications in a versioned user cache.
pub fn sleigh_home() -> Option<PathBuf> {
    if let Some(directory) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        return Some(PathBuf::from(directory));
    }
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    if let Some(home) = HOME.get() {
        return Some(home.clone());
    }
    let home = materialize()?;
    Some(HOME.get_or_init(|| home).clone())
}

fn materialize() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let root = PathBuf::from(home).join(".cache/rampage").join(BUNDLE_ID);
    reject_symlinks(&root).ok()?;
    std::fs::create_dir_all(root.parent()?).ok()?;
    let lock_path = root.with_extension("lock");
    reject_symlinks(&lock_path).ok()?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let lock = options.open(lock_path).ok()?;
    if !lock.metadata().ok()?.is_file() {
        return None;
    }
    lock.lock().ok()?;
    materialize_at(&root).ok()?;
    Some(root)
}

fn materialize_at(root: &Path) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    reject_symlinks(root)?;
    for &(relative, bytes) in BUNDLED_SPECS {
        let target = root.join(relative);
        reject_symlinks(&target)?;
        std::fs::create_dir_all(target.parent().expect("spec parent"))?;
        if exact_expected_file(&target, bytes)? {
            continue;
        }
        let (temporary, mut file) = loop {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos();
            let temporary = target.with_extension(format!(
                "partial-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary) {
                Ok(file) => break (temporary, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        use std::io::Write;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &target)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
    }
    Ok(())
}

fn reject_symlinks(path: &Path) -> std::io::Result<()> {
    for ancestor in path.ancestors() {
        if let Ok(metadata) = std::fs::symlink_metadata(ancestor)
            && metadata.file_type().is_symlink()
        {
            return Err(std::io::Error::other("specification cache contains a symlink"));
        }
    }
    Ok(())
}

fn regular_read(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    {
        #[cfg(not(unix))]
        reject_symlinks(path)?;
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("specification entry is not a regular file"));
        }
        Ok(file)
    }
}

/// Compares from a no-follow, nonblocking regular descriptor without allocating the cache entry's size.
/// An oversized regular cache entry is repairable; special files and unstable identities are refused.
fn exact_expected_file(path: &Path, expected: &[u8]) -> std::io::Result<bool> {
    let file = match regular_read(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let before = file.metadata()?;
    if before.len() != expected.len() as u64 {
        return Ok(false);
    }
    let mut limited = file.take(expected.len() as u64 + 1);
    let mut buffer = [0u8; 8192];
    let mut read = 0usize;
    loop {
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let end = read.checked_add(count).ok_or_else(|| std::io::Error::other("specification size overflow"))?;
        if expected.get(read..end) != Some(&buffer[..count]) {
            return Ok(false);
        }
        read = end;
    }
    let after = limited.get_ref().metadata()?;
    let pathname = std::fs::symlink_metadata(path)?;
    if pathname.file_type().is_symlink() || stamp(&before)? != stamp(&after)? || stamp(&after)? != stamp(&pathname)? {
        return Err(std::io::Error::other("specification changed during bounded comparison"));
    }
    Ok(read == expected.len())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecStamp(u64, u64, u64, i64, i64, i64, i64);

fn stamp(metadata: &std::fs::Metadata) -> std::io::Result<SpecStamp> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(SpecStamp(
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ))
    }
    #[cfg(not(unix))]
    {
        let time = metadata.modified()?.duration_since(std::time::UNIX_EPOCH).map_err(std::io::Error::other)?;
        Ok(SpecStamp(0, 0, metadata.len(), time.as_secs() as i64, i64::from(time.subsec_nanos()), 0, 0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleProof {
    pub(crate) home: PathBuf,
    pub(crate) stamps: Vec<(PathBuf, SpecStamp)>,
}

pub(crate) fn bundle_id() -> &'static str {
    BUNDLE_ID
}

pub(crate) fn feed_manifest_identity(mut update: impl FnMut(&[u8])) {
    for &(relative, expected) in BUNDLED_SPECS {
        update(&(relative.len() as u64).to_le_bytes());
        update(relative.as_bytes());
        update(&(expected.len() as u64).to_le_bytes());
        update(expected);
    }
}

pub(crate) fn verify_bundled() -> std::io::Result<BundleProof> {
    if !cfg!(unix) {
        return Err(std::io::Error::other("checked specification file identity unavailable"));
    }
    if std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
        return Err(std::io::Error::other("checked layouts require embedded bundled specifications, not an override"));
    }
    let home = sleigh_home().ok_or_else(|| std::io::Error::other("bundled specifications unavailable"))?;
    let proof = verify_bundle_at(&home)?;
    if std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
        return Err(std::io::Error::other("specification selection changed during verification"));
    }
    Ok(proof)
}

/// The entire home is closed over the embedded manifest, not only `Ghidra/Processors`.
/// Exact trusted manifest bytes prevent custom ldefs/path escapes; extra discovery roots are refused, never removed.
fn verify_bundle_at(home: &Path) -> std::io::Result<BundleProof> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Component;
    reject_symlinks(home)?;
    let home = home.canonicalize()?;
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::from([PathBuf::new()]);
    let mut bytes = 0usize;
    for &(relative, expected) in BUNDLED_SPECS {
        let relative = PathBuf::from(relative);
        if relative.components().any(|component| !matches!(component, Component::Normal(_)))
            || files.insert(relative.clone(), expected).is_some()
            || files.len() > 512
        {
            return Err(std::io::Error::other("invalid bundled specification manifest"));
        }
        bytes = bytes
            .checked_add(expected.len())
            .filter(|&bytes| bytes <= 64 * 1024 * 1024)
            .ok_or_else(|| std::io::Error::other("bundled specification byte budget exceeded"))?;
        for ancestor in relative.ancestors().skip(1) {
            directories.insert(ancestor.to_owned());
        }
    }
    let mut pending = vec![(PathBuf::new(), 0usize)];
    let mut stamps = Vec::new();
    let mut seen = 0usize;
    while let Some((relative, depth)) = pending.pop() {
        seen += 1;
        if seen > 4096 || depth > 8 || relative.as_os_str().len() > 512 {
            return Err(std::io::Error::other("bundled specification entry budget exceeded"));
        }
        let path = home.join(&relative);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::other("bundled specification tree contains a symlink"));
        }
        stamps.push((path.clone(), stamp(&metadata)?));
        if metadata.is_dir() && directories.contains(&relative) {
            for entry in std::fs::read_dir(&path)? {
                if pending.len() + seen >= 4096 {
                    return Err(std::io::Error::other("bundled specification entry budget exceeded"));
                }
                pending.push((relative.join(entry?.file_name()), depth + 1));
            }
        } else if metadata.is_file() {
            let expected = files
                .remove(&relative)
                .ok_or_else(|| std::io::Error::other("unexpected file in bundled specification search home"))?;
            if !exact_expected_file(&path, expected)? {
                return Err(std::io::Error::other("bundled specification bytes do not match the embedded manifest"));
            }
        } else {
            return Err(std::io::Error::other(
                "unexpected directory or special file in bundled specification search home",
            ));
        }
    }
    if !files.is_empty() {
        return Err(std::io::Error::other("bundled specification manifest entry is missing"));
    }
    stamps.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, before) in &stamps {
        if stamp(&std::fs::symlink_metadata(path)?)? != *before {
            return Err(std::io::Error::other("bundled specifications changed during verification"));
        }
    }
    Ok(BundleProof { home, stamps })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OwnedCache(PathBuf);

    impl OwnedCache {
        fn new(name: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("rampage-spec-{name}-{}-{index}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for OwnedCache {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exact_manifest_proof_refuses_extra_search_roots_and_modified_ldefs_without_removing_them() {
        let cache = OwnedCache::new("closed-manifest");
        materialize_at(&cache.0).unwrap();
        verify_bundle_at(&cache.0).unwrap();
        let unexpected = cache.0.join("contrib");
        std::fs::create_dir(&unexpected).unwrap();
        std::fs::write(unexpected.join("extra.ldefs"), b"outside search input").unwrap();
        assert!(verify_bundle_at(&cache.0).is_err());
        assert!(unexpected.join("extra.ldefs").exists());
        std::fs::remove_file(unexpected.join("extra.ldefs")).unwrap();
        std::fs::remove_dir(&unexpected).unwrap();
        let (relative, _) = BUNDLED_SPECS.iter().find(|(relative, _)| relative.ends_with("x86.ldefs")).unwrap();
        let target = cache.0.join(relative);
        std::fs::write(&target, b"<language_definitions><compiler spec=\"/outside.cspec\" /></language_definitions>")
            .unwrap();
        assert!(verify_bundle_at(&cache.0).is_err());
    }

    #[test]
    fn oversized_regular_cache_entries_are_compared_without_reading_their_length_and_repaired() {
        let cache = OwnedCache::new("oversized-cache");
        materialize_at(&cache.0).unwrap();
        let (relative, expected) = BUNDLED_SPECS[0];
        let target = cache.0.join(relative);
        let file = std::fs::OpenOptions::new().write(true).open(&target).unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();
        drop(file);
        assert!(!exact_expected_file(&target, expected).unwrap());
        materialize_at(&cache.0).unwrap();
        assert!(exact_expected_file(&target, expected).unwrap());
        assert_eq!(std::fs::metadata(&target).unwrap().len(), expected.len() as u64);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cache_comparison_refuses_symlinks_and_fifo_without_following_or_blocking() {
        use std::os::unix::{ffi::OsStrExt, fs::symlink};
        let cache = OwnedCache::new("special-cache");
        let ordinary = cache.0.join("ordinary");
        std::fs::write(&ordinary, b"expected").unwrap();
        let link = cache.0.join("link");
        symlink(&ordinary, &link).unwrap();
        assert!(exact_expected_file(&link, b"expected").is_err());
        let fifo = cache.0.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: an owned test path and a live NUL-terminated name; no target binary is executed.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(exact_expected_file(&fifo, b"expected").is_err());
        assert!(fifo.exists() && ordinary.exists() && link.exists());
    }

    #[test]
    fn embedded_specs_materialize_without_build_tree_and_repair_modified_files() {
        let root =
            std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-embedded-specs-{}", std::process::id()));
        assert!(!root.exists());
        let result = (|| {
            materialize_at(&root)?;
            let (relative, bytes) = BUNDLED_SPECS[0];
            std::fs::write(root.join(relative), b"modified")?;
            materialize_at(&root)?;
            if std::fs::read(root.join(relative))? != bytes {
                return Err(std::io::Error::other("cache file was not repaired"));
            }
            Ok::<_, std::io::Error>(())
        })();
        std::fs::remove_dir_all(&root).unwrap();
        result.unwrap();
    }
}
