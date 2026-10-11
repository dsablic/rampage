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
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path).ok()?;
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
        if std::fs::read(&target).ok().as_deref() == Some(bytes) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
