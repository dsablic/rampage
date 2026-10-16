use std::path::Path;
use std::sync::Arc;

use rampage_arch::Arch;
use rampage_loaders::ImageAt;

use crate::{ApiError, Project, Session};

/// Fresh checked opening for explicitly selected plugin-triage sources, not the legacy Session cache path.
/// Original source identity is retained, and the actual parser mapping is capped at 16 MiB before mmap and
/// admitted before native producers. Raw preload admission accepts conservative little-endian x86-64 ELF and
/// whole-file unmanaged PE32+ profiles (see preload/pe.rs); CLR, Go recovery candidates and other native loader
/// profiles are refused before loading. This is separate from the 1 MiB final fact payload admission limit.
/// Native parsing/checked sidecar ingestion remain outside component limits, not an atomic source snapshot.
/// Inputs must remain quiescent during mapped admission and parsing: metadata revalidation detects observable
/// drift but cannot prevent concurrent mapped-file modification or truncation while the callback reads it.
pub fn open_plugin_triage_source(
    session: &Session,
    path: &Path,
    arch: Option<Arch>,
    image: Option<ImageAt>,
) -> Result<Arc<Project>, ApiError> {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
    {
        supported::open(session, path, arch, image)
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
    {
        let _ = (session, path, arch, image);
        Err(ApiError::Unavailable("checked plugin source opening is unavailable on this platform".into()))
    }
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod supported {
    use std::fs::{File, Metadata};
    use std::io;
    #[cfg(test)]
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use rampage_arch::Arch;
    use rampage_loaders::ImageAt;
    use rustix::fs::{Mode, OFlags};

    use super::super::{MAX_PLUGIN_TRIAGE_SOURCE_BYTES, bounds, invalid, preflight_names, preload};
    use crate::{ApiError, Project, ProjectWorkspaceTaskControl, Session};

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        length: u64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
    }

    impl Stamp {
        fn new(metadata: &Metadata) -> Result<Self, ApiError> {
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES as u64 {
                return Err(invalid("plugin source must be a nonempty regular file of at most 16 MiB"));
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                mtime: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
            })
        }
    }

    struct HeldSource {
        path: PathBuf,
        file: File,
        stamp: Stamp,
    }

    impl HeldSource {
        fn open(path: &Path) -> Result<Self, ApiError> {
            if path.as_os_str().len() > 4096 {
                return Err(invalid("plugin source pathname exceeds 4096 bytes"));
            }
            let stamp = Stamp::new(&std::fs::symlink_metadata(path).map_err(io_error)?)?;
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let file = File::from(
                rustix::fs::open(path, flags, Mode::empty())
                    .map_err(|_| invalid("cannot open checked plugin source"))?,
            );
            let held = Self { path: path.to_owned(), file, stamp };
            held.check()?;
            Ok(held)
        }

        fn check(&self) -> Result<(), ApiError> {
            let descriptor = Stamp::new(&self.file.metadata().map_err(io_error)?)?;
            let pathname = Stamp::new(&std::fs::symlink_metadata(&self.path).map_err(io_error)?)?;
            if descriptor != self.stamp || pathname != self.stamp {
                return Err(invalid("original plugin source was modified or replaced during checked opening"));
            }
            Ok(())
        }

        #[cfg(test)]
        fn snapshot(&mut self) -> Result<Vec<u8>, ApiError> {
            self.check()?;
            let expected = usize::try_from(self.stamp.length).map_err(|_| invalid("source length overflow"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(expected)
                .map_err(|_| ApiError::Unavailable("cannot reserve bounded source preflight bytes".into()))?;
            let mut buffer = [0u8; 8192];
            loop {
                self.check()?;
                let count = match self.file.read(&mut buffer) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(io_error(error)),
                };
                self.check()?;
                if count == 0 {
                    break;
                }
                if count > expected.saturating_sub(bytes.len()) {
                    return Err(invalid("plugin source grew during raw preflight"));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            if bytes.len() != expected {
                return Err(invalid("plugin source changed length during raw preflight"));
            }
            self.check()?;
            Ok(bytes)
        }
    }

    pub(super) fn open(
        session: &Session,
        path: &Path,
        arch: Option<Arch>,
        image: Option<ImageAt>,
    ) -> Result<Arc<Project>, ApiError> {
        if session.packs().configured() {
            return Err(invalid("configured data packs are not admitted by source-only plugin triage"));
        }
        let held = HeldSource::open(path)?;
        // The first descriptor alone cannot authorize a later reopened path. Re-admit the exact mapping the
        // loader will consume, under its own pre-map 16 MiB descriptor cap, before any native producer runs.
        // Session's delegate supplies fresh checked sidecar ingestion without cached legacy history.
        let mut admit = |bytes: &[u8]| {
            preload::admit_before_load(bytes, image)?;
            held.check()
        };
        let result = session.open_plugin_triage_at(path, arch, image, &mut admit);
        held.check()?;
        let project = result?;
        project.binary.validate_backing_source().map_err(|_| invalid("checked source lost its original mapping"))?;
        preload::reject_loaded_managed(&project)?;
        let cancellation = AtomicBool::new(false);
        let mut observer = |_| {};
        let control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
        bounds::preflight_source(&project, &control)?;
        preflight_names(&project)?;
        held.check()?;
        project.binary.validate_backing_source().map_err(|_| invalid("checked source mapping became stale"))?;
        Ok(project)
    }

    fn io_error(_: io::Error) -> ApiError {
        invalid("cannot inspect or read original plugin source")
    }

    #[cfg(test)]
    mod tests {
        use std::cell::Cell;
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::*;

        struct SwapFiles {
            directory: PathBuf,
            source: PathBuf,
            replacement: PathBuf,
        }

        impl SwapFiles {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let directory = std::env::temp_dir().join(format!(
                    "rampage-plugin-profile-swap-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                std::fs::create_dir(&directory).unwrap();
                let files =
                    Self { source: directory.join("source"), replacement: directory.join("replacement"), directory };
                let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/net-client-x64.elf");
                std::fs::copy(fixture, &files.source).unwrap();
                files
            }

            fn replace(&self, bytes: &[u8]) {
                File::options().write(true).create_new(true).open(&self.replacement).unwrap().write_all(bytes).unwrap();
                std::fs::rename(&self.replacement, &self.source).unwrap();
            }
        }

        impl Drop for SwapFiles {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.source);
                let _ = std::fs::remove_file(&self.replacement);
                let _ = std::fs::remove_dir(&self.directory);
            }
        }

        #[test]
        fn swapped_clr_and_go_profiles_are_rejected_on_the_actual_parser_mapping() {
            for replacement_name in ["Microsoft.Bcl.HashCode.dll", "hello-go-x64.elf"] {
                let files = SwapFiles::new();
                let mut original = HeldSource::open(&files.source).unwrap();
                preload::admit_before_load(&original.snapshot().unwrap(), None).unwrap();
                let replacement_path =
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(replacement_name);
                let replacement = std::fs::read(replacement_path).unwrap();
                let expected = preload::admit_before_load(&replacement, None).unwrap_err().to_string();
                files.replace(&replacement);
                let callback_entered = Cell::new(false);
                let mut admit = |actual: &[u8]| {
                    callback_entered.set(true);
                    assert_eq!(actual, replacement.as_slice());
                    preload::admit_before_load(actual, None)
                };
                let result = Session::default().open_plugin_triage_at(&files.source, None, None, &mut admit);
                assert!(callback_entered.get());
                assert_eq!(result.err().unwrap().to_string(), expected);
                assert!(original.check().is_err());
            }
        }

        #[test]
        fn admitted_pe_replacement_still_cannot_upgrade_the_original_descriptor() {
            let files = SwapFiles::new();
            let mut original = HeldSource::open(&files.source).unwrap();
            preload::admit_before_load(&original.snapshot().unwrap(), None).unwrap();
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
            let replacement = std::fs::read(path).unwrap();
            preload::admit_before_load(&replacement, None).unwrap();
            files.replace(&replacement);
            let entered = Cell::new(false);
            let mut admit = |actual: &[u8]| {
                entered.set(true);
                assert_eq!(actual, replacement.as_slice());
                preload::admit_before_load(actual, None)?;
                original.check()
            };
            let result = Session::default().open_plugin_triage_at(&files.source, None, None, &mut admit);
            assert!(entered.get());
            assert!(result.err().unwrap().to_string().contains("modified or replaced"));
        }

        #[test]
        fn swapped_oversized_source_never_reaches_admission_or_native_producers() {
            let files = SwapFiles::new();
            let mut original = HeldSource::open(&files.source).unwrap();
            preload::admit_before_load(&original.snapshot().unwrap(), None).unwrap();
            File::create(&files.replacement).unwrap().set_len(MAX_PLUGIN_TRIAGE_SOURCE_BYTES as u64 + 1).unwrap();
            std::fs::rename(&files.replacement, &files.source).unwrap();
            let callback_entered = Cell::new(false);
            let mut admit = |_: &[u8]| {
                callback_entered.set(true);
                Ok(())
            };
            let result = Session::default().open_plugin_triage_at(&files.source, None, None, &mut admit);
            assert!(result.is_err());
            assert!(!callback_entered.get());
            assert!(original.check().is_err());
        }

        #[test]
        fn preflight_descriptor_cannot_be_upgraded_by_same_content_path_replacement() {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            struct Files {
                source: PathBuf,
                replacement: PathBuf,
            }
            impl Drop for Files {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(&self.source);
                    let _ = std::fs::remove_file(&self.replacement);
                }
            }
            let source = std::env::temp_dir().join(format!(
                "rampage-plugin-preload-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            let replacement = source.with_extension("replacement");
            let files = Files { source, replacement };
            File::options().write(true).create_new(true).open(&files.source).unwrap().set_len(4).unwrap();
            let mut held = HeldSource::open(&files.source).unwrap();
            let before = held.snapshot().unwrap();
            File::options().write(true).create_new(true).open(&files.replacement).unwrap().set_len(4).unwrap();
            std::fs::rename(&files.replacement, &files.source).unwrap();
            assert_eq!(std::fs::read(&files.source).unwrap(), before);
            assert!(held.check().is_err());
        }
    }
}
