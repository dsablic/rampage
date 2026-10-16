use std::path::Path;

use crate::ApiError;

/// Reads one explicitly selected regular component file into an execution snapshot. Final-leaf symlinks and
/// special files are refused; no directory permissions policy, scanning or autoloading is imposed. Observable
/// descriptor/path changes are refused, but these checks do not provide an atomic filesystem snapshot. The
/// runtime hashes and executes the returned bytes, never reopening this pathname to establish authority.
pub fn read_plugin_triage_component(path: &Path) -> Result<Vec<u8>, ApiError> {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
    {
        supported::ComponentSource::open(path)?.read()
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
    {
        let _ = path;
        Err(ApiError::Unavailable("checked triage component opening is unavailable on this platform".into()))
    }
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod supported {
    use std::fs::{File, Metadata};
    use std::io::{self, Read};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use rustix::fs::{Mode, OFlags, open};

    use crate::ApiError;

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        length: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl Stamp {
        fn new(metadata: &Metadata) -> Result<Self, ApiError> {
            if !metadata.is_file() || metadata.len() > rampage_plugin::MAX_COMPONENT_BYTES as u64 {
                return Err(invalid("component must be a bounded regular file, not a symlink or special file"));
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
    }

    pub(super) struct ComponentSource {
        path: PathBuf,
        file: File,
        stamp: Stamp,
    }

    impl ComponentSource {
        pub(super) fn open(path: &Path) -> Result<Self, ApiError> {
            let before = std::fs::symlink_metadata(path).map_err(io_error)?;
            let stamp = Stamp::new(&before)?;
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let file =
                File::from(open(path, flags, Mode::empty()).map_err(|_| {
                    invalid("cannot open selected component with checked nonblocking no-follow semantics")
                })?);
            let source = Self { path: path.to_owned(), file, stamp };
            source.check()?;
            Ok(source)
        }

        fn check(&self) -> Result<(), ApiError> {
            let descriptor = self.file.metadata().map_err(io_error)?;
            let pathname = std::fs::symlink_metadata(&self.path).map_err(io_error)?;
            if Stamp::new(&descriptor)? != self.stamp || Stamp::new(&pathname)? != self.stamp {
                return Err(invalid("selected component was modified or replaced while reading"));
            }
            Ok(())
        }

        pub(super) fn read(mut self) -> Result<Vec<u8>, ApiError> {
            // Validate the retained descriptor and pathname before reserving any component-byte allocation.
            self.check()?;
            let expected =
                usize::try_from(self.stamp.length).map_err(|_| invalid("component length is not addressable"))?;
            if expected > rampage_plugin::MAX_COMPONENT_BYTES {
                return Err(invalid("component exceeds runtime byte limit"));
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(expected)
                .map_err(|_| ApiError::Unavailable("cannot allocate bounded component snapshot".into()))?;
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
                if count > expected.saturating_sub(bytes.len())
                    || count > rampage_plugin::MAX_COMPONENT_BYTES.saturating_sub(bytes.len())
                {
                    return Err(invalid("component grew while reading; no snapshot admitted"));
                }
                // Initial reservation covers every admitted append; no read_to_end or unchecked Vec growth.
                bytes.extend_from_slice(&buffer[..count]);
            }
            if bytes.len() != expected {
                return Err(invalid("component length changed while reading; no snapshot admitted"));
            }
            self.check()?;
            Ok(bytes)
        }
    }

    fn invalid(message: &str) -> ApiError {
        ApiError::Invalid(message.to_owned())
    }

    fn io_error(_: io::Error) -> ApiError {
        invalid("cannot inspect or read selected triage component")
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::*;
        use crate::plugin_triage::read_plugin_triage_component;

        struct Directory(PathBuf);

        impl Directory {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let path = std::env::temp_dir().join(format!(
                    "rampage-component-read-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }

            fn path(&self, name: &str) -> PathBuf {
                self.0.join(name)
            }
        }

        impl Drop for Directory {
            fn drop(&mut self) {
                for name in ["component", "replacement", "link", "fifo"] {
                    let _ = std::fs::remove_file(self.path(name));
                }
                let _ = std::fs::remove_dir(&self.0);
            }
        }

        #[test]
        fn binary_snapshot_is_independent_of_later_path_contents_and_needs_no_private_directory() {
            let directory = Directory::new();
            std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = directory.path("component");
            let content = [0, 0xff, 0xfe, b'\n', 0x80];
            std::fs::write(&path, content).unwrap();
            let snapshot = read_plugin_triage_component(&path).unwrap();
            std::fs::write(&path, b"changed after admission").unwrap();
            assert_eq!(snapshot, content);
        }

        #[test]
        fn runtime_size_cap_is_enforced_before_snapshot_allocation() {
            let directory = Directory::new();
            let path = directory.path("component");
            let file = File::create(&path).unwrap();
            file.set_len(rampage_plugin::MAX_COMPONENT_BYTES as u64 + 1).unwrap();
            assert!(read_plugin_triage_component(&path).is_err());
            file.set_len(rampage_plugin::MAX_COMPONENT_BYTES as u64).unwrap();
            assert_eq!(read_plugin_triage_component(&path).unwrap().len(), rampage_plugin::MAX_COMPONENT_BYTES);
        }

        #[test]
        fn final_symlink_fifo_directory_and_device_are_not_read() {
            let directory = Directory::new();
            let path = directory.path("component");
            std::fs::write(&path, b"component").unwrap();
            let link = directory.path("link");
            symlink(&path, &link).unwrap();
            assert!(read_plugin_triage_component(&link).is_err());
            let fifo = directory.path("fifo");
            assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
            assert!(read_plugin_triage_component(&fifo).is_err());
            assert!(read_plugin_triage_component(&directory.0).is_err());
            assert!(read_plugin_triage_component(Path::new("/dev/zero")).is_err());
        }

        #[test]
        fn descriptor_snapshot_rejects_same_bytes_at_replaced_path() {
            let directory = Directory::new();
            let path = directory.path("component");
            let replacement = directory.path("replacement");
            std::fs::write(&path, b"same bytes").unwrap();
            let source = ComponentSource::open(&path).unwrap();
            std::fs::write(&replacement, b"same bytes").unwrap();
            std::fs::rename(&replacement, &path).unwrap();
            assert!(source.read().is_err());
        }

        #[test]
        fn descriptor_snapshot_rejects_truncation_growth_and_leaf_symlink_replacement() {
            let directory = Directory::new();
            let path = directory.path("component");
            for length in [0, 128] {
                std::fs::write(&path, b"original bytes").unwrap();
                let source = ComponentSource::open(&path).unwrap();
                File::options().write(true).open(&path).unwrap().set_len(length).unwrap();
                assert!(source.read().is_err());
            }
            std::fs::write(&path, b"original bytes").unwrap();
            let source = ComponentSource::open(&path).unwrap();
            let replacement = directory.path("replacement");
            std::fs::write(&replacement, b"original bytes").unwrap();
            std::fs::remove_file(&path).unwrap();
            symlink(&replacement, &path).unwrap();
            assert!(source.read().is_err());
        }
    }
}
