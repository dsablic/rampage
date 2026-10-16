#[cfg(unix)]
mod platform {
    use std::fs::{File, Metadata};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};

    use rustix::fs::{Mode, OFlags};

    use crate::ApiError;

    fn invalid(message: &str) -> ApiError {
        ApiError::Invalid(message.to_owned())
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp(u64, u64, u64, i64, i64, i64, i64);

    fn stamp(metadata: &Metadata) -> Result<Stamp, ApiError> {
        if !metadata.is_file() {
            return Err(invalid("file-range input must be a regular file"));
        }
        Ok(Stamp(
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ))
    }

    pub(crate) struct RangeSource {
        file: File,
        path: PathBuf,
        stamp: Stamp,
        offset: u64,
        length: usize,
    }

    impl RangeSource {
        pub(crate) fn open(path: &Path, offset: u64, length: usize) -> Result<Self, ApiError> {
            let descriptor = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| ApiError::Unavailable(format!("file-range source open: {error}")))?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(io_error)?;
            let stamp = stamp(&metadata)?;
            if offset.checked_add(length as u64).is_none_or(|end| end > metadata.len()) {
                return Err(invalid("file range is outside the regular source"));
            }
            let source = Self { file, path: path.to_owned(), stamp, offset, length };
            source.revalidate()?;
            Ok(source)
        }

        pub(crate) fn read(&self) -> Result<Vec<u8>, ApiError> {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(self.length).map_err(|_| invalid("file-range input allocation failed"))?;
            bytes.resize(self.length, 0);
            self.file.read_exact_at(&mut bytes, self.offset).map_err(io_error)?;
            Ok(bytes)
        }

        pub(crate) fn revalidate(&self) -> Result<(), ApiError> {
            let descriptor = stamp(&self.file.metadata().map_err(io_error)?)?;
            let pathname = stamp(&std::fs::symlink_metadata(&self.path).map_err(io_error)?)?;
            if descriptor != self.stamp || pathname != self.stamp {
                return Err(invalid("file-range source changed or was replaced during observation"));
            }
            Ok(())
        }

        pub(crate) fn size(&self) -> u64 {
            self.stamp.2
        }
    }

    fn io_error(error: std::io::Error) -> ApiError {
        ApiError::Unavailable(format!("file-range source I/O: {error}"))
    }
}

#[cfg(not(unix))]
mod platform {
    use crate::ApiError;
    use std::path::Path;
    pub(crate) struct RangeSource;
    impl RangeSource {
        pub(crate) fn open(_: &Path, _: u64, _: usize) -> Result<Self, ApiError> {
            Err(ApiError::Unavailable("file ranges require Unix regular-file source checks".into()))
        }
        pub(crate) fn read(&self) -> Result<Vec<u8>, ApiError> {
            unreachable!()
        }
        pub(crate) fn revalidate(&self) -> Result<(), ApiError> {
            unreachable!()
        }
        pub(crate) fn size(&self) -> u64 {
            unreachable!()
        }
    }
}

pub(crate) use platform::RangeSource;
