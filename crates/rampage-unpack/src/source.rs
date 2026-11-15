//! Random-access byte sources: a file range, a spooled temporary file, memory, or a view built over another source.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

/// Bytes read by offset. Reads past the end fail.
pub trait ReadAt: Send + Sync {
    fn size(&self) -> u64;
    /// Fills `buf` from `offset`, or fails (with `UnexpectedEof` past the end).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

pub type Source = Arc<dyn ReadAt>;

fn past_end() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the image")
}

/// Whether `len` bytes from `offset` lie inside `size` bytes.
pub(crate) fn within(offset: u64, len: u64, size: u64) -> bool {
    offset.checked_add(len).is_some_and(|end| end <= size)
}

/// `size` bytes of a file from `base`.
pub struct FileRange {
    file: File,
    base: u64,
    size: u64,
}

impl FileRange {
    pub fn new(file: File, base: u64, size: u64) -> Self {
        Self { file, base, size }
    }
}

impl ReadAt for FileRange {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if !within(offset, buf.len() as u64, self.size) {
            return Err(past_end());
        }
        let at = self.base.checked_add(offset).ok_or_else(past_end)?;
        read_exact_at(&self.file, at, buf)
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match std::os::windows::fs::FileExt::seek_read(file, buf, offset) {
            Ok(0) => return Err(past_end()),
            Ok(read) => {
                buf = &mut buf[read..];
                offset += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl ReadAt for Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if !within(offset, buf.len() as u64, self.len() as u64) {
            return Err(past_end());
        }
        let start = offset as usize;
        buf.copy_from_slice(&self[start..start + buf.len()]);
        Ok(())
    }
}

/// `size` bytes of another source from `base`.
pub struct Slice {
    inner: Source,
    base: u64,
    size: u64,
}

impl Slice {
    /// The range, or `None` when it does not lie inside `inner`.
    pub fn new(inner: Source, base: u64, size: u64) -> Option<Self> {
        within(base, size, inner.size()).then_some(Self { inner, base, size })
    }
}

impl ReadAt for Slice {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if !within(offset, buf.len() as u64, self.size) {
            return Err(past_end());
        }
        self.inner.read_at(self.base + offset, buf)
    }
}

/// Up to `len` bytes from `offset` (fewer at the end of the source).
pub(crate) fn read_prefix(source: &dyn ReadAt, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let available = source.size().saturating_sub(offset).min(len as u64) as usize;
    let mut buf = vec![0; available];
    source.read_at(offset, &mut buf)?;
    Ok(buf)
}

/// A source read as a stream, with `Read`, `Seek` and (through `BufReader`) `BufRead`.
pub struct Cursor {
    source: Source,
    position: u64,
    end: u64,
}

impl Cursor {
    pub fn new(source: Source) -> Self {
        let end = source.size();
        Self { source, position: 0, end }
    }

    /// A stream over `len` bytes from `offset` (clamped to the source).
    pub fn range(source: Source, offset: u64, len: u64) -> Self {
        let size = source.size();
        let start = offset.min(size);
        let end = start.saturating_add(len).min(size);
        Self { source, position: start, end }
    }
}

impl Read for Cursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.end.saturating_sub(self.position);
        let count = (buf.len() as u64).min(remaining) as usize;
        if count == 0 {
            return Ok(0);
        }
        self.source.read_at(self.position, &mut buf[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Cursor {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "seek outside the image");
        let target = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.end.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = target.ok_or_else(invalid)?;
        Ok(self.position)
    }
}

/// An unlinked temporary file holding a nested image or partition; it is deleted when the last reference goes.
pub(crate) struct Spool {
    file: File,
    size: u64,
}

impl Spool {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self { file: tempfile::tempfile()?, size: 0 })
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn set_size(&mut self, size: u64) -> io::Result<()> {
        self.file.set_len(size)?;
        self.size = size;
        Ok(())
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_all_at(&self.file, self.size, bytes)?;
        self.size += bytes.len() as u64;
        Ok(())
    }

    pub(crate) fn into_source(self) -> Source {
        let size = self.size;
        Arc::new(FileRange::new(self.file, 0, size))
    }
}

#[cfg(unix)]
pub(crate) fn write_all_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, bytes, offset)
}

#[cfg(windows)]
pub(crate) fn write_all_at(file: &File, mut offset: u64, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = std::os::windows::fs::FileExt::seek_write(file, bytes, offset)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "temporary file write failed"));
        }
        bytes = &bytes[written..];
        offset += written as u64;
    }
    Ok(())
}
