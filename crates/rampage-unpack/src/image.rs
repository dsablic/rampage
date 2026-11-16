//! Image recognition, the common entry model, and opening nested images layer by layer.

use std::sync::Arc;

use serde::Serialize;

use crate::error::{Result, UnpackError};
use crate::limits::{Budget, Limits};
use crate::source::{ReadAt, Source, Spool, read_prefix};

/// A recognised image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Squashfs,
    /// ext2, ext3 or ext4.
    Ext,
    AndroidSparse,
    /// An Android OTA `payload.bin` (update_engine).
    OtaPayload,
    Cpio,
    Tar,
    Ubi,
    Ubifs,
    /// A ZIP archive: also APK, AAB and JAR files.
    Zip,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Squashfs => "squashfs",
            Format::Ext => "ext",
            Format::AndroidSparse => "android_sparse",
            Format::OtaPayload => "ota_payload",
            Format::Cpio => "cpio",
            Format::Tar => "tar",
            Format::Ubi => "ubi",
            Format::Ubifs => "ubifs",
            Format::Zip => "zip",
        }
    }
}

/// The format of the image at the start of `source`, from its magic numbers.
pub fn detect(source: &dyn ReadAt) -> Option<Format> {
    let head = read_prefix(source, 0, 1024 + 64).ok()?;
    detect_bytes(&head)
}

/// [`detect`] on the first 1088 bytes of an image (fewer for a short one).
pub fn detect_bytes(head: &[u8]) -> Option<Format> {
    let at = |offset: usize, magic: &[u8]| head.get(offset..offset + magic.len()) == Some(magic);
    if at(0, b"hsqs") || at(0, b"sqsh") {
        return Some(Format::Squashfs);
    }
    if at(0, &0xed26_ff3au32.to_le_bytes()) {
        return Some(Format::AndroidSparse);
    }
    if at(0, b"CrAU") {
        return Some(Format::OtaPayload);
    }
    if at(0, b"UBI#") {
        return Some(Format::Ubi);
    }
    if at(0, &0x0610_1831u32.to_le_bytes()) {
        return Some(Format::Ubifs);
    }
    if at(0, b"PK\x03\x04") || at(0, b"PK\x05\x06") {
        return Some(Format::Zip);
    }
    if at(0, b"070701") || at(0, b"070702") {
        return Some(Format::Cpio);
    }
    if at(257, b"ustar") && crate::tar::header_checksum_ok(head.get(..512)?) {
        return Some(Format::Tar);
    }
    if at(1024 + 56, &0xef53u16.to_le_bytes()) {
        return Some(Format::Ext);
    }
    None
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    /// A partition or unpacked image inside a container (an OTA partition, an unsparsed image).
    Image,
    /// An entry type this reader does not interpret.
    Other,
}

impl EntryKind {
    /// Whether the entry has content to read.
    pub fn has_content(self) -> bool {
        matches!(self, EntryKind::File | EntryKind::Image)
    }

    /// The kind for a POSIX `st_mode` file-type field.
    pub(crate) fn from_mode(mode: u32) -> Self {
        match mode & 0o170_000 {
            0o100_000 => EntryKind::File,
            0o040_000 => EntryKind::Dir,
            0o120_000 => EntryKind::Symlink,
            0o020_000 => EntryKind::CharDevice,
            0o060_000 => EntryKind::BlockDevice,
            0o010_000 => EntryKind::Fifo,
            0o140_000 => EntryKind::Socket,
            _ => EntryKind::Other,
        }
    }
}

/// One file, directory, link, node or partition in an image.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// The path inside the image, `/`-separated without a leading `/`, as stored (lossily decoded to UTF-8). It is
    /// not sanitised: extraction checks it.
    pub path: String,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    pub size: u64,
    /// Permission bits, setuid, setgid and sticky included.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// A symlink's target, or the path a hard link names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Anything the reader wants said about the entry (a delta partition, a hard link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A list of entries and a way to read the content of each.
pub trait Image {
    fn format(&self) -> Format;
    fn entries(&self) -> &[Entry];
    /// Streams the content of entry `index` to `sink`, refusing more than `budget`'s per-file limit and charging
    /// every byte handed to `sink` (and any rebuild written on the way) to `budget`.
    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;
    /// Facts about the image as a whole, for the listing's layer record.
    fn notes(&self) -> Vec<String> {
        Vec::new()
    }
}

/// One image in a nesting chain.
#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    pub format: Format,
    /// The image's size in bytes (the unsparsed size for a sparse image).
    pub size: u64,
    /// The entry of the previous layer this image was read from; `None` for the outer image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// An opened image with the layers that lead to it, outermost first.
pub struct Opened {
    pub layers: Vec<Layer>,
    pub image: Box<dyn Image>,
}

/// Opens the image in `source`, unwrapping an Android sparse image to the filesystem inside it.
pub fn open(source: Source, entry: Option<String>, limits: &Limits, depth: usize) -> Result<Opened> {
    if depth >= limits.max_depth {
        return Err(UnpackError::Limit(format!("images nested deeper than {} layers", limits.max_depth)));
    }
    let size = source.size();
    let format = detect(&*source).ok_or_else(|| {
        UnpackError::Unsupported(
            "no SquashFS, ext2/3/4, Android sparse, OTA payload, cpio, tar or ZIP image starts here".to_owned(),
        )
    })?;
    let image: Box<dyn Image> = match format {
        Format::Squashfs => Box::new(crate::squashfs::Squashfs::open(source, limits)?),
        Format::Ext => Box::new(crate::ext::Ext::open(source, limits)?),
        Format::OtaPayload => Box::new(crate::ota::Payload::open(source, limits)?),
        Format::Cpio => Box::new(crate::cpio::Cpio::open(source, limits)?),
        Format::Tar => Box::new(crate::tar::Tar::open(source, limits)?),
        Format::Zip => Box::new(crate::zip::Zip::open(source, limits)?),
        Format::AndroidSparse => {
            let sparse = crate::sparse::SparseView::open(source)?;
            let notes = sparse.notes();
            let inner: Source = Arc::new(sparse);
            let layer = Layer { format, size: inner.size(), entry, notes };
            if detect(&*inner).is_some() {
                let mut opened = open(inner, None, limits, depth + 1)?;
                opened.layers.insert(0, layer);
                return Ok(opened);
            }
            let image = Box::new(crate::sparse::Unsparsed::new(inner));
            return Ok(Opened { layers: vec![layer], image });
        }
        Format::Ubi | Format::Ubifs => {
            return Err(UnpackError::Unsupported(format!(
                "{} images are recognised but not read yet; carve or file_layout can still inspect the bytes",
                if format == Format::Ubi { "UBI" } else { "UBIFS" }
            )));
        }
    };
    let layer = Layer { format, size, entry, notes: image.notes() };
    Ok(Opened { layers: vec![layer], image })
}

/// `path` as image paths are compared: without leading `/` or `./` and trailing `/`.
pub fn normalize(path: &str) -> &str {
    let mut path = path;
    loop {
        if let Some(rest) = path.strip_prefix("./") {
            path = rest;
        } else if let Some(rest) = path.strip_prefix('/') {
            path = rest;
        } else {
            break;
        }
    }
    path.trim_end_matches('/')
}

/// The index of the entry named `path` (compared after [`normalize`]).
pub fn find(image: &dyn Image, path: &str) -> Option<usize> {
    let wanted = normalize(path);
    image.entries().iter().position(|entry| normalize(&entry.path) == wanted)
}

/// Spools entry `index` of `image` into an unlinked temporary file, charging `budget`.
pub(crate) fn spool(image: &dyn Image, index: usize, budget: &mut Budget) -> Result<Source> {
    let mut spool = Spool::new().map_err(|error| UnpackError::io("create a temporary file", error))?;
    image.read(index, budget, &mut |chunk| {
        spool.append(chunk).map_err(|error| UnpackError::io("write a temporary file", error))
    })?;
    Ok(spool.into_source())
}

/// Opens the image in `source` and descends through `inner`, a chain of entry paths each naming an image inside
/// the previous one (an OTA partition, then a file inside it).
pub fn open_chain(source: Source, inner: &[String], budget: &mut Budget) -> Result<Opened> {
    let limits = budget.limits;
    let mut opened = open(source, None, &limits, 0)?;
    for path in inner {
        let index = find(&*opened.image, path).ok_or_else(|| {
            UnpackError::Invalid(format!("no entry `{path}` in the {} image", opened.image.format().name()))
        })?;
        let entry = &opened.image.entries()[index];
        if !entry.kind.has_content() {
            return Err(UnpackError::Invalid(format!("entry `{path}` is not a file or partition")));
        }
        let entry_path = entry.path.clone();
        let nested = spool(&*opened.image, index, budget)?;
        let next = open(nested, Some(entry_path), &limits, opened.layers.len())?;
        let mut layers = std::mem::take(&mut opened.layers);
        layers.extend(next.layers);
        opened = Opened { layers, image: next.image };
    }
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_normalize_for_lookup() {
        assert_eq!(normalize("/./a/b/"), "a/b");
        assert_eq!(normalize("./system.img"), "system.img");
        assert_eq!(normalize("/"), "");
    }
}
