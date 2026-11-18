//! Lists and extracts firmware filesystem images: SquashFS 4.0, ext2/3/4, Android sparse images, Android OTA
//! payloads (full payloads), cpio (newc), tar, ZIP (APK, AAB, JAR), UBI and UBIFS, nested inside one another. Every image is treated as hostile:
//! see [`Limits`] and [`extract`] for what is enforced. Design: docs/plans/2026-11-15-firmware-unpacking.md.

mod codec;
mod cpio;
mod error;
mod ext;
mod extract;
mod image;
mod limits;
mod ota;
mod source;
mod sparse;
mod squashfs;
mod tar;
mod ubi;
mod ubifs;
mod zip;

use std::path::Path;
use std::sync::Arc;

pub use codec::{Codec, decompress};
pub use error::{Result, UnpackError};
pub use extract::{Executable, ExtractReport, Skipped, executable_format, safe_components};
pub use image::{Entry, EntryKind, Format, Image, Layer, Opened, detect, detect_bytes, find, normalize, open_chain};
pub use limits::{Budget, Limits, RATIO_FLOOR};
pub use source::{Cursor, FileRange, ReadAt, Slice, Source};

/// Where an image lies in its file: from `offset`, for `length` bytes or to the end.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct At {
    pub offset: u64,
    pub length: Option<u64>,
}

/// The bytes of the regular file at `path` that `at` selects, as a source.
pub fn file_source(path: &Path, at: At) -> Result<Source> {
    let image_offset = at.offset;
    let file = std::fs::File::open(path).map_err(|error| UnpackError::io(format!("open {}", path.display()), error))?;
    let metadata = file.metadata().map_err(|error| UnpackError::io("inspect the file", error))?;
    if !metadata.is_file() {
        return Err(UnpackError::Invalid(format!("{} is not a regular file", path.display())));
    }
    let size = metadata.len();
    if image_offset >= size {
        return Err(UnpackError::Invalid(format!(
            "image_offset {image_offset} is past the end of the {size}-byte file"
        )));
    }
    let available = size - image_offset;
    let length = match at.length {
        Some(length) if length == 0 || length > available => {
            return Err(UnpackError::Invalid(format!(
                "image_length {length} does not fit the {available} bytes after image_offset"
            )));
        }
        Some(length) => length,
        None => available,
    };
    Ok(Arc::new(FileRange::new(file, image_offset, length)))
}

/// Every entry of the image `at` selects in `path`, after descending through `inner`.
#[derive(Debug)]
pub struct Listing {
    pub layers: Vec<Layer>,
    pub entries: Vec<Entry>,
}

/// Lists the image `at` selects in `path`, or the one `inner` names inside it (see [`open_chain`]).
pub fn list(path: &Path, at: At, inner: &[String], limits: Limits) -> Result<Listing> {
    let mut budget = Budget::new(limits);
    let _meter = limits::MeterScope::new(budget.limits.max_ratio);
    let opened = open_chain(file_source(path, at)?, inner, &mut budget)?;
    Ok(Listing { layers: opened.layers, entries: opened.image.entries().to_vec() })
}

#[derive(Debug)]
pub struct Extraction {
    pub layers: Vec<Layer>,
    pub report: ExtractReport,
}

/// Extracts the entries `selection` names (all when empty) of the image `at` selects in `path`, or of the one
/// `inner` names inside it, under `output_dir`, which must be new or empty.
pub fn extract(
    path: &Path,
    at: At,
    inner: &[String],
    output_dir: &Path,
    selection: &[String],
    limits: Limits,
) -> Result<Extraction> {
    let mut budget = Budget::new(limits);
    let _meter = limits::MeterScope::new(budget.limits.max_ratio);
    let opened = open_chain(file_source(path, at)?, inner, &mut budget)?;
    let report = extract::extract(&*opened.image, output_dir, selection, &mut budget)?;
    Ok(Extraction { layers: opened.layers, report })
}

/// What [`read_entries`] read: the layers, every entry, and the content of the selected ones by entry index.
#[derive(Debug)]
pub struct Selected {
    pub layers: Vec<Layer>,
    pub entries: Vec<Entry>,
    pub contents: Vec<(usize, Vec<u8>)>,
}

/// Opens the image `at` selects in `path` (or the one `inner` names inside it) and reads the content of the file
/// entries `select` picks into memory, under `limits`: per-file and total bytes, and the compression ratio.
pub fn read_entries(
    path: &Path,
    at: At,
    inner: &[String],
    limits: Limits,
    select: &mut dyn FnMut(&Entry) -> bool,
) -> Result<Selected> {
    read_chosen(path, at, inner, limits, &mut |entries| {
        entries.iter().enumerate().filter(|(_, entry)| select(entry)).map(|(index, _)| index).collect()
    })
}

/// As [`read_entries`], with `choose` seeing every entry at once and returning the indexes to read, in the order
/// to read them (the budget is charged in that order).
pub fn read_chosen(
    path: &Path,
    at: At,
    inner: &[String],
    limits: Limits,
    choose: &mut dyn FnMut(&[Entry]) -> Vec<usize>,
) -> Result<Selected> {
    let mut budget = Budget::new(limits);
    let _meter = limits::MeterScope::new(budget.limits.max_ratio);
    let opened = open_chain(file_source(path, at)?, inner, &mut budget)?;
    let entries = opened.image.entries().to_vec();
    let mut contents = Vec::new();
    for index in choose(&entries) {
        let Some(entry) = entries.get(index) else { continue };
        if entry.kind != EntryKind::File {
            continue;
        }
        let mut bytes = Vec::new();
        opened.image.read(index, &mut budget, &mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        contents.push((index, bytes));
    }
    Ok(Selected { layers: opened.layers, entries, contents })
}

/// The image format at the start of the file at `path`, if it is one this crate recognises.
pub fn sniff(path: &Path) -> Option<Format> {
    let source = file_source(path, At::default()).ok()?;
    detect(&*source)
}
