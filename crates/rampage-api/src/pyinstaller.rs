//! PyInstaller CArchive inspection on any file, without opening it as a project.

use std::path::{Path, PathBuf};

use rampage_loaders::pyinstaller::{PyInstallerArchive, TocEntry};
use serde::Serialize;

use crate::ApiError;
use crate::rows::{fit_window, item_budget};

/// The most TOC entries one page returns.
pub const MAX_PYINSTALLER_PAGE: usize = 100;

/// A CArchive's cookie, package and TOC facts with one page of its TOC entries.
#[derive(Debug, Serialize)]
pub struct PyInstallerPage {
    pub file_path: PathBuf,
    #[serde(flatten)]
    pub archive: PyInstallerArchive,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    /// Whether the JSON byte budget, not `limit`, ended the page.
    pub byte_capped: bool,
    pub entries: Vec<TocEntry>,
    pub limitations: Vec<&'static str>,
}

/// What [`pyinstaller_archive`] found: an archive page, or magic matches none of which validated as a cookie.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum PyInstallerResult {
    Archive(Box<PyInstallerPage>),
    NoCookie(PyInstallerMiss),
}

/// A file whose cookie magic matches all failed to validate: not a PyInstaller archive, or a damaged one.
#[derive(Debug, Serialize)]
pub struct PyInstallerMiss {
    pub file_path: PathBuf,
    /// Always null, so the two result shapes are told apart by this key.
    pub archive: Option<()>,
    /// Why each magic match, newest first, was not taken as a cookie.
    pub rejected_candidates: Vec<String>,
}

/// The PyInstaller CArchive appended to the regular file at `path`, with `limit` TOC entries (default and at most
/// [`MAX_PYINSTALLER_PAGE`], fewer when they would overrun the result's JSON byte budget) from `offset`; `None`
/// when the file's last 8 MiB hold no cookie magic.
pub fn pyinstaller_archive(
    path: &Path,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Option<PyInstallerResult>, ApiError> {
    let limit = limit.unwrap_or(MAX_PYINSTALLER_PAGE);
    if !(1..=MAX_PYINSTALLER_PAGE).contains(&limit) {
        return Err(ApiError::Invalid(format!("limit must be in 1..={MAX_PYINSTALLER_PAGE}")));
    }
    let search = rampage_loaders::pyinstaller::pyinstaller_file(path)
        .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
    let Some(mut archive) = search.archive else {
        return Ok((!search.rejected.is_empty()).then(|| {
            PyInstallerResult::NoCookie(PyInstallerMiss {
                file_path: path.to_owned(),
                archive: None,
                rejected_candidates: search.rejected,
            })
        }));
    };
    let all = std::mem::take(&mut archive.entries);
    let offset = offset.unwrap_or(0);
    let mut page = PyInstallerPage {
        file_path: path.to_owned(),
        archive,
        offset,
        limit,
        returned: 0,
        more: false,
        next_offset: None,
        byte_capped: false,
        entries: Vec::new(),
        limitations: vec![
            "The cookie is searched for only in the file's last 8 MiB; magic matches that do not validate are skipped.",
            "Entry payloads are located, not read: no extraction, decompression, decryption or pyc decompilation.",
            "Sizes, positions and flags are as the TOC declares them; data_in_bounds checks only the package extent.",
            "The PYZ header is read from an uncompressed PYZ entry only; its zlib-compressed TOC is not read.",
        ],
    };
    let window = fit_window(all.into_iter().skip(offset), limit, item_budget(&page)?)?;
    page.byte_capped = window.byte_capped;
    page.entries = window.items;
    page.returned = page.entries.len();
    page.more = offset.saturating_add(page.returned) < page.archive.entries_total;
    page.next_offset = page.more.then_some(offset + page.returned);
    Ok(Some(PyInstallerResult::Archive(Box::new(page))))
}
