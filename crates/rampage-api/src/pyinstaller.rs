//! PyInstaller CArchive inspection on any file, without opening it as a project.

use std::path::{Path, PathBuf};

use rampage_loaders::pyinstaller::{PyInstallerArchive, TocEntry};
use serde::Serialize;

use crate::ApiError;

/// The most TOC entries one page returns.
pub const MAX_PYINSTALLER_PAGE: usize = 100;
/// The JSON byte budget of one format-inspection result; pages hold fewer items when theirs are long.
pub const MAX_FORMAT_RESULT_BYTES: usize = 60_000;

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

/// The PyInstaller CArchive appended to the regular file at `path`, with `limit` TOC entries (default and at most
/// [`MAX_PYINSTALLER_PAGE`]) from `offset`; `None` when the file's last 8 MiB hold no cookie magic.
pub fn pyinstaller_archive(
    path: &Path,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Option<PyInstallerPage>, ApiError> {
    let limit = limit.unwrap_or(MAX_PYINSTALLER_PAGE);
    if !(1..=MAX_PYINSTALLER_PAGE).contains(&limit) {
        return Err(ApiError::Invalid(format!("limit must be in 1..={MAX_PYINSTALLER_PAGE}")));
    }
    let Some(mut archive) = rampage_loaders::pyinstaller::pyinstaller_file(path)
        .map_err(|source| ApiError::Load { path: path.to_owned(), source })?
    else {
        return Ok(None);
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
    let window = fit_page(&all, offset, limit, &page)?;
    page.byte_capped = window.byte_capped;
    page.entries = window.items;
    page.returned = page.entries.len();
    page.more = window.more;
    page.next_offset = window.more.then_some(offset + page.returned);
    Ok(Some(page))
}

pub(crate) struct Window<T> {
    pub items: Vec<T>,
    pub more: bool,
    pub byte_capped: bool,
}

/// At most `limit` of `items` from `offset`, as many whole ones as fit [`MAX_FORMAT_RESULT_BYTES`] alongside
/// `header` (the result without them). A page that cannot fit even one item is an error, so paging always
/// progresses.
pub(crate) fn fit_page<T: Serialize + Clone>(
    items: &[T],
    offset: usize,
    limit: usize,
    header: &impl Serialize,
) -> Result<Window<T>, ApiError> {
    // Room for the paging numbers the header does not hold yet.
    let mut used = json_size(header)? + 64;
    let mut window = Window { items: Vec::new(), more: false, byte_capped: false };
    for item in items.iter().skip(offset).take(limit) {
        let size = json_size(item)? + 1;
        if used + size > MAX_FORMAT_RESULT_BYTES {
            window.byte_capped = true;
            break;
        }
        used += size;
        window.items.push(item.clone());
    }
    window.more = offset.saturating_add(window.items.len()) < items.len();
    if window.more && window.items.is_empty() && offset < items.len() {
        return Err(ApiError::Invalid("result cannot fit one item within its JSON byte budget".to_owned()));
    }
    Ok(window)
}

fn json_size(value: &impl Serialize) -> Result<usize, ApiError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| ApiError::Invalid(format!("result is not JSON-serializable: {error}")))
}
