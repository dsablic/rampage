//! Carving: finding embedded executables and containers inside any file, without opening it as a project.

use std::path::Path;

use rampage_loaders::carve::{Carving, Limits, MAX_CANDIDATES};
use serde::Serialize;

use crate::ApiError;

/// The most candidates one page returns, so that a page fits one tool result.
pub const MAX_CARVE_PAGE: usize = 100;

/// A page of a carving: `limit` candidates from `offset`, with the scan's limitations. The scan stops one
/// candidate past the page, so there is no total: `more` says whether another page follows.
#[derive(Debug, Serialize)]
pub struct CarvingPage {
    #[serde(flatten)]
    pub carving: Carving,
    pub offset: usize,
    pub more: bool,
}

/// Scans the regular file at `path` for embedded ELF, PE and Mach-O executables and common containers, reporting
/// at most `max_candidates` (at most [`MAX_CANDIDATES`]). Read-only: nothing is extracted or decompressed.
pub fn carve(path: &Path, max_candidates: Option<usize>) -> Result<Carving, ApiError> {
    let limits = Limits {
        max_candidates: max_candidates.unwrap_or(MAX_CANDIDATES).clamp(1, MAX_CANDIDATES),
        ..Limits::default()
    };
    rampage_loaders::carve::carve_file(path, &limits).map_err(|source| ApiError::Load { path: path.to_owned(), source })
}

/// [`carve`], keeping `limit` candidates (default and at most [`MAX_CARVE_PAGE`]) from `offset`. The file is
/// scanned only as far as the candidate after the page.
pub fn carve_page(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<CarvingPage, ApiError> {
    let offset = offset.unwrap_or(0).min(MAX_CANDIDATES);
    let limit = limit.unwrap_or(MAX_CARVE_PAGE).min(MAX_CARVE_PAGE);
    let page_end = offset + limit;
    let mut carving = carve(path, Some(page_end + 1))?;
    let more = carving.candidates.len() > page_end;
    // Below MAX_CANDIDATES the cap only marks the page's end; at it, the scan's own limit is reported.
    if page_end < MAX_CANDIDATES {
        carving.treat_candidate_cap_as_page_end();
    }
    carving.candidates = carving.candidates.into_iter().skip(offset).take(limit).collect();
    Ok(CarvingPage { carving, offset, more })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_scan_one_candidate_past_their_end() {
        let xz = [0xfd, b'7', b'z', b'X', b'Z', 0, 0, 4, 0xe6, 0xd6, 0xb4, 0x46];
        let path = std::env::temp_dir().join(format!("rampage-carve-page-{}", std::process::id()));
        std::fs::write(&path, xz.repeat(10)).unwrap();
        let page = carve_page(&path, Some(2), Some(3));
        let last = carve_page(&path, Some(8), Some(5));
        let past = carve_page(&path, Some(20), None);
        std::fs::remove_file(&path).unwrap();

        let page = page.unwrap();
        let offsets: Vec<u64> = page.carving.candidates.iter().map(|candidate| candidate.offset).collect();
        assert_eq!((offsets, page.offset, page.more), (vec![24, 36, 48], 2, true));
        assert!(!page.carving.truncated, "{:?}", page.carving.limitations);
        assert!(!page.carving.limitations.iter().any(|text| text.contains("candidate cap")));
        let last = last.unwrap();
        assert_eq!((last.carving.candidates.len(), last.more, last.carving.truncated), (2, false, false));
        let past = past.unwrap();
        assert_eq!((past.carving.candidates.len(), past.more), (0, false));
    }
}
