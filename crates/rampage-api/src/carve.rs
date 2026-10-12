//! Carving: finding embedded executables and containers inside any file, without opening it as a project.

use std::path::Path;

use rampage_loaders::carve::{Carving, Limits, MAX_CANDIDATES};
use serde::Serialize;

use crate::ApiError;

/// The most candidates one page returns, so that a page fits one tool result.
pub const MAX_CARVE_PAGE: usize = 100;

/// A page of a carving: every limitation and total, but only `limit` candidates from `offset`.
#[derive(Debug, Serialize)]
pub struct CarvingPage {
    #[serde(flatten)]
    pub carving: Carving,
    pub candidates_total: usize,
    pub offset: usize,
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

/// [`carve`], keeping `limit` candidates (default and at most [`MAX_CARVE_PAGE`]) from `offset`.
pub fn carve_page(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<CarvingPage, ApiError> {
    let mut carving = carve(path, None)?;
    let candidates_total = carving.candidates.len();
    let offset = offset.unwrap_or(0).min(candidates_total);
    let limit = limit.unwrap_or(MAX_CARVE_PAGE).min(MAX_CARVE_PAGE);
    carving.candidates = carving.candidates.into_iter().skip(offset).take(limit).collect();
    Ok(CarvingPage { carving, candidates_total, offset })
}
