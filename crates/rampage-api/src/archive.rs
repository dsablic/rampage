use std::path::{Path, PathBuf};

use rampage_loaders::container::archive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ApiError;

pub use archive::{ArchiveMember, ArchiveMemberRef, ArchiveRef};

pub const MAX_ARCHIVE_PAGE: usize = 100;
pub const MAX_ARCHIVE_RESULT_BYTES: usize = 60_000;

#[derive(Debug, Default, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveQuery {
    /// Matching central-directory records to skip, not a byte offset or native-image offset.
    pub offset: Option<usize>,
    /// Records per page, 1 through 100; the JSON byte budget may return fewer records.
    #[schemars(range(min = 1, max = 100))]
    pub limit: Option<usize>,
    /// Case-sensitive raw-name substring in UTF-8 bytes, tested before truncation (at most 1024 bytes).
    pub contains: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ArchivePage {
    pub file_path: PathBuf,
    pub archive_ref: ArchiveRef,
    pub declared: usize,
    pub examined: usize,
    /// Structurally checked directory records, not validated members, local headers or payloads.
    pub validated: usize,
    pub retained: usize,
    pub matched: usize,
    pub returned: usize,
    /// Combined retained raw-hex and UTF-8 display bytes, before JSON escaping, across the whole inventory.
    pub retained_name_bytes: usize,
    pub names_truncated: usize,
    pub central_directory_complete: bool,
    pub payload_validated: bool,
    pub observation: &'static str,
    /// Inventory truncation only; successful inventories are complete. Names and pages have separate caps.
    pub truncated: bool,
    pub offset: usize,
    pub limit: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub byte_capped: bool,
    pub metadata_read_bytes: usize,
    pub eocd_candidates_examined: usize,
    pub extra_fields_examined: usize,
    pub name_filter_steps: usize,
    pub members: Vec<ArchiveMember>,
    pub warnings: Vec<String>,
    pub warnings_total: usize,
    pub warnings_truncated: bool,
    pub limitations: Vec<&'static str>,
}

/// Metadata-only inventory without a Project, binary load, discovery, sidecar, or member opening.
/// Successful receipts validate the whole bounded central directory, not any payload or local header.
pub fn archive_inventory(path: &Path, query: &ArchiveQuery) -> Result<ArchivePage, ApiError> {
    let limit = query.limit.unwrap_or(MAX_ARCHIVE_PAGE);
    if !(1..=MAX_ARCHIVE_PAGE).contains(&limit) {
        return Err(ApiError::Invalid("archive limit must be in 1..=100".to_owned()));
    }
    if query.contains.as_ref().is_some_and(|needle| needle.len() > archive::MAX_NAME_BYTES) {
        return Err(ApiError::Invalid("archive contains exceeds 1024 UTF-8 bytes".to_owned()));
    }
    let path_json = serde_json::to_vec(path)
        .map_err(|error| ApiError::Invalid(format!("archive path is not JSON-serializable: {error}")))?;
    if path_json.len() > MAX_ARCHIVE_RESULT_BYTES / 2 {
        return Err(ApiError::Invalid("archive path exceeds the JSON receipt budget".to_owned()));
    }
    let inventory = archive::inventory(path, query.contains.as_deref())
        .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
    let offset = query.offset.unwrap_or(0);
    let mut page = ArchivePage {
        file_path: path.to_owned(),
        archive_ref: inventory.archive_ref,
        declared: inventory.declared,
        examined: inventory.examined,
        validated: inventory.validated,
        retained: inventory.retained,
        matched: inventory.matched,
        returned: 0,
        retained_name_bytes: inventory.retained_name_bytes,
        names_truncated: inventory.names_truncated,
        central_directory_complete: inventory.central_directory_complete,
        payload_validated: false,
        observation: "revalidated_non_atomic_metadata",
        truncated: inventory.truncated,
        offset,
        limit,
        more: false,
        next_offset: None,
        byte_capped: false,
        metadata_read_bytes: inventory.metadata_read_bytes,
        eocd_candidates_examined: inventory.eocd_candidates_examined,
        extra_fields_examined: inventory.extra_fields_examined,
        name_filter_steps: inventory.name_filter_steps,
        members: Vec::new(),
        warnings: inventory.warnings,
        warnings_total: inventory.warnings_total,
        warnings_truncated: inventory.warnings_truncated,
        limitations: vec![
            "Standalone single-disk ZIP32 only; no SFX offset inference, ZIP64, multi-disk or directory gaps.",
            "Bounded prefix, tail and central-directory metadata reads; tail reads may overlap member data.",
            concat!(
                "No member/local-header offset is followed; ",
                "no decompression, extraction, CRC verification or format probing."
            ),
            "Sizes, flags, CRC32 and local-header offsets are unverified payload declarations.",
            concat!(
                "Names are raw metadata, not filesystem paths or extraction-safe names; ",
                "duplicates retain ordinal identity."
            ),
            "Metadata SHA-256 is not a whole-archive hash or authenticity proof; revalidation is not atomicity.",
            "Budget exhaustion rejects the operation, never certifies absent members in a partial directory.",
        ],
    };
    // Reserve room for the largest numeric paging fields before selecting byte-bounded whole records.
    page.more = true;
    page.next_offset = Some(usize::MAX);
    page.returned = MAX_ARCHIVE_PAGE;
    let base = json_size(&page)?;
    let mut used = base;
    for member in inventory.members.into_iter().filter(|member| member.matches_filter).skip(offset).take(limit) {
        let bytes = json_size(&member)? + usize::from(!page.members.is_empty());
        if used.checked_add(bytes).is_none_or(|size| size > MAX_ARCHIVE_RESULT_BYTES) {
            page.byte_capped = true;
            break;
        }
        used += bytes;
        page.members.push(member);
    }
    page.returned = page.members.len();
    let consumed = offset.saturating_add(page.returned);
    page.more = consumed < page.matched;
    page.next_offset = page.more.then_some(consumed);
    if page.more && page.returned == 0 {
        return Err(ApiError::Invalid("archive receipt cannot fit one bounded member record".to_owned()));
    }
    if json_size(&page)? > MAX_ARCHIVE_RESULT_BYTES {
        return Err(ApiError::Invalid("archive result exceeds JSON byte budget".to_owned()));
    }
    Ok(page)
}

fn json_size(value: &impl Serialize) -> Result<usize, ApiError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| ApiError::Invalid(format!("archive result is not JSON-serializable: {error}")))
}
