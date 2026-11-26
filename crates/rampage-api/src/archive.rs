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

/// The most index symbols listed per member row; `symbols_total` counts them all.
pub const MAX_MEMBER_SYMBOLS: usize = 16;

/// One member of a static (`ar`) archive, with what its symbol index says it defines.
#[derive(Debug, Serialize)]
pub struct StaticMemberRow {
    #[serde(flatten)]
    pub member: rampage_loaders::ar::Member,
    /// The path that opens this member in any binary tool: `archive(member)`.
    pub open: String,
    /// The member's format, kind and architecture (`elf relocatable x86_64`), or `not an object file`.
    pub format: String,
    /// Symbols the archive's index says the member defines (those matching `contains` first), at most 16.
    pub symbols: Vec<String>,
    pub symbols_total: usize,
}

/// A page of a static archive's members.
#[derive(Debug, Serialize)]
pub struct StaticArchivePage {
    pub file_path: PathBuf,
    /// Always `ar`.
    pub format: &'static str,
    /// `gnu`, `gnu64`, `bsd`, `bsd64`, `coff` or `unknown` (no symbol index or long names to tell).
    pub kind: &'static str,
    pub members_total: usize,
    /// Entries in the archive's symbol index.
    pub index_symbols: usize,
    /// Members whose name, or a symbol the index gives them, contains `contains` (every member without it).
    pub matched: usize,
    pub returned: usize,
    pub offset: usize,
    pub limit: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub members: Vec<StaticMemberRow>,
    pub next: &'static str,
}

/// Whether the file at `path` is a static (`ar`) archive.
pub fn is_static_archive(path: &Path) -> bool {
    let mut magic = [0u8; 8];
    std::fs::File::open(path).and_then(|mut file| std::io::Read::read_exact(&mut file, &mut magic)).is_ok()
        && rampage_loaders::ar::is_archive(&magic)
}

/// A static archive's members, paged, each with the path that opens it and the symbols its index lists.
pub fn static_archive_inventory(path: &Path, query: &ArchiveQuery) -> Result<StaticArchivePage, ApiError> {
    let limit = query.limit.unwrap_or(MAX_ARCHIVE_PAGE);
    if !(1..=MAX_ARCHIVE_PAGE).contains(&limit) {
        return Err(ApiError::Invalid("archive limit must be in 1..=100".to_owned()));
    }
    let load = |source| ApiError::Load { path: path.to_owned(), source };
    let data = rampage_loaders::ar::map(path).map_err(load)?;
    let archive = rampage_loaders::ar::read(&data).map_err(load)?;
    let mut defined: Vec<Vec<&str>> = vec![Vec::new(); archive.members.len()];
    for (name, member) in &archive.symbols {
        defined[*member].push(name);
    }
    let needle = query.contains.as_deref();
    let matching = |member: &rampage_loaders::ar::Member| match needle {
        None => true,
        Some(needle) => {
            member.name.contains(needle) || defined[member.index].iter().any(|symbol| symbol.contains(needle))
        }
    };
    let matched: Vec<&rampage_loaders::ar::Member> = archive.members.iter().filter(|member| matching(member)).collect();
    let offset = query.offset.unwrap_or(0);
    let display = path.to_string_lossy();
    let mut page = StaticArchivePage {
        file_path: path.to_owned(),
        format: "ar",
        kind: archive.kind,
        members_total: archive.members.len(),
        index_symbols: archive.symbols.len(),
        matched: matched.len(),
        returned: 0,
        offset,
        limit,
        more: true,
        next_offset: Some(usize::MAX),
        members: Vec::new(),
        next: "Pass a row's `open` as the path of any binary tool (binary_info, list_functions, decompile, ...) to \
               analyze that member; `name#N` picks member N where names repeat.",
    };
    let mut used = json_size(&page)?;
    for member in matched.iter().skip(offset).take(limit) {
        let start = usize::try_from(member.offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(member.size).unwrap_or(usize::MAX));
        let format = data.get(start..end).map_or_else(|| "truncated".to_owned(), rampage_loaders::ar::member_format);
        let mut symbols = defined[member.index].clone();
        if let Some(needle) = needle {
            symbols.sort_by_key(|symbol| !symbol.contains(needle));
        }
        let row = StaticMemberRow {
            open: format!("{display}({})", member.selector()),
            format,
            symbols_total: symbols.len(),
            symbols: symbols.into_iter().take(MAX_MEMBER_SYMBOLS).map(str::to_owned).collect(),
            member: (*member).clone(),
        };
        let bytes = json_size(&row)? + 1;
        if used + bytes > MAX_ARCHIVE_RESULT_BYTES {
            break;
        }
        used += bytes;
        page.members.push(row);
    }
    page.returned = page.members.len();
    let consumed = offset.saturating_add(page.returned);
    page.more = consumed < page.matched;
    page.next_offset = page.more.then_some(consumed);
    if page.more && page.returned == 0 {
        return Err(ApiError::Invalid("archive receipt cannot fit one member record".to_owned()));
    }
    Ok(page)
}
