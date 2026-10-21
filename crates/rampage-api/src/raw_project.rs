//! Ordinary Raw Projects opened from an explicit regular-file range with an asserted closed profile and mapping.
//! The request is an analyst assertion, not header admission; bytes are read once through the checked range source.

use std::path::Path;

use rampage_loaders::{Binary, MAX_RAW_BYTES, MAX_RAW_SEEDS, RawCodeOptions, RawProfile};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// One Raw interpretation of a file range: closed profile, source range, code-space mapping, entry and seeds.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawProjectRequest {
    /// Closed Raw language ID, not a path, architecture alias, compiler or ABI selection.
    #[schemars(schema_with = "profile_schema")]
    pub profile: String,
    /// Original-file BYTE offset of the first code byte.
    pub offset: FileOffset,
    /// Exact source byte count, 1..=131072.
    pub length: FileOffset,
    /// Internal code-space BYTE address of the first selected byte, including word-addressed processors.
    pub base_address: FileOffset,
    /// Optional internal code-space BYTE address of the asserted entry; aligned and inside the mapped range.
    #[serde(default)]
    pub entry: Option<FileOffset>,
    /// At most 8192 explicit internal code-space BYTE addresses of function starts inside the mapped range.
    #[serde(default)]
    #[schemars(length(max = 8192))]
    pub seeds: Vec<FileOffset>,
}

fn profile_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let ids: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    schemars::json_schema!({
        "type": "string",
        "description": "Closed Raw language ID, not a path, architecture alias, compiler or ABI selection.",
        "enum": ids,
    })
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

impl RawProjectRequest {
    fn options(&self) -> Result<(usize, RawCodeOptions), ApiError> {
        let profile = RawProfile::from_language_id(&self.profile)
            .map_err(|_| invalid("unsupported Raw profile; select one of the closed Raw language IDs"))?;
        let length = usize::try_from(self.length.0)
            .ok()
            .filter(|length| (1..=MAX_RAW_BYTES).contains(length))
            .ok_or_else(|| invalid("Raw length must be 1..=131072 bytes"))?;
        if self.seeds.len() > MAX_RAW_SEEDS {
            return Err(invalid("Raw accepts at most 8192 seeds"));
        }
        self.offset.0.checked_add(length as u64).ok_or_else(|| invalid("Raw source range overflows"))?;
        let options = RawCodeOptions {
            profile,
            base: self.base_address.0,
            entry: self.entry.map(|entry| entry.0),
            seeds: self.seeds.iter().map(|seed| seed.0).collect(),
        };
        Ok((length, options))
    }
}

/// Reads exactly the requested range of a regular, non-symlinked file (revalidated after the read) and admits it
/// as a Raw [`Binary`]. No native header admission, sidecar or annotation log is involved.
pub fn open_raw_binary(path: &Path, request: &RawProjectRequest) -> Result<Binary, ApiError> {
    let (length, options) = request.options()?;
    let source = RangeSource::open(path, request.offset.0, length)?;
    let bytes = source.read()?;
    source.revalidate()?;
    Binary::from_raw_code(bytes, options).map_err(|source| ApiError::Load { path: path.to_owned(), source })
}
