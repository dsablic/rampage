use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset, RawCodeMode, RawCodeReport, RawCodeRequest, inspect_raw_code};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RawByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawFileRequest {
    /// Original-file byte offset, not a native-image or decoded address.
    pub offset: FileOffset,
    /// Window length, 1..4096 bytes. No decoder reads outside this supplied range.
    pub length: FileOffset,
    /// Required architecture: x86, x86_64, arm or aarch64. No format/architecture guessing.
    pub arch: String,
    /// ARM requires arm or thumb; other architectures require native.
    pub mode: RawCodeMode,
    /// Explicit instruction order; initially only little is supported.
    pub code_byte_order: RawByteOrder,
    /// Explicit data order; initially only little is supported.
    pub data_byte_order: RawByteOrder,
    /// Analyst-asserted VA of the first selected byte, not of the whole file.
    pub base_address: FileOffset,
    /// Linear instruction count, 1..256; default 64. No targets are followed.
    #[serde(default = "default_count")]
    pub instruction_limit: usize,
}

fn default_count() -> usize {
    64
}

#[derive(Debug, Serialize)]
pub struct RawFileReport {
    pub file_path: PathBuf,
    pub source_size: u64,
    pub source_offset: u64,
    pub source_length: usize,
    pub source_range_sha256: String,
    pub source_observation: &'static str,
    pub source_coordinate_space: &'static str,
    pub mapping: RawCodeReport,
    pub undecoded_prefix_hex: String,
    pub continuation: Option<RawContinuation>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct RawContinuation {
    pub tool: &'static str,
    pub source_offset: u64,
    pub length: usize,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    pub note: &'static str,
}

/// Inspect one explicit original-file code window without a native loader, Project, annotations or extraction.
pub fn inspect_raw_file(path: &Path, request: &RawFileRequest) -> Result<RawFileReport, ApiError> {
    let length = usize::try_from(request.length.0).map_err(|_| invalid("raw window exceeds host width"))?;
    let mapping = RawCodeRequest {
        arch: request.arch.parse().map_err(ApiError::Invalid)?,
        mode: request.mode,
        code_big_endian: matches!(request.code_byte_order, RawByteOrder::Big),
        data_big_endian: matches!(request.data_byte_order, RawByteOrder::Big),
        base_address: request.base_address.0,
        instruction_limit: request.instruction_limit,
    };
    crate::raw_code::validate_raw_window_size(length, &mapping)?;
    request.offset.0.checked_add(length as u64).ok_or_else(|| invalid("raw source range overflows"))?;
    if serde_json::to_vec(path).map_err(|_| invalid("raw source path is not JSON-serializable"))?.len() > 4096 {
        return Err(invalid("raw source path exceeds receipt budget"));
    }
    let source = RangeSource::open(path, request.offset.0, length)?;
    let bytes = source.read()?;
    source.revalidate()?;
    let report = inspect_raw_code(&bytes, &mapping)?;
    let consumed = report.consumed_bytes;
    let continuation =
        (consumed > 0 && consumed < bytes.len() && report.stop_reason == crate::RawCodeStopReason::InstructionLimit)
            .then_some(RawContinuation {
                tool: "inspect_raw_code",
                source_offset: request.offset.0 + consumed as u64,
                length: bytes.len() - consumed,
                base_address: mapping.base_address + consumed as u64,
                note: "Repeat with these range/base values and the same architecture/mode/orders; \
                   prior facts are not retained.",
            });
    source.revalidate()?;
    let result = RawFileReport {
        file_path: path.to_owned(),
        source_size: source.size(),
        source_offset: request.offset.0,
        source_length: bytes.len(),
        source_range_sha256: rampage_arch::hex::bytes(&Sha256::digest(&bytes)),
        source_observation: "revalidated_non_atomic_file_range",
        source_coordinate_space: "original_file_byte_offset",
        mapping: report,
        undecoded_prefix_hex: rampage_arch::hex::bytes(&bytes[consumed..(consumed + 16).min(bytes.len())]),
        continuation,
        limitations: vec![
            "Source offset plus each window offset locates original bytes; VAs derive only from the supplied base.",
            "The range hash binds selected bytes, not a whole-file identity or authenticity proof. \
             Reads are not atomic.",
            "No executable headers, architecture detection, function boundaries, annotations, sidecars or execution.",
            "Only the selected range was inspected. Use inspect_raw_code for another explicit window; facts may reset.",
        ],
    };
    if serde_json::to_vec(&result).map_err(|_| invalid("raw report serialization failed"))?.len() > 60_000 {
        return Err(invalid("raw file report exceeds JSON budget; reduce length or instruction_limit"));
    }
    Ok(result)
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

#[cfg(test)]
#[path = "raw_file_tests.rs"]
mod tests;
