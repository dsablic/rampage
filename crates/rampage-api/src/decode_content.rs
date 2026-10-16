use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rampage_decode::{DecodeOptions, Decoder, Lzss4k};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ApiError;

pub const MAX_DECODE_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DECODE_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DECODE_PREVIEW_BYTES: usize = 1024;
pub const MAX_DECODE_RECEIPT_BYTES: usize = 16_384;
pub const MAX_DECODE_EXPANSION_RATIO: usize = 128;
const MAX_DECODE_STEPS: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, serde::Deserialize, Serialize, schemars::JsonSchema)]
pub enum ContentCodec {
    #[serde(rename = "lzss-4k")]
    Lzss4k,
}

impl std::str::FromStr for ContentCodec {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lzss-4k" => Ok(Self::Lzss4k),
            _ => Err("unsupported decoder; select lzss-4k explicitly".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodeFileRequest {
    pub codec: ContentCodec,
    pub offset: u64,
    pub length: usize,
    pub expected_output_size: usize,
    pub initial_write_offset: u16,
    pub dictionary_fill: u8,
    pub timeout_ms: u64,
    pub preview_offset: usize,
    pub preview_size: usize,
}

#[derive(Debug)]
pub struct DecodedContent {
    pub receipt: DecodeReceipt,
    bytes: Vec<u8>,
}

impl DecodedContent {
    /// Transient bytes for explicit downstream analysis; no loader or execution is invoked automatically.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Serialize)]
pub struct DecodeReceipt {
    pub file_path: PathBuf,
    pub source_size: u64,
    pub source_offset: u64,
    pub source_length: usize,
    pub source_range_sha256: String,
    pub source_byte_sum32: u32,
    pub source_observation: &'static str,
    pub codec: &'static str,
    pub dictionary_size: usize,
    pub initial_write_offset: u16,
    pub dictionary_fill: u8,
    pub expected_output_size: usize,
    pub output_size: usize,
    pub output_sha256: String,
    pub input_consumed: usize,
    pub trailing_input_bytes: usize,
    pub input_fully_consumed: bool,
    pub completion: &'static str,
    pub steps: u64,
    pub max_output_bytes: usize,
    pub max_expansion_ratio: usize,
    pub max_steps: u64,
    pub decode_timeout_ms: u64,
    pub preview: DecodePreview,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct DecodePreview {
    pub coordinate_space: &'static str,
    pub offset: usize,
    pub size: usize,
    pub hex: String,
    pub ascii: String,
    pub next_offset: Option<usize>,
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn validate(request: &DecodeFileRequest) -> Result<(), ApiError> {
    if !(1..=MAX_DECODE_INPUT_BYTES).contains(&request.length) {
        return Err(invalid("decode length must be 1..=8388608 bytes"));
    }
    if !(1..=MAX_DECODE_OUTPUT_BYTES).contains(&request.expected_output_size) {
        return Err(invalid("decode expected_output_size must be 1..=16777216 bytes"));
    }
    if request.expected_output_size > request.length.saturating_mul(MAX_DECODE_EXPANSION_RATIO) {
        return Err(invalid("decode expected output exceeds the 128:1 expansion budget"));
    }
    if request.initial_write_offset >= 4096 {
        return Err(invalid("LZSS initial_write_offset must be 0..4095"));
    }
    if !(1..=10_000).contains(&request.timeout_ms) {
        return Err(invalid("decode timeout_ms must be 1..=10000"));
    }
    if request.preview_size > MAX_DECODE_PREVIEW_BYTES || request.preview_offset > request.expected_output_size {
        return Err(invalid("decoded preview exceeds its offset or 1024-byte size limit"));
    }
    request.offset.checked_add(request.length as u64).ok_or_else(|| invalid("decode source range overflows"))?;
    Ok(())
}

/// Explicit bounded file-range decoding. The returned content is memory-owned and is never published to disk.
pub fn decode_file_range(path: &Path, request: &DecodeFileRequest) -> Result<DecodedContent, ApiError> {
    validate(request)?;
    if serde_json::to_vec(path).map_err(|_| invalid("decode source path is not JSON-serializable"))?.len() > 4096 {
        return Err(invalid("decode source path exceeds the receipt budget"));
    }
    let source = source::RangeSource::open(path, request.offset, request.length)?;
    let input = source.read(request.offset, request.length)?;
    source.revalidate()?;
    let started = Instant::now();
    let timeout = Duration::from_millis(request.timeout_ms);
    let decoder = match request.codec {
        ContentCodec::Lzss4k => {
            Lzss4k { initial_write_offset: request.initial_write_offset, dictionary_fill: request.dictionary_fill }
        }
    };
    let options = DecodeOptions {
        expected_output_size: request.expected_output_size,
        max_output_size: MAX_DECODE_OUTPUT_BYTES,
        max_expansion_ratio: MAX_DECODE_EXPANSION_RATIO,
        max_steps: MAX_DECODE_STEPS,
    };
    let decoded = decoder
        .decode(&input, &options, &mut || started.elapsed() >= timeout)
        .map_err(|error| ApiError::Invalid(format!("{} decode refused: {error}", decoder.id())))?;
    if started.elapsed() >= timeout {
        return Err(invalid("decode deadline exceeded"));
    }
    if decoded.bytes.len() != request.expected_output_size
        || decoded.consumed > input.len()
        || decoded.steps > MAX_DECODE_STEPS
    {
        return Err(invalid("decoder returned an inconsistent completion"));
    }
    source.revalidate()?;
    let end = request.preview_offset.saturating_add(request.preview_size).min(decoded.bytes.len());
    let preview = &decoded.bytes[request.preview_offset..end];
    let receipt = DecodeReceipt {
        file_path: path.to_owned(),
        source_size: source.size(),
        source_offset: request.offset,
        source_length: request.length,
        source_range_sha256: rampage_arch::hex::bytes(&Sha256::digest(&input)),
        source_byte_sum32: input.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))),
        source_observation: "revalidated_non_atomic_file_range",
        codec: decoder.id(),
        dictionary_size: 4096,
        initial_write_offset: request.initial_write_offset,
        dictionary_fill: request.dictionary_fill,
        expected_output_size: request.expected_output_size,
        output_size: decoded.bytes.len(),
        output_sha256: rampage_arch::hex::bytes(&Sha256::digest(&decoded.bytes)),
        input_consumed: decoded.consumed,
        trailing_input_bytes: input.len() - decoded.consumed,
        input_fully_consumed: decoded.consumed == input.len(),
        completion: "expected_output_size_reached",
        steps: decoded.steps,
        max_output_bytes: MAX_DECODE_OUTPUT_BYTES,
        max_expansion_ratio: MAX_DECODE_EXPANSION_RATIO,
        max_steps: MAX_DECODE_STEPS,
        decode_timeout_ms: request.timeout_ms,
        preview: DecodePreview {
            coordinate_space: "decoded_byte_offset",
            offset: request.preview_offset,
            size: preview.len(),
            hex: rampage_arch::hex::bytes(preview),
            ascii: preview
                .iter()
                .map(|&byte| if (0x20..=0x7e).contains(&byte) { char::from(byte) } else { '.' })
                .collect(),
            next_offset: (!preview.is_empty() && end < decoded.bytes.len()).then_some(end),
        },
        limitations: vec![
            "Explicit lzss-4k variant: 4096-byte ring, LSB-first flags, 1=literal, 12-bit offset and length nibble+3.",
            "This codec has no end marker: expected output size is an analyst assertion, \
             not a discovered stream boundary.",
            "Hashes and the additive byte sum describe observed ranges, \
             not authenticity or validated container fields.",
            "Trailing input is reported, never silently certified as consumed. \
             A backreference cannot be cut to fit output.",
            "Expansion budgeting uses the entire selected input range, including any trailing bytes.",
            "Decoded offsets are not source-file offsets or load addresses. \
             No executable format or architecture is inferred.",
            "Bytes are transient. No extraction, file publication, recursion, native loading, \
             annotations or execution.",
            "Decode deadline is cooperative; regular-file reads and hash computation are not forcibly interrupted.",
            "Descriptor/path metadata is revalidated; source reads are not atomic with concurrent file modification.",
        ],
    };
    if serde_json::to_vec(&receipt).map_err(|_| invalid("decode receipt serialization failed"))?.len()
        > MAX_DECODE_RECEIPT_BYTES
    {
        return Err(invalid("decode receipt exceeds the JSON byte budget"));
    }
    Ok(DecodedContent { receipt, bytes: decoded.bytes })
}

#[cfg(unix)]
mod source {
    use std::fs::{File, Metadata};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};

    use rustix::fs::{Mode, OFlags};

    use super::{ApiError, invalid};

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp(u64, u64, u64, i64, i64, i64, i64);

    fn stamp(metadata: &Metadata) -> Result<Stamp, ApiError> {
        if !metadata.is_file() {
            return Err(invalid("decode input must be a regular file"));
        }
        Ok(Stamp(
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ))
    }

    pub(super) struct RangeSource {
        file: File,
        path: PathBuf,
        stamp: Stamp,
    }

    impl RangeSource {
        pub(super) fn open(path: &Path, offset: u64, length: usize) -> Result<Self, ApiError> {
            let descriptor = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| ApiError::Unavailable(format!("decode source open: {error}")))?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(io_error)?;
            let stamp = stamp(&metadata)?;
            if offset.checked_add(length as u64).is_none_or(|end| end > metadata.len()) {
                return Err(invalid("decode source range is outside the regular file"));
            }
            let source = Self { file, path: path.to_owned(), stamp };
            source.revalidate()?;
            Ok(source)
        }

        pub(super) fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, ApiError> {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|_| invalid("decode input allocation failed"))?;
            bytes.resize(length, 0);
            self.file.read_exact_at(&mut bytes, offset).map_err(io_error)?;
            Ok(bytes)
        }

        pub(super) fn revalidate(&self) -> Result<(), ApiError> {
            let descriptor = stamp(&self.file.metadata().map_err(io_error)?)?;
            let pathname = stamp(&std::fs::symlink_metadata(&self.path).map_err(io_error)?)?;
            if descriptor != self.stamp || pathname != self.stamp {
                return Err(invalid("decode source changed or was replaced during observation"));
            }
            Ok(())
        }

        pub(super) fn size(&self) -> u64 {
            self.stamp.2
        }
    }

    fn io_error(error: std::io::Error) -> ApiError {
        ApiError::Unavailable(format!("decode source I/O: {error}"))
    }
}

#[cfg(all(test, unix))]
#[path = "decode_content_tests.rs"]
mod tests;

#[cfg(not(unix))]
mod source {
    use super::*;
    pub(super) struct RangeSource;
    impl RangeSource {
        pub(super) fn open(_: &Path, _: u64, _: usize) -> Result<Self, ApiError> {
            Err(ApiError::Unavailable("decode file ranges require Unix regular-file source checks".into()))
        }
        pub(super) fn read(&self, _: u64, _: usize) -> Result<Vec<u8>, ApiError> {
            unreachable!()
        }
        pub(super) fn revalidate(&self) -> Result<(), ApiError> {
            unreachable!()
        }
        pub(super) fn size(&self) -> u64 {
            unreachable!()
        }
    }
}
