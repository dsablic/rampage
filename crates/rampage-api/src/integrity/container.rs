//! Compressed streams inside a Raw project mapped from a container file: a record before each stream names its
//! compressed length, decoded size and a byte sum or CRC-32 of the compressed bytes. The sum becomes an ordinary
//! check over the stream at mapped addresses, and the stream's decoded image is offered as a ready `raw` selector.

use std::path::Path;

use rampage_loaders::{Binary, RawRegionSource};
use serde::Serialize;
use serde_json::Value;

use super::{Algorithm, Endian, Found};
use crate::container_record::{ContainerRecord, RECORD_WINDOW};

/// Streams reported per project; each costs one byte sum and CRC-32 per candidate length, and one decode.
const MAX_STREAMS: usize = 4;
/// Decoded sizes larger than this are not decoded sizes.
const MAX_DECODED_SIZE: u64 = 16 << 20;
/// Length and size pairs decoded when no record word verifies the compressed bytes.
const MAX_UNVERIFIED_PAIRS: usize = 8;

/// A compressed stream a container record describes, and its decoded image.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerStream {
    /// File offsets of the stream and of its record's first field with an inferred role.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub stream_offset: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub record_offset: u64,
    pub compressed_length: u64,
    pub decoded_size: u64,
    /// The check in `checks` that is the record's checksum field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<usize>,
    /// Whether a record word is the byte sum or CRC-32 of the compressed bytes (then it is `check`).
    pub checksum: String,
    /// `reproduced` when the classic LZSS (4 KiB ring) or LZ4 block decoder turns exactly the compressed length
    /// into exactly the decoded size; otherwise why not, and `probe_compression` finds the codec.
    pub decode_check: String,
    /// The `raw` selector for the decoded image: this project's profile, the decode arguments and the best load
    /// address (the record's base hint when the decoded bytes' base candidates agree).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_as_raw: Option<Value>,
    pub record: ContainerRecord,
}

pub(super) struct Stream {
    pub(super) report: ContainerStream,
    pub(super) found: Option<Found>,
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes")))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// Streams in the file-range regions of a Raw `binary` read from `path`. A record lies within 64 bytes before its
/// stream and holds the compressed length and the decoded size. The stream is found either from a word that is the
/// byte sum of the bytes after it for one of the record's lengths (found with prefix sums over the region), or from
/// a payload-offset word holding the stream's own file offset; in the latter case a byte sum or CRC-32 that does
/// not match is reported as not verifying, when a fixed-parameter codec decodes the stream exactly.
pub(super) fn streams(binary: &Binary, path: Option<&Path>) -> Vec<Stream> {
    let Some(raw) = binary.raw_code_image() else { return Vec::new() };
    let mut streams: Vec<Stream> = Vec::new();
    for region in raw.regions() {
        let Some(RawRegionSource::FileRange { offset: file_offset, .. }) = &region.source else { continue };
        let Some(bytes) = binary.image_bytes().get(region.data_range()) else { continue };
        let file_offset = *file_offset;
        let file_end = file_offset + bytes.len() as u64;
        let first = ((4 - file_offset % 4) % 4) as usize;
        // prefix[i]: the byte sum of bytes[..i], modulo 2^32.
        let mut prefix = Vec::with_capacity(bytes.len() + 1);
        prefix.push(0u32);
        for &byte in bytes {
            let last = *prefix.last().expect("seeded");
            prefix.push(u32::wrapping_add(last, u32::from(byte)));
        }
        let window_words = |stream: u64| -> (u64, Vec<u64>) {
            let start = stream.saturating_sub(RECORD_WINDOW as u64).max(file_offset);
            let words = ((start - file_offset) as usize..(stream - file_offset) as usize)
                .filter(|&at| (file_offset + at as u64).is_multiple_of(4) && at + 4 <= (stream - file_offset) as usize)
                .map(|at| word(bytes, at))
                .collect();
            (start, words)
        };
        let mut candidates: Vec<u64> = Vec::new();
        for at in (first..bytes.len().saturating_sub(3)).step_by(4) {
            let position = file_offset + at as u64;
            let value = word(bytes, at);
            // A payload-offset word: the stream's own file offset, just after the word.
            if value > position && value - position <= RECORD_WINDOW as u64 && value < file_end {
                candidates.push(value);
            }
            // A compressed-length word whose stream starts within 64 bytes after it and is summed by a word before.
            if value < 16 || value > bytes.len() as u64 {
                continue;
            }
            for stream in (position + 4..=position + RECORD_WINDOW as u64).step_by(4) {
                if stream + value > file_end {
                    break;
                }
                let (from, to) = ((stream - file_offset) as usize, (stream - file_offset + value) as usize);
                let sum = u64::from(prefix[to].wrapping_sub(prefix[from]));
                if window_words(stream).1.contains(&sum) {
                    candidates.push(stream);
                }
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        for stream in candidates {
            if streams.len() == MAX_STREAMS {
                return streams;
            }
            if streams.iter().any(|known| known.report.stream_offset == stream) {
                continue;
            }
            let stream_at = (stream - file_offset) as usize;
            let (window_start, words) = window_words(stream);
            let window = &bytes[(window_start - file_offset) as usize..stream_at];
            let lengths: Vec<u64> =
                words.iter().copied().filter(|&length| length >= 16 && stream + length <= file_end).collect();
            let pairs = || {
                lengths.iter().flat_map(|&length| {
                    words
                        .iter()
                        .filter(move |&&size| size > length && size <= MAX_DECODED_SIZE)
                        .map(move |&size| (length, size))
                })
            };
            let record_for = |length: u64, size: u64| {
                let input = &bytes[stream_at..stream_at + length as usize];
                crate::container_record::find(window_start, window, stream, input, length as usize, size as usize)
            };
            let matched = pairs().find_map(|(length, size)| {
                let input = &bytes[stream_at..stream_at + length as usize];
                let sum = u64::from(input.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))));
                if !words.contains(&sum) && !words.contains(&u64::from(crc32(input))) {
                    return None;
                }
                let record = record_for(length, size)?;
                record.checksum_over.is_some().then_some((length, size, record))
            });
            let (length, size, record, decoded) = match matched {
                Some((length, size, record)) => {
                    let decoded = decoded_selector(path, stream, length, size, &record, raw);
                    (length, size, record, decoded)
                }
                None => {
                    let reproduced = pairs().take(MAX_UNVERIFIED_PAIRS).find_map(|(length, size)| {
                        let record = record_for(length, size)?;
                        let decoded = decoded_selector(path, stream, length, size, &record, raw);
                        (decoded.0 == "reproduced").then_some((length, size, record, decoded))
                    });
                    let Some(found) = reproduced else { continue };
                    found
                }
            };
            streams.push(stream_report(region, file_offset, stream, length, size, record, decoded));
        }
    }
    streams
}

fn stream_report(
    region: &rampage_loaders::RawRegionInfo,
    file_offset: u64,
    stream: u64,
    length: u64,
    size: u64,
    record: ContainerRecord,
    (decode_check, open_as_raw): (String, Option<Value>),
) -> Stream {
    let field = record.fields.iter().find(|field| matches!(field.role, "byte_sum32" | "crc32"));
    let record_offset = record
        .fields
        .iter()
        .find(|field| field.role != "unknown")
        .map_or(stream.saturating_sub(RECORD_WINDOW as u64), |first| first.offset);
    let memory = |file: u64| region.base_address + (file - file_offset);
    let found = field.map(|field| {
        let algorithm = if field.role == "crc32" { Algorithm::Crc32 } else { Algorithm::Sum32 };
        Found {
            algorithm: Some(algorithm),
            field: memory(field.offset),
            endian: Endian::Little,
            range: (memory(stream), memory(stream + length)),
            score: 0.9,
            emulated: false,
            routine: None,
            code_bound: false,
            evidence: vec![format!(
                "container record at file offset {record_offset:#x}: compressed length {length:#x} and decoded size \
                 {size:#x} of the stream at file offset {stream:#x}, and this word, the {} of its compressed bytes \
                 (file offset {:#x})",
                if algorithm == Algorithm::Crc32 { "CRC-32" } else { "byte sum (sum32)" },
                field.offset
            )],
            alternatives: 0,
        }
    });
    let checksum = match field {
        Some(field) => format!("{} at file offset {:#x} verifies", field.role, field.offset),
        None => "no record word equals the byte sum or CRC-32 of the compressed bytes: a checksum field, if the \
                 record has one, does not verify (the stream or the record was changed)"
            .into(),
    };
    Stream {
        report: ContainerStream {
            stream_offset: stream,
            record_offset,
            compressed_length: length,
            decoded_size: size,
            check: None,
            checksum,
            decode_check,
            open_as_raw,
            record,
        },
        found,
    }
}

/// Decodes the stream with each fixed-parameter codec and, when one reproduces the record's sizes exactly, the
/// `raw` selector for the decoded bytes at the best load-address candidate.
fn decoded_selector(
    path: Option<&Path>,
    offset: u64,
    length: u64,
    size: u64,
    record: &ContainerRecord,
    raw: &rampage_loaders::RawCodeImage,
) -> (String, Option<Value>) {
    let Some(path) = path else { return ("not tried: the project has no source file".into(), None) };
    if size > rampage_loaders::MAX_RAW_NATIVE_BYTES as u64 && raw.profile().native_decoder() {
        return (format!("not tried: {size} decoded bytes exceed the Raw cap"), None);
    }
    for codec in [crate::ContentCodec::Lzss4k, crate::ContentCodec::Lz4Block] {
        let request = crate::DecodeFileRequest {
            codec,
            lzss: None,
            offset,
            length: length as usize,
            expected_output_size: size as usize,
            initial_write_offset: crate::default_initial_write_offset(codec),
            dictionary_fill: 0,
            timeout_ms: 3000,
            preview_offset: 0,
            preview_size: 0,
        };
        let Ok(decoded) = crate::decode_file_range(path, &request) else { continue };
        let receipt = &decoded.receipt;
        if receipt.output_size != size as usize || !receipt.input_fully_consumed {
            continue;
        }
        let arguments = crate::DecodeArguments {
            codec,
            offset,
            length,
            expected_output_size: size as usize,
            initial_write_offset: Some(request.initial_write_offset),
            dictionary_fill: Some(0),
            lzss: None,
            timeout_ms: None,
        };
        let Some(mut selector) = crate::compression_probe::open_as_raw(&arguments) else {
            return ("reproduced, but the decoded size exceeds the Raw cap".into(), None);
        };
        let candidates = rampage_loaders::raw_base::base_candidates(decoded.bytes(), None, &record.hints());
        selector["profile"] = Value::String(raw.profile().language_id().to_owned());
        if let Some(best) = candidates.candidates.first() {
            selector["base_address"] = Value::String(format!("{:#x}", best.base_address));
        }
        return ("reproduced".into(), Some(selector));
    }
    (
        "not reproduced by the classic 4 KiB-ring LZSS or LZ4 block decoder: run probe_compression with the stream's \
         offset, length and decoded size"
            .into(),
        None,
    )
}
