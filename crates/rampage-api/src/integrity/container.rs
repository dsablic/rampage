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

#[derive(Debug, Clone)]
pub(crate) struct Stream {
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

/// Candidate stream offsets examined per project, after the prescan.
const MAX_ATTEMPTS: usize = 64;
/// Bytes CRC-32ed (record checks and the record matcher) per project.
const MAX_CRC_BYTES: u64 = 64 << 20;
/// Decodes per project, sharing one deadline.
const MAX_DECODES: usize = 8;
const DECODE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(6000);

/// What one scan of a project's container streams found, and which budget, if any, cut it short.
#[derive(Debug, Clone, Default)]
pub(crate) struct ContainerScan {
    pub(super) streams: Vec<Stream>,
    pub(super) notes: Vec<String>,
}

/// The work one scan may do: candidates examined, CRC bytes, decodes and their shared deadline.
struct Budget {
    attempts: usize,
    crc_bytes: u64,
    decodes: usize,
    deadline: std::time::Instant,
    exhausted: Vec<&'static str>,
}

impl Budget {
    fn new() -> Self {
        Self {
            attempts: 0,
            crc_bytes: 0,
            decodes: 0,
            deadline: std::time::Instant::now() + DECODE_DEADLINE,
            exhausted: Vec::new(),
        }
    }

    fn note(&mut self, what: &'static str) {
        if !self.exhausted.contains(&what) {
            self.exhausted.push(what);
        }
    }

    /// Charges `bytes` of CRC-32 work; false (and noted) when the budget does not cover them.
    fn crc(&mut self, bytes: u64) -> bool {
        if self.crc_bytes + bytes > MAX_CRC_BYTES {
            self.note("CRC-32 bytes");
            return false;
        }
        self.crc_bytes += bytes;
        true
    }

    /// The milliseconds the next decode may take, charging it; None (and noted) when no decode is left.
    fn decode(&mut self) -> Option<u64> {
        let left = self.deadline.saturating_duration_since(std::time::Instant::now());
        if self.decodes >= MAX_DECODES || left.is_zero() {
            self.note("decodes");
            return None;
        }
        self.decodes += 1;
        Some((left.as_millis() as u64).clamp(1, 3000))
    }
}

/// Streams in the file-range regions of a Raw `binary` read from `path`. A record lies within 64 bytes before its
/// stream and holds the compressed length and the decoded size. The stream is found either from a word that is the
/// byte sum of the bytes after it for one of the record's lengths (found with prefix sums over the region), or from
/// a payload-offset word holding the stream's own file offset; in the latter case a byte sum or CRC-32 that does
/// not match is reported as not verifying, when a fixed-parameter codec decodes the stream exactly. Bounded: at
/// most 64 candidates examined, 64 MiB of CRC-32 and 8 decodes within 6 s; a cut is said in `notes`.
pub(crate) fn scan(binary: &Binary, path: Option<&Path>) -> ContainerScan {
    let Some(raw) = binary.raw_code_image() else { return ContainerScan::default() };
    let mut budget = Budget::new();
    let mut streams: Vec<Stream> = Vec::new();
    for region in raw.regions() {
        let Some(RawRegionSource::FileRange { offset: file_offset, .. }) = &region.source else { continue };
        let Some(bytes) = binary.image_bytes().get(region.data_range()) else { continue };
        let region_streams = Region::new(bytes, *file_offset).streams(&mut budget, path, raw, region);
        streams.extend(region_streams);
        if streams.len() >= MAX_STREAMS || budget.attempts >= MAX_ATTEMPTS {
            break;
        }
    }
    streams.truncate(MAX_STREAMS);
    // A record that does not verify, with a word where a verified sibling record keeps its checksum: say changed.
    let verified: Vec<(u64, &'static str)> = streams
        .iter()
        .filter(|stream| stream.found.is_some())
        .filter_map(|stream| {
            let field =
                stream.report.record.fields.iter().find(|field| matches!(field.role, "byte_sum32" | "crc32"))?;
            Some((stream.report.stream_offset - field.offset, field.role))
        })
        .collect();
    for stream in streams.iter_mut().filter(|stream| stream.found.is_none()) {
        let report = &mut stream.report;
        if let Some(&(distance, role)) = verified.first()
            && let Some(word) =
                report.record.fields.iter().find(|field| report.stream_offset - field.offset == distance)
        {
            report.checksum = format!(
                "the word at file offset {:#x} ({:#x}), where a verified sibling record keeps its {role}, does not \
                 match the compressed bytes: the stream or the record changed",
                word.offset, word.value
            );
        }
    }
    let mut notes = Vec::new();
    if budget.attempts >= MAX_ATTEMPTS {
        budget.note("candidates");
    }
    if !budget.exhausted.is_empty() {
        notes.push(format!(
            "container stream search budget exhausted ({}): streams may be missing",
            budget.exhausted.join(", ")
        ));
    }
    ContainerScan { streams, notes }
}

/// One file-range region's bytes, its aligned words and byte-sum prefix, held only while it is scanned.
struct Region<'a> {
    bytes: &'a [u8],
    file_offset: u64,
    file_end: u64,
    /// File offset of `words[0]`, the first 4-aligned file offset in the region.
    words_start: u64,
    words: Vec<u64>,
    /// prefix[i]: the byte sum of bytes[..i], modulo 2^32.
    prefix: Vec<u32>,
}

impl<'a> Region<'a> {
    fn new(bytes: &'a [u8], file_offset: u64) -> Self {
        let first = ((4 - file_offset % 4) % 4) as usize;
        let words = (first..bytes.len().saturating_sub(3)).step_by(4).map(|at| word(bytes, at)).collect();
        let mut prefix = Vec::with_capacity(bytes.len() + 1);
        prefix.push(0u32);
        let mut sum = 0u32;
        for &byte in bytes {
            sum = sum.wrapping_add(u32::from(byte));
            prefix.push(sum);
        }
        Self {
            bytes,
            file_offset,
            file_end: file_offset + bytes.len() as u64,
            words_start: file_offset + first as u64,
            words,
            prefix,
        }
    }

    /// The aligned words wholly within the 64 bytes before the aligned file offset `stream`.
    fn window(&self, stream: u64) -> &[u64] {
        let from = stream.saturating_sub(RECORD_WINDOW as u64).max(self.words_start);
        let first = ((from - self.words_start) as usize).div_ceil(4);
        let end = ((stream.saturating_sub(self.words_start)) / 4) as usize;
        &self.words[first.min(end)..end.min(self.words.len())]
    }

    fn sum(&self, stream: u64, length: u64) -> u64 {
        let from = (stream - self.file_offset) as usize;
        u64::from(self.prefix[from + length as usize].wrapping_sub(self.prefix[from]))
    }

    /// Aligned candidate stream offsets, in file order, at most a few more than can be examined.
    /// Offsets a byte sum names first (rare by chance), then offsets only a payload-offset word names; each kind
    /// at most 4 x 64, in file order.
    fn candidates(&self) -> Vec<u64> {
        let mut summed = std::collections::BTreeSet::new();
        let mut named = std::collections::BTreeSet::new();
        for (index, &value) in self.words.iter().enumerate() {
            let position = self.words_start + 4 * index as u64;
            // A payload-offset word: the stream's own file offset, just after the word.
            if value > position
                && value - position <= RECORD_WINDOW as u64
                && value < self.file_end
                && value.is_multiple_of(4)
                && named.len() < 4 * MAX_ATTEMPTS
            {
                named.insert(value);
            }
            // A stream starting at this word, summed by a word of the window before it for one of the window's
            // distinct lengths (at most 16 sums of 16 words per offset, however repetitive the bytes).
            let stream = position;
            let window = self.window(stream);
            let mut lengths = [0u64; RECORD_WINDOW / 4];
            let mut distinct = 0;
            for &length in window {
                if length >= 16 && stream + length <= self.file_end && !lengths[..distinct].contains(&length) {
                    lengths[distinct] = length;
                    distinct += 1;
                }
            }
            if lengths[..distinct].iter().any(|&length| window.contains(&self.sum(stream, length))) {
                summed.insert(stream);
                if summed.len() >= 4 * MAX_ATTEMPTS {
                    break;
                }
            }
        }
        let mut candidates: Vec<u64> = summed.iter().copied().collect();
        candidates.extend(named.into_iter().filter(|stream| !summed.contains(stream)));
        candidates
    }

    fn streams(
        &self,
        budget: &mut Budget,
        path: Option<&Path>,
        raw: &rampage_loaders::RawCodeImage,
        info: &rampage_loaders::RawRegionInfo,
    ) -> Vec<Stream> {
        // Records whose checksum verifies first, so noise candidates never spend the decodes they need.
        let mut streams = Vec::new();
        let mut unverified = Vec::new();
        for stream in self.candidates() {
            if streams.len() == MAX_STREAMS || budget.attempts >= MAX_ATTEMPTS {
                break;
            }
            budget.attempts += 1;
            match self.stream_at(stream, budget, path, raw, info, true) {
                Some(found) => streams.push(found),
                None => unverified.push(stream),
            }
        }
        for stream in unverified {
            if streams.len() == MAX_STREAMS || budget.decodes >= MAX_DECODES {
                break;
            }
            if let Some(found) = self.stream_at(stream, budget, path, raw, info, false) {
                streams.push(found);
            }
        }
        streams.sort_by_key(|stream| stream.report.stream_offset);
        streams
    }

    fn stream_at(
        &self,
        stream: u64,
        budget: &mut Budget,
        path: Option<&Path>,
        raw: &rampage_loaders::RawCodeImage,
        info: &rampage_loaders::RawRegionInfo,
        verified: bool,
    ) -> Option<Stream> {
        let stream_at = (stream - self.file_offset) as usize;
        let words = self.window(stream);
        let window_start = stream.saturating_sub(RECORD_WINDOW as u64).max(self.file_offset);
        let window = &self.bytes[(window_start - self.file_offset) as usize..stream_at];
        let mut lengths: Vec<u64> =
            words.iter().copied().filter(|&length| length >= 16 && stream + length <= self.file_end).collect();
        lengths.sort_unstable();
        lengths.dedup();
        let sizes = |length: u64| {
            let mut sizes: Vec<u64> =
                words.iter().copied().filter(|&size| size > length && size <= MAX_DECODED_SIZE).collect();
            sizes.sort_unstable();
            sizes.dedup();
            sizes
        };
        // container_record::find sums and CRCs the stream once per call.
        let record_for = |budget: &mut Budget, length: u64, size: u64| {
            if !budget.crc(length) {
                return None;
            }
            let input = &self.bytes[stream_at..stream_at + length as usize];
            crate::container_record::find(window_start, window, stream, input, length as usize, size as usize)
        };
        // A record word that is the byte sum (prefix sums) or CRC-32 of the stream for one of its lengths.
        let mut matched = None;
        for &length in lengths.iter().filter(|_| verified) {
            let summed = words.contains(&self.sum(stream, length));
            let checked = summed
                || (budget.crc(length)
                    && words.contains(&u64::from(crc32(&self.bytes[stream_at..stream_at + length as usize]))));
            if !checked {
                continue;
            }
            matched = sizes(length).into_iter().find_map(|size| {
                let record = record_for(budget, length, size)?;
                record.checksum_over.is_some().then_some((length, size, record))
            });
            if matched.is_some() {
                break;
            }
        }
        let (length, size, record, decoded) = match matched {
            Some((length, size, record)) => {
                let decoded = decoded_selector(budget, path, stream, length, size, &record, raw);
                (length, size, record, decoded)
            }
            None if verified => return None,
            None => {
                // Only a payload-offset word names this offset: the first length and size whose stream a
                // fixed-parameter codec decodes exactly.
                let pairs: Vec<(u64, u64)> = lengths
                    .iter()
                    .flat_map(|&length| sizes(length).into_iter().map(move |size| (length, size)))
                    .take(MAX_UNVERIFIED_PAIRS)
                    .collect();
                let mut reproduced = None;
                for (length, size) in pairs {
                    let Some(record) = record_for(budget, length, size) else { continue };
                    let decoded = decoded_selector(budget, path, stream, length, size, &record, raw);
                    if decoded.0 == "reproduced" {
                        reproduced = Some((length, size, record, decoded));
                        break;
                    }
                    if budget.decodes >= MAX_DECODES {
                        break;
                    }
                }
                reproduced?
            }
        };
        Some(stream_report(info, self.file_offset, stream, length, size, record, decoded))
    }
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
        None => UNVERIFIED.into(),
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

const UNVERIFIED: &str = "no record word equals the byte sum or CRC-32 of the compressed bytes; the record may use \
                          another algorithm or range, or the bytes changed";

/// Decodes the stream with each fixed-parameter codec, within `budget`, and, when one reproduces the record's sizes
/// exactly, the `raw` selector for the decoded bytes at the best load-address candidate.
fn decoded_selector(
    budget: &mut Budget,
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
        let Some(timeout_ms) = budget.decode() else {
            return ("not tried: the decode budget is exhausted".into(), None);
        };
        let request = crate::DecodeFileRequest {
            codec,
            lzss: None,
            offset,
            length: length as usize,
            expected_output_size: size as usize,
            initial_write_offset: crate::default_initial_write_offset(codec),
            dictionary_fill: 0,
            timeout_ms,
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
