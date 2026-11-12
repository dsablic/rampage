//! `probe_compression`: a bounded sweep of the built-in decoder families over an explicit file range, returning
//! ranked parameter sets that `decode_file_range` accepts as they are. Nothing is applied, published or executed.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rampage_decode::probe::{self, Codec, ProbeOptions, Verdict};
use rampage_decode::{DecodeError, DecodeOptions, Decoder, Lz4Block, ScanEnd};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decode_codecs::{ContentCodec, LzssParameters};
use crate::decode_content::{
    MAX_DECODE_EXPANSION_RATIO, MAX_DECODE_INPUT_BYTES, MAX_DECODE_OUTPUT_BYTES, MAX_DECODE_STEPS,
};
use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// Work steps for one whole sweep, counted as the decoders count them (a token or an output byte each).
pub const MAX_PROBE_STEPS: u64 = 768 * 1024 * 1024;
pub const MAX_PROBE_CANDIDATES: usize = 16;
pub const MAX_PROBE_PREVIEW_BYTES: usize = 128;
const MAX_PROBE_RESULT_BYTES: usize = 60_000;
/// The deadline shared by all of one call's candidate reproductions.
const REPRODUCE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeCompressionRequest {
    /// Original-file offset where the encoded stream is thought to start.
    pub offset: FileOffset,
    /// Encoded bytes, 1..=8388608. Trailing bytes after the stream are reported, not required to decode.
    pub length: FileOffset,
    /// The decoded size when known (a header's decoded-size word, say), 1..=16777216. With it a candidate must
    /// reach exactly this size; without it only an entropy drop and parse statistics rank candidates, and none
    /// is confident.
    pub expected_output_size: Option<FileOffset>,
    /// Candidates returned, 1..=16; default 5.
    #[schemars(range(min = 1, max = 16))]
    pub candidate_limit: Option<usize>,
    /// Cooperative sweep deadline, 1..=30000 ms; default 15000. File reads and hashes are not interrupted.
    #[schemars(range(min = 1, max = 30000))]
    pub timeout_ms: Option<u64>,
    /// Decoded preview bytes per candidate, 0..=128; default 48.
    #[schemars(range(min = 0, max = 128))]
    pub preview_size: Option<usize>,
}

/// Arguments for `decode_file_range` that reproduce a candidate exactly.
#[derive(Debug, Clone, Serialize)]
pub struct DecodeArguments {
    pub codec: ContentCodec,
    pub offset: u64,
    pub length: u64,
    pub expected_output_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_write_offset: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dictionary_fill: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lzss: Option<LzssParameters>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeCheck {
    pub name: &'static str,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeMetrics {
    /// Shannon entropy of the consumed input and of the output, bits per byte.
    pub input_entropy: f64,
    pub output_entropy: f64,
    /// How far reference length fields are from uniform: 0 uniform (typical of a wrong parse), 1 one value.
    pub length_field_skew: f64,
    /// The share of references whose source is close behind the output end.
    pub near_reference_fraction: f64,
    /// Ring offsets only: the share of the first window's output read from never-written ring positions.
    pub unwritten_dictionary_fraction: f64,
    /// The share of output bytes in printable runs of at least five characters.
    pub printable_fraction: f64,
    /// LZSS: short references whose next output byte equals the byte after their source, so the encoder could
    /// have made them longer. Near zero for the right parameters of a greedy or lazy encoder; it ranks
    /// parse-equivalent alternatives (ring start, distance bias, fill).
    pub extendable_matches: u64,
    pub extendable_match_fraction: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeCandidate {
    pub rank: usize,
    /// `confident` (only the first, only with expected_output_size), `plausible` or `weak`.
    pub verdict: &'static str,
    pub score: f64,
    pub decode_arguments: DecodeArguments,
    pub output_size: usize,
    pub output_sha256: String,
    pub input_consumed: usize,
    pub trailing_input_bytes: usize,
    /// Why decoding stopped: `input_exhausted`, `partial_token`, `output_limit` or `invalid_token`.
    pub stream_end: &'static str,
    pub literals: u64,
    pub references: u64,
    pub metrics: ProbeMetrics,
    pub checks: Vec<ProbeCheck>,
    /// Other passing candidates that split the input into the same tokens but decode different bytes.
    pub parse_equivalents: usize,
    /// Variants folded into this one because they decoded identical bytes from identical input.
    pub same_output_variants: usize,
    /// Ring offsets only: initial write offsets that explain the first references equally well.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_offset_alternatives: Option<usize>,
    /// Ring offsets only: whether output came from the initial fill, so `dictionary_fill` matters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dictionary_fill_exercised: Option<bool>,
    /// `reproduced` when decode_file_range's provider, with its budgets, gave the same bytes; otherwise why not.
    pub decode_check: String,
    pub preview_hex: String,
    pub preview_ascii: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeSweep {
    pub families: Vec<&'static str>,
    pub lzss_space: Vec<&'static str>,
    pub lzss_variants_sampled: usize,
    pub size_walks: usize,
    pub size_fits: usize,
    pub sample_input_bytes: usize,
    pub sample_decodes: usize,
    pub full_decodes: usize,
    pub size_mismatches: usize,
    pub steps: u64,
    pub max_steps: u64,
    /// `work_budget`, `cancelled` (the deadline) or absent when everything in the space was tried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_early: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ProbeCompressionReport {
    pub file_path: PathBuf,
    pub source_size: u64,
    pub source_offset: u64,
    pub source_length: usize,
    pub source_range_sha256: String,
    pub source_observation: &'static str,
    pub input_entropy_bits_per_byte: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_output_size: Option<usize>,
    pub interpretation: &'static str,
    pub candidates: Vec<ProbeCandidate>,
    /// Candidates found before `candidate_limit` cut the list.
    pub candidates_found: usize,
    pub sweep: ProbeSweep,
    pub not_tried: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn end_name(end: ScanEnd) -> &'static str {
    match end {
        ScanEnd::InputExhausted => "input_exhausted",
        ScanEnd::PartialToken => "partial_token",
        ScanEnd::OutputLimit => "output_limit",
        ScanEnd::InvalidToken => "invalid_token",
    }
}

fn arguments(codec: &Codec, offset: u64, length: usize, output_size: usize) -> DecodeArguments {
    match codec {
        Codec::Lzss(lzss) => DecodeArguments {
            codec: ContentCodec::Lzss,
            offset,
            length: length as u64,
            expected_output_size: output_size,
            initial_write_offset: Some(lzss.initial_write_offset),
            dictionary_fill: Some(lzss.dictionary_fill),
            lzss: Some(LzssParameters::from_provider(lzss)),
        },
        Codec::Lz4Block => DecodeArguments {
            codec: ContentCodec::Lz4Block,
            offset,
            length: length as u64,
            expected_output_size: output_size,
            initial_write_offset: None,
            dictionary_fill: None,
            lzss: None,
        },
    }
}

/// Probes an explicit file range for the built-in compressed-stream families.
pub fn probe_compression(path: &Path, request: &ProbeCompressionRequest) -> Result<ProbeCompressionReport, ApiError> {
    let length = usize::try_from(request.length.0).map_err(|_| invalid("probe length exceeds host width"))?;
    if !(1..=MAX_DECODE_INPUT_BYTES).contains(&length) {
        return Err(invalid("probe length must be 1..=8388608 bytes"));
    }
    let expected = match request.expected_output_size {
        Some(size) => {
            let size = usize::try_from(size.0).map_err(|_| invalid("probe expected size exceeds host width"))?;
            if !(1..=MAX_DECODE_OUTPUT_BYTES).contains(&size) {
                return Err(invalid("probe expected_output_size must be 1..=16777216 bytes"));
            }
            Some(size)
        }
        None => None,
    };
    let limit = request.candidate_limit.unwrap_or(5);
    if !(1..=MAX_PROBE_CANDIDATES).contains(&limit) {
        return Err(invalid("probe candidate_limit must be 1..=16"));
    }
    let timeout_ms = request.timeout_ms.unwrap_or(15_000);
    if !(1..=30_000).contains(&timeout_ms) {
        return Err(invalid("probe timeout_ms must be 1..=30000"));
    }
    let preview_size = request.preview_size.unwrap_or(48);
    if preview_size > MAX_PROBE_PREVIEW_BYTES {
        return Err(invalid("probe preview_size must be 0..=128"));
    }
    request.offset.0.checked_add(length as u64).ok_or_else(|| invalid("probe source range overflows"))?;
    if serde_json::to_vec(path).map_err(|_| invalid("probe path is not JSON-serializable"))?.len() > 4096 {
        return Err(invalid("probe path exceeds receipt budget"));
    }

    let source = RangeSource::open(path, request.offset.0, length)?;
    let input = source.read()?;
    source.revalidate()?;
    let started = Instant::now();
    let deadline = Duration::from_millis(timeout_ms);
    let max_output = expected.unwrap_or(MAX_DECODE_OUTPUT_BYTES.min(length.saturating_mul(MAX_DECODE_EXPANSION_RATIO)));
    let options =
        ProbeOptions { expected_output_size: expected, max_output_size: max_output, max_steps: MAX_PROBE_STEPS };
    let report = probe::probe(&input, &options, &mut || started.elapsed() >= deadline);
    source.revalidate()?;

    let found = report.candidates.len();
    // Reproductions share their own deadline, so a probe that used its whole deadline still checks candidates.
    let reproducing = Instant::now();
    let mut reproduce_cancelled = || reproducing.elapsed() >= REPRODUCE_TIMEOUT;
    let candidates = report
        .candidates
        .iter()
        .take(limit)
        .enumerate()
        .map(|(index, candidate)| {
            let (decode_check, sha, preview) = reproduce(&input, candidate, preview_size, &mut reproduce_cancelled);
            let ring = matches!(candidate.codec, Codec::Lzss(lzss) if lzss.offset_mode == rampage_decode::OffsetMode::RingPosition);
            ProbeCandidate {
                rank: index + 1,
                verdict: match candidate.verdict {
                    Verdict::Confident => "confident",
                    Verdict::Plausible => "plausible",
                    Verdict::Weak => "weak",
                },
                score: candidate.score,
                decode_arguments: arguments(&candidate.codec, request.offset.0, length, candidate.output_size),
                output_size: candidate.output_size,
                output_sha256: sha,
                input_consumed: candidate.consumed,
                trailing_input_bytes: candidate.trailing,
                stream_end: end_name(candidate.end),
                literals: candidate.literals,
                references: candidate.references,
                metrics: ProbeMetrics {
                    input_entropy: round(candidate.input_entropy),
                    output_entropy: round(candidate.output_entropy),
                    length_field_skew: round(candidate.length_skew),
                    near_reference_fraction: round(candidate.near_fraction),
                    unwritten_dictionary_fraction: round(candidate.unwritten_fraction),
                    printable_fraction: round(candidate.printable_fraction),
                    extendable_matches: candidate.extendable_matches,
                    extendable_match_fraction: round(candidate.extendable_fraction),
                },
                checks: candidate.checks.iter().map(|check| ProbeCheck { name: check.name, passed: check.passed }).collect(),
                parse_equivalents: candidate.parse_equivalents,
                same_output_variants: candidate.same_output_variants,
                write_offset_alternatives: ring.then_some(candidate.write_offset_alternatives),
                dictionary_fill_exercised: ring.then_some(candidate.fill_exercised),
                decode_check,
                preview_hex: rampage_arch::hex::bytes(&preview),
                preview_ascii: preview
                    .iter()
                    .map(|&byte| if (0x20..=0x7e).contains(&byte) { char::from(byte) } else { '.' })
                    .collect(),
            }
        })
        .collect();

    let result = ProbeCompressionReport {
        file_path: path.to_owned(),
        source_size: source.size(),
        source_offset: request.offset.0,
        source_length: length,
        source_range_sha256: rampage_arch::hex::bytes(&Sha256::digest(&input)),
        source_observation: "revalidated_non_atomic_file_range",
        input_entropy_bits_per_byte: round(report.input_entropy),
        expected_output_size: expected,
        interpretation: "ranked_candidates_not_identifications",
        candidates,
        candidates_found: found,
        sweep: ProbeSweep {
            families: vec!["lzss", "lz4-block"],
            lzss_space: vec![
                "window_bits 12, 11, 13, 10; min_match 3, 2",
                "flag_order lsb_first, msb_first; literal_bit 1, 0",
                "reference_layout split_byte, le16_offset_low, le16_length_low, be16_offset_low, be16_length_low",
                "offset_mode distance, distance_minus_one, ring_position",
                "ring_position: initial_write_offset window-max_match and 0, plus the offsets that best explain the \
                 first references; dictionary_fill 0x00, 0x20, 0xff only when output reads the fill",
            ],
            lzss_variants_sampled: report.lzss_variants,
            size_walks: report.size_walks,
            size_fits: report.size_fits,
            sample_input_bytes: input.len().min(probe::SAMPLE_INPUT_BYTES),
            sample_decodes: report.sample_decodes,
            full_decodes: report.full_decodes,
            size_mismatches: report.size_mismatches,
            steps: report.steps,
            max_steps: MAX_PROBE_STEPS,
            stopped_early: report.stopped_early,
        },
        not_tried: vec![
            "LZSS with references other than two bytes, literals other than one byte, flags other than 8-bit bytes, \
             or in-band end markers",
            "LZ77 variants with variable-length (Elias-gamma or Huffman) codes, LZO, LZMA, deflate/zlib, \
             zstd, Brotli and LZ4 frames",
            "Streams that do not start at offset, interleaved or chunked streams, XOR or other obfuscation",
            "Architecture-aware plausibility (such as a valid Thumb decode ratio); output is judged by entropy, \
             printable runs and parse statistics only",
        ],
        limitations: vec![
            "Candidates are ranked by parse statistics, input consumption, a supplied size and an entropy drop: \
             evidence, not identification. Read checks and metrics before decoding.",
            "Without expected_output_size no candidate is confident; parameters such as min_match, a distance \
             bias, a ring start or the ring fill can decode the same tokens to different bytes (see \
             parse_equivalents). Alternatives are ordered by extendable matches, then output entropy; when they \
             tie, as an exercised ring fill often does, the first is only plausible.",
            "decode_arguments reproduce a candidate in decode_file_range; decode_check says whether its budgets \
             (128:1 expansion, 64 Mi steps) allowed that.",
            "Each LZSS variant first decodes at most 16 KiB of input; only the best then decode the whole range.",
            "Decoded bytes are transient: no extraction, file publication, recursion, loading or execution.",
            "The deadline is cooperative; file reads and hashes are not interrupted. Reads are not atomic.",
        ],
    };
    if serde_json::to_vec(&result).map_err(|_| invalid("probe serialization failed"))?.len() > MAX_PROBE_RESULT_BYTES {
        return Err(invalid("probe result exceeds 60000 JSON bytes; lower candidate_limit or preview_size"));
    }
    Ok(result)
}

/// Decodes a candidate again through the provider `decode_file_range` uses, with its budgets.
fn reproduce(
    input: &[u8],
    candidate: &probe::Candidate,
    preview_size: usize,
    cancelled: &mut dyn FnMut() -> bool,
) -> (String, String, Vec<u8>) {
    let options = DecodeOptions {
        expected_output_size: candidate.output_size,
        max_output_size: MAX_DECODE_OUTPUT_BYTES,
        max_expansion_ratio: MAX_DECODE_EXPANSION_RATIO,
        max_steps: MAX_DECODE_STEPS,
    };
    let result = match candidate.codec {
        Codec::Lzss(lzss) => lzss.decode(input, &options, cancelled),
        Codec::Lz4Block => Lz4Block.decode(input, &options, cancelled),
    };
    match result {
        Ok(decoded) if decoded.consumed == candidate.consumed => {
            let preview = decoded.bytes[..decoded.bytes.len().min(preview_size)].to_vec();
            ("reproduced".to_owned(), rampage_arch::hex::bytes(&Sha256::digest(&decoded.bytes)), preview)
        }
        Ok(_) => ("consumed a different input length when decoded".to_owned(), String::new(), Vec::new()),
        Err(DecodeError::Cancelled) => {
            ("not reproduced: the reproduction deadline passed".to_owned(), String::new(), Vec::new())
        }
        Err(error) => (format!("decode_file_range would refuse: {error}"), String::new(), Vec::new()),
    }
}

#[cfg(all(test, unix))]
#[path = "compression_probe_tests.rs"]
mod tests;
