//! Format-independent layout of an explicit file range: fill and occupied regions, per-block entropy, printable
//! string clusters, range hashes and clearly labelled heuristic hints. No loader, mapping, extraction or decoding.

use std::path::{Path, PathBuf};

use rampage_analysis::strings::is_printable;
use rampage_analysis::triage::entropy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use rampage_analysis::strings::Encoding as StringEncoding;

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// The most bytes one call reads. A whole-file request on a larger file covers this much and names the rest.
pub const MAX_LAYOUT_BYTES: u64 = 64 << 20;
/// The largest JSON result; a larger one is refused with the limits to lower.
pub const MAX_LAYOUT_RESULT_BYTES: usize = 60_000;
/// Bits per byte at or above which a block is flagged high entropy.
pub const HIGH_ENTROPY: f64 = 7.2;
/// Bits per byte at or below which a block is flagged low entropy.
pub const LOW_ENTROPY: f64 = 2.0;
/// The smallest block size, and the smallest block that is classified. The entropy of a small sample is biased
/// low: uniformly random 256-byte blocks average about 7.2 bits per byte (often below the high threshold),
/// 512-byte blocks about 7.6.
pub const MIN_BLOCK_SIZE: u64 = 512;
const MAX_BLOCK_SIZE: u64 = 16 << 20;
/// Spans summarise `blocks`, so they are capped at `block_limit` and at most this many.
const MAX_SPANS: usize = 128;
const MAX_HINTS: usize = 8;
/// Occupied-region starts searched for compressed-component headers.
const MAX_CONTAINER_SEEDS: usize = 4096;
/// Exception words after the reset vector that a vector-table hint needs within the range.
const MIN_HANDLER_WORDS: usize = 4;
const PREVIEWS_PER_CLUSTER: usize = 3;
const PREVIEW_CHARS: usize = 48;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileLayoutRequest {
    /// Original-file byte offset where the selection starts; default 0.
    pub offset: Option<FileOffset>,
    /// Selected bytes, 1..=67108864 (64 MiB). Omitted: the rest of the file, at most 64 MiB; a continuation then
    /// names the remainder.
    pub length: Option<FileOffset>,
    /// Shortest run of one repeated byte reported as a fill region, 8..=16777216; default 64.
    #[schemars(range(min = 8, max = 16777216))]
    pub min_fill_run: Option<u64>,
    /// Entropy block size in bytes, 512..=16777216; default 4096. Blocks start at the selection offset.
    #[schemars(range(min = 512, max = 16777216))]
    pub block_size: Option<u64>,
    /// Shortest printable run counted as a string, 4..=64 characters; default 6.
    #[schemars(range(min = 4, max = 64))]
    pub min_string_length: Option<usize>,
    /// Largest byte gap between consecutive strings of one cluster, 1..=4096; default 64.
    #[schemars(range(min = 1, max = 4096))]
    pub cluster_gap: Option<u64>,
    /// Fewest strings a cluster needs, 1..=64; default 3.
    #[schemars(range(min = 1, max = 64))]
    pub cluster_min_strings: Option<usize>,
    /// Also cluster UTF-16LE strings of ASCII-range characters; default false.
    pub utf16: Option<bool>,
    /// Report heuristic hints (Cortex-M vector-table candidates); default true. Hints are evidence, not mappings.
    pub hints: Option<bool>,
    /// Regions returned, 1..=256; default 128.
    #[schemars(range(min = 1, max = 256))]
    pub region_limit: Option<usize>,
    /// Per-block entropy values returned, 1..=4096; default 1024.
    #[schemars(range(min = 1, max = 4096))]
    pub block_limit: Option<usize>,
    /// String clusters returned, 1..=128; default 16.
    #[schemars(range(min = 1, max = 128))]
    pub cluster_limit: Option<usize>,
}

/// The parameters in effect, defaults applied.
#[derive(Debug, Clone, Serialize)]
pub struct LayoutParameters {
    pub min_fill_run: u64,
    pub block_size: u64,
    pub min_string_length: usize,
    pub cluster_gap: u64,
    pub cluster_min_strings: usize,
    pub utf16: bool,
    pub hints: bool,
    pub region_limit: usize,
    pub block_limit: usize,
    pub cluster_limit: usize,
    pub high_entropy_threshold: f64,
    pub low_entropy_threshold: f64,
}

impl LayoutParameters {
    pub fn from_request(request: &FileLayoutRequest) -> Result<Self, ApiError> {
        fn bounded<T: PartialOrd + Copy + std::fmt::Display>(
            name: &str,
            value: Option<T>,
            default: T,
            (min, max): (T, T),
        ) -> Result<T, ApiError> {
            let value = value.unwrap_or(default);
            if value < min || value > max {
                return Err(invalid(&format!("file layout {name} must be {min}..={max}")));
            }
            Ok(value)
        }
        Ok(Self {
            min_fill_run: bounded("min_fill_run", request.min_fill_run, 64, (8, 16 << 20))?,
            block_size: bounded("block_size", request.block_size, 4096, (MIN_BLOCK_SIZE, MAX_BLOCK_SIZE))?,
            min_string_length: bounded("min_string_length", request.min_string_length, 6, (4, 64))?,
            cluster_gap: bounded("cluster_gap", request.cluster_gap, 64, (1, 4096))?,
            cluster_min_strings: bounded("cluster_min_strings", request.cluster_min_strings, 3, (1, 64))?,
            utf16: request.utf16.unwrap_or(false),
            hints: request.hints.unwrap_or(true),
            region_limit: bounded("region_limit", request.region_limit, 128, (1, 256))?,
            block_limit: bounded("block_limit", request.block_limit, 1024, (1, 4096))?,
            cluster_limit: bounded("cluster_limit", request.cluster_limit, 16, (1, 128))?,
            high_entropy_threshold: HIGH_ENTROPY,
            low_entropy_threshold: LOW_ENTROPY,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// A run of 0xff, as erased flash reads.
    FillFf,
    /// A run of 0x00.
    FillZero,
    /// A run of one other repeated byte.
    FillOther,
    /// Everything between fill runs, including repeated-byte runs shorter than `min_fill_run`.
    Occupied,
}

#[derive(Debug, Serialize)]
pub struct LayoutRegion {
    pub offset: u64,
    pub length: u64,
    pub kind: RegionKind,
    /// The repeated byte of a fill region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_byte: Option<String>,
    /// SHA-256 of an occupied region's bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Shannon entropy of an occupied region's bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_bits_per_byte: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyClass {
    High,
    Low,
}

/// Adjacent blocks of one entropy class.
#[derive(Debug, Serialize)]
pub struct EntropySpan {
    pub offset: u64,
    pub length: u64,
    pub class: EntropyClass,
    pub block_count: usize,
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Serialize)]
pub struct EntropyReport {
    pub block_size: u64,
    /// Entropy of the whole selection, bits per byte.
    pub whole_range: f64,
    /// Bits per byte of each block, one number per block: block `i` starts at `source_offset + i * block_size`.
    pub blocks: Vec<f64>,
    /// Size of the selection's last block, which is shorter than `block_size` when the selection is not a
    /// multiple of it.
    pub last_block_bytes: u64,
    /// High- and low-entropy spans of adjacent blocks; medium blocks are not listed.
    pub spans: Vec<EntropySpan>,
    /// When the blocks were cut off: the smallest power of two that fits every block in `block_limit`, or the
    /// 16 MiB maximum when none does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_block_size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct StringPreview {
    pub offset: u64,
    /// The string's length in bytes (two per character in UTF-16LE).
    pub length: u64,
    pub characters: usize,
    /// At most 48 characters of the string.
    pub text: String,
    pub truncated: bool,
}

/// A dense area of printable strings, from the first string's start to the last one's end.
#[derive(Debug, Serialize)]
pub struct StringCluster {
    pub offset: u64,
    pub length: u64,
    pub encoding: StringEncoding,
    pub strings: usize,
    pub string_bytes: u64,
    /// `string_bytes / length`.
    pub density: f64,
    /// The first few strings, for orientation; list_strings returns them all.
    pub previews: Vec<StringPreview>,
}

/// The words of a Cortex-M vector-table candidate.
#[derive(Debug, Serialize)]
pub struct CortexMVectors {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub initial_sp: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub reset_handler: u64,
    pub handler_words_checked: usize,
    pub handler_words_plausible: usize,
}

/// A heuristic observation, never a mapping, base address or architecture claim. `kind` names which of the
/// kind-specific objects is present.
#[derive(Debug, Serialize)]
pub struct LayoutHint {
    pub kind: &'static str,
    pub offset: u64,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cortex_m: Option<CortexMVectors>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<crate::layout_containers::ContainerCandidate>,
}

#[derive(Debug, Default, Serialize)]
pub struct LayoutSummary {
    pub occupied_bytes: u64,
    pub occupied_regions: usize,
    pub fill_ff_bytes: u64,
    pub fill_zero_bytes: u64,
    pub fill_other_bytes: u64,
    pub fill_regions: usize,
    pub high_entropy_bytes: u64,
    pub low_entropy_bytes: u64,
    pub strings: usize,
    pub string_clusters: usize,
}

/// How much of one list was returned. `next_offset` is the first item left out, when any was.
#[derive(Debug, Default, Serialize)]
pub struct ListBound {
    pub total: usize,
    pub returned: usize,
    pub next_offset: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
pub struct LayoutBounds {
    pub regions: ListBound,
    pub blocks: ListBound,
    pub entropy_spans: ListBound,
    pub string_clusters: ListBound,
    pub hints: ListBound,
    /// How far the compressed-component search went, when hints were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_search: Option<crate::layout_containers::ContainerSearch>,
}

/// Arguments for a follow-up call covering what this one left out.
#[derive(Debug, Serialize)]
pub struct LayoutContinuation {
    pub offset: u64,
    pub length: u64,
    /// Why: the lists that were cut off (`regions`, `blocks`, `string_clusters`), or `range` when the whole-file
    /// default stopped at 64 MiB.
    pub truncated: Vec<&'static str>,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FileLayoutReport {
    pub file_path: PathBuf,
    pub source_size: u64,
    pub source_offset: u64,
    pub source_length: u64,
    pub source_range_sha256: String,
    pub source_observation: &'static str,
    pub source_coordinate_space: &'static str,
    pub parameters: LayoutParameters,
    pub summary: LayoutSummary,
    pub regions: Vec<LayoutRegion>,
    pub entropy: EntropyReport,
    pub string_clusters: Vec<StringCluster>,
    pub hints: Vec<LayoutHint>,
    pub hint_interpretation: &'static str,
    pub bounds: LayoutBounds,
    pub continuation: Option<LayoutContinuation>,
    pub limitations: Vec<&'static str>,
}

/// Lays out an explicit range of the regular file at `path`, or its first 64 MiB from `offset`.
pub fn file_layout(path: &Path, request: &FileLayoutRequest) -> Result<FileLayoutReport, ApiError> {
    let parameters = LayoutParameters::from_request(request)?;
    if serde_json::to_vec(path).map_err(|_| invalid("file layout path is not JSON-serializable"))?.len() > 4096 {
        return Err(invalid("file layout path exceeds receipt budget"));
    }
    let offset = request.offset.map_or(0, |offset| offset.0);
    let explicit = request.length.map(|length| length.0);
    let source = RangeSource::open_sized(path, offset, |size| {
        let length = match explicit {
            Some(0) => return Err(invalid("file layout needs a non-empty range; length must be at least 1")),
            Some(length) if length > MAX_LAYOUT_BYTES => {
                return Err(invalid(
                    "file layout length exceeds 64 MiB; select at most 67108864 bytes and continue from there",
                ));
            }
            Some(length) => length,
            None if offset >= size => {
                return Err(invalid("file layout range is empty: offset is at or past the end of the file"));
            }
            None => (size - offset).min(MAX_LAYOUT_BYTES),
        };
        usize::try_from(length).map_err(|_| invalid("file layout range exceeds host width"))
    })?;
    let bytes = source.read()?;
    source.revalidate()?;
    let mut report = layout(&bytes, offset, source.size(), explicit.is_some(), &parameters);
    report.file_path = path.to_owned();
    let json = serde_json::to_vec(&report).map_err(|_| invalid("file layout serialization failed"))?;
    if json.len() > MAX_LAYOUT_RESULT_BYTES {
        return Err(invalid(
            "file layout exceeds 60000 JSON bytes; lower region_limit, block_limit or cluster_limit, raise \
             block_size, or select a smaller range",
        ));
    }
    Ok(report)
}

/// The layout of `bytes`, which were read from `offset` of a source of `source_size` bytes. `explicit_length`
/// says whether the caller chose the length, which decides how far a continuation reaches.
pub(crate) fn layout(
    bytes: &[u8],
    offset: u64,
    source_size: u64,
    explicit_length: bool,
    parameters: &LayoutParameters,
) -> FileLayoutReport {
    let end = offset + bytes.len() as u64;
    let mut summary = LayoutSummary::default();
    let mut bounds = LayoutBounds::default();

    let (regions, mut hints, boundaries) = regions_and_hints(bytes, offset, parameters, &mut summary, &mut bounds);
    if parameters.hints {
        let (found, mut search) = crate::layout_containers::candidates(
            bytes,
            offset,
            &boundaries.occupied,
            &boundaries.fill,
            crate::layout_containers::SearchLimits::default(),
        );
        search.seed_limit_reached |= boundaries.occupied_truncated;
        bounds.container_search = Some(search);
        merge_hints(&mut hints, &mut bounds.hints, found.into_iter().map(crate::layout_containers::hint).collect());
    }
    let entropy = entropy_report(bytes, offset, parameters, &mut summary, &mut bounds);
    let string_clusters = clusters(bytes, offset, parameters, &mut summary, &mut bounds.string_clusters);

    // Only the caller-sized lists move the continuation. Spans summarise `blocks`, which stay complete up to
    // their own cut, and hints are a capped sample.
    let mut truncated = Vec::new();
    let mut next = None::<u64>;
    for (name, bound) in
        [("regions", &bounds.regions), ("blocks", &bounds.blocks), ("string_clusters", &bounds.string_clusters)]
    {
        if let Some(at) = bound.next_offset {
            truncated.push(name);
            next = Some(next.map_or(at, |next| next.min(at)));
        }
    }
    if !explicit_length && end < source_size {
        truncated.push("range");
        next = Some(next.map_or(end, |next| next.min(end)));
    }
    let continuation = next.map(|next| LayoutContinuation {
        offset: next,
        length: if explicit_length { end - next } else { (source_size - next).min(MAX_LAYOUT_BYTES) },
        truncated,
        note: "Call again with this offset and length and the same parameters. Lists restart there, so items at or \
               after the offset may repeat, and entropy blocks are aligned to the new offset.",
    });

    FileLayoutReport {
        file_path: PathBuf::new(),
        source_size,
        source_offset: offset,
        source_length: bytes.len() as u64,
        source_range_sha256: rampage_arch::hex::bytes(&Sha256::digest(bytes)),
        source_observation: "revalidated_non_atomic_file_range",
        source_coordinate_space: "original_file_byte_offset",
        parameters: parameters.clone(),
        summary,
        regions,
        entropy,
        string_clusters,
        hints,
        hint_interpretation: "heuristic_candidates_not_mappings",
        bounds,
        continuation,
        limitations: vec![
            "Offsets are original-file byte offsets. Nothing is mapped, loaded, decoded, extracted or executed.",
            "Fill means a run of one repeated byte at least min_fill_run long; shorter runs stay in occupied regions.",
            "Entropy flags are statistics, not proof of compression or encryption; low entropy is not proof of padding.",
            "String clusters are dense printable runs, not a full string list; use list_strings for every string.",
            "Hints are heuristic candidates. A vector-table candidate proves no architecture, base address or entry.",
            "A compressed-component candidate is a header whose words agree with the bytes after it (a size, and a \
             byte sum or CRC-32, or a packed payload ending at a boundary); field roles are inferred, not known, and \
             nothing is decoded. Hand its payload range and decoded-size candidates to probe_compression.",
            "Hashes bind the selected bytes as read; reads are not atomic and are not an authenticity proof.",
        ],
    }
}

/// Range-relative starts of every occupied region and fill run, listed or not.
#[derive(Default)]
struct Boundaries {
    occupied: Vec<usize>,
    /// More occupied regions than [`MAX_CONTAINER_SEEDS`] started in the range.
    occupied_truncated: bool,
    fill: std::collections::BTreeSet<usize>,
}

/// Appends offset-ordered `extra` hints after the vector-table `hints`, which keep their places: hints are ordered
/// by kind, then offset, each kind a prefix of its own candidates. At most [`MAX_HINTS`] are kept; `next_offset`
/// is the lowest offset left out of any kind, so a call from it sees every omitted hint again.
fn merge_hints(hints: &mut Vec<LayoutHint>, bound: &mut ListBound, extra: Vec<LayoutHint>) {
    for hint in extra {
        bound.total += 1;
        if hints.len() < MAX_HINTS {
            hints.push(hint);
        } else {
            bound.next_offset = Some(bound.next_offset.map_or(hint.offset, |next| next.min(hint.offset)));
        }
    }
    bound.returned = hints.len();
}

fn regions_and_hints(
    bytes: &[u8],
    offset: u64,
    parameters: &LayoutParameters,
    summary: &mut LayoutSummary,
    bounds: &mut LayoutBounds,
) -> (Vec<LayoutRegion>, Vec<LayoutHint>, Boundaries) {
    let mut regions = Vec::new();
    let mut hints = Vec::new();
    let mut boundaries = Boundaries::default();
    let mut last_hint_check = None;
    let mut emit = |start: usize, end: usize, fill: Option<u8>| {
        if fill.is_some() {
            boundaries.fill.insert(start);
        } else if boundaries.occupied.len() < MAX_CONTAINER_SEEDS {
            boundaries.occupied.push(start);
        } else {
            boundaries.occupied_truncated = true;
        }
        let length = (end - start) as u64;
        match fill {
            Some(0xff) => summary.fill_ff_bytes += length,
            Some(0) => summary.fill_zero_bytes += length,
            Some(_) => summary.fill_other_bytes += length,
            None => summary.occupied_bytes += length,
        }
        if fill.is_some() {
            summary.fill_regions += 1;
        } else {
            summary.occupied_regions += 1;
            if parameters.hints {
                // A table whose first bytes equal the preceding fill byte starts inside the fill run.
                let absolute = offset + start as u64;
                for candidate in [absolute & !3, absolute] {
                    let Some(index) = candidate.checked_sub(offset).map(|index| index as usize) else { continue };
                    if candidate % 4 != 0 || last_hint_check == Some(index) {
                        continue;
                    }
                    last_hint_check = Some(index);
                    if let Some(hint) = cortex_m_candidate(bytes, index, offset) {
                        record(&mut bounds.hints, &mut hints, MAX_HINTS, hint.offset, hint);
                    }
                }
            }
        }
        let region = LayoutRegion {
            offset: offset + start as u64,
            length,
            kind: match fill {
                Some(0xff) => RegionKind::FillFf,
                Some(0) => RegionKind::FillZero,
                Some(_) => RegionKind::FillOther,
                None => RegionKind::Occupied,
            },
            fill_byte: fill.map(|byte| format!("{byte:#04x}")),
            sha256: None,
            entropy_bits_per_byte: None,
        };
        record(&mut bounds.regions, &mut regions, parameters.region_limit, region.offset, region);
    };
    let mut occupied_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let run = bytes[index..].iter().position(|&other| other != byte).unwrap_or(bytes.len() - index);
        if run as u64 >= parameters.min_fill_run {
            if occupied_start < index {
                emit(occupied_start, index, None);
            }
            emit(index, index + run, Some(byte));
            occupied_start = index + run;
        }
        index += run;
    }
    if occupied_start < bytes.len() {
        emit(occupied_start, bytes.len(), None);
    }
    for region in regions.iter_mut().filter(|region| region.kind == RegionKind::Occupied) {
        let start = (region.offset - offset) as usize;
        let slice = &bytes[start..start + region.length as usize];
        region.sha256 = Some(rampage_arch::hex::bytes(&Sha256::digest(slice)));
        region.entropy_bits_per_byte = Some(entropy(slice));
    }
    (regions, hints, boundaries)
}

/// Keeps `item` when fewer than `limit` are kept, and counts it either way.
fn record<T>(bound: &mut ListBound, items: &mut Vec<T>, limit: usize, offset: u64, item: T) {
    bound.total += 1;
    if items.len() < limit {
        items.push(item);
        bound.returned += 1;
    } else if bound.next_offset.is_none() {
        bound.next_offset = Some(offset);
    }
}

fn word(bytes: &[u8], index: usize) -> Option<u32> {
    bytes.get(index..index + 4).map(|word| u32::from_le_bytes(word.try_into().unwrap()))
}

fn sram_or_ccm(value: u32) -> bool {
    (0x1000_0000..=0x1100_0000).contains(&value) || (0x2000_0000..=0x3fff_fffc).contains(&value)
}

fn thumb_code(value: u32) -> bool {
    value & 1 == 1 && value > 1 && value < 0x2000_0000
}

/// A word pair at `index` that reads like a Cortex-M initial SP and reset vector: the SP word-aligned in the SRAM
/// (or CCM) region and the reset handler an odd (Thumb) code-region address, with at least four following
/// exception words in the range, at least half of them zero or odd code-region addresses.
fn cortex_m_candidate(bytes: &[u8], index: usize, offset: u64) -> Option<LayoutHint> {
    let sp = word(bytes, index)?;
    let reset = word(bytes, index + 4)?;
    if sp % 4 != 0 || !sram_or_ccm(sp) || !thumb_code(reset) {
        return None;
    }
    let handlers: Vec<u32> = (2..16).map_while(|slot| word(bytes, index + slot * 4)).collect();
    let plausible = handlers.iter().filter(|&&handler| handler == 0 || thumb_code(handler)).count();
    if handlers.len() < MIN_HANDLER_WORDS || plausible * 2 < handlers.len() {
        return None;
    }
    Some(LayoutHint {
        kind: "cortex_m_vector_table_candidate",
        offset: offset + index as u64,
        evidence: vec![
            format!("word {sp:#010x} is word-aligned in the Cortex-M SRAM/CCM address range, like an initial SP"),
            format!("next word {reset:#010x} is odd (Thumb bit) and below 0x20000000, like a reset handler"),
            format!(
                "{plausible} of {} following exception words are zero or odd code-region addresses",
                handlers.len()
            ),
        ],
        container: None,
        cortex_m: Some(CortexMVectors {
            initial_sp: sp.into(),
            reset_handler: reset.into(),
            handler_words_checked: handlers.len(),
            handler_words_plausible: plausible,
        }),
    })
}

fn entropy_report(
    bytes: &[u8],
    offset: u64,
    parameters: &LayoutParameters,
    summary: &mut LayoutSummary,
    bounds: &mut LayoutBounds,
) -> EntropyReport {
    let block_size = parameters.block_size as usize;
    let span_limit = parameters.block_limit.min(MAX_SPANS);
    let mut blocks = Vec::new();
    let mut spans: Vec<EntropySpan> = Vec::new();
    let mut open: Option<EntropySpan> = None;
    for (index, block) in bytes.chunks(block_size).enumerate() {
        let start = offset + (index * block_size) as u64;
        let value = entropy(block);
        record(&mut bounds.blocks, &mut blocks, parameters.block_limit, start, value);
        let class = if (block.len() as u64) < MIN_BLOCK_SIZE {
            None
        } else if value >= HIGH_ENTROPY {
            Some(EntropyClass::High)
        } else if value <= LOW_ENTROPY {
            Some(EntropyClass::Low)
        } else {
            None
        };
        match class {
            Some(EntropyClass::High) => summary.high_entropy_bytes += block.len() as u64,
            Some(EntropyClass::Low) => summary.low_entropy_bytes += block.len() as u64,
            None => {}
        }
        match (&mut open, class) {
            (Some(span), Some(class)) if span.class == class => {
                span.length += block.len() as u64;
                span.block_count += 1;
                span.min = span.min.min(value);
                span.max = span.max.max(value);
            }
            _ => {
                if let Some(span) = open.take() {
                    record(&mut bounds.entropy_spans, &mut spans, span_limit, span.offset, span);
                }
                open = class.map(|class| EntropySpan {
                    offset: start,
                    length: block.len() as u64,
                    class,
                    block_count: 1,
                    min: value,
                    max: value,
                });
            }
        }
    }
    if let Some(span) = open {
        record(&mut bounds.entropy_spans, &mut spans, span_limit, span.offset, span);
    }
    let suggested_block_size = (bounds.blocks.total > parameters.block_limit).then(|| {
        (bytes.len() as u64)
            .div_ceil(parameters.block_limit as u64)
            .next_power_of_two()
            .clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE)
    });
    let last_block_bytes = match bytes.len() % block_size {
        0 => block_size.min(bytes.len()) as u64,
        partial => partial as u64,
    };
    EntropyReport {
        block_size: parameters.block_size,
        whole_range: entropy(bytes),
        blocks,
        last_block_bytes,
        spans,
        suggested_block_size,
    }
}

struct Building {
    start: usize,
    end: usize,
    strings: usize,
    string_bytes: u64,
    previews: Vec<StringPreview>,
}

/// Groups one encoding's strings, in offset order, into clusters.
struct Clusterer<'a> {
    bytes: &'a [u8],
    offset: u64,
    encoding: StringEncoding,
    parameters: &'a LayoutParameters,
    current: Option<Building>,
    kept: Vec<StringCluster>,
    bound: ListBound,
    strings: usize,
}

impl<'a> Clusterer<'a> {
    fn new(bytes: &'a [u8], offset: u64, encoding: StringEncoding, parameters: &'a LayoutParameters) -> Self {
        Self {
            bytes,
            offset,
            encoding,
            parameters,
            current: None,
            kept: Vec::new(),
            bound: ListBound::default(),
            strings: 0,
        }
    }

    fn push(&mut self, start: usize, end: usize, characters: usize) {
        self.strings += 1;
        if let Some(current) = &self.current
            && (start - current.end) as u64 > self.parameters.cluster_gap
        {
            self.flush();
        }
        let wanted = self.current.as_ref().is_none_or(|current| current.previews.len() < PREVIEWS_PER_CLUSTER);
        let preview = wanted.then(|| self.preview(start, end, characters));
        match &mut self.current {
            Some(current) => {
                current.end = end;
                current.strings += 1;
                current.string_bytes += (end - start) as u64;
                current.previews.extend(preview);
            }
            None => {
                self.current = Some(Building {
                    start,
                    end,
                    strings: 1,
                    string_bytes: (end - start) as u64,
                    previews: preview.into_iter().collect(),
                });
            }
        }
    }

    fn preview(&self, start: usize, end: usize, characters: usize) -> StringPreview {
        let step = match self.encoding {
            StringEncoding::Ascii => 1,
            StringEncoding::Utf16Le => 2,
        };
        let text = self.bytes[start..end].iter().step_by(step).take(PREVIEW_CHARS).map(|&byte| char::from(byte));
        StringPreview {
            offset: self.offset + start as u64,
            length: (end - start) as u64,
            characters,
            text: text.collect(),
            truncated: characters > PREVIEW_CHARS,
        }
    }

    fn flush(&mut self) {
        let Some(building) = self.current.take() else { return };
        if building.strings < self.parameters.cluster_min_strings {
            return;
        }
        let length = (building.end - building.start) as u64;
        let cluster = StringCluster {
            offset: self.offset + building.start as u64,
            length,
            encoding: self.encoding,
            strings: building.strings,
            string_bytes: building.string_bytes,
            density: (building.string_bytes as f64 / length as f64 * 100.0).round() / 100.0,
            previews: building.previews,
        };
        let at = cluster.offset;
        record(&mut self.bound, &mut self.kept, self.parameters.cluster_limit, at, cluster);
    }

    fn finish(mut self) -> Self {
        self.flush();
        self
    }
}

fn ascii_strings(bytes: &[u8], minimum: usize, clusterer: &mut Clusterer) {
    let mut index = 0;
    while index < bytes.len() {
        if !is_printable(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_printable(bytes[index]) {
            index += 1;
        }
        if index - start >= minimum {
            clusterer.push(start, index, index - start);
        }
    }
}

fn utf16_strings(bytes: &[u8], parity: usize, minimum: usize, clusterer: &mut Clusterer) {
    let character = |index: usize| index + 1 < bytes.len() && is_printable(bytes[index]) && bytes[index + 1] == 0;
    let mut index = parity;
    while index + 1 < bytes.len() {
        if !character(index) {
            index += 2;
            continue;
        }
        let start = index;
        while character(index) {
            index += 2;
        }
        let characters = (index - start) / 2;
        if characters >= minimum {
            clusterer.push(start, index, characters);
        }
    }
}

fn clusters(
    bytes: &[u8],
    offset: u64,
    parameters: &LayoutParameters,
    summary: &mut LayoutSummary,
    bound: &mut ListBound,
) -> Vec<StringCluster> {
    let mut ascii = Clusterer::new(bytes, offset, StringEncoding::Ascii, parameters);
    ascii_strings(bytes, parameters.min_string_length, &mut ascii);
    let mut scans = vec![ascii.finish()];
    if parameters.utf16 {
        // Even and odd starts are separate streams, so each is in offset order.
        for parity in 0..2 {
            let mut wide = Clusterer::new(bytes, offset, StringEncoding::Utf16Le, parameters);
            utf16_strings(bytes, parity, parameters.min_string_length, &mut wide);
            scans.push(wide.finish());
        }
    }
    let mut kept = Vec::new();
    let mut next = None::<u64>;
    for scan in scans {
        summary.strings += scan.strings;
        bound.total += scan.bound.total;
        if let Some(at) = scan.bound.next_offset {
            next = Some(next.map_or(at, |next| next.min(at)));
        }
        kept.extend(scan.kept);
    }
    kept.sort_by_key(|cluster| (cluster.offset, cluster.encoding == StringEncoding::Utf16Le));
    if kept.len() > parameters.cluster_limit {
        let at = kept[parameters.cluster_limit].offset;
        next = Some(next.map_or(at, |next| next.min(at)));
    }
    // A prefix in offset order: nothing at or after the first omitted cluster is returned.
    if let Some(next) = next {
        kept.retain(|cluster| cluster.offset < next);
    }
    kept.truncate(parameters.cluster_limit);
    summary.string_clusters = bound.total;
    bound.returned = kept.len();
    bound.next_offset = next;
    kept
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

#[cfg(test)]
#[path = "file_layout_tests.rs"]
mod tests;
