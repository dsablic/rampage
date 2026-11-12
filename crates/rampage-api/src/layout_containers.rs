//! Header-checked compressed-component candidates for `file_layout`: a small header whose words are
//! self-consistent with the bytes after it. Generic structure only; no container format is recognised by name.

use std::collections::BTreeSet;

use rampage_analysis::triage::entropy;
use serde::Serialize;

use super::file_layout::LayoutHint;

/// The furthest a payload starts after a seed, in bytes.
const SEED_REACH: usize = 128;
/// The longest header, in bytes, that fields are looked for in.
const HEADER_WINDOW: usize = 64;
/// The smallest payload considered.
const MIN_PAYLOAD: u32 = 64;
/// Payload entropy, bits per byte, at or above which a payload reads as packed.
pub const PACKED_ENTROPY: f64 = 6.5;
/// The largest decoded-to-payload size ratio a decoded-size word may have.
const MAX_RATIO: u64 = 128;
/// Seeds examined in one call: region starts, the range start and the ends of payloads found.
const MAX_SEEDS: usize = 4096;
const SUM_BLOCK: usize = 32;
/// Payload bytes, from its start, whose entropy is measured.
const ENTROPY_SAMPLE: usize = 64 << 10;
/// Payload bytes CRC-32 is computed over in one call; past this, only byte sums are checked.
const MAX_CRC_BYTES: usize = 64 << 20;
/// The largest payload checked for a CRC-32 when its end is not at a boundary.
const MAX_UNBOUNDED_CRC_PAYLOAD: usize = 64 << 10;

/// One header word, with its file offset and value.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HeaderWord {
    pub offset: u64,
    pub value: u32,
}

/// A header word that equals a checksum of the payload.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ChecksumField {
    pub offset: u64,
    /// `byte_sum32` (32-bit wrapping sum of the payload bytes), `byte_sum16` (its low 16 bits, in a 16-bit
    /// field) or `crc32` (IEEE, as zlib computes it).
    pub kind: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
}

/// A header-checked compressed-component candidate. Field roles are inferred from consistency, never asserted.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerCandidate {
    /// The first header field matched; the header may start earlier.
    pub header_offset: u64,
    pub payload_offset: u64,
    pub payload_length: u64,
    /// Of the payload's first 64 KiB.
    pub payload_entropy_bits_per_byte: f64,
    /// `little` or `big`: the byte order of the matched words.
    pub byte_order: &'static str,
    /// The word that equals `payload_length`.
    pub size_field: HeaderWord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_field: Option<ChecksumField>,
    /// What the payload end coincides with: `range_end`, `fill_run`, `next_candidate` or `none`.
    pub payload_end: &'static str,
    /// Header words larger than the payload by at most 128:1: candidate decoded sizes for a decode or probe.
    pub decoded_size_candidates: Vec<HeaderWord>,
    /// The header window's other words, uninterpreted (a load address or flags may be among them).
    pub other_header_words: Vec<HeaderWord>,
    /// The names of the checks that passed.
    pub checks_passed: Vec<&'static str>,
}

/// Wrapping byte sums in blocks of [`SUM_BLOCK`] bytes, for the sum of any range in at most two partial blocks.
/// CRC-32 is computed per candidate payload, so its total input is capped per call.
struct Sums<'a> {
    bytes: &'a [u8],
    prefix: Vec<u32>,
    crc_budget: std::cell::Cell<usize>,
}

impl<'a> Sums<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        let mut prefix = Vec::with_capacity(bytes.len() / SUM_BLOCK + 1);
        let mut total = 0u32;
        prefix.push(0);
        for block in bytes.as_chunks::<SUM_BLOCK>().0 {
            total = block.iter().fold(total, |sum, &byte| sum.wrapping_add(u32::from(byte)));
            prefix.push(total);
        }
        Self { bytes, prefix, crc_budget: std::cell::Cell::new(MAX_CRC_BYTES) }
    }

    /// The CRC-32 of `start..end`, or `None` once the call's CRC budget is spent.
    fn crc32(&self, start: usize, end: usize) -> Option<u32> {
        let left = self.crc_budget.get().checked_sub(end - start)?;
        self.crc_budget.set(left);
        let mut crc = flate2::Crc::new();
        crc.update(&self.bytes[start..end]);
        Some(crc.sum())
    }

    fn up_to(&self, end: usize) -> u32 {
        let block = end / SUM_BLOCK;
        self.bytes[block * SUM_BLOCK..end]
            .iter()
            .fold(self.prefix[block], |sum, &byte| sum.wrapping_add(u32::from(byte)))
    }

    fn range(&self, start: usize, end: usize) -> u32 {
        self.up_to(end).wrapping_sub(self.up_to(start))
    }
}

fn read(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let word: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if big { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) })
}

fn read16(bytes: &[u8], at: usize, big: bool) -> Option<u16> {
    let half: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(if big { u16::from_be_bytes(half) } else { u16::from_le_bytes(half) })
}

/// Candidates in `bytes` (read from file `offset`). `seeds` are range-relative offsets where a header may start
/// (region starts); `fill_starts` are the range-relative starts of fill runs.
pub(crate) fn candidates(
    bytes: &[u8],
    offset: u64,
    seeds: &[usize],
    fill_starts: &BTreeSet<usize>,
) -> Vec<ContainerCandidate> {
    let sums = Sums::new(bytes);
    // A header may start exactly at a region start or at the aligned word holding it.
    let mut queue: Vec<usize> = seeds.iter().flat_map(|&seed| [seed & !3, seed]).collect();
    queue.push(0);
    let mut seen = BTreeSet::new();
    let mut found: Vec<ContainerCandidate> = Vec::new();
    let mut covered = 0usize;
    while let Some(seed) = queue.pop() {
        if seen.len() >= MAX_SEEDS {
            break;
        }
        if !seen.insert(seed) || seed < covered && found.iter().any(|c| inside(c, offset, seed)) {
            continue;
        }
        if let Some(candidate) = at_seed(bytes, offset, seed, &sums, fill_starts) {
            let end = (candidate.payload_offset + candidate.payload_length - offset) as usize;
            covered = covered.max(end);
            // A following component may start at the payload end or the next aligned offset.
            queue.extend([end, (end + 3) & !3, (end + 15) & !15]);
            found.push(candidate);
        }
    }
    found.sort_by_key(|candidate| candidate.header_offset);
    found.dedup_by_key(|candidate| candidate.payload_offset);
    // A payload that ends where the next candidate's header starts is chained to it.
    let starts: BTreeSet<u64> = found.iter().map(|candidate| candidate.header_offset).collect();
    for candidate in &mut found {
        let end = candidate.payload_offset + candidate.payload_length;
        if candidate.payload_end == "none" && starts.range(end..end.saturating_add(16)).next().is_some() {
            candidate.payload_end = "next_candidate";
            candidate.checks_passed.push("payload_end_at_next_candidate");
        }
    }
    found
}

fn inside(candidate: &ContainerCandidate, offset: u64, at: usize) -> bool {
    let at = offset + at as u64;
    at > candidate.header_offset && at < candidate.payload_offset + candidate.payload_length
}

/// The best candidate whose payload starts within [`SEED_REACH`] bytes after `seed`: one with a verified
/// checksum, else one whose packed payload ends at a boundary and whose header has a decoded-size word.
fn at_seed(
    bytes: &[u8],
    offset: u64,
    seed: usize,
    sums: &Sums,
    fill_starts: &BTreeSet<usize>,
) -> Option<ContainerCandidate> {
    let mut best: Option<(u8, ContainerCandidate)> = None;
    for big in [false, true] {
        for payload in (seed + 8..=seed + SEED_REACH).step_by(4) {
            if payload >= bytes.len() {
                break;
            }
            let window = payload.saturating_sub(HEADER_WINDOW).max(seed);
            for size_at in (window..payload).step_by(4) {
                let Some(size) = read(bytes, size_at, big) else { continue };
                if size < MIN_PAYLOAD || size as usize > bytes.len() - payload {
                    continue;
                }
                let end = payload + size as usize;
                let boundary = if end == bytes.len() {
                    "range_end"
                } else if fill_starts.range(end..end + 16).next().is_some() {
                    "fill_run"
                } else {
                    "none"
                };
                // CRC-32 costs a pass over the payload, so only payloads that end at a boundary or are small get one.
                let try_crc = boundary != "none" || size as usize <= MAX_UNBOUNDED_CRC_PAYLOAD;
                let checksum = checksum(bytes, offset, window, payload, size_at, end, sums, big, try_crc);
                if checksum.is_none() && boundary == "none" {
                    continue;
                }
                let mut decoded = Vec::new();
                let mut others = Vec::new();
                for at in (window..payload).step_by(4).filter(|&at| at != size_at) {
                    let Some(value) = read(bytes, at, big) else { continue };
                    if checksum.is_some_and(|field| field.offset == offset + at as u64) {
                        continue;
                    }
                    let word = HeaderWord { offset: offset + at as u64, value };
                    if u64::from(value) > u64::from(size) && u64::from(value) <= u64::from(size) * MAX_RATIO {
                        decoded.push(word);
                    } else {
                        others.push(word);
                    }
                }
                // Without a checksum, a boundary alone is too common: a decoded-size word comes first, as it is cheap.
                if checksum.is_none() && decoded.is_empty() {
                    continue;
                }
                let packed = entropy(&bytes[payload..end.min(payload + ENTROPY_SAMPLE)]);
                let packed_ok = packed >= PACKED_ENTROPY;
                // A 16-bit sum matches by chance too often to stand alone.
                if checksum.is_some_and(|field| field.kind == "byte_sum16") && boundary == "none" && !packed_ok {
                    continue;
                }
                // Without a checksum, a boundary alone is too common: also need packed bytes and a decoded size.
                if checksum.is_none() && !(packed_ok && !decoded.is_empty()) {
                    continue;
                }
                let mut checks = vec!["size_field_within_range"];
                if checksum.is_some() {
                    checks.push("checksum_verified_over_payload");
                }
                if boundary != "none" {
                    checks.push(if boundary == "range_end" {
                        "payload_end_at_range_end"
                    } else {
                        "payload_end_at_fill_run"
                    });
                }
                if packed_ok {
                    checks.push("payload_entropy_packed");
                }
                if !decoded.is_empty() {
                    checks.push("decoded_size_word_present");
                }
                let rank = u8::from(checksum.is_some()) * 4 + u8::from(boundary != "none") * 2 + u8::from(packed_ok);
                let header =
                    checksum.map_or(size_at as u64 + offset, |field| field.offset.min(offset + size_at as u64));
                let candidate = ContainerCandidate {
                    header_offset: header,
                    payload_offset: offset + payload as u64,
                    payload_length: u64::from(size),
                    payload_entropy_bits_per_byte: (packed * 100.0).round() / 100.0,
                    byte_order: if big { "big" } else { "little" },
                    size_field: HeaderWord { offset: offset + size_at as u64, value: size },
                    checksum_field: checksum,
                    payload_end: boundary,
                    decoded_size_candidates: decoded,
                    other_header_words: others,
                    checks_passed: checks,
                };
                if best.as_ref().is_none_or(|(kept, _)| rank > *kept) {
                    best = Some((rank, candidate));
                }
            }
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// A header word in `window..payload`, other than the size word, equal to a checksum of `payload..end`.
/// Words are read at the size word's alignment; 16-bit sums at every even offset from it. A 32-bit sum is
/// preferred to a CRC-32 and both to a 16-bit sum, which is weaker evidence.
#[allow(clippy::too_many_arguments)]
fn checksum(
    bytes: &[u8],
    offset: u64,
    window: usize,
    payload: usize,
    size_at: usize,
    end: usize,
    sums: &Sums,
    big: bool,
    try_crc: bool,
) -> Option<ChecksumField> {
    let sum = sums.range(payload, end);
    let fields = || (window..payload).step_by(2).filter(|&at| at + 4 <= size_at || at >= size_at + 4);
    let field = |at: usize, kind, value: u32| ChecksumField { offset: offset + at as u64, kind, value: value.into() };
    let word_equal = |value: u32| {
        fields()
            .filter(|&at| (at - window).is_multiple_of(4))
            .find(|&at| read(bytes, at, big) == Some(value))
    };
    if sum > 0xffff
        && let Some(at) = word_equal(sum)
    {
        return Some(field(at, "byte_sum32", sum));
    }
    if try_crc
        && let Some(crc) = sums.crc32(payload, end)
        && let Some(at) = word_equal(crc)
    {
        return Some(field(at, "crc32", crc));
    }
    fields()
        .find(|&at| at + 2 <= payload && read16(bytes, at, big) == Some(sum as u16) && sum as u16 > 0xff)
        .map(|at| field(at, "byte_sum16", u32::from(sum as u16)))
}

/// The layout hint for a candidate.
pub(crate) fn hint(candidate: ContainerCandidate) -> LayoutHint {
    let mut evidence = vec![
        "header-checked compressed-component candidate: header words are consistent with the bytes after them"
            .to_owned(),
        format!(
            "{}-endian word at {:#x} equals the {}-byte payload length from {:#x}",
            candidate.byte_order, candidate.size_field.offset, candidate.payload_length, candidate.payload_offset
        ),
    ];
    if let Some(field) = &candidate.checksum_field {
        evidence.push(format!("word at {:#x} equals the payload's {} {:#x}", field.offset, field.kind, field.value));
    }
    match candidate.payload_end {
        "none" => {}
        end => evidence.push(format!("the payload ends at a boundary ({end})")),
    }
    evidence.push(format!("payload entropy {:.2} bits/byte", candidate.payload_entropy_bits_per_byte));
    if let Some(word) = candidate.decoded_size_candidates.first() {
        evidence.push(format!(
            "word at {:#x} ({}) is a candidate decoded size for probe_compression or decode_file_range",
            word.offset, word.value
        ));
    }
    LayoutHint {
        kind: "compressed_component_candidate",
        offset: candidate.header_offset,
        evidence,
        cortex_m: None,
        container: Some(candidate),
    }
}

#[cfg(test)]
#[path = "layout_containers_tests.rs"]
mod tests;
