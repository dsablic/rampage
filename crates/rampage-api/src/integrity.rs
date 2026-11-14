//! `integrity_checks`: checksum, CRC and digest fields that protect an image, the ranges they cover, whether they
//! still hold after byte patches, and corrected values written as further patches.
//!
//! Checks are found in the original (unpatched) image, where a stored value matches by construction; the
//! effective (patched) image is then measured against each one. Evidence: a bounded brute-force match of every
//! algorithm over candidate ranges against candidate stored-value locations; code that holds CRC tables or
//! polynomials and the addresses it and its callers reference; optionally the image's own routine run by
//! `evaluate_function` over the range.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use rampage_analysis::discover::XrefKind;
use rampage_loaders::{Binary, Format};
use serde::Serialize;
use serde_json::Value;

use crate::evaluate::{EvaluateArgument, EvaluateRequest, IntegerText, StopReason};
use crate::{ApiError, PatchReceipt, Project, XrefQuery};

mod algorithms;
#[cfg(test)]
mod tests;

pub use algorithms::{ALL as ALGORITHMS, Algorithm};

/// Mapped blocks searched; further ones are reported, not searched.
const MAX_BLOCKS: usize = 16;
/// Shortest run of 0x00 or 0xff bytes treated as padding between parts of an image.
const MIN_FILL_RUN: usize = 32;
const MAX_FILL_RUNS: usize = 16;
/// Header words read as stored-value candidates at the start of each block and after each padding run.
const HEADER_WORDS: u64 = 16;
const MAX_CODE_CONSTANTS: usize = 64;
/// Range starts per block and width, in priority order.
const MAX_STARTS: usize = 32;
/// Shortest range considered.
const MIN_RANGE: u64 = 16;
/// Shortest range for an algorithm that is not strong (a 16- or 8-bit value, a sum or an XOR).
const MIN_WEAK_RANGE: u64 = 64;
/// Bytes fed to all algorithms together before the search stops.
pub const SEARCH_BUDGET_BYTES: u64 = 256 << 20;
const MAX_MATCHES: usize = 4096;
/// Value lookups (one per range end and algorithm) before the search stops, independent of the byte budget.
pub const SEARCH_LOOKUP_BUDGET: u64 = 1 << 22;
const MAX_CHECKS: usize = 32;
const MAX_EMULATIONS: usize = 4;
const MAX_EMULATED_RANGE: u64 = 64 * 1024;
const MAX_ROUTINES: usize = 8;

/// What `integrity_checks` does besides reporting.
#[derive(Debug, Clone, Default)]
pub struct IntegrityRequest {
    /// Run the image's own CRC routine over a matched range with evaluate_function to confirm it.
    pub emulate: bool,
    /// Write corrected stored values for invalid checks as byte patches.
    pub fix: bool,
    /// Only these check ids (default: every invalid check of medium or high confidence).
    pub ids: Vec<usize>,
    pub source_sha256: Option<String>,
    pub expected_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredField {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: usize,
    /// `little`, `big`, or `bytes` for a one-byte value or a digest.
    pub endian: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CoveredRange {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityCheck {
    pub id: usize,
    pub algorithm: &'static str,
    pub parameters: Value,
    /// `memory` (addresses) or `file` (file offsets: the PE header checksum).
    pub space: &'static str,
    pub stored: StoredField,
    pub ranges: Vec<CoveredRange>,
    /// Hex of the stored bytes in the effective (patched) image, as they lie in memory.
    pub stored_hex: String,
    /// Hex of the value computed over the effective image, in the stored byte order.
    pub computed_hex: String,
    pub valid: bool,
    pub confidence: &'static str,
    pub score: f64,
    pub confirmed_by_emulation: bool,
    pub evidence: Vec<String>,
    /// Checks whose stored value lies inside this check's range: they are fixed first.
    pub depends_on: Vec<usize>,
    /// Other ranges or algorithms that matched the same stored value less well.
    pub alternatives: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutineRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub algorithms: Vec<&'static str>,
    pub evidence: Vec<String>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub callers: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchedBlock {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchStats {
    pub blocks: Vec<SearchedBlock>,
    pub blocks_omitted: usize,
    pub algorithms: usize,
    pub candidate_fields: usize,
    pub range_starts: usize,
    pub bytes_hashed: u64,
    pub budget_bytes: u64,
    /// Computed values looked up among the candidate stored values.
    pub lookups: u64,
    pub lookup_budget: u64,
    /// Work items skipped because the byte or lookup budget ran out; matches may be missing when true.
    pub budget_exhausted: bool,
    pub skipped_items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixWrite {
    pub check: usize,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub current_hex: String,
    pub replacement_hex: String,
    /// `patch` (a patch record over the original bytes), `revert` (the original bytes are correct again) or
    /// `unsupported` with the reason in `detail`.
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixReport {
    pub applied: bool,
    pub writes: Vec<FixWrite>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityReport {
    pub checks: Vec<IntegrityCheck>,
    pub checks_total: usize,
    pub invalid: usize,
    pub routines: Vec<RoutineRow>,
    pub search: SearchStats,
    /// Writes that would correct (preview) or corrected (applied) the invalid checks, in dependency order.
    pub fix: FixReport,
    /// The patch receipt to review a fix or an export with, when the image takes patches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<PatchReceipt>,
    pub notes: Vec<String>,
}

/// The report, the effective project after any fix, and the annotation transition a fix made.
pub struct IntegrityOutcome {
    pub report: IntegrityReport,
    pub project: Arc<Project>,
    pub transition: Option<(Arc<()>, Arc<()>)>,
}

// ---------------------------------------------------------------------------------------------------------------
// Image blocks

/// One contiguous run of mapped bytes the search reads.
struct Block<'a> {
    name: String,
    start: u64,
    bytes: &'a [u8],
    /// End of the bytes before trailing 0x00/0xff padding.
    content_end: u64,
    /// Interior padding runs `[start, end)`.
    fills: Vec<(u64, u64)>,
}

impl<'a> Block<'a> {
    fn new(name: String, start: u64, bytes: &'a [u8]) -> Self {
        let fill = |byte: u8| byte == 0 || byte == 0xff;
        let content = match bytes.last() {
            Some(&last) if fill(last) => bytes.iter().rposition(|&byte| byte != last).map_or(0, |index| index + 1),
            _ => bytes.len(),
        };
        let mut fills = Vec::new();
        let mut at = 0;
        while at < content && fills.len() < MAX_FILL_RUNS {
            if !fill(bytes[at]) {
                at += 1;
                continue;
            }
            let run = bytes[at..content].iter().take_while(|&&byte| byte == bytes[at]).count();
            if run >= MIN_FILL_RUN && at > 0 {
                fills.push((start + at as u64, start + (at + run) as u64));
            }
            at += run;
        }
        Block { name, start, bytes, content_end: start + content as u64, fills }
    }

    fn end(&self) -> u64 {
        self.start + self.bytes.len() as u64
    }

    fn slice(&self, start: u64, end: u64) -> &[u8] {
        &self.bytes[(start - self.start) as usize..(end - self.start) as usize]
    }
}

/// The mapped bytes of `binary` as blocks: a Raw project's backed regions (its RAM regions too), or a native
/// image's file-backed readable segments, ascending and without overlaps.
fn blocks(binary: &Binary) -> (Vec<Block<'_>>, usize) {
    let mut found: Vec<(String, u64, &[u8])> = Vec::new();
    if let Some(raw) = binary.raw_code_image() {
        for region in raw.regions().iter().filter(|region| region.backed()) {
            found.push((region.name.clone(), region.base_address, &binary.image_bytes()[region.data_range()]));
        }
    } else {
        for segment in binary.segments.iter().filter(|segment| segment.perms.read && segment.file_size > 0) {
            if let Some(bytes) = binary.read(segment.address, segment.file_size) {
                found.push((segment.name.clone(), segment.address, bytes));
            }
        }
    }
    found.sort_by_key(|(_, start, _)| *start);
    let mut blocks: Vec<Block> = Vec::new();
    let mut omitted = 0;
    for (name, start, bytes) in found {
        if bytes.is_empty() || blocks.last().is_some_and(|last| last.end() > start) {
            continue;
        }
        if blocks.len() == MAX_BLOCKS {
            omitted += 1;
            continue;
        }
        blocks.push(Block::new(name, start, bytes));
    }
    (blocks, omitted)
}

fn read<'a>(blocks: &'a [Block], start: u64, end: u64) -> Option<&'a [u8]> {
    let block = blocks.iter().find(|block| block.start <= start && end <= block.end())?;
    Some(block.slice(start, end))
}

fn erased(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0) || bytes.iter().all(|&byte| byte == 0xff)
}

fn uniform(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == bytes[0])
}

// ---------------------------------------------------------------------------------------------------------------
// Code evidence

/// CRC families code can reveal, with the algorithms each admits.
fn family_algorithms(family: &str) -> &'static [Algorithm] {
    match family {
        "crc32-reflected" => &[Algorithm::Crc32, Algorithm::Crc32Jamcrc],
        "crc32c" => &[Algorithm::Crc32c],
        "crc32-msb-first" => &[Algorithm::Crc32Bzip2, Algorithm::Crc32Mpeg2, Algorithm::Crc32Mpeg2Words],
        "crc16-arc" => &[Algorithm::Crc16Arc, Algorithm::Crc16Modbus],
        "crc16-ccitt" => &[Algorithm::Crc16CcittFalse, Algorithm::Crc16Xmodem],
        _ => &[],
    }
}

/// 32-bit polynomial words a table-less CRC loop loads, and their family.
const POLYNOMIALS: [(u32, &str); 4] = [
    (0xedb8_8320, "crc32-reflected"),
    (0x04c1_1db7, "crc32-msb-first"),
    (0x82f6_3b78, "crc32c"),
    (0x1edc_6f41, "crc32c"),
];

struct Routine {
    address: u64,
    name: Option<String>,
    families: BTreeSet<&'static str>,
    evidence: Vec<String>,
    callers: Vec<u64>,
    /// Image addresses this routine and its callers reference or load as constants.
    constants: BTreeSet<u64>,
}

impl Routine {
    fn admits(&self, algorithm: Algorithm) -> bool {
        self.families.iter().any(|family| family_algorithms(family).contains(&algorithm))
    }
}

#[derive(Default)]
struct CodeEvidence {
    routines: Vec<Routine>,
    /// Image addresses the routines and their callers reference or load as constants.
    constants: BTreeSet<u64>,
}

fn word_at(bytes: &[u8], big_endian: bool) -> u32 {
    let word: [u8; 4] = bytes[..4].try_into().expect("word");
    if big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) }
}

/// Aligned words in the blocks equal to `value`: literal-pool slots holding a constant.
fn slots_holding(blocks: &[Block], value: u32, big_endian: bool, cap: usize) -> Vec<u64> {
    let mut slots = Vec::new();
    for block in blocks {
        let skew = (4 - block.start % 4) % 4;
        let mut at = skew as usize;
        while at + 4 <= block.bytes.len() && slots.len() < cap {
            if word_at(&block.bytes[at..], big_endian) == value {
                slots.push(block.start + at as u64);
            }
            at += 4;
        }
    }
    slots
}

/// 32-bit constants Thumb-2 code forms with a MOVW then a MOVT of the same register at most 64 bytes later:
/// (address of the MOVT, value). Little-endian halfwords; every halfword position is tried.
fn thumb_wide_constants(bytes: &[u8], base: u64) -> Vec<(u64, u32)> {
    let mut found = Vec::new();
    let mut low: [Option<(usize, u32)>; 16] = [None; 16];
    let halfword = |at: usize| u32::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
    let mut at = (base % 2) as usize;
    while at + 4 <= bytes.len() {
        let (first, second) = (halfword(at), halfword(at + 2));
        let kind = first & 0xfbf0;
        if (kind == 0xf240 || kind == 0xf2c0) && second & 0x8000 == 0 {
            let register = ((second >> 8) & 0xf) as usize;
            let value =
                ((first & 0xf) << 12) | (((first >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0xff);
            if kind == 0xf240 {
                low[register] = Some((at, value));
            } else if let Some((movw, low_half)) = low[register].take()
                && at - movw <= 64
            {
                found.push((base + at as u64, (value << 16) | low_half));
            }
        }
        at += 2;
    }
    found
}

fn code_evidence(project: &Project, blocks: &[Block], notes: &mut Vec<String>) -> CodeEvidence {
    let mut evidence = CodeEvidence::default();
    if let Err(error) = project.analysis() {
        notes.push(format!("no code evidence: analysis unavailable ({error})"));
        return evidence;
    }
    let big_endian = project.binary.big_endian;
    // (address the code references, family, what it is)
    let mut anchors: Vec<(u64, &'static str, String)> = Vec::new();
    let scan = rampage_constants::scan_binary_report(&project.binary, rampage_constants::ConstantDb::bundled());
    for hit in scan.hits.iter().filter(|hit| hit.algorithm.starts_with("CRC") && hit.complete) {
        let family = match hit.what.as_ref() {
            what if what.contains("0xEDB88320") => "crc32-reflected",
            what if what.contains("0x82F63B78") => "crc32c",
            what if what.contains("0x04C11DB7") => "crc32-msb-first",
            what if what.contains("0xA001") => "crc16-arc",
            what if what.contains("0x1021") => "crc16-ccitt",
            _ => continue,
        };
        anchors.push((hit.address, family, format!("{} at {:#x}", hit.what, hit.address)));
        for slot in slots_holding(blocks, hit.address as u32, big_endian, 8) {
            anchors.push((slot, family, format!("pointer to {} at {:#x}", hit.what, hit.address)));
        }
    }
    for (value, family) in POLYNOMIALS {
        for slot in slots_holding(blocks, value, big_endian, 8) {
            anchors.push((slot, family, format!("polynomial {value:#010x} literal at {slot:#x}")));
        }
    }
    // (referencing instruction, family, what): xrefs to each anchor, and polynomials Thumb code forms in a register
    // with a movw/movt pair, which leave no literal to reference.
    let mut sites: Vec<(u64, &'static str, String)> = Vec::new();
    for (address, family, what) in anchors.into_iter().take(64) {
        let Ok(page) = project.xrefs(XrefQuery::To(address), None, Some(64)) else { continue };
        sites.extend(page.items.iter().map(|row| (row.from, family, what.clone())));
    }
    if !project.binary.thumb.is_empty() && !project.binary.big_endian {
        for block in blocks {
            for (site, value) in thumb_wide_constants(block.bytes, block.start) {
                if let Some(&(_, family)) = POLYNOMIALS.iter().find(|(polynomial, _)| *polynomial == value)
                    && project.binary.thumb.iter().any(|range| range.contains(&site))
                {
                    sites.push((site, family, format!("polynomial {value:#010x} formed by movw/movt")));
                }
            }
        }
    }
    let mut routines: BTreeMap<u64, Routine> = BTreeMap::new();
    for (site, family, what) in sites.into_iter().take(128) {
        let Ok(Some(function)) = project.function_containing(site) else { continue };
        if routines.len() == MAX_ROUTINES && !routines.contains_key(&function) {
            continue;
        }
        let routine = routines.entry(function).or_insert_with(|| Routine {
            address: function,
            name: Some(project.function_name(function)),
            families: BTreeSet::new(),
            evidence: Vec::new(),
            callers: Vec::new(),
            constants: BTreeSet::new(),
        });
        routine.families.insert(family);
        let line = format!("{what} at {site:#x}");
        if routine.evidence.len() < 8 && !routine.evidence.contains(&line) {
            routine.evidence.push(line);
        }
    }
    let in_image = |address: u64| blocks.iter().any(|block| block.start <= address && address <= block.end());
    for routine in routines.values_mut() {
        if let Ok(page) = project.xrefs(XrefQuery::To(routine.address), None, Some(64)) {
            for row in page.items.iter().filter(|row| row.kind == XrefKind::Call) {
                if let Ok(Some(caller)) = project.function_containing(row.from)
                    && !routine.callers.contains(&caller)
                    && routine.callers.len() < 8
                {
                    routine.callers.push(caller);
                }
            }
        }
        for function in std::iter::once(routine.address).chain(routine.callers.iter().copied()) {
            let Ok(page) = project.xrefs(XrefQuery::From(function), None, Some(512)) else { continue };
            for row in page.items.iter().filter(|row| row.kind == XrefKind::Data) {
                let mut values = vec![row.to];
                if let Some(bytes) = read(blocks, row.to, row.to + 4).filter(|_| row.to.is_multiple_of(4)) {
                    values.push(u64::from(word_at(bytes, big_endian)));
                }
                for value in values.into_iter().filter(|&value| in_image(value)) {
                    if evidence.constants.len() < MAX_CODE_CONSTANTS {
                        evidence.constants.insert(value);
                    }
                    if routine.constants.len() < MAX_CODE_CONSTANTS {
                        routine.constants.insert(value);
                    }
                }
            }
        }
    }
    evidence.routines = routines.into_values().collect();
    evidence
}

// ---------------------------------------------------------------------------------------------------------------
// Brute-force search

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    /// From the image's layout: a block or content end, a padding boundary or a header word.
    Layout,
    /// An address code references.
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
    Bytes,
}

impl Endian {
    fn name(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
            Endian::Bytes => "bytes",
        }
    }

    /// The stored bytes of a value computed little-endian.
    fn encode(self, value: &[u8]) -> Vec<u8> {
        match self {
            Endian::Big => value.iter().rev().copied().collect(),
            _ => value.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
struct Match {
    algorithm: Algorithm,
    field: u64,
    endian: Endian,
    range: (u64, u64),
    field_origin: Origin,
    bounds_from_code: bool,
    adjacent: bool,
}

struct Search<'a> {
    blocks: &'a [Block<'a>],
    big_endian: bool,
    constants: &'a BTreeSet<u64>,
    stats: SearchStats,
    matches: Vec<Match>,
}

/// Stored-value candidates of one width: address and origin.
fn fields(blocks: &[Block], constants: &BTreeSet<u64>, width: usize) -> BTreeMap<u64, Origin> {
    let width = width as u64;
    let align = width.min(4);
    let mut fields = BTreeMap::new();
    for block in blocks {
        let mut add = |address: u64, origin: Origin| {
            let fits = address >= block.start && address + width <= block.end() && address.is_multiple_of(align);
            if fits && !erased(block.slice(address, address + width)) {
                let entry = fields.entry(address).or_insert(origin);
                *entry = (*entry).min(origin);
            }
        };
        let mut ends = vec![block.end(), block.content_end];
        ends.extend(block.fills.iter().map(|&(start, _)| start));
        for end in ends {
            // The value ends there, aligned down to its own width.
            if let Some(field) = end.checked_sub(width) {
                add(field - field % align, Origin::Layout);
            }
        }
        let mut headers = vec![block.start];
        headers.extend(block.fills.iter().map(|&(_, end)| end));
        for header in headers {
            for word in 0..HEADER_WORDS {
                add(header + 4 * word, Origin::Layout);
            }
        }
        for &constant in constants.range(block.start..block.end()) {
            add(constant, Origin::Code);
        }
    }
    fields
}

impl Search<'_> {
    fn run(&mut self, algorithms: &[Algorithm]) {
        let mut items: Vec<(u8, usize, usize, u64, u64)> = Vec::new(); // (tier, algorithm, block, start, cost)
        let mut fields_by_width: HashMap<usize, BTreeMap<u64, Origin>> = HashMap::new();
        for &algorithm in algorithms {
            fields_by_width
                .entry(algorithm.width())
                .or_insert_with(|| fields(self.blocks, self.constants, algorithm.width()));
        }
        self.stats.candidate_fields = fields_by_width.values().map(BTreeMap::len).sum();
        // Candidate stored values by their bytes as a little-endian computation would produce them, so each
        // computed value is one lookup however many candidates there are.
        let mut indexes: HashMap<usize, ValueIndex> = HashMap::new();
        for (&width, fields) in &fields_by_width {
            let mut index = ValueIndex::new();
            for &field in fields.keys() {
                let Some(stored) = read(self.blocks, field, field + width as u64) else { continue };
                if width == 1 || width > 8 {
                    index.entry(stored.to_vec()).or_default().push((field, Endian::Bytes));
                } else {
                    index.entry(stored.to_vec()).or_default().push((field, Endian::Little));
                    index.entry(stored.iter().rev().copied().collect()).or_default().push((field, Endian::Big));
                }
            }
            indexes.insert(width, index);
        }
        let mut starts_total = 0;
        for (index, &algorithm) in algorithms.iter().enumerate() {
            let fields = &fields_by_width[&algorithm.width()];
            for (block_index, block) in self.blocks.iter().enumerate() {
                let mut starts: Vec<(u8, u64)> = vec![(0, block.start)];
                starts.extend(block.fills.iter().map(|&(_, end)| (0, end)));
                starts.extend(self.constants.range(block.start..block.end()).map(|&constant| (1, constant)));
                // A header value covering what follows it.
                starts.extend(
                    fields
                        .range(block.start..block.end())
                        .filter(|(_, origin)| **origin == Origin::Layout)
                        .map(|(&field, _)| (2, field + algorithm.width() as u64))
                        .filter(|&(_, start)| {
                            start <= block.start + 4 * HEADER_WORDS + 4
                                || block
                                    .fills
                                    .iter()
                                    .any(|&(_, end)| (end..end + 4 * HEADER_WORDS + 4).contains(&start))
                        }),
                );
                starts.sort();
                starts.dedup_by_key(|(_, start)| *start);
                starts.retain(|&(_, start)| start + MIN_RANGE <= block.end());
                starts.truncate(MAX_STARTS);
                starts_total += starts.len();
                for (tier, start) in starts {
                    items.push((tier, index, block_index, start, block.end() - start));
                }
            }
        }
        self.stats.range_starts = starts_total;
        items.sort_by_key(|&(tier, algorithm, block, start, _)| (tier, algorithm, block, start));
        for (_, algorithm, block, start, cost) in items {
            if self.stats.bytes_hashed + cost > self.stats.budget_bytes {
                self.stats.budget_exhausted = true;
                self.stats.skipped_items += 1;
                continue;
            }
            self.stats.bytes_hashed += cost;
            let algorithm = algorithms[algorithm];
            let width = algorithm.width();
            self.stream(algorithm, &self.blocks[block], start, &fields_by_width[&width], &indexes[&width]);
        }
    }

    /// Feeds `block` from `start` to its end through `algorithm`, comparing the value at every candidate range end
    /// with the candidate stored values.
    fn stream(
        &mut self,
        algorithm: Algorithm,
        block: &Block,
        start: u64,
        fields: &BTreeMap<u64, Origin>,
        index: &ValueIndex,
    ) {
        let width = algorithm.width() as u64;
        let mut ends: BTreeSet<u64> = BTreeSet::new();
        ends.extend([block.end(), block.content_end]);
        ends.extend(block.fills.iter().map(|&(fill, _)| fill));
        ends.extend(self.constants.range(block.start..=block.end()).copied());
        ends.extend(fields.range(block.start..block.end()).map(|(&field, _)| field));
        let layout_start = start == block.start || block.fills.iter().any(|&(_, fill)| fill == start);
        let mut state = algorithm.start(self.big_endian);
        let mut at = start;
        for end in ends.into_iter().filter(|&end| end >= start + MIN_RANGE) {
            state.update(block.slice(at, end));
            at = end;
            // A weak value sits right after or right before a range of at least MIN_WEAK_RANGE bytes whose far end
            // is a layout boundary; a strong one may sit anywhere outside its range.
            let layout_end =
                end == block.end() || end == block.content_end || block.fills.iter().any(|&(fill, _)| fill == end);
            if !algorithm.strong() && (end - start < MIN_WEAK_RANGE || !(layout_start || layout_end)) {
                continue;
            }
            if self.stats.lookups >= self.stats.lookup_budget {
                self.stats.budget_exhausted = true;
                self.stats.skipped_items += 1;
                return;
            }
            self.stats.lookups += 1;
            let Some(value) = state.value() else { continue };
            let Some(hits) = index.get(&value) else { continue };
            for &(field, endian) in hits {
                let admitted = if algorithm.strong() {
                    field + width <= start || field >= end
                } else {
                    (field == end && layout_start) || (field + width == start && layout_end)
                };
                if !admitted || uniform(block.slice(start, end)) {
                    continue;
                }
                let in_code = |address: u64| self.constants.contains(&address);
                self.matches.push(Match {
                    algorithm,
                    field,
                    endian,
                    range: (start, end),
                    field_origin: fields[&field],
                    bounds_from_code: in_code(start) || in_code(end),
                    adjacent: field == end || field + width == start,
                });
                if self.matches.len() >= MAX_MATCHES {
                    return;
                }
            }
        }
    }
}

/// Candidate stored values keyed by their bytes in little-endian computation order: (address, byte order).
type ValueIndex = HashMap<Vec<u8>, Vec<(u64, Endian)>>;

// ---------------------------------------------------------------------------------------------------------------
// Checks

/// One check as found: what it computes, over what, stored where.
#[derive(Debug, Clone)]
struct Found {
    algorithm: Option<Algorithm>,
    field: u64,
    endian: Endian,
    range: (u64, u64),
    score: f64,
    emulated: bool,
    /// Code references the stored value or a range bound.
    code_bound: bool,
    evidence: Vec<String>,
    alternatives: usize,
}

fn base_score(algorithm: Algorithm) -> f64 {
    match algorithm {
        Algorithm::Sha256 | Algorithm::Md5 => 0.7,
        algorithm if algorithm.strong() && algorithm.crc().is_some() => 0.55,
        algorithm if algorithm.strong() => 0.45,
        algorithm if algorithm.crc().is_some_and(|crc| crc.width == 16) => 0.3,
        Algorithm::Fletcher16 => 0.25,
        _ => 0.2,
    }
}

fn confidence(score: f64) -> &'static str {
    if score >= 0.75 {
        "high"
    } else if score >= 0.5 {
        "medium"
    } else {
        "low"
    }
}

fn score_match(found: &Match, code: &CodeEvidence) -> (f64, Vec<String>) {
    let (start, end) = found.range;
    let mut evidence = vec![format!(
        "brute force: the {} of {start:#x}..{end:#x} in the original image equals the {} value stored at {:#x}",
        found.algorithm.name(),
        found.endian.name(),
        found.field
    )];
    let mut score = base_score(found.algorithm);
    if found.adjacent {
        score += 0.1;
    }
    // A routine counts only when it (or a caller) references this check's value or range.
    let referenced =
        |routine: &&Routine| [found.field, start, end].iter().any(|address| routine.constants.contains(address));
    if let Some(routine) = code.routines.iter().filter(referenced).find(|routine| routine.admits(found.algorithm)) {
        score += 0.2;
        evidence.push(format!(
            "code: {} at {:#x} holds {} constants ({})",
            routine.name.as_deref().unwrap_or("routine"),
            routine.address,
            routine.families.iter().copied().collect::<Vec<_>>().join(", "),
            routine.evidence.first().map_or("", String::as_str)
        ));
    }
    if found.field_origin == Origin::Code || found.bounds_from_code {
        score += 0.1;
        let mut referenced: Vec<String> = [found.field, start, end]
            .into_iter()
            .filter(|address| code.constants.contains(address))
            .map(|address| format!("{address:#x}"))
            .collect();
        referenced.dedup();
        evidence.push(format!("code: the CRC routine or its callers reference {}", referenced.join(", ")));
    }
    (score.min(0.95), evidence)
}

/// One best match per stored value; the others count as its alternatives.
fn select(matches: Vec<Match>, code: &CodeEvidence) -> Vec<Found> {
    let mut by_field: BTreeMap<u64, Vec<(f64, Vec<String>, Match)>> = BTreeMap::new();
    for found in matches {
        let (score, evidence) = score_match(&found, code);
        by_field.entry(found.field).or_default().push((score, evidence, found));
    }
    let mut checks: Vec<Found> = Vec::new();
    for (_, mut candidates) in by_field {
        // Highest score, then the longer range, then the stronger algorithm.
        candidates.sort_by(|a, b| {
            b.0.total_cmp(&a.0)
                .then((b.2.range.1 - b.2.range.0).cmp(&(a.2.range.1 - a.2.range.0)))
                .then(a.2.algorithm.cmp(&b.2.algorithm))
        });
        let alternatives = candidates.len() - 1;
        let (score, evidence, best) = candidates.swap_remove(0);
        checks.push(Found {
            algorithm: Some(best.algorithm),
            field: best.field,
            endian: best.endian,
            range: best.range,
            score,
            emulated: false,
            code_bound: best.field_origin == Origin::Code || best.bounds_from_code,
            evidence,
            alternatives,
        });
    }
    // A stored value inside a higher-scored check's range is usually a chance match on the bytes that check covers;
    // it is dropped unless code references it.
    checks.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.field.cmp(&b.field)));
    let mut kept: Vec<Found> = Vec::new();
    for check in checks {
        let covered =
            kept.iter().any(|other| other.score > check.score && (other.range.0..other.range.1).contains(&check.field));
        if !covered || check.code_bound {
            kept.push(check);
        }
    }
    kept
}

/// Runs the image's CRC routine over each matched range it admits; a result equal to the computed value confirms.
fn emulate(project: &Project, code: &CodeEvidence, blocks: &[Block], checks: &mut [Found], notes: &mut Vec<String>) {
    let mut runs = 0;
    for check in checks.iter_mut() {
        let Some(algorithm) = check.algorithm else { continue };
        let (start, end) = check.range;
        if end - start > MAX_EMULATED_RANGE || algorithm.width() > 4 {
            continue;
        }
        let Some(expected) = read(blocks, start, end).and_then(|bytes| {
            let mut state = algorithm.start(project.binary.big_endian);
            state.update(bytes);
            state.number()
        }) else {
            continue;
        };
        'routines: for routine in code.routines.iter().filter(|routine| routine.admits(algorithm)) {
            for (second, label) in [(end - start, "length"), (end, "end")] {
                if runs == MAX_EMULATIONS {
                    notes.push(format!("emulation stopped after {MAX_EMULATIONS} runs"));
                    return;
                }
                runs += 1;
                let request = EvaluateRequest {
                    at: format!("{:#x}", routine.address),
                    args: vec![
                        EvaluateArgument::Integer(IntegerText::Unsigned(start)),
                        EvaluateArgument::Integer(IntegerText::Unsigned(second)),
                    ],
                    max_steps: Some((200 * (end - start) + 100_000).min(crate::evaluate::MAX_STEPS)),
                    timeout_ms: Some(5_000),
                    ..Default::default()
                };
                let Ok(report) = project.evaluate_function(&request) else { continue };
                let mask = if algorithm.width() >= 8 { u64::MAX } else { (1u64 << (8 * algorithm.width())) - 1 };
                let result = report.result.as_ref().and_then(|result| result.unsigned.as_u64());
                if report.stop == StopReason::Returned && result.map(|value| value & mask) == Some(expected) {
                    check.emulated = true;
                    check.score = 0.98;
                    check.evidence.push(format!(
                        "emulation: evaluate_function({:#x}, {start:#x}, {label} {second:#x}) returned {expected:#x} \
                         in {} steps",
                        routine.address, report.steps
                    ));
                    break 'routines;
                }
            }
        }
    }
}

/// The PE optional-header CheckSum: its file offset when the file has one.
pub(crate) fn pe_checksum_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let header = u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if bytes.get(header..header + 4)? != b"PE\0\0" {
        return None;
    }
    let offset = header.checked_add(24 + 64)?;
    (offset + 4 <= bytes.len()).then_some(offset)
}

/// The PE image checksum over `bytes` with the CheckSum field at `field` taken as zero.
pub(crate) fn pe_checksum(bytes: &[u8], field: usize) -> u32 {
    let mut sum: u64 = 0;
    for (index, pair) in bytes.chunks(2).enumerate() {
        let at = index * 2;
        if (field..field + 4).contains(&at) {
            continue;
        }
        let word = u64::from(pair[0]) | pair.get(1).map_or(0, |&high| u64::from(high) << 8);
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(bytes.len() as u32)
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).filter_map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).ok()).collect()
}

/// The check's value over the blocks of one image, in the stored byte order.
fn compute(found: &Found, blocks: &[Block], big_endian: bool) -> Option<Vec<u8>> {
    let algorithm = found.algorithm?;
    let value = algorithm.compute(read(blocks, found.range.0, found.range.1)?, big_endian)?;
    Some(found.endian.encode(&value))
}

fn width(found: &Found) -> usize {
    found.algorithm.map_or(4, Algorithm::width)
}

/// Fixing order of the chosen checks: a check whose range covers another's stored value comes after it.
fn fix_order(checks: &[Found], chosen: &[bool]) -> Result<Vec<usize>, String> {
    let depends = |index: usize| -> Vec<usize> {
        let (start, end) = checks[index].range;
        (0..checks.len())
            .filter(|&other| other != index && chosen[other])
            .filter(|&other| {
                let field = checks[other].field;
                field < end && start < field + width(&checks[other]) as u64
            })
            .collect()
    };
    let mut order = Vec::new();
    let mut state = vec![0u8; checks.len()]; // 0 new, 1 visiting, 2 done
    fn visit(
        index: usize,
        depends: &dyn Fn(usize) -> Vec<usize>,
        state: &mut [u8],
        order: &mut Vec<usize>,
    ) -> Result<(), String> {
        match state[index] {
            2 => return Ok(()),
            1 => return Err(format!("checks form a cycle through check {index}: each covers another's value")),
            _ => {}
        }
        state[index] = 1;
        for dependency in depends(index) {
            visit(dependency, depends, state, order)?;
        }
        state[index] = 2;
        order.push(index);
        Ok(())
    }
    for index in (0..checks.len()).filter(|&index| chosen[index]) {
        visit(index, &depends, &mut state, &mut order)?;
    }
    Ok(order)
}

impl Project {
    /// Finds integrity checks in the original image, measures them on this (effective) image, and with
    /// `request.fix` writes corrected stored values as reviewed byte patches in dependency order.
    pub fn integrity_checks(self: &Arc<Self>, request: &IntegrityRequest) -> Result<IntegrityOutcome, ApiError> {
        let source = self.patch_source();
        let mut notes = Vec::new();
        let (original_blocks, blocks_omitted) = blocks(&source.binary);
        let code = code_evidence(&source, &original_blocks, &mut notes);
        let mut search = Search {
            blocks: &original_blocks,
            big_endian: source.binary.big_endian,
            constants: &code.constants,
            stats: SearchStats {
                blocks: original_blocks
                    .iter()
                    .map(|block| SearchedBlock { name: block.name.clone(), start: block.start, end: block.end() })
                    .collect(),
                blocks_omitted,
                algorithms: ALGORITHMS.len(),
                candidate_fields: 0,
                range_starts: 0,
                bytes_hashed: 0,
                budget_bytes: SEARCH_BUDGET_BYTES,
                lookups: 0,
                lookup_budget: SEARCH_LOOKUP_BUDGET,
                budget_exhausted: false,
                skipped_items: 0,
            },
            matches: Vec::new(),
        };
        search.run(&ALGORITHMS);
        if search.matches.len() >= MAX_MATCHES {
            notes.push(format!("the search stopped at {MAX_MATCHES} matches"));
        }
        let stats = search.stats;
        let mut found = select(search.matches, &code);
        found.truncate(MAX_CHECKS * 2);
        if request.emulate {
            emulate(&source, &code, &original_blocks, &mut found, &mut notes);
            found.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.field.cmp(&b.field)));
        }
        let checks_total = found.len();
        found.truncate(MAX_CHECKS);
        if checks_total > MAX_CHECKS {
            notes.push(format!("{} lower-scored checks omitted", checks_total - MAX_CHECKS));
        }
        let pe_field =
            (source.binary.format == Format::Pe).then(|| pe_checksum_offset(source.binary.file_bytes())).flatten();
        let receipt = self.patch_receipt().ok();

        let mut project = Arc::clone(self);
        let mut writes = Vec::new();
        let mut transition: Option<(Arc<()>, Arc<()>)> = None;
        if let Some(&unknown) = request.ids.iter().find(|&&id| id >= found.len() + usize::from(pe_field.is_some())) {
            return Err(ApiError::Invalid(format!("no check with id {unknown}")));
        }
        // By default only checks with independent evidence are written: confirmed by emulation, or a stored value or
        // range bound the code references. Anything else is fixed only when its id is given.
        let chosen: Vec<bool> =
            found
                .iter()
                .enumerate()
                .map(|(index, found)| {
                    if request.ids.is_empty() {
                        found.emulated || found.code_bound
                    } else {
                        request.ids.contains(&index)
                    }
                })
                .collect();
        let order = fix_order(&found, &chosen).map_err(ApiError::Invalid)?;
        let tokens = match (request.fix, &request.source_sha256, &request.expected_revision) {
            (false, ..) => None,
            (true, Some(source_sha256), Some(revision)) => Some((source_sha256.clone(), revision.clone())),
            (true, ..) => {
                return Err(ApiError::Invalid(
                    "fix requires source_sha256 and expected_revision from this tool's receipt (or list_patches)"
                        .into(),
                ));
            }
        };
        // Plan: every write is validated (admission, preimage, overlapping records, record budget) before any is
        // committed. Values of dependent checks are computed as the writes before them land.
        let existing = if receipt.is_some() { self.list_patches()? } else { Vec::new() };
        let mut planned = Vec::new();
        for &index in &order {
            let check = &found[index];
            let field_end = check.field + width(check) as u64;
            let original = read(&original_blocks, check.field, field_end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| ApiError::Invalid(format!("check {index}: its stored value is not in the image")))?;
            let previous = existing.iter().find(|patch| {
                let length = patch.original_hex.len() as u64 / 2;
                patch.address < field_end && check.field < patch.address + length
            });
            if let Some(patch) = previous
                && (patch.address != check.field || patch.original_hex.len() / 2 != width(check))
            {
                let message = format!(
                    "check {index}: the patch at {:#x} overlaps the stored value at {:#x} without matching it exactly; \
                     revert or adjust that patch first",
                    patch.address, check.field
                );
                if request.fix && receipt.is_some() {
                    return Err(ApiError::Invalid(message));
                }
                notes.push(message);
            }
            if receipt.is_some() {
                source.check_patch_admission(check.field, width(check), true).map_err(|error| {
                    ApiError::Invalid(format!("check {index}: the stored value cannot be patched: {error}"))
                })?;
            }
            planned.push((index, original, previous.cloned()));
        }
        let new_records = planned.iter().filter(|(_, _, previous)| previous.is_none()).count();
        if request.fix && existing.len() + new_records > crate::MAX_ACTIVE_PATCHES {
            return Err(ApiError::Invalid("the fix would exceed the active patch budget".into()));
        }
        let mut revision = tokens.as_ref().map(|(_, revision)| revision.clone());
        let mut applied: Vec<(u64, Option<crate::BytePatch>)> = Vec::new();
        let mut failure = None;
        for (index, original, previous) in planned {
            let check = &found[index];
            let (current_blocks, _) = blocks(&project.binary);
            let field_end = check.field + width(check) as u64;
            let (Some(current), Some(desired)) = (
                read(&current_blocks, check.field, field_end).map(<[u8]>::to_vec),
                compute(check, &current_blocks, project.binary.big_endian),
            ) else {
                continue;
            };
            if current == desired {
                continue;
            }
            // The original bytes are correct again: remove the record at the value, which covers exactly its bytes
            // (anything else was refused above).
            let revert = desired == original;
            let mut write = FixWrite {
                check: index,
                address: check.field,
                current_hex: hex(&current),
                replacement_hex: hex(&desired),
                action: if revert { "revert" } else { "patch" },
                detail: None,
            };
            if receipt.is_none() {
                write.action = "unsupported";
                write.detail = Some("this image does not take byte patches".into());
            }
            if let (Some((source_sha256, _)), Some(expected), true) = (&tokens, &revision, receipt.is_some()) {
                let outcome = if revert {
                    project.revert_patch_reviewed(check.field, source_sha256, expected)
                } else {
                    project.patch_bytes_reviewed(check.field, &original, &desired, true, source_sha256, expected)
                };
                match outcome {
                    Ok(outcome) => {
                        transition = Some(match transition {
                            None => (outcome.before_annotation_revision, outcome.after_annotation_revision),
                            Some((before, _)) => (before, outcome.after_annotation_revision),
                        });
                        revision = Some(outcome.receipt.revision_sha256.clone());
                        project = outcome.project;
                        applied.push((check.field, previous));
                    }
                    Err(error) => {
                        failure = Some(format!("check {index} at {:#x}: {error}", check.field));
                        break;
                    }
                }
            }
            writes.push(write);
        }
        if let Some(failure) = failure {
            // Undo the writes already committed, newest first, restoring each value's previous record.
            let (source_sha256, _) = tokens.as_ref().expect("fix tokens");
            let mut restored = true;
            for (address, previous) in applied.into_iter().rev() {
                let Some(expected) = revision.clone() else { break };
                let outcome = match previous {
                    None => project.revert_patch_reviewed(address, source_sha256, &expected),
                    Some(patch) => project.patch_bytes_reviewed(
                        address,
                        &unhex(&patch.original_hex),
                        &unhex(&patch.replacement_hex),
                        patch.allow_data,
                        source_sha256,
                        &expected,
                    ),
                };
                match outcome {
                    Ok(outcome) => {
                        revision = Some(outcome.receipt.revision_sha256.clone());
                        project = outcome.project;
                    }
                    Err(_) => restored = false,
                }
            }
            let state = if restored { "earlier writes were undone" } else { "earlier writes could not all be undone" };
            return Err(ApiError::Invalid(format!("fix failed at {failure}; {state}")));
        }
        for (index, check) in found.iter().enumerate().filter(|(index, _)| !chosen[*index]) {
            let (current_blocks, _) = blocks(&project.binary);
            let field_end = check.field + width(check) as u64;
            let (Some(current), Some(desired)) = (
                read(&current_blocks, check.field, field_end).map(<[u8]>::to_vec),
                compute(check, &current_blocks, project.binary.big_endian),
            ) else {
                continue;
            };
            if current != desired {
                writes.push(FixWrite {
                    check: index,
                    address: check.field,
                    current_hex: hex(&current),
                    replacement_hex: hex(&desired),
                    action: "preview_only",
                    detail: Some(
                        "not confirmed by emulation and no code references its value or range; pass its id to fix it"
                            .into(),
                    ),
                });
            }
        }
        if pe_field.is_some() && request.fix && request.ids.contains(&found.len()) {
            notes.push("the PE CheckSum is written by export_image with pe_checksum: true, not as a patch".into());
        }

        // Measure every check on the (possibly fixed) effective image.
        let (effective_blocks, _) = blocks(&project.binary);
        let mut checks = Vec::new();
        for (index, check) in found.iter().enumerate() {
            let Some(algorithm) = check.algorithm else { continue };
            let field_end = check.field + algorithm.width() as u64;
            let stored = read(&effective_blocks, check.field, field_end).map(<[u8]>::to_vec).unwrap_or_default();
            let computed = compute(check, &effective_blocks, project.binary.big_endian).unwrap_or_default();
            let depends_on = (0..found.len())
                .filter(|&other| other != index)
                .filter(|&other| {
                    let field = found[other].field;
                    field < check.range.1 && check.range.0 < field + width(&found[other]) as u64
                })
                .collect();
            checks.push(IntegrityCheck {
                id: index,
                algorithm: algorithm.name(),
                parameters: algorithm.parameters(),
                space: "memory",
                stored: StoredField { address: check.field, size: algorithm.width(), endian: check.endian.name() },
                ranges: vec![CoveredRange { start: check.range.0, end: check.range.1 }],
                valid: stored == computed,
                stored_hex: hex(&stored),
                computed_hex: hex(&computed),
                confidence: confidence(check.score),
                score: (check.score * 100.0).round() / 100.0,
                confirmed_by_emulation: check.emulated,
                evidence: check.evidence.clone(),
                depends_on,
                alternatives: check.alternatives,
            });
        }
        if let Some(field) = pe_field {
            let bytes = project.binary.file_bytes();
            let stored = &bytes[field..field + 4];
            let computed = pe_checksum(bytes, field).to_le_bytes();
            checks.push(IntegrityCheck {
                id: found.len(),
                algorithm: "pe_checksum",
                parameters: serde_json::json!({
                    "description": "PE optional-header CheckSum: folded 16-bit sum of the file with the field as \
                                    zero, plus the file length; Windows checks it only for drivers and boot images"
                }),
                space: "file",
                stored: StoredField { address: field as u64, size: 4, endian: "little" },
                ranges: vec![CoveredRange { start: 0, end: bytes.len() as u64 }],
                valid: stored == computed || stored == [0; 4],
                stored_hex: hex(stored),
                computed_hex: hex(&computed),
                confidence: "high",
                score: 0.95,
                confirmed_by_emulation: false,
                evidence: vec!["PE header field; zero means not set".into()],
                depends_on: Vec::new(),
                alternatives: 0,
            });
        }
        if code.routines.is_empty() && notes.iter().all(|note| !note.starts_with("no code evidence")) {
            notes.push("no CRC tables or polynomial literals referenced by code".into());
        }
        let invalid = checks.iter().filter(|check| !check.valid).count();
        let routines = code
            .routines
            .iter()
            .map(|routine| RoutineRow {
                address: routine.address,
                name: routine.name.clone(),
                algorithms: routine
                    .families
                    .iter()
                    .flat_map(|family| family_algorithms(family).iter().map(|algorithm| algorithm.name()))
                    .collect(),
                evidence: routine.evidence.clone(),
                callers: routine.callers.clone(),
            })
            .collect();
        let applied = transition.is_some();
        let receipt = if applied { project.patch_receipt().ok() } else { receipt };
        Ok(IntegrityOutcome {
            report: IntegrityReport {
                checks,
                checks_total: checks_total + usize::from(pe_field.is_some()),
                invalid,
                routines,
                search: stats,
                fix: FixReport { applied, writes },
                receipt,
                notes,
            },
            project,
            transition,
        })
    }
}
