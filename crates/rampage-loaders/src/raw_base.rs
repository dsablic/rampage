//! Load-address candidates for a Thumb (Cortex-M) code image whose base is unknown, and a check of an asserted
//! base against them.
//!
//! Nothing here maps anything: candidates are ranked suggestions with their evidence. Five methods contribute:
//!
//! - **vector table**: a Cortex-M table at offset 0 (an initial SP in a RAM-like range, odd handler words) whose
//!   handlers fit the image only from some base ([`crate::raw_vectors`] suggests the most aligned one);
//! - **pointer vote**: aligned 32-bit words of the image (at most [`MAX_WORDS`], sampled at a fixed stride beyond)
//!   that point at a `push {…, lr}` prologue (odd words, Thumb code pointers) or at the start of a NUL-terminated
//!   string (any word). A word `w` and a target at image offset `t` agree on the base `w - t`; only bases aligned to
//!   4 KiB are voted, so a word is paired only with targets whose low 12 bits equal its own, and the bases with the
//!   most votes are validated by counting hits exactly over every distinct word;
//! - **literal pool**: constants of at least 0x10000 that `ldr Rt, [pc, #imm]` or a `movw`/`movt` pair builds
//!   anywhere in the image (decoded linearly), which should land inside it: the 4 KiB-aligned bases that cover the
//!   most are kept, and in SRAM they count half (constants there are mostly variables' addresses);
//! - **reset-code constants**: the literal constants the code loads in its first 4 KiB from the entry (copy-table
//!   addresses, the `bx`/`blx` targets of startup code); odd ones should land on prologues;
//! - **hints**: bases a caller read elsewhere, such as a container record naming the payload's load address.
//!
//! Only bases from which the whole image lies in memory a Cortex-M can execute from (the code region, SRAM and
//! external RAM of the default memory map) are candidates, so peripheral constants never vote for a base.
//!
//! Every bound is fixed (words read, vote targets, votes, candidates validated), so a hostile image of 16 MiB costs
//! a bounded, deterministic amount of work (about 65 ms for 3.5 MiB in a release build). Scans are memoized by the
//! image's SHA-256 and the entry offset.

use std::ops::Range;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Aligned words read for the vote; a larger image is sampled at a fixed stride.
pub const MAX_WORDS: usize = 1 << 20;
/// Function and string starts each used as vote targets; more are sampled at a fixed stride. Validation still
/// counts against every start.
const MAX_VOTE_TARGETS: usize = 1 << 16;
/// Votes cast in one vote; beyond this, distinct words are sampled at a fixed stride.
const MAX_VOTES: usize = 1 << 22;
/// Vote winners validated exactly.
const SHORTLIST: usize = 12;
/// Candidates returned.
pub const MAX_CANDIDATES: usize = 5;
/// Bytes of code from the entry whose literal loads are reset-code constants.
const RESET_WINDOW: usize = 4096;
const MAX_RESET_CONSTANTS: usize = 256;
/// Literal loads read from the whole image.
const MAX_LITERAL_LOADS: usize = 1 << 18;
/// Smaller literal constants are counts, masks and offsets more often than addresses.
const MIN_LITERAL_POINTER: u32 = 0x1_0000;
/// Caller hints considered.
pub const MAX_HINTS: usize = 8;
/// The vote's base alignment.
const VOTE_ALIGNMENT_BITS: u32 = 12;
/// Printable bytes a string needs before its NUL.
const MIN_STRING: usize = 4;
const MEMO_SCANS: usize = 4;
const ERASED: u32 = 0xffff_ffff;

/// How a candidate was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseMethod {
    /// A Cortex-M vector table at offset 0 whose handlers fit the image from this base.
    VectorTable,
    /// Words of the image that point at function or string starts under this base.
    PointerVote,
    /// Literal-pool constants of the image lie inside it under this base.
    LiteralPool,
    /// Odd literal constants of the code from the entry land on prologues under this base.
    ResetCode,
    /// A caller-supplied hint, such as a container record's address field.
    Hint,
}

/// How strongly the evidence singles a candidate out. Only the first candidate can be `strong` or `plausible`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseConfidence {
    /// At least 8 pointer hits and three times the runner-up's, or an independent method (vector table, hint)
    /// that agrees with at least 4 hits and twice the runner-up's.
    Strong,
    /// At least 3 pointer hits and twice the runner-up's, or an independent method with at least the runner-up's.
    Plausible,
    Weak,
}

/// A base address supplied by the caller, with where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct BaseHint {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    /// Where the hint came from, e.g. "container record words at 0x2028 and 0x2038".
    pub source: String,
}

/// What supports one base. Pointer counts are distinct word values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BaseEvidence {
    /// Odd words whose target, under this base, is a `push {…, lr}` prologue in the image.
    pub function_pointers: usize,
    /// Words that point, under this base, at the start of a NUL-terminated run of at least four printable bytes.
    pub string_pointers: usize,
    /// Odd words inside the image under this base, prologue or not.
    pub code_pointers_inside: usize,
    /// Literal-pool constants of at least 0x10000, loaded anywhere in the image, inside it under this base.
    pub literal_pointers_inside: usize,
    /// Literal constants of the code from the entry that lie inside the image under this base.
    pub reset_constants_inside: usize,
    /// Of those, odd ones that land on a prologue: startup code's call and jump targets.
    pub reset_code_pointers: usize,
    /// The vector table at offset 0 fits the image from this base.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub vector_table: bool,
    /// The caller hints naming this base.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

impl BaseEvidence {
    /// Pointer hits: the vote's own measure.
    pub fn hits(&self) -> usize {
        self.function_pointers + self.string_pointers + self.reset_code_pointers
    }

    /// Function and reset-code pointers: the hits least likely by chance, since prologues are sparse.
    fn code_hits(&self) -> usize {
        self.function_pointers + self.reset_code_pointers
    }

    /// Literal constants count half in SRAM, where most of them are the addresses of variables.
    fn score(&self, base: u64) -> u64 {
        let literals = self.literal_pointers_inside as u64;
        4 * self.function_pointers as u64
            + 2 * self.string_pointers as u64
            + 4 * self.reset_code_pointers as u64
            + if (0x2000_0000..0x4000_0000).contains(&base) { literals / 2 } else { literals }
            + if self.vector_table { 32 } else { 0 }
            + if self.hints.is_empty() { 0 } else { 16 }
    }

    fn independent(&self) -> bool {
        self.vector_table || !self.hints.is_empty()
    }
}

/// One ranked load-address candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseCandidate {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    /// The largest of 1 MiB, 64 KiB, 4 KiB or 4 bytes that divides the base.
    pub alignment: u64,
    /// 4 per function pointer and per reset-code pointer, 2 per string pointer, 1 per literal constant inside,
    /// 32 for a fitting vector table, 16 for a hint.
    pub score: u64,
    pub confidence: BaseConfidence,
    pub methods: Vec<BaseMethod>,
    pub evidence: BaseEvidence,
}

/// The ranked candidates and what the vote read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseCandidates {
    /// At most five, best first. Suggestions: nothing is mapped at any of them.
    pub candidates: Vec<BaseCandidate>,
    pub image_length: u64,
    /// Aligned words read, and the stride between them (1 unless the image holds more than 1 Mi words).
    pub words_read: usize,
    pub word_stride: usize,
    /// Distinct nonzero, non-erased word values among them.
    pub distinct_words: usize,
    /// `push {…, lr}` prologues and NUL-terminated string starts found in the image.
    pub function_starts: usize,
    pub string_starts: usize,
    pub votes: usize,
    /// The vote budget sampled the words (counts in `evidence` are still exact).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub votes_sampled: bool,
    /// The image offset the reset-code constants were read from, and how many distinct constants it loads.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub reset_code_offset: Option<u64>,
    pub reset_constants: usize,
    /// Distinct literal-pool constants of at least 0x10000 loaded anywhere in the image (decoded linearly).
    pub literal_constants: usize,
    pub note: &'static str,
}

impl BaseCandidates {
    /// The first candidate, when its confidence is `strong`.
    pub fn strong(&self) -> Option<&BaseCandidate> {
        self.candidates.first().filter(|candidate| candidate.confidence == BaseConfidence::Strong)
    }
}

const NOTE: &str = "suggestions for 32-bit little-endian Thumb code, not applied. The vote pairs aligned words with \
                    push {..., lr} prologues and string starts at bases aligned to 4 KiB; a base that is not 4 KiB \
                    aligned is found only from a vector table or a hint. Code copied to another run address votes \
                    for the base of its copy too, so a second candidate can be a startup copy's displacement";

/// What one image's scan keeps, for evaluating any base.
#[derive(Debug)]
struct Scan {
    length: u64,
    /// Distinct nonzero, non-erased words, ascending.
    words: Vec<u32>,
    /// `push {…, lr}` starts, one bit per halfword offset.
    function_starts: Vec<u64>,
    /// String starts, one bit per byte offset.
    string_starts: Vec<u64>,
    reset_constants: Vec<u32>,
    /// Distinct literal constants of at least [`MIN_LITERAL_POINTER`] the whole image loads.
    literals: Vec<u32>,
    vector_table_base: Option<u64>,
    candidates: BaseCandidates,
}

type MemoKey = [u8; 32];
static MEMO: Mutex<Vec<(MemoKey, Arc<Scan>)>> = Mutex::new(Vec::new());

fn bit(bits: &[u64], index: u64) -> bool {
    usize::try_from(index / 64).ok().and_then(|word| bits.get(word)).is_some_and(|word| word >> (index % 64) & 1 == 1)
}

fn set(bits: &mut [u64], index: usize) {
    bits[index / 64] |= 1 << (index % 64);
}

fn half(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A Thumb `push {…, lr}`: T1 `push` with `lr`, or `push.w`/`stmdb sp!` of at least two registers including `lr`
/// and not `sp` or `pc`.
fn push_lr(bytes: &[u8], at: usize) -> bool {
    let Some(first) = half(bytes, at) else { return false };
    if first & 0xff00 == 0xb500 {
        return true;
    }
    if first == 0xe92d
        && let Some(list) = half(bytes, at + 2)
    {
        return list & 0x4000 != 0 && list & 0xa000 == 0 && list.count_ones() >= 2;
    }
    false
}

fn printable(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

/// Whether a 32-bit Thumb instruction starts with this halfword.
fn wide(first: u16) -> bool {
    first >> 11 >= 0b11101
}

/// Distinct constants the code from `offset` to `end` builds, decoded linearly, at most `limit`: words loaded by
/// `ldr Rt, [pc, #imm]` (T1 and T2) and `movw`/`movt` pairs into one register. Literal addresses are
/// PC-relative, so the values do not depend on the base.
fn code_constants(bytes: &[u8], offset: usize, end: usize, limit: usize) -> Vec<u32> {
    let end = bytes.len().min(end);
    let mut constants = Vec::new();
    // The last `movw` per register, with the instruction count it was seen at.
    let mut movw = [None::<(u16, usize)>; 16];
    let mut count = 0usize;
    let mut at = offset & !1;
    while at + 2 <= end && constants.len() < limit {
        let Some(first) = half(bytes, at) else { break };
        count += 1;
        let aligned_pc = (at + 4) & !3;
        let second = if wide(first) { half(bytes, at + 2) } else { None };
        let literal = if first & 0xf800 == 0x4800 {
            Some(aligned_pc + usize::from(first & 0xff) * 4)
        } else if first & 0xff7f == 0xf85f {
            second.and_then(|second| {
                let imm = usize::from(second & 0xfff);
                if first & 0x80 != 0 { Some(aligned_pc + imm) } else { aligned_pc.checked_sub(imm) }
            })
        } else {
            None
        };
        let mut value = literal.and_then(|literal| word(bytes, literal));
        if let Some(second) = second
            && second & 0x8000 == 0
            && matches!(first & 0xfbf0, 0xf240 | 0xf2c0)
        {
            let imm = (first & 0xf) << 12 | (first >> 10 & 1) << 11 | (second >> 12 & 7) << 8 | second & 0xff;
            let register = usize::from(second >> 8 & 0xf);
            if first & 0xfbf0 == 0xf240 {
                movw[register] = Some((imm, count));
            } else if let Some((low, seen)) = movw[register].take()
                && count - seen <= 16
            {
                value = Some(u32::from(imm) << 16 | u32::from(low));
            }
        }
        if let Some(value) = value
            && value != 0
            && value != ERASED
        {
            constants.push(value);
        }
        at += if second.is_some() { 4 } else { 2 };
    }
    constants.sort_unstable();
    constants.dedup();
    constants
}

/// Whether code can run from every byte of `base..end` in the Cortex-M default memory map: the code region, SRAM
/// and external RAM, not the execute-never peripheral, device and system regions.
fn executable(base: u64, end: u64) -> bool {
    end <= 0x4000_0000 || (0x6000_0000..0xa000_0000).contains(&base) && end <= 0xa000_0000
}

/// A RAM-like initial stack pointer: SRAM, external RAM or a TCM above the code alias.
fn ram_like(sp: u64) -> bool {
    (0x1000_0000..0xe000_0000).contains(&sp)
}

/// The base a vector table at offset 0 implies: the suggestion of [`crate::raw_vectors`] when handlers fall outside
/// the image at base 0, or 0 when they all fit there.
fn vector_table_base(bytes: &[u8]) -> Option<u64> {
    let table = crate::raw_vectors::read(bytes, 0, 0).ok()?;
    let sp = table.vectors.first()?;
    if sp.status != crate::raw_vectors::VectorStatus::StackPointer || !ram_like(sp.word) {
        return None;
    }
    let reset = table.vectors.get(1)?.word;
    if reset & 1 == 0 || reset == u64::from(ERASED) {
        return None;
    }
    match &table.base_address_suggestion {
        Some(suggestion) => Some(suggestion.base_address),
        None => table.reset().map(|_| 0),
    }
}

fn alignment(base: u64) -> u64 {
    [1 << 20, 1 << 16, 1 << 12].into_iter().find(|&alignment| base.is_multiple_of(alignment)).unwrap_or(4)
}

impl Scan {
    fn new(bytes: &[u8], entry_offset: Option<u64>) -> Self {
        let length = bytes.len() as u64;
        let word_count = bytes.len() / 4;
        let stride = word_count.div_ceil(MAX_WORDS).max(1);
        let mut words: Vec<u32> = (0..word_count).step_by(stride).filter_map(|index| word(bytes, index * 4)).collect();
        let words_read = words.len();
        words.retain(|&word| word != 0 && word != ERASED);
        words.sort_unstable();
        words.dedup();

        let mut function_starts = vec![0u64; (bytes.len() / 2).div_ceil(64)];
        let mut functions = Vec::new();
        for at in (0..bytes.len().saturating_sub(1)).step_by(2) {
            if push_lr(bytes, at) {
                set(&mut function_starts, at / 2);
                functions.push(at as u32);
            }
        }
        let mut string_starts = vec![0u64; bytes.len().div_ceil(64)];
        let mut strings = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            if (at == 0 || !printable(bytes[at - 1])) && printable(bytes[at]) {
                let run = bytes[at..].iter().take_while(|&&byte| printable(byte)).count();
                if run >= MIN_STRING && bytes.get(at + run) == Some(&0) {
                    set(&mut string_starts, at);
                    strings.push(at as u32);
                }
                at += run.max(1);
            } else {
                at += 1;
            }
        }

        let vector_table_base = vector_table_base(bytes);
        let reset_offset = entry_offset
            .filter(|&offset| offset < length)
            .or_else(|| {
                let base = vector_table_base?;
                let reset = u64::from(word(bytes, 4)?) & !1;
                reset.checked_sub(base).filter(|&offset| offset < length)
            })
            .or((length > 0).then_some(0));
        let reset_constants = reset_offset.map_or_else(Vec::new, |offset| {
            let offset = usize::try_from(offset).unwrap_or(0);
            code_constants(bytes, offset, offset.saturating_add(RESET_WINDOW), MAX_RESET_CONSTANTS)
        });
        let mut literals = code_constants(bytes, 0, bytes.len(), MAX_LITERAL_LOADS);
        literals.retain(|&value| value >= MIN_LITERAL_POINTER);

        let mut scan = Scan {
            length,
            words,
            function_starts,
            string_starts,
            reset_constants,
            literals,
            vector_table_base,
            candidates: BaseCandidates {
                candidates: Vec::new(),
                image_length: length,
                words_read,
                word_stride: stride,
                distinct_words: 0,
                function_starts: functions.len(),
                string_starts: strings.len(),
                votes: 0,
                votes_sampled: false,
                reset_code_offset: reset_offset,
                reset_constants: 0,
                literal_constants: 0,
                note: NOTE,
            },
        };
        scan.candidates.distinct_words = scan.words.len();
        scan.candidates.reset_constants = scan.reset_constants.len();
        scan.candidates.literal_constants = scan.literals.len();
        let (mut shortlist, votes, sampled) = scan.vote(&functions, &strings);
        shortlist.extend(scan.stab());
        scan.candidates.votes = votes;
        scan.candidates.votes_sampled = sampled;
        scan.candidates.candidates = scan.rank(shortlist, &[]);
        scan
    }

    /// The bases with the most votes, best first.
    fn vote(&self, functions: &[u32], strings: &[u32]) -> (Vec<u64>, usize, bool) {
        let buckets = |starts: &[u32]| {
            let step = starts.len().div_ceil(MAX_VOTE_TARGETS).max(1);
            let mut buckets = vec![Vec::new(); 1 << VOTE_ALIGNMENT_BITS];
            for &start in starts.iter().step_by(step) {
                buckets[(start & 0xfff) as usize].push(start);
            }
            buckets
        };
        let functions = buckets(functions);
        let strings = buckets(strings);
        let cost: usize = self
            .words
            .iter()
            .map(|&word| {
                let low = (word & 0xfff) as usize;
                strings[low].len() + if word & 1 == 1 { functions[low & !1].len() } else { 0 }
            })
            .sum();
        let step = cost.div_ceil(MAX_VOTES).max(1);
        // Votes are bases shifted right by 12, weighted like the score: function hits twice string hits.
        let mut votes: Vec<u32> = Vec::with_capacity(cost.min(MAX_VOTES * 2));
        for &word in self.words.iter().step_by(step) {
            let low = (word & 0xfff) as usize;
            if word & 1 == 1 {
                let target = word & !1;
                for &start in &functions[low & !1] {
                    if let Some(base) = target.checked_sub(start) {
                        votes.extend([base >> VOTE_ALIGNMENT_BITS; 2]);
                    }
                }
            }
            for &start in &strings[low] {
                if let Some(base) = word.checked_sub(start) {
                    votes.push(base >> VOTE_ALIGNMENT_BITS);
                }
            }
        }
        let cast = votes.len();
        votes.sort_unstable();
        let mut counted: Vec<(usize, u32)> = Vec::new();
        for run in votes.chunk_by(|left, right| left == right) {
            counted.push((run.len(), run[0]));
        }
        // Most votes first, lower base on ties: deterministic.
        counted.sort_unstable_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        let shortlist = counted
            .iter()
            .take(SHORTLIST)
            .filter(|(count, _)| *count >= 2)
            .map(|&(_, base)| u64::from(base) << VOTE_ALIGNMENT_BITS)
            .filter(|&base| self.fits(base))
            .collect();
        (shortlist, cast, step > 1)
    }

    /// The 4 KiB-aligned bases that place the most literal constants inside the image: each constant `c` admits
    /// the bases `c - length + 1 ..= c`, and the most aligned base of each best-covered run of bases is kept.
    fn stab(&self) -> Vec<u64> {
        let unit = 1u64 << VOTE_ALIGNMENT_BITS;
        let mut events: Vec<(u64, i32)> = Vec::with_capacity(self.literals.len() * 2);
        for &literal in &self.literals {
            let literal = u64::from(literal);
            let low = literal.saturating_sub(self.length.saturating_sub(1)).div_ceil(unit);
            let high = literal / unit;
            if low <= high {
                events.push((low, 1));
                events.push((high + 1, -1));
            }
        }
        events.sort_unstable();
        let mut runs: Vec<(i32, u64, u64)> = Vec::new();
        let mut coverage = 0;
        for (index, &(at, change)) in events.iter().enumerate() {
            coverage += change;
            let next = events.get(index + 1).map(|&(next, _)| next);
            if let Some(next) = next
                && next > at
                && coverage >= 2
            {
                runs.push((coverage, at, next - 1));
            }
        }
        runs.sort_unstable_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        runs.iter()
            .map(|&(_, low, high)| {
                (VOTE_ALIGNMENT_BITS..32)
                    .rev()
                    .map(|bits| (low * unit).next_multiple_of(1 << bits))
                    .find(|&base| base <= high * unit)
                    .unwrap_or(low * unit)
            })
            .filter(|&base| self.fits(base))
            .take(SHORTLIST)
            .collect()
    }

    /// Whether the image fits from `base` inside memory a Cortex-M executes from.
    fn fits(&self, base: u64) -> bool {
        base.checked_add(self.length).is_some_and(|end| executable(base, end))
    }

    /// Exact evidence for `base`, which [`Self::fits`].
    fn evaluate(&self, base: u64) -> BaseEvidence {
        let end = base + self.length;
        let inside = |value: u32| (base..end).contains(&u64::from(value));
        let on_function = |value: u32| {
            let target = u64::from(value & !1);
            (base..end).contains(&target) && bit(&self.function_starts, (target - base) / 2)
        };
        let mut evidence = BaseEvidence::default();
        let start = self.words.partition_point(|&word| u64::from(word) < base);
        for &word in &self.words[start..] {
            if u64::from(word) >= end {
                break;
            }
            let offset = u64::from(word) - base;
            if word & 1 == 1 {
                evidence.code_pointers_inside += 1;
                if bit(&self.function_starts, (offset & !1) / 2) {
                    evidence.function_pointers += 1;
                }
            }
            if bit(&self.string_starts, offset) {
                evidence.string_pointers += 1;
            }
        }
        evidence.literal_pointers_inside = self.literals.iter().filter(|&&literal| inside(literal)).count();
        for &constant in &self.reset_constants {
            if inside(constant) {
                evidence.reset_constants_inside += 1;
                if constant & 1 == 1 && on_function(constant) {
                    evidence.reset_code_pointers += 1;
                }
            }
        }
        evidence.vector_table = self.vector_table_base == Some(base);
        evidence
    }

    /// Validates the shortlist, the vector-table base and the hints, and ranks them.
    fn rank(&self, shortlist: Vec<u64>, hints: &[BaseHint]) -> Vec<BaseCandidate> {
        let mut bases: Vec<u64> = shortlist;
        bases.extend(self.vector_table_base);
        bases.extend(hints.iter().take(MAX_HINTS).map(|hint| hint.base_address));
        let mut ranked: Vec<BaseCandidate> = Vec::new();
        bases.sort_unstable();
        bases.dedup();
        for base in bases {
            if !self.fits(base) {
                continue;
            }
            let mut evidence = self.evaluate(base);
            evidence.hints = hints
                .iter()
                .take(MAX_HINTS)
                .filter(|hint| hint.base_address == base)
                .map(|hint| hint.source.clone())
                .collect();
            let mut methods = Vec::new();
            if evidence.vector_table {
                methods.push(BaseMethod::VectorTable);
            }
            if evidence.function_pointers + evidence.string_pointers > 0 {
                methods.push(BaseMethod::PointerVote);
            }
            if evidence.literal_pointers_inside > 0 {
                methods.push(BaseMethod::LiteralPool);
            }
            if evidence.reset_code_pointers > 0 {
                methods.push(BaseMethod::ResetCode);
            }
            if !evidence.hints.is_empty() {
                methods.push(BaseMethod::Hint);
            }
            if methods.is_empty() {
                continue;
            }
            ranked.push(BaseCandidate {
                base_address: base,
                alignment: alignment(base),
                score: evidence.score(base),
                confidence: BaseConfidence::Weak,
                methods,
                evidence,
            });
        }
        ranked.sort_by(|left, right| right.score.cmp(&left.score).then(left.base_address.cmp(&right.base_address)));
        // A base a little off the best one still covers most of its pointers and literals: drop such shadows, whose
        // prologue hits collapse, unless a hint names them.
        let mut kept: Vec<BaseCandidate> = Vec::new();
        for candidate in ranked {
            let shadow = candidate.evidence.hints.is_empty()
                && kept.iter().any(|better| {
                    better.base_address.abs_diff(candidate.base_address) < self.length
                        && candidate.evidence.function_pointers * 4 <= better.evidence.function_pointers
                        && candidate.score * 2 < better.score
                });
            if !shadow {
                kept.push(candidate);
            }
        }
        let mut ranked = kept;
        ranked.truncate(MAX_CANDIDATES);
        let others = || ranked.iter().skip(1);
        let runner_up = others().map(|candidate| candidate.evidence.hits()).max().unwrap_or(0);
        let runner_up_code = others().map(|candidate| candidate.evidence.code_hits()).max().unwrap_or(0);
        let runner_up_score = ranked.get(1).map_or(0, |candidate| candidate.score);
        if let Some(first) = ranked.first_mut() {
            let hits = first.evidence.hits();
            let code = first.evidence.code_hits();
            first.confidence = if (hits >= 8 && hits >= 3 * runner_up)
                || (code >= 8 && code >= 3 * runner_up_code && first.score >= 2 * runner_up_score)
                || (first.evidence.independent() && hits >= 4 && hits >= 2 * runner_up)
            {
                BaseConfidence::Strong
            } else if (hits >= 3 && hits >= 2 * runner_up)
                || (first.evidence.independent() && hits >= runner_up)
                || (first.evidence.literal_pointers_inside >= 8 && first.score >= 2 * runner_up_score)
            {
                BaseConfidence::Plausible
            } else {
                BaseConfidence::Weak
            };
        }
        ranked
    }
}

fn memo_key(bytes: &[u8], entry_offset: Option<u64>) -> MemoKey {
    let mut hash = Sha256::new();
    hash.update(b"raw-base-v1");
    hash.update(entry_offset.map_or([0xff; 8], u64::to_be_bytes));
    hash.update(bytes);
    hash.finalize().into()
}

fn scan(bytes: &[u8], entry_offset: Option<u64>) -> Arc<Scan> {
    let key = memo_key(bytes, entry_offset);
    if let Some((_, scan)) = MEMO.lock().ok().and_then(|memo| memo.iter().find(|(stored, _)| *stored == key).cloned()) {
        return scan;
    }
    let scan = Arc::new(Scan::new(bytes, entry_offset));
    if let Ok(mut memo) = MEMO.lock() {
        if memo.len() >= MEMO_SCANS {
            memo.remove(0);
        }
        memo.push((key, Arc::clone(&scan)));
    }
    scan
}

/// Ranked load-address candidates for `bytes` as Thumb code, with `entry_offset` the image offset of the code
/// whose literal constants are checked (default: the vector table's Reset handler, else offset 0) and `hints`
/// bases read elsewhere (at most eight).
pub fn base_candidates(bytes: &[u8], entry_offset: Option<u64>, hints: &[BaseHint]) -> BaseCandidates {
    let scan = scan(bytes, entry_offset);
    if hints.is_empty() {
        return scan.candidates.clone();
    }
    let shortlist = scan.candidates.candidates.iter().map(|candidate| candidate.base_address).collect();
    let mut candidates = scan.candidates.clone();
    candidates.candidates = scan.rank(shortlist, hints);
    candidates
}

/// Whether the asserted base looks right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseVerdict {
    /// The asserted base is the best candidate, or close to it in pointer hits.
    Consistent,
    /// Another base explains the image far better, or the reset-code follow fetched outside every region at an
    /// address that another candidate places inside the image.
    LooksWrong,
    /// Too little evidence either way.
    Unknown,
}

/// The reset-code follow stopped fetching outside every mapped region at an address another base would map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BadFetchCheck {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub target: u64,
    /// The best-ranked candidate under which the target lies inside the image, when one does.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub candidate_base: Option<u64>,
}

/// A Raw project's asserted base checked against the candidates.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BaseCheck {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    pub verdict: BaseVerdict,
    /// Evidence for the asserted base, counted like a candidate's.
    pub evidence: BaseEvidence,
    /// The asserted base's pointer hits over the best hits of any candidate or of the asserted base (1.0 when it is
    /// the best; 0 when nothing has any).
    pub pointer_share: f64,
    /// Literal constants of the code from the entry that lie inside any mapped region, of `reset_constants`.
    pub reset_constants_in_regions: usize,
    pub reset_constants: usize,
    /// The better base, when the verdict is `looks_wrong`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub better_candidate: Option<BaseCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bad_fetch: Option<BadFetchCheck>,
    /// Every candidate, best first.
    pub candidates: Vec<BaseCandidate>,
    /// What to do, when the base looks wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// Checks `base`, where `bytes` (the primary region) are mapped, against the candidates; `regions` are every
/// mapped range and `scatter` the reset-code follow, whose `bad_fetch` outside every region is matched against
/// the candidates.
pub fn check_base(
    bytes: &[u8],
    base: u64,
    entry_offset: Option<u64>,
    regions: &[Range<u64>],
    scatter: Option<&crate::raw_scatter::ScatterLoad>,
) -> BaseCheck {
    let scan = scan(bytes, entry_offset);
    let candidates = scan.candidates.candidates.clone();
    let mut evidence = if scan.fits(base) { scan.evaluate(base) } else { BaseEvidence::default() };
    evidence.vector_table = scan.vector_table_base == Some(base);
    let in_regions = |value: u64| regions.iter().any(|range| range.contains(&value));
    let reset_constants_in_regions =
        scan.reset_constants.iter().filter(|&&constant| in_regions(u64::from(constant))).count();
    let hits = evidence.hits();
    let best_hits = candidates.iter().map(|candidate| candidate.evidence.hits()).max().unwrap_or(0).max(hits);
    let pointer_share = if best_hits == 0 { 0.0 } else { (hits as f64 / best_hits as f64 * 1000.0).round() / 1000.0 };

    let bad_fetch = scatter
        .filter(|scatter| scatter.stop == crate::raw_scatter::FollowStop::BadFetch && !in_regions(scatter.stopped_at))
        .map(|scatter| {
            let target = scatter.stopped_at;
            let candidate_base = candidates.iter().map(|candidate| candidate.base_address).find(|&candidate| {
                candidate != base && (candidate..candidate.saturating_add(scan.length)).contains(&target)
            });
            BadFetchCheck { target, candidate_base }
        });

    let top = candidates.first();
    let mut better = None;
    let mut next = None;
    let verdict = if let Some(fetch) = &bad_fetch
        && let Some(candidate_base) = fetch.candidate_base
    {
        let candidate = candidates.iter().find(|candidate| candidate.base_address == candidate_base).cloned();
        next = Some(format!(
            "The base looks wrong: following the reset code fetched an instruction at {:#x}, outside every mapped \
             region, which lies inside the image under candidate base {candidate_base:#x}{}. Reopen with \
             base_address {candidate_base:#x}.",
            fetch.target,
            candidate.as_ref().map_or_else(String::new, |candidate| format!(
                " ({} function pointers, {} string pointers)",
                candidate.evidence.function_pointers, candidate.evidence.string_pointers
            )),
        ));
        better = candidate;
        BaseVerdict::LooksWrong
    } else if let Some(top) = top
        && top.base_address != base
        && top.confidence != BaseConfidence::Weak
        && hits * 4 < top.evidence.hits()
    {
        next = Some(format!(
            "The base looks wrong: under {base:#x}, {hits} words point at function or string starts in the image; \
             under candidate base {:#x}, {} do ({} function pointers, {} string pointers{}). Reopen with \
             base_address {:#x}.",
            top.base_address,
            top.evidence.hits(),
            top.evidence.function_pointers,
            top.evidence.string_pointers,
            if top.evidence.hints.is_empty() { "" } else { ", and a hint names it" },
            top.base_address,
        ));
        better = Some(top.clone());
        BaseVerdict::LooksWrong
    } else if hits >= 3 && hits * 4 >= best_hits * 3 {
        BaseVerdict::Consistent
    } else {
        BaseVerdict::Unknown
    };
    BaseCheck {
        base_address: base,
        verdict,
        evidence,
        pointer_share,
        reset_constants_in_regions,
        reset_constants: scan.reset_constants.len(),
        better_candidate: better,
        bad_fetch,
        candidates,
        next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic image at `base`: functions with `push {r7, lr}` prologues, a string, and a table of pointers to
    /// them.
    fn image(base: u32, functions: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x4000];
        let mut targets = Vec::new();
        for index in 0..functions {
            let at = 0x100 + index * 0x40;
            bytes[at..at + 2].copy_from_slice(&0xb580u16.to_le_bytes());
            bytes[at + 2..at + 4].copy_from_slice(&0xbd80u16.to_le_bytes());
            targets.push(base + at as u32 + 1);
        }
        bytes[0x3000..0x3006].copy_from_slice(b"hello\0");
        targets.push(base + 0x3000);
        for (index, target) in targets.iter().enumerate() {
            let at = 0x2000 + index * 4;
            bytes[at..at + 4].copy_from_slice(&target.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn the_pointer_vote_finds_the_base() {
        let bytes = image(0x0800_0000, 12);
        let found = base_candidates(&bytes, None, &[]);
        let first = &found.candidates[0];
        assert_eq!(first.base_address, 0x0800_0000, "{found:#?}");
        assert_eq!(first.evidence.function_pointers, 12);
        assert_eq!(first.evidence.string_pointers, 1);
        assert_eq!(first.confidence, BaseConfidence::Strong);
        assert_eq!(first.alignment, 1 << 20);
    }

    #[test]
    fn a_hint_is_validated_and_ranked() {
        let bytes = image(0x6000_0000, 6);
        let hint = BaseHint { base_address: 0x6000_0000, source: "test record".into() };
        let found = base_candidates(&bytes, None, std::slice::from_ref(&hint));
        let first = &found.candidates[0];
        assert_eq!(first.base_address, 0x6000_0000);
        assert!(first.methods.contains(&BaseMethod::Hint) && first.methods.contains(&BaseMethod::PointerVote));
        assert_eq!(first.confidence, BaseConfidence::Strong);
        // A hint nothing supports still appears, ranked by its own evidence.
        let wrong = BaseHint { base_address: 0x0100_0000, source: "elsewhere".into() };
        let found = base_candidates(&bytes, None, &[wrong]);
        assert_eq!(found.candidates[0].base_address, 0x6000_0000);
        assert!(found.candidates.iter().any(|candidate| candidate.base_address == 0x0100_0000));
    }

    #[test]
    fn a_wrong_base_is_named_with_the_right_one() {
        let bytes = image(0x0800_0000, 12);
        let check = check_base(&bytes, 0x0100_0000, None, std::slice::from_ref(&(0x0100_0000..0x0100_4000)), None);
        assert_eq!(check.verdict, BaseVerdict::LooksWrong);
        assert_eq!(check.better_candidate.as_ref().unwrap().base_address, 0x0800_0000);
        assert!(check.next.as_ref().unwrap().contains("0x8000000"), "{:?}", check.next);
        let right = check_base(&bytes, 0x0800_0000, None, std::slice::from_ref(&(0x0800_0000..0x0800_4000)), None);
        assert_eq!(right.verdict, BaseVerdict::Consistent);
        assert_eq!(right.pointer_share, 1.0);
        assert!(right.next.is_none());
    }

    #[test]
    fn hostile_images_give_no_confident_candidate() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let random: Vec<u8> = (0..1 << 20)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let pushes: Vec<u8> = (0..1u32 << 18).flat_map(|index| (0xb500_0001 | index << 1).to_le_bytes()).collect();
        for bytes in [vec![0xff; 1 << 20], random, [0x01, 0xb5, 0x01, 0xb5].repeat(1 << 18), Vec::new()] {
            let found = base_candidates(&bytes, None, &[]);
            assert!(found.strong().is_none(), "{:#?}", found.candidates.first());
            assert!(found.votes <= MAX_VOTES * 2);
        }
        // Distinct odd words that are all push prologues: the most votes per word. The work stays bounded.
        let found = base_candidates(&pushes, None, &[]);
        assert!(found.votes <= MAX_VOTES * 2 && found.votes_sampled, "{}", found.votes);
    }
}
