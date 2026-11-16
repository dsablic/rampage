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
/// Word-target pairings cast as votes (4 bytes each); beyond this, pairings are sampled by cost, and casting stops
/// at it.
pub const MAX_VOTES: usize = 1 << 22;
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
    /// At least 3 pointer hits and twice the runner-up's, an independent method with at least the runner-up's,
    /// or at least 8 literal constants inside and twice the runner-up's score; never without a pointer hit, and
    /// never for a span that crosses 0x20000000.
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

/// A hint that is not a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RejectedHint {
    #[serde(flatten)]
    pub hint: BaseHint,
    pub reason: &'static str,
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
    /// Reset-code pointers not already counted in `function_pointers` (built by `movw`/`movt`, not image words).
    #[serde(skip)]
    reset_only_pointers: usize,
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
        self.function_pointers + self.string_pointers + self.reset_only_pointers
    }

    /// Function and reset-code pointers, each counted once: the hits least likely by chance, since prologues are
    /// sparse.
    fn code_hits(&self) -> usize {
        self.function_pointers + self.reset_only_pointers
    }

    /// Literal constants count half in SRAM, where most of them are the addresses of variables.
    fn score(&self, base: u64) -> u64 {
        let literals = self.literal_pointers_inside as u64;
        4 * self.function_pointers as u64
            + 2 * self.string_pointers as u64
            + 4 * self.reset_only_pointers as u64
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
    /// 4 per function pointer and per reset-code pointer not among them, 2 per string pointer, 1 per literal constant inside,
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
    /// Hints that are not candidates, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejected_hints: Vec<RejectedHint>,
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
                rejected_hints: Vec::new(),
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
        // Each pairing of a word with a target is one vote entry; a pairing with a prologue weighs 2.
        let pairings = |word: u32| {
            let low = (word & 0xfff) as usize;
            let code: &[u32] = if word & 1 == 1 { &functions[low & !1] } else { &[] };
            (code, &strings[low][..])
        };
        let cost: usize = self
            .words
            .iter()
            .map(|&word| {
                let (code, text) = pairings(word);
                code.len() + text.len()
            })
            .sum();
        // Sampled by cost: of every `step` consecutive pairings (counted over all words in order) one is cast, so a
        // few words with huge buckets cannot take the whole budget; the cap is also a hard stop.
        let step = cost.div_ceil(MAX_VOTES).max(1);
        let mut votes: Vec<u32> = Vec::with_capacity(cost.min(MAX_VOTES));
        let mut seen = 0usize;
        let mut capped = false;
        'words: for &word in &self.words {
            let (code, text) = pairings(word);
            for (targets, value, function) in [(code, word & !1, 1u32), (text, word, 0)] {
                let first = (step - seen % step) % step;
                for &start in targets.iter().skip(first).step_by(step) {
                    if votes.len() >= MAX_VOTES {
                        capped = true;
                        break 'words;
                    }
                    if let Some(base) = value.checked_sub(start) {
                        votes.push((base >> VOTE_ALIGNMENT_BITS) << 1 | function);
                    }
                }
                seen += targets.len();
            }
        }
        let cast = votes.len();
        votes.sort_unstable();
        // The SHORTLIST bases with the most weight, kept without materialising every distinct base: most weight
        // first, lower base on ties, so the result is deterministic.
        let mut best: Vec<(usize, u32)> = Vec::with_capacity(SHORTLIST + 1);
        for run in votes.chunk_by(|left, right| left >> 1 == right >> 1) {
            let weight: usize = run.iter().map(|&vote| 1 + (vote & 1) as usize).sum();
            let base = run[0] >> 1;
            if weight < 2 || !self.fits(u64::from(base) << VOTE_ALIGNMENT_BITS) {
                continue;
            }
            if best.len() == SHORTLIST && best.last().is_some_and(|&(last, _)| last >= weight) {
                continue;
            }
            let at = best.partition_point(|&(other, _)| other >= weight);
            best.insert(at, (weight, base));
            best.truncate(SHORTLIST);
        }
        let shortlist = best.iter().map(|&(_, base)| u64::from(base) << VOTE_ALIGNMENT_BITS).collect();
        (shortlist, cast, step > 1 || capped)
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

    /// Whether the image would span the start of SRAM, 0x20000000, from `base`.
    fn crosses_sram(&self, base: u64) -> bool {
        base < 0x2000_0000 && base + self.length > 0x2000_0000
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
                    if self.words.binary_search(&constant).is_err() {
                        evidence.reset_only_pointers += 1;
                    }
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
        // A span that crosses from the code region into SRAM at 0x20000000 is no flash or RAM image: usually
        // pointers to code copied to RAM, displaced. Such candidates rank after the others and stay weak.
        ranked.sort_by(|left, right| {
            self.crosses_sram(left.base_address)
                .cmp(&self.crosses_sram(right.base_address))
                .then(right.score.cmp(&left.score))
                .then(left.base_address.cmp(&right.base_address))
        });
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
        let first_crosses = ranked.first().is_some_and(|first| self.crosses_sram(first.base_address));
        if let Some(first) = ranked.first_mut().filter(|first| first.evidence.hits() > 0 && !first_crosses) {
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
    candidates.rejected_hints = hints
        .iter()
        .enumerate()
        .filter_map(|(index, hint)| {
            let reason = if index >= MAX_HINTS {
                "more than eight hints"
            } else if !scan.fits(hint.base_address) {
                "the image would not lie in memory a Cortex-M executes from (code region, SRAM or external RAM)"
            } else if !candidates.candidates.iter().any(|candidate| candidate.base_address == hint.base_address) {
                "ranked below the five candidates listed"
            } else {
                return None;
            };
            Some(RejectedHint { hint: hint.clone(), reason })
        })
        .collect();
    candidates
}

/// Whether the asserted base looks right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseVerdict {
    /// The vector table at offset 0 fits from it, it is the first candidate (`strong` or `plausible`), or it has at
    /// least 3 pointer hits and three quarters of the best candidate's.
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
    /// The best-ranked candidate under which the target is a function start, when that candidate is `strong` or
    /// `plausible`, has more pointer hits than the asserted base and is not a startup copy's displacement.
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
    /// Why a base with more pointer hits is not taken as better (a fitting vector table, a copy displacement), or
    /// why a fetch outside every region names no base.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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

    // Code copied to a run address votes for the base that maps its run addresses onto the image: copy
    // displacements are not the image's base.
    let displacements: Vec<u64> = scatter
        .map(|scatter| {
            scatter
                .copies
                .iter()
                .filter(|copy| copy.kind == crate::raw_scatter::CopyKind::Copy)
                .filter_map(|copy| copy.destination.checked_sub(copy.source?.checked_sub(base)?))
                .collect()
        })
        .unwrap_or_default();
    let displacement = |candidate: u64| displacements.iter().any(|&shift| candidate.abs_diff(shift) < 0x1000);
    let on_prologue = |candidate: u64, target: u64| {
        target
            .checked_sub(candidate)
            .is_some_and(|offset| offset < scan.length && bit(&scan.function_starts, offset / 2))
    };

    let bad_fetch = scatter
        .filter(|scatter| scatter.stop == crate::raw_scatter::FollowStop::BadFetch && !in_regions(scatter.stopped_at))
        .map(|scatter| {
            let target = scatter.stopped_at;
            let candidate_base = candidates
                .iter()
                .find(|candidate| {
                    candidate.base_address != base
                        && candidate.confidence != BaseConfidence::Weak
                        && candidate.evidence.hits() > hits
                        && on_prologue(candidate.base_address, target)
                        && !displacement(candidate.base_address)
                })
                .map(|candidate| candidate.base_address);
            BadFetchCheck { target, candidate_base }
        });

    let top = candidates.first();
    let mut better = None;
    let mut next = None;
    let mut note = None;
    let top_beats = |top: &BaseCandidate| {
        top.base_address != base && top.confidence != BaseConfidence::Weak && hits * 4 < top.evidence.hits()
    };
    let verdict = if evidence.vector_table {
        let most =
            candidates.iter().filter(|other| other.base_address != base).max_by_key(|other| other.evidence.hits());
        if let Some(top) = most.filter(|top| top.evidence.hits() > hits) {
            note = Some(format!(
                "the vector table at offset 0 fits this base; candidate base {:#x} has more pointer hits ({} vs \
                 {hits}), most likely the displacement of code copied to another run address",
                top.base_address,
                top.evidence.hits()
            ));
        }
        BaseVerdict::Consistent
    } else if let Some(fetch) = &bad_fetch
        && let Some(candidate_base) = fetch.candidate_base
    {
        let candidate = candidates.iter().find(|candidate| candidate.base_address == candidate_base).cloned();
        next = Some(format!(
            "The base looks wrong: following the reset code fetched an instruction at {:#x}, outside every mapped \
             region, which is a function start in the image under candidate base {candidate_base:#x}{}. Reopen with \
             base_address {candidate_base:#x}.",
            fetch.target,
            candidate.as_ref().map_or_else(String::new, |candidate| format!(
                " ({} function pointers, {} string pointers)",
                candidate.evidence.function_pointers, candidate.evidence.string_pointers
            )),
        ));
        better = candidate;
        BaseVerdict::LooksWrong
    } else if let Some(fetch) = &bad_fetch {
        note = Some(format!(
            "following the reset code fetched an instruction at {:#x}, outside every mapped region, and no candidate \
             base with evidence places a function start there: a jump into another image, or a region not mapped",
            fetch.target
        ));
        BaseVerdict::Unknown
    } else if let Some(top) = top.filter(|top| top_beats(top) && !displacement(top.base_address)) {
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
    } else {
        if let Some(top) = top.filter(|top| top_beats(top)) {
            note = Some(format!(
                "candidate base {:#x} has more pointer hits ({} vs {hits}) but is the displacement of a startup copy \
                 (raw.scatter_load), not the image's base",
                top.base_address,
                top.evidence.hits()
            ));
        }
        if (hits >= 3 && hits * 4 >= best_hits * 3)
            || top.is_some_and(|top| top.base_address == base && top.confidence != BaseConfidence::Weak)
        {
            BaseVerdict::Consistent
        } else {
            BaseVerdict::Unknown
        }
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
        note,
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
            assert!(found.votes <= MAX_VOTES);
        }
        // Distinct odd words that are all push prologues: the most votes per word. The work stays bounded.
        let found = base_candidates(&pushes, None, &[]);
        assert!(found.votes <= MAX_VOTES && found.votes_sampled, "{}", found.votes);
    }

    fn put(bytes: &mut [u8], at: usize, word: u32) {
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }

    /// A 64 KiB flash image at 0x08000000: 3 flash pointers to prologues, and 20 functions copied from flash
    /// offset 0x1000 that pointers name by their run addresses at `run`. With `vector_table`, a valid table at
    /// offset 0.
    fn copied_image(run: u32, vector_table: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x1_0000];
        for index in 0..23 {
            let at = 0x1000 + index * 0x40;
            bytes[at..at + 4].copy_from_slice(&[0x80, 0xb5, 0x80, 0xbd]);
        }
        for index in 0..20 {
            put(&mut bytes, 0x8000 + index * 4, run + (index * 0x40) as u32 + 1);
        }
        for index in 0..3 {
            put(&mut bytes, 0x9000 + index * 4, 0x0800_1000 + ((20 + index) * 0x40) as u32 + 1);
        }
        if vector_table {
            put(&mut bytes, 0, 0x2001_0000);
            for index in 1..4 {
                put(&mut bytes, index * 4, 0x0800_1501);
            }
        }
        bytes
    }

    fn scatter(
        copies: Vec<crate::raw_scatter::ScatterCopy>,
        stop: crate::raw_scatter::FollowStop,
        at: u64,
    ) -> crate::raw_scatter::ScatterLoad {
        crate::raw_scatter::ScatterLoad {
            entry: 0,
            steps: 1,
            stop,
            stopped_at: at,
            continues_at: None,
            copies,
            copies_not_listed: 0,
            skipped_calls: Vec::new(),
            skipped_calls_not_listed: 0,
            vtor_stores: Vec::new(),
            vtor_stores_not_listed: 0,
            last_vtor_store: None,
            after_jump: None,
            vector_table: None,
            vector_table_refused: None,
            note: "",
        }
    }

    fn copy(destination: u64, source: u64, length: u64) -> crate::raw_scatter::ScatterCopy {
        crate::raw_scatter::ScatterCopy {
            kind: crate::raw_scatter::CopyKind::Copy,
            destination,
            length,
            source: Some(source),
            source_region: None,
            source_offset: None,
            stores: 2,
            store_sites: Vec::new(),
            call_site: None,
            routine: None,
            executed: true,
            written_after_jump: false,
            status: crate::raw_scatter::CopyStatus::Mapped,
            region: None,
            not_mapped_reason: None,
        }
    }

    /// Most pointers name code copied to RAM: the displaced base spans 0x20000000 and stays weak, and a fitting
    /// vector table keeps the asserted base consistent with a note.
    #[test]
    fn pointers_to_a_ram_copy_do_not_overrule_a_fitting_vector_table() {
        let bytes = copied_image(0x2000_0000, true);
        let flash = 0x0800_0000..0x0801_0000;
        let check = check_base(&bytes, 0x0800_0000, None, std::slice::from_ref(&flash), None);
        assert_eq!(check.verdict, BaseVerdict::Consistent, "{check:#?}");
        assert!(check.next.is_none() && check.better_candidate.is_none());
        assert!(check.note.as_deref().unwrap().contains("vector table"), "{:?}", check.note);
        let displaced = check.candidates.iter().find(|candidate| candidate.base_address == 0x1fff_f000).unwrap();
        assert_eq!(displaced.confidence, BaseConfidence::Weak);
        assert_eq!(check.candidates[0].base_address, 0x0800_0000, "{:#?}", check.candidates);
    }

    /// Without a vector table, a startup copy's displacement is not called the better base.
    #[test]
    fn a_copy_displacement_is_not_the_better_base() {
        let bytes = copied_image(0x1000_0000, false);
        let flash = 0x0800_0000..0x0801_0000;
        let alone = check_base(&bytes, 0x0800_0000, None, std::slice::from_ref(&flash), None);
        assert_eq!(alone.verdict, BaseVerdict::LooksWrong, "{alone:#?}");
        assert_eq!(alone.better_candidate.unwrap().base_address, 0x0fff_f000);
        let copies = scatter(
            vec![copy(0x1000_0000, 0x0800_1000, 0x500)],
            crate::raw_scatter::FollowStop::JumpedIntoCopiedCode,
            0x1000_0000,
        );
        let check = check_base(&bytes, 0x0800_0000, None, &[flash, 0x1000_0000..0x1000_0500], Some(&copies));
        assert_ne!(check.verdict, BaseVerdict::LooksWrong, "{check:#?}");
        assert!(check.next.is_none());
        assert!(check.note.as_deref().unwrap().contains("displacement"), "{:?}", check.note);
    }

    /// A bootloader jumping to an application outside its image: the fetch is reported, no base is named.
    #[test]
    fn a_bad_fetch_no_candidate_explains_names_no_base() {
        let bytes = image(0x0800_0000, 12);
        let flash = 0x0800_0000..0x0800_4000;
        let fetch = scatter(Vec::new(), crate::raw_scatter::FollowStop::BadFetch, 0x0801_0000);
        let check = check_base(&bytes, 0x0800_0000, None, std::slice::from_ref(&flash), Some(&fetch));
        assert_eq!(check.verdict, BaseVerdict::Unknown, "{check:#?}");
        assert_eq!(check.bad_fetch.as_ref().unwrap().candidate_base, None);
        assert!(check.next.is_none() && check.better_candidate.is_none());
        // A weak candidate covering the target, or one where it is no function start, is not enough either.
        let fetch = scatter(Vec::new(), crate::raw_scatter::FollowStop::BadFetch, 0x0800_0102);
        let check =
            check_base(&bytes, 0x0100_0000, None, std::slice::from_ref(&(0x0100_0000..0x0100_4000)), Some(&fetch));
        assert_eq!(check.bad_fetch.as_ref().unwrap().candidate_base, None);
        assert_eq!(check.verdict, BaseVerdict::Unknown, "{check:#?}");
        // On a prologue under a plausible candidate with more hits: named.
        let fetch = scatter(Vec::new(), crate::raw_scatter::FollowStop::BadFetch, 0x0800_0100);
        let check =
            check_base(&bytes, 0x0100_0000, None, std::slice::from_ref(&(0x0100_0000..0x0100_4000)), Some(&fetch));
        assert_eq!(check.bad_fetch.as_ref().unwrap().candidate_base, Some(0x0800_0000));
        assert_eq!(check.verdict, BaseVerdict::LooksWrong);
    }

    #[test]
    fn hints_outside_executable_memory_are_listed_as_rejected() {
        let bytes = image(0x0800_0000, 12);
        let hint = BaseHint { base_address: 0x4000_0000, source: "peripheral".into() };
        let found = base_candidates(&bytes, None, std::slice::from_ref(&hint));
        assert!(found.candidates.iter().all(|candidate| candidate.base_address != 0x4000_0000));
        assert_eq!(found.rejected_hints.len(), 1);
        assert_eq!(found.rejected_hints[0].hint, hint);
        assert!(found.rejected_hints[0].reason.contains("executes"));
    }
}
