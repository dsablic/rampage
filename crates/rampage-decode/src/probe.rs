//! A bounded sweep over the built-in decoder families for a stream whose parameters are unknown. Every
//! candidate is a parameter set the ordinary [`Decoder`](crate::Decoder) path accepts; nothing is applied.
//!
//! The sweep has two stages. Each LZSS variant first decodes a prefix of the input and is scored on parse
//! statistics that do not depend on what the data means. The best few then decode the whole input and are
//! scored again, with the supplied output size when there is one.

use crate::lzss::ScanStats;
use crate::{DecodeError, FlagOrder, Lz4Block, Lzss, OffsetMode, ReferenceLayout, Scan, ScanEnd};

/// Input bytes each LZSS variant decodes in the first stage.
pub const SAMPLE_INPUT_BYTES: usize = 16 * 1024;
/// Output bytes at which a first-stage decode stops.
pub const SAMPLE_OUTPUT_BYTES: usize = 128 * 1024;
/// LZSS variants that decode the whole input in the second stage.
pub const FINALISTS: usize = 8;
/// Trailing input bytes a stream may leave and still count as consuming its input, unless they are one
/// repeated byte (padding), which may be any length.
pub const MAX_TRAILING_BYTES: usize = 3;
/// A candidate needs at least this many references: fewer say nothing about the parameters.
pub const MIN_REFERENCES: u64 = 16;

pub const WINDOW_BITS: [u8; 4] = [12, 11, 13, 10];
pub const MIN_MATCHES: [u8; 2] = [3, 2];
pub const FLAG_ORDERS: [FlagOrder; 2] = [FlagOrder::LsbFirst, FlagOrder::MsbFirst];
pub const LAYOUTS: [ReferenceLayout; 5] = [
    ReferenceLayout::SplitByte,
    ReferenceLayout::Le16OffsetLow,
    ReferenceLayout::Le16LengthLow,
    ReferenceLayout::Be16OffsetLow,
    ReferenceLayout::Be16LengthLow,
];
pub const FILLS: [u8; 3] = [0x00, 0x20, 0xff];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOptions {
    /// The decoded size, when known. A candidate must then reach exactly this size.
    pub expected_output_size: Option<usize>,
    /// The most output any one decode may produce.
    pub max_output_size: usize,
    /// Work steps for the whole sweep, counted as the decoders count them.
    pub max_steps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    Lzss(Lzss),
    Lz4Block,
}

/// A check a candidate passed or failed. Failed checks are reported, not hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub codec: Codec,
    pub output_size: usize,
    pub consumed: usize,
    pub trailing: usize,
    /// Whether the trailing input is one repeated byte, as padding is.
    pub trailing_padding: bool,
    pub end: ScanEnd,
    pub literals: u64,
    pub references: u64,
    /// Shannon entropy of the consumed input, in bits per byte.
    pub input_entropy: f64,
    pub output_entropy: f64,
    /// How far the length-field distribution is from uniform: 0 is uniform, 1 a single value.
    pub length_skew: f64,
    /// The share of references that start close behind the output end.
    pub near_fraction: f64,
    /// Ring mode: the share of the first window's output that was read from never-written ring positions.
    pub unwritten_fraction: f64,
    /// The share of output bytes in printable runs of at least five characters.
    pub printable_fraction: f64,
    /// LZSS: the share of short references whose next output byte equals the byte after their source, so the
    /// encoder could have made them longer. Near zero for the right parameters of a greedy or lazy encoder.
    pub extendable_fraction: f64,
    pub extendable_matches: u64,
    /// Ring mode: whether any output byte came from the ring's initial fill, so the fill byte matters.
    pub fill_exercised: bool,
    /// Ring mode: how many initial write offsets explain the first references equally well.
    pub write_offset_alternatives: usize,
    pub checks: Vec<Check>,
    /// Other candidates that pass every check with the same token parse; see [`rank`].
    pub parse_equivalents: usize,
    /// FNV-1a of the output, which identifies variants that decode the same bytes.
    pub output_fingerprint: u64,
    /// Other variants that decoded exactly these bytes from exactly this input and were folded into this one.
    pub same_output_variants: usize,
    pub score: f64,
    /// Every check passed.
    pub passes_checks: bool,
    pub verdict: Verdict,
}

/// How far a candidate can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The first candidate, with a supplied output size reached exactly, every check passed and no
    /// parse-equivalent rival with similar output.
    Confident,
    /// Every check passed, but without a supplied size, or with a close parse-equivalent rival.
    Plausible,
    /// Some check failed.
    Weak,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Ranked best first. Only the first can be [`Verdict::Confident`].
    pub candidates: Vec<Candidate>,
    pub input_entropy: f64,
    pub lzss_variants: usize,
    /// With a supplied size: token walks over the whole input, one per parse (flag order and polarity, window,
    /// minimum match and reference layout), and how many reached the size exactly.
    pub size_walks: usize,
    pub size_fits: usize,
    pub sample_decodes: usize,
    pub full_decodes: usize,
    /// Finalists dropped because they did not reach the expected output size exactly.
    pub size_mismatches: usize,
    pub steps: u64,
    /// `work_budget` or `cancelled` when the sweep stopped before trying everything.
    pub stopped_early: Option<&'static str>,
}

pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    let total = bytes.len() as f64;
    counts.iter().filter(|&&count| count != 0).map(|&count| count as f64 / total).map(|p| -p * p.log2()).sum()
}

fn printable_fraction(bytes: &[u8]) -> f64 {
    let mut printable = 0;
    let mut run = 0;
    for &byte in bytes.iter().chain(&[0]) {
        if (0x20..=0x7e).contains(&byte) || byte == b'\t' {
            run += 1;
        } else {
            if run >= 5 {
                printable += run;
            }
            run = 0;
        }
    }
    if bytes.is_empty() { 0.0 } else { printable as f64 / bytes.len() as f64 }
}

fn length_skew(stats: &ScanStats, values: usize) -> f64 {
    if stats.references == 0 || values < 2 {
        return 0.0;
    }
    let total = stats.references as f64;
    let bits: f64 = stats.length_fields[..values]
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| f64::from(count) / total)
        .map(|p| -p * p.log2())
        .sum();
    (1.0 - bits / (values as f64).log2()).clamp(0.0, 1.0)
}

/// Initial write offsets worth trying for a ring-mode variant: the conventional ones, and when neither explains
/// the first references, the offsets that leave the fewest of them pointing at never-written positions.
/// Returns the offsets and how many offsets tie for the fewest violations.
fn write_offsets(lzss: &Lzss, stats: &ScanStats) -> (Vec<u16>, usize) {
    let window = lzss.window_size();
    let conventional = [(window - lzss.max_match()) as u16, 0];
    if stats.early_references.is_empty() {
        return (conventional.to_vec(), window);
    }
    let violations = |start: usize| {
        stats
            .early_references
            .iter()
            .filter(|&&(position, written)| {
                let distance = (start + written as usize).wrapping_sub(usize::from(position)) & (window - 1);
                distance == 0 || distance > written as usize
            })
            .count()
    };
    let counts: Vec<usize> = (0..window).map(violations).collect();
    let fewest = *counts.iter().min().unwrap();
    let best: Vec<u16> = (0..window).filter(|&start| counts[start] == fewest).map(|start| start as u16).collect();
    let mut offsets = conventional.to_vec();
    if conventional.iter().all(|&start| counts[usize::from(start)] > fewest) {
        offsets.push(best[0]);
        offsets.push(*best.last().unwrap());
        offsets.dedup();
    }
    (offsets, best.len())
}

struct Budget<'a> {
    remaining: u64,
    used: u64,
    stopped: Option<&'static str>,
    cancelled: &'a mut dyn FnMut() -> bool,
}

impl Budget<'_> {
    /// Runs one decode against what is left. `None` means the sweep must stop.
    fn scan(
        &mut self,
        decode: impl FnOnce(u64, &mut dyn FnMut() -> bool) -> Result<Scan, DecodeError>,
    ) -> Option<Scan> {
        if self.stopped.is_some() {
            return None;
        }
        // Every work step polls cancellation once, so the polls count a failed decode's steps too.
        let mut polls = 0u64;
        let cancelled = &mut *self.cancelled;
        let result = decode(self.remaining, &mut || {
            polls += 1;
            cancelled()
        });
        let steps = match &result {
            Ok(scan) => scan.steps,
            Err(_) => polls.min(self.remaining),
        };
        self.remaining -= steps;
        self.used += steps;
        match result {
            Ok(scan) => Some(scan),
            Err(error) => {
                self.stopped = Some(match error {
                    DecodeError::Cancelled => "cancelled",
                    DecodeError::WorkLimitExceeded => "work_budget",
                    DecodeError::AllocationFailure => "allocation_failure",
                    _ => "decoder_error",
                });
                None
            }
        }
    }
}

fn candidate(codec: Codec, input: &[u8], scan: &Scan, alternatives: usize) -> Candidate {
    let (window, length_values) = match codec {
        Codec::Lzss(lzss) => (lzss.window_size(), 1usize << lzss.length_bits()),
        Codec::Lz4Block => (65536, 16),
    };
    let references = scan.stats.references;
    Candidate {
        codec,
        output_size: scan.bytes.len(),
        consumed: scan.consumed,
        trailing: input.len() - scan.consumed,
        trailing_padding: input[scan.consumed..].iter().all(|&byte| byte == input[scan.consumed]),
        end: scan.end,
        literals: scan.stats.literals,
        references,
        input_entropy: entropy(&input[..scan.consumed]),
        output_entropy: entropy(&scan.bytes),
        length_skew: length_skew(&scan.stats, length_values),
        near_fraction: if references == 0 { 0.0 } else { scan.stats.near_references as f64 / references as f64 },
        unwritten_fraction: scan.stats.unwritten_bytes as f64 / scan.bytes.len().clamp(1, window) as f64,
        printable_fraction: printable_fraction(&scan.bytes),
        extendable_matches: scan.stats.extendable,
        extendable_fraction: if scan.stats.maximal_checked == 0 {
            0.0
        } else {
            scan.stats.extendable as f64 / scan.stats.maximal_checked as f64
        },
        fill_exercised: scan.stats.unwritten_bytes != 0,
        write_offset_alternatives: alternatives,
        checks: Vec::new(),
        parse_equivalents: 0,
        output_fingerprint: fingerprint(&scan.bytes),
        same_output_variants: 0,
        score: 0.0,
        passes_checks: false,
        verdict: Verdict::Weak,
    }
}

/// Thresholds for the checks. Wrong parameters give near-uniform length fields and reference positions, read
/// much of the first window from never-written ring positions, and leave the output as mixed as the input.
pub const MIN_LENGTH_SKEW: f64 = 0.08;
pub const MIN_NEAR_FRACTION: f64 = 0.25;
pub const MAX_UNWRITTEN_FRACTION: f64 = 0.10;
pub const MIN_ENTROPY_DROP: f64 = 0.1;

/// The parse score of an LZSS decode, in 0..=1, from statistics alone.
fn parse_score(candidate: &Candidate) -> f64 {
    let skew = (candidate.length_skew / 0.3).min(1.0);
    let near = ((candidate.near_fraction - 0.125) / 0.4).clamp(0.0, 1.0);
    let written = (1.0 - candidate.unwritten_fraction / 0.3).clamp(0.0, 1.0);
    let drop = ((candidate.input_entropy - candidate.output_entropy) / 1.0).clamp(0.0, 1.0);
    0.3 * skew + 0.3 * near + 0.2 * written + 0.2 * drop
}

fn judge(candidate: &mut Candidate, expected: Option<usize>) {
    let lz4 = candidate.codec == Codec::Lz4Block;
    let mut checks = vec![
        Check { name: "enough_references", passed: candidate.references >= MIN_REFERENCES },
        Check {
            name: "input_consumed",
            passed: candidate.trailing <= MAX_TRAILING_BYTES || candidate.trailing_padding,
        },
        Check {
            name: "output_entropy_below_input",
            passed: candidate.input_entropy - candidate.output_entropy >= MIN_ENTROPY_DROP,
        },
    ];
    if let Some(expected) = expected {
        checks.push(Check { name: "expected_output_size_reached", passed: candidate.output_size == expected });
    }
    if lz4 {
        checks.push(Check { name: "block_ends_with_input", passed: candidate.end == ScanEnd::InputExhausted });
    } else {
        checks.push(Check { name: "length_fields_skewed", passed: candidate.length_skew >= MIN_LENGTH_SKEW });
        checks.push(Check { name: "references_mostly_near", passed: candidate.near_fraction >= MIN_NEAR_FRACTION });
        checks.push(Check {
            name: "references_read_written_data",
            passed: candidate.unwritten_fraction <= MAX_UNWRITTEN_FRACTION,
        });
    }
    let passed = |name: &str| checks.iter().any(|check| check.name == name && check.passed);
    let enough = passed("enough_references");
    let drop = passed("output_entropy_below_input");
    let consumed = passed("input_consumed");
    let sized = expected.is_some() && passed("expected_output_size_reached");
    let mut score = parse_score(candidate);
    if lz4 {
        // An LZ4 block has no free choices: every sequence must be valid and the block must end with the input.
        let ended = passed("block_ends_with_input") || (sized && consumed);
        score = if ended {
            1.0
        } else {
            0.4 * (candidate.consumed as f64 / (candidate.consumed + candidate.trailing).max(1) as f64)
        };
        candidate.passes_checks = enough && ended;
    } else {
        let parse = passed("length_fields_skewed")
            && passed("references_mostly_near")
            && passed("references_read_written_data");
        if sized && consumed {
            // A wrong variant reaches the supplied size at an unrelated input position.
            score = 0.5 + score / 2.0;
        } else {
            score /= 2.0;
        }
        candidate.passes_checks = enough && parse && if expected.is_some() { sized && consumed } else { drop };
    }
    candidate.score = (score * 1000.0).round() / 1000.0;
    candidate.checks = checks;
}

/// Every combination of the fields that decide how a stream splits into tokens, with the others zeroed.
fn parse_keys() -> impl Iterator<Item = Lzss> {
    WINDOW_BITS.into_iter().flat_map(|window_bits| {
        MIN_MATCHES.into_iter().flat_map(move |min_match| {
            FLAG_ORDERS.into_iter().flat_map(move |flag_order| {
                [true, false].into_iter().flat_map(move |literal_flag| {
                    LAYOUTS.into_iter().map(move |layout| Lzss {
                        window_bits,
                        min_match,
                        flag_order,
                        literal_flag,
                        layout,
                        offset_mode: OffsetMode::Distance,
                        initial_write_offset: 0,
                        dictionary_fill: 0,
                    })
                })
            })
        })
    })
}

/// The best of parse-equivalent candidates is clear when the next has at least twice its extendable matches
/// plus this many.
pub const MIN_EXTENDABLE_GAP: u64 = 2;
/// The score by which a confident first candidate must beat any passing candidate with a different parse.
pub const MIN_SCORE_MARGIN: f64 = 0.05;

fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3))
}

/// Lower is simpler: a distance before a biased distance before a ring, which needs a start and a fill.
fn simplicity(codec: &Codec) -> u8 {
    match codec {
        Codec::Lz4Block => 0,
        Codec::Lzss(lzss) => match lzss.offset_mode {
            OffsetMode::Distance => 0,
            OffsetMode::DistanceMinusOne => 1,
            OffsetMode::RingPosition => 2,
        },
    }
}

/// Folds variants that decode the same bytes from the same input into the simplest of them, then orders
/// candidates that pass every check first, by score. Candidates that split the input into the same tokens (same
/// consumed bytes and reference count) but decode different bytes differ only in what a reference means, such as
/// the minimum match, a distance bias, the ring start or fill. Among those, the fewest extendable matches go
/// first, then the least mixed output; a first that does not have clearly fewer extendable matches than the next is
/// not confident (a fill the stream reads but never pins down stays ambiguous this way). Only a
/// first candidate whose parse-equivalent rivals all have clearly more mixed output, and that reached a supplied
/// size, is confident.
fn rank(candidates: &mut Vec<Candidate>, sized: bool) {
    candidates.sort_by(|a, b| {
        (a.output_fingerprint, a.consumed)
            .cmp(&(b.output_fingerprint, b.consumed))
            .then(b.passes_checks.cmp(&a.passes_checks))
            .then(simplicity(&a.codec).cmp(&simplicity(&b.codec)))
    });
    let mut folded: Vec<Candidate> = Vec::with_capacity(candidates.len());
    for candidate in candidates.drain(..) {
        match folded.last_mut() {
            Some(kept)
                if kept.output_fingerprint == candidate.output_fingerprint
                    && kept.consumed == candidate.consumed
                    && kept.output_size == candidate.output_size =>
            {
                kept.same_output_variants += 1;
            }
            _ => folded.push(candidate),
        }
    }
    *candidates = folded;
    candidates.sort_by(|a, b| b.passes_checks.cmp(&a.passes_checks).then(b.score.total_cmp(&a.score)));
    let Some(first) = candidates.first() else { return };
    let (consumed, references) = (first.consumed, first.references);
    let group = |candidate: &Candidate| {
        candidate.passes_checks && candidate.consumed == consumed && candidate.references == references
    };
    let tied = candidates.iter().filter(|candidate| group(candidate)).count();
    // Bring every member of the group to the front, keeping the others' order.
    candidates.sort_by_key(|candidate| !group(candidate));
    candidates[..tied].sort_by(|a, b| {
        a.extendable_matches.cmp(&b.extendable_matches).then(a.output_entropy.total_cmp(&b.output_entropy))
    });
    // Group members have the same tokens, so their counts compare directly.
    let clear =
        tied <= 1 || candidates[1].extendable_matches >= 2 * candidates[0].extendable_matches + MIN_EXTENDABLE_GAP;
    // A passing candidate with another parse must also score clearly lower.
    let group_score = candidates[..tied].iter().map(|candidate| candidate.score).fold(f64::MIN, f64::max);
    let rival = candidates[tied..]
        .iter()
        .filter(|candidate| candidate.passes_checks)
        .map(|candidate| candidate.score)
        .fold(f64::MIN, f64::max);
    let clear = clear && group_score - rival >= MIN_SCORE_MARGIN;
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.parse_equivalents = if index < tied { tied - 1 } else { 0 };
        candidate.verdict = match candidate.passes_checks {
            true if index == 0 && clear && sized => Verdict::Confident,
            true => Verdict::Plausible,
            false => Verdict::Weak,
        };
    }
}

fn padding_like(bytes: &[u8]) -> bool {
    bytes.len() <= 16 || bytes.iter().all(|&byte| byte == bytes[0])
}

/// Sweeps the built-in families over `input`. Budget or cancellation ends the sweep early with what was found.
pub fn probe(input: &[u8], options: &ProbeOptions, cancelled: &mut dyn FnMut() -> bool) -> Report {
    let mut budget = Budget { remaining: options.max_steps, used: 0, stopped: None, cancelled };
    let limit = options.expected_output_size.unwrap_or(options.max_output_size).min(options.max_output_size);
    let sample = &input[..input.len().min(SAMPLE_INPUT_BYTES)];
    let sample_limit = limit.min(SAMPLE_OUTPUT_BYTES);
    let mut report = Report {
        candidates: Vec::new(),
        input_entropy: entropy(input),
        lzss_variants: 0,
        size_walks: 0,
        size_fits: 0,
        sample_decodes: 0,
        full_decodes: 0,
        size_mismatches: 0,
        steps: 0,
        stopped_early: None,
    };

    // LZ4 first: one decode, so a budget or deadline spent on the LZSS sweep cannot skip it.
    if let Some(scan) = budget.scan(|steps, cancelled| Lz4Block.decode_available(input, limit, steps, cancelled)) {
        report.full_decodes += 1;
        let sized = options.expected_output_size.is_none_or(|expected| scan.bytes.len() == expected);
        let covered = scan.consumed * 10 >= input.len() * 9 || padding_like(&input[scan.consumed..]);
        if sized && covered && scan.stats.references >= MIN_REFERENCES {
            let mut found = candidate(Codec::Lz4Block, input, &scan, 1);
            judge(&mut found, options.expected_output_size);
            report.candidates.push(found);
        } else if !sized {
            report.size_mismatches += 1;
        }
    }

    // With a supplied size, a token walk (no copying) keeps only the parses that reach it exactly.
    let fits = options.expected_output_size.map(|expected| {
        let mut fits = Vec::new();
        for key in parse_keys() {
            if budget.stopped.is_some() || (budget.cancelled)() {
                budget.stopped.get_or_insert("cancelled");
                break;
            }
            let (consumed, tokens) = key.measure(input, expected);
            report.size_walks += 1;
            let tokens = tokens.min(budget.remaining);
            budget.remaining -= tokens;
            budget.used += tokens;
            if budget.remaining == 0 {
                budget.stopped = Some("work_budget");
            }
            if consumed.is_some() {
                fits.push(key);
            }
        }
        report.size_fits = fits.len();
        fits
    });

    // Stage one: every variant on a prefix.
    let mut sampled: Vec<(f64, Lzss, usize)> = Vec::new();
    let mut try_sample = |lzss: Lzss, alternatives: usize, budget: &mut Budget, report: &mut Report| {
        let scan = budget.scan(|steps, cancelled| lzss.decode_available(sample, sample_limit, steps, cancelled))?;
        report.sample_decodes += 1;
        if scan.end == ScanEnd::InvalidToken && !padding_like(&sample[scan.consumed..]) {
            return Some(());
        }
        if scan.stats.references >= MIN_REFERENCES || fits.is_some() {
            let score = parse_score(&candidate(Codec::Lzss(lzss), sample, &scan, alternatives));
            sampled.push((score, lzss, alternatives));
        }
        Some(())
    };
    'sweep: for window_bits in WINDOW_BITS {
        for min_match in MIN_MATCHES {
            for flag_order in FLAG_ORDERS {
                for literal_flag in [true, false] {
                    for layout in LAYOUTS {
                        let base = Lzss {
                            window_bits,
                            min_match,
                            flag_order,
                            literal_flag,
                            layout,
                            offset_mode: OffsetMode::Distance,
                            initial_write_offset: 0,
                            dictionary_fill: 0,
                        };
                        if fits.as_ref().is_some_and(|fits| !fits.contains(&base)) {
                            continue;
                        }
                        for offset_mode in [OffsetMode::Distance, OffsetMode::DistanceMinusOne] {
                            report.lzss_variants += 1;
                            if try_sample(Lzss { offset_mode, ..base }, 1, &mut budget, &mut report).is_none() {
                                break 'sweep;
                            }
                        }
                        let ring = Lzss { offset_mode: OffsetMode::RingPosition, ..base };
                        // The parse does not depend on the write offset, so one scan finds the offsets to try.
                        let first = (ring.window_size() - ring.max_match()) as u16;
                        let Some(scan) = budget.scan(|steps, cancelled| {
                            Lzss { initial_write_offset: first, ..ring }.decode_available(
                                sample,
                                sample_limit.min(ring.window_size()),
                                steps,
                                cancelled,
                            )
                        }) else {
                            break 'sweep;
                        };
                        let (offsets, alternatives) = write_offsets(&ring, &scan.stats);
                        for initial_write_offset in offsets {
                            report.lzss_variants += 1;
                            let lzss = Lzss { initial_write_offset, ..ring };
                            if try_sample(lzss, alternatives, &mut budget, &mut report).is_none() {
                                break 'sweep;
                            }
                        }
                    }
                }
            }
        }
    }
    sampled.sort_by(|a, b| b.0.total_cmp(&a.0));
    sampled.truncate(if fits.is_some() { 2 * FINALISTS } else { FINALISTS });

    // Stage two: the best variants on the whole input.
    for (_, lzss, alternatives) in sampled {
        let Some(scan) = budget.scan(|steps, cancelled| lzss.decode_available(input, limit, steps, cancelled)) else {
            break;
        };
        report.full_decodes += 1;
        if options.expected_output_size.is_some_and(|expected| scan.bytes.len() != expected) {
            report.size_mismatches += 1;
            continue;
        }
        if scan.end == ScanEnd::InvalidToken && !padding_like(&input[scan.consumed..]) {
            continue;
        }
        let exercised = lzss.offset_mode == OffsetMode::RingPosition && scan.stats.unwritten_bytes != 0;
        let mut found = candidate(Codec::Lzss(lzss), input, &scan, alternatives);
        judge(&mut found, options.expected_output_size);
        report.candidates.push(found);
        if exercised {
            // The output reads the initial fill, which the stream cannot determine: each fill is a candidate
            // with the same tokens, and ranking reports them as parse-equivalent alternatives.
            for dictionary_fill in FILLS.into_iter().filter(|&fill| fill != lzss.dictionary_fill) {
                let other = Lzss { dictionary_fill, ..lzss };
                let Some(filled) =
                    budget.scan(|steps, cancelled| other.decode_available(input, limit, steps, cancelled))
                else {
                    break;
                };
                report.full_decodes += 1;
                let mut found = candidate(Codec::Lzss(other), input, &filled, alternatives);
                judge(&mut found, options.expected_output_size);
                report.candidates.push(found);
            }
        }
    }

    rank(&mut report.candidates, options.expected_output_size.is_some());
    report.steps = budget.used;
    report.stopped_early = budget.stopped;
    report
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
