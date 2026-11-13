//! Which stretches of code hold instructions at all, and which hold bytes that only become code at run time:
//! encrypted or packed code that a protection wrapper or packer decrypts or unpacks after loading.
//!
//! Every code section is measured, together with (in PE images, where each section has its own permissions) every
//! executable section without the code flag, or the executable segments when the image has no such sections. A
//! section is judged in [`WINDOW_BYTES`] windows, so a packer's clear stub beside its compressed payload, or a
//! firmware loader in front of a compressed image, stays code:
//!
//! 1. A window whose Shannon entropy is at least [`MIN_ENTROPY`] is a candidate: compiled code stays well below 8
//!    bits per byte, while encrypted or compressed bytes sit at the ceiling. Adjacent candidates join into runs.
//! 2. Each run's edges are trimmed in [`EDGE_BYTES`] blocks while a block's entropy is below [`MIN_EDGE_ENTROPY`],
//!    so a run ends close to where the random bytes do. The image's entry point runs before anything could decrypt
//!    it, so the block holding it is cut out of a run as well.
//! 3. A run of at least [`MIN_RUN_BYTES`] is judged [`Verdict::LikelyEncryptedOrPacked`] when at most
//!    [`MAX_VALID_SHARE`] of its swept bytes decode as valid instructions with the image's own decoder, on a
//!    linear sweep of windows spread across it (which for variable-length instruction sets re-synchronizes from
//!    sampled starts).
//!
//! Neither signal alone is enough: dense code can approach the entropy floor, and on instruction sets where nearly
//! every byte sequence decodes (8-bit microcontrollers) decoding says little, so those images are never judged
//! from entropy alone. The thresholds are calibrated against every fixture in the repository (see the fixture
//! margin test), and the numbers behind each verdict are reported so a reader can weigh them.

use std::ops::Range;

use rampage_arch::{Disassembler, Flow};
use rampage_loaders::{Binary, Format, Section, SectionKind};
use serde::Serialize;

use crate::memory::Memory;

/// Bytes per judged window.
pub const WINDOW_BYTES: u64 = 4096;
/// A section's last window is judged only when it holds at least this many bytes: entropy measured over few
/// bytes is biased low and noisy.
const MIN_WINDOW_BYTES: usize = 1024;
/// Entropy, in bits per byte, at or above which a window's bytes look encrypted or compressed.
pub const MIN_ENTROPY: f64 = 7.6;
/// Bytes per block when trimming a run's edges.
pub const EDGE_BYTES: usize = 512;
/// Entropy at or above which an edge block stays in its run. Random 512-byte blocks measure about 7.6.
pub const MIN_EDGE_ENTROPY: f64 = 7.0;
/// Runs shorter than this after trimming are not judged.
pub const MIN_RUN_BYTES: u64 = 8192;
/// The share of swept bytes decoding as valid instructions at or below which a run does not read as code.
pub const MAX_VALID_SHARE: f64 = 0.97;
/// Windows decoded per run, spread evenly across it.
const SAMPLES: u64 = 64;
/// Bytes decoded per sample.
const SAMPLE_BYTES: u64 = 1024;

/// The judgement on one stretch of code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// High entropy and a poor decode: the bytes are probably encrypted or packed, and only become code at run
    /// time. Functions found by exploring them would be noise, so discovery does not explore them.
    LikelyEncryptedOrPacked,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LikelyEncryptedOrPacked => "likely_encrypted_or_packed",
        }
    }
}

/// A stretch of a section judged encrypted or packed, with the evidence for it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CodeRegion {
    /// The section's name, or the executable segment's when the image has no sections.
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    /// Shannon entropy of the stretch's bytes, in bits per byte, rounded to two decimals.
    pub entropy: f64,
    /// Bytes the decode sweep covered.
    pub swept_bytes: u64,
    /// The share of swept bytes that decoded as valid instructions, rounded to three decimals.
    pub valid_share: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
}

impl CodeRegion {
    pub fn range(&self) -> Range<u64> {
        self.address..self.address.saturating_add(self.size)
    }

    pub fn contains(&self, address: u64) -> bool {
        self.range().contains(&address)
    }

    /// One line naming the verdict and the evidence for it against the thresholds.
    pub fn explain(&self) -> String {
        let verdict = self.verdict.map_or("no verdict", Verdict::as_str);
        format!(
            "{} {:#x}..{:#x}: {verdict} (entropy {:.2} >= {MIN_ENTROPY:.2}; {:.1}% of {} swept bytes decode as \
             instructions, <= {:.0}%)",
            self.name,
            self.address,
            self.address.saturating_add(self.size),
            self.entropy,
            self.valid_share * 100.0,
            self.swept_bytes,
            MAX_VALID_SHARE * 100.0
        )
    }
}

/// The stretches of code judged encrypted or packed, measured with a decoder from `new_decoder`. Images whose
/// decoder cannot be built are never judged.
pub fn assess<E>(binary: &Binary, new_decoder: impl Fn() -> Result<Box<dyn Disassembler>, E>) -> Vec<CodeRegion> {
    let mut decoder = None;
    let mut regions = Vec::new();
    for (name, address, bytes) in units(binary) {
        let entry = binary.entry.and_then(|entry| entry.checked_sub(address)).filter(|&at| at < bytes.len() as u64);
        for run in runs(bytes, entry.map(|at| at as usize)) {
            if ((run.end - run.start) as u64) < MIN_RUN_BYTES {
                continue;
            }
            let Some(decoder) = decoder.get_or_insert_with(|| new_decoder().ok()).as_mut() else {
                return Vec::new();
            };
            let start = address + run.start as u64;
            let (swept, valid) = sweep(decoder.as_mut(), &bytes[run.clone()], start);
            let valid_share = (valid as f64 / swept.max(1) as f64 * 1000.0).round() / 1000.0;
            if swept == 0 || valid_share > MAX_VALID_SHARE {
                continue;
            }
            regions.push(CodeRegion {
                name: name.to_owned(),
                address: start,
                size: (run.end - run.start) as u64,
                entropy: crate::triage::entropy(&bytes[run]),
                swept_bytes: swept,
                valid_share,
                verdict: Some(Verdict::LikelyEncryptedOrPacked),
            });
        }
    }
    regions
}

/// One measured section's evidence, for calibration: the highest entropy of any judged window, and the valid share
/// of a decode sweep over the whole section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Measurement {
    pub name: String,
    pub size: u64,
    pub max_window_entropy: f64,
    pub valid_share: f64,
}

/// Every measured section's [`Measurement`].
pub fn measure<E>(binary: &Binary, new_decoder: impl Fn() -> Result<Box<dyn Disassembler>, E>) -> Vec<Measurement> {
    let mut decoder = new_decoder().ok();
    units(binary)
        .filter(|(_, _, bytes)| bytes.len() >= MIN_WINDOW_BYTES)
        .map(|(name, address, bytes)| {
            let (swept, valid) = decoder.as_mut().map_or((0, 0), |decoder| sweep(decoder.as_mut(), bytes, address));
            let entropies = windows(bytes).map(|window| crate::triage::entropy(&bytes[window]));
            Measurement {
                name: name.to_owned(),
                size: bytes.len() as u64,
                max_window_entropy: entropies.fold(0.0, f64::max),
                valid_share: if swept == 0 { 1.0 } else { valid as f64 / swept as f64 },
            }
        })
        .collect()
}

/// The regions [`assess`] judged, as address ranges.
pub fn flagged_ranges(regions: &[CodeRegion]) -> Vec<Range<u64>> {
    regions.iter().filter(|region| region.verdict.is_some()).map(CodeRegion::range).collect()
}

/// The judged windows of a section: whole windows, and a last one of at least [`MIN_WINDOW_BYTES`].
fn windows(bytes: &[u8]) -> impl Iterator<Item = Range<usize>> + '_ {
    let size = WINDOW_BYTES as usize;
    (0..bytes.len())
        .step_by(size)
        .map(move |start| start..(start + size).min(bytes.len()))
        .filter(|window| window.len() >= MIN_WINDOW_BYTES)
}

/// The high-entropy runs of a section, as byte offsets: adjacent candidate windows joined, edges trimmed, and the
/// block holding the entry point (at offset `entry`) cut out.
fn runs(bytes: &[u8], entry: Option<usize>) -> Vec<Range<usize>> {
    let mut joined: Vec<Range<usize>> = Vec::new();
    for window in windows(bytes) {
        if crate::triage::entropy(&bytes[window.clone()]) < MIN_ENTROPY {
            continue;
        }
        match joined.last_mut() {
            Some(last) if last.end == window.start => last.end = window.end,
            _ => joined.push(window),
        }
    }
    let mut runs = Vec::new();
    for run in joined {
        match entry.filter(|at| run.contains(at)) {
            Some(at) => {
                let block = run.start + (at - run.start) / EDGE_BYTES * EDGE_BYTES;
                runs.push(trim(bytes, run.start..block));
                runs.push(trim(bytes, (block + EDGE_BYTES).min(run.end)..run.end));
            }
            None => runs.push(trim(bytes, run)),
        }
    }
    runs.retain(|run| !run.is_empty());
    runs
}

/// `run` without the low-entropy [`EDGE_BYTES`] blocks at either end.
fn trim(bytes: &[u8], mut run: Range<usize>) -> Range<usize> {
    let low = |block: &[u8]| crate::triage::entropy(block) < MIN_EDGE_ENTROPY;
    while run.len() >= EDGE_BYTES && low(&bytes[run.start..run.start + EDGE_BYTES]) {
        run.start += EDGE_BYTES;
    }
    while run.len() >= EDGE_BYTES && low(&bytes[run.end - EDGE_BYTES..run.end]) {
        run.end -= EDGE_BYTES;
    }
    if run.len() < EDGE_BYTES { run.start..run.start } else { run }
}

/// Code sections, and in PE images also executable sections without the code flag, with their file-backed bytes;
/// the executable segments when the image has no such sections.
fn units(binary: &Binary) -> impl Iterator<Item = (&str, u64, &[u8])> {
    let executable = |address| binary.segment_containing(address).is_some_and(|segment| segment.perms.execute);
    let measured = |section: &&Section| {
        section.size > 0
            && (section.kind == SectionKind::Code || (binary.format == Format::Pe && executable(section.address)))
    };
    let units: Vec<_> = if binary.sections.iter().any(|section| measured(&section)) {
        binary
            .sections
            .iter()
            .filter(measured)
            .filter_map(|section| Some((section.name.as_str(), section.address, binary.section_file_bytes(section)?)))
            .collect()
    } else {
        binary
            .segments
            .iter()
            .filter(|segment| segment.perms.execute && segment.file_size > 0)
            .filter_map(|segment| {
                let bytes = binary.read(segment.address, segment.file_size.min(segment.size))?;
                Some((segment.name.as_str(), segment.address, bytes))
            })
            .collect()
    };
    units.into_iter()
}

/// Decodes [`SAMPLES`] windows of [`SAMPLE_BYTES`] spread evenly across `bytes` and returns the bytes swept and the
/// bytes covered by valid instructions.
fn sweep(decoder: &mut dyn Disassembler, bytes: &[u8], address: u64) -> (u64, u64) {
    let len = bytes.len() as u64;
    let windows = SAMPLES.min(len.div_ceil(SAMPLE_BYTES)).max(1);
    let (mut swept, mut valid) = (0, 0);
    for window in 0..windows {
        // Window starts are kept 4-byte aligned so fixed-width instruction sets decode on instruction boundaries.
        let start = (window * len / windows) & !3;
        let end = (start + SAMPLE_BYTES).min(len);
        decoder.reset();
        let mut at = start;
        while at < end {
            let insn = decoder.decode(&bytes[at as usize..], address.wrapping_add(at));
            let step = u64::from(insn.len.max(1)).min(len - at);
            if insn.flow != Flow::Invalid && insn.len > 0 {
                valid += step;
            }
            swept += step;
            at += step;
        }
    }
    (swept, valid)
}

/// A view of `inner` in which the `excluded` ranges are not code: discovery neither starts in them nor runs into
/// them, so judged stretches yield no functions while the clear code around them is still explored.
pub struct ExcludingMemory<'a, M> {
    pub inner: &'a M,
    pub excluded: &'a [Range<u64>],
}

impl<M: Memory> ExcludingMemory<'_, M> {
    fn excluded(&self, address: u64) -> bool {
        self.excluded.iter().any(|range| range.contains(&address))
    }
}

impl<M: Memory> Memory for ExcludingMemory<'_, M> {
    fn code_from(&self, address: u64) -> Option<&[u8]> {
        if self.excluded(address) {
            return None;
        }
        let bytes = self.inner.code_from(address)?;
        // Stop where an excluded range begins, so a linear run never decodes into it.
        let limit = self
            .excluded
            .iter()
            .filter(|range| range.start > address)
            .map(|range| range.start - address)
            .min()
            .map_or(bytes.len(), |gap| bytes.len().min(usize::try_from(gap).unwrap_or(usize::MAX)));
        Some(&bytes[..limit])
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.inner.is_mapped(address)
    }

    fn is_executable(&self, address: u64) -> bool {
        !self.excluded(address) && self.inner.is_executable(address)
    }

    fn immediates_may_be_addresses(&self) -> bool {
        self.inner.immediates_may_be_addresses()
    }

    fn code_address(&self, address: u64) -> u64 {
        self.inner.code_address(address)
    }

    fn may_point_to_code(&self, address: u64) -> bool {
        self.inner.may_point_to_code(address)
    }

    fn read_pointer(&self, address: u64, size: u8) -> Option<u64> {
        self.inner.read_pointer(address, size)
    }

    fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
        self.inner.read_constant(address, size)
    }
}
