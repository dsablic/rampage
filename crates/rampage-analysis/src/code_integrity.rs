//! Whether each code region holds instructions at all, or bytes that only become code at run time: encrypted or
//! packed code that a protection wrapper or packer decrypts or unpacks after loading.
//!
//! Every code section (the executable segments, when the image has no code sections) is measured two ways. Its
//! Shannon entropy says how random its bytes are: compiled code stays well below 8 bits per byte, while
//! encrypted or compressed bytes sit at the 8-bit ceiling. A decode sweep says how much of it the image's own
//! decoder reads as valid instructions: windows spread evenly across the region are decoded linearly, which for
//! variable-length instruction sets (x86) also re-synchronizes from sampled starts. A region is judged
//! [`Verdict::LikelyEncryptedOrPacked`] only when both agree: its entropy is at least [`MIN_ENTROPY`] and at most
//! [`MAX_VALID_SHARE`] of the swept bytes decode. Neither alone is enough: dense code can approach the entropy
//! floor, and instruction sets where nearly every byte sequence is valid (8-bit microcontrollers) say little
//! through decoding, so those images are never judged from entropy alone.
//!
//! The thresholds are calibrated against every fixture in the repository (see the fixture margin test), and the
//! numbers behind each verdict are reported so a reader can weigh them.

use std::ops::Range;

use rampage_arch::{Disassembler, Flow};
use rampage_loaders::{Binary, SectionKind};
use serde::Serialize;

use crate::memory::Memory;

/// Regions smaller than this are not judged: entropy measured over few bytes is biased low and noisy.
pub const MIN_REGION_BYTES: u64 = 4096;
/// Entropy, in bits per byte, at or above which a code region's bytes look encrypted or compressed.
pub const MIN_ENTROPY: f64 = 7.6;
/// The share of swept bytes decoding as valid instructions at or below which a region does not read as code.
pub const MAX_VALID_SHARE: f64 = 0.97;
/// Windows decoded per region, spread evenly across it.
const WINDOWS: u64 = 64;
/// Bytes decoded per window.
const WINDOW_BYTES: u64 = 1024;

/// The judgement on one code region.
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

/// The measurements for one code region and the verdict they support, if any.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CodeRegion {
    /// The code section's name, or the executable segment's when the image has no code sections.
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    /// Shannon entropy of the region's file-backed bytes, in bits per byte, rounded to two decimals.
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

/// Every code region of at least [`MIN_REGION_BYTES`] file-backed bytes, measured with a decoder from
/// `new_decoder`. Images whose decoder cannot be built are measured by entropy only and never judged.
pub fn assess<E>(binary: &Binary, new_decoder: impl Fn() -> Result<Box<dyn Disassembler>, E>) -> Vec<CodeRegion> {
    let mut decoder = None;
    let mut regions = Vec::new();
    for (name, address, bytes) in units(binary) {
        if (bytes.len() as u64) < MIN_REGION_BYTES {
            continue;
        }
        let entropy = crate::triage::entropy(bytes);
        let (swept, valid) = if entropy >= MIN_ENTROPY {
            if decoder.is_none() {
                decoder = Some(new_decoder().ok());
            }
            match decoder.as_mut().and_then(Option::as_mut) {
                Some(decoder) => sweep(decoder.as_mut(), bytes, address),
                None => (0, 0),
            }
        } else {
            (0, 0)
        };
        let valid_share = if swept == 0 { 1.0 } else { ((valid as f64 / swept as f64) * 1000.0).round() / 1000.0 };
        let verdict = (swept > 0 && entropy >= MIN_ENTROPY && valid_share <= MAX_VALID_SHARE)
            .then_some(Verdict::LikelyEncryptedOrPacked);
        regions.push(CodeRegion {
            name: name.to_owned(),
            address,
            size: bytes.len() as u64,
            entropy,
            swept_bytes: swept,
            valid_share,
            verdict,
        });
    }
    regions
}

/// [`assess`], measuring every region's decode share even when its entropy alone rules out a verdict. For
/// calibration: the decode sweep is otherwise skipped for low-entropy regions.
pub fn measure<E>(binary: &Binary, new_decoder: impl Fn() -> Result<Box<dyn Disassembler>, E>) -> Vec<CodeRegion> {
    let mut decoder = new_decoder().ok();
    units(binary)
        .filter(|(_, _, bytes)| bytes.len() as u64 >= MIN_REGION_BYTES)
        .map(|(name, address, bytes)| {
            let (swept, valid) = decoder.as_mut().map_or((0, 0), |decoder| sweep(decoder.as_mut(), bytes, address));
            let valid_share = if swept == 0 { 1.0 } else { valid as f64 / swept as f64 };
            CodeRegion {
                name: name.to_owned(),
                address,
                size: bytes.len() as u64,
                entropy: crate::triage::entropy(bytes),
                swept_bytes: swept,
                valid_share,
                verdict: None,
            }
        })
        .collect()
}

/// The regions [`assess`] judged, as address ranges.
pub fn flagged_ranges(regions: &[CodeRegion]) -> Vec<Range<u64>> {
    regions.iter().filter(|region| region.verdict.is_some()).map(CodeRegion::range).collect()
}

/// Code sections with their file-backed bytes, or the executable segments when there are no code sections.
fn units(binary: &Binary) -> impl Iterator<Item = (&str, u64, &[u8])> {
    let sections: Vec<_> = binary
        .sections
        .iter()
        .filter(|section| section.kind == SectionKind::Code && section.size > 0)
        .filter_map(|section| Some((section.name.as_str(), section.address, binary.section_file_bytes(section)?)))
        .collect();
    let units = if binary.sections.iter().any(|section| section.kind == SectionKind::Code) {
        sections
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

/// Decodes [`WINDOWS`] windows spread evenly across `bytes` and returns the bytes swept and the bytes covered by
/// valid instructions.
fn sweep(decoder: &mut dyn Disassembler, bytes: &[u8], address: u64) -> (u64, u64) {
    let len = bytes.len() as u64;
    let windows = WINDOWS.min(len.div_ceil(WINDOW_BYTES)).max(1);
    let (mut swept, mut valid) = (0, 0);
    for window in 0..windows {
        // Window starts are kept 4-byte aligned so fixed-width instruction sets decode on instruction boundaries.
        let start = (window * len / windows) & !3;
        let end = (start + WINDOW_BYTES).min(len);
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

/// A view of `inner` in which the `excluded` ranges are not code: discovery neither starts
/// nor runs into them, so judged regions yield no functions.
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
