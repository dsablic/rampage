use std::ops::Range;

use rampage_arch::Arch;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{LoadError, Perms, Section, SectionKind, Segment};

/// Input cap for Sleigh-decoded profiles (every profile except the natively decoded Cortex-M and MIPS ones).
pub const MAX_RAW_BYTES: usize = 128 * 1024;
/// Input cap for the natively decoded profiles: Cortex-M flash images are typically 256 KiB to 2 MiB, MIPS boot
/// ROMs and bootloaders 64 KiB to 1 MiB.
pub const MAX_RAW_NATIVE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RAW_SEEDS: usize = 8192;
/// Regions one Raw project maps, the primary one included.
pub const MAX_RAW_REGIONS: usize = 16;
const IDENTITY_SCHEMA: &str = "rampage-raw-interpretation-v6";

/// Closed set of Raw ordinary-Project profiles, admitted family by family on Project-level evidence.
/// Every row must equal the verified native translator's metadata; the decoder factory checks this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawProfile {
    Msp430,
    Avr8,
    Mos6502,
    I8051,
    Pic16,
    SuperH2,
    V850,
    Tricore,
    Xtensa,
    Z80,
    Hcs12,
    Mc6805,
    Cr16c,
    Ebpf,
    Loongarch64,
    Hexagon,
    /// Little-endian ARMv6-M/ARMv7-M Thumb. Decoded by rampage's native ARM decoder with every byte in Thumb
    /// mode, not by a Sleigh translator; see [`RawProfile::native_decoder`].
    CortexM,
    /// Big-endian MIPS32 (o32), decoded by rampage's native MIPS decoder: boot ROMs, bootloaders and bare-metal
    /// router and camera firmware.
    Mips32Be,
    /// Little-endian MIPS32 (o32), decoded natively, as [`RawProfile::Mips32Be`].
    Mips32Le,
}

/// Which decoder serves a Raw profile's discovery, listing and search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDecoder {
    /// The bundled Sleigh translator of `language_id`, whose metadata must equal the profile's facts.
    Sleigh,
    /// rampage's native decoder for `arch`, with the whole mapped range in Thumb mode.
    NativeThumb,
    /// rampage's native decoder for `arch` (MIPS32, Xtensa), with no mode to choose.
    Native,
}

struct RawProfileFacts {
    profile: RawProfile,
    language_id: &'static str,
    arch: Arch,
    big_endian: bool,
    code_big_endian: bool,
    code_space: RawCodeSpace,
    parallel_helper: Option<&'static str>,
    decoder: RawDecoder,
}

const fn space(
    name: &'static str,
    address_size: u8,
    word_size: u8,
    highest_byte: u64,
    instruction_alignment: u8,
) -> RawCodeSpace {
    RawCodeSpace { name, address_size, word_size, highest_byte, instruction_alignment }
}

const fn facts(
    profile: RawProfile,
    language_id: &'static str,
    arch: Arch,
    big_endian: bool,
    code_space: RawCodeSpace,
) -> RawProfileFacts {
    RawProfileFacts {
        profile,
        language_id,
        arch,
        big_endian,
        code_big_endian: big_endian,
        code_space,
        parallel_helper: None,
        decoder: RawDecoder::Sleigh,
    }
}

const HEXAGON_PARALLEL_HELPER: &str = "ghidra.app.util.viewer.field.HexagonParallelInstructionHelper";

// Indexed by discriminant. Encoded address size and word units are not C-pointer defaults or cross-translator
// space IDs; alignments are the SLA's declared instruction alignment, not the shortest encoding.
// The Cortex-M row's code space is ARM8_le.sla's `ram` space; no Sleigh translator decodes that profile.
const PROFILE_FACTS: [RawProfileFacts; 19] = [
    facts(RawProfile::Msp430, "TI_MSP430:LE:16:default", Arch::Msp430, false, space("RAM", 2, 1, 0xffff, 2)),
    facts(RawProfile::Avr8, "avr8:LE:16:default", Arch::Avr8, false, space("code", 2, 2, 0x1ffff, 2)),
    facts(RawProfile::Mos6502, "6502:LE:16:default", Arch::Mos6502, false, space("RAM", 2, 1, 0xffff, 1)),
    facts(RawProfile::I8051, "8051:BE:16:default", Arch::I8051, true, space("CODE", 2, 1, 0xffff, 1)),
    facts(RawProfile::Pic16, "PIC-16:LE:16:PIC-16", Arch::Pic16, false, space("CODE", 2, 2, 0x1ffff, 2)),
    facts(RawProfile::SuperH2, "SuperH:BE:32:SH-2", Arch::Sh2, true, space("ram", 4, 1, 0xffff_ffff, 1)),
    facts(RawProfile::V850, "V850:LE:32:default", Arch::V850, false, space("ram", 4, 1, 0xffff_ffff, 2)),
    facts(RawProfile::Tricore, "tricore:LE:32:default", Arch::Tricore, false, space("ram", 4, 1, 0xffff_ffff, 2)),
    RawProfileFacts {
        decoder: RawDecoder::Native,
        ..facts(RawProfile::Xtensa, "Xtensa:LE:32:default", Arch::Xtensa, false, space("ram", 4, 1, 0xffff_ffff, 1))
    },
    facts(RawProfile::Z80, "z80:LE:16:default", Arch::Z80, false, space("ram", 2, 1, 0xffff, 1)),
    facts(RawProfile::Hcs12, "HCS-12:BE:24:default", Arch::Hcs12, true, space("RAM", 3, 1, 0xff_ffff, 1)),
    facts(RawProfile::Mc6805, "6805:BE:16:default", Arch::Mc6805, true, space("RAM", 2, 1, 0xffff, 1)),
    facts(RawProfile::Cr16c, "CR16C:LE:16:default", Arch::Cr16c, false, space("ram", 4, 1, 0xffff_ffff, 2)),
    facts(RawProfile::Ebpf, "eBPF:LE:64:default", Arch::Ebpf, false, space("ram", 8, 1, u64::MAX, 1)),
    facts(RawProfile::Loongarch64, "Loongarch:LE:64:lp64d", Arch::Loongarch64, false, space("ram", 8, 1, u64::MAX, 4)),
    RawProfileFacts {
        parallel_helper: Some(HEXAGON_PARALLEL_HELPER),
        ..facts(RawProfile::Hexagon, "Hexagon:LE:32:default", Arch::Hexagon, false, space("ram", 4, 1, 0xffff_ffff, 4))
    },
    RawProfileFacts {
        decoder: RawDecoder::NativeThumb,
        ..facts(RawProfile::CortexM, "ARM:LE:32:Cortex", Arch::Arm, false, space("ram", 4, 1, 0xffff_ffff, 2))
    },
    RawProfileFacts {
        decoder: RawDecoder::Native,
        ..facts(RawProfile::Mips32Be, "MIPS:BE:32:default", Arch::Mips, true, space("ram", 4, 1, 0xffff_ffff, 4))
    },
    RawProfileFacts {
        decoder: RawDecoder::Native,
        ..facts(RawProfile::Mips32Le, "MIPS:LE:32:default", Arch::Mips, false, space("ram", 4, 1, 0xffff_ffff, 4))
    },
];

impl RawProfile {
    pub const ALL: [RawProfile; PROFILE_FACTS.len()] = {
        let mut all = [RawProfile::Msp430; PROFILE_FACTS.len()];
        let mut index = 0;
        while index < PROFILE_FACTS.len() {
            all[index] = PROFILE_FACTS[index].profile;
            index += 1;
        }
        all
    };

    fn facts(self) -> &'static RawProfileFacts {
        &PROFILE_FACTS[self as usize]
    }

    pub fn from_language_id(language: &str) -> Result<Self, LoadError> {
        PROFILE_FACTS
            .iter()
            .find(|facts| facts.language_id == language)
            .map(|facts| facts.profile)
            .ok_or_else(|| LoadError::Unsupported(format!("Raw profile {language:?}")))
    }

    pub fn language_id(self) -> &'static str {
        self.facts().language_id
    }

    /// Real identity without a legacy pointer width or native decoder, never an existing-architecture alias.
    pub fn arch(self) -> Arch {
        self.facts().arch
    }

    /// Translator data byte order.
    pub fn big_endian(self) -> bool {
        self.facts().big_endian
    }

    /// Default code-space byte order.
    pub fn code_big_endian(self) -> bool {
        self.facts().code_big_endian
    }

    /// Declared processor-spec parallel helper; helper-gated instructions still serialize unknown flow.
    pub fn parallel_helper(self) -> Option<&'static str> {
        self.facts().parallel_helper
    }

    /// Closed profile facts. The decoder factory must check these against its verified translator.
    pub fn code_space(self) -> RawCodeSpace {
        self.facts().code_space
    }

    /// Whether rampage's native decoder for [`Self::arch`] serves this profile (Cortex-M with the whole mapped range
    /// in Thumb mode, or MIPS32) instead of a Sleigh translator. Such a profile has typed operands, data references
    /// and a pointer width; the others have none of these.
    pub fn native_decoder(self) -> bool {
        self.facts().decoder != RawDecoder::Sleigh
    }

    /// Whether the profile is MIPS32: the entry defaults to the base address (a boot ROM's reset vector).
    pub fn mips(self) -> bool {
        matches!(self, RawProfile::Mips32Be | RawProfile::Mips32Le)
    }

    /// Whether the profile is an ARMv6-M/ARMv7-M(E) processor: all code Thumb, no A32 state, the M-profile
    /// instruction set and a Cortex-M vector table.
    pub fn m_profile(self) -> bool {
        self == RawProfile::CortexM
    }

    /// Largest admitted input: 4 MiB for the natively decoded profiles, 128 KiB for Sleigh-decoded ones.
    pub fn max_bytes(self) -> usize {
        if self.native_decoder() { MAX_RAW_NATIVE_BYTES } else { MAX_RAW_BYTES }
    }
}

impl Serialize for RawProfile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.language_id())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RawCodeSpace {
    pub name: &'static str,
    pub address_size: u8,
    pub word_size: u8,
    pub highest_byte: u64,
    pub instruction_alignment: u8,
}

#[derive(Debug, Clone)]
pub struct RawCodeOptions {
    pub profile: RawProfile,
    pub base: u64,
    pub entry: Option<u64>,
    pub seeds: Vec<u64>,
    /// Cortex-M only: the code-space byte address of a vector table to read the initial SP and handler words
    /// from. Accepted handlers become the entry (Reset, unless `entry` is given) and seeds.
    pub vector_table: Option<u64>,
    /// Cortex-M only: scan the image for tables of Thumb code pointers. Targets of accepted tables become seeds.
    pub pointer_tables: bool,
}

/// What an additional region holds, which fixes its permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRegionKind {
    /// Executable bytes the program does not write (flash, or a stage copied to RAM and then run): `r-x`.
    /// Discovery seeds may lie here, and on Cortex-M its literal pools fold as constants.
    Code,
    /// Constant bytes: `r--`.
    Data,
    /// Memory the program writes: `rw-`. With bytes they are initial values, never constants; without bytes it
    /// is zero-filled or uninitialised RAM, or memory-mapped I/O.
    Ram,
}

impl RawRegionKind {
    fn name(self) -> &'static str {
        match self {
            RawRegionKind::Code => "code",
            RawRegionKind::Data => "data",
            RawRegionKind::Ram => "ram",
        }
    }

    fn perms(self) -> Perms {
        Perms { read: true, write: self == RawRegionKind::Ram, execute: self == RawRegionKind::Code }
    }
}

/// Where a region's bytes came from, as the opener states it. Reported with the region and bound by the
/// interpretation identity; the loader itself reads no file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RawRegionSource {
    /// `length` bytes at `offset` of the opened file, mapped as they are.
    FileRange { offset: u64, length: u64 },
    /// The output of a decoder provider over `length` bytes at `offset` of the opened file. `receipt` is the
    /// provider's receipt (codec, parameters, source-range and output hashes); the decoded bytes exist only in
    /// memory.
    Decoded { offset: u64, length: u64, receipt: serde_json::Value },
    /// A contiguous run of data records of an Intel HEX or S-record file; the address comes from the records.
    Records { format: crate::raw_records::RawRecordFormat },
    /// A copy of `length` bytes at `offset` of the earlier backed region named `region` (`raw.code` for the
    /// primary one, decoded bytes included), mapped at this region's base: code or data a program copies to its
    /// run address. The opener passes no bytes; admission copies them.
    Slice { region: String, offset: u64, length: u64 },
    /// Mapped from `scatter_load.copies[copy]`: a copy of `offset` onwards in the region named `region`, or a
    /// zero fill (no region, no bytes) the reset code made.
    ScatterLoad {
        copy: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
    },
    /// No bytes: zero-filled or uninitialised RAM, or memory-mapped I/O.
    Unbacked,
    /// Segment `segment` of the ESP app image at `image_offset` of the opened file, whose `length` bytes lie at
    /// `offset`; the load address comes from the segment header.
    EspSegment { image_offset: u64, segment: usize, offset: u64, length: u64 },
}

/// One additional region of a Raw project: an analyst-stated mapping of `bytes`, or of `size` unbacked bytes.
#[derive(Debug, Clone)]
pub struct RawRegion {
    pub kind: RawRegionKind,
    /// Code-space byte address of the first byte.
    pub base: u64,
    /// Mapped byte count; equal to the byte count when `bytes` is given.
    pub size: u64,
    /// The region's bytes; `None` only for an unbacked [`RawRegionKind::Ram`] region.
    pub bytes: Option<Vec<u8>>,
    pub source: RawRegionSource,
}

/// A record file's facts that are not region bytes.
#[derive(Debug, Clone, Copy)]
pub struct RawRecordFacts {
    pub format: crate::raw_records::RawRecordFormat,
    pub data_records: usize,
    pub start_address: Option<u64>,
}

/// Everything one Raw project maps: the primary code region of `options`, further regions, and record facts.
#[derive(Debug, Clone)]
pub struct RawImage {
    /// The primary code region's bytes, mapped at `options.base`.
    pub bytes: Vec<u8>,
    pub options: RawCodeOptions,
    /// Where the primary region's bytes came from, when the opener states it.
    pub source: Option<RawRegionSource>,
    /// Additional regions; only the natively decoded Cortex-M profile admits any.
    pub regions: Vec<RawRegion>,
    pub records: Option<RawRecordFacts>,
    /// The ESP app image the regions were read from, when the opener read one.
    pub esp: Option<crate::esp::EspImage>,
    /// Cortex-M only: follow the reset code from the entry for scatter-load copies ([`crate::raw_scatter`]).
    /// `Some(true)` also maps each well-evidenced copy at its run address; `Some(false)` reports them only;
    /// `None` does not follow.
    pub scatter_load: Option<bool>,
}

/// One mapped region as admitted, the primary code region first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawRegionInfo {
    /// The segment and section name: `raw.code` for the primary region, `raw.<kind>.<index>` for the others.
    pub name: String,
    pub kind: RawRegionKind,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    /// Mapped bytes.
    pub length: u64,
    /// SHA-256 of the mapped bytes; absent for an unbacked region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<RawRegionSource>,
    /// Offset of the region's bytes in the project's owned bytes.
    #[serde(skip)]
    data_offset: u64,
}

impl RawRegionInfo {
    pub fn range(&self) -> Range<u64> {
        self.base_address..self.base_address + self.length
    }

    /// Whether the region has bytes; an unbacked region reads as nothing.
    pub fn backed(&self) -> bool {
        self.sha256.is_some()
    }

    /// The region's bytes in the project's owned bytes; empty for an unbacked region.
    pub fn data_range(&self) -> Range<usize> {
        let start = self.data_offset as usize;
        start..start + if self.backed() { self.length as usize } else { 0 }
    }

    fn segment(&self) -> Segment {
        Segment {
            name: self.name.clone(),
            address: self.base_address,
            size: self.length,
            file_offset: self.data_offset,
            file_size: if self.backed() { self.length } else { 0 },
            perms: self.kind.perms(),
        }
    }

    fn section(&self) -> Section {
        let kind = match (self.kind, self.backed()) {
            (RawRegionKind::Code, _) => SectionKind::Code,
            (RawRegionKind::Data, _) => SectionKind::ReadOnlyData,
            (RawRegionKind::Ram, true) => SectionKind::Data,
            (RawRegionKind::Ram, false) => SectionKind::UninitializedData,
        };
        Section {
            name: self.name.clone(),
            address: self.base_address,
            size: self.length,
            kind,
            file_offset: self.backed().then_some(self.data_offset),
            file_size: if self.backed() { self.length } else { 0 },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawStartStatus {
    /// Inside a code region: used as the entry, or as a seed when `entry` or the vector table's Reset names
    /// another address.
    Accepted,
    /// Zero with no code mapped there: the record states no start address.
    Empty,
    /// Not used; `refused_reason` says why.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawStartRefusedReason {
    /// Outside every mapped code region.
    OutsideCode,
    /// Violates the profile's instruction alignment.
    Unaligned,
    /// Inside the vector table that was read: table words, not an instruction.
    InVectorTable,
}

/// The start-address record of a record file and the verdict on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawStartAddress {
    /// The record's value as written.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub word: u64,
    pub status: RawStartStatus,
    /// The instruction it names (a Thumb bit cleared), when accepted.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<RawStartRefusedReason>,
}

/// What a record file contributed besides region bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawRecordsEvidence {
    pub format: crate::raw_records::RawRecordFormat,
    pub data_records: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_address: Option<RawStartAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawCodeImage {
    profile: RawProfile,
    base: u64,
    length: u64,
    end: u64,
    entry: Option<u64>,
    seeds: Vec<u64>,
    regions: Vec<RawRegionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<RawRecordsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vector_table: Option<crate::raw_vectors::VectorTable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer_tables: Option<crate::raw_pointers::PointerTables>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scatter_load: Option<crate::raw_scatter::ScatterLoad>,
    #[serde(skip_serializing_if = "Option::is_none")]
    esp: Option<crate::esp::EspImage>,
    /// Whether scatter-load copies were followed, and mapped.
    #[serde(skip)]
    scatter_load_mode: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawInterpretationIdentity {
    pub schema: &'static str,
    pub sha256: String,
}

#[cfg(test)]
thread_local! {
    /// Whole-image identity hashes computed on this thread.
    pub(crate) static IDENTITY_HASHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn sha256_hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

impl RawCodeImage {
    /// Admits `image` and returns the retained facts with the project's owned bytes: the primary region's bytes
    /// followed by every other backed region's, in region order.
    pub(crate) fn admit(image: RawImage) -> Result<(Self, Vec<u8>), LoadError> {
        let RawImage { bytes, mut options, source, regions: extra, records, esp, scatter_load: scatter_load_mode } =
            image;
        if esp.as_ref().is_some_and(|esp| !esp.chip.xtensa())
            || (esp.is_some() && options.profile != RawProfile::Xtensa)
        {
            return Err(LoadError::Malformed("Raw ESP app images are read only with the Xtensa profile".into()));
        }
        let length = bytes.len();
        let max = options.profile.max_bytes();
        if length == 0 || length > max || options.seeds.len() > MAX_RAW_SEEDS {
            return Err(LoadError::Malformed(format!(
                "Raw {} requires 1..={} KiB and at most 8192 supplied seeds",
                options.profile.language_id(),
                max / 1024
            )));
        }
        let length = u64::try_from(length).map_err(|_| LoadError::Malformed("Raw length overflows".into()))?;
        let space = options.profile.code_space();
        let alignment = u64::from(space.instruction_alignment);
        if !options.base.is_multiple_of(alignment) {
            return Err(LoadError::Malformed("Raw base violates profile instruction alignment".into()));
        }
        let end = checked_code_end(options.base, length, space.highest_byte)?;
        let mut regions = vec![RawRegionInfo {
            name: "raw.code".into(),
            kind: RawRegionKind::Code,
            base_address: options.base,
            length,
            sha256: Some(sha256_hex(&bytes)),
            source,
            data_offset: 0,
        }];
        let mut data = bytes;
        if !extra.is_empty() && !options.profile.native_decoder() {
            return Err(LoadError::Malformed(format!(
                "Raw {} maps one code region: additional regions are defined only for ARM:LE:32:Cortex, MIPS and \
                 Xtensa",
                options.profile.language_id()
            )));
        }
        if extra.len() >= MAX_RAW_REGIONS {
            return Err(LoadError::Malformed(format!(
                "Raw maps at most {MAX_RAW_REGIONS} regions, the primary one included"
            )));
        }
        for (index, mut region) in extra.into_iter().enumerate() {
            let name = format!("raw.{}.{}", region.kind.name(), index + 1);
            let refuse = |message: &str| Err(LoadError::Malformed(format!("Raw region {name}: {message}")));
            if matches!(region.source, RawRegionSource::ScatterLoad { .. }) {
                return refuse("scatter-load regions are derived at admission, never stated");
            }
            if let RawRegionSource::Slice { region: from, offset, length } = &region.source {
                if region.bytes.is_some() || region.size != *length {
                    return refuse("a slice takes its bytes from its source region; size must equal its length");
                }
                match slice_bytes(&regions, &data, from, *offset, *length, max - data.len()) {
                    Ok(bytes) => region.bytes = Some(bytes),
                    Err(message) => return refuse(&message),
                }
            }
            match &region.bytes {
                Some(bytes) if bytes.len() as u64 != region.size => {
                    return refuse("size disagrees with its bytes");
                }
                Some(_) if region.source == RawRegionSource::Unbacked => {
                    return refuse("an unbacked source has no bytes");
                }
                None if region.kind != RawRegionKind::Ram || region.source != RawRegionSource::Unbacked => {
                    return refuse("only a ram region may be unbacked; code and data need bytes");
                }
                _ => {}
            }
            if region.kind == RawRegionKind::Code && !region.base.is_multiple_of(alignment) {
                return refuse("base violates profile instruction alignment");
            }
            if let Err(error) = checked_code_end(region.base, region.size, space.highest_byte) {
                return refuse(&error.to_string());
            }
            let backed = region.bytes.as_deref().unwrap_or_default();
            if data.len() + backed.len() > max {
                return Err(LoadError::Malformed(format!(
                    "Raw {} regions together hold more than {} KiB of bytes",
                    options.profile.language_id(),
                    max / 1024
                )));
            }
            let info = RawRegionInfo {
                name,
                kind: region.kind,
                base_address: region.base,
                length: region.size,
                sha256: region.bytes.as_deref().map(sha256_hex),
                source: Some(region.source),
                data_offset: data.len() as u64,
            };
            data.extend_from_slice(backed);
            regions.push(info);
        }
        let mut by_address: Vec<&RawRegionInfo> = regions.iter().collect();
        by_address.sort_by_key(|region| region.base_address);
        if let Some(pair) = by_address.windows(2).find(|pair| pair[0].range().end > pair[1].base_address) {
            return Err(LoadError::Malformed(format!(
                "Raw regions overlap: {} {:#x}..{:#x} and {} {:#x}..{:#x}",
                pair[0].name,
                pair[0].base_address,
                pair[0].range().end,
                pair[1].name,
                pair[1].base_address,
                pair[1].range().end
            )));
        }
        let in_code = |address: u64| {
            regions.iter().any(|region| region.kind == RawRegionKind::Code && region.range().contains(&address))
        };
        if options.profile.m_profile() {
            // Thumb code pointers carry bit 0; the instruction starts at the even address.
            options.entry = options.entry.map(|entry| entry & !1);
            options.seeds.iter_mut().for_each(|seed| *seed &= !1);
        }
        // A MIPS image mapped without an entry starts at its base, as a boot ROM does at the reset vector
        // (0xbfc00000 on MIPS32).
        let entry_from_base = options.profile.mips() && options.entry.is_none();
        if entry_from_base {
            options.entry = Some(options.base);
        }
        let check_start = |address: u64| {
            if !address.is_multiple_of(alignment) || !in_code(address) {
                return Err(LoadError::Malformed("Raw entry/seed must be aligned and backed by code bytes".into()));
            }
            Ok(())
        };
        if let Some(entry) = options.entry {
            check_start(entry).map_err(|error| match entry_from_base {
                true => LoadError::Malformed(format!(
                    "Raw {} takes base_address {:#x} as the entry when none is given: it must be {alignment}-byte \
                     aligned with code bytes there (or give `entry`)",
                    options.profile.language_id(),
                    options.base
                )),
                false => error,
            })?;
        }
        for &seed in &options.seeds {
            check_start(seed)?;
        }
        // The vector table is read from the primary region only; its targets lie inside it.
        let primary = &data[..length as usize];
        let vector_table = match options.vector_table {
            None => None,
            Some(_) if !options.profile.m_profile() => {
                return Err(LoadError::Malformed(
                    "Raw vector-table seeding is defined only for ARM:LE:32:Cortex".into(),
                ));
            }
            Some(address) => {
                let ram = |address: u64| {
                    regions.iter().any(|region| region.kind == RawRegionKind::Ram && region.range().contains(&address))
                };
                let table = crate::raw_vectors::read_reset_table(primary, options.base, address, &ram)?;
                if let Some(reset) = table.reset() {
                    match options.entry {
                        None => options.entry = Some(reset),
                        Some(entry) if entry != reset => options.seeds.push(reset),
                        Some(_) => {}
                    }
                }
                let entry = options.entry;
                options.seeds.extend(table.handlers().filter(|&handler| Some(handler) != entry));
                Some(table)
            }
        };
        let table_words = vector_table.as_ref().map(|table| table.address..table.address + 4 * table.words_read as u64);
        let records = records.map(|facts| {
            let start_address = facts.start_address.map(|word| {
                let target = if options.profile.m_profile() { word & !1 } else { word };
                let refused = if !in_code(target) {
                    Some(RawStartRefusedReason::OutsideCode)
                } else if !target.is_multiple_of(alignment) {
                    Some(RawStartRefusedReason::Unaligned)
                } else if table_words.as_ref().is_some_and(|table| table.contains(&target)) {
                    Some(RawStartRefusedReason::InVectorTable)
                } else {
                    None
                };
                let status = match refused {
                    None => RawStartStatus::Accepted,
                    Some(RawStartRefusedReason::OutsideCode) if word == 0 => RawStartStatus::Empty,
                    Some(_) => RawStartStatus::Refused,
                };
                RawStartAddress {
                    word,
                    status,
                    target: (status == RawStartStatus::Accepted).then_some(target),
                    refused_reason: refused.filter(|_| status == RawStartStatus::Refused),
                }
            });
            RawRecordsEvidence { format: facts.format, data_records: facts.data_records, start_address }
        });
        if let Some(start) = records.as_ref().and_then(|records| records.start_address.as_ref()?.target) {
            match options.entry {
                None => options.entry = Some(start),
                Some(entry) if entry != start => options.seeds.push(start),
                Some(_) => {}
            }
        }
        let scatter_load = match (scatter_load_mode, options.entry) {
            (Some(map), Some(entry)) if options.profile.m_profile() => {
                let mut report = scatter_regions(&mut regions, &mut data, entry, map, max);
                let in_code = |address: u64| {
                    regions.iter().any(|region| region.kind == RawRegionKind::Code && region.range().contains(&address))
                };
                // The jump into copied code starts a function there, once that code is mapped.
                if let Some(target) = report.continues_at
                    && target != entry
                    && in_code(target)
                {
                    options.seeds.push(target);
                }
                // The vector table the program installs last, once the memory holding it is mapped.
                if let Some(store) = report.last_vtor_store.clone() {
                    let holder = regions.iter().find(|region| region.backed() && region.range().contains(&store.value));
                    match holder {
                        None => {
                            report.vector_table_refused = Some(format!(
                                "VTOR value {:#x} lies in no region with bytes: the program fills that table at run \
                                 time, so its interrupt handlers are not seeded; `xrefs` to {:#x} and the stores \
                                 after it show the code that fills it",
                                store.value, store.value
                            ));
                        }
                        Some(region) => {
                            match crate::raw_vectors::read_with(
                                &data[region.data_range()],
                                region.base_address,
                                store.value,
                                &in_code,
                            ) {
                                Ok(table) => {
                                    options
                                        .seeds
                                        .extend(table.handlers().filter(|&handler| Some(handler) != options.entry));
                                    report.vector_table = Some(table);
                                }
                                Err(error) => report.vector_table_refused = Some(error.to_string()),
                            }
                        }
                    }
                }
                Some(report)
            }
            _ => None,
        };
        let primary = &data[..length as usize];
        let pointer_tables = if !options.pointer_tables {
            None
        } else if !options.profile.m_profile() {
            return Err(LoadError::Malformed("Raw pointer-table seeding is defined only for ARM:LE:32:Cortex".into()));
        } else {
            let mut tables = crate::raw_pointers::scan(primary, options.base, table_words);
            // Code mapped elsewhere (startup copies, further regions) holds its own tables, such as an init-hook
            // array in code copied to TCM.
            for region in regions.iter().filter(|region| {
                region.kind == RawRegionKind::Code && region.backed() && region.base_address != options.base
            }) {
                tables.merge(crate::raw_pointers::scan(&data[region.data_range()], region.base_address, None));
            }
            let entry = options.entry;
            // Tables repeat targets (a default handler in many slots): dedupe before they meet the seed cap.
            let targets: std::collections::BTreeSet<u64> = tables.targets().collect();
            options.seeds.extend(targets.into_iter().filter(|&target| Some(target) != entry));
            Some(tables)
        };
        options.seeds.sort_unstable();
        options.seeds.dedup();
        if options.seeds.len() > MAX_RAW_SEEDS {
            return Err(LoadError::Malformed(
                "Raw accepts at most 8192 seeds, vector-table handlers and pointer-table targets included".into(),
            ));
        }
        let image = Self {
            profile: options.profile,
            base: options.base,
            length,
            end,
            entry: options.entry,
            seeds: options.seeds,
            regions,
            records,
            vector_table,
            pointer_tables,
            scatter_load,
            esp,
            scatter_load_mode,
        };
        Ok((image, data))
    }

    pub fn profile(&self) -> RawProfile {
        self.profile
    }

    /// The ESP app image the project was read from.
    pub fn esp(&self) -> Option<&crate::esp::EspImage> {
        self.esp.as_ref()
    }

    /// Whether the code uses Xtensa's call0 ABI: an ESP8266 app image.
    pub fn xtensa_call0(&self) -> bool {
        self.esp.as_ref().is_some_and(|esp| esp.chip.call0())
    }

    /// Base address of the primary code region.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Byte count of the primary code region.
    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn entry(&self) -> Option<u64> {
        self.entry
    }

    pub fn seeds(&self) -> &[u64] {
        &self.seeds
    }

    /// Every mapped region, the primary code region first, then the additional ones in the order given.
    pub fn regions(&self) -> &[RawRegionInfo] {
        &self.regions
    }

    /// Bytes all backed regions hold together: the length of the project's owned bytes.
    pub fn backed_bytes(&self) -> u64 {
        self.regions.iter().filter(|region| region.backed()).map(|region| region.length).sum()
    }

    /// What a record file contributed besides region bytes, when the project was opened from one.
    pub fn records(&self) -> Option<&RawRecordsEvidence> {
        self.records.as_ref()
    }

    /// Evidence for every vector read when vector-table seeding was requested.
    pub fn vector_table(&self) -> Option<&crate::raw_vectors::VectorTable> {
        self.vector_table.as_ref()
    }

    /// Evidence for every pointer table found when pointer-table seeding was requested.
    /// What following the reset code found, when scatter-load following was requested on a Cortex-M image with an
    /// entry.
    pub fn scatter_load(&self) -> Option<&crate::raw_scatter::ScatterLoad> {
        self.scatter_load.as_ref()
    }

    pub fn pointer_tables(&self) -> Option<&crate::raw_pointers::PointerTables> {
        self.pointer_tables.as_ref()
    }

    /// The Thumb-mode ranges a native decoder reads: every code region for the Cortex-M profile.
    pub fn thumb_ranges(&self) -> Vec<Range<u64>> {
        if self.profile.m_profile() { self.code_ranges() } else { Vec::new() }
    }

    /// The primary code region's range.
    pub fn range(&self) -> Range<u64> {
        self.base..self.end
    }

    /// Every code region's range, ascending.
    pub fn code_ranges(&self) -> Vec<Range<u64>> {
        let mut ranges: Vec<Range<u64>> =
            self.regions.iter().filter(|region| region.kind == RawRegionKind::Code).map(RawRegionInfo::range).collect();
        ranges.sort_by_key(|range| range.start);
        ranges
    }

    pub(crate) fn segments(&self) -> Vec<Segment> {
        self.regions.iter().map(RawRegionInfo::segment).collect()
    }

    /// The same admission facts over replacement owned bytes of the same length: each backed region's SHA-256 is
    /// recomputed; entry, seeds and vector/pointer-table evidence stay those of the admitted bytes.
    pub(crate) fn with_bytes(&self, data: &[u8]) -> Self {
        let mut image = self.clone();
        for region in image.regions.iter_mut().filter(|region| region.backed()) {
            region.sha256 = Some(sha256_hex(&data[region.data_range()]));
        }
        image
    }

    pub(crate) fn sections(&self) -> Vec<Section> {
        self.regions.iter().map(RawRegionInfo::section).collect()
    }

    pub(crate) fn identity(&self, bytes: &[u8]) -> RawInterpretationIdentity {
        #[cfg(test)]
        IDENTITY_HASHES.with(|count| count.set(count.get() + 1));
        let mut hash = Sha256::new();
        let text = |hash: &mut Sha256, text: &str| {
            hash.update((text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        };
        text(&mut hash, IDENTITY_SCHEMA);
        text(&mut hash, self.profile.language_id());
        let space = self.profile.code_space();
        text(&mut hash, space.name);
        hash.update([space.address_size, space.word_size, space.instruction_alignment]);
        hash.update(space.highest_byte.to_be_bytes());
        hash.update([u8::from(self.profile.big_endian()), u8::from(self.profile.code_big_endian())]);
        // Schema v5 binds every region: kind, mapping, where its bytes lie in `bytes`, and the stated source.
        hash.update((self.regions.len() as u64).to_be_bytes());
        for region in &self.regions {
            hash.update([region.kind as u8, u8::from(region.backed())]);
            for value in [region.base_address, region.length, region.data_offset] {
                hash.update(value.to_be_bytes());
            }
            match &region.source {
                None => hash.update([0]),
                Some(RawRegionSource::FileRange { offset, length }) => {
                    hash.update([1]);
                    hash.update(offset.to_be_bytes());
                    hash.update(length.to_be_bytes());
                }
                Some(RawRegionSource::Decoded { offset, length, receipt }) => {
                    hash.update([2]);
                    hash.update(offset.to_be_bytes());
                    hash.update(length.to_be_bytes());
                    // The deadline and the whole file's size do not change the decoded bytes.
                    let mut receipt = receipt.clone();
                    if let Some(object) = receipt.as_object_mut() {
                        object.remove("decode_timeout_ms");
                        object.remove("source_size");
                    }
                    text(&mut hash, &receipt.to_string());
                }
                Some(RawRegionSource::Records { format }) => hash.update([3, *format as u8]),
                Some(RawRegionSource::Unbacked) => hash.update([4]),
                Some(RawRegionSource::EspSegment { image_offset, segment, offset, length }) => {
                    hash.update([7]);
                    for value in [*image_offset, *segment as u64, *offset, *length] {
                        hash.update(value.to_be_bytes());
                    }
                }
                // Schema v6 binds a slice's source region and range.
                Some(RawRegionSource::Slice { region, offset, length }) => {
                    hash.update([5]);
                    text(&mut hash, region);
                    hash.update(offset.to_be_bytes());
                    hash.update(length.to_be_bytes());
                }
                // Schema v6 binds a scatter-load region's copy and source; the copy itself follows from the bytes.
                Some(RawRegionSource::ScatterLoad { copy, region, offset }) => {
                    hash.update([6]);
                    hash.update((*copy as u64).to_be_bytes());
                    text(&mut hash, region.as_deref().unwrap_or(""));
                    hash.update(offset.unwrap_or(u64::MAX).to_be_bytes());
                }
            }
        }
        // Schema v6 binds whether the reset code was followed, and whether its copies were mapped.
        hash.update([match self.scatter_load_mode {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        }]);
        // An ESP app image binds its chip, which decides the ABI the code is decompiled with.
        if let Some(esp) = &self.esp {
            hash.update([8, esp.chip as u8]);
        }
        for value in [self.base, self.length, self.end] {
            hash.update(value.to_be_bytes());
        }
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        hash.update([u8::from(self.entry.is_some())]);
        if let Some(entry) = self.entry {
            hash.update(entry.to_be_bytes());
        }
        hash.update((self.seeds.len() as u64).to_be_bytes());
        for seed in &self.seeds {
            hash.update(seed.to_be_bytes());
        }
        // Schema v3 binds the requested vector-table address; its evidence is a function of bytes and address.
        let table = self.vector_table.as_ref().map(|table| table.address);
        hash.update([u8::from(table.is_some())]);
        hash.update(table.unwrap_or(0).to_be_bytes());
        // Schema v4 binds whether pointer tables were scanned; their evidence is a function of bytes and mapping.
        hash.update([u8::from(self.pointer_tables.is_some())]);
        // Schema v5 binds the record format, record count and start-address word; the verdict follows from them.
        match &self.records {
            None => hash.update([0]),
            Some(records) => {
                hash.update([1, records.format as u8]);
                hash.update((records.data_records as u64).to_be_bytes());
                let word = records.start_address.as_ref().map(|start| start.word);
                hash.update([u8::from(word.is_some())]);
                hash.update(word.unwrap_or(0).to_be_bytes());
            }
        }
        RawInterpretationIdentity { schema: IDENTITY_SCHEMA, sha256: rampage_arch::hex::bytes(&hash.finalize()) }
    }
}

/// Follows the reset code at `entry` over the admitted `regions` and, when `map`, maps each well-evidenced write at
/// its run address as a further region: a complete copy whose source lies in one backed region, or a complete zero
/// fill, whose destination no region maps, within the region and byte caps. Returns the report, every write's
/// mapping or the reason it was not mapped included.
fn scatter_regions(
    regions: &mut Vec<RawRegionInfo>,
    data: &mut Vec<u8>,
    entry: u64,
    map: bool,
    max: usize,
) -> crate::raw_scatter::ScatterLoad {
    use crate::raw_scatter::{CopyKind, CopyStatus, Mapped, NotMappedReason};
    let follow = {
        let memory: Vec<Mapped<'_>> = regions
            .iter()
            .map(|region| Mapped {
                range: region.range(),
                bytes: region.backed().then(|| &data[region.data_range()]),
                code: region.kind == RawRegionKind::Code,
            })
            .collect();
        crate::raw_scatter::follow(&memory, entry)
    };
    let mut report = follow.report;
    for (index, copy) in report.copies.iter_mut().enumerate() {
        let range = copy.destination..copy.destination + copy.length;
        let source = copy.source.and_then(|source| {
            let region = regions.iter().position(|region| {
                region.backed() && region.base_address <= source && source + copy.length <= region.range().end
            })?;
            Some((region, source - regions[region].base_address))
        });
        if let Some((region, offset)) = source {
            copy.source_region = Some(regions[region].name.clone());
            copy.source_offset = Some(offset);
        }
        let reason = if !map {
            Some(NotMappedReason::NotRequested)
        } else if !follow.complete[index] {
            Some(NotMappedReason::Incomplete)
        } else if follow.overwritten[index] {
            Some(NotMappedReason::Overwritten)
        } else if copy.kind == CopyKind::Computed {
            Some(NotMappedReason::ComputedBytes)
        } else if copy.kind == CopyKind::Copy && source.is_none() {
            Some(NotMappedReason::SourceNotMapped)
        } else if range.end > 1 << 32 {
            Some(NotMappedReason::OutOfRange)
        } else if regions.iter().any(|region| region.base_address < range.end && range.start < region.range().end) {
            Some(NotMappedReason::DestinationMapped)
        } else if regions.len() >= MAX_RAW_REGIONS {
            Some(NotMappedReason::RegionLimit)
        } else if copy.kind == CopyKind::Copy && data.len() as u64 + copy.length > max as u64 {
            Some(NotMappedReason::ByteLimit)
        } else {
            None
        };
        if let Some(reason) = reason {
            copy.not_mapped_reason = Some(reason);
            continue;
        }
        // Copied code ran where it was copied to and nothing stored into it afterwards; everything else is data the
        // program may change, which the decompiler must not fold as constants.
        let kind = if copy.kind == CopyKind::Copy
            && copy.destination.is_multiple_of(2)
            && copy.executed
            && !copy.written_after_jump
        {
            RawRegionKind::Code
        } else {
            RawRegionKind::Ram
        };
        let name = format!("raw.{}.{}", kind.name(), regions.len());
        let (bytes, source) = match source {
            Some((region, offset)) if copy.kind == CopyKind::Copy => {
                let start = regions[region].data_range().start + offset as usize;
                (Some(data[start..start + copy.length as usize].to_vec()), Some((regions[region].name.clone(), offset)))
            }
            _ => (None, None),
        };
        let (region, offset) = source.map_or((None, None), |(region, offset)| (Some(region), Some(offset)));
        regions.push(RawRegionInfo {
            name: name.clone(),
            kind,
            base_address: copy.destination,
            length: copy.length,
            sha256: bytes.as_deref().map(sha256_hex),
            source: Some(RawRegionSource::ScatterLoad { copy: index, region, offset }),
            data_offset: data.len() as u64,
        });
        if let Some(bytes) = bytes {
            data.extend_from_slice(&bytes);
        }
        copy.status = CopyStatus::Mapped;
        copy.region = Some(name);
    }
    report
}

/// A copy of `length` bytes at `offset` of the admitted region named `from`, whose bytes lie in `data`; refused
/// when that region is unknown or unbacked, the range leaves it, or the copy exceeds `budget` bytes.
fn slice_bytes(
    regions: &[RawRegionInfo],
    data: &[u8],
    from: &str,
    offset: u64,
    length: u64,
    budget: usize,
) -> Result<Vec<u8>, String> {
    let source = regions.iter().find(|earlier| earlier.name == from).ok_or_else(|| {
        let names: Vec<&str> = regions.iter().map(|region| region.name.as_str()).collect();
        format!("slice source {from:?} names no earlier region (earlier: {})", names.join(", "))
    })?;
    if !source.backed() {
        return Err(format!("slice source {from} is unbacked and has no bytes"));
    }
    let end = offset.checked_add(length).filter(|&end| length >= 1 && end <= source.length).ok_or_else(|| {
        format!("slice {offset:#x}+{length:#x} is not inside the {:#x} bytes of {from}", source.length)
    })?;
    if length > budget as u64 {
        return Err(format!("a {length:#x}-byte slice exceeds the {budget:#x} bytes the regions may still hold"));
    }
    let start = source.data_range().start;
    Ok(data[start + offset as usize..start + end as usize].to_vec())
}

fn checked_code_end(base: u64, length: u64, highest: u64) -> Result<u64, LoadError> {
    let last_offset = length.checked_sub(1).ok_or_else(|| LoadError::Malformed("empty Raw range".into()))?;
    let last = base.checked_add(last_offset).ok_or_else(|| LoadError::Malformed("Raw last byte overflows".into()))?;
    let end = base.checked_add(length).ok_or_else(|| LoadError::Malformed("Raw exclusive end overflows".into()))?;
    if last > highest {
        return Err(LoadError::Malformed("Raw last byte exceeds profile code-space highest byte".into()));
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_FACTS, RawProfile, checked_code_end};

    #[test]
    fn profile_table_is_indexed_by_discriminant_with_unique_languages_and_arches() {
        for (index, profile) in RawProfile::ALL.into_iter().enumerate() {
            assert_eq!(profile as usize, index);
            assert_eq!(PROFILE_FACTS[index].profile, profile);
            assert_eq!(RawProfile::from_language_id(profile.language_id()).unwrap(), profile);
            assert_eq!(serde_json::to_value(profile).unwrap(), profile.language_id());
            // Sleigh-decoded profiles have no legacy pointer width; the native profiles are 32-bit ARM and MIPS.
            assert_eq!(profile.arch().pointer_size(), profile.native_decoder().then_some(4));
            assert_eq!(profile.arch().native_address_width().is_some(), profile.native_decoder());
            assert_eq!(profile.max_bytes() > super::MAX_RAW_BYTES, profile.native_decoder());
            let identity = |profile: RawProfile| (profile.arch(), profile.big_endian());
            assert!(RawProfile::ALL[..index].iter().all(|&other| identity(other) != identity(profile)));
        }
    }

    #[test]
    fn checked_ranges_refuse_both_kinds_of_overflow_and_empty_input() {
        assert!(checked_code_end(u64::MAX, 2, u64::MAX).is_err());
        assert!(checked_code_end(u64::MAX, 1, u64::MAX).is_err());
        assert!(checked_code_end(0, 0, u64::MAX).is_err());
        assert_eq!(checked_code_end(0x1fffe, 2, 0x1ffff).unwrap(), 0x20000);
        assert!(checked_code_end(0x1fffe, 3, 0x1ffff).is_err());
    }
}
