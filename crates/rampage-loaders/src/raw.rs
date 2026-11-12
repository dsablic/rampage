use std::ops::Range;

use rampage_arch::Arch;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{LoadError, Perms, Section, SectionKind, Segment};

/// Input cap for Sleigh-decoded profiles (every profile except [`RawProfile::CortexM`]).
pub const MAX_RAW_BYTES: usize = 128 * 1024;
/// Input cap for the natively decoded Cortex-M profile: flash images are typically 256 KiB to 2 MiB.
pub const MAX_RAW_NATIVE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RAW_SEEDS: usize = 8192;
/// Regions one Raw project maps, the primary one included.
pub const MAX_RAW_REGIONS: usize = 16;
const IDENTITY_SCHEMA: &str = "rampage-raw-interpretation-v5";

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
}

/// Which decoder serves a Raw profile's discovery, listing and search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawDecoder {
    /// The bundled Sleigh translator of `language_id`, whose metadata must equal the profile's facts.
    Sleigh,
    /// rampage's native decoder for `arch`, with the whole mapped range in Thumb mode.
    NativeThumb,
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
const PROFILE_FACTS: [RawProfileFacts; 17] = [
    facts(RawProfile::Msp430, "TI_MSP430:LE:16:default", Arch::Msp430, false, space("RAM", 2, 1, 0xffff, 2)),
    facts(RawProfile::Avr8, "avr8:LE:16:default", Arch::Avr8, false, space("code", 2, 2, 0x1ffff, 2)),
    facts(RawProfile::Mos6502, "6502:LE:16:default", Arch::Mos6502, false, space("RAM", 2, 1, 0xffff, 1)),
    facts(RawProfile::I8051, "8051:BE:16:default", Arch::I8051, true, space("CODE", 2, 1, 0xffff, 1)),
    facts(RawProfile::Pic16, "PIC-16:LE:16:PIC-16", Arch::Pic16, false, space("CODE", 2, 2, 0x1ffff, 2)),
    facts(RawProfile::SuperH2, "SuperH:BE:32:SH-2", Arch::Sh2, true, space("ram", 4, 1, 0xffff_ffff, 1)),
    facts(RawProfile::V850, "V850:LE:32:default", Arch::V850, false, space("ram", 4, 1, 0xffff_ffff, 2)),
    facts(RawProfile::Tricore, "tricore:LE:32:default", Arch::Tricore, false, space("ram", 4, 1, 0xffff_ffff, 2)),
    facts(RawProfile::Xtensa, "Xtensa:LE:32:default", Arch::Xtensa, false, space("ram", 4, 1, 0xffff_ffff, 1)),
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

    /// Whether rampage's native decoder for [`Self::arch`] serves this profile, with the whole mapped range in
    /// Thumb mode, instead of a Sleigh translator. Such a profile has typed operands, data references and a
    /// pointer width; the others have none of these.
    pub fn native_decoder(self) -> bool {
        self.facts().decoder == RawDecoder::NativeThumb
    }

    /// Whether the profile is an ARMv6-M/ARMv7-M(E) processor: all code Thumb, no A32 state, the M-profile
    /// instruction set and a Cortex-M vector table.
    pub fn m_profile(self) -> bool {
        self == RawProfile::CortexM
    }

    /// Largest admitted input: 4 MiB for the natively decoded profile, 128 KiB for Sleigh-decoded ones.
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
    /// No bytes: zero-filled or uninitialised RAM, or memory-mapped I/O.
    Unbacked,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawInterpretationIdentity {
    pub schema: &'static str,
    pub sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

impl RawCodeImage {
    /// Admits `image` and returns the retained facts with the project's owned bytes: the primary region's bytes
    /// followed by every other backed region's, in region order.
    pub(crate) fn admit(image: RawImage) -> Result<(Self, Vec<u8>), LoadError> {
        let RawImage { bytes, mut options, source, regions: extra, records } = image;
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
                "Raw {} maps one code region: additional regions are defined only for ARM:LE:32:Cortex",
                options.profile.language_id()
            )));
        }
        if extra.len() >= MAX_RAW_REGIONS {
            return Err(LoadError::Malformed(format!(
                "Raw maps at most {MAX_RAW_REGIONS} regions, the primary one included"
            )));
        }
        for (index, region) in extra.into_iter().enumerate() {
            let name = format!("raw.{}.{}", region.kind.name(), index + 1);
            let refuse = |message: &str| Err(LoadError::Malformed(format!("Raw region {name}: {message}")));
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
        let check_start = |address: u64| {
            if !address.is_multiple_of(alignment) || !in_code(address) {
                return Err(LoadError::Malformed("Raw entry/seed must be aligned and backed by code bytes".into()));
            }
            Ok(())
        };
        if let Some(entry) = options.entry {
            check_start(entry)?;
        }
        for &seed in &options.seeds {
            check_start(seed)?;
        }
        // Vector and pointer tables are read from the primary region only; their targets lie inside it.
        let primary = &data[..length as usize];
        let vector_table = match options.vector_table {
            None => None,
            Some(_) if !options.profile.m_profile() => {
                return Err(LoadError::Malformed(
                    "Raw vector-table seeding is defined only for ARM:LE:32:Cortex".into(),
                ));
            }
            Some(address) => {
                let table = crate::raw_vectors::read(primary, options.base, address)?;
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
        let table_words =
            vector_table.as_ref().map(|table| table.address..table.address + 4 * table.words_read as u64);
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
        let pointer_tables = if !options.pointer_tables {
            None
        } else if !options.profile.m_profile() {
            return Err(LoadError::Malformed("Raw pointer-table seeding is defined only for ARM:LE:32:Cortex".into()));
        } else {
            let tables = crate::raw_pointers::scan(primary, options.base, table_words);
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
        };
        Ok((image, data))
    }

    pub fn profile(&self) -> RawProfile {
        self.profile
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
        let mut ranges: Vec<Range<u64>> = self
            .regions
            .iter()
            .filter(|region| region.kind == RawRegionKind::Code)
            .map(RawRegionInfo::range)
            .collect();
        ranges.sort_by_key(|range| range.start);
        ranges
    }

    pub(crate) fn segments(&self) -> Vec<Segment> {
        self.regions.iter().map(RawRegionInfo::segment).collect()
    }

    pub(crate) fn sections(&self) -> Vec<Section> {
        self.regions.iter().map(RawRegionInfo::section).collect()
    }

    pub(crate) fn identity(&self, bytes: &[u8]) -> RawInterpretationIdentity {
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
                    text(&mut hash, &receipt.to_string());
                }
                Some(RawRegionSource::Records { format }) => hash.update([3, *format as u8]),
                Some(RawRegionSource::Unbacked) => hash.update([4]),
            }
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
            // Sleigh-decoded profiles have no legacy pointer width; the native Thumb profile is 32-bit ARM.
            assert_eq!(profile.arch().pointer_size(), profile.native_decoder().then_some(4));
            assert_eq!(profile.arch().native_address_width().is_some(), profile.native_decoder());
            assert_eq!(profile.max_bytes() > super::MAX_RAW_BYTES, profile.native_decoder());
            assert!(RawProfile::ALL[..index].iter().all(|other| other.arch() != profile.arch()));
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
