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
const IDENTITY_SCHEMA: &str = "rampage-raw-interpretation-v3";

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawCodeImage {
    profile: RawProfile,
    base: u64,
    length: u64,
    end: u64,
    entry: Option<u64>,
    seeds: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vector_table: Option<crate::raw_vectors::VectorTable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawInterpretationIdentity {
    pub schema: &'static str,
    pub sha256: String,
}

impl RawCodeImage {
    pub(crate) fn admit(bytes: &[u8], mut options: RawCodeOptions) -> Result<Self, LoadError> {
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
        if options.profile.m_profile() {
            // Thumb code pointers carry bit 0; the instruction starts at the even address.
            options.entry = options.entry.map(|entry| entry & !1);
            options.seeds.iter_mut().for_each(|seed| *seed &= !1);
        }
        let check_start = |address: u64| {
            if !address.is_multiple_of(alignment) || !(options.base..end).contains(&address) {
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
        let vector_table = match options.vector_table {
            None => None,
            Some(_) if !options.profile.m_profile() => {
                return Err(LoadError::Malformed(
                    "Raw vector-table seeding is defined only for ARM:LE:32:Cortex".into(),
                ));
            }
            Some(address) => {
                let table = crate::raw_vectors::read(bytes, options.base, address)?;
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
        options.seeds.sort_unstable();
        options.seeds.dedup();
        if options.seeds.len() > MAX_RAW_SEEDS {
            return Err(LoadError::Malformed("Raw accepts at most 8192 seeds, vector-table handlers included".into()));
        }
        Ok(Self {
            profile: options.profile,
            base: options.base,
            length,
            end,
            entry: options.entry,
            seeds: options.seeds,
            vector_table,
        })
    }

    pub fn profile(&self) -> RawProfile {
        self.profile
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn entry(&self) -> Option<u64> {
        self.entry
    }

    pub fn seeds(&self) -> &[u64] {
        &self.seeds
    }

    /// Evidence for every vector read when vector-table seeding was requested.
    pub fn vector_table(&self) -> Option<&crate::raw_vectors::VectorTable> {
        self.vector_table.as_ref()
    }

    /// The Thumb-mode ranges a native decoder reads: the whole mapped range for the Cortex-M profile.
    pub fn thumb_ranges(&self) -> Vec<Range<u64>> {
        if self.profile.m_profile() { vec![self.range()] } else { Vec::new() }
    }

    pub fn range(&self) -> Range<u64> {
        self.base..self.end
    }

    pub(crate) fn segment(&self) -> Segment {
        Segment {
            name: "raw.code".into(),
            address: self.base,
            size: self.length,
            file_offset: 0,
            file_size: self.length,
            perms: Perms { read: true, write: false, execute: true },
        }
    }

    pub(crate) fn section(&self) -> Section {
        Section {
            name: "raw.code".into(),
            address: self.base,
            size: self.length,
            kind: SectionKind::Code,
            file_offset: Some(0),
            file_size: self.length,
        }
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
        // Schema v2 is exactly one RX code mapping, offset zero, no zero-fill or additional address spaces.
        hash.update([1, 0, 1]);
        for value in [self.base, self.length, self.end, 0_u64] {
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
