use std::ops::Range;

use rampage_arch::Arch;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{LoadError, Perms, Section, SectionKind, Segment};

pub const MAX_RAW_BYTES: usize = 128 * 1024;
pub const MAX_RAW_SEEDS: usize = 8192;
const IDENTITY_SCHEMA: &str = "rampage-raw-interpretation-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RawProfile {
    #[serde(rename = "TI_MSP430:LE:16:default")]
    Msp430,
    #[serde(rename = "avr8:LE:16:default")]
    Avr8,
    #[serde(rename = "6502:LE:16:default")]
    Mos6502,
}

impl RawProfile {
    pub const ALL: [RawProfile; 3] = [Self::Msp430, Self::Avr8, Self::Mos6502];

    pub fn from_language_id(language: &str) -> Result<Self, LoadError> {
        match language {
            "TI_MSP430:LE:16:default" => Ok(Self::Msp430),
            "avr8:LE:16:default" => Ok(Self::Avr8),
            "6502:LE:16:default" => Ok(Self::Mos6502),
            _ => Err(LoadError::Unsupported(format!("Raw pilot profile {language:?}"))),
        }
    }

    pub fn language_id(self) -> &'static str {
        match self {
            Self::Msp430 => "TI_MSP430:LE:16:default",
            Self::Avr8 => "avr8:LE:16:default",
            Self::Mos6502 => "6502:LE:16:default",
        }
    }

    pub(crate) fn arch(self) -> Arch {
        // Prerequisite: real identities after the classified optional-width migration, not legacy aliases.
        match self {
            Self::Msp430 => Arch::Msp430,
            Self::Avr8 => Arch::Avr8,
            Self::Mos6502 => Arch::Mos6502,
        }
    }

    /// Closed profile facts. The decoder factory must check these against its verified translator.
    /// Encoded address size and word units are not C-pointer defaults or cross-translator space IDs.
    pub fn code_space(self) -> RawCodeSpace {
        match self {
            Self::Msp430 => RawCodeSpace {
                name: "RAM",
                address_size: 2,
                word_size: 1,
                highest_byte: 0xffff,
                instruction_alignment: 2,
            },
            Self::Avr8 => RawCodeSpace {
                name: "code",
                address_size: 2,
                word_size: 2,
                highest_byte: 0x1ffff,
                instruction_alignment: 2,
            },
            Self::Mos6502 => RawCodeSpace {
                name: "RAM",
                address_size: 2,
                word_size: 1,
                highest_byte: 0xffff,
                instruction_alignment: 1,
            },
        }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawCodeImage {
    profile: RawProfile,
    base: u64,
    length: u64,
    end: u64,
    entry: Option<u64>,
    seeds: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawInterpretationIdentity {
    pub schema: &'static str,
    pub sha256: String,
}

impl RawCodeImage {
    pub(crate) fn admit(length: usize, mut options: RawCodeOptions) -> Result<Self, LoadError> {
        if length == 0 || length > MAX_RAW_BYTES || options.seeds.len() > MAX_RAW_SEEDS {
            return Err(LoadError::Malformed("Raw requires 1..=128 KiB and at most 8192 supplied seeds".into()));
        }
        let length = u64::try_from(length).map_err(|_| LoadError::Malformed("Raw length overflows".into()))?;
        let space = options.profile.code_space();
        let alignment = u64::from(space.instruction_alignment);
        if !options.base.is_multiple_of(alignment) {
            return Err(LoadError::Malformed("Raw base violates profile instruction alignment".into()));
        }
        let end = checked_code_end(options.base, length, space.highest_byte)?;
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
        options.seeds.sort_unstable();
        options.seeds.dedup();
        Ok(Self {
            profile: options.profile,
            base: options.base,
            length,
            end,
            entry: options.entry,
            seeds: options.seeds,
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
        // Schema v1 is exactly one RX code mapping, offset zero, no zero-fill or additional address spaces.
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
    use super::checked_code_end;

    #[test]
    fn checked_ranges_refuse_both_kinds_of_overflow_and_empty_input() {
        assert!(checked_code_end(u64::MAX, 2, u64::MAX).is_err());
        assert!(checked_code_end(u64::MAX, 1, u64::MAX).is_err());
        assert!(checked_code_end(0, 0, u64::MAX).is_err());
        assert_eq!(checked_code_end(0x1fffe, 2, 0x1ffff).unwrap(), 0x20000);
        assert!(checked_code_end(0x1fffe, 3, 0x1ffff).is_err());
    }
}
