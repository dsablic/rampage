use rampage_arch::MAX_JUMP_TABLE_ENTRIES;
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct JumpTable {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub encoding: String,
    pub entries: Vec<JumpTableEntry>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct JumpTableEntry {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub slot: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub target: u64,
}

impl Project {
    /// Validates an explicitly selected ARM64 table; does not invent the index range or branch xrefs.
    pub fn inspect_jump_table(
        &self,
        address: u64,
        count: usize,
        relative_base: Option<u64>,
    ) -> Result<JumpTable, ApiError> {
        if self.binary.arch != rampage_arch::Arch::Aarch64 || !(1..=MAX_JUMP_TABLE_ENTRIES).contains(&(count as u64)) {
            return Err(ApiError::Invalid(format!(
                "jump-table inspection requires ARM64 and 1–{MAX_JUMP_TABLE_ENTRIES} entries"
            )));
        }
        let size = if relative_base.is_some() { 4u8 } else { 8u8 };
        if !address.is_multiple_of(u64::from(size)) {
            return Err(ApiError::Invalid("jump-table address is not aligned to entry size".to_owned()));
        }
        // The analyst supplies the index range, so there is no bounding comparison.
        let table = rampage_arch::JumpTable {
            guard: address,
            table: address,
            entry_size: size,
            entries: count as u64,
            signed: relative_base.is_some(),
            base: relative_base,
            shift: 0,
            alignment: 4,
        };
        let mut entries = Vec::with_capacity(count);
        for index in 0..table.entries {
            let slot =
                table.slot(index).ok_or_else(|| ApiError::Invalid("jump table overflows address space".to_owned()))?;
            let raw = self
                .binary
                .read_constant(slot, size)
                .ok_or_else(|| ApiError::Invalid(format!("table slot {slot:#x} is not readable immutable memory")))?;
            let target = table
                .target(raw)
                .ok_or_else(|| ApiError::Invalid(format!("table slot {slot:#x} selects a misaligned target")))?;
            if !self.binary.is_code(target)
                || self.binary.read(target, 4).is_none()
                || self
                    .binary
                    .segment_containing(target)
                    .is_none_or(|segment| segment.perms.write || !segment.perms.read)
            {
                return Err(ApiError::Invalid(format!(
                    "table target {target:#x} is not aligned file-backed ARM64 code"
                )));
            }
            let mut decoder = self.binary.decoder()?;
            if decoder.decode(self.binary.read(target, 4).unwrap(), target).flow == rampage_arch::Flow::Invalid {
                return Err(ApiError::Invalid(format!("table target {target:#x} does not decode")));
            }
            entries.push(JumpTableEntry { slot, target });
        }
        Ok(JumpTable {
            address,
            encoding: if relative_base.is_some() { "signed_relative32" } else { "absolute64" }.to_owned(),
            entries,
            limitations: vec![
                "Explicit table inspection only; the index range and dispatch instruction are supplied by the analyst."
                    .to_owned(),
                "Valid entries do not prove execution; no CFG edges or function seeds are inserted automatically."
                    .to_owned(),
                "Authenticated, writable and unbacked targets are rejected rather than guessed.".to_owned(),
            ],
        })
    }
}
