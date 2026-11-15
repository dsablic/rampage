//! Files an agent writes for a head-to-head task, checked after the run (suite v4's image export tasks).
//!
//! A task with an [`OutputSpec`] names a file in the run's working directory and the memory image it must encode.
//! The check decodes the file (Intel HEX, Motorola S-records or a flat binary at a base address) with the small
//! readers below, independent of both benchmarked servers, and requires exactly the expected addresses with
//! exactly the expected bytes: a missing, extra or different byte fails, and so does any record with a wrong
//! checksum or an unknown type.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The largest file the check reads.
pub const MAX_OUTPUT_BYTES: u64 = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Ihex,
    Srec,
    Binary,
}

/// A file the task's question asks the agent to write; `{output}` in the question becomes its quoted path.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    /// The file name in the run's directory: ASCII letters, digits, `.`, `-` and `_` only.
    pub name: String,
    pub format: OutputFormat,
    /// The address of the expected image's first byte, and of a flat binary's first byte.
    pub base: u64,
    /// Repository-relative flat image of the expected memory, from the suite's truth script.
    pub expected: PathBuf,
    pub expected_sha256: String,
}

impl OutputSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.starts_with("fixture.")
            || !self.name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            return Err(format!("invalid output name {:?}", self.name));
        }
        if self.expected.is_absolute() || self.expected.components().any(|part| part.as_os_str() == "..") {
            return Err(format!("expected image must be repository-relative: {}", self.expected.display()));
        }
        if self.expected_sha256.len() != 64
            || !self.expected_sha256.bytes().all(|byte| b"0123456789abcdef".contains(&byte))
        {
            return Err("expected_sha256 must contain 64 lowercase hexadecimal digits".into());
        }
        Ok(())
    }

    /// The expected memory, after checking the truth file against its digest.
    pub fn expected_memory(&self, root: &Path) -> Result<BTreeMap<u64, u8>, String> {
        let path = root.join(&self.expected);
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if rampage_arch::hex::bytes(&Sha256::digest(&bytes)) != self.expected_sha256 {
            return Err(format!("{}: differs from its declared digest", path.display()));
        }
        Ok(flat(&bytes, self.base))
    }

    /// Ok when the file at `produced` encodes exactly the expected memory; otherwise why not.
    pub fn check(&self, root: &Path, produced: &Path) -> Result<(), String> {
        let expected = self.expected_memory(root)?;
        // A symbolic link could point the check at a file the agent did not write (the truth image itself).
        let metadata =
            std::fs::symlink_metadata(produced).map_err(|_| format!("no file was written at {}", self.name))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", self.name));
        }
        if metadata.len() > MAX_OUTPUT_BYTES {
            return Err(format!("{} is larger than {MAX_OUTPUT_BYTES} bytes", self.name));
        }
        let bytes = std::fs::read(produced).map_err(|error| format!("{}: {error}", self.name))?;
        compare(&decode(self.format, &bytes, self.base)?, &expected)
    }
}

fn flat(bytes: &[u8], base: u64) -> BTreeMap<u64, u8> {
    bytes.iter().enumerate().map(|(index, byte)| (base + index as u64, *byte)).collect()
}

/// Exactly the same addresses with the same bytes.
pub fn compare(produced: &BTreeMap<u64, u8>, expected: &BTreeMap<u64, u8>) -> Result<(), String> {
    let missing = expected.keys().filter(|address| !produced.contains_key(address)).count();
    let extra = produced.keys().filter(|address| !expected.contains_key(address)).count();
    let differing: Vec<u64> = expected
        .iter()
        .filter(|(address, byte)| produced.get(address).is_some_and(|got| got != *byte))
        .map(|(a, _)| *a)
        .collect();
    if missing == 0 && extra == 0 && differing.is_empty() {
        return Ok(());
    }
    let mut reasons = Vec::new();
    if missing > 0 {
        reasons.push(format!("{missing} expected addresses missing"));
    }
    if extra > 0 {
        reasons.push(format!("{extra} addresses outside the expected image"));
    }
    if let Some(first) = differing.first() {
        reasons.push(format!("{} bytes differ, the first at {first:#x}", differing.len()));
    }
    Err(reasons.join("; "))
}

/// Decode a written image into address -> byte. A flat binary starts at `base`.
pub fn decode(format: OutputFormat, bytes: &[u8], base: u64) -> Result<BTreeMap<u64, u8>, String> {
    match format {
        OutputFormat::Binary => Ok(flat(bytes, base)),
        OutputFormat::Ihex => decode_ihex(ascii(bytes)?),
        OutputFormat::Srec => decode_srec(ascii(bytes)?),
    }
}

/// Record files are ASCII; anything else is refused before a record is sliced.
fn ascii(bytes: &[u8]) -> Result<&str, String> {
    if !bytes.is_ascii() {
        return Err("not ASCII text".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "not ASCII text".to_owned())
}

fn record_bytes(digits: &str, number: usize) -> Result<Vec<u8>, String> {
    if !digits.len().is_multiple_of(2) || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("line {number}: not hexadecimal byte pairs"));
    }
    Ok((0..digits.len()).step_by(2).map(|index| u8::from_str_radix(&digits[index..index + 2], 16).unwrap()).collect())
}

fn store(memory: &mut BTreeMap<u64, u8>, address: u64, data: &[u8], number: usize) -> Result<(), String> {
    for (index, byte) in data.iter().enumerate() {
        if memory.insert(address + index as u64, *byte).is_some() {
            return Err(format!("line {number}: address {:#x} written twice", address + index as u64));
        }
    }
    Ok(())
}

pub fn decode_ihex(text: &str) -> Result<BTreeMap<u64, u8>, String> {
    let mut memory = BTreeMap::new();
    let mut upper = 0u64;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let digits = line.strip_prefix(':').ok_or_else(|| format!("line {number}: not a record"))?;
        let record = record_bytes(digits, number)?;
        if record.len() < 5 || usize::from(record[0]) + 5 != record.len() {
            return Err(format!("line {number}: bad length"));
        }
        if record.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(format!("line {number}: bad checksum"));
        }
        let address = u64::from(u16::from_be_bytes([record[1], record[2]]));
        let data = &record[4..record.len() - 1];
        match record[3] {
            0 => store(&mut memory, upper + address, data, number)?,
            1 => return Ok(memory),
            2 if data.len() == 2 => upper = u64::from(u16::from_be_bytes([data[0], data[1]])) << 4,
            4 if data.len() == 2 => upper = u64::from(u16::from_be_bytes([data[0], data[1]])) << 16,
            3 | 5 => {}
            kind => return Err(format!("line {number}: record type {kind:02X}")),
        }
    }
    Err("no end-of-file record".into())
}

pub fn decode_srec(text: &str) -> Result<BTreeMap<u64, u8>, String> {
    let mut memory = BTreeMap::new();
    let mut terminated = false;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if terminated {
            return Err(format!("line {number}: record after the termination record"));
        }
        if !line.is_ascii() {
            return Err(format!("line {number}: not ASCII text"));
        }
        let rest = line.strip_prefix('S').ok_or_else(|| format!("line {number}: not a record"))?;
        let kind = rest.chars().next().ok_or_else(|| format!("line {number}: not a record"))?;
        let body = record_bytes(&rest[kind.len_utf8()..], number)?;
        if body.is_empty() || usize::from(body[0]) + 1 != body.len() {
            return Err(format!("line {number}: bad length"));
        }
        if body.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0xFF {
            return Err(format!("line {number}: bad checksum"));
        }
        let width = match kind {
            '1' | '9' => 2,
            '2' | '8' => 3,
            '3' | '7' => 4,
            '0' | '5' | '6' => 0,
            other => return Err(format!("line {number}: record type S{other}")),
        };
        if body.len() < 2 + width {
            return Err(format!("line {number}: too short for its address"));
        }
        match kind {
            '1' | '2' | '3' => {
                let address = body[1..1 + width].iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
                store(&mut memory, address, &body[1 + width..body.len() - 1], number)?;
            }
            '7' | '8' | '9' => terminated = true,
            _ => {}
        }
    }
    if !terminated {
        return Err("no termination record".into());
    }
    Ok(memory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_hex_reads_data_extended_addresses_and_the_end_record() {
        let text = ":0400000001020304F2\n:020000040001F9\n:02000000AABB99\n:00000001FF\n";
        let memory = decode_ihex(text).unwrap();
        assert_eq!(memory.len(), 6);
        assert_eq!(memory[&0x3], 4);
        assert_eq!(memory[&0x10001], 0xBB);
        assert!(decode_ihex(":0400000001020304F3\n:00000001FF\n").unwrap_err().contains("checksum"));
        assert!(decode_ihex(":0400000001020304F2\n").unwrap_err().contains("end-of-file"));
        assert!(decode_ihex(":0400000001020304F2\n:0400000001020304F2\n:00000001FF\n").unwrap_err().contains("twice"));
    }

    #[test]
    fn s_records_read_every_address_width_and_need_a_termination() {
        // S1 at 0x0000 holding 01 02, S2 at 0x010000 holding AA, S9 terminator.
        let text = "S00600004844521B\nS10500000102F7\nS2050100005A9F\nS9030000FC\n";
        let memory = decode_srec(text).unwrap();
        assert_eq!(memory.len(), 3);
        assert_eq!(memory[&0x1], 2);
        assert_eq!(memory[&0x10000], 0x5A);
        assert!(decode_srec("S10500000102F7\n").unwrap_err().contains("termination"));
        assert!(decode_srec("S1050000010250\nS9030000FC\n").unwrap_err().contains("checksum"));
        // A multi-byte character where the record type goes is refused, not sliced mid-character.
        assert!(decode_srec("S\u{e9}0500000102F7\nS9030000FC\n").unwrap_err().contains("ASCII"));
        assert!(decode(OutputFormat::Srec, "S\u{e9}05\n".as_bytes(), 0).unwrap_err().contains("ASCII"));
    }

    #[test]
    fn comparison_requires_the_same_addresses_and_bytes() {
        let expected = flat(&[1, 2, 3], 0x100);
        assert!(compare(&flat(&[1, 2, 3], 0x100), &expected).is_ok());
        assert!(compare(&flat(&[1, 9, 3], 0x100), &expected).unwrap_err().contains("first at 0x101"));
        assert!(compare(&flat(&[1, 2], 0x100), &expected).unwrap_err().contains("missing"));
        assert!(compare(&flat(&[1, 2, 3, 4], 0x100), &expected).unwrap_err().contains("outside"));
        assert!(compare(&flat(&[1, 2, 3], 0x0), &expected).is_err());
    }
}
