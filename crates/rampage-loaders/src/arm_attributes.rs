//! The CPU facts of an ARM ELF's build attributes (`.ARM.attributes`, `SHT_ARM_ATTRIBUTES`): the public `aeabi`
//! subsection's file-scope `Tag_CPU_arch` and `Tag_CPU_arch_profile`, which say whether the code targets an
//! M-profile (Cortex-M) processor. The section is untrusted input: every length is checked against the bytes left,
//! ULEB128 values are bounded, and anything malformed is an error rather than a guess.
//!
//! Layout (ARM IHI 0045, "Build attributes"): a format-version byte `'A'`, then vendor subsections, each a `u32`
//! length (counting itself), a NUL-terminated vendor name and, for `aeabi`, sub-subsections: a tag byte (1 file,
//! 2 section, 3 symbol), a `u32` size (counting the tag and itself) and attributes. An attribute is a ULEB128 tag
//! followed by a ULEB128 or NUL-terminated string value.

/// Largest attributes section read; toolchains write well under 1 KiB.
pub const MAX_ATTRIBUTES_BYTES: usize = 64 * 1024;

const FORMAT_VERSION: u8 = b'A';
const TAG_FILE: u8 = 1;
const TAG_CPU_RAW_NAME: u64 = 4;
const TAG_CPU_NAME: u64 = 5;
const TAG_CPU_ARCH: u64 = 6;
const TAG_CPU_ARCH_PROFILE: u64 = 7;
const TAG_COMPATIBILITY: u64 = 32;

/// `Tag_CPU_arch` values of the M-profile architectures: v6-M, v6S-M, v7E-M, v8-M.baseline, v8-M.mainline and
/// v8.1-M.mainline. ARMv7-M shares value 10 (v7) with A and R and is told apart only by the profile tag.
const M_PROFILE_ARCHES: [u64; 6] = [11, 12, 13, 16, 17, 21];

/// The file-scope CPU attributes of the public `aeabi` subsection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuAttributes {
    /// `Tag_CPU_arch`.
    pub arch: Option<u64>,
    /// `Tag_CPU_arch_profile`: `b'A'`, `b'R'`, `b'M'`, `b'S'` (A or R), or 0 for none.
    pub profile: Option<u8>,
}

impl CpuAttributes {
    /// An M-profile processor: the profile tag says `'M'`, or, without a profile (absent or 0), the architecture
    /// is one only M-profile cores implement. An explicit A, R or S profile is never M.
    pub fn m_profile(&self) -> bool {
        match self.profile {
            Some(b'M') => true,
            None | Some(0) => self.arch.is_some_and(|arch| M_PROFILE_ARCHES.contains(&arch)),
            Some(_) => false,
        }
    }
}

/// Why an attributes section was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributesError(pub &'static str);

impl std::fmt::Display for AttributesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Reads the CPU attributes from a `.ARM.attributes` section's bytes, `big_endian` as the ELF's data. Subsections
/// of other vendors and non-file scopes are skipped by their lengths.
pub fn parse(bytes: &[u8], big_endian: bool) -> Result<CpuAttributes, AttributesError> {
    if bytes.len() > MAX_ATTRIBUTES_BYTES {
        return Err(AttributesError("attributes section is larger than any toolchain writes"));
    }
    let (&version, mut rest) = bytes.split_first().ok_or(AttributesError("attributes section is empty"))?;
    if version != FORMAT_VERSION {
        return Err(AttributesError("unknown attributes format version"));
    }
    let mut found = CpuAttributes::default();
    while !rest.is_empty() {
        let (subsection, after) = sized(rest, 0, big_endian)?;
        rest = after;
        let name_end =
            subsection.iter().position(|&byte| byte == 0).ok_or(AttributesError("vendor name is not terminated"))?;
        if &subsection[..name_end] != b"aeabi" {
            continue;
        }
        let mut scopes = &subsection[name_end + 1..];
        while !scopes.is_empty() {
            let tag = scopes[0];
            let (scope, after) = sized(scopes, 1, big_endian)?;
            scopes = after;
            if tag == TAG_FILE {
                read_file_scope(scope, &mut found)?;
            }
        }
    }
    Ok(found)
}

/// Splits a length-prefixed record off `bytes`: `prefix` bytes, a `u32` length counting the prefix and itself,
/// then the body. Returns the body and what follows the record.
fn sized(bytes: &[u8], prefix: usize, big_endian: bool) -> Result<(&[u8], &[u8]), AttributesError> {
    let header = prefix + 4;
    let field: [u8; 4] = bytes
        .get(prefix..header)
        .and_then(|field| field.try_into().ok())
        .ok_or(AttributesError("attributes length is truncated"))?;
    let length = if big_endian { u32::from_be_bytes(field) } else { u32::from_le_bytes(field) };
    let length = usize::try_from(length).map_err(|_| AttributesError("attributes length overflows"))?;
    if length < header || length > bytes.len() {
        return Err(AttributesError("attributes length is outside the section"));
    }
    Ok((&bytes[header..length], &bytes[length..]))
}

fn read_file_scope(mut bytes: &[u8], found: &mut CpuAttributes) -> Result<(), AttributesError> {
    while !bytes.is_empty() {
        let tag = uleb128(&mut bytes)?;
        match tag {
            TAG_CPU_RAW_NAME | TAG_CPU_NAME => string(&mut bytes)?,
            TAG_COMPATIBILITY => {
                uleb128(&mut bytes)?;
                string(&mut bytes)?;
            }
            TAG_CPU_ARCH => found.arch = Some(uleb128(&mut bytes)?),
            TAG_CPU_ARCH_PROFILE => {
                let profile = uleb128(&mut bytes)?;
                found.profile = Some(u8::try_from(profile).map_err(|_| AttributesError("CPU profile is not a byte"))?);
            }
            // The generic rule for the tags this reader does not name: below 32 every one is an integer; from 32
            // on, odd tags are strings and even tags integers.
            tag if tag >= 32 && tag % 2 == 1 => string(&mut bytes)?,
            _ => {
                uleb128(&mut bytes)?;
            }
        }
    }
    Ok(())
}

/// At most 10 bytes, as a `u64` holds; a longer or unterminated value is malformed.
fn uleb128(bytes: &mut &[u8]) -> Result<u64, AttributesError> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate().take(10) {
        let bits = u64::from(byte & 0x7f);
        let shift = 7 * index as u32;
        if index == 9 && bits > 1 {
            return Err(AttributesError("attribute value overflows 64 bits"));
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            *bytes = &bytes[index + 1..];
            return Ok(value);
        }
    }
    Err(AttributesError("attribute value is truncated"))
}

fn string(bytes: &mut &[u8]) -> Result<(), AttributesError> {
    let end = bytes.iter().position(|&byte| byte == 0).ok_or(AttributesError("attribute string is not terminated"))?;
    *bytes = &bytes[end + 1..];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section with one `aeabi` subsection holding one file scope with `attributes`.
    fn section(attributes: &[u8]) -> Vec<u8> {
        let mut scope = vec![TAG_FILE];
        scope.extend_from_slice(&(5 + attributes.len() as u32).to_le_bytes());
        scope.extend_from_slice(attributes);
        let mut subsection = Vec::new();
        subsection.extend_from_slice(&(4 + 6 + scope.len() as u32).to_le_bytes());
        subsection.extend_from_slice(b"aeabi\0");
        subsection.extend_from_slice(&scope);
        let mut bytes = vec![b'A'];
        bytes.extend_from_slice(&subsection);
        bytes
    }

    /// What clang writes for `-mcpu=cortex-m3`: name, arch v7 (10), profile 'M', then integer tags.
    fn cortex_m3() -> Vec<u8> {
        let mut attributes = vec![5];
        attributes.extend_from_slice(b"cortex-m3\0");
        attributes.extend_from_slice(&[6, 10, 7, b'M', 8, 0, 9, 2, 34, 1]);
        section(&attributes)
    }

    #[test]
    fn m_profile_from_the_profile_tag() {
        let attributes = parse(&cortex_m3(), false).unwrap();
        assert_eq!(attributes, CpuAttributes { arch: Some(10), profile: Some(b'M') });
        assert!(attributes.m_profile());
    }

    #[test]
    fn a_and_r_profiles_are_not_m() {
        for &profile in b"ARS" {
            let attributes = parse(&section(&[6, 10, 7, profile]), false).unwrap();
            assert!(!attributes.m_profile(), "{}", profile as char);
        }
        // An explicit profile wins over an M-only architecture.
        assert!(!parse(&section(&[6, 13, 7, b'A']), false).unwrap().m_profile());
    }

    #[test]
    fn m_profile_from_the_architecture_without_a_profile() {
        for arch in M_PROFILE_ARCHES {
            assert!(parse(&section(&[6, arch as u8]), false).unwrap().m_profile(), "{arch}");
            assert!(parse(&section(&[6, arch as u8, 7, 0]), false).unwrap().m_profile(), "{arch}");
        }
        // v7 alone names no profile; v8-A (14) and v4T (2) are not M.
        for arch in [10, 14, 2] {
            assert!(!parse(&section(&[6, arch]), false).unwrap().m_profile(), "{arch}");
        }
    }

    #[test]
    fn missing_attributes_are_not_m() {
        assert!(!parse(&section(&[]), false).unwrap().m_profile());
        assert!(!parse(&section(&[8, 1]), false).unwrap().m_profile());
        assert!(!parse(b"A", false).unwrap().m_profile());
    }

    #[test]
    fn other_vendors_and_scopes_are_skipped() {
        let mut bytes = vec![b'A'];
        // A vendor subsection whose body would claim M if it were read.
        bytes.extend_from_slice(&(4 + 4 + 2u32).to_le_bytes());
        bytes.extend_from_slice(b"gnu\0");
        bytes.extend_from_slice(&[7, b'M']);
        // An aeabi subsection with a section scope (tag 2) claiming M, then a file scope saying A.
        let section_scope = [2, 9, 0, 0, 0, 1, 0, 7, b'M'];
        let file_scope = [1, 7, 0, 0, 0, 7, b'A'];
        bytes.extend_from_slice(&(4 + 6 + (section_scope.len() + file_scope.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(b"aeabi\0");
        bytes.extend_from_slice(&section_scope);
        bytes.extend_from_slice(&file_scope);
        let attributes = parse(&bytes, false).unwrap();
        assert_eq!(attributes.profile, Some(b'A'));
        assert!(!attributes.m_profile());
    }

    #[test]
    fn big_endian_lengths() {
        let mut bytes = cortex_m3();
        bytes[1..5].reverse();
        bytes[12..16].reverse();
        assert!(parse(&bytes, true).unwrap().m_profile());
        assert!(parse(&bytes, false).is_err());
    }

    #[test]
    fn truncated_and_malformed_sections_are_errors() {
        let good = cortex_m3();
        for length in 2..good.len() {
            assert!(parse(&good[..length], false).is_err(), "{length}");
        }
        assert!(parse(&[], false).is_err());
        let mut version = good.clone();
        version[0] = b'B';
        assert!(parse(&version, false).is_err());
        // Lengths shorter than their own header or past the section.
        for length in [0u32, 3, 1000, u32::MAX] {
            let mut bytes = good.clone();
            bytes[1..5].copy_from_slice(&length.to_le_bytes());
            assert!(parse(&bytes, false).is_err(), "{length}");
            let mut bytes = good.clone();
            bytes[12..16].copy_from_slice(&length.to_le_bytes());
            assert!(parse(&bytes, false).is_err(), "{length}");
        }
        // An unterminated vendor name, string value and ULEB128, and a value past 64 bits.
        let mut unterminated = vec![b'A'];
        unterminated.extend_from_slice(&9u32.to_le_bytes());
        unterminated.extend_from_slice(b"aeabi");
        assert!(parse(&unterminated, false).is_err());
        assert!(parse(&section(&[5, b'x']), false).is_err());
        assert!(parse(&section(&[6, 0x80]), false).is_err());
        assert!(parse(&section(&[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]), false).is_err());
        assert!(parse(&section(&[7, 0x80, 0x02]), false).is_err());
        assert!(parse(&vec![b'A'; MAX_ATTRIBUTES_BYTES + 1], false).is_err());
    }

    #[test]
    fn ten_byte_values_up_to_u64_max() {
        let attributes =
            parse(&section(&[6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), false).unwrap();
        assert_eq!(attributes.arch, Some(u64::MAX));
    }
}
