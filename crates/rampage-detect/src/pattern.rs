//! A byte pattern with nibble and byte wildcards, as PeID-style entry-point signatures use them.
//!
//! The hex text is parsed two characters per byte. A hex digit fixes that nibble; a `?` leaves it free. So `60`
//! matches exactly, `6?` matches `0x60..=0x6f`, `?0` matches any byte whose low nibble is zero, and `??` matches
//! any byte at all. ASCII whitespace between bytes is ignored, so `60 E8 ?? ?? ?? ??` and `60E8????????` parse
//! the same. Every pattern is at most [`MAX_PATTERN_BYTES`] long so a malformed signature cannot allocate wildly.

/// Upper bound on a pattern's length in bytes; real entry-point stubs are far shorter.
pub const MAX_PATTERN_BYTES: usize = 256;

/// One byte of a pattern: `value` holds the fixed bits and `mask` marks which bits are fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaskedByte {
    value: u8,
    mask: u8,
}

/// A parsed byte pattern. Empty patterns are rejected at parse time, so a pattern always has at least one byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<MaskedByte>,
}

/// Why a hex pattern could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// The pattern held no bytes (all whitespace).
    Empty,
    /// The hex text had an odd number of nibbles, so a byte was left half-specified.
    OddNibbles,
    /// A character was neither a hex digit, a `?`, nor whitespace.
    BadChar(char),
    /// The pattern was longer than [`MAX_PATTERN_BYTES`].
    TooLong,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "pattern is empty"),
            Self::OddNibbles => write!(f, "pattern has an odd number of nibbles"),
            Self::BadChar(c) => write!(f, "unexpected character {c:?} in pattern"),
            Self::TooLong => write!(f, "pattern exceeds {MAX_PATTERN_BYTES} bytes"),
        }
    }
}

impl std::error::Error for PatternError {}

/// One nibble: its value and whether it is fixed (`Some`) or a wildcard (`None`).
fn nibble(c: char) -> Result<Option<u8>, PatternError> {
    match c {
        '?' => Ok(None),
        _ => c.to_digit(16).map(|d| Some(d as u8)).ok_or(PatternError::BadChar(c)),
    }
}

impl BytePattern {
    /// Parses a hex pattern with `?` nibble wildcards. Whitespace between nibbles is ignored.
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let nibbles: Vec<char> = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if nibbles.is_empty() {
            return Err(PatternError::Empty);
        }
        if !nibbles.len().is_multiple_of(2) {
            return Err(PatternError::OddNibbles);
        }
        if nibbles.len() / 2 > MAX_PATTERN_BYTES {
            return Err(PatternError::TooLong);
        }
        let mut bytes = Vec::with_capacity(nibbles.len() / 2);
        for pair in nibbles.as_chunks::<2>().0 {
            let (high, low) = (nibble(pair[0])?, nibble(pair[1])?);
            let mut value = 0u8;
            let mut mask = 0u8;
            if let Some(high) = high {
                value |= high << 4;
                mask |= 0xf0;
            }
            if let Some(low) = low {
                value |= low;
                mask |= 0x0f;
            }
            bytes.push(MaskedByte { value, mask });
        }
        Ok(Self { bytes })
    }

    /// The pattern's length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether the pattern matches the start of `data`. A shorter `data` than the pattern never matches.
    pub fn matches_at(&self, data: &[u8]) -> bool {
        data.len() >= self.bytes.len()
            && self.bytes.iter().zip(data).all(|(p, &b)| b & p.mask == p.value)
    }

    /// The first offset in `data` where the pattern matches, scanning left to right.
    pub fn find_in(&self, data: &[u8]) -> Option<usize> {
        if self.bytes.len() > data.len() {
            return None;
        }
        (0..=data.len() - self.bytes.len()).find(|&start| self.matches_at(&data[start..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bytes_match_only_themselves() {
        let pattern = BytePattern::parse("60 E8").unwrap();
        assert_eq!(pattern.len(), 2);
        assert!(pattern.matches_at(&[0x60, 0xe8, 0x00]));
        assert!(!pattern.matches_at(&[0x60, 0xe9]));
        assert!(!pattern.matches_at(&[0x60]));
    }

    #[test]
    fn byte_wildcard_matches_any_byte() {
        let pattern = BytePattern::parse("60 ?? 8D").unwrap();
        assert!(pattern.matches_at(&[0x60, 0x00, 0x8d]));
        assert!(pattern.matches_at(&[0x60, 0xff, 0x8d]));
        assert!(!pattern.matches_at(&[0x60, 0xff, 0x8e]));
    }

    #[test]
    fn nibble_wildcards_pin_one_half() {
        let high = BytePattern::parse("6?").unwrap();
        assert!(high.matches_at(&[0x60]));
        assert!(high.matches_at(&[0x6f]));
        assert!(!high.matches_at(&[0x70]));
        let low = BytePattern::parse("?a").unwrap();
        assert!(low.matches_at(&[0x0a]));
        assert!(low.matches_at(&[0xfa]));
        assert!(!low.matches_at(&[0x0b]));
    }

    #[test]
    fn spaced_and_unspaced_hex_parse_the_same() {
        assert_eq!(BytePattern::parse("60 E8 ?? ??"), BytePattern::parse("60E8????"));
    }

    #[test]
    fn find_locates_a_pattern_inside_a_buffer() {
        let pattern = BytePattern::parse("E8 ?? ?? ?? ??").unwrap();
        let data = [0x55, 0x89, 0xe5, 0xe8, 0x01, 0x02, 0x03, 0x04, 0x90];
        assert_eq!(pattern.find_in(&data), Some(3));
        assert_eq!(pattern.find_in(&[0x90, 0x90]), None);
    }

    #[test]
    fn malformed_patterns_are_rejected() {
        assert_eq!(BytePattern::parse(""), Err(PatternError::Empty));
        assert_eq!(BytePattern::parse("   "), Err(PatternError::Empty));
        assert_eq!(BytePattern::parse("6"), Err(PatternError::OddNibbles));
        assert_eq!(BytePattern::parse("6G"), Err(PatternError::BadChar('G')));
        let long = "00".repeat(MAX_PATTERN_BYTES + 1);
        assert_eq!(BytePattern::parse(&long), Err(PatternError::TooLong));
    }
}
