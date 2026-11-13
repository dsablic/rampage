//! A byte pattern with nibble and byte wildcards, as PeID-style entry-point signatures use them.
//!
//! The hex text is parsed two characters per byte. A hex digit fixes that nibble; a `?` leaves it free. So `60`
//! matches exactly, `6?` matches `0x60..=0x6f`, `?0` matches any byte whose low nibble is zero, and `??` matches
//! any byte at all. ASCII whitespace between bytes is ignored, so `60 E8 ?? ?? ?? ??` and `60E8????????` parse
//! the same. Every pattern is at most [`MAX_PATTERN_BYTES`] long, checked before anything is allocated, so a
//! malformed signature cannot allocate wildly.

/// Upper bound on a pattern's length in bytes. Real entry-point stubs are far shorter, but hand-made PeID
/// databases carry signatures of several hundred bytes.
pub const MAX_PATTERN_BYTES: usize = 4096;

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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// The pattern held no bytes (all whitespace).
    #[error("pattern is empty")]
    Empty,
    /// The hex text had an odd number of nibbles, so a byte was left half-specified.
    #[error("pattern has an odd number of nibbles")]
    OddNibbles,
    /// A character was neither a hex digit, a `?`, nor whitespace.
    #[error("unexpected character {0:?} in pattern")]
    BadChar(char),
    /// The pattern was longer than [`MAX_PATTERN_BYTES`].
    #[error("pattern exceeds {MAX_PATTERN_BYTES} bytes")]
    TooLong,
    /// Every nibble was a wildcard, so the pattern would match anything.
    #[error("pattern has no fixed nibble")]
    AllWildcard,
}

/// The fewest fixed nibbles (four whole bytes' worth) that make a pattern distinctive on its own; a shorter one
/// such as a lone `61` turns up by chance.
pub const MIN_DISTINCTIVE_NIBBLES: usize = 8;

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
        let mut nibbles = text.chars().filter(|c| !c.is_ascii_whitespace());
        // Counted before anything is allocated, so the length bound also bounds memory.
        let count = nibbles.clone().count();
        if count == 0 {
            return Err(PatternError::Empty);
        }
        if !count.is_multiple_of(2) {
            return Err(PatternError::OddNibbles);
        }
        if count / 2 > MAX_PATTERN_BYTES {
            return Err(PatternError::TooLong);
        }
        let mut bytes = Vec::with_capacity(count / 2);
        while let (Some(high), Some(low)) = (nibbles.next(), nibbles.next()) {
            let (high, low) = (nibble(high)?, nibble(low)?);
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
        let pattern = Self { bytes };
        if pattern.fixed_nibbles() == 0 {
            return Err(PatternError::AllWildcard);
        }
        Ok(pattern)
    }

    /// The longest run of fully fixed bytes and its offset in the pattern, or `None` when no byte is fully fixed.
    /// Ties go to the run with fewer `00`/`ff` bytes, which are common filler and so make poor search keys.
    pub fn longest_literal(&self) -> Option<(usize, Vec<u8>)> {
        let filler = |run: &[MaskedByte]| run.iter().filter(|byte| matches!(byte.value, 0x00 | 0xff)).count();
        let mut best: Option<(usize, &[MaskedByte])> = None;
        let mut offset = 0;
        for run in self.bytes.chunk_by(|a, b| (a.mask == 0xff) == (b.mask == 0xff)) {
            let better = best.is_none_or(|(_, kept)| {
                run.len() > kept.len() || (run.len() == kept.len() && filler(run) < filler(kept))
            });
            if run[0].mask == 0xff && better {
                best = Some((offset, run));
            }
            offset += run.len();
        }
        best.map(|(offset, run)| (offset, run.iter().map(|byte| byte.value).collect()))
    }

    /// How many nibbles the pattern pins to a value (two per fully fixed byte).
    pub fn fixed_nibbles(&self) -> usize {
        self.bytes.iter().map(|byte| byte.mask.count_ones() as usize / 4).sum()
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
        data.len() >= self.bytes.len() && self.bytes.iter().zip(data).all(|(p, &b)| b & p.mask == p.value)
    }

    /// The first offset in `data` where the pattern matches, scanning left to right.
    pub fn find_in(&self, data: &[u8]) -> Option<usize> {
        if self.bytes.len() > data.len() {
            return None;
        }
        (0..=data.len() - self.bytes.len()).find(|&start| self.matches_at(&data[start..]))
    }
}

/// One piece of a [`JumpPattern`]: bytes to match, or a relative jump to follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpPiece {
    Bytes(BytePattern),
    /// A signed displacement of this many bytes (1, 2 or 4), read in the image's byte order. Matching continues
    /// at the address just past the displacement plus its value, as a `jmp`/`call` to it would.
    Jump(u8),
}

/// A byte pattern that follows relative jumps, as Detect It Easy's `$` signatures do: `E9 $4 60 BE` matches an
/// `E9` byte, reads a 4-byte displacement, and goes on matching `60 BE` where that jump lands.
///
/// The text is a [`BytePattern`] with whitespace-separated `$1`, `$2` or `$4` tokens where a displacement sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpPattern {
    pieces: Vec<JumpPiece>,
}

impl JumpPattern {
    /// Parses the text form. A pattern needs at least one fixed nibble in its byte pieces; `$` tokens other than
    /// `$1`, `$2` and `$4` are rejected as [`PatternError::BadChar`].
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut pieces = Vec::new();
        let mut bytes = String::new();
        let mut total = 0usize;
        let flush = |bytes: &mut String, pieces: &mut Vec<JumpPiece>, total: &mut usize| -> Result<(), PatternError> {
            if bytes.trim().is_empty() {
                bytes.clear();
                return Ok(());
            }
            let pattern = match BytePattern::parse(bytes) {
                Ok(pattern) => pattern,
                // A run of only wildcards between jumps is still a valid stretch of the whole pattern.
                Err(PatternError::AllWildcard) => BytePattern::wildcards(bytes)?,
                Err(error) => return Err(error),
            };
            *total += pattern.len();
            pieces.push(JumpPiece::Bytes(pattern));
            bytes.clear();
            Ok(())
        };
        for token in text.split_ascii_whitespace() {
            if let Some(size) = token.strip_prefix('$') {
                flush(&mut bytes, &mut pieces, &mut total)?;
                let size = match size {
                    "1" => 1,
                    "2" => 2,
                    "4" => 4,
                    _ => return Err(PatternError::BadChar('$')),
                };
                total += usize::from(size);
                pieces.push(JumpPiece::Jump(size));
            } else {
                bytes.push_str(token);
                bytes.push(' ');
            }
            if total > MAX_PATTERN_BYTES {
                return Err(PatternError::TooLong);
            }
        }
        flush(&mut bytes, &mut pieces, &mut total)?;
        if total > MAX_PATTERN_BYTES {
            return Err(PatternError::TooLong);
        }
        let pattern = Self { pieces };
        if pattern.fixed_nibbles() == 0 {
            return Err(if pattern.pieces.is_empty() { PatternError::Empty } else { PatternError::AllWildcard });
        }
        Ok(pattern)
    }

    /// The pieces in order.
    pub fn pieces(&self) -> &[JumpPiece] {
        &self.pieces
    }

    /// Whether the pattern follows no jump, so it is a plain [`BytePattern`].
    pub fn into_plain(self) -> Result<BytePattern, Self> {
        match self.pieces.as_slice() {
            [JumpPiece::Bytes(pattern)] => Ok(pattern.clone()),
            _ => Err(self),
        }
    }

    /// Fixed nibbles across every byte piece.
    pub fn fixed_nibbles(&self) -> usize {
        self.pieces
            .iter()
            .map(|piece| match piece {
                JumpPiece::Bytes(pattern) => pattern.fixed_nibbles(),
                JumpPiece::Jump(_) => 0,
            })
            .sum()
    }

    /// Matches starting at `address`, reading memory through `read(address, len)` (file-backed bytes only).
    pub fn matches_from(
        &self,
        mut address: u64,
        big_endian: bool,
        read: impl Fn(u64, usize) -> Option<Vec<u8>>,
    ) -> bool {
        for piece in &self.pieces {
            match piece {
                JumpPiece::Bytes(pattern) => {
                    let Some(bytes) = read(address, pattern.len()) else { return false };
                    if !pattern.matches_at(&bytes) {
                        return false;
                    }
                    let Some(next) = address.checked_add(pattern.len() as u64) else { return false };
                    address = next;
                }
                JumpPiece::Jump(size) => {
                    let Some(bytes) = read(address, usize::from(*size)) else { return false };
                    let displacement: i64 = match (size, big_endian) {
                        (1, _) => i64::from(bytes[0] as i8),
                        (2, false) => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
                        (2, true) => i64::from(i16::from_be_bytes([bytes[0], bytes[1]])),
                        (_, false) => i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                        (_, true) => i64::from(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                    };
                    let Some(next) =
                        address.checked_add(u64::from(*size)).and_then(|after| after.checked_add_signed(displacement))
                    else {
                        return false;
                    };
                    address = next;
                }
            }
        }
        true
    }
}

impl BytePattern {
    /// Bytes the pattern matches: its fixed bits, with every wildcard bit zero.
    #[cfg(test)]
    pub(crate) fn example(&self) -> Vec<u8> {
        self.bytes.iter().map(|byte| byte.value).collect()
    }

    /// A pattern of only `??` bytes, as many as `text` holds; used inside a [`JumpPattern`], never on its own.
    fn wildcards(text: &str) -> Result<Self, PatternError> {
        let count = text.chars().filter(|c| !c.is_ascii_whitespace()).count();
        if !count.is_multiple_of(2) {
            return Err(PatternError::OddNibbles);
        }
        if let Some(bad) = text.chars().find(|c| !c.is_ascii_whitespace() && *c != '?') {
            return Err(PatternError::BadChar(bad));
        }
        Ok(Self { bytes: vec![MaskedByte { value: 0, mask: 0 }; count / 2] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_patterns_follow_displacements() {
        // E9 +2 lands past two filler bytes on 60 BE.
        let pattern = JumpPattern::parse("E9 $4 60 BE").unwrap();
        let memory = [0xe9, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0x60, 0xbe];
        let read = |address: u64, len: usize| memory.get(address as usize..address as usize + len).map(<[u8]>::to_vec);
        assert!(pattern.matches_from(0, false, read));
        assert!(!pattern.matches_from(1, false, read));
        // A backward one-byte jump.
        let back = JumpPattern::parse("EB $1").unwrap();
        let spin = [0xeb, 0xfe];
        assert!(back.matches_from(0, false, |address, len| {
            spin.get(address as usize..address as usize + len).map(<[u8]>::to_vec)
        }));
        assert_eq!(JumpPattern::parse("$3 E8"), Err(PatternError::BadChar('$')));
        assert_eq!(JumpPattern::parse("?? $4 ??"), Err(PatternError::AllWildcard));
        assert!(JumpPattern::parse("60 E8").unwrap().into_plain().is_ok());
        assert!(JumpPattern::parse("$4 ?? ?? 55").is_ok());
    }

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
        assert_eq!(BytePattern::parse("?? ??"), Err(PatternError::AllWildcard));
    }

    #[test]
    fn the_longest_fixed_run_is_the_search_literal() {
        let literal = |text: &str| BytePattern::parse(text).unwrap().longest_literal();
        assert_eq!(literal("60 ?? E8 01 02 ?? 03"), Some((2, vec![0xe8, 0x01, 0x02])));
        assert_eq!(literal("00 00 ?? 8B EC"), Some((3, vec![0x8b, 0xec])));
        assert_eq!(literal("6? ?0"), None);
    }

    #[test]
    fn fixed_nibbles_count_pinned_halves() {
        assert_eq!(BytePattern::parse("60 ?? 6? ?0").unwrap().fixed_nibbles(), 4);
    }
}
