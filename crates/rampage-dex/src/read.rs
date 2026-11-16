//! Bounds-checked little-endian reads, LEB128 and modified UTF-8, shared by the DEX and binary XML readers.

use crate::error::{DexError, Result};

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A forward cursor over `data` that refuses to read past its end.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn eof(&self, what: &str) -> DexError {
        DexError::Malformed(format!("{what} at offset {:#x} runs past the end of the file", self.pos))
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let byte = *self.data.get(self.pos).ok_or_else(|| self.eof("byte"))?;
        self.pos += 1;
        Ok(byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let value = u16_at(self.data, self.pos).ok_or_else(|| self.eof("u16"))?;
        self.pos += 2;
        Ok(value)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let value = u32_at(self.data, self.pos).ok_or_else(|| self.eof("u32"))?;
        self.pos += 4;
        Ok(value)
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or_else(|| self.eof("range"))?;
        let bytes = self.data.get(self.pos..end).ok_or_else(|| self.eof("range"))?;
        self.pos = end;
        Ok(bytes)
    }

    /// An unsigned LEB128 of at most five bytes whose value fits 32 bits.
    pub(crate) fn uleb128(&mut self) -> Result<u32> {
        let start = self.pos;
        let mut value = 0u64;
        for shift in 0..5 {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << (shift * 7);
            if byte & 0x80 == 0 {
                return u32::try_from(value)
                    .map_err(|_| DexError::Malformed(format!("uleb128 at {start:#x} overflows 32 bits")));
            }
        }
        Err(DexError::Malformed(format!("uleb128 at {start:#x} is longer than five bytes")))
    }

    /// A signed LEB128 of at most five bytes.
    pub(crate) fn sleb128(&mut self) -> Result<i32> {
        let start = self.pos;
        let mut value = 0i64;
        for shift in 0..5 {
            let byte = self.u8()?;
            value |= i64::from(byte & 0x7f) << (shift * 7);
            if byte & 0x80 == 0 {
                let bits = (shift + 1) * 7;
                if bits < 64 && byte & 0x40 != 0 {
                    value |= -1i64 << bits;
                }
                return i32::try_from(value)
                    .map_err(|_| DexError::Malformed(format!("sleb128 at {start:#x} overflows 32 bits")));
            }
        }
        Err(DexError::Malformed(format!("sleb128 at {start:#x} is longer than five bytes")))
    }
}

/// A decoded modified UTF-8 string, and whether its bytes were well formed and matched the declared length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutf8 {
    pub text: String,
    /// Ill-formed bytes were replaced with U+FFFD, or the UTF-16 length differed from the declared one.
    pub malformed: bool,
}

/// Decodes the NUL-terminated modified UTF-8 at `data[offset..]`: NUL is `C0 80` and characters outside the BMP are
/// surrogate pairs of three bytes each. `utf16_len` is the declared length in UTF-16 units; at most `max_bytes` bytes
/// are read.
pub(crate) fn mutf8(data: &[u8], offset: usize, utf16_len: u32, max_bytes: usize) -> Result<Mutf8> {
    let tail = data
        .get(offset..)
        .ok_or_else(|| DexError::Malformed(format!("string data at {offset:#x} is outside the file")))?;
    let window = &tail[..tail.len().min(max_bytes.saturating_add(1))];
    let end = window.iter().position(|&byte| byte == 0).ok_or_else(|| {
        DexError::Malformed(format!("string at {offset:#x} has no terminating NUL within {max_bytes} bytes"))
    })?;
    let bytes = &window[..end];
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len().min(utf16_len as usize));
    let mut malformed = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let continuation = |at: usize| bytes.get(at).copied().filter(|byte| byte & 0xc0 == 0x80);
        if byte < 0x80 {
            units.push(u16::from(byte));
            index += 1;
        } else if byte & 0xe0 == 0xc0 {
            match continuation(index + 1) {
                Some(next) => {
                    units.push((u16::from(byte & 0x1f) << 6) | u16::from(next & 0x3f));
                    index += 2;
                }
                None => {
                    units.push(0xfffd);
                    malformed = true;
                    index += 1;
                }
            }
        } else if byte & 0xf0 == 0xe0 {
            match (continuation(index + 1), continuation(index + 2)) {
                (Some(second), Some(third)) => {
                    units.push(
                        (u16::from(byte & 0x0f) << 12) | (u16::from(second & 0x3f) << 6) | u16::from(third & 0x3f),
                    );
                    index += 3;
                }
                _ => {
                    units.push(0xfffd);
                    malformed = true;
                    index += 1;
                }
            }
        } else {
            units.push(0xfffd);
            malformed = true;
            index += 1;
        }
    }
    if units.len() != utf16_len as usize {
        malformed = true;
    }
    let text = char::decode_utf16(units.iter().copied())
        .map(|unit| {
            unit.unwrap_or_else(|_| {
                malformed = true;
                '\u{fffd}'
            })
        })
        .collect();
    Ok(Mutf8 { text, malformed })
}

/// Adler-32 of `data`, as the DEX header checksum uses.
pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_bounds() {
        assert_eq!(Cursor::new(&[0xe5, 0x8e, 0x26], 0).uleb128().unwrap(), 624_485);
        assert_eq!(Cursor::new(&[0x7f], 0).sleb128().unwrap(), -1);
        assert_eq!(Cursor::new(&[0x80, 0x7f], 0).sleb128().unwrap(), -128);
        assert!(Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0x7f], 0).uleb128().is_err());
        assert!(Cursor::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 0).uleb128().is_err());
        assert!(Cursor::new(&[0x80], 0).uleb128().is_err());
        assert_eq!(Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0).uleb128().unwrap(), u32::MAX);
    }

    #[test]
    fn mutf8_decodes_nul_and_surrogates_and_flags_bad_bytes() {
        let decoded = mutf8(b"a\xc0\x80b\0", 0, 3, 64).unwrap();
        assert_eq!(decoded.text, "a\0b");
        assert!(!decoded.malformed);
        // U+1F600 as a surrogate pair, three bytes per half.
        let decoded = mutf8(b"\xed\xa0\xbd\xed\xb8\x80\0", 0, 2, 64).unwrap();
        assert_eq!(decoded.text, "\u{1f600}");
        let decoded = mutf8(b"\xff\xc3\0", 0, 2, 64).unwrap();
        assert!(decoded.malformed);
        assert!(mutf8(b"abc", 0, 3, 64).is_err());
        assert!(mutf8(b"abcdef\0", 0, 6, 3).is_err());
    }

    #[test]
    fn adler32_matches_the_reference() {
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }
}
