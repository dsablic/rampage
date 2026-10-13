//! The `#Strings`, `#US`, `#GUID` and `#Blob` heaps (II.24.2.2 - II.24.2.5).

/// Longest identifier read from `#Strings`; real names are far shorter, generated ones rarely exceed this.
const MAX_NAME_BYTES: usize = 1024;
/// Caps on the `#US` literals collected, so a huge or hostile heap cannot dominate the result.
pub(super) const MAX_USER_STRINGS: usize = 65_536;
const MAX_USER_STRING_UNITS: usize = 4096;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Heaps<'a> {
    pub(super) strings: &'a [u8],
    pub(super) user_strings: &'a [u8],
    pub(super) guids: &'a [u8],
    pub(super) blobs: &'a [u8],
}

impl<'a> Heaps<'a> {
    /// The NUL-terminated UTF-8 identifier at `offset`, or `None` when the offset lies outside the heap.
    /// Unterminated or overlong names are cut at the heap end or the length cap.
    pub(super) fn string(&self, offset: u32) -> Option<String> {
        let tail = self.strings.get(usize::try_from(offset).ok()?..)?;
        let tail = &tail[..tail.len().min(MAX_NAME_BYTES)];
        let end = tail.iter().position(|&byte| byte == 0).unwrap_or(tail.len());
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    /// The 1-based GUID at `index` as its canonical text; index 0 is the null GUID and yields `None`.
    pub(super) fn guid(&self, index: u32) -> Option<String> {
        let start = usize::try_from(index.checked_sub(1)?).ok()?.checked_mul(16)?;
        let bytes = self.guids.get(start..start.checked_add(16)?)?;
        // The first three groups are stored little-endian, the last two as bytes (the Windows GUID layout).
        Some(format!(
            "{:08x}-{:04x}-{:04x}-{}-{}",
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
            u16::from_le_bytes([bytes[6], bytes[7]]),
            hex(&bytes[8..10]),
            hex(&bytes[10..16])
        ))
    }

    /// The blob at `offset`, without its length prefix.
    pub(super) fn blob(&self, offset: u32) -> Option<&'a [u8]> {
        let tail = self.blobs.get(usize::try_from(offset).ok()?..)?;
        let (length, header) = compressed_length(tail)?;
        tail.get(header..header.checked_add(length)?)
    }

    /// The `#US` entry at `offset`, what `ldstr` loads: at most `cap` of its UTF-16 code units, and its full
    /// length in units. `None` when the offset or the entry's length lies outside the heap.
    pub(super) fn user_string(&self, offset: u32, cap: usize) -> Option<(Vec<u16>, usize)> {
        let tail = self.user_strings.get(usize::try_from(offset).ok()?..)?;
        let (length, header) = compressed_length(tail)?;
        let body = tail.get(header..header.checked_add(length)?)?;
        // The odd byte at the end of a well-formed entry is a flag, not text.
        let units = body.as_chunks::<2>().0;
        Some((units.iter().take(cap).map(|&pair| u16::from_le_bytes(pair)).collect(), units.len()))
    }

    /// Every literal in `#US`, in heap order. Each entry is a compressed length, UTF-16LE text and one trailing
    /// flag byte (II.24.2.4); a malformed entry ends the walk.
    pub(super) fn user_string_literals(&self) -> (Vec<String>, bool) {
        let mut literals = Vec::new();
        // Offset 0 is the mandatory empty entry.
        let mut offset = 1usize;
        while let Some(tail) = self.user_strings.get(offset..).filter(|tail| !tail.is_empty()) {
            let Some((length, header)) = compressed_length(tail) else {
                return (literals, false);
            };
            let Some(body) = header.checked_add(length).and_then(|end| tail.get(header..end)) else {
                return (literals, false);
            };
            if length > 1 {
                let units = ((length - 1) / 2).min(MAX_USER_STRING_UNITS);
                let text: Vec<u16> =
                    body.as_chunks::<2>().0.iter().take(units).map(|&pair| u16::from_le_bytes(pair)).collect();
                if literals.len() == MAX_USER_STRINGS {
                    return (literals, false);
                }
                literals.push(String::from_utf16_lossy(&text));
            }
            offset += header + length;
        }
        (literals, true)
    }
}

/// Decodes a compressed unsigned length (II.23.2): returns `(value, bytes used)`.
pub(super) fn compressed_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        Some((usize::from(first), 1))
    } else if first & 0xC0 == 0x80 {
        Some(((usize::from(first & 0x3F) << 8) | usize::from(*bytes.get(1)?), 2))
    } else if first & 0xE0 == 0xC0 {
        let rest = bytes.get(1..4)?;
        let value = (u32::from(first & 0x1F) << 24)
            | (u32::from(rest[0]) << 16)
            | (u32::from(rest[1]) << 8)
            | u32::from(rest[2]);
        Some((usize::try_from(value).ok()?, 4))
    } else {
        None
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_compressed_lengths() {
        assert_eq!(compressed_length(&[0x03]), Some((3, 1)));
        assert_eq!(compressed_length(&[0x80, 0x80]), Some((0x80, 2)));
        assert_eq!(compressed_length(&[0xC0, 0x00, 0x40, 0x00]), Some((0x4000, 4)));
        assert_eq!(compressed_length(&[0xC0, 0x00]), None);
        assert_eq!(compressed_length(&[0xE0]), None);
        assert_eq!(compressed_length(&[]), None);
    }

    #[test]
    fn reads_bounded_strings_and_guids() {
        let heaps = Heaps { strings: b"\0Foo\0Bar", guids: &[0x11; 16], ..Heaps::default() };
        assert_eq!(heaps.string(1).as_deref(), Some("Foo"));
        assert_eq!(heaps.string(5).as_deref(), Some("Bar"));
        assert_eq!(heaps.string(8).as_deref(), Some(""));
        assert_eq!(heaps.string(9), None);
        assert_eq!(heaps.guid(1).as_deref(), Some("11111111-1111-1111-1111-111111111111"));
        assert_eq!(heaps.guid(0), None);
        assert_eq!(heaps.guid(2), None);
        assert_eq!(heaps.guid(u32::MAX), None);
    }

    #[test]
    fn walks_user_strings() {
        let heaps = Heaps { user_strings: &[0, 5, b'h', 0, b'i', 0, 0, 0, 0], ..Heaps::default() };
        assert_eq!(heaps.user_string_literals(), (vec!["hi".to_owned()], true));
        let truncated = Heaps { user_strings: &[0, 9, b'h', 0], ..Heaps::default() };
        assert_eq!(truncated.user_string_literals(), (vec![], false));
        assert_eq!(heaps.user_string(1, 8), Some((vec![u16::from(b'h'), u16::from(b'i')], 2)));
        assert_eq!(heaps.user_string(1, 1), Some((vec![u16::from(b'h')], 2)));
        assert_eq!(heaps.user_string(0, 8), Some((vec![], 0)));
        assert_eq!(truncated.user_string(1, 8), None);
        assert_eq!(heaps.user_string(u32::MAX, 8), None);
    }
}
