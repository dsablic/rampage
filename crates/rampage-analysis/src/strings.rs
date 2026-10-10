use rampage_loaders::Binary;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundString {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub encoding: Encoding,
    pub text: String,
}

/// Strings in the image's data. Runs inside code sections are left out: there they are instruction bytes that
/// happen to be printable (push sequences such as `UAWAVAUATVWSH`), not text.
pub fn scan(binary: &Binary, min_len: usize) -> Vec<FoundString> {
    let mut found = Vec::new();
    for segment in &binary.segments {
        if let Some(bytes) = binary.read_to_segment_end(segment.address) {
            found
                .extend(scan_bytes(bytes, segment.address, min_len).into_iter().filter(|s| !binary.is_code(s.address)));
        }
    }
    found
}

/// ASCII and UTF-16LE runs are found by independent passes, so a run of one encoding never hides the other.
pub fn scan_bytes(bytes: &[u8], base_address: u64, min_len: usize) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut found = Vec::new();
    let at = |offset: usize| base_address + offset as u64;

    let mut offset = 0;
    while offset < bytes.len() {
        let len = bytes[offset..].iter().take_while(|&&byte| is_printable(byte)).count();
        if len >= min_len {
            let text = bytes[offset..offset + len].iter().map(|&byte| byte as char).collect();
            found.push(FoundString { address: at(offset), encoding: Encoding::Ascii, text });
        }
        offset += len.max(1);
    }

    let mut offset = 0;
    while offset < bytes.len() {
        let len = utf16le_run(&bytes[offset..]);
        if len >= min_len {
            let text = bytes[offset..offset + len * 2].iter().step_by(2).map(|&byte| byte as char).collect();
            found.push(FoundString { address: at(offset), encoding: Encoding::Utf16Le, text });
            offset += len * 2;
        } else {
            offset += 1;
        }
    }

    found.sort_by_key(|string| string.address);
    found
}

fn utf16le_run(bytes: &[u8]) -> usize {
    bytes.as_chunks::<2>().0.iter().take_while(|&&[low, high]| is_printable(low) && high == 0).count()
}

fn is_printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) || byte == b'\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(found: &[FoundString]) -> Vec<(u64, Encoding, &str)> {
        found.iter().map(|string| (string.address, string.encoding, string.text.as_str())).collect()
    }

    #[test]
    fn finds_ascii_runs_at_or_above_minimum_length() {
        let found = scan_bytes(b"\x00abc\x00hello\x01world!\x00", 0x100, 4);
        assert_eq!(texts(&found), [(0x105, Encoding::Ascii, "hello"), (0x10b, Encoding::Ascii, "world!")]);
    }

    #[test]
    fn finds_utf16le_runs_at_any_alignment() {
        let found = scan_bytes(b"\xffW\x00i\x00d\x00e\x00\x00\x00", 0, 4);
        assert_eq!(texts(&found), [(1, Encoding::Utf16Le, "Wide")]);
    }

    #[test]
    fn utf16le_after_a_printable_byte_is_found() {
        assert_eq!(texts(&scan_bytes(b"xW\0i\0d\0e\0\0\0", 0, 4)), [(1, Encoding::Utf16Le, "Wide")]);
    }

    #[test]
    fn utf16le_directly_after_an_ascii_string_is_found() {
        let found = scan_bytes(b"\0helloW\0i\0d\0e\0\0\0", 0, 4);
        assert_eq!(texts(&found), [(1, Encoding::Ascii, "helloW"), (6, Encoding::Utf16Le, "Wide")]);
    }

    #[test]
    fn string_at_end_of_buffer_is_reported() {
        assert_eq!(texts(&scan_bytes(b"\x00tail", 0, 4)), [(1, Encoding::Ascii, "tail")]);
    }
}
