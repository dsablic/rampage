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
    pub address: u64,
    pub encoding: Encoding,
    pub text: String,
}

pub fn scan(binary: &Binary, min_len: usize) -> Vec<FoundString> {
    let mut found = Vec::new();
    for segment in &binary.segments {
        if let Some(bytes) = binary.read_to_segment_end(segment.address) {
            found.extend(scan_bytes(bytes, segment.address, min_len));
        }
    }
    found
}

pub fn scan_bytes(bytes: &[u8], base_address: u64, min_len: usize) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut found = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let ascii_len = bytes[offset..].iter().take_while(|&&byte| is_printable(byte)).count();
        let utf16_len = utf16le_run(&bytes[offset..]);
        if utf16_len >= min_len {
            let text = bytes[offset..offset + utf16_len * 2].iter().step_by(2).map(|&byte| byte as char).collect();
            found.push(FoundString { address: base_address + offset as u64, encoding: Encoding::Utf16Le, text });
            offset += utf16_len * 2;
        } else if ascii_len >= min_len {
            let text = bytes[offset..offset + ascii_len].iter().map(|&byte| byte as char).collect();
            found.push(FoundString { address: base_address + offset as u64, encoding: Encoding::Ascii, text });
            offset += ascii_len;
        } else {
            offset += ascii_len.max(1);
        }
    }
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
    fn string_at_end_of_buffer_is_reported() {
        assert_eq!(texts(&scan_bytes(b"\x00tail", 0, 4)), [(1, Encoding::Ascii, "tail")]);
    }
}
