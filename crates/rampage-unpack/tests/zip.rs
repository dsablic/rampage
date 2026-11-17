//! ZIP archives (APK, AAB, JAR): listing, reading, extraction and hostile directories and members.

use rampage_unpack::{At, EntryKind, Format, Limits, extract, list, read_entries};

use crate::support::Scratch;

/// A ZIP of `(name, content, deflate)` members; `declared` overrides each member's declared uncompressed size.
fn zip(members: &[(&str, &[u8], bool)], declared: Option<u32>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (name, content, deflate) in members {
        let data = if *deflate {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            std::io::Write::write_all(&mut encoder, content).unwrap();
            encoder.finish().unwrap()
        } else {
            content.to_vec()
        };
        let fields = |out: &mut Vec<u8>| {
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(if *deflate { 8u16 } else { 0 }).to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&declared.unwrap_or(content.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
        };
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        fields(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data);
        directory.extend_from_slice(b"PK\x01\x02\x14\x03");
        fields(&mut directory);
        directory.extend_from_slice(&[0; 6]);
        let mode: u32 = if name.ends_with('/') { 0o040_755 } else { 0o100_644 };
        directory.extend_from_slice(&(mode << 16).to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let at = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn a_zip_lists_reads_and_extracts() {
    let scratch = Scratch::new("zip");
    let path = scratch.join("app.apk");
    let text = b"hello hello hello hello hello".repeat(100);
    std::fs::write(&path, zip(&[("lib/", b"", false), ("lib/a.txt", &text, true), ("b.bin", b"raw", false)], None))
        .unwrap();
    let listing = list(&path, At::default(), &[], Limits::default()).unwrap();
    assert_eq!(listing.layers[0].format, Format::Zip);
    let kinds: Vec<(&str, EntryKind, u64)> =
        listing.entries.iter().map(|entry| (entry.path.as_str(), entry.kind, entry.size)).collect();
    assert_eq!(
        kinds,
        [("lib", EntryKind::Dir, 0), ("lib/a.txt", EntryKind::File, 2900), ("b.bin", EntryKind::File, 3)]
    );
    let selected = read_entries(&path, At::default(), &[], Limits::default(), &mut |_| true).unwrap();
    assert_eq!(selected.contents.len(), 2);
    assert_eq!(selected.contents[0].1, text);
    let out = scratch.join("out");
    extract(&path, At::default(), &[], &out, &[], Limits::default()).unwrap();
    assert_eq!(std::fs::read(out.join("b.bin")).unwrap(), b"raw");
}

#[test]
fn members_inflating_past_their_declared_size_are_refused() {
    let scratch = Scratch::new("zip-lie");
    let path = scratch.join("lie.zip");
    std::fs::write(&path, zip(&[("a", &[7u8; 10_000], true)], Some(100))).unwrap();
    assert!(read_entries(&path, At::default(), &[], Limits::default(), &mut |_| true).is_err());
}

#[test]
fn a_zip_bomb_is_refused_by_the_ratio_meter() {
    let scratch = Scratch::new("zip-bomb");
    let path = scratch.join("bomb.zip");
    let zeros = vec![0u8; 80 << 20];
    std::fs::write(&path, zip(&[("zeros", &zeros, true)], None)).unwrap();
    let limits = Limits { max_ratio: 100, ..Limits::default() };
    let error = read_entries(&path, At::default(), &[], limits, &mut |_| true).unwrap_err();
    assert!(error.to_string().contains("ratio"), "{error}");
    let small = Limits { max_file_bytes: 1 << 20, ..Limits::default() };
    assert!(read_entries(&path, At::default(), &[], small, &mut |_| true).is_err());
}

#[test]
fn overlapping_members_are_noted() {
    let scratch = Scratch::new("zip-overlap");
    let path = scratch.join("overlap.zip");
    let mut bytes = zip(&[("a", b"abcdef", false), ("b", b"ghijkl", false)], None);
    // Point the second directory record at the first local header.
    let directory = u32::from_le_bytes(bytes[bytes.len() - 6..bytes.len() - 2].try_into().unwrap()) as usize;
    let second = directory + 46 + 1;
    bytes[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let listing = list(&path, At::default(), &[], Limits::default()).unwrap();
    assert!(listing.layers[0].notes.iter().any(|note| note.contains("overlaps")), "{:?}", listing.layers[0].notes);
    assert!(listing.entries.iter().any(|entry| entry.note.as_deref() == Some("data overlaps another entry")));
}

#[test]
fn lying_directories_are_refused_without_panicking() {
    let good = zip(&[("a", b"abc", false), ("b", b"defg", true)], None);
    let scratch = Scratch::new("zip-fuzz");
    let path = scratch.join("fuzz.zip");
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..2000 {
        let mut bytes = good.clone();
        if round % 3 == 0 {
            bytes.truncate((next() as usize) % bytes.len());
        } else {
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % bytes.len();
                bytes[at] = next() as u8;
            }
        }
        std::fs::write(&path, &bytes).unwrap();
        let _ = read_entries(&path, At::default(), &[], Limits::default(), &mut |_| true);
    }
    // An entry count far beyond what the directory holds.
    let mut bytes = good;
    let eocd = bytes.len() - 22;
    bytes[eocd + 8..eocd + 12].copy_from_slice(&[0xff, 0xfe, 0xff, 0xfe]);
    std::fs::write(&path, &bytes).unwrap();
    assert!(list(&path, At::default(), &[], Limits::default()).is_err());
}
