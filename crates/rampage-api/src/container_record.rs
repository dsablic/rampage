//! A record before a compressed stream that describes it: little-endian words within 64 bytes before the stream that
//! hold its compressed length and its decoded size, and often a checksum of the compressed bytes and the address
//! the decoded image loads at. Fields are found by value, never by a fixed layout, and every role is inferred.

use std::path::Path;

use serde::Serialize;

use crate::range_source::RangeSource;

/// Bytes before the stream that record words are looked for in.
pub const RECORD_WINDOW: usize = 64;
/// The smallest compressed length or decoded size a record is matched for.
const MIN_LENGTH: usize = 16;
/// Powers of two up to this are sizes, alignments or flags more often than load addresses.
const MAX_SIZE_LIKE: u64 = 8 << 20;

/// A load-address-like record word: nonzero and 4 KiB aligned, above the decoded size, and not a power of two up to
/// 8 MiB.
fn address_like(value: u64, decoded_size: u64) -> bool {
    value & 0xfff == 0 && value > decoded_size && !(value.is_power_of_two() && value <= MAX_SIZE_LIKE)
}

/// Words a matched record spans around its length and size fields.
const SPAN: u64 = 16;

/// One word of the record and the role inferred for it.
#[derive(Debug, Clone, Serialize)]
pub struct RecordField {
    /// File offset of the word.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub offset: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
    /// `compressed_length`, `decoded_size`, `payload_offset` (the stream's own file offset), `byte_sum32` or
    /// `crc32` (of the compressed bytes), `address` (4 KiB aligned, above the decoded size and not a power of two up
    /// to 8 MiB: a base_hint) or `unknown`.
    pub role: &'static str,
}

/// An address-like record word, with every field offset that holds it.
#[derive(Debug, Clone, Serialize)]
pub struct RecordBaseHint {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub field_offsets: Vec<u64>,
}

/// The record found before a stream.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerRecord {
    /// The record's words in file order, from 16 bytes before its first matched field to 16 bytes after its last
    /// (within the 64 bytes before the stream).
    pub fields: Vec<RecordField>,
    /// Address-like words, most repeated first: candidate load addresses of the decoded bytes. Base candidates
    /// for the decoded image validate them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub base_hints: Vec<RecordBaseHint>,
    /// The byte range the checksum field covers, when a field equals the byte sum or CRC-32 of the compressed
    /// bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_over: Option<[u64; 2]>,
    pub note: &'static str,
}

const NOTE: &str = "inferred from values: a word equal to the stream's compressed length and one equal to its \
                    decoded size (both required, each at least 16), within 64 bytes before it. A base_hint is a suggestion until the \
                    decoded image's base candidates agree with it";

/// Reads up to [`RECORD_WINDOW`] bytes before `offset` of `path`, with the window's file offset.
pub fn read_window(path: &Path, offset: u64) -> Option<(u64, Vec<u8>)> {
    let start = offset.saturating_sub(RECORD_WINDOW as u64);
    let length = usize::try_from(offset - start).ok().filter(|&length| length > 0)?;
    let source = RangeSource::open(path, start, length).ok()?;
    Some((start, source.read().ok()?))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// The record before a stream at `offset` whose bytes are `input` (the requested range): `consumed` of them
/// decoded to `decoded_size` bytes. `window` holds the file bytes from `window_start` up to `offset`.
pub fn find(
    window_start: u64,
    window: &[u8],
    offset: u64,
    input: &[u8],
    consumed: usize,
    decoded_size: usize,
) -> Option<ContainerRecord> {
    // Tiny lengths match padding and small header fields by chance.
    if consumed < MIN_LENGTH || decoded_size < MIN_LENGTH {
        return None;
    }
    let lengths: Vec<u64> = [consumed, input.len()]
        .into_iter()
        .filter(|&length| length >= MIN_LENGTH)
        .map(|length| length as u64)
        .collect();
    let size = decoded_size as u64;
    // Word positions aligned to the stream, and to the file when the stream is not.
    let mut alignments = vec![offset % 4];
    if !offset.is_multiple_of(4) {
        alignments.push(0);
    }
    for alignment in alignments {
        let words: Vec<(u64, u64)> = (0..window.len().saturating_sub(3))
            .filter(|&at| (window_start + at as u64) % 4 == alignment)
            .map(|at| {
                let word = u32::from_le_bytes(window[at..at + 4].try_into().expect("four bytes"));
                (window_start + at as u64, u64::from(word))
            })
            .collect();
        let length_at = words.iter().rev().find(|(_, value)| lengths.contains(value)).map(|&(at, _)| at);
        let size_at =
            words.iter().rev().find(|&&(at, value)| value == size && Some(at) != length_at).map(|&(at, _)| at);
        let (Some(length_at), Some(size_at)) = (length_at, size_at) else { continue };
        let first = length_at.min(size_at).saturating_sub(SPAN);
        let last = length_at.max(size_at) + SPAN;
        let checksums = |end: usize| {
            let bytes = &input[..end.min(input.len())];
            (bytes.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))), crc32(bytes))
        };
        let sums: Vec<(usize, (u32, u32))> = {
            let mut ends = vec![consumed.min(input.len()), input.len()];
            ends.dedup();
            ends.retain(|&end| end > 0);
            ends.into_iter().map(|end| (end, checksums(end))).collect()
        };
        let mut checksum_over = None;
        let mut fields = Vec::new();
        for &(at, value) in words.iter().filter(|&&(at, _)| (first..=last).contains(&at) && at + 4 <= offset) {
            let role = if at == length_at {
                "compressed_length"
            } else if at == size_at {
                "decoded_size"
            } else if value == offset {
                "payload_offset"
            } else if let Some(&(end, (sum, _))) =
                sums.iter().find(|(_, (sum, crc))| value == u64::from(*sum) || value == u64::from(*crc))
            {
                checksum_over = Some([offset, offset + end as u64]);
                if value == u64::from(sum) { "byte_sum32" } else { "crc32" }
            } else if address_like(value, size) {
                "address"
            } else {
                "unknown"
            };
            fields.push(RecordField { offset: at, value, role });
        }
        let mut base_hints: Vec<RecordBaseHint> = Vec::new();
        for field in fields.iter().filter(|field| field.role == "address") {
            match base_hints.iter_mut().find(|hint| hint.base_address == field.value) {
                Some(hint) => hint.field_offsets.push(field.offset),
                None => {
                    base_hints.push(RecordBaseHint { base_address: field.value, field_offsets: vec![field.offset] })
                }
            }
        }
        base_hints.sort_by(|left, right| {
            right
                .field_offsets
                .len()
                .cmp(&left.field_offsets.len())
                .then(right.base_address.trailing_zeros().cmp(&left.base_address.trailing_zeros()))
                .then(left.field_offsets[0].cmp(&right.field_offsets[0]))
        });
        return Some(ContainerRecord { fields, base_hints, checksum_over, note: NOTE });
    }
    None
}

/// [`find`], reading the window before `offset` and the `length` bytes of the stream's range from `path`.
pub fn find_in_file(
    path: &Path,
    offset: u64,
    length: usize,
    consumed: usize,
    decoded_size: usize,
) -> Option<ContainerRecord> {
    let (start, window) = read_window(path, offset)?;
    let input = RangeSource::open(path, offset, length).ok()?.read().ok()?;
    find(start, &window, offset, &input, consumed, decoded_size)
}

impl ContainerRecord {
    /// The base hints as [`rampage_loaders::raw_base::BaseHint`]s naming their fields.
    pub fn hints(&self) -> Vec<rampage_loaders::raw_base::BaseHint> {
        self.base_hints
            .iter()
            .map(|hint| rampage_loaders::raw_base::BaseHint {
                base_address: hint.base_address,
                source: format!(
                    "container record field{} at {}",
                    if hint.field_offsets.len() == 1 { "" } else { "s" },
                    hint.field_offsets.iter().map(|offset| format!("{offset:#x}")).collect::<Vec<_>>().join(", ")
                ),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    /// A six-word record (address, offset, compressed length, byte sum, address, decoded size) right before the
    /// stream, behind unrelated header words.
    #[test]
    fn a_record_names_length_size_sum_and_base() {
        let input: Vec<u8> = (0..100u32).map(|value| (value * 7) as u8).collect();
        let sum = input.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
        let mut window = words(&[0x1234_5678, 0xdead_beef]);
        window.extend(words(&[0x6000_0000, 0x40, 100, sum, 0x6000_0000, 400]));
        let offset = 0x1000 + window.len() as u64;
        let record = find(0x1000, &window, offset, &input, 100, 400).unwrap();
        let roles: Vec<_> = record.fields.iter().map(|field| field.role).collect();
        assert_eq!(
            roles,
            ["unknown", "unknown", "address", "unknown", "compressed_length", "byte_sum32", "address", "decoded_size"]
        );
        assert_eq!(record.base_hints.len(), 1);
        assert_eq!(record.base_hints[0].base_address, 0x6000_0000);
        assert_eq!(record.base_hints[0].field_offsets, [0x1008, 0x1018]);
        assert_eq!(record.checksum_over, Some([offset, offset + 100]));
        assert_eq!(record.hints()[0].source, "container record fields at 0x1008, 0x1018");
    }

    #[test]
    fn a_crc_and_a_shorter_consumed_length_are_matched() {
        let input = b"compressed bytes and trailing padding".to_vec();
        let crc = crc32(&input[..16]);
        let window = words(&[16, 0x9000_0000, crc, 64]);
        let record = find(0, &window, 16, &input, 16, 64).unwrap();
        let roles: Vec<_> = record.fields.iter().map(|field| field.role).collect();
        assert_eq!(roles, ["compressed_length", "address", "crc32", "decoded_size"]);
        assert_eq!(record.checksum_over, Some([16, 32]));
    }

    /// Size-like words (a power of two, a value below the decoded size) are not addresses, and a hint needs both
    /// lengths of at least 16 bytes.
    #[test]
    fn sizes_flags_and_tiny_lengths_are_not_records_or_addresses() {
        let input = vec![1u8; 0x100];
        let window = words(&[0x1000, 0x8000, 0x4_0000, 0x100, 0x3000, 0x2_0000]);
        let record = find(0, &window, 24, &input, 0x100, 0x2_0000).unwrap();
        let roles: Vec<_> = record.fields.iter().map(|field| field.role).collect();
        assert_eq!(roles, ["unknown", "unknown", "unknown", "compressed_length", "unknown", "decoded_size"]);
        assert!(record.base_hints.is_empty());
        // Lengths under 16 bytes: a coincidental 8 in the header is not a record.
        assert!(find(0, &words(&[8, 0x6000_0000, 12]), 12, &[0u8; 8], 8, 12).is_none());
        // A zero window matches nothing.
        assert!(find(0, &[0; 64], 64, &input, 0x100, 0x400).is_none());
    }

    /// One word can be the compressed length or the decoded size, not both.
    #[test]
    fn equal_length_and_size_need_two_words() {
        let input = vec![1u8; 0x40];
        assert!(find(0, &words(&[0x40, 0x6000_0000]), 8, &input, 0x40, 0x40).is_none());
        let record = find(0, &words(&[0x40, 0x6000_0000, 0x40]), 12, &input, 0x40, 0x40).unwrap();
        assert_eq!(record.base_hints[0].base_address, 0x6000_0000);
    }

    #[test]
    fn without_both_length_and_size_there_is_no_record() {
        let input = vec![0u8; 32];
        assert!(find(0, &words(&[32, 0x6000_0000, 0]), 12, &input, 32, 128).is_none());
        assert!(find(0, &words(&[128, 0x6000_0000]), 8, &input, 32, 128).is_none());
        assert!(find(0, &[], 0, &input, 32, 128).is_none());
    }
}
