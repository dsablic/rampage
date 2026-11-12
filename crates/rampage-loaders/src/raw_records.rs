//! Intel HEX and Motorola S-record text as a source of Raw regions. Addresses come from the data records; runs of
//! contiguous records become one region each. Every record's checksum is verified, nothing is filled or merged
//! across a gap, and overlapping records are refused. The start-address record (Intel HEX 03/05, S7/S8/S9) is
//! returned as written; whether it becomes the entry is the Raw admission's reported verdict.

use serde::Serialize;

use crate::LoadError;

/// Largest record text admitted: 4 MiB of data in 16-byte Intel HEX records is about 11.5 MiB.
pub const MAX_RAW_RECORD_TEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRecordFormat {
    /// Intel HEX (`:LLAAAATT...CC`), with extended segment and extended linear address records.
    Ihex,
    /// Motorola S-records (S1/S2/S3 data, S7/S8/S9 start address).
    Srec,
}

impl RawRecordFormat {
    pub fn name(self) -> &'static str {
        match self {
            RawRecordFormat::Ihex => "ihex",
            RawRecordFormat::Srec => "srec",
        }
    }
}

/// What a record file holds: contiguous byte runs by ascending address, and the start address it states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecords {
    pub format: RawRecordFormat,
    /// Contiguous runs, ascending and disjoint: (address of the first byte, bytes).
    pub runs: Vec<(u64, Vec<u8>)>,
    /// Data records read.
    pub data_records: usize,
    /// The start-address record's value as written (a Thumb entry keeps bit 0), when the file has one.
    pub start_address: Option<u64>,
}

fn malformed(format: RawRecordFormat, line: usize, message: impl std::fmt::Display) -> LoadError {
    LoadError::Malformed(format!("Raw {} record line {line}: {message}", format.name()))
}

fn hex_bytes(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |byte: u8| char::from(byte).to_digit(16).map(|digit| digit as u8);
    text.as_chunks::<2>().0.iter().map(|&[high, low]| Some(digit(high)? << 4 | digit(low)?)).collect()
}

fn big_endian(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |value, &byte| value << 8 | u64::from(byte))
}

/// Parses `text` as `format`, admitting at most `max_data_bytes` of record data. Refuses a bad checksum, an unknown
/// record type, a missing end record, data after it, overlapping records and addresses past 32 bits.
pub fn parse_raw_records(text: &[u8], format: RawRecordFormat, max_data_bytes: usize) -> Result<RawRecords, LoadError> {
    if text.len() > MAX_RAW_RECORD_TEXT_BYTES {
        return Err(LoadError::Malformed(format!(
            "Raw {} record text exceeds {MAX_RAW_RECORD_TEXT_BYTES} bytes",
            format.name()
        )));
    }
    let mut records: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut data_bytes = 0_usize;
    let mut start_address = None;
    let mut ended = false;
    // Intel HEX: the base the last extended segment (02) or extended linear (04) address record set.
    let mut upper = 0_u64;
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let number = index + 1;
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let bad = |message: &str| malformed(format, number, message);
        if ended {
            return Err(bad("a record follows the end record"));
        }
        let mut data = |address: u64, bytes: &[u8]| -> Result<(), LoadError> {
            if bytes.is_empty() {
                return Ok(());
            }
            if address.checked_add(bytes.len() as u64).is_none_or(|end| end > 1 << 32) {
                return Err(bad("data lies past the 32-bit address space"));
            }
            data_bytes += bytes.len();
            if data_bytes > max_data_bytes {
                return Err(LoadError::Malformed(format!(
                    "Raw {} records hold more than {max_data_bytes} data bytes",
                    format.name()
                )));
            }
            records.push((address, bytes.to_vec()));
            Ok(())
        };
        match format {
            RawRecordFormat::Ihex => {
                let body = line.strip_prefix(b":").and_then(hex_bytes).ok_or_else(|| bad("not ':' and hex digits"))?;
                if body.len() < 5 || body.len() != usize::from(body[0]) + 5 {
                    return Err(bad("length field disagrees with the record"));
                }
                if body.iter().fold(0_u8, |sum, &byte| sum.wrapping_add(byte)) != 0 {
                    return Err(bad("checksum mismatch"));
                }
                let offset = big_endian(&body[1..3]);
                let payload = &body[4..body.len() - 1];
                match (body[3], payload.len()) {
                    (0, _) => data(upper + offset, payload)?,
                    (1, 0) => ended = true,
                    (2, 2) => upper = big_endian(payload) << 4,
                    (3, 4) => start_address = Some((big_endian(&payload[..2]) << 4) + big_endian(&payload[2..])),
                    (4, 2) => upper = big_endian(payload) << 16,
                    (5, 4) => start_address = Some(big_endian(payload)),
                    (1..=5, _) => return Err(bad("record type has the wrong length")),
                    _ => return Err(bad("unknown record type")),
                }
            }
            RawRecordFormat::Srec => {
                let kind = match line {
                    [b'S', kind @ b'0'..=b'9', ..] => kind - b'0',
                    _ => return Err(bad("not 'S', a type digit and hex digits")),
                };
                let body = hex_bytes(&line[2..]).ok_or_else(|| bad("not hex digits"))?;
                if body.len() < 2 || body.len() != usize::from(body[0]) + 1 {
                    return Err(bad("count field disagrees with the record"));
                }
                if body.iter().fold(0_u8, |sum, &byte| sum.wrapping_add(byte)) != 0xff {
                    return Err(bad("checksum mismatch"));
                }
                let address_bytes = match kind {
                    0 | 1 | 5 | 9 => 2,
                    2 | 6 | 8 => 3,
                    3 | 7 => 4,
                    _ => return Err(bad("unknown record type")),
                };
                let fields = &body[1..body.len() - 1];
                if fields.len() < address_bytes {
                    return Err(bad("record is shorter than its address"));
                }
                let (address, payload) = fields.split_at(address_bytes);
                match kind {
                    1..=3 => data(big_endian(address), payload)?,
                    7..=9 if payload.is_empty() => {
                        start_address = Some(big_endian(address));
                        ended = true;
                    }
                    7..=9 => return Err(bad("start-address record carries data")),
                    // S0 header text and S5/S6 record counts carry no mapped bytes.
                    _ => {}
                }
            }
        }
    }
    if !ended {
        return Err(LoadError::Malformed(format!(
            "Raw {} records have no end record: the file is truncated or not {}",
            format.name(),
            format.name()
        )));
    }
    let data_records = records.len();
    records.sort_by_key(|(address, _)| *address);
    let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
    for (address, bytes) in records {
        match runs.last_mut() {
            Some((base, run)) if *base + run.len() as u64 == address => run.extend_from_slice(&bytes),
            Some((base, run)) if *base + run.len() as u64 > address => {
                return Err(LoadError::Malformed(format!(
                    "Raw {} records overlap at {address:#x}; nothing is chosen between them",
                    format.name()
                )));
            }
            _ => runs.push((address, bytes)),
        }
    }
    if runs.is_empty() {
        return Err(LoadError::Malformed(format!("Raw {} records hold no data", format.name())));
    }
    Ok(RawRecords { format, runs, data_records, start_address })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ihex(text: &str) -> Result<RawRecords, LoadError> {
        parse_raw_records(text.as_bytes(), RawRecordFormat::Ihex, 1024)
    }

    fn srec(text: &str) -> Result<RawRecords, LoadError> {
        parse_raw_records(text.as_bytes(), RawRecordFormat::Srec, 1024)
    }

    #[test]
    fn intel_hex_runs_follow_extended_addresses_and_merge_only_contiguous_records() {
        let parsed = ihex(
            ":020000040800F2\r\n:0400000001020304F2\r\n:0400040005060708DE\r\n:020010000A0BD9\n\
             :020000042000DA\n:02000000AABB99\n:0400000508000101ED\n:00000001FF\n\n",
        )
        .unwrap();
        assert_eq!(
            parsed.runs,
            [
                (0x0800_0000, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                (0x0800_0010, vec![0x0a, 0x0b]),
                (0x2000_0000, vec![0xaa, 0xbb])
            ]
        );
        assert_eq!((parsed.data_records, parsed.start_address), (4, Some(0x0800_0101)));
        // Extended segment addresses and a CS:IP start record are real-mode linear addresses.
        let parsed = ihex(":020000021000EC\n:0100100055 9A\n".replace(' ', "").as_str());
        assert!(parsed.unwrap_err().to_string().contains("no end record"));
        let parsed = ihex(":020000021000EC\n:01001000559A\n:0400000310000020C9\n:00000001FF\n").unwrap();
        assert_eq!((parsed.runs, parsed.start_address), (vec![(0x10010, vec![0x55])], Some(0x10020)));
    }

    #[test]
    fn intel_hex_refuses_bad_checksums_types_overlaps_and_trailing_records() {
        for (text, expected) in [
            (":0400000001020304F3\n:00000001FF\n", "line 1: checksum mismatch"),
            (":0400000001020304\n:00000001FF\n", "length field"),
            ("0400000001020304F2\n", "not ':'"),
            (":00000006FA\n:00000001FF\n", "unknown record type"),
            (":00000001FF\n:0400000001020304F2\n", "follows the end record"),
            (":0400000001020304F2\n:020002000909EA\n:00000001FF\n", "overlap at 0x2"),
            (":00000001FF\n", "hold no data"),
            (":0100000400FB\n:00000001FF\n", "wrong length"),
        ] {
            let error = ihex(text).unwrap_err().to_string();
            assert!(error.contains(expected), "{text:?}: {error}");
        }
        let error = parse_raw_records(b":0400000001020304F2\n:00000001FF\n", RawRecordFormat::Ihex, 3).unwrap_err();
        assert!(error.to_string().contains("more than 3 data bytes"), "{error}");
    }

    #[test]
    fn s_records_read_all_three_address_widths_and_the_start_record() {
        let parsed = srec(
            "S00600004844521B\nS107001001020304DE\nS207010000AABBCCC6\nS30A200000001122334455D6\n\
             S5030003F9\nS70508000101F0\n"
                .replace(' ', "")
                .as_str(),
        )
        .unwrap();
        assert_eq!(
            parsed.runs,
            [
                (0x10, vec![1, 2, 3, 4]),
                (0x1_0000, vec![0xaa, 0xbb, 0xcc]),
                (0x2000_0000, vec![0x11, 0x22, 0x33, 0x44, 0x55])
            ]
        );
        assert_eq!((parsed.data_records, parsed.start_address), (3, Some(0x0800_0101)));
        for (text, expected) in [
            ("S107001001020304DF\nS9030000FC\n", "checksum mismatch"),
            ("S107001001020304DE\n", "no end record"),
            ("S4030000FC\nS9030000FC\n", "unknown record type"),
            ("X1070010010203049C\n", "not 'S'"),
            ("S9030000FC\nS107001001020304DE\n", "follows the end record"),
            ("S9030000FC\n", "hold no data"),
        ] {
            let error = srec(text).unwrap_err().to_string();
            assert!(error.contains(expected), "{text:?}: {error}");
        }
    }
}
