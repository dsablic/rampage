use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rampage_loaders::container::archive::{self, ArchiveInventory};
use sha2::{Digest, Sha256};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Input(PathBuf);

impl Input {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rampage-zip32-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn inventory(&self) -> Result<ArchiveInventory, rampage_loaders::LoadError> {
        archive::inventory(&self.0, None)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

#[derive(Clone)]
struct Entry {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    extra: Vec<u8>,
    comment: Vec<u8>,
}

impl Entry {
    fn named(name: &[u8]) -> Self {
        Self { name: name.to_vec(), flags: 0, method: 0, extra: vec![], comment: vec![] }
    }
}

struct Zip {
    bytes: Vec<u8>,
    cd: usize,
    eocd: usize,
    records: Vec<usize>,
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn zip(entries: &[Entry], comment: &[u8], payload_length: usize) -> Zip {
    assert!(comment.len() <= usize::from(u16::MAX));
    let mut bytes = Vec::new();
    if !entries.is_empty() {
        bytes.extend(b"PK\x03\x04");
        // Deliberately not a valid local header or compressed stream: neither is inspected.
        bytes.resize(4 + payload_length, 0xa5);
    }
    let cd = bytes.len();
    let mut records = Vec::new();
    for entry in entries {
        let start = bytes.len();
        records.push(start);
        let mut header = [0; 46];
        header[..4].copy_from_slice(b"PK\x01\x02");
        put16(&mut header, 4, 20);
        put16(&mut header, 6, 20);
        put16(&mut header, 8, entry.flags);
        put16(&mut header, 10, entry.method);
        put32(&mut header, 16, 0x12345678);
        put32(&mut header, 20, 123);
        put32(&mut header, 24, 987654321);
        put16(&mut header, 28, entry.name.len().try_into().unwrap());
        put16(&mut header, 30, entry.extra.len().try_into().unwrap());
        put16(&mut header, 32, entry.comment.len().try_into().unwrap());
        bytes.extend(header);
        bytes.extend(&entry.name);
        bytes.extend(&entry.extra);
        bytes.extend(&entry.comment);
    }
    let eocd = bytes.len();
    let mut end = [0; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    put16(&mut end, 8, entries.len().try_into().unwrap());
    put16(&mut end, 10, entries.len().try_into().unwrap());
    put32(&mut end, 12, (eocd - cd).try_into().unwrap());
    put32(&mut end, 16, cd.try_into().unwrap());
    put16(&mut end, 20, comment.len().try_into().unwrap());
    bytes.extend(end);
    bytes.extend(comment);
    Zip { bytes, cd, eocd, records }
}

fn refused(bytes: &[u8]) -> String {
    Input::new(bytes).inventory().unwrap_err().to_string()
}

#[test]
fn empty_stored_compressed_encrypted_descriptor_and_duplicate_records_are_metadata_only() {
    let empty = Input::new(&zip(&[], b"comment PK\x05\x06 false signature", 0).bytes).inventory().unwrap();
    assert_eq!((empty.declared, empty.validated, empty.retained), (0, 0, 0));
    assert!(empty.central_directory_complete);
    let stored = Entry::named(b"duplicate");
    let mut compressed = stored.clone();
    compressed.method = 8;
    compressed.flags = 1 | 8;
    compressed.comment = b"ignored record comment PK\x05\x06".to_vec();
    let zip = zip(&[stored, compressed], b"archive comment", 8);
    let input = Input::new(&zip.bytes);
    let before = std::fs::read(&input.0).unwrap();
    let report = input.inventory().unwrap();
    assert_eq!((report.declared, report.examined, report.validated, report.retained), (2, 2, 2, 2));
    assert!(!report.truncated);
    assert_eq!(report.members[0].name_display.as_deref(), Some("duplicate"));
    assert_eq!(report.members[0].raw_name_hex, report.members[1].raw_name_hex);
    assert_ne!(report.members[0].member_ref, report.members[1].member_ref);
    let member = &report.members[1];
    assert_eq!((member.compression_method, member.compressed_size, member.uncompressed_size), (8, 123, 987654321));
    assert_eq!(member.crc32, 0x12345678);
    assert!(member.encrypted && member.data_descriptor);
    assert_eq!(member.local_header_offset, 0);
    assert_eq!(std::fs::read(&input.0).unwrap(), before);
    assert!(!input.0.with_extension("rampage").exists());
    assert!(rampage_loaders::Binary::open(&input.0).is_err());
    assert!(report.metadata_read_bytes <= archive::MAX_METADATA_READ_BYTES);
}

#[test]
fn metadata_reference_ignores_payload_but_binds_directory_eocd_and_comments() {
    let mut first = zip(&[Entry::named(b"a")], b"comment", 100_000);
    let reference = Input::new(&first.bytes).inventory().unwrap().archive_ref;
    let expected = rampage_arch::hex::bytes(&Sha256::digest(&first.bytes[first.cd..]));
    assert_eq!(reference.metadata_sha256, expected);
    first.bytes[100] ^= 1;
    assert_eq!(Input::new(&first.bytes).inventory().unwrap().archive_ref, reference);
    first.bytes[first.cd - 1] ^= 1;
    assert_eq!(Input::new(&first.bytes).inventory().unwrap().archive_ref, reference);
    first.bytes[first.eocd + 22] ^= 1;
    assert_ne!(Input::new(&first.bytes).inventory().unwrap().archive_ref, reference);
    first.bytes[first.eocd + 22] ^= 1;
    first.bytes[first.cd + 16] ^= 1;
    assert_ne!(Input::new(&first.bytes).inventory().unwrap().archive_ref, reference);
}

#[test]
fn tail_budget_is_independent_of_large_payload_and_bounds_both_read_passes() {
    let zip = zip(&[Entry::named(b"a")], &vec![0; u16::MAX as usize], 200_000);
    let report = Input::new(&zip.bytes).inventory().unwrap();
    let directory_bytes = zip.eocd - zip.cd;
    assert_eq!(report.metadata_read_bytes, 2 * (4 + archive::MAX_TAIL_BYTES + directory_bytes));
    assert!(report.metadata_read_bytes < zip.bytes.len());
}

#[test]
fn complete_name_validation_precedes_utf8_safe_truncation_and_raw_substring_filtering() {
    let mut valid = Entry::named(format!("{}λ-tail", "a".repeat(1023)).as_bytes());
    valid.flags = 0x800;
    let mut invalid = Entry::named(&[b'a'; 1100]);
    invalid.flags = 0x800;
    invalid.name.push(0xff);
    let legacy = Entry::named(b"../absolute\\path/\xff");
    let zip = zip(&[valid, invalid, legacy], b"", 4);
    let input = Input::new(&zip.bytes);
    let report = archive::inventory(&input.0, Some("λ-tail")).unwrap();
    assert_eq!((report.declared, report.validated, report.retained, report.matched), (3, 3, 3, 1));
    let name = &report.members[0];
    assert_eq!(name.name_display.as_ref().unwrap().len(), 1023);
    assert_eq!(name.raw_name_hex.len(), 2048);
    assert!(name.name_utf8_valid && name.name_truncated && name.matches_filter);
    assert!(!report.members[1].name_utf8_valid);
    assert!(report.members[1].name_display.is_none());
    assert_eq!(report.members[2].name_encoding, "legacy_raw");
    assert!(report.members[2].raw_name_hex.ends_with("ff"));
    assert_eq!(report.warnings.len(), 1);
}

#[test]
fn adversarial_repeated_prefix_filtering_has_linear_bounded_work_and_preserves_overlapping_matches() {
    let long = Entry::named(&vec![b'a'; u16::MAX as usize]);
    let input = Input::new(&zip(&[long.clone(), long, Entry::named(b"aaaaab")], b"", 0).bytes);
    let needle = format!("{}b", "a".repeat(1023));
    let report = archive::inventory(&input.0, Some(&needle)).unwrap();
    assert_eq!(report.matched, 0);
    assert!(report.name_filter_steps < 4 * usize::from(u16::MAX) + 4096);
    assert!(report.name_filter_steps <= archive::MAX_NAME_FILTER_STEPS);
    let report = archive::inventory(&input.0, Some("aaab")).unwrap();
    assert_eq!(report.matched, 1);
    assert!(report.members[2].matches_filter);
}

#[test]
fn unsafe_looking_names_are_preserved_not_normalized_and_warnings_are_bounded() {
    let names = [b"../x".as_slice(), b"/absolute", b"C:\\windows\\path", b"a\0b", b"a/../x", b"\xc3\xa9", b"e\xcc\x81"];
    let entries: Vec<_> = names.iter().map(|name| Entry::named(name)).collect();
    let report = Input::new(&zip(&entries, b"", 0).bytes).inventory().unwrap();
    for (member, name) in report.members.iter().zip(names) {
        assert_eq!(member.name_display.as_deref(), Some(std::str::from_utf8(name).unwrap()));
        assert_eq!(member.original_name_bytes, name.len());
    }
    assert_ne!(report.members[5].raw_name_hex, report.members[6].raw_name_hex);
    let mut invalid = Entry::named(b"\xff");
    invalid.flags = 0x800;
    let report = Input::new(&zip(&vec![invalid; archive::MAX_WARNINGS + 20], b"", 0).bytes).inventory().unwrap();
    assert_eq!(report.validated, archive::MAX_WARNINGS + 20);
    assert_eq!(report.warnings.len(), archive::MAX_WARNINGS);
    assert_eq!(report.warnings_total, archive::MAX_WARNINGS + 20);
    assert!(report.warnings_truncated);
}

#[test]
fn eocd_false_signatures_are_not_selected_and_multiple_plausible_candidates_fail_closed() {
    let real = zip(&[Entry::named(b"real")], b"comment PK\x05\x06 not an end record", 0);
    assert_eq!(Input::new(&real.bytes).inventory().unwrap().declared, 1);
    let mut false_end = [0; 22];
    false_end[..4].copy_from_slice(b"PK\x05\x06");
    let real = zip(&[Entry::named(b"real")], &false_end, 0);
    assert_eq!(Input::new(&real.bytes).inventory().unwrap().declared, 1);
    let nested = zip(&[Entry::named(b"fake")], b"", 0);
    let mut comment = nested.bytes[nested.cd..].to_vec();
    let mut outer = zip(&[Entry::named(b"real")], &comment, 0);
    let fake_end = comment.len() - 22;
    put32(&mut comment, fake_end + 16, (outer.eocd + 22) as u32);
    outer.bytes[outer.eocd + 22..].copy_from_slice(&comment);
    assert!(refused(&outer.bytes).contains("ambiguous"));
    let signatures = b"PK\x05\x06".repeat(archive::MAX_EOCD_CANDIDATES + 16);
    assert!(refused(&zip(&[], &signatures, 0).bytes).contains("candidate work budget"));
}

#[test]
fn truncated_ranges_count_mismatches_and_integer_sentinels_are_refused() {
    let original = zip(&[Entry::named(b"name")], b"comment", 0);
    for length in [0, 3, 21, original.cd + 45, original.eocd + 21, original.bytes.len() - 1] {
        assert!(Input::new(&original.bytes[..length]).inventory().is_err(), "length={length}");
    }
    let mut bytes = original.bytes.clone();
    put32(&mut bytes, original.eocd + 16, u32::MAX - 1);
    assert!(refused(&bytes).contains("adjoin"));
    for field in [12, 16] {
        let mut bytes = original.bytes.clone();
        put32(&mut bytes, original.eocd + field, u32::MAX);
        assert!(refused(&bytes).contains("ZIP64"));
    }
    for field in [20, 24, 42] {
        let mut bytes = original.bytes.clone();
        put32(&mut bytes, original.cd + field, u32::MAX);
        assert!(refused(&bytes).contains("ZIP64"));
    }
    let mut bytes = original.bytes.clone();
    put16(&mut bytes, original.eocd + 8, 0);
    put16(&mut bytes, original.eocd + 10, 0);
    assert!(refused(&bytes).contains("range/count"));
    let original = zip(&[Entry::named(b"a"), Entry::named(b"b")], b"", 0);
    let mut bytes = original.bytes.clone();
    put16(&mut bytes, original.eocd + 8, 1);
    put16(&mut bytes, original.eocd + 10, 1);
    assert!(refused(&bytes).contains("size/count mismatch"));
    let mut bytes = original.bytes.clone();
    bytes[original.records[1]] = 0;
    assert!(refused(&bytes).contains("signature"));
    let mut bytes = original.bytes.clone();
    put16(&mut bytes, original.cd + 28, u16::MAX);
    assert!(refused(&bytes).contains("truncated"));
    let mut bytes = original.bytes.clone();
    put32(&mut bytes, original.cd + 42, original.cd as u32);
    assert!(refused(&bytes).contains("local-header offset"));
}

#[test]
fn zip64_multidisk_sfx_directory_gaps_and_digital_signatures_are_explicitly_unsupported() {
    let original = zip(&[Entry::named(b"name")], b"", 0);
    for field in [4, 6] {
        let mut bytes = original.bytes.clone();
        put16(&mut bytes, original.eocd + field, 1);
        assert!(refused(&bytes).contains("multi-disk"));
    }
    let mut bytes = original.bytes.clone();
    put16(&mut bytes, original.cd + 34, 1);
    assert!(refused(&bytes).contains("multi-disk"));
    let mut bytes = original.bytes.clone();
    put16(&mut bytes, original.eocd + 8, u16::MAX);
    put16(&mut bytes, original.eocd + 10, u16::MAX);
    assert!(refused(&bytes).contains("ZIP64"));
    let mut entry = Entry::named(b"x");
    entry.extra = vec![1, 0, 0, 0];
    assert!(refused(&zip(&[entry], b"", 0).bytes).contains("ZIP64"));
    let mut sfx = b"MZinstaller".to_vec();
    sfx.extend(&original.bytes);
    assert!(refused(&sfx).contains("SFX"));
    let mut gap = original.bytes.clone();
    gap.splice(original.eocd..original.eocd, *b"PK\x05\x05\x00\x00");
    assert!(refused(&gap).contains("gaps and digital signatures"));
}

#[test]
fn all_structural_and_retention_budgets_reject_whole_inventory_including_with_filters() {
    let record_limit = zip(&vec![Entry::named(b""); archive::MAX_RECORDS], b"", 0);
    assert_eq!(Input::new(&record_limit.bytes).inventory().unwrap().validated, archive::MAX_RECORDS);
    let over_records = zip(&vec![Entry::named(b""); archive::MAX_RECORDS + 1], b"", 0);
    assert!(refused(&over_records.bytes).contains("record-attempt budget"));
    let retained = Entry::named(&vec![b'a'; archive::MAX_NAME_BYTES]);
    let entries = vec![retained; archive::MAX_RETAINED_NAME_BYTES / (3 * archive::MAX_NAME_BYTES) + 1];
    let input = Input::new(&zip(&entries, b"", 0).bytes);
    assert!(archive::inventory(&input.0, Some("not-present")).unwrap_err().to_string().contains("retained-name"));
    let mut large = Entry::named(b"");
    large.comment = vec![0; u16::MAX as usize];
    assert!(refused(&zip(&vec![large; 129], b"", 0).bytes).contains("size or record-attempt budget"));
    let mut many_extra = Entry::named(b"");
    many_extra.extra = [2, 0, 0, 0].repeat(16_000);
    assert!(refused(&zip(&vec![many_extra; 5], b"", 0).bytes).contains("extra-field work budget"));
    let mut broken_extra = Entry::named(b"");
    broken_extra.extra = vec![2, 0, 10, 0];
    assert!(refused(&zip(&[broken_extra], b"", 0).bytes).contains("truncated central-directory extra"));
}

#[cfg(unix)]
#[test]
fn nonregular_and_final_symlink_inputs_are_refused_without_waiting_or_reading() {
    assert!(archive::inventory(Path::new("/dev/zero"), None).is_err());
    assert!(archive::inventory(&std::env::temp_dir(), None).is_err());
    let input = Input::new(&zip(&[], b"", 0).bytes);
    let link = input.0.with_extension("link");
    std::os::unix::fs::symlink(&input.0, &link).unwrap();
    let result = archive::inventory(&link, None);
    std::fs::remove_file(link).unwrap();
    assert!(result.is_err());
    let fifo = input.0.with_extension("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let result = archive::inventory(&fifo, None);
    std::fs::remove_file(fifo).unwrap();
    assert!(result.is_err());
}
