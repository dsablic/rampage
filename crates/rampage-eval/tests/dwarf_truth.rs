use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use object::{Object, ObjectSection};
use rampage_eval::{dwarf_file_truth, dwarf_function_truth};
use rampage_loaders::Binary;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

struct Scratch(PathBuf);

impl Scratch {
    fn write(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-dwarf-truth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let scratch = Self(path);
        file.write_all(bytes).unwrap();
        scratch
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn elf_concrete_dwarf_truth_checks_nonempty_exact_twin_ranges() {
    for arch in ["x86_64", "aarch64"] {
        let mut original = Binary::open(fixture(&format!("eval-types-sym-{arch}.elf"))).unwrap();
        let mut stripped = Binary::open(fixture(&format!("eval-types-{arch}.elf"))).unwrap();
        let main_address = original.symbols.iter().find(|symbol| symbol.name == "main").unwrap().address;
        original.symbols.clear();
        original.function_starts.clear();
        stripped.symbols.clear();
        stripped.function_starts.clear();
        let report = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap();
        assert!(report.no_truth_reason.is_none(), "{report:?}");
        assert!(report.twin_verified, "{report:?}");
        assert!(report.exact_ranges_checked >= report.truth.0.len());
        assert!(report.checked_bytes > 0);
        assert!(report.truth.0.values().any(|name| name == "main"));
        assert!(report.truth.0.values().any(|name| name == "t_sum_ints"));
        assert_eq!(report.truth.0.get(&main_address).map(String::as_str), Some("main"));
    }
}

#[test]
fn original_only_does_not_claim_twin_verification() {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, None).unwrap();
    assert!(!report.truth.0.is_empty());
    assert!(report.exact_ranges_checked > 0);
    assert!(!report.twin_verified);
}

#[test]
fn missing_dwarf_is_explicitly_no_truth_not_a_vacuously_verified_twin() {
    let original = Binary::open(fixture("eval-types-x86_64.elf")).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
    assert!(report.truth.0.is_empty());
    assert!(report.no_truth_reason.as_deref().is_some_and(|reason| reason.contains("no embedded DWARF")));
    assert!(!report.notes.is_empty());
    assert_eq!(report.exact_ranges_checked, 0);
    assert_eq!(report.checked_bytes, 0);
    assert!(!report.twin_verified);
}

fn reject_changed_code(original_path: &Path, stripped_path: &Path) {
    let original = Binary::open(original_path).unwrap();
    let stripped = Binary::open(stripped_path).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap();
    let address = *report.truth.0.keys().next().expect("nonempty concrete function truth");
    reject_changed_byte(&original, &stripped, address);
}

fn reject_changed_byte(original: &Binary, stripped: &Binary, address: u64) {
    let segment = stripped.segment_containing(address).unwrap();
    let offset = usize::try_from(segment.file_offset + address - segment.address).unwrap();
    let mut bytes = stripped.image_bytes().to_vec();
    bytes[offset] ^= 1;
    let scratch = Scratch::write(&bytes);
    let changed = Binary::open(&scratch.0).unwrap();
    let error = dwarf_function_truth(original.image_bytes(), original, Some(&changed)).unwrap_err();
    assert!(error.contains("not a twin") && error.contains("code differs"), "{error}");
}

#[test]
fn changing_a_retained_function_byte_rejects_the_twin() {
    reject_changed_code(&fixture("eval-types-sym-x86_64.elf"), &fixture("eval-types-x86_64.elf"));
}

#[test]
fn changing_the_last_function_byte_rejects_a_start_only_byte_check() {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    let stripped = Binary::open(fixture("eval-types-x86_64.elf")).unwrap();
    let main = original.symbols.iter().find(|symbol| symbol.name == "main").unwrap();
    assert!(main.size > 1);
    reject_changed_byte(&original, &stripped, main.address + main.size - 1);
}

#[test]
fn accessible_but_nonexecutable_twin_code_is_rejected() {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    let mut stripped = Binary::open(fixture("eval-types-x86_64.elf")).unwrap();
    for segment in &mut stripped.segments {
        segment.perms.execute = false;
    }
    let error = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap_err();
    assert!(error.contains("not a twin") && error.contains("not executable-backed"), "{error}");
}

#[test]
fn zero_fill_instead_of_file_backed_code_is_rejected() {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    let mut stripped = Binary::open(fixture("eval-types-x86_64.elf")).unwrap();
    for segment in &mut stripped.segments {
        if segment.perms.execute {
            segment.file_size = 0;
        }
    }
    let error = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap_err();
    assert!(error.contains("not a twin") && error.contains("not executable-backed"), "{error}");
}

#[test]
fn malformed_dwarf_is_an_error_not_empty_success() {
    let bytes = std::fs::read(fixture("eval-types-sym-x86_64.elf")).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let section = object.section_by_name(".debug_info").unwrap();
    let (offset, _) = section.file_range().unwrap();
    let offset = usize::try_from(offset).unwrap();
    let mut malformed = bytes.clone();
    malformed[offset..offset + 4].copy_from_slice(&0xffff_fff0_u32.to_le_bytes());
    let scratch = Scratch::write(&malformed);
    let original = Binary::open(&scratch.0).unwrap();
    let error = dwarf_function_truth(&malformed, &original, None).unwrap_err();
    assert!(error.contains("DWARF"), "{error}");
}

#[test]
fn bytes_from_a_different_original_cannot_supply_truth() {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    assert!(dwarf_function_truth(b"", &original, None).unwrap_err().contains("do not match"));
    assert!(dwarf_function_truth(b"\x7fELF\x02\x01\x01", &original, None).is_err());
}

const SYNTHETIC_ABBREV: &[u8] = &[
    1, 0x11, 1, 0x11, 0x01, 0, 0, 2, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0, 0, 3, 0x2e, 0, 0x03, 0x08, 0x11,
    0x01, 0x12, 0x06, 0x55, 0x17, 0, 0, 4, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x31, 0x13, 0, 0, 5, 0x2e, 0,
    0x6e, 0x08, 0, 0, 6, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x47, 0x13, 0, 0, 7, 0x2e, 0, 0x03, 0x08, 0x11,
    0x01, 0x12, 0x01, 0, 0, 8, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0x12, 0x07, 0, 0, 0,
];

fn synthetic_unit(address_size: u8, base: u64, body: &[u8]) -> Vec<u8> {
    let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, address_size, 1];
    info.extend_from_slice(&base.to_le_bytes()[..usize::from(address_size)]);
    info.extend_from_slice(body);
    info.push(0);
    let length = u32::try_from(info.len() - 4).unwrap();
    info[..4].copy_from_slice(&length.to_le_bytes());
    info
}

// Replace only nonloaded debug sections in the existing ELF64-LE fixture; its mapped code is unchanged.
fn synthetic_image(info: &[u8], ranges: Option<&[u8]>) -> Scratch {
    let bytes = std::fs::read(fixture("eval-types-sym-x86_64.elf")).unwrap();
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let shoff = usize::try_from(u64::from_le_bytes(bytes[40..48].try_into().unwrap())).unwrap();
    let shentsize = usize::from(u16::from_le_bytes(bytes[58..60].try_into().unwrap()));
    let header = |name: &str| shoff + object.section_by_name(name).unwrap().index().0 * shentsize;
    let mut replacements =
        vec![(header(".debug_info"), info.to_vec()), (header(".debug_abbrev"), SYNTHETIC_ABBREV.to_vec())];
    let mut output = bytes.clone();
    if let Some(ranges) = ranges {
        let mut names = object.section_by_name(".shstrtab").unwrap().data().unwrap().to_vec();
        let name_offset = u32::try_from(names.len()).unwrap();
        names.extend_from_slice(b".debug_ranges\0");
        let range_header = header(".debug_line");
        output[range_header..range_header + 4].copy_from_slice(&name_offset.to_le_bytes());
        replacements.push((range_header, ranges.to_vec()));
        replacements.push((header(".shstrtab"), names));
    }
    for (header, replacement) in replacements {
        let offset = output.len() as u64;
        let size = replacement.len() as u64;
        output.extend_from_slice(&replacement);
        output[header + 24..header + 32].copy_from_slice(&offset.to_le_bytes());
        output[header + 32..header + 40].copy_from_slice(&size.to_le_bytes());
    }
    Scratch::write(&output)
}

fn mapped_low_pc() -> u32 {
    let original = Binary::open(fixture("eval-types-sym-x86_64.elf")).unwrap();
    u32::try_from(original.symbols.iter().find(|symbol| symbol.name == "main").unwrap().address).unwrap()
}

#[test]
fn all_raw_range_lists_are_explicitly_unsupported_even_when_normalization_would_map_them() {
    let low = mapped_low_pc();
    let cases = [
        ("valid", 0_u32, vec![(low, low + 8)]),
        ("valid_and_inverted", 0, vec![(low, low + 8), (low + 16, low + 8)]),
        ("wrapped_to_mapped_code", 0xffff_fff0, vec![(low + 16, low + 24)]),
    ];
    for (label, base, pairs) in cases {
        let mut body = vec![3, b'f', 0];
        body.extend_from_slice(&low.to_le_bytes());
        body.extend_from_slice(&8_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        let mut ranges = Vec::new();
        for (begin, end) in pairs {
            ranges.extend_from_slice(&begin.to_le_bytes());
            ranges.extend_from_slice(&end.to_le_bytes());
        }
        ranges.extend_from_slice(&[0; 8]);
        let info = synthetic_unit(4, u64::from(base), &body);
        let scratch = synthetic_image(&info, Some(&ranges));
        let original = Binary::open(&scratch.0).unwrap();
        assert!(original.read(u64::from(low), 8).is_some());
        let report = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
        assert!(report.truth.0.is_empty(), "{label}: {report:?}");
        assert!(report.no_truth_reason.is_some(), "{label}: {report:?}");
        assert!(!report.twin_verified, "{label}: {report:?}");
        assert_eq!(report.exact_ranges_checked, 0, "{label}");
        assert_eq!(report.omitted_subprograms, 1, "{label}");
        assert_eq!(report.unsupported_range_subprograms, 1, "{label}");
        assert!(report.notes.iter().any(|note| note.contains("DW_AT_ranges") && note.contains("unsupported")));
    }
}

#[test]
fn unsupported_range_list_omission_counts_survive_bounded_notes() {
    let low = mapped_low_pc();
    let mut body = vec![3, b'f', 0];
    body.extend_from_slice(&low.to_le_bytes());
    body.extend_from_slice(&8_u32.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    let info = synthetic_unit(4, 0, &body.repeat(256));
    let scratch = synthetic_image(&info, Some(&[0; 8]));
    let original = Binary::open(&scratch.0).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
    assert_eq!(report.omitted_subprograms, 256);
    assert_eq!(report.unsupported_range_subprograms, 256);
    assert!(report.omitted > 0);
    assert!(report.notes.len() < report.omitted_subprograms);
    assert!(report.no_truth_reason.is_some());
    assert!(report.truth.0.is_empty() && !report.twin_verified);
}

#[test]
fn synthetic_contiguous_low_high_pcs_remain_truth() {
    let low = mapped_low_pc();
    for (abbrev, high) in [(2, 8), (7, low + 8)] {
        let mut body = vec![abbrev, b'f', 0];
        body.extend_from_slice(&low.to_le_bytes());
        body.extend_from_slice(&high.to_le_bytes());
        let scratch = synthetic_image(&synthetic_unit(4, 0, &body), None);
        let original = Binary::open(&scratch.0).unwrap();
        let report = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
        assert_eq!(report.truth.0.get(&u64::from(low)).map(String::as_str), Some("f"));
        assert!(report.twin_verified);
        assert_eq!(report.exact_ranges_checked, 1);
        assert_eq!(report.checked_bytes, 8);
    }
}

#[test]
fn malformed_contiguous_pcs_fail_for_unit_width_overflow_u64_overflow_and_inversion() {
    let low = mapped_low_pc();
    let cases = [
        (4, 2, u64::from(low), u64::from(u32::MAX), "address width"),
        (8, 8, u64::MAX - 15, 32, "address width"),
        (4, 7, u64::from(low), u64::from(low - 1), "inverted"),
    ];
    for (width, abbrev, low, high, reason) in cases {
        let mut body = vec![abbrev, b'f', 0];
        body.extend_from_slice(&low.to_le_bytes()[..usize::from(width)]);
        let high_width = if abbrev == 8 { 8 } else { 4 };
        body.extend_from_slice(&high.to_le_bytes()[..high_width]);
        let scratch = synthetic_image(&synthetic_unit(width, 0, &body), None);
        let original = Binary::open(&scratch.0).unwrap();
        let error = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap_err();
        assert!(error.contains(reason), "{error}");
    }
}

#[test]
fn inherited_linkage_name_wins_over_a_local_source_name() {
    let low = mapped_low_pc();
    for abbrev in [4, 6] {
        let mut body = vec![abbrev];
        body.extend_from_slice(b"local_source_name\0");
        body.extend_from_slice(&low.to_le_bytes());
        body.extend_from_slice(&8_u32.to_le_bytes());
        let origin_offset = u32::try_from(16 + body.len() + 4).unwrap();
        body.extend_from_slice(&origin_offset.to_le_bytes());
        body.push(5);
        body.extend_from_slice(b"_Z16inherited_symbolv\0");
        let scratch = synthetic_image(&synthetic_unit(4, 0, &body), None);
        let original = Binary::open(&scratch.0).unwrap();
        let report = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
        assert_eq!(report.truth.0.get(&u64::from(low)).map(String::as_str), Some("_Z16inherited_symbolv"));
        assert!(report.twin_verified);
    }
}

fn owned_root() -> Option<PathBuf> {
    let root = std::env::var_os("RAMPAGE_EVAL_DWARF_OWNED_ROOT").map(PathBuf::from);
    if root.is_none() {
        eprintln!("owned DWARF fixture check not run: set RAMPAGE_EVAL_DWARF_OWNED_ROOT");
    }
    root
}

#[test]
fn opt_in_owned_zig_pe_uses_image_vas_and_checks_real_ranges() {
    let Some(root) = owned_root() else { return };
    let directory = root.join("core-x64-pe-zig-o2");
    let original_path = directory.join("symbolized.exe");
    let stripped_path = directory.join("stripped.exe");
    let original = Binary::open(&original_path).unwrap();
    let stripped = Binary::open(&stripped_path).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap();
    assert!(report.no_truth_reason.is_none(), "{report:?}");
    assert!(report.twin_verified && report.exact_ranges_checked > 0, "{report:?}");
    assert!(!report.truth.0.is_empty());
    assert!(report.truth.0.keys().all(|address| *address >= 0x1_4000_0000));
    reject_changed_code(&original_path, &stripped_path);
}

#[test]
fn opt_in_owned_go_macho_reads_compressed_embedded_dwarf() {
    let Some(root) = owned_root() else { return };
    let directory = root.join("parity-go-a64-macho-noinline");
    let original_path = directory.join("symbolized.macho");
    let stripped_path = directory.join("stripped.macho");
    let original = Binary::open(&original_path).unwrap();
    let stripped = Binary::open(&stripped_path).unwrap();
    let report = dwarf_function_truth(original.image_bytes(), &original, Some(&stripped)).unwrap();
    assert!(report.no_truth_reason.is_none(), "{report:?}");
    assert!(report.twin_verified && report.exact_ranges_checked > 0, "{report:?}");
    assert!(report.truth.0.values().any(|name| name == "main.main"));
    reject_changed_code(&original_path, &stripped_path);
}

// A thin MH_DSYM with only UUID and debug sections: deliberately no executable code bytes.
fn external_macho(original: &Binary, uuid: Option<[u8; 16]>, info: &[u8]) -> Vec<u8> {
    let section_command_size = 72 + 2 * 80;
    let commands_size = section_command_size + if uuid.is_some() { 24 } else { 0 };
    let payload_offset = 32 + commands_size;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xfeed_facf_u32.to_le_bytes());
    bytes.extend_from_slice(&original.image_bytes()[4..12]);
    for value in [10_u32, if uuid.is_some() { 2 } else { 1 }, commands_size as u32, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    if let Some(uuid) = uuid {
        bytes.extend_from_slice(&0x1b_u32.to_le_bytes());
        bytes.extend_from_slice(&24_u32.to_le_bytes());
        bytes.extend_from_slice(&uuid);
    }
    bytes.extend_from_slice(&0x19_u32.to_le_bytes());
    bytes.extend_from_slice(&(section_command_size as u32).to_le_bytes());
    bytes.extend_from_slice(b"__DWARF\0\0\0\0\0\0\0\0\0");
    for value in [0_u64, 0, payload_offset as u64, (info.len() + SYNTHETIC_ABBREV.len()) as u64] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0_u32, 0, 2, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut offset = payload_offset;
    for (name, size) in [("__debug_info", info.len()), ("__debug_abbrev", SYNTHETIC_ABBREV.len())] {
        let mut section_name = [0; 16];
        section_name[..name.len()].copy_from_slice(name.as_bytes());
        bytes.extend_from_slice(&section_name);
        bytes.extend_from_slice(b"__DWARF\0\0\0\0\0\0\0\0\0");
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&(size as u64).to_le_bytes());
        for value in [offset as u32, 0, 0, 0, 0, 0, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        offset += size;
    }
    assert_eq!(bytes.len(), payload_offset);
    bytes.extend_from_slice(info);
    bytes.extend_from_slice(SYNTHETIC_ABBREV);
    bytes
}

fn external_case(abbrev: u8) -> (Binary, Vec<u8>, u64) {
    let original = Binary::open(fixture("hello-x64.macho")).unwrap();
    let (low, uuid) = {
        let object = object::File::parse(original.image_bytes()).unwrap();
        (object.section_by_name("__text").unwrap().address(), object.mach_uuid().unwrap().unwrap())
    };
    let mut body = vec![abbrev, b'f', 0];
    body.extend_from_slice(&low.to_le_bytes());
    body.extend_from_slice(&8_u32.to_le_bytes());
    if abbrev == 3 {
        body.extend_from_slice(&0_u32.to_le_bytes());
    }
    let data = external_macho(&original, Some(uuid), &synthetic_unit(8, 0, &body));
    (original, data, low)
}

#[test]
fn uuid_matched_external_dwarf_uses_original_code_not_debug_object_code() {
    let (mut original, data, low) = external_case(2);
    original.symbols.clear();
    original.function_starts.clear();
    let report = dwarf_file_truth(&data, &original, Some(&original)).unwrap();
    assert_eq!(report.originating_metadata, "uuid_matched_external_dwarf");
    let receipt = report.uuid_comparison.as_ref().unwrap();
    assert_ne!(receipt.original_uuid, [0; 16]);
    assert_eq!(receipt.original_uuid, receipt.dwarf_uuid);
    assert_eq!(receipt.twin_uuid, Some(receipt.original_uuid));
    assert_eq!(report.truth.0.get(&low).map(String::as_str), Some("f"));
    assert_eq!(report.exact_ranges_checked, 1);
    assert_eq!(report.checked_bytes, 8);
    assert!(report.twin_verified && report.no_truth_reason.is_none());
    let original_only = dwarf_file_truth(&data, &original, None).unwrap();
    assert!(!original_only.twin_verified);
    assert_eq!(original_only.uuid_comparison.as_ref().unwrap().twin_uuid, None);
    assert_eq!(original_only.truth, report.truth);
    let embedded = dwarf_function_truth(original.image_bytes(), &original, Some(&original)).unwrap();
    assert!(embedded.uuid_comparison.is_none());
    assert!(dwarf_function_truth(&data, &original, None).unwrap_err().contains("do not match"));
}

#[test]
fn external_dwarf_rejects_wrong_missing_and_zero_uuids() {
    let (original, data, _) = external_case(2);
    let mut wrong = data.clone();
    // The synthetic file's first command is LC_UUID, with its payload at byte 40.
    wrong[40] ^= 1;
    assert!(dwarf_file_truth(&wrong, &original, None).unwrap_err().contains("LC_UUID does not match"));
    for uuid in [None, Some([0; 16])] {
        let missing = external_macho(&original, uuid, &[]);
        let error = dwarf_file_truth(&missing, &original, None).unwrap_err();
        assert!(error.contains("missing or zero LC_UUID"), "{error}");
    }
    let mut missing_original = original.image_bytes().to_vec();
    let command_count = u32::from_le_bytes(missing_original[16..20].try_into().unwrap());
    let mut offset = 32;
    let mut cleared = false;
    for _ in 0..command_count {
        let command = u32::from_le_bytes(missing_original[offset..offset + 4].try_into().unwrap());
        let size = u32::from_le_bytes(missing_original[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if command == 0x1b {
            missing_original[offset + 8..offset + 24].fill(0);
            cleared = true;
        }
        offset += size;
    }
    assert!(cleared);
    let scratch = Scratch::write(&missing_original);
    let original = Binary::open(&scratch.0).unwrap();
    let error = dwarf_file_truth(&data, &original, None).unwrap_err();
    assert!(error.contains("original: missing or zero LC_UUID"), "{error}");
}

#[test]
fn external_dwarf_rejects_wrong_architecture_and_universal_images() {
    let (original, mut data, _) = external_case(2);
    data[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
    let error = dwarf_file_truth(&data, &original, None).unwrap_err();
    assert!(error.contains("architecture or endianness differs"), "{error}");
    let fat = std::fs::read(fixture("hello-universal.macho")).unwrap();
    assert!(dwarf_file_truth(&fat, &original, None).unwrap_err().contains("thin Mach-O"));
    let fat_original = Binary::open(fixture("hello-universal.macho")).unwrap();
    assert!(dwarf_file_truth(&data, &fat_original, None).unwrap_err().contains("thin Mach-O"));
}

#[test]
fn external_dwarf_rejects_opposite_endianness_even_with_matching_uuid() {
    let (original, _, _) = external_case(2);
    let object = object::File::parse(original.image_bytes()).unwrap();
    let mut data = Vec::new();
    for value in [0xfeed_facf_u32, 0x0100_0007, 3, 10, 1, 24, 0, 0, 0x1b, 24] {
        data.extend_from_slice(&value.to_be_bytes());
    }
    data.extend_from_slice(&object.mach_uuid().unwrap().unwrap());
    let error = dwarf_file_truth(&data, &original, None).unwrap_err();
    assert!(error.contains("architecture or endianness differs"), "{error}");
}

#[test]
fn external_dwarf_requires_exact_raw_cpu_subtypes_in_all_three_images() {
    let (original, data, _) = external_case(2);
    assert_eq!(&original.image_bytes()[8..12], &3_u32.to_le_bytes());
    for subtype in [8_u32, 0x8000_0003] {
        let mut changed_debug = data.clone();
        changed_debug[8..12].copy_from_slice(&subtype.to_le_bytes());
        let error = dwarf_file_truth(&changed_debug, &original, None).unwrap_err();
        assert!(error.contains("architecture or endianness differs"), "{error}");

        let mut changed_image = original.image_bytes().to_vec();
        changed_image[8..12].copy_from_slice(&subtype.to_le_bytes());
        let scratch = Scratch::write(&changed_image);
        let changed = Binary::open(&scratch.0).unwrap();
        let error = dwarf_file_truth(&data, &changed, None).unwrap_err();
        assert!(error.contains("architecture or endianness differs"), "{error}");
        let error = dwarf_file_truth(&data, &original, Some(&changed)).unwrap_err();
        assert!(error.contains("not a twin") && error.contains("architecture or endianness differs"), "{error}");
    }
}

fn uuid_command_offset(bytes: &[u8]) -> usize {
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let mut offset = 32;
    for _ in 0..count {
        if u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) == 0x1b {
            return offset;
        }
        offset += u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
    }
    panic!("fixture must have an LC_UUID");
}

fn trailing_command(bytes: &[u8], command: &[u8]) -> Vec<u8> {
    let mut output = bytes.to_vec();
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let offset = 32 + size as usize;
    output.resize(output.len().max(offset + command.len()), 0);
    output[offset..offset + command.len()].copy_from_slice(command);
    output[16..20].copy_from_slice(&(count + 1).to_le_bytes());
    output[20..24].copy_from_slice(&(size + command.len() as u32).to_le_bytes());
    output
}

fn identity_corruptions(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let offset = uuid_command_offset(bytes);
    let uuid_command = &bytes[offset..offset + 24];
    let duplicate = trailing_command(bytes, uuid_command);
    let mut conflicting = duplicate.clone();
    let table_size = u32::from_le_bytes(conflicting[20..24].try_into().unwrap()) as usize;
    conflicting[32 + table_size - 16] ^= 1;
    let mut missing = bytes.to_vec();
    missing[offset..offset + 4].copy_from_slice(&0_u32.to_le_bytes());
    let mut zero = bytes.to_vec();
    zero[offset + 8..offset + 24].fill(0);
    let mut oversized_uuid = bytes.to_vec();
    oversized_uuid[offset + 4..offset + 8].copy_from_slice(&32_u32.to_le_bytes());
    let mut undersized_uuid = bytes.to_vec();
    undersized_uuid[offset + 4..offset + 8].copy_from_slice(&16_u32.to_le_bytes());
    let mut short_command = vec![0; 8];
    short_command[4..8].copy_from_slice(&4_u32.to_le_bytes());
    let malformed_trailing = trailing_command(bytes, &short_command);
    let mut unaligned_command = vec![0; 12];
    unaligned_command[4..8].copy_from_slice(&12_u32.to_le_bytes());
    let unaligned_trailing = trailing_command(bytes, &unaligned_command);
    let mut long_command = vec![0; 8];
    long_command[4..8].copy_from_slice(&16_u32.to_le_bytes());
    let truncated_command = trailing_command(bytes, &long_command);
    let mut missing_command = bytes.to_vec();
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    missing_command[16..20].copy_from_slice(&(count + 1).to_le_bytes());
    let mut unconsumed_table = bytes.to_vec();
    let size = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    unconsumed_table[20..24].copy_from_slice(&(size + 8).to_le_bytes());
    vec![
        ("duplicate", duplicate, "duplicate LC_UUID"),
        ("conflicting", conflicting, "duplicate LC_UUID"),
        ("missing", missing, "missing or zero LC_UUID"),
        ("zero", zero, "missing or zero LC_UUID"),
        ("oversized_uuid", oversized_uuid, "malformed LC_UUID"),
        ("undersized_uuid", undersized_uuid, "malformed LC_UUID"),
        ("malformed_trailing", malformed_trailing, "malformed Mach-O load-command"),
        ("unaligned_trailing", unaligned_trailing, "malformed Mach-O load-command"),
        ("truncated_command", truncated_command, "malformed Mach-O load-command"),
        ("missing_command", missing_command, "malformed Mach-O load-command"),
        ("unconsumed_table", unconsumed_table, "malformed Mach-O load-command"),
    ]
}

#[test]
fn external_dwarf_checks_the_entire_debug_load_command_table_and_unique_uuid() {
    let (original, data, _) = external_case(2);
    for (name, changed, expected) in identity_corruptions(&data) {
        let error = dwarf_file_truth(&changed, &original, Some(&original)).unwrap_err();
        assert!(error.contains("external DWARF") && error.contains(expected), "{name}: {error}");
    }
    let table_size = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
    let truncated_table = &data[..32 + table_size - 1];
    let error = dwarf_file_truth(truncated_table, &original, None).unwrap_err();
    assert!(error.contains("malformed Mach-O load-command"), "{error}");
}

#[test]
fn external_dwarf_checks_original_and_twin_load_command_tables_too() {
    let (original, data, _) = external_case(2);
    for (name, changed, expected) in identity_corruptions(original.image_bytes()) {
        let scratch = Scratch::write(&changed);
        let changed = Binary::open(&scratch.0).unwrap();
        let error = dwarf_file_truth(&data, &changed, None).unwrap_err();
        assert!(error.starts_with("original:") && error.contains(expected), "{name}: {error}");
        let error = dwarf_file_truth(&data, &original, Some(&changed)).unwrap_err();
        assert!(error.starts_with("not a twin:") && error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn external_dwarf_rejects_a_twin_uuid_change_even_when_code_is_identical() {
    let (original, data, _) = external_case(2);
    let mut changed = original.image_bytes().to_vec();
    let offset = uuid_command_offset(&changed);
    changed[offset + 8] ^= 1;
    let scratch = Scratch::write(&changed);
    let changed = Binary::open(&scratch.0).unwrap();
    let error = dwarf_file_truth(&data, &original, Some(&changed)).unwrap_err();
    assert!(error.contains("not a twin: LC_UUID does not match"), "{error}");
}

#[test]
fn external_dwarf_checks_the_last_range_byte_in_the_twin() {
    let (original, data, low) = external_case(2);
    let segment = original.segment_containing(low).unwrap();
    let offset = usize::try_from(segment.file_offset + low + 7 - segment.address).unwrap();
    let mut bytes = original.image_bytes().to_vec();
    bytes[offset] ^= 1;
    let scratch = Scratch::write(&bytes);
    let changed = Binary::open(&scratch.0).unwrap();
    let error = dwarf_file_truth(&data, &original, Some(&changed)).unwrap_err();
    assert!(error.contains("not a twin") && error.contains("code differs"), "{error}");
}

#[test]
fn external_dwarf_missing_units_and_unsupported_ranges_are_not_verified_truth() {
    let (original, data, _) = external_case(3);
    let report = dwarf_file_truth(&data, &original, Some(&original)).unwrap();
    assert_eq!(report.unsupported_range_subprograms, 1);
    assert!(report.notes.iter().any(|note| note.contains("DW_AT_ranges") && note.contains("unsupported")));
    assert!(report.truth.0.is_empty() && report.no_truth_reason.is_some() && !report.twin_verified);
    assert_eq!(report.checked_bytes, 0);
    let object = object::File::parse(original.image_bytes()).unwrap();
    let empty = external_macho(&original, object.mach_uuid().unwrap(), &[]);
    let report = dwarf_file_truth(&empty, &original, Some(&original)).unwrap();
    assert!(report.no_truth_reason.as_deref().unwrap().contains("no external DWARF compilation units"));
    assert!(report.uuid_comparison.is_some());
    assert!(report.truth.0.is_empty() && !report.twin_verified);
}

#[test]
fn opt_in_owned_cpp_and_rust_macho_use_explicit_uuid_matched_dsym_files() {
    let Some(root) = owned_root() else { return };
    for (name, source_function) in
        [("parity-classes-a64-macho-clang-o1", "dispatch_commands"), ("parity-rust-a64-macho-o1", "parse_config")]
    {
        let directory = root.join(name);
        let mut original = Binary::open(directory.join("symbolized.macho")).unwrap();
        let mut stripped = Binary::open(directory.join("stripped.macho")).unwrap();
        original.symbols.clear();
        original.function_starts.clear();
        stripped.symbols.clear();
        stripped.function_starts.clear();
        let dwarf_path = directory.join("symbolized.macho.dSYM/Contents/Resources/DWARF/symbolized.macho");
        let data = std::fs::read(dwarf_path).unwrap();
        let report = dwarf_file_truth(&data, &original, Some(&stripped)).unwrap();
        assert!(report.no_truth_reason.is_none(), "{name}: {report:?}");
        assert!(report.twin_verified && report.exact_ranges_checked > 0, "{name}: {report:?}");
        assert!(report.checked_bytes > 0 && !report.truth.0.is_empty());
        assert!(report.truth.0.values().any(|name| name.contains(source_function)), "{name}: {report:?}");
        assert_eq!(report.originating_metadata, "uuid_matched_external_dwarf");
        let receipt = report.uuid_comparison.unwrap();
        assert_eq!(receipt.original_uuid, receipt.dwarf_uuid);
        assert_eq!(receipt.twin_uuid, Some(receipt.original_uuid));
    }
}
