use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use object::{Object, ObjectSection};
use rampage_eval::dwarf_function_truth;
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
