use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_analysis::entry_audit::{
    EntryAssessment, EntryAuditLimits, EntryAuditStatus, EntryAuditTruncation, EntryOriginKind, EntrySampleStatus,
    EntrySampleStop, EntrySignal, EntryWindowBound, MAX_BYTES_PER_ENTRY, MAX_DECLARATIONS, MAX_ENTRIES,
    MAX_INSTRUCTIONS_PER_ENTRY, MAX_LOOKUP_WORK, MAX_METADATA_ITEMS, MAX_METADATA_NAME_BYTES, MAX_NAME_BYTES,
    MAX_ORIGINS_PER_ENTRY, MAX_OUTPUT_NAME_BYTES, MAX_TOTAL_BYTES, MAX_TOTAL_DECODE_ATTEMPTS, sample_declared_entries,
    sample_entry,
};
use rampage_arch::{Arch, Flow};
use rampage_loaders::{Binary, Export, Format, Symbol, SymbolKind};

struct FixtureFile(PathBuf);

impl Drop for FixtureFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).expect("remove synthetic entry-evidence fixture");
    }
}

// Synthetic byte/mapping evidence, not a claim of compiled-source provenance.
fn fixture(arch: &str, regions: &[(&str, u64, &str, bool)]) -> Binary {
    fixture_with_order(arch, regions, false)
}

fn fixture_with_order(arch: &str, regions: &[(&str, u64, &str, bool)], big_endian: bool) -> Binary {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rampage-entry-evidence-{}-{}.snapshot.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let guard = FixtureFile(path);
    write!(
        file,
        r#"{{"format":"rampage-snapshot-v1","arch":"{arch}","big_endian":{big_endian},
        "provenance":"synthetic local entry evidence, not compiled-source proof","regions":["#
    )
    .unwrap();
    for (index, &(permissions, address, bytes, thumb)) in regions.iter().enumerate() {
        if index != 0 {
            write!(file, ",").unwrap();
        }
        write!(
            file,
            r#"{{"name":"region-{index}","address":"{address:#x}",
            "permissions":"{permissions}","bytes":"{bytes}","thumb":{thumb}}}"#
        )
        .unwrap();
    }
    write!(file, "]}}").unwrap();
    drop(file);
    Binary::open(&guard.0).unwrap()
}

fn x64(bytes: &str) -> Binary {
    fixture("x86_64", &[("r-x", 0x1000, bytes, false)])
}

fn symbol(address: u64, name: &str, kind: SymbolKind) -> Symbol {
    Symbol { address, name: name.to_owned(), size: 32, kind }
}

#[test]
fn owned_x86_family_and_aarch64_entries_report_local_return_evidence_without_verification() {
    let cases = [
        ("x86", "5589e531c05dc3", 7),
        ("x86_64", "554889e531c05dc3", 8),
        ("aarch64", "fd7bbfa9fd03009100040091fd7bc1a8c0035fd6", 20),
    ];
    for (arch, bytes, decoded_bytes) in cases {
        let mut binary = fixture(arch, &[("r-x", 0x1000, bytes, false)]);
        binary.entry = Some(0x1000);
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        assert_eq!(result.status, EntryAuditStatus::Available);
        assert_eq!(result.entries.len(), 1);
        let entry = &result.entries[0];
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.assessment, EntryAssessment::LocallyPlausible);
        assert_eq!(entry.instruction_count, 5);
        assert_eq!(entry.decoded_bytes, decoded_bytes);
        assert_eq!(entry.last_flow, Some(Flow::Return));
        assert_eq!(entry.stop, EntrySampleStop::ControlTransfer);
        assert_eq!(entry.origins[0].kind, EntryOriginKind::Entry);
        assert!(result.limitations.iter().any(|text| text.contains("not verified functions")));
    }
}

#[test]
fn duplicate_addresses_merge_exact_origins_without_erasing_symbol_kinds_or_duplicate_counts() {
    let mut binary = x64("c3");
    binary.symbols = vec![
        symbol(0x1000, "alpha", SymbolKind::Function),
        symbol(0x1000, "alpha", SymbolKind::Function),
        symbol(0x1000, "misleading_data", SymbolKind::Data),
    ];
    binary.exports = vec![Export { name: "exported".to_owned(), address: 0x1000 }; 2];
    binary.function_starts = vec![0x1000, 0x1000];
    binary.entry = Some(0x1000);
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];
    assert_eq!(entry.metadata_records_at_address, 8);
    assert_eq!(entry.origins.len(), 5);
    assert!(!entry.origins_truncated);
    let kinds: Vec<_> = entry.origins.iter().map(|origin| origin.kind).collect();
    assert_eq!(
        kinds,
        vec![
            EntryOriginKind::Symbol,
            EntryOriginKind::Symbol,
            EntryOriginKind::Export,
            EntryOriginKind::FunctionStarts,
            EntryOriginKind::Entry,
        ]
    );
    assert!(entry.origins.iter().any(|origin| origin.symbol_kind == Some(SymbolKind::Data)));
}

#[test]
fn explicit_interior_address_gets_only_a_caller_assertion_not_a_containing_function_origin() {
    let mut binary = x64("9090c3");
    binary.symbols.push(symbol(0x1000, "claimed_outer", SymbolKind::Function));
    binary.entry = Some(0x1000);
    let result = sample_entry(&binary, 0x1001, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.address, 0x1001);
    assert_eq!(entry.metadata_records_at_address, 0);
    assert_eq!(entry.origins.len(), 1);
    assert_eq!(entry.origins[0].kind, EntryOriginKind::CallerAddress);
    assert_eq!(entry.origins[0].name, None);
    assert_eq!(entry.decoded_bytes, 2);
}

#[test]
fn an_exact_data_symbol_is_preserved_without_inventing_a_caller_or_function_origin() {
    let mut binary = x64("c3");
    binary.symbols.push(symbol(0x1000, "literal", SymbolKind::Data));
    let explicit = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    assert_eq!(explicit.entries[0].origins[0].kind, EntryOriginKind::Symbol);
    assert_eq!(explicit.entries[0].origins[0].symbol_kind, Some(SymbolKind::Data));
    assert_eq!(sample_declared_entries(&binary, EntryAuditLimits::default()).status, EntryAuditStatus::Empty);
}

#[test]
fn function_names_and_exports_do_not_turn_non_code_mappings_into_code() {
    let mut binary = fixture("x86_64", &[("r-x", 0x1000, "c3", false), ("r--", 0x2000, "c3", false)]);
    binary.symbols.push(symbol(0x2000, "claims_function", SymbolKind::Function));
    binary.exports.push(Export { name: "data_export".to_owned(), address: 0x2000 });
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].status, EntrySampleStatus::NonCode);
    assert_eq!(result.entries[0].assessment, EntryAssessment::Unknown);
    assert_eq!(result.usage.decode_attempts, 0);
    binary.segments[1].perms.execute = true;
    let executable_but_not_code = sample_entry(&binary, 0x2000, EntryAuditLimits::default());
    assert_eq!(executable_but_not_code.entries[0].status, EntrySampleStatus::NonCode);
}

#[test]
fn decodable_x64_data_fragments_are_only_locally_plausible() {
    let binary = x64("0000000000000000");
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.assessment, EntryAssessment::LocallyPlausible);
    assert_eq!(entry.instruction_count, 4);
    assert_eq!(entry.last_flow, Some(Flow::Next));
    assert_eq!(entry.stop, EntrySampleStop::WindowEnd);
    assert!(result.limitations.iter().any(|text| text.contains("Random fragments")));
}

#[test]
fn entropy_and_full_width_decode_failure_are_suspicious_observations_not_protector_proof() {
    let bytes: String = (0..128).map(|byte| format!("{byte:02x}")).collect();
    let entropy = sample_entry(&x64(&bytes), 0x1000, EntryAuditLimits::default());
    assert!(entropy.entries[0].signals.contains(&EntrySignal::HighEntropyWindow));
    assert_eq!(entropy.entries[0].assessment, EntryAssessment::Suspicious);
    assert!(entropy.limitations.iter().any(|text| text.contains("does not establish encryption")));

    let binary = fixture("aarch64", &[("r-x", 0x1000, "ffffffff", false)]);
    let invalid = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &invalid.entries[0];
    assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
    assert_eq!(entry.assessment, EntryAssessment::Suspicious);
    assert_eq!(entry.stop, EntrySampleStop::InvalidInstruction);
    assert_eq!(entry.invalid_count, 1);
    assert_eq!(entry.instruction_count, 0);
    assert_eq!(entry.decoded_bytes, 0);
    assert_eq!(entry.decode_attempts, 1);
    assert!(entry.signals.contains(&EntrySignal::DecodeFailure));
}

#[test]
fn short_incomplete_tails_stay_unknown_instead_of_becoming_decode_failure_proof() {
    let arm = fixture("aarch64", &[("r-x", 0x1000, "c0035f", false)]);
    let result = sample_entry(&arm, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].stop, EntrySampleStop::IncompleteInstruction);
    assert_eq!(result.entries[0].assessment, EntryAssessment::Unknown);
    assert_eq!(result.entries[0].invalid_count, 0);
    assert_eq!(result.entries[0].decode_attempts, 0);

    let result = sample_entry(&x64("0f"), 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].stop, EntrySampleStop::InvalidOrIncompleteTail);
    assert_eq!(result.entries[0].assessment, EntryAssessment::Unknown);
    assert_eq!(result.entries[0].invalid_count, 1);
    assert!(result.entries[0].signals.contains(&EntrySignal::InvalidOrIncompleteTail));
}

#[test]
fn unaligned_unmapped_zero_fill_and_truncated_backing_are_not_decoded() {
    let arm = fixture("aarch64", &[("r-x", 0x1000, "c0035fd6", false)]);
    assert_eq!(sample_entry(&arm, 0x1002, EntryAuditLimits::default()).entries[0].status, EntrySampleStatus::Unaligned);
    for address in [0x1800, u64::MAX] {
        let result = sample_entry(&x64("c3"), address, EntryAuditLimits::default());
        assert_eq!(result.entries[0].status, EntrySampleStatus::Unavailable);
        assert_eq!(result.usage.decode_attempts, 0);
    }
    let mut zero_fill = x64("c3");
    zero_fill.segments[0].file_size = 0;
    let result = sample_entry(&zero_fill, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::Unavailable);
    assert!(result.entries[0].unavailable_reason.unwrap().contains("zero-fill"));

    let mut truncated = x64("c3");
    truncated.segments[0].file_offset = u64::MAX;
    let result = sample_entry(&truncated, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::Unavailable);
    assert_eq!(result.usage.bytes_sampled, 0);
}

#[test]
fn supported_32_bit_entries_above_target_width_keep_origins_without_sampling() {
    let address = u64::from(u32::MAX) + 1;
    for (arch, bytes, thumb) in [("x86", "c3", false), ("arm", "7047", true)] {
        let mut binary = fixture(arch, &[("r-x", address, bytes, thumb)]);
        binary.symbols.push(symbol(address, "declared", SymbolKind::Function));
        binary.exports.push(Export { name: "exported".to_owned(), address });
        binary.function_starts.push(address);
        binary.entry = Some(address);
        for result in [
            sample_entry(&binary, address, EntryAuditLimits::default()),
            sample_declared_entries(&binary, EntryAuditLimits::default()),
        ] {
            assert_eq!(result.entries.len(), 1);
            let entry = &result.entries[0];
            assert_eq!(entry.address, address);
            assert_eq!(entry.status, EntrySampleStatus::AddressOutsideTargetWidth);
            assert_eq!(entry.assessment, EntryAssessment::Unknown);
            assert_eq!(entry.metadata_records_at_address, 4);
            assert_eq!(
                entry.origins.iter().map(|origin| origin.kind).collect::<Vec<_>>(),
                vec![
                    EntryOriginKind::Symbol,
                    EntryOriginKind::Export,
                    EntryOriginKind::FunctionStarts,
                    EntryOriginKind::Entry,
                ]
            );
            assert_eq!(entry.stop, EntrySampleStop::NotSampled);
            assert_eq!(entry.last_flow, None);
            assert!(!entry.last_conditional_transfer);
            assert_eq!(entry.invalid_count, 0);
            assert_eq!(entry.entropy_bits_per_byte, None);
            assert_eq!(result.usage.bytes_sampled, 0);
            assert_eq!(result.usage.decode_attempts, 0);
            assert_eq!(result.usage.lookup_work_reserved, 0);
        }
        let odd = sample_entry(&binary, address + 1, EntryAuditLimits::default());
        assert_eq!(odd.entries[0].status, EntrySampleStatus::AddressOutsideTargetWidth);
        assert_eq!(odd.entries[0].origins[0].kind, EntryOriginKind::CallerAddress);
    }
}

#[test]
fn a_complete_return_at_the_top_of_each_supported_32_bit_address_space_remains_sampleable() {
    let maximum = u64::from(u32::MAX);
    let cases = [("x86", maximum, "c3", false, 1), ("arm", maximum - 1, "7047", true, 2)];
    for (arch, address, bytes, thumb, length) in cases {
        let mut binary = fixture(arch, &[("r-x", address, bytes, thumb)]);
        binary.entry = Some(address);
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        let entry = &result.entries[0];
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.assessment, EntryAssessment::LocallyPlausible);
        assert_eq!(entry.bytes_sampled, length);
        assert_eq!(entry.decoded_bytes, length);
        assert_eq!(entry.instruction_count, 1);
        assert_eq!(entry.invalid_count, 0);
        assert_eq!(entry.last_flow, Some(Flow::Return));
        assert_eq!(entry.stop, EntrySampleStop::ControlTransfer);
        assert_eq!(entry.stop_address, Some(address));
        assert!(result.limitations.iter().any(|text| text.contains("not verified functions")));
    }
}

#[test]
fn supported_32_bit_windows_stop_at_the_exclusive_address_end_despite_continued_backing() {
    let end = u64::from(u32::MAX) + 1;
    let cases = [("x86", end - 2, "9090c3ff", false, 2), ("arm", end - 4, "00bf00bf00b87047", true, 4)];
    for (arch, address, bytes, thumb, length) in cases {
        let mut binary = fixture(arch, &[("r-x", address, bytes, thumb)]);
        binary.function_starts.push(address);
        assert!(binary.segment_containing(end).unwrap().perms.execute);
        assert!(binary.is_code(end));
        assert!(binary.read(end, 1).is_some());
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        let entry = &result.entries[0];
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.bytes_sampled, length);
        assert_eq!(entry.decoded_bytes, length);
        assert_eq!(entry.instruction_count, 2);
        assert_eq!(entry.decode_attempts, 2);
        assert_eq!(entry.invalid_count, 0);
        assert_eq!(entry.last_flow, Some(Flow::Next));
        assert_eq!(entry.stop, EntrySampleStop::WindowEnd);
        assert_eq!(entry.stop_address, Some(end));
        assert!(entry.window_bounds.contains(&EntryWindowBound::TargetAddressSpaceBoundary));
        assert_eq!(result.usage.bytes_sampled, length);
    }
}

#[test]
fn a_32_bit_boundary_clipped_instruction_stays_incomplete_even_if_its_suffix_is_backed() {
    let end = u64::from(u32::MAX) + 1;
    let cases = [("x86", end - 2, "90b801000000c3", false, 2, 1), ("arm", end - 4, "00bf00f000f87047", true, 4, 2)];
    for (arch, address, bytes, thumb, sampled, decoded) in cases {
        let binary = fixture(arch, &[("r-x", address, bytes, thumb)]);
        assert!(binary.read(end, 2).is_some());
        let result = sample_entry(&binary, address, EntryAuditLimits::default());
        let entry = &result.entries[0];
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.assessment, EntryAssessment::Unknown);
        assert_eq!(entry.bytes_sampled, sampled);
        assert_eq!(entry.decoded_bytes, decoded);
        assert_eq!(entry.instruction_count, 1);
        assert_eq!(entry.decode_attempts, 2);
        assert_eq!(entry.invalid_count, 1);
        assert_eq!(entry.last_flow, Some(Flow::Invalid));
        assert_eq!(entry.stop, EntrySampleStop::InvalidOrIncompleteTail);
        assert_eq!(entry.stop_address, Some(address + decoded as u64));
        assert!(entry.signals.contains(&EntrySignal::InvalidOrIncompleteTail));
        assert!(!entry.signals.contains(&EntrySignal::DecodeFailure));
        assert!(entry.window_bounds.contains(&EntryWindowBound::TargetAddressSpaceBoundary));
    }
}

#[test]
fn representable_64_bit_window_ends_remain_non_wrapping() {
    for (bytes, flow, stop) in
        [("c3", Flow::Return, EntrySampleStop::ControlTransfer), ("90", Flow::Next, EntrySampleStop::WindowEnd)]
    {
        let binary = fixture("x86_64", &[("r-x", u64::MAX - 1, bytes, false)]);
        let result = sample_entry(&binary, u64::MAX - 1, EntryAuditLimits::default());
        let entry = &result.entries[0];
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.bytes_sampled, 1);
        assert_eq!(entry.decoded_bytes, 1);
        assert_eq!(entry.invalid_count, 0);
        assert_eq!(entry.last_flow, Some(flow));
        assert_eq!(entry.stop, stop);
        let expected_end = if flow == Flow::Return { u64::MAX - 1 } else { u64::MAX };
        assert_eq!(entry.stop_address, Some(expected_end));
    }
    let arm64 = fixture("aarch64", &[("r-x", u64::MAX - 3, "1f2003", false)]);
    let result = sample_entry(&arm64, u64::MAX - 3, EntryAuditLimits::default());
    assert_eq!(result.entries[0].bytes_sampled, 3);
    assert_eq!(result.entries[0].stop, EntrySampleStop::IncompleteInstruction);
    assert_eq!(result.entries[0].assessment, EntryAssessment::Unknown);
    assert_eq!(result.entries[0].invalid_count, 0);
    assert_eq!(result.usage.decode_attempts, 0);
}

#[test]
fn sampling_never_bridges_a_gap_or_runs_past_a_segments_memory_span() {
    let binary = fixture("x86_64", &[("r-x", 0x1000, "90", false), ("r-x", 0x1002, "c3", false)]);
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].bytes_sampled, 1);
    assert_eq!(result.entries[0].last_flow, Some(Flow::Next));
    assert!(result.entries[0].window_bounds.contains(&EntryWindowBound::CodeOrBackingBoundary));
    assert_eq!(
        sample_entry(&binary, 0x1001, EntryAuditLimits::default()).entries[0].status,
        EntrySampleStatus::Unavailable
    );
    let mut oversized_backing = x64("90909090c3");
    oversized_backing.segments[0].size = 2;
    let result = sample_entry(&oversized_backing, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].bytes_sampled, 2);
    assert_eq!(result.entries[0].decoded_bytes, 2);
}

#[test]
fn a_code_range_ending_inside_a_larger_backed_executable_segment_is_not_crossed() {
    let mut binary = fixture("x86_64", &[("r-x", 0x1000, "90", false), ("r--", 0x1001, "0f0f0f0f", false)]);
    let backed_size = binary.image_bytes().len() as u64;
    binary.segments[0].size = backed_size;
    binary.segments[0].file_size = backed_size;
    binary.segments.truncate(1);
    assert!(binary.segment_containing(0x1001).unwrap().perms.execute);
    assert_eq!(binary.read(0x1000, backed_size).unwrap(), &[0x90, 0x0f, 0x0f, 0x0f, 0x0f]);
    assert!(!binary.is_code(0x1001));

    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.bytes_sampled, 1);
    assert_eq!(entry.decoded_bytes, 1);
    assert_eq!(entry.instruction_count, 1);
    assert_eq!(entry.invalid_count, 0);
    assert_eq!(entry.stop, EntrySampleStop::WindowEnd);
    assert!(entry.window_bounds.contains(&EntryWindowBound::CodeOrBackingBoundary));
    assert_eq!(
        sample_entry(&binary, 0x1001, EntryAuditLimits::default()).entries[0].status,
        EntrySampleStatus::NonCode
    );
}

#[test]
fn a_zero_fill_tail_preserves_only_the_backed_prefix_without_decoding_the_tail() {
    let mut binary = x64("90909090c3");
    binary.segments[0].file_size = 2;
    assert!(binary.is_code(0x1002));
    assert!(binary.segment_containing(0x1002).is_some());
    assert!(binary.read(0x1000, 3).is_none());

    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.bytes_sampled, 2);
    assert_eq!(entry.decoded_bytes, 2);
    assert_eq!(entry.instruction_count, 2);
    assert_eq!(entry.last_flow, Some(Flow::Next));
    assert_eq!(entry.stop, EntrySampleStop::WindowEnd);
    assert!(entry.window_bounds.contains(&EntryWindowBound::CodeOrBackingBoundary));

    let tail = sample_entry(&binary, 0x1002, EntryAuditLimits::default());
    assert_eq!(tail.entries[0].status, EntrySampleStatus::Unavailable);
    assert!(tail.entries[0].unavailable_reason.unwrap().contains("zero-fill"));
    assert_eq!(tail.usage.bytes_sampled, 0);
    assert_eq!(tail.usage.decode_attempts, 0);
}

#[test]
fn truncated_backing_preserves_a_short_prefix_and_marks_its_incomplete_decode_unknown() {
    let mut binary = x64("909090909090900f");
    binary.segments[0].file_offset = 6;
    assert!(binary.read(0x1000, binary.segments[0].file_size).is_none());
    assert_eq!(binary.read(0x1000, 2).unwrap(), &[0x90, 0x0f]);

    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.bytes_sampled, 2);
    assert_eq!(entry.decoded_bytes, 1);
    assert_eq!(entry.instruction_count, 1);
    assert_eq!(entry.invalid_count, 1);
    assert_eq!(entry.assessment, EntryAssessment::Unknown);
    assert_eq!(entry.stop, EntrySampleStop::InvalidOrIncompleteTail);
    assert!(entry.window_bounds.contains(&EntryWindowBound::CodeOrBackingBoundary));
    assert!(entry.signals.contains(&EntrySignal::InvalidOrIncompleteTail));

    let tail = sample_entry(&binary, 0x1002, EntryAuditLimits::default());
    assert_eq!(tail.entries[0].status, EntrySampleStatus::Unavailable);
    assert_eq!(tail.usage.bytes_sampled, 0);
    assert_eq!(tail.usage.decode_attempts, 0);
}

#[test]
fn selection_and_origin_order_are_deterministic_without_sorting_input_metadata() {
    let mut binary = x64("90909090c3");
    binary.function_starts = vec![0x1004, 0x1000, 0x1002, 0x1000];
    binary.exports =
        vec![Export { name: "z".to_owned(), address: 0x1000 }, Export { name: "a".to_owned(), address: 0x1000 }];
    binary.symbols = vec![symbol(0x1000, "z", SymbolKind::Function), symbol(0x1000, "a", SymbolKind::Function)];
    let limits = EntryAuditLimits { max_entries: 2, ..EntryAuditLimits::default() };
    let first = sample_declared_entries(&binary, limits);
    assert_eq!(first.entries.iter().map(|entry| entry.address).collect::<Vec<_>>(), vec![0x1000, 0x1002]);
    assert!(first.truncation.contains(&EntryAuditTruncation::EntryLimit));
    binary.function_starts.reverse();
    binary.exports.reverse();
    binary.symbols.reverse();
    assert_eq!(format!("{first:?}"), format!("{:?}", sample_declared_entries(&binary, limits)));
}

#[test]
fn failed_low_address_candidates_consume_the_entry_cap_without_rescuing_a_later_candidate() {
    let mut binary = fixture("x86_64", &[("r-x", 0x8000, "c3", false)]);
    binary.function_starts = (0..MAX_ENTRIES).map(|index| 0x1000 + index as u64).collect();
    binary.function_starts.push(0x8000);
    let limits = EntryAuditLimits {
        max_entries: usize::MAX,
        bytes_per_entry: usize::MAX,
        instructions_per_entry: usize::MAX,
        total_bytes: usize::MAX,
        total_decode_attempts: usize::MAX,
    };
    let result = sample_declared_entries(&binary, limits);
    assert_eq!(result.entries.len(), MAX_ENTRIES);
    assert!(result.entries.iter().all(|entry| entry.status == EntrySampleStatus::Unavailable));
    assert!(result.truncation.contains(&EntryAuditTruncation::EntryLimit));
    assert!(result.truncation.contains(&EntryAuditTruncation::RequestedLimitsClamped));
    assert_eq!(result.usage.bytes_sampled, 0);
}

#[test]
fn preflight_refuses_metadata_and_declaration_counts_before_sampling_or_copying_names() {
    let mut binary = x64("c3");
    binary.symbols.push(symbol(0x1000, "claimed", SymbolKind::Function));
    binary.segments.extend(std::iter::repeat_n(binary.segments[0].clone(), MAX_METADATA_ITEMS));
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.status, EntryAuditStatus::Unavailable);
    assert!(result.entries.is_empty());
    assert!(result.truncation.contains(&EntryAuditTruncation::MetadataLimit));
    assert_eq!(result.usage.name_bytes_copied, 0);
    assert_eq!(result.usage.lookup_work_reserved, 0);

    let mut binary = x64("c3");
    binary.function_starts = vec![0x1000; MAX_DECLARATIONS + 1];
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.status, EntryAuditStatus::Unavailable);
    assert!(result.truncation.contains(&EntryAuditTruncation::DeclarationLimit));
    assert_eq!(result.usage.declaration_records, 0);
    assert_eq!(result.usage.bytes_sampled, 0);
}

#[test]
fn name_preflights_fail_before_any_output_name_copy_or_target_lookup() {
    let mut binary = x64("c3");
    binary.symbols.push(symbol(0x1000, &"x".repeat(MAX_NAME_BYTES + 1), SymbolKind::Function));
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    assert!(result.entries.is_empty());
    assert!(result.truncation.contains(&EntryAuditTruncation::NameLengthLimit));
    assert_eq!(result.usage.name_bytes_copied, 0);
    assert_eq!(result.usage.lookup_work_reserved, 0);

    let mut binary = x64("c3");
    let named = symbol(0x1000, &"x".repeat(MAX_NAME_BYTES), SymbolKind::Function);
    binary.symbols = vec![named; MAX_METADATA_NAME_BYTES / MAX_NAME_BYTES + 1];
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert!(result.entries.is_empty());
    assert!(result.truncation.contains(&EntryAuditTruncation::MetadataNameBytes));
    assert_eq!(result.usage.name_bytes_copied, 0);
    assert_eq!(result.usage.decode_attempts, 0);
}

#[test]
fn output_name_budget_omits_text_explicitly_without_losing_entries_or_origin_kinds() {
    let mut binary = x64(&"90".repeat(64));
    binary.symbols = (0..32).map(|index| symbol(0x1000 + index, &"x".repeat(3000), SymbolKind::Function)).collect();
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), 32);
    assert!(result.truncation.contains(&EntryAuditTruncation::OutputNameBytes));
    assert!(result.usage.name_bytes_copied <= MAX_OUTPUT_NAME_BYTES);
    assert!(result.entries.iter().any(|entry| entry.origins[0].name_omitted));
    assert!(result.entries.iter().all(|entry| entry.origins[0].kind == EntryOriginKind::Symbol));
}

#[test]
fn alias_overflow_keeps_each_metadata_origin_kind_and_reports_loss_deterministically() {
    let mut binary = x64("c3");
    binary.symbols = (0..32).map(|index| symbol(0x1000, &format!("alias-{index:02}"), SymbolKind::Function)).collect();
    binary.exports.push(Export { name: "export".to_owned(), address: 0x1000 });
    binary.function_starts.push(0x1000);
    binary.entry = Some(0x1000);
    let first = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &first.entries[0];
    assert!(entry.origins_truncated);
    assert!(entry.origins.len() <= MAX_ORIGINS_PER_ENTRY);
    let kinds =
        [EntryOriginKind::Symbol, EntryOriginKind::Export, EntryOriginKind::FunctionStarts, EntryOriginKind::Entry];
    for kind in kinds {
        assert!(entry.origins.iter().any(|origin| origin.kind == kind));
    }
    binary.symbols.reverse();
    assert_eq!(format!("{first:?}"), format!("{:?}", sample_entry(&binary, 0x1000, EntryAuditLimits::default())));
}

#[test]
fn cumulative_sample_bytes_and_decode_attempts_are_spent_across_entries() {
    let mut binary = x64(&"90".repeat(64));
    binary.function_starts = vec![0x1000, 0x1008, 0x1010];
    let byte_limits = EntryAuditLimits { bytes_per_entry: 4, total_bytes: 5, ..EntryAuditLimits::default() };
    let result = sample_declared_entries(&binary, byte_limits);
    assert_eq!(result.usage.bytes_sampled, 5);
    assert_eq!(result.entries[0].bytes_sampled, 4);
    assert_eq!(result.entries[1].bytes_sampled, 1);
    assert!(result.entries[1].window_bounds.contains(&EntryWindowBound::TotalByteBudget));
    assert_eq!(result.entries[2].status, EntrySampleStatus::BudgetUnavailable);
    assert!(result.truncation.contains(&EntryAuditTruncation::TotalBytes));

    let decode_limits = EntryAuditLimits {
        bytes_per_entry: 4,
        instructions_per_entry: 2,
        total_decode_attempts: 3,
        ..EntryAuditLimits::default()
    };
    let result = sample_declared_entries(&binary, decode_limits);
    assert_eq!(result.usage.decode_attempts, 3);
    assert_eq!(result.entries[0].stop, EntrySampleStop::InstructionLimit);
    assert_eq!(result.entries[1].stop, EntrySampleStop::TotalDecodeAttempts);
    assert_eq!(result.entries[2].status, EntrySampleStatus::BudgetUnavailable);
    assert!(result.truncation.contains(&EntryAuditTruncation::TotalDecodeAttempts));
}

#[test]
fn default_budgets_bound_aggregate_and_per_entry_work_even_for_overlapping_windows() {
    let mut binary = x64(&"90".repeat(MAX_BYTES_PER_ENTRY + MAX_ENTRIES));
    binary.function_starts = (0..MAX_ENTRIES + 10).map(|index| 0x1000 + index as u64).collect();
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), MAX_ENTRIES);
    assert!(result.usage.bytes_sampled <= MAX_TOTAL_BYTES);
    assert!(result.usage.decode_attempts <= MAX_TOTAL_DECODE_ATTEMPTS);
    assert!(result.entries.iter().all(|entry| entry.bytes_sampled <= MAX_BYTES_PER_ENTRY));
    assert!(result.entries.iter().all(|entry| entry.decode_attempts <= MAX_INSTRUCTIONS_PER_ENTRY));
    assert!(result.entries.iter().all(|entry| entry.stop == EntrySampleStop::InstructionLimit));
}

#[test]
fn cumulative_lookup_work_is_reserved_before_reading_another_entry() {
    let mut binary = x64(&"90".repeat(MAX_BYTES_PER_ENTRY));
    let mut unrelated = binary.segments[0].clone();
    unrelated.address = 0x8000;
    binary.segments.extend(std::iter::repeat_n(unrelated, 4000));
    binary.function_starts = (0..MAX_ENTRIES).map(|index| 0x1000 + index as u64).collect();
    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), MAX_ENTRIES);
    assert!(result.entries.iter().any(|entry| entry.status == EntrySampleStatus::BackedExecutableCode));
    assert!(result.entries.iter().any(|entry| entry.status == EntrySampleStatus::BudgetUnavailable));
    assert!(result.truncation.contains(&EntryAuditTruncation::LookupWork));
    assert!(result.usage.lookup_work_reserved <= MAX_LOOKUP_WORK);
    for entry in result.entries.iter().filter(|entry| entry.status == EntrySampleStatus::BudgetUnavailable) {
        assert_eq!(entry.bytes_sampled, 0);
        assert_eq!(entry.decode_attempts, 0);
    }
}

#[test]
fn zero_limits_disable_before_preflight_and_empty_or_unsupported_inputs_are_explicit() {
    let mut binary = x64("c3");
    binary.symbols.push(symbol(0x1000, &"x".repeat(MAX_NAME_BYTES + 1), SymbolKind::Function));
    let disabled = sample_entry(&binary, 0x1000, EntryAuditLimits { max_entries: 0, ..EntryAuditLimits::default() });
    assert_eq!(disabled.status, EntryAuditStatus::Disabled);
    assert!(disabled.entries.is_empty());
    assert_eq!(disabled.usage.declaration_records, 0);
    assert_eq!(sample_declared_entries(&x64("c3"), EntryAuditLimits::default()).status, EntryAuditStatus::Empty);

    let mut unsupported = x64("c3");
    unsupported.arch = Arch::Mips;
    let result = sample_entry(&unsupported, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::UnsupportedArchitecture);
    assert_eq!(result.entries[0].assessment, EntryAssessment::Unknown);
    assert_eq!(result.usage.decode_attempts, 0);
    let outside_32_bits = sample_entry(&unsupported, u64::from(u32::MAX) + 1, EntryAuditLimits::default());
    assert_eq!(outside_32_bits.entries[0].status, EntrySampleStatus::UnsupportedArchitecture);

    let mut empty = x64("c3");
    empty.segments.clear();
    empty.sections.clear();
    assert_eq!(
        sample_entry(&empty, 0x1000, EntryAuditLimits::default()).entries[0].status,
        EntrySampleStatus::Unavailable
    );
}

#[test]
fn thumb_sampling_requires_positive_declared_mode_and_never_guesses_a32_or_clears_address_tags() {
    let thumb = fixture("arm", &[("r-x", 0x1000, "7047", true)]);
    let result = sample_entry(&thumb, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::BackedExecutableCode);
    assert_eq!(result.entries[0].last_flow, Some(Flow::Return));
    assert_eq!(result.entries[0].decoded_bytes, 2);
    assert_eq!(
        sample_entry(&thumb, 0x1001, EntryAuditLimits::default()).entries[0].status,
        EntrySampleStatus::Unaligned
    );
    let unresolved = fixture("arm", &[("r-x", 0x1000, "1eff2fe1", false)]);
    let result = sample_entry(&unresolved, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::ModeUnavailable);
    assert_eq!(result.usage.decode_attempts, 0);

    let mut bounded = fixture("arm", &[("r-x", 0x1000, "00bf7047", true)]);
    bounded.thumb = std::iter::once(0x1000..0x1002).collect();
    let result = sample_entry(&bounded, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].bytes_sampled, 2);
    assert_eq!(result.entries[0].last_flow, Some(Flow::Next));
    assert!(result.entries[0].window_bounds.contains(&EntryWindowBound::ThumbModeBoundary));
}

#[test]
fn declared_thumb_conditional_returns_and_indirect_jumps_stop_before_invalid_padding() {
    for bytes in ["08bf704700b800b8", "08bf004700b800b8"] {
        let mut binary = fixture("arm", &[("r-x", 0x1000, bytes, true)]);
        binary.function_starts.push(0x1000);
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        let entry = &result.entries[0];
        assert_eq!(entry.origins[0].kind, EntryOriginKind::FunctionStarts);
        assert_eq!(entry.status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(entry.stop, EntrySampleStop::ControlTransfer);
        assert_eq!(entry.last_flow, Some(Flow::Next));
        assert!(entry.last_conditional_transfer);
        assert_eq!(entry.stop_address, Some(0x1002));
        assert_eq!(entry.instruction_count, 2);
        assert_eq!(entry.decoded_bytes, 4);
        assert_eq!(entry.decode_attempts, 2);
        assert_eq!(entry.invalid_count, 0);
        assert_eq!(entry.assessment, EntryAssessment::LocallyPlausible);
        assert!(result.limitations.iter().any(|text| text.contains("not verified functions")));
    }
}

#[test]
fn ordinary_predicated_thumb_data_execution_does_not_stop_the_prefix_as_a_transfer() {
    let binary = fixture("arm", &[("r-x", 0x1000, "08bf0120704700b8", true)]);
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    let entry = &result.entries[0];
    assert_eq!(entry.stop, EntrySampleStop::ControlTransfer);
    assert_eq!(entry.last_flow, Some(Flow::Return));
    assert!(!entry.last_conditional_transfer);
    assert_eq!(entry.stop_address, Some(0x1004));
    assert_eq!(entry.instruction_count, 3);
    assert_eq!(entry.decoded_bytes, 6);
    assert_eq!(entry.invalid_count, 0);
}

#[test]
fn learned_a32_call_target_mode_does_not_leak_into_a_later_declared_thumb_entry() {
    let mut binary = fixture("arm", &[("r-x", 0x1000, "00f002e800b800b87047", true)]);
    binary.function_starts = vec![0x1008, 0x1000];

    let mut probe = binary.decoder().unwrap();
    let call = probe.decode(binary.code_from(0x1000).unwrap(), 0x1000);
    assert_eq!(call.flow, Flow::Call(0x1008));
    assert!(probe.code_modes().contains(&(0x1008, false)));
    probe.begin_run();
    assert_eq!(probe.decode(binary.code_from(0x1008).unwrap(), 0x1008).flow, Flow::Invalid);

    let result = sample_declared_entries(&binary, EntryAuditLimits::default());
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].address, 0x1000);
    assert_eq!(result.entries[0].last_flow, Some(Flow::Call(0x1008)));
    assert_eq!(result.entries[0].decoded_bytes, 4);
    let later = &result.entries[1];
    assert_eq!(later.address, 0x1008);
    assert_eq!(later.origins[0].kind, EntryOriginKind::FunctionStarts);
    assert_eq!(later.status, EntrySampleStatus::BackedExecutableCode);
    assert_eq!(later.last_flow, Some(Flow::Return));
    assert!(!later.last_conditional_transfer);
    assert_eq!(later.stop, EntrySampleStop::ControlTransfer);
    assert_eq!(later.decoded_bytes, 2);
    assert_eq!(later.instruction_count, 1);
    assert_eq!(later.invalid_count, 0);
}

#[test]
fn invalid_mode_metadata_is_refused_before_target_cloning_or_sampling() {
    let mut binary = fixture("arm", &[("r-x", 0x1000, "7047", true)]);
    binary.thumb = vec![0x1000..0x1002, 0x1001..0x1002];
    let result = sample_entry(&binary, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.status, EntryAuditStatus::Unavailable);
    assert!(result.entries.is_empty());
    assert!(result.truncation.contains(&EntryAuditTruncation::InvalidThumbMetadata));
    assert_eq!(result.usage.lookup_work_reserved, 0);
}

#[test]
fn instruction_byte_order_is_honored_or_explicitly_refused_not_silently_decoded_as_little_endian() {
    let thumb = fixture_with_order("arm", &[("r-x", 0x1000, "4770", true)], true);
    let result = sample_entry(&thumb, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::BackedExecutableCode);
    assert_eq!(result.entries[0].last_flow, Some(Flow::Return));

    let arm64 = fixture_with_order("aarch64", &[("r-x", 0x1000, "d65f03c0", false)], true);
    let result = sample_entry(&arm64, 0x1000, EntryAuditLimits::default());
    assert_eq!(result.entries[0].status, EntrySampleStatus::UnsupportedByteOrder);
    assert_eq!(result.usage.decode_attempts, 0);
}

#[test]
fn generic_mapping_evidence_does_not_depend_on_a_product_or_static_format_label() {
    let mut binary = x64("c3");
    binary.entry = Some(0x1000);
    for format in [Format::Elf, Format::MachO, Format::Pe, Format::Snapshot] {
        binary.format = format;
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        assert_eq!(result.entries[0].status, EntrySampleStatus::BackedExecutableCode);
        assert_eq!(result.entries[0].last_flow, Some(Flow::Return));
    }
}

#[test]
fn control_transfers_are_observed_without_following_targets_or_mutating_binary_metadata() {
    let cases = [
        ("e800000000c3", Flow::Call(0x1005), 0, 0),
        ("ffd0c3", Flow::IndirectCall, 1, 0),
        ("ffe0c3", Flow::IndirectJump, 0, 1),
        ("eb00c3", Flow::Jump(0x1002), 0, 0),
        ("7400c3", Flow::ConditionalJump(0x1002), 0, 0),
        ("f4c3", Flow::Halt, 0, 0),
    ];
    for (bytes, flow, calls, jumps) in cases {
        let mut binary = x64(bytes);
        binary.entry = Some(0x1000);
        let before = format!("{binary:?}");
        let result = sample_declared_entries(&binary, EntryAuditLimits::default());
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].instruction_count, 1);
        assert_eq!(result.entries[0].stop, EntrySampleStop::ControlTransfer);
        assert_eq!(result.entries[0].last_flow, Some(flow));
        assert!(!result.entries[0].last_conditional_transfer);
        assert_eq!(result.entries[0].indirect_calls, calls);
        assert_eq!(result.entries[0].indirect_jumps, jumps);
        assert_eq!(format!("{binary:?}"), before);
    }
}
