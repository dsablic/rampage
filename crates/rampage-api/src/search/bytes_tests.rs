use std::sync::atomic::AtomicBool;

use rampage_loaders::{Binary, Perms, Segment};
use serde_json::json;

use super::*;

fn snapshot(regions: &[(u64, &[u8])]) -> Binary {
    let regions: Vec<_> = regions
        .iter()
        .enumerate()
        .map(|(index, (address, bytes))| {
            json!({
                "name": format!("owned_{index}"), "address": format!("0x{address:x}"),
                "permissions": "r--", "bytes": rampage_arch::hex::bytes(bytes),
            })
        })
        .collect();
    Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64",
            "provenance": "Owned search fixture; inspected, never executed", "regions": regions,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn bytes(pattern: &str) -> SearchQuery {
    SearchQuery::new(SearchMode::Bytes { pattern: pattern.into() })
}

fn text(pattern: &str, encoding: SearchTextEncoding, regex: bool) -> SearchQuery {
    SearchQuery::new(SearchMode::Text { pattern: pattern.into(), encoding, regex })
}

fn addresses(report: &SearchReport) -> Vec<u64> {
    report.hits.iter().map(|hit| hit.address).collect()
}

fn fragmented_snapshot(image: &[u8], mappings: &[(u64, u64, u64)]) -> Binary {
    let mut binary = snapshot(&[(0x8000, image)]);
    binary.segments = mappings
        .iter()
        .enumerate()
        .map(|(index, &(address, offset, size))| Segment {
            name: format!("piece_{index}"),
            address,
            size,
            file_offset: offset,
            file_size: size,
            perms: Perms { read: true, write: false, execute: false },
        })
        .collect();
    binary
}

#[test]
fn discontiguous_backing_is_one_virtual_domain_for_literals_and_regex_anchors() {
    let project = Project::new(fragmented_snapshot(b"aXb", &[(0x1000, 0, 1), (0x1001, 2, 1)]));
    for query in
        [bytes("6? 62"), text("ab", SearchTextEncoding::Ascii, false), text("^ab$", SearchTextEncoding::Ascii, true)]
    {
        let report = project.search(&query).unwrap();
        assert_eq!(addresses(&report), [0x1000]);
        assert_eq!(report.hits[0].size, 2);
        assert_eq!(report.hits[0].image_offset, Some(0));
        assert!(report.total_is_exact);
    }
    for pattern in ["a$", "^b", "X", "aXb"] {
        assert_eq!(project.search(&text(pattern, SearchTextEncoding::Ascii, true)).unwrap().total, 0, "{pattern}");
    }
    let report = project.search(&text("b$", SearchTextEncoding::Ascii, true)).unwrap();
    assert_eq!(addresses(&report), [0x1001]);
    assert_eq!(report.hits[0].image_offset, Some(2));
}

#[test]
fn declared_ranges_bound_regex_domains_but_scan_budgets_do_not_invent_domain_ends() {
    let project = Project::new(fragmented_snapshot(b"aXb", &[(0x1000, 0, 1), (0x1001, 2, 1)]));
    let mut query = text("a$", SearchTextEncoding::Ascii, true);
    query.range = Some(SearchRange { start: 0x1000, end: 0x1001 });
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1000]);
    assert!(report.total_is_exact);
    query.range = None;
    query.budget.scan_bytes = 1;
    let report = project.search(&query).unwrap();
    assert_eq!(report.total, 0);
    assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
    assert!(!report.total_is_exact);
    let project = Project::new(fragmented_snapshot(b"aXb", &[(0x1000, 0, 1), (0x1002, 2, 1)]));
    assert_eq!(addresses(&project.search(&text("a$", SearchTextEncoding::Ascii, true)).unwrap()), [0x1000]);
    assert_eq!(project.search(&text("ab", SearchTextEncoding::Ascii, false)).unwrap().total, 0);
}

#[test]
fn discontiguous_ascii_runs_stop_at_the_allocation_bound_without_matching_a_partial_end() {
    let mut image = vec![b'a'; MAX_SEARCH_TEXT_RUN_BYTES];
    image.extend([0xff, b'b']);
    let project = Project::new(fragmented_snapshot(
        &image,
        &[
            (0x1000, 0, MAX_SEARCH_TEXT_RUN_BYTES as u64),
            (0x1000 + MAX_SEARCH_TEXT_RUN_BYTES as u64, MAX_SEARCH_TEXT_RUN_BYTES as u64 + 1, 1),
        ],
    ));
    let report = project.search(&text("a$", SearchTextEncoding::Ascii, true)).unwrap();
    assert_eq!(report.total, 0);
    assert_eq!(report.stop_reason, SearchStopReason::TextRunBudget);
    assert!(!report.total_is_exact);
}

#[test]
fn utf16_units_and_surrogate_pairs_cross_discontiguous_backing_without_false_boundaries() {
    for encoding in [SearchTextEncoding::Utf16Le, SearchTextEncoding::Utf16Be] {
        let mut image = vec![0xff; 16];
        let bytes: Vec<u8> = "a😀b"
            .encode_utf16()
            .flat_map(|unit| match encoding {
                SearchTextEncoding::Utf16Le => unit.to_le_bytes(),
                _ => unit.to_be_bytes(),
            })
            .collect();
        // Every byte has a separate physical piece, so both words and the surrogate pair cross mappings.
        let mappings: Vec<_> = bytes
            .iter()
            .enumerate()
            .map(|(index, &byte)| {
                image[index * 2] = byte;
                (0x1000 + index as u64, (index * 2) as u64, 1)
            })
            .collect();
        let project = Project::new(fragmented_snapshot(&image, &mappings));
        for query in [text("a😀b", encoding, false), text("^a😀b$", encoding, true)] {
            let report = project.search(&query).unwrap();
            assert_eq!(addresses(&report), [0x1000]);
            assert_eq!(report.hits[0].size, 8);
            assert_eq!(report.invalid_utf16_units, 0);
            assert_eq!(report.utf16_trailing_bytes, 0);
            assert_eq!(report.hits[0].image_offset, Some(0));
        }
        assert_eq!(project.search(&text("a$", encoding, true)).unwrap().total, 0);
        let report = project.search(&text("😀", encoding, true)).unwrap();
        assert_eq!(addresses(&report), [0x1002]);
        assert_eq!(report.hits[0].size, 4);
        assert_eq!(report.hits[0].image_offset, Some(4));
        let report = project.search(&text("b", encoding, false)).unwrap();
        assert_eq!(addresses(&report), [0x1006]);
        assert_eq!(report.hits[0].image_offset, Some(12));
    }
}

#[test]
fn discontiguous_unicode_regex_keeps_real_invalid_surrogates_as_boundaries() {
    let project = Project::new(fragmented_snapshot(
        &[0x61, 0, 0xff, 0x00, 0xdc, 0xff, 0x62, 0],
        &[(0x1000, 0, 2), (0x1002, 3, 2), (0x1004, 6, 2)],
    ));
    assert_eq!(project.search(&text("a.*b", SearchTextEncoding::Utf16Le, true)).unwrap().total, 0);
    let report = project.search(&text("^b$", SearchTextEncoding::Utf16Le, true)).unwrap();
    assert_eq!(addresses(&report), [0x1004]);
    assert_eq!(report.hits[0].image_offset, Some(6));
    assert_eq!(report.invalid_utf16_units, 1);
}

#[test]
fn repository_file_offsets_describe_the_first_piece_not_a_fabricated_contiguous_extent() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let mut binary = Binary::open(&path).unwrap();
    assert_eq!(&binary.image_bytes()[..4], b"\x7fELF");
    binary.segments = vec![
        Segment {
            name: "first".into(),
            address: 0x1000,
            size: 1,
            file_offset: 1,
            file_size: 1,
            perms: Perms { read: true, write: false, execute: false },
        },
        Segment {
            name: "last".into(),
            address: 0x1001,
            size: 1,
            file_offset: 3,
            file_size: 1,
            perms: Perms { read: true, write: false, execute: false },
        },
    ];
    let project = Project::new(binary);
    assert_eq!(project.search(&text("E$", SearchTextEncoding::Ascii, true)).unwrap().total, 0);
    let report = project.search(&text("EF", SearchTextEncoding::Ascii, false)).unwrap();
    assert_eq!(addresses(&report), [0x1000]);
    assert_eq!(report.hits[0].file_offset, Some(1));
    assert_eq!(report.hits[0].image_offset, Some(1));
    assert_eq!(report.hits[0].size, 2);
    let report = project.search(&text("F", SearchTextEncoding::Ascii, true)).unwrap();
    assert_eq!(report.hits[0].file_offset, Some(3));
}

#[test]
fn shared_block_hits_keep_the_retained_owner_and_each_owners_annotated_name() {
    let project = Project::new(
        Binary::from_snapshot_bytes(
            serde_json::to_vec(&json!({
                "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": "Owned shared-block fixture",
                "entry": "0x1000", "seeds": ["0x1000", "0x2000"],
                "regions": [
                    {"name": "first", "address": "0x1000", "permissions": "r-x", "bytes": "0f84fa1f0000c3"},
                    {"name": "second", "address": "0x2000", "permissions": "r-x", "bytes": "0f84fa0f0000c3"},
                    {"name": "shared", "address": "0x3000", "permissions": "r-x", "bytes": "b82a000000c3"}
                ]
            }))
            .unwrap(),
        )
        .unwrap(),
    );
    let mut query = SearchQuery::new(SearchMode::FunctionsReferencing {
        reference: SearchReference::Constant { immediate: semantic(SearchValue::Unsigned(42)) },
    });
    query.include_context = true;
    for hit in project.search(&query).unwrap().hits {
        let context = hit.function.as_ref().unwrap();
        assert_eq!(context.address, hit.code.as_ref().unwrap().native_function);
        if hit.address == 0x1000 {
            assert_eq!(context.symbol_source, SearchSymbolSource::LoaderName);
            assert_eq!(context.name, "entry");
        } else {
            assert_eq!(context.symbol_source, SearchSymbolSource::Synthetic);
            assert_eq!(context.name, "sub_2000");
        }
    }
    project.rename(0x1000, Some("first_owner")).unwrap();
    project.rename(0x2000, Some("second_owner")).unwrap();
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1000, 0x2000]);
    for (hit, name) in report.hits.iter().zip(["first_owner", "second_owner"]) {
        let context = hit.function.as_ref().unwrap();
        assert_eq!(hit.code.as_ref().unwrap().site, 0x3000);
        assert_eq!(context.address, hit.address);
        assert_eq!(context.address, hit.code.as_ref().unwrap().native_function);
        assert_eq!(context.name, name);
        assert_eq!(context.symbol_source, SearchSymbolSource::Annotation);
    }
    query.mode = SearchMode::Immediate { immediate: semantic(SearchValue::Unsigned(42)) };
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x3000]);
    assert_eq!(
        report.hits[0].function.as_ref().unwrap().address,
        report.hits[0].code.as_ref().unwrap().native_function
    );
    assert_eq!(report.hits[0].function.as_ref().unwrap().name, "first_owner");
}

#[test]
fn nibble_and_byte_wildcards_find_exact_offsets_without_analysis() {
    let project = Project::new(snapshot(&[(0x1000, &[0x60, 0x2a, 0x99, 0x6f, 0xfa, 0x42])]));
    let report = project.search(&bytes("6? ?a ??")).unwrap();
    assert_eq!(addresses(&report), [0x1000, 0x1003]);
    assert_eq!(report.total, 2);
    assert!(report.total_is_exact);
    assert_eq!(report.scanned_bytes, 6);
    assert_eq!(report.hits[1].image_offset, Some(3));
    assert!(report.hits.iter().all(|hit| hit.file_offset.is_none() && hit.function.is_none()));
    assert!(!project.analysis_cache_status().program);
    assert!(report.source.backing_path.is_none());
    assert!(report.source.owned_image);
}

#[test]
fn malformed_and_unbounded_patterns_are_refused_by_the_shared_parser() {
    let project = Project::new(snapshot(&[(0x1000, &[0])]));
    for pattern in ["", "?? ??", "?", "GG"] {
        assert!(project.search(&bytes(pattern)).is_err(), "{pattern:?}");
    }
    assert!(project.search(&bytes(&"00".repeat(MAX_SEARCH_PATTERN_BYTES + 1))).is_err());
}

#[test]
fn gaps_and_missing_segment_tails_never_join_into_matches() {
    let mut binary = snapshot(&[(0x1000, b"ab"), (0x2000, b"cd")]);
    binary.segments[0].size = 0x100;
    let project = Project::new(binary);
    assert_eq!(project.search(&bytes("62 63")).unwrap().total, 0);
    assert_eq!(project.search(&bytes("62 00")).unwrap().total, 0);
    let report = project.search(&bytes("61")).unwrap();
    assert_eq!(report.scope.eligible_bytes, 4);
    assert_eq!(report.scanned_bytes, 4);
    assert_eq!(report.scope.mapped_spans, 2);
}

#[test]
fn contiguous_unambiguous_mappings_can_match_across_the_boundary() {
    let project = Project::new(snapshot(&[(0x1000, b"ab"), (0x1002, b"cd")]));
    let report = project.search(&bytes("62 63")).unwrap();
    assert_eq!(addresses(&report), [0x1001]);
    assert_eq!(report.scope.mapped_spans, 1);
}

#[test]
fn duplicate_backing_is_deduplicated_but_conflicting_backing_is_refused() {
    let mut binary = snapshot(&[(0x1000, b"aaa")]);
    binary.segments.push(binary.segments[0].clone());
    let report = Project::new(binary).search(&bytes("61")).unwrap();
    assert_eq!(addresses(&report), [0x1000, 0x1001, 0x1002]);
    assert_eq!(report.scanned_bytes, 3);

    let mut binary = snapshot(&[(0x1000, b"abc"), (0x2000, b"xyz")]);
    binary.segments[1].address = 0x1001;
    assert!(Project::new(binary).search(&bytes("61")).is_err());
}

#[test]
fn stored_bytes_overlapping_another_mappings_zero_fill_are_ambiguous() {
    let mut binary = snapshot(&[(0x1000, b"ab"), (0x2000, b"cd")]);
    binary.segments[0].size = 8;
    binary.segments[1].address = 0x1002;
    assert!(Project::new(binary).search(&bytes("63")).is_err());
}

#[test]
fn pagination_does_not_change_totals_and_overlapping_matches_are_retained() {
    let project = Project::new(snapshot(&[(0x1000, b"aaaaa")]));
    let mut query = bytes("61 61");
    query.offset = 2;
    query.limit = 1;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1002]);
    assert_eq!(report.total, 4);
    assert!(report.total_is_exact);
    assert_eq!(report.scanned_bytes, 5);
    query.limit = 0;
    assert!(project.search(&query).is_err());
}

#[test]
fn ranges_use_exclusive_end_and_do_not_read_pattern_lookahead_outside_them() {
    let project = Project::new(snapshot(&[(0x1000, b"ababa")]));
    let mut query = bytes("61 62 61");
    query.range = Some(SearchRange { start: 0x1001, end: 0x1004 });
    let report = project.search(&query).unwrap();
    assert_eq!(report.total, 0);
    assert_eq!(report.scanned_bytes, 3);
    query.range = Some(SearchRange { start: 0x1002, end: 0x1005 });
    assert_eq!(addresses(&project.search(&query).unwrap()), [0x1002]);
}

#[test]
fn byte_and_work_budgets_report_lower_bounds_not_complete_totals() {
    let project = Project::new(snapshot(&[(0x1000, b"aaaaa")]));
    let mut query = bytes("61");
    query.budget.scan_bytes = 3;
    let report = project.search(&query).unwrap();
    assert_eq!(report.total, 3);
    assert!(!report.total_is_exact);
    assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
    assert_eq!(report.scanned_bytes, 3);
    query.budget.scan_bytes = MAX_SEARCH_SCAN_BYTES;
    query.budget.match_work = 2;
    let report = project.search(&query).unwrap();
    assert_eq!(report.total, 2);
    assert_eq!(report.stop_reason, SearchStopReason::MatchWorkBudget);
    assert_eq!(report.budget.match_work, 2);
    assert_eq!(report.scanned_bytes, 2);
    // Byte patterns resume at the first start they could not afford to compare.
    assert_eq!(report.resume_at, Some(0x1002));
    assert_eq!(report.unscanned_ranges, [UnscannedRange { start: 0x1002, end: 0x1005 }]);
}

/// Benchmark v2: a 42-character text search over the 50 MB Hugo image stopped on match_work after 1.6 MB, with
/// no hits, because each candidate start was charged the whole needle length. Exact text is charged one unit per
/// candidate start, and a stopped scan says where to resume and what it left unscanned.
#[test]
fn exact_text_work_is_linear_in_the_haystack_and_a_stopped_scan_can_resume() {
    let needle = "cascade is only supported for branch nodes";
    let mut data = vec![b'x'; 8 * 1024 * 1024];
    let at = data.len() - 1000;
    data[at..at + needle.len()].copy_from_slice(needle.as_bytes());
    let project = Project::new(snapshot(&[(0x1000, &data), (0x2000_0000, b"tail")]));
    let mut query = text(needle, SearchTextEncoding::Ascii, false);
    // Less than the old per-start charge of the needle length (8 MiB x 42), more than one unit per start.
    query.budget.match_work = 9 * 1024 * 1024;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1000 + at as u64]);
    assert_eq!(report.stop_reason, SearchStopReason::Complete);
    assert!(report.resume_at.is_none() && report.unscanned_ranges.is_empty());

    query.budget.match_work = 1024 * 1024;
    let report = project.search(&query).unwrap();
    assert_eq!((report.total, report.stop_reason), (0, SearchStopReason::MatchWorkBudget));
    let resume = report.resume_at.unwrap();
    assert_eq!(resume, 0x1000 + 1024 * 1024);
    assert_eq!(
        report.unscanned_ranges,
        [
            UnscannedRange { start: resume, end: 0x1000 + data.len() as u64 },
            UnscannedRange { start: 0x2000_0000, end: 0x2000_0004 }
        ]
    );
    query.budget.match_work = MAX_SEARCH_MATCH_WORK;
    query.range = Some(SearchRange { start: resume, end: 0x1000 + data.len() as u64 });
    assert_eq!(addresses(&project.search(&query).unwrap()), [0x1000 + at as u64]);
}

#[test]
fn result_cap_observes_one_additional_unique_hit_and_reports_a_lower_bound() {
    let project = Project::new(snapshot(&[(0x1000, b"aaaaa")]));
    let mut query = bytes("61");
    query.budget.results = 2;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1000, 0x1001]);
    assert_eq!(report.total, 3);
    assert_eq!(report.stop_reason, SearchStopReason::ResultCap);
    assert!(!report.total_is_exact);
    assert!(report.truncated);
}

#[test]
fn cancellation_does_not_initialize_analysis_or_invent_a_complete_empty_result() {
    let project = Project::new(snapshot(&[(0x1000, b"aaa")]));
    let cancelled = AtomicBool::new(true);
    let report = project.search_controlled(&bytes("61"), &SearchControl { cancel: Some(&cancelled) }).unwrap();
    assert_eq!(report.stop_reason, SearchStopReason::Cancelled);
    assert_eq!(report.total, 0);
    assert_eq!(report.scanned_bytes, 0);
    assert!(report.cancelled);
    assert!(!report.total_is_exact);
    assert!(!project.analysis_cache_status().program);
}

#[test]
fn ascii_exact_is_content_not_a_symbol_name_search() {
    let mut binary = snapshot(&[(0x1000, b"actual content")]);
    binary.symbols.push(rampage_loaders::Symbol {
        name: "imaginary".into(),
        address: 0x1000,
        size: 1,
        kind: rampage_loaders::SymbolKind::Data,
    });
    let project = Project::new(binary);
    assert_eq!(project.search(&text("imaginary", SearchTextEncoding::Ascii, false)).unwrap().total, 0);
    assert_eq!(addresses(&project.search(&text("content", SearchTextEncoding::Ascii, false)).unwrap()), [0x1007]);
    assert!(project.search(&text("é", SearchTextEncoding::Ascii, false)).is_err());
}

#[test]
fn utf16_exact_encodes_non_ascii_and_surrogate_pairs_for_both_byte_orders() {
    let query_text = "é水😀";
    for encoding in [SearchTextEncoding::Utf16Le, SearchTextEncoding::Utf16Be] {
        let mut data = vec![0xff, 0xff];
        for unit in query_text.encode_utf16() {
            data.extend(match encoding {
                SearchTextEncoding::Utf16Le => unit.to_le_bytes(),
                _ => unit.to_be_bytes(),
            });
        }
        data.extend([0x00, 0xd8]);
        let project = Project::new(snapshot(&[(0x1000, &data)]));
        let report = project.search(&text(query_text, encoding, false)).unwrap();
        assert_eq!(addresses(&report), [0x1002]);
        assert_eq!(report.hits[0].size, 8);
        assert_eq!(report.hits[0].image_offset, Some(2));
    }
}

#[test]
fn utf16_alignment_is_virtual_address_based_even_when_range_starts_odd() {
    let project = Project::new(snapshot(&[(0x1001, &[0x61, 0, 0x61, 0, 0x61, 0])]));
    assert_eq!(project.search(&text("a", SearchTextEncoding::Utf16Le, false)).unwrap().total, 0);
    let project = Project::new(snapshot(&[(0x1001, &[0xff, 0x61, 0, 0x61, 0])]));
    let mut query = text("a", SearchTextEncoding::Utf16Le, false);
    query.range = Some(SearchRange { start: 0x1003, end: 0x1006 });
    assert_eq!(addresses(&project.search(&query).unwrap()), [0x1004]);
}

#[test]
fn malformed_utf16_surrogates_are_not_replaced_to_invent_exact_matches() {
    let project = Project::new(snapshot(&[(0x1000, &[0x00, 0xd8, 0x61, 0, 0x00, 0xdc])]));
    assert_eq!(project.search(&text("�", SearchTextEncoding::Utf16Le, false)).unwrap().total, 0);
    assert_eq!(addresses(&project.search(&text("a", SearchTextEncoding::Utf16Le, false)).unwrap()), [0x1002]);
}

#[test]
fn high_virtual_addresses_do_not_overflow_valid_small_backing_offsets() {
    let project = Project::new(snapshot(&[(0x1000, &[0; 32]), (u64::MAX - 16, b"abc")]));
    let mut query = bytes("62");
    query.range = Some(SearchRange { start: u64::MAX - 15, end: u64::MAX - 13 });
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [u64::MAX - 15]);
    assert_eq!(report.hits[0].image_offset, Some(33));
}

#[test]
fn ascii_regex_binds_raw_offsets_with_non_ascii_run_boundaries_and_paging() {
    let project = Project::new(snapshot(&[(0x1000, b"ab12\xffab345")]));
    let mut query = text(r"^ab[0-9]+$", SearchTextEncoding::Ascii, true);
    query.offset = 1;
    query.limit = 1;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1005]);
    assert_eq!(report.hits[0].size, 5);
    assert_eq!(report.hits[0].image_offset, Some(5));
    assert_eq!(report.total, 2);
    assert!(report.total_is_exact);
}

#[test]
fn regex_zero_width_invalid_and_complex_patterns_are_refused_explicitly() {
    let project = Project::new(snapshot(&[(0x1000, b"abc")]));
    for pattern in ["a*", r"\b", "(", "a{1000000000}"] {
        assert!(project.search(&text(pattern, SearchTextEncoding::Ascii, true)).is_err(), "{pattern}");
    }
    assert!(project.search(&text(&"a".repeat(MAX_SEARCH_PATTERN_BYTES + 1), SearchTextEncoding::Ascii, true)).is_err());
    assert!(project.search(&text(r"\b", SearchTextEncoding::Utf16Le, true)).is_err());
}

#[test]
fn utf16_unicode_regex_preserves_scalar_to_source_offsets_for_surrogate_pairs_and_invalid_runs() {
    for encoding in [SearchTextEncoding::Utf16Le, SearchTextEncoding::Utf16Be] {
        let mut data = vec![0xff, 0xff];
        for unit in "é水😀".encode_utf16().chain([0xd800]).chain("水😀".encode_utf16()) {
            data.extend(match encoding {
                SearchTextEncoding::Utf16Le => unit.to_le_bytes(),
                _ => unit.to_be_bytes(),
            });
        }
        data.push(0xff);
        let project = Project::new(snapshot(&[(0x1000, &data)]));
        let mut query = text("水\\p{Emoji}", encoding, true);
        query.offset = 1;
        query.limit = 1;
        let report = project.search(&query).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(addresses(&report), [0x100c]);
        assert_eq!(report.hits[0].size, 6);
        assert_eq!(report.hits[0].image_offset, Some(12));
        assert_eq!(report.invalid_utf16_units, 1);
        assert_eq!(report.utf16_trailing_bytes, 1);
        assert!(report.total_is_exact);
    }
}

#[test]
fn utf16_regex_never_replaces_or_bridges_invalid_surrogates() {
    let project = Project::new(snapshot(&[(0x1000, &[0x61, 0, 0x00, 0xdc, 0x62, 0])]));
    for pattern in ["a.*b", "�"] {
        let report = project.search(&text(pattern, SearchTextEncoding::Utf16Le, true)).unwrap();
        assert_eq!(report.total, 0);
        assert_eq!(report.invalid_utf16_units, 1);
    }
    let report = project.search(&text("^b$", SearchTextEncoding::Utf16Le, true)).unwrap();
    assert_eq!(addresses(&report), [0x1004]);
}

#[test]
fn utf16_regex_bounds_do_not_search_artificial_partial_runs() {
    let bytes: Vec<u8> = "a".repeat(MAX_SEARCH_TEXT_RUN_BYTES + 1).encode_utf16().flat_map(u16::to_le_bytes).collect();
    let project = Project::new(snapshot(&[(0x1000, &bytes)]));
    let report = project.search(&text("a$", SearchTextEncoding::Utf16Le, true)).unwrap();
    assert_eq!(report.total, 0);
    assert_eq!(report.stop_reason, SearchStopReason::TextRunBudget);
    assert!(!report.total_is_exact);
}

fn native_project() -> Project {
    Project::new(
        Binary::from_snapshot_bytes(
            serde_json::to_vec(&json!({
                "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": "Owned native search adapter fixture",
                "entry": "0x1000", "seeds": ["0x1000", "0x2000"],
                "regions": [
                    {"name": "first", "address": "0x1000", "permissions": "r-x", "bytes": "b82a000000488d05f41f0000c3"},
                    {"name": "second", "address": "0x2000", "permissions": "r-x", "bytes": "b8ffffffffc3"},
                    {"name": "source", "address": "0x3000", "permissions": "r--", "bytes": "346c3dd800de0000"}
                ]
            }))
            .unwrap(),
        )
        .unwrap(),
    )
}

fn semantic(value: SearchValue) -> SearchImmediate {
    SearchImmediate { value, width_bits: None, include_addresses: false, include_displacements: false }
}

#[test]
fn unified_native_search_preserves_signed_width_operand_and_instruction_evidence() {
    let project = native_project();
    let mut immediate = semantic(SearchValue::Signed(-1));
    immediate.width_bits = Some(32);
    let mut query = SearchQuery::new(SearchMode::Immediate { immediate });
    query.include_context = true;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x2000]);
    let hit = &report.hits[0];
    assert_eq!(hit.function.as_ref().unwrap().address, 0x2000);
    let code = hit.code.as_ref().unwrap();
    assert_eq!(code.native.operand.as_ref().unwrap().signed_value, Some(-1));
    assert_eq!(code.native.operand.as_ref().unwrap().width_bits, Some(32));
    assert!(!code.text.is_empty());
    assert!(report.scanned_bytes > 0);
    let report = project
        .search(&SearchQuery::new(SearchMode::Instruction { mnemonic: None, operands: Some("eax, *".into()) }))
        .unwrap();
    assert_eq!(addresses(&report), [0x1000, 0x2000]);
    assert!(project.search(&SearchQuery::new(SearchMode::Instruction { mnemonic: None, operands: None })).is_err());
}

#[test]
fn unified_function_references_preserve_string_constant_and_address_selectors() {
    let project = native_project();
    for reference in [
        SearchReference::Address { target: 0x3000 },
        SearchReference::String { text: "水😀".into(), encoding: SearchStringEncoding::Utf16Le },
        SearchReference::Constant { immediate: semantic(SearchValue::Unsigned(42)) },
    ] {
        let report = project.search(&SearchQuery::new(SearchMode::FunctionsReferencing { reference })).unwrap();
        assert_eq!(addresses(&report), [0x1000], "{report:?}");
        assert_eq!(
            report.hits[0].code.as_ref().unwrap().site,
            if report.hits[0].code.as_ref().unwrap().native.kind == "immediate" { 0x1000 } else { 0x1005 }
        );
    }
    let report = project.search(&SearchQuery::new(SearchMode::References { target: 0x3000 })).unwrap();
    assert_eq!(addresses(&report), [0x1005]);
    assert_eq!(report.hits[0].target, Some(0x3000));
    assert_eq!(report.hits[0].reference_kinds, [rampage_analysis::discover::XrefKind::Data]);
    assert_eq!(report.scanned_instructions, 0);
    assert_eq!(project.search(&SearchQuery::new(SearchMode::References { target: 42 })).unwrap().total, 0);
}

#[test]
fn unified_native_cancellation_and_byte_budgets_are_real() {
    let project = native_project();
    let mut query = SearchQuery::new(SearchMode::Instruction { mnemonic: Some("mov".into()), operands: None });
    let cancel = AtomicBool::new(true);
    let report = project.search_controlled(&query, &SearchControl { cancel: Some(&cancel) }).unwrap();
    assert!(report.cancelled && !report.total_is_exact);
    assert!(!project.analysis_cache_status().program);
    query.budget.scan_bytes = 5;
    let report = project.search(&query).unwrap();
    assert!(report.hits.is_empty());
    assert_eq!(report.scanned_bytes, 0);
    assert_eq!(report.scanned_instructions, 0);
    assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
    assert!(!report.total_is_exact);
    // The first x86 decoder input window covers all 13 bytes of the fixture's first block.
    query.budget.scan_bytes = 13;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [0x1000]);
    assert_eq!(report.scanned_bytes, 13);
    assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
    assert!(!report.total_is_exact);
}

#[test]
fn unified_import_selector_keeps_exact_library_identity_and_reference_evidence() {
    let mut binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64", "provenance": "Owned import adapter fixture",
            "entry": "0x1000", "seeds": ["0x1000"],
            "regions": [
                {"name": "caller", "address": "0x1000", "permissions": "r-x", "bytes": "ff15fa1f0000c3"},
                {"name": "slot", "address": "0x3000", "permissions": "rw-", "bytes": "0000000000000000"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    binary.imports.push(rampage_loaders::Import { name: "puts".into(), library: Some("libA".into()) });
    binary.import_slots.push(rampage_loaders::ImportSlot {
        address: 0x3000,
        name: "puts".into(),
        library: Some("libA".into()),
    });
    let project = Project::new(binary);
    let report = project
        .search(&SearchQuery::new(SearchMode::FunctionsReferencing {
            reference: SearchReference::Import { name: "puts".into(), library: Some("libA".into()) },
        }))
        .unwrap();
    assert_eq!(addresses(&report), [0x1000]);
    assert_eq!(report.hits[0].code.as_ref().unwrap().native.kind, "import_xref");
    assert_eq!(report.hits[0].code.as_ref().unwrap().native.target, Some(0x3000));
    let report = project
        .search(&SearchQuery::new(SearchMode::FunctionsReferencing {
            reference: SearchReference::Import { name: "puts".into(), library: Some("libB".into()) },
        }))
        .unwrap();
    assert_eq!(report.total, 0);
    assert!(!report.total_is_exact);
}

#[test]
fn public_json_contract_preserves_full_width_values_and_rejects_unknown_fields() {
    let query: SearchQuery = serde_json::from_value(json!({
        "mode": {"kind": "immediate", "immediate": {
            "value": {"kind": "unsigned", "value": u64::MAX}, "width_bits": 64,
            "include_addresses": true
        }}, "include_context": true
    }))
    .unwrap();
    let SearchMode::Immediate { immediate } = &query.mode else { panic!("wrong mode") };
    assert!(matches!(immediate.value, SearchValue::Unsigned(u64::MAX)));
    assert!(!immediate.include_displacements);
    assert!(immediate.include_addresses);
    assert_eq!(serde_json::to_value(&query).unwrap()["mode"]["immediate"]["value"]["value"], json!(u64::MAX));
    assert!(
        serde_json::from_value::<SearchQuery>(json!({
            "mode": {"kind": "references", "target": 42, "name": "not content"}
        }))
        .is_err()
    );
}

#[test]
fn native_names_are_utf8_safely_bounded_in_shared_and_direct_reports() {
    let mut project = native_project();
    project.binary.symbols.push(rampage_loaders::Symbol {
        name: "水".repeat(300),
        address: 0x1000,
        size: 13,
        kind: rampage_loaders::SymbolKind::Function,
    });
    let project = Project::new(project.binary);
    let mut query = SearchQuery::new(SearchMode::Immediate { immediate: semantic(SearchValue::Unsigned(42)) });
    query.include_context = true;
    let report = project.search(&query).unwrap();
    let context = report.hits[0].function.as_ref().unwrap();
    assert_eq!(context.name.len(), 510);
    assert!(context.name_truncated);
    let direct = project
        .search_code(&crate::search_code::CodeSearchQuery::new(native_kind(&query.mode).unwrap()).unwrap())
        .unwrap();
    assert_eq!(direct.hits[0].function_name.len(), 510);
    assert!(direct.hits[0].function_name_truncated);
}

#[test]
fn regex_scan_budget_does_not_manufacture_an_end_anchor_hit() {
    let project = Project::new(snapshot(&[(0x1000, b"ab")]));
    let mut query = text("a$", SearchTextEncoding::Ascii, true);
    query.budget.scan_bytes = 1;
    let report = project.search(&query).unwrap();
    assert_eq!(report.total, 0);
    assert!(!report.total_is_exact);
    assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
}

#[test]
fn malformed_mapping_arithmetic_and_out_of_image_backing_are_refused() {
    let mut binary = snapshot(&[(0x1000, b"abc")]);
    binary.segments.push(Segment {
        name: "invalid".into(),
        address: u64::MAX,
        size: 2,
        file_offset: 0,
        file_size: 1,
        perms: Perms { read: true, write: false, execute: false },
    });
    assert!(Project::new(binary).search(&bytes("61")).is_err());
    let mut binary = snapshot(&[(0x1000, b"abc")]);
    binary.segments[0].file_offset = 3;
    assert!(Project::new(binary).search(&bytes("61")).is_err());
}

#[test]
fn owned_repository_elf_byte_results_use_real_offsets_and_opt_in_native_context() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let project = Project::new(Binary::open(&path).unwrap());
    let main = project.resolve("main").unwrap();
    let data = project.binary.read(main, 1).unwrap();
    let mut query = bytes(&format!("{:02x}", data[0]));
    query.range = Some(SearchRange { start: main, end: main + 1 });
    query.include_context = true;
    let report = project.search(&query).unwrap();
    assert_eq!(addresses(&report), [main]);
    let context = report.hits[0].function.as_ref().unwrap();
    assert_eq!(context.address, main);
    assert_eq!(context.name, "main");
    assert_eq!(context.symbol_source, SearchSymbolSource::LoaderName);
    assert!(report.source.backing_path.is_some());
    assert!(report.source.mapped_source_checked);
    assert!(report.hits[0].file_offset.is_some());
}
