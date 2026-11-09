use super::*;

fn parameters(request: FileLayoutRequest) -> LayoutParameters {
    LayoutParameters::from_request(&request).unwrap()
}

fn defaults() -> LayoutParameters {
    parameters(FileLayoutRequest::default())
}

/// Deterministic high-entropy bytes (xorshift64*).
fn noise(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Bytes with no run of one byte longer than one and no printable runs.
fn varied(length: usize) -> Vec<u8> {
    (0..length).map(|index| 0x80 + (index % 64) as u8).collect()
}

fn kinds(report: &FileLayoutReport) -> Vec<(u64, u64, RegionKind)> {
    report.regions.iter().map(|region| (region.offset, region.length, region.kind)).collect()
}

#[test]
fn fill_runs_at_both_edges_bracket_one_hashed_occupied_region() {
    let mut bytes = vec![0xff; 100];
    bytes.extend(varied(50));
    bytes.extend([0; 100]);
    let report = layout(&bytes, 0x1000, 0x2000, true, &defaults());

    assert_eq!(
        kinds(&report),
        [(0x1000, 100, RegionKind::FillFf), (0x1064, 50, RegionKind::Occupied), (0x1096, 100, RegionKind::FillZero)]
    );
    assert_eq!(report.regions[0].fill_byte.as_deref(), Some("0xff"));
    assert_eq!(report.regions[2].fill_byte.as_deref(), Some("0x00"));
    let occupied = &report.regions[1];
    assert_eq!(occupied.sha256.as_deref(), Some(rampage_arch::hex::bytes(&Sha256::digest(&bytes[100..150])).as_str()));
    assert!(report.regions[0].sha256.is_none());
    assert_eq!(report.sha256, rampage_arch::hex::bytes(&Sha256::digest(&bytes)));
    let summary = &report.summary;
    assert_eq!((summary.fill_ff_bytes, summary.fill_zero_bytes, summary.occupied_bytes), (100, 100, 50));
    assert_eq!((summary.fill_regions, summary.occupied_regions), (2, 1));
    assert!(report.continuation.is_none());
}

#[test]
fn runs_shorter_than_the_minimum_stay_occupied_and_other_bytes_are_fill_other() {
    let mut bytes = varied(10);
    bytes.extend([0xaa; 63]);
    bytes.extend(varied(10));
    bytes.extend([0xaa; 64]);
    let report = layout(&bytes, 0, bytes.len() as u64, true, &defaults());

    assert_eq!(kinds(&report), [(0, 83, RegionKind::Occupied), (83, 64, RegionKind::FillOther)]);
    assert_eq!(report.regions[1].fill_byte.as_deref(), Some("0xaa"));
    assert_eq!(report.summary.fill_other_bytes, 64);
}

#[test]
fn a_single_byte_is_one_occupied_region_and_an_unclassified_block() {
    let report = layout(&[0x41], 7, 8, true, &defaults());

    assert_eq!(kinds(&report), [(7, 1, RegionKind::Occupied)]);
    assert_eq!(report.entropy.blocks, [0.0]);
    assert_eq!(report.entropy.last_block_bytes, 1);
    assert!(report.entropy.spans.is_empty(), "a block under 256 bytes is not classified");
    assert!(report.string_clusters.is_empty() && report.hints.is_empty());
}

#[test]
fn a_huge_fill_run_is_one_region_and_one_low_entropy_span() {
    let bytes = vec![0xff; 10 << 20];
    let report = layout(&bytes, 0, bytes.len() as u64, true, &defaults());

    assert_eq!(kinds(&report), [(0, 10 << 20, RegionKind::FillFf)]);
    assert_eq!(report.entropy.spans.len(), 1);
    let span = &report.entropy.spans[0];
    assert_eq!((span.class, span.length, span.blocks, span.max), (EntropyClass::Low, 10 << 20, 2560, 0.0));
    assert_eq!(report.summary.low_entropy_bytes, 10 << 20);
    // 2560 blocks exceed the default 1024: the list is cut and a coarser block size suggested.
    assert_eq!((report.bounds.blocks.total, report.bounds.blocks.returned), (2560, 1024));
    assert_eq!(report.entropy.blocks.len(), 1024);
    assert_eq!(report.bounds.blocks.next_offset, Some(1024 * 4096));
    assert_eq!(report.entropy.suggested_block_size, Some(16384));
    let continuation = report.continuation.unwrap();
    assert_eq!(
        (continuation.offset, continuation.length, continuation.truncated),
        (1024 * 4096, 1536 * 4096, vec!["blocks"])
    );
}

#[test]
fn entropy_spans_flag_high_and_low_blocks_without_medium_ones() {
    let mut bytes = noise(8192, 3);
    bytes.extend((0..4096).map(|index| b"mov r0, r1; ldr r2, [r3]\n"[index % 25]));
    bytes.extend([0; 4096]);
    let report = layout(&bytes, 0, bytes.len() as u64, true, &defaults());

    let spans: Vec<_> = report.entropy.spans.iter().map(|span| (span.offset, span.length, span.class)).collect();
    assert_eq!(spans, [(0, 8192, EntropyClass::High), (12288, 4096, EntropyClass::Low)]);
    assert!(report.entropy.blocks[0] > 7.9 && report.entropy.blocks[2] < 7.2 && report.entropy.blocks[2] > 2.0);
    assert_eq!((report.summary.high_entropy_bytes, report.summary.low_entropy_bytes), (8192, 4096));
    assert!(report.entropy.whole_range > 0.0);
}

#[test]
fn region_truncation_names_the_first_omitted_region_and_a_continuation() {
    // Alternating 64-byte fill runs and 8 varied bytes: many regions.
    let mut bytes = Vec::new();
    for _ in 0..20 {
        bytes.extend([0xff; 64]);
        bytes.extend(varied(8));
    }
    let request = FileLayoutRequest { region_limit: Some(4), ..FileLayoutRequest::default() };
    let report = layout(&bytes, 0x100, 0x10000, true, &parameters(request));

    assert_eq!(report.regions.len(), 4);
    assert_eq!((report.bounds.regions.total, report.bounds.regions.returned), (40, 4));
    assert_eq!(report.bounds.regions.next_offset, Some(0x100 + 2 * 72));
    assert_eq!(report.summary.fill_regions + report.summary.occupied_regions, 40);
    let continuation = report.continuation.unwrap();
    assert_eq!(continuation.offset, 0x100 + 144);
    assert_eq!(continuation.length, bytes.len() as u64 - 144, "an explicit range continues to its own end");
    assert_eq!(continuation.truncated, ["regions"]);
}

#[test]
fn whole_file_default_continues_past_the_selection() {
    let bytes = varied(4096);
    let report = layout(&bytes, 0, MAX_LAYOUT_BYTES * 2, false, &defaults());
    let continuation = report.continuation.unwrap();
    assert_eq!(
        (continuation.offset, continuation.length, continuation.truncated),
        (4096, MAX_LAYOUT_BYTES, vec!["range"])
    );
}

#[test]
fn strings_cluster_by_gap_and_count_with_bounded_previews() {
    let mut bytes = vec![0x80; 16];
    for text in ["Firmware v1.2", "Bootloader", "Copyright (c) Example"] {
        bytes.extend(text.as_bytes());
        bytes.extend([0x80; 4]);
    }
    let long = "x".repeat(60);
    bytes.extend(long.as_bytes());
    bytes.extend([0x81, 0x82].repeat(200));
    // An isolated string 400 bytes away is not a cluster with the default minimum of three.
    bytes.extend(b"Lonely string");
    bytes.extend([0x81, 0x82].repeat(10));
    let report = layout(&bytes, 0, bytes.len() as u64, true, &defaults());

    assert_eq!(report.string_clusters.len(), 1);
    let cluster = &report.string_clusters[0];
    assert_eq!((cluster.offset, cluster.strings, cluster.encoding), (16, 4, StringEncoding::Ascii));
    assert_eq!(cluster.length, 13 + 4 + 10 + 4 + 21 + 4 + 60);
    assert_eq!(cluster.string_bytes, 13 + 10 + 21 + 60);
    let previews: Vec<&str> = cluster.previews.iter().map(|preview| preview.text.as_str()).collect();
    assert_eq!(previews, ["Firmware v1.2", "Bootloader", "Copyright (c) Example"], "three previews at most");
    assert_eq!(report.summary.strings, 5);
    assert_eq!(report.summary.string_clusters, 1);

    let request = FileLayoutRequest { cluster_min_strings: Some(1), ..FileLayoutRequest::default() };
    let report = layout(&bytes, 0, bytes.len() as u64, true, &parameters(request));
    assert_eq!(report.string_clusters.len(), 2);
    let first = &report.string_clusters[0];
    let request = FileLayoutRequest { cluster_gap: Some(0), cluster_min_strings: Some(1), ..Default::default() };
    let report = layout(&bytes, 0, bytes.len() as u64, true, &parameters(request));
    let long = report.string_clusters.iter().find(|cluster| cluster.string_bytes == 60).unwrap();
    assert_eq!((long.previews[0].length, long.previews[0].text.len(), long.previews[0].truncated), (60, 48, true));
    assert_eq!(first.strings, 4);
}

#[test]
fn utf16_clusters_only_when_requested_and_cluster_truncation_is_a_prefix() {
    let mut bytes = vec![0x90; 3];
    for text in ["Settings", "Network", "Password"] {
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend([0x90; 2]);
    }
    let report = layout(&bytes, 0, bytes.len() as u64, true, &defaults());
    assert!(report.string_clusters.is_empty());

    let request = FileLayoutRequest { utf16: Some(true), ..FileLayoutRequest::default() };
    let report = layout(&bytes, 0, bytes.len() as u64, true, &parameters(request));
    assert_eq!(report.string_clusters.len(), 1);
    let cluster = &report.string_clusters[0];
    assert_eq!((cluster.offset, cluster.encoding, cluster.strings), (3, StringEncoding::Utf16le, 3));
    assert_eq!(cluster.previews[1].text, "Network");

    let mut many = Vec::new();
    for index in 0..10 {
        many.extend([0x80; 200]);
        many.extend(format!("alpha{index} beta{index} gamma{index}").replace(' ', "\x01").as_bytes());
    }
    let request =
        FileLayoutRequest { cluster_limit: Some(3), min_string_length: Some(5), ..FileLayoutRequest::default() };
    let report = layout(&many, 0, many.len() as u64, true, &parameters(request));
    assert_eq!((report.bounds.string_clusters.total, report.bounds.string_clusters.returned), (10, 3));
    let next = report.bounds.string_clusters.next_offset.unwrap();
    assert!(report.string_clusters.iter().all(|cluster| cluster.offset < next));
    assert_eq!(next, report.string_clusters[2].offset + 19 + 200);
}

fn vector_table(sp: u32, reset: u32) -> Vec<u8> {
    let mut words = vec![sp, reset];
    words.extend([reset + 0x40, reset + 0x42, 0, 0, 0, 0, 0, 0, 0, reset + 0x44, 0, 0, reset + 0x46, reset + 0x48]);
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

#[test]
fn cortex_m_vector_table_after_zero_padding_is_a_hint_at_the_aligned_word() {
    // SP 0x20005000 starts with a zero byte, which joins the zero fill: the region starts one byte later.
    let mut bytes = vec![0; 0x100];
    bytes.extend(vector_table(0x2000_5000, 0x0800_0131));
    bytes.extend(varied(64));
    let report = layout(&bytes, 0x8000, 0x10000, true, &defaults());

    assert_eq!(report.regions[1].offset, 0x8101);
    assert_eq!(report.hints.len(), 1);
    let hint = &report.hints[0];
    assert_eq!((hint.kind, hint.offset), ("cortex_m_vector_table_candidate", 0x8100));
    assert_eq!((hint.initial_sp, hint.reset_handler), (0x2000_5000, 0x0800_0131));
    assert_eq!((hint.handler_words_checked, hint.handler_words_plausible), (14, 14));
    assert_eq!(report.hint_interpretation, "heuristic_candidates_not_mappings");

    let request = FileLayoutRequest { hints: Some(false), ..FileLayoutRequest::default() };
    assert!(layout(&bytes, 0x8000, 0x10000, true, &parameters(request)).hints.is_empty());
}

#[test]
fn implausible_vector_words_and_noise_give_no_hint() {
    for table in [
        vector_table(0x2000_5000, 0x0800_0130),
        vector_table(0x2000_5002, 0x0800_0131),
        vector_table(0x6000_0000, 0x0800_0131),
    ] {
        assert!(layout(&table, 0, table.len() as u64, true, &defaults()).hints.is_empty());
    }
    let mut table = vector_table(0x2000_5000, 0x0800_0131);
    table[8..].copy_from_slice(&noise(56, 9));
    assert!(layout(&table, 0, 64, true, &defaults()).hints.is_empty(), "handler words must mostly be plausible");
    let noise = noise(1 << 20, 5);
    assert!(layout(&noise, 0, noise.len() as u64, true, &defaults()).hints.is_empty());
}

#[test]
fn parameters_outside_their_ranges_are_refused() {
    for request in [
        FileLayoutRequest { block_size: Some(255), ..Default::default() },
        FileLayoutRequest { min_fill_run: Some(7), ..Default::default() },
        FileLayoutRequest { region_limit: Some(0), ..Default::default() },
        FileLayoutRequest { block_limit: Some(4097), ..Default::default() },
        FileLayoutRequest { min_string_length: Some(3), ..Default::default() },
    ] {
        let error = LayoutParameters::from_request(&request).unwrap_err().to_string();
        assert!(error.starts_with("file layout "), "{error}");
    }
}

struct Temporary(PathBuf);

impl Temporary {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-file-layout-{name}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn file_ranges_are_checked_and_empty_selections_refused() {
    let file = Temporary::new("ranges", &[[0xff; 128].as_slice(), &varied(64)].concat());
    let report = file_layout(&file.0, &FileLayoutRequest::default()).unwrap();
    assert_eq!((report.offset, report.length, report.source_size), (0, 192, 192));
    assert_eq!(report.file_path, file.0);
    let request = FileLayoutRequest {
        offset: Some(FileOffset(128)),
        length: Some(FileOffset(32)),
        ..FileLayoutRequest::default()
    };
    let report = file_layout(&file.0, &request).unwrap();
    assert_eq!(kinds(&report), [(128, 32, RegionKind::Occupied)]);

    let refuse = |request: FileLayoutRequest| file_layout(&file.0, &request).unwrap_err().to_string();
    assert!(refuse(FileLayoutRequest { length: Some(FileOffset(0)), ..Default::default() }).contains("non-empty"));
    assert!(refuse(FileLayoutRequest { offset: Some(FileOffset(192)), ..Default::default() }).contains("empty"));
    assert!(
        refuse(FileLayoutRequest { offset: Some(FileOffset(100)), length: Some(FileOffset(93)), ..Default::default() })
            .contains("outside")
    );
    assert!(
        refuse(FileLayoutRequest { length: Some(FileOffset(MAX_LAYOUT_BYTES + 1)), ..Default::default() })
            .contains("64 MiB")
    );
    let empty = Temporary::new("empty", &[]);
    assert!(file_layout(&empty.0, &FileLayoutRequest::default()).unwrap_err().to_string().contains("empty"));
    let directory = std::env::temp_dir();
    assert!(file_layout(&directory, &FileLayoutRequest::default()).is_err());
}

#[cfg(unix)]
#[test]
fn oversized_json_is_refused_with_the_limits_to_lower() {
    let mut bytes = Vec::new();
    for _ in 0..300 {
        bytes.extend([0xff; 8]);
        bytes.extend(b"abcdefghij".repeat(5));
    }
    bytes.extend(noise(4096 * 300, 1));
    let file = Temporary::new("budget", &bytes);
    let request = FileLayoutRequest {
        min_fill_run: Some(8),
        block_size: Some(256),
        cluster_gap: Some(0),
        cluster_min_strings: Some(1),
        region_limit: Some(256),
        block_limit: Some(4096),
        cluster_limit: Some(128),
        ..FileLayoutRequest::default()
    };
    let error = file_layout(&file.0, &request).unwrap_err().to_string();
    assert!(error.contains("60000 JSON bytes") && error.contains("region_limit"), "{error}");
}
