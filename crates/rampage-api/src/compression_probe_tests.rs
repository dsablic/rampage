use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decode::encode::{self, Random};
use rampage_decode::{FlagOrder, Lzss, OffsetMode, ReferenceLayout};

use super::*;
use crate::{DecodeFileRequest, decode_file_range};

struct Input(PathBuf);

impl Input {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-probe-{}-{}.bin",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn request(offset: u64, length: usize, expected: Option<usize>) -> ProbeCompressionRequest {
    ProbeCompressionRequest {
        offset: FileOffset(offset),
        length: FileOffset(length as u64),
        expected_output_size: expected.map(|size| FileOffset(size as u64)),
        candidate_limit: None,
        timeout_ms: None,
        preview_size: None,
    }
}

/// Decodes a candidate's arguments through decode_file_range, as an agent would.
fn decode(path: &Path, arguments: &DecodeArguments) -> Vec<u8> {
    let request = DecodeFileRequest {
        codec: arguments.codec,
        lzss: arguments.lzss,
        offset: arguments.offset,
        length: arguments.length as usize,
        expected_output_size: arguments.expected_output_size,
        initial_write_offset: arguments.initial_write_offset.unwrap_or(0),
        dictionary_fill: arguments.dictionary_fill.unwrap_or(0),
        timeout_ms: 10_000,
        preview_offset: 0,
        preview_size: 0,
    };
    decode_file_range(path, &request).unwrap().bytes().to_vec()
}

#[test]
fn probe_returns_decode_arguments_that_reproduce_a_non_classic_variant_from_a_file_range() {
    let original = encode::synthetic_firmware(48 << 10, 21);
    let variant = Lzss {
        window_bits: 11,
        min_match: 2,
        flag_order: FlagOrder::MsbFirst,
        literal_flag: false,
        layout: ReferenceLayout::Le16LengthLow,
        offset_mode: OffsetMode::Distance,
        initial_write_offset: 0,
        dictionary_fill: 0,
    };
    let stream = encode::lzss(&variant, &original);
    let mut file = vec![0x5a; 32];
    file.extend(&stream);
    file.extend([0xff; 7]);
    let input = Input::new(&file);
    let report = probe_compression(&input.0, &request(32, stream.len() + 7, Some(original.len()))).unwrap();
    let best = &report.candidates[0];
    assert_eq!(best.verdict, "confident", "{:#?}", report.candidates);
    assert_eq!(best.decode_check, "reproduced");
    assert_eq!(best.input_consumed, stream.len());
    assert_eq!(best.trailing_input_bytes, 7);
    assert_eq!(decode(&input.0, &best.decode_arguments), original);
    let arguments = serde_json::to_value(&best.decode_arguments).unwrap();
    assert_eq!(arguments["codec"], "lzss");
    assert_eq!(arguments["lzss"]["reference_layout"], "le16_length_low");
    assert!(report.sweep.size_fits >= 1 && report.sweep.stopped_early.is_none());
    assert!(serde_json::to_vec(&report).unwrap().len() < MAX_PROBE_RESULT_BYTES);
}

#[test]
fn probe_without_size_ranks_but_never_claims_confidence_and_random_bytes_get_no_passing_candidate() {
    let original = encode::synthetic_firmware(32 << 10, 3);
    let stream = encode::lz4_block(&original);
    let input = Input::new(&stream);
    let report = probe_compression(&input.0, &request(0, stream.len(), None)).unwrap();
    assert!(report.candidates.iter().all(|candidate| candidate.verdict != "confident"));
    let lz4 = report.candidates.iter().find(|candidate| candidate.decode_arguments.codec == ContentCodec::Lz4Block);
    assert_eq!(decode(&input.0, &lz4.unwrap().decode_arguments), original);

    let noise = Input::new(&Random(11).bytes(64 << 10));
    for expected in [None, Some(200_000)] {
        let report = probe_compression(&noise.0, &request(0, 64 << 10, expected)).unwrap();
        assert!(report.candidates.iter().all(|candidate| candidate.verdict == "weak"), "{:#?}", report.candidates);
    }
}

#[test]
fn probe_refuses_bad_requests_before_reading() {
    let missing = Path::new("/nonexistent/rampage-probe");
    for bad in [
        request(0, 0, None),
        request(0, MAX_DECODE_INPUT_BYTES + 1, None),
        request(0, 16, Some(0)),
        ProbeCompressionRequest { candidate_limit: Some(17), ..request(0, 16, None) },
        ProbeCompressionRequest { timeout_ms: Some(0), ..request(0, 16, None) },
        ProbeCompressionRequest { preview_size: Some(129), ..request(0, 16, None) },
    ] {
        let error = probe_compression(missing, &bad).unwrap_err().to_string();
        assert!(error.contains("probe"), "{error}");
    }
}
