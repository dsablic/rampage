use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

struct Fixture(PathBuf);

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-decode-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = std::fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700).create(&path).unwrap();
        std::fs::write(path.join("input.bin"), bytes).unwrap();
        Self(path)
    }

    fn input(&self) -> PathBuf {
        self.0.join("input.bin")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn request(length: usize, expected_output_size: usize) -> DecodeFileRequest {
    DecodeFileRequest {
        codec: ContentCodec::Lzss4k,
        lzss: None,
        offset: 0,
        length,
        expected_output_size,
        initial_write_offset: 4078,
        dictionary_fill: 0,
        timeout_ms: 3000,
        preview_offset: 0,
        preview_size: 256,
    }
}

#[test]
fn explicit_decode_preserves_ranges_hashes_and_transient_content_without_publication() {
    let fixture = Fixture::new(&[0xcc, 0xcc, 0xcc, 7, b'A', b'B', b'C', 0xdd]);
    let mut query = request(4, 3);
    query.offset = 3;
    query.preview_offset = 1;
    query.preview_size = 2;
    let decoded = decode_file_range(&fixture.input(), &query).unwrap();
    assert_eq!(decoded.bytes(), b"ABC");
    assert_eq!(decoded.receipt.source_offset, 3);
    assert_eq!(decoded.receipt.source_length, 4);
    assert_eq!(decoded.receipt.source_size, 8);
    assert_eq!(decoded.receipt.output_sha256, "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78");
    assert_eq!(decoded.receipt.source_byte_sum32, 205);
    assert!(decoded.receipt.input_fully_consumed);
    assert_eq!(decoded.receipt.preview.coordinate_space, "decoded_byte_offset");
    assert_eq!(decoded.receipt.preview.ascii, "BC");
    assert_eq!(decoded.receipt.preview.hex, "4243");
    assert!(decoded.receipt.preview.next_offset.is_none());
    assert!(serde_json::to_vec(&decoded.receipt).unwrap().len() <= MAX_DECODE_RECEIPT_BYTES);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    assert_eq!(std::fs::read(fixture.input()).unwrap(), [0xcc, 0xcc, 0xcc, 7, b'A', b'B', b'C', 0xdd]);
}

#[test]
fn expected_size_is_not_reported_as_a_stream_boundary_or_complete_input_consumption() {
    let fixture = Fixture::new(&[1, b'Z', 0xaa]);
    let mut query = request(3, 1);
    query.preview_size = 0;
    let decoded = decode_file_range(&fixture.input(), &query).unwrap();
    assert_eq!(decoded.receipt.completion, "expected_output_size_reached");
    assert_eq!(decoded.receipt.input_consumed, 2);
    assert_eq!(decoded.receipt.trailing_input_bytes, 1);
    assert!(!decoded.receipt.input_fully_consumed);
    assert_eq!(decoded.receipt.preview.size, 0);
    assert!(decoded.receipt.preview.next_offset.is_none());
}

#[test]
fn parameters_and_ranges_refuse_before_open_and_malformed_tokens_are_not_truncated() {
    let missing = Path::new("/nonexistent/rampage-decode-input");
    let mut queries = Vec::new();
    for (length, output) in [(0, 1), (MAX_DECODE_INPUT_BYTES + 1, 1), (1, MAX_DECODE_OUTPUT_BYTES + 1), (1, 129)] {
        queries.push(request(length, output));
    }
    let mut query = request(2, 1);
    query.offset = u64::MAX;
    queries.push(query);
    let mut query = request(2, 1);
    query.initial_write_offset = 4096;
    queries.push(query);
    let mut query = request(2, 1);
    query.preview_offset = 2;
    queries.push(query);
    let mut query = request(2, 1);
    query.timeout_ms = 0;
    queries.push(query);
    for query in queries {
        let error = decode_file_range(missing, &query).unwrap_err();
        assert!(matches!(error, ApiError::Invalid(_)), "{error}");
    }
    for (bytes, expected, message) in [(&[1][..], 1, "truncated"), (&[0, 0, 0][..], 2, "token exceeds")] {
        let fixture = Fixture::new(bytes);
        let error = decode_file_range(&fixture.input(), &request(bytes.len(), expected)).unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn special_files_symlinks_and_out_of_file_ranges_are_refused_without_blocking() {
    let fixture = Fixture::new(&[1, b'Z']);
    assert!(decode_file_range(Path::new("/dev/zero"), &request(2, 1)).is_err());
    assert!(decode_file_range(&fixture.0, &request(2, 1)).is_err());
    assert!(decode_file_range(&fixture.input(), &request(3, 1)).is_err());
    let link = fixture.0.join("link.bin");
    std::os::unix::fs::symlink(fixture.input(), &link).unwrap();
    assert!(decode_file_range(&link, &request(2, 1)).is_err());
    let fifo = fixture.0.join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    assert!(decode_file_range(&fifo, &request(2, 1)).is_err());
}

#[test]
fn retained_source_refuses_mutation_and_same_byte_path_replacement() {
    let fixture = Fixture::new(&[1, b'Z']);
    let source = source::RangeSource::open(&fixture.input(), 0, 2).unwrap();
    std::fs::rename(fixture.input(), fixture.0.join("original.bin")).unwrap();
    std::fs::write(fixture.input(), [1, b'Z']).unwrap();
    assert!(source.revalidate().is_err());
    let source = source::RangeSource::open(&fixture.input(), 0, 2).unwrap();
    std::fs::write(fixture.input(), [1, b'X']).unwrap();
    assert!(source.revalidate().is_err());
}
