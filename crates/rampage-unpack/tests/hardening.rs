//! Regressions from the security review of the first slice: deep SquashFS trees on a small stack, OTA extents
//! that overlap or outgrow the budget, synthesised bytes against the ratio limit, and corrupt files skipped alone.

use std::io::Cursor;

use backhand::{FilesystemWriter, NodeHeader};
use rampage_unpack::{At, Limits, extract, list};

use crate::support::{Scratch, fixture};

/// The tokio `spawn_blocking` default: MCP tool calls run on threads this small.
const SMALL_STACK: usize = 2 << 20;

/// A SquashFS image with `depth` directories nested one in another, written on a thread with room for backhand's
/// recursive writer.
fn nested_squashfs(depth: usize) -> Vec<u8> {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            let mut writer = FilesystemWriter::default();
            writer.set_time(0);
            let uncompressed = backhand::v4::compressor::Compressor::Uncompressed;
            writer.set_compressor(backhand::FilesystemCompressor::new(uncompressed, None).unwrap());
            let mut path = String::new();
            for _ in 0..depth {
                path.push_str("/a");
                writer.push_dir(&path, NodeHeader::new(0o755, 0, 0, 0)).unwrap();
            }
            let mut out = Cursor::new(Vec::new());
            writer.write(&mut out).unwrap();
            out.into_inner()
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Lists `path` on a thread with the small stack MCP calls get.
fn list_on_small_stack(path: std::path::PathBuf) -> Result<usize, String> {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            list(&path, At::default(), &[], Limits::default()).map(|l| l.entries.len()).map_err(|e| e.to_string())
        })
        .unwrap()
        .join()
        .expect("listing must not overflow the stack")
}

#[test]
fn a_deep_squashfs_tree_is_refused_without_overflowing_a_small_stack() {
    // 8,000 nested directories: backhand's own tree building overflows a 2 MiB stack on it (process abort). The
    // image is committed because the writer takes about 40 minutes to make it (see build-fsimages.sh).
    let error = list_on_small_stack(fixture("deep-8000.sqfs")).unwrap_err();
    assert!(error.contains("nested deeper than 128"), "{error}");
    let scratch = Scratch::new("deep");
    // The deepest tree the limit allows still lists on the same stack.
    let allowed = scratch.join("allowed.sqfs");
    std::fs::write(&allowed, nested_squashfs(128)).unwrap();
    assert_eq!(list_on_small_stack(allowed).unwrap(), 128);
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn bytes_field(number: u64, value: &[u8]) -> Vec<u8> {
    [varint(number << 3 | 2), varint(value.len() as u64), value.to_vec()].concat()
}

fn int_field(number: u64, value: u64) -> Vec<u8> {
    [varint(number << 3), varint(value)].concat()
}

/// A full payload with one partition of `size` bytes written by ZERO operations over `extents` (start, blocks).
fn zero_payload(size: u64, extents: &[(u64, u64)]) -> Vec<u8> {
    let mut partition = [bytes_field(1, b"zeros"), bytes_field(7, &int_field(1, size))].concat();
    for &(start, count) in extents {
        let extent = [int_field(1, start), int_field(2, count)].concat();
        partition.extend(bytes_field(8, &[int_field(1, 6), bytes_field(6, &extent)].concat()));
    }
    let manifest = [int_field(3, 4096), bytes_field(13, &partition)].concat();
    let mut out = b"CrAU".to_vec();
    out.extend(2u64.to_be_bytes());
    out.extend((manifest.len() as u64).to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend(manifest);
    out
}

#[test]
fn ota_zero_extents_never_overlap_and_are_charged() {
    let scratch = Scratch::new("ota-zero");
    let write = |name: &str, bytes: Vec<u8>| {
        let path = scratch.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    // The same blocks zeroed again and again: rejected before anything is written.
    let overlapping = write("overlap.bin", zero_payload(1 << 20, &[(0, 256); 64]));
    let error = extract(&overlapping, At::default(), &[], &scratch.join("a"), &[], Limits::default()).unwrap_err();
    assert!(error.to_string().contains("overlapping"), "{error}");
    // More operations than the partition has blocks: rejected while the manifest is read.
    let crowded = write("crowded.bin", zero_payload(8192, &[(0, 1), (1, 1), (0, 1)]));
    let error = list(&crowded, At::default(), &[], Limits::default()).unwrap_err();
    assert!(error.to_string().contains("more operations than the partition has blocks"), "{error}");
    // The rebuild counts against max_bytes even though nothing reaches the output yet.
    let large = write("large.bin", zero_payload(8 << 20, &[(0, 2048)]));
    let small = Limits { max_total_bytes: 1 << 20, ..Limits::default() };
    let error = extract(&large, At::default(), &[], &scratch.join("b"), &[], small).unwrap_err();
    assert!(error.to_string().contains("max_bytes"), "{error}");
    // 200 MiB of zeros from a few bytes of manifest is a bomb.
    let zeros = write("zeros.bin", zero_payload(200 << 20, &[(0, 51_200)]));
    let error = extract(&zeros, At::default(), &[], &scratch.join("c"), &[], Limits::default()).unwrap_err();
    assert!(error.to_string().contains("decompression bomb"), "{error}");
    extract(&large, At::default(), &[], &scratch.join("d"), &[], Limits::default()).unwrap();
    assert_eq!(std::fs::read(scratch.join("d/zeros.img")).unwrap(), vec![0u8; 8 << 20]);
}

/// An Android sparse image of one chunk of `kind` covering `blocks` 4 KiB blocks: 28 + 12 (+ 4) bytes.
fn sparse_bomb(kind: u16, blocks: u32) -> Vec<u8> {
    let body: &[u8] = if kind == 0xcac2 { b"ABCD" } else { b"" };
    let mut out = 0xed26_ff3au32.to_le_bytes().to_vec();
    for half in [1u16, 0, 28, 12] {
        out.extend(half.to_le_bytes());
    }
    for word in [4096u32, blocks, 1, 0] {
        out.extend(word.to_le_bytes());
    }
    out.extend(kind.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(blocks.to_le_bytes());
    out.extend((12 + body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

#[test]
fn synthesised_bytes_count_against_the_ratio_limit() {
    let scratch = Scratch::new("synthesised");
    for (name, kind) in [("dontcare.simg", 0xcac3u16), ("fill.simg", 0xcac2)] {
        let path = scratch.join(name);
        let bomb = sparse_bomb(kind, 51_200);
        assert!(bomb.len() <= 44);
        std::fs::write(&path, bomb).unwrap();
        let error = extract(&path, At::default(), &[], &scratch.join(&format!("{name}.out")), &[], Limits::default());
        let error = error.unwrap_err().to_string();
        assert!(error.contains("decompression bomb"), "{name}: {error}");
    }
    // A 200 MiB hole in ext4, a 200 MiB file of sparse SquashFS blocks, and 200 MiB of one byte through the xz
    // codec backhand calls.
    for name in ["holes.ext4", "holes.sqfs", "repeat-xz.sqfs"] {
        let out = scratch.join(&format!("{name}.out"));
        let error = extract(&fixture(name), At::default(), &[], &out, &[], Limits::default()).unwrap_err().to_string();
        assert!(error.contains("decompression bomb"), "{name}: {error}");
        let generous = Limits { max_ratio: 100_000, ..Limits::default() };
        let report = extract(&fixture(name), At::default(), &[], &scratch.join(&format!("{name}.ok")), &[], generous);
        assert_eq!(report.unwrap().report.bytes, 200 << 20, "{name}");
    }
}

#[test]
fn a_corrupt_file_is_skipped_without_stopping_the_extraction() {
    // The last byte of payload.bin belongs to the vendor partition's REPLACE data: its hash no longer matches.
    let scratch = Scratch::new("corrupt");
    let mut payload = std::fs::read(fixture("payload.bin")).unwrap();
    *payload.last_mut().unwrap() ^= 0xff;
    let path = scratch.join("payload.bin");
    std::fs::write(&path, payload).unwrap();
    let out = scratch.join("out");
    let report = extract(&path, At::default(), &[], &out, &[], Limits::default()).unwrap().report;
    assert_eq!(std::fs::read(out.join("system.img")).unwrap(), std::fs::read(fixture("ext4.img")).unwrap());
    assert!(!out.join("vendor.img").exists(), "the partial file is removed");
    let skip = report.skipped.iter().find(|skip| skip.path == "vendor.img").unwrap();
    assert!(skip.reason.contains("SHA-256"), "{}", skip.reason);
    assert_eq!(report.files, 1);
}
