//! Test-side image generators for what no local tool makes: SquashFS with legacy LZMA compression (Homebrew's
//! mksquashfs is built without it), written by backhand's writer with an LZMA-alone encoder plugged in.

use std::io::{Cursor, Write};

use backhand::kind::Kind;
use backhand::traits::CompressionAction;
use backhand::v4::compressor::Compressor;
use backhand::{BackhandError, FilesystemCompressor, FilesystemWriter, NodeHeader, SuperBlock};

struct LzmaAlone;

static LZMA_ALONE: LzmaAlone = LzmaAlone;

impl CompressionAction for LzmaAlone {
    type Error = BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    fn decompress(&self, _: &[u8], _: &mut Vec<u8>, _: Compressor) -> Result<(), BackhandError> {
        Err(BackhandError::CorruptedOrInvalidSquashfs)
    }

    fn compress(&self, bytes: &[u8], _: FilesystemCompressor, _: u32) -> Result<Vec<u8>, BackhandError> {
        let options = lzma_rust2::LzmaOptions::with_preset(6);
        let mut writer = lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, Some(bytes.len() as u64))
            .map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)?;
        writer.write_all(bytes)?;
        writer.finish().map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)
    }
}

/// Twenty 4 KiB blocks of varied text, so the image has full data blocks.
pub fn blocks() -> Vec<u8> {
    (0..2000)
        .flat_map(|i: u32| format!("{:08x} block text {}\n", i.wrapping_mul(2_654_435_761), i % 7).into_bytes())
        .collect()
}

/// A SquashFS 4.0 image compressed with legacy LZMA: etc/hostname and data/blocks.bin.
pub fn squashfs_lzma() -> Vec<u8> {
    let mut writer = FilesystemWriter::default();
    writer.set_kind(Kind::new_v4(&LZMA_ALONE));
    writer.set_compressor(FilesystemCompressor::new(Compressor::Lzma, None).unwrap());
    writer.set_block_size(4096);
    writer.set_time(0);
    let header = NodeHeader::new(0o755, 0, 0, 0);
    writer.push_dir("etc", header).unwrap();
    writer.push_dir("data", header).unwrap();
    writer.push_file(Cursor::new(b"demo-device\n".to_vec()), "etc/hostname", NodeHeader::new(0o644, 0, 0, 0)).unwrap();
    writer.push_file(Cursor::new(blocks()), "data/blocks.bin", NodeHeader::new(0o644, 0, 0, 0)).unwrap();
    let mut out = Cursor::new(Vec::new());
    writer.write(&mut out).unwrap();
    out.into_inner()
}
