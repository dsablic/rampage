//! Bounded decompression with pure-Rust codecs. Every call stops at an output limit and feeds the ratio meter.

use std::io::Read;

use crate::error::{Result, UnpackError};
use crate::limits::account;

/// Memory an LZMA or XZ dictionary may take: hostile headers can declare gigabytes.
const LZMA_MEMORY_KIB: u32 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// zlib (SquashFS calls it gzip).
    Zlib,
    Xz,
    /// The legacy `.lzma` ("LZMA alone") format with its 13-byte header.
    LzmaAlone,
    /// An LZ4 block without frame.
    Lz4Block,
    Zstd,
    /// LZO1X.
    Lzo,
    Bzip2,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Zlib => "zlib",
            Codec::Xz => "xz",
            Codec::LzmaAlone => "lzma",
            Codec::Lz4Block => "lz4",
            Codec::Zstd => "zstd",
            Codec::Lzo => "lzo",
            Codec::Bzip2 => "bzip2",
        }
    }
}

fn corrupt(codec: Codec, error: impl std::fmt::Display) -> UnpackError {
    UnpackError::Invalid(format!("corrupt {} data: {error}", codec.name()))
}

/// A streaming decoder for `codec` over `input`; block-only codecs have none.
fn stream<'a>(codec: Codec, input: Box<dyn Read + 'a>) -> Result<Box<dyn Read + 'a>> {
    Ok(match codec {
        Codec::Zlib => Box::new(flate2::read::ZlibDecoder::new(input)),
        Codec::Xz => Box::new(lzma_rust2::XzReader::new_mem_limit(input, true, LZMA_MEMORY_KIB)),
        Codec::LzmaAlone => Box::new(
            lzma_rust2::LzmaReader::new_mem_limit(input, LZMA_MEMORY_KIB, None).map_err(|e| corrupt(codec, e))?,
        ),
        Codec::Zstd => Box::new(ruzstd::decoding::StreamingDecoder::new(input).map_err(|e| corrupt(codec, e))?),
        Codec::Bzip2 => Box::new(bzip2_rs::DecoderReader::new(input)),
        Codec::Lz4Block | Codec::Lzo => {
            return Err(UnpackError::Unsupported(format!("{} has no stream form", codec.name())));
        }
    })
}

/// Decompresses `input` whole, refusing more than `limit` bytes of output.
pub fn decompress(codec: Codec, input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let out = match codec {
        Codec::Lz4Block => {
            let mut out = vec![0; limit];
            let len = lz4_flex::block::decompress_into(input, &mut out).map_err(|e| corrupt(codec, e))?;
            out.truncate(len);
            out
        }
        Codec::Lzo => lzo::decompress(input, limit).map_err(|e| corrupt(codec, format!("{e:?}")))?,
        _ => {
            let mut out = Vec::new();
            decompress_stream(codec, input, input.len() as u64, limit as u64, &mut |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            })?;
            return Ok(out);
        }
    };
    account(input.len() as u64, out.len() as u64)?;
    Ok(out)
}

/// Decompresses `input_len` bytes read from `input`, passing the output to `sink` in chunks and refusing more than
/// `limit` bytes of it.
pub fn decompress_stream(
    codec: Codec,
    input: impl Read,
    input_len: u64,
    limit: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    account(input_len, 0)?;
    let mut reader = stream(codec, Box::new(input))?;
    let mut buffer = vec![0; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(corrupt(codec, error)),
        };
        total = total.saturating_add(read as u64);
        if total > limit {
            return Err(UnpackError::Invalid(format!(
                "{} data decompresses past its expected size of {limit} bytes",
                codec.name()
            )));
        }
        account(0, read as u64)?;
        sink(&buffer[..read])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_an_error_for_every_codec() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for codec in [Codec::Zlib, Codec::Xz, Codec::LzmaAlone, Codec::Lz4Block, Codec::Zstd, Codec::Lzo, Codec::Bzip2]
        {
            for len in [0usize, 1, 13, 64, 4096] {
                let input: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect();
                // Any outcome but a panic or an oversized result is acceptable.
                if let Ok(out) = decompress(codec, &input, 8192) {
                    assert!(out.len() <= 8192);
                }
            }
        }
    }

    #[test]
    fn output_past_the_limit_is_refused() {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut encoder, &[0u8; 100_000]).unwrap();
        let packed = encoder.finish().unwrap();
        assert_eq!(decompress(Codec::Zlib, &packed, 100_000).unwrap().len(), 100_000);
        assert!(decompress(Codec::Zlib, &packed, 99_999).is_err());
    }
}
