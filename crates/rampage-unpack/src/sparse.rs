//! Android sparse images, read as a virtual unsparsed image: nothing is materialised.

use crate::error::{Result, UnpackError, checked};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::source::{ReadAt, Source, within};

const FORMAT: &str = "android_sparse";
const MAGIC: u32 = 0xed26_ff3a;
const RAW: u16 = 0xcac1;
const FILL: u16 = 0xcac2;
const DONT_CARE: u16 = 0xcac3;
const CRC32: u16 = 0xcac4;
/// Chunks an image may declare: real images have thousands.
const MAX_CHUNKS: u32 = 4_000_000;

#[derive(Debug, Clone, Copy)]
enum Fill {
    /// Bytes at this offset of the sparse file.
    Raw(u64),
    /// A repeated little-endian 32-bit word.
    Word([u8; 4]),
    Zero,
}

#[derive(Debug, Clone, Copy)]
struct Chunk {
    /// Where the chunk starts in the unsparsed image.
    start: u64,
    len: u64,
    fill: Fill,
}

/// The unsparsed image an Android sparse image describes.
pub struct SparseView {
    source: Source,
    chunks: Vec<Chunk>,
    size: u64,
    block_size: u32,
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

impl SparseView {
    pub fn open(source: Source) -> Result<Self> {
        let mut header = [0u8; 28];
        source.read_at(0, &mut header).map_err(|_| malformed("truncated header"))?;
        if le32(&header, 0) != MAGIC {
            return Err(malformed("bad magic"));
        }
        let (major, header_size, chunk_header_size) = (le16(&header, 4), le16(&header, 8), le16(&header, 10));
        let (block_size, total_blocks, total_chunks) = (le32(&header, 12), le32(&header, 16), le32(&header, 20));
        if major != 1 {
            return Err(UnpackError::Unsupported(format!("Android sparse major version {major}")));
        }
        if header_size < 28 || chunk_header_size < 12 {
            return Err(malformed("header sizes too small"));
        }
        if block_size == 0 || !block_size.is_multiple_of(4) || block_size > (64 << 20) {
            return Err(malformed(format!("block size {block_size}")));
        }
        if total_chunks > MAX_CHUNKS {
            return Err(UnpackError::Limit(format!("{total_chunks} chunks (at most {MAX_CHUNKS})")));
        }
        let size = checked(u64::from(total_blocks).checked_mul(u64::from(block_size)), FORMAT, "image size")?;
        let mut chunks = Vec::new();
        let mut offset = u64::from(header_size);
        let mut position = 0u64;
        for index in 0..total_chunks {
            let mut chunk = [0u8; 12];
            source.read_at(offset, &mut chunk).map_err(|_| malformed(format!("chunk {index} is truncated")))?;
            let (kind, blocks, total) = (le16(&chunk, 0), le32(&chunk, 4), le32(&chunk, 8));
            let len = checked(u64::from(blocks).checked_mul(u64::from(block_size)), FORMAT, "chunk size")?;
            let body = u64::from(total)
                .checked_sub(u64::from(chunk_header_size))
                .ok_or_else(|| malformed(format!("chunk {index} is shorter than its header")))?;
            let data = checked(offset.checked_add(u64::from(chunk_header_size)), FORMAT, "chunk offset")?;
            if !within(data, body, source.size()) {
                return Err(malformed(format!("chunk {index} runs past the end of the file")));
            }
            let fill = match kind {
                RAW if body == len => Some(Fill::Raw(data)),
                FILL if body == 4 => {
                    let mut word = [0u8; 4];
                    source.read_at(data, &mut word).map_err(|_| malformed("truncated fill chunk"))?;
                    Some(Fill::Word(word))
                }
                DONT_CARE if body == 0 => Some(Fill::Zero),
                CRC32 if body == 4 => None,
                RAW | FILL | DONT_CARE | CRC32 => {
                    return Err(malformed(format!("chunk {index} has the wrong data size for its type")));
                }
                other => return Err(malformed(format!("chunk {index} has unknown type {other:#06x}"))),
            };
            if let Some(fill) = fill {
                if len > 0 {
                    chunks.push(Chunk { start: position, len, fill });
                }
                position = checked(position.checked_add(len), FORMAT, "image position")?;
                if position > size {
                    return Err(malformed("chunks cover more blocks than the header declares"));
                }
            }
            offset = checked(offset.checked_add(u64::from(total)), FORMAT, "chunk offset")?;
        }
        if position != size {
            return Err(malformed(format!("chunks cover {position} bytes, the header declares {size}")));
        }
        Ok(Self { source, chunks, size, block_size })
    }

    pub fn notes(&self) -> Vec<String> {
        vec![format!("block size {}", self.block_size), format!("{} chunks", self.chunks.len())]
    }
}

impl ReadAt for SparseView {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if !within(offset, buf.len() as u64, self.size) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read past the unsparsed image"));
        }
        let mut position = offset;
        let mut done = 0usize;
        let mut index = self.chunks.partition_point(|chunk| chunk.start + chunk.len <= position);
        while done < buf.len() {
            let chunk = self.chunks[index];
            let inside = position - chunk.start;
            let count = ((chunk.len - inside) as usize).min(buf.len() - done);
            let out = &mut buf[done..done + count];
            match chunk.fill {
                Fill::Raw(base) => self.source.read_at(base + inside, out)?,
                Fill::Zero => out.fill(0),
                Fill::Word(word) => {
                    for (at, byte) in out.iter_mut().enumerate() {
                        *byte = word[((inside as usize) + at) % 4];
                    }
                }
            }
            done += count;
            position += count as u64;
            index += 1;
        }
        Ok(())
    }
}

/// A sparse image whose content is not a filesystem rampage reads: one entry, the unsparsed image.
pub struct Unsparsed {
    source: Source,
    entries: Vec<Entry>,
}

impl Unsparsed {
    pub fn new(source: Source) -> Self {
        let entry = Entry {
            path: "unsparsed.img".to_owned(),
            kind: EntryKind::Image,
            size: source.size(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            link: None,
            note: Some("content not recognised; extract it to inspect the raw image".to_owned()),
        };
        Self { source, entries: vec![entry] }
    }
}

impl Image for Unsparsed {
    fn format(&self) -> Format {
        Format::AndroidSparse
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn read(&self, index: usize, limit: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if index != 0 {
            return Err(UnpackError::Invalid("no such entry".to_owned()));
        }
        copy_range(&*self.source, 0, self.source.size(), limit, sink)
    }
}

/// Streams `len` bytes of `source` from `offset` to `sink`, refusing more than `limit`.
pub(crate) fn copy_range(
    source: &dyn ReadAt,
    offset: u64,
    len: u64,
    limit: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if len > limit {
        return Err(UnpackError::Limit(format!("{len} bytes is more than max_file_bytes ({limit})")));
    }
    let mut buffer = vec![0; (len.min(1 << 20)) as usize];
    let mut done = 0u64;
    while done < len {
        let count = (len - done).min(buffer.len() as u64) as usize;
        let at = offset.checked_add(done).ok_or_else(|| UnpackError::Invalid("offset overflows".to_owned()))?;
        source.read_at(at, &mut buffer[..count]).map_err(|error| UnpackError::io("read the image", error))?;
        sink(&buffer[..count])?;
        done += count as u64;
    }
    Ok(())
}
