//! SquashFS 4.0 through backhand, with rampage's pure-Rust bounded codecs plugged in as its compressor.

use std::cell::{Cell, RefCell};
use std::io::{BufReader, Read};
use std::sync::Mutex;

use backhand::kind::{BE_V4_0, Kind};
use backhand::traits::CompressionAction;
use backhand::v4::compressor::Compressor;
use backhand::{BackhandError, FilesystemReader, InnerNode};

use crate::codec::{Codec, decompress};
use crate::error::{Result, UnpackError};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::{Budget, Limits};
use crate::source::{Cursor, Source, read_prefix};

/// Largest SquashFS data block (1 MiB) and metadata block (8 KiB): no codec call may produce more.
const MAX_BLOCK: usize = 1 << 20;
const METADATA_BLOCK: usize = 8 << 10;

/// Bytes the tables backhand loads when opening an image (inodes, directories, fragments, ids) may decompress to.
/// Real tables compress a few times; a hostile image could pack gigabytes of metadata blocks below the ratio limit.
const MAX_TABLE_BYTES: u64 = 256 << 20;

thread_local! {
    /// The error behind the last failed codec call, which backhand's own error type cannot carry.
    static CODEC_ERROR: RefCell<Option<UnpackError>> = const { RefCell::new(None) };
    /// Table bytes still allowed while an image is being opened; `None` outside [`Squashfs::open`].
    static TABLE_BUDGET: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Charges `len` decompressed bytes to the table budget when an image is being opened.
fn charge_tables(len: usize) -> Result<()> {
    TABLE_BUDGET.with(|budget| match budget.get() {
        None => Ok(()),
        Some(left) => match left.checked_sub(len as u64) {
            Some(left) => {
                budget.set(Some(left));
                Ok(())
            }
            None => Err(UnpackError::Limit(format!("SquashFS tables decompress to more than {MAX_TABLE_BYTES} bytes"))),
        },
    })
}

struct PureCodecs;

static PURE_CODECS: PureCodecs = PureCodecs;

impl CompressionAction for PureCodecs {
    type Error = BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = backhand::FilesystemCompressor;
    type SuperBlock = backhand::SuperBlock;

    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        compressor: Compressor,
    ) -> std::result::Result<(), Self::Error> {
        // backhand sizes `out` for the block it expects: 8 KiB for metadata, the block size for data.
        let limit = out.capacity().clamp(METADATA_BLOCK, MAX_BLOCK);
        let codec = match compressor {
            Compressor::Uncompressed => {
                out.extend_from_slice(bytes);
                return Ok(());
            }
            Compressor::Gzip => Codec::Zlib,
            Compressor::Lzma => Codec::LzmaAlone,
            Compressor::Lzo => Codec::Lzo,
            Compressor::Xz => Codec::Xz,
            Compressor::Lz4 => Codec::Lz4Block,
            Compressor::Zstd => Codec::Zstd,
        };
        match decompress(codec, bytes, limit).and_then(|data| charge_tables(data.len()).map(|()| data)) {
            Ok(data) => {
                out.extend_from_slice(&data);
                Ok(())
            }
            Err(error) => {
                CODEC_ERROR.with(|slot| *slot.borrow_mut() = Some(error));
                Err(BackhandError::CorruptedOrInvalidSquashfs)
            }
        }
    }

    fn compress(&self, _: &[u8], _: Self::FilesystemCompressor, _: u32) -> std::result::Result<Vec<u8>, Self::Error> {
        Err(BackhandError::UnsupportedCompression("rampage reads SquashFS only".to_owned()))
    }
}

/// The codec error behind `error` when there is one, else `error` itself as a malformed image.
fn translate(error: BackhandError) -> UnpackError {
    CODEC_ERROR
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| UnpackError::malformed("squashfs", error.to_string()))
}

fn io_translate(error: std::io::Error) -> UnpackError {
    CODEC_ERROR
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| UnpackError::malformed("squashfs", format!("file data: {error}")))
}

/// Charges table decompression to [`TABLE_BUDGET`] while it lives, and clears the budget when dropped, even when
/// backhand panics.
struct TableScope;

impl TableScope {
    fn new() -> Self {
        TABLE_BUDGET.with(|budget| budget.set(Some(MAX_TABLE_BYTES)));
        Self
    }
}

impl Drop for TableScope {
    fn drop(&mut self) {
        TABLE_BUDGET.with(|budget| budget.set(None));
    }
}

/// The bytes of a directory listing in the directory table, as backhand locates them; `None` for an empty one.
fn listing<'a>(
    squashfs: &'a backhand::Squashfs<'_>,
    block_index: u64,
    file_size: u32,
    block_offset: usize,
) -> Result<Option<&'a [u8]>> {
    if file_size < 4 {
        return Ok(None);
    }
    let corrupt = || UnpackError::malformed("squashfs", "directory listing outside the directory table");
    let (offsets, bytes) = &squashfs.dir_blocks;
    let start = offsets.get(&block_index).ok_or_else(corrupt)?;
    let block = usize::try_from(*start).ok().and_then(|start| bytes.get(start..)).ok_or_else(corrupt)?;
    let len = file_size as usize - 3;
    block.get(block_offset..).and_then(|rest| rest.get(..len)).map(Some).ok_or_else(corrupt)
}

/// The inode numbers of the subdirectories a directory listing names, parsed as backhand parses it: header groups
/// of at most 257 entries, stopping at the first group that does not parse.
fn subdirectories(bytes: &[u8], big_endian: bool) -> Vec<i64> {
    let u16_at = |at: usize| {
        let pair = [bytes[at], bytes[at + 1]];
        if big_endian { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) }
    };
    let u32_at = |at: usize| {
        let word = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        if big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) }
    };
    let mut found = Vec::new();
    let mut at = 0usize;
    'groups: while bytes.len().saturating_sub(at) >= 12 {
        let (count, inode_base) = (u32_at(at), u32_at(at + 8));
        if count > 256 {
            break;
        }
        let mut cursor = at + 12;
        let mut group = Vec::new();
        for _ in 0..=count {
            if bytes.len().saturating_sub(cursor) < 8 {
                break 'groups;
            }
            let (offset, kind, name_size) = (u16_at(cursor + 2) as i16, u16_at(cursor + 4), u16_at(cursor + 6));
            let end = cursor + 8 + usize::from(name_size) + 1;
            if end > bytes.len() {
                break 'groups;
            }
            // Basic (1) and extended (8) directory entries.
            if kind == 1 || kind == 8 {
                group.push(i64::from(inode_base as i32) + i64::from(offset));
            }
            cursor = end;
        }
        found.extend(group);
        at = cursor;
    }
    found
}

/// Walks the directory tree backhand is about to build, with an explicit stack, refusing it when directories nest
/// deeper than `max_path_depth`, number more than `max_entries` or revisit a directory (as backhand would).
fn check_tree(squashfs: &backhand::Squashfs, big_endian: bool, limits: &Limits) -> Result<()> {
    use backhand::v4::inode::InodeInner;
    let location = |inode: &backhand::Inode| match &inode.inner {
        InodeInner::BasicDirectory(dir) => {
            Some((u64::from(dir.block_index), u32::from(dir.file_size), usize::from(dir.block_offset)))
        }
        InodeInner::ExtendedDirectory(dir) => {
            Some((u64::from(dir.block_index), dir.file_size, usize::from(dir.block_offset)))
        }
        _ => None,
    };
    let mut visited = std::collections::HashSet::new();
    let mut pending = vec![(squashfs.root_inode.clone(), 0usize)];
    while let Some((inode, depth)) = pending.pop() {
        let Some((block_index, file_size, block_offset)) = location(&inode) else { continue };
        if !visited.insert(inode.header.inode_number) {
            return Err(UnpackError::malformed("squashfs", "a directory is reached twice (a directory cycle)"));
        }
        if visited.len() > limits.max_entries {
            return Err(UnpackError::Limit(format!("more than {} directories", limits.max_entries)));
        }
        let Some(bytes) = listing(squashfs, block_index, file_size, block_offset)? else { continue };
        for number in subdirectories(bytes, big_endian) {
            let child = u32::try_from(number).ok().and_then(|number| squashfs.inodes.get(&number));
            let child = child.ok_or_else(|| UnpackError::malformed("squashfs", "directory entry names no inode"))?;
            if location(child).is_some() {
                if depth + 1 > limits.max_path_depth {
                    return Err(UnpackError::Limit(format!(
                        "directories nested deeper than {} levels",
                        limits.max_path_depth
                    )));
                }
                pending.push((child.clone(), depth + 1));
            }
        }
    }
    Ok(())
}

pub struct Squashfs {
    reader: Mutex<FilesystemReader<'static>>,
    entries: Vec<Entry>,
    /// The index in backhand's node list of each entry.
    nodes: Vec<usize>,
    notes: Vec<String>,
}

impl Squashfs {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let head = read_prefix(&*source, 0, 32).map_err(|error| UnpackError::io("read the superblock", error))?;
        let big_endian = head.starts_with(b"sqsh");
        let major = match head.get(28..30) {
            Some(bytes) if big_endian => u16::from_be_bytes([bytes[0], bytes[1]]),
            Some(bytes) => u16::from_le_bytes([bytes[0], bytes[1]]),
            None => return Err(UnpackError::malformed("squashfs", "truncated superblock")),
        };
        if major != 4 {
            return Err(UnpackError::Unsupported(format!("SquashFS version {major} (only 4.x is read)")));
        }
        let kind = if big_endian { Kind::new_v4_with_const(&PURE_CODECS, BE_V4_0) } else { Kind::new_v4(&PURE_CODECS) };
        CODEC_ERROR.with(|slot| slot.borrow_mut().take());
        let reader = BufReader::new(Cursor::new(source));
        let reader = {
            let _tables = TableScope::new();
            let squashfs = backhand::Squashfs::from_reader_with_offset_and_kind(reader, 0, kind).map_err(translate)?;
            // backhand builds the tree recursively, one stack frame per directory level: bound the depth first.
            check_tree(&squashfs, big_endian, limits)?;
            squashfs.into_filesystem_reader().map_err(translate)?
        };
        let mut entries = Vec::new();
        let mut nodes = Vec::new();
        for (index, node) in reader.root.nodes.iter().enumerate() {
            let path = node.fullpath.to_string_lossy();
            let path = path.trim_start_matches('/');
            if path.is_empty() {
                continue;
            }
            if entries.len() >= limits.max_entries {
                return Err(UnpackError::Limit(format!("more than {} entries", limits.max_entries)));
            }
            if path.split('/').count() > limits.max_path_depth {
                return Err(UnpackError::Limit(format!("paths deeper than {} levels", limits.max_path_depth)));
            }
            let (kind, size, link) = match &node.inner {
                InnerNode::File(file) => (EntryKind::File, file.file_len() as u64, None),
                InnerNode::Symlink(link) => (EntryKind::Symlink, 0, Some(link.link.to_string_lossy().into_owned())),
                InnerNode::Dir(_) => (EntryKind::Dir, 0, None),
                InnerNode::CharacterDevice(_) => (EntryKind::CharDevice, 0, None),
                InnerNode::BlockDevice(_) => (EntryKind::BlockDevice, 0, None),
                InnerNode::NamedPipe => (EntryKind::Fifo, 0, None),
                InnerNode::Socket => (EntryKind::Socket, 0, None),
            };
            let header = &node.header;
            entries.push(Entry {
                path: path.to_owned(),
                kind,
                size,
                mode: u32::from(header.permissions) & 0o7777,
                uid: header.uid,
                gid: header.gid,
                link,
                note: None,
            });
            nodes.push(index);
        }
        let compressor = reader.compressor.map_or_else(|| "unknown".to_owned(), |c| format!("{c:?}").to_lowercase());
        let notes = vec![
            format!("version 4.0 {}", if big_endian { "big-endian" } else { "little-endian" }),
            format!("compression {compressor}"),
            format!("block size {}", reader.block_size),
        ];
        Ok(Self { reader: Mutex::new(reader), entries, nodes, notes })
    }
}

impl Image for Squashfs {
    fn format(&self) -> Format {
        Format::Squashfs
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let limit = budget.limits.max_file_bytes;
        let entry = self.entries.get(index).ok_or_else(|| UnpackError::Invalid("no such entry".to_owned()))?;
        if entry.size > limit {
            return Err(UnpackError::Limit(format!("`{}` is larger than max_file_bytes ({limit})", entry.path)));
        }
        let reader = self.reader.lock().map_err(|_| UnpackError::Invalid("image reader poisoned".to_owned()))?;
        let InnerNode::File(file) = &reader.root.nodes[self.nodes[index]].inner else {
            return Err(UnpackError::Invalid(format!("`{}` is not a file", entry.path)));
        };
        // Sparse blocks are zeros backhand synthesises: they count against the ratio limit, with the block list as
        // their nominal input.
        let sparse = file.block_sizes().iter().filter(|block| block.size() == 0).count() as u64;
        if sparse > 0 {
            let bytes = sparse.saturating_mul(u64::from(reader.block_size)).min(entry.size);
            crate::limits::account(4 * sparse, bytes)?;
        }
        CODEC_ERROR.with(|slot| slot.borrow_mut().take());
        let mut stream = reader.file(file).reader_checked().map_err(translate)?;
        let mut buffer = vec![0; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_translate(error)),
            };
            total = total.saturating_add(read as u64);
            if total > entry.size {
                return Err(UnpackError::malformed("squashfs", format!("`{}` holds more than its size", entry.path)));
            }
            budget.charge_bytes(read as u64)?;
            sink(&buffer[..read])?;
        }
        if total != entry.size {
            return Err(UnpackError::malformed("squashfs", format!("`{}` ends before its size", entry.path)));
        }
        Ok(())
    }
}
