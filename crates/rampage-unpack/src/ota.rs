//! Android OTA `payload.bin` (update_engine, major version 2). Full payloads only: REPLACE, REPLACE_BZ,
//! REPLACE_XZ, ZERO and DISCARD rebuild a partition from the payload alone; every other operation patches the
//! previous build and is refused.

use std::cell::RefCell;

use sha2::{Digest, Sha256};

use crate::codec::{Codec, decompress_stream};
use crate::error::{Result, UnpackError, checked};
use crate::image::{Entry, EntryKind, Format, Image};
use crate::limits::{Budget, Limits};
use crate::source::{Cursor, Source, Spool, write_all_at};

const FORMAT: &str = "ota_payload";
/// Manifest bytes a payload may declare.
const MAX_MANIFEST: u64 = 64 << 20;
const MAX_PARTITIONS: usize = 4096;
const MAX_OPERATIONS: usize = 4_000_000;
const MAX_EXTENTS: usize = 16_000_000;

const REPLACE: u32 = 0;
const REPLACE_BZ: u32 = 1;
const ZERO: u32 = 6;
const DISCARD: u32 = 7;
const REPLACE_XZ: u32 = 8;

fn operation_name(kind: u32) -> &'static str {
    match kind {
        0 => "REPLACE",
        1 => "REPLACE_BZ",
        2 => "MOVE",
        3 => "BSDIFF",
        4 => "SOURCE_COPY",
        5 => "SOURCE_BSDIFF",
        6 => "ZERO",
        7 => "DISCARD",
        8 => "REPLACE_XZ",
        9 => "PUFFDIFF",
        10 => "BROTLI_BSDIFF",
        11 => "ZUCCHINI",
        12 => "LZ4DIFF_BSDIFF",
        13 => "LZ4DIFF_PUFFDIFF",
        _ => "unknown",
    }
}

fn malformed(reason: impl Into<String>) -> UnpackError {
    UnpackError::malformed(FORMAT, reason)
}

/// A protobuf message read field by field.
struct Fields<'a> {
    bytes: &'a [u8],
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A fixed 32- or 64-bit field, not used by the fields read here.
    Fixed,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.bytes.split_first().ok_or_else(|| malformed("truncated manifest varint"))?;
            self.bytes = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(malformed("manifest varint longer than 10 bytes"))
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8]> {
        let len = usize::try_from(len).ok().filter(|len| *len <= self.bytes.len());
        let len = len.ok_or_else(|| malformed("manifest field runs past its message"))?;
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    /// The next field number and value, or `None` at the end.
    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>> {
        if self.bytes.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let value = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let len = self.varint()?;
                Value::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            wire => return Err(malformed(format!("unsupported protobuf wire type {wire}"))),
        };
        Ok(Some((key >> 3, value)))
    }
}

#[derive(Debug, Clone, Copy)]
struct Extent {
    start_block: u64,
    num_blocks: u64,
}

#[derive(Debug, Default)]
struct Operation {
    kind: u32,
    data_offset: u64,
    data_length: u64,
    dst: Vec<Extent>,
    data_sha256: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Partition {
    name: String,
    size: u64,
    hash: Option<Vec<u8>>,
    has_old_info: bool,
    operations: Vec<Operation>,
}

impl Partition {
    /// The first operation that needs the previous build, if any.
    fn delta_operation(&self) -> Option<u32> {
        self.operations
            .iter()
            .map(|operation| operation.kind)
            .find(|kind| !matches!(*kind, REPLACE | REPLACE_BZ | REPLACE_XZ | ZERO | DISCARD))
    }
}

fn extent(bytes: &[u8]) -> Result<Extent> {
    let mut extent = Extent { start_block: 0, num_blocks: 0 };
    let mut fields = Fields::new(bytes);
    while let Some((field, value)) = fields.next()? {
        match (field, value) {
            (1, Value::Varint(value)) => extent.start_block = value,
            (2, Value::Varint(value)) => extent.num_blocks = value,
            _ => {}
        }
    }
    Ok(extent)
}

/// Compressed-input bytes charged to the ratio meter for each extent a ZERO or DISCARD operation fills: the zeros
/// are synthesised from a few bytes of manifest.
const NOMINAL_EXTENT_INPUT: u64 = 16;

/// Operation and extent counts a partition may declare: each one writes at least one block of it.
struct Counts {
    cap: usize,
    operations: usize,
    extents: usize,
}

fn operation(bytes: &[u8], counts: &mut Counts) -> Result<Operation> {
    let mut operation = Operation::default();
    let mut fields = Fields::new(bytes);
    while let Some((field, value)) = fields.next()? {
        match (field, value) {
            (1, Value::Varint(value)) => {
                operation.kind = u32::try_from(value).map_err(|_| malformed("operation type out of range"))?;
            }
            (2, Value::Varint(value)) => operation.data_offset = value,
            (3, Value::Varint(value)) => operation.data_length = value,
            (6, Value::Bytes(bytes)) => {
                counts.extents += 1;
                if counts.extents > counts.cap.min(MAX_EXTENTS) {
                    return Err(malformed("more destination extents than the partition has blocks"));
                }
                operation.dst.push(extent(bytes)?);
            }
            (8, Value::Bytes(bytes)) => operation.data_sha256 = Some(bytes.to_vec()),
            _ => {}
        }
    }
    Ok(operation)
}

fn partition_info(bytes: &[u8]) -> Result<(u64, Option<Vec<u8>>)> {
    let (mut size, mut hash) = (0, None);
    let mut fields = Fields::new(bytes);
    while let Some((field, value)) = fields.next()? {
        match (field, value) {
            (1, Value::Varint(value)) => size = value,
            (2, Value::Bytes(bytes)) => hash = Some(bytes.to_vec()),
            _ => {}
        }
    }
    Ok((size, hash))
}

fn partition(bytes: &[u8], block_size: u64) -> Result<Partition> {
    let mut partition = Partition::default();
    // The size comes first, wherever the field sits, so operation and extent counts are capped by it before any
    // operation is kept: each writes at least one block.
    let mut fields = Fields::new(bytes);
    while let Some((field, value)) = fields.next()? {
        if let (7, Value::Bytes(info)) = (field, value) {
            (partition.size, partition.hash) = partition_info(info)?;
        }
    }
    let blocks = usize::try_from(partition.size.div_ceil(block_size)).unwrap_or(usize::MAX);
    let mut counts = Counts { cap: blocks.max(1), operations: 0, extents: 0 };
    let mut fields = Fields::new(bytes);
    while let Some((field, value)) = fields.next()? {
        match (field, value) {
            (1, Value::Bytes(name)) => partition.name = String::from_utf8_lossy(name).into_owned(),
            (6, Value::Bytes(_)) => partition.has_old_info = true,
            (8, Value::Bytes(bytes)) => {
                counts.operations += 1;
                if counts.operations > counts.cap.min(MAX_OPERATIONS) {
                    return Err(malformed("more operations than the partition has blocks"));
                }
                partition.operations.push(operation(bytes, &mut counts)?);
            }
            _ => {}
        }
    }
    Ok(partition)
}

pub struct Payload {
    source: Source,
    /// Where blob data starts: after the header, manifest and metadata signature.
    data_start: u64,
    block_size: u64,
    minor_version: u64,
    partitions: Vec<Partition>,
    entries: Vec<Entry>,
    /// The partition last rebuilt, kept so reading it again does not rebuild it.
    cached: RefCell<Option<(usize, Source)>>,
}

fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8]))
}

impl Payload {
    pub fn open(source: Source, limits: &Limits) -> Result<Self> {
        let mut header = [0u8; 24];
        source.read_at(0, &mut header).map_err(|_| malformed("truncated header"))?;
        if &header[..4] != b"CrAU" {
            return Err(malformed("bad magic"));
        }
        let version = be64(&header[4..12]);
        if version != 2 {
            return Err(UnpackError::Unsupported(format!("OTA payload major version {version} (only 2 is read)")));
        }
        let manifest_size = be64(&header[12..20]);
        let signature_size = u64::from(u32::from_be_bytes([header[20], header[21], header[22], header[23]]));
        if manifest_size > MAX_MANIFEST {
            return Err(UnpackError::Limit(format!("manifest of {manifest_size} bytes (at most {MAX_MANIFEST})")));
        }
        let data_start = checked(24u64.checked_add(manifest_size), FORMAT, "manifest end")?;
        let data_start = checked(data_start.checked_add(signature_size), FORMAT, "metadata signature end")?;
        if data_start > source.size() {
            return Err(malformed("manifest runs past the end of the file"));
        }
        let mut manifest = vec![0u8; manifest_size as usize];
        source.read_at(24, &mut manifest).map_err(|_| malformed("truncated manifest"))?;
        let (mut block_size, mut minor_version) = (4096u64, 0u64);
        let mut fields = Fields::new(&manifest);
        while let Some((field, value)) = fields.next()? {
            match (field, value) {
                (3, Value::Varint(value)) => block_size = value,
                (12, Value::Varint(value)) => minor_version = value,
                _ => {}
            }
        }
        if !(512..=(1 << 20)).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(malformed(format!("block size {block_size}")));
        }
        let mut partitions = Vec::new();
        let (mut operations, mut extents) = (0usize, 0usize);
        let mut fields = Fields::new(&manifest);
        while let Some((field, value)) = fields.next()? {
            if let (13, Value::Bytes(bytes)) = (field, value) {
                if partitions.len() >= MAX_PARTITIONS.min(limits.max_entries) {
                    return Err(UnpackError::Limit("too many partitions".to_owned()));
                }
                let partition = partition(bytes, block_size)?;
                operations += partition.operations.len();
                extents += partition.operations.iter().map(|operation| operation.dst.len()).sum::<usize>();
                if operations > MAX_OPERATIONS || extents > MAX_EXTENTS {
                    return Err(UnpackError::Limit(format!(
                        "more than {MAX_OPERATIONS} operations or {MAX_EXTENTS} extents"
                    )));
                }
                partitions.push(partition);
            }
        }
        let entries = partitions
            .iter()
            .map(|partition| Entry {
                path: format!("{}.img", partition.name),
                kind: EntryKind::Image,
                size: partition.size,
                mode: 0o644,
                uid: 0,
                gid: 0,
                link: None,
                note: partition.delta_operation().map(|kind| {
                    format!("delta update ({}): needs the previous build, cannot be rebuilt", operation_name(kind))
                }),
            })
            .collect();
        Ok(Self { source, data_start, block_size, minor_version, partitions, entries, cached: RefCell::new(None) })
    }

    /// Writes partition `index` into a temporary file, verifying each operation's data hash and the partition's.
    /// The rebuild is charged to `budget` as the partition's size.
    fn materialise(&self, index: usize, budget: &mut Budget) -> Result<Source> {
        let limit = budget.limits.max_file_bytes;
        if let Some((cached, source)) = &*self.cached.borrow()
            && *cached == index
        {
            return Ok(source.clone());
        }
        let partition = &self.partitions[index];
        if let Some(kind) = partition.delta_operation() {
            return Err(UnpackError::Unsupported(format!(
                "partition `{}` is a delta update (operation {}): it patches the previous build's partition, which \
                 the payload alone cannot rebuild; only full payloads (REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO) are \
                 supported",
                partition.name,
                operation_name(kind)
            )));
        }
        if partition.size > limit {
            return Err(UnpackError::Limit(format!(
                "partition `{}` is {} bytes, more than max_file_bytes ({limit})",
                partition.name, partition.size
            )));
        }
        let zero_extents = self.check_extents(partition)?;
        let zero_bytes: u64 = zero_extents.iter().sum();
        crate::limits::account(NOMINAL_EXTENT_INPUT.saturating_mul(zero_extents.len() as u64), zero_bytes)?;
        budget.charge_bytes(partition.size)?;
        let mut spool = Spool::new().map_err(|error| UnpackError::io("create a temporary file", error))?;
        spool.set_size(partition.size).map_err(|error| UnpackError::io("size a temporary file", error))?;
        for (number, operation) in partition.operations.iter().enumerate() {
            let context =
                |reason: String| malformed(format!("partition `{}` operation {number}: {reason}", partition.name));
            // The destination extents, as byte ranges inside the partition.
            let mut ranges = Vec::with_capacity(operation.dst.len());
            let mut total = 0u64;
            for extent in &operation.dst {
                let start = extent.start_block.checked_mul(self.block_size);
                let len = extent.num_blocks.checked_mul(self.block_size);
                let (Some(start), Some(len)) = (start, len) else {
                    return Err(context("extent overflows".to_owned()));
                };
                if !crate::source::within(start, len, partition.size) {
                    return Err(context("extent lies outside the partition".to_owned()));
                }
                total = total.checked_add(len).ok_or_else(|| context("extents overflow".to_owned()))?;
                ranges.push((start, len));
            }
            let mut writer = ExtentWriter { file: spool.file(), ranges: &ranges, index: 0, written: 0 };
            match operation.kind {
                // Extents never overlap (checked above), so these blocks are still the file's initial zeros.
                ZERO | DISCARD => {}
                REPLACE | REPLACE_BZ | REPLACE_XZ => {
                    let offset = checked(self.data_start.checked_add(operation.data_offset), FORMAT, "data offset")?;
                    if !crate::source::within(offset, operation.data_length, self.source.size()) {
                        return Err(context("data lies past the end of the payload (truncated?)".to_owned()));
                    }
                    let mut hasher = Sha256::new();
                    let input = HashingRead {
                        inner: Cursor::range(self.source.clone(), offset, operation.data_length),
                        hasher: &mut hasher,
                    };
                    let sink = &mut |chunk: &[u8]| writer.write(chunk);
                    let produced = if operation.kind == REPLACE {
                        let mut input = input;
                        let mut buffer = vec![0u8; 1 << 20];
                        let mut produced = 0u64;
                        loop {
                            let read = std::io::Read::read(&mut input, &mut buffer)
                                .map_err(|error| UnpackError::io("read the payload", error))?;
                            if read == 0 {
                                break;
                            }
                            produced += read as u64;
                            sink(&buffer[..read])?;
                        }
                        produced
                    } else {
                        let codec = if operation.kind == REPLACE_BZ { Codec::Bzip2 } else { Codec::Xz };
                        decompress_stream(codec, input, operation.data_length, total, sink)?
                    };
                    if produced != total {
                        return Err(context(format!("data yields {produced} bytes for {total} bytes of extents")));
                    }
                    if let Some(expected) = &operation.data_sha256
                        && hasher.finalize().as_slice() != expected.as_slice()
                    {
                        return Err(context("data does not match its SHA-256 (corrupt or truncated payload)".into()));
                    }
                }
                _ => unreachable!("delta operations were refused above"),
            }
        }
        let source = spool.into_source();
        if let Some(expected) = &partition.hash {
            let mut hasher = Sha256::new();
            crate::sparse::for_each_chunk(&*source, 0, source.size(), &mut |chunk| {
                hasher.update(chunk);
                Ok(())
            })?;
            if hasher.finalize().as_slice() != expected.as_slice() {
                return Err(malformed(format!(
                    "partition `{}` does not match the SHA-256 in the manifest once rebuilt",
                    partition.name
                )));
            }
        }
        *self.cached.borrow_mut() = Some((index, source.clone()));
        Ok(source)
    }

    /// Checks that the destination extents of every operation of `partition` lie inside it and never overlap, so
    /// the rebuild writes each block at most once. Returns the byte length of each ZERO or DISCARD extent.
    fn check_extents(&self, partition: &Partition) -> Result<Vec<u64>> {
        let blocks = partition.size / self.block_size;
        let mut ranges = Vec::new();
        let mut zeros = Vec::new();
        for operation in &partition.operations {
            for extent in &operation.dst {
                let end = extent.start_block.checked_add(extent.num_blocks).filter(|end| *end <= blocks);
                let Some(end) = end else {
                    return Err(malformed(format!("partition `{}`: an extent lies outside it", partition.name)));
                };
                if matches!(operation.kind, ZERO | DISCARD) {
                    zeros.push(extent.num_blocks * self.block_size);
                }
                ranges.push((extent.start_block, end));
            }
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            return Err(malformed(format!("partition `{}`: operations write overlapping extents", partition.name)));
        }
        Ok(zeros)
    }
}

/// Writes a stream across a list of byte ranges of a file in order.
struct ExtentWriter<'a> {
    file: &'a std::fs::File,
    ranges: &'a [(u64, u64)],
    index: usize,
    /// Bytes written into `ranges[index]`.
    written: u64,
}

impl ExtentWriter<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let Some(&(start, len)) = self.ranges.get(self.index) else {
                return Err(malformed("operation data is longer than its extents"));
            };
            let count = (len - self.written).min(bytes.len() as u64) as usize;
            write_all_at(self.file, start + self.written, &bytes[..count])
                .map_err(|error| UnpackError::io("write a temporary file", error))?;
            bytes = &bytes[count..];
            self.written += count as u64;
            if self.written == len {
                self.index += 1;
                self.written = 0;
            }
        }
        Ok(())
    }
}

struct HashingRead<'a, R> {
    inner: R,
    hasher: &'a mut Sha256,
}

impl<R: std::io::Read> std::io::Read for HashingRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        Ok(read)
    }
}

impl Image for Payload {
    fn format(&self) -> Format {
        Format::OtaPayload
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn notes(&self) -> Vec<String> {
        let delta = self.partitions.iter().any(|p| p.delta_operation().is_some() || p.has_old_info);
        let kind = if delta || self.minor_version != 0 { "delta" } else { "full" };
        vec![
            format!("{kind} payload (minor version {})", self.minor_version),
            format!("block size {}", self.block_size),
            format!("{} partitions", self.partitions.len()),
        ]
    }

    fn read(&self, index: usize, budget: &mut Budget, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if index >= self.partitions.len() {
            return Err(UnpackError::Invalid("no such entry".to_owned()));
        }
        let source = self.materialise(index, budget)?;
        crate::sparse::copy_range(&*source, 0, source.size(), budget, sink)
    }
}
