//! Built-in models of common C library functions, run in place of an imported function's code so a run continues
//! through ordinary string and memory handling instead of stopping at the import.

use std::collections::HashMap;
use std::time::Instant;

use super::machine::Ram;
use super::{ImageRam, PAGE, StopReason, fault_stop};

/// Bytes a heap may reach, counted in pages against the run's copy-on-write cap.
pub(super) const HEAP_BYTES: u64 = 16 << 20;
/// Bytes a stand-in reads or writes per step of the run's budget.
pub(super) const BYTES_PER_STEP: u64 = 16;
const ALIGNMENT: u64 = 16;
const CHUNK: u64 = 4096;

/// A modelled library function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stub {
    Memcpy,
    Memmove,
    Memset,
    Memcmp,
    Strlen,
    Strnlen,
    Strcpy,
    Strncpy,
    Strcmp,
    Strncmp,
    Strchr,
    Strrchr,
    Strcat,
    Toupper,
    Tolower,
    Abs,
    Malloc,
    Calloc,
    Realloc,
    Free,
}

impl Stub {
    /// Integer and pointer arguments read (a fortified variant's trailing object size is not read).
    pub fn arity(self) -> usize {
        match self {
            Self::Strlen | Self::Toupper | Self::Tolower | Self::Abs | Self::Malloc | Self::Free => 1,
            Self::Strnlen
            | Self::Strcpy
            | Self::Strcmp
            | Self::Strchr
            | Self::Strrchr
            | Self::Strcat
            | Self::Calloc
            | Self::Realloc => 2,
            Self::Memcpy | Self::Memmove | Self::Memset | Self::Memcmp | Self::Strncpy | Self::Strncmp => 3,
        }
    }
}

/// The stand-in for an imported `name`: the C name, its Mach-O spelling with a leading underscore, a fortified
/// `__name_chk` variant, an MSVC CRT `_name` alias, or an ELF name with a symbol version (`memcpy@GLIBC_2.14`).
pub(super) fn lookup(name: &str) -> Option<Stub> {
    let name = name.split('@').next().unwrap_or(name);
    let bare = name.trim_start_matches('_');
    // Fortified variants are `__name_chk` (`___name_chk` on Mach-O).
    let base = if bare.len() < name.len() { bare.strip_suffix("_chk").unwrap_or(bare) } else { bare };
    Some(match base {
        "memcpy" => Stub::Memcpy,
        "memmove" => Stub::Memmove,
        "memset" => Stub::Memset,
        "memcmp" => Stub::Memcmp,
        "strlen" => Stub::Strlen,
        "strnlen" => Stub::Strnlen,
        "strcpy" => Stub::Strcpy,
        "strncpy" => Stub::Strncpy,
        "strcmp" => Stub::Strcmp,
        "strncmp" => Stub::Strncmp,
        "strchr" => Stub::Strchr,
        "strrchr" => Stub::Strrchr,
        "strcat" => Stub::Strcat,
        "toupper" => Stub::Toupper,
        "tolower" => Stub::Tolower,
        "abs" => Stub::Abs,
        "malloc" => Stub::Malloc,
        "calloc" => Stub::Calloc,
        "realloc" => Stub::Realloc,
        "free" => Stub::Free,
        _ => return None,
    })
}

/// A bump heap of zeroed memory: blocks are never reused, so `free` only forgets a block's size.
pub(super) struct Heap {
    pub base: u64,
    pub bytes: Vec<u8>,
    sizes: HashMap<u64, u64>,
}

impl Heap {
    pub fn new(base: u64) -> Self {
        Self { base, bytes: Vec::new(), sizes: HashMap::new() }
    }

    pub fn pages(&self) -> usize {
        (self.bytes.len() as u64).div_ceil(PAGE) as usize
    }

    /// The heap bytes from `address`, when `length` of them are allocated.
    pub fn slice(&mut self, address: u64, length: usize) -> Option<&mut [u8]> {
        let offset = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.bytes.get_mut(offset..offset.checked_add(length)?)
    }
}

pub(super) type Stop = (StopReason, String);

/// The value a stand-in returns and the bytes it touched.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Outcome {
    pub value: u64,
    pub bytes: u64,
}

impl ImageRam<'_> {
    fn allocate(&mut self, size: u64, what: &str) -> Result<u64, Stop> {
        let limit = |detail: String| (StopReason::MemoryLimit, detail);
        let heap = self.heap.as_mut().ok_or_else(|| limit(format!("{what}: no heap is mapped")))?;
        let offset = (heap.bytes.len() as u64).next_multiple_of(ALIGNMENT);
        let end = offset.checked_add(size.max(1)).filter(|&end| end <= HEAP_BYTES).ok_or_else(|| {
            limit(format!("{what} would grow the heap past {} MiB ({} bytes in use)", HEAP_BYTES >> 20, offset))
        })?;
        let pages = end.div_ceil(PAGE) as usize;
        if self.pages.len() + pages > self.page_limit {
            return Err(limit(format!(
                "{what} would take the heap and written image pages past {} pages ({} MiB)",
                self.page_limit,
                (self.page_limit as u64 * PAGE) >> 20
            )));
        }
        let heap = self.heap.as_mut().expect("heap checked above");
        heap.bytes.resize(end as usize, 0);
        let address = heap.base + offset;
        heap.sizes.insert(address, size);
        Ok(address)
    }
}

impl ImageRam<'_> {
    /// Bytes a write can still reach: mapped regions, the heap's allocated bytes, image pages already written and
    /// the pages left under the cap. A longer write stops before it starts.
    fn writable_bytes(&self) -> u64 {
        let regions: u64 = self.regions.iter().map(|region| region.bytes.len() as u64).sum();
        let heap = self.heap.as_ref().map_or(0, |heap| heap.bytes.len() as u64);
        let heap_pages = self.heap.as_ref().map_or(0, Heap::pages);
        let free_pages = self.page_limit.saturating_sub(self.pages.len() + heap_pages) as u64;
        regions + heap + (self.pages.len() as u64 + free_pages) * PAGE
    }
}

/// What a stand-in may spend: bytes touched (the remaining steps) and the run's deadline.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits<'a> {
    pub bytes: u64,
    pub deadline: Instant,
    /// The import called, for stop details.
    pub name: &'a str,
}

/// Chunks between deadline checks inside one stand-in (1 MiB).
const CHUNKS_PER_CHECK: u64 = 256;

impl Limits<'_> {
    fn bytes(&self, length: u64) -> Result<u64, Stop> {
        if length > self.bytes {
            return Err((
                StopReason::StepLimit,
                format!("library stand-in {} ran past the remaining step budget (max_steps)", self.name),
            ));
        }
        Ok(length)
    }

    /// Checks the deadline every `CHUNKS_PER_CHECK` chunks.
    fn tick(&self, chunk: u64) -> Result<(), Stop> {
        if chunk.is_multiple_of(CHUNKS_PER_CHECK) && Instant::now() >= self.deadline {
            return Err((StopReason::Timeout, format!("library stand-in {} ran past timeout_ms", self.name)));
        }
        Ok(())
    }

    /// A write of `length` bytes, within the budget and what memory can take.
    fn writable(&self, ram: &ImageRam<'_>, length: u64) -> Result<u64, Stop> {
        let length = self.bytes(length)?;
        let writable = ram.writable_bytes();
        if length > writable {
            return Err((
                StopReason::MemoryLimit,
                format!("{} would write {length} bytes; at most {writable} more bytes can be written", self.name),
            ));
        }
        Ok(length)
    }
}

/// Reads up to `out.len()` bytes; on a fault, byte by byte so the fault names the first unreadable byte.
fn read_chunk(ram: &mut ImageRam<'_>, address: u64, out: &mut [u8]) -> Result<(), Stop> {
    if ram.read(address, out).is_ok() {
        return Ok(());
    }
    for (index, byte) in out.iter_mut().enumerate() {
        let mut one = [0u8];
        ram.read(address.wrapping_add(index as u64), &mut one).map_err(fault_stop)?;
        *byte = one[0];
    }
    Ok(())
}

/// Reads string bytes into `out`: all of them, or (when the whole range is not mapped) byte by byte through the
/// first NUL, which ends the valid bytes. Returns how many bytes are valid.
fn read_string_chunk(ram: &mut ImageRam<'_>, address: u64, out: &mut [u8]) -> Result<usize, Stop> {
    if ram.read(address, out).is_ok() {
        return Ok(out.len());
    }
    for (index, byte) in out.iter_mut().enumerate() {
        let mut one = [0u8];
        ram.read(address.wrapping_add(index as u64), &mut one).map_err(fault_stop)?;
        *byte = one[0];
        if one[0] == 0 {
            return Ok(index + 1);
        }
    }
    Ok(out.len())
}

fn write_chunk(ram: &mut ImageRam<'_>, address: u64, bytes: &[u8]) -> Result<(), Stop> {
    if ram.write(address, bytes).is_ok() {
        return Ok(());
    }
    for (index, byte) in bytes.iter().enumerate() {
        ram.write(address.wrapping_add(index as u64), &[*byte]).map_err(fault_stop)?;
    }
    Ok(())
}

/// Copies `length` bytes in 4 KiB chunks, backwards when the destination overlaps the source from above.
fn copy(ram: &mut ImageRam<'_>, destination: u64, source: u64, length: u64, limits: &Limits<'_>) -> Result<(), Stop> {
    let chunks = length.div_ceil(CHUNK);
    let backwards = destination > source && destination < source.wrapping_add(length);
    let mut buffer = vec![0u8; CHUNK.min(length) as usize];
    for index in 0..chunks {
        limits.tick(index)?;
        let chunk = if backwards { chunks - 1 - index } else { index };
        let offset = chunk * CHUNK;
        let size = (length - offset).min(CHUNK) as usize;
        read_chunk(ram, source.wrapping_add(offset), &mut buffer[..size])?;
        write_chunk(ram, destination.wrapping_add(offset), &buffer[..size])?;
    }
    Ok(())
}

fn fill(ram: &mut ImageRam<'_>, destination: u64, byte: u8, length: u64, limits: &Limits<'_>) -> Result<(), Stop> {
    let buffer = vec![byte; CHUNK.min(length) as usize];
    for index in 0..length.div_ceil(CHUNK) {
        limits.tick(index)?;
        let offset = index * CHUNK;
        let size = (length - offset).min(CHUNK) as usize;
        write_chunk(ram, destination.wrapping_add(offset), &buffer[..size])?;
    }
    Ok(())
}

/// Streams the string at `address` (at most `limit` bytes, without its NUL) to `visit` in chunks, and returns its
/// length. Reading stops at a NUL, at `limit`, or at the budget (then with a step-limit stop).
fn scan(
    ram: &mut ImageRam<'_>,
    address: u64,
    limit: u64,
    limits: &Limits<'_>,
    mut visit: impl FnMut(u64, &[u8]),
) -> Result<u64, Stop> {
    let mut buffer = [0u8; CHUNK as usize];
    let mut length = 0u64;
    let mut index = 0;
    while length < limit {
        limits.tick(index)?;
        index += 1;
        // The chunk ends at a page boundary, so it never reaches into unmapped memory past a NUL.
        let at = address.wrapping_add(length);
        let size = (CHUNK - at % CHUNK).min(limit - length) as usize;
        let valid = read_string_chunk(ram, at, &mut buffer[..size])?;
        let chunk = &buffer[..valid];
        let end = chunk.iter().position(|&byte| byte == 0).unwrap_or(valid);
        limits.bytes(length + end as u64)?;
        visit(length, &chunk[..end]);
        length += end as u64;
        if end < size {
            break;
        }
    }
    Ok(length)
}

fn sign(value: i64) -> u64 {
    value as u64
}

/// Compares `length` bytes (or, for strings, up to the first NUL in either) in chunks.
fn compare(
    ram: &mut ImageRam<'_>,
    a: u64,
    b: u64,
    length: u64,
    strings: bool,
    limits: &Limits<'_>,
) -> Result<(u64, u64), Stop> {
    let mut left = [0u8; CHUNK as usize];
    let mut right = [0u8; CHUNK as usize];
    let mut offset = 0u64;
    let mut index = 0;
    while offset < length {
        limits.tick(index)?;
        index += 1;
        // Strings are read byte by byte up to a page boundary of either side, so no read passes a NUL into
        // unmapped memory.
        let size = if strings {
            let to_page = |address: u64| CHUNK - address.wrapping_add(offset) % CHUNK;
            to_page(a).min(to_page(b)).min(length - offset)
        } else {
            (length - offset).min(CHUNK)
        } as usize;
        limits.bytes(2 * (offset + size as u64))?;
        let valid = if strings {
            let left_valid = read_string_chunk(ram, a.wrapping_add(offset), &mut left[..size])?;
            let right_valid = read_string_chunk(ram, b.wrapping_add(offset), &mut right[..size])?;
            left_valid.min(right_valid)
        } else {
            read_chunk(ram, a.wrapping_add(offset), &mut left[..size])?;
            read_chunk(ram, b.wrapping_add(offset), &mut right[..size])?;
            size
        };
        // A string side with fewer valid bytes ended at a NUL inside them, so the loop returns.
        for (x, y) in left[..valid].iter().zip(&right[..valid]) {
            if x != y {
                return Ok((sign(i64::from(*x) - i64::from(*y)), 2 * offset));
            }
            if strings && *x == 0 {
                return Ok((0, 2 * offset));
            }
        }
        offset += size as u64;
    }
    Ok((0, 2 * offset))
}

/// Runs `stub` on `args` (each masked to the pointer width), within `limits`.
pub(super) fn call(
    stub: Stub,
    args: &[u64],
    width: u32,
    ram: &mut ImageRam<'_>,
    limits: &Limits<'_>,
) -> Result<Outcome, Stop> {
    let name = limits.name;
    let mask = if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
    let arg = |index: usize| args.get(index).copied().unwrap_or(0) & mask;
    let int = |index: usize| i64::from(arg(index) as u32 as i32);
    let outcome = |value: u64, bytes: u64| Ok(Outcome { value: value & mask, bytes });
    match stub {
        Stub::Memcpy | Stub::Memmove => {
            let length = limits.writable(ram, arg(2))?;
            copy(ram, arg(0), arg(1), length, limits)?;
            outcome(arg(0), length)
        }
        Stub::Memset => {
            let length = limits.writable(ram, arg(2))?;
            fill(ram, arg(0), arg(1) as u8, length, limits)?;
            outcome(arg(0), length)
        }
        Stub::Memcmp => {
            let length = limits.bytes(arg(2))?;
            let (value, touched) = compare(ram, arg(0), arg(1), length, false, limits)?;
            outcome(value, touched)
        }
        Stub::Strlen | Stub::Strnlen => {
            let limit = if stub == Stub::Strnlen { arg(1) } else { u64::MAX };
            let length = scan(ram, arg(0), limit, limits, |_, _| {})?;
            outcome(length, length)
        }
        Stub::Strcpy => {
            let length = scan(ram, arg(1), u64::MAX, limits, |_, _| {})? + 1;
            let length = limits.writable(ram, length)?;
            copy(ram, arg(0), arg(1), length, limits)?;
            outcome(arg(0), length)
        }
        Stub::Strncpy => {
            let limit = limits.writable(ram, arg(2))?;
            let length = scan(ram, arg(1), limit, limits, |_, _| {})?;
            copy(ram, arg(0), arg(1), length, limits)?;
            fill(ram, arg(0).wrapping_add(length), 0, limit - length, limits)?;
            outcome(arg(0), limit)
        }
        Stub::Strcmp | Stub::Strncmp => {
            let limit = if stub == Stub::Strncmp { arg(2) } else { u64::MAX };
            let (value, touched) = compare(ram, arg(0), arg(1), limit, true, limits)?;
            outcome(value, touched)
        }
        Stub::Strchr | Stub::Strrchr => {
            let wanted = arg(1) as u8;
            let mut found = None;
            let length = scan(ram, arg(0), u64::MAX, limits, |offset, chunk| {
                let hit = if stub == Stub::Strchr {
                    chunk.iter().position(|&byte| byte == wanted)
                } else {
                    chunk.iter().rposition(|&byte| byte == wanted)
                };
                if let Some(hit) = hit
                    && (stub == Stub::Strrchr || found.is_none())
                {
                    found = Some(offset + hit as u64);
                }
            })?;
            let found = if wanted == 0 { Some(length) } else { found };
            outcome(found.map_or(0, |offset| arg(0).wrapping_add(offset)), length)
        }
        Stub::Strcat => {
            let head = scan(ram, arg(0), u64::MAX, limits, |_, _| {})?;
            let tail = scan(ram, arg(1), u64::MAX, limits, |_, _| {})? + 1;
            let tail = limits.writable(ram, tail)?;
            copy(ram, arg(0).wrapping_add(head), arg(1), tail, limits)?;
            outcome(arg(0), head + tail)
        }
        Stub::Toupper | Stub::Tolower => {
            let value = int(0);
            let changed = match u8::try_from(value) {
                Ok(byte) if stub == Stub::Toupper => i64::from(byte.to_ascii_uppercase()),
                Ok(byte) => i64::from(byte.to_ascii_lowercase()),
                Err(_) => value,
            };
            outcome(sign(changed), 0)
        }
        Stub::Abs => outcome(sign(i64::from((int(0) as i32).wrapping_abs())), 0),
        Stub::Malloc => {
            let address = ram.allocate(arg(0), &format!("{name}({})", arg(0)))?;
            outcome(address, 0)
        }
        Stub::Calloc => {
            let Some(total) = arg(0).checked_mul(arg(1)).filter(|&total| total <= mask) else {
                return outcome(0, 0);
            };
            // Heap memory starts zeroed and is never reused, so nothing is touched.
            let address = ram.allocate(total, &format!("{name}({}, {})", arg(0), arg(1)))?;
            outcome(address, 0)
        }
        Stub::Realloc => {
            let (old, size) = (arg(0), arg(1));
            let previous = match old {
                0 => 0,
                _ => ram.heap.as_ref().and_then(|heap| heap.sizes.get(&old).copied()).ok_or_else(|| {
                    (StopReason::UnsupportedOp, format!("{name} of {old:#x}, which is not a live heap block"))
                })?,
            };
            let kept = limits.bytes(previous.min(size))?;
            let address = ram.allocate(size, &format!("{name}({old:#x}, {size})"))?;
            if old != 0 {
                copy(ram, address, old, kept, limits)?;
                if let Some(heap) = ram.heap.as_mut() {
                    heap.sizes.remove(&old);
                }
            }
            outcome(address, kept)
        }
        Stub::Free => {
            if let Some(heap) = ram.heap.as_mut() {
                heap.sizes.remove(&arg(0));
            }
            outcome(0, 0)
        }
    }
}
