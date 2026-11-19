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
    Strdup,
    Strndup,
    /// `sprintf(out, format, ...)`.
    Sprintf,
    /// `snprintf(out, size, format, ...)`.
    Snprintf,
    /// `__sprintf_chk(out, flag, object_size, format, ...)`.
    SprintfChk,
    /// `__snprintf_chk(out, size, flag, object_size, format, ...)`.
    SnprintfChk,
    /// C++ `operator new` and `new[]`: a heap block, as malloc.
    New,
    /// C++ `operator delete` and `delete[]`, sized or not: as free.
    Delete,
}

/// Argument words a formatting stand-in reads after its format: the variadic arguments it may consume.
pub(super) const VARIADIC_WORDS: usize = 24;

impl Stub {
    /// For a variadic stand-in, its fixed argument words (the rest are variadic).
    pub fn fixed_words(self) -> Option<usize> {
        match self {
            Self::Sprintf => Some(2),
            Self::Snprintf => Some(3),
            Self::SprintfChk => Some(4),
            Self::SnprintfChk => Some(5),
            _ => None,
        }
    }

    /// Integer and pointer arguments read (a fortified variant's trailing object size is not read).
    pub fn arity(self) -> usize {
        match self {
            Self::Strlen
            | Self::Toupper
            | Self::Tolower
            | Self::Abs
            | Self::Malloc
            | Self::Free
            | Self::Strdup
            | Self::New
            | Self::Delete => 1,
            Self::Strndup => 2,
            Self::Sprintf => 2 + VARIADIC_WORDS,
            Self::Snprintf => 3 + VARIADIC_WORDS,
            Self::SprintfChk => 4 + VARIADIC_WORDS,
            Self::SnprintfChk => 5 + VARIADIC_WORDS,
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
    // Aligned forms (align_val_t) are left out: the heap aligns to 16 bytes only.
    if name.contains("align_val_t") {
        return None;
    }
    // MSVC operator new/new[] (??2@, ??_U@) and delete/delete[] (??3@, ??_V@), any pointer width; placement new
    // (a pointer parameter after the size) is left out.
    if name.starts_with("??2@") || name.starts_with("??_U@") {
        return (!name.contains("_KPEAX@") && !name.contains("IPAX@")).then_some(Stub::New);
    }
    if name.starts_with("??3@") || name.starts_with("??_V@") {
        return Some(Stub::Delete);
    }
    let name = name.split('@').next().unwrap_or(name);
    let bare = name.trim_start_matches('_');
    // Itanium operator new/new[] (size_t of either width, also nothrow) and delete/delete[] (also sized). Placement
    // new (`_ZnwmPv`) returns its pointer argument and is left out.
    if let Some(rest) = ["Znwm", "Znwj", "Znam", "Znaj"].iter().find_map(|prefix| bare.strip_prefix(prefix)) {
        return (rest.is_empty() || rest == "RKSt9nothrow_t").then_some(Stub::New);
    }
    if ["ZdlPv", "ZdaPv"].iter().any(|prefix| bare.starts_with(prefix)) {
        return Some(Stub::Delete);
    }
    match bare {
        "sprintf_chk" => return Some(Stub::SprintfChk),
        "snprintf_chk" => return Some(Stub::SnprintfChk),
        _ => {}
    }
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
        "strdup" => Stub::Strdup,
        "strndup" => Stub::Strndup,
        "sprintf" => Stub::Sprintf,
        "snprintf" => Stub::Snprintf,
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
    /// A variadic 64-bit argument on a 32-bit target starts at an even argument word (AAPCS, MIPS o32).
    pub even_pairs: bool,
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
        Stub::Free | Stub::Delete => {
            if let Some(heap) = ram.heap.as_mut() {
                heap.sizes.remove(&arg(0));
            }
            outcome(0, 0)
        }
        Stub::New => {
            let address = ram.allocate(arg(0), &format!("{name}({})", arg(0)))?;
            outcome(address, 0)
        }
        Stub::Strdup | Stub::Strndup => {
            let limit = if stub == Stub::Strndup { arg(1) } else { u64::MAX };
            let length = scan(ram, arg(0), limit, limits, |_, _| {})?;
            let length = limits.writable(ram, length + 1)? - 1;
            let address = ram.allocate(length + 1, &format!("{name}({length} bytes)"))?;
            copy(ram, address, arg(0), length, limits)?;
            write_chunk(ram, address.wrapping_add(length), &[0])?;
            outcome(address, 2 * length)
        }
        Stub::Sprintf | Stub::Snprintf | Stub::SprintfChk | Stub::SnprintfChk => {
            // (output, size limit, format, first variadic word)
            let (output, size, format, first) = match stub {
                Stub::Sprintf => (arg(0), None, arg(1), 2),
                Stub::Snprintf => (arg(0), Some(arg(1)), arg(2), 3),
                Stub::SprintfChk => (arg(0), None, arg(3), 4),
                _ => (arg(0), Some(arg(1)), arg(4), 5),
            };
            let words: Vec<u64> = args.iter().skip(first).map(|&word| word & mask).collect();
            let text = format_printf(ram, format, &words, first, width, limits)?;
            let length = text.len() as u64;
            let written = match size {
                None => length + 1,
                Some(0) => 0,
                Some(size) => (length + 1).min(size),
            };
            if written > 0 {
                let written = limits.writable(ram, written)?;
                let mut bytes = text;
                bytes.truncate(written as usize - 1);
                bytes.push(0);
                write_chunk(ram, output, &bytes)?;
            }
            outcome(length, length + written)
        }
    }
}

/// Bytes of one formatted result; a longer one stops the run.
const MAX_FORMATTED: usize = 64 * 1024;

/// The C library's formatting of `format` (read from memory) with integer argument `words`, the argument words
/// from word `first` of the call on: conversions d i u x X o c s p and %%, flags - 0 + space #, width and
/// precision (also *), and length modifiers hh h l ll z j t. Bytes are copied as they are (no text encoding).
/// Floating-point conversions and %n stop the run.
fn format_printf(
    ram: &mut ImageRam<'_>,
    format: u64,
    words: &[u64],
    first: usize,
    width: u32,
    limits: &Limits<'_>,
) -> Result<Vec<u8>, Stop> {
    let unsupported = |what: String| (StopReason::UnsupportedOp, format!("library stand-in {}: {what}", limits.name));
    let mut spec = Vec::new();
    scan(ram, format, MAX_FORMATTED as u64, limits, |_, chunk| spec.extend_from_slice(chunk))?;
    let mut next = 0usize;
    let mut take = |bytes: u32| -> Result<u64, Stop> {
        // A 64-bit value on a 32-bit target takes two words, from an even word where the convention says so.
        let value = if bytes > width {
            // The pair's position counts from the call's first argument word, not the first variadic one.
            if limits.even_pairs {
                next = (first + next).next_multiple_of(2) - first;
            }
            let low = words.get(next).copied();
            let high = words.get(next + 1).copied();
            next += 2;
            match (low, high) {
                (Some(low), Some(high)) => low | (high << 32),
                _ => return Err(unsupported("more variadic arguments than it reads".to_owned())),
            }
        } else {
            next += 1;
            words
                .get(next - 1)
                .copied()
                .ok_or_else(|| unsupported("more variadic arguments than it reads".to_owned()))?
        };
        Ok(value)
    };
    let mut out: Vec<u8> = Vec::new();
    let mut index = 0usize;
    while index < spec.len() {
        if out.len() > MAX_FORMATTED {
            return Err(unsupported(format!("output longer than {MAX_FORMATTED} bytes")));
        }
        let byte = spec[index];
        index += 1;
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let (mut left, mut zero, mut plus, mut space, mut alternate) = (false, false, false, false, false);
        while let Some(&flag) = spec.get(index) {
            match flag {
                b'-' => left = true,
                b'0' => zero = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alternate = true,
                _ => break,
            }
            index += 1;
        }
        let number = |index: &mut usize, take: &mut dyn FnMut(u32) -> Result<u64, Stop>| -> Result<Option<i64>, Stop> {
            if spec.get(*index) == Some(&b'*') {
                *index += 1;
                return Ok(Some(i64::from(take(4)? as u32 as i32)));
            }
            let start = *index;
            while spec.get(*index).is_some_and(u8::is_ascii_digit) {
                *index += 1;
            }
            Ok((start < *index).then(|| {
                std::str::from_utf8(&spec[start..*index]).ok().and_then(|text| text.parse().ok()).unwrap_or(i64::MAX)
            }))
        };
        let mut field = number(&mut index, &mut take)?;
        if let Some(negative) = field.filter(|&field| field < 0) {
            left = true;
            field = Some(-negative);
        }
        let precision = if spec.get(index) == Some(&b'.') {
            index += 1;
            Some(number(&mut index, &mut take)?.unwrap_or(0)).filter(|&precision| precision >= 0)
        } else {
            None
        };
        if field.is_some_and(|field| field > MAX_FORMATTED as i64)
            || precision.is_some_and(|p| p > MAX_FORMATTED as i64)
        {
            return Err(unsupported("a field width or precision past the output limit".to_owned()));
        }
        // Integer size in bytes: int by default, long/size_t/pointer-sized for l z j t, 64-bit for ll.
        let mut size = 4u32;
        let mut narrow = 0u32;
        loop {
            match spec.get(index) {
                Some(b'h') => narrow += 1,
                Some(b'l') if spec.get(index + 1) == Some(&b'l') => {
                    size = 8;
                    index += 1;
                }
                Some(b'l' | b'z' | b't') => size = width,
                Some(b'j' | b'q' | b'L') => size = 8,
                _ => break,
            }
            index += 1;
        }
        let Some(&conversion) = spec.get(index) else { break };
        index += 1;
        let (body, sign_or_prefix): (Vec<u8>, String) = match conversion {
            b'%' => {
                out.push(b'%');
                continue;
            }
            b'd' | b'i' => {
                let raw = take(size)?;
                let value = match (narrow, size) {
                    (1, _) => i64::from(raw as u16 as i16),
                    (n, _) if n >= 2 => i64::from(raw as u8 as i8),
                    (_, 8) => raw as i64,
                    _ => i64::from(raw as u32 as i32),
                };
                let sign = if value < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                (digits(value.unsigned_abs().to_string(), precision).into_bytes(), sign.to_owned())
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = take(size)?;
                let value = match (narrow, size) {
                    (1, _) => raw & 0xffff,
                    (n, _) if n >= 2 => raw & 0xff,
                    (_, 8) => raw,
                    _ => raw & 0xffff_ffff,
                };
                let text = match conversion {
                    b'u' => value.to_string(),
                    b'x' => format!("{value:x}"),
                    b'X' => format!("{value:X}"),
                    _ => format!("{value:o}"),
                };
                let prefix = match conversion {
                    b'x' if alternate && value != 0 => "0x",
                    b'X' if alternate && value != 0 => "0X",
                    b'o' if alternate && !text.starts_with('0') => "0",
                    _ => "",
                };
                (digits(text, precision).into_bytes(), prefix.to_owned())
            }
            b'p' => {
                let value = take(width)?;
                if value == 0 {
                    (b"(nil)".to_vec(), String::new())
                } else {
                    (format!("{value:x}").into_bytes(), "0x".to_owned())
                }
            }
            b'c' => (vec![take(4)? as u8], String::new()),
            b's' => {
                let address = take(width)?;
                let mut text = if address == 0 {
                    b"(null)".to_vec()
                } else {
                    let limit = precision.map_or(MAX_FORMATTED as u64, |precision| precision as u64);
                    let mut bytes = Vec::new();
                    scan(ram, address, limit.min(MAX_FORMATTED as u64), limits, |_, chunk| {
                        bytes.extend_from_slice(chunk)
                    })?;
                    bytes
                };
                if let Some(precision) = precision {
                    text.truncate(precision as usize);
                }
                (text, String::new())
            }
            other => {
                return Err(unsupported(format!("conversion %{} is not modelled", char::from(other))));
            }
        };
        let content = sign_or_prefix.len() + body.len();
        let pad = field.map_or(0, |field| (field as usize).saturating_sub(content));
        let numeric = !matches!(conversion, b's' | b'c' | b'p');
        if left {
            out.extend_from_slice(sign_or_prefix.as_bytes());
            out.extend_from_slice(&body);
            out.extend(std::iter::repeat_n(b' ', pad));
        } else if zero && numeric && precision.is_none() {
            out.extend_from_slice(sign_or_prefix.as_bytes());
            out.extend(std::iter::repeat_n(b'0', pad));
            out.extend_from_slice(&body);
        } else {
            out.extend(std::iter::repeat_n(b' ', pad));
            out.extend_from_slice(sign_or_prefix.as_bytes());
            out.extend_from_slice(&body);
        }
    }
    Ok(out)
}

/// `text` (decimal or hex digits) padded with zeros to `precision` digits; precision 0 prints 0 as nothing.
fn digits(text: String, precision: Option<i64>) -> String {
    match precision {
        Some(0) if text == "0" => String::new(),
        Some(precision) if (precision as usize) > text.len() => {
            format!("{}{text}", "0".repeat(precision as usize - text.len()))
        }
        _ => text,
    }
}
