//! Built-in models of common C library functions, run in place of an imported function's code so a run continues
//! through ordinary string and memory handling instead of stopping at the import.

use std::collections::HashMap;

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

fn read(ram: &mut ImageRam<'_>, address: u64, length: u64) -> Result<Vec<u8>, Stop> {
    let mut out = vec![0; length as usize];
    let mut done = 0u64;
    while done < length {
        let size = (length - done).min(CHUNK);
        let chunk = &mut out[done as usize..(done + size) as usize];
        if ram.read(address.wrapping_add(done), chunk).is_err() {
            // Byte by byte, so the fault names the first unreadable byte.
            for (index, byte) in chunk.iter_mut().enumerate() {
                let mut one = [0u8];
                ram.read(address.wrapping_add(done + index as u64), &mut one).map_err(fault_stop)?;
                *byte = one[0];
            }
        }
        done += size;
    }
    Ok(out)
}

fn write(ram: &mut ImageRam<'_>, address: u64, bytes: &[u8]) -> Result<(), Stop> {
    for (index, chunk) in bytes.chunks(CHUNK as usize).enumerate() {
        let at = address.wrapping_add(index as u64 * CHUNK);
        if ram.write(at, chunk).is_err() {
            for (offset, byte) in chunk.iter().enumerate() {
                ram.write(at.wrapping_add(offset as u64), &[*byte]).map_err(fault_stop)?;
            }
        }
    }
    Ok(())
}

/// The bytes of the string at `address` without its NUL, reading at most `limit` bytes (then without a NUL).
fn string(ram: &mut ImageRam<'_>, address: u64, limit: u64, budget: u64, name: &str) -> Result<Vec<u8>, Stop> {
    let mut out = Vec::new();
    while (out.len() as u64) < limit {
        if out.len() as u64 >= budget {
            return Err(over_budget(name));
        }
        let mut byte = [0u8];
        ram.read(address.wrapping_add(out.len() as u64), &mut byte).map_err(fault_stop)?;
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    Ok(out)
}

fn over_budget(name: &str) -> Stop {
    (StopReason::StepLimit, format!("library stand-in {name} ran past the remaining step budget (max_steps)"))
}

fn sign(value: i64) -> u64 {
    value as u64
}

fn compare(a: &[u8], b: &[u8]) -> u64 {
    match a.iter().zip(b).find(|(x, y)| x != y) {
        Some((x, y)) => sign(i64::from(*x) - i64::from(*y)),
        None => sign(a.len().cmp(&b.len()) as i64),
    }
}

/// Runs `stub` on `args` (each masked to the pointer width). `budget` bounds the bytes it may touch; `name` is the
/// import called, for stop details.
pub(super) fn call(
    stub: Stub,
    args: &[u64],
    width: u32,
    ram: &mut ImageRam<'_>,
    budget: u64,
    name: &str,
) -> Result<Outcome, Stop> {
    let mask = if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
    let arg = |index: usize| args.get(index).copied().unwrap_or(0) & mask;
    let int = |index: usize| i64::from(arg(index) as u32 as i32);
    let sized = |length: u64| if length > budget { Err(over_budget(name)) } else { Ok(length) };
    let outcome = |value: u64, bytes: u64| Ok(Outcome { value: value & mask, bytes });
    match stub {
        Stub::Memcpy | Stub::Memmove => {
            let length = sized(arg(2))?;
            let bytes = read(ram, arg(1), length)?;
            write(ram, arg(0), &bytes)?;
            outcome(arg(0), length)
        }
        Stub::Memset => {
            let length = sized(arg(2))?;
            write(ram, arg(0), &vec![arg(1) as u8; length as usize])?;
            outcome(arg(0), length)
        }
        Stub::Memcmp => {
            let length = sized(arg(2))?;
            let (a, b) = (read(ram, arg(0), length)?, read(ram, arg(1), length)?);
            outcome(compare(&a, &b), length)
        }
        Stub::Strlen => {
            let text = string(ram, arg(0), u64::MAX, budget, name)?;
            outcome(text.len() as u64, text.len() as u64)
        }
        Stub::Strnlen => {
            let text = string(ram, arg(0), arg(1), budget, name)?;
            outcome(text.len() as u64, text.len() as u64)
        }
        Stub::Strcpy => {
            let mut text = string(ram, arg(1), u64::MAX, budget, name)?;
            text.push(0);
            write(ram, arg(0), &text)?;
            outcome(arg(0), text.len() as u64)
        }
        Stub::Strncpy => {
            let limit = sized(arg(2))?;
            let mut text = string(ram, arg(1), limit, budget, name)?;
            text.resize(limit as usize, 0);
            write(ram, arg(0), &text)?;
            outcome(arg(0), limit)
        }
        Stub::Strcmp | Stub::Strncmp => {
            let limit = if stub == Stub::Strncmp { arg(2) } else { u64::MAX };
            let a = string(ram, arg(0), limit, budget, name)?;
            let b = string(ram, arg(1), limit, budget, name)?;
            let touched = (a.len() + b.len()) as u64;
            outcome(compare(&a, &b), touched)
        }
        Stub::Strchr | Stub::Strrchr => {
            let text = string(ram, arg(0), u64::MAX, budget, name)?;
            let wanted = arg(1) as u8;
            let found = if wanted == 0 {
                Some(text.len())
            } else if stub == Stub::Strchr {
                text.iter().position(|&byte| byte == wanted)
            } else {
                text.iter().rposition(|&byte| byte == wanted)
            };
            outcome(found.map_or(0, |offset| arg(0).wrapping_add(offset as u64)), text.len() as u64)
        }
        Stub::Strcat => {
            let head = string(ram, arg(0), u64::MAX, budget, name)?;
            let mut tail = string(ram, arg(1), u64::MAX, budget, name)?;
            tail.push(0);
            write(ram, arg(0).wrapping_add(head.len() as u64), &tail)?;
            outcome(arg(0), (head.len() + tail.len()) as u64)
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
            // Heap memory starts zeroed and is never reused.
            let address = ram.allocate(total, &format!("{name}({}, {})", arg(0), arg(1)))?;
            outcome(address, total)
        }
        Stub::Realloc => {
            let (old, size) = (arg(0), arg(1));
            let address = ram.allocate(size, &format!("{name}({old:#x}, {size})"))?;
            if old != 0 {
                let previous = ram.heap.as_ref().and_then(|heap| heap.sizes.get(&old).copied()).ok_or_else(|| {
                    (StopReason::UnsupportedOp, format!("{name} of {old:#x}, which is not a live heap block"))
                })?;
                let bytes = read(ram, old, previous.min(size))?;
                write(ram, address, &bytes)?;
                if let Some(heap) = ram.heap.as_mut() {
                    heap.sizes.remove(&old);
                }
                return outcome(address, previous.min(size));
            }
            outcome(address, 0)
        }
        Stub::Free => {
            if let Some(heap) = ram.heap.as_mut() {
                heap.sizes.remove(&arg(0));
            }
            outcome(0, 0)
        }
    }
}
