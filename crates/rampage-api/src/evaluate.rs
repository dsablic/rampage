//! `evaluate_function`: run one function of the image on given integer and buffer arguments with a p-code
//! interpreter over the bundled Sleigh decoder, and report what it returns. Nothing executes natively.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use rampage_arch::Arch;
use rampage_decompiler::sleigh_decode::{DecodeStatus, PcodeOp, RegisterStorage, SleighDecoder, Varnode};
use rampage_loaders::Binary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiError, Project};

mod convention;
mod float;
mod machine;
mod stubs;
#[cfg(test)]
mod tests;
mod userops;
#[cfg(test)]
mod vector_tests;
mod xtensa;

pub use convention::Convention;
use convention::{Abi, Link, Place};
use machine::{Fault, Flow, Machine, Ram, SpaceIds, UserOp, WriteLog};
use stubs::{BYTES_PER_STEP, HEAP_BYTES, Heap, Limits, Stop, Stub};

pub const DEFAULT_MAX_STEPS: u64 = 1_000_000;
pub const MAX_STEPS: u64 = 20_000_000;
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
pub const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_ARGUMENTS: usize = 16;
const MAX_BUFFER_BYTES: usize = 1 << 20;
const MAX_BUFFERS_TOTAL: usize = 4 << 20;
const MAX_MEMORY_WRITES: usize = 64;
const MAX_MEMORY_WRITE_BYTES: usize = 1 << 20;
/// Buffer bytes returned across all buffers; the rest are counted in `omitted_bytes`.
const RETURNED_BUFFER_BYTES: usize = 16 * 1024;
const MAX_CALL_ROWS: usize = 32;
const STACK_BYTES: u64 = 1 << 20;
const THREAD_BYTES: u64 = 0x2000;
const MAX_CACHED_INSTRUCTIONS: usize = 1 << 18;
const PAGE: u64 = 4096;
/// Copy-on-write image pages a run may create (64 MiB).
const MAX_WRITTEN_PAGES: usize = 16 * 1024;
/// Addresses below this are unmapped, so null-pointer accesses stop, unless the image is linked to run there.
const NULL_GUARD: u64 = 0x1000;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    /// The function's entry: an address (hex) or a symbol name.
    pub at: String,
    /// Up to 16, in order: integers (number, or 0x-hex/decimal string; over 8 hex digits is 64-bit on 32-bit
    /// targets), {value, bits}, {float, bits: 32|64} (a double by default), or {buffer: {hex | text, size}} passed
    /// by pointer (text gets a NUL).
    #[serde(default)]
    pub args: Vec<EvaluateArgument>,
    /// Calling convention; default is the binary's own.
    #[serde(default)]
    pub convention: Convention,
    /// Result width in bits (default the register width; 32 for an `int` on 64-bit targets; twice the register
    /// width reads a pair such as EDX:EAX or r1:r0).
    pub return_bits: Option<u32>,
    /// Read a 32-bit (float) or 64-bit (double) float result instead of an integer.
    pub return_float: Option<u32>,
    /// Up to 64 byte writes into the image (copy-on-write) before the run.
    #[serde(default)]
    pub memory: Vec<MemoryWrite>,
    /// Up to 64 memory-mapped registers {at, value}, each mapping its 4 KiB page as RAM.
    #[serde(default)]
    pub mmio: Vec<MmioValue>,
    /// Instruction budget (default 1000000, at most 20000000).
    pub max_steps: Option<u64>,
    /// Wall-clock milliseconds (default 10000, at most 60000).
    pub timeout_ms: Option<u64>,
    /// Model common C library imports (memcpy, strlen, strcmp, malloc, free, ...) instead of stopping at them
    /// (default true).
    pub stubs: Option<bool>,
    /// Trace the first and last N (1-32) executed instructions with what each wrote.
    pub trace: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum EvaluateArgument {
    Integer(IntegerText),
    Detailed(DetailedArgument),
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetailedArgument {
    pub value: Option<IntegerText>,
    pub bits: Option<u32>,
    pub buffer: Option<BufferArgument>,
    /// A float argument: a number, or a string (decimal, inf, -inf, nan, or 0x hex of its bits).
    pub float: Option<FloatText>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum FloatText {
    Number(f64),
    Text(String),
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum IntegerText {
    Unsigned(u64),
    Signed(i64),
    Text(String),
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BufferArgument {
    pub hex: Option<String>,
    pub text: Option<String>,
    /// Bytes (default the content, or 256), at most 1 MiB; a smaller size takes the content's.
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryWrite {
    /// Address or symbol.
    pub address: String,
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MmioValue {
    pub at: String,
    pub value: IntegerText,
}

/// Why the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The function returned to the sentinel return address.
    Returned,
    StepLimit,
    Timeout,
    /// A read outside the image, the stack and the argument buffers.
    UnmappedRead,
    UnmappedWrite,
    /// Control reached an address with no image bytes.
    UnmappedFetch,
    /// A call or jump to an imported function, which lies outside the image.
    ExternalCall,
    /// A read of an imported object's data, which lies outside the image.
    ExternalRead,
    /// A p-code operation the interpreter does not implement.
    UnsupportedOp,
    /// A processor-specific operation (CALLOTHER): system calls, traps, special registers.
    UserOp,
    InvalidInstruction,
    DivisionByZero,
    /// The run wrote more image pages than the copy-on-write cap (64 MiB).
    MemoryLimit,
}

#[derive(Debug, Serialize)]
pub struct EvaluateReport {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub convention: String,
    pub stop: StopReason,
    /// One sentence naming the operation, import or address behind `stop`.
    pub detail: String,
    /// Instructions executed, including those of called functions.
    pub steps: u64,
    /// The result, present when the function returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultValue>,
    /// Where execution stopped, unless it returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<StoppedAt>,
    pub arguments: Vec<ArgumentPlacement>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub buffers: Vec<BufferResult>,
    /// Functions called during the run, by first call, with call counts.
    pub calls: Vec<CallRow>,
    pub calls_omitted: usize,
    /// Imports run by a built-in library model instead of stopping the run, with call counts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stubbed: Vec<StubRow>,
    #[serde(skip_serializing_if = "is_zero")]
    pub stubbed_omitted: usize,
    pub max_steps: u64,
    pub timeout_ms: u64,
    /// With `trace`: the first and last executed instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Trace>,
}

#[derive(Debug, Serialize)]
pub struct Trace {
    pub first: Vec<TraceRow>,
    /// The last instructions, after `omitted` others; empty when `first` holds the whole run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub last: Vec<TraceRow>,
    pub omitted: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceRow {
    pub step: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub instruction: String,
    /// What it wrote: `REGISTER=value` and `[address]=value` (stores), space-separated, after it ran.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub writes: String,
}

/// Instructions a trace keeps at each end.
const MAX_TRACE: u32 = 32;
/// Characters of one trace row's writes; longer ones end in `...`.
const TRACE_WRITES_CHARS: usize = 200;

#[derive(Debug, Serialize)]
pub struct ResultValue {
    pub bits: u32,
    pub hex: String,
    /// Decimal, as a number up to 64 bits and as a string beyond; absent for a float result.
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub unsigned: serde_json::Value,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub signed: serde_json::Value,
    /// A float result (return_float) in decimal, the shortest text that reads back as the same value (`hex` holds
    /// its bits); `inf`, `-inf` and `NaN` as such.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub float: Option<String>,
    /// The registers read, high half first for a pair.
    pub registers: Vec<String>,
    /// Without return_bits on a target wider than 32 bits: the low 32 bits, the value of a C int or bool result,
    /// whose upper register bits are undefined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_32: Option<LowView>,
}

#[derive(Debug, Serialize)]
pub struct LowView {
    pub hex: String,
    pub unsigned: serde_json::Value,
    pub signed: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct StoppedAt {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ArgumentPlacement {
    pub index: usize,
    /// A register, a register pair (high:low), or `stack+0xN` from the stack pointer at entry.
    pub location: String,
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct BufferResult {
    /// The argument this buffer was passed as.
    pub argument: usize,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: usize,
    /// The `size` asked for, when it was short of the content and the buffer took the content's length instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_size: Option<usize>,
    /// Final contents (the first bytes, within the shared budget).
    pub hex: String,
    /// The contents up to the first NUL, when that is printable UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub omitted_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct StubRow {
    pub name: String,
    pub count: u64,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Serialize)]
pub struct CallRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub count: u64,
}

/// One argument after parsing: an integer of `bytes` width, or a buffer.
enum Prepared {
    Integer {
        value: u64,
        bytes: u32,
        negative: bool,
    },
    /// A float's bits, of `bytes` (4 or 8).
    Float {
        bits: u64,
        bytes: u32,
    },
    Buffer(Vec<u8>),
}

/// A float argument's bits at `bits` width (32 or 64).
fn parse_float(value: &FloatText, bits: Option<u32>) -> Result<Prepared, ApiError> {
    let bytes = match bits {
        None | Some(64) => 8,
        Some(32) => 4,
        Some(other) => return Err(invalid(format!("a float argument's bits must be 32 or 64, not {other}"))),
    };
    let number = match value {
        FloatText::Number(number) => *number,
        FloatText::Text(text) => {
            let trimmed = text.trim();
            if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                let raw = u64::from_str_radix(&hex.replace('_', ""), 16)
                    .map_err(|_| invalid(format!("float argument {text:?} is not hex bits")))?;
                if bytes == 4 && raw > u64::from(u32::MAX) {
                    return Err(invalid(format!("float argument {text:?} has more than 32 bits")));
                }
                return Ok(Prepared::Float { bits: raw, bytes });
            }
            match trimmed.to_ascii_lowercase().as_str() {
                "inf" | "+inf" | "infinity" => f64::INFINITY,
                "-inf" | "-infinity" => f64::NEG_INFINITY,
                "nan" => f64::NAN,
                other => {
                    other.parse::<f64>().map_err(|_| invalid(format!("float argument {text:?} is not a number")))?
                }
            }
        }
    };
    let bits = if bytes == 4 { u64::from((number as f32).to_bits()) } else { number.to_bits() };
    Ok(Prepared::Float { bits, bytes })
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn parse_integer(text: &str) -> Result<(u64, bool, usize), ApiError> {
    let trimmed = text.trim().replace('_', "");
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest.to_owned()),
        None => (false, trimmed.clone()),
    };
    let (value, digits) = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        (u64::from_str_radix(hex, 16), hex.len())
    } else {
        (body.parse::<u64>(), 0)
    };
    let value = value.map_err(|_| invalid(format!("argument {text:?} is not an integer")))?;
    if negative && value > 1u64 << 63 {
        return Err(invalid(format!("argument {text:?} is below the 64-bit signed minimum")));
    }
    Ok((if negative { value.wrapping_neg() } else { value }, negative, digits))
}

fn decode_hex(text: &str, what: &str) -> Result<Vec<u8>, ApiError> {
    let clean: String = text.chars().filter(|character| !character.is_whitespace()).collect();
    let clean = clean.strip_prefix("0x").unwrap_or(&clean);
    if !clean.len().is_multiple_of(2) {
        return Err(invalid(format!("{what} hex has an odd number of digits")));
    }
    (0..clean.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&clean[index..index + 2], 16).map_err(|_| invalid(format!("{what} is not valid hex")))
        })
        .collect()
}

fn prepare(argument: &EvaluateArgument, width: u32) -> Result<Prepared, ApiError> {
    let integer = |value: &IntegerText, bits: Option<u32>| -> Result<Prepared, ApiError> {
        let (value, negative, digits) = match value {
            IntegerText::Unsigned(value) => (*value, false, 0),
            IntegerText::Signed(value) => (*value as u64, *value < 0, 0),
            IntegerText::Text(text) => parse_integer(text)?,
        };
        let bytes = match bits {
            Some(bits @ (8 | 16 | 32 | 64)) => bits / 8,
            Some(bits) => return Err(invalid(format!("argument bits must be 8, 16, 32 or 64, not {bits}"))),
            None if width == 4 && (digits > 8 || (!negative && value > u64::from(u32::MAX))) => 8,
            None if width == 4 && negative && (value as i64) < i64::from(i32::MIN) => 8,
            None => width,
        };
        if negative && bytes == 8 && value != 0 && (value as i64) >= 0 {
            return Err(invalid(format!("argument {value:#x} does not fit in 64 signed bits")));
        }
        if bytes < 8 {
            let limit = 1u64 << (bytes * 8);
            let fits = if negative { (value as i64) >= -((limit / 2) as i64) } else { value < limit };
            if !fits {
                return Err(invalid(format!("argument {value:#x} does not fit in {} bits", bytes * 8)));
            }
        }
        Ok(Prepared::Integer { value, bytes, negative })
    };
    match argument {
        EvaluateArgument::Integer(value) => integer(value, None),
        EvaluateArgument::Detailed(detail) => match (&detail.value, &detail.buffer) {
            (None, None) if detail.float.is_some() => parse_float(detail.float.as_ref().expect("checked"), detail.bits),
            _ if detail.float.is_some() => {
                Err(invalid("an argument object takes exactly one of value, float or buffer"))
            }
            (Some(value), None) => integer(value, detail.bits),
            (None, Some(buffer)) => {
                if detail.bits.is_some() {
                    return Err(invalid("a buffer argument takes no bits"));
                }
                let mut content = match (&buffer.hex, &buffer.text) {
                    (Some(hex), None) => decode_hex(hex, "buffer")?,
                    (None, Some(text)) => text.bytes().chain([0]).collect(),
                    (None, None) => Vec::new(),
                    (Some(_), Some(_)) => return Err(invalid("a buffer takes hex or text, not both")),
                };
                // A size short of the content (text counts its NUL) takes the content's length.
                let size = match buffer.size {
                    Some(size) if size >= content.len() => size,
                    None if content.is_empty() => 256,
                    _ => content.len(),
                };
                if size == 0 || size > MAX_BUFFER_BYTES {
                    return Err(invalid(format!(
                        "buffer size must be 1..={MAX_BUFFER_BYTES} bytes (content: {})",
                        content.len()
                    )));
                }
                content.resize(size, 0);
                Ok(Prepared::Buffer(content))
            }
            _ => Err(invalid("an argument object takes exactly one of value, float or buffer")),
        },
    }
}

/// A mapped region outside the image: the stack, the thread block and argument buffers.
struct Region {
    start: u64,
    bytes: Vec<u8>,
    /// Bytes from the start a write may reach; reads reach all of `bytes`. An argument buffer reads to the end of
    /// its page, as aligned vector loads (SSE `strlen`) do on real memory, but writes stop at its size.
    writable: usize,
}

struct Segment<'a> {
    start: u64,
    size: u64,
    file: &'a [u8],
    execute: bool,
    /// Writable data (not code): what a run reads there may have been changed by earlier code.
    data: bool,
}

/// The image's segments (copy-on-write), the regions, and stand-in addresses for import slots.
struct ImageRam<'a> {
    segments: Vec<Segment<'a>>,
    pages: HashMap<u64, Box<[u8]>>,
    regions: Vec<Region>,
    pointer_bytes: u32,
    big_endian: bool,
    /// Import slot address to (stand-in address, import name).
    slots: HashMap<u64, u64>,
    /// Import slots the run wrote, which then read back as written.
    written_slots: HashSet<u64>,
    stand_ins: BTreeMap<u64, String>,
    code_written: bool,
    page_limit: usize,
    /// The address of the latest unmapped read or write, for naming the register a run stopped at.
    last_fault: Option<u64>,
    /// The library stand-ins' bump heap, reserving `HEAP_BYTES` of addresses from its base.
    heap: Option<Heap>,
    /// Addresses below this read as unmapped: `NULL_GUARD`, or 0 for an image linked to run at page 0.
    null_guard: u64,
    /// Code sections inside the null page of an ELF PIE or shared object (linked at 0, as GCC links MIPS PIEs),
    /// address 0 excluded: their instructions may be fetched, while loads, stores and other fetches there fault.
    guarded_code: Vec<std::ops::Range<u64>>,
    /// For a stateful run ([`Project::evaluate_stateful`]): which image bytes were written, and the reads of writable
    /// data no write set.
    track: Option<Tracking>,
}

/// Image bytes written in a stateful run (by its setup runs or itself), and reads of writable data that none wrote.
#[derive(Debug, Default)]
struct Tracking {
    /// Per image page, a bit per byte.
    written: HashMap<u64, Box<[u64; 64]>>,
    reads: DataReads,
}

/// Reads of writable data (not code) that no write of the run or its setup set, by kind: `unset` bytes have no
/// file contents (`.bss`, Raw RAM), so the program sets them at run time; `initial` bytes hold the file's initial
/// values, which the program may have changed before the call.
#[derive(Debug, Clone, Default)]
pub(crate) struct DataReads {
    /// The first distinct addresses (8-byte granules) of each kind.
    pub unset: Vec<u64>,
    pub initial: Vec<u64>,
    pub unset_count: u64,
    pub initial_count: u64,
}

/// Distinct read addresses [`DataReads`] keeps of each kind.
const MAX_DATA_READS: usize = 8;

/// The image as a stateful run left it: its written pages and which bytes were written, to start a later run from.
#[derive(Debug, Clone, Default)]
pub(crate) struct ImageState {
    pages: HashMap<u64, Box<[u8]>>,
    written: HashMap<u64, Box<[u64; 64]>>,
}

impl Tracking {
    fn set(&mut self, address: u64) {
        let bits = self.written.entry(address / PAGE).or_insert_with(|| Box::new([0; 64]));
        let offset = (address % PAGE) as usize;
        bits[offset / 64] |= 1 << (offset % 64);
    }

    fn is_set(&self, address: u64) -> bool {
        let offset = (address % PAGE) as usize;
        self.written.get(&(address / PAGE)).is_some_and(|bits| bits[offset / 64] & (1 << (offset % 64)) != 0)
    }

    fn note(&mut self, address: u64, unset: bool) {
        let (list, count) = if unset {
            (&mut self.reads.unset, &mut self.reads.unset_count)
        } else {
            (&mut self.reads.initial, &mut self.reads.initial_count)
        };
        *count += 1;
        let granule = address & !7;
        if list.len() < MAX_DATA_READS && !list.contains(&granule) {
            list.push(granule);
        }
    }
}

/// Whether the image is linked to run with mapped contents in page 0, as Cortex-M and other firmware images commonly
/// are (vector table and code from address 0): a fixed-address image (Raw, or an ELF executable) with a mapped
/// segment there. Page 0 of a shared object, PIE, PE or Mach-O dylib holds headers the loader relocates away, and
/// Mach-O's `__PAGEZERO` maps nothing, so those keep the null-page guard.
fn runs_at_page_zero(binary: &Binary, segments: &[Segment<'_>]) -> bool {
    let fixed_address = match &binary.details {
        rampage_loaders::Details::Elf(elf) => elf.kind == "executable",
        _ => binary.format == rampage_loaders::Format::Raw,
    };
    fixed_address && segments.iter().any(|segment| segment.start < NULL_GUARD)
}

impl<'a> ImageRam<'a> {
    fn new(binary: &'a Binary, pointer_bytes: u32) -> Self {
        let image = binary.image_bytes();
        let segments = binary
            .segments
            .iter()
            // A segment with no permissions (Mach-O __PAGEZERO) reserves addresses; it maps nothing.
            .filter(|segment| segment.size > 0 && (segment.perms.read || segment.perms.write || segment.perms.execute))
            .map(|segment| {
                let start = usize::try_from(segment.file_offset).unwrap_or(usize::MAX).min(image.len());
                let length = usize::try_from(segment.file_size.min(segment.size)).unwrap_or(usize::MAX);
                let end = start.saturating_add(length).min(image.len());
                Segment {
                    start: segment.address,
                    size: segment.size,
                    file: &image[start..end],
                    execute: segment.perms.execute,
                    data: segment.perms.write && !segment.perms.execute,
                }
            })
            .collect::<Vec<_>>();
        let null_guard = if runs_at_page_zero(binary, &segments) { 0 } else { NULL_GUARD };
        let position_independent =
            matches!(&binary.details, rampage_loaders::Details::Elf(elf) if elf.kind == "shared");
        let guarded_code = if position_independent && null_guard > 0 {
            binary
                .code_ranges()
                .iter()
                .filter(|range| range.start < null_guard)
                .map(|range| range.start.max(1)..range.end.min(null_guard))
                .filter(|range| !range.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        Self {
            segments,
            null_guard,
            guarded_code,
            pages: HashMap::new(),
            regions: Vec::new(),
            pointer_bytes,
            big_endian: binary.big_endian,
            slots: HashMap::new(),
            written_slots: HashSet::new(),
            stand_ins: BTreeMap::new(),
            code_written: false,
            page_limit: MAX_WRITTEN_PAGES,
            last_fault: None,
            heap: None,
            track: None,
        }
    }

    /// Notes a read of the image byte at `address`, which `segment` holds, in a stateful run.
    fn track_read(&mut self, address: u64) {
        let Some(track) = &self.track else { return };
        if track.is_set(address) {
            return;
        }
        let Some(segment) = self.segment(address).filter(|segment| segment.data) else { return };
        let unset = address - segment.start >= segment.file.len() as u64;
        if let Some(track) = &mut self.track {
            track.note(address, unset);
        }
    }

    fn overlaps(&self, start: u64, length: u64) -> bool {
        let end = start.saturating_add(length);
        self.segments.iter().any(|segment| start < segment.start.saturating_add(segment.size) && segment.start < end)
            || self.regions.iter().any(|region| start < region.start + region.bytes.len() as u64 && region.start < end)
            || self.stand_ins.range(start..end).next().is_some()
            || self.heap.as_ref().is_some_and(|heap| start < heap.base + HEAP_BYTES && heap.base < end)
    }

    /// A free, `PAGE`-aligned range of `length` bytes from the first candidate base that does not overlap.
    fn free_range(&self, candidates: &[u64], length: u64) -> Option<u64> {
        candidates.iter().copied().find(|&base| base.checked_add(length).is_some() && !self.overlaps(base, length))
    }

    fn map(&mut self, start: u64, bytes: Vec<u8>) {
        let writable = bytes.len();
        self.regions.push(Region { start, bytes, writable });
    }

    /// Maps `bytes` readable through the end of their last page and writable through their own length.
    fn map_buffer(&mut self, start: u64, mut bytes: Vec<u8>) {
        let writable = bytes.len();
        bytes.resize(writable.next_multiple_of(PAGE as usize), 0);
        self.regions.push(Region { start, bytes, writable });
    }

    fn segment(&self, address: u64) -> Option<&Segment<'a>> {
        if address < self.null_guard {
            return None;
        }
        self.segments.iter().find(|segment| address >= segment.start && address - segment.start < segment.size)
    }

    /// An instruction byte of a code section in the null page of an ELF PIE or shared object linked at 0, whose
    /// first functions can lie in page 0: fetching there runs the code, while loads and stores still fault as null
    /// dereferences, and so does a fetch from address 0 or from the headers (a call through a null pointer).
    fn fetch_guarded_byte(&self, address: u64) -> Option<u8> {
        if !self.guarded_code.iter().any(|range| range.contains(&address)) {
            return None;
        }
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.execute && address >= segment.start && address - segment.start < segment.size)?;
        if let Some(page) = self.pages.get(&(address / PAGE)) {
            return Some(page[(address % PAGE) as usize]);
        }
        Some(segment.file.get((address - segment.start) as usize).copied().unwrap_or(0))
    }

    fn region_mut(&mut self, address: u64, length: usize) -> Option<(&mut Region, usize)> {
        self.regions.iter_mut().find_map(|region| {
            let offset = address.checked_sub(region.start)?;
            (offset.checked_add(length as u64)? <= region.bytes.len() as u64).then_some((region, offset as usize))
        })
    }

    fn stand_in(&self, address: u64) -> Option<&String> {
        let (&start, name) = self.stand_ins.range(..=address).next_back()?;
        (address - start < 16).then_some(name)
    }

    fn read_image_byte(&self, address: u64) -> Option<u8> {
        // A written page may extend past its segment; only segment addresses are mapped.
        let segment = self.segment(address)?;
        if let Some(page) = self.pages.get(&(address / PAGE)) {
            return Some(page[(address % PAGE) as usize]);
        }
        Some(segment.file.get((address - segment.start) as usize).copied().unwrap_or(0))
    }
}

impl Ram for ImageRam<'_> {
    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), Fault> {
        if out.len() == self.pointer_bytes as usize
            && let Some(&stand_in) = self.slots.get(&address)
            && !self.written_slots.contains(&address)
        {
            let bytes = stand_in.to_le_bytes();
            out.copy_from_slice(&bytes[..out.len()]);
            if self.big_endian {
                out.reverse();
            }
            return Ok(());
        }
        if let Some((region, offset)) = self.region_mut(address, out.len()) {
            out.copy_from_slice(&region.bytes[offset..offset + out.len()]);
            return Ok(());
        }
        if let Some(bytes) = self.heap.as_mut().and_then(|heap| heap.slice(address, out.len())) {
            out.copy_from_slice(bytes);
            return Ok(());
        }
        for (index, byte) in out.iter_mut().enumerate() {
            let at = address.wrapping_add(index as u64);
            match self.read_image_byte(at) {
                Some(value) => {
                    *byte = value;
                    if self.track.is_some() {
                        self.track_read(at);
                    }
                }
                None => {
                    if let Some(name) = self.stand_in(at) {
                        return Err(Fault::ExternalRead { address: at, name: name.clone() });
                    }
                    self.last_fault = Some(at);
                    return Err(Fault::UnmappedRead { address: at, size: out.len() as u32 });
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault> {
        if let Some((region, offset)) = self.region_mut(address, bytes.len()) {
            if offset + bytes.len() > region.writable {
                let at = address.wrapping_add(region.writable.saturating_sub(offset) as u64);
                self.last_fault = Some(at);
                return Err(Fault::UnmappedWrite { address: at, size: bytes.len() as u32 });
            }
            region.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
            return Ok(());
        }
        if let Some(slice) = self.heap.as_mut().and_then(|heap| heap.slice(address, bytes.len())) {
            slice.copy_from_slice(bytes);
            return Ok(());
        }
        for index in 0..bytes.len() {
            let at = address.wrapping_add(index as u64);
            let Some(segment) = self.segment(at) else {
                self.last_fault = Some(at);
                return Err(Fault::UnmappedWrite { address: at, size: bytes.len() as u32 });
            };
            self.code_written |= segment.execute;
        }
        for (index, &byte) in bytes.iter().enumerate() {
            let at = address.wrapping_add(index as u64);
            if let Some(track) = &mut self.track {
                track.set(at);
            }
            for slot in at.saturating_sub(u64::from(self.pointer_bytes) - 1)..=at {
                if self.slots.contains_key(&slot) {
                    self.written_slots.insert(slot);
                }
            }
            let page_number = at / PAGE;
            if !self.pages.contains_key(&page_number) {
                if self.pages.len() + self.heap.as_ref().map_or(0, Heap::pages) >= self.page_limit {
                    return Err(Fault::MemoryLimit { pages: self.page_limit });
                }
                let page: Box<[u8]> =
                    (0..PAGE).map(|offset| self.read_image_byte(page_number * PAGE + offset).unwrap_or(0)).collect();
                self.pages.insert(page_number, page);
            }
            self.pages.get_mut(&page_number).expect("page just inserted")[(at % PAGE) as usize] = byte;
        }
        Ok(())
    }
}

struct Decoded {
    ops: Vec<PcodeOp>,
    extent: u64,
    text: String,
}

struct Run<'a> {
    project: &'a Project,
    decoder: SleighDecoder,
    machine: Machine<ImageRam<'a>>,
    cache: HashMap<(u64, bool), Rc<Decoded>>,
    /// ARM and MIPS16e images: whether the next instruction is in the alternate instruction set (Thumb, MIPS16e),
    /// the decoder's current mode, the context variable that selects it (`TMode`, `ISA_MODE`) and the register an
    /// interworking branch records the new mode in (`TB`, `ISAModeSwitch`).
    thumb: bool,
    decoder_thumb: bool,
    mode_variable: &'static str,
    mode_switch: Option<RegisterStorage>,
    /// The decoder's register space, and trace labels by (offset, size).
    register_space: u32,
    labels: HashMap<(u64, u32), String>,
    /// Whether decodes are extended (see `decode`).
    extended: bool,
}

fn varnode(storage: RegisterStorage) -> Varnode {
    Varnode {
        space: storage.space,
        size: storage.size,
        address_size: 0,
        word_size: 1,
        offset: Some(storage.offset),
        selected_space: None,
    }
}

impl Run<'_> {
    fn register(&self, name: &str) -> Result<RegisterStorage, ApiError> {
        self.decoder.register(name).ok_or_else(|| {
            ApiError::Unavailable(format!("the {} decoder has no register {name}", self.decoder.profile()))
        })
    }

    fn set_register(&mut self, name: &str, value: u128) -> Result<(), ApiError> {
        let storage = self.register(name)?;
        self.machine.write_int(&varnode(storage), value).map_err(|fault| invalid(format!("{fault:?}")))
    }

    fn get_register(&mut self, name: &str) -> Result<u128, ApiError> {
        let storage = self.register(name)?;
        self.machine.read_int(&varnode(storage)).map_err(|fault| invalid(format!("{fault:?}")))
    }

    fn decode(&mut self, address: u64) -> Result<Rc<Decoded>, (StopReason, String)> {
        let key = (address, self.thumb);
        if let Some(decoded) = self.cache.get(&key) {
            return Ok(Rc::clone(decoded));
        }
        if self.decoder_thumb != self.thumb {
            self.decoder.set_context_variable(self.mode_variable, u32::from(self.thumb));
            self.decoder_thumb = self.thumb;
        }
        let mut bytes = Vec::with_capacity(16);
        for index in 0..16u64 {
            let at = address.wrapping_add(index);
            let mut byte = [0u8];
            if self.machine.ram.read(at, &mut byte).is_err() {
                match self.machine.ram.fetch_guarded_byte(at) {
                    Some(value) => byte[0] = value,
                    None => break,
                }
            }
            bytes.push(byte[0]);
        }
        if bytes.is_empty() {
            return Err((StopReason::UnmappedFetch, format!("execution reached unmapped address {address:#x}")));
        }
        // Long p-code (AVX per-element operations) needs extended decoding; once a run has met it, every later
        // decode is extended, so none is decoded twice.
        let mut decoded = if self.extended {
            self.decoder.decode_instruction_extended(&bytes, address)
        } else {
            self.decoder.decode_instruction(&bytes, address)
        };
        if decoded.status == DecodeStatus::BudgetExceeded && !self.extended {
            self.extended = true;
            decoded = self.decoder.decode_instruction_extended(&bytes, address);
        }
        let text = format!("{} {}", decoded.mnemonic, decoded.operand_text).trim().to_owned();
        match decoded.status {
            DecodeStatus::Valid => {}
            DecodeStatus::UnimplementedPcode => {
                return Err((
                    StopReason::UnsupportedOp,
                    format!("the bundled Sleigh specification does not implement {text:?} at {address:#x}"),
                ));
            }
            status => {
                let reason = decoded.diagnostic.unwrap_or_else(|| format!("{status:?}"));
                return Err((
                    StopReason::InvalidInstruction,
                    format!("no valid instruction at {address:#x}: {reason}"),
                ));
            }
        }
        if let Some(unknown) =
            decoded.pcode.iter().find(|op| machine::opcode_name(op.opcode).is_some_and(|name| name != op.name))
        {
            return Err((
                StopReason::UnsupportedOp,
                format!("p-code opcode {} is named {} by the decoder", unknown.opcode, unknown.name),
            ));
        }
        let extent = u64::from(if decoded.translated_extent > 0 { decoded.translated_extent } else { decoded.length });
        let decoded = Rc::new(Decoded { ops: decoded.pcode, extent, text });
        if self.cache.len() >= MAX_CACHED_INSTRUCTIONS {
            self.cache.clear();
        }
        self.cache.insert(key, Rc::clone(&decoded));
        Ok(decoded)
    }

    /// The name of the register bytes at `offset`: the register's own name, or `NAME+offset:size` for part of one.
    fn label(&mut self, offset: u64, size: u32) -> String {
        if let Some(label) = self.labels.get(&(offset, size)) {
            return label.clone();
        }
        let label = match self.decoder.register_name(self.register_space, offset, size) {
            Some((name, base)) => {
                let whole = self.decoder.register(&name).is_some_and(|storage| storage.size == size);
                if base == offset && whole { name } else { format!("{name}+{}:{size}", offset.wrapping_sub(base)) }
            }
            None => format!("register[{offset:#x}:{size}]"),
        };
        self.labels.insert((offset, size), label.clone());
        label
    }

    /// One instruction's writes with their values after it ran, unnamed: a write inside a larger one of the same
    /// instruction is left out.
    fn capture(&mut self, log: &WriteLog) -> Writes {
        let registers = outermost(&log.registers)
            .into_iter()
            .map(|(offset, size)| {
                let node = Varnode {
                    space: self.register_space,
                    size,
                    address_size: 0,
                    word_size: 1,
                    offset: Some(offset),
                    selected_space: None,
                };
                (offset, size, self.machine.read_bytes(&node).ok())
            })
            .collect();
        let stores = outermost(&log.stores)
            .into_iter()
            .map(|(address, size)| {
                (address, size, (size <= 16).then(|| self.machine.read_memory(address, size).ok()).flatten())
            })
            .collect();
        Writes { registers, stores }
    }

    /// A kept trace row's writes as text: `REGISTER=value` and `[address]=value`, at most `TRACE_WRITES_CHARS`.
    fn describe(&mut self, writes: &Writes) -> String {
        let mut parts = Vec::new();
        for (offset, size, value) in &writes.registers {
            let value = value.as_deref().map_or_else(|| "?".to_owned(), hex_bytes);
            parts.push(format!("{}={value}", self.label(*offset, *size)));
        }
        for (address, size, value) in &writes.stores {
            let value = match value {
                Some(value) => short_hex(*value),
                None => format!("{size} bytes"),
            };
            parts.push(format!("[{address:#x}]={value}"));
        }
        let mut text = parts.join(" ");
        if text.len() > TRACE_WRITES_CHARS {
            let cut = (0..=TRACE_WRITES_CHARS).rev().find(|&at| text.is_char_boundary(at)).unwrap_or(0);
            text.truncate(cut);
            text.push_str("...");
        }
        text
    }

    /// The first `count` register-width arguments under `abi`, with their locations. `pushed` says whether an x86
    /// `call` has already pushed the return address.
    fn arguments(&mut self, abi: &Abi, count: usize, pushed: bool) -> Result<Vec<(String, u64)>, Stop> {
        let unreadable = |error: ApiError| (StopReason::UnsupportedOp, error.to_string());
        let width = abi.width;
        let sp = self.get_register(abi.stack_pointer).map_err(unreadable)? as u64;
        let return_address = if pushed && abi.link == Link::Stack { u64::from(width) } else { 0 };
        let first_stack = sp.wrapping_add(return_address + abi.stack_arguments);
        let mut values = Vec::with_capacity(count);
        for place in convention::assign(abi, &vec![width; count], self.machine.ram.big_endian) {
            let value = match place {
                Place::Register(name) => (name.to_owned(), self.get_register(name).map_err(unreadable)? as u64),
                Place::Stack(offset) => {
                    let address = first_stack.wrapping_add(offset);
                    let value = self.machine.read_memory(address, width).map_err(fault_stop)? as u64;
                    (format!("stack+{:#x}", address.wrapping_sub(sp)), value)
                }
                // Register-width arguments never take a pair.
                Place::Pair(..) | Place::Split(..) => break,
            };
            values.push(value);
        }
        Ok(values)
    }

    /// Runs the library model `stub` for the import `name` the run just reached (without one, the import returns
    /// 0), writes its result and returns to the caller. Returns the address returned to and the steps it costs.
    fn call_import(&mut self, stub: Option<Stub>, abi: &Abi, limits: &stubs::Limits<'_>) -> Result<(u64, u64), Stop> {
        let unreadable = |error: ApiError| (StopReason::UnsupportedOp, error.to_string());
        let outcome = match stub {
            Some(stub) => {
                let args: Vec<u64> = match stub.fixed_words() {
                    // Apple arm64 passes every variadic argument on the stack, in 8-byte slots.
                    Some(fixed) if abi.natural_stack_slots => {
                        let mut args: Vec<u64> =
                            self.arguments(abi, fixed, true)?.into_iter().map(|(_, value)| value).collect();
                        let sp = self.get_register(abi.stack_pointer).map_err(unreadable)? as u64;
                        for index in 0..stubs::VARIADIC_WORDS as u64 {
                            args.push(self.machine.read_memory(sp + 8 * index, 8).map_err(fault_stop)? as u64);
                        }
                        args
                    }
                    _ => self.arguments(abi, stub.arity(), true)?.into_iter().map(|(_, value)| value).collect(),
                };
                stubs::call(stub, &args, abi.width, &mut self.machine.ram, limits)?
            }
            None => stubs::Outcome { value: 0, bytes: 0 },
        };
        self.set_register(abi.result.0, u128::from(outcome.value)).map_err(unreadable)?;
        let target = match abi.link {
            Link::Stack => {
                let sp = self.get_register(abi.stack_pointer).map_err(unreadable)? as u64;
                let target = self.machine.read_memory(sp, abi.width).map_err(fault_stop)? as u64;
                self.set_register(abi.stack_pointer, u128::from(sp.wrapping_add(u64::from(abi.width))))
                    .map_err(unreadable)?;
                target
            }
            Link::Register(link) => self.get_register(link).map_err(unreadable)? as u64,
        };
        let target = if self.mode_switch.is_some() {
            self.thumb = target & 1 == 1;
            target & !1
        } else {
            target
        };
        Ok((target, 1 + outcome.bytes / BYTES_PER_STEP))
    }
}

/// The stop a fault ends a run with.
fn fault_stop(fault: Fault) -> Stop {
    match fault {
        Fault::UnmappedRead { address, size } => {
            (StopReason::UnmappedRead, format!("{size}-byte read of unmapped address {address:#x}"))
        }
        Fault::UnmappedWrite { address, size } => {
            (StopReason::UnmappedWrite, format!("{size}-byte write to unmapped address {address:#x}"))
        }
        Fault::ExternalRead { name, .. } => {
            (StopReason::ExternalRead, format!("read of imported data {name}, which lies outside the image"))
        }
        Fault::Unsupported(what) => (StopReason::UnsupportedOp, format!("unsupported: {what}")),
        Fault::UserOp(name) => (
            StopReason::UserOp,
            format!("processor operation {name} (system call, trap or special register) is not interpreted"),
        ),
        Fault::DivisionByZero => (StopReason::DivisionByZero, "integer division by zero".to_owned()),
        Fault::MemoryLimit { pages } => (
            StopReason::MemoryLimit,
            format!("the run wrote more than {pages} image pages ({} MiB)", (pages as u64 * PAGE) >> 20),
        ),
        Fault::Malformed(what) => (StopReason::UnsupportedOp, format!("malformed p-code: {what}")),
    }
}

/// Candidate bases for synthetic regions, high in the address space first.
fn candidates(pointer_bytes: u32) -> Vec<u64> {
    if pointer_bytes >= 8 {
        (0..64u64).map(|index| 0x7ff0_0000_0000 - index * 0x1000_0000).collect()
    } else {
        (0..96u64).map(|index| 0xbff0_0000 - index * 0x0100_0000).collect()
    }
}

/// What a probing run (string_decoding's `evaluate`) also looks at.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Probe {
    /// Start at `.0`, a caller's code, and end when the call instruction at `.1` returns, instead of running a
    /// function from its entry to its return.
    pub replay: Option<(u64, u64)>,
    /// The encoded input (a blob address): output equal to or a prefix of its bytes is not decoded text.
    pub input: Option<u64>,
}

/// What a probing run found.
#[derive(Debug, Default)]
pub(crate) struct Probed {
    /// The replayed call's argument values, by location, when it was reached.
    pub arguments: Option<Vec<(String, u64)>>,
    /// Printable NUL-terminated strings, different from the file's bytes there, at the result or an argument.
    pub texts: Vec<ProbedText>,
    /// Imports without a model that a replay skipped (returning 0) before the replayed call, with call counts.
    pub skipped: Vec<(String, u64)>,
    /// A stateful run's image as it ended, and its reads of writable data nothing in it wrote.
    pub state: Option<ImageState>,
    pub reads: DataReads,
}

#[derive(Debug)]
pub(crate) struct ProbedText {
    /// `result`, an argument location, or `argument N`.
    pub source: String,
    pub address: u64,
    pub text: String,
}

/// Argument locations a replay reads at the call.
const REPLAY_ARGUMENTS: usize = 4;
/// Bytes of a probed string read; longer strings are cut.
const PROBED_TEXT_BYTES: usize = 256;
const MIN_PROBED_TEXT: usize = 4;
/// Frame-pointer registers a replay points into its stack, so a caller's frame-relative locals are mapped.
const FRAME_POINTERS: [&str; 7] = ["RBP", "EBP", "x29", "r11", "fp", "s0", "r31"];

impl Project {
    pub fn evaluate_function(&self, request: &EvaluateRequest) -> Result<EvaluateReport, ApiError> {
        self.evaluate_probed(request, None).map(|(report, _)| report)
    }

    /// `evaluate_function`, plus what `probe` asks for.
    pub(crate) fn evaluate_probed(
        &self,
        request: &EvaluateRequest,
        probe: Option<Probe>,
    ) -> Result<(EvaluateReport, Probed), ApiError> {
        self.evaluate_with(request, probe, None)
    }

    /// `evaluate_function` starting from `state` (the image as an earlier stateful run left it, or the file's for a
    /// default state), returning the image as this run leaves it and the reads of writable data that neither run
    /// wrote: a result that depends on them depends on what the program did before the call.
    pub(crate) fn evaluate_stateful(
        &self,
        request: &EvaluateRequest,
        state: &ImageState,
    ) -> Result<(EvaluateReport, ImageState, DataReads), ApiError> {
        let (report, probed) = self.evaluate_with(request, None, Some(state))?;
        Ok((report, probed.state.unwrap_or_default(), probed.reads))
    }

    fn evaluate_with(
        &self,
        request: &EvaluateRequest,
        probe: Option<Probe>,
        carried: Option<&ImageState>,
    ) -> Result<(EvaluateReport, Probed), ApiError> {
        let binary = &self.binary;
        let replay = probe.and_then(|probe| probe.replay);
        let entry = match replay {
            Some((start, _)) => start,
            // On Cortex-M a function pointer's Thumb bit names the code at the even address.
            None if binary.m_profile() => self.thumb_code_address(self.resolve(&request.at)?).0,
            None => self.resolve(&request.at)?,
        };
        let max_steps = request.max_steps.unwrap_or(DEFAULT_MAX_STEPS);
        if !(1..=MAX_STEPS).contains(&max_steps) {
            return Err(invalid(format!("max_steps must be 1..={MAX_STEPS}")));
        }
        let timeout_ms = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(invalid(format!("timeout_ms must be 1..={MAX_TIMEOUT_MS}")));
        }
        if request.args.len() > MAX_ARGUMENTS {
            return Err(invalid(format!("at most {MAX_ARGUMENTS} arguments")));
        }
        if request.memory.len() > MAX_MEMORY_WRITES || request.mmio.len() > MAX_MEMORY_WRITES {
            return Err(invalid(format!("at most {MAX_MEMORY_WRITES} memory writes")));
        }
        let target = binary.target();
        let big_endian = binary.big_endian;
        let convention = match request.convention {
            // An ARM ELF marked for the hard-float ABI passes floats in VFP registers.
            Convention::Default if binary.arch == Arch::Arm && elf_arm_hard_float(binary) => Convention::AapcsVfp,
            convention => convention,
        };
        let abi = Abi::select(binary.arch, binary.format, big_endian, convention).map_err(invalid)?;
        let width = abi.width;
        if request.return_float.is_some() && request.return_bits.is_some() {
            return Err(invalid("pass return_bits or return_float, not both"));
        }
        let float_result = match request.return_float {
            None => None,
            Some(bits @ (32 | 64)) => Some((bits, convention::float_result(&abi, bits / 8).map_err(invalid)?)),
            Some(bits) => return Err(invalid(format!("return_float must be 32 or 64, not {bits}"))),
        };
        let return_bits = request.return_bits.unwrap_or(width * 8);
        if return_bits == 0 || !return_bits.is_multiple_of(8) || return_bits > (2 * width * 8).min(128) {
            return Err(invalid(format!("return_bits must be a multiple of 8 up to {}", (2 * width * 8).min(128))));
        }
        let prepared = request.args.iter().map(|argument| prepare(argument, width)).collect::<Result<Vec<_>, _>>()?;
        // Floats that travel as integers (the x86-32 stack, ARM soft float) are integers from here on; their
        // placement still knows them as floats.
        let as_integers = abi.float == convention::FloatAbi::Integer;
        let floats: Vec<Option<u32>> = prepared
            .iter()
            .map(|argument| match argument {
                Prepared::Float { bytes, .. } => Some(*bytes),
                _ => None,
            })
            .collect();
        let prepared: Vec<Prepared> = prepared
            .into_iter()
            .map(|argument| match argument {
                Prepared::Float { bits, bytes } if as_integers => {
                    Prepared::Integer { value: bits, bytes, negative: false }
                }
                argument => argument,
            })
            .collect();
        let buffer_total: usize =
            prepared.iter().map(|argument| if let Prepared::Buffer(bytes) = argument { bytes.len() } else { 0 }).sum();
        if buffer_total > MAX_BUFFERS_TOTAL {
            return Err(invalid(format!("buffers may total at most {MAX_BUFFERS_TOTAL} bytes")));
        }

        let decoder = SleighDecoder::for_emulation(&target).map_err(|error| match error {
            rampage_decompiler::Error::UnsupportedArch(arch) => {
                ApiError::Invalid(format!("evaluate_function does not support {arch:?}"))
            }
            error => ApiError::Unavailable(format!("instruction decoder: {error}")),
        })?;
        // The timeout covers emulation, not building the decoder: a cold language load can take longer than a
        // short run's whole budget on a busy machine.
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let metadata = decoder.metadata().clone();
        let space = |name: &str| metadata.spaces.iter().find(|space| space.name == name).map(|space| space.id);
        let ram_id = metadata.code_space;
        let address_bytes =
            metadata.spaces.iter().find(|space| space.id == ram_id).map_or(width, |space| space.address_size);
        let space_ids = SpaceIds {
            constant: space("const").ok_or_else(|| ApiError::Unavailable("decoder lacks a constant space".into()))?,
            unique: space("unique").unwrap_or(u32::MAX - 1),
            register: space("register").unwrap_or(u32::MAX - 2),
            ram: ram_id,
            address_bytes,
        };

        let mut ram = ImageRam::new(binary, width);
        if let Some(state) = carried {
            ram.pages = state.pages.clone();
            ram.track = Some(Tracking { written: state.written.clone(), reads: DataReads::default() });
        }
        let bases = candidates(width);
        let stack_base = ram.free_range(&bases, STACK_BYTES).ok_or_else(|| invalid("no free range for the stack"))?;
        ram.map(stack_base, vec![0; STACK_BYTES as usize]);
        let thread_base =
            ram.free_range(&bases, THREAD_BYTES).ok_or_else(|| invalid("no free range for the thread block"))?;
        ram.map(thread_base, vec![0; THREAD_BYTES as usize]);
        let mut buffer_addresses = Vec::new();
        for argument in &prepared {
            if let Prepared::Buffer(bytes) = argument {
                // Each buffer is followed by an unmapped guard gap, so overruns stop instead of corrupting.
                let length = (bytes.len() as u64).next_multiple_of(PAGE) + PAGE;
                let base = ram.free_range(&bases, length).ok_or_else(|| invalid("no free range for a buffer"))?;
                ram.map_buffer(base, bytes.clone());
                buffer_addresses.push(Some(base));
            } else {
                buffer_addresses.push(None);
            }
        }
        let stand_in_base = ram
            .free_range(&bases, (binary.import_slots.len() as u64 * 16).max(16))
            .ok_or_else(|| invalid("no free range for import stand-ins"))?;
        for (index, slot) in binary.import_slots.iter().enumerate() {
            let stand_in = stand_in_base + index as u64 * 16;
            ram.slots.insert(slot.address, stand_in);
            ram.stand_ins.insert(stand_in, slot.name.clone());
        }
        // The library models use the binary's own convention, whatever the evaluated function's.
        let stub_abi = if request.stubs.unwrap_or(true) {
            Abi::select(binary.arch, binary.format, big_endian, Convention::Default).ok()
        } else {
            None
        };
        if stub_abi.is_some() {
            let base = ram.free_range(&bases, HEAP_BYTES).ok_or_else(|| invalid("no free range for the heap"))?;
            ram.heap = Some(Heap::new(base));
        }
        let sentinel_candidates: Vec<u64> = if binary.arch == Arch::Xtensa {
            // A windowed return keeps the top two bits of its own address (the window increment's place), so the
            // sentinel shares code's 0x4xxxxxxx quarter.
            vec![0x7fff_ff00, 0x5fff_ff00, 0x4fff_ff00]
        } else if width >= 8 {
            vec![0xffff_ffff_ffff_ff00, 0x7fff_ffff_ff00, 0x0fff_ffff_ff00]
        } else {
            vec![0xffff_ff00, 0x7fff_ff00, 0x0fff_ff00]
        };
        let sentinel = ram.free_range(&sentinel_candidates, 16).ok_or_else(|| invalid("no free sentinel address"))?;

        for write in &request.memory {
            let address = self.resolve(&write.address)?;
            let bytes = decode_hex(&write.hex, "memory write")?;
            if bytes.len() > MAX_MEMORY_WRITE_BYTES {
                return Err(invalid(format!("a memory write is at most {MAX_MEMORY_WRITE_BYTES} bytes")));
            }
            ram.write(address, &bytes)
                .map_err(|_| invalid(format!("memory write at {address:#x} is outside the image")))?;
        }
        for register in &request.mmio {
            let address = self.resolve(&register.at)?;
            let value = match &register.value {
                IntegerText::Unsigned(value) => *value,
                IntegerText::Signed(value) => *value as u64,
                IntegerText::Text(text) => parse_integer(text)?.0,
            };
            let size = self.register_bytes(address);
            let mut bytes = value.to_le_bytes()[..size].to_vec();
            if big_endian {
                bytes.reverse();
            }
            if ram.region_mut(address, size).is_none() {
                let page = address & !(PAGE - 1);
                if ram.overlaps(page, PAGE) {
                    return Err(invalid(format!("mmio address {address:#x} is inside the image; use memory")));
                }
                ram.map(page, vec![0; PAGE as usize]);
            }
            ram.write(address, &bytes).map_err(|_| invalid(format!("mmio value at {address:#x} crosses its page")))?;
        }

        let thumb = binary.arch == Arch::Arm
            && (entry & 1 == 1 || binary.thumb.iter().any(|range| range.contains(&(entry & !1))));
        // A MIPS16e entry: an odd address, a symbol's MIPS16e range, or the mode discovery learned there.
        let mips16 = binary.mips16() && {
            let even = entry & !1;
            let learned = || {
                self.analysis().is_ok_and(|analysis| {
                    let modes = &analysis.program.code_modes;
                    modes.binary_search_by_key(&even, |&(at, _)| at).is_ok_and(|index| modes[index].1)
                })
            };
            entry & 1 == 1 || binary.mips16_ranges().iter().any(|range| range.contains(&even)) || learned()
        };
        let thumb = thumb || mips16;
        let entry = if binary.has_code_modes() { entry & !1 } else { entry };
        // Ghidra's ARM semantics record an interworking branch's instruction set in TB, its MIPS ones in
        // ISAModeSwitch.
        let (mode_variable, mode_switch) = match binary.arch {
            Arch::Arm => ("TMode", decoder.register("TB")),
            Arch::Mips if binary.mips16() => ("ISA_MODE", decoder.register("ISAModeSwitch")),
            _ => ("TMode", None),
        };
        let mut decoder = decoder;
        if binary.arch == Arch::Arm {
            // Thumb IT blocks set the following instructions' conditions through context commits.
            decoder.keep_context_commits(true);
        }
        let mut run = Run {
            project: self,
            decoder,
            machine: Machine::new(space_ids, big_endian, ram),
            cache: HashMap::new(),
            thumb,
            decoder_thumb: false,
            mode_variable,
            mode_switch,
            register_space: space_ids.register,
            labels: HashMap::new(),
            extended: false,
        };
        let trace_length = match request.trace {
            None => None,
            Some(length @ 1..=MAX_TRACE) => Some(length as usize),
            Some(_) => return Err(invalid(format!("trace must be 1..={MAX_TRACE}"))),
        };
        let mut first_rows: Vec<RawRow> = Vec::new();
        let mut last_rows: std::collections::VecDeque<RawRow> = std::collections::VecDeque::new();
        let mut omitted_rows = 0u64;
        let mut record = |row: RawRow| {
            let Some(length) = trace_length else { return };
            if first_rows.len() < length {
                first_rows.push(row);
                return;
            }
            if last_rows.len() == length {
                last_rows.pop_front();
                omitted_rows += 1;
            }
            last_rows.push_back(row);
        };
        let family = match binary.arch {
            Arch::X86 | Arch::X86_64 => Some(userops::Family::X86),
            Arch::Arm => Some(userops::Family::Arm),
            _ => None,
        };
        run.machine.integer_indefinite = family == Some(userops::Family::X86);
        install_user_ops(&mut run, thread_base, family);

        // Arguments and the stack frame.
        let widths: Vec<u32> = prepared
            .iter()
            .map(|argument| match argument {
                Prepared::Integer { bytes, .. } if *bytes > width => 2 * width,
                // Apple arm64 packs stack arguments at their own size.
                Prepared::Integer { bytes, .. } if abi.natural_stack_slots => *bytes,
                _ => width,
            })
            .collect();
        let places = convention::assign_with_floats(&abi, &widths, &floats, big_endian).map_err(invalid)?;
        let stack_bytes: u64 = places
            .iter()
            .zip(&widths)
            .filter_map(|(place, &bytes)| match place {
                Place::Stack(offset) => Some(offset + u64::from(bytes)),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let frame = (abi.stack_arguments + stack_bytes + 0x100).next_multiple_of(abi.stack_alignment);
        let top = stack_base + STACK_BYTES - 0x1000;
        let aligned = (top - frame) & !(abi.stack_alignment - 1);
        // x86 `call` has pushed the return address just below the aligned argument area.
        let (sp, first_stack_argument) = match abi.link {
            Link::Stack => (aligned - u64::from(width), aligned + abi.stack_arguments),
            Link::Register(_) => (aligned, aligned + abi.stack_arguments),
        };
        let mut placements = Vec::new();
        let mut probed_arguments = Vec::new();
        let mut buffer_index = 0usize;
        let mut buffers = Vec::new();
        for (index, ((argument, place), &bytes)) in prepared.iter().zip(&places).zip(&widths).enumerate() {
            let (value, buffer) = match argument {
                Prepared::Integer { value, bytes: own, negative } => {
                    let extended = if *own < width && *negative
                        || (*own == 4 && width == 8 && abi.sign_extend_words && value & 0x8000_0000 != 0)
                    {
                        let shift = 64 - own * 8;
                        (((*value << shift) as i64) >> shift) as u64
                    } else if *own < 8 {
                        value & ((1u64 << (own * 8)) - 1)
                    } else {
                        *value
                    };
                    let masked = if bytes < 8 { extended & ((1u64 << (bytes * 8)) - 1) } else { extended };
                    (masked, None)
                }
                Prepared::Float { bits, .. } => (*bits, None),
                Prepared::Buffer(content) => {
                    let address = buffer_addresses[index].expect("buffer address");
                    // A size short of the content was enlarged to it; the result says what was asked for.
                    let requested = match request.args.get(index) {
                        Some(EvaluateArgument::Detailed(DetailedArgument {
                            buffer: Some(BufferArgument { size: Some(size), .. }),
                            ..
                        })) if *size < content.len() => Some(*size),
                        _ => None,
                    };
                    buffers.push((index, address, content.len(), requested));
                    buffer_index += 1;
                    (address, Some(buffer_index - 1))
                }
            };
            let location = match *place {
                Place::Register(name) => {
                    run.set_register(name, u128::from(value))?;
                    name.to_owned()
                }
                Place::Pair(low, high) => {
                    let half = 8 * width;
                    let low_mask = (1u64 << half) - 1;
                    run.set_register(low, u128::from(value & low_mask))?;
                    run.set_register(high, u128::from(value >> half))?;
                    format!("{high}:{low}")
                }
                Place::Split(low, offset) => {
                    let half = 8 * width;
                    run.set_register(low, u128::from(value & ((1u64 << half) - 1)))?;
                    let address = first_stack_argument + offset;
                    run.machine
                        .write_memory(address, width, u128::from(value >> half))
                        .map_err(|fault| invalid(format!("stack write failed: {fault:?}")))?;
                    format!("stack+{:#x}:{low}", address - sp)
                }
                Place::Stack(offset) => {
                    let address = first_stack_argument + offset;
                    run.machine
                        .write_memory(address, bytes, u128::from(value))
                        .map_err(|fault| invalid(format!("stack write failed: {fault:?}")))?;
                    format!("stack+{:#x}", address - sp)
                }
            };
            probed_arguments.push((format!("argument {index}"), value));
            placements.push(ArgumentPlacement { index, location, hex: format!("{value:#x}"), buffer });
        }
        run.set_register(abi.stack_pointer, u128::from(sp))?;
        match abi.link {
            Link::Stack => {
                run.machine
                    .write_memory(sp, width, u128::from(sentinel))
                    .map_err(|fault| invalid(format!("stack write failed: {fault:?}")))?;
            }
            Link::Register(name) => run.set_register(name, u128::from(sentinel))?,
        }
        for name in abi.entry_registers {
            run.set_register(name, u128::from(entry))?;
        }
        if let (Some(name), Some(pointer)) = (abi.global_pointer, binary.target().global_pointer) {
            run.set_register(name, u128::from(pointer))?;
        }
        for name in ["FS_OFFSET", "tpidr_el0"] {
            if let Some(storage) = run.decoder.register(name) {
                let _ = run.machine.write_int(&varnode(storage), u128::from(thread_base + THREAD_BYTES / 2));
            }
        }
        if abi.convention == Convention::Win64
            && let Some(storage) = run.decoder.register("GS_OFFSET")
        {
            let _ = run.machine.write_int(&varnode(storage), u128::from(thread_base + THREAD_BYTES / 2));
        }
        if replay.is_some() {
            for name in FRAME_POINTERS {
                if let Some(storage) = run.decoder.register(name).filter(|storage| storage.size == width) {
                    let _ = run.machine.write_int(&varnode(storage), u128::from(sp + 0x400));
                }
            }
        }

        // Interpret.
        let mut pc = entry;
        let mut steps = 0u64;
        let mut calls: Vec<(u64, u64)> = Vec::new();
        let mut call_index: HashMap<u64, usize> = HashMap::new();
        let mut last_text = None;
        let mut stubbed: Vec<(String, u64)> = Vec::new();
        let mut skipped: Vec<(String, u64)> = Vec::new();
        let mut replay_return = None;
        let mut replay_arguments = None;
        let stdcall_imports = binary.arch == Arch::X86 && binary.format == rampage_loaders::Format::Pe;
        // What the probed addresses held before the run (direct) or at the replayed call: the blob's bytes and each
        // argument's string, which decoded output must differ from.
        let mut snapshots: Vec<(u64, Vec<u8>)> = Vec::new();
        if let Some(probe) = probe {
            let addresses = probe.input.into_iter().chain(if replay.is_none() {
                probed_arguments.iter().map(|(_, value)| *value).collect()
            } else {
                Vec::new()
            });
            for address in addresses {
                snapshots.push((address, snapshot(&mut run.machine.ram, address)));
            }
        }
        let xtensa = binary.arch == Arch::Xtensa;
        let mut windows = xtensa::Windows::default();
        let (stop, detail) = loop {
            if pc == sentinel {
                break (StopReason::Returned, "the function returned".to_owned());
            }
            if xtensa && let Err(error) = windows.returned(&mut run, pc) {
                break (StopReason::UnsupportedOp, format!("register window: {error}"));
            }
            if replay_return == Some(pc) {
                break (StopReason::Returned, "the replayed call returned".to_owned());
            }
            let stand_in = run.machine.ram.stand_in(pc).cloned();
            let stub = stand_in.as_deref().filter(|_| stub_abi.is_some()).and_then(stubs::lookup);
            // Replaying a caller, imports before the replayed call that have no model return 0. Not on 32-bit
            // PE, where a stdcall import pops its own arguments and skipping it would leave the stack pointer off.
            let skip = stub.is_none() && replay.is_some() && replay_return.is_none();
            if let Some(name) = &stand_in
                && stub.is_none()
            {
                if !skip {
                    break (StopReason::ExternalCall, format!("call to imported function {name}, outside the image"));
                }
                if stdcall_imports {
                    break (
                        StopReason::ExternalCall,
                        format!(
                            "call to imported function {name} before the replayed call; on 32-bit PE an import may \
                             pop its own arguments, so it is not skipped"
                        ),
                    );
                }
            }
            if steps >= max_steps {
                break (StopReason::StepLimit, format!("stopped after {max_steps} instructions (max_steps)"));
            }
            if (stand_in.is_some() || steps.is_multiple_of(4096)) && Instant::now() >= deadline {
                break (StopReason::Timeout, format!("stopped after {timeout_ms} ms (timeout_ms)"));
            }
            if let Some(name) = &stand_in {
                if trace_length.is_some() {
                    run.machine.trace = Some(WriteLog::default());
                }
                let limits = Limits {
                    bytes: (max_steps - steps).saturating_mul(BYTES_PER_STEP),
                    deadline,
                    name: name.as_str(),
                    even_pairs: stub_abi.as_ref().unwrap_or(&abi).pair == convention::PairRule::Even
                        || stub_abi.as_ref().unwrap_or(&abi).positional_slots,
                };
                match run.call_import(stub, stub_abi.as_ref().unwrap_or(&abi), &limits) {
                    Ok((target, cost)) => {
                        if let Some(log) = run.machine.trace.take() {
                            let kind = if stub.is_some() { "model" } else { "skipped, returns 0" };
                            let writes = run.capture(&log);
                            record(RawRow {
                                step: steps,
                                address: pc,
                                instruction: format!("{name} ({kind})"),
                                writes,
                            });
                        }
                        let rows = if stub.is_some() { &mut stubbed } else { &mut skipped };
                        match rows.iter_mut().find(|(seen, _)| seen == name) {
                            Some(row) => row.1 += 1,
                            None => rows.push((name.clone(), 1)),
                        }
                        steps = steps.saturating_add(cost);
                        pc = target;
                        windows.returned_from_model();
                        continue;
                    }
                    Err(stop) => {
                        steps += 1;
                        break stop;
                    }
                }
            }
            let decoded = match run.decode(pc) {
                Ok(decoded) => decoded,
                Err(stop) => break stop,
            };
            if let Some((_, call)) = replay
                && call == pc
                && replay_return.is_none()
            {
                replay_return = Some(pc.wrapping_add(decoded.extent));
                replay_arguments = run.arguments(&abi, REPLAY_ARGUMENTS, false).ok();
                for &(_, address) in replay_arguments.iter().flatten() {
                    snapshots.push((address, snapshot(&mut run.machine.ram, address)));
                }
            }
            last_text = Some(decoded.text.clone());
            if let Some(storage) = run.mode_switch {
                let _ = run.machine.write_int(&varnode(storage), u128::from(run.thumb));
            }
            if trace_length.is_some() {
                run.machine.trace = Some(WriteLog::default());
            }
            let pending = if xtensa {
                match windows.before(&mut run, pc, decoded.extent, &decoded.text, binary.code_from(pc)) {
                    Ok(pending) => pending,
                    Err(error) => break (StopReason::UnsupportedOp, format!("register window: {error}")),
                }
            } else {
                xtensa::Pending::None
            };
            let executed = run.machine.execute(&decoded.ops);
            if let Some(log) = run.machine.trace.take() {
                let writes = run.capture(&log);
                record(RawRow { step: steps, address: pc, instruction: decoded.text.clone(), writes });
            }
            match executed {
                Ok(Flow::Next) => pc = pc.wrapping_add(decoded.extent),
                Ok(Flow::Jump { target, call }) => {
                    let mut target = target;
                    if let Some(storage) = run.mode_switch {
                        let switch = run.machine.read_int(&varnode(storage)).unwrap_or(0);
                        run.thumb = switch != 0 || target & 1 == 1;
                        target &= !1;
                    }
                    if call {
                        match call_index.get(&target) {
                            Some(&row) => calls[row].1 += 1,
                            None => {
                                call_index.insert(target, calls.len());
                                calls.push((target, 1));
                            }
                        }
                    }
                    pc = target;
                }
                Err(fault) => {
                    steps += 1;
                    break fault_stop(fault);
                }
            }
            if xtensa {
                let fell_through = matches!(executed, Ok(Flow::Next));
                match windows.after(&mut run, pending, fell_through, pc) {
                    Ok(next) => pc = next,
                    Err(error) => break (StopReason::UnsupportedOp, format!("register window: {error}")),
                }
            }
            if std::mem::take(&mut run.machine.ram.code_written) {
                run.cache.clear();
            }
            steps += 1;
        };

        let result = if stop == StopReason::Returned
            && let Some((bits, register)) = float_result
        {
            Some(read_float_result(&mut run, &abi, bits, register, big_endian)?)
        } else if stop == StopReason::Returned {
            let half = width * 8;
            let half_mask = (1u128 << half) - 1;
            let (value, registers) = if return_bits > half {
                let (low_name, high_name) = convention::result_pair(&abi, big_endian);
                let low = run.get_register(low_name)? & half_mask;
                let high = run.get_register(high_name)? & half_mask;
                ((high << half) | low, vec![high_name.to_owned(), low_name.to_owned()])
            } else {
                (run.get_register(abi.result.0)? & half_mask, vec![abi.result.0.to_owned()])
            };
            let mut result = result_value(value, return_bits, registers);
            if request.return_bits.is_none() && width * 8 > 32 {
                let low = result_value(value, 32, Vec::new());
                result.low_32 = Some(LowView { hex: low.hex, unsigned: low.unsigned, signed: low.signed });
            }
            Some(result)
        } else {
            None
        };
        let stopped_at = (stop != StopReason::Returned).then(|| StoppedAt {
            address: pc,
            instruction: last_text.filter(|_| !matches!(stop, StopReason::ExternalCall | StopReason::UnmappedFetch)),
            function: self.function_containing(pc).ok().flatten().map(|start| self.function_name(start)),
        });
        let mut budget = RETURNED_BUFFER_BYTES;
        let buffers = buffers
            .into_iter()
            .map(|(argument, address, size, requested_size)| {
                let mut bytes = vec![0; size];
                let _ = run.machine.ram.read(address, &mut bytes);
                let shown = size.min(budget);
                budget -= shown;
                let text = bytes
                    .iter()
                    .position(|&byte| byte == 0)
                    .and_then(|end| std::str::from_utf8(&bytes[..end]).ok())
                    .filter(|text| text.chars().all(|character| !character.is_control() || character == '\n'))
                    .map(|text| text.chars().take(1024).collect());
                BufferResult {
                    argument,
                    address,
                    size,
                    requested_size,
                    hex: bytes[..shown].iter().map(|byte| format!("{byte:02x}")).collect(),
                    text,
                    omitted_bytes: size - shown,
                }
            })
            .collect();
        skipped.truncate(MAX_CALL_ROWS);
        let mut probed = Probed { arguments: replay_arguments, texts: Vec::new(), skipped, ..Probed::default() };
        // A replay that returned without reaching its call ran past it some other way: nothing to probe.
        let reached = replay.is_none() || replay_return.is_some();
        if probe.is_some() && stop == StopReason::Returned && reached {
            let mut pointers = match &probed.arguments {
                Some(arguments) => arguments.clone(),
                None if replay.is_some() => Vec::new(),
                None => probed_arguments,
            };
            if let Ok(value) = run.get_register(abi.result.0) {
                pointers.insert(0, ("result".to_owned(), value as u64 & width_mask(width)));
            }
            for (source, address) in pointers {
                if probed.texts.iter().any(|text| text.address == address) {
                    continue;
                }
                if let Some(text) = self.probed_text(&mut run.machine.ram, address, &snapshots) {
                    probed.texts.push(ProbedText { source, address, text });
                }
            }
        }
        let stubbed_omitted = stubbed.len().saturating_sub(MAX_CALL_ROWS);
        let stubbed = stubbed.into_iter().take(MAX_CALL_ROWS).map(|(name, count)| StubRow { name, count }).collect();
        let calls_omitted = calls.len().saturating_sub(MAX_CALL_ROWS);
        let calls = calls
            .into_iter()
            .take(MAX_CALL_ROWS)
            .map(|(address, count)| CallRow {
                address,
                name: run.project.name_at(address).or_else(|| run.machine.ram.stand_in(address).cloned()),
                count,
            })
            .collect();
        let report = EvaluateReport {
            function: entry,
            name: self.name_at(entry),
            convention: abi.name(),
            stop,
            detail: self.name_unmapped_register(stop, detail, run.machine.ram.last_fault),
            steps,
            result,
            stopped_at,
            arguments: placements,
            buffers,
            calls,
            calls_omitted,
            stubbed,
            stubbed_omitted,
            max_steps,
            timeout_ms,
            trace: trace_length.map(|_| {
                let mut row = |raw: RawRow| TraceRow {
                    step: raw.step,
                    address: raw.address,
                    instruction: raw.instruction,
                    writes: run.describe(&raw.writes),
                };
                Trace {
                    first: first_rows.into_iter().map(&mut row).collect(),
                    last: last_rows.into_iter().map(&mut row).collect(),
                    omitted: omitted_rows,
                }
            }),
        };
        if let Some(track) = run.machine.ram.track.take() {
            probed.state =
                Some(ImageState { pages: std::mem::take(&mut run.machine.ram.pages), written: track.written });
            probed.reads = track.reads;
        }
        Ok((report, probed))
    }

    /// The printable NUL-terminated string at `address` after a run, unless the file holds the same bytes there,
    /// the address held it before (`snapshots`), or it is an input's bytes (equal to or a prefix of a snapshot).
    fn probed_text(&self, ram: &mut ImageRam<'_>, address: u64, snapshots: &[(u64, Vec<u8>)]) -> Option<String> {
        let bytes = snapshot(ram, address);
        if snapshots.iter().any(|(_, before)| before.starts_with(&bytes)) {
            return None;
        }
        let printable = |byte: &u8| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
        if bytes.len() < MIN_PROBED_TEXT || !bytes.iter().all(printable) {
            return None;
        }
        let unchanged = self.binary.read_to_segment_end(address).is_some_and(|file| {
            file.get(..bytes.len()) == Some(&bytes[..]) && file.get(bytes.len()).is_none_or(|&byte| byte == 0)
        });
        (!unchanged).then(|| String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// The bytes at `address` up to a NUL, an unreadable byte or `PROBED_TEXT_BYTES`.
fn snapshot(ram: &mut ImageRam<'_>, address: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < PROBED_TEXT_BYTES {
        let mut byte = [0u8];
        if ram.read(address.wrapping_add(bytes.len() as u64), &mut byte).is_err() || byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    bytes
}

/// What one traced instruction wrote, with the values after it ran: (register offset, bytes, little-endian
/// value) and (address, bytes, value up to 16 bytes).
#[derive(Debug, Default)]
struct Writes {
    registers: Vec<(u64, u32, Option<Vec<u8>>)>,
    stores: Vec<(u64, u32, Option<u128>)>,
}

/// A trace row before its writes are named and formatted.
struct RawRow {
    step: u64,
    address: u64,
    instruction: String,
    writes: Writes,
}

/// The distinct (start, length) ranges of `ranges` not inside another, in address order.
fn outermost(ranges: &[(u64, u32)]) -> Vec<(u64, u32)> {
    let mut sorted = ranges.to_vec();
    // Longest first at each start, so a range inside an earlier one is seen after it.
    sorted.sort_by_key(|&(start, length)| (start, std::cmp::Reverse(length)));
    sorted.dedup();
    let mut kept: Vec<(u64, u32)> = Vec::with_capacity(sorted.len());
    let mut end = 0u64;
    for (start, length) in sorted {
        let stop = start.saturating_add(u64::from(length));
        if kept.is_empty() || stop > end {
            kept.push((start, length));
            end = end.max(stop);
        }
    }
    kept
}

/// Little-endian `bytes` as one hex number, or a single decimal digit.
fn hex_bytes(bytes: &[u8]) -> String {
    let digits: String = bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect();
    let digits = digits.trim_start_matches('0');
    match digits {
        "" => "0".to_owned(),
        digit if digit.len() == 1 && digit.as_bytes()[0].is_ascii_digit() => digit.to_owned(),
        digits => format!("0x{digits}"),
    }
}

/// `value` in hex without leading zeros, or a single decimal digit.
fn short_hex(value: u128) -> String {
    if value < 10 { value.to_string() } else { format!("{value:#x}") }
}

fn width_mask(width: u32) -> u64 {
    if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 }
}

/// User operations without effect on a single thread's results.
const NO_EFFECT_USER_OPS: [&str; 19] = [
    "setISAMode",
    // Xtensa memory and instruction barriers, ordered already on one thread.
    "memw",
    "extw",
    "excw",
    "isync",
    "rsync",
    "esync",
    "dsync",
    "LOCK",
    "UNLOCK",
    "HintPreloadData",
    "HintPreloadDataForWrite",
    "HintPreloadInstruction",
    "HintYield",
    "DataMemoryBarrier",
    "DataSynchronizationBarrier",
    "InstructionSynchronizationBarrier",
    "SYNC",
    "sync",
];

/// Xtensa's register-window operations, as the compiler specification's fixups define them: `swapN` (before a
/// windowed call) saves the callee's a2/a3.. in t-registers and moves the caller's a(N+2).. into a2.., `restoreN`
/// (after it) moves the result back and restores them; `rotateRegWindow` and `restoreRegWindow` (`entry`, `retw`)
/// then have no effect. The registers a window rotates out and back are not modelled beyond that, as in decompiled
/// code.
fn xtensa_window_moves(run: &Run<'_>, name: &str) -> Option<Vec<(u64, u64, u32)>> {
    if run.decoder.profile() != "Xtensa:LE:32:default" {
        return None;
    }
    let pairs: &[(&str, &str)] = match name {
        "rotateRegWindow" | "restoreRegWindow" => &[],
        "swap4" => &[
            ("t2", "a2"),
            ("t3", "a3"),
            ("a2", "a6"),
            ("a3", "a7"),
            ("a4", "a8"),
            ("a5", "a9"),
            ("a6", "a10"),
            ("a7", "a11"),
        ],
        "restore4" => &[("a6", "a2"), ("a7", "a3"), ("a2", "t2"), ("a3", "t3")],
        "swap8" => &[
            ("t2", "a2"),
            ("t3", "a3"),
            ("t4", "a4"),
            ("t5", "a5"),
            ("t6", "a6"),
            ("t7", "a7"),
            ("a2", "a10"),
            ("a3", "a11"),
            ("a4", "a12"),
            ("a5", "a13"),
            ("a6", "a14"),
            ("a7", "a15"),
        ],
        "restore8" => &[
            ("a10", "a2"),
            ("a11", "a3"),
            ("a2", "t2"),
            ("a3", "t3"),
            ("a4", "t4"),
            ("a5", "t5"),
            ("a6", "t6"),
            ("a7", "t7"),
        ],
        "swap12" => &[("t2", "a2"), ("t3", "a3"), ("a2", "a14"), ("a3", "a15")],
        "restore12" => &[("a14", "a2"), ("a15", "a3"), ("a2", "t2"), ("a3", "t3")],
        _ => return None,
    };
    let mut moves = Vec::with_capacity(pairs.len());
    for (destination, source) in pairs {
        let destination = run.decoder.register(destination)?;
        let source = run.decoder.register(source)?;
        moves.push((destination.offset, source.offset, destination.size.min(source.size)));
    }
    Some(moves)
}

fn install_user_ops(run: &mut Run<'_>, thread_base: u64, family: Option<userops::Family>) {
    let thread_selectors: Vec<(u32, u64)> = ["FS", "GS"]
        .iter()
        .filter_map(|name| run.decoder.register(name))
        .map(|storage| (storage.space, storage.offset))
        .collect();
    for index in 0..1024u32 {
        let Some(name) = run.decoder.user_op_name(index) else {
            break;
        };
        let window = xtensa_window_moves(run, &name);
        let op = if let Some(moves) = window {
            UserOp::Moves(moves)
        } else if name == "segment" {
            UserOp::Segment { thread_selectors: thread_selectors.clone(), thread_base: thread_base + THREAD_BYTES / 2 }
        } else if NO_EFFECT_USER_OPS.contains(&name.as_str()) {
            UserOp::Nop(name)
        } else if let Some(family) = family.filter(|&family| userops::known(&name, family)) {
            UserOp::Computed(name, family)
        } else {
            UserOp::Other(name)
        };
        run.machine.set_user_op(u64::from(index), op);
    }
}

/// The float result of `bits` (32 or 64) from `register` (and whether it is the x87 ST0), or from the integer
/// result registers under ARM soft float.
fn read_float_result(
    run: &mut Run<'_>,
    abi: &Abi,
    bits: u32,
    register: Option<(&'static str, bool)>,
    big_endian: bool,
) -> Result<ResultValue, ApiError> {
    let format = if bits == 32 { float::SINGLE } else { float::DOUBLE };
    let mask = (1u128 << bits) - 1;
    let (raw, registers) = match register {
        Some((name, true)) => {
            let extended = run.get_register(name)? & ((1u128 << 80) - 1);
            (float::convert(extended, float::EXTENDED, format), vec![name.to_owned()])
        }
        Some((name, false)) => (run.get_register(name)? & mask, vec![name.to_owned()]),
        None if bits <= abi.width * 8 => (run.get_register(abi.result.0)? & mask, vec![abi.result.0.to_owned()]),
        None => {
            let (low, high) = convention::result_pair(abi, big_endian);
            let half = abi.width * 8;
            let word = (1u128 << half) - 1;
            let value = ((run.get_register(high)? & word) << half) | (run.get_register(low)? & word);
            (value, vec![high.to_owned(), low.to_owned()])
        }
    };
    let text = if bits == 32 {
        format!("{:?}", f32::from_bits(raw as u32))
    } else {
        format!("{:?}", f64::from_bits(raw as u64))
    };
    Ok(ResultValue {
        bits,
        hex: format!("{raw:#0width$x}", width = (bits / 4) as usize + 2),
        unsigned: serde_json::Value::Null,
        signed: serde_json::Value::Null,
        float: Some(text),
        registers,
        low_32: None,
    })
}

/// Whether an ARM ELF's header flags select the hard-float (VFP) procedure call standard.
fn elf_arm_hard_float(binary: &Binary) -> bool {
    const EF_ARM_ABI_FLOAT_HARD: u32 = 0x400;
    let bytes = binary.image_bytes();
    if binary.format != rampage_loaders::Format::Elf || bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&1) {
        return false;
    }
    let Some(flags) = bytes.get(0x24..0x28) else { return false };
    let flags = <[u8; 4]>::try_from(flags).expect("four bytes");
    let flags = if bytes.get(5) == Some(&2) { u32::from_be_bytes(flags) } else { u32::from_le_bytes(flags) };
    flags & EF_ARM_ABI_FLOAT_HARD != 0
}

fn result_value(value: u128, bits: u32, registers: Vec<String>) -> ResultValue {
    let mask = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
    let value = value & mask;
    let shift = 128 - bits;
    let signed = ((value << shift) as i128) >> shift;
    let unsigned = match u64::try_from(value) {
        Ok(value) => serde_json::Value::from(value),
        Err(_) => serde_json::Value::from(value.to_string()),
    };
    let signed = match i64::try_from(signed) {
        Ok(value) => serde_json::Value::from(value),
        Err(_) => serde_json::Value::from(signed.to_string()),
    };
    ResultValue {
        bits,
        hex: format!("{value:#0width$x}", width = (bits / 4) as usize + 2),
        unsigned,
        signed,
        float: None,
        registers,
        low_32: None,
    }
}
