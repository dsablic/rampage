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
mod machine;
mod stubs;
#[cfg(test)]
mod tests;

pub use convention::Convention;
use convention::{Abi, Link, Place};
use machine::{Fault, Flow, Machine, Ram, SpaceIds, UserOp};
use stubs::{BYTES_PER_STEP, HEAP_BYTES, Heap, Stop, Stub};

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
/// Addresses below this are never mapped, so null-pointer accesses stop.
const NULL_GUARD: u64 = 0x1000;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    /// The function's entry: an address (hex) or a symbol name.
    pub at: String,
    /// Up to 16, in order: integers (number, or 0x-hex/decimal string; over 8 hex digits is 64-bit on 32-bit
    /// targets), {value, bits}, or {buffer: {hex | text, size}} passed by pointer (text gets a NUL).
    #[serde(default)]
    pub args: Vec<EvaluateArgument>,
    /// Calling convention; default is the binary's own.
    #[serde(default)]
    pub convention: Convention,
    /// Result width in bits (default the register width; 32 for an `int` on 64-bit targets; twice the register
    /// width reads a pair such as EDX:EAX or r1:r0).
    pub return_bits: Option<u32>,
    /// Up to 64 byte writes into the image (copy-on-write) before the run.
    #[serde(default)]
    pub memory: Vec<MemoryWrite>,
    /// Instruction budget (default 1000000, at most 20000000).
    pub max_steps: Option<u64>,
    /// Wall-clock milliseconds (default 10000, at most 60000).
    pub timeout_ms: Option<u64>,
    /// Model common C library imports (memcpy, strlen, strcmp, malloc, free, ...) instead of stopping at them
    /// (default true).
    pub stubs: Option<bool>,
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
    /// Bytes, at least the content (default the content, or 256), at most 1 MiB.
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryWrite {
    /// Address or symbol.
    pub address: String,
    pub hex: String,
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
    /// The integer result, present when the function returned.
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
}

#[derive(Debug, Serialize)]
pub struct ResultValue {
    pub bits: u32,
    pub hex: String,
    /// Decimal, as a number up to 64 bits and as a string beyond.
    pub unsigned: serde_json::Value,
    pub signed: serde_json::Value,
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
    Integer { value: u64, bytes: u32, negative: bool },
    Buffer(Vec<u8>),
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
                let size = buffer.size.unwrap_or(if content.is_empty() { 256 } else { content.len() });
                if size < content.len() || size == 0 || size > MAX_BUFFER_BYTES {
                    return Err(invalid(format!(
                        "buffer size must cover its content ({} bytes) and be 1..={MAX_BUFFER_BYTES}",
                        content.len()
                    )));
                }
                content.resize(size, 0);
                Ok(Prepared::Buffer(content))
            }
            _ => Err(invalid("an argument object takes exactly one of value or buffer")),
        },
    }
}

/// A mapped region outside the image: the stack, the thread block and argument buffers.
struct Region {
    start: u64,
    bytes: Vec<u8>,
}

struct Segment<'a> {
    start: u64,
    size: u64,
    file: &'a [u8],
    execute: bool,
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
    /// The library stand-ins' bump heap, reserving `HEAP_BYTES` of addresses from its base.
    heap: Option<Heap>,
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
                }
            })
            .collect();
        Self {
            segments,
            pages: HashMap::new(),
            regions: Vec::new(),
            pointer_bytes,
            big_endian: binary.big_endian,
            slots: HashMap::new(),
            written_slots: HashSet::new(),
            stand_ins: BTreeMap::new(),
            code_written: false,
            page_limit: MAX_WRITTEN_PAGES,
            heap: None,
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
        self.regions.push(Region { start, bytes });
    }

    fn segment(&self, address: u64) -> Option<&Segment<'a>> {
        if address < NULL_GUARD {
            return None;
        }
        self.segments.iter().find(|segment| address >= segment.start && address - segment.start < segment.size)
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
                Some(value) => *byte = value,
                None => {
                    if let Some(name) = self.stand_in(at) {
                        return Err(Fault::ExternalRead { address: at, name: name.clone() });
                    }
                    return Err(Fault::UnmappedRead { address: at, size: out.len() as u32 });
                }
            }
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault> {
        if let Some((region, offset)) = self.region_mut(address, bytes.len()) {
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
                return Err(Fault::UnmappedWrite { address: at, size: bytes.len() as u32 });
            };
            self.code_written |= segment.execute;
        }
        for (index, &byte) in bytes.iter().enumerate() {
            let at = address.wrapping_add(index as u64);
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
    /// ARM: whether the next instruction is Thumb, the decoder's current TMode and the TB register.
    thumb: bool,
    decoder_thumb: bool,
    mode_switch: Option<RegisterStorage>,
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
            self.decoder.set_context_variable("TMode", u32::from(self.thumb));
            self.decoder_thumb = self.thumb;
        }
        let mut bytes = Vec::with_capacity(16);
        for index in 0..16u64 {
            let mut byte = [0u8];
            if self.machine.ram.read(address.wrapping_add(index), &mut byte).is_err() {
                break;
            }
            bytes.push(byte[0]);
        }
        if bytes.is_empty() {
            return Err((StopReason::UnmappedFetch, format!("execution reached unmapped address {address:#x}")));
        }
        let decoded = self.decoder.decode_instruction(&bytes, address);
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
    fn call_import(&mut self, stub: Option<Stub>, abi: &Abi, name: &str, budget: u64) -> Result<(u64, u64), Stop> {
        let unreadable = |error: ApiError| (StopReason::UnsupportedOp, error.to_string());
        let outcome = match stub {
            Some(stub) => {
                let args: Vec<u64> =
                    self.arguments(abi, stub.arity(), true)?.into_iter().map(|(_, value)| value).collect();
                stubs::call(stub, &args, abi.width, &mut self.machine.ram, budget, name)?
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
        let binary = &self.binary;
        let replay = probe.and_then(|probe| probe.replay);
        let entry = match replay {
            Some((start, _)) => start,
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
        if request.memory.len() > MAX_MEMORY_WRITES {
            return Err(invalid(format!("at most {MAX_MEMORY_WRITES} memory writes")));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let target = binary.target();
        let big_endian = binary.big_endian;
        let abi = Abi::select(binary.arch, binary.format, big_endian, request.convention).map_err(invalid)?;
        let width = abi.width;
        let return_bits = request.return_bits.unwrap_or(width * 8);
        if return_bits == 0 || !return_bits.is_multiple_of(8) || return_bits > (2 * width * 8).min(128) {
            return Err(invalid(format!("return_bits must be a multiple of 8 up to {}", (2 * width * 8).min(128))));
        }
        let prepared = request.args.iter().map(|argument| prepare(argument, width)).collect::<Result<Vec<_>, _>>()?;
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
                ram.map(base, bytes.clone());
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
        let sentinel_candidates: Vec<u64> = if width >= 8 {
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

        let thumb = binary.arch == Arch::Arm
            && (entry & 1 == 1 || binary.thumb.iter().any(|range| range.contains(&(entry & !1))));
        let entry = if binary.arch == Arch::Arm { entry & !1 } else { entry };
        // Ghidra's ARM semantics record an interworking branch's instruction set in TB.
        let mode_switch = if binary.arch == Arch::Arm { decoder.register("TB") } else { None };
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
            mode_switch,
        };
        install_user_ops(&mut run, thread_base);

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
        let places = convention::assign(&abi, &widths, big_endian);
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
                Prepared::Buffer(content) => {
                    let address = buffer_addresses[index].expect("buffer address");
                    buffers.push((index, address, content.len()));
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
        let (stop, detail) = loop {
            if pc == sentinel {
                break (StopReason::Returned, "the function returned".to_owned());
            }
            if replay_return == Some(pc) {
                break (StopReason::Returned, "the replayed call returned".to_owned());
            }
            let stand_in = run.machine.ram.stand_in(pc).cloned();
            let stub = stand_in.as_deref().filter(|_| stub_abi.is_some()).and_then(stubs::lookup);
            // Replaying a caller, imports before the replayed call that have no model return 0.
            let skip = stub.is_none() && replay.is_some() && replay_return.is_none();
            if let Some(name) = &stand_in
                && stub.is_none()
                && !skip
            {
                break (StopReason::ExternalCall, format!("call to imported function {name}, outside the image"));
            }
            if steps >= max_steps {
                break (StopReason::StepLimit, format!("stopped after {max_steps} instructions (max_steps)"));
            }
            if (stand_in.is_some() || steps.is_multiple_of(4096)) && Instant::now() >= deadline {
                break (StopReason::Timeout, format!("stopped after {timeout_ms} ms (timeout_ms)"));
            }
            if let Some(name) = &stand_in {
                let budget = (max_steps - steps).saturating_mul(BYTES_PER_STEP);
                match run.call_import(stub, stub_abi.as_ref().unwrap_or(&abi), name, budget) {
                    Ok((target, cost)) => {
                        let rows = if stub.is_some() { &mut stubbed } else { &mut skipped };
                        match rows.iter_mut().find(|(seen, _)| seen == name) {
                            Some(row) => row.1 += 1,
                            None => rows.push((name.clone(), 1)),
                        }
                        steps = steps.saturating_add(cost);
                        pc = target;
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
            }
            last_text = Some(decoded.text.clone());
            if let Some(storage) = run.mode_switch {
                let _ = run.machine.write_int(&varnode(storage), u128::from(run.thumb));
            }
            match run.machine.execute(&decoded.ops) {
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
            if std::mem::take(&mut run.machine.ram.code_written) {
                run.cache.clear();
            }
            steps += 1;
        };

        let result = if stop == StopReason::Returned {
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
            .map(|(argument, address, size)| {
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
                    hex: bytes[..shown].iter().map(|byte| format!("{byte:02x}")).collect(),
                    text,
                    omitted_bytes: size - shown,
                }
            })
            .collect();
        skipped.truncate(MAX_CALL_ROWS);
        let mut probed = Probed { arguments: replay_arguments, texts: Vec::new(), skipped };
        if probe.is_some() && stop == StopReason::Returned {
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
                if let Some(text) = self.probed_text(&mut run.machine.ram, address) {
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
            detail,
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
        };
        Ok((report, probed))
    }

    /// The printable NUL-terminated string at `address` after a run, unless the file holds the same bytes there.
    fn probed_text(&self, ram: &mut ImageRam<'_>, address: u64) -> Option<String> {
        let mut bytes = Vec::new();
        while bytes.len() < PROBED_TEXT_BYTES {
            let mut byte = [0u8];
            ram.read(address.wrapping_add(bytes.len() as u64), &mut byte).ok()?;
            if byte[0] == 0 {
                break;
            }
            bytes.push(byte[0]);
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

fn width_mask(width: u32) -> u64 {
    if width >= 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 }
}

/// User operations without effect on a single thread's results.
const NO_EFFECT_USER_OPS: [&str; 12] = [
    "setISAMode",
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

fn install_user_ops(run: &mut Run<'_>, thread_base: u64) {
    let thread_selectors: Vec<(u32, u64)> = ["FS", "GS"]
        .iter()
        .filter_map(|name| run.decoder.register(name))
        .map(|storage| (storage.space, storage.offset))
        .collect();
    for index in 0..1024u32 {
        let Some(name) = run.decoder.user_op_name(index) else {
            break;
        };
        let op = if name == "segment" {
            UserOp::Segment { thread_selectors: thread_selectors.clone(), thread_base: thread_base + THREAD_BYTES / 2 }
        } else if NO_EFFECT_USER_OPS.contains(&name.as_str()) {
            UserOp::Nop(name)
        } else {
            UserOp::Other(name)
        };
        run.machine.set_user_op(u64::from(index), op);
    }
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
        registers,
        low_32: None,
    }
}
