//! Scatter-load copies for the `ARM:LE:32:Cortex` Raw profile: what the reset code copies to run addresses
//! before it jumps there.
//!
//! Startup code moves code and initialised data from their load addresses to the addresses they run at, and
//! zeroes `.bss`, in shapes that vary by toolchain: GCC-style loops over pairs of linker symbols, Arm's
//! `__scatterload` walking a `Region$$Table` of (load, run, size, handler) entries with copy, zero and decompress
//! handlers, and vendor routines called with constant (destination, length, source) triples. Matching each shape
//! would need a recogniser per toolchain, so the reset code is followed instead: a deterministic Thumb interpreter
//! over the mapped bytes, with no host effects, executes from the entry and records every store with the origin of
//! its bytes (a load from mapped bytes, zero, or computed). It stops at the first jump into memory the code wrote
//! (the copied code), a return from the entry, a halt, or its step budget. A call it cannot follow (an unsupported
//! instruction, a branch on a peripheral's value) is skipped with the caller's AAPCS view: r0-r3, r12, lr and the
//! flags become unknown and the call's earlier stores stand.
//!
//! Contiguous stores of one origin become one write: `copy` (bytes loaded in order from one mapped source), `zero`
//! or `computed`. Every bound is fixed: steps, writes, scattered bytes, kept computed bytes, call depth and listed
//! results, so a hostile image costs at most the step budget.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use rampage_arch::aarch32::{self, Decoded, ItState, Set};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Instructions followed from the entry.
pub const MAX_STEPS: u64 = 2_000_000;
/// Writes listed in the report; more are counted in `copies_not_listed`.
pub const MAX_LISTED_COPIES: usize = 64;
/// Separate writes tracked before the follow stops.
const MAX_WRITES: usize = 4096;
/// Bytes stored inside earlier writes or on the stack before the follow stops.
const MAX_SCATTERED_BYTES: usize = 1 << 16;
/// Computed bytes kept so later loads can read them back; beyond this they read as unknown.
const MAX_COMPUTED_BYTES: usize = 1 << 20;
const MAX_CALL_DEPTH: usize = 64;
const MAX_LISTED_SKIPPED_CALLS: usize = 16;
const MAX_DECODE_CACHE: usize = 1 << 16;
/// A write smaller than this, or of a single store, is a variable's assignment, not a section copy.
const MIN_WRITE_BYTES: u64 = 8;
/// Instructions between a write's last store and an abnormal stop within which it counts as interrupted.
const INTERRUPTED_WINDOW: u64 = 16;
/// The value of `lr` at reset on Cortex-M: a return to it leaves the entry.
const RESET_LR: u32 = 0xffff_ffff;
/// The stack pointer the follow starts with. Its value only names stack slots: stores through any value derived
/// from `sp` stay on a private stack and never become writes.
const STACK_TOP: u32 = 0x2000_8000;
/// Recent follows kept, keyed by the mapped bytes and the entry, since every Raw tool call admits its image again.
const MEMO_FOLLOWS: usize = 8;
/// The Cortex-M Vector Table Offset Register.
pub const VTOR: u64 = 0xe000_ed08;

/// A mapped region as the follow reads it.
pub(crate) struct Mapped<'a> {
    pub range: Range<u64>,
    pub bytes: Option<&'a [u8]>,
    pub code: bool,
}

/// How a write's bytes were produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyKind {
    /// Every byte was loaded, in order, from `source` onwards in a mapped region.
    Copy,
    /// Every byte is zero (`.bss`).
    Zero,
    /// Bytes the code computed (a decompressor's output, values read from a peripheral or from unmapped memory).
    Computed,
}

/// Why the follow stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FollowStop {
    /// It jumped into memory it had written: the copied code (`continues_at`).
    JumpedIntoCopiedCode,
    /// The entry returned (to the reset `lr`).
    Returned,
    /// A branch to itself, `wfi`, or a halt instruction at the entry's level.
    Halted,
    /// The step budget ran out.
    StepBudget,
    /// An instruction the follow does not model, at the entry's level.
    UnsupportedInstruction,
    /// A branch whose condition or target depends on an unknown value (a peripheral, unmapped memory).
    UnknownBranch,
    /// A store through an address that depends on an unknown value.
    UnknownStoreAddress,
    /// An instruction fetch from unmapped memory, or a switch to the A32 state Cortex-M lacks.
    BadFetch,
    /// More separate writes, or bytes stored inside earlier writes, than the follow tracks.
    TooManyWrites,
    /// Calls nested deeper than 64.
    CallDepth,
}

impl FollowStop {
    /// Whether the follow ended the way startup code ends, so the writes it saw are the whole startup work.
    fn clean(self) -> bool {
        matches!(self, Self::JumpedIntoCopiedCode | Self::Returned | Self::Halted)
    }
}

/// Why a detected write was not mapped as a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotMappedReason {
    /// `scatter_load` is false: reported only.
    NotRequested,
    /// The follow stopped while the write was still in progress (step budget, unsupported instruction, ...).
    Incomplete,
    /// Later stores changed some of its bytes.
    Overwritten,
    /// Its bytes are computed, not copied from mapped bytes or zero.
    ComputedBytes,
    /// Its source is not wholly inside one backed region.
    SourceNotMapped,
    /// Its destination overlaps a mapped region.
    DestinationMapped,
    /// The project already maps 16 regions.
    RegionLimit,
    /// Mapping it would exceed the profile's backed-byte cap.
    ByteLimit,
    /// Its destination range leaves the 32-bit address space.
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyStatus {
    /// Mapped as the region `region`.
    Mapped,
    /// Reported only; `not_mapped_reason` says why.
    NotMapped,
}

/// One write the startup code made: a copy, a zero fill or computed bytes, and the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScatterCopy {
    pub kind: CopyKind,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub destination: u64,
    pub length: u64,
    /// First source byte of a copy.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub source: Option<u64>,
    /// The mapped region holding the source, and the source's byte offset in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    /// Store instructions executed for it.
    pub stores: u64,
    /// The store instructions, up to four.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub store_sites: Vec<u64>,
    /// The entry-level call during which it was written and the routine called, when not written by the entry's
    /// own code.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub call_site: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub routine: Option<u64>,
    /// Instructions were fetched from it: the copied code ran.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub executed: bool,
    pub status: CopyStatus,
    /// The region it is mapped as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_mapped_reason: Option<NotMappedReason>,
}

/// A call the follow could not complete and skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedCall {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub call_site: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub target: u64,
    pub reason: FollowStop,
    /// The instruction where the callee could not continue.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub at: u64,
}

/// A constant store to the Vector Table Offset Register the follow saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VtorStore {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
    /// The store instruction.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
}

/// What following the reset code from the entry found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScatterLoad {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub entry: u64,
    /// Instructions executed.
    pub steps: u64,
    pub stop: FollowStop,
    /// The instruction the follow stopped at.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub stopped_at: u64,
    /// Where the code jumped into memory it had copied; seeded as a function start when that memory is mapped.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub continues_at: Option<u64>,
    /// Writes of at least 8 bytes by more than one store, in the order they began.
    pub copies: Vec<ScatterCopy>,
    pub copies_not_listed: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_calls: Vec<SkippedCall>,
    #[serde(skip_serializing_if = "is_zero")]
    pub skipped_calls_not_listed: usize,
    /// Constant VTOR stores, in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vtor_stores: Vec<VtorStore>,
    pub note: &'static str,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

const NOTE: &str = "the reset code is followed by a bounded Thumb interpreter over the mapped bytes until it jumps into \
                    memory it wrote, returns or halts; contiguous stores of one origin are one write. A copy whose \
                    source lies in one backed region and whose destination is unmapped is mapped at its run address \
                    (code below 0x20000000 or when it ran, writable RAM otherwise), a zero fill as unbacked RAM";

/// What [`follow`] returns besides the report: each listed write's internal facts.
#[derive(Debug, Clone)]
pub(crate) struct Follow {
    pub report: ScatterLoad,
    /// Per listed copy: whether the follow ended cleanly and the write was not interrupted or overwritten.
    pub complete: Vec<bool>,
    pub overwritten: Vec<bool>,
}

type MemoKey = [u8; 32];
static MEMO: Mutex<Vec<(MemoKey, Arc<Follow>)>> = Mutex::new(Vec::new());
thread_local! {
    static FOLLOWS: Cell<usize> = const { Cell::new(0) };
}

/// Full follows run on this thread; a repeated interpretation is served from the memo without one.
pub fn follows_run() -> usize {
    FOLLOWS.with(Cell::get)
}

/// Follows the reset code at `entry` over `memory` with the default step budget. The result is a function of the
/// mapped ranges, their bytes and the entry, so a recent identical follow is reused.
pub(crate) fn follow(memory: &[Mapped<'_>], entry: u64) -> Follow {
    follow_with_budget(memory, entry, MAX_STEPS)
}

pub(crate) fn follow_with_budget(memory: &[Mapped<'_>], entry: u64, budget: u64) -> Follow {
    let mut hash = Sha256::new();
    hash.update(entry.to_be_bytes());
    hash.update(budget.to_be_bytes());
    for region in memory {
        hash.update(region.range.start.to_be_bytes());
        hash.update(region.range.end.to_be_bytes());
        hash.update([u8::from(region.code), u8::from(region.bytes.is_some())]);
        if let Some(bytes) = region.bytes {
            hash.update(Sha256::digest(bytes));
        }
    }
    let key: MemoKey = hash.finalize().into();
    {
        let mut memo = MEMO.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = memo.iter().position(|(cached, _)| *cached == key) {
            let entry = memo.remove(index);
            let found = Follow::clone(&entry.1);
            memo.push(entry);
            return found;
        }
    }
    FOLLOWS.with(|follows| follows.set(follows.get() + 1));
    let result = Arc::new(Machine::new(memory, entry).run(budget));
    let mut memo = MEMO.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    memo.push((key, Arc::clone(&result)));
    if memo.len() > MEMO_FOLLOWS {
        memo.remove(0);
    }
    Follow::clone(&result)
}

/// Where a byte's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    None,
    /// Part of a stack pointer.
    Stack,
    /// Loaded from this address of mapped bytes.
    From(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Byte {
    value: Option<u8>,
    origin: Origin,
}

/// What a register's value is known to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Plain,
    /// Derived from `sp`: it names a stack slot.
    Stack,
    /// Loaded unchanged from `width` mapped bytes at `from`.
    Loaded {
        from: u32,
        width: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    Unknown,
    Known(u32, Tag),
}

impl Val {
    fn plain(value: u32) -> Self {
        Val::Known(value, Tag::Plain)
    }

    fn get(self) -> Option<u32> {
        match self {
            Val::Known(value, _) => Some(value),
            Val::Unknown => None,
        }
    }

    fn stack(self) -> bool {
        matches!(self, Val::Known(_, Tag::Stack))
    }

    fn byte(self, index: u32) -> Byte {
        match self {
            Val::Unknown => Byte { value: None, origin: Origin::None },
            Val::Known(value, tag) => Byte {
                value: Some((value >> (8 * index)) as u8),
                origin: match tag {
                    Tag::Plain => Origin::None,
                    Tag::Stack => Origin::Stack,
                    Tag::Loaded { from, width } if index < u32::from(width) => Origin::From(from.wrapping_add(index)),
                    Tag::Loaded { .. } => Origin::None,
                },
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    n: Option<bool>,
    z: Option<bool>,
    c: Option<bool>,
    v: Option<bool>,
}

impl Flags {
    fn condition(self, condition: u32) -> Option<bool> {
        let result = match condition >> 1 {
            0 => self.z?,
            1 => self.c?,
            2 => self.n?,
            3 => self.v?,
            4 => self.c? && !self.z?,
            5 => self.n? == self.v?,
            6 => !self.z? && self.n? == self.v?,
            _ => return Some(true),
        };
        Some(if condition & 1 == 1 && condition != 15 { !result } else { result })
    }
}

/// One write: contiguous stores of one origin.
#[derive(Debug, Clone)]
struct Write {
    start: u32,
    length: u32,
    /// Still a copy: the first byte came from here and every later byte from the following addresses.
    copy_from: Option<u32>,
    /// Still all zero.
    zero: bool,
    /// Neither a copy nor zero from its first store.
    computed: bool,
    /// A computed write's bytes, while within the kept-bytes budget.
    values: Option<Vec<u8>>,
    stores: u64,
    sites: Vec<u32>,
    /// The entry-level call during which it began: (call site, target).
    call: Option<(u32, u32)>,
    last_store: u64,
    overwritten: bool,
    /// A skipped call was still making it.
    interrupted: bool,
    executed: bool,
}

impl Write {
    fn end(&self) -> u64 {
        u64::from(self.start) + u64::from(self.length)
    }

    fn contains(&self, address: u32) -> bool {
        address >= self.start && u64::from(address) < self.end()
    }
}

struct Frame {
    return_to: u32,
    call_site: u32,
    target: u32,
    /// The caller's registers and flags at an entry-level call, restored when the call is skipped.
    saved: Option<([Val; 16], Flags)>,
}

type Step = Result<(), FollowStop>;

fn stop(reason: FollowStop) -> FollowStop {
    reason
}

struct Machine<'a> {
    memory: &'a [Mapped<'a>],
    regs: [Val; 16],
    flags: Flags,
    it: ItState,
    pc: u32,
    writes: Vec<Write>,
    starts: BTreeMap<u32, usize>,
    scattered: HashMap<u32, Byte>,
    computed_bytes: usize,
    frames: Vec<Frame>,
    steps: u64,
    cache: HashMap<u32, Option<Decoded>>,
    skipped: Vec<SkippedCall>,
    skipped_total: usize,
    vtor: Vec<VtorStore>,
    continues_at: Option<u32>,
}

fn unsupported() -> FollowStop {
    stop(FollowStop::UnsupportedInstruction)
}

/// ThumbExpandImm_C: the modified immediate of `imm12` and the carry it produces.
fn expand_imm(imm12: u32, carry: Option<bool>) -> (u32, Option<bool>) {
    let imm8 = imm12 & 0xff;
    if imm12 >> 10 == 0 {
        let value = match (imm12 >> 8) & 3 {
            0 => imm8,
            1 => imm8 << 16 | imm8,
            2 => imm8 << 24 | imm8 << 8,
            _ => imm8 * 0x0101_0101,
        };
        (value, carry)
    } else {
        let value = (0x80 | (imm12 & 0x7f)).rotate_right(imm12 >> 7);
        (value, Some(value >> 31 == 1))
    }
}

/// Shift_C for shift type `kind` (LSL, LSR, ASR, ROR) by `amount`.
fn shift(value: u32, kind: u32, amount: u32, carry: Option<bool>) -> (u32, Option<bool>) {
    if amount == 0 {
        return (value, carry);
    }
    let bit = |index: u32| Some((value >> index) & 1 == 1);
    match kind {
        0 => match amount {
            1..=31 => (value << amount, bit(32 - amount)),
            32 => (0, bit(0)),
            _ => (0, Some(false)),
        },
        1 => match amount {
            1..=31 => (value >> amount, bit(amount - 1)),
            32 => (0, bit(31)),
            _ => (0, Some(false)),
        },
        2 => match amount {
            1..=31 => (((value as i32) >> amount) as u32, bit(amount - 1)),
            _ => (((value as i32) >> 31) as u32, bit(31)),
        },
        _ => {
            let result = value.rotate_right(amount % 32);
            (result, Some(result >> 31 == 1))
        }
    }
}

/// DecodeImmShift without RRX: the shift type and amount of an immediate shift.
fn imm_shift(kind: u32, imm5: u32) -> (u32, u32) {
    match (kind, imm5) {
        (1 | 2, 0) => (kind, 32),
        _ => (kind, imm5),
    }
}

fn add_with_carry(x: u32, y: u32, carry: bool) -> (u32, bool, bool) {
    let unsigned = u64::from(x) + u64::from(y) + u64::from(carry);
    let signed = i64::from(x as i32) + i64::from(y as i32) + i64::from(carry);
    let result = unsigned as u32;
    (result, u64::from(result) != unsigned, i64::from(result as i32) != signed)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alu {
    Add,
    Sub,
    Rsb,
    And,
    Orr,
    Orn,
    Eor,
    Bic,
    Mov,
    Mvn,
    Mul,
}

fn field(decoded: &Decoded, name: &str) -> u32 {
    decoded.field(name).unwrap_or(0) as u32
}

/// Peripheral and system space: stores there are device writes, never memory a later load reads back.
fn device(address: u32) -> bool {
    (0x4000_0000..0x6000_0000).contains(&address) || address >= 0xa000_0000
}

impl<'a> Machine<'a> {
    fn new(memory: &'a [Mapped<'a>], entry: u64) -> Self {
        let mut regs = [Val::Unknown; 16];
        regs[13] = Val::Known(STACK_TOP, Tag::Stack);
        regs[14] = Val::plain(RESET_LR);
        Self {
            memory,
            regs,
            flags: Flags::default(),
            it: ItState::default(),
            pc: (entry & !1) as u32,
            writes: Vec::new(),
            starts: BTreeMap::new(),
            scattered: HashMap::new(),
            computed_bytes: 0,
            frames: Vec::new(),
            steps: 0,
            cache: HashMap::new(),
            skipped: Vec::new(),
            skipped_total: 0,
            vtor: Vec::new(),
            continues_at: None,
        }
    }

    fn mapped(&self, address: u32) -> Option<&Mapped<'a>> {
        self.memory.iter().find(|region| region.range.contains(&u64::from(address)))
    }

    /// The byte the program reads at `address`: its latest store, else the mapped bytes.
    fn byte(&self, address: u32) -> Byte {
        if let Some(byte) = self.scattered.get(&address) {
            return *byte;
        }
        if let Some(write) = self.write_at(address) {
            let offset = address - write.start;
            if let Some(from) = write.copy_from {
                return self.original(from.wrapping_add(offset));
            }
            if write.zero {
                return Byte { value: Some(0), origin: Origin::None };
            }
            let value = write.values.as_ref().and_then(|values| values.get(offset as usize).copied());
            return Byte { value, origin: Origin::None };
        }
        self.original(address)
    }

    /// The mapped byte at `address` before any store.
    fn original(&self, address: u32) -> Byte {
        let value = self.mapped(address).and_then(|region| {
            let bytes = region.bytes?;
            bytes.get((u64::from(address) - region.range.start) as usize).copied()
        });
        let origin = if value.is_some() { Origin::From(address) } else { Origin::None };
        Byte { value, origin }
    }

    fn write_at(&self, address: u32) -> Option<&Write> {
        let (_, &index) = self.starts.range(..=address).next_back()?;
        let write = &self.writes[index];
        write.contains(address).then_some(write)
    }

    fn load(&self, address: Val, width: u8, signed: bool) -> Val {
        let Some(address) = address.get() else {
            return Val::Unknown;
        };
        if address.checked_add(u32::from(width) - 1).is_none()
            || (device(address) && self.mapped(address).is_none() && !self.scattered.contains_key(&address))
        {
            return Val::Unknown;
        }
        let mut value = 0u32;
        let mut origins = Vec::with_capacity(usize::from(width));
        for index in 0..u32::from(width) {
            let byte = self.byte(address + index);
            let Some(part) = byte.value else {
                return Val::Unknown;
            };
            value |= u32::from(part) << (8 * index);
            origins.push(byte.origin);
        }
        if signed && width < 4 {
            let shift = 32 - 8 * u32::from(width);
            value = (((value << shift) as i32) >> shift) as u32;
        }
        let tag = if origins.iter().all(|origin| *origin == Origin::Stack) && width == 4 {
            Tag::Stack
        } else if let Origin::From(from) = origins[0]
            && !signed
            && origins
                .iter()
                .enumerate()
                .all(|(index, origin)| *origin == Origin::From(from.wrapping_add(index as u32)))
        {
            Tag::Loaded { from, width }
        } else {
            Tag::Plain
        };
        Val::Known(value, tag)
    }

    fn store(&mut self, address: Val, width: u8, value: Val, site: u32) -> Step {
        let Some(base) = address.get() else {
            return Err(stop(FollowStop::UnknownStoreAddress));
        };
        if base.checked_add(u32::from(width) - 1).is_none() {
            return Err(stop(FollowStop::UnknownStoreAddress));
        }
        let bytes: Vec<Byte> = (0..u32::from(width)).map(|index| value.byte(index)).collect();
        // Instructions decoded from these bytes (one may start two bytes earlier) decode again.
        if !self.cache.is_empty() {
            let first = base.wrapping_sub(2) & !1;
            for offset in (0..u32::from(width) + 2).step_by(2) {
                self.cache.remove(&first.wrapping_add(offset));
            }
        }
        if address.stack() {
            return self.scatter(base, &bytes);
        }
        if device(base) && self.mapped(base).is_none() {
            if u64::from(base) == VTOR
                && width == 4
                && let Some(value) = value.get()
            {
                self.vtor.push(VtorStore { value: u64::from(value), site: u64::from(site) });
            }
            return Ok(());
        }
        let end = u64::from(base) + u64::from(width);
        let last = base + u32::from(width) - 1;
        let previous = self.starts.range(..=last).next_back().map(|(_, &index)| index);
        if let Some(index) = previous {
            let write = &self.writes[index];
            if write.end() > u64::from(base) {
                // Inside an earlier write: the bytes change in place.
                self.writes[index].overwritten = true;
                return self.scatter(base, &bytes);
            }
            if write.end() == u64::from(base) && self.extend(index, &bytes, site) {
                self.clear_scattered(base, width);
                return Ok(());
            }
        }
        if self.writes.len() >= MAX_WRITES {
            return Err(stop(FollowStop::TooManyWrites));
        }
        let copy_from = match bytes[0].origin {
            Origin::From(from)
                if bytes.iter().enumerate().all(|(index, byte)| byte.origin == Origin::From(from + index as u32)) =>
            {
                Some(from)
            }
            _ => None,
        };
        let zero = bytes.iter().all(|byte| byte.value == Some(0));
        let computed = copy_from.is_none() && !zero;
        let values = computed.then(|| bytes.iter().map(|byte| byte.value).collect::<Option<Vec<u8>>>()).flatten();
        self.computed_bytes += values.as_ref().map_or(0, Vec::len);
        let call = self.frames.first().map(|frame| (frame.call_site, frame.target));
        self.starts.insert(base, self.writes.len());
        self.writes.push(Write {
            start: base,
            length: (end - u64::from(base)) as u32,
            copy_from,
            zero,
            computed,
            values,
            stores: 1,
            sites: vec![site],
            call,
            last_store: self.steps,
            overwritten: false,
            interrupted: false,
            executed: false,
        });
        self.clear_scattered(base, width);
        Ok(())
    }

    /// Extends write `index` by `bytes` when they keep one of its origins; false when they do not.
    fn extend(&mut self, index: usize, bytes: &[Byte], site: u32) -> bool {
        let steps = self.steps;
        let budget = MAX_COMPUTED_BYTES.saturating_sub(self.computed_bytes);
        let write = &mut self.writes[index];
        let length = write.length;
        let copy = write.copy_from.filter(|&from| {
            bytes
                .iter()
                .enumerate()
                .all(|(offset, byte)| byte.origin == Origin::From(from.wrapping_add(length + offset as u32)))
        });
        let zero = write.zero && bytes.iter().all(|byte| byte.value == Some(0));
        if copy.is_none() && !zero && !write.computed {
            return false;
        }
        if u64::from(write.length) + bytes.len() as u64 > u64::from(u32::MAX) {
            return false;
        }
        write.copy_from = copy;
        write.zero = zero;
        let mut added = 0;
        if write.computed {
            match bytes.iter().map(|byte| byte.value).collect::<Option<Vec<u8>>>() {
                Some(values) if values.len() <= budget => {
                    if let Some(kept) = write.values.as_mut() {
                        added = values.len();
                        kept.extend(values);
                    }
                }
                _ => write.values = None,
            }
        }
        write.length += bytes.len() as u32;
        write.stores += 1;
        write.last_store = steps;
        if write.sites.len() < 4 && !write.sites.contains(&site) {
            write.sites.push(site);
        }
        self.computed_bytes += added;
        true
    }

    fn scatter(&mut self, base: u32, bytes: &[Byte]) -> Step {
        for (index, byte) in bytes.iter().enumerate() {
            self.scattered.insert(base.wrapping_add(index as u32), *byte);
        }
        if self.scattered.len() > MAX_SCATTERED_BYTES {
            return Err(stop(FollowStop::TooManyWrites));
        }
        Ok(())
    }

    fn clear_scattered(&mut self, base: u32, width: u8) {
        if !self.scattered.is_empty() {
            for index in 0..u32::from(width) {
                self.scattered.remove(&base.wrapping_add(index));
            }
        }
    }

    fn reg(&self, number: u32) -> Val {
        if number == 15 { Val::plain(self.pc.wrapping_add(4)) } else { self.regs[number as usize] }
    }

    /// Writes a register other than the PC; anything written to `sp` names the stack.
    fn set(&mut self, number: u32, value: Val) {
        let value = match (number, value) {
            (13, Val::Known(value, _)) => Val::Known(value, Tag::Stack),
            _ => value,
        };
        self.regs[number as usize & 15] = value;
    }

    fn branch(&mut self, target: Val, exchange: bool, next: &mut u32) -> Step {
        let Some(target) = target.get() else {
            return Err(stop(FollowStop::UnknownBranch));
        };
        if exchange && target & 1 == 0 {
            return Err(stop(FollowStop::BadFetch));
        }
        let target = target & !1;
        if let Some(depth) = self.frames.iter().rposition(|frame| frame.return_to == target) {
            self.frames.truncate(depth);
        } else if self.frames.is_empty() && target == RESET_LR & !1 {
            return Err(stop(FollowStop::Returned));
        }
        *next = target;
        Ok(())
    }

    fn call(&mut self, target: u32, return_to: u32, next: &mut u32) -> Step {
        if self.frames.len() >= MAX_CALL_DEPTH {
            return Err(stop(FollowStop::CallDepth));
        }
        let saved = self.frames.is_empty().then_some((self.regs, self.flags));
        self.frames.push(Frame { return_to, call_site: self.pc, target, saved });
        self.regs[14] = Val::plain(return_to | 1);
        *next = target;
        Ok(())
    }

    /// Skips the entry-level call that could not continue, or stops when the entry itself cannot.
    fn recover(&mut self, reason: FollowStop) -> Result<(), FollowStop> {
        let recoverable = !matches!(reason, FollowStop::TooManyWrites | FollowStop::JumpedIntoCopiedCode);
        if self.frames.is_empty() || !recoverable {
            return Err(reason);
        }
        let frame = self.frames.swap_remove(0);
        self.frames.clear();
        let (regs, _) = frame.saved.expect("entry-level frames save the caller's state");
        self.regs = regs;
        for number in [0, 1, 2, 3, 12, 14] {
            self.regs[number] = Val::Unknown;
        }
        self.flags = Flags::default();
        self.it = ItState::default();
        self.skipped_total += 1;
        if self.skipped.len() < MAX_LISTED_SKIPPED_CALLS {
            self.skipped.push(SkippedCall {
                call_site: u64::from(frame.call_site),
                target: u64::from(frame.target),
                reason,
                at: u64::from(self.pc),
            });
        }
        // Writes the abandoned callee was still making are incomplete.
        let steps = self.steps;
        for write in self.writes.iter_mut().filter(|write| steps - write.last_store <= INTERRUPTED_WINDOW) {
            write.interrupted = true;
        }
        self.pc = frame.return_to;
        Ok(())
    }

    fn decode(&mut self, pc: u32) -> Result<Decoded, FollowStop> {
        let cached = !self.it.in_block();
        if cached && let Some(decoded) = self.cache.get(&pc) {
            return decoded.ok_or_else(unsupported);
        }
        let half = |machine: &Self, address: u32| {
            let low = machine.byte(address).value?;
            let high = machine.byte(address.wrapping_add(1)).value?;
            Some(u16::from_le_bytes([low, high]))
        };
        let Some(first) = half(self, pc) else {
            return Err(stop(FollowStop::BadFetch));
        };
        let second = if aarch32::is_wide(first) {
            Some(half(self, pc.wrapping_add(2)).ok_or_else(|| stop(FollowStop::BadFetch))?)
        } else {
            None
        };
        let decoded = aarch32::decode_t32_m(first, second, self.it);
        if cached {
            if self.cache.len() >= MAX_DECODE_CACHE {
                self.cache.clear();
            }
            self.cache.insert(pc, decoded);
        }
        decoded.ok_or_else(unsupported)
    }

    /// Whether `address` lies in memory the program wrote and no mapped code region holds it.
    fn copied(&self, address: u32) -> Option<usize> {
        let (_, &index) = self.starts.range(..=address).next_back()?;
        let in_code = self.mapped(address).is_some_and(|region| region.code && region.bytes.is_some());
        (self.writes[index].contains(address) && !in_code).then_some(index)
    }

    fn run(mut self, budget: u64) -> Follow {
        let entry = self.pc;
        let reason = loop {
            if self.steps >= budget {
                break FollowStop::StepBudget;
            }
            if let Some(index) = self.copied(self.pc) {
                self.writes[index].executed = true;
                self.continues_at = Some(self.pc);
                break FollowStop::JumpedIntoCopiedCode;
            }
            self.steps += 1;
            match self.step() {
                Ok(()) => {}
                Err(reason) => {
                    if let Err(reason) = self.recover(reason) {
                        break reason;
                    }
                }
            }
        };
        self.finish(entry, reason)
    }

    fn finish(self, entry: u32, reason: FollowStop) -> Follow {
        let steps = self.steps;
        let interrupted = |write: &Write| match reason {
            _ if reason.clean() => false,
            FollowStop::StepBudget => write.last_store >= steps - steps / 4,
            _ => steps - write.last_store <= INTERRUPTED_WINDOW,
        };
        let mut incomplete: Vec<bool> =
            self.writes.iter().map(|write| write.interrupted || interrupted(write)).collect();
        // A write that runs on into an interrupted one by the same stores (a copy that went past its source) is
        // interrupted too.
        let mut order: Vec<usize> = (0..self.writes.len()).collect();
        order.sort_by_key(|&index| std::cmp::Reverse(self.writes[index].start));
        for &index in &order {
            if incomplete[index] {
                continue;
            }
            let write = &self.writes[index];
            let next = self.starts.get(&((write.end()) as u32)).copied().filter(|_| write.end() <= u64::from(u32::MAX));
            if let Some(next) = next
                && incomplete[next]
                && self.writes[next].sites.iter().any(|site| write.sites.contains(site))
            {
                incomplete[index] = true;
            }
        }
        let mut copies = Vec::new();
        let mut complete = Vec::new();
        let mut overwritten = Vec::new();
        let mut not_listed = 0;
        for (index, write) in self.writes.iter().enumerate() {
            if u64::from(write.length) < MIN_WRITE_BYTES || write.stores < 2 {
                continue;
            }
            if copies.len() == MAX_LISTED_COPIES {
                not_listed += 1;
                continue;
            }
            let kind = if write.copy_from.is_some() {
                CopyKind::Copy
            } else if write.zero {
                CopyKind::Zero
            } else {
                CopyKind::Computed
            };
            copies.push(ScatterCopy {
                kind,
                destination: u64::from(write.start),
                length: u64::from(write.length),
                source: write.copy_from.map(u64::from),
                source_region: None,
                source_offset: None,
                stores: write.stores,
                store_sites: write.sites.iter().map(|&site| u64::from(site)).collect(),
                call_site: write.call.map(|(site, _)| u64::from(site)),
                routine: write.call.map(|(_, target)| u64::from(target)),
                executed: write.executed,
                status: CopyStatus::NotMapped,
                region: None,
                not_mapped_reason: None,
            });
            complete.push(!incomplete[index]);
            overwritten.push(write.overwritten);
        }
        Follow {
            report: ScatterLoad {
                entry: u64::from(entry),
                steps,
                stop: reason,
                stopped_at: u64::from(self.pc),
                continues_at: self.continues_at.map(u64::from),
                copies,
                copies_not_listed: not_listed,
                skipped_calls: self.skipped,
                skipped_calls_not_listed: self.skipped_total.saturating_sub(MAX_LISTED_SKIPPED_CALLS),
                vtor_stores: self.vtor,
                note: NOTE,
            },
            complete,
            overwritten,
        }
    }

    /// Executes one instruction.
    fn step(&mut self) -> Step {
        let pc = self.pc;
        let decoded = self.decode(pc)?;
        let size = u32::from(decoded.size());
        let mut next = pc.wrapping_add(size);
        let it = self.it;
        let name = decoded.encoding.name;
        if name == "IT_T1" {
            self.it = ItState::new(field(&decoded, "firstcond") as u8, field(&decoded, "mask") as u8);
            self.pc = next;
            return Ok(());
        }
        self.it = it.advance();
        if let Some(condition) = it.condition() {
            match self.flags.condition(u32::from(condition)) {
                None => return Err(stop(FollowStop::UnknownBranch)),
                Some(false) => {
                    self.pc = next;
                    return Ok(());
                }
                Some(true) => {}
            }
        }
        let in_it = it.in_block();
        self.execute(&decoded, pc, in_it, &mut next)?;
        if next == pc {
            return Err(stop(FollowStop::Halted));
        }
        self.pc = next;
        Ok(())
    }

    fn execute(&mut self, d: &Decoded, pc: u32, in_it: bool, next: &mut u32) -> Step {
        let name = d.encoding.name;
        let f = |name: &str| field(d, name);
        let wide = d.set == Set::T32;
        // 16-bit data processing sets the flags outside an IT block; 32-bit encodings say so in S.
        let narrow_flags = !in_it;
        let s = f("S") == 1;
        let aligned_pc = pc.wrapping_add(4) & !3;
        match name {
            // Branches.
            "B_T1" | "B_T3" => {
                let condition = f("cond");
                let offset = if name == "B_T1" {
                    sign_extend(f("imm8") << 1, 9)
                } else {
                    sign_extend(f("S") << 20 | f("J2") << 19 | f("J1") << 18 | f("imm6") << 12 | f("imm11") << 1, 21)
                };
                match self.flags.condition(condition) {
                    None => return Err(stop(FollowStop::UnknownBranch)),
                    Some(true) => *next = pc.wrapping_add(4).wrapping_add(offset),
                    Some(false) => {}
                }
            }
            "B_T2" => *next = pc.wrapping_add(4).wrapping_add(sign_extend(f("imm11") << 1, 12)),
            "B_T4" | "BL_i_T1" => {
                let s = f("S");
                let i1 = !(f("J1") ^ s) & 1;
                let i2 = !(f("J2") ^ s) & 1;
                let offset = sign_extend(s << 24 | i1 << 23 | i2 << 22 | f("imm10") << 12 | f("imm11") << 1, 25);
                let target = pc.wrapping_add(4).wrapping_add(offset);
                if name == "B_T4" {
                    *next = target;
                } else {
                    self.call(target, pc.wrapping_add(4), next)?;
                }
            }
            "BL_i_T2" => return Err(stop(FollowStop::BadFetch)),
            "BX_T1" => self.branch(self.reg(f("Rm")), true, next)?,
            "BLX_r_T1" => {
                let target = self.reg(f("Rm"));
                let Some(value) = target.get() else {
                    return Err(stop(FollowStop::UnknownBranch));
                };
                if value & 1 == 0 {
                    return Err(stop(FollowStop::BadFetch));
                }
                self.call(value & !1, pc.wrapping_add(2), next)?;
            }
            "CBZ_T1" | "CBNZ_T1" => {
                let Some(value) = self.reg(f("Rn")).get() else {
                    return Err(stop(FollowStop::UnknownBranch));
                };
                if (value == 0) == (name == "CBZ_T1") {
                    *next = pc.wrapping_add(4).wrapping_add(f("i") << 6 | f("imm5") << 1);
                }
            }
            // Hints, barriers and system-register moves change nothing the follow tracks.
            "NOP_T1" | "NOP_T2" | "YIELD_T1" | "YIELD_T2" | "SEV_T1" | "SEV_T2" | "DSB_T1" | "DMB_T1" | "ISB_T1"
            | "CPSID_T1_AS" | "CPSIE_T1_AS" | "CPSID_T2_AS" | "CPSIE_T2_AS" => {}
            "WFI_T1" | "WFI_T2" | "WFE_T1" | "WFE_T2" => return Err(stop(FollowStop::Halted)),
            "MSR_M_T1" => {
                // MSP and PSP set the stack pointer; the masks and control bits change nothing tracked.
                if matches!(f("SYSm"), 8 | 9) {
                    let value = self.reg(f("Rn"));
                    self.set(13, value);
                }
            }
            "MRS_M_T1" => self.set(f("Rd"), Val::Unknown),
            // Moves.
            "MOV_i_T1" => self.alu(Alu::Mov, Some(f("Rd")), Val::plain(0), Val::plain(f("imm8")), None, narrow_flags),
            "MOV_i_T2" | "MOVS_i_T2" | "MVN_i_T1" | "MVNS_i_T1" => {
                let (value, carry) = expand_imm(f("i") << 11 | f("imm3") << 8 | f("imm8"), self.flags.c);
                let op = if name.starts_with("MVN") { Alu::Mvn } else { Alu::Mov };
                self.alu(op, Some(f("Rd")), Val::plain(0), Val::plain(value), carry, s);
            }
            "MOV_i_T3" => {
                self.set(f("Rd"), Val::plain(f("imm4") << 12 | f("i") << 11 | f("imm3") << 8 | f("imm8")));
            }
            "MOVT_T1" => {
                let high = f("imm4") << 12 | f("i") << 11 | f("imm3") << 8 | f("imm8");
                let value = self.reg(f("Rd")).get().map_or(Val::Unknown, |low| Val::plain(low & 0xffff | high << 16));
                self.set(f("Rd"), value);
            }
            "MOV_r_T1" => {
                let rd = f("D") << 3 | f("Rd");
                let value = self.reg(f("Rm"));
                if rd == 15 {
                    let target = value.get().map_or(Val::Unknown, |value| Val::plain(value | 1));
                    self.branch(target, true, next)?;
                } else {
                    self.set(rd, value);
                }
            }
            "MOV_r_T2" => {
                let (kind, amount) = imm_shift(f("op"), f("imm5"));
                self.shifted_move(f("Rd"), self.reg(f("Rm")), kind, amount, narrow_flags);
            }
            "MOV_r_T3" | "MOVS_r_T3" | "MVN_r_T2" | "MVNS_r_T2" => {
                let (kind, amount) = imm_shift(f("stype"), f("imm3") << 2 | f("imm2"));
                if name.starts_with("MVN") {
                    let (operand, carry) = self.shifted(self.reg(f("Rm")), kind, amount);
                    self.alu(Alu::Mvn, Some(f("Rd")), Val::plain(0), operand, carry, s);
                } else {
                    self.shifted_move(f("Rd"), self.reg(f("Rm")), kind, amount, s);
                }
            }
            "MOV_rr_T1_LSL" | "MOV_rr_T1_LSR" | "MOV_rr_T1_ASR" | "MOV_rr_T1_ROR" | "MOV_rr_T2" | "MOVS_rr_T2" => {
                let (rd, rm, kind, flags) = if wide {
                    (f("Rd"), f("Rm"), f("stype"), s)
                } else {
                    let kind = match name {
                        "MOV_rr_T1_LSL" => 0,
                        "MOV_rr_T1_LSR" => 1,
                        "MOV_rr_T1_ASR" => 2,
                        _ => 3,
                    };
                    (f("Rd"), f("Rd"), kind, narrow_flags)
                };
                match self.reg(f("Rs")).get() {
                    Some(amount) => self.shifted_move(rd, self.reg(rm), kind, amount & 0xff, flags),
                    None => self.unknown_result(rd, flags),
                }
            }
            // Arithmetic and logic with an immediate.
            "ADD_i_T1" | "SUB_i_T1" => {
                let op = if name == "ADD_i_T1" { Alu::Add } else { Alu::Sub };
                self.alu(op, Some(f("Rd")), self.reg(f("Rn")), Val::plain(f("imm3")), None, narrow_flags);
            }
            "ADD_i_T2" | "SUB_i_T2" => {
                let op = if name == "ADD_i_T2" { Alu::Add } else { Alu::Sub };
                self.alu(op, Some(f("Rdn")), self.reg(f("Rdn")), Val::plain(f("imm8")), None, narrow_flags);
            }
            "CMP_i_T1" => self.alu(Alu::Sub, None, self.reg(f("Rn")), Val::plain(f("imm8")), None, true),
            "RSB_i_T1" => self.alu(Alu::Rsb, Some(f("Rd")), self.reg(f("Rn")), Val::plain(0), None, narrow_flags),
            "ADD_SP_i_T1" => self.alu(Alu::Add, Some(f("Rd")), self.reg(13), Val::plain(f("imm8") << 2), None, false),
            "ADD_SP_i_T2" | "SUB_SP_i_T1" => {
                let op = if name == "ADD_SP_i_T2" { Alu::Add } else { Alu::Sub };
                self.alu(op, Some(13), self.reg(13), Val::plain(f("imm7") << 2), None, false);
            }
            "ADR_T1" => self.set(f("Rd"), Val::plain(aligned_pc.wrapping_add(f("imm8") << 2))),
            "ADR_T2" | "ADR_T3" => {
                let offset = f("i") << 11 | f("imm3") << 8 | f("imm8");
                let value =
                    if name == "ADR_T2" { aligned_pc.wrapping_sub(offset) } else { aligned_pc.wrapping_add(offset) };
                self.set(f("Rd"), Val::plain(value));
            }
            "ADD_i_T4" | "SUB_i_T4" | "ADD_SP_i_T4" | "SUB_SP_i_T3" => {
                let op = if name.starts_with("ADD") { Alu::Add } else { Alu::Sub };
                let rn = if name.contains("SP") { 13 } else { f("Rn") };
                let imm = f("i") << 11 | f("imm3") << 8 | f("imm8");
                self.alu(op, Some(f("Rd")), self.reg(rn), Val::plain(imm), None, false);
            }
            "ADD_i_T3" | "ADDS_i_T3" | "SUB_i_T3" | "SUBS_i_T3" | "ADD_SP_i_T3" | "ADDS_SP_i_T3" | "SUB_SP_i_T2"
            | "SUBS_SP_i_T2" | "CMP_i_T2" | "CMN_i_T1" | "RSB_i_T2" | "RSBS_i_T2" | "AND_i_T1" | "ANDS_i_T1"
            | "TST_i_T1" | "ORR_i_T1" | "ORRS_i_T1" | "ORN_i_T1" | "ORNS_i_T1" | "EOR_i_T1" | "EORS_i_T1"
            | "TEQ_i_T1" | "BIC_i_T1" | "BICS_i_T1" => {
                let (imm, carry) = expand_imm(f("i") << 11 | f("imm3") << 8 | f("imm8"), self.flags.c);
                let (op, compare) = wide_op(name);
                let rn = if name.contains("SP") { 13 } else { f("Rn") };
                let rd = (!compare).then(|| f("Rd"));
                self.alu(op, rd, self.reg(rn), Val::plain(imm), carry, s || compare);
            }
            // Arithmetic and logic with a register.
            "ADD_r_T1" | "SUB_r_T1" => {
                let op = if name == "ADD_r_T1" { Alu::Add } else { Alu::Sub };
                self.alu(op, Some(f("Rd")), self.reg(f("Rn")), self.reg(f("Rm")), None, narrow_flags);
            }
            "ADD_r_T2" | "ADD_SP_r_T1" | "ADD_SP_r_T2" => {
                let (rd, rm) = match name {
                    "ADD_r_T2" => (f("DN") << 3 | f("Rdn"), f("Rm")),
                    "ADD_SP_r_T1" => (f("DM") << 3 | f("Rdm"), 13),
                    _ => (13, f("Rm")),
                };
                let (left, right) =
                    if name == "ADD_SP_r_T1" { (self.reg(13), self.reg(rd)) } else { (self.reg(rd), self.reg(rm)) };
                if rd == 15 {
                    let sum = match (left.get(), right.get()) {
                        (Some(left), Some(right)) => Val::plain(left.wrapping_add(right) | 1),
                        _ => Val::Unknown,
                    };
                    self.branch(sum, true, next)?;
                } else {
                    self.alu(Alu::Add, Some(rd), left, right, None, false);
                }
            }
            "CMP_r_T1" | "CMP_r_T2" | "CMN_r_T1" | "TST_r_T1" => {
                let rn = if name == "CMP_r_T2" { f("N") << 3 | f("Rn") } else { f("Rn") };
                let op = match name {
                    "CMN_r_T1" => Alu::Add,
                    "TST_r_T1" => Alu::And,
                    _ => Alu::Sub,
                };
                let carry = self.flags.c;
                self.alu(op, None, self.reg(rn), self.reg(f("Rm")), carry, true);
            }
            "AND_r_T1" | "EOR_r_T1" | "ORR_r_T1" | "BIC_r_T1" | "MVN_r_T1" | "MUL_T1" => {
                let op = match name {
                    "AND_r_T1" => Alu::And,
                    "EOR_r_T1" => Alu::Eor,
                    "ORR_r_T1" => Alu::Orr,
                    "BIC_r_T1" => Alu::Bic,
                    "MVN_r_T1" => Alu::Mvn,
                    _ => Alu::Mul,
                };
                let (rd, left, right) = match name {
                    "MVN_r_T1" => (f("Rd"), Val::plain(0), self.reg(f("Rm"))),
                    "MUL_T1" => (f("Rdm"), self.reg(f("Rn")), self.reg(f("Rdm"))),
                    _ => (f("Rdn"), self.reg(f("Rdn")), self.reg(f("Rm"))),
                };
                let carry = self.flags.c;
                self.alu(op, Some(rd), left, right, carry, narrow_flags);
            }
            "MUL_T2" => self.alu(Alu::Mul, Some(f("Rd")), self.reg(f("Rn")), self.reg(f("Rm")), None, false),
            "ADD_r_T3" | "ADDS_r_T3" | "SUB_r_T2" | "SUBS_r_T2" | "ADD_SP_r_T3" | "ADDS_SP_r_T3" | "SUB_SP_r_T1"
            | "SUBS_SP_r_T1" | "CMP_r_T3" | "CMN_r_T2" | "RSB_r_T1" | "RSBS_r_T1" | "AND_r_T2" | "ANDS_r_T2"
            | "TST_r_T2" | "ORR_r_T2" | "ORRS_r_T2" | "ORN_r_T1" | "ORNS_r_T1" | "EOR_r_T2" | "EORS_r_T2"
            | "TEQ_r_T1" | "BIC_r_T2" | "BICS_r_T2" => {
                let (kind, amount) = imm_shift(f("stype"), f("imm3") << 2 | f("imm2"));
                let (operand, carry) = self.shifted(self.reg(f("Rm")), kind, amount);
                let (op, compare) = wide_op(name);
                let rn = if name.contains("SP") { 13 } else { f("Rn") };
                let rd = (!compare).then(|| f("Rd"));
                self.alu(op, rd, self.reg(rn), operand, carry, s || compare);
            }
            "UXTB_T1" | "UXTH_T1" | "SXTB_T1" | "SXTH_T1" | "UXTB_T2" | "UXTH_T2" | "SXTB_T2" | "SXTH_T2" => {
                let rotation = if wide { f("rotate") * 8 } else { 0 };
                let value = self.reg(f("Rm")).get().map_or(Val::Unknown, |value| {
                    let value = value.rotate_right(rotation);
                    Val::plain(match &name[..4] {
                        "UXTB" => value & 0xff,
                        "UXTH" => value & 0xffff,
                        "SXTB" => value as u8 as i8 as i32 as u32,
                        _ => value as u16 as i16 as i32 as u32,
                    })
                });
                self.set(f("Rd"), value);
            }
            // Loads and stores.
            _ if name.starts_with("LDR") || name.starts_with("STR") => {
                self.load_store(d, name, pc, aligned_pc, next)?
            }
            "LDM_T1" | "STM_T1" | "LDM_T2" | "STM_T2" | "LDMDB_T1" | "STMDB_T1" | "PUSH_T1" | "POP_T1" => {
                self.multiple(d, name, pc, next)?;
            }
            _ => return Err(unsupported()),
        }
        Ok(())
    }

    /// Applies `op` to `left` and `right`, writes `rd` (none for a comparison) and sets the flags when asked.
    /// `carry` is a logical operation's shifter carry.
    fn alu(&mut self, op: Alu, rd: Option<u32>, left: Val, right: Val, carry: Option<bool>, set_flags: bool) {
        let (Some(x), Some(y)) = (left.get(), right.get()) else {
            if let Some(rd) = rd {
                self.set(rd, Val::Unknown);
            }
            if set_flags {
                let v = self.flags.v;
                self.flags = Flags {
                    v: if matches!(op, Alu::Add | Alu::Sub | Alu::Rsb) { None } else { v },
                    ..Flags::default()
                };
            }
            return;
        };
        let (result, c, v) = match op {
            Alu::Add => {
                let (result, c, v) = add_with_carry(x, y, false);
                (result, Some(c), Some(v))
            }
            Alu::Sub => {
                let (result, c, v) = add_with_carry(x, !y, true);
                (result, Some(c), Some(v))
            }
            Alu::Rsb => {
                let (result, c, v) = add_with_carry(y, !x, true);
                (result, Some(c), Some(v))
            }
            Alu::And => (x & y, carry, self.flags.v),
            Alu::Orr => (x | y, carry, self.flags.v),
            Alu::Orn => (x | !y, carry, self.flags.v),
            Alu::Eor => (x ^ y, carry, self.flags.v),
            Alu::Bic => (x & !y, carry, self.flags.v),
            Alu::Mov => (y, carry, self.flags.v),
            Alu::Mvn => (!y, carry, self.flags.v),
            Alu::Mul => (x.wrapping_mul(y), self.flags.c, self.flags.v),
        };
        if let Some(rd) = rd {
            let tag = match (op, left, right) {
                (Alu::Mov, _, Val::Known(_, tag)) => tag,
                (Alu::Add | Alu::Sub, Val::Known(_, Tag::Stack), Val::Known(_, tag)) if tag != Tag::Stack => Tag::Stack,
                (Alu::Add, Val::Known(_, tag), Val::Known(_, Tag::Stack)) if tag != Tag::Stack => Tag::Stack,
                _ => Tag::Plain,
            };
            self.set(rd, Val::Known(result, tag));
        }
        if set_flags {
            self.flags = Flags { n: Some(result >> 31 == 1), z: Some(result == 0), c, v };
        }
    }

    /// `value` shifted, with the shifter carry; unknown when `value` is.
    fn shifted(&self, value: Val, kind: u32, amount: u32) -> (Val, Option<bool>) {
        match value {
            Val::Known(value, tag) if amount == 0 => (Val::Known(value, tag), self.flags.c),
            Val::Known(value, _) => {
                let (result, carry) = shift(value, kind, amount, self.flags.c);
                (Val::plain(result), carry)
            }
            Val::Unknown => (Val::Unknown, None),
        }
    }

    fn shifted_move(&mut self, rd: u32, value: Val, kind: u32, amount: u32, set_flags: bool) {
        let (operand, carry) = self.shifted(value, kind, amount);
        self.alu(Alu::Mov, Some(rd), Val::plain(0), operand, carry, set_flags);
    }

    fn unknown_result(&mut self, rd: u32, set_flags: bool) {
        self.set(rd, Val::Unknown);
        if set_flags {
            self.flags = Flags { v: self.flags.v, ..Flags::default() };
        }
    }

    /// Single loads and stores: immediate, register and literal addressing, pre- and post-indexed.
    fn load_store(&mut self, d: &Decoded, name: &str, pc: u32, aligned_pc: u32, next: &mut u32) -> Step {
        let f = |name: &str| field(d, name);
        let mnemonic = &name[..name.find('_').unwrap_or(name.len())];
        let (load, width, signed, double) = match mnemonic {
            "LDR" => (true, 4, false, false),
            "LDRB" => (true, 1, false, false),
            "LDRH" => (true, 2, false, false),
            "LDRSB" => (true, 1, true, false),
            "LDRSH" => (true, 2, true, false),
            "LDRD" => (true, 4, false, true),
            "STR" => (false, 4, false, false),
            "STRB" => (false, 1, false, false),
            "STRH" => (false, 2, false, false),
            "STRD" => (false, 4, false, true),
            _ => return Err(unsupported()),
        };
        let kind = &name[mnemonic.len()..];
        let rt = f("Rt");
        // (address, writeback value)
        let (address, writeback): (Val, Option<(u32, Val)>) = if kind.starts_with("_l_") {
            let offset = if d.set == Set::T16 || double { f("imm8") << 2 } else { f("imm12") };
            let address = if d.set == Set::T16 || f("U") == 1 {
                aligned_pc.wrapping_add(offset)
            } else {
                aligned_pc.wrapping_sub(offset)
            };
            (Val::plain(address), None)
        } else if kind.starts_with("_r_") {
            let shift = if d.set == Set::T32 { f("imm2") } else { 0 };
            let address = match (self.reg(f("Rn")), self.reg(f("Rm")).get()) {
                (Val::Known(base, tag), Some(index)) => {
                    let tag = if tag == Tag::Stack { Tag::Stack } else { Tag::Plain };
                    Val::Known(base.wrapping_add(index << shift), tag)
                }
                _ => Val::Unknown,
            };
            (address, None)
        } else if kind.starts_with("_i_") {
            let (rn, offset, index, add, wback) = if d.set == Set::T16 {
                let scale = match width {
                    4 => 4,
                    2 => 2,
                    _ => 1,
                };
                if kind == "_i_T2" && width == 4 {
                    (13, f("imm8") << 2, true, true, false)
                } else {
                    (f("Rn"), f("imm5") * scale, true, true, false)
                }
            } else if double {
                (f("Rn"), f("imm8") << 2, f("P") == 1, f("U") == 1, f("W") == 1)
            } else if d.encoding.fields.iter().any(|field| field.name == "imm12") {
                (f("Rn"), f("imm12"), true, true, false)
            } else {
                (f("Rn"), f("imm8"), f("P") == 1, f("U") == 1, f("W") == 1)
            };
            let base = self.reg(rn);
            let offset_address = match base {
                Val::Known(base, tag) => {
                    let value = if add { base.wrapping_add(offset) } else { base.wrapping_sub(offset) };
                    Val::Known(value, if tag == Tag::Stack { Tag::Stack } else { Tag::Plain })
                }
                Val::Unknown => Val::Unknown,
            };
            let address = if index { offset_address } else { base };
            (address, wback.then_some((rn, offset_address)))
        } else {
            return Err(unsupported());
        };
        let registers: Vec<u32> = if double { vec![rt, f("Rt2")] } else { vec![rt] };
        for (slot, &register) in registers.iter().enumerate() {
            let address = match address {
                Val::Known(value, tag) => Val::Known(value.wrapping_add(4 * slot as u32), tag),
                Val::Unknown => Val::Unknown,
            };
            if load {
                let value = self.load(address, width, signed);
                if register == 15 {
                    self.branch(value, true, next)?;
                } else {
                    self.set(register, value);
                }
            } else {
                let value = self.reg(register);
                self.store(address, width, value, pc)?;
            }
        }
        if let Some((rn, value)) = writeback
            && !(load && registers.contains(&rn))
        {
            self.set(rn, value);
        }
        Ok(())
    }

    /// LDM, STM, their decrement-before forms, PUSH and POP.
    fn multiple(&mut self, d: &Decoded, name: &str, pc: u32, next: &mut u32) -> Step {
        let f = |name: &str| field(d, name);
        let (rn, mut list, load, before, wback) = match name {
            "PUSH_T1" => (13, f("register_list") | f("M") << 14, false, true, true),
            "POP_T1" => (13, f("register_list") | f("P") << 15, true, false, true),
            "LDM_T1" => {
                let rn = f("Rn");
                let list = f("register_list");
                (rn, list, true, false, list & (1 << rn) == 0)
            }
            "STM_T1" => (f("Rn"), f("register_list"), false, false, true),
            _ => {
                let list = f("register_list") | f("M") << 14 | f("P") << 15;
                (f("Rn"), list, name.starts_with("LDM"), name.ends_with("DB_T1"), f("W") == 1)
            }
        };
        if !load {
            list &= 0x7fff;
        }
        let count = list.count_ones();
        if count == 0 {
            return Err(unsupported());
        }
        let base = self.reg(rn);
        let Val::Known(base_value, tag) = base else {
            if load {
                for register in 0..15 {
                    if list & (1 << register) != 0 {
                        self.set(register, Val::Unknown);
                    }
                }
                if list & (1 << 15) != 0 {
                    return Err(stop(FollowStop::UnknownBranch));
                }
                if wback {
                    self.set(rn, Val::Unknown);
                }
                return Ok(());
            }
            return Err(stop(FollowStop::UnknownStoreAddress));
        };
        let tag = if tag == Tag::Stack { Tag::Stack } else { Tag::Plain };
        let start = if before { base_value.wrapping_sub(4 * count) } else { base_value };
        let mut address = start;
        let mut target = None;
        for register in 0..16 {
            if list & (1 << register) == 0 {
                continue;
            }
            let slot = Val::Known(address, tag);
            if load {
                let value = self.load(slot, 4, false);
                if register == 15 {
                    target = Some(value);
                } else {
                    self.set(register, value);
                }
            } else {
                let value = self.reg(register);
                self.store(slot, 4, value, pc)?;
            }
            address = address.wrapping_add(4);
        }
        if wback && !(load && list & (1 << rn) != 0) {
            let value = if before { start } else { base_value.wrapping_add(4 * count) };
            self.set(rn, Val::Known(value, tag));
        }
        if let Some(target) = target {
            self.branch(target, true, next)?;
        }
        Ok(())
    }
}

/// The operation of a 32-bit data-processing encoding, and whether it only sets flags.
fn wide_op(name: &str) -> (Alu, bool) {
    match &name[..name.find('_').unwrap_or(name.len())] {
        "ADD" | "ADDS" => (Alu::Add, false),
        "SUB" | "SUBS" => (Alu::Sub, false),
        "RSB" | "RSBS" => (Alu::Rsb, false),
        "AND" | "ANDS" => (Alu::And, false),
        "ORR" | "ORRS" => (Alu::Orr, false),
        "ORN" | "ORNS" => (Alu::Orn, false),
        "EOR" | "EORS" => (Alu::Eor, false),
        "BIC" | "BICS" => (Alu::Bic, false),
        "CMP" => (Alu::Sub, true),
        "CMN" => (Alu::Add, true),
        "TST" => (Alu::And, true),
        "TEQ" => (Alu::Eor, true),
        _ => (Alu::Mov, false),
    }
}

fn sign_extend(value: u32, bits: u32) -> u32 {
    let shift = 32 - bits;
    (((value << shift) as i32) >> shift) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x0800_0000;

    /// A tiny Thumb assembler for hand-built startup code: 16-bit encodings, a literal pool and label patches.
    #[derive(Default)]
    struct Asm {
        code: Vec<u16>,
        literals: Vec<(usize, u32)>,
        patches: Vec<(usize, &'static str, u16)>,
        labels: Vec<(&'static str, u32)>,
    }

    impl Asm {
        fn here(&self) -> u32 {
            BASE + 2 * self.code.len() as u32
        }

        fn label(&mut self, name: &'static str) {
            let here = self.here();
            self.labels.push((name, here));
        }

        fn emit(&mut self, half: u16) {
            self.code.push(half);
        }

        /// `ldr rt, =value`.
        fn ldr(&mut self, rt: u16, value: u32) {
            self.literals.push((self.code.len(), value));
            self.emit(0x4800 | rt << 8);
        }

        fn branch(&mut self, opcode: u16, label: &'static str) {
            self.patches.push((self.code.len(), label, opcode));
            self.emit(opcode);
        }

        fn finish(mut self) -> Vec<u8> {
            for (index, label, opcode) in std::mem::take(&mut self.patches) {
                let target = self.labels.iter().find(|(name, _)| *name == label).unwrap().1;
                let offset = (i64::from(target) - (i64::from(BASE) + 2 * index as i64 + 4)) / 2;
                let mask = if opcode == B { 0x7ff } else { 0xff };
                self.code[index] = opcode | (offset as u16 & mask);
            }
            if self.code.len() % 2 == 1 {
                self.emit(0xbf00);
            }
            let pool = BASE + 2 * self.code.len() as u32;
            let mut bytes: Vec<u8> = self.code.iter().flat_map(|half| half.to_le_bytes()).collect();
            for (slot, &(index, _)) in self.literals.iter().enumerate() {
                let pc = (BASE + 2 * index as u32 + 4) & !3;
                let offset = (pool + 4 * slot as u32 - pc) / 4;
                let half = u16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]) | offset as u16;
                bytes[2 * index..2 * index + 2].copy_from_slice(&half.to_le_bytes());
            }
            for (_, value) in &self.literals {
                bytes.extend(value.to_le_bytes());
            }
            bytes
        }

        /// Points every `ldr rN, =0` placeholder at `address` as a Thumb function pointer.
        fn resolve_calls(&mut self, address: u32) {
            for literal in self.literals.iter_mut().filter(|(_, value)| *value == 0) {
                literal.1 = address | 1;
            }
        }
    }

    const HALT: u16 = 0xe7fe;
    const BEQ: u16 = 0xd000;
    const BNE: u16 = 0xd100;
    const BLO: u16 = 0xd300;
    const B: u16 = 0xe000;
    const BLX_R4: u16 = 0x47a0;

    /// `copy(r0 = destination, r1 = length, r2 = source)`, a word loop, at label `copy`.
    fn copy_routine(asm: &mut Asm) {
        asm.label("copy");
        asm.emit(0x2900); // cmp r1, #0
        asm.branch(BEQ, "done");
        asm.label("loop");
        asm.emit(0x6813); // ldr r3, [r2]
        asm.emit(0x3204); // adds r2, #4
        asm.emit(0x6003); // str r3, [r0]
        asm.emit(0x3004); // adds r0, #4
        asm.emit(0x3904); // subs r1, #4
        asm.branch(BNE, "loop");
        asm.label("done");
        asm.emit(0x4770); // bx lr
    }

    /// Startup code calling the copy routine once per (destination, length, source) triple, then halting; the
    /// image is padded to `size` bytes with copyable bytes.
    fn image(triples: &[(u32, u32, u32)], size: usize) -> (Vec<u8>, u32) {
        let mut asm = Asm::default();
        for &(destination, length, source) in triples {
            asm.ldr(0, destination);
            asm.ldr(1, length);
            asm.ldr(2, source);
            asm.ldr(4, 0);
            asm.emit(BLX_R4);
        }
        asm.emit(HALT);
        let copy_at = asm.here();
        copy_routine(&mut asm);
        asm.resolve_calls(copy_at);
        let mut bytes = asm.finish();
        let code = bytes.len();
        bytes.extend((code..size).map(|index| index as u8 ^ 0x5a));
        (bytes, copy_at)
    }

    fn run(bytes: &[u8], budget: u64) -> Follow {
        let range = u64::from(BASE)..u64::from(BASE) + bytes.len() as u64;
        let memory = [Mapped { range, bytes: Some(bytes), code: true }];
        follow_with_budget(&memory, u64::from(BASE), budget)
    }

    #[test]
    fn constant_triples_passed_to_a_copy_routine_are_copies_with_their_sources() {
        let (bytes, copy_at) = image(&[(0x2000_0000, 64, BASE + 0x100), (0x1000_0000, 32, BASE + 0x180)], 0x200);
        let follow = run(&bytes, 100_000);
        let report = &follow.report;
        assert_eq!(report.stop, FollowStop::Halted, "{report:#?}");
        let triples: Vec<_> =
            report.copies.iter().map(|copy| (copy.kind, copy.destination, copy.length, copy.source)).collect();
        assert_eq!(
            triples,
            [
                (CopyKind::Copy, 0x2000_0000, 64, Some(u64::from(BASE) + 0x100)),
                (CopyKind::Copy, 0x1000_0000, 32, Some(u64::from(BASE) + 0x180))
            ]
        );
        assert_eq!(report.copies[0].routine, Some(u64::from(copy_at)));
        assert_eq!(follow.complete, [true, true]);
        // The same interpretation is served from the memo.
        let before = follows_run();
        assert_eq!(run(&bytes, 100_000).report, follow.report);
        assert_eq!(follows_run(), before);
    }

    /// Hostile tables: a length far past the image, a source in unmapped memory, overlapping destinations and
    /// walks that never end are reported without panics or large allocations, and none is complete and intact.
    #[test]
    fn hostile_copies_are_bounded_and_reported_incomplete_computed_or_overwritten() {
        let (huge, _) = image(&[(0x2000_0000, 0x7fff_fff0, BASE + 0x100)], 0x200);
        let follow = run(&huge, 50_000);
        assert_eq!(follow.report.stop, FollowStop::StepBudget);
        assert!(follow.complete.iter().all(|complete| !complete), "{:#?}", follow.report);
        assert!(follow.report.copies.iter().any(|copy| copy.kind == CopyKind::Computed));

        let (unmapped, _) = image(&[(0x2000_0000, 64, 0x3000_0000)], 0x200);
        let report = run(&unmapped, 50_000).report;
        assert_eq!((report.copies.len(), report.copies[0].kind), (1, CopyKind::Computed), "{report:#?}");

        let (overlapping, _) = image(&[(0x2000_0000, 64, BASE + 0x100), (0x2000_0020, 64, BASE + 0x180)], 0x200);
        let follow = run(&overlapping, 50_000);
        let shape: Vec<_> = follow.report.copies.iter().map(|copy| (copy.destination, copy.length)).collect();
        assert_eq!(shape, [(0x2000_0000, 64), (0x2000_0040, 32)]);
        assert_eq!(follow.overwritten, [true, false]);

        // The startup code repeats the same copy for ever (a table that leads back to its start).
        let mut asm = Asm::default();
        asm.label("again");
        asm.ldr(0, 0x2000_0000);
        asm.ldr(1, 64);
        asm.ldr(2, BASE + 0x100);
        asm.ldr(4, 0);
        asm.emit(BLX_R4);
        asm.branch(B, "again");
        let copy_at = asm.here();
        copy_routine(&mut asm);
        asm.resolve_calls(copy_at);
        let mut cyclic = asm.finish();
        cyclic.resize(0x200, 0x11);
        let follow = run(&cyclic, 50_000);
        assert_eq!(follow.report.stop, FollowStop::StepBudget);
        assert_eq!(follow.overwritten, [true]);

        // A table walk whose bound is never reached reads garbage entries and calls through them.
        let mut asm = Asm::default();
        asm.ldr(5, BASE + 0x100);
        asm.ldr(4, 0xffff_fff0);
        asm.label("walk");
        asm.emit(0xcd0f); // ldm r5!, {r0-r3}
        asm.emit(0x4798); // blx r3
        asm.emit(0x42a5); // cmp r5, r4
        asm.branch(BLO, "walk");
        asm.emit(HALT);
        let mut walker = asm.finish();
        walker.extend((walker.len()..0x400).map(|index| (index * 37) as u8));
        let report = run(&walker, 50_000).report;
        assert!(report.steps <= 50_000 && report.copies.len() <= MAX_LISTED_COPIES, "{report:#?}");
        assert!(report.skipped_calls.len() <= MAX_LISTED_SKIPPED_CALLS);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..64 {
            let bytes: Vec<u8> = (0..512)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    (state >> 56) as u8
                })
                .collect();
            assert!(run(&bytes, 5_000).report.steps <= 5_000);
        }
    }
}
