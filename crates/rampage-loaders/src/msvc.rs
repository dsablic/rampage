//! Microsoft C++ ABI metadata in x86 and x64 PE images: vftables located through their RTTI complete object
//! locators, and the exception-handling tables (`FuncInfo` of `__CxxFrameHandler3`, the `__C_specific_handler`
//! scope table, and `_ThrowInfo`).
//!
//! Everything here is structural and read from file-backed image bytes: each followed address must be mapped,
//! every count is capped, address arithmetic is checked, and a record that does not validate is skipped. One
//! image shares one work budget and one retained-record budget across all of it, so crafted tables that share a
//! try map or handler array cannot multiply into unbounded work or memory; running out stops the read with a
//! warning. Names are returned as stored (`.?AV...` type-descriptor names); demangling is the caller's. The
//! loader reads this once per image ([`Binary::msvc_metadata`]) and hands the code it names that the call graph
//! does not reach (virtual methods, catch and cleanup funclets, handler thunks, copy constructors of thrown
//! types) to discovery as function-start hints.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::Arch;
use serde::Serialize;

use crate::{Binary, Format, SectionKind};

/// Upper bound on reported vftables, on functions with exception tables and on throw-info records.
const MAX_RECORDS: usize = 65_536;
/// Upper bound on slots read from one vftable.
const MAX_SLOTS: usize = 1024;
/// Upper bound on the states, try blocks, catch handlers and IP map entries of one `FuncInfo`.
const MAX_STATES: u32 = 65_536;
const MAX_TRY_BLOCKS: u32 = 4096;
const MAX_CATCHES: u32 = 256;
const MAX_IP_ENTRIES: u32 = 262_144;
/// Upper bound on the catchable types of one thrown type and on the base classes of one hierarchy.
const MAX_CATCHABLE_TYPES: u32 = 64;
const MAX_BASES: u32 = 1024;
const MAX_NAME_BYTES: usize = 4096;
/// Upper bound on `__C_specific_handler` scope records in one function.
const MAX_SCOPES: u32 = 4096;
/// How far before its `mov eax, offset FuncInfo` an x86 handler thunk may begin (a security-cookie check).
const X86_THUNK_PREFIX: u64 = 64;

/// The image base and exception directory of a PE image, kept from its headers at load.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeLayout {
    pub image_base: u64,
    /// The exception directory's absolute address and size (x64 `.pdata`).
    pub exception_directory: Option<(u64, u64)>,
}

/// A vftable: the slots that follow a pointer to an RTTI complete object locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vftable {
    /// Address of slot 0; the locator pointer is the word before it.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub locator: u64,
    /// The `TypeDescriptor` of the most-derived class the table belongs to.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub type_descriptor: u64,
    /// The type descriptor's stored name, such as `.?AVRect@geo@@`.
    pub mangled: String,
    /// Offset in the complete object of the subobject whose vfptr points here; non-zero for the secondary
    /// tables of multiple and virtual inheritance.
    pub offset: u32,
    /// Slot values in order: code addresses.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub slots: Vec<u64>,
    /// The slot cap ended the table, so later slots exist.
    pub truncated: bool,
}

/// One state-transition action of a `FuncInfo` unwind map: leaving `state` runs `action` and enters `to_state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnwindAction {
    pub state: i32,
    pub to_state: i32,
    /// The cleanup funclet (a destructor call), absent for a state with nothing to destroy.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub action: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatchHandler {
    /// `HandlerType` adjectives: 1 const, 2 volatile, 8 reference, 0x40 catch-all (`std::` details aside).
    pub adjectives: u32,
    /// The caught type's `TypeDescriptor`; absent for `catch (...)`.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub type_descriptor: Option<u64>,
    /// The caught type's stored name (`.?AUError@@`, `.H` for int); absent for `catch (...)`.
    pub mangled: Option<String>,
    /// The catch funclet.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub handler: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressRange {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    /// Exclusive.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TryBlock {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    /// Code ranges whose EH state lies in `try_low..=try_high`, from the IP-to-state map. Empty on x86, where
    /// the state is a frame slot written at run time.
    pub ranges: Vec<AddressRange>,
    pub catches: Vec<CatchHandler>,
}

/// A `__try` scope of `__C_specific_handler`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SehScope {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    /// Exclusive.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
    /// `except` with a filter function, `except_always` (the filter is the constant
    /// `EXCEPTION_EXECUTE_HANDLER`) or `finally`.
    pub kind: &'static str,
    /// The filter funclet of an `except`, or the termination funclet of a `finally`.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub funclet: Option<u64>,
    /// Where an `except` block's body starts.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub target: Option<u64>,
}

/// The exception tables of one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EhFunction {
    /// The function's start. On x64 it is the unwind range the tables hang off that is not one of their own
    /// funclets; on x86 it is absent, since only code that registers the handler thunk ties it to a function
    /// (see `registrations`).
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub function: Option<u64>,
    /// Exclusive end of the function's unwind range (x64).
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub function_end: Option<u64>,
    /// `cxx_frame_handler3` (a `FuncInfo`) or `c_specific_handler` (a scope table).
    pub kind: &'static str,
    /// The language handler: on x64 the routine named by the unwind info, on x86 the per-function thunk that
    /// loads the `FuncInfo` address and jumps to the frame handler.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub handler: Option<u64>,
    /// The import the handler jumps to, when it is an import thunk.
    pub handler_import: Option<String>,
    /// x86: instructions that push the handler thunk to register it, each inside the owning function.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub registrations: Vec<u64>,
    /// The `FuncInfo` (or scope table) address.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub table: u64,
    pub max_state: i32,
    pub unwind: Vec<UnwindAction>,
    pub try_blocks: Vec<TryBlock>,
    pub scopes: Vec<SehScope>,
}

impl EhFunction {
    /// Catch and cleanup funclets, SEH filters and termination handlers: code run by the handler, not called.
    pub fn funclets(&self) -> impl Iterator<Item = u64> + '_ {
        let unwind = self.unwind.iter().filter_map(|entry| entry.action);
        let catches = self.try_blocks.iter().flat_map(|block| block.catches.iter().map(|catch| catch.handler));
        let scopes = self.scopes.iter().filter_map(|scope| scope.funclet);
        unwind.chain(catches).chain(scopes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatchableType {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub type_descriptor: u64,
    pub mangled: String,
    pub size: u32,
    /// The copy constructor used to initialise a catch object, absent for trivially copied types.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub copy_function: Option<u64>,
}

/// A `_ThrowInfo`: what one `throw` expression's operand type can be caught as, most derived first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThrowInfo {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub attributes: u32,
    /// The thrown object's destructor.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub destructor: Option<u64>,
    pub types: Vec<CatchableType>,
}

/// Everything this module reads from one image, under one shared work and retention budget.
#[derive(Debug, Default, Serialize)]
pub struct MsvcMetadata {
    pub vftables: Vec<Vftable>,
    pub exceptions: EhReport,
    /// Set when a budget ran out, so later tables were not read; the warning is also in `exceptions.warnings`.
    pub budget_exhausted: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct EhReport {
    pub functions: Vec<EhFunction>,
    pub throws: Vec<ThrowInfo>,
    /// x64 unwind entries naming a language handler this reader does not decode (`__CxxFrameHandler4`,
    /// `__GSHandlerCheck`, a statically linked handler without a `FuncInfo`).
    pub undecoded_handlers: usize,
    pub warnings: Vec<String>,
}

/// Field reads and validation steps one image may cost, across vftables, `FuncInfo` and `_ThrowInfo` parsing.
const WORK_BUDGET: u64 = 16_000_000;
/// Approximate bytes of parsed records (slots, unwind actions, catch handlers, ranges, catchable types and their
/// names) one image may keep, so crafted tables that share one try map or handler array cannot multiply into
/// memory.
const RETAIN_BUDGET: u64 = 64 * 1024 * 1024;
/// Approximate retained sizes of one record of each kind, names excluded.
const SLOT_BYTES: u64 = 8;
const TABLE_BYTES: u64 = 96;
const UNWIND_BYTES: u64 = 24;
const TRY_BYTES: u64 = 72;
const CATCH_BYTES: u64 = 64;
const RANGE_BYTES: u64 = 16;
const SCOPE_BYTES: u64 = 56;

/// The address `offset` bytes past `base`, or `None` on overflow (an image based near 2^64, or a crafted field).
fn at(base: u64, offset: u64) -> Option<u64> {
    base.checked_add(offset)
}

/// The address of entry `index` of `size` bytes in the array at `base`.
fn element(base: u64, index: u64, size: u64) -> Option<u64> {
    base.checked_add(index.checked_mul(size)?)
}

type TryMapKey = (u64, u32, u32);
type Memo<K, V> = RefCell<HashMap<K, Option<V>>>;

struct Reader<'a> {
    binary: &'a Binary,
    image_base: u64,
    /// 64-bit image: pointers are 8 bytes and table fields are image-relative.
    wide: bool,
    work: Cell<u64>,
    retained: Cell<u64>,
    exhausted: Cell<bool>,
    /// Parsed type-descriptor names, unwind maps and try maps by address, so tables that share them (as crafted
    /// input can) are read once.
    names: Memo<u64, String>,
    unwind_maps: Memo<(u64, u32), Vec<UnwindAction>>,
    try_maps: Memo<TryMapKey, Vec<TryBlock>>,
}

impl<'a> Reader<'a> {
    fn new(binary: &'a Binary, work: u64, retain: u64) -> Option<Self> {
        let layout = binary.pe_layout()?;
        let wide = match binary.arch {
            Arch::X86 => false,
            Arch::X86_64 => true,
            _ => return None,
        };
        (binary.format == Format::Pe).then(|| Reader {
            binary,
            image_base: layout.image_base,
            wide,
            work: Cell::new(work),
            retained: Cell::new(retain),
            exhausted: Cell::new(false),
            names: RefCell::default(),
            unwind_maps: RefCell::default(),
            try_maps: RefCell::default(),
        })
    }

    fn take(&self, counter: &Cell<u64>, units: u64) -> Option<()> {
        match counter.get().checked_sub(units) {
            Some(left) if !self.exhausted.get() => {
                counter.set(left);
                Some(())
            }
            _ => {
                self.exhausted.set(true);
                None
            }
        }
    }

    /// Charges `units` of parsing work; `None` once the image's budget is spent.
    fn spend(&self, units: u64) -> Option<()> {
        self.take(&self.work, units)
    }

    /// Charges `bytes` of retained records; `None` once the image's budget is spent.
    fn retain(&self, bytes: u64) -> Option<()> {
        self.take(&self.retained, bytes)
    }

    fn exhausted(&self) -> bool {
        self.exhausted.get()
    }

    fn pointer_size(&self) -> u64 {
        if self.wide { 8 } else { 4 }
    }

    fn u32(&self, address: u64) -> Option<u32> {
        let bytes: [u8; 4] = self.binary.read(address, 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn i32(&self, address: u64) -> Option<i32> {
        self.u32(address).map(|value| value as i32)
    }

    fn pointer(&self, address: u64) -> Option<u64> {
        if self.wide {
            let bytes: [u8; 8] = self.binary.read(address, 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        } else {
            self.u32(address).map(u64::from)
        }
    }

    /// A table cross-reference field: an image-relative RVA on x64, an absolute address on x86. Zero is null.
    fn reference(&self, address: u64) -> Option<Option<u64>> {
        let field = self.u32(address)?;
        Some(match field {
            0 => None,
            _ if self.wide => Some(self.image_base.checked_add(u64::from(field))?),
            _ => Some(u64::from(field)),
        })
    }

    /// A reference that must be present and file-backed non-code.
    fn data_reference(&self, address: u64) -> Option<u64> {
        self.reference(address)?.filter(|&target| self.is_data(target))
    }

    /// A reference that is null or code; `None` when it is neither.
    fn code_reference(&self, address: u64) -> Option<Option<u64>> {
        let target = self.reference(address)?;
        target.is_none_or(|target| self.binary.is_code(target)).then_some(target)
    }

    fn is_data(&self, address: u64) -> bool {
        !self.binary.is_code(address) && self.binary.read(address, 1).is_some()
    }

    /// The stored name of the `TypeDescriptor` at `address`: a `.`-prefixed decorated type name after a
    /// non-null vftable pointer and a spare word. Each descriptor is read once; each use retains a copy.
    fn type_name(&self, address: u64) -> Option<String> {
        let cached = self.names.borrow().get(&address).cloned();
        let name = match cached {
            Some(name) => name,
            None => {
                let name = self.read_type_name(address);
                self.names.borrow_mut().insert(address, name.clone());
                name
            }
        }?;
        self.retain(24 + name.len() as u64)?;
        Some(name)
    }

    fn read_type_name(&self, address: u64) -> Option<String> {
        self.spend(2)?;
        let width = self.pointer_size();
        self.pointer(address).filter(|&vftable| vftable != 0 && self.binary.read(vftable, 1).is_some())?;
        let bytes = self.binary.read_to_segment_end(at(address, 2 * width)?)?;
        let scanned = bytes.len().min(MAX_NAME_BYTES);
        let end = bytes[..scanned].iter().position(|&byte| byte == 0);
        self.spend(1 + end.unwrap_or(scanned) as u64 / 64)?;
        let name = std::str::from_utf8(&bytes[..end?]).ok()?;
        (name.len() >= 2 && name.starts_with('.') && name.bytes().all(|byte| byte.is_ascii_graphic()))
            .then(|| name.to_owned())
    }

    /// Validates an RTTI complete object locator, returning its subobject offset and type descriptor.
    fn locator(&self, address: u64) -> Option<(u32, u64, String)> {
        self.spend(8)?;
        if self.u32(address)? != u32::from(self.wide) {
            return None;
        }
        let offset = self.u32(at(address, 4)?)?;
        let type_descriptor = self.data_reference(at(address, 12)?)?;
        let hierarchy = self.data_reference(at(address, 16)?)?;
        if self.wide && self.reference(at(address, 20)?)? != Some(address) {
            return None;
        }
        let mangled = self.type_name(type_descriptor).filter(|name| name.starts_with(".?A"))?;
        let bases = self.u32(at(hierarchy, 8)?)?;
        if self.u32(hierarchy)? != 0 || bases == 0 || bases > MAX_BASES {
            return None;
        }
        self.data_reference(at(hierarchy, 12)?)?;
        Some((offset, type_descriptor, mangled))
    }

    /// File-backed data sections as (address, bytes).
    fn data_sections(&self) -> impl Iterator<Item = (u64, &'a [u8])> + '_ {
        self.binary.sections.iter().filter_map(|section| {
            let data = matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData);
            let len = section.file_size.min(section.size);
            (data && section.file_offset.is_some() && len != 0)
                .then(|| self.binary.read(section.address, len).map(|bytes| (section.address, bytes)))
                .flatten()
        })
    }

    /// The import a `jmp [slot]` thunk at `address` reaches.
    fn import_thunk(&self, address: u64) -> Option<&'a str> {
        let bytes = self.binary.code_from(address)?;
        if bytes.len() < 6 || bytes[..2] != [0xff, 0x25] {
            return None;
        }
        let field = u32::from_le_bytes(bytes[2..6].try_into().ok()?);
        let slot = if self.wide {
            address.checked_add(6)?.checked_add_signed(i64::from(field as i32))?
        } else {
            u64::from(field)
        };
        self.binary.import_slot(slot).map(|slot| slot.name.as_str())
    }
}

/// Vftables with RTTI, sorted by address.
///
/// A table is found by its header: the word before slot 0 points to a complete object locator, which is
/// validated down to its type name. Slots are read while they hold code addresses, so a table ends at the next
/// table's locator pointer or at any other data; an adjacent array of code pointers with no header of its own
/// would be read as further slots.
fn read_vftables(reader: &Reader) -> Vec<Vftable> {
    let binary = reader.binary;
    let width = reader.pointer_size();
    let mut locators: HashMap<u64, Option<(u32, u64, String)>> = HashMap::new();
    let mut tables = Vec::new();
    // Every locator lies in a data section; anything outside their span is rejected without a lookup.
    let low = reader.data_sections().map(|(start, _)| start).min().unwrap_or(0);
    let high = reader.data_sections().filter_map(|(start, bytes)| at(start, bytes.len() as u64)).max().unwrap_or(0);
    'sections: for (start, bytes) in reader.data_sections() {
        let step = width as usize;
        let mut offset = ((width - start % width) % width) as usize;
        while offset + 2 * step <= bytes.len() && tables.len() < MAX_RECORDS {
            let Some(here) = at(start, offset as u64) else { break };
            let mut word = [0u8; 8];
            word[..step].copy_from_slice(&bytes[offset..offset + step]);
            offset += step;
            let candidate = u64::from_le_bytes(word);
            if !(low..high).contains(&candidate) || candidate % 4 != 0 || !reader.is_data(candidate) {
                continue;
            }
            let parsed = match locators.get(&candidate) {
                Some(parsed) => parsed.clone(),
                None => {
                    let parsed = reader.locator(candidate);
                    locators.insert(candidate, parsed.clone());
                    parsed
                }
            };
            if reader.exhausted() {
                break 'sections;
            }
            let Some((subobject, type_descriptor, mangled)) = parsed else { continue };
            let Some(address) = at(here, width) else { continue };
            let mut slots = Vec::new();
            let mut truncated = false;
            while let Some(slot) = element(address, slots.len() as u64, width).and_then(|entry| reader.pointer(entry)) {
                if !binary.is_code(slot) {
                    break;
                }
                if slots.len() == MAX_SLOTS {
                    truncated = true;
                    break;
                }
                if reader.spend(1).and_then(|()| reader.retain(SLOT_BYTES)).is_none() {
                    break 'sections;
                }
                slots.push(slot);
            }
            if !slots.is_empty() {
                if reader.retain(TABLE_BYTES + mangled.len() as u64).is_none() {
                    break 'sections;
                }
                tables.push(Vftable {
                    address,
                    locator: candidate,
                    type_descriptor,
                    mangled,
                    offset: subobject,
                    slots,
                    truncated,
                });
            }
        }
    }
    tables.sort_by_key(|table| table.address);
    tables
}

struct FuncInfo {
    max_state: i32,
    unwind: Vec<UnwindAction>,
    try_blocks: Vec<TryBlock>,
    /// (address, state), sorted by address; x64 only.
    ip_states: Vec<(u64, i32)>,
}

fn is_func_info_magic(magic: u32) -> bool {
    // The top three bits are flags; the rest is the version stamp.
    (0x1993_0520..=0x1993_0522).contains(&(magic & 0x1fff_ffff))
}

fn unwind_map(reader: &Reader, map: u64, max_state: u32) -> Option<Vec<UnwindAction>> {
    let mut unwind = Vec::new();
    for state in 0..max_state {
        reader.spend(2)?;
        let entry = element(map, u64::from(state), 8)?;
        let to_state = reader.i32(entry)?;
        if !(-1..max_state as i32).contains(&to_state) {
            return None;
        }
        unwind.push(UnwindAction { state: state as i32, to_state, action: reader.code_reference(at(entry, 4)?)? });
    }
    Some(unwind)
}

fn try_map(reader: &Reader, map: u64, try_count: u32, max_state: u32) -> Option<Vec<TryBlock>> {
    let handler_size = if reader.wide { 20 } else { 16 };
    let mut try_blocks = Vec::new();
    for index in 0..u64::from(try_count) {
        reader.spend(5)?;
        let entry = element(map, index, 20)?;
        let (try_low, try_high) = (reader.i32(entry)?, reader.i32(at(entry, 4)?)?);
        let catch_high = reader.i32(at(entry, 8)?)?;
        let catch_count = reader.u32(at(entry, 12)?)?;
        let ordered = 0 <= try_low && try_low <= try_high && try_high <= catch_high && catch_high < max_state as i32;
        if !ordered || catch_count == 0 || catch_count > MAX_CATCHES {
            return None;
        }
        let handlers = reader.data_reference(at(entry, 16)?)?;
        let mut catches = Vec::new();
        for catch in 0..u64::from(catch_count) {
            reader.spend(3)?;
            let entry = element(handlers, catch, handler_size)?;
            let type_descriptor = reader.reference(at(entry, 4)?)?;
            let mangled = match type_descriptor {
                Some(descriptor) => Some(reader.type_name(descriptor)?),
                None => None,
            };
            let handler = reader.code_reference(at(entry, 12)?)??;
            catches.push(CatchHandler { adjectives: reader.u32(entry)?, type_descriptor, mangled, handler });
        }
        try_blocks.push(TryBlock { try_low, try_high, catch_high, ranges: Vec::new(), catches });
    }
    Some(try_blocks)
}

/// Approximate retained bytes of one copy of a parsed try map, names included.
fn try_map_units(try_blocks: &[TryBlock]) -> u64 {
    let catch = |catch: &CatchHandler| CATCH_BYTES + catch.mangled.as_ref().map_or(0, |name| name.len() as u64);
    try_blocks.iter().map(|block| TRY_BYTES + block.catches.iter().map(catch).sum::<u64>()).sum()
}

/// Parses and validates the `FuncInfo` at `address`: every table must be mapped data and every action or
/// handler must be code. Unwind and try maps shared between `FuncInfo` records are parsed once, but every copy
/// is charged to the retention budget.
fn func_info(reader: &Reader, address: u64) -> Option<FuncInfo> {
    reader.spend(6)?;
    if !is_func_info_magic(reader.u32(address)?) {
        return None;
    }
    let max_state = reader.u32(at(address, 4)?)?;
    let try_count = reader.u32(at(address, 12)?)?;
    let ip_count = reader.u32(at(address, 20)?)?;
    if max_state > MAX_STATES || try_count > MAX_TRY_BLOCKS || ip_count > MAX_IP_ENTRIES {
        return None;
    }
    let table = |field: u64, count: u32| -> Option<u64> {
        if count == 0 { Some(0) } else { reader.data_reference(at(address, field)?) }
    };
    let unwind_at = table(8, max_state)?;
    let try_at = table(16, try_count)?;
    let ip_map = if reader.wide { table(24, ip_count)? } else { 0 };

    let cached = reader.unwind_maps.borrow().get(&(unwind_at, max_state)).cloned();
    let unwind = match cached {
        Some(unwind) => unwind,
        None => {
            let unwind = unwind_map(reader, unwind_at, max_state);
            reader.unwind_maps.borrow_mut().insert((unwind_at, max_state), unwind.clone());
            unwind
        }
    }?;
    reader.retain(unwind.len() as u64 * UNWIND_BYTES)?;
    let key = (try_at, try_count, max_state);
    let cached = reader.try_maps.borrow().get(&key).cloned();
    let try_blocks = match cached {
        Some(try_blocks) => try_blocks,
        None => {
            let try_blocks = try_map(reader, try_at, try_count, max_state);
            reader.try_maps.borrow_mut().insert(key, try_blocks.clone());
            try_blocks
        }
    }?;
    reader.retain(try_map_units(&try_blocks))?;

    let mut ip_states = Vec::new();
    for index in 0..u64::from(if reader.wide { ip_count } else { 0 }) {
        reader.spend(2)?;
        reader.retain(RANGE_BYTES)?;
        let entry = element(ip_map, index, 8)?;
        let ip = reader.code_reference(entry)??;
        let state = reader.i32(at(entry, 4)?)?;
        if !(-1..max_state as i32).contains(&state) {
            return None;
        }
        ip_states.push((ip, state));
    }
    ip_states.sort_unstable();
    (!unwind.is_empty() || !try_blocks.is_empty()).then_some(FuncInfo {
        max_state: max_state as i32,
        unwind,
        try_blocks,
        ip_states,
    })
}

/// One x64 unwind range and where its language handler and handler data lie.
struct UnwindRange {
    start: u64,
    end: u64,
    handler: u64,
    data: u64,
}

fn x64_unwind_ranges(reader: &Reader, report: &mut EhReport) -> Vec<UnwindRange> {
    let Some((directory, size)) = reader.binary.pe_layout().and_then(|layout| layout.exception_directory) else {
        return Vec::new();
    };
    let available = reader.binary.read_to_segment_end(directory).unwrap_or_default();
    let table = &available[..size.min(available.len() as u64) as usize];
    let mut ranges = Vec::new();
    for entry in table.as_chunks::<12>().0 {
        let field = |offset: usize| u32::from_le_bytes(entry[offset..offset + 4].try_into().unwrap());
        let (begin, end, unwind) = (field(0), field(4), field(8));
        if begin == 0 || end <= begin || unwind & 1 != 0 {
            continue;
        }
        let Some(info) = reader.image_base.checked_add(u64::from(unwind)) else { continue };
        let Some(header) = reader.binary.read(info, 4) else { continue };
        let flags = header[0] >> 3;
        // Bit 0 and 1: an exception or termination handler follows the unwind codes; bit 2: chained info.
        if flags & 0x4 != 0 || flags & 0x3 == 0 {
            continue;
        }
        let codes = u64::from(header[2]).div_ceil(2) * 4;
        let (Some(handler_field), Some(data)) = (at(info, 4 + codes), at(info, 8 + codes)) else { continue };
        let (Some(start), Some(end)) =
            (reader.image_base.checked_add(u64::from(begin)), reader.image_base.checked_add(u64::from(end)))
        else {
            continue;
        };
        let Some(Some(handler)) = reader.code_reference(handler_field) else {
            report.undecoded_handlers += 1;
            continue;
        };
        ranges.push(UnwindRange { start, end, handler, data });
    }
    ranges.sort_by_key(|range| range.start);
    ranges
}

fn scope_table(reader: &Reader, range: &UnwindRange) -> Option<Vec<SehScope>> {
    let count = reader.u32(range.data)?;
    if count == 0 || count > MAX_SCOPES {
        return None;
    }
    let mut scopes = Vec::new();
    for index in 0..u64::from(count) {
        reader.spend(4)?;
        reader.retain(SCOPE_BYTES)?;
        let entry = element(at(range.data, 4)?, index, 16)?;
        let start = reader.code_reference(entry)??;
        let end = reader.code_reference(at(entry, 4)?)??;
        let handler = reader.u32(at(entry, 8)?)?;
        let target = reader.code_reference(at(entry, 12)?)?;
        let funclet = if handler == 1 { None } else { Some(reader.code_reference(at(entry, 8)?)??) };
        let kind = match (target, funclet) {
            (None, Some(_)) => "finally",
            (Some(_), None) => "except_always",
            (Some(_), Some(_)) => "except",
            (None, None) => return None,
        };
        scopes.push(SehScope { start, end, kind, funclet, target });
    }
    Some(scopes)
}

/// Code ranges whose state lies in `low..=high`: each IP map entry holds until the next one or the end of the
/// unwind range it falls in. `spans` is sorted by start and does not overlap. `None` once the budget is spent.
fn state_ranges(
    reader: &Reader,
    ip_states: &[(u64, i32)],
    spans: &[(u64, u64)],
    low: i32,
    high: i32,
) -> Option<Vec<AddressRange>> {
    reader.spend(ip_states.len() as u64)?;
    let mut ranges: Vec<AddressRange> = Vec::new();
    for (index, &(start, state)) in ip_states.iter().enumerate() {
        if !(low..=high).contains(&state) {
            continue;
        }
        let containing = spans.partition_point(|&(begin, _)| begin <= start).checked_sub(1);
        let Some(&(_, limit)) = containing.map(|index| &spans[index]).filter(|&&(_, end)| start < end) else {
            continue;
        };
        let end = ip_states.get(index + 1).map_or(limit, |&(next, _)| next.min(limit));
        match ranges.last_mut() {
            Some(last) if last.end == start => last.end = end,
            _ if end > start => {
                reader.retain(RANGE_BYTES)?;
                ranges.push(AddressRange { start, end });
            }
            _ => {}
        }
    }
    Some(ranges)
}

fn x64_functions(reader: &Reader, report: &mut EhReport) {
    let ranges = x64_unwind_ranges(reader, report);
    // Unwind ranges by the table they share: a function and each of its funclets name the same `FuncInfo`.
    let mut by_table: BTreeMap<u64, Vec<&UnwindRange>> = BTreeMap::new();
    let mut imports: HashMap<u64, Option<&str>> = HashMap::new();
    for range in &ranges {
        if reader.exhausted() {
            return;
        }
        let import = *imports.entry(range.handler).or_insert_with(|| reader.import_thunk(range.handler));
        if import == Some("__C_specific_handler") {
            match scope_table(reader, range) {
                Some(scopes) if report.functions.len() < MAX_RECORDS => report.functions.push(EhFunction {
                    function: Some(range.start),
                    function_end: Some(range.end),
                    kind: "c_specific_handler",
                    handler: Some(range.handler),
                    handler_import: import.map(str::to_owned),
                    registrations: Vec::new(),
                    table: range.data,
                    max_state: 0,
                    unwind: Vec::new(),
                    try_blocks: Vec::new(),
                    scopes,
                }),
                _ => report.undecoded_handlers += 1,
            }
            continue;
        }
        // `__CxxFrameHandler3` and its security-cookie wrapper both start their data with the `FuncInfo` RVA. A
        // statically linked handler has no name, so the magic decides.
        let table = reader.data_reference(range.data).filter(|&table| {
            import.is_none_or(|name| name == "__CxxFrameHandler3") && reader.u32(table).is_some_and(is_func_info_magic)
        });
        match table {
            Some(table) => by_table.entry(table).or_default().push(range),
            None => report.undecoded_handlers += 1,
        }
    }
    for (table, ranges) in by_table {
        if report.functions.len() >= MAX_RECORDS || reader.exhausted() {
            break;
        }
        let Some(info) = func_info(reader, table) else {
            report.undecoded_handlers += ranges.len();
            continue;
        };
        let mut function = EhFunction {
            function: None,
            function_end: None,
            kind: "cxx_frame_handler3",
            handler: Some(ranges[0].handler),
            handler_import: reader.import_thunk(ranges[0].handler).map(str::to_owned),
            registrations: Vec::new(),
            table,
            max_state: info.max_state,
            unwind: info.unwind,
            try_blocks: info.try_blocks,
            scopes: Vec::new(),
        };
        let funclets: BTreeSet<u64> = function.funclets().collect();
        let owner = ranges.iter().find(|range| !funclets.contains(&range.start)).unwrap_or(&ranges[0]);
        function.function = Some(owner.start);
        function.function_end = Some(owner.end);
        // Unwind ranges of distinct functions do not overlap, so the sorted spans can be binary-searched.
        let spans: Vec<(u64, u64)> = ranges.iter().map(|range| (range.start, range.end)).collect();
        for block in &mut function.try_blocks {
            match state_ranges(reader, &info.ip_states, &spans, block.try_low, block.try_high) {
                Some(ranges) => block.ranges = ranges,
                None => break,
            }
        }
        report.functions.push(function);
    }
}

/// Where an instruction whose imm32 operand starts at the end of `before` begins, when it is one that stores an
/// exception registration's handler: `push imm32`, `mov [ebp+disp8|disp32], imm32` or `mov [esp+disp8], imm32`.
fn registration_start(before: &[u8]) -> Option<usize> {
    let tail = |length: usize| before.len().checked_sub(length).map(|start| (start, &before[start..]));
    match (tail(1), tail(3), tail(4), tail(6)) {
        (Some((start, [0x68])), ..) => Some(start),
        (_, Some((start, [0xc7, 0x45, _])), ..) => Some(start),
        (_, _, Some((start, [0xc7, 0x44, 0x24, _])), _) => Some(start),
        (_, _, _, Some((start, [0xc7, 0x85, ..]))) => Some(start),
        _ => None,
    }
}

/// The target of the `jmp rel32` or `jmp rel8` at `address`.
fn x86_jump_target(reader: &Reader, address: u64) -> Option<u64> {
    let bytes = reader.binary.code_from(address)?;
    match bytes {
        [0xe9, a, b, c, d, ..] => {
            address.checked_add(5)?.checked_add_signed(i64::from(i32::from_le_bytes([*a, *b, *c, *d])))
        }
        [0xeb, offset, ..] => address.checked_add(2)?.checked_add_signed(i64::from(*offset as i8)),
        _ => None,
    }
}

/// x86 has no unwind directory: each function with C++ EH state registers a thunk that loads its `FuncInfo`
/// address into EAX and jumps to the frame handler. The tables are found by their version stamp and validated;
/// the thunk and its registrations are then found by the addresses they encode.
fn x86_functions(reader: &Reader, report: &mut EhReport) {
    let mut tables: BTreeMap<u64, FuncInfo> = BTreeMap::new();
    'sections: for (start, bytes) in reader.data_sections() {
        let skew = ((4 - start % 4) % 4) as usize;
        for (index, word) in bytes[skew.min(bytes.len())..].as_chunks::<4>().0.iter().enumerate() {
            if tables.len() >= MAX_RECORDS || reader.exhausted() {
                break 'sections;
            }
            if !is_func_info_magic(u32::from_le_bytes(*word)) {
                continue;
            }
            let Some(address) = at(start, (skew + index * 4) as u64) else { break };
            if let Some(info) = func_info(reader, address) {
                tables.insert(address, info);
            }
        }
    }
    if tables.is_empty() {
        return;
    }
    let code: Vec<(u64, &[u8])> = reader
        .binary
        .sections
        .iter()
        .filter(|section| section.kind == SectionKind::Code)
        .filter_map(|section| Some((section.address, reader.binary.code_from(section.address)?)))
        .collect();
    // `mov eax, imm32` (B8) loading a table address, directly followed by a jump: the tail of a handler thunk.
    let mut loads: BTreeMap<u64, u64> = BTreeMap::new();
    for &(start, bytes) in &code {
        for (offset, window) in bytes.windows(6).enumerate() {
            let table = u64::from(u32::from_le_bytes(window[1..5].try_into().unwrap()));
            if window[0] == 0xb8 && matches!(window[5], 0xe9 | 0xeb | 0xff) && tables.contains_key(&table) {
                let Some(load) = at(start, offset as u64) else { continue };
                loads.entry(table).or_insert(load);
            }
        }
    }
    // Storing the address of such a thunk (at or shortly before its load) into the frame's registration record
    // registers it: MSVC pushes it (`push imm32`), clang moves it into the record (`mov [ebp+disp], imm32`).
    let mut registrations: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
    let by_load: BTreeMap<u64, u64> = loads.iter().map(|(&table, &load)| (load, table)).collect();
    for &(start, bytes) in &code {
        for offset in 1..bytes.len().saturating_sub(3) {
            let Some(instruction) = registration_start(&bytes[..offset]) else { continue };
            let stored = u64::from(u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()));
            let Some((_, &table)) = by_load.range(stored..=stored.saturating_add(X86_THUNK_PREFIX)).next() else {
                continue;
            };
            let Some(at_instruction) = at(start, instruction as u64) else { continue };
            if reader.retain(RANGE_BYTES).is_none() {
                break;
            }
            registrations.entry(table).or_default().push((at_instruction, stored));
        }
    }
    for (table, info) in tables {
        let stores = registrations.remove(&table).unwrap_or_default();
        let load = loads.get(&table).copied();
        // The thunk starts at the stored address nearest its load: a stray `push imm32` of an address further
        // back would otherwise seed a start inside the preceding code. Without a registration, at the load.
        let handler = stores.iter().map(|&(_, stored)| stored).max().or(load);
        let handler_import = load
            .and_then(|load| at(load, 5))
            .and_then(|jump| x86_jump_target(reader, jump))
            .and_then(|target| reader.import_thunk(target).map(str::to_owned));
        report.functions.push(EhFunction {
            function: None,
            function_end: None,
            kind: "cxx_frame_handler3",
            handler,
            handler_import,
            registrations: stores.iter().map(|&(instruction, _)| instruction).collect(),
            table,
            max_state: info.max_state,
            unwind: info.unwind,
            try_blocks: info.try_blocks,
            scopes: Vec::new(),
        });
    }
}

fn throw_info(reader: &Reader, address: u64) -> Option<ThrowInfo> {
    reader.spend(4)?;
    let attributes = reader.u32(address)?;
    // Bits: const, volatile, unaligned, pure (CLR), WinRT. A forward-compatibility handler is never emitted.
    if attributes > 0x1f || reader.u32(at(address, 8)?)? != 0 {
        return None;
    }
    let array = reader.data_reference(at(address, 12)?)?;
    let count = reader.u32(array)?;
    if count == 0 || count > MAX_CATCHABLE_TYPES {
        return None;
    }
    let destructor = reader.code_reference(at(address, 4)?)?;
    let mut types = Vec::new();
    for index in 0..u64::from(count) {
        reader.spend(4)?;
        let entry = reader.data_reference(element(at(array, 4)?, index, 4)?)?;
        // properties, pType, this displacement (mdisp, pdisp, vdisp), sizeOrOffset, copyFunction.
        if reader.u32(entry)? > 0x1f {
            return None;
        }
        let type_descriptor = reader.data_reference(at(entry, 4)?)?;
        let mangled = reader.type_name(type_descriptor)?;
        let copy_function = reader.code_reference(at(entry, 24)?)?;
        reader.retain(CATCH_BYTES)?;
        types.push(CatchableType { type_descriptor, mangled, size: reader.u32(at(entry, 20)?)?, copy_function });
    }
    Some(ThrowInfo { address, attributes, destructor, types })
}

fn throws(reader: &Reader, report: &mut EhReport) {
    for (start, bytes) in reader.data_sections() {
        let skew = ((4 - start % 4) % 4) as usize;
        let words = bytes[skew.min(bytes.len())..].as_chunks::<4>().0;
        for (index, record) in words.windows(4).enumerate() {
            // Cheap reject before the full parse: a small attribute bit set, no forward-compatibility handler
            // and a catchable-type array.
            let field = |position: usize| u32::from_le_bytes(record[position]);
            if field(0) > 0x1f || field(2) != 0 || field(3) == 0 {
                continue;
            }
            if report.throws.len() >= MAX_RECORDS {
                report.warnings.push(format!("throw-info scan stopped at its {MAX_RECORDS}-record cap"));
                return;
            }
            if reader.exhausted() {
                return;
            }
            let Some(address) = at(start, (skew + index * 4) as u64) else { return };
            if let Some(info) = throw_info(reader, address) {
                report.throws.push(info);
            }
        }
    }
}

/// Reads the image's vftables and exception tables under one budget. Empty for formats and machines other than
/// x86 and x64 PE.
///
/// Decoded: vftables found through their RTTI complete object locators; `FuncInfo` of `__CxxFrameHandler3`
/// (unwind map, try blocks with typed catch handlers and, on x64, the code ranges of each try block); the
/// `__C_specific_handler` scope table when that handler is an import thunk; and `_ThrowInfo` records. Not decoded:
/// the compressed `__CxxFrameHandler4` tables and SEH on x86.
pub fn read(binary: &Binary) -> MsvcMetadata {
    read_with_budget(binary, WORK_BUDGET, RETAIN_BUDGET)
}

fn read_with_budget(binary: &Binary, work: u64, retain: u64) -> MsvcMetadata {
    let Some(reader) = Reader::new(binary, work, retain) else { return MsvcMetadata::default() };
    let mut metadata = MsvcMetadata { vftables: read_vftables(&reader), ..MsvcMetadata::default() };
    let report = &mut metadata.exceptions;
    if reader.wide {
        x64_functions(&reader, report);
    } else {
        x86_functions(&reader, report);
    }
    throws(&reader, report);
    report.functions.sort_by_key(|function| (function.function, function.table));
    if reader.exhausted() {
        metadata.budget_exhausted = true;
        report.warnings.push(format!(
            "MSVC metadata budget exhausted ({work} work units, {retain} retained bytes); later vftables and \
             exception tables were not read"
        ));
    }
    metadata
}

/// Code addresses the tables name that calls do not reach: vftable slots, funclets, x86 handler thunks, and the
/// destructors and copy constructors of thrown types.
pub(crate) fn code_targets(binary: &Binary, metadata: &MsvcMetadata) -> Vec<u64> {
    let mut targets: Vec<u64> = metadata.vftables.iter().flat_map(|table| table.slots.iter().copied()).collect();
    for function in &metadata.exceptions.functions {
        targets.extend(function.funclets());
        // On x64 the handler is the shared frame handler, already an unwind range or import thunk.
        if binary.arch == Arch::X86 {
            targets.extend(function.handler);
        }
    }
    for throw in &metadata.exceptions.throws {
        targets.extend(throw.destructor);
        targets.extend(throw.types.iter().filter_map(|caught| caught.copy_function));
    }
    targets
}

#[cfg(test)]
mod tests;
