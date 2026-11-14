//! CMSIS-SVD peripheral maps on a project. `import_svd` stores each peripheral of an SVD file as a
//! [`Field::Peripheral`] annotation at its base address. From there:
//! - decompilation types each peripheral as a struct global at its base (`TIMER0.CR = uVar1 | 0x21;`, volatile) and
//!   comments bit-field constants on lines that touch a register (`/* TIMER0.CR: EN|MODE=Single_MATCH */`);
//! - addresses inside a peripheral are named `TIMER0.CR` in disassembly, xrefs and evaluation faults, and those
//!   names resolve wherever an address is accepted;
//! - a p-code scan of every function finds the loads and stores whose address is a constant, so xrefs and
//!   `peripheral_access` answer which functions touch a peripheral or register.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use rampage_analysis::discover::XrefKind;
use rampage_decompiler::sleigh_decode::{DecodeStatus, SleighDecoder, Varnode};
use serde::Serialize;

use crate::annotations::Field;
use crate::svd::{self, Peripheral, Register};
use crate::{ApiError, Project};

/// Stored peripherals together may hold at most this much JSON; past it descriptions are dropped, then the import
/// is refused.
const MAX_STORED_BYTES: usize = 4 << 20;
const MAX_REPORTED: usize = 32;
/// Most instructions one access scan decodes, and most accesses it keeps.
const MAX_SCAN_INSTRUCTIONS: usize = 4_000_000;
const MAX_ACCESSES: usize = 1 << 20;
/// Largest peripheral struct handed to the decompiler (its global limit).
const MAX_STRUCT_BYTES: u64 = 1 << 20;

pub(crate) fn decode(value: &str) -> Result<Peripheral, String> {
    let mut peripheral: Peripheral =
        serde_json::from_str(value).map_err(|error| format!("peripheral annotation: {error}"))?;
    // Lookups rely on offset order; a stable sort keeps alternates in declaration order.
    peripheral.registers.sort_by_key(|register| register.offset);
    let identifier = |name: &str| svd::identifier(name) == name;
    if !identifier(&peripheral.name) || peripheral.registers.len() > 65_536 {
        return Err(format!("peripheral annotation {:?} is malformed", peripheral.name));
    }
    for register in &peripheral.registers {
        let field_ok = register.fields.iter().all(|field| {
            identifier(&field.name)
                && field.width >= 1
                && field.lsb.checked_add(field.width).is_some_and(|end| end <= register.bits)
        });
        let end = register.offset.checked_add(register.bytes()).and_then(|end| peripheral.base.checked_add(end));
        if register.name.is_empty() || !(1..=64).contains(&register.bits) || end.is_none() || !field_ok {
            return Err(format!("peripheral annotation {}.{} is malformed", peripheral.name, register.name));
        }
    }
    Ok(peripheral)
}

pub(crate) fn encode(peripheral: &Peripheral) -> Result<String, String> {
    serde_json::to_string(peripheral).map_err(|error| error.to_string())
}

/// What lies at an address inside an imported peripheral.
pub(crate) struct Hit<'a> {
    pub peripheral: &'a Peripheral,
    pub register: Option<&'a Register>,
    /// Offset from the peripheral base.
    pub offset: u64,
}

impl Hit<'_> {
    pub fn name(&self) -> String {
        match self.register {
            Some(register) if register.offset == self.offset => format!("{}.{}", self.peripheral.name, register.name),
            Some(register) => {
                format!("{}.{}+{}", self.peripheral.name, register.name, self.offset - register.offset)
            }
            None => format!("{}+{:#x}", self.peripheral.name, self.offset),
        }
    }
}

/// The imported peripherals, by base address and by name.
#[derive(Debug, Default)]
pub(crate) struct PeripheralMap {
    by_base: BTreeMap<u64, Peripheral>,
    by_name: HashMap<String, u64>,
    /// The largest span, which bounds how far below an address a covering peripheral's base can lie.
    widest: u64,
}

impl PeripheralMap {
    pub fn new(stored: &BTreeMap<u64, String>) -> Self {
        let mut map = PeripheralMap::default();
        for value in stored.values() {
            if let Ok(peripheral) = decode(value) {
                map.by_name.entry(peripheral.name.clone()).or_insert(peripheral.base);
                map.widest = map.widest.max(peripheral.span());
                map.by_base.insert(peripheral.base, peripheral);
            }
        }
        map
    }

    pub fn is_empty(&self) -> bool {
        self.by_base.is_empty()
    }

    pub fn peripherals(&self) -> impl Iterator<Item = &Peripheral> {
        self.by_base.values()
    }

    pub fn named(&self, name: &str) -> Option<&Peripheral> {
        self.by_name.get(name).and_then(|base| self.by_base.get(base))
    }

    /// The peripheral (and register) whose registers cover `address`: of overlapping peripherals the one with the
    /// highest base; of overlapping registers one starting exactly there, else the covering one starting highest,
    /// the first declared breaking ties.
    pub fn at(&self, address: u64) -> Option<Hit<'_>> {
        let lowest = address.saturating_sub(self.widest);
        let peripheral = self
            .by_base
            .range(lowest..=address)
            .rev()
            .map(|(_, peripheral)| peripheral)
            .find(|peripheral| address - peripheral.base < peripheral.span())?;
        let offset = address - peripheral.base;
        let end = peripheral.registers.partition_point(|register| register.offset <= offset);
        // Registers are sorted by offset (stably, so alternates sharing one stay in declaration order). Walking
        // down, the first covering register has the highest offset; keep walking through that same offset to reach
        // the first declared.
        let mut register: Option<&Register> = None;
        for candidate in peripheral.registers[..end].iter().rev() {
            if register.is_some_and(|found| found.offset != candidate.offset) || candidate.offset + 8 < offset {
                break;
            }
            if offset < candidate.offset + candidate.bytes() {
                register = Some(candidate);
            }
        }
        Some(Hit { peripheral, register, offset })
    }

    pub fn name(&self, address: u64) -> Option<String> {
        self.at(address).map(|hit| hit.name())
    }

    /// The address of `PERIPHERAL` or `PERIPHERAL.REGISTER`.
    pub fn resolve(&self, text: &str) -> Option<u64> {
        let (peripheral, register) = match text.split_once('.') {
            Some((peripheral, register)) => (peripheral, Some(register)),
            None => (text, None),
        };
        let peripheral = self.named(peripheral)?;
        match register {
            None => Some(peripheral.base),
            Some(name) => peripheral
                .registers
                .iter()
                .find(|register| register.name == name)
                .map(|register| peripheral.base + register.offset),
        }
    }
}

/// The address `text` names, given what a symbol (or the analyst's name) and an imported peripheral say: one of
/// them, or an ambiguity error naming both when they differ.
pub(crate) fn unambiguous(text: &str, symbol: Option<u64>, peripheral: Option<u64>) -> Result<Option<u64>, ApiError> {
    match (symbol, peripheral) {
        (Some(symbol), Some(peripheral)) if symbol != peripheral => Err(ApiError::Invalid(format!(
            "{text:?} is ambiguous: a symbol at {symbol:#x} and an imported peripheral register at {peripheral:#x}; \
             pass the address"
        ))),
        (symbol, peripheral) => Ok(symbol.or(peripheral)),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Import

#[derive(Debug, Clone)]
pub struct ImportSvdRequest {
    pub svd: PathBuf,
    pub apply: bool,
}

#[derive(Debug, Serialize)]
pub struct ImportSvdReport {
    pub device: String,
    pub applied: bool,
    pub peripherals: usize,
    pub registers: usize,
    pub fields: usize,
    /// Changes to the project's peripheral annotations, as previewed or applied.
    pub added: usize,
    pub replaced: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Peripherals given no struct type in decompilation (overlapping another or an analyst global); their
    /// addresses are still named.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub untyped: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub descriptions_dropped: bool,
    /// Elements the reader left out, and duplicates skipped. At most 32 are listed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub omitted_warnings: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn read_svd(path: &std::path::Path) -> Result<String, ApiError> {
    let load = |error: std::io::Error| ApiError::Invalid(format!("{}: {error}", path.display()));
    let metadata = std::fs::metadata(path).map_err(load)?;
    if !metadata.is_file() {
        return Err(ApiError::Invalid(format!("{} is not a regular file", path.display())));
    }
    if metadata.len() > svd::MAX_SVD_BYTES {
        return Err(ApiError::Invalid(format!("{} is larger than {} bytes", path.display(), svd::MAX_SVD_BYTES)));
    }
    let bytes = std::fs::read(path).map_err(load)?;
    if bytes.len() as u64 > svd::MAX_SVD_BYTES {
        return Err(ApiError::Invalid(format!("{} is larger than {} bytes", path.display(), svd::MAX_SVD_BYTES)));
    }
    String::from_utf8(bytes).map_err(|_| ApiError::Invalid(format!("{} is not UTF-8 text", path.display())))
}

impl Project {
    /// Reads the CMSIS-SVD file and previews, or with `apply` stores, its peripherals as annotations, replacing any
    /// imported before. One undo step reverts an apply.
    pub fn import_svd(&self, request: &ImportSvdRequest) -> Result<ImportSvdReport, ApiError> {
        let text = read_svd(&request.svd)?;
        let device = svd::parse(&text).map_err(ApiError::Invalid)?;
        let mut warnings = device.warnings;
        let mut peripherals: BTreeMap<u64, Peripheral> = BTreeMap::new();
        let mut names = std::collections::HashSet::new();
        for peripheral in device.peripherals {
            if peripherals.contains_key(&peripheral.base) || !names.insert(peripheral.name.clone()) {
                warnings.push(format!(
                    "peripheral {} at {:#x} duplicates a name or base; skipped",
                    peripheral.name, peripheral.base
                ));
                continue;
            }
            peripherals.insert(peripheral.base, peripheral);
        }
        let mut encoded = encode_all(&peripherals)?;
        let mut descriptions_dropped = false;
        if encoded.values().map(String::len).sum::<usize>() > MAX_STORED_BYTES {
            for peripheral in peripherals.values_mut() {
                peripheral.description = None;
                for register in &mut peripheral.registers {
                    register.description = None;
                    register.fields.iter_mut().for_each(|field| field.description = None);
                }
            }
            encoded = encode_all(&peripherals)?;
            descriptions_dropped = true;
            if encoded.values().map(String::len).sum::<usize>() > MAX_STORED_BYTES {
                return Err(ApiError::Invalid(format!(
                    "the SVD's peripherals need more than {MAX_STORED_BYTES} bytes of annotations"
                )));
            }
        }
        let current = self.annotations().peripherals().clone();
        let mut changes: Vec<(Field, u64, Option<String>)> = Vec::new();
        let (mut added, mut replaced, mut unchanged) = (0, 0, 0);
        for (&base, value) in &encoded {
            match current.get(&base) {
                Some(old) if old == value => unchanged += 1,
                Some(_) => {
                    replaced += 1;
                    changes.push((Field::Peripheral, base, Some(value.clone())));
                }
                None => {
                    added += 1;
                    changes.push((Field::Peripheral, base, Some(value.clone())));
                }
            }
        }
        let removed: Vec<u64> = current.keys().filter(|base| !encoded.contains_key(base)).copied().collect();
        changes.extend(removed.iter().map(|&base| (Field::Peripheral, base, None)));
        let widest = peripherals.values().map(Peripheral::span).max().unwrap_or(0);
        let candidate = PeripheralMap { by_name: HashMap::new(), by_base: peripherals, widest };
        let untyped = {
            let mapped = crate::decompile::mapped_ranges(&self.binary);
            let highest = crate::decompile::highest_data_address(&self.binary);
            struct_plan(&candidate, &occupied(&self.annotations()), &mapped, highest).1
        };
        if request.apply && !changes.is_empty() {
            self.set_peripheral_annotations(&changes)?;
        }
        let omitted_warnings = warnings.len().saturating_sub(MAX_REPORTED);
        warnings.truncate(MAX_REPORTED);
        Ok(ImportSvdReport {
            device: device.name,
            applied: request.apply,
            peripherals: candidate.by_base.len(),
            registers: candidate.by_base.values().map(|peripheral| peripheral.registers.len()).sum(),
            fields: candidate
                .by_base
                .values()
                .flat_map(|peripheral| &peripheral.registers)
                .map(|register| register.fields.len())
                .sum(),
            added,
            replaced,
            removed: removed.len(),
            unchanged,
            untyped: untyped.into_iter().take(MAX_REPORTED).collect(),
            descriptions_dropped,
            warnings,
            omitted_warnings,
        })
    }

    fn set_peripheral_annotations(&self, changes: &[(Field, u64, Option<String>)]) -> Result<(), ApiError> {
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        // Without a decompiler image (a Raw profile with no C model) the map still names addresses; there is no
        // engine to check its structs against.
        let decompiles = !crate::decompile::mapped_ranges(&self.binary).is_empty();
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|current| {
            self.validate_patch_context(current)?;
            current
                .set_batch_validated(changes, |candidate| {
                    if decompiles { self.validate_annotation_snapshot(&state, &options, candidate) } else { Ok(()) }
                })
                .map_err(ApiError::Invalid)
                .map(|_| ())
        })
    }

    /// An unmapped_read/unmapped_write detail with the imported register at the faulting `address` appended.
    pub(crate) fn name_unmapped_register(
        &self,
        stop: crate::evaluate::StopReason,
        detail: String,
        address: Option<u64>,
    ) -> String {
        use crate::evaluate::StopReason;
        let name = address
            .filter(|_| matches!(stop, StopReason::UnmappedRead | StopReason::UnmappedWrite))
            .and_then(|address| self.peripheral_name(address));
        match name {
            Some(name) => format!("{detail} ({name})"),
            None => detail,
        }
    }

    /// The width in bytes of the imported register starting at `address`, else 4.
    pub(crate) fn register_bytes(&self, address: u64) -> usize {
        let map = self.peripheral_map();
        map.at(address)
            .and_then(|hit| hit.register.filter(|register| register.offset == hit.offset))
            .map_or(4, |register| register.bytes() as usize)
    }

    /// The imported peripherals' index.
    pub(crate) fn peripheral_map(&self) -> Arc<PeripheralMap> {
        self.annotations().peripheral_map()
    }

    /// `PERIPHERAL.REGISTER` at `address`, when an imported peripheral covers it.
    pub(crate) fn peripheral_name(&self, address: u64) -> Option<String> {
        let map = self.peripheral_map();
        if map.is_empty() { None } else { map.name(address) }
    }
}

fn encode_all(peripherals: &BTreeMap<u64, Peripheral>) -> Result<BTreeMap<u64, String>, ApiError> {
    peripherals
        .iter()
        .map(|(&base, peripheral)| encode(peripheral).map(|value| (base, value)).map_err(ApiError::Invalid))
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Decompiler types

/// Address ranges analyst globals and typed data already hold, which peripheral globals must not overlap.
fn occupied(annotations: &crate::annotations::Annotations) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = annotations.globals().keys().map(|&address| (address, address + 1)).collect();
    for (&address, value) in annotations.data_types() {
        let length = crate::annotations::parse_data_type(value).map_or(1, |entry| u64::from(entry.byte_length.max(1)));
        ranges.push((address, address.saturating_add(length)));
    }
    ranges
}

fn scalar(bytes: u64) -> Option<&'static str> {
    match bytes {
        1 => Some("uint1"),
        2 => Some("uint2"),
        4 => Some("uint4"),
        8 => Some("uint8"),
        _ => None,
    }
}

/// The struct declaration of one peripheral and its size, or `None` when no register can be typed.
fn struct_declaration(peripheral: &Peripheral) -> Option<(String, u64)> {
    let mut members: Vec<String> = Vec::new();
    let mut end = 0u64;
    let mut alignment = 1u64;
    let registers = &peripheral.registers;
    let mut index = 0;
    while index < registers.len() {
        let register = &registers[index];
        index += 1;
        let size = register.bytes();
        let Some(kind) = scalar(size) else { continue };
        if register.offset < end || !register.offset.is_multiple_of(size) {
            continue;
        }
        // `X[0]`, `X[1]`, ... at consecutive offsets become one array member.
        let (name, count) = match register.name.strip_suffix("[0]") {
            Some(stem) => {
                let mut count = 1;
                while let Some(next) = registers.get(index)
                    && next.name == format!("{stem}[{count}]")
                    && next.offset == register.offset + count * size
                    && next.bytes() == size
                {
                    count += 1;
                    index += 1;
                }
                (stem.to_owned(), Some(count))
            }
            None if register.name.contains('[') => (register.name.replace(['[', ']'], "_"), None),
            None => (register.name.clone(), None),
        };
        if register.offset > end {
            members.push(format!("uint1 _reserved_{end:x}[{}];", register.offset - end));
        }
        members.push(match count {
            Some(count) => format!("{kind} {name}[{count}];"),
            None => format!("{kind} {name};"),
        });
        end = register.offset + size * count.unwrap_or(1);
        alignment = alignment.max(size);
    }
    if members.is_empty() {
        return None;
    }
    let size = end.next_multiple_of(alignment);
    if size > end {
        members.push(format!("uint1 _reserved_{end:x}[{}];", size - end));
    }
    (size <= MAX_STRUCT_BYTES).then(|| (format!("struct {}_regs {{ {} }};", peripheral.name, members.join(" ")), size))
}

/// One peripheral typed for decompilation: a struct global at its base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Typed {
    pub base: u64,
    pub size: u64,
    pub declaration: String,
    pub global: String,
    /// The image maps nothing there, so the decompiler gets a writable, zero-filled region for it.
    pub unmapped: bool,
}

/// The peripherals typed for decompilation, and the names of those left untyped: overlapping an earlier one,
/// `occupied`, code or the edge of a mapped range, or past `highest`. `mapped` is the decompiler image as
/// `(start, end, executable)`.
fn struct_plan(
    map: &PeripheralMap,
    occupied: &[(u64, u64)],
    mapped: &[(u64, u64, bool)],
    highest: u64,
) -> (Vec<Typed>, Vec<String>) {
    let mut typed = Vec::new();
    let mut untyped = Vec::new();
    let mut taken: Vec<(u64, u64)> = occupied.to_vec();
    for peripheral in map.peripherals() {
        let Some((declaration, size)) = struct_declaration(peripheral) else { continue };
        let (start, end) = (peripheral.base, peripheral.base.saturating_add(size));
        let overlapping: Vec<&(u64, u64, bool)> =
            mapped.iter().filter(|&&(first, last, _)| first < end && start < last).collect();
        let inside_data = matches!(overlapping.as_slice(), [(first, last, false)] if *first <= start && end <= *last);
        if taken.iter().any(|&(first, last)| first < end && start < last)
            || end - 1 > highest
            || !(overlapping.is_empty() || inside_data)
        {
            untyped.push(peripheral.name.clone());
            continue;
        }
        taken.push((start, end));
        let name = &peripheral.name;
        typed.push(Typed {
            base: start,
            size,
            declaration,
            global: format!("struct {name}_regs {name};"),
            unmapped: overlapping.is_empty(),
        });
    }
    (typed, untyped)
}

/// The decompiler's typed peripherals over an image mapping `mapped` as `(start, end, executable)`.
pub(crate) fn decompiler_typing(
    annotations: &crate::annotations::Annotations,
    mapped: &[(u64, u64, bool)],
    highest: u64,
) -> Vec<Typed> {
    let map = annotations.peripheral_map();
    if map.is_empty() {
        return Vec::new();
    }
    struct_plan(&map, &occupied(annotations), mapped, highest).0
}

/// Decompiler operations marking every imported peripheral's registers volatile, typed or not, so loads and stores
/// to them are never merged, forwarded or dropped. They precede the globals, which take the property.
pub(crate) fn volatile_operations(
    annotations: &crate::annotations::Annotations,
    highest: u64,
) -> Vec<rampage_decompiler::worker::WorkerOperation> {
    let map = annotations.peripheral_map();
    map.peripherals()
        .filter(|peripheral| peripheral.span() > 0)
        .filter_map(|peripheral| {
            let last = peripheral.base.checked_add(peripheral.span() - 1)?.min(highest);
            (peripheral.base <= last)
                .then_some(rampage_decompiler::worker::WorkerOperation::VolatileRange { first: peripheral.base, last })
        })
        .collect()
}

/// Decompiler operations declaring each typed peripheral's struct and global.
pub(crate) fn decompiler_operations(typed: &[Typed]) -> Vec<rampage_decompiler::worker::WorkerOperation> {
    use rampage_decompiler::worker::WorkerOperation;
    typed
        .iter()
        .flat_map(|peripheral| {
            [
                WorkerOperation::ParseTypes { declarations: peripheral.declaration.clone() },
                WorkerOperation::Global { address: peripheral.base, declaration: peripheral.global.clone() },
            ]
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Bit-field comments in decompiled C

/// The fields a constant sets in `register`: `EN|MODE=Single_MATCH`, or `~EN` for a mask that clears them.
fn describe_constant(register: &Register, value: u64) -> Option<String> {
    let width_mask = if register.bits >= 64 { u64::MAX } else { (1u64 << register.bits) - 1 };
    let mut value = value & width_mask;
    if value == 0 || register.fields.is_empty() {
        return None;
    }
    let inverted = value.count_ones() * 2 > register.bits && (!value & width_mask) != 0;
    if inverted {
        value = !value & width_mask;
    }
    let mut parts = Vec::new();
    for field in &register.fields {
        let mask = if field.width >= 64 { u64::MAX } else { ((1u64 << field.width) - 1) << field.lsb };
        let bits = value & mask;
        if bits == 0 {
            continue;
        }
        let shifted = bits >> field.lsb;
        if field.width == 1 || (bits == mask && !inverted && field.values.iter().all(|(_, value)| *value != shifted)) {
            parts.push(field.name.clone());
        } else {
            let label = field.values.iter().find(|(_, value)| *value == shifted).map(|(name, _)| name.clone());
            parts.push(format!("{}={}", field.name, label.unwrap_or_else(|| format!("{shifted:#x}"))));
        }
        if parts.len() == 6 {
            parts.push("…".to_owned());
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    let text = parts.join("|");
    Some(if inverted { format!("~({text})") } else { text })
}

/// The integer literals of a line of C, skipping subscripts, shift counts and parts of identifiers.
fn literals(line: &str) -> Vec<u64> {
    let bytes = line.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let character = bytes[index];
        let previous = index.checked_sub(1).map(|at| bytes[at]);
        if character.is_ascii_digit() && !previous.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric()) {
                index += 1;
            }
            let token = line[start..index].trim_end_matches(['U', 'u', 'L', 'l']);
            let parsed = match token.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => token.parse().ok(),
            };
            // Subscripts and shift counts are not register values.
            let before = line[..start].trim_end();
            // A literal right after `-` is negative: a comparison bound, not a mask.
            if previous != Some(b'[')
                && previous != Some(b'-')
                && !before.ends_with("<<")
                && !before.ends_with(">>")
                && let Some(value) = parsed
            {
                result.push(value);
            }
            continue;
        }
        index += 1;
    }
    result
}

/// Registers named on a line as `PERIPHERAL.REGISTER`.
fn registers_on<'a>(map: &'a PeripheralMap, line: &str) -> Vec<&'a Register> {
    let mut found: Vec<&Register> = Vec::new();
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(dot) = line[start..].find('.').map(|at| at + start) {
        let begin = line[..dot]
            .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .map_or(0, |at| at + 1);
        let mut end = dot + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let peripheral = &line[begin..dot];
        let member = &line[dot + 1..end];
        if let Some(peripheral) = map.named(peripheral) {
            // An array member is followed by its subscript.
            let subscripted = line[end..]
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
                .map(|(index, _)| format!("{member}[{index}]"));
            let register = peripheral.registers.iter().find(|register| {
                register.name == member || subscripted.as_deref().is_some_and(|name| register.name == name)
            });
            if let Some(register) = register
                && !found.iter().any(|seen| std::ptr::eq(*seen, register))
            {
                found.push(register);
            }
        }
        start = dot + 1;
    }
    found
}

impl Project {
    /// Appends a comment naming the bit fields of each constant on a line that touches exactly one register.
    pub(crate) fn annotate_register_fields(&self, decompilation: &mut crate::Decompilation) {
        let map = self.peripheral_map();
        if map.is_empty() {
            return;
        }
        let mut insertions: Vec<(usize, String)> = Vec::new();
        let mut position = 0;
        for line in decompilation.code.split_inclusive('\n') {
            let body = line.trim_end_matches('\n');
            let registers = registers_on(&map, body);
            if let [register] = registers.as_slice() {
                let named: Vec<String> =
                    literals(body).into_iter().filter_map(|value| describe_constant(register, value)).collect();
                if !named.is_empty() && !body.contains("/*") {
                    insertions.push((position + body.len(), format!(" /* {}: {} */", register.name, named.join(", "))));
                }
            }
            position += line.len();
        }
        for (at, text) in insertions.into_iter().rev() {
            decompilation.code.insert_str(at, &text);
            for token in &mut decompilation.tokens {
                if let Some((start, end)) = token.span.as_mut().filter(|(start, _)| *start >= at) {
                    *start += text.len();
                    *end += text.len();
                }
            }
            let index = decompilation
                .tokens
                .iter()
                .position(|token| token.span.is_some_and(|(start, _)| start >= at + text.len()))
                .unwrap_or(decompilation.tokens.len());
            decompilation.tokens.insert(
                index,
                crate::decompile::DecompiledToken {
                    text: text.clone(),
                    kind: "comment".to_owned(),
                    address: None,
                    span: Some((at, at + text.len())),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Constant-address accesses

/// A load or store whose address is a constant the function forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Access {
    pub instruction: u64,
    pub function: u64,
    pub address: u64,
    pub write: bool,
}

/// Every constant-address access outside read-only image memory, sorted by address, and their indices by
/// instruction.
#[derive(Debug, Default)]
pub(crate) struct AccessIndex {
    pub by_address: Vec<Access>,
    by_instruction: Vec<usize>,
    /// The scan stopped at its instruction or access budget.
    pub incomplete: bool,
}

impl AccessIndex {
    pub fn in_range(&self, start: u64, end: u64) -> &[Access] {
        let first = self.by_address.partition_point(|access| access.address < start);
        let last = self.by_address.partition_point(|access| access.address < end);
        &self.by_address[first..last]
    }

    pub fn at_instruction(&self, instruction: u64) -> impl Iterator<Item = &Access> {
        let first = self.by_instruction.partition_point(|&index| self.by_address[index].instruction < instruction);
        self.by_instruction[first..]
            .iter()
            .map(|&index| &self.by_address[index])
            .take_while(move |access| access.instruction == instruction)
    }
}

/// Known varnode values at a point of a function: `(space, offset, size)` to value.
type Values = HashMap<(u32, u64, u32), u64>;

fn mask(value: u64, size: u32) -> u64 {
    if size >= 8 { value } else { value & ((1u64 << (8 * size)) - 1) }
}

/// One decoded basic block: its instructions' p-code and the blocks it may continue to.
struct DecodedBlock {
    start: u64,
    instructions: Vec<(u64, Vec<rampage_decompiler::sleigh_decode::PcodeOp>)>,
    successors: Vec<u64>,
}

/// What the scan needs to evaluate p-code: the decoder's spaces, the image and the call-preserved registers.
struct Evaluator<'a> {
    binary: &'a rampage_loaders::Binary,
    constant: u32,
    register: Option<u32>,
    ram: u32,
    preserved: Vec<(u64, u32)>,
}

impl Evaluator<'_> {
    fn value(&self, node: &Varnode, values: &Values) -> Option<u64> {
        let offset = node.offset?;
        if node.space == self.constant {
            return Some(mask(offset, node.size));
        }
        if node.space == self.ram {
            return self.binary.read_constant(offset, u8::try_from(node.size).ok()?);
        }
        values.get(&(node.space, offset, node.size)).copied()
    }

    /// Runs one instruction's p-code over `values`, appending the accesses it makes at constant addresses outside
    /// read-only image memory to `accesses`.
    fn step(
        &self,
        ops: &[rampage_decompiler::sleigh_decode::PcodeOp],
        values: &mut Values,
        mut record: impl FnMut(u64, bool),
    ) {
        // After a CBRANCH inside the instruction (ARM conditional execution, IT blocks) the rest of its p-code may
        // not run, so what it writes is unknown.
        let mut conditional = false;
        for op in ops {
            let branch = matches!(op.name.as_str(), "BRANCH" | "CBRANCH" | "CALL");
            // Direct memory operands in the code space are accesses at constant addresses.
            for (node, write) in
                op.inputs.iter().map(|node| (node, false)).chain(op.output.iter().map(|node| (node, true)))
            {
                if !branch
                    && node.space == self.ram
                    && let Some(at) = node.offset
                    && (write || self.binary.read_constant(at, u8::try_from(node.size).unwrap_or(0)).is_none())
                {
                    record(at, write);
                }
            }
            let input = |index: usize| op.inputs.get(index).and_then(|node| self.value(node, values));
            let size = op.output.as_ref().map_or(8, |node| node.size);
            let result = match op.name.as_str() {
                "LOAD" | "STORE" => {
                    let write = op.name == "STORE";
                    input(1).and_then(|at| {
                        let bytes = if write { op.inputs.get(2).map_or(0, |node| node.size) } else { size };
                        let folded =
                            (!write).then(|| self.binary.read_constant(at, u8::try_from(bytes).unwrap_or(0))).flatten();
                        if folded.is_none() {
                            record(at, write);
                        }
                        folded
                    })
                }
                "CALL" | "CALLIND" => {
                    values.retain(|&(space, offset, size), _| {
                        Some(space) == self.register && self.preserved.contains(&(offset, size))
                    });
                    None
                }
                "COPY" | "INT_ZEXT" => input(0),
                "INT_SEXT" => op.inputs.first().zip(input(0)).map(|(node, value)| {
                    let bits = 8 * node.size.clamp(1, 8);
                    (((value << (64 - bits)) as i64) >> (64 - bits)) as u64
                }),
                "INT_ADD" => input(0).zip(input(1)).map(|(a, b)| a.wrapping_add(b)),
                "INT_SUB" => input(0).zip(input(1)).map(|(a, b)| a.wrapping_sub(b)),
                "INT_OR" => input(0).zip(input(1)).map(|(a, b)| a | b),
                "INT_AND" => input(0).zip(input(1)).map(|(a, b)| a & b),
                "INT_XOR" => input(0).zip(input(1)).map(|(a, b)| a ^ b),
                "INT_LEFT" => input(0).zip(input(1)).map(|(a, b)| if b < 64 { a << b } else { 0 }),
                "INT_RIGHT" => input(0).zip(input(1)).map(|(a, b)| if b < 64 { a >> b } else { 0 }),
                "INT_MULT" => input(0).zip(input(1)).map(|(a, b)| a.wrapping_mul(b)),
                "SUBPIECE" => input(0).zip(input(1)).map(|(a, b)| if b < 8 { a >> (8 * b) } else { 0 }),
                _ => None,
            }
            .map(|value| mask(value, size));
            if let Some(output) = &op.output
                && let Some(offset) = output.offset
                && output.space != self.ram
            {
                // A write to part of a known varnode forgets every known varnode it overlaps.
                values.retain(|&(space, start, size), _| {
                    space != output.space
                        || start.saturating_add(u64::from(size)) <= offset
                        || offset.saturating_add(u64::from(output.size)) <= start
                });
                if let Some(result) = result.filter(|_| !conditional) {
                    values.insert((output.space, offset, output.size), result);
                }
            }
            conditional |= op.name == "CBRANCH";
        }
    }
}

impl Project {
    pub(crate) fn access_index(&self) -> Result<Arc<AccessIndex>, ApiError> {
        self.mmio_accesses
            .get_or_init(|| self.scan_accesses().map(Arc::new).map_err(|error| error.to_string()))
            .clone()
            .map_err(ApiError::Unavailable)
    }

    /// Finds every load and store whose address is a constant: per function, constants flow forward through
    /// registers and temporaries across blocks (meeting where paths join), and a call forgets all but the
    /// registers the callee preserves.
    fn scan_accesses(&self) -> Result<AccessIndex, ApiError> {
        self.scan_accesses_within(MAX_SCAN_INSTRUCTIONS, MAX_ACCESSES)
    }

    /// [`Self::scan_accesses`] decoding at most `max_instructions` and keeping at most `max_accesses`; a function
    /// either limit cuts short contributes nothing, and the index says `incomplete`.
    pub(crate) fn scan_accesses_within(
        &self,
        max_instructions: usize,
        max_accesses: usize,
    ) -> Result<AccessIndex, ApiError> {
        let binary = &self.binary;
        let target = binary.target();
        let mut decoder = SleighDecoder::for_emulation(&target)
            .map_err(|error| ApiError::Unavailable(format!("access scan decoder: {error}")))?;
        let metadata = decoder.metadata().clone();
        let space = |name: &str| metadata.spaces.iter().find(|space| space.name == name).map(|space| space.id);
        let arm = binary.arch == rampage_arch::Arch::Arm;
        if arm {
            decoder.keep_context_commits(true);
        }
        let evaluator = Evaluator {
            binary,
            constant: space("const").ok_or_else(|| ApiError::Unavailable("decoder lacks a constant space".into()))?,
            register: space("register"),
            ram: metadata.code_space,
            // ARM callees preserve r4-r11; every other register is forgotten at a call.
            preserved: if arm {
                (4..=11)
                    .filter_map(|index| decoder.register(&format!("r{index}")))
                    .map(|storage| (storage.offset, storage.size))
                    .collect()
            } else {
                Vec::new()
            },
        };
        let analysis = self.analysis()?;
        let modes = &analysis.program.code_modes;
        let mut accesses: Vec<Access> = Vec::new();
        let mut decoded = 0usize;
        let mut incomplete = false;
        let mut current_mode: Option<bool> = None;
        for function in &analysis.program.functions {
            let mut blocks: Vec<DecodedBlock> = Vec::with_capacity(function.blocks.len());
            for block in &function.blocks {
                let thumb = arm
                    && modes
                        .binary_search_by_key(&block.start, |&(address, _)| address)
                        .map_or_else(|_| binary.m_profile() || target.is_thumb(block.start), |index| modes[index].1);
                if arm && current_mode != Some(thumb) {
                    decoder.set_context_variable("TMode", u32::from(thumb));
                    current_mode = Some(thumb);
                }
                let mut decoded_block =
                    DecodedBlock { start: block.start, instructions: Vec::new(), successors: vec![block.end] };
                let mut address = block.start;
                while address < block.end {
                    decoded += 1;
                    if decoded > max_instructions {
                        incomplete = true;
                        break;
                    }
                    let Some(bytes) = binary.read_to_segment_end(address) else { break };
                    let instruction = decoder.decode_instruction(&bytes[..bytes.len().min(16)], address);
                    if instruction.status != DecodeStatus::Valid || instruction.length == 0 {
                        break;
                    }
                    // Every branch target in the code space may continue this block; so may the next block.
                    for op in &instruction.pcode {
                        if matches!(op.name.as_str(), "BRANCH" | "CBRANCH")
                            && let Some(target) = op.inputs.first().filter(|node| node.space == evaluator.ram)
                            && let Some(offset) = target.offset
                        {
                            decoded_block.successors.push(offset);
                        }
                    }
                    decoded_block.instructions.push((address, instruction.pcode));
                    address += u64::from(instruction.length);
                }
                blocks.push(decoded_block);
            }
            // A function cut short by the budget would report a partial set of accesses: report none of it.
            if incomplete {
                break;
            }
            blocks.sort_by_key(|block| block.start);
            let index_of = |address: u64| blocks.binary_search_by_key(&address, |block| block.start).ok();
            // Forward dataflow: a block's entry values are those every visited predecessor agrees on.
            let mut entry: Vec<Option<Values>> = vec![None; blocks.len()];
            if let Some(first) = index_of(function.address) {
                entry[first] = Some(Values::new());
            }
            let mut work: std::collections::BTreeSet<usize> =
                entry.iter().enumerate().filter(|(_, values)| values.is_some()).map(|(index, _)| index).collect();
            let mut budget = blocks.len().saturating_mul(16).max(64);
            while let Some(index) = work.pop_first() {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let mut values = entry[index].clone().unwrap_or_default();
                for (_, ops) in &blocks[index].instructions {
                    evaluator.step(ops, &mut values, |_, _| {});
                }
                for &successor in &blocks[index].successors {
                    let Some(next) = index_of(successor) else { continue };
                    let merged = match &entry[next] {
                        None => values.clone(),
                        Some(known) => known
                            .iter()
                            .filter(|(key, value)| values.get(key) == Some(value))
                            .map(|(key, value)| (*key, *value))
                            .collect(),
                    };
                    if entry[next].as_ref() != Some(&merged) {
                        entry[next] = Some(merged);
                        work.insert(next);
                    }
                }
            }
            let mut found: Vec<Access> = Vec::new();
            for (index, block) in blocks.iter().enumerate() {
                let mut values = entry[index].clone().unwrap_or_default();
                for (address, ops) in &block.instructions {
                    evaluator.step(ops, &mut values, |at, write| {
                        found.push(Access { instruction: *address, function: function.address, address: at, write });
                    });
                }
            }
            // A function's accesses are kept whole or not at all.
            if accesses.len() + found.len() > max_accesses {
                incomplete = true;
                break;
            }
            accesses.append(&mut found);
        }
        accesses.sort_by_key(|access| (access.address, access.instruction, access.write));
        accesses.dedup();
        let mut by_instruction: Vec<usize> = (0..accesses.len()).collect();
        by_instruction.sort_by_key(|&index| (accesses[index].instruction, accesses[index].address));
        Ok(AccessIndex { by_address: accesses, by_instruction, incomplete })
    }

    /// Accesses to imported peripherals' registers at `instruction`, named.
    pub(crate) fn register_accesses_at(&self, instruction: u64) -> Option<String> {
        let map = self.peripheral_map();
        if map.is_empty() {
            return None;
        }
        let index = self.access_index().ok()?;
        let mut names: Vec<String> = Vec::new();
        for access in index.at_instruction(instruction) {
            if let Some(name) = map.name(access.address)
                && !names.contains(&name)
            {
                names.push(name);
            }
        }
        (!names.is_empty()).then(|| names.join(", "))
    }

    /// The register an immediate at `instruction` names, when it is plausibly an address: at least 0x100, and inside
    /// a peripheral that the function holding the instruction loads or stores at a constant address.
    pub(crate) fn immediate_register_name(&self, instruction: u64, value: u64) -> Option<String> {
        const MIN_ADDRESS: u64 = 0x100;
        if value < MIN_ADDRESS {
            return None;
        }
        let map = self.peripheral_map();
        let hit = map.at(value)?;
        let function = self.function_containing(instruction).ok()??;
        let index = self.access_index().ok()?;
        let (start, end) = (hit.peripheral.base, hit.peripheral.base + hit.peripheral.span());
        index.in_range(start, end).iter().any(|access| access.function == function).then(|| hit.name())
    }

    /// Xref rows for the constant-address accesses in `[start, end)`, when imported peripherals cover them.
    pub(crate) fn register_xrefs(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<(rampage_analysis::discover::Xref, bool)>, ApiError> {
        let map = self.peripheral_map();
        if map.is_empty() || map.at(start).is_none() && map.by_base.range(start..end).next().is_none() {
            return Ok(Vec::new());
        }
        // Without a p-code decoder for the target there is no scan, and no rows to add.
        let Ok(index) = self.access_index() else { return Ok(Vec::new()) };
        Ok(index
            .in_range(start, end)
            .iter()
            .map(|access| {
                (
                    rampage_analysis::discover::Xref {
                        to: access.address,
                        from: access.instruction,
                        kind: XrefKind::Data,
                    },
                    access.write,
                )
            })
            .collect())
    }

    /// The xref query for a `to` argument: a peripheral's name covers all its registers. A name that is also a
    /// symbol's is refused as ambiguous, as [`Project::resolve`] refuses it.
    pub fn xref_query_to(&self, text: &str) -> Result<crate::XrefQuery, ApiError> {
        let map = self.peripheral_map();
        if let Some(peripheral) = map.named(text.trim()) {
            let symbol = self.address_named(&self.annotations(), text.trim());
            unambiguous(text.trim(), symbol, Some(peripheral.base))?;
            return Ok(crate::XrefQuery::ToRange(peripheral.base, peripheral.base + peripheral.span()));
        }
        self.resolve(text).map(crate::XrefQuery::To)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// peripheral_access

#[derive(Debug, Clone, Default)]
pub struct PeripheralAccessQuery {
    pub peripheral: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralRow {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub span: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub registers: usize,
    pub reads: usize,
    pub writes: usize,
    pub functions: usize,
}

#[derive(Debug, Serialize)]
pub struct RegisterRow {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub bits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rampage_arch::hex::optional_address")]
    pub reset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Bit fields as `NAME[msb:lsb]`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    pub reads: usize,
    pub writes: usize,
    /// Up to eight accessing functions, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub more_functions: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralAccess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peripheral: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub total: usize,
    pub offset: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peripherals: Vec<PeripheralRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub registers: Vec<RegisterRow>,
    /// The access scan stopped at its budget or could not run, so counts may be low.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
}

impl Project {
    /// Imported peripherals with access counts, or one peripheral's registers with the functions that access each.
    pub fn peripheral_access(&self, query: &PeripheralAccessQuery) -> Result<PeripheralAccess, ApiError> {
        let map = self.peripheral_map();
        if map.is_empty() {
            return Err(ApiError::NotFound("no peripherals are imported; run import_svd first".to_owned()));
        }
        let index = self
            .access_index()
            .unwrap_or_else(|_| Arc::new(AccessIndex { incomplete: true, ..AccessIndex::default() }));
        let device = map.peripherals().next().map(|peripheral| peripheral.device.clone());
        let Some(name) = &query.peripheral else {
            let rows = crate::rows::Page::of(map.peripherals(), Some(query.offset), Some(query.limit));
            let peripherals = rows
                .items
                .into_iter()
                .map(|peripheral| {
                    let accesses = index.in_range(peripheral.base, peripheral.base + peripheral.span());
                    let mut functions: Vec<u64> = accesses.iter().map(|access| access.function).collect();
                    functions.sort_unstable();
                    functions.dedup();
                    PeripheralRow {
                        name: peripheral.name.clone(),
                        base: peripheral.base,
                        span: peripheral.span(),
                        group: peripheral.group.clone(),
                        registers: peripheral.registers.len(),
                        reads: accesses.iter().filter(|access| !access.write).count(),
                        writes: accesses.iter().filter(|access| access.write).count(),
                        functions: functions.len(),
                    }
                })
                .collect();
            return Ok(PeripheralAccess {
                device,
                peripheral: None,
                description: None,
                total: rows.total,
                offset: rows.offset,
                peripherals,
                registers: Vec::new(),
                incomplete: index.incomplete,
            });
        };
        let peripheral = map
            .named(name.trim())
            .or_else(|| self.resolve(name).ok().and_then(|address| map.at(address)).map(|hit| hit.peripheral))
            .ok_or_else(|| ApiError::NotFound(format!("no imported peripheral named {name:?}")))?;
        let rows = crate::rows::Page::of(&peripheral.registers, Some(query.offset), Some(query.limit));
        let registers = rows
            .items
            .into_iter()
            .map(|register| {
                let address = peripheral.base + register.offset;
                // Accesses inside this register, attributed to it rather than to an alternate at the same offset.
                let accesses: Vec<&Access> = index
                    .in_range(address, address + register.bytes())
                    .iter()
                    .filter(|access| {
                        map.at(access.address)
                            .and_then(|hit| hit.register)
                            .is_some_and(|found| found.offset == register.offset)
                    })
                    .collect();
                let mut functions: Vec<u64> = accesses.iter().map(|access| access.function).collect();
                functions.sort_unstable();
                functions.dedup();
                RegisterRow {
                    name: register.name.clone(),
                    address,
                    bits: register.bits,
                    access: register.access.clone(),
                    reset: register.reset,
                    description: register.description.clone(),
                    fields: register
                        .fields
                        .iter()
                        .map(|field| match field.width {
                            1 => format!("{}[{}]", field.name, field.lsb),
                            width => format!("{}[{}:{}]", field.name, field.lsb + width - 1, field.lsb),
                        })
                        .collect(),
                    reads: accesses.iter().filter(|access| !access.write).count(),
                    writes: accesses.iter().filter(|access| access.write).count(),
                    more_functions: functions.len().saturating_sub(8),
                    functions: functions.iter().take(8).map(|&function| self.function_name(function)).collect(),
                }
            })
            .collect();
        Ok(PeripheralAccess {
            device,
            peripheral: Some(peripheral.name.clone()),
            description: peripheral.description.clone(),
            total: rows.total,
            offset: rows.offset,
            peripherals: Vec::new(),
            registers,
            incomplete: index.incomplete,
        })
    }
}

#[cfg(test)]
mod tests;
