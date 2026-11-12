//! Conservative class evidence from existing, named Itanium vtable symbols, alongside the symbol-independent
//! RTTI recovery of [`crate::rtti`].

use std::collections::BTreeMap;

use rampage_arch::{Arch, Target};
use rampage_loaders::{Binary, Format, SectionKind, Symbol};
use serde::Serialize;

const MAX_CLASSES: usize = 4096;
const MAX_SLOTS: u64 = 64;
const MAX_SYMBOL_BYTES: usize = 32 * 1024 * 1024;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;
const MAX_METADATA_ITEMS: usize = 16_384;
const MAX_LOOKUP_WORK: usize = 8_000_000;
const MAX_NAMED_TEXT_BYTES: usize = 64 * 1024;

/// Field order puts the warnings and counts before the large lists, so a cut result still shows them.
#[derive(Debug, Serialize)]
pub struct ClassRecovery {
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    /// All MSVC vftables found; `vftables` holds the page starting at `vftables_offset`.
    pub vftables_total: usize,
    pub vftables_offset: usize,
    /// Where the next page of `vftables` starts, when more exist.
    pub vftables_next_offset: Option<usize>,
    pub classes: Vec<ClassEvidence>,
    /// Classes recovered from RTTI data, scanned for every ELF, Mach-O and PE image whether or not symbols
    /// exist, minus any class already named in the symbol-derived `classes` above.
    pub rtti_classes: Vec<crate::rtti::RttiClass>,
    /// MSVC vftables of a PE image, each tied to its class by the complete object locator before slot 0.
    pub vftables: Vec<MsvcVftable>,
}

/// An MSVC vftable found through its RTTI complete object locator.
#[derive(Debug, Serialize)]
pub struct MsvcVftable {
    /// The most-derived class the table belongs to, demangled from its type descriptor.
    pub class: String,
    pub mangled: String,
    /// Address of slot 0.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub locator: u64,
    /// Offset of the subobject whose vfptr points here: 0 for the primary table, non-zero for the tables of a
    /// second or virtual base.
    pub offset: u32,
    /// Slots read, up to the first non-code word.
    pub slot_count: usize,
    /// The first 64 slot targets.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub slots: Vec<u64>,
    /// More slots exist than `slots` lists.
    pub truncated: bool,
}

/// Longest class or stored name a vftable row carries; longer ones are cut at a character boundary.
const MAX_VFTABLE_NAME_BYTES: usize = 512;

fn bounded_name(mut name: String) -> String {
    if name.len() > MAX_VFTABLE_NAME_BYTES {
        let mut end = MAX_VFTABLE_NAME_BYTES;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
        name.push('…');
    }
    name
}

/// MSVC vftables of a PE image, read once at load, each listing at most [`MAX_SLOTS`] slots and 512-byte names.
pub fn msvc_vftables(binary: &Binary) -> Vec<MsvcVftable> {
    let Some(metadata) = binary.msvc_metadata() else { return Vec::new() };
    metadata
        .vftables
        .iter()
        .map(|table| {
            let slot_count = table.slots.len();
            let class = crate::language::msvc_type_name(&table.mangled).unwrap_or_else(|| table.mangled.clone());
            MsvcVftable {
                class: bounded_name(class),
                mangled: bounded_name(table.mangled.clone()),
                address: table.address,
                locator: table.locator,
                offset: table.offset,
                slot_count,
                slots: table.slots.iter().copied().take(MAX_SLOTS as usize).collect(),
                truncated: table.truncated || slot_count > MAX_SLOTS as usize,
            }
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct ClassEvidence {
    pub name: String,
    pub vtable_symbol: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub source: &'static str,
    pub confidence: &'static str,
    pub pointer_size: u8,
    pub header: HeaderClassification,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub raw_offset_word: u64,
    pub offset_to_top: Option<i64>,
    /// The second symbol-prefix word, not an established RTTI field for unverified headers.
    pub rtti_candidate: RttiEvidence,
    pub bound: &'static str,
    /// Exclusive bound on complete pointer slots eligible for examination.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub scan_limit: u64,
    /// Exclusive end of successfully read slots; an unreadable attempted slot is excluded.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub scan_end: u64,
    /// Entries beginning two words after the symbol; unverified headers imply candidate slot positions only.
    pub slots: Vec<VtableSlot>,
    pub stop: ScanStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderClassification {
    KnownRtti,
    UnverifiedPrefix,
}

#[derive(Debug, Serialize)]
pub struct RttiEvidence {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub classification: RttiClassification,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RttiClassification {
    KnownSymbol,
    Unresolved,
    Null,
}

#[derive(Debug, Serialize)]
pub struct VtableSlot {
    pub index: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub raw_value: u64,
    pub classification: SlotClassification,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotClassification {
    Function,
    Unresolved,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStop {
    Bound,
    SlotLimit,
    NonFunction,
    Unreadable,
}

fn normalized(name: &str) -> &str {
    if name.starts_with("__Z") { &name[1..] } else { name }
}

fn readonly_end(binary: &Binary, address: u64) -> Option<u64> {
    let segment = binary.segment_containing(address)?;
    if !segment.perms.read || segment.perms.write {
        return None;
    }
    let section = binary.sections.iter().find(|section| {
        section.kind == SectionKind::ReadOnlyData
            && address >= section.address
            && address - section.address < section.size
    })?;
    let section_end = section.address.checked_add(section.size.min(section.file_size))?;
    let segment_end = segment.address.checked_add(segment.size.min(segment.file_size))?;
    let end = section_end.min(segment_end);
    (address < end).then_some(end)
}

fn rtti(binary: &Binary, address: u64, symbols: &BTreeMap<u64, &Symbol>, size: u8) -> RttiEvidence {
    let symbol = symbols.get(&address).filter(|_| {
        readonly_end(binary, address).is_some_and(|end| end - address >= u64::from(size))
            && binary.read(address, u64::from(size)).is_some()
    });
    RttiEvidence {
        address,
        classification: if address == 0 {
            RttiClassification::Null
        } else if symbol.is_some() {
            RttiClassification::KnownSymbol
        } else {
            RttiClassification::Unresolved
        },
        symbol: symbol.filter(|_| address != 0).map(|symbol| symbol.name.clone()),
    }
}

fn code_target(binary: &Binary, target: &Target, raw: u64) -> Option<u64> {
    let (address, alignment, minimum_bytes) = match target.arch {
        Arch::X86 | Arch::X86_64 => (raw, 1, 1),
        Arch::Aarch64 => (raw, 4, 4),
        Arch::Arm => {
            let address = raw & !1;
            let thumb = raw & 1 != 0;
            if target.is_thumb(address) != thumb {
                return None;
            }
            (address, if thumb { 2 } else { 4 }, if thumb { 2 } else { 4 })
        }
        _ => return None,
    };
    if address % alignment != 0 || binary.code_from(address)?.len() < minimum_bytes {
        return None;
    }
    let segment = binary.segment_containing(address)?;
    let minimum_bytes = minimum_bytes as u64;
    let offset_end = (address - segment.address).checked_add(minimum_bytes)?;
    address.checked_add(minimum_bytes)?;
    if !segment.perms.execute || offset_end > segment.size || offset_end > segment.file_size {
        return None;
    }
    Some(address)
}

fn evidence(
    binary: &Binary,
    target: &Target,
    symbol: &Symbol,
    rtti_symbols: &BTreeMap<u64, &Symbol>,
    max_slots: u64,
    text_budget: Option<usize>,
) -> Result<ClassEvidence, &'static str> {
    if symbol.name.len() > MAX_NAME_BYTES {
        return Err("vtable symbol name exceeds the 4096-byte limit");
    }
    let size = binary
        .arch
        .default_pointer_size()
        .filter(|width| matches!(width, 4 | 8))
        .ok_or("native named-vtable pointer width is unavailable or unsupported")?;
    let width = u64::from(size);
    if !symbol.address.is_multiple_of(width) {
        return Err("unaligned vtable header");
    }
    let readonly_end = readonly_end(binary, symbol.address).ok_or("vtable is not mapped read-only data")?;
    let (end, bound) = if symbol.size == 0 {
        (readonly_end, "section_end")
    } else {
        (
            symbol.address.checked_add(symbol.size).ok_or("vtable symbol range overflows")?.min(readonly_end),
            "symbol_size",
        )
    };
    let start = symbol.address.checked_add(2 * width).ok_or("vtable header range overflows")?;
    if start > end {
        return Err("vtable header exceeds the symbol or mapped section bound");
    }
    let offset = binary.read_pointer(symbol.address, size).ok_or("unreadable vtable offset-to-top")?;
    let rtti_address = binary.read_pointer(symbol.address + width, size).ok_or("unreadable vtable RTTI pointer")?;
    let demangled = crate::language::demangle(&symbol.name).ok_or("invalid Itanium vtable name")?;
    let name = demangled
        .strip_prefix("vtable for ")
        .or_else(|| demangled.strip_prefix("{vtable(").and_then(|name| name.strip_suffix(")}")))
        .filter(|name| !name.is_empty())
        .ok_or("invalid Itanium vtable name")?;
    let text_bytes =
        name.len() + symbol.name.len() + rtti_symbols.get(&rtti_address).map_or(0, |symbol| symbol.name.len());
    if text_budget.is_some_and(|budget| text_bytes > budget) {
        return Err("named-vtable text budget exhausted");
    }
    let available = (end - start) / width;
    let count = available.min(max_slots);
    let mut slots = Vec::new();
    let mut stop = if available > max_slots { ScanStop::SlotLimit } else { ScanStop::Bound };
    for index in 0..count {
        let address = start + index * width;
        let Some(raw_value) = binary.read_pointer(address, size) else {
            stop = ScanStop::Unreadable;
            break;
        };
        let target = (raw_value != 0).then(|| code_target(binary, target, raw_value)).flatten();
        let classification = if raw_value == 0 {
            SlotClassification::Null
        } else if target.is_some() {
            SlotClassification::Function
        } else {
            SlotClassification::Unresolved
        };
        slots.push(VtableSlot { index, address, raw_value, classification, target });
        if classification != SlotClassification::Function {
            stop = ScanStop::NonFunction;
            break;
        }
    }
    let rtti_candidate = rtti(binary, rtti_address, rtti_symbols, size);
    let verified = rtti_candidate.classification == RttiClassification::KnownSymbol
        && rtti_candidate
            .symbol
            .as_deref()
            .is_some_and(|rtti| normalized(rtti).strip_prefix("_ZTI") == normalized(&symbol.name).strip_prefix("_ZTV"));
    Ok(ClassEvidence {
        name: name.to_owned(),
        vtable_symbol: symbol.name.clone(),
        address: symbol.address,
        source: "named_itanium_vtable_symbol",
        confidence: "raw_named_vtable_evidence",
        pointer_size: size,
        header: if verified { HeaderClassification::KnownRtti } else { HeaderClassification::UnverifiedPrefix },
        raw_offset_word: offset,
        offset_to_top: verified.then_some(if size == 4 { i64::from(offset as u32 as i32) } else { offset as i64 }),
        rtti_candidate,
        bound,
        scan_limit: start + count * width,
        scan_end: start + slots.len() as u64 * width,
        slots,
        stop,
    })
}

/// Whether `binary` is a MIPS64 ELFCLASS32 (N32) image, whose 32-bit ABI pointers the architecture's pointer
/// width misstates; class recovery is disabled for it.
pub(crate) fn is_mips64_n32(binary: &Binary) -> bool {
    binary.format == Format::Elf
        && binary.arch == Arch::Mips64
        && binary.image_bytes().get(..5) == Some(b"\x7fELF\x01".as_slice())
}

/// Bounded named-symbol evidence only; never invokes symbol-independent RTTI recovery.
/// Limits are clamped to the full recovery caps, with an additional 64 KiB raw-name budget.
pub fn recover_named_bounded(binary: &Binary, max_tables: usize, max_slots: u64) -> ClassRecovery {
    let max_tables = max_tables.min(MAX_CLASSES);
    let max_slots = max_slots.min(MAX_SLOTS);
    let mut result = ClassRecovery {
        classes: Vec::new(),
        rtti_classes: Vec::new(),
        vftables: Vec::new(),
        vftables_total: 0,
        vftables_offset: 0,
        vftables_next_offset: None,
        warnings: Vec::new(),
        limitations: vec![
            format!(
                "Named-only recovery examines at most {max_tables} vtable candidates and {max_slots} slots per \
                 table, with 64 KiB of raw names; symbol-independent RTTI recovery is not run."
            ),
            "Named recovery retains the one-million-symbol, 32 MiB symbol-name, 4096 named-RTTI candidate, \
             16384 metadata-item and eight-million metadata-lookup budgets of full class recovery."
                .to_owned(),
        ],
    };
    if max_tables != 0 && max_slots != 0 {
        recover_named_into(binary, &mut result, max_tables, max_slots, Some(MAX_NAMED_TEXT_BYTES));
    }
    result
}

/// Reports class evidence without inserting types or asserting a class layout.
pub fn recover(binary: &Binary) -> ClassRecovery {
    let mut result = ClassRecovery {
        classes: Vec::new(),
        rtti_classes: Vec::new(),
        vftables: Vec::new(),
        vftables_total: 0,
        vftables_offset: 0,
        vftables_next_offset: None,
        warnings: Vec::new(),
        limitations: vec![
            "`classes` is named Itanium vtable evidence only; no automatic type insertion, complete class \
             layouts or proven virtual-call edges. Symbol-independent names and base edges come only from \
             `rtti_classes`."
                .to_owned(),
            "`rtti_classes` recovers names and direct base edges from Itanium/MSVC RTTI in file-backed data \
             sections; followed pointers must land in mapped data and names must demangle. Mach-O chained \
             rebases are followed, and chained binds to the C++ runtime's typeinfo vtables are accepted; other \
             relocated pointers unresolved on disk are not, so classes whose RTTI pointers are not image-backed \
             are missed."
                .to_owned(),
            "Named vtables are examined only in static ELF and Mach-O read-only, image-backed tables; snapshots \
             are disabled."
                .to_owned(),
            "At most 4096 vtable candidates, 4096 RTTI candidates, one million symbols, 32 MiB of symbol-name bytes \
             and 64 slots per table; \
             nonzero symbol sizes bound reads, otherwise the mapped section end bounds reads."
                .to_owned(),
            "Scanning stops at the first null or unresolved entry, which may omit later slots or secondary tables. \
              Function classifications mean aligned code targets with an executable, file-backed minimum \
              instruction span, not proven function starts."
                .to_owned(),
            "Relocations are not resolved. Null or foreign RTTI, relative/authenticated vtables, construction \
             vtables and function descriptors are not reconstructed."
                .to_owned(),
            "Only a two-word prefix at the symbol address is read; virtual-base prefixes and secondary \
             address points are not reconstructed. Offset-to-top requires known RTTI with the same encoded \
             type identity in the second word; \
             otherwise prefix words and slot positions remain uninterpreted candidates, not header facts."
                .to_owned(),
            "Direct code targets are supported only for x86, x86-64, ARM and AArch64; ARM Thumb tag clearing \
             requires the target's mapped Thumb mode."
                .to_owned(),
            "MIPS64 ELFCLASS32/N32 images are unsupported: architecture pointer width does not describe \
             their 32-bit ABI pointers."
                .to_owned(),
            "Metadata is limited to 16384 combined sections, segments and Thumb ranges; conservative \
             per-table reservations cap linear metadata lookup work at eight million visited items."
                .to_owned(),
        ],
    };
    match crate::rtti::recover(binary) {
        Ok(classes) => result.rtti_classes = classes,
        Err(limitation) => result.warnings.push(format!("Symbol-independent RTTI not inspected: {limitation}.")),
    }
    if binary.format == Format::Pe {
        result.vftables = msvc_vftables(binary);
        result.vftables_total = result.vftables.len();
        if binary.msvc_metadata().is_some_and(|metadata| metadata.budget_exhausted) {
            result
                .warnings
                .push("MSVC metadata budget exhausted at load; vftables after that point were not read.".to_owned());
        }
        result.limitations.push(
            "`vftables` (x86/x64 PE) are MSVC tables whose preceding word points to a validated RTTI complete \
             object locator; slots run to the first non-code word, so a table directly followed by another code \
             pointer array reads too long, and tables of classes without RTTI (/GR-) are not found. Slot targets \
             are code addresses, not proven function starts; adjustor thunks appear as their own targets."
                .to_owned(),
        );
    }
    recover_named_into(binary, &mut result, MAX_CLASSES, MAX_SLOTS, None);
    let named: std::collections::BTreeSet<&str> = result.classes.iter().map(|class| class.name.as_str()).collect();
    result.rtti_classes.retain(|class| !named.contains(class.name.as_str()));
    result
}

fn recover_named_into(
    binary: &Binary,
    result: &mut ClassRecovery,
    max_tables: usize,
    max_slots: u64,
    mut text_budget: Option<usize>,
) {
    if !matches!(binary.format, Format::Elf | Format::MachO) {
        result.warnings.push(
            "Named vtable evidence requires a static ELF or Mach-O image; only `rtti_classes` is reported for \
             this format."
                .to_owned(),
        );
        return;
    }
    if !matches!(binary.arch.default_pointer_size(), Some(4 | 8)) {
        result
            .warnings
            .push("Named vtable evidence unavailable: native pointer width is unknown or unsupported.".to_owned());
        return;
    }
    if is_mips64_n32(binary) {
        result
            .warnings
            .push("Class evidence is disabled for unsupported MIPS64 ELFCLASS32/N32 pointer width.".to_owned());
        return;
    }
    let mut candidates = Vec::new();
    let mut rtti_symbols = BTreeMap::new();
    let mut name_bytes = 0_usize;
    let mut vtable_limit = false;
    let mut rtti_limit = false;
    let mut rtti_candidates = 0;
    if binary.symbols.len() > MAX_SYMBOLS {
        result.warnings.push("Class evidence symbol scan reached its one-million-symbol budget.".to_owned());
    }
    for symbol in binary.symbols.iter().take(MAX_SYMBOLS) {
        name_bytes = name_bytes.saturating_add(symbol.name.len());
        if name_bytes > MAX_SYMBOL_BYTES {
            result.warnings.push("Class evidence symbol-name scan reached its 32 MiB budget.".to_owned());
            break;
        }
        let name = normalized(&symbol.name);
        if name.starts_with("_ZTV") {
            if candidates.len() < max_tables {
                candidates.push(symbol);
            } else {
                vtable_limit = true;
            }
        } else if name.starts_with("_ZTI") && symbol.name.len() <= MAX_NAME_BYTES {
            if rtti_candidates >= MAX_CLASSES {
                rtti_limit = true;
            } else {
                rtti_candidates += 1;
                if crate::language::demangle(&symbol.name).is_some_and(|name| name.starts_with("typeinfo for ")) {
                    rtti_symbols.entry(symbol.address).or_insert(symbol);
                }
            }
        }
    }
    if vtable_limit {
        result.warnings.push(format!("Class evidence reached its {max_tables} named-vtable candidate limit."));
    }
    if rtti_limit {
        result.warnings.push("Class evidence reached its 4096 named-RTTI candidate limit.".to_owned());
    }
    if candidates.is_empty() {
        return;
    }
    let metadata_items = binary.sections.len().saturating_add(binary.segments.len()).saturating_add(binary.thumb.len());
    if metadata_items > MAX_METADATA_ITEMS {
        result.warnings.push("Class evidence exceeded its 16384-item metadata budget.".to_owned());
        return;
    }
    let table_work = binary.sections.len() * 2 + binary.segments.len() * (max_slots as usize * 5 + 8);
    let mut lookup_work = MAX_LOOKUP_WORK;
    let target = binary.target();
    for symbol in candidates {
        let Some(remaining) = lookup_work.checked_sub(table_work) else {
            result.warnings.push("Class evidence exhausted its metadata lookup work budget.".to_owned());
            break;
        };
        lookup_work = remaining;
        match evidence(binary, &target, symbol, &rtti_symbols, max_slots, text_budget) {
            Ok(evidence) => {
                if let Some(budget) = &mut text_budget {
                    *budget -= evidence.name.len()
                        + evidence.vtable_symbol.len()
                        + evidence.rtti_candidate.symbol.as_ref().map_or(0, String::len);
                }
                result.classes.push(evidence);
            }
            Err(reason) => result.warnings.push(format!("Skipped named vtable at {:#x}: {reason}.", symbol.address)),
        }
    }
}
