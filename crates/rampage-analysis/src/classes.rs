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

#[derive(Debug, Serialize)]
pub struct ClassRecovery {
    pub classes: Vec<ClassEvidence>,
    /// Classes recovered from RTTI data, scanned for every ELF, Mach-O and PE image whether or not symbols
    /// exist, minus any class already named in the symbol-derived `classes` above.
    pub rtti_classes: Vec<crate::rtti::RttiClass>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
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
) -> Result<ClassEvidence, &'static str> {
    if symbol.name.len() > MAX_NAME_BYTES {
        return Err("vtable symbol name exceeds the 4096-byte limit");
    }
    let size = binary.arch.pointer_size();
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
    let name = crate::language::demangle(&symbol.name)
        .and_then(|name| {
            name.strip_prefix("vtable for ")
                .or_else(|| name.strip_prefix("{vtable(").and_then(|name| name.strip_suffix(")}")))
                .map(str::to_owned)
        })
        .filter(|name| !name.is_empty())
        .ok_or("invalid Itanium vtable name")?;
    let available = (end - start) / width;
    let count = available.min(MAX_SLOTS);
    let mut slots = Vec::new();
    let mut stop = if available > MAX_SLOTS { ScanStop::SlotLimit } else { ScanStop::Bound };
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
        name,
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

/// Reports class evidence without inserting types or asserting a class layout.
pub fn recover(binary: &Binary) -> ClassRecovery {
    let mut result = ClassRecovery {
        classes: Vec::new(),
        rtti_classes: crate::rtti::recover(binary),
        warnings: Vec::new(),
        limitations: vec![
            "`classes` is named Itanium vtable evidence only; no automatic type insertion, complete class \
             layouts or proven virtual-call edges. Symbol-independent names and base edges come only from \
             `rtti_classes`."
                .to_owned(),
            "`rtti_classes` recovers names and direct base edges from Itanium/MSVC RTTI in file-backed data \
             sections; followed pointers must land in mapped data and names must demangle. Chained-fixup or \
             relocated pointers that are unresolved on disk are not followed, so classes whose RTTI pointers \
             are not image-backed are missed."
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
             vtables, MSVC vftable slots and function descriptors are not reconstructed."
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
    if !matches!(binary.format, Format::Elf | Format::MachO) {
        result.warnings.push(
            "Named vtable evidence requires a static ELF or Mach-O image; only `rtti_classes` is reported for \
             this format."
                .to_owned(),
        );
        return result;
    }
    if is_mips64_n32(binary) {
        result
            .warnings
            .push("Class evidence is disabled for unsupported MIPS64 ELFCLASS32/N32 pointer width.".to_owned());
        return result;
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
            if candidates.len() < MAX_CLASSES {
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
        result.warnings.push("Class evidence reached its 4096 named-vtable candidate limit.".to_owned());
    }
    if rtti_limit {
        result.warnings.push("Class evidence reached its 4096 named-RTTI candidate limit.".to_owned());
    }
    if candidates.is_empty() {
        return result;
    }
    let metadata_items = binary.sections.len().saturating_add(binary.segments.len()).saturating_add(binary.thumb.len());
    if metadata_items > MAX_METADATA_ITEMS {
        result.warnings.push("Class evidence exceeded its 16384-item metadata budget.".to_owned());
        return result;
    }
    let table_work = binary.sections.len() * 2 + binary.segments.len() * (MAX_SLOTS as usize * 5 + 8);
    let mut lookup_work = MAX_LOOKUP_WORK;
    let target = binary.target();
    for symbol in candidates {
        let Some(remaining) = lookup_work.checked_sub(table_work) else {
            result.warnings.push("Class evidence exhausted its metadata lookup work budget.".to_owned());
            break;
        };
        lookup_work = remaining;
        match evidence(binary, &target, symbol, &rtti_symbols) {
            Ok(evidence) => result.classes.push(evidence),
            Err(reason) => result.warnings.push(format!("Skipped named vtable at {:#x}: {reason}.", symbol.address)),
        }
    }
    let named: std::collections::BTreeSet<&str> = result.classes.iter().map(|class| class.name.as_str()).collect();
    result.rtti_classes.retain(|class| !named.contains(class.name.as_str()));
    result
}
