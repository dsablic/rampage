//! Function-start truth from checked embedded DWARF low/high PCs, without function discovery.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::ops::Range;

use gimli::{AttributeValue, Dwarf, DwarfSections, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};
use rampage_loaders::Binary;
use rampage_signatures::alias_rank;

const MAX_DIES: usize = 1_000_000;
const MAX_UNITS: usize = 100_000;
const MAX_FUNCTIONS: usize = 250_000;
const MAX_METADATA_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 4096;
const MAX_OUTPUT_NAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_NOTES: usize = 128;
const MAX_REFERENCE_DEPTH: usize = 16;

type Reader<'a> = EndianSlice<'a, RunTimeEndian>;
type Unit<'a> = gimli::Unit<Reader<'a>>;
type Entry<'a> = gimli::DebuggingInformationEntry<Reader<'a>>;

/// A nonempty truth is evidence only for the retained concrete subprograms, not full code coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub truth: crate::Truth,
    pub originating_metadata: &'static str,
    /// Nonempty ranges checked in the original and, when supplied, at the same VAs in the twin.
    /// One checked low/high-PC range per retained DIE, including aliases; never inferred symbol extents.
    pub exact_ranges_checked: usize,
    pub checked_bytes: u64,
    /// False without a twin, or when no concrete function truth was retained.
    pub twin_verified: bool,
    pub no_truth_reason: Option<String>,
    pub omitted_subprograms: usize,
    /// Unsupported `DW_AT_ranges` DIEs, also included in `omitted_subprograms`, even when notes are capped.
    pub unsupported_range_subprograms: usize,
    pub aliased_addresses: usize,
    pub notes: Vec<String>,
    /// Notes suppressed by the bounded note list, not unexamined DIEs.
    pub omitted: usize,
}

impl Report {
    fn new() -> Self {
        Self {
            truth: crate::Truth::default(),
            originating_metadata: "embedded_dwarf",
            exact_ranges_checked: 0,
            checked_bytes: 0,
            twin_verified: false,
            no_truth_reason: None,
            omitted_subprograms: 0,
            unsupported_range_subprograms: 0,
            aliased_addresses: 0,
            notes: Vec::new(),
            omitted: 0,
        }
    }

    fn note(&mut self, note: String) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(note);
        } else {
            self.omitted += 1;
        }
    }

    fn omit(&mut self, offset: usize, reason: &str) {
        self.omitted_subprograms += 1;
        self.note(format!("subprogram at unit offset {offset:#x}: {reason}; omitted"));
    }
}

/// Read concrete `DW_TAG_subprogram` DIEs with explicit, checked contiguous low/high-PC extents.
///
/// Addresses are the linked image VAs recorded in DWARF, including PE image bases: no RVA guessing,
/// next-symbol sizes, format function-start tables, or analysis-discovered functions are used. Every
/// `DW_AT_ranges` subprogram is unsupported and omitted before decoding any range list. Low/high-PC
/// arithmetic must fit the unit's address width. An explicit entry PC must lie within that single range.
/// Each preferred name attribute follows bounded same-unit origin/specification references before falling
/// back to a lower-priority attribute. Unsupported entries are omitted with bounded notes and counters;
/// malformed low/high PCs and inaccessible or different retained code are errors, not partial success.
///
/// Missing DWARF or no retained concrete functions returns empty truth with `no_truth_reason` set and
/// `twin_verified == false`. Callers requiring usable truth must check that field, not just `Result::Ok`.
/// `data` must be the exact single-image bytes loaded as `original` (select a fat/embedded slice first).
pub fn dwarf_function_truth(data: &[u8], original: &Binary, stripped: Option<&Binary>) -> Result<Report, String> {
    if data != original.image_bytes() {
        return Err("DWARF bytes do not match the original loaded image".to_owned());
    }
    if let Some(twin) = stripped
        && (original.format != twin.format || original.arch != twin.arch || original.big_endian != twin.big_endian)
    {
        return Err("not a twin: format, architecture, or endianness differs".to_owned());
    }
    let object = object::File::parse(data).map_err(|error| format!("DWARF image: {error}"))?;
    if !matches!(object.kind(), object::ObjectKind::Executable | object::ObjectKind::Dynamic) {
        return Err("DWARF function truth requires a linked executable image".to_owned());
    }
    let endian = if object.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let mut metadata_bytes = 0_u64;
    let sections = DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, String> {
        let macho_name = format!("__{}", id.name().trim_start_matches('.'));
        let compressed_name = id.name().replacen(".debug_", ".zdebug_", 1);
        let macho_compressed_name = format!("__{}", compressed_name.trim_start_matches('.'));
        let section = object.section_by_name(id.name()).or_else(|| object.section_by_name(&macho_name))
            .or_else(|| object.section_by_name(&compressed_name))
            .or_else(|| object.section_by_name(&macho_compressed_name));
        let Some(section) = section else { return Ok(Cow::Borrowed(&[])) };
        let compressed = section.compressed_data().map_err(|error| format!("{}: {error}", id.name()))?;
        metadata_bytes = metadata_bytes
            .checked_add(compressed.uncompressed_size)
            .filter(|size| *size <= MAX_METADATA_BYTES)
            .ok_or_else(|| format!("embedded DWARF exceeds {MAX_METADATA_BYTES} uncompressed bytes"))?;
        let bytes = compressed.decompress().map_err(|error| format!("{}: {error}", id.name()))?;
        if bytes.len() as u64 != compressed.uncompressed_size {
            return Err(format!("{}: uncompressed metadata size differs from its header", id.name()));
        }
        Ok(bytes)
    })?;
    let dwarf = sections.borrow(|bytes| EndianSlice::new(bytes, endian));
    let mut report = Report::new();
    let mut aliases = BTreeSet::new();
    let mut units = dwarf.units();
    let (mut unit_count, mut dies, mut functions, mut name_bytes) = (0, 0, 0, 0);
    while let Some(header) = units.next().map_err(dwarf_error)? {
        unit_count += 1;
        if unit_count > MAX_UNITS {
            return Err(format!("more than {MAX_UNITS} DWARF units"));
        }
        let unit = dwarf.unit(header).map_err(dwarf_error)?;
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().map_err(dwarf_error)? {
            dies += 1;
            if dies > MAX_DIES {
                return Err(format!("more than {MAX_DIES} DWARF entries"));
            }
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let offset = entry.offset().0;
            if entry.has_attr(gimli::DW_AT_ranges) {
                report.unsupported_range_subprograms += 1;
                report.omit(offset, "DW_AT_ranges range lists are unsupported; only explicit low/high PCs are truth");
                continue;
            }
            if is_declaration(entry) {
                report.omit(offset, "declaration has no concrete function truth");
                continue;
            }
            let Some(range) = contiguous_range(&dwarf, &unit, entry)? else {
                report.omit(offset, "no nonzero concrete low/high-PC range (abstract, empty, or tombstone DIE)");
                continue;
            };
            let entry_pc = address_attribute(&dwarf, &unit, entry, gimli::DW_AT_entry_pc)?;
            let Some(start) = function_start(&range, entry_pc) else {
                report.omit(offset, "explicit entry PC is outside the concrete low/high-PC range");
                continue;
            };
            let name = match function_name(&dwarf, &unit, entry)? {
                Ok(name) => name,
                Err(reason) => {
                    report.omit(offset, reason);
                    continue;
                }
            };
            functions += 1;
            name_bytes += name.len();
            if functions > MAX_FUNCTIONS || name_bytes > MAX_OUTPUT_NAME_BYTES {
                return Err("DWARF function truth output limit exceeded".to_owned());
            }
            let len = range.end - range.start;
            report.checked_bytes = report
                .checked_bytes
                .checked_add(len)
                .filter(|bytes| *bytes <= MAX_CHECKED_BYTES)
                .ok_or_else(|| "DWARF code verification byte limit exceeded".to_owned())?;
            let bytes = executable_bytes(original, &range).ok_or_else(|| {
                format!("{name}: original range {:#x}..{:#x} is not executable-backed", range.start, range.end)
            })?;
            if let Some(twin) = stripped {
                let twin_bytes = executable_bytes(twin, &range).ok_or_else(|| {
                    format!("not a twin: {name} range {:#x}..{:#x} is not executable-backed", range.start, range.end)
                })?;
                if bytes != twin_bytes {
                    return Err(format!(
                        "not a twin: {name} code differs at range {:#x}..{:#x}",
                        range.start, range.end
                    ));
                }
            }
            report.exact_ranges_checked += 1;
            match report.truth.0.entry(start) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(name);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let note = format!("{name} at {start:#x}: aliased function start; deterministic name selected");
                    if alias_rank(&name) < alias_rank(slot.get()) {
                        slot.insert(name);
                    }
                    if aliases.insert(start) {
                        report.aliased_addresses += 1;
                    }
                    report.note(note);
                }
            }
        }
    }
    if report.truth.0.is_empty() {
        report.no_truth_reason = Some(if unit_count == 0 {
            "no embedded DWARF compilation units; no function truth".to_owned()
        } else {
            "no named concrete DWARF subprograms with usable code ranges; no function truth".to_owned()
        });
        report.note(report.no_truth_reason.clone().expect("set above"));
    } else {
        report.twin_verified = stripped.is_some() && report.exact_ranges_checked > 0;
    }
    Ok(report)
}

fn dwarf_error(error: gimli::Error) -> String {
    format!("embedded DWARF: {error}")
}

fn is_declaration(entry: &Entry<'_>) -> bool {
    entry.attr_value(gimli::DW_AT_declaration).is_some_and(|value| {
        matches!(value, AttributeValue::Flag(true)) || value.udata_value().is_some_and(|value| value != 0)
    })
}

fn address_attribute<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<'a>,
    entry: &Entry<'a>,
    attribute: gimli::DwAt,
) -> Result<Option<u64>, String> {
    match entry.attr_value(attribute) {
        Some(value) => dwarf
            .attr_address(unit, value)
            .map_err(dwarf_error)?
            .map(Some)
            .ok_or_else(|| format!("unsupported DWARF address form for {attribute:?}")),
        None => Ok(None),
    }
}

fn contiguous_range<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<'a>,
    entry: &Entry<'a>,
) -> Result<Option<Range<u64>>, String> {
    let Some(low) = address_attribute(dwarf, unit, entry, gimli::DW_AT_low_pc)? else { return Ok(None) };
    let Some(high) = entry.attr_value(gimli::DW_AT_high_pc) else { return Ok(None) };
    let width = unit.encoding().address_size;
    let max_address = match width {
        1..=7 => (1_u64 << (u32::from(width) * 8)) - 1,
        8 => u64::MAX,
        _ => return Err(format!("unsupported DWARF unit address width: {width}")),
    };
    let overflow =
        || format!("DWARF subprogram at {:#x}: low/high PC overflows {width}-byte address width", entry.offset().0);
    let end = match high {
        AttributeValue::Udata(size) => low.checked_add(size).ok_or_else(overflow)?,
        value => dwarf
            .attr_address(unit, value)
            .map_err(dwarf_error)?
            .ok_or_else(|| "unsupported DWARF high_pc form".to_owned())?,
    };
    if low > max_address || end > max_address {
        return Err(overflow());
    }
    if end < low {
        return Err(format!("DWARF subprogram at {:#x}: inverted low/high-PC range", entry.offset().0));
    }
    if low == 0 || low == end {
        return Ok(None);
    }
    Ok(Some(low..end))
}

fn function_start(range: &Range<u64>, entry_pc: Option<u64>) -> Option<u64> {
    match entry_pc {
        Some(entry) => range.contains(&entry).then_some(entry),
        None => Some(range.start),
    }
}

fn function_name<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<'a>,
    entry: &Entry<'a>,
) -> Result<Result<String, &'static str>, String> {
    for attribute in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name, gimli::DW_AT_name] {
        let mut remaining = MAX_REFERENCE_DEPTH;
        match name_attribute(dwarf, unit, entry, attribute, &mut Vec::new(), &mut remaining)? {
            Ok(Some(name)) => return Ok(Ok(name)),
            Ok(None) => {}
            Err(reason) => return Ok(Err(reason)),
        }
    }
    Ok(Err("no recoverable DWARF function name"))
}

fn name_attribute<'a>(
    dwarf: &Dwarf<Reader<'a>>,
    unit: &Unit<'a>,
    entry: &Entry<'a>,
    attribute: gimli::DwAt,
    visited: &mut Vec<usize>,
    remaining: &mut usize,
) -> Result<Result<Option<String>, &'static str>, String> {
    if *remaining == 0 || visited.contains(&entry.offset().0) {
        return Ok(Err("name origin/specification cycle or depth limit"));
    }
    *remaining -= 1;
    visited.push(entry.offset().0);
    let result = (|| {
        if let Some(value) = entry.attr_value(attribute) {
            let reader = dwarf.attr_string(unit, value).map_err(dwarf_error)?;
            let name = reader.to_string().map_err(dwarf_error)?;
            if name.is_empty() || name.len() > MAX_NAME_BYTES {
                return Ok(Err("empty or over-limit DWARF function name"));
            }
            return Ok(Ok(Some(name.to_owned())));
        }
        for reference in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
            if let Some(value) = entry.attr_value(reference) {
                let offset = match value {
                    AttributeValue::UnitRef(offset) => Some(offset),
                    AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
                    _ => None,
                };
                let Some(offset) = offset else { return Ok(Err("unsupported cross-unit function name reference")) };
                let origin = unit.entry(offset).map_err(dwarf_error)?;
                if origin.tag() != gimli::DW_TAG_subprogram {
                    return Ok(Err("function name reference does not name a subprogram"));
                }
                match name_attribute(dwarf, unit, &origin, attribute, visited, remaining)? {
                    Ok(None) => {}
                    result => return Ok(result),
                }
            }
        }
        Ok(Ok(None))
    })();
    visited.pop();
    result
}

fn executable_bytes<'a>(binary: &'a Binary, range: &Range<u64>) -> Option<&'a [u8]> {
    let segment = binary.segment_containing(range.start)?;
    let offset = range.start.checked_sub(segment.address)?;
    let len = range.end.checked_sub(range.start)?;
    if len == 0 || !segment.perms.execute || offset.checked_add(len)? > segment.size {
        return None;
    }
    binary.read(range.start, len).filter(|bytes| !bytes.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{Dwarf, EndianSlice, MAX_REFERENCE_DEPTH, RunTimeEndian, function_name, function_start};

    #[test]
    fn contiguous_range_uses_low_pc_unless_an_in_range_entry_is_explicit() {
        let range = 0x100..0x120;
        assert_eq!(function_start(&range, None), Some(0x100));
        assert_eq!(function_start(&range, Some(0x108)), Some(0x108));
        assert_eq!(function_start(&range, Some(0x120)), None);
        assert_eq!(function_start(&range, Some(0x200)), None);
    }

    #[test]
    fn same_unit_origin_and_specification_names_resolve_but_cycles_do_not() {
        let abbrev = [
            1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x03, 0x08, 0, 0, 3, 0x2e, 0, 0x31, 0x13, 0, 0, 4, 0x2e, 0, 0x47, 0x13, 0, 0,
            0,
        ];
        let mut info = vec![0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
        let named = info.len();
        info.extend_from_slice(&[2, b'f', b'o', b'o', 0]);
        let origin = info.len();
        info.push(3);
        info.extend_from_slice(&(named as u32).to_le_bytes());
        let specification = info.len();
        info.push(4);
        info.extend_from_slice(&(origin as u32).to_le_bytes());
        let cycle = info.len();
        info.push(3);
        info.extend_from_slice(&(cycle as u32).to_le_bytes());
        let mut too_deep = named;
        for _ in 0..MAX_REFERENCE_DEPTH {
            let next = info.len();
            info.push(3);
            info.extend_from_slice(&(too_deep as u32).to_le_bytes());
            too_deep = next;
        }
        info.push(0);
        let length = (info.len() - 4) as u32;
        info[..4].copy_from_slice(&length.to_le_bytes());
        let dwarf = Dwarf::load(|id| -> gimli::Result<_> {
            let bytes = match id {
                gimli::SectionId::DebugInfo => info.as_slice(),
                gimli::SectionId::DebugAbbrev => abbrev.as_slice(),
                _ => &[],
            };
            Ok(EndianSlice::new(bytes, RunTimeEndian::Little))
        })
        .unwrap();
        let header = dwarf.units().next().unwrap().unwrap();
        let unit = dwarf.unit(header).unwrap();
        for offset in [named, origin, specification] {
            let entry = unit.entry(gimli::UnitOffset(offset)).unwrap();
            assert_eq!(function_name(&dwarf, &unit, &entry).unwrap(), Ok("foo".to_owned()));
        }
        let entry = unit.entry(gimli::UnitOffset(cycle)).unwrap();
        let reason = function_name(&dwarf, &unit, &entry).unwrap().unwrap_err();
        assert!(reason.contains("cycle"));
        let entry = unit.entry(gimli::UnitOffset(too_deep)).unwrap();
        let reason = function_name(&dwarf, &unit, &entry).unwrap().unwrap_err();
        assert!(reason.contains("depth limit"));
    }
}
