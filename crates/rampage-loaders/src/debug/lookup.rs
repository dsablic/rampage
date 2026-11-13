//! Indexed, per-request bounded DWARF type layout lookup.
//!
//! One linear skim of the top-level DIEs builds a name → DIE index; that is the only whole-file pass and callers
//! keep the index for the image's lifetime. A lookup then reads only the DIEs of the requested type, its members
//! and the type chains they name, under a per-request budget that does not grow with the number of units or
//! types in the image. Nothing is imported, applied or checked against a native layout: this is producer
//! evidence, read-only.

use std::collections::BTreeMap;
use std::io::Read;

use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, Unit, UnitOffset};
use object::{CompressionFormat, Object, ObjectKind, ObjectSection};
use serde::Serialize;

use super::{DebugReader, bounded_name_limit, signature_unit};
use crate::Binary;

/// Decompressed DWARF sections kept for an index's lifetime.
const MAX_SECTION_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INDEX_ENTRIES: usize = 4_000_000;
const MAX_NAMESPACE_DEPTH: usize = 64;
const MAX_NAME: usize = 512;
/// Index entries of one name that a lookup materialises; the rest are only counted.
pub const MAX_LOOKUP_CANDIDATES: usize = 16;
/// DIEs one lookup may read, across all of its candidates.
pub const MAX_LOOKUP_DIES: usize = 65_536;
const MAX_MEMBERS: usize = 4096;
const MAX_TYPE_CHAIN: usize = 16;
const MAX_SELECTION_DEPTH: usize = 32;
pub const MAX_LOOKUP_DEPTH: usize = 4;
pub const MAX_LOOKUP_LIMIT: usize = 512;
const MAX_OUTPUT_MEMBERS: usize = 1024;
const MAX_SUGGESTIONS: usize = 16;

/// The DWARF sections a lookup reads, owned so that compressed sections are inflated once.
#[derive(Debug, Default)]
struct Sections {
    big_endian: bool,
    info: Vec<u8>,
    abbrev: Vec<u8>,
    str: Vec<u8>,
    line_str: Vec<u8>,
    str_offsets: Vec<u8>,
    addr: Vec<u8>,
}

impl Sections {
    fn load(object: &object::File<'_>) -> Result<Self, String> {
        let mut sections = Sections { big_endian: !object.is_little_endian(), ..Sections::default() };
        let mut total = 0u64;
        for (id, slot) in [
            (gimli::SectionId::DebugInfo, &mut sections.info),
            (gimli::SectionId::DebugAbbrev, &mut sections.abbrev),
            (gimli::SectionId::DebugStr, &mut sections.str),
            (gimli::SectionId::DebugLineStr, &mut sections.line_str),
            (gimli::SectionId::DebugStrOffsets, &mut sections.str_offsets),
            (gimli::SectionId::DebugAddr, &mut sections.addr),
        ] {
            let macho = if id == gimli::SectionId::DebugStrOffsets {
                "__debug_str_offs".to_owned()
            } else {
                id.name().replacen(".debug_", "__debug_", 1)
            };
            let Some(section) = object.section_by_name(id.name()).or_else(|| object.section_by_name(&macho)) else {
                continue;
            };
            let compressed = section.compressed_data().map_err(|error| error.to_string())?;
            total = total
                .checked_add(compressed.uncompressed_size)
                .filter(|&total| total <= MAX_SECTION_BYTES)
                .ok_or("DWARF sections exceed the 512 MiB lookup limit")?;
            *slot = match compressed.format {
                CompressionFormat::None => compressed.data.to_vec(),
                CompressionFormat::Zlib => {
                    let size = usize::try_from(compressed.uncompressed_size).map_err(|_| "DWARF size overflow")?;
                    let mut data = Vec::with_capacity(size);
                    flate2::read::ZlibDecoder::new(compressed.data)
                        .take(compressed.uncompressed_size + 1)
                        .read_to_end(&mut data)
                        .map_err(|error| format!("{}: {error}", id.name()))?;
                    if data.len() != size {
                        return Err(format!("{}: decompressed size differs from its header", id.name()));
                    }
                    data
                }
                _ => return Err(format!("{}: unsupported DWARF section compression", id.name())),
            };
        }
        Ok(sections)
    }

    fn dwarf(&self) -> Dwarf<DebugReader<'_>> {
        let endian = if self.big_endian { RunTimeEndian::Big } else { RunTimeEndian::Little };
        fn slice(data: &[u8], endian: RunTimeEndian) -> DebugReader<'_> {
            EndianSlice::new(data, endian)
        }
        Dwarf {
            debug_info: slice(&self.info, endian).into(),
            debug_abbrev: slice(&self.abbrev, endian).into(),
            debug_str: slice(&self.str, endian).into(),
            debug_line_str: slice(&self.line_str, endian).into(),
            debug_str_offsets: slice(&self.str_offsets, endian).into(),
            debug_addr: slice(&self.addr, endian).into(),
            ..Dwarf::default()
        }
    }
}

/// What the one-time index skim did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DwarfIndexStats {
    pub units: usize,
    /// Units the skim could not read (unsupported unit kinds, split DWARF, malformed headers).
    pub skipped_units: usize,
    pub dies_skimmed: usize,
    pub named_types: usize,
    /// The index stopped at its entry limit; later names are missing.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    die: usize,
    rank: u8,
}

/// Name → DIE index over every unit's top-level (and namespace-nested) named types.
#[derive(Debug)]
pub struct DwarfTypeIndex {
    sections: Sections,
    units: Vec<usize>,
    names: BTreeMap<String, Vec<IndexEntry>>,
    stats: DwarfIndexStats,
}

/// Builds the index for an image's embedded DWARF. Fails when there is no `.debug_info`.
pub fn dwarf_type_index(binary: &Binary) -> Result<DwarfTypeIndex, String> {
    let object = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
    if object.kind() == ObjectKind::Relocatable {
        return Err("DWARF type lookup does not apply relocations; relocatable objects are unsupported".into());
    }
    let sections = Sections::load(&object)?;
    if sections.info.is_empty() {
        return Err("no embedded DWARF .debug_info; external debug files are not searched".into());
    }
    DwarfTypeIndex::build(sections)
}

fn indexed_tag(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_typedef
            | gimli::DW_TAG_base_type
    )
}

/// Lower ranks are materialised first: complete definitions, then typedefs, then declarations.
fn rank(tag: gimli::DwTag, declaration: bool) -> u8 {
    match (tag, declaration) {
        (_, true) => 2,
        (gimli::DW_TAG_typedef, false) => 1,
        _ => 0,
    }
}

impl DwarfTypeIndex {
    fn build(sections: Sections) -> Result<Self, String> {
        let mut index =
            DwarfTypeIndex { sections, units: Vec::new(), names: BTreeMap::new(), stats: DwarfIndexStats::default() };
        let mut names = BTreeMap::new();
        let mut units = Vec::new();
        let mut stats = DwarfIndexStats::default();
        {
            let dwarf = index.sections.dwarf();
            let mut headers = dwarf.units();
            loop {
                let header = match headers.next() {
                    Ok(Some(header)) => header,
                    Ok(None) => break,
                    Err(error) => {
                        if units.is_empty() {
                            return Err(format!("DWARF unit header: {error}"));
                        }
                        stats.skipped_units += 1;
                        break;
                    }
                };
                stats.units += 1;
                units.push(header.offset().0);
                if !matches!(header.type_(), gimli::UnitType::Compilation | gimli::UnitType::Partial) {
                    stats.skipped_units += 1;
                    continue;
                }
                let Ok(unit) = signature_unit(&dwarf, header) else {
                    stats.skipped_units += 1;
                    continue;
                };
                if skim_unit(&dwarf, &unit, &mut names, &mut stats).is_err() {
                    stats.skipped_units += 1;
                }
                if stats.truncated {
                    break;
                }
            }
        }
        index.names = names;
        index.units = units;
        index.stats = stats;
        Ok(index)
    }

    pub fn stats(&self) -> &DwarfIndexStats {
        &self.stats
    }

    /// Indexed names containing `text`, for a not-found hint.
    pub fn suggestions(&self, text: &str) -> Vec<String> {
        let lower = text.to_ascii_lowercase();
        self.names
            .keys()
            .filter(|name| name.to_ascii_lowercase().contains(&lower))
            .take(MAX_SUGGESTIONS)
            .cloned()
            .collect()
    }

    /// Reads one named type's layout(s). Work is bounded by [`MAX_LOOKUP_DIES`] and [`MAX_LOOKUP_CANDIDATES`].
    pub fn lookup(&self, request: &DwarfTypeRequest) -> Result<DwarfTypeLookup, String> {
        if request.member.is_some() && request.byte_offset.is_some() {
            return Err("pass member or byte_offset, not both".into());
        }
        if request.depth > MAX_LOOKUP_DEPTH {
            return Err(format!("depth exceeds {MAX_LOOKUP_DEPTH}"));
        }
        if request.limit > MAX_LOOKUP_LIMIT {
            return Err(format!("limit exceeds {MAX_LOOKUP_LIMIT}"));
        }
        let (keyword, name) = split_keyword(request.name.trim());
        let entries: Vec<IndexEntry> = self.names.get(name).cloned().unwrap_or_default();
        let dwarf = self.sections.dwarf();
        let mut reader = DieReader::new(&dwarf, self);
        let mut result = DwarfTypeLookup {
            source: "dwarf",
            name: request.name.clone(),
            matches: entries.len(),
            examined: 0,
            ambiguous: false,
            definitions: Vec::new(),
            work: DwarfLookupWork::default(),
            index: self.stats.clone(),
            warnings: Vec::new(),
        };
        let mut ordered = entries;
        ordered.sort_by_key(|entry| (entry.rank, entry.die));
        // Distinct records: the same DIE reached by name and through a typedef is one definition.
        let mut seen_records = BTreeMap::new();
        let mut fingerprints: BTreeMap<String, usize> = BTreeMap::new();
        for entry in ordered.iter().take(MAX_LOOKUP_CANDIDATES) {
            result.examined += 1;
            let candidate = match reader.definition(entry.die, keyword, request) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => continue,
                Err(error) => {
                    result.warnings.push(format!("DIE {:#x}: {error}", entry.die));
                    if reader.exhausted() {
                        break;
                    }
                    continue;
                }
            };
            let (definition, record_die, fingerprint) = candidate;
            if let Some(&slot) = seen_records.get(&record_die) {
                let existing: &mut DwarfTypeDefinition = &mut result.definitions[slot];
                if existing.via_typedef.is_none() {
                    existing.via_typedef = definition.via_typedef;
                }
                continue;
            }
            if let Some(&slot) = fingerprints.get(&fingerprint) {
                result.definitions[slot].occurrences += 1;
                seen_records.insert(record_die, slot);
                continue;
            }
            fingerprints.insert(fingerprint, result.definitions.len());
            seen_records.insert(record_die, result.definitions.len());
            result.definitions.push(definition);
        }
        if ordered.len() > MAX_LOOKUP_CANDIDATES {
            result.warnings.push(format!(
                "{} index entries named {name:?}; examined the first {MAX_LOOKUP_CANDIDATES} (definitions first)",
                ordered.len()
            ));
        }
        // A declaration-only candidate adds nothing beside a complete definition.
        if result.definitions.iter().any(|definition| definition.complete) {
            result.definitions.retain(|definition| definition.complete);
        }
        result.ambiguous = result.definitions.len() > 1;
        result.work = reader.work();
        Ok(result)
    }
}

fn split_keyword(name: &str) -> (Option<gimli::DwTag>, &str) {
    for (keyword, tag) in [
        ("struct ", gimli::DW_TAG_structure_type),
        ("union ", gimli::DW_TAG_union_type),
        ("enum ", gimli::DW_TAG_enumeration_type),
        ("class ", gimli::DW_TAG_class_type),
    ] {
        if let Some(rest) = name.strip_prefix(keyword) {
            return (Some(tag), rest.trim());
        }
    }
    (None, name)
}

fn skim_unit(
    dwarf: &Dwarf<DebugReader<'_>>,
    unit: &Unit<DebugReader<'_>>,
    names: &mut BTreeMap<String, Vec<IndexEntry>>,
    stats: &mut DwarfIndexStats,
) -> gimli::Result<()> {
    let mut tree = unit.entries_tree(None)?;
    let root = tree.root()?;
    skim_children(dwarf, unit, root.children(), "", 0, names, stats)
}

fn skim_children(
    dwarf: &Dwarf<DebugReader<'_>>,
    unit: &Unit<DebugReader<'_>>,
    mut children: gimli::EntriesTreeIter<'_, '_, DebugReader<'_>>,
    prefix: &str,
    depth: usize,
    names: &mut BTreeMap<String, Vec<IndexEntry>>,
    stats: &mut DwarfIndexStats,
) -> gimli::Result<()> {
    while let Some(child) = children.next()? {
        stats.dies_skimmed += 1;
        let entry = child.entry();
        let tag = entry.tag();
        let name = entry
            .attr_value(gimli::DW_AT_name)
            .and_then(|value| bounded_name_limit(dwarf, unit, value, MAX_NAME).ok())
            .map(|name| String::from_utf8_lossy(name.slice()).into_owned());
        if tag == gimli::DW_TAG_namespace && depth < MAX_NAMESPACE_DEPTH {
            let nested = format!("{prefix}{}::", name.as_deref().unwrap_or("(anonymous namespace)"));
            skim_children(dwarf, unit, child.children(), &nested, depth + 1, names, stats)?;
            continue;
        }
        if !indexed_tag(tag) {
            continue;
        }
        let Some(name) = name.filter(|name| !name.is_empty()) else { continue };
        if stats.named_types >= MAX_INDEX_ENTRIES {
            stats.truncated = true;
            return Ok(());
        }
        let declaration = matches!(entry.attr_value(gimli::DW_AT_declaration), Some(AttributeValue::Flag(true)));
        let die = entry.offset().0 + unit.header.offset().0;
        names.entry(format!("{prefix}{name}")).or_default().push(IndexEntry { die, rank: rank(tag, declaration) });
        stats.named_types += 1;
    }
    Ok(())
}

/// One lookup request. `offset`/`limit` page the top-level members (or enumerators).
#[derive(Debug, Clone, Default)]
pub struct DwarfTypeRequest {
    /// A type name, optionally with a `struct`/`union`/`enum`/`class` keyword; namespaces as `ns::Name`.
    pub name: String,
    /// A dotted member path such as `init.busy` or `aDb[1].pBt`.
    pub member: Option<String>,
    /// A byte offset into the type; the innermost member covering it is selected.
    pub byte_offset: Option<u64>,
    /// How many levels of by-value record members to expand inline.
    pub depth: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DwarfLookupWork {
    pub dies_read: usize,
    pub units_opened: usize,
}

#[derive(Debug, Serialize)]
pub struct DwarfTypeLookup {
    pub source: &'static str,
    pub name: String,
    /// Index entries with this name across every unit (definitions, typedefs and declarations).
    pub matches: usize,
    /// Entries materialised (at most [`MAX_LOOKUP_CANDIDATES`]).
    pub examined: usize,
    /// More than one distinct layout carries this name.
    pub ambiguous: bool,
    pub definitions: Vec<DwarfTypeDefinition>,
    pub work: DwarfLookupWork,
    pub index: DwarfIndexStats,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DwarfTypeDefinition {
    /// `struct`, `union`, `class`, `enum`, `base`, or the DWARF tag a typedef finally names.
    pub kind: String,
    pub type_name: String,
    /// Set when the requested name is a typedef: the chain to this definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_typedef: Option<String>,
    pub byte_size: Option<u64>,
    /// False for a declaration with no definition among the examined entries.
    pub complete: bool,
    /// `.debug_info` offset of the defining DIE.
    pub die_offset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decl_line: Option<u64>,
    /// Units that define an identical layout, this one included.
    pub occurrences: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<DwarfMemberSelection>,
    /// Members (record) or enumerators (enum) in this page. Member offsets are relative to their parent record.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<DwarfMember>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enumerators: Vec<DwarfEnumerator>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub next_offset: Option<usize>,
    /// Nested expansion stopped at the output limit.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DwarfMember {
    pub name: Option<String>,
    pub offset: Option<u64>,
    pub byte_size: Option<u64>,
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_size: Option<u64>,
    /// Bit offset from the start of the record (DW_AT_data_bit_offset), or the legacy DW_AT_bit_offset value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub inheritance: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<DwarfMember>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DwarfEnumerator {
    pub name: String,
    pub value: i128,
}

#[derive(Debug, Clone, Serialize)]
pub struct DwarfMemberSelection {
    /// The member path, e.g. `init.busy` or `aDb[1].pBt`.
    pub path: String,
    /// Offset from the start of the requested type.
    pub offset: u64,
    pub byte_size: Option<u64>,
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u64>,
    /// For a byte_offset query: how far into the selected member the offset falls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within: Option<u64>,
    /// For a byte_offset query: the offset lies in padding after the selected member.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub padding: bool,
    /// For a byte_offset query in a union: how many other members also cover the offset.
    #[serde(skip_serializing_if = "is_zero")]
    pub union_alternatives: usize,
    /// Each step from the requested type down, with offsets from the start of the requested type.
    pub chain: Vec<DwarfSelectionStep>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct DwarfSelectionStep {
    pub name: String,
    pub offset: u64,
    pub byte_size: Option<u64>,
    pub type_name: String,
}

/// The attributes a lookup uses from one DIE.
#[derive(Debug, Clone)]
struct Die {
    offset: usize,
    tag: gimli::DwTag,
    name: Option<String>,
    target: Option<usize>,
    byte_size: Option<u64>,
    declaration: bool,
    member_location: Option<u64>,
    bit_size: Option<u64>,
    data_bit_offset: Option<u64>,
    bit_offset: Option<u64>,
    count: Option<u64>,
    upper: Option<u64>,
    lower: Option<u64>,
    value: Option<i128>,
    decl_line: Option<u64>,
    external: bool,
    address_size: u8,
}

struct DieReader<'d, 'a> {
    dwarf: &'d Dwarf<DebugReader<'a>>,
    index: &'d DwarfTypeIndex,
    units: BTreeMap<usize, Unit<DebugReader<'a>>>,
    /// DIEs and child lists already read by this request; `work` counts only first reads.
    dies: BTreeMap<usize, Die>,
    children: BTreeMap<usize, (Vec<Die>, bool)>,
    work: DwarfLookupWork,
    output: usize,
}

type Candidate = (DwarfTypeDefinition, usize, String);

impl<'d, 'a> DieReader<'d, 'a> {
    fn new(dwarf: &'d Dwarf<DebugReader<'a>>, index: &'d DwarfTypeIndex) -> Self {
        Self {
            dwarf,
            index,
            units: BTreeMap::new(),
            dies: BTreeMap::new(),
            children: BTreeMap::new(),
            work: DwarfLookupWork::default(),
            output: 0,
        }
    }

    fn work(&self) -> DwarfLookupWork {
        self.work.clone()
    }

    fn exhausted(&self) -> bool {
        self.work.dies_read >= MAX_LOOKUP_DIES
    }

    fn spend(&mut self) -> Result<(), String> {
        if self.work.dies_read >= MAX_LOOKUP_DIES {
            return Err(format!("lookup read its {MAX_LOOKUP_DIES}-DIE budget"));
        }
        self.work.dies_read += 1;
        Ok(())
    }

    fn unit_of(&mut self, die: usize) -> Result<usize, String> {
        let position = self.index.units.partition_point(|&unit| unit <= die);
        let start = *position.checked_sub(1).and_then(|at| self.index.units.get(at)).ok_or("DIE outside every unit")?;
        if !self.units.contains_key(&start) {
            let header =
                self.dwarf.debug_info.header_from_offset(gimli::DebugInfoOffset(start)).map_err(|e| e.to_string())?;
            let unit = signature_unit(self.dwarf, header)?;
            self.work.units_opened += 1;
            self.units.insert(start, unit);
        }
        Ok(start)
    }

    fn die(&mut self, offset: usize) -> Result<Die, String> {
        if let Some(die) = self.dies.get(&offset) {
            return Ok(die.clone());
        }
        self.spend()?;
        let start = self.unit_of(offset)?;
        let unit = &self.units[&start];
        let entry = unit.entry(UnitOffset(offset - start)).map_err(|error| error.to_string())?;
        let die = read_die(self.dwarf, unit, start, &entry);
        self.dies.insert(offset, die.clone());
        Ok(die)
    }

    fn children(&mut self, offset: usize) -> Result<(Vec<Die>, bool), String> {
        if let Some(children) = self.children.get(&offset) {
            return Ok(children.clone());
        }
        self.spend()?;
        let start = self.unit_of(offset)?;
        let unit = &self.units[&start];
        let mut tree = unit.entries_tree(Some(UnitOffset(offset - start))).map_err(|error| error.to_string())?;
        let root = tree.root().map_err(|error| error.to_string())?;
        let mut children = root.children();
        let mut dies = Vec::new();
        let mut truncated = false;
        while let Some(child) = children.next().map_err(|error| error.to_string())? {
            if dies.len() >= MAX_MEMBERS {
                truncated = true;
                break;
            }
            if self.work.dies_read >= MAX_LOOKUP_DIES {
                return Err(format!("lookup read its {MAX_LOOKUP_DIES}-DIE budget"));
            }
            self.work.dies_read += 1;
            dies.push(read_die(self.dwarf, unit, start, child.entry()));
        }
        for die in &dies {
            self.dies.entry(die.offset).or_insert_with(|| die.clone());
        }
        self.children.insert(offset, (dies.clone(), truncated));
        Ok((dies, truncated))
    }

    /// Follows typedefs and qualifiers to the type that has a layout, with the typedef chain it crossed.
    fn strip(&mut self, mut die: Die) -> Result<(Die, Vec<String>), String> {
        let mut chain = Vec::new();
        for _ in 0..MAX_TYPE_CHAIN {
            if !matches!(
                die.tag,
                gimli::DW_TAG_typedef
                    | gimli::DW_TAG_const_type
                    | gimli::DW_TAG_volatile_type
                    | gimli::DW_TAG_restrict_type
                    | gimli::DW_TAG_atomic_type
            ) {
                return Ok((die, chain));
            }
            if die.tag == gimli::DW_TAG_typedef
                && let Some(name) = &die.name
            {
                chain.push(name.clone());
            }
            let Some(target) = die.target else {
                return Ok((die, chain));
            };
            die = self.die(target)?;
        }
        Err("type chain too deep".into())
    }

    /// A declaration's complete definition elsewhere in the image, found by name through the index.
    fn complete(&mut self, die: Die) -> Result<Die, String> {
        if !die.declaration || !record_tag(die.tag) && die.tag != gimli::DW_TAG_enumeration_type {
            return Ok(die);
        }
        let Some(name) = die.name.clone() else { return Ok(die) };
        let Some(entries) = self.index.names.get(&name) else { return Ok(die) };
        for entry in entries.iter().filter(|entry| entry.rank == 0).take(MAX_LOOKUP_CANDIDATES) {
            let candidate = self.die(entry.die)?;
            if candidate.tag == die.tag && !candidate.declaration {
                return Ok(candidate);
            }
        }
        Ok(die)
    }

    fn type_name(&mut self, target: Option<usize>) -> Result<String, String> {
        let mut suffix = String::new();
        let mut prefix = String::new();
        let mut next = target;
        for _ in 0..MAX_TYPE_CHAIN {
            let Some(offset) = next else {
                return Ok(format!("{prefix}void{suffix}"));
            };
            let die = self.die(offset)?;
            match die.tag {
                gimli::DW_TAG_pointer_type => suffix.insert_str(0, " *"),
                gimli::DW_TAG_reference_type => suffix.insert_str(0, " &"),
                gimli::DW_TAG_rvalue_reference_type => suffix.insert_str(0, " &&"),
                gimli::DW_TAG_const_type => prefix.push_str("const "),
                gimli::DW_TAG_volatile_type => prefix.push_str("volatile "),
                gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type => {}
                gimli::DW_TAG_array_type => {
                    let (dimensions, _) = self.dimensions(&die)?;
                    for count in dimensions {
                        suffix.push_str(&count.map_or_else(|| "[]".to_owned(), |count| format!("[{count}]")));
                    }
                }
                gimli::DW_TAG_subroutine_type => return Ok(format!("{prefix}fn(..){suffix}")),
                _ => return Ok(format!("{prefix}{}{suffix}", spelled(&die))),
            }
            next = die.target;
        }
        Ok(format!("{prefix}...{suffix}"))
    }

    fn dimensions(&mut self, array: &Die) -> Result<(Vec<Option<u64>>, bool), String> {
        let (children, truncated) = self.children(array.offset)?;
        let dimensions = children
            .iter()
            .filter(|child| matches!(child.tag, gimli::DW_TAG_subrange_type | gimli::DW_TAG_enumeration_type))
            .map(|child| {
                child.count.or_else(|| child.upper.map(|upper| upper.saturating_sub(child.lower.unwrap_or(0)) + 1))
            })
            .collect();
        Ok((dimensions, truncated))
    }

    fn size(&mut self, target: Option<usize>) -> Result<Option<u64>, String> {
        let Some(offset) = target else { return Ok(None) };
        let die = self.die(offset)?;
        let (die, _) = self.strip(die)?;
        let die = self.complete(die)?;
        self.size_of(&die)
    }

    fn size_of(&mut self, die: &Die) -> Result<Option<u64>, String> {
        if let Some(size) = die.byte_size {
            return Ok(Some(size));
        }
        Ok(match die.tag {
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_ptr_to_member_type => Some(u64::from(die.address_size)),
            gimli::DW_TAG_array_type => {
                let (dimensions, _) = self.dimensions(die)?;
                let element = self.size(die.target)?;
                let mut size = element;
                for count in dimensions {
                    size = size.zip(count).and_then(|(size, count)| size.checked_mul(count));
                }
                size
            }
            _ => None,
        })
    }

    fn members(&mut self, record: &Die) -> Result<(Vec<(Die, DwarfMember)>, bool), String> {
        let (children, truncated) = self.children(record.offset)?;
        let union = record.tag == gimli::DW_TAG_union_type;
        let mut members = Vec::new();
        for child in children {
            let inheritance = child.tag == gimli::DW_TAG_inheritance;
            if child.tag != gimli::DW_TAG_member && !inheritance {
                continue;
            }
            // C++ static data members (DWARF 4) are declarations without storage in the record.
            if child.declaration || child.external && child.member_location.is_none() && !union {
                continue;
            }
            let offset = child.member_location.or(child.data_bit_offset.map(|bits| bits / 8)).or(union.then_some(0));
            let byte_size = match child.byte_size {
                Some(size) => Some(size),
                None if child.bit_size.is_some() => None,
                None => self.size(child.target)?,
            };
            let member = DwarfMember {
                name: child.name.clone(),
                offset,
                byte_size,
                type_name: self.type_name(child.target)?,
                bit_size: child.bit_size,
                bit_offset: child.data_bit_offset.or(child.bit_offset),
                inheritance,
                members: Vec::new(),
            };
            members.push((child, member));
        }
        Ok((members, truncated))
    }

    /// The record a by-value member names, if any.
    fn record_of(&mut self, target: Option<usize>) -> Result<Option<Die>, String> {
        let Some(offset) = target else { return Ok(None) };
        let die = self.die(offset)?;
        let (die, _) = self.strip(die)?;
        let die = self.complete(die)?;
        Ok(record_tag(die.tag).then_some(die))
    }

    fn expand(&mut self, members: &mut [(Die, DwarfMember)], depth: usize, truncated: &mut bool) -> Result<(), String> {
        if depth == 0 {
            return Ok(());
        }
        for (die, member) in members.iter_mut() {
            let Some(record) = self.record_of(die.target)? else { continue };
            let (mut nested, cut) = self.members(&record)?;
            *truncated |= cut;
            if self.output + nested.len() > MAX_OUTPUT_MEMBERS {
                *truncated = true;
                return Ok(());
            }
            self.output += nested.len();
            self.expand(&mut nested, depth - 1, truncated)?;
            member.members = nested.into_iter().map(|(_, member)| member).collect();
        }
        Ok(())
    }

    fn definition(
        &mut self,
        die: usize,
        keyword: Option<gimli::DwTag>,
        request: &DwarfTypeRequest,
    ) -> Result<Option<Candidate>, String> {
        let named = self.die(die)?;
        let (resolved, typedefs) = self.strip(named.clone())?;
        let resolved = self.complete(resolved)?;
        if let Some(tag) = keyword
            && (named.tag != tag || !typedefs.is_empty())
        {
            return Ok(None);
        }
        let via_typedef = (!typedefs.is_empty()).then(|| {
            let mut chain = typedefs.join(" -> ");
            chain.push_str(" -> ");
            chain.push_str(&spelled(&resolved));
            chain
        });
        let byte_size = self.size_of(&resolved)?;
        let complete = !resolved.declaration;
        let unit_name = {
            let start = self.unit_of(resolved.offset)?;
            let unit = &self.units[&start];
            unit.entries()
                .next_dfs()
                .ok()
                .flatten()
                .and_then(|root| root.attr_value(gimli::DW_AT_name))
                .and_then(|value| bounded_name_limit(self.dwarf, unit, value, MAX_NAME).ok())
                .map(|name| String::from_utf8_lossy(name.slice()).into_owned())
        };
        let mut definition = DwarfTypeDefinition {
            kind: kind(resolved.tag),
            type_name: spelled(&resolved),
            via_typedef,
            byte_size,
            complete,
            die_offset: format!("{:#x}", resolved.offset),
            unit: unit_name,
            decl_line: resolved.decl_line,
            occurrences: 1,
            selection: None,
            members: Vec::new(),
            enumerators: Vec::new(),
            total: 0,
            offset: request.offset,
            limit: request.limit,
            next_offset: None,
            truncated: false,
        };
        let mut fingerprint = format!("{}|{}|{:?}|{}", definition.kind, definition.type_name, byte_size, complete);
        if record_tag(resolved.tag) && complete {
            let (mut members, truncated) = self.members(&resolved)?;
            definition.truncated = truncated;
            for (_, member) in &members {
                fingerprint.push_str(&format!(
                    "|{:?}:{:?}:{}:{:?}:{:?}",
                    member.name, member.offset, member.type_name, member.bit_size, member.bit_offset
                ));
            }
            if let Some(path) = &request.member {
                definition.selection = Some(self.select_path(&resolved, path)?);
            } else if let Some(at) = request.byte_offset {
                definition.selection = self.select_offset(&resolved, at)?;
            }
            definition.total = members.len();
            let end = request.offset.saturating_add(request.limit).min(members.len());
            let mut page: Vec<_> = members.drain(request.offset.min(end)..end).collect();
            self.output = page.len();
            let mut cut = false;
            self.expand(&mut page, request.depth, &mut cut)?;
            definition.truncated |= cut;
            definition.members = page.into_iter().map(|(_, member)| member).collect();
            definition.next_offset = (request.limit > 0 && end < definition.total).then_some(end);
        } else if resolved.tag == gimli::DW_TAG_enumeration_type && complete {
            let (children, truncated) = self.children(resolved.offset)?;
            definition.truncated = truncated;
            let values: Vec<_> = children
                .into_iter()
                .filter(|child| child.tag == gimli::DW_TAG_enumerator)
                .map(|child| DwarfEnumerator { name: child.name.unwrap_or_default(), value: child.value.unwrap_or(0) })
                .collect();
            for value in &values {
                fingerprint.push_str(&format!("|{}={}", value.name, value.value));
            }
            if request.member.is_some() || request.byte_offset.is_some() {
                return Err("member and byte_offset select within a struct, union or class".into());
            }
            definition.total = values.len();
            let end = request.offset.saturating_add(request.limit).min(values.len());
            definition.enumerators = values[request.offset.min(end)..end].to_vec();
            definition.next_offset = (request.limit > 0 && end < definition.total).then_some(end);
        } else if request.member.is_some() || request.byte_offset.is_some() {
            if !complete {
                return Ok(Some((definition, resolved.offset, fingerprint)));
            }
            return Err("member and byte_offset select within a struct, union or class".into());
        }
        Ok(Some((definition, resolved.offset, fingerprint)))
    }

    fn select_path(&mut self, record: &Die, path: &str) -> Result<DwarfMemberSelection, String> {
        let mut current = record.clone();
        let mut base = 0u64;
        let mut chain = Vec::new();
        let mut last: Option<(DwarfMember, Option<usize>)> = None;
        let segments: Vec<&str> = path.split('.').collect();
        if segments.len() > MAX_SELECTION_DEPTH || segments.iter().any(|segment| segment.is_empty()) {
            return Err(format!("invalid member path {path:?}"));
        }
        for (step, segment) in segments.iter().enumerate() {
            let (name, indices) = parse_segment(segment)?;
            if step > 0 {
                let (_, target) = last.as_ref().expect("previous step");
                current = self
                    .record_of(*target)?
                    .ok_or_else(|| format!("{:?} is not a struct, union or class", chain_path(&chain)))?;
            }
            let (offset, member, die) = self
                .find_member(&current, name, 0)?
                .ok_or_else(|| format!("no member {name:?} in {}", spelled(&current)))?;
            base += offset;
            let mut member = member;
            let mut target = die.target;
            let mut label = name.to_owned();
            for index in indices {
                let array = target.map(|offset| self.die(offset)).transpose()?;
                let array = match array {
                    Some(array) => self.strip(array)?.0,
                    None => return Err(format!("{label} is not an array")),
                };
                if array.tag != gimli::DW_TAG_array_type {
                    return Err(format!("{label} is not an array"));
                }
                let element = self.size(array.target)?.ok_or_else(|| format!("{label}: element size unknown"))?;
                let (dimensions, _) = self.dimensions(&array)?;
                if let Some(Some(count)) = dimensions.first()
                    && index >= *count
                {
                    return Err(format!("{label}[{index}] is out of bounds ({count} elements)"));
                }
                base += element * index;
                label = format!("{label}[{index}]");
                target = array.target;
                member = DwarfMember {
                    name: Some(label.clone()),
                    offset: Some(base),
                    byte_size: Some(element),
                    type_name: self.type_name(array.target)?,
                    bit_size: None,
                    bit_offset: None,
                    inheritance: false,
                    members: Vec::new(),
                };
            }
            chain.push(DwarfSelectionStep {
                name: label,
                offset: base,
                byte_size: member.byte_size,
                type_name: member.type_name.clone(),
            });
            last = Some((member, target));
        }
        let (member, _) = last.ok_or("empty member path")?;
        Ok(DwarfMemberSelection {
            path: chain_path(&chain),
            offset: base,
            byte_size: member.byte_size,
            type_name: member.type_name,
            bit_size: member.bit_size,
            bit_offset: member.bit_offset,
            within: None,
            padding: false,
            union_alternatives: 0,
            chain,
        })
    }

    /// Finds a named member, looking through anonymous struct/union members as C does. Returns its offset.
    fn find_member(
        &mut self,
        record: &Die,
        name: &str,
        depth: usize,
    ) -> Result<Option<(u64, DwarfMember, Die)>, String> {
        let (members, _) = self.members(record)?;
        for (die, member) in &members {
            if member.name.as_deref() == Some(name) {
                return Ok(Some((member.offset.unwrap_or(0), member.clone(), die.clone())));
            }
        }
        if depth >= MAX_SELECTION_DEPTH {
            return Ok(None);
        }
        for (die, member) in members {
            if member.name.is_some() {
                continue;
            }
            if let Some(nested) = self.record_of(die.target)?
                && let Some((offset, found, found_die)) = self.find_member(&nested, name, depth + 1)?
            {
                return Ok(Some((member.offset.unwrap_or(0) + offset, found, found_die)));
            }
        }
        Ok(None)
    }

    fn select_offset(&mut self, record: &Die, at: u64) -> Result<Option<DwarfMemberSelection>, String> {
        if self.size_of(record)?.is_some_and(|size| at >= size) {
            return Err(format!("byte_offset {at:#x} is past the end of {}", spelled(record)));
        }
        let mut current = record.clone();
        let mut remaining = at;
        let mut base = 0u64;
        let mut chain: Vec<DwarfSelectionStep> = Vec::new();
        let mut selection: Option<DwarfMemberSelection> = None;
        for _ in 0..MAX_SELECTION_DEPTH {
            let (members, _) = self.members(&current)?;
            let covering: Vec<_> = members
                .iter()
                .filter(|(_, member)| {
                    let Some(offset) = member.offset else { return false };
                    let size = member.byte_size.or(member.bit_size.map(|bits| bits.div_ceil(8))).unwrap_or(0);
                    remaining >= offset && remaining < offset + size.max(1)
                })
                .collect();
            let (die, member, padding) = match covering.first() {
                Some((die, member)) => (die.clone(), member.clone(), false),
                None => {
                    let Some((die, member)) = members
                        .iter()
                        .filter(|(_, member)| member.offset.is_some_and(|offset| offset <= remaining))
                        .max_by_key(|(_, member)| member.offset)
                    else {
                        break;
                    };
                    (die.clone(), member.clone(), true)
                }
            };
            let offset = member.offset.unwrap_or(0);
            let mut label = member.name.clone().unwrap_or_else(|| "(anonymous)".into());
            let mut step_offset = base + offset;
            let mut step_size = member.byte_size;
            let mut step_type = member.type_name.clone();
            let mut target = die.target;
            let mut inner = remaining - offset;
            // Arrays: select the element, then continue into it.
            if !padding && let Some(array_offset) = target {
                let array = self.die(array_offset)?;
                let (array, _) = self.strip(array)?;
                if array.tag == gimli::DW_TAG_array_type
                    && let Some(element) = self.size(array.target)?.filter(|&size| size > 0)
                {
                    let index = inner / element;
                    label = format!("{label}[{index}]");
                    step_offset += index * element;
                    step_size = Some(element);
                    step_type = self.type_name(array.target)?;
                    inner -= index * element;
                    target = array.target;
                }
            }
            chain.push(DwarfSelectionStep {
                name: label,
                offset: step_offset,
                byte_size: step_size,
                type_name: step_type.clone(),
            });
            selection = Some(DwarfMemberSelection {
                path: chain_path(&chain),
                offset: step_offset,
                byte_size: step_size,
                type_name: step_type,
                bit_size: member.bit_size,
                bit_offset: member.bit_offset,
                within: Some(inner),
                padding,
                union_alternatives: covering.len().saturating_sub(1),
                chain: chain.clone(),
            });
            if padding {
                break;
            }
            let Some(nested) = self.record_of(target)? else { break };
            current = nested;
            base = step_offset;
            remaining = inner;
        }
        Ok(selection)
    }
}

fn chain_path(chain: &[DwarfSelectionStep]) -> String {
    chain.iter().map(|step| step.name.as_str()).collect::<Vec<_>>().join(".")
}

fn parse_segment(segment: &str) -> Result<(&str, Vec<u64>), String> {
    let Some(open) = segment.find('[') else { return Ok((segment, Vec::new())) };
    let name = &segment[..open];
    let mut indices = Vec::new();
    let mut rest = &segment[open..];
    while let Some(stripped) = rest.strip_prefix('[') {
        let close = stripped.find(']').ok_or_else(|| format!("invalid member path segment {segment:?}"))?;
        let text = stripped[..close].trim();
        let index = match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => text.parse(),
        }
        .map_err(|_| format!("invalid array index in {segment:?}"))?;
        indices.push(index);
        rest = &stripped[close + 1..];
    }
    if !rest.is_empty() || name.is_empty() {
        return Err(format!("invalid member path segment {segment:?}"));
    }
    Ok((name, indices))
}

fn record_tag(tag: gimli::DwTag) -> bool {
    matches!(tag, gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type)
}

fn kind(tag: gimli::DwTag) -> String {
    match tag {
        gimli::DW_TAG_structure_type => "struct".into(),
        gimli::DW_TAG_union_type => "union".into(),
        gimli::DW_TAG_class_type => "class".into(),
        gimli::DW_TAG_enumeration_type => "enum".into(),
        gimli::DW_TAG_base_type => "base".into(),
        gimli::DW_TAG_pointer_type => "pointer".into(),
        gimli::DW_TAG_array_type => "array".into(),
        gimli::DW_TAG_subroutine_type => "function".into(),
        other => other.static_string().map_or_else(|| format!("{:#x}", other.0), |name| name.to_owned()),
    }
}

fn spelled(die: &Die) -> String {
    let keyword = match die.tag {
        gimli::DW_TAG_structure_type => "struct ",
        gimli::DW_TAG_union_type => "union ",
        gimli::DW_TAG_enumeration_type => "enum ",
        gimli::DW_TAG_class_type => "class ",
        _ => "",
    };
    match &die.name {
        Some(name) => format!("{keyword}{name}"),
        None if keyword.is_empty() => "<unnamed>".into(),
        None => format!("{keyword}<anonymous>"),
    }
}

fn read_die(
    dwarf: &Dwarf<DebugReader<'_>>,
    unit: &Unit<DebugReader<'_>>,
    start: usize,
    entry: &gimli::DebuggingInformationEntry<DebugReader<'_>>,
) -> Die {
    let reference = |value: AttributeValue<DebugReader<'_>>| match value {
        AttributeValue::UnitRef(offset) => Some(start + offset.0),
        AttributeValue::DebugInfoRef(offset) => Some(offset.0),
        _ => None,
    };
    let mut die = Die {
        offset: start + entry.offset().0,
        tag: entry.tag(),
        name: None,
        target: None,
        byte_size: None,
        declaration: false,
        member_location: None,
        bit_size: None,
        data_bit_offset: None,
        bit_offset: None,
        count: None,
        upper: None,
        lower: None,
        value: None,
        decl_line: None,
        external: false,
        address_size: unit.header.address_size(),
    };
    for attr in entry.attrs() {
        let value = attr.value();
        match attr.name() {
            gimli::DW_AT_name => {
                die.name = bounded_name_limit(dwarf, unit, value, MAX_NAME)
                    .ok()
                    .map(|name| String::from_utf8_lossy(name.slice()).into_owned());
            }
            gimli::DW_AT_type => die.target = reference(value),
            gimli::DW_AT_byte_size => die.byte_size = value.udata_value(),
            gimli::DW_AT_declaration => die.declaration = matches!(value, AttributeValue::Flag(true)),
            gimli::DW_AT_external => die.external = matches!(value, AttributeValue::Flag(true)),
            gimli::DW_AT_data_member_location => die.member_location = member_location(value),
            gimli::DW_AT_bit_size => die.bit_size = value.udata_value(),
            gimli::DW_AT_data_bit_offset => die.data_bit_offset = value.udata_value(),
            gimli::DW_AT_bit_offset => die.bit_offset = value.udata_value(),
            gimli::DW_AT_count => die.count = value.udata_value(),
            gimli::DW_AT_upper_bound => die.upper = value.udata_value(),
            gimli::DW_AT_lower_bound => die.lower = value.udata_value(),
            gimli::DW_AT_decl_line => die.decl_line = value.udata_value(),
            gimli::DW_AT_const_value => {
                die.value = match value {
                    AttributeValue::Sdata(value) => Some(i128::from(value)),
                    AttributeValue::Udata(value) => Some(i128::from(value)),
                    other => other.udata_value().map(i128::from),
                };
            }
            _ => {}
        }
    }
    die
}

/// A constant member offset, or the `DW_OP_plus_uconst n` / `DW_OP_constu n` expression older producers emit.
fn member_location(value: AttributeValue<DebugReader<'_>>) -> Option<u64> {
    match value {
        AttributeValue::Exprloc(expression) => {
            let bytes = expression.0.slice();
            let (&op, rest) = bytes.split_first()?;
            if op != gimli::DW_OP_plus_uconst.0 && op != gimli::DW_OP_constu.0 {
                return None;
            }
            let mut reader = EndianSlice::new(rest, RunTimeEndian::Little);
            let offset = gimli::Reader::read_uleb128(&mut reader).ok()?;
            gimli::Reader::is_empty(&reader).then_some(offset)
        }
        other => other.udata_value(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABBREV: &[u8] = &[
        // 1: compile_unit, children, name string
        1, 0x11, 1, 0x03, 0x08, 0, 0, //
        // 2: structure_type, children, name string, byte_size data1
        2, 0x13, 1, 0x03, 0x08, 0x0b, 0x0b, 0, 0, //
        // 3: member, no children, name string, type ref4, data_member_location data1
        3, 0x0d, 0, 0x03, 0x08, 0x49, 0x13, 0x38, 0x0b, 0, 0, //
        // 4: base_type, no children, name string, byte_size data1, encoding data1
        4, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, //
        // 5: typedef, no children, name string, type ref4
        5, 0x16, 0, 0x03, 0x08, 0x49, 0x13, 0, 0, //
        0,
    ];

    fn cstr(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(text.as_bytes());
        out.push(0);
    }

    /// One DWARF 4 compilation unit: `int`, then each struct with `fields` int members, then a typedef per struct.
    fn unit(info: &mut Vec<u8>, structs: &[(&str, usize)]) {
        let mut body = Vec::new();
        body.push(1);
        cstr(&mut body, "unit.c");
        let header = 11usize;
        let int = header + body.len();
        body.push(4);
        cstr(&mut body, "int");
        body.extend_from_slice(&[4, 5]);
        let mut records = Vec::new();
        for &(name, fields) in structs {
            records.push(header + body.len());
            body.push(2);
            cstr(&mut body, name);
            body.push(u8::try_from(fields * 4).unwrap());
            for field in 0..fields {
                body.push(3);
                cstr(&mut body, &format!("f{field}"));
                body.extend_from_slice(&u32::try_from(int).unwrap().to_le_bytes());
                body.push(u8::try_from(field * 4).unwrap());
            }
            body.push(0);
        }
        for (&(name, _), record) in structs.iter().zip(records) {
            body.push(5);
            cstr(&mut body, &format!("{name}_t"));
            body.extend_from_slice(&u32::try_from(record).unwrap().to_le_bytes());
        }
        body.push(0);
        let length = u32::try_from(body.len() + 7).unwrap();
        info.extend_from_slice(&length.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.push(8);
        info.extend_from_slice(&body);
    }

    fn index(fillers: usize) -> DwarfTypeIndex {
        let mut info = Vec::new();
        let names: Vec<String> = (0..20).map(|n| format!("filler{n}")).collect();
        for filler in 0..fillers {
            let structs: Vec<(&str, usize)> = names.iter().map(|name| (name.as_str(), 1 + filler % 7)).collect();
            unit(&mut info, &structs);
        }
        unit(&mut info, &[("inner", 2), ("target", 8)]);
        for filler in 0..fillers {
            let structs: Vec<(&str, usize)> = names.iter().map(|name| (name.as_str(), 2 + filler % 5)).collect();
            unit(&mut info, &structs);
        }
        let sections = Sections { info, abbrev: ABBREV.to_vec(), ..Sections::default() };
        DwarfTypeIndex::build(sections).unwrap()
    }

    fn request(name: &str) -> DwarfTypeRequest {
        DwarfTypeRequest { name: name.into(), limit: 64, ..DwarfTypeRequest::default() }
    }

    #[test]
    fn lookup_work_is_independent_of_unit_and_type_count() {
        let small = index(0);
        let large = index(200);
        assert_eq!(small.stats().units, 1);
        assert_eq!(large.stats().units, 401);
        assert!(large.stats().named_types > 200 * 40);
        for name in ["target", "target_t", "struct target"] {
            let small = small.lookup(&request(name)).unwrap();
            let large = large.lookup(&request(name)).unwrap();
            assert_eq!(small.definitions.len(), 1, "{name}");
            assert_eq!(large.definitions.len(), 1, "{name}");
            assert_eq!(large.definitions[0].members.len(), 8);
            assert_eq!(large.definitions[0].byte_size, Some(32));
            assert_eq!(small.work.dies_read, large.work.dies_read, "{name}");
            assert_eq!(small.work.units_opened, 1);
            assert_eq!(large.work.units_opened, 1);
        }
        let selected = large.lookup(&DwarfTypeRequest { byte_offset: Some(13), ..request("target_t") }).unwrap();
        let selection = selected.definitions[0].selection.as_ref().unwrap();
        assert_eq!((selection.path.as_str(), selection.offset, selection.within), ("f3", 12, Some(1)));
        assert_eq!(selected.definitions[0].via_typedef.as_deref(), Some("target_t -> struct target"));
    }

    #[test]
    fn identical_definitions_merge_and_different_ones_are_ambiguous() {
        let large = index(3);
        let lookup = large.lookup(&request("filler0")).unwrap();
        assert_eq!(lookup.matches, 6);
        // Filler sizes cycle: (1, 2, 3) fields before, (2, 3, 4) after.
        assert!(lookup.ambiguous);
        assert_eq!(lookup.definitions.len(), 4);
        assert_eq!(lookup.definitions.iter().map(|d| d.occurrences).sum::<usize>(), 6);
    }

    #[test]
    fn member_paths_and_errors() {
        let index = index(0);
        let lookup = index.lookup(&DwarfTypeRequest { member: Some("f5".into()), ..request("target") }).unwrap();
        let selection = lookup.definitions[0].selection.as_ref().unwrap();
        assert_eq!((selection.offset, selection.byte_size, selection.type_name.as_str()), (20, Some(4), "int"));
        assert!(
            index
                .lookup(&DwarfTypeRequest { member: Some("nope".into()), ..request("target") })
                .is_ok_and(|lookup| lookup.definitions.is_empty() && lookup.warnings[0].contains("no member \"nope\""))
        );
        assert!(index.lookup(&request("missing")).unwrap().definitions.is_empty());
        assert_eq!(index.suggestions("targ"), vec!["target".to_owned(), "target_t".to_owned()]);
        assert_eq!(parse_segment("a[1][0x2]").unwrap(), ("a", vec![1, 2]));
        assert!(parse_segment("a[").is_err());
    }
}
