//! Bounded embedded producer evidence, independent of the legacy flat projections.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{AttributeValue, Dwarf, EndianSlice, Reader, RunTimeEndian, Section};
use object::{CompressionFormat, Object, ObjectKind, ObjectSection};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    DebugLayoutSource, DebugLayoutTypeId, DebugReader, MAX_ATTRIBUTES, MAX_DEBUG_BYTES, MAX_NESTING, MAX_TYPE_DEPTH,
    MAX_UNITS, TypeRef, WARNINGS, bounded_name_limit, signature_unit, validate_abbreviations_work,
};
use crate::{Binary, Format, LoadError};

// Same retained graph and work bounds as layouts.rs; neither preview widens the other's admission gate.
const MAX_NAMES: usize = 32 * 1024;
const MAX_NAME: usize = 128;
const MAX_SIZE: u64 = 1024 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_LAYOUTS: usize = 128;
const MAX_TOTAL_FIELDS: usize = 4096;
const MAX_EDGES: usize = 8192;
const MAX_TYPES: usize = 4096;
const MAX_NODES: usize = 16384;
const MAX_FUNCTIONS: usize = 1024;
const MAX_WORK: usize = 262144;
const MAX_READ_WORK: usize = 262144;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugTypeTarget {
    X86_64Elf,
    Aarch64Elf,
    Aarch64MachO,
}

#[derive(Debug, Default, Serialize)]
pub struct DebugProducerReport {
    pub target: Option<DebugTypeTarget>,
    pub types: Vec<DebugProducerType>,
    pub functions: Vec<DebugProducerFunction>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerType {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub byte_size: Option<u64>,
    pub producer_alignment: Option<u64>,
    pub source: Option<DebugLayoutSource>,
    pub kind: DebugProducerKind,
    /// Includes unsupported dependencies, even through a pointer. Never a native verification claim.
    pub unsupported_reasons: Vec<String>,
    pub eligible_for_native_verification: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugProducerKind {
    Scalar {
        encoding: u8,
        scalar_kind: DebugProducerScalarKind,
        bit_width: u64,
        signed: Option<bool>,
    },
    Pointer {
        target: Option<DebugLayoutTypeId>,
        address_size: u8,
    },
    Record {
        record_kind: DebugProducerRecordKind,
        members: Vec<DebugProducerMember>,
    },
    Array {
        element: Option<DebugLayoutTypeId>,
        dimensions: Vec<DebugProducerDimension>,
        /// Through the last element, excluding unproven trailing allocation padding.
        occupied_byte_size: Option<u64>,
        /// Explicit array-DIE DW_AT_byte_size only.
        producer_byte_size: Option<u64>,
        /// Explicit array-DIE stride, separate from any subrange-DIE stride.
        producer_byte_stride: Option<u64>,
        /// A byte/bit stride attribute exists, including when its value is nonconstant or unsupported.
        producer_stride_present: bool,
    },
    Enum {
        underlying: Option<DebugLayoutTypeId>,
        encoding: Option<u8>,
        values: Vec<DebugProducerEnumerator>,
    },
    Alias {
        target: Option<DebugLayoutTypeId>,
    },
    Qualified {
        target: Option<DebugLayoutTypeId>,
        qualifier: String,
    },
    Function {
        prototype: DebugProducerPrototype,
    },
    Unsupported {
        dwarf_tag: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugProducerScalarKind {
    Integer,
    Float,
    Boolean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugProducerRecordKind {
    Struct,
    Class,
    Union,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerMember {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub ty: Option<DebugLayoutTypeId>,
    pub byte_offset: Option<u64>,
    pub producer_alignment: Option<u64>,
    pub bitfield: Option<DebugProducerBitfield>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerBitfield {
    pub bit_size: Option<u64>,
    pub data_bit_offset: Option<u64>,
    pub legacy_bit_offset: Option<u64>,
    /// Only the member DIE's explicit DW_AT_byte_size, never the underlying integer type's size.
    pub raw_storage_byte_size: Option<u64>,
    pub underlying_type_byte_size: Option<u64>,
    pub native_unsupported_reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerDimension {
    pub id: DebugLayoutTypeId,
    pub lower_bound: Option<i64>,
    pub lower_bound_present: bool,
    /// Explicit subrange-DIE DW_AT_upper_bound, including when the element type is unsupported.
    pub raw_upper_bound: Option<i64>,
    pub count: Option<u64>,
    pub byte_stride: Option<u64>,
    pub stride_present: bool,
    pub unsupported_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerEnumerator {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    /// Signed and unsigned constants stay distinct, including unsigned values above i64::MAX.
    pub value: Option<DebugProducerInteger>,
    pub raw_constant: Option<DebugProducerConstant>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DebugProducerConstant {
    pub form: u16,
    /// Fixed-width data forms only; LEB constants have no fixed byte width.
    pub byte_width: Option<u8>,
    /// Fixed-form unsigned bits or the LEB constant's original signed/unsigned value, before enum interpretation.
    pub value: DebugProducerInteger,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DebugProducerInteger {
    Signed(i64),
    Unsigned(u64),
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerParameter {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub ty: Option<DebugLayoutTypeId>,
    pub artificial: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerPrototype {
    /// None is void only when return_type_absent is true, never an unresolved reference.
    pub return_type: Option<DebugLayoutTypeId>,
    pub return_type_absent: bool,
    pub parameters: Vec<DebugProducerParameter>,
    pub variadic: bool,
    /// Complete prototype evidence may be explicit or inherent in a recognized C++ CU language.
    pub prototyped: bool,
    pub producer_prototyped: Option<bool>,
    pub producer_prototyped_present: bool,
    pub prototype_basis: Option<DebugProducerPrototypeBasis>,
    /// Absent DW_AT_calling_convention means DW_CC_normal under DWARF, not host inference.
    pub calling_convention: Option<u8>,
    pub calling_convention_explicit: bool,
    pub object_pointer: Option<DebugLayoutTypeId>,
    pub declaration_id: Option<DebugLayoutTypeId>,
    pub record_id: Option<DebugLayoutTypeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugProducerPrototypeBasis {
    ExplicitAttribute,
    CppLanguage { language: u16 },
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugProducerFunction {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub address: Option<u64>,
    pub source: Option<DebugLayoutSource>,
    pub prototype: DebugProducerPrototype,
    pub unsupported_reasons: Vec<String>,
    pub eligible_for_native_verification: bool,
}

impl DebugProducerReport {
    fn warn(&mut self, reason: String) {
        WARNINGS.push(&mut self.warnings, reason);
    }
}

/// Reads producer facts only. No external sources, runtime expressions, native types or host layouts are consulted.
pub fn producer_type_graph(binary: &Binary) -> Result<DebugProducerReport, LoadError> {
    let mut report = DebugProducerReport::default();
    if !matches!(binary.format, Format::Elf | Format::MachO) {
        report.warn("embedded DWARF type graph requires little-endian ELF64 or AArch64 Mach-O".into());
        return Ok(report);
    }
    let object = object::File::parse(binary.image_bytes())?;
    report.target = match (object.format(), object.architecture(), object.is_little_endian(), object.is_64()) {
        (object::BinaryFormat::Elf, object::Architecture::X86_64, true, true) => Some(DebugTypeTarget::X86_64Elf),
        (object::BinaryFormat::Elf, object::Architecture::Aarch64, true, true) => Some(DebugTypeTarget::Aarch64Elf),
        (object::BinaryFormat::MachO, object::Architecture::Aarch64, true, true) => Some(DebugTypeTarget::Aarch64MachO),
        _ => None,
    };
    let metadata_matches = match report.target {
        Some(DebugTypeTarget::X86_64Elf) => binary.arch == rampage_arch::Arch::X86_64 && binary.format == Format::Elf,
        Some(DebugTypeTarget::Aarch64Elf) => binary.arch == rampage_arch::Arch::Aarch64 && binary.format == Format::Elf,
        Some(DebugTypeTarget::Aarch64MachO) => {
            binary.arch == rampage_arch::Arch::Aarch64 && binary.format == Format::MachO
        }
        None => false,
    };
    if !metadata_matches {
        report.target = None;
    }
    if report.target.is_none() || object.kind() == ObjectKind::Relocatable {
        report.warn("unsupported DWARF type graph image target or relocatable context".into());
        return Ok(report);
    }
    let dwarf = match embedded_dwarf(&object) {
        Ok(dwarf) => dwarf,
        Err(error) => {
            report.warn(error);
            return Ok(report);
        }
    };
    if dwarf.debug_info.reader().is_empty() {
        report.warn("no embedded DWARF .debug_info; external debug files are not searched".into());
        return Ok(report);
    }
    match read_nodes(&dwarf, &mut Budget::default()) {
        Ok(nodes) => build_report(&nodes, |address| binary.is_code(address), &mut report),
        Err(error) => report.warn(format!("DWARF producer graph stopped: {error}; {}", super::DWARF_LOOKUP_HINT)),
    }
    Ok(report)
}

fn embedded_dwarf<'a>(object: &object::File<'a>) -> Result<Dwarf<DebugReader<'a>>, String> {
    let mut total = 0usize;
    let mut names = BTreeSet::new();
    for section in object.sections() {
        let name = section.name().map_err(|error| error.to_string())?;
        let canonical = if name == "__debug_str_offs" {
            ".debug_str_offsets".to_owned()
        } else if let Some(name) = name.strip_prefix("__debug_") {
            format!(".debug_{name}")
        } else {
            name.to_owned()
        };
        if matches!(
            canonical.as_str(),
            ".gnu_debuglink"
                | ".gnu_debugaltlink"
                | ".debug_sup"
                | ".debug_types"
                | ".debug_cu_index"
                | ".debug_tu_index"
        ) || name.ends_with(".dwo")
            || name.starts_with(".rela.debug_")
            || name.starts_with(".rel.debug_")
        {
            return Err("external, split, relocated or type-unit DWARF context is unsupported".into());
        }
        if ![".debug_", ".zdebug_", "__debug_", "__zdebug_"].iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        if !names.insert(canonical) {
            return Err("duplicate canonical DWARF section identity".into());
        }
        if section.relocations().next().is_some() {
            return Err("relocated DWARF section requires unsupported producer context".into());
        }
        let size = usize::try_from(section.size()).map_err(|_| "DWARF section size overflow")?;
        total = total
            .checked_add(size)
            .filter(|&size| size <= MAX_DEBUG_BYTES)
            .ok_or("DWARF exceeds the 64 MiB section-byte limit")?;
        if name.contains("zdebug_")
            || section.compressed_file_range().map_err(|error| error.to_string())?.format != CompressionFormat::None
        {
            return Err("compressed DWARF type context is unsupported".into());
        }
    }
    Dwarf::load(|id| {
        if !matches!(
            id,
            gimli::SectionId::DebugInfo
                | gimli::SectionId::DebugAbbrev
                | gimli::SectionId::DebugStr
                | gimli::SectionId::DebugLineStr
                | gimli::SectionId::DebugStrOffsets
                | gimli::SectionId::DebugAddr
        ) {
            return Ok(EndianSlice::new(&[], RunTimeEndian::Little));
        }
        let macho = if id == gimli::SectionId::DebugStrOffsets {
            "__debug_str_offs".to_owned()
        } else {
            id.name().replacen(".debug_", "__debug_", 1)
        };
        let Some(section) = object.section_by_name(id.name()).or_else(|| object.section_by_name(&macho)) else {
            return Ok(EndianSlice::new(&[], RunTimeEndian::Little));
        };
        let data = section.data().map_err(|error| error.to_string())?;
        if data.len() as u64 != section.size() {
            return Err("DWARF section declared/data size mismatch".into());
        }
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    })
}

#[derive(Debug, Default)]
struct Budget {
    read: usize,
    work: usize,
    names: usize,
    edges: usize,
}

impl Budget {
    fn reserve(&mut self, amount: usize) -> Result<(), String> {
        self.read = self
            .read
            .checked_add(amount)
            .filter(|&n| n <= MAX_READ_WORK)
            .ok_or("DWARF cumulative pre-read work limit exceeded")?;
        Ok(())
    }
    fn work(&mut self) -> Result<(), String> {
        self.work += 1;
        if self.work > MAX_WORK {
            return Err("DWARF cumulative graph work limit exceeded".into());
        }
        Ok(())
    }
    fn edge(&mut self) -> Result<(), String> {
        self.edges += 1;
        if self.edges > MAX_EDGES {
            return Err("DWARF cumulative edge limit exceeded".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Node {
    id: DebugLayoutTypeId,
    tag: gimli::DwTag,
    parent: Option<usize>,
    children: Vec<usize>,
    source: Option<DebugLayoutSource>,
    name: Option<String>,
    linkage_name: Option<String>,
    target: TypeRef,
    specification: TypeRef,
    object_pointer: TypeRef,
    size: Option<u64>,
    alignment: Option<u64>,
    encoding: Option<gimli::DwAte>,
    offset: Option<u64>,
    bit_size: Option<u64>,
    data_bit_offset: Option<u64>,
    bit_offset: Option<u64>,
    bit_attributes: bool,
    count: Option<u64>,
    lower: Option<i64>,
    lower_present: bool,
    upper: Option<i64>,
    stride: Option<u64>,
    stride_present: bool,
    value: Option<DebugProducerConstant>,
    address: Option<u64>,
    calling: Option<gimli::DwCc>,
    prototyped: bool,
    prototyped_attribute: Option<bool>,
    prototyped_present: bool,
    artificial: bool,
    declaration: bool,
    reasons: Vec<String>,
}

impl Node {
    fn new(id: DebugLayoutTypeId, tag: gimli::DwTag) -> Self {
        Self {
            id,
            tag,
            parent: None,
            children: Vec::new(),
            source: None,
            name: None,
            linkage_name: None,
            target: TypeRef::Absent,
            specification: TypeRef::Absent,
            object_pointer: TypeRef::Absent,
            size: None,
            alignment: None,
            encoding: None,
            offset: None,
            bit_size: None,
            data_bit_offset: None,
            bit_offset: None,
            bit_attributes: false,
            count: None,
            lower: None,
            lower_present: false,
            upper: None,
            stride: None,
            stride_present: false,
            value: None,
            address: None,
            calling: None,
            prototyped: false,
            prototyped_attribute: None,
            prototyped_present: false,
            artificial: false,
            declaration: false,
            reasons: Vec::new(),
        }
    }
    fn reject(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
    fn bitfield(&self) -> bool {
        self.bit_attributes || self.bit_size.is_some() || self.data_bit_offset.is_some() || self.bit_offset.is_some()
    }
}

fn type_tag(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_base_type
            | gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_array_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
            | gimli::DW_TAG_subroutine_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_ptr_to_member_type
            | gimli::DW_TAG_unspecified_type
            | gimli::DW_TAG_string_type
            | gimli::DW_TAG_set_type
            | gimli::DW_TAG_packed_type
            | gimli::DW_TAG_interface_type
            | gimli::DW_TAG_file_type
            | gimli::DW_TAG_template_type_parameter
            | gimli::DW_TAG_thrown_type
            | gimli::DW_TAG_shared_type
            | gimli::DW_TAG_template_alias
            | gimli::DW_TAG_coarray_type
            | gimli::DW_TAG_dynamic_type
            | gimli::DW_TAG_immutable_type
            | gimli::DW_TAG_HP_array_descriptor
            | gimli::DW_TAG_class_template
            | gimli::DW_TAG_GNU_template_template_param
            | gimli::DW_TAG_SUN_class_template
            | gimli::DW_TAG_SUN_struct_template
            | gimli::DW_TAG_SUN_union_template
    )
}

fn language(language: gimli::DwLang) -> bool {
    matches!(
        language,
        gimli::DW_LANG_C89
            | gimli::DW_LANG_C
            | gimli::DW_LANG_C99
            | gimli::DW_LANG_C11
            | gimli::DW_LANG_C17
            | gimli::DW_LANG_C_plus_plus
            | gimli::DW_LANG_C_plus_plus_11
            | gimli::DW_LANG_C_plus_plus_14
            | gimli::DW_LANG_C_plus_plus_17
    )
}

fn unsigned(value: AttributeValue<DebugReader<'_>>) -> Option<u64> {
    match value {
        AttributeValue::Data1(n) => Some(n.into()),
        AttributeValue::Data2(n) => Some(n.into()),
        AttributeValue::Data4(n) => Some(n.into()),
        AttributeValue::Data8(n) | AttributeValue::Udata(n) => Some(n),
        AttributeValue::Sdata(n) => u64::try_from(n).ok(),
        _ => None,
    }
}

fn integer(value: AttributeValue<DebugReader<'_>>, form: gimli::DwForm) -> Option<DebugProducerConstant> {
    let byte_width = match form {
        gimli::DW_FORM_data1 => Some(1),
        gimli::DW_FORM_data2 => Some(2),
        gimli::DW_FORM_data4 => Some(4),
        gimli::DW_FORM_data8 => Some(8),
        _ => None,
    };
    let value = match value {
        AttributeValue::Sdata(n) => DebugProducerInteger::Signed(n),
        value => DebugProducerInteger::Unsigned(unsigned(value)?),
    };
    Some(DebugProducerConstant { form: form.0, byte_width, value })
}

fn enum_constant(raw: DebugProducerConstant, signed: bool) -> Option<DebugProducerInteger> {
    match (raw.value, raw.byte_width, signed) {
        (DebugProducerInteger::Unsigned(value), Some(width), true) => {
            let value = match width {
                1 => i64::from(value as i8),
                2 => i64::from(value as i16),
                4 => i64::from(value as i32),
                8 => value as i64,
                _ => return None,
            };
            Some(DebugProducerInteger::Signed(value))
        }
        (DebugProducerInteger::Unsigned(value), None, true) => {
            i64::try_from(value).ok().map(DebugProducerInteger::Signed)
        }
        (DebugProducerInteger::Signed(value), _, false) => {
            u64::try_from(value).ok().map(DebugProducerInteger::Unsigned)
        }
        (value, _, _) => Some(value),
    }
}

fn signed(value: AttributeValue<DebugReader<'_>>) -> Option<i64> {
    match value {
        AttributeValue::Sdata(n) => Some(n),
        value => unsigned(value).and_then(|n| i64::try_from(n).ok()),
    }
}

fn member_offset(value: AttributeValue<DebugReader<'_>>) -> Option<u64> {
    let AttributeValue::Exprloc(expression) = value else {
        return unsigned(value);
    };
    let mut bytes = expression.0;
    if bytes.len() > 12 {
        return None;
    }
    let op = bytes.read_u8().ok()?;
    let offset = if op == gimli::DW_OP_plus_uconst.0 || op == gimli::DW_OP_constu.0 {
        bytes.read_uleb128().ok()?
    } else if (gimli::DW_OP_lit0.0..=gimli::DW_OP_lit31.0).contains(&op) {
        u64::from(op - gimli::DW_OP_lit0.0)
    } else {
        return None;
    };
    if op != gimli::DW_OP_plus_uconst.0 && bytes.read_u8().ok()? != gimli::DW_OP_plus.0 {
        return None;
    }
    bytes.is_empty().then_some(offset)
}

fn read_nodes(dwarf: &Dwarf<DebugReader<'_>>, budget: &mut Budget) -> Result<BTreeMap<usize, Node>, String> {
    budget.reserve(dwarf.debug_info.reader().len().checked_mul(3).ok_or("DWARF read-work size overflow")?)?;
    let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
    let mut units = dwarf.units();
    let mut unit_count = 0;
    let mut types = 0;
    let mut records = 0;
    let mut fields = 0;
    let mut functions = 0;
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        unit_count += 1;
        if unit_count > MAX_UNITS {
            return Err("DWARF unit limit exceeded".into());
        }
        if header.type_() != gimli::UnitType::Compilation
            || !matches!(header.version(), 4 | 5)
            || header.address_size() != 8
        {
            return Err("graph requires DWARF4/5 address-size-8 compilation units".into());
        }
        let unit_offset = header.offset().to_debug_info_offset(&header).ok_or("unit outside .debug_info")?.0;
        let abbrev_offset = header.debug_abbrev_offset();
        let suffix = dwarf
            .debug_abbrev
            .reader()
            .len()
            .checked_sub(abbrev_offset.0)
            .ok_or("DWARF abbreviation offset outside section")?;
        // signature_unit performs validation and allocation again: reserve every pass, even shared tables.
        budget.reserve(suffix.checked_mul(3).ok_or("DWARF abbreviation work overflow")?)?;
        validate_abbreviations_work(dwarf, abbrev_offset, &mut budget.work, MAX_WORK, true)
            .map_err(|error| format!("DWARF abbreviation bounds: {error}"))?;
        let unit = signature_unit(dwarf, header)?;
        let mut strings_base = false;
        let mut addresses_base = false;
        let mut source = None;
        let mut entries = unit.header.entries_raw(&unit.abbreviations, None).map_err(|e| e.to_string())?;
        let mut parents = Vec::new();
        while !entries.is_empty() {
            budget.work()?;
            let depth = entries.next_depth();
            let relative = entries.next_offset();
            let Some(abbreviation) = entries.read_abbreviation().map_err(|e| e.to_string())? else {
                if depth <= 0 {
                    return Err("unbalanced DWARF DIE terminator".into());
                }
                continue;
            };
            if nodes.len() >= MAX_NODES {
                return Err("DWARF graph node limit exceeded".into());
            }
            if depth < 0 || depth as usize > MAX_NESTING || depth as usize > parents.len() {
                return Err("DWARF DIE nesting or parent-depth limit exceeded".into());
            }
            if depth == 0 && !parents.is_empty() {
                return Err("multiple DWARF unit roots".into());
            }
            let tag = abbreviation.tag();
            if depth == 0 && tag != gimli::DW_TAG_compile_unit {
                return Err("invalid DWARF unit root".into());
            }
            parents.truncate(depth as usize);
            let offset = relative.to_debug_info_offset(&unit.header).ok_or("DIE outside .debug_info")?.0;
            let mut node =
                Node::new(DebugLayoutTypeId { unit_offset: unit_offset as u64, die_offset: offset as u64 }, tag);
            node.parent = parents.last().copied();
            node.source = source.clone();
            types += usize::from(type_tag(tag));
            records += usize::from(matches!(
                tag,
                gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
            ));
            fields += usize::from(matches!(
                tag,
                gimli::DW_TAG_member | gimli::DW_TAG_formal_parameter | gimli::DW_TAG_enumerator
            ));
            functions += usize::from(tag == gimli::DW_TAG_subprogram);
            if types > MAX_TYPES || records > MAX_LAYOUTS || fields > MAX_TOTAL_FIELDS || functions > MAX_FUNCTIONS {
                return Err("DWARF cumulative type/record/member/function limit exceeded".into());
            }
            let mut seen = BTreeSet::new();
            for spec in abbreviation.attributes() {
                budget.work()?;
                if seen.len() >= MAX_ATTRIBUTES {
                    return Err("DWARF attribute limit exceeded".into());
                }
                let attr = entries.read_attribute(*spec).map_err(|e| e.to_string())?;
                if !seen.insert(attr.name()) {
                    return Err(format!("duplicate DWARF attribute {}", attr.name()));
                }
                let value = attr.value();
                match attr.name() {
                    gimli::DW_AT_str_offsets_base if depth == 0 => {
                        if unit.header.version() < 5 || attr.form() != gimli::DW_FORM_sec_offset {
                            return Err("malformed DWARF string-offset base".into());
                        }
                        strings_base = matches!(value, AttributeValue::DebugStrOffsetsBase(_));
                        if !strings_base {
                            return Err("invalid DWARF string-offset base".into());
                        }
                    }
                    gimli::DW_AT_addr_base | gimli::DW_AT_GNU_addr_base if depth == 0 => {
                        if addresses_base || attr.form() != gimli::DW_FORM_sec_offset {
                            return Err("duplicate or malformed DWARF address base".into());
                        }
                        addresses_base = matches!(value, AttributeValue::DebugAddrBase(_));
                        if !addresses_base {
                            return Err("invalid DWARF address base".into());
                        }
                    }
                    gimli::DW_AT_language if depth == 0 => {
                        if let AttributeValue::Language(lang) = value
                            && language(lang)
                        {
                            source = Some(DebugLayoutSource {
                                unit_offset: unit_offset as u64,
                                language: lang.0,
                                dwarf_version: unit.header.version(),
                                address_size: 8,
                            });
                        }
                    }
                    gimli::DW_AT_name | gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name
                        if tag == gimli::DW_TAG_subprogram
                            || (attr.name() == gimli::DW_AT_name
                                && (type_tag(tag)
                                    || matches!(
                                        tag,
                                        gimli::DW_TAG_member
                                            | gimli::DW_TAG_formal_parameter
                                            | gimli::DW_TAG_enumerator
                                    ))) =>
                    {
                        if matches!(value, AttributeValue::DebugStrOffsetsIndex(_)) && !strings_base {
                            return Err("indexed DWARF name has no verified string-offset base".into());
                        }
                        budget.reserve(4 * (MAX_NAME + 1) + 64)?;
                        let name = bounded_name_limit(dwarf, &unit, value, MAX_NAME).map_err(|e| e.to_string())?;
                        if name.len() > MAX_NAME {
                            return Err("DWARF producer name exceeds 128 bytes".into());
                        }
                        let bytes = name.to_slice().map_err(|e| e.to_string())?;
                        budget.names += bytes.len();
                        if budget.names > MAX_NAMES {
                            return Err("DWARF retained-name limit exceeded".into());
                        }
                        let name = std::str::from_utf8(&bytes).map_err(|_| "non-UTF8 DWARF name")?.to_owned();
                        if attr.name() == gimli::DW_AT_name {
                            node.name = Some(name);
                        } else if node.linkage_name.as_ref().is_some_and(|previous| previous != &name) {
                            node.reject("conflicting producer linkage names");
                        } else {
                            node.linkage_name = Some(name);
                        }
                    }
                    gimli::DW_AT_type | gimli::DW_AT_specification | gimli::DW_AT_object_pointer => {
                        budget.edge()?;
                        let reference = match value {
                            AttributeValue::UnitRef(r) if r.is_in_bounds(&unit.header) => {
                                TypeRef::Offset(r.to_debug_info_offset(&unit.header).ok_or("invalid UnitRef")?.0)
                            }
                            AttributeValue::DebugInfoRef(r) => TypeRef::Offset(r.0),
                            _ => TypeRef::Unsupported,
                        };
                        match attr.name() {
                            gimli::DW_AT_type => node.target = reference,
                            gimli::DW_AT_specification => node.specification = reference,
                            _ => node.object_pointer = reference,
                        }
                    }
                    gimli::DW_AT_byte_size
                    | gimli::DW_AT_alignment
                    | gimli::DW_AT_bit_size
                    | gimli::DW_AT_data_bit_offset
                    | gimli::DW_AT_bit_offset
                    | gimli::DW_AT_count
                    | gimli::DW_AT_byte_stride => {
                        node.bit_attributes |= matches!(
                            attr.name(),
                            gimli::DW_AT_bit_size | gimli::DW_AT_data_bit_offset | gimli::DW_AT_bit_offset
                        );
                        let number = unsigned(value);
                        if number.is_none() {
                            node.reject(format!("nonconstant {}", attr.name()));
                        }
                        match attr.name() {
                            gimli::DW_AT_byte_size => node.size = number,
                            gimli::DW_AT_alignment => node.alignment = number,
                            gimli::DW_AT_bit_size => node.bit_size = number,
                            gimli::DW_AT_data_bit_offset => node.data_bit_offset = number,
                            gimli::DW_AT_bit_offset => node.bit_offset = number,
                            gimli::DW_AT_count => node.count = number,
                            _ => {
                                if node.stride_present {
                                    node.reject("conflicting array stride attributes");
                                }
                                node.stride_present = true;
                                node.stride = number;
                            }
                        }
                    }
                    gimli::DW_AT_bit_stride => {
                        let stride = unsigned(value).filter(|n| n % 8 == 0).map(|n| n / 8);
                        if stride.is_none() || node.stride_present {
                            node.reject("unsupported/conflicting bit stride");
                        }
                        node.stride_present = true;
                        node.stride = stride;
                    }
                    gimli::DW_AT_lower_bound | gimli::DW_AT_upper_bound => {
                        let bound = signed(value);
                        if bound.is_none() {
                            node.reject("nonconstant or out-of-range array bound");
                        }
                        if attr.name() == gimli::DW_AT_lower_bound {
                            node.lower_present = true;
                            node.lower = bound;
                        } else {
                            node.upper = bound;
                        }
                    }
                    gimli::DW_AT_const_value => {
                        node.value = integer(value, attr.form());
                        if node.value.is_none() {
                            node.reject("nonconstant enum value");
                        }
                    }
                    gimli::DW_AT_data_member_location => {
                        node.offset = member_offset(value);
                        if node.offset.is_none() {
                            node.reject("runtime or unsupported DWARF member offset expression");
                        }
                    }
                    gimli::DW_AT_encoding => {
                        if let AttributeValue::Encoding(encoding) = value {
                            node.encoding = Some(encoding);
                        } else {
                            node.reject("invalid scalar encoding");
                        }
                    }
                    gimli::DW_AT_low_pc if tag == gimli::DW_TAG_subprogram => {
                        if matches!(value, AttributeValue::DebugAddrIndex(_)) && !addresses_base {
                            return Err("indexed DWARF address has no verified address base".into());
                        }
                        budget.reserve(64)?;
                        node.address = dwarf.attr_address(&unit, value).map_err(|e| e.to_string())?;
                        if node.address.is_none() {
                            node.reject("invalid function entry address");
                        }
                    }
                    gimli::DW_AT_calling_convention => {
                        if let AttributeValue::CallingConvention(cc) = value {
                            node.calling = Some(cc);
                        } else {
                            node.reject("invalid calling convention");
                        }
                    }
                    gimli::DW_AT_prototyped | gimli::DW_AT_artificial | gimli::DW_AT_declaration => {
                        node.prototyped_present |= attr.name() == gimli::DW_AT_prototyped;
                        if let AttributeValue::Flag(flag) = value {
                            match attr.name() {
                                gimli::DW_AT_prototyped => {
                                    node.prototyped = flag;
                                    node.prototyped_attribute = Some(flag);
                                }
                                gimli::DW_AT_artificial => node.artificial = flag,
                                _ => node.declaration = flag,
                            }
                        } else {
                            node.reject("invalid flag attribute");
                        }
                    }
                    gimli::DW_AT_address_class => {
                        if !matches!(value, AttributeValue::AddressClass(gimli::DW_ADDR_none)) {
                            node.reject("non-default address class");
                        }
                    }
                    gimli::DW_AT_ordering => {
                        if !matches!(value, AttributeValue::Ordering(gimli::DW_ORD_row_major)) {
                            node.reject("non-row-major or malformed array ordering");
                        }
                    }
                    gimli::DW_AT_endianity => {
                        if !matches!(value, AttributeValue::Endianity(gimli::DW_END_default | gimli::DW_END_little)) {
                            node.reject("non-native scalar endianity");
                        }
                    }
                    gimli::DW_AT_virtuality
                    | gimli::DW_AT_vtable_elem_location
                    | gimli::DW_AT_containing_type
                    | gimli::DW_AT_abstract_origin
                    | gimli::DW_AT_signature
                    | gimli::DW_AT_allocated
                    | gimli::DW_AT_associated
                    | gimli::DW_AT_data_location
                    | gimli::DW_AT_rank => {
                        node.reject(format!("unsupported producer ABI/dynamic attribute {}", attr.name()));
                    }
                    _ if relevant_tag(tag) && !metadata_attribute(tag, attr.name()) => {
                        node.reject(format!("unsupported producer attribute {}", attr.name()));
                    }
                    _ => {}
                }
            }
            if node.alignment.is_some_and(|n| n == 0 || !n.is_power_of_two() || n > MAX_SIZE) {
                node.reject("invalid producer alignment");
            }
            if node.size.is_some_and(|n| n > MAX_SIZE) {
                node.reject("producer byte size exceeds limit");
            }
            if let Some(parent) = node.parent {
                budget.edge()?;
                let parent = nodes.get_mut(&parent).ok_or("missing DWARF parent")?;
                let limit = if parent.tag == gimli::DW_TAG_compile_unit { MAX_TOTAL_FIELDS } else { MAX_FIELDS };
                if parent.children.len() >= limit {
                    return Err("DWARF parent child limit exceeded".into());
                }
                parent.children.push(offset);
            }
            parents.push(offset);
            if nodes.insert(offset, node).is_some() {
                return Err("duplicate DWARF DIE identity".into());
            }
        }
        if entries.next_depth() != 0 {
            return Err("unterminated DWARF DIE children".into());
        }
    }
    Ok(nodes)
}

fn relevant_tag(tag: gimli::DwTag) -> bool {
    type_tag(tag)
        || matches!(
            tag,
            gimli::DW_TAG_member
                | gimli::DW_TAG_subprogram
                | gimli::DW_TAG_formal_parameter
                | gimli::DW_TAG_enumerator
                | gimli::DW_TAG_subrange_type
        )
}

fn metadata_attribute(tag: gimli::DwTag, attribute: gimli::DwAt) -> bool {
    matches!(
        attribute,
        gimli::DW_AT_decl_file
            | gimli::DW_AT_decl_line
            | gimli::DW_AT_decl_column
            | gimli::DW_AT_sibling
            | gimli::DW_AT_accessibility
            | gimli::DW_AT_external
            | gimli::DW_AT_linkage_name
            | gimli::DW_AT_MIPS_linkage_name
            | gimli::DW_AT_enum_class
    ) || (tag == gimli::DW_TAG_formal_parameter && attribute == gimli::DW_AT_location)
        || (tag == gimli::DW_TAG_subprogram
            && matches!(
                attribute,
                gimli::DW_AT_high_pc
                    | gimli::DW_AT_frame_base
                    | gimli::DW_AT_inline
                    | gimli::DW_AT_call_all_calls
                    | gimli::DW_AT_call_all_tail_calls
                    | gimli::DW_AT_call_all_source_calls
                    | gimli::DW_AT_GNU_all_call_sites
                    | gimli::DW_AT_GNU_all_tail_call_sites
            ))
}

fn reference(reference: TypeRef, nodes: &BTreeMap<usize, Node>) -> Option<DebugLayoutTypeId> {
    match reference {
        TypeRef::Offset(offset) => nodes.get(&offset).map(|node| node.id),
        _ => None,
    }
}

fn emitted(id: DebugLayoutTypeId) -> String {
    format!("dwarf_u{:x}_d{:x}", id.unit_offset, id.die_offset)
}

fn prototype_basis(node: &Node) -> Option<DebugProducerPrototypeBasis> {
    match node.prototyped_attribute {
        Some(false) => None,
        Some(true) => Some(DebugProducerPrototypeBasis::ExplicitAttribute),
        None if node.prototyped_present => None,
        None if node.prototyped => Some(DebugProducerPrototypeBasis::ExplicitAttribute),
        None => node
            .source
            .as_ref()
            .filter(|source| source.is_cpp())
            .map(|source| DebugProducerPrototypeBasis::CppLanguage { language: source.language }),
    }
}

fn prototype(node: &Node, nodes: &BTreeMap<usize, Node>) -> DebugProducerPrototype {
    let parameters = node
        .children
        .iter()
        .filter_map(|child| {
            let child = &nodes[child];
            (child.tag == gimli::DW_TAG_formal_parameter).then(|| DebugProducerParameter {
                id: child.id,
                original_name: child.name.clone(),
                ty: reference(child.target, nodes),
                artificial: child.artificial,
            })
        })
        .collect();
    DebugProducerPrototype {
        return_type: reference(node.target, nodes),
        return_type_absent: matches!(node.target, TypeRef::Absent),
        parameters,
        variadic: node.children.iter().any(|child| nodes[child].tag == gimli::DW_TAG_unspecified_parameters),
        prototyped: prototype_basis(node).is_some(),
        producer_prototyped: node.prototyped_attribute,
        producer_prototyped_present: node.prototyped_present,
        prototype_basis: prototype_basis(node),
        calling_convention: Some(node.calling.unwrap_or(gimli::DW_CC_normal).0),
        calling_convention_explicit: node.calling.is_some(),
        object_pointer: reference(node.object_pointer, nodes),
        declaration_id: reference(node.specification, nodes),
        record_id: declaring_record(node, nodes).map(|record| record.id),
    }
}

fn scalar_kind(encoding: Option<gimli::DwAte>) -> Option<(DebugProducerScalarKind, Option<bool>)> {
    match encoding? {
        gimli::DW_ATE_signed | gimli::DW_ATE_signed_char => Some((DebugProducerScalarKind::Integer, Some(true))),
        gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char => Some((DebugProducerScalarKind::Integer, Some(false))),
        gimli::DW_ATE_float => Some((DebugProducerScalarKind::Float, None)),
        gimli::DW_ATE_boolean => Some((DebugProducerScalarKind::Boolean, None)),
        _ => None,
    }
}

struct Graph<'a> {
    nodes: &'a BTreeMap<usize, Node>,
    active: BTreeSet<usize>,
    work: usize,
}

struct ArrayLayout {
    dimensions: Vec<DebugProducerDimension>,
    occupied_byte_size: u64,
    byte_size: Option<u64>,
    native_contiguous: bool,
}

fn dimension(node: &Node, c_default_lower: bool) -> DebugProducerDimension {
    let lower = node.lower.or((c_default_lower && !node.lower_present).then_some(0));
    let derived_count = lower
        .zip(node.upper)
        .and_then(|(lower, upper)| upper.checked_sub(lower))
        .and_then(|difference| difference.checked_add(1))
        .and_then(|count| u64::try_from(count).ok());
    DebugProducerDimension {
        id: node.id,
        lower_bound: lower,
        lower_bound_present: node.lower_present || node.lower.is_some(),
        raw_upper_bound: node.upper,
        count: node.count.or(derived_count),
        byte_stride: node.stride,
        stride_present: node.stride_present || node.stride.is_some(),
        unsupported_reasons: node.reasons.clone(),
    }
}

impl<'a> Graph<'a> {
    fn new(nodes: &'a BTreeMap<usize, Node>) -> Self {
        Self { nodes, active: BTreeSet::new(), work: 0 }
    }
    fn charge(&mut self, depth: usize) -> Result<(), String> {
        self.work += 1;
        if self.work > MAX_WORK {
            return Err("DWARF cumulative graph resolution work limit exceeded".into());
        }
        if depth >= MAX_TYPE_DEPTH {
            return Err("DWARF graph depth limit exceeded".into());
        }
        Ok(())
    }
    fn target(&mut self, target: TypeRef, depth: usize) -> Result<Option<u64>, String> {
        let TypeRef::Offset(offset) = target else {
            return Err("missing or unsupported type reference".into());
        };
        self.size(offset, depth)
    }
    fn size(&mut self, offset: usize, depth: usize) -> Result<Option<u64>, String> {
        self.charge(depth)?;
        // Do not cache context-sensitive depth failures: every path must fit the same depth limit.
        if !self.active.insert(offset) {
            return Err("by-value or alias DWARF cycle".into());
        }
        let result = self.size_inner(offset, depth);
        self.active.remove(&offset);
        result
    }
    fn size_inner(&mut self, offset: usize, depth: usize) -> Result<Option<u64>, String> {
        let node = self.nodes.get(&offset).ok_or("unresolved absolute DIE reference")?;
        if let Some(reason) = node.reasons.first() {
            return Err(reason.clone());
        }
        if node.source.is_none() {
            return Err("no verified C/C++ compilation-unit language".into());
        }
        if node.declaration {
            return Err("declaration-only type has no complete producer definition".into());
        }
        let size = match node.tag {
            gimli::DW_TAG_base_type => {
                let (kind, _) = scalar_kind(node.encoding).ok_or("unsupported scalar encoding")?;
                let size = node.size.ok_or("scalar has no exact byte size")?;
                if !match kind {
                    DebugProducerScalarKind::Integer => matches!(size, 1 | 2 | 4 | 8),
                    DebugProducerScalarKind::Float => matches!(size, 4 | 8),
                    DebugProducerScalarKind::Boolean => size == 1,
                } {
                    return Err("scalar width requires unsupported native representation".into());
                }
                if node.bitfield() {
                    return Err("bit-sized scalar requires unsupported native representation".into());
                }
                Some(size)
            }
            gimli::DW_TAG_pointer_type => {
                // DWARF's CU address_size is the producer's default pointer width, not the host's.
                if node.size.is_some_and(|n| n != 8) {
                    return Err("pointer width differs from CU address_size".into());
                }
                if !matches!(node.target, TypeRef::Absent) && reference(node.target, self.nodes).is_none() {
                    return Err("unresolved pointer target".into());
                }
                Some(8)
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => {
                let size = self.target(node.target, depth + 1)?;
                if node.size.is_some() && node.size != size {
                    return Err("alias/qualifier size conflicts with target".into());
                }
                size
            }
            gimli::DW_TAG_array_type => {
                let layout = self.array(node, depth + 1)?;
                if !layout.native_contiguous {
                    return Err("strided or padded producer array cannot be represented as a native C array".into());
                }
                layout.byte_size
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                let size = node.size.ok_or("record has no complete producer byte size")?;
                if size == 0 {
                    return Err("zero-size native aggregate unsupported".into());
                }
                let mut ranges = Vec::new();
                for &child_offset in &node.children {
                    self.charge(depth)?;
                    let child = &self.nodes[&child_offset];
                    if child.tag == gimli::DW_TAG_member {
                        if let Some(reason) = child.reasons.first() {
                            return Err(reason.clone());
                        }
                        if child.declaration {
                            return Err("declaration-only/static member ABI unsupported".into());
                        }
                        if child.bitfield() {
                            return Err("native bitfield import unsupported; raw member evidence retained".into());
                        }
                        let start = if node.tag == gimli::DW_TAG_union_type {
                            child.offset.unwrap_or(0)
                        } else {
                            child.offset.ok_or("member has no exact constant byte offset")?
                        };
                        if node.tag == gimli::DW_TAG_union_type && start != 0 {
                            return Err("union member has nonzero byte offset".into());
                        }
                        let width = self.target(child.target, depth + 1)?.ok_or("member type has no object size")?;
                        if child.size.is_some_and(|n| n != width) {
                            return Err("member storage size conflicts with type".into());
                        }
                        let end = start
                            .checked_add(width)
                            .filter(|&end| end <= size)
                            .ok_or("member extent overflows complete record")?;
                        if node.tag != gimli::DW_TAG_union_type {
                            if ranges.iter().any(|&(lo, hi)| start < hi && lo < end) {
                                return Err("overlapping non-union member layout".into());
                            }
                            ranges.push((start, end));
                        }
                    } else if child.tag == gimli::DW_TAG_subprogram {
                        if child.reasons.iter().any(|reason| reason.contains("ABI/dynamic")) {
                            return Err("record has unsupported virtual/member-function ABI evidence".into());
                        }
                    } else if type_tag(child.tag) {
                        // Nested declarations and ordinary methods do not contribute object storage.
                    } else {
                        return Err(format!(
                            "unsupported record child {} (inheritance/virtual ABI not recovered)",
                            child.tag
                        ));
                    }
                }
                Some(size)
            }
            gimli::DW_TAG_enumeration_type => {
                let (size, signed) = self.enum_facts(node, depth + 1)?;
                for &child in &node.children {
                    let child = &self.nodes[&child];
                    if child.tag != gimli::DW_TAG_enumerator || child.value.is_none() || !child.reasons.is_empty() {
                        return Err("incomplete or unsupported enum enumerator".into());
                    }
                    let bits = size * 8;
                    let value =
                        match enum_constant(child.value.unwrap(), signed).ok_or("invalid enum constant width")? {
                            DebugProducerInteger::Signed(value) => i128::from(value),
                            DebugProducerInteger::Unsigned(value) => i128::from(value),
                        };
                    let (min, max) = if signed {
                        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
                    } else {
                        (0, (1i128 << bits) - 1)
                    };
                    if value < min || value > max {
                        return Err("enum value exceeds exact underlying integer range".into());
                    }
                }
                Some(size)
            }
            gimli::DW_TAG_subroutine_type => {
                self.check_prototype(node, depth + 1)?;
                None
            }
            _ => return Err(format!("unsupported producer type {}", node.tag)),
        };
        if size.is_some_and(|n| n > MAX_SIZE) {
            return Err("producer object size exceeds limit".into());
        }
        Ok(size)
    }
    fn enum_facts(&mut self, node: &Node, depth: usize) -> Result<(u64, bool), String> {
        self.charge(depth)?;
        let (size, signed) = if matches!(node.target, TypeRef::Absent) {
            let Some((DebugProducerScalarKind::Integer, Some(signed))) = scalar_kind(node.encoding) else {
                return Err("enum lacks exact integer underlying producer encoding/type".into());
            };
            (node.size.ok_or("enum has no exact byte size")?, signed)
        } else {
            let (size, signed) = self.integer_facts(node.target, depth + 1)?;
            self.target(node.target, depth + 1)?;
            if node.size.is_some_and(|n| n != size) {
                return Err("enum size conflicts with underlying".into());
            }
            if node.encoding.is_some()
                && scalar_kind(node.encoding) != Some((DebugProducerScalarKind::Integer, Some(signed)))
            {
                return Err("enum encoding conflicts with exact underlying type".into());
            }
            (size, signed)
        };
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err("unsupported enum underlying width".into());
        }
        Ok((size, signed))
    }
    fn integer_facts(&mut self, target: TypeRef, depth: usize) -> Result<(u64, bool), String> {
        self.charge(depth)?;
        let TypeRef::Offset(offset) = target else {
            return Err("missing enum underlying".into());
        };
        let node = self.nodes.get(&offset).ok_or("unresolved enum underlying")?;
        match node.tag {
            gimli::DW_TAG_base_type => {
                let Some((DebugProducerScalarKind::Integer, Some(signed))) = scalar_kind(node.encoding) else {
                    return Err("enum underlying is not an exact integer".into());
                };
                Ok((node.size.ok_or("enum underlying has no width")?, signed))
            }
            gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
                self.integer_facts(node.target, depth + 1)
            }
            _ => Err("enum underlying is not integer".into()),
        }
    }
    fn array(&mut self, node: &Node, depth: usize) -> Result<ArrayLayout, String> {
        if let Some(reason) = node.reasons.first() {
            return Err(reason.clone());
        }
        if node.source.is_none() {
            return Err("array has no verified C/C++ compilation-unit language".into());
        }
        if node.stride_present && node.stride.is_none() {
            return Err("present array stride has no exact constant value".into());
        }
        let mut width = self.target(node.target, depth + 1)?.ok_or("array element has no object size")?;
        let mut dimensions = Vec::new();
        for &child in &node.children {
            self.charge(depth)?;
            let child = &self.nodes[&child];
            if child.tag != gimli::DW_TAG_subrange_type || !child.reasons.is_empty() {
                return Err("unsupported or malformed array dimension".into());
            }
            // Only C/C++ units reach here, whose absent lower bound means zero under DWARF.
            let lower = dimension(child, true).lower_bound.ok_or("present array lower bound is unknown")?;
            if child.stride_present && child.stride.is_none() {
                return Err("present subrange stride has no exact constant value".into());
            }
            let upper_count = child
                .upper
                .and_then(|upper| upper.checked_sub(lower))
                .and_then(|difference| difference.checked_add(1))
                .and_then(|count| u64::try_from(count).ok());
            let count = child.count.or(upper_count).ok_or("array has no exact count (flexible/dynamic array)")?;
            if child.count.is_some() && child.upper.is_some() && upper_count != Some(count) {
                return Err("conflicting array count and bounds".into());
            }
            if count == 0 || lower != 0 {
                return Err("zero-count/nonzero-lower-bound C array unsupported".into());
            }
            dimensions.push(DebugProducerDimension {
                id: child.id,
                lower_bound: Some(lower),
                lower_bound_present: child.lower_present || child.lower.is_some(),
                raw_upper_bound: child.upper,
                count: Some(count),
                byte_stride: child.stride,
                stride_present: child.stride_present || child.stride.is_some(),
                unsupported_reasons: child.reasons.clone(),
            });
        }
        if dimensions.is_empty() {
            return Err("array has no exact subrange count".into());
        }
        if node.stride.is_some() && dimensions.len() != 1 {
            return Err("ambiguous multidimensional array stride".into());
        }
        let mut native_contiguous = true;
        for dimension in dimensions.iter_mut().rev() {
            if dimension.byte_stride.zip(node.stride).is_some_and(|(subrange, array)| subrange != array) {
                return Err("conflicting explicit array and subrange byte strides".into());
            }
            if !native_contiguous && dimension.byte_stride.or(node.stride).is_none() {
                return Err("outer array stride is unknown for a strided inner dimension".into());
            }
            let stride = dimension.byte_stride.or(node.stride).unwrap_or(width);
            if stride < width || stride == 0 {
                return Err("array stride is missing/overlapping/zero".into());
            }
            native_contiguous &= stride == width;
            dimension.byte_stride = Some(stride);
            width = dimension
                .count
                .unwrap()
                .checked_sub(1)
                .and_then(|count| stride.checked_mul(count))
                .and_then(|prefix| prefix.checked_add(width))
                .filter(|&n| n <= MAX_SIZE)
                .ok_or("array count/stride overflow or size limit")?;
        }
        if node.size.is_some_and(|size| size < width || size > MAX_SIZE) {
            return Err("array allocation is smaller than occupied extent or exceeds size limit".into());
        }
        let byte_size = node.size.or(native_contiguous.then_some(width));
        native_contiguous &= byte_size == Some(width);
        Ok(ArrayLayout { dimensions, occupied_byte_size: width, byte_size, native_contiguous })
    }
    fn signature_value(&mut self, target: TypeRef, depth: usize) -> Result<(), String> {
        self.charge(depth)?;
        let TypeRef::Offset(offset) = target else {
            return Err("missing signature value type".into());
        };
        let node = self.nodes.get(&offset).ok_or("unresolved signature value type")?;
        match node.tag {
            gimli::DW_TAG_base_type | gimli::DW_TAG_pointer_type | gimli::DW_TAG_enumeration_type => {
                self.size(offset, depth + 1)?;
                Ok(())
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => self.signature_value(node.target, depth + 1),
            _ => Err("aggregate-by-value/member-function ABI signature unsupported".into()),
        }
    }
    fn check_prototype(&mut self, node: &Node, depth: usize) -> Result<(), String> {
        self.charge(depth)?;
        if !node.reasons.is_empty() {
            return Err(node.reasons[0].clone());
        }
        if prototype_basis(node).is_none() {
            return Err("function lacks explicit complete producer prototype".into());
        }
        if node.calling.is_some_and(|cc| cc != gimli::DW_CC_normal) {
            return Err("non-normal producer calling convention lacks verified native counterpart".into());
        }
        if let Some(record) = declaring_record(node, self.nodes) {
            validate_method_this(node, record, self.nodes)?;
        }
        if !matches!(node.target, TypeRef::Absent) {
            self.signature_value(node.target, depth + 1)?;
        }
        let mut variadic = false;
        let mut parameters = 0;
        for &child in &node.children {
            let child = &self.nodes[&child];
            match child.tag {
                gimli::DW_TAG_formal_parameter if !variadic => {
                    if !child.reasons.is_empty() {
                        return Err("unsupported parameter attributes".into());
                    }
                    self.signature_value(child.target, depth + 1)?;
                    parameters += 1;
                }
                gimli::DW_TAG_unspecified_parameters if !variadic && parameters > 0 => variadic = true,
                gimli::DW_TAG_formal_parameter | gimli::DW_TAG_unspecified_parameters => {
                    return Err("malformed formal/variadic parameter ordering".into());
                }
                _ if node.tag == gimli::DW_TAG_subprogram => {}
                _ => return Err("unsupported function-type child".into()),
            }
        }
        if !matches!(node.object_pointer, TypeRef::Absent) {
            let TypeRef::Offset(object) = node.object_pointer else {
                return Err("invalid object-pointer reference".into());
            };
            if !node.children.contains(&object) || self.nodes[&object].tag != gimli::DW_TAG_formal_parameter {
                return Err("object pointer does not reference an actual formal parameter".into());
            }
            if node.children.iter().find(|&&id| self.nodes[&id].tag == gimli::DW_TAG_formal_parameter) != Some(&object)
            {
                return Err("object pointer is not the first formal parameter".into());
            }
        }
        Ok(())
    }
}

fn dependencies(node: &Node, nodes: &BTreeMap<usize, Node>) -> Vec<usize> {
    let mut refs = Vec::new();
    if let TypeRef::Offset(offset) = node.target {
        refs.push(offset);
    }
    for &child in &node.children {
        if matches!(nodes[&child].tag, gimli::DW_TAG_member | gimli::DW_TAG_formal_parameter)
            && let TypeRef::Offset(target) = nodes[&child].target
        {
            refs.push(target);
        }
    }
    refs.sort_unstable();
    refs.dedup();
    refs
}

fn build_report(nodes: &BTreeMap<usize, Node>, is_code: impl Fn(u64) -> bool, report: &mut DebugProducerReport) {
    let mut graph = Graph::new(nodes);
    for (&offset, node) in nodes {
        if !type_tag(node.tag) {
            continue;
        }
        let size = graph.size(offset, 0);
        let mut reasons = node.reasons.clone();
        if let Err(reason) = &size
            && !reasons.contains(reason)
        {
            reasons.push(reason.clone());
        }
        let kind = match node.tag {
            gimli::DW_TAG_base_type => match scalar_kind(node.encoding) {
                Some((kind, signed)) => DebugProducerKind::Scalar {
                    encoding: node.encoding.unwrap().0,
                    scalar_kind: kind,
                    bit_width: node.size.and_then(|size| size.checked_mul(8)).unwrap_or(0),
                    signed,
                },
                None => DebugProducerKind::Unsupported { dwarf_tag: node.tag.0 },
            },
            gimli::DW_TAG_pointer_type => {
                DebugProducerKind::Pointer { target: reference(node.target, nodes), address_size: 8 }
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type => {
                let members = node
                    .children
                    .iter()
                    .filter_map(|child| {
                        let child = &nodes[child];
                        if child.tag != gimli::DW_TAG_member {
                            return None;
                        }
                        let underlying_size =
                            if child.bitfield() { graph.target(child.target, 0).ok().flatten() } else { None };
                        Some(DebugProducerMember {
                            id: child.id,
                            original_name: child.name.clone(),
                            emitted_name: emitted(child.id),
                            ty: reference(child.target, nodes),
                            producer_alignment: child.alignment,
                            byte_offset: if node.tag == gimli::DW_TAG_union_type {
                                Some(child.offset.unwrap_or(0))
                            } else {
                                child.offset
                            },
                            bitfield: child.bitfield().then(|| DebugProducerBitfield {
                                bit_size: child.bit_size,
                                data_bit_offset: child.data_bit_offset,
                                legacy_bit_offset: child.bit_offset,
                                raw_storage_byte_size: child.size,
                                underlying_type_byte_size: underlying_size,
                                native_unsupported_reason:
                                    "native bitfield import unsupported; storage is not truncated".into(),
                            }),
                        })
                    })
                    .collect();
                DebugProducerKind::Record {
                    record_kind: match node.tag {
                        gimli::DW_TAG_class_type => DebugProducerRecordKind::Class,
                        gimli::DW_TAG_union_type => DebugProducerRecordKind::Union,
                        _ => DebugProducerRecordKind::Struct,
                    },
                    members,
                }
            }
            gimli::DW_TAG_array_type => {
                let layout = graph.array(node, 0).ok();
                let occupied_byte_size = layout.as_ref().map(|layout| layout.occupied_byte_size);
                let dimensions = layout.map(|layout| layout.dimensions).unwrap_or_else(|| {
                    node.children
                        .iter()
                        .filter_map(|&child| {
                            let child = &nodes[&child];
                            (child.tag == gimli::DW_TAG_subrange_type).then(|| dimension(child, node.source.is_some()))
                        })
                        .collect()
                });
                DebugProducerKind::Array {
                    element: reference(node.target, nodes),
                    dimensions,
                    occupied_byte_size,
                    producer_byte_size: node.size,
                    producer_byte_stride: node.stride,
                    producer_stride_present: node.stride_present || node.stride.is_some(),
                }
            }
            gimli::DW_TAG_enumeration_type => {
                let signed = graph.enum_facts(node, 0).ok().map(|(_, signed)| signed);
                DebugProducerKind::Enum {
                    underlying: reference(node.target, nodes),
                    encoding: node.encoding.map(|encoding| encoding.0),
                    values: node
                        .children
                        .iter()
                        .filter_map(|child| {
                            let child = &nodes[child];
                            (child.tag == gimli::DW_TAG_enumerator).then(|| DebugProducerEnumerator {
                                id: child.id,
                                original_name: child.name.clone(),
                                emitted_name: emitted(child.id),
                                value: child.value.zip(signed).and_then(|(raw, signed)| enum_constant(raw, signed)),
                                raw_constant: child.value,
                            })
                        })
                        .collect(),
                }
            }
            gimli::DW_TAG_typedef => DebugProducerKind::Alias { target: reference(node.target, nodes) },
            gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type => {
                DebugProducerKind::Qualified { target: reference(node.target, nodes), qualifier: node.tag.to_string() }
            }
            gimli::DW_TAG_subroutine_type => DebugProducerKind::Function { prototype: prototype(node, nodes) },
            _ => DebugProducerKind::Unsupported { dwarf_tag: node.tag.0 },
        };
        report.types.push(DebugProducerType {
            id: node.id,
            original_name: node.name.clone(),
            emitted_name: emitted(node.id),
            byte_size: size.ok().flatten().or(node.size),
            producer_alignment: node.alignment,
            source: node.source.clone(),
            kind,
            eligible_for_native_verification: reasons.is_empty(),
            unsupported_reasons: reasons,
        });
    }
    // Propagate unsupported closure along all type edges. A pointer breaks storage recursion, not proof dependency.
    let by_offset: BTreeMap<usize, usize> =
        report.types.iter().enumerate().map(|(index, ty)| (ty.id.die_offset as usize, index)).collect();
    let mut reverse: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    let mut queue = Vec::new();
    for (&offset, &index) in &by_offset {
        if !report.types[index].eligible_for_native_verification {
            rejected.insert(offset);
            queue.push(offset);
        }
        for dependency in dependencies(&nodes[&offset], nodes) {
            reverse.entry(dependency).or_default().push(offset);
            if !by_offset.contains_key(&dependency) && rejected.insert(offset) {
                queue.push(offset);
            }
        }
    }
    while let Some(offset) = queue.pop() {
        for &dependent in reverse.get(&offset).into_iter().flatten() {
            if rejected.insert(dependent) {
                queue.push(dependent);
            }
        }
    }
    for (&offset, &index) in &by_offset {
        let ty = &mut report.types[index];
        if rejected.contains(&offset) && ty.unsupported_reasons.is_empty() {
            ty.unsupported_reasons.push("unsupported producer dependency closure; preview only".into());
        }
        ty.eligible_for_native_verification = ty.unsupported_reasons.is_empty();
    }
    for original in nodes.values().filter(|node| node.tag == gimli::DW_TAG_subprogram) {
        let effective = effective_function(original, nodes);
        let node = effective.as_ref().unwrap_or(original);
        let mut reasons = node.reasons.clone();
        if let Err(reason) = &effective {
            reasons.push(reason.clone());
        }
        if let Err(reason) = graph.check_prototype(node, 0) {
            reasons.push(reason);
        }
        if node.source.is_none() {
            reasons.push("no verified C/C++ compilation-unit language".into());
        }
        if node.declaration {
            reasons.push("addressed declaration is not a concrete definition".into());
        }
        match node.address {
            Some(address) if !is_code(address) => reasons.push("function entry is not mapped code".into()),
            None => reasons.push("no concrete producer function entry address; preview only".into()),
            _ => {}
        }
        if dependencies(node, nodes).iter().any(|id| rejected.contains(id) || !by_offset.contains_key(id)) {
            reasons.push("unsupported producer dependency closure; preview only".into());
        }
        report.functions.push(DebugProducerFunction {
            id: node.id,
            original_name: node
                .name
                .as_ref()
                .filter(|name| !name.is_empty())
                .or_else(|| node.linkage_name.as_ref().filter(|name| !name.is_empty()))
                .cloned(),
            emitted_name: emitted(node.id),
            address: node.address,
            source: node.source.clone(),
            prototype: prototype(node, nodes),
            eligible_for_native_verification: reasons.is_empty(),
            unsupported_reasons: reasons,
        });
    }
}

fn effective_function(node: &Node, nodes: &BTreeMap<usize, Node>) -> Result<Node, String> {
    let mut effective = node.clone();
    if matches!(node.specification, TypeRef::Absent) {
        if let Some(record) = declaring_record(node, nodes) {
            validate_method_this(node, record, nodes)?;
        }
        return Ok(effective);
    }
    let TypeRef::Offset(offset) = node.specification else {
        return Err("unsupported method specification reference".into());
    };
    let declaration = nodes.get(&offset).ok_or("unresolved method specification reference")?;
    let record =
        declaration.parent.and_then(|parent| nodes.get(&parent)).ok_or("method has no exact declaring record")?;
    if declaration.tag != gimli::DW_TAG_subprogram
        || !declaration.declaration
        || !matches!(declaration.specification, TypeRef::Absent)
        || !matches!(record.tag, gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type)
        || node.id.unit_offset != declaration.id.unit_offset
        || node.source != declaration.source
        || !node.source.as_ref().is_some_and(DebugLayoutSource::is_cpp)
        || !declaration.reasons.is_empty()
    {
        return Err("method association lacks a clean exact same-CU C++ declaration".into());
    }
    effective.name = node.name.clone().or_else(|| declaration.name.clone());
    effective.linkage_name = node.linkage_name.clone().or_else(|| declaration.linkage_name.clone());
    if matches!(node.target, TypeRef::Absent) {
        effective.target = declaration.target;
    } else if reference(node.target, nodes) != reference(declaration.target, nodes) {
        return Err("method definition/declaration return types conflict".into());
    }
    if node.calling.is_some() && declaration.calling.is_some() && node.calling != declaration.calling {
        return Err("method definition/declaration calling conventions conflict".into());
    }
    effective.calling = node.calling.or(declaration.calling);
    effective.prototyped |= declaration.prototyped;
    if node
        .prototyped_attribute
        .zip(declaration.prototyped_attribute)
        .is_some_and(|(actual, declared)| actual != declared)
    {
        return Err("method definition/declaration prototype attributes conflict".into());
    }
    effective.prototyped_attribute = if node.prototyped_present {
        node.prototyped_attribute
    } else {
        node.prototyped_attribute.or(declaration.prototyped_attribute)
    };
    effective.prototyped_present = node.prototyped_present || declaration.prototyped_present;
    let actual: Vec<_> =
        node.children.iter().filter(|&&child| nodes[&child].tag == gimli::DW_TAG_formal_parameter).collect();
    let declared: Vec<_> =
        declaration.children.iter().filter(|&&child| nodes[&child].tag == gimli::DW_TAG_formal_parameter).collect();
    if actual.len() != declared.len()
        || actual.iter().zip(declared.iter()).any(|(&actual, &declared)| {
            reference(nodes[actual].target, nodes) != reference(nodes[declared].target, nodes)
        })
    {
        return Err("method definition/declaration formals lack exact matching producer types".into());
    }
    let has_varargs =
        |n: &Node| n.children.iter().any(|child| nodes[child].tag == gimli::DW_TAG_unspecified_parameters);
    if has_varargs(node) != has_varargs(declaration) {
        return Err("method variadic declarations conflict".into());
    }
    validate_method_this(&effective, record, nodes)?;
    Ok(effective)
}

fn declaring_record<'a>(node: &Node, nodes: &'a BTreeMap<usize, Node>) -> Option<&'a Node> {
    if node.tag != gimli::DW_TAG_subprogram {
        return None;
    }
    let parent = if let TypeRef::Offset(declaration) = node.specification {
        nodes.get(&declaration)?.parent
    } else {
        node.parent
    };
    parent
        .and_then(|parent| nodes.get(&parent))
        .filter(|parent| matches!(parent.tag, gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type))
}

fn validate_method_this(node: &Node, record: &Node, nodes: &BTreeMap<usize, Node>) -> Result<(), String> {
    if node.id.unit_offset != record.id.unit_offset
        || node.source != record.source
        || !node.source.as_ref().is_some_and(DebugLayoutSource::is_cpp)
    {
        return Err("method lacks exact same-CU C++ declaring-record evidence".into());
    }
    // A concrete object pointer must identify the actual first formal, not a declaration's distinct DIE.
    let TypeRef::Offset(object) = node.object_pointer else {
        return Err("method lacks concrete object-pointer evidence".into());
    };
    if node.children.iter().find(|&&child| nodes[&child].tag == gimli::DW_TAG_formal_parameter) != Some(&object) {
        return Err("method object pointer is not the actual first formal".into());
    }
    let TypeRef::Offset(pointer) = nodes[&object].target else {
        return Err("method this formal has no pointer type".into());
    };
    let pointer = nodes.get(&pointer).ok_or("method this pointer unresolved")?;
    let mut target = pointer.target;
    if pointer.tag != gimli::DW_TAG_pointer_type {
        return Err("method this formal is not a native pointer".into());
    }
    for _ in 0..MAX_TYPE_DEPTH {
        let TypeRef::Offset(offset) = target else {
            break;
        };
        let pointee = nodes.get(&offset).ok_or("method this pointee unresolved")?;
        if pointee.id == record.id {
            return Ok(());
        }
        if !matches!(pointee.tag, gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type) {
            break;
        }
        target = pointee.target;
    }
    Err("method this pointer does not identify its exact declaring record".into())
}

fn shared_id(id: DebugLayoutTypeId) -> String {
    format!("dwarf:cu:{:x}:die:{:x}", id.unit_offset, id.die_offset)
}

fn shared_origin(id: DebugLayoutTypeId) -> crate::debug_types::DebugTypeOrigin {
    crate::debug_types::DebugTypeOrigin {
        source: crate::debug_types::DebugSourceKind::Dwarf,
        unit: Some(format!("{:x}", id.unit_offset)),
        index: id.die_offset,
    }
}

fn shared_encoding(encoding: u8) -> crate::debug_types::DebugScalarEncoding {
    use crate::debug_types::DebugScalarEncoding as E;
    match gimli::DwAte(encoding) {
        gimli::DW_ATE_signed | gimli::DW_ATE_signed_char => E::Signed,
        gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char => E::Unsigned,
        gimli::DW_ATE_float => E::Float,
        gimli::DW_ATE_boolean => E::Boolean,
        _ => E::Unknown,
    }
}

fn shared_prototype(prototype: &DebugProducerPrototype) -> crate::debug_types::DebugTypeKind {
    crate::debug_types::DebugTypeKind::Function {
        // The image target, not this spelling alone, selects a native calling convention during checked import.
        convention: if prototype.calling_convention == Some(gimli::DW_CC_normal.0) {
            "normal".into()
        } else {
            format!("dwarf_cc_{}", prototype.calling_convention.unwrap_or(0))
        },
        parameters: prototype
            .parameters
            .iter()
            .map(|p| p.ty.map(shared_id).unwrap_or_else(|| "dwarf:missing".into()))
            .collect(),
        return_type: prototype
            .return_type
            .map(shared_id)
            .unwrap_or_else(|| if prototype.return_type_absent { "dwarf:void".into() } else { "dwarf:missing".into() }),
        variadic: prototype.variadic,
    }
}

/// Shared project-import DTO adapter. `producer_type_graph` retains evidence that this DTO cannot express.
/// The adapter never drops a member to make an incomplete record appear complete.
pub fn type_graph(binary: &Binary) -> Result<crate::debug_types::DebugTypeReport, LoadError> {
    let producer = producer_type_graph(binary)?;
    Ok(shared_report(producer, rampage_arch::hex::bytes(&Sha256::digest(binary.image_bytes()))))
}

fn source_field_identifier(name: &str) -> bool {
    super::identifier(name)
        && (!super::c_keyword(name)
            || matches!(
                name,
                "int8_t" | "int16_t" | "int32_t" | "int64_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t"
            ))
}

fn shared_report(producer: DebugProducerReport, source_sha256: String) -> crate::debug_types::DebugTypeReport {
    use crate::debug_types as dto;
    let mut report = dto::DebugTypeReport {
        types: Vec::new(),
        signatures: Vec::new(),
        provenance: dto::DebugTypeProvenance {
            source: dto::DebugSourceKind::Dwarf,
            source_sha256,
            pdb_guid: None,
            pdb_age: None,
        },
        warnings: producer.warnings,
        limits: dto::DebugTypeLimits::default(),
    };
    let Some(target) = producer.target else {
        return report;
    };
    if producer.types.is_empty() && producer.functions.is_empty() {
        return report;
    }
    report.warnings.push(format!("embedded DWARF target {target:?}; native graph/ABI verification remains required"));
    if producer.types.len() + producer.functions.len() + 1 > report.limits.types
        || producer.functions.len() > report.limits.signatures
    {
        report.warnings.push("shared DTO output budget exceeded; detailed producer graph remains preview-only".into());
        return report;
    }
    report.types.push(dto::DebugType {
        id: "dwarf:void".into(),
        original_name: None,
        emitted_name: None,
        byte_size: Some(0),
        alignment: None,
        kind: dto::DebugTypeKind::Scalar { encoding: dto::DebugScalarEncoding::Void, c_name: Some("void".into()) },
        origin: dto::DebugTypeOrigin { source: dto::DebugSourceKind::Dwarf, unit: None, index: 0 },
        unsupported: vec![],
    });
    for ty in producer.types {
        let mut unsupported = ty.unsupported_reasons.clone();
        if !unsupported.is_empty()
            && matches!(&ty.kind, DebugProducerKind::Array { .. } | DebugProducerKind::Enum { .. })
        {
            unsupported.push(format!(
                "detailed unsupported producer evidence: {}",
                serde_json::to_string(&ty.kind).unwrap_or_default()
            ));
        }
        let mut extra = None;
        let kind = match &ty.kind {
            DebugProducerKind::Scalar { encoding, scalar_kind, signed, bit_width } => {
                let c_name = match (scalar_kind, signed, bit_width) {
                    (DebugProducerScalarKind::Integer, Some(true), width) => Some(format!("int{width}_t")),
                    (DebugProducerScalarKind::Integer, Some(false), width) => Some(format!("uint{width}_t")),
                    (DebugProducerScalarKind::Float, _, 32) => Some("float".into()),
                    (DebugProducerScalarKind::Float, _, 64) => Some("double".into()),
                    (DebugProducerScalarKind::Boolean, _, 8) => Some("bool".into()),
                    _ => None,
                };
                dto::DebugTypeKind::Scalar { encoding: shared_encoding(*encoding), c_name }
            }
            DebugProducerKind::Pointer { target, .. } => dto::DebugTypeKind::Pointer {
                target: target.map(shared_id).unwrap_or_else(|| {
                    if unsupported.is_empty() { "dwarf:void".into() } else { "dwarf:missing".into() }
                }),
            },
            DebugProducerKind::Record { record_kind, members } => {
                if members.iter().any(|member| member.byte_offset.is_none() || member.ty.is_none()) {
                    unsupported.push(
                        "shared DTO cannot represent missing member offsets/references; full evidence follows".into(),
                    );
                    dto::DebugTypeKind::Unsupported { description: serde_json::to_string(&ty.kind).unwrap_or_default() }
                } else {
                    let mut names = BTreeMap::new();
                    for member in members {
                        if let Some(name) = member.original_name.as_deref() {
                            *names.entry(name).or_insert(0usize) += 1;
                        }
                    }
                    let members = members
                        .iter()
                        .map(|member| {
                            let mut reasons = Vec::new();
                            match member.original_name.as_deref() {
                                None => reasons.push("anonymous producer field; preview only".into()),
                                Some(name) if !source_field_identifier(name) => {
                                    reasons.push("unsupported original C field identifier; no alias substituted".into())
                                }
                                Some(name) if names.get(name).copied().unwrap_or(0) != 1 => reasons.push(
                                    "duplicate original producer field name in this record; no alias substituted"
                                        .into(),
                                ),
                                _ => {}
                            }
                            if !reasons.is_empty() {
                                unsupported
                                    .push(format!("unsupported field name at {}; preview only", shared_id(member.id)));
                            }
                            let bitfield = member.bitfield.as_ref().and_then(|bits| {
                                reasons.push(format!(
                                    "native bitfield unsupported; producer evidence: {}",
                                    serde_json::to_string(member).unwrap_or_default()
                                ));
                                Some(dto::DebugBitfield {
                                    bit_size: bits.bit_size?,
                                    bit_offset: bits.legacy_bit_offset?,
                                })
                            });
                            dto::DebugMember {
                                name: member.original_name.clone(),
                                type_id: shared_id(member.ty.unwrap()),
                                byte_offset: member.byte_offset.unwrap(),
                                bitfield,
                                unsupported: reasons,
                            }
                        })
                        .collect();
                    if *record_kind == DebugProducerRecordKind::Union {
                        dto::DebugTypeKind::Union { members }
                    } else {
                        dto::DebugTypeKind::Struct { members }
                    }
                }
            }
            DebugProducerKind::Array { element: Some(element), dimensions, .. } if dimensions.len() == 1 => {
                dto::DebugTypeKind::Array {
                    element: shared_id(*element),
                    count: dimensions[0].count,
                    stride: dimensions[0].byte_stride,
                }
            }
            DebugProducerKind::Enum { underlying, encoding, values } => {
                let mut names = BTreeMap::new();
                for value in values {
                    if let Some(name) = value.original_name.as_deref() {
                        *names.entry(name).or_insert(0usize) += 1;
                    }
                }
                for value in values {
                    let reason = match value.original_name.as_deref() {
                        None => Some("anonymous enumerator has no producer name"),
                        Some(name) if !source_field_identifier(name) => {
                            Some("unsupported original enumerator identifier")
                        }
                        Some(name) if names.get(name).copied().unwrap_or(0) != 1 => {
                            Some("duplicate original enumerator name")
                        }
                        _ => None,
                    };
                    if let Some(reason) = reason {
                        unsupported.push(format!(
                            "{reason} at {}; preview only; evidence: {}",
                            shared_id(value.id),
                            serde_json::to_string(value).unwrap_or_default()
                        ));
                    }
                }
                let underlying = underlying.map(shared_id).unwrap_or_else(|| {
                    let id = format!("{}:underlying", shared_id(ty.id));
                    extra = Some(dto::DebugType {
                        id: id.clone(),
                        original_name: None,
                        emitted_name: None,
                        byte_size: ty.byte_size,
                        alignment: None,
                        kind: dto::DebugTypeKind::Scalar {
                            encoding: encoding.map(shared_encoding).unwrap_or(dto::DebugScalarEncoding::Unknown),
                            c_name: None,
                        },
                        origin: shared_origin(ty.id),
                        unsupported: unsupported.clone(),
                    });
                    id
                });
                dto::DebugTypeKind::Enum {
                    underlying,
                    values: values
                        .iter()
                        .map(|value| dto::DebugEnumerator {
                            // The shared DTO has no optional enumerator name. Empty means absent, not an ID alias.
                            name: value.original_name.clone().unwrap_or_default(),
                            value: match value.value {
                                Some(DebugProducerInteger::Signed(n)) => n.to_string(),
                                Some(DebugProducerInteger::Unsigned(n)) => n.to_string(),
                                None => "<missing>".into(),
                            },
                        })
                        .collect(),
                }
            }
            DebugProducerKind::Alias { target: Some(target) } => {
                dto::DebugTypeKind::Typedef { target: shared_id(*target), constant: false, volatile: false }
            }
            DebugProducerKind::Qualified { target: Some(target), qualifier }
                if qualifier == "DW_TAG_const_type" || qualifier == "DW_TAG_volatile_type" =>
            {
                dto::DebugTypeKind::Typedef {
                    target: shared_id(*target),
                    constant: qualifier == "DW_TAG_const_type",
                    volatile: qualifier == "DW_TAG_volatile_type",
                }
            }
            DebugProducerKind::Function { prototype } => shared_prototype(prototype),
            _ => {
                unsupported
                    .push("shared DTO cannot losslessly express this producer category; full evidence follows".into());
                dto::DebugTypeKind::Unsupported { description: serde_json::to_string(&ty.kind).unwrap_or_default() }
            }
        };
        if let Some(extra) = extra {
            report.types.push(extra);
        }
        report.types.push(dto::DebugType {
            id: shared_id(ty.id),
            original_name: ty.original_name,
            emitted_name: Some(ty.emitted_name),
            byte_size: ty.byte_size,
            alignment: ty.producer_alignment,
            kind,
            origin: shared_origin(ty.id),
            unsupported,
        });
    }
    for function in producer.functions {
        let id = shared_id(function.id);
        report.types.push(dto::DebugType {
            id: id.clone(),
            original_name: function.original_name.clone(),
            emitted_name: Some(function.emitted_name),
            byte_size: None,
            alignment: None,
            kind: shared_prototype(&function.prototype),
            origin: shared_origin(function.id),
            unsupported: function.unsupported_reasons.clone(),
        });
        if let Some(address) = function.address {
            report.signatures.push(dto::DebugSignature {
                address,
                name: function.original_name,
                type_id: id,
                origin: shared_origin(function.id),
                unsupported: function.unsupported_reasons,
            });
        }
    }
    if report.types.len() > report.limits.types {
        report.types.clear();
        report.signatures.clear();
        report
            .warnings
            .push("shared DTO expanded enum-underlying type budget exceeded; no partial graph emitted".into());
        return report;
    }
    // Adapter-specific unsupported categories must invalidate their dependent closures as well.
    let mut rejected: BTreeSet<String> =
        report.types.iter().filter(|ty| !ty.unsupported.is_empty()).map(|ty| ty.id.clone()).collect();
    let known: BTreeSet<String> = report.types.iter().map(|ty| ty.id.clone()).collect();
    loop {
        let mut changed = false;
        for ty in &mut report.types {
            if !rejected.contains(&ty.id)
                && ty.kind.references().iter().any(|id| !known.contains(*id) || rejected.contains(*id))
            {
                ty.unsupported.push("unsupported/missing shared producer dependency closure; preview only".into());
                rejected.insert(ty.id.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for signature in &mut report.signatures {
        if rejected.contains(&signature.type_id) && signature.unsupported.is_empty() {
            signature.unsupported.push("unsupported shared producer dependency closure; preview only".into());
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::ObjectSymbol;
    use std::path::PathBuf;

    fn unit(entries: &[u8]) -> Vec<u8> {
        let mut bytes = ((entries.len() + 7) as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[4, 0, 0, 0, 0, 0, 8]);
        bytes.extend_from_slice(entries);
        bytes
    }

    fn dwarf<'a>(info: &'a [u8], abbrev: &'a [u8]) -> Dwarf<DebugReader<'a>> {
        Dwarf::load(|id| -> gimli::Result<_> {
            let bytes = match id {
                gimli::SectionId::DebugInfo => info,
                gimli::SectionId::DebugAbbrev => abbrev,
                _ => &[],
            };
            Ok(EndianSlice::new(bytes, RunTimeEndian::Little))
        })
        .unwrap()
    }

    fn node(offset: usize, tag: gimli::DwTag) -> Node {
        let mut node = Node::new(DebugLayoutTypeId { unit_offset: 0, die_offset: offset as u64 }, tag);
        node.source = Some(DebugLayoutSource {
            unit_offset: 0,
            language: gimli::DW_LANG_C11.0,
            dwarf_version: 4,
            address_size: 8,
        });
        node
    }

    fn scalar(offset: usize) -> Node {
        let mut node = node(offset, gimli::DW_TAG_base_type);
        node.size = Some(4);
        node.encoding = Some(gimli::DW_ATE_signed);
        node
    }

    fn report(nodes: &BTreeMap<usize, Node>) -> DebugProducerReport {
        let mut report = DebugProducerReport { target: Some(DebugTypeTarget::X86_64Elf), ..Default::default() };
        build_report(nodes, |_| true, &mut report);
        report
    }

    #[test]
    fn producer_byte_budgets_precede_even_malformed_headers() {
        let info = vec![0xff; MAX_READ_WORK / 3 + 1];
        let mut budget = Budget::default();
        let error = read_nodes(&dwarf(&info, &[]), &mut budget).unwrap_err();
        assert!(error.contains("pre-read"));
        assert_eq!(budget.work, 0);
        let info = unit(&[1, 0]);
        let abbrev = vec![0; MAX_READ_WORK / 3 + 1];
        let error = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap_err();
        assert!(error.contains("pre-read"));
    }

    #[test]
    fn malformed_absolute_and_unit_references_do_not_become_void_pointers() {
        // Compilation unit with C11 language, pointer with ref4, and dangling absolute ref_addr.
        let abbrev = [1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x0f, 0, 0x49, 0x13, 0, 0, 3, 0x0f, 0, 0x49, 0x10, 0, 0, 0];
        let info = unit(&[1, 0x1d, 0, 2, 0xff, 0xff, 0xff, 0x7f, 3, 99, 0, 0, 0, 0]);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        assert_eq!(producer.types.len(), 2);
        assert!(producer.types.iter().all(|ty| !ty.eligible_for_native_verification));
        let shared = shared_report(producer, "fixture".into());
        assert!(shared.types.iter().filter(|ty| ty.id != "dwarf:void").all(|ty| !ty.unsupported.is_empty()));
    }

    #[test]
    fn same_named_cross_cu_types_remain_distinct_and_absolute_refs_keep_identity() {
        let abbrev = [
            1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x24, 0, 3, 8, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 3, 0x16, 0, 0x49, 0x10, 0, 0,
            0,
        ];
        let first = unit(b"\x01\x1d\0\x02same\0\x05\x04\0");
        let first_die = 14;
        let second_start = first.len();
        let mut second_entries = b"\x01\x1d\0\x02same\0\x07\x04\x03".to_vec();
        second_entries.extend_from_slice(&(first_die as u32).to_le_bytes());
        second_entries.push(0);
        let info = [first, unit(&second_entries)].concat();
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        let same: Vec<_> = producer.types.iter().filter(|ty| ty.original_name.as_deref() == Some("same")).collect();
        assert_eq!(same.len(), 2);
        assert_ne!(same[0].id, same[1].id);
        assert_ne!(same[0].emitted_name, same[1].emitted_name);
        assert_eq!(same[1].id.unit_offset, second_start as u64);
        let alias = producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Alias { .. })).unwrap();
        assert!(matches!(alias.kind, DebugProducerKind::Alias { target: Some(id) } if id == same[0].id));
    }

    #[test]
    fn dwarf5_compilation_units_keep_exact_producer_facts() {
        let abbrev = [1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x24, 0, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 0];
        let entries = [1, 0x1d, 0, 2, 5, 4, 0];
        let mut info = ((entries.len() + 8) as u32).to_le_bytes().to_vec();
        info.extend_from_slice(&[5, 0, 1, 8, 0, 0, 0, 0]);
        info.extend_from_slice(&entries);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        assert_eq!(producer.types.len(), 1);
        assert_eq!(producer.types[0].byte_size, Some(4));
        assert_eq!(producer.types[0].source.as_ref().unwrap().dwarf_version, 5);
        assert!(producer.types[0].eligible_for_native_verification);
        assert_eq!(producer.types[0].producer_alignment, None);
    }

    #[test]
    fn fixed_form_enum_constants_are_interpreted_only_with_the_underlying_signedness() {
        for (form, width) in
            [(gimli::DW_FORM_data1, 1), (gimli::DW_FORM_data2, 2), (gimli::DW_FORM_data4, 4), (gimli::DW_FORM_data8, 8)]
        {
            for encoding in [gimli::DW_ATE_signed, gimli::DW_ATE_unsigned] {
                let abbrev = [
                    1,
                    0x11,
                    1,
                    0x13,
                    0x05,
                    0,
                    0,
                    2,
                    0x24,
                    0,
                    0x3e,
                    0x0b,
                    0x0b,
                    0x0b,
                    0,
                    0,
                    3,
                    0x04,
                    1,
                    0x49,
                    0x13,
                    0,
                    0,
                    4,
                    0x28,
                    0,
                    0x1c,
                    form.0 as u8,
                    0,
                    0,
                    0,
                ];
                let mut entries = vec![1, 0x1d, 0, 2, encoding.0, width as u8, 3, 14, 0, 0, 0, 4];
                entries.extend(vec![0xff; width]);
                entries.extend([0, 0]);
                let info = unit(&entries);
                let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
                let producer = report(&nodes);
                let enumeration =
                    producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Enum { .. })).unwrap();
                assert!(enumeration.eligible_for_native_verification, "{:?}", enumeration.unsupported_reasons);
                let DebugProducerKind::Enum { values, .. } = &enumeration.kind else { unreachable!() };
                let raw = values[0].raw_constant.unwrap();
                assert_eq!(raw.form, form.0);
                assert_eq!(raw.byte_width, Some(width as u8));
                let expected_unsigned = u64::MAX >> ((8 - width) * 8);
                assert!(matches!(raw.value, DebugProducerInteger::Unsigned(value) if value == expected_unsigned));
                if encoding == gimli::DW_ATE_signed {
                    assert!(matches!(values[0].value, Some(DebugProducerInteger::Signed(-1))));
                } else {
                    assert!(matches!(values[0].value, Some(DebugProducerInteger::Unsigned(value))
                        if value == expected_unsigned));
                }
                let mut unresolved = nodes;
                unresolved.get_mut(&14).unwrap().encoding = None;
                let producer = report(&unresolved);
                let enumeration =
                    producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Enum { .. })).unwrap();
                let DebugProducerKind::Enum { values, .. } = &enumeration.kind else { unreachable!() };
                assert!(values[0].value.is_none());
                assert_eq!(values[0].raw_constant.unwrap().form, form.0);
            }
        }
    }

    #[test]
    fn concrete_cpp_scalar_method_requires_exact_this_and_declaration_identity() {
        let mut record = node(1, gimli::DW_TAG_class_type);
        record.size = Some(4);
        record.children = vec![2, 5];
        let mut member = node(2, gimli::DW_TAG_member);
        member.target = TypeRef::Offset(3);
        member.offset = Some(0);
        let mut pointer = node(4, gimli::DW_TAG_pointer_type);
        pointer.target = TypeRef::Offset(1);
        let mut declaration = node(5, gimli::DW_TAG_subprogram);
        declaration.parent = Some(1);
        declaration.declaration = true;
        declaration.prototyped = true;
        declaration.target = TypeRef::Offset(3);
        declaration.name = Some("query".into());
        declaration.children = vec![6];
        let mut declared_this = node(6, gimli::DW_TAG_formal_parameter);
        declared_this.target = TypeRef::Offset(4);
        let mut definition = node(7, gimli::DW_TAG_subprogram);
        definition.specification = TypeRef::Offset(5);
        definition.object_pointer = TypeRef::Offset(8);
        definition.address = Some(0x1000);
        definition.children = vec![8];
        let mut actual_this = node(8, gimli::DW_TAG_formal_parameter);
        actual_this.target = TypeRef::Offset(4);
        let mut nodes = BTreeMap::from([
            (1, record),
            (2, member),
            (3, scalar(3)),
            (4, pointer),
            (5, declaration),
            (6, declared_this),
            (7, definition),
            (8, actual_this),
        ]);
        for node in nodes.values_mut() {
            node.source.as_mut().unwrap().language = gimli::DW_LANG_C_plus_plus_14.0;
        }
        let producer = report(&nodes);
        let method = producer.functions.iter().find(|function| function.address.is_some()).unwrap();
        assert!(method.eligible_for_native_verification, "{:?}", method.unsupported_reasons);
        assert_eq!(method.original_name.as_deref(), Some("query"));
        assert_eq!(method.prototype.record_id, Some(nodes[&1].id));
        assert_eq!(method.prototype.declaration_id, Some(nodes[&5].id));
        nodes.get_mut(&7).unwrap().object_pointer = TypeRef::Offset(6);
        assert!(
            !report(&nodes)
                .functions
                .iter()
                .find(|function| function.address.is_some())
                .unwrap()
                .eligible_for_native_verification
        );
    }

    #[test]
    fn directly_nested_cpp_methods_validate_this_against_the_exact_parent_record() {
        let mut record = node(1, gimli::DW_TAG_class_type);
        record.name = Some("SameName".into());
        record.size = Some(4);
        record.children = vec![5];
        let mut pointer = node(4, gimli::DW_TAG_pointer_type);
        pointer.target = TypeRef::Offset(1);
        let mut method = node(5, gimli::DW_TAG_subprogram);
        method.parent = Some(1);
        method.prototyped = true;
        method.address = Some(0x1000);
        method.object_pointer = TypeRef::Offset(6);
        method.children = vec![6, 7];
        let mut this = node(6, gimli::DW_TAG_formal_parameter);
        this.target = TypeRef::Offset(4);
        let mut argument = node(7, gimli::DW_TAG_formal_parameter);
        argument.target = TypeRef::Offset(3);
        let mut other_record = node(8, gimli::DW_TAG_class_type);
        other_record.name = record.name.clone();
        other_record.size = Some(4);
        other_record.id.unit_offset = 100;
        other_record.source.as_mut().unwrap().unit_offset = 100;
        let mut nodes = BTreeMap::from([
            (1, record),
            (3, scalar(3)),
            (4, pointer),
            (5, method),
            (6, this),
            (7, argument),
            (8, other_record),
        ]);
        for node in nodes.values_mut() {
            node.source.as_mut().unwrap().language = gimli::DW_LANG_C_plus_plus_14.0;
        }
        let producer = report(&nodes);
        assert!(producer.functions[0].eligible_for_native_verification);
        assert_eq!(producer.functions[0].prototype.record_id, Some(nodes[&1].id));
        assert_eq!(producer.functions[0].prototype.declaration_id, None);
        for object in [TypeRef::Absent, TypeRef::Offset(7), TypeRef::Offset(99)] {
            nodes.get_mut(&5).unwrap().object_pointer = object;
            assert!(!report(&nodes).functions[0].eligible_for_native_verification);
        }
        nodes.get_mut(&5).unwrap().object_pointer = TypeRef::Offset(6);
        nodes.get_mut(&6).unwrap().target = TypeRef::Offset(3);
        assert!(!report(&nodes).functions[0].eligible_for_native_verification);
        nodes.get_mut(&6).unwrap().target = TypeRef::Offset(4);
        nodes.get_mut(&4).unwrap().target = TypeRef::Offset(8);
        let producer = report(&nodes);
        assert!(!producer.functions[0].eligible_for_native_verification);
        assert_eq!(producer.functions[0].prototype.record_id, Some(nodes[&1].id));
    }

    #[test]
    fn self_pointer_callback_cycles_are_supported_but_by_value_cycles_are_not() {
        let mut record = node(1, gimli::DW_TAG_structure_type);
        record.size = Some(16);
        record.children = vec![2, 4];
        let mut next = node(2, gimli::DW_TAG_member);
        next.target = TypeRef::Offset(3);
        next.offset = Some(0);
        let mut pointer = node(3, gimli::DW_TAG_pointer_type);
        pointer.target = TypeRef::Offset(1);
        let mut callback_member = node(4, gimli::DW_TAG_member);
        callback_member.target = TypeRef::Offset(5);
        callback_member.offset = Some(8);
        let mut callback = node(5, gimli::DW_TAG_pointer_type);
        callback.target = TypeRef::Offset(6);
        let mut function = node(6, gimli::DW_TAG_subroutine_type);
        function.prototyped = true;
        function.target = TypeRef::Offset(8);
        function.children = vec![7];
        let mut parameter = node(7, gimli::DW_TAG_formal_parameter);
        parameter.target = TypeRef::Offset(3);
        let mut nodes = BTreeMap::from([
            (1, record),
            (2, next),
            (3, pointer),
            (4, callback_member),
            (5, callback),
            (6, function),
            (7, parameter),
            (8, scalar(8)),
        ]);
        let producer = report(&nodes);
        assert!(producer.types.iter().all(|ty| ty.eligible_for_native_verification));
        assert!(producer.types.iter().all(|ty| ty.producer_alignment.is_none()));
        nodes.get_mut(&2).unwrap().target = TypeRef::Offset(1);
        let producer = report(&nodes);
        assert!(producer.types.iter().all(|ty| !ty.eligible_for_native_verification || ty.id.die_offset == 8));
        assert!(producer.types[0].unsupported_reasons.iter().any(|reason| reason.contains("cycle")));
    }

    #[test]
    fn arrays_require_exact_counts_and_reject_overflow_and_short_stride() {
        let mut array = node(2, gimli::DW_TAG_array_type);
        array.target = TypeRef::Offset(1);
        array.children = vec![3];
        let mut range = node(3, gimli::DW_TAG_subrange_type);
        range.count = Some(2);
        let mut nodes = BTreeMap::from([(1, scalar(1)), (2, array), (3, range)]);
        let mut graph = Graph::new(&nodes);
        let layout = graph.array(&nodes[&2], 0).unwrap();
        assert_eq!(layout.byte_size, Some(8));
        assert_eq!(layout.dimensions[0].byte_stride, Some(4));
        for (count, stride) in [(None, None), (Some(u64::MAX), None), (Some(2), Some(1)), (Some(2), Some(0))] {
            nodes.get_mut(&3).unwrap().count = count;
            nodes.get_mut(&3).unwrap().stride = stride;
            assert!(Graph::new(&nodes).array(&nodes[&2], 0).is_err());
        }
    }

    #[test]
    fn strided_arrays_keep_occupied_extent_separate_from_total_allocation() {
        let mut array = node(2, gimli::DW_TAG_array_type);
        array.target = TypeRef::Offset(1);
        array.children = vec![3];
        array.stride = Some(8);
        array.size = Some(12);
        let mut range = node(3, gimli::DW_TAG_subrange_type);
        range.count = Some(2);
        range.stride = Some(8);
        let mut nodes = BTreeMap::from([(1, scalar(1)), (2, array), (3, range)]);
        let layout = Graph::new(&nodes).array(&nodes[&2], 0).unwrap();
        assert_eq!(layout.occupied_byte_size, 12);
        assert_eq!(layout.byte_size, Some(12));
        assert!(!layout.native_contiguous);
        let producer = report(&nodes);
        assert!(!producer.types[1].eligible_for_native_verification);
        assert_eq!(producer.types[1].byte_size, Some(12));
        nodes.get_mut(&2).unwrap().size = None;
        let layout = Graph::new(&nodes).array(&nodes[&2], 0).unwrap();
        assert_eq!(layout.byte_size, None);
        let producer = report(&nodes);
        assert_eq!(producer.types[1].byte_size, None);
        assert!(matches!(&producer.types[1].kind, DebugProducerKind::Array { occupied_byte_size: Some(12), .. }));
        nodes.get_mut(&2).unwrap().size = Some(11);
        assert!(Graph::new(&nodes).array(&nodes[&2], 0).is_err());
        nodes.get_mut(&2).unwrap().size = Some(16);
        assert_eq!(Graph::new(&nodes).array(&nodes[&2], 0).unwrap().byte_size, Some(16));
        nodes.get_mut(&3).unwrap().stride = Some(4);
        let error = Graph::new(&nodes).array(&nodes[&2], 0).err().unwrap();
        assert!(error.contains("conflicting explicit"));
        nodes.get_mut(&2).unwrap().stride = Some(u64::MAX);
        nodes.get_mut(&3).unwrap().stride = Some(u64::MAX);
        assert!(Graph::new(&nodes).array(&nodes[&2], 0).is_err());
    }

    #[test]
    fn unsupported_array_elements_do_not_erase_upper_bounds_or_derivable_counts() {
        let mut array = node(2, gimli::DW_TAG_array_type);
        array.target = TypeRef::Offset(1);
        array.children = vec![3];
        array.stride = Some(16);
        let mut range = node(3, gimli::DW_TAG_subrange_type);
        range.lower = Some(0);
        range.upper = Some(2);
        range.stride = Some(8);
        let mut nodes = BTreeMap::from([(1, node(1, gimli::DW_TAG_ptr_to_member_type)), (2, array), (3, range)]);
        let producer = report(&nodes);
        let DebugProducerKind::Array { dimensions, producer_byte_stride, .. } = &producer.types[1].kind else {
            panic!("array evidence lost")
        };
        assert_eq!(dimensions[0].lower_bound, Some(0));
        assert_eq!(dimensions[0].raw_upper_bound, Some(2));
        assert_eq!(dimensions[0].count, Some(3));
        assert_eq!(dimensions[0].byte_stride, Some(8));
        assert_eq!(*producer_byte_stride, Some(16));
        nodes.get_mut(&3).unwrap().count = Some(5);
        nodes.get_mut(&3).unwrap().lower = None;
        let producer = report(&nodes);
        let DebugProducerKind::Array { dimensions, .. } = &producer.types[1].kind else { unreachable!() };
        assert_eq!(dimensions[0].count, Some(5));
        assert_eq!(dimensions[0].raw_upper_bound, Some(2));
        assert_eq!(dimensions[0].lower_bound, Some(0));
    }

    #[test]
    fn runtime_lower_bounds_are_not_replaced_with_absent_c_defaults() {
        // The subrange has a register-dependent lower bound and an independently constant upper bound of nine.
        let abbrev = [
            1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x24, 0, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 3, 0x01, 1, 0x49, 0x13, 0, 0, 4,
            0x21, 0, 0x22, 0x18, 0x2f, 0x0b, 0, 0, 0,
        ];
        let info = unit(&[1, 0x1d, 0, 2, 5, 4, 3, 14, 0, 0, 0, 4, 1, gimli::DW_OP_reg0.0, 9, 0, 0]);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        let array = producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Array { .. })).unwrap();
        assert!(!array.eligible_for_native_verification);
        assert_eq!(array.byte_size, None);
        let DebugProducerKind::Array { dimensions, occupied_byte_size, .. } = &array.kind else { unreachable!() };
        let range = &dimensions[0];
        assert!(range.lower_bound_present);
        assert_eq!(range.lower_bound, None);
        assert_eq!(range.count, None);
        assert_eq!(range.raw_upper_bound, Some(9));
        assert_eq!(*occupied_byte_size, None);
        assert!(range.unsupported_reasons.iter().any(|reason| reason.contains("array bound")));
    }

    #[test]
    fn runtime_array_strides_do_not_create_contiguous_stride_or_extent_evidence() {
        let abbrev = [
            1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x24, 0, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 3, 0x01, 1, 0x49, 0x13, 0x51, 0x18,
            0, 0, 4, 0x21, 0, 0x37, 0x0b, 0, 0, 0,
        ];
        let info = unit(&[1, 0x1d, 0, 2, 5, 4, 3, 14, 0, 0, 0, 1, gimli::DW_OP_reg0.0, 4, 2, 0, 0]);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        let array = producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Array { .. })).unwrap();
        assert!(!array.eligible_for_native_verification);
        assert_eq!(array.byte_size, None);
        let DebugProducerKind::Array {
            dimensions,
            occupied_byte_size,
            producer_byte_stride,
            producer_stride_present,
            ..
        } = &array.kind
        else {
            unreachable!()
        };
        assert!(*producer_stride_present);
        assert_eq!(*producer_byte_stride, None);
        assert_eq!(*occupied_byte_size, None);
        assert_eq!(dimensions[0].byte_stride, None);
        assert_eq!(dimensions[0].count, Some(2));
        assert_eq!(dimensions[0].lower_bound, Some(0));
        assert!(!dimensions[0].lower_bound_present);
        assert!(array.unsupported_reasons.iter().any(|reason| reason.contains("DW_AT_byte_stride")));
    }

    #[test]
    fn absent_c_lower_and_stride_defaults_still_produce_exact_contiguous_arrays() {
        let abbrev = [
            1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x24, 0, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 3, 0x01, 1, 0x49, 0x13, 0, 0, 4,
            0x21, 0, 0x2f, 0x0b, 0, 0, 0,
        ];
        let info = unit(&[1, 0x1d, 0, 2, 5, 4, 3, 14, 0, 0, 0, 4, 9, 0, 0]);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        let array = producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Array { .. })).unwrap();
        assert!(array.eligible_for_native_verification);
        assert_eq!(array.byte_size, Some(40));
        let DebugProducerKind::Array { dimensions, occupied_byte_size, producer_stride_present, .. } = &array.kind
        else {
            unreachable!()
        };
        assert!(!*producer_stride_present);
        assert_eq!(*occupied_byte_size, Some(40));
        assert!(!dimensions[0].lower_bound_present);
        assert_eq!(dimensions[0].lower_bound, Some(0));
        assert_eq!(dimensions[0].raw_upper_bound, Some(9));
        assert_eq!(dimensions[0].count, Some(10));
        assert_eq!(dimensions[0].byte_stride, Some(4));
        assert!(!dimensions[0].stride_present);
        let mut explicit_abbrev = abbrev.to_vec();
        let end = explicit_abbrev.len() - 3;
        drop(explicit_abbrev.splice(end..end, [0x22, 0x0b]));
        let info = unit(&[1, 0x1d, 0, 2, 5, 4, 3, 14, 0, 0, 0, 4, 9, 0, 0, 0]);
        let nodes = read_nodes(&dwarf(&info, &explicit_abbrev), &mut Budget::default()).unwrap();
        let producer = report(&nodes);
        let array = producer.types.iter().find(|ty| matches!(ty.kind, DebugProducerKind::Array { .. })).unwrap();
        assert!(array.eligible_for_native_verification);
        assert_eq!(array.byte_size, Some(40));
        let DebugProducerKind::Array { dimensions, .. } = &array.kind else { unreachable!() };
        assert!(dimensions[0].lower_bound_present);
        assert_eq!(dimensions[0].lower_bound, Some(0));
        assert_eq!(dimensions[0].count, Some(10));
    }

    #[test]
    fn bitfield_evidence_is_retained_and_invalidates_dependents_without_truncating_record() {
        let mut record = node(1, gimli::DW_TAG_structure_type);
        record.size = Some(4);
        record.children = vec![2, 3];
        let mut first = node(2, gimli::DW_TAG_member);
        first.target = TypeRef::Offset(4);
        first.bit_size = Some(1);
        first.data_bit_offset = Some(0);
        let mut second = node(3, gimli::DW_TAG_member);
        second.target = TypeRef::Offset(4);
        second.bit_size = Some(31);
        second.bit_offset = Some(0);
        second.offset = Some(0);
        second.size = Some(4);
        let mut pointer = node(5, gimli::DW_TAG_pointer_type);
        pointer.target = TypeRef::Offset(1);
        let nodes = BTreeMap::from([(1, record), (2, first), (3, second), (4, scalar(4)), (5, pointer)]);
        let producer = report(&nodes);
        let record = &producer.types[0];
        assert!(!record.eligible_for_native_verification);
        let DebugProducerKind::Record { members, .. } = &record.kind else { panic!("record evidence lost") };
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].bitfield.as_ref().unwrap().raw_storage_byte_size, None);
        assert_eq!(members[0].bitfield.as_ref().unwrap().underlying_type_byte_size, Some(4));
        assert_eq!(members[1].bitfield.as_ref().unwrap().raw_storage_byte_size, Some(4));
        assert_eq!(members[0].bitfield.as_ref().unwrap().data_bit_offset, Some(0));
        assert_eq!(members[1].bitfield.as_ref().unwrap().legacy_bit_offset, Some(0));
        assert_eq!(members[1].id.die_offset, 3);
        assert!(!producer.types.last().unwrap().eligible_for_native_verification);
        let shared = shared_report(producer, "fixture".into());
        let record = shared.types.iter().find(|ty| ty.id == "dwarf:cu:0:die:1").unwrap();
        assert!(!record.unsupported.is_empty());
        let text = serde_json::to_string(&record.kind).unwrap();
        assert!(text.contains("raw_storage_byte_size"));
        assert!(text.contains("data_bit_offset"));
        let mut packed_nodes = nodes;
        packed_nodes.get_mut(&1).unwrap().size = Some(1);
        packed_nodes.get_mut(&1).unwrap().children = vec![2];
        let packed = report(&packed_nodes);
        let DebugProducerKind::Record { members, .. } = &packed.types[0].kind else { unreachable!() };
        assert_eq!(packed.types[0].byte_size, Some(1));
        assert_eq!(members[0].bitfield.as_ref().unwrap().raw_storage_byte_size, None);
        assert_eq!(members[0].bitfield.as_ref().unwrap().underlying_type_byte_size, Some(4));
    }

    #[test]
    fn shared_fields_keep_source_names_and_reject_unrepresentable_names_without_aliasing() {
        let mut record = node(1, gimli::DW_TAG_structure_type);
        record.size = Some(8);
        record.children = vec![2, 3];
        let mut first = node(2, gimli::DW_TAG_member);
        first.offset = Some(0);
        first.target = TypeRef::Offset(4);
        first.name = Some("count".into());
        let mut second = node(3, gimli::DW_TAG_member);
        second.offset = Some(4);
        second.target = TypeRef::Offset(4);
        second.name = Some("int32_t".into());
        let mut other_record = node(5, gimli::DW_TAG_structure_type);
        other_record.size = Some(4);
        other_record.children = vec![6];
        let mut other_member = node(6, gimli::DW_TAG_member);
        other_member.offset = Some(0);
        other_member.target = TypeRef::Offset(4);
        other_member.name = Some("count".into());
        let mut nodes = BTreeMap::from([
            (1, record),
            (2, first),
            (3, second),
            (4, scalar(4)),
            (5, other_record),
            (6, other_member),
        ]);
        let shared = shared_report(report(&nodes), "fixture".into());
        let record = shared.types.iter().find(|ty| ty.id == shared_id(nodes[&1].id)).unwrap();
        assert!(record.unsupported.is_empty());
        let crate::debug_types::DebugTypeKind::Struct { members } = &record.kind else { unreachable!() };
        assert_eq!(members[0].name.as_deref(), Some("count"));
        assert_eq!(members[1].name.as_deref(), Some("int32_t"));
        assert!(shared.types.iter().find(|ty| ty.id == shared_id(nodes[&5].id)).unwrap().unsupported.is_empty());
        for name in [None, Some("bad-name"), Some("while"), Some("count")] {
            nodes.get_mut(&3).unwrap().name = name.map(str::to_owned);
            let shared = shared_report(report(&nodes), "fixture".into());
            let record = shared.types.iter().find(|ty| ty.id == shared_id(nodes[&1].id)).unwrap();
            assert!(!record.unsupported.is_empty());
            let crate::debug_types::DebugTypeKind::Struct { members } = &record.kind else { unreachable!() };
            assert_eq!(members[1].name.as_deref(), name);
            assert!(!members[1].unsupported.is_empty());
            if name == Some("count") {
                assert!(!members[0].unsupported.is_empty());
            }
        }
    }

    #[test]
    fn function_source_names_are_not_replaced_with_generated_declaration_names() {
        let mut function = node(1, gimli::DW_TAG_subprogram);
        function.name = Some("source_query".into());
        function.linkage_name = Some("_Z12source_queryv".into());
        function.address = Some(0x1000);
        function.prototyped = true;
        let mut nodes = BTreeMap::from([(1, function)]);
        let shared = shared_report(report(&nodes), "fixture".into());
        assert_eq!(shared.signatures[0].name.as_deref(), Some("source_query"));
        assert_eq!(shared.signatures[0].address, 0x1000);
        let ty = shared.types.iter().find(|ty| ty.id == shared.signatures[0].type_id).unwrap();
        assert_eq!(ty.original_name.as_deref(), Some("source_query"));
        assert_ne!(ty.emitted_name.as_deref(), shared.signatures[0].name.as_deref());
        nodes.get_mut(&1).unwrap().name = None;
        let shared = shared_report(report(&nodes), "fixture".into());
        assert_eq!(shared.signatures[0].name.as_deref(), Some("_Z12source_queryv"));
        nodes.get_mut(&1).unwrap().linkage_name = None;
        let shared = shared_report(report(&nodes), "fixture".into());
        assert_eq!(shared.signatures[0].name, None);
        let abbrev = [1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x2e, 0, 0x6e, 0x08, 0x27, 0x0c, 0x11, 0x01, 0, 0, 0];
        let mut entries = b"\x01\x1d\0\x02producer_linkage_only\0\x01".to_vec();
        entries.extend_from_slice(&0x1000u64.to_le_bytes());
        entries.push(0);
        let info = unit(&entries);
        let nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
        let shared = shared_report(report(&nodes), "fixture".into());
        assert_eq!(shared.signatures[0].name.as_deref(), Some("producer_linkage_only"));
        assert_eq!(shared.signatures[0].address, 0x1000);
    }

    #[test]
    fn shared_enumerator_names_remain_original_and_bad_names_do_not_become_id_aliases() {
        let mut enumeration = node(2, gimli::DW_TAG_enumeration_type);
        enumeration.target = TypeRef::Offset(1);
        enumeration.children = vec![3, 4];
        let mut ready = node(3, gimli::DW_TAG_enumerator);
        ready.name = Some("DEBUG_READY".into());
        ready.value = Some(DebugProducerConstant {
            form: gimli::DW_FORM_sdata.0,
            byte_width: None,
            value: DebugProducerInteger::Signed(7),
        });
        let mut fault = node(4, gimli::DW_TAG_enumerator);
        fault.name = Some("DEBUG_FAULT".into());
        fault.value = Some(DebugProducerConstant {
            form: gimli::DW_FORM_sdata.0,
            byte_width: None,
            value: DebugProducerInteger::Signed(-3),
        });
        let mut nodes = BTreeMap::from([(1, scalar(1)), (2, enumeration), (3, ready), (4, fault)]);
        let shared = shared_report(report(&nodes), "fixture".into());
        let enumeration = shared.types.iter().find(|ty| ty.id == shared_id(nodes[&2].id)).unwrap();
        assert!(enumeration.unsupported.is_empty());
        let crate::debug_types::DebugTypeKind::Enum { values, .. } = &enumeration.kind else { unreachable!() };
        assert_eq!(values[0].name, "DEBUG_READY");
        assert_eq!(values[0].value, "7");
        assert_eq!(values[1].name, "DEBUG_FAULT");
        assert_eq!(values[1].value, "-3");
        for name in [None, Some("bad-name"), Some("while"), Some("DEBUG_READY")] {
            nodes.get_mut(&4).unwrap().name = name.map(str::to_owned);
            let shared = shared_report(report(&nodes), "fixture".into());
            let enumeration = shared.types.iter().find(|ty| ty.id == shared_id(nodes[&2].id)).unwrap();
            assert!(!enumeration.unsupported.is_empty());
            let crate::debug_types::DebugTypeKind::Enum { values, .. } = &enumeration.kind else { unreachable!() };
            assert_eq!(values[1].name, name.unwrap_or_default());
            assert_ne!(values[1].name, emitted(nodes[&4].id));
        }
    }

    #[test]
    fn omitted_prototype_attributes_use_only_recognized_cpp_language_semantics() {
        let abbrev = [1, 0x11, 1, 0x13, 0x05, 0, 0, 2, 0x2e, 0, 0x03, 0x08, 0x11, 0x01, 0, 0, 3, 0x15, 0, 0, 0, 0];
        for language in [
            gimli::DW_LANG_C11,
            gimli::DW_LANG_C_plus_plus,
            gimli::DW_LANG_C_plus_plus_11,
            gimli::DW_LANG_C_plus_plus_14,
            gimli::DW_LANG_C_plus_plus_17,
        ] {
            let mut entries = vec![1];
            entries.extend_from_slice(&language.0.to_le_bytes());
            entries.extend_from_slice(b"\x02_Znot_a_language_witness\0");
            entries.extend_from_slice(&0x1000u64.to_le_bytes());
            entries.extend_from_slice(&[3, 0]);
            let info = unit(&entries);
            let mut nodes = read_nodes(&dwarf(&info, &abbrev), &mut Budget::default()).unwrap();
            let producer = report(&nodes);
            let function = &producer.functions[0];
            assert_eq!(function.prototype.producer_prototyped, None);
            assert!(!function.prototype.producer_prototyped_present);
            if language == gimli::DW_LANG_C11 {
                assert!(!function.eligible_for_native_verification);
                assert_eq!(function.prototype.prototype_basis, None);
                assert!(!producer.types[0].eligible_for_native_verification);
            } else {
                assert!(function.eligible_for_native_verification, "{:?}", function.unsupported_reasons);
                assert!(function.prototype.prototyped);
                assert_eq!(
                    function.prototype.prototype_basis,
                    Some(DebugProducerPrototypeBasis::CppLanguage { language: language.0 })
                );
                assert!(producer.types[0].eligible_for_native_verification);
                let shared = shared_report(producer, "fixture".into());
                assert!(shared.signatures[0].unsupported.is_empty());
            }
            let function = nodes.values_mut().find(|node| node.tag == gimli::DW_TAG_subprogram).unwrap();
            function.prototyped_present = true;
            function.prototyped_attribute = Some(false);
            assert!(!report(&nodes).functions[0].eligible_for_native_verification);
            let function = nodes.values_mut().find(|node| node.tag == gimli::DW_TAG_subprogram).unwrap();
            function.prototyped_attribute = None;
            function.reject("invalid flag attribute");
            let producer = report(&nodes);
            assert!(!producer.functions[0].eligible_for_native_verification);
            assert_eq!(producer.functions[0].prototype.prototype_basis, None);
        }
    }

    #[test]
    fn runtime_member_expressions_are_never_evaluated() {
        fn expr(bytes: &[u8]) -> AttributeValue<DebugReader<'_>> {
            AttributeValue::Exprloc(gimli::Expression(EndianSlice::new(bytes, RunTimeEndian::Little)))
        }
        assert_eq!(member_offset(expr(&[gimli::DW_OP_plus_uconst.0, 12])), Some(12));
        assert_eq!(member_offset(expr(&[gimli::DW_OP_constu.0, 12, gimli::DW_OP_plus.0])), Some(12));
        assert_eq!(member_offset(expr(&[gimli::DW_OP_deref.0])), None);
        assert_eq!(member_offset(expr(&[gimli::DW_OP_fbreg.0, 0])), None);
        assert_eq!(member_offset(expr(&[gimli::DW_OP_plus_uconst.0, 12, gimli::DW_OP_deref.0])), None);
    }

    fn fixture_dir() -> Option<PathBuf> {
        let value = std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES")?;
        if value == "1" {
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/phase1-6"))
        } else {
            Some(PathBuf::from(value))
        }
    }

    fn constant_table(binary: &Binary) -> Vec<u32> {
        let object = object::File::parse(binary.image_bytes()).unwrap();
        let symbol = object
            .symbols()
            .find(|symbol| matches!(symbol.name(), Ok("debug_type_layout" | "_debug_type_layout")))
            .expect("compiler layout constant table");
        let section = object.section_by_index(symbol.section_index().unwrap()).unwrap();
        let start = usize::try_from(symbol.address().checked_sub(section.address()).unwrap()).unwrap();
        section.data().unwrap()[start..start + 14 * 4]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect()
    }

    #[test]
    fn opt_in_generated_elf_graphs_match_compiler_constant_tables_without_execution() {
        let Some(directory) = fixture_dir() else {
            return;
        };
        for name in ["debug-types-x64.elf", "debug-types-arm64.elf"] {
            let binary = Binary::open(directory.join(name)).unwrap();
            let constants = constant_table(&binary);
            let producer = producer_type_graph(&binary).unwrap();
            let ty = |name: &str| producer.types.iter().find(|ty| ty.original_name.as_deref() == Some(name)).unwrap();
            let record = ty("DebugRecord");
            assert_eq!(record.byte_size, Some(u64::from(constants[2])));
            assert_eq!(ty("DebugInner").byte_size, Some(u64::from(constants[0])));
            assert_eq!(ty("DebugPayload").byte_size, Some(u64::from(constants[11])));
            for (ty, alignment) in
                [(record, constants[3]), (ty("DebugInner"), constants[1]), (ty("DebugPayload"), constants[12])]
            {
                if let Some(producer_alignment) = ty.producer_alignment {
                    assert_eq!(producer_alignment, u64::from(alignment));
                }
            }
            assert!(record.eligible_for_native_verification, "{name}: {:?}", record.unsupported_reasons);
            let DebugProducerKind::Record { members, .. } = &record.kind else { panic!("record kind") };
            assert_eq!(members.len(), 7);
            let shared = type_graph(&binary).unwrap();
            let shared_record = shared.types.iter().find(|ty| ty.id == shared_id(record.id)).unwrap();
            assert!(shared_record.unsupported.is_empty(), "{:?}", shared_record.unsupported);
            let crate::debug_types::DebugTypeKind::Struct { members: shared_members } = &shared_record.kind else {
                panic!("shared record kind")
            };
            let expected_names = ["identifier", "nested", "taps", "mode", "payload", "next", "callback"];
            assert_eq!(
                members.iter().map(|member| member.original_name.as_deref()).collect::<Vec<_>>(),
                expected_names.map(Some)
            );
            assert_eq!(
                shared_members.iter().map(|member| member.name.as_deref()).collect::<Vec<_>>(),
                expected_names.map(Some)
            );
            for (member, &offset) in members.iter().zip(&constants[4..11]) {
                assert_eq!(member.byte_offset, Some(offset.into()));
            }
            let array = producer.types.iter().find(|ty| Some(ty.id) == members[2].ty).unwrap();
            assert_eq!(array.byte_size, Some(16));
            let DebugProducerKind::Array { dimensions, .. } = &array.kind else { panic!("array kind") };
            assert_eq!(dimensions[0].count, Some(2));
            assert_eq!(dimensions[0].byte_stride, Some(8));
            let DebugProducerKind::Enum { values, .. } = &ty("DebugMode").kind else { panic!("enum kind") };
            let shared_mode = shared.types.iter().find(|mode| mode.id == shared_id(ty("DebugMode").id)).unwrap();
            let crate::debug_types::DebugTypeKind::Enum { values: shared_values, .. } = &shared_mode.kind else {
                panic!("shared enum kind")
            };
            assert!(shared_mode.unsupported.is_empty(), "{:?}", shared_mode.unsupported);
            assert_eq!(
                shared_values.iter().map(|value| value.name.as_str()).collect::<Vec<_>>(),
                ["DEBUG_OFF", "DEBUG_READY", "DEBUG_FAULT"]
            );
            assert_eq!(shared_values.iter().map(|value| value.value.as_str()).collect::<Vec<_>>(), ["0", "7", "-3"]);
            assert!(values.iter().any(|value| matches!(value.value, Some(DebugProducerInteger::Signed(-3)))));
            assert!(values.iter().any(|value| matches!(
                value.value,
                Some(DebugProducerInteger::Signed(7) | DebugProducerInteger::Unsigned(7))
            )));
            let bits = ty("DebugBits");
            assert_eq!(bits.byte_size, Some(constants[13].into()));
            assert!(!bits.eligible_for_native_verification);
            let DebugProducerKind::Record { members, .. } = &bits.kind else { panic!("bitfield record kind") };
            assert_eq!(members.len(), 3);
            assert!(members.iter().all(|member| member.bitfield.is_some()));
            assert!(
                producer
                    .functions
                    .iter()
                    .any(|function| function.original_name.as_deref() == Some("debug_types_query")
                        && function.eligible_for_native_verification)
            );
            for source_name in ["debug_types_query", "debug_types_identity", "debug_types_main"] {
                let function = producer
                    .functions
                    .iter()
                    .find(|function| function.original_name.as_deref() == Some(source_name))
                    .unwrap();
                let signature =
                    shared.signatures.iter().find(|signature| signature.type_id == shared_id(function.id)).unwrap();
                assert_eq!(signature.name.as_deref(), Some(source_name));
                assert_eq!(Some(signature.address), function.address);
            }
        }
    }

    #[test]
    fn opt_in_generated_cpp_graph_keeps_original_field_and_addressed_function_names() {
        let Some(directory) = fixture_dir() else {
            return;
        };
        let binary = Binary::open(directory.join("debug-cpp-x64.elf")).unwrap();
        let producer = producer_type_graph(&binary).unwrap();
        let shared = type_graph(&binary).unwrap();
        for (source_name, expected_names) in
            [("DebugOwner", vec!["cells", "bias", "next"]), ("DebugCell", vec!["count", "level"])]
        {
            let candidates: Vec<_> = producer
                .types
                .iter()
                .filter(|ty| {
                    ty.original_name.as_deref() == Some(source_name)
                        && matches!(ty.kind, DebugProducerKind::Record { .. })
                        && ty.unsupported_reasons.is_empty()
                })
                .collect();
            assert_eq!(candidates.len(), 1, "exact complete fixture record {source_name}");
            let record = shared.types.iter().find(|ty| ty.id == shared_id(candidates[0].id)).unwrap();
            let crate::debug_types::DebugTypeKind::Struct { members } = &record.kind else {
                panic!("shared record kind")
            };
            assert_eq!(
                members.iter().map(|member| member.name.as_deref()).collect::<Vec<_>>(),
                expected_names.into_iter().map(Some).collect::<Vec<_>>()
            );
        }
        let object = object::File::parse(binary.image_bytes()).unwrap();
        let symbols: Vec<_> =
            object.symbols().filter(|symbol| matches!(symbol.name(), Ok("debug_cpp_query"))).collect();
        assert_eq!(symbols.len(), 1, "exact fixture wrapper symbol");
        let signatures: Vec<_> =
            shared.signatures.iter().filter(|signature| signature.address == symbols[0].address()).collect();
        assert_eq!(signatures.len(), 1, "exact addressed producer wrapper");
        assert_eq!(signatures[0].name.as_deref(), Some("debug_cpp_query"));
        assert!(signatures[0].unsupported.is_empty(), "{:?}", signatures[0].unsupported);
        let producer_wrapper =
            producer.functions.iter().find(|function| function.address == Some(signatures[0].address)).unwrap();
        assert!(producer_wrapper.prototype.prototyped);
        assert!(producer_wrapper.prototype.prototype_basis.is_some());
        if producer_wrapper.prototype.producer_prototyped.is_none() {
            assert_eq!(
                producer_wrapper.prototype.prototype_basis,
                Some(DebugProducerPrototypeBasis::CppLanguage {
                    language: producer_wrapper.source.as_ref().unwrap().language,
                })
            );
        }
        let function_type = shared.types.iter().find(|ty| ty.id == signatures[0].type_id).unwrap();
        assert_eq!(function_type.original_name.as_deref(), Some("debug_cpp_query"));
        assert_ne!(function_type.emitted_name.as_deref(), signatures[0].name.as_deref());
    }
}
