use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::{
    DebugReader, MAX_ATTRIBUTES, MAX_DEBUG_BYTES, MAX_DIES, MAX_NESTING, MAX_TYPE_DEPTH, MAX_UNITS, TypeRef, WARNINGS,
    bounded_name_limit, c_name, validate_abbreviations_work,
};
use crate::{Binary, Format, LoadError};
use gimli::{AttributeValue, Dwarf, EndianSlice, Reader, RunTimeEndian, Section, Unit};
use object::{CompressionFormat, Object, ObjectKind, ObjectSection};
use serde::Serialize;

const MAX_NAMES: usize = 32 * 1024;
const MAX_NAME: usize = 128;
const MAX_SIZE: u64 = 1024 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_LAYOUTS: usize = 128;
const MAX_TOTAL_FIELDS: usize = 4096;
const MAX_EDGES: usize = 8192;
const MAX_TYPES: usize = 4096;
const MAX_NODES: usize = 16384;
const MAX_SIGNATURES: usize = 256;
const MAX_FUNCTIONS: usize = 1024;
const MAX_DECLARATIONS: usize = 256 * 1024;
const MAX_DECLARATION: usize = 4095;
const MAX_WORK: usize = 262144;
const MAX_READ_WORK: usize = 262144;
const NAME_READ_RESERVATION: usize = 4 * (MAX_NAME + 1) + 64;

/// Both offsets are absolute byte offsets in embedded `.debug_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DebugLayoutTypeId {
    pub unit_offset: u64,
    pub die_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugLayoutSource {
    pub unit_offset: u64,
    pub language: u16,
    pub dwarf_version: u16,
    pub address_size: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugLayoutScalarKind {
    SignedInteger,
    UnsignedInteger,
    Float,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugLayoutScalar {
    pub id: DebugLayoutTypeId,
    pub kind: DebugLayoutScalarKind,
    pub byte_size: u64,
    pub encoding: u8,
    pub producer_alignment: Option<u64>,
    pub original_name: Option<String>,
    pub declaration: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugLayoutLeaf {
    Scalar {
        scalar: DebugLayoutScalar,
    },
    Pointer {
        id: DebugLayoutTypeId,
        byte_size: u64,
        producer_alignment: Option<u64>,
        pointee: Option<DebugLayoutScalar>,
    },
}

impl DebugLayoutLeaf {
    fn alignment_proven(&self) -> bool {
        match self {
            Self::Scalar { scalar } => scalar.producer_alignment.is_some(),
            Self::Pointer { producer_alignment, pointee, .. } => {
                producer_alignment.is_some()
                    && pointee.as_ref().is_none_or(|scalar| scalar.producer_alignment.is_some())
            }
        }
    }
    fn alignment(&self) -> Option<u64> {
        match self {
            Self::Scalar { scalar } => scalar.producer_alignment,
            Self::Pointer { producer_alignment, .. } => *producer_alignment,
        }
    }
    fn size(&self) -> u64 {
        match self {
            Self::Scalar { scalar } => scalar.byte_size,
            Self::Pointer { byte_size, .. } => *byte_size,
        }
    }

    fn declaration(&self) -> String {
        match self {
            Self::Scalar { scalar } => scalar.declaration.clone(),
            Self::Pointer { pointee, .. } => {
                format!("{} *", pointee.as_ref().map_or("void", |scalar| scalar.declaration.as_str()))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugLayoutField {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub offset: u64,
    pub byte_size: u64,
    pub producer_alignment: Option<u64>,
    pub leaf: DebugLayoutLeaf,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugStructLayout {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub byte_size: u64,
    pub producer_alignment: Option<u64>,
    pub fields: Vec<DebugLayoutField>,
    pub source: DebugLayoutSource,
    pub strictly_applicable: bool,
    /// Complete supported candidate with explicit struct alignment, not a verified native layout.
    pub eligible_for_native_verification: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugLayoutValue {
    Void,
    Leaf {
        leaf: DebugLayoutLeaf,
    },
    StructPointer {
        pointer_id: DebugLayoutTypeId,
        layout_id: DebugLayoutTypeId,
        byte_size: u64,
        producer_alignment: Option<u64>,
    },
}

impl DebugLayoutValue {
    fn alignment_proven(&self) -> bool {
        match self {
            Self::Void => true,
            Self::Leaf { leaf } => leaf.alignment_proven(),
            Self::StructPointer { producer_alignment, .. } => producer_alignment.is_some(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugLayoutParameter {
    pub id: DebugLayoutTypeId,
    pub original_name: Option<String>,
    pub emitted_name: String,
    pub ty: DebugLayoutValue,
}

/// Exact concrete-method association through one same-CU definition-to-declaration specification.
#[derive(Debug, Clone, Serialize)]
pub struct DebugLayoutMethod {
    pub record_id: DebugLayoutTypeId,
    pub declaration_id: DebugLayoutTypeId,
    /// The definition's actual first formal, explicitly referenced by `DW_AT_object_pointer`.
    pub object_pointer_id: DebugLayoutTypeId,
    pub linkage_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugLayoutSignature {
    pub id: DebugLayoutTypeId,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub original_name: String,
    pub emitted_name: String,
    pub declaration: String,
    pub return_type: DebugLayoutValue,
    pub parameters: Vec<DebugLayoutParameter>,
    pub dependencies: Vec<DebugLayoutTypeId>,
    pub source: DebugLayoutSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<DebugLayoutMethod>,
    pub strictly_applicable: bool,
    /// Requires checked native counterpart evidence before any unknown alignment can be admitted.
    pub eligible_for_native_verification: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct DebugLayoutReport {
    pub layouts: Vec<DebugStructLayout>,
    pub signatures: Vec<DebugLayoutSignature>,
    pub warnings: Vec<String>,
}

impl DebugLayoutReport {
    fn warn(&mut self, message: String) {
        WARNINGS.push(&mut self.warnings, message);
    }
}

/// Explicit flat-record preview, separate from scalar-only `signatures`.
/// Unknown producer alignment is retained as unknown and is never strictly applicable.
/// Addresses identify entry points only. Absent high_pc does not establish a function extent.
/// An incomplete concrete address index refuses the whole preview; explicitly proven abstract C inline
/// metadata and body-only inline arguments are not imported as concrete function prototypes.
pub fn layout_signatures(binary: &Binary) -> Result<DebugLayoutReport, LoadError> {
    let mut report = DebugLayoutReport::default();
    if binary.format != Format::Elf || binary.arch != rampage_arch::Arch::X86_64 {
        report.warn("DWARF layout preview requires x86_64 little-endian ELF".to_owned());
        return Ok(report);
    }
    let object = object::File::parse(binary.image_bytes())?;
    if object.kind() == ObjectKind::Relocatable {
        report.warn("relocatable DWARF layouts and addresses are unsupported".to_owned());
        return Ok(report);
    }
    if object.format() != object::BinaryFormat::Elf
        || object.architecture() != object::Architecture::X86_64
        || !object.is_little_endian()
        || !object.is_64()
    {
        report.warn("DWARF layout preview requires x86_64 little-endian ELF64".to_owned());
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
        report.warn("no embedded DWARF .debug_info; external debug files are not searched".to_owned());
        return Ok(report);
    }
    let nodes = match read_layout_nodes(&dwarf) {
        Ok(nodes) => nodes,
        Err(error) => {
            report.warn(format!("DWARF layout preview stopped: {error}"));
            return Ok(report);
        }
    };
    build_report(
        &nodes,
        |address| binary.code_from(address).is_some_and(|bytes| !bytes.is_empty()),
        |start, end| {
            binary
                .code_from(start)
                .is_some_and(|bytes| end.checked_sub(start).is_some_and(|size| size <= bytes.len() as u64))
        },
        &mut report,
    );
    Ok(report)
}

fn embedded_dwarf<'a>(object: &object::File<'a>) -> Result<Dwarf<DebugReader<'a>>, String> {
    let mut total = 0usize;
    let mut names = BTreeSet::new();
    for section in object.sections() {
        let name = section.name().map_err(|error| error.to_string())?;
        if matches!(name, ".gnu_debuglink" | ".gnu_debugaltlink" | ".debug_sup" | ".debug_types")
            || name.ends_with(".dwo")
            || matches!(name, ".debug_cu_index" | ".debug_tu_index")
            || name.starts_with(".rela.debug_")
            || name.starts_with(".rel.debug_")
        {
            return Err("external, split, or type-unit DWARF layout context is unsupported".to_owned());
        }
        if !name.starts_with(".debug_") && !name.starts_with(".zdebug_") {
            continue;
        }
        if !names.insert(name) {
            return Err("duplicate DWARF section names cannot establish unique layout evidence".to_owned());
        }
        let size = usize::try_from(section.size()).map_err(|_| "DWARF section size overflow".to_owned())?;
        total = total
            .checked_add(size)
            .filter(|&size| size <= MAX_DEBUG_BYTES)
            .ok_or_else(|| "DWARF exceeds the 64 MiB section-byte limit".to_owned())?;
        if name.starts_with(".zdebug_")
            || section.compressed_file_range().map_err(|error| error.to_string())?.format != CompressionFormat::None
        {
            return Err("compressed DWARF layout context is unsupported".to_owned());
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
        let Some(section) = object.section_by_name(id.name()) else {
            return Ok(EndianSlice::new(&[], RunTimeEndian::Little));
        };
        let data = section.data().map_err(|error| error.to_string())?;
        if data.len() as u64 != section.size() {
            return Err("DWARF section data does not match its declared size".to_owned());
        }
        Ok(EndianSlice::new(data, RunTimeEndian::Little))
    })
}

#[derive(Debug, Clone)]
struct LayoutNode {
    id: DebugLayoutTypeId,
    tag: gimli::DwTag,
    parent: Option<usize>,
    children: Vec<usize>,
    source: Option<DebugLayoutSource>,
    name: Option<String>,
    linkage_name: Option<String>,
    specification: TypeRef,
    object_pointer: TypeRef,
    artificial: bool,
    target: TypeRef,
    size: Option<u64>,
    alignment: Option<u64>,
    member_offset: Option<u64>,
    encoding: Option<gimli::DwAte>,
    address: Option<u64>,
    address_end: Option<u64>,
    address_evidence: bool,
    address_index_incomplete: bool,
    inline: Option<gimli::DwInl>,
    declaration: bool,
    prototyped: bool,
    invalid: bool,
}

enum HighPc {
    Address(u64),
    Offset(u64),
}

fn is_type(tag: gimli::DwTag) -> bool {
    // Budget type-related and recognized vendor type DIEs even when resolution refuses their categories.
    matches!(
        tag,
        gimli::DW_TAG_base_type
            | gimli::DW_TAG_typedef
            | gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_array_type
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
            | gimli::DW_TAG_subroutine_type
            | gimli::DW_TAG_enumeration_type
            | gimli::DW_TAG_atomic_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_string_type
            | gimli::DW_TAG_ptr_to_member_type
            | gimli::DW_TAG_set_type
            | gimli::DW_TAG_subrange_type
            | gimli::DW_TAG_file_type
            | gimli::DW_TAG_packed_type
            | gimli::DW_TAG_template_type_parameter
            | gimli::DW_TAG_thrown_type
            | gimli::DW_TAG_interface_type
            | gimli::DW_TAG_unspecified_type
            | gimli::DW_TAG_shared_type
            | gimli::DW_TAG_template_alias
            | gimli::DW_TAG_coarray_type
            | gimli::DW_TAG_generic_subrange
            | gimli::DW_TAG_dynamic_type
            | gimli::DW_TAG_immutable_type
            | gimli::DW_TAG_HP_array_descriptor
            | gimli::DW_TAG_class_template
            | gimli::DW_TAG_GNU_template_template_param
            | gimli::DW_TAG_SUN_class_template
            | gimli::DW_TAG_SUN_struct_template
            | gimli::DW_TAG_SUN_union_template
            | gimli::DW_TAG_SUN_f90_interface
            | gimli::DW_TAG_SUN_fortran_vax_structure
            | gimli::DW_TAG_ALTIUM_circ_type
            | gimli::DW_TAG_ALTIUM_mwa_circ_type
            | gimli::DW_TAG_ALTIUM_rev_carry_type
            | gimli::DW_TAG_upc_shared_type
            | gimli::DW_TAG_upc_strict_type
            | gimli::DW_TAG_upc_relaxed_type
            | gimli::DW_TAG_PGI_kanji_type
            | gimli::DW_TAG_BORLAND_Delphi_string
            | gimli::DW_TAG_BORLAND_Delphi_dynamic_array
            | gimli::DW_TAG_BORLAND_Delphi_set
            | gimli::DW_TAG_BORLAND_Delphi_variant
    )
}

fn constant(value: AttributeValue<DebugReader<'_>>) -> Option<u64> {
    match value {
        AttributeValue::Data1(value) => Some(u64::from(value)),
        AttributeValue::Data2(value) => Some(u64::from(value)),
        AttributeValue::Data4(value) => Some(u64::from(value)),
        AttributeValue::Data8(value) => Some(value),
        AttributeValue::Udata(value) => Some(value),
        AttributeValue::Sdata(value) => u64::try_from(value).ok(),
        _ => None,
    }
}

fn supported_language(language: gimli::DwLang) -> bool {
    matches!(
        language,
        gimli::DW_LANG_C89 | gimli::DW_LANG_C | gimli::DW_LANG_C99 | gimli::DW_LANG_C11 | gimli::DW_LANG_C17
    ) || cpp_language(language.0)
}

fn cpp_language(language: u16) -> bool {
    matches!(
        gimli::DwLang(language),
        gimli::DW_LANG_C_plus_plus
            | gimli::DW_LANG_C_plus_plus_11
            | gimli::DW_LANG_C_plus_plus_14
            | gimli::DW_LANG_C_plus_plus_17
    )
}

fn cpp_node(node: &LayoutNode) -> bool {
    node.source.as_ref().is_some_and(|source| cpp_language(source.language))
}

fn record_tag(tag: gimli::DwTag) -> bool {
    matches!(tag, gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type)
}

#[derive(Default)]
struct ReadBudget {
    reserved: usize,
    rejected_reservations: usize,
    abbreviation_tables: usize,
    root_passes: usize,
}

impl ReadBudget {
    fn reserve(&mut self, bytes: usize) -> Result<(), String> {
        let next = self.reserved.checked_add(bytes).filter(|&bytes| bytes <= MAX_READ_WORK);
        match next {
            Some(next) => {
                self.reserved = next;
                Ok(())
            }
            None => {
                self.rejected_reservations += 1;
                Err("DWARF cumulative pre-read work limit exceeded".to_owned())
            }
        }
    }
}

struct UnitProof<'a> {
    unit: Unit<DebugReader<'a>>,
    strings_base: bool,
    addresses_base: bool,
}

fn layout_unit<'a>(
    dwarf: &Dwarf<DebugReader<'a>>,
    header: gimli::UnitHeader<DebugReader<'a>>,
    cache: &mut BTreeMap<usize, Arc<gimli::Abbreviations>>,
    budget: &mut ReadBudget,
    work: &mut usize,
) -> Result<UnitProof<'a>, String> {
    let offset = header.debug_abbrev_offset();
    let abbreviations = match cache.get(&offset.0) {
        Some(abbreviations) => Arc::clone(abbreviations),
        None => {
            let suffix = dwarf
                .debug_abbrev
                .reader()
                .len()
                .checked_sub(offset.0)
                .ok_or_else(|| "DWARF abbreviation offset is outside the section".to_owned())?;
            // Reserve both complete passes before validation or gimli allocation, including failed parses.
            budget.reserve(suffix.checked_mul(2).ok_or_else(|| "DWARF read-work size overflow".to_owned())?)?;
            validate_abbreviations_work(dwarf, offset, work, MAX_WORK, true)
                .map_err(|error| format!("DWARF abbreviation work limit or malformed table: {error}"))?;
            budget.abbreviation_tables += 1;
            let abbreviations = Arc::new(dwarf.debug_abbrev.abbreviations(offset).map_err(|error| error.to_string())?);
            cache.insert(offset.0, Arc::clone(&abbreviations));
            abbreviations
        }
    };
    let encoding = header.encoding();
    let mut unit = Unit {
        abbreviations,
        name: None,
        comp_dir: None,
        low_pc: 0,
        str_offsets_base: gimli::DebugStrOffsetsBase::default_for_encoding_and_file(encoding, dwarf.file_type),
        addr_base: gimli::DebugAddrBase(0),
        loclists_base: gimli::DebugLocListsBase::default_for_encoding_and_file(encoding, dwarf.file_type),
        rnglists_base: gimli::DebugRngListsBase::default_for_encoding_and_file(encoding, dwarf.file_type),
        line_program: None,
        dwo_id: None,
        header,
    };
    let mut strings_base = None;
    let mut addresses_base = None;
    {
        budget.root_passes += 1;
        let mut entries = unit.header.entries_raw(&unit.abbreviations, None).map_err(|error| error.to_string())?;
        *work += 1;
        if *work > MAX_WORK {
            return Err("DWARF cumulative root work limit exceeded".to_owned());
        }
        let root = entries
            .read_abbreviation()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "missing DWARF compilation unit root".to_owned())?;
        if root.tag() != gimli::DW_TAG_compile_unit {
            return Err("partial or unsupported DWARF unit root".to_owned());
        }
        let mut names = BTreeSet::new();
        for spec in root.attributes() {
            *work += 1;
            if *work > MAX_WORK {
                return Err("DWARF cumulative root attribute work limit exceeded".to_owned());
            }
            let attr = entries.read_attribute(*spec).map_err(|error| error.to_string())?;
            if !names.insert(attr.name()) {
                return Err(format!("duplicate DWARF root attribute {}", attr.name()));
            }
            match attr.name() {
                gimli::DW_AT_str_offsets_base => {
                    if encoding.version < 5 || attr.form() != gimli::DW_FORM_sec_offset {
                        return Err("malformed DWARF string-offset base form/context".to_owned());
                    }
                    let AttributeValue::DebugStrOffsetsBase(base) = attr.value() else {
                        return Err("malformed DWARF string-offset base value".to_owned());
                    };
                    strings_base = Some(base);
                }
                gimli::DW_AT_addr_base | gimli::DW_AT_GNU_addr_base => {
                    if attr.form() != gimli::DW_FORM_sec_offset
                        || (attr.name() == gimli::DW_AT_addr_base && encoding.version < 5)
                        || (attr.name() == gimli::DW_AT_GNU_addr_base && encoding.version < 4)
                    {
                        return Err("malformed DWARF address base form/context".to_owned());
                    }
                    let AttributeValue::DebugAddrBase(base) = attr.value() else {
                        return Err("malformed DWARF address base value".to_owned());
                    };
                    if addresses_base.is_some() {
                        return Err("duplicate or conflicting GNU/standard DWARF address bases".to_owned());
                    }
                    addresses_base = Some(base);
                }
                gimli::DW_AT_dwo_name | gimli::DW_AT_GNU_dwo_name | gimli::DW_AT_GNU_dwo_id => {
                    return Err("split DWARF is unsupported".to_owned());
                }
                _ => {}
            }
        }
    }
    if let Some(base) = strings_base {
        unit.str_offsets_base = base;
    }
    if let Some(base) = addresses_base {
        unit.addr_base = base;
    }
    Ok(UnitProof { unit, strings_base: strings_base.is_some(), addresses_base: addresses_base.is_some() })
}

fn read_layout_nodes(dwarf: &Dwarf<DebugReader<'_>>) -> Result<BTreeMap<usize, LayoutNode>, String> {
    read_layout_nodes_budget(dwarf, &mut ReadBudget::default())
}

fn read_layout_nodes_budget(
    dwarf: &Dwarf<DebugReader<'_>>,
    budget: &mut ReadBudget,
) -> Result<BTreeMap<usize, LayoutNode>, String> {
    // Header/main DIE reads plus the extra root pass are bounded by twice all .debug_info bytes.
    // This reservation precedes even header parsing, so unknown inline attributes cannot bypass it.
    let info_bytes =
        dwarf.debug_info.reader().len().checked_mul(2).ok_or_else(|| "DWARF read-work size overflow".to_owned())?;
    budget.reserve(info_bytes)?;
    let mut abbreviations = BTreeMap::new();
    let mut nodes: BTreeMap<usize, LayoutNode> = BTreeMap::new();
    let mut units = dwarf.units();
    let mut unit_count = 0;
    let mut names = 0;
    let mut work = 0;
    let mut types = 0;
    let mut layouts = 0;
    let mut fields = 0;
    let mut functions = 0;
    let mut parameters = 0;
    let mut edges = 0;
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        unit_count += 1;
        if unit_count > MAX_UNITS {
            return Err("DWARF unit limit exceeded (256)".to_owned());
        }
        if header.type_() != gimli::UnitType::Compilation {
            return Err("partial, split, or type-unit DWARF is unsupported".to_owned());
        }
        let unit_offset =
            header.offset().to_debug_info_offset(&header).ok_or_else(|| "unit is not in .debug_info".to_owned())?.0;
        let proof = layout_unit(dwarf, header, &mut abbreviations, budget, &mut work)?;
        let unit = proof.unit;
        let mut source = None;
        let mut entries = unit.header.entries_raw(&unit.abbreviations, None).map_err(|error| error.to_string())?;
        let mut parents = Vec::new();
        while !entries.is_empty() {
            work += 1;
            if work > MAX_WORK {
                return Err("DWARF cumulative entry work limit exceeded".to_owned());
            }
            let depth = entries.next_depth();
            let relative_offset = entries.next_offset();
            let Some(abbreviation) = entries.read_abbreviation().map_err(|error| error.to_string())? else {
                if depth <= 0 {
                    return Err("unbalanced DWARF DIE terminator".to_owned());
                }
                continue;
            };
            if nodes.len() >= MAX_NODES || nodes.len() >= MAX_DIES {
                return Err("DWARF layout node limit exceeded".to_owned());
            }
            if depth < 0 || depth as usize > MAX_NESTING || depth as usize > parents.len() {
                return Err("DWARF DIE nesting or parent-depth limit exceeded".to_owned());
            }
            if depth == 0 && !parents.is_empty() {
                return Err("multiple DWARF unit roots".to_owned());
            }
            parents.truncate(depth as usize);
            let offset = relative_offset
                .to_debug_info_offset(&unit.header)
                .ok_or_else(|| "DIE is not in .debug_info".to_owned())?
                .0;
            let tag = abbreviation.tag();
            if depth == 0 && tag != gimli::DW_TAG_compile_unit {
                return Err("partial or unsupported DWARF unit root".to_owned());
            }
            if let Some(&parent_offset) = parents.last() {
                let parent: &LayoutNode = nodes.get(&parent_offset).ok_or_else(|| "missing DWARF parent".to_owned())?;
                if (parent.tag == gimli::DW_TAG_structure_type
                    || (parent.tag == gimli::DW_TAG_class_type && cpp_node(parent)))
                    && parent.children.len() >= MAX_FIELDS
                {
                    return Err("DWARF struct field limit exceeded (128)".to_owned());
                }
                if parent.children.len() >= MAX_TOTAL_FIELDS {
                    return Err("DWARF cumulative child-edge limit exceeded".to_owned());
                }
                if matches!(tag, gimli::DW_TAG_formal_parameter | gimli::DW_TAG_unspecified_parameters)
                    && !matches!(
                        parent.tag,
                        gimli::DW_TAG_subprogram | gimli::DW_TAG_subroutine_type | gimli::DW_TAG_inlined_subroutine
                    )
                {
                    return Err("DWARF formal/variadic DIE has a nested or inappropriate parent".to_owned());
                }
            } else if matches!(tag, gimli::DW_TAG_formal_parameter | gimli::DW_TAG_unspecified_parameters) {
                return Err("DWARF formal/variadic DIE has no prototype parent".to_owned());
            }
            types += usize::from(is_type(tag));
            layouts += usize::from(
                tag == gimli::DW_TAG_structure_type
                    || (tag == gimli::DW_TAG_class_type
                        && source.as_ref().is_some_and(|source: &DebugLayoutSource| cpp_language(source.language))),
            );
            fields += usize::from(tag == gimli::DW_TAG_member);
            functions += usize::from(tag == gimli::DW_TAG_subprogram);
            parameters += usize::from(tag == gimli::DW_TAG_formal_parameter);
            if types > MAX_TYPES
                || layouts > MAX_LAYOUTS
                || fields > MAX_TOTAL_FIELDS
                || functions > MAX_FUNCTIONS
                || parameters > MAX_TOTAL_FIELDS
            {
                return Err("DWARF cumulative type/layout/field/function limit exceeded".to_owned());
            }
            let mut node = LayoutNode {
                id: DebugLayoutTypeId { unit_offset: unit_offset as u64, die_offset: offset as u64 },
                tag,
                parent: parents.last().copied(),
                children: Vec::new(),
                source: source.clone(),
                name: None,
                linkage_name: None,
                specification: TypeRef::Absent,
                object_pointer: TypeRef::Absent,
                artificial: false,
                target: TypeRef::Absent,
                size: None,
                alignment: None,
                member_offset: None,
                encoding: None,
                address: None,
                address_end: None,
                address_evidence: false,
                address_index_incomplete: false,
                inline: None,
                declaration: false,
                prototyped: false,
                invalid: false,
            };
            let mut attribute_names = BTreeSet::new();
            let mut high_pc = None;
            for spec in abbreviation.attributes() {
                work += 1;
                if work > MAX_WORK || attribute_names.len() >= MAX_ATTRIBUTES {
                    return Err("DWARF cumulative attribute work limit exceeded".to_owned());
                }
                let attr = entries.read_attribute(*spec).map_err(|error| error.to_string())?;
                if !attribute_names.insert(attr.name()) {
                    return Err(format!("duplicate DWARF attribute {}", attr.name()));
                }
                let value = attr.value();
                node.address_evidence |= matches!(
                    attr.name(),
                    gimli::DW_AT_low_pc | gimli::DW_AT_high_pc | gimli::DW_AT_ranges | gimli::DW_AT_entry_pc
                );
                node.address_index_incomplete |= matches!(attr.name(), gimli::DW_AT_ranges | gimli::DW_AT_entry_pc);
                let relevant = is_type(tag)
                    || matches!(
                        tag,
                        gimli::DW_TAG_member
                            | gimli::DW_TAG_subprogram
                            | gimli::DW_TAG_formal_parameter
                            | gimli::DW_TAG_unspecified_parameters
                    );
                let cpp = cpp_node(&node);
                if relevant && !allowed_attribute(tag, attr.name()) && !(cpp && allowed_cpp_attribute(tag, attr.name()))
                {
                    node.invalid = true;
                }
                match attr.name() {
                    gimli::DW_AT_name | gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name if relevant => {
                        work += MAX_NAME + 1;
                        if work > MAX_WORK {
                            return Err("DWARF cumulative name lookup work limit exceeded".to_owned());
                        }
                        if matches!(value, AttributeValue::DebugStrOffsetsIndex(_)) && !proof.strings_base {
                            return Err("indexed DWARF name has no verified string-offset base".to_owned());
                        }
                        budget.reserve(NAME_READ_RESERVATION)?;
                        let reader =
                            bounded_name_limit(dwarf, &unit, value, MAX_NAME).map_err(|error| error.to_string())?;
                        if reader.len() > MAX_NAME {
                            return Err("DWARF layout name exceeds 128 ASCII bytes".to_owned());
                        } else {
                            let bytes = reader.to_slice().map_err(|error| error.to_string())?;
                            if !bytes.is_ascii() || names + bytes.len() > MAX_NAMES {
                                return Err("DWARF layout names exceed ASCII/32 KiB retained-text limit".to_owned());
                            }
                            names += bytes.len();
                            let name = std::str::from_utf8(&bytes).unwrap().to_owned();
                            if attr.name() == gimli::DW_AT_name {
                                node.name = Some(name);
                            } else {
                                node.invalid |= node.linkage_name.is_some();
                                node.linkage_name = Some(name);
                            }
                        }
                    }
                    gimli::DW_AT_type | gimli::DW_AT_specification | gimli::DW_AT_object_pointer => {
                        edges += 1;
                        if edges > MAX_EDGES {
                            return Err("DWARF cumulative type-edge limit exceeded".to_owned());
                        }
                        let reference = match value {
                            AttributeValue::UnitRef(reference) if reference.is_in_bounds(&unit.header) => {
                                TypeRef::Offset(reference.to_debug_info_offset(&unit.header).unwrap().0)
                            }
                            AttributeValue::DebugInfoRef(reference) => TypeRef::Offset(reference.0),
                            _ => TypeRef::Unsupported,
                        };
                        match attr.name() {
                            gimli::DW_AT_type => node.target = reference,
                            gimli::DW_AT_specification => node.specification = reference,
                            _ => node.object_pointer = reference,
                        }
                    }
                    gimli::DW_AT_byte_size => {
                        node.size = constant(value);
                        node.invalid |= node.size.is_none();
                    }
                    gimli::DW_AT_alignment => {
                        node.alignment = constant(value);
                        node.invalid |= !node.alignment.is_some_and(valid_alignment);
                    }
                    gimli::DW_AT_data_member_location => {
                        node.member_offset = constant(value);
                        node.invalid |= node.member_offset.is_none();
                    }
                    gimli::DW_AT_encoding => {
                        if let AttributeValue::Encoding(encoding) = value {
                            node.encoding = Some(encoding);
                        } else {
                            node.invalid = true;
                        }
                    }
                    gimli::DW_AT_low_pc => {
                        if matches!(value, AttributeValue::DebugAddrIndex(_)) && !proof.addresses_base {
                            return Err("indexed DWARF address has no verified address base".to_owned());
                        }
                        budget.reserve(64)?;
                        node.address = dwarf.attr_address(&unit, value).map_err(|error| error.to_string())?;
                        node.invalid |= node.address.is_none();
                    }
                    gimli::DW_AT_high_pc if tag == gimli::DW_TAG_subprogram => {
                        high_pc = match value {
                            AttributeValue::Addr(_) | AttributeValue::DebugAddrIndex(_) => {
                                if matches!(value, AttributeValue::DebugAddrIndex(_)) && !proof.addresses_base {
                                    return Err("indexed DWARF extent has no verified address base".to_owned());
                                }
                                budget.reserve(64)?;
                                dwarf
                                    .attr_address(&unit, value)
                                    .map_err(|error| error.to_string())?
                                    .map(HighPc::Address)
                            }
                            value if unit.header.version() >= 4 => constant(value).map(HighPc::Offset),
                            _ => None,
                        };
                        node.invalid |= high_pc.is_none();
                    }
                    gimli::DW_AT_declaration => match value {
                        AttributeValue::Flag(flag) => node.declaration = flag,
                        _ => node.invalid = true,
                    },
                    gimli::DW_AT_artificial => match value {
                        AttributeValue::Flag(flag) => node.artificial = flag,
                        _ => node.invalid = true,
                    },
                    gimli::DW_AT_accessibility if cpp => {
                        node.invalid |= !matches!(
                            value,
                            AttributeValue::Accessibility(
                                gimli::DW_ACCESS_public | gimli::DW_ACCESS_protected | gimli::DW_ACCESS_private
                            )
                        );
                    }
                    gimli::DW_AT_prototyped => {
                        node.prototyped = matches!(value, AttributeValue::Flag(true));
                        node.invalid |= !node.prototyped;
                    }
                    gimli::DW_AT_inline => match value {
                        AttributeValue::Inline(inline) => {
                            node.inline = Some(inline);
                            node.invalid |= !matches!(
                                inline,
                                gimli::DW_INL_not_inlined
                                    | gimli::DW_INL_inlined
                                    | gimli::DW_INL_declared_not_inlined
                                    | gimli::DW_INL_declared_inlined
                            );
                        }
                        _ => node.invalid = true,
                    },
                    gimli::DW_AT_calling_convention => {
                        node.invalid |= if cpp && record_tag(tag) {
                            !matches!(value, AttributeValue::CallingConvention(gimli::DW_CC_pass_by_value))
                        } else {
                            !matches!(value, AttributeValue::CallingConvention(gimli::DW_CC_normal))
                        };
                    }
                    gimli::DW_AT_address_class => {
                        node.invalid |= !matches!(value, AttributeValue::AddressClass(gimli::DW_ADDR_none));
                    }
                    gimli::DW_AT_endianity => {
                        node.invalid |= !matches!(value, AttributeValue::Endianity(gimli::DW_END_default));
                    }
                    gimli::DW_AT_language if depth == 0 => {
                        if let AttributeValue::Language(language) = value
                            && supported_language(language)
                            && unit.header.address_size() == 8
                        {
                            source = Some(DebugLayoutSource {
                                unit_offset: unit_offset as u64,
                                language: language.0,
                                dwarf_version: unit.header.version(),
                                address_size: unit.header.address_size(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            if let Some(high_pc) = high_pc {
                node.address_end = node.address.and_then(|start| {
                    let end = match high_pc {
                        HighPc::Address(end) => Some(end),
                        HighPc::Offset(size) => start.checked_add(size),
                    };
                    end.filter(|&end| end > start)
                });
                node.invalid |= node.address_end.is_none();
            }
            if depth == 0 && (node.declaration || node.invalid) {
                return Err("invalid or declaration-only DWARF compilation unit".to_owned());
            }
            if let Some(parent) = node.parent {
                let parent = nodes.get_mut(&parent).ok_or_else(|| "missing DWARF parent".to_owned())?;
                edges += 1;
                if edges > MAX_EDGES {
                    return Err("DWARF cumulative edge limit exceeded".to_owned());
                }
                parent.children.push(offset);
            }
            parents.push(offset);
            if nodes.insert(offset, node).is_some() {
                return Err("duplicate absolute DWARF DIE identity".to_owned());
            }
        }
        if entries.next_depth() != 0 {
            return Err("unterminated DWARF DIE children".to_owned());
        }
    }
    Ok(nodes)
}

#[derive(Debug, Clone, Copy)]
enum Resolved {
    Scalar(usize),
    Pointer { offset: usize, target: Pointee },
    Struct(usize),
}

#[derive(Debug, Clone, Copy)]
enum Pointee {
    Void,
    Scalar(usize),
    Struct(usize),
}

struct Resolver<'a> {
    nodes: &'a BTreeMap<usize, LayoutNode>,
    types: BTreeMap<usize, Result<Resolved, String>>,
    heights: BTreeMap<usize, usize>,
    layouts: BTreeMap<usize, Result<DebugStructLayout, String>>,
    active: BTreeSet<usize>,
    ambiguous_layouts: BTreeSet<usize>,
    work: usize,
    text: usize,
    contextual_failures: usize,
}

struct MethodProof {
    metadata: DebugLayoutMethod,
    original_name: String,
    return_type: TypeRef,
}

impl<'a> Resolver<'a> {
    fn new(nodes: &'a BTreeMap<usize, LayoutNode>) -> Self {
        let mut names: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (&offset, node) in nodes {
            if node.tag == gimli::DW_TAG_structure_type
                && !cpp_node(node)
                && let Some(name) = node.name.as_deref().filter(|name| !name.is_empty())
            {
                names.entry(c_name(name)).or_default().push(offset);
            }
        }
        let ambiguous_layouts = names.values().filter(|offsets| offsets.len() != 1).flatten().copied().collect();
        Self {
            nodes,
            types: BTreeMap::new(),
            heights: BTreeMap::new(),
            layouts: BTreeMap::new(),
            active: BTreeSet::new(),
            ambiguous_layouts,
            work: 0,
            text: nodes
                .values()
                .map(|node| {
                    node.name.as_ref().map_or(0, String::len) + node.linkage_name.as_ref().map_or(0, String::len)
                })
                .sum(),
            contextual_failures: 0,
        }
    }

    fn charge_work(&mut self) -> Result<(), String> {
        self.work += 1;
        if self.work > MAX_WORK {
            self.contextual_failures += 1;
            return Err("DWARF cumulative resolution work limit exceeded".to_owned());
        }
        Ok(())
    }

    fn retain_text(&mut self, bytes: usize) -> Result<(), String> {
        let Some(next) = self.text.checked_add(bytes).filter(|&size| size <= MAX_NAMES) else {
            self.contextual_failures += 1;
            return Err("DWARF retained leaf/name text exceeds 32 KiB".to_owned());
        };
        self.text = next;
        Ok(())
    }

    fn resolve(&mut self, target: TypeRef, depth: usize) -> Result<Resolved, String> {
        self.charge_work()?;
        let TypeRef::Offset(offset) = target else {
            return Err("missing or unsupported type reference".to_owned());
        };
        if depth >= MAX_TYPE_DEPTH {
            self.contextual_failures += 1;
            return Err("DWARF type depth limit exceeded".to_owned());
        }
        if let Some(result) = self.types.get(&offset) {
            if self.heights.get(&offset).is_some_and(|height| depth + height > MAX_TYPE_DEPTH) {
                self.contextual_failures += 1;
                return Err("DWARF cached type depth limit exceeded".to_owned());
            }
            return result.clone();
        }
        if !self.active.insert(offset) {
            return Err("recursive DWARF type graph".to_owned());
        }
        let context = self.contextual_failures;
        let result = self.resolve_node(offset, depth);
        self.active.remove(&offset);
        if result.is_ok() {
            let height = match self.nodes[&offset].target {
                TypeRef::Offset(target) => self.heights.get(&target).copied().unwrap_or(0) + 1,
                _ => 1,
            };
            self.heights.insert(offset, height);
        }
        if result.is_ok() || self.contextual_failures == context {
            self.types.insert(offset, result.clone());
        }
        result
    }

    fn resolve_node(&mut self, offset: usize, depth: usize) -> Result<Resolved, String> {
        let nodes = self.nodes;
        let node = nodes.get(&offset).ok_or_else(|| "unresolved absolute DIE reference".to_owned())?;
        clean(node)?;
        if !node.children.is_empty() && !record_tag(node.tag) {
            return Err("type has unsupported child DIEs".to_owned());
        }
        match node.tag {
            gimli::DW_TAG_base_type => {
                scalar_kind(node)?;
                if node.alignment.is_some_and(|alignment| Some(alignment) != node.size) {
                    return Err("scalar producer alignment is not the supported ordinary C ABI alignment".to_owned());
                }
                Ok(Resolved::Scalar(offset))
            }
            gimli::DW_TAG_typedef => self.resolve(node.target, depth + 1),
            gimli::DW_TAG_pointer_type => {
                if node.size.unwrap_or(8) != 8 || node.alignment.is_some_and(|alignment| alignment != 8) {
                    return Err("pointer byte size is not the verified ELF64 address size".to_owned());
                }
                let target = match node.target {
                    TypeRef::Absent => Pointee::Void,
                    target => match self.resolve(target, depth + 1)? {
                        Resolved::Scalar(offset) => Pointee::Scalar(offset),
                        Resolved::Struct(offset) => Pointee::Struct(offset),
                        Resolved::Pointer { .. } => return Err("pointer chains are unsupported".to_owned()),
                    },
                };
                Ok(Resolved::Pointer { offset, target })
            }
            gimli::DW_TAG_structure_type => Ok(Resolved::Struct(offset)),
            gimli::DW_TAG_class_type if cpp_node(node) => Ok(Resolved::Struct(offset)),
            _ => Err(format!("unsupported layout type {} (qualifiers/aggregates are not erased)", node.tag)),
        }
    }

    fn scalar(&mut self, offset: usize) -> Result<DebugLayoutScalar, String> {
        let nodes = self.nodes;
        let node = &nodes[&offset];
        let (kind, declaration) = scalar_kind(node)?;
        self.retain_text(node.name.as_ref().map_or(0, String::len) + declaration.len())?;
        Ok(DebugLayoutScalar {
            id: node.id,
            kind,
            byte_size: node.size.unwrap(),
            encoding: node.encoding.unwrap().0,
            producer_alignment: node.alignment,
            original_name: node.name.clone(),
            declaration,
        })
    }

    fn leaf(&mut self, resolved: Resolved) -> Result<DebugLayoutLeaf, String> {
        match resolved {
            Resolved::Scalar(offset) => Ok(DebugLayoutLeaf::Scalar { scalar: self.scalar(offset)? }),
            Resolved::Pointer { offset, target: Pointee::Void } => Ok(DebugLayoutLeaf::Pointer {
                id: self.nodes[&offset].id,
                byte_size: 8,
                producer_alignment: self.nodes[&offset].alignment,
                pointee: None,
            }),
            Resolved::Pointer { offset, target: Pointee::Scalar(target) } => Ok(DebugLayoutLeaf::Pointer {
                id: self.nodes[&offset].id,
                byte_size: 8,
                producer_alignment: self.nodes[&offset].alignment,
                pointee: Some(self.scalar(target)?),
            }),
            _ => Err("fields require scalar or single scalar/void pointer leaves".to_owned()),
        }
    }

    fn layout(&mut self, offset: usize) -> Result<(), String> {
        self.charge_work()?;
        if let Some(result) = self.layouts.get(&offset) {
            return result.as_ref().map(|_| ()).map_err(Clone::clone);
        }
        let context = self.contextual_failures;
        let result = self.layout_node(offset);
        let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
        if result.is_ok() || self.contextual_failures == context {
            self.layouts.insert(offset, result);
        }
        outcome
    }

    fn layout_node(&mut self, offset: usize) -> Result<DebugStructLayout, String> {
        let nodes = self.nodes;
        let node = &nodes[&offset];
        clean(node)?;
        if self.ambiguous_layouts.contains(&offset) {
            return Err("duplicate or sanitized-colliding struct names have distinct DIE identities".to_owned());
        }
        if !record_tag(node.tag)
            || (node.tag == gimli::DW_TAG_class_type && !cpp_node(node))
            || !matches!(node.target, TypeRef::Absent)
        {
            return Err("not a complete flat struct".to_owned());
        }
        if node.parent.is_some_and(|parent| self.nodes[&parent].tag != gimli::DW_TAG_compile_unit) {
            return Err("nested or non-CU-scoped structs are unsupported".to_owned());
        }
        let size = node
            .size
            .filter(|&size| size > 0 && size <= MAX_SIZE)
            .ok_or_else(|| "struct requires complete nonzero byte size at most 1 MiB".to_owned())?;
        if cpp_node(node)
            && (node.alignment.is_none() || node.name.as_deref().is_none_or(|name| !ordinary_identifier(name)))
        {
            return Err("C++ records require explicit producer alignment and a non-template source name".to_owned());
        }
        if node.alignment.is_some_and(|alignment| size % alignment != 0) {
            return Err("struct byte size conflicts with explicit producer alignment".to_owned());
        }
        if node.children.is_empty() || node.children.len() > MAX_FIELDS {
            return Err("struct requires 1..128 complete fields".to_owned());
        }
        let prefix = format!("debug_layout_{:x}_{:x}", node.id.unit_offset, node.id.die_offset);
        let emitted_name = match node.name.as_deref().filter(|name| !name.is_empty()) {
            Some(original) => {
                let stem = c_name(original);
                let available = MAX_NAME.saturating_sub(prefix.len() + 1);
                format!("{prefix}_{}", &stem[..stem.len().min(available)])
            }
            None => prefix,
        };
        self.retain_text(node.name.as_ref().map_or(0, String::len) + emitted_name.len())?;
        let mut fields = Vec::new();
        let mut names = BTreeSet::new();
        let mut intervals = Vec::new();
        let mut leaf_alignment = 1;
        let mut alignment_proof = node.alignment.is_some();
        for (index, &child) in node.children.iter().enumerate() {
            self.charge_work()?;
            let field = &nodes[&child];
            if cpp_node(node) && field.tag == gimli::DW_TAG_subprogram {
                clean_declaration(field)?;
                if field.id.unit_offset != node.id.unit_offset || field.parent != Some(offset) {
                    return Err("method declaration is not owned by the exact record DIE".to_owned());
                }
                continue;
            }
            clean(field)?;
            if field.tag != gimli::DW_TAG_member || !field.children.is_empty() || field.artificial {
                return Err("struct has inheritance, nested types, or non-member children".to_owned());
            }
            let emitted = emitted_name_for(field.name.as_deref(), &format!("field_{}", index + 1))?;
            if !names.insert(emitted.clone()) {
                return Err("duplicate or sanitized-colliding field names".to_owned());
            }
            self.retain_text(field.name.as_ref().map_or(0, String::len) + emitted.len())?;
            let resolved = self.resolve(field.target, 0)?;
            if cpp_node(node) && matches!(resolved, Resolved::Pointer { target: Pointee::Void, .. }) {
                return Err("C++ record pointer fields require an exact scalar pointee".to_owned());
            }
            let leaf = self.leaf(resolved)?;
            alignment_proof &= field.alignment.is_some() && leaf.alignment_proven();
            let field_size = leaf.size();
            leaf_alignment = leaf_alignment.max(field_size);
            if field.size.is_some_and(|declared| declared != field_size) {
                return Err("member byte size conflicts with exact leaf size".to_owned());
            }
            let field_offset =
                field.member_offset.ok_or_else(|| "member has no exact constant byte offset".to_owned())?;
            let end = field_offset
                .checked_add(field_size)
                .filter(|&end| end <= size)
                .ok_or_else(|| "member offset overflow or out-of-range extent".to_owned())?;
            if field_offset % field_size != 0
                || field.alignment.is_some_and(|alignment| alignment != field_size)
                || leaf.alignment().is_some_and(|alignment| alignment != field_size)
            {
                return Err(
                    "packed, unaligned, or over-aligned leaves are unsupported by the ordinary C ABI".to_owned()
                );
            }
            let alignment = field.alignment.or(leaf.alignment());
            if alignment.is_some_and(|alignment| {
                field_offset % alignment != 0
                    || node.alignment.is_some_and(|struct_alignment| struct_alignment < alignment)
            }) {
                return Err("member extent conflicts with explicit producer alignment".to_owned());
            }
            intervals.push((field_offset, end));
            fields.push(DebugLayoutField {
                id: field.id,
                original_name: field.name.clone(),
                emitted_name: emitted,
                offset: field_offset,
                byte_size: field_size,
                producer_alignment: field.alignment,
                leaf,
            });
        }
        if fields.is_empty() {
            return Err("record has no supported data members".to_owned());
        }
        intervals.sort_unstable();
        if intervals.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err("overlapping struct members".to_owned());
        }
        // ABI consistency is not producer evidence: absent struct alignment remains None below.
        if size % leaf_alignment != 0 || node.alignment.is_some_and(|alignment| alignment != leaf_alignment) {
            return Err("struct extent or producer alignment is not an ordinary supported C layout".to_owned());
        }
        Ok(DebugStructLayout {
            id: node.id,
            original_name: node.name.clone(),
            emitted_name,
            byte_size: size,
            producer_alignment: node.alignment,
            fields,
            source: node.source.clone().unwrap(),
            strictly_applicable: alignment_proof,
            eligible_for_native_verification: node.alignment.is_some(),
        })
    }

    fn value(&mut self, target: TypeRef, parameter: bool) -> Result<DebugLayoutValue, String> {
        let resolved = self.resolve(target, 0)?;
        match resolved {
            Resolved::Pointer { offset: pointer, target: Pointee::Struct(offset) } if parameter => {
                self.layout(offset)?;
                Ok(DebugLayoutValue::StructPointer {
                    pointer_id: self.nodes[&pointer].id,
                    layout_id: self.nodes[&offset].id,
                    byte_size: 8,
                    producer_alignment: self.nodes[&pointer].alignment,
                })
            }
            _ => Ok(DebugLayoutValue::Leaf { leaf: self.leaf(resolved)? }),
        }
    }

    fn value_declaration(&self, value: &DebugLayoutValue) -> String {
        match value {
            DebugLayoutValue::Void => "void".to_owned(),
            DebugLayoutValue::Leaf { leaf } => leaf.declaration(),
            DebugLayoutValue::StructPointer { layout_id, .. } => {
                let layout = self.layouts[&(layout_id.die_offset as usize)].as_ref().unwrap();
                format!("struct {} *", layout.emitted_name)
            }
        }
    }

    fn method_parameters(&mut self, offset: usize, record: usize) -> Result<Vec<usize>, String> {
        self.charge_work()?;
        let nodes = self.nodes;
        let node = &nodes[&offset];
        let mut parameters = Vec::new();
        for &child in &node.children {
            self.charge_work()?;
            let parameter = &nodes[&child];
            match parameter.tag {
                gimli::DW_TAG_formal_parameter => {
                    clean(parameter)?;
                    if parameter.parent != Some(offset)
                        || parameter.id.unit_offset != node.id.unit_offset
                        || !parameter.children.is_empty()
                        || parameters.len() >= MAX_FIELDS
                    {
                        return Err("method formal parameter has unsupported ownership, children, or count".to_owned());
                    }
                    parameters.push(child);
                }
                gimli::DW_TAG_variable | gimli::DW_TAG_lexical_block | gimli::DW_TAG_inlined_subroutine
                    if !node.declaration => {}
                _ => return Err("method has variadic, template, or unsupported prototype children".to_owned()),
            }
        }
        let object = match node.object_pointer {
            TypeRef::Offset(object) => object,
            TypeRef::Absent if node.declaration => {
                // Only the explicit definition object pointer establishes the method role; specification pairs formals.
                *parameters
                    .first()
                    .ok_or_else(|| "associated declaration has no artificial object formal".to_owned())?
            }
            _ => return Err("instance method definition requires an explicit object-pointer DIE reference".to_owned()),
        };
        if parameters.first() != Some(&object) || parameters.iter().filter(|&&id| id == object).count() != 1 {
            return Err("DW_AT_object_pointer must reference the actual first formal parameter".to_owned());
        }
        if !nodes[&object].artificial {
            return Err("associated method object formals must have explicit artificial-parameter evidence".to_owned());
        }
        let TypeRef::Offset(pointer) = nodes[&object].target else {
            return Err("object formal has no direct pointer type".to_owned());
        };
        self.charge_work()?;
        let pointer = nodes.get(&pointer).ok_or_else(|| "unresolved object-pointer type".to_owned())?;
        if pointer.tag != gimli::DW_TAG_pointer_type
            || !matches!(pointer.target, TypeRef::Offset(target) if target == record)
        {
            return Err("object pointer must target the exact unqualified owning record DIE".to_owned());
        }
        self.resolve(nodes[&object].target, 0)?;
        for &parameter in parameters.iter().skip(1) {
            if nodes[&parameter].artificial
                || !matches!(self.resolve(nodes[&parameter].target, 0)?, Resolved::Scalar(_))
            {
                return Err("method arguments must be ordinary non-artificial scalar formals".to_owned());
            }
        }
        Ok(parameters)
    }

    fn method_proof(&mut self, offset: usize) -> Result<MethodProof, String> {
        self.charge_work()?;
        let nodes = self.nodes;
        let node = &nodes[&offset];
        let declaration_offset = method_declaration(offset, nodes)?;
        let declaration = &nodes[&declaration_offset];
        let record = declaration.parent.unwrap();
        let mut declarations = 0;
        for &child in &nodes[&record].children {
            self.charge_work()?;
            declarations += usize::from(child == declaration_offset);
        }
        if declarations != 1 {
            return Err("method declaration must occur exactly once in its owning record".to_owned());
        }
        let original = declaration.name.as_deref().unwrap();
        if !ordinary_identifier(original)
            || nodes[&record].name.as_deref() == Some(original)
            || node.artificial
            || declaration.artificial
            || node.inline.is_some()
            || declaration.inline.is_some()
        {
            return Err(
                "constructors, destructors, operators, templates, artificial and inline methods are unsupported"
                    .to_owned(),
            );
        }
        let linkage = node.linkage_name.as_ref().or(declaration.linkage_name.as_ref()).unwrap();
        if !linkage.starts_with("_ZN") {
            return Err("method linkage is not an ordinary non-thunk Itanium member symbol".to_owned());
        }
        let parameters = self.method_parameters(offset, record)?;
        let declared_parameters = self.method_parameters(declaration_offset, record)?;
        if parameters.len() != declared_parameters.len() {
            return Err("method definition and declaration have different formal counts".to_owned());
        }
        for (&actual, &declared) in parameters.iter().zip(&declared_parameters).skip(1) {
            self.charge_work()?;
            if !same_reference(nodes[&actual].target, nodes[&declared].target) {
                return Err("method definition and declaration have conflicting formal types".to_owned());
            }
        }
        if !matches!(declaration.target, TypeRef::Absent)
            && !matches!(self.resolve(declaration.target, 0)?, Resolved::Scalar(_))
        {
            return Err("method return must be void or an ordinary scalar".to_owned());
        }
        self.layout(record)?;
        self.retain_text(linkage.len())?;
        Ok(MethodProof {
            metadata: DebugLayoutMethod {
                record_id: nodes[&record].id,
                declaration_id: declaration.id,
                object_pointer_id: nodes[&parameters[0]].id,
                linkage_name: linkage.clone(),
            },
            original_name: original.to_owned(),
            return_type: declaration.target,
        })
    }

    fn signature(&mut self, offset: usize, declaration_limit: usize) -> Result<DebugLayoutSignature, String> {
        let nodes = self.nodes;
        let node = &nodes[&offset];
        clean(node)?;
        let method = if cpp_node(node) { Some(self.method_proof(offset)?) } else { None };
        if method.is_none() && node.parent.is_none_or(|parent| nodes[&parent].tag != gimli::DW_TAG_compile_unit) {
            return Err("function is not an ordinary CU-scoped C subprogram".to_owned());
        }
        if method.is_none() && !node.prototyped {
            return Err("function has no explicit complete fixed C prototype".to_owned());
        }
        if node.inline.is_some() {
            return Err("abstract/inline subprogram metadata is not an importable concrete prototype".to_owned());
        }
        let mut has_struct_pointer = false;
        for &child in &node.children {
            self.charge_work()?;
            let parameter = &nodes[&child];
            if parameter.tag == gimli::DW_TAG_formal_parameter {
                let resolved = self.resolve(parameter.target, 0)?;
                has_struct_pointer |= matches!(resolved, Resolved::Pointer { target: Pointee::Struct(_), .. });
            }
        }
        if !has_struct_pointer {
            return Err("function has no supported pointer-to-struct parameter".to_owned());
        }
        let original = method
            .as_ref()
            .map(|proof| proof.original_name.as_str())
            .or(node.name.as_deref())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "function has no original name".to_owned())?;
        let emitted =
            if method.is_some() { method_emitted_name(node, original)? } else { emitted_name_for(Some(original), "")? };
        self.retain_text(original.len() + emitted.len())?;
        let result = match method.as_ref().map_or(node.target, |proof| proof.return_type) {
            TypeRef::Absent => DebugLayoutValue::Void,
            target => self.value(target, false)?,
        };
        let mut parameters = Vec::new();
        let mut dependencies = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut arguments = Vec::new();
        let mut declaration_bytes = self.value_declaration(&result).len() + emitted.len() + 4;
        for &child in &node.children {
            self.charge_work()?;
            let parameter = &nodes[&child];
            if parameter.tag == gimli::DW_TAG_unspecified_parameters {
                return Err("variadic functions are not fixed prototypes".to_owned());
            }
            if parameter.tag != gimli::DW_TAG_formal_parameter {
                continue;
            }
            if parameters.len() >= MAX_FIELDS {
                return Err("function exceeds 128 parameters".to_owned());
            }
            clean(parameter)?;
            if !parameter.children.is_empty() {
                return Err("parameter has unsupported children".to_owned());
            }
            let object = method.as_ref().is_some_and(|proof| proof.metadata.object_pointer_id == parameter.id);
            let name = if object {
                "self".to_owned()
            } else {
                emitted_name_for(parameter.name.as_deref(), &format!("arg_{}", parameters.len() + 1))?
            };
            if !names.insert(name.clone()) {
                return Err("duplicate or sanitized-colliding parameter names".to_owned());
            }
            self.retain_text(parameter.name.as_ref().map_or(0, String::len) + name.len())?;
            let ty = self.value(parameter.target, true)?;
            if let DebugLayoutValue::StructPointer { layout_id, .. } = &ty {
                dependencies.insert(*layout_id);
            }
            let text = self.value_declaration(&ty);
            declaration_bytes += text.len() + name.len() + 3;
            if declaration_bytes > declaration_limit.min(MAX_DECLARATION) {
                return Err("layout function declaration exceeds 4095 bytes".to_owned());
            }
            arguments.push(format!("{text} {name}"));
            parameters.push(DebugLayoutParameter {
                id: parameter.id,
                original_name: parameter.name.clone(),
                emitted_name: name,
                ty,
            });
        }
        if dependencies.is_empty() {
            return Err("function has no supported pointer-to-struct parameter".to_owned());
        }
        let candidate = dependencies
            .iter()
            .all(|id| self.layouts[&(id.die_offset as usize)].as_ref().unwrap().eligible_for_native_verification);
        let applicable = candidate
            && result.alignment_proven()
            && parameters.iter().all(|parameter| parameter.ty.alignment_proven())
            && dependencies
                .iter()
                .all(|id| self.layouts[&(id.die_offset as usize)].as_ref().unwrap().strictly_applicable);
        let declaration = format!("{} {emitted}({});", self.value_declaration(&result), arguments.join(", "));
        if declaration.len() > declaration_limit.min(MAX_DECLARATION) {
            return Err("layout function declaration exceeds 4095 bytes".to_owned());
        }
        Ok(DebugLayoutSignature {
            id: node.id,
            address: node.address.ok_or_else(|| "function has no exact address".to_owned())?,
            original_name: original.to_owned(),
            emitted_name: emitted,
            declaration,
            return_type: result,
            parameters,
            dependencies: dependencies.into_iter().collect(),
            source: node.source.clone().unwrap(),
            method: method.map(|proof| proof.metadata),
            strictly_applicable: applicable,
            eligible_for_native_verification: candidate,
        })
    }
}

fn clean(node: &LayoutNode) -> Result<(), String> {
    if node.invalid || node.declaration || node.source.is_none() {
        return Err("invalid/unsupported attributes, declaration-only DIE, or unverified source context".to_owned());
    }
    Ok(())
}

fn clean_declaration(node: &LayoutNode) -> Result<(), String> {
    if node.invalid
        || !node.declaration
        || !cpp_node(node)
        || node.address_evidence
        || node.address.is_some()
        || node.address_index_incomplete
        || !matches!(node.specification, TypeRef::Absent)
    {
        return Err("record has an unsupported or non-declaration member method".to_owned());
    }
    Ok(())
}

fn same_reference(left: TypeRef, right: TypeRef) -> bool {
    match (left, right) {
        (TypeRef::Absent, TypeRef::Absent) => true,
        (TypeRef::Offset(left), TypeRef::Offset(right)) => left == right,
        _ => false,
    }
}

fn ordinary_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn method_emitted_name(node: &LayoutNode, original: &str) -> Result<String, String> {
    let name = format!("debug_method_{:x}_{:x}_{original}", node.id.unit_offset, node.id.die_offset);
    emitted_name_for(Some(&name), "")
}

fn method_declaration(offset: usize, nodes: &BTreeMap<usize, LayoutNode>) -> Result<usize, String> {
    let node = &nodes[&offset];
    clean(node)?;
    if !cpp_node(node) || node.parent.is_none_or(|parent| nodes[&parent].tag != gimli::DW_TAG_compile_unit) {
        return Err("C++ method definition must be a concrete CU-scoped subprogram".to_owned());
    }
    let TypeRef::Offset(declaration_offset) = node.specification else {
        return Err("C++ method requires a single explicit definition-to-declaration specification".to_owned());
    };
    let declaration = nodes.get(&declaration_offset).ok_or_else(|| "unresolved method specification".to_owned())?;
    clean_declaration(declaration)?;
    if declaration.tag != gimli::DW_TAG_subprogram || declaration.id.unit_offset != node.id.unit_offset {
        return Err("method specification must target one declaration in the same CU".to_owned());
    }
    let record = declaration
        .parent
        .and_then(|parent| nodes.get(&parent))
        .filter(|record| record_tag(record.tag) && cpp_node(record))
        .ok_or_else(|| "method declaration is not owned by a C++ record".to_owned())?;
    if record.id.unit_offset != node.id.unit_offset
        || record.parent.is_none_or(|parent| nodes[&parent].tag != gimli::DW_TAG_compile_unit)
    {
        return Err("method declaration must belong to the exact same-CU, CU-scoped record".to_owned());
    }
    if declaration.name.as_deref().is_none_or(str::is_empty)
        || (node.name.is_some() && node.name != declaration.name)
        || (node.linkage_name.is_some()
            && declaration.linkage_name.is_some()
            && node.linkage_name != declaration.linkage_name)
        || node.linkage_name.as_ref().or(declaration.linkage_name.as_ref()).is_none_or(String::is_empty)
        || (!matches!(node.target, TypeRef::Absent) && !same_reference(node.target, declaration.target))
    {
        return Err(
            "method definition and declaration have missing or conflicting name/linkage/return evidence".to_owned()
        );
    }
    Ok(declaration_offset)
}

fn emitted_name_for(original: Option<&str>, fallback: &str) -> Result<String, String> {
    let name = original.filter(|name| !name.is_empty()).map_or_else(|| fallback.to_owned(), c_name);
    if name.is_empty() || name.len() > MAX_NAME || !name.is_ascii() {
        return Err("emitted identifier exceeds the 128 ASCII-byte limit".to_owned());
    }
    Ok(name)
}

fn scalar_kind(node: &LayoutNode) -> Result<(DebugLayoutScalarKind, String), String> {
    use DebugLayoutScalarKind::{Boolean, Float, SignedInteger, UnsignedInteger};
    let size = node.size.ok_or_else(|| "scalar has no exact byte size".to_owned())?;
    let encoding = node.encoding.ok_or_else(|| "scalar has no verified encoding".to_owned())?;
    match (encoding, size) {
        (gimli::DW_ATE_signed, 1 | 2 | 4 | 8) | (gimli::DW_ATE_signed_char, 1) => {
            Ok((SignedInteger, format!("int{}_t", size * 8)))
        }
        (gimli::DW_ATE_unsigned, 1 | 2 | 4 | 8) | (gimli::DW_ATE_unsigned_char, 1) => {
            Ok((UnsignedInteger, format!("uint{}_t", size * 8)))
        }
        (gimli::DW_ATE_float, 4) => Ok((Float, "float".to_owned())),
        (gimli::DW_ATE_float, 8) => Ok((Float, "double".to_owned())),
        (gimli::DW_ATE_boolean, 1) => Ok((Boolean, "bool".to_owned())),
        _ => Err("unsupported scalar encoding or byte width".to_owned()),
    }
}

fn abstract_inline_metadata(node: &LayoutNode, nodes: &BTreeMap<usize, LayoutNode>) -> bool {
    node.tag == gimli::DW_TAG_subprogram
        && !node.declaration
        && !node.invalid
        && node.source.is_some()
        && !cpp_node(node)
        && node.prototyped
        && !node.address_evidence
        && !node.address_index_incomplete
        && node.address.is_none()
        && matches!(node.inline, Some(gimli::DW_INL_inlined | gimli::DW_INL_declared_inlined))
        && node.parent.is_some_and(|parent| nodes[&parent].tag == gimli::DW_TAG_compile_unit)
}

fn build_report(
    nodes: &BTreeMap<usize, LayoutNode>,
    is_code: impl Fn(u64) -> bool,
    supported_extent: impl Fn(u64, u64) -> bool,
    report: &mut DebugLayoutReport,
) {
    let mut resolver = Resolver::new(nodes);
    let mut function_names: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    let mut addresses: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut definitions: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (&offset, node) in nodes {
        if node.tag == gimli::DW_TAG_subprogram {
            if resolver.charge_work().is_err() {
                report.warn("DWARF function-name index reached the work limit".to_owned());
                return;
            }
            let cpp = cpp_node(node);
            if cpp {
                if !node.declaration
                    && let TypeRef::Offset(declaration) = node.specification
                {
                    definitions.entry(declaration).or_default().push(offset);
                }
                let declaration = method_declaration(offset, nodes).ok();
                let linkage =
                    node.linkage_name.as_ref().or_else(|| declaration.and_then(|id| nodes[&id].linkage_name.as_ref()));
                let key = match linkage {
                    Some(linkage) => format!("cpp:{linkage}"),
                    None => format!("cpp-die:{}:{}", node.id.unit_offset, node.id.die_offset),
                };
                function_names.entry(key).or_default().push((offset, declaration.unwrap_or(offset)));
                if let Some(declaration) = declaration
                    && let Ok(emitted) = method_emitted_name(node, nodes[&declaration].name.as_deref().unwrap())
                {
                    function_names.entry(format!("emitted:{emitted}")).or_default().push((offset, offset));
                }
            } else {
                let Some(name) = node.name.as_deref().filter(|name| !name.is_empty()) else {
                    report.warn("incomplete DWARF function-name index cannot establish uniqueness".to_owned());
                    return;
                };
                function_names.entry(format!("emitted:{}", c_name(name))).or_default().push((offset, offset));
            }
            if node.address_index_incomplete
                || (node.declaration
                    && (node.address_evidence
                        || node.address.is_some()
                        || node.invalid
                        || !matches!(node.specification, TypeRef::Absent)))
                || (!node.declaration && node.address.is_none() && !abstract_inline_metadata(node, nodes))
            {
                report.warn("incomplete concrete DWARF function-address index cannot establish uniqueness".to_owned());
                return;
            }
            if let Some(address) = node.address {
                addresses.entry(address).or_default().push(offset);
            }
        }
    }
    let mut ambiguous: BTreeSet<_> = function_names
        .values()
        .filter(|identities| {
            identities.iter().map(|&(_, identity)| identity).collect::<BTreeSet<_>>().len() != 1
                || identities.iter().filter(|&&(offset, _)| !nodes[&offset].declaration).count() > 1
        })
        .flatten()
        .map(|&(offset, _)| offset)
        .collect();
    ambiguous.extend(addresses.values().filter(|offsets| offsets.len() != 1).flatten().copied());
    ambiguous.extend(definitions.values().filter(|offsets| offsets.len() != 1).flatten().copied());
    let mut declaration_bytes = 0;
    let mut dependencies = BTreeSet::new();
    for (&offset, node) in nodes {
        if WARNINGS.is_full(&report.warnings) || resolver.work > MAX_WORK {
            report.warn("DWARF layout preview reached the diagnostic/work limit".to_owned());
            break;
        }
        if node.tag != gimli::DW_TAG_subprogram || node.declaration || node.address.is_none() {
            continue;
        }
        if report.signatures.len() >= MAX_SIGNATURES {
            report.warn("DWARF cumulative signature limit exceeded".to_owned());
            break;
        }
        let result = if ambiguous.contains(&offset) {
            Err("ambiguous function name or address across distinct DIE identities".to_owned())
        } else if !is_code(node.address.unwrap()) {
            Err("function address is not mapped code".to_owned())
        } else if node.address_end.is_some_and(|end| end.checked_sub(1).is_none_or(|last| !is_code(last))) {
            Err("function high_pc extent ends outside mapped code".to_owned())
        } else if node.address_end.is_some_and(|end| !supported_extent(node.address.unwrap(), end)) {
            Err("function high_pc extent is not one file-backed code range".to_owned())
        } else {
            resolver.signature(offset, MAX_DECLARATIONS - declaration_bytes)
        };
        match result {
            Ok(signature) => {
                declaration_bytes += signature.declaration.len();
                if report.signatures.len() >= MAX_SIGNATURES || declaration_bytes > MAX_DECLARATIONS {
                    report.warn("DWARF cumulative signature/declaration limit exceeded".to_owned());
                    break;
                }
                if !signature.strictly_applicable {
                    let reason = if signature.eligible_for_native_verification {
                        "incomplete producer leaf/member alignment; checked native verification required"
                    } else {
                        "missing explicit struct alignment; preview only"
                    };
                    report.warn(format!("DWARF function {}: {reason}", signature.original_name));
                }
                dependencies.extend(signature.dependencies.iter().map(|id| id.die_offset as usize));
                report.signatures.push(signature);
            }
            Err(error) => report.warn(format!(
                "skipped DWARF layout function {} at {:#x}: {error}",
                node.name.as_deref().unwrap_or("<unnamed>"),
                node.address.unwrap()
            )),
        }
    }
    for (offset, result) in resolver.layouts {
        if dependencies.contains(&offset)
            && let Ok(layout) = result
        {
            report.layouts.push(layout);
        }
    }
    report.signatures.sort_by_key(|signature| (signature.address, signature.id));
    report.layouts.sort_by_key(|layout| layout.id);
    if report.signatures.is_empty() && report.warnings.is_empty() {
        report.warn("embedded DWARF contains no supported fixed struct-pointer prototypes".to_owned());
    }
}

fn valid_alignment(value: u64) -> bool {
    value.is_power_of_two() && value <= 8
}

fn allowed_attribute(tag: gimli::DwTag, name: gimli::DwAt) -> bool {
    if matches!(
        name,
        gimli::DW_AT_name
            | gimli::DW_AT_decl_file
            | gimli::DW_AT_decl_line
            | gimli::DW_AT_decl_column
            | gimli::DW_AT_sibling
            | gimli::DW_AT_declaration
    ) {
        return true;
    }
    match tag {
        gimli::DW_TAG_base_type => matches!(
            name,
            gimli::DW_AT_byte_size | gimli::DW_AT_encoding | gimli::DW_AT_alignment | gimli::DW_AT_endianity
        ),
        gimli::DW_TAG_typedef => name == gimli::DW_AT_type,
        gimli::DW_TAG_pointer_type => matches!(
            name,
            gimli::DW_AT_type | gimli::DW_AT_byte_size | gimli::DW_AT_address_class | gimli::DW_AT_alignment
        ),
        gimli::DW_TAG_structure_type => matches!(name, gimli::DW_AT_byte_size | gimli::DW_AT_alignment),
        gimli::DW_TAG_member => matches!(
            name,
            gimli::DW_AT_type | gimli::DW_AT_byte_size | gimli::DW_AT_data_member_location | gimli::DW_AT_alignment
        ),
        gimli::DW_TAG_subprogram => matches!(
            name,
            gimli::DW_AT_type
                | gimli::DW_AT_low_pc
                | gimli::DW_AT_high_pc
                | gimli::DW_AT_prototyped
                | gimli::DW_AT_inline
                | gimli::DW_AT_calling_convention
                | gimli::DW_AT_external
                | gimli::DW_AT_frame_base
                | gimli::DW_AT_GNU_all_call_sites
                | gimli::DW_AT_GNU_all_tail_call_sites
                | gimli::DW_AT_call_all_calls
                | gimli::DW_AT_call_all_source_calls
                | gimli::DW_AT_call_all_tail_calls
        ),
        gimli::DW_TAG_formal_parameter => matches!(name, gimli::DW_AT_type | gimli::DW_AT_location),
        _ => false,
    }
}

fn allowed_cpp_attribute(tag: gimli::DwTag, name: gimli::DwAt) -> bool {
    match tag {
        gimli::DW_TAG_class_type | gimli::DW_TAG_structure_type => {
            matches!(name, gimli::DW_AT_byte_size | gimli::DW_AT_alignment | gimli::DW_AT_calling_convention)
        }
        gimli::DW_TAG_member => matches!(name, gimli::DW_AT_accessibility | gimli::DW_AT_artificial),
        gimli::DW_TAG_subprogram => matches!(
            name,
            gimli::DW_AT_linkage_name
                | gimli::DW_AT_MIPS_linkage_name
                | gimli::DW_AT_specification
                | gimli::DW_AT_object_pointer
                | gimli::DW_AT_accessibility
                | gimli::DW_AT_artificial
        ),
        gimli::DW_TAG_formal_parameter => name == gimli::DW_AT_artificial,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type RawAttribute = (gimli::DwAt, gimli::DwForm, Vec<u8>);
    type AbbreviationKey = (u16, bool, Vec<(u16, u16)>);

    #[derive(Default)]
    struct Raw {
        entries: Vec<u8>,
        abbreviations: Vec<u8>,
        codes: BTreeMap<AbbreviationKey, usize>,
    }

    fn uleb(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            bytes.push(byte | if value == 0 { 0 } else { 0x80 });
            if value == 0 {
                return bytes;
            }
        }
    }

    fn number(name: gimli::DwAt, value: u64) -> RawAttribute {
        (name, gimli::DW_FORM_udata, uleb(value))
    }

    fn text(name: &str) -> RawAttribute {
        let mut bytes = name.as_bytes().to_vec();
        bytes.push(0);
        (gimli::DW_AT_name, gimli::DW_FORM_string, bytes)
    }

    fn target(offset: usize) -> RawAttribute {
        (gimli::DW_AT_type, gimli::DW_FORM_ref4, (offset as u32).to_le_bytes().to_vec())
    }

    fn flag(name: gimli::DwAt, value: bool) -> RawAttribute {
        (name, gimli::DW_FORM_flag, vec![u8::from(value)])
    }

    fn expression(name: gimli::DwAt) -> RawAttribute {
        (name, gimli::DW_FORM_exprloc, vec![1, gimli::DW_OP_lit0.0])
    }

    impl Raw {
        fn die(&mut self, tag: gimli::DwTag, children: bool, attributes: Vec<RawAttribute>) -> usize {
            let key = (tag.0, children, attributes.iter().map(|(name, form, _)| (name.0, form.0)).collect());
            let next = self.codes.len() + 1;
            let code = *self.codes.entry(key).or_insert_with(|| {
                self.abbreviations.extend(uleb(next as u64));
                self.abbreviations.extend(uleb(u64::from(tag.0)));
                self.abbreviations.push(u8::from(children));
                for (name, form, _) in &attributes {
                    self.abbreviations.extend(uleb(u64::from(name.0)));
                    self.abbreviations.extend(uleb(u64::from(form.0)));
                }
                self.abbreviations.extend_from_slice(&[0, 0]);
                next
            });
            let offset = self.entries.len() + 11;
            self.entries.extend(uleb(code as u64));
            for (_, _, bytes) in attributes {
                self.entries.extend(bytes);
            }
            offset
        }

        fn close(&mut self) {
            self.entries.push(0);
        }

        fn unit(&self) -> Vec<u8> {
            let mut bytes = ((self.entries.len() + 7) as u32).to_le_bytes().to_vec();
            bytes.extend_from_slice(&[4, 0, 0, 0, 0, 0, 8]);
            bytes.extend_from_slice(&self.entries);
            bytes
        }

        fn unit5(&self) -> Vec<u8> {
            let mut bytes = ((self.entries.len() + 8) as u32).to_le_bytes().to_vec();
            bytes.extend_from_slice(&[5, 0, gimli::DW_UT_compile.0, 8, 0, 0, 0, 0]);
            bytes.extend_from_slice(&self.entries);
            bytes
        }

        fn abbrev(&self) -> Vec<u8> {
            let mut bytes = self.abbreviations.clone();
            bytes.push(0);
            bytes
        }

        fn root(&mut self, language: gimli::DwLang) {
            self.die(gimli::DW_TAG_compile_unit, true, vec![number(gimli::DW_AT_language, u64::from(language.0))]);
        }

        fn scalar(&mut self, name: &str, size: Option<u64>, encoding: gimli::DwAte) -> usize {
            let mut attributes = vec![text(name), number(gimli::DW_AT_encoding, u64::from(encoding.0))];
            if let Some(size) = size {
                attributes.push(number(gimli::DW_AT_byte_size, size));
            }
            self.die(gimli::DW_TAG_base_type, false, attributes)
        }
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

    fn read(raw: &Raw) -> Result<BTreeMap<usize, LayoutNode>, String> {
        read_layout_nodes(&dwarf(&raw.unit(), &raw.abbrev()))
    }

    struct Flat {
        raw: Raw,
        structure: usize,
        fields: Vec<usize>,
        pointer: usize,
        function: usize,
        parameter: usize,
        integer: usize,
    }

    fn flat(alignment: Option<RawAttribute>) -> Flat {
        flat_extent(alignment, None)
    }

    fn flat_extent(alignment: Option<RawAttribute>, high_pc: Option<RawAttribute>) -> Flat {
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        let character = raw.scalar("signed char", Some(1), gimli::DW_ATE_signed_char);
        let integer = raw.scalar("int", Some(4), gimli::DW_ATE_signed);
        let pointer = raw.die(gimli::DW_TAG_pointer_type, false, vec![target(integer)]);
        let mut attributes = vec![text("record"), number(gimli::DW_AT_byte_size, 24)];
        attributes.extend(alignment);
        let structure = raw.die(gimli::DW_TAG_structure_type, true, attributes);
        let mut fields = Vec::new();
        for (name, offset, ty) in [("tag", 0, character), ("count", 4, integer), ("value", 8, pointer)] {
            fields.push(raw.die(
                gimli::DW_TAG_member,
                false,
                vec![text(name), number(gimli::DW_AT_data_member_location, offset), target(ty)],
            ));
        }
        raw.close();
        let pointer = raw.die(gimli::DW_TAG_pointer_type, false, vec![target(structure)]);
        let mut function_attributes = vec![
            text("read_record"),
            flag(gimli::DW_AT_prototyped, true),
            target(integer),
            (gimli::DW_AT_low_pc, gimli::DW_FORM_addr, 0x1234_5678_9000u64.to_le_bytes().to_vec()),
        ];
        function_attributes.extend(high_pc);
        let function = raw.die(gimli::DW_TAG_subprogram, true, function_attributes);
        let parameter = raw.die(gimli::DW_TAG_formal_parameter, false, vec![text("item"), target(pointer)]);
        raw.close();
        raw.close();
        Flat { raw, structure, fields, pointer, function, parameter, integer }
    }

    fn report(nodes: &BTreeMap<usize, LayoutNode>) -> DebugLayoutReport {
        let mut report = DebugLayoutReport::default();
        build_report(nodes, |_| true, |start, end| end > start, &mut report);
        report
    }

    fn reference(name: gimli::DwAt, offset: usize) -> RawAttribute {
        (name, gimli::DW_FORM_ref4, (offset as u32).to_le_bytes().to_vec())
    }

    fn linkage(name: &str) -> RawAttribute {
        let (_, form, bytes) = text(name);
        (gimli::DW_AT_linkage_name, form, bytes)
    }

    struct Cpp {
        raw: Raw,
        record: usize,
        declaration: usize,
        declared_object: usize,
        definition: usize,
        object: usize,
        pointer: usize,
        declared_pointer: usize,
        integer: usize,
        field: usize,
    }

    fn cpp(language: gimli::DwLang, tag: gimli::DwTag, declaration_extra: Vec<RawAttribute>) -> Cpp {
        let mut raw = Raw::default();
        raw.root(language);
        let character = raw.scalar("signed char", Some(1), gimli::DW_ATE_signed_char);
        let integer = raw.scalar("int", Some(4), gimli::DW_ATE_signed);
        let flags = raw.scalar("unsigned short", Some(2), gimli::DW_ATE_unsigned);
        let weight = raw.scalar("double", Some(8), gimli::DW_ATE_float);
        let tail = raw.scalar("unsigned char", Some(1), gimli::DW_ATE_unsigned_char);
        let scalar_pointer = raw.die(gimli::DW_TAG_pointer_type, false, vec![target(integer)]);
        let declared_pointer = raw.die(gimli::DW_TAG_pointer_type, false, vec![target(0)]);
        let pointer_patch = raw.entries.len() - 4;
        let record = raw.die(
            tag,
            true,
            vec![
                text("CheckedRecord"),
                number(gimli::DW_AT_byte_size, 40),
                number(gimli::DW_AT_alignment, 8),
                number(gimli::DW_AT_calling_convention, u64::from(gimli::DW_CC_pass_by_value.0)),
            ],
        );
        raw.entries[pointer_patch..pointer_patch + 4].copy_from_slice(&(record as u32).to_le_bytes());
        let mut field = 0;
        for (name, offset, ty) in [
            ("tag", 0, character),
            ("count", 4, integer),
            ("flags", 8, flags),
            ("weight", 16, weight),
            ("value", 24, scalar_pointer),
            ("tail", 32, tail),
        ] {
            field = raw.die(
                gimli::DW_TAG_member,
                false,
                vec![
                    text(name),
                    target(ty),
                    number(gimli::DW_AT_data_member_location, offset),
                    number(gimli::DW_AT_accessibility, u64::from(gimli::DW_ACCESS_public.0)),
                ],
            );
        }
        let mut attributes = vec![
            text("readcount"),
            linkage("_ZN13CheckedRecord9readcountEv"),
            flag(gimli::DW_AT_declaration, true),
            target(integer),
        ];
        attributes.extend(declaration_extra);
        let declaration = raw.die(gimli::DW_TAG_subprogram, true, attributes);
        let declared_object = raw.die(
            gimli::DW_TAG_formal_parameter,
            false,
            vec![target(declared_pointer), flag(gimli::DW_AT_artificial, true)],
        );
        raw.close();
        raw.close();
        let pointer = raw.die(gimli::DW_TAG_pointer_type, false, vec![target(record)]);
        let definition = raw.die(
            gimli::DW_TAG_subprogram,
            true,
            vec![
                reference(gimli::DW_AT_specification, declaration),
                (gimli::DW_AT_low_pc, gimli::DW_FORM_addr, 0x1234_5678_9000u64.to_le_bytes().to_vec()),
                reference(gimli::DW_AT_object_pointer, 0),
            ],
        );
        let definition_patch = raw.entries.len() - 4;
        let object = raw.die(
            gimli::DW_TAG_formal_parameter,
            false,
            vec![text("not_named_this"), target(pointer), flag(gimli::DW_AT_artificial, true)],
        );
        raw.entries[definition_patch..definition_patch + 4].copy_from_slice(&(object as u32).to_le_bytes());
        raw.close();
        raw.close();
        Cpp { raw, record, declaration, declared_object, definition, object, pointer, declared_pointer, integer, field }
    }

    #[test]
    fn cpp_methods_require_exact_producer_owned_object_identity_not_a_this_name() {
        for language in [
            gimli::DW_LANG_C_plus_plus,
            gimli::DW_LANG_C_plus_plus_11,
            gimli::DW_LANG_C_plus_plus_14,
            gimli::DW_LANG_C_plus_plus_17,
        ] {
            for tag in [gimli::DW_TAG_class_type, gimli::DW_TAG_structure_type] {
                let cpp = cpp(language, tag, Vec::new());
                let nodes = read(&cpp.raw).unwrap();
                let output = report(&nodes);
                assert_eq!(output.signatures.len(), 1, "{language} {tag}: {output:?}");
                assert_eq!(output.layouts.len(), 1, "{output:?}");
                let layout = &output.layouts[0];
                assert_eq!(layout.id, nodes[&cpp.record].id);
                assert_eq!((layout.byte_size, layout.producer_alignment), (40, Some(8)));
                assert_eq!(layout.fields.len(), 6);
                let signature = &output.signatures[0];
                let method = signature.method.as_ref().unwrap();
                assert_eq!(method.record_id, layout.id);
                assert_eq!(method.declaration_id, nodes[&cpp.declaration].id);
                assert_eq!(method.object_pointer_id, nodes[&cpp.object].id);
                assert_ne!(method.object_pointer_id, nodes[&cpp.declared_object].id);
                assert!(matches!(nodes[&cpp.declaration].object_pointer, TypeRef::Absent));
                assert_ne!(nodes[&cpp.pointer].id, nodes[&cpp.declared_pointer].id);
                assert_eq!(method.linkage_name, "_ZN13CheckedRecord9readcountEv");
                assert_eq!(signature.id, nodes[&cpp.definition].id);
                assert_eq!(signature.original_name, "readcount");
                assert!(ordinary_identifier(&signature.emitted_name));
                assert_eq!(signature.parameters[0].emitted_name, "self");
                assert_eq!(signature.parameters[0].original_name.as_deref(), Some("not_named_this"));
                assert!(signature.declaration.contains(&format!("struct {} * self", layout.emitted_name)));
                assert!(signature.eligible_for_native_verification);
                assert!(!signature.strictly_applicable);
            }
        }
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let output = report(&read(&flat.raw).unwrap());
        assert!(output.signatures[0].method.is_none());
        let json = serde_json::to_value(&output).unwrap();
        assert!(json["signatures"][0].get("method").is_none());
    }

    #[test]
    fn cpp_object_pointer_must_be_first_actual_formal_and_direct_exact_record_pointer() {
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let original = read(&cpp.raw).unwrap();
        for case in 0..12 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&cpp.definition).unwrap().object_pointer = TypeRef::Absent,
                1 => nodes.get_mut(&cpp.definition).unwrap().object_pointer = TypeRef::Unsupported,
                2 => nodes.get_mut(&cpp.definition).unwrap().object_pointer = TypeRef::Offset(cpp.declared_object),
                3 => nodes.get_mut(&cpp.definition).unwrap().object_pointer = TypeRef::Offset(cpp.integer),
                4 => nodes.get_mut(&cpp.object).unwrap().parent = Some(cpp.declaration),
                5 => nodes.get_mut(&cpp.object).unwrap().target = TypeRef::Offset(cpp.record),
                6 => nodes.get_mut(&cpp.pointer).unwrap().target = TypeRef::Offset(cpp.integer),
                7 => nodes.get_mut(&cpp.declared_object).unwrap().artificial = false,
                8 => {
                    let mut alias = nodes[&cpp.integer].clone();
                    alias.id.die_offset = 9999;
                    alias.tag = gimli::DW_TAG_typedef;
                    alias.target = TypeRef::Offset(cpp.record);
                    nodes.insert(9999, alias);
                    nodes.get_mut(&cpp.pointer).unwrap().target = TypeRef::Offset(9999);
                }
                9 => {
                    let mut parameter = nodes[&cpp.object].clone();
                    parameter.id.die_offset = 9999;
                    parameter.name = Some("earlier".to_owned());
                    nodes.insert(9999, parameter);
                    nodes.get_mut(&cpp.definition).unwrap().children.insert(0, 9999);
                }
                10 => nodes.get_mut(&cpp.declaration).unwrap().object_pointer = TypeRef::Offset(cpp.object),
                11 => nodes.get_mut(&cpp.object).unwrap().artificial = false,
                _ => unreachable!(),
            }
            let output = report(&nodes);
            assert!(output.layouts.is_empty() && output.signatures.is_empty(), "case {case}: {output:?}");
        }
        let mut nodes = original;
        nodes.get_mut(&cpp.declaration).unwrap().object_pointer = TypeRef::Offset(cpp.declared_object);
        assert_eq!(report(&nodes).signatures.len(), 1);
    }

    #[test]
    fn cpp_specification_is_one_same_cu_hop_and_conflicting_definition_facts_never_override_it() {
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let original = read(&cpp.raw).unwrap();
        for case in 0..12 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&cpp.definition).unwrap().specification = TypeRef::Absent,
                1 => nodes.get_mut(&cpp.definition).unwrap().specification = TypeRef::Offset(cpp.definition),
                2 => nodes.get_mut(&cpp.declaration).unwrap().specification = TypeRef::Offset(cpp.definition),
                3 => nodes.get_mut(&cpp.declaration).unwrap().id.unit_offset = 1000,
                4 => nodes.get_mut(&cpp.definition).unwrap().name = Some("different".to_owned()),
                5 => nodes.get_mut(&cpp.definition).unwrap().linkage_name = Some("_ZN5Other4readEv".to_owned()),
                6 => nodes.get_mut(&cpp.definition).unwrap().target = TypeRef::Offset(cpp.pointer),
                7 => nodes.get_mut(&cpp.declaration).unwrap().declaration = false,
                8 => nodes.get_mut(&cpp.declaration).unwrap().parent = nodes[&cpp.record].parent,
                9 => nodes.get_mut(&cpp.declaration).unwrap().invalid = true,
                10 => nodes.get_mut(&cpp.definition).unwrap().invalid = true,
                11 => nodes.get_mut(&cpp.declaration).unwrap().specification = TypeRef::Offset(cpp.declaration),
                _ => unreachable!(),
            }
            let output = report(&nodes);
            assert!(output.layouts.is_empty() && output.signatures.is_empty(), "case {case}: {output:?}");
        }
        let mut nodes = original;
        nodes.get_mut(&cpp.definition).unwrap().name = nodes[&cpp.declaration].name.clone();
        nodes.get_mut(&cpp.definition).unwrap().linkage_name = nodes[&cpp.declaration].linkage_name.clone();
        nodes.get_mut(&cpp.definition).unwrap().target = nodes[&cpp.declaration].target;
        assert_eq!(report(&nodes).signatures.len(), 1, "equal explicit facts must not create a namesake collision");
    }

    #[test]
    fn cpp_virtuality_unknown_qualifiers_static_methods_and_non_natural_layouts_refuse_atomically() {
        for attribute in [
            number(gimli::DW_AT_virtuality, 1),
            reference(gimli::DW_AT_abstract_origin, 0),
            number(gimli::DW_AT_reference, 1),
            number(gimli::DW_AT_rvalue_reference, 1),
            number(gimli::DW_AT_GNU_deleted, 1),
        ] {
            let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, vec![attribute]);
            let nodes = read(&cpp.raw).unwrap();
            assert!(nodes[&cpp.declaration].invalid);
            let output = report(&nodes);
            assert!(output.signatures.is_empty() && output.layouts.is_empty(), "{output:?}");
        }
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let original = read(&cpp.raw).unwrap();
        for case in 0..12 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&cpp.record).unwrap().alignment = None,
                1 => nodes.get_mut(&cpp.record).unwrap().alignment = Some(4),
                2 => nodes.get_mut(&cpp.field).unwrap().member_offset = Some(40),
                3 => nodes.get_mut(&cpp.field).unwrap().artificial = true,
                4 => nodes.get_mut(&cpp.field).unwrap().tag = gimli::DW_TAG_inheritance,
                5 => nodes.get_mut(&cpp.field).unwrap().tag = gimli::DW_TAG_template_type_parameter,
                6 => nodes.get_mut(&cpp.declaration).unwrap().name = Some("CheckedRecord".to_owned()),
                7 => nodes.get_mut(&cpp.declaration).unwrap().name = Some("~CheckedRecord".to_owned()),
                8 => {
                    nodes.get_mut(&cpp.declaration).unwrap().linkage_name =
                        Some("_ZThn8_N13CheckedRecord9readcountEv".to_owned());
                }
                9 => {
                    nodes.get_mut(&cpp.definition).unwrap().object_pointer = TypeRef::Absent;
                    nodes.get_mut(&cpp.declaration).unwrap().object_pointer = TypeRef::Absent;
                    nodes.get_mut(&cpp.object).unwrap().name = Some("this".to_owned());
                }
                10 => nodes.get_mut(&cpp.record).unwrap().name = Some("CheckedRecord<int>".to_owned()),
                11 => nodes.get_mut(&cpp.pointer).unwrap().tag = gimli::DW_TAG_reference_type,
                _ => unreachable!(),
            }
            let output = report(&nodes);
            assert!(output.signatures.is_empty() && output.layouts.is_empty(), "case {case}: {output:?}");
        }
        for qualifier in [gimli::DW_TAG_const_type, gimli::DW_TAG_volatile_type] {
            let mut nodes = original.clone();
            let mut qualified = nodes[&cpp.integer].clone();
            qualified.id.die_offset = 9999;
            qualified.tag = qualifier;
            qualified.target = TypeRef::Offset(cpp.record);
            nodes.insert(9999, qualified);
            nodes.get_mut(&cpp.pointer).unwrap().target = TypeRef::Offset(9999);
            assert!(report(&nodes).signatures.is_empty());
        }
    }

    #[test]
    fn cpp_method_proof_and_new_reference_and_linkage_reads_consume_existing_budgets() {
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let nodes = read(&cpp.raw).unwrap();
        let mut resolver = Resolver::new(&nodes);
        resolver.work = MAX_WORK;
        assert!(resolver.signature(cpp.definition, MAX_DECLARATION).unwrap_err().contains("work limit"));
        assert!(resolver.layouts.is_empty());
        let mut resolver = Resolver::new(&nodes);
        resolver.text = MAX_NAMES;
        assert!(resolver.signature(cpp.definition, MAX_DECLARATION).unwrap_err().contains("text"));
        assert!(Resolver::new(&nodes).signature(cpp.definition, 1).unwrap_err().contains("declaration"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C_plus_plus_14);
        raw.die(gimli::DW_TAG_subprogram, false, vec![linkage(&"x".repeat(MAX_NAME + 1))]);
        raw.close();
        assert!(read(&raw).unwrap_err().contains("128"));
    }

    #[test]
    fn cpp_linkage_and_explicit_declaration_identity_disambiguate_same_named_methods() {
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let original = read(&cpp.raw).unwrap();
        for duplicate_linkage in [false, true] {
            let mut nodes = original.clone();
            let mut declaration = nodes[&cpp.declaration].clone();
            declaration.id.die_offset = 10_000;
            declaration.children = vec![10_001];
            declaration.object_pointer = TypeRef::Offset(10_001);
            if !duplicate_linkage {
                declaration.linkage_name = Some("_ZN13CheckedRecord9readcountEi".to_owned());
            }
            let mut declared_object = nodes[&cpp.declared_object].clone();
            declared_object.id.die_offset = 10_001;
            declared_object.parent = Some(10_000);
            let mut definition = nodes[&cpp.definition].clone();
            definition.id.die_offset = 10_002;
            definition.address = Some(definition.address.unwrap() + 32);
            definition.specification = TypeRef::Offset(10_000);
            definition.object_pointer = TypeRef::Offset(10_003);
            definition.children = vec![10_003];
            let mut object = nodes[&cpp.object].clone();
            object.id.die_offset = 10_003;
            object.parent = Some(10_002);
            if !duplicate_linkage {
                let mut declared_argument = nodes[&cpp.declared_object].clone();
                declared_argument.id.die_offset = 10_004;
                declared_argument.parent = Some(10_000);
                declared_argument.target = TypeRef::Offset(cpp.integer);
                declared_argument.artificial = false;
                declaration.children.push(10_004);
                let mut argument = declared_argument.clone();
                argument.id.die_offset = 10_005;
                argument.parent = Some(10_002);
                argument.name = Some("delta".to_owned());
                definition.children.push(10_005);
                nodes.insert(10_004, declared_argument);
                nodes.insert(10_005, argument);
            }
            nodes.insert(10_000, declaration);
            nodes.insert(10_001, declared_object);
            nodes.insert(10_002, definition);
            nodes.insert(10_003, object);
            nodes.get_mut(&cpp.record).unwrap().children.push(10_000);
            let output = report(&nodes);
            if duplicate_linkage {
                assert!(output.signatures.is_empty() && output.layouts.is_empty(), "{output:?}");
            } else {
                assert_eq!(output.signatures.len(), 2, "{output:?}");
                assert_eq!(output.layouts.len(), 1, "{output:?}");
                assert_ne!(output.signatures[0].emitted_name, output.signatures[1].emitted_name);
                assert_eq!(output.signatures[0].original_name, output.signatures[1].original_name);
                assert_eq!(output.signatures[1].parameters.len(), 2);
                assert_eq!(output.signatures[1].parameters[1].emitted_name, "delta");
            }
        }
        let mut nodes = original;
        let mut wrapper = nodes[&cpp.definition].clone();
        wrapper.id.die_offset = 20_000;
        wrapper.name = Some("debug_cpp_read_count".to_owned());
        wrapper.address = Some(wrapper.address.unwrap() + 64);
        wrapper.specification = TypeRef::Absent;
        wrapper.object_pointer = TypeRef::Absent;
        wrapper.prototyped = true;
        let mut argument = nodes[&cpp.object].clone();
        argument.id.die_offset = 20_001;
        argument.name = Some("this".to_owned());
        argument.parent = Some(20_000);
        argument.artificial = false;
        wrapper.children = vec![20_001];
        nodes.insert(20_000, wrapper);
        nodes.insert(20_001, argument);
        let output = report(&nodes);
        assert_eq!(output.signatures.len(), 1, "{output:?}");
        assert_eq!(output.signatures[0].id, nodes[&cpp.definition].id);
        let mut concrete = nodes[&cpp.definition].clone();
        concrete.id.die_offset = 30_000;
        concrete.address = Some(concrete.address.unwrap() + 128);
        nodes.insert(30_000, concrete);
        let output = report(&nodes);
        assert!(output.signatures.is_empty() && output.layouts.is_empty(), "duplicate definition: {output:?}");
        nodes.get_mut(&30_000).unwrap().linkage_name = Some("_ZN5Other4readEv".to_owned());
        let output = report(&nodes);
        assert!(output.signatures.is_empty() && output.layouts.is_empty(), "conflicting duplicate: {output:?}");
    }

    #[test]
    fn cpp_scalar_setter_is_lowered_but_reference_byvalue_variadic_and_artificial_arguments_are_not() {
        let cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
        let mut original = read(&cpp.raw).unwrap();
        original.get_mut(&cpp.declaration).unwrap().name = Some("writeCount".to_owned());
        original.get_mut(&cpp.declaration).unwrap().linkage_name = Some("_ZN13CheckedRecord10writeCountEi".to_owned());
        original.get_mut(&cpp.declaration).unwrap().target = TypeRef::Absent;
        let mut declared = original[&cpp.declared_object].clone();
        declared.id.die_offset = 10_000;
        declared.target = TypeRef::Offset(cpp.integer);
        declared.artificial = false;
        let mut actual = declared.clone();
        actual.id.die_offset = 10_001;
        actual.parent = Some(cpp.definition);
        actual.name = Some("replacement".to_owned());
        original.insert(10_000, declared);
        original.insert(10_001, actual);
        original.get_mut(&cpp.declaration).unwrap().children.push(10_000);
        original.get_mut(&cpp.definition).unwrap().children.push(10_001);
        let output = report(&original);
        assert_eq!(output.signatures.len(), 1, "{output:?}");
        assert!(matches!(&output.signatures[0].return_type, DebugLayoutValue::Void));
        assert_eq!(output.signatures[0].parameters.len(), 2);
        assert!(output.signatures[0].declaration.contains("int32_t replacement"));
        for case in 0..8 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&10_001).unwrap().target = TypeRef::Absent,
                1 => nodes.get_mut(&10_001).unwrap().target = TypeRef::Offset(cpp.record),
                2 => nodes.get_mut(&10_001).unwrap().tag = gimli::DW_TAG_unspecified_parameters,
                3 => nodes.get_mut(&10_001).unwrap().artificial = true,
                4 => nodes.get_mut(&10_001).unwrap().name = Some("self".to_owned()),
                5 => nodes.get_mut(&cpp.declaration).unwrap().target = TypeRef::Offset(cpp.record),
                6 => nodes.get_mut(&cpp.integer).unwrap().tag = gimli::DW_TAG_reference_type,
                7 => nodes.get_mut(&cpp.integer).unwrap().tag = gimli::DW_TAG_ptr_to_member_type,
                _ => unreachable!(),
            }
            let output = report(&nodes);
            assert!(output.signatures.is_empty() && output.layouts.is_empty(), "case {case}: {output:?}");
        }
    }

    #[test]
    fn exact_flat_layout_and_64_bit_address_are_identity_linked_without_natural_alignment_inference() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let nodes = read(&flat.raw).unwrap();
        let output = report(&nodes);
        assert_eq!(output.layouts.len(), 1, "{output:?}");
        assert_eq!(output.signatures.len(), 1, "{output:?}");
        let layout = &output.layouts[0];
        assert_eq!(layout.id, nodes[&flat.structure].id);
        assert_eq!(layout.byte_size, 24);
        assert_eq!(layout.producer_alignment, Some(8));
        assert!(!layout.strictly_applicable);
        assert!(layout.eligible_for_native_verification);
        let extents: Vec<_> = layout.fields.iter().map(|field| (field.offset, field.byte_size)).collect();
        assert_eq!(extents, [(0, 1), (4, 4), (8, 8)]);
        let signature = &output.signatures[0];
        assert_eq!(signature.address, 0x1234_5678_9000);
        assert_eq!(signature.dependencies, [layout.id]);
        assert!(!signature.strictly_applicable);
        assert!(signature.eligible_for_native_verification);
        assert!(signature.declaration.contains(&format!("struct {} * item", layout.emitted_name)));
        assert!(matches!(&layout.fields[0].leaf, DebugLayoutLeaf::Scalar { scalar }
            if scalar.kind == DebugLayoutScalarKind::SignedInteger && scalar.declaration == "int8_t"));
        assert!(matches!(&layout.fields[2].leaf, DebugLayoutLeaf::Pointer { pointee: Some(scalar), .. }
            if scalar.byte_size == 4 && scalar.encoding == gimli::DW_ATE_signed.0));
    }

    #[test]
    fn absent_alignment_is_preview_only_but_bad_or_expression_alignment_is_refused() {
        let missing = flat(None);
        let output = report(&read(&missing.raw).unwrap());
        assert_eq!(output.layouts.len(), 1, "{output:?}");
        assert_eq!(output.layouts[0].producer_alignment, None);
        assert!(!output.layouts[0].strictly_applicable);
        assert!(!output.signatures[0].strictly_applicable);
        assert!(!output.layouts[0].eligible_for_native_verification);
        assert!(!output.signatures[0].eligible_for_native_verification);
        assert!(output.warnings.iter().any(|warning| warning.contains("preview only")));
        for attribute in [
            number(gimli::DW_AT_alignment, 0),
            number(gimli::DW_AT_alignment, 3),
            number(gimli::DW_AT_alignment, 16),
            expression(gimli::DW_AT_alignment),
        ] {
            let flat = flat(Some(attribute));
            let output = report(&read(&flat.raw).unwrap());
            assert!(output.layouts.is_empty(), "{output:?}");
            assert!(output.signatures.is_empty(), "{output:?}");
        }
    }

    #[test]
    fn malformed_duplicate_attributes_and_truncated_children_do_not_yield_partial_nodes() {
        let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        flat.raw.entries.pop();
        assert!(read(&flat.raw).unwrap_err().contains("unterminated"));
        flat.raw.entries.pop();
        assert!(read(&flat.raw).is_err());
        for name in [
            gimli::DW_AT_byte_size,
            gimli::DW_AT_alignment,
            gimli::DW_AT_data_member_location,
            gimli::DW_AT_encoding,
            gimli::DW_AT_type,
        ] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            raw.die(gimli::DW_TAG_member, false, vec![number(name, 4), number(name, 8)]);
            raw.close();
            assert!(read(&raw).unwrap_err().contains("duplicate"));
        }
    }

    #[test]
    fn scalar_width_and_encoding_not_display_names_establish_exact_leaf_types() {
        for (size, encoding) in [
            (None, gimli::DW_ATE_signed_char),
            (Some(2), gimli::DW_ATE_signed_char),
            (Some(8), gimli::DW_ATE_unsigned_char),
            (Some(4), gimli::DW_ATE_address),
        ] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            let offset = raw.scalar("int32_t", size, encoding);
            raw.close();
            let nodes = read(&raw).unwrap();
            assert!(Resolver::new(&nodes).resolve(TypeRef::Offset(offset), 0).is_err());
        }
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        nodes.get_mut(&flat.integer).unwrap().name = Some("unsigned int".to_owned());
        let output = report(&nodes);
        assert!(matches!(&output.layouts[0].fields[1].leaf, DebugLayoutLeaf::Scalar { scalar }
            if scalar.kind == DebugLayoutScalarKind::SignedInteger));
    }

    #[test]
    fn every_layout_sensitive_unsupported_attribute_invalidates_its_die() {
        for tag in [gimli::DW_TAG_structure_type, gimli::DW_TAG_member, gimli::DW_TAG_base_type] {
            for attribute in [
                gimli::DW_AT_bit_size,
                gimli::DW_AT_bit_offset,
                gimli::DW_AT_data_bit_offset,
                gimli::DW_AT_byte_stride,
                gimli::DW_AT_bit_stride,
                gimli::DW_AT_abstract_origin,
                gimli::DW_AT_specification,
                gimli::DW_AT_allocated,
                gimli::DW_AT_associated,
                gimli::DW_AT_data_location,
            ] {
                let mut raw = Raw::default();
                raw.root(gimli::DW_LANG_C11);
                let offset = raw.die(tag, false, vec![number(attribute, 0)]);
                raw.close();
                assert!(read(&raw).unwrap()[&offset].invalid, "{tag} {attribute}");
            }
        }
        for attribute in [gimli::DW_AT_byte_size, gimli::DW_AT_data_member_location] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            let offset = raw.die(gimli::DW_TAG_member, false, vec![expression(attribute)]);
            raw.close();
            assert!(read(&raw).unwrap()[&offset].invalid);
        }
    }

    #[test]
    fn overlaps_missing_offsets_overflow_and_incomplete_structs_refuse_dependent_signatures_atomically() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let original = read(&flat.raw).unwrap();
        for case in 0..8 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&flat.fields[1]).unwrap().member_offset = Some(0),
                1 => nodes.get_mut(&flat.fields[1]).unwrap().member_offset = None,
                2 => nodes.get_mut(&flat.fields[1]).unwrap().member_offset = Some(u64::MAX),
                3 => nodes.get_mut(&flat.structure).unwrap().declaration = true,
                4 => nodes.get_mut(&flat.structure).unwrap().size = None,
                5 => nodes.get_mut(&flat.fields[1]).unwrap().size = Some(8),
                6 => nodes.get_mut(&flat.fields[2]).unwrap().member_offset = Some(3),
                7 => nodes.get_mut(&flat.structure).unwrap().size = Some(MAX_SIZE + 1),
                _ => unreachable!(),
            }
            let output = report(&nodes);
            assert!(output.layouts.is_empty(), "case {case}: {output:?}");
            assert!(output.signatures.is_empty(), "case {case}: {output:?}");
        }
        let mut nodes = original;
        nodes.get_mut(&flat.parameter).unwrap().target = TypeRef::Offset(flat.structure);
        assert!(report(&nodes).signatures.is_empty());
        nodes.get_mut(&flat.parameter).unwrap().target = TypeRef::Offset(flat.pointer);
        nodes.get_mut(&flat.function).unwrap().target = TypeRef::Offset(flat.structure);
        assert!(report(&nodes).signatures.is_empty());
    }

    #[test]
    fn second_bad_parameter_never_leaves_a_signature_or_orphan_layout() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        let mut bad = nodes[&flat.parameter].clone();
        bad.id.die_offset = 9999;
        bad.target = TypeRef::Unsupported;
        nodes.insert(9999, bad);
        nodes.get_mut(&flat.function).unwrap().children.push(9999);
        let output = report(&nodes);
        assert!(output.signatures.is_empty(), "{output:?}");
        assert!(output.layouts.is_empty(), "{output:?}");
        let mut nodes = read(&flat.raw).unwrap();
        let mut incomplete = nodes[&flat.structure].clone();
        incomplete.id.die_offset = 9997;
        incomplete.name = Some("incomplete_dependency".to_owned());
        incomplete.size = None;
        nodes.insert(9997, incomplete);
        let mut pointer = nodes[&flat.pointer].clone();
        pointer.id.die_offset = 9998;
        pointer.target = TypeRef::Offset(9997);
        nodes.insert(9998, pointer);
        let mut parameter = nodes[&flat.parameter].clone();
        parameter.id.die_offset = 9999;
        parameter.name = Some("other".to_owned());
        parameter.target = TypeRef::Offset(9998);
        nodes.insert(9999, parameter);
        nodes.get_mut(&flat.function).unwrap().children.push(9999);
        let output = report(&nodes);
        assert!(output.signatures.is_empty(), "{output:?}");
        assert!(output.layouts.is_empty(), "{output:?}");
    }

    #[test]
    fn accepted_and_rejected_types_are_memoized_and_active_cycles_do_not_recurse_unboundedly() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        nodes.get_mut(&flat.integer).unwrap().tag = gimli::DW_TAG_typedef;
        nodes.get_mut(&flat.integer).unwrap().target = TypeRef::Offset(flat.integer);
        let mut resolver = Resolver::new(&nodes);
        let first = resolver.resolve(TypeRef::Offset(flat.integer), 0).unwrap_err();
        assert!(first.contains("recursive"));
        let work = resolver.work;
        assert_eq!(resolver.resolve(TypeRef::Offset(flat.integer), 0).unwrap_err(), first);
        assert_eq!(resolver.work, work + 1);
        assert!(resolver.active.is_empty());
        let nodes = read(&flat.raw).unwrap();
        let mut resolver = Resolver::new(&nodes);
        resolver.layout(flat.structure).unwrap();
        let text = resolver.text;
        resolver.layout(flat.structure).unwrap();
        assert_eq!(resolver.text, text);
        resolver.work = MAX_WORK;
        assert!(resolver.resolve(TypeRef::Offset(flat.integer), 0).unwrap_err().contains("work limit"));
        resolver.text = MAX_NAMES;
        assert!(resolver.retain_text(1).is_err());
    }

    #[test]
    fn fields_and_names_are_bounded_before_retaining_an_unbounded_collection() {
        for count in [MAX_FIELDS, MAX_FIELDS + 1] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            let scalar = raw.scalar("byte", Some(1), gimli::DW_ATE_unsigned);
            let structure = raw.die(
                gimli::DW_TAG_structure_type,
                true,
                vec![number(gimli::DW_AT_byte_size, count as u64), number(gimli::DW_AT_alignment, 1)],
            );
            for index in 0..count {
                raw.die(
                    gimli::DW_TAG_member,
                    false,
                    vec![number(gimli::DW_AT_data_member_location, index as u64), target(scalar)],
                );
            }
            raw.close();
            raw.close();
            if count == MAX_FIELDS {
                let nodes = read(&raw).unwrap();
                Resolver::new(&nodes).layout(structure).unwrap();
            } else {
                assert!(read(&raw).unwrap_err().contains("field limit"));
            }
        }
        for name in ["x".repeat(MAX_NAME + 1), "é".to_owned()] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            raw.scalar(&name, Some(4), gimli::DW_ATE_signed);
            raw.close();
            assert!(read(&raw).is_err());
        }
    }

    #[test]
    fn duplicate_struct_names_in_distinct_cus_are_not_layout_equivalence_proof() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let first = flat.raw.unit();
        let info = [first.clone(), first.clone()].concat();
        let nodes = read_layout_nodes(&dwarf(&info, &flat.raw.abbrev())).unwrap();
        let second = first.len() + flat.structure;
        assert_ne!(nodes[&flat.structure].id, nodes[&second].id);
        assert_eq!(nodes[&second].id.unit_offset, first.len() as u64);
        let mut resolver = Resolver::new(&nodes);
        for offset in [flat.structure, second] {
            assert!(resolver.layout(offset).unwrap_err().contains("distinct DIE identities"));
        }
    }

    #[test]
    fn cross_unit_references_use_absolute_identity_not_equal_relative_offsets() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut second =
            Raw { abbreviations: flat.raw.abbreviations.clone(), codes: flat.raw.codes.clone(), ..Default::default() };
        second.root(gimli::DW_LANG_C11);
        let alias = second.die(
            gimli::DW_TAG_typedef,
            false,
            vec![(gimli::DW_AT_type, gimli::DW_FORM_ref_addr, (flat.structure as u32).to_le_bytes().to_vec())],
        );
        second.close();
        let first = flat.raw.unit();
        let info = [first.clone(), second.unit()].concat();
        let nodes = read_layout_nodes(&dwarf(&info, &second.abbrev())).unwrap();
        let mut resolver = Resolver::new(&nodes);
        assert!(matches!(resolver.resolve(TypeRef::Offset(first.len() + alias), 0).unwrap(),
            Resolved::Struct(offset) if offset == flat.structure));
        resolver.layout(flat.structure).unwrap();
    }

    #[test]
    fn sanitized_collisions_and_synthesized_names_never_normalize_die_identity() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        nodes.get_mut(&flat.fields[0]).unwrap().name = Some("bad-name".to_owned());
        nodes.get_mut(&flat.fields[1]).unwrap().name = Some("bad_name".to_owned());
        assert!(report(&nodes).signatures.is_empty());
        nodes.get_mut(&flat.fields[0]).unwrap().name = None;
        nodes.get_mut(&flat.fields[1]).unwrap().name = Some("int4".to_owned());
        let output = report(&nodes);
        assert_eq!(output.layouts[0].fields[0].emitted_name, "field_1");
        assert_eq!(output.layouts[0].fields[1].emitted_name, "debug_int4");
        assert_eq!(output.layouts[0].fields[0].id, nodes[&flat.fields[0]].id);
    }

    #[test]
    fn unsupported_graph_edges_languages_and_calling_contexts_refuse_whole_prototypes() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let original = read(&flat.raw).unwrap();
        for tag in [
            gimli::DW_TAG_union_type,
            gimli::DW_TAG_array_type,
            gimli::DW_TAG_subroutine_type,
            gimli::DW_TAG_reference_type,
            gimli::DW_TAG_rvalue_reference_type,
            gimli::DW_TAG_const_type,
            gimli::DW_TAG_volatile_type,
            gimli::DW_TAG_restrict_type,
            gimli::DW_TAG_atomic_type,
        ] {
            let mut nodes = original.clone();
            nodes.get_mut(&flat.integer).unwrap().tag = tag;
            assert!(report(&nodes).signatures.is_empty(), "{tag}");
        }
        for case in 0..5 {
            let mut nodes = original.clone();
            match case {
                0 => nodes.get_mut(&flat.fields[0]).unwrap().target = TypeRef::Offset(flat.structure),
                1 => nodes.get_mut(&flat.fields[0]).unwrap().target = TypeRef::Offset(flat.pointer),
                2 => nodes.get_mut(&flat.pointer).unwrap().target = TypeRef::Offset(flat.pointer),
                3 => nodes.get_mut(&flat.function).unwrap().prototyped = false,
                4 => nodes.get_mut(&flat.structure).unwrap().source = None,
                _ => unreachable!(),
            }
            assert!(report(&nodes).signatures.is_empty(), "case {case}");
        }
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_Rust);
        let scalar = raw.scalar("int", Some(4), gimli::DW_ATE_signed);
        raw.close();
        let nodes = read(&raw).unwrap();
        assert!(Resolver::new(&nodes).resolve(TypeRef::Offset(scalar), 0).is_err());
        for (tag, attribute) in [
            (gimli::DW_TAG_subprogram, number(gimli::DW_AT_calling_convention, u64::from(gimli::DW_CC_nocall.0))),
            (gimli::DW_TAG_pointer_type, number(gimli::DW_AT_address_class, 1)),
            (gimli::DW_TAG_base_type, number(gimli::DW_AT_endianity, u64::from(gimli::DW_END_big.0))),
        ] {
            let mut raw = Raw::default();
            raw.root(gimli::DW_LANG_C11);
            let offset = raw.die(tag, false, vec![attribute]);
            raw.close();
            assert!(read(&raw).unwrap()[&offset].invalid);
        }
    }

    #[test]
    fn cached_aliases_cannot_bypass_the_total_type_depth_limit() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        let mut previous = flat.integer;
        for index in 0..MAX_TYPE_DEPTH {
            let offset = 10_000 + index;
            let mut alias = nodes[&flat.integer].clone();
            alias.id.die_offset = offset as u64;
            alias.tag = gimli::DW_TAG_typedef;
            alias.target = TypeRef::Offset(previous);
            nodes.insert(offset, alias);
            previous = offset;
        }
        let mut resolver = Resolver::new(&nodes);
        for index in 0..MAX_TYPE_DEPTH - 1 {
            resolver.resolve(TypeRef::Offset(10_000 + index), 0).unwrap();
        }
        assert!(resolver.resolve(TypeRef::Offset(previous), 0).unwrap_err().contains("depth"));
    }

    #[test]
    fn cumulative_layout_type_function_field_and_attribute_work_caps_are_not_just_depth_limits() {
        for (language, tag, count) in [
            (gimli::DW_LANG_C11, gimli::DW_TAG_structure_type, MAX_LAYOUTS + 1),
            (gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, MAX_LAYOUTS + 1),
            (gimli::DW_LANG_C11, gimli::DW_TAG_base_type, MAX_TYPES + 1),
            (gimli::DW_LANG_C11, gimli::DW_TAG_subprogram, MAX_FUNCTIONS + 1),
        ] {
            let mut raw = Raw::default();
            raw.root(language);
            for _ in 0..count {
                raw.die(tag, false, Vec::new());
            }
            raw.close();
            assert!(read(&raw).unwrap_err().contains("cumulative"), "{tag}");
        }
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        for _ in 0..=MAX_TOTAL_FIELDS / MAX_FIELDS {
            raw.die(gimli::DW_TAG_structure_type, true, Vec::new());
            for _ in 0..MAX_FIELDS {
                raw.die(gimli::DW_TAG_member, false, Vec::new());
            }
            raw.close();
        }
        raw.close();
        assert!(read(&raw).unwrap_err().contains("cumulative"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        let attributes: Vec<_> =
            (0..MAX_ATTRIBUTES - 1).map(|index| number(gimli::DwAt(0x2000 + index as u16), 1)).collect();
        for _ in 0..MAX_WORK / attributes.len() + 2 {
            raw.die(gimli::DW_TAG_base_type, false, attributes.clone());
        }
        raw.close();
        assert!(read(&raw).unwrap_err().contains("work limit"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        let attributes: Vec<_> = (0..MAX_ATTRIBUTES - 1)
            .map(|index| (gimli::DwAt(0x3000 + index as u16), gimli::DW_FORM_flag_present, Vec::new()))
            .collect();
        for _ in 0..MAX_WORK / attributes.len() + 2 {
            raw.die(gimli::DW_TAG_base_type, false, attributes.clone());
        }
        raw.close();
        assert!(read(&raw).unwrap_err().contains("attribute work limit"));
    }

    #[test]
    fn cumulative_name_text_edges_and_declarations_are_bounded() {
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        for _ in 0..=MAX_NAMES / MAX_NAME {
            raw.scalar(&"a".repeat(MAX_NAME), Some(1), gimli::DW_ATE_unsigned);
        }
        raw.close();
        assert!(read(&raw).unwrap_err().contains("retained-text"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        let scalar = raw.scalar("int", Some(4), gimli::DW_ATE_signed);
        for _ in 0..MAX_TOTAL_FIELDS / MAX_FIELDS {
            raw.die(gimli::DW_TAG_structure_type, true, Vec::new());
            for _ in 0..MAX_FIELDS {
                raw.die(gimli::DW_TAG_member, false, vec![target(scalar)]);
            }
            raw.close();
        }
        raw.close();
        assert!(read(&raw).unwrap_err().contains("edge limit"));
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let nodes = read(&flat.raw).unwrap();
        assert!(Resolver::new(&nodes).signature(flat.function, 1).unwrap_err().contains("declaration"));
    }

    #[test]
    fn partial_roots_indirect_forms_and_missing_language_never_establish_source_context() {
        let mut raw = Raw::default();
        raw.die(gimli::DW_TAG_partial_unit, true, Vec::new());
        raw.close();
        assert!(read(&raw).unwrap_err().contains("unit root"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        raw.die(
            gimli::DW_TAG_base_type,
            false,
            vec![(gimli::DW_AT_byte_size, gimli::DW_FORM_indirect, vec![gimli::DW_FORM_data1.0 as u8, 4])],
        );
        raw.close();
        assert!(read(&raw).unwrap_err().contains("abbreviation"));
        let mut raw = Raw::default();
        raw.die(gimli::DW_TAG_compile_unit, true, Vec::new());
        let offset = raw.scalar("int", Some(4), gimli::DW_ATE_signed);
        raw.close();
        let nodes = read(&raw).unwrap();
        assert!(Resolver::new(&nodes).resolve(TypeRef::Offset(offset), 0).is_err());
    }

    #[test]
    fn giant_unknown_root_strings_are_refused_before_any_header_root_or_abbreviation_pass() {
        for name in [gimli::DW_AT_comp_dir, gimli::DW_AT_name] {
            let mut raw = Raw::default();
            let mut bytes = vec![b'x'; 32 * 1024 * 1024];
            bytes.push(0);
            raw.die(gimli::DW_TAG_compile_unit, false, vec![(name, gimli::DW_FORM_string, bytes)]);
            let info = raw.unit();
            let abbrev = raw.abbrev();
            let dwarf = dwarf(&info, &abbrev);
            let mut budget = ReadBudget::default();
            assert!(read_layout_nodes_budget(&dwarf, &mut budget).unwrap_err().contains("pre-read work limit"));
            assert_eq!(budget.root_passes, 0);
            assert_eq!(budget.abbreviation_tables, 0);
            assert_eq!(budget.reserved, 0);
            assert_eq!(budget.rejected_reservations, 1);
        }
    }

    #[test]
    fn hundreds_of_shared_cus_parse_a_thousand_attribute_table_once() {
        let mut raw = Raw::default();
        let mut attributes: Vec<_> = (0..64).map(|index| number(gimli::DwAt(0x3000 + index), 1)).collect();
        attributes.push(number(gimli::DW_AT_language, u64::from(gimli::DW_LANG_C11.0)));
        raw.die(gimli::DW_TAG_compile_unit, false, attributes);
        for code in 2..6 {
            raw.abbreviations.extend(uleb(code));
            raw.abbreviations.extend(uleb(u64::from(gimli::DW_TAG_base_type.0)));
            raw.abbreviations.push(0);
            for attribute in 0..250 {
                raw.abbreviations.extend(uleb(0x4000 + code * 256 + attribute));
                raw.abbreviations.extend(uleb(u64::from(gimli::DW_FORM_data1.0)));
            }
            raw.abbreviations.extend_from_slice(&[0, 0]);
        }
        let info = vec![raw.unit(); MAX_UNITS].concat();
        let abbrev = raw.abbrev();
        let mut budget = ReadBudget::default();
        let nodes = read_layout_nodes_budget(&dwarf(&info, &abbrev), &mut budget).unwrap();
        assert_eq!(nodes.len(), MAX_UNITS);
        assert_eq!(budget.abbreviation_tables, 1);
        assert_eq!(budget.root_passes, MAX_UNITS);
        assert!(budget.reserved <= MAX_READ_WORK);
    }

    #[test]
    fn malformed_bases_and_gnu_standard_conflicts_are_refused_before_indexed_resolution() {
        for base in [gimli::DW_AT_str_offsets_base, gimli::DW_AT_addr_base, gimli::DW_AT_GNU_addr_base] {
            for form in [gimli::DW_FORM_exprloc, gimli::DW_FORM_block, gimli::DW_FORM_data4] {
                let bytes = if form == gimli::DW_FORM_data4 { vec![0; 4] } else { vec![1, 0] };
                let mut raw = Raw::default();
                raw.die(
                    gimli::DW_TAG_compile_unit,
                    false,
                    vec![number(gimli::DW_AT_language, u64::from(gimli::DW_LANG_C11.0)), (base, form, bytes)],
                );
                let error = read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err();
                assert!(error.contains("base"), "{base} {form}: {error}");
            }
        }
        let mut raw = Raw::default();
        raw.die(
            gimli::DW_TAG_compile_unit,
            false,
            vec![
                (gimli::DW_AT_addr_base, gimli::DW_FORM_sec_offset, 8u32.to_le_bytes().to_vec()),
                (gimli::DW_AT_GNU_addr_base, gimli::DW_FORM_sec_offset, 16u32.to_le_bytes().to_vec()),
            ],
        );
        assert!(read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err().contains("conflicting"));
        let mut raw = Raw::default();
        raw.die(
            gimli::DW_TAG_compile_unit,
            false,
            vec![
                (gimli::DW_AT_addr_base, gimli::DW_FORM_sec_offset, 8u32.to_le_bytes().to_vec()),
                (gimli::DW_AT_GNU_addr_base, gimli::DW_FORM_sec_offset, 8u32.to_le_bytes().to_vec()),
            ],
        );
        assert!(read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err().contains("duplicate"));
        for (base, version) in [(gimli::DW_AT_addr_base, 5), (gimli::DW_AT_GNU_addr_base, 4)] {
            let mut raw = Raw::default();
            raw.die(
                gimli::DW_TAG_compile_unit,
                false,
                vec![(base, gimli::DW_FORM_sec_offset, 8u32.to_le_bytes().to_vec())],
            );
            let info = if version == 5 { raw.unit5() } else { raw.unit() };
            assert!(read_layout_nodes(&dwarf(&info, &raw.abbrev())).is_ok());
        }
        let mut raw = Raw::default();
        raw.die(
            gimli::DW_TAG_compile_unit,
            false,
            vec![
                (gimli::DW_AT_str_offsets_base, gimli::DW_FORM_sec_offset, vec![0; 4]),
                (gimli::DW_AT_str_offsets_base, gimli::DW_FORM_sec_offset, vec![0; 4]),
            ],
        );
        assert!(read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err().contains("duplicate"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        raw.die(gimli::DW_TAG_base_type, false, vec![(gimli::DW_AT_name, gimli::DW_FORM_strx1, vec![0])]);
        raw.close();
        assert!(read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err().contains("verified string"));
        let mut raw = Raw::default();
        raw.root(gimli::DW_LANG_C11);
        raw.die(
            gimli::DW_TAG_subprogram,
            false,
            vec![text("indexed"), (gimli::DW_AT_low_pc, gimli::DW_FORM_addrx1, vec![0])],
        );
        raw.close();
        assert!(read_layout_nodes(&dwarf(&raw.unit5(), &raw.abbrev())).unwrap_err().contains("verified address"));
        let mut raw = Raw::default();
        raw.die(
            gimli::DW_TAG_compile_unit,
            false,
            vec![(gimli::DW_AT_str_offsets_base, gimli::DW_FORM_sec_offset, vec![0; 4])],
        );
        assert!(read(&raw).unwrap_err().contains("context"));
    }

    #[test]
    fn strict_flags_require_every_producer_alignment_but_native_candidates_retain_unknowns() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut nodes = read(&flat.raw).unwrap();
        let candidate = report(&nodes);
        assert!(candidate.layouts[0].eligible_for_native_verification);
        assert!(!candidate.layouts[0].strictly_applicable);
        assert_eq!(candidate.layouts[0].fields[0].producer_alignment, None);
        for node in nodes.values_mut() {
            if node.tag == gimli::DW_TAG_base_type {
                node.alignment = node.size;
            } else if node.tag == gimli::DW_TAG_pointer_type {
                node.alignment = Some(8);
            }
        }
        for (&field, alignment) in flat.fields.iter().zip([1, 4, 8]) {
            nodes.get_mut(&field).unwrap().alignment = Some(alignment);
        }
        let proven = report(&nodes);
        assert!(proven.layouts[0].strictly_applicable);
        assert!(proven.signatures[0].strictly_applicable);
        for case in 0..3 {
            let mut partial = nodes.clone();
            match case {
                0 => partial.get_mut(&flat.fields[0]).unwrap().alignment = None,
                1 => partial.get_mut(&flat.integer).unwrap().alignment = None,
                2 => partial.get_mut(&flat.pointer).unwrap().alignment = None,
                _ => unreachable!(),
            }
            let output = report(&partial);
            assert!(output.signatures[0].eligible_for_native_verification);
            assert!(!output.signatures[0].strictly_applicable);
        }
        for case in 0..3 {
            let mut conflicting = nodes.clone();
            match case {
                0 => conflicting.get_mut(&flat.fields[1]).unwrap().alignment = Some(8),
                1 => conflicting.get_mut(&flat.pointer).unwrap().alignment = Some(4),
                2 => conflicting.get_mut(&flat.integer).unwrap().alignment = Some(8),
                _ => unreachable!(),
            }
            assert!(report(&conflicting).signatures.is_empty());
        }
    }

    #[test]
    fn incomplete_invalid_and_unaddressed_namesakes_prevent_uniqueness() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let original = read(&flat.raw).unwrap();
        for case in 0..5 {
            let mut nodes = original.clone();
            let mut other = nodes[&flat.function].clone();
            other.id.die_offset = 9999;
            match case {
                0 => other.address = None,
                1 => other.invalid = true,
                2 => other.declaration = true,
                3 => {
                    other.address = None;
                    other.invalid = true;
                }
                4 => other.name = None,
                _ => unreachable!(),
            }
            nodes.insert(9999, other);
            let output = report(&nodes);
            assert!(output.layouts.is_empty(), "case {case}: {output:?}");
            assert!(output.signatures.is_empty(), "case {case}: {output:?}");
        }
    }

    #[test]
    fn nested_formals_or_varargs_cannot_be_hidden_in_body_blocks_but_normal_locals_can() {
        for tag in [gimli::DW_TAG_formal_parameter, gimli::DW_TAG_unspecified_parameters, gimli::DW_TAG_variable] {
            let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
            flat.raw.entries.truncate(flat.raw.entries.len() - 2);
            flat.raw.die(gimli::DW_TAG_lexical_block, true, Vec::new());
            flat.raw.die(tag, false, vec![text("local"), target(flat.integer)]);
            flat.raw.close();
            flat.raw.close();
            flat.raw.close();
            if tag == gimli::DW_TAG_variable {
                let nodes = read(&flat.raw).unwrap();
                assert_eq!(report(&nodes).signatures.len(), 1);
            } else {
                assert!(read(&flat.raw).unwrap_err().contains("inappropriate parent"));
            }
        }
    }

    #[test]
    fn contextual_depth_failure_does_not_poison_a_later_shallow_shared_alias_in_either_order() {
        let flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        let mut original = read(&flat.raw).unwrap();
        let mut previous = flat.integer;
        for index in 0..MAX_TYPE_DEPTH {
            let offset = 10_000 + index;
            let mut alias = original[&flat.integer].clone();
            alias.id.die_offset = offset as u64;
            alias.tag = gimli::DW_TAG_typedef;
            alias.target = TypeRef::Offset(previous);
            original.insert(offset, alias);
            previous = offset;
        }
        let mut other = original[&flat.function].clone();
        other.id.die_offset = 20_000;
        other.address = Some(other.address.unwrap() + 64);
        original.insert(20_000, other);
        for deep_first in [true, false] {
            let mut nodes = original.clone();
            let (deep, shallow) = if deep_first { (flat.function, 20_000) } else { (20_000, flat.function) };
            nodes.get_mut(&deep).unwrap().name = Some("deep".to_owned());
            nodes.get_mut(&deep).unwrap().target = TypeRef::Offset(previous);
            nodes.get_mut(&shallow).unwrap().name = Some("shallow".to_owned());
            nodes.get_mut(&shallow).unwrap().target = TypeRef::Offset(10_000);
            let output = report(&nodes);
            assert_eq!(output.signatures.len(), 1, "deep first {deep_first}: {output:?}");
            assert_eq!(output.signatures[0].original_name, "shallow");
        }
    }

    #[test]
    fn malformed_or_overflowing_present_high_pc_is_not_ignored() {
        let start = 0x1234_5678_9000u64;
        for attribute in [
            expression(gimli::DW_AT_high_pc),
            (gimli::DW_AT_high_pc, gimli::DW_FORM_block, vec![1, 0]),
            number(gimli::DW_AT_high_pc, u64::MAX),
            number(gimli::DW_AT_high_pc, 0),
            (gimli::DW_AT_high_pc, gimli::DW_FORM_addr, (start - 1).to_le_bytes().to_vec()),
        ] {
            let flat = flat_extent(Some(number(gimli::DW_AT_alignment, 8)), Some(attribute));
            let output = report(&read(&flat.raw).unwrap());
            assert!(output.layouts.is_empty(), "{output:?}");
            assert!(output.signatures.is_empty(), "{output:?}");
        }
        for attribute in [
            number(gimli::DW_AT_high_pc, 16),
            (gimli::DW_AT_high_pc, gimli::DW_FORM_addr, (start + 16).to_le_bytes().to_vec()),
        ] {
            let flat = flat_extent(Some(number(gimli::DW_AT_alignment, 8)), Some(attribute));
            let nodes = read(&flat.raw).unwrap();
            assert_eq!(nodes[&flat.function].address_end, Some(start + 16));
            assert_eq!(report(&nodes).signatures.len(), 1);
            let mut unmapped = DebugLayoutReport::default();
            build_report(&nodes, |address| address == start, |start, end| end > start, &mut unmapped);
            assert!(unmapped.signatures.is_empty());
            let mut disjoint = DebugLayoutReport::default();
            build_report(&nodes, |_| true, |_, _| false, &mut disjoint);
            assert!(disjoint.signatures.is_empty());
        }
    }

    #[test]
    fn different_named_concrete_functions_with_missing_or_range_based_addresses_fail_closed() {
        for address_form in 0..3 {
            let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
            flat.raw.entries.pop();
            let mut attributes = vec![text("other_function"), flag(gimli::DW_AT_prototyped, true)];
            if address_form != 0 {
                attributes.push((gimli::DW_AT_ranges, gimli::DW_FORM_sec_offset, vec![0; 4]));
            }
            if address_form == 2 {
                attributes.push((gimli::DW_AT_low_pc, gimli::DW_FORM_addr, 0x1234_5678_9010u64.to_le_bytes().to_vec()));
            }
            flat.raw.die(gimli::DW_TAG_subprogram, false, attributes);
            flat.raw.close();
            let info = flat.raw.unit();
            let abbrev = flat.raw.abbrev();
            let mut dwarf = dwarf(&info, &abbrev);
            let mut ranges = 0x1234_5678_9000u64.to_le_bytes().to_vec();
            ranges.extend_from_slice(&0x1234_5678_9020u64.to_le_bytes());
            ranges.extend_from_slice(&[0; 16]);
            dwarf.ranges = gimli::RangeLists::new(
                gimli::DebugRanges::new(&ranges, RunTimeEndian::Little),
                gimli::DebugRngLists::new(&[], RunTimeEndian::Little),
            );
            let nodes = read_layout_nodes(&dwarf).unwrap();
            let output = report(&nodes);
            assert!(output.layouts.is_empty(), "form {address_form}: {output:?}");
            assert!(output.signatures.is_empty(), "form {address_form}: {output:?}");
            assert!(output.warnings.iter().any(|warning| warning.contains("function-address index")));
        }
    }

    #[test]
    fn declarations_only_avoid_address_competition_when_they_have_no_address_evidence() {
        for evidence in 0..4 {
            let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
            flat.raw.entries.pop();
            let mut attributes = vec![
                text("other_declared_function"),
                flag(gimli::DW_AT_declaration, true),
                flag(gimli::DW_AT_prototyped, true),
            ];
            if evidence == 1 {
                attributes.push((gimli::DW_AT_ranges, gimli::DW_FORM_sec_offset, vec![0; 4]));
            } else if evidence == 2 {
                attributes.push((gimli::DW_AT_low_pc, gimli::DW_FORM_exprloc, vec![1, 0x9c]));
            } else if evidence == 3 {
                attributes.push((
                    gimli::DW_AT_specification,
                    gimli::DW_FORM_ref4,
                    (flat.function as u32).to_le_bytes().to_vec(),
                ));
            }
            flat.raw.die(gimli::DW_TAG_subprogram, false, attributes);
            flat.raw.close();
            let info = flat.raw.unit();
            let abbrev = flat.raw.abbrev();
            let mut dwarf = dwarf(&info, &abbrev);
            let mut ranges = 0x1234_5678_9000u64.to_le_bytes().to_vec();
            ranges.extend_from_slice(&0x1234_5678_9020u64.to_le_bytes());
            ranges.extend_from_slice(&[0; 16]);
            dwarf.ranges = gimli::RangeLists::new(
                gimli::DebugRanges::new(&ranges, RunTimeEndian::Little),
                gimli::DebugRngLists::new(&[], RunTimeEndian::Little),
            );
            let nodes = read_layout_nodes(&dwarf).unwrap();
            let output = report(&nodes);
            if evidence == 0 {
                assert_eq!(output.signatures.len(), 1, "{output:?}");
                assert_eq!(output.layouts.len(), 1, "{output:?}");
            } else {
                assert!(output.signatures.is_empty() && output.layouts.is_empty(), "{output:?}");
                assert!(output.warnings.iter().any(|warning| warning.contains("function-address index")));
            }
        }
    }

    #[test]
    fn cpp_sibling_declarations_require_direct_valid_address_free_evidence_for_index_exemption() {
        for case in 0..6 {
            let mut cpp = cpp(gimli::DW_LANG_C_plus_plus_14, gimli::DW_TAG_class_type, Vec::new());
            cpp.raw.entries.pop();
            let mut attributes = vec![text("unrelated_declaration"), flag(gimli::DW_AT_declaration, true)];
            match case {
                0 => {}
                1 => attributes.push(reference(gimli::DW_AT_specification, cpp.definition)),
                2 => attributes.push(reference(gimli::DW_AT_abstract_origin, cpp.definition)),
                3 => attributes.push(number(gimli::DW_AT_virtuality, 1)),
                4 => attributes.push(expression(gimli::DW_AT_specification)),
                5 => attributes.push(reference(gimli::DW_AT_specification, cpp.declaration)),
                _ => unreachable!(),
            }
            let sibling = cpp.raw.die(gimli::DW_TAG_subprogram, false, attributes);
            cpp.raw.close();
            let nodes = read(&cpp.raw).unwrap();
            assert!(nodes[&sibling].declaration);
            assert!(nodes[&sibling].address.is_none());
            assert!(!nodes[&sibling].address_evidence);
            if case == 1 {
                assert!(!nodes[&sibling].invalid, "specification must be checked independently of invalid bits");
            }
            let output = report(&nodes);
            if case == 0 {
                assert_eq!(output.signatures.len(), 1, "{output:?}");
                assert_eq!(output.layouts.len(), 1, "{output:?}");
            } else {
                assert!(output.signatures.is_empty() && output.layouts.is_empty(), "case {case}: {output:?}");
                assert!(output.warnings.iter().any(|warning| warning.contains("function-address index")));
            }
        }
    }

    #[test]
    fn unsupported_c_classes_do_not_consume_the_cpp_layout_or_record_child_budgets() {
        let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        flat.raw.entries.pop();
        for _ in 0..=MAX_LAYOUTS {
            flat.raw.die(gimli::DW_TAG_class_type, false, Vec::new());
        }
        flat.raw.die(gimli::DW_TAG_class_type, true, Vec::new());
        for _ in 0..=MAX_FIELDS {
            flat.raw.die(gimli::DW_TAG_variable, false, Vec::new());
        }
        flat.raw.close();
        flat.raw.close();
        let output = report(&read(&flat.raw).unwrap());
        assert_eq!(output.signatures.len(), 1, "{output:?}");
        assert_eq!(output.layouts.len(), 1, "{output:?}");
        assert_eq!(output.signatures[0].original_name, "read_record");
    }

    #[test]
    fn abstract_inline_helpers_and_body_only_inline_arguments_preserve_the_complete_caller() {
        let mut flat = flat(Some(number(gimli::DW_AT_alignment, 8)));
        flat.raw.entries.pop();
        let helper = flat.raw.die(
            gimli::DW_TAG_subprogram,
            true,
            vec![
                text("inline_helper"),
                flag(gimli::DW_AT_prototyped, true),
                target(flat.integer),
                number(gimli::DW_AT_inline, u64::from(gimli::DW_INL_inlined.0)),
            ],
        );
        let helper_parameter =
            flat.raw.die(gimli::DW_TAG_formal_parameter, false, vec![text("value"), target(flat.integer)]);
        flat.raw.close();
        let caller = flat.raw.die(
            gimli::DW_TAG_subprogram,
            true,
            vec![
                text("caller_with_inline"),
                flag(gimli::DW_AT_prototyped, true),
                target(flat.integer),
                (gimli::DW_AT_low_pc, gimli::DW_FORM_addr, 0x1234_5678_9040u64.to_le_bytes().to_vec()),
            ],
        );
        flat.raw.die(gimli::DW_TAG_formal_parameter, false, vec![text("item"), target(flat.pointer)]);
        flat.raw.die(
            gimli::DW_TAG_inlined_subroutine,
            true,
            vec![
                (gimli::DW_AT_abstract_origin, gimli::DW_FORM_ref4, (helper as u32).to_le_bytes().to_vec()),
                (gimli::DW_AT_low_pc, gimli::DW_FORM_addr, 0x1234_5678_9041u64.to_le_bytes().to_vec()),
                number(gimli::DW_AT_high_pc, 4),
            ],
        );
        flat.raw.die(
            gimli::DW_TAG_formal_parameter,
            false,
            vec![
                (gimli::DW_AT_abstract_origin, gimli::DW_FORM_ref4, (helper_parameter as u32).to_le_bytes().to_vec()),
                expression(gimli::DW_AT_location),
            ],
        );
        flat.raw.close();
        flat.raw.close();
        flat.raw.close();
        let nodes = read(&flat.raw).unwrap();
        assert!(abstract_inline_metadata(&nodes[&helper], &nodes));
        let output = report(&nodes);
        assert_eq!(output.signatures.len(), 2, "{output:?}");
        let signature = output.signatures.iter().find(|signature| signature.id == nodes[&caller].id).unwrap();
        assert_eq!(signature.parameters.len(), 1);
        assert_eq!(signature.parameters[0].original_name.as_deref(), Some("item"));
        assert!(signature.eligible_for_native_verification);
        assert!(!output.signatures.iter().any(|signature| signature.id == nodes[&helper].id));
        let mut concrete_inline = nodes.clone();
        concrete_inline.get_mut(&helper).unwrap().address = Some(0x1234_5678_9080);
        concrete_inline.get_mut(&helper).unwrap().address_evidence = true;
        let concrete = report(&concrete_inline);
        assert_eq!(concrete.signatures.len(), 2, "{concrete:?}");
        assert!(!concrete.signatures.iter().any(|signature| signature.id == nodes[&helper].id));
        for case in 0..3 {
            let mut unproven = nodes.clone();
            match case {
                0 => unproven.get_mut(&helper).unwrap().inline = Some(gimli::DW_INL_not_inlined),
                1 => unproven.get_mut(&helper).unwrap().address_evidence = true,
                2 => unproven.get_mut(&helper).unwrap().invalid = true,
                _ => unreachable!(),
            }
            assert!(report(&unproven).signatures.is_empty());
        }
    }

    #[test]
    fn unsupported_type_categories_consume_the_exact_cumulative_type_budget() {
        for tag in [
            gimli::DW_TAG_unspecified_type,
            gimli::DW_TAG_class_type,
            gimli::DW_TAG_string_type,
            gimli::DW_TAG_ptr_to_member_type,
            gimli::DW_TAG_set_type,
            gimli::DW_TAG_subrange_type,
            gimli::DW_TAG_file_type,
            gimli::DW_TAG_packed_type,
            gimli::DW_TAG_template_type_parameter,
            gimli::DW_TAG_thrown_type,
            gimli::DW_TAG_interface_type,
            gimli::DW_TAG_shared_type,
            gimli::DW_TAG_template_alias,
            gimli::DW_TAG_coarray_type,
            gimli::DW_TAG_generic_subrange,
            gimli::DW_TAG_dynamic_type,
            gimli::DW_TAG_immutable_type,
            gimli::DW_TAG_HP_array_descriptor,
            gimli::DW_TAG_class_template,
            gimli::DW_TAG_GNU_template_template_param,
            gimli::DW_TAG_SUN_class_template,
            gimli::DW_TAG_SUN_struct_template,
            gimli::DW_TAG_SUN_union_template,
            gimli::DW_TAG_SUN_f90_interface,
            gimli::DW_TAG_SUN_fortran_vax_structure,
            gimli::DW_TAG_ALTIUM_circ_type,
            gimli::DW_TAG_ALTIUM_mwa_circ_type,
            gimli::DW_TAG_ALTIUM_rev_carry_type,
            gimli::DW_TAG_upc_shared_type,
            gimli::DW_TAG_upc_strict_type,
            gimli::DW_TAG_upc_relaxed_type,
            gimli::DW_TAG_PGI_kanji_type,
            gimli::DW_TAG_BORLAND_Delphi_string,
            gimli::DW_TAG_BORLAND_Delphi_dynamic_array,
            gimli::DW_TAG_BORLAND_Delphi_set,
            gimli::DW_TAG_BORLAND_Delphi_variant,
        ] {
            for count in [MAX_TYPES, MAX_TYPES + 1] {
                let mut first = Raw::default();
                first.root(gimli::DW_LANG_C11);
                for _ in 0..count / 2 {
                    first.die(tag, false, Vec::new());
                }
                first.close();
                let mut second =
                    Raw { abbreviations: first.abbreviations.clone(), codes: first.codes.clone(), ..Raw::default() };
                second.root(gimli::DW_LANG_C11);
                for _ in count / 2..count {
                    second.die(tag, false, Vec::new());
                }
                second.close();
                let info = [first.unit(), second.unit()].concat();
                let result = read_layout_nodes(&dwarf(&info, &first.abbrev()));
                if count == MAX_TYPES {
                    assert_eq!(result.unwrap().values().filter(|node| node.tag == tag).count(), count, "{tag}");
                } else {
                    assert!(result.unwrap_err().contains("cumulative type"), "{tag}");
                }
            }
        }
    }
}
