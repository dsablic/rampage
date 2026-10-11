use std::collections::BTreeMap;
use std::sync::Arc;

use gimli::{AttributeValue, Dwarf, EndianSlice, Reader, RunTimeEndian, Section, Unit};
use object::{CompressionFormat, Object, ObjectKind, ObjectSection};
use serde::Serialize;

use crate::{Binary, Format, LoadError};

const MAX_DEBUG_BYTES: usize = 64 * 1024 * 1024;
const MAX_UNITS: usize = 256;
const MAX_DIES: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;
const MAX_NESTING: usize = 256;
const MAX_TYPE_DEPTH: usize = 32;
const MAX_PARAMETERS: usize = 4096;
const MAX_WARNINGS: usize = 4096;
const MAX_ABBREVIATIONS: usize = 4096;
const MAX_ATTRIBUTES: usize = 256;
const MAX_DECLARATION_BYTES: usize = 65_536;
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_DECLARATION_LINE_BYTES: usize = 4095;

type DebugReader<'a> = EndianSlice<'a, RunTimeEndian>;

#[derive(Debug, Default, Serialize)]
pub struct DebugReport {
    pub signatures: Vec<DebugSignature>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DebugSignature {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    pub declaration: String,
}

impl DebugReport {
    fn warn(&mut self, warning: String) {
        if self.warnings.len() < MAX_WARNINGS - 1 {
            self.warnings.push(warning);
        } else if self.warnings.len() == MAX_WARNINGS - 1 {
            self.warnings.push("DWARF warning limit reached; further diagnostics are truncated".to_owned());
        }
    }
}

/// Reads only embedded DWARF. Declarations expand typedefs to exact-width scalar types;
/// aggregate layouts, external debug files, and source compiler selection are not inferred.
/// Const qualifiers are erased with a warning; volatile and restrict signatures are rejected.
pub fn signatures(binary: &Binary) -> Result<DebugReport, LoadError> {
    let mut report = DebugReport::default();
    if !matches!(binary.format, Format::Elf | Format::MachO) {
        report.warn("embedded DWARF signature preview is unavailable for this format".to_owned());
        return Ok(report);
    }
    let object = object::File::parse(binary.image_bytes())?;
    if object.kind() == ObjectKind::Relocatable {
        report.warn("DWARF addresses in relocatable objects cannot be imported".to_owned());
        return Ok(report);
    }
    let endian = if object.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let mut total: usize = 0;
    for section in object.sections() {
        let name = section.name().unwrap_or_default();
        if ![".debug_", ".zdebug_", "__debug_", "__zdebug_"].iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        let size = usize::try_from(section.size()).ok();
        let bounded = size.and_then(|size| total.checked_add(size)).filter(|&size| size <= MAX_DEBUG_BYTES);
        let Some(size) = bounded else {
            report.warn("DWARF exceeds the 64 MiB section-byte limit".to_owned());
            return Ok(report);
        };
        total = size;
    }
    let dwarf = Dwarf::load(|id| -> Result<DebugReader<'_>, String> {
        // Line tables and other unrelated sections are not parsed by this preview.
        let wanted = matches!(
            id,
            gimli::SectionId::DebugInfo
                | gimli::SectionId::DebugAbbrev
                | gimli::SectionId::DebugStr
                | gimli::SectionId::DebugLineStr
                | gimli::SectionId::DebugStrOffsets
                | gimli::SectionId::DebugAddr
        );
        if !wanted {
            return Ok(EndianSlice::new(&[], endian));
        }
        let section = object.section_by_name(id.name()).or_else(|| {
            let compressed = id.name().replacen(".debug_", ".zdebug_", 1);
            object.section_by_name(&compressed)
        });
        let Some(section) = section else {
            return Ok(EndianSlice::new(&[], endian));
        };
        if section.compressed_file_range().map_err(|error| error.to_string())?.format != CompressionFormat::None {
            return Err(format!("compressed DWARF section {} is unsupported", id.name()));
        }
        let size = usize::try_from(section.size()).map_err(|_| "DWARF section size overflow".to_owned())?;
        if size > MAX_DEBUG_BYTES {
            return Err("DWARF exceeds the 64 MiB section-byte limit".to_owned());
        }
        let data = section.data().map_err(|error| error.to_string())?;
        if data.len() > size {
            return Err("DWARF section data exceeds its declared size".to_owned());
        }
        Ok(EndianSlice::new(data, endian))
    });
    let dwarf = match dwarf {
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
    let nodes = match read_nodes(&dwarf) {
        Ok(nodes) => nodes,
        Err(error) => {
            report.warn(format!("DWARF signature preview stopped: {error}"));
            return Ok(report);
        }
    };
    let mut parameters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut variadic = BTreeMap::new();
    let mut invalid_parameters = std::collections::BTreeSet::new();
    for (&offset, node) in &nodes {
        if let Some(parent) = node.parent {
            if node.tag == gimli::DW_TAG_formal_parameter {
                parameters.entry(parent).or_default().push(offset);
            } else if node.tag == gimli::DW_TAG_unspecified_parameters
                && (node.invalid || node.inherited || variadic.insert(parent, offset).is_some())
            {
                invalid_parameters.insert(parent);
            }
        }
    }
    let mut output_bytes = 0;
    for (&offset, node) in &nodes {
        if report.warnings.len() >= MAX_WARNINGS - 1 {
            report.warn("DWARF signature preview stopped at the warning limit".to_owned());
            break;
        }
        if node.tag != gimli::DW_TAG_subprogram || node.declaration || node.address.is_none() {
            continue;
        }
        let args = parameters.get(&offset).map(Vec::as_slice).unwrap_or_default();
        let varargs = variadic.get(&offset).copied();
        if invalid_parameters.contains(&offset) {
            report.warn(format!("skipped DWARF function at {:#x}: invalid variadic parameters", node.address.unwrap()));
            continue;
        }
        if !binary.is_code(node.address.unwrap()) {
            report.warn(format!("skipped DWARF function at {:#x}: address is not mapped code", node.address.unwrap()));
            continue;
        }
        match declaration(node, args, varargs, &nodes, binary.arch.pointer_size(), &mut report) {
            Ok(signature) => {
                output_bytes += signature.name.len() + signature.declaration.len();
                if output_bytes > MAX_DEBUG_BYTES {
                    report.warn("DWARF signature preview reached the 64 MiB output limit".to_owned());
                    break;
                }
                report.signatures.push(signature);
            }
            Err(error) => {
                let name = node.name.as_deref().unwrap_or("<unnamed>");
                report.warn(format!("skipped DWARF function {name}: {error}"));
            }
        }
    }
    report.signatures.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
    if report.signatures.is_empty() && report.warnings.is_empty() {
        report.warn("embedded DWARF contains no supported addressed function signatures".to_owned());
    }
    Ok(report)
}

#[derive(Debug, Clone, Copy)]
enum TypeRef {
    Absent,
    Offset(usize),
    Unsupported,
}

#[derive(Debug)]
struct Node {
    tag: gimli::DwTag,
    parent: Option<usize>,
    name: Option<String>,
    target: TypeRef,
    size: Option<u64>,
    encoding: Option<gimli::DwAte>,
    address: Option<u64>,
    address_size: u8,
    declaration: bool,
    inherited: bool,
    invalid: bool,
    prototyped: bool,
}

fn read_nodes(dwarf: &Dwarf<DebugReader<'_>>) -> Result<BTreeMap<usize, Node>, String> {
    let mut nodes = BTreeMap::new();
    let mut units = dwarf.units();
    let mut count = 0;
    let mut die_count = 0;
    let mut name_bytes = 0;
    let mut name_work = 0;
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        count += 1;
        if count > MAX_UNITS {
            return Err("DWARF unit limit exceeded (256)".to_owned());
        }
        if !matches!(header.type_(), gimli::UnitType::Compilation | gimli::UnitType::Partial) {
            return Err("split or type-unit DWARF is unsupported".to_owned());
        }
        let unit = signature_unit(dwarf, header)?;
        let mut entries = unit.entries();
        let mut parents = Vec::new();
        while entries.next_entry().map_err(|error| error.to_string())? {
            die_count += 1;
            if die_count > MAX_DIES {
                return Err("DWARF DIE limit exceeded (1000000)".to_owned());
            }
            let Some(entry) = entries.current() else {
                if entries.depth() <= 0 {
                    return Err("unbalanced DWARF DIE terminator".to_owned());
                }
                continue;
            };
            let depth = entry.depth();
            if depth < 0 || depth as usize > MAX_NESTING {
                return Err("DWARF DIE nesting limit exceeded (256)".to_owned());
            }
            if depth == 0 && !parents.is_empty() {
                return Err("multiple DWARF unit roots".to_owned());
            }
            if depth as usize > parents.len() {
                return Err("invalid DWARF DIE parent depth".to_owned());
            }
            let offset = entry
                .offset()
                .to_debug_info_offset(&unit.header)
                .ok_or_else(|| "DIE is not in .debug_info".to_owned())?
                .0;
            parents.truncate(depth as usize);
            let mut node = Node {
                tag: entry.tag(),
                parent: parents.last().copied(),
                name: None,
                target: TypeRef::Absent,
                size: None,
                encoding: None,
                address: None,
                address_size: unit.header.address_size(),
                declaration: false,
                inherited: false,
                invalid: false,
                prototyped: false,
            };
            let mut attribute_names = std::collections::BTreeSet::new();
            for attr in entry.attrs() {
                if !attribute_names.insert(attr.name()) {
                    return Err(format!("duplicate DWARF attribute {}", attr.name()));
                }
                let value = attr.value();
                match attr.name() {
                    gimli::DW_AT_name
                        if matches!(
                            node.tag,
                            gimli::DW_TAG_subprogram | gimli::DW_TAG_formal_parameter | gimli::DW_TAG_base_type
                        ) =>
                    {
                        name_work += MAX_NAME_BYTES + 1;
                        if name_work > MAX_DEBUG_BYTES {
                            return Err("DWARF name lookup work limit exceeded".to_owned());
                        }
                        let reader = bounded_name(dwarf, &unit, value).map_err(|error| error.to_string())?;
                        if reader.len() > MAX_NAME_BYTES {
                            node.invalid = true;
                        } else {
                            let bytes = reader.to_slice().map_err(|error| error.to_string())?;
                            match std::str::from_utf8(&bytes) {
                                Ok(name) => {
                                    name_bytes += name.len();
                                    if name_bytes > MAX_DEBUG_BYTES {
                                        return Err("DWARF name-byte limit exceeded".to_owned());
                                    }
                                    node.name = Some(name.to_owned());
                                }
                                Err(_) => node.invalid = true,
                            }
                        }
                    }
                    gimli::DW_AT_type => {
                        node.target = match value {
                            AttributeValue::UnitRef(reference) if reference.is_in_bounds(&unit.header) => {
                                TypeRef::Offset(reference.to_debug_info_offset(&unit.header).unwrap().0)
                            }
                            AttributeValue::DebugInfoRef(reference) => TypeRef::Offset(reference.0),
                            _ => TypeRef::Unsupported,
                        };
                    }
                    gimli::DW_AT_byte_size => {
                        node.size = value.udata_value();
                        node.invalid |= node.size.is_none();
                    }
                    gimli::DW_AT_encoding => {
                        if let AttributeValue::Encoding(encoding) = value {
                            node.encoding = Some(encoding);
                        }
                    }
                    gimli::DW_AT_low_pc => {
                        node.address = dwarf.attr_address(&unit, value).map_err(|error| error.to_string())?;
                    }
                    gimli::DW_AT_declaration => node.declaration = !matches!(value, AttributeValue::Flag(false)),
                    gimli::DW_AT_abstract_origin | gimli::DW_AT_specification => node.inherited = true,
                    gimli::DW_AT_calling_convention => {
                        node.invalid |= !matches!(value, AttributeValue::CallingConvention(gimli::DW_CC_normal));
                    }
                    gimli::DW_AT_prototyped => {
                        node.prototyped = matches!(value, AttributeValue::Flag(true));
                        node.invalid |= !node.prototyped;
                    }
                    gimli::DW_AT_bit_size | gimli::DW_AT_bit_offset | gimli::DW_AT_data_bit_offset
                        if node.tag == gimli::DW_TAG_base_type =>
                    {
                        node.invalid = true
                    }
                    gimli::DW_AT_address_class => {
                        node.invalid |= !matches!(value, AttributeValue::AddressClass(gimli::DW_ADDR_none));
                    }
                    gimli::DW_AT_endianity => {
                        node.invalid |= !matches!(value, AttributeValue::Endianity(gimli::DW_END_default));
                    }
                    gimli::DW_AT_object_pointer => node.invalid = true,
                    _ => {}
                }
            }
            parents.push(offset);
            nodes.insert(offset, node);
        }
        if entries.next_depth() != 0 {
            return Err("unterminated DWARF DIE children".to_owned());
        }
    }
    Ok(nodes)
}

fn signature_unit<'a>(
    dwarf: &Dwarf<DebugReader<'a>>,
    header: gimli::UnitHeader<DebugReader<'a>>,
) -> Result<Unit<DebugReader<'a>>, String> {
    // Construct only the context needed for indexed strings/addresses, without line-table allocation.
    let encoding = header.encoding();
    validate_abbreviations(dwarf, header.debug_abbrev_offset()).map_err(|error| error.to_string())?;
    let mut unit = Unit {
        abbreviations: Arc::new(
            dwarf.debug_abbrev.abbreviations(header.debug_abbrev_offset()).map_err(|error| error.to_string())?,
        ),
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
    let mut low_pc = None;
    let mut str_offsets_base = unit.str_offsets_base;
    let mut addr_base = None;
    {
        let mut entries = unit.entries();
        let root = entries
            .next_dfs()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "missing DWARF unit DIE".to_owned())?;
        if !matches!(root.tag(), gimli::DW_TAG_compile_unit | gimli::DW_TAG_partial_unit) {
            return Err("missing DWARF unit DIE".to_owned());
        }
        let mut attribute_names = std::collections::BTreeSet::new();
        for attr in root.attrs() {
            if !attribute_names.insert(attr.name()) {
                return Err(format!("duplicate DWARF root attribute {}", attr.name()));
            }
            match attr.value() {
                AttributeValue::DebugStrOffsetsBase(base) if attr.name() == gimli::DW_AT_str_offsets_base => {
                    str_offsets_base = base;
                }
                AttributeValue::DebugAddrBase(base)
                    if matches!(attr.name(), gimli::DW_AT_addr_base | gimli::DW_AT_GNU_addr_base) =>
                {
                    if addr_base.is_some_and(|previous| previous != base) {
                        return Err("conflicting DWARF address-base attributes".to_owned());
                    }
                    addr_base = Some(base);
                }
                value if attr.name() == gimli::DW_AT_low_pc => low_pc = Some(value),
                _ if matches!(
                    attr.name(),
                    gimli::DW_AT_dwo_name | gimli::DW_AT_GNU_dwo_name | gimli::DW_AT_GNU_dwo_id
                ) =>
                {
                    return Err("split DWARF is unsupported".to_owned());
                }
                _ => {}
            }
        }
    }
    unit.str_offsets_base = str_offsets_base;
    unit.addr_base = addr_base.unwrap_or(unit.addr_base);
    if let Some(value) = low_pc {
        unit.low_pc = dwarf.attr_address(&unit, value).map_err(|error| error.to_string())?.unwrap_or(0);
    }
    Ok(unit)
}

fn bounded_name<'a>(
    dwarf: &Dwarf<DebugReader<'a>>,
    unit: &Unit<DebugReader<'a>>,
    value: AttributeValue<DebugReader<'a>>,
) -> gimli::Result<DebugReader<'a>> {
    let (mut reader, offset) = match value {
        AttributeValue::String(reader) => return dwarf.attr_string(unit, AttributeValue::String(reader)),
        AttributeValue::DebugStrRef(offset) => (*dwarf.debug_str.reader(), offset.0),
        AttributeValue::DebugLineStrRef(offset) => (*dwarf.debug_line_str.reader(), offset.0),
        AttributeValue::DebugStrOffsetsIndex(index) => (*dwarf.debug_str.reader(), dwarf.string_offset(unit, index)?.0),
        _ => return Err(gimli::Error::ExpectedStringAttributeValue),
    };
    reader.skip(offset)?;
    reader.truncate(reader.len().min(MAX_NAME_BYTES + 1))?;
    let string = reader.read_null_terminated_slice()?;
    dwarf.attr_string(unit, AttributeValue::String(string))
}

fn validate_abbreviations(dwarf: &Dwarf<DebugReader<'_>>, offset: gimli::DebugAbbrevOffset) -> gimli::Result<()> {
    let mut reader = *dwarf.debug_abbrev.reader();
    reader.skip(offset.0)?;
    let mut count = 0;
    while !reader.is_empty() && reader.read_uleb128()? != 0 {
        count += 1;
        if count > MAX_ABBREVIATIONS {
            return Err(gimli::Error::TooManyIterations);
        }
        reader.read_uleb128()?;
        reader.read_u8()?;
        let mut attributes = 0;
        loop {
            let name = reader.read_uleb128()?;
            let form = reader.read_uleb128()?;
            if name == 0 && form == 0 {
                break;
            }
            attributes += 1;
            if attributes > MAX_ATTRIBUTES {
                return Err(gimli::Error::TooManyIterations);
            }
            if form == u64::from(gimli::DW_FORM_implicit_const.0) {
                reader.read_sleb128()?;
            }
        }
    }
    Ok(())
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn c_name(name: &str) -> String {
    let mut sanitized: String =
        name.chars().map(|ch| if ch.is_ascii_alphanumeric() || ch == '_' { ch } else { '_' }).collect();
    if !identifier(&sanitized) || c_keyword(&sanitized) || native_type_name(&sanitized) {
        sanitized.insert_str(0, "debug_");
    }
    sanitized
}

fn native_type_name(name: &str) -> bool {
    ["int", "uint", "float", "undefined", "xunknown", "wchar", "char"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|ch| ch.is_ascii_digit()))
    }) || matches!(
        name,
        "wchar"
            | "wchar_t"
            | "char16_t"
            | "char32_t"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
            | "uchar"
            | "ushort"
            | "uint"
            | "ulong"
            | "longlong"
            | "ulonglong"
            | "code"
            | "undefined"
    )
}

fn c_keyword(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "bool"
            | "true"
            | "false"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
    )
}

fn declaration(
    function: &Node,
    parameters: &[usize],
    varargs: Option<usize>,
    nodes: &BTreeMap<usize, Node>,
    pointer_size: u8,
    report: &mut DebugReport,
) -> Result<DebugSignature, String> {
    if function.invalid || function.inherited {
        return Err("invalid name or inherited signature attributes are unsupported".to_owned());
    }
    if !function.prototyped {
        return Err("DWARF function has no explicit complete prototype".to_owned());
    }
    let original_name =
        function.name.as_deref().filter(|name| !name.is_empty()).ok_or_else(|| "missing function name".to_owned())?;
    let name = c_name(original_name);
    if name.len() > MAX_IDENTIFIER_BYTES {
        return Err("sanitized function name exceeds the 1024-byte identifier limit".to_owned());
    }
    if name != original_name {
        report.warn(format!("DWARF function {original_name}: C declaration name sanitized as {name}"));
    }
    if parameters.len() > MAX_PARAMETERS {
        return Err("function parameter limit exceeded".to_owned());
    }
    let result = match function.target {
        TypeRef::Absent => ResolvedType { text: "void".to_owned(), const_erased: false },
        target => resolve_type(target, nodes, pointer_size, 0, false)?,
    };
    let mut const_erased = result.const_erased;
    let result = result.text;
    let mut args = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut declaration_bytes = result.len() + name.len() + 4;
    for (index, &offset) in parameters.iter().enumerate() {
        if varargs.is_some_and(|varargs| offset > varargs) {
            return Err("formal parameter follows variadic marker".to_owned());
        }
        let parameter = &nodes[&offset];
        if parameter.invalid || parameter.inherited {
            return Err("invalid or inherited parameter attributes".to_owned());
        }
        let ty = resolve_type(parameter.target, nodes, pointer_size, 0, false)?;
        const_erased |= ty.const_erased;
        let mut parameter_name = match parameter.name.as_deref().filter(|name| !name.is_empty()) {
            Some(original) => {
                let sanitized = c_name(original);
                if sanitized != original {
                    report.warn(format!("DWARF function {name}: parameter {original} sanitized as {sanitized}"));
                }
                sanitized
            }
            None => {
                let synthesized = format!("arg_{}", index + 1);
                report.warn(format!("DWARF function {name}: unnamed parameter synthesized as {synthesized}"));
                synthesized
            }
        };
        if names.contains(&parameter_name) {
            let original = parameter_name.clone();
            let mut suffix = index + 1;
            while names.contains(&parameter_name) {
                parameter_name = format!("{original}_{suffix}");
                suffix += 1;
            }
            report.warn(format!("DWARF function {name}: duplicate parameter {original} renamed as {parameter_name}"));
        }
        names.insert(parameter_name.clone());
        if parameter_name.len() > MAX_IDENTIFIER_BYTES {
            return Err("sanitized parameter name exceeds the 1024-byte identifier limit".to_owned());
        }
        declaration_bytes += ty.text.len() + parameter_name.len() + 5;
        if declaration_bytes > MAX_DECLARATION_BYTES {
            return Err("function declaration exceeds the 65536-byte limit".to_owned());
        }
        args.push(format!("{} {parameter_name}", ty.text));
    }
    if varargs.is_some() {
        if args.is_empty() {
            return Err("variadic function has no fixed parameters".to_owned());
        }
        args.push("...".to_owned());
    } else if args.is_empty() {
        args.push("void".to_owned());
    }
    let argument_bytes = args.iter().map(String::len).sum::<usize>();
    let separators = args.len().saturating_sub(1);
    let single_line_bytes = result.len() + name.len() + 4 + argument_bytes + separators * 2;
    let wrapped = single_line_bytes > MAX_DECLARATION_LINE_BYTES;
    let output_bytes =
        if wrapped { result.len() + name.len() + 11 + argument_bytes + separators * 6 } else { single_line_bytes };
    if output_bytes > MAX_DECLARATION_BYTES {
        return Err("function declaration exceeds the 65536-byte limit".to_owned());
    }
    let declaration = if !wrapped {
        format!("{result} {name}({});", args.join(", "))
    } else {
        format!("{result} {name}(\n    {} \n);", args.join(",\n    "))
    };
    if declaration.len() > MAX_DECLARATION_BYTES {
        return Err("function declaration exceeds the 65536-byte limit".to_owned());
    }
    if declaration.lines().any(|line| line.len() > MAX_DECLARATION_LINE_BYTES) {
        return Err("function declaration line exceeds the 4095-byte lexer limit".to_owned());
    }
    if const_erased {
        if report.warnings.len() >= MAX_WARNINGS - 1 {
            return Err("cannot emit const-erased signature after the warning limit".to_owned());
        }
        report.warn(format!("DWARF function {name}: const qualifiers intentionally erased from signature preview"));
    }
    Ok(DebugSignature { address: function.address.unwrap(), name, declaration })
}

struct ResolvedType {
    text: String,
    const_erased: bool,
}

fn resolve_type(
    reference: TypeRef,
    nodes: &BTreeMap<usize, Node>,
    pointer_size: u8,
    depth: usize,
    pointee: bool,
) -> Result<ResolvedType, String> {
    if depth >= MAX_TYPE_DEPTH {
        return Err("recursive or over-depth DWARF type".to_owned());
    }
    let TypeRef::Offset(offset) = reference else {
        return Err("missing or unsupported DWARF type reference".to_owned());
    };
    let node = nodes.get(&offset).ok_or_else(|| "unresolved DWARF type reference".to_owned())?;
    if node.invalid || node.inherited {
        return Err("invalid or inherited DWARF type attributes".to_owned());
    }
    match node.tag {
        gimli::DW_TAG_base_type => Ok(ResolvedType { text: scalar(node)?, const_erased: false }),
        gimli::DW_TAG_typedef => resolve_type(node.target, nodes, pointer_size, depth + 1, pointee),
        gimli::DW_TAG_const_type => {
            let mut ty = if pointee && matches!(node.target, TypeRef::Absent) {
                ResolvedType { text: "void".to_owned(), const_erased: false }
            } else {
                resolve_type(node.target, nodes, pointer_size, depth + 1, pointee)?
            };
            ty.const_erased = true;
            Ok(ty)
        }
        gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type => {
            Err(format!("unsupported DWARF qualifier {} cannot be preserved by signature import", node.tag))
        }
        gimli::DW_TAG_pointer_type if !pointee => {
            let size = node.size.unwrap_or(u64::from(node.address_size));
            if size != u64::from(pointer_size) || node.address_size != pointer_size {
                return Err("DWARF pointer width does not match the binary".to_owned());
            }
            let target = match node.target {
                TypeRef::Absent => ResolvedType { text: "void".to_owned(), const_erased: false },
                target => resolve_type(target, nodes, pointer_size, depth + 1, true)?,
            };
            Ok(ResolvedType { text: format!("{} *", target.text), const_erased: target.const_erased })
        }
        _ => Err(format!("unsupported DWARF type {} (no aggregate layout is inferred)", node.tag)),
    }
}

fn scalar(node: &Node) -> Result<String, String> {
    let size = node.size.ok_or_else(|| "DWARF scalar has no exact byte size".to_owned())?;
    let encoding = node.encoding.ok_or_else(|| "DWARF scalar has no encoding".to_owned())?;
    let spelling = match (encoding, size) {
        (gimli::DW_ATE_signed_char, 1) if node.name.as_deref() == Some("char") => "char".to_owned(),
        (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 1 | 2 | 4 | 8) => format!("int{}_t", size * 8),
        (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 1 | 2 | 4 | 8) => format!("uint{}_t", size * 8),
        (gimli::DW_ATE_float, 4) => "float".to_owned(),
        (gimli::DW_ATE_float, 8) => "double".to_owned(),
        (gimli::DW_ATE_boolean, 1) => "bool".to_owned(),
        _ => return Err(format!("unsupported DWARF scalar encoding {encoding} with byte size {size}")),
    };
    Ok(spelling)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(tag: gimli::DwTag, target: TypeRef) -> Node {
        Node {
            tag,
            parent: None,
            name: None,
            target,
            size: None,
            encoding: None,
            address: None,
            address_size: 8,
            declaration: false,
            inherited: false,
            invalid: false,
            prototyped: true,
        }
    }

    fn integer(size: Option<u64>) -> Node {
        Node { size, encoding: Some(gimli::DW_ATE_signed), ..node(gimli::DW_TAG_base_type, TypeRef::Absent) }
    }

    #[test]
    fn unknown_scalar_width_and_unresolved_types_never_become_void() {
        let nodes = BTreeMap::from([(1, integer(None)), (2, integer(Some(3)))]);
        for reference in
            [TypeRef::Absent, TypeRef::Unsupported, TypeRef::Offset(1), TypeRef::Offset(2), TypeRef::Offset(99)]
        {
            assert!(resolve_type(reference, &nodes, 8, 0, false).is_err());
        }
    }

    #[test]
    fn explicit_void_pointer_and_pointer_qualifiers_are_distinct_from_missing_parameter_types() {
        let nodes = BTreeMap::from([
            (1, node(gimli::DW_TAG_pointer_type, TypeRef::Absent)),
            (2, node(gimli::DW_TAG_const_type, TypeRef::Offset(1))),
            (3, node(gimli::DW_TAG_restrict_type, TypeRef::Offset(2))),
            (4, integer(Some(4))),
            (5, node(gimli::DW_TAG_restrict_type, TypeRef::Offset(4))),
            (6, node(gimli::DW_TAG_const_type, TypeRef::Absent)),
            (7, node(gimli::DW_TAG_pointer_type, TypeRef::Offset(6))),
        ]);
        assert!(resolve_type(TypeRef::Offset(3), &nodes, 8, 0, false).is_err());
        let qualified = resolve_type(TypeRef::Offset(2), &nodes, 8, 0, false).unwrap();
        assert_eq!(qualified.text, "void *");
        assert!(qualified.const_erased);
        assert!(resolve_type(TypeRef::Offset(5), &nodes, 8, 0, false).is_err());
        assert!(resolve_type(TypeRef::Offset(1), &nodes, 4, 0, false).is_err());
        assert_eq!(resolve_type(TypeRef::Offset(7), &nodes, 8, 0, false).unwrap().text, "void *");
        assert!(resolve_type(TypeRef::Offset(6), &nodes, 8, 0, false).is_err());
    }

    #[test]
    fn recursive_typedefs_and_non_scalar_pointees_are_rejected() {
        let nodes = BTreeMap::from([
            (1, node(gimli::DW_TAG_typedef, TypeRef::Offset(2))),
            (2, node(gimli::DW_TAG_const_type, TypeRef::Offset(1))),
            (3, node(gimli::DW_TAG_enumeration_type, TypeRef::Absent)),
            (4, node(gimli::DW_TAG_pointer_type, TypeRef::Offset(3))),
            (5, node(gimli::DW_TAG_reference_type, TypeRef::Offset(3))),
        ]);
        for offset in [1, 4, 5] {
            assert!(resolve_type(TypeRef::Offset(offset), &nodes, 8, 0, false).is_err());
        }
    }

    #[test]
    fn unnamed_parameters_are_reported_and_incomplete_signatures_are_not_emitted() {
        let function = Node {
            name: Some("reset".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes =
            BTreeMap::from([(1, integer(Some(4))), (2, node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1)))]);
        let mut report = DebugReport::default();
        let signature = declaration(&function, &[2], None, &nodes, 8, &mut report).unwrap();
        assert_eq!(signature.declaration, "void reset(int32_t arg_1);");
        assert!(report.warnings.iter().any(|warning| warning.contains("arg_1")));
        nodes.get_mut(&2).unwrap().target = TypeRef::Absent;
        assert!(declaration(&function, &[2], None, &nodes, 8, &mut report).is_err());
    }

    #[test]
    fn names_are_sanitized_and_colliding_parameter_names_remain_unique() {
        let function = Node {
            name: Some("call@12".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes = BTreeMap::from([(1, integer(Some(4)))]);
        for (index, name) in [Some("arg_2"), None, Some("void"), Some("bad-name")].iter().enumerate() {
            nodes.insert(
                index + 2,
                Node { name: name.map(str::to_owned), ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1)) },
            );
        }
        let mut report = DebugReport::default();
        let signature = declaration(&function, &[2, 3, 4, 5], None, &nodes, 8, &mut report).unwrap();
        assert_eq!(signature.name, "call_12");
        assert_eq!(
            signature.declaration,
            "void call_12(int32_t arg_2, int32_t arg_2_2, int32_t debug_void, int32_t bad_name);"
        );
        assert!(report.warnings.iter().any(|warning| warning.contains("duplicate")));
        assert_eq!(c_name("int32_t"), "debug_int32_t");
    }

    #[test]
    fn large_declarations_are_rejected_before_joining_parameter_strings() {
        let function = Node {
            name: Some("large".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes = BTreeMap::from([(1, integer(Some(4)))]);
        let parameters: Vec<_> = (2..82).collect();
        for &offset in &parameters {
            nodes.insert(
                offset,
                Node {
                    name: Some(format!("{}_{offset}", "a".repeat(MAX_IDENTIFIER_BYTES - 4))),
                    ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                },
            );
        }
        let mut report = DebugReport::default();
        assert!(declaration(&function, &parameters, None, &nodes, 8, &mut report).unwrap_err().contains("65536"));
    }

    #[test]
    fn oversized_inline_names_invalidate_the_node_without_copying_the_string() {
        let abbrev = [1, 0x11, 1, 0, 0, 2, 0x2e, 0, 3, 8, 0, 0, 0];
        let mut entries = vec![1, 2];
        entries.extend_from_slice(&vec![b'a'; MAX_NAME_BYTES + 1]);
        entries.extend_from_slice(&[0, 0]);
        let info = unit(&entries);
        let nodes = read_nodes(&dwarf(&info, &abbrev)).unwrap();
        assert!(nodes[&12].invalid);
        assert!(nodes[&12].name.is_none());
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

    fn unit(entries: &[u8]) -> Vec<u8> {
        let mut bytes = ((entries.len() + 7) as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[4, 0, 0, 0, 0, 0, 8]);
        bytes.extend_from_slice(entries);
        bytes
    }

    #[test]
    fn debug_info_references_resolve_across_units_without_confusing_unit_relative_offsets() {
        let abbrev = [
            1, 0x11, 1, 0, 0, 2, 0x24, 0, 0x3e, 0x0b, 0x0b, 0x0b, 0, 0, 3, 0x16, 0, 0x49, 0x10, 0, 0, 4, 0x16, 0, 0x49,
            0x13, 0, 0, 0,
        ];
        let first = unit(&[1, 2, 5, 4, 0]);
        let second = unit(&[1, 3, 12, 0, 0, 0, 4, 12, 0, 0, 0, 0]);
        let second_start = first.len();
        let info = [first, second].concat();
        let nodes = read_nodes(&dwarf(&info, &abbrev)).unwrap();
        assert_eq!(resolve_type(TypeRef::Offset(second_start + 12), &nodes, 8, 0, false).unwrap().text, "int32_t");
        assert!(matches!(nodes[&(second_start + 17)].target, TypeRef::Offset(offset) if offset == second_start + 12));
        assert_eq!(resolve_type(TypeRef::Offset(second_start + 17), &nodes, 8, 0, false).unwrap().text, "int32_t");
    }

    #[test]
    fn malformed_units_and_excessive_nesting_fail_before_emitting_partial_metadata() {
        let abbrev = [1, 0x11, 1, 0, 0, 0];
        let deep = unit(&vec![1; MAX_NESTING + 2]);
        assert!(read_nodes(&dwarf(&deep, &abbrev)).unwrap_err().contains("nesting"));
        let too_many = vec![unit(&[1, 0]); MAX_UNITS + 1].concat();
        assert!(read_nodes(&dwarf(&too_many, &abbrev)).unwrap_err().contains("unit limit"));
        assert!(read_nodes(&dwarf(&[0xff, 0xff, 0xff, 0x7f], &abbrev)).is_err());
        assert!(read_nodes(&dwarf(&unit(&[1]), &abbrev)).unwrap_err().contains("unterminated"));
        assert!(read_nodes(&dwarf(&unit(&[1, 0, 0]), &abbrev)).unwrap_err().contains("unbalanced"));
        assert!(read_nodes(&dwarf(&unit(&[1, 0, 1, 0]), &abbrev)).unwrap_err().contains("multiple"));
    }

    #[test]
    fn abbreviation_attribute_counts_are_bounded_before_gimli_allocates_them() {
        let mut abbrev = vec![1, 0x11, 1];
        for _ in 0..=MAX_ATTRIBUTES {
            abbrev.extend_from_slice(&[3, 8]);
        }
        abbrev.extend_from_slice(&[0, 0, 0]);
        let info = unit(&[1]);
        assert!(read_nodes(&dwarf(&info, &abbrev)).is_err());
    }

    #[test]
    fn referenced_names_are_bounded_before_searching_for_the_terminator() {
        let info = unit(&[1, 0]);
        let abbrev = [1, 0x11, 1, 0, 0, 0];
        let mut dwarf = dwarf(&info, &abbrev);
        let strings = vec![b'a'; MAX_NAME_BYTES * 2];
        dwarf.debug_str = gimli::DebugStr::new(&strings, RunTimeEndian::Little);
        let unit = signature_unit(&dwarf, dwarf.units().next().unwrap().unwrap()).unwrap();
        for offset in [0, 1, MAX_NAME_BYTES - 1] {
            assert!(bounded_name(&dwarf, &unit, AttributeValue::DebugStrRef(gimli::DebugStrOffset(offset))).is_err());
        }
    }

    #[test]
    fn absent_prototyping_is_not_treated_as_a_complete_fixed_c_prototype() {
        let function = Node {
            name: Some("unprototyped".to_owned()),
            address: Some(0x1000),
            prototyped: false,
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        assert!(declaration(&function, &[], None, &BTreeMap::new(), 8, &mut DebugReport::default()).is_err());
    }

    #[test]
    fn native_type_names_are_sanitized_for_functions_and_parameters() {
        for reserved in [
            "int1",
            "int8",
            "int128",
            "uint4",
            "float4",
            "float8",
            "wchar",
            "wchar_t",
            "wchar16",
            "char32",
            "undefined4",
            "xunknown1",
            "xunknown8",
            "xunknown128",
        ] {
            let function = Node {
                name: Some(reserved.to_owned()),
                address: Some(0x1000),
                ..node(gimli::DW_TAG_subprogram, TypeRef::Offset(1))
            };
            let nodes = BTreeMap::from([
                (1, integer(Some(4))),
                (
                    2,
                    Node {
                        name: Some(reserved.to_owned()),
                        ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                    },
                ),
            ]);
            let mut report = DebugReport::default();
            let signature = declaration(&function, &[2], None, &nodes, 8, &mut report).unwrap();
            assert_eq!(signature.name, format!("debug_{reserved}"));
            assert_eq!(signature.declaration, format!("int32_t debug_{reserved}(int32_t debug_{reserved});"));
            assert_eq!(report.warnings.len(), 2);
        }
        for ordinary in ["int1_value", "uint_count", "float_fraction", "integer"] {
            assert_eq!(c_name(ordinary), ordinary);
        }
    }

    #[test]
    fn const_erasure_is_reported_once_and_volatile_or_restrict_rejects_whole_signatures() {
        let mut nodes = BTreeMap::from([
            (1, integer(Some(4))),
            (2, node(gimli::DW_TAG_const_type, TypeRef::Offset(1))),
            (3, node(gimli::DW_TAG_const_type, TypeRef::Offset(2))),
            (4, node(gimli::DW_TAG_pointer_type, TypeRef::Offset(3))),
            (5, node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(4))),
            (6, node(gimli::DW_TAG_volatile_type, TypeRef::Offset(1))),
            (7, node(gimli::DW_TAG_restrict_type, TypeRef::Offset(4))),
        ]);
        nodes.get_mut(&5).unwrap().name = Some("value".to_owned());
        let function = Node {
            name: Some("qualified".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Offset(3))
        };
        let mut report = DebugReport::default();
        let signature = declaration(&function, &[5], None, &nodes, 8, &mut report).unwrap();
        assert_eq!(signature.declaration, "int32_t qualified(int32_t * value);");
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("const qualifiers intentionally erased"));
        let mut exhausted = DebugReport { signatures: Vec::new(), warnings: vec![String::new(); MAX_WARNINGS] };
        assert!(declaration(&function, &[5], None, &nodes, 8, &mut exhausted).unwrap_err().contains("warning limit"));
        for offset in [6, 7] {
            nodes.get_mut(&5).unwrap().target = TypeRef::Offset(offset);
            let error = declaration(&function, &[5], None, &nodes, 8, &mut DebugReport::default()).unwrap_err();
            assert!(error.contains("unsupported DWARF qualifier"));
            let return_function = Node {
                name: Some("qualified_return".to_owned()),
                address: Some(0x1000),
                ..node(gimli::DW_TAG_subprogram, TypeRef::Offset(offset))
            };
            assert!(
                declaration(&return_function, &[], None, &nodes, 8, &mut DebugReport::default())
                    .unwrap_err()
                    .contains("unsupported DWARF qualifier")
            );
        }
        nodes.get_mut(&4).unwrap().target = TypeRef::Offset(6);
        nodes.get_mut(&5).unwrap().target = TypeRef::Offset(4);
        assert!(declaration(&function, &[5], None, &nodes, 8, &mut DebugReport::default()).is_err());
    }

    #[test]
    fn unsigned_plain_char_is_not_imported_as_native_signed_char() {
        let mut character = Node {
            name: Some("char".to_owned()),
            size: Some(1),
            encoding: Some(gimli::DW_ATE_unsigned_char),
            ..node(gimli::DW_TAG_base_type, TypeRef::Absent)
        };
        assert_eq!(scalar(&character).unwrap(), "uint8_t");
        character.encoding = Some(gimli::DW_ATE_signed_char);
        assert_eq!(scalar(&character).unwrap(), "char");
        character.name = Some("signed char".to_owned());
        assert_eq!(scalar(&character).unwrap(), "int8_t");
    }

    #[test]
    fn duplicate_signature_attributes_are_rejected_instead_of_using_the_last_value() {
        for (attribute, first, second) in [
            (gimli::DW_AT_type, 12, 99),
            (gimli::DW_AT_byte_size, 4, 8),
            (gimli::DW_AT_encoding, 5, 7),
            (gimli::DW_AT_prototyped, 0, 1),
            (gimli::DW_AT_low_pc, 0, 1),
            (gimli::DW_AT_declaration, 0, 1),
        ] {
            let abbrev = [1, 0x11, 1, 0, 0, 2, 0x24, 0, attribute.0 as u8, 0x0b, attribute.0 as u8, 0x0b, 0, 0, 0];
            let info = unit(&[1, 2, first, second, 0]);
            assert!(read_nodes(&dwarf(&info, &abbrev)).unwrap_err().contains("duplicate DWARF attribute"));
        }
        let abbrev = [1, 0x11, 1, 0, 0, 2, 0x2e, 0, 3, 8, 3, 8, 0, 0, 0];
        let info = unit(b"\x01\x02first\0second\0\0");
        assert!(read_nodes(&dwarf(&info, &abbrev)).unwrap_err().contains("duplicate DWARF attribute"));
        let root_abbrev = [1, 0x11, 1, 0x73, 0x17, 0x73, 0x17, 0, 0, 0];
        let info = unit(&[1, 0, 0, 0, 0, 8, 0, 0, 0, 0]);
        assert!(read_nodes(&dwarf(&info, &root_abbrev)).unwrap_err().contains("duplicate DWARF root attribute"));
        let parameter_abbrev = [1, 0x11, 1, 0, 0, 2, 0x05, 0, 0x49, 0x13, 0x49, 0x13, 0, 0, 0];
        let info = unit(&[1, 2, 12, 0, 0, 0, 99, 0, 0, 0, 0]);
        assert!(read_nodes(&dwarf(&info, &parameter_abbrev)).unwrap_err().contains("duplicate DWARF attribute"));
    }

    #[test]
    fn long_parameter_lists_wrap_without_changing_argument_order_or_variadic_markers() {
        let function = Node {
            name: Some("wrapped".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes = BTreeMap::from([(1, integer(Some(4)))]);
        let parameters: Vec<_> = (2..10).collect();
        for &offset in &parameters {
            nodes.insert(
                offset,
                Node {
                    name: Some(format!("{}_{offset}", "a".repeat(600))),
                    ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                },
            );
        }
        let signature = declaration(&function, &parameters, Some(10), &nodes, 8, &mut DebugReport::default()).unwrap();
        assert!(signature.declaration.starts_with("void wrapped(\n"));
        assert!(signature.declaration.ends_with("\n    ... \n);"));
        assert!(signature.declaration.lines().all(|line| line.len() <= MAX_DECLARATION_LINE_BYTES));
        let argument_lines: Vec<_> = signature.declaration.lines().skip(1).take(parameters.len()).collect();
        for (line, offset) in argument_lines.iter().zip(parameters) {
            assert!(line.contains(&format!("_{offset}")));
        }
        assert!(signature.declaration.len() <= MAX_DECLARATION_BYTES);
    }

    #[test]
    fn single_overlong_identifiers_cannot_bypass_declaration_line_limits() {
        let function = Node {
            name: Some("a".repeat(MAX_IDENTIFIER_BYTES + 1)),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        assert!(
            declaration(&function, &[], None, &BTreeMap::new(), 8, &mut DebugReport::default())
                .unwrap_err()
                .contains("identifier limit")
        );
        let function = Node { name: Some("short".to_owned()), ..function };
        let nodes = BTreeMap::from([
            (1, integer(Some(4))),
            (
                2,
                Node {
                    name: Some("a".repeat(MAX_IDENTIFIER_BYTES + 1)),
                    ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                },
            ),
        ]);
        assert!(
            declaration(&function, &[2], None, &nodes, 8, &mut DebugReport::default())
                .unwrap_err()
                .contains("identifier limit")
        );
    }

    #[test]
    fn declaration_wrapping_starts_only_above_the_line_limit() {
        let function = Node {
            name: Some("f".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes = BTreeMap::from([(1, integer(Some(4)))]);
        for (offset, length) in [(2, 1024), (3, 1024), (4, 1024), (5, 976)] {
            nodes.insert(
                offset,
                Node {
                    name: Some(format!("p{offset}{}", "a".repeat(length - 2))),
                    ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                },
            );
        }
        let signature = declaration(&function, &[2, 3, 4, 5], None, &nodes, 8, &mut DebugReport::default()).unwrap();
        assert_eq!(signature.declaration.len(), MAX_DECLARATION_LINE_BYTES);
        assert!(!signature.declaration.contains('\n'));
        nodes.get_mut(&5).unwrap().name.as_mut().unwrap().push('a');
        let signature = declaration(&function, &[2, 3, 4, 5], None, &nodes, 8, &mut DebugReport::default()).unwrap();
        assert!(signature.declaration.contains('\n'));
        assert!(signature.declaration.lines().nth(4).unwrap().ends_with(' '));
        assert!(signature.declaration.ends_with(" \n);"));
        assert!(!signature.declaration.lines().any(|line| line.len() == 4096));
        assert!(signature.declaration.lines().all(|line| line.len() <= MAX_DECLARATION_LINE_BYTES));
    }

    #[test]
    fn multiline_separator_bytes_count_toward_the_total_declaration_limit() {
        let function = Node {
            name: Some("many".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Absent)
        };
        let mut nodes = BTreeMap::from([(1, integer(Some(4)))]);
        let parameters: Vec<_> = (2..2102).collect();
        for &offset in &parameters {
            nodes.insert(
                offset,
                Node {
                    name: Some(format!("p{offset:017}")),
                    ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1))
                },
            );
        }
        assert!(
            declaration(&function, &parameters, None, &nodes, 8, &mut DebugReport::default())
                .unwrap_err()
                .contains("65536-byte limit")
        );
    }

    #[test]
    fn encoded_default_address_class_is_supported_but_other_classes_are_rejected() {
        let abbrev = [1, 0x11, 1, 0, 0, 2, 0x0f, 0, 0x33, 0x0b, 0, 0, 0];
        for (class, valid) in [(0, true), (1, false)] {
            let info = unit(&[1, 2, class, 0]);
            let nodes = read_nodes(&dwarf(&info, &abbrev)).unwrap();
            assert_eq!(resolve_type(TypeRef::Offset(12), &nodes, 8, 0, false).is_ok(), valid);
        }
    }

    #[test]
    fn standard_and_gnu_address_bases_cannot_conflict_in_either_attribute_order() {
        for reversed in [false, true] {
            let standard = [0x73, 0x17];
            let gnu = [0xb3, 0x42, 0x17];
            let mut abbrev = vec![1, 0x11, 1];
            for attribute in if reversed { [&gnu[..], &standard[..]] } else { [&standard[..], &gnu[..]] } {
                abbrev.extend_from_slice(attribute);
            }
            abbrev.extend_from_slice(&[0x11, 0x1b, 0, 0, 0]);
            for (second_base, valid) in [(8u32, true), (16, false)] {
                let mut entries = vec![1];
                entries.extend_from_slice(&8u32.to_le_bytes());
                entries.extend_from_slice(&second_base.to_le_bytes());
                entries.extend_from_slice(&[0, 0]);
                let info = unit(&entries);
                let addresses = [0u64, 0x1000, 0x2000].map(u64::to_le_bytes).concat();
                let mut dwarf = dwarf(&info, &abbrev);
                dwarf.debug_addr = gimli::DebugAddr::from(EndianSlice::new(&addresses, RunTimeEndian::Little));
                let result = signature_unit(&dwarf, dwarf.units().next().unwrap().unwrap());
                if valid {
                    assert_eq!(result.unwrap().low_pc, 0x1000);
                } else {
                    assert!(result.unwrap_err().contains("conflicting DWARF address-base"));
                }
            }
        }
    }

    #[test]
    fn warning_floods_are_visible_and_cannot_hide_const_erasure_for_emitted_signatures() {
        let function = Node {
            name: Some("qualified".to_owned()),
            address: Some(0x1000),
            ..node(gimli::DW_TAG_subprogram, TypeRef::Offset(2))
        };
        let mut nodes =
            BTreeMap::from([(1, integer(Some(4))), (2, node(gimli::DW_TAG_const_type, TypeRef::Offset(1)))]);
        let parameters: Vec<_> = (3..2203).collect();
        for &offset in &parameters {
            nodes.insert(
                offset,
                Node { name: Some("x-y".to_owned()), ..node(gimli::DW_TAG_formal_parameter, TypeRef::Offset(1)) },
            );
        }
        let mut report = DebugReport::default();
        assert!(
            declaration(&function, &parameters, None, &nodes, 8, &mut report).unwrap_err().contains("warning limit")
        );
        assert_eq!(report.warnings.len(), MAX_WARNINGS);
        assert!(report.warnings.last().unwrap().contains("diagnostics are truncated"));
        report.warn("later warning".to_owned());
        assert_eq!(report.warnings.len(), MAX_WARNINGS);
    }
}
