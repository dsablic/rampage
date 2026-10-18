//! Explicit, bounded CodeView producer graph. No native type library or declaration renderer is used here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::debug_types::*;

use super::*;

const MAX_TYPE_STREAM_BYTES: usize = 1024 * 1024;
const MAX_TYPE_RECORDS: usize = 4096;
const MAX_ARGUMENTS: usize = 128;

/// Reads type facts and procedure references from the same owned bytes used for the PE identity/name check.
/// This does not read a CodeView path, discover a sidecar, or assert a native layout/calling ABI.
pub fn matched_types_checked(path: &Path, binary: &Binary) -> Result<(DebugTypeReport, PdbProvenance), LoadError> {
    binary.validate_backing_source()?;
    let input = read_pdb_input(path, open_pdb_file)?;
    input.provenance.require_identity()?;
    let report = with_backing_source(binary, || {
        let mut budget = Budget { bytes: MAX_SOURCE_BYTES, work: MAX_STRUCTURAL_WORK };
        let msf = preflight_msf(&input.bytes, &mut budget)?;
        preflight_symbols(&msf, &mut budget)?;
        // The raw audit precedes all dependency parsing, including its potentially allocating list parsers.
        let tpi = type_stream(&msf, 2, &mut budget)?;
        let ipi = if msf.streams.get(4).and_then(Option::as_ref).is_some_and(|s| s.length > 0) {
            Some(type_stream(&msf, 4, &mut budget)?)
        } else {
            None
        };
        let raw = parse_types(&tpi)?;
        audit_ipi(ipi.as_ref(), &raw)?;
        let symbols = procedure_refs(&msf, &mut budget, binary)?;
        let names = match_report(binary, || pdb_symbols_bytes(&input.bytes))?;
        let identity = names.identity.as_ref().ok_or_else(|| malformed("missing checked type-source identity"))?;
        let provenance = DebugTypeProvenance {
            source: DebugSourceKind::Pdb,
            source_sha256: rampage_arch::hex::bytes(input.provenance.sha256()),
            pdb_guid: Some(rampage_arch::hex::bytes(&identity.guid)),
            pdb_age: Some(identity.age),
        };
        make_report(raw, ipi.as_ref(), symbols, names, provenance, binary)
    })?;
    Ok((report, input.provenance))
}

struct TypeStream {
    bytes: Vec<u8>,
    records: BTreeMap<u32, (usize, usize)>,
}

impl TypeStream {
    fn record(&self, index: u32) -> Result<&[u8], LoadError> {
        let &(start, length) = self.records.get(&index).ok_or_else(|| malformed("invalid type index"))?;
        range(&self.bytes, start, length)
    }
}

fn type_stream(msf: &Msf<'_>, stream: u16, budget: &mut Budget) -> Result<TypeStream, LoadError> {
    if msf.stream(stream)?.length > MAX_TYPE_STREAM_BYTES {
        return Err(malformed("TPI/IPI stream exceeds 1 MiB audit limit"));
    }
    let bytes = msf.read(stream, budget)?;
    if uint(&bytes, 0)? != 20040203 || uint(&bytes, 4)? != 56 || uint(&bytes, 8)? != 0x1000 {
        return Err(malformed("unsupported TPI/IPI header"));
    }
    let end = uint(&bytes, 12)?;
    let count = end.checked_sub(0x1000).ok_or_else(|| malformed("invalid TPI/IPI index interval"))? as usize;
    if count > MAX_TYPE_RECORDS || uint(&bytes, 16)? as usize != bytes.len().saturating_sub(56) {
        return Err(malformed("TPI/IPI record count or byte length exceeds bounds"));
    }
    budget.work(count)?;
    let mut records = BTreeMap::new();
    let mut at = 56;
    for index in 0x1000..end {
        let length = usize::from(ushort(&bytes, at)?);
        if length < 2 || !(length + 2).is_multiple_of(4) {
            return Err(malformed("invalid TPI/IPI record length"));
        }
        range(&bytes, at + 2, length)?;
        records.insert(index, (at + 2, length));
        at += length + 2;
    }
    if at != bytes.len() {
        return Err(malformed("TPI/IPI count does not cover the record bytes"));
    }
    Ok(TypeStream { bytes, records })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], LoadError> {
        let bytes = range(self.bytes, self.at, count)?;
        self.at += count;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, LoadError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, LoadError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(malformed)?))
    }

    fn u32(&mut self) -> Result<u32, LoadError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(malformed)?))
    }

    fn string(&mut self) -> Result<String, LoadError> {
        let rest = &self.bytes[self.at..];
        let count = rest.iter().position(|&b| b == 0).ok_or_else(|| malformed("unterminated type name"))?;
        if count > MAX_NAME_BYTES {
            return Err(malformed("type name exceeds limit"));
        }
        let name = std::str::from_utf8(self.take(count)?).map_err(malformed)?.to_owned();
        self.take(1)?;
        Ok(name)
    }

    fn number(&mut self) -> Result<i128, LoadError> {
        Ok(self.numeric()?.value)
    }

    fn numeric(&mut self) -> Result<Numeric, LoadError> {
        let leaf = self.u16()?;
        let value = match leaf {
            0..=0x7fff => i128::from(leaf),
            0x8000 => i128::from(self.u8()? as i8),
            0x8001 => i128::from(self.u16()? as i16),
            0x8002 => i128::from(self.u16()?),
            0x8003 => i128::from(self.u32()? as i32),
            0x8004 => i128::from(self.u32()?),
            0x8009 => i128::from(i64::from_le_bytes(self.take(8)?.try_into().map_err(malformed)?)),
            0x800a => i128::from(u64::from_le_bytes(self.take(8)?.try_into().map_err(malformed)?)),
            _ => return Err(malformed("unsupported type numeric leaf")),
        };
        let unsigned_width = match leaf {
            0x8002 => Some(16),
            0x8004 => Some(32),
            0x800a => Some(64),
            _ => None,
        };
        Ok(Numeric { value, unsigned_width })
    }

    fn size(&mut self) -> Result<u64, LoadError> {
        u64::try_from(self.number()?)
            .ok()
            .filter(|&n| n <= MAX_DEBUG_TYPE_BYTES)
            .ok_or_else(|| malformed("type size/offset is negative or exceeds 1 MiB"))
    }

    fn padding(&mut self) -> Result<(), LoadError> {
        if self.at < self.bytes.len() && self.bytes[self.at] >= 0xf0 {
            let count = usize::from(self.bytes[self.at] & 15);
            if count == 0 || count > 3 {
                return Err(malformed("invalid CodeView type padding"));
            }
            for expected in (1..=count).rev() {
                if self.u8()? != 0xf0 + expected as u8 {
                    return Err(malformed("invalid CodeView type padding sequence"));
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), LoadError> {
        self.padding()?;
        if self.at != self.bytes.len() {
            return Err(malformed("unaccounted type record bytes"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Numeric {
    value: i128,
    unsigned_width: Option<u8>,
}

#[derive(Clone)]
struct Aggregate {
    leaf: u16,
    count: usize,
    properties: u16,
    fields: u32,
    size: Option<u64>,
    name: String,
    unique: Option<String>,
    underlying: Option<u32>,
    unsupported: Vec<String>,
}

#[derive(Clone)]
enum Field {
    Member { name: String, target: u32, offset: u64, attributes: u16 },
    Enumerator { name: String, numeric: Numeric },
    Unsupported(String),
}

#[derive(Clone)]
enum RawType {
    Aggregate(Aggregate),
    Pointer { target: u32, attributes: u32 },
    Modifier { target: u32, flags: u16 },
    Alias { target: u32, name: String },
    Array { element: u32, index: u32, size: u64, stride: Option<u64> },
    Function { result: u32, convention: u8, attributes: u8, count: usize, arguments: u32 },
    Bitfield { target: u32, bits: u8, position: u8 },
    Fields { fields: Vec<Field>, continuation: Option<u32>, complete: bool },
    Arguments(Vec<u32>),
    Unsupported(u16),
}

impl RawType {
    fn references(&self) -> Vec<u32> {
        match self {
            Self::Aggregate(a) => a.underlying.into_iter().chain((a.fields != 0).then_some(a.fields)).collect(),
            Self::Pointer { target, .. }
            | Self::Modifier { target, .. }
            | Self::Alias { target, .. }
            | Self::Bitfield { target, .. } => vec![*target],
            Self::Array { element, index, .. } => vec![*element, *index],
            Self::Function { result, arguments, .. } => vec![*result, *arguments],
            Self::Fields { fields, continuation, .. } => fields
                .iter()
                .filter_map(|field| match field {
                    Field::Member { target, .. } => Some(*target),
                    _ => None,
                })
                .chain(continuation.iter().copied())
                .collect(),
            Self::Arguments(arguments) => arguments.clone(),
            Self::Unsupported(_) => Vec::new(),
        }
    }
}

fn parse_types(stream: &TypeStream) -> Result<BTreeMap<u32, RawType>, LoadError> {
    let mut types = BTreeMap::new();
    let mut data_types = 0usize;
    for &index in stream.records.keys() {
        let mut c = Cursor::new(stream.record(index)?);
        let leaf = c.u16()?;
        let ty = match leaf {
            0x1504..=0x1507 => {
                let count = usize::from(c.u16()?);
                let properties = c.u16()?;
                if count > MAX_DEBUG_FIELDS {
                    return Err(malformed("aggregate field count exceeds 128"));
                }
                let underlying = if leaf == 0x1507 { Some(c.u32()?) } else { None };
                let fields = c.u32()?;
                let mut unsupported = Vec::new();
                if matches!(leaf, 0x1504 | 0x1505) {
                    let derived = c.u32()?;
                    let vshape = c.u32()?;
                    if [derived, vshape].into_iter().any(|r| r != 0 && !stream.records.contains_key(&r)) {
                        return Err(malformed("aggregate inheritance/vtable reference is outside TPI"));
                    }
                    if leaf == 0x1504 || derived != 0 || vshape != 0 {
                        unsupported.push("C++ class/inheritance/vtable layout is preview-only".to_owned());
                    }
                }
                let size = if underlying.is_none() { Some(c.size()?) } else { None };
                if properties & 0x80 != 0 && (count != 0 || fields != 0 || size.is_some_and(|size| size != 0)) {
                    return Err(malformed("forward aggregate record contains conflicting layout facts"));
                }
                let name = c.string()?;
                let unique = if properties & 0x200 != 0 { Some(c.string()?) } else { None };
                if properties & !(0x80 | 0x200 | 0x400) != 0 {
                    unsupported.push("scoped/nested or special aggregate properties are preview-only".to_owned());
                }
                RawType::Aggregate(Aggregate {
                    leaf,
                    count,
                    properties,
                    fields,
                    size,
                    name,
                    unique,
                    underlying,
                    unsupported,
                })
            }
            0x1002 => RawType::Pointer { target: c.u32()?, attributes: c.u32()? },
            0x1001 => RawType::Modifier { target: c.u32()?, flags: c.u16()? },
            0x150a => RawType::Alias { target: c.u32()?, name: c.string()? },
            0x1503 | 0x1516 => {
                let element = c.u32()?;
                let index = c.u32()?;
                let stride = if leaf == 0x1516 { Some(u64::from(c.u32()?)) } else { None };
                let size = c.size()?;
                c.string()?;
                RawType::Array { element, index, size, stride }
            }
            0x1008 => {
                let result = c.u32()?;
                let convention = c.u8()?;
                let attributes = c.u8()?;
                let count = usize::from(c.u16()?);
                if count > MAX_ARGUMENTS {
                    return Err(malformed("procedure parameter count exceeds limit"));
                }
                RawType::Function { result, convention, attributes, count, arguments: c.u32()? }
            }
            0x1205 => RawType::Bitfield { target: c.u32()?, bits: c.u8()?, position: c.u8()? },
            0x1201 => {
                let count = c.u32()? as usize;
                if count > MAX_ARGUMENTS || count.checked_mul(4).is_none_or(|n| n > c.bytes.len() - c.at) {
                    return Err(malformed("argument-list count/length exceeds bounds"));
                }
                let mut arguments = Vec::with_capacity(count);
                for _ in 0..count {
                    arguments.push(c.u32()?);
                }
                RawType::Arguments(arguments)
            }
            0x1203 => parse_fields(&mut c)?,
            _ => {
                // Unknown records are retained as unsupported facts, never passed to pdb's recursive type parser.
                c.at = c.bytes.len();
                RawType::Unsupported(leaf)
            }
        };
        // Member pointers have extra class/representation fields; they remain explicitly unsupported below.
        if matches!(&ty, RawType::Pointer { attributes, .. } if (attributes >> 5) & 7 >= 2) {
            c.at = c.bytes.len();
        }
        c.finish()?;
        if !matches!(ty, RawType::Fields { .. } | RawType::Arguments(_)) {
            data_types += 1;
            if data_types > MAX_DEBUG_TYPES {
                return Err(malformed("TPI data-type count exceeds 256"));
            }
        }
        types.insert(index, ty);
    }
    audit_types(&types)?;
    Ok(types)
}

fn parse_fields(c: &mut Cursor<'_>) -> Result<RawType, LoadError> {
    let mut fields = Vec::new();
    let mut continuation = None;
    let mut complete = true;
    while c.at < c.bytes.len() {
        c.padding()?;
        if c.at == c.bytes.len() {
            break;
        }
        if fields.len() >= MAX_DEBUG_FIELDS {
            return Err(malformed("field-list count exceeds 128"));
        }
        let leaf = c.u16()?;
        let field = match leaf {
            0x150d => {
                let attributes = c.u16()?;
                let target = c.u32()?;
                let offset = c.size()?;
                Field::Member { name: c.string()?, target, offset, attributes }
            }
            0x1502 => {
                c.u16()?;
                let numeric = c.numeric()?;
                Field::Enumerator { name: c.string()?, numeric }
            }
            0x1404 => {
                if continuation.is_some() || c.u16()? != 0 {
                    return Err(malformed("invalid or duplicate field-list continuation"));
                }
                let target = c.u32()?;
                if target < 0x1000 {
                    return Err(malformed("field-list continuation is not a TPI record index"));
                }
                continuation = Some(target);
                c.finish()?;
                break;
            }
            _ => {
                complete = false;
                // An unrecognized field has no trustworthy framing; do not claim the remaining layout is complete.
                c.at = c.bytes.len();
                Field::Unsupported(format!("field leaf {leaf:#06x} (inheritance/method/static/nested) is preview-only"))
            }
        };
        fields.push(field);
    }
    Ok(RawType::Fields { fields, continuation, complete })
}

fn audit_types(types: &BTreeMap<u32, RawType>) -> Result<(), LoadError> {
    for ty in types.values() {
        for reference in ty.references() {
            if reference >= 0x1000 && !types.contains_key(&reference) {
                return Err(malformed("TPI reference is outside the complete type-index interval"));
            }
        }
        if let RawType::Function { count, arguments, .. } = ty {
            let Some(RawType::Arguments(args)) = types.get(arguments) else {
                return Err(malformed("procedure does not reference an argument list"));
            };
            if args.len() != *count && !(args.last() == Some(&0) && args.len() == *count + 1) {
                return Err(malformed("procedure and argument-list counts disagree"));
            }
        }
        if let RawType::Aggregate(a) = ty
            && a.properties & 0x80 == 0
        {
            let (fields, complete) = flatten_fields(types, a.fields)?;
            if complete && fields.len() != a.count {
                return Err(malformed("aggregate and complete field-list counts disagree"));
            }
        }
    }
    // Audit even orphaned lists, including cycles not reachable from a displayed type.
    for (&index, ty) in types {
        if matches!(ty, RawType::Fields { .. }) {
            flatten_fields(types, index)?;
        }
    }
    Ok(())
}

fn flatten_fields(types: &BTreeMap<u32, RawType>, mut index: u32) -> Result<(Vec<&Field>, bool), LoadError> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    let mut complete = true;
    while index != 0 {
        if seen.len() >= MAX_DEBUG_DEPTH || !seen.insert(index) {
            return Err(malformed("field-list continuation cycle/depth exceeds limit"));
        }
        let Some(RawType::Fields { fields, continuation, complete: part_complete }) = types.get(&index) else {
            return Err(malformed("field-list reference is not a field list"));
        };
        if result.len() + fields.len() > MAX_DEBUG_FIELDS {
            return Err(malformed("continued field-list exceeds 128 fields"));
        }
        result.extend(fields.iter());
        complete &= *part_complete;
        index = continuation.unwrap_or(0);
    }
    Ok((result, complete))
}

fn audit_ipi(ipi: Option<&TypeStream>, types: &BTreeMap<u32, RawType>) -> Result<(), LoadError> {
    let Some(ipi) = ipi else { return Ok(()) };
    for &index in ipi.records.keys() {
        let bytes = ipi.record(index)?;
        match ushort(bytes, 0)? {
            0x1601 | 0x1602 => {
                let mut c = Cursor::new(bytes);
                c.u16()?;
                let parent = c.u32()?;
                let target = c.u32()?;
                if !types.contains_key(&target) {
                    return Err(malformed("IPI function has an invalid TPI reference"));
                }
                let function_kind_matches = matches!(
                    (ushort(bytes, 0)?, types.get(&target)),
                    (0x1601, Some(RawType::Function { .. })) | (0x1602, Some(RawType::Unsupported(0x1009)))
                );
                if !function_kind_matches {
                    return Err(malformed("IPI function type does not reference the appropriate TPI procedure kind"));
                }
                if ushort(bytes, 0)? == 0x1601 && parent != 0 && !ipi.records.contains_key(&parent) {
                    return Err(malformed("IPI function scope is outside IPI"));
                }
                if ushort(bytes, 0)? == 0x1602 && !types.contains_key(&parent) {
                    return Err(malformed("IPI member-function parent is outside TPI"));
                }
                c.string()?;
                c.finish()?;
            }
            // No dependency IPI parser is used. Other IPI records stay opaque bounded bytes.
            _ => {}
        }
    }
    Ok(())
}

struct ProcedureRef {
    rva: u64,
    index: u32,
    is_id: bool,
    module: u16,
    offset: u64,
}

struct ProcedureRefs {
    procedures: Vec<ProcedureRef>,
    aliases: BTreeMap<DebugTypeId, SymbolAlias>,
}

#[derive(Debug, PartialEq, Eq)]
struct SymbolAlias {
    target: u32,
    name: String,
    stream: u16,
    offset: u64,
}

fn procedure_refs(msf: &Msf<'_>, budget: &mut Budget, binary: &Binary) -> Result<ProcedureRefs, LoadError> {
    let dbi = msf.read(3, budget)?;
    // NewDBIHeader: flags at 56, COFF machine at 58, reserved u32 at 60.
    // This is the same owned source used for the type graph, GUID/age check and source SHA.
    validate_type_machine(ushort(&dbi, 58)?, binary)?;
    let mut extra = 64usize;
    for offset in [24, 28, 32, 36, 40, 52] {
        extra += uint(&dbi, offset)? as usize;
    }
    let debug = range(&dbi, extra, uint(&dbi, 48)? as usize)?;
    let sections = msf.read(ushort(debug, 10)?, budget)?;
    let modules = range(&dbi, 64, uint(&dbi, 24)? as usize)?;
    let mut result = ProcedureRefs { procedures: Vec::new(), aliases: BTreeMap::new() };
    let mut at = 0;
    while at < modules.len() {
        let header = range(modules, at, 64)?;
        let stream = ushort(header, 34)?;
        let size = uint(header, 36)? as usize;
        if stream != u16::MAX && size > 0 {
            let bytes = msf.read(stream, budget)?;
            collect_refs(range(&bytes, 4, size - 4)?, stream, 4, &sections, &mut result)?;
        }
        at += 64;
        for _ in 0..2 {
            at += modules[at..].iter().position(|&b| b == 0).ok_or_else(|| malformed("module name"))? + 1;
        }
        at = (at + 3) & !3;
    }
    let globals = ushort(&dbi, 20)?;
    let bytes = msf.read(globals, budget)?;
    collect_refs(&bytes, globals, 0, &sections, &mut result)?;
    Ok(result)
}

fn validate_type_machine(dbi_machine: u16, binary: &Binary) -> Result<(), LoadError> {
    let parsed = object::File::parse(binary.image_bytes())?;
    let selected_machine = match &parsed {
        object::File::Pe32(file) => file.nt_headers().file_header().machine.get(object::LittleEndian).0,
        object::File::Pe64(file) => file.nt_headers().file_header().machine.get(object::LittleEndian).0,
        _ => return Err(LoadError::Unsupported("PDB types require a PE image".to_owned())),
    };
    if !matches!(selected_machine, 0x014c | 0x8664 | 0xaa64) || !matches!(dbi_machine, 0x014c | 0x8664 | 0xaa64) {
        return Err(malformed(format!(
            "unsupported machine for checked types: PE COFF {selected_machine:#06x}, PDB DBI {dbi_machine:#06x}"
        )));
    }
    if dbi_machine != selected_machine {
        return Err(malformed(format!(
            "PDB DBI machine {dbi_machine:#06x} does not match selected PE COFF machine {selected_machine:#06x}"
        )));
    }
    Ok(())
}

fn collect_refs(
    bytes: &[u8],
    module: u16,
    stream_offset: u64,
    sections: &[u8],
    result: &mut ProcedureRefs,
) -> Result<(), LoadError> {
    let mut at = 0;
    while at < bytes.len() {
        let length = usize::from(ushort(bytes, at)?);
        let record = range(bytes, at + 2, length)?;
        let kind = ushort(record, 0)?;
        match kind {
            0x110f | 0x1110 | 0x1146 | 0x1147 => {
                if result.procedures.len() >= MAX_DEBUG_SIGNATURES {
                    return Err(malformed("procedure-type signature count exceeds 256"));
                }
                let section = usize::from(ushort(record, 34)?)
                    .checked_sub(1)
                    .ok_or_else(|| malformed("null procedure section"))?;
                let header = range(sections, section * 40, 40)?;
                let offset = uint(record, 30)?;
                if offset >= uint(header, 8)?.max(uint(header, 16)?) {
                    return Err(malformed("typed procedure is outside its section"));
                }
                let rva = uint(header, 12)?.checked_add(offset).ok_or_else(|| malformed("procedure RVA overflow"))?;
                result.procedures.push(ProcedureRef {
                    rva: u64::from(rva),
                    index: uint(record, 26)?,
                    is_id: matches!(kind, 0x1146 | 0x1147),
                    module,
                    offset: at as u64,
                });
            }
            0x1108 => {
                let target = uint(record, 2)?;
                let mut name = Cursor::new(range(record, 6, record.len().saturating_sub(6))?);
                let name = name.string()?;
                if name.is_empty() {
                    return Err(malformed("empty UDT alias name"));
                }
                let offset = stream_offset.checked_add(at as u64).ok_or_else(|| malformed("UDT offset overflow"))?;
                let id = symbol_type_id(module, offset);
                let alias = SymbolAlias { target, name, stream: module, offset };
                if let Some(previous) = result.aliases.get(&id)
                    && previous != &alias
                {
                    return Err(malformed("conflicting UDT alias facts at one symbol identity"));
                }
                if !result.aliases.contains_key(&id) && result.aliases.len() >= MAX_DEBUG_TYPES {
                    return Err(malformed("UDT alias record count exceeds 256"));
                }
                result.aliases.entry(id).or_insert(alias);
            }
            _ => {}
        }
        at += length + 2;
    }
    Ok(())
}

fn type_id(index: u32) -> DebugTypeId {
    format!("pdb:tpi:{index:08x}")
}

fn symbol_type_id(stream: u16, offset: u64) -> DebugTypeId {
    format!("pdb:sym:{stream:04x}:{offset:08x}")
}

fn origin(index: u64, unit: String) -> DebugTypeOrigin {
    DebugTypeOrigin { source: DebugSourceKind::Pdb, unit: Some(unit), index }
}

fn forward_resolutions(types: &BTreeMap<u32, RawType>) -> BTreeMap<u32, u32> {
    let mut result = BTreeMap::new();
    for (&index, ty) in types {
        let RawType::Aggregate(forward) = ty else { continue };
        if forward.properties & 0x80 == 0 {
            continue;
        }
        let candidates: Vec<_> = types
            .iter()
            .filter_map(|(&target, ty)| {
                let RawType::Aggregate(full) = ty else { return None };
                if full.properties & 0x80 != 0 || forward.leaf != full.leaf || forward.name != full.name {
                    return None;
                }
                if !forward.unsupported.is_empty() && full.unsupported.is_empty() {
                    return None;
                }
                let same_identity = match (&forward.unique, &full.unique) {
                    (Some(left), Some(right)) => !left.is_empty() && left == right,
                    // A same-name S_UDT/definition, even in one CU, cannot identify a block-scope forward.
                    _ => false,
                };
                same_identity.then_some(target)
            })
            .collect();
        if candidates.len() == 1 {
            result.insert(index, candidates[0]);
        }
    }
    result
}

fn resolved(index: u32, forwards: &BTreeMap<u32, u32>) -> u32 {
    forwards.get(&index).copied().unwrap_or(index)
}

fn make_report(
    raw: BTreeMap<u32, RawType>,
    ipi: Option<&TypeStream>,
    symbols: ProcedureRefs,
    names: PdbReport,
    provenance: DebugTypeProvenance,
    binary: &Binary,
) -> Result<DebugTypeReport, LoadError> {
    let forwards = forward_resolutions(&raw);
    let mut indices: BTreeSet<_> = raw
        .iter()
        .filter_map(|(&index, ty)| (!matches!(ty, RawType::Fields { .. } | RawType::Arguments(_))).then_some(index))
        .collect();
    for ty in raw.values() {
        indices.extend(ty.references().into_iter().filter(|&index| index < 0x1000));
    }
    indices.extend(symbols.aliases.values().map(|alias| alias.target).filter(|&index| index < 0x1000));
    let primitive_pointees: Vec<_> =
        indices.iter().copied().filter(|&i| i < 0x1000 && i & 0xf00 != 0).map(|i| i & 0xff).collect();
    indices.extend(primitive_pointees);
    if indices.len().checked_add(symbols.aliases.len()).is_none_or(|count| count > MAX_DEBUG_TYPES) {
        return Err(malformed("producer graph exceeds 256 types"));
    }
    let mut types = BTreeMap::new();
    for &index in &indices {
        let ty = if index < 0x1000 { primitive(index) } else { convert_type(index, &raw, &forwards)? };
        types.insert(ty.id.clone(), ty);
    }
    insert_symbol_aliases(&mut types, &symbols.aliases)?;
    finish_graph(&mut types)?;
    let checked: BTreeMap<_, _> = names.functions.iter().map(|f| (f.address, &f.name)).collect();
    let parsed = object::File::parse(binary.image_bytes())?;
    let image_base = parsed.relative_address_base();
    let mut signatures = BTreeMap::new();
    for procedure in symbols.procedures {
        let index = if procedure.is_id {
            let bytes = ipi.ok_or_else(|| malformed("PROC32_ID requires IPI, not TPI"))?.record(procedure.index)?;
            if !matches!(ushort(bytes, 0)?, 0x1601 | 0x1602) {
                return Err(malformed("PROC32_ID does not reference an IPI function identity"));
            }
            uint(bytes, 6)?
        } else {
            procedure.index
        };
        let index = resolved(index, &forwards);
        let ty = types.get(&type_id(index)).ok_or_else(|| malformed("procedure type is outside the graph"))?;
        let mut unsupported = ty.unsupported.clone();
        if !matches!(ty.kind, DebugTypeKind::Function { .. }) {
            unsupported.push("procedure reference is not a supported free-function type".to_owned());
        }
        let address = image_base.checked_add(procedure.rva).ok_or_else(|| malformed("typed procedure VA overflow"))?;
        let name = checked.get(&address).ok_or_else(|| malformed("typed procedure has no checked code VA"))?;
        let signature = DebugSignature {
            address,
            name: Some((*name).clone()),
            type_id: ty.id.clone(),
            origin: origin(procedure.offset, format!("symbols:{}", procedure.module)),
            unsupported,
        };
        if let Some(previous) = signatures.insert(address, signature.clone())
            && previous.type_id != signature.type_id
        {
            return Err(malformed("conflicting procedure type identities at one checked VA"));
        }
    }
    Ok(DebugTypeReport {
        types: types.into_values().collect(),
        signatures: signatures.into_values().collect(),
        provenance,
        limits: DebugTypeLimits::default(),
        warnings: vec![
            "Producer facts only; alignment is not inferred and calling conventions are not native ABI proof."
                .to_owned(),
            "Unrecognized records, C++ layouts, bitfields and aggregate-by-value calls are preview-only.".to_owned(),
            "Forward completion requires a matching producer unique identity on the forward and definition.".to_owned(),
        ],
    })
}

fn insert_symbol_aliases(
    types: &mut BTreeMap<DebugTypeId, DebugType>,
    aliases: &BTreeMap<DebugTypeId, SymbolAlias>,
) -> Result<(), LoadError> {
    if types.len().checked_add(aliases.len()).is_none_or(|count| count > MAX_DEBUG_TYPES) {
        return Err(malformed("producer graph including UDT aliases exceeds 256 types"));
    }
    for (id, alias) in aliases {
        let target = type_id(alias.target);
        if !types.contains_key(&target) {
            return Err(malformed("UDT alias target is outside the producer data-type graph"));
        }
        if types.contains_key(id) {
            return Err(malformed("UDT alias source identity collides with an existing graph type"));
        }
        types.insert(
            id.clone(),
            DebugType {
                id: id.clone(),
                original_name: Some(alias.name.clone()),
                emitted_name: None,
                byte_size: None,
                alignment: None,
                kind: DebugTypeKind::Typedef { target, constant: false, volatile: false },
                origin: origin(alias.offset, format!("symbols:{}", alias.stream)),
                unsupported: Vec::new(),
            },
        );
    }
    Ok(())
}

fn blank_type(index: u32, kind: DebugTypeKind) -> DebugType {
    DebugType {
        id: type_id(index),
        original_name: None,
        emitted_name: None,
        byte_size: None,
        alignment: None,
        kind,
        origin: origin(u64::from(index), "tpi".to_owned()),
        unsupported: Vec::new(),
    }
}

fn primitive(index: u32) -> DebugType {
    use DebugScalarEncoding::*;
    let code = index & 0xff;
    let (size, encoding, name) = match code {
        0x03 => (None, Void, Some("void")),
        0x08 => (Some(4), Signed, None),
        0x10 | 0x68 => (Some(1), Signed, Some("signed char")),
        0x20 | 0x69 => (Some(1), Unsigned, Some("unsigned char")),
        0x70 => (Some(1), Character, Some("char")),
        0x11 | 0x72 => (Some(2), Signed, Some("short")),
        0x21 | 0x73 => (Some(2), Unsigned, Some("unsigned short")),
        0x12 => (Some(4), Signed, Some("long")),
        0x22 => (Some(4), Unsigned, Some("unsigned long")),
        0x74 => (Some(4), Signed, Some("int")),
        0x75 => (Some(4), Unsigned, Some("unsigned int")),
        0x13 | 0x76 => (Some(8), Signed, Some("long long")),
        0x23 | 0x77 => (Some(8), Unsigned, Some("unsigned long long")),
        0x40 => (Some(4), Float, Some("float")),
        0x41 => (Some(8), Float, Some("double")),
        0x30 => (Some(1), Boolean, Some("_Bool")),
        0x71 | 0x7a => (Some(2), Character, None),
        0x7b => (Some(4), Character, None),
        0x14 | 0x78 => (Some(16), Signed, None),
        0x24 | 0x79 => (Some(16), Unsigned, None),
        0x31 => (Some(2), Boolean, None),
        0x32 => (Some(4), Boolean, None),
        0x33 => (Some(8), Boolean, None),
        0x46 => (Some(2), Float, None),
        0x45 => (Some(4), Float, None),
        0x44 => (Some(6), Float, None),
        0x42 => (Some(10), Float, None),
        0x43 => (Some(16), Float, None),
        0x50 => (Some(8), Unknown, None),
        0x51 => (Some(16), Unknown, None),
        0x52 => (Some(20), Unknown, None),
        0x53 => (Some(32), Unknown, None),
        _ => (None, Unknown, None),
    };
    let mode = (index >> 8) & 15;
    let mut ty = blank_type(
        index,
        if mode == 0 {
            DebugTypeKind::Scalar { encoding, c_name: name.map(str::to_owned) }
        } else {
            DebugTypeKind::Pointer { target: type_id(code) }
        },
    );
    ty.byte_size = if mode == 0 {
        size
    } else {
        match mode {
            1 => Some(2),
            2 | 3 => Some(4),
            4 => Some(4),
            5 => Some(6),
            6 => Some(8),
            7 => Some(16),
            _ => None,
        }
    };
    if name.is_none() || mode != 0 && !matches!(mode, 4 | 6) {
        ty.unsupported.push(format!("primitive TypeIndex {index:#06x} has no supported C representation"));
    }
    ty
}

fn convert_type(
    index: u32,
    raw: &BTreeMap<u32, RawType>,
    forwards: &BTreeMap<u32, u32>,
) -> Result<DebugType, LoadError> {
    let reference = |index| type_id(resolved(index, forwards));
    let mut ty = blank_type(index, DebugTypeKind::Unsupported { description: "unconverted record".to_owned() });
    ty.kind = match &raw[&index] {
        RawType::Aggregate(a) => {
            ty.original_name = (!a.name.is_empty()).then(|| a.name.clone());
            ty.byte_size = a.size;
            ty.unsupported.extend(a.unsupported.clone());
            if a.properties & 0x80 != 0 {
                if let Some(&full) = forwards.get(&index) {
                    DebugTypeKind::Typedef { target: type_id(full), constant: false, volatile: false }
                } else {
                    ty.byte_size = None;
                    ty.unsupported.push("forward type lacks matching producer unique identity/scope proof".to_owned());
                    DebugTypeKind::Unsupported { description: "unresolved aggregate forward".to_owned() }
                }
            } else {
                let (fields, complete) = flatten_fields(raw, a.fields)?;
                if !complete {
                    ty.unsupported.push("field list contains unsupported records; layout is incomplete".to_owned());
                }
                let mut members = Vec::new();
                let mut values = Vec::new();
                for field in fields {
                    match field {
                        Field::Member { name, target, offset, attributes } => {
                            if a.underlying.is_some() {
                                return Err(malformed("enumeration contains a data member"));
                            }
                            let bitfield = match raw.get(target) {
                                Some(RawType::Bitfield { bits, position, .. }) => {
                                    Some(DebugBitfield { bit_size: u64::from(*bits), bit_offset: u64::from(*position) })
                                }
                                _ => None,
                            };
                            let mut unsupported = if bitfield.is_some() {
                                ty.unsupported.push("bitfield layout is preview-only".to_owned());
                                vec!["bitfield layout is preview-only".to_owned()]
                            } else {
                                Vec::new()
                            };
                            if attributes & !3 != 0 || matches!(attributes & 3, 1 | 2) {
                                let reason = "C++/special member attributes are preview-only".to_owned();
                                unsupported.push(reason.clone());
                                ty.unsupported.push(reason);
                            }
                            members.push(DebugMember {
                                name: (!name.is_empty()).then(|| name.clone()),
                                type_id: reference(*target),
                                byte_offset: *offset,
                                bitfield,
                                unsupported,
                            });
                        }
                        Field::Enumerator { name, numeric } => {
                            let underlying =
                                a.underlying.ok_or_else(|| malformed("non-enumeration contains an enumerator"))?;
                            values.push(DebugEnumerator {
                                name: name.clone(),
                                value: enum_number(*numeric, underlying, raw, forwards, 0).to_string(),
                            });
                        }
                        Field::Unsupported(reason) => ty.unsupported.push(reason.clone()),
                    }
                }
                if let Some(underlying) = a.underlying {
                    DebugTypeKind::Enum { underlying: reference(underlying), values }
                } else if a.leaf == 0x1506 {
                    DebugTypeKind::Union { members }
                } else {
                    DebugTypeKind::Struct { members }
                }
            }
        }
        RawType::Pointer { target, attributes } => {
            let declared_size = u64::from((attributes >> 13) & 0x3f);
            let pointer_kind = attributes & 31;
            let size = if declared_size == 0 {
                match pointer_kind {
                    10 => 4,
                    12 => 8,
                    _ => 0,
                }
            } else {
                declared_size
            };
            ty.byte_size = (size > 0).then_some(size);
            if !matches!((pointer_kind, size), (10, 4) | (12, 8)) || attributes & !(0x1f | 0x100 | (0x3f << 13)) != 0 {
                ty.unsupported.push("non-plain, qualified or non-flat pointer is preview-only".to_owned());
            }
            DebugTypeKind::Pointer { target: reference(*target) }
        }
        RawType::Modifier { target, flags } => {
            if flags & !3 != 0 {
                ty.unsupported.push("unaligned/unknown type modifier is preview-only".to_owned());
            }
            DebugTypeKind::Typedef { target: reference(*target), constant: flags & 1 != 0, volatile: flags & 2 != 0 }
        }
        RawType::Alias { target, name } => {
            ty.original_name = Some(name.clone());
            DebugTypeKind::Typedef { target: reference(*target), constant: false, volatile: false }
        }
        RawType::Array { element, size, stride, .. } => {
            ty.byte_size = Some(*size);
            DebugTypeKind::Array { element: reference(*element), count: None, stride: *stride }
        }
        RawType::Function { result, convention, attributes, arguments, .. } => {
            let RawType::Arguments(args) = &raw[arguments] else { return Err(malformed("argument list")) };
            let variadic = args.last() == Some(&0);
            if args.iter().take(args.len().saturating_sub(1)).any(|&arg| arg == 0) {
                return Err(malformed("no-type sentinel before the end of a parameter list"));
            }
            let convention = match convention {
                0 => "cdecl",
                7 => "stdcall",
                4 => "fastcall",
                11 => "thiscall",
                24 => "vectorcall",
                _ => "unsupported",
            }
            .to_owned();
            if !matches!(convention.as_str(), "cdecl" | "stdcall" | "fastcall") || *attributes != 0 {
                ty.unsupported.push("calling convention/function attributes are preview-only".to_owned());
            }
            DebugTypeKind::Function {
                convention,
                return_type: reference(*result),
                variadic,
                parameters: args.iter().filter(|&&arg| arg != 0).map(|&arg| reference(arg)).collect(),
            }
        }
        RawType::Bitfield { target, bits, position } => {
            ty.unsupported.push("bitfield storage descriptor is preview-only".to_owned());
            DebugTypeKind::Bitfield {
                target: reference(*target),
                bit_size: u64::from(*bits),
                bit_offset: u64::from(*position),
            }
        }
        RawType::Unsupported(leaf) => {
            ty.unsupported.push(format!("CodeView leaf {leaf:#06x} is unsupported"));
            DebugTypeKind::Unsupported { description: format!("CodeView leaf {leaf:#06x}") }
        }
        RawType::Arguments(_) | RawType::Fields { .. } => return Err(malformed("list used as a data type")),
    };
    Ok(ty)
}

fn enum_number(
    numeric: Numeric,
    underlying: u32,
    raw: &BTreeMap<u32, RawType>,
    forwards: &BTreeMap<u32, u32>,
    depth: usize,
) -> i128 {
    if depth >= MAX_DEBUG_DEPTH {
        return numeric.value;
    }
    let underlying = resolved(underlying, forwards);
    if underlying >= 0x1000 {
        return match raw.get(&underlying) {
            Some(RawType::Alias { target, .. } | RawType::Modifier { target, .. }) => {
                enum_number(numeric, *target, raw, forwards, depth + 1)
            }
            _ => numeric.value,
        };
    }
    let primitive = primitive(underlying);
    if let (Some(width), Some(bytes), DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Signed, .. }) =
        (numeric.unsigned_width, primitive.byte_size, &primitive.kind)
    {
        // CodeView producers may encode a signed enumerator as an unsigned leaf of the same width.
        // Width/sign evidence is mandatory: never wrap an unsigned enum, or narrow a wider numeric leaf.
        if u64::from(width) == bytes * 8 && numeric.value >= 1i128 << (width - 1) {
            return numeric.value - (1i128 << width);
        }
    }
    numeric.value
}

fn graph_size(
    id: &DebugTypeId,
    types: &BTreeMap<DebugTypeId, DebugType>,
    visiting: &mut BTreeSet<DebugTypeId>,
    work: &mut usize,
) -> Result<Option<u64>, LoadError> {
    graph_work(work)?;
    if visiting.len() >= MAX_DEBUG_DEPTH || !visiting.insert(id.clone()) {
        return Err(malformed("by-value type cycle/depth exceeds limit"));
    }
    let ty = types.get(id).ok_or_else(|| malformed("data-type reference points to a list or absent type"))?;
    let size = match &ty.kind {
        DebugTypeKind::Typedef { target, .. } | DebugTypeKind::Bitfield { target, .. } => {
            graph_size(target, types, visiting, work)?
        }
        DebugTypeKind::Enum { underlying, .. } => graph_size(underlying, types, visiting, work)?,
        DebugTypeKind::Array { element, count, stride } => {
            let element_size = graph_size(element, types, visiting, work)?;
            if let Some(stride) = stride
                && (element_size.is_some_and(|size| *stride < size) || *stride == 0 || *stride > MAX_DEBUG_TYPE_BYTES)
            {
                return Err(malformed("array stride is smaller than the element or outside bounds"));
            }
            if let (Some(count), Some(stride)) = (count, stride) {
                Some(
                    count
                        .checked_mul(*stride)
                        .filter(|&n| n <= MAX_DEBUG_TYPE_BYTES)
                        .ok_or_else(|| malformed("array extent overflow"))?,
                )
            } else {
                ty.byte_size
            }
        }
        DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } => {
            for member in members {
                let size = graph_size(&member.type_id, types, visiting, work)?;
                let zero_width = member.bitfield.as_ref().is_some_and(|bits| bits.bit_size == 0)
                    || matches!(
                        underlying_kind(&member.type_id, types, 0),
                        Some(DebugTypeKind::Bitfield { bit_size: 0, .. })
                    );
                if let Some(size) = size.filter(|_| !zero_width) {
                    let end =
                        member.byte_offset.checked_add(size).ok_or_else(|| malformed("member extent overflow"))?;
                    if ty.byte_size.is_some_and(|extent| end > extent) {
                        return Err(malformed("member extent exceeds producer aggregate size"));
                    }
                }
                if matches!(ty.kind, DebugTypeKind::Union { .. }) && member.byte_offset != 0 {
                    return Err(malformed("union member has nonzero byte offset"));
                }
                if let (Some(bits), Some(size)) = (&member.bitfield, size)
                    && bits.bit_offset.checked_add(bits.bit_size).is_none_or(|end| end > size.saturating_mul(8))
                {
                    return Err(malformed("bitfield extent exceeds its producer storage type"));
                }
            }
            ty.byte_size
        }
        _ => ty.byte_size,
    };
    visiting.remove(id);
    Ok(size)
}

fn walk_depth(
    id: &DebugTypeId,
    types: &BTreeMap<DebugTypeId, DebugType>,
    path: &mut BTreeSet<DebugTypeId>,
    work: &mut usize,
) -> Result<(), LoadError> {
    graph_work(work)?;
    if path.contains(id) {
        return Ok(()); // Pointer/callback recursion is legal; graph_size separately rejects by-value cycles.
    }
    if path.len() >= MAX_DEBUG_DEPTH {
        return Err(malformed("producer graph dependency depth exceeds 32"));
    }
    path.insert(id.clone());
    let ty = types.get(id).ok_or_else(|| malformed("graph reference outside data-type identities"))?;
    for reference in ty.kind.references() {
        walk_depth(reference, types, path, work)?;
    }
    path.remove(id);
    Ok(())
}

fn finish_graph(types: &mut BTreeMap<DebugTypeId, DebugType>) -> Result<(), LoadError> {
    let ids: Vec<_> = types.keys().cloned().collect();
    let mut work = MAX_STRUCTURAL_WORK;
    for id in &ids {
        walk_depth(id, types, &mut BTreeSet::new(), &mut work)?;
        let size = graph_size(id, types, &mut BTreeSet::new(), &mut work)?;
        let array = match &types[id].kind {
            DebugTypeKind::Array { element, stride, .. } => {
                let element_size = graph_size(element, types, &mut BTreeSet::new(), &mut work)?;
                Some((stride.or(element_size), element_size))
            }
            _ => None,
        };
        let ty = types.get_mut(id).ok_or_else(|| malformed("type identity disappeared"))?;
        ty.byte_size = size;
        if let Some((stride, element_size)) = array {
            if let (Some(stride), Some(bytes), Some(_)) = (stride, size, element_size) {
                if stride == 0 || bytes % stride != 0 {
                    return Err(malformed("array byte size is not an exact multiple of its stride"));
                }
                if let DebugTypeKind::Array { count, stride: stored, .. } = &mut ty.kind {
                    *count = Some(bytes / stride);
                    *stored = Some(stride);
                }
            } else {
                ty.unsupported.push("array count/stride lacks a complete element-size witness".to_owned());
            }
        }
    }
    // Check producer object facts before considering prototype eligibility and unsupported dependencies.
    for id in &ids {
        let enum_out_of_range = match &types[id].kind {
            DebugTypeKind::Enum { underlying, values } => !enum_values_fit(underlying, values, types),
            _ => false,
        };
        if enum_out_of_range {
            types
                .get_mut(id)
                .ok_or_else(|| malformed("enum identity"))?
                .unsupported
                .push("enum constants do not fit an exact known underlying signed/unsigned integer range".to_owned());
        }
        let overlapping_members = match &types[id].kind {
            DebugTypeKind::Struct { members } => ordinary_members_overlap(members, types),
            _ => false,
        };
        if overlapping_members {
            types
                .get_mut(id)
                .ok_or_else(|| malformed("record identity"))?
                .unsupported
                .push("ordinary struct member storage extents overlap; layout is preview-only".to_owned());
        }
        let invalid_shape = match &types[id].kind {
            DebugTypeKind::Enum { underlying, .. } => !matches!(
                underlying_kind(underlying, types, 0),
                Some(DebugTypeKind::Scalar {
                    encoding: DebugScalarEncoding::Signed
                        | DebugScalarEncoding::Unsigned
                        | DebugScalarEncoding::Character,
                    ..
                })
            ),
            DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } => {
                members.iter().any(|member| types.get(&member.type_id).is_none_or(|ty| ty.byte_size.is_none()))
            }
            DebugTypeKind::Array { count, .. } => *count == Some(0),
            DebugTypeKind::Function { parameters, .. } => parameters.iter().any(|parameter| {
                matches!(
                    underlying_kind(parameter, types, 0),
                    Some(DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Void, .. })
                )
            }),
            _ => false,
        };
        if invalid_shape {
            types
                .get_mut(id)
                .ok_or_else(|| malformed("shape identity"))?
                .unsupported
                .push("producer shape lacks a complete supported C object/parameter representation".to_owned());
        }
        let aggregate_call = match &types[id].kind {
            DebugTypeKind::Function { parameters, return_type, .. } => {
                parameters.iter().chain(std::iter::once(return_type)).any(|r| !scalar_or_pointer(r, types, 0))
            }
            _ => false,
        };
        if aggregate_call {
            types
                .get_mut(id)
                .ok_or_else(|| malformed("function identity"))?
                .unsupported
                .push("aggregate/unknown by-value calling ABI is preview-only".to_owned());
        }
    }
    // A root is never marked complete if any reachable producer fact is unsupported.
    for _ in 0..types.len() {
        let mut changed = false;
        for id in &ids {
            if !types[id].unsupported.is_empty() {
                continue;
            }
            let unsupported = types[id]
                .kind
                .references()
                .into_iter()
                .any(|r| types.get(r).is_none_or(|ty| !ty.unsupported.is_empty()));
            if unsupported {
                types
                    .get_mut(id)
                    .ok_or_else(|| malformed("dependency identity"))?
                    .unsupported
                    .push("depends on an unsupported/incomplete producer type".to_owned());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

fn graph_work(work: &mut usize) -> Result<(), LoadError> {
    *work = work.checked_sub(1).ok_or_else(|| malformed("type-graph structural work budget exceeded"))?;
    Ok(())
}

fn scalar_or_pointer(id: &DebugTypeId, types: &BTreeMap<DebugTypeId, DebugType>, depth: usize) -> bool {
    if depth >= MAX_DEBUG_DEPTH {
        return false;
    }
    match types.get(id).map(|ty| &ty.kind) {
        Some(DebugTypeKind::Scalar { .. } | DebugTypeKind::Pointer { .. } | DebugTypeKind::Enum { .. }) => true,
        Some(DebugTypeKind::Typedef { target, .. }) => scalar_or_pointer(target, types, depth + 1),
        _ => false,
    }
}

fn underlying_kind<'a>(
    id: &DebugTypeId,
    types: &'a BTreeMap<DebugTypeId, DebugType>,
    depth: usize,
) -> Option<&'a DebugTypeKind> {
    if depth >= MAX_DEBUG_DEPTH {
        return None;
    }
    let kind = &types.get(id)?.kind;
    match kind {
        DebugTypeKind::Typedef { target, .. } => underlying_kind(target, types, depth + 1),
        _ => Some(kind),
    }
}

fn enum_values_fit(
    underlying: &DebugTypeId,
    values: &[DebugEnumerator],
    types: &BTreeMap<DebugTypeId, DebugType>,
) -> bool {
    let Some(DebugTypeKind::Scalar { encoding, .. }) = underlying_kind(underlying, types, 0) else {
        return false;
    };
    if !matches!(encoding, DebugScalarEncoding::Signed | DebugScalarEncoding::Unsigned) {
        return false;
    }
    let Some(bytes @ 1..=16) = types.get(underlying).and_then(|ty| ty.byte_size) else {
        return false;
    };
    let bits = bytes * 8;
    values.iter().all(|value| {
        let text = value.value.as_str();
        let digits = text.strip_prefix('-').unwrap_or(text);
        if text.len() > 40 || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        match encoding {
            DebugScalarEncoding::Signed => text.parse::<i128>().is_ok_and(|number| {
                bits == 128 || (-(1i128 << (bits - 1))..=(1i128 << (bits - 1)) - 1).contains(&number)
            }),
            DebugScalarEncoding::Unsigned => {
                !text.starts_with('-')
                    && text.parse::<u128>().is_ok_and(|number| bits == 128 || number < (1u128 << bits))
            }
            _ => false,
        }
    })
}

fn ordinary_members_overlap(members: &[DebugMember], types: &BTreeMap<DebugTypeId, DebugType>) -> bool {
    let mut extents = Vec::new();
    for member in members {
        if member.bitfield.is_some() || !member.unsupported.is_empty() {
            continue;
        }
        let Some(ty) = types.get(&member.type_id).filter(|ty| ty.unsupported.is_empty()) else { continue };
        // A standalone or aliased bitfield descriptor is never an ordinary object extent.
        if matches!(underlying_kind(&member.type_id, types, 0), Some(DebugTypeKind::Bitfield { .. })) {
            continue;
        }
        let Some(size) = ty.byte_size.filter(|&size| size != 0) else { continue };
        let Some(end) = member.byte_offset.checked_add(size) else { return true };
        extents.push((member.byte_offset, end));
    }
    extents.sort_unstable();
    extents.windows(2).any(|pair| pair[1].0 < pair[0].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(types: Vec<DebugType>) -> BTreeMap<DebugTypeId, DebugType> {
        types.into_iter().map(|ty| (ty.id.clone(), ty)).collect()
    }

    fn udt(target: u32, name: &str) -> Vec<u8> {
        let mut record = vec![0; 2];
        record.extend_from_slice(&0x1108u16.to_le_bytes());
        record.extend_from_slice(&target.to_le_bytes());
        record.extend_from_slice(name.as_bytes());
        record.push(0);
        let length = u16::try_from(record.len() - 2).unwrap();
        record[..2].copy_from_slice(&length.to_le_bytes());
        record
    }

    #[test]
    fn explicit_udt_primitive_aliases_keep_source_identity_and_never_overwrite_type_facts() {
        let first = udt(0x74, "Word");
        let second = udt(0x75, "Word");
        let bytes = [first.as_slice(), second.as_slice()].concat();
        let mut symbols = ProcedureRefs { procedures: Vec::new(), aliases: BTreeMap::new() };
        collect_refs(&bytes, 7, 4, &[], &mut symbols).unwrap();
        // Repeated reads of the same source records are idempotent, not new facts or overwrites.
        collect_refs(&bytes, 7, 4, &[], &mut symbols).unwrap();
        assert_eq!(symbols.aliases.len(), 2);
        let int = primitive(0x74);
        let uint = primitive(0x75);
        let mut types = graph(vec![int.clone(), uint.clone()]);
        insert_symbol_aliases(&mut types, &symbols.aliases).unwrap();
        finish_graph(&mut types).unwrap();
        assert_eq!(types[&int.id], int);
        assert_eq!(types[&uint.id], uint);
        for (offset, target) in [(4, 0x74), (4 + first.len() as u64, 0x75)] {
            let alias = &types[&symbol_type_id(7, offset)];
            assert_eq!(alias.original_name.as_deref(), Some("Word"));
            assert_eq!(alias.byte_size, Some(4));
            assert_eq!(alias.alignment, None);
            assert_eq!(alias.origin, origin(offset, "symbols:7".to_owned()));
            assert!(matches!(&alias.kind, DebugTypeKind::Typedef { target: actual, .. } if actual == &type_id(target)));
            assert!(alias.unsupported.is_empty());
        }
        let error = collect_refs(&udt(0x75, "Word"), 7, 4, &[], &mut symbols).unwrap_err();
        assert!(error.to_string().contains("conflicting UDT alias"), "{error}");
        assert_eq!(symbols.aliases[&symbol_type_id(7, 4)].target, 0x74);
        let collision = BTreeMap::from([(
            int.id.clone(),
            SymbolAlias { target: 0x75, name: "Overwrite".to_owned(), stream: 7, offset: 4 },
        )]);
        assert!(insert_symbol_aliases(&mut types, &collision).is_err());
        assert_eq!(types[&int.id], int);
    }

    #[test]
    fn explicit_udt_aliases_cannot_complete_a_forward_or_reference_an_absent_type() {
        let mut forward =
            blank_type(0x1000, DebugTypeKind::Unsupported { description: "unresolved forward".to_owned() });
        forward.original_name = Some("Tag".to_owned());
        forward.unsupported.push("forward lacks producer scope/unique identity".to_owned());
        let mut full = blank_type(0x1001, DebugTypeKind::Struct { members: Vec::new() });
        full.original_name = Some("Tag".to_owned());
        full.byte_size = Some(0);
        let mut types = graph(vec![forward, full]);
        let id = symbol_type_id(7, 0);
        let aliases = BTreeMap::from([(
            id.clone(),
            SymbolAlias { target: 0x1000, name: "Tag".to_owned(), stream: 7, offset: 0 },
        )]);
        insert_symbol_aliases(&mut types, &aliases).unwrap();
        finish_graph(&mut types).unwrap();
        assert_eq!(types[&id].byte_size, None);
        assert!(!types[&id].unsupported.is_empty());
        assert!(matches!(&types[&id].kind, DebugTypeKind::Typedef { target, .. } if target == &type_id(0x1000)));
        let absent = BTreeMap::from([(
            symbol_type_id(7, 32),
            SymbolAlias { target: 0xffff_ffff, name: "Absent".to_owned(), stream: 7, offset: 32 },
        )]);
        assert!(insert_symbol_aliases(&mut types, &absent).is_err());
    }

    #[test]
    fn udt_names_records_and_total_graph_types_are_bounded() {
        let mut symbols = ProcedureRefs { procedures: Vec::new(), aliases: BTreeMap::new() };
        let bytes = udt(0x74, &"x".repeat(MAX_NAME_BYTES + 1));
        assert!(collect_refs(&bytes, 7, 0, &[], &mut symbols).is_err());
        let bytes: Vec<_> = (0..=MAX_DEBUG_TYPES).flat_map(|_| udt(0x74, "Word")).collect();
        assert!(collect_refs(&bytes, 7, 0, &[], &mut symbols).is_err());
        assert_eq!(symbols.aliases.len(), MAX_DEBUG_TYPES);
        let mut types = graph(vec![primitive(0x74)]);
        let error = insert_symbol_aliases(&mut types, &symbols.aliases).unwrap_err();
        assert!(error.to_string().contains("exceeds 256 types"), "{error}");
    }

    #[test]
    fn array_extent_and_dependency_depth_are_checked_without_native_layouts() {
        for (size, stride) in [(7, None), (8, Some(2)), (8, Some(0)), (8, Some(u64::MAX))] {
            let mut array = blank_type(0x1000, DebugTypeKind::Array { element: type_id(0x74), count: None, stride });
            array.byte_size = Some(size);
            assert!(finish_graph(&mut graph(vec![primitive(0x74), array])).is_err());
        }
        let mut types = vec![primitive(0x74)];
        for index in 0..MAX_DEBUG_DEPTH as u32 {
            types.push(blank_type(
                0x1000 + index,
                DebugTypeKind::Typedef {
                    target: if index == 0 { type_id(0x74) } else { type_id(0xfff + index) },
                    constant: false,
                    volatile: false,
                },
            ));
        }
        let error = finish_graph(&mut graph(types)).unwrap_err();
        assert!(error.to_string().contains("depth"), "{error}");
    }

    #[test]
    fn legal_self_pointers_do_not_hide_illegal_by_value_cycles() {
        let mut record = blank_type(
            0x1000,
            DebugTypeKind::Struct {
                members: vec![DebugMember {
                    name: Some("next".to_owned()),
                    type_id: type_id(0x1001),
                    byte_offset: 0,
                    bitfield: None,
                    unsupported: Vec::new(),
                }],
            },
        );
        record.byte_size = Some(8);
        let mut pointer = blank_type(0x1001, DebugTypeKind::Pointer { target: record.id.clone() });
        pointer.byte_size = Some(8);
        let mut types = graph(vec![record.clone(), pointer]);
        finish_graph(&mut types).unwrap();
        assert!(types.values().all(|ty| ty.unsupported.is_empty()));
        let DebugTypeKind::Struct { members } = &mut record.kind else { panic!("struct") };
        members[0].type_id = record.id.clone();
        assert!(finish_graph(&mut graph(vec![record])).is_err());
    }

    #[test]
    fn unsupported_bitfield_facts_propagate_through_pointer_prototypes_to_roots() {
        let mut bits = blank_type(
            0x1000,
            DebugTypeKind::Struct {
                members: vec![DebugMember {
                    name: Some("active".to_owned()),
                    type_id: type_id(0x75),
                    byte_offset: 0,
                    bitfield: Some(DebugBitfield { bit_size: 1, bit_offset: 0 }),
                    unsupported: vec!["bitfield preview-only".to_owned()],
                }],
            },
        );
        bits.byte_size = Some(4);
        bits.unsupported.push("bitfield preview-only".to_owned());
        let mut pointer = blank_type(0x1001, DebugTypeKind::Pointer { target: bits.id.clone() });
        pointer.byte_size = Some(8);
        let function = blank_type(
            0x1002,
            DebugTypeKind::Function {
                convention: "cdecl".to_owned(),
                parameters: vec![pointer.id.clone()],
                return_type: type_id(0x74),
                variadic: false,
            },
        );
        let mut types = graph(vec![primitive(0x74), primitive(0x75), bits, pointer, function]);
        finish_graph(&mut types).unwrap();
        for index in [0x1000, 0x1001, 0x1002] {
            assert!(!types[&type_id(index)].unsupported.is_empty());
        }
        let DebugTypeKind::Struct { members } = &types[&type_id(0x1000)].kind else { panic!("struct") };
        assert_eq!(members[0].bitfield.as_ref().unwrap().bit_size, 1);
    }

    #[test]
    fn a_display_name_alone_cannot_resolve_a_forward_type() {
        let aggregate = |properties| Aggregate {
            leaf: 0x1505,
            count: 0,
            properties,
            fields: 0,
            size: Some(0),
            name: "Tag".to_owned(),
            unique: None,
            underlying: None,
            unsupported: Vec::new(),
        };
        let raw =
            BTreeMap::from([(0x1000, RawType::Aggregate(aggregate(0x80))), (0x1001, RawType::Aggregate(aggregate(0)))]);
        assert!(forward_resolutions(&raw).is_empty());
        let mut raw = raw;
        let RawType::Aggregate(forward) = raw.get_mut(&0x1000).unwrap() else { panic!("forward") };
        forward.unique = Some(".?AUTag@@".to_owned());
        assert!(forward_resolutions(&raw).is_empty());
        let RawType::Aggregate(full) = raw.get_mut(&0x1001).unwrap() else { panic!("complete") };
        full.unique = Some(".?AUTag@@".to_owned());
        assert_eq!(forward_resolutions(&raw).get(&0x1000), Some(&0x1001));
    }

    #[test]
    fn a_complete_file_scope_tag_cannot_complete_a_same_cu_block_scope_forward() {
        // One C CU may contain f(){ struct Tag; struct Tag *p; } and a different file-scope Tag definition.
        // S_UDT naming that definition says nothing about the scope/identity of the block's forward record.
        let raw = BTreeMap::from([
            (
                0x1000,
                RawType::Aggregate(Aggregate {
                    leaf: 0x1505,
                    count: 0,
                    properties: 0x80,
                    fields: 0,
                    size: Some(0),
                    name: "Tag".to_owned(),
                    unique: None,
                    underlying: None,
                    unsupported: Vec::new(),
                }),
            ),
            (
                0x1001,
                RawType::Aggregate(Aggregate {
                    leaf: 0x1505,
                    count: 1,
                    properties: 0,
                    fields: 0x1003,
                    size: Some(4),
                    name: "Tag".to_owned(),
                    unique: None,
                    underlying: None,
                    unsupported: Vec::new(),
                }),
            ),
            (0x1002, RawType::Pointer { target: 0x1000, attributes: 0x1000c }),
            (
                0x1003,
                RawType::Fields {
                    fields: vec![Field::Member { name: "n".to_owned(), target: 0x74, offset: 0, attributes: 3 }],
                    continuation: None,
                    complete: true,
                },
            ),
        ]);
        let forwards = forward_resolutions(&raw);
        assert!(forwards.is_empty());
        let mut types = graph(vec![
            primitive(0x74),
            convert_type(0x1000, &raw, &forwards).unwrap(),
            convert_type(0x1001, &raw, &forwards).unwrap(),
            convert_type(0x1002, &raw, &forwards).unwrap(),
        ]);
        finish_graph(&mut types).unwrap();
        assert!(!types[&type_id(0x1000)].unsupported.is_empty());
        assert!(!types[&type_id(0x1002)].unsupported.is_empty());
        assert!(types[&type_id(0x1001)].unsupported.is_empty());
        assert!(matches!(&types[&type_id(0x1002)].kind,
            DebugTypeKind::Pointer { target } if target == &type_id(0x1000)));
    }

    #[test]
    fn producer_conventions_use_consumer_supported_aliases() {
        for (convention, expected) in [(0, "cdecl"), (7, "stdcall"), (4, "fastcall")] {
            let raw = BTreeMap::from([
                (0x1000, RawType::Function { result: 0x74, convention, attributes: 0, count: 0, arguments: 0x1001 }),
                (0x1001, RawType::Arguments(Vec::new())),
            ]);
            let ty = convert_type(0x1000, &raw, &BTreeMap::new()).unwrap();
            assert!(ty.unsupported.is_empty());
            assert!(matches!(&ty.kind, DebugTypeKind::Function { convention, .. } if convention == expected));
        }
    }

    #[test]
    fn enum_values_must_fit_the_exact_underlying_signedness_and_width() {
        for (index, values, supported) in [
            (0x20, vec!["0", "255"], true),
            (0x20, vec!["-1"], false),
            (0x20, vec!["256"], false),
            (0x68, vec!["-128", "127"], true),
            (0x68, vec!["-129"], false),
            (0x68, vec!["128"], false),
            (0x77, vec!["18446744073709551615"], true),
            (0x77, vec!["18446744073709551616"], false),
            (0x74, vec!["1.0"], false),
        ] {
            let enumeration = blank_type(
                0x1000,
                DebugTypeKind::Enum {
                    underlying: type_id(index),
                    values: values
                        .into_iter()
                        .enumerate()
                        .map(|(i, value)| DebugEnumerator { name: format!("v{i}"), value: value.to_owned() })
                        .collect(),
                },
            );
            let mut types = graph(vec![primitive(index), enumeration]);
            finish_graph(&mut types).unwrap();
            assert_eq!(types[&type_id(0x1000)].unsupported.is_empty(), supported);
        }
        let values = vec![DebugEnumerator { name: "huge".to_owned(), value: "9".repeat(4096) }];
        assert!(!enum_values_fit(&type_id(0x74), &values, &graph(vec![primitive(0x74)])));
    }

    #[test]
    fn enum_numeric_leaf_width_and_sign_control_contextual_bit_pattern_interpretation() {
        let cases = [
            (vec![4, 0x80, 0xfd, 0xff, 0xff, 0xff], 0x74, "-3", true),
            (vec![4, 0x80, 0xfd, 0xff, 0xff, 0xff], 0x75, "4294967293", true),
            (vec![4, 0x80, 0xff, 0xff, 0xff, 0x7f], 0x74, "2147483647", true),
            (vec![4, 0x80, 0, 0, 0, 0x80], 0x74, "-2147483648", true),
            (vec![4, 0x80, 0xfd, 0xff, 0xff, 0xff], 0x11, "4294967293", false),
            (vec![0x0a, 0x80, 0xfd, 0xff, 0xff, 0xff, 0, 0, 0, 0], 0x74, "4294967293", false),
            (vec![0x09, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0], 0x74, "2147483648", false),
            (vec![0, 1], 0x20, "256", false),
            (vec![0, 0x80, 0xff], 0x20, "-1", false),
        ];
        for (bytes, underlying, expected, supported) in cases {
            let numeric = Cursor::new(&bytes).numeric().unwrap();
            let value = enum_number(numeric, underlying, &BTreeMap::new(), &BTreeMap::new(), 0).to_string();
            assert_eq!(value, expected, "underlying {underlying:#x}, raw {bytes:02x?}");
            let values = vec![DebugEnumerator { name: "value".to_owned(), value }];
            assert_eq!(enum_values_fit(&type_id(underlying), &values, &graph(vec![primitive(underlying)])), supported);
        }
    }

    #[test]
    fn ordinary_struct_overlap_is_preview_only_but_union_storage_and_bitfields_are_not_misclassified() {
        for (is_union, bitfield, expected_overlap) in [(false, false, true), (true, false, false), (false, true, false)]
        {
            let members = (0..2)
                .map(|i| DebugMember {
                    name: Some(format!("m{i}")),
                    type_id: type_id(0x74),
                    byte_offset: if bitfield { 4 } else { 0 },
                    bitfield: bitfield.then_some(DebugBitfield { bit_size: 0, bit_offset: 0 }),
                    unsupported: if bitfield { vec!["bitfield preview-only".to_owned()] } else { Vec::new() },
                })
                .collect();
            let mut record = blank_type(
                0x1000,
                if is_union { DebugTypeKind::Union { members } } else { DebugTypeKind::Struct { members } },
            );
            record.byte_size = Some(4);
            if bitfield {
                record.unsupported.push("bitfield preview-only".to_owned());
            }
            let mut types = graph(vec![primitive(0x74), record]);
            finish_graph(&mut types).unwrap();
            assert_eq!(types[&type_id(0x1000)].unsupported.iter().any(|r| r.contains("overlap")), expected_overlap);
        }
    }

    #[test]
    fn orphan_and_indirect_bitfield_descriptors_retain_structured_width_and_position() {
        let raw = BTreeMap::from([
            (0x1000, RawType::Bitfield { target: 0x75, bits: 3, position: 5 }),
            (0x1001, RawType::Alias { target: 0x1000, name: "IndirectBits".to_owned() }),
        ]);
        let bitfield = convert_type(0x1000, &raw, &BTreeMap::new()).unwrap();
        let value = serde_json::to_value(&bitfield).unwrap();
        assert_eq!(value["kind"]["kind"], "bitfield");
        assert_eq!(value["kind"]["bit_size"], 3);
        assert_eq!(value["kind"]["bit_offset"], 5);
        assert_eq!(serde_json::from_value::<DebugType>(value).unwrap(), bitfield);
        let mut orphan = graph(vec![primitive(0x75), bitfield.clone()]);
        finish_graph(&mut orphan).unwrap();
        assert_eq!(orphan[&type_id(0x1000)].kind, bitfield.kind);
        assert!(!orphan[&type_id(0x1000)].unsupported.is_empty());
        let mut types = graph(vec![primitive(0x75), bitfield, convert_type(0x1001, &raw, &BTreeMap::new()).unwrap()]);
        finish_graph(&mut types).unwrap();
        assert!(!types[&type_id(0x1001)].unsupported.is_empty());
        assert_eq!(types[&type_id(0x1000)].kind.references(), vec![&type_id(0x75)]);
    }
}
