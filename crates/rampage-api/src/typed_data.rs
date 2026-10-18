use std::collections::{BTreeMap, BTreeSet};

use rampage_decompiler::worker::WorkerOperation;
use rampage_decompiler::{NamedType, NamedTypeKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::annotations::{Annotations, DataTypeAnnotation, Field, encode_data_type, parse_data_type};
use crate::{ApiError, DataInspection, DataQuery, DataStatus, Project};

pub use crate::annotations::DataStringEncoding;

pub const MAX_TYPED_DATA_RESULT_BYTES: usize = 60_000;
const MAX_BINDING_BYTES: u64 = 1024 * 1024;
const MAX_NODES: usize = 256;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyDataTypeRequest {
    pub type_name: Option<String>,
    pub count: Option<u32>,
    pub encoding: Option<DataStringEncoding>,
    pub byte_length: Option<u32>,
    #[serde(default)]
    pub clear: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TypedDataQuery {
    pub address: u64,
    pub size: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DataTypeEdit {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub changed: bool,
    pub binding: Option<DataTypeAnnotation>,
    pub native_declaration: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TypedDataReport {
    pub raw: DataInspection,
    pub objects: Vec<TypedDataObject>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct TypedDataObject {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub binding: DataTypeAnnotation,
    pub name: String,
    pub fields: Vec<TypedDataField>,
}

#[derive(Debug, Serialize)]
pub struct TypedDataField {
    pub path: String,
    pub type_name: String,
    pub offset: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    pub status: String,
    pub raw_hex: Option<String>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub raw_address: Option<u64>,
    pub raw_size: usize,
    pub value: Option<Value>,
    pub union_candidate: bool,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn checked_end(address: u64, size: u64) -> Result<u64, ApiError> {
    address.checked_add(size).ok_or_else(|| invalid("typed data range overflows the address space"))
}

fn bindings(annotations: &Annotations) -> Result<Vec<(u64, DataTypeAnnotation)>, ApiError> {
    annotations
        .data_types()
        .iter()
        .map(|(&address, text)| parse_data_type(text).map(|binding| (address, binding)).map_err(invalid))
        .collect()
}

fn named<'a>(types: &'a [NamedType], name: &str) -> Result<&'a NamedType, ApiError> {
    types.iter().find(|ty| ty.name == name).ok_or_else(|| invalid(format!("missing native data type {name:?}")))
}

fn type_size(ty: &NamedType) -> Result<u64, ApiError> {
    ty.size
        .filter(|&size| size > 0 && size <= MAX_BINDING_BYTES)
        .filter(|_| !ty.incomplete && !matches!(ty.kind, NamedTypeKind::Void | NamedTypeKind::Function))
        .ok_or_else(|| invalid(format!("type {:?} has no supported complete native data layout", ty.name)))
}

fn valid_label(name: &str) -> bool {
    rampage_decompiler::validate_local_name(name).is_ok()
}

fn label(project: &Project, annotations: &Annotations, address: u64) -> String {
    project
        .inventory_function_name_in(annotations, address)
        .filter(|name| valid_label(name))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("data_{address:x}"))
}

fn declaration(project: &Project, annotations: &Annotations, address: u64, binding: &DataTypeAnnotation) -> String {
    let name = label(project, annotations, address);
    match &binding.type_name {
        Some(ty) if binding.count == 1 => format!("{ty} {name};"),
        Some(ty) => format!("{ty} {name}[{}];", binding.count),
        None => format!("char {name}[{}];", binding.byte_length),
    }
}

fn validate_extent(project: &Project, address: u64, length: u32) -> Result<(), ApiError> {
    let end = checked_end(address, u64::from(length))?;
    if project.binary.arch.pointer_size() == 4 && end > 0x1_0000_0000 {
        return Err(invalid("typed data range exceeds the target address space"));
    }
    let mut at = address;
    while at < end {
        let mut segments = project.binary.segments.iter().filter(|segment| segment.contains(at));
        let segment = segments.next().ok_or_else(|| invalid("typed data range contains unmapped bytes"))?;
        if segments.next().is_some() || !segment.perms.read {
            return Err(invalid("typed data requires unambiguous readable non-code mappings"));
        }
        let next = checked_end(segment.address, segment.size)?.min(end);
        if project.binary.is_code(at) {
            return Err(invalid("typed data range overlaps code"));
        }
        for section in
            project.binary.sections.iter().filter(|section| section.kind == rampage_loaders::SectionKind::Code)
        {
            let section_end = checked_end(section.address, section.size)?;
            if section.address < next && section_end > at {
                return Err(invalid("typed data range overlaps code"));
            }
        }
        if project.binary.segments.iter().any(|other| other.address > at && other.address < next && other.size > 0) {
            return Err(invalid("typed data range has overlapping mappings"));
        }
        at = next;
    }
    Ok(())
}

/// Native replay parses declarations and rejects manual global overlaps; bytes are never changed.
pub(crate) fn data_type_plan(project: &Project, annotations: &Annotations) -> Result<Vec<WorkerOperation>, ApiError> {
    let mut operations = Vec::new();
    let mut previous_end = 0;
    let mut labels = BTreeSet::new();
    for (address, binding) in bindings(annotations)? {
        validate_extent(project, address, binding.byte_length)?;
        if address < previous_end {
            return Err(invalid("data type bindings overlap"));
        }
        previous_end = checked_end(address, u64::from(binding.byte_length))?;
        if annotations.globals().contains_key(&address) {
            return Err(invalid("data type binding conflicts with a manual global"));
        }
        let name = label(project, annotations, address);
        if !labels.insert(name.clone())
            || project.address_named(annotations, &name).is_some_and(|other| other != address)
        {
            return Err(invalid(format!("generated data label {name:?} conflicts with another address")));
        }
        operations.push(WorkerOperation::Global {
            address,
            declaration: declaration(project, annotations, address, &binding),
        });
    }
    Ok(operations)
}

pub(crate) fn validate_bindings(
    project: &Project,
    annotations: &Annotations,
    types: &[NamedType],
) -> Result<(), ApiError> {
    data_type_plan(project, annotations)?;
    for (_, binding) in bindings(annotations)? {
        if let Some(name) = &binding.type_name {
            let length = type_size(named(types, name)?)?
                .checked_mul(u64::from(binding.count))
                .ok_or_else(|| invalid("native data type extent overflows"))?;
            if length != u64::from(binding.byte_length) {
                return Err(invalid(format!("native type {name:?} changed the fixed data binding byte extent")));
            }
        }
    }
    Ok(())
}

pub(crate) fn binding_names(annotations: &Annotations) -> Result<Vec<String>, ApiError> {
    let names: BTreeSet<_> = bindings(annotations)?.into_iter().filter_map(|(_, binding)| binding.type_name).collect();
    if names.len() > 64 {
        return Err(invalid("native data binding type budget exceeds 64 names"));
    }
    Ok(names.into_iter().collect())
}

pub(crate) fn identity_references(
    value: &Value,
    names: &mut BTreeSet<String>,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ApiError> {
    if depth > 32 {
        return Err(invalid("native data identity depth budget exceeded"));
    }
    if value.get("kind").is_some() || value.get("reference").is_some() {
        *nodes += 1;
        if *nodes > MAX_NODES {
            return Err(invalid("native data identity graph exceeds 256 nodes"));
        }
    }
    if let Some(name) = value.get("reference").and_then(Value::as_str) {
        names.insert(name.to_owned());
    }
    if matches!(value.get("kind").and_then(Value::as_u64), Some(8 | 9)) {
        return Ok(());
    }
    if let Some(object) = value.as_object() {
        for child in object.values().filter(|child| child.is_object() || child.is_array()) {
            identity_references(child, names, depth + 1, nodes)?;
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            identity_references(child, names, depth + 1, nodes)?;
        }
    }
    if names.len() > 64 {
        return Err(invalid("native data type query budget exceeds 64 names"));
    }
    Ok(())
}

impl Project {
    pub fn apply_data_type(&self, address: u64, request: &ApplyDataTypeRequest) -> Result<DataTypeEdit, ApiError> {
        self.apply_data_type_with_preflight(address, request, |_| Ok(()))
    }

    pub fn apply_data_type_with_preflight(
        &self,
        address: u64,
        request: &ApplyDataTypeRequest,
        preflight: impl FnOnce(&DataTypeEdit) -> Result<(), ApiError>,
    ) -> Result<DataTypeEdit, ApiError> {
        if request.clear {
            if request.type_name.is_some()
                || request.encoding.is_some()
                || request.count.is_some()
                || request.byte_length.is_some()
            {
                return Err(invalid("clear cannot be combined with a data type assignment"));
            }
        } else if request.type_name.is_some() == request.encoding.is_some() {
            return Err(invalid("provide exactly one named type or explicit string encoding"));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            self.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
            let binding = if request.clear {
                None
            } else {
                let count = request.count.unwrap_or(1);
                let byte_length = match &request.type_name {
                    Some(name) => {
                        encode_data_type(&DataTypeAnnotation {
                            type_name: Some(name.clone()),
                            count,
                            byte_length: 1,
                            encoding: None,
                        })
                        .map_err(invalid)?;
                        let types =
                            self.native_data_types(&state, &options, annotations, std::slice::from_ref(name))?;
                        let length = type_size(named(&types, name)?)?
                            .checked_mul(u64::from(count))
                            .filter(|&size| size <= MAX_BINDING_BYTES)
                            .ok_or_else(|| invalid("data binding exceeds 1 MiB"))?
                            as u32;
                        if request.byte_length.is_some_and(|expected| expected != length) {
                            return Err(invalid("byte_length must equal native sizeof(type) multiplied by count"));
                        }
                        length
                    }
                    None => {
                        request.byte_length.ok_or_else(|| invalid("encoded strings require an explicit byte_length"))?
                    }
                };
                Some(DataTypeAnnotation {
                    type_name: request.type_name.clone(),
                    count,
                    byte_length,
                    encoding: request.encoding,
                })
            };
            let value = binding.as_ref().map(encode_data_type).transpose().map_err(invalid)?;
            let mut result = DataTypeEdit {
                address,
                changed: annotations.data_types().get(&address) != value.as_ref(),
                native_declaration: binding.as_ref().map(|binding| declaration(self, annotations, address, binding)),
                binding,
                warnings: Vec::new(),
            };
            if !result.changed {
                self.validate_annotation_snapshot(&state, &options, annotations).map_err(invalid)?;
                check_result(&result)?;
                preflight(&result)?;
                return Ok(result);
            }
            let mut preflight = Some(preflight);
            result.changed = annotations
                .set_validated(Field::DataType, address, value, |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)?;
                    self.binary.validate_available_backing_source().map_err(|error| error.to_string())?;
                    check_result(&result).map_err(|error| error.to_string())?;
                    preflight.take().expect("single data type response preflight")(&result)
                        .map_err(|error| error.to_string())
                })
                .map_err(invalid)?;
            Ok(result)
        })
    }

    pub fn read_data(&self, query: &TypedDataQuery) -> Result<TypedDataReport, ApiError> {
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let annotations = self.read_annotations_lock().read().expect("annotations lock").checked_read_snapshot()?;
        let bindings = bindings(&annotations)?;
        let containing = bindings.iter().find(|(address, binding)| {
            *address <= query.address && query.address - *address < u64::from(binding.byte_length)
        });
        let size = query.size.unwrap_or_else(|| {
            containing.map_or(64, |(address, binding)| {
                (u64::from(binding.byte_length) - (query.address - *address)).min(crate::MAX_DATA_BYTES as u64) as usize
            })
        });
        let end = checked_end(query.address, size as u64)?;
        let raw = crate::data::inspect_static_data(
            &self.binary,
            &DataQuery { address: query.address, size, word_size: None },
        )?;
        let names = binding_names(&annotations)?;
        let types = if bindings.is_empty() {
            Vec::new()
        } else {
            self.native_data_types(&state, &options, &annotations, &names)?
        };
        validate_bindings(self, &annotations, &types)?;
        let bytes = window_bytes(&raw)?;
        let mut decoder = Decoder { types: &types, raw: &raw, bytes, big_endian: self.binary.big_endian, nodes: 0 };
        let mut objects = Vec::new();
        for (address, binding) in bindings {
            if address >= end || checked_end(address, u64::from(binding.byte_length))? <= query.address {
                continue;
            }
            let name = label(self, &annotations, address);
            let mut fields = Vec::new();
            if let Some(encoding) = binding.encoding {
                let mut field = decoder.field(
                    &name,
                    "explicit_encoded_string",
                    address,
                    address,
                    u64::from(binding.byte_length),
                    false,
                )?;
                if field.status == "stored" {
                    let bytes =
                        decoder.complete_bytes(address, u64::from(binding.byte_length)).expect("stored field bytes");
                    match decode_string(&bytes, encoding) {
                        Ok(text) => field.value = Some(json!({"encoding": encoding, "text": text})),
                        Err(reason) => {
                            field.status = "invalid_encoding".to_owned();
                            field.value = Some(json!({"encoding": encoding, "error": reason}));
                        }
                    }
                }
                fields.push(field);
            } else if let Some(type_name) = &binding.type_name {
                let size = type_size(named(&types, type_name)?)?;
                for index in 0..u64::from(binding.count) {
                    let at =
                        checked_end(address, index.checked_mul(size).ok_or_else(|| invalid("array offset overflow"))?)?;
                    let path = if binding.count == 1 { name.clone() } else { format!("{name}[{index}]") };
                    decoder.decode_named(
                        DecodeSite { path: &path, base: address, address: at, union: false, depth: 0 },
                        type_name,
                        &mut fields,
                    )?;
                }
            }
            objects.push(TypedDataObject { address, binding, name, fields });
        }
        let report = TypedDataReport {
            raw,
            objects,
            limitations: vec![
                "Analyst-assigned layouts are interpretations, not producer type or execution evidence.",
                "Only stored bytes in the explicit byte window are decoded; partial and zero-fill fields are not values.",
                "Pointers remain raw addresses, never dereferenced. Union fields are candidates, not an active-member claim.",
                "Character arrays are not Unicode strings without explicit encoding. Unsupported shapes retain raw bytes.",
            ],
        };
        check_result(&report)?;
        Ok(report)
    }
}

fn check_result(result: &impl Serialize) -> Result<(), ApiError> {
    if serde_json::to_vec(result).map_err(|error| invalid(error.to_string()))?.len() > MAX_TYPED_DATA_RESULT_BYTES {
        return Err(invalid("typed data result exceeds 60000 bytes; request a smaller byte window"));
    }
    Ok(())
}

fn window_bytes(raw: &DataInspection) -> Result<BTreeMap<u64, u8>, ApiError> {
    let mut bytes = BTreeMap::new();
    for span in &raw.spans {
        if span.status != DataStatus::Stored {
            continue;
        }
        let text = span.hex.as_deref().ok_or_else(|| invalid("stored span omitted bytes"))?;
        for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let text = std::str::from_utf8(pair).map_err(|error| invalid(error.to_string()))?;
            let byte = u8::from_str_radix(text, 16).map_err(|error| invalid(error.to_string()))?;
            bytes.insert(checked_end(span.address, index as u64)?, byte);
        }
    }
    Ok(bytes)
}

fn decode_string(bytes: &[u8], encoding: DataStringEncoding) -> Result<String, &'static str> {
    match encoding {
        DataStringEncoding::Utf8 => std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| "invalid UTF-8"),
        DataStringEncoding::Ascii => {
            if !bytes.is_ascii() {
                return Err("invalid ASCII");
            }
            Ok(bytes.iter().map(|&byte| char::from(byte)).collect())
        }
        DataStringEncoding::Utf16Le | DataStringEncoding::Utf16Be => {
            if !bytes.len().is_multiple_of(2) {
                return Err("UTF-16 has an incomplete code unit");
            }
            let units = bytes.as_chunks::<2>().0.iter().map(|pair| {
                if encoding == DataStringEncoding::Utf16Be {
                    u16::from_be_bytes([pair[0], pair[1]])
                } else {
                    u16::from_le_bytes([pair[0], pair[1]])
                }
            });
            char::decode_utf16(units).collect::<Result<String, _>>().map_err(|_| "UTF-16 has an unpaired surrogate")
        }
    }
}

struct Decoder<'a> {
    types: &'a [NamedType],
    raw: &'a DataInspection,
    bytes: BTreeMap<u64, u8>,
    big_endian: bool,
    nodes: usize,
}

#[derive(Clone, Copy)]
struct DecodeSite<'a> {
    path: &'a str,
    base: u64,
    address: u64,
    union: bool,
    depth: usize,
}

impl Decoder<'_> {
    fn complete_bytes(&self, address: u64, size: u64) -> Option<Vec<u8>> {
        let end = address.checked_add(size)?;
        if address < self.raw.address || end > self.raw.address + self.raw.size as u64 {
            return None;
        }
        (address..end).map(|at| self.bytes.get(&at).copied()).collect()
    }

    fn field(
        &mut self,
        path: &str,
        type_name: &str,
        base: u64,
        address: u64,
        size: u64,
        union_candidate: bool,
    ) -> Result<TypedDataField, ApiError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(invalid("typed data exceeds 256 decoded nodes; request a smaller byte window"));
        }
        let end = checked_end(address, size)?;
        let start = address.max(self.raw.address);
        let stop = end.min(self.raw.address + self.raw.size as u64);
        let stored: Vec<_> = (start..stop).filter_map(|at| self.bytes.get(&at).copied()).collect();
        let whole = start == address && stop == end;
        let status = if !whole {
            "partial"
        } else if stored.len() as u64 == size {
            "stored"
        } else {
            let mut statuses = self
                .raw
                .spans
                .iter()
                .filter(|span| span.address < end && span.address + span.size as u64 > address)
                .map(|span| span.status);
            match statuses.next().filter(|first| statuses.all(|status| status == *first)) {
                Some(DataStatus::ZeroFill) => "zero_fill",
                Some(DataStatus::Unmapped) => "unmapped",
                Some(DataStatus::Unreadable) => "unreadable",
                _ => "unavailable",
            }
        };
        let contiguous = stored.len() as u64 == stop.saturating_sub(start) && !stored.is_empty();
        let raw_hex = if contiguous { Some(rampage_arch::hex::bytes(&stored)) } else { None };
        Ok(TypedDataField {
            path: path.to_owned(),
            type_name: type_name.to_owned(),
            offset: address - base,
            address,
            size,
            status: status.to_owned(),
            raw_hex,
            raw_address: contiguous.then_some(start),
            raw_size: if contiguous { stored.len() } else { 0 },
            value: None,
            union_candidate,
        })
    }

    fn intersects(&self, address: u64, size: u64) -> Result<bool, ApiError> {
        Ok(address < self.raw.address + self.raw.size as u64 && checked_end(address, size)? > self.raw.address)
    }

    fn decode_named(
        &mut self,
        site: DecodeSite<'_>,
        name: &str,
        fields: &mut Vec<TypedDataField>,
    ) -> Result<(), ApiError> {
        let DecodeSite { path, base, address, union, .. } = site;
        let types = self.types;
        let ty = named(types, name)?;
        let size = ty.size.unwrap_or(0);
        if !self.intersects(address, size)? {
            return Ok(());
        }
        if let Some(identity) = &ty.identity {
            let mut identity = identity.clone();
            if let Some(members) = identity.get_mut("fields").and_then(Value::as_array_mut) {
                for (member, metadata) in members.iter_mut().zip(&ty.fields) {
                    member["type_name"] = Value::String(metadata.type_name.clone());
                    member["size"] = serde_json::to_value(metadata.size).map_err(|error| invalid(error.to_string()))?;
                }
            }
            self.decode_identity(site, name, &identity, size, fields)
        } else {
            let mut field = self.field(path, name, base, address, size, union)?;
            if field.status == "stored" {
                field.status = "unsupported".to_owned();
            }
            fields.push(field);
            Ok(())
        }
    }

    fn decode_identity(
        &mut self,
        site: DecodeSite<'_>,
        name: &str,
        identity: &Value,
        fallback_size: u64,
        fields: &mut Vec<TypedDataField>,
    ) -> Result<(), ApiError> {
        let DecodeSite { path, base, address, union, depth } = site;
        if depth > 32 {
            return Err(invalid("typed data nesting budget exceeded"));
        }
        if let Some(reference) = identity.get("reference").and_then(Value::as_str)
            && self.types.iter().any(|ty| ty.name == reference)
        {
            return self.decode_named(DecodeSite { depth: depth + 1, ..site }, reference, fields);
        }
        let size = identity.get("size").and_then(Value::as_u64).unwrap_or(fallback_size);
        if !self.intersects(address, size)? {
            return Ok(());
        }
        let kind = identity.get("kind").and_then(Value::as_u64);
        if let Some(target) = identity.get("typedef")
            && !matches!(kind, Some(8 | 9))
        {
            return self.decode_identity(DecodeSite { depth: depth + 1, ..site }, name, target, size, fields);
        }
        let mut field = self.field(path, name, base, address, size, union)?;
        if let Some(bytes) = self.complete_bytes(address, size) {
            field.value = scalar_value(&bytes, kind, self.big_endian, identity);
            if field.value.is_none() && !matches!(kind, Some(3 | 4 | 7)) {
                field.status = "unsupported".to_owned();
            }
        }
        fields.push(field);
        if matches!(kind, Some(3 | 4)) {
            if let Some(members) = identity.get("fields").and_then(Value::as_array) {
                for (index, member) in members.iter().enumerate() {
                    let Some(offset) = member.get("offset").and_then(Value::as_u64) else {
                        continue;
                    };
                    let Some(shape) = member.get("type") else {
                        continue;
                    };
                    let member_size =
                        self.identity_size(shape).or_else(|| member.get("size").and_then(Value::as_u64)).unwrap_or(0);
                    if offset.checked_add(member_size).is_none_or(|end| end > size) {
                        return Err(invalid("native field lies outside its containing layout"));
                    }
                    let member_name = member
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("<anonymous:{index}>"));
                    let display = member
                        .get("type_name")
                        .and_then(Value::as_str)
                        .or_else(|| shape.get("reference").and_then(Value::as_str))
                        .unwrap_or("anonymous_native_type");
                    self.decode_identity(
                        DecodeSite {
                            path: &format!("{path}.{member_name}"),
                            address: checked_end(address, offset)?,
                            union: union || kind == Some(3),
                            depth: depth + 1,
                            ..site
                        },
                        display,
                        shape,
                        member_size,
                        fields,
                    )?;
                }
            }
        } else if kind == Some(7)
            && let (Some(count), Some(element)) =
                (identity.get("length").and_then(Value::as_u64), identity.get("element"))
            && let Some(element_size) = self.identity_size(element).filter(|&size| size > 0)
        {
            if element_size.checked_mul(count) != Some(size) {
                return Err(invalid("native array shape disagrees with its size"));
            }
            let first = self.raw.address.saturating_sub(address) / element_size;
            let last =
                ((self.raw.address + self.raw.size as u64).saturating_sub(address).div_ceil(element_size)).min(count);
            for index in first..last {
                let display = element.get("reference").and_then(Value::as_str).unwrap_or("anonymous_native_type");
                self.decode_identity(
                    DecodeSite {
                        path: &format!("{path}[{index}]"),
                        address: checked_end(address, index * element_size)?,
                        depth: depth + 1,
                        ..site
                    },
                    display,
                    element,
                    element_size,
                    fields,
                )?;
            }
        }
        Ok(())
    }

    fn identity_size(&self, identity: &Value) -> Option<u64> {
        identity.get("size").and_then(Value::as_u64).or_else(|| {
            let reference = identity.get("reference")?.as_str()?;
            self.types.iter().find(|ty| ty.name == reference)?.size
        })
    }
}

fn scalar_value(bytes: &[u8], kind: Option<u64>, big_endian: bool, identity: &Value) -> Option<Value> {
    if bytes.is_empty() || bytes.len() > 16 {
        return None;
    }
    let mut value = 0u128;
    if big_endian {
        for &byte in bytes {
            value = (value << 8) | u128::from(byte);
        }
    } else {
        for &byte in bytes.iter().rev() {
            value = (value << 8) | u128::from(byte);
        }
    }
    let hexadecimal = format!("0x{value:0width$x}", width = bytes.len() * 2);
    match kind? {
        9 => Some(json!({"kind": "pointer", "raw_address": hexadecimal, "dereferenced": false})),
        8 => Some(json!({"kind": "relative_pointer", "raw_bits": hexadecimal, "dereferenced": false})),
        5 | 6 | 12 | 13 | 14 => {
            let signed = matches!(kind, Some(5 | 14));
            let decimal = if signed {
                let shift = 128 - bytes.len() * 8;
                (((value << shift) as i128) >> shift).to_string()
            } else {
                value.to_string()
            };
            let names: Vec<_> = identity
                .get("enum_values")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|entry| {
                    entry.get("value").and_then(Value::as_str).and_then(|decimal| enum_value_bits(decimal, bytes.len()))
                        == Some(value)
                })
                .filter_map(|entry| entry.get("name").and_then(Value::as_str))
                .collect();
            Some(json!({"kind": if identity.get("enum_values").is_some() { "enum" } else { "integer" },
                "hex": hexadecimal,
                "decimal": decimal, "signed": signed, "enum_names": names}))
        }
        10 if bytes.len() == 4 || bytes.len() == 8 => {
            let number =
                if bytes.len() == 4 { f32::from_bits(value as u32) as f64 } else { f64::from_bits(value as u64) };
            let display = if number.is_nan() {
                "NaN".to_owned()
            } else if number == f64::INFINITY {
                "+Infinity".to_owned()
            } else if number == f64::NEG_INFINITY {
                "-Infinity".to_owned()
            } else if bytes.len() == 4 {
                (number as f32).to_string()
            } else {
                number.to_string()
            };
            Some(json!({"kind": "float", "raw_bits": hexadecimal, "display": display, "finite": number.is_finite()}))
        }
        _ => None,
    }
}

fn enum_value_bits(decimal: &str, byte_width: usize) -> Option<u128> {
    if !(1..=16).contains(&byte_width) {
        return None;
    }
    let bits = decimal
        .parse::<u128>()
        .ok()
        .or_else(|| decimal.parse::<i128>().ok().map(|signed| u128::from_be_bytes(signed.to_be_bytes())))?;
    let mask = u128::MAX >> (128 - byte_width * 8);
    Some(bits & mask)
}

#[cfg(test)]
#[path = "typed_data_tests.rs"]
mod tests;
