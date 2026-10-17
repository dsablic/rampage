//! Analyst-selected operand interpretations backed by structured decoder and native type evidence.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::{Flow, OperandEvidence, OperandKind};
use rampage_decompiler::{NamedEnumValue, NamedType, NamedTypeKind};
use serde::{Deserialize, Serialize};

use crate::annotations::{
    Annotations, Field, OperandTypeAnnotation, OperandTypeKind, encode_operand_types, parse_operand_types,
};
use crate::{ApiError, Project};

const LIMITATION: &str = "Analyst-selected type and instruction address; not proof of an instruction boundary, \
                         runtime object type, or producer intent. Only explicit decoder operand evidence is used.";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyOperandTypeRequest {
    pub operand: u8,
    pub type_name: Option<String>,
    #[serde(default)]
    pub clear: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperandAnnotationDisplay {
    pub operand: u8,
    pub kind: OperandTypeKind,
    pub type_name: String,
    pub display: String,
    /// For enums, an exact enumerator match; for offsets, an exact field-start match.
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rampage_arch::hex::optional_address")]
    pub immediate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width_bits: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Exact nonnegative byte displacement, encoded as hexadecimal rather than a JSON number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displacement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_size: Option<u16>,
    pub limitation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OperandTypeEdit {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub operand: u8,
    pub kind: OperandTypeKind,
    pub changed: bool,
    /// The actual selected entry after the edit; clearing leaves this absent.
    pub annotation: Option<OperandTypeAnnotation>,
    pub display: Option<OperandAnnotationDisplay>,
    pub warnings: Vec<String>,
    pub limitation: &'static str,
}

type TypeCatalog = BTreeMap<String, NamedType>;

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(format!("operand type: {}", message.into()))
}

fn entries_at(annotations: &Annotations, address: u64) -> Result<Vec<OperandTypeAnnotation>, ApiError> {
    annotations
        .operand_types()
        .get(&address)
        .map(|value| parse_operand_types(value).map_err(invalid))
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(crate) fn binding_names(annotations: &Annotations) -> Result<Vec<String>, ApiError> {
    let mut names = BTreeSet::new();
    for value in annotations.operand_types().values() {
        for entry in parse_operand_types(value).map_err(invalid)? {
            names.insert(entry.type_name);
            if names.len() > 32 {
                return Err(invalid("operand type query exceeds 32 distinct names"));
            }
        }
    }
    Ok(names.into_iter().collect())
}

fn validate_request(request: &ApplyOperandTypeRequest) -> Result<(), ApiError> {
    if request.operand > 31 {
        return Err(invalid("operand index must be 0..=31"));
    }
    match (&request.type_name, request.clear) {
        (Some(name), false) => {
            rampage_decompiler::validate_local_name(name).map_err(|error| invalid(error.to_string()))?;
        }
        (None, true) => {}
        (Some(_), true) => return Err(invalid("cannot set and clear the same operand type")),
        (None, false) => return Err(invalid("provide type_name or clear")),
    }
    Ok(())
}

fn native_type<'a>(catalog: &'a TypeCatalog, name: &str) -> Result<Cow<'a, NamedType>, ApiError> {
    resolve_native_type(catalog, name, 0)
}

fn resolve_native_type<'a>(catalog: &'a TypeCatalog, name: &str, depth: usize) -> Result<Cow<'a, NamedType>, ApiError> {
    if depth >= 32 {
        return Err(invalid("native typedef chain is cyclic or exceeds 32 entries"));
    }
    let ty = catalog.get(name).ok_or_else(|| invalid(format!("native type {name:?} is unavailable")))?;
    if ty.incomplete {
        return Err(invalid(format!("native type {name:?} is incomplete")));
    }
    if ty.kind != NamedTypeKind::Typedef {
        return Ok(Cow::Borrowed(ty));
    }
    let target = ty
        .identity
        .as_ref()
        .and_then(|identity| identity.get("typedef"))
        .ok_or_else(|| invalid("native typedef has no structural target identity"))?;
    resolve_typedef_identity(catalog, ty, target, depth + 1)
}

fn resolve_typedef_identity<'a>(
    catalog: &'a TypeCatalog,
    owner: &'a NamedType,
    identity: &serde_json::Value,
    depth: usize,
) -> Result<Cow<'a, NamedType>, ApiError> {
    if depth >= 32 {
        return Err(invalid("native typedef chain is cyclic or exceeds 32 entries"));
    }
    if let Some(reference) = identity.get("reference").and_then(serde_json::Value::as_str) {
        return resolve_native_type(catalog, reference, depth);
    }
    if let Some(target) = identity.get("typedef") {
        return resolve_typedef_identity(catalog, owner, target, depth + 1);
    }
    let kind = identity.get("kind").and_then(serde_json::Value::as_u64);
    let mut resolved = owner.clone();
    resolved.kind = match kind {
        Some(4) => NamedTypeKind::Struct,
        Some(5 | 6 | 13 | 14) if identity.get("enum_values").is_some() => NamedTypeKind::Enum,
        _ => return Err(invalid("anonymous typedef target is not a native struct or scalar enum")),
    };
    let size = identity
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or_else(|| invalid("anonymous typedef target has no complete native size"))?;
    if owner.size != Some(size) {
        return Err(invalid("anonymous typedef identity disagrees with its native layout size"));
    }
    if resolved.kind == NamedTypeKind::Enum && resolved.enum_values.is_empty() {
        let width = u16::try_from(size.checked_mul(8).ok_or_else(|| invalid("enum size overflows"))?)
            .map_err(|_| invalid("enum size exceeds supported scalar width"))?;
        let mask = bit_mask(width)?;
        let entries = identity
            .get("enum_values")
            .cloned()
            .ok_or_else(|| invalid("anonymous enum identity has no enumerator values"))?;
        resolved.enum_values =
            serde_json::from_value::<Vec<NamedEnumValue>>(entries).map_err(|error| invalid(error.to_string()))?;
        // Structural identity emits uint64 bit patterns; named enum metadata already emits signed decimals.
        for entry in &mut resolved.enum_values {
            let bits = entry
                .value
                .parse::<u64>()
                .map_err(|_| invalid("native identity enum value is not an exact unsigned integer"))?
                & mask;
            let value = if matches!(kind, Some(5 | 14)) && bits & (1u64 << (width - 1)) != 0 {
                i128::from(bits) - (1i128 << width)
            } else {
                i128::from(bits)
            };
            entry.value = value.to_string();
        }
    }
    Ok(Cow::Owned(resolved))
}

fn bit_mask(width: u16) -> Result<u64, ApiError> {
    match width {
        1..=63 => Ok((1u64 << width) - 1),
        64 => Ok(u64::MAX),
        _ => Err(invalid("operand requires an explicit logical width of 1..=64 bits")),
    }
}

fn enum_pattern(value: &str, enum_width: u16, operand_width: u16) -> Result<u64, ApiError> {
    let maximum = i128::from(bit_mask(enum_width)?);
    let value = value.parse::<i128>().map_err(|_| invalid("native enum value is not an exact decimal integer"))?;
    let minimum = -(1i128 << (enum_width - 1));
    if value < minimum || value > maximum {
        return Err(invalid("native enum value exceeds its declared scalar width"));
    }
    Ok((value as u64) & bit_mask(operand_width)?)
}

fn interpret(
    annotation: &OperandTypeAnnotation,
    operand: &OperandEvidence,
    catalog: &TypeCatalog,
) -> Result<OperandAnnotationDisplay, ApiError> {
    let ty = native_type(catalog, &annotation.type_name)?;
    let mut result = OperandAnnotationDisplay {
        operand: annotation.operand,
        kind: annotation.kind,
        type_name: annotation.type_name.clone(),
        display: String::new(),
        matched: false,
        immediate: None,
        width_bits: None,
        field_path: None,
        base: None,
        displacement: None,
        access_size: None,
        limitation: LIMITATION,
    };
    match annotation.kind {
        OperandTypeKind::Enum => {
            if operand.kind != OperandKind::Immediate || ty.kind != NamedTypeKind::Enum {
                return Err(invalid("enum annotations require a native scalar enum and an explicit immediate operand"));
            }
            let width = operand.width_bits.ok_or_else(|| invalid("immediate logical width is unknown"))?;
            let mask = bit_mask(width)?;
            let value = operand.immediate.ok_or_else(|| invalid("immediate value is unavailable"))? & mask;
            let enum_width = ty
                .size
                .filter(|size| (1..=8).contains(size))
                .map(|size| (size * 8) as u16)
                .ok_or_else(|| invalid("native enum scalar size is unknown or unsupported"))?;
            if enum_width > width {
                return Err(invalid("native enum is wider than the immediate's logical width"));
            }
            let mut matched = None;
            for entry in &ty.enum_values {
                let pattern = enum_pattern(&entry.value, enum_width, width)?;
                if pattern == value && matched.is_none() {
                    matched = Some(&entry.name);
                }
            }
            result.display = match matched {
                Some(name) => format!("{}::{name}", annotation.type_name),
                None => format!("{}({value:#x})", annotation.type_name),
            };
            result.matched = matched.is_some();
            result.immediate = Some(value);
            result.width_bits = Some(width);
        }
        OperandTypeKind::Offset => {
            if operand.kind != OperandKind::Memory || ty.kind != NamedTypeKind::Struct {
                return Err(invalid("offset annotations require a native struct and an explicit memory operand"));
            }
            let memory = operand.memory.as_ref().ok_or_else(|| invalid("memory operand evidence is unavailable"))?;
            if memory.relative || memory.base.as_ref().is_none_or(|base| base.is_empty()) {
                return Err(invalid("PC-relative and absolute references are not object-base struct offsets"));
            }
            if memory.index.is_some() {
                return Err(invalid("indexed memory operands are not supported as struct offsets"));
            }
            let offset = u64::try_from(memory.displacement)
                .map_err(|_| invalid("negative displacements are not supported as struct offsets"))?;
            let size = ty.size.ok_or_else(|| invalid("native struct size is unavailable"))?;
            let access = memory
                .access_size
                .filter(|size| *size > 0)
                .ok_or_else(|| invalid("memory access size is unknown; address formation is not a field access"))?;
            let end = offset.checked_add(u64::from(access)).ok_or_else(|| invalid("field access overflows"))?;
            if offset >= size || end > size {
                return Err(invalid("memory access lies outside the complete native struct layout"));
            }
            let mut fields = ty.fields.iter().filter(|field| {
                field.offset == offset
                    && !field.name.is_empty()
                    && field.size.is_some_and(|field_size| {
                        u64::from(access) <= field_size
                            && field.offset.checked_add(field_size).is_some_and(|end| end <= size)
                    })
            });
            let field =
                fields.next().ok_or_else(|| invalid("displacement is not a known field start of sufficient size"))?;
            if fields.next().is_some() {
                return Err(invalid("native layout has ambiguous fields at this displacement"));
            }
            result.display = format!("{}.{}", annotation.type_name, field.name);
            result.matched = true;
            result.field_path = Some(field.name.clone());
            result.base = memory.base.clone();
            result.displacement = Some(format!("{offset:#x}"));
            result.access_size = Some(access);
        }
    }
    Ok(result)
}

fn instruction(project: &Project, address: u64) -> Result<(String, Vec<OperandEvidence>), ApiError> {
    project.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
    let mut decoder = project.binary.decoder()?;
    let code = project
        .binary
        .code_from(address)
        .ok_or_else(|| invalid(format!("address {address:#x} is not file-backed code")))?;
    let insn = decoder.decode(code, address);
    let len = usize::from(insn.len);
    if insn.flow == Flow::Invalid || len == 0 || len > 32 || len > code.len() {
        return Err(invalid("instruction is invalid, truncated, or exceeds 32 bytes"));
    }
    let bytes = &code[..len];
    let operands = decoder
        .operands(bytes, address)
        .ok_or_else(|| invalid("structured operand evidence is unavailable for this instruction"))?;
    let hex = rampage_arch::hex::bytes(bytes);
    project.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
    Ok((hex, operands))
}

fn display_entries(
    entries: &[OperandTypeAnnotation],
    hex: &str,
    operands: &[OperandEvidence],
    catalog: &TypeCatalog,
) -> Result<Vec<OperandAnnotationDisplay>, ApiError> {
    entries
        .iter()
        .map(|entry| {
            if !entry.instruction_hex.eq_ignore_ascii_case(hex) {
                return Err(invalid(
                    "stored instruction bytes differ from the complete current instruction; annotation is stale",
                ));
            }
            let operand = operands
                .iter()
                .find(|operand| operand.index == entry.operand)
                .ok_or_else(|| invalid(format!("instruction has no operand {}", entry.operand)))?;
            interpret(entry, operand, catalog)
        })
        .collect()
}

/// Called with metadata already acquired under the parent's decompiler lock; never calls `Project::get_type`.
pub(crate) fn validate_operand_annotations(
    project: &Project,
    annotations: &Annotations,
    metadata: &[NamedType],
) -> Result<(), ApiError> {
    if annotations.operand_types().is_empty() {
        return Ok(());
    }
    let catalog = metadata.iter().cloned().map(|ty| (ty.name.clone(), ty)).collect();
    for (&address, value) in annotations.operand_types() {
        let entries = parse_operand_types(value).map_err(invalid)?;
        let (hex, operands) = instruction(project, address)?;
        display_entries(&entries, &hex, &operands, &catalog)?;
    }
    Ok(())
}

pub(crate) struct OperandListingContext {
    annotations: Annotations,
    catalog: TypeCatalog,
}

impl OperandListingContext {
    pub(crate) fn display(
        &self,
        project: &Project,
        address: u64,
        bytes: &[u8],
    ) -> Result<Vec<OperandAnnotationDisplay>, ApiError> {
        let entries = entries_at(&self.annotations, address)?;
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let (hex, operands) = instruction(project, address)?;
        if hex != rampage_arch::hex::bytes(bytes) {
            return Err(invalid("listing bytes do not match the complete typed instruction"));
        }
        display_entries(&entries, &hex, &operands, &self.catalog)
    }
}

impl Project {
    pub(crate) fn operand_listing_context(&self) -> Result<Option<OperandListingContext>, ApiError> {
        if self.annotations.read().expect("annotations lock").operand_types().is_empty() {
            return Ok(None);
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let annotations = self.annotations.read().expect("annotations lock").checked_read_snapshot()?;
        if annotations.operand_types().is_empty() {
            return Ok(None);
        }
        let names = binding_names(&annotations)?;
        let metadata = self.native_data_types(&state, &options, &annotations, &names)?;
        let catalog = metadata.into_iter().map(|ty| (ty.name.clone(), ty)).collect();
        Ok(Some(OperandListingContext { annotations, catalog }))
    }

    pub fn apply_enum(&self, address: u64, request: &ApplyOperandTypeRequest) -> Result<OperandTypeEdit, ApiError> {
        self.apply_enum_with_preflight(address, request, |_| Ok(()))
    }

    pub fn apply_enum_with_preflight(
        &self,
        address: u64,
        request: &ApplyOperandTypeRequest,
        preflight: impl FnOnce(&OperandTypeEdit) -> Result<(), ApiError>,
    ) -> Result<OperandTypeEdit, ApiError> {
        self.apply_operand_type(address, request, OperandTypeKind::Enum, preflight)
    }

    pub fn apply_offset(&self, address: u64, request: &ApplyOperandTypeRequest) -> Result<OperandTypeEdit, ApiError> {
        self.apply_offset_with_preflight(address, request, |_| Ok(()))
    }

    pub fn apply_offset_with_preflight(
        &self,
        address: u64,
        request: &ApplyOperandTypeRequest,
        preflight: impl FnOnce(&OperandTypeEdit) -> Result<(), ApiError>,
    ) -> Result<OperandTypeEdit, ApiError> {
        self.apply_operand_type(address, request, OperandTypeKind::Offset, preflight)
    }

    fn apply_operand_type(
        &self,
        address: u64,
        request: &ApplyOperandTypeRequest,
        kind: OperandTypeKind,
        preflight: impl FnOnce(&OperandTypeEdit) -> Result<(), ApiError>,
    ) -> Result<OperandTypeEdit, ApiError> {
        validate_request(request)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            let (hex, operands) = instruction(self, address)?;
            let mut names: BTreeSet<_> = binding_names(annotations)?.into_iter().collect();
            names.extend(request.type_name.iter().cloned());
            if names.len() > 32 {
                return Err(invalid("operand type query exceeds 32 distinct names"));
            }
            let names: Vec<_> = names.into_iter().collect();
            let metadata = if names.is_empty() {
                Vec::new()
            } else {
                self.native_data_types(&state, &options, annotations, &names)?
            };
            let catalog = metadata.into_iter().map(|ty| (ty.name.clone(), ty)).collect();
            let mut entries = entries_at(annotations, address)?;
            // Validate the original binding before editing so a stale entry cannot be silently rebound or cleared.
            display_entries(&entries, &hex, &operands, &catalog)?;
            let selected = operands
                .iter()
                .find(|operand| operand.index == request.operand)
                .ok_or_else(|| invalid(format!("instruction has no operand {}", request.operand)))?;
            if request.clear && entries.iter().any(|entry| entry.operand == request.operand && entry.kind != kind) {
                return Err(invalid("selected operand has a different annotation kind"));
            }
            entries.retain(|entry| entry.operand != request.operand);
            let annotation = request.type_name.as_ref().map(|name| OperandTypeAnnotation {
                operand: request.operand,
                kind,
                type_name: name.clone(),
                instruction_hex: hex.clone(),
            });
            let display = annotation.as_ref().map(|entry| interpret(entry, selected, &catalog)).transpose()?;
            if let Some(entry) = &annotation {
                entries.push(entry.clone());
            }
            let value = (!entries.is_empty()).then(|| encode_operand_types(&entries)).transpose().map_err(invalid)?;
            let result = OperandTypeEdit {
                address,
                operand: request.operand,
                kind,
                changed: annotations.operand_types().get(&address) != value.as_ref(),
                annotation,
                display,
                warnings: annotations.warnings(),
                limitation: LIMITATION,
            };
            let mut preflight = Some(preflight);
            let changed = annotations
                .set_validated(Field::OperandType, address, value, |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)?;
                    preflight.take().expect("one candidate preflight")(&result).map_err(|error| error.to_string())?;
                    self.binary.validate_available_backing_source().map(|_| ()).map_err(|error| error.to_string())
                })
                .map_err(invalid)?;
            // No-op edits still preflight their complete response, but create no log/history entry.
            if !changed {
                self.validate_annotation_snapshot(&state, &options, annotations).map_err(invalid)?;
                preflight.take().expect("no-op preflight")(&result)?;
                self.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
#[path = "operand_types_tests.rs"]
mod tests;
