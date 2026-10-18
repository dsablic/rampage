use std::collections::{BTreeMap, BTreeSet};

use rampage_decompiler::{DataOrganization, NamedType, NamedTypeKind};
use rampage_loaders::debug_types::{
    DebugScalarEncoding, DebugType, DebugTypeKind, DebugTypeReport, MAX_DEBUG_DEPTH, MAX_DEBUG_FIELDS,
    MAX_DEBUG_SIGNATURES, MAX_DEBUG_TYPES,
};
use serde_json::Value;

use super::{ApiError, digest, invalid, json};

pub(super) struct Plan {
    pub declarations: String,
    pub names: Vec<String>,
    pub emitted: BTreeMap<String, String>,
    pub accepted: BTreeSet<String>,
    pub reasons: BTreeMap<String, Vec<String>>,
    unified_windows_x64: bool,
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()))
        && !matches!(
            name,
            "struct"
                | "union"
                | "enum"
                | "typedef"
                | "void"
                | "const"
                | "volatile"
                | "int"
                | "long"
                | "float"
                | "double"
                | "unsigned"
                | "signed"
                | "char"
                | "short"
                | "return"
                | "if"
                | "else"
                | "while"
                | "for"
                | "switch"
                | "case"
                | "default"
                | "extern"
                | "static"
                | "register"
                | "auto"
                | "sizeof"
                | "do"
                | "break"
                | "continue"
                | "goto"
        )
}

fn named(ty: &DebugType) -> bool {
    matches!(
        ty.kind,
        DebugTypeKind::Struct { .. }
            | DebugTypeKind::Union { .. }
            | DebugTypeKind::Enum { .. }
            | DebugTypeKind::Typedef { .. }
            | DebugTypeKind::Function { .. }
    )
}

fn scalar(ty: &DebugType) -> Result<String, ApiError> {
    let DebugTypeKind::Scalar { encoding, .. } = ty.kind else { return Err(invalid("not a scalar")) };
    let name = match (encoding, ty.byte_size) {
        (DebugScalarEncoding::Void, None | Some(0)) => "void".to_owned(),
        (DebugScalarEncoding::Signed, Some(size @ (1 | 2 | 4 | 8))) => format!("int{size}"),
        (DebugScalarEncoding::Unsigned, Some(size @ (1 | 2 | 4 | 8))) => format!("uint{size}"),
        (DebugScalarEncoding::Float, Some(size @ (4 | 8))) => format!("float{size}"),
        (DebugScalarEncoding::Boolean, Some(1)) => "bool".to_owned(),
        // Producer plain-char signedness must be supplied explicitly rather than guessed from the target.
        _ => return Err(invalid("unsupported or ambiguous scalar encoding/width")),
    };
    Ok(name)
}

fn convention(value: &str) -> Result<&str, ApiError> {
    match value {
        "default" | "normal" => Ok(""),
        "cdecl" | "__cdecl" | "near_c" => Ok("__cdecl"),
        "stdcall" | "__stdcall" | "near_stdcall" => Ok("__stdcall"),
        "fastcall" | "__fastcall" | "near_fastcall" => Ok("__fastcall"),
        _ => Err(invalid("unsupported producer calling convention")),
    }
}

fn projected_convention(value: &str, unified_windows_x64: bool) -> Result<&str, ApiError> {
    let known = convention(value)?;
    if unified_windows_x64 && matches!(known, "__cdecl" | "__stdcall" | "__fastcall") { Ok("") } else { Ok(known) }
}

fn local_reasons(ty: &DebugType) -> Vec<String> {
    let mut reasons = ty.unsupported.clone();
    if ty.byte_size.is_some_and(|size| size > 1024 * 1024)
        || ty.alignment.is_some_and(|alignment| !alignment.is_power_of_two() || alignment > 16)
    {
        reasons.push("producer size/alignment exceeds checked bounds".to_owned())
    }
    if ty.byte_size == Some(0)
        && !matches!(
            ty.kind,
            DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Void, .. } | DebugTypeKind::Function { .. }
        )
    {
        reasons.push("zero-sized object types are preview-only".to_owned());
    }
    match &ty.kind {
        DebugTypeKind::Scalar { .. } => {
            if let Err(error) = scalar(ty) {
                reasons.push(error.to_string())
            }
            if ty.alignment.is_some() {
                reasons.push("explicit producer scalar alignment lacks an independently retained core-type measurement; preview-only".into());
            }
        }
        DebugTypeKind::Pointer { .. } => {
            if !matches!(ty.byte_size, Some(4 | 8)) {
                reasons.push("unsupported pointer width".to_owned())
            }
        }
        DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } => {
            if members.is_empty() || members.len() > MAX_DEBUG_FIELDS || ty.byte_size.is_none() {
                reasons.push("incomplete or over-budget record".to_owned());
            }
            let mut names = BTreeSet::new();
            for member in members {
                if member.bitfield.is_some() {
                    reasons.push("bitfield members are preview-only".to_owned())
                }
                reasons.extend(member.unsupported.iter().cloned());
                if member.name.as_deref().is_none_or(|name| !identifier(name) || !names.insert(name)) {
                    reasons.push("anonymous, duplicate or unsupported member name".to_owned());
                }
            }
        }
        DebugTypeKind::Enum { values, .. } => {
            let mut names = BTreeSet::new();
            if values.is_empty()
                || values.len() > 256
                || values.iter().any(|value| {
                    !identifier(&value.name) || !names.insert(&value.name) || value.value.parse::<i128>().is_err()
                })
            {
                reasons.push("unsupported/ambiguous enum values".to_owned())
            }
        }
        DebugTypeKind::Array { count, .. } => {
            if count.is_none_or(|count| count == 0 || count > 65536) {
                reasons.push("array requires an explicit bounded count".to_owned());
            }
        }
        DebugTypeKind::Function { convention: model, parameters, variadic, .. } => {
            if *variadic || parameters.len() > 128 || convention(model).is_err() {
                reasons.push("vararg/unsupported convention or parameter budget".to_owned());
            }
        }
        DebugTypeKind::Unsupported { description } => reasons.push(description.clone()),
        DebugTypeKind::Bitfield { .. } => {
            reasons.push("standalone producer bitfield types are preview-only".to_owned());
        }
        DebugTypeKind::Typedef { constant, volatile, .. } => {
            if *constant || *volatile {
                reasons.push(
                    "qualified types lack independently checkable native qualifier identity; preview-only".into(),
                );
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn extent(id: &str, types: &BTreeMap<&str, &DebugType>, depth: usize) -> Option<u64> {
    if depth > MAX_DEBUG_DEPTH {
        return None;
    }
    let ty = types.get(id)?;
    if let Some(size) = ty.byte_size {
        return Some(size);
    }
    match &ty.kind {
        DebugTypeKind::Typedef { target, .. } => extent(target, types, depth + 1),
        DebugTypeKind::Array { element, count: Some(count), stride } => {
            stride.or_else(|| extent(element, types, depth + 1))?.checked_mul(*count)
        }
        _ => None,
    }
}

fn resolved_integer(id: &str, types: &BTreeMap<&str, &DebugType>, depth: usize) -> Option<(DebugScalarEncoding, u64)> {
    if depth > MAX_DEBUG_DEPTH {
        return None;
    }
    let ty = types.get(id)?;
    match &ty.kind {
        DebugTypeKind::Scalar {
            encoding: encoding @ (DebugScalarEncoding::Signed | DebugScalarEncoding::Unsigned),
            ..
        } if matches!(ty.byte_size, Some(1 | 2 | 4 | 8)) => Some((*encoding, ty.byte_size?)),
        DebugTypeKind::Typedef { target, .. } => {
            let resolved = resolved_integer(target, types, depth + 1)?;
            ty.byte_size.is_none_or(|size| size == resolved.1).then_some(resolved)
        }
        _ => None,
    }
}

fn alias_anchor<'a>(id: &'a str, types: &BTreeMap<&'a str, &'a DebugType>, depth: usize) -> Option<&'a str> {
    if depth > MAX_DEBUG_DEPTH {
        return None;
    }
    match &types.get(id)?.kind {
        DebugTypeKind::Typedef { target, constant: false, volatile: false } => alias_anchor(target, types, depth + 1),
        _ => Some(id),
    }
}

fn distinguish_proven_aliases(plan: &mut Plan, types: &BTreeMap<&str, &DebugType>) -> Result<(), ApiError> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, name) in &plan.emitted {
        groups.entry(name.clone()).or_default().push(id.clone());
    }
    for ids in groups.values().filter(|ids| ids.len() > 1) {
        let anchor = alias_anchor(&ids[0], types, 0).ok_or_else(|| invalid("invalid producer alias dependency"))?;
        if !matches!(
            types[anchor].kind,
            DebugTypeKind::Struct { .. } | DebugTypeKind::Union { .. } | DebugTypeKind::Enum { .. }
        ) || ids.iter().any(|id| alias_anchor(id, types, 0) != Some(anchor))
        {
            return Err(invalid(
                "distinct producer IDs share an emitted type name without an exact aggregate/enum alias edge",
            ));
        }
        for id in ids.iter().filter(|id| id.as_str() != anchor) {
            plan.emitted.insert(id.clone(), format!("debug_alias_{}", &digest(id.as_bytes())[..16]));
        }
    }
    let mut used = BTreeSet::new();
    if plan.emitted.values().any(|name| !used.insert(name)) {
        return Err(invalid("generated producer alias name collides with another exact type identity"));
    }
    Ok(())
}

fn enum_reasons(ty: &DebugType, types: &BTreeMap<&str, &DebugType>) -> Vec<String> {
    let DebugTypeKind::Enum { underlying, values } = &ty.kind else { return Vec::new() };
    let Some((encoding, width)) = resolved_integer(underlying, types, 0) else {
        return vec!["unsupported enum underlying integer type/alias extent".into()];
    };
    let mut reasons = Vec::new();
    if ty.byte_size != Some(width) {
        reasons.push("enum byte size disagrees with resolved underlying integer width".into());
    }
    let bits = width * 8;
    let (minimum, maximum) = if encoding == DebugScalarEncoding::Signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    for entry in values {
        let Ok(value) = entry.value.parse::<i128>() else { continue };
        if !(minimum..=maximum).contains(&value) {
            reasons.push("enum value is not representable by its resolved producer width/signedness".into());
        }
        if !(i128::from(i32::MIN)..=i128::from(i32::MAX)).contains(&value) {
            reasons.push("enum value exceeds the native C declaration renderer's signed-int literal range".into());
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn record_reasons(ty: &DebugType, types: &BTreeMap<&str, &DebugType>) -> Vec<String> {
    let (members, overlapping) = match &ty.kind {
        DebugTypeKind::Struct { members } => (members, false),
        DebugTypeKind::Union { members } => (members, true),
        _ => return Vec::new(),
    };
    let mut reasons = Vec::new();
    let mut ranges = Vec::new();
    for member in members.iter().filter(|member| member.bitfield.is_none()) {
        let end = extent(&member.type_id, types, 0)
            .filter(|size| *size > 0)
            .and_then(|size| member.byte_offset.checked_add(size));
        let Some(end) = end else {
            reasons.push("record member lacks a bounded nonzero storage extent".into());
            continue;
        };
        if ty.byte_size.is_none_or(|size| end > size) {
            reasons.push("record member storage exceeds the explicit producer record size".into());
        }
        ranges.push((member.byte_offset, end));
    }
    if !overlapping {
        ranges.sort_unstable();
        let mut previous_end = 0;
        for (start, end) in ranges {
            if start < previous_end {
                reasons.push("non-bitfield struct member storage overlaps another member".into());
            }
            previous_end = previous_end.max(end);
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn closure(
    id: &str,
    types: &BTreeMap<&str, &DebugType>,
    local: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEBUG_DEPTH {
        return Err("dependency depth exceeds 32".to_owned());
    }
    let ty = types.get(id).ok_or_else(|| format!("missing producer dependency {id}"))?;
    if local.get(id).is_some_and(|reasons| !reasons.is_empty()) {
        return Err(format!("unsupported producer dependency {id}"));
    }
    if !visiting.insert(id.to_owned()) {
        return Ok(());
    }
    for dependency in ty.kind.references() {
        closure(dependency, types, local, visiting, depth + 1)?
    }
    Ok(())
}

fn abi_value(id: &str, types: &BTreeMap<&str, &DebugType>, depth: usize) -> bool {
    if depth > MAX_DEBUG_DEPTH {
        return false;
    }
    let Some(ty) = types.get(id) else { return false };
    match &ty.kind {
        DebugTypeKind::Scalar { .. } | DebugTypeKind::Pointer { .. } => true,
        DebugTypeKind::Typedef { target, .. } => abi_value(target, types, depth + 1),
        _ => false,
    }
}

fn by_value_visit<'a>(
    id: &'a str,
    types: &BTreeMap<&'a str, &'a DebugType>,
    visiting: &mut BTreeSet<&'a str>,
    done: &mut BTreeSet<&'a str>,
    depth: usize,
) -> Result<(), ApiError> {
    if done.contains(id) {
        return Ok(());
    }
    if depth > MAX_DEBUG_DEPTH || !visiting.insert(id) {
        return Err(invalid("by-value dependency cycle/depth"));
    }
    let ty = types[id];
    if !matches!(ty.kind, DebugTypeKind::Pointer { .. } | DebugTypeKind::Function { .. }) {
        for dependency in ty.kind.references() {
            by_value_visit(dependency, types, visiting, done, depth + 1)?
        }
    }
    visiting.remove(id);
    done.insert(id);
    Ok(())
}

fn declaration(
    id: &str,
    name: &str,
    types: &BTreeMap<&str, &DebugType>,
    emitted: &BTreeMap<String, String>,
    unified_windows_x64: bool,
    depth: usize,
    defining: bool,
) -> Result<String, ApiError> {
    if depth > MAX_DEBUG_DEPTH {
        return Err(invalid("declarator depth exceeds 32"));
    }
    let ty = types.get(id).ok_or_else(|| invalid("missing declarator type"))?;
    if !defining && let Some(alias) = emitted.get(id) {
        let prefix = match ty.kind {
            DebugTypeKind::Struct { .. } => "struct ",
            DebugTypeKind::Union { .. } => "union ",
            DebugTypeKind::Enum { .. } => "enum ",
            _ => "",
        };
        return Ok(format!("{prefix}{alias} {name}"));
    }
    match &ty.kind {
        DebugTypeKind::Scalar { .. } => Ok(format!("{} {name}", scalar(ty)?)),
        DebugTypeKind::Pointer { target } => {
            let nested = types.get(target.as_str()).ok_or_else(|| invalid("missing pointer target"))?;
            let declarator = if matches!(nested.kind, DebugTypeKind::Array { .. }) {
                format!("(*{name})")
            } else {
                format!("*{name}")
            };
            declaration(target, &declarator, types, emitted, unified_windows_x64, depth + 1, false)
        }
        DebugTypeKind::Array { element, count: Some(count), .. } => {
            declaration(element, &format!("{name}[{count}]"), types, emitted, unified_windows_x64, depth + 1, false)
        }
        DebugTypeKind::Typedef { target, constant, volatile } => {
            if *constant || *volatile {
                return Err(invalid("qualified declarators remain preview-only without native qualifier identity"));
            }
            declaration(target, name, types, emitted, unified_windows_x64, depth + 1, false)
        }
        DebugTypeKind::Function { convention: model, parameters, return_type, variadic: false } => {
            let parameters = if parameters.is_empty() {
                "void".to_owned()
            } else {
                parameters
                    .iter()
                    .enumerate()
                    .map(|(index, id)| {
                        declaration(id, &format!("p{index}"), types, emitted, unified_windows_x64, depth + 1, false)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join(", ")
            };
            let convention = projected_convention(model, unified_windows_x64)?;
            let result = declaration(
                return_type,
                &format!("{name}({parameters})"),
                types,
                emitted,
                unified_windows_x64,
                depth + 1,
                false,
            )?;
            if convention.is_empty() { Ok(result) } else { Ok(format!("{convention} {result}")) }
        }
        _ => Err(invalid("unsupported inline type declaration")),
    }
}

fn ordering_dependencies<'a>(
    id: &'a str,
    types: &BTreeMap<&'a str, &'a DebugType>,
    output: &mut BTreeSet<&'a str>,
    depth: usize,
) -> Result<(), ApiError> {
    if depth > MAX_DEBUG_DEPTH {
        return Err(invalid("declaration dependency depth exceeds 32"));
    }
    let ty = types[id];
    if matches!(ty.kind, DebugTypeKind::Struct { .. } | DebugTypeKind::Union { .. }) {
        output.insert(id);
        return Ok(());
    }
    if named(ty) {
        output.insert(id);
        return Ok(());
    }
    if let DebugTypeKind::Pointer { target } = &ty.kind
        && matches!(types[target.as_str()].kind, DebugTypeKind::Struct { .. } | DebugTypeKind::Union { .. })
    {
        return Ok(());
    }
    for dependency in ty.kind.references() {
        ordering_dependencies(dependency, types, output, depth + 1)?
    }
    Ok(())
}

fn emit_visit<'a>(
    id: &'a str,
    types: &BTreeMap<&'a str, &'a DebugType>,
    plan: &Plan,
    visiting: &mut BTreeSet<&'a str>,
    done: &mut BTreeSet<&'a str>,
    text: &mut String,
    depth: usize,
) -> Result<(), ApiError> {
    if done.contains(id) {
        return Ok(());
    }
    if depth > MAX_DEBUG_DEPTH || !visiting.insert(id) {
        return Err(invalid("unsupported declaration cycle; no partial type is imported"));
    }
    let ty = types[id];
    let mut required = BTreeSet::new();
    for dependency in ty.kind.references() {
        ordering_dependencies(dependency, types, &mut required, 0)?;
    }
    // Pointers to records need only the forward tags emitted before this pass.
    if let DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } = &ty.kind {
        required.clear();
        for member in members {
            ordering_dependencies(&member.type_id, types, &mut required, 0)?;
        }
    }
    for dependency in required {
        if plan.emitted.contains_key(dependency) {
            emit_visit(dependency, types, plan, visiting, done, text, depth + 1)?;
        }
    }
    let name = &plan.emitted[id];
    match &ty.kind {
        DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } => {
            let keyword = if matches!(ty.kind, DebugTypeKind::Struct { .. }) { "struct" } else { "union" };
            text.push_str(&format!("{keyword} {name} {{\n"));
            for member in members {
                text.push_str(&declaration(
                    &member.type_id,
                    member.name.as_deref().unwrap_or(""),
                    types,
                    &plan.emitted,
                    plan.unified_windows_x64,
                    0,
                    false,
                )?);
                text.push_str(";\n");
            }
            text.push_str("};\n");
        }
        DebugTypeKind::Enum { values, .. } => {
            text.push_str(&format!("enum {name} {{"));
            text.push_str(
                &values.iter().map(|value| format!("{} = {}", value.name, value.value)).collect::<Vec<_>>().join(", "),
            );
            text.push_str("};\n");
        }
        _ => {
            text.push_str("typedef ");
            text.push_str(&declaration(id, name, types, &plan.emitted, plan.unified_windows_x64, 0, true)?);
            text.push_str(";\n");
        }
    }
    if text.len() > 64 * 1024 {
        return Err(invalid("declarations exceed 64 KiB"));
    }
    visiting.remove(id);
    done.insert(id);
    Ok(())
}

pub(super) fn prepare(report: &DebugTypeReport) -> Result<Plan, ApiError> {
    prepare_with_policy(report, false)
}

pub(super) fn prepare_for_target(
    report: &DebugTypeReport,
    language_id: &str,
    organization: DataOrganization,
) -> Result<Plan, ApiError> {
    let unified_windows_x64 = report.provenance.source == rampage_loaders::debug_types::DebugSourceKind::Pdb
        && matches!(language_id, "x86:LE:64:default:windows" | "x86:LE:64:default:clangwindows")
        && organization == (DataOrganization { pointer: 8, int: 4, long: 4 });
    if unified_windows_x64 { prepare_with_policy(report, true) } else { prepare(report) }
}

fn prepare_with_policy(report: &DebugTypeReport, unified_windows_x64: bool) -> Result<Plan, ApiError> {
    if report.types.len() > MAX_DEBUG_TYPES
        || report.signatures.len() > MAX_DEBUG_SIGNATURES
        || json(report)?.len() > 768 * 1024
    {
        return Err(invalid("producer graph exceeds checked node/signature/byte limits"));
    }
    let mut types = BTreeMap::new();
    let mut local = BTreeMap::new();
    for ty in &report.types {
        if ty.id.is_empty() || ty.id.len() > 256 || types.insert(ty.id.as_str(), ty).is_some() {
            return Err(invalid("empty, duplicate or oversized producer source identity"));
        }
        local.insert(ty.id.clone(), local_reasons(ty));
    }
    for ty in &report.types {
        for dependency in ty.kind.references() {
            if !types.contains_key(dependency.as_str()) {
                local.get_mut(&ty.id).expect("graph ID").push(format!("missing producer dependency {dependency}"));
            }
        }
        local.get_mut(&ty.id).expect("graph ID").extend(record_reasons(ty, &types));
        local.get_mut(&ty.id).expect("graph ID").extend(enum_reasons(ty, &types));
        if let DebugTypeKind::Function { parameters, return_type, .. } = &ty.kind
            && (!abi_value(return_type, &types, 0) || parameters.iter().any(|id| !abi_value(id, &types, 0)))
        {
            local.get_mut(&ty.id).expect("graph ID").push("aggregate-by-value ABI is preview-only".to_owned());
        }
        if let DebugTypeKind::Array { element, count: Some(count), stride } = &ty.kind {
            let element_size = extent(element, &types, 0);
            let effective_stride = stride.or(element_size);
            if element_size.is_none()
                || element_size != effective_stride
                || effective_stride.and_then(|stride| count.checked_mul(stride)) != extent(&ty.id, &types, 0)
            {
                local.get_mut(&ty.id).expect("graph ID").push("array stride/extent disagrees with element size".into());
            }
        }
    }
    let mut plan = Plan {
        declarations: String::new(),
        names: Vec::new(),
        emitted: BTreeMap::new(),
        accepted: BTreeSet::new(),
        reasons: local.clone(),
        unified_windows_x64,
    };
    for ty in &report.types {
        let eligible = closure(&ty.id, &types, &local, &mut BTreeSet::new(), 0)
            .map_err(invalid)
            .and_then(|()| by_value_visit(&ty.id, &types, &mut BTreeSet::new(), &mut BTreeSet::new(), 0));
        if let Err(error) = eligible {
            plan.reasons.entry(ty.id.clone()).or_default().push(error.to_string());
            continue;
        }
        plan.accepted.insert(ty.id.clone());
        if named(ty) {
            let proposed = ty
                .emitted_name
                .as_deref()
                .or(ty.original_name.as_deref())
                .filter(|name| identifier(name))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("debug_type_{}", &digest(ty.id.as_bytes())[..16]));
            plan.emitted.insert(ty.id.clone(), proposed);
        }
    }
    distinguish_proven_aliases(&mut plan, &types)?;
    let mut text = String::new();
    for (id, name) in &plan.emitted {
        match types[id.as_str()].kind {
            DebugTypeKind::Struct { .. } => text.push_str(&format!("struct {name};\n")),
            DebugTypeKind::Union { .. } => text.push_str(&format!("union {name};\n")),
            _ => {}
        }
    }
    let mut done = BTreeSet::new();
    for id in plan.emitted.keys() {
        emit_visit(id, &types, &plan, &mut BTreeSet::new(), &mut done, &mut text, 0)?;
    }
    plan.names = plan.emitted.values().cloned().collect();
    plan.names.sort();
    plan.declarations = text;
    Ok(plan)
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value, ApiError> {
    value.get(key).ok_or_else(|| invalid(format!("native counterpart lacks {key}")))
}

fn number(value: &Value, key: &str, expected: u64) -> Result<(), ApiError> {
    if required(value, key)?.as_u64() != Some(expected) {
        return Err(invalid(format!("native {key} differs from explicit producer fact")));
    }
    Ok(())
}

fn enum_wire_bits(text: &str, width: u64, encoding: DebugScalarEncoding, native_wire: bool) -> Option<u128> {
    let bits = u32::try_from(width.checked_mul(8)?).ok()?;
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return None;
    }
    let modulus = 1u128.checked_shl(bits)?;
    let mask = modulus.checked_sub(1)?;
    let value = text.parse::<i128>().ok()?;
    if value < 0 {
        if encoding != DebugScalarEncoding::Signed {
            return None;
        }
        let magnitude = u128::try_from(value.checked_neg()?).ok()?;
        if magnitude > modulus.checked_shr(1)? {
            return None;
        }
        return Some(modulus.checked_sub(magnitude)? & mask);
    }
    let value = u128::try_from(value).ok()?;
    let maximum = if native_wire {
        // TypeEnum's structural wire value is an unsigned 64-bit carrier, not the producer's width.
        u128::from(u64::MAX)
    } else if encoding == DebugScalarEncoding::Signed {
        modulus.checked_shr(1)?.checked_sub(1)?
    } else if encoding == DebugScalarEncoding::Unsigned {
        mask
    } else {
        return None;
    };
    (value <= maximum).then_some(value & mask)
}

fn shape(
    id: &str,
    value: &Value,
    types: &BTreeMap<&str, &DebugType>,
    plan: &Plan,
    default_model: &str,
    expand: bool,
    depth: usize,
) -> Result<(), ApiError> {
    if depth > MAX_DEBUG_DEPTH {
        return Err(invalid("native comparison depth exceeds 32"));
    }
    let ty = types.get(id).ok_or_else(|| invalid("missing producer identity during native comparison"))?;
    if !expand {
        let expected = if let Some(name) = plan.emitted.get(id) {
            Some(name.clone())
        } else if matches!(ty.kind, DebugTypeKind::Scalar { .. }) {
            Some(scalar(ty)?)
        } else {
            None
        };
        if let Some(expected) = expected {
            if value.get("reference").and_then(Value::as_str) != Some(&expected) {
                return Err(invalid("native type reference differs from the source-ID-bound declaration"));
            }
            return Ok(());
        }
    }
    if let Some(size) = extent(id, types, 0).filter(|size| *size > 0) {
        number(value, "size", size)?
    }
    if let Some(alignment) = ty.alignment {
        number(value, "alignment", alignment)?
    }
    let recurse = |id: &str, value: &Value| shape(id, value, types, plan, default_model, false, depth + 1);
    match &ty.kind {
        DebugTypeKind::Pointer { target } => {
            number(value, "kind", 9)?;
            recurse(target, required(value, "target")?)?;
        }
        DebugTypeKind::Array { element, count: Some(count), stride } => {
            number(value, "kind", 7)?;
            number(value, "length", *count)?;
            if extent(element, types, 0) != stride.or_else(|| extent(element, types, 0)) {
                return Err(invalid("producer array stride is not represented by the native element"));
            }
            recurse(element, required(value, "element")?)?;
        }
        DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } => {
            number(value, "kind", if matches!(ty.kind, DebugTypeKind::Struct { .. }) { 4 } else { 3 })?;
            let fields = required(value, "fields")?.as_array().ok_or_else(|| invalid("invalid native field list"))?;
            if fields.len() != members.len() {
                return Err(invalid("native/producer field count differs"));
            }
            for (field, member) in fields.iter().zip(members) {
                if field.get("name").and_then(Value::as_str) != member.name.as_deref() {
                    return Err(invalid("native/producer member name differs"));
                }
                number(field, "offset", member.byte_offset)?;
                recurse(&member.type_id, required(field, "type")?)?;
            }
        }
        DebugTypeKind::Enum { underlying, values } => {
            let (encoding, width) =
                resolved_integer(underlying, types, 0).ok_or_else(|| invalid("unsupported enum encoding/width"))?;
            let kind = match encoding {
                DebugScalarEncoding::Signed => 14,
                DebugScalarEncoding::Unsigned => 13,
                _ => return Err(invalid("unsupported enum encoding")),
            };
            number(value, "kind", kind)?;
            let entries = required(value, "enum_values")?.as_array().ok_or_else(|| invalid("invalid native enum"))?;
            let actual: BTreeMap<_, _> = entries
                .iter()
                .map(|value| (value.get("name").and_then(Value::as_str), value.get("value").and_then(Value::as_str)))
                .collect();
            if entries.len() != values.len()
                || values.iter().any(|entry| {
                    let Some(Some(text)) = actual.get(&Some(entry.name.as_str())) else { return true };
                    let Some(expected) = enum_wire_bits(&entry.value, width, encoding, false) else { return true };
                    let Some(actual) = enum_wire_bits(text, width, encoding, true) else { return true };
                    expected != actual
                })
            {
                return Err(invalid("native enum values differ"));
            }
        }
        DebugTypeKind::Typedef { target, .. } => recurse(target, required(value, "typedef")?)?,
        DebugTypeKind::Function { convention: model, parameters, return_type, variadic } => {
            number(value, "kind", 11)?;
            let native_model = required(value, "calling_convention")?
                .as_str()
                .ok_or_else(|| invalid("native callback lacks explicit convention"))?;
            let requested = projected_convention(model, plan.unified_windows_x64)?;
            let expected_model = if requested.is_empty() { default_model } else { requested };
            if native_model != expected_model
                || required(value, "signature_known")?.as_bool() != Some(true)
                || required(value, "variadic")?.as_bool() != Some(*variadic)
            {
                return Err(invalid("native callback declaration/convention differs"));
            }
            recurse(return_type, required(value, "return_type")?)?;
            let native_parameters =
                required(value, "parameters")?.as_array().ok_or_else(|| invalid("invalid callback parameters"))?;
            if native_parameters.len() != parameters.len() {
                return Err(invalid("callback parameter count differs"));
            }
            for (parameter, id) in native_parameters.iter().zip(parameters) {
                recurse(id, required(parameter, "type")?)?;
            }
        }
        _ => return Err(invalid("unsupported expanded producer shape")),
    }
    Ok(())
}

pub(super) fn compare(
    report: &DebugTypeReport,
    plan: &Plan,
    native: &[NamedType],
    default_model: &str,
) -> Result<(), ApiError> {
    if default_model.is_empty() || default_model.len() > 256 || default_model.chars().any(char::is_control) {
        return Err(invalid("missing or invalid independently measured native default calling convention"));
    }
    let types: BTreeMap<_, _> = report.types.iter().map(|ty| (ty.id.as_str(), ty)).collect();
    if native.len() != plan.names.len() {
        return Err(invalid("native root count differs from the complete producer plan"));
    }
    for (id, name) in &plan.emitted {
        let counterpart =
            native.iter().find(|ty| ty.name == *name).ok_or_else(|| invalid("native parser omitted an owned root"))?;
        let producer = types[id.as_str()];
        let expected_kind = match producer.kind {
            DebugTypeKind::Struct { .. } => NamedTypeKind::Struct,
            DebugTypeKind::Union { .. } => NamedTypeKind::Union,
            DebugTypeKind::Enum { .. } => NamedTypeKind::Enum,
            DebugTypeKind::Typedef { .. } | DebugTypeKind::Function { .. } => NamedTypeKind::Typedef,
            _ => return Err(invalid("unexpected named producer root")),
        };
        if counterpart.incomplete
            || counterpart.kind != expected_kind
            || extent(id, &types, 0).filter(|size| *size > 0).is_some_and(|size| counterpart.size != Some(size))
            || producer.alignment.is_some_and(|alignment| counterpart.alignment.map(u64::from) != Some(alignment))
        {
            return Err(invalid(format!("native kind/size/alignment differs for {name:?}")));
        }
        let identity = counterpart.identity.as_ref().ok_or_else(|| invalid("native root lacks structural identity"))?;
        // A named function is emitted as a typedef to an anonymous declared callback.
        let identity = if matches!(producer.kind, DebugTypeKind::Function { .. }) {
            required(identity, "typedef")?
        } else {
            identity
        };
        shape(id, identity, &types, plan, default_model, true, 0)?;
        if counterpart.dependencies.iter().any(|dependency| !plan.names.contains(dependency)) {
            return Err(invalid("native dependency closure contains an unowned non-core type"));
        }
        if let DebugTypeKind::Struct { members } | DebugTypeKind::Union { members } = &producer.kind {
            if counterpart.fields.len() != members.len() {
                return Err(invalid("native field metadata was truncated"));
            }
            for (field, member) in counterpart.fields.iter().zip(members) {
                if field.name.as_str() != member.name.as_deref().unwrap_or("")
                    || field.offset != member.byte_offset
                    || extent(&member.type_id, &types, 0)
                        .filter(|size| *size > 0)
                        .is_some_and(|size| field.size != Some(size))
                {
                    return Err(invalid("native member storage differs from producer facts"));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn signature(report: &DebugTypeReport, plan: &Plan, id: &str) -> Result<String, ApiError> {
    if !plan.accepted.contains(id) {
        return Err(invalid("signature dependency is preview-only"));
    }
    let types: BTreeMap<_, _> = report.types.iter().map(|ty| (ty.id.as_str(), ty)).collect();
    if !matches!(types.get(id).map(|ty| &ty.kind), Some(DebugTypeKind::Function { .. })) {
        return Err(invalid("signature does not reference a producer function type"));
    }
    Ok(format!("{};", declaration(id, "debug_signature", &types, &plan.emitted, plan.unified_windows_x64, 0, true)?))
}
