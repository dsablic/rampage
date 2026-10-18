//! Bounded, read-only consistency assertions over consumer-measured native named types.

use std::collections::BTreeSet;
use std::ffi::{CString, c_char};
use std::io::{self, Write};

use serde_json::Value;

use crate::type_library::{MAX_TYPE_ITEMS, MAX_TYPE_JSON_BYTES, validate_type_name};
use crate::{DataOrganization, Decompiler, Error, FFI_LOCK, NamedType, Opaque, ffi_result};

unsafe extern "C" {
    fn rampage_decomp_assert_named_shape(handle: *mut Opaque, name: *const c_char) -> *const c_char;
    fn rampage_decomp_assert_type_model(
        handle: *mut Opaque,
        language: *const c_char,
        pointer: u8,
        int: u8,
        long: u8,
    ) -> *const c_char;
}

fn invalid(message: &str) -> Error {
    Error::Ghidra(format!("named type assertion: {message}"))
}

fn text(value: &str, empty: bool) -> Result<(), Error> {
    if (!empty && value.is_empty()) || value.len() > 256 || value.contains('\0') {
        return Err(invalid("invalid or over-budget text (256 bytes)"));
    }
    Ok(())
}

fn identity(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    *nodes += 1;
    if depth > 32 || *nodes > 4096 {
        return Err(invalid("identity depth/graph limit exceeded (32/4096)"));
    }
    match value {
        Value::String(value) => text(value, true)?,
        Value::Array(values) => {
            if values.len() > MAX_TYPE_ITEMS {
                return Err(invalid("identity collection limit exceeded (256)"));
            }
            for value in values {
                identity(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            if values.len() > 32 {
                return Err(invalid("identity key limit exceeded"));
            }
            if values.get("signature_known") == Some(&Value::Bool(false))
                || values.contains_key("abi_signature")
                || values
                    .get("kind")
                    .and_then(Value::as_u64)
                    .is_some_and(|kind| !matches!(kind, 3 | 4 | 7 | 9..=14 | 17))
            {
                return Err(invalid("unsupported native structural identity or unknown callback declaration"));
            }
            for (key, value) in values {
                text(key, false)?;
                identity(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct ByteBudget(usize);

impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| io::Error::other("named type JSON exceeds 1 MiB"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// No cloning, output allocation or native queries before this entire preflight succeeds.
pub(crate) fn validate_named_types(
    language_id: &str,
    organization: DataOrganization,
    expected: &[NamedType],
) -> Result<(), Error> {
    text(language_id, false)?;
    if language_id.split(':').count() != 5
        || !matches!(organization.pointer, 4 | 8)
        || !matches!(organization.int, 2 | 4 | 8)
        || !matches!(organization.long, 4 | 8)
        || expected.is_empty()
        || expected.len() > MAX_TYPE_ITEMS
    {
        return Err(invalid("invalid target organization or root count (1..256)"));
    }
    let mut names = BTreeSet::new();
    let mut nodes = 0;
    for ty in expected {
        validate_type_name(&ty.name)?;
        if !names.insert(ty.name.as_str()) {
            return Err(invalid("duplicate/conflicting named root"));
        }
        if ty.incomplete
            || ty.fields.len() > MAX_TYPE_ITEMS
            || ty.enum_values.len() > MAX_TYPE_ITEMS
            || ty.dependencies.len() > MAX_TYPE_ITEMS
            || ty.by_value_dependencies.len() > MAX_TYPE_ITEMS
            || ty.packing.is_some_and(|packing| !matches!(packing, 1 | 2 | 4 | 8 | 16))
        {
            return Err(invalid("incomplete type or item/packing bounds exceeded"));
        }
        let shape = ty
            .identity
            .as_ref()
            .filter(|value| value.is_object())
            .ok_or_else(|| invalid("missing structural identity"))?;
        if shape.get("kind").and_then(Value::as_u64).is_none() {
            return Err(invalid("named root requires an expanded native structural identity"));
        }
        let has_no_object_size = matches!(shape.get("kind").and_then(Value::as_u64), Some(11 | 17));
        if (has_no_object_size && (ty.size.is_some() || ty.alignment.is_some()))
            || (!has_no_object_size
                && (ty.size.is_none_or(|size| size == 0 || size > MAX_TYPE_JSON_BYTES as u64)
                    || ty.alignment.is_none_or(|alignment| !alignment.is_power_of_two() || alignment > 16)))
        {
            return Err(invalid("missing or unsupported native size/alignment"));
        }
        identity(shape, 0, &mut nodes)?;
        if let Some(target) = &ty.target {
            text(target, false)?;
        }
        let mut field_names = BTreeSet::new();
        for field in &ty.fields {
            text(&field.name, false)?;
            text(&field.type_name, false)?;
            if !field_names.insert(field.name.as_str())
                || field.size.is_none_or(|size| size == 0)
                || field.offset.checked_add(field.size.unwrap_or(0)).is_none_or(|end| Some(end) > ty.size)
            {
                return Err(invalid("duplicate/incomplete/out-of-range field"));
            }
            let shape = field
                .identity
                .as_ref()
                .filter(|value| value.is_object())
                .ok_or_else(|| invalid("missing field structural identity"))?;
            identity(shape, 0, &mut nodes)?;
        }
        let mut enum_names = BTreeSet::new();
        for entry in &ty.enum_values {
            text(&entry.name, false)?;
            text(&entry.value, false)?;
            if !enum_names.insert(entry.name.as_str()) || entry.value.parse::<i128>().is_err() {
                return Err(invalid("duplicate or invalid enum value"));
            }
        }
        for dependency in ty.dependencies.iter().chain(&ty.by_value_dependencies) {
            text(dependency, false)?;
        }
        if let Some(callback) = &ty.callback {
            text(&callback.return_type, false)?;
            text(callback.calling_convention.as_deref().ok_or_else(|| invalid("missing callback model"))?, false)?;
            if callback.parameters.len() > MAX_TYPE_ITEMS {
                return Err(invalid("callback parameter limit exceeded (256)"));
            }
            for parameter in &callback.parameters {
                text(&parameter.name, true)?;
                text(&parameter.type_name, false)?;
            }
        }
    }
    for ty in expected {
        if ty.dependencies.iter().any(|name| !names.contains(name.as_str()))
            || ty.by_value_dependencies.iter().any(|name| !ty.dependencies.contains(name))
        {
            return Err(invalid("expected roots omit a named dependency"));
        }
        if ty.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || ty.by_value_dependencies.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("dependencies must be unique and in native sorted order"));
        }
    }
    serde_json::to_writer(ByteBudget(MAX_TYPE_JSON_BYTES), expected)
        .map_err(|_| invalid("expected records exceed native JSON limit (1 MiB)"))?;
    Ok(())
}

impl Decompiler {
    /// Rechecks the live language/compiler and widths, then independently queries each exact named root.
    /// Every non-core dependency must also be supplied; complete metadata is compared without mutation.
    /// Alignments are consumer measurements, not producer facts. This analyst assertion authenticates
    /// neither the declarations nor producer layout, and must be repeated after native type changes.
    pub fn assert_named_types(
        &self,
        language_id: &str,
        organization: DataOrganization,
        expected: &[NamedType],
    ) -> Result<(), Error> {
        validate_named_types(language_id, organization, expected)?;
        let language = CString::new(language_id).map_err(|_| invalid("invalid language ID"))?;
        {
            let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            // SAFETY: live serialized handle and bounded language string; this native check is read-only.
            ffi_result(unsafe {
                rampage_decomp_assert_type_model(
                    self.handle,
                    language.as_ptr(),
                    organization.pointer,
                    organization.int,
                    organization.long,
                )
            })?;
        }
        for ty in expected {
            let name = CString::new(ty.name.as_str()).map_err(|_| invalid("invalid type name"))?;
            {
                let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
                // SAFETY: live serialized handle and preflighted name; native traversal does not intern types.
                ffi_result(unsafe { rampage_decomp_assert_named_shape(self.handle, name.as_ptr()) })?;
            }
            let actual = self.get_type(&ty.name)?;
            if actual != *ty {
                return Err(invalid(&format!("native metadata differs for {:?}", ty.name)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::layout_wire::decode_worker;

    #[test]
    fn named_wire_preflight_admits_native_numeric_kinds_but_bounds_payload_before_serde() {
        let valid = br#"{"operations":[{"types":[{"identity":{"kind":4,"fields":[]}}],
            "op":"assert_named_types"}]}"#;
        assert!(decode_worker(valid, |_| Ok(())).is_ok());
        let arrays =
            format!(r#"{{"operations":[{{"types":[{}],"\u006fp":"assert_named_types"}}]}}"#, vec!["{}"; 257].join(","));
        let text =
            format!(r#"{{"operations":[{{"types":[{{"name":"{}"}}],"op":"assert_named_types"}}]}}"#, "x".repeat(257));
        let too_many_bytes = format!(
            r#"{{"operations":[{{"types":[],"op":"assert_named_types","extra":[{}]}}]}}"#,
            " ".repeat(crate::type_library::MAX_TYPE_JSON_BYTES)
        );
        for forged in [arrays, text, too_many_bytes] {
            let decoded = Cell::new(false);
            assert!(
                decode_worker(forged.as_bytes(), |_| {
                    decoded.set(true);
                    Ok(())
                })
                .is_err()
            );
            assert!(!decoded.get(), "wire bounds must run before tagged-enum buffering");
        }
    }
}
