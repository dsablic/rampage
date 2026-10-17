use std::ffi::{CStr, CString, c_char};

use serde::{Deserialize, Serialize};

use crate::{Decompiler, Error, FFI_LOCK, Opaque};

pub const MAX_TYPE_DECLARATION_BYTES: usize = 64 * 1024;
pub const MAX_TYPE_ITEMS: usize = 256;
pub const MAX_TYPE_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedTypeKind {
    Struct,
    Union,
    Enum,
    Typedef,
    Pointer,
    Array,
    Function,
    Void,
    Primitive,
}

/// Native Ghidra type metadata for the selected target/compiler, never the host ABI.
/// Unknown, incomplete, void, and function sizes/alignment are None rather than zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedType {
    /// Structural native identity, with named references terminating recursion and anonymous types expanded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<serde_json::Value>,
    pub name: String,
    pub kind: NamedTypeKind,
    pub size: Option<u64>,
    pub alignment: Option<u32>,
    pub incomplete: bool,
    pub packing: Option<u32>,
    pub fields: Vec<NamedTypeField>,
    pub enum_values: Vec<NamedEnumValue>,
    pub target: Option<String>,
    pub array_length: Option<u64>,
    pub callback: Option<NamedFunctionType>,
    /// Sorted direct named references, traversing anonymous pointers/arrays/functions only.
    /// Core builtins are excluded. Self references are retained.
    pub dependencies: Vec<String>,
    /// The subset requiring a complete by-value layout; pointer/callback edges are excluded.
    pub by_value_dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTypeField {
    /// Includes anonymous callback/array/pointer shape rather than relying on the display type name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<serde_json::Value>,
    pub name: String,
    pub offset: u64,
    pub type_name: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedEnumValue {
    pub name: String,
    /// Decimal native enum value, preserving signedness without JSON number precision loss.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedFunctionType {
    /// The selected native prototype model, not a convention guessed from lowered storage.
    #[serde(default)]
    pub calling_convention: Option<String>,
    pub return_type: String,
    pub variadic: bool,
    pub parameters: Vec<NamedTypeParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTypeParameter {
    pub name: String,
    pub type_name: String,
}

unsafe extern "C" {
    fn rampage_decomp_parse_type_library(
        handle: *mut Opaque,
        text: *const c_char,
        packing: u32,
        json: *mut *const c_char,
        length: *mut usize,
    ) -> *const c_char;
    fn rampage_decomp_type_inventory(
        handle: *mut Opaque,
        name: *const c_char,
        json: *mut *const c_char,
        length: *mut usize,
    ) -> *const c_char;
}

pub(crate) fn validate_library_input(declarations: &str, packing: Option<u32>) -> Result<(), Error> {
    if declarations.is_empty() || declarations.len() > MAX_TYPE_DECLARATION_BYTES || declarations.contains('\0') {
        return Err(Error::Ghidra("type declarations require 1..65536 bytes without NUL".to_owned()));
    }
    if packing.is_some_and(|packing| !matches!(packing, 1 | 2 | 4 | 8 | 16)) {
        return Err(Error::Ghidra("packing must be 1, 2, 4, 8, or 16".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_type_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > 256 || name.contains('\0') {
        return Err(Error::Ghidra("type query name requires 1..256 bytes without NUL".to_owned()));
    }
    Ok(())
}

unsafe fn decode(error: *const c_char, json: *const c_char, length: usize) -> Result<Vec<NamedType>, Error> {
    if !error.is_null() {
        return Err(Error::Ghidra(unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()));
    }
    if json.is_null() || length > MAX_TYPE_JSON_BYTES {
        return Err(Error::Ghidra("invalid native type inventory bounds".to_owned()));
    }
    let bytes = unsafe { std::slice::from_raw_parts(json.cast::<u8>(), length) };
    let types: Vec<NamedType> = serde_json::from_slice(bytes)
        .map_err(|error| Error::Ghidra(format!("invalid native type inventory: {error}")))?;
    if types.len() > MAX_TYPE_ITEMS
        || types.iter().any(|ty| {
            ty.fields.len() > MAX_TYPE_ITEMS
                || ty.enum_values.len() > MAX_TYPE_ITEMS
                || ty.dependencies.len() > MAX_TYPE_ITEMS
                || ty.by_value_dependencies.len() > MAX_TYPE_ITEMS
                || ty.callback.as_ref().is_some_and(|callback| callback.parameters.len() > MAX_TYPE_ITEMS)
        })
    {
        return Err(Error::Ghidra("native type inventory item limit exceeded".to_owned()));
    }
    Ok(types)
}

impl Decompiler {
    /// Registers a bounded batch of type-only C declarations and returns its named top-level roots,
    /// in declaration order. Nested named types remain available through get_type/type_inventory.
    /// Incidental forward types referenced by callbacks/pointers are not roots. A forward root completed
    /// later in the same batch is returned once with its final complete metadata.
    /// Parsing failures can poison this handle: build a fresh engine before committing persistent state.
    /// Packing is a maximum field alignment applied by Ghidra before dependent aggregates are laid out.
    /// Bitfields, preprocessing directives, and function/object declarations are rejected.
    pub fn parse_type_library(&mut self, declarations: &str, packing: Option<u32>) -> Result<Vec<NamedType>, Error> {
        validate_library_input(declarations, packing)?;
        let text = CString::new(declarations).map_err(|error| Error::Ghidra(error.to_string()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut json = std::ptr::null();
        let mut length = 0;
        // SAFETY: the handle and input stay valid; native output is consumed under FFI_LOCK.
        unsafe {
            let error = rampage_decomp_parse_type_library(
                self.handle,
                text.as_ptr(),
                packing.unwrap_or(0),
                &mut json,
                &mut length,
            );
            decode(error, json, length)
        }
    }

    /// Returns non-core named types in Ghidra's stable name order; fails rather than truncating.
    pub fn type_inventory(&self) -> Result<Vec<NamedType>, Error> {
        self.query_types(None)
    }

    /// Inspects exactly one native named type, including a builtin, without enumerating the inventory.
    pub fn get_type(&self, name: &str) -> Result<NamedType, Error> {
        validate_type_name(name)?;
        let mut types = self.query_types(Some(name))?;
        if types.len() != 1 {
            return Err(Error::Ghidra("native single-type query returned an invalid count".to_owned()));
        }
        Ok(types.remove(0))
    }

    fn query_types(&self, name: Option<&str>) -> Result<Vec<NamedType>, Error> {
        let name = name.map(CString::new).transpose().map_err(|error| Error::Ghidra(error.to_string()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut json = std::ptr::null();
        let mut length = 0;
        // SAFETY: the handle and optional name stay valid; output is consumed under FFI_LOCK.
        unsafe {
            let error = rampage_decomp_type_inventory(
                self.handle,
                name.as_ref().map_or(std::ptr::null(), |name| name.as_ptr()),
                &mut json,
                &mut length,
            );
            decode(error, json, length)
        }
    }
}
