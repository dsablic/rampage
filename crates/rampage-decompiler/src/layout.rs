//! Read-only verification of already parsed, complete, flat C structs. This is not an ABI importer.
//! Assertions are ephemeral: reassert for each engine/session and selected compiler specification rebuild.
//! Serde visitors check schema bounds, but third-party deserializers may allocate/buffer before calling them.
//! Use `PlainStructLayout::from_wire` for bounded decoding of isolated JSON, not arbitrary `Deserialize` calls.

use std::ffi::{CString, c_char};

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Decompiler, Error, FFI_LOCK, Opaque, ffi_result};

pub const MAX_LAYOUT_FIELDS: usize = 128;
pub const MAX_LAYOUT_NAME_BYTES: usize = 128;
pub const MAX_LAYOUT_TEXT_BYTES: usize = 32 * 1024;
pub const MAX_LAYOUT_SIZE: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarKind {
    Void,
    SignedInteger,
    UnsignedInteger,
    SignedCharacter,
    UnsignedCharacter,
    Float,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutScalar {
    #[serde(deserialize_with = "bounded_name")]
    pub name: String,
    pub kind: ScalarKind,
    pub size: u32,
    pub alignment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayoutType {
    Scalar {
        scalar: LayoutScalar,
    },
    /// Only byte-addressed native-width pointers to void or an admitted scalar are supported.
    Pointer {
        #[serde(deserialize_with = "bounded_name")]
        name: String,
        size: u32,
        alignment: u32,
        pointee: LayoutScalar,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutField {
    #[serde(deserialize_with = "bounded_name")]
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub ty: LayoutType,
}

/// Measured from the selected native type factory, including external GHIDRA_INSTALL_DIR specifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutOrganization {
    pub pointer_size: u32,
    pub int_size: u32,
    pub long_size: u32,
    /// Native primitive alignment map for byte sizes 1, 2, 4 and 8, respectively.
    pub scalar_alignments: [u32; 4],
}

/// An explicit bounded plain-struct schema. No padding fields or recursive type graph are synthesized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainStructLayout {
    #[serde(deserialize_with = "bounded_name")]
    pub name: String,
    pub size: u32,
    pub alignment: u32,
    pub organization: LayoutOrganization,
    #[serde(deserialize_with = "bounded_fields")]
    pub fields: Vec<LayoutField>,
}

fn invalid(message: &str) -> Error {
    Error::Ghidra(format!("plain-struct layout: {message}"))
}

fn identifier(name: &str, empty: bool) -> bool {
    if name.is_empty() {
        return empty;
    }
    name.len() <= MAX_LAYOUT_NAME_BYTES
        && name.bytes().next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn alignment(value: u32) -> bool {
    value.is_power_of_two() && value <= 8
}

fn scalar_valid(scalar: &LayoutScalar, allow_void: bool) -> bool {
    if !identifier(&scalar.name, false) || !alignment(scalar.alignment) {
        return false;
    }
    if scalar.size != 0 && scalar.alignment > scalar.size {
        return false;
    }
    match scalar.kind {
        ScalarKind::Void => allow_void && scalar.size == 0 && scalar.alignment == 1,
        ScalarKind::SignedInteger | ScalarKind::UnsignedInteger => matches!(scalar.size, 1 | 2 | 4 | 8),
        ScalarKind::SignedCharacter | ScalarKind::UnsignedCharacter | ScalarKind::Bool => scalar.size == 1,
        ScalarKind::Float => matches!(scalar.size, 4 | 8),
    }
}

impl PlainStructLayout {
    /// Decodes isolated JSON only after an allocation-free raw-wire budget/escape/duplicate-key preflight.
    /// Wire caps: 384 KiB encoded, 64 KiB total decoded text, 2048 nodes, depth 12, 128 entries/array,
    /// 32 keys/object, 128 bytes/string or key (32 bytes for tags). Schema bounds are checked afterward.
    /// Arbitrary third-party `Deserialize` implementations do not provide this allocation-safety contract.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, Error> {
        crate::layout_wire::preflight_layout(bytes).map_err(|_| invalid("invalid or over-budget layout wire"))?;
        let layout: Self = serde_json::from_slice(bytes).map_err(|_| invalid("invalid layout wire schema"))?;
        layout.validate()?;
        Ok(layout)
    }

    /// Checks caller-owned input before cloning, serialization, output allocation, or native access.
    pub fn validate(&self) -> Result<(), Error> {
        if !identifier(&self.name, false)
            || self.size == 0
            || self.size > MAX_LAYOUT_SIZE
            || !alignment(self.alignment)
            || !self.size.is_multiple_of(self.alignment)
            || self.fields.is_empty()
            || self.fields.len() > MAX_LAYOUT_FIELDS
        {
            return Err(invalid("invalid name, size, alignment or field count"));
        }
        let organization = &self.organization;
        if organization.pointer_size != 8
            || organization.int_size != 4
            || organization.long_size != 8
            || !organization
                .scalar_alignments
                .iter()
                .enumerate()
                .all(|(index, &value)| alignment(value) && value <= 1 << index)
        {
            return Err(invalid("unsupported compiler organization"));
        }
        let mut text_bytes = self.name.len();
        let mut previous_end = 0;
        for (index, field) in self.fields.iter().enumerate() {
            if !identifier(&field.name, false) || self.fields[..index].iter().any(|other| other.name == field.name) {
                return Err(invalid("invalid or duplicate field name"));
            }
            let (size, align, type_bytes) = match &field.ty {
                LayoutType::Scalar { scalar } if scalar_valid(scalar, false) => {
                    (scalar.size, scalar.alignment, scalar.name.len())
                }
                LayoutType::Pointer { name, size, alignment, pointee }
                    if identifier(name, true)
                        && *size == organization.pointer_size
                        && crate::layout::alignment(*alignment)
                        && scalar_valid(pointee, true) =>
                {
                    (*size, *alignment, name.len() + pointee.name.len())
                }
                _ => return Err(invalid("unsupported field type descriptor")),
            };
            let end = field.offset.checked_add(field.size).ok_or_else(|| invalid("field end overflows"))?;
            if field.size != size
                || field.offset < previous_end
                || end > self.size
                || !field.offset.is_multiple_of(align)
                || align > self.alignment
            {
                return Err(invalid("invalid field size, offset, overlap or alignment"));
            }
            text_bytes = text_bytes
                .checked_add(field.name.len() + type_bytes)
                .filter(|&bytes| bytes <= MAX_LAYOUT_TEXT_BYTES)
                .ok_or_else(|| invalid("cumulative name/type byte limit exceeded"))?;
            previous_end = end;
        }
        Ok(())
    }
}

fn bounded_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct NameVisitor;
    impl Visitor<'_> for NameVisitor {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a layout name of at most 128 bytes")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > MAX_LAYOUT_NAME_BYTES {
                return Err(E::custom("layout name byte limit exceeded"));
            }
            Ok(value.to_owned())
        }
    }
    deserializer.deserialize_str(NameVisitor)
}

fn bounded_fields<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<LayoutField>, D::Error> {
    struct FieldsVisitor;
    impl<'de> Visitor<'de> for FieldsVisitor {
        type Value = Vec<LayoutField>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("at most 128 plain-struct fields")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut fields = Vec::new();
            let mut text_bytes = 0usize;
            while let Some(field) = sequence.next_element::<LayoutField>()? {
                if fields.len() == MAX_LAYOUT_FIELDS {
                    return Err(serde::de::Error::custom("layout field count limit exceeded"));
                }
                let type_bytes = match &field.ty {
                    LayoutType::Scalar { scalar } => scalar.name.len(),
                    LayoutType::Pointer { name, pointee, .. } => name.len() + pointee.name.len(),
                };
                text_bytes += field.name.len() + type_bytes;
                if text_bytes > MAX_LAYOUT_TEXT_BYTES {
                    return Err(serde::de::Error::custom("layout cumulative name/type byte limit exceeded"));
                }
                fields.push(field);
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_seq(FieldsVisitor)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeScalar {
    name: [u8; MAX_LAYOUT_NAME_BYTES + 1],
    kind: u32,
    size: u32,
    alignment: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeField {
    name: [u8; MAX_LAYOUT_NAME_BYTES + 1],
    type_name: [u8; MAX_LAYOUT_NAME_BYTES + 1],
    offset: u32,
    size: u32,
    alignment: u32,
    pointer: u32,
    scalar: NativeScalar,
}

#[repr(C)]
struct NativeLayout {
    name: [u8; MAX_LAYOUT_NAME_BYTES + 1],
    size: u32,
    alignment: u32,
    pointer_size: u32,
    int_size: u32,
    long_size: u32,
    scalar_alignments: [u32; 4],
    count: u32,
    fields: [NativeField; MAX_LAYOUT_FIELDS],
}

unsafe extern "C" {
    fn rampage_decomp_inspect_layout(
        handle: *mut Opaque,
        name: *const c_char,
        name_len: usize,
        layout: *mut NativeLayout,
    ) -> *const c_char;
}

fn native_text(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes.iter().position(|&byte| byte == 0).ok_or_else(|| invalid("unterminated native name"))?;
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("native name is not UTF-8"))?;
    if !identifier(text, true) {
        return Err(invalid("invalid native name"));
    }
    Ok(text)
}

fn native_name(bytes: &[u8]) -> Result<String, Error> {
    Ok(native_text(bytes)?.to_owned())
}

fn native_scalar(scalar: &NativeScalar) -> Result<LayoutScalar, Error> {
    let kind = match scalar.kind {
        0 => ScalarKind::Void,
        1 => ScalarKind::SignedInteger,
        2 => ScalarKind::UnsignedInteger,
        3 => ScalarKind::SignedCharacter,
        4 => ScalarKind::UnsignedCharacter,
        5 => ScalarKind::Float,
        6 => ScalarKind::Bool,
        _ => return Err(invalid("invalid native scalar category")),
    };
    Ok(LayoutScalar { name: native_name(&scalar.name)?, kind, size: scalar.size, alignment: scalar.alignment })
}

impl Decompiler {
    /// Inspects an existing type without parsing, repairing or mutating native types. Currently limited to
    /// x86-64 little-endian gcc/ELF organization; unsupported leaf shapes cause an atomic error.
    /// Inspection alone does not verify a producer's layout: assert an independently obtained schema instead.
    /// Bitfield refusal concerns retained native facts, not source syntax normalized away by the C parser.
    pub fn inspect_plain_struct(&self, name: &str) -> Result<PlainStructLayout, Error> {
        if !identifier(name, false) {
            return Err(invalid("invalid struct name"));
        }
        if self.language_id() != "x86:LE:64:default:gcc" {
            return Err(invalid("unsupported processor/compiler specification"));
        }
        let name_c = CString::new(name).map_err(|_| invalid("name contains NUL"))?;
        // Fixed-size POD is zero-initializable; native code publishes it only after full validation.
        let mut record: NativeLayout = unsafe { std::mem::zeroed() };
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: serialized live handle, bounded C name and writable fixed-size record throughout the call.
        ffi_result(unsafe { rampage_decomp_inspect_layout(self.handle, name_c.as_ptr(), name.len(), &mut record) })?;
        let count = usize::try_from(record.count).map_err(|_| invalid("invalid native field count"))?;
        if count == 0 || count > MAX_LAYOUT_FIELDS {
            return Err(invalid("invalid native field count"));
        }
        if record.size == 0 || record.size > MAX_LAYOUT_SIZE || !alignment(record.alignment) {
            return Err(invalid("invalid native struct size/alignment"));
        }
        let mut text_bytes = native_text(&record.name)?.len();
        for field in &record.fields[..count] {
            text_bytes += native_text(&field.name)?.len() + native_text(&field.scalar.name)?.len();
            if field.pointer != 0 {
                text_bytes += native_text(&field.type_name)?.len();
            }
            if text_bytes > MAX_LAYOUT_TEXT_BYTES {
                return Err(invalid("native cumulative name/type byte limit exceeded"));
            }
        }
        let mut fields = Vec::with_capacity(count);
        for field in &record.fields[..count] {
            let scalar = native_scalar(&field.scalar)?;
            let ty = match field.pointer {
                0 => LayoutType::Scalar { scalar },
                1 => LayoutType::Pointer {
                    name: native_name(&field.type_name)?,
                    size: field.size,
                    alignment: field.alignment,
                    pointee: scalar,
                },
                _ => return Err(invalid("invalid native pointer descriptor")),
            };
            fields.push(LayoutField { name: native_name(&field.name)?, offset: field.offset, size: field.size, ty });
        }
        let result = PlainStructLayout {
            name: native_name(&record.name)?,
            size: record.size,
            alignment: record.alignment,
            organization: LayoutOrganization {
                pointer_size: record.pointer_size,
                int_size: record.int_size,
                long_size: record.long_size,
                scalar_alignments: record.scalar_alignments,
            },
            fields,
        };
        result.validate()?;
        if result.name != name {
            return Err(invalid("native struct name differs from requested name"));
        }
        Ok(result)
    }

    /// Compares every field, leaf descriptor, offset, size, native alignment and compiler organization.
    /// Read-only and ephemeral: callers must reassert per engine/session/compiler-specification rebuild.
    /// Success supplies no persistence or provenance and does not enable general aggregate ABI recovery.
    pub fn assert_plain_struct_layout(&self, expected: &PlainStructLayout) -> Result<(), Error> {
        expected.validate()?;
        let actual = self.inspect_plain_struct(&expected.name)?;
        if actual != *expected {
            return Err(invalid("registered struct does not match the complete expected layout"));
        }
        Ok(())
    }
}
