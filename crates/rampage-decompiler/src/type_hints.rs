use std::ffi::{CString, c_char};

use serde::{Deserialize, Serialize};

use crate::variables::{NativeOverride, NativeRange};
use crate::{Decompiler, Error, FFI_LOCK, Opaque, VariableStorage, ffi_result};

/// Ephemeral native inference evidence, never an analyst name/type lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeHint {
    Parameter { index: u32, data_type: String },
    Return { data_type: String },
    Local { storage: VariableStorage, data_type: String },
}

pub(crate) fn validate_hints(hints: &[TypeHint]) -> Result<(), Error> {
    if hints.len() > 256 {
        return Err(Error::Ghidra("native type hint count exceeds 256".to_owned()));
    }
    let mut bytes = 0usize;
    for (index, hint) in hints.iter().enumerate() {
        let declaration = match hint {
            TypeHint::Parameter { index, data_type } => {
                if *index >= 256 {
                    return Err(Error::Ghidra("native parameter hint index exceeds 255".to_owned()));
                }
                data_type
            }
            TypeHint::Return { data_type } => data_type,
            TypeHint::Local { storage, data_type } => {
                storage.validate()?;
                bytes += storage.space.len() + storage.use_ranges.iter().map(|range| range.space.len()).sum::<usize>();
                data_type
            }
        };
        if declaration.trim().is_empty() || declaration.len() > 4096 || declaration.contains('\0') {
            return Err(Error::Ghidra("invalid native type hint declaration".to_owned()));
        }
        bytes += declaration.len();
        if bytes > 65536 {
            return Err(Error::Ghidra("native type hint text exceeds 64 KiB".to_owned()));
        }
        if hints[..index].iter().any(|other| match (hint, other) {
            (TypeHint::Parameter { index: a, .. }, TypeHint::Parameter { index: b, .. }) => a == b,
            (TypeHint::Return { .. }, TypeHint::Return { .. }) => true,
            (TypeHint::Local { storage: a, .. }, TypeHint::Local { storage: b, .. }) => a == b,
            _ => false,
        }) {
            return Err(Error::Ghidra("duplicate native type hint target".to_owned()));
        }
    }
    Ok(())
}

#[repr(C)]
struct NativeHint {
    kind: u32,
    index: u32,
    storage: NativeOverride,
}

unsafe extern "C" {
    fn rampage_decomp_type_hints(
        handle: *mut Opaque,
        function: u64,
        hints: *const NativeHint,
        count: usize,
    ) -> *const c_char;
}

impl Decompiler {
    /// Replaces pending weak evidence for one function; an empty slice clears it.
    /// Parsing uses the selected native type library/data organization, not the host ABI.
    /// Exact identities, widths and retention are checked during decompilation. Unsupported shapes or
    /// hints lost by native analysis fail explicitly. Analyst prototypes and local type locks win.
    /// When another function is decompiled, registered hinted direct call targets are analyzed to seed their
    /// recovered register-only CALL shape without prototype locks (at most 32 functions/256 call edges).
    pub fn set_type_hints(&mut self, function: u64, hints: &[TypeHint]) -> Result<(), Error> {
        self.valid_address(function)?;
        validate_hints(hints)?;
        let mut strings = Vec::new();
        let mut string = |value: &str| {
            let value = CString::new(value).expect("validated native hint string");
            let pointer = value.as_ptr();
            strings.push(value);
            pointer
        };
        let ranges: Vec<Vec<_>> = hints
            .iter()
            .map(|hint| match hint {
                TypeHint::Local { storage, .. } => storage
                    .use_ranges
                    .iter()
                    .map(|range| NativeRange { space: string(&range.space), start: range.start, end: range.end })
                    .collect(),
                _ => Vec::new(),
            })
            .collect();
        let native: Vec<_> = hints
            .iter()
            .zip(&ranges)
            .map(|(hint, ranges)| {
                let (kind, index, storage, declaration) = match hint {
                    TypeHint::Parameter { index, data_type } => (1, *index, None, data_type),
                    TypeHint::Return { data_type } => (2, 0, None, data_type),
                    TypeHint::Local { storage, data_type } => (0, 0, Some(storage), data_type),
                };
                NativeHint {
                    kind,
                    index,
                    storage: NativeOverride {
                        kind: u32::from(storage.is_some_and(|key| key.kind == crate::results::StorageKind::Spacebase)),
                        space: storage.map(|key| string(&key.space)).unwrap_or(std::ptr::null()),
                        address: storage.map_or(0, |key| key.address),
                        size: storage.map_or(0, |key| key.size),
                        ranges: ranges.as_ptr(),
                        range_count: ranges.len(),
                        name: std::ptr::null(),
                        data_type: string(declaration),
                    },
                }
            })
            .collect();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: all strings and range arrays remain owned until native registration copies the batch.
        ffi_result(unsafe { rampage_decomp_type_hints(self.handle, function, native.as_ptr(), native.len()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;
    use rampage_arch::Arch;

    unsafe extern "C" {
        fn rampage_decomp_test_hint_input_identity(handle: *mut Opaque, function: u64) -> *const c_char;
    }

    #[test]
    fn unrestricted_parameter_hint_never_types_a_later_unmapped_rdi_definition() {
        let code = [0x8b, 7, 0x0f, 0xaf, 0xc6, 3, 0x47, 4, 0xc3];
        let mut engine =
            Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &code, writable: false }]).unwrap();
        engine.parse_type_library("struct HintState { int4 gain; int4 bias; };", None).unwrap();
        engine.decompile(0x1000, "fields", false).unwrap();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: the live handle is serialized; the internal probe owns and clears its temporary native SSA nodes.
        ffi_result(unsafe { rampage_decomp_test_hint_input_identity(engine.handle, 0x1000) }).unwrap();
    }
}
