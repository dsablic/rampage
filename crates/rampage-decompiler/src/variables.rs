use serde::{Deserialize, Serialize};

use crate::results::{Storage, StorageKind, StorageUseRange};
use crate::{Decompiler, Error, FFI_LOCK, Opaque, ffi_result};
use std::ffi::{CString, c_char};

/// Exact whole-symbol mapping identity. Use ranges are inclusive definition/use selectors, not live ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariableStorage {
    pub kind: StorageKind,
    pub space: String,
    #[serde(with = "hex_address")]
    pub address: u64,
    #[serde(deserialize_with = "selector_size")]
    pub size: u32,
    pub use_ranges: Vec<StorageUseRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalOverride {
    pub storage: VariableStorage,
    pub name: Option<String>,
    pub data_type: Option<String>,
}

/// Checks the bounded ASCII C identifier accepted for a native local or parameter name.
pub fn validate_local_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .enumerate()
            .all(|(index, ch)| ch == b'_' || ch.is_ascii_alphabetic() || (index != 0 && ch.is_ascii_digit()))
    {
        return Err(Error::Ghidra("local name requires a bounded C identifier".to_owned()));
    }
    if matches!(
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
    ) {
        return Err(Error::Ghidra("local name cannot be a reserved C keyword".to_owned()));
    }
    Ok(())
}

fn selector_size<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let size = hex_address::deserialize(deserializer)?;
    u32::try_from(size).map_err(|_| serde::de::Error::custom("variable storage size exceeds 32 bits"))
}

impl TryFrom<&Storage> for VariableStorage {
    type Error = Error;

    fn try_from(storage: &Storage) -> Result<Self, Error> {
        if storage.dynamic_hash.is_some()
            || storage.symbol_offset != Some(0)
            || storage.is_piece != Some(false)
            || storage.join_logical_size.is_some()
            || !storage.pieces.is_empty()
        {
            return Err(Error::Ghidra("variable selector requires a complete whole mapping".to_owned()));
        }
        let key = Self {
            kind: storage.kind,
            space: storage.space.clone().ok_or_else(|| Error::Ghidra("missing storage space".to_owned()))?,
            address: storage.address.ok_or_else(|| Error::Ghidra("missing storage address".to_owned()))?,
            size: storage.size,
            use_ranges: storage
                .use_ranges
                .clone()
                .ok_or_else(|| Error::Ghidra("missing storage use ranges".to_owned()))?,
        };
        key.validate()?;
        Ok(key)
    }
}

impl VariableStorage {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.kind, StorageKind::Processor | StorageKind::Spacebase)
            || self.space.is_empty()
            || self.space.len() > 128
            || self.space.contains('\0')
            || self.size == 0
            || self.size > 1048576
            || self.address.checked_add(u64::from(self.size) - 1).is_none()
            || self.use_ranges.len() > 256
        {
            return Err(Error::Ghidra("unsupported or incomplete variable storage selector".to_owned()));
        }
        for (index, range) in self.use_ranges.iter().enumerate() {
            if range.space.is_empty()
                || range.space.len() > 128
                || range.space.contains('\0')
                || range.start > range.end
                || self.use_ranges[..index].iter().any(|other| other.space == range.space && other.end >= range.start)
            {
                return Err(Error::Ghidra("invalid or noncanonical variable use ranges".to_owned()));
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_overrides(overrides: &[LocalOverride]) -> Result<(), Error> {
    if overrides.len() > 256 {
        return Err(Error::Ghidra("local override count exceeds 256".to_owned()));
    }
    let mut bytes = 0usize;
    for (index, entry) in overrides.iter().enumerate() {
        entry.storage.validate()?;
        if entry.name.is_none() && entry.data_type.is_none() {
            return Err(Error::Ghidra("local override requires a name or data type".to_owned()));
        }
        if let Some(name) = &entry.name {
            validate_local_name(name)?;
            bytes += name.len();
        }
        if let Some(data_type) = &entry.data_type {
            if data_type.trim().is_empty() || data_type.len() > 4096 || data_type.contains('\0') {
                return Err(Error::Ghidra("invalid local data type declaration".to_owned()));
            }
            bytes += data_type.len();
        }
        bytes += entry.storage.space.len();
        bytes += entry.storage.use_ranges.iter().map(|range| range.space.len()).sum::<usize>();
        if bytes > 65536 {
            return Err(Error::Ghidra("local override text exceeds 64 KiB".to_owned()));
        }
        if overrides[..index]
            .iter()
            .any(|other| other.storage == entry.storage || (entry.name.is_some() && other.name == entry.name))
        {
            return Err(Error::Ghidra("duplicate local override selector or name".to_owned()));
        }
    }
    Ok(())
}

#[repr(C)]
pub(crate) struct NativeRange {
    pub(crate) space: *const c_char,
    pub(crate) start: u64,
    pub(crate) end: u64,
}

#[repr(C)]
pub(crate) struct NativeOverride {
    pub(crate) kind: u32,
    pub(crate) space: *const c_char,
    pub(crate) address: u64,
    pub(crate) size: u32,
    pub(crate) ranges: *const NativeRange,
    pub(crate) range_count: usize,
    pub(crate) name: *const c_char,
    pub(crate) data_type: *const c_char,
}

unsafe extern "C" {
    fn rampage_decomp_local_variables(
        handle: *mut Opaque,
        function: u64,
        overrides: *const NativeOverride,
        count: usize,
    ) -> *const c_char;
}

impl Decompiler {
    /// Replaces this function's pending native overrides. Exact mapping resolution occurs at decompilation.
    /// An empty slice clears overrides; no user locks remain between decompilations.
    pub fn set_variable_overrides(&mut self, function: u64, overrides: &[LocalOverride]) -> Result<(), Error> {
        self.valid_address(function)?;
        validate_overrides(overrides)?;
        let mut strings = Vec::new();
        let mut string = |value: &str| {
            let value = CString::new(value).expect("validated local override string");
            let pointer = value.as_ptr();
            strings.push(value);
            pointer
        };
        let ranges: Vec<Vec<_>> = overrides
            .iter()
            .map(|entry| {
                entry
                    .storage
                    .use_ranges
                    .iter()
                    .map(|range| NativeRange { space: string(&range.space), start: range.start, end: range.end })
                    .collect()
            })
            .collect();
        let native: Vec<_> = overrides
            .iter()
            .zip(&ranges)
            .map(|(entry, ranges)| NativeOverride {
                kind: u32::from(entry.storage.kind == StorageKind::Spacebase),
                space: string(&entry.storage.space),
                address: entry.storage.address,
                size: entry.storage.size,
                ranges: ranges.as_ptr(),
                range_count: ranges.len(),
                name: entry.name.as_deref().map(&mut string).unwrap_or(std::ptr::null()),
                data_type: entry.data_type.as_deref().map(&mut string).unwrap_or(std::ptr::null()),
            })
            .collect();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: validated records and all owned strings/ranges outlive this serialized call; native copies them.
        ffi_result(unsafe { rampage_decomp_local_variables(self.handle, function, native.as_ptr(), native.len()) })
    }
}

pub(crate) mod hex_address {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{value:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Address {
            Number(u64),
            Text(String),
        }
        match Address::deserialize(deserializer)? {
            Address::Number(value) => Ok(value),
            Address::Text(text) => text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .filter(|digits| !digits.is_empty() && digits.bytes().all(|ch| ch.is_ascii_hexdigit()))
                .and_then(|digits| u64::from_str_radix(digits, 16).ok())
                .ok_or_else(|| serde::de::Error::custom("expected an unsigned number or hexadecimal address")),
        }
    }
}

pub(crate) mod optional_hex_address {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|value| format!("0x{value:x}")).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Address(#[serde(with = "super::hex_address")] u64);
        Option::<Address>::deserialize(deserializer).map(|value| value.map(|address| address.0))
    }
}
