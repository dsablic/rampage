//! User annotations: names and comments, kept as an append-only log of edits.
//!
//! Every edit records the value it replaced, so undo is just another edit that restores it, and the log on disk
//! remains a complete history in JSON Lines that people and tools can read. Several processes (the UI, an MCP
//! server, the CLI) may share one log: each appends its own edits and picks up the others' through `refresh`.
//!
//! The binary beside a log can be rebuilt or replaced, and an address then may name different code. So a writer
//! that knows its image's SHA-256 logs it in an identity line (`{"image": "<hex>"}`) before the first edit it makes
//! on that image, and every edit is attributed to the identity line before it, or, in a log begun before identity
//! lines existed, to the first one. [`Annotations::warnings`] says when some edits were made on another image, or
//! when none can be attributed yet.
//!
//! Every reader caps unread raw bytes at 16 MiB, each line (including a newline-free tail) at 2 MiB, and records
//! at 8192 before serde. Complete records require exactly one syntactically valid JSON object and no trailing tokens.
//! Patch-bearing records require valid complete newline-terminated envelopes; torn records and incomplete batches refuse
//! the refresh instead of silently returning the unpatched image.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use rampage_decompiler::VariableStorage;
use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Name,
    Comment,
    Signature,
    Types,
    TypeLibrary,
    DebugTypes,
    Global,
    LocalName,
    LocalType,
    TypeHint,
    DataType,
    OperandType,
    Patch,
    /// An investigation ledger entry (see `crate::findings`), keyed by its id rather than an address.
    Finding,
}

/// An exact named data type or explicitly encoded string at an image address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataTypeAnnotation {
    pub type_name: Option<String>,
    pub count: u32,
    pub byte_length: u32,
    pub encoding: Option<DataStringEncoding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataStringEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Ascii,
}

/// An operand interpretation bound to the original instruction bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperandTypeAnnotation {
    pub operand: u8,
    pub kind: OperandTypeKind,
    pub type_name: String,
    pub instruction_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperandTypeKind {
    Enum,
    Offset,
}

pub fn parse_data_type(value: &str) -> Result<DataTypeAnnotation, String> {
    preflight_typed_value(value)?;
    let entry: DataTypeAnnotation =
        serde_json::from_str(value).map_err(|error| format!("invalid data type annotation: {error}"))?;
    validate_data_type(&entry)?;
    Ok(entry)
}

pub fn encode_data_type(entry: &DataTypeAnnotation) -> Result<String, String> {
    validate_data_type(entry)?;
    serde_json::to_string(entry).map_err(|error| error.to_string())
}

fn validate_data_type(entry: &DataTypeAnnotation) -> Result<(), String> {
    if entry.type_name.is_some() == entry.encoding.is_some() {
        return Err("data annotations require exactly one named type or string encoding".to_owned());
    }
    if !(1..=4096).contains(&entry.count) || !(1..=1048576).contains(&entry.byte_length) {
        return Err("data annotations require count 1..=4096 and byte length 1..=1 MiB".to_owned());
    }
    if entry.encoding.is_some() && entry.count != 1 {
        return Err("string data annotations require count 1".to_owned());
    }
    if let Some(name) = &entry.type_name {
        validate_data_type_name(name)?;
    }
    Ok(())
}

fn validate_data_type_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte == b'_' || byte.is_ascii_alphabetic() || (index != 0 && byte.is_ascii_digit()))
    {
        return Err("data type names require a bounded ASCII identifier".to_owned());
    }
    Ok(())
}

pub fn parse_operand_types(value: &str) -> Result<Vec<OperandTypeAnnotation>, String> {
    preflight_typed_value(value)?;
    let mut entries: Vec<OperandTypeAnnotation> =
        serde_json::from_str(value).map_err(|error| format!("invalid operand type annotations: {error}"))?;
    validate_operand_types(&entries)?;
    canonical_operand_types(&mut entries);
    Ok(entries)
}

pub fn encode_operand_types(entries: &[OperandTypeAnnotation]) -> Result<String, String> {
    validate_operand_types(entries)?;
    let mut entries = entries.to_vec();
    canonical_operand_types(&mut entries);
    serde_json::to_string(&entries).map_err(|error| error.to_string())
}

fn preflight_typed_value(value: &str) -> Result<(), String> {
    if value.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(value.as_bytes(), false)
}

fn validate_operand_types(entries: &[OperandTypeAnnotation]) -> Result<(), String> {
    if entries.is_empty() || entries.len() > 32 {
        return Err("operand annotation collections require 1..=32 entries; clear with None".to_owned());
    }
    let mut operands = 0u32;
    for entry in entries {
        if entry.operand > 31 {
            return Err("operand indices must be 0..=31".to_owned());
        }
        let mask = 1u32 << entry.operand;
        if operands & mask != 0 {
            return Err("operand annotation indices must be unique".to_owned());
        }
        operands |= mask;
        rampage_decompiler::validate_local_name(&entry.type_name).map_err(|error| error.to_string())?;
        if entry.instruction_hex.is_empty()
            || entry.instruction_hex.len() > 64
            || entry.instruction_hex.len() % 2 != 0
            || !entry.instruction_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("instruction hex requires 1..=32 bytes of even-length ASCII hexadecimal".to_owned());
        }
    }
    Ok(())
}

fn canonical_operand_types(entries: &mut [OperandTypeAnnotation]) {
    entries.sort_by_key(|entry| entry.operand);
    for entry in entries {
        entry.instruction_hex.make_ascii_lowercase();
    }
}

fn checked_annotation_field(field: Field) -> bool {
    matches!(
        field,
        Field::TypeLibrary | Field::DebugTypes | Field::DataType | Field::OperandType | Field::TypeHint | Field::Patch
    )
}

/// Function-local names keyed by complete storage selectors, never by generated names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalNameAnnotation {
    pub storage: VariableStorage,
    pub name: String,
}

/// Function-local abstract type declarations keyed by complete storage selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTypeAnnotation {
    pub storage: VariableStorage,
    pub data_type: String,
}

/// Derived evidence is persisted independently of analyst-authored type overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeHintAnnotation {
    pub source_fingerprint: String,
    pub hints: Vec<DerivedTypeHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedTypeHint {
    pub target: TypeHintTarget,
    pub data_type: String,
    pub evidence: Vec<TypeHintEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeHintTarget {
    Local { storage: VariableStorage },
    Parameter { index: u32, storage: VariableStorage },
    Return,
}

impl<'de> Deserialize<'de> for TypeHintTarget {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Target {
            Local { storage: VariableStorage },
            Parameter { index: u32, storage: VariableStorage },
            Return {},
        }
        Ok(match Target::deserialize(deserializer)? {
            Target::Local { storage } => Self::Local { storage },
            Target::Parameter { index, storage } => Self::Parameter { index, storage },
            Target::Return {} => Self::Return,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeHintEvidence {
    #[serde(serialize_with = "rampage_arch::hex::address", deserialize_with = "deserialize_type_hint_address")]
    pub function: u64,
    #[serde(serialize_with = "rampage_arch::hex::address", deserialize_with = "deserialize_type_hint_address")]
    pub at: u64,
    pub reason: String,
}

fn deserialize_type_hint_address<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct Address;

    impl serde::de::Visitor<'_> for Address {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an unsigned 64-bit number or 0x-prefixed hexadecimal address")
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<u64, E> {
            rampage_arch::hex::deserialize_address(serde::de::value::StrDeserializer::<E>::new(value))
        }
    }

    deserializer.deserialize_any(Address)
}

pub fn parse_type_hints(value: &str) -> Result<TypeHintAnnotation, String> {
    preflight_typed_value(value)?;
    let mut entry: TypeHintAnnotation =
        serde_json::from_str(value).map_err(|error| format!("invalid type hint annotation: {error}"))?;
    validate_type_hints(&entry)?;
    canonical_type_hints(&mut entry)?;
    Ok(entry)
}

pub fn encode_type_hints(entry: &TypeHintAnnotation) -> Result<String, String> {
    validate_type_hints(entry)?;
    let mut entry = entry.clone();
    canonical_type_hints(&mut entry)?;
    let mut encoded = CheckedLogBuffer::default();
    serde_json::to_writer(&mut encoded, &entry).map_err(|error| error.to_string())?;
    if encoded.bytes.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(&encoded.bytes, false)?;
    String::from_utf8(encoded.bytes).map_err(|error| error.to_string())
}

fn type_hint_target_key(target: &TypeHintTarget) -> Result<String, String> {
    let mut target = target.clone();
    canonical_type_hint_target(&mut target);
    serde_json::to_string(&target).map_err(|error| error.to_string())
}

fn canonical_type_hint_target(target: &mut TypeHintTarget) {
    let storage = match target {
        TypeHintTarget::Local { storage } | TypeHintTarget::Parameter { storage, .. } => storage,
        TypeHintTarget::Return => return,
    };
    canonical_type_hint_storage(storage);
}

fn canonical_type_hint_storage(storage: &mut VariableStorage) {
    storage
        .use_ranges
        .sort_by(|left, right| (&left.space, left.start, left.end).cmp(&(&right.space, right.start, right.end)));
}

fn validate_type_hint_storage(storage: &VariableStorage) -> Result<(), String> {
    if storage.space.len() > 128
        || storage.use_ranges.len() > 256
        || storage.use_ranges.iter().any(|range| range.space.len() > 128)
    {
        return Err("unsupported or incomplete variable storage selector".to_owned());
    }
    let mut storage = storage.clone();
    canonical_type_hint_storage(&mut storage);
    storage.validate().map_err(|error| error.to_string())
}

fn validate_type_hints(entry: &TypeHintAnnotation) -> Result<(), String> {
    if entry.source_fingerprint.len() != 64 || !entry.source_fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("type hint source fingerprint requires exactly 64 ASCII hexadecimal digits".to_owned());
    }
    if entry.hints.is_empty() || entry.hints.len() > 256 {
        return Err("type hint collections require 1..=256 entries; clear with None".to_owned());
    }
    let mut targets = std::collections::BTreeSet::new();
    let mut parameters = std::collections::BTreeSet::new();
    let mut bytes = entry.source_fingerprint.len();
    for hint in &entry.hints {
        let storage = match &hint.target {
            TypeHintTarget::Local { storage } => Some(storage),
            TypeHintTarget::Parameter { index, storage } => {
                if !parameters.insert(*index) {
                    return Err("duplicate type hint parameter index".to_owned());
                }
                Some(storage)
            }
            TypeHintTarget::Return => None,
        };
        if let Some(storage) = storage {
            validate_type_hint_storage(storage)?;
            bytes += storage.space.len();
            bytes += storage.use_ranges.iter().map(|range| range.space.len()).sum::<usize>();
        }
        if hint.data_type.trim().is_empty()
            || hint.data_type.len() > 4096
            || hint.data_type.chars().any(char::is_control)
        {
            return Err("type hint requires a bounded abstract declaration without control characters".to_owned());
        }
        if hint.evidence.len() > 16 {
            return Err("type hints allow at most 16 evidence entries".to_owned());
        }
        bytes += hint.data_type.len();
        for evidence in &hint.evidence {
            if evidence.reason.trim().is_empty() || evidence.reason.chars().any(char::is_control) {
                return Err("type hint evidence requires nonempty reason text without control characters".to_owned());
            }
            bytes = bytes.checked_add(evidence.reason.len()).ok_or(CHECKED_ERROR)?;
        }
        if bytes > 65536 {
            return Err("type hint annotation text exceeds 64 KiB".to_owned());
        }
        if !targets.insert(type_hint_target_key(&hint.target)?) {
            return Err("duplicate type hint target".to_owned());
        }
    }
    Ok(())
}

fn canonical_type_hints(entry: &mut TypeHintAnnotation) -> Result<(), String> {
    entry.source_fingerprint.make_ascii_lowercase();
    for hint in &mut entry.hints {
        canonical_type_hint_target(&mut hint.target);
        hint.evidence.sort_by(|left, right| {
            (left.function, left.at, &left.reason).cmp(&(right.function, right.at, &right.reason))
        });
    }
    let mut keyed = entry
        .hints
        .drain(..)
        .map(|hint| type_hint_target_key(&hint.target).map(|key| (key, hint)))
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    entry.hints = keyed.into_iter().map(|(_, hint)| hint).collect();
    Ok(())
}

const LOCAL_ENTRIES: usize = 256;

/// One declaration unit, kept in dependency order in the project-wide type library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryDeclaration {
    pub names: Vec<String>,
    pub declarations: String,
    pub packing: Option<u32>,
    pub source: Option<TypeLibrarySource>,
}

/// Textual provenance; no source file is needed to restore a persisted library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeLibrarySource {
    pub kind: String,
    pub identity: String,
}

pub fn parse_type_library(value: &str) -> Result<Vec<LibraryDeclaration>, String> {
    if value.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(value.as_bytes(), false)?;
    let mut entries: Vec<LibraryDeclaration> =
        serde_json::from_str(value).map_err(|error| format!("invalid type library: {error}"))?;
    validate_type_library(&entries)?;
    for entry in &mut entries {
        entry.names.sort();
    }
    Ok(entries)
}

pub fn encode_type_library(entries: &[LibraryDeclaration]) -> Result<String, String> {
    validate_type_library(entries)?;
    let mut entries = entries.to_vec();
    for entry in &mut entries {
        entry.names.sort();
    }
    let mut encoded = CheckedLogBuffer::default();
    serde_json::to_writer(&mut encoded, &entries).map_err(|error| error.to_string())?;
    if encoded.bytes.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(&encoded.bytes, false)?;
    String::from_utf8(encoded.bytes).map_err(|error| error.to_string())
}

fn validate_type_library(entries: &[LibraryDeclaration]) -> Result<(), String> {
    if entries.is_empty() || entries.len() > 256 {
        return Err("type libraries require 1..=256 declaration units; clear with None".to_owned());
    }
    let mut names = std::collections::BTreeSet::new();
    let mut bytes = 0usize;
    for entry in entries {
        if entry.names.is_empty()
            || entry.declarations.trim().is_empty()
            || entry.declarations.len() > 65536
            || entry.declarations.contains('\0')
        {
            return Err(
                "type library units require names and nonempty declarations of at most 64 KiB without NUL".into()
            );
        }
        if !matches!(entry.packing, None | Some(1 | 2 | 4 | 8 | 16)) {
            return Err("type library packing must be 1, 2, 4, 8 or 16".to_owned());
        }
        bytes = bytes.checked_add(entry.declarations.len()).ok_or(CHECKED_ERROR)?;
        for name in &entry.names {
            rampage_decompiler::validate_local_name(name).map_err(|error| error.to_string())?;
            bytes = bytes.checked_add(name.len()).ok_or(CHECKED_ERROR)?;
            if bytes > CHECKED_VALUE_BYTES || !names.insert(name) {
                return Err("type library names must be unique within the bounded library".to_owned());
            }
        }
        if let Some(source) = &entry.source {
            for text in [&source.kind, &source.identity] {
                if text.trim().is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
                    return Err("type library provenance requires bounded nonempty text without controls".to_owned());
                }
                bytes = bytes.checked_add(text.len()).ok_or(CHECKED_ERROR)?;
            }
        }
        if bytes > CHECKED_VALUE_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
    }
    Ok(())
}

/// Structural storage envelope only; import semantics and native proofs are checked by the API.
pub fn parse_debug_types(value: &str) -> Result<serde_json::Value, String> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        version: u64,
        imports: Vec<serde_json::Value>,
    }

    preflight_typed_value(value)?;
    let envelope: Envelope =
        serde_json::from_str(value).map_err(|error| format!("invalid debug types annotation: {error}"))?;
    let value = serde_json::to_value(envelope).map_err(|error| error.to_string())?;
    validate_debug_types(&value)?;
    Ok(value)
}

pub fn encode_debug_types(value: &serde_json::Value) -> Result<String, String> {
    validate_debug_types(value)?;
    let mut encoded = CheckedLogBuffer::default();
    serde_json::to_writer(&mut encoded, value).map_err(|error| error.to_string())?;
    if encoded.bytes.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(&encoded.bytes, false)?;
    String::from_utf8(encoded.bytes).map_err(|error| error.to_string())
}

fn validate_debug_types(value: &serde_json::Value) -> Result<(), String> {
    let root = value.as_object().ok_or("debug types require a versioned object envelope")?;
    if root.len() != 2 || root.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err("debug types require exactly version 1 and imports".to_owned());
    }
    let imports =
        root.get("imports").and_then(serde_json::Value::as_array).ok_or("debug types require an imports array")?;
    if imports.is_empty() || imports.len() > 16 {
        return Err("debug types require 1..=16 imports; clear with None".to_owned());
    }
    let mut ids = std::collections::BTreeSet::new();
    for import in imports {
        let import = import.as_object().ok_or("debug type imports must be objects")?;
        let id = import.get("id").and_then(serde_json::Value::as_str).ok_or("debug type imports require an id")?;
        if id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !ids.insert(id)
        {
            return Err("debug type import ids must be unique lowercase 64-digit hexadecimal".to_owned());
        }
        if let Some(names) = import.get("library_names") {
            let names = names.as_array().ok_or("debug type library_names must be an array")?;
            if names.len() > 256 {
                return Err("debug type imports allow at most 256 library names".to_owned());
            }
            for name in names {
                validate_data_type_name(name.as_str().ok_or("debug type library names must be strings")?)?;
            }
        }
    }
    validate_debug_types_text(value, 0)
}

fn validate_debug_types_text(value: &serde_json::Value, depth: usize) -> Result<(), String> {
    let depth = depth + usize::from(value.is_array() || value.is_object());
    if depth > 8 {
        return Err(CHECKED_ERROR.to_owned());
    }
    match value {
        serde_json::Value::String(text) if text.contains('\0') => {
            return Err("debug type annotations must not contain NUL".to_owned());
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_debug_types_text(value, depth)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if key.contains('\0') {
                    return Err("debug type annotations must not contain NUL".to_owned());
                }
                validate_debug_types_text(value, depth)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_project_address(field: Field, address: u64) -> Result<(), String> {
    if field == Field::TypeLibrary && address != 0 {
        return Err("the project-wide type library requires address 0".to_owned());
    }
    if field == Field::DebugTypes && address != 0 {
        return Err("project-wide debug types require address 0".to_owned());
    }
    Ok(())
}

pub fn parse_local_names(value: &str) -> Result<Vec<LocalNameAnnotation>, String> {
    let entries: Vec<LocalNameAnnotation> = parse_local_collection(value)?;
    validate_local_names(&entries)?;
    Ok(entries)
}

fn validate_local_names(entries: &[LocalNameAnnotation]) -> Result<(), String> {
    validate_local_entries(entries, |entry| (&entry.storage, entry.name.as_str()))?;
    for (index, entry) in entries.iter().enumerate() {
        if rampage_decompiler::validate_local_name(&entry.name).is_err()
            || entries[..index].iter().any(|other| other.name == entry.name)
        {
            return Err("local names must be unique bounded C identifiers".to_owned());
        }
    }
    Ok(())
}

pub fn parse_local_types(value: &str) -> Result<Vec<LocalTypeAnnotation>, String> {
    let entries: Vec<LocalTypeAnnotation> = parse_local_collection(value)?;
    validate_local_types(&entries)?;
    Ok(entries)
}

fn validate_local_types(entries: &[LocalTypeAnnotation]) -> Result<(), String> {
    validate_local_entries(entries, |entry| (&entry.storage, entry.data_type.as_str()))?;
    if entries.iter().any(|entry| {
        entry.data_type.trim().is_empty()
            || entry.data_type.len() > 4096
            || entry.data_type.chars().any(char::is_control)
    }) {
        return Err("local type requires a bounded abstract declaration without control characters".to_owned());
    }
    Ok(())
}

pub fn encode_local_names(entries: &[LocalNameAnnotation]) -> Result<String, String> {
    validate_local_names(entries)?;
    encode_local_collection(entries, |entry| &entry.storage)
}

pub fn encode_local_types(entries: &[LocalTypeAnnotation]) -> Result<String, String> {
    validate_local_types(entries)?;
    encode_local_collection(entries, |entry| &entry.storage)
}

fn parse_local_collection<T: serde::de::DeserializeOwned>(value: &str) -> Result<Vec<T>, String> {
    if value.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(value.as_bytes(), false)?;
    let entries: Vec<T> = serde_json::from_str(value).map_err(|error| format!("invalid local annotations: {error}"))?;
    if entries.is_empty() || entries.len() > LOCAL_ENTRIES {
        return Err("local annotation collections require 1..=256 entries; clear with None".to_owned());
    }
    Ok(entries)
}

fn validate_local_entries<T>(entries: &[T], parts: impl Fn(&T) -> (&VariableStorage, &str)) -> Result<(), String> {
    if entries.is_empty() || entries.len() > LOCAL_ENTRIES {
        return Err("local annotation collections require 1..=256 entries; clear with None".to_owned());
    }
    let mut bytes = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let (storage, text) = parts(entry);
        storage.validate().map_err(|error| error.to_string())?;
        if entries[..index].iter().any(|other| parts(other).0 == storage) {
            return Err("duplicate local storage selector".to_owned());
        }
        bytes += text.len() + storage.space.len();
        bytes += storage.use_ranges.iter().map(|range| range.space.len()).sum::<usize>();
        if bytes > 65536 {
            return Err("local annotation text exceeds 64 KiB".to_owned());
        }
    }
    Ok(())
}

fn encode_local_collection<T: Serialize>(
    entries: &[T],
    storage: impl Fn(&T) -> &VariableStorage,
) -> Result<String, String> {
    if entries.is_empty() || entries.len() > LOCAL_ENTRIES {
        return Err("local annotation collections require 1..=256 entries; clear with None".to_owned());
    }
    let mut keyed = entries
        .iter()
        .map(|entry| serde_json::to_string(storage(entry)).map(|key| (key, entry)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let ordered: Vec<_> = keyed.into_iter().map(|(_, entry)| entry).collect();
    let mut encoded = CheckedLogBuffer::default();
    serde_json::to_writer(&mut encoded, &ordered).map_err(|error| error.to_string())?;
    if encoded.bytes.len() > CHECKED_VALUE_BYTES {
        return Err(CHECKED_ERROR.to_owned());
    }
    checked_json_preflight(&encoded.bytes, false)?;
    String::from_utf8(encoded.bytes).map_err(|error| error.to_string())
}

fn canonical_local_value(field: Field, value: Option<&str>) -> Result<Option<String>, String> {
    value
        .map(|value| match field {
            Field::LocalName => encode_local_names(&parse_local_names(value)?),
            Field::LocalType => encode_local_types(&parse_local_types(value)?),
            Field::TypeHint => encode_type_hints(&parse_type_hints(value)?),
            Field::TypeLibrary => encode_type_library(&parse_type_library(value)?),
            Field::DebugTypes => encode_debug_types(&parse_debug_types(value)?),
            Field::DataType => encode_data_type(&parse_data_type(value)?),
            Field::OperandType => encode_operand_types(&parse_operand_types(value)?),
            Field::Patch => crate::patches::encode_patch(&crate::patches::parse_patch(value)?),
            _ => Ok(value.to_owned()),
        })
        .transpose()
}

fn validate_local_value(field: Field, value: &str) -> Result<(), String> {
    match field {
        Field::LocalName => parse_local_names(value).map(|_| ()),
        Field::LocalType => parse_local_types(value).map(|_| ()),
        Field::TypeHint => parse_type_hints(value).map(|_| ()),
        Field::TypeLibrary => parse_type_library(value).map(|_| ()),
        Field::DebugTypes => parse_debug_types(value).map(|_| ()),
        Field::DataType => parse_data_type(value).map(|_| ()),
        Field::OperandType => parse_operand_types(value).map(|_| ()),
        Field::Patch => crate::patches::parse_patch(value).map(|_| ()),
        _ => Ok(()),
    }
}

/// One change: `field` at `address` went from `previous` to `value` (`None` removes it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub field: Field,
    #[serde(
        serialize_with = "rampage_arch::hex::address",
        deserialize_with = "rampage_arch::hex::deserialize_address"
    )]
    pub address: u64,
    pub value: Option<String>,
    pub previous: Option<String>,
}

impl Edit {
    fn inverse(&self) -> Edit {
        Edit { field: self.field, address: self.address, value: self.previous.clone(), previous: self.value.clone() }
    }
}

/// The line logged before a batch's edits, saying how many follow. Each of them carries the batch's id, so a reader
/// applies the batch only once all are there, and never takes edits written after an interrupted batch for the
/// rest of it. Readers that predate batches skip this line, which is not an edit, and apply the edits one by one.
#[derive(Serialize, Deserialize)]
struct BatchHeader {
    batch: String,
    edits: usize,
}

/// One of a batch's edits, as logged.
#[derive(Serialize)]
struct BatchMember<'a> {
    #[serde(flatten)]
    edit: &'a Edit,
    batch: &'a str,
}

/// Enough of a log line to tell a batch header (both), a batch's edit (`batch` only), an identity line (`image`)
/// and a lone edit (none).
#[derive(Deserialize)]
struct LineKind {
    #[serde(default)]
    batch: Option<String>,
    #[serde(default)]
    edits: Option<usize>,
    #[serde(default)]
    image: Option<String>,
}

/// The line logged before the edits a writer makes on one image: that image's SHA-256, in hex. Readers that predate
/// it skip it, as it is not an edit.
#[derive(Serialize)]
struct ImageLine<'a> {
    image: &'a str,
}

/// An id no other batch in the log is likely to share: this process's, the time's, and a count.
fn batch_id() -> String {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    format!("{:x}-{nanos:x}-{count:x}", std::process::id())
}

/// Appended to an undo's refusal over another client's edits, which repeats until the step is undone or discarded;
/// a refusal ending with it is one [`Annotations::discard_undo_step`] can clear.
pub const DISCARD_HINT: &str =
    "; discard_undo drops this step from the undo history (its edits stay in effect) so earlier ones can be undone";

/// Why replaying a step changed nothing.
enum Refusal {
    /// Another client's edits since block it; trying again will not help until they change.
    Blocked(String),
    /// The result failed validation, or the log could not be written.
    Failed(String),
}

impl Refusal {
    fn message(self) -> String {
        match self {
            Self::Blocked(message) | Self::Failed(message) => message,
        }
    }
}

#[derive(Default)]
pub struct Annotations {
    revision: std::sync::Arc<()>,
    names_revision: std::sync::Arc<()>,
    patches_revision: std::sync::Arc<()>,
    names: BTreeMap<u64, String>,
    /// Each name's address, for resolving names.
    addresses: HashMap<String, u64>,
    name_owners: BTreeMap<String, std::collections::BTreeSet<u64>>,
    comments: BTreeMap<u64, String>,
    signatures: BTreeMap<u64, String>,
    types: BTreeMap<u64, String>,
    type_library: BTreeMap<u64, String>,
    debug_types: BTreeMap<u64, String>,
    globals: BTreeMap<u64, String>,
    local_names: BTreeMap<u64, String>,
    local_types: BTreeMap<u64, String>,
    type_hints: BTreeMap<u64, String>,
    data_types: BTreeMap<u64, String>,
    operand_types: BTreeMap<u64, String>,
    patches: BTreeMap<u64, String>,
    /// Ledger entries by id, and the highest id any logged edit has used, so an id is never handed out twice.
    findings: BTreeMap<u64, String>,
    finding_high: u64,
    patch_validator: Option<PatchValidator>,
    patch_freezer: Option<PatchFreezer>,
    unpatched_view: Option<std::sync::Arc<Annotations>>,
    /// Steps applied in this session, for undo; and undone ones, for redo. A step is the edits one call made,
    /// in order: a single edit, or a whole batch, which undoes and redoes together.
    done: Vec<Vec<Edit>>,
    undone: Vec<Vec<Edit>>,
    /// Where edits are appended; `None` keeps them in memory only.
    log: Option<Log>,
    /// Whether `locked` holds the log's lock, which edits made inside it must not try to take again.
    held: bool,
    /// Checked structural/cache/history ingestion, beyond the raw byte limits shared by all log readers.
    checked_reads: bool,
    managed_layouts: usize,
}

type PatchValidator = std::sync::Arc<dyn Fn(&Annotations) -> Result<(), String> + Send + Sync>;
type PatchFreezer = std::sync::Arc<dyn Fn(&Annotations) + Send + Sync>;

const CHECKED_CACHE_BYTES: usize = 8 * 1024 * 1024;
const CHECKED_VALUE_BYTES: usize = 1024 * 1024;
const CHECKED_RECORDS: usize = 8192;
const CHECKED_HISTORY_STEPS: usize = 1024;
const CHECKED_READ_BYTES: usize = 16 * 1024 * 1024;
const CHECKED_LINE_BYTES: usize = 2 * 1024 * 1024;
const CHECKED_ERROR: &str = "checked annotation input is malformed, unstable, or exceeds its bounded ingestion budget";

#[derive(Default)]
struct CheckedBudget {
    bytes: usize,
    records: usize,
}

impl CheckedBudget {
    fn text(&mut self, text: &str) -> Result<(), String> {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(CHECKED_ERROR)?;
        self.records += 1;
        if text.len() > CHECKED_VALUE_BYTES || self.bytes > CHECKED_CACHE_BYTES || self.records > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }
    fn edit(&mut self, edit: &Edit) -> Result<(), String> {
        validate_project_address(edit.field, edit.address)?;
        self.records += 1;
        if let Some(value) = &edit.value {
            if edit.field == Field::Name && value.len() > 128 {
                return Err(CHECKED_ERROR.to_owned());
            }
            self.text(value)?;
            validate_local_value(edit.field, value)?;
        }
        if let Some(previous) = &edit.previous {
            if edit.field == Field::Name && previous.len() > 128 {
                return Err(CHECKED_ERROR.to_owned());
            }
            self.text(previous)?;
            validate_local_value(edit.field, previous)?;
        }
        if self.records > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Log {
    path: PathBuf,
    /// How many bytes of the file have been applied: every complete line before this offset. Other processes'
    /// edits, and a line still being written, lie past it.
    read: u64,
    /// The file read, to notice it being replaced by another of any size.
    identity: Option<(u64, u64)>,
    /// The SHA-256 (hex) of the image these annotations are applied to, when known.
    image: Option<String>,
    /// The identity line last read: the image the edits after it were made on.
    logged_image: Option<String>,
    /// Edits were read before any identity line, so the image they were made on is not known yet.
    unattributed: bool,
    /// An image other than `image` that some edits read were made on.
    other_image: Option<String>,
}

impl Log {
    /// Advances the cursor past a writer's own append, which `commit` already applies, so a fully refreshed writer
    /// does not replay its own bytes on refresh (which would manufacture a new authority nonce after the transition
    /// witness was returned). Only an append observed to land exactly at the read end of the same file is skipped:
    /// the cursor must equal the pre-write length, the file identity must match, and the post-write length must be
    /// exactly the pre-write length plus the bytes written. Anything else, such as a lock-ignoring appender racing
    /// the write, leaves the cursor in place so the next `refresh` reads the appended lines back.
    fn adopt_own_append(&mut self, before: u64, identity: Option<(u64, u64)>, written: u64, after: Option<u64>) {
        if self.read == before
            && self.identity.is_none_or(|known| Some(known) == identity)
            && after.is_some_and(|after| before.checked_add(written) == Some(after))
        {
            self.read = before + written;
            self.identity = identity;
            self.attribute_edits();
        }
    }

    /// Attributes edits just read to the image they were made on.
    fn attribute_edits(&mut self) {
        match &self.logged_image {
            None => self.unattributed = true,
            Some(logged) => self.note_image(logged.clone()),
        }
    }

    fn note_image(&mut self, logged: String) {
        if self.image.as_ref().is_some_and(|image| *image != logged) {
            self.other_image = Some(logged);
        }
    }

    /// Reads an identity line. The first one in a log also stands for the edits before it, which were logged by
    /// writers that predate identity lines.
    fn read_image(&mut self, logged: String) {
        if self.logged_image.is_none() && std::mem::take(&mut self.unattributed) {
            self.note_image(logged.clone());
        }
        self.logged_image = Some(logged);
    }
}

impl Annotations {
    #[cfg(test)]
    pub(crate) fn test_log_cursor(&self) -> Option<u64> {
        self.log.as_ref().map(|log| log.read)
    }
    pub(crate) fn patches_revision(&self) -> std::sync::Arc<()> {
        std::sync::Arc::clone(&self.patches_revision)
    }

    pub(crate) fn set_patch_validator(&mut self, validator: PatchValidator) {
        self.patch_validator = Some(validator);
    }

    pub(crate) fn set_patch_freezer(&mut self, freezer: PatchFreezer) {
        self.patch_freezer = Some(freezer);
    }

    pub(crate) fn read_snapshot(&self) -> Self {
        let mut snapshot = self.snapshot();
        snapshot.patch_freezer = None;
        snapshot.unpatched_view = None;
        snapshot
    }

    pub(crate) fn original_read_snapshot(&self) -> Self {
        if let Some(view) = &self.unpatched_view {
            return view.read_snapshot();
        }
        let mut view = self.read_snapshot();
        view.patches.clear();
        view.patches_revision = std::sync::Arc::new(());
        view.revision = std::sync::Arc::new(());
        view
    }

    fn freeze_unpatched_view(&mut self) {
        if !self.patches.is_empty() {
            return;
        }
        if self.unpatched_view.is_none() {
            self.unpatched_view = Some(std::sync::Arc::new(self.read_snapshot()));
        }
    }

    fn publish_staged(&mut self, mut staged: Self) {
        if self.patches.is_empty()
            && !staged.patches.is_empty()
            && let Some(freeze) = &self.patch_freezer
        {
            freeze(self);
        }
        staged.patch_freezer = self.patch_freezer.clone();
        *self = staged;
    }

    pub(crate) fn validate_patches(&self) -> Result<(), String> {
        crate::patches::validate_patch_collection(&self.patches)?;
        if let Some(validate) = &self.patch_validator {
            validate(self)?;
        }
        Ok(())
    }

    pub(crate) fn revision(&self) -> std::sync::Arc<()> {
        std::sync::Arc::clone(&self.revision)
    }

    pub(crate) fn names_revision(&self) -> std::sync::Arc<()> {
        std::sync::Arc::clone(&self.names_revision)
    }

    pub(crate) fn persistent_path(&self) -> Option<&std::path::Path> {
        self.log.as_ref().map(|log| log.path.as_path())
    }

    /// Loads the log at `path` if it exists; later edits are appended to it.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        Self::open_for_image(path, None)
    }

    /// [`Annotations::open`] for an image whose SHA-256 is `image`: edits are logged as made on it, and
    /// [`Annotations::warnings`] compares it with the images earlier edits were made on.
    pub fn open_for_image(path: PathBuf, image: Option<[u8; 32]>) -> Result<Self, String> {
        let image = image.map(|digest| rampage_arch::hex::bytes(&digest));
        let mut annotations = Self { log: Some(Log { path, image, ..Log::default() }), ..Self::default() };
        annotations.refresh()?;
        Ok(annotations)
    }

    /// Bounded boundary for logs containing checked layout bundles. Limits apply BEFORE reading/serde:
    /// 16 MiB unread raw bytes, 2 MiB/line, 8192 lines, depth 8 and 65536 structural separators.
    /// Cache/history limits: 8 MiB cumulative text, 1 MiB/value, 8192 counted entries, 1024 undo/redo steps.
    /// Ordinary legacy `open` shares the raw limits while retaining compatibility for ordinary legacy fragments.
    pub fn open_checked(path: PathBuf) -> Result<Self, String> {
        Self::open_for_image_checked(path, None)
    }

    pub fn open_for_image_checked(path: PathBuf, image: Option<[u8; 32]>) -> Result<Self, String> {
        if path.as_os_str().len() > 4096 {
            return Err(CHECKED_ERROR.to_owned());
        }
        let image = image.map(|digest| rampage_arch::hex::bytes(&digest));
        let mut annotations =
            Self { log: Some(Log { path, image, ..Log::default() }), checked_reads: true, ..Self::default() };
        annotations.refresh()?;
        Ok(annotations)
    }

    pub(crate) fn preflight_checked(&self) -> Result<(), String> {
        self.preflight_checked_with_history(self, &[])
    }

    pub(crate) fn has_checked_layouts(&self) -> bool {
        self.managed_layouts != 0
    }

    fn has_checked_annotations(&self) -> bool {
        !self.type_library.is_empty()
            || !self.debug_types.is_empty()
            || !self.data_types.is_empty()
            || !self.operand_types.is_empty()
            || !self.type_hints.is_empty()
            || !self.patches.is_empty()
    }

    fn introduces_checked_state(&self, field: Field, value: Option<&str>) -> bool {
        value.is_some_and(|value| {
            (checked_annotation_field(field) && !self.has_checked_annotations())
                || (matches!(field, Field::Types | Field::Signature)
                    && value.starts_with('!')
                    && !self.has_checked_layouts())
        })
    }

    fn preflight_checked_log(&self) -> Result<(), String> {
        if let Some(log) = &self.log {
            checked_full_log(log, &[])?;
        }
        Ok(())
    }

    fn preflight_checked_with_history(&self, history: &Self, extra: &[Edit]) -> Result<(), String> {
        let mut budget = CheckedBudget::default();
        let rows = self
            .names
            .len()
            .saturating_add(self.comments.len())
            .saturating_add(self.signatures.len())
            .saturating_add(self.types.len())
            .saturating_add(self.type_library.len())
            .saturating_add(self.debug_types.len())
            .saturating_add(self.globals.len())
            .saturating_add(self.local_names.len())
            .saturating_add(self.local_types.len())
            .saturating_add(self.type_hints.len())
            .saturating_add(self.data_types.len())
            .saturating_add(self.operand_types.len())
            .saturating_add(self.patches.len())
            .saturating_add(self.findings.len())
            .saturating_add(self.addresses.len())
            .saturating_add(self.name_owners.len());
        if rows > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        if self.names.values().chain(self.addresses.keys()).chain(self.name_owners.keys()).any(|name| name.len() > 128)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
        for text in self
            .names
            .values()
            .chain(self.comments.values())
            .chain(self.signatures.values())
            .chain(self.types.values())
            .chain(self.type_library.values())
            .chain(self.debug_types.values())
            .chain(self.globals.values())
            .chain(self.local_names.values())
            .chain(self.local_types.values())
            .chain(self.type_hints.values())
            .chain(self.data_types.values())
            .chain(self.operand_types.values())
            .chain(self.patches.values())
            .chain(self.findings.values())
            .chain(self.addresses.keys())
            .chain(self.name_owners.keys())
        {
            budget.text(text)?;
        }
        self.validate_local_collections()?;
        for owners in self.name_owners.values() {
            budget.records = budget
                .records
                .checked_add(owners.len())
                .filter(|&records| records <= CHECKED_RECORDS)
                .ok_or(CHECKED_ERROR)?;
        }
        if history.done.len() + history.undone.len() + usize::from(!extra.is_empty()) > CHECKED_HISTORY_STEPS {
            return Err(CHECKED_ERROR.to_owned());
        }
        for step in history.done.iter().chain(&history.undone) {
            budget.records += 1;
            for edit in step {
                budget.edit(edit)?;
            }
        }
        if !extra.is_empty() {
            budget.records += 1;
        }
        for edit in extra {
            budget.edit(edit)?;
        }
        if let Some(log) = &history.log {
            if log.path.as_os_str().len() > 4096 {
                return Err(CHECKED_ERROR.to_owned());
            }
            budget.bytes = budget.bytes.checked_add(4096 + 3 * 128).ok_or(CHECKED_ERROR)?;
            budget.records += 4;
            for text in [&log.image, &log.logged_image, &log.other_image].into_iter().flatten() {
                if text.len() > 128 {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
        if budget.records > CHECKED_RECORDS || budget.bytes > CHECKED_CACHE_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }

    /// Why these annotations may not fit this image: some were made on another image (a different build at the
    /// same path), or the log predates identity lines, so nothing says which image they were made on.
    pub fn warnings(&self) -> Vec<String> {
        let Some(log) = &self.log else { return Vec::new() };
        let Some(image) = &log.image else { return Vec::new() };
        let path = log.path.display();
        let mut warnings = Vec::new();
        if let Some(other) = &log.other_image {
            warnings.push(format!(
                "annotations in {path} include edits made on a different image (sha256 {other}) than this one \
                 (sha256 {image}); their addresses may no longer name the same code"
            ));
        }
        if log.unattributed && log.logged_image.is_none() {
            warnings.push(format!(
                "annotations in {path} were logged without the image they were made on, so they are unverified \
                 against this one (sha256 {image}); the next edit records it"
            ));
        }
        warnings
    }

    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Takes over the undo and redo steps of `previous`, an instance this one replaces, when both write the same
    /// log: the steps are edits in that log, so reloading the binary beside it leaves them as undoable as before.
    pub(crate) fn inherit_history(&mut self, previous: &Self) {
        let path = |annotations: &Self| annotations.log.as_ref().map(|log| log.path.clone());
        if self.log.is_some() && path(self) == path(previous) {
            self.done.clone_from(&previous.done);
            self.undone.clone_from(&previous.undone);
        }
    }

    pub(crate) fn snapshot(&self) -> Self {
        Self {
            revision: std::sync::Arc::clone(&self.revision),
            names_revision: std::sync::Arc::clone(&self.names_revision),
            patches_revision: std::sync::Arc::clone(&self.patches_revision),
            names: self.names.clone(),
            addresses: self.addresses.clone(),
            name_owners: self.name_owners.clone(),
            comments: self.comments.clone(),
            signatures: self.signatures.clone(),
            types: self.types.clone(),
            type_library: self.type_library.clone(),
            debug_types: self.debug_types.clone(),
            globals: self.globals.clone(),
            local_names: self.local_names.clone(),
            local_types: self.local_types.clone(),
            type_hints: self.type_hints.clone(),
            data_types: self.data_types.clone(),
            operand_types: self.operand_types.clone(),
            patches: self.patches.clone(),
            findings: self.findings.clone(),
            finding_high: self.finding_high,
            patch_validator: self.patch_validator.clone(),
            patch_freezer: None,
            unpatched_view: self.unpatched_view.clone(),
            checked_reads: self.checked_reads,
            managed_layouts: self.managed_layouts,
            ..Self::default()
        }
    }

    /// Reads current shared edits into a detached candidate without publishing cache, cursor or history.
    pub(crate) fn checked_snapshot(&self) -> Result<Self, ApiError> {
        self.preflight_checked().map_err(ApiError::Invalid)?;
        let _lock = self.log_lock_checked().map_err(ApiError::Invalid)?;
        let mut candidate = Self { log: self.log.clone(), held: true, checked_reads: true, ..self.snapshot() };
        candidate.refresh().map_err(ApiError::Invalid)?;
        candidate.log = None;
        candidate.held = false;
        Ok(candidate)
    }

    /// Reads a bounded annotation snapshot without creating lock files or publishing a writer transaction.
    pub(crate) fn checked_read_snapshot(&self) -> Result<Self, ApiError> {
        self.preflight_checked().map_err(ApiError::Invalid)?;
        let mut candidate = Self { log: self.log.clone(), checked_reads: true, ..self.snapshot() };
        candidate.refresh().map_err(ApiError::Invalid)?;
        candidate.log = None;
        candidate.held = false;
        Ok(candidate)
    }

    /// Applies edits other processes have appended to the log since it was last read. Returns whether any were.
    pub fn refresh(&mut self) -> Result<bool, String> {
        if self.checked_reads || self.has_checked_layouts() || self.has_checked_annotations() {
            self.preflight_checked()?;
            let mut staged = Self {
                done: self.done.clone(),
                undone: self.undone.clone(),
                log: self.log.clone(),
                held: self.held,
                checked_reads: true,
                ..self.snapshot()
            };
            let changed = staged.refresh_inner(true)?;
            staged.preflight_checked()?;
            self.publish_staged(staged);
            return Ok(changed);
        }
        self.refresh_inner(false)
    }

    pub(crate) fn refresh_validated(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<bool, String> {
        if self.checked_reads || self.has_checked_layouts() || self.has_checked_annotations() {
            self.preflight_checked()?;
        }
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: self.held,
            ..self.snapshot()
        };
        let changed = staged.refresh()?;
        validate(&staged)?;
        self.publish_staged(staged);
        Ok(changed)
    }

    fn refresh_inner(&mut self, checked: bool) -> Result<bool, String> {
        let Some(log) = &mut self.log else { return Ok(false) };
        let mut next_log = log.clone();
        let (restart, edits) = read_new_edits(&mut next_log, checked)?;
        let introduces_checked_state =
            edits.iter().any(|edit| self.introduces_checked_state(edit.field, edit.value.as_deref()));
        if introduces_checked_state {
            checked_full_log(&next_log, &[])?;
        }
        if !checked && (introduces_checked_state || edits.iter().any(|edit| checked_annotation_field(edit.field))) {
            self.preflight_checked()?;
            let mut staged = Self {
                done: self.done.clone(),
                undone: self.undone.clone(),
                log: self.log.clone(),
                held: self.held,
                checked_reads: true,
                ..self.snapshot()
            };
            let changed = staged.refresh_inner(true)?;
            staged.preflight_checked()?;
            staged.checked_reads = self.checked_reads;
            self.publish_staged(staged);
            return Ok(changed);
        }
        for edit in edits.iter().filter(|edit| checked_annotation_field(edit.field)) {
            validate_project_address(edit.field, edit.address)?;
            for value in [&edit.value, &edit.previous].into_iter().flatten() {
                validate_local_value(edit.field, value)?;
            }
        }
        if checked {
            let mut budget = CheckedBudget::default();
            for edit in &edits {
                budget.edit(edit)?;
            }
        }
        if self.patch_freezer.is_some() && edits.iter().any(|edit| edit.field == Field::Patch && edit.value.is_some()) {
            self.freeze_unpatched_view();
        }
        self.log = Some(next_log);
        if restart {
            self.revision = std::sync::Arc::new(());
            if !self.names.is_empty() {
                self.names_revision = std::sync::Arc::new(());
            }
            self.names.clear();
            self.addresses.clear();
            self.name_owners.clear();
            self.comments.clear();
            self.signatures.clear();
            self.types.clear();
            self.type_library.clear();
            self.debug_types.clear();
            self.globals.clear();
            self.local_names.clear();
            self.local_types.clear();
            self.type_hints.clear();
            self.data_types.clear();
            self.operand_types.clear();
            if !self.patches.is_empty() {
                self.patches_revision = std::sync::Arc::new(());
            }
            self.patches.clear();
            self.findings.clear();
            self.finding_high = 0;
            self.managed_layouts = 0;
        }
        for edit in &edits {
            self.apply(edit);
        }
        self.validate_patches()?;
        Ok(restart || !edits.is_empty())
    }

    fn apply(&mut self, edit: &Edit) {
        if edit.field == Field::Patch && edit.value.is_some() {
            self.freeze_unpatched_view();
        }
        self.revision = std::sync::Arc::new(());
        if edit.field == Field::Patch && self.patches.get(&edit.address) != edit.value.as_ref() {
            self.patches_revision = std::sync::Arc::new(());
        }
        if matches!(edit.field, Field::Types | Field::Signature) {
            let managed = |text: &str| {
                text.starts_with('!')
                    && (edit.field != Field::Signature || !crate::debug_type_import::is_signature_seal(text))
            };
            let old = self.field_map(edit.field).get(&edit.address).is_some_and(|text| managed(text));
            let new = edit.value.as_ref().is_some_and(|text| managed(text));
            if old != new {
                if new {
                    self.managed_layouts += 1;
                } else {
                    self.managed_layouts -= 1;
                }
            }
        }
        match edit.field {
            Field::Name => {
                if self.names.get(&edit.address).map(String::as_str) != edit.value.as_deref() {
                    self.names_revision = std::sync::Arc::new(());
                }
                if let Some(old) = self.names.remove(&edit.address) {
                    let owners = self.name_owners.get_mut(&old).expect("indexed name owners");
                    owners.remove(&edit.address);
                    let next = owners.first().copied();
                    if owners.is_empty() {
                        self.name_owners.remove(&old);
                    }
                    if self.addresses.get(&old) == Some(&edit.address) {
                        match next {
                            Some(other) => self.addresses.insert(old, other),
                            None => self.addresses.remove(&old),
                        };
                    }
                }
                if let Some(value) = &edit.value {
                    self.names.insert(edit.address, value.clone());
                    self.addresses.insert(value.clone(), edit.address);
                    self.name_owners.entry(value.clone()).or_default().insert(edit.address);
                }
            }
            Field::Comment => match &edit.value {
                Some(value) => drop(self.comments.insert(edit.address, value.clone())),
                None => drop(self.comments.remove(&edit.address)),
            },
            Field::Finding => {
                self.finding_high = self.finding_high.max(edit.address);
                match &edit.value {
                    Some(value) => drop(self.findings.insert(edit.address, value.clone())),
                    None => drop(self.findings.remove(&edit.address)),
                }
            }
            Field::Signature
            | Field::Types
            | Field::TypeLibrary
            | Field::DebugTypes
            | Field::Global
            | Field::LocalName
            | Field::LocalType
            | Field::TypeHint
            | Field::DataType
            | Field::OperandType
            | Field::Patch => {
                let values = match edit.field {
                    Field::Signature => &mut self.signatures,
                    Field::Types => &mut self.types,
                    Field::TypeLibrary => &mut self.type_library,
                    Field::DebugTypes => &mut self.debug_types,
                    Field::LocalName => &mut self.local_names,
                    Field::LocalType => &mut self.local_types,
                    Field::TypeHint => &mut self.type_hints,
                    Field::DataType => &mut self.data_types,
                    Field::OperandType => &mut self.operand_types,
                    Field::Patch => &mut self.patches,
                    _ => &mut self.globals,
                };
                match &edit.value {
                    Some(value) => {
                        values.insert(edit.address, value.clone());
                    }
                    None => {
                        values.remove(&edit.address);
                    }
                }
            }
        }
    }

    /// Appends `edits` to the log in one write. Several are written as a batch (see `BatchHeader`), which readers
    /// apply whole or not at all, even if the write is cut short. A fully refreshed writer advances its cursor past
    /// its own append; otherwise the appended lines are read back, harmlessly, by the next `refresh`. An unterminated
    /// tail must be completed by its writer before another edit can append; padding an interrupted object with a
    /// newline would publish a syntactically invalid physical record.
    fn record(&mut self, edits: &[Edit]) -> Result<(), String> {
        if self.checked_reads
            || self.has_checked_annotations()
            || edits.iter().any(|edit| checked_annotation_field(edit.field))
            || edits.iter().any(|edit| self.introduces_checked_state(edit.field, edit.value.as_deref()))
        {
            return self.record_checked(edits);
        }
        let Some(log) = &mut self.log else { return Ok(()) };
        let error = |error: std::io::Error| format!("{}: {error}", log.path.display());
        let mut file = OpenOptions::new().read(true).create(true).append(true).open(&log.path).map_err(error)?;
        let before = file.metadata().map_err(error)?;
        let len = before.len();
        let mut last = *b"\n";
        if len > 0 {
            file.seek(SeekFrom::Start(len - 1)).map_err(error)?;
            file.read_exact(&mut last).map_err(error)?;
        }
        if last[0] != b'\n' {
            return Err("unterminated annotation tail; complete the existing record before appending".into());
        }
        let mut lines = String::new();
        let mut push = |line: Result<String, serde_json::Error>| -> Result<(), String> {
            lines.push_str(&line.map_err(|error| error.to_string())?);
            lines.push('\n');
            Ok(())
        };
        // Every caller has read the log up to now under its lock, so the last identity line is current.
        let new_image = log.image.clone().filter(|image| log.logged_image.as_ref() != Some(image));
        if let Some(image) = &new_image {
            push(serde_json::to_string(&ImageLine { image }))?;
        }
        if let [edit] = edits {
            push(serde_json::to_string(edit))?;
        } else {
            let batch = batch_id();
            push(serde_json::to_string(&BatchHeader { batch: batch.clone(), edits: edits.len() }))?;
            for edit in edits {
                push(serde_json::to_string(&BatchMember { edit, batch: &batch }))?;
            }
        }
        file.write_all(lines.as_bytes()).map_err(error)?;
        let after = file.metadata().map_err(error)?.len();
        if new_image.is_some() {
            log.logged_image = new_image;
        }
        log.adopt_own_append(len, file_identity(&before), lines.len() as u64, Some(after));
        Ok(())
    }

    fn record_checked(&mut self, edits: &[Edit]) -> Result<(), String> {
        let full_prefix = edits.iter().any(|edit| self.introduces_checked_state(edit.field, edit.value.as_deref()));
        let Some(log) = &mut self.log else { return Ok(()) };
        let new_image = log.image.clone().filter(|image| log.logged_image.as_ref() != Some(image));
        let mut encoded = CheckedLogBuffer::default();
        if let Some(image) = &new_image {
            encoded.line(&ImageLine { image })?;
        }
        if let [edit] = edits {
            encoded.line(edit)?;
        } else {
            let batch = batch_id();
            encoded.line(&BatchHeader { batch: batch.clone(), edits: edits.len() })?;
            for edit in edits {
                encoded.line(&BatchMember { edit, batch: &batch })?;
            }
        }
        checked_outer_preflight(&encoded.bytes)?;
        let mut file = checked_log_append(&log.path).map_err(|_| CHECKED_ERROR.to_owned())?;
        let before = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        if !before.is_file()
            || before.len() < log.read
            || (log.identity.is_some() && log.identity != file_identity(&before))
        {
            return Err(CHECKED_ERROR.to_owned());
        }
        if before.len() != 0 {
            file.seek(SeekFrom::Start(before.len() - 1)).map_err(|_| CHECKED_ERROR.to_owned())?;
            let mut last = [0];
            file.read_exact(&mut last).map_err(|_| CHECKED_ERROR.to_owned())?;
            if last != *b"\n" {
                return Err(CHECKED_ERROR.to_owned());
            }
        }
        if full_prefix {
            checked_full_log(log, edits)?;
        }
        let read = if full_prefix { 0 } else { log.read };
        let unread = usize::try_from(before.len() - read).map_err(|_| CHECKED_ERROR.to_owned())?;
        let combined_len =
            unread.checked_add(encoded.bytes.len()).filter(|&size| size <= CHECKED_READ_BYTES).ok_or(CHECKED_ERROR)?;
        let mut combined = Vec::with_capacity(combined_len);
        combined.resize(unread, 0);
        file.seek(SeekFrom::Start(read)).map_err(|_| CHECKED_ERROR.to_owned())?;
        file.read_exact(&mut combined).map_err(|_| CHECKED_ERROR.to_owned())?;
        combined.extend_from_slice(&encoded.bytes);
        checked_outer_preflight(&combined)?;
        let after = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        let pathname = std::fs::symlink_metadata(&log.path).map_err(|_| CHECKED_ERROR.to_owned())?;
        if pathname.file_type().is_symlink()
            || checked_log_stamp(&before) != checked_log_stamp(&after)
            || checked_log_stamp(&after) != checked_log_stamp(&pathname)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
        before.len().checked_add(encoded.bytes.len() as u64).ok_or(CHECKED_ERROR)?;
        file.write_all(&encoded.bytes).map_err(|_| CHECKED_ERROR.to_owned())?;
        if new_image.is_some() {
            log.logged_image = new_image;
        }
        let after = file.metadata().ok().map(|metadata| metadata.len());
        log.adopt_own_append(before.len(), file_identity(&before), encoded.bytes.len() as u64, after);
        Ok(())
    }

    fn commit(&mut self, edits: &[Edit]) -> Result<(), String> {
        self.record(edits)?;
        if self.patches.is_empty() && self.patch_freezer.is_some() {
            let mut active = std::collections::BTreeSet::new();
            for edit in edits.iter().filter(|edit| edit.field == Field::Patch) {
                if edit.value.is_some() {
                    active.insert(edit.address);
                } else {
                    active.remove(&edit.address);
                }
            }
            if !active.is_empty()
                && let Some(freeze) = &self.patch_freezer
            {
                freeze(self);
            }
        }
        for edit in edits {
            self.apply(edit);
        }
        Ok(())
    }

    /// Sets or clears `field` at `address`, recording the edit. Returns false when nothing changed.
    pub fn set(&mut self, field: Field, address: u64, value: Option<String>) -> Result<bool, String> {
        self.set_validated(field, address, value, |_| Ok(()))
    }

    /// Runs `work` holding the log's cross-process lock, after picking up other processes' edits, so that what it
    /// checks against them (such as a name being free) still holds when it edits.
    pub(crate) fn locked<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T, ApiError>) -> Result<T, ApiError> {
        let _lock = self.log_lock().map_err(ApiError::Invalid)?;
        self.refresh().map_err(ApiError::Invalid)?;
        self.held = true;
        let result = work(self);
        self.held = false;
        result
    }

    /// Checked PDB apply stages refresh, cursor and history under the same log lock, publishing only on success.
    /// This does not roll back durable writes: work must finish all fallible validation before its final commit.
    pub(crate) fn locked_staged<T>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let _lock = self.log_lock().map_err(ApiError::Invalid)?;
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: true,
            ..self.snapshot()
        };
        staged.refresh().map_err(ApiError::Invalid)?;
        let result = work(&mut staged)?;
        staged.held = self.held;
        self.publish_staged(staged);
        Ok(result)
    }

    /// Checked history publishes only on success; ordinary legacy history keeps shared refresh on refusal.
    pub(crate) fn locked_staged_history<T>(
        &mut self,
        redo: bool,
        work: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let history = if redo { &self.undone } else { &self.done };
        if history.is_empty() {
            return work(self);
        }
        let checked_target =
            history.last().is_some_and(|step| step.iter().any(|edit| checked_annotation_field(edit.field)));
        if self.checked_reads || self.has_checked_layouts() || self.has_checked_annotations() || checked_target {
            return self.locked_staged_checked(work);
        }

        let _lock = self.log_lock().map_err(ApiError::Invalid)?;
        // Legacy discovery retains legacy deserialization semantics. Parsed checked annotations require a bounded
        // reread from the original cursor, including batches that introduce and then clear those annotations.
        let shared_checked = if let Some(mut log) = self.log.clone() {
            let (_, edits) = read_new_edits(&mut log, false).map_err(ApiError::Invalid)?;
            edits.iter().any(|edit| checked_annotation_field(edit.field))
        } else {
            false
        };
        if shared_checked {
            self.preflight_checked().map_err(ApiError::Invalid)?;
        }
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: true,
            checked_reads: shared_checked,
            ..self.snapshot()
        };
        staged.refresh().map_err(ApiError::Invalid)?;
        let result = work(&mut staged);
        if shared_checked && result.is_err() {
            return result;
        }
        staged.checked_reads = self.checked_reads || staged.has_checked_layouts() || staged.has_checked_annotations();
        staged.held = self.held;
        self.publish_staged(staged);
        result
    }

    /// Checked import/option publication: preflight the already constructed object BEFORE cloning, and
    /// ingest shared edits with bounded outer JSON before publishing cache, history or cursor.
    pub(crate) fn locked_staged_checked<T>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.preflight_checked().map_err(ApiError::Invalid)?;
        let _lock = self.log_lock_checked().map_err(ApiError::Invalid)?;
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: true,
            checked_reads: true,
            ..self.snapshot()
        };
        staged.refresh().map_err(ApiError::Invalid)?;
        let result = work(&mut staged)?;
        staged.checked_reads = self.checked_reads || staged.has_checked_layouts() || staged.has_checked_annotations();
        staged.held = self.held;
        self.publish_staged(staged);
        Ok(result)
    }

    fn log_lock(&self) -> Result<Option<File>, String> {
        if self.checked_reads {
            return self.log_lock_checked();
        }
        let Some(log) = self.log.as_ref().filter(|_| !self.held) else { return Ok(None) };
        let mut path = log.path.as_os_str().to_owned();
        path.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        file.lock().map_err(|error| error.to_string())?;
        Ok(Some(file))
    }

    fn log_lock_checked(&self) -> Result<Option<File>, String> {
        let Some(log) = self.log.as_ref().filter(|_| !self.held) else { return Ok(None) };
        let mut path = log.path.as_os_str().to_owned();
        path.push(".lock");
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, open};
            let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let mode = Mode::RUSR | Mode::WUSR;
            let descriptor = open(std::path::Path::new(&path), flags, mode).map_err(|_| CHECKED_ERROR.to_owned())?;
            let file = File::from(descriptor);
            if !file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?.is_file() {
                return Err(CHECKED_ERROR.to_owned());
            }
            file.lock().map_err(|_| CHECKED_ERROR.to_owned())?;
            Ok(Some(file))
        }
        #[cfg(not(unix))]
        Err(CHECKED_ERROR.to_owned())
    }

    pub(crate) fn set_validated(
        &mut self,
        field: Field,
        address: u64,
        value: Option<String>,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<bool, String> {
        validate_project_address(field, address)?;
        let _lock = self.log_lock()?;
        if self.introduces_checked_state(field, value.as_deref()) {
            self.preflight_checked_log()?;
        }
        self.refresh()?;
        if self.checked_reads || checked_annotation_field(field) || self.has_checked_annotations() {
            self.preflight_checked()?;
        }
        let value_limit = if field == Field::Name { 128 } else { CHECKED_VALUE_BYTES };
        if self.checked_reads && value.as_ref().is_some_and(|value| value.len() > value_limit) {
            return Err(CHECKED_ERROR.to_owned());
        }
        let value = canonical_local_value(field, value.as_deref())?;
        let previous = self.field_map(field).get(&address).cloned();
        if previous == value {
            return Ok(false);
        }
        if field == Field::Types {
            crate::debug_layout_import::preserve_bundle(previous.as_deref(), value.as_deref())?;
        }
        let edit = Edit { field, address, value, previous };
        if self.checked_reads || checked_annotation_field(field) || self.has_checked_annotations() {
            self.preflight_checked_with_history(self, std::slice::from_ref(&edit))?;
        }
        let mut candidate = self.snapshot();
        candidate.apply(&edit);
        candidate.validate_local_collections()?;
        if self.checked_reads || checked_annotation_field(field) || self.has_checked_annotations() {
            candidate.preflight_checked_with_history(self, std::slice::from_ref(&edit))?;
        }
        crate::debug_layout_import::validate_transition(self, &candidate)?;
        validate(&candidate)?;
        self.commit(std::slice::from_ref(&edit))?;
        self.done.push(vec![edit]);
        self.undone.clear();
        Ok(true)
    }

    /// Sets each `(field, address, value)` in order as one undo step, after `validate` accepts the state they
    /// leave; all are recorded or none. Returns, for each, whether it changed anything.
    pub(crate) fn set_batch_validated(
        &mut self,
        changes: &[(Field, u64, Option<String>)],
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<bool>, String> {
        for (field, address, _) in changes {
            validate_project_address(*field, *address)?;
        }
        let _lock = self.log_lock()?;
        if changes.iter().any(|(field, _, value)| self.introduces_checked_state(*field, value.as_deref())) {
            self.preflight_checked_log()?;
        }
        self.refresh()?;
        if self.checked_reads
            || self.has_checked_annotations()
            || changes.iter().any(|change| checked_annotation_field(change.0))
        {
            self.preflight_checked()?;
            let mut budget = CheckedBudget::default();
            for (field, _, value) in changes {
                budget.records += 1;
                if let Some(value) = value {
                    if *field == Field::Name && value.len() > 128 {
                        return Err(CHECKED_ERROR.to_owned());
                    }
                    budget.text(value)?;
                }
            }
            if budget.records > CHECKED_RECORDS {
                return Err(CHECKED_ERROR.to_owned());
            }
        }
        let mut candidate = self.snapshot();
        let mut edits = Vec::new();
        let mut changed = Vec::with_capacity(changes.len());
        for (field, address, value) in changes {
            let value = canonical_local_value(*field, value.as_deref())?;
            let previous = candidate.field_map(*field).get(address).cloned();
            changed.push(previous != value);
            if previous != value {
                if *field == Field::Types {
                    crate::debug_layout_import::preserve_bundle(previous.as_deref(), value.as_deref())?;
                }
                let edit = Edit { field: *field, address: *address, value: value.clone(), previous };
                candidate.apply(&edit);
                edits.push(edit);
            }
        }
        if edits.is_empty() {
            return Ok(changed);
        }
        candidate.validate_local_collections()?;
        if self.checked_reads
            || self.has_checked_annotations()
            || edits.iter().any(|edit| checked_annotation_field(edit.field))
        {
            self.preflight_checked_with_history(self, &edits)?;
            candidate.preflight_checked_with_history(self, &edits)?;
        }
        crate::debug_layout_import::validate_transition(self, &candidate)?;
        validate(&candidate)?;
        self.commit(&edits)?;
        self.done.push(edits);
        self.undone.clear();
        Ok(changed)
    }

    pub(crate) fn import_signatures(
        &mut self,
        signatures: &[(u64, String)],
        prepare: impl Fn(&Self, u64, &str) -> String,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<u64>, String> {
        let _lock = self.log_lock()?;
        self.refresh()?;
        let mut candidate = self.snapshot();
        let mut seen = std::collections::BTreeSet::new();
        let edits: Vec<_> = signatures
            .iter()
            .filter(|(address, _)| !self.signatures.contains_key(address) && seen.insert(*address))
            .map(|(address, declaration)| Edit {
                field: Field::Signature,
                address: *address,
                value: Some(prepare(self, *address, declaration)),
                previous: None,
            })
            .collect();
        for edit in &edits {
            candidate.apply(edit);
        }
        candidate.validate_local_collections()?;
        validate(&candidate)?;
        let mut applied = Vec::new();
        for edit in edits {
            self.commit(std::slice::from_ref(&edit))?;
            self.undone.clear();
            applied.push(edit.address);
            self.done.push(vec![edit]);
        }
        Ok(applied)
    }

    /// Reverts the last step made through this instance: one edit, or a whole batch. Returns its edits, in the
    /// order they were made; empty when there is nothing to undo.
    pub fn undo(&mut self) -> Result<Vec<Edit>, String> {
        self.undo_validated(|_| Ok(()))
    }

    pub(crate) fn undo_validated(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<Edit>, String> {
        if self.done.is_empty() {
            return Ok(Vec::new());
        }
        let _lock = self.log_lock()?;
        self.refresh()?;
        if self.done.last().is_some_and(|step| step.iter().any(|edit| checked_annotation_field(edit.field))) {
            self.preflight_checked()?;
        }
        let Some(step) = self.done.last().cloned() else { return Ok(Vec::new()) };
        let inverses: Vec<Edit> = step.iter().rev().map(Edit::inverse).collect();
        self.replay(&inverses, validate).map_err(|refusal| match refusal {
            Refusal::Blocked(message) => format!("{message}{DISCARD_HINT}"),
            Refusal::Failed(message) => message,
        })?;
        self.done.pop();
        self.undone.push(step.clone());
        Ok(step)
    }

    /// Drops the last step from this instance's undo history without reverting it, for a step another client's
    /// edits block from undoing, which would otherwise block every earlier step too. Its edits stay in effect, and
    /// the log is untouched. Unless `force` is set, it refuses a step that undo could still revert: one client
    /// (such as an assistant sharing the user's project) must not silently take away another's undo. Returns the
    /// dropped step's edits; empty when there is nothing to undo.
    pub fn discard_undo_step(&mut self, force: bool) -> Result<Vec<Edit>, String> {
        let Some(step) = self.done.last() else { return Ok(Vec::new()) };
        if !force {
            let inverses: Vec<Edit> = step.iter().rev().map(Edit::inverse).collect();
            self.refresh()?;
            if self.snapshot().blocked(&inverses).is_none() {
                return Err("no other client's edit blocks undoing the last step, so undo can still revert it; \
                            discard it anyway only with force"
                    .to_owned());
            }
        }
        Ok(self.done.pop().unwrap_or_default())
    }

    /// Reapplies the last undone step. Returns its edits; empty when there is nothing to redo.
    pub fn redo(&mut self) -> Result<Vec<Edit>, String> {
        self.redo_validated(|_| Ok(()))
    }

    pub(crate) fn redo_validated(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<Edit>, String> {
        if self.undone.is_empty() {
            return Ok(Vec::new());
        }
        let _lock = self.log_lock()?;
        self.refresh()?;
        if self.undone.last().is_some_and(|step| step.iter().any(|edit| checked_annotation_field(edit.field))) {
            self.preflight_checked()?;
        }
        let Some(step) = self.undone.last().cloned() else { return Ok(Vec::new()) };
        self.replay(&step, validate).map_err(Refusal::message)?;
        self.undone.pop();
        self.done.push(step.clone());
        Ok(step)
    }

    /// Commits `edits` in order, each only over the value it replaces, and only once `validate` accepts the result
    /// when the step touches what the decompiler checks.
    fn replay(&mut self, edits: &[Edit], validate: impl FnOnce(&Self) -> Result<(), String>) -> Result<(), Refusal> {
        if self.checked_reads
            || self.has_checked_annotations()
            || edits.iter().any(|edit| checked_annotation_field(edit.field))
        {
            self.preflight_checked().map_err(Refusal::Failed)?;
            for edit in edits {
                CheckedBudget::default().edit(edit).map_err(Refusal::Failed)?;
            }
        }
        let mut candidate = self.snapshot();
        if let Some(message) = candidate.blocked(edits) {
            return Err(Refusal::Blocked(message));
        }
        if self.checked_reads
            || self.has_checked_annotations()
            || edits.iter().any(|edit| checked_annotation_field(edit.field))
        {
            candidate.preflight_checked_with_history(self, &[]).map_err(Refusal::Failed)?;
        }
        candidate.validate_local_collections().map_err(Refusal::Failed)?;
        crate::debug_layout_import::validate_transition(self, &candidate).map_err(Refusal::Failed)?;
        let checked = edits.iter().any(|edit| {
            matches!(
                edit.field,
                Field::Signature
                    | Field::Types
                    | Field::TypeLibrary
                    | Field::DebugTypes
                    | Field::Global
                    | Field::LocalName
                    | Field::LocalType
                    | Field::TypeHint
                    | Field::DataType
                    | Field::OperandType
                    | Field::Patch
            ) || (edit.field == Field::Name && (!candidate.globals().is_empty() || !candidate.data_types().is_empty()))
        });
        if checked {
            validate(&candidate).map_err(Refusal::Failed)?;
        }
        self.commit(edits).map_err(Refusal::Failed)
    }

    /// Applies `edits` to this state, saying why they cannot be replayed over other clients' edits: a field
    /// changed since, or a name since given to another address. `None` when nothing blocks them.
    fn blocked(&mut self, edits: &[Edit]) -> Option<String> {
        let mut conflicts = Vec::new();
        for edit in edits {
            if !self.is_unchanged(edit) {
                conflicts.push(edit.address);
            }
            self.apply(edit);
        }
        if !conflicts.is_empty() {
            conflicts.sort_unstable();
            conflicts.dedup();
            let verb = if conflicts.len() == 1 { "was" } else { "were" };
            return Some(format!("{} {verb} edited by another client since; not changed", address_list(&conflicts)));
        }
        let mut taken = Vec::new();
        for edit in edits.iter().filter(|edit| edit.field == Field::Name) {
            let Some(name) = &edit.value else { continue };
            if self.names.iter().any(|(&address, other)| other == name && address != edit.address) {
                taken.push(format!("{name:?}"));
            }
        }
        (!taken.is_empty())
            .then(|| format!("another client has since given {} to another address; not changed", taken.join(", ")))
    }

    /// Whether `edit`'s field still holds `edit.previous`: if another client changed it since, undoing or redoing
    /// over that change would silently discard it.
    fn is_unchanged(&self, edit: &Edit) -> bool {
        self.field_map(edit.field).get(&edit.address) == edit.previous.as_ref()
    }

    fn field_map(&self, field: Field) -> &BTreeMap<u64, String> {
        match field {
            Field::Name => &self.names,
            Field::Comment => &self.comments,
            Field::Signature => &self.signatures,
            Field::Types => &self.types,
            Field::TypeLibrary => &self.type_library,
            Field::DebugTypes => &self.debug_types,
            Field::Global => &self.globals,
            Field::LocalName => &self.local_names,
            Field::LocalType => &self.local_types,
            Field::TypeHint => &self.type_hints,
            Field::DataType => &self.data_types,
            Field::OperandType => &self.operand_types,
            Field::Patch => &self.patches,
            Field::Finding => &self.findings,
        }
    }

    pub fn name(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    pub fn comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.addresses.get(name).copied()
    }

    pub fn names(&self) -> &BTreeMap<u64, String> {
        &self.names
    }

    pub fn comments(&self) -> &BTreeMap<u64, String> {
        &self.comments
    }

    pub fn signatures(&self) -> &BTreeMap<u64, String> {
        &self.signatures
    }

    pub fn types(&self) -> &BTreeMap<u64, String> {
        &self.types
    }

    pub fn type_library(&self) -> &BTreeMap<u64, String> {
        &self.type_library
    }

    pub fn debug_types(&self) -> &BTreeMap<u64, String> {
        &self.debug_types
    }

    pub fn globals(&self) -> &BTreeMap<u64, String> {
        &self.globals
    }

    pub fn local_names(&self) -> &BTreeMap<u64, String> {
        &self.local_names
    }

    pub fn local_types(&self) -> &BTreeMap<u64, String> {
        &self.local_types
    }

    pub fn type_hints(&self) -> &BTreeMap<u64, String> {
        &self.type_hints
    }

    pub fn data_types(&self) -> &BTreeMap<u64, String> {
        &self.data_types
    }

    pub fn operand_types(&self) -> &BTreeMap<u64, String> {
        &self.operand_types
    }

    /// Ledger entries by id, as logged JSON.
    pub fn findings(&self) -> &BTreeMap<u64, String> {
        &self.findings
    }

    /// The id the next new ledger entry takes: one past every id any logged edit has used, including entries
    /// since undone, so a later session never sees one id name two different entries.
    pub(crate) fn next_finding_id(&self) -> u64 {
        self.finding_high.saturating_add(1)
    }

    /// The SHA-256 (hex) of the image these annotations are applied to, when known.
    pub(crate) fn image_sha256(&self) -> Option<&str> {
        self.log.as_ref().and_then(|log| log.image.as_deref())
    }

    pub fn patches(&self) -> &BTreeMap<u64, String> {
        &self.patches
    }

    pub(crate) fn values_equal(&self, other: &Self) -> bool {
        const FIELDS: [Field; 13] = [
            Field::Name,
            Field::Comment,
            Field::Signature,
            Field::Types,
            Field::TypeLibrary,
            Field::DebugTypes,
            Field::Global,
            Field::LocalName,
            Field::LocalType,
            Field::TypeHint,
            Field::DataType,
            Field::OperandType,
            Field::Patch,
        ];
        FIELDS.into_iter().all(|field| self.field_map(field) == other.field_map(field))
    }

    fn validate_local_collections(&self) -> Result<(), String> {
        self.validate_patches()?;
        for value in self.type_hints.values() {
            parse_type_hints(value)?;
        }
        for value in self.data_types.values() {
            parse_data_type(value)?;
        }
        for value in self.operand_types.values() {
            parse_operand_types(value)?;
        }
        for (&address, value) in &self.type_library {
            validate_project_address(Field::TypeLibrary, address)?;
            parse_type_library(value)?;
        }
        for (&address, value) in &self.debug_types {
            validate_project_address(Field::DebugTypes, address)?;
            parse_debug_types(value)?;
        }
        for address in self.local_names.keys().chain(self.local_types.keys()) {
            let names =
                self.local_names.get(address).map(|value| parse_local_names(value)).transpose()?.unwrap_or_default();
            let types =
                self.local_types.get(address).map(|value| parse_local_types(value)).transpose()?.unwrap_or_default();
            let extra_types =
                types.iter().filter(|entry| !names.iter().any(|name| name.storage == entry.storage)).count();
            if names.len() + extra_types > LOCAL_ENTRIES {
                return Err("local override count exceeds 256 per function".to_owned());
            }
        }
        crate::debug_type_import::validate_retained_proofs(self)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "annotations_local_tests.rs"]
mod local_tests;

#[cfg(test)]
#[path = "annotations_type_library_tests.rs"]
mod type_library_tests;

#[cfg(test)]
#[path = "annotations_debug_types_tests.rs"]
pub(crate) mod debug_types_tests;

#[cfg(test)]
#[path = "annotations_data_types_tests.rs"]
mod data_types_tests;

#[cfg(test)]
#[path = "annotations_type_hint_tests.rs"]
mod type_hint_tests;

/// A first checked transition must be readable from the beginning, not just from a legacy cursor that skipped lines.
fn checked_full_log(log: &Log, extra: &[Edit]) -> Result<(), String> {
    let mut full =
        Log { read: 0, identity: None, logged_image: None, unattributed: false, other_image: None, ..log.clone() };
    let (_, edits) = read_new_edits(&mut full, true)?;
    let mut budget = CheckedBudget::default();
    let mut candidate = Annotations { log: Some(full), checked_reads: true, ..Annotations::default() };
    for edit in edits.iter().chain(extra) {
        budget.edit(edit)?;
        candidate.apply(edit);
    }
    candidate.preflight_checked()
}

/// Reads the complete lines appended to `log` since it was last read. Returns their edits, and whether the file
/// was replaced (it shrank or is another file), in which case they are its whole contents and earlier state must be
/// dropped. Ordinary unbatched legacy fragments can be skipped. Patch-bearing malformed/torn records and batches
/// refuse the whole read; legacy-only incomplete batches remain pending for a later read.
fn read_new_edits(log: &mut Log, checked: bool) -> Result<(bool, Vec<Edit>), String> {
    let path = log.path.clone();
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    let opened = if checked || cfg!(unix) { checked_log_file(&path) } else { File::open(&path) };
    let mut file = match opened {
        Ok(file) => file,
        Err(problem) if problem.kind() == std::io::ErrorKind::NotFound => return Ok((false, Vec::new())),
        Err(problem) => return Err(error(problem)),
    };
    let metadata = file.metadata().map_err(error)?;
    if !metadata.is_file() || metadata.len().saturating_sub(log.read) > CHECKED_READ_BYTES as u64 {
        return Err(CHECKED_ERROR.to_owned());
    }
    let identity = file_identity(&metadata);
    let restart = metadata.len() < log.read || (log.identity.is_some() && log.identity != identity);
    if restart {
        *log = Log { path: path.clone(), image: log.image.take(), ..Log::default() };
    }
    log.identity = identity;
    if metadata.len() == log.read {
        return Ok((restart, Vec::new()));
    }
    if metadata.len().saturating_sub(log.read) > CHECKED_READ_BYTES as u64 {
        return Err(CHECKED_ERROR.to_owned());
    }
    file.seek(SeekFrom::Start(log.read)).map_err(error)?;
    let bytes = read_bounded_log(&mut file)?;
    if checked {
        checked_outer_preflight(&bytes)?;
        let after = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        let pathname = std::fs::symlink_metadata(&path).map_err(|_| CHECKED_ERROR.to_owned())?;
        if pathname.file_type().is_symlink()
            || checked_log_stamp(&metadata) != checked_log_stamp(&after)
            || checked_log_stamp(&after) != checked_log_stamp(&pathname)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
    }
    // Only complete lines: the rest may still be being written.
    let complete = bytes.iter().rposition(|&byte| byte == b'\n').map_or(0, |end| end + 1);
    let tail = &bytes[complete..];
    // Checked ingestion keeps its errors opaque; only legacy reads report the detailed record-shape problem.
    let shape_error = |problem: String| if checked { CHECKED_ERROR.to_owned() } else { problem };
    crate::patches::validate_log_record_tail(tail).map_err(shape_error)?;
    if crate::patches::patch_log_shape(tail).patch {
        return Err("unterminated patch record: patch records require a complete newline-terminated JSON line".into());
    }
    let mut lines = Vec::new();
    let mut start = 0;
    for line in bytes[..complete].split_inclusive(|&byte| byte == b'\n') {
        crate::patches::validate_patch_log_line(line).map_err(shape_error)?;
        lines.push((start, line));
        start += line.len();
    }
    let mut edits = Vec::new();
    let mut read = complete;
    let mut index = 0;
    while let Some(&(start, line)) = lines.get(index) {
        index += 1;
        match serde_json::from_slice::<LineKind>(line) {
            Ok(LineKind { batch: Some(batch), edits: Some(count), .. }) => {
                if checked && (batch.len() > 128 || count > CHECKED_RECORDS) {
                    return Err(CHECKED_ERROR.to_owned());
                }
                let members: Vec<Edit> =
                    lines[index..].iter().take(count).map_while(|(_, line)| batch_member(line, &batch)).collect();
                if members.len() != count
                    && lines[index..].iter().take(count).any(|(_, line)| crate::patches::patch_log_shape(line).patch)
                {
                    return Err("incomplete or mismatched patch batch; no members were applied".into());
                }
                index += members.len();
                if members.len() == count {
                    log.attribute_edits();
                    edits.extend(members);
                } else if index == lines.len() {
                    read = start;
                    break;
                }
            }
            Ok(LineKind { batch: Some(_), edits: None, .. }) => {
                if crate::patches::patch_log_shape(line).patch {
                    return Err("orphan patch batch member; no patch was applied".into());
                }
            }
            Ok(LineKind { batch: None, edits: None, image: Some(image) }) => {
                if checked && image.len() > 128 {
                    return Err(CHECKED_ERROR.to_owned());
                }
                log.read_image(image);
            }
            _ => {
                if let Ok(edit) = serde_json::from_slice::<Edit>(line) {
                    log.attribute_edits();
                    edits.push(edit);
                } else if checked {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
    }
    log.read += read as u64;
    Ok((restart, edits))
}

fn read_bounded_log(file: &mut File) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut line_bytes = 0usize;
    let mut records = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        let limit = chunk
            .len()
            .min(CHECKED_READ_BYTES - bytes.len() + 1)
            .min(CHECKED_LINE_BYTES - line_bytes + 1)
            .min(if records == CHECKED_RECORDS { 1 } else { chunk.len() });
        let length = file.read(&mut chunk[..limit]).map_err(|_| CHECKED_ERROR.to_owned())?;
        if length == 0 {
            break;
        }
        if records == CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        if bytes.len().checked_add(length).is_none_or(|length| length > CHECKED_READ_BYTES) {
            return Err(CHECKED_ERROR.to_owned());
        }
        for &byte in &chunk[..length] {
            if records == CHECKED_RECORDS {
                return Err(CHECKED_ERROR.to_owned());
            }
            line_bytes += 1;
            if line_bytes > CHECKED_LINE_BYTES {
                return Err(CHECKED_ERROR.to_owned());
            }
            if byte == b'\n' {
                records += 1;
                if records > CHECKED_RECORDS {
                    return Err(CHECKED_ERROR.to_owned());
                }
                line_bytes = 0;
            }
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    Ok(bytes)
}

fn checked_log_file(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = open(path, flags, Mode::empty())?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other(CHECKED_ERROR))
    }
}

fn checked_log_append(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        let flags =
            OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = open(path, flags, Mode::RUSR | Mode::WUSR)?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other(CHECKED_ERROR))
    }
}

#[derive(Default)]
struct CheckedLogBuffer {
    bytes: Vec<u8>,
    line_bytes: usize,
}

impl Write for CheckedLogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let error = || std::io::Error::other(CHECKED_ERROR);
        let size =
            self.bytes.len().checked_add(bytes.len()).filter(|&size| size <= CHECKED_READ_BYTES).ok_or_else(error)?;
        let mut line_bytes = self.line_bytes;
        for &byte in bytes {
            line_bytes += 1;
            if line_bytes > CHECKED_LINE_BYTES {
                return Err(error());
            }
            if byte == b'\n' {
                line_bytes = 0;
            }
        }
        if size > self.bytes.capacity() {
            let capacity = size.max(self.bytes.capacity().saturating_mul(2)).min(CHECKED_READ_BYTES);
            self.bytes.try_reserve_exact(capacity - self.bytes.len()).map_err(|_| error())?;
        }
        self.bytes.extend_from_slice(bytes);
        self.line_bytes = line_bytes;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CheckedLogBuffer {
    fn line(&mut self, value: &impl Serialize) -> Result<(), String> {
        serde_json::to_writer(&mut *self, value).map_err(|_| CHECKED_ERROR.to_owned())?;
        self.write_all(b"\n").map_err(|_| CHECKED_ERROR.to_owned())
    }
}

type CheckedLogStamp = (Option<(u64, u64)>, u64, Option<std::time::SystemTime>, i64, i64);

fn checked_log_stamp(metadata: &std::fs::Metadata) -> CheckedLogStamp {
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        (metadata.ctime(), metadata.ctime_nsec())
    };
    #[cfg(not(unix))]
    let changed = (0, 0);
    (file_identity(metadata), metadata.len(), metadata.modified().ok(), changed.0, changed.1)
}

fn checked_outer_preflight(bytes: &[u8]) -> Result<(), String> {
    checked_json_preflight(bytes, true)
}

fn checked_json_preflight(bytes: &[u8], json_lines: bool) -> Result<(), String> {
    let mut records = 0usize;
    let mut separators = 0usize;
    for line in bytes.split_inclusive(|&byte| json_lines && byte == b'\n') {
        records += 1;
        if records > CHECKED_RECORDS || line.len() > CHECKED_LINE_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
        let mut depth = 0usize;
        let mut string = false;
        let mut escaped = false;
        for &byte in line {
            if string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
            } else {
                match byte {
                    b'"' => string = true,
                    b'{' | b'[' => {
                        depth += 1;
                        separators += 1;
                    }
                    b'}' | b']' => depth = depth.checked_sub(1).ok_or(CHECKED_ERROR)?,
                    b',' | b':' => separators += 1,
                    _ => {}
                }
                if depth > 8 || separators > 65536 {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
        if (!json_lines || line.ends_with(b"\n")) && (depth != 0 || string) {
            return Err(CHECKED_ERROR.to_owned());
        }
    }
    Ok(())
}

/// The edit `line` holds if it belongs to `batch`.
fn batch_member(line: &[u8], batch: &str) -> Option<Edit> {
    let kind: LineKind = serde_json::from_slice(line).ok()?;
    if kind.edits.is_some() || kind.batch.as_deref() != Some(batch) {
        return None;
    }
    serde_json::from_slice(line).ok()
}

/// The most addresses an error lists before counting the rest.
const LISTED_ADDRESSES: usize = 20;

fn address_list(addresses: &[u64]) -> String {
    let mut list: Vec<String> =
        addresses.iter().take(LISTED_ADDRESSES).map(|address| format!("{address:#x}")).collect();
    if addresses.len() > LISTED_ADDRESSES {
        list.push(format!("{} more", addresses.len() - LISTED_ADDRESSES));
    }
    list.join(", ")
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CheckedLogFiles(PathBuf);

    impl Drop for CheckedLogFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            cleanup_lock(self.0.clone());
        }
    }

    #[test]
    fn indexed_duplicate_name_owners_keep_last_writer_and_lowest_surviving_address() {
        let files = CheckedLogFiles(temporary_log("checked-duplicate-name-owners"));
        let mut first = Annotations::open_checked(files.0.clone()).unwrap();
        first.set(Field::Name, 20, Some("shared".to_owned())).unwrap();
        let mut second = Annotations::open_checked(files.0.clone()).unwrap();
        second.set(Field::Name, 10, Some("shared".to_owned())).unwrap();
        second.set(Field::Name, 30, Some("shared".to_owned())).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(30));
        first.refresh().unwrap();
        assert_eq!(first.address_of("shared"), Some(30));
        second.set(Field::Name, 30, None).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(10));
        first.refresh().unwrap();
        assert_eq!(first.address_of("shared"), Some(10));
        assert!(second.undo().unwrap_err().contains("another address"));
        assert_eq!(second.address_of("shared"), Some(10));
        second.set(Field::Name, 30, Some("shared".to_owned())).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(30));
    }

    #[test]
    fn checked_encoded_line_limits_reject_before_append_and_preserve_readable_undo() {
        let files = CheckedLogFiles(temporary_log("checked-encoded-write"));
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        let before = annotations.log.clone();
        let oversized = "\0".repeat(384 * 1024);
        assert_eq!(annotations.set(Field::Comment, 1, Some(oversized)).unwrap_err(), CHECKED_ERROR);
        assert!(!files.0.exists());
        assert!(annotations.comments.is_empty() && annotations.done.is_empty() && annotations.undone.is_empty());
        assert_eq!(annotations.log, before);
        let accepted = "\0".repeat(32);
        annotations.set(Field::Comment, 1, Some(accepted.clone())).unwrap();
        annotations.refresh().unwrap();
        assert_eq!(annotations.comment(1), Some(accepted.as_str()));
        assert_eq!(annotations.undo().unwrap().len(), 1);
        annotations.refresh().unwrap();
        assert_eq!(annotations.comment(1), None);
        assert_eq!(Annotations::open_checked(files.0.clone()).unwrap().comment(1), None);
    }

    #[test]
    fn checked_writer_refuses_an_unterminated_tail_without_extending_it() {
        let files = CheckedLogFiles(temporary_log("checked-pending-tail"));
        let partial = b"{\"field\":\"comment\"";
        std::fs::write(&files.0, partial).unwrap();
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        assert_eq!(annotations.set(Field::Comment, 1, Some("new".to_owned())).unwrap_err(), CHECKED_ERROR);
        assert_eq!(std::fs::read(&files.0).unwrap(), partial);
        assert!(annotations.comments.is_empty() && annotations.done.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
    }

    #[test]
    fn checked_writer_counts_pending_batch_bytes_before_appending_a_new_record() {
        let files = CheckedLogFiles(temporary_log("checked-pending-byte-budget"));
        let mut file = File::create(&files.0).unwrap();
        serde_json::to_writer(&mut file, &BatchHeader { batch: "pending".to_owned(), edits: 3901 }).unwrap();
        file.write_all(b"\n").unwrap();
        for address in 0..3900 {
            let edit = Edit { field: Field::Comment, address, value: Some("p".repeat(4000)), previous: None };
            serde_json::to_writer(&mut file, &BatchMember { edit: &edit, batch: "pending" }).unwrap();
            file.write_all(b"\n").unwrap();
        }
        drop(file);
        let length = std::fs::metadata(&files.0).unwrap().len();
        assert!(length < CHECKED_READ_BYTES as u64);
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        assert!(annotations.comments.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
        let value = "\0".repeat(300 * 1024);
        assert_eq!(annotations.set(Field::Comment, 10_000, Some(value)).unwrap_err(), CHECKED_ERROR);
        assert_eq!(std::fs::metadata(&files.0).unwrap().len(), length);
        assert!(annotations.comments.is_empty() && annotations.done.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
        Annotations::open_checked(files.0.clone()).unwrap();
    }

    #[test]
    fn checked_open_bounds_a_real_large_types_envelope_before_decoding() {
        let path = temporary_log("checked-large-types-envelope");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"{\"field\":\"types\",\"address\":\"0x1\",\"value\":\"").unwrap();
        let chunk = [b'x'; 65536];
        for _ in 0..(CHECKED_READ_BYTES / chunk.len() + 1) {
            file.write_all(&chunk).unwrap();
        }
        file.write_all(b"\",\"previous\":null}\n").unwrap();
        drop(file);
        let length = std::fs::metadata(&path).unwrap().len();
        assert_eq!(Annotations::open_checked(path.clone()).err().unwrap(), CHECKED_ERROR);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        cleanup(path);
    }

    #[test]
    fn checked_staging_rejects_hostile_escapes_without_publishing_cursor_cache_or_history() {
        let path = temporary_log("checked-hostile-escapes");
        let mut annotations = Annotations::open_checked(path.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("original".to_owned())).unwrap();
        annotations.refresh().unwrap();
        let before_log = annotations.log.clone();
        let before_done = annotations.done.clone();
        let before_undone = annotations.undone.clone();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"field\":\"types\",\"address\":\"0x2\",\"value\":\"\\u0021rampage-layout\\n").unwrap();
        let escaped = b"\\u0078".repeat(4096);
        for _ in 0..(CHECKED_LINE_BYTES / escaped.len() + 1) {
            file.write_all(&escaped).unwrap();
        }
        file.write_all(b"\",\"previous\":null}\n").unwrap();
        drop(file);
        let length = std::fs::metadata(&path).unwrap().len();
        let result: Result<(), ApiError> = annotations.locked_staged_checked(|_| panic!("must refuse before work"));
        assert_eq!(result.unwrap_err().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.log, before_log);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(annotations.comment(1), Some("original"));
        assert!(annotations.types().is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        cleanup(path);
    }

    #[test]
    fn checked_snapshot_preflights_preconstructed_legacy_cache_and_history_without_cloning() {
        let mut annotations = Annotations::in_memory();
        annotations.comments.insert(1, "x".repeat(CHECKED_VALUE_BYTES + 1));
        assert_eq!(annotations.checked_snapshot().err().unwrap().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.comments[&1].len(), CHECKED_VALUE_BYTES + 1);
        annotations.comments.clear();
        annotations.done.resize_with(CHECKED_HISTORY_STEPS + 1, Vec::new);
        assert_eq!(annotations.checked_snapshot().err().unwrap().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.done.len(), CHECKED_HISTORY_STEPS + 1);
    }

    #[test]
    fn checked_precommit_reserves_the_new_step_and_keeps_its_undo_state_representable() {
        for edit_count in [1usize, 2] {
            let largest_base = CHECKED_RECORDS - (5 + 3 * edit_count);
            for excess in [0, 1] {
                let original = Annotations {
                    comments: (0..largest_base + excess).map(|address| (address as u64, "x".to_owned())).collect(),
                    log: Some(Log { path: PathBuf::from("checked-budget.rampage"), ..Default::default() }),
                    checked_reads: true,
                    ..Default::default()
                };
                original.preflight_checked().unwrap();
                let edits: Vec<_> = (0..edit_count)
                    .map(|index| Edit {
                        field: Field::Comment,
                        address: 10_000 + index as u64,
                        value: Some("x".to_owned()),
                        previous: None,
                    })
                    .collect();
                let mut candidate = original.snapshot();
                for edit in &edits {
                    candidate.apply(edit);
                }
                let result = candidate.preflight_checked_with_history(&original, &edits);
                if excess != 0 {
                    assert_eq!(result.unwrap_err(), CHECKED_ERROR);
                    assert!(original.done.is_empty());
                    continue;
                }
                result.unwrap();
                candidate.log = original.log.clone();
                candidate.done.push(edits);
                candidate.preflight_checked().unwrap();
                original.preflight_checked_with_history(&candidate, &[]).unwrap();
            }
        }
    }

    #[test]
    fn checked_reader_rejects_deep_complete_json_but_legacy_reader_keeps_ordinary_compatibility() {
        let path = temporary_log("checked-deep-json");
        let nested = format!("{}0{}", "[".repeat(9), "]".repeat(9));
        let text = format!(
            "{{\"field\":\"comment\",\"address\":\"0x1\",\"value\":\"kept\",\"previous\":null,\"extra\":{nested}}}\n"
        );
        std::fs::write(&path, text).unwrap();
        assert_eq!(Annotations::open_checked(path.clone()).err().unwrap(), CHECKED_ERROR);
        assert_eq!(Annotations::open(path.clone()).unwrap().comment(1), Some("kept"));
        cleanup(path);
    }

    fn append_foreign_comment(path: &std::path::Path, address: u64, value: &str) {
        let edit = Edit { field: Field::Comment, address, value: Some(value.to_owned()), previous: None };
        let mut line = serde_json::to_string(&edit).unwrap();
        line.push('\n');
        OpenOptions::new().append(true).open(path).unwrap().write_all(line.as_bytes()).unwrap();
    }

    fn own_comment(annotations: &Annotations, address: u64, value: &str) -> Edit {
        Edit {
            field: Field::Comment,
            address,
            value: Some(value.to_owned()),
            previous: annotations.comment(address).map(str::to_owned),
        }
    }

    #[test]
    fn unchecked_writer_adopts_its_own_append_at_the_read_end() {
        let files = CheckedLogFiles(temporary_log("unchecked-own-append"));
        let mut annotations = Annotations::open(files.0.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("own".to_owned())).unwrap();
        assert_eq!(annotations.test_log_cursor(), Some(std::fs::metadata(&files.0).unwrap().len()));
        assert!(!annotations.refresh().unwrap());
        assert_eq!(annotations.comment(1), Some("own"));
    }

    #[test]
    fn unchecked_writer_behind_the_read_end_reads_its_append_back_in_disk_order() {
        let files = CheckedLogFiles(temporary_log("unchecked-behind-read-end"));
        let mut annotations = Annotations::open(files.0.clone()).unwrap();
        annotations.set(Field::Comment, 2, Some("first".to_owned())).unwrap();
        let cursor = annotations.test_log_cursor();
        append_foreign_comment(&files.0, 1, "foreign");
        let edit = own_comment(&annotations, 1, "own");
        annotations.commit(std::slice::from_ref(&edit)).unwrap();
        assert_eq!(annotations.test_log_cursor(), cursor);
        assert!(annotations.refresh().unwrap());
        assert_eq!(annotations.test_log_cursor(), Some(std::fs::metadata(&files.0).unwrap().len()));
        assert_eq!(annotations.comment(1), Some("own"));
        assert_eq!(Annotations::open(files.0.clone()).unwrap().comment(1), Some("own"));
    }

    #[test]
    fn checked_writer_behind_the_read_end_reads_its_append_back_in_disk_order() {
        let files = CheckedLogFiles(temporary_log("checked-behind-read-end"));
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        annotations.set(Field::Comment, 2, Some("first".to_owned())).unwrap();
        assert_eq!(annotations.test_log_cursor(), Some(std::fs::metadata(&files.0).unwrap().len()));
        assert!(!annotations.refresh().unwrap());
        let cursor = annotations.test_log_cursor();
        append_foreign_comment(&files.0, 1, "foreign");
        let edit = own_comment(&annotations, 1, "own");
        annotations.commit(std::slice::from_ref(&edit)).unwrap();
        assert_eq!(annotations.test_log_cursor(), cursor);
        assert!(annotations.refresh().unwrap());
        assert_eq!(annotations.test_log_cursor(), Some(std::fs::metadata(&files.0).unwrap().len()));
        assert_eq!(annotations.comment(1), Some("own"));
        assert_eq!(Annotations::open_checked(files.0.clone()).unwrap().comment(1), Some("own"));
    }

    fn temporary_log(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rampage-{name}-{}.rampage", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn cleanup(path: PathBuf) {
        std::fs::remove_file(&path).unwrap();
        cleanup_lock(path);
    }

    fn cleanup_lock(path: PathBuf) {
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }

    #[test]
    fn edits_undo_redo_and_replay_from_the_log() {
        let path = temporary_log("annotations");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        assert!(annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        assert!(!annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        annotations.set(Field::Comment, 0x1004, Some("length check".into())).unwrap();
        annotations.set(Field::Name, 0x1000, Some("parse_header".into())).unwrap();
        assert_eq!(annotations.undo().unwrap()[0].value, Some("parse_header".into()));
        assert_eq!(annotations.name(0x1000), Some("parse"));
        assert_eq!(annotations.address_of("parse_header"), None);
        annotations.redo().unwrap();
        assert_eq!(annotations.name(0x1000), Some("parse_header"));
        annotations.set(Field::Comment, 0x1004, None).unwrap();

        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!(replayed.name(0x1000), Some("parse_header"));
        assert_eq!(replayed.comment(0x1004), None);
        assert_eq!(replayed.address_of("parse_header"), Some(0x1000));
        cleanup(path);
    }

    #[test]
    fn sees_edits_from_another_writer() {
        let path = temporary_log("shared");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Name, 0x2000, Some("decrypt".into())).unwrap();
        assert!(ui.refresh().unwrap());
        assert_eq!(ui.name(0x2000), Some("decrypt"));
        ui.set(Field::Comment, 0x2000, Some("xor loop".into())).unwrap();
        agent.set(Field::Name, 0x2000, Some("decrypt_config".into())).unwrap();
        assert_eq!(agent.comment(0x2000), Some("xor loop"));
        ui.refresh().unwrap();
        assert_eq!(ui.name(0x2000), Some("decrypt_config"));
        cleanup(path);
    }

    #[test]
    fn failed_staged_refresh_preserves_private_cache_history_cursor_and_external_log_bytes() {
        let path = temporary_log("failed-staged-refresh");
        let mut annotations = Annotations::open_for_image(path.clone(), Some([1; 32])).unwrap();
        for (field, address, value) in [
            (Field::Name, 0x10, "original"),
            (Field::Comment, 0x20, "original comment"),
            (Field::Signature, 0x30, "int4 original(void);"),
            (Field::Types, 0x40, "typedef int4 original_type;"),
            (Field::Global, 0x50, "int4 original_global;"),
        ] {
            annotations.set(field, address, Some(value.to_owned())).unwrap();
        }
        annotations.set(Field::Comment, 0x60, Some("redo comment".to_owned())).unwrap();
        annotations.undo().unwrap();
        annotations.refresh().unwrap();
        let before_cache = annotations.snapshot();
        let before_done = annotations.done.clone();
        let before_undone = annotations.undone.clone();
        let before_log = annotations.log.clone();
        let before_warnings = annotations.warnings();
        assert!(!before_done.is_empty());
        assert!(!before_undone.is_empty());
        assert!(!annotations.held);

        let mut writer = Annotations::open_for_image(path.clone(), Some([2; 32])).unwrap();
        for (field, address, value) in [
            (Field::Name, 0x10, "external_name"),
            (Field::Comment, 0x20, "external comment"),
            (Field::Signature, 0x30, "int4 external_name(void);"),
            (Field::Types, 0x40, "typedef int4 external_type;"),
            (Field::Global, 0x50, "int4 external_global;"),
        ] {
            writer.set(field, address, Some(value.to_owned())).unwrap();
        }
        let external_bytes = std::fs::read(&path).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged(|staged| {
            assert!(staged.held);
            assert_eq!(staged.name(0x10), Some("external_name"));
            assert_eq!(staged.address_of("original"), None);
            assert_eq!(staged.comment(0x20), Some("external comment"));
            assert_eq!(staged.signatures()[&0x30], "int4 external_name(void);");
            assert_eq!(staged.types()[&0x40], "typedef int4 external_type;");
            assert_eq!(staged.globals()[&0x50], "int4 external_global;");
            assert!(staged.log.as_ref().unwrap().read > before_log.as_ref().unwrap().read);
            assert_ne!(staged.warnings(), before_warnings);
            Err(ApiError::Invalid("source changed after staged refresh".to_owned()))
        });
        assert!(result.unwrap_err().to_string().contains("source changed"));
        assert_eq!(annotations.names, before_cache.names);
        assert_eq!(annotations.addresses, before_cache.addresses);
        assert_eq!(annotations.comments, before_cache.comments);
        assert_eq!(annotations.signatures, before_cache.signatures);
        assert_eq!(annotations.types, before_cache.types);
        assert_eq!(annotations.globals, before_cache.globals);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(annotations.log, before_log);
        assert_eq!(annotations.warnings(), before_warnings);
        assert!(!annotations.held);
        assert_eq!(std::fs::read(&path).unwrap(), external_bytes);

        assert!(annotations.refresh().unwrap());
        assert_eq!(annotations.name(0x10), Some("external_name"));
        assert_eq!(annotations.address_of("external_name"), Some(0x10));
        assert_eq!(annotations.comment(0x20), Some("external comment"));
        assert_ne!(annotations.warnings(), before_warnings);
        assert_eq!(annotations.log.as_ref().unwrap().read, external_bytes.len() as u64);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(std::fs::read(&path).unwrap(), external_bytes);
        assert!(!annotations.refresh().unwrap());
        cleanup(path);
    }

    #[test]
    fn staged_batch_success_publishes_history_and_preserves_an_outer_log_lock_on_success_and_failure() {
        let path = temporary_log("nested-staged-batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Comment, 0x10, Some("earlier step".to_owned())).unwrap();
        let changes = [(Field::Name, 0x10, Some("first".to_owned())), (Field::Name, 0x20, Some("second".to_owned()))];
        annotations
            .locked(|outer| {
                assert!(outer.held);
                let changed = outer.locked_staged(|staged| {
                    assert!(staged.held);
                    staged.set_batch_validated(&changes, |_| Ok(())).map_err(ApiError::Invalid)
                })?;
                assert_eq!(changed, [true, true]);
                assert!(outer.held);
                assert_eq!(outer.name(0x10), Some("first"));
                assert_eq!(outer.done.len(), 2);
                let before = std::fs::read(&path).unwrap();
                let failed: Result<(), ApiError> = outer.locked_staged(|staged| {
                    assert!(staged.held);
                    Err(ApiError::Invalid("source changed".to_owned()))
                });
                assert!(failed.is_err());
                assert!(outer.held);
                assert_eq!(std::fs::read(&path).unwrap(), before);
                Ok(())
            })
            .unwrap();
        assert!(!annotations.held);
        assert_eq!(annotations.undo().unwrap().len(), 2);
        assert!(annotations.names().is_empty());
        assert_eq!(annotations.undo().unwrap()[0].value.as_deref(), Some("earlier step"));
        cleanup(path);
    }

    #[test]
    fn survives_an_interrupted_write() {
        let path = temporary_log("interrupted");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Name, 0x10, Some("first".into())).unwrap();
        OpenOptions::new().append(true).open(&path).unwrap().write_all(br#"{"field":"name","addr"#).unwrap();
        let mut reopened = Annotations::open(path.clone()).unwrap();
        assert_eq!(reopened.name(0x10), Some("first"));
        let before = std::fs::read(&path).unwrap();
        assert!(reopened.set(Field::Name, 0x20, Some("second".into())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"ess\":\"0x20\",\"value\":\"second\",\"previous\":null}\n")
            .unwrap();
        assert!(reopened.refresh().unwrap());
        reopened.set(Field::Name, 0x40, Some("after".into())).unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("first"), Some("second")));
        cleanup(path);
    }

    #[test]
    fn a_line_read_while_half_written_is_read_whole_later() {
        let path = temporary_log("torn");
        let mut reader = Annotations::open(path.clone()).unwrap();
        let line = serde_json::to_string(&Edit {
            field: Field::Name,
            address: 0x30,
            value: Some("late".into()),
            previous: None,
        })
        .unwrap();
        let (head, tail) = line.split_at(10);
        let mut file = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        file.write_all(head.as_bytes()).unwrap();
        assert!(!reader.refresh().unwrap());
        file.write_all(format!("{tail}\n").as_bytes()).unwrap();
        assert!(reader.refresh().unwrap());
        assert_eq!(reader.name(0x30), Some("late"));
        reader.set(Field::Name, 0x40, Some("after".into())).unwrap();
        assert_eq!(Annotations::open(path.clone()).unwrap().name(0x40), Some("after"));
        cleanup(path);
    }

    #[test]
    fn undo_refuses_to_discard_another_clients_edit() {
        let path = temporary_log("conflict");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        ui.set(Field::Name, 0x10, Some("a".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("b".into())).unwrap();
        assert!(ui.undo().is_err());
        assert_eq!(ui.name(0x10), Some("b"));
        cleanup(path);
    }

    #[test]
    fn discarding_a_blocked_undo_step_unblocks_the_earlier_ones() {
        let path = temporary_log("discard");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        ui.set(Field::Comment, 0x20, Some("kept".into())).unwrap();
        ui.set(Field::Name, 0x10, Some("a".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("b".into())).unwrap();
        let error = ui.undo().unwrap_err();
        assert!(error.contains("discard_undo"), "{error}");
        assert!(ui.undo().is_err());
        let log = std::fs::read_to_string(&path).unwrap();

        let discarded = ui.discard_undo_step(false).unwrap();
        assert_eq!(discarded.len(), 1);
        assert_eq!((discarded[0].address, discarded[0].value.as_deref()), (0x10, Some("a")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), log);
        assert_eq!(ui.name(0x10), Some("b"));
        assert_eq!(ui.undo().unwrap()[0].address, 0x20);
        assert_eq!(ui.comment(0x20), None);
        assert!(ui.discard_undo_step(false).unwrap().is_empty());
        cleanup(path);
    }

    #[test]
    fn discarding_refuses_a_step_undo_could_still_revert_unless_forced() {
        let path = temporary_log("discard-unblocked");
        let mut user = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        user.set(Field::Name, 0x10, Some("parse".into())).unwrap();
        // Another client's edit elsewhere does not block it.
        agent.set(Field::Name, 0x20, Some("other".into())).unwrap();
        let error = user.discard_undo_step(false).unwrap_err();
        assert!(error.contains("force"), "{error}");
        assert_eq!(user.undo().unwrap()[0].address, 0x10, "the step is still there to undo");
        user.redo().unwrap();
        let dropped = user.discard_undo_step(true).unwrap();
        assert_eq!((dropped[0].address, user.name(0x10)), (0x10, Some("parse")));
        assert!(user.undo().unwrap().is_empty());
        // A name another client has since taken blocks it as much as an edit to the same address.
        user.set(Field::Name, 0x30, Some("first".into())).unwrap();
        user.set(Field::Name, 0x30, Some("second".into())).unwrap();
        agent.set(Field::Name, 0x40, Some("first".into())).unwrap();
        assert_eq!(user.discard_undo_step(false).unwrap()[0].value.as_deref(), Some("second"));
        cleanup(path);
    }

    #[test]
    fn only_a_refusal_over_another_clients_edit_suggests_discarding() {
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x10, Some("int4 f(void);".into())).unwrap();
        let error = annotations.undo_validated(|_| Err("the decompiler rejects it".to_owned())).unwrap_err();
        assert_eq!(error, "the decompiler rejects it");
        assert!(annotations.discard_undo_step(false).is_err(), "a validation failure is no other client's block");

        let path = temporary_log("undo-io");
        let mut writer = Annotations::open(path.clone()).unwrap();
        writer.set(Field::Comment, 0x10, Some("note".into())).unwrap();
        let writable = std::fs::metadata(&path).unwrap().permissions();
        let mut read_only = writable.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&path, read_only).unwrap();
        let error = writer.undo().unwrap_err();
        assert!(!error.contains("discard_undo"), "{error}");
        std::fs::set_permissions(&path, writable).unwrap();

        let mut agent = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Comment, 0x10, Some("changed".into())).unwrap();
        assert!(writer.undo().unwrap_err().contains("discard_undo"));
        cleanup(path);
    }

    #[test]
    fn a_name_left_at_two_addresses_still_resolves() {
        let mut annotations = Annotations::in_memory();
        let edit =
            |address, value: &str| Edit { field: Field::Name, address, value: Some(value.into()), previous: None };
        annotations.apply(&edit(0x10, "foo"));
        annotations.apply(&edit(0x20, "foo"));
        annotations.apply(&edit(0x20, "baz"));
        assert_eq!(annotations.address_of("foo"), Some(0x10));
    }

    #[test]
    fn debug_import_deduplicates_entries_and_does_not_replace_existing_signatures() {
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x10, Some("int4 preserved(void);".to_owned())).unwrap();
        let candidates = vec![
            (0x10, "int4 ignored(void);".to_owned()),
            (0x20, "int4 first(void);".to_owned()),
            (0x20, "int4 second(void);".to_owned()),
        ];
        let applied =
            annotations.import_signatures(&candidates, |_, _, declaration| declaration.to_owned(), |_| Ok(())).unwrap();
        assert_eq!(applied, vec![0x20]);
        assert_eq!(annotations.signatures()[&0x10], "int4 preserved(void);");
        assert_eq!(annotations.signatures()[&0x20], "int4 first(void);");
        annotations.undo().unwrap();
        assert!(!annotations.signatures().contains_key(&0x20));
        annotations.redo().unwrap();
        assert_eq!(annotations.signatures()[&0x20], "int4 first(void);");
    }

    #[test]
    fn a_batch_is_one_undo_step_written_in_one_append() {
        let path = temporary_log("batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Comment, 0x10, Some("before".into())).unwrap();
        let changes = vec![
            (Field::Name, 0x10, Some("first".to_owned())),
            (Field::Comment, 0x10, Some("before".to_owned())),
            (Field::Name, 0x20, Some("second".to_owned())),
            (Field::Comment, 0x20, Some("note".to_owned())),
        ];
        assert_eq!(annotations.set_batch_validated(&changes, |_| Ok(())).unwrap(), [true, false, true, true]);
        assert_eq!(annotations.undo().unwrap().len(), 3);
        assert_eq!((annotations.name(0x10), annotations.name(0x20), annotations.comment(0x20)), (None, None, None));
        assert_eq!(annotations.comment(0x10), Some("before"));
        annotations.redo().unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("first"), Some("second")));
        assert_eq!(replayed.comment(0x20), Some("note"));
        assert_eq!(annotations.undo().unwrap().len(), 3);
        assert_eq!(annotations.undo().unwrap()[0].value.as_deref(), Some("before"));
        assert!(annotations.undo().unwrap().is_empty());
        cleanup(path);
    }

    #[test]
    fn a_refused_batch_records_nothing() {
        let path = temporary_log("refused-batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        assert!(annotations.set_batch_validated(&changes, |_| Err("no".to_owned())).is_err());
        assert!(annotations.names().is_empty());
        assert!(annotations.undo().unwrap().is_empty());
        assert!(Annotations::open(path.clone()).unwrap().names().is_empty());
        let _ = std::fs::remove_file(&path);
        cleanup_lock(path);
    }

    #[test]
    fn undoing_a_batch_refuses_when_another_client_changed_any_of_it() {
        let path = temporary_log("batch-conflict");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        agent.set_batch_validated(&changes, |_| Ok(())).unwrap();
        ui.set(Field::Name, 0x20, Some("c".into())).unwrap();
        assert!(agent.undo().is_err());
        assert_eq!((agent.name(0x10), agent.name(0x20)), (Some("a"), Some("c")));
        cleanup(path);
    }

    fn name_edit(address: u64, value: &str) -> Edit {
        Edit { field: Field::Name, address, value: Some(value.into()), previous: None }
    }

    fn append(path: &PathBuf, text: &str) {
        OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn a_batch_is_logged_under_a_header_and_replays_whole() {
        let path = temporary_log("batch-header");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        let header: BatchHeader = serde_json::from_str(lines[0]).unwrap();
        assert_eq!((header.edits, lines.len()), (2, 3));
        assert!(lines[1..].iter().all(|line| line.contains(&format!("\"batch\":\"{}\"", header.batch))));
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("a"), Some("b")));
        cleanup(path);
    }

    #[test]
    fn a_batch_cut_short_is_never_applied() {
        let path = temporary_log("batch-truncated");
        let header = serde_json::to_string(&BatchHeader { batch: "cut".into(), edits: 3 }).unwrap();
        let member = |address, value| {
            serde_json::to_string(&BatchMember { edit: &name_edit(address, value), batch: "cut" }).unwrap()
        };
        append(&path, &format!("{header}\n{}\n{}\n", member(0x10, "a"), member(0x20, "b")));
        let mut reader = Annotations::open(path.clone()).unwrap();
        assert!(reader.names().is_empty());

        // The interrupted write is followed by another client's edits, which are not taken for the rest of it.
        let mut writer = Annotations::open(path.clone()).unwrap();
        writer.set(Field::Name, 0x30, Some("c".into())).unwrap();
        writer
            .set_batch_validated(
                &[(Field::Name, 0x40, Some("d".into())), (Field::Name, 0x50, Some("e".into()))],
                |_| Ok(()),
            )
            .unwrap();
        reader.refresh().unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        for annotations in [&reader, &replayed] {
            assert_eq!(annotations.names().keys().copied().collect::<Vec<_>>(), [0x30, 0x40, 0x50]);
        }
        cleanup(path);
    }

    #[test]
    fn a_batch_read_while_being_written_is_applied_once_complete() {
        let path = temporary_log("batch-in-progress");
        let header = serde_json::to_string(&BatchHeader { batch: "late".into(), edits: 2 }).unwrap();
        let member = |address, value| {
            serde_json::to_string(&BatchMember { edit: &name_edit(address, value), batch: "late" }).unwrap()
        };
        append(&path, &format!("{header}\n{}\n", member(0x10, "a")));
        let mut reader = Annotations::open(path.clone()).unwrap();
        assert!(reader.names().is_empty());
        append(&path, &format!("{}\n", member(0x20, "b")));
        assert!(reader.refresh().unwrap());
        assert_eq!((reader.name(0x10), reader.name(0x20)), (Some("a"), Some("b")));
        cleanup(path);
    }

    fn open_on(path: &std::path::Path, image: u8) -> Annotations {
        Annotations::open_for_image(path.to_path_buf(), Some([image; 32])).unwrap()
    }

    #[test]
    fn edits_are_logged_after_the_identity_of_the_image_they_were_made_on() {
        let path = temporary_log("image-identity");
        let mut first = open_on(&path, 0xaa);
        first.set(Field::Name, 0x10, Some("a".into())).unwrap();
        first
            .set_batch_validated(&[(Field::Name, 0x20, Some("b".into())), (Field::Comment, 0x20, None)], |_| Ok(()))
            .unwrap();
        let mut same = open_on(&path, 0xaa);
        same.set(Field::Name, 0x30, Some("c".into())).unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.matches("\"image\"").count(), 1, "{log}");
        assert!(log.starts_with(&format!("{{\"image\":\"{}\"}}\n", "aa".repeat(32))), "{log}");
        assert!(open_on(&path, 0xaa).warnings().is_empty());
        // A reader that predates identity lines still replays every edit.
        let old: Vec<Edit> = log.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
        assert_eq!(old.len(), 3);

        let rebuilt = open_on(&path, 0xbb);
        assert_eq!(rebuilt.name(0x30), Some("c"), "annotations still apply by address");
        let warnings = rebuilt.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&format!("different image (sha256 {})", "aa".repeat(32))), "{warnings:?}");
        assert!(Annotations::open(path.clone()).unwrap().warnings().is_empty(), "no image to compare");
        cleanup(path);
    }

    #[test]
    fn edits_made_on_another_image_are_reported_to_every_image_but_that_one() {
        let path = temporary_log("image-mixed");
        open_on(&path, 0xaa).set(Field::Name, 0x10, Some("a".into())).unwrap();
        open_on(&path, 0xbb).set(Field::Name, 0x20, Some("b".into())).unwrap();
        let mut a = open_on(&path, 0xaa);
        assert!(a.warnings()[0].contains(&"bb".repeat(32)), "{:?}", a.warnings());
        // Switching back to the first image logs its identity again, for the edits after it.
        a.set(Field::Name, 0x30, Some("c".into())).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().matches("\"image\"").count(), 3);
        assert!(open_on(&path, 0xbb).warnings()[0].contains(&"aa".repeat(32)));
        cleanup(path);
    }

    #[test]
    fn a_log_without_identity_lines_is_unverified_until_an_image_is_recorded() {
        let path = temporary_log("image-legacy");
        append(&path, &(serde_json::to_string(&name_edit(0x10, "a")).unwrap() + "\n"));
        let mut legacy = open_on(&path, 0xaa);
        assert_eq!(legacy.name(0x10), Some("a"));
        let warnings = legacy.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unverified"), "{warnings:?}");
        // The first identity line stands for the edits before it: the note is given once, not on every open.
        legacy.set(Field::Comment, 0x10, Some("checked".into())).unwrap();
        assert!(legacy.warnings().is_empty(), "{:?}", legacy.warnings());
        assert!(open_on(&path, 0xaa).warnings().is_empty());
        assert!(open_on(&path, 0xbb).warnings()[0].contains("different image"));
        cleanup(path);
    }

    #[test]
    fn logs_written_before_batch_headers_replay_unchanged() {
        let path = temporary_log("old-format");
        let lines: Vec<String> = [name_edit(0x10, "a"), name_edit(0x20, "b")]
            .iter()
            .map(|edit| serde_json::to_string(edit).unwrap() + "\n")
            .collect();
        append(&path, &lines.concat());
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("a"), Some("b")));
        // What a reader that predates batches makes of one: the header is no edit, the edits are.
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations
            .set_batch_validated(
                &[(Field::Name, 0x30, Some("c".into())), (Field::Name, 0x40, Some("d".into()))],
                |_| Ok(()),
            )
            .unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        let old: Vec<Edit> = log.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
        assert_eq!(old.iter().map(|edit| edit.address).collect::<Vec<_>>(), [0x10, 0x20, 0x30, 0x40]);
        cleanup(path);
    }

    #[test]
    fn a_conflicting_batch_undo_lists_every_changed_address_up_to_a_bound() {
        let path = temporary_log("batch-conflicts");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        let changes: Vec<_> = (0..25).map(|index| (Field::Comment, 0x10 * index, Some("a".to_owned()))).collect();
        agent.set_batch_validated(&changes, |_| Ok(())).unwrap();
        ui.set(Field::Comment, 0x20, Some("b".into())).unwrap();
        ui.set(Field::Comment, 0x30, Some("b".into())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.starts_with("0x20, 0x30 were edited by another client"), "{error}");
        let changes: Vec<_> = (0..25).map(|index| (Field::Comment, 0x10 * index, Some("c".to_owned()))).collect();
        ui.set_batch_validated(&changes, |_| Ok(())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.contains(", 0x130, 5 more were edited"), "{error}");
        assert!(!error.contains("0x140"), "{error}");
        cleanup(path);
    }

    #[test]
    fn undo_and_redo_refuse_to_duplicate_a_name_another_client_took() {
        let path = temporary_log("undo-name-taken");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Name, 0x10, Some("foo".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("bar".into())).unwrap();
        ui.set(Field::Name, 0x30, Some("foo".into())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.contains("\"foo\""), "{error}");
        assert_eq!(agent.name(0x10), Some("bar"));
        assert_eq!(agent.address_of("foo"), Some(0x30));

        agent.set(Field::Name, 0x40, Some("baz".into())).unwrap();
        agent.undo().unwrap();
        ui.set(Field::Name, 0x50, Some("baz".into())).unwrap();
        let error = agent.redo().unwrap_err();
        assert!(error.contains("\"baz\""), "{error}");
        assert_eq!(agent.name(0x40), None);
        cleanup(path);
    }
}
