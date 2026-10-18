//! Bounded debug-producer facts. These are not assertions about the native type library or calling ABI.

use serde::{Deserialize, Serialize};

pub const MAX_DEBUG_TYPES: usize = 256;
pub const MAX_DEBUG_SIGNATURES: usize = 256;
pub const MAX_DEBUG_FIELDS: usize = 128;
pub const MAX_DEBUG_DEPTH: usize = 32;
pub const MAX_DEBUG_TYPE_BYTES: u64 = 1024 * 1024;
pub const MAX_DEBUG_DECLARATION_BYTES: usize = 64 * 1024;

/// Identity within the report's fingerprinted producer source, never a display-name identity.
pub type DebugTypeId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugSourceKind {
    Pdb,
    Dwarf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypeProvenance {
    pub source: DebugSourceKind,
    pub source_sha256: String,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypeOrigin {
    pub source: DebugSourceKind,
    /// Producer namespace, for example `tpi`, or a DWARF compilation-unit offset.
    pub unit: Option<String>,
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypeReport {
    pub types: Vec<DebugType>,
    pub signatures: Vec<DebugSignature>,
    pub provenance: DebugTypeProvenance,
    pub warnings: Vec<String>,
    pub limits: DebugTypeLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypeLimits {
    pub types: usize,
    pub signatures: usize,
    pub fields_per_type: usize,
    pub depth: usize,
    pub type_bytes: u64,
    pub declaration_bytes: usize,
}

impl Default for DebugTypeLimits {
    fn default() -> Self {
        Self {
            types: MAX_DEBUG_TYPES,
            signatures: MAX_DEBUG_SIGNATURES,
            fields_per_type: MAX_DEBUG_FIELDS,
            depth: MAX_DEBUG_DEPTH,
            type_bytes: MAX_DEBUG_TYPE_BYTES,
            declaration_bytes: MAX_DEBUG_DECLARATION_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugType {
    pub id: DebugTypeId,
    pub original_name: Option<String>,
    /// Absent until a declaration renderer has checked the identifier and target language.
    pub emitted_name: Option<String>,
    pub byte_size: Option<u64>,
    /// Missing producer alignment stays missing; size is not an alignment witness.
    pub alignment: Option<u64>,
    pub kind: DebugTypeKind,
    pub origin: DebugTypeOrigin,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DebugTypeKind {
    Scalar {
        encoding: DebugScalarEncoding,
        c_name: Option<String>,
    },
    Pointer {
        target: DebugTypeId,
    },
    Struct {
        members: Vec<DebugMember>,
    },
    Union {
        members: Vec<DebugMember>,
    },
    Enum {
        underlying: DebugTypeId,
        values: Vec<DebugEnumerator>,
    },
    Typedef {
        target: DebugTypeId,
        constant: bool,
        volatile: bool,
    },
    /// Raw producer storage descriptor, always preview-only rather than a C object/typedef.
    Bitfield {
        target: DebugTypeId,
        bit_size: u64,
        bit_offset: u64,
    },
    Array {
        element: DebugTypeId,
        count: Option<u64>,
        stride: Option<u64>,
    },
    Function {
        convention: String,
        parameters: Vec<DebugTypeId>,
        return_type: DebugTypeId,
        variadic: bool,
    },
    Unsupported {
        description: String,
    },
}

impl DebugTypeKind {
    pub fn references(&self) -> Vec<&DebugTypeId> {
        match self {
            Self::Pointer { target } | Self::Typedef { target, .. } | Self::Bitfield { target, .. } => vec![target],
            Self::Struct { members } | Self::Union { members } => members.iter().map(|m| &m.type_id).collect(),
            Self::Enum { underlying, .. } => vec![underlying],
            Self::Array { element, .. } => vec![element],
            Self::Function { parameters, return_type, .. } => {
                std::iter::once(return_type).chain(parameters.iter()).collect()
            }
            Self::Scalar { .. } | Self::Unsupported { .. } => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugScalarEncoding {
    Void,
    Signed,
    Unsigned,
    Float,
    Boolean,
    Character,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugMember {
    pub name: Option<String>,
    pub type_id: DebugTypeId,
    pub byte_offset: u64,
    pub bitfield: Option<DebugBitfield>,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugBitfield {
    pub bit_size: u64,
    /// Producer bit offset within the member's storage unit, not a converted host bit order.
    pub bit_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugEnumerator {
    pub name: String,
    /// Decimal text preserves signed and unsigned producer values without narrowing.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSignature {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    #[serde(deserialize_with = "rampage_arch::hex::deserialize_address")]
    pub address: u64,
    pub name: Option<String>,
    pub type_id: DebugTypeId,
    pub origin: DebugTypeOrigin,
    pub unsupported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn retained_producer_signatures_decode_hex_addresses_without_losing_width() {
        let signature = DebugSignature {
            address: u64::MAX,
            name: Some("owned".into()),
            type_id: "type:1".into(),
            origin: DebugTypeOrigin { source: DebugSourceKind::Dwarf, unit: Some("cu:0".into()), index: 1 },
            unsupported: Vec::new(),
        };
        let value = serde_json::to_value(&signature).unwrap();
        assert_eq!(value["address"], "0xffffffffffffffff");
        assert_eq!(serde_json::from_value::<DebugSignature>(value).unwrap(), signature);
    }

    #[test]
    fn retained_member_metadata_cannot_silently_discard_unrecognized_bitfield_facts() {
        let mut value = json!({"name":"flags","type_id":"type:1","byte_offset":0,
            "bitfield":null,"unsupported":[]});
        assert!(serde_json::from_value::<DebugMember>(value.clone()).is_ok());
        value["raw_storage_byte_size"] = json!(4);
        assert!(serde_json::from_value::<DebugMember>(value).is_err());
        let value = json!({"kind":"array","element":"type:1","count":2,"stride":4,
            "unrecognized_stride":8});
        assert!(serde_json::from_value::<DebugTypeKind>(value).is_err());
    }
}
