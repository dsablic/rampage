use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandKind {
    Register,
    Immediate,
    Memory,
    /// Includes branch targets, implicit memory forms, and other operands not proven here.
    Unsupported,
}

/// Evidence about one explicit operand, obtained without parsing rendered assembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperandEvidence {
    pub index: u8,
    pub kind: OperandKind,
    /// The semantic immediate, truncated to `width_bits`, not its encoded bit-field.
    #[serde(serialize_with = "crate::hex::optional_address")]
    pub immediate: Option<u64>,
    /// The same semantic bits interpreted as two's-complement, serialized as a decimal string.
    #[serde(serialize_with = "optional_signed")]
    pub signed_value: Option<i64>,
    /// Logical operand width in bits, not the encoded immediate width. Unknown widths stay absent.
    pub width_bits: Option<u16>,
    /// Also present on supported 64-bit A64 ADD immediates that form a base-plus-offset address.
    pub memory: Option<MemoryOperand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    /// Signed displacement serialized as a decimal string to preserve all 64 bits in JSON consumers.
    #[serde(serialize_with = "signed_decimal")]
    pub displacement: i64,
    pub scale: u8,
    /// Bytes actually accessed; absent for address formation (LEA / ADD) or unknown accesses.
    pub access_size: Option<u16>,
    /// PC-relative references are addresses, never object-base struct offsets. Absolute operands
    /// have no base; consumers must require a non-PC object base for struct-offset annotations.
    pub relative: bool,
}

impl OperandEvidence {
    pub(crate) fn unsupported(index: u8) -> Self {
        Self {
            index,
            kind: OperandKind::Unsupported,
            immediate: None,
            signed_value: None,
            width_bits: None,
            memory: None,
        }
    }

    pub(crate) fn immediate(index: u8, value: u64, width: u16) -> Self {
        let shift = 64 - u32::from(width);
        let value = (value << shift) >> shift;
        Self {
            index,
            kind: OperandKind::Immediate,
            immediate: Some(value),
            signed_value: Some(((value << shift) as i64) >> shift),
            width_bits: Some(width),
            memory: None,
        }
    }
}

fn signed_decimal<S: Serializer>(value: &i64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

fn optional_signed<S: Serializer>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => signed_decimal(value, serializer),
        None => serializer.serialize_none(),
    }
}
