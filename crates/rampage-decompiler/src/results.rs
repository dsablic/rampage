use serde::{Deserialize, Serialize};

const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;

/// Facts recovered by the decompiler engine, not inferred from rendered C text.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StructuredResult {
    pub provenance: ResultProvenance,
    pub signature: Signature,
    pub variables: Vec<Variable>,
    pub blocks: Vec<BasicBlock>,
    pub calls: Vec<Call>,
    pub jump_tables: Vec<JumpTable>,
}

impl StructuredResult {
    pub fn empty() -> Self {
        Self {
            provenance: ResultProvenance::EngineRecovered,
            signature: Signature {
                return_type: TypeInfo { name: "void".to_owned(), size: 0 },
                calling_convention: None,
                variadic: false,
                parameters: Vec::new(),
            },
            variables: Vec::new(),
            blocks: Vec::new(),
            calls: Vec::new(),
            jump_tables: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProvenance {
    EngineRecovered,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Signature {
    pub return_type: TypeInfo,
    /// Engine prototype-model name; not necessarily a source compiler ABI designation.
    pub calling_convention: Option<String>,
    pub variadic: bool,
    pub parameters: Vec<Parameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TypeInfo {
    pub name: String,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Parameter {
    pub name: String,
    pub data_type: TypeInfo,
    pub storage: Storage,
}

/// `address` is an offset in `space`, not necessarily a program virtual address.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Storage {
    pub kind: StorageKind,
    pub space: Option<String>,
    pub address: Option<u64>,
    pub size: u32,
    /// Inclusive Ghidra definition/use-point selector ranges, not live ranges or instruction availability.
    /// Inputs commonly select entry-1; empty means unrestricted selection, None means unavailable metadata.
    #[serde(default)]
    pub use_ranges: Option<Vec<StorageUseRange>>,
    #[serde(default)]
    pub dynamic_hash: Option<u64>,
    /// Byte offset of this mapping within its owning symbol.
    #[serde(default)]
    pub symbol_offset: Option<u32>,
    /// False identifies a whole-symbol mapping, true a precision piece.
    #[serde(default)]
    pub is_piece: Option<bool>,
    #[serde(default)]
    pub join_logical_size: Option<u32>,
    /// Single-piece joins can convert floating precision; physical size need not equal logical size.
    #[serde(default)]
    pub pieces: Vec<StoragePiece>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StorageUseRange {
    pub space: String,
    pub start: u64,
    pub end: u64,
}

/// A physical join component; logical_offset is a byte offset in the target's endian order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StoragePiece {
    pub kind: StorageKind,
    pub space: String,
    pub address: u64,
    pub size: u32,
    pub logical_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    Processor,
    Spacebase,
    Internal,
    Join,
    Constant,
    Fspec,
    Iop,
    Dynamic,
    Unknown,
}

/// One local-scope symbol, including every storage mapping (and split-storage piece).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Variable {
    pub name: String,
    pub data_type: TypeInfo,
    pub kind: VariableKind,
    pub storage: Vec<Storage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableKind {
    Parameter,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BasicBlock {
    pub index: u32,
    pub start: Option<u64>,
    /// Last recovered instruction start in the block's original address coverage.
    pub end: Option<u64>,
    pub successors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Call {
    pub source: Option<u64>,
    pub target: Option<u64>,
    pub name: Option<String>,
    pub indirect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct JumpTable {
    pub switch_address: Option<u64>,
    pub targets: Vec<u64>,
    pub partial: bool,
    #[serde(default)]
    /// Index-aligned unsigned raw switch-value bit patterns; null means no recovered explicit label.
    /// Empty means absent metadata. Signed interpretation requires operand width/signedness.
    pub case_values: Vec<Option<u64>>,
}

/// Parses the bounded JSON snapshot copied from a decompiler handle.
pub fn parse_results(text: &str) -> Result<StructuredResult, crate::Error> {
    if text.len() > MAX_RESULT_BYTES {
        return Err(crate::Error::Ghidra("structured result exceeds the 4 MiB limit".to_owned()));
    }
    serde_json::from_str(text)
        .map_err(|error| crate::Error::Ghidra(format!("invalid structured decompiler result: {error}")))
}
