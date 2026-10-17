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
    /// None means the producer did not export recovery diagnostics, not that recovery was issue-free.
    #[serde(default)]
    pub diagnostics: Option<RecoveryDiagnostics>,
    /// Native stack-space configuration, not a recovered frame layout or entry-SP equivalence proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_context: Option<FrameContext>,
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
            diagnostics: None,
            frame_context: None,
        }
    }
}

/// Bounded to one native stack space and, when configured unambiguously, one base register.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FrameContext {
    pub stack_space: String,
    /// Ghidra AddrSpace::getAddrSize(), in bytes; not the target's assumed pointer width.
    pub address_size_bytes: u32,
    pub base_convention: FrameBaseConvention,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_register: Option<FrameBaseRegister>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameBaseConvention {
    /// The space is indexed relative to its configured Ghidra spacebase register.
    /// This does not establish equivalence to the machine stack pointer at function entry.
    NativeSpacebaseRegister,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FrameBaseRegister {
    pub space: String,
    #[serde(with = "crate::variables::hex_address")]
    pub address: u64,
    pub size: u32,
    /// Width of the register address space, not the register value's size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_size_bytes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecoveryDiagnostics {
    pub bad_data: bool,
    pub unimplemented: bool,
    pub unresolved_calls: usize,
    pub unresolved_indirect_jumps: usize,
    pub partial_jump_tables: usize,
    pub warnings: Vec<RecoveryWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecoveryWarning {
    pub kind: WarningKind,
    pub address: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    Header,
    Body,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Incomplete,
    Warnings,
    NoReportedIssues,
    Unavailable,
}

impl RecoveryStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete recovery",
            Self::Warnings => "recovery warnings",
            Self::NoReportedIssues => "no reported recovery issues (not a correctness guarantee)",
            Self::Unavailable => "recovery diagnostics unavailable",
        }
    }
}

impl StructuredResult {
    pub fn recovery_status(&self) -> RecoveryStatus {
        let Some(diagnostics) = &self.diagnostics else { return RecoveryStatus::Unavailable };
        if diagnostics.bad_data || diagnostics.unimplemented {
            RecoveryStatus::Incomplete
        } else if !diagnostics.warnings.is_empty()
            || diagnostics.unresolved_calls != 0
            || diagnostics.unresolved_indirect_jumps != 0
            || diagnostics.partial_jump_tables != 0
        {
            RecoveryStatus::Warnings
        } else {
            RecoveryStatus::NoReportedIssues
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
    /// Native address-space width in bytes. None means unavailable (including addressless dynamic storage).
    /// Interpret stack offset bit patterns using this width, not the target pointer width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_size_bytes: Option<u32>,
    #[serde(with = "crate::variables::optional_hex_address")]
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
    #[serde(with = "crate::variables::hex_address")]
    pub start: u64,
    #[serde(with = "crate::variables::hex_address")]
    pub end: u64,
}

/// A physical join component; logical_offset is a byte offset in the target's endian order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StoragePiece {
    pub kind: StorageKind,
    pub space: String,
    /// Width of this physical component's own address space, not its value size or the join space width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_size_bytes: Option<u32>,
    #[serde(with = "crate::variables::hex_address")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<CallArgument>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CallResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_unavailable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallArgument {
    /// Exact native CALL input slot (slot zero is the call destination).
    pub input_index: u32,
    /// Declared destination parameter, only for an unambiguous native scalar/pointer layout.
    pub parameter_index: Option<u32>,
    pub value: CallValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallResult {
    pub value: CallValue,
    /// Every normal return carries this output through at most 16 same-width COPY/CAST operations.
    pub direct_return: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CallValue {
    pub status: CallValueStatus,
    pub data_type: Option<TypeInfo>,
    /// Owning symbol's native type, separate from a same-width CAST at the call input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_type: Option<TypeInfo>,
    /// Present only for one complete owning local/parameter symbol mapping.
    pub storage: Option<crate::VariableStorage>,
    pub raw_storage: Option<Storage>,
    pub display_name: Option<String>,
    pub type_locked: bool,
    pub global_address: Option<u64>,
    /// Object type at global_address. For GlobalAddress this is not the argument's owning symbol type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_object_type: Option<TypeInfo>,
    #[serde(default)]
    pub global_type_locked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallValueStatus {
    Unknown,
    Constant,
    Computed,
    Variable,
    Global,
    /// Address of a global object: data_type is the native pointer type; symbol_type is absent.
    GlobalAddress,
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
