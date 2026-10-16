use serde::{Deserialize, Serialize};

use crate::FactId;

/// All collections are exhaustive for the builtin triage primitives, including every signature match.
/// `record_total` counts fact-ID-bearing records, including binary and triage, not scalar/evidence strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageFacts {
    pub schema_version: u32,
    pub exhaustive: bool,
    pub record_total: u32,
    pub per_section: u32,
    pub binary: BinaryFact,
    pub triage: TriageFact,
    pub detections: Vec<DetectionFact>,
    pub managed: Option<ManagedFact>,
    pub capabilities: Vec<CapabilityFact>,
    pub imports: Vec<ImportFact>,
    pub strings: Vec<StringFact>,
    pub functions: FunctionFacts,
    pub signature_matches: Vec<SignatureFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryFact {
    pub id: FactId,
    /// The builtin Debug-format label, such as `Pe` or `Elf`.
    pub format: String,
    /// The builtin architecture Display label.
    pub arch: String,
    pub entry: Option<u64>,
    pub section_count: u64,
    pub segment_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageFact {
    pub id: FactId,
    pub image_size: u64,
    pub entropy: f64,
    pub sha256: String,
    pub md5: String,
    pub hints: Vec<HintFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HintFact {
    pub id: FactId,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionKind {
    Compiler,
    Packer,
    Protector,
    Installer,
    Linker,
    Runtime,
    Unknown,
}

impl DetectionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Compiler => "compiler",
            Self::Packer => "packer",
            Self::Protector => "protector",
            Self::Installer => "installer",
            Self::Linker => "linker",
            Self::Runtime => "runtime",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionConfidence {
    Strong,
    Tentative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionFact {
    pub id: FactId,
    pub name: String,
    pub kind: DetectionKind,
    pub confidence: DetectionConfidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedFact {
    pub id: FactId,
    pub assembly: Option<AssemblyIdentity>,
    pub runtime_version: String,
    pub type_count: u64,
    pub method_count: u64,
    pub il_method_count: u64,
    pub native_method_count: u64,
    pub assembly_refs: Vec<AssemblyRefFact>,
    pub entry_method: Option<u32>,
    /// Methods in the same order as the builtin default first page of types, flattened across those types.
    pub first_page_methods: Vec<MethodFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyRefFact {
    pub id: FactId,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MethodFact {
    pub id: FactId,
    pub token: u32,
    pub has_il: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityFact {
    pub id: FactId,
    pub name: String,
    pub category: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportFact {
    pub id: FactId,
    pub library: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StringFact {
    pub id: FactId,
    pub address: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum FunctionFacts {
    Available { rows: Vec<FunctionFact> },
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionFact {
    pub id: FactId,
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignatureSource {
    Bundled,
    User,
    Pack { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureFact {
    pub id: FactId,
    pub address: u64,
    pub name: String,
    pub unnamed: bool,
    pub source: SignatureSource,
}
