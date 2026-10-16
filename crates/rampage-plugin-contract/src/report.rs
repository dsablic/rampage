use serde::{Deserialize, Serialize};

use crate::FactId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestResponse {
    pub schema_version: u32,
    pub outcome: GuestOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestOutcome {
    Report { body: ReportBody },
    Failure { code: FailureCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    UnsupportedSchema,
    InvalidInput,
    InputLimit,
    OutputLimit,
    InvalidReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportBody {
    pub summary: Vec<String>,
    pub limitations: Vec<String>,
    pub next_steps: Vec<NextStep>,
    pub next_steps_omitted: u32,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Section {
    pub title: String,
    pub findings: Vec<Finding>,
    pub total: u32,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    BinaryInfo,
    Triage,
    DetectTools,
    DotnetMetadata,
    Capabilities,
    ListImports,
    ListStrings,
    ListFunctions,
    IdentifyFunctions,
}

impl Source {
    pub fn tool(self) -> &'static str {
        match self {
            Self::BinaryInfo => "binary_info",
            Self::Triage => "triage",
            Self::DetectTools => "detect_tools",
            Self::DotnetMetadata => "dotnet_metadata",
            Self::Capabilities => "capabilities",
            Self::ListImports => "list_imports",
            Self::ListStrings => "list_strings",
            Self::ListFunctions => "list_functions",
            Self::IdentifyFunctions => "identify_functions",
        }
    }
}

/// A plugin's confidence claim, never host/native analysis authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub observation: String,
    pub evidence: Vec<String>,
    pub source: Source,
    pub confidence: Confidence,
    pub address: Option<u64>,
    pub fact_refs: Vec<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NextStep {
    pub action: Action,
    pub reason: String,
    pub fact_refs: Vec<FactId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    FindMain,
    DotnetMetadata,
    DotnetIl { method: u32 },
    NetworkSurface,
    AnalysisDiagnostics { include_discovery: bool },
    IdentifyFunctions { apply: bool },
    Xrefs { to: u64 },
}

impl Action {
    pub fn tool(&self) -> &'static str {
        match self {
            Self::FindMain => "find_main",
            Self::DotnetMetadata => "dotnet_metadata",
            Self::DotnetIl { .. } => "dotnet_il",
            Self::NetworkSurface => "network_surface",
            Self::AnalysisDiagnostics { .. } => "analysis_diagnostics",
            Self::IdentifyFunctions { .. } => "identify_functions",
            Self::Xrefs { .. } => "xrefs",
        }
    }
}
