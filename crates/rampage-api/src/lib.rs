//! The single command and query surface shared by the CLI, the MCP server and the UI.

pub mod annotations;
mod archive;
mod assembly;
mod batch;
mod benchmark;
mod branch_observation;
mod build_info;
mod capabilities;
mod carve;
mod correlation;
mod data;
mod debug_import;
mod debug_layout_import;
pub(crate) mod debug_type_import;
mod debugger;
mod debugger_capture;
mod decode_content;
mod decoder;
mod decompile;
pub mod derived_cache;
mod detect;
mod diagnostics;
mod dotnet;
mod fid_signatures;
mod files;
mod findings;
mod frame;
mod fuzzy_signatures;
mod graph;
mod import_types;
mod jumptable;
mod listing;
mod module_references;
mod offset;
mod operand_types;
pub mod packs;
mod patches;
mod plugin_triage;
mod pointer_compare;
mod pointer_observation;
mod project;
mod project_workspace;
mod propagation;
mod range_source;
mod raw_code;
mod raw_file;
mod raw_project;
mod rows;
mod runtime_compare;
pub mod search;
pub mod search_code;
mod search_request;
mod session;
mod signature_import;
mod signatures;
pub mod sleigh_window;
mod summary;
pub mod tool_views;
pub mod tools;
mod type_headers;
mod type_library;
mod typed_data;
mod variables;
pub mod workflows;
mod xrefs;

use std::path::PathBuf;

use rampage_arch::UnsupportedArch;
use rampage_loaders::LoadError;

pub use annotations::{DataTypeAnnotation, DerivedTypeHint, TypeHintAnnotation, TypeHintEvidence, TypeHintTarget};
pub use archive::{
    ArchiveMember, ArchiveMemberRef, ArchivePage, ArchiveQuery, ArchiveRef, MAX_ARCHIVE_PAGE, MAX_ARCHIVE_RESULT_BYTES,
    archive_inventory,
};
pub use assembly::{AssemblyReport, AssemblyRequest};
pub use batch::{
    AnnotationBatchEntry, AnnotationBatchOutcome, AnnotationBatchResult, BatchEntry, BatchOutcome, BatchResult,
    MAX_BATCH, NameCheck,
};
pub use benchmark::{Comparison, ReferenceAnalysis};
pub use branch_observation::{BranchObservation, BranchSlotStatus};
pub use build_info::{BuildInfo, BuildInfoQuery, GoBuildInfo, PclntabCheck, RustAudit};
pub use carve::{CarvingPage, MAX_CARVE_PAGE, carve, carve_page};
pub use correlation::RuntimeCorrelation;
pub use data::{
    DataImport, DataInspection, DataQuery, DataSpan, DataStatus, DataTarget, DataWord, MAX_DATA_BYTES,
    MAX_DATA_RESULT_BYTES, inspect_native_data, resolve_data_address,
};
pub use debug_import::DebugImport;
pub use debug_layout_import::{
    DebugLayoutFunction, DebugLayoutImport, DebugLayoutPreview, DebugLayoutProjection, DebugLayoutReport,
    DebugLayoutReview, DebugLayoutType, DebugLayoutVirtualEvidence, DebugLayoutVirtualMethodEvidence,
    DebugLayoutVtableEvidence,
};
pub use debug_type_import::{
    DebugTypesDetail, DebugTypesImport, DebugTypesManifest, DebugTypesRequest, DebugTypesSignature,
};
pub use debugger::{
    DebuggerAddress, DebuggerBackend, DebuggerError, DebuggerObservation, DebuggerPermissions, DebuggerRequest,
    DebuggerResponse, DebuggerToken, MAX_DEBUGGER_REQUEST_BYTES, MAX_DEBUGGER_RESPONSE_BYTES, query_debugger,
};
pub use debugger_capture::{
    DebuggerCapturePreview, DebuggerCapturePublication, DebuggerCapturePublicationStatus, DebuggerCaptureRequest,
    DebuggerCaptureStagingRetention, DebuggerCaptureSummary, prepare_debugger_capture,
    read_debugger_capture_publication,
};
pub use decode_content::{
    ContentCodec, DecodeFileRequest, DecodePreview, DecodeReceipt, DecodedContent, MAX_DECODE_INPUT_BYTES,
    MAX_DECODE_OUTPUT_BYTES, MAX_DECODE_PREVIEW_BYTES, decode_file_range,
};
pub use decoder::DecoderInitializationError;
pub use decompile::{
    Decompilation, DecompileEntryOrigin, DecompileEntryRequest, DecompilerConfigurationRevision, EntryContextCounts,
    EntryDecompilation, EntryDecompilationContext, EntryPreparationPhase, EntryPreparationProgress,
    EntryPreparationTimings, EntryValidation,
};
pub use detect::ToolDetections;
pub use dotnet::{DotNetCounts, DotNetIl, DotNetIlQuery, DotNetList, DotNetQuery, DotNetSummary, parse_il_offset};
pub use fid_signatures::{
    FidHostAdapter, FidReader, FidSignatureReport, FidSignatureRow, FidSignatureStatus, MAX_FID_QUERY_ROWS,
    MAX_FID_REPORT_BYTES,
};
pub use files::{
    MAX_CONSTANTS_BYTES, MAX_PACK_MANIFEST_BYTES, MAX_PEID_BYTES, MAX_RULE_FILE_BYTES, MAX_SIGNATURE_DB_BYTES,
    read_bounded,
};
pub use findings::{
    LedgerEntry, LedgerConfidence, LedgerCounts, LedgerEvidence, LedgerKind, LedgerList, LedgerRecord, LedgerRequest,
    LedgerStatus, LedgerQuery, MAX_LEDGER_EVIDENCE, MAX_LEDGER_RESOLUTION, MAX_LEDGER_TEXT, MAX_LEDGER_ENTRIES,
    MAX_LEDGER_PAGE,
};
pub use frame::{
    FrameCategory, FrameCoordinate, FrameLocation, FrameQuery, FrameRow, FrameSource, FrameTrackerSlot,
    FunctionFrameReport, MAX_FRAME_PAGE, MAX_FRAME_WORK, NativeFrameEvidence, TrackerFrameEvidence,
};
pub use fuzzy_signatures::{
    FuzzyBuildReport, FuzzyBuildRequest, FuzzyExactEvidence, FuzzyFeatureRejection, FuzzySuggestRequest,
    FuzzySuggestion, FuzzySuggestionStatus, FuzzySuggestions, FuzzyTarget, MAX_FUZZY_BUILD_FUNCTIONS,
    MAX_FUZZY_QUERY_FUNCTIONS, fuzzy_code_identity, fuzzy_code_projection,
};
pub use graph::{Edge, EdgeKind, FunctionGraph, GraphBlock};
pub use import_types::{ImportPrototype, PosixContext, import_prototype};
pub use jumptable::{JumpTable, JumpTableEntry};
pub use listing::{DisassemblyLine, FunctionListing};
pub use module_references::{
    MAX_MODULE_REFERENCE_MODULES, MAX_MODULE_REFERENCE_PAGE, MAX_MODULE_REFERENCE_RESULT_BYTES,
    ModuleReferenceCandidate, ModuleReferenceCoverage, ModuleReferenceInput, ModuleReferenceMetadataOrigin,
    ModuleReferenceMetadataStatus, ModuleReferenceName, ModuleReferenceQuery, ModuleReferenceReport,
    ModuleReferenceRow, ModuleReferenceStatus, ModuleReferenceView, module_references, prepare_module_reference_view,
    validate_module_reference_inputs,
};
pub use offset::{FileOffset, parse_file_offset};
pub use operand_types::{ApplyOperandTypeRequest, OperandAnnotationDisplay, OperandTypeEdit};
pub use packs::{ContentInfo, ContentStatus, PackInfo, PackManifest, Packs};
pub use patches::{
    BytePatch, MAX_ACTIVE_PATCHES, MAX_PATCH_BYTES, MAX_PATCH_SOURCE_BYTES, MAX_TOTAL_PATCH_BYTES, PatchExport,
    PatchOutcome, PatchReceipt,
};
pub use plugin_triage::{
    MAX_PLUGIN_TRIAGE_REPORT_BYTES, MAX_PLUGIN_TRIAGE_SOURCE_BYTES, PluginTriageProvenance, PluginTriageReport,
    PreparedPluginTriage, open_plugin_triage_source, prepare_plugin_triage, prepare_plugin_triage_with_analysis,
    read_plugin_triage_component,
};
pub use pointer_compare::{PointerChange, PointerComparison};
pub use pointer_observation::{PointerAssessment, PointerObservation};
pub use project::{AnalysisCacheStatus, PdbImport, PdbPreview, Project};
pub use project_workspace::{
    LoadedProjectModule, LoadedProjectWorkspace, ProjectWorkspaceCaptureIdentity, ProjectWorkspaceIdentity,
    ProjectWorkspaceImage, ProjectWorkspaceManifest, ProjectWorkspaceModule, ProjectWorkspaceModuleInput,
    ProjectWorkspaceNavigation, ProjectWorkspaceOptions, ProjectWorkspacePhase, ProjectWorkspacePlatform,
    ProjectWorkspacePreview, ProjectWorkspaceProgress, ProjectWorkspacePublication, ProjectWorkspaceTaskControl,
    QualifiedProjectAddress, capture_project_workspace, capture_project_workspace_controlled,
    capture_project_workspace_with_session, preview_project_workspace, preview_project_workspace_controlled,
    publish_project_workspace, publish_project_workspace_controlled,
};
pub use propagation::{
    MAX_PROPAGATION_CANDIDATES, MAX_PROPAGATION_EDGES, MAX_PROPAGATION_FUNCTIONS, PropagationCandidate,
    PropagationConflict, PropagationCounts, PropagationHintEdit, PropagationRequest, PropagationResult,
    PropagationSkip,
};
pub use rampage_analysis::triage::Triage;
pub use rampage_capabilities::Capability;
pub use rampage_decompiler::VariableStorage;
pub use rampage_decompiler::results::RecoveryStatus;
pub use rampage_decompiler::worker::SupervisedMetrics;
pub use rampage_decompiler::worker::WorkerConfig as DecompilerWorkerConfig;
pub use rampage_decompiler::{
    DecompilerOptions, NamedEnumValue, NamedFunctionType, NamedType, NamedTypeField, NamedTypeKind, NamedTypeParameter,
    Platform as DecompilerPlatform,
};
pub use rampage_detect::{Confidence as DetectionConfidence, Detection, Kind as DetectionKind};
pub use rampage_plugin::PluginConfig as ComponentPluginConfig;
pub use rampage_signatures::SignatureDb;
pub use rampage_yara::{MatchedString, YaraMatch};
pub use raw_code::{
    MAX_RAW_CODE_BYTES, MAX_RAW_CODE_INSTRUCTIONS, MAX_RAW_CODE_RESULT_BYTES, RawCodeMode, RawCodeReport,
    RawCodeRequest, RawCodeRow, RawCodeStopReason, inspect_raw_code,
};
pub use raw_file::{RawByteOrder, RawContinuation, RawFileReport, RawFileRequest, inspect_raw_file};
pub use raw_project::{RawProjectRequest, open_raw_binary};
pub use rows::{
    Annotation, AnnotationList, EditResult, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Page, StringsQuery,
    Summary, label,
};
pub use runtime_compare::{ByteComparison, ComparedSpan, RuntimeComparison, RuntimeRange};
pub use search_request::{
    MAX_SEARCH_REQUEST_BYTES, SearchAddress, SearchRequest, SearchRequestMode, SearchRequestRange,
    SearchRequestReference,
};
pub use session::{MAX_RAW_PROJECTS, Session};
pub use signature_import::load_signature_database;
pub use signatures::{SignatureApplication, SignatureMatch, USER_SIGNATURES};
pub use summary::FunctionSummary;
pub use tool_views::{ToolView, ToolViewKind, project_tool_view};
pub use type_headers::{HeaderBundle, HeaderDeclaration, HeaderProvenance, PreparedHeader};
pub use type_library::{DeclareTypesRequest, TypeLibraryEdit, TypeLibraryEntry, TypeLibraryPage};
pub use typed_data::{
    ApplyDataTypeRequest, DataStringEncoding, DataTypeEdit, MAX_TYPED_DATA_RESULT_BYTES, TypedDataField,
    TypedDataObject, TypedDataQuery, TypedDataReport,
};
pub use variables::{VariableDescriptor, VariableEditRequest, VariableEditResult};
pub use workflows::{
    Confidence as FindingConfidence, Excerpt, Finding, NextStep, ReportLimits, ReportTarget, Section, WorkflowReport,
};
pub use xrefs::{XrefQuery, XrefRow};

/// How many instructions a disassembly shows unless asked for another count.
pub const DEFAULT_INSTRUCTIONS: usize = 40;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{path}")]
    Load { path: PathBuf, source: LoadError },
    #[error(transparent)]
    Unsupported(#[from] UnsupportedArch),
    #[error("instruction decoder: {0}")]
    DecoderInitialization(#[source] std::sync::Arc<rampage_decompiler::Error>),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    /// A capability that needs an external resource (such as the decompiler's Ghidra specifications) is not
    /// available in this environment.
    #[error("{0}")]
    Unavailable(String),
    /// A recognized native weak-hint context refusal, not a worker transport or hard-annotation error.
    #[error("decompiler: {0}")]
    NativeTypeHintUnsupported(String),
    #[error(transparent)]
    DebuggerCaptureStagingRetained(#[from] DebuggerCaptureStagingRetention),
}
