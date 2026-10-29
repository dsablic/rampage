use std::collections::HashSet;
use std::sync::Arc;

use rampage_loaders::Format;
use rampage_loaders::linkage::{
    LinkageCoverage, LinkageCoverageStatus, LinkageExport, LinkageExportTarget, LinkageImport, LinkageImportProvenance,
    LinkageLimits, LinkageMetadata, LinkageStatus, LinkageSymbol, linkage_metadata,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::rows::json_size;
use crate::{ApiError, Project};

pub const MAX_MODULE_REFERENCE_MODULES: usize = 8;
pub const MAX_MODULE_REFERENCE_PAGE: usize = 256;
pub const MAX_MODULE_REFERENCE_RESULT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_AGGREGATE_SOURCE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECORDS: usize = 65_536;
const MAX_NAME_BYTES: usize = 1024 * 1024;
const MAX_NAME: usize = 4096;
const MAX_ROWS: usize = 8192;
const MAX_MATCHING_WORK: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct ModuleReferenceInput {
    pub module_id: String,
    pub project: Arc<Project>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleReferenceQuery {
    pub source_module_id: Option<String>,
    pub source_slot: Option<u64>,
    /// Exact UTF-8 byte substring of the raw import library or named symbol, at most 256 bytes.
    pub filter: Option<String>,
    pub offset: Option<usize>,
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<usize>,
    /// Comparison-byte allowance, down-clamped to 32 MiB; zero prevents text comparisons.
    pub matching_work_limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleReferenceStatus {
    DeclaredLink,
    Ambiguous,
    Unresolved,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleReferenceMetadataStatus {
    Complete,
    Incomplete,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleReferenceMetadataOrigin {
    NativeMapped,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReferenceName {
    pub raw_hex: String,
    pub display: Option<String>,
}

impl ModuleReferenceName {
    fn from_bytes(bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut raw_hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            raw_hex.push(HEX[usize::from(byte >> 4)] as char);
            raw_hex.push(HEX[usize::from(byte & 15)] as char);
        }
        Self { raw_hex, display: std::str::from_utf8(bytes).ok().map(str::to_owned) }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReferenceCoverage {
    pub module_id: String,
    pub format: Format,
    pub metadata_status: ModuleReferenceMetadataStatus,
    pub metadata_origin: Option<ModuleReferenceMetadataOrigin>,
    pub source_revalidated_non_atomic: bool,
    pub export_directory_present: Option<bool>,
    pub producer_identity: Option<ModuleReferenceName>,
    pub import_table_complete: bool,
    pub export_table_complete: bool,
    pub known_source_slots: usize,
    pub examined_imports: usize,
    pub examined_exports: usize,
    pub loader_status: Option<LinkageStatus>,
    pub regular_imports: Option<LinkageCoverage>,
    pub delay_imports: Option<LinkageCoverage>,
    pub exports: Option<LinkageCoverage>,
    pub loader_limits: Option<LinkageLimits>,
    pub metadata_lookup_work: u64,
    pub omissions: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReferenceCandidate {
    pub module_id: String,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub address: Option<u64>,
    pub export_name: Option<ModuleReferenceName>,
    pub forwarder: Option<ModuleReferenceName>,
    pub raw_kind: String,
    pub executable_backing: bool,
    pub identity_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReferenceRow {
    pub source_module_id: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub source_slot: u64,
    pub import_library: ModuleReferenceName,
    pub import_name: Option<ModuleReferenceName>,
    pub import_ordinal: Option<u16>,
    pub raw_kind: String,
    pub status: ModuleReferenceStatus,
    pub reason: String,
    pub candidates: Vec<ModuleReferenceCandidate>,
    /// Known candidates, saturating; incomplete searches may leave additional unknown candidates.
    pub candidate_count: usize,
    pub candidates_truncated: bool,
    pub producer_search_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReferenceReport {
    pub version: u32,
    pub matching_policy: &'static str,
    pub proven_runtime_flow: bool,
    pub proven_layout: bool,
    pub coverage: Vec<ModuleReferenceCoverage>,
    pub rows: Vec<ModuleReferenceRow>,
    /// Matching declarations actually observed, not an estimate of an unreadable table's remainder.
    pub matched: usize,
    pub matched_is_lower_bound: bool,
    pub returned: usize,
    pub offset: usize,
    pub limit: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub rows_truncated: bool,
    pub byte_capped: bool,
    pub complete: bool,
    pub matching_work_limit: usize,
    pub matching_work_used: usize,
    pub matching_work_exhausted: bool,
    pub limitations: Vec<&'static str>,
}

/// Process-local source retention, not a serializable navigation authorization.
pub struct ModuleReferenceView {
    inputs: Vec<ModuleReferenceInput>,
    query: ModuleReferenceQuery,
    report: ModuleReferenceReport,
}

impl ModuleReferenceView {
    pub fn report(&self) -> &ModuleReferenceReport {
        &self.report
    }

    pub fn query(&self) -> &ModuleReferenceQuery {
        &self.query
    }

    pub fn inputs(&self) -> &[ModuleReferenceInput] {
        &self.inputs
    }

    pub fn revalidate_sources(&self) -> Result<(), ApiError> {
        validate_module_reference_inputs(&self.inputs)
    }
}

/// Checks original descriptors only; owned inputs remain unsupported rather than acquiring source proof.
pub fn validate_module_reference_inputs(inputs: &[ModuleReferenceInput]) -> Result<(), ApiError> {
    if inputs.is_empty() || inputs.len() > MAX_MODULE_REFERENCE_MODULES {
        return Err(ApiError::Invalid("module references require 1..=8 modules".into()));
    }
    let mut ids = HashSet::with_capacity(inputs.len());
    for input in inputs {
        let id = input.module_id.as_bytes();
        if id.is_empty() || id.len() > 64 || !id.is_ascii() || id.iter().any(u8::is_ascii_control) {
            return Err(ApiError::Invalid("module IDs require 1..=64 printable ASCII bytes".into()));
        }
        if !ids.insert(&input.module_id) {
            return Err(ApiError::Invalid("module IDs must be unique".into()));
        }
        input.project.binary.validate_available_backing_source().map_err(|error| {
            ApiError::Invalid(format!("module {} original source validation failed: {error}", input.module_id))
        })?;
    }
    Ok(())
}

pub fn prepare_module_reference_view(
    inputs: &[ModuleReferenceInput],
    query: &ModuleReferenceQuery,
) -> Result<ModuleReferenceView, ApiError> {
    let report = module_references(inputs, query)?;
    Ok(ModuleReferenceView { inputs: inputs.to_vec(), query: query.clone(), report })
}

struct ModuleMetadata {
    metadata: Option<LinkageMetadata>,
    original_mapped: bool,
    omission: Option<&'static str>,
}

fn imports_complete(metadata: &LinkageMetadata) -> bool {
    metadata.regular_imports.status == LinkageCoverageStatus::Complete
        && metadata.delay_imports.status == LinkageCoverageStatus::Complete
}

fn exports_complete(metadata: &LinkageMetadata) -> bool {
    metadata.export_coverage.status == LinkageCoverageStatus::Complete
}

fn export_directory_absent(metadata: &LinkageMetadata) -> bool {
    metadata.export_directory_present == Some(false) && exports_complete(metadata) && metadata.exports.is_empty()
}

fn producer_identity_supported(metadata: &LinkageMetadata) -> bool {
    metadata.producer_library.as_ref().is_some_and(|identity| !identity.is_empty() && identity.is_ascii())
}

fn query_limit(inputs: &[ModuleReferenceInput], query: &ModuleReferenceQuery) -> Result<usize, ApiError> {
    let limit = query.limit.unwrap_or(64);
    if !(1..=MAX_MODULE_REFERENCE_PAGE).contains(&limit) {
        return Err(ApiError::Invalid("module reference limit must be in 1..=256".into()));
    }
    if query.filter.as_ref().is_some_and(|filter| filter.len() > 256) {
        return Err(ApiError::Invalid("module reference filter exceeds 256 UTF-8 bytes".into()));
    }
    if let Some(id) = &query.source_module_id
        && !inputs.iter().any(|input| &input.module_id == id)
    {
        return Err(ApiError::Invalid("module reference source_module_id is not loaded".into()));
    }
    Ok(limit)
}

fn read_metadata(inputs: &[ModuleReferenceInput]) -> Result<Vec<ModuleMetadata>, ApiError> {
    let aggregate =
        inputs.iter().try_fold(0usize, |sum, input| sum.checked_add(input.project.binary.file_bytes().len()));
    let aggregate_exceeded = aggregate.is_none_or(|size| size > MAX_AGGREGATE_SOURCE_BYTES);
    let records_per_module = MAX_RECORDS / inputs.len();
    let mut names_left = MAX_NAME_BYTES;
    let mut work_left = LinkageLimits::default().max_lookup_work;
    let mut modules = Vec::with_capacity(inputs.len());
    for input in inputs {
        let binary = &input.project.binary;
        let original_mapped = binary.validate_available_backing_source().map_err(|error| {
            ApiError::Invalid(format!("module {} source changed before metadata: {error}", input.module_id))
        })?;
        let omission = if binary.format != Format::Pe {
            Some("Only native mapped PE linkage metadata is supported; other formats are inventory-only.")
        } else if !original_mapped {
            Some("Owned bytes have no original mapped-source proof; no linkage join is authorized.")
        } else if aggregate_exceeded {
            Some("Aggregate original-source byte limit exceeded; no metadata was read.")
        } else if binary.file_bytes().len() > MAX_SOURCE_BYTES || binary.image_bytes().len() > MAX_SOURCE_BYTES {
            Some("Original-source or selected-image byte limit exceeded; no metadata was read.")
        } else if names_left == 0 || work_left == 0 {
            Some("Aggregate metadata budget exhausted; this module was not examined.")
        } else {
            None
        };
        let metadata = if omission.is_none() {
            let limits = LinkageLimits {
                max_records: records_per_module,
                max_name_bytes: MAX_NAME,
                max_total_name_bytes: names_left,
                max_lookup_work: work_left,
                max_image_bytes: MAX_SOURCE_BYTES,
            };
            let metadata = linkage_metadata(binary, limits).map_err(|error| {
                ApiError::Invalid(format!("module {} source changed during metadata: {error}", input.module_id))
            })?;
            let records = metadata
                .imports
                .len()
                .checked_add(metadata.exports.len())
                .ok_or_else(|| ApiError::Invalid("module reference record count overflow".into()))?;
            if records > records_per_module {
                return Err(ApiError::Invalid("module reference raw record allowance exceeded".into()));
            }
            names_left = names_left
                .checked_sub(metadata.name_bytes)
                .ok_or_else(|| ApiError::Invalid("module reference aggregate name limit exceeded".into()))?;
            work_left = work_left
                .checked_sub(metadata.lookup_work)
                .ok_or_else(|| ApiError::Invalid("module reference aggregate parser work limit exceeded".into()))?;
            Some(metadata)
        } else {
            None
        };
        modules.push(ModuleMetadata { metadata, original_mapped, omission });
    }
    preflight_metadata(&modules)?;
    validate_module_reference_inputs(inputs)?;
    Ok(modules)
}

fn preflight_metadata(modules: &[ModuleMetadata]) -> Result<(), ApiError> {
    let mut names = 0usize;
    let mut records = 0usize;
    for module in modules {
        let Some(metadata) = &module.metadata else { continue };
        records = records.saturating_add(metadata.imports.len()).saturating_add(metadata.exports.len());
        if records > MAX_RECORDS {
            return Err(ApiError::Invalid("module reference raw record limit exceeded".into()));
        }
        let mut add_name = |name: &[u8]| -> Result<(), ApiError> {
            names = names.saturating_add(name.len());
            if name.len() > MAX_NAME || names > MAX_NAME_BYTES {
                return Err(ApiError::Invalid("module reference raw name limit exceeded".into()));
            }
            Ok(())
        };
        if let Some(identity) = &metadata.producer_library {
            add_name(identity)?;
        }
        for import in &metadata.imports {
            add_name(&import.library)?;
            if let LinkageSymbol::Named(name) = &import.symbol {
                add_name(name)?;
            }
        }
        for export in &metadata.exports {
            if let Some(name) = &export.name {
                add_name(name)?;
            }
            if let LinkageExportTarget::Forwarder { raw } = &export.target {
                add_name(raw)?;
            }
        }
    }
    Ok(())
}

fn module_coverage(input: &ModuleReferenceInput, module: &ModuleMetadata) -> ModuleReferenceCoverage {
    let metadata = module.metadata.as_ref();
    let imports_complete = metadata.is_some_and(imports_complete);
    let exports_complete = metadata.is_some_and(exports_complete);
    let mut omissions: Vec<String> = module.omission.into_iter().map(str::to_owned).collect();
    if let Some(metadata) = metadata {
        omissions.extend(metadata.limitations.iter().map(|limitation| format!("{limitation:?}")));
    }
    ModuleReferenceCoverage {
        module_id: input.module_id.clone(),
        format: input.project.binary.format,
        metadata_status: if imports_complete
            && exports_complete
            && metadata
                .is_some_and(|metadata| producer_identity_supported(metadata) || export_directory_absent(metadata))
        {
            ModuleReferenceMetadataStatus::Complete
        } else if metadata.is_some() {
            ModuleReferenceMetadataStatus::Incomplete
        } else {
            ModuleReferenceMetadataStatus::Unsupported
        },
        metadata_origin: metadata
            .filter(|metadata| {
                module.original_mapped
                    && matches!(
                        metadata.status,
                        LinkageStatus::Available | LinkageStatus::Incomplete | LinkageStatus::InsufficientIdentity
                    )
            })
            .map(|_| ModuleReferenceMetadataOrigin::NativeMapped),
        source_revalidated_non_atomic: metadata.is_some() && module.original_mapped,
        export_directory_present: metadata.and_then(|metadata| metadata.export_directory_present),
        producer_identity: metadata
            .and_then(|metadata| metadata.producer_library.as_deref())
            .map(ModuleReferenceName::from_bytes),
        import_table_complete: imports_complete,
        export_table_complete: exports_complete,
        known_source_slots: metadata.map_or(0, |metadata| metadata.imports.len()),
        examined_imports: metadata.map_or(0, |metadata| metadata.imports.len()),
        examined_exports: metadata.map_or(0, |metadata| metadata.exports.len()),
        loader_status: metadata.map(|metadata| metadata.status),
        regular_imports: metadata.map(|metadata| metadata.regular_imports.clone()),
        delay_imports: metadata.map(|metadata| metadata.delay_imports.clone()),
        exports: metadata.map(|metadata| metadata.export_coverage.clone()),
        loader_limits: metadata.map(|metadata| metadata.limits),
        metadata_lookup_work: metadata.map_or(0, |metadata| metadata.lookup_work),
        omissions,
        warnings: vec!["Source checks observe metadata changes; concurrent mapped writes are not atomic.".into()],
    }
}

struct ExportIndex<'a> {
    module: usize,
    identity: &'a [u8],
    exports: Vec<&'a LinkageExport>,
}

fn build_indexes<'a>(modules: &'a [ModuleMetadata], work: &mut MatchWork) -> Result<Vec<ExportIndex<'a>>, ()> {
    let mut indexes = Vec::new();
    for (module, evidence) in modules.iter().enumerate() {
        let Some(metadata) = evidence.metadata.as_ref() else { continue };
        if export_directory_absent(metadata) {
            continue;
        }
        let Some(identity) = metadata.producer_library.as_deref() else { continue };
        if identity.is_empty() || !identity.is_ascii() {
            continue;
        }
        let mut exports: Vec<_> = metadata.exports.iter().filter(|export| export.name.is_some()).collect();
        sort_exports(&mut exports, work)?;
        indexes.push(ExportIndex { module, identity, exports });
    }
    Ok(indexes)
}

fn sort_exports(exports: &mut Vec<&LinkageExport>, work: &mut MatchWork) -> Result<(), ()> {
    let length = exports.len();
    if length < 2 {
        return Ok(());
    }
    let mut buffer = exports.clone();
    let mut width = 1;
    while width < length {
        for start in (0..length).step_by(width * 2) {
            let middle = (start + width).min(length);
            let end = (middle + width).min(length);
            let mut left = start;
            let mut right = middle;
            let mut output = start;
            while left < middle && right < end {
                let left_name = exports[left].name.as_deref().ok_or(())?;
                let right_name = exports[right].name.as_deref().ok_or(())?;
                work.charge(left_name.len().min(right_name.len()).saturating_add(1))?;
                if left_name <= right_name {
                    buffer[output] = exports[left];
                    left += 1;
                } else {
                    buffer[output] = exports[right];
                    right += 1;
                }
                output += 1;
            }
            while left < middle {
                buffer[output] = exports[left];
                left += 1;
                output += 1;
            }
            while right < end {
                buffer[output] = exports[right];
                right += 1;
                output += 1;
            }
        }
        std::mem::swap(exports, &mut buffer);
        width *= 2;
    }
    Ok(())
}

fn producer_search_complete(inputs: &[ModuleReferenceInput], modules: &[ModuleMetadata]) -> bool {
    inputs.iter().zip(modules).all(|(input, module)| {
        if input.project.binary.format != Format::Pe {
            return true;
        }
        let Some(metadata) = &module.metadata else { return false };
        if !imports_complete(metadata) {
            return false;
        }
        if export_directory_absent(metadata) {
            return true;
        }
        if !exports_complete(metadata) {
            return false;
        }
        producer_identity_supported(metadata)
    })
}

struct MatchWork {
    remaining: usize,
    exhausted: bool,
}

impl MatchWork {
    fn charge(&mut self, amount: usize) -> Result<(), ()> {
        if self.exhausted {
            return Err(());
        }
        let Some(remaining) = self.remaining.checked_sub(amount) else {
            self.exhausted = true;
            return Err(());
        };
        self.remaining = remaining;
        Ok(())
    }
}

fn matching_exports<'a>(
    index: &ExportIndex<'a>,
    name: &[u8],
    work: &mut MatchWork,
) -> Result<std::ops::Range<usize>, ()> {
    let mut start = 0;
    let mut end = index.exports.len();
    while start < end {
        let middle = start + (end - start) / 2;
        let candidate = index.exports[middle].name.as_deref().ok_or(())?;
        work.charge(candidate.len().min(name.len()).saturating_add(1))?;
        if candidate < name {
            start = middle + 1;
        } else {
            end = middle;
        }
    }
    let first = start;
    while end < index.exports.len() {
        let candidate = index.exports[end].name.as_deref().ok_or(())?;
        work.charge(candidate.len().min(name.len()).saturating_add(1))?;
        if candidate != name {
            break;
        }
        end += 1;
    }
    Ok(first..end)
}

fn export_candidate(input: &ModuleReferenceInput, export: &LinkageExport) -> ModuleReferenceCandidate {
    let (address, executable_backing, forwarder, raw_kind, reason) = match &export.target {
        LinkageExportTarget::Direct { address, executable_backing } => (
            Some(*address),
            *executable_backing,
            None,
            "pe_direct_export",
            "Named direct export declaration; address is raw image metadata, not a function entry.",
        ),
        LinkageExportTarget::Forwarder { raw } => (
            None,
            false,
            Some(ModuleReferenceName::from_bytes(raw)),
            "pe_forwarded_export",
            "Forwarded export is unsupported; no forwarder target was followed.",
        ),
    };
    ModuleReferenceCandidate {
        module_id: input.module_id.clone(),
        address,
        export_name: export.name.as_deref().map(ModuleReferenceName::from_bytes),
        forwarder,
        raw_kind: raw_kind.into(),
        executable_backing,
        identity_only: false,
        reason: reason.into(),
    }
}

fn identity_candidate(input: &ModuleReferenceInput) -> ModuleReferenceCandidate {
    ModuleReferenceCandidate {
        module_id: input.module_id.clone(),
        address: None,
        export_name: None,
        forwarder: None,
        raw_kind: "pe_producer_identity_only".into(),
        executable_backing: false,
        identity_only: true,
        reason: "Producer DLL identity matches; no matching named export was observed.".into(),
    }
}

fn reference_row(
    inputs: &[ModuleReferenceInput],
    source: usize,
    import: &LinkageImport,
    source_complete: bool,
    indexes: &[ExportIndex<'_>],
    search_complete: bool,
    work: &mut MatchWork,
) -> ModuleReferenceRow {
    let (name, ordinal) = match &import.symbol {
        LinkageSymbol::Named(name) => (Some(name.as_slice()), None),
        LinkageSymbol::Ordinal(ordinal) => (None, Some(*ordinal)),
    };
    let mut row = ModuleReferenceRow {
        source_module_id: inputs[source].module_id.clone(),
        source_slot: import.slot_address,
        import_library: ModuleReferenceName::from_bytes(&import.library),
        import_name: name.map(ModuleReferenceName::from_bytes),
        import_ordinal: ordinal,
        raw_kind: match (import.provenance, ordinal.is_some()) {
            (LinkageImportProvenance::PeImportDirectory, false) => "pe_named_import",
            (LinkageImportProvenance::PeImportDirectory, true) => "pe_ordinal_import",
            (LinkageImportProvenance::PeDelayImportDirectory, false) => "pe_delay_named_import",
            (LinkageImportProvenance::PeDelayImportDirectory, true) => "pe_delay_ordinal_import",
        }
        .into(),
        status: ModuleReferenceStatus::Unsupported,
        reason: String::new(),
        candidates: Vec::new(),
        candidate_count: 0,
        candidates_truncated: false,
        producer_search_complete: search_complete && source_complete,
    };
    let Some(name) = name else {
        row.reason = "Ordinal imports are unsupported; ordinal tags never match literal #name exports.".into();
        row.producer_search_complete = false;
        row.candidates_truncated = true;
        return row;
    };
    if import.library.is_empty() || !import.library.is_ascii() {
        row.reason = "UnsupportedIdentity: DLL identity requires nonempty whole-name ASCII bytes.".into();
        row.producer_search_complete = false;
        row.candidates_truncated = true;
        return row;
    }
    let mut providers = Vec::new();
    for index in indexes {
        if work.charge(index.identity.len().min(import.library.len()).saturating_add(1)).is_err() {
            break;
        }
        if index.identity.eq_ignore_ascii_case(&import.library) {
            providers.push(index);
        }
    }
    if work.exhausted {
        row.producer_search_complete = false;
        row.candidates_truncated = true;
        row.candidate_count = providers.len();
        for index in providers {
            let mut candidate = identity_candidate(&inputs[index.module]);
            candidate.reason = "Producer identity matches; remaining identity/export search is incomplete.".into();
            row.candidates.push(candidate);
        }
        row.reason = "Matching comparison budget exhausted; producer uniqueness is unproven.".into();
        return row;
    }
    let provider_count = providers.len();
    let mut direct_exports = 0usize;
    let mut forwarded_exports = 0usize;
    for index in providers {
        let matches = match matching_exports(index, name, work) {
            Ok(matches) => matches,
            Err(()) => {
                row.producer_search_complete = false;
                row.candidate_count = row.candidate_count.saturating_add(1);
                if row.candidates.len() < 16 {
                    let mut candidate = identity_candidate(&inputs[index.module]);
                    candidate.reason = "Producer identity matches; named-export search budget exhausted.".into();
                    row.candidates.push(candidate);
                }
                continue;
            }
        };
        let count = matches.len().max(1);
        row.candidate_count = row.candidate_count.saturating_add(count);
        if matches.is_empty() {
            if row.candidates.len() < 16 {
                row.candidates.push(identity_candidate(&inputs[index.module]));
            }
        } else {
            for matched in matches {
                let export = index.exports[matched];
                match &export.target {
                    LinkageExportTarget::Direct { .. } => direct_exports += 1,
                    LinkageExportTarget::Forwarder { .. } => forwarded_exports += 1,
                }
                if row.candidates.len() < 16 {
                    row.candidates.push(export_candidate(&inputs[index.module], export));
                }
            }
        }
    }
    row.candidates_truncated = row.candidate_count > row.candidates.len() || !row.producer_search_complete;
    let (status, reason) = if work.exhausted {
        (ModuleReferenceStatus::Unsupported, "Matching comparison budget exhausted; producer uniqueness is unproven.")
    } else if provider_count > 1 {
        (ModuleReferenceStatus::Ambiguous, "Multiple loaded modules declare the same whole DLL identity.")
    } else if !row.producer_search_complete {
        (ModuleReferenceStatus::Unsupported, "Incomplete source or producer metadata search; uniqueness is unproven.")
    } else if direct_exports + forwarded_exports > 1 {
        (ModuleReferenceStatus::Ambiguous, "Multiple named exports match the declaration; no target was selected.")
    } else if forwarded_exports != 0 {
        (ModuleReferenceStatus::Unsupported, "Forwarded exports are unsupported; no forwarder target was followed.")
    } else if direct_exports == 1 && !row.candidates_truncated {
        (ModuleReferenceStatus::DeclaredLink, "Exact named declaration and one loaded PE producer/direct export.")
    } else {
        (ModuleReferenceStatus::Unresolved, "Complete loaded-PE metadata search found no matching direct export.")
    };
    row.status = status;
    row.reason = reason.into();
    row
}

struct NameFilter<'a> {
    needle: &'a [u8],
    prefix: [usize; 256],
}

impl<'a> NameFilter<'a> {
    fn new(filter: Option<&'a str>) -> Self {
        let needle = filter.unwrap_or("").as_bytes();
        let mut prefix = [0; 256];
        let mut matched = 0;
        for index in 1..needle.len() {
            while matched > 0 && needle[index] != needle[matched] {
                matched = prefix[matched - 1];
            }
            if needle[index] == needle[matched] {
                matched += 1;
            }
            prefix[index] = matched;
        }
        Self { needle, prefix }
    }

    fn contains(&self, bytes: &[u8]) -> bool {
        if self.needle.is_empty() {
            return true;
        }
        let mut matched = 0;
        for byte in bytes {
            while matched > 0 && *byte != self.needle[matched] {
                matched = self.prefix[matched - 1];
            }
            if *byte == self.needle[matched] {
                matched += 1;
            }
            if matched == self.needle.len() {
                return true;
            }
        }
        false
    }

    fn matches(&self, import: &LinkageImport) -> bool {
        self.contains(&import.library)
            || match &import.symbol {
                LinkageSymbol::Named(name) => self.contains(name),
                LinkageSymbol::Ordinal(_) => false,
            }
    }
}

/// PE declaration metadata only. The source query never narrows the producer uniqueness search.
pub fn module_references(
    inputs: &[ModuleReferenceInput],
    query: &ModuleReferenceQuery,
) -> Result<ModuleReferenceReport, ApiError> {
    validate_module_reference_inputs(inputs)?;
    let limit = query_limit(inputs, query)?;
    let modules = read_metadata(inputs)?;
    let coverage: Vec<_> = inputs.iter().zip(&modules).map(|(input, module)| module_coverage(input, module)).collect();
    let matching_work_limit = query.matching_work_limit.unwrap_or(MAX_MATCHING_WORK).min(MAX_MATCHING_WORK);
    let mut work = MatchWork { remaining: matching_work_limit, exhausted: false };
    let indexes = match build_indexes(&modules, &mut work) {
        Ok(indexes) => indexes,
        Err(()) => {
            work.exhausted = true;
            Vec::new()
        }
    };
    let search_complete = !work.exhausted && producer_search_complete(inputs, &modules);
    let filter = NameFilter::new(query.filter.as_deref());
    let offset = query.offset.unwrap_or(0);
    let matched_is_lower_bound = coverage.iter().any(|module| {
        query.source_module_id.as_ref().is_none_or(|id| id == &module.module_id) && !module.import_table_complete
    });
    let mut report = ModuleReferenceReport {
        version: 1,
        matching_policy: "pe-whole-dll-ascii-case-only-exact-symbol-v1",
        proven_runtime_flow: false,
        proven_layout: false,
        complete: coverage.iter().all(|module| module.metadata_status == ModuleReferenceMetadataStatus::Complete),
        matching_work_limit,
        matching_work_used: matching_work_limit,
        matching_work_exhausted: false,
        coverage,
        rows: Vec::new(),
        matched: 0,
        matched_is_lower_bound,
        returned: 0,
        offset,
        limit,
        more: false,
        next_offset: None,
        rows_truncated: false,
        byte_capped: false,
        limitations: vec![
            "PE metadata declarations only; no runtime flow, load-order choice, layout or function-entry proof.",
            "DLL identity uses entire raw ASCII metadata names with ASCII case equivalence; symbols use exact bytes.",
            "No paths, basenames, labels, extension guesses, namespace bindings or lossy Unicode joins are used.",
            "Only supplied modules are searched; ordinal imports and forwarded exports remain unsupported.",
            "Unknown PE producer identities block uniqueness unless export-directory absence is proven.",
            "Every supplied PE must have complete regular/delay import coverage, including non-exporting modules.",
            "Sort, DLL identity and export-name comparisons share a 32 MiB work cap, separate from parser work.",
            "Mapped-source revalidation is non-atomic; serialized reports do not authorize stale UI navigation.",
        ],
    };
    let mut retained = Vec::new();
    for (source, module) in modules.iter().enumerate() {
        if query.source_module_id.as_ref().is_some_and(|id| id != &inputs[source].module_id) {
            continue;
        }
        let Some(metadata) = &module.metadata else { continue };
        for import in &metadata.imports {
            if query.source_slot.is_some_and(|slot| slot != import.slot_address) || !filter.matches(import) {
                continue;
            }
            report.matched = report.matched.saturating_add(1);
            if retained.len() < MAX_ROWS {
                retained.push((source, import, imports_complete(metadata)));
            } else {
                report.rows_truncated = true;
                report.complete = false;
            }
        }
    }
    // Reserve maximum-width paging fields and false booleans before selecting whole encoded rows.
    let metadata_complete = report.complete;
    report.complete = false;
    report.next_offset = Some(usize::MAX);
    report.returned = MAX_MODULE_REFERENCE_PAGE;
    let mut used = json_size(&report)?;
    for (source, import, source_complete) in retained.iter().skip(offset).take(limit) {
        let row = reference_row(inputs, *source, import, *source_complete, &indexes, search_complete, &mut work);
        let row_size = json_size(&row)?.saturating_add(usize::from(!report.rows.is_empty()));
        if used.checked_add(row_size).is_none_or(|size| size > MAX_MODULE_REFERENCE_RESULT_BYTES) {
            report.byte_capped = true;
            break;
        }
        used += row_size;
        report.rows.push(row);
    }
    report.returned = report.rows.len();
    let consumed = offset.saturating_add(report.returned);
    report.more = consumed < retained.len();
    report.next_offset = report.more.then_some(consumed);
    if report.more && report.returned == 0 {
        return Err(ApiError::Invalid("module reference response cannot fit one bounded whole row".into()));
    }
    report.matching_work_used = matching_work_limit - work.remaining;
    report.matching_work_exhausted = work.exhausted;
    report.complete =
        metadata_complete && !work.exhausted && report.rows.iter().all(|row| row.producer_search_complete);
    if json_size(&report)? > MAX_MODULE_REFERENCE_RESULT_BYTES {
        return Err(ApiError::Invalid("module reference response exceeds encoded JSON byte limit".into()));
    }
    validate_module_reference_inputs(inputs)?;
    Ok(report)
}
