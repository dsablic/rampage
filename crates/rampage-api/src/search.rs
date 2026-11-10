//! Read-only, bounded searches of retained image bytes and native analysis evidence.
//!
//! Ranges are half-open virtual addresses. Pagination never limits the scan: `total` describes all observed
//! unique hit addresses, and is a lower bound whenever `total_is_exact` is false. Context is opt-in because
//! native function discovery can initialize the program-analysis cache. No annotation or source is changed.

mod bytes;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::{ApiError, Project};

pub const MAX_SEARCH_SCAN_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SEARCH_MATCH_WORK: u64 = 64 * 1024 * 1024;
pub const MAX_SEARCH_INSTRUCTIONS: u64 = 1_000_000;
pub const MAX_SEARCH_RESULTS: usize = 100_000;
pub const MAX_SEARCH_PAGE: usize = 1000;
pub const MAX_SEARCH_PATTERN_BYTES: usize = rampage_detect::MAX_PATTERN_BYTES;
pub const MAX_SEARCH_REGEX_SIZE: usize = 1024 * 1024;
pub const MAX_SEARCH_MAPPINGS: usize = 16_384;
pub const MAX_SEARCH_TEXT_RUN_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchMode {
    Bytes {
        pattern: String,
    },
    Text {
        pattern: String,
        encoding: SearchTextEncoding,
        #[serde(default)]
        regex: bool,
    },
    Immediate {
        immediate: SearchImmediate,
    },
    Instruction {
        mnemonic: Option<String>,
        operands: Option<String>,
    },
    References {
        target: u64,
    },
    FunctionsReferencing {
        reference: SearchReference,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchValue {
    Unsigned(u64),
    Signed(i64),
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchImmediate {
    pub value: SearchValue,
    pub width_bits: Option<u16>,
    #[serde(default)]
    pub include_displacements: bool,
    #[serde(default)]
    pub include_addresses: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchStringEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchReference {
    Address { target: u64 },
    String { text: String, encoding: SearchStringEncoding },
    Import { name: String, library: Option<String> },
    Constant { immediate: SearchImmediate },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchTextEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SearchBudget {
    pub scan_bytes: u64,
    /// Conservative byte comparisons for literal/wildcard search; regex charges haystack bytes per search.
    pub match_work: u64,
    pub instructions: u64,
    pub results: usize,
}

impl Default for SearchBudget {
    fn default() -> Self {
        Self {
            scan_bytes: MAX_SEARCH_SCAN_BYTES,
            match_work: MAX_SEARCH_MATCH_WORK,
            instructions: MAX_SEARCH_INSTRUCTIONS,
            results: MAX_SEARCH_RESULTS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub mode: SearchMode,
    #[serde(default)]
    pub range: Option<SearchRange>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub include_context: bool,
    #[serde(default)]
    pub budget: SearchBudget,
}

fn default_page_limit() -> usize {
    100
}

impl SearchQuery {
    pub fn new(mode: SearchMode) -> Self {
        Self {
            mode,
            range: None,
            offset: 0,
            limit: default_page_limit(),
            include_context: false,
            budget: SearchBudget::default(),
        }
    }
}

#[derive(Default)]
pub struct SearchControl<'a> {
    pub cancel: Option<&'a AtomicBool>,
}

impl SearchControl<'_> {
    pub fn cancelled(&self) -> bool {
        self.cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStopReason {
    Complete,
    ScanByteBudget,
    MatchWorkBudget,
    InstructionBudget,
    ResultCap,
    Cancelled,
    IncompleteEvidence,
    TextRunBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSymbolSource {
    Annotation,
    LoaderName,
    Synthetic,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchFunctionContext {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    pub name_truncated: bool,
    pub symbol_source: SearchSymbolSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchHitEvidence {
    BytePattern,
    Text,
    Immediate,
    Instruction,
    Reference,
    ReferencingFunction,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Matching byte extent at `address`; zero for reference/function rows. Instruction-site bytes are in `code`.
    pub size: u64,
    /// Backing offset of the first byte; a virtual match may cross discontiguous image pieces.
    pub image_offset: Option<u64>,
    /// Absent for owned captures: their packed image offsets are not offsets in a source document.
    pub file_offset: Option<u64>,
    pub function: Option<SearchFunctionContext>,
    pub evidence: SearchHitEvidence,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub target: Option<u64>,
    pub code: Option<SearchCodeEvidence>,
    pub reference_kinds: Vec<rampage_analysis::discover::XrefKind>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchCodeEvidence {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub native_function: u64,
    pub bytes: String,
    pub text: String,
    pub text_truncated: bool,
    pub flow: rampage_arch::Flow,
    pub native: crate::search_code::CodeSearchEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSource {
    /// Only the loader's actual retained backing path; never target-reported provenance or module paths.
    pub backing_path: Option<PathBuf>,
    pub mapped_source_checked: bool,
    pub owned_image: bool,
    pub selected_image_file_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchScope {
    pub kind: &'static str,
    pub requested_range: Option<SearchRange>,
    pub eligible_bytes: u64,
    pub mapped_spans: usize,
    pub excludes_unmapped_overlay_and_zero_fill: bool,
    pub joins_virtual_gaps: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchBudgetEvidence {
    pub limits: SearchBudget,
    pub match_work: u64,
}

/// Unscanned ranges listed in one report; the rest are counted.
pub const MAX_UNSCANNED_RANGES: usize = 32;

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// A half-open mapped range a stopped scan did not search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnscannedRange {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchReport {
    pub source: SearchSource,
    pub scope: SearchScope,
    pub hits: Vec<SearchHit>,
    pub offset: usize,
    pub limit: usize,
    /// Exact on complete scans; an observed lower bound on any interrupted scan.
    pub total: usize,
    pub total_is_exact: bool,
    /// Charged byte inspection; native scopes include decoder overfetch and may repeat inspected bytes.
    pub scanned_bytes: u64,
    pub scanned_instructions: u64,
    pub scanned_references: u64,
    pub truncated: bool,
    pub cancelled: bool,
    pub stop_reason: SearchStopReason,
    pub budget: SearchBudgetEvidence,
    pub invalid_utf16_units: u64,
    pub utf16_trailing_bytes: u64,
    /// When a budget or cancellation stopped a byte/text scan: the first address whose matches were not searched.
    /// Searching again with `range.start` here (and the same end) continues the scan.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub resume_at: Option<u64>,
    /// The first [`MAX_UNSCANNED_RANGES`] mapped ranges, from `resume_at` on, that the stopped scan left
    /// unsearched; `unscanned_range_count` and `unscanned_bytes` cover all of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unscanned_ranges: Vec<UnscannedRange>,
    #[serde(skip_serializing_if = "is_zero")]
    pub unscanned_range_count: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub unscanned_bytes: u64,
    pub limitations: Vec<String>,
}

impl Project {
    pub fn search(&self, query: &SearchQuery) -> Result<SearchReport, ApiError> {
        self.search_controlled(query, &SearchControl::default())
    }

    pub fn search_controlled(
        &self,
        query: &SearchQuery,
        control: &SearchControl<'_>,
    ) -> Result<SearchReport, ApiError> {
        validate_query(query)?;
        match &query.mode {
            SearchMode::Bytes { .. } | SearchMode::Text { .. } => bytes::search(self, query, control),
            _ => search_native(self, query, control),
        }
    }
}

pub(crate) fn validate_query(query: &SearchQuery) -> Result<(), ApiError> {
    if query.range.is_some_and(|range| range.start >= range.end) {
        return Err(invalid("search range must have start < end (exclusive)"));
    }
    if query.limit == 0 || query.limit > MAX_SEARCH_PAGE || query.offset > MAX_SEARCH_RESULTS {
        return Err(invalid("search pagination exceeds the page/result bound"));
    }
    let budget = query.budget;
    if budget.scan_bytes == 0
        || budget.scan_bytes > MAX_SEARCH_SCAN_BYTES
        || budget.match_work == 0
        || budget.match_work > MAX_SEARCH_MATCH_WORK
        || budget.instructions == 0
        || budget.instructions > MAX_SEARCH_INSTRUCTIONS
        || budget.results == 0
        || budget.results > MAX_SEARCH_RESULTS
    {
        return Err(invalid("search budget is zero or exceeds a public maximum"));
    }
    Ok(())
}

pub(crate) fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

/// The function containing `address`, looked up in an analysis the caller already checked once for all its hits.
pub(crate) fn function_context(
    project: &Project,
    analysis: &crate::project::Analysis,
    address: u64,
) -> Option<SearchFunctionContext> {
    let address = analysis.function_containing(address)?;
    Some(function_context_for_owner(project, address))
}

fn function_context_for_owner(project: &Project, address: u64) -> SearchFunctionContext {
    let annotations = project.annotations();
    let symbol_source = if annotations.name(address).is_some() {
        SearchSymbolSource::Annotation
    } else if project.inventory_function_name_in(&annotations, address).is_some() {
        SearchSymbolSource::LoaderName
    } else {
        SearchSymbolSource::Synthetic
    };
    let mut name = project.function_name_in(&annotations, address);
    let name_truncated = name.len() > 512;
    if name_truncated {
        let mut end = 512;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
    }
    SearchFunctionContext { address, name, name_truncated, symbol_source }
}

pub(crate) fn bytes_source_check(binary: &rampage_loaders::Binary) -> Result<(), ApiError> {
    binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Unavailable(format!("search source validation: {error}")))?;
    Ok(())
}

fn native_immediate(immediate: &SearchImmediate) -> crate::search_code::CodeImmediate {
    crate::search_code::CodeImmediate {
        value: match immediate.value {
            SearchValue::Unsigned(value) => crate::search_code::CodeValue::Unsigned(value),
            SearchValue::Signed(value) => crate::search_code::CodeValue::Signed(value),
        },
        width_bits: immediate.width_bits,
        include_displacements: immediate.include_displacements,
        include_addresses: immediate.include_addresses,
    }
}

fn native_kind(mode: &SearchMode) -> Result<crate::search_code::CodeSearchKind, ApiError> {
    use crate::search_code::{CodePattern, CodeReference, CodeSearchKind, SourceString, SourceStringEncoding};
    Ok(match mode {
        SearchMode::Immediate { immediate } => CodeSearchKind::Immediate(native_immediate(immediate)),
        SearchMode::Instruction { mnemonic, operands } => {
            if mnemonic.is_none() && operands.is_none() {
                return Err(invalid("instruction search needs a mnemonic or operand glob"));
            }
            CodeSearchKind::Instruction {
                mnemonic: CodePattern::new(mnemonic.as_deref().unwrap_or("*"))?,
                operands: operands.as_deref().map(CodePattern::new).transpose()?,
            }
        }
        SearchMode::FunctionsReferencing { reference } => CodeSearchKind::FunctionsReferencing(match reference {
            SearchReference::Address { target } => CodeReference::Address(*target),
            SearchReference::Constant { immediate } => CodeReference::Constant(native_immediate(immediate)),
            SearchReference::Import { name, library } => {
                CodeReference::Import { name: name.clone(), library: library.clone() }
            }
            SearchReference::String { text, encoding } => CodeReference::String(SourceString::new(
                text,
                match encoding {
                    SearchStringEncoding::Utf8 => SourceStringEncoding::Utf8,
                    SearchStringEncoding::Utf16Le => SourceStringEncoding::Utf16Le,
                    SearchStringEncoding::Utf16Be => SourceStringEncoding::Utf16Be,
                },
            )?),
        }),
        _ => return Err(invalid("native backend needs immediate, instruction or function-reference mode")),
    })
}

fn hit_offsets(spans: &[bytes::ByteSpan], source: &SearchSource, address: u64) -> (Option<u64>, Option<u64>) {
    let image_offset = spans
        .iter()
        .find(|span| address >= span.address && address - span.address < span.size)
        .map(|span| span.image_offset + (address - span.address));
    let file_offset = image_offset.and_then(|offset| source.selected_image_file_offset?.checked_add(offset));
    (image_offset, file_offset)
}

fn native_report(project: &Project, query: &SearchQuery) -> Result<(SearchReport, Vec<bytes::ByteSpan>), ApiError> {
    let source = bytes::source(&project.binary)?;
    let spans = bytes::mapped_spans(&project.binary, None)?;
    let scoped = bytes::mapped_spans(&project.binary, query.range)?;
    let eligible_bytes = scoped.iter().map(|span| span.size).sum();
    Ok((
        SearchReport {
            source,
            scope: SearchScope {
                kind: "production_discovered_blocks_and_retained_xrefs",
                requested_range: query.range,
                eligible_bytes,
                mapped_spans: scoped.len(),
                excludes_unmapped_overlay_and_zero_fill: true,
                joins_virtual_gaps: false,
            },
            hits: vec![],
            offset: query.offset,
            limit: query.limit,
            total: 0,
            total_is_exact: true,
            scanned_bytes: 0,
            scanned_instructions: 0,
            scanned_references: 0,
            truncated: false,
            cancelled: false,
            stop_reason: SearchStopReason::Complete,
            budget: SearchBudgetEvidence { limits: query.budget, match_work: 0 },
            invalid_utf16_units: 0,
            utf16_trailing_bytes: 0,
            resume_at: None,
            unscanned_ranges: Vec::new(),
            unscanned_range_count: 0,
            unscanned_bytes: 0,
            limitations: vec![
                "Only production-discovered instruction boundaries and retained references are searched.".into(),
                "Native discovery/cache initialization is not interruptible; cancellation is checked \
             before and after it."
                    .into(),
                "Native scanned bytes include charged decoder input windows, pointer reads and source text; \
             repeated inspections can count bytes again."
                    .into(),
                "Instruction/reference ranges filter sites, not the returned referencing-function entry address."
                    .into(),
                "Mnemonic and operand patterns are whole-field ASCII-case-insensitive globs, not regex; \
             omitted mnemonic means '*'."
                    .into(),
            ],
        },
        spans,
    ))
}

fn search_native(
    project: &Project,
    query: &SearchQuery,
    control: &SearchControl<'_>,
) -> Result<SearchReport, ApiError> {
    if let SearchMode::References { target } = query.mode {
        return search_references(project, query, control, target);
    }
    let kind = native_kind(&query.mode)?;
    let native_query = crate::search_code::CodeSearchQuery::new(kind)?
        .with_range(query.range.map(|range| range.start..range.end))?
        .with_page(query.offset, query.limit)?
        .with_bounds(query.budget.instructions as usize, query.budget.results)?
        .with_scan_bounds(query.budget.scan_bytes, query.budget.match_work)?;
    let (mut report, spans) = native_report(project, query)?;
    let code = project.search_code_controlled(&native_query, control)?;
    report.total = code.total;
    report.total_is_exact = !code.total_is_lower_bound;
    report.scanned_bytes = code.decoded_bytes + code.source_bytes;
    report.scanned_instructions = code.decoded_instructions as u64;
    report.scanned_references = code.examined_references;
    report.cancelled = code.cancelled;
    report.stop_reason = code.stop_reason;
    report.truncated = code.total_is_lower_bound;
    report.budget.match_work = code.match_work;
    report.limitations.extend(code.limitations);
    for hit in code.hits {
        if control.cancelled() {
            report.cancelled = true;
            report.total_is_exact = false;
            report.truncated = true;
            report.stop_reason = SearchStopReason::Cancelled;
            break;
        }
        let (image_offset, file_offset) = hit_offsets(&spans, &report.source, hit.address);
        let function = query.include_context.then(|| function_context_for_owner(project, hit.function));
        report.hits.push(SearchHit {
            address: hit.address,
            size: if matches!(query.mode, SearchMode::FunctionsReferencing { .. }) {
                0
            } else {
                (hit.bytes.len() / 2) as u64
            },
            image_offset,
            file_offset,
            function,
            evidence: match query.mode {
                SearchMode::Immediate { .. } => SearchHitEvidence::Immediate,
                SearchMode::Instruction { .. } => SearchHitEvidence::Instruction,
                _ => SearchHitEvidence::ReferencingFunction,
            },
            target: hit.evidence.target,
            reference_kinds: vec![],
            code: Some(SearchCodeEvidence {
                site: hit.site,
                native_function: hit.function,
                bytes: hit.bytes,
                text: hit.text,
                text_truncated: hit.text_truncated,
                flow: hit.flow,
                native: hit.evidence,
            }),
        });
    }
    bytes_source_check(&project.binary)?;
    Ok(report)
}

fn search_references(
    project: &Project,
    query: &SearchQuery,
    control: &SearchControl<'_>,
    target: u64,
) -> Result<SearchReport, ApiError> {
    use std::collections::BTreeMap;
    let (mut report, spans) = native_report(project, query)?;
    report.scope.kind = "retained_xref_sites_to_exact_address";
    if control.cancelled() {
        report.stop_reason = SearchStopReason::Cancelled;
    } else {
        let analysis = project.analysis()?;
        if control.cancelled() {
            report.stop_reason = SearchStopReason::Cancelled;
        }
        let mut hits: BTreeMap<u64, Vec<rampage_analysis::discover::XrefKind>> = BTreeMap::new();
        // The same retained target index used by Project::xrefs(To(target)); never an immediate search.
        for xref in analysis.program.xrefs_to(target) {
            if control.cancelled() {
                report.stop_reason = SearchStopReason::Cancelled;
                break;
            }
            if report.budget.match_work == query.budget.match_work {
                report.stop_reason = SearchStopReason::MatchWorkBudget;
                break;
            }
            report.scanned_references += 1;
            report.budget.match_work += 1;
            if query.range.is_some_and(|range| xref.from < range.start || xref.from >= range.end) {
                continue;
            }
            let kinds = hits.entry(xref.from).or_default();
            if !kinds.contains(&xref.kind) {
                kinds.push(xref.kind);
            }
            if hits.len() > query.budget.results {
                report.stop_reason = SearchStopReason::ResultCap;
                break;
            }
        }
        report.total = hits.len();
        for (address, mut kinds) in hits.into_iter().take(query.budget.results).skip(query.offset).take(query.limit) {
            if control.cancelled() {
                report.stop_reason = SearchStopReason::Cancelled;
                break;
            }
            kinds.sort_unstable();
            let (image_offset, file_offset) = hit_offsets(&spans, &report.source, address);
            report.hits.push(SearchHit {
                address,
                size: 0,
                image_offset,
                file_offset,
                function: if query.include_context { function_context(project, analysis, address) } else { None },
                evidence: SearchHitEvidence::Reference,
                target: Some(target),
                code: None,
                reference_kinds: kinds,
            });
        }
    }
    report.total_is_exact = report.stop_reason == SearchStopReason::Complete;
    report.truncated = !report.total_is_exact;
    report.cancelled = report.stop_reason == SearchStopReason::Cancelled;
    bytes_source_check(&project.binary)?;
    Ok(report)
}

#[cfg(test)]
#[path = "search/bytes_tests.rs"]
mod bytes_tests;
