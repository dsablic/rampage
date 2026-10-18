//! Read-only search over production-discovered instruction boundaries, not executable-section sweeps.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use rampage_analysis::discover::{Block, Program, XrefKind};
use rampage_arch::{Flow, Insn, OperandEvidence, OperandKind};
use serde::Serialize;

use crate::search::{SearchControl, SearchStopReason};
use crate::{ApiError, Project};

const MAX_INSTRUCTIONS: usize = 1_000_000;
const MAX_HITS: usize = 100_000;
const MAX_TEXT: usize = 4096;
const MAX_SOURCE_STRING: usize = 16_384;
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum CodeValue {
    Unsigned(u64),
    Signed(i64),
}

#[derive(Debug, Clone)]
pub struct CodeImmediate {
    pub value: CodeValue,
    /// Semantic operand width, not the encoded immediate field's width.
    pub width_bits: Option<u16>,
    pub include_displacements: bool,
    pub include_addresses: bool,
}

impl CodeImmediate {
    fn validate(&self) -> Result<(), ApiError> {
        if let Some(width) = self.width_bits {
            if !(1..=64).contains(&width) {
                return Err(invalid("immediate width must be in 1..=64"));
            }
            let fits = match self.value {
                CodeValue::Unsigned(value) => width == 64 || value < (1u64 << width),
                CodeValue::Signed(value) => {
                    width == 64 || (-(1i64 << (width - 1))..(1i64 << (width - 1))).contains(&value)
                }
            };
            if !fits {
                return Err(invalid("immediate value does not fit its requested semantic width"));
            }
        }
        Ok(())
    }

    fn matches(&self, unsigned: Option<u64>, signed: Option<i64>, width: Option<u16>) -> bool {
        self.width_bits.is_none_or(|wanted| width == Some(wanted))
            && match self.value {
                CodeValue::Unsigned(wanted) => unsigned == Some(wanted),
                CodeValue::Signed(wanted) => signed == Some(wanted),
            }
    }
}

/// Whole-field ASCII-case-insensitive glob: `*` matches zero or more bytes, `?` one byte;
/// every other character (including backslash) is literal. Whitespace is collapsed to one space.
/// Assembly patterns are ASCII, bounded to 512 bytes, and never interpreted as regular expressions.
#[derive(Debug, Clone)]
pub struct CodePattern(String);

impl CodePattern {
    pub fn new(pattern: &str) -> Result<Self, ApiError> {
        if pattern.is_empty() || pattern.len() > 512 || !pattern.is_ascii() || pattern.contains('\0') {
            return Err(invalid("assembly glob must contain 1..=512 ASCII bytes without NUL"));
        }
        let pattern = normalize(pattern);
        if pattern.is_empty() {
            return Err(invalid("assembly glob must not be whitespace-only"));
        }
        Ok(Self(pattern))
    }

    fn matches(&self, text: &str) -> bool {
        let text = normalize(text);
        let (pattern, text) = (self.0.as_bytes(), text.as_bytes());
        let (mut p, mut t, mut star, mut retry) = (0, 0, None, 0);
        while t < text.len() {
            if p < pattern.len() && pattern[p] == b'*' {
                star = Some(p);
                p += 1;
                retry = t;
            } else if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
                p += 1;
                t += 1;
            } else if let Some(at) = star {
                retry += 1;
                t = retry;
                p = at + 1;
            } else {
                return false;
            }
        }
        while p < pattern.len() && pattern[p] == b'*' {
            p += 1;
        }
        p == pattern.len()
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStringEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// A literal, case-sensitive Unicode substring of text starting at a retained data-xref target.
/// Source text is decoded in the selected encoding up to NUL, backing end, or the source bound.
#[derive(Debug, Clone)]
pub struct SourceString {
    text: String,
    encoding: SourceStringEncoding,
}

impl SourceString {
    pub fn new(text: &str, encoding: SourceStringEncoding) -> Result<Self, ApiError> {
        if text.is_empty() || text.len() > MAX_TEXT || text.contains('\0') {
            return Err(invalid("source string must contain 1..=4096 UTF-8 bytes without NUL"));
        }
        Ok(Self { text: text.to_owned(), encoding })
    }
}

#[derive(Debug, Clone)]
pub enum CodeReference {
    Address(u64),
    String(SourceString),
    /// Exact retained import name and, when supplied, exact library identity; no analyst-name matching.
    Import {
        name: String,
        library: Option<String>,
    },
    Constant(CodeImmediate),
}

#[derive(Debug, Clone)]
pub enum CodeSearchKind {
    Immediate(CodeImmediate),
    Instruction { mnemonic: CodePattern, operands: Option<CodePattern> },
    FunctionsReferencing(CodeReference),
}

/// Checked native query. Ranges are half-open instruction-site ranges; a range never seeds decoding.
#[derive(Debug, Clone)]
pub struct CodeSearchQuery {
    kind: CodeSearchKind,
    range: Option<Range<u64>>,
    offset: usize,
    limit: usize,
    max_instructions: usize,
    max_hits: usize,
    max_bytes: u64,
    max_work: u64,
}

impl CodeSearchQuery {
    pub fn new(kind: CodeSearchKind) -> Result<Self, ApiError> {
        match &kind {
            CodeSearchKind::Immediate(value) | CodeSearchKind::FunctionsReferencing(CodeReference::Constant(value)) => {
                value.validate()?
            }
            CodeSearchKind::FunctionsReferencing(CodeReference::Import { name, library })
                if name.is_empty()
                    || name.len() > MAX_TEXT
                    || name.contains('\0')
                    || library.as_ref().is_some_and(|s| s.is_empty() || s.len() > MAX_TEXT || s.contains('\0')) =>
            {
                return Err(invalid("import identity must contain 1..=4096 bytes without NUL"));
            }
            _ => {}
        }
        Ok(Self {
            kind,
            range: None,
            offset: 0,
            limit: 100,
            max_instructions: MAX_INSTRUCTIONS,
            max_hits: MAX_HITS,
            max_bytes: crate::search::MAX_SEARCH_SCAN_BYTES,
            max_work: crate::search::MAX_SEARCH_MATCH_WORK,
        })
    }

    pub fn with_range(mut self, range: Option<Range<u64>>) -> Result<Self, ApiError> {
        if range.as_ref().is_some_and(|range| range.start >= range.end) {
            return Err(invalid("code search range must be nonempty and increasing"));
        }
        self.range = range;
        Ok(self)
    }

    pub fn with_page(mut self, offset: usize, limit: usize) -> Result<Self, ApiError> {
        if limit == 0 || limit > crate::search::MAX_SEARCH_PAGE || offset.checked_add(limit).is_none() {
            return Err(invalid("code search page requires 1..=1000 hits and a nonoverflowing offset"));
        }
        self.offset = offset;
        self.limit = limit;
        Ok(self)
    }

    pub fn with_bounds(mut self, instructions: usize, hits: usize) -> Result<Self, ApiError> {
        if instructions == 0 || instructions > MAX_INSTRUCTIONS || hits == 0 || hits > MAX_HITS {
            return Err(invalid("code search bounds require 1..=1000000 instructions and 1..=100000 hits"));
        }
        self.max_instructions = instructions;
        self.max_hits = hits;
        Ok(self)
    }

    pub fn with_scan_bounds(mut self, bytes: u64, work: u64) -> Result<Self, ApiError> {
        if bytes == 0
            || bytes > crate::search::MAX_SEARCH_SCAN_BYTES
            || work == 0
            || work > crate::search::MAX_SEARCH_MATCH_WORK
        {
            return Err(invalid("code search byte/work bounds exceed public search limits"));
        }
        self.max_bytes = bytes;
        self.max_work = work;
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeSearchEvidence {
    pub kind: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub target: Option<u64>,
    pub operand: Option<OperandEvidence>,
    pub source_encoding: Option<SourceStringEncoding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeSearchHit {
    /// Sort/pagination key: the instruction site, or the function entry in reference mode.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub function_name: String,
    pub function_name_truncated: bool,
    pub bytes: String,
    pub text: String,
    pub text_truncated: bool,
    pub flow: Flow,
    pub evidence: CodeSearchEvidence,
}

#[derive(Debug, Serialize)]
pub struct CodeSearchReport {
    pub hits: Vec<CodeSearchHit>,
    /// Exact observed distinct total unless `total_is_lower_bound` is true.
    pub total: usize,
    pub total_is_lower_bound: bool,
    pub offset: usize,
    pub limit: usize,
    pub decoded_instructions: usize,
    /// Successful decoded bytes, including repeated boundaries in overlapping discovered blocks.
    pub decoded_bytes: u64,
    /// Charged decoder input windows, including overfetch and rejected attempts; overlaps count again.
    pub inspected_code_bytes: u64,
    /// Other charged source inspection: pointer/string bytes and code-window bytes not in `decoded_bytes`.
    /// Thus `decoded_bytes + source_bytes` is the total charged byte inspection, without double counting.
    pub source_bytes: u64,
    pub examined_references: u64,
    /// Bounded preparation entries/name comparisons, conservative ordered-index costs, decoder
    /// windows/probes, and string inspection. Preparation retains at most one million entries.
    pub match_work: u64,
    pub cancelled: bool,
    pub stop_reason: SearchStopReason,
    pub scan_complete: bool,
    pub hit_cap_reached: bool,
    pub limitations: Vec<String>,
}

impl Project {
    pub fn search_code(&self, query: &CodeSearchQuery) -> Result<CodeSearchReport, ApiError> {
        self.search_code_controlled(query, &SearchControl::default())
    }

    pub fn search_code_controlled(
        &self,
        query: &CodeSearchQuery,
        control: &SearchControl<'_>,
    ) -> Result<CodeSearchReport, ApiError> {
        crate::search::bytes_source_check(&self.binary)?;
        if control.cancelled() {
            return Ok(cancelled_report(query, "Cancelled before native analysis initialization."));
        }
        let analysis = self.analysis()?;
        // Analysis initialization is not interruptible; preparation below must not inherit that exception.
        if control.cancelled() {
            return Ok(cancelled_report(query, "Cancelled immediately after native analysis initialization."));
        }
        let report = search_program(self, &analysis.program, &analysis.xrefs_by_source, query, control)?;
        crate::search::bytes_source_check(&self.binary)?;
        Ok(report)
    }
}

fn cancelled_report(query: &CodeSearchQuery, limitation: &str) -> CodeSearchReport {
    CodeSearchReport {
        hits: vec![],
        total: 0,
        total_is_lower_bound: true,
        offset: query.offset,
        limit: query.limit,
        decoded_instructions: 0,
        decoded_bytes: 0,
        inspected_code_bytes: 0,
        source_bytes: 0,
        examined_references: 0,
        match_work: 0,
        cancelled: true,
        stop_reason: SearchStopReason::Cancelled,
        scan_complete: false,
        hit_cap_reached: false,
        limitations: vec![limitation.into()],
    }
}

fn search_program(
    project: &Project,
    program: &Program,
    xrefs_by_source: &[usize],
    query: &CodeSearchQuery,
    control: &SearchControl<'_>,
) -> Result<CodeSearchReport, ApiError> {
    if control.cancelled() {
        return Ok(cancelled_report(query, "Cancelled before metadata preparation."));
    }
    let mut hits: BTreeMap<u64, CodeSearchHit> = BTreeMap::new();
    let mut decoded = 0;
    let mut decoded_bytes = 0u64;
    let mut inspected_code_bytes = 0u64;
    let mut work = 0u64;
    let mut incomplete = control.cancelled();
    let mut stop_reason = if incomplete { SearchStopReason::Cancelled } else { SearchStopReason::Complete };
    let mut hit_cap = false;
    let mut invalid_blocks = 0;
    let mut unsupported_operands = 0;
    let mut unresolved_flows = 0;
    let mut source_bytes = 0;
    let mut source_truncated = false;
    let mut source_cache = BTreeMap::new();
    let mut references_read = 0;
    let prepared = prepare_search(project, program, xrefs_by_source, query, control, &mut work, &mut references_read);
    let (blocks, import_targets) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => {
            incomplete = true;
            stop_reason = reason;
            (BTreeMap::new(), BTreeSet::new())
        }
    };
    if !incomplete {
        // The decoder copies the retained mode map. Charge its bounded construction before entering it.
        let mode_work = (program.code_modes.len() as u64)
            .saturating_mul(tree_work(program.code_modes.len()))
            .saturating_add(project.binary.thumb.len() as u64);
        if let Err(reason) = charge_work(query, control, &mut work, mode_work) {
            incomplete = true;
            stop_reason = reason;
        }
    }
    let mut decoder = if incomplete { None } else { Some(project.binary.decoder()?) };
    if let Some(decoder) = &mut decoder {
        decoder.set_code_modes(&program.code_modes);
    }
    let annotations = project.annotations();
    let reference_mode = matches!(&query.kind, CodeSearchKind::FunctionsReferencing(_));
    'blocks: for (_, (block, function)) in blocks {
        if incomplete {
            break;
        }
        if control.cancelled() {
            incomplete = true;
            stop_reason = SearchStopReason::Cancelled;
            break;
        }
        let decoder = decoder.as_mut().expect("successful preparation initialized the decoder");
        if let Err(reason) = charge_work(query, control, &mut work, project.binary.segments.len() as u64) {
            incomplete = true;
            stop_reason = reason;
            break;
        }
        let Some(bytes) = block.end.checked_sub(block.start).and_then(|size| project.binary.read(block.start, size))
        else {
            invalid_blocks += 1;
            continue;
        };
        decoder.begin_run();
        let mut offset = 0;
        while offset < bytes.len() {
            if control.cancelled() {
                incomplete = true;
                stop_reason = SearchStopReason::Cancelled;
                break 'blocks;
            }
            let address = block.start + offset as u64;
            if query.range.as_ref().is_some_and(|range| address >= range.end) {
                break;
            }
            if decoded == query.max_instructions {
                incomplete = true;
                stop_reason = SearchStopReason::InstructionBudget;
                break 'blocks;
            }
            if decoded_bytes + source_bytes as u64 == query.max_bytes || work == query.max_work {
                incomplete = true;
                stop_reason = if work == query.max_work {
                    SearchStopReason::MatchWorkBudget
                } else {
                    SearchStopReason::ScanByteBudget
                };
                break 'blocks;
            }
            // Decoders may inspect beyond the eventual instruction length. Never expose an uncharged tail.
            let window = match project.binary.arch {
                rampage_arch::Arch::X86 | rampage_arch::Arch::X86_64 => 15,
                rampage_arch::Arch::Arm | rampage_arch::Arch::Aarch64 => 4,
                _ => 32,
            };
            let window = window.min(bytes.len() - offset);
            if window as u64 > query.max_bytes - decoded_bytes - source_bytes as u64 {
                incomplete = true;
                stop_reason = SearchStopReason::ScanByteBudget;
                break 'blocks;
            }
            if let Err(reason) = charge_work(query, control, &mut work, 1 + window as u64) {
                incomplete = true;
                stop_reason = reason;
                break 'blocks;
            }
            source_bytes += window;
            inspected_code_bytes += window as u64;
            let mut decode_bytes = &bytes[offset..offset + window];
            let semantic_limit =
                match semantic_lookahead(project, decoder.as_ref(), decode_bytes, address, query, control, &mut work) {
                    Ok(limit) => limit,
                    Err(reason) => {
                        incomplete = true;
                        stop_reason = reason;
                        break 'blocks;
                    }
                };
            if let Some(limit) = semantic_limit.filter(|&limit| limit > window) {
                // Production get-PC classification reads following instructions, potentially past this
                // discovered block. code_from stops at the original code range/file-backed segment end.
                let metadata_work = (project.binary.segments.len() as u64).saturating_mul(2)
                    + tree_work(project.binary.sections.len().saturating_add(project.binary.segments.len()));
                if let Err(reason) = charge_work(query, control, &mut work, metadata_work) {
                    incomplete = true;
                    stop_reason = reason;
                    break 'blocks;
                }
                let Some(available) = project.binary.code_from(address) else {
                    incomplete = true;
                    stop_reason = SearchStopReason::IncompleteEvidence;
                    break 'blocks;
                };
                let expanded = available.len().min(limit);
                if expanded < window {
                    incomplete = true;
                    stop_reason = SearchStopReason::IncompleteEvidence;
                    break 'blocks;
                }
                let extra = expanded - window;
                if extra as u64 > query.max_bytes - decoded_bytes - source_bytes as u64 {
                    incomplete = true;
                    stop_reason = SearchStopReason::ScanByteBudget;
                    break 'blocks;
                }
                if let Err(reason) = charge_work(query, control, &mut work, extra as u64) {
                    incomplete = true;
                    stop_reason = reason;
                    break 'blocks;
                }
                source_bytes += extra;
                inspected_code_bytes += extra as u64;
                decode_bytes = &available[..expanded];
            }
            let pointer_state =
                RefCell::new(PointerInspection { source_bytes, work, stop: None, cache: BTreeMap::new() });
            let mut instruction = decoder.decode_with_memory(decode_bytes, address, &|at, size| {
                pointer_state.borrow_mut().read(project, query, control, decoded_bytes, at, size)
            });
            let pointer_state = pointer_state.into_inner();
            source_bytes = pointer_state.source_bytes;
            work = pointer_state.work;
            decoded += 1;
            if let Some(reason) = pointer_state.stop {
                incomplete = true;
                stop_reason = reason;
                break 'blocks;
            }
            let size = usize::from(instruction.len);
            if size == 0
                || size > decode_bytes.len()
                || size > bytes.len() - offset
                || instruction.flow == Flow::Invalid
            {
                invalid_blocks += 1;
                break;
            }
            source_bytes -= size;
            decoded_bytes += size as u64;
            let native = &bytes[offset..offset + size];
            offset += size;
            if let Err(reason) = charge_work(query, control, &mut work, tree_work(program.resolved_flows.len())) {
                incomplete = true;
                stop_reason = reason;
                break 'blocks;
            }
            if let Ok(index) = program
                .resolved_flows
                .binary_search_by_key(&(function, address), |resolved| (resolved.function, resolved.address))
            {
                instruction.flow = program.resolved_flows[index].flow;
            }
            if matches!(instruction.flow, Flow::IndirectCall | Flow::IndirectJump) {
                unresolved_flows += 1;
            }
            if query.range.as_ref().is_some_and(|range| !range.contains(&address)) {
                continue;
            }
            let text = decoder.format(native, address);
            let evidence = match &query.kind {
                CodeSearchKind::Immediate(value)
                | CodeSearchKind::FunctionsReferencing(CodeReference::Constant(value)) => {
                    let operands = decoder.operands(native, address);
                    if operands.is_none()
                        || operands
                            .as_ref()
                            .is_some_and(|items| items.iter().any(|operand| operand.kind == OperandKind::Unsupported))
                    {
                        unsupported_operands += 1;
                    }
                    immediate_evidence(value, &instruction, operands.as_deref(), project.binary.arch.pointer_size())
                }
                CodeSearchKind::Instruction { mnemonic, operands } => {
                    let (actual_mnemonic, actual_operands) = assembly_fields(&text);
                    (mnemonic.matches(actual_mnemonic)
                        && operands.as_ref().is_none_or(|pattern| pattern.matches(actual_operands)))
                    .then(|| evidence("instruction_pattern", None, None))
                }
                CodeSearchKind::FunctionsReferencing(reference) => {
                    if import_targets.contains(&function) {
                        continue;
                    }
                    if let Err(reason) = charge_work(query, control, &mut work, tree_work(xrefs_by_source.len())) {
                        incomplete = true;
                        stop_reason = reason;
                        break 'blocks;
                    }
                    let start = xrefs_by_source.partition_point(|&index| program.xrefs[index].from < address);
                    let mut matched = None;
                    for &index in &xrefs_by_source[start..] {
                        let xref = &program.xrefs[index];
                        if xref.from != address {
                            break;
                        }
                        if references_read == MAX_INSTRUCTIONS {
                            incomplete = true;
                            stop_reason = SearchStopReason::MatchWorkBudget;
                            break 'blocks;
                        }
                        if control.cancelled() || work == query.max_work {
                            incomplete = true;
                            stop_reason = if control.cancelled() {
                                SearchStopReason::Cancelled
                            } else {
                                SearchStopReason::MatchWorkBudget
                            };
                            break 'blocks;
                        }
                        references_read += 1;
                        work += 1;
                        match reference {
                            CodeReference::Address(target) if xref.to == *target => {
                                matched = Some(evidence("address_xref", Some(xref.to), None));
                            }
                            CodeReference::Import { .. } if import_targets.contains(&xref.to) => {
                                matched = Some(evidence("import_xref", Some(xref.to), None));
                            }
                            CodeReference::String(source) if xref.kind == XrefKind::Data => {
                                let matches = if let Some(&matched) = source_cache.get(&xref.to) {
                                    matched
                                } else {
                                    if source_bytes >= MAX_SOURCE_BYTES || source_cache.len() == MAX_HITS {
                                        incomplete = true;
                                        stop_reason = SearchStopReason::MatchWorkBudget;
                                        break 'blocks;
                                    }
                                    let before = source_bytes;
                                    if let Err(reason) = charge_work(
                                        query,
                                        control,
                                        &mut work,
                                        (project.binary.segments.len() as u64).saturating_mul(2),
                                    ) {
                                        incomplete = true;
                                        stop_reason = reason;
                                        break 'blocks;
                                    }
                                    let remaining = (query.max_work - work)
                                        .min(query.max_bytes - decoded_bytes - source_bytes as u64)
                                        as usize;
                                    if remaining == 0 {
                                        incomplete = true;
                                        stop_reason = if work == query.max_work {
                                            SearchStopReason::MatchWorkBudget
                                        } else {
                                            SearchStopReason::ScanByteBudget
                                        };
                                        break 'blocks;
                                    }
                                    let matched = source_matches(
                                        project,
                                        xref.to,
                                        source,
                                        &mut source_bytes,
                                        &mut source_truncated,
                                        remaining,
                                    );
                                    work += (source_bytes - before) as u64;
                                    source_cache.insert(xref.to, matched);
                                    matched
                                };
                                if matches {
                                    let mut found = evidence("string_xref", Some(xref.to), None);
                                    found.source_encoding = Some(source.encoding);
                                    matched = Some(found);
                                }
                            }
                            _ => {}
                        }
                        if matched.is_some() {
                            break;
                        }
                    }
                    matched
                }
            };
            let Some(evidence) = evidence else { continue };
            let key = if reference_mode { function } else { address };
            if let Some(previous) = hits.get(&key)
                && (previous.site, previous.function) <= (address, function)
            {
                continue;
            }
            if !hits.contains_key(&key) && hits.len() == query.max_hits {
                hit_cap = true;
                if hits.last_key_value().is_some_and(|(&last, _)| key > last) {
                    continue;
                }
                hits.pop_last();
            }
            let mut function_name = project.function_name_in(&annotations, function);
            let function_name_truncated = truncate_text(&mut function_name, 512);
            let mut text = text;
            let text_truncated = truncate_text(&mut text, MAX_TEXT);
            hits.insert(
                key,
                CodeSearchHit {
                    address: key,
                    site: address,
                    function,
                    function_name,
                    function_name_truncated,
                    bytes: rampage_arch::hex::bytes(native),
                    text,
                    text_truncated,
                    flow: instruction.flow,
                    evidence,
                },
            );
        }
    }
    let scan_complete = !incomplete && invalid_blocks == 0;
    let mut limitations = vec![
        "Only production-discovered blocks and retained xrefs are searched; undiscovered code, unresolved indirect \
         references, and runtime-generated/decoded strings are not covered. No target code is executed."
            .into(),
    ];
    if incomplete {
        limitations.push(
            "Cancelled or bounded preparation, decoder inspection, reference, or source-byte work stopped; \
             totals are lower bounds. Decoder input windows are charged before decoding; cached pointer \
             probes charge work, but charge immutable pointer bytes only once per instruction."
                .into(),
        );
    }
    if hit_cap {
        limitations.push("Hit retention capped; the smallest observed address keys are retained before paging.".into());
    }
    if invalid_blocks != 0 {
        limitations.push(format!("{invalid_blocks} blocks were unbacked or failed complete-instruction decoding."));
    }
    if unsupported_operands != 0 {
        limitations.push(format!(
            "{unsupported_operands} instructions had absent/partial native operand evidence; their unsupported \
             operands were not guessed from text."
        ));
    }
    if unresolved_flows != 0 {
        limitations.push(format!("{unresolved_flows} decoded indirect transfers lacked retained resolved flows."));
    }
    if source_truncated {
        limitations
            .push("Source strings exceeded the bounded preview; only valid decoded prefixes were tested.".into());
    }
    if matches!(&query.kind, CodeSearchKind::FunctionsReferencing(CodeReference::Import { .. })) {
        limitations.push(
            "Import users follow retained slot xrefs and named, slot-linked stubs only; unnamed forwarding \
             functions and forwarding chains are not inferred."
                .into(),
        );
    }
    let missing_import_identity =
        matches!(&query.kind, CodeSearchKind::FunctionsReferencing(CodeReference::Import { .. }))
            && import_targets.is_empty();
    if missing_import_identity {
        limitations.push(
            "No matching retained import slot identity was available; same-named symbols alone are not imports.".into(),
        );
    }
    let total_is_lower_bound =
        !scan_complete || hit_cap || unsupported_operands != 0 || source_truncated || missing_import_identity;
    let total = hits.len() + usize::from(hit_cap);
    if stop_reason == SearchStopReason::Complete && total_is_lower_bound {
        stop_reason = if hit_cap { SearchStopReason::ResultCap } else { SearchStopReason::IncompleteEvidence };
    }
    Ok(CodeSearchReport {
        hits: hits.into_values().skip(query.offset).take(query.limit).collect(),
        total,
        total_is_lower_bound,
        offset: query.offset,
        limit: query.limit,
        decoded_instructions: decoded,
        decoded_bytes,
        inspected_code_bytes,
        source_bytes: source_bytes as u64,
        examined_references: references_read as u64,
        match_work: work,
        cancelled: stop_reason == SearchStopReason::Cancelled,
        stop_reason,
        scan_complete,
        hit_cap_reached: hit_cap,
        limitations,
    })
}

fn immediate_evidence(
    query: &CodeImmediate,
    instruction: &Insn,
    operands: Option<&[OperandEvidence]>,
    pointer_size: u8,
) -> Option<CodeSearchEvidence> {
    for operand in operands.unwrap_or_default() {
        if operand.kind == OperandKind::Immediate
            && (operand.memory.is_none() || query.include_addresses)
            && query.matches(operand.immediate, operand.signed_value, operand.width_bits)
        {
            return Some(evidence("immediate", None, Some(operand.clone())));
        }
        if query.include_displacements
            && let Some(memory) = &operand.memory
            && (memory.access_size.is_some() || query.include_addresses)
            && ((!memory.relative && memory.base.is_some()) || query.include_addresses)
            && query.matches(u64::try_from(memory.displacement).ok(), Some(memory.displacement), None)
        {
            return Some(evidence("displacement", None, Some(operand.clone())));
        }
    }
    if query.include_addresses {
        let branch = match instruction.flow {
            Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target) => Some(target),
            _ => None,
        };
        for target in branch.into_iter().chain(instruction.data_ref) {
            if query.matches(Some(target), i64::try_from(target).ok(), Some(u16::from(pointer_size) * 8)) {
                return Some(evidence("address", Some(target), None));
            }
        }
    }
    None
}

type PreparedBlocks<'a> = BTreeMap<(u64, u64, u64, usize), (&'a Block, u64)>;

/// Preparation is all-or-nothing: a partial inventory cannot establish the global address order.
/// Entries and conservative tree-comparison work are charged before retention; there is no unbounded sort.
fn prepare_search<'a>(
    project: &Project,
    program: &'a Program,
    xrefs_by_source: &[usize],
    query: &CodeSearchQuery,
    control: &SearchControl<'_>,
    work: &mut u64,
    references: &mut usize,
) -> Result<(PreparedBlocks<'a>, BTreeSet<u64>), SearchStopReason> {
    charge_work(query, control, work, 0)?;
    let targets = match &query.kind {
        CodeSearchKind::FunctionsReferencing(CodeReference::Import { name, library }) => import_targets(
            project,
            program,
            xrefs_by_source,
            name,
            library.as_deref(),
            query,
            control,
            work,
            references,
        )?,
        _ => BTreeSet::new(),
    };
    let mut blocks = BTreeMap::new();
    let mut entries = 0;
    for function in &program.functions {
        charge_work(query, control, work, 1)?;
        entries += 1;
        if entries > MAX_INSTRUCTIONS {
            return Err(SearchStopReason::MatchWorkBudget);
        }
        for (index, block) in function.blocks.iter().enumerate() {
            charge_work(query, control, work, 1)?;
            entries += 1;
            if entries > MAX_INSTRUCTIONS {
                return Err(SearchStopReason::MatchWorkBudget);
            }
            if query.range.as_ref().is_some_and(|range| block.start >= range.end || range.start >= block.end) {
                continue;
            }
            charge_work(query, control, work, tree_work(blocks.len()))?;
            blocks.insert((block.start, block.end, function.address, index), (block, function.address));
        }
    }
    Ok((blocks, targets))
}

fn tree_work(entries: usize) -> u64 {
    // Reserve for a full linear search of each B-tree node as well as its height.
    (u64::from(usize::BITS - entries.leading_zeros()) + 1) * 12
}

/// Only get-PC candidates need semantic context beyond the ordinary instruction window. All bytes
/// passed here have already been charged. Link-register decoders probe four following instructions;
/// x86 probes one following instruction. Preview decoders are independent, never the live run's state.
fn semantic_lookahead(
    project: &Project,
    decoder: &dyn rampage_arch::Disassembler,
    bytes: &[u8],
    address: u64,
    query: &CodeSearchQuery,
    control: &SearchControl<'_>,
    work: &mut u64,
) -> Result<Option<usize>, SearchStopReason> {
    let arch = project.binary.arch;
    match arch {
        rampage_arch::Arch::Aarch64 => Ok(bytes.starts_with(&[0x01, 0x00, 0x00, 0x94]).then_some(20)),
        rampage_arch::Arch::Arm => {
            charge_work(query, control, work, tree_work(project.binary.thumb.len()) + tree_work(MAX_INSTRUCTIONS))?;
            let Some(word) = bytes.first_chunk::<4>() else { return Ok(None) };
            let candidate = match decoder.code_mode_at(address) {
                Some(true) => *word == [0x00, 0xf0, 0x00, 0xf8] || *word == [0xf0, 0x00, 0xf8, 0x00],
                // Admit both instruction byte orders conservatively (BE8 differs from data order).
                // The live decoder, with its retained target, alone decides the instruction's meaning.
                Some(false) => [u32::from_le_bytes(*word), u32::from_be_bytes(*word)]
                    .into_iter()
                    .any(|word| word & 0x0fff_ffff == 0x0bff_ffff && word >> 28 != 0xf),
                None => return Err(SearchStopReason::IncompleteEvidence),
            };
            Ok(candidate.then_some(20))
        }
        rampage_arch::Arch::X86 | rampage_arch::Arch::X86_64 => {
            let opcode = bytes.iter().copied().find(|byte| {
                !matches!(byte, 0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67)
                    && !(arch == rampage_arch::Arch::X86_64 && (0x40..=0x4f).contains(byte))
            });
            if opcode != Some(0xe8) {
                return Ok(None);
            }
            charge_work(query, control, work, bytes.len() as u64)?;
            let mut preview = rampage_arch::decoder_for(arch).expect("x86 has a native decoder");
            let instruction = preview.decode(bytes, address);
            Ok((instruction.flow == Flow::Call(address.wrapping_add(u64::from(instruction.len))))
                .then_some(usize::from(instruction.len) + 15))
        }
        rampage_arch::Arch::Mips
        | rampage_arch::Arch::Mips64
        | rampage_arch::Arch::PowerPc
        | rampage_arch::Arch::PowerPc64
        | rampage_arch::Arch::Sparc
        | rampage_arch::Arch::Sparc64 => {
            charge_work(query, control, work, bytes.len() as u64 + project.binary.thumb.len() as u64)?;
            let mut preview = project.binary.decoder().map_err(|_| SearchStopReason::IncompleteEvidence)?;
            let instruction = preview.decode(bytes, address);
            let next = address.wrapping_add(u64::from(instruction.len) * (1 + u64::from(arch.delay_slots())));
            Ok((instruction.flow == Flow::Call(next)).then_some(usize::from(instruction.len) + 16))
        }
        _ => Ok(None),
    }
}

fn charge_work(
    query: &CodeSearchQuery,
    control: &SearchControl<'_>,
    work: &mut u64,
    amount: u64,
) -> Result<(), SearchStopReason> {
    if control.cancelled() {
        return Err(SearchStopReason::Cancelled);
    }
    if amount > query.max_work - *work {
        return Err(SearchStopReason::MatchWorkBudget);
    }
    *work += amount;
    Ok(())
}

struct PointerInspection {
    source_bytes: usize,
    work: u64,
    stop: Option<SearchStopReason>,
    // Decoder-local caching only: repeated probes of the same slot/width in this one instruction
    // reuse immutable source evidence. Every probe still incurs its own work charge.
    cache: BTreeMap<(u64, u8), Option<u64>>,
}

impl PointerInspection {
    fn read(
        &mut self,
        project: &Project,
        query: &CodeSearchQuery,
        control: &SearchControl<'_>,
        decoded_bytes: u64,
        address: u64,
        size: u8,
    ) -> Option<u64> {
        if self.stop.is_some() {
            return None;
        }
        if let Err(reason) = charge_work(query, control, &mut self.work, 1) {
            self.stop = Some(reason);
            return None;
        }
        if let Some(value) = self.cache.get(&(address, size)) {
            return *value;
        }
        if !matches!(size, 4 | 8) {
            return None;
        }
        // Binary's permission/backing/pointer methods each use a linear segment lookup. Reserve
        // their conservative metadata cost before entering any of those noninterruptible lookups.
        let metadata_work = (project.binary.segments.len() as u64).saturating_mul(4);
        if let Err(reason) = charge_work(query, control, &mut self.work, metadata_work) {
            self.stop = Some(reason);
            return None;
        }
        let eligible = project.binary.segment_containing(address).is_some_and(|segment| {
            segment.perms.read && !segment.perms.write && project.binary.read(address, u64::from(size)).is_some()
        });
        if !eligible {
            self.cache.insert((address, size), None);
            return None;
        }
        if u64::from(size) > query.max_bytes - decoded_bytes - self.source_bytes as u64 {
            self.stop = Some(SearchStopReason::ScanByteBudget);
            return None;
        }
        if let Err(reason) = charge_work(query, control, &mut self.work, u64::from(size)) {
            self.stop = Some(reason);
            return None;
        }
        self.source_bytes += usize::from(size);
        let value = project.binary.read_pointer(address, size);
        self.cache.insert((address, size), value);
        value
    }
}

#[allow(clippy::too_many_arguments)]
fn import_targets(
    project: &Project,
    program: &Program,
    xrefs_by_source: &[usize],
    name: &str,
    library: Option<&str>,
    query: &CodeSearchQuery,
    control: &SearchControl<'_>,
    work: &mut u64,
    references: &mut usize,
) -> Result<BTreeSet<u64>, SearchStopReason> {
    let mut slots = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for slot in &project.binary.import_slots {
        let comparisons = 1 + slot.name.len() as u64 + slot.library.as_ref().map_or(0, |name| name.len() as u64);
        charge_work(query, control, work, comparisons)?;
        if slot.name == name && library.is_none_or(|wanted| slot.library.as_deref() == Some(wanted)) {
            if slots.len() == MAX_HITS {
                return Err(SearchStopReason::MatchWorkBudget);
            }
            charge_work(query, control, work, tree_work(slots.len()) * 2)?;
            slots.insert(slot.address);
            targets.insert(slot.address);
        }
    }
    for (address, retained_name) in project.inventory_loader_names() {
        charge_work(query, control, work, 1 + retained_name.len() as u64)?;
        if retained_name != name && retained_name.strip_suffix("@plt") != Some(name) {
            continue;
        }
        charge_work(query, control, work, tree_work(program.functions.len()))?;
        let Some(function) = program.function_at(address) else { continue };
        // A same-named symbol alone is not a library-qualified import identity. Link its body to a slot.
        let mut linked = false;
        for block in &function.blocks {
            charge_work(query, control, work, 1 + tree_work(xrefs_by_source.len()))?;
            let start = xrefs_by_source.partition_point(|&index| program.xrefs[index].from < block.start);
            for &index in &xrefs_by_source[start..] {
                charge_work(query, control, work, 1 + tree_work(slots.len()))?;
                if *references == MAX_INSTRUCTIONS {
                    return Err(SearchStopReason::MatchWorkBudget);
                }
                *references += 1;
                let xref = &program.xrefs[index];
                if xref.from >= block.end {
                    break;
                }
                if slots.contains(&xref.to) {
                    linked = true;
                    break;
                }
            }
            if linked {
                break;
            }
        }
        if linked {
            charge_work(query, control, work, tree_work(targets.len()))?;
            targets.insert(address);
        }
    }
    Ok(targets)
}

fn source_matches(
    project: &Project,
    address: u64,
    query: &SourceString,
    inspected: &mut usize,
    truncated: &mut bool,
    work_remaining: usize,
) -> bool {
    let Some(bytes) = project.binary.read_to_segment_end(address) else { return false };
    let limit = bytes.len().min(MAX_SOURCE_STRING).min(MAX_SOURCE_BYTES - *inspected).min(work_remaining);
    *truncated |= limit < bytes.len() && limit < MAX_SOURCE_STRING;
    let bytes = &bytes[..limit];
    match query.encoding {
        SourceStringEncoding::Utf8 => {
            let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
            *inspected += end + usize::from(end < bytes.len());
            *truncated |= end == bytes.len() && limit == MAX_SOURCE_STRING;
            // A bound may cut a UTF-8 scalar. Its complete prefix remains valid source evidence.
            let text = match std::str::from_utf8(&bytes[..end]) {
                Ok(text) => text,
                Err(error) if error.error_len().is_none() && end == bytes.len() => {
                    *truncated = true;
                    std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or_default()
                }
                Err(_) => return false,
            };
            text.contains(&query.text)
        }
        SourceStringEncoding::Utf16Le | SourceStringEncoding::Utf16Be => {
            let mut words = Vec::new();
            let mut terminated = false;
            for pair in bytes.as_chunks::<2>().0 {
                *inspected += 2;
                let pair = [pair[0], pair[1]];
                let word = match query.encoding {
                    SourceStringEncoding::Utf16Be => u16::from_be_bytes(pair),
                    _ => u16::from_le_bytes(pair),
                };
                if word == 0 {
                    terminated = true;
                    break;
                }
                words.push(word);
            }
            if !terminated {
                *truncated |= limit == MAX_SOURCE_STRING || !bytes.len().is_multiple_of(2);
                if words.last().is_some_and(|word| (0xd800..=0xdbff).contains(word)) {
                    words.pop();
                    *truncated = true;
                }
            }
            String::from_utf16(&words).is_ok_and(|text| text.contains(&query.text))
        }
    }
}

fn assembly_fields(text: &str) -> (&str, &str) {
    let mut rest = text.trim();
    loop {
        let (mnemonic, operands) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if ["lock", "rep", "repe", "repne", "repz", "repnz", "bnd", "xacquire", "xrelease", "notrack"]
            .iter()
            .any(|prefix| mnemonic.eq_ignore_ascii_case(prefix))
        {
            rest = operands.trim_start();
        } else {
            return (mnemonic, operands.trim());
        }
    }
}

fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

fn truncate_text(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

fn evidence(kind: &'static str, target: Option<u64>, operand: Option<OperandEvidence>) -> CodeSearchEvidence {
    CodeSearchEvidence { kind, target, operand, source_encoding: None }
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

#[cfg(test)]
mod tests {
    use rampage_analysis::discover::{Block, DiscoveredFunction, ResolvedFlow};
    use rampage_loaders::{Binary, Import, ImportSlot, Symbol, SymbolKind};

    use super::*;

    fn snapshot(arch: &str, regions: &[(u64, &str, &str)], seeds: &[u64]) -> Binary {
        snapshot_endian(arch, regions, seeds, false)
    }

    fn snapshot_endian(arch: &str, regions: &[(u64, &str, &str)], seeds: &[u64], big_endian: bool) -> Binary {
        let regions: Vec<_> = regions
            .iter()
            .map(|(address, permissions, bytes)| {
                serde_json::json!({
                    "name": format!("owned-{address:x}"), "address": format!("{address:#x}"),
                    "permissions": permissions, "bytes": bytes,
                })
            })
            .collect();
        Binary::from_snapshot_bytes(
            serde_json::to_vec(&serde_json::json!({
                "format": "rampage-snapshot-v1", "arch": arch,
                "big_endian": big_endian,
                "provenance": "Owned instruction-search test bytes; never executed",
                "regions": regions,
                "entry": seeds.first().map(|address| format!("{address:#x}")),
                "seeds": seeds.iter().map(|address| format!("{address:#x}")).collect::<Vec<_>>(),
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn constant(value: CodeValue) -> CodeImmediate {
        CodeImmediate { value, width_bits: None, include_displacements: false, include_addresses: false }
    }

    fn immediate(value: CodeImmediate) -> CodeSearchQuery {
        CodeSearchQuery::new(CodeSearchKind::Immediate(value)).unwrap()
    }

    fn sites(report: &CodeSearchReport) -> Vec<u64> {
        report.hits.iter().map(|hit| hit.site).collect()
    }

    fn constants() -> Project {
        Project::new(snapshot(
            "x86_64",
            &[
                // The jump skips a MOV-shaped data gap. MOV/CMP immediates are not load/LEA displacements.
                (0x1000, "r-x", "b82a00000083f82a8b432a488d432aeb05b82a000000b8ffffffffc3"),
                (0x2000, "r-x", "b82a000000c3"),
                (0x3000, "r--", "b82a000000c3"),
            ],
            &[0x1000, 0x2000],
        ))
    }

    #[test]
    fn immediate_search_uses_structured_operands_and_never_sweeps_gaps_or_data() {
        let project = constants();
        let query = immediate(constant(CodeValue::Unsigned(42)));
        let report = project.search_code(&query).unwrap();
        assert_eq!(sites(&report), [0x1000, 0x1005, 0x2000]);
        assert!(report.hits.iter().all(|hit| hit.evidence.kind == "immediate"));
        assert_eq!(report.hits[1].evidence.operand.as_ref().unwrap().width_bits, Some(32));

        let mut value = constant(CodeValue::Unsigned(42));
        value.include_displacements = true;
        assert_eq!(sites(&project.search_code(&immediate(value.clone())).unwrap()), [0x1000, 0x1005, 0x1008, 0x2000]);
        value.include_addresses = true;
        assert_eq!(sites(&project.search_code(&immediate(value)).unwrap()), [0x1000, 0x1005, 0x1008, 0x100b, 0x2000]);
    }

    #[test]
    fn semantic_sign_and_width_are_not_encoded_immediate_width() {
        let project = constants();
        let mut value = constant(CodeValue::Signed(-1));
        value.width_bits = Some(32);
        let report = project.search_code(&immediate(value.clone())).unwrap();
        assert_eq!(sites(&report), [0x1016]);
        assert_eq!(report.hits[0].evidence.operand.as_ref().unwrap().immediate, Some(0xffff_ffff));
        value.width_bits = Some(64);
        assert!(project.search_code(&immediate(value)).unwrap().hits.is_empty());
        let mut value = constant(CodeValue::Unsigned(42));
        value.width_bits = Some(8);
        assert!(project.search_code(&immediate(value)).unwrap().hits.is_empty());
    }

    #[test]
    fn ranges_filter_real_instruction_starts_and_branch_addresses_are_opt_in() {
        let project = constants();
        let query = immediate(constant(CodeValue::Unsigned(42))).with_range(Some(0x1001..0x1008)).unwrap();
        assert_eq!(sites(&project.search_code(&query).unwrap()), [0x1005]);
        let mut value = constant(CodeValue::Unsigned(0x1016));
        assert!(project.search_code(&immediate(value.clone())).unwrap().hits.is_empty());
        value.include_addresses = true;
        let report = project.search_code(&immediate(value)).unwrap();
        assert_eq!(sites(&report), [0x100f]);
        assert_eq!(report.hits[0].evidence.kind, "address");
    }

    #[test]
    fn mnemonic_and_operand_patterns_match_separate_native_rendered_fields() {
        let project = constants();
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("m?v").unwrap(),
            operands: Some(CodePattern::new("EAX, *").unwrap()),
        })
        .unwrap();
        assert_eq!(sites(&project.search_code(&query).unwrap()), [0x1000, 0x1008, 0x1016, 0x2000]);
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("eax").unwrap(),
            operands: None,
        })
        .unwrap();
        assert!(project.search_code(&query).unwrap().hits.is_empty());
        assert!(CodePattern::new("*[rax*]").unwrap().matches("qword ptr [rax*4]"));
        assert!(!CodePattern::new("mov").unwrap().matches("cmov"));
        assert_eq!(assembly_fields("lock add dword ptr [rax],1"), ("add", "dword ptr [rax],1"));
    }

    #[test]
    fn reference_constants_deduplicate_functions_before_global_paging() {
        let project = constants();
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Constant(constant(
            CodeValue::Unsigned(42),
        ))))
        .unwrap()
        .with_page(1, 1)
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.hits.len(), 1);
        assert_eq!((report.hits[0].address, report.hits[0].site, report.hits[0].function), (0x2000, 0x2000, 0x2000));
        let capped = project.search_code(&query.with_bounds(100, 1).unwrap()).unwrap();
        assert!(capped.hits.is_empty());
        assert!(capped.hit_cap_reached && capped.total_is_lower_bound);
        assert_eq!(capped.total, 2);
    }

    #[test]
    fn unicode_source_string_xrefs_preserve_encoding_site_and_source_name() {
        let text = "Hello 世界 🦀";
        for encoding in [SourceStringEncoding::Utf8, SourceStringEncoding::Utf16Le, SourceStringEncoding::Utf16Be] {
            let bytes: Vec<u8> = match encoding {
                SourceStringEncoding::Utf8 => text.bytes().chain([0]).collect(),
                SourceStringEncoding::Utf16Le => text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect(),
                SourceStringEncoding::Utf16Be => text.encode_utf16().chain([0]).flat_map(u16::to_be_bytes).collect(),
            };
            let hex = rampage_arch::hex::bytes(&bytes);
            let mut binary = snapshot(
                "x86_64",
                &[
                    (0x1000, "r-x", "488d05f91f0000488d0df21f0000c3"),
                    (0x2000, "r-x", "488d05f90f0000c3"),
                    (0x3000, "r--", &hex),
                ],
                &[0x1000, 0x2000],
            );
            binary.symbols.push(Symbol {
                name: "source_function".into(),
                address: 0x1000,
                size: 15,
                kind: SymbolKind::Function,
            });
            let project = Project::new(binary);
            let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::String(
                SourceString::new("世界 🦀", encoding).unwrap(),
            )))
            .unwrap();
            let report = project.search_code(&query).unwrap();
            assert_eq!(report.total, 2, "{report:?}");
            assert_eq!(sites(&report), [0x1000, 0x2000]);
            assert_eq!(report.hits[0].function_name, "source_function");
            assert_eq!(report.hits[0].evidence.target, Some(0x3000));
            assert_eq!(report.hits[0].evidence.kind, "string_xref");
            let page = project.search_code(&query.with_page(1, 1).unwrap()).unwrap();
            assert_eq!(sites(&page), [0x2000]);
        }
    }

    #[test]
    fn import_references_follow_slot_linked_stubs_and_keep_library_identity() {
        let mut binary = snapshot(
            "x86_64",
            &[
                (0x1000, "r-x", "e8fb0f0000c3"),
                (0x2000, "r-x", "ff25fa0f0000"),
                (0x3000, "rw-", "00000000000000000000000000000000"),
                (0x4000, "r-x", "ff1502f0ffffc3"),
            ],
            &[0x1000, 0x4000],
        );
        for (address, library) in [(0x3000, "libA"), (0x3008, "libB")] {
            binary.imports.push(Import { library: Some(library.into()), name: "puts".into() });
            binary.import_slots.push(ImportSlot { address, name: "puts".into(), library: Some(library.into()) });
        }
        binary.symbols.push(Symbol { name: "puts".into(), address: 0x2000, size: 6, kind: SymbolKind::Function });
        let project = Project::new(binary);
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Import {
            name: "puts".into(),
            library: Some("libA".into()),
        }))
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(sites(&report), [0x1000], "{report:?}");
        assert_eq!(report.hits[0].evidence.target, Some(0x2000));
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Import {
            name: "puts".into(),
            library: Some("libB".into()),
        }))
        .unwrap();
        assert_eq!(sites(&project.search_code(&query).unwrap()), [0x4000]);
    }

    fn retained_search(project: &Project, program: &Program, query: &CodeSearchQuery) -> CodeSearchReport {
        let mut sources: Vec<_> = (0..program.xrefs.len()).collect();
        sources.sort_unstable_by_key(|&index| (program.xrefs[index].from, program.xrefs[index].to));
        search_program(project, program, &sources, query, &SearchControl::default()).unwrap()
    }

    fn function(address: u64, end: u64) -> DiscoveredFunction {
        DiscoveredFunction {
            address,
            blocks: vec![Block { start: address, end }],
            instruction_count: 2,
            switches: vec![],
        }
    }

    #[test]
    fn retained_learned_thumb_mode_controls_instruction_boundaries() {
        let project = Project::new(snapshot("arm", &[(0x1000, "r-x", "2a207047")], &[0x1000]));
        assert!(project.binary.thumb.is_empty());
        let program = Program {
            functions: vec![function(0x1000, 0x1004)],
            code_modes: vec![(0x1000, true)],
            ..Default::default()
        };
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("mov*").unwrap(),
            operands: Some(CodePattern::new("r0,*").unwrap()),
        })
        .unwrap();
        let report = retained_search(&project, &program, &query);
        assert_eq!(sites(&report), [0x1000]);
        assert_eq!(report.hits[0].bytes, "2a20");
        assert_eq!(report.decoded_instructions, 2);
        let unsupported = retained_search(&project, &program, &immediate(constant(CodeValue::Unsigned(42))));
        assert!(unsupported.hits.is_empty());
        assert!(unsupported.total_is_lower_bound);
        assert!(unsupported.limitations.iter().any(|text| text.contains("native operand evidence")));
    }

    #[test]
    fn retained_a64_indirect_call_flow_is_applied_without_fabricating_operand_evidence() {
        let project = Project::new(snapshot("aarch64", &[(0x1000, "r-x", "00003fd6c0035fd6")], &[0x1000]));
        let program = Program {
            functions: vec![function(0x1000, 0x1008)],
            resolved_flows: vec![ResolvedFlow { function: 0x1000, address: 0x1000, flow: Flow::Call(0x2000) }],
            ..Default::default()
        };
        let mut value = constant(CodeValue::Unsigned(0x2000));
        value.include_addresses = true;
        let report = retained_search(&project, &program, &immediate(value));
        assert_eq!(sites(&report), [0x1000]);
        assert_eq!(report.hits[0].flow, Flow::Call(0x2000));
        assert!(report.hits[0].text.to_ascii_lowercase().starts_with("blr"));
        assert!(report.hits[0].evidence.operand.is_none());
    }

    #[test]
    fn a64_native_memory_and_address_forming_evidence_are_opt_in() {
        let project =
            Project::new(snapshot("aarch64", &[(0x1000, "r-x", "20a840b920a0029102158052c0035fd6")], &[0x1000]));
        let mut value = constant(CodeValue::Unsigned(168));
        assert_eq!(sites(&project.search_code(&immediate(value.clone())).unwrap()), [0x1008]);
        value.include_displacements = true;
        assert_eq!(sites(&project.search_code(&immediate(value.clone())).unwrap()), [0x1000, 0x1008]);
        value.include_addresses = true;
        assert_eq!(sites(&project.search_code(&immediate(value)).unwrap()), [0x1000, 0x1004, 0x1008]);
    }

    fn first_instruction_query() -> CodeSearchQuery {
        CodeSearchQuery::new(CodeSearchKind::Instruction { mnemonic: CodePattern::new("*").unwrap(), operands: None })
            .unwrap()
            .with_bounds(1, 100)
            .unwrap()
    }

    #[test]
    fn a64_get_pc_uses_precharged_production_context_without_a_false_address_hit() {
        let project = Project::new(snapshot("aarch64", &[(0x1000, "r-x", "01000094e0031eaac0035fd6")], &[0x1000]));
        assert_eq!(project.function_listing(0x1000).unwrap().blocks[0][0].flow, Flow::Next);
        let report = project.search_code(&first_instruction_query()).unwrap();
        assert_eq!(sites(&report), [0x1000]);
        assert_eq!(report.hits[0].flow, Flow::Next);
        assert_eq!((report.decoded_bytes, report.inspected_code_bytes, report.source_bytes), (4, 12, 8));
        let mut value = constant(CodeValue::Unsigned(0x1004));
        value.include_addresses = true;
        assert!(project.search_code(&immediate(value)).unwrap().hits.is_empty());
        for bytes in [4, 11] {
            let query =
                first_instruction_query().with_scan_bounds(bytes, crate::search::MAX_SEARCH_MATCH_WORK).unwrap();
            let report = project.search_code(&query).unwrap();
            assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
            assert!(report.hits.is_empty() && report.total_is_lower_bound && !report.scan_complete);
            assert_eq!((report.decoded_instructions, report.decoded_bytes), (0, 0));
            assert_eq!((report.inspected_code_bytes, report.source_bytes), (4, 4));
        }
    }

    #[test]
    fn a64_get_pc_can_read_the_fourth_following_word_but_never_crosses_an_unbacked_gap() {
        let project = Project::new(snapshot(
            "aarch64",
            &[(0x1000, "r-x", "010000941f2003d51f2003d51f2003d5e0031eaac0035fd6")],
            &[0x1000],
        ));
        let query = first_instruction_query().with_scan_bounds(20, crate::search::MAX_SEARCH_MATCH_WORK).unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.hits[0].flow, Flow::Next);
        assert_eq!((report.decoded_bytes, report.inspected_code_bytes, report.source_bytes), (4, 20, 16));
        let project = Project::new(snapshot(
            "aarch64",
            &[(0x1000, "r-x", "01000094"), (0x1008, "r-x", "e0031eaac0035fd6")],
            &[0x1000],
        ));
        let report = project.search_code(&first_instruction_query()).unwrap();
        assert_eq!(report.hits[0].flow, Flow::Call(0x1004));
        assert_eq!((report.inspected_code_bytes, report.source_bytes), (4, 0));
    }

    #[test]
    fn x86_get_pc_preserves_a_long_following_instruction_without_mutating_the_live_run_twice() {
        let project =
            Project::new(snapshot("x86_64", &[(0x1000, "r-x", "e80000000066666666666666488b0424c3")], &[0x1000]));
        assert_eq!(project.function_listing(0x1000).unwrap().blocks[0][0].flow, Flow::Next);
        let report = project.search_code(&first_instruction_query()).unwrap();
        assert_eq!(report.hits[0].flow, Flow::Next);
        assert_eq!((report.decoded_bytes, report.inspected_code_bytes, report.source_bytes), (5, 17, 12));
        let mut value = constant(CodeValue::Unsigned(0x1005));
        value.include_addresses = true;
        assert!(project.search_code(&immediate(value)).unwrap().hits.is_empty());
        let query = first_instruction_query().with_scan_bounds(15, crate::search::MAX_SEARCH_MATCH_WORK).unwrap();
        let report = project.search_code(&query).unwrap();
        assert!(report.hits.is_empty() && report.total_is_lower_bound);
        assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
        assert_eq!((report.decoded_bytes, report.inspected_code_bytes, report.source_bytes), (0, 15, 15));
    }

    #[test]
    fn arm_thumb_and_capstone_link_idioms_keep_bounded_context_across_block_ends() {
        for (arch, hex, big_endian, thumb) in [
            ("arm", "ffffffeb0e00a0e1", false, false),
            ("arm", "00f000f800bf7046", false, true),
            ("powerpc", "480000057fc802a6", true, false),
            ("mips", "04110001000000003c1c0002279c80b4039fe021", true, false),
            ("sparc", "4000000201000000ae03c017", true, false),
        ] {
            let mut binary = snapshot_endian(arch, &[(0x1000, "r-x", hex)], &[0x1000], big_endian);
            if thumb {
                binary.thumb.push(0x1000..0x1000 + (hex.len() / 2) as u64);
            }
            let project = Project::new(binary);
            let report = project.search_code(&first_instruction_query()).unwrap();
            assert_eq!(report.hits[0].flow, Flow::Next, "{arch}: {report:?}");
            let end = 0x1000 + 4 * (1 + u64::from(project.binary.arch.delay_slots()));
            let program = Program { functions: vec![function(0x1000, end)], ..Default::default() };
            let report = retained_search(&project, &program, &first_instruction_query());
            assert_eq!(report.hits[0].flow, Flow::Next, "{arch}: {report:?}");
            assert!(report.inspected_code_bytes <= 20);
            let query = first_instruction_query().with_scan_bounds(4, crate::search::MAX_SEARCH_MATCH_WORK).unwrap();
            let report = retained_search(&project, &program, &query);
            assert!(report.hits.is_empty() && report.total_is_lower_bound, "{arch}: {report:?}");
            assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
        }
    }

    fn literal_load() -> Project {
        Project::new(snapshot(
            "aarch64",
            &[(0x1000, "r-x", "40000058c0035fd6"), (0x1008, "r--", "0020000000000000")],
            &[0x1000],
        ))
    }

    fn ldr_query(bytes: u64) -> CodeSearchQuery {
        CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("ldr").unwrap(),
            operands: Some(CodePattern::new("x0,*").unwrap()),
        })
        .unwrap()
        .with_bounds(1, 100)
        .unwrap()
        .with_scan_bounds(bytes, crate::search::MAX_SEARCH_MATCH_WORK)
        .unwrap()
    }

    #[test]
    fn a64_literal_callbacks_charge_unique_pointer_bytes_even_when_decoder_probes_twice() {
        let project = literal_load();
        let report = project.search_code(&ldr_query(12)).unwrap();
        assert_eq!(sites(&report), [0x1000], "{report:?}");
        assert_eq!(report.decoded_bytes, 4);
        assert_eq!(report.inspected_code_bytes, 4);
        assert_eq!(report.source_bytes, 8);
        assert_eq!(report.decoded_bytes + report.source_bytes, 12);
        assert_eq!(report.stop_reason, SearchStopReason::InstructionBudget);

        let query = ldr_query(32);
        let mut probes = PointerInspection { source_bytes: 0, work: 0, stop: None, cache: BTreeMap::new() };
        let control = SearchControl::default();
        assert_eq!(probes.read(&project, &query, &control, 0, 0x1008, 8), Some(0x2000));
        let first_work = probes.work;
        assert_eq!(probes.read(&project, &query, &control, 0, 0x1008, 8), Some(0x2000));
        assert_eq!(probes.source_bytes, 8);
        assert_eq!(probes.work, first_work + 1);
    }

    #[test]
    fn refused_literal_read_preserves_inspection_counts_but_never_admits_a_fallback_match() {
        let project = literal_load();
        let report = project.search_code(&ldr_query(4)).unwrap();
        assert!(report.hits.is_empty());
        assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
        assert_eq!((report.decoded_instructions, report.decoded_bytes), (1, 0));
        assert_eq!((report.inspected_code_bytes, report.source_bytes), (4, 4));
        assert!(report.total_is_lower_bound && !report.scan_complete);

        let report = project.search_code(&ldr_query(3)).unwrap();
        assert_eq!(report.stop_reason, SearchStopReason::ScanByteBudget);
        assert_eq!((report.decoded_instructions, report.inspected_code_bytes, report.source_bytes), (0, 0, 0));
        assert!(report.hits.is_empty());

        let query = ldr_query(32).with_scan_bounds(32, 1).unwrap();
        let mut probes = PointerInspection { source_bytes: 0, work: 0, stop: None, cache: BTreeMap::new() };
        assert_eq!(probes.read(&project, &query, &SearchControl::default(), 0, 0x1008, 8), None);
        assert_eq!(probes.source_bytes, 0);
        assert_eq!(probes.stop, Some(SearchStopReason::MatchWorkBudget));
    }

    #[test]
    fn mutable_or_unbacked_pointer_probes_are_not_source_inspection() {
        let project = Project::new(snapshot(
            "aarch64",
            &[(0x1000, "r-x", "40000058c0035fd6"), (0x1008, "rw-", "0020000000000000")],
            &[0x1000],
        ));
        let report = project.search_code(&ldr_query(12)).unwrap();
        assert_eq!(sites(&report), [0x1000]);
        assert_eq!(report.source_bytes, 0);
        let query = ldr_query(32);
        let mut probes = PointerInspection { source_bytes: 0, work: 0, stop: None, cache: BTreeMap::new() };
        assert_eq!(probes.read(&project, &query, &SearchControl::default(), 0, 0xffff, 8), None);
        assert_eq!(probes.source_bytes, 0);
        assert_eq!(probes.stop, None);
    }

    fn metadata_project() -> Project {
        let mut binary = snapshot("x86_64", &[(0x1000, "r-x", "90c3")], &[0x1000]);
        for index in 0..4096 {
            binary.symbols.push(Symbol {
                name: format!("retained_data_{index}"),
                address: 0x10000 + index,
                size: 1,
                kind: SymbolKind::Data,
            });
            binary.import_slots.push(ImportSlot {
                address: 0x20000 + index * 8,
                name: format!("unused_import_{index}"),
                library: Some("retained_library".into()),
            });
        }
        let project = Project::new(binary);
        project.analysis().unwrap();
        project
    }

    #[test]
    fn cancellation_after_analysis_precedes_all_metadata_preparation() {
        use std::sync::atomic::AtomicBool;

        let project = metadata_project();
        let analysis = project.analysis().unwrap();
        let cancel = AtomicBool::new(true);
        let control = SearchControl { cancel: Some(&cancel) };
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Import {
            name: "unused_import_4095".into(),
            library: None,
        }))
        .unwrap();
        // Model cancellation arriving as analysis returns, before calling any preparation helper.
        let report = search_program(&project, &analysis.program, &analysis.xrefs_by_source, &query, &control).unwrap();
        assert!(report.cancelled);
        assert_eq!(report.stop_reason, SearchStopReason::Cancelled);
        assert_eq!((report.match_work, report.examined_references, report.decoded_instructions), (0, 0, 0));
        assert!(report.hits.is_empty());
        let report = project.search_code_controlled(&query, &control).unwrap();
        assert_eq!(report.match_work, 0);
    }

    #[test]
    fn tiny_work_stops_cached_import_and_name_inventory_without_decoding() {
        let project = metadata_project();
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Import {
            name: "unused_import_4095".into(),
            library: None,
        }))
        .unwrap()
        .with_scan_bounds(1024, 1)
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.stop_reason, SearchStopReason::MatchWorkBudget);
        assert!(report.match_work <= 1);
        assert_eq!((report.decoded_instructions, report.examined_references), (0, 0));
        assert!(report.total_is_lower_bound && !report.scan_complete);
    }

    #[test]
    fn tiny_work_stops_cached_block_preparation_without_collecting_the_inventory() {
        let hex = "7500".repeat(2048) + "c3";
        let project = Project::new(snapshot("x86_64", &[(0x1000, "r-x", &hex)], &[0x1000]));
        let analysis = project.analysis().unwrap();
        assert!(analysis.program.functions.iter().map(|function| function.blocks.len()).sum::<usize>() > 1000);
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("j*").unwrap(),
            operands: None,
        })
        .unwrap()
        .with_scan_bounds(1024, 1)
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.match_work, 1);
        assert_eq!(report.stop_reason, SearchStopReason::MatchWorkBudget);
        assert_eq!(report.decoded_instructions, 0);
        assert!(report.hits.is_empty() && report.total_is_lower_bound);
    }

    #[test]
    fn import_stub_preparation_charges_retained_xrefs_before_each_visit() {
        let mut code = Vec::new();
        for index in 0..256i32 {
            code.extend([0x48, 0x8d, 0x05]);
            code.extend((0x3000i32 - (0x1000 + index * 7 + 7)).to_le_bytes());
        }
        code.push(0xc3);
        let hex = rampage_arch::hex::bytes(&code);
        let mut binary = snapshot("x86_64", &[(0x1000, "r-x", &hex), (0x3000, "r--", "0000000000000000")], &[0x1000]);
        binary.symbols.push(Symbol {
            name: "foo".into(),
            address: 0x1000,
            size: code.len() as u64,
            kind: SymbolKind::Function,
        });
        binary.import_slots.push(ImportSlot { address: 0x4000, name: "foo".into(), library: None });
        let project = Project::new(binary);
        assert_eq!(project.analysis().unwrap().program.xrefs.len(), 256);
        let query = CodeSearchQuery::new(CodeSearchKind::FunctionsReferencing(CodeReference::Import {
            name: "foo".into(),
            library: None,
        }))
        .unwrap()
        .with_scan_bounds(4096, 250)
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.stop_reason, SearchStopReason::MatchWorkBudget);
        assert!(report.examined_references > 0 && report.examined_references < 256, "{report:?}");
        assert!(report.match_work <= 250);
        assert_eq!(report.decoded_instructions, 0);
        assert!(report.hits.is_empty() && report.total_is_lower_bound);
    }

    #[test]
    fn cross_function_block_order_and_paging_stay_sorted_when_instruction_budget_caps_scan() {
        let project = Project::new(snapshot(
            "aarch64",
            &[(0x1000, "r-x", "1f2003d5"), (0x1800, "r-x", "1f2003d5"), (0x2000, "r-x", "1f2003d5")],
            &[0x1000],
        ));
        let mut first = function(0x1000, 0x1004);
        first.blocks.push(Block { start: 0x2000, end: 0x2004 });
        let program = Program { functions: vec![first, function(0x1800, 0x1804)], ..Default::default() };
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("nop").unwrap(),
            operands: None,
        })
        .unwrap()
        .with_bounds(2, 100)
        .unwrap()
        .with_page(1, 1)
        .unwrap();
        let report = retained_search(&project, &program, &query);
        assert_eq!(sites(&report), [0x1800]);
        assert_eq!(report.total, 2);
        assert_eq!(report.stop_reason, SearchStopReason::InstructionBudget);
        assert!(report.total_is_lower_bound);
        let report = retained_search(&project, &program, &query.with_scan_bounds(1024, 1).unwrap());
        assert!(report.hits.is_empty());
        assert_eq!(report.stop_reason, SearchStopReason::MatchWorkBudget);
        assert!(report.total_is_lower_bound);
    }

    #[test]
    fn budgets_and_query_validation_are_explicit() {
        let project = constants();
        let query = immediate(constant(CodeValue::Unsigned(42))).with_bounds(1, 10).unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(sites(&report), [0x1000]);
        assert!(!report.scan_complete);
        assert!(report.total_is_lower_bound);
        assert_eq!(report.decoded_instructions, 1);
        assert!(query.clone().with_bounds(MAX_INSTRUCTIONS + 1, 10).is_err());
        assert!(query.clone().with_page(usize::MAX, 1).is_err());
        assert!(query.with_range(Some(5..5)).is_err());
        let mut value = constant(CodeValue::Unsigned(256));
        value.width_bits = Some(8);
        assert!(CodeSearchQuery::new(CodeSearchKind::Immediate(value)).is_err());
        assert!(CodePattern::new(&"*".repeat(513)).is_err());
        assert!(SourceString::new("世界 🦀", SourceStringEncoding::Utf16Le).is_ok());
    }
}
