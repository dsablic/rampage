use rampage_decompiler::results::{
    FrameBaseConvention, FrameContext, RecoveryDiagnostics, RecoveryStatus, ResultProvenance, Signature, Storage,
    StorageKind, VariableKind,
};
use serde::{Deserialize, Serialize};

use crate::{ApiError, Decompilation, Project, VariableDescriptor};

pub const MAX_FRAME_PAGE: usize = 128;
pub const MAX_FRAME_WORK: usize = 4096;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct FrameQuery {
    pub offset: usize,
    pub limit: usize,
    pub include_tracker: bool,
}

impl Default for FrameQuery {
    fn default() -> Self {
        Self { offset: 0, limit: 64, include_tracker: true }
    }
}

#[derive(Debug, Serialize)]
pub struct FunctionFrameReport {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    pub native: NativeFrameEvidence,
    pub tracker: TrackerFrameEvidence,
    pub coordinates: Vec<FrameCoordinate>,
    pub metadata: FrameMetadataCoverage,
    pub total_rows: usize,
    pub available_rows: usize,
    pub omitted_rows: usize,
    pub offset: usize,
    pub limit: usize,
    pub next_offset: Option<usize>,
    pub rows: Vec<FrameRow>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct FrameMetadataCoverage {
    pub bounded: bool,
    pub signature_parameters_total: usize,
    pub signature_parameters_omitted: usize,
    pub warnings_total: Option<usize>,
    pub warnings_omitted: usize,
    pub frame_context_omitted: bool,
    pub coordinates_total: usize,
    pub coordinates_omitted: usize,
    pub tracker_limitations_total: usize,
    pub tracker_limitations_omitted: usize,
    pub text_truncations: Vec<FrameTextTruncation>,
}

#[derive(Debug, Serialize)]
pub struct FrameTextTruncation {
    pub path: String,
    pub original_bytes: usize,
    pub retained_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct NativeFrameEvidence {
    pub available: bool,
    pub language_id: String,
    pub provenance: ResultProvenance,
    pub signature: Signature,
    pub frame_context: Option<FrameContext>,
    pub recovery_status: RecoveryStatus,
    #[serde(serialize_with = "serialize_diagnostics")]
    pub diagnostics: Option<RecoveryDiagnostics>,
    pub variable_total: usize,
    pub mapping_total: usize,
    pub variables_in_workset: usize,
    pub mappings_in_workset: usize,
    pub omitted_variables: usize,
    pub omitted_mappings: usize,
}

#[derive(Debug, Serialize)]
pub struct TrackerFrameEvidence {
    pub requested: bool,
    pub available: bool,
    pub unavailable_reason: Option<String>,
    pub slot_total: usize,
    pub register_evidence_total: usize,
    pub slots_in_workset: usize,
    pub register_evidence_in_workset: usize,
    pub omitted_slots: usize,
    pub omitted_register_evidence: usize,
    pub incomplete_instructions: Option<usize>,
    pub decoded_instructions: Option<usize>,
    pub lifted_instructions: Option<usize>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameSource {
    NativeDecompiler,
    StackTracker,
}

#[derive(Debug, Serialize)]
pub struct FrameCoordinate {
    pub id: String,
    pub source: FrameSource,
    pub space: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameCategory {
    Parameter,
    Local,
    TrackerSlot,
    RegisterEvidence,
}

#[derive(Debug, Serialize)]
pub struct FrameLocation {
    pub mapping_index: usize,
    pub piece_index: Option<usize>,
    pub coordinate_id: Option<String>,
    pub address_size_bits: Option<u32>,
    pub signed_offset: Option<String>,
    pub size_bytes: u32,
}

#[derive(Debug, Serialize)]
pub struct FrameTrackerSlot {
    pub offset: String,
    pub bits: u8,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub reads: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub writes: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct FrameRow {
    pub category: FrameCategory,
    pub source: FrameSource,
    pub native_variable: Option<VariableDescriptor>,
    pub raw_native_storage: Vec<Storage>,
    pub locations: Vec<FrameLocation>,
    pub coordinate_id: Option<String>,
    pub signed_offset: Option<String>,
    pub size_bits: Option<u32>,
    pub tracker_slot: Option<FrameTrackerSlot>,
    pub register_evidence: Option<rampage_analysis::dataflow::StackRegisterEvidence>,
    pub editable: bool,
    pub evidence: Vec<String>,
}

fn signed_offset(address: Option<u64>, bits: Option<u32>) -> Option<String> {
    let (address, bits) = (address?, bits?);
    if !(1..=64).contains(&bits) || (bits < 64 && address >> bits != 0) {
        return None;
    }
    let value =
        if address & (1_u64 << (bits - 1)) == 0 { i128::from(address) } else { i128::from(address) - (1_i128 << bits) };
    Some(value.to_string())
}

fn coordinate_id(kind: StorageKind, space: Option<&str>) -> Option<String> {
    let space = space?;
    match kind {
        StorageKind::Spacebase | StorageKind::Processor => Some(format!("native:{space}")),
        _ => None,
    }
}

fn serialize_diagnostics<S: serde::Serializer>(
    diagnostics: &Option<RecoveryDiagnostics>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut value = serde_json::to_value(diagnostics).map_err(serde::ser::Error::custom)?;
    if let Some(warnings) = value.get_mut("warnings").and_then(serde_json::Value::as_array_mut) {
        for warning in warnings {
            if let Some(address) = warning.get("address").and_then(serde_json::Value::as_u64) {
                warning["address"] = serde_json::Value::String(format!("{address:#x}"));
            }
        }
    }
    value.serialize(serializer)
}

fn native_row(variable: VariableDescriptor, storage: Vec<Storage>, context: Option<&FrameContext>) -> FrameRow {
    let mut locations = Vec::new();
    for (mapping_index, mapping) in storage.iter().enumerate() {
        let bits = mapping.address_size_bytes.and_then(|bytes| bytes.checked_mul(8));
        let stack = is_stack(mapping.kind, mapping.space.as_deref(), context);
        locations.push(FrameLocation {
            mapping_index,
            piece_index: None,
            coordinate_id: coordinate_id(mapping.kind, mapping.space.as_deref()),
            address_size_bits: bits,
            signed_offset: stack.then(|| signed_offset(mapping.address, bits)).flatten(),
            size_bytes: mapping.size,
        });
        for (piece_index, piece) in mapping.pieces.iter().enumerate() {
            let bits = piece.address_size_bytes.and_then(|bytes| bytes.checked_mul(8));
            let stack = is_stack(piece.kind, Some(&piece.space), context);
            locations.push(FrameLocation {
                mapping_index,
                piece_index: Some(piece_index),
                coordinate_id: coordinate_id(piece.kind, Some(&piece.space)),
                address_size_bits: bits,
                signed_offset: stack.then(|| signed_offset(Some(piece.address), bits)).flatten(),
                size_bytes: piece.size,
            });
        }
    }
    let (coordinate_id, signed_offset) = match locations.as_slice() {
        [location] => (location.coordinate_id.clone(), location.signed_offset.clone()),
        _ => (None, None),
    };
    FrameRow {
        category: match variable.kind {
            VariableKind::Parameter => FrameCategory::Parameter,
            VariableKind::Local => FrameCategory::Local,
        },
        source: FrameSource::NativeDecompiler,
        editable: variable.editable,
        size_bits: variable.data_type.size.checked_mul(8),
        native_variable: Some(variable),
        raw_native_storage: storage,
        locations,
        coordinate_id,
        signed_offset,
        tracker_slot: None,
        register_evidence: None,
        evidence: vec!["Native local-scope symbol and all of its exported storage mappings.".to_owned()],
    }
}

fn is_stack(kind: StorageKind, space: Option<&str>, context: Option<&FrameContext>) -> bool {
    kind == StorageKind::Spacebase
        && space.is_some_and(|space| context.map_or(space == "stack", |context| context.stack_space == space))
}

fn native_workset(decompilation: Decompilation) -> (FunctionFrameReport, usize) {
    let structure = decompilation.structure;
    let variable_total = structure.variables.len();
    let mapping_total = structure.variables.iter().map(|variable| variable.storage.len()).sum();
    let mut rows = Vec::new();
    let mut coordinates = std::collections::BTreeMap::new();
    let mut work = 0;
    let mut mappings_in_workset = 0;
    for (variable, descriptor) in structure.variables.into_iter().zip(decompilation.variables) {
        let cost = variable
            .storage
            .iter()
            .map(|mapping| 1_usize.saturating_add(mapping.pieces.len()))
            .fold(0_usize, usize::saturating_add)
            .max(1);
        if cost > MAX_FRAME_WORK - work {
            continue;
        }
        work += cost;
        mappings_in_workset += variable.storage.len();
        let row = native_row(descriptor, variable.storage, structure.frame_context.as_ref());
        for location in &row.locations {
            if let Some(id) = &location.coordinate_id {
                coordinates.entry(id.clone()).or_insert_with(|| FrameCoordinate {
                    id: id.clone(),
                    source: FrameSource::NativeDecompiler,
                    space: Some(id.strip_prefix("native:").unwrap_or(id).to_owned()),
                    origin: structure.frame_context.as_ref().and_then(|context| {
                        (id == &format!("native:{}", context.stack_space)
                            && context.base_convention == FrameBaseConvention::NativeSpacebaseRegister)
                            .then(|| "native_spacebase_register".to_owned())
                    }),
                });
            }
        }
        rows.push(row);
    }
    let variables_in_workset = rows.len();
    (
        FunctionFrameReport {
            address: decompilation.address,
            name: decompilation.name,
            native: NativeFrameEvidence {
                available: true,
                language_id: decompilation.language_id,
                provenance: structure.provenance,
                signature: structure.signature,
                frame_context: structure.frame_context,
                recovery_status: decompilation.recovery_status,
                diagnostics: structure.diagnostics,
                variable_total,
                mapping_total,
                variables_in_workset,
                mappings_in_workset,
                omitted_variables: variable_total - variables_in_workset,
                omitted_mappings: mapping_total - mappings_in_workset,
            },
            tracker: TrackerFrameEvidence {
                requested: false,
                available: false,
                unavailable_reason: Some("Stack tracker was not requested.".to_owned()),
                slot_total: 0,
                register_evidence_total: 0,
                slots_in_workset: 0,
                register_evidence_in_workset: 0,
                omitted_slots: 0,
                omitted_register_evidence: 0,
                incomplete_instructions: None,
                decoded_instructions: None,
                lifted_instructions: None,
                limitations: Vec::new(),
            },
            coordinates: coordinates.into_values().collect(),
            metadata: FrameMetadataCoverage::default(),
            total_rows: variable_total,
            available_rows: variables_in_workset,
            omitted_rows: variable_total - variables_in_workset,
            offset: 0,
            limit: 0,
            next_offset: None,
            rows,
            limitations: vec![
                "Native space offsets and tracker entry-SP offsets are independent coordinates; \
                 no equivalence is asserted."
                    .to_owned(),
                "Recovered variables and observed accesses do not prove a complete frame, frame size, \
                 or ABI callee-save roles."
                    .to_owned(),
                "Native warnings are recovery evidence, not proof that a variable type is wrong.".to_owned(),
                "Native rows represent complete local-scope symbols; repeated signature, diagnostics and coordinate \
                 metadata are bounded independently, with coverage and text truncations reported in metadata."
                    .to_owned(),
            ],
        },
        work,
    )
}

fn page(report: &mut FunctionFrameReport, query: &FrameQuery) {
    report.available_rows = report.rows.len();
    report.omitted_rows = report.total_rows - report.available_rows;
    report.offset = query.offset.min(report.available_rows);
    report.limit = query.limit;
    let end = report.offset.saturating_add(query.limit).min(report.available_rows);
    report.next_offset = (end < report.available_rows).then_some(end);
    report.rows = report.rows.drain(report.offset..end).collect();
    if report.omitted_rows != 0 {
        report.limitations.push(format!(
            "{} rows omitted by the {MAX_FRAME_WORK}-unit native mapping/piece and tracker evidence work bound; \
             pagination covers only the {} available rows.",
            report.omitted_rows, report.available_rows,
        ));
    }
    bound_frame_header(report);
}

fn truncate_header_text(text: &mut String, limit: usize, path: &str, truncations: &mut Vec<FrameTextTruncation>) {
    if text.len() <= limit {
        return;
    }
    let original_bytes = text.len();
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    truncations.push(FrameTextTruncation { path: path.to_owned(), original_bytes, retained_bytes: end });
}

/// Bounds only repeated metadata. Row contents remain complete for the caller's envelope budget check.
pub(crate) fn bound_frame_header(report: &mut FunctionFrameReport) {
    const LIST_BYTES: usize = 4096;
    const LIST_ITEMS: usize = 16;
    let coverage = &mut report.metadata;
    if coverage.bounded {
        return;
    }
    coverage.bounded = true;
    let truncations = &mut coverage.text_truncations;
    truncate_header_text(&mut report.name, 128, "name", truncations);
    truncate_header_text(&mut report.native.language_id, 128, "native.language_id", truncations);
    truncate_header_text(
        &mut report.native.signature.return_type.name,
        256,
        "native.signature.return_type.name",
        truncations,
    );
    if let Some(convention) = &mut report.native.signature.calling_convention {
        truncate_header_text(convention, 128, "native.signature.calling_convention", truncations);
    }

    coverage.signature_parameters_total = report.native.signature.parameters.len();
    let mut bytes = 2;
    let mut retained = 0;
    for parameter in report.native.signature.parameters.iter().take(LIST_ITEMS) {
        let size = serde_json::to_vec(parameter).expect("native parameter JSON").len() + 1;
        if size > LIST_BYTES - bytes {
            break;
        }
        bytes += size;
        retained += 1;
    }
    report.native.signature.parameters.truncate(retained);
    coverage.signature_parameters_omitted = coverage.signature_parameters_total - retained;

    if let Some(diagnostics) = &mut report.native.diagnostics {
        coverage.warnings_total = Some(diagnostics.warnings.len());
        let mut bytes = 2;
        let mut warnings = Vec::new();
        for mut warning in std::mem::take(&mut diagnostics.warnings).into_iter().take(LIST_ITEMS) {
            let mut text_omissions = Vec::new();
            let path = format!("native.diagnostics.warnings[{}].message", warnings.len());
            truncate_header_text(&mut warning.message, 256, &path, &mut text_omissions);
            // Numeric and hexadecimal address serialization each fit within this fixed allowance.
            let size = serde_json::to_vec(&warning).expect("native warning JSON").len() + 32;
            if size > LIST_BYTES - bytes {
                break;
            }
            bytes += size;
            warnings.push(warning);
            truncations.extend(text_omissions);
        }
        coverage.warnings_omitted = coverage.warnings_total.unwrap_or(0) - warnings.len();
        diagnostics.warnings = warnings;
    }

    if report
        .native
        .frame_context
        .as_ref()
        .is_some_and(|context| serde_json::to_vec(context).expect("native frame context JSON").len() > 1024)
    {
        report.native.frame_context = None;
        coverage.frame_context_omitted = true;
    }

    coverage.coordinates_total = report.coordinates.len();
    let mut bytes = 2;
    let mut retained = 0;
    for coordinate in report.coordinates.iter().take(LIST_ITEMS) {
        let size = serde_json::to_vec(coordinate).expect("frame coordinate JSON").len() + 1;
        if size > LIST_BYTES - bytes {
            break;
        }
        bytes += size;
        retained += 1;
    }
    report.coordinates.truncate(retained);
    coverage.coordinates_omitted = coverage.coordinates_total - retained;

    coverage.tracker_limitations_total = report.tracker.limitations.len();
    let mut bytes = 2;
    let mut limitations = Vec::new();
    for mut limitation in std::mem::take(&mut report.tracker.limitations).into_iter().take(LIST_ITEMS) {
        let mut text_omissions = Vec::new();
        let path = format!("tracker.limitations[{}]", limitations.len());
        truncate_header_text(&mut limitation, 256, &path, &mut text_omissions);
        let size = serde_json::to_vec(&limitation).expect("tracker limitation JSON").len() + 1;
        if size > LIST_BYTES - bytes {
            break;
        }
        bytes += size;
        limitations.push(limitation);
        truncations.extend(text_omissions);
    }
    coverage.tracker_limitations_omitted = coverage.tracker_limitations_total - limitations.len();
    report.tracker.limitations = limitations;
}

fn append_tracker(report: &mut FunctionFrameReport, work: &mut usize, dataflow: rampage_analysis::dataflow::DataFlow) {
    report.tracker.available = true;
    report.tracker.unavailable_reason = None;
    report.tracker.incomplete_instructions = Some(dataflow.incomplete_instructions);
    report.tracker.limitations.extend(dataflow.limitations);
    report.tracker.slot_total = dataflow.stack_slots.len();
    report.tracker.register_evidence_total = dataflow.stack_registers.len();
    report.total_rows += dataflow.stack_slots.len() + dataflow.stack_registers.len();
    report.coordinates.push(FrameCoordinate {
        id: "tracker:entry_sp".to_owned(),
        source: FrameSource::StackTracker,
        space: None,
        origin: Some("function_entry_stack_pointer".to_owned()),
    });
    for slot in dataflow.stack_slots {
        if *work == MAX_FRAME_WORK {
            break;
        }
        *work += 1;
        report.tracker.slots_in_workset += 1;
        report.rows.push(FrameRow {
            category: FrameCategory::TrackerSlot,
            source: FrameSource::StackTracker,
            native_variable: None,
            raw_native_storage: Vec::new(),
            locations: Vec::new(),
            coordinate_id: Some("tracker:entry_sp".to_owned()),
            signed_offset: Some(slot.offset.to_string()),
            size_bits: Some(u32::from(slot.bits)),
            tracker_slot: Some(FrameTrackerSlot {
                offset: slot.offset.to_string(),
                bits: slot.bits,
                reads: slot.reads,
                writes: slot.writes,
            }),
            register_evidence: None,
            editable: false,
            evidence: vec!["SSA dataflow stack access relative to entry SP.".to_owned()],
        });
    }
    for registers in dataflow.stack_registers {
        if *work == MAX_FRAME_WORK {
            break;
        }
        *work += 1;
        report.tracker.register_evidence_in_workset += 1;
        report.rows.push(FrameRow {
            category: FrameCategory::RegisterEvidence,
            source: FrameSource::StackTracker,
            native_variable: None,
            raw_native_storage: Vec::new(),
            locations: Vec::new(),
            coordinate_id: Some("tracker:entry_sp".to_owned()),
            signed_offset: Some(registers.offset.to_string()),
            size_bits: Some(u32::from(registers.bits)),
            tracker_slot: None,
            evidence: registers.evidence.iter().map(|evidence| (*evidence).to_owned()).collect(),
            register_evidence: Some(registers),
            editable: false,
        });
    }
    report.tracker.omitted_slots = report.tracker.slot_total - report.tracker.slots_in_workset;
    report.tracker.omitted_register_evidence =
        report.tracker.register_evidence_total - report.tracker.register_evidence_in_workset;
}

fn append_frame_summary(
    report: &mut FunctionFrameReport,
    work: &mut usize,
    result: Result<crate::FunctionSummary, ApiError>,
) -> Result<(), ApiError> {
    let summary = result?;
    report.tracker.limitations = summary.limitations;
    report.tracker.decoded_instructions = Some(summary.ir.len());
    report.tracker.lifted_instructions = Some(summary.lifted_instructions);
    if let Some(dataflow) = summary.dataflow {
        append_tracker(report, work, dataflow);
    } else {
        report.tracker.unavailable_reason =
            Some("Stack tracker unavailable: function_summary did not produce dataflow.".to_owned());
    }
    Ok(())
}

impl Project {
    /// Reads current native symbols and independent bounded stack-tracker evidence without publishing annotations.
    pub fn function_frame(&self, address: u64, query: &FrameQuery) -> Result<FunctionFrameReport, ApiError> {
        if !(1..=MAX_FRAME_PAGE).contains(&query.limit) {
            return Err(ApiError::Invalid(format!("frame limit must be between 1 and {MAX_FRAME_PAGE}")));
        }
        let (mut report, mut work) = native_workset(self.decompile(address)?);
        report.tracker.requested = query.include_tracker;
        if query.include_tracker {
            if self.binary.arch != rampage_arch::Arch::Aarch64 {
                report.tracker.unavailable_reason =
                    Some("Stack tracker unavailable: function_summary has no SSA for this architecture.".to_owned());
            } else {
                let summary = self.function_summary_for_frame(report.address);
                append_frame_summary(&mut report, &mut work, summary)?;
            }
        }
        page(&mut report, query);
        Ok(report)
    }
}

#[cfg(test)]
#[path = "frame_tests.rs"]
mod tests;
