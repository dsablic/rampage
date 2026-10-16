//! Explicit host preparation followed by an import-free compiled triage component.
//!
//! Preparation is cooperative native work, outside component fuel and the worker deadline. Admission is
//! complete-or-reject relative to the existing primitives, not a claim that the loader recovered every fact.
//! Original-descriptor checks detect observable changes but cannot make mapped reads atomic with file writes.
//! Native managed metadata preparation is not admitted. Fresh opening uses conservative ELF64, AMD64 PE32+
//! and thin x86-64 Mach-O profiles; native-loader producers do not have a 1 MiB allocation contract.

mod bounds;
mod component;
mod conversion;
mod preload;
mod source;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use rampage_plugin_contract as contract;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ApiError, Packs, Project, ProjectWorkspaceTaskControl, ReportLimits, WorkflowReport};

pub use component::read_plugin_triage_component;
pub use source::open_plugin_triage_source;

pub const MAX_PLUGIN_TRIAGE_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PLUGIN_TRIAGE_REPORT_BYTES: usize = 60_000;

type FunctionNamesSnapshot = (Arc<()>, Vec<(u64, String)>);

/// Process-local retention of the exact project, original descriptor, names and configuration.
/// No deserialization, replacement project, caller-supplied facts, or annotation application is supported.
pub struct PreparedPluginTriage {
    project: Arc<Project>,
    names: Arc<()>,
    packs: Arc<Packs>,
    image_sha256: [u8; 32],
    facts: contract::TriageFacts,
    input: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginTriageProvenance {
    pub content_authority: &'static str,
    pub confidence_interpretation: &'static str,
    pub component_sha256: String,
    pub interface: &'static str,
    pub source_revalidated_non_atomic: bool,
    pub host_preparation_outside_component_limits: bool,
}

/// Every report field is a plugin claim, including summaries, limitations, suggestions and `observed` claims.
/// The host alone supplies the workflow, target and provenance. Suggestions are inert, never executed.
#[derive(Debug, Clone, Serialize)]
pub struct PluginTriageReport {
    pub provenance: PluginTriageProvenance,
    pub report: WorkflowReport,
}

/// Explicit opt-in to native whole-program preparation. Source, loader metadata and names are admitted before
/// discovery starts. The existing discovery producer is monolithic: cancellation is checked before/after it,
/// not inside it, and neither component fuel nor the worker deadline covers this operation.
pub fn prepare_plugin_triage_with_analysis(
    project: Arc<Project>,
    limits: ReportLimits,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<PreparedPluginTriage, ApiError> {
    control.check()?;
    check_source(&project)?;
    preload::reject_loaded_managed(&project)?;
    if !(1..=contract::MAX_FINDINGS_PER_SECTION).contains(&limits.per_section) {
        return Err(invalid("section limit is outside the plugin contract"));
    }
    let packs = project.packs();
    if packs.configured() {
        return Err(invalid("configured data packs are not admitted by source-only plugin triage"));
    }
    bounds::preflight_source(&project, control)?;
    let names = preflight_names(&project)?;
    checked_primitive(&project, &names, &packs, control, || project.analysis().map(|_| ()))?;
    let prepared = prepare_plugin_triage(project, limits, control)?;
    if !Arc::ptr_eq(&names, &prepared.names) || !Arc::ptr_eq(&packs, &prepared.packs) {
        return Err(invalid("names or configuration changed during explicit analysis preparation"));
    }
    prepared.revalidate(control)?;
    Ok(prepared)
}

/// Requires successful, already-completed native analysis. Call a native analysis operation explicitly first.
/// This function never starts whole-program discovery, reads historical inventory, or loads lazy data packs.
/// Managed sources and configured packs are rejected: their native producers have no preallocation admission
/// contract in this lane. Guest managed composition remains a separate capability, not host-source admission.
pub fn prepare_plugin_triage(
    project: Arc<Project>,
    limits: ReportLimits,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<PreparedPluginTriage, ApiError> {
    control.check()?;
    check_source(&project)?;
    preload::reject_loaded_managed(&project)?;
    if !(1..=contract::MAX_FINDINGS_PER_SECTION).contains(&limits.per_section) {
        return Err(invalid("section limit is outside the plugin contract"));
    }
    let packs = project.packs();
    if packs.configured() {
        return Err(invalid("configured data packs are not admitted by source-only plugin triage"));
    }
    bounds::preflight_source(&project, control)?;
    let analysis = project.cached_analysis().ok_or_else(|| {
        ApiError::Unavailable("plugin triage requires explicitly completed successful native analysis".into())
    })?;
    bounds::preflight_analysis(&project, analysis, control)?;
    let (names, functions) = snapshot_functions(&project, analysis)?;
    control.check()?;
    check_names_and_packs(&project, &names, &packs)?;
    check_source(&project)?;
    let image_sha256 = digest(&project, control)?;

    let mut ids = bounds::FactBudget::default();
    let binary = &project.binary;
    let binary_fact = contract::BinaryFact {
        id: ids.record()?,
        format: format!("{:?}", binary.format),
        arch: binary.arch.to_string(),
        entry: binary.entry,
        section_count: binary.sections.len() as u64,
        segment_count: binary.segments.len() as u64,
    };
    let triage = checked_primitive(&project, &names, &packs, control, || Ok(rampage_analysis::triage::triage(binary)))?;
    bounds::serialized_preflight(&triage)?;
    let triage_fact = contract::TriageFact {
        id: ids.record()?,
        image_size: triage.image_size,
        entropy: triage.entropy,
        sha256: triage.image_hashes.sha256,
        md5: triage.image_hashes.md5,
        hints: triage
            .hints
            .into_iter()
            .map(|text| {
                ids.text(&text)?;
                Ok(contract::HintFact { id: ids.record()?, text })
            })
            .collect::<Result<_, ApiError>>()?,
    };
    let detected = checked_primitive(&project, &names, &packs, control, || {
        Ok(rampage_detect::identify(binary, &rampage_detect::SignatureDb::bundled()))
    })?;
    bounds::serialized_preflight(&detected)?;
    let detections = detected
        .into_iter()
        .map(|row| {
            ids.text(&row.name)?;
            ids.texts(&row.evidence)?;
            Ok(contract::DetectionFact {
                id: ids.record()?,
                name: row.name,
                kind: match row.kind {
                    rampage_detect::Kind::Compiler => contract::DetectionKind::Compiler,
                    rampage_detect::Kind::Packer => contract::DetectionKind::Packer,
                    rampage_detect::Kind::Protector => contract::DetectionKind::Protector,
                    rampage_detect::Kind::Installer => contract::DetectionKind::Installer,
                    rampage_detect::Kind::Linker => contract::DetectionKind::Linker,
                    rampage_detect::Kind::Runtime => contract::DetectionKind::Runtime,
                    rampage_detect::Kind::Unknown => contract::DetectionKind::Unknown,
                },
                confidence: match row.confidence {
                    rampage_detect::Confidence::Strong => contract::DetectionConfidence::Strong,
                    rampage_detect::Confidence::Tentative => contract::DetectionConfidence::Tentative,
                },
                evidence: row.evidence,
            })
        })
        .collect::<Result<_, ApiError>>()?;

    checked_primitive(&project, &names, &packs, control, || bounds::preflight_strings(&project, control))?;
    let scanned =
        checked_primitive(&project, &names, &packs, control, || Ok(rampage_analysis::strings::scan(binary, 4)))?;
    let strings = scanned
        .into_iter()
        .map(|row| {
            ids.text(&row.text)?;
            Ok(contract::StringFact { id: ids.record()?, address: row.address, text: row.text })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    let capabilities = checked_primitive(&project, &names, &packs, control, || {
        let imports = binary
            .imports
            .iter()
            .map(|row| row.name.clone())
            .chain(binary.import_slots.iter().map(|row| row.name.clone()))
            .collect::<Vec<_>>();
        let symbols = binary
            .symbols
            .iter()
            .filter(|row| row.kind == rampage_loaders::SymbolKind::Function)
            .map(|row| row.name.clone())
            .collect::<Vec<_>>();
        let text = strings.iter().map(|row| row.text.clone()).collect::<Vec<_>>();
        Ok(rampage_capabilities::detect_with_symbols(&imports, &symbols, &text))
    })?;
    bounds::serialized_preflight(&capabilities)?;
    let capabilities = capabilities
        .into_iter()
        .map(|row| {
            ids.text(&row.name)?;
            ids.text(&row.category)?;
            ids.texts(&row.evidence)?;
            Ok(contract::CapabilityFact {
                id: ids.record()?,
                name: row.name.into_owned(),
                category: row.category.into_owned(),
                evidence: row.evidence,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    let imports = binary
        .imports
        .iter()
        .map(|row| {
            ids.text(&row.name)?;
            if let Some(library) = &row.library {
                ids.text(library)?;
            }
            Ok(contract::ImportFact { id: ids.record()?, library: row.library.clone(), name: row.name.clone() })
        })
        .collect::<Result<_, ApiError>>()?;
    let functions = functions
        .into_iter()
        .map(|(address, name)| {
            ids.text(&name)?;
            Ok(contract::FunctionFact { id: ids.record()?, address, name })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    // Keep the exact admitted configuration rather than racing a later Project::set_packs or reacquiring names
    // from inside a mapped-byte operation. No configured packs or user databases are admitted in this lane.
    let identified = checked_primitive(&project, &names, &packs, control, || {
        let bundled = rampage_signatures::bundled(binary.arch);
        let database = bundled.ok_or_else(|| {
            ApiError::Unavailable("complete bundled signature database is unavailable for this architecture".into())
        })?;
        let bodies = analysis
            .program
            .functions
            .iter()
            .map(|function| {
                let body =
                    function.body(binary).ok_or_else(|| invalid("signature search lost a backed function body"))?;
                Ok((function.address, body))
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        let image = rampage_signatures::MaskContext::from_binary(binary);
        let matched = rampage_signatures::identify_program_sources(&[&database], &binary.target(), &image, &bodies);
        let mut rows = Vec::with_capacity(matched.len());
        for (address, (_, name)) in matched {
            control.check()?;
            if name.len() > contract::MAX_TEXT_BYTES {
                return Err(invalid("signature producer name exceeds admission limit"));
            }
            rows.push((address, name.to_owned()));
        }
        Ok(rows)
    })?;
    bounds::serialized_preflight(&identified)?;
    let function_names =
        functions.iter().map(|row| (row.address, row.name.as_str())).collect::<std::collections::BTreeMap<_, _>>();
    let signature_matches = identified
        .into_iter()
        .map(|(address, name)| {
            ids.text(&name)?;
            let current =
                function_names.get(&address).ok_or_else(|| invalid("signature references missing function"))?;
            let unnamed = *current == format!("sub_{address:x}");
            Ok(contract::SignatureFact {
                id: ids.record()?,
                address,
                name,
                unnamed,
                source: contract::SignatureSource::Bundled,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    drop(function_names);
    let facts = contract::TriageFacts {
        schema_version: contract::SCHEMA_VERSION,
        exhaustive: true,
        record_total: ids.records(),
        per_section: limits.per_section as u32,
        binary: binary_fact,
        triage: triage_fact,
        detections,
        managed: None,
        capabilities,
        imports,
        strings,
        functions: contract::FunctionFacts::Available { rows: functions },
        signature_matches,
    };
    contract::validate_facts(&facts).map_err(|_| invalid("prepared facts exceed or violate the complete contract"))?;
    let input = bounds::serialize_bounded(&facts, contract::MAX_INPUT_BYTES)?;
    contract::preflight_facts_json(&input).map_err(|_| invalid("serialized facts exceed contract JSON limits"))?;
    check_names_and_packs(&project, &names, &packs)?;
    if digest(&project, control)? != image_sha256 {
        return Err(invalid("selected source changed during plugin triage preparation"));
    }
    check_names_and_packs(&project, &names, &packs)?;
    control.check()?;
    Ok(PreparedPluginTriage { project, names, packs, image_sha256, facts, input })
}

impl PreparedPluginTriage {
    pub fn fact_count(&self) -> usize {
        self.facts.record_total as usize
    }

    pub fn revalidate(&self, control: &ProjectWorkspaceTaskControl<'_>) -> Result<(), ApiError> {
        control.check()?;
        check_names_and_packs(&self.project, &self.names, &self.packs)?;
        if digest(&self.project, control)? != self.image_sha256 {
            return Err(invalid("prepared plugin triage source changed"));
        }
        check_names_and_packs(&self.project, &self.names, &self.packs)?;
        control.check()
    }

    /// Only compiled component execution; there is no native guest fallback. The separate cancellation flag
    /// reaches the supervisor while this calling thread is blocked; `control` governs host checkpoints.
    pub fn run_component(
        &self,
        component: &[u8],
        config: &rampage_plugin::PluginConfig,
        cancellation: Option<&AtomicBool>,
        control: &ProjectWorkspaceTaskControl<'_>,
    ) -> Result<PluginTriageReport, ApiError> {
        self.revalidate(control)?;
        if component.len() > rampage_plugin::MAX_COMPONENT_BYTES {
            return Err(invalid("triage component exceeds the runtime size limit"));
        }
        let component_sha256 = rampage_arch::hex::bytes(&Sha256::digest(component));
        let bytes = rampage_plugin::run_component(component, &self.input, config, cancellation)
            .map_err(|error| ApiError::Unavailable(format!("triage component: {error}")))?;
        self.revalidate(control)?;
        // Re-admit at this API boundary as well as in the runtime: lexical allocation budgets precede serde.
        let response =
            contract::decode_response(&bytes, &self.facts).map_err(|_| invalid("invalid triage component response"))?;
        let report = conversion::adopt(self, response, component_sha256)?;
        self.revalidate(control)?;
        Ok(report)
    }
}

fn snapshot_functions(
    project: &Project,
    analysis: &crate::project::Analysis,
) -> Result<FunctionNamesSnapshot, ApiError> {
    let annotations = project.annotations.try_read().map_err(|_| {
        ApiError::Unavailable("annotations are busy or poisoned during plugin triage preparation".into())
    })?;
    let mut budget = bounds::FactBudget::default();
    for name in annotations.names().values() {
        budget.text(name)?;
    }
    for (_, name) in project.inventory_loader_names() {
        budget.text(name)?;
    }
    for function in &analysis.program.functions {
        if let Some(name) = project.inventory_function_name_in(&annotations, function.address) {
            budget.text(name)?;
        }
        budget.record()?;
    }
    let names = annotations.names_revision();
    let rows = analysis
        .program
        .functions
        .iter()
        .map(|function| (function.address, project.function_name_in(&annotations, function.address)))
        .collect();
    // No mapped reads, callbacks, hashing or filesystem work while annotations are locked.
    Ok((names, rows))
}

fn preflight_names(project: &Project) -> Result<Arc<()>, ApiError> {
    let annotations = project.annotations.try_read().map_err(|_| {
        ApiError::Unavailable("annotations are busy or poisoned during plugin triage preparation".into())
    })?;
    let mut budget = bounds::FactBudget::default();
    for name in annotations.names().values() {
        budget.record()?;
        budget.text(name)?;
    }
    for (_, name) in project.inventory_loader_names() {
        budget.record()?;
        budget.text(name)?;
    }
    Ok(annotations.names_revision())
}

fn checked_primitive<T>(
    project: &Project,
    names: &Arc<()>,
    packs: &Arc<Packs>,
    control: &ProjectWorkspaceTaskControl<'_>,
    work: impl FnOnce() -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    control.check()?;
    check_names_and_packs(project, names, packs)?;
    check_source(project)?;
    let result = work();
    check_source(project)?;
    check_names_and_packs(project, names, packs)?;
    control.check()?;
    result
}

fn check_names_and_packs(project: &Project, names: &Arc<()>, packs: &Arc<Packs>) -> Result<(), ApiError> {
    if !Arc::ptr_eq(names, &project.names_revision()?) || !Arc::ptr_eq(packs, &project.packs()) {
        return Err(invalid("plugin triage names or data-pack configuration changed; prepare again"));
    }
    Ok(())
}

fn check_source(project: &Project) -> Result<(), ApiError> {
    project
        .binary
        .validate_backing_source()
        .map_err(|_| invalid("plugin triage requires an unchanged original mapping"))
}

fn digest(project: &Project, control: &ProjectWorkspaceTaskControl<'_>) -> Result<[u8; 32], ApiError> {
    check_source(project)?;
    let mut hash = Sha256::new();
    for chunk in project.binary.image_bytes().chunks(64 * 1024) {
        control.check()?;
        check_source(project)?;
        hash.update(chunk);
    }
    check_source(project)?;
    control.check()?;
    Ok(hash.finalize().into())
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}
