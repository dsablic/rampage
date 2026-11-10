//! Bounded, explicit-source type propagation. Derived hints never become propagation sources.

use std::collections::{BTreeMap, BTreeSet};

use rampage_decompiler::results::{CallValue, CallValueStatus, StructuredResult, TypeInfo};
use rampage_decompiler::{DecompilerOptions, VariableStorage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::annotations::{
    Annotations, DerivedTypeHint, Field, TypeHintAnnotation, TypeHintEvidence, TypeHintTarget, encode_type_hints,
    parse_local_types, parse_type_hints,
};
use crate::decompile::NativeDecompileContext;
use crate::{ApiError, Project};

pub const MAX_PROPAGATION_FUNCTIONS: usize = 32;
pub const MAX_PROPAGATION_EDGES: usize = 256;
pub const MAX_PROPAGATION_CANDIDATES: usize = 256;

pub(crate) type DerivedHints = BTreeMap<u64, Vec<DerivedTypeHint>>;
type NativePassResult = (PropagationResult, BTreeSet<u64>, Vec<rampage_decompiler::worker::WorkerOperation>);

struct PropagationPass<'a> {
    state: &'a crate::decompile::DecompilerState,
    options: &'a DecompilerOptions,
    annotations: &'a Annotations,
    address: u64,
    request: &'a PropagationRequest,
    context: &'a BTreeSet<u64>,
    bootstrap: &'a [rampage_decompiler::worker::WorkerOperation],
    cancellation: Option<&'a std::sync::atomic::AtomicBool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropagationRequest {
    pub address: u64,
    pub apply: bool,
    pub max_functions: usize,
    pub max_candidates: usize,
}

#[cfg(test)]
#[path = "propagation_tests.rs"]
mod tests;

#[derive(Debug, Clone, Serialize)]
pub struct PropagationCandidate {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub target: TypeHintTarget,
    pub data_type: String,
    pub evidence: Vec<TypeHintEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationConflict {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub target: TypeHintTarget,
    pub alternatives: Vec<DerivedTypeHint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationSkip {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub target: Option<TypeHintTarget>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropagationHintEdit {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub previous: Option<TypeHintAnnotation>,
    pub value: Option<TypeHintAnnotation>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PropagationCounts {
    /// Distinct functions in the bounded native context, not the number of replay passes.
    pub functions: usize,
    /// Native call entries examined, including explicitly unsupported entries.
    pub edges: usize,
    pub candidates: usize,
    pub applied: usize,
    pub skipped: usize,
    pub conflicts: usize,
    pub planned_hint_edits: usize,
    pub persisted_hint_edits: usize,
    /// Planned removal of complete function payloads; partial removals appear in old/new hint_edits.
    pub planned_hint_clears: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropagationResult {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub source_fingerprint: String,
    pub apply: bool,
    /// Successful apply appended at least one payload edit. Preflight receives this prospective receipt.
    pub persisted: bool,
    pub hint_edits: Vec<PropagationHintEdit>,
    pub candidates: Vec<PropagationCandidate>,
    pub applied: Vec<PropagationCandidate>,
    pub skipped: Vec<PropagationSkip>,
    pub conflicts: Vec<PropagationConflict>,
    pub limitations: Vec<String>,
    pub counts: PropagationCounts,
}

#[derive(Clone)]
pub(crate) struct LazyContext {
    address: u64,
    fingerprint: String,
    revision: std::sync::Arc<()>,
    values: BTreeMap<u64, Option<String>>,
    limitations: Vec<String>,
}

#[derive(Clone, Copy)]
enum AutomaticSpecificationContext {
    Bundled,
    ExternalOverride,
}

fn automatic_specification_gate(
    annotations: &Annotations,
    selection: AutomaticSpecificationContext,
    validate_source: impl FnOnce() -> Result<(), ApiError>,
) -> Result<Option<(Annotations, Vec<String>)>, ApiError> {
    if !matches!(selection, AutomaticSpecificationContext::ExternalOverride)
        || !annotations.type_hints().is_empty()
        || (annotations.signatures().is_empty()
            && annotations.local_types().is_empty()
            && annotations.globals().is_empty()
            && annotations.data_types().is_empty())
    {
        return Ok(None);
    }
    validate_source()?;
    Ok(Some((
        annotations.snapshot(),
        vec![
            concat!(
                "automatic type propagation omitted for configured external specifications; ",
                "ordinary explicit typing retained without a bundled fingerprint",
            )
            .to_owned(),
        ],
    )))
}

pub(crate) fn lazy_context(
    project: &Project,
    state: &mut crate::decompile::DecompilerState,
    options: &DecompilerOptions,
    annotations: &Annotations,
    address: u64,
    cancellation: &std::sync::atomic::AtomicBool,
) -> Result<(Annotations, Vec<String>), ApiError> {
    check_cancellation(Some(cancellation))?;
    let selection = if std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
        AutomaticSpecificationContext::ExternalOverride
    } else {
        AutomaticSpecificationContext::Bundled
    };
    if let Some(context) = automatic_specification_gate(annotations, selection, || {
        project
            .binary
            .validate_available_backing_source()
            .map(|_| ())
            .map_err(|error| ApiError::Invalid(format!("type propagation source unavailable: {error}")))
    })? {
        state.propagation_cache = None;
        return Ok(context);
    }
    lazy_context_with_fingerprint(project, state, options, annotations, address, cancellation, || {
        fingerprint_availability(project, options, annotations)
    })
}

fn lazy_context_with_fingerprint(
    project: &Project,
    state: &mut crate::decompile::DecompilerState,
    options: &DecompilerOptions,
    annotations: &Annotations,
    address: u64,
    cancellation: &std::sync::atomic::AtomicBool,
    fingerprint: impl FnOnce() -> Result<FingerprintAvailability, ApiError>,
) -> Result<(Annotations, Vec<String>), ApiError> {
    if annotations.signatures().is_empty()
        && annotations.local_types().is_empty()
        && annotations.globals().is_empty()
        && annotations.data_types().is_empty()
        && annotations.type_hints().is_empty()
    {
        return Ok((annotations.snapshot(), Vec::new()));
    }
    let fingerprint = match fingerprint()? {
        FingerprintAvailability::Reviewed(fingerprint) => fingerprint,
        FingerprintAvailability::NoReviewedCModel(reason) => {
            state.propagation_cache = None;
            return Ok((
                annotations.snapshot(),
                vec![format!(
                    "automatic type propagation omitted: {reason}; ordinary explicit typing retained; \
                     durable derived hints withheld"
                )],
            ));
        }
    };
    let fresh = state.propagation_cache.as_ref().is_some_and(|cache| {
        cache.address == address
            && cache.fingerprint == fingerprint
            && std::sync::Arc::ptr_eq(&cache.revision, &annotations.revision())
    });
    if !fresh {
        let request =
            PropagationRequest { address, apply: false, max_functions: 8, max_candidates: MAX_PROPAGATION_CANDIDATES };
        let derived = project.derive_types(state, options, annotations, address, &request, Some(cancellation));
        check_cancellation(Some(cancellation))?;
        let mut context = match derived {
            Ok((result, functions)) => {
                let mut values: BTreeMap<_, _> = functions.into_iter().map(|function| (function, None)).collect();
                let mut grouped: BTreeMap<u64, Vec<DerivedTypeHint>> = BTreeMap::new();
                for candidate in result.candidates {
                    grouped.entry(candidate.function).or_default().push(DerivedTypeHint {
                        target: candidate.target,
                        data_type: candidate.data_type,
                        evidence: candidate.evidence,
                    });
                }
                for (function, hints) in grouped {
                    values.insert(
                        function,
                        Some(
                            encode_type_hints(&TypeHintAnnotation { source_fingerprint: fingerprint.clone(), hints })
                                .map_err(ApiError::Invalid)?,
                        ),
                    );
                }
                LazyContext {
                    address,
                    fingerprint,
                    revision: annotations.revision(),
                    values,
                    limitations: result.limitations,
                }
            }
            Err(ApiError::NativeTypeHintUnsupported(reason)) => LazyContext {
                address,
                fingerprint,
                revision: annotations.revision(),
                values: BTreeMap::new(),
                limitations: vec![format!("automatic type propagation unavailable: {reason}")],
            },
            Err(error) => return Err(error),
        };
        let candidate = apply_lazy_context(annotations, &context)?;
        if candidate.type_hints() != annotations.type_hints()
            && let Some(limitation) = validate_automatic_context(annotations, &candidate, |snapshot| {
                project
                    .decompile_annotation_candidate_with_operations(
                        state,
                        options,
                        snapshot,
                        address,
                        NativeDecompileContext { cancellation: Some(cancellation), ..Default::default() },
                    )
                    .map(|_| ())
            })?
        {
            context.values.clear();
            context.limitations.push(limitation);
        }
        state.propagation_cache = Some(context);
    }
    let context = state.propagation_cache.as_ref().expect("fresh bounded propagation context");
    let candidate = apply_lazy_context(annotations, context)?;
    Ok((candidate, context.limitations.clone()))
}

fn apply_lazy_context(annotations: &Annotations, context: &LazyContext) -> Result<Annotations, ApiError> {
    let mut candidate = annotations.snapshot();
    for (&function, value) in &context.values {
        candidate.set(Field::TypeHint, function, value.clone()).map_err(ApiError::Invalid)?;
    }
    Ok(candidate)
}

fn validate_automatic_context(
    original: &Annotations,
    candidate: &Annotations,
    mut validate: impl FnMut(&Annotations) -> Result<(), ApiError>,
) -> Result<Option<String>, ApiError> {
    validate(original)?;
    match validate(candidate) {
        Ok(()) => Ok(None),
        Err(ApiError::NativeTypeHintUnsupported(reason)) => Ok(Some(format!(
            "optional automatic type context omitted; ordinary explicit/durable context retained: {reason}"
        ))),
        Err(error) => Err(error),
    }
}

enum FingerprintAvailability {
    Reviewed(String),
    NoReviewedCModel(String),
}

pub(crate) fn source_fingerprint(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
) -> Result<String, ApiError> {
    match fingerprint_availability(project, options, annotations)? {
        FingerprintAvailability::Reviewed(fingerprint) => Ok(fingerprint),
        FingerprintAvailability::NoReviewedCModel(reason) => {
            Err(ApiError::Invalid(format!("type propagation unavailable: {reason}")))
        }
    }
}

fn fingerprint_availability(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
) -> Result<FingerprintAvailability, ApiError> {
    project
        .binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Invalid(format!("type propagation source unavailable: {error}")))?;
    let mut hash = Sha256::new();
    hash.update(b"rampage-type-propagation-v2\0");
    hash.update(rampage_decompiler::worker::PROTOCOL_VERSION.to_le_bytes());
    hash.update(Sha256::digest(project.binary.image_bytes()));
    if project.binary.format == rampage_loaders::Format::Snapshot {
        let capture = rampage_analysis::capture_identity::capture_identity(&project.binary)
            .ok_or_else(|| ApiError::Invalid("type propagation snapshot identity unavailable".into()))?;
        hash.update(
            serde_json::to_vec(&(capture.schema, capture.sha256))
                .map_err(|error| ApiError::Invalid(error.to_string()))?,
        );
    }
    if let Some(raw) = project
        .binary
        .raw_interpretation_identity()
        .map_err(|error| ApiError::Invalid(format!("type propagation Raw identity unavailable: {error}")))?
    {
        hash.update(
            serde_json::to_vec(&(raw.schema, raw.sha256)).map_err(|error| ApiError::Invalid(error.to_string()))?,
        );
    }
    hash.update(crate::debug_layout_import::current_specification_digest()?.as_bytes());
    let image_context = serde_json::to_vec(&(
        project
            .binary
            .segments
            .iter()
            .map(|segment| {
                (
                    segment.address,
                    segment.size,
                    segment.file_offset,
                    segment.file_size,
                    segment.perms.read,
                    segment.perms.write,
                    segment.perms.execute,
                )
            })
            .collect::<Vec<_>>(),
        &project.binary.import_slots,
        &project.binary.sections,
    ))
    .map_err(|error| ApiError::Invalid(error.to_string()))?;
    hash.update(image_context);
    let language =
        rampage_decompiler::language_id_with_options(project.binary.arch, project.binary.big_endian, options)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
    let organization = rampage_decompiler::c_data_organization(&language);
    if let Some(organization) = organization {
        hash.update(
            serde_json::to_vec(&(&language, organization)).map_err(|error| ApiError::Invalid(error.to_string()))?,
        );
    }
    let posix = crate::decompile::posix_context(annotations, options, &language)?;
    for slot in &project.binary.import_slots {
        if let Some(prototype) = rampage_decompiler::c_prototype(&slot.name) {
            hash.update(prototype.as_bytes());
        }
        if let Some(prototype) = organization.and_then(|organization| {
            crate::import_types::import_prototype(&slot.name, options.platform, &language, organization, posix)
        }) {
            hash.update(prototype.declaration.as_bytes());
            hash.update(prototype.context.as_bytes());
            hash.update(prototype.source.as_bytes());
        }
    }
    let inputs = serde_json::to_vec(&(
        project.binary.arch.to_string(),
        project.binary.big_endian,
        format!("{:?}", options.platform),
        &options.compiler,
        options.arm_be8,
        annotations.signatures(),
        annotations.types(),
        annotations.type_library(),
        annotations.local_types(),
        annotations.globals(),
        annotations.data_types(),
    ))
    .map_err(|error| ApiError::Invalid(error.to_string()))?;
    hash.update(inputs);
    project
        .binary
        .validate_available_backing_source()
        .map_err(|error| ApiError::Invalid(format!("type propagation source unavailable: {error}")))?;
    // All backing, capture, specification and explicit-input checks above remain fatal even without a C model.
    Ok(match organization {
        Some(_) => FingerprintAvailability::Reviewed(rampage_arch::hex::bytes(&hash.finalize())),
        None => FingerprintAvailability::NoReviewedCModel(format!("no reviewed C data organization for {language}")),
    })
}

pub(crate) fn without_hints(annotations: &Annotations) -> Result<Annotations, ApiError> {
    let mut candidate = annotations.snapshot();
    let changes: Vec<_> = annotations.type_hints().keys().map(|address| (Field::TypeHint, *address, None)).collect();
    candidate.set_batch_validated(&changes, |_| Ok(())).map_err(ApiError::Invalid)?;
    Ok(candidate)
}

fn check_cancellation(cancellation: Option<&std::sync::atomic::AtomicBool>) -> Result<(), ApiError> {
    if cancellation.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
        return Err(ApiError::Unavailable("decompilation cancelled".into()));
    }
    Ok(())
}

fn target_key(target: &TypeHintTarget) -> String {
    let mut target = target.clone();
    if let TypeHintTarget::Local { storage } | TypeHintTarget::Parameter { storage, .. } = &mut target {
        storage.use_ranges.sort_by(|a, b| (&a.space, a.start, a.end).cmp(&(&b.space, b.start, b.end)));
    }
    serde_json::to_string(&target).expect("type hint target JSON")
}

fn overridden(annotations: &Annotations, function: u64, target: &TypeHintTarget) -> Result<bool, ApiError> {
    if matches!(target, TypeHintTarget::Return | TypeHintTarget::Parameter { .. })
        && annotations.signatures().contains_key(&function)
    {
        return Ok(true);
    }
    let storage = match target {
        TypeHintTarget::Local { storage } | TypeHintTarget::Parameter { storage, .. } => storage,
        TypeHintTarget::Return => return Ok(false),
    };
    let types = annotations
        .local_types()
        .get(&function)
        .map(|text| parse_local_types(text))
        .transpose()
        .map_err(ApiError::Invalid)?
        .unwrap_or_default();
    Ok(types.iter().any(|entry| entry.storage == *storage))
}

/// Shared whole-program and exact-entry replay gate. Never upgrades soft hints to hard overrides.
pub(crate) fn replay_hints(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
    only_function: Option<u64>,
) -> Result<(DerivedHints, Vec<String>), ApiError> {
    if annotations.type_hints().is_empty() {
        return Ok((BTreeMap::new(), Vec::new()));
    }
    let fingerprint = match fingerprint_availability(project, options, annotations)? {
        FingerprintAvailability::Reviewed(fingerprint) => fingerprint,
        FingerprintAvailability::NoReviewedCModel(reason) => {
            return Ok((BTreeMap::new(), vec![format!("durable derived hints withheld: {reason}")]));
        }
    };
    let mut hints = BTreeMap::new();
    let mut limitations = Vec::new();
    let signature_stubs: BTreeSet<_> = annotations
        .signatures()
        .keys()
        .filter(|address| project.binary.import_slot(**address).is_some())
        .flat_map(|slot| crate::decompile::import_stub_targets(project, *slot))
        .collect();
    for (&function, text) in annotations.type_hints() {
        if only_function.is_some_and(|only| only != function) {
            continue;
        }
        let payload = parse_type_hints(text).map_err(ApiError::Invalid)?;
        if payload.source_fingerprint != fingerprint {
            limitations.push(format!("stale derived type hints at {function:#x} omitted; recompute propagate_types"));
            continue;
        }
        let mut current = Vec::new();
        for hint in payload.hints {
            if overridden(annotations, function, &hint.target)?
                || (signature_stubs.contains(&function)
                    && matches!(hint.target, TypeHintTarget::Parameter { .. } | TypeHintTarget::Return))
            {
                limitations.push(format!("analyst type overrides derived hint at {function:#x}"));
            } else {
                current.push(hint);
            }
        }
        if !current.is_empty() {
            hints.insert(function, current);
        }
    }
    Ok((hints, limitations))
}

pub(crate) fn append_limitations(structure: &mut StructuredResult, limitations: Vec<String>) {
    use rampage_decompiler::results::{RecoveryDiagnostics, RecoveryWarning, WarningKind};
    if limitations.is_empty() {
        return;
    }
    let diagnostics = structure.diagnostics.get_or_insert_with(|| RecoveryDiagnostics {
        bad_data: false,
        unimplemented: false,
        unresolved_calls: 0,
        unresolved_indirect_jumps: 0,
        partial_jump_tables: 0,
        warnings: Vec::new(),
    });
    for message in limitations {
        diagnostics.warnings.push(RecoveryWarning { kind: WarningKind::Header, address: None, message });
    }
}

pub(crate) fn hint_operations(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
    only_function: Option<u64>,
) -> Result<Vec<rampage_decompiler::worker::WorkerOperation>, ApiError> {
    let Some(root) = only_function else { return Ok(Vec::new()) };
    let (context, _) = call_context(project, root, MAX_PROPAGATION_FUNCTIONS)?;
    hint_operations_in_context(project, options, annotations, &context)
}

pub(crate) fn hint_operations_in_context(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
    context: &BTreeSet<u64>,
) -> Result<Vec<rampage_decompiler::worker::WorkerOperation>, ApiError> {
    let (mut functions, _) = replay_hints(project, options, annotations, None)?;
    functions.retain(|function, _| context.contains(function));
    for (&function, text) in annotations.local_types() {
        if !context.contains(&function) {
            continue;
        }
        for entry in parse_local_types(text).map_err(ApiError::Invalid)? {
            functions.entry(function).or_default().push(DerivedTypeHint {
                target: TypeHintTarget::Local { storage: entry.storage },
                data_type: entry.data_type,
                evidence: Vec::new(),
            });
        }
    }
    // Parameter ordinals remain checked metadata; native replay uses the complete owning storage instead.
    Ok(functions
        .into_iter()
        .map(|(address, hints)| {
            let hints = hints
                .into_iter()
                .map(|hint| match hint.target {
                    TypeHintTarget::Parameter { storage, .. } | TypeHintTarget::Local { storage } => {
                        rampage_decompiler::TypeHint::Local { storage, data_type: hint.data_type }
                    }
                    TypeHintTarget::Return => rampage_decompiler::TypeHint::Return { data_type: hint.data_type },
                })
                .collect();
            rampage_decompiler::worker::WorkerOperation::TypeHints { address, hints }
        })
        .collect())
}

fn call_context(project: &Project, root: u64, limit: usize) -> Result<(BTreeSet<u64>, bool), ApiError> {
    let mut context = BTreeSet::new();
    let mut pending = BTreeSet::from([root]);
    let mut edges = BTreeSet::new();
    while let Some(function) = pending.pop_first() {
        if context.contains(&function) {
            continue;
        }
        if context.len() == limit {
            return Ok((context, true));
        }
        if !context.insert(function) {
            continue;
        }
        let analysis = project.analysis()?;
        for xref in &analysis.program.xrefs {
            if xref.kind != rampage_analysis::discover::XrefKind::Call {
                continue;
            }
            let caller = analysis.function_containing(xref.from);
            if xref.to != function && caller != Some(function) {
                continue;
            }
            if !edges.insert((xref.from, xref.to)) {
                continue;
            }
            if edges.len() > MAX_PROPAGATION_EDGES {
                return Ok((context, true));
            }
            if let Some(caller) = caller {
                pending.insert(caller);
            }
            if project.binary.code_from(xref.to).is_some() {
                pending.insert(xref.to);
            }
        }
    }
    Ok((context, false))
}

#[derive(Clone)]
struct Node {
    function: u64,
    target: TypeHintTarget,
    size: u32,
    hard: bool,
    facts: BTreeMap<String, Vec<TypeHintEvidence>>,
    rejected: BTreeMap<String, Vec<TypeHintEvidence>>,
}

#[derive(Clone)]
struct Link {
    from: usize,
    to: usize,
    evidence: TypeHintEvidence,
}

#[derive(Default)]
struct Graph {
    nodes: Vec<Node>,
    keys: BTreeMap<(u64, String), usize>,
    links: Vec<Link>,
    skipped: Vec<PropagationSkip>,
    limitations: BTreeSet<String>,
    origins: BTreeSet<(u64, u64, String)>,
}

impl Graph {
    fn has_return_source(&self, function: u64) -> bool {
        self.keys
            .get(&(function, target_key(&TypeHintTarget::Return)))
            .is_some_and(|index| !self.nodes[*index].facts.is_empty())
    }

    fn unavailable(&mut self, function: u64, reason: String) {
        self.limitations.insert(reason.clone());
        self.skipped.push(PropagationSkip { function, target: None, reason });
    }

    fn node(&mut self, function: u64, target: TypeHintTarget, size: u32, hard: bool) -> Result<usize, ApiError> {
        let key = (function, target_key(&target));
        if let Some(&index) = self.keys.get(&key) {
            return Ok(index);
        }
        if self.nodes.len() >= MAX_PROPAGATION_CANDIDATES {
            return Err(ApiError::Invalid("propagation native target budget exceeds 256; reduce the context".into()));
        }
        let index = self.nodes.len();
        self.nodes.push(Node { function, target, size, hard, facts: BTreeMap::new(), rejected: BTreeMap::new() });
        self.keys.insert(key, index);
        Ok(index)
    }

    fn seed(&mut self, node: usize, ty: &TypeInfo, at: u64, reason: &str) {
        self.seed_from(node, ty, self.nodes[node].function, at, reason);
    }

    fn seed_from(&mut self, node: usize, ty: &TypeInfo, function: u64, at: u64, reason: &str) {
        if ty.name == "void" && ty.size == 0 {
            return;
        }
        if !supported_type(ty) || self.nodes[node].size != ty.size {
            self.limitations.insert(format!("unsupported scalar/pointer source type {:?} at {at:#x}", ty.name));
            return;
        }
        self.origins.insert((function, at, reason.to_owned()));
        merge_evidence(
            self.nodes[node].facts.entry(ty.name.clone()).or_default(),
            &[TypeHintEvidence { function, at, reason: reason.to_owned() }],
        );
    }

    fn link(&mut self, from: usize, to: usize, function: u64, at: u64, reason: &str) {
        if self.nodes[to].hard {
            self.skipped.push(PropagationSkip {
                function: self.nodes[to].function,
                target: Some(self.nodes[to].target.clone()),
                reason: "analyst target type preserved".to_owned(),
            });
        }
        if self.nodes[from].size == 0 || self.nodes[from].size != self.nodes[to].size {
            self.limitations.insert(format!("native storage/type width mismatch at {at:#x}"));
            return;
        }
        self.links.push(Link { from, to, evidence: TypeHintEvidence { function, at, reason: reason.to_owned() } });
    }

    fn solve(&mut self) {
        // Preserve every explicit origin and immediate call edge; intermediate targets have their own evidence.
        for _ in 0..=self.nodes.len() {
            let mut changed = false;
            for link in &self.links {
                let facts = self.nodes[link.from].facts.clone();
                for (ty, mut evidence) in facts {
                    evidence.retain(|item| self.origins.contains(&(item.function, item.at, item.reason.clone())));
                    merge_evidence(&mut evidence, std::slice::from_ref(&link.evidence));
                    if self.nodes[link.to].hard {
                        if !self.nodes[link.to].facts.contains_key(&ty) {
                            changed |= merge_evidence(self.nodes[link.to].rejected.entry(ty).or_default(), &evidence);
                        }
                    } else {
                        changed |= merge_evidence(self.nodes[link.to].facts.entry(ty).or_default(), &evidence);
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }
}

fn merge_evidence(target: &mut Vec<TypeHintEvidence>, evidence: &[TypeHintEvidence]) -> bool {
    let before = target.clone();
    for item in evidence {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
    target.sort_by(|a, b| (a.function, a.at, &a.reason).cmp(&(b.function, b.at, &b.reason)));
    *target != before
}

fn supported_type(ty: &TypeInfo) -> bool {
    if ty.size == 0 || ty.size > 16 || crate::decompile::validate_local_type(&ty.name).is_err() {
        return false;
    }
    ty.name.contains('*')
        || (!ty.name.starts_with("undefined")
            && !ty.name.starts_with("xunknown")
            && !matches!(ty.name.as_str(), "unknown" | "void" | "BADTYPE"))
}

fn parameter_target(structure: &StructuredResult, index: u32) -> Option<(TypeHintTarget, u32)> {
    let parameter = structure.signature.parameters.get(index as usize)?;
    let storage = VariableStorage::try_from(&parameter.storage).ok()?;
    Some((TypeHintTarget::Parameter { index, storage }, parameter.data_type.size))
}

fn value_target(structure: &StructuredResult, value: &CallValue) -> Option<(TypeHintTarget, u32)> {
    if value.status != CallValueStatus::Variable {
        return None;
    }
    let storage = value.storage.as_ref()?;
    storage_target(structure, storage)
}

fn storage_target(structure: &StructuredResult, storage: &VariableStorage) -> Option<(TypeHintTarget, u32)> {
    for index in 0..structure.signature.parameters.len() {
        if let Some((TypeHintTarget::Parameter { index, storage: parameter }, size)) =
            parameter_target(structure, index as u32)
            && parameter == *storage
        {
            return Some((TypeHintTarget::Parameter { index, storage: parameter }, size));
        }
    }
    let matches: Vec<_> = structure
        .variables
        .iter()
        .filter(|variable| {
            variable.storage.len() == 1
                && VariableStorage::try_from(&variable.storage[0]).ok().as_ref() == Some(storage)
        })
        .collect();
    let [variable] = matches.as_slice() else { return None };
    if variable.kind == rampage_decompiler::results::VariableKind::Parameter {
        return None;
    }
    Some((TypeHintTarget::Local { storage: storage.clone() }, variable.data_type.size))
}

fn global_source_type<'a>(annotations: &Annotations, value: &'a CallValue) -> Option<(u64, &'a TypeInfo)> {
    let address = value.global_address?;
    if !annotations.globals().contains_key(&address) && !annotations.data_types().contains_key(&address) {
        return None;
    }
    if !value.global_type_locked {
        return None;
    }
    let object = value.global_object_type.as_ref()?;
    let argument = value.data_type.as_ref()?;
    match value.status {
        CallValueStatus::Global
            if value.type_locked && value.symbol_type.as_ref() == Some(object) && argument == object =>
        {
            Some((address, argument))
        }
        CallValueStatus::GlobalAddress if value.symbol_type.is_none() => Some((address, argument)),
        _ => None,
    }
}

fn seed_function(
    graph: &mut Graph,
    annotations: &Annotations,
    address: u64,
    structure: &StructuredResult,
    builtin: Option<&str>,
    signature_at: Option<u64>,
) -> Result<(), ApiError> {
    let signature = signature_at.is_some() || annotations.signatures().contains_key(&address);
    let source_at = signature_at.unwrap_or(address);
    let result = graph.node(address, TypeHintTarget::Return, structure.signature.return_type.size, signature)?;
    if signature {
        graph.seed(result, &structure.signature.return_type, source_at, "explicit analyst signature return");
    } else if let Some(reason) = builtin {
        graph.seed(result, &structure.signature.return_type, address, &format!("{reason}; return"));
    }
    for (index, parameter) in structure.signature.parameters.iter().enumerate() {
        if let Some((target, size)) = parameter_target(structure, index as u32) {
            let node = graph.node(address, target, size, signature)?;
            if signature {
                graph.seed(
                    node,
                    &parameter.data_type,
                    source_at,
                    &format!("explicit analyst signature parameter {index}"),
                );
            } else if let Some(reason) = builtin {
                graph.seed(node, &parameter.data_type, address, &format!("{reason}; parameter {index}"));
            }
        }
    }
    if let Some(text) = annotations.local_types().get(&address) {
        for entry in parse_local_types(text).map_err(ApiError::Invalid)? {
            let variable = structure.variables.iter().find(|variable| {
                variable.storage.len() == 1
                    && VariableStorage::try_from(&variable.storage[0]).ok().as_ref() == Some(&entry.storage)
            });
            let Some(variable) = variable else {
                graph.limitations.insert(format!("explicit local type at {address:#x} has no complete native symbol"));
                continue;
            };
            if let Some((target, size)) = storage_target(structure, &entry.storage) {
                let node = graph.node(address, target, size, true)?;
                graph.nodes[node].hard = true;
                let storage =
                    serde_json::to_string(&entry.storage).map_err(|error| ApiError::Invalid(error.to_string()))?;
                graph.seed(node, &variable.data_type, address, &format!("explicit analyst local type for {storage}"));
            }
        }
    }
    Ok(())
}

impl Project {
    /// Previews or atomically applies bounded soft type hints across proven native direct calls.
    /// This explicit operation recomputes from analyst types, never from previously derived hints.
    pub fn propagate_types(&self, request: &PropagationRequest) -> Result<PropagationResult, ApiError> {
        self.propagate_types_with_preflight(request, |_| Ok(()))
    }

    /// Checks the complete prospective response and every affected native function before writing the log.
    pub fn propagate_types_with_preflight(
        &self,
        request: &PropagationRequest,
        preflight: impl FnOnce(&PropagationResult) -> Result<(), ApiError>,
    ) -> Result<PropagationResult, ApiError> {
        if !(1..=MAX_PROPAGATION_FUNCTIONS).contains(&request.max_functions)
            || !(1..=MAX_PROPAGATION_CANDIDATES).contains(&request.max_candidates)
        {
            return Err(ApiError::Invalid("propagation requires 1..=32 functions and 1..=256 candidates".into()));
        }
        let address = self.function_containing(request.address)?.unwrap_or(request.address);
        if self.binary.code_from(address).is_none() {
            return Err(ApiError::Invalid("type propagation requires a file-backed code entry".into()));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        crate::decompile::validate_cached_layout_source(self, &state)?;
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        if !request.apply {
            let snapshot = self.read_annotations_lock().read().expect("annotations lock").checked_read_snapshot()?;
            let (mut result, functions) = self.derive_types(&state, &options, &snapshot, address, request, None)?;
            prepare_hint_receipt(&snapshot, &functions, request.apply, &mut result)?;
            preflight(&result)?;
            return Ok(result);
        }
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            let (mut result, functions) = self.derive_types(&state, &options, annotations, address, request, None)?;
            prepare_hint_receipt(annotations, &functions, request.apply, &mut result)?;
            let mut changes = Vec::new();
            let mut changed_functions = BTreeSet::new();
            for edit in &result.hint_edits {
                let value = edit.value.as_ref().map(encode_type_hints).transpose().map_err(ApiError::Invalid)?;
                changed_functions.insert(edit.function);
                changes.push((Field::TypeHint, edit.function, value));
            }
            result.applied = result
                .candidates
                .iter()
                .filter(|candidate| changed_functions.contains(&candidate.function))
                .cloned()
                .collect();
            result.counts.applied = result.applied.len();
            result.persisted = !changes.is_empty();
            result.counts.persisted_hint_edits = changes.len();
            let mut preflight = Some(preflight);
            annotations
                .set_batch_validated(&changes, |candidate| {
                    let retained = replay_hints(self, &options, candidate, None).map_err(|error| error.to_string())?.0;
                    let mut validation_context =
                        call_context(self, address, request.max_functions).map_err(|error| error.to_string())?.0;
                    validation_context.extend(retained.keys().copied());
                    if validation_context.len() > request.max_functions {
                        return Err(concat!(
                            "complete retained hint-context validation exceeds the requested function budget; ",
                            "no annotation changes applied",
                        )
                        .into());
                    }
                    let mut validation_targets = changed_functions.clone();
                    validation_targets.extend(retained.keys().copied());
                    for function in validation_targets {
                        let output = self
                            .decompile_annotation_candidate_with_operations(
                                &state,
                                &options,
                                candidate,
                                function,
                                NativeDecompileContext { admitted: Some(&validation_context), ..Default::default() },
                            )
                            .map_err(|error| error.to_string())?;
                        validate_output_targets(candidate, function, &output.structure)
                            .map_err(|error| error.to_string())?;
                    }
                    preflight.take().expect("single propagation preflight")(&result)
                        .map_err(|error| error.to_string())?;
                    let fingerprint =
                        source_fingerprint(self, &options, candidate).map_err(|error| error.to_string())?;
                    if fingerprint != result.source_fingerprint {
                        return Err("propagation source changed before append".into());
                    }
                    Ok(())
                })
                .map_err(ApiError::Invalid)?;
            if let Some(preflight) = preflight {
                preflight(&result)?;
            }
            Ok(result)
        })
    }

    fn derive_types(
        &self,
        state: &crate::decompile::DecompilerState,
        options: &DecompilerOptions,
        annotations: &Annotations,
        address: u64,
        request: &PropagationRequest,
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<(PropagationResult, BTreeSet<u64>), ApiError> {
        let (context, truncated) = call_context(self, address, request.max_functions)?;
        let (mut result, functions) = run_native_passes(context.len(), cancellation, |bootstrap| {
            self.derive_types_pass(PropagationPass {
                state,
                options,
                annotations,
                address,
                request,
                context: &context,
                bootstrap,
                cancellation,
            })
        })?;
        if source_fingerprint(self, options, annotations)? != result.source_fingerprint {
            return Err(ApiError::Invalid("propagation source changed during native context passes".into()));
        }
        if truncated {
            result
                .limitations
                .push("direct-call context truncated by function/edge budget; findings are incomplete".into());
            result.limitations.sort();
        }
        Ok((result, functions))
    }

    fn derive_types_pass(&self, pass: PropagationPass<'_>) -> Result<NativePassResult, ApiError> {
        let PropagationPass { state, options, annotations, address, request, context, bootstrap, cancellation } = pass;
        let fingerprint = source_fingerprint(self, options, annotations)?;
        let explicit = without_hints(annotations)?;
        let import_stubs: BTreeMap<_, _> = rampage_analysis::functions::stub_names(&self.binary)
            .into_iter()
            .chain(rampage_analysis::functions::thunk_names(&self.binary))
            .collect();
        let mut graph = Graph::default();
        if context.iter().any(|function| explicit.local_types().contains_key(function)) || !bootstrap.is_empty() {
            graph.limitations.insert(
                concat!(
                    "Native bootstrap retains recovered non-source parameter/return shape as inference only; ",
                    "it is never a provenance seed",
                )
                .into(),
            );
        }
        let structures = analyze_native_context(
            context,
            cancellation,
            |function| {
                self.decompile_annotation_candidate_with_operations(
                    state,
                    options,
                    &explicit,
                    function,
                    NativeDecompileContext { operations: bootstrap, admitted: Some(context), cancellation },
                )
                .map(|decompilation| decompilation.structure)
            },
            &mut graph,
        )?;
        let native_context = if structures.keys().any(|function| import_stubs.contains_key(function)) {
            Some(self.native_type_context(state, options, &explicit, cancellation)?)
        } else {
            None
        };
        let mut signature_sources = BTreeMap::new();
        for slot in explicit.signatures().keys().filter(|address| self.binary.import_slot(**address).is_some()) {
            for stub in crate::decompile::import_stub_targets(self, *slot) {
                signature_sources.insert(stub, *slot);
            }
        }
        for (&function, structure) in &structures {
            let builtin =
                if let (Some(name), Some((language, organization))) = (import_stubs.get(&function), &native_context) {
                    let name = name.strip_suffix("@plt").or_else(|| name.strip_suffix("@got")).unwrap_or(name);
                    let posix = crate::decompile::posix_context(&explicit, options, language)?;
                    if let Some(prototype) =
                        crate::import_types::import_prototype(name, options.platform, language, *organization, posix)
                    {
                        Some(format!(
                            "target-model builtin import prototype {}; {}",
                            prototype.canonical_name, prototype.context
                        ))
                    } else if !matches!(name.trim_start_matches('_'), "recv" | "CreateFileW")
                        && !name.starts_with("_recv@")
                        && !name.starts_with("_CreateFileW@")
                        && rampage_decompiler::c_prototype(name).is_some()
                        && matches!(
                            language.rsplit(':').next(),
                            Some("default" | "gcc" | "macosx" | "apcs" | "apple" | "windows" | "clangwindows")
                        )
                    {
                        Some(format!("selected native runtime import prototype {name}; {language}"))
                    } else {
                        None
                    }
                } else {
                    None
                };
            seed_function(
                &mut graph,
                &explicit,
                function,
                structure,
                builtin.as_deref(),
                signature_sources.get(&function).copied(),
            )?;
        }
        let mut edges = 0;
        let mut import_targets: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        if structures.values().map(|structure| structure.calls.len()).sum::<usize>() > MAX_PROPAGATION_EDGES {
            graph.limitations.insert("256-call edge budget reached; findings are incomplete".into());
        }
        for (&caller, structure) in &structures {
            for call in &structure.calls {
                if edges == MAX_PROPAGATION_EDGES {
                    break;
                }
                edges += 1;
                let at = call.source.unwrap_or(caller);
                if call.indirect {
                    graph.unavailable(caller, format!("indirect call at {at:#x} is unsupported"));
                    continue;
                }
                let Some(mut callee) = call.target else { continue };
                if !structures.contains_key(&callee)
                    && self.binary.import_slot(callee).is_some()
                    && let Some(source) = call.source
                {
                    let stubs = import_targets
                        .entry(callee)
                        .or_insert_with(|| crate::decompile::import_stub_targets(self, callee).into_iter().collect());
                    let mut proven = self.analysis()?.program.xrefs.iter().filter(|xref| {
                        xref.from == source
                            && xref.kind == rampage_analysis::discover::XrefKind::Call
                            && stubs.contains(&xref.to)
                            && structures.contains_key(&xref.to)
                    });
                    if let (Some(edge), None) = (proven.next(), proven.next()) {
                        callee = edge.to;
                    }
                }
                let Some(destination) = structures.get(&callee) else {
                    graph.unavailable(
                        caller,
                        format!("callee {callee:#x} at call {at:#x} outside bounded native context"),
                    );
                    continue;
                };
                if structure.signature.variadic || destination.signature.variadic {
                    graph.unavailable(caller, format!("variadic call at {at:#x} is unsupported"));
                    continue;
                }
                let has_return_source = graph.has_return_source(caller) || graph.has_return_source(callee);
                let result_target = call.result.as_ref().and_then(|result| value_target(structure, &result.value));
                if let Some(reason) = &call.evidence_unavailable {
                    graph.unavailable(caller, format!("call {at:#x}: {reason}"));
                    continue;
                }
                if let Some(arguments) = &call.arguments {
                    if arguments.len() != destination.signature.parameters.len() {
                        graph.unavailable(
                            caller,
                            format!("call {at:#x}: caller inputs require native prototype-shape bootstrap"),
                        );
                    }
                    for argument in arguments {
                        let Some(index) = argument.parameter_index else {
                            graph.unavailable(
                                caller,
                                format!("call {at:#x}: input {} parameter index not proven", argument.input_index),
                            );
                            continue;
                        };
                        let Some((target, size)) = parameter_target(destination, index) else { continue };
                        let parameter =
                            graph.node(callee, target.clone(), size, overridden(&explicit, callee, &target)?)?;
                        if let Some((target, size)) = value_target(structure, &argument.value) {
                            let value =
                                graph.node(caller, target.clone(), size, overridden(&explicit, caller, &target)?)?;
                            graph.link(parameter, value, caller, at, "callee parameter to caller argument");
                            graph.link(value, parameter, caller, at, "caller argument to callee parameter");
                        } else if let Some((global, ty)) = global_source_type(&explicit, &argument.value) {
                            let reason = format!(
                                "explicit native global/data {} source {global:#x}",
                                if argument.value.status == CallValueStatus::GlobalAddress {
                                    "address"
                                } else {
                                    "value"
                                }
                            );
                            if graph.nodes[parameter].hard {
                                graph.skipped.push(PropagationSkip {
                                    function: callee,
                                    target: Some(graph.nodes[parameter].target.clone()),
                                    reason: "analyst target type preserved".into(),
                                });
                                if supported_type(ty)
                                    && graph.nodes[parameter].size == ty.size
                                    && !graph.nodes[parameter].facts.contains_key(&ty.name)
                                {
                                    merge_evidence(
                                        graph.nodes[parameter].rejected.entry(ty.name.clone()).or_default(),
                                        &[TypeHintEvidence { function: caller, at, reason }],
                                    );
                                }
                            } else {
                                graph.seed_from(parameter, ty, caller, at, &reason);
                            }
                        } else if let Some(global) = argument.value.global_address {
                            graph.unavailable(
                                caller,
                                format!(
                                    "call {at:#x}: global/data {global:#x} lacks explicit typing or value/address proof"
                                ),
                            );
                        } else {
                            graph.unavailable(
                                caller,
                                format!(
                                    "call {at:#x}: input {} computed/constant/unmapped argument unsupported",
                                    argument.input_index
                                ),
                            );
                        }
                    }
                } else {
                    graph.unavailable(caller, format!("call {at:#x}: native argument evidence unavailable"));
                }
                if let Some(result) = &call.result {
                    let return_node = graph.node(
                        callee,
                        TypeHintTarget::Return,
                        destination.signature.return_type.size,
                        explicit.signatures().contains_key(&callee),
                    )?;
                    if let Some((target, size)) = value_target(structure, &result.value) {
                        let value =
                            graph.node(caller, target.clone(), size, overridden(&explicit, caller, &target)?)?;
                        graph.link(return_node, value, caller, at, "callee return to caller result");
                    }
                    if result.direct_return {
                        let caller_return = graph.node(
                            caller,
                            TypeHintTarget::Return,
                            structure.signature.return_type.size,
                            explicit.signatures().contains_key(&caller),
                        )?;
                        graph.link(caller_return, return_node, caller, at, "direct caller return to callee return");
                        graph.link(return_node, caller_return, caller, at, "callee return to direct caller return");
                    } else if has_return_source && result_target.is_none() {
                        graph.unavailable(
                            caller,
                            format!("call {at:#x}: native result has no canonical owner or proven direct-return flow"),
                        );
                    }
                } else if has_return_source {
                    graph.unavailable(caller, format!("call {at:#x}: native call-result evidence unavailable"));
                }
            }
        }
        graph.solve();
        let mut candidates = Vec::new();
        let mut conflicts = Vec::new();
        for node in &graph.nodes {
            if node.facts.is_empty() {
                continue;
            }
            if node.hard && node.rejected.is_empty() {
                continue;
            }
            if node.facts.len() > 1 || (node.hard && !node.rejected.is_empty()) {
                conflicts.push(PropagationConflict {
                    function: node.function,
                    target: node.target.clone(),
                    alternatives: node
                        .facts
                        .iter()
                        .chain(node.rejected.iter())
                        .map(|(ty, evidence)| DerivedTypeHint {
                            target: node.target.clone(),
                            data_type: ty.clone(),
                            evidence: evidence.clone(),
                        })
                        .collect(),
                });
            } else {
                let (ty, evidence) = node.facts.first_key_value().expect("one source type");
                candidates.push(PropagationCandidate {
                    function: node.function,
                    target: node.target.clone(),
                    data_type: ty.clone(),
                    evidence: evidence.clone(),
                });
            }
        }
        candidates.sort_by_key(|candidate| (candidate.function, target_key(&candidate.target)));
        conflicts.sort_by_key(|conflict| (conflict.function, target_key(&conflict.target)));
        if candidates.len() + conflicts.iter().map(|conflict| conflict.alternatives.len()).sum::<usize>()
            > request.max_candidates
        {
            return Err(ApiError::Invalid("propagation candidate budget exceeded; reduce the function context".into()));
        }
        graph.skipped.sort_by_key(|skip| (skip.function, skip.target.as_ref().map(target_key), skip.reason.clone()));
        graph.skipped.dedup_by(|a, b| a.function == b.function && a.target == b.target && a.reason == b.reason);
        let mut by_function: BTreeMap<u64, Vec<DerivedTypeHint>> = BTreeMap::new();
        let mut unsupported = BTreeSet::new();
        for candidate in &candidates {
            if candidate.evidence.len() > 16 {
                graph
                    .limitations
                    .insert(format!("evidence budget exceeds 16 at {:#x}; candidate omitted", candidate.function));
                unsupported.insert(candidate.function);
                continue;
            }
            by_function.entry(candidate.function).or_default().push(DerivedTypeHint {
                target: candidate.target.clone(),
                data_type: candidate.data_type.clone(),
                evidence: candidate.evidence.clone(),
            });
        }
        by_function.retain(|function, _| !unsupported.contains(function));
        let selected = select_native_candidates(&explicit, &fingerprint, &by_function, |candidate, function| {
            check_cancellation(cancellation)?;
            self.decompile_annotation_candidate_with_operations(
                state,
                options,
                candidate,
                function,
                NativeDecompileContext { admitted: Some(context), cancellation, ..Default::default() },
            )
            .and_then(|output| validate_output_targets(candidate, function, &output.structure))
        })?;
        check_cancellation(cancellation)?;
        unsupported.extend(selected.rejected.keys().copied());
        for (function, error) in selected.rejected {
            graph.limitations.insert(format!("native soft-hint validation unavailable at {function:#x}: {error}"));
        }
        by_function.retain(|function, _| !unsupported.contains(function));
        let combined =
            validate_combined_candidates(&explicit, &fingerprint, &mut by_function, |candidate, function| {
                check_cancellation(cancellation)?;
                self.decompile_annotation_candidate_with_operations(
                    state,
                    options,
                    candidate,
                    function,
                    NativeDecompileContext { admitted: Some(context), cancellation, ..Default::default() },
                )
                .and_then(|output| validate_output_targets(candidate, function, &output.structure))
            })?;
        check_cancellation(cancellation)?;
        for (function, reason) in combined {
            unsupported.insert(function);
            graph.limitations.insert(format!("native soft-hint validation unavailable at {function:#x}: {reason}"));
        }
        candidates.retain(|candidate| {
            if unsupported.contains(&candidate.function) {
                graph.skipped.push(PropagationSkip {
                    function: candidate.function,
                    target: Some(candidate.target.clone()),
                    reason: "candidate omitted; see hint_edits for payload replacement or removal".into(),
                });
                false
            } else {
                true
            }
        });
        let next_bootstrap = candidate_operations(&candidates);
        if source_fingerprint(self, options, annotations)? != fingerprint {
            return Err(ApiError::Invalid("propagation source changed during native analysis".into()));
        }
        let counts = PropagationCounts {
            functions: context.len(),
            edges,
            candidates: candidates.len(),
            applied: 0,
            skipped: graph.skipped.len(),
            conflicts: conflicts.len(),
            ..Default::default()
        };
        let result = PropagationResult {
            address,
            source_fingerprint: fingerprint,
            apply: false,
            persisted: false,
            hint_edits: Vec::new(),
            candidates,
            applied: Vec::new(),
            skipped: graph.skipped,
            conflicts,
            limitations: graph.limitations.into_iter().collect(),
            counts,
        };
        Ok((result, structures.keys().copied().collect(), next_bootstrap))
    }
}

fn prepare_hint_receipt(
    annotations: &Annotations,
    functions: &BTreeSet<u64>,
    apply: bool,
    result: &mut PropagationResult,
) -> Result<(), ApiError> {
    let mut grouped = DerivedHints::new();
    for candidate in &result.candidates {
        grouped.entry(candidate.function).or_default().push(DerivedTypeHint {
            target: candidate.target.clone(),
            data_type: candidate.data_type.clone(),
            evidence: candidate.evidence.clone(),
        });
    }
    let mut edits = Vec::new();
    for &function in functions {
        let previous = annotations
            .type_hints()
            .get(&function)
            .map(|text| parse_type_hints(text))
            .transpose()
            .map_err(ApiError::Invalid)?;
        let value = grouped
            .remove(&function)
            .map(|hints| {
                let encoded = encode_type_hints(&TypeHintAnnotation {
                    source_fingerprint: result.source_fingerprint.clone(),
                    hints,
                })
                .map_err(ApiError::Invalid)?;
                parse_type_hints(&encoded).map_err(ApiError::Invalid)
            })
            .transpose()?;
        if previous != value {
            edits.push(PropagationHintEdit { function, previous, value });
        }
    }
    edits.sort_by_key(|edit| edit.function);
    result.apply = apply;
    result.persisted = false;
    result.counts.planned_hint_edits = edits.len();
    result.counts.persisted_hint_edits = 0;
    result.counts.planned_hint_clears = edits.iter().filter(|edit| edit.value.is_none()).count();
    result.hint_edits = edits;
    Ok(())
}

#[derive(Debug, Default)]
struct CandidateSelection {
    retained: BTreeSet<u64>,
    rejected: BTreeMap<u64, String>,
}

enum NativeProbe<T> {
    Supported(T),
    Refused(String),
}

fn native_probe<T>(result: Result<T, ApiError>) -> Result<NativeProbe<T>, ApiError> {
    match result {
        Ok(value) => Ok(NativeProbe::Supported(value)),
        Err(ApiError::NativeTypeHintUnsupported(reason)) => Ok(NativeProbe::Refused(reason)),
        Err(error) => Err(error),
    }
}

fn run_native_passes(
    functions: usize,
    cancellation: Option<&std::sync::atomic::AtomicBool>,
    mut analyze: impl FnMut(&[rampage_decompiler::worker::WorkerOperation]) -> Result<NativePassResult, ApiError>,
) -> Result<(PropagationResult, BTreeSet<u64>), ApiError> {
    let mut bootstrap = Vec::new();
    let mut latest: Option<(PropagationResult, BTreeSet<u64>)> = None;
    for pass in 0..=functions {
        check_cancellation(cancellation)?;
        let analyzed = analyze(&bootstrap);
        check_cancellation(cancellation)?;
        let (mut result, admitted, next) = match native_probe(analyzed)? {
            NativeProbe::Supported(result) => result,
            NativeProbe::Refused(reason) => {
                let Some((mut result, admitted)) = latest else {
                    return Err(ApiError::NativeTypeHintUnsupported(reason));
                };
                result.limitations.push(format!("native prototype-shape bootstrap unavailable: {reason}"));
                return Ok((result, admitted));
            }
        };
        let changed = serde_json::to_value(&next).map_err(|error| ApiError::Invalid(error.to_string()))?
            != serde_json::to_value(&bootstrap).map_err(|error| ApiError::Invalid(error.to_string()))?;
        if changed && pass == functions {
            result.limitations.push("bounded native prototype-shape pass budget reached; context incomplete".into());
        }
        latest = Some((result, admitted));
        if !changed {
            break;
        }
        bootstrap = next;
    }
    Ok(latest.expect("at least one bounded derivation pass"))
}

fn analyze_native_context(
    functions: &BTreeSet<u64>,
    cancellation: Option<&std::sync::atomic::AtomicBool>,
    mut analyze: impl FnMut(u64) -> Result<StructuredResult, ApiError>,
    graph: &mut Graph,
) -> Result<BTreeMap<u64, StructuredResult>, ApiError> {
    let mut structures = BTreeMap::new();
    for &function in functions {
        check_cancellation(cancellation)?;
        let analyzed = analyze(function);
        check_cancellation(cancellation)?;
        match native_probe(analyzed)? {
            NativeProbe::Supported(structure) => {
                structures.insert(function, structure);
            }
            NativeProbe::Refused(reason) => {
                graph.unavailable(function, format!("native type context unavailable at {function:#x}: {reason}"));
            }
        }
    }
    Ok(structures)
}

fn staged_hints(
    annotations: &Annotations,
    fingerprint: &str,
    functions: &DerivedHints,
) -> Result<Annotations, ApiError> {
    let changes = functions
        .iter()
        .map(|(&function, hints)| {
            let value = encode_type_hints(&TypeHintAnnotation {
                source_fingerprint: fingerprint.to_owned(),
                hints: hints.clone(),
            })
            .map_err(ApiError::Invalid)?;
            Ok((Field::TypeHint, function, Some(value)))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut staged = annotations.snapshot();
    staged.set_batch_validated(&changes, |_| Ok(())).map_err(ApiError::Invalid)?;
    Ok(staged)
}

fn select_native_candidates(
    annotations: &Annotations,
    fingerprint: &str,
    proposals: &DerivedHints,
    mut validate: impl FnMut(&Annotations, u64) -> Result<(), ApiError>,
) -> Result<CandidateSelection, ApiError> {
    let mut selected = CandidateSelection::default();
    let mut accepted = DerivedHints::new();
    for _ in 0..=proposals.len() {
        let before = selected.retained.len();
        for (&function, hints) in proposals {
            if selected.retained.contains(&function) {
                continue;
            }
            let mut trial = accepted.clone();
            trial.insert(function, hints.clone());
            let staged = staged_hints(annotations, fingerprint, &trial)?;
            match native_probe(validate(&staged, function))? {
                NativeProbe::Supported(()) => {
                    accepted = trial;
                    selected.retained.insert(function);
                    selected.rejected.remove(&function);
                }
                NativeProbe::Refused(reason) => {
                    selected.rejected.insert(function, reason);
                }
            }
        }
        if selected.retained.len() == before {
            break;
        }
    }
    Ok(selected)
}

fn validate_combined_candidates(
    annotations: &Annotations,
    fingerprint: &str,
    proposals: &mut DerivedHints,
    mut validate: impl FnMut(&Annotations, u64) -> Result<(), ApiError>,
) -> Result<BTreeMap<u64, String>, ApiError> {
    let mut rejected = BTreeMap::new();
    for _ in 0..=proposals.len() {
        proposals.retain(|function, _| !rejected.contains_key(function));
        let staged = staged_hints(annotations, fingerprint, proposals)?;
        let before = rejected.len();
        for function in proposals.keys() {
            if let NativeProbe::Refused(reason) = native_probe(validate(&staged, *function))? {
                rejected.insert(*function, reason);
            }
        }
        if rejected.len() == before {
            break;
        }
    }
    Ok(rejected)
}

fn candidate_operations(candidates: &[PropagationCandidate]) -> Vec<rampage_decompiler::worker::WorkerOperation> {
    let mut functions: BTreeMap<u64, Vec<rampage_decompiler::TypeHint>> = BTreeMap::new();
    for candidate in candidates {
        let hint = match &candidate.target {
            TypeHintTarget::Local { storage } | TypeHintTarget::Parameter { storage, .. } => {
                rampage_decompiler::TypeHint::Local { storage: storage.clone(), data_type: candidate.data_type.clone() }
            }
            TypeHintTarget::Return => rampage_decompiler::TypeHint::Return { data_type: candidate.data_type.clone() },
        };
        functions.entry(candidate.function).or_default().push(hint);
    }
    functions
        .into_iter()
        .map(|(address, hints)| rampage_decompiler::worker::WorkerOperation::TypeHints { address, hints })
        .collect()
}

fn validate_output_targets(
    annotations: &Annotations,
    function: u64,
    structure: &StructuredResult,
) -> Result<(), ApiError> {
    let Some(text) = annotations.type_hints().get(&function) else { return Ok(()) };
    validate_hint_targets(&parse_type_hints(text).map_err(ApiError::Invalid)?.hints, function, structure)
}

pub(crate) fn validate_replayed_targets(
    project: &Project,
    options: &DecompilerOptions,
    annotations: &Annotations,
    function: u64,
    structure: &StructuredResult,
) -> Result<(), ApiError> {
    let (hints, _) = replay_hints(project, options, annotations, Some(function))?;
    if let Some(hints) = hints.get(&function) {
        validate_hint_targets(hints, function, structure)?;
    }
    Ok(())
}

fn validate_hint_targets(
    hints: &[DerivedTypeHint],
    function: u64,
    structure: &StructuredResult,
) -> Result<(), ApiError> {
    for hint in hints {
        let actual = match &hint.target {
            TypeHintTarget::Return => Some(&structure.signature.return_type),
            TypeHintTarget::Parameter { index, storage } => structure
                .signature
                .parameters
                .get(*index as usize)
                .filter(|parameter| {
                    VariableStorage::try_from(&parameter.storage).ok().as_ref() == Some(storage)
                        && parameter.data_type.size == storage.size
                })
                .map(|parameter| &parameter.data_type),
            TypeHintTarget::Local { storage } => {
                let mut matches = structure.variables.iter().filter(|variable| {
                    variable.storage.len() == 1
                        && VariableStorage::try_from(&variable.storage[0]).ok().as_ref() == Some(storage)
                        && variable.data_type.size == storage.size
                });
                match (matches.next(), matches.next()) {
                    (Some(variable), None) => Some(&variable.data_type),
                    _ => None,
                }
            }
        };
        let Some(actual) = actual else {
            return Err(ApiError::NativeTypeHintUnsupported(format!(
                "native soft hint changed or lost canonical target identity at {function:#x}"
            )));
        };
        if !crate::decompile::type_tokens(&actual.name).eq(crate::decompile::type_tokens(&hint.data_type)) {
            return Err(ApiError::NativeTypeHintUnsupported(format!(
                "native soft hint type was not retained at {function:#x}: expected {}, recovered {}",
                hint.data_type, actual.name,
            )));
        }
    }
    Ok(())
}
