//! Checked producer facts and independently measured native counterparts, retained separately from C text.

mod graph;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rampage_decompiler::worker::WorkerOperation;
use rampage_decompiler::{DataOrganization, DecompilerOptions, NamedType};
use rampage_loaders::debug_types::DebugTypeReport;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::annotations::{Annotations, Field, LibraryDeclaration, TypeLibrarySource};
use crate::{ApiError, Project};

const SIGNATURE_MAGIC: &str = "!rampage-debug-types-signature-v1\n";
const MAX_PROOF_BYTES: usize = 1024 * 1024;

pub(crate) fn is_signature_seal(text: &str) -> bool {
    text.starts_with(SIGNATURE_MAGIC)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypesRequest {
    pub pdb: Option<PathBuf>,
    #[serde(default)]
    pub apply: bool,
    pub review_sha256: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    32
}

impl Default for DebugTypesRequest {
    fn default() -> Self {
        Self { pdb: None, apply: false, review_sha256: None, offset: 0, limit: default_limit() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypesSignature {
    pub address: u64,
    pub declaration: String,
    pub producer_type_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTypesManifest {
    pub id: String,
    pub review_sha256: String,
    pub image_sha256: String,
    pub specification_sha256: String,
    pub options: Value,
    pub language_id: String,
    pub organization: DataOrganization,
    pub default_calling_convention: String,
    #[serde(with = "proof_json")]
    pub producer: Value,
    pub library_names: Vec<String>,
    pub declarations: String,
    pub declarations_sha256: String,
    #[serde(with = "proof_json")]
    pub expected_native_named_types: Vec<NamedType>,
    pub signatures: Vec<DebugTypesSignature>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proofs {
    version: u32,
    imports: Vec<DebugTypesManifest>,
}

mod proof_json {
    use super::MAX_PROOF_BYTES;
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    pub(super) fn validate(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
        *nodes += 1;
        if depth > 48 || *nodes > 65_536 {
            return Err("framed debug proof exceeds depth/node bounds (48/65536)".into());
        }
        match value {
            Value::String(text) if text.contains('\0') => return Err("framed debug proof contains NUL".into()),
            Value::Array(values) => {
                for value in values {
                    validate(value, depth + 1, nodes)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if key.contains('\0') {
                        return Err("framed debug proof key contains NUL".into());
                    }
                    validate(value, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn serialize<T: Serialize, S: serde::Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        let value = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
        validate(&value, 0, &mut 0).map_err(serde::ser::Error::custom)?;
        let text = serde_json::to_string(&value).map_err(serde::ser::Error::custom)?;
        if text.len() > MAX_PROOF_BYTES {
            return Err(serde::ser::Error::custom("framed debug proof exceeds 1 MiB"));
        }
        serializer.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, T: DeserializeOwned, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() > MAX_PROOF_BYTES {
            return Err(serde::de::Error::custom("framed debug proof exceeds 1 MiB"));
        }
        let value: Value = serde_json::from_str(&text).map_err(serde::de::Error::custom)?;
        validate(&value, 0, &mut 0).map_err(serde::de::Error::custom)?;
        serde_json::from_value(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugTypesDetail {
    pub producer_type_id: String,
    pub original_name: Option<String>,
    pub emitted_name: Option<String>,
    pub applicable: bool,
    pub reasons: Vec<String>,
    pub producer: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_evidence: Option<Value>,
    pub native: Option<NamedType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebugTypesImport {
    pub applied: bool,
    pub review_sha256: String,
    pub manifest_id: Option<String>,
    pub total: usize,
    pub applicable_types: usize,
    pub applicable_signatures: usize,
    pub preserved_signatures: usize,
    pub imported_types: usize,
    pub imported_signatures: usize,
    pub offset: usize,
    pub limit: usize,
    pub next_offset: Option<usize>,
    pub details: Vec<DebugTypesDetail>,
    pub warnings: Vec<String>,
}

fn invalid(message: impl std::fmt::Display) -> ApiError {
    ApiError::Invalid(format!("checked debug types: {message}"))
}

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn hash_text(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn json<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(invalid)
}

fn option_identity(options: &DecompilerOptions) -> Value {
    serde_json::json!({"platform": format!("{:?}", options.platform),
        "compiler": options.compiler, "arm_be8": options.arm_be8})
}

fn producer_evidence(ty: &rampage_loaders::debug_types::DebugType) -> Result<Option<Value>, ApiError> {
    let rampage_loaders::debug_types::DebugTypeKind::Unsupported { description } = &ty.kind else {
        return Ok(None);
    };
    if description.len() > MAX_PROOF_BYTES {
        return Err(invalid("unsupported producer evidence exceeds 1 MiB"));
    }
    let Ok(evidence) = serde_json::from_str::<Value>(description) else { return Ok(None) };
    if !evidence.is_object() {
        return Ok(None);
    }
    proof_json::validate(&evidence, 0, &mut 0).map_err(invalid)?;
    Ok(Some(evidence))
}

fn manifests(annotations: &Annotations) -> Result<Vec<DebugTypesManifest>, ApiError> {
    let Some(text) = annotations.debug_types().get(&0) else { return Ok(Vec::new()) };
    crate::annotations::parse_debug_types(text).map_err(invalid)?;
    let proofs: Proofs = serde_json::from_str(text).map_err(invalid)?;
    if proofs.version != 1 || proofs.imports.is_empty() || proofs.imports.len() > 16 {
        return Err(invalid("invalid proof envelope"));
    }
    Ok(proofs.imports)
}

fn proof_value(imports: Vec<DebugTypesManifest>) -> Result<Option<String>, ApiError> {
    if imports.is_empty() {
        return Ok(None);
    }
    let text = json(&Proofs { version: 1, imports })?;
    if text.len() > MAX_PROOF_BYTES {
        return Err(invalid("proof exceeds 1 MiB"));
    }
    crate::annotations::parse_debug_types(&text)
        .map_err(|error| invalid(format!("proof envelope structural preflight ({} bytes): {error}", text.len())))?;
    Ok(Some(text))
}

fn manifest_identity(manifest: &DebugTypesManifest) -> Result<String, ApiError> {
    let mut canonical = manifest.clone();
    canonical.id.clear();
    canonical.review_sha256.clear();
    Ok(digest(json(&canonical)?.as_bytes()))
}

fn check_manifest(manifest: &DebugTypesManifest) -> Result<(), ApiError> {
    if manifest.id != manifest_identity(manifest)?
        || !hash_text(&manifest.review_sha256)
        || !hash_text(&manifest.image_sha256)
        || !hash_text(&manifest.specification_sha256)
        || manifest.declarations_sha256 != digest(manifest.declarations.as_bytes())
        || manifest.declarations.len() > 64 * 1024
        || manifest.signatures.len() > 256
    {
        return Err(invalid("invalid manifest identity/declaration bounds"));
    }
    let producer: DebugTypeReport = serde_json::from_value(manifest.producer.clone()).map_err(invalid)?;
    validate_provenance(&producer, &manifest.image_sha256)?;
    let plan = graph::prepare_for_target(&producer, &manifest.language_id, manifest.organization)?;
    if plan.declarations != manifest.declarations || plan.names != manifest.library_names {
        return Err(invalid("retained producer facts do not justify the owned declarations"));
    }
    graph::compare(&producer, &plan, &manifest.expected_native_named_types, &manifest.default_calling_convention)?;
    let names: BTreeSet<_> = manifest.expected_native_named_types.iter().map(|ty| &ty.name).collect();
    if names.len() != manifest.library_names.len() || manifest.library_names.iter().any(|name| !names.contains(name)) {
        return Err(invalid("native proof omits or adds an owned type"));
    }
    let mut addresses = BTreeSet::new();
    let mut producer_address_counts = BTreeMap::new();
    for fact in &producer.signatures {
        *producer_address_counts.entry(fact.address).or_insert(0usize) += 1;
    }
    for signature in &manifest.signatures {
        if !addresses.insert(signature.address)
            || producer_address_counts.get(&signature.address) != Some(&1)
            || !producer.signatures.iter().any(|fact| {
                fact.address == signature.address
                    && fact.type_id == signature.producer_type_id
                    && fact.unsupported.is_empty()
            })
            || graph::signature(&producer, &plan, &signature.producer_type_id)? != signature.declaration
        {
            return Err(invalid("signature is not justified by retained producer evidence"));
        }
    }
    Ok(())
}

fn validate_provenance(producer: &DebugTypeReport, image_sha256: &str) -> Result<(), ApiError> {
    use rampage_loaders::debug_types::DebugSourceKind;
    let provenance = &producer.provenance;
    if !hash_text(&provenance.source_sha256)
        || producer.types.iter().any(|ty| ty.origin.source != provenance.source)
        || producer.signatures.iter().any(|signature| signature.origin.source != provenance.source)
    {
        return Err(invalid("producer source SHA/origin source kind is inconsistent"));
    }
    match provenance.source {
        DebugSourceKind::Dwarf => {
            if provenance.source_sha256 != image_sha256 || provenance.pdb_guid.is_some() || provenance.pdb_age.is_some()
            {
                return Err(invalid("embedded DWARF provenance does not match the selected image SHA"));
            }
        }
        DebugSourceKind::Pdb => {
            if provenance.pdb_guid.as_ref().is_none_or(|guid| {
                guid.len() != 32 || !guid.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) || provenance.pdb_age.is_none_or(|age| age == 0)
            {
                return Err(invalid("PDB provenance requires a lowercase GUID, nonzero age and source SHA"));
            }
        }
    }
    Ok(())
}

/// Validates ownership and retained facts without opening any external debug source.
pub(crate) fn validate_replay_source(project: &Project, annotations: &Annotations) -> Result<(), ApiError> {
    validate_retained(annotations)?;
    let proofs = manifests(annotations)?;
    if proofs.is_empty() {
        return Ok(());
    }
    let image = rampage_arch::hex::bytes(&crate::debug_layout_import::image_digest(project)?);
    let specifications = crate::debug_layout_import::current_specification_digest()?;
    for proof in proofs {
        if proof.image_sha256 != image || proof.specification_sha256 != specifications {
            return Err(invalid("proof does not match the selected image/specification"));
        }
        let producer: DebugTypeReport = serde_json::from_value(proof.producer.clone()).map_err(invalid)?;
        validate_selected_pdb_identity(&project.binary, &producer)?;
    }
    validate_signature_entries(project, annotations)?;
    Ok(())
}

fn validate_selected_pdb_identity(
    binary: &rampage_loaders::Binary,
    producer: &DebugTypeReport,
) -> Result<(), ApiError> {
    if producer.provenance.source == rampage_loaders::debug_types::DebugSourceKind::Pdb {
        let identity = rampage_loaders::pdb::selected_image_identity(binary).map_err(invalid)?;
        if producer.provenance.pdb_guid.as_deref() != Some(rampage_arch::hex::bytes(&identity.guid).as_str())
            || producer.provenance.pdb_age != Some(identity.age)
        {
            return Err(invalid("retained PDB GUID/age differs from the selected PE CodeView identity"));
        }
    }
    Ok(())
}

fn validate_signature_entries(project: &Project, annotations: &Annotations) -> Result<(), ApiError> {
    if !annotations.signatures().values().any(|text| text.starts_with(SIGNATURE_MAGIC)) {
        return Ok(());
    }
    let entries = signature_entry_witnesses(project)?;
    for (&address, text) in annotations.signatures() {
        if text.starts_with(SIGNATURE_MAGIC) {
            validate_signature_entry(project, address, &entries)?;
        }
    }
    Ok(())
}

fn signature_entry_witnesses(project: &Project) -> Result<BTreeSet<u64>, ApiError> {
    let binary = &project.binary;
    if binary.symbols.len() > 8192 || binary.exports.len() > 8192 || binary.function_starts.len() > 8192 {
        return Err(invalid("signature entry metadata exceeds checked replay bounds"));
    }
    let entries: BTreeSet<_> = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
        .map(|symbol| symbol.address)
        .chain(binary.exports.iter().map(|export| export.address))
        .chain(binary.function_starts.iter().copied())
        .chain(binary.entry)
        .collect();
    Ok(entries)
}

fn validate_signature_entry(project: &Project, address: u64, entries: &BTreeSet<u64>) -> Result<(), ApiError> {
    let binary = &project.binary;
    if !entries.contains(&address)
        || !binary.is_code(address)
        || binary.read(address, 1).is_none()
        || !binary.segment_containing(address).is_some_and(|segment| segment.perms.execute && segment.perms.read)
    {
        return Err(invalid(format!(
            "sealed signature {address:#x} lacks an exact file-backed executable entry witness"
        )));
    }
    Ok(())
}

/// Annotation collection boundary hook: no project, native calls, filesystem reads, or mutation.
pub(crate) fn validate_retained_proofs(annotations: &Annotations) -> Result<(), String> {
    validate_retained(annotations).map_err(|error| error.to_string())
}

fn validate_retained(annotations: &Annotations) -> Result<(), ApiError> {
    let proofs = manifests(annotations)?;
    let units = crate::type_library::stored_declarations(annotations)?;
    if proofs.is_empty() {
        if units.iter().any(|unit| unit.source.as_ref().is_some_and(|source| source.kind == "checked_debug_types"))
            || annotations.signatures().values().any(|text| text.starts_with(SIGNATURE_MAGIC))
        {
            return Err(invalid("checked source/signature is missing its separate proof"));
        }
        return Ok(());
    }
    let mut ids = BTreeSet::new();
    for proof in &proofs {
        check_manifest(proof)?;
        if !ids.insert(&proof.id) {
            return Err(invalid("duplicate retained proof identity"));
        }
        let owned: Vec<_> = units
            .iter()
            .filter(|unit| {
                unit.source
                    .as_ref()
                    .is_some_and(|source| source.kind == "checked_debug_types" && source.identity == proof.id)
            })
            .collect();
        if owned.len() != 1
            || owned[0].names != proof.library_names
            || owned[0].declarations != proof.declarations
            || owned[0].packing.is_some()
        {
            return Err(invalid("proof ownership/declaration differs from the retained library unit"));
        }
    }
    for unit in &units {
        if let Some(source) = &unit.source
            && source.kind == "checked_debug_types"
            && !ids.contains(&source.identity)
        {
            return Err(invalid("library references a missing proof"));
        }
    }
    for (&address, text) in annotations.signatures() {
        signature_declaration_at(text, Some(address), annotations)?;
    }
    Ok(())
}

pub(crate) fn validate_options(annotations: &Annotations, options: &DecompilerOptions) -> Result<(), ApiError> {
    for proof in manifests(annotations)? {
        if proof.options != option_identity(options) {
            return Err(invalid("compiler options differ from retained proof"));
        }
    }
    Ok(())
}

/// Whole-unit removal is allowed only after every sealed signature has been explicitly removed/replaced.
pub(crate) fn library_transition_proofs(
    annotations: &Annotations,
    units: &[LibraryDeclaration],
) -> Result<Option<String>, ApiError> {
    let mut retained = Vec::new();
    for proof in manifests(annotations)? {
        let owned = units.iter().find(|unit| {
            unit.source
                .as_ref()
                .is_some_and(|source| source.kind == "checked_debug_types" && source.identity == proof.id)
        });
        if let Some(unit) = owned {
            if unit.names != proof.library_names || unit.declarations != proof.declarations || unit.packing.is_some() {
                return Err(invalid("checked definitions cannot be replaced; explicitly remove the whole owned unit"));
            }
            retained.push(proof);
        } else {
            let marker = format!("{SIGNATURE_MAGIC}{}\n", proof.id);
            if annotations.signatures().values().any(|text| text.starts_with(&marker))
                || units.iter().any(|unit| unit.names.iter().any(|name| proof.library_names.contains(name)))
            {
                return Err(invalid(
                    "cannot remove/replace a checked unit while its names or sealed signatures remain",
                ));
            }
        }
    }
    proof_value(retained)
}

/// Must be inserted after all library/type parsing, before globals and prototypes.
pub(crate) fn operations(annotations: &Annotations) -> Result<Vec<WorkerOperation>, ApiError> {
    Ok(manifests(annotations)?
        .into_iter()
        .map(|proof| WorkerOperation::AssertNamedTypes {
            language_id: proof.language_id,
            organization: proof.organization,
            types: proof.expected_native_named_types,
            expected_context: Some(proof.specification_sha256),
        })
        .collect())
}

pub(crate) fn signature_declaration<'a>(text: &'a str, annotations: &Annotations) -> Result<&'a str, ApiError> {
    signature_declaration_at(text, None, annotations)
}

fn signature_declaration_at<'a>(
    text: &'a str,
    address: Option<u64>,
    annotations: &Annotations,
) -> Result<&'a str, ApiError> {
    let Some(sealed) = text.strip_prefix(SIGNATURE_MAGIC) else { return Ok(text) };
    if text.len() > 8192 {
        return Err(invalid("oversized sealed signature"));
    }
    let (id, declaration) = sealed.split_once('\n').ok_or_else(|| invalid("invalid signature seal"))?;
    let proofs = manifests(annotations)?;
    let proof = proofs.iter().find(|proof| proof.id == id).ok_or_else(|| invalid("missing signature proof"))?;
    if !proof.signatures.iter().any(|signature| {
        signature.declaration == declaration && address.is_none_or(|address| signature.address == address)
    }) {
        return Err(invalid("sealed declaration/address does not match retained proof"));
    }
    Ok(declaration)
}

fn seal(proof: &DebugTypesManifest, signature: &DebugTypesSignature) -> String {
    format!("{SIGNATURE_MAGIC}{}\n{}", proof.id, signature.declaration)
}

struct Pending {
    receipt: DebugTypesImport,
    changes: Vec<(Field, u64, Option<String>)>,
    source: Source,
}

#[derive(Debug, PartialEq, Eq)]
struct Source {
    report: DebugTypeReport,
    pdb: Option<rampage_loaders::pdb::PdbProvenance>,
}

fn source(project: &Project, request: &DebugTypesRequest) -> Result<Source, ApiError> {
    crate::debug_layout_import::check_backing(project)?;
    let source = if let Some(path) = &request.pdb {
        let (report, provenance) =
            rampage_loaders::pdb::matched_types_checked(path, &project.binary).map_err(invalid)?;
        provenance.validate_current().map_err(invalid)?;
        Source { report, pdb: Some(provenance) }
    } else {
        Source { report: rampage_loaders::debug::type_graph(&project.binary).map_err(invalid)?, pdb: None }
    };
    crate::debug_layout_import::check_backing(project)?;
    Ok(source)
}

impl Project {
    pub fn import_debug_types(&self, request: &DebugTypesRequest) -> Result<DebugTypesImport, ApiError> {
        self.import_debug_types_with_preflight(request, |_| Ok(()))
    }

    /// Preview uses only read snapshots; applying recomputes the whole plan under the staged annotation lock.
    pub fn import_debug_types_with_preflight(
        &self,
        request: &DebugTypesRequest,
        preflight: impl FnOnce(&DebugTypesImport) -> Result<(), ApiError>,
    ) -> Result<DebugTypesImport, ApiError> {
        if request.limit == 0
            || request.limit > 256
            || request.review_sha256.as_ref().is_some_and(|hash| !hash_text(hash))
        {
            return Err(invalid("page limit must be 1..256; review hash must contain 64 hex characters"));
        }
        if request.apply && request.review_sha256.is_none() {
            return Err(invalid("apply requires a fresh review_sha256"));
        }
        crate::debug_layout_import::check_backing(self)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        if !request.apply {
            let snapshot = self.annotations.read().expect("annotations lock").checked_read_snapshot()?;
            let pending = self.prepare_debug_types(&state, &options, &snapshot, request)?;
            preflight(&pending.receipt)?;
            return Ok(pending.receipt);
        }
        self.annotations.write().expect("annotations lock").locked_staged_checked(|annotations| {
            let mut pending = self.prepare_debug_types(&state, &options, annotations, request)?;
            if request.review_sha256.as_ref() != Some(&pending.receipt.review_sha256) {
                return Err(invalid("whole-plan review changed; preview again"));
            }
            pending.receipt.applied = true;
            pending.receipt.imported_types = pending.receipt.applicable_types;
            pending.receipt.imported_signatures = pending.receipt.applicable_signatures;
            let mut preflight = Some(preflight);
            if pending.changes.is_empty() {
                preflight.take().expect("single preflight")(&pending.receipt)?;
                return Ok(pending.receipt);
            }
            annotations
                .set_batch_validated(&pending.changes, |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)?;
                    preflight.take().expect("single preflight")(&pending.receipt).map_err(|error| error.to_string())?;
                    if source(self, request).map_err(|error| error.to_string())? != pending.source {
                        return Err("debug source changed during commit validation".to_owned());
                    }
                    crate::debug_layout_import::validate_replay_source(self, candidate)
                        .map_err(|error| error.to_string())?;
                    validate_replay_source(self, candidate).map_err(|error| error.to_string())?;
                    Ok(())
                })
                .map_err(invalid)?;
            Ok(pending.receipt)
        })
    }

    fn prepare_debug_types(
        &self,
        state: &crate::decompile::DecompilerState,
        options: &DecompilerOptions,
        annotations: &Annotations,
        request: &DebugTypesRequest,
    ) -> Result<Pending, ApiError> {
        validate_replay_source(self, annotations)?;
        validate_options(annotations, options)?;
        let image = rampage_arch::hex::bytes(&crate::debug_layout_import::image_digest(self)?);
        let specifications = crate::debug_layout_import::current_specification_digest()?;
        if self.binary.symbols.len() > 8192
            || self.binary.exports.len() > 8192
            || self.binary.function_starts.len() > 8192
            || self.binary.imports.len() > 1024
            || self.binary.import_slots.len() > 1024
            || self.binary.segments.len() > 256
        {
            return Err(invalid("selected image metadata exceeds checked native-work bounds"));
        }
        let source_evidence = source(self, request)?;
        let producer = &source_evidence.report;
        validate_provenance(producer, &image)?;
        let current = self.inspect_types(state, options, annotations, None, &[])?;
        let probe_name = "rampage_debug_default_callback_probe";
        let probe = self.inspect_types(
            state,
            options,
            &Annotations::in_memory(),
            None,
            &[(format!("typedef int4 (*{probe_name})(void);"), None)],
        )?;
        if probe.language_id != current.language_id || probe.organization != current.organization {
            return Err(invalid("native default-model probe changed the selected language/organization"));
        }
        let default_calling_convention = probe
            .types
            .iter()
            .find(|ty| ty.name == probe_name)
            .and_then(|ty| ty.callback.as_ref())
            .and_then(|callback| callback.calling_convention.clone())
            .ok_or_else(|| invalid("native default-model probe omitted the declared calling convention"))?;
        let plan = graph::prepare_for_target(producer, &current.language_id, current.organization)?;
        let units = crate::type_library::stored_declarations(annotations)?;
        let reserved: BTreeSet<_> = annotations
            .types()
            .values()
            .chain(annotations.globals().values())
            .chain(annotations.signatures().values())
            .flat_map(|text| crate::debug_layout_import::words(text))
            .collect();
        for name in &plan.names {
            if current.types.iter().any(|ty| ty.name == *name) || reserved.contains(name.as_str()) {
                return Err(invalid(format!(
                    "producer type {name:?} conflicts with an existing definition; nothing applied"
                )));
            }
        }
        let native = if plan.names.is_empty() {
            None
        } else {
            Some(self.inspect_types(state, options, annotations, None, &[(plan.declarations.clone(), None)])?)
        };
        let expected: Vec<_> = native.as_ref().map_or(Vec::new(), |native| {
            native.types.iter().filter(|ty| plan.names.contains(&ty.name)).cloned().collect()
        });
        graph::compare(producer, &plan, &expected, &default_calling_convention)?;
        if let Some(native) = &native {
            for previous in &current.types {
                if native.types.iter().find(|ty| ty.name == previous.name) != Some(previous) {
                    return Err(invalid("producer declarations change an existing native type"));
                }
            }
        }
        let entries = signature_entry_witnesses(self)?;
        let mut signatures = Vec::new();
        let mut preserved = 0;
        let mut warnings = producer.warnings.clone();
        let mut address_counts = BTreeMap::new();
        for fact in &producer.signatures {
            *address_counts.entry(fact.address).or_insert(0usize) += 1;
        }
        for fact in &producer.signatures {
            if validate_signature_entry(self, fact.address, &entries).is_err() {
                warnings.push(format!("signature at {:#x} ({}): no cold-image metadata entry witness; producer/discovered-only entries remain preview-only",
                    fact.address, fact.type_id));
                preserved += 1;
                continue;
            }
            if !fact.unsupported.is_empty()
                || address_counts[&fact.address] != 1
                || annotations.signatures().contains_key(&fact.address)
                || annotations.types().contains_key(&fact.address)
            {
                preserved += 1;
                continue;
            }
            match graph::signature(producer, &plan, &fact.type_id) {
                Ok(declaration) => signatures.push(DebugTypesSignature {
                    address: fact.address,
                    declaration,
                    producer_type_id: fact.type_id.clone(),
                }),
                Err(_) => preserved += 1,
            }
        }
        let mut proof = DebugTypesManifest {
            id: String::new(),
            review_sha256: String::new(),
            image_sha256: image.clone(),
            specification_sha256: specifications.clone(),
            options: option_identity(options),
            language_id: current.language_id,
            organization: current.organization,
            default_calling_convention,
            producer: serde_json::to_value(producer).map_err(invalid)?,
            library_names: plan.names.clone(),
            declarations: plan.declarations.clone(),
            declarations_sha256: digest(plan.declarations.as_bytes()),
            expected_native_named_types: expected.clone(),
            signatures,
        };
        proof.id = manifest_identity(&proof)?;
        // The exact current project object and all prospective facts participate; paging never does.
        let baseline = json(&(
            annotations.types(),
            annotations.type_library(),
            annotations.debug_types(),
            annotations.globals(),
            annotations.signatures(),
            annotations.names(),
        ))?;
        proof.review_sha256 =
            digest(json(&(format!("{:p}", self), &proof, baseline, format!("{:?}", source_evidence.pdb)))?.as_bytes());
        let mut changes = Vec::new();
        if !proof.library_names.is_empty() {
            let mut next_units = units;
            next_units.push(LibraryDeclaration {
                names: proof.library_names.clone(),
                declarations: proof.declarations.clone(),
                packing: None,
                source: Some(TypeLibrarySource { kind: "checked_debug_types".to_owned(), identity: proof.id.clone() }),
            });
            changes.push((Field::TypeLibrary, 0, crate::type_library::library_value(&next_units)?));
            let mut imports = manifests(annotations)?;
            imports.push(proof.clone());
            changes.push((Field::DebugTypes, 0, proof_value(imports)?));
            for signature in &proof.signatures {
                changes.push((Field::Signature, signature.address, Some(seal(&proof, signature))));
            }
            let mut candidate = annotations.snapshot();
            candidate.set_batch_validated(&changes, |_| Ok(())).map_err(invalid)?;
            self.validate_annotation_snapshot(state, options, &candidate).map_err(invalid)?;
        }
        if rampage_arch::hex::bytes(&crate::debug_layout_import::image_digest(self)?) != image
            || crate::debug_layout_import::current_specification_digest()? != specifications
            || source(self, request)? != source_evidence
        {
            return Err(invalid("image, specifications or producer changed during preview"));
        }
        let total = producer.types.len();
        let details = producer
            .types
            .iter()
            .skip(request.offset)
            .take(request.limit)
            .map(|ty| {
                let emitted = plan.emitted.get(&ty.id).cloned();
                Ok(DebugTypesDetail {
                    producer_type_id: ty.id.clone(),
                    original_name: ty.original_name.clone(),
                    native: emitted
                        .as_ref()
                        .and_then(|name| expected.iter().find(|native| native.name == *name))
                        .cloned(),
                    emitted_name: emitted,
                    applicable: plan.accepted.contains(&ty.id),
                    reasons: plan.reasons.get(&ty.id).cloned().unwrap_or_default(),
                    producer: serde_json::to_value(ty).map_err(invalid)?,
                    producer_evidence: producer_evidence(ty)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        let end = request.offset.saturating_add(details.len());
        let receipt = DebugTypesImport {
            applied: false,
            review_sha256: proof.review_sha256,
            manifest_id: (!plan.names.is_empty()).then_some(proof.id),
            total,
            applicable_types: plan.names.len(),
            applicable_signatures: proof.signatures.len(),
            preserved_signatures: preserved,
            imported_types: 0,
            imported_signatures: 0,
            offset: request.offset,
            limit: request.limit,
            next_offset: (end < total).then_some(end),
            details,
            warnings,
        };
        Ok(Pending { receipt, changes, source: source_evidence })
    }
}

#[cfg(test)]
mod tests;
