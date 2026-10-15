//! Bounded historical function inventory, isolated from current/native analysis authority.
//!
//! See `derived_cache/METHODOLOGY.md` for the precommitted measurement gate and observations.
//! Matching keys/checksums establish consistency only: every loaded row remains cached and unverified.

mod key;
mod preflight;
mod wire;

#[cfg(all(test, unix))]
mod contention_tests;

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::project_workspace::{ProjectWorkspacePhase, ProjectWorkspacePublication, ProjectWorkspaceTaskControl};
use crate::{ApiError, Project};

const DOCUMENT_BYTES: usize = 1024 * 1024;
const DEFAULT_ROWS: usize = 2048;
const MAX_ROWS: usize = 8192;

/// Dependency consistency, never host origin or an authorization token. No source paths are serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionInventoryCacheKey {
    source_sha256: String,
    image_sha256: String,
    context_sha256: String,
    names_sha256: String,
    decoder: String,
    discovery: String,
    naming: String,
}

/// Display-only historical hints. Canonical hexadecimal addresses preserve all 64 bits across JSON/JS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionInventoryCacheRow {
    /// Raw cached address, not a validated current function entry or source-evidence assertion.
    pub address: String,
    /// Historical display name, not an import/rename instruction.
    pub name: String,
    /// Historical sum of block byte lengths; not proof of mapped bytes or current geometry.
    pub size: u64,
    /// Historical aggregate only; no blocks or graph state are restored.
    pub block_count: u64,
    /// Historical aggregate only; no decoded instructions are restored.
    pub instruction_count: u64,
}

/// Opaque completed capture bound to the exact original project and names-only process-local revision.
pub struct PreparedFunctionInventory {
    project: Arc<Project>,
    names_revision: Arc<()>,
    document: wire::Document,
    bytes: Box<[u8]>,
}

/// Opaque historical view. It cannot initialize Project analysis or native/function-entry authority.
pub struct CachedFunctionInventory {
    project: Arc<Project>,
    names_revision: Arc<()>,
    document: Box<wire::Document>,
}

/// Hit is permanently cached/unverified. Miss and rejection never trigger discovery or write anything.
pub enum InventoryCacheReadOutcome {
    /// Dependency-consistent historical rows, not authenticated host observations.
    Hit(CachedFunctionInventory),
    /// Missing explicit cache file, or a well-formed cache with different dependencies.
    Miss,
    /// Invalid, over-budget, unsupported or privately unreadable document. No attacker text is echoed.
    Rejected,
    /// Original descriptor/path metadata or names changed during this operation.
    SourceChanged,
}

/// Uses the same typed publication/uncertain-commit and retained-staging semantics as workspace documents.
pub type InventoryCachePublication = ProjectWorkspacePublication;

impl PreparedFunctionInventory {
    pub fn key(&self) -> &FunctionInventoryCacheKey {
        &self.document.key
    }

    pub fn rows(&self) -> &[FunctionInventoryCacheRow] {
        &self.document.rows
    }

    pub fn total_functions(&self) -> u64 {
        self.document.total_functions
    }

    pub fn truncated(&self) -> bool {
        self.document.truncated
    }
}

impl CachedFunctionInventory {
    pub fn key(&self) -> &FunctionInventoryCacheKey {
        &self.document.key
    }

    pub fn rows(&self) -> &[FunctionInventoryCacheRow] {
        &self.document.rows
    }

    pub fn total_functions(&self) -> u64 {
        self.document.total_functions
    }

    pub fn truncated(&self) -> bool {
        self.document.truncated
    }

    pub fn project(&self) -> &Arc<Project> {
        &self.project
    }

    /// For process-local Arc::ptr_eq only, not a serialized authorization or source-evidence proof.
    pub fn names_revision(&self) -> &Arc<()> {
        &self.names_revision
    }

    /// Constant provenance independent of every cache-supplied field, including valid recomputed checksums.
    pub fn provenance(&self) -> &'static str {
        "cached_unverified_historical"
    }

    /// Cheap adoption/raw-address guard only. Does not make rows current functions or authenticate their origin.
    pub fn validate_current_metadata(&self, project: &Arc<Project>) -> Result<(), ApiError> {
        if !Arc::ptr_eq(project, &self.project) {
            return Err(invalid("inventory view belongs to a different project"));
        }
        validate_binding(project, &self.names_revision)
    }
}

/// Explicit background operation. Requires successful, already completed global discovery; never starts it.
pub fn capture_function_inventory(
    project: Arc<Project>,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<PreparedFunctionInventory, ApiError> {
    control.phase(ProjectWorkspacePhase::CapturingInputs, None, 0, 1)?;
    backing(&project)?;
    let analysis = project.cached_analysis().ok_or_else(|| invalid("inventory capture requires completed analysis"))?;
    let names_revision = background_names_revision(&project, control)?;
    let key = key::dependency_key(&project, control)?;
    control.phase(ProjectWorkspacePhase::CapturingInventory, None, 0, 1)?;
    backing(&project)?;
    let rows = project_rows(&project, control)?;
    let total_functions = analysis.program.functions.len() as u64;
    let payload_sha256 = wire::payload_digest(&key, total_functions, total_functions > rows.len() as u64, &rows)?;
    let document = wire::Document {
        version: "FunctionInventoryCacheV0".into(),
        key,
        total_functions,
        truncated: total_functions > rows.len() as u64,
        payload_sha256,
        rows,
    };
    document.validate()?;
    control.phase(ProjectWorkspacePhase::PreparingDocument, None, 0, 1)?;
    let mut bytes = BoundedDocument(Vec::new());
    serde_json::to_writer(&mut bytes, &document).map_err(|_| invalid("inventory document budget exceeded"))?;
    let bytes = bytes.0;
    preflight::raw_preflight(&bytes)?;
    control.phase(ProjectWorkspacePhase::ValidatingCache, None, 1, 1)?;
    validate_background_binding(&project, &names_revision, control)?;
    control.check()?;
    Ok(PreparedFunctionInventory { project, names_revision, document, bytes: bytes.into_boxed_slice() })
}

/// The capture's exact bounded historical projection, exposed for an honest discovery/projection baseline.
/// Requires completed analysis, performs no source hash, and does not confer fresh function-entry authority.
pub fn completed_function_inventory_rows(
    project: &Arc<Project>,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<Vec<FunctionInventoryCacheRow>, ApiError> {
    control.phase(ProjectWorkspacePhase::CapturingInventory, None, 0, 1)?;
    backing(project)?;
    let names_revision = background_names_revision(project, control)?;
    let rows = project_rows(project, control)?;
    validate_background_binding(project, &names_revision, control)?;
    control.check()?;
    Ok(rows)
}

fn project_rows(
    project: &Project,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<Vec<FunctionInventoryCacheRow>, ApiError> {
    let analysis =
        project.cached_analysis().ok_or_else(|| invalid("inventory projection requires completed analysis"))?;
    let mut rows = Vec::with_capacity(analysis.program.functions.len().min(DEFAULT_ROWS));
    let mut named_bytes = 0usize;
    let mut blocks = 0usize;
    {
        let annotations = borrow_annotations(project, control)?;
        for function in analysis.program.functions.iter().take(DEFAULT_ROWS) {
            control.check()?;
            blocks = blocks.checked_add(function.blocks.len()).ok_or_else(|| invalid("inventory block budget"))?;
            if blocks > 65_536 {
                return Err(invalid("inventory projection block budget exceeded"));
            }
            let name = project.inventory_function_name_in(&annotations, function.address);
            let length = name.map_or(20, str::len);
            named_bytes = named_bytes.checked_add(length).ok_or_else(|| invalid("inventory projection name budget"))?;
            if length > 4096 || named_bytes > DOCUMENT_BYTES {
                return Err(invalid("inventory projection name budget exceeded"));
            }
            let size = function
                .blocks
                .iter()
                .try_fold(0u64, |size, block| {
                    block.end.checked_sub(block.start).and_then(|length| size.checked_add(length))
                })
                .ok_or_else(|| invalid("invalid function block lengths"))?;
            rows.push(FunctionInventoryCacheRow {
                address: format!("{:#x}", function.address),
                name: name.map_or_else(|| format!("sub_{:x}", function.address), str::to_owned),
                size,
                block_count: function.blocks.len() as u64,
                instruction_count: function.instruction_count as u64,
            });
        }
    }
    Ok(rows)
}

/// Explicit path only. No fallback discovery, namespace scan, native call, source-path import or write occurs.
/// Awaits annotation writers cooperatively on the calling background worker, never on the paint thread.
pub fn read_function_inventory(
    project: Arc<Project>,
    path: &Path,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<InventoryCacheReadOutcome, ApiError> {
    control.phase(ProjectWorkspacePhase::ValidatingIdentity, None, 0, 1)?;
    if !background_source_unchanged(&project, control)? {
        return Ok(InventoryCacheReadOutcome::SourceChanged);
    }
    let names_revision = background_names_revision(&project, control)?;
    control.phase(ProjectWorkspacePhase::ReadingCache, None, 0, 1)?;
    let outcome = match crate::debugger_capture::read_private_document(path, DOCUMENT_BYTES) {
        Ok(bytes) => {
            control.phase(ProjectWorkspacePhase::ValidatingCache, None, 0, 1)?;
            match parse_document(&bytes) {
                Ok(document) => {
                    control.phase(ProjectWorkspacePhase::ValidatingIdentity, None, 0, 1)?;
                    let key_result = key::dependency_key(&project, control);
                    control.check()?;
                    let key = match key_result {
                        Ok(key) => key,
                        Err(error @ ApiError::Load { .. }) => return Err(error),
                        Err(error) => {
                            if !background_source_unchanged(&project, control)? {
                                return Ok(InventoryCacheReadOutcome::SourceChanged);
                            }
                            return Err(error);
                        }
                    };
                    if !background_source_unchanged(&project, control)? {
                        return Ok(InventoryCacheReadOutcome::SourceChanged);
                    }
                    if document.key == key {
                        InventoryCacheReadOutcome::Hit(CachedFunctionInventory {
                            project: Arc::clone(&project),
                            names_revision: Arc::clone(&names_revision),
                            document: Box::new(document),
                        })
                    } else {
                        InventoryCacheReadOutcome::Miss
                    }
                }
                Err(_) => InventoryCacheReadOutcome::Rejected,
            }
        }
        Err(_) => match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => InventoryCacheReadOutcome::Miss,
            _ => InventoryCacheReadOutcome::Rejected,
        },
    };
    control.phase(ProjectWorkspacePhase::ResultValidation, None, 1, 1)?;
    if !background_binding_unchanged(&project, &names_revision, control)? {
        return Ok(InventoryCacheReadOutcome::SourceChanged);
    }
    control.check()?;
    Ok(outcome)
}

/// No-clobber private publication. Post-link cancellation/freshness failures preserve uncertain commit status.
pub fn publish_function_inventory(
    prepared: &PreparedFunctionInventory,
    path: &Path,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<InventoryCachePublication, ApiError> {
    let outcome = crate::debugger_capture::publish_private_document_observed(path, &prepared.bytes, |phase| {
        use crate::debugger_capture::PublicationCheckPhase;
        let phase = match phase {
            PublicationCheckPhase::BeforeStaging => ProjectWorkspacePhase::Publishing,
            PublicationCheckPhase::BeforeLink => ProjectWorkspacePhase::PublicationStaged,
            PublicationCheckPhase::AfterLink => ProjectWorkspacePhase::ValidatingCache,
        };
        control.phase(phase, None, 0, 1)?;
        validate_background_binding(&prepared.project, &prepared.names_revision, control)
    })?;
    Ok(ProjectWorkspacePublication {
        path: outcome.path,
        document_sha256: outcome.document_sha256,
        status: outcome.status,
        warnings: outcome.warnings,
        retained_staging_paths: outcome.retained_staging_paths,
    })
}

/// Explicit background dependency-key measurement; does not start discovery or confer cache authority.
pub fn function_inventory_dependency_key(
    project: &Arc<Project>,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<FunctionInventoryCacheKey, ApiError> {
    control.phase(ProjectWorkspacePhase::ValidatingCache, None, 0, 1)?;
    let names_revision = background_names_revision(project, control)?;
    let key = key::dependency_key(project, control)?;
    validate_background_binding(project, &names_revision, control)?;
    control.check()?;
    Ok(key)
}

fn parse_document(bytes: &[u8]) -> Result<wire::Document, ApiError> {
    preflight::raw_preflight(bytes)?;
    let document: wire::Document = serde_json::from_slice(bytes).map_err(|_| invalid("inventory cache rejected"))?;
    document.validate()?;
    Ok(document)
}

fn validate_binding(project: &Project, revision: &Arc<()>) -> Result<(), ApiError> {
    backing(project)?;
    if !Arc::ptr_eq(revision, &project.names_revision()?) {
        return Err(invalid("inventory names changed"));
    }
    Ok(())
}

fn borrow_annotations<'a>(
    project: &'a Project,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<std::sync::RwLockReadGuard<'a, crate::annotations::Annotations>, ApiError> {
    loop {
        control.check()?;
        match project.annotations.try_read() {
            Ok(annotations) => return Ok(annotations),
            Err(std::sync::TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        #[cfg(all(test, unix))]
        contention_tests::annotation_waiting();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn background_names_revision(
    project: &Project,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<Arc<()>, ApiError> {
    Ok(borrow_annotations(project, control)?.names_revision())
}

fn background_binding_unchanged(
    project: &Project,
    revision: &Arc<()>,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<bool, ApiError> {
    if !background_source_unchanged(project, control)? {
        return Ok(false);
    }
    let current = background_names_revision(project, control)?;
    Ok(background_source_unchanged(project, control)? && Arc::ptr_eq(revision, &current))
}

fn validate_background_binding(
    project: &Project,
    revision: &Arc<()>,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<(), ApiError> {
    if !background_binding_unchanged(project, revision, control)? {
        return Err(invalid("inventory source or names changed"));
    }
    Ok(())
}

fn source_unchanged(project: &Project) -> Result<bool, ApiError> {
    match project.binary.validate_available_backing_source() {
        Ok(available) => Ok(available),
        Err(rampage_loaders::LoadError::Malformed(_)) => Ok(false),
        Err(source) => {
            Err(ApiError::Load { path: project.binary.backing_path().map(Path::to_owned).unwrap_or_default(), source })
        }
    }
}

fn background_source_unchanged(project: &Project, control: &ProjectWorkspaceTaskControl<'_>) -> Result<bool, ApiError> {
    control.check()?;
    let result = source_unchanged(project);
    control.check()?;
    result
}

fn backing(project: &Project) -> Result<(), ApiError> {
    if !source_unchanged(project)? {
        return Err(invalid("inventory requires an unchanged retained original mapped source"));
    }
    Ok(())
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.into())
}

struct BoundedDocument(Vec<u8>);

impl std::io::Write for BoundedDocument {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > DOCUMENT_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("inventory document byte budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
