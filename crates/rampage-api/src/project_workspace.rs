//! Bounded, explicitly reviewed local multi-module workspaces. No analysis state is serialized.

mod control;
use control::uncontrolled;
pub use control::{ProjectWorkspacePhase, ProjectWorkspaceProgress, ProjectWorkspaceTaskControl};

use std::collections::HashSet;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rampage_analysis::capture_identity::capture_identity;
use rampage_arch::Arch;
use rampage_decompiler::{DecompilerOptions, Platform};
use rampage_loaders::{Binary, Format, ImageAt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ApiError, Project, Session};

const MANIFEST_BYTES: u64 = 256 * 1024;
const SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const TOTAL_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const ANNOTATION_POLICY: &str = "recognized_local_logs_checked";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedProjectAddress {
    pub module_id: String,
    #[serde(serialize_with = "rampage_arch::hex::address", deserialize_with = "deserialize_address")]
    pub address: u64,
}

fn deserialize_address<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct Address;

    impl serde::de::Visitor<'_> for Address {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonical lowercase 0x-prefixed 64-bit hexadecimal address string")
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<u64, E> {
            let digits = text.strip_prefix("0x").ok_or_else(|| E::custom("address must start with 0x"))?;
            if digits.is_empty()
                || digits.len() > 16
                || digits.len() > 1 && digits.starts_with('0')
                || !digits.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(E::custom("address must be canonical lowercase hexadecimal within 64 bits"));
            }
            u64::from_str_radix(digits, 16).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(Address)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceNavigation {
    pub current: Option<QualifiedProjectAddress>,
    pub back: Vec<QualifiedProjectAddress>,
    pub forward: Vec<QualifiedProjectAddress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceImage {
    pub offset: u64,
    pub length: Option<u64>,
}

impl ProjectWorkspaceImage {
    fn selection(self) -> ImageAt {
        ImageAt::new(self.offset, self.length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceCaptureIdentity {
    pub schema: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceIdentity {
    pub source_sha256: String,
    pub image_sha256: String,
    pub source_bytes: u64,
    pub format: String,
    pub architecture: String,
    pub data_big_endian: bool,
    pub code_big_endian: bool,
    pub capture_identity: Option<ProjectWorkspaceCaptureIdentity>,
    pub snapshot_document_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectWorkspacePlatform {
    Default,
    Darwin,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceOptions {
    pub platform: ProjectWorkspacePlatform,
    pub compiler: Option<String>,
    pub arm_be8: bool,
}

impl ProjectWorkspaceOptions {
    fn from_options(options: DecompilerOptions) -> Self {
        Self {
            platform: match options.platform {
                Platform::Default => ProjectWorkspacePlatform::Default,
                Platform::Darwin => ProjectWorkspacePlatform::Darwin,
                Platform::Windows => ProjectWorkspacePlatform::Windows,
            },
            compiler: options.compiler,
            arm_be8: options.arm_be8,
        }
    }

    fn options(&self) -> DecompilerOptions {
        DecompilerOptions {
            platform: match self.platform {
                ProjectWorkspacePlatform::Default => Platform::Default,
                ProjectWorkspacePlatform::Darwin => Platform::Darwin,
                ProjectWorkspacePlatform::Windows => Platform::Windows,
            },
            compiler: self.compiler.clone(),
            arm_be8: self.arm_be8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceModule {
    pub id: String,
    pub label: String,
    pub source_path: PathBuf,
    pub image: Option<ProjectWorkspaceImage>,
    pub identity: ProjectWorkspaceIdentity,
    /// Snapshot annotation-directory context only; this digest never supplies or authorizes a filesystem path.
    pub annotation_context_sha256: Option<String>,
    /// `None` means automatic selection, distinct from explicitly configured defaults.
    pub options: Option<ProjectWorkspaceOptions>,
    pub navigation: ProjectWorkspaceNavigation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectWorkspaceManifest {
    pub version: u32,
    pub modules: Vec<ProjectWorkspaceModule>,
    pub active_module_id: String,
    /// Authorizes only derived sidecars, never a manifest-supplied annotation directory or log path.
    pub annotation_policy: String,
}

#[derive(Clone)]
pub struct ProjectWorkspaceModuleInput {
    pub id: String,
    pub label: String,
    pub source_path: PathBuf,
    pub image: Option<ImageAt>,
    pub project: Arc<Project>,
    pub navigation: ProjectWorkspaceNavigation,
}

/// Process-local review authority. Its immutable manifest is bound to an open descriptor and exact document hash.
pub struct ProjectWorkspacePreview {
    manifest: ProjectWorkspaceManifest,
    source: SourceFile,
    path: PathBuf,
    document_sha256: String,
}

impl std::fmt::Debug for ProjectWorkspacePreview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectWorkspacePreview")
            .field("manifest", &self.manifest)
            .field("document_sha256", &self.document_sha256)
            .finish_non_exhaustive()
    }
}

impl ProjectWorkspacePreview {
    pub fn manifest(&self) -> &ProjectWorkspaceManifest {
        &self.manifest
    }

    pub fn document_sha256(&self) -> &str {
        &self.document_sha256
    }

    /// These reads are included in approval: per-path/per-slice ordinary logs and identity-scoped capture logs.
    /// Capture logs use the current session's annotation directory, or the source's canonical parent directory.
    /// Logs are derived only after loading; checked ingestion is bounded and does not create missing logs.
    pub fn annotation_review(&self) -> &'static str {
        "Recognized local annotation logs will be read using bounded checked ingestion. Ordinary logs are derived \
         from each source filename, selected image and architecture. Snapshot logs are derived from validated \
         capture identity in the current session's annotation directory, or the source's canonical parent. \
         Snapshot annotation-directory settings must match the saved context digest. No manifest-supplied log \
         paths or runtime settings are accepted. Missing logs are not created on load."
    }

    /// Explicit approval opens all listed sources into a fresh session before returning any candidate bank.
    pub fn open_reviewed(&self, session: &Session) -> Result<LoadedProjectWorkspace, ApiError> {
        uncontrolled(|control| self.open_reviewed_controlled(session, control))
    }

    pub fn validate_metadata(&self) -> Result<(), ApiError> {
        validate_source_file(&self.path, &self.source)
    }

    pub fn open_reviewed_controlled(
        &self,
        session: &Session,
        control: &mut ProjectWorkspaceTaskControl<'_>,
    ) -> Result<LoadedProjectWorkspace, ApiError> {
        let total = self.manifest.modules.len();
        control.phase(ProjectWorkspacePhase::PreflightingSources, None, 0, total)?;
        self.validate_document_controlled(control)?;
        let sources = preflight_sources(&self.manifest)?;
        let fresh = session.unloaded_copy();
        let mut modules = Vec::with_capacity(self.manifest.modules.len());
        for (index, (module, source)) in self.manifest.modules.iter().zip(sources).enumerate() {
            control.phase(ProjectWorkspacePhase::LoadingModule, Some(&module.id), index, total)?;
            self.validate_document_controlled(control)?;
            validate_source_file(&module.source_path, &source)?;
            validate_annotation_context(module, &fresh)?;
            let source_hash = source.hash_controlled(control)?;
            if source_hash != module.identity.source_sha256 {
                return Err(invalid("workspace source hash changed; no modules adopted"));
            }
            let arch = architecture(&module.identity.architecture)?;
            let image = module.image.map(ProjectWorkspaceImage::selection);
            let project = fresh.open_workspace_at(&module.source_path, Some(arch), image)?;
            control.phase(ProjectWorkspacePhase::ValidatingIdentity, Some(&module.id), index, total)?;
            validate_source_file(&module.source_path, &source)?;
            if identity_controlled(&project.binary, control)? != module.identity {
                return Err(invalid("workspace selected image or capture document changed; no modules adopted"));
            }
            project.set_decompiler_options(module.options.as_ref().map(ProjectWorkspaceOptions::options));
            if project.configured_decompiler_options()?.map(ProjectWorkspaceOptions::from_options) != module.options {
                return Err(invalid("workspace options are incompatible with the selected image"));
            }
            let configuration_revision = project.decompiler_configuration_revision()?;
            modules.push(LoadedProjectModule { module: module.clone(), project, configuration_revision, source });
        }
        control.phase(ProjectWorkspacePhase::ResultValidation, None, total, total)?;
        self.validate_document_controlled(control)?;
        let loaded = LoadedProjectWorkspace { manifest: self.manifest.clone(), modules, session: fresh };
        loaded.validate_controlled(control)?;
        Ok(loaded)
    }

    fn validate_document_controlled(&self, control: &ProjectWorkspaceTaskControl<'_>) -> Result<(), ApiError> {
        control.check()?;
        validate_source_file(&self.path, &self.source)?;
        if self.source.hash_controlled(control)? != self.document_sha256 {
            return Err(invalid("workspace document changed since review; preview again"));
        }
        Ok(())
    }
}

pub struct LoadedProjectModule {
    module: ProjectWorkspaceModule,
    project: Arc<Project>,
    configuration_revision: crate::DecompilerConfigurationRevision,
    source: SourceFile,
}

impl LoadedProjectModule {
    pub fn module(&self) -> &ProjectWorkspaceModule {
        &self.module
    }

    pub fn project(&self) -> &Arc<Project> {
        &self.project
    }
}

pub struct LoadedProjectWorkspace {
    manifest: ProjectWorkspaceManifest,
    modules: Vec<LoadedProjectModule>,
    session: Session,
}

impl LoadedProjectWorkspace {
    pub fn manifest(&self) -> &ProjectWorkspaceManifest {
        &self.manifest
    }

    pub fn modules(&self) -> &[LoadedProjectModule] {
        &self.modules
    }

    pub fn active_module_id(&self) -> &str {
        &self.manifest.active_module_id
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn into_parts(self) -> (ProjectWorkspaceManifest, Vec<LoadedProjectModule>, Session) {
        (self.manifest, self.modules, self.session)
    }

    /// Rechecks the exact returned Arcs, not replacement projects looked up by names or addresses.
    pub fn validate(&self) -> Result<(), ApiError> {
        uncontrolled(|control| self.validate_controlled(control))
    }

    /// Cheap adoption checks only: original descriptors, pathname stamps, settings and bounded metadata.
    /// Full source hashes are validated by the background operation, not by this method.
    pub fn validate_metadata(&self) -> Result<(), ApiError> {
        validate_manifest(&self.manifest)?;
        if self.modules.len() != self.manifest.modules.len() {
            return Err(invalid("incomplete loaded workspace"));
        }
        for (loaded, module) in self.modules.iter().zip(&self.manifest.modules) {
            validate_source_file(&loaded.module.source_path, &loaded.source)?;
            loaded.project.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
            validate_annotation_context(module, &self.session)?;
            if loaded.module != *module
                || loaded.project.decompiler_configuration_revision()? != loaded.configuration_revision
                || loaded.project.configured_decompiler_options()?.map(ProjectWorkspaceOptions::from_options)
                    != module.options
            {
                return Err(invalid("loaded workspace metadata changed before adoption"));
            }
        }
        Ok(())
    }

    fn validate_controlled(&self, control: &ProjectWorkspaceTaskControl<'_>) -> Result<(), ApiError> {
        control.check()?;
        self.validate_metadata()?;
        let sources = preflight_sources(&self.manifest)?;
        for ((loaded, module), source) in self.modules.iter().zip(&self.manifest.modules).zip(&sources) {
            control.check()?;
            validate_annotation_context(module, &self.session)?;
            if loaded.module != *module
                || identity_controlled(&loaded.project.binary, control)? != module.identity
                || source.hash_controlled(control)? != module.identity.source_sha256
                || loaded.project.decompiler_configuration_revision()? != loaded.configuration_revision
                || loaded.project.configured_decompiler_options()?.map(ProjectWorkspaceOptions::from_options)
                    != module.options
            {
                return Err(invalid("loaded workspace changed before adoption"));
            }
            validate_source_file(&module.source_path, source)?;
            validate_source_file(&module.source_path, &loaded.source)?;
        }
        control.check()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectWorkspacePublication {
    pub path: PathBuf,
    pub document_sha256: String,
    pub status: crate::DebuggerCapturePublicationStatus,
    pub warnings: Vec<String>,
    pub retained_staging_paths: Vec<PathBuf>,
}

/// Reads only this regular bounded UTF-8 manifest. It does not stat, canonicalize or open any module path.
pub fn preview_project_workspace(path: &Path) -> Result<ProjectWorkspacePreview, ApiError> {
    uncontrolled(|control| preview_project_workspace_controlled(path, control))
}

pub fn preview_project_workspace_controlled(
    path: &Path,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<ProjectWorkspacePreview, ApiError> {
    control.phase(ProjectWorkspacePhase::ReadingManifest, None, 0, 0)?;
    let source = open_regular(path, MANIFEST_BYTES)?;
    let document = source.read_bounded_controlled(MANIFEST_BYTES, control)?;
    raw_preflight(&document)?;
    let manifest: ProjectWorkspaceManifest = serde_json::from_slice(&document).map_err(|error| {
        invalid(format!("invalid workspace document at line {}, column {}", error.line(), error.column(),))
    })?;
    validate_manifest(&manifest)?;
    control.phase(ProjectWorkspacePhase::ResultValidation, None, 0, manifest.modules.len())?;
    validate_source_file(path, &source)?;
    control.check()?;
    Ok(ProjectWorkspacePreview { manifest, source, path: path.to_owned(), document_sha256: digest(&document) })
}

/// Uses each source's canonical parent for snapshot logs. Custom settings require the session-aware variant.
pub fn capture_project_workspace(
    modules: &[ProjectWorkspaceModuleInput],
    active: &str,
) -> Result<ProjectWorkspaceManifest, ApiError> {
    capture_project_workspace_with_session(modules, active, &Session::default())
}

/// Captures recognized annotation locations using current process-local settings, never serialized log paths.
pub fn capture_project_workspace_with_session(
    modules: &[ProjectWorkspaceModuleInput],
    active: &str,
    session: &Session,
) -> Result<ProjectWorkspaceManifest, ApiError> {
    uncontrolled(|control| capture_project_workspace_controlled(modules, active, session, control))
}

pub fn capture_project_workspace_controlled(
    modules: &[ProjectWorkspaceModuleInput],
    active: &str,
    session: &Session,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<ProjectWorkspaceManifest, ApiError> {
    if modules.is_empty() || modules.len() > 8 {
        return Err(invalid("a workspace must contain between one and eight modules"));
    }
    control.phase(ProjectWorkspacePhase::CapturingInputs, None, 0, modules.len())?;
    // All sizes and canonical selection collisions are checked before any map or hash work.
    let mut sources = Vec::with_capacity(modules.len());
    let mut total = 0u64;
    let mut selections = HashSet::new();
    let mut ids = HashSet::new();
    let mut configuration_revisions = Vec::with_capacity(modules.len());
    let mut annotation_revisions = Vec::with_capacity(modules.len());
    for input in modules {
        control.check()?;
        check_id(&input.id)?;
        check_label(&input.label)?;
        check_path(&input.source_path)?;
        check_navigation(&input.navigation, &input.id)?;
        if !ids.insert(input.id.as_str()) {
            return Err(invalid("duplicate workspace module ID"));
        }
        configuration_revisions.push(input.project.decompiler_configuration_revision()?);
        annotation_revisions.push(input.project.authoritative_annotation_revision()?);
        let source = open_source(&input.source_path)?;
        total = total.checked_add(source.stamp.length).ok_or_else(|| invalid("source size overflow"))?;
        if total > TOTAL_SOURCE_BYTES {
            return Err(invalid("workspace aggregate source budget exceeds 256 MiB"));
        }
        let canonical = input.source_path.canonicalize().map_err(|error| invalid(error.to_string()))?;
        let image = normalized_image(input.image);
        if !selections.insert((canonical, input.project.binary.arch, image)) {
            return Err(invalid("duplicate canonical source, architecture and image selection"));
        }
        sources.push(source);
    }
    let mut captured = Vec::with_capacity(modules.len());
    for (index, (input, source)) in modules.iter().zip(&sources).enumerate() {
        control.phase(ProjectWorkspacePhase::ValidatingIdentity, Some(&input.id), index, modules.len())?;
        validate_source_file(&input.source_path, source)?;
        let binary = &input.project.binary;
        binary.validate_checked_source_profile().map_err(|error| invalid(error.to_string()))?;
        if let Some(backing) = binary.backing_path()
            && backing.canonicalize().map_err(|error| invalid(error.to_string()))?
                != input.source_path.canonicalize().map_err(|error| invalid(error.to_string()))?
        {
            return Err(invalid("workspace source is not the project's resolved backing file"));
        }
        let identity = identity_controlled(binary, control)?;
        if identity.source_sha256 != source.hash_controlled(control)? || identity.source_bytes != source.stamp.length {
            return Err(invalid("workspace source does not match the retained project"));
        }
        validate_selection(binary, input.image)?;
        let (annotations, log) = detached_annotations(&input.project)?;
        control.phase(ProjectWorkspacePhase::ReadingAnnotations, Some(&input.id), index, modules.len())?;
        validate_source_file(&input.source_path, source)?;
        binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
        validate_annotation_persistence(
            binary,
            &input.source_path,
            input.image,
            &annotations,
            log.as_deref(),
            session,
            control,
        )?;
        validate_source_file(&input.source_path, source)?;
        captured.push(ProjectWorkspaceModule {
            id: input.id.clone(),
            label: input.label.clone(),
            source_path: input.source_path.clone(),
            image: normalized_image(input.image),
            identity,
            annotation_context_sha256: if binary.format == Format::Snapshot {
                Some(annotation_context(&annotation_root(&input.source_path, session)?)?)
            } else {
                None
            },
            options: input.project.configured_decompiler_options()?.map(ProjectWorkspaceOptions::from_options),
            navigation: input.navigation.clone(),
        });
    }
    let manifest = ProjectWorkspaceManifest {
        version: 1,
        modules: captured,
        active_module_id: active.to_owned(),
        annotation_policy: ANNOTATION_POLICY.to_owned(),
    };
    control.phase(ProjectWorkspacePhase::PreparingDocument, None, modules.len(), modules.len())?;
    validate_manifest(&manifest)?;
    let bytes = serde_json::to_vec(&manifest).map_err(|error| invalid(error.to_string()))?;
    raw_preflight(&bytes)?;
    control.phase(ProjectWorkspacePhase::ResultValidation, None, modules.len(), modules.len())?;
    for (index, ((input, revision), source)) in modules.iter().zip(&configuration_revisions).zip(&sources).enumerate() {
        control.check()?;
        if input.project.decompiler_configuration_revision()? != *revision {
            return Err(invalid("workspace configuration changed during capture"));
        }
        if !Arc::ptr_eq(&input.project.authoritative_annotation_revision()?, &annotation_revisions[index]) {
            return Err(invalid("workspace annotations changed during capture"));
        }
        validate_annotation_context(&manifest.modules[index], session)?;
        validate_source_file(&input.source_path, source)?;
        input.project.binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
    }
    control.check()?;
    Ok(manifest)
}

pub fn publish_project_workspace(
    manifest: &ProjectWorkspaceManifest,
    output: &Path,
) -> Result<ProjectWorkspacePublication, ApiError> {
    uncontrolled(|control| publish_project_workspace_controlled(manifest, output, control))
}

pub fn publish_project_workspace_controlled(
    manifest: &ProjectWorkspaceManifest,
    output: &Path,
    control: &mut ProjectWorkspaceTaskControl<'_>,
) -> Result<ProjectWorkspacePublication, ApiError> {
    control.phase(ProjectWorkspacePhase::PreparingDocument, None, 0, manifest.modules.len().min(8))?;
    validate_manifest(manifest)?;
    let bytes = serde_json::to_vec(manifest).map_err(|error| invalid(error.to_string()))?;
    raw_preflight(&bytes)?;
    control.phase(ProjectWorkspacePhase::PreflightingSources, None, 0, manifest.modules.len())?;
    let sources = preflight_sources(manifest)?;
    validate_publication_sources(manifest, &sources, control)?;
    let publication = crate::debugger_capture::publish_private_document_observed(output, &bytes, |phase| {
        use crate::debugger_capture::PublicationCheckPhase;
        let (phase, completed) = match phase {
            PublicationCheckPhase::BeforeStaging => (ProjectWorkspacePhase::Publishing, 0),
            PublicationCheckPhase::BeforeLink => (ProjectWorkspacePhase::PublicationStaged, 0),
            PublicationCheckPhase::AfterLink => (ProjectWorkspacePhase::ResultValidation, manifest.modules.len()),
        };
        control.phase(phase, None, completed, manifest.modules.len())?;
        validate_publication_sources(manifest, &sources, control)
    })?;
    Ok(ProjectWorkspacePublication {
        path: publication.path,
        document_sha256: publication.document_sha256,
        status: publication.status,
        warnings: publication.warnings,
        retained_staging_paths: publication.retained_staging_paths,
    })
}

fn validate_publication_sources(
    manifest: &ProjectWorkspaceManifest,
    sources: &[SourceFile],
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<(), ApiError> {
    control.check()?;
    for (module, source) in manifest.modules.iter().zip(sources) {
        validate_source_file(&module.source_path, source)?;
        if source.hash_controlled(control)? != module.identity.source_sha256 {
            return Err(invalid("workspace source changed before publication"));
        }
    }
    control.check()
}

fn normalized_image(image: Option<ImageAt>) -> Option<ProjectWorkspaceImage> {
    image
        .filter(|image| !image.is_whole_file())
        .map(|image| ProjectWorkspaceImage { offset: image.offset(), length: image.length() })
}

fn detached_annotations(project: &Project) -> Result<(crate::annotations::Annotations, Option<PathBuf>), ApiError> {
    let current = project.annotations.read().expect("annotations lock");
    project.validate_patch_context(&current)?;
    current.preflight_checked().map_err(invalid)?;
    Ok((current.snapshot(), current.persistent_path().map(Path::to_owned)))
}

fn validate_annotation_persistence(
    binary: &Binary,
    source_path: &Path,
    selected_image: Option<ImageAt>,
    current: &crate::annotations::Annotations,
    log: Option<&Path>,
    session: &Session,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<(), ApiError> {
    control.check()?;
    let empty = current.values_equal(&crate::annotations::Annotations::in_memory());
    let Some(log) = log else {
        return if empty {
            Ok(())
        } else {
            Err(invalid("workspace cannot persist in-memory analyst edits; save them to recognized local logs first"))
        };
    };
    if binary.format == Format::Snapshot {
        let capture = capture_identity(binary).ok_or_else(|| invalid("invalid capture annotation identity"))?;
        let filename = format!(".{}-{}.jsonl", capture.schema, capture.sha256);
        let parent = log.parent().ok_or_else(|| invalid("snapshot annotation log has no parent directory"))?;
        let actual_root = parent.canonicalize().map_err(|error| invalid(error.to_string()))?;
        if log.file_name() != Some(std::ffi::OsStr::new(&filename))
            || actual_root != annotation_root(source_path, session)?
        {
            return Err(invalid("snapshot annotations do not match the current session's recognized log directory"));
        }
    } else {
        let expected = crate::session::annotation_path(
            source_path,
            normalized_image(selected_image).map(ProjectWorkspaceImage::selection),
            binary,
        );
        if log != expected.as_path() {
            return Err(invalid("workspace annotations are not in the source's recognized local log"));
        }
    }
    let image_hash = if binary.format != Format::Snapshot {
        Some(digest_bytes_controlled(binary.image_bytes(), control)?)
    } else {
        None
    };
    let persisted =
        crate::annotations::Annotations::open_for_image_checked(log.to_owned(), image_hash).map_err(invalid)?;
    control.check()?;
    if !current.values_equal(&persisted) {
        return Err(invalid("workspace analyst state differs from its checked local log; refresh before saving"));
    }
    Ok(())
}

fn annotation_root(source_path: &Path, session: &Session) -> Result<PathBuf, ApiError> {
    let canonical_source = source_path.canonicalize().map_err(|error| invalid(error.to_string()))?;
    let parent = canonical_source.parent().ok_or_else(|| invalid("snapshot source has no parent directory"))?;
    let directory = session.capture_annotations().unwrap_or(parent);
    let metadata = std::fs::metadata(directory).map_err(|error| invalid(error.to_string()))?;
    if !metadata.is_dir() {
        return Err(invalid("current snapshot annotation directory is not a directory"));
    }
    directory.canonicalize().map_err(|error| invalid(error.to_string()))
}

fn annotation_context(directory: &Path) -> Result<String, ApiError> {
    let metadata = std::fs::metadata(directory).map_err(|error| invalid(error.to_string()))?;
    if !metadata.is_dir() {
        return Err(invalid("snapshot annotation context is no longer a directory"));
    }
    let mut hash = Sha256::new();
    hash.update(b"rampage-workspace-annotation-directory-v1\0");
    hash.update(directory.as_os_str().as_encoded_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash.update(metadata.dev().to_be_bytes());
        hash.update(metadata.ino().to_be_bytes());
    }
    Ok(rampage_arch::hex::bytes(&hash.finalize()))
}

fn validate_annotation_context(module: &ProjectWorkspaceModule, session: &Session) -> Result<(), ApiError> {
    if module.identity.format == "snapshot" {
        let context = annotation_context(&annotation_root(&module.source_path, session)?)?;
        if module.annotation_context_sha256.as_ref() != Some(&context) {
            return Err(invalid("snapshot annotation directory changed; use the settings used to save this workspace"));
        }
    }
    Ok(())
}

fn validate_selection(binary: &Binary, image: Option<ImageAt>) -> Result<(), ApiError> {
    match (binary.embedded, normalized_image(image)) {
        (None, None) => Ok(()),
        (Some(embedded), Some(image))
            if embedded.offset == image.offset && image.length.is_none_or(|length| length == embedded.size) =>
        {
            Ok(())
        }
        _ => Err(invalid("workspace image selector does not match the retained project")),
    }
}

fn identity_controlled(
    binary: &Binary,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<ProjectWorkspaceIdentity, ApiError> {
    control.check()?;
    let format = match binary.format {
        Format::Elf => "elf",
        Format::Pe => "pe",
        Format::MachO => "macho",
        Format::Snapshot => "snapshot",
        Format::Raw => {
            return Err(invalid(
                "Raw workspace persistence is unsupported: interpretation-bound workspace identity is not implemented",
            ));
        }
    };
    if binary.file_bytes().len() as u64 > SOURCE_BYTES {
        return Err(invalid("workspace source exceeds 128 MiB"));
    }
    binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
    let source_sha256 = digest_controlled(binary.file_bytes(), control)?;
    let target = binary.target();
    let identity = ProjectWorkspaceIdentity {
        source_sha256: source_sha256.clone(),
        image_sha256: digest_controlled(binary.image_bytes(), control)?,
        source_bytes: binary.file_bytes().len() as u64,
        format: format.to_owned(),
        architecture: binary.arch.to_string(),
        data_big_endian: target.data_big_endian,
        code_big_endian: target.big_endian,
        capture_identity: capture_identity(binary).map(|capture| ProjectWorkspaceCaptureIdentity {
            schema: capture.schema.to_owned(),
            sha256: capture.sha256,
        }),
        snapshot_document_sha256: (binary.format == Format::Snapshot).then_some(source_sha256),
    };
    binary.validate_available_backing_source().map_err(|error| invalid(error.to_string()))?;
    control.check()?;
    Ok(identity)
}

fn digest_controlled(bytes: &[u8], control: &ProjectWorkspaceTaskControl<'_>) -> Result<String, ApiError> {
    Ok(rampage_arch::hex::bytes(&digest_bytes_controlled(bytes, control)?))
}

fn digest_bytes_controlled(bytes: &[u8], control: &ProjectWorkspaceTaskControl<'_>) -> Result<[u8; 32], ApiError> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(65536) {
        control.check()?;
        hash.update(chunk);
    }
    control.check()?;
    Ok(hash.finalize().into())
}

fn validate_manifest(manifest: &ProjectWorkspaceManifest) -> Result<(), ApiError> {
    if manifest.version != 1 || manifest.annotation_policy != ANNOTATION_POLICY {
        return Err(invalid("unsupported workspace version or annotation policy"));
    }
    if manifest.modules.is_empty() || manifest.modules.len() > 8 {
        return Err(invalid("a workspace must contain between one and eight modules"));
    }
    let mut ids = HashSet::new();
    let mut selections = HashSet::new();
    let mut total = 0u64;
    for module in &manifest.modules {
        check_id(&module.id)?;
        check_label(&module.label)?;
        check_path(&module.source_path)?;
        check_navigation(&module.navigation, &module.id)?;
        if !ids.insert(module.id.as_str()) {
            return Err(invalid("duplicate workspace module ID"));
        }
        if !selections.insert((&module.source_path, &module.identity.architecture, module.image)) {
            return Err(invalid("duplicate workspace source, architecture and image selection"));
        }
        if module.image.is_some_and(|image| {
            image.length == Some(0)
                || image.offset == 0 && image.length.is_none()
                || image.length.is_some_and(|length| image.offset.checked_add(length).is_none())
        }) {
            return Err(invalid("invalid or noncanonical workspace image selection"));
        }
        let identity = &module.identity;
        architecture(&identity.architecture)?;
        check_hash(&identity.source_sha256)?;
        check_hash(&identity.image_sha256)?;
        if !matches!(identity.format.as_str(), "elf" | "pe" | "macho" | "snapshot")
            || identity.source_bytes > SOURCE_BYTES
        {
            return Err(invalid("invalid workspace source identity"));
        }
        total = total.checked_add(identity.source_bytes).ok_or_else(|| invalid("source size overflow"))?;
        if total > TOTAL_SOURCE_BYTES {
            return Err(invalid("workspace aggregate source budget exceeds 256 MiB"));
        }
        match (&identity.capture_identity, &identity.snapshot_document_sha256) {
            (Some(capture), Some(document)) if identity.format == "snapshot" => {
                if capture.schema != "rampage-capture-identity-v1" || document != &identity.source_sha256 {
                    return Err(invalid("invalid snapshot identity binding"));
                }
                check_hash(&capture.sha256)?;
                check_hash(document)?;
            }
            (None, None) if identity.format != "snapshot" => {}
            _ => return Err(invalid("snapshot capture and exact document identities are required together")),
        }
        match &module.annotation_context_sha256 {
            Some(context) if identity.format == "snapshot" => check_hash(context)?,
            None if identity.format != "snapshot" => {}
            _ => return Err(invalid("snapshot modules require a current-session annotation-directory context digest")),
        }
        if let Some(options) = &module.options
            && options.compiler.as_deref().is_some_and(|compiler| !ascii_id(compiler, 64))
        {
            return Err(invalid("invalid workspace compiler identifier"));
        }
    }
    check_id(&manifest.active_module_id)?;
    if !ids.contains(manifest.active_module_id.as_str()) {
        return Err(invalid("workspace active module does not exist"));
    }
    Ok(())
}

fn architecture(value: &str) -> Result<Arch, ApiError> {
    let arch: Arch = value.parse().map_err(invalid)?;
    if arch.to_string() != value {
        return Err(invalid("workspace architecture must use its canonical spelling"));
    }
    Ok(arch)
}

fn ascii_id(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !matches!(value, "." | "..")
}

fn check_id(id: &str) -> Result<(), ApiError> {
    if !ascii_id(id, 64) {
        return Err(invalid("workspace module IDs must be opaque ASCII identifiers of at most 64 bytes"));
    }
    Ok(())
}

fn check_label(label: &str) -> Result<(), ApiError> {
    if label.is_empty() || label.len() > 256 || label.contains('\0') {
        return Err(invalid("workspace labels must contain between one and 256 UTF-8 bytes without NUL"));
    }
    Ok(())
}

fn check_path(path: &Path) -> Result<(), ApiError> {
    let text = path.to_str().ok_or_else(|| invalid("workspace paths must be UTF-8"))?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.contains('\0')
        || text.split('/').skip(1).any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid("workspace paths must be absolute, nonempty, and free of empty/dot/NUL components"));
    }
    Ok(())
}

fn check_navigation(navigation: &ProjectWorkspaceNavigation, id: &str) -> Result<(), ApiError> {
    if navigation.back.len() > 256 || navigation.forward.len() > 256 {
        return Err(invalid("workspace navigation exceeds 256 entries in one direction"));
    }
    if navigation
        .current
        .iter()
        .chain(&navigation.back)
        .chain(&navigation.forward)
        .any(|address| address.module_id != id)
    {
        return Err(invalid("workspace navigation address belongs to a different module"));
    }
    Ok(())
}

fn check_hash(hash: &str) -> Result<(), ApiError> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(invalid("workspace hashes must be 64 lowercase hexadecimal characters"));
    }
    Ok(())
}

fn raw_preflight(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() as u64 > MANIFEST_BYTES || std::str::from_utf8(bytes).is_err() {
        return Err(invalid("workspace manifest exceeds 256 KiB or is not UTF-8"));
    }
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut string = false;
    let mut escaped = false;
    for &byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    nodes += 1;
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(|| invalid("unbalanced workspace JSON"))?,
                b',' | b':' => nodes += 1,
                _ => {}
            }
            if depth > 8 || nodes > 32768 {
                return Err(invalid("workspace JSON exceeds depth eight or structural work budget"));
            }
        }
    }
    if depth != 0 || string {
        return Err(invalid("unbalanced workspace JSON"));
    }
    Ok(())
}

fn preflight_sources(manifest: &ProjectWorkspaceManifest) -> Result<Vec<SourceFile>, ApiError> {
    let mut sources = Vec::with_capacity(manifest.modules.len());
    let mut total = 0u64;
    let mut selections = HashSet::new();
    for module in &manifest.modules {
        let source = open_source(&module.source_path)?;
        total = total.checked_add(source.stamp.length).ok_or_else(|| invalid("source size overflow"))?;
        if total > TOTAL_SOURCE_BYTES || source.stamp.length != module.identity.source_bytes {
            return Err(invalid("workspace source size changed or aggregate size exceeds 256 MiB"));
        }
        let canonical = module.source_path.canonicalize().map_err(|error| invalid(error.to_string()))?;
        if !selections.insert((canonical, module.identity.architecture.as_str(), module.image)) {
            return Err(invalid("duplicate canonical source, architecture and image selection"));
        }
        validate_source_file(&module.source_path, &source)?;
        sources.push(source);
    }
    Ok(sources)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SourceStamp {
    length: u64,
    modified: Option<std::time::SystemTime>,
    identity: Option<(u64, u64, i64, i64)>,
}

impl SourceStamp {
    fn new(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            Some((metadata.dev(), metadata.ino(), metadata.ctime(), metadata.ctime_nsec()))
        };
        #[cfg(not(unix))]
        let identity = None;
        Self { length: metadata.len(), modified: metadata.modified().ok(), identity }
    }
}

pub(crate) struct SourceFile {
    file: File,
    stamp: SourceStamp,
}

impl SourceFile {
    fn read_bounded_controlled(
        &self,
        limit: u64,
        control: &ProjectWorkspaceTaskControl<'_>,
    ) -> Result<Vec<u8>, ApiError> {
        control.check()?;
        self.check_descriptor()?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 8192];
        while bytes.len() as u64 <= limit {
            control.check()?;
            let remaining = (limit + 1 - bytes.len() as u64).min(buffer.len() as u64) as usize;
            let count = self.read_at(&mut buffer[..remaining], bytes.len() as u64)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        if bytes.len() as u64 > limit || bytes.len() as u64 != self.stamp.length {
            return Err(invalid("local document grew or changed while reading"));
        }
        self.check_descriptor()?;
        Ok(bytes)
    }

    fn hash_controlled(&self, control: &ProjectWorkspaceTaskControl<'_>) -> Result<String, ApiError> {
        control.check()?;
        self.check_descriptor()?;
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut buffer = [0u8; 65536];
        while length <= self.stamp.length {
            control.check()?;
            let remaining = (self.stamp.length + 1 - length).min(buffer.len() as u64) as usize;
            let count = self.read_at(&mut buffer[..remaining], length)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            length += count as u64;
        }
        if length != self.stamp.length {
            return Err(invalid("source changed while hashing"));
        }
        self.check_descriptor()?;
        Ok(rampage_arch::hex::bytes(&hash.finalize()))
    }

    fn read_at(&self, bytes: &mut [u8], offset: u64) -> Result<usize, ApiError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.read_at(bytes, offset).map_err(|error| invalid(error.to_string()))
        }
        #[cfg(not(unix))]
        {
            let _ = (bytes, offset);
            Err(invalid("checked positional source reads are unavailable on this platform"))
        }
    }

    fn check_descriptor(&self) -> Result<(), ApiError> {
        let metadata = self.file.metadata().map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() || SourceStamp::new(&metadata) != self.stamp {
            return Err(invalid("local source was modified while open"));
        }
        Ok(())
    }
}

pub(crate) fn open_source(path: &Path) -> Result<SourceFile, ApiError> {
    open_regular(path, SOURCE_BYTES)
}

fn open_regular(path: &Path, limit: u64) -> Result<SourceFile, ApiError> {
    let before = std::fs::symlink_metadata(path).map_err(|error| invalid(error.to_string()))?;
    if !before.is_file() || before.len() > limit {
        return Err(invalid("workspace input must be a bounded regular file, not a symlink or special file"));
    }
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        File::from(open(path, flags, Mode::empty()).map_err(|error| invalid(error.to_string()))?)
    };
    #[cfg(not(unix))]
    let file: File = {
        return Err(invalid("checked workspace regular-file opening is unavailable on this platform"));
    };
    let source = SourceFile { file, stamp: SourceStamp::new(&before) };
    validate_source_file(path, &source)?;
    Ok(source)
}

pub(crate) fn validate_source_file(path: &Path, source: &SourceFile) -> Result<(), ApiError> {
    source.check_descriptor()?;
    let current = std::fs::symlink_metadata(path).map_err(|error| invalid(error.to_string()))?;
    if !current.is_file() || SourceStamp::new(&current) != source.stamp {
        return Err(invalid("local source pathname was modified or replaced"));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

#[cfg(test)]
mod raw_tests {
    use std::sync::atomic::AtomicBool;

    use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

    use super::{ProjectWorkspaceTaskControl, identity_controlled, uncontrolled};
    use crate::ApiError;

    #[test]
    fn raw_cannot_acquire_a_legacy_workspace_identity() {
        for profile in [RawProfile::Msp430, RawProfile::Avr8, RawProfile::Mos6502] {
            let options = RawCodeOptions {
                profile,
                base: 0x1000,
                entry: None,
                seeds: vec![],
                vector_table: None,
                pointer_tables: false,
            };
            let binary = Binary::from_raw_code(vec![0; 4], options).unwrap();
            let result = uncontrolled(|control| identity_controlled(&binary, control));
            assert!(
                matches!(result, Err(ApiError::Invalid(ref message))
                if message.contains("Raw workspace persistence is unsupported")),
                "{result:?}"
            );
        }
    }

    #[test]
    fn cancellation_keeps_its_unavailable_classification_before_raw_workspace_refusal() {
        let options = RawCodeOptions {
            profile: RawProfile::Avr8,
            base: 0x1000,
            entry: None,
            seeds: vec![],
            vector_table: None,
            pointer_tables: false,
        };
        let binary = Binary::from_raw_code(vec![0; 4], options).unwrap();
        let cancelled = AtomicBool::new(true);
        let mut observer = |_| {};
        let control = ProjectWorkspaceTaskControl::new(&cancelled, &mut observer);
        let result = identity_controlled(&binary, &control);
        assert!(
            matches!(result, Err(ApiError::Unavailable(ref message))
            if message.contains("cancellation")),
            "{result:?}"
        );
    }
}
