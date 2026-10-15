//! Client-local capture composition over the unchanged read-only debugger query protocol.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rampage_arch::Arch;
use rampage_loaders::snapshot::{
    Snapshot, SnapshotModule, SnapshotPlatform, SnapshotRegion, SnapshotRegister, SnapshotTarget,
};
use rampage_loaders::{Binary, Details, Format};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{ApiError, DebuggerAddress, DebuggerPermissions, DebuggerRequest, DebuggerToken, Project};

const RESPONSE_BYTES: usize = 65_536;
const DOCUMENT_BYTES: usize = 1024 * 1024;
const READ_SEMANTICS: &str = "LLDB ReadMemory may normalize software-breakpoint trap bytes";
const ADDRESS_SEMANTICS: &str = "LLDB file virtual address, not a file byte offset";

#[derive(Debug, Clone)]
pub struct DebuggerCaptureRequest {
    pub expected_token: DebuggerToken,
    pub module_index: usize,
    pub module_uuid: String,
    pub thread_id: u64,
    pub file_address: u64,
    pub size: u64,
    pub permissions: DebuggerPermissions,
}

/// Display-only information. A serialized summary cannot authorize publication or import.
#[derive(Debug, Clone, Serialize)]
pub struct DebuggerCaptureSummary {
    pub token: DebuggerToken,
    pub module_index: usize,
    pub module_uuid: String,
    pub module_name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub thread_id: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub file_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub load_address: u64,
    pub size: u64,
    pub permissions: DebuggerPermissions,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_base: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_base: u64,
    pub bytes_sha256: String,
    pub document_sha256: String,
    pub source_image_sha256: String,
    pub limitations: Vec<String>,
    /// Preparation is filesystem-write-free; this compatibility field is currently always empty.
    pub retained_staging_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebuggerCapturePublicationStatus {
    /// The link and required post-publication checks succeeded, not an ongoing immutability/source proof.
    Published,
    /// Publication may have occurred, or a post-link check failed. Inspect explicitly before further use.
    PublishedUncertain,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerCapturePublication {
    pub path: PathBuf,
    pub document_sha256: String,
    pub captured_bytes: u64,
    pub status: DebuggerCapturePublicationStatus,
    pub warnings: Vec<String>,
    pub retained_staging_paths: Vec<PathBuf>,
}

/// Paths requiring operator inspection/cleanup, not authorization to unlink their current occupants.
#[derive(Debug, Clone, Serialize)]
pub struct DebuggerCaptureStagingRetention {
    pub paths: Vec<PathBuf>,
    pub message: String,
}

impl std::fmt::Display for DebuggerCaptureStagingRetention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; retained staging requires operator inspection/cleanup: {:?}", self.message, self.paths)
    }
}

impl std::error::Error for DebuggerCaptureStagingRetention {}

#[derive(Debug)]
pub(crate) struct PublicationOutcome {
    pub(crate) path: PathBuf,
    pub(crate) document_sha256: String,
    pub(crate) status: DebuggerCapturePublicationStatus,
    pub(crate) warnings: Vec<String>,
    pub(crate) retained_staging_paths: Vec<PathBuf>,
}

impl PublicationOutcome {
    pub(crate) fn uncertain(&mut self, error: ApiError) {
        self.status = DebuggerCapturePublicationStatus::PublishedUncertain;
        if self.warnings.len() < 8 {
            self.warnings.push(error.to_string().chars().take(512).collect());
        }
    }
}

/// Immutable process-local authority bound to the exact original project, not to a supplied receipt.
pub struct DebuggerCapturePreview {
    source: Arc<Project>,
    capture: Project,
    selection: DebuggerCaptureRequest,
    document: Box<[u8]>,
    summary: DebuggerCaptureSummary,
}

impl std::fmt::Debug for DebuggerCapturePreview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DebuggerCapturePreview").field("summary", &self.summary).finish_non_exhaustive()
    }
}

impl DebuggerCapturePreview {
    pub fn summary(&self) -> &DebuggerCaptureSummary {
        &self.summary
    }

    pub fn source_project(&self) -> &Arc<Project> {
        &self.source
    }

    /// Explicitly compares prepared bytes with the retained original, not with a subsequently saved pathname.
    pub fn compare_original(&self) -> Result<crate::RuntimeComparison, ApiError> {
        let identity = static_identity(&self.source.binary, &self.selection)?;
        if identity.sha256 != self.summary.source_image_sha256 {
            return Err(invalid("original selected image changed; prepare again"));
        }
        let comparison = self.capture.compare_runtime_bytes(
            &self.summary.module_uuid,
            &self.source.binary,
            &[crate::RuntimeRange { address: self.summary.load_address, size: self.selection.size }],
        )?;
        backing(&self.source.binary)?;
        Ok(comparison)
    }

    /// Saves historical observations only. This does not contact LLDB, open a workspace or import anything.
    /// Uncertain outcomes retain destination/hash context and never authorize opening or deleting a pathname.
    pub fn publish(&self, output: &Path) -> Result<DebuggerCapturePublication, ApiError> {
        let identity = static_identity(&self.source.binary, &self.selection)?;
        if identity.sha256 != self.summary.source_image_sha256 {
            return Err(invalid("original selected image changed; prepare again"));
        }
        let outcome = publish_private_document(output, &self.document, || backing(&self.source.binary))?;
        let mut retained_staging_paths = self.summary.retained_staging_paths.clone();
        retained_staging_paths.extend(outcome.retained_staging_paths);
        Ok(DebuggerCapturePublication {
            path: outcome.path,
            document_sha256: outcome.document_sha256,
            captured_bytes: self.selection.size,
            status: outcome.status,
            warnings: outcome.warnings,
            retained_staging_paths,
        })
    }
}

pub(crate) fn publish_private_document(
    output: &Path,
    document: &[u8],
    validate: impl Fn() -> Result<(), ApiError>,
) -> Result<PublicationOutcome, ApiError> {
    publish_private_document_observed(output, document, |_| validate())
}

#[derive(Clone, Copy)]
pub(crate) enum PublicationCheckPhase {
    BeforeStaging,
    BeforeLink,
    AfterLink,
}

pub(crate) fn publish_private_document_observed(
    output: &Path,
    document: &[u8],
    mut validate: impl FnMut(PublicationCheckPhase) -> Result<(), ApiError>,
) -> Result<PublicationOutcome, ApiError> {
    if document.is_empty() || document.len() > DOCUMENT_BYTES {
        return Err(ApiError::Invalid("private document exceeds its publication byte budget".into()));
    }
    validate(PublicationCheckPhase::BeforeStaging)?;
    let mut outcome = local::publish(output, document, || validate(PublicationCheckPhase::BeforeLink))?;
    if let Err(error) = validate(PublicationCheckPhase::AfterLink) {
        outcome.uncertain(error);
    }
    Ok(outcome)
}

/// Reads an explicitly selected local publication with matching bytes, not an authority-bearing receipt.
/// Snapshot semantics and current workspace/source binding must be checked separately before opening it.
pub fn read_debugger_capture_publication(path: &Path, document_sha256: &str) -> Result<Vec<u8>, ApiError> {
    if document_sha256.len() != 64
        || !document_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("publication SHA-256 must be exactly 64 lowercase hexadecimal characters"));
    }
    local::read_publication(path, document_sha256)
}

/// Reads an explicitly selected private document as untrusted bytes, never as a source or consent receipt.
pub(crate) fn read_private_document(path: &Path, limit: usize) -> Result<Vec<u8>, ApiError> {
    if limit == 0 || limit > DOCUMENT_BYTES {
        return Err(ApiError::Invalid("private document read limit must be within one MiB".into()));
    }
    local::read_private_document(path, limit)
}

pub fn prepare_debugger_capture(
    source: Arc<Project>,
    socket: &Path,
    request: &DebuggerCaptureRequest,
    timeout: Duration,
    cancellation: &AtomicBool,
) -> Result<DebuggerCapturePreview, ApiError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| invalid("capture deadline overflows"))?;
    checkpoint(deadline, cancellation)?;
    validate_selection(request)?;
    let identity = static_identity(&source.binary, request)?;
    checkpoint(deadline, cancellation)?;
    let token = request.expected_token.clone();
    let describe = DebuggerRequest::DescribeSession {
        version: 1,
        expected_token: Some(token.clone()),
        response_budget: Some(RESPONSE_BYTES),
    };
    let modules = DebuggerRequest::ListModules {
        version: 1,
        expected_token: token.clone(),
        response_budget: Some(RESPONSE_BYTES),
        offset: Some(request.module_index),
        limit: Some(1),
    };
    let resolve = DebuggerRequest::ResolveModuleAddress {
        version: 1,
        expected_token: token.clone(),
        response_budget: Some(RESPONSE_BYTES),
        module_uuid: request.module_uuid.clone(),
        file_address: DebuggerAddress::Integer(request.file_address),
    };
    let registers = DebuggerRequest::ReadRegisters {
        version: 1,
        expected_token: token.clone(),
        response_budget: Some(RESPONSE_BYTES),
        thread_id: DebuggerAddress::Integer(request.thread_id),
        registers: Some(vec!["rip".into(), "rsp".into(), "rflags".into()]),
    };
    let mut observations = Vec::with_capacity(9);
    let mut query = |query: &DebuggerRequest| -> Result<Value, ApiError> {
        checkpoint(deadline, cancellation)?;
        let response = crate::query_debugger(socket, query, deadline)?;
        checkpoint(deadline, cancellation)?;
        if !response.ok {
            let error = response.error.ok_or_else(|| invalid("missing debugger refusal"))?;
            return Err(invalid(&format!("debugger capture refused: {}: {}", error.code, error.message)));
        }
        let data = response.data.clone().ok_or_else(|| invalid("missing debugger evidence"))?;
        observations.push(serde_json::to_value(response).map_err(encode_error)?);
        Ok(data)
    };
    let session = query(&describe)?;
    validate_session(&session, request)?;
    let page = query(&modules)?;
    let module = validate_module_page(&page, &session, request, &identity)?;
    let resolution = query(&resolve)?;
    let load = validate_resolution(&resolution, &module, request, &identity)?;
    let before_registers = query(&registers)?;
    validate_registers(&before_registers, request.thread_id)?;
    let memory_request = DebuggerRequest::ReadMemory {
        version: 1,
        expected_token: token.clone(),
        response_budget: Some(RESPONSE_BYTES),
        address: DebuggerAddress::Integer(load),
        size: request.size as usize,
        permissions: request.permissions.clone(),
        thread_id: Some(DebuggerAddress::Integer(request.thread_id)),
    };
    let memory = query(&memory_request)?;
    let bytes = validate_memory(&memory, &before_registers, load, request)?;
    if query(&registers)? != before_registers {
        return Err(invalid("selected thread registers or context changed across capture"));
    }
    if query(&resolve)? != resolution {
        return Err(invalid("module resolution changed across capture"));
    }
    if query(&modules)? != page {
        return Err(invalid("selected module changed across capture"));
    }
    if query(&describe)? != session {
        return Err(invalid("session context changed across capture"));
    }
    for (first, repeated) in [(0, 8), (1, 7), (2, 6), (3, 5)] {
        if observations[first] != observations[repeated] {
            return Err(invalid("repeated debugger observation envelope changed across capture"));
        }
    }
    checkpoint(deadline, cancellation)?;
    backing(&source.binary)?;
    let limitations = limitations();
    let provenance = json!({
        "producer": "rampage client-local debugger capture",
        "consistency": "revalidated-non-atomic",
        "atomic_snapshot": false,
        "historical_token": token,
        "source_image_sha256": identity.sha256,
        "module_index": request.module_index,
        "thread_id": request.thread_id,
        "file_address": format!("{:#x}", request.file_address),
        "requested_bytes": request.size,
        "limitations": limitations,
        "observations": observations,
    });
    let values = &before_registers["context"]["registers"];
    let snapshot = Snapshot {
        format: "rampage-snapshot-v1".into(),
        arch: "x86_64".into(),
        big_endian: false,
        data_big_endian: false,
        provenance: serde_json::to_string(&provenance).map_err(encode_error)?,
        regions: vec![SnapshotRegion {
            name: "explicit debugger capture".into(),
            address: format!("{load:#x}"),
            permissions: permissions(&request.permissions).into(),
            bytes: rampage_arch::hex::bytes(&bytes),
            thumb: false,
        }],
        seeds: Vec::new(),
        entry: None,
        modules: vec![SnapshotModule {
            name: text(&module, "name")?.into(),
            path: text(&module, "path")?.into(),
            uuid: uuid(&request.module_uuid)?,
            image_base: format!("{:#x}", identity.image_base),
            runtime_base: text(&module, "runtime_base")?.into(),
        }],
        registers: ["rip", "rsp", "rflags"]
            .into_iter()
            .map(|name| SnapshotRegister {
                thread_id: format!("{:#x}", request.thread_id),
                name: name.into(),
                value: values[name].as_str().unwrap_or_default().into(),
            })
            .collect(),
        target: Some(SnapshotTarget { platform: SnapshotPlatform::Darwin, compiler: None }),
    };
    let document = serde_json::to_vec_pretty(&snapshot).map_err(encode_error)?;
    if document.len() > DOCUMENT_BYTES {
        return Err(invalid("capture document exceeds client-local byte limit"));
    }
    backing(&source.binary)?;
    checkpoint(deadline, cancellation)?;
    let capture = Project::new(validate_document(&document)?);
    checkpoint(deadline, cancellation)?;
    let revalidated = static_identity(&source.binary, request)?;
    if revalidated.sha256 != identity.sha256 || revalidated.image_base != identity.image_base {
        return Err(invalid("original selected image changed during capture"));
    }
    checkpoint(deadline, cancellation)?;
    let summary = DebuggerCaptureSummary {
        token: request.expected_token.clone(),
        module_index: request.module_index,
        module_uuid: uuid(&request.module_uuid)?,
        module_name: text(&module, "name")?.into(),
        thread_id: request.thread_id,
        file_address: request.file_address,
        load_address: load,
        size: request.size,
        permissions: request.permissions.clone(),
        image_base: identity.image_base,
        runtime_base: address(&module["runtime_base"])?,
        bytes_sha256: digest(&bytes),
        document_sha256: digest(&document),
        source_image_sha256: identity.sha256,
        limitations,
        retained_staging_paths: Vec::new(),
    };
    Ok(DebuggerCapturePreview { source, capture, selection: request.clone(), document: document.into(), summary })
}

fn validate_document(document: &[u8]) -> Result<Binary, ApiError> {
    if document.is_empty() || document.len() > DOCUMENT_BYTES {
        return Err(invalid("capture document exceeds local bounded-byte policy"));
    }
    let binary = Binary::from_snapshot_bytes(document.to_vec())
        .map_err(|error| invalid(&format!("completed capture failed semantic snapshot loading: {error}")))?;
    if binary.format != Format::Snapshot
        || binary.arch != Arch::X86_64
        || binary.file_bytes() != document
        || binary.entry.is_some()
        || !binary.function_starts.is_empty()
        || binary.segments.len() != 1
        || binary.snapshot_modules.len() != 1
        || binary.snapshot_registers.len() != 3
        || binary.big_endian
        || binary.target().big_endian
        || binary
            .snapshot_target
            .as_ref()
            .is_none_or(|target| target.platform != SnapshotPlatform::Darwin || target.compiler.is_some())
    {
        return Err(invalid("completed capture does not match the bounded M1 snapshot context"));
    }
    Ok(binary)
}

fn retain_staging(error: ApiError, paths: Vec<PathBuf>) -> ApiError {
    let mut retention = match error {
        ApiError::DebuggerCaptureStagingRetained(retention) => retention,
        error => DebuggerCaptureStagingRetention {
            paths: Vec::new(),
            message: error.to_string().chars().take(512).collect(),
        },
    };
    for path in paths {
        if !retention.paths.contains(&path) {
            retention.paths.push(path);
        }
    }
    ApiError::DebuggerCaptureStagingRetained(retention)
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(format!("debugger capture: {message}"))
}

fn encode_error(error: serde_json::Error) -> ApiError {
    invalid(&format!("cannot encode capture evidence: {error}"))
}

fn digest(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn checkpoint(deadline: Instant, cancellation: &AtomicBool) -> Result<(), ApiError> {
    if cancellation.load(Ordering::Acquire) {
        return Err(ApiError::Unavailable("debugger capture cancelled".into()));
    }
    if Instant::now() >= deadline {
        return Err(ApiError::Unavailable("debugger capture composition deadline exceeded".into()));
    }
    Ok(())
}

fn backing(binary: &Binary) -> Result<(), ApiError> {
    binary.validate_backing_source().map_err(|error| invalid(&format!("original static backing: {error}")))
}

fn validate_selection(request: &DebuggerCaptureRequest) -> Result<(), ApiError> {
    if !(1..=4096).contains(&request.size)
        || request.module_index >= 4096
        || request.thread_id == 0
        || request.thread_id == u64::MAX
        || request.file_address == u64::MAX
        || request.file_address.checked_add(request.size).is_none()
    {
        return Err(invalid("select one module/thread and a nonoverflowing 1..4096-byte file-VA range"));
    }
    uuid(&request.module_uuid)?;
    DebuggerRequest::DescribeSession {
        version: 1,
        expected_token: Some(request.expected_token.clone()),
        response_budget: Some(RESPONSE_BYTES),
    }
    .validate()
}

fn permissions(value: &DebuggerPermissions) -> &'static str {
    match value {
        DebuggerPermissions::Read => "r--",
        DebuggerPermissions::ReadWrite => "rw-",
        DebuggerPermissions::ReadExecute => "r-x",
        DebuggerPermissions::ReadWriteExecute => "rwx",
    }
}

fn keys(value: &Value, names: &[&str]) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(|| invalid("expected an evidence object"))?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err(invalid("missing or unknown evidence fields"));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    value[name].as_str().ok_or_else(|| invalid(&format!("missing or unknown {name}")))
}

fn number(value: &Value, name: &str) -> Result<u64, ApiError> {
    value[name].as_u64().ok_or_else(|| invalid(&format!("invalid {name}")))
}

fn address(value: &Value) -> Result<u64, ApiError> {
    let parsed = if let Some(value) = value.as_u64() {
        value
    } else {
        let digits = value
            .as_str()
            .and_then(|value| value.strip_prefix("0x"))
            .filter(|digits| {
                !digits.is_empty() && digits.len() <= 16 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| invalid("invalid hexadecimal evidence address"))?;
        u64::from_str_radix(digits, 16).map_err(|_| invalid("evidence address exceeds width"))?
    };
    if parsed == u64::MAX {
        return Err(invalid("unknown SDK address"));
    }
    Ok(parsed)
}

fn uuid(value: &str) -> Result<String, ApiError> {
    let canonical = rampage_loaders::snapshot::canonical_module_identity(value);
    if canonical.len() != 32 || !canonical.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("requires an exact 16-byte Mach-O UUID"));
    }
    Ok(canonical)
}

fn apple_x64(triple: &str) -> Result<(), ApiError> {
    let parts: Vec<_> = triple.split('-').collect();
    if parts.len() != 3
        || parts[0] != "x86_64"
        || parts[1] != "apple"
        || !["darwin", "macosx", "macos"].iter().any(|prefix| {
            parts[2].strip_prefix(*prefix).is_some_and(|version| {
                version.is_empty()
                    || version.as_bytes()[0].is_ascii_digit()
                        && version.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
        })
    {
        return Err(invalid("only ordinary x86_64 Apple Darwin triples are supported for capture"));
    }
    Ok(())
}

fn little_data(value: &Value) -> Result<(), ApiError> {
    keys(value, &["order", "source"])?;
    if text(value, "order")? != "little" || text(value, "source")? != "LLDB target byte order" {
        return Err(invalid("runtime DATA endianness must be affirmatively known little-endian"));
    }
    Ok(())
}

struct StaticIdentity {
    sha256: String,
    image_base: u64,
}

fn static_identity(binary: &Binary, request: &DebuggerCaptureRequest) -> Result<StaticIdentity, ApiError> {
    backing(binary)?;
    if binary.format != Format::MachO || binary.arch != Arch::X86_64 || binary.big_endian {
        return Err(invalid("capture requires an ordinary little-endian x86_64 static Mach-O"));
    }
    let Details::MachO(details) = &binary.details else {
        return Err(invalid("static Mach-O header context is unavailable"));
    };
    if details.uuid.as_deref().map(uuid).transpose()? != Some(uuid(&request.module_uuid)?) || details.encrypted {
        return Err(invalid("static Mach-O UUID does not match or image is encrypted"));
    }
    let image = binary.image_bytes();
    let header = image.get(..32).ok_or_else(|| invalid("truncated static Mach-O header"))?;
    let word = |at| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    if header[..4] != [0xcf, 0xfa, 0xed, 0xfe] || word(4) != 0x0100_0007 || word(8) != 3 {
        return Err(invalid("unsupported static Mach-O CPU subtype or code endianness"));
    }
    if !matches!(word(12), 2 | 6 | 8) || binary.target().big_endian {
        return Err(invalid("static Mach-O must be an ordinary executable, dylib or bundle"));
    }
    let header_size = 32u64 + u64::from(word(20));
    if header_size > image.len() as u64 || binary.segments.len() > 16384 || binary.sections.len() > 16384 {
        return Err(invalid("static header or mapping limit exceeded"));
    }
    let mut header_mappings = binary.segments.iter().filter(|segment| {
        segment.file_offset == 0
            && segment.file_size >= header_size
            && segment.size >= header_size
            && segment.perms.read
    });
    let header_mapping = header_mappings.next().ok_or_else(|| invalid("static header has no readable mapping"))?;
    if header_mappings.next().is_some() {
        return Err(invalid("static header mapping is ambiguous"));
    }
    let end = request.file_address.checked_add(request.size).ok_or_else(|| invalid("static range overflows"))?;
    let mut mappings = binary.segments.iter().filter(|segment| {
        segment.address < end && segment.address.checked_add(segment.size).is_some_and(|at| at > request.file_address)
    });
    let mapping = mappings.next().ok_or_else(|| invalid("static range is not mapped"))?;
    let offset = request.file_address.checked_sub(mapping.address).ok_or_else(|| invalid("static mapping gap"))?;
    let file_end = mapping
        .file_offset
        .checked_add(offset)
        .and_then(|at| at.checked_add(request.size))
        .ok_or_else(|| invalid("static file range overflows"))?;
    if mappings.next().is_some()
        || !mapping.perms.read
        || offset.checked_add(request.size).is_none_or(|at| at > mapping.file_size || at > mapping.size)
        || file_end > image.len() as u64
    {
        return Err(invalid("static range must fit one readable, unambiguous file-backed mapping"));
    }
    for section in &binary.sections {
        let section_end =
            section.address.checked_add(section.size).ok_or_else(|| invalid("static section overflows"))?;
        if section.address < end && section_end > request.file_address {
            let overlap = section.address.max(request.file_address);
            let overlap_end = section_end.min(end);
            let file = section.file_offset.ok_or_else(|| invalid("static range intersects unbacked section"))?;
            if overlap_end - section.address > section.file_size
                || file.checked_add(overlap - section.address)
                    != mapping.file_offset.checked_add(overlap - mapping.address)
            {
                return Err(invalid("static section contradicts file-backed mapping"));
            }
        }
    }
    let sha256 = digest(image);
    backing(binary)?;
    Ok(StaticIdentity { sha256, image_base: header_mapping.address })
}

fn validate_session(session: &Value, request: &DebuggerCaptureRequest) -> Result<(), ApiError> {
    keys(
        session,
        &[
            "pid",
            "state",
            "triple",
            "architecture",
            "target_byte_order",
            "data_byte_order",
            "address_byte_size",
            "module_count",
            "thread_count",
            "operations",
            "limits",
        ],
    )?;
    apple_x64(text(session, "triple")?)?;
    little_data(&session["data_byte_order"])?;
    if text(session, "state")? != "stopped"
        || text(session, "architecture")? != "x86_64"
        || text(session, "target_byte_order")? != "little"
        || number(session, "address_byte_size")? != 8
        || number(session, "pid")? == 0
        || !(1..=4096).contains(&number(session, "thread_count")?)
        || number(session, "module_count")? <= request.module_index as u64
        || number(session, "module_count")? > 4096
    {
        return Err(invalid("unsupported or unknown stopped-session context"));
    }
    let operations = session["operations"].as_array().ok_or_else(|| invalid("unknown session operations"))?;
    let expected =
        ["describe_session", "list_modules", "list_threads", "read_registers", "read_memory", "resolve_module_address"];
    if operations.len() != expected.len()
        || expected
            .iter()
            .any(|operation| operations.iter().filter(|value| value.as_str() == Some(*operation)).count() != 1)
    {
        return Err(invalid("unknown session operations"));
    }
    let limits = &session["limits"];
    let names = [
        "request_bytes",
        "response_bytes",
        "memory_bytes",
        "page_items",
        "modules",
        "threads",
        "resolution_work",
        "module_sections",
        "section_depth",
        "module_uuid_bytes",
    ];
    keys(limits, &names)?;
    for name in names {
        if number(limits, name)? == 0 {
            return Err(invalid("unknown debugger inspection limit"));
        }
    }
    if number(limits, "memory_bytes")? < request.size {
        return Err(invalid("requested range exceeds debugger inspection limit"));
    }
    Ok(())
}

fn module_fields(module: &Value, header: bool) -> Result<(), ApiError> {
    let mut names =
        vec!["index", "name", "path", "uuid", "triple", "target_byte_order", "lldb_byte_order", "address_byte_size"];
    if header {
        names.extend(["runtime_base", "image_base"]);
    }
    keys(module, &names)?;
    apple_x64(text(module, "triple")?)?;
    if text(module, "target_byte_order")? != "little"
        || number(module, "address_byte_size")? != 8
        || number(module, "lldb_byte_order")? != 4
        || text(module, "name")?.is_empty()
        || text(module, "name")?.len() > 4096
        || text(module, "path")?.len() > 4096
    {
        return Err(invalid("unsupported or unknown module context"));
    }
    Ok(())
}

fn validate_module_page(
    page: &Value,
    session: &Value,
    request: &DebuggerCaptureRequest,
    identity: &StaticIdentity,
) -> Result<Value, ApiError> {
    keys(page, &["items", "offset", "total", "next_offset"])?;
    let items = page["items"].as_array().ok_or_else(|| invalid("invalid module page"))?;
    let total = number(page, "total")?;
    let next = request.module_index as u64 + 1;
    if items.len() != 1
        || number(page, "offset")? != request.module_index as u64
        || total != number(session, "module_count")?
        || page["next_offset"] != if next < total { json!(next) } else { Value::Null }
    {
        return Err(invalid("module page does not match the one selected index"));
    }
    let module = &items[0];
    module_fields(module, true)?;
    if number(module, "index")? != request.module_index as u64
        || uuid(text(module, "uuid")?)? != uuid(&request.module_uuid)?
        || address(&module["image_base"])? != identity.image_base
    {
        return Err(invalid("module index, UUID or header mapping conflicts with selection"));
    }
    address(&module["runtime_base"])?;
    Ok(module.clone())
}

fn validate_resolution(
    resolution: &Value,
    module: &Value,
    request: &DebuggerCaptureRequest,
    identity: &StaticIdentity,
) -> Result<u64, ApiError> {
    keys(
        resolution,
        &[
            "module_uuid",
            "module",
            "module_context",
            "file_address",
            "load_address",
            "section",
            "mapping",
            "interpretation",
            "address_semantics",
            "proven_flow",
            "proven_layout",
        ],
    )?;
    let resolved_module = &resolution["module"];
    module_fields(resolved_module, false)?;
    for name in resolved_module.as_object().unwrap().keys() {
        if resolved_module[name] != module[name] {
            return Err(invalid("resolved module differs from the selected module page"));
        }
    }
    let context = &resolution["module_context"];
    keys(context, &["triple", "object_byte_order", "address_byte_size", "data_byte_order"])?;
    keys(&context["data_byte_order"], &["order", "source"])?;
    if context["triple"] != module["triple"]
        || context["object_byte_order"] != module["target_byte_order"]
        || context["address_byte_size"] != module["address_byte_size"]
        || text(&context["data_byte_order"], "order")? != "unknown"
        || text(&context["data_byte_order"], "source")? != "no runtime data interpretation"
        || uuid(text(resolution, "module_uuid")?)? != uuid(&request.module_uuid)?
        || text(resolution, "interpretation")? != "raw-addresses-only"
        || text(resolution, "address_semantics")? != ADDRESS_SEMANTICS
        || resolution["proven_flow"] != false
        || resolution["proven_layout"] != false
        || address(&resolution["file_address"])? != request.file_address
    {
        return Err(invalid("conflicting module context or missing literal raw-address qualifications"));
    }
    let load = address(&resolution["load_address"])?;
    let runtime_base = address(&module["runtime_base"])?;
    let relative = request
        .file_address
        .checked_sub(identity.image_base)
        .ok_or_else(|| invalid("range precedes static file header"))?;
    if runtime_base.checked_add(relative) != Some(load) {
        return Err(invalid("observed file/load mapping is not affine with the UUID-matched header mapping"));
    }
    let section = &resolution["section"];
    keys(section, &["index_path", "name", "file_base", "file_end", "load_base", "load_end", "offset", "ancestors"])?;
    let ancestors = section["ancestors"].as_array().ok_or_else(|| invalid("missing section ancestors"))?;
    if ancestors.len() >= 32 {
        return Err(invalid("section ancestry exceeds capture limit"));
    }
    let file_end = request.file_address.checked_add(request.size).ok_or_else(|| invalid("file range overflows"))?;
    let load_end = load.checked_add(request.size).ok_or_else(|| invalid("load range overflows"))?;
    let mut parent: Option<(Vec<u64>, u64, u64, u64, u64)> = None;
    for (depth, row) in ancestors.iter().chain(std::iter::once(section)).enumerate() {
        if depth < ancestors.len() {
            keys(row, &["index_path", "name", "file_base", "file_end", "load_base", "load_end"])?;
        }
        if !row["name"].is_null() {
            text(row, "name")?;
        }
        let path = row["index_path"]
            .as_array()
            .ok_or_else(|| invalid("missing section index path"))?
            .iter()
            .map(|value| value.as_u64().filter(|value| *value < 4096).ok_or_else(|| invalid("unknown section index")))
            .collect::<Result<Vec<_>, _>>()?;
        let file_base = address(&row["file_base"])?;
        let file_limit = address(&row["file_end"])?;
        let load_base = address(&row["load_base"])?;
        let load_limit = address(&row["load_end"])?;
        let size = file_limit
            .checked_sub(file_base)
            .filter(|size| *size > 0)
            .ok_or_else(|| invalid("invalid section bounds"))?;
        if path.len() != depth + 1
            || load_base.checked_add(size) != Some(load_limit)
            || file_base > request.file_address
            || file_end > file_limit
            || load_base > load
            || load_end > load_limit
            || request.file_address - file_base != load - load_base
        {
            return Err(invalid("whole capture range must fit the observed leaf and every ancestor"));
        }
        if let Some((parent_path, parent_file, parent_file_end, parent_load, parent_load_end)) = &parent
            && (!path.starts_with(parent_path)
                || file_base < *parent_file
                || file_limit > *parent_file_end
                || load_base < *parent_load
                || load_limit > *parent_load_end
                || parent_load.checked_add(file_base - parent_file) != Some(load_base))
        {
            return Err(invalid("section ancestry is not an inherited affine mapping"));
        }
        parent = Some((path, file_base, file_limit, load_base, load_limit));
    }
    if address(&section["offset"])? != request.file_address - address(&section["file_base"])? {
        return Err(invalid("SDK section offset conflicts with file address"));
    }
    let mapping = &resolution["mapping"];
    keys(mapping, &["base", "end", "permissions"])?;
    if address(&mapping["base"])? > load
        || address(&mapping["end"])? < load_end
        || text(mapping, "permissions")? != permissions(&request.permissions)
    {
        return Err(invalid("whole range must fit one known-readable mapping with exactly requested permissions"));
    }
    Ok(load)
}

fn validate_stop(value: &Value) -> Result<(), ApiError> {
    keys(value, &["source", "is_stopped", "stop_reason"])?;
    let reason = number(value, "stop_reason")?;
    if reason > u32::MAX as u64 || !value["is_stopped"].is_boolean() {
        return Err(invalid("unknown selected-thread stop evidence"));
    }
    match text(value, "source")? {
        "SBThread.IsStopped" if value["is_stopped"] == true => Ok(()),
        "SBThread.GetStopReason/current-process-stop"
            if value["is_stopped"] == false && current_stop_reason(reason) =>
        {
            Ok(())
        }
        _ => Err(invalid("missing affirmative SDK state or current-stop evidence")),
    }
}

fn current_stop_reason(reason: u64) -> bool {
    // LLDB StopReason at the bridge's pinned swiftlang/llvm-project 1b669c3f63758879bb0c517a589abdea4c6efbeb.
    const RECOGNIZED: &[(u64, &str)] = &[
        (2, "Trace"),
        (3, "Breakpoint"),
        (4, "Watchpoint"),
        (5, "Signal"),
        (6, "Exception"),
        (7, "Exec"),
        (8, "PlanComplete"),
        (9, "ThreadExiting"),
        (10, "Instrumentation"),
        (11, "ProcessorTrace"),
        (12, "Fork"),
        (13, "VFork"),
        (14, "VForkDone"),
        (15, "Interrupt"),
    ];
    RECOGNIZED.iter().any(|(value, _)| *value == reason)
}

fn validate_registers(registers: &Value, thread: u64) -> Result<(), ApiError> {
    keys(registers, &["thread_id", "required_registers", "context", "data_byte_order"])?;
    little_data(&registers["data_byte_order"])?;
    if address(&registers["thread_id"])? != thread || registers["required_registers"] != json!(["rflags", "rip", "rsp"])
    {
        return Err(invalid("register evidence must name the selected thread and exact core registers"));
    }
    let context = &registers["context"];
    keys(context, &["stop_evidence", "frame_id", "pc", "sp", "registers"])?;
    validate_stop(&context["stop_evidence"])?;
    let values = &context["registers"];
    keys(values, &["rip", "rsp", "rflags"])?;
    if number(context, "frame_id")? != 0
        || address(&context["pc"])? != address(&values["rip"])?
        || address(&context["sp"])? != address(&values["rsp"])?
        || address(&values["rflags"])? > u32::MAX as u64
        || ["rip", "rsp", "rflags"].iter().any(|name| !values[*name].is_string())
    {
        return Err(invalid("conflicting top-frame registers or unsupported register width"));
    }
    Ok(())
}

fn validate_memory(
    memory: &Value,
    registers: &Value,
    load: u64,
    request: &DebuggerCaptureRequest,
) -> Result<Vec<u8>, ApiError> {
    keys(
        memory,
        &[
            "address",
            "size",
            "permissions",
            "bytes_hex",
            "data_byte_order",
            "stop_evidence",
            "thread_id",
            "interpretation",
            "read_semantics",
        ],
    )?;
    little_data(&memory["data_byte_order"])?;
    validate_stop(&memory["stop_evidence"])?;
    if address(&memory["address"])? != load
        || number(memory, "size")? != request.size
        || address(&memory["thread_id"])? != request.thread_id
        || text(memory, "permissions")? != permissions(&request.permissions)
        || memory["stop_evidence"] != registers["context"]["stop_evidence"]
        || memory["data_byte_order"] != registers["data_byte_order"]
        || text(memory, "interpretation")? != "raw-bytes-only"
        || text(memory, "read_semantics")? != READ_SEMANTICS
    {
        return Err(invalid(
            "memory evidence differs from selected range/thread/permissions or raw ReadMemory semantics",
        ));
    }
    let hex = text(memory, "bytes_hex")?;
    if hex.len() != request.size as usize * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("memory response is partial or is not complete ASCII hexadecimal bytes"));
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("invalid memory hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("invalid memory hex"))
        })
        .collect()
}

fn limitations() -> Vec<String> {
    [
        "Historical token identifies the observed stop, not a claim that the process is currently stopped.",
        "Nine revalidated observations are non-atomic; matching tokens and fresh checks are not an atomic snapshot.",
        "UUID/header mapping does not prove runtime/static byte equality, process authenticity, flow or layout.",
        READ_SEMANTICS,
        "Raw-addresses-only; LLDB file virtual address, not a file byte offset.",
        "The whole range fits the observed leaf/ancestors; no full intersecting-section proof is supplied by v1.",
        "Backing metadata checks are not atomic with external writes or truncation; keep source files quiescent.",
        "Darwin is declared ABI context from the positive Apple triple; compiler is unknown and omitted.",
        "Entry is null and seeds are empty; registers do not authorize automatic PC navigation or discovery.",
        "Save is explicit and client-local; import and comparison require separate explicit user actions.",
        "Private directories restrict other users, not same-user namespace manipulation or endpoint impersonation.",
        "Prepare validates owned snapshot bytes without filesystem staging; only explicit Save creates staging files.",
        "Save staging paths are retained for explicit operator inspection/cleanup, never automatically unlinked.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(not(unix))]
mod local {
    use super::*;

    pub(super) fn read_publication(_: &Path, _: &str) -> Result<Vec<u8>, ApiError> {
        Err(ApiError::Unavailable("debugger capture publication reading is unsupported on this platform".into()))
    }

    pub(super) fn read_private_document(_: &Path, _: usize) -> Result<Vec<u8>, ApiError> {
        Err(ApiError::Unavailable("private document reading is unsupported on this platform".into()))
    }

    pub(super) fn publish(
        _: &Path,
        _: &[u8],
        _: impl FnOnce() -> Result<(), ApiError>,
    ) -> Result<PublicationOutcome, ApiError> {
        Err(ApiError::Unavailable("debugger capture publication is unavailable on this platform".into()))
    }
}

#[cfg(unix)]
mod local {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    use std::sync::atomic::AtomicU64;

    use rustix::fs::{AtFlags, Mode, OFlags, linkat, open, openat, statat};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[cfg(test)]
    struct TestScratch(PathBuf);

    #[cfg(test)]
    impl TestScratch {
        fn directory() -> (Self, Directory) {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;

            let path = std::env::temp_dir().canonicalize().unwrap().join(unique_name("capture-publication-test"));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            let directory = Directory::open(&path, true).unwrap();
            (Self(path), directory)
        }
    }

    #[cfg(test)]
    impl Drop for TestScratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove controlled test scratch");
        }
    }

    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    fn io_error(error: impl std::fmt::Display) -> ApiError {
        ApiError::Unavailable(format!("client-local capture file: {error}"))
    }

    fn same_file(first: &Metadata, second: &Metadata) -> bool {
        first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.uid() == second.uid()
            && first.mode() == second.mode()
    }

    struct Directory {
        path: PathBuf,
        file: File,
        chain: Vec<Metadata>,
    }

    impl Directory {
        fn open(path: &Path, private: bool) -> Result<Self, ApiError> {
            if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
                return Err(invalid("output must have an explicit absolute parent path"));
            }
            let raw = path.as_os_str().as_bytes();
            if raw != b"/"
                && raw.split(|byte| *byte == b'/').skip(1).any(|part| part.is_empty() || part == b"." || part == b"..")
            {
                return Err(invalid("directory path contains empty, dot or parent components"));
            }
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut file = File::from(open("/", flags, Mode::empty()).map_err(io_error)?);
            let mut chain = vec![file.metadata().map_err(io_error)?];
            for component in path.components().skip(1) {
                let Component::Normal(name) = component else {
                    return Err(invalid("invalid directory path component"));
                };
                file = File::from(openat(&file, name, flags, Mode::empty()).map_err(io_error)?);
                chain.push(file.metadata().map_err(io_error)?);
            }
            let metadata = file.metadata().map_err(io_error)?;
            // SAFETY: geteuid has no arguments or memory safety preconditions.
            if private && (metadata.uid() != unsafe { geteuid() } || metadata.mode() & 0o7777 != 0o700) {
                return Err(invalid("output parent must be a preexisting same-user private 0700 directory"));
            }
            Ok(Self { path: path.to_owned(), file, chain })
        }

        fn revalidate(&self, private: bool) -> Result<(), ApiError> {
            let current = Self::open(&self.path, private)?;
            if current.chain.len() != self.chain.len()
                || current.chain.iter().zip(&self.chain).any(|(a, b)| !same_file(a, b))
                || !same_file(&current.file.metadata().map_err(io_error)?, &self.file.metadata().map_err(io_error)?)
            {
                return Err(invalid("output directory namespace changed"));
            }
            Ok(())
        }
    }

    fn file_location(path: &Path) -> Result<(&Path, &OsStr), ApiError> {
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid("publication path must name a capture file"))?;
        if !path.is_absolute()
            || path.as_os_str().as_bytes().contains(&0)
            || path.components().any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            || path
                .as_os_str()
                .as_bytes()
                .split(|byte| *byte == b'/')
                .skip(1)
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || name == OsStr::new(".")
            || name == OsStr::new("..")
        {
            return Err(invalid("publication path must be absolute without dot, empty or NUL components"));
        }
        Ok((path.parent().ok_or_else(|| invalid("publication path has no parent directory"))?, name))
    }

    fn same_stamp(first: &Metadata, second: &Metadata) -> bool {
        same_file(first, second)
            && first.len() == second.len()
            && first.nlink() == second.nlink()
            && first.mtime() == second.mtime()
            && first.mtime_nsec() == second.mtime_nsec()
            && first.ctime() == second.ctime()
            && first.ctime_nsec() == second.ctime_nsec()
    }

    struct PublicationReader {
        directory: Directory,
        name: OsString,
        file: File,
        stamp: Metadata,
    }

    impl PublicationReader {
        fn open(path: &Path) -> Result<Self, ApiError> {
            let (parent, name) = file_location(path)?;
            let directory = Directory::open(parent, true)?;
            let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let file = File::from(openat(&directory.file, name, flags, Mode::empty()).map_err(io_error)?);
            let stamp = file.metadata().map_err(io_error)?;
            // SAFETY: geteuid has no arguments or memory safety preconditions.
            if !stamp.is_file() || stamp.uid() != unsafe { geteuid() } || stamp.mode() & 0o7777 != 0o600 {
                return Err(invalid("publication must be a same-user regular 0600 file, not a symlink or device"));
            }
            if stamp.len() == 0 || stamp.len() > DOCUMENT_BYTES as u64 {
                return Err(invalid("publication must contain 1..1048576 bounded document bytes"));
            }
            let reader = Self { directory, name: name.to_owned(), file, stamp };
            reader.verify()?;
            Ok(reader)
        }

        fn verify(&self) -> Result<(), ApiError> {
            self.directory.revalidate(true)?;
            if !same_stamp(&self.stamp, &self.file.metadata().map_err(io_error)?) {
                return Err(invalid("publication file changed while reading"));
            }
            let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let named = File::from(openat(&self.directory.file, &self.name, flags, Mode::empty()).map_err(io_error)?);
            if !same_stamp(&self.stamp, &named.metadata().map_err(io_error)?) {
                return Err(invalid("publication pathname changed while reading"));
            }
            self.directory.revalidate(true)
        }

        fn read_bytes(&mut self, limit: usize) -> Result<Vec<u8>, ApiError> {
            if self.stamp.len() > limit as u64 {
                return Err(invalid("private document exceeds the requested byte limit"));
            }
            self.verify()?;
            let mut bytes = Vec::with_capacity(self.stamp.len() as usize);
            (&mut self.file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
            self.verify()?;
            if bytes.len() != self.stamp.len() as usize || bytes.len() > limit {
                return Err(invalid("publication size changed or exceeds the bounded document limit"));
            }
            Ok(bytes)
        }

        fn read(mut self, expected_sha256: &str) -> Result<Vec<u8>, ApiError> {
            let bytes = self.read_bytes(DOCUMENT_BYTES)?;
            if digest(&bytes) != expected_sha256 {
                return Err(invalid("publication document SHA-256 does not match the explicitly expected bytes"));
            }
            self.verify()?;
            Ok(bytes)
        }
    }

    pub(super) fn read_publication(path: &Path, expected_sha256: &str) -> Result<Vec<u8>, ApiError> {
        PublicationReader::open(path)?.read(expected_sha256)
    }

    pub(super) fn read_private_document(path: &Path, limit: usize) -> Result<Vec<u8>, ApiError> {
        let mut reader = PublicationReader::open(path)?;
        let bytes = reader.read_bytes(limit)?;
        reader.verify()?;
        Ok(bytes)
    }

    #[cfg(test)]
    mod publication_reader_tests {
        use super::*;
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn held_descriptor_rejects_mutation_and_identical_byte_path_replacement() {
            for replace in [false, true] {
                let (_scratch, directory) = TestScratch::directory();
                let bytes = b"owned original publication bytes";
                let original = TemporaryFile::create(&directory, bytes).unwrap();
                let path = original.path();
                let reader = PublicationReader::open(&path).unwrap();
                if replace {
                    let replacement = TemporaryFile::create(&directory, bytes).unwrap();
                    std::fs::rename(replacement.path(), &path).unwrap();
                    let result = reader.read(&digest(bytes));
                    std::fs::remove_file(&path).unwrap();
                    assert!(result.is_err(), "identical bytes cannot replace the held file identity during a read");
                } else {
                    std::fs::write(&path, b"changed publication bytes").unwrap();
                    assert!(reader.read(&digest(bytes)).is_err());
                }
            }
        }

        #[test]
        fn held_reader_revalidates_private_parent_before_returning_bytes() {
            let (_scratch, directory) = TestScratch::directory();
            let bytes = b"owned original publication bytes";
            let original = TemporaryFile::create(&directory, bytes).unwrap();
            let path = original.path();
            let reader = PublicationReader::open(&path).unwrap();
            std::fs::set_permissions(&directory.path, Permissions::from_mode(0o755)).unwrap();
            let result = reader.read(&digest(bytes));
            std::fs::set_permissions(&directory.path, Permissions::from_mode(0o700)).unwrap();
            assert!(result.is_err());
        }
    }

    struct TemporaryFile<'a> {
        directory: &'a Directory,
        name: OsString,
        file: File,
        size: u64,
        sha256: String,
    }

    impl<'a> TemporaryFile<'a> {
        #[cfg(test)]
        fn create(directory: &'a Directory, document: &[u8]) -> Result<Self, ApiError> {
            Self::create_excluding(directory, document, None)
        }

        fn create_excluding(
            directory: &'a Directory,
            document: &[u8],
            excluded: Option<&OsStr>,
        ) -> Result<Self, ApiError> {
            Self::create_with_names(directory, document, excluded, || unique_name(".rampage-capture"))
        }

        fn create_with_names(
            directory: &'a Directory,
            document: &[u8],
            excluded: Option<&OsStr>,
            mut next_name: impl FnMut() -> OsString,
        ) -> Result<Self, ApiError> {
            if document.is_empty() || document.len() > DOCUMENT_BYTES {
                return Err(invalid("capture document exceeds local bounded-byte policy"));
            }
            for _ in 0..64 {
                let name = next_name();
                if excluded.is_some_and(|excluded| excluded.as_bytes().eq_ignore_ascii_case(name.as_bytes())) {
                    continue;
                }
                let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                let descriptor = match openat(&directory.file, &name, flags, Mode::RUSR | Mode::WUSR) {
                    Ok(file) => file,
                    Err(rustix::io::Errno::EXIST) => continue,
                    Err(error) => {
                        return Err(retain_staging(io_error(error), vec![directory.path.join(&name)]));
                    }
                };
                let mut temporary = Self {
                    directory,
                    name,
                    file: File::from(descriptor),
                    size: document.len() as u64,
                    sha256: digest(document),
                };
                let prepared = (|| {
                    let metadata = temporary.file.metadata().map_err(io_error)?;
                    if metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1 {
                        return Err(invalid("private capture staging file permissions are not 0600"));
                    }
                    temporary.file.write_all(document).map_err(io_error)?;
                    temporary.file.sync_all().map_err(io_error)?;
                    temporary.verify()
                })();
                if let Err(error) = prepared {
                    return Err(retain_staging(error, vec![temporary.path()]));
                }
                return Ok(temporary);
            }
            Err(invalid("cannot allocate a fresh private capture staging file"))
        }

        fn path(&self) -> PathBuf {
            self.directory.path.join(&self.name)
        }

        fn verify_name(&self) -> Result<(), ApiError> {
            let path = statat(&self.directory.file, &self.name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
            let file = self.file.metadata().map_err(io_error)?;
            if path.st_dev as u64 != file.dev()
                || path.st_ino as u64 != file.ino()
                || path.st_mode as u32 != file.mode()
                || path.st_uid != file.uid()
                || path.st_size as u64 != file.len()
            {
                return Err(invalid("capture staging file changed"));
            }
            Ok(())
        }

        fn verify(&self) -> Result<(), ApiError> {
            use std::os::unix::fs::FileExt;

            self.verify_name()?;
            if self.file.metadata().map_err(io_error)?.len() != self.size {
                return Err(invalid("capture staging length changed"));
            }
            let mut bytes = vec![0; self.size as usize];
            self.file.read_exact_at(&mut bytes, 0).map_err(io_error)?;
            if digest(&bytes) != self.sha256 {
                return Err(invalid("capture staging bytes changed"));
            }
            self.verify_name()
        }
    }

    fn unique_name(prefix: &str) -> OsString {
        format!("{prefix}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)).into()
    }

    pub(super) fn publish(
        output: &Path,
        document: &[u8],
        revalidate_source: impl FnOnce() -> Result<(), ApiError>,
    ) -> Result<PublicationOutcome, ApiError> {
        publish_with(output, document, revalidate_source, || Ok(()))
    }

    fn publish_with(
        output: &Path,
        document: &[u8],
        revalidate_source: impl FnOnce() -> Result<(), ApiError>,
        after_link: impl FnOnce() -> Result<(), ApiError>,
    ) -> Result<PublicationOutcome, ApiError> {
        publish_with_operations(output, document, revalidate_source, after_link, |directory, temporary, name| {
            linkat(directory, temporary, directory, name, AtFlags::empty())
        })
    }

    fn publish_with_operations(
        output: &Path,
        document: &[u8],
        revalidate_source: impl FnOnce() -> Result<(), ApiError>,
        after_link: impl FnOnce() -> Result<(), ApiError>,
        link: impl FnOnce(&File, &OsStr, &OsStr) -> Result<(), rustix::io::Errno>,
    ) -> Result<PublicationOutcome, ApiError> {
        let (parent, name) = file_location(output)?;
        let directory = Directory::open(parent, true)?;
        match statat(&directory.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(invalid("output already exists; capture publication never clobbers")),
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(io_error(error)),
        }
        let temporary = TemporaryFile::create_excluding(&directory, document, Some(name))?;
        let retained_staging_paths = vec![temporary.path()];
        let prepared = (|| {
            revalidate_source()?;
            directory.revalidate(true)?;
            temporary.verify()
        })();
        if let Err(error) = prepared {
            return Err(retain_staging(error, retained_staging_paths));
        }
        let mut outcome = PublicationOutcome {
            path: output.to_owned(),
            document_sha256: digest(document),
            status: DebuggerCapturePublicationStatus::Published,
            warnings: Vec::new(),
            retained_staging_paths,
        };
        // A hard link makes the complete, synced inode visible atomically and refuses every existing destination.
        match link(&directory.file, &temporary.name, name) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                return Err(retain_staging(
                    invalid("output already exists; never clobbered"),
                    outcome.retained_staging_paths,
                ));
            }
            Err(error) => {
                outcome.uncertain(io_error(error));
                return Ok(outcome);
            }
        }
        let checked = (|| {
            after_link()?;
            directory.revalidate(true)?;
            let published = statat(&directory.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
            let file = temporary.file.metadata().map_err(io_error)?;
            if published.st_dev as u64 != file.dev() || published.st_ino as u64 != file.ino() {
                return Err(invalid("published capture namespace changed; inspect output explicitly"));
            }
            temporary.verify()?;
            directory.file.sync_all().map_err(io_error)?;
            Ok(())
        })();
        if let Err(error) = checked {
            outcome.uncertain(error);
        }
        Ok(outcome)
    }

    #[cfg(test)]
    mod publication_lifecycle_tests {
        use super::*;
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn explicit_output_is_excluded_from_the_staging_namespace_before_any_write() {
            let (_scratch, directory) = TestScratch::directory();
            let output_name = OsString::from(format!(".rampage-capture-{}-0", std::process::id()));
            let output = directory.path.join(&output_name);
            let uppercase = OsString::from(output_name.to_str().unwrap().to_ascii_uppercase());
            let mut names = [output_name.clone(), uppercase, OsString::from("disjoint-staging")].into_iter();
            let temporary =
                TemporaryFile::create_with_names(&directory, b"complete document", Some(&output_name), || {
                    names.next().unwrap()
                })
                .unwrap();
            assert!(!output.exists(), "staging must never create the explicitly selected destination");
            assert_ne!(temporary.name, output_name);
            linkat(&directory.file, &temporary.name, &directory.file, &output_name, AtFlags::empty()).unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), b"complete document");
            drop(temporary);
            assert_eq!(std::fs::read(&output).unwrap(), b"complete document");
        }

        #[test]
        fn dropping_staging_handles_never_deletes_replacements_or_retained_names() {
            let (_scratch, root) = TestScratch::directory();
            let original = TemporaryFile::create(&root, b"original").unwrap();
            let path = original.path();
            std::fs::rename(&path, root.path.join("operator-owned-original")).unwrap();
            std::fs::write(&path, b"unknown replacement").unwrap();
            drop(original);
            assert_eq!(std::fs::read(&path).unwrap(), b"unknown replacement");
        }

        #[test]
        fn post_link_failure_reports_uncertain_publication_with_destination_hash_and_retention() {
            let (_scratch, directory) = TestScratch::directory();
            let output = directory.path.join("capture.json");
            let bytes = b"complete controlled document";
            let outcome = publish_with(
                &output,
                bytes,
                || Ok(()),
                || Err(ApiError::Unavailable("injected failure after committed link".into())),
            )
            .unwrap();
            assert_eq!(outcome.status, DebuggerCapturePublicationStatus::PublishedUncertain);
            assert_eq!(outcome.path, output);
            assert_eq!(outcome.document_sha256, digest(bytes));
            assert!(!outcome.warnings.is_empty());
            assert_eq!(std::fs::read(&output).unwrap(), bytes);
            assert_eq!(outcome.retained_staging_paths.len(), 1);
            assert_eq!(std::fs::read(&outcome.retained_staging_paths[0]).unwrap(), bytes);
        }

        #[test]
        fn changed_parent_after_link_keeps_published_state_and_never_removes_the_output() {
            let (_scratch, directory) = TestScratch::directory();
            let output = directory.path.join("capture.json");
            let outcome = publish_with(
                &output,
                b"complete",
                || Ok(()),
                || {
                    std::fs::set_permissions(&directory.path, Permissions::from_mode(0o755)).unwrap();
                    Ok(())
                },
            )
            .unwrap();
            std::fs::set_permissions(&directory.path, Permissions::from_mode(0o700)).unwrap();
            assert_eq!(outcome.status, DebuggerCapturePublicationStatus::PublishedUncertain);
            assert_eq!(outcome.path, output);
            assert_eq!(std::fs::read(&output).unwrap(), b"complete");
        }

        #[test]
        fn ambiguous_link_io_failure_reports_uncertain_not_unpublished() {
            let (_scratch, directory) = TestScratch::directory();
            let output = directory.path.join("capture.json");
            let outcome = publish_with_operations(
                &output,
                b"complete",
                || Ok(()),
                || Ok(()),
                |_, _, _| Err(rustix::io::Errno::IO),
            )
            .unwrap();
            assert_eq!(outcome.status, DebuggerCapturePublicationStatus::PublishedUncertain);
            assert_eq!(outcome.path, output);
            assert_eq!(outcome.document_sha256, digest(b"complete"));
            assert!(!outcome.warnings.is_empty());
            assert!(!output.exists());
            assert!(outcome.retained_staging_paths[0].exists());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::AtomicU64;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn document() -> Value {
        json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64", "big_endian": false, "data_big_endian": false,
            "provenance": "controlled semantic-validation fixture",
            "regions": [{"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "c3"}],
            "entry": null, "seeds": [],
            "modules": [{"name": "fixture", "path": "/provenance-only", "uuid": "fixture-id",
                "image_base": "0x0", "runtime_base": "0x1000"}],
            "registers": [
                {"thread_id": "0x1", "name": "rip", "value": "0x1000"},
                {"thread_id": "0x1", "name": "rsp", "value": "0x2000"},
                {"thread_id": "0x1", "name": "rflags", "value": "0x202"},
            ],
            "target": {"platform": "darwin"},
        })
    }

    #[test]
    fn completed_document_uses_semantic_snapshot_loading_not_only_deserialization() {
        let valid = document();
        let bytes = serde_json::to_vec(&valid).unwrap();
        let binary = validate_document(&bytes).unwrap();
        assert_eq!(binary.image_bytes(), &[0xc3]);
        assert_eq!(binary.file_bytes(), bytes.as_slice());
        assert!(binary.validate_backing_source().is_err(), "owned snapshots provide no mapped-source proof");
        assert!(binary.entry.is_none() && binary.function_starts.is_empty());
        for (pointer, value) in [
            ("/seeds", json!(["0x2000"])),
            ("/regions/0/bytes", json!("zz")),
            ("/regions/0/permissions", json!("r?x")),
            ("/regions/0/address", json!("0xffffffffffffffff")),
            ("/registers/1/name", json!("rip")),
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(serde_json::from_value::<Snapshot>(invalid.clone()).is_ok());
            let error = validate_document(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
            assert!(matches!(error, ApiError::Invalid(_)), "{pointer}: no filesystem staging or retained paths");
        }
    }

    #[test]
    fn pure_document_validation_enforces_the_capture_limit_before_owned_loader_cloning() {
        assert!(matches!(validate_document(b""), Err(ApiError::Invalid(_))));
        let oversized = vec![b' '; DOCUMENT_BYTES + 1];
        let error = validate_document(&oversized).unwrap_err();
        assert!(error.to_string().contains("bounded-byte policy"));
        assert!(matches!(error, ApiError::Invalid(_)));
    }

    #[test]
    fn source_refusal_after_staging_reports_retained_paths_without_publication_or_deletion() {
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "dc-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let output = directory.join("not-published.json");
        let result = local::publish(&output, b"controlled bounded bytes", || {
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
            Err(invalid("controlled source revalidation failure"))
        });
        let retention = match result.unwrap_err() {
            ApiError::DebuggerCaptureStagingRetained(retention) => retention,
            error => panic!("expected structured retained staging, got {error}"),
        };
        assert!(!output.exists());
        assert_eq!(retention.paths.len(), 1);
        assert_eq!(std::fs::read(&retention.paths[0]).unwrap(), b"controlled bounded bytes");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
