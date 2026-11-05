//! Static ↔ runtime correlation for debug sessions (phase 9.3): binding projects to a session's modules with a
//! verified slide, placing breakpoints by static address or function name, locating stops and register values in
//! the bound projects, stepping over calls and out of functions with temporary breakpoints, and evidence an agent
//! can record in the findings ledger. Nothing here writes to the target: temporary breakpoints are `Z1`/`Z0`
//! entries the stub inserts, never patched instructions.

use std::path::Path;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use rampage_arch::{Arch, Flow, Target};
use rampage_debug::{
    BreakKind, ByteOrder, Cancel, Family, Placement, RegisterValue, Session, State, StopEvent, TemporaryPlacement,
};
use rampage_loaders::{Details, Format};
use serde::Serialize;

use crate::debug_control::{
    DebugBreakKind, DebugBreakpoint, DebugRegistry, debug_failure, failure, family_arch, run_wait, session_number,
};
use crate::{ApiError, Project};

/// Most projects bound to one session.
pub const MAX_BINDINGS: usize = 8;
/// Bytes compared per verification window.
const VERIFY_BYTES: u64 = 32;
/// Bytes of a module's mapped headers compared with the file.
const HEADER_BYTES: u64 = 256;
/// Function entries compared to verify a slide, spread over the image.
const MAX_FUNCTION_WINDOWS: usize = 16;
/// The least bytes a target without a module list must match.
const MIN_IMAGE_BYTES: usize = 16;
/// Candidates listed for an ambiguous function name.
const MAX_CANDIDATES: usize = 16;
/// Over-steps reported one by one (the last ones); earlier ones are only counted.
const MAX_STEP_DETAILS: usize = 32;
/// No over-step starts this long after the request began.
const STEP_OVER_BUDGET: Duration = Duration::from_secs(60);
/// Registers and memory ranges one evidence object holds, and bytes per range.
const MAX_EVIDENCE_REGISTERS: usize = 8;
const MAX_EVIDENCE_RANGES: usize = 4;
const MAX_EVIDENCE_BYTES: usize = 64;
/// Bytes of a ledger evidence item's detail.
const MAX_LEDGER_DETAIL: usize = 300;

/// The rule `debug_step` with `out` follows, as results and documentation state it.
pub const STEP_OUT_RULE: &str = "step out only at a function's first instruction in a bound project, where the \
    return address is still where the ABI puts it on entry: ARM/Thumb lr (not an M-profile EXC_RETURN value), \
    AArch64 x30, RISC-V ra, x86-64 [rsp] and x86 [esp]; anywhere else the return address may have been moved or \
    overwritten, so it is refused";

/// A project bound to one runtime module of a session, with the slide that maps its static addresses to runtime
/// ones: `runtime = static + slide`, wrapping at the pointer width.
pub struct Binding {
    pub(crate) module: String,
    pub(crate) path: String,
    pub(crate) project: Arc<Project>,
    pub(crate) slide: u64,
    pub(crate) evidence: BindEvidence,
    pub(crate) verification: SlideCheck,
    pub(crate) explicit_slide: bool,
    pub(crate) limitations: Vec<String>,
    mask: u64,
}

impl Binding {
    /// The static address of `runtime` when it falls in one of the project's mapped segments.
    pub(crate) fn to_static(&self, runtime: u64) -> Option<u64> {
        // A value wider than the target's addresses (a 64-bit register on a 32-bit target) is not an address.
        if runtime > self.mask {
            return None;
        }
        let address = runtime.wrapping_sub(self.slide) & self.mask;
        self.project
            .binary
            .segments
            .iter()
            .any(|segment| mapped(segment) && segment.contains(address))
            .then_some(address)
    }

    pub(crate) fn to_runtime(&self, address: u64) -> u64 {
        address.wrapping_add(self.slide) & self.mask
    }

    fn view(&self) -> BindingView {
        BindingView {
            module: self.module.clone(),
            path: self.path.clone(),
            arch: self.project.binary.arch.to_string(),
            format: format!("{:?}", self.project.binary.format).to_lowercase(),
            slide: self.slide,
            explicit_slide: self.explicit_slide,
            evidence: self.evidence.clone(),
            verification: self.verification.clone(),
            limitations: self.limitations.clone(),
        }
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Binding").field("module", &self.module).field("path", &self.path).finish()
    }
}

/// Whether a segment is mapped memory a pointer can reach: not Mach-O's `__PAGEZERO` guard or an empty one.
fn mapped(segment: &rampage_loaders::Segment) -> bool {
    segment.size > 0 && (segment.perms.read || segment.perms.write || segment.perms.execute)
}

/// What matched a project to a runtime module.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindEvidence {
    /// The module's GNU build ID (read from target memory) equals the ELF file's.
    BuildId { build_id: String },
    /// The module's Mach-O `LC_UUID` (read from target memory) equals the file's.
    Uuid { uuid: String },
    /// The module's reported path equals the project's path.
    Path { name: String },
    /// Only the file names are equal.
    Basename { name: String },
    /// The module's mapped header bytes equal the file's first bytes.
    HeaderBytes {
        #[serde(serialize_with = "rampage_arch::hex::address")]
        address: u64,
        length: usize,
    },
    /// The stub lists no modules; the image's code is mapped at the slide, byte for byte, at every window
    /// compared.
    MappedBytes { compared: usize, windows: usize },
    /// No module matched; the caller gave the slide.
    ExplicitSlide,
    /// The PE file's CodeView record (PDB GUID and age) equals the one in the module's mapped debug directory.
    Codeview { guid: String, age: u32 },
}

impl BindEvidence {
    /// Whether the evidence identifies the image itself rather than only a name.
    fn identifies(&self) -> bool {
        !matches!(self, BindEvidence::Path { .. } | BindEvidence::Basename { .. } | BindEvidence::ExplicitSlide)
    }
}

/// The comparison of a window of the file with the target memory at the slide.
#[derive(Debug, Clone, Serialize)]
pub struct SlideCheck {
    /// `matched`, `mismatched`, `unreadable` (the target memory could not be read) or `no_file_bytes`.
    pub outcome: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub static_address: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub runtime_address: Option<u64>,
    pub length: usize,
    /// What was compared (the entry point, a code section) and, on a mismatch, the first differing offset.
    pub detail: String,
}

/// A binding as results show it.
#[derive(Debug, Clone, Serialize)]
pub struct BindingView {
    pub module: String,
    pub path: String,
    pub arch: String,
    pub format: String,
    /// `runtime = static + slide`, wrapping at the pointer width.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub slide: u64,
    pub explicit_slide: bool,
    pub evidence: BindEvidence,
    pub verification: SlideCheck,
    pub limitations: Vec<String>,
}

/// The outcome of `debug_bind`.
#[derive(Debug, Serialize)]
pub struct DebugBinding {
    pub session: String,
    pub binding: BindingView,
    /// Whether it replaced an earlier binding of the same module.
    pub replaced: bool,
    pub bindings: usize,
}

/// The arguments `show_address` takes to show a location to the user.
#[derive(Debug, Clone, Serialize)]
pub struct ShowAddress {
    pub path: String,
    pub at: String,
}

/// A runtime address inside a bound module, as the project sees it.
#[derive(Debug, Clone, Serialize)]
pub struct DebugLocation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub static_address: u64,
    pub module: String,
    pub path: String,
    /// The function containing it, as project tools name it; null outside every function the analysis found.
    pub function: Option<String>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub function_address: Option<u64>,
    pub offset_in_function: Option<u64>,
    /// Why `function` is null when it is not for lack of a function there (the analysis failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_note: Option<String>,
    pub show_address: ShowAddress,
}

/// A runtime address and its location, or null with the reason there is none.
#[derive(Debug, Clone, Serialize)]
pub struct Located {
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub runtime_address: Option<u64>,
    pub location: Option<DebugLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreakpointLocated {
    pub id: u32,
    #[serde(flatten)]
    pub located: Located,
}

/// Where a stop is in the bound projects.
#[derive(Debug, Clone, Serialize)]
pub struct StopLocations {
    pub pc: Located,
    pub breakpoints: Vec<BreakpointLocated>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watch: Option<Located>,
    /// How the pc was decoded when the session's byte order is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc_evidence: Option<String>,
}

/// A register as `debug_registers` reports it, with what its value points at when asked (`annotate`).
#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedRegister {
    #[serde(flatten)]
    pub register: RegisterValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub points_to: Option<Pointee>,
}

impl std::ops::Deref for AnnotatedRegister {
    type Target = RegisterValue;

    fn deref(&self) -> &RegisterValue {
        &self.register
    }
}

/// What a register value points at in a bound project.
#[derive(Debug, Clone, Serialize)]
pub struct Pointee {
    #[serde(flatten)]
    pub location: DebugLocation,
    /// `code` (inside a function), `symbol` (a named address), `string` or `data`.
    pub kind: &'static str,
    /// The name at exactly this address, if any.
    pub symbol: Option<String>,
    /// The NUL-terminated ASCII string there, at most 80 characters, from the file.
    pub string: Option<String>,
    /// The register's value with its pointer authentication code, when the location is that of the value without
    /// it (arm64; see the session's `address_mask`).
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub signed_value: Option<u64>,
}

/// One step of an over-step request.
#[derive(Debug, Clone, Serialize)]
pub struct OverStep {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub pc: u64,
    pub length: u8,
    /// The decoded control flow: `call`, `indirect_call`, `next`, `jump`...
    pub flow: String,
    /// `target_memory`, or `file` when target memory was unreadable or did not decode (a stub's own breakpoint
    /// instruction, say).
    pub bytes_source: &'static str,
    /// `stepped` (one instruction), `returned` (ran to the temporary breakpoint after the call),
    /// `stopped_elsewhere` (another stop came first), `inner_frame` or `other_thread` (the return address was reached
    /// by a recursive frame or another thread; the target stays stopped there), `running` (no stop in time) or
    /// `cancelled`.
    pub outcome: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub return_address: Option<u64>,
    /// The temporary breakpoint's ID, or the table breakpoint that stood in for it.
    pub temporary_breakpoint: Option<u32>,
    pub user_breakpoint: Option<u32>,
}

/// The outcome of `debug_step` with `over` or `out`.
#[derive(Debug, Serialize)]
pub struct DebugStepped {
    pub session: String,
    /// `over` or `out`.
    pub mode: &'static str,
    #[serde(flatten)]
    pub state: State,
    pub epoch: u64,
    pub requested: u32,
    /// Over: instructions stepped (a call and its return count as one). Out: 1 when the function returned.
    pub completed: u32,
    /// The last steps, at most 32.
    pub steps: Vec<OverStep>,
    pub steps_omitted: usize,
    /// The last stop observed.
    pub event: Option<StopEvent>,
    pub locations: Option<StopLocations>,
    pub cancelled: bool,
    pub truncated: Option<String>,
    pub running_for_ms: Option<u64>,
    pub warnings: Vec<String>,
    /// Step out: the rule it follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<&'static str>,
}

/// A memory range for [`DebugRegistry::evidence`].
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRange {
    /// Runtime address (hex string or integer).
    pub address: crate::FileOffset,
    /// Bytes, 1..=64.
    pub length: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRegister {
    pub name: String,
    /// The value in the session's byte order, else the bytes as the stub sent them.
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceMemory {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The bytes read, as hex; short when the target could not read them all.
    pub hex: String,
    pub complete: bool,
}

/// A bounded, typed record of a stopped target for the findings ledger.
#[derive(Debug, Serialize)]
pub struct DebugEvidence {
    pub session: String,
    pub endpoint: String,
    pub epoch: u64,
    pub thread: Option<rampage_debug::ThreadId>,
    pub pc: Located,
    pub registers: Vec<EvidenceRegister>,
    pub memory: Vec<EvidenceMemory>,
    /// Pass this as an `evidence` item of `record_finding`: a compact text form of the above, at most 300 bytes.
    pub ledger_evidence: crate::LedgerEvidence,
    pub limitations: Vec<String>,
}

/// Where `debug_breakpoints` places a breakpoint.
#[derive(Debug, Clone)]
pub enum BreakTarget {
    Runtime(u64),
    Static { address: u64, path: Option<String> },
    Function { name: String, path: Option<String> },
}

/// What the static side resolved for a breakpoint.
struct Resolved {
    binding: Arc<Binding>,
    address: u64,
    function: Option<(String, u64)>,
}

/// A register value's possible integers: the decoded value, or both byte orders of its bytes when the order is
/// unknown.
fn candidates(register: &RegisterValue) -> Vec<u64> {
    if let Some(value) = register.integer() {
        return vec![value];
    }
    match register.bytes.as_deref() {
        Some(bytes) if register.bitsize <= 64 => both_orders(bytes),
        _ => Vec::new(),
    }
}

/// The value of hex `bytes` read little- and big-endian (one value when they agree).
fn both_orders(bytes: &str) -> Vec<u64> {
    let Some(raw) = rampage_debug::packet::decode_hex(bytes.as_bytes()).filter(|raw| !raw.is_empty() && raw.len() <= 8)
    else {
        return Vec::new();
    };
    let little = raw.iter().rev().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
    let big = raw.iter().fold(0u64, |value, byte| value << 8 | u64::from(*byte));
    let mut values = vec![little, big];
    values.dedup();
    values
}

/// The binding whose mapped segments hold `runtime`, with the static address.
fn locate(bindings: &[Arc<Binding>], runtime: u64) -> Option<(Arc<Binding>, u64)> {
    bindings.iter().find_map(|binding| binding.to_static(runtime).map(|address| (Arc::clone(binding), address)))
}

/// One of `values` when it is the only one, or the only one inside a bound module (with the evidence for picking
/// it).
fn pick(values: &[u64], bindings: &[Arc<Binding>]) -> Option<(u64, Option<String>)> {
    match values {
        [] => None,
        [value] => Some((*value, None)),
        _ => {
            let inside: Vec<u64> = values.iter().copied().filter(|value| locate(bindings, *value).is_some()).collect();
            match inside[..] {
                [value] => Some((
                    value,
                    Some(format!(
                        "the byte order is unknown; of the decodings {}, only {value:#x} lies in a bound module",
                        values.iter().map(|value| format!("{value:#x}")).collect::<Vec<_>>().join(" and ")
                    )),
                )),
                _ => None,
            }
        }
    }
}

/// The start of the function containing `address`, from the project's analysis only when it is already done
/// (`debug_bind` runs it), so execution tools never wait for a whole-program analysis; else why there is none.
fn function_start(project: &Project, address: u64) -> (Option<u64>, Option<String>) {
    match project.cached_analysis_checked() {
        Ok(Some(_)) => {}
        Ok(None) => return (None, Some("the project's analysis is not done; functions are not named".into())),
        Err(error) => return (None, Some(format!("the project's analysis failed: {error}"))),
    }
    match project.function_containing(address) {
        Ok(start) => (start, None),
        Err(error) => (None, Some(format!("the project's analysis failed: {error}"))),
    }
}

fn describe(binding: &Binding, runtime: u64, address: u64) -> DebugLocation {
    let project = &binding.project;
    let (start, function_note) = function_start(project, address);
    DebugLocation {
        runtime_address: runtime,
        static_address: address,
        module: binding.module.clone(),
        path: binding.path.clone(),
        function: start.map(|start| project.function_name(start)),
        function_address: start,
        // A function's cold part can lie below its start: no offset then.
        offset_in_function: start.and_then(|start| address.checked_sub(start)),
        function_note,
        show_address: ShowAddress { path: binding.path.clone(), at: format!("{address:#x}") },
    }
}

fn located(bindings: &[Arc<Binding>], runtime: Option<u64>, unknown: &str) -> Located {
    let Some(runtime) = runtime else {
        return Located { runtime_address: None, location: None, reason: Some(unknown.to_owned()) };
    };
    if bindings.is_empty() {
        return Located {
            runtime_address: Some(runtime),
            location: None,
            reason: Some("no project is bound to this session; debug_bind one".into()),
        };
    }
    match locate(bindings, runtime) {
        Some((binding, address)) => Located {
            runtime_address: Some(runtime),
            location: Some(describe(&binding, runtime, address)),
            reason: None,
        },
        None => Located {
            runtime_address: Some(runtime),
            location: None,
            reason: Some(format!("{runtime:#x} is outside every bound module's mapped segments")),
        },
    }
}

/// The bytes of `length` at `address` when the target reads all of them.
fn read_exact(session: &Session, address: u64, length: u64, epoch: Option<u64>) -> Result<Option<Vec<u8>>, ApiError> {
    if length == 0 || address.checked_add(length - 1).is_none() {
        return Ok(None);
    }
    let read =
        session.read_memory_at(address, length as usize, None, epoch, &Cancel::default()).map_err(debug_failure)?;
    if !read.complete() {
        return Ok(None);
    }
    Ok(Some(read.chunks.into_iter().flat_map(|chunk| chunk.bytes).collect()))
}

/// The readable prefix of `length` bytes at `address`.
fn read_prefix(session: &Session, address: u64, length: u64, epoch: Option<u64>) -> Result<Vec<u8>, ApiError> {
    if length == 0 || address.checked_add(length - 1).is_none() {
        return Ok(Vec::new());
    }
    let read =
        session.read_memory_at(address, length as usize, None, epoch, &Cancel::default()).map_err(debug_failure)?;
    let mut bytes = Vec::new();
    for chunk in read.chunks {
        bytes.extend_from_slice(&chunk.bytes);
        if chunk.error.is_some() || chunk.read < chunk.requested {
            break;
        }
    }
    Ok(bytes)
}

/// The address of the image's file header in its own address space: the segment mapping file offset 0.
fn header_address(binary: &rampage_loaders::Binary) -> Option<u64> {
    binary
        .segments
        .iter()
        .filter(|segment| segment.file_offset == 0 && segment.file_size > 0)
        .map(|segment| segment.address)
        .min()
}

/// The image's own identity: an ELF build ID or a Mach-O UUID, as lowercase hex.
fn image_identity(binary: &rampage_loaders::Binary) -> Option<(bool, String)> {
    match &binary.details {
        Details::Elf(details) => details.build_id.clone().map(|id| (false, id.to_ascii_lowercase())),
        Details::MachO(details) => {
            details.uuid.as_deref().map(|uuid| (true, uuid.replace('-', "").to_ascii_lowercase()))
        }
        _ => None,
    }
}

/// The GNU build ID of the ELF image whose header is at `header` and whose load bias is `bias`, from target
/// memory.
fn runtime_build_id(session: &Session, header: u64, bias: u64, epoch: Option<u64>) -> Result<Option<String>, ApiError> {
    use rampage_debug::maps;
    let Some(bytes) = read_exact(session, header, 64, epoch)? else { return Ok(None) };
    let Some(elf) = maps::elf_header(&bytes) else { return Ok(None) };
    let size = elf.phentsize.saturating_mul(elf.phnum);
    if size == 0 || size > 4096 {
        return Ok(None);
    }
    let Some(headers) = read_exact(session, header.wrapping_add(elf.phoff), size, epoch)? else { return Ok(None) };
    for (address, length) in maps::note_segments(&elf, &headers).into_iter().take(4) {
        if length == 0 || length > 4096 {
            continue;
        }
        if let Some(notes) = read_exact(session, bias.wrapping_add(address), length, epoch)?
            && let Some(id) = maps::build_id(&notes, elf.little)
        {
            return Ok(Some(id.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

/// The `LC_UUID` of the Mach-O image whose header is at `header`, from target memory.
fn runtime_uuid(session: &Session, header: u64, epoch: Option<u64>) -> Result<Option<String>, ApiError> {
    let Some(bytes) = read_exact(session, header, 32, epoch)? else { return Ok(None) };
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    let size = match word(0) {
        0xfeed_facf => 32u64,
        0xfeed_face => 28,
        _ => return Ok(None),
    };
    let (count, commands) = (word(16) as usize, u64::from(word(20)));
    if commands == 0 || commands > 16 * 1024 {
        return Ok(None);
    }
    let Some(commands) = read_exact(session, header.wrapping_add(size), commands, epoch)? else { return Ok(None) };
    let mut at = 0usize;
    for _ in 0..count.min(512) {
        let Some(command) = commands.get(at..at + 8) else { break };
        let kind = u32::from_le_bytes(command[..4].try_into().expect("four bytes"));
        let length = u32::from_le_bytes(command[4..].try_into().expect("four bytes")) as usize;
        if kind == 0x1b
            && let Some(uuid) = commands.get(at + 8..at + 24)
        {
            return Ok(Some(rampage_arch::hex::bytes(uuid)));
        }
        if length < 8 {
            break;
        }
        at += length;
    }
    Ok(None)
}

/// A PE file's facts for binding (step 9.6a): its headers (the preferred base, the first section), its CodeView
/// record, and the static spans its base relocations patch when the loader moves it.
struct PeFile {
    header: rampage_debug::pe::PeHeader,
    codeview: Option<rampage_debug::CodeView>,
    /// `(static address, length)`, sorted.
    relocated: Vec<(u64, u64)>,
    relocation_error: Option<String>,
}

fn pe_file(binary: &rampage_loaders::Binary) -> Option<PeFile> {
    use rampage_debug::pe;
    if binary.format != Format::Pe {
        return None;
    }
    let bytes = binary.image_bytes();
    let header = pe::PeHeader::parse(bytes)?;
    // The loader's record when it has one; the same RSDS bytes either way.
    let codeview = match &binary.details {
        Details::Pe(details) => details.codeview.as_ref().map(|codeview| rampage_debug::CodeView {
            guid: codeview.guid,
            age: codeview.age,
            path: codeview.path.clone(),
        }),
        _ => None,
    }
    .or_else(|| pe::file_codeview(bytes, &header));
    let (relocated, relocation_error) = match pe::relocations(bytes, &header) {
        Ok(spans) => (
            spans
                .into_iter()
                .map(|(rva, length)| (header.image_base.wrapping_add(u64::from(rva)), u64::from(length)))
                .collect(),
            None,
        ),
        Err(error) => (Vec::new(), Some(error)),
    };
    Some(PeFile { header, codeview, relocated, relocation_error })
}

/// The CodeView record of the PE image whose `MZ` header is at `base`, from target memory.
fn runtime_codeview(
    session: &Session,
    base: u64,
    epoch: Option<u64>,
) -> Result<Option<rampage_debug::CodeView>, ApiError> {
    use rampage_debug::pe;
    let Some(bytes) = read_exact(session, base, pe::HEADER_READ as u64, epoch)? else { return Ok(None) };
    let Some(header) = pe::PeHeader::parse(&bytes) else { return Ok(None) };
    let Some((rva, length)) = header.directory(pe::DIRECTORY_DEBUG) else { return Ok(None) };
    let at = base.wrapping_add(u64::from(rva));
    let Some(directory) = read_exact(session, at, u64::from(length.min(28 * 16)), epoch)? else { return Ok(None) };
    let Some((rva, _, length)) = pe::codeview_entry(&directory) else { return Ok(None) };
    let at = base.wrapping_add(u64::from(rva));
    Ok(read_exact(session, at, u64::from(length.min(1048)), epoch)?.and_then(|record| pe::parse_rsds(&record)))
}

/// Whether the PE headers mapped at `base` equal the file's first bytes (up to [`HEADER_BYTES`]), leaving out
/// `OptionalHeader.ImageBase`, which the loader rewrites with the runtime base when it moves the image.
fn pe_header_matches(session: &Session, file: &PeFile, bytes: &[u8], base: u64) -> Result<Option<usize>, ApiError> {
    let length = bytes.len().min(HEADER_BYTES as usize).min(file.header.size_of_headers as usize);
    if length < 64 {
        return Ok(None);
    }
    let Some(memory) = read_exact(session, base, length as u64, None)? else { return Ok(None) };
    let (field, width) = file.header.image_base_field;
    let equal = memory
        .iter()
        .zip(&bytes[..length])
        .enumerate()
        .all(|(at, (a, b))| (at >= field && at < field + width) || a == b);
    Ok(equal.then_some(length))
}

/// Windows paths compared as Windows compares them: case-insensitively, `/` as `\`, without `\\?\`.
fn same_windows_path(a: &str, b: &str) -> bool {
    rampage_debug::pe::normalize_path(a) == rampage_debug::pe::normalize_path(b)
}

/// The windows of the file a slide is checked with: the entry point, the start, middle and end of every executable
/// segment's file bytes (at most 8 segments), and function entries spread over the image (at most 16), each up to
/// 32 bytes. Comparing many places catches a rebuilt image that shares its first bytes (a vector table, a header)
/// with the one running.
fn verification_windows(binary: &rampage_loaders::Binary) -> Vec<(u64, &[u8], &'static str)> {
    let thumb_mask = if binary.arch == Arch::Arm { !1 } else { !0 };
    let code: Vec<&rampage_loaders::Segment> =
        binary.segments.iter().filter(|segment| segment.perms.execute && segment.file_size > 0).take(8).collect();
    let in_code = |address: u64| {
        code.iter().any(|segment| address >= segment.address && address - segment.address < segment.file_size)
    };
    let mut places: Vec<(u64, &'static str)> = Vec::new();
    if let Some(entry) = binary.entry {
        places.push((entry & thumb_mask, "the entry point"));
    }
    for segment in &code {
        let last = segment.file_size.saturating_sub(VERIFY_BYTES);
        places.push((segment.address, "the start of a code segment"));
        places.push((segment.address + last / 2, "the middle of a code segment"));
        places.push((segment.address + last, "the end of a code segment"));
    }
    let mut functions: Vec<u64> = binary
        .function_starts
        .iter()
        .copied()
        .chain(
            binary
                .symbols
                .iter()
                .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
                .map(|symbol| symbol.address),
        )
        .map(|address| address & thumb_mask)
        .filter(|address| in_code(*address))
        .collect();
    functions.sort_unstable();
    functions.dedup();
    let stride = functions.len().div_ceil(MAX_FUNCTION_WINDOWS).max(1);
    places.extend(functions.iter().step_by(stride).map(|address| (*address, "a function entry")));
    places.sort_unstable();
    places.dedup_by_key(|(address, _)| *address);
    places
        .into_iter()
        .filter_map(|(address, what)| {
            let available = binary.read_to_segment_end(address)?;
            let length = available.len().min(VERIFY_BYTES as usize);
            (length > 0).then(|| (address, &available[..length], what))
        })
        .collect()
}

/// Whether `length` bytes at `address` lie in readable memory by the stub's region list: `None` when the regions
/// state no permissions (only LLDB's `qMemoryRegionInfo` does), or when the list stopped short (`partial`) and the
/// range is in no listed readable region, so only a read can tell.
fn region_readable(regions: &[rampage_debug::Region], partial: bool, address: u64, length: u64) -> Option<bool> {
    if !regions.iter().any(|region| region.permissions.is_some()) {
        return None;
    }
    let last = address.checked_add(length.max(1) - 1)?;
    let readable = regions.iter().any(|region| {
        region.permissions.as_deref().is_some_and(|permissions| permissions.contains('r'))
            && address >= region.start
            && last - region.start < region.length
    });
    (readable || !partial).then_some(readable)
}

/// Compares every [verification window](verification_windows) with target memory at `slide`: matched when at
/// least one window could be read and none differs, mismatched when any differs. A window the stub's region list
/// shows unreadable is counted unreadable without asking the target for it. Bytes in `relocated` (static spans a
/// PE image's base relocations patch) are left out when the image moved (`slide` not 0), since the loader rewrote
/// them; a window left with nothing to compare counts as skipped.
fn verify_slide(
    session: &Session,
    binary: &rampage_loaders::Binary,
    slide: u64,
    mask: u64,
    modules: &rampage_debug::Modules,
    relocated: &[(u64, u64)],
) -> Result<SlideCheck, ApiError> {
    let epoch = None;
    let windows = verification_windows(binary);
    if windows.is_empty() {
        return Ok(SlideCheck {
            outcome: "no_file_bytes",
            static_address: None,
            runtime_address: None,
            length: 0,
            detail: "the image has no file-backed code to compare".into(),
        });
    }
    let (mut matched, mut compared, mut unreadable, mut skipped) = (0usize, 0usize, 0usize, 0usize);
    let mut relocated_bytes = 0usize;
    let moved = slide & mask != 0;
    let patched = |at: u64| {
        moved && {
            let index = relocated.partition_point(|(start, _)| *start <= at);
            index > 0 && at - relocated[index - 1].0 < relocated[index - 1].1
        }
    };
    let mut first = None;
    for (address, file, what) in &windows {
        let runtime = address.wrapping_add(slide) & mask;
        let memory = match region_readable(&modules.regions, modules.regions_partial, runtime, file.len() as u64) {
            Some(false) => None,
            _ => read_exact(session, runtime, file.len() as u64, epoch)?,
        };
        let kept: Vec<bool> = (0..file.len() as u64).map(|offset| !patched(address.wrapping_add(offset))).collect();
        let left_out = kept.iter().filter(|kept| !**kept).count();
        match memory {
            Some(_) if left_out == file.len() => skipped += 1,
            Some(memory) => {
                match memory.iter().zip(file.iter()).zip(&kept).position(|((a, b), kept)| *kept && a != b) {
                    None => {
                        matched += 1;
                        compared += file.len() - left_out;
                        relocated_bytes += left_out;
                        first.get_or_insert((*address, runtime));
                    }
                    Some(offset) => {
                        return Ok(SlideCheck {
                            outcome: "mismatched",
                            static_address: Some(*address),
                            runtime_address: Some(runtime),
                            length: file.len(),
                            detail: format!(
                                "{what} at {address:#x} differs from the file at byte {offset} (of {} windows, {matched} \
                             compared before it matched)",
                                windows.len()
                            ),
                        });
                    }
                }
            }
            None => unreadable += 1,
        }
    }
    Ok(match first {
        Some((address, runtime)) => SlideCheck {
            outcome: "matched",
            static_address: Some(address),
            runtime_address: Some(runtime),
            length: compared,
            detail: format!(
                "{matched} windows ({compared} bytes) at the entry point, code segments and function entries equal \
                 the file{}{}{}",
                if unreadable > 0 { format!("; {unreadable} could not be read") } else { String::new() },
                if relocated_bytes > 0 {
                    format!("; {relocated_bytes} bytes the image's base relocations patch were left out")
                } else {
                    String::new()
                },
                if skipped > 0 { format!("; {skipped} held only relocated bytes") } else { String::new() }
            ),
        },
        None => SlideCheck {
            outcome: "unreadable",
            static_address: Some(windows[0].0),
            runtime_address: Some(windows[0].0.wrapping_add(slide) & mask),
            length: windows[0].1.len(),
            detail: format!("the target could not read any of the {} windows at the slide", windows.len()),
        },
    })
}

/// Whether the image is mapped at `slide` on a target that lists no modules (bare-metal firmware): every
/// [verification window](verification_windows) must be readable and equal, at least 16 bytes in all. Returns the
/// bytes and windows compared.
fn mapped_image_matches(
    session: &Session,
    binary: &rampage_loaders::Binary,
    slide: u64,
    mask: u64,
    epoch: Option<u64>,
) -> Result<Option<(usize, usize)>, ApiError> {
    let windows = verification_windows(binary);
    let mut compared = 0usize;
    for (address, file, _) in &windows {
        let Some(memory) = read_exact(session, address.wrapping_add(slide) & mask, file.len() as u64, epoch)? else {
            return Ok(None);
        };
        if memory != *file {
            return Ok(None);
        }
        compared += file.len();
    }
    Ok((compared >= MIN_IMAGE_BYTES).then_some((compared, windows.len())))
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// arm64 registers that hold return addresses, the pc or frame pointers, which pointer authentication may sign.
const CODE_POINTER_REGISTERS: &[&str] = &["lr", "x30", "pc", "fp", "x29"];

/// Whether `entry` has the path or file name `wanted`.
fn named_as(entry: &rampage_debug::Module, wanted: &str) -> bool {
    entry.name == wanted || basename(&entry.name) == wanted
}

/// Why a module in the dyld shared cache does not bind without its extracted image.
fn shared_cache_refusal(name: &str) -> ApiError {
    failure(
        "shared_cache_image",
        format!(
            "`{name}` lives in the dyld shared cache, not in a file at its path, so nothing on disk is known to be \
             the code that runs; extract it from the cache (for example `dyld_shared_cache_util -extract` or `ipsw \
             dyld extract`) and bind the extracted image, which binds when its UUID matches; nothing was bound"
        ),
    )
}

/// A function's address by name in `project`: the user's name first, then symbols. Several symbols of that name
/// at different addresses refuse, listing them.
fn resolve_function(project: &Project, name: &str) -> Result<u64, ApiError> {
    let address = resolve_name(project, name)?;
    let binary = &project.binary;
    let function = binary.function_starts.binary_search(&address).is_ok()
        || binary
            .symbols
            .iter()
            .any(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function && symbol.address & !1 == address & !1);
    if !function && !binary.is_code(address) {
        return Err(failure(
            "not_code",
            format!(
                "`{name}` is at {address:#x}, which is neither code nor a known function start (a data symbol or an \
                 import slot?); give a function"
            ),
        ));
    }
    Ok(address)
}

/// The address a name refers to: the user's name first, then the loader's names; several of those refuse.
fn resolve_name(project: &Project, name: &str) -> Result<u64, ApiError> {
    if let Some(address) = project.annotations().address_of(name) {
        return Ok(address);
    }
    let mut addresses: Vec<u64> =
        project.inventory_loader_names().filter(|(_, known)| *known == name).map(|(address, _)| address).collect();
    addresses.sort_unstable();
    addresses.dedup();
    match addresses[..] {
        [address] => Ok(address),
        [] => project
            .symbol_address(name)
            .or_else(|| crate::project::default_name_address(name))
            .ok_or_else(|| ApiError::NotFound(format!("no function or symbol named `{name}`"))),
        _ => Err(failure(
            "ambiguous_name",
            format!(
                "`{name}` names {} addresses; place the breakpoint by static_address instead: {}{}",
                addresses.len(),
                addresses
                    .iter()
                    .take(MAX_CANDIDATES)
                    .map(|address| format!("{name}@{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if addresses.len() > MAX_CANDIDATES { ", ..." } else { "" }
            ),
        )),
    }
}

impl DebugRegistry {
    /// The projects bound to session `id`.
    pub(crate) fn bindings_of(&self, id: &str) -> Vec<Arc<Binding>> {
        let Some(number) = session_number(id) else { return Vec::new() };
        let bindings =
            self.bindings.lock().unwrap_or_else(PoisonError::into_inner).get(&number).cloned().unwrap_or_default();
        // Names other clients (the UI, the CLI) saved since, as project tools see them. A log that cannot be read
        // leaves the names as they were.
        for binding in &bindings {
            let _ = binding.project.refresh_annotations();
        }
        bindings
    }

    pub(crate) fn binding_views(&self, id: &str) -> Vec<BindingView> {
        self.bindings_of(id).iter().map(|binding| binding.view()).collect()
    }

    /// Binds the project at `path` to one of session `id`'s runtime modules, opening it in `projects`.
    ///
    /// Modules are matched by build ID or UUID (read from target memory), then by path or file name, then by their
    /// mapped header bytes; a target that lists no modules matches when the image's executable segments are mapped
    /// byte for byte at the slide (`qOffsets`, else 0). `module` restricts the match to a module of that name or
    /// file name. Without a match, an explicit `slide` binds anyway. The slide is verified by comparing a window of
    /// the file with target memory: a mismatch refuses unless the slide was explicit.
    pub fn bind(
        &self,
        id: &str,
        projects: &crate::Session,
        path: &Path,
        module: Option<&str>,
        slide: Option<u64>,
    ) -> Result<DebugBinding, ApiError> {
        let session = self.session(id)?;
        let number = session_number(id).expect("a known session id");
        let info = session.info();
        let arch = family_arch(info.family);
        // The target's architecture picks the slice of a universal binary; a file without it is a mismatch.
        let project = match projects.open(path, arch) {
            Ok(project) => project,
            Err(error) => match arch.map(|_| projects.open(path, None)) {
                Some(Ok(project)) => project,
                // A system library's path names an image in the dyld shared cache, with no file there.
                _ if !path.exists() && info.apple() => {
                    let display = path.display().to_string();
                    let cached = session.modules().ok().is_some_and(|modules| {
                        modules.modules.iter().any(|entry| {
                            entry.name == display && entry.dyld.as_ref().is_some_and(|image| image.in_shared_cache)
                        })
                    });
                    return Err(if cached { shared_cache_refusal(&display) } else { error });
                }
                _ => return Err(error),
            },
        };
        let binary = &project.binary;
        if binary.format == Format::Snapshot {
            return Err(failure("invalid_argument", "bind the original image, not a snapshot"));
        }
        match arch {
            Some(arch) if binary.arch != arch => {
                return Err(failure(
                    "arch_mismatch",
                    format!("the project is {} but the target is {arch}; nothing was bound", binary.arch),
                ));
            }
            None if slide.is_none() => {
                return Err(failure(
                    "arch_mismatch",
                    format!(
                        "the target architecture `{}` has no rampage equivalent, so the project's ({}) cannot be \
                         checked against it; pass slide to bind anyway",
                        info.architecture.as_deref().unwrap_or("unknown"),
                        binary.arch
                    ),
                ));
            }
            _ => {}
        }
        let mask = match binary.arch.default_pointer_size() {
            Some(4) => u64::from(u32::MAX),
            _ => u64::MAX,
        };
        let display = path.display().to_string();
        let canonical = path.canonicalize().ok().map(|path| path.display().to_string());
        let modules = session.modules().map_err(debug_failure)?;
        let pe = pe_file(binary);
        // A PE file's headers are no segment's bytes: the image base is where its `MZ` header maps.
        let header = header_address(binary).or(pe.as_ref().map(|pe| pe.header.image_base));
        let identity = image_identity(binary);
        let windows = info.is_windows() || pe.is_some();
        let mut limitations = Vec::new();

        // The match: (module label, its candidate slides, evidence).
        let mut matched: Option<(String, Vec<u64>, BindEvidence)> = None;
        let mut ambiguous = Vec::new();
        // Windows file names are case-insensitive and may be spelled with `\\?\` or `/`.
        let named = |name: &str| {
            module.is_none_or(|wanted| {
                name == wanted
                    || basename(name) == wanted
                    || (windows && (same_windows_path(name, wanted) || basename(name).eq_ignore_ascii_case(wanted)))
            })
        };
        let label = |entry: &rampage_debug::Module| {
            if entry.name.is_empty() {
                modules.exec_file.clone().unwrap_or_else(|| "<main>".into())
            } else {
                entry.name.clone()
            }
        };
        // Candidate slides per module: svr4 gives the load bias; a library list gives segment or section load
        // addresses, read as the header or as the first section, whichever verifies.
        let mut candidates: Vec<(String, Vec<u64>, Option<u64>)> = Vec::new();
        for entry in &modules.modules {
            let name = label(entry);
            if !named(&name) {
                continue;
            }
            if let Some(bias) = entry.l_addr {
                candidates.push((name, vec![bias], header));
            } else if let Some(image) = &entry.dyld {
                // dyld gives the Mach-O header's runtime address: the slide is that minus the file's `__TEXT`
                // address (the segment mapping file offset 0), or minus the `__TEXT` address dyld reports.
                let mut slides = Vec::new();
                if let Some(header) = header {
                    slides.push(image.load_address.wrapping_sub(header) & mask);
                }
                if let Some(text) = image.text_vmaddr {
                    slides.push(image.load_address.wrapping_sub(text) & mask);
                }
                slides.dedup();
                candidates.push((name, slides, header));
            } else if let (Some(pe), Some(image)) = (&pe, &entry.pe) {
                // A Windows stub's module whose PE header rampage found: the slide is its runtime base minus the
                // file's preferred base (`OptionalHeader.ImageBase`).
                candidates.push((name, vec![image.base.wrapping_sub(pe.header.image_base) & mask], header));
            } else if let Some(first) = entry.segments.first().or(entry.sections.first()) {
                let mut slides = Vec::new();
                if let Some(header) = header {
                    slides.push(first.wrapping_sub(header) & mask);
                }
                // gdbserver's `<segment>` is the base plus 0x1000 (`gdbserver/win32-low.cc`, `handle_load_dll`).
                if let Some(pe) = &pe {
                    let base = first.wrapping_sub(rampage_debug::pe::GDBSERVER_SEGMENT_OFFSET);
                    slides.insert(0, base.wrapping_sub(pe.header.image_base) & mask);
                }
                if let Some(section) =
                    binary.sections.iter().filter(|section| section.size > 0).map(|section| section.address).min()
                {
                    slides.push(first.wrapping_sub(section) & mask);
                }
                slides.dedup();
                candidates.push((name, slides, header));
            }
        }
        if let Some(pe) = &pe
            && let Some(wanted) = &pe.codeview
        {
            // The PDB GUID and age tie a PE image to its build like a build ID: read from the mapped debug
            // directory (by the module listing, else here at each candidate base).
            for (name, slides, _) in &candidates {
                let entry = modules.modules.iter().find(|entry| label(entry) == *name);
                let mut found = entry.and_then(|entry| entry.pe.as_ref()?.codeview.clone());
                for slide in slides {
                    if found.is_some() {
                        break;
                    }
                    found = runtime_codeview(&session, pe.header.image_base.wrapping_add(*slide) & mask, None)?;
                }
                if found.is_some_and(|found| found.guid == wanted.guid && found.age == wanted.age) {
                    if matched.is_some() {
                        ambiguous.push(name.clone());
                    } else {
                        matched = Some((
                            name.clone(),
                            slides.clone(),
                            BindEvidence::Codeview { guid: rampage_arch::hex::bytes(&wanted.guid), age: wanted.age },
                        ));
                    }
                }
            }
        }
        if let Some(wanted) = module
            && candidates.len() > 1
        {
            return Err(failure(
                "ambiguous_module",
                format!(
                    "{} modules are named `{wanted}`: {}; pass a full path",
                    candidates.len(),
                    candidates.iter().take(8).map(|(name, _, _)| name.clone()).collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        if let Some((macho, wanted)) = &identity {
            for (name, slides, header) in &candidates {
                let entry = modules.modules.iter().find(|entry| label(entry) == *name);
                // The stub's own reading of the identity: an ELF build ID, or the UUID dyld reports.
                let mut found = if *macho {
                    entry
                        .and_then(|entry| entry.dyld.as_ref()?.uuid.as_deref())
                        .map(|uuid| uuid.replace('-', "").to_ascii_lowercase())
                } else {
                    entry.and_then(|entry| entry.build_id.clone()).map(|id| id.to_ascii_lowercase())
                };
                // The identity is read at the header under each candidate slide until one carries it.
                for slide in slides {
                    if found.is_some() {
                        break;
                    }
                    let Some(header) = header else { break };
                    let at = header.wrapping_add(*slide) & mask;
                    found = if *macho {
                        runtime_uuid(&session, at, None)?
                    } else {
                        runtime_build_id(&session, at, *slide, None)?
                    };
                }
                if found.as_deref() == Some(wanted.as_str()) {
                    let evidence = if *macho {
                        BindEvidence::Uuid { uuid: wanted.clone() }
                    } else {
                        BindEvidence::BuildId { build_id: wanted.clone() }
                    };
                    if matched.is_some() {
                        ambiguous.push(name.clone());
                    } else {
                        matched = Some((name.clone(), slides.clone(), evidence));
                    }
                }
            }
        }
        if matched.is_none() {
            for (name, slides, _) in &candidates {
                let exact = Some(name.as_str()) == canonical.as_deref()
                    || *name == display
                    || (windows && same_windows_path(name, &display));
                let same_file = basename(name) == basename(&display)
                    || (windows && basename(name).eq_ignore_ascii_case(basename(&display)));
                if exact || same_file {
                    let evidence = if exact {
                        BindEvidence::Path { name: name.clone() }
                    } else {
                        BindEvidence::Basename { name: name.clone() }
                    };
                    if matched.as_ref().is_some_and(|(_, _, earlier)| matches!(earlier, BindEvidence::Path { .. })) {
                        continue;
                    }
                    if matched.is_some() && !exact {
                        ambiguous.push(name.clone());
                        continue;
                    }
                    matched = Some((name.clone(), slides.clone(), evidence));
                }
            }
        }
        if matched.is_none()
            && let Some(pe) = &pe
        {
            // PE headers: the file's first bytes, the `ImageBase` field left out.
            for (name, slides, _) in &candidates {
                for slide in slides {
                    let at = pe.header.image_base.wrapping_add(*slide) & mask;
                    if let Some(length) = pe_header_matches(&session, pe, binary.image_bytes(), at)? {
                        if matched.is_some() {
                            ambiguous.push(name.clone());
                        } else {
                            matched =
                                Some((name.clone(), vec![*slide], BindEvidence::HeaderBytes { address: at, length }));
                        }
                    }
                }
            }
        }
        if matched.is_none()
            && pe.is_none()
            && let Some(header_static) = header
            && let Some(file) = binary.read(header_static, HEADER_BYTES).or_else(|| binary.read(header_static, 64))
        {
            for (name, slides, _) in &candidates {
                for slide in slides {
                    let at = header_static.wrapping_add(*slide) & mask;
                    if read_exact(&session, at, file.len() as u64, None)?.as_deref() == Some(file) {
                        if matched.is_some() {
                            ambiguous.push(name.clone());
                        } else {
                            matched = Some((
                                name.clone(),
                                vec![*slide],
                                BindEvidence::HeaderBytes { address: at, length: file.len() },
                            ));
                        }
                    }
                }
            }
        }
        if !ambiguous.is_empty() && module.is_none() {
            let first = matched.as_ref().map(|(name, _, _)| name.clone()).unwrap_or_default();
            return Err(failure(
                "ambiguous_module",
                format!(
                    "several modules match this project ({first}, {}); pass module to choose one",
                    ambiguous.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        if matched.is_none() && modules.modules.is_empty() {
            // Bare-metal firmware and other targets without a module list: the image is the whole target.
            let offset = modules.offsets.as_ref().map(|offsets| offsets.text).unwrap_or(0);
            let candidate = slide.unwrap_or(offset) & mask;
            if let Some((compared, windows)) = mapped_image_matches(&session, binary, candidate, mask, None)? {
                matched = Some((
                    module.unwrap_or("<image>").to_owned(),
                    vec![candidate],
                    BindEvidence::MappedBytes { compared, windows },
                ));
            }
        }
        let (label, slides, evidence) = match (matched, slide) {
            (Some(found), _) => found,
            (None, Some(slide)) => {
                limitations.push(
                    "no runtime module matched the project; the slide is the caller's and only the byte comparison \
                     below supports it"
                        .into(),
                );
                (module.unwrap_or("<image>").to_owned(), vec![slide & mask], BindEvidence::ExplicitSlide)
            }
            (None, None) => {
                return Err(failure(
                    "no_module_match",
                    format!(
                        "no runtime module matches {display} by build ID or UUID, path, mapped header bytes or (with \
                         no module list) mapped code bytes; {} module(s) listed{}. Pass slide to bind anyway (0 for \
                         firmware linked where it runs)",
                        modules.modules.len(),
                        module.map(|module| format!(", none named `{module}`")).unwrap_or_default()
                    ),
                ));
            }
        };
        // A shared-cache image has no file at its path: only an image extracted from the cache, matched by its UUID,
        // is known to be the code that runs. A name, header bytes or a caller's slide are not enough.
        let relocated: &[(u64, u64)] = pe.as_ref().map_or(&[], |pe| &pe.relocated);
        let cached = modules.modules.iter().find(|entry| {
            (entry.name == label || module.is_some_and(|wanted| named_as(entry, wanted)))
                && entry.dyld.as_ref().is_some_and(|image| image.in_shared_cache)
        });
        if let Some(entry) = cached
            && !matches!(evidence, BindEvidence::Uuid { .. })
        {
            return Err(shared_cache_refusal(&entry.name));
        }
        let explicit = slide.is_some();
        // Every candidate slide is verified and the first that matches is kept; a caller's slide is the only one.
        let (slide, verification) = match slide {
            Some(given) => {
                let given = given & mask;
                if !slides.contains(&given) && !matches!(evidence, BindEvidence::ExplicitSlide) {
                    limitations.push(format!(
                        "the module's own slide is {}; the caller's {given:#x} is used instead",
                        slides.iter().map(|slide| format!("{slide:#x}")).collect::<Vec<_>>().join(" or ")
                    ));
                }
                (given, verify_slide(&session, binary, given, mask, &modules, relocated)?)
            }
            None => {
                let mut checked = Vec::new();
                for candidate in &slides {
                    let check = verify_slide(&session, binary, *candidate, mask, &modules, relocated)?;
                    let matched = check.outcome == "matched";
                    checked.push((*candidate, check));
                    if matched {
                        break;
                    }
                }
                let index = checked.iter().position(|(_, check)| check.outcome == "matched").unwrap_or(0);
                checked.swap_remove(index)
            }
        };
        match verification.outcome {
            "matched" => {}
            "mismatched" if !explicit => {
                return Err(failure(
                    "slide_mismatch",
                    format!(
                        "the module matched ({}), but at slide {slide:#x} {}; nothing was bound. Pass slide to bind \
                         anyway",
                        serde_json::to_string(&evidence).unwrap_or_default(),
                        verification.detail
                    ),
                ));
            }
            "mismatched" => {
                limitations.push(format!("slide verification failed: {}; locations may be wrong", verification.detail))
            }
            _ if !explicit && !evidence.identifies() => {
                return Err(failure(
                    "slide_unverified",
                    format!(
                        "only the module's name matched and the slide cannot be verified ({}); pass slide to bind \
                         anyway",
                        verification.detail
                    ),
                ));
            }
            _ => limitations.push(format!("the slide is not verified: {}", verification.detail)),
        }
        if binary.format == Format::Elf
            && let Details::Elf(details) = &binary.details
            && details.build_id.is_none()
        {
            limitations.push("the ELF file has no GNU build ID, so it cannot be matched by identity".into());
        }
        if let Some(pe) = &pe {
            if pe.codeview.is_none() {
                limitations.push(
                    "the PE file has no CodeView (RSDS) debug record, so it cannot be matched by identity".into(),
                );
            }
            if let Some(error) = &pe.relocation_error
                && slide & mask != 0
            {
                limitations.push(format!(
                    "the image moved but its base relocations could not be read ({error}); bytes the loader patched \
                     may fail verification"
                ));
            }
        }
        // Whole-program analysis runs now, so the stops that follow name functions without waiting for it.
        if let Err(error) = project.analysis() {
            limitations.push(format!("the project's analysis failed ({error}); stops will not name functions"));
        }
        let binding = Arc::new(Binding {
            module: label.clone(),
            path: display,
            project,
            slide,
            evidence,
            verification,
            explicit_slide: explicit,
            limitations,
            mask,
        });
        let mut all = self.bindings.lock().unwrap_or_else(PoisonError::into_inner);
        // A disconnect that finished while this bind ran must not leave a binding behind.
        if !self.has_session(number) {
            return Err(failure("unknown_session", format!("session `{id}` was disconnected while binding")));
        }
        let list = all.entry(number).or_default();
        let replaced = list.iter().position(|existing| existing.module == label);
        if replaced.is_none() && list.len() >= MAX_BINDINGS {
            return Err(failure(
                "binding_limit",
                format!(
                    "a session binds at most {MAX_BINDINGS} projects; bind again with a bound module to replace it"
                ),
            ));
        }
        match replaced {
            Some(index) => list[index] = Arc::clone(&binding),
            None => list.push(Arc::clone(&binding)),
        }
        Ok(DebugBinding {
            session: id.to_owned(),
            binding: binding.view(),
            replaced: replaced.is_some(),
            bindings: list.len(),
        })
    }

    /// The stop's pc, matched breakpoints and watch address located in the bound projects.
    pub(crate) fn stop_locations(&self, id: &str, session: &Session, event: &StopEvent) -> StopLocations {
        let bindings = self.bindings_of(id);
        let values = match (event.pc, event.pc_bytes.as_deref()) {
            (Some(pc), _) => vec![pc],
            (None, Some(bytes)) => both_orders(bytes),
            (None, None) => Vec::new(),
        };
        let picked = pick(&values, &bindings);
        let unknown = if values.is_empty() {
            "the pc could not be read"
        } else {
            "the byte order is unknown and no single decoding of the pc lies in a bound module"
        };
        let pc = located(&bindings, picked.as_ref().map(|(pc, _)| *pc), unknown);
        let table = if event.breakpoints.is_empty() { Vec::new() } else { session.breakpoints().unwrap_or_default() };
        let breakpoints = event
            .breakpoints
            .iter()
            .map(|id| {
                let address = table.iter().find(|entry| entry.id == *id).map(|entry| entry.address);
                BreakpointLocated {
                    id: *id,
                    located: located(&bindings, address, "the breakpoint is no longer listed"),
                }
            })
            .collect();
        let watch = event.watch.as_ref().map(|watch| located(&bindings, Some(watch.address), ""));
        StopLocations { pc, breakpoints, watch, pc_evidence: picked.and_then(|(_, evidence)| evidence) }
    }

    /// For each register, what its value points at in a bound project; and notes on what could not be annotated.
    pub(crate) fn annotate_registers(
        &self,
        id: &str,
        session: &Session,
        registers: &[RegisterValue],
    ) -> (Vec<Option<Pointee>>, Vec<String>) {
        let bindings = self.bindings_of(id);
        let mut notes = Vec::new();
        if bindings.is_empty() {
            notes.push("annotate: no project is bound to this session; debug_bind one".into());
            return (vec![None; registers.len()], notes);
        }
        // With an unknown byte order, the pc's decodings decide it when exactly one lies in a bound module.
        let mut order = session.info().byte_order;
        if order == ByteOrder::Unknown {
            let pc = registers.iter().find(|register| ["pc", "rip", "eip"].contains(&register.name.as_str()));
            if let Some(bytes) = pc.and_then(|pc| pc.bytes.as_deref())
                && let [little, big] = both_orders(bytes)[..]
            {
                order = match (locate(&bindings, little).is_some(), locate(&bindings, big).is_some()) {
                    (true, false) => ByteOrder::Little,
                    (false, true) => ByteOrder::Big,
                    _ => ByteOrder::Unknown,
                };
            }
            match order {
                ByteOrder::Unknown => notes.push(
                    "annotate: the byte order is unknown and the pc does not settle it; values are not annotated"
                        .into(),
                ),
                _ => notes.push(format!(
                    "annotate: values were read {} because only that decoding of the pc lies in a bound module",
                    if order == ByteOrder::Little { "little-endian" } else { "big-endian" }
                )),
            }
        }
        let annotations = registers
            .iter()
            .map(|register| {
                let value = match order {
                    ByteOrder::Unknown => return None,
                    _ if register.integer().is_some() => register.integer()?,
                    _ => {
                        let values = both_orders(register.bytes.as_deref()?);
                        match (order, &values[..]) {
                            (_, [value]) => *value,
                            (ByteOrder::Little, [little, _]) => *little,
                            (_, [_, big]) => *big,
                            _ => return None,
                        }
                    }
                };
                if value == 0 || register.bitsize > 64 {
                    return None;
                }
                if let Some((binding, address)) = locate(&bindings, value) {
                    return Some(pointee(&binding, value, address));
                }
                // A signed return address or frame pointer (arm64e) locates once its PAC is taken off. Only registers
                // that hold code or frame pointers are stripped, so a plain integer is never read as a code pointer.
                // debugserver already strips these when it reads them; this guards stubs that do not.
                if !CODE_POINTER_REGISTERS.contains(&register.name.as_str()) {
                    return None;
                }
                let stripped = session.info().strip_code_address(value);
                let (binding, address) = locate(&bindings, stripped).filter(|_| stripped != value)?;
                Some(Pointee { signed_value: Some(value), ..pointee(&binding, stripped, address) })
            })
            .collect();
        (annotations, notes)
    }

    /// Inserts a breakpoint or watchpoint at a runtime address, a static address in a bound project, or a function
    /// of a bound project by name, recording the static location with the entry.
    pub fn set_breakpoint_at(
        &self,
        id: &str,
        epoch: u64,
        kind: DebugBreakKind,
        target: BreakTarget,
        size: Option<u64>,
        length: Option<u64>,
    ) -> Result<DebugBreakpoint, ApiError> {
        let (address, placement, thumb) = match target {
            BreakTarget::Runtime(address) => (address, None, None),
            BreakTarget::Static { address, path } => {
                let binding = self.binding_for(id, path.as_deref())?;
                let resolved = Resolved { function: function_at(&binding.project, address), binding, address };
                self.placed(resolved)?
            }
            BreakTarget::Function { name, path } => {
                let bindings = match path.as_deref() {
                    Some(path) => vec![self.binding_for(id, Some(path))?],
                    None => self.bindings_of(id),
                };
                if bindings.is_empty() {
                    return Err(failure("not_bound", "no project is bound to this session; debug_bind one first"));
                }
                let mut found = Vec::new();
                let mut errors = Vec::new();
                for binding in bindings {
                    match resolve_function(&binding.project, &name) {
                        Ok(address) => found.push((binding, address)),
                        Err(error @ ApiError::Invalid(_)) => return Err(error),
                        Err(error) => errors.push(error.to_string()),
                    }
                }
                let (binding, address) = match found.len() {
                    1 => found.pop().expect("one"),
                    0 => return Err(ApiError::NotFound(errors.join("; "))),
                    _ => {
                        return Err(failure(
                            "ambiguous_name",
                            format!(
                                "`{name}` is in several bound projects ({}); pass path",
                                found.iter().map(|(binding, _)| binding.path.clone()).collect::<Vec<_>>().join(", ")
                            ),
                        ));
                    }
                };
                let function = Some((binding.project.function_name(address), address));
                self.placed(Resolved { binding, address, function })?
            }
        };
        let session = self.session(id)?;
        let kind = kind.into();
        let size = match (kind, size, length) {
            (BreakKind::Software | BreakKind::Hardware, size, None) => size.or_else(|| {
                // A-profile ARM: the breakpoint's kind follows the instruction set state of the code it is placed in,
                // as the project maps it, not the state the target is stopped in.
                let a_profile = session.info().family == Family::Arm
                    && !rampage_debug::target::m_profile(session.info().layout.as_ref());
                (a_profile && thumb == Some(false)).then_some(4)
            }),
            (BreakKind::Software | BreakKind::Hardware, _, Some(_)) => {
                return Err(failure("invalid_argument", "breakpoints take size, not length"));
            }
            (_, None, length) => length,
            (_, Some(_), _) => return Err(failure("invalid_argument", "watchpoints take length, not size")),
        };
        // An odd address names Thumb code to the session; only breakpoints take it, never a watched data address.
        let address = if thumb == Some(true) && !kind.is_watchpoint() { address | 1 } else { address };
        let breakpoint =
            session.set_breakpoint_placed(Some(epoch), kind, address, size, placement).map_err(debug_failure)?;
        Ok(DebugBreakpoint { session: id.to_owned(), action: "set", breakpoint })
    }

    /// The runtime address of a resolved static location, its placement record and, on ARM, whether the project
    /// maps it as Thumb code.
    fn placed(&self, resolved: Resolved) -> Result<(u64, Option<Placement>, Option<bool>), ApiError> {
        let Resolved { binding, address, function } = resolved;
        if binding.to_static(binding.to_runtime(address)).is_none() {
            return Err(failure(
                "invalid_argument",
                format!("{address:#x} is not in a mapped segment of {}", binding.path),
            ));
        }
        let binary = &binding.project.binary;
        let thumb = (binary.arch == Arch::Arm).then(|| binary.thumb.iter().any(|range| range.contains(&address)));
        let placement = Placement {
            static_address: address,
            path: binding.path.clone(),
            module: binding.module.clone(),
            function: function.as_ref().map(|(name, _)| name.clone()),
            offset_in_function: function.and_then(|(_, start)| address.checked_sub(start)),
        };
        Ok((binding.to_runtime(address), Some(placement), thumb))
    }

    /// The binding a static address or name refers to: the one at `path`, else the session's only one.
    fn binding_for(&self, id: &str, path: Option<&str>) -> Result<Arc<Binding>, ApiError> {
        let bindings = self.bindings_of(id);
        match path {
            Some(path) => {
                let canonical = Path::new(path).canonicalize().ok();
                bindings
                    .iter()
                    .find(|binding| {
                        binding.path == path
                            || canonical.is_some() && Path::new(&binding.path).canonicalize().ok() == canonical
                    })
                    .cloned()
                    .ok_or_else(|| failure("not_bound", format!("{path} is not bound to this session; debug_bind it")))
            }
            None => match &bindings[..] {
                [binding] => Ok(Arc::clone(binding)),
                [] => Err(failure("not_bound", "no project is bound to this session; debug_bind one first")),
                _ => Err(failure("invalid_argument", "several projects are bound; pass path")),
            },
        }
    }

    /// Steps over `count` instructions: a call runs to the instruction after it (a temporary breakpoint there,
    /// removed at whatever stop comes), anything else is single-stepped.
    pub fn step_over(
        &self,
        id: &str,
        epoch: u64,
        count: Option<u32>,
        timeout_ms: Option<u64>,
        cancel: &Cancel,
    ) -> Result<DebugStepped, ApiError> {
        let session = self.session(id)?;
        let count = count.unwrap_or(1);
        if !(1..=rampage_debug::MAX_STEPS).contains(&count) {
            return Err(failure("invalid_argument", format!("count must be in 1..={}", rampage_debug::MAX_STEPS)));
        }
        let wait = run_wait(timeout_ms)?;
        let started = Instant::now();
        let mut result = stepped(id, "over", epoch, count);
        let mut epoch = epoch;
        for _ in 0..count {
            if cancel.is_cancelled() {
                result.cancelled = true;
                break;
            }
            if started.elapsed() >= STEP_OVER_BUDGET {
                result.truncated = Some(format!("no step starts {} s after the request", STEP_OVER_BUDGET.as_secs()));
                break;
            }
            let instruction = match self.instruction_at_pc(id, &session, epoch) {
                Ok(instruction) => instruction,
                Err(error) if result.completed == 0 => return Err(error),
                Err(error) => {
                    result.truncated = Some(format!("stopped before step {}: {error}", result.completed + 1));
                    break;
                }
            };
            let mut step = OverStep {
                pc: instruction.pc,
                length: instruction.length,
                flow: instruction.flow,
                bytes_source: instruction.source,
                outcome: "stepped",
                return_address: None,
                temporary_breakpoint: None,
                user_breakpoint: None,
            };
            let done = if instruction.call {
                let back = instruction.pc.wrapping_add(u64::from(instruction.length));
                step.return_address = Some(back);
                let address = back | u64::from(instruction.thumb == Some(true));
                // Returning from the call restores the stack pointer it was made with; an inner (recursive) frame
                // reaching the same address has a lower one.
                let frame = Frame { thread: instruction.thread, least_sp: instruction.sp };
                let size = arm_size(&session, instruction.thumb);
                let landed =
                    self.run_to(id, &session, epoch, address, size, frame, wait, cancel, &mut step, &mut result)?;
                epoch = result.epoch;
                landed
            } else {
                let steps = session.step_with(Some(epoch), None, 1, true, cancel).map_err(debug_failure)?;
                result.state = steps.state.clone();
                result.epoch = steps.epoch;
                result.running_for_ms = steps.running_for_ms;
                result.event = steps.event.clone();
                epoch = steps.epoch;
                if steps.cancelled {
                    result.cancelled = true;
                    step.outcome = "cancelled";
                } else if steps.completed == 1 {
                    step.outcome = "stepped";
                } else if steps.state == State::Running {
                    step.outcome = "running";
                } else {
                    step.outcome = "stopped_elsewhere";
                }
                if let Some(why) = steps.truncated {
                    result.truncated = Some(why);
                }
                steps.completed == 1
            };
            push_step(&mut result, step);
            if !done {
                break;
            }
            result.completed += 1;
        }
        self.finish_stepped(id, &session, &mut result);
        Ok(result)
    }

    /// Steps out of the function whose first instruction is at the pc: a temporary breakpoint at the return address
    /// the ABI holds on entry, removed at whatever stop comes. Refused anywhere but a function's entry
    /// ([`STEP_OUT_RULE`]).
    pub fn step_out(
        &self,
        id: &str,
        epoch: u64,
        timeout_ms: Option<u64>,
        cancel: &Cancel,
    ) -> Result<DebugStepped, ApiError> {
        let session = self.session(id)?;
        let wait = run_wait(timeout_ms)?;
        let bindings = self.bindings_of(id);
        let info = session.info();
        let registers = session.registers_at(None, Some(epoch)).map_err(debug_failure)?;
        let pc = register_value(&registers.registers, &["pc", "rip", "eip"], &bindings)
            .ok_or_else(|| failure("unsupported", "the pc could not be read or its byte order is unknown"))?;
        let refuse = |why: String| failure("step_out_refused", format!("{why}. Rule: {STEP_OUT_RULE}"));
        let Some((binding, address)) = locate(&bindings, pc) else {
            return Err(refuse(format!("the pc {pc:#x} is not in a bound project, so its function entry is unknown")));
        };
        let project = &binding.project;
        let entry =
            function_start(project, address).0 == Some(address)
                || project.binary.symbols.iter().any(|symbol| {
                    symbol.kind == rampage_loaders::SymbolKind::Function && symbol.address & !1 == address
                });
        if !entry {
            let at = describe(&binding, pc, address);
            return Err(refuse(format!(
                "the pc {pc:#x} ({}+{:#x}) is not a function's first instruction",
                at.function.as_deref().unwrap_or("no function"),
                at.offset_in_function.unwrap_or(0)
            )));
        }
        let sp_name: &[&str] = match info.family {
            Family::X86_64 => &["rsp"],
            Family::X86 => &["esp"],
            _ => &["sp"],
        };
        let sp = register_in_order(&registers.registers, sp_name, &bindings);
        let mut pac_note = None;
        let (back, thumb) = match info.family {
            Family::Arm => {
                let lr = register_value(&registers.registers, &["lr", "r14"], &bindings)
                    .ok_or_else(|| refuse("lr could not be read".into()))?;
                if rampage_debug::target::m_profile(info.layout.as_ref()) && lr >= 0xf000_0000 {
                    return Err(refuse(format!(
                        "lr is {lr:#x}, an exception return value: this is an exception handler, which returns by \
                         exception return, not to an address"
                    )));
                }
                (lr & !1, lr & 1 == 1)
            }
            Family::Aarch64 => {
                let signed = register_value(&registers.registers, &["x30", "lr"], &bindings)
                    .ok_or_else(|| refuse("x30 could not be read".into()))?;
                // arm64e signs return addresses; the breakpoint goes at the address without the PAC.
                let back = info.strip_code_address(signed);
                if back != signed {
                    pac_note = Some(format!(
                        "x30 {signed:#x} carries a pointer authentication code; the return address is {back:#x} ({})",
                        info.address_mask.as_ref().map(|mask| mask.source.as_str()).unwrap_or_default()
                    ));
                }
                (back, false)
            }
            Family::Riscv32 | Family::Riscv64 => (
                register_value(&registers.registers, &["ra", "x1"], &bindings)
                    .ok_or_else(|| refuse("ra could not be read".into()))?,
                false,
            ),
            Family::X86_64 | Family::X86 => {
                let (name, width) = if info.family == Family::X86_64 { ("rsp", 8) } else { ("esp", 4) };
                let sp = register_value(&registers.registers, &[name], &bindings)
                    .ok_or_else(|| refuse(format!("{name} could not be read")))?;
                let bytes = read_exact(&session, sp, width, Some(epoch))?
                    .ok_or_else(|| refuse(format!("the return address at [{name}] = {sp:#x} could not be read")))?;
                (bytes.iter().rev().fold(0u64, |value, byte| value << 8 | u64::from(*byte)), false)
            }
            Family::Other => return Err(refuse("the target architecture has no known return-address rule".into())),
        };
        if back == 0 {
            return Err(refuse("the return address is 0".into()));
        }
        let mut result = stepped(id, "out", epoch, 1);
        result.rule = Some(STEP_OUT_RULE);
        result.warnings.extend(pac_note);
        let mut step = OverStep {
            pc,
            length: 0,
            flow: "return".into(),
            bytes_source: "registers",
            outcome: "returned",
            return_address: Some(back),
            temporary_breakpoint: None,
            user_breakpoint: None,
        };
        let address = back | u64::from(thumb && info.family == Family::Arm);
        // Back in the caller the stack pointer is at least the entry's (above it on x86, which pops the return
        // address); the caller's own frame calling this function again has a lower one.
        let pushed = match info.family {
            Family::X86_64 => 8,
            Family::X86 => 4,
            _ => 0,
        };
        let frame = Frame { thread: registers.thread, least_sp: sp.map(|sp| sp.wrapping_add(pushed)) };
        let size = if info.family == Family::Arm { arm_size(&session, Some(thumb)) } else { None };
        if self.run_to(id, &session, epoch, address, size, frame, wait, cancel, &mut step, &mut result)? {
            result.completed = 1;
        }
        push_step(&mut result, step);
        self.finish_stepped(id, &session, &mut result);
        Ok(result)
    }

    /// Places a temporary breakpoint at `address`, continues and reports whether the stop was that breakpoint
    /// (or the table breakpoint standing in for it). The temporary breakpoint goes at the next stop whatever it is;
    /// if continuing fails before anything runs, it is removed here.
    #[allow(clippy::too_many_arguments)]
    fn run_to(
        &self,
        id: &str,
        session: &Session,
        epoch: u64,
        address: u64,
        size: Option<u64>,
        frame: Frame,
        wait: Duration,
        cancel: &Cancel,
        step: &mut OverStep,
        result: &mut DebugStepped,
    ) -> Result<bool, ApiError> {
        let bindings = self.bindings_of(id);
        let placement = locate(&bindings, address & !1).map(|(binding, at)| {
            let function = function_at(&binding.project, at);
            Placement {
                static_address: at,
                path: binding.path.clone(),
                module: binding.module.clone(),
                function: function.as_ref().map(|(name, _)| name.clone()),
                offset_in_function: function.and_then(|(_, start)| at.checked_sub(start)),
            }
        });
        let placed = session.set_temporary(Some(epoch), address, size, placement).map_err(debug_failure)?;
        let (temporary, user) = match &placed {
            TemporaryPlacement::Inserted { breakpoint } => (Some(breakpoint.id), None),
            TemporaryPlacement::Existing { breakpoint } => (None, Some(breakpoint.id)),
        };
        step.temporary_breakpoint = temporary;
        step.user_breakpoint = user;
        let run = match session.resume(Some(epoch), wait, cancel) {
            Ok(run) => run,
            Err(error) => {
                if let Some(temporary) = temporary
                    && session.clear_breakpoint(None, temporary).is_err()
                {
                    result.warnings.push(format!(
                        "temporary breakpoint {temporary} could not be removed after the continue failed; it is \
                         removed at the next stop or when disconnecting"
                    ));
                }
                return Err(debug_failure(error));
            }
        };
        result.state = run.state.clone();
        result.epoch = run.epoch;
        result.running_for_ms = run.running_for_ms;
        result.warnings.extend(run.warnings.iter().cloned());
        if run.cancelled {
            result.cancelled = true;
        }
        let hit = match (&run.state, &run.event) {
            (State::Stopped, Some(event)) if event.epoch == run.epoch => {
                event.temporary.iter().any(|outcome| outcome.hit && Some(outcome.id) == temporary)
                    || user.is_some_and(|user| event.breakpoints.contains(&user))
            }
            _ => false,
        };
        // The breakpoint was reached; whether by the frame and thread that will return there is checked next.
        let mut wrong = None;
        if hit && let Some(event) = &run.event {
            if let (Some(expected), Some(stopped)) = (frame.thread, event.thread)
                && expected != stopped
            {
                wrong = Some("other_thread");
            } else if let Some(least) = frame.least_sp {
                let registers = session.registers_at(None, Some(run.epoch)).map_err(debug_failure)?;
                let names: &[&str] = &["rsp", "esp", "sp"];
                match register_in_order(&registers.registers, names, &self.bindings_of(id)) {
                    Some(sp) if sp < least => wrong = Some("inner_frame"),
                    Some(_) => {}
                    None => result.warnings.push(
                        "the stack pointer could not be read at the stop, so the frame it returned to is not checked"
                            .into(),
                    ),
                }
            } else {
                result.warnings.push(
                    "the stack pointer could not be read before running, so the frame it returned to is not checked"
                        .into(),
                );
            }
        }
        let landed = hit && wrong.is_none();
        if let Some(wrong) = wrong {
            result.warnings.push(format!(
                "the return address was reached by {}; the target is stopped there and nothing more was run",
                if wrong == "other_thread" { "another thread" } else { "an inner (recursive) frame, not the caller" }
            ));
        }
        step.outcome = match run.state {
            _ if landed => "returned",
            _ if wrong.is_some() => wrong.unwrap_or_default(),
            State::Running if run.cancelled => "cancelled",
            State::Running => "running",
            _ => "stopped_elsewhere",
        };
        if run.state == State::Running && temporary.is_some() {
            result.warnings.push(format!(
                "the target is still running with temporary breakpoint {} inserted; it is removed at the next stop \
                 (debug_wait, debug_interrupt) whatever the stop is, or when disconnecting",
                temporary.unwrap_or_default()
            ));
        }
        result.event = run.event;
        Ok(landed)
    }

    fn finish_stepped(&self, id: &str, session: &Session, result: &mut DebugStepped) {
        result.locations = match (&result.state, &result.event) {
            (State::Stopped, Some(event)) => Some(self.stop_locations(id, session, event)),
            _ => None,
        };
    }

    /// The instruction at the stopped thread's pc, decoded with rampage's decoder for the bound project's
    /// architecture (or the session's), from target memory (else the file).
    fn instruction_at_pc(&self, id: &str, session: &Session, epoch: u64) -> Result<PcInstruction, ApiError> {
        let info = session.info();
        let arch = family_arch(info.family).ok_or_else(|| {
            failure("unsupported", "the target architecture has no rampage decoder; step over needs one")
        })?;
        let bindings = self.bindings_of(id);
        let registers = session.registers_at(None, Some(epoch)).map_err(debug_failure)?;
        let pc = register_value(&registers.registers, &["pc", "rip", "eip"], &bindings).ok_or_else(|| {
            failure(
                "unsupported",
                "the pc could not be read, or the byte order is unknown and no bound module settles it",
            )
        })?;
        let at = locate(&bindings, pc);
        let thumb = match arch {
            Arch::Arm if rampage_debug::target::m_profile(info.layout.as_ref()) => Some(true),
            Arch::Arm => {
                let cpsr = register_value(&registers.registers, &["cpsr"], &bindings).map(|cpsr| cpsr & 0x20 != 0);
                let from_project = at
                    .as_ref()
                    .map(|(binding, address)| binding.project.binary.thumb.iter().any(|range| range.contains(address)));
                Some(cpsr.or(from_project).ok_or_else(|| {
                    failure("unsupported", "the ARM instruction set state (CPSR.T) is unknown at the pc")
                })?)
            }
            _ => None,
        };
        let mut target = match &at {
            Some((binding, _)) => binding.project.binary.target(),
            None => Target::new(arch),
        };
        // The instruction set state at the pc is the runtime's, whatever the file's ranges say.
        let thumb_at_pc = (thumb == Some(true)).then(|| pc..pc.wrapping_add(4));
        target.thumb = thumb_at_pc.into_iter().collect();
        let mut decoder = rampage_arch::decoder(&target)?;
        let length: u64 = if matches!(arch, Arch::X86 | Arch::X86_64) { 15 } else { 4 };
        let memory = read_prefix(session, pc, length, Some(epoch))?;
        let decode = |decoder: &mut Box<dyn rampage_arch::Disassembler>, bytes: &[u8]| {
            decoder.reset();
            let insn = decoder.decode(bytes, pc);
            (!bytes.is_empty() && !matches!(insn.flow, Flow::Invalid | Flow::Halt) && insn.len > 0).then_some(insn)
        };
        let (insn, source) = match decode(&mut decoder, &memory) {
            Some(insn) => (insn, "target_memory"),
            None => {
                let file = at.as_ref().and_then(|(binding, address)| {
                    [length, 4, 2].into_iter().find_map(|length| binding.project.binary.read(*address, length))
                });
                match file.and_then(|file| decode(&mut decoder, file)) {
                    Some(insn) => (insn, "file"),
                    None => {
                        return Err(failure(
                            "undecodable",
                            format!(
                                "the instruction at {pc:#x} does not decode from target memory{}",
                                if at.is_some() { " or the file" } else { " (no bound project to fall back on)" }
                            ),
                        ));
                    }
                }
            }
        };
        let call = matches!(insn.flow, Flow::Call(_) | Flow::IndirectCall);
        let flow = serde_json::to_value(insn.flow)
            .ok()
            .and_then(|value| value.get("kind").and_then(|kind| kind.as_str().map(str::to_owned)))
            .unwrap_or_default();
        let sp = register_in_order(&registers.registers, &["rsp", "esp", "sp"], &bindings);
        Ok(PcInstruction { pc, length: insn.len, call, flow, source, thumb, sp, thread: registers.thread })
    }

    /// A bounded record of the stopped target for the findings ledger: endpoint, epoch, the pc's location,
    /// selected registers and small memory ranges, plus a compact form `record_finding` takes as evidence.
    pub fn evidence(
        &self,
        id: &str,
        epoch: Option<u64>,
        names: Option<&[String]>,
        ranges: &[EvidenceRange],
    ) -> Result<DebugEvidence, ApiError> {
        let session = self.session(id)?;
        if ranges.len() > MAX_EVIDENCE_RANGES
            || ranges.iter().any(|range| !(1..=MAX_EVIDENCE_BYTES).contains(&range.length))
        {
            return Err(failure(
                "invalid_argument",
                format!("give at most {MAX_EVIDENCE_RANGES} memory ranges of 1..={MAX_EVIDENCE_BYTES} bytes"),
            ));
        }
        if names.is_some_and(|names| names.is_empty() || names.len() > MAX_EVIDENCE_REGISTERS) {
            return Err(failure("invalid_argument", format!("names takes 1..={MAX_EVIDENCE_REGISTERS} registers")));
        }
        let info = session.info();
        let bindings = self.bindings_of(id);
        let registers = session.registers_at(None, epoch).map_err(debug_failure)?;
        let mut limitations = Vec::new();
        let pc_register =
            registers.registers.iter().find(|register| ["pc", "rip", "eip"].contains(&register.name.as_str()));
        let pc_values = pc_register.map(candidates).unwrap_or_default();
        let pc = located(
            &bindings,
            pick(&pc_values, &bindings).map(|(pc, _)| pc),
            "the pc could not be read, or its byte order is unknown",
        );
        let default_names: &[&str] = match info.family {
            Family::Arm => &["pc", "sp", "lr", "r0", "r1", "r2", "r3"],
            // debugserver names x30 `lr`.
            Family::Aarch64 => &["pc", "sp", "x30", "lr", "x0", "x1", "x2", "x3"],
            Family::Riscv32 | Family::Riscv64 => &["pc", "sp", "ra", "a0", "a1", "a2", "a3"],
            // The Microsoft x64 calling convention passes the first arguments in rcx, rdx, r8 and r9.
            Family::X86_64 if info.is_windows() => &["rip", "rsp", "rax", "rcx", "rdx", "r8", "r9"],
            Family::X86_64 => &["rip", "rsp", "rax", "rdi", "rsi", "rdx", "rcx"],
            Family::X86 => &["eip", "esp", "eax", "ecx", "edx"],
            Family::Other => &["pc", "sp"],
        };
        let wanted: Vec<String> = match names {
            Some(names) => names.to_vec(),
            None => default_names.iter().map(|name| (*name).to_owned()).collect(),
        };
        let mut selected = Vec::new();
        for name in &wanted {
            match registers.registers.iter().find(|register| register.name == *name) {
                Some(register) => selected.push(EvidenceRegister {
                    name: name.clone(),
                    value: register
                        .value
                        .clone()
                        .or_else(|| register.bytes.as_ref().map(|bytes| format!("bytes:{bytes}")))
                        .unwrap_or_else(|| "unavailable".into()),
                }),
                None if names.is_some() => {
                    return Err(failure("invalid_argument", format!("unknown register `{name}`")));
                }
                None => {}
            }
        }
        if registers.byte_order == ByteOrder::Unknown {
            limitations.push("the byte order is unknown: register values are the bytes as the stub sent them".into());
        }
        let mut memory = Vec::new();
        for range in ranges {
            let bytes = read_prefix(&session, range.address.0, range.length as u64, Some(registers.epoch))?;
            memory.push(EvidenceMemory {
                address: range.address.0,
                hex: rampage_arch::hex::bytes(&bytes),
                complete: bytes.len() == range.length,
            });
        }
        let mut detail = format!("{} {id} epoch {} pc ", info.endpoint, registers.epoch);
        match (&pc.runtime_address, &pc.location) {
            (Some(runtime), Some(location)) => detail.push_str(&format!(
                "{runtime:#x}={}:{:#x}{}",
                basename(&location.path),
                location.static_address,
                location
                    .function
                    .as_ref()
                    .map(|function| format!("({function}+{:#x})", location.offset_in_function.unwrap_or(0)))
                    .unwrap_or_default()
            )),
            (Some(runtime), None) => detail.push_str(&format!("{runtime:#x}")),
            _ => detail.push('?'),
        }
        // The memory asked for comes before the registers; whole items that do not fit are left out and named.
        let items = memory
            .iter()
            .map(|range| (format!("[{:#x}]", range.address), format!(" [{:#x}]={}", range.address, range.hex)))
            .chain(
                selected
                    .iter()
                    .map(|register| (register.name.clone(), format!(" {}={}", register.name, register.value))),
            );
        let mut omitted = Vec::new();
        for (name, text) in items {
            // Room is kept for the note naming what is left out.
            if detail.len() + text.len() <= MAX_LEDGER_DETAIL - 40 {
                detail.push_str(&text);
            } else {
                omitted.push(name);
            }
        }
        if !omitted.is_empty() {
            detail.push_str(&format!(" (+{} omitted)", omitted.len()));
            limitations.push(format!(
                "ledger_evidence's {MAX_LEDGER_DETAIL}-byte detail leaves out {}; they are in this result only",
                omitted.join(", ")
            ));
        }
        let detail = clip(&detail, MAX_LEDGER_DETAIL);
        Ok(DebugEvidence {
            session: id.to_owned(),
            endpoint: info.endpoint.clone(),
            epoch: registers.epoch,
            thread: registers.thread,
            pc,
            registers: selected,
            memory,
            ledger_evidence: crate::LedgerEvidence { tool: "debug_evidence".into(), detail },
            limitations,
        })
    }
}

/// `text` cut to at most `limit` bytes at a character boundary, ending in `...` when cut.
fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit - 3;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

struct PcInstruction {
    pc: u64,
    length: u8,
    call: bool,
    flow: String,
    source: &'static str,
    thumb: Option<bool>,
    /// The stack pointer and thread the instruction runs with.
    sp: Option<u64>,
    thread: Option<rampage_debug::ThreadId>,
}

/// The frame a step over or out must return to: the thread, and the least stack pointer it has there.
#[derive(Clone, Copy)]
struct Frame {
    thread: Option<rampage_debug::ThreadId>,
    least_sp: Option<u64>,
}

/// The breakpoint size for code in the given instruction set state on A-profile ARM: 4 in ARM state, so the kind
/// follows the destination rather than the state the target is stopped in. `None` elsewhere (the default applies).
fn arm_size(session: &Session, thumb: Option<bool>) -> Option<u64> {
    let info = session.info();
    let a_profile = info.family == Family::Arm && !rampage_debug::target::m_profile(info.layout.as_ref());
    (a_profile && thumb == Some(false)).then_some(4)
}

/// The byte order register values are read in: the session's, else the one under which only one decoding of the pc
/// lies in a bound module.
fn inferred_order(registers: &[RegisterValue], bindings: &[Arc<Binding>]) -> ByteOrder {
    let pc = registers.iter().find(|register| ["pc", "rip", "eip"].contains(&register.name.as_str()));
    if pc.is_some_and(|pc| pc.integer().is_some()) {
        return ByteOrder::Unknown;
    }
    match pc.and_then(|pc| pc.bytes.as_deref()).map(both_orders).as_deref() {
        Some([little, big]) => match (locate(bindings, *little).is_some(), locate(bindings, *big).is_some()) {
            (true, false) => ByteOrder::Little,
            (false, true) => ByteOrder::Big,
            _ => ByteOrder::Unknown,
        },
        _ => ByteOrder::Unknown,
    }
}

/// The first of `names` the registers hold, decoded in the session's byte order, else the order the pc settles.
fn register_in_order(registers: &[RegisterValue], names: &[&str], bindings: &[Arc<Binding>]) -> Option<u64> {
    let register = names.iter().find_map(|name| registers.iter().find(|register| register.name == *name))?;
    if let Some(value) = register.integer() {
        return Some(value);
    }
    let values = both_orders(register.bytes.as_deref()?);
    match (inferred_order(registers, bindings), &values[..]) {
        (_, [value]) => Some(*value),
        (ByteOrder::Little, [little, _]) => Some(*little),
        (ByteOrder::Big, [_, big]) => Some(*big),
        _ => None,
    }
}

fn stepped(id: &str, mode: &'static str, epoch: u64, requested: u32) -> DebugStepped {
    DebugStepped {
        session: id.to_owned(),
        mode,
        state: State::Stopped,
        epoch,
        requested,
        completed: 0,
        steps: Vec::new(),
        steps_omitted: 0,
        event: None,
        locations: None,
        cancelled: false,
        truncated: None,
        running_for_ms: None,
        warnings: Vec::new(),
        rule: None,
    }
}

fn push_step(result: &mut DebugStepped, step: OverStep) {
    if result.steps.len() == MAX_STEP_DETAILS {
        result.steps.remove(0);
        result.steps_omitted += 1;
    }
    result.steps.push(step);
}

/// The first of `names` the registers hold, as an integer: decoded, or (byte order unknown) the decoding a bound
/// module settles.
fn register_value(registers: &[RegisterValue], names: &[&str], bindings: &[Arc<Binding>]) -> Option<u64> {
    let register = names.iter().find_map(|name| registers.iter().find(|register| register.name == *name))?;
    pick(&candidates(register), bindings).map(|(value, _)| value)
}

/// The function containing static `address` and its start.
fn function_at(project: &Project, address: u64) -> Option<(String, u64)> {
    let start = function_start(project, address).0?;
    Some((project.function_name(start), start))
}

fn pointee(binding: &Binding, runtime: u64, address: u64) -> Pointee {
    let location = describe(binding, runtime, address);
    let binary = &binding.project.binary;
    let symbol = binding.project.name_at(address);
    let code = binary.is_code(address);
    let string = if code { None } else { crate::listing::string_at(binary, address) };
    let kind = if string.is_some() {
        "string"
    } else if code && location.function.is_some() {
        "code"
    } else if symbol.is_some() {
        "symbol"
    } else {
        "data"
    };
    Pointee { location, kind, symbol, string, signed_value: None }
}
