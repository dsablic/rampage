//! Explicit, finite Sleigh code windows. This does not admit a native executable or assert a C ABI.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rampage_analysis::discover::{Program, discover};
use rampage_analysis::memory::Memory;
use rampage_arch::{DecodeGate, Disassembler, Flow, Insn};
use rampage_decompiler::sleigh_decode::{
    DecodeStatus, DecodedInstruction, InstructionFlow, PcodeOp, ProfileMetadata, SleighDecoder, Space, UnknownGate,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

pub const MAX_SLEIGH_WINDOW_BYTES: usize = 65_536;
pub const MAX_SLEIGH_DISCOVERY_BYTES: usize = 4096;
pub const MAX_SLEIGH_DECODE_ATTEMPTS: usize = 4096;
pub const MAX_SLEIGH_HANDLE_OPENS: usize = 128;
pub const MAX_SLEIGH_STOP_DIAGNOSTICS: usize = 256;
pub const MAX_SLEIGH_CACHE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SLEIGH_WINDOW_SEEDS: usize = 32;
pub const MAX_SLEIGH_WINDOW_INSTRUCTIONS: usize = 1000;
pub const MAX_SLEIGH_WINDOW_REPORT_BYTES: usize = 60_000;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SleighWindowRequest {
    /// Closed bundled language ID, not a path, architecture alias, compiler or ABI selection.
    pub profile: String,
    pub offset: FileOffset,
    /// Explicit original-file window: 1..=65536 bytes for listing, 1..=4096 for discovery.
    pub length: FileOffset,
    /// Internal code-space BYTE offset of the first selected byte, including word-addressed processors.
    pub base_address: FileOffset,
    /// Opt in to the existing recursive-descent discovery engine, restricted to this single window.
    #[serde(default)]
    pub discover: bool,
    /// Required only for discovery: 1..=32 explicit internal code-space byte addresses in the window.
    #[serde(default)]
    pub seeds: Vec<FileOffset>,
    /// 1..=1000 distinct decode addresses; default 256. Discovery exceeding this fails, not partial success.
    #[serde(default = "default_count")]
    pub instruction_limit: usize,
    /// Total decoder requests, including repeated discovery passes and cache hits; 1..=4096.
    #[serde(default = "default_decode_attempts")]
    pub decode_attempt_limit: usize,
    /// Native handle initialization attempts, including the initial profile validation; 1..=128.
    #[serde(default = "default_handle_opens")]
    pub handle_open_limit: usize,
    /// Address-sorted stop diagnostics, 1..=256; default 64, with explicit omission counts.
    #[serde(default = "default_stop_limit")]
    pub stop_limit: usize,
    /// Address-sorted listing page offset. Does not change discovery or reset the instruction budget.
    #[serde(default)]
    pub listing_offset: usize,
    /// 1..=1000 rows, default 256. P-code may require a much smaller page to fit the JSON budget.
    #[serde(default = "default_count")]
    pub listing_limit: usize,
    #[serde(default)]
    pub include_pcode: bool,
    /// Cooperative checks between decodes; the discovery engine and native calls are not interruptible.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_count() -> usize {
    256
}

fn default_timeout() -> u64 {
    10_000
}

fn default_decode_attempts() -> usize {
    MAX_SLEIGH_DECODE_ATTEMPTS
}

fn default_handle_opens() -> usize {
    MAX_SLEIGH_HANDLE_OPENS
}

fn default_stop_limit() -> usize {
    64
}

#[derive(Debug, Serialize)]
pub struct SleighSourceProfile {
    pub language_id: String,
    pub provenance: &'static str,
    pub mapping_validation: &'static str,
    pub abi: &'static str,
    pub code_space: u32,
    pub spaces: Vec<Space>,
    pub alignment_bytes: u32,
    pub required_parallel_helper: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SleighWindowRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub window_byte_offset: usize,
    pub source_byte_offset: u64,
    pub bytes: String,
    pub status: DecodeStatus,
    pub length: u32,
    pub translated_extent: u32,
    pub mnemonic: String,
    pub operand_text: String,
    pub flow: InstructionFlow,
    pub context_mediated_flow: bool,
    pub processor_helper_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_gate: Option<UnknownGate>,
    pub diagnostic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcode: Option<Vec<PcodeOp>>,
}

#[derive(Debug, Serialize)]
pub struct SleighWindowStop {
    pub profile: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub status: DecodeStatus,
    pub flow: InstructionFlow,
    pub context_mediated_flow: bool,
    pub processor_helper_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_gate: Option<UnknownGate>,
    pub reason: &'static str,
    pub diagnostic: Option<String>,
    pub backed_prefix_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SleighWindowCompletion {
    LinearWindowEnd,
    LinearInstructionLimit,
    LinearDecodeStopped,
    SeededDiscoveryFinished,
}

#[derive(Debug, Serialize)]
pub struct SleighWindowReport {
    pub file_path: PathBuf,
    pub source_size: u64,
    pub source_offset: u64,
    pub source_length: usize,
    pub source_range_sha256: String,
    pub source_range_sha256_after: String,
    pub source_observation: &'static str,
    pub source_coordinate_space: &'static str,
    pub profile: SleighSourceProfile,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end_address_exclusive: u64,
    pub code_coordinate_space: &'static str,
    pub discovery_requested: bool,
    pub discovery_coverage: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub seeds: Vec<u64>,
    /// The existing analysis engine's complete result, never a reconstructed parallel CFG.
    pub program: Option<Program>,
    pub completion: SleighWindowCompletion,
    pub instruction_limit: usize,
    pub decode_addresses_observed: usize,
    pub decode_attempt_limit: usize,
    pub decode_attempts: usize,
    pub native_decode_attempts: usize,
    pub retained_cache_bytes: usize,
    pub retained_cache_byte_limit: usize,
    pub handle_open_limit: usize,
    pub handle_open_attempts: usize,
    pub listing_offset: usize,
    pub listing_limit: usize,
    pub listing_total: usize,
    pub listing_omitted_before: usize,
    pub listing_omitted_after: usize,
    pub listing_next_offset: Option<usize>,
    pub rows: Vec<SleighWindowRow>,
    /// Bounded sidecar, independent of listing pagination. Unknown flow is not an invalid-opcode verdict.
    pub stops: Vec<SleighWindowStop>,
    pub stop_limit: usize,
    pub stops_total: usize,
    pub stops_omitted: usize,
    pub linear_consumed_bytes: Option<usize>,
    pub linear_remaining_bytes: Option<usize>,
    pub timeout_ms: u64,
    pub elapsed_ms: u128,
    pub cancellation: &'static str,
    pub limitations: Vec<&'static str>,
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn validate(request: &SleighWindowRequest) -> Result<(usize, u64, Vec<u64>), ApiError> {
    if !SleighDecoder::is_registered_profile(&request.profile) {
        return Err(invalid("unregistered Sleigh window profile; select a reviewed bundled language ID"));
    }
    let length = usize::try_from(request.length.0).map_err(|_| invalid("Sleigh window exceeds host width"))?;
    if !(1..=MAX_SLEIGH_WINDOW_BYTES).contains(&length) {
        return Err(invalid("Sleigh window length must be 1..=65536 bytes"));
    }
    if request.discover && length > MAX_SLEIGH_DISCOVERY_BYTES {
        return Err(invalid("Sleigh discovery window must contain at most 4096 bytes; listing permits 65536"));
    }
    if !(1..=MAX_SLEIGH_DECODE_ATTEMPTS).contains(&request.decode_attempt_limit)
        || !(1..=MAX_SLEIGH_HANDLE_OPENS).contains(&request.handle_open_limit)
        || !(1..=MAX_SLEIGH_STOP_DIAGNOSTICS).contains(&request.stop_limit)
    {
        return Err(invalid(
            "Sleigh work limits require decode_attempt_limit 1..=4096, \
            handle_open_limit 1..=128 and stop_limit 1..=256",
        ));
    }
    if !(1..=MAX_SLEIGH_WINDOW_INSTRUCTIONS).contains(&request.instruction_limit)
        || !(1..=MAX_SLEIGH_WINDOW_INSTRUCTIONS).contains(&request.listing_limit)
    {
        return Err(invalid("Sleigh instruction_limit and listing_limit must be 1..=1000"));
    }
    if !(1..=10_000).contains(&request.timeout_ms) {
        return Err(invalid("Sleigh timeout_ms must be 1..=10000"));
    }
    let base = request.base_address.0;
    let end = base.checked_add(length as u64).ok_or_else(|| invalid("Sleigh code window address overflows"))?;
    request.offset.0.checked_add(length as u64).ok_or_else(|| invalid("Sleigh source range overflows"))?;
    if request.seeds.len() > MAX_SLEIGH_WINDOW_SEEDS
        || (request.discover && request.seeds.is_empty())
        || (!request.discover && !request.seeds.is_empty())
    {
        return Err(invalid("Sleigh discovery requires 1..=32 explicit seeds; linear mode accepts no seeds"));
    }
    let mut seeds: Vec<u64> = request.seeds.iter().map(|seed| seed.0).collect();
    if seeds.iter().any(|seed| !(base..end).contains(seed)) {
        return Err(invalid("every Sleigh seed must be an internal byte address within the selected window"));
    }
    seeds.sort_unstable();
    seeds.dedup();
    Ok((length, end, seeds))
}

fn validate_profile_mapping(
    request: &SleighWindowRequest,
    end: u64,
    seeds: &[u64],
    metadata: &ProfileMetadata,
) -> Result<(), ApiError> {
    let alignment = u64::from(metadata.alignment_bytes);
    if metadata.profile != request.profile || alignment == 0 {
        return Err(invalid("Sleigh translator metadata does not match the selected profile"));
    }
    let code = metadata
        .spaces
        .iter()
        .find(|space| space.id == metadata.code_space)
        .ok_or_else(|| invalid("Sleigh metadata has no default code space"))?;
    if end - 1 > code.highest {
        return Err(invalid("Sleigh window exceeds the selected profile's internal code-space byte range"));
    }
    if !request.base_address.0.is_multiple_of(alignment) || seeds.iter().any(|seed| !seed.is_multiple_of(alignment)) {
        return Err(invalid("Sleigh base and seeds must satisfy the translator's actual byte alignment"));
    }
    Ok(())
}

/// An owned, single code-space source. It exposes neither pointer/data reads nor other Harvard spaces.
struct CodeWindow {
    base: u64,
    bytes: Vec<u8>,
}

impl Memory for CodeWindow {
    fn code_from(&self, address: u64) -> Option<&[u8]> {
        let offset = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.bytes.get(offset..).filter(|bytes| !bytes.is_empty())
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.code_from(address).is_some()
    }

    fn is_executable(&self, address: u64) -> bool {
        self.is_mapped(address)
    }

    fn immediates_may_be_addresses(&self) -> bool {
        false
    }
}

#[derive(Default)]
struct Observations {
    instructions: BTreeMap<u64, DecodedInstruction>,
    failure: Option<String>,
    work_stop_status: Option<DecodeStatus>,
    retained_bytes: usize,
    gates: BTreeMap<u64, DecodeGate>,
}

struct CappedCounter {
    written: usize,
    limit: usize,
}

impl Write for CappedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.written {
            return Err(io::Error::other("JSON byte budget exceeded"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fits_json_budget<T: Serialize + ?Sized>(value: &T, limit: usize) -> bool {
    serde_json::to_writer(CappedCounter { written: 0, limit }, value).is_ok()
}

fn retained_instruction_bytes(instruction: &DecodedInstruction) -> usize {
    std::mem::size_of::<DecodedInstruction>()
        + instruction.profile.capacity()
        + instruction.mnemonic.capacity()
        + instruction.operand_text.capacity()
        + instruction.diagnostic.as_ref().map_or(0, String::capacity)
        + instruction.unknown_gate.as_ref().map_or(0, |gate| gate.profile.capacity())
        + instruction.spaces.capacity() * std::mem::size_of::<Space>()
        + instruction.spaces.iter().map(|space| space.name.capacity()).sum::<usize>()
        + instruction.pcode.capacity() * std::mem::size_of::<PcodeOp>()
        + instruction
            .pcode
            .iter()
            .map(|op| {
                op.name.capacity()
                    + op.inputs.capacity() * std::mem::size_of::<rampage_decompiler::sleigh_decode::Varnode>()
            })
            .sum::<usize>()
}

#[derive(Clone)]
struct InstructionObservation {
    status: DecodeStatus,
    length: u32,
    instruction: Insn,
    mnemonic: String,
    operand_text: String,
    gate: Option<DecodeGate>,
}

impl From<&DecodedInstruction> for InstructionObservation {
    fn from(decoded: &DecodedInstruction) -> Self {
        Self {
            status: decoded.status,
            length: decoded.length,
            instruction: analysis_instruction(decoded),
            mnemonic: decoded.mnemonic.clone(),
            operand_text: decoded.operand_text.clone(),
            gate: None,
        }
    }
}

type SharedObservations = Arc<Mutex<Observations>>;

#[derive(Default)]
struct WorkCounters {
    decode_attempts: AtomicUsize,
    native_decode_attempts: AtomicUsize,
    handle_open_attempts: AtomicUsize,
}

fn charge(counter: &AtomicUsize, limit: usize) -> bool {
    counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| (count < limit).then_some(count + 1)).is_ok()
}

fn work_budget_failure(kind: &str, counters: &WorkCounters, request: &SleighWindowRequest) -> String {
    format!(
        "Sleigh work budget exceeded ({kind}); decode_attempts={}/{}, handle_open_attempts={}/{}; \
         conservative stop, function coverage inexact; entire program discarded, not an invalid-opcode verdict",
        counters.decode_attempts.load(Ordering::Relaxed),
        request.decode_attempt_limit,
        counters.handle_open_attempts.load(Ordering::Relaxed),
        request.handle_open_limit,
    )
}

struct DiscoveryDecoder {
    decoder: Option<SleighDecoder>,
    observations: SharedObservations,
    instruction_limit: usize,
    started: Instant,
    timeout: Duration,
    retain_pcode: bool,
    work: Arc<WorkCounters>,
    decode_attempt_limit: usize,
    handle_open_limit: usize,
    last_gate: Option<DecodeGate>,
}

impl DiscoveryDecoder {
    fn observation(&mut self, bytes: &[u8], address: u64) -> Option<InstructionObservation> {
        let mut state = self.observations.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.failure.is_some() {
            return None;
        }
        if !charge(&self.work.decode_attempts, self.decode_attempt_limit) {
            state.work_stop_status = Some(DecodeStatus::BudgetExceeded);
            state.failure = Some(format!(
                "Sleigh work budget exceeded (total decode attempts) at {address:#x}; \
                 decode_attempts={}/{}, handle_open_attempts={}/{}; \
                 conservative stop, function coverage inexact; entire program discarded, \
                 not an invalid-opcode verdict",
                self.work.decode_attempts.load(Ordering::Relaxed),
                self.decode_attempt_limit,
                self.work.handle_open_attempts.load(Ordering::Relaxed),
                self.handle_open_limit,
            ));
            return None;
        }
        if self.started.elapsed() >= self.timeout {
            state.failure = Some("Sleigh analysis cooperative deadline exceeded; no partial program returned".into());
            return None;
        }
        if let Some(instruction) = state.instructions.get(&address) {
            let mut observation = InstructionObservation::from(instruction);
            observation.gate = state.gates.get(&address).copied();
            return Some(observation);
        }
        if state.instructions.len() >= self.instruction_limit {
            state.work_stop_status = Some(DecodeStatus::BudgetExceeded);
            state.failure = Some(format!(
                "Sleigh discovery instruction budget exceeded at {address:#x}; observed={}/{}; \
                 decode_attempts={}/{}, handle_open_attempts={}/{}; entire program discarded, \
                 not an invalid-opcode verdict",
                state.instructions.len(),
                self.instruction_limit,
                self.work.decode_attempts.load(Ordering::Relaxed),
                self.decode_attempt_limit,
                self.work.handle_open_attempts.load(Ordering::Relaxed),
                self.handle_open_limit,
            ));
            return None;
        }
        let Some(decoder) = self.decoder.as_mut() else {
            state.failure = Some("Sleigh discovery decoder initialization failed".into());
            return None;
        };
        self.work.native_decode_attempts.fetch_add(1, Ordering::Relaxed);
        let mut instruction = decoder.decode_instruction(bytes, address);
        let gate = decoder.decode_gate();
        if instruction.status == DecodeStatus::Valid
            && matches!(instruction.flow, InstructionFlow::Unknown { .. })
            && !gate.is_some_and(|gate| gate.address == address && gate.profile == instruction.profile.as_str())
        {
            state.failure = Some(format!(
                "Sleigh valid unknown flow at {address:#x} lacks its production discovery gate; \
                 integration prerequisite unavailable, entire program discarded"
            ));
            return None;
        }
        if matches!(instruction.status, DecodeStatus::BudgetExceeded | DecodeStatus::InternalError) {
            state.failure =
                Some(format!("Sleigh decoder failed: {:?}: {:?}", instruction.status, instruction.diagnostic));
            return None;
        }
        if instruction.status == DecodeStatus::Valid
            && (instruction.length == 0 || instruction.length as usize > bytes.len() || instruction.length > 255)
        {
            state.failure =
                Some("Sleigh decoder returned an inconsistent or unrepresentable instruction length".into());
            return None;
        }
        if !self.retain_pcode {
            instruction.pcode = Vec::new();
        }
        let retained = retained_instruction_bytes(&instruction)
            + gate.map_or(0, |_| std::mem::size_of::<DecodeGate>() + std::mem::size_of::<u64>());
        if retained > MAX_SLEIGH_CACHE_BYTES - state.retained_bytes {
            state.work_stop_status = Some(DecodeStatus::BudgetExceeded);
            state.failure = Some(format!(
                "Sleigh retained cache budget exceeded at {address:#x}; retained_bytes={}, limit={}; \
                 entire program discarded, not an invalid-opcode verdict",
                state.retained_bytes, MAX_SLEIGH_CACHE_BYTES,
            ));
            return None;
        }
        state.retained_bytes += retained;
        let mut observation = InstructionObservation::from(&instruction);
        observation.gate = gate;
        if let Some(gate) = gate {
            state.gates.insert(address, gate);
        }
        state.instructions.insert(address, instruction);
        Some(observation)
    }
}

fn analysis_instruction(decoded: &DecodedInstruction) -> Insn {
    // Classification is exclusively the bridge's conservative p-code classification, not assembly parsing.
    let flow = match decoded.flow {
        InstructionFlow::Next => Flow::Next,
        InstructionFlow::Branch { target } => Flow::Jump(target),
        InstructionFlow::ConditionalBranch { target } => Flow::ConditionalJump(target),
        InstructionFlow::DirectCall { target } => Flow::Call(target),
        InstructionFlow::IndirectBranch => Flow::IndirectJump,
        InstructionFlow::IndirectCall => Flow::IndirectCall,
        InstructionFlow::Return => Flow::Return,
        InstructionFlow::Unknown { .. } => Flow::Invalid,
    };
    Insn {
        address: decoded.address,
        len: decoded.length as u8,
        flow,
        data_ref: None,
        accesses: false,
        immediate: None,
        conditional: false,
    }
}

impl Disassembler for DiscoveryDecoder {
    fn decode_gate(&self) -> Option<DecodeGate> {
        self.last_gate
    }

    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        self.last_gate = None;
        let observation = self.observation(bytes, address);
        self.last_gate = observation.as_ref().and_then(|observation| observation.gate);
        observation.map(|observation| observation.instruction).unwrap_or(Insn {
            address,
            len: 0,
            flow: Flow::Invalid,
            data_ref: None,
            accesses: false,
            immediate: None,
            conditional: false,
        })
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        self.last_gate = None;
        self.observation(bytes, address)
            .map(|instruction| format!("{} {}", instruction.mnemonic, instruction.operand_text))
            .unwrap_or_default()
    }

    fn reset(&mut self) {
        self.last_gate = None;
    }
}

fn open_discovery_decoder<F>(
    request: &SleighWindowRequest,
    observations: &SharedObservations,
    work: &WorkCounters,
    started: Instant,
    open: F,
) -> Option<SleighDecoder>
where
    F: FnOnce() -> Result<SleighDecoder, rampage_decompiler::Error>,
{
    // Native admission and terminal failure publication share this guard. Both open and decode use
    // observations -> FFI_LOCK; no native operation acquires observations while holding FFI_LOCK.
    let mut state = observations.lock().unwrap_or_else(|poison| poison.into_inner());
    if state.failure.is_some() {
        return None;
    }
    if started.elapsed() >= Duration::from_millis(request.timeout_ms) {
        state.failure =
            Some("Sleigh analysis cooperative deadline exceeded before handle open; program discarded".into());
        return None;
    }
    if !charge(&work.handle_open_attempts, request.handle_open_limit) {
        state.work_stop_status = Some(DecodeStatus::BudgetExceeded);
        state.failure = Some(work_budget_failure("native handle opens", work, request));
        return None;
    }
    match open() {
        Ok(decoder) => Some(decoder),
        Err(error) => {
            state.failure =
                Some(format!("Sleigh discovery decoder initialization failed: {error}; entire program discarded"));
            None
        }
    }
}

fn seeded_discovery<F>(
    memory: &CodeWindow,
    request: &SleighWindowRequest,
    seeds: &[u64],
    observations: &SharedObservations,
    work: &Arc<WorkCounters>,
    started: Instant,
    open: F,
) -> Result<Program, ApiError>
where
    F: Fn() -> Result<SleighDecoder, rampage_decompiler::Error> + Sync,
{
    let program = discover(
        memory,
        || {
            let decoder = open_discovery_decoder(request, observations, work, started, &open);
            Box::new(DiscoveryDecoder {
                decoder,
                observations: Arc::clone(observations),
                instruction_limit: request.instruction_limit,
                started,
                timeout: Duration::from_millis(request.timeout_ms),
                retain_pcode: request.include_pcode,
                work: Arc::clone(work),
                decode_attempt_limit: request.decode_attempt_limit,
                handle_open_limit: request.handle_open_limit,
                last_gate: None,
            }) as Box<dyn Disassembler>
        },
        seeds,
    );
    check_completion(observations, started, request.timeout_ms)?;
    Ok(program)
}

fn check_completion(state: &SharedObservations, started: Instant, timeout_ms: u64) -> Result<(), ApiError> {
    let state = state.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(message) = &state.failure {
        return Err(match state.work_stop_status {
            Some(status) => invalid(&format!("{status:?}: {message}")),
            None => invalid(message),
        });
    }
    if started.elapsed() >= Duration::from_millis(timeout_ms) {
        return Err(invalid("Sleigh analysis cooperative deadline exceeded; no partial program returned"));
    }
    Ok(())
}

fn verify_source_after(source: &RangeSource, before_hash: &str) -> Result<String, ApiError> {
    source.revalidate()?;
    let after_hash = rampage_arch::hex::bytes(&Sha256::digest(source.read()?));
    source.revalidate()?;
    if before_hash != after_hash {
        return Err(invalid("Sleigh source range bytes changed during observation"));
    }
    Ok(after_hash)
}

/// Read-only inspection of one explicit regular-file range with an asserted bundled profile and code base.
/// No Binary, Project, native Arch admission, ABI claim, extraction, annotation or target execution is involved.
pub fn inspect_sleigh_file_range(path: &Path, request: &SleighWindowRequest) -> Result<SleighWindowReport, ApiError> {
    let (length, end, seeds) = validate(request)?;
    if !fits_json_budget(path, 4096) {
        return Err(invalid("Sleigh source path exceeds receipt budget"));
    }
    let source = RangeSource::open(path, request.offset.0, length)?;
    let memory = CodeWindow { base: request.base_address.0, bytes: source.read()? };
    source.revalidate()?;
    let before_hash = rampage_arch::hex::bytes(&Sha256::digest(&memory.bytes));
    let started = Instant::now();
    let work = Arc::new(WorkCounters::default());
    if !charge(&work.handle_open_attempts, request.handle_open_limit) {
        return Err(invalid(&work_budget_failure("initial native handle open", &work, request)));
    }
    // Validate the profile and verified bundled context before constructing discover's infallible factory.
    let decoder = SleighDecoder::open(&request.profile)
        .map_err(|error| ApiError::Unavailable(format!("Sleigh profile could not be opened: {error}")))?;
    let metadata = decoder.metadata().clone();
    validate_profile_mapping(request, end, &seeds, &metadata)?;
    let observations = Arc::new(Mutex::new(Observations::default()));
    let mut initial = DiscoveryDecoder {
        decoder: Some(decoder),
        observations: Arc::clone(&observations),
        instruction_limit: request.instruction_limit,
        started,
        timeout: Duration::from_millis(request.timeout_ms),
        retain_pcode: request.include_pcode,
        work: Arc::clone(&work),
        decode_attempt_limit: request.decode_attempt_limit,
        handle_open_limit: request.handle_open_limit,
        last_gate: None,
    };
    let profile = SleighSourceProfile {
        language_id: request.profile.clone(),
        provenance: "closed_registry_verified_bundled_sla_and_processor_defaults",
        mapping_validation: "analyst_asserted_code_window_not_native_executable_admission",
        abi: "unknown_not_asserted_no_compiler_specification_or_c_decompilation",
        code_space: metadata.code_space,
        spaces: metadata.spaces,
        alignment_bytes: metadata.alignment_bytes,
        required_parallel_helper: metadata.required_parallel_helper,
    };
    let mut consumed = 0;
    let (program, completion) = if request.discover {
        drop(initial);
        let program = seeded_discovery(&memory, request, &seeds, &observations, &work, started, || {
            SleighDecoder::open(&request.profile)
        })?;
        (Some(program), SleighWindowCompletion::SeededDiscoveryFinished)
    } else {
        let completion = loop {
            if consumed == memory.bytes.len() {
                break SleighWindowCompletion::LinearWindowEnd;
            }
            if observations.lock().unwrap_or_else(|poison| poison.into_inner()).instructions.len()
                == request.instruction_limit
            {
                break SleighWindowCompletion::LinearInstructionLimit;
            }
            let instruction = initial.observation(&memory.bytes[consumed..], memory.base + consumed as u64);
            check_completion(&observations, started, request.timeout_ms)?;
            let instruction = instruction.ok_or_else(|| invalid("Sleigh instruction observation unavailable"))?;
            if instruction.status != DecodeStatus::Valid {
                break SleighWindowCompletion::LinearDecodeStopped;
            }
            consumed += instruction.length as usize;
        };
        (None, completion)
    };
    check_completion(&observations, started, request.timeout_ms)?;
    let after_hash = verify_source_after(&source, &before_hash)?;
    let mut state = observations.lock().unwrap_or_else(|poison| poison.into_inner());
    let retained_cache_bytes = state.retained_bytes;
    let instructions = std::mem::take(&mut state.instructions);
    drop(state);
    let listing_total = instructions.len();
    if request.listing_offset > listing_total {
        return Err(invalid("Sleigh listing_offset is outside the complete address-sorted observation set"));
    }
    let mut stops_total = 0;
    let stops: Vec<_> = instructions
        .values()
        .filter_map(|instruction| {
            let reason = if instruction.status != DecodeStatus::Valid {
                "decode_stopped_status_not_valid"
            } else if matches!(instruction.flow, InstructionFlow::Unknown { .. }) {
                "conservative_unknown_flow_not_invalid_opcode"
            } else if matches!(instruction.flow, InstructionFlow::IndirectBranch) {
                "unresolved_indirect_branch"
            } else if matches!(instruction.flow,
            InstructionFlow::Branch { target }
            | InstructionFlow::ConditionalBranch { target }
            | InstructionFlow::DirectCall { target } if !memory.is_executable(target))
            {
                "direct_target_outside_window_not_followed"
            } else {
                return None;
            };
            let backed = memory.code_from(instruction.address).unwrap_or_default();
            stops_total += 1;
            if stops_total > request.stop_limit {
                return None;
            }
            Some(SleighWindowStop {
                profile: instruction.profile.clone(),
                address: instruction.address,
                status: instruction.status,
                flow: instruction.flow.clone(),
                context_mediated_flow: instruction.context_mediated_flow,
                processor_helper_required: instruction.processor_helper_required,
                unknown_gate: instruction.unknown_gate.clone(),
                reason,
                diagnostic: instruction.diagnostic.clone(),
                backed_prefix_hex: rampage_arch::hex::bytes(&backed[..backed.len().min(16)]),
            })
        })
        .collect();
    // Consume the cache: unselected records are dropped and selected strings/p-code are moved, not cloned.
    let rows: Vec<_> = instructions
        .into_values()
        .enumerate()
        .filter_map(|(index, instruction)| {
            if index < request.listing_offset || index - request.listing_offset >= request.listing_limit {
                return None;
            }
            let offset = (instruction.address - memory.base) as usize;
            let available_length = (instruction.length as usize).min(memory.bytes.len() - offset);
            Some(SleighWindowRow {
                address: instruction.address,
                window_byte_offset: offset,
                source_byte_offset: request.offset.0 + offset as u64,
                bytes: rampage_arch::hex::bytes(&memory.bytes[offset..offset + available_length]),
                status: instruction.status,
                length: instruction.length,
                translated_extent: instruction.translated_extent,
                mnemonic: instruction.mnemonic,
                operand_text: instruction.operand_text,
                flow: instruction.flow,
                context_mediated_flow: instruction.context_mediated_flow,
                processor_helper_required: instruction.processor_helper_required,
                unknown_gate: instruction.unknown_gate,
                diagnostic: instruction.diagnostic,
                pcode: request.include_pcode.then_some(instruction.pcode),
            })
        })
        .collect();
    let listing_end = request.listing_offset + rows.len();
    let report = SleighWindowReport {
        file_path: path.to_owned(),
        source_size: source.size(),
        source_offset: request.offset.0,
        source_length: length,
        source_range_sha256: before_hash,
        source_range_sha256_after: after_hash,
        source_observation: "revalidated_descriptor_and_path_non_atomic_range_read_before_and_after",
        source_coordinate_space: "original_file_byte_offset",
        profile,
        base_address: memory.base,
        end_address_exclusive: end,
        code_coordinate_space: "sleigh_internal_code_space_byte_offset_not_display_word_address",
        discovery_requested: request.discover,
        discovery_coverage: "seed_reachable_conservative_stops_not_complete_function_or_control_flow_coverage",
        seeds,
        program,
        completion,
        instruction_limit: request.instruction_limit,
        decode_addresses_observed: listing_total,
        decode_attempt_limit: request.decode_attempt_limit,
        decode_attempts: work.decode_attempts.load(Ordering::Relaxed),
        native_decode_attempts: work.native_decode_attempts.load(Ordering::Relaxed),
        retained_cache_bytes,
        retained_cache_byte_limit: MAX_SLEIGH_CACHE_BYTES,
        handle_open_limit: request.handle_open_limit,
        handle_open_attempts: work.handle_open_attempts.load(Ordering::Relaxed),
        listing_offset: request.listing_offset,
        listing_limit: request.listing_limit,
        listing_total,
        listing_omitted_before: request.listing_offset,
        listing_omitted_after: listing_total - listing_end,
        listing_next_offset: (listing_end < listing_total).then_some(listing_end),
        rows,
        stops_omitted: stops_total - stops.len(),
        stops,
        stops_total,
        stop_limit: request.stop_limit,
        linear_consumed_bytes: (!request.discover).then_some(consumed),
        linear_remaining_bytes: (!request.discover).then_some(length - consumed),
        timeout_ms: request.timeout_ms,
        elapsed_ms: started.elapsed().as_millis(),
        cancellation: "cooperative_between_decodes_native_calls_and_discovery_not_interruptible",
        limitations: vec![
            "Explicit windows support the 16 closed selected processor profiles plus existing x86/A64 bridge profiles. \
             This does not admit them through ordinary native-image Project loading or assert a full backend.",
            "Profile, base and seeds are analyst assertions. \
             No native executable admission, CPU guessing or ABI proof.",
            "Code-space offsets are internal bytes. \
             Space word_size is descriptive; never multiply these offsets again.",
            "Only selected regular-file bytes are owned. No data-space reads, runtime memory, zero fill or extraction.",
            "Range hashes before/after and metadata revalidation are non-atomic observations, \
             not source authentication.",
            "Discovery uses the existing Program engine and follows only code backed by this window; no prologue scan.",
            "Functions and xrefs are conservative decoder evidence, not execution or complete code coverage.",
            "Direct xrefs may name outside targets; those targets are not followed. \
             Indirect targets remain unresolved.",
            "Unknown p-code flow stops discovery and is retained separately; it is not an invalid-opcode verdict.",
            "Listing pages and stop diagnostics are address sorted; omitted diagnostics are explicitly counted.",
            "Discovery windows are at most 4096 bytes; listing allows 65536. \
             Total decoder requests and native handle initialization attempts have separate shared budgets.",
            "Budget exhaustion rejects the entire report, \
             never publishing a partial Program or invalid-opcode verdict.",
            "Program is the unabridged engine result, not a claim that all functions or control-flow edges were found.",
            "Linear mode explicitly treats the supplied window as code, even after returns; no targets are followed.",
            "Assembly operands are display text, not typed operand evidence. \
             P-code is opt-in and may force smaller pages.",
            "The JSON output cap is separate from the 8 MiB decoded-cache capacity-accounting cap. \
             Cache accounting includes retained records, vectors and strings, not allocator/BTree/native overhead; \
             those have separate fixed record, instruction and native-handle count limits.",
            "Discovery and native calls cannot be forcibly interrupted; deadlines are checked cooperatively.",
            "No C decompilation, compiler specification, annotations, sidecars, \
             target execution or source publication.",
        ],
    };
    if !fits_json_budget(&report, MAX_SLEIGH_WINDOW_REPORT_BYTES) {
        return Err(invalid("Sleigh report exceeds 60000 JSON bytes; reduce listing_limit or narrow window/seeds"));
    }
    Ok(report)
}

#[cfg(test)]
#[path = "sleigh_window_tests.rs"]
mod tests;
