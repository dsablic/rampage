//! Bounded, standalone instruction decoding through the pinned bundled Sleigh engine.
//! Assembly operands are display text, not typed operand evidence. Offsets are Ghidra's internal byte
//! offsets; `word_size` describes display address units and must not be applied to these offsets again.

use std::ffi::{CStr, CString, c_char, c_void};

use rampage_arch::{Arch, Disassembler, Flow, Insn, Target};
use serde::Serialize;

use crate::{Error, FFI_LOCK, context};

pub const MAX_WINDOW_BYTES: usize = 65_536;
const MAX_OPS: usize = 128;
const MAX_INPUTS: usize = 16;
const MAX_SPACES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeStatus {
    Valid,
    Invalid,
    Truncated,
    Unavailable,
    UnimplementedPcode,
    BudgetExceeded,
    InternalError,
    /// Padding was needed for lookahead and no instruction was resolved: neither verdict is proven.
    InvalidOrTruncated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Space {
    /// Identity within this decoder's translator, not a native pointer or a cross-profile identifier.
    pub id: u32,
    pub name: String,
    pub kind: u32,
    pub address_size: u32,
    pub word_size: u32,
    pub highest: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Varnode {
    pub space: u32,
    pub size: u32,
    pub address_size: u32,
    pub word_size: u32,
    /// Absent for LOAD/STORE space selectors, whose native offset encodes an engine pointer.
    pub offset: Option<u64>,
    pub selected_space: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PcodeOp {
    pub opcode: u32,
    pub name: String,
    pub address: u64,
    pub output: Option<Varnode>,
    pub inputs: Vec<Varnode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownFlow {
    IncompletePcode,
    InternalPcodeBranch,
    MultipleExits,
    UnsupportedTargetSpace,
    UserDefinedOperation,
    DelaySlotAggregation,
    MalformedPcode,
    ContextMediatedFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownGate {
    pub profile: String,
    pub address: u64,
    pub reason: UnknownFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstructionFlow {
    Next,
    Branch { target: u64 },
    ConditionalBranch { target: u64 },
    DirectCall { target: u64 },
    IndirectBranch,
    IndirectCall,
    Return,
    Unknown { reason: UnknownFlow },
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInstruction {
    pub profile: String,
    pub address: u64,
    pub status: DecodeStatus,
    pub length: u32,
    /// `oneInstruction` may include delay-slot instructions. Such aggregation has unknown flow here.
    pub translated_extent: u32,
    pub mnemonic: String,
    pub operand_text: String,
    pub flow: InstructionFlow,
    pub code_space: u32,
    pub spaces: Vec<Space>,
    pub pcode: Vec<PcodeOp>,
    /// A pending global context commit was observed before `allowContextSet(false)` suppressed storage.
    pub context_mediated_flow: bool,
    /// Valid instruction with unsupported flow: a conservative discovery stop, not an invalid opcode.
    pub unknown_gate: Option<UnknownGate>,
    pub diagnostic: Option<String>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSpace {
    id: u32,
    kind: u32,
    address_size: u32,
    word_size: u32,
    highest: u64,
    name: [c_char; 64],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeNode {
    space: u32,
    size: u32,
    offset: u64,
    selector: u32,
    selector_space: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeOp {
    opcode: u32,
    input_count: u32,
    has_output: u32,
    name: [c_char; 32],
    address: u64,
    output: NativeNode,
    inputs: [NativeNode; MAX_INPUTS],
}

#[repr(C)]
struct NativeResult {
    status: u32,
    length: u32,
    extent: u32,
    op_count: u32,
    space_count: u32,
    code_space: u32,
    context_mediated_flow: u32,
    mnemonic: [c_char; 256],
    operands: [c_char; 3840],
    error: [c_char; 256],
    spaces: [NativeSpace; MAX_SPACES],
    ops: [NativeOp; MAX_OPS],
}

unsafe extern "C" {
    fn rampage_sleigh_result_size() -> usize;
    fn rampage_sleigh_open(home: *const c_char, sla: *const c_char, pspec: *const c_char) -> *mut c_void;
    fn rampage_sleigh_error(handle: *mut c_void) -> *const c_char;
    fn rampage_sleigh_decode(handle: *mut c_void, base: u64, bytes: *const u8, size: usize, result: *mut NativeResult);
    fn rampage_sleigh_close(handle: *mut c_void);
    #[cfg(test)]
    fn rampage_sleigh_test_loader_isolation(handle: *mut c_void) -> u8;
    #[cfg(test)]
    fn rampage_sleigh_test_parser_read(start: i32, size: i32, offset: u32, bits: u8, output: *mut u32) -> u8;
}

// Closed selectors: adding a profile requires a reviewed bundled asset and its processor defaults.
fn registered_profile(profile: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match profile {
        "x86:LE:32:default" => Some(("x86", "x86", "x86")),
        "x86:LE:64:default" => Some(("x86", "x86-64", "x86-64")),
        "AARCH64:LE:64:v8A" => Some(("AARCH64", "AARCH64", "AARCH64")),
        "AARCH64:BE:64:v8A" => Some(("AARCH64", "AARCH64BE", "AARCH64")),
        "TI_MSP430:LE:16:default" => Some(("TI_MSP430", "TI_MSP430", "TI_MSP430")),
        "avr8:LE:16:default" => Some(("Atmel", "avr8", "avr8")),
        "6502:LE:16:default" => Some(("6502", "6502", "6502")),
        _ => None,
    }
}

/// One profile, reused across bounded windows. Every decode rebinds bytes/base and clears translation caches.
/// This does not admit decompilation, ABI/type layouts, executable discovery, or external specification paths.
pub struct SleighDecoder {
    handle: *mut c_void,
    profile: String,
    last_unknown_gate: Option<UnknownGate>,
}

// SAFETY: every native operation, including destruction, holds the process-wide FFI_LOCK.
unsafe impl Send for SleighDecoder {}

impl SleighDecoder {
    /// Selects a reviewed language's SLA and processor defaults, never arbitrary ldefs siblings.
    /// This decoder does not load a compiler specification or assert a C ABI, including for 6502.
    pub fn open(profile: &str) -> Result<Self, Error> {
        let (family, sla_file, pspec_file) = registered_profile(profile)
            .ok_or_else(|| Error::Ghidra("unregistered bundled decoder profile".to_owned()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: this reads only the shim's compile-time record size under the native serialization lock.
        if unsafe { rampage_sleigh_result_size() } != std::mem::size_of::<NativeResult>() {
            return Err(Error::Ghidra("instruction decoder ABI record size mismatch".to_owned()));
        }
        let proof = context::require_verified_bundled_native_context_locked()?;
        let home_path = proof.home();
        let directory = home_path.join("Ghidra/Processors").join(family).join("data/languages");
        let text = |path: &std::path::Path| {
            CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| Error::Ghidra("invalid bundled decoder path".to_owned()))
        };
        let home = text(home_path)?;
        let sla = text(&directory.join(format!("{sla_file}.sla")))?;
        let pspec = text(&directory.join(format!("{pspec_file}.pspec")))?;
        let before = context::begin_native_attempt(home_path);
        // SAFETY: paths come only from the verified bundle and remain valid during initialization.
        let handle = unsafe { rampage_sleigh_open(home.as_ptr(), sla.as_ptr(), pspec.as_ptr()) };
        context::finish_native_attempt(before);
        if handle.is_null() {
            context::failed_native_attempt();
            return Err(Error::Ghidra("could not allocate instruction decoder".to_owned()));
        }
        // SAFETY: native error storage belongs to this live handle and is copied before destruction.
        let error = unsafe { rampage_sleigh_error(handle) };
        if !error.is_null() {
            let message = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            unsafe { rampage_sleigh_close(handle) };
            return Err(Error::Ghidra(message));
        }
        if let Err(error) = context::require_verified_bundled_native_context_locked() {
            // SAFETY: the native handle must not escape when the bundled context changed during initialization.
            unsafe { rampage_sleigh_close(handle) };
            return Err(error);
        }
        Ok(Self { handle, profile: profile.to_owned(), last_unknown_gate: None })
    }

    pub fn for_target(target: &Target) -> Result<Self, Error> {
        let profile = match (target.arch, target.big_endian) {
            (Arch::X86, false) => "x86:LE:32:default",
            (Arch::X86_64, false) => "x86:LE:64:default",
            (Arch::Aarch64, false) => "AARCH64:LE:64:v8A",
            (Arch::Aarch64, true) => "AARCH64:BE:64:v8A",
            _ => return Err(Error::UnsupportedArch(target.arch)),
        };
        Self::open(profile)
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The trait adapter uses `Flow::Invalid` as a STOP sentinel because the legacy trait has no unknown flow.
    /// Check this retained gate before calling that sentinel an invalid opcode. Independent windows use only
    /// profile-default incoming context; a gate forbids discovering a fall-through edge into the next window.
    pub fn last_unknown_gate(&self) -> Option<&UnknownGate> {
        self.last_unknown_gate.as_ref()
    }

    /// The supplied bytes are the entire backed executable window, with no implicit zero-fill mapping.
    pub fn decode_instruction(&mut self, bytes: &[u8], address: u64) -> DecodedInstruction {
        let mut output = Box::<NativeResult>::new_uninit();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: C initializes the complete fixed-size result, copies bounded input, and keeps no Rust pointers.
        unsafe {
            rampage_sleigh_decode(self.handle, address, bytes.as_ptr(), bytes.len(), output.as_mut_ptr());
        }
        let output = unsafe { output.assume_init() };
        let decoded = convert(&self.profile, address, &output);
        self.last_unknown_gate = decoded.unknown_gate.clone();
        decoded
    }
}

impl Drop for SleighDecoder {
    fn drop(&mut self) {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: this is the unique owning handle, serialized against all Ghidra entry points.
        unsafe { rampage_sleigh_close(self.handle) };
    }
}

fn text<const N: usize>(bytes: &[c_char; N]) -> String {
    let bytes: Vec<u8> = bytes.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn node(value: NativeNode, spaces: &[Space]) -> Varnode {
    let space = spaces.iter().find(|space| space.id == value.space);
    Varnode {
        space: value.space,
        size: value.size,
        address_size: space.map_or(0, |space| space.address_size),
        word_size: space.map_or(0, |space| space.word_size),
        offset: (value.selector == 0).then_some(value.offset),
        selected_space: (value.selector != 0).then_some(value.selector_space),
    }
}

fn convert(profile: &str, address: u64, value: &NativeResult) -> DecodedInstruction {
    if value.op_count as usize > MAX_OPS
        || value.space_count as usize > MAX_SPACES
        || value.status > 7
        || value.context_mediated_flow > 1
        || value.ops[..value.op_count as usize]
            .iter()
            .any(|op| op.input_count as usize > MAX_INPUTS || op.has_output > 1)
    {
        return malformed_record(profile, address);
    }
    let status = match value.status {
        0 => DecodeStatus::Valid,
        1 => DecodeStatus::Invalid,
        2 => DecodeStatus::Truncated,
        3 => DecodeStatus::Unavailable,
        4 => DecodeStatus::UnimplementedPcode,
        5 => DecodeStatus::BudgetExceeded,
        7 => DecodeStatus::InvalidOrTruncated,
        _ => DecodeStatus::InternalError,
    };
    let spaces = value.spaces[..value.space_count as usize]
        .iter()
        .filter(|space| space.address_size != 0)
        .map(|space| Space {
            id: space.id,
            name: text(&space.name),
            kind: space.kind,
            address_size: space.address_size,
            word_size: space.word_size,
            highest: space.highest,
        })
        .collect::<Vec<_>>();
    let pcode = value.ops[..value.op_count as usize]
        .iter()
        .map(|op| PcodeOp {
            opcode: op.opcode,
            name: text(&op.name),
            address: op.address,
            output: (op.has_output != 0).then(|| node(op.output, &spaces)),
            inputs: op.inputs[..op.input_count as usize].iter().copied().map(|value| node(value, &spaces)).collect(),
        })
        .collect::<Vec<_>>();
    let flow = if status == DecodeStatus::Valid && value.context_mediated_flow != 0 {
        InstructionFlow::Unknown { reason: UnknownFlow::ContextMediatedFlow }
    } else {
        classify(status, value.length, value.extent, value.code_space, &spaces, &pcode)
    };
    let unknown_gate = match (&flow, status) {
        (InstructionFlow::Unknown { reason }, DecodeStatus::Valid) => {
            Some(UnknownGate { profile: profile.to_owned(), address, reason: *reason })
        }
        _ => None,
    };
    let diagnostic = text(&value.error);
    let diagnostic = if diagnostic.is_empty() {
        unknown_gate.as_ref().map(|gate| format!("conservative instruction-flow gate: {:?}", gate.reason))
    } else {
        Some(diagnostic)
    };
    DecodedInstruction {
        profile: profile.to_owned(),
        address,
        status,
        length: value.length,
        translated_extent: value.extent,
        mnemonic: text(&value.mnemonic),
        operand_text: text(&value.operands),
        flow,
        code_space: value.code_space,
        spaces,
        pcode,
        context_mediated_flow: value.context_mediated_flow != 0,
        unknown_gate,
        diagnostic,
    }
}

fn malformed_record(profile: &str, address: u64) -> DecodedInstruction {
    DecodedInstruction {
        profile: profile.to_owned(),
        address,
        status: DecodeStatus::InternalError,
        length: 0,
        translated_extent: 0,
        mnemonic: String::new(),
        operand_text: String::new(),
        flow: InstructionFlow::Unknown { reason: UnknownFlow::MalformedPcode },
        code_space: 0,
        spaces: Vec::new(),
        pcode: Vec::new(),
        context_mediated_flow: false,
        unknown_gate: None,
        diagnostic: Some("malformed native instruction decoder record".to_owned()),
    }
}

fn classify(
    status: DecodeStatus,
    length: u32,
    extent: u32,
    code_space: u32,
    spaces: &[Space],
    pcode: &[PcodeOp],
) -> InstructionFlow {
    let unknown = |reason| InstructionFlow::Unknown { reason };
    if status != DecodeStatus::Valid {
        return unknown(UnknownFlow::IncompletePcode);
    }
    if length != extent {
        return unknown(UnknownFlow::DelaySlotAggregation);
    }
    let branches: Vec<_> = pcode.iter().filter(|op| matches!(op.opcode, 4..=8 | 10)).collect();
    if branches.len() > 1 {
        return unknown(UnknownFlow::MultipleExits);
    }
    if pcode.iter().any(|op| op.opcode == 9) {
        return unknown(UnknownFlow::UserDefinedOperation);
    }
    let Some(branch) = branches.first() else { return InstructionFlow::Next };
    if branch.inputs.is_empty() {
        return unknown(UnknownFlow::MalformedPcode);
    }
    match branch.opcode {
        6 => InstructionFlow::IndirectBranch,
        8 => InstructionFlow::IndirectCall,
        10 => InstructionFlow::Return,
        4 | 5 | 7 => {
            let target = &branch.inputs[0];
            let Some(space) = spaces.iter().find(|space| space.id == target.space) else {
                return unknown(UnknownFlow::MalformedPcode);
            };
            // Constant-space branch offsets are relative p-code operation indices, never machine addresses.
            if space.kind == 0 {
                return unknown(UnknownFlow::InternalPcodeBranch);
            }
            if target.space != code_space || target.selected_space.is_some() {
                return unknown(UnknownFlow::UnsupportedTargetSpace);
            }
            let Some(target) = target.offset.filter(|offset| *offset <= space.highest) else {
                return unknown(UnknownFlow::MalformedPcode);
            };
            match branch.opcode {
                4 => InstructionFlow::Branch { target },
                5 => InstructionFlow::ConditionalBranch { target },
                _ => InstructionFlow::DirectCall { target },
            }
        }
        _ => unknown(UnknownFlow::MalformedPcode),
    }
}

impl Disassembler for SleighDecoder {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        let decoded = self.decode_instruction(&bytes[..bytes.len().min(MAX_WINDOW_BYTES)], address);
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
            address,
            len: u8::try_from(decoded.length).unwrap_or(0),
            flow,
            data_ref: None,
            accesses: false,
            immediate: None,
            conditional: false,
        }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let decoded = self.decode_instruction(&bytes[..bytes.len().min(MAX_WINDOW_BYTES)], address);
        if decoded.operand_text.is_empty() {
            decoded.mnemonic
        } else {
            format!("{} {}", decoded.mnemonic, decoded.operand_text)
        }
    }
}

#[cfg(test)]
#[path = "sleigh_decode_oracle.rs"]
mod oracle_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avr_skip_context_commits_are_unknown_and_do_not_leak_across_windows() {
        let mut decoder = SleighDecoder::open("avr8:LE:16:default").expect("admitted AVR decoder");
        for bytes in [
            [0x01, 0x10, 0x00, 0x00], // CPSE R0,R1 followed by NOP
            [0x00, 0x99, 0x00, 0x00], // SBIC 0,0 followed by NOP
            [0x00, 0x9b, 0x00, 0x00], // SBIS 0,0 followed by NOP
            [0x00, 0xfc, 0x00, 0x00], // SBRC R0,0 followed by NOP
            [0x00, 0xfe, 0x00, 0x00], // SBRS R0,0 followed by NOP
        ] {
            let result = decoder.decode_instruction(&bytes, 0x1000);
            assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
            assert_eq!(result.length, 2);
            assert!(result.context_mediated_flow, "{result:?}");
            assert_eq!(result.flow, InstructionFlow::Unknown { reason: UnknownFlow::ContextMediatedFlow });
            let gate = result.unknown_gate.expect("valid unknown-flow gate");
            assert_eq!(gate.address, 0x1000);
            assert_eq!(gate.profile, "avr8:LE:16:default");
            assert_eq!(gate.reason, UnknownFlow::ContextMediatedFlow);
            assert_eq!(decoder.last_unknown_gate(), Some(&gate));
            assert!(result.diagnostic.is_some());
            let adapter = decoder.decode(&bytes, 0x1000);
            assert_eq!(adapter.flow, Flow::Invalid);
            assert_eq!(decoder.last_unknown_gate(), Some(&gate));
            // This fresh window has default incoming context; the gate above forbids assuming a connecting edge.
            let independent = decoder.decode_instruction(&[0, 0], 0x1002);
            assert_eq!(independent.flow, InstructionFlow::Next, "{independent:?}");
            assert!(!independent.context_mediated_flow);
            assert!(decoder.last_unknown_gate().is_none());
        }
        let rebound = decoder.decode_instruction(&[0, 0], 0x1000);
        assert_eq!(rebound.flow, InstructionFlow::Next);
    }

    #[test]
    fn parser_reads_zero_extend_partial_words_and_reject_invalid_ranges() {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let read = |start, size, offset, bits| {
            let mut output = 0;
            // SAFETY: the probe owns its 16-byte parser and writes only this valid scalar output.
            let status = unsafe { rampage_sleigh_test_parser_read(start, size, offset, bits, &mut output) };
            (status, output)
        };
        assert_eq!(read(0, 4, 13, 0), (0, 0x0e0f1000));
        assert_eq!(read(0, 4, 14, 0), (0, 0x0f100000));
        assert_eq!(read(0, 4, 15, 0), (0, 0x10000000));
        assert_eq!(read(0, 4, 12, 0), (0, 0x0d0e0f10));
        assert_eq!(read(0, 1, 15, 0), (0, 0x10));
        assert_eq!(read(1, 32, 0, 1), (0, 0x02040608));
        assert_eq!(read(1, 32, 13, 1), (0, 0x1c1e2000));
        assert_eq!(read(7, 32, 15, 1), (0, 0));
        assert_eq!(read(0, 8, 15, 1), (0, 0x10));
        for bits in [0, 1] {
            for (start, size, offset) in [
                (-1, 1, 0),
                (0, -1, 0),
                (0, 0, 0),
                (0, 1, 16),
                (0, 1, u32::MAX),
                (i32::MAX, 1, u32::MAX),
                (i32::MAX, i32::MAX, 15),
            ] {
                assert_eq!(read(start, size, offset, bits).0, 1, "{start}, {size}, {offset}, {bits}");
            }
        }
        assert_eq!(read(0, 5, 0, 0).0, 1);
        assert_eq!(read(0, 33, 0, 1).0, 1);
        assert_eq!(read(128, 1, 0, 1).0, 1);
    }

    #[test]
    fn repeated_x86_prefixes_cannot_read_past_parser_buffer() {
        let mut decoder = SleighDecoder::open("x86:LE:64:default").expect("verified bundled x86 decoder");
        for count in 12..=14 {
            let mut bytes = vec![0x2e; count];
            bytes.push(0x90);
            let result = decoder.decode_instruction(&bytes, 0x1000);
            assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
            assert_eq!(result.length as usize, bytes.len());
            assert_eq!(result.flow, InstructionFlow::Next, "{result:?}");
        }
        for count in 13..=17 {
            let bytes = vec![0x2e; count];
            let result = decoder.decode_instruction(&bytes, 0x1000);
            assert_ne!(result.status, DecodeStatus::Valid, "{result:?}");
        }
        let mut beyond_buffer = vec![0x2e; 16];
        beyond_buffer.push(0x90);
        assert_ne!(decoder.decode_instruction(&beyond_buffer, 0x1000).status, DecodeStatus::Valid);
    }

    #[test]
    fn malformed_native_counts_are_rejected_without_partial_evidence() {
        for (ops, spaces, inputs) in [
            (MAX_OPS + 1, 0, 0),
            (0, MAX_SPACES + 1, 0),
            (1, 0, MAX_INPUTS + 1),
            (u32::MAX as usize, 0, 0),
            (0, u32::MAX as usize, 0),
        ] {
            // SAFETY: this record consists only of integers and fixed arrays of integer records.
            let mut record: NativeResult = unsafe { std::mem::zeroed() };
            record.op_count = ops as u32;
            record.space_count = spaces as u32;
            record.ops[0].input_count = inputs as u32;
            let result = convert("x86:LE:64:default", 0x1000, &record);
            assert_eq!(result.status, DecodeStatus::InternalError, "{result:?}");
            assert_eq!(result.flow, InstructionFlow::Unknown { reason: UnknownFlow::MalformedPcode });
            assert!(result.pcode.is_empty());
            assert!(result.spaces.is_empty());
            assert_eq!(result.length, 0);
            assert!(result.diagnostic.as_ref().is_some_and(|text| text.len() <= 256));
        }
    }

    #[test]
    fn x86_bridge_owned_bytes_flow_rebinding_and_real_window_ends() {
        let mut decoder = SleighDecoder::open("x86:LE:64:default").expect("verified bundled x86 decoder");
        for (bytes, length, expected) in [
            (vec![0x48, 0x89, 0xd8], 3, InstructionFlow::Next),
            (vec![0xc3], 1, InstructionFlow::Return),
            (vec![0xe8, 0x10, 0, 0, 0], 5, InstructionFlow::DirectCall { target: 0x1015 }),
            (vec![0x75, 0x10], 2, InstructionFlow::ConditionalBranch { target: 0x1012 }),
            (vec![0xff, 0xe0], 2, InstructionFlow::IndirectBranch),
            (vec![0xff, 0xd0], 2, InstructionFlow::IndirectCall),
        ] {
            let result = decoder.decode_instruction(&bytes, 0x1000);
            assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
            assert_eq!(result.length, length);
            assert_eq!(result.flow, expected, "{result:?}");
            assert!(!result.mnemonic.is_empty());
            assert!(!result.pcode.is_empty());
            assert!(decoder.operands(&bytes, 0x1000).is_none());
        }
        let first = decoder.decode_instruction(&[0x90], 0x1234);
        let second = decoder.decode_instruction(&[0xc3], 0x1234);
        assert_ne!(first.mnemonic, second.mnemonic);
        assert_eq!(second.flow, InstructionFlow::Return);
        assert_eq!(decoder.decode_instruction(&[], 0x1234).status, DecodeStatus::Unavailable);
        assert_eq!(decoder.decode_instruction(&[0xc3, 0], u64::MAX).status, DecodeStatus::Unavailable);
        let last = decoder.decode_instruction(&[0xc3], u64::MAX);
        assert_eq!(last.status, DecodeStatus::Valid, "{last:?}");
        let adapter = decoder.decode(&[0xe8, 0x10, 0, 0, 0], 0x2000);
        assert_eq!(adapter.len, 5);
        assert_eq!(adapter.flow, Flow::Call(0x2015));
        assert!(adapter.data_ref.is_none());
        assert!(adapter.immediate.is_none());
    }

    #[test]
    fn proper_x86_prefixes_cannot_decode_from_lookahead_padding() {
        let mut decoder = SleighDecoder::open("x86:LE:64:default").expect("verified bundled x86 decoder");
        for instruction in [&[0xe8, 0x10, 0, 0, 0][..], &[0x48, 0x89, 0xd8], &[0x75, 0x10]] {
            for length in 1..instruction.len() {
                let result = decoder.decode_instruction(&instruction[..length], 0x1000);
                assert!(
                    matches!(result.status, DecodeStatus::Truncated | DecodeStatus::InvalidOrTruncated),
                    "prefix {length}: {result:?}"
                );
            }
        }
        assert_eq!(
            decoder.decode_instruction(&vec![0x90; MAX_WINDOW_BYTES + 1], 0).status,
            DecodeStatus::BudgetExceeded
        );
        let invalid = decoder.decode_instruction(&[0x06; 16], 0x1000);
        assert_eq!(invalid.status, DecodeStatus::Invalid, "{invalid:?}");
    }

    #[test]
    fn a64_load_store_space_selectors_never_export_native_pointer_offsets() {
        let mut decoder = SleighDecoder::open("AARCH64:LE:64:v8A").expect("verified bundled A64 decoder");
        for (bytes, name) in [([0x20, 0, 0x40, 0xf9], "LOAD"), ([0x20, 0, 0, 0xf9], "STORE")] {
            let result = decoder.decode_instruction(&bytes, 0x4000);
            assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
            assert_eq!(result.length, 4);
            let op = result.pcode.iter().find(|op| op.name == name).expect("memory operation");
            let selector = &op.inputs[0];
            assert_eq!(selector.offset, None);
            let selected = selector.selected_space.expect("sanitized selected space identity");
            assert!(result.spaces.iter().any(|space| space.id == selected && space.word_size == 1));
            for prefix in 1..4 {
                let truncated = decoder.decode_instruction(&bytes[..prefix], 0x4000);
                assert!(
                    matches!(truncated.status, DecodeStatus::Truncated | DecodeStatus::InvalidOrTruncated),
                    "{truncated:?}"
                );
            }
        }
    }

    #[test]
    fn internal_branches_multi_exit_and_delay_aggregation_never_claim_machine_targets() {
        let spaces = [
            Space { id: 0, name: "const".to_owned(), kind: 0, address_size: 8, word_size: 1, highest: u64::MAX },
            Space { id: 1, name: "ram".to_owned(), kind: 1, address_size: 8, word_size: 1, highest: u64::MAX },
        ];
        let branch = PcodeOp {
            opcode: 5,
            name: "CBRANCH".to_owned(),
            address: 0x1000,
            output: None,
            inputs: vec![Varnode {
                space: 0,
                size: 8,
                address_size: 8,
                word_size: 1,
                offset: Some(3),
                selected_space: None,
            }],
        };
        assert_eq!(
            classify(DecodeStatus::Valid, 4, 4, 1, &spaces, std::slice::from_ref(&branch)),
            InstructionFlow::Unknown { reason: UnknownFlow::InternalPcodeBranch }
        );
        let indirect = PcodeOp { opcode: 6, name: "BRANCHIND".to_owned(), ..branch.clone() };
        assert_eq!(
            classify(DecodeStatus::Valid, 4, 4, 1, &spaces, &[branch, indirect]),
            InstructionFlow::Unknown { reason: UnknownFlow::MultipleExits }
        );
        assert_eq!(
            classify(DecodeStatus::Valid, 4, 8, 1, &spaces, &[]),
            InstructionFlow::Unknown { reason: UnknownFlow::DelaySlotAggregation }
        );
        assert_eq!(
            classify(DecodeStatus::UnimplementedPcode, 4, 4, 1, &spaces, &[]),
            InstructionFlow::Unknown { reason: UnknownFlow::IncompletePcode }
        );
    }

    #[test]
    fn unregistered_profile_is_rejected_without_native_initialization() {
        for profile in [
            "../../arbitrary.sla",
            "TI_MSP430X:LE:32:default",
            "avr8:LE:16:extended",
            "avr8:LE:16:atmega256",
            "avr8:LE:24:xmega",
            "65C02:LE:16:default",
        ] {
            assert!(SleighDecoder::open(profile).is_err(), "{profile}");
        }
    }

    #[test]
    fn admitted_processors_decode_owned_instruction_windows_without_c_abi_admission() {
        for (profile, instructions) in [
            (
                "TI_MSP430:LE:16:default",
                vec![
                    (vec![0x34, 0x40, 0x34, 0x12], InstructionFlow::Next),
                    (vec![0x30, 0x41], InstructionFlow::Return),
                    (vec![0xb0, 0x12, 0x34, 0x12], InstructionFlow::DirectCall { target: 0x1234 }),
                    (vec![0x01, 0x20], InstructionFlow::ConditionalBranch { target: 0x1004 }),
                    (vec![0x01, 0x3c], InstructionFlow::Branch { target: 0x1004 }),
                ],
            ),
            (
                "avr8:LE:16:default",
                vec![
                    (vec![0x01, 0xe0], InstructionFlow::Next),
                    (vec![0x08, 0x95], InstructionFlow::Return),
                    (vec![0x01, 0xd0], InstructionFlow::DirectCall { target: 0x1004 }),
                    (vec![0x01, 0xc0], InstructionFlow::Branch { target: 0x1004 }),
                    (vec![0x09, 0x94], InstructionFlow::IndirectBranch),
                ],
            ),
            (
                "6502:LE:16:default",
                vec![
                    (vec![0xa9, 0x01], InstructionFlow::Next),
                    (vec![0x60], InstructionFlow::Return),
                    (vec![0x20, 0x34, 0x12], InstructionFlow::DirectCall { target: 0x1234 }),
                    (vec![0xd0, 0x02], InstructionFlow::ConditionalBranch { target: 0x1004 }),
                    (vec![0x4c, 0x34, 0x12], InstructionFlow::Branch { target: 0x1234 }),
                    (vec![0x6c, 0x34, 0x12], InstructionFlow::IndirectBranch),
                ],
            ),
        ] {
            let mut decoder = SleighDecoder::open(profile).expect("admitted decoder profile");
            for (bytes, expected) in instructions {
                let result = decoder.decode_instruction(&bytes, 0x1000);
                assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
                assert_eq!(result.length as usize, bytes.len(), "{result:?}");
                assert_eq!(result.flow, expected, "{result:?}");
                let code = result.spaces.iter().find(|space| space.id == result.code_space).expect("code space");
                assert_eq!(code.address_size, 2, "{result:?}");
                assert_eq!(code.word_size, if profile.starts_with("avr8:") { 2 } else { 1 });
                assert!(decoder.operands(&bytes, 0x1000).is_none());
                for prefix in 1..bytes.len() {
                    let truncated = decoder.decode_instruction(&bytes[..prefix], 0x1000);
                    assert!(
                        matches!(truncated.status, DecodeStatus::Truncated | DecodeStatus::InvalidOrTruncated),
                        "prefix {prefix}: {truncated:?}"
                    );
                }
            }
            assert_eq!(decoder.decode_instruction(&[], 0x1000).status, DecodeStatus::Unavailable);
            let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            // SAFETY: live decoder under FFI_LOCK; the probe uses only translator-owned space identities.
            assert_eq!(unsafe { rampage_sleigh_test_loader_isolation(decoder.handle) }, 1);
        }
    }

    #[test]
    fn avr_word_addresses_and_harvard_load_selectors_retain_native_identity() {
        let mut decoder = SleighDecoder::open("avr8:LE:16:default").expect("admitted AVR decoder");
        for (bytes, operation, selected_name) in [
            (vec![0x0c, 0x91], "LOAD", "mem"),
            (vec![0x0c, 0x93], "STORE", "mem"),
            (vec![0x04, 0x91], "LOAD", "codebyte"),
        ] {
            let result = decoder.decode_instruction(&bytes, 0x1000);
            assert_eq!(result.status, DecodeStatus::Valid, "{result:?}");
            let code = result.spaces.iter().find(|space| space.id == result.code_space).expect("code space");
            assert_eq!(code.name, "code");
            assert_eq!(code.word_size, 2);
            assert_eq!(code.highest, 0x1ffff);
            let memory = result.spaces.iter().find(|space| space.name == selected_name).expect("Harvard space");
            assert_ne!(memory.id, code.id);
            assert_eq!(memory.word_size, 1);
            assert!(
                result.pcode.iter().filter(|op| op.name == operation).any(|op| {
                    op.inputs
                        .first()
                        .is_some_and(|selector| selector.offset.is_none() && selector.selected_space == Some(memory.id))
                }),
                "{result:?}"
            );
        }
        let absolute = decoder.decode_instruction(&[0x00, 0x91, 0x34, 0x12], 0x1000);
        assert_eq!(absolute.status, DecodeStatus::Valid, "{absolute:?}");
        let data_space = absolute.spaces.iter().find(|space| space.name == "mem").expect("data space");
        assert_ne!(data_space.id, absolute.code_space);
        assert!(
            absolute.pcode.iter().any(|op| {
                op.name == "COPY"
                    && op.inputs.iter().any(|input| input.space == data_space.id && input.offset == Some(0x1234))
            }),
            "{absolute:?}"
        );
        let first = decoder.decode_instruction(&[0x01, 0xc0], 0x10000);
        let changed = decoder.decode_instruction(&[0x02, 0xc0], 0x10000);
        let moved = decoder.decode_instruction(&[0x02, 0xc0], 0x18000);
        assert_eq!(first.flow, InstructionFlow::Branch { target: 0x10004 });
        assert_eq!(changed.flow, InstructionFlow::Branch { target: 0x10006 });
        assert_eq!(moved.flow, InstructionFlow::Branch { target: 0x18006 });
        assert_eq!(decoder.decode_instruction(&[0x08, 0x95], 0x1fffe).status, DecodeStatus::Valid);
        assert_eq!(decoder.decode_instruction(&[0x08, 0x95], 0x1ffff).status, DecodeStatus::Unavailable);
    }
}
