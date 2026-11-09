use rampage_arch::{Arch, Disassembler, Flow, Insn, Target};
use serde::Serialize;

use crate::ApiError;

pub const MAX_RAW_CODE_BYTES: usize = 4096;
pub const MAX_RAW_CODE_INSTRUCTIONS: usize = 256;
pub const MAX_RAW_CODE_RESULT_BYTES: usize = 48_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RawCodeMode {
    Native,
    Arm,
    Thumb,
}

impl std::str::FromStr for RawCodeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "native" => Ok(Self::Native),
            "arm" => Ok(Self::Arm),
            "thumb" => Ok(Self::Thumb),
            _ => Err("unsupported raw-code mode; select native, arm or thumb explicitly".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawCodeRequest {
    pub arch: Arch,
    pub mode: RawCodeMode,
    pub code_big_endian: bool,
    pub data_big_endian: bool,
    pub base_address: u64,
    pub instruction_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCodeStopReason {
    WindowEnd,
    InstructionLimit,
    InvalidOrIncompleteInstruction,
}

#[derive(Debug, Serialize)]
pub struct RawCodeRow {
    pub window_byte_offset: usize,
    /// Hex of the actual instruction bytes, without padding or synthetic bytes.
    pub bytes: String,
    pub text: String,
    /// Decoder observations, not validated execution, references or pointer identities.
    #[serde(flatten)]
    pub observation: Insn,
}

#[derive(Debug, Serialize)]
pub struct RawCodeReport {
    pub arch: Arch,
    pub mode: RawCodeMode,
    pub code_big_endian: bool,
    pub data_big_endian: bool,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub end_address_exclusive: u64,
    pub mapping_validation: &'static str,
    pub facts_interpretation: &'static str,
    pub coordinate_space: &'static str,
    pub window_bytes: usize,
    pub instruction_limit: usize,
    pub instructions_decoded: usize,
    pub consumed_bytes: usize,
    pub remaining_bytes: usize,
    pub stop_reason: RawCodeStopReason,
    pub rows: Vec<RawCodeRow>,
    pub limitations: Vec<&'static str>,
}

/// ARM or AArch64 text with its decimal `#` immediates also in hex, after a `;` as GNU objdump prints them
/// (`movt r1, #1934 ; 0x78e`), so a `movw`/`movt` pair or an offset reads without converting by hand. Immediates
/// below 10 read the same in both bases and get none.
pub(crate) fn with_hex_immediates(text: String) -> String {
    let mut values = Vec::new();
    for (index, _) in text.match_indices('#') {
        let rest = &text[index + 1..];
        let negative = rest.starts_with('-');
        let digits: String = rest[usize::from(negative)..].chars().take_while(char::is_ascii_digit).collect();
        let next = rest[usize::from(negative) + digits.len()..].chars().next();
        // Hex (`#0x10`) and floating-point (`#1.5`) immediates are left alone.
        if digits.is_empty() || matches!(next, Some('x' | 'X' | '.' | 'e' | 'E')) {
            continue;
        }
        let Ok(value) = digits.parse::<u64>() else { continue };
        if value >= 10 {
            values.push(if negative { format!("-{value:#x}") } else { format!("{value:#x}") });
        }
    }
    if values.is_empty() { text } else { format!("{text} ; {}", values.join(", ")) }
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

pub(crate) fn validate_raw_window_size(length: usize, request: &RawCodeRequest) -> Result<u64, ApiError> {
    if !(1..=MAX_RAW_CODE_BYTES).contains(&length) {
        return Err(invalid("raw-code window must contain 1..=4096 bytes"));
    }
    if !(1..=MAX_RAW_CODE_INSTRUCTIONS).contains(&request.instruction_limit) {
        return Err(invalid("raw-code instruction_limit must be 1..=256"));
    }
    if !matches!(request.arch, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Aarch64) {
        return Err(invalid("raw-code inspection supports only x86, x86_64, arm and aarch64"));
    }
    if request.arch == Arch::Arm {
        if request.mode == RawCodeMode::Native {
            return Err(invalid("raw ARM code requires explicit arm or thumb mode"));
        }
    } else if request.mode != RawCodeMode::Native {
        return Err(invalid("raw-code arm and thumb modes require the arm architecture"));
    }
    if request.code_big_endian || request.data_big_endian {
        return Err(invalid("raw-code inspection initially supports only little-endian instructions and data"));
    }
    let alignment = match (request.arch, request.mode) {
        (Arch::Arm, RawCodeMode::Thumb) => 2,
        (Arch::Arm | Arch::Aarch64, _) => 4,
        _ => 1,
    };
    if !request.base_address.is_multiple_of(alignment) {
        return Err(invalid("raw-code base is not instruction-aligned; Thumb bits are not stripped"));
    }
    let end = request
        .base_address
        .checked_add(length as u64)
        .ok_or_else(|| invalid("raw-code virtual-address range overflows"))?;
    let highest = request
        .arch
        .native_address_width()
        .ok_or_else(|| invalid("native raw-code address bounds are unavailable"))?
        .highest_address();
    if end - 1 > highest {
        return Err(invalid("raw-code window exceeds the 32-bit virtual-address range"));
    }
    Ok(end)
}

fn instruction_size(
    bytes: &[u8],
    address: u64,
    request: &RawCodeRequest,
    probe: &mut dyn Disassembler,
) -> Option<usize> {
    match (request.arch, request.mode) {
        (Arch::X86 | Arch::X86_64, _) => {
            // Minimal-prefix probing prevents the decoder's get-PC lookahead from reclassifying calls.
            for size in 1..=bytes.len().min(15) {
                probe.reset();
                let instruction = probe.decode(&bytes[..size], address);
                if instruction.flow != Flow::Invalid && usize::from(instruction.len) == size {
                    return Some(size);
                }
            }
            None
        }
        (Arch::Arm, RawCodeMode::Thumb) => {
            let first = u16::from_le_bytes(*bytes.first_chunk::<2>()?);
            let size = if rampage_arch::aarch32::is_wide(first) { 4 } else { 2 };
            (bytes.len() >= size).then_some(size)
        }
        _ => (bytes.len() >= 4).then_some(4),
    }
}

fn is_arm_literal_load(bytes: &[u8], mode: RawCodeMode) -> bool {
    let decoded = match mode {
        RawCodeMode::Arm => {
            bytes.first_chunk::<4>().and_then(|word| rampage_arch::aarch32::decode_a32(u32::from_le_bytes(*word)))
        }
        RawCodeMode::Thumb => bytes.first_chunk::<2>().and_then(|first| {
            rampage_arch::aarch32::decode_t32(
                u16::from_le_bytes(*first),
                bytes.get(2..).and_then(|rest| rest.first_chunk::<2>()).map(|word| u16::from_le_bytes(*word)),
                rampage_arch::aarch32::ItState::default(),
            )
        }),
        RawCodeMode::Native => None,
    };
    decoded.is_some_and(|instruction| instruction.encoding.name.starts_with("LDR_l"))
}

/// Linear decoding of an explicitly mapped borrowed window. No files, loaders, projects or memory readers.
/// ARM literal LDR may read complete words from the supplied window suffix, never external or runtime memory.
/// Big-endian requests are explicitly refused by this initial implementation.
pub fn inspect_raw_code(bytes: &[u8], request: &RawCodeRequest) -> Result<RawCodeReport, ApiError> {
    let end = validate_raw_window_size(bytes.len(), request)?;
    let target = Target {
        arch: request.arch,
        big_endian: request.code_big_endian,
        data_big_endian: request.data_big_endian,
        thumb: if request.mode == RawCodeMode::Thumb {
            std::iter::once(request.base_address..end).collect()
        } else {
            Vec::new().into()
        },
        global_pointer: None,
        got: None,
        // A-profile Thumb: Cortex-M images open as the ARM:LE:32:Cortex Raw profile instead.
        m_profile: false,
    };
    let mut decoder = rampage_arch::decoder(&target)?;
    let mut probe = rampage_arch::decoder(&target)?;
    let mut rows = Vec::new();
    let mut consumed = 0;
    let stop_reason = loop {
        if consumed == bytes.len() {
            break RawCodeStopReason::WindowEnd;
        }
        if rows.len() == request.instruction_limit {
            break RawCodeStopReason::InstructionLimit;
        }
        let address = request.base_address + consumed as u64;
        let remaining = &bytes[consumed..];
        let Some(size) = instruction_size(remaining, address, request, probe.as_mut()) else {
            break RawCodeStopReason::InvalidOrIncompleteInstruction;
        };
        let instruction_bytes = &remaining[..size];
        if request.arch == Arch::Arm {
            // Learned branch-target modes must not override the analyst's single explicit instruction set.
            decoder.set_code_modes(&[]);
        }
        // ARM's literal reader bounds-checks complete words relative to the current instruction address.
        // Only literal LDR gets the remaining window; other instructions cannot perform get-PC lookahead.
        let decode_bytes = if request.arch == Arch::Arm && is_arm_literal_load(instruction_bytes, request.mode) {
            remaining
        } else {
            instruction_bytes
        };
        let observation = decoder.decode(decode_bytes, address);
        if observation.flow == Flow::Invalid || usize::from(observation.len) != size {
            break RawCodeStopReason::InvalidOrIncompleteInstruction;
        }
        if observation.address != address {
            return Err(invalid("raw-code decoder returned an inconsistent virtual address"));
        }
        let transfer = observation.flow != Flow::Next;
        let conditional_fallthrough = observation.flow == Flow::Next && observation.conditional;
        let mut text = decoder.format(instruction_bytes, address);
        if matches!(request.arch, Arch::Arm | Arch::Aarch64) {
            text = with_hex_immediates(text);
        }
        rows.push(RawCodeRow {
            window_byte_offset: consumed,
            bytes: rampage_arch::hex::bytes(instruction_bytes),
            text,
            observation,
        });
        consumed += size;
        if transfer {
            decoder.reset();
            decoder.set_code_modes(&[]);
        } else if conditional_fallthrough {
            // Conditional returns/indirect jumps retain sequential Thumb IT state, but not register facts.
            decoder.join();
            decoder.set_code_modes(&[]);
        }
    };
    let report = RawCodeReport {
        arch: request.arch,
        mode: request.mode,
        code_big_endian: request.code_big_endian,
        data_big_endian: request.data_big_endian,
        base_address: request.base_address,
        end_address_exclusive: end,
        mapping_validation: "analyst_asserted",
        facts_interpretation: "decoder_observations_not_proof",
        coordinate_space: "window_byte_offset_and_analyst_asserted_virtual_address",
        window_bytes: bytes.len(),
        instruction_limit: request.instruction_limit,
        instructions_decoded: rows.len(),
        consumed_bytes: consumed,
        remaining_bytes: bytes.len() - consumed,
        stop_reason,
        rows,
        limitations: vec![
            "Architecture, mode, endianness and base are analyst assertions, not validated mappings or code identity.",
            "Rows are linear decoder observations, not proof of execution, reachability, valid pointers or functions.",
            "No executable opening, discovery, functions, annotations, sidecars, target following or external reads.",
            "ARM literal LDR reads complete words only from the window suffix; unavailable values stay unknown.",
            "Backward ARM literals before the current instruction are not recovered, even within the supplied window.",
            "Other decodes receive only instruction bytes; no get-PC lookahead or external/runtime memory recovery.",
            "Propagated facts are reset after transfers; learned ARM branch-target modes do not change explicit mode.",
            "Conditional fallthrough retains sequential Thumb IT context while discarding propagated register facts.",
            "A window starting inside a Thumb IT block has no prior IT state; missing predicates are not evidence.",
            "Only little-endian instructions and data are accepted; literals are decoder observations, not proof.",
            "The first invalid or incomplete instruction remains unconsumed; the decoder may not distinguish them.",
            "Offsets are window-relative, not source-file offsets. No source identity, hash or provenance is inferred.",
            "Straight-line register facts can depend on earlier rows; missing facts are not negative evidence.",
        ],
    };
    if serde_json::to_vec(&report).map_err(|_| invalid("raw-code report serialization failed"))?.len()
        > MAX_RAW_CODE_RESULT_BYTES
    {
        return Err(invalid("raw-code report exceeds 48000 JSON bytes; narrow the window or instruction_limit"));
    }
    Ok(report)
}

#[cfg(test)]
#[path = "raw_code_tests.rs"]
mod tests;
