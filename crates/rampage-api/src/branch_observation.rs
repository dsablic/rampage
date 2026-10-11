use rampage_arch::{Arch, Flow, a64};
use rampage_loaders::Format;
use serde::Serialize;

use crate::{ApiError, PointerObservation, Project};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchSlotStatus {
    Linked,
    NoSlotEvidence,
    UnsupportedInstruction,
    ControlFlowBoundary,
    IncompleteWindow,
    AuthenticatedBranch,
}

#[derive(Debug, Serialize)]
pub struct BranchObservation {
    pub capture_identity: rampage_analysis::capture_identity::CaptureIdentity,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub window_start: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub branch_address: u64,
    pub branch_bytes: String,
    pub branch_text: String,
    pub flow: Flow,
    pub slot_status: BranchSlotStatus,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub evidence_stopped_at: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub load_address: Option<u64>,
    pub pointer: Option<PointerObservation>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy)]
enum RegisterEvidence {
    Address(u64),
    Slot { load: u64, slot: u64 },
}

fn relative_address(decoded: &a64::Decoded, address: u64, page: bool) -> Option<u64> {
    let raw = (decoded.field("immhi")? << 2) | decoded.field("immlo")?;
    let signed = ((raw << 43) as i64) >> 43;
    let base = if page { address & !0xfff } else { address };
    let displacement = signed * if page { 4096 } else { 1 };
    Some(base.wrapping_add_signed(displacement))
}

fn step(decoded: &a64::Decoded, address: u64, registers: &mut [Option<RegisterEvidence>; 32]) -> bool {
    let register = |field| decoded.field(field).map(|value| value as usize);
    let known_address = |register: usize| match registers[register] {
        Some(RegisterEvidence::Address(address)) => Some(address),
        _ => None,
    };
    let name = decoded.encoding.name;
    let (destination, produced) = match name {
        "ADR_only_pcreladdr" | "ADRP_only_pcreladdr" => (
            register("Rd"),
            relative_address(decoded, address, name.starts_with("ADRP")).map(RegisterEvidence::Address),
        ),
        "ADD_64_addsub_imm" => {
            let offset = decoded.field("imm12").unwrap_or(0) << if decoded.field("sh") == Some(1) { 12 } else { 0 };
            let produced = if offset == 0 {
                register("Rn").and_then(|source| registers[source])
            } else {
                register("Rn").and_then(known_address).map(|base| RegisterEvidence::Address(base.wrapping_add(offset)))
            };
            (register("Rd"), produced)
        }
        "LDR_64_ldst_pos" => {
            let offset = decoded.field("imm12").unwrap_or(0) * 8;
            let slot = register("Rn").and_then(known_address).map(|base| base.wrapping_add(offset));
            (register("Rt"), slot.map(|slot| RegisterEvidence::Slot { load: address, slot }))
        }
        "LDR_64_loadlit" => {
            let raw = decoded.field("imm19").unwrap_or(0);
            let signed = ((raw << 45) as i64) >> 45;
            let slot = address.wrapping_add_signed(signed * 4);
            (register("Rt"), Some(RegisterEvidence::Slot { load: address, slot }))
        }
        "ORR_64_log_shift"
            if decoded.field("Rn") == Some(31)
                && decoded.field("shift") == Some(0)
                && decoded.field("imm6") == Some(0) =>
        {
            let produced = register("Rm")
                .and_then(|source| if source == 31 { Some(RegisterEvidence::Address(0)) } else { registers[source] });
            (register("Rd"), produced)
        }
        "NOP_HI_hints" => return true,
        _ => return false,
    };
    if let Some(destination) = destination.filter(|&register| register < 31 || name == "ADD_64_addsub_imm") {
        registers[destination] = produced;
    }
    true
}

impl Project {
    /// Links a decoded ARM64 branch to a slot load in an explicitly selected straight-line window, not a CFG edge.
    pub fn observe_indirect_branch(&self, start: u64, branch: u64) -> Result<BranchObservation, ApiError> {
        if self.binary.format != Format::Snapshot
            || self.binary.arch != Arch::Aarch64
            || self.binary.target().big_endian
        {
            return Err(ApiError::Invalid("branch observations require a little-endian ARM64 snapshot".to_owned()));
        }
        let distance = branch.checked_sub(start).filter(|distance| *distance <= 252 && distance.is_multiple_of(4));
        if distance.is_none() || !start.is_multiple_of(4) {
            return Err(ApiError::Invalid(
                "select an aligned ARM64 window of 1..64 instructions ending at the branch".to_owned(),
            ));
        }
        let capture_identity = rampage_analysis::capture_identity::capture_identity(&self.binary)
            .ok_or_else(|| ApiError::Invalid("capture identity unavailable".to_owned()))?;
        let instruction_bytes = |address: u64| {
            let segment = self.binary.segment_containing(address)?;
            if !segment.perms.read
                || !segment.perms.execute
                || address.checked_sub(segment.address)?.checked_add(4)? > segment.size
            {
                return None;
            }
            self.binary.code_from(address)?.first_chunk::<4>()
        };
        let bytes = instruction_bytes(branch).ok_or_else(|| {
            ApiError::Invalid("branch instruction is not fully readable executable backing".to_owned())
        })?;
        let decoded_branch = a64::decode_word(u32::from_le_bytes(*bytes))
            .ok_or_else(|| ApiError::Invalid("selected branch bytes do not decode".to_owned()))?;
        let mut decoder = self.binary.decoder()?;
        let flow = decoder.decode(bytes, branch).flow;
        if !matches!(flow, Flow::IndirectCall | Flow::IndirectJump) {
            return Err(ApiError::Invalid("selected instruction is not an indirect call or jump".to_owned()));
        }
        let mut result = BranchObservation { capture_identity, window_start: start, branch_address: branch,
            branch_bytes: rampage_arch::hex::bytes(bytes), branch_text: decoder.format(bytes, branch), flow,
            slot_status: BranchSlotStatus::NoSlotEvidence, evidence_stopped_at: None,
            load_address: None, pointer: None, limitations: vec![
                "The selected window is conditional decoding evidence, not proof that this path or branch executed.".to_owned(),
                "A linked slot's captured value is not a proven load value, call edge or future invariant.".to_owned(),
                "Only ADR/ADRP, ADD-immediate, 64-bit literal/unsigned LDR, MOV-register and NOP are tracked.".to_owned(),
                "Other instructions, control-flow boundaries and incomplete backing stop slot linking. No discovery is run.".to_owned(),
                "Authentication is not modeled; register values and module ownership are not inferred.".to_owned(),
            ] };
        if !matches!(decoded_branch.encoding.name, "BR_64_branch_reg" | "BLR_64_branch_reg") {
            result.slot_status = BranchSlotStatus::AuthenticatedBranch;
            return Ok(result);
        }
        let mut registers = [None; 32];
        let mut address = start;
        while address < branch {
            let Some(bytes) = instruction_bytes(address) else {
                result.slot_status = BranchSlotStatus::IncompleteWindow;
                result.evidence_stopped_at = Some(address);
                return Ok(result);
            };
            let Some(decoded) = a64::decode_word(u32::from_le_bytes(*bytes)) else {
                result.slot_status = BranchSlotStatus::UnsupportedInstruction;
                result.evidence_stopped_at = Some(address);
                return Ok(result);
            };
            decoder.reset();
            if decoder.decode(bytes, address).flow != Flow::Next {
                result.slot_status = BranchSlotStatus::ControlFlowBoundary;
                result.evidence_stopped_at = Some(address);
                return Ok(result);
            }
            if !step(&decoded, address, &mut registers) {
                result.slot_status = BranchSlotStatus::UnsupportedInstruction;
                result.evidence_stopped_at = Some(address);
                return Ok(result);
            }
            address += 4;
        }
        if let Some(RegisterEvidence::Slot { load, slot }) = decoded_branch
            .field("Rn")
            .filter(|&register| register < 31)
            .and_then(|register| registers[register as usize])
        {
            result.slot_status = BranchSlotStatus::Linked;
            result.load_address = Some(load);
            result.pointer = Some(self.observe_pointer(slot)?);
        }
        Ok(result)
    }
}
