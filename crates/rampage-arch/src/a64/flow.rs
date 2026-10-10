//! Control flow and data references of decoded instructions.
//!
//! Each encoding's flow class, address effect and general-purpose destinations are worked out once from its name
//! and assembly syntax. Data references follow the address a register holds after ADRP (or an ADD of an
//! immediate to a known address) into the loads, stores and ADDs that use it.

use std::sync::LazyLock;

use super::Decoded;
use super::helpers::{ones, pc_relative};
use super::spec::ENCODINGS;
use super::spec_types::Encoding;
use crate::Flow;

/// Addresses known to be held by general-purpose registers: ADRP pages, and the full addresses an ADD forms
/// from them.
#[derive(Clone, Default)]
pub struct Addresses {
    valid: u32,
    /// Registers holding a page rather than a full address.
    page: u32,
    value: [u64; 31],
}

impl Addresses {
    fn get(&self, register: u64) -> Option<u64> {
        (register < 31 && self.valid & (1 << register) != 0).then(|| self.value[register as usize])
    }

    fn page(&self, register: u64) -> Option<u64> {
        self.get(register).filter(|_| self.page & (1 << register) != 0)
    }

    fn set(&mut self, register: u64, address: u64, page: bool) {
        if register < 31 {
            self.valid |= 1 << register;
            self.page = (self.page & !(1 << register)) | (u32::from(page) << register);
            self.value[register as usize] = address;
        }
    }

    fn clear(&mut self, register: u64) {
        if register < 31 {
            self.valid &= !(1 << register);
        }
    }

    /// A call may change x0-x18 and x30 (AAPCS64); x19-x28 are preserved.
    fn clobber_caller_saved(&mut self) {
        self.valid &= !(0x7_ffff | (1 << 30));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowClass {
    Next,
    Jump,
    /// B.cond and BC.cond: unconditional when the condition is AL or NV.
    ConditionalBranch,
    ConditionalJump,
    Call,
    IndirectJump,
    IndirectCall,
    Return,
    Halt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    None,
    Adrp,
    Adr,
    /// ADD (immediate), 64-bit.
    AddImmediate,
    /// Load or store with an unsigned 12-bit offset scaled by the access size (`None`: by the size field).
    ScaledOffset(Option<u64>),
    LoadLiteral,
}

/// A general-purpose register field an instruction writes; `plus` is 1 for the second register of a pair that
/// shares one field (CASP).
#[derive(Clone, Copy)]
struct Written {
    start: u8,
    width: u8,
    plus: u8,
}

struct Info {
    flow: FlowClass,
    effect: Effect,
    written: Vec<Written>,
    /// Pre- and post-indexed forms update the base register.
    writeback: Option<Written>,
    /// Calls and supervisor calls may change every caller-saved register.
    clobbers_caller_saved: bool,
}

static INFO: LazyLock<Vec<Info>> = LazyLock::new(|| ENCODINGS.iter().map(info_for).collect());

fn info_for(encoding: &Encoding) -> Info {
    let name = encoding.name;
    let prefix = name.split('_').next().unwrap_or(name);
    let flow = match prefix {
        "B" if name == "B_only_branch_imm" => FlowClass::Jump,
        "B" | "BC" if name.ends_with("condbranch") => FlowClass::ConditionalBranch,
        "BL" => FlowClass::Call,
        "CBZ" | "CBNZ" | "TBZ" | "TBNZ" => FlowClass::ConditionalJump,
        _ if prefix.starts_with("CB") && (name.ends_with("_regs") || name.ends_with("_imm")) => {
            FlowClass::ConditionalJump
        }
        "BR" | "BRAA" | "BRAAZ" | "BRAB" | "BRABZ" => FlowClass::IndirectJump,
        "BLR" | "BLRAA" | "BLRAAZ" | "BLRAB" | "BLRABZ" => FlowClass::IndirectCall,
        "RET" | "RETAA" | "RETAB" | "RETAASPPC" | "RETABSPPC" | "RETAASPPCR" | "RETABSPPCR" | "ERET" | "ERETAA"
        | "ERETAB" | "DRPS" | "TEXIT" => FlowClass::Return,
        "BRK" | "HLT" | "UDF" => FlowClass::Halt,
        _ => FlowClass::Next,
    };
    let effect = if name.starts_with("ADRP") {
        Effect::Adrp
    } else if name.starts_with("ADR_") {
        Effect::Adr
    } else if name == "ADD_64_addsub_imm" {
        Effect::AddImmediate
    } else if name.ends_with("_loadlit") {
        Effect::LoadLiteral
    } else if name.ends_with("_ldst_pos") {
        Effect::ScaledOffset(name.contains("_Q_").then_some(16))
    } else {
        Effect::None
    };

    let written_by = |register: &str| -> bool {
        let starts = |prefixes: &[&str]| prefixes.iter().any(|p| prefix.starts_with(p));
        match register {
            "Rd" | "Rdn" => true,
            "Rt" => starts(&["LD", "MRS", "MRRS", "SWP", "CAS", "RCW", "SYSL", "GCSPOP"]),
            "Rt2" => starts(&["LD"]),
            // Store-exclusive status and compare-and-swap old values.
            "Rs" => starts(&["ST", "CAS", "RCW", "CPY", "SET"]),
            _ => false,
        }
    };
    let mut written = Vec::new();
    let mut base = None;
    for operand in encoding.syntax.operands {
        let &[index] = operand.fields else { continue };
        let register = &encoding.fields[index as usize];
        if register.name == "Rn" {
            base = Some(Written { start: register.start, width: register.width, plus: 0 });
        }
        // Only W and X operands are general-purpose registers; SIMD&FP destinations use the same field names.
        // SVE writes some as <R><d>, where <R> picks W or X.
        let general = operand.name.starts_with("<W")
            || operand.name.starts_with("<X")
            || matches!(operand.name, "<d>" | "<dn>") && encoding.syntax.operands.iter().any(|o| o.name == "<R>");
        if general && written_by(register.name) {
            let plus = u8::from(operand.name.contains("+1"));
            written.push(Written { start: register.start, width: register.width, plus });
        }
    }
    // CPY* and SET* advance all three of their registers; LDRAA and LDRAB write back when W is set.
    let indexed = ["post", "pre", "asisdlsep", "asisdlsop", "memcms", "memset_go", "64W_ldst_pac"]
        .iter()
        .any(|n| name.contains(n));
    let clobbers_caller_saved =
        matches!(flow, FlowClass::Call | FlowClass::IndirectCall) || matches!(prefix, "SVC" | "HVC" | "SMC");
    Info { flow, effect, written, writeback: base.filter(|_| indexed), clobbers_caller_saved }
}

/// The PC-relative target of a branch or literal load: imm26, imm19, imm14 or imm9 words.
fn relative_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let (raw, width) = [("imm26", 26), ("imm19", 19), ("imm14", 14), ("imm9", 9)]
        .into_iter()
        .find_map(|(name, width)| decoded.field(name).map(|raw| (raw, width)))?;
    Some(pc_relative(address, raw, width, 2).0)
}

/// ADR/ADRP targets; ADRP yields the 4 KiB page.
fn address_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let raw = (decoded.field("immhi")? << 2) | decoded.field("immlo")?;
    let scale = if decoded.encoding.name.starts_with("ADRP") { 12 } else { 0 };
    Some(pc_relative(address, raw, 21, scale).0)
}

fn index_of(encoding: &'static Encoding) -> usize {
    (encoding as *const Encoding as usize - ENCODINGS.as_ptr() as usize) / size_of::<Encoding>()
}

pub fn analyze(decoded: &Decoded, address: u64, addresses: &mut Addresses) -> (Flow, Option<u64>) {
    let info = &INFO[index_of(decoded.encoding)];
    let direct = |make: fn(u64) -> Flow| relative_target(decoded, address).map_or(Flow::Invalid, make);
    let flow = match info.flow {
        FlowClass::Next => Flow::Next,
        FlowClass::Jump => direct(Flow::Jump),
        FlowClass::ConditionalBranch if decoded.field("cond").is_some_and(|cond| cond >= 14) => direct(Flow::Jump),
        FlowClass::ConditionalBranch | FlowClass::ConditionalJump => direct(Flow::ConditionalJump),
        FlowClass::Call => direct(Flow::Call),
        FlowClass::IndirectJump => Flow::IndirectJump,
        FlowClass::IndirectCall => Flow::IndirectCall,
        FlowClass::Return => Flow::Return,
        FlowClass::Halt => Flow::Halt,
    };

    let word = u64::from(decoded.word);
    let register = |w: Written| ((word >> w.start) & ones(w.width.into())) + u64::from(w.plus);
    let base = || decoded.field("Rn").and_then(|rn| addresses.get(rn));
    // A register's new known address, and whether it is an ADRP page.
    let mut produced = None;
    let data_ref = match info.effect {
        Effect::None => None,
        Effect::LoadLiteral => relative_target(decoded, address),
        Effect::Adr => address_target(decoded, address),
        Effect::Adrp => {
            produced = address_target(decoded, address).map(|page| (page, true));
            None
        }
        Effect::AddImmediate => {
            // ADRP + ADD forms an address; further ADDs are pointer arithmetic, not new references.
            let shift = if decoded.field("sh") == Some(1) { 12 } else { 0 };
            let offset = decoded.field("imm12").unwrap_or(0) << shift;
            let page = decoded.field("Rn").and_then(|rn| addresses.page(rn));
            let target = page.map(|page| page.wrapping_add(offset));
            produced = target.map(|target| (target, false));
            target
        }
        Effect::ScaledOffset(scale) => {
            let scale = scale.unwrap_or_else(|| 1 << decoded.field("size").unwrap_or(0));
            let offset = decoded.field("imm12").unwrap_or(0) * scale;
            base().map(|base| base.wrapping_add(offset))
        }
    };

    // Whatever this instruction writes no longer holds a known address.
    for &written in &info.written {
        addresses.clear(register(written));
    }
    if let Some(base) = info.writeback {
        addresses.clear(register(base));
    }
    if info.clobbers_caller_saved {
        addresses.clobber_caller_saved();
    }
    if let (Some((value, page)), Some(rd)) = (produced, decoded.field("Rd")) {
        addresses.set(rd, value, page);
    }
    (flow, data_ref)
}
