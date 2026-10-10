//! Control flow and data references of decoded instructions, by encoding name.

use super::Decoded;
use crate::Flow;

fn sign_extend(value: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((value << shift) as i64) >> shift
}

/// Pages loaded by ADRP into each general-purpose register, so a following ADD or load can resolve the full
/// address it forms.
#[derive(Clone, Default)]
pub struct Pages {
    valid: u32,
    page: [u64; 31],
}

impl Pages {
    fn get(&self, register: u64) -> Option<u64> {
        (register < 31 && self.valid & (1 << register) != 0).then(|| self.page[register as usize])
    }

    fn set(&mut self, register: u64, page: u64) {
        if register < 31 {
            self.valid |= 1 << register;
            self.page[register as usize] = page;
        }
    }

    fn clear(&mut self, register: u64) {
        if register < 31 {
            self.valid &= !(1 << register);
        }
    }
}

/// The PC-relative target of a branch or literal load: imm26, imm19, imm14 or imm9 words.
fn relative_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let (raw, width) = [("imm26", 26), ("imm19", 19), ("imm14", 14), ("imm9", 9)]
        .into_iter()
        .find_map(|(name, width)| decoded.field(name).map(|raw| (raw, width)))?;
    Some(address.wrapping_add((sign_extend(raw, width) << 2) as u64))
}

/// ADR/ADRP targets; ADRP yields the 4 KiB page.
fn address_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let raw = (decoded.field("immhi")? << 2) | decoded.field("immlo")?;
    let offset = sign_extend(raw, 21);
    if decoded.encoding.name.starts_with("ADRP") {
        Some((address & !0xfff).wrapping_add((offset << 12) as u64))
    } else {
        Some(address.wrapping_add(offset as u64))
    }
}

/// Bytes per register of a load or store with an unsigned scaled offset (`*_ldst_pos`).
fn scaled_access_size(decoded: &Decoded) -> u64 {
    if decoded.encoding.name.contains("_Q_") { 16 } else { 1 << decoded.field("size").unwrap_or(0) }
}

pub fn analyze(decoded: &Decoded, address: u64, pages: &mut Pages) -> (Flow, Option<u64>) {
    let name = decoded.encoding.name;
    let prefix = name.split('_').next().unwrap_or(name);
    let direct = |make: fn(u64) -> Flow| relative_target(decoded, address).map_or(Flow::Invalid, make);
    let flow = match prefix {
        "B" if name == "B_only_branch_imm" => direct(Flow::Jump),
        "B" | "BC" if name.ends_with("condbranch") => {
            // Conditions AL and NV always branch.
            if decoded.field("cond").is_some_and(|cond| cond >= 14) {
                direct(Flow::Jump)
            } else {
                direct(Flow::ConditionalJump)
            }
        }
        "BL" => direct(Flow::Call),
        "CBZ" | "CBNZ" | "TBZ" | "TBNZ" => direct(Flow::ConditionalJump),
        _ if prefix.starts_with("CB") && (name.ends_with("_regs") || name.ends_with("_imm")) => {
            direct(Flow::ConditionalJump)
        }
        "BR" | "BRAA" | "BRAAZ" | "BRAB" | "BRABZ" => Flow::IndirectJump,
        "BLR" | "BLRAA" | "BLRAAZ" | "BLRAB" | "BLRABZ" => Flow::IndirectCall,
        "RET" | "RETAA" | "RETAB" | "RETAASPPC" | "RETABSPPC" | "RETAASPPCR" | "RETABSPPCR" | "ERET" | "ERETAA"
        | "ERETAB" | "DRPS" => Flow::Return,
        "BRK" | "HLT" | "UDF" => Flow::Halt,
        _ => Flow::Next,
    };

    let rd = decoded.field("Rd");
    let rn = decoded.field("Rn");
    let data_ref = if name.ends_with("_loadlit") {
        relative_target(decoded, address)
    } else if name.starts_with("ADRP") {
        if let (Some(rd), Some(page)) = (rd, address_target(decoded, address)) {
            pages.set(rd, page);
        }
        return (flow, None);
    } else if name.starts_with("ADR_") {
        address_target(decoded, address)
    } else if name == "ADD_64_addsub_imm" {
        // ADRP xN, page; ADD xD, xN, #offset
        let target = rn.and_then(|rn| pages.get(rn)).map(|page| {
            let shift = if decoded.field("sh") == Some(1) { 12 } else { 0 };
            page.wrapping_add(decoded.field("imm12").unwrap_or(0) << shift)
        });
        if let Some(rd) = rd {
            pages.clear(rd);
        }
        return (flow, target);
    } else if name.ends_with("_ldst_pos") {
        // ADRP xN, page; LDR/STR xT, [xN, #offset]
        let target = rn
            .and_then(|rn| pages.get(rn))
            .map(|page| page.wrapping_add(decoded.field("imm12").unwrap_or(0) * scaled_access_size(decoded)));
        let writes_general =
            name.starts_with("LD") && !matches!(name.split('_').nth(1), Some("B" | "H" | "S" | "D" | "Q"));
        if let Some(rt) = decoded.field("Rt").filter(|_| writes_general) {
            pages.clear(rt);
        }
        return (flow, target);
    } else {
        None
    };
    // Any other write to a general-purpose destination ends what ADRP put there.
    if let Some(rd) = rd {
        pages.clear(rd);
    }
    if name.starts_with("LD")
        && let Some(rt) = decoded.field("Rt")
    {
        pages.clear(rt);
    }
    (flow, data_ref)
}
