//! Capstone-based decoding for the architectures that have no native decoder yet: 32-bit ARM (A32 and Thumb),
//! MIPS, PowerPC, RISC-V, SPARC, z/Architecture and m68k. Capstone's instruction groups and operands give the
//! control flow; the per-architecture rules here fill in what they leave implicit (condition codes, returns
//! through ordinary jumps, PC-relative literals).

use capstone::arch::{self, ArchOperand, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode};
use capstone::{Capstone, Endian, Insn, InsnGroupType};

use crate::{Arch, Disassembler, Flow, Insn as Decoded, Target, UnsupportedArch};

pub struct CapstoneDisassembler {
    target: Target,
    primary: Capstone,
    /// ARM only: a second engine for Thumb code.
    thumb: Option<Capstone>,
}

fn engine(arch: Arch, big_endian: bool, thumb: bool) -> Option<Capstone> {
    let endian = if big_endian { Endian::Big } else { Endian::Little };
    let built = match arch {
        Arch::Arm => {
            let mode = if thumb { arch::arm::ArchMode::Thumb } else { arch::arm::ArchMode::Arm };
            let v8 = [arch::arm::ArchExtraMode::V8];
            Capstone::new().arm().mode(mode).extra_mode(v8.into_iter()).endian(endian).detail(true).build()
        }
        Arch::Mips | Arch::Mips64 => {
            let mode = if arch == Arch::Mips { arch::mips::ArchMode::Mips32 } else { arch::mips::ArchMode::Mips64 };
            Capstone::new().mips().mode(mode).endian(endian).detail(true).build()
        }
        Arch::PowerPc | Arch::PowerPc64 => {
            let mode = if arch == Arch::PowerPc { arch::ppc::ArchMode::Mode32 } else { arch::ppc::ArchMode::Mode64 };
            Capstone::new().ppc().mode(mode).endian(endian).detail(true).build()
        }
        Arch::Riscv32 | Arch::Riscv64 => {
            let mode =
                if arch == Arch::Riscv32 { arch::riscv::ArchMode::RiscV32 } else { arch::riscv::ArchMode::RiscV64 };
            let compressed = [arch::riscv::ArchExtraMode::RiscVC];
            Capstone::new().riscv().mode(mode).extra_mode(compressed.into_iter()).detail(true).build()
        }
        Arch::Sparc => Capstone::new().sparc().mode(arch::sparc::ArchMode::Default).detail(true).build(),
        Arch::Sparc64 => Capstone::new().sparc().mode(arch::sparc::ArchMode::V9).detail(true).build(),
        Arch::S390x => Capstone::new().sysz().mode(arch::sysz::ArchMode::Default).detail(true).build(),
        Arch::M68k => Capstone::new().m68k().mode(arch::m68k::ArchMode::M68k040).detail(true).build(),
        Arch::X86 | Arch::X86_64 | Arch::Aarch64 => return None,
    };
    built.ok()
}

impl CapstoneDisassembler {
    pub fn new(target: &Target) -> Result<Self, UnsupportedArch> {
        let primary = engine(target.arch, target.big_endian, false).ok_or(UnsupportedArch(target.arch))?;
        let thumb = if target.arch == Arch::Arm { engine(Arch::Arm, target.big_endian, true) } else { None };
        Ok(Self { target: target.clone(), primary, thumb })
    }

    fn engine_at(&self, address: u64) -> (&Capstone, bool) {
        match &self.thumb {
            Some(thumb) if self.target.is_thumb(address) => (thumb, true),
            _ => (&self.primary, false),
        }
    }

    /// The smallest instruction, which is how far an undecodable one is skipped.
    fn minimum_length(&self, thumb: bool) -> u8 {
        match self.target.arch {
            Arch::Riscv32 | Arch::Riscv64 | Arch::S390x | Arch::M68k => 2,
            Arch::Arm if thumb => 2,
            _ => 4,
        }
    }
}

/// Mnemonics that branch whatever the flags say; any other jump is conditional.
fn unconditional(arch: Arch, mnemonic: &str) -> bool {
    let list: &[&str] = match arch {
        Arch::Mips | Arch::Mips64 => &["j", "b", "jr", "jal", "bal", "jalr", "jr.hb", "jalr.hb"],
        Arch::PowerPc | Arch::PowerPc64 => &["b", "ba", "bl", "bla", "bctr", "bctrl", "blr", "blrl"],
        Arch::Riscv32 | Arch::Riscv64 => &["j", "jal", "jr", "jalr", "ret", "c.j", "c.jal", "c.jr", "c.jalr"],
        Arch::Sparc | Arch::Sparc64 => &["b", "ba", "ba,a", "ba,pt", "ba,a,pt", "jmp", "jmpl", "call", "ret", "retl"],
        Arch::S390x => &["j", "jg", "br", "b", "bras", "brasl", "basr", "bas"],
        Arch::M68k => &["bra", "bra.s", "bra.w", "bra.l", "jmp", "bsr", "jsr", "rts"],
        _ => &[],
    };
    list.contains(&mnemonic)
}

/// Returns that Capstone does not mark as such: ARM `bx lr` and PC pops, MIPS `jr $ra`, PowerPC `blr`.
fn is_return(arch: Arch, mnemonic: &str, operands: &str) -> bool {
    match arch {
        Arch::Arm => {
            mnemonic == "bx" && operands == "lr"
                || (mnemonic == "pop" || mnemonic.starts_with("ldm")) && operands.contains("pc")
                || mnemonic == "mov" && operands == "pc, lr"
        }
        Arch::Mips | Arch::Mips64 => mnemonic == "jr" && operands == "$ra",
        Arch::PowerPc | Arch::PowerPc64 => mnemonic == "blr",
        Arch::Riscv32 | Arch::Riscv64 => mnemonic == "ret" || mnemonic == "c.jr" && operands == "ra",
        Arch::Sparc | Arch::Sparc64 => mnemonic == "ret" || mnemonic == "retl",
        Arch::S390x => mnemonic == "br" && operands == "%r14",
        Arch::M68k => mnemonic == "rts",
        _ => false,
    }
}

impl CapstoneDisassembler {
    fn classify(&self, engine: &Capstone, insn: &Insn, thumb: bool) -> (Flow, Option<u64>) {
        let arch = self.target.arch;
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands_text = insn.op_str().unwrap_or("");
        let Ok(detail) = engine.insn_detail(insn) else { return (Flow::Next, None) };
        let in_group = |group: InsnGroupType::Type| detail.groups().iter().any(|id| u32::from(id.0) == group);
        let arch_detail = detail.arch_detail();
        let operands = arch_detail.operands();
        let immediate = operands.iter().rev().find_map(|operand| match operand {
            ArchOperand::ArmOperand(operand) => match operand.op_type {
                arch::arm::ArmOperandType::Imm(value) => Some(u64::from(value as u32)),
                _ => None,
            },
            ArchOperand::MipsOperand(arch::mips::MipsOperand::Imm(value))
            | ArchOperand::PpcOperand(arch::ppc::PpcOperand::Imm(value))
            | ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(value))
            | ArchOperand::SparcOperand(arch::sparc::SparcOperand::Imm(value))
            | ArchOperand::SysZOperand(arch::sysz::SysZOperand::Imm(value)) => Some(*value as u64),
            _ => None,
        });
        // ARM literal loads: PC reads as the instruction plus 8 (A32) or plus 4, word-aligned (Thumb).
        let data_ref = operands.iter().find_map(|operand| match operand {
            ArchOperand::ArmOperand(operand) => match &operand.op_type {
                arch::arm::ArmOperandType::Mem(memory) if engine.reg_name(memory.base()).as_deref() == Some("pc") => {
                    let pc = if thumb { (insn.address() + 4) & !3 } else { insn.address() + 8 };
                    Some(pc.wrapping_add(i64::from(memory.disp()) as u64))
                }
                _ => None,
            },
            _ => None,
        });

        let condition_always = match &arch_detail {
            capstone::arch::ArchDetail::ArmDetail(arm) => {
                matches!(arm.cc(), arch::arm::ArmCC::ARM_CC_AL | arch::arm::ArmCC::ARM_CC_INVALID)
                    && !mnemonic.starts_with("cb")
            }
            _ => unconditional(arch, mnemonic),
        };

        let flow = if is_return(arch, mnemonic, operands_text) || in_group(InsnGroupType::CS_GRP_RET) {
            if condition_always { Flow::Return } else { Flow::Next }
        } else if in_group(InsnGroupType::CS_GRP_CALL) || mnemonic.starts_with("bl") && arch == Arch::Arm {
            immediate.map_or(Flow::IndirectCall, Flow::Call)
        } else if in_group(InsnGroupType::CS_GRP_JUMP) || in_group(InsnGroupType::CS_GRP_BRANCH_RELATIVE) {
            match (immediate, condition_always) {
                (Some(target), true) => Flow::Jump(target),
                (Some(target), false) => Flow::ConditionalJump(target),
                (None, _) => Flow::IndirectJump,
            }
        } else if matches!(mnemonic, "udf" | "trap" | "illegal") {
            Flow::Halt
        } else {
            Flow::Next
        };
        (flow, data_ref)
    }
}

impl Disassembler for CapstoneDisassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Decoded {
        let (engine, thumb) = self.engine_at(address);
        let invalid =
            Decoded { address, len: self.minimum_length(thumb), flow: Flow::Invalid, data_ref: None, immediate: None };
        let Ok(instructions) = engine.disasm_count(bytes, address, 1) else { return invalid };
        let Some(insn) = instructions.iter().next() else { return invalid };
        let (flow, data_ref) = self.classify(engine, insn, thumb);
        Decoded { address, len: insn.len() as u8, flow, data_ref, immediate: None }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let (engine, _) = self.engine_at(address);
        let Ok(instructions) = engine.disasm_count(bytes, address, 1) else { return "(bad)".to_owned() };
        match instructions.iter().next() {
            Some(insn) => match insn.op_str() {
                Some(operands) if !operands.is_empty() => format!("{} {operands}", insn.mnemonic().unwrap_or("")),
                _ => insn.mnemonic().unwrap_or("").to_owned(),
            },
            None => "(bad)".to_owned(),
        }
    }

    fn delay_slots(&self) -> u8 {
        match self.target.arch {
            Arch::Mips | Arch::Mips64 | Arch::Sparc | Arch::Sparc64 => 1,
            _ => 0,
        }
    }
}
