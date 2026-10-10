//! Capstone-based decoding for the architectures that have no native decoder yet: 32-bit ARM (A32 and Thumb),
//! MIPS, PowerPC, RISC-V, SPARC, z/Architecture and m68k. Capstone decodes and renders instructions; control flow
//! comes from per-architecture mnemonic rules, because Capstone's instruction groups miss many calls and returns
//! and do not say whether a branch is conditional.

use capstone::arch::{self, ArchOperand, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode};
use capstone::{Capstone, Endian, Insn, InsnGroupType};

use crate::track::{self, Tracker};
use crate::{Arch, Disassembler, Flow, Insn as Decoded, Target, UnsupportedArch};

pub struct CapstoneDisassembler {
    target: Target,
    primary: Capstone,
    /// ARM only: a second engine for Thumb code.
    thumb: Option<Capstone>,
    /// Thumb only: the address of the next instruction an IT block covers, and how many it still covers.
    it_block: Option<(u64, usize)>,
    /// Register values, for each engine (their register numbering is the same, but a run never mixes them).
    tracker: Tracker,
    thumb_tracker: Tracker,
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
        let tracker = Tracker::new(target.arch, &primary, target.global_pointer, target.got.clone());
        let thumb_tracker = Tracker::new(target.arch, &primary, target.global_pointer, target.got.clone());
        Ok(Self { target: target.clone(), primary, thumb, it_block: None, tracker, thumb_tracker })
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

/// What a control-flow instruction does, before its target is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A call; `direct` ones name their target as an operand.
    Call {
        direct: bool,
    },
    Jump {
        direct: bool,
    },
    Return,
    Halt,
}

/// An instruction's effect on control flow: `None` for one that falls through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Branch {
    kind: Kind,
    conditional: bool,
}

const fn branch(kind: Kind, conditional: bool) -> Option<Branch> {
    Some(Branch { kind, conditional })
}

const CALL: Kind = Kind::Call { direct: true };
const INDIRECT_CALL: Kind = Kind::Call { direct: false };
const JUMP: Kind = Kind::Jump { direct: true };
const INDIRECT_JUMP: Kind = Kind::Jump { direct: false };

/// ARM, with the condition already stripped from `mnemonic` and reported by `conditional`.
fn arm(mnemonic: &str, operands: &str, conditional: bool) -> Option<Branch> {
    let writes_pc = operands.starts_with("pc,");
    let kind = match mnemonic {
        "bl" | "blx" => CALL,
        "b" => JUMP,
        "cbz" | "cbnz" => return branch(JUMP, true),
        "bx" if operands == "lr" => Kind::Return,
        "bx" | "bxj" | "tbb" | "tbh" => INDIRECT_JUMP,
        "mov" | "movs" if writes_pc && operands == "pc, lr" => Kind::Return,
        "ldr" if operands.starts_with("pc, [sp]") => Kind::Return,
        "mov" | "movs" | "add" | "sub" if writes_pc => INDIRECT_JUMP,
        "ldr" if writes_pc => INDIRECT_JUMP,
        "pop" | "ldm" | "ldmia" | "ldmib" | "ldmda" | "ldmdb" | "ldmfd" if operands.contains("pc}") => Kind::Return,
        "udf" => Kind::Halt,
        _ => return None,
    };
    branch(kind, conditional)
}

fn mips(mnemonic: &str, operands: &str, is_branch: bool) -> Option<Branch> {
    let kind = match mnemonic {
        "jr" | "jr.hb" | "jrc" if operands == "$ra" => Kind::Return,
        "jal" | "bal" | "jalx" | "balc" => CALL,
        "bgezal" | "bltzal" | "bgezall" | "bltzall" => return branch(CALL, true),
        "jalr" | "jalr.hb" | "jalrc" | "jialc" => INDIRECT_CALL,
        "j" | "b" | "bc" => JUMP,
        "jr" | "jr.hb" | "jrc" | "jic" => INDIRECT_JUMP,
        "break" | "sdbbp" => Kind::Halt,
        _ if is_branch => return branch(JUMP, true),
        _ => return None,
    };
    branch(kind, false)
}

/// PowerPC encodes the link (`l`), the count-register target (`ctr`) and the link-register target (`lr`) in the
/// mnemonic, after the condition: `bnelr`, `bdnzl`, `bctrl`.
fn powerpc(mnemonic: &str, is_branch: bool) -> Option<Branch> {
    let mnemonic = mnemonic.trim_end_matches(['+', '-']);
    let unconditional = |plain: &str| mnemonic == plain;
    let kind = match mnemonic {
        "trap" => return branch(Kind::Halt, false),
        _ if !mnemonic.starts_with('b') || !is_branch => return None,
        _ if mnemonic.ends_with("lrl") || mnemonic.ends_with("ctrl") => INDIRECT_CALL,
        _ if mnemonic.ends_with("lr") => return branch(Kind::Return, !unconditional("blr")),
        _ if mnemonic.ends_with("ctr") => return branch(INDIRECT_JUMP, !unconditional("bctr")),
        "bl" | "bla" => CALL,
        "b" | "ba" => JUMP,
        _ if mnemonic.ends_with('l') || mnemonic.ends_with("la") => return branch(CALL, true),
        _ => return branch(JUMP, true),
    };
    branch(kind, false)
}

/// RISC-V: `jal` and `jalr` call when they link through `ra` or `t0`, the ABI's link registers (the one-operand
/// forms link `ra`), and jump otherwise: `j`, `jr`, and PLT stubs' `jalr t1`, which passes a value in `t1`.
fn riscv(mnemonic: &str, operands: &str) -> Option<Branch> {
    let implicit_link = !operands.contains(',') && mnemonic.trim_start_matches("c.").starts_with("jal");
    let links = implicit_link || matches!(operands.split(',').next(), Some("ra" | "t0"));
    let kind = match mnemonic {
        "ret" => Kind::Return,
        "jr" | "c.jr" if operands == "ra" => Kind::Return,
        "j" | "c.j" => JUMP,
        "jr" | "c.jr" => INDIRECT_JUMP,
        "jal" | "c.jal" if links => CALL,
        "jal" | "c.jal" => JUMP,
        "jalr" | "c.jalr" if links => INDIRECT_CALL,
        "jalr" | "c.jalr" => INDIRECT_JUMP,
        "ebreak" | "c.ebreak" | "unimp" | "c.unimp" => Kind::Halt,
        _ if mnemonic.starts_with('b') || mnemonic.starts_with("c.b") => return branch(JUMP, true),
        _ => return None,
    };
    branch(kind, false)
}

/// SPARC branches carry annul and prediction suffixes (`ba,a`, `bne,pt`), stripped from `mnemonic` here.
fn sparc(mnemonic: &str, operands: &str, is_branch: bool) -> Option<Branch> {
    let base = mnemonic.split(',').next().unwrap_or(mnemonic);
    let kind = match base {
        "ret" | "retl" | "rett" | "return" => Kind::Return,
        "call" if operands.starts_with('%') => INDIRECT_CALL,
        "call" => CALL,
        "jmpl" if operands.ends_with("%o7") => INDIRECT_CALL,
        "jmp" | "jmpl" => INDIRECT_JUMP,
        "b" | "ba" | "fba" | "cba" => JUMP,
        "bn" | "fbn" | "cbn" => return None,
        "unimp" | "illtrap" => Kind::Halt,
        _ if is_branch => return branch(JUMP, true),
        _ => return None,
    };
    branch(kind, false)
}

/// z/Architecture: `j`-mnemonics are relative branches, `b`-mnemonics branch to a register (`br`, `ber`) or to
/// memory (`b`, `be`); a condition sits between the prefix and the form letter.
fn s390x(mnemonic: &str, operands: &str, is_branch: bool) -> Option<Branch> {
    let kind = match mnemonic {
        "br" if operands == "%r14" => Kind::Return,
        "brasl" | "bras" => CALL,
        "basr" | "bas" | "balr" | "bal" => INDIRECT_CALL,
        "j" | "jg" => JUMP,
        "br" | "b" => INDIRECT_JUMP,
        "jnop" | "jgnop" | "nop" | "nopr" | "bc" | "bcr" => return None,
        // Compare and branch to a register-based address (`cib`, `crb`); the relative forms end in `j` (`crj`).
        _ if mnemonic.starts_with('c') && !mnemonic.contains('j') => return None,
        // A conditional branch to a register or memory: a conditional return, or a computed branch.
        _ if mnemonic.starts_with('b') && !mnemonic.starts_with("br") => return None,
        _ if is_branch => return branch(JUMP, true),
        _ => return None,
    };
    branch(kind, false)
}

/// m68k, with the size suffix (`.b`, `.w`, `.l`) stripped from `mnemonic`.
fn m68k(mnemonic: &str) -> Option<Branch> {
    let kind = match mnemonic {
        "bsr" => CALL,
        "jsr" => INDIRECT_CALL,
        "bra" => JUMP,
        "jmp" => INDIRECT_JUMP,
        "rts" | "rte" | "rtr" | "rtd" => Kind::Return,
        "illegal" => Kind::Halt,
        _ if mnemonic.starts_with("db") || mnemonic.starts_with('b') && mnemonic.len() == 3 => {
            return branch(JUMP, true);
        }
        _ => return None,
    };
    branch(kind, false)
}

/// ARM condition-code suffixes.
const CONDITIONS: [&str; 15] =
    ["eq", "ne", "hs", "cs", "lo", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt"];

/// `mnemonic` without its width qualifier and, when `conditional`, its condition suffix (`bxeq` to `bx`).
fn arm_base(mnemonic: &str, conditional: bool) -> &str {
    let mnemonic = mnemonic.trim_end_matches(".w").trim_end_matches(".n");
    if !conditional {
        return mnemonic;
    }
    CONDITIONS
        .iter()
        .chain(&["le", "al"])
        .find_map(|condition| mnemonic.strip_suffix(condition))
        .filter(|base| !base.is_empty())
        .unwrap_or(mnemonic)
}

/// The instruction's control flow and, for an ARM PC-relative load, the address it reads. `it_block` tracks the
/// An instruction's control flow; whether it executes only under a condition (ARM); and its mnemonic without
/// ARM's condition and width suffixes.
struct Classified<'a> {
    flow: Flow,
    conditional: bool,
    mnemonic: &'a str,
}

/// Classifies `insn`'s control flow. `it_block` tracks the Thumb IT block it may lie in.
fn classify<'a>(
    arch: Arch,
    it_block: &mut Option<(u64, usize)>,
    engine_is_thumb: bool,
    insn: &'a Insn,
    detail: &capstone::InsnDetail,
) -> Classified<'a> {
    {
        let address = insn.address();
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands_text = insn.op_str().unwrap_or("");
        let is_branch = detail
            .groups()
            .iter()
            .any(|id| matches!(u32::from(id.0), InsnGroupType::CS_GRP_JUMP | InsnGroupType::CS_GRP_BRANCH_RELATIVE));
        let arch_detail = detail.arch_detail();
        let operands = arch_detail.operands();

        let mut mnemonic_base = mnemonic;
        let mut predicated = false;
        let branch = match (arch, &arch_detail) {
            (Arch::Arm, capstone::arch::ArchDetail::ArmDetail(arm_detail)) => {
                let in_it_block = it_block.is_some_and(|(next, left)| next == address && left > 0);
                *it_block = match mnemonic.strip_prefix("it") {
                    Some(pattern) if engine_is_thumb && pattern.len() < 4 => {
                        Some((address + insn.len() as u64, pattern.len() + 1))
                    }
                    _ => it_block.filter(|_| in_it_block).map(|(_, left)| (address + insn.len() as u64, left - 1)),
                };
                let has_condition =
                    !matches!(arm_detail.cc(), arch::arm::ArmCC::ARM_CC_AL | arch::arm::ArmCC::ARM_CC_INVALID);
                mnemonic_base = arm_base(mnemonic, has_condition);
                predicated = has_condition || in_it_block;
                arm(mnemonic_base, operands_text, predicated)
            }
            (Arch::Mips | Arch::Mips64, _) => mips(mnemonic, operands_text, is_branch),
            (Arch::PowerPc | Arch::PowerPc64, _) => powerpc(mnemonic, is_branch),
            (Arch::Riscv32 | Arch::Riscv64, _) => riscv(mnemonic, operands_text),
            (Arch::Sparc | Arch::Sparc64, _) => sparc(mnemonic, operands_text, is_branch),
            (Arch::S390x, _) => s390x(mnemonic, operands_text, is_branch),
            (Arch::M68k, _) => m68k(mnemonic.split('.').next().unwrap_or(mnemonic)),
            _ => None,
        };

        // A direct branch's target is its last immediate or displacement operand.
        let target = operands.iter().rev().find_map(|operand| match operand {
            ArchOperand::ArmOperand(operand) => match operand.op_type {
                arch::arm::ArmOperandType::Imm(value) => Some(u64::from(value as u32)),
                _ => None,
            },
            ArchOperand::MipsOperand(arch::mips::MipsOperand::Imm(value))
            | ArchOperand::PpcOperand(arch::ppc::PpcOperand::Imm(value))
            | ArchOperand::SparcOperand(arch::sparc::SparcOperand::Imm(value))
            | ArchOperand::SysZOperand(arch::sysz::SysZOperand::Imm(value)) => Some(*value as u64),
            // RISC-V immediates are offsets from the branch.
            ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(value)) => {
                Some(address.wrapping_add(*value as u64))
            }
            // m68k displacements count from the end of the opcode word.
            ArchOperand::M68kOperand(arch::m68k::M68kOperand::Displacement(displacement)) => {
                Some(address.wrapping_add(2).wrapping_add(i64::from(displacement.disp) as u64))
            }
            _ => None,
        });

        let next = address + insn.len() as u64;
        let flow = match branch {
            None => Flow::Next,
            Some(Branch { kind, conditional }) => match kind {
                Kind::Halt => Flow::Halt,
                Kind::Return if conditional => Flow::Next,
                Kind::Return => Flow::Return,
                // A call to the next instruction reads the program counter (PowerPC `bcl 20, 31, .+4`).
                Kind::Call { direct: true } if target == Some(next) => Flow::Next,
                Kind::Call { direct: true } => target.map_or(Flow::IndirectCall, Flow::Call),
                Kind::Call { direct: false } => Flow::IndirectCall,
                Kind::Jump { direct: true } => match target {
                    Some(target) if conditional => Flow::ConditionalJump(target),
                    Some(target) => Flow::Jump(target),
                    None if conditional => Flow::Next,
                    None => Flow::IndirectJump,
                },
                Kind::Jump { direct: false } if conditional => Flow::Next,
                Kind::Jump { direct: false } => Flow::IndirectJump,
            },
        };
        Classified { flow, conditional: predicated, mnemonic: mnemonic_base }
    }
}

impl Disassembler for CapstoneDisassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Decoded {
        let (engine, thumb) = match &self.thumb {
            Some(thumb) if self.target.is_thumb(address) => (thumb, true),
            _ => (&self.primary, false),
        };
        let invalid =
            Decoded { address, len: self.minimum_length(thumb), flow: Flow::Invalid, data_ref: None, immediate: None };
        let Ok(instructions) = engine.disasm_count(bytes, address, 1) else { return invalid };
        let Some(insn) = instructions.iter().next() else { return invalid };
        let Ok(detail) = engine.insn_detail(insn) else { return invalid };
        let arch = self.target.arch;
        let Classified { flow, conditional, mnemonic } = classify(arch, &mut self.it_block, thumb, insn, &detail);

        let operands = track::operands(&detail);
        let writes = track::written_registers(arch, mnemonic, &detail, &operands);
        // ARM reads PC as the instruction plus 8 (A32) or plus 4, word-aligned for addressing (Thumb).
        let pc = match (arch, thumb) {
            (Arch::Arm, true) => (address + 4) & !3,
            (Arch::Arm, false) => address + 8,
            _ => address,
        };
        let big_endian = self.target.big_endian;
        let literal = |at: u64| track::word(bytes.get(usize::try_from(at.checked_sub(address)?).ok()?..)?, big_endian);
        let is_call = matches!(flow, Flow::Call(_) | Flow::IndirectCall);
        let tracker = if thumb { &mut self.thumb_tracker } else { &mut self.tracker };
        let found = tracker.step(mnemonic, &operands, &writes, address, pc, conditional, is_call, literal);
        let flow = match (flow, found.branch_target) {
            (Flow::IndirectCall, Some(target)) => Flow::Call(target),
            (Flow::IndirectJump, Some(target)) => Flow::Jump(target),
            (flow, _) => flow,
        };
        Decoded { address, len: insn.len() as u8, flow, data_ref: found.data_ref, immediate: found.immediate }
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

    fn reset(&mut self) {
        self.it_block = None;
        self.tracker.reset();
        self.thumb_tracker.reset();
    }

    fn delay_slots(&self) -> u8 {
        self.target.arch.delay_slots()
    }
}
