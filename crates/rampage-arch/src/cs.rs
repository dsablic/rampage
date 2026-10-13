//! Capstone-based decoding for the architectures that have no native decoder yet: MIPS, PowerPC, RISC-V,
//! SPARC, z/Architecture and m68k. Capstone decodes and renders instructions; control flow
//! comes from per-architecture mnemonic rules, because Capstone's instruction groups miss many calls and returns
//! and do not say whether a branch is conditional.

use capstone::arch::{self, ArchOperand, BuildsCapstone, BuildsCapstoneEndian, BuildsCapstoneExtraMode};
use capstone::{Capstone, Endian, Insn, InsnGroupType};

use crate::track::{self, Tracker};
use crate::{Arch, Disassembler, Flow, Insn as Decoded, Target, UnsupportedArch};

pub struct CapstoneDisassembler {
    target: Target,
    engine: Capstone,
    /// Register values known within a straight-line run.
    tracker: Tracker,
}

fn engine(arch: Arch, big_endian: bool) -> Option<Capstone> {
    let endian = if big_endian { Endian::Big } else { Endian::Little };
    let built = match arch {
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
        Arch::X86 | Arch::X86_64 | Arch::Aarch64 | Arch::Arm => return None,
    };
    built.ok()
}

impl CapstoneDisassembler {
    pub fn new(target: &Target) -> Result<Self, UnsupportedArch> {
        let engine = engine(target.arch, target.big_endian).ok_or(UnsupportedArch(target.arch))?;
        let tracker = Tracker::new(target.arch, &engine, target.global_pointer, target.got.clone());
        Ok(Self { target: target.clone(), engine, tracker })
    }

    /// The smallest instruction, which is how far an undecodable one is skipped.
    fn minimum_length(&self) -> u8 {
        match self.target.arch {
            Arch::Riscv32 | Arch::Riscv64 | Arch::S390x | Arch::M68k => 2,
            _ => 4,
        }
    }

    /// Whether the code at `target`, which a call at `address` (whose bytes start `bytes`) links to, takes the
    /// return address as a value: the get-PC idioms `bal 1f; nop; 1: addu $gp, $gp, $ra`, `bl 1f; 1: mflr r30`
    /// and `call 1f; nop; 1: add %o7, %l7, %l7`. A callee saves it instead, or returns through it.
    fn reads_link(&self, bytes: &[u8], address: u64, target: u64) -> bool {
        let mut at = target;
        for _ in 0..LINK_READ_WINDOW {
            let offset = at.checked_sub(address).and_then(|offset| usize::try_from(offset).ok());
            let Some(code) = offset.and_then(|offset| bytes.get(offset..)) else { return false };
            let Ok(instructions) = self.engine.disasm_count(code, at, 1) else { return false };
            let Some(insn) = instructions.iter().next() else { return false };
            let Ok(detail) = self.engine.insn_detail(insn) else { return false };
            if classify(self.target.arch, insn, &detail) != (Flow::Next, false) {
                return false;
            }
            match link_use(self.target.arch, insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or("")) {
                LinkUse::Read => return true,
                LinkUse::Clobber => return false,
                LinkUse::Neither => at = at.wrapping_add(insn.len() as u64),
            }
        }
        false
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
        _ if mnemonic.ends_with("lrl") || mnemonic.ends_with("ctrl") => {
            return branch(INDIRECT_CALL, !unconditional("blrl") && !unconditional("bctrl"));
        }
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
        // Compare and branch to a register-based address (`cib`, `crb`; the relative forms end in `j`, `crj`), and a
        // conditional branch to a register or memory (`ber`, `be`): a conditional return through %r14, or a
        // computed branch.
        _ if mnemonic.starts_with('c') && !mnemonic.contains('j')
            || mnemonic.starts_with('b') && !mnemonic.starts_with("br") =>
        {
            return is_branch.then(|| {
                let returns = operands == "%r14" || operands.ends_with(" 0(%r14)");
                Branch { kind: if returns { Kind::Return } else { INDIRECT_JUMP }, conditional: true }
            });
        }
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

/// Classifies `insn`'s control flow, and whether it is a conditional transfer ([`Decoded::conditional`]).
fn classify(arch: Arch, insn: &Insn, detail: &capstone::InsnDetail) -> (Flow, bool) {
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

        let branch = match arch {
            Arch::Mips | Arch::Mips64 => mips(mnemonic, operands_text, is_branch),
            Arch::PowerPc | Arch::PowerPc64 => powerpc(mnemonic, is_branch),
            Arch::Riscv32 | Arch::Riscv64 => riscv(mnemonic, operands_text),
            Arch::Sparc | Arch::Sparc64 => sparc(mnemonic, operands_text, is_branch),
            Arch::S390x => s390x(mnemonic, operands_text, is_branch),
            Arch::M68k => m68k(mnemonic.split('.').next().unwrap_or(mnemonic)),
            _ => None,
        };

        // A direct branch's target is its last immediate or displacement operand.
        let target = operands.iter().rev().find_map(|operand| match operand {
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

        match branch {
            None => (Flow::Next, false),
            Some(Branch { kind, conditional }) => {
                let kind = match kind {
                    Kind::Halt => crate::flow::Kind::Halt,
                    Kind::Return => crate::flow::Kind::Return,
                    Kind::Call { direct } => crate::flow::Kind::Call(target.filter(|_| direct)),
                    Kind::Jump { direct } => crate::flow::Kind::Jump(target.filter(|_| direct)),
                };
                (kind.flow(conditional), kind.is_conditional_transfer(conditional))
            }
        }
    }
}

/// How many instructions at a call's target are searched for a read of the return address.
const LINK_READ_WINDOW: usize = 4;

/// What one instruction does with the return address in the link register, judged by its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkUse {
    /// Takes it as a value: the code is reading the PC.
    Read,
    /// Saves or overwrites it, as a callee's prologue does.
    Clobber,
    Neither,
}

fn link_use(arch: Arch, mnemonic: &str, operands: &str) -> LinkUse {
    let operands: Vec<&str> = operands.split(", ").collect();
    let (link, destination_last) = match arch {
        Arch::Mips | Arch::Mips64 => ("$ra", false),
        Arch::Sparc | Arch::Sparc64 => ("%o7", true),
        Arch::PowerPc | Arch::PowerPc64 => {
            // A prologue saves the link register through r0, which cannot serve as a base register.
            return match mnemonic {
                "mflr" if operands != ["r0"] => LinkUse::Read,
                "mflr" | "mtlr" => LinkUse::Clobber,
                _ => LinkUse::Neither,
            };
        }
        _ => return LinkUse::Neither,
    };
    if mnemonic == "save" {
        return LinkUse::Clobber;
    }
    let Some(position) = operands.iter().position(|operand| *operand == link) else { return LinkUse::Neither };
    let is_store = mnemonic.starts_with('s') && operands.iter().any(|operand| operand.contains(['(', '[']));
    let destination = if destination_last { operands.len() - 1 } else { 0 };
    if is_store || position == destination { LinkUse::Clobber } else { LinkUse::Read }
}

impl Disassembler for CapstoneDisassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Decoded {
        let invalid = Decoded {
            address,
            len: self.minimum_length(),
            flow: Flow::Invalid,
            data_ref: None,
            immediate: None,
            conditional: false,
        };
        let Ok(instructions) = self.engine.disasm_count(bytes, address, 1) else { return invalid };
        let Some(insn) = instructions.iter().next() else { return invalid };
        let Ok(detail) = self.engine.insn_detail(insn) else { return invalid };
        let arch = self.target.arch;
        let mnemonic = insn.mnemonic().unwrap_or("");
        // Execution continues after the delay slot, whose instruction is as long as the branch's (MIPS, SPARC).
        let next = address.wrapping_add(insn.len() as u64 * (1 + u64::from(arch.delay_slots())));
        let (classified, conditional) = classify(arch, insn, &detail);
        let flow = match classified {
            // `bcl 20, 31, .+4` is the form the ISA reserves for reading the PC (Capstone may print it as a
            // conditional `bdnzl`); no call to a function is a conditional branch to the next instruction.
            Flow::Call(target)
                if target == next && matches!(arch, Arch::PowerPc | Arch::PowerPc64) && mnemonic != "bl" =>
            {
                Flow::Next
            }
            Flow::Call(target) if target == next && self.reads_link(bytes, address, target) => Flow::Next,
            flow => flow,
        };
        let operands = track::operands(&detail);
        let writes = track::written_registers(arch, mnemonic, &detail, &operands);
        let is_call = matches!(flow, Flow::Call(_) | Flow::IndirectCall);
        let found = self.tracker.step(mnemonic, &operands, &writes, address, is_call);
        let flow = match (flow, found.branch_target) {
            (Flow::IndirectCall, Some(target)) => Flow::Call(target),
            (Flow::IndirectJump, Some(target)) => Flow::Jump(target),
            (flow, _) => flow,
        };
        Decoded {
            address,
            len: insn.len() as u8,
            flow,
            data_ref: found.data_ref,
            immediate: found.immediate,
            // A get-PC call is no call at all.
            conditional: conditional && (classified == Flow::Next || flow != Flow::Next),
        }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let Ok(instructions) = self.engine.disasm_count(bytes, address, 1) else { return "(bad)".to_owned() };
        let Some(insn) = instructions.iter().next() else { return "(bad)".to_owned() };
        let mnemonic = insn.mnemonic().unwrap_or("");
        let mut operands = insn.op_str().unwrap_or("").to_owned();
        // Capstone prints a RISC-V branch's target as its offset from the branch; show the address, as elsewhere.
        if matches!(self.target.arch, Arch::Riscv32 | Arch::Riscv64)
            && let Ok(detail) = self.engine.insn_detail(insn)
            && let (Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target), _) =
                classify(self.target.arch, insn, &detail)
        {
            let kept = operands.rfind(", ").map_or("", |at| &operands[..at + 2]);
            operands = format!("{kept}{target:#x}");
        }
        if operands.is_empty() { mnemonic.to_owned() } else { format!("{mnemonic} {operands}") }
    }

    fn reset(&mut self) {
        self.tracker.reset();
    }

    fn delay_slots(&self) -> u8 {
        self.target.arch.delay_slots()
    }
}
