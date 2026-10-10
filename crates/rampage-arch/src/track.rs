//! Addresses that RISC architectures decoded through Capstone build from instruction pairs, followed through
//! registers within a straight-line run: MIPS `lui`/`addiu`, RISC-V `auipc`/`addi`, PowerPC `lis`/`addi`, SPARC
//! `sethi`/`or`, and s390x `larl`. Loads and stores through a known
//! base yield their address, and the ABI's global-pointer register reads as the image's global pointer, so GOT
//! accesses resolve too.

use capstone::arch::{self, ArchOperand};
use capstone::{Capstone, InsnDetail, RegId};

use crate::{Arch, Got};

/// An operand, reduced to what tracking needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Register(u16),
    Immediate(i64),
    Memory { base: u16, index: u16, disp: i64 },
    Other,
}

/// A register's known value. `address` marks values formed relative to the program counter or the global
/// pointer, which are certainly addresses; other constants only may be.
#[derive(Debug, Clone, Copy)]
struct Value {
    value: u64,
    address: bool,
}

/// What tracking learned from one instruction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Found {
    /// An address the instruction reads, writes or forms.
    pub data_ref: Option<u64>,
    /// A constant it forms that may be an address.
    pub immediate: Option<u64>,
    /// The target of an indirect branch through a known register (RISC-V `auipc`/`jalr`).
    pub branch_target: Option<u64>,
}

pub(crate) struct Tracker {
    arch: Arch,
    known: Vec<(u16, Value)>,
    /// The global-pointer register and its value, when the image has one.
    global_pointer: Option<(u16, u64)>,
    got: Option<Got>,
    /// Instructions left before a call made in a delay slot's shadow forgets every register.
    forget_after: Option<u8>,
}

fn register_named(engine: &Capstone, name: &str) -> Option<u16> {
    (1..1024u16).find(|&id| engine.reg_name(RegId(id)).as_deref() == Some(name))
}

impl Tracker {
    pub(crate) fn new(arch: Arch, engine: &Capstone, global_pointer: Option<u64>, got: Option<Got>) -> Self {
        let register = match arch {
            Arch::Mips | Arch::Mips64 | Arch::Riscv32 | Arch::Riscv64 => register_named(engine, "gp"),
            Arch::PowerPc64 => register_named(engine, "r2"),
            _ => None,
        };
        Self { arch, known: Vec::new(), global_pointer: register.zip(global_pointer), got, forget_after: None }
    }

    pub(crate) fn reset(&mut self) {
        self.known.clear();
        self.forget_after = None;
    }

    fn get(&self, register: u16) -> Option<Value> {
        if let Some((gp, value)) = self.global_pointer
            && gp == register
        {
            return Some(Value { value, address: true });
        }
        self.known.iter().find(|(known, _)| *known == register).map(|&(_, value)| value)
    }

    fn set(&mut self, register: u16, value: Value) {
        let value = Value { value: self.wrap(value.value), ..value };
        self.clear(register);
        self.known.push((register, value));
    }

    fn clear(&mut self, register: u16) {
        self.known.retain(|(known, _)| *known != register);
    }

    /// Registers are 32 bits wide on 32-bit architectures.
    fn wrap(&self, value: u64) -> u64 {
        if self.arch.pointer_size() == 4 { value & 0xffff_ffff } else { value }
    }

    /// Sign-extends a 32-bit result, as 64-bit MIPS, RISC-V and PowerPC do for `lui`, `lis` and `addiw`.
    fn extend32(&self, value: u64) -> u64 {
        self.wrap(value as u32 as i32 as i64 as u64)
    }

    /// Follows the instruction at `address`. `operands` are its reduced operands and `writes` the registers it
    /// changes.
    pub(crate) fn step(
        &mut self,
        mnemonic: &str,
        operands: &[Operand],
        writes: &[u16],
        address: u64,
        is_call: bool,
    ) -> Found {
        let mut found = Found::default();
        // A load or store through a known base: its address.
        for operand in operands {
            if let Operand::Memory { base, index: 0, disp } = *operand
                && let Some(base) = self.get(base)
            {
                found.data_ref = Some(self.wrap(base.value.wrapping_add(disp as u64)));
            }
        }
        let result = self.result(mnemonic, operands, address, &mut found);
        for &register in writes {
            self.clear(register);
        }
        if let Some((register, value)) = result {
            self.set(register, value);
            // Halves of an address (`lui` and its kin) are not reported.
            if self.complete(mnemonic) {
                let value_found = Some(self.wrap(value.value));
                if value.address {
                    found.data_ref = found.data_ref.or(value_found);
                } else {
                    found.immediate = value_found;
                }
            }
        }
        // A call changes registers; with a delay slot, only after the slot's instruction.
        match self.forget_after.take() {
            Some(0) => self.known.clear(),
            Some(left) => self.forget_after = Some(left - 1),
            None => {}
        }
        if is_call {
            match self.arch.delay_slots() {
                0 => self.known.clear(),
                slots => self.forget_after = Some(slots - 1),
            }
        }
        found
    }

    /// Whether `mnemonic` finishes forming a constant (rather than starting one, as `lui` does; PowerPC64's
    /// `addis` adds the high half of a TOC offset).
    fn complete(&self, mnemonic: &str) -> bool {
        !matches!(mnemonic, "lui" | "c.lui" | "lis" | "addis" | "sethi" | "auipc")
    }

    /// The register the instruction sets to a known value, and that value.
    fn result(&self, mnemonic: &str, operands: &[Operand], address: u64, found: &mut Found) -> Option<(u16, Value)> {
        use Operand::{Immediate as I, Memory as M, Register as R};
        let constant = |value: u64| Value { value, address: false };
        let offset = |base: Value, delta: i64| Value { value: base.value.wrapping_add(delta as u64), ..base };
        let or = |register, value| {
            let base = self.get(register)?;
            Some(Value { value: base.value | value as u64, ..base })
        };
        // A load from the GOT: the address stored there.
        if let Some(got) = &self.got
            && let Some(slot) = found.data_ref
            && LOADS.contains(&mnemonic)
            && let Some(entry) = got.entry(slot, self.arch.pointer_size()).filter(|&entry| entry != 0)
        {
            let destination = match self.arch {
                Arch::Sparc | Arch::Sparc64 => operands.iter().rev().find_map(register),
                _ => operands.iter().find_map(register),
            };
            return Some((destination?, Value { value: entry, address: true }));
        }
        match (self.arch, mnemonic, operands) {
            (Arch::Mips | Arch::Mips64, "lui", &[R(rt), I(value)]) => {
                Some((rt, constant(self.extend32((value as u64) << 16))))
            }
            (Arch::Mips | Arch::Mips64, "addiu" | "daddiu" | "addi" | "daddi", &[R(rt), R(rs), I(value)]) => {
                Some((rt, offset(self.get(rs)?, value)))
            }
            (Arch::Mips | Arch::Mips64, "ori", &[R(rt), R(rs), I(value)]) => Some((rt, or(rs, value)?)),
            (Arch::Mips | Arch::Mips64, "move", &[R(rd), R(rs)]) => Some((rd, self.get(rs)?)),

            (Arch::Riscv32 | Arch::Riscv64, "auipc", &[R(rd), I(value)]) => {
                Some((rd, Value { value: address.wrapping_add(self.extend32((value as u64) << 12)), address: true }))
            }
            (Arch::Riscv32 | Arch::Riscv64, "lui" | "c.lui", &[R(rd), I(value)]) => {
                Some((rd, constant(self.extend32((value as u64) << 12))))
            }
            (Arch::Riscv32 | Arch::Riscv64, "addi", &[R(rd), R(rs), I(value)]) => {
                Some((rd, offset(self.get(rs)?, value)))
            }
            (Arch::Riscv32 | Arch::Riscv64, "addiw", &[R(rd), R(rs), I(value)]) => {
                let base = self.get(rs)?;
                Some((rd, Value { value: self.extend32(base.value.wrapping_add(value as u64)), ..base }))
            }
            (Arch::Riscv32 | Arch::Riscv64, "addi" | "c.addi", &[R(rd), I(value)]) => {
                Some((rd, offset(self.get(rd)?, value)))
            }
            (Arch::Riscv32 | Arch::Riscv64, "mv" | "c.mv", &[R(rd), R(rs)]) => Some((rd, self.get(rs)?)),
            // A far call or jump through a register holding a known address: RISC-V `auipc` then `jalr`, or MIPS
            // `jalr $t9` after loading `$t9` from the GOT.
            (
                Arch::Riscv32 | Arch::Riscv64 | Arch::Mips | Arch::Mips64,
                "jalr" | "c.jalr" | "jr" | "c.jr" | "jalr.hb" | "jr.hb",
                operands,
            ) => {
                let (base, disp) = match *operands {
                    [R(base)] | [R(_), R(base)] => (base, 0),
                    [R(_), R(base), I(disp)] | [R(_), M { base, index: 0, disp }] => (base, disp),
                    _ => return None,
                };
                found.branch_target = Some(offset(self.get(base)?, disp).value);
                found.data_ref = None;
                None
            }

            (Arch::PowerPc | Arch::PowerPc64, "lis", &[R(rd), I(value)]) => {
                Some((rd, constant(self.extend32(((value as i16) as i64 as u64) << 16))))
            }
            (Arch::PowerPc | Arch::PowerPc64, "addis", &[R(rd), R(ra), I(value)]) => {
                Some((rd, offset(self.get(ra)?, ((value as i16) as i64) << 16)))
            }
            (Arch::PowerPc | Arch::PowerPc64, "addi", &[R(rd), R(ra), I(value)]) => {
                Some((rd, offset(self.get(ra)?, (value as i16) as i64)))
            }
            (Arch::PowerPc | Arch::PowerPc64, "ori", &[R(rd), R(ra), I(value)]) => Some((rd, or(ra, value)?)),
            (Arch::PowerPc | Arch::PowerPc64, "mr", &[R(rd), R(rs)]) => Some((rd, self.get(rs)?)),

            (Arch::Sparc | Arch::Sparc64, "sethi", &[I(value), R(rd)]) => Some((rd, constant((value as u64) << 10))),
            (Arch::Sparc | Arch::Sparc64, "or", &[R(rs), I(value), R(rd)]) => Some((rd, or(rs, value)?)),
            (Arch::Sparc | Arch::Sparc64, "add", &[R(rs), I(value), R(rd)]) => Some((rd, offset(self.get(rs)?, value))),

            (Arch::S390x, "larl", &[R(rd), I(value)]) => Some((rd, Value { value: value as u64, address: true })),
            (
                Arch::S390x,
                "lgrl" | "lrl" | "lgfrl" | "llgfrl" | "lhrl" | "lghrl" | "stgrl" | "strl",
                &[_, I(value)],
            ) => {
                found.data_ref = Some(value as u64);
                None
            }
            (Arch::S390x, "la" | "lay", &[R(rd), M { base, index: 0, disp }]) => {
                Some((rd, offset(self.get(base)?, disp)))
            }
            (Arch::S390x, "aghi" | "agfi", &[R(rd), I(value)]) => Some((rd, offset(self.get(rd)?, value))),
            _ => None,
        }
    }
}

/// Pointer-sized loads, whose destination can take a GOT entry's value.
const LOADS: [&str; 7] = ["lw", "ld", "lwz", "ldr", "ldx", "lg", "l"];

fn register(operand: &Operand) -> Option<u16> {
    match *operand {
        Operand::Register(register) => Some(register),
        _ => None,
    }
}

/// Reduces Capstone's operands for tracking.
pub(crate) fn operands(detail: &InsnDetail) -> Vec<Operand> {
    detail
        .arch_detail()
        .operands()
        .into_iter()
        .map(|operand| match operand {
            ArchOperand::MipsOperand(arch::mips::MipsOperand::Reg(register))
            | ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Reg(register))
            | ArchOperand::PpcOperand(arch::ppc::PpcOperand::Reg(register))
            | ArchOperand::SparcOperand(arch::sparc::SparcOperand::Reg(register))
            | ArchOperand::SysZOperand(arch::sysz::SysZOperand::Reg(register)) => Operand::Register(register.0),
            ArchOperand::MipsOperand(arch::mips::MipsOperand::Imm(value))
            | ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(value))
            | ArchOperand::PpcOperand(arch::ppc::PpcOperand::Imm(value))
            | ArchOperand::SparcOperand(arch::sparc::SparcOperand::Imm(value))
            | ArchOperand::SysZOperand(arch::sysz::SysZOperand::Imm(value)) => Operand::Immediate(value),
            ArchOperand::MipsOperand(arch::mips::MipsOperand::Mem(memory)) => {
                Operand::Memory { base: memory.base().0, index: 0, disp: memory.disp() }
            }
            ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Mem(memory)) => {
                Operand::Memory { base: memory.base().0, index: 0, disp: memory.disp() }
            }
            ArchOperand::PpcOperand(arch::ppc::PpcOperand::Mem(memory)) => {
                Operand::Memory { base: memory.base().0, index: 0, disp: i64::from(memory.disp()) }
            }
            ArchOperand::SparcOperand(arch::sparc::SparcOperand::Mem(memory)) => {
                Operand::Memory { base: memory.base().0, index: memory.index().0, disp: i64::from(memory.disp()) }
            }
            ArchOperand::SysZOperand(arch::sysz::SysZOperand::Mem(memory)) => Operand::Memory {
                base: u16::from(memory.base()),
                index: u16::from(memory.index()),
                disp: memory.disp(),
            },
            _ => Operand::Other,
        })
        .collect()
}

/// The registers an instruction changes: those Capstone reports, and its destination, the first register operand
/// (the last on SPARC); stores harmlessly forget their source. PowerPC update forms also change their base.
pub(crate) fn written_registers(arch: Arch, mnemonic: &str, detail: &InsnDetail, operands: &[Operand]) -> Vec<u16> {
    let mut written: Vec<u16> = detail.regs_write().iter().map(|register| register.0).collect();
    let mut registers = operands.iter().filter_map(register);
    let destination =
        if matches!(arch, Arch::Sparc | Arch::Sparc64) { registers.next_back() } else { registers.next() };
    written.extend(destination);
    if matches!(arch, Arch::PowerPc | Arch::PowerPc64) && (mnemonic.ends_with('u') || mnemonic.ends_with("ux")) {
        written.extend(operands.iter().filter_map(|operand| match *operand {
            Operand::Memory { base, .. } => Some(base),
            _ => None,
        }));
    }
    written
}
