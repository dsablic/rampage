//! Addresses that RISC architectures decoded through Capstone build from instruction pairs, followed through
//! registers within a straight-line run: MIPS `lui`/`addiu`, RISC-V `auipc`/`addi`, PowerPC `lis`/`addi`, SPARC
//! `sethi`/`or`, and s390x `larl`. Loads and stores through a known
//! base yield their address, and the ABI's global-pointer register reads as the image's global pointer, so GOT
//! accesses resolve too.
//!
//! MIPS position-independent code computes its global pointer from `$t9`, which holds the function's own address
//! on entry (`lui $v0, %hi(_gp_disp); addiu $v0, $v0, %lo(_gp_disp); addu $s0, $v0, $t9`), and keeps it in a
//! callee-saved register for the whole function. A run that starts at a function entry ([`Tracker::begin_run`])
//! knows `$t9`, and a register found to hold the global pointer stays known across blocks and calls until written.

use capstone::arch::{self, ArchOperand};
use capstone::{Capstone, InsnDetail, RegId};

use crate::{Arch, Got, TargetWidth};

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
    /// The instruction loads from or stores to `data_ref` rather than forming it.
    pub accesses: bool,
    /// A constant it forms that may be an address.
    pub immediate: Option<u64>,
    /// The target of an indirect branch through a known register (RISC-V `auipc`/`jalr`).
    pub branch_target: Option<u64>,
}

pub(crate) struct Tracker {
    arch: Arch,
    register_width: Option<TargetWidth>,
    known: Vec<(u16, Value)>,
    /// The global-pointer register and its value, when the image has one.
    global_pointer: Option<(u16, u64)>,
    got: Option<Got>,
    /// Instructions left before a call made in a delay slot's shadow forgets every register.
    forget_after: Option<u8>,
    /// MIPS: `$t9`, which holds a function's address on entry under the PIC calling convention.
    entry_register: Option<u16>,
    /// MIPS: the registers a callee preserves (`$s0`-`$s7`, `$fp`).
    callee_saved: Vec<u16>,
    /// MIPS: `$sp` and `$fp`, through which a function's stack slots are addressed.
    stack_registers: Vec<u16>,
    /// Values that hold for the rest of the function, whatever block is decoded: the entry `$t9` and registers
    /// holding the global pointer. Each is dropped once written, and a call drops the caller-saved ones.
    sticky: Vec<(u16, Value)>,
    /// The entry of the function being decoded ([`Tracker::begin_function`]), until its first instruction is.
    at_entry: Option<u64>,
    /// Registers loaded from a GOT entry that the dynamic linker fills (an import's), with the entry's address.
    slots: Vec<(u16, u64)>,
    /// MIPS: stack slots (base register and displacement) the function saved its global pointer to, as
    /// unoptimised code does before each call and reloads after it.
    gp_slots: Vec<(u16, i64)>,
    /// Slots this straight-line run can no longer trust: their base register was written, or a store through the
    /// other of `$sp` and `$fp` may have overwritten them. Another block's run trusts them again, since the
    /// function keeps its frame registers fixed between prologue and epilogue.
    run_killed: Vec<(u16, i64)>,
}

fn native_register_width(arch: Arch) -> Option<TargetWidth> {
    match arch {
        Arch::X86 | Arch::Arm | Arch::Mips | Arch::PowerPc | Arch::Riscv32 | Arch::Sparc | Arch::M68k => {
            Some(TargetWidth::Bits32)
        }
        Arch::X86_64 | Arch::Aarch64 | Arch::Mips64 | Arch::PowerPc64 | Arch::Riscv64 | Arch::Sparc64 | Arch::S390x => {
            Some(TargetWidth::Bits64)
        }
        Arch::Msp430
        | Arch::Avr8
        | Arch::Mos6502
        | Arch::Mc6805
        | Arch::I8051
        | Arch::Pic16
        | Arch::Sh2
        | Arch::V850
        | Arch::Tricore
        | Arch::Xtensa
        | Arch::Z80
        | Arch::Hcs12
        | Arch::Cr16c
        | Arch::Ebpf
        | Arch::Loongarch64
        | Arch::Hexagon => None,
    }
}

fn wrap_native(value: u64, width: Option<TargetWidth>) -> Option<u64> {
    match width? {
        TargetWidth::Bits32 => Some(value & 0xffff_ffff),
        TargetWidth::Bits64 => Some(value),
    }
}

pub(crate) fn register_named(engine: &Capstone, name: &str) -> Option<u16> {
    (1..1024u16).find(|&id| engine.reg_name(RegId(id)).as_deref() == Some(name))
}

impl Tracker {
    pub(crate) fn new(arch: Arch, engine: &Capstone, global_pointer: Option<u64>, got: Option<Got>) -> Self {
        let register = match arch {
            Arch::Mips | Arch::Mips64 | Arch::Riscv32 | Arch::Riscv64 => register_named(engine, "gp"),
            Arch::PowerPc64 => register_named(engine, "r2"),
            _ => None,
        };
        let mips = matches!(arch, Arch::Mips | Arch::Mips64);
        let entry_register = if mips { register_named(engine, "t9") } else { None };
        let callee_saved = if mips {
            ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "fp"]
                .into_iter()
                .filter_map(|name| register_named(engine, name))
                .collect()
        } else {
            Vec::new()
        };
        let stack_registers = if mips {
            ["sp", "fp"].into_iter().filter_map(|name| register_named(engine, name)).collect()
        } else {
            Vec::new()
        };
        Self {
            arch,
            register_width: native_register_width(arch),
            known: Vec::new(),
            global_pointer: register.zip(global_pointer),
            got,
            forget_after: None,
            entry_register,
            callee_saved,
            stack_registers,
            sticky: Vec::new(),
            at_entry: None,
            slots: Vec::new(),
            gp_slots: Vec::new(),
            run_killed: Vec::new(),
        }
    }

    /// Forgets what the straight-line run proved; values that hold for the whole function stay.
    pub(crate) fn reset(&mut self) {
        self.run_killed.clear();
        self.known.clear();
        self.slots.clear();
        self.forget_after = None;
        self.known.extend(self.sticky.iter().copied());
    }

    /// Starts an independent run: nothing carries over from another one, and no register is assumed.
    pub(crate) fn begin_run(&mut self) {
        self.sticky.clear();
        self.gp_slots.clear();
        self.reset();
        self.at_entry = None;
    }

    /// Starts decoding the function at `entry`: as [`Tracker::begin_run`], and when the first instruction decoded is
    /// the entry itself, MIPS `$t9` holds its address (the PIC calling convention). A run that starts at a block
    /// inside a function assumes nothing.
    pub(crate) fn begin_function(&mut self, entry: u64) {
        self.begin_run();
        self.at_entry = self.entry_register.map(|_| entry);
    }

    /// The value a register is known to hold, and whether it is certainly an address.
    pub(crate) fn value(&self, register: u16) -> Option<(u64, bool)> {
        self.get(register).map(|value| (value.value, value.address))
    }

    /// Records that `register` now holds `value` (an address formed or loaded by an instruction the caller
    /// decoded itself, such as a MIPS16e PC-relative one), after [`Tracker::step`] has forgotten its old value.
    /// A register found to hold the global pointer keeps it for the rest of the function, as in [`Tracker::step`].
    pub(crate) fn assign(&mut self, register: u16, value: u64, address: bool) {
        let value = Value { value, address };
        self.set(register, value);
        if let Some(wrapped) = self.wrap(value.value) {
            let value = Value { value: wrapped, address };
            if self.is_global_pointer(value) {
                self.sticky.push((register, value));
            }
        }
    }

    /// A call without a delay slot (MIPS16e `jalrc`) has returned: caller-saved registers have changed already.
    pub(crate) fn call_returned(&mut self) {
        self.forget_after = None;
        self.forget_call();
    }

    /// A call: caller-saved registers change, so only the callee-saved function-wide values stay.
    fn forget_call(&mut self) {
        let callee_saved = &self.callee_saved;
        self.sticky.retain(|(register, _)| callee_saved.contains(register));
        self.known.clear();
        self.slots.clear();
        self.known.extend(self.sticky.iter().copied());
    }

    /// Whether `value` is the global pointer, which a register keeps for the rest of the function.
    fn is_global_pointer(&self, value: Value) -> bool {
        value.address
            && self.entry_register.is_some()
            && self.global_pointer.is_some_and(|(_, global)| self.wrap(global) == Some(value.value))
    }

    fn get(&self, register: u16) -> Option<Value> {
        self.register_width?;
        if let Some((gp, value)) = self.global_pointer
            && gp == register
        {
            return Some(Value { value, address: true });
        }
        self.known.iter().find(|(known, _)| *known == register).map(|&(_, value)| value)
    }

    fn set(&mut self, register: u16, value: Value) {
        self.clear(register);
        if let Some(wrapped) = self.wrap(value.value) {
            self.known.push((register, Value { value: wrapped, ..value }));
        }
    }

    fn clear(&mut self, register: u16) {
        self.known.retain(|(known, _)| *known != register);
    }

    /// Registers are 32 bits wide on 32-bit architectures.
    fn wrap(&self, value: u64) -> Option<u64> {
        wrap_native(value, self.register_width)
    }

    /// Sign-extends a 32-bit result, as 64-bit MIPS, RISC-V and PowerPC do for `lui`, `lis` and `addiw`.
    fn extend32(&self, value: u64) -> Option<u64> {
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
        if self.register_width.is_none() {
            self.reset();
            return Found::default();
        }
        if self.at_entry.take() == Some(address)
            && let Some(register) = self.entry_register
            && let Some(value) = self.wrap(address)
        {
            let entry = Value { value, address: true };
            self.set(register, entry);
            self.sticky.push((register, entry));
        }
        let mut found = Found::default();
        // A load or store through a known base: its address.
        for operand in operands {
            if let Operand::Memory { base, index: 0, disp } = *operand
                && let Some(base) = self.get(base)
            {
                found.data_ref = self.wrap(base.value.wrapping_add(disp as u64));
                found.accesses = found.data_ref.is_some();
            }
        }
        let slot_load = self.filled_at_run_time(mnemonic, operands, found.data_ref);
        let result = match self.global_pointer_spill(mnemonic, operands) {
            Some(reload) => Some(reload),
            None => self.result(mnemonic, operands, address, &mut found),
        };
        for &register in writes {
            self.clear(register);
            self.sticky.retain(|(sticky, _)| *sticky != register);
            self.slots.retain(|(slot, _)| *slot != register);
            // A slot is addressed from its base register: once that changes, the offset means another place.
            let moved = self.gp_slots.iter().filter(|(base, _)| *base == register).copied();
            self.run_killed.extend(moved.collect::<Vec<_>>());
        }
        self.slots.extend(slot_load);
        if let Some((register, value)) = result {
            self.set(register, value);
            if self.is_global_pointer(value) {
                self.sticky.push((register, value));
            }
            // Halves of an address (`lui` and its kin) are not reported, nor is a MIPS function's own global
            // pointer, which it computes or reloads and which references nothing.
            if self.complete(mnemonic) && !self.is_global_pointer(value) {
                let value_found = self.wrap(value.value);
                if value.address {
                    found.data_ref = found.data_ref.or(value_found);
                } else {
                    found.immediate = value_found;
                }
            }
        }
        // A call changes registers; with a delay slot, only after the slot's instruction.
        match self.forget_after.take() {
            Some(0) => self.forget_call(),
            Some(left) => self.forget_after = Some(left - 1),
            None => {}
        }
        if is_call {
            match self.arch.delay_slots() {
                0 => self.forget_call(),
                slots => self.forget_after = Some(slots - 1),
            }
        }
        found
    }

    /// Follows the global pointer through the stack in a MIPS function: a pointer-sized store of it records its
    /// slot, and a pointer-sized load from a recorded slot reloads it. A store through the same base that overlaps a
    /// slot forgets it; one through the other of `$sp` and `$fp`, which may alias it, does for the rest of the run.
    fn global_pointer_spill(&mut self, mnemonic: &str, operands: &[Operand]) -> Option<(u16, Value)> {
        self.entry_register?;
        let &[Operand::Register(register), Operand::Memory { base, index: 0, disp }] = operands else { return None };
        let pointer = i64::from(self.arch.default_pointer_size()?);
        if let Some(size) = mips_store_size(mnemonic) {
            let stack = &self.stack_registers;
            self.gp_slots.retain(|&(slot_base, slot_disp)| {
                !(slot_base == base && disp < slot_disp + pointer && slot_disp < disp + size)
            });
            let aliased: Vec<(u16, i64)> = self
                .gp_slots
                .iter()
                .filter(|(slot_base, _)| *slot_base != base && stack.contains(slot_base) && stack.contains(&base))
                .copied()
                .collect();
            self.run_killed.extend(aliased);
            let saved = self.get(register).filter(|&value| self.is_global_pointer(value));
            if size == pointer && saved.is_some() {
                self.gp_slots.push((base, disp));
                self.run_killed.retain(|&killed| killed != (base, disp));
            }
            return None;
        }
        match mnemonic {
            "lw" | "ld" if self.gp_slots.contains(&(base, disp)) && !self.run_killed.contains(&(base, disp)) => {
                let (_, global) = self.global_pointer?;
                Some((register, Value { value: self.wrap(global)?, address: true }))
            }
            _ => None,
        }
    }

    /// For a MIPS load from a GOT entry the dynamic linker fills (an import's, zero in the file), the register
    /// loaded and the entry's address: a call through that register calls the import.
    fn filled_at_run_time(&self, mnemonic: &str, operands: &[Operand], slot: Option<u64>) -> Option<(u16, u64)> {
        let got = self.got.as_ref().filter(|_| self.entry_register.is_some())?;
        let slot = slot.filter(|_| LOADS.contains(&mnemonic))?;
        let width = self.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8))?;
        got.entry(slot, width)?;
        if got.value(slot, width).is_some() {
            return None;
        }
        Some((operands.iter().find_map(register)?, slot))
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
            && let Some(width) = self.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8))
            && let Some(entry) = got.value(slot, width)
        {
            let destination = match self.arch {
                Arch::Sparc | Arch::Sparc64 => operands.iter().rev().find_map(register),
                _ => operands.iter().find_map(register),
            };
            // A MIPS local entry holds a 64 KiB page that `%lo` offsets complete, or the address of a local
            // symbol itself (`lw $a0, %got(main)($gp)`): the latter is the address the code takes, as an x86
            // `lea` forms one, so it is what the instruction references.
            if got.is_local(slot, width) && entry % 0x1_0000 != 0 {
                found.data_ref = Some(entry);
                found.accesses = false;
            }
            return Some((destination?, Value { value: entry, address: true }));
        }
        match (self.arch, mnemonic, operands) {
            (Arch::Mips | Arch::Mips64, "lui", &[R(rt), I(value)]) => {
                Some((rt, constant(self.extend32((value as u64) << 16)?)))
            }
            (Arch::Mips | Arch::Mips64, "addiu" | "daddiu" | "addi" | "daddi", &[R(rt), R(rs), I(value)]) => {
                Some((rt, offset(self.get(rs)?, value)))
            }
            (Arch::Mips | Arch::Mips64, "ori", &[R(rt), R(rs), I(value)]) => Some((rt, or(rs, value)?)),
            (Arch::Mips | Arch::Mips64, "move", &[R(rd), R(rs)]) => Some((rd, self.get(rs)?)),
            // PIC prologues add `$t9` to the distance to the global pointer (`_gp_disp`).
            (Arch::Mips | Arch::Mips64, "addu" | "daddu", &[R(rd), R(rs), R(rt)]) => {
                let (left, right) = (self.get(rs)?, self.get(rt)?);
                let sum = left.value.wrapping_add(right.value);
                let value = if mnemonic == "addu" { self.extend32(sum)? } else { sum };
                Some((rd, Value { value, address: left.address || right.address }))
            }

            (Arch::Riscv32 | Arch::Riscv64, "auipc", &[R(rd), I(value)]) => {
                Some((rd, Value { value: address.wrapping_add(self.extend32((value as u64) << 12)?), address: true }))
            }
            (Arch::Riscv32 | Arch::Riscv64, "lui" | "c.lui", &[R(rd), I(value)]) => {
                Some((rd, constant(self.extend32((value as u64) << 12)?)))
            }
            (Arch::Riscv32 | Arch::Riscv64, "addi", &[R(rd), R(rs), I(value)]) => {
                Some((rd, offset(self.get(rs)?, value)))
            }
            (Arch::Riscv32 | Arch::Riscv64, "addiw", &[R(rd), R(rs), I(value)]) => {
                let base = self.get(rs)?;
                Some((rd, Value { value: self.extend32(base.value.wrapping_add(value as u64))?, ..base }))
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
                if let Some(value) = self.get(base) {
                    found.branch_target = Some(offset(value, disp).value);
                    found.data_ref = None;
                    found.accesses = false;
                } else if let Some(&(_, slot)) = self.slots.iter().find(|(register, _)| *register == base) {
                    // MIPS `lw $t9, %call16(f)($gp); jalr $t9`: a call through the import's GOT entry, as x86's
                    // `call [slot]` is.
                    found.data_ref = Some(slot);
                    found.accesses = true;
                }
                None
            }

            (Arch::PowerPc | Arch::PowerPc64, "lis", &[R(rd), I(value)]) => {
                Some((rd, constant(self.extend32(((value as i16) as i64 as u64) << 16)?)))
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
                found.accesses = true;
                None
            }
            (Arch::S390x, "la" | "lay", &[R(rd), M { base, index: 0, disp }]) => {
                // Load address forms its operand's address without reading it.
                found.accesses = false;
                Some((rd, offset(self.get(base)?, disp)))
            }
            (Arch::S390x, "aghi" | "agfi", &[R(rd), I(value)]) => Some((rd, offset(self.get(rd)?, value))),
            _ => None,
        }
    }
}

/// The bytes a MIPS store writes, or `None` for any other instruction.
fn mips_store_size(mnemonic: &str) -> Option<i64> {
    match mnemonic {
        "sb" => Some(1),
        "sh" => Some(2),
        "sw" | "swl" | "swr" | "sc" | "swc1" | "swc2" => Some(4),
        "sd" | "sdl" | "sdr" | "scd" | "sdc1" | "sdc2" => Some(8),
        _ => None,
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
    // A MIPS store reads its first register (a store-conditional also writes it, with the outcome): a value saved
    // to the stack stays known.
    let mips_store = matches!(arch, Arch::Mips | Arch::Mips64)
        && mnemonic.starts_with('s')
        && !matches!(mnemonic, "sc" | "scd")
        && operands.iter().any(|operand| matches!(operand, Operand::Memory { .. }));
    written.extend(destination.filter(|_| !mips_store));
    if matches!(arch, Arch::PowerPc | Arch::PowerPc64) && (mnemonic.ends_with('u') || mnemonic.ends_with("ux")) {
        written.extend(operands.iter().filter_map(|operand| match *operand {
            Operand::Memory { base, .. } => Some(base),
            _ => None,
        }));
    }
    written
}

#[cfg(test)]
mod width_tests {
    use super::*;

    #[test]
    fn real_pilots_have_no_capstone_native_register_facts() {
        for arch in Arch::ALL.into_iter().skip(14) {
            let width = native_register_width(arch);
            assert_eq!(width, None, "{arch}");
            assert_eq!(wrap_native(u64::MAX, width), None);
        }
    }

    #[test]
    fn missing_register_width_does_not_preserve_a_guessed_64_bit_value() {
        assert_eq!(wrap_native(u64::MAX, None), None);
        assert_eq!(wrap_native(u64::MAX, Some(TargetWidth::Bits32)), Some(u64::from(u32::MAX)));
        assert_eq!(wrap_native(u64::MAX, Some(TargetWidth::Bits64)), Some(u64::MAX));
    }

    #[test]
    fn unknown_register_width_withholds_gp_and_clears_stale_calculations() {
        let mut tracker = Tracker {
            arch: Arch::Mips,
            register_width: None,
            known: vec![(1, Value { value: 0x1234, address: true })],
            global_pointer: Some((2, 0x2000)),
            got: None,
            forget_after: Some(1),
            entry_register: None,
            callee_saved: Vec::new(),
            stack_registers: Vec::new(),
            sticky: Vec::new(),
            at_entry: None,
            slots: Vec::new(),
            gp_slots: Vec::new(),
            run_killed: Vec::new(),
        };
        assert!(tracker.get(1).is_none());
        assert!(tracker.get(2).is_none());
        let found = tracker.step("lw", &[Operand::Memory { base: 2, index: 0, disp: 8 }], &[1], 0x1000, false);
        assert_eq!(found, Found::default());
        assert!(tracker.known.is_empty());
        assert_eq!(tracker.forget_after, None);
    }

    #[test]
    fn known_native_gp_is_not_truncated_before_the_original_arithmetic() {
        let tracker = Tracker {
            arch: Arch::Mips,
            register_width: Some(TargetWidth::Bits32),
            known: Vec::new(),
            global_pointer: Some((2, u64::MAX)),
            got: None,
            forget_after: None,
            entry_register: None,
            callee_saved: Vec::new(),
            stack_registers: Vec::new(),
            sticky: Vec::new(),
            at_entry: None,
            slots: Vec::new(),
            gp_slots: Vec::new(),
            run_killed: Vec::new(),
        };
        assert_eq!(tracker.get(2).unwrap().value, u64::MAX);
        assert_eq!(tracker.wrap(u64::MAX), Some(u64::from(u32::MAX)));
    }
}
