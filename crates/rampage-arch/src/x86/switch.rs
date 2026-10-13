//! Switch jump tables behind x86 indirect jumps.
//!
//! Along a straight-line run this follows which general-purpose registers hold a known address (`lea r,
//! [rip+table]`), an index bounded by `cmp r, imm` directly followed by `ja`/`jae` (or masked by `and r, imm`), and
//! a table entry loaded with such an index, possibly added to a known address. A jump through such an entry, or
//! through memory indexed by a bounded register, dispatches through a [`JumpTable`].

use iced_x86::{ConditionCode, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::{JumpTable, MAX_JUMP_TABLE_ENTRIES};

const REGISTERS: usize = 16;

#[derive(Clone, Copy)]
struct Bound {
    max: u64,
    /// Whether the bound covers the whole register rather than only its 32-bit view.
    wide: bool,
    guard: u64,
}

#[derive(Clone, Copy)]
struct Compare {
    register: usize,
    limit: u64,
    wide: bool,
    address: u64,
}

#[derive(Default)]
pub struct Registers {
    /// Registers whose upper 32 bits a write to their 32-bit view zeroed.
    upper_zero: u16,
    known: [Option<u64>; REGISTERS],
    bounds: [Option<Bound>; REGISTERS],
    /// Registers holding a switch-table entry, or a target formed by adding one to a known address.
    entries: [Option<JumpTable>; REGISTERS],
    /// The comparison of a register with an immediate that the previous instruction made.
    compare: Option<Compare>,
}

/// The index of the general-purpose register `register` is part of.
fn gpr(register: Register) -> Option<usize> {
    let full = register.full_register();
    full.is_gpr64().then(|| full.number())
}

/// The immediate second operand of a 32- or 64-bit arithmetic instruction.
fn immediate(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.op1_kind(),
        OpKind::Immediate8to32 | OpKind::Immediate32 | OpKind::Immediate8to64 | OpKind::Immediate32to64
    )
    .then(|| instruction.immediate(1))
}

fn writes(access: OpAccess) -> bool {
    matches!(access, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
}

impl Registers {
    /// Tracks `instruction` and returns the bounded table it jumps through, if it is such an indirect jump.
    pub fn step(
        &mut self,
        instruction: &Instruction,
        bitness: u32,
        info: &mut InstructionInfoFactory,
    ) -> Option<JumpTable> {
        let pointer = if bitness == 64 { 8 } else { 4 };
        let compare = self.compare.take();
        let jump_table = (instruction.mnemonic() == Mnemonic::Jmp)
            .then(|| match instruction.op0_kind() {
                OpKind::Register => self
                    .entries
                    .get(gpr(instruction.op0_register())?)
                    .copied()
                    .flatten()
                    .filter(|table| table.base.is_some() || table.entry_size == pointer),
                OpKind::Memory => self.table_load(instruction, pointer, false),
                _ => None,
            })
            .flatten();

        let mut bound = None;
        let mut known = None;
        let mut entry = None;
        let destination = (instruction.op_count() > 0 && instruction.op0_kind() == OpKind::Register)
            .then(|| instruction.op0_register());
        let source = (instruction.op_count() > 1 && instruction.op1_kind() == OpKind::Register)
            .then(|| instruction.op1_register());
        let size = |register: Register| register.size() as u32 * 8;
        match (instruction.mnemonic(), destination, source) {
            (Mnemonic::Ja | Mnemonic::Jae, ..) => {
                // A `ja` or `jae` straight after `cmp r, limit` falls through only when r is within the limit.
                bound = compare.and_then(|compare| {
                    let max = match instruction.condition_code() {
                        ConditionCode::a => compare.limit,
                        ConditionCode::ae => compare.limit.checked_sub(1)?,
                        _ => return None,
                    };
                    Some((compare.register, Bound { max, wide: compare.wide, guard: compare.address }))
                });
            }
            (Mnemonic::And, Some(register), None) if matches!(size(register), 32 | 64) => {
                // The mask bounds the whole register: a 32-bit `and` zeroes the upper half.
                bound = immediate(instruction).zip(gpr(register)).map(|(mask, index)| {
                    let max = if size(register) == 32 { mask & 0xffff_ffff } else { mask };
                    (index, Bound { max, wide: true, guard: instruction.ip() })
                });
            }
            (Mnemonic::Mov, Some(to_register), Some(from_register))
                if size(to_register) == size(from_register) && matches!(size(to_register), 32 | 64) =>
            {
                if let (Some(to), Some(from)) = (gpr(to_register), gpr(from_register)) {
                    // A 32-bit copy zero-extends the bounded 32-bit view into the whole register.
                    let zero_extends = size(to_register) == 32;
                    bound = self.bounds[from].map(|bound| (to, Bound { wide: bound.wide || zero_extends, ..bound }));
                    if size(to_register) == bitness {
                        known = self.known[from].map(|address| (to, address));
                        entry = self.entries[from].map(|table| (to, table));
                    }
                }
            }
            (Mnemonic::Movsxd, Some(to), Some(from)) if matches!(size(to), 32 | 64) && size(from) == 32 => {
                bound = gpr(from).zip(gpr(to)).and_then(|(from, to)| {
                    let bound = self.bounds[from].filter(|bound| bound.max < 1 << 31)?;
                    Some((to, Bound { wide: true, ..bound }))
                });
            }
            (Mnemonic::Lea, Some(to), _) if size(to) == bitness && instruction.is_ip_rel_memory_operand() => {
                known = gpr(to).map(|to| (to, instruction.ip_rel_memory_address()));
            }
            (Mnemonic::Movsxd | Mnemonic::Mov, Some(to), None) if instruction.op1_kind() == OpKind::Memory => {
                let signed = instruction.mnemonic() == Mnemonic::Movsxd;
                entry = self.table_load(instruction, pointer, signed).and_then(|table| {
                    let entry_size = u32::from(table.entry_size) * 8;
                    let fits = if signed { size(to) == 64 } else { size(to) == entry_size.max(32) };
                    fits.then_some((gpr(to)?, table))
                });
            }
            (Mnemonic::Add, Some(to), Some(from)) if size(to) == bitness && size(from) == bitness => {
                if let (Some(to), Some(from)) = (gpr(to), gpr(from)) {
                    let relative = |entry: Option<JumpTable>, base: Option<u64>| {
                        let table = entry.filter(|table| table.base.is_none())?;
                        Some(JumpTable { base: Some(base?), ..table })
                    };
                    entry = relative(self.entries[to], self.known[from])
                        .or_else(|| relative(self.entries[from], self.known[to]))
                        .map(|table| (to, table));
                }
            }
            _ => {}
        }
        let bound = bound.filter(|(_, bound)| bound.max < MAX_JUMP_TABLE_ENTRIES);

        if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Syscall | Mnemonic::Sysenter) {
            *self = Self::default();
        } else {
            let info = info.info(instruction);
            for used in info.used_registers() {
                if let Some(index) = gpr(used.register()).filter(|_| writes(used.access())) {
                    self.clear(index);
                }
            }
            let narrow = destination.filter(|&register| bitness == 64 && register.is_gpr32());
            if let Some(index) = narrow.and_then(gpr).filter(|_| writes(info.op0_access())) {
                self.upper_zero |= 1 << index;
            }
        }
        if let Some((index, bound)) = bound {
            self.bounds[index] = Some(bound);
        }
        if let Some((index, address)) = known {
            self.known[index] = Some(address);
        }
        if let Some((index, table)) = entry {
            self.entries[index] = Some(table);
        }

        if instruction.mnemonic() == Mnemonic::Cmp
            && let Some(register) = destination.filter(|&register| matches!(size(register), 32 | 64))
            && let Some(limit) = immediate(instruction)
            && let Some(index) = gpr(register)
        {
            let narrow = size(register) == 32;
            let limit = if narrow { limit & 0xffff_ffff } else { limit };
            let wide = !narrow || bitness == 32 || self.upper_zero & (1 << index) != 0;
            self.compare = Some(Compare { register: index, limit, wide, address: instruction.ip() });
        }
        jump_table
    }

    fn clear(&mut self, index: usize) {
        self.upper_zero &= !(1 << index);
        self.known[index] = None;
        self.bounds[index] = None;
        self.entries[index] = None;
    }

    /// The table a memory operand reads entries from: pointer-sized for a jump or `mov`, 4 bytes for `movsxd` or a
    /// 32-bit `mov` in 64-bit code. The index must be bounded over its whole register and scaled by the entry size,
    /// and the base, if any, must hold a known address.
    fn table_load(&self, instruction: &Instruction, pointer: u8, signed: bool) -> Option<JumpTable> {
        let entry_size = u8::try_from(instruction.memory_size().size()).ok()?;
        if signed && entry_size != 4 || !matches!(entry_size, 4 | 8) || entry_size > pointer {
            return None;
        }
        if matches!(instruction.memory_segment(), Register::FS | Register::GS) || instruction.is_ip_rel_memory_operand()
        {
            return None;
        }
        let index = instruction.memory_index();
        if index.size() != usize::from(pointer) || instruction.memory_index_scale() != u32::from(entry_size) {
            return None;
        }
        let bound = self.bounds[gpr(index)?].filter(|bound| bound.wide)?;
        let base = match instruction.memory_base() {
            Register::None => 0,
            base => self.known[gpr(base)?]?,
        };
        let displacement = instruction.memory_displacement64();
        let displacement = if pointer == 4 { displacement & 0xffff_ffff } else { displacement };
        Some(JumpTable {
            guard: bound.guard,
            table: base.wrapping_add(displacement),
            entry_size,
            entries: bound.max + 1,
            signed,
            base: None,
            shift: 0,
            alignment: 1,
        })
    }
}
