//! Switch jump tables behind x86 indirect jumps.
//!
//! Along a straight-line run this follows which general-purpose registers hold a known address (`lea r,
//! [rip+table]`), an index bounded by `cmp r, imm` directly followed by `ja`/`jae` (or masked by `and r, imm`), and
//! a table entry loaded with such an index, possibly added to a known address. A jump through such an entry, or
//! through memory indexed by a bounded register, dispatches through a [`JumpTable`].
//!
//! It also follows which registers hold equal values (`mov r13d, esi` after `mov r12d, esi`), so a bound proven on
//! one register holds for its copies, and the PC that `call __x86.get_pc_thunk.bx` or `call 1f; 1: pop ebx` puts in a
//! register. A call keeps the registers every x86 calling convention preserves. The facts can be carried across
//! joins with [`Registers::meet`], which keeps only what holds on every incoming path.

use iced_x86::{ConditionCode, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::{JumpTable, MAX_JUMP_TABLE_ENTRIES};

const REGISTERS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bound {
    max: u64,
    /// Whether the bound covers the whole register rather than only its 32-bit view.
    wide: bool,
    guard: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Compare {
    register: usize,
    limit: u64,
    wide: bool,
    address: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registers {
    /// Registers whose upper 32 bits a write to their 32-bit view zeroed.
    upper_zero: u16,
    known: [Option<u64>; REGISTERS],
    bounds: [Option<Bound>; REGISTERS],
    /// Registers holding a switch-table entry, or a target formed by adding one to a known address.
    entries: [Option<JumpTable>; REGISTERS],
    /// The comparison of a register with an immediate that the previous instruction made.
    compare: Option<Compare>,
    /// For each register, the other registers holding the same 64-bit value.
    same: [u16; REGISTERS],
    /// For each register, the registers holding its low 32 bits zero-extended.
    zero_extended: [u16; REGISTERS],
    /// The return address that the previous instruction, a call to the next instruction, pushed.
    pushed_pc: Option<u64>,
    /// Registers whose bound the conditional branch just stepped proved on its fall-through path only.
    fall_through_bounds: u16,
}

/// Registers that every x86 calling convention keeps across a call: rbx, rbp, r12-r15 (System V and Windows x64),
/// ebx, ebp, esi and edi (i386).
fn preserved(bitness: u32) -> u16 {
    if bitness == 64 { 1 << 3 | 1 << 5 | 0xf000 } else { 1 << 3 | 1 << 5 | 1 << 6 | 1 << 7 }
}

/// The register a get-PC thunk loads with its return address: `mov reg, [esp]; ret`.
fn get_pc_thunk(read: &dyn Fn(u64, u8) -> Option<u64>, target: u64) -> Option<usize> {
    let [opcode, modrm, sib, ret] = u32::try_from(read(target, 4)?).ok()?.to_le_bytes();
    (opcode == 0x8b && modrm & 0xc7 == 0x04 && sib == 0x24 && ret == 0xc3).then_some(usize::from(modrm >> 3 & 7))
}

/// `address + offset` in a register `bitness` bits wide.
fn wrap(address: u64, offset: u64, bitness: u32) -> u64 {
    let sum = address.wrapping_add(offset);
    if bitness == 32 { sum & 0xffff_ffff } else { sum }
}

fn bits(mask: u16) -> impl Iterator<Item = usize> {
    (0..REGISTERS).filter(move |&index| mask & (1 << index) != 0)
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
    /// Tracks `instruction` and returns the bounded table it jumps through, if it is such an indirect jump. `read`
    /// reads immutable memory, such as the code a call goes to.
    pub fn step(
        &mut self,
        instruction: &Instruction,
        bitness: u32,
        info: &mut InstructionInfoFactory,
        read: Option<&dyn Fn(u64, u8) -> Option<u64>>,
    ) -> Option<JumpTable> {
        let pointer = if bitness == 64 { 8 } else { 4 };
        let compare = self.compare.take();
        let pushed_pc = self.pushed_pc.take();
        self.fall_through_bounds = 0;
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
        // A register copy: the destination, the source, and whether it holds only the source's low 32 bits
        // zero-extended.
        let mut copy = None;
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
                // The mask bounds the whole register: a 32-bit `and` zeroes the upper half. Only a mask of low bits
                // selects every index up to it; any other leaves gaps that are not table entries.
                bound = immediate(instruction).zip(gpr(register)).and_then(|(mask, index)| {
                    let max = if size(register) == 32 { mask & 0xffff_ffff } else { mask };
                    (max & max.wrapping_add(1) == 0)
                        .then(|| (index, Bound { max, wide: true, guard: instruction.ip() }))
                });
            }
            (Mnemonic::Mov, Some(to_register), Some(from_register))
                if size(to_register) == size(from_register) && matches!(size(to_register), 32 | 64) =>
            {
                if let (Some(to), Some(from)) = (gpr(to_register), gpr(from_register)) {
                    // A 32-bit copy zero-extends the bounded 32-bit view into the whole register.
                    let zero_extends = size(to_register) == 32;
                    let whole = !zero_extends || bitness == 32 || self.upper_zero & (1 << from) != 0;
                    copy = (to != from).then_some((to, from, !whole));
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
            (Mnemonic::Lea, Some(to), _) if size(to) == bitness && instruction.memory_index() == Register::None => {
                let base = gpr(instruction.memory_base()).and_then(|base| self.known[base]);
                let displacement = instruction.memory_displacement64();
                known = base.zip(gpr(to)).map(|(base, to)| (to, wrap(base, displacement, bitness)));
            }
            (Mnemonic::Add | Mnemonic::Sub, Some(to), None) if size(to) == bitness => {
                // PIC i386 code adds the GOT's offset to the PC a get-PC thunk returned.
                let address = gpr(to).and_then(|index| self.known[index]);
                known = address.zip(immediate(instruction)).zip(gpr(to)).map(|((address, offset), to)| {
                    let offset = if instruction.mnemonic() == Mnemonic::Sub { offset.wrapping_neg() } else { offset };
                    (to, wrap(address, offset, bitness))
                });
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
                    // 32-bit addition wraps, so a 32-bit entry above the base's distance to 4 GiB is a negative offset.
                    let relative = |entry: Option<JumpTable>, base: Option<u64>| {
                        let table = entry.filter(|table| table.base.is_none())?;
                        Some(JumpTable { base: Some(base?), signed: table.signed || bitness == 32, ..table })
                    };
                    entry = relative(self.entries[to], self.known[from])
                        .or_else(|| relative(self.entries[from], self.known[to]))
                        .map(|table| (to, table));
                }
            }
            _ => {}
        }
        let bound = bound.filter(|(_, bound)| bound.max < MAX_JUMP_TABLE_ENTRIES);
        // `call 1f; 1: pop reg` and `mov reg, [esp]` there take the PC the call pushed.
        let takes_pc = instruction.mnemonic() == Mnemonic::Pop
            || instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Memory
                && matches!(instruction.memory_base(), Register::ESP | Register::RSP)
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == 0;
        if let Some(pc) = pushed_pc.filter(|_| takes_pc)
            && let Some(to) = destination.filter(|&register| size(register) == bitness).and_then(gpr)
        {
            known = Some((to, pc));
        }

        if matches!(instruction.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter) {
            *self = Self::default();
        } else if instruction.mnemonic() == Mnemonic::Call {
            let kept = preserved(bitness);
            for index in (0..REGISTERS).filter(|index| kept & (1 << index) == 0) {
                self.clear(index);
            }
            let direct = matches!(instruction.op0_kind(), OpKind::NearBranch32 | OpKind::NearBranch64)
                .then(|| instruction.near_branch_target());
            if direct == Some(instruction.next_ip()) {
                self.pushed_pc = direct;
            } else if let Some(thunk) = direct.zip(read).and_then(|(target, read)| get_pc_thunk(read, target)) {
                self.clear(thunk);
                known = Some((thunk, instruction.next_ip()));
            }
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
        if let Some((to, from, zero_extended)) = copy {
            self.copy(to, from, zero_extended);
        }
        if let Some((index, bound)) = bound {
            // Copies hold the bounded value too, and zero-extended copies of its low half hold it whole.
            let copies = 1 << index | self.same[index];
            let zero_extended = self.zero_extended[index] & !copies;
            for copy in bits(copies) {
                self.bounds[copy] = Some(bound);
            }
            for copy in bits(zero_extended) {
                self.bounds[copy] = Some(Bound { wide: true, ..bound });
            }
            if matches!(instruction.mnemonic(), Mnemonic::Ja | Mnemonic::Jae) {
                self.fall_through_bounds = copies | zero_extended;
            }
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
        self.same[index] = 0;
        self.zero_extended[index] = 0;
        for other in 0..REGISTERS {
            self.same[other] &= !(1 << index);
            self.zero_extended[other] &= !(1 << index);
        }
    }

    /// Records that `to` now holds `from`'s value, or only its low 32 bits zero-extended.
    fn copy(&mut self, to: usize, from: usize, zero_extended: bool) {
        if zero_extended {
            if let Some(other) = bits(self.zero_extended[from]).next() {
                self.alias(to, other);
            }
            self.zero_extended[from] |= 1 << to;
        } else {
            self.alias(to, from);
        }
    }

    /// Makes `to`, which no relation mentions, one more register holding `from`'s value.
    fn alias(&mut self, to: usize, from: usize) {
        let copies = self.same[from] | 1 << from;
        for copy in bits(copies) {
            self.same[copy] |= 1 << to;
        }
        self.same[to] = copies;
        self.zero_extended[to] = self.zero_extended[from];
        for other in 0..REGISTERS {
            if self.zero_extended[other] & (1 << from) != 0 {
                self.zero_extended[other] |= 1 << to;
            }
        }
    }

    /// The facts on the fall-through path of the instruction just stepped.
    pub fn fall_through(&self) -> Self {
        Self { fall_through_bounds: 0, ..self.clone() }
    }

    /// The facts where the conditional branch just stepped is taken: its bound holds only when it is not.
    pub fn taken(&self) -> Self {
        let mut taken = self.fall_through();
        for index in bits(self.fall_through_bounds) {
            taken.bounds[index] = None;
        }
        taken
    }

    /// What holds on both of two paths that join.
    pub fn meet(&self, other: &Self) -> Self {
        fn equal<T: PartialEq>(a: Option<T>, b: Option<T>) -> Option<T> {
            if a == b { a } else { None }
        }
        // A bound survives only from the one comparison that guards every path, so a switch has a single guard.
        let bound = |a: Option<Bound>, b: Option<Bound>| {
            let (a, b) = a.zip(b).filter(|(a, b)| a.guard == b.guard)?;
            Some(Bound { max: a.max.max(b.max), wide: a.wide && b.wide, guard: a.guard })
        };
        Self {
            upper_zero: self.upper_zero & other.upper_zero,
            known: std::array::from_fn(|index| equal(self.known[index], other.known[index])),
            bounds: std::array::from_fn(|index| bound(self.bounds[index], other.bounds[index])),
            entries: std::array::from_fn(|index| equal(self.entries[index], other.entries[index])),
            compare: equal(self.compare, other.compare),
            same: std::array::from_fn(|index| self.same[index] & other.same[index]),
            zero_extended: std::array::from_fn(|index| self.zero_extended[index] & other.zero_extended[index]),
            pushed_pc: equal(self.pushed_pc, other.pushed_pc),
            fall_through_bounds: 0,
        }
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
        Some(JumpTable {
            guard: bound.guard,
            table: wrap(base, instruction.memory_displacement64(), u32::from(pointer) * 8),
            entry_size,
            entries: bound.max + 1,
            signed,
            base: None,
            shift: 0,
            alignment: 1,
        })
    }
}
