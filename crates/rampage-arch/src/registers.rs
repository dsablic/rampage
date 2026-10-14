//! Which registers an instruction reads and writes, for liveness across calling conventions.

use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

/// Registers as bits: x86-64 general-purpose registers by hardware number (RAX 0, RCX 1, RDX 2, RBX 3, ... R15
/// 15), then XMM0 to XMM15 as bits 16 to 31.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegisterAccess {
    /// Registers whose incoming values the instruction uses.
    pub reads: u64,
    /// Registers the instruction writes unconditionally, taken to end their earlier values. A write to the low 8
    /// or 16 bits of a general-purpose register merges with the rest, but compilers avoid reading the merged
    /// whole (a partial-register stall), so code that writes `r9b` and tests `r9b` never uses the old R9.
    pub writes: u64,
}

/// The [`RegisterAccess`] bit of XMM register `number`.
pub const fn xmm(number: u32) -> u64 {
    1 << (16 + number)
}

/// The [`RegisterAccess`] bit of the general-purpose register with hardware `number`.
pub const fn gpr(number: u32) -> u64 {
    1 << number
}

/// Decodes x86-64 instructions for their register access.
pub struct X86Registers {
    info: InstructionInfoFactory,
}

impl Default for X86Registers {
    fn default() -> Self {
        Self { info: InstructionInfoFactory::new() }
    }
}

impl X86Registers {
    /// The length and register access of the instruction at the start of `bytes`, or `None` when it is invalid.
    pub fn access(&mut self, bytes: &[u8], address: u64) -> Option<(usize, RegisterAccess)> {
        self.decode(bytes, address).map(|(instruction, access)| (instruction.len(), access))
    }

    /// [`Self::access`] for code from the Go compiler. Its nil checks (`test [rdx], al`) touch memory only to
    /// fault on a nil pointer, so the register named is arbitrary and its value unused. A zero source leaves a
    /// `bsf` or `bsr` destination as it was on some processors, but Go never relies on that: it follows with a
    /// conditional move for the zero case, so the destination counts as written, not read.
    pub fn go_access(&mut self, bytes: &[u8], address: u64) -> Option<(usize, RegisterAccess)> {
        let (instruction, mut access) = self.decode(bytes, address)?;
        if matches!(instruction.mnemonic(), Mnemonic::Bsf | Mnemonic::Bsr)
            && instruction.op0_kind() == OpKind::Register
            && let Some(bit) = register_bit(instruction.op0_register())
            && !(instruction.op1_kind() == OpKind::Register && instruction.op1_register() == instruction.op0_register())
        {
            access.reads &= !bit;
            access.writes |= bit;
        }
        if instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && instruction.op1_register() == Register::AL
        {
            access.reads = instruction_address_registers(&instruction);
        }
        Some((instruction.len(), access))
    }

    fn decode(&mut self, bytes: &[u8], address: u64) -> Option<(iced_x86::Instruction, RegisterAccess)> {
        let instruction = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE).decode();
        if instruction.is_invalid() {
            return None;
        }
        let mut access = RegisterAccess::default();
        if padding(&instruction) {
            return Some((instruction, access));
        }
        for used in self.info.info(&instruction).used_registers() {
            let Some(bit) = register_bit(used.register()) else { continue };
            match used.access() {
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    access.reads |= bit;
                }
                OpAccess::Write => access.writes |= bit,
                _ => {}
            }
        }
        if zeroing_idiom(&instruction)
            && let Some(bit) = register_bit(instruction.op_register(0))
        {
            access.reads &= !bit;
            access.writes |= bit;
        }
        Some((instruction, access))
    }
}

/// The base and index registers of an instruction's memory operand.
fn instruction_address_registers(instruction: &iced_x86::Instruction) -> u64 {
    [instruction.memory_base(), instruction.memory_index()]
        .into_iter()
        .filter_map(register_bit)
        .fold(0, |bits, bit| bits | bit)
}

/// The bit of a register, or of the whole register a part of one belongs to.
fn register_bit(register: Register) -> Option<u64> {
    let full = register.full_register();
    if full.is_gpr64() {
        Some(gpr(full.number() as u32))
    } else if full.is_zmm() && full.number() < 16 {
        Some(xmm(full.number() as u32))
    } else {
        None
    }
}

/// Alignment padding: `nop [rax+rax]` names registers in its operand but reads nothing, and `xchg ax, ax`
/// exchanges a register with itself.
fn padding(instruction: &iced_x86::Instruction) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Nop => true,
        Mnemonic::Xchg => {
            instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == instruction.op1_register()
        }
        _ => false,
    }
}

/// `xor eax, eax`, `sbb r10, r10` (only the carry flag matters), `pcmpeqd xmm0, xmm0` (all ones) and their
/// relatives: an operation on a register and itself whose result does not depend on the register's old value.
fn zeroing_idiom(instruction: &iced_x86::Instruction) -> bool {
    use Mnemonic::*;
    let zeroing = matches!(
        instruction.mnemonic(),
        Xor | Sub
            | Sbb
            | Pxor
            | Xorps
            | Xorpd
            | Vpxor
            | Vxorps
            | Vxorpd
            | Psubb
            | Psubw
            | Psubd
            | Psubq
            | Vpsubb
            | Vpsubw
            | Vpsubd
            | Vpsubq
            | Pcmpeqb
            | Pcmpeqw
            | Pcmpeqd
            | Pcmpeqq
            | Vpcmpeqb
            | Vpcmpeqw
            | Vpcmpeqd
            | Vpcmpeqq
    );
    let count = instruction.op_count();
    let registers = (0..count).all(|operand| instruction.op_kind(operand) == OpKind::Register);
    let sources = if count == 3 { [1, 2] } else { [0, 1] };
    zeroing && registers && count >= 2 && instruction.op_register(sources[0]) == instruction.op_register(sources[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(bytes: &[u8]) -> RegisterAccess {
        X86Registers::default().access(bytes, 0x1000).expect("valid").1
    }

    const RAX: u64 = gpr(0);
    const RBX: u64 = gpr(3);
    const RSP: u64 = gpr(4);

    #[test]
    fn moves_read_the_source_and_replace_the_destination() {
        assert_eq!(access(&[0x48, 0x89, 0xd8]), RegisterAccess { reads: RBX, writes: RAX }, "mov rax, rbx");
        assert_eq!(access(&[0x89, 0xd8]), RegisterAccess { reads: RBX, writes: RAX }, "mov eax, ebx");
    }

    #[test]
    fn narrow_writes_end_the_register_and_conditional_moves_do_not() {
        assert_eq!(access(&[0xb0, 0x01]), RegisterAccess { reads: 0, writes: RAX }, "mov al, 1");
        assert_eq!(access(&[0x41, 0x0f, 0x94, 0xc1]), RegisterAccess { reads: 0, writes: gpr(9) }, "sete r9b");
        assert_eq!(access(&[0x48, 0x0f, 0x44, 0xc3]).writes, 0, "cmove rax, rbx");
    }

    #[test]
    fn zeroing_idioms_do_not_read() {
        assert_eq!(access(&[0x31, 0xc0]), RegisterAccess { reads: 0, writes: RAX }, "xor eax, eax");
        assert_eq!(access(&[0x66, 0x0f, 0xef, 0xc0]), RegisterAccess { reads: 0, writes: xmm(0) }, "pxor xmm0, xmm0");
        assert_eq!(access(&[0x48, 0x31, 0xd8]).reads, RAX | RBX, "xor rax, rbx");
        assert_eq!(access(&[0x4d, 0x19, 0xd2]), RegisterAccess { reads: 0, writes: gpr(10) }, "sbb r10, r10");
    }

    #[test]
    fn padding_reads_nothing() {
        let none = RegisterAccess::default();
        assert_eq!(access(&[0x0f, 0x1f, 0x44, 0x00, 0x00]), none, "nop [rax+rax]");
        assert_eq!(access(&[0x66, 0x90]), none, "xchg ax, ax");
        assert_eq!(access(&[0x48, 0x93]).reads, RAX | RBX, "xchg rax, rbx");
    }

    #[test]
    fn go_nil_checks_read_only_the_checked_pointer() {
        let check = [0x84, 0x02]; // test [rdx], al
        assert_eq!(access(&check).reads, RAX | gpr(2));
        assert_eq!(X86Registers::default().go_access(&check, 0x1000).expect("valid").1.reads, gpr(2));
    }

    #[test]
    fn go_bit_scans_write_their_destination() {
        let scan = [0x48, 0x0f, 0xbc, 0xc8]; // bsf rcx, rax
        let go = X86Registers::default().go_access(&scan, 0x1000).expect("valid").1;
        assert_eq!(go, RegisterAccess { reads: RAX, writes: gpr(1) });
    }

    #[test]
    fn memory_operands_read_their_address_registers_and_vector_stores_read_the_source() {
        // movsd [rsp+8], xmm0
        assert_eq!(access(&[0xf2, 0x0f, 0x11, 0x44, 0x24, 0x08]).reads, RSP | xmm(0));
        // mov [rsp+8], rax
        assert_eq!(access(&[0x48, 0x89, 0x44, 0x24, 0x08]).reads, RSP | RAX);
    }
}
