use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory, IntelFormatter, Mnemonic,
    OpKind, Register,
};

use crate::{Disassembler, Flow, Insn, JumpTable};

mod switch;

/// Immediates below this are almost never addresses (small constants, flags, sizes).
const MIN_IMMEDIATE_ADDRESS: u64 = 0x1000;

pub struct X86Disassembler {
    bitness: u32,
    formatter: Option<IntelFormatter>,
    info: InstructionInfoFactory,
    registers: switch::Registers,
    jump_table: Option<JumpTable>,
}

impl X86Disassembler {
    pub fn new(bitness: u32) -> Self {
        Self {
            bitness,
            formatter: None,
            info: InstructionInfoFactory::new(),
            registers: switch::Registers::default(),
            jump_table: None,
        }
    }

    fn decode_raw(&self, bytes: &[u8], address: u64) -> Instruction {
        Decoder::with_ip(self.bitness, bytes, address, DecoderOptions::NONE).decode()
    }
}

impl Disassembler for X86Disassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        let instruction = self.decode_raw(bytes, address);
        if instruction.is_invalid() {
            self.jump_table = None;
            return Insn { address, len: 1, flow: Flow::Invalid, data_ref: None, immediate: None };
        }
        self.jump_table = self.registers.step(&instruction, self.bitness, &mut self.info);
        let mut flow = flow_of(&instruction);
        // `call 1f; 1: pop reg` reads the PC; a callee would not start by popping its own return address.
        if flow == Flow::Call(instruction.next_ip())
            && let Some(following) = bytes.get(instruction.len()..)
            && self.decode_raw(following, instruction.next_ip()).mnemonic() == Mnemonic::Pop
        {
            flow = Flow::Next;
        }
        Insn {
            address,
            len: instruction.len() as u8,
            flow,
            data_ref: memory_ref_of(&instruction),
            immediate: pointer_immediate_of(&instruction),
        }
    }

    fn reset(&mut self) {
        self.registers = switch::Registers::default();
        self.jump_table = None;
    }

    fn jump_table(&self) -> Option<JumpTable> {
        self.jump_table
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let instruction = self.decode_raw(bytes, address);
        if instruction.is_invalid() {
            return "(bad)".to_owned();
        }
        let formatter = self.formatter.get_or_insert_with(new_formatter);
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        text
    }
}

fn new_formatter() -> IntelFormatter {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    options.set_space_after_operand_separator(true);
    options.set_branch_leading_zeros(false);
    formatter
}

fn flow_of(instruction: &Instruction) -> Flow {
    let direct_target = || match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Some(instruction.near_branch_target()),
        _ => None,
    };
    match instruction.flow_control() {
        FlowControl::Next | FlowControl::Interrupt | FlowControl::XbeginXabortXend => match instruction.mnemonic() {
            Mnemonic::Hlt => Flow::Halt,
            Mnemonic::Xbegin => direct_target().map_or(Flow::Next, Flow::ConditionalJump),
            _ => Flow::Next,
        },
        FlowControl::UnconditionalBranch => direct_target().map_or(Flow::IndirectJump, Flow::Jump),
        FlowControl::ConditionalBranch => direct_target().map_or(Flow::IndirectJump, Flow::ConditionalJump),
        FlowControl::Call => direct_target().map_or(Flow::IndirectCall, Flow::Call),
        FlowControl::IndirectBranch => Flow::IndirectJump,
        FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::Return => Flow::Return,
        FlowControl::Exception => Flow::Halt,
    }
}

fn memory_ref_of(instruction: &Instruction) -> Option<u64> {
    (0..instruction.op_count()).find_map(|operand| {
        if instruction.op_kind(operand) != OpKind::Memory {
            return None;
        }
        // FS/GS point at thread-local blocks, so their offsets are not addresses in the image.
        if matches!(instruction.memory_segment(), Register::FS | Register::GS) {
            return None;
        }
        if instruction.is_ip_rel_memory_operand() {
            return Some(instruction.ip_rel_memory_address());
        }
        (instruction.memory_base() == Register::None && instruction.memory_index() == Register::None)
            .then(|| instruction.memory_displacement64())
    })
}

/// Only moves and pushes put pointers in registers or on the stack; immediates in arithmetic and comparisons are
/// numbers even when they happen to fall inside the image.
fn pointer_immediate_of(instruction: &Instruction) -> Option<u64> {
    if !matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Push) {
        return None;
    }
    (0..instruction.op_count()).find_map(|operand| {
        let kind = instruction.op_kind(operand);
        if !matches!(kind, OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) {
            return None;
        }
        let value = instruction.immediate(operand);
        let sign_extended_negative = kind == OpKind::Immediate32to64 && (value as i64) < 0;
        (value >= MIN_IMMEDIATE_ADDRESS && !sign_extended_negative).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use crate::{Arch, Flow, decoder_for};

    fn decode_all(bytes: &[u8], address: u64) -> Vec<crate::Insn> {
        let mut decoder = decoder_for(Arch::X86_64).unwrap();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let insn = decoder.decode(&bytes[offset..], address + offset as u64);
            offset += insn.len as usize;
            out.push(insn);
        }
        out
    }

    fn texts(bytes: &[u8], address: u64) -> Vec<String> {
        let mut decoder = decoder_for(Arch::X86_64).unwrap();
        decode_all(bytes, address)
            .iter()
            .map(|insn| decoder.format(&bytes[(insn.address - address) as usize..], insn.address))
            .collect()
    }

    #[test]
    fn decodes_prologue_and_return() {
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0xc3];
        assert_eq!(texts(&bytes, 0x1000), ["push rbp", "mov rbp, rsp", "ret"]);
        let insns = decode_all(&bytes, 0x1000);
        assert_eq!(insns[0].flow, Flow::Next);
        assert_eq!(insns[2].flow, Flow::Return);
        assert_eq!(insns[1].address, 0x1001);
    }

    #[test]
    fn resolves_direct_branch_targets() {
        assert_eq!(decode_all(&[0xe8, 0, 0, 0, 0], 0x1000)[0].flow, Flow::Call(0x1005));
        assert_eq!(decode_all(&[0x74, 0x02], 0x1000)[0].flow, Flow::ConditionalJump(0x1004));
        assert_eq!(decode_all(&[0xeb, 0xfe], 0x1000)[0].flow, Flow::Jump(0x1000));
    }

    #[test]
    fn a_call_to_the_next_instruction_reads_the_pc_only_when_that_pops_it() {
        let mut decoder = decoder_for(Arch::X86).unwrap();
        // call 0x1005; pop ebx
        assert_eq!(decoder.decode(&[0xe8, 0, 0, 0, 0, 0x5b], 0x1000).flow, Flow::Next);
        // call 0x1005; push ebp: a function that happens to follow.
        assert_eq!(decoder.decode(&[0xe8, 0, 0, 0, 0, 0x55], 0x1000).flow, Flow::Call(0x1005));
    }

    #[test]
    fn formats_hex_with_0x_prefix() {
        assert_eq!(texts(&[0xe8, 0, 0, 0, 0], 0x1000), ["call 0x1005"]);
    }

    #[test]
    fn reports_indirect_flow() {
        assert_eq!(decode_all(&[0xff, 0xe0], 0)[0].flow, Flow::IndirectJump);
        assert_eq!(decode_all(&[0xff, 0xd0], 0)[0].flow, Flow::IndirectCall);
    }

    #[test]
    fn truncated_bytes_decode_as_one_invalid_byte() {
        let insn = &decode_all(&[0x48], 0)[0];
        assert_eq!(insn.flow, Flow::Invalid);
        assert_eq!(insn.len, 1);
        assert_eq!(texts(&[0x48], 0), ["(bad)"]);
    }

    #[test]
    fn rip_relative_operand_is_a_data_ref() {
        let insn = &decode_all(&[0x48, 0x8d, 0x05, 0x10, 0, 0, 0], 0x1000)[0];
        assert_eq!(insn.data_ref, Some(0x1017));
    }

    #[test]
    fn absolute_memory_operand_is_a_data_ref() {
        let insn = &decode_all(&[0x8b, 0x04, 0x25, 0x00, 0x20, 0x40, 0x00], 0)[0];
        assert_eq!(insn.data_ref, Some(0x402000), "mov eax, [0x402000]");
    }

    #[test]
    fn moved_or_pushed_address_sized_immediate_is_a_possible_pointer() {
        let mov = &decode_all(&[0xbf, 0x00, 0x10, 0x40, 0x00], 0)[0];
        assert_eq!((mov.immediate, mov.data_ref), (Some(0x401000), None), "mov edi, 0x401000");
        assert_eq!(decode_all(&[0x68, 0x00, 0x10, 0x40, 0x00], 0)[0].immediate, Some(0x401000), "push 0x401000");
        assert_eq!(decode_all(&[0xb8, 5, 0, 0, 0], 0)[0].immediate, None, "mov eax, 5");
    }

    #[test]
    fn arithmetic_and_comparison_immediates_are_not_pointers() {
        assert_eq!(decode_all(&[0x48, 0x69, 0xc6, 0x9a, 0x28, 0, 0], 0)[0].immediate, None, "imul rax, rsi, 0x289a");
        assert_eq!(decode_all(&[0x81, 0xf9, 0x91, 0x37, 0, 0], 0)[0].immediate, None, "cmp ecx, 0x3791");
        assert_eq!(decode_all(&[0x48, 0x05, 0x00, 0x10, 0x40, 0x00], 0)[0].immediate, None, "add rax, 0x401000");
    }

    #[test]
    fn branches_and_register_memory_have_no_data_ref() {
        assert_eq!(decode_all(&[0xe8, 0, 0, 0, 0], 0x1000)[0].data_ref, None);
        assert_eq!(decode_all(&[0x8b, 0x07], 0)[0].data_ref, None, "mov eax, [rdi]");
    }

    #[test]
    fn segment_relative_memory_is_not_a_data_ref() {
        let insn = &decode_all(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0], 0)[0];
        assert_eq!(insn.data_ref, None, "mov rax, fs:[0x28]");
        let insn = &decode_all(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0], 0)[0];
        assert_eq!(insn.data_ref, None, "mov rax, gs:[0x30]");
    }

    #[test]
    fn negative_immediates_are_not_data_refs() {
        assert_eq!(decode_all(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff], 0)[0].immediate, None, "mov rax, -1");
        assert_eq!(decode_all(&[0x48, 0x83, 0xe4, 0xf0], 0)[0].immediate, None, "and rsp, -16");
    }

    #[test]
    fn xbegin_is_a_conditional_jump_to_the_abort_handler() {
        let insn = &decode_all(&[0xc7, 0xf8, 0x10, 0, 0, 0], 0x1000)[0];
        assert_eq!(insn.flow, Flow::ConditionalJump(0x1016));
    }
}
