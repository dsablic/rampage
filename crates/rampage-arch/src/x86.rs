use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};

use crate::{Disassembler, Flow, Insn};

/// Immediates below this are almost never addresses (small constants, flags, sizes).
const MIN_IMMEDIATE_ADDRESS: u64 = 0x1000;

pub struct X86Disassembler {
    bitness: u32,
    formatter: Option<IntelFormatter>,
}

impl X86Disassembler {
    pub fn new(bitness: u32) -> Self {
        Self { bitness, formatter: None }
    }

    fn decode_raw(&self, bytes: &[u8], address: u64) -> Instruction {
        Decoder::with_ip(self.bitness, bytes, address, DecoderOptions::NONE).decode()
    }
}

impl Disassembler for X86Disassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        let instruction = self.decode_raw(bytes, address);
        if instruction.is_invalid() {
            return Insn { address, len: 1, flow: Flow::Invalid, data_ref: None };
        }
        Insn { address, len: instruction.len() as u8, flow: flow_of(&instruction), data_ref: data_ref_of(&instruction) }
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

fn data_ref_of(instruction: &Instruction) -> Option<u64> {
    let mut immediate = None;
    for operand in 0..instruction.op_count() {
        match instruction.op_kind(operand) {
            OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
                return Some(instruction.ip_rel_memory_address());
            }
            OpKind::Memory
                if instruction.memory_base() == Register::None && instruction.memory_index() == Register::None =>
            {
                return Some(instruction.memory_displacement64());
            }
            OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64 => {
                immediate = Some(instruction.immediate(operand)).filter(|&value| value >= MIN_IMMEDIATE_ADDRESS);
            }
            _ => {}
        }
    }
    immediate
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
    fn address_sized_immediate_is_a_data_ref() {
        assert_eq!(decode_all(&[0xbf, 0x00, 0x10, 0x40, 0x00], 0)[0].data_ref, Some(0x401000), "mov edi, 0x401000");
        assert_eq!(decode_all(&[0xb8, 5, 0, 0, 0], 0)[0].data_ref, None, "mov eax, 5");
    }

    #[test]
    fn branches_and_register_memory_have_no_data_ref() {
        assert_eq!(decode_all(&[0xe8, 0, 0, 0, 0], 0x1000)[0].data_ref, None);
        assert_eq!(decode_all(&[0x8b, 0x07], 0)[0].data_ref, None, "mov eax, [rdi]");
    }

    #[test]
    fn aarch64_is_not_supported_yet() {
        assert!(decoder_for(Arch::Aarch64).is_err());
    }
}
