use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind};

use crate::{Disassembler, Flow, Insn};

pub struct X86Disassembler {
    bitness: u32,
    formatter: IntelFormatter,
    text: String,
}

impl X86Disassembler {
    pub fn new(bitness: u32) -> Self {
        let mut formatter = IntelFormatter::new();
        let options = formatter.options_mut();
        options.set_hex_prefix("0x");
        options.set_hex_suffix("");
        options.set_uppercase_hex(false);
        options.set_space_after_operand_separator(true);
        options.set_branch_leading_zeros(false);
        Self { bitness, formatter, text: String::new() }
    }
}

impl Disassembler for X86Disassembler {
    fn decode_one(&mut self, bytes: &[u8], address: u64) -> Insn {
        let mut decoder = Decoder::with_ip(self.bitness, bytes, address, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Insn { address, len: 1, text: "(bad)".to_owned(), flow: Flow::Invalid };
        }
        self.text.clear();
        self.formatter.format(&instruction, &mut self.text);
        Insn { address, len: instruction.len() as u8, text: self.text.clone(), flow: flow_of(&instruction) }
    }
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

#[cfg(test)]
mod tests {
    use crate::{Arch, Flow, decoder_for};

    fn decode_all(bytes: &[u8], address: u64) -> Vec<crate::Insn> {
        let mut decoder = decoder_for(Arch::X86_64).unwrap();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let insn = decoder.decode_one(&bytes[offset..], address + offset as u64);
            offset += insn.len as usize;
            out.push(insn);
        }
        out
    }

    #[test]
    fn decodes_prologue_and_return() {
        let insns = decode_all(&[0x55, 0x48, 0x89, 0xe5, 0xc3], 0x1000);
        let texts: Vec<_> = insns.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, ["push rbp", "mov rbp, rsp", "ret"]);
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
        assert_eq!(decode_all(&[0xe8, 0, 0, 0, 0], 0x1000)[0].text, "call 0x1005");
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
    }

    #[test]
    fn aarch64_is_not_supported_yet() {
        assert!(decoder_for(Arch::Aarch64).is_err());
    }
}
