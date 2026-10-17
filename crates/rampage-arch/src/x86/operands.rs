use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::{MemoryOperand, OperandEvidence, OperandKind};

pub(super) fn evidence(instruction: &Instruction) -> Vec<OperandEvidence> {
    (0..instruction.op_count()).map(|index| operand(instruction, index)).collect()
}

fn operand(instruction: &Instruction, index: u32) -> OperandEvidence {
    let mut evidence = OperandEvidence::unsupported(index as u8);
    let immediate_width = match instruction.op_kind(index) {
        OpKind::Immediate8 | OpKind::Immediate8_2nd => Some(8),
        OpKind::Immediate16 | OpKind::Immediate8to16 => Some(16),
        OpKind::Immediate32 | OpKind::Immediate8to32 => Some(32),
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => Some(64),
        _ => None,
    };
    if let Some(width) = immediate_width {
        return OperandEvidence::immediate(index as u8, instruction.immediate(index), width);
    }
    match instruction.op_kind(index) {
        OpKind::Register => {
            evidence.kind = OperandKind::Register;
            evidence.width_bits = nonzero_size(instruction.op_register(index).size()).map(|bytes| bytes * 8);
        }
        OpKind::Memory => {
            // Segment-relative TLS is not an ordinary object-base offset.
            if matches!(instruction.memory_segment(), Register::FS | Register::GS)
                || instruction.memory_index().size() > 8
            {
                return evidence;
            }
            let relative = instruction.is_ip_rel_memory_operand();
            let base = instruction.memory_base();
            let access_size = if matches!(instruction.mnemonic(), Mnemonic::Lea | Mnemonic::Nop) {
                None
            } else {
                nonzero_size(instruction.memory_size().size())
            };
            let displacement = if relative {
                // iced stores the resolved target, not the encoded displacement, for RIP/EIP operands.
                let offset = instruction.ip_rel_memory_address().wrapping_sub(instruction.next_ip());
                if base == Register::EIP { i64::from(offset as i32) } else { offset as i64 }
            } else {
                match base {
                    Register::None => instruction.memory_displacement64() as i64,
                    _ if base.size() == 2 => i64::from(instruction.memory_displacement64() as i16),
                    _ if base.size() == 4 => i64::from(instruction.memory_displacement64() as i32),
                    _ => instruction.memory_displacement64() as i64,
                }
            };
            evidence.kind = OperandKind::Memory;
            evidence.width_bits = access_size.map(|size| size * 8);
            evidence.memory = Some(MemoryOperand {
                base: register_name(base),
                index: register_name(instruction.memory_index()),
                displacement,
                scale: instruction.memory_index_scale() as u8,
                access_size,
                relative,
            });
        }
        _ => {}
    }
    evidence
}

fn nonzero_size(size: usize) -> Option<u16> {
    u16::try_from(size).ok().filter(|size| *size != 0)
}

fn register_name(register: Register) -> Option<String> {
    (register != Register::None).then(|| format!("{register:?}").to_ascii_lowercase())
}
