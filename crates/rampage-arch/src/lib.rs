mod x86;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum Flow {
    Next,
    Jump(u64),
    ConditionalJump(u64),
    Call(u64),
    IndirectJump,
    IndirectCall,
    Return,
    Halt,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Insn {
    pub address: u64,
    pub len: u8,
    pub text: String,
    pub flow: Flow,
}

pub trait Disassembler {
    fn decode_one(&mut self, bytes: &[u8], address: u64) -> Insn;
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported architecture: {0:?}")]
pub struct UnsupportedArch(pub Arch);

pub fn decoder_for(arch: Arch) -> Result<Box<dyn Disassembler>, UnsupportedArch> {
    match arch {
        Arch::X86 => Ok(Box::new(x86::X86Disassembler::new(32))),
        Arch::X86_64 => Ok(Box::new(x86::X86Disassembler::new(64))),
        Arch::Aarch64 => Err(UnsupportedArch(arch)),
    }
}
