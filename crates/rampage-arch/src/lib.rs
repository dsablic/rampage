mod x86;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        })
    }
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
    pub flow: Flow,
    /// Absolute address referenced by a memory or immediate operand; direct branch targets are in `flow`.
    pub data_ref: Option<u64>,
}

pub trait Disassembler {
    /// Decodes one instruction. Undecodable bytes yield a one-byte `Flow::Invalid` instruction.
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn;
    /// Renders one instruction as assembly text.
    fn format(&mut self, bytes: &[u8], address: u64) -> String;
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported architecture: {0}")]
pub struct UnsupportedArch(pub Arch);

pub fn decoder_for(arch: Arch) -> Result<Box<dyn Disassembler>, UnsupportedArch> {
    match arch {
        Arch::X86 => Ok(Box::new(x86::X86Disassembler::new(32))),
        Arch::X86_64 => Ok(Box::new(x86::X86Disassembler::new(64))),
        Arch::Aarch64 => Err(UnsupportedArch(arch)),
    }
}
