pub mod hex;
mod x86;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
}

impl std::str::FromStr for Arch {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" => Ok(Arch::X86),
            "x86_64" | "x64" | "amd64" => Ok(Arch::X86_64),
            "aarch64" | "arm64" => Ok(Arch::Aarch64),
            _ => Err(format!("unknown architecture {text:?}; expected x86, x86_64 or aarch64")),
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Serializes as `{"kind": "call", "target": "0x…"}`, with `target` only for direct branches.
impl Serialize for Flow {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (kind, target) = match *self {
            Flow::Next => ("next", None),
            Flow::Jump(target) => ("jump", Some(target)),
            Flow::ConditionalJump(target) => ("conditional_jump", Some(target)),
            Flow::Call(target) => ("call", Some(target)),
            Flow::IndirectJump => ("indirect_jump", None),
            Flow::IndirectCall => ("indirect_call", None),
            Flow::Return => ("return", None),
            Flow::Halt => ("halt", None),
            Flow::Invalid => ("invalid", None),
        };
        let mut state = serializer.serialize_struct("Flow", 2)?;
        state.serialize_field("kind", kind)?;
        if let Some(target) = target {
            state.serialize_field("target", &format!("{target:#x}"))?;
        } else {
            state.skip_field("target")?;
        }
        state.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Insn {
    #[serde(serialize_with = "crate::hex::address")]
    pub address: u64,
    pub len: u8,
    pub flow: Flow,
    /// Absolute address of a memory operand (RIP-relative or absolute displacement).
    #[serde(serialize_with = "crate::hex::optional_address")]
    pub data_ref: Option<u64>,
    /// An address-sized immediate that the instruction moves or pushes, which may be a pointer. Only callers that
    /// know immediates are meaningful as addresses (images not based at zero) should treat it as one.
    #[serde(serialize_with = "crate::hex::optional_address")]
    pub immediate: Option<u64>,
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
