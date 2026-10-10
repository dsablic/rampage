pub mod a64;
mod cs;
pub mod hex;
mod x86;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
    /// 32-bit ARM, in both the A32 and T32 (Thumb) instruction sets.
    Arm,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    Riscv32,
    Riscv64,
    Sparc,
    Sparc64,
    S390x,
    M68k,
}

/// Each architecture's name, followed by the other spellings it is known by.
const NAMES: [(Arch, &[&str]); 14] = [
    (Arch::X86, &["x86", "i386", "i686"]),
    (Arch::X86_64, &["x86_64", "x64", "amd64"]),
    (Arch::Aarch64, &["aarch64", "arm64"]),
    (Arch::Arm, &["arm", "arm32", "armv7", "thumb"]),
    (Arch::Mips, &["mips", "mips32", "mipsel"]),
    (Arch::Mips64, &["mips64", "mips64el"]),
    (Arch::PowerPc, &["powerpc", "ppc", "ppc32"]),
    (Arch::PowerPc64, &["powerpc64", "ppc64", "ppc64le"]),
    (Arch::Riscv32, &["riscv32", "rv32"]),
    (Arch::Riscv64, &["riscv64", "rv64"]),
    (Arch::Sparc, &["sparc"]),
    (Arch::Sparc64, &["sparc64", "sparcv9"]),
    (Arch::S390x, &["s390x", "systemz"]),
    (Arch::M68k, &["m68k"]),
];

impl Arch {
    pub const ALL: [Arch; 14] = {
        let mut all = [Arch::X86; 14];
        let mut index = 0;
        while index < NAMES.len() {
            all[index] = NAMES[index].0;
            index += 1;
        }
        all
    };

    fn names(self) -> &'static [&'static str] {
        NAMES.iter().find(|(arch, _)| *arch == self).map_or(&[], |(_, names)| names)
    }
}

impl std::str::FromStr for Arch {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.to_ascii_lowercase();
        NAMES.iter().find(|(_, names)| names.contains(&text.as_str())).map(|(arch, _)| *arch).ok_or_else(|| {
            let known: Vec<&str> = NAMES.iter().map(|(_, names)| names[0]).collect();
            format!("unknown architecture {text:?}; expected one of {}", known.join(", "))
        })
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.names()[0])
    }
}

/// What a decoder needs to know about the code it reads, beyond the architecture.
#[derive(Debug, Clone)]
pub struct Target {
    pub arch: Arch,
    pub big_endian: bool,
    /// ARM only: the sorted address ranges that hold Thumb (T32) code.
    pub thumb: std::sync::Arc<[std::ops::Range<u64>]>,
}

impl Target {
    /// A little-endian target with no Thumb code.
    pub fn new(arch: Arch) -> Self {
        Self { arch, big_endian: false, thumb: std::sync::Arc::new([]) }
    }

    /// Whether `address` lies in Thumb code.
    pub fn is_thumb(&self, address: u64) -> bool {
        let index = self.thumb.partition_point(|range| range.start <= address);
        index > 0 && address < self.thumb[index - 1].end
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
    /// Decodes one instruction. Undecodable bytes yield a `Flow::Invalid` instruction.
    ///
    /// Decoders may carry state from one instruction to the next within a straight-line run (AArch64 builds
    /// addresses from ADRP plus ADD or a load); call [`Disassembler::reset`] wherever control flow joins.
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn;
    /// Forgets state carried between instructions, such as AArch64 ADRP pages.
    fn reset(&mut self) {}
    /// Instructions executed after a branch before it takes effect (MIPS and SPARC delay slots).
    fn delay_slots(&self) -> u8 {
        0
    }
    /// Renders one instruction as assembly text.
    fn format(&mut self, bytes: &[u8], address: u64) -> String;
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported architecture: {0}")]
pub struct UnsupportedArch(pub Arch);

pub fn decoder_for(arch: Arch) -> Result<Box<dyn Disassembler>, UnsupportedArch> {
    decoder(&Target::new(arch))
}

/// A decoder for `target`: native ones for x86 (iced-x86) and AArch64 (generated from Arm's specification),
/// Capstone for the rest.
pub fn decoder(target: &Target) -> Result<Box<dyn Disassembler>, UnsupportedArch> {
    match target.arch {
        Arch::X86 => Ok(Box::new(x86::X86Disassembler::new(32))),
        Arch::X86_64 => Ok(Box::new(x86::X86Disassembler::new(64))),
        Arch::Aarch64 => Ok(Box::new(a64::A64Disassembler::default())),
        _ => cs::CapstoneDisassembler::new(target).map(|decoder| Box::new(decoder) as Box<dyn Disassembler>),
    }
}
