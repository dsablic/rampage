pub mod a64;
pub mod aarch32;
pub mod bytes;
mod cs;
mod flow;
pub mod hex;
pub mod ir;
mod mrs;
mod track;
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
    (Arch::Arm, &["arm", "arm32", "armv7"]),
    (Arch::Mips, &["mips", "mips32"]),
    (Arch::Mips64, &["mips64"]),
    (Arch::PowerPc, &["powerpc", "ppc", "ppc32"]),
    (Arch::PowerPc64, &["powerpc64", "ppc64"]),
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

    /// Bytes in a pointer.
    pub fn pointer_size(self) -> u8 {
        match self {
            Arch::X86 | Arch::Arm | Arch::Mips | Arch::PowerPc | Arch::Riscv32 | Arch::Sparc | Arch::M68k => 4,
            _ => 8,
        }
    }

    /// Instructions executed after a branch before it takes effect (MIPS and SPARC delay slots).
    pub fn delay_slots(self) -> u8 {
        match self {
            Arch::Mips | Arch::Mips64 | Arch::Sparc | Arch::Sparc64 => 1,
            _ => 0,
        }
    }

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
    /// The byte order of instructions (little-endian in ARM BE8 images, whose data is big-endian).
    pub big_endian: bool,
    /// The byte order of data, such as literal pools within code.
    pub data_big_endian: bool,
    /// ARM only: the sorted address ranges that hold Thumb (T32) code.
    pub thumb: std::sync::Arc<[std::ops::Range<u64>]>,
    /// The value the ABI keeps in its global-pointer register (MIPS `$gp`, PowerPC64 `r2`, RISC-V `gp`), through
    /// which position-independent code reaches its GOT and data.
    pub global_pointer: Option<u64>,
    /// The global offset table's contents, which position-independent code loads addresses from.
    pub got: Option<Got>,
}

/// Pointer-sized entries starting at `address`, as stored in the file (before dynamic relocation).
#[derive(Debug, Clone)]
pub struct Got {
    pub address: u64,
    pub entries: std::sync::Arc<[u64]>,
}

impl Got {
    pub fn entry(&self, address: u64, pointer_size: u8) -> Option<u64> {
        let offset = address.checked_sub(self.address)?;
        if offset % u64::from(pointer_size) != 0 {
            return None;
        }
        self.entries.get(usize::try_from(offset / u64::from(pointer_size)).ok()?).copied()
    }
}

impl Target {
    /// A little-endian target with no Thumb code.
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            big_endian: false,
            data_big_endian: false,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
        }
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
    /// Absolute address of a memory operand (RIP-relative or absolute displacement), or an address the
    /// instruction forms (`lea`, `adr`, ADRP plus ADD).
    #[serde(serialize_with = "crate::hex::optional_address")]
    pub data_ref: Option<u64>,
    /// The instruction loads from or stores to `data_ref` rather than forming it. Memory accessed is data, even in
    /// a literal pool inside code; only a formed address may be a code pointer.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub accesses: bool,
    /// An address-sized constant that the instruction moves, pushes or loads from a PC-relative literal pool in
    /// read-only memory (ARM `ldr r0, =func`), which may be a pointer. Only callers that know immediates are
    /// meaningful as addresses (images not based at zero) should treat it as one.
    #[serde(serialize_with = "crate::hex::optional_address")]
    pub immediate: Option<u64>,
    /// The call, return or register-indirect jump the instruction makes happens only when a condition holds, so
    /// execution may instead continue at the next instruction: `flow` is then the call, or [`Flow::Next`] for a
    /// return or indirect jump, which may leave the function. Conditional direct jumps are
    /// [`Flow::ConditionalJump`] and leave this unset.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub conditional: bool,
}

/// Most entries a switch jump table is read for; a larger proven bound leaves the jump unresolved.
pub const MAX_JUMP_TABLE_ENTRIES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetWidth {
    Bits32,
    Bits64,
}

/// A switch jump table a register-indirect jump dispatches through, with the index bound that a comparison and
/// conditional branch before it proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JumpTable {
    /// The bounding comparison. The bound holds only if no other path joins between it and the jump.
    pub guard: u64,
    pub table: u64,
    pub entry_size: u8,
    /// The bound plus one, at most [`MAX_JUMP_TABLE_ENTRIES`].
    pub entries: u64,
    /// Whether entries are sign-extended.
    pub signed: bool,
    /// Targets are `base + (entry << shift)`, or the entry itself when there is no base.
    pub base: Option<u64>,
    pub shift: u8,
    /// Instruction alignment every target must have.
    pub alignment: u64,
    /// The width of the target address calculation, independent of the table entry size.
    pub target_width: TargetWidth,
}

impl JumpTable {
    /// The address of entry `index`.
    pub fn slot(&self, index: u64) -> Option<u64> {
        self.table.checked_add(index.checked_mul(u64::from(self.entry_size))?)
    }

    /// The target an entry whose raw, zero-extended value is `raw` selects, if it is aligned.
    pub fn target(&self, raw: u64) -> Option<u64> {
        let bits = u32::from(self.entry_size) * 8;
        let value = if self.signed && bits < 64 { ((raw << (64 - bits)) as i64 >> (64 - bits)) as u64 } else { raw };
        let target = match self.base {
            Some(base) => base.wrapping_add(value.checked_shl(self.shift.into())?),
            None => value,
        };
        let target = match self.target_width {
            TargetWidth::Bits32 => target & 0xffff_ffff,
            TargetWidth::Bits64 => target,
        };
        target.is_multiple_of(self.alignment.max(1)).then_some(target)
    }
}

/// What a decoder's run has proven about registers at one point (known addresses, bounded indices, copies,
/// loaded table entries), for carrying across joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterFacts(Facts);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Facts {
    X86(Box<x86::switch::Registers>),
    A64(Box<a64::flow::Addresses>),
}

impl RegisterFacts {
    /// What holds on both of two paths that join.
    pub fn meet(&self, other: &Self) -> Self {
        match (&self.0, &other.0) {
            (Facts::X86(a), Facts::X86(b)) => RegisterFacts(Facts::X86(Box::new(a.meet(b)))),
            (Facts::A64(a), Facts::A64(b)) => RegisterFacts(Facts::A64(Box::new(a.meet(b)))),
            // Facts from different decoders share nothing.
            _ => RegisterFacts(Facts::X86(Box::default())),
        }
    }
}

pub trait Disassembler {
    /// Decodes one instruction. Undecodable bytes yield a `Flow::Invalid` instruction.
    ///
    /// Decoders may carry state from one instruction to the next within a straight-line run (AArch64 builds
    /// addresses from ADRP plus ADD or a load); call [`Disassembler::reset`] wherever control flow joins.
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn;
    /// Decodes with access to trusted, immutable pointer-sized memory values.
    fn decode_with_memory(&mut self, bytes: &[u8], address: u64, _read: &dyn Fn(u64, u8) -> Option<u64>) -> Insn {
        self.decode(bytes, address)
    }
    /// Forgets state carried between instructions, such as AArch64 ADRP pages.
    fn reset(&mut self) {}
    /// Forgets what a straight-line run proved about registers where another path joins it, before decoding the
    /// instruction there. How the run decodes (such as its instruction-set mode) carries on.
    fn join(&mut self) {
        self.reset();
    }
    /// Starts an independent exploration, including restoring its initial memory assumptions.
    /// Block-level resets keep memory invalidation from stores/calls already observed within that exploration.
    fn begin_run(&mut self) {
        self.reset();
    }
    /// Applies instruction-set modes learned from branches, before exploring another block.
    fn set_code_modes(&mut self, _modes: &[(u64, bool)]) {}
    /// ARM instruction-set modes learned at code addresses (`true` means Thumb).
    fn code_modes(&self) -> Vec<(u64, bool)> {
        Vec::new()
    }
    fn instruction_mode(&self) -> Option<bool> {
        None
    }
    fn code_mode_at(&self, _address: u64) -> Option<bool> {
        None
    }
    fn resolved_flow(&self) -> Option<Flow> {
        None
    }
    /// For the register-indirect jump just decoded, the code address its register was formed from: the target
    /// itself, or the base a switch adds its jump-table offset to.
    fn indirect_jump_base(&self) -> Option<u64> {
        None
    }
    /// For the register-indirect jump just decoded, the bounded switch table its register was loaded from. Its
    /// entries are not read or validated.
    fn jump_table(&self) -> Option<JumpTable> {
        None
    }
    /// What the run has proven about registers on the fall-through path of the instruction just decoded, or `None`
    /// when this decoder cannot carry its facts across joins.
    fn facts(&self) -> Option<RegisterFacts> {
        None
    }
    /// What the run has proven about registers where the conditional branch just decoded is taken.
    fn taken_facts(&self) -> Option<RegisterFacts> {
        self.facts()
    }
    /// Continues the run from `facts`, which must hold on every path into the next instruction decoded. Facts from
    /// another kind of decoder say nothing, so the run forgets what it proved, as at a join.
    fn assume(&mut self, _facts: &RegisterFacts) {}
    /// Instructions executed after a branch before it takes effect (MIPS and SPARC delay slots).
    fn delay_slots(&self) -> u8 {
        0
    }
    /// Renders one instruction as assembly text.
    fn format(&mut self, bytes: &[u8], address: u64) -> String;
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
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
        Arch::Arm => Ok(Box::new(aarch32::Aarch32Disassembler::new(target))),
        _ => cs::CapstoneDisassembler::new(target).map(|decoder| Box::new(decoder) as Box<dyn Disassembler>),
    }
}
