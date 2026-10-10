//! Types of the generated specification tables, and the Arm pseudocode helpers their conditions call.

pub use super::helpers::{bfx_preferred, move_wide_preferred, sve_move_mask_preferred, sys_op, sys_op128, sysl_op};

pub struct Encoding {
    /// The specification's encoding name, such as `ADD_64_addsub_imm`.
    pub name: &'static str,
    pub mask: u32,
    pub value: u32,
    /// Decode condition id for [`super::spec::condition`]; 0 is always true.
    pub condition: u16,
    /// Encoding fields, most significant first.
    pub fields: &'static [Field],
    pub syntax: Syntax,
    pub aliases: &'static [Alias],
}

pub struct Field {
    pub name: &'static str,
    pub start: u8,
    pub width: u8,
}

pub struct Alias {
    /// The alias's operation id, such as `MOV_ADD_addsub_imm`.
    pub name: &'static str,
    /// When the alias applies at all.
    pub condition: u16,
    /// When the alias is the preferred disassembly.
    pub preferred: u16,
    pub syntax: Syntax,
}

pub struct Syntax {
    pub tokens: &'static [Token],
    pub operands: &'static [Operand],
}

pub enum Token {
    Text(&'static str),
    Operand(u8),
    /// Rendered unless every operand inside it is at its default value.
    Optional(&'static [Token]),
    /// The first alternative whose operands can all be rendered.
    Choice(&'static [&'static [Token]]),
}

pub struct Operand {
    /// The placeholder as the specification writes it, such as `<Xd|SP>`.
    pub name: &'static str,
    /// Indices into the encoding's fields, concatenated most significant first.
    pub fields: &'static [u8],
    /// The legal spellings, for operands the grammar defines as a choice (such as the arrangements of `<T>`).
    pub choices: &'static [&'static str],
}

pub enum Node {
    Switch { shift: u8, bits: u8, first: u32 },
    Leaf { first: u32, count: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysKind {
    Apas,
    At,
    Brb,
    Cfp,
    Cosp,
    Cpp,
    Dc,
    Dvp,
    Gcspopcx,
    Gcspopm,
    Gcspopx,
    Gcspushm,
    Gcspushx,
    Gcsss1,
    Gcsss2,
    Gic,
    Gicr,
    Gsb,
    Ic,
    Plbi,
    Tlbi,
    Tlbip,
    Trcit,
}

// Short constructors that keep the generated tables compact.

pub const fn enc(
    name: &'static str,
    mask: u32,
    value: u32,
    condition: u16,
    fields: &'static [Field],
    syntax: Syntax,
    aliases: &'static [Alias],
) -> Encoding {
    Encoding { name, mask, value, condition, fields, syntax, aliases }
}

pub const fn f(name: &'static str, start: u8, width: u8) -> Field {
    Field { name, start, width }
}

pub const fn alias(name: &'static str, condition: u16, preferred: u16, syntax: Syntax) -> Alias {
    Alias { name, condition, preferred, syntax }
}

pub const fn syn(tokens: &'static [Token], operands: &'static [Operand]) -> Syntax {
    Syntax { tokens, operands }
}

pub const fn op(name: &'static str, fields: &'static [u8], choices: &'static [&'static str]) -> Operand {
    Operand { name, fields, choices }
}

pub const fn sw(shift: u8, bits: u8, first: u32) -> Node {
    Node::Switch { shift, bits, first }
}

pub const fn leaf(first: u32, count: u16) -> Node {
    Node::Leaf { first, count }
}
pub use Token::{Choice as Alt, Operand as O, Optional as Opt, Text as T};
