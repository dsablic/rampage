//! CIL disassembly of one managed method body (ECMA-335 Partition III): every one-byte and `0xFE`-prefixed
//! opcode with its operand, metadata tokens resolved to names and signatures, `ldstr` literals from `#US`, the
//! exception clauses after a fat body (II.25.4.6) and the local variable types from its LocalVarSig (II.23.2.6).
//!
//! The body is hostile input: decoding is bounded by the body's bytes and [`MAX_INSTRUCTIONS`], a byte that is no
//! opcode renders as `.byte 0xNN` and decoding continues after it, and an operand cut off by the end of the body
//! ends the listing with that instruction marked truncated.

use std::collections::HashMap;

use serde::Serialize;

use super::signatures::{Generics, Reader};
use super::tables::{self, Coded};
use super::{
    BodyKind, Decoder, DotNetMetadata, IlBody, MethodDef, Warnings, il_body, member_owners, read_u16, read_u32,
};
use crate::LoadError;

/// Instructions decoded from one body; a longer body is listed up to here and marked truncated.
pub const MAX_INSTRUCTIONS: usize = 131_072;
/// Targets kept from one `switch`; the rest are counted, not listed.
const MAX_SWITCH_TARGETS: usize = 4096;
/// Switch targets kept across one listing, which bounds its label text as [`MAX_OPERAND_TEXT`] bounds its
/// token text; later switches are counted, not listed.
const MAX_LISTING_SWITCH_TARGETS: usize = 1 << 18;
/// UTF-16 units of an `ldstr` literal shown; a longer literal is cut and its length given.
const MAX_LITERAL_UNITS: usize = 512;
/// Local variable type text kept from one LocalVarSig; up to 65,535 locals of up to 8 KiB each would otherwise
/// fill every page of the listing. Later locals are counted, not listed.
pub const MAX_LOCALS_TEXT: usize = 64 << 10;
/// Rendered operand text of one listing; past it tokens show as hex, since every instruction naming a
/// long signature would otherwise repeat it.
const MAX_OPERAND_TEXT: usize = 16 << 20;
/// Overloads an ambiguous-name error lists; the rest are counted.
const MAX_CANDIDATES: usize = 50;
const MAX_EH_SECTIONS: usize = 64;
const MAX_CLAUSES: usize = 4096;

/// Fat header flag (II.25.4.4): locals are zero-initialized.
const CORILMETHOD_INIT_LOCALS: u16 = 0x10;
/// Method data section flags (II.25.4.5).
const SECTION_EH_TABLE: u8 = 0x01;
const SECTION_FAT_FORMAT: u8 = 0x40;
const SECTION_MORE_SECTS: u8 = 0x80;
const USER_STRING_TABLE: u8 = 0x70;

/// Which method [`super::method_il`] disassembles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodSelector<'s> {
    /// A MethodDef token, e.g. `0x0600000d`.
    Token(u32),
    /// `Namespace.Type::Name` (nested types as `Outer/Inner`), or a bare method name.
    Name(&'s str),
}

impl std::fmt::Display for MethodSelector<'_> {
    /// The selector as a user writes it: a hex token or the name.
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Token(token) => write!(formatter, "{token:#010x}"),
            Self::Name(name) => formatter.write_str(name),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IlError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error("no method {0} in the assembly")]
    NotFound(String),
    #[error("{name} names {total} methods; select one by token: {}{}", candidates.join("; "), more(*total, candidates))]
    Ambiguous {
        name: String,
        /// Every method the name matches.
        total: usize,
        /// The first [`MAX_CANDIDATES`] of them as `token Type::Name signature`.
        candidates: Vec<String>,
    },
    #[error("{method} has no IL body (its body is {body:?})")]
    NoBody { method: String, body: BodyKind },
    #[error("{method}: {reason}")]
    Unreadable { method: String, reason: String },
}

/// `; ... N more` for the candidates an ambiguous-name error leaves out.
fn more(total: usize, listed: &[String]) -> String {
    match total.saturating_sub(listed.len()) {
        0 => String::new(),
        left => format!("; ... {left} more"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodIl {
    pub token: u32,
    /// `Namespace.Type::Name`.
    pub method: String,
    pub signature: String,
    pub rva: u32,
    pub body: IlBody,
    /// Whether the fat header asks for zero-initialized locals (`.locals init`).
    pub init_locals: bool,
    /// Local variable types by index, from the LocalVarSig; empty when there are none or it is unreadable. Only
    /// the first [`MAX_LOCALS_TEXT`] bytes of type text are kept.
    pub locals: Vec<String>,
    /// Locals the LocalVarSig declares, listed or not.
    pub locals_total: usize,
    /// Whether `locals` stops before `locals_total`.
    pub locals_truncated: bool,
    pub exception_clauses: Vec<ExceptionClause>,
    pub instructions: Vec<Instruction>,
    /// Whether the listing stops early: at the instruction cap, a cut-off operand, or a body shorter than its
    /// header declares.
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instruction {
    /// Offset from the start of the IL code.
    pub offset: u32,
    /// The ILAsm opcode name, or `.byte` for a byte that is no opcode.
    pub opcode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operand: Option<String>,
    /// The metadata token operand of a call, field, type, string or signature instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<u32>,
    /// Branch and switch targets as IL offsets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<u32>,
}

impl Instruction {
    /// `IL_0000: ldarg.0`, ILDasm style.
    pub fn text(&self) -> String {
        match &self.operand {
            Some(operand) => format!("{}: {} {operand}", label(self.offset), self.opcode),
            None => format!("{}: {}", label(self.offset), self.opcode),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClauseKind {
    Catch,
    Filter,
    Finally,
    Fault,
    /// Flags no ECMA-335 clause kind uses.
    Unknown,
}

/// One exception handling clause (II.25.4.6); ranges are IL offsets, ends exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExceptionClause {
    pub kind: ClauseKind,
    pub flags: u32,
    pub try_start: u32,
    pub try_end: u32,
    pub handler_start: u32,
    pub handler_end: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_start: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_token: Option<u32>,
    /// The caught type's name, when the token resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_type: Option<String>,
}

impl ExceptionClause {
    /// `.try IL_0000 to IL_0010 catch System.Exception handler IL_0010 to IL_0018`, ILAsm style.
    pub fn text(&self) -> String {
        let what = match self.kind {
            ClauseKind::Catch => {
                let token = self.catch_token.map(|token| format!("<token {token:#010x}>")).unwrap_or_default();
                format!("catch {}", self.catch_type.clone().unwrap_or(token))
            }
            ClauseKind::Filter => format!("filter {}", label(self.filter_start.unwrap_or(0))),
            ClauseKind::Finally => "finally".to_owned(),
            ClauseKind::Fault => "fault".to_owned(),
            ClauseKind::Unknown => format!("flags {:#x}", self.flags),
        };
        format!(
            ".try {} to {} {what} handler {} to {}",
            label(self.try_start),
            label(self.try_end),
            label(self.handler_start),
            label(self.handler_end)
        )
    }
}

/// ILDasm's label for an IL offset.
fn label(offset: u32) -> String {
    format!("IL_{offset:04x}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    None,
    Int8,
    Int32,
    Int64,
    Float32,
    Float64,
    ShortBranch,
    Branch,
    Switch,
    Token,
    Arg8,
    Arg16,
    Local8,
    Local16,
    /// The alignment of `unaligned.` or the check mask of `no.`.
    UInt8,
}

impl Operand {
    /// Bytes the operand takes; a switch's are counted separately from its 4-byte count.
    fn size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Int8 | Self::ShortBranch | Self::Arg8 | Self::Local8 | Self::UInt8 => 1,
            Self::Arg16 | Self::Local16 => 2,
            Self::Int32 | Self::Float32 | Self::Branch | Self::Switch | Self::Token => 4,
            Self::Int64 | Self::Float64 => 8,
        }
    }
}

/// The one-byte opcodes (III.1.2.1, the 0x00-0xE0 table); `None` for an unused byte and the 0xFE prefix.
fn opcode(code: u8) -> Option<(&'static str, Operand)> {
    use Operand::*;
    let simple = |name| Some((name, None));
    match code {
        0x00 => simple("nop"),
        0x01 => simple("break"),
        0x02 => simple("ldarg.0"),
        0x03 => simple("ldarg.1"),
        0x04 => simple("ldarg.2"),
        0x05 => simple("ldarg.3"),
        0x06 => simple("ldloc.0"),
        0x07 => simple("ldloc.1"),
        0x08 => simple("ldloc.2"),
        0x09 => simple("ldloc.3"),
        0x0A => simple("stloc.0"),
        0x0B => simple("stloc.1"),
        0x0C => simple("stloc.2"),
        0x0D => simple("stloc.3"),
        0x0E => Some(("ldarg.s", Arg8)),
        0x0F => Some(("ldarga.s", Arg8)),
        0x10 => Some(("starg.s", Arg8)),
        0x11 => Some(("ldloc.s", Local8)),
        0x12 => Some(("ldloca.s", Local8)),
        0x13 => Some(("stloc.s", Local8)),
        0x14 => simple("ldnull"),
        0x15 => simple("ldc.i4.m1"),
        0x16 => simple("ldc.i4.0"),
        0x17 => simple("ldc.i4.1"),
        0x18 => simple("ldc.i4.2"),
        0x19 => simple("ldc.i4.3"),
        0x1A => simple("ldc.i4.4"),
        0x1B => simple("ldc.i4.5"),
        0x1C => simple("ldc.i4.6"),
        0x1D => simple("ldc.i4.7"),
        0x1E => simple("ldc.i4.8"),
        0x1F => Some(("ldc.i4.s", Int8)),
        0x20 => Some(("ldc.i4", Int32)),
        0x21 => Some(("ldc.i8", Int64)),
        0x22 => Some(("ldc.r4", Float32)),
        0x23 => Some(("ldc.r8", Float64)),
        0x25 => simple("dup"),
        0x26 => simple("pop"),
        0x27 => Some(("jmp", Token)),
        0x28 => Some(("call", Token)),
        0x29 => Some(("calli", Token)),
        0x2A => simple("ret"),
        0x2B => Some(("br.s", ShortBranch)),
        0x2C => Some(("brfalse.s", ShortBranch)),
        0x2D => Some(("brtrue.s", ShortBranch)),
        0x2E => Some(("beq.s", ShortBranch)),
        0x2F => Some(("bge.s", ShortBranch)),
        0x30 => Some(("bgt.s", ShortBranch)),
        0x31 => Some(("ble.s", ShortBranch)),
        0x32 => Some(("blt.s", ShortBranch)),
        0x33 => Some(("bne.un.s", ShortBranch)),
        0x34 => Some(("bge.un.s", ShortBranch)),
        0x35 => Some(("bgt.un.s", ShortBranch)),
        0x36 => Some(("ble.un.s", ShortBranch)),
        0x37 => Some(("blt.un.s", ShortBranch)),
        0x38 => Some(("br", Branch)),
        0x39 => Some(("brfalse", Branch)),
        0x3A => Some(("brtrue", Branch)),
        0x3B => Some(("beq", Branch)),
        0x3C => Some(("bge", Branch)),
        0x3D => Some(("bgt", Branch)),
        0x3E => Some(("ble", Branch)),
        0x3F => Some(("blt", Branch)),
        0x40 => Some(("bne.un", Branch)),
        0x41 => Some(("bge.un", Branch)),
        0x42 => Some(("bgt.un", Branch)),
        0x43 => Some(("ble.un", Branch)),
        0x44 => Some(("blt.un", Branch)),
        0x45 => Some(("switch", Switch)),
        0x46 => simple("ldind.i1"),
        0x47 => simple("ldind.u1"),
        0x48 => simple("ldind.i2"),
        0x49 => simple("ldind.u2"),
        0x4A => simple("ldind.i4"),
        0x4B => simple("ldind.u4"),
        0x4C => simple("ldind.i8"),
        0x4D => simple("ldind.i"),
        0x4E => simple("ldind.r4"),
        0x4F => simple("ldind.r8"),
        0x50 => simple("ldind.ref"),
        0x51 => simple("stind.ref"),
        0x52 => simple("stind.i1"),
        0x53 => simple("stind.i2"),
        0x54 => simple("stind.i4"),
        0x55 => simple("stind.i8"),
        0x56 => simple("stind.r4"),
        0x57 => simple("stind.r8"),
        0x58 => simple("add"),
        0x59 => simple("sub"),
        0x5A => simple("mul"),
        0x5B => simple("div"),
        0x5C => simple("div.un"),
        0x5D => simple("rem"),
        0x5E => simple("rem.un"),
        0x5F => simple("and"),
        0x60 => simple("or"),
        0x61 => simple("xor"),
        0x62 => simple("shl"),
        0x63 => simple("shr"),
        0x64 => simple("shr.un"),
        0x65 => simple("neg"),
        0x66 => simple("not"),
        0x67 => simple("conv.i1"),
        0x68 => simple("conv.i2"),
        0x69 => simple("conv.i4"),
        0x6A => simple("conv.i8"),
        0x6B => simple("conv.r4"),
        0x6C => simple("conv.r8"),
        0x6D => simple("conv.u4"),
        0x6E => simple("conv.u8"),
        0x6F => Some(("callvirt", Token)),
        0x70 => Some(("cpobj", Token)),
        0x71 => Some(("ldobj", Token)),
        0x72 => Some(("ldstr", Token)),
        0x73 => Some(("newobj", Token)),
        0x74 => Some(("castclass", Token)),
        0x75 => Some(("isinst", Token)),
        0x76 => simple("conv.r.un"),
        0x79 => Some(("unbox", Token)),
        0x7A => simple("throw"),
        0x7B => Some(("ldfld", Token)),
        0x7C => Some(("ldflda", Token)),
        0x7D => Some(("stfld", Token)),
        0x7E => Some(("ldsfld", Token)),
        0x7F => Some(("ldsflda", Token)),
        0x80 => Some(("stsfld", Token)),
        0x81 => Some(("stobj", Token)),
        0x82 => simple("conv.ovf.i1.un"),
        0x83 => simple("conv.ovf.i2.un"),
        0x84 => simple("conv.ovf.i4.un"),
        0x85 => simple("conv.ovf.i8.un"),
        0x86 => simple("conv.ovf.u1.un"),
        0x87 => simple("conv.ovf.u2.un"),
        0x88 => simple("conv.ovf.u4.un"),
        0x89 => simple("conv.ovf.u8.un"),
        0x8A => simple("conv.ovf.i.un"),
        0x8B => simple("conv.ovf.u.un"),
        0x8C => Some(("box", Token)),
        0x8D => Some(("newarr", Token)),
        0x8E => simple("ldlen"),
        0x8F => Some(("ldelema", Token)),
        0x90 => simple("ldelem.i1"),
        0x91 => simple("ldelem.u1"),
        0x92 => simple("ldelem.i2"),
        0x93 => simple("ldelem.u2"),
        0x94 => simple("ldelem.i4"),
        0x95 => simple("ldelem.u4"),
        0x96 => simple("ldelem.i8"),
        0x97 => simple("ldelem.i"),
        0x98 => simple("ldelem.r4"),
        0x99 => simple("ldelem.r8"),
        0x9A => simple("ldelem.ref"),
        0x9B => simple("stelem.i"),
        0x9C => simple("stelem.i1"),
        0x9D => simple("stelem.i2"),
        0x9E => simple("stelem.i4"),
        0x9F => simple("stelem.i8"),
        0xA0 => simple("stelem.r4"),
        0xA1 => simple("stelem.r8"),
        0xA2 => simple("stelem.ref"),
        0xA3 => Some(("ldelem", Token)),
        0xA4 => Some(("stelem", Token)),
        0xA5 => Some(("unbox.any", Token)),
        0xB3 => simple("conv.ovf.i1"),
        0xB4 => simple("conv.ovf.u1"),
        0xB5 => simple("conv.ovf.i2"),
        0xB6 => simple("conv.ovf.u2"),
        0xB7 => simple("conv.ovf.i4"),
        0xB8 => simple("conv.ovf.u4"),
        0xB9 => simple("conv.ovf.i8"),
        0xBA => simple("conv.ovf.u8"),
        0xC2 => Some(("refanyval", Token)),
        0xC3 => simple("ckfinite"),
        0xC6 => Some(("mkrefany", Token)),
        0xD0 => Some(("ldtoken", Token)),
        0xD1 => simple("conv.u2"),
        0xD2 => simple("conv.u1"),
        0xD3 => simple("conv.i"),
        0xD4 => simple("conv.ovf.i"),
        0xD5 => simple("conv.ovf.u"),
        0xD6 => simple("add.ovf"),
        0xD7 => simple("add.ovf.un"),
        0xD8 => simple("mul.ovf"),
        0xD9 => simple("mul.ovf.un"),
        0xDA => simple("sub.ovf"),
        0xDB => simple("sub.ovf.un"),
        0xDC => simple("endfinally"),
        0xDD => Some(("leave", Branch)),
        0xDE => Some(("leave.s", ShortBranch)),
        0xDF => simple("stind.i"),
        0xE0 => simple("conv.u"),
        _ => Option::None,
    }
}

/// The two-byte opcodes `0xFE xx` (III.1.2.1); `None` for an unused second byte.
fn extended_opcode(code: u8) -> Option<(&'static str, Operand)> {
    use Operand::*;
    let simple = |name| Some((name, None));
    match code {
        0x00 => simple("arglist"),
        0x01 => simple("ceq"),
        0x02 => simple("cgt"),
        0x03 => simple("cgt.un"),
        0x04 => simple("clt"),
        0x05 => simple("clt.un"),
        0x06 => Some(("ldftn", Token)),
        0x07 => Some(("ldvirtftn", Token)),
        0x09 => Some(("ldarg", Arg16)),
        0x0A => Some(("ldarga", Arg16)),
        0x0B => Some(("starg", Arg16)),
        0x0C => Some(("ldloc", Local16)),
        0x0D => Some(("ldloca", Local16)),
        0x0E => Some(("stloc", Local16)),
        0x0F => simple("localloc"),
        0x11 => simple("endfilter"),
        0x12 => Some(("unaligned.", UInt8)),
        0x13 => simple("volatile."),
        0x14 => simple("tail."),
        0x15 => Some(("initobj", Token)),
        0x16 => Some(("constrained.", Token)),
        0x17 => simple("cpblk"),
        0x18 => simple("initblk"),
        0x19 => Some(("no.", UInt8)),
        0x1A => simple("rethrow"),
        0x1C => Some(("sizeof", Token)),
        0x1D => simple("refanytype"),
        0x1E => simple("readonly."),
        _ => Option::None,
    }
}

/// Renders the metadata tokens of one listing, caching each and charging the text against
/// [`MAX_OPERAND_TEXT`].
struct Names<'d, 't, 'a> {
    decoder: &'d Decoder<'t, 'a>,
    /// The owning TypeDef row of each MethodDef and Field token.
    owners: HashMap<u32, u32>,
    cache: HashMap<u32, Option<String>>,
    spent: usize,
    spent_reported: bool,
    /// Whether the warning that the signature budget ran out has been given.
    budget_reported: bool,
}

impl<'d, 't, 'a> Names<'d, 't, 'a> {
    fn new(decoder: &'d Decoder<'t, 'a>, metadata: &DotNetMetadata) -> Self {
        let mut owners = HashMap::new();
        for (ty, row) in metadata.types.iter().zip(1..) {
            let members = ty.methods.iter().map(|method| method.token);
            owners.extend(members.chain(ty.fields.iter().map(|field| field.token)).map(|token| (token, row)));
        }
        Self { decoder, owners, cache: HashMap::new(), spent: 0, spent_reported: false, budget_reported: false }
    }

    /// Whether the signature budget is spent, warning of it once; a signature that fails then is not malformed.
    fn budget_spent(&mut self, warnings: &mut Warnings) -> bool {
        let spent = self.decoder.budget.get() == 0;
        if spent && !std::mem::replace(&mut self.budget_reported, true) {
            warnings.push(super::BUDGET_EXHAUSTED.to_owned());
        }
        spent
    }

    /// The operand text of `token`: its name and signature, or `<token 0x...>` when it does not resolve or the
    /// listing's text budget is spent.
    fn operand(&mut self, token: u32, warnings: &mut Warnings) -> String {
        let unresolved = || format!("<token {token:#010x}>");
        if self.spent > MAX_OPERAND_TEXT {
            if !std::mem::replace(&mut self.spent_reported, true) {
                warnings.push("operand text budget spent; later tokens are shown as hex".to_owned());
            }
            return unresolved();
        }
        let text = match self.cache.get(&token) {
            Some(text) => text.clone(),
            None => {
                let text = self.resolve(token);
                self.budget_spent(warnings);
                self.cache.insert(token, text.clone());
                text
            }
        };
        let text = text.unwrap_or_else(unresolved);
        self.spent += text.len();
        text
    }

    fn resolve(&self, token: u32) -> Option<String> {
        let decoder = self.decoder;
        let (table, row) = ((token >> 24) as u8, token & tables::MAX_ROWS);
        match table {
            USER_STRING_TABLE => {
                let (units, total) = decoder.heaps.user_string(row, MAX_LITERAL_UNITS)?;
                Some(literal(&units, total))
            }
            tables::TYPE_DEF | tables::TYPE_REF | tables::TYPE_SPEC => decoder.row_label(table, row),
            tables::METHOD_DEF | tables::FIELD => {
                let name = decoder.row_label(table, row)?;
                let Some(&owner) = self.owners.get(&token) else { return Some(name) };
                let qualified = self.qualified(owner, &name);
                Some(decoder.render_signature(table, row, &qualified, Some(owner)).unwrap_or(qualified))
            }
            tables::MEMBER_REF => {
                let qualified = self.member_ref_name(row)?;
                Some(decoder.render_signature(table, row, &qualified, None).unwrap_or(qualified))
            }
            tables::METHOD_SPEC => self.method_spec(row),
            tables::STAND_ALONE_SIG => {
                let blob = decoder.heaps.blob(decoder.tables.cell(table, row, 0)?)?;
                let method = Reader::new(decoder, Generics::default(), &decoder.budget).method(blob)?;
                Some(method.render("", &Generics::default()))
            }
            _ => None,
        }
    }

    fn qualified(&self, owner: u32, name: &str) -> String {
        match self.decoder.row_label(tables::TYPE_DEF, owner) {
            Some(ty) => format!("{ty}::{name}"),
            None => name.to_owned(),
        }
    }

    /// `Parent::Name` of a MemberRef row.
    fn member_ref_name(&self, row: u32) -> Option<String> {
        let decoder = self.decoder;
        let name = decoder.heaps.string(decoder.tables.cell(tables::MEMBER_REF, row, 1)?)?;
        let parent = decoder.tables.cell(tables::MEMBER_REF, row, 0);
        Some(match parent.and_then(|value| decoder.coded_label(Coded::MemberRefParent, value)) {
            Some(parent) => format!("{parent}::{name}"),
            None => name,
        })
    }

    /// A MethodSpec (II.22.29): the generic method's signature, ILAsm style, with the instantiation in place
    /// of its generic parameter list: `int32 System.HashCode::Combine<int32>(!!0)`.
    fn method_spec(&self, row: u32) -> Option<String> {
        let decoder = self.decoder;
        let method = decoder.tables.cell(tables::METHOD_SPEC, row, 0)?;
        let instantiation = decoder.heaps.blob(decoder.tables.cell(tables::METHOD_SPEC, row, 1)?)?;
        let arguments = Reader::new(decoder, Generics::default(), &decoder.budget).method_spec(instantiation)?;
        let arguments: Vec<(u32, String)> = (0..).zip(arguments.into_iter().map(|ty| ty.text)).collect();
        let (table, method) = Coded::MethodDefOrRef.decode(method)?;
        let (name, owner, column) = match table {
            tables::METHOD_DEF => {
                let name = decoder.row_label(table, method)?;
                let owner = self.owners.get(&super::token(table, method)).copied();
                (owner.map_or_else(|| name.clone(), |owner| self.qualified(owner, &name)), owner, 4)
            }
            _ => (self.member_ref_name(method)?, None, 2),
        };
        let blob = decoder.tables.cell(table, method, column).and_then(|offset| decoder.heaps.blob(offset));
        let type_params = owner.map_or(&[][..], |owner| decoder.generics(tables::TYPE_DEF, owner));
        let context = Generics { type_params, method_params: &[] };
        let signature = blob.and_then(|blob| Reader::new(decoder, context, &decoder.budget).method(blob));
        let instantiated = Generics { type_params: &[], method_params: &arguments };
        Some(match signature {
            Some(signature) => signature.render(&name, &instantiated),
            None => {
                let arguments: Vec<&str> = arguments.iter().map(|(_, text)| text.as_str()).collect();
                format!("{name}<{}>", arguments.join(", "))
            }
        })
    }
}

/// An `ldstr` literal as a quoted, escaped string; `total` is the literal's full length in UTF-16 units.
fn literal(units: &[u16], total: usize) -> String {
    let mut text = String::from("\"");
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok('"') => text.push_str("\\\""),
            Ok('\\') => text.push_str("\\\\"),
            Ok('\n') => text.push_str("\\n"),
            Ok('\r') => text.push_str("\\r"),
            Ok('\t') => text.push_str("\\t"),
            Ok('\0') => text.push_str("\\0"),
            // Bidi overrides and invisible format characters are escaped too, so a hostile literal cannot
            // reorder or hide the listing text around it.
            Ok(c)
                if c.is_control()
                    || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}')
                    || matches!(c, '\u{2060}'..='\u{2069}' | '\u{FEFF}') =>
            {
                text.push_str(&format!("\\u{:04x}", u32::from(c)))
            }
            Ok(c) => text.push(c),
            Err(error) => text.push_str(&format!("\\u{:04x}", error.unpaired_surrogate())),
        }
    }
    text.push('"');
    if total > units.len() {
        text.push_str(&format!("... ({total} chars)"));
    }
    text
}

/// Disassembles the method `selector` names, while `decoder` still holds the image's tables.
pub(super) fn disassemble<'a>(
    decoder: &Decoder,
    metadata: &DotNetMetadata,
    read_rva: &dyn Fn(u32) -> Option<&'a [u8]>,
    selector: MethodSelector,
) -> Result<MethodIl, IlError> {
    let owners = member_owners(&metadata.types, |row| decoder.row_label(tables::TYPE_DEF, row));
    let (method, owner) = select(metadata, &owners, selector)?;
    let name = owners.get(&method.token).cloned().unwrap_or_else(|| method.name.clone());
    if method.body != BodyKind::Il {
        return Err(IlError::NoBody { method: name, body: method.body });
    }
    let unreadable = |reason: &str| IlError::Unreadable { method: name.clone(), reason: reason.to_owned() };
    let bytes = read_rva(method.rva).ok_or_else(|| unreadable("the body RVA is unmapped"))?;
    let body = il_body(bytes).ok_or_else(|| unreadable("the body header is invalid"))?;
    let mut warnings = Warnings::default();
    let start = body.header_size as usize;
    let declared_end = start.saturating_add(body.code_size as usize);
    let code = bytes.get(start.min(bytes.len())..declared_end.min(bytes.len())).unwrap_or_default();
    let mut truncated = false;
    if code.len() < body.code_size as usize {
        warnings.push(format!("the body declares {} bytes of IL but only {} are mapped", body.code_size, code.len()));
        truncated = true;
    }
    let init_locals =
        body.header == super::IlHeader::Fat && read_u16(bytes, 0).is_some_and(|f| f & CORILMETHOD_INIT_LOCALS != 0);
    let method_row = method.token & tables::MAX_ROWS;
    let mut names = Names::new(decoder, metadata);
    let (locals, locals_total) = locals(&mut names, body.local_var_sig_token, owner, method_row, &mut warnings);
    let (instructions, cut) = decode(code, &mut |token, warnings| names.operand(token, warnings), &mut warnings);
    let exception_clauses = if body.more_sections && code.len() == body.code_size as usize {
        let clauses = exception_clauses(bytes, method.rva, declared_end, &mut names, &mut warnings);
        check_clause_ranges(&clauses, body.code_size, &mut warnings);
        clauses
    } else {
        Vec::new()
    };
    Ok(MethodIl {
        token: method.token,
        method: name,
        signature: method.signature.clone(),
        rva: method.rva,
        body,
        init_locals,
        locals_truncated: locals.len() < locals_total,
        locals,
        locals_total,
        exception_clauses,
        instructions,
        truncated: truncated || cut,
        warnings: warnings.0,
    })
}

/// The one method `selector` names, with its owning TypeDef row.
fn select<'m>(
    metadata: &'m DotNetMetadata,
    owners: &HashMap<u32, String>,
    selector: MethodSelector,
) -> Result<(&'m MethodDef, u32), IlError> {
    let methods = metadata.types.iter().zip(1..).flat_map(|(ty, row)| ty.methods.iter().map(move |m| (m, row)));
    let (wanted, matched): (String, Vec<_>) = match selector {
        MethodSelector::Token(token) => {
            (selector.to_string(), methods.filter(|(method, _)| method.token == token).collect())
        }
        MethodSelector::Name(name) if name.contains("::") => (
            name.to_owned(),
            methods.filter(|(method, _)| owners.get(&method.token).is_some_and(|owner| owner == name)).collect(),
        ),
        MethodSelector::Name(name) => (name.to_owned(), methods.filter(|(method, _)| method.name == name).collect()),
    };
    match matched.as_slice() {
        [] => Err(IlError::NotFound(wanted)),
        [one] => Ok(*one),
        many => Err(ambiguous(
            wanted,
            many.iter().map(|(method, _)| {
                let owner = owners.get(&method.token).map_or("", |owner| owner.as_str());
                format!("{:#010x} {owner} {}", method.token, method.signature)
            }),
        )),
    }
}

/// The error for a name matching every method of `candidates`, listing the first [`MAX_CANDIDATES`].
fn ambiguous(name: String, candidates: impl ExactSizeIterator<Item = String>) -> IlError {
    let total = candidates.len();
    IlError::Ambiguous { name, total, candidates: candidates.take(MAX_CANDIDATES).collect() }
}

/// The local variable types of a LocalVarSig StandAloneSig token, in the method's generic context, up to
/// [`MAX_LOCALS_TEXT`] of their text, with how many it declares.
fn locals(names: &mut Names, token: u32, owner: u32, method: u32, warnings: &mut Warnings) -> (Vec<String>, usize) {
    let decoder = names.decoder;
    if token == 0 {
        return (Vec::new(), 0);
    }
    let blob = ((token >> 24) as u8 == tables::STAND_ALONE_SIG)
        .then(|| decoder.tables.cell(tables::STAND_ALONE_SIG, token & tables::MAX_ROWS, 0))
        .flatten()
        .and_then(|offset| decoder.heaps.blob(offset));
    let generics = Generics {
        type_params: decoder.generics(tables::TYPE_DEF, owner),
        method_params: decoder.generics(tables::METHOD_DEF, method),
    };
    let locals = blob.and_then(|blob| Reader::new(decoder, generics, &decoder.budget).locals(blob));
    match locals {
        Some(locals) => {
            let total = locals.len();
            let mut text = 0;
            let kept: Vec<String> = locals
                .into_iter()
                .map(|ty| ty.text)
                .take_while(|ty| {
                    text += ty.len();
                    text <= MAX_LOCALS_TEXT
                })
                .collect();
            if kept.len() < total {
                warnings.push(format!(
                    "only the first {} of {total} locals are listed ({MAX_LOCALS_TEXT} bytes of type text)",
                    kept.len()
                ));
            }
            (kept, total)
        }
        None => {
            if !names.budget_spent(warnings) {
                warnings.push(format!("local variable signature {token:#010x} is unreadable"));
            }
            (Vec::new(), 0)
        }
    }
}

/// Renders a token operand.
type TokenText<'n> = &'n mut dyn FnMut(u32, &mut Warnings) -> String;

/// Decodes `code` into instructions; the flag says whether decoding stopped before the end of `code`.
fn decode(code: &[u8], token_text: TokenText, warnings: &mut Warnings) -> (Vec<Instruction>, bool) {
    let mut instructions = Vec::new();
    let mut at = 0usize;
    let (mut switch_targets_left, mut switch_cap_reported) = (MAX_LISTING_SWITCH_TARGETS, false);
    while at < code.len() {
        if instructions.len() == MAX_INSTRUCTIONS {
            warnings.push(format!("listing stops at {MAX_INSTRUCTIONS} instructions"));
            return (instructions, true);
        }
        let offset = at as u32;
        let first = code[at];
        at += 1;
        let byte = |operand: String| Instruction {
            offset,
            opcode: ".byte",
            operand: Some(operand),
            token: None,
            targets: Vec::new(),
        };
        let decoded = if first == 0xFE {
            match code.get(at) {
                Some(&second) => {
                    at += 1;
                    extended_opcode(second).ok_or_else(|| byte(format!("0xfe, {second:#04x}")))
                }
                None => Err(byte("0xfe".to_owned())),
            }
        } else {
            opcode(first).ok_or_else(|| byte(format!("{first:#04x}")))
        };
        let (name, operand) = match decoded {
            Ok(decoded) => decoded,
            Err(unknown) => {
                instructions.push(unknown);
                continue;
            }
        };
        let rest = &code[at..];
        let mut instruction = Instruction { offset, opcode: name, operand: None, token: None, targets: Vec::new() };
        let size = operand_size(operand, rest);
        let Some(bytes) = rest.get(..size) else {
            instruction.operand = Some(format!("<truncated: {} of {size} operand bytes>", rest.len()));
            warnings.push(format!("{name} at {} is cut off by the end of the body", label(offset)));
            instructions.push(instruction);
            return (instructions, true);
        };
        at += size;
        let branch = Branch { from: offset, next: at as i64, code_length: code.len(), opcode: name };
        instruction.operand = match operand {
            Operand::None => None,
            Operand::Int8 | Operand::Int32 | Operand::Int64 => Some(read_signed(bytes).to_string()),
            Operand::UInt8 | Operand::Arg8 | Operand::Arg16 => Some(read_unsigned(bytes).to_string()),
            Operand::Local8 | Operand::Local16 => Some(format!("V_{}", read_unsigned(bytes))),
            Operand::Float32 => Some(float32(read_unsigned(bytes) as u32)),
            Operand::Float64 => Some(float64(read_unsigned(bytes))),
            Operand::ShortBranch | Operand::Branch => {
                Some(branch.target(read_signed(bytes), &mut instruction, warnings))
            }
            Operand::Token => {
                let token = read_unsigned(bytes) as u32;
                instruction.token = Some(token);
                Some(token_text(token, warnings))
            }
            Operand::Switch => {
                let count = bytes.len() / 4 - 1;
                let kept = count.min(MAX_SWITCH_TARGETS);
                if kept > switch_targets_left && !std::mem::replace(&mut switch_cap_reported, true) {
                    warnings.push(format!(
                        "listing keeps {MAX_LISTING_SWITCH_TARGETS} switch targets; later ones are counted, not listed"
                    ));
                }
                let kept = kept.min(switch_targets_left);
                switch_targets_left -= kept;
                let mut labels = Vec::new();
                for chunk in bytes[4..].as_chunks::<4>().0.iter().take(kept) {
                    labels.push(branch.target(i64::from(i32::from_le_bytes(*chunk)), &mut instruction, warnings));
                }
                if count > labels.len() {
                    labels.push(format!("... {} more", count - labels.len()));
                }
                Some(format!("({})", labels.join(", ")))
            }
        };
        instructions.push(instruction);
    }
    (instructions, false)
}

/// Bytes the operand at the start of `rest` takes; for a switch, its count and every target, which can exceed
/// `rest` (the caller then reports the operand cut off).
fn operand_size(operand: Operand, rest: &[u8]) -> usize {
    match operand {
        Operand::Switch => match read_u32(rest, 0) {
            Some(count) => (count as usize).saturating_mul(4).saturating_add(4),
            None => 4,
        },
        _ => operand.size(),
    }
}

/// The branching instruction a target is relative to.
struct Branch {
    from: u32,
    /// Offset of the next instruction, which targets are relative to (III.1.7.2).
    next: i64,
    code_length: usize,
    opcode: &'static str,
}

impl Branch {
    /// The target `delta` bytes from the next instruction as a label, recorded on `instruction`.
    fn target(&self, delta: i64, instruction: &mut Instruction, warnings: &mut Warnings) -> String {
        let target = self.next + delta;
        let Ok(offset) = u32::try_from(target) else {
            warnings.push(format!("{} at {} targets offset {target}, before the body", self.opcode, label(self.from)));
            return format!("<offset {target}>");
        };
        if offset as usize >= self.code_length {
            warnings.push(format!("{} at {} targets {} past the body", self.opcode, label(self.from), label(offset)));
        }
        instruction.targets.push(offset);
        label(offset)
    }
}

/// An `ldc.r4` constant; a NaN as its raw bits, ILDasm style, since its sign and payload would otherwise be lost.
fn float32(bits: u32) -> String {
    let value = f32::from_bits(bits);
    if value.is_nan() { format!("float32({bits:#010x})") } else { format!("{value:?}") }
}

/// An `ldc.r8` constant, rendered as [`float32`] renders an `ldc.r4` one.
fn float64(bits: u64) -> String {
    let value = f64::from_bits(bits);
    if value.is_nan() { format!("float64({bits:#018x})") } else { format!("{value:?}") }
}

/// A little-endian unsigned integer of at most 8 bytes.
fn read_unsigned(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

/// A little-endian two's-complement integer of 1, 4 or 8 bytes.
fn read_signed(bytes: &[u8]) -> i64 {
    let shift = 64 - 8 * bytes.len() as u32;
    ((read_unsigned(bytes) << shift) as i64) >> shift
}

/// The exception clauses of the data sections after the code (II.25.4.5), which start at the next 4-byte
/// aligned RVA after it. Sections other than exception tables are skipped.
fn exception_clauses(
    bytes: &[u8],
    rva: u32,
    code_end: usize,
    names: &mut Names,
    warnings: &mut Warnings,
) -> Vec<ExceptionClause> {
    let mut clauses = Vec::new();
    let mut position = (u64::from(rva) + code_end as u64).next_multiple_of(4);
    for _ in 0..MAX_EH_SECTIONS {
        let at = (position - u64::from(rva)) as usize;
        let Some(&kind) = bytes.get(at) else {
            warnings.push("exception sections lie past the end of the section".to_owned());
            return clauses;
        };
        let fat = kind & SECTION_FAT_FORMAT != 0;
        let size = if fat {
            bytes
                .get(at + 1..at + 4)
                .map(|size| usize::from(size[0]) | usize::from(size[1]) << 8 | usize::from(size[2]) << 16)
        } else {
            bytes.get(at + 1).map(|&size| usize::from(size))
        };
        let Some(data) = size.filter(|&size| size >= 4).and_then(|size| bytes.get(at..at + size)) else {
            warnings.push("an exception section is malformed or truncated".to_owned());
            return clauses;
        };
        if kind & 0x3F == SECTION_EH_TABLE {
            let clause_size = if fat { 24 } else { 12 };
            for clause in data[4..].chunks_exact(clause_size) {
                if clauses.len() == MAX_CLAUSES {
                    warnings.push(format!("only the first {MAX_CLAUSES} exception clauses are listed"));
                    return clauses;
                }
                clauses.push(exception_clause(clause, fat, names, warnings));
            }
        }
        if kind & SECTION_MORE_SECTS == 0 {
            return clauses;
        }
        position = (position + data.len() as u64).next_multiple_of(4);
    }
    warnings.push(format!("only the first {MAX_EH_SECTIONS} method data sections are read"));
    clauses
}

/// Warns of each clause range that leaves the `code_length` bytes of IL, as branch targets past the body are.
fn check_clause_ranges(clauses: &[ExceptionClause], code_length: u32, warnings: &mut Warnings) {
    for (clause, number) in clauses.iter().zip(1..) {
        let ranges = [("try", clause.try_start, clause.try_end), ("handler", clause.handler_start, clause.handler_end)];
        for (what, start, end) in ranges {
            if start >= code_length || end > code_length {
                warnings.push(format!(
                    "exception clause {number} {what} {} to {} runs past the {code_length}-byte body",
                    label(start),
                    label(end)
                ));
            }
        }
        if let Some(filter) = clause.filter_start.filter(|&filter| filter >= code_length) {
            warnings.push(format!(
                "exception clause {number} filter {} lies past the {code_length}-byte body",
                label(filter)
            ));
        }
    }
}

fn exception_clause(clause: &[u8], fat: bool, names: &mut Names, warnings: &mut Warnings) -> ExceptionClause {
    // Small clauses (II.25.4.6) pack 2-byte offsets and 1-byte lengths; fat ones use 4 bytes for each.
    let fields: [u32; 6] = if fat {
        std::array::from_fn(|index| read_u32(clause, index * 4).unwrap_or(0))
    } else {
        let u16_at = |offset| u32::from(read_u16(clause, offset).unwrap_or(0));
        [u16_at(0), u16_at(2), u32::from(clause[4]), u16_at(5), u32::from(clause[7]), read_u32(clause, 8).unwrap_or(0)]
    };
    let [flags, try_start, try_length, handler_start, handler_length, extra] = fields;
    let kind = match flags {
        0 => ClauseKind::Catch,
        1 => ClauseKind::Filter,
        2 => ClauseKind::Finally,
        4 => ClauseKind::Fault,
        _ => ClauseKind::Unknown,
    };
    let catch_token = (kind == ClauseKind::Catch).then_some(extra);
    ExceptionClause {
        kind,
        flags,
        try_start,
        try_end: try_start.saturating_add(try_length),
        handler_start,
        handler_end: handler_start.saturating_add(handler_length),
        filter_start: (kind == ClauseKind::Filter).then_some(extra),
        catch_token,
        catch_type: catch_token.and_then(|token| {
            let text = names.operand(token, warnings);
            (!text.starts_with("<token ")).then_some(text)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_byte_has_one_meaning() {
        let one: Vec<u8> = (0..=255u8).filter(|&code| opcode(code).is_some()).collect();
        // III.1.2.1: 0x00-0xE0 less the 34 unused bytes 0x24, 0x77, 0x78, 0xA6-0xB2, 0xBB-0xC1, 0xC4, 0xC5,
        // 0xC7-0xCF.
        assert_eq!(one.len(), 0xE1 - 1 - 2 - 13 - 7 - 2 - 9);
        let two = (0..=255u8).filter(|&code| extended_opcode(code).is_some()).count();
        assert_eq!(two, 0x1F - 3, "0xFE 0x00-0x1E less 0x08, 0x10 and 0x1B");
        assert_eq!(opcode(0x20), Some(("ldc.i4", Operand::Int32)));
        assert_eq!(extended_opcode(0x16), Some(("constrained.", Operand::Token)));
    }

    #[test]
    fn escapes_and_caps_literals() {
        let units: Vec<u16> = "a\"b\\\n\u{202E}é".encode_utf16().chain([0xD800]).collect();
        assert_eq!(literal(&units, units.len()), "\"a\\\"b\\\\\\n\\u202eé\\ud800\"");
        assert_eq!(literal(&[u16::from(b'x')], 600), "\"x\"... (600 chars)");
    }

    fn listing(code: &[u8]) -> (Vec<String>, bool, Vec<String>) {
        let mut warnings = Warnings::default();
        let mut token_text = |token: u32, _: &mut Warnings| format!("T{token:x}");
        let (instructions, cut) = decode(code, &mut token_text, &mut warnings);
        (instructions.iter().map(Instruction::text).collect(), cut, warnings.0)
    }

    #[test]
    fn decodes_every_operand_kind() {
        let mut code = vec![0x1F, 0xFE, 0x20, 0x78, 0x56, 0x34, 0x12, 0x21];
        code.extend([0xFF; 8]);
        code.extend([0x22, 0x00, 0x00, 0x80, 0x3F, 0x23, 0, 0, 0, 0, 0, 0, 0xF8, 0x7F]);
        // switch at 0x1e with targets +0 and -5 from 0x2b.
        code.extend([0x45, 2, 0, 0, 0, 0, 0, 0, 0, 0xFB, 0xFF, 0xFF, 0xFF]);
        code.extend([0x24, 0xFE, 0x08, 0xFE, 0x0C, 0x03, 0x01, 0xFE, 0x09, 0x02, 0x00, 0xFE, 0x12, 0x04]);
        code.extend([0x11, 0x07, 0x0E, 0x01, 0x72, 0x05, 0x00, 0x00, 0x70, 0x38, 0xC0, 0xFF, 0xFF, 0xFF]);
        code.extend([0xFE, 0x16, 0x01, 0x00, 0x00, 0x1B, 0xDE, 0x00, 0x2A]);
        let (texts, cut, warnings) = listing(&code);
        assert_eq!(
            texts,
            [
                "IL_0000: ldc.i4.s -2",
                "IL_0002: ldc.i4 305419896",
                "IL_0007: ldc.i8 -1",
                "IL_0010: ldc.r4 1.0",
                "IL_0015: ldc.r8 float64(0x7ff8000000000000)",
                "IL_001e: switch (IL_002b, IL_0026)",
                "IL_002b: .byte 0x24",
                "IL_002c: .byte 0xfe, 0x08",
                "IL_002e: ldloc V_259",
                "IL_0032: ldarg 2",
                "IL_0036: unaligned. 4",
                "IL_0039: ldloc.s V_7",
                "IL_003b: ldarg.s 1",
                "IL_003d: ldstr T70000005",
                "IL_0042: br IL_0007",
                "IL_0047: constrained. T1b000001",
                "IL_004d: leave.s IL_004f",
                "IL_004f: ret",
            ]
        );
        assert!(!cut && warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn branches_outside_the_body_are_reported() {
        let (texts, cut, warnings) = listing(&[0x2B, 0x10, 0x2B, 0x80, 0x45, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(texts, ["IL_0000: br.s IL_0012", "IL_0002: br.s <offset -124>", "IL_0004: switch (IL_000d)"]);
        assert!(!cut);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
    }

    #[test]
    fn every_truncation_ends_cleanly() {
        let mut code = vec![0x45, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0x21];
        code.extend([1; 8]);
        code.extend([0x28, 1, 0, 0, 0x0A, 0xFE, 0x0C, 1, 0, 0xFE]);
        for length in 0..code.len() {
            let (texts, cut, _) = listing(&code[..length]);
            assert!(texts.len() <= length);
            let last = texts.last().map_or("", String::as_str);
            assert_eq!(cut, last.contains("<truncated"), "{length}: {texts:?}");
        }
        let (texts, cut, _) = listing(&code);
        assert_eq!(texts.last().unwrap(), "IL_001f: .byte 0xfe");
        assert!(!cut);
        // A switch whose count claims 16 GiB of targets is cut off, not allocated.
        let (texts, cut, _) = listing(&[0x45, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
        assert_eq!(texts, ["IL_0000: switch <truncated: 8 of 17179869184 operand bytes>"]);
        assert!(cut);
    }

    #[test]
    fn listings_stop_at_the_instruction_cap() {
        let (texts, cut, warnings) = listing(&vec![0x00; MAX_INSTRUCTIONS + 5]);
        assert_eq!(texts.len(), MAX_INSTRUCTIONS);
        assert!(cut);
        assert_eq!(warnings, [format!("listing stops at {MAX_INSTRUCTIONS} instructions")]);
        let (texts, _, _) = listing(&[0x45, 0x01, 0x10, 0, 0]);
        assert_eq!(texts.len(), 1);
        let mut switch = vec![0x45];
        switch.extend(((MAX_SWITCH_TARGETS + 2) as u32).to_le_bytes());
        switch.extend(vec![0; (MAX_SWITCH_TARGETS + 2) * 4]);
        let (texts, _, _) = listing(&switch);
        assert!(texts[0].ends_with("IL_400d, ... 2 more)"), "{}", &texts[0][texts[0].len() - 40..]);
    }

    #[test]
    fn ambiguous_names_list_the_first_candidates() {
        let error = ambiguous("M".to_owned(), (0..70).map(|index| format!("c{index}")));
        let text = error.to_string();
        assert!(text.starts_with("M names 70 methods; select one by token: c0; c1; "), "{text}");
        assert!(text.ends_with("; c49; ... 20 more"), "{text}");
        let IlError::Ambiguous { total, candidates, .. } = error else { panic!() };
        assert_eq!((total, candidates.len()), (70, MAX_CANDIDATES));
        assert!(
            ambiguous("M".to_owned(), ["a".to_owned(), "b".to_owned()].into_iter()).to_string().ends_with(": a; b")
        );
    }

    #[test]
    fn clause_ranges_past_the_body_are_reported() {
        let inside = ExceptionClause {
            kind: ClauseKind::Filter,
            flags: 1,
            try_start: 0,
            try_end: 4,
            handler_start: 6,
            handler_end: 8,
            filter_start: Some(4),
            catch_token: None,
            catch_type: None,
        };
        let past = ExceptionClause { try_start: 8, try_end: 8, filter_start: Some(9), ..inside.clone() };
        let mut warnings = Warnings::default();
        check_clause_ranges(&[inside.clone(), past], 8, &mut warnings);
        assert_eq!(
            warnings.0,
            [
                "exception clause 2 try IL_0008 to IL_0008 runs past the 8-byte body",
                "exception clause 2 filter IL_0009 lies past the 8-byte body",
            ]
        );
        check_clause_ranges(&[inside], 7, &mut warnings);
        assert_eq!(warnings.0[2], "exception clause 1 handler IL_0006 to IL_0008 runs past the 7-byte body");
    }

    #[test]
    fn nans_keep_their_sign_and_payload() {
        assert_eq!(float32(0xFFC0_0001), "float32(0xffc00001)");
        assert_eq!(float32(0x7F80_0000), "inf");
        assert_eq!(float32(0x3F80_0000), "1.0");
        assert_eq!(float64(0xFFF8_0000_0000_0001), "float64(0xfff8000000000001)");
        assert_eq!(float64(0x7FF0_0000_0000_0002), "float64(0x7ff0000000000002)");
        assert_eq!(float64(0x8000_0000_0000_0000), "-0.0");
        let (texts, _, _) = listing(&[0x22, 0x01, 0x00, 0xC0, 0xFF]);
        assert_eq!(texts, ["IL_0000: ldc.r4 float32(0xffc00001)"]);
    }

    #[test]
    fn switch_targets_are_capped_per_listing() {
        let switches = MAX_LISTING_SWITCH_TARGETS / MAX_SWITCH_TARGETS + 6;
        let mut code = Vec::new();
        for _ in 0..switches {
            code.push(0x45);
            code.extend((MAX_SWITCH_TARGETS as u32).to_le_bytes());
            code.extend(vec![0; MAX_SWITCH_TARGETS * 4]);
        }
        let mut warnings = Warnings::default();
        let (instructions, cut) = decode(&code, &mut |_, _| String::new(), &mut warnings);
        assert_eq!((instructions.len(), cut), (switches, false));
        let targets: usize = instructions.iter().map(|instruction| instruction.targets.len()).sum();
        assert_eq!(targets, MAX_LISTING_SWITCH_TARGETS);
        let text: usize =
            instructions.iter().filter_map(|instruction| instruction.operand.as_ref()).map(String::len).sum();
        assert!(text < MAX_LISTING_SWITCH_TARGETS * 10, "{text} bytes of switch labels");
        assert_eq!(instructions.last().unwrap().operand.as_deref(), Some("(... 4096 more)"));
        let capped = warnings.0.iter().filter(|warning| warning.contains("switch targets")).count();
        assert_eq!(capped, 1, "{:?}", warnings.0);
    }

    #[test]
    fn signed_operands_sign_extend() {
        assert_eq!(read_signed(&[0xFE]), -2);
        assert_eq!(read_signed(&[0xFF, 0xFF, 0xFF, 0x7F]), i64::from(i32::MAX));
        assert_eq!(read_signed(&[0, 0, 0, 0x80]), i64::from(i32::MIN));
        assert_eq!(read_signed(&[0xFF; 8]), -1);
    }
}
