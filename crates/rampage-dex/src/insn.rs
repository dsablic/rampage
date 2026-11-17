//! Dalvik bytecode: the opcode table (all 256 values and the three payload pseudo-instructions), decoding of each
//! instruction format, and smali-style text with every string, type, field, method, proto, call site and method
//! handle resolved through the DEX file.

use std::collections::HashMap;

use serde::Serialize;

use crate::dex::{Dex, cut, escape};

/// An instruction format, named as in the Dalvik bytecode documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
}

impl Format {
    /// Size in 16-bit code units.
    pub fn units(self) -> u32 {
        use Format::*;
        match self {
            F10x | F12x | F11n | F11x | F10t => 1,
            F20t | F22x | F21t | F21s | F21h | F21c | F23x | F22b | F22t | F22s | F22c => 2,
            F30t | F32x | F31i | F31t | F31c | F35c | F3rc => 3,
            F45cc | F4rcc => 4,
            F51l => 5,
        }
    }
}

/// What an instruction's index operand refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Debug, Clone, Copy)]
pub struct Op {
    pub name: &'static str,
    pub format: Format,
    pub reference: Option<RefKind>,
}

const fn op(name: &'static str, format: Format, reference: Option<RefKind>) -> Op {
    Op { name, format, reference }
}

const UNOPS: [&str; 21] = [
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "neg-float",
    "neg-double",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "long-to-float",
    "long-to-double",
    "float-to-int",
    "float-to-long",
    "float-to-double",
    "double-to-int",
    "double-to-long",
    "double-to-float",
    "int-to-byte",
    "int-to-char",
    "int-to-short",
];

const BINOPS: [&str; 32] = [
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long",
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double",
];

const BINOPS_2ADDR: [&str; 32] = [
    "add-int/2addr",
    "sub-int/2addr",
    "mul-int/2addr",
    "div-int/2addr",
    "rem-int/2addr",
    "and-int/2addr",
    "or-int/2addr",
    "xor-int/2addr",
    "shl-int/2addr",
    "shr-int/2addr",
    "ushr-int/2addr",
    "add-long/2addr",
    "sub-long/2addr",
    "mul-long/2addr",
    "div-long/2addr",
    "rem-long/2addr",
    "and-long/2addr",
    "or-long/2addr",
    "xor-long/2addr",
    "shl-long/2addr",
    "shr-long/2addr",
    "ushr-long/2addr",
    "add-float/2addr",
    "sub-float/2addr",
    "mul-float/2addr",
    "div-float/2addr",
    "rem-float/2addr",
    "add-double/2addr",
    "sub-double/2addr",
    "mul-double/2addr",
    "div-double/2addr",
    "rem-double/2addr",
];

const LIT16: [&str; 8] = [
    "add-int/lit16",
    "rsub-int",
    "mul-int/lit16",
    "div-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit16",
];

const LIT8: [&str; 11] = [
    "add-int/lit8",
    "rsub-int/lit8",
    "mul-int/lit8",
    "div-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "xor-int/lit8",
    "shl-int/lit8",
    "shr-int/lit8",
    "ushr-int/lit8",
];

const ARRAY_OPS: [&str; 14] = [
    "aget",
    "aget-wide",
    "aget-object",
    "aget-boolean",
    "aget-byte",
    "aget-char",
    "aget-short",
    "aput",
    "aput-wide",
    "aput-object",
    "aput-boolean",
    "aput-byte",
    "aput-char",
    "aput-short",
];

const INSTANCE_OPS: [&str; 14] = [
    "iget",
    "iget-wide",
    "iget-object",
    "iget-boolean",
    "iget-byte",
    "iget-char",
    "iget-short",
    "iput",
    "iput-wide",
    "iput-object",
    "iput-boolean",
    "iput-byte",
    "iput-char",
    "iput-short",
];

const STATIC_OPS: [&str; 14] = [
    "sget",
    "sget-wide",
    "sget-object",
    "sget-boolean",
    "sget-byte",
    "sget-char",
    "sget-short",
    "sput",
    "sput-wide",
    "sput-object",
    "sput-boolean",
    "sput-byte",
    "sput-char",
    "sput-short",
];

/// The opcode table entry for `code`. Unassigned values decode as `unused` (format 10x).
pub fn opcode(code: u8) -> Op {
    use Format::*;
    use RefKind as R;
    let n = usize::from(code);
    match code {
        0x00 => op("nop", F10x, None),
        0x01 => op("move", F12x, None),
        0x02 => op("move/from16", F22x, None),
        0x03 => op("move/16", F32x, None),
        0x04 => op("move-wide", F12x, None),
        0x05 => op("move-wide/from16", F22x, None),
        0x06 => op("move-wide/16", F32x, None),
        0x07 => op("move-object", F12x, None),
        0x08 => op("move-object/from16", F22x, None),
        0x09 => op("move-object/16", F32x, None),
        0x0a => op("move-result", F11x, None),
        0x0b => op("move-result-wide", F11x, None),
        0x0c => op("move-result-object", F11x, None),
        0x0d => op("move-exception", F11x, None),
        0x0e => op("return-void", F10x, None),
        0x0f => op("return", F11x, None),
        0x10 => op("return-wide", F11x, None),
        0x11 => op("return-object", F11x, None),
        0x12 => op("const/4", F11n, None),
        0x13 => op("const/16", F21s, None),
        0x14 => op("const", F31i, None),
        0x15 => op("const/high16", F21h, None),
        0x16 => op("const-wide/16", F21s, None),
        0x17 => op("const-wide/32", F31i, None),
        0x18 => op("const-wide", F51l, None),
        0x19 => op("const-wide/high16", F21h, None),
        0x1a => op("const-string", F21c, Some(R::String)),
        0x1b => op("const-string/jumbo", F31c, Some(R::String)),
        0x1c => op("const-class", F21c, Some(R::Type)),
        0x1d => op("monitor-enter", F11x, None),
        0x1e => op("monitor-exit", F11x, None),
        0x1f => op("check-cast", F21c, Some(R::Type)),
        0x20 => op("instance-of", F22c, Some(R::Type)),
        0x21 => op("array-length", F12x, None),
        0x22 => op("new-instance", F21c, Some(R::Type)),
        0x23 => op("new-array", F22c, Some(R::Type)),
        0x24 => op("filled-new-array", F35c, Some(R::Type)),
        0x25 => op("filled-new-array/range", F3rc, Some(R::Type)),
        0x26 => op("fill-array-data", F31t, None),
        0x27 => op("throw", F11x, None),
        0x28 => op("goto", F10t, None),
        0x29 => op("goto/16", F20t, None),
        0x2a => op("goto/32", F30t, None),
        0x2b => op("packed-switch", F31t, None),
        0x2c => op("sparse-switch", F31t, None),
        0x2d => op("cmpl-float", F23x, None),
        0x2e => op("cmpg-float", F23x, None),
        0x2f => op("cmpl-double", F23x, None),
        0x30 => op("cmpg-double", F23x, None),
        0x31 => op("cmp-long", F23x, None),
        0x32..=0x37 => op(["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"][n - 0x32], F22t, None),
        0x38..=0x3d => op(["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"][n - 0x38], F21t, None),
        0x44..=0x51 => op(ARRAY_OPS[n - 0x44], F23x, None),
        0x52..=0x5f => op(INSTANCE_OPS[n - 0x52], F22c, Some(R::Field)),
        0x60..=0x6d => op(STATIC_OPS[n - 0x60], F21c, Some(R::Field)),
        0x6e..=0x72 => op(
            ["invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"][n - 0x6e],
            F35c,
            Some(R::Method),
        ),
        0x74..=0x78 => op(
            [
                "invoke-virtual/range",
                "invoke-super/range",
                "invoke-direct/range",
                "invoke-static/range",
                "invoke-interface/range",
            ][n - 0x74],
            F3rc,
            Some(R::Method),
        ),
        0x7b..=0x8f => op(UNOPS[n - 0x7b], F12x, None),
        0x90..=0xaf => op(BINOPS[n - 0x90], F23x, None),
        0xb0..=0xcf => op(BINOPS_2ADDR[n - 0xb0], F12x, None),
        0xd0..=0xd7 => op(LIT16[n - 0xd0], F22s, None),
        0xd8..=0xe2 => op(LIT8[n - 0xd8], F22b, None),
        0xfa => op("invoke-polymorphic", F45cc, Some(R::Method)),
        0xfb => op("invoke-polymorphic/range", F4rcc, Some(R::Method)),
        0xfc => op("invoke-custom", F35c, Some(R::CallSite)),
        0xfd => op("invoke-custom/range", F3rc, Some(R::CallSite)),
        0xfe => op("const-method-handle", F21c, Some(R::MethodHandle)),
        0xff => op("const-method-type", F21c, Some(R::Proto)),
        _ => op("unused", F10x, None),
    }
}

/// A resolved index operand.
#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub kind: RefKind,
    pub index: u32,
    pub text: String,
}

/// One decoded instruction or payload.
#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    /// Address in 16-bit code units from the start of the method body.
    pub address: u32,
    pub units: u32,
    pub mnemonic: &'static str,
    /// Operands in smali style: registers, literals, `:xxxx` branch labels and resolved references.
    pub operands: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<Reference>,
    /// invoke-polymorphic's prototype.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<Reference>,
    /// Branch, switch-case and payload targets in code units.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<u32>,
}

/// Decoded fields before resolution.
struct Raw {
    regs: Vec<u32>,
    range: bool,
    literal: Option<i64>,
    index: Option<u32>,
    proto: Option<u32>,
    branch: Option<i64>,
}

fn label(address: i64) -> String {
    if address < 0 { format!(":-{:04x}", -address) } else { format!(":{address:04x}") }
}

fn hex(value: i64) -> String {
    if value < 0 { format!("-{:#x}", value.unsigned_abs()) } else { format!("{value:#x}") }
}

fn decode_raw(format: Format, unit: &[u16]) -> Option<Raw> {
    use Format::*;
    let u0 = u32::from(unit[0]);
    let a8 = u0 >> 8;
    let a4 = (u0 >> 8) & 0xf;
    let b4 = u0 >> 12;
    let w = |i: usize| u32::from(unit[i]);
    let w32 = |i: usize| w(i) | (w(i + 1) << 16);
    let mut raw = Raw { regs: Vec::new(), range: false, literal: None, index: None, proto: None, branch: None };
    match format {
        F10x => {}
        F12x => raw.regs = vec![a4, b4],
        F11n => {
            raw.regs = vec![a4];
            raw.literal = Some(i64::from(((b4 as i8) << 4) >> 4));
        }
        F11x => raw.regs = vec![a8],
        F10t => raw.branch = Some(i64::from(a8 as u8 as i8)),
        F20t => raw.branch = Some(i64::from(unit[1] as i16)),
        F22x => raw.regs = vec![a8, w(1)],
        F21t => {
            raw.regs = vec![a8];
            raw.branch = Some(i64::from(unit[1] as i16));
        }
        F21s => {
            raw.regs = vec![a8];
            raw.literal = Some(i64::from(unit[1] as i16));
        }
        F21h => {
            raw.regs = vec![a8];
            raw.literal = Some(i64::from(unit[1] as i16));
        }
        F21c => {
            raw.regs = vec![a8];
            raw.index = Some(w(1));
        }
        F23x => raw.regs = vec![a8, w(1) & 0xff, w(1) >> 8],
        F22b => {
            raw.regs = vec![a8, w(1) & 0xff];
            raw.literal = Some(i64::from((w(1) >> 8) as u8 as i8));
        }
        F22t => {
            raw.regs = vec![a4, b4];
            raw.branch = Some(i64::from(unit[1] as i16));
        }
        F22s => {
            raw.regs = vec![a4, b4];
            raw.literal = Some(i64::from(unit[1] as i16));
        }
        F22c => {
            raw.regs = vec![a4, b4];
            raw.index = Some(w(1));
        }
        F30t => raw.branch = Some(i64::from(w32(1) as i32)),
        F32x => raw.regs = vec![w(1), w(2)],
        F31i => {
            raw.regs = vec![a8];
            raw.literal = Some(i64::from(w32(1) as i32));
        }
        F31t => {
            raw.regs = vec![a8];
            raw.branch = Some(i64::from(w32(1) as i32));
        }
        F31c => {
            raw.regs = vec![a8];
            raw.index = Some(w32(1));
        }
        F35c | F45cc => {
            let count = b4 as usize;
            if count > 5 {
                return None;
            }
            let packed = w(2);
            let all = [packed & 0xf, (packed >> 4) & 0xf, (packed >> 8) & 0xf, packed >> 12, a4];
            raw.regs = all[..count].to_vec();
            raw.index = Some(w(1));
            if format == F45cc {
                raw.proto = Some(w(3));
            }
        }
        F3rc | F4rcc => {
            let first = w(2);
            raw.range = true;
            raw.regs = if a8 == 0 { Vec::new() } else { vec![first, first + a8 - 1] };
            raw.index = Some(w(1));
            if format == F4rcc {
                raw.proto = Some(w(3));
            }
        }
        F51l => {
            raw.regs = vec![a8];
            raw.literal = Some((u64::from(w32(1)) | (u64::from(w32(3)) << 32)) as i64);
        }
    }
    Some(raw)
}

fn resolve(dex: &Dex, kind: RefKind, index: u32) -> Reference {
    let text = match kind {
        RefKind::String => dex
            .string(index)
            .map_or_else(|_| format!("<bad string {index}>"), |s| format!("\"{}\"", escape(&cut(&s.text)))),
        RefKind::Type => dex.type_text(index),
        RefKind::Field => dex.field_text(index),
        RefKind::Method => dex.method_text(index),
        RefKind::Proto => dex.proto_text(index),
        RefKind::CallSite => dex.call_site_text(index),
        RefKind::MethodHandle => dex.method_handle_text(index),
    };
    Reference { kind, index, text }
}

/// The size in code units of the payload starting at `units[0]`, when it is one (`0x0100`, `0x0200`, `0x0300`).
fn payload_units(units: &[u16]) -> Option<u64> {
    let size = u64::from(*units.get(1)?);
    match units[0] {
        0x0100 => Some(4 + size * 2),
        0x0200 => Some(2 + size * 4),
        0x0300 => {
            let width = u64::from(units[1]);
            let count = u64::from(*units.get(2)?) | (u64::from(*units.get(3)?) << 16);
            Some(4 + (width * count).div_ceil(2))
        }
        _ => None,
    }
}

/// Bytes of fill-array-data shown as hex before the text is cut.
const MAX_ARRAY_HEX_BYTES: usize = 64;

/// What occupies one slot of a method body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Instruction,
    Payload,
    /// A code unit that starts no complete instruction (`.unit`).
    Unit,
}

/// Where each instruction of a body starts and how long it is, and which switch each payload belongs to: one pass
/// that resolves nothing, so a page of a long body can be rendered without rendering the rest.
pub struct Layout {
    /// `(address, units, slot)` in order.
    pub slots: Vec<(u32, u32, Slot)>,
    /// Switch payload address -> the switch instruction's address, for payload-relative targets.
    switches: HashMap<u32, u32>,
}

/// Lays out the body `insns` linearly. Payloads are recognised by their identifiers.
pub fn layout(insns: &[u16]) -> Layout {
    let mut slots = Vec::new();
    let mut switches = HashMap::new();
    let mut address = 0usize;
    while address < insns.len() {
        if let Some(size) = payload_units(&insns[address..])
            && address as u64 + size <= insns.len() as u64
        {
            slots.push((address as u32, size as u32, Slot::Payload));
            address += size as usize;
            continue;
        }
        let unit = insns[address];
        let op = opcode(unit as u8);
        let units = op.format.units() as usize;
        let decoded =
            (address + units <= insns.len()).then(|| decode_raw(op.format, &insns[address..address + units])).flatten();
        let Some(raw) = decoded else {
            slots.push((address as u32, 1, Slot::Unit));
            address += 1;
            continue;
        };
        if matches!(unit as u8, 0x2b | 0x2c)
            && let Some(branch) = raw.branch
        {
            let target = address as i64 + branch;
            if (0..insns.len() as i64).contains(&target) {
                switches.entry(target as u32).or_insert(address as u32);
            }
        }
        slots.push((address as u32, units as u32, Slot::Instruction));
        address += units;
    }
    Layout { slots, switches }
}

/// Renders slot `index` of `layout`, resolving its references through `dex`.
pub fn render(dex: &Dex, insns: &[u16], layout: &Layout, index: usize) -> Option<Insn> {
    let &(address, units, slot) = layout.slots.get(index)?;
    let start = address as usize;
    let body = &insns[start..start + units as usize];
    Some(match slot {
        Slot::Payload => payload(dex, body, address, &layout.switches),
        Slot::Unit => Insn {
            address,
            units: 1,
            mnemonic: ".unit",
            operands: format!("{:#06x}", body[0]),
            reference: None,
            proto: None,
            targets: Vec::new(),
        },
        Slot::Instruction => instruction(dex, body, address, insns.len()),
    })
}

/// Decodes the whole body `insns`: [`layout`], then [`render`] of every slot. Payloads are rendered with their
/// targets relative to the switch that refers to them; units that decode to nothing show as `.unit`.
pub fn disassemble(dex: &Dex, insns: &[u16]) -> Vec<Insn> {
    let layout = layout(insns);
    (0..layout.slots.len()).filter_map(|index| render(dex, insns, &layout, index)).collect()
}

fn instruction(dex: &Dex, body: &[u16], address: u32, len: usize) -> Insn {
    let unit = body[0];
    let op = opcode(unit as u8);
    let raw = decode_raw(op.format, body).expect("laid out as a decodable instruction");
    let mut parts: Vec<String> = Vec::new();
    if raw.range {
        parts.push(match raw.regs.as_slice() {
            [] => "{}".to_owned(),
            [first, last] if first == last => format!("{{v{first}}}"),
            [first, last] => format!("{{v{first} .. v{last}}}"),
            _ => "{}".to_owned(),
        });
    } else if matches!(op.format, Format::F35c | Format::F45cc) {
        let regs: Vec<String> = raw.regs.iter().map(|reg| format!("v{reg}")).collect();
        parts.push(format!("{{{}}}", regs.join(", ")));
    } else {
        parts.extend(raw.regs.iter().map(|reg| format!("v{reg}")));
    }
    if op.name == "unused" {
        parts.push(format!("{:#04x}", unit as u8));
    }
    if let Some(literal) = raw.literal {
        let value = match (op.format, unit as u8) {
            (Format::F21h, 0x15) => literal << 16,
            (Format::F21h, _) => literal << 48,
            _ => literal,
        };
        parts.push(hex(value));
    }
    let reference = op.reference.zip(raw.index).map(|(kind, index)| resolve(dex, kind, index));
    if let Some(reference) = &reference {
        parts.push(reference.text.clone());
    }
    let proto = raw.proto.map(|index| resolve(dex, RefKind::Proto, index));
    if let Some(proto) = &proto {
        parts.push(proto.text.clone());
    }
    let mut targets = Vec::new();
    if let Some(branch) = raw.branch {
        let target = i64::from(address) + branch;
        parts.push(label(target));
        if (0..len as i64).contains(&target) {
            targets.push(target as u32);
        }
    }
    Insn { address, units: body.len() as u32, mnemonic: op.name, operands: parts.join(", "), reference, proto, targets }
}

fn payload(_dex: &Dex, units: &[u16], address: u32, switches: &HashMap<u32, u32>) -> Insn {
    let word = |i: usize| u32::from(units[i]) | (u32::from(units[i + 1]) << 16);
    let base = switches.get(&address).map(|&switch| i64::from(switch));
    let target = |relative: i32| base.map(|base| base + i64::from(relative));
    let mut targets = Vec::new();
    let mut render_targets = |relatives: Vec<i32>| -> String {
        relatives
            .into_iter()
            .map(|relative| match target(relative) {
                Some(absolute) => {
                    if absolute >= 0 {
                        targets.push(absolute as u32);
                    }
                    label(absolute)
                }
                None => format!("+{}", hex(i64::from(relative))),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (mnemonic, operands) = match units[0] {
        0x0100 => {
            let size = usize::from(units[1]);
            let first = word(2) as i32;
            let relatives = (0..size).map(|i| word(4 + i * 2) as i32).collect();
            (
                "packed-switch-payload",
                format!("first_key={}, targets=[{}]", hex(i64::from(first)), render_targets(relatives)),
            )
        }
        0x0200 => {
            let size = usize::from(units[1]);
            let keys: Vec<String> = (0..size).map(|i| hex(i64::from(word(2 + i * 2) as i32))).collect();
            let relatives = (0..size).map(|i| word(2 + size * 2 + i * 2) as i32).collect();
            ("sparse-switch-payload", format!("keys=[{}], targets=[{}]", keys.join(", "), render_targets(relatives)))
        }
        _ => {
            let width = usize::from(units[1]);
            let count = word(2) as usize;
            let bytes: Vec<u8> = units[4..].iter().flat_map(|unit| unit.to_le_bytes()).take(width * count).collect();
            let shown: String = bytes.iter().take(MAX_ARRAY_HEX_BYTES).map(|byte| format!("{byte:02x}")).collect();
            let cut = if bytes.len() > MAX_ARRAY_HEX_BYTES { "..." } else { "" };
            ("fill-array-data-payload", format!("width={width}, count={count}, data={shown}{cut}"))
        }
    };
    Insn { address, units: units.len() as u32, mnemonic, operands, reference: None, proto: None, targets }
}

/// Every method an `invoke-*` instruction in `insns` calls, and every string a `const-string` loads, by index:
/// a fast scan that resolves nothing, for cross-references.
pub fn references(insns: &[u16], mut each: impl FnMut(RefKind, u32, u32)) {
    let mut address = 0usize;
    while address < insns.len() {
        if let Some(size) = payload_units(&insns[address..]) {
            address = address.saturating_add(size as usize);
            continue;
        }
        let op = opcode(insns[address] as u8);
        let units = op.format.units() as usize;
        if address + units > insns.len() {
            break;
        }
        if let Some(kind) = op.reference
            && matches!(kind, RefKind::String | RefKind::Method)
        {
            let index = match op.format {
                Format::F31c => u32::from(insns[address + 1]) | (u32::from(insns[address + 2]) << 16),
                _ => u32::from(insns[address + 1]),
            };
            each(kind, index, address as u32);
        }
        address += units;
    }
}
