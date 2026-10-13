//! Control flow and data references of decoded instructions.
//!
//! Each encoding's flow class, address effect and general-purpose destinations are worked out once from its name
//! and assembly syntax. Data references follow the address a register holds after ADRP (or an ADD of an
//! immediate to a known address) into the loads, stores and ADDs that use it.

use std::sync::LazyLock;

use super::Decoded;
use super::helpers::{ones, pc_relative};
use super::spec::ENCODINGS;
use super::spec_types::{Encoding, Token};
use crate::{Flow, JumpTable, MAX_JUMP_TABLE_ENTRIES};

/// Addresses known to be held by general-purpose registers: ADRP pages, and the full addresses an ADD forms
/// from them.
#[derive(Clone, Default)]
pub struct Addresses {
    valid: u32,
    /// Registers holding a page rather than a full address.
    page: u32,
    value: [u64; 31],
    /// Registers holding an unknown offset from a known full address (a switch's `add x9, x9, x10, lsl #2`).
    derived: u32,
    derived_base: [u64; 31],
    /// Registers whose upper 32 bits a write to their W view zeroed.
    upper_zero: u32,
    /// The comparison of a register with an immediate that the previous instruction made.
    compare: Option<Compare>,
    /// Unsigned bounds that a `b.hi` or `b.hs` after a comparison proved on its fall-through path.
    bounds: [Option<Bound>; 31],
    /// Registers holding a switch-table entry, or a target formed from one.
    entries: [Option<Entry>; 31],
    pub memory_changed: bool,
}

#[derive(Clone, Copy)]
struct Compare {
    register: u64,
    limit: u64,
    wide: bool,
    address: u64,
}

#[derive(Clone, Copy)]
struct Bound {
    max: u64,
    /// Whether the bound covers the whole X register rather than only its W view.
    wide: bool,
    guard: u64,
}

/// How a table load extends its entry into the 64-bit register.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Extension {
    Zero,
    Sign,
    /// Sign-extended into the W view, whose write zeroes the upper half.
    SignToW,
}

#[derive(Clone, Copy)]
struct Entry {
    table: JumpTable,
    load: Extension,
}

impl Addresses {
    fn get(&self, register: u64) -> Option<u64> {
        (register < 31 && self.valid & (1 << register) != 0).then(|| self.value[register as usize])
    }

    fn page(&self, register: u64) -> Option<u64> {
        self.get(register).filter(|_| self.page & (1 << register) != 0)
    }

    fn full(&self, register: u64) -> Option<u64> {
        self.get(register).filter(|_| self.page & (1 << register) == 0)
    }

    /// The full address `register` holds, or that it holds an unknown offset from.
    fn base(&self, register: u64) -> Option<u64> {
        let derived = register < 31 && self.derived & (1 << register) != 0;
        self.full(register).or_else(|| derived.then(|| self.derived_base[register as usize]))
    }

    fn set_derived(&mut self, register: u64, base: u64) {
        if register < 31 {
            self.derived |= 1 << register;
            self.derived_base[register as usize] = base;
        }
    }

    fn set(&mut self, register: u64, address: u64, page: bool) {
        if register < 31 {
            self.valid |= 1 << register;
            self.page = (self.page & !(1 << register)) | (u32::from(page) << register);
            self.value[register as usize] = address;
        }
    }

    fn clear(&mut self, register: u64) {
        if register < 31 {
            self.valid &= !(1 << register);
            self.derived &= !(1 << register);
            self.upper_zero &= !(1 << register);
            self.bounds[register as usize] = None;
            self.entries[register as usize] = None;
        }
    }

    /// A call may change x0-x18 and x30 (AAPCS64); x19-x28 are preserved.
    fn clobber_caller_saved(&mut self) {
        for register in (0..19).chain([30]) {
            self.clear(register);
        }
    }

    fn bound(&self, register: u64) -> Option<Bound> {
        self.bounds.get(usize::try_from(register).ok()?).copied().flatten()
    }

    fn entry(&self, register: u64) -> Option<Entry> {
        self.entries.get(usize::try_from(register).ok()?).copied().flatten()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowClass {
    Next,
    Jump,
    /// B.cond and BC.cond: unconditional when the condition is AL or NV.
    ConditionalBranch,
    ConditionalJump,
    Call,
    IndirectJump,
    IndirectCall,
    Return,
    Halt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    None,
    Adrp,
    Adr,
    /// ADD (immediate), 64-bit.
    AddImmediate,
    /// Load or store with an unsigned 12-bit offset scaled by the access size (`None`: by the size field).
    ScaledOffset(Option<u64>),
    LoadLiteral,
}

/// A general-purpose register field an instruction writes; `plus` is 1 for the second register of a pair that
/// shares one field (CASP).
#[derive(Clone, Copy)]
struct Written {
    start: u8,
    width: u8,
    plus: u8,
    /// A W register, whose write zeroes the upper half of the X register.
    narrow: bool,
}

struct Info {
    flow: FlowClass,
    effect: Effect,
    written: Vec<Written>,
    /// Pre- and post-indexed forms update the base register.
    writeback: Option<Written>,
    /// Registers written that no operand names, such as CHKFEAT's x16.
    implicit: Vec<u64>,
    /// Whether `written`, `writeback` and `implicit` are every general-purpose register the instruction writes.
    writes_known: bool,
    /// Calls and supervisor calls may change every caller-saved register.
    clobbers_caller_saved: bool,
}

static INFO: LazyLock<Vec<Info>> = LazyLock::new(|| ENCODINGS.iter().map(info_for).collect());

fn info_for(encoding: &Encoding) -> Info {
    let name = encoding.name;
    let prefix = name.split('_').next().unwrap_or(name);
    let flow = match prefix {
        "B" if name == "B_only_branch_imm" => FlowClass::Jump,
        "B" | "BC" if name.ends_with("condbranch") => FlowClass::ConditionalBranch,
        "BL" => FlowClass::Call,
        "CBZ" | "CBNZ" | "TBZ" | "TBNZ" => FlowClass::ConditionalJump,
        _ if prefix.starts_with("CB") && (name.ends_with("_regs") || name.ends_with("_imm")) => {
            FlowClass::ConditionalJump
        }
        "BR" | "BRAA" | "BRAAZ" | "BRAB" | "BRABZ" => FlowClass::IndirectJump,
        "BLR" | "BLRAA" | "BLRAAZ" | "BLRAB" | "BLRABZ" => FlowClass::IndirectCall,
        "RET" | "RETAA" | "RETAB" | "RETAASPPC" | "RETABSPPC" | "RETAASPPCR" | "RETABSPPCR" | "ERET" | "ERETAA"
        | "ERETAB" | "DRPS" | "TEXIT" => FlowClass::Return,
        // HLT is a debugger or semihosting call, which resumes at the next instruction.
        "BRK" | "UDF" => FlowClass::Halt,
        _ => FlowClass::Next,
    };
    let effect = if name.starts_with("ADRP") {
        Effect::Adrp
    } else if name.starts_with("ADR_") {
        Effect::Adr
    } else if name == "ADD_64_addsub_imm" {
        Effect::AddImmediate
    } else if name.ends_with("_loadlit") {
        Effect::LoadLiteral
    } else if name.ends_with("_ldst_pos") {
        Effect::ScaledOffset(name.contains("_Q_").then_some(16))
    } else {
        Effect::None
    };

    let written_by = |register: &str| -> bool {
        let starts = |prefixes: &[&str]| prefixes.iter().any(|p| prefix.starts_with(p));
        match register {
            "Rd" | "Rdn" => true,
            "Rt" => starts(&["LD", "MRS", "MRRS", "SWP", "CAS", "RCW", "SYSL", "GCSPOP"]),
            "Rt2" => starts(&["LD", "SWP", "RCW"]),
            // Store-exclusive status and compare-and-swap old values.
            "Rs" => starts(&["ST", "CAS", "RCW", "CPY", "SET"]),
            _ => false,
        }
    };
    let mut written = Vec::new();
    let mut base = None;
    for operand in encoding.syntax.operands {
        let &[index] = operand.fields else { continue };
        let register = &encoding.fields[index as usize];
        if register.name == "Rn" {
            base = Some(Written { start: register.start, width: register.width, plus: 0, narrow: false });
        }
        // Only W and X operands are general-purpose registers; SIMD&FP destinations use the same field names.
        // SVE writes some as <R><d>, where <R> picks W or X.
        let general = operand.name.starts_with("<W")
            || operand.name.starts_with("<X")
            || matches!(operand.name, "<d>" | "<dn>") && encoding.syntax.operands.iter().any(|o| o.name == "<R>");
        if general && written_by(register.name) {
            let plus = u8::from(operand.name.contains("+1"));
            let narrow = operand.name.starts_with("<W");
            written.push(Written { start: register.start, width: register.width, plus, narrow });
        }
    }
    // LD64B loads eight consecutive registers from one field.
    if prefix == "LD64B" {
        let first = written.pop();
        written.extend(first.into_iter().flat_map(|first| (0..8).map(move |plus| Written { plus, ..first })));
    }
    // CPY* and SET* advance all three of their registers; LDRAA and LDRAB write back when W is set. Pre- and
    // post-indexed forms without a class of their own (LDAPR Xt, [Xn], #8) show it in their syntax.
    let indexed_syntax =
        |token: &Token| matches!(token, Token::Text(text) if text.contains("]!") || text.contains("], #"));
    let indexed = ["post", "pre", "asisdlsep", "asisdlsop", "memcms", "memset_go", "64W_ldst_pac"]
        .iter()
        .any(|n| name.contains(n))
        || encoding.syntax.tokens.iter().any(indexed_syntax);
    let clobbers_caller_saved =
        matches!(flow, FlowClass::Call | FlowClass::IndirectCall) || matches!(prefix, "SVC" | "HVC" | "SMC");
    let implicit = match prefix {
        "CHKFEAT" => vec![16],
        "PACIA1716" | "PACIB1716" | "AUTIA1716" | "AUTIB1716" => vec![17],
        "PACIAZ" | "PACIASP" | "PACIBZ" | "PACIBSP" | "AUTIAZ" | "AUTIASP" | "AUTIBZ" | "AUTIBSP" | "XPACLRI" => {
            vec![30]
        }
        _ => Vec::new(),
    };
    Info {
        flow,
        effect,
        written,
        writeback: base.filter(|_| indexed),
        implicit,
        writes_known: writes_known(name, prefix),
        clobbers_caller_saved,
    }
}

/// Encoding classes where an instruction can write general-purpose registers that no operand names (CHKFEAT
/// writes x16, LD64B eight registers from one field), with the mnemonics whose writes [`info_for`] models. Any
/// other encoding of these classes, such as an unallocated hint that a later extension gives a result, may write
/// registers the model misses.
const AUDITED: &[(&str, &[&str])] = &[
    (
        "hints",
        &[
            "NOP",
            "YIELD",
            "WFE",
            "WFI",
            "SEV",
            "SEVL",
            "DGH",
            "ESB",
            "PSB",
            "TSB",
            "GCSB",
            "CSDB",
            "CLRBHB",
            "BTI",
            "PACM",
            "STSHH",
            "SHUH",
            "STCPH",
            "CHKFEAT",
            "XPACLRI",
            "PACIA1716",
            "PACIB1716",
            "AUTIA1716",
            "AUTIB1716",
            "PACIAZ",
            "PACIASP",
            "PACIBZ",
            "PACIBSP",
            "AUTIAZ",
            "AUTIASP",
            "AUTIBZ",
            "AUTIBSP",
        ],
    ),
    ("systeminstrs", &["SYS", "SYSL"]),
    ("systeminstrswithreg", &["WFET", "WFIT"]),
    ("syspairinstrs", &["SYSP"]),
    ("systemmove", &["MRS", "MSR"]),
    ("systemmovepr", &["MRRS", "MSRR"]),
    ("exception", &["SVC", "HVC", "SMC", "BRK", "HLT"]),
];

/// Atomic memory-operation mnemonic families whose register writes [`info_for`] models.
const AUDITED_MEMORY_OPERATIONS: &[&str] = &[
    "LD64B", "ST64B", "LDADD", "LDCLR", "LDEOR", "LDSET", "LDSMAX", "LDSMIN", "LDUMAX", "LDUMIN", "LDAPR", "LDTADD",
    "LDTCLR", "LDTSET", "SWP", "RCW",
];

/// Whether [`info_for`] knows every general-purpose register the encoding writes.
fn writes_known(name: &str, prefix: &str) -> bool {
    let class = name.splitn(3, '_').nth(2).unwrap_or("");
    if class.starts_with("memop") {
        return AUDITED_MEMORY_OPERATIONS.iter().any(|family| prefix.starts_with(family));
    }
    AUDITED.iter().find(|(audited, _)| *audited == class).is_none_or(|(_, mnemonics)| mnemonics.contains(&prefix))
}

/// The PC-relative target of a branch or literal load: imm26, imm19, imm14 or imm9 words.
fn relative_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let (raw, width) = [("imm26", 26), ("imm19", 19), ("imm14", 14), ("imm9", 9)]
        .into_iter()
        .find_map(|(name, width)| decoded.field(name).map(|raw| (raw, width)))?;
    Some(pc_relative(address, raw, width, 2).0)
}

/// ADR/ADRP targets; ADRP yields the 4 KiB page.
fn address_target(decoded: &Decoded, address: u64) -> Option<u64> {
    let raw = (decoded.field("immhi")? << 2) | decoded.field("immlo")?;
    let scale = if decoded.encoding.name.starts_with("ADRP") { 12 } else { 0 };
    Some(pc_relative(address, raw, 21, scale).0)
}

fn index_of(encoding: &'static Encoding) -> usize {
    (encoding as *const Encoding as usize - ENCODINGS.as_ptr() as usize) / size_of::<Encoding>()
}

/// How a register-offset load of a switch-table entry extends it, or `None` for any other instruction.
fn table_load(name: &str) -> Option<Extension> {
    match name {
        "LDRB_32B_ldst_regoff"
        | "LDRB_32BL_ldst_regoff"
        | "LDRH_32_ldst_regoff"
        | "LDR_32_ldst_regoff"
        | "LDR_64_ldst_regoff" => Some(Extension::Zero),
        "LDRSB_64B_ldst_regoff" | "LDRSB_64BL_ldst_regoff" | "LDRSH_64_ldst_regoff" | "LDRSW_64_ldst_regoff" => {
            Some(Extension::Sign)
        }
        "LDRSB_32B_ldst_regoff" | "LDRSB_32BL_ldst_regoff" | "LDRSH_32_ldst_regoff" => Some(Extension::SignToW),
        _ => None,
    }
}

/// Whether an offset register holding an entry loaded with `load`, extended by `extend` (bits and signedness;
/// `None` for the whole register), is the entry sign-extended (`true`) or zero-extended (`false`). `None` when it
/// is neither, such as a sign-extended byte read back zero-extended from 16 bits.
fn extended_sign(load: Extension, entry_size: u8, extend: Option<(u64, bool)>) -> Option<bool> {
    let entry_bits = u64::from(entry_size) * 8;
    match (extend, load) {
        (None, Extension::Zero) => Some(false),
        (None, Extension::Sign) => Some(true),
        (Some((bits, signed)), _) if bits == entry_bits => Some(signed),
        (Some((bits, _)), Extension::Zero) if bits > entry_bits => Some(false),
        (Some((bits, true)), _) if bits > entry_bits => Some(true),
        _ => None,
    }
}

/// The register a switch-dispatch instruction writes and what it then holds: an entry a register-offset load read
/// from a known table with an index a comparison bounded, or a target formed by adding such an entry, extended
/// and shifted, to a known address.
fn switch_entry(decoded: &Decoded, addresses: &Addresses) -> Option<(u64, Entry)> {
    let name = decoded.encoding.name;
    let field = |name: &str| decoded.field(name);
    if let Some(load) = table_load(name) {
        let size_log2 = field("size")?;
        let size = 1u64 << size_log2;
        let table = addresses.full(field("Rn")?)?;
        let bound = addresses.bound(field("Rm")?)?;
        let index_wide = match field("option")? {
            0b011 | 0b111 => true,
            0b010 | 0b110 => false,
            _ => return None,
        };
        let shift = if field("S")? == 1 { size_log2 } else { 0 };
        if index_wide && !bound.wide || 1 << shift != size || bound.max >= MAX_JUMP_TABLE_ENTRIES {
            return None;
        }
        let table = JumpTable {
            guard: bound.guard,
            table,
            entry_size: size as u8,
            entries: bound.max + 1,
            signed: load == Extension::Sign,
            base: None,
            shift: 0,
            alignment: 4,
        };
        return Some((field("Rt")?, Entry { table, load }));
    }
    let (extend, shift) = match name {
        "ADD_64_addsub_shift" if field("shift")? == 0 => (None, field("imm6")?),
        "ADD_64_addsub_ext" => {
            let option = field("option")?;
            ((option & 3 != 3).then(|| (8 << (option & 3), option & 4 != 0)), field("imm3")?)
        }
        _ => return None,
    };
    let base = addresses.full(field("Rn")?)?;
    let entry = addresses.entry(field("Rm")?).filter(|entry| entry.table.base.is_none())?;
    let signed = extended_sign(entry.load, entry.table.entry_size, extend)?;
    let table = JumpTable { signed, base: Some(base), shift: u8::try_from(shift).ok()?, ..entry.table };
    Some((field("Rd")?, Entry { table, ..entry }))
}

/// What one instruction does to control flow and which address it references.
pub struct Analysis {
    pub flow: Flow,
    pub data_ref: Option<u64>,
    /// The instruction loads from or stores to `data_ref` rather than forming it.
    pub accesses: bool,
    /// The pointer a 64-bit literal load reads from read-only memory, which may be a code pointer.
    pub immediate: Option<u64>,
    /// For BR: the full address its register holds or was offset from, such as a switch's jump-table base.
    pub jump_base: Option<u64>,
    /// For BR: the bounded switch table its register was loaded from.
    pub jump_table: Option<JumpTable>,
}

pub fn analyze(
    decoded: &Decoded,
    address: u64,
    addresses: &mut Addresses,
    read: &dyn Fn(u64, u8) -> Option<u64>,
) -> Analysis {
    let info = &INFO[index_of(decoded.encoding)];
    let compare = addresses.compare.take();
    let direct = |make: fn(u64) -> Flow| relative_target(decoded, address).map_or(Flow::Invalid, make);
    let mut flow = match info.flow {
        FlowClass::Next => Flow::Next,
        FlowClass::Jump => direct(Flow::Jump),
        FlowClass::ConditionalBranch if decoded.field("cond").is_some_and(|cond| cond >= 14) => direct(Flow::Jump),
        FlowClass::ConditionalBranch | FlowClass::ConditionalJump => direct(Flow::ConditionalJump),
        FlowClass::Call => direct(Flow::Call),
        FlowClass::IndirectJump => Flow::IndirectJump,
        FlowClass::IndirectCall => Flow::IndirectCall,
        FlowClass::Return => Flow::Return,
        // `brk #1` (LLVM) and `brk #0x3e8` (GCC) are `__builtin_trap`; any other BRK is a breakpoint a debugger
        // resumes from.
        FlowClass::Halt
            if decoded.encoding.name.starts_with("BRK") && !matches!(decoded.field("imm16"), Some(1 | 0x3e8)) =>
        {
            Flow::Next
        }
        FlowClass::Halt => Flow::Halt,
    };
    let name = decoded.encoding.name;
    let prefix = name.split('_').next().unwrap_or(name).to_ascii_uppercase();
    if [
        "ST", "CAS", "SWP", "RCW", "CPY", "SET", "LDADD", "LDCLR", "LDEOR", "LDSET", "LDSMAX", "LDSMIN", "LDUMAX",
        "LDUMIN",
    ]
    .iter()
    .any(|name| prefix.starts_with(name))
    {
        addresses.memory_changed = true;
    }
    if matches!(name, "BR_64_branch_reg" | "BLR_64_branch_reg")
        && let Some(target) = decoded.field("Rn").and_then(|rn| addresses.get(rn))
        && target != 0
        && target % 4 == 0
    {
        flow = if info.flow == FlowClass::IndirectCall { Flow::Call(target) } else { Flow::Jump(target) };
    }
    let jump_base =
        (name == "BR_64_branch_reg").then(|| decoded.field("Rn").and_then(|rn| addresses.base(rn))).flatten();
    let jump_table = (name == "BR_64_branch_reg")
        .then(|| decoded.field("Rn").and_then(|rn| addresses.entry(rn)))
        .flatten()
        .filter(|entry| entry.table.base.is_some() || entry.table.entry_size == 8)
        .map(|entry| entry.table);
    let switch = switch_entry(decoded, addresses);
    // A `b.hi` or `b.hs` straight after `cmp xN, #limit` falls through only when xN is within the limit.
    let bound = compare.filter(|_| name == "B_only_condbranch").and_then(|compare| {
        let max = match decoded.field("cond")? {
            0b1000 => compare.limit,
            0b0010 => compare.limit.checked_sub(1)?,
            _ => return None,
        };
        let wide = compare.wide || addresses.upper_zero & (1 << compare.register) != 0;
        Some((compare.register, Bound { max, wide, guard: compare.address }))
    });
    let offset_from = matches!(name, "ADD_64_addsub_shift" | "ADD_64_addsub_ext")
        .then(|| decoded.field("Rn").and_then(|rn| addresses.base(rn)))
        .flatten();

    let word = u64::from(decoded.word);
    let register = |w: Written| ((word >> w.start) & ones(w.width.into())) + u64::from(w.plus);
    let base = || decoded.field("Rn").and_then(|rn| addresses.get(rn));
    // A register's new known address, and whether it is an ADRP page.
    let mut produced = None;
    let data_ref = match info.effect {
        Effect::None => None,
        Effect::LoadLiteral => relative_target(decoded, address),
        Effect::Adr => {
            produced = address_target(decoded, address).map(|target| (target, false));
            address_target(decoded, address)
        }
        Effect::Adrp => {
            produced = address_target(decoded, address).map(|page| (page, true));
            None
        }
        Effect::AddImmediate => {
            // ADRP + ADD forms an address; further ADDs are pointer arithmetic, not new references.
            let shift = if decoded.field("sh") == Some(1) { 12 } else { 0 };
            let offset = decoded.field("imm12").unwrap_or(0) << shift;
            let page = decoded.field("Rn").and_then(|rn| addresses.page(rn));
            let target = page.map(|page| page.wrapping_add(offset));
            produced = base().map(|base| (base.wrapping_add(offset), false));
            target
        }
        Effect::ScaledOffset(scale) => {
            let scale = scale.unwrap_or_else(|| 1 << decoded.field("size").unwrap_or(0));
            let offset = decoded.field("imm12").unwrap_or(0) * scale;
            base().map(|base| base.wrapping_add(offset))
        }
    };
    let accesses = matches!(info.effect, Effect::LoadLiteral | Effect::ScaledOffset(_)) && data_ref.is_some();
    let immediate = data_ref.filter(|_| name == "LDR_64_loadlit").and_then(|slot| read(slot, 8));
    let mut destination = decoded.field("Rd");
    if matches!(name, "LDR_64_ldst_pos" | "LDR_64_loadlit") {
        destination = decoded.field("Rt");
        produced =
            data_ref.filter(|_| !addresses.memory_changed).and_then(|slot| read(slot, 8)).map(|target| (target, false));
    } else if name == "ORR_64_log_shift"
        && decoded.field("Rn") == Some(31)
        && decoded.field("shift") == Some(0)
        && decoded.field("imm6") == Some(0)
    {
        produced = decoded.field("Rm").and_then(|rm| addresses.get(rm)).map(|target| (target, false));
    } else if matches!(name, "MOVZ_64_movewide" | "MOVK_64_movewide") {
        let shift = decoded.field("hw").unwrap_or(0) * 16;
        let value = decoded.field("imm16").unwrap_or(0) << shift;
        produced = if name.starts_with("MOVZ") {
            Some((value, false))
        } else {
            destination.and_then(|rd| addresses.get(rd)).map(|old| ((old & !(0xffff << shift)) | value, false))
        };
    }

    // Whatever this instruction writes no longer holds a known address.
    for &written in &info.written {
        addresses.clear(register(written));
    }
    for &written in info.written.iter().filter(|written| written.narrow) {
        let register = register(written);
        if register < 31 {
            addresses.upper_zero |= 1 << register;
        }
    }
    if let Some(base) = info.writeback {
        addresses.clear(register(base));
    }
    for &register in &info.implicit {
        addresses.clear(register);
    }
    if !info.writes_known {
        for register in 0..31 {
            addresses.clear(register);
        }
    }
    if info.clobbers_caller_saved {
        addresses.clobber_caller_saved();
        addresses.memory_changed = true;
    }
    if let (Some((value, page)), Some(rd)) = (produced, destination) {
        addresses.set(rd, value, page);
    }
    if let (Some(base), Some(rd)) = (offset_from, destination) {
        addresses.set_derived(rd, base);
    }
    if let Some((register, entry)) = switch.filter(|&(register, _)| register < 31) {
        addresses.entries[register as usize] = Some(entry);
    }
    if let Some((register, bound)) = bound {
        addresses.bounds[register as usize] = Some(bound);
    }
    if matches!(name, "SUBS_32S_addsub_imm" | "SUBS_64S_addsub_imm")
        && decoded.field("Rd") == Some(31)
        && let Some(register) = decoded.field("Rn").filter(|&rn| rn < 31)
    {
        let shift = if decoded.field("sh") == Some(1) { 12 } else { 0 };
        let limit = decoded.field("imm12").unwrap_or(0) << shift;
        let wide = decoded.field("sf") == Some(1);
        addresses.compare = Some(Compare { register, limit, wide, address });
    }
    Analysis { flow, data_ref, accesses, immediate, jump_base, jump_table }
}
