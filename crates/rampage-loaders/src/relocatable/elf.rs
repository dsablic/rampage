//! ELF relocation types: which ones call, which reach a GOT, and how each is computed and encoded, for x86, x86-64,
//! AArch64, ARM/Thumb, MIPS and RISC-V. Names come from `object`'s per-machine constant names.

use std::collections::HashMap;

use rampage_arch::Arch;

use super::{GotKey, Image, Refused, Reloc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    X86,
    X86_64,
    Aarch64,
    Arm,
    Mips { wide: bool },
    Riscv,
}

/// Symbols a linker defines itself, which are not externs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Special {
    /// `_GLOBAL_OFFSET_TABLE_`: the GOT's address.
    GotBase,
    /// MIPS `_gp` and `__gnu_local_gp`: the global pointer.
    GlobalPointer,
    /// MIPS `_gp_disp`: the global pointer's distance from the `lui` (and `addiu`) using it.
    GpDisp,
}

/// Results `apply` gives: the addend used and the resolved target, or nothing for a type that writes nothing.
type Applied = Result<Option<(i64, u64)>, Refused>;

/// Relocation state carried between relocations: MIPS HI16s awaiting their LO16, RISC-V `auipc` values.
#[derive(Default)]
pub(crate) struct State {
    /// MIPS HI16 or local GOT16 fields awaiting their LO16: (place, symbol index, symbol value, high addend, GOT16).
    pending: Vec<(u64, Option<usize>, u64, i64, bool)>,
    /// RISC-V `auipc` places and the PC-relative value each one's HI20 encodes, for the LO12 that names it.
    riscv_hi: HashMap<u64, i64>,
    /// RISC-V PCREL_LO12 relocations whose HI20 came later: (place, auipc address, store form).
    riscv_lo: Vec<(u64, u64, bool)>,
    /// MIPS local GOT16 page entries handed out, by page.
    pages: HashMap<u64, u64>,
}

impl Machine {
    pub fn of(arch: Arch, wide: bool) -> Option<Self> {
        Some(match arch {
            Arch::X86 => Self::X86,
            Arch::X86_64 => Self::X86_64,
            Arch::Aarch64 => Self::Aarch64,
            Arch::Arm => Self::Arm,
            Arch::Mips | Arch::Mips64 => Self::Mips { wide },
            Arch::Riscv32 | Arch::Riscv64 => Self::Riscv,
            _ => return None,
        })
    }

    fn em(self) -> object::elf::Machine {
        match self {
            Self::X86 => object::elf::EM_386,
            Self::X86_64 => object::elf::EM_X86_64,
            Self::Aarch64 => object::elf::EM_AARCH64,
            Self::Arm => object::elf::EM_ARM,
            Self::Mips { .. } => object::elf::EM_MIPS,
            Self::Riscv => object::elf::EM_RISCV,
        }
    }

    pub fn type_name(self, r_type: object::elf::RelocationType) -> String {
        object::elf::machine_names(self.em()).r.name(r_type).map_or_else(|| format!("type {}", r_type.0), str::to_owned)
    }

    pub fn is_mips(self) -> bool {
        matches!(self, Self::Mips { .. })
    }

    pub fn special(self, name: &str) -> Option<Special> {
        match (self, name) {
            (_, "_GLOBAL_OFFSET_TABLE_") => Some(Special::GotBase),
            (Self::Mips { .. }, "_gp" | "__gnu_local_gp") => Some(Special::GlobalPointer),
            (Self::Mips { .. }, "_gp_disp") => Some(Special::GpDisp),
            _ => None,
        }
    }

    /// Whether the type is a call or branch to its symbol, so an extern it reaches is a function. `before` holds
    /// the (up to two) bytes before the field: x86 uses PC32 for calls and data alike, told apart by the opcode
    /// (`call`/`jmp` rel32, `jcc` rel32).
    pub fn is_call(self, r_type: u32, before: &[u8]) -> bool {
        match self {
            Self::X86 | Self::X86_64 => {
                r_type == 4
                    || (r_type == 2
                        && (matches!(before.last(), Some(0xe8 | 0xe9)) || matches!(before, [0x0f, 0x80..=0x8f])))
            }
            Self::Aarch64 => matches!(r_type, 282 | 283 | 314),
            Self::Arm => matches!(r_type, 1 | 10 | 27 | 28 | 29 | 30),
            Self::Mips { .. } => matches!(r_type & 0xff, 4 | 11 | 30 | 31),
            Self::Riscv => matches!(r_type, 17 | 18 | 19),
        }
    }

    /// Whether the type reaches its symbol through a GOT entry holding the symbol's address. MIPS GOT16 against a
    /// local symbol is a page entry instead, handed out as relocations are applied.
    pub fn uses_got(self, r_type: u32) -> bool {
        match self {
            Self::X86_64 => matches!(r_type, 3 | 9 | 41 | 42 | 43),
            Self::X86 => matches!(r_type, 3 | 43),
            Self::Aarch64 => matches!(r_type, 309 | 311 | 312 | 313),
            Self::Arm => matches!(r_type, 26 | 96),
            Self::Mips { .. } => matches!(r_type & 0xff, 9 | 11 | 19 | 22 | 23 | 30 | 31),
            Self::Riscv => r_type == 20,
        }
    }

    /// Whether the type is MIPS GOT16, which against a local symbol needs a page entry.
    pub fn is_local_got_page(self, r_type: u32) -> bool {
        self.is_mips() && r_type & 0xff == 9
    }

    pub fn apply(self, image: &mut Image, reloc: &Reloc, state: &mut State) -> Applied {
        match self {
            Self::X86_64 => x86_64(image, reloc),
            Self::X86 => x86(image, reloc),
            Self::Aarch64 => aarch64(image, reloc),
            Self::Arm => arm(image, reloc),
            Self::Mips { .. } => mips(image, reloc, state),
            Self::Riscv => riscv(image, reloc, state),
        }
    }
}

/// Applies what waits on a later relocation: MIPS HI16s with no LO16, RISC-V LO12s whose HI20 came after them.
pub(crate) fn finish(image: &mut Image, state: &mut State, machine: &Machine) {
    if machine.is_mips() {
        for (place, _, value, high, got16) in std::mem::take(&mut state.pending) {
            let _ = mips_write_high(image, state, place, value, high, got16);
        }
    }
    for (place, auipc, store) in std::mem::take(&mut state.riscv_lo) {
        if let Some(&value) = state.riscv_hi.get(&auipc) {
            let _ = riscv_lo12(image, place, value, store);
        }
    }
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn got(image: &Image, reloc: &Reloc) -> Result<u64, Refused> {
    let index = reloc.symbol_index.ok_or(Refused::Unsupported)?;
    image.got_entry(GotKey::Symbol(index)).ok_or(Refused::Unsupported)
}

fn put(image: &mut Image, place: u64, width: usize, value: u64) -> Result<(), Refused> {
    image.put(place, width, value).ok_or(Refused::OutOfRange)
}

fn get(image: &Image, place: u64, width: usize) -> Result<u64, Refused> {
    image.get(place, width).ok_or(Refused::OutOfRange)
}

/// The addend: RELA's explicit one, or the field's stored value read as `width` bytes, sign-extended.
fn addend(image: &Image, reloc: &Reloc, width: usize) -> Result<i64, Refused> {
    match reloc.addend {
        Some(addend) => Ok(addend),
        None => Ok(sign_extend(get(image, reloc.place, width)?, width as u32 * 8)),
    }
}

/// Writes a data field of `width` bytes: absolute `S + A`, or relative `S + A - P`.
fn data(image: &mut Image, reloc: &Reloc, width: usize, relative: bool) -> Applied {
    let a = addend(image, reloc, width)?;
    let target = reloc.symbol.value.wrapping_add(a as u64);
    let value = if relative { target.wrapping_sub(reloc.place) } else { target };
    put(image, reloc.place, width, value)?;
    Ok(Some((a, target)))
}

fn x86_64(image: &mut Image, reloc: &Reloc) -> Applied {
    let s = reloc.symbol.value;
    let p = reloc.place;
    match reloc.r_type {
        0 => Ok(None),
        1 => data(image, reloc, 8, false),
        2 | 4 => data(image, reloc, 4, true),
        10 | 11 => data(image, reloc, 4, false),
        12 => data(image, reloc, 2, false),
        13 => data(image, reloc, 2, true),
        14 => data(image, reloc, 1, false),
        15 => data(image, reloc, 1, true),
        24 => data(image, reloc, 8, true),
        // GOTPCREL, GOTPCRELX, REX_GOTPCRELX, CODE_4_GOTPCRELX: G + A - P.
        9 | 41 | 42 | 43 => {
            let a = addend(image, reloc, 4)?;
            let g = got(image, reloc)?;
            put(image, p, 4, g.wrapping_add(a as u64).wrapping_sub(p))?;
            Ok(Some((a, g)))
        }
        // GOT32: G + A - GOT.
        3 => {
            let a = addend(image, reloc, 4)?;
            let g = got(image, reloc)?;
            put(image, p, 4, g.wrapping_add(a as u64).wrapping_sub(image.got))?;
            Ok(Some((a, g)))
        }
        // GOTOFF64: S + A - GOT.
        25 => {
            let a = addend(image, reloc, 8)?;
            put(image, p, 8, s.wrapping_add(a as u64).wrapping_sub(image.got))?;
            Ok(Some((a, s.wrapping_add(a as u64))))
        }
        // GOTPC32, GOTPC64: GOT + A - P.
        26 | 29 => {
            let width = if reloc.r_type == 26 { 4 } else { 8 };
            let a = addend(image, reloc, width)?;
            put(image, p, width, image.got.wrapping_add(a as u64).wrapping_sub(p))?;
            Ok(Some((a, image.got)))
        }
        // SIZE32, SIZE64: Z + A.
        32 | 33 => {
            let width = if reloc.r_type == 32 { 4 } else { 8 };
            let a = addend(image, reloc, width)?;
            put(image, p, width, reloc.symbol.size.wrapping_add(a as u64))?;
            Ok(Some((a, reloc.symbol.size.wrapping_add(a as u64))))
        }
        _ => Err(Refused::Unsupported),
    }
}

fn x86(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    match reloc.r_type {
        0 => Ok(None),
        1 => data(image, reloc, 4, false),
        2 | 4 => data(image, reloc, 4, true),
        20 => data(image, reloc, 2, false),
        21 => data(image, reloc, 2, true),
        22 => data(image, reloc, 1, false),
        23 => data(image, reloc, 1, true),
        // GOT32, GOT32X: G + A - GOT.
        3 | 43 => {
            let a = addend(image, reloc, 4)?;
            let g = got(image, reloc)?;
            put(image, p, 4, g.wrapping_add(a as u64).wrapping_sub(image.got))?;
            Ok(Some((a, g)))
        }
        // GOTOFF: S + A - GOT.
        9 => {
            let a = addend(image, reloc, 4)?;
            let target = reloc.symbol.value.wrapping_add(a as u64);
            put(image, p, 4, target.wrapping_sub(image.got))?;
            Ok(Some((a, target)))
        }
        // GOTPC: GOT + A - P.
        10 => {
            let a = addend(image, reloc, 4)?;
            put(image, p, 4, image.got.wrapping_add(a as u64).wrapping_sub(p))?;
            Ok(Some((a, image.got)))
        }
        _ => Err(Refused::Unsupported),
    }
}

fn page(address: u64) -> u64 {
    address & !0xfff
}

/// Writes an A64 `adr`/`adrp` immediate (21 bits, split immlo:immhi).
fn a64_adr(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    let immlo = value & 3;
    let immhi = (value >> 2) & 0x7ffff;
    put(image, place, 4, (insn & !0x60ff_ffe0) | (immlo << 29) | (immhi << 5))
}

/// Writes an A64 immediate field of `bits` bits at bit `shift`.
fn a64_field(image: &mut Image, place: u64, value: u64, shift: u32, bits: u32) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    let mask = ((1u64 << bits) - 1) << shift;
    put(image, place, 4, (insn & !mask) | ((value << shift) & mask))
}

fn aarch64(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    let a = reloc.addend.unwrap_or(0);
    let x = reloc.symbol.value.wrapping_add(a as u64);
    let applied = Ok(Some((a, x)));
    match reloc.r_type {
        0 | 256 => Ok(None),
        257 => data(image, reloc, 8, false),
        258 => data(image, reloc, 4, false),
        259 => data(image, reloc, 2, false),
        260 => data(image, reloc, 8, true),
        261 | 314 => data(image, reloc, 4, true),
        262 => data(image, reloc, 2, true),
        // MOVW_UABS_G0..G3 (and _NC): a 16-bit chunk of S + A.
        263..=270 => {
            let chunk = (reloc.r_type - 263) / 2;
            a64_field(image, p, (x >> (16 * chunk)) & 0xffff, 5, 16)?;
            applied
        }
        // LD_PREL_LO19, CONDBR19: (S + A - P) >> 2 in bits 23:5.
        273 | 280 => {
            a64_field(image, p, x.wrapping_sub(p) >> 2, 5, 19)?;
            applied
        }
        274 => {
            a64_adr(image, p, x.wrapping_sub(p))?;
            applied
        }
        275 | 276 => {
            a64_adr(image, p, page(x).wrapping_sub(page(p)) >> 12)?;
            applied
        }
        277 | 278 => {
            a64_field(image, p, x & 0xfff, 10, 12)?;
            applied
        }
        // TSTBR14: (S + A - P) >> 2 in bits 18:5.
        279 => {
            a64_field(image, p, x.wrapping_sub(p) >> 2, 5, 14)?;
            applied
        }
        282 | 283 => {
            a64_field(image, p, x.wrapping_sub(p) >> 2, 0, 26)?;
            applied
        }
        // LDST16/32/64/128_ABS_LO12_NC: the page offset scaled by the access size.
        284 | 285 | 286 | 299 => {
            let scale = match reloc.r_type {
                284 => 1,
                285 => 2,
                286 => 3,
                _ => 4,
            };
            a64_field(image, p, (x & 0xfff) >> scale, 10, 12)?;
            applied
        }
        // GOT_LD_PREL19, ADR_GOT_PAGE, LD64_GOT_LO12_NC, LD64_GOTPAGE_LO15.
        309 | 311 | 312 | 313 => {
            let g = got(image, reloc)?.wrapping_add(a as u64);
            match reloc.r_type {
                309 => a64_field(image, p, g.wrapping_sub(p) >> 2, 5, 19)?,
                311 => a64_adr(image, p, page(g).wrapping_sub(page(p)) >> 12)?,
                312 => a64_field(image, p, (g & 0xfff) >> 3, 10, 12)?,
                _ => a64_field(image, p, g.wrapping_sub(page(image.got)) >> 3, 10, 12)?,
            }
            Ok(Some((a, g)))
        }
        _ => Err(Refused::Unsupported),
    }
}

/// A Thumb-2 `bl`/`blx`/`b.w` offset (S:I1:I2:imm10:imm11:'0', 25 bits signed).
fn thumb_branch_offset(high: u64, low: u64) -> i64 {
    let s = (high >> 10) & 1;
    let j1 = (low >> 13) & 1;
    let j2 = (low >> 11) & 1;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    let value = (s << 24) | (i1 << 23) | (i2 << 22) | ((high & 0x3ff) << 12) | ((low & 0x7ff) << 1);
    sign_extend(value, 25)
}

fn thumb_branch_encode(high: u64, low: u64, offset: u64) -> (u64, u64) {
    let s = (offset >> 24) & 1;
    let i1 = (offset >> 23) & 1;
    let i2 = (offset >> 22) & 1;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    let high = (high & 0xf800) | (s << 10) | ((offset >> 12) & 0x3ff);
    let low = (low & 0xd000) | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x7ff);
    (high, low)
}

/// The 16-bit immediate of an A32 `movw`/`movt` (imm4:imm12) or a T32 one (imm4:i:imm3:imm8).
fn mov_immediate(insn: u64, thumb: bool) -> u64 {
    if thumb {
        let (high, low) = (insn >> 16, insn & 0xffff);
        ((high & 0xf) << 12) | (((high >> 10) & 1) << 11) | (((low >> 12) & 7) << 8) | (low & 0xff)
    } else {
        ((insn >> 4) & 0xf000) | (insn & 0xfff)
    }
}

fn mov_encode(insn: u64, thumb: bool, value: u64) -> u64 {
    let value = value & 0xffff;
    if thumb {
        let (high, low) = (insn >> 16, insn & 0xffff);
        let high = (high & !0x040f) | ((value >> 12) & 0xf) | (((value >> 11) & 1) << 10);
        let low = (low & !0x70ff) | (((value >> 8) & 7) << 12) | (value & 0xff);
        (high << 16) | low
    } else {
        (insn & !0x000f_0fff) | ((value & 0xf000) << 4) | (value & 0xfff)
    }
}

/// Reads two Thumb halfwords as one value, the first in the high half.
fn thumb_pair(image: &Image, place: u64) -> Result<u64, Refused> {
    Ok((get(image, place, 2)? << 16) | get(image, place + 2, 2)?)
}

fn put_thumb_pair(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    put(image, place, 2, value >> 16)?;
    put(image, place + 2, 2, value & 0xffff)
}

fn arm(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    let symbol = reloc.symbol;
    // The Thumb bit of a Thumb function's address; S has it already, so T is the bit and S without it is used where
    // the ABI says (S + A) | T.
    let thumb_target = symbol.function && symbol.value & 1 == 1;
    let s = symbol.value;
    match reloc.r_type {
        0 | 40 => Ok(None),
        2 | 38 => data(image, reloc, 4, false),
        3 => data(image, reloc, 4, true),
        5 => data(image, reloc, 2, false),
        8 => data(image, reloc, 1, false),
        // PC24, CALL, JUMP24, PLT32: A32 `b`/`bl` (24-bit word offset).
        1 | 27 | 28 | 29 => {
            let insn = get(image, p, 4)?;
            let a = match reloc.addend {
                Some(addend) => addend,
                None => sign_extend(insn & 0xff_ffff, 24) << 2,
            };
            let target = (s & !1).wrapping_add(a as u64);
            let offset = target.wrapping_sub(p);
            // A `bl` to a Thumb function defined here becomes `blx`, as the linker makes it.
            let insn = if reloc.r_type == 28 && thumb_target && symbol.defined && insn >> 28 == 0xe {
                0xfa00_0000 | (((offset >> 1) & 1) << 24) | ((offset >> 2) & 0xff_ffff)
            } else {
                (insn & 0xff00_0000) | ((offset >> 2) & 0xff_ffff)
            };
            put(image, p, 4, insn)?;
            Ok(Some((a, target)))
        }
        // THM_CALL, THM_JUMP24: Thumb-2 `bl`/`blx`/`b.w`.
        10 | 30 => {
            let pair = thumb_pair(image, p)?;
            let (high, low) = (pair >> 16, pair & 0xffff);
            let a = reloc.addend.unwrap_or_else(|| thumb_branch_offset(high, low));
            let target = (s & !1).wrapping_add(a as u64);
            // A `bl` to an ARM function defined here becomes `blx`, whose offset is from the word-aligned PC.
            let arm_target = reloc.r_type == 10 && symbol.defined && symbol.function && !thumb_target;
            let (offset, low) = if arm_target {
                (target.wrapping_sub(p & !3), low & !0x1000)
            } else {
                (target.wrapping_sub(p), if reloc.r_type == 10 { low | 0x1000 } else { low })
            };
            let (high, low) = thumb_branch_encode(high, low, offset);
            put_thumb_pair(image, p, (high << 16) | low)?;
            Ok(Some((a, target)))
        }
        // THM_JUMP19: `b<cond>.w` (S:J2:J1:imm6:imm11:'0').
        51 => {
            let pair = thumb_pair(image, p)?;
            let (high, low) = (pair >> 16, pair & 0xffff);
            let a = reloc.addend.unwrap_or_else(|| {
                let value = (((high >> 10) & 1) << 20)
                    | (((low >> 11) & 1) << 19)
                    | (((low >> 13) & 1) << 18)
                    | ((high & 0x3f) << 12)
                    | ((low & 0x7ff) << 1);
                sign_extend(value, 21)
            });
            let target = (s & !1).wrapping_add(a as u64);
            let x = target.wrapping_sub(p);
            let high = (high & 0xfbc0) | (((x >> 20) & 1) << 10) | ((x >> 12) & 0x3f);
            let low = (low & 0xd000) | (((x >> 18) & 1) << 13) | (((x >> 19) & 1) << 11) | ((x >> 1) & 0x7ff);
            put_thumb_pair(image, p, (high << 16) | low)?;
            Ok(Some((a, target)))
        }
        // THM_JUMP11 (`b`), THM_JUMP8 (`b<cond>`).
        102 | 103 => {
            let insn = get(image, p, 2)?;
            let bits = if reloc.r_type == 102 { 11 } else { 8 };
            let mask = (1u64 << bits) - 1;
            let a = reloc.addend.unwrap_or_else(|| sign_extend((insn & mask) << 1, bits + 1));
            let target = (s & !1).wrapping_add(a as u64);
            let x = target.wrapping_sub(p);
            put(image, p, 2, (insn & !mask) | ((x >> 1) & mask))?;
            Ok(Some((a, target)))
        }
        // MOVW_ABS_NC, MOVT_ABS, MOVW_PREL_NC, MOVT_PREL and their Thumb forms.
        43..=50 => {
            let thumb = reloc.r_type >= 47;
            let insn = if thumb { thumb_pair(image, p)? } else { get(image, p, 4)? };
            let a = reloc.addend.unwrap_or_else(|| sign_extend(mov_immediate(insn, thumb), 16));
            let kind = (reloc.r_type - 43) % 4;
            let top = kind % 2 == 1;
            let relative = kind >= 2;
            // MOVW takes (S + A) | T, MOVT (S + A) alone.
            let mut x = s.wrapping_add(a as u64);
            if relative {
                x = x.wrapping_sub(p);
            }
            if top {
                x &= !1;
            }
            let value = if top { x >> 16 } else { x };
            let insn = mov_encode(insn, thumb, value);
            if thumb {
                put_thumb_pair(image, p, insn)?;
            } else {
                put(image, p, 4, insn)?;
            }
            Ok(Some((a, s.wrapping_add(a as u64))))
        }
        // PREL31 (exception index tables): ((S + A) | T) - P in 31 bits.
        42 => {
            let word = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or_else(|| sign_extend(word & 0x7fff_ffff, 31));
            let target = s.wrapping_add(a as u64);
            put(image, p, 4, (word & 0x8000_0000) | (target.wrapping_sub(p) & 0x7fff_ffff))?;
            Ok(Some((a, target)))
        }
        // BASE_PREL: GOT + A - P; GOTOFF32: S + A - GOT.
        25 | 24 => {
            let word = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or(sign_extend(word, 32));
            let (value, target) = if reloc.r_type == 25 {
                (image.got.wrapping_add(a as u64).wrapping_sub(p), image.got)
            } else {
                (s.wrapping_add(a as u64).wrapping_sub(image.got), s.wrapping_add(a as u64))
            };
            put(image, p, 4, value)?;
            Ok(Some((a, target)))
        }
        // GOT_BREL: G + A - GOT; GOT_PREL: G + A - P.
        26 | 96 => {
            let word = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or(sign_extend(word, 32));
            let g = got(image, reloc)?;
            let base = if reloc.r_type == 26 { image.got } else { p };
            put(image, p, 4, g.wrapping_add(a as u64).wrapping_sub(base))?;
            Ok(Some((a, g)))
        }
        _ => Err(Refused::Unsupported),
    }
}

/// Writes the high half of a MIPS `%hi` (or a local `%got` page entry's offset from `$gp`) once its full value is
/// known.
fn mips_write_high(
    image: &mut Image,
    state: &mut State,
    place: u64,
    value: u64,
    high: i64,
    got16: bool,
) -> Result<(), Refused> {
    let _ = high;
    let insn = get(image, place, 4)?;
    let field = if got16 {
        let page = value.wrapping_add(0x8000) & !0xffff & 0xffff_ffff;
        let entry = mips_page_entry(image, state, page)?;
        entry.wrapping_sub(image.gp)
    } else {
        value.wrapping_add(0x8000) >> 16
    };
    put(image, place, 4, (insn & !0xffff) | (field & 0xffff))
}

/// The GOT entry holding `page`, handed out from the page entries reserved after the symbol entries.
fn mips_page_entry(image: &mut Image, state: &mut State, page: u64) -> Result<u64, Refused> {
    if let Some(&entry) = state.pages.get(&page) {
        return Ok(entry);
    }
    let index = state.pages.len() as u64;
    let entry = image.got_entry(GotKey::Page(index)).ok_or(Refused::Unsupported)?;
    image.put(entry, image.pointer, page).ok_or(Refused::OutOfRange)?;
    state.pages.insert(page, entry);
    Ok(entry)
}

fn mips(image: &mut Image, reloc: &Reloc, state: &mut State) -> Applied {
    let p = reloc.place;
    let s = reloc.symbol.value;
    // n64 packs up to three types into one; only single ones are applied.
    if reloc.r_type > 0xff {
        return Err(Refused::Unsupported);
    }
    let field16 = |image: &mut Image, value: u64| -> Result<(), Refused> {
        let insn = get(image, p, 4)?;
        put(image, p, 4, (insn & !0xffff) | (value & 0xffff))
    };
    match reloc.r_type {
        0 | 37 => Ok(None),
        1 => data(image, reloc, 2, false),
        2 | 3 => data(image, reloc, 4, false),
        18 => data(image, reloc, 8, false),
        // R_MIPS_26: `j`/`jal` within the 256 MiB region of the delay slot.
        4 => {
            let insn = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or(((insn & 0x3ff_ffff) << 2) as i64);
            let target = if reloc.symbol.local && reloc.addend.is_none() {
                ((a as u64) | (p.wrapping_add(4) & 0xf000_0000)).wrapping_add(s)
            } else {
                s.wrapping_add(sign_extend(a as u64, 28) as u64)
            };
            put(image, p, 4, (insn & 0xfc00_0000) | ((target >> 2) & 0x3ff_ffff))?;
            Ok(Some((a, target)))
        }
        // HI16, and GOT16 against a local symbol (a page entry): wait for the LO16 that completes the addend.
        5 | 9 if reloc.r_type == 5 || reloc.symbol.local => {
            let got16 = reloc.r_type == 9;
            match reloc.addend {
                Some(a) => {
                    let value = s.wrapping_add(a as u64);
                    mips_write_high(image, state, p, value, a, got16)?;
                    Ok(Some((a, value)))
                }
                None => {
                    let insn = get(image, p, 4)?;
                    let high = sign_extend((insn & 0xffff) << 16, 32);
                    state.pending.push((p, reloc.symbol_index, s, high, got16));
                    Ok(Some((high, s.wrapping_add(high as u64))))
                }
            }
        }
        // LO16: completes the HI16s waiting on the same symbol.
        6 => {
            let insn = get(image, p, 4)?;
            let low = reloc.addend.unwrap_or_else(|| sign_extend(insn & 0xffff, 16));
            let mut matched = None;
            let pending = std::mem::take(&mut state.pending);
            for item in pending {
                let (place, index, value, high, got16) = item;
                if index == reloc.symbol_index && reloc.addend.is_none() {
                    let ahl = high.wrapping_add(low);
                    mips_write_high(image, state, place, value.wrapping_add(ahl as u64), high, got16)?;
                    matched = Some(ahl);
                } else {
                    state.pending.push(item);
                }
            }
            let a = matched.unwrap_or(low);
            // `_gp_disp` is relative to the `lui`; the `addiu` sits 4 bytes after it in the ABI's sequence.
            let base = if reloc.symbol.gp_disp { s.wrapping_add(4) } else { s };
            let value = base.wrapping_add(a as u64);
            field16(image, value)?;
            Ok(Some((a, value)))
        }
        // GPREL16, GPREL32: S + A - GP (objects' GP0 is zero).
        7 => {
            let insn = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or_else(|| sign_extend(insn & 0xffff, 16));
            let target = s.wrapping_add(a as u64);
            field16(image, target.wrapping_sub(image.gp))?;
            Ok(Some((a, target)))
        }
        12 => {
            let a = addend(image, reloc, 4)?;
            let target = s.wrapping_add(a as u64);
            put(image, p, 4, target.wrapping_sub(image.gp))?;
            Ok(Some((a, target)))
        }
        // PC16: a branch's word offset from the delay slot.
        10 => {
            let insn = get(image, p, 4)?;
            let a = reloc.addend.unwrap_or_else(|| sign_extend((insn & 0xffff) << 2, 18));
            let target = s.wrapping_add(a as u64);
            field16(image, target.wrapping_sub(p) >> 2)?;
            Ok(Some((a, target)))
        }
        // GOT16 (global), CALL16, GOT_DISP: G - GP; GOT_HI16/CALL_HI16 and GOT_LO16/CALL_LO16 halves of it.
        9 | 11 | 19 | 22 | 23 | 30 | 31 => {
            let g = got(image, reloc)?;
            let offset = g.wrapping_sub(image.gp);
            let value = match reloc.r_type {
                22 | 30 => offset.wrapping_add(0x8000) >> 16,
                _ => offset,
            };
            field16(image, value)?;
            Ok(Some((0, g)))
        }
        _ => Err(Refused::Unsupported),
    }
}

fn riscv_u(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    let high = value.wrapping_add(0x800) & 0xffff_f000;
    put(image, place, 4, (insn & 0xfff) | high)
}

fn riscv_i(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    put(image, place, 4, (insn & 0x000f_ffff) | ((value & 0xfff) << 20))
}

fn riscv_s(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    let value = value & 0xfff;
    put(image, place, 4, (insn & 0x01ff_f07f) | ((value >> 5) << 25) | ((value & 0x1f) << 7))
}

fn riscv_lo12(image: &mut Image, place: u64, value: i64, store: bool) -> Result<(), Refused> {
    if store { riscv_s(image, place, value as u64) } else { riscv_i(image, place, value as u64) }
}

fn riscv(image: &mut Image, reloc: &Reloc, state: &mut State) -> Applied {
    let p = reloc.place;
    let a = reloc.addend.unwrap_or(0);
    let x = reloc.symbol.value.wrapping_add(a as u64);
    let applied = Ok(Some((a, x)));
    match reloc.r_type {
        // NONE, ALIGN, RELAX: nothing to write (no relaxation is done).
        0 | 43 | 51 => Ok(None),
        1 => data(image, reloc, 4, false),
        2 => data(image, reloc, 8, false),
        57 => data(image, reloc, 4, true),
        // BRANCH: B-type imm[12|10:5] and imm[4:1|11].
        16 => {
            let insn = get(image, p, 4)?;
            let v = x.wrapping_sub(p);
            let encoded =
                (((v >> 12) & 1) << 31) | (((v >> 5) & 0x3f) << 25) | (((v >> 1) & 0xf) << 8) | (((v >> 11) & 1) << 7);
            put(image, p, 4, (insn & 0x01ff_f07f) | encoded)?;
            applied
        }
        // JAL: J-type imm[20|10:1|11|19:12].
        17 => {
            let insn = get(image, p, 4)?;
            let v = x.wrapping_sub(p);
            let encoded = (((v >> 20) & 1) << 31)
                | (((v >> 1) & 0x3ff) << 21)
                | (((v >> 11) & 1) << 20)
                | (((v >> 12) & 0xff) << 12);
            put(image, p, 4, (insn & 0xfff) | encoded)?;
            applied
        }
        // CALL, CALL_PLT: `auipc` + `jalr`.
        18 | 19 => {
            let v = x.wrapping_sub(p);
            riscv_u(image, p, v)?;
            riscv_i(image, p + 4, v)?;
            applied
        }
        // GOT_HI20, PCREL_HI20: the `auipc` half; its LO12 names this place.
        20 | 23 => {
            let target = if reloc.r_type == 20 { got(image, reloc)?.wrapping_add(a as u64) } else { x };
            let v = target.wrapping_sub(p);
            riscv_u(image, p, v)?;
            state.riscv_hi.insert(p, v as i64);
            Ok(Some((a, target)))
        }
        // PCREL_LO12_I/S: the low half of the value of the `auipc` at the symbol's address.
        24 | 25 => {
            let auipc = reloc.symbol.value;
            let store = reloc.r_type == 25;
            match state.riscv_hi.get(&auipc) {
                Some(&value) => riscv_lo12(image, p, value, store)?,
                None => state.riscv_lo.push((p, auipc, store)),
            }
            Ok(Some((a, auipc)))
        }
        26 => {
            riscv_u(image, p, x)?;
            applied
        }
        27 => {
            riscv_i(image, p, x)?;
            applied
        }
        28 => {
            riscv_s(image, p, x)?;
            applied
        }
        // RVC_BRANCH: CB-type offset[8|4:3] and [7:6|2:1|5].
        44 => {
            let insn = get(image, p, 2)?;
            let v = x.wrapping_sub(p);
            let encoded = (((v >> 8) & 1) << 12)
                | (((v >> 3) & 3) << 10)
                | (((v >> 6) & 3) << 5)
                | (((v >> 1) & 3) << 3)
                | (((v >> 5) & 1) << 2);
            put(image, p, 2, (insn & 0xe383) | encoded)?;
            applied
        }
        // RVC_JUMP: CJ-type offset[11|4|9:8|10|6|7|3:1|5].
        45 => {
            let insn = get(image, p, 2)?;
            let v = x.wrapping_sub(p);
            let encoded = (((v >> 11) & 1) << 12)
                | (((v >> 4) & 1) << 11)
                | (((v >> 8) & 3) << 9)
                | (((v >> 10) & 1) << 8)
                | (((v >> 6) & 1) << 7)
                | (((v >> 7) & 1) << 6)
                | (((v >> 1) & 7) << 3)
                | (((v >> 5) & 1) << 2);
            put(image, p, 2, (insn & 0xe003) | encoded)?;
            applied
        }
        // ADD8..ADD64, SUB8..SUB64: the field plus or minus S + A (label differences in tables).
        33..=40 => {
            let width = [1, 2, 4, 8][((reloc.r_type - 33) % 4) as usize];
            let current = get(image, p, width)?;
            let value = if reloc.r_type <= 36 { current.wrapping_add(x) } else { current.wrapping_sub(x) };
            put(image, p, width, value)?;
            applied
        }
        // SUB6, SET6: the low six bits.
        52 | 53 => {
            let current = get(image, p, 1)?;
            let low = if reloc.r_type == 52 { current.wrapping_sub(x) } else { x };
            put(image, p, 1, (current & 0xc0) | (low & 0x3f))?;
            applied
        }
        54..=56 => {
            let width = [1, 2, 4][(reloc.r_type - 54) as usize];
            put(image, p, width, x)?;
            applied
        }
        _ => Err(Refused::Unsupported),
    }
}
