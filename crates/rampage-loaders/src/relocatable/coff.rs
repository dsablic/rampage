//! COFF relocation types (`.obj`) for AMD64, I386, ARM64 and ARMNT (Thumb-2): which ones call, and how each is
//! computed and encoded, the way `lld-link` applies them. COFF addends are implicit: the field holds them. The
//! layout's image base is 0, so an image-relative (`ADDR32NB`) field holds the same address an absolute one does.

use rampage_arch::Arch;

use super::elf::{a64_adr, get, mov_encode, mov_immediate, put, put_thumb_pair, sign_extend, thumb_pair};
use super::{Applied, Image, Refused, Reloc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    Amd64,
    I386,
    Arm64,
    ArmNt,
}

const AMD64: [&str; 17] = [
    "ABSOLUTE", "ADDR64", "ADDR32", "ADDR32NB", "REL32", "REL32_1", "REL32_2", "REL32_3", "REL32_4", "REL32_5",
    "SECTION", "SECREL", "SECREL7", "TOKEN", "SREL32", "PAIR", "SSPAN32",
];

const ARM64: [&str; 18] = [
    "ABSOLUTE",
    "ADDR32",
    "ADDR32NB",
    "BRANCH26",
    "PAGEBASE_REL21",
    "REL21",
    "PAGEOFFSET_12A",
    "PAGEOFFSET_12L",
    "SECREL",
    "SECREL_LOW12A",
    "SECREL_HIGH12A",
    "SECREL_LOW12L",
    "TOKEN",
    "SECTION",
    "ADDR64",
    "BRANCH19",
    "BRANCH14",
    "REL32",
];

impl Machine {
    pub fn of(arch: Arch) -> Option<Self> {
        Some(match arch {
            Arch::X86_64 => Self::Amd64,
            Arch::X86 => Self::I386,
            Arch::Aarch64 => Self::Arm64,
            Arch::Arm => Self::ArmNt,
            _ => return None,
        })
    }

    pub fn type_name(self, typ: u32) -> String {
        let name = match self {
            Self::Amd64 => AMD64.get(typ as usize).copied().map(|name| ("AMD64", name)),
            Self::Arm64 => ARM64.get(typ as usize).copied().map(|name| ("ARM64", name)),
            Self::I386 => match typ {
                0 => Some("ABSOLUTE"),
                1 => Some("DIR16"),
                2 => Some("REL16"),
                6 => Some("DIR32"),
                7 => Some("DIR32NB"),
                9 => Some("SEG12"),
                10 => Some("SECTION"),
                11 => Some("SECREL"),
                12 => Some("TOKEN"),
                13 => Some("SECREL7"),
                20 => Some("REL32"),
                _ => None,
            }
            .map(|name| ("I386", name)),
            Self::ArmNt => match typ {
                0 => Some("ABSOLUTE"),
                1 => Some("ADDR32"),
                2 => Some("ADDR32NB"),
                3 => Some("BRANCH24"),
                4 => Some("BRANCH11"),
                10 => Some("REL32"),
                14 => Some("SECTION"),
                15 => Some("SECREL"),
                16 => Some("MOV32"),
                17 => Some("MOV32T"),
                18 => Some("BRANCH20T"),
                20 => Some("BRANCH24T"),
                21 => Some("BLX23T"),
                22 => Some("PAIR"),
                _ => None,
            }
            .map(|name| ("ARM", name)),
        };
        match name {
            Some((machine, name)) => format!("IMAGE_REL_{machine}_{name}"),
            None => format!("type {typ:#x}"),
        }
    }

    /// Whether the type is a call or branch to its symbol. `before` holds the bytes before the field: x86 uses
    /// REL32 for calls and data alike, told apart by the opcode.
    pub fn is_call(self, typ: u32, before: &[u8]) -> bool {
        let x86_branch = matches!(before.last(), Some(0xe8 | 0xe9)) || matches!(before, [0x0f, 0x80..=0x8f]);
        match self {
            Self::Amd64 => typ == 4 && x86_branch,
            Self::I386 => typ == 20 && x86_branch,
            Self::Arm64 => matches!(typ, 3 | 15 | 16),
            Self::ArmNt => matches!(typ, 18 | 20 | 21),
        }
    }

    /// Whether a reference through an import pointer (`__imp_X`) of this type is an indirect call or jump
    /// (`call`/`jmp [__imp_X]`), so `X` is a function. Other architectures load the pointer first; their imports
    /// are taken for functions.
    pub fn calls_through(self, typ: u32, before: &[u8]) -> bool {
        match self {
            Self::Amd64 | Self::I386 => matches!(before, [0xff, 0x15 | 0x25]) && matches!(typ, 4 | 6 | 20),
            Self::Arm64 | Self::ArmNt => true,
        }
    }

    pub fn apply(self, image: &mut Image, reloc: &Reloc) -> Applied {
        match self {
            Self::Amd64 => amd64(image, reloc),
            Self::I386 => i386(image, reloc),
            Self::Arm64 => arm64(image, reloc),
            Self::ArmNt => armnt(image, reloc),
        }
    }
}

/// Adds `value` to the `width`-byte field at `place`, whose stored value is the addend.
fn add(image: &mut Image, place: u64, width: usize, value: u64) -> Applied {
    let stored = get(image, place, width)?;
    let a = sign_extend(stored, width as u32 * 8);
    put(image, place, width, stored.wrapping_add(value))?;
    Ok(Some((a, value.wrapping_add(a as u64))))
}

/// `SECTION`: the object's own section number of the symbol's section.
fn section_number(image: &mut Image, reloc: &Reloc) -> Applied {
    let number = u64::from(reloc.symbol.section_number);
    if number == 0 {
        return Err(Refused::Unsupported);
    }
    let (a, _) = add(image, reloc.place, 2, number)?.unwrap_or_default();
    Ok(Some((a, number)))
}

/// `SECREL`: the symbol's offset in its section.
fn secrel(reloc: &Reloc) -> u64 {
    reloc.symbol.value.wrapping_sub(reloc.symbol.section_base)
}

/// `REL32` and its forms: `S + A - (P + 4 + extra)`, where `extra` counts the bytes of the instruction after the
/// field. The site's value is `S + A`, the address referenced.
fn rel32(image: &mut Image, reloc: &Reloc, extra: u64) -> Applied {
    let p = reloc.place;
    let a = sign_extend(get(image, p, 4)?, 32);
    let target = reloc.symbol.value.wrapping_add(a as u64);
    put(image, p, 4, target.wrapping_sub(p.wrapping_add(4 + extra)))?;
    Ok(Some((a, target)))
}

fn amd64(image: &mut Image, reloc: &Reloc) -> Applied {
    let s = reloc.symbol.value;
    match reloc.r_type {
        0 => Ok(None),
        1 => add(image, reloc.place, 8, s),
        2 | 3 => add(image, reloc.place, 4, s),
        4..=9 => rel32(image, reloc, u64::from(reloc.r_type - 4)),
        10 => section_number(image, reloc),
        11 => add(image, reloc.place, 4, secrel(reloc)),
        _ => Err(Refused::Unsupported),
    }
}

fn i386(image: &mut Image, reloc: &Reloc) -> Applied {
    let s = reloc.symbol.value;
    match reloc.r_type {
        0 => Ok(None),
        1 => add(image, reloc.place, 2, s),
        6 | 7 => add(image, reloc.place, 4, s),
        10 => section_number(image, reloc),
        11 => add(image, reloc.place, 4, secrel(reloc)),
        20 => rel32(image, reloc, 0),
        _ => Err(Refused::Unsupported),
    }
}

/// Adds `value` to an A64 instruction's 12-bit immediate (bits 21:10), keeping `12 - limit` bits, as `lld-link`
/// does. Returns the immediate the field held.
fn a64_imm12(image: &mut Image, place: u64, value: u64, limit: u32) -> Result<u64, Refused> {
    let insn = get(image, place, 4)?;
    let stored = (insn >> 10) & 0xfff;
    let imm = stored.wrapping_add(value) & (0xfff >> limit);
    put(image, place, 4, (insn & !(0xfff << 10)) | (imm << 10))?;
    Ok(stored)
}

/// The access size (log2 bytes) of an A64 load/store with an unsigned offset: 128-bit SIMD loads are 4.
fn a64_scale(insn: u64) -> u32 {
    let size = (insn >> 30) as u32;
    if insn & 0x0480_0000 == 0x0480_0000 { size + 4 } else { size }
}

/// A scaled 12-bit load/store offset (`PAGEOFFSET_12L`, `SECREL_LOW12L`): the page offset `value` divided by the
/// access size, added to the stored one. Returns the addend in bytes.
fn a64_ldst(image: &mut Image, place: u64, value: u64) -> Result<i64, Refused> {
    let scale = a64_scale(get(image, place, 4)?);
    let stored = a64_imm12(image, place, value >> scale, scale)?;
    Ok((stored << scale) as i64)
}

/// The 21-bit immediate of an `adr`/`adrp`, which COFF uses as the addend in bytes.
fn a64_adr_immediate(insn: u64) -> i64 {
    sign_extend(((insn >> 29) & 3) | ((insn >> 3) & 0x1f_fffc), 21)
}

/// Branches: `S + A - P` (A the stored offset) in `bits` bits at bit `shift`.
fn a64_branch(image: &mut Image, reloc: &Reloc, shift: u32, bits: u32) -> Applied {
    let p = reloc.place;
    let insn = get(image, p, 4)?;
    let mask = ((1u64 << bits) - 1) << shift;
    let a = sign_extend((insn & mask) >> shift, bits) << 2;
    let target = reloc.symbol.value.wrapping_add(a as u64);
    let field = (target.wrapping_sub(p) >> 2) << shift;
    put(image, p, 4, (insn & !mask) | (field & mask))?;
    Ok(Some((a, target)))
}

fn arm64(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    let s = reloc.symbol.value;
    match reloc.r_type {
        0 => Ok(None),
        1 | 2 => add(image, p, 4, s),
        14 => add(image, p, 8, s),
        17 => rel32(image, reloc, 0),
        3 => a64_branch(image, reloc, 0, 26),
        15 => a64_branch(image, reloc, 5, 19),
        16 => a64_branch(image, reloc, 5, 14),
        // PAGEBASE_REL21 (`adrp`), REL21 (`adr`): the stored immediate is the addend in bytes.
        4 | 5 => {
            let a = a64_adr_immediate(get(image, p, 4)?);
            let target = s.wrapping_add(a as u64);
            let value = if reloc.r_type == 4 { (target >> 12).wrapping_sub(p >> 12) } else { target.wrapping_sub(p) };
            a64_adr(image, p, value)?;
            Ok(Some((a, target)))
        }
        // PAGEOFFSET_12A (`add`): the page offset added to the stored immediate.
        6 => {
            let a = a64_imm12(image, p, s & 0xfff, 0)? as i64;
            Ok(Some((a, s.wrapping_add(a as u64))))
        }
        // PAGEOFFSET_12L (loads and stores): scaled by the access size.
        7 => {
            let a = a64_ldst(image, p, s & 0xfff)?;
            Ok(Some((a, s.wrapping_add(a as u64))))
        }
        8 => add(image, p, 4, secrel(reloc)),
        9 | 10 => {
            let offset = secrel(reloc);
            let part = if reloc.r_type == 9 { offset & 0xfff } else { (offset >> 12) & 0xfff };
            let a = a64_imm12(image, p, part, 0)? as i64;
            Ok(Some((a, s)))
        }
        11 => {
            let a = a64_ldst(image, p, secrel(reloc) & 0xfff)?;
            Ok(Some((a, s)))
        }
        13 => section_number(image, reloc),
        _ => Err(Refused::Unsupported),
    }
}

/// A Thumb-2 `b.w`/`bl`/`blx` (`BRANCH24T`, `BLX23T`) to `offset` from the field, as `lld-link` encodes it.
fn thumb_branch24(image: &mut Image, place: u64, offset: u64) -> Result<(), Refused> {
    let pair = thumb_pair(image, place)?;
    let (high, low) = (pair >> 16, pair & 0xffff);
    let (high, low) = super::elf::thumb_branch_encode(high & 0xf800, low, offset);
    put_thumb_pair(image, place, (high << 16) | low)
}

/// A Thumb-2 conditional `b<c>.w` (`BRANCH20T`).
fn thumb_branch20(image: &mut Image, place: u64, x: u64) -> Result<(), Refused> {
    let pair = thumb_pair(image, place)?;
    let (high, low) = (pair >> 16, pair & 0xffff);
    let high = (high & 0xfbc0) | (((x >> 20) & 1) << 10) | ((x >> 12) & 0x3f);
    let low = (low & 0xd000) | (((x >> 18) & 1) << 13) | (((x >> 19) & 1) << 11) | ((x >> 1) & 0x7ff);
    put_thumb_pair(image, place, (high << 16) | low)
}

fn armnt(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    // A pointer to Thumb code has the low bit set.
    let s = reloc.symbol.value | u64::from(reloc.symbol.in_code);
    match reloc.r_type {
        0 => Ok(None),
        1 | 2 => add(image, p, 4, s),
        10 => rel32(image, reloc, 0),
        14 => section_number(image, reloc),
        15 => add(image, p, 4, secrel(reloc)),
        // MOV32T: a `movw`/`movt` pair holding the address, the stored halves the addend.
        17 => {
            let high_place = p.checked_add(4).ok_or(Refused::OutOfRange)?;
            let low = thumb_pair(image, p)?;
            let high = thumb_pair(image, high_place)?;
            let a = ((mov_immediate(high, true) << 16) | mov_immediate(low, true)) as u32 as i32 as i64;
            let value = s.wrapping_add(a as u64);
            put_thumb_pair(image, p, mov_encode(low, true, value))?;
            put_thumb_pair(image, high_place, mov_encode(high, true, value >> 16))?;
            Ok(Some((a, value)))
        }
        18 => {
            let target = s & !1;
            thumb_branch20(image, p, target.wrapping_sub(p).wrapping_sub(4))?;
            Ok(Some((0, target)))
        }
        20 | 21 => {
            let target = s & !1;
            thumb_branch24(image, p, target.wrapping_sub(p).wrapping_sub(4))?;
            Ok(Some((0, target)))
        }
        _ => Err(Refused::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::{Image, Reloc, SymbolInfo};
    use super::Machine;

    /// Applies one relocation of `typ` at 0x1000 + `at` over `bytes`, against a symbol at `value` in a section
    /// numbered 3 that starts at 0x2000, and returns the bytes.
    fn apply(machine: Machine, typ: u32, bytes: &[u8], at: u64, value: u64) -> Vec<u8> {
        let mut bytes = bytes.to_vec();
        let placed = [(0x1000, bytes.len() as u64, 0)];
        let entries = HashMap::new();
        let mut image = Image {
            bytes: &mut bytes,
            big_endian: false,
            placed: &placed,
            got: 0,
            got_entries: &entries,
            gp: 0,
            pointer: 8,
            delta: 0,
            touched: None,
        };
        let symbol = SymbolInfo { value, section_number: 3, section_base: 0x2000, ..SymbolInfo::NONE };
        let reloc = Reloc {
            r_type: typ,
            place: 0x1000 + at,
            symbol,
            symbol_index: Some(1),
            addend: None,
            pcrel: false,
            length: 0,
            external: true,
            subtractor: None,
        };
        machine.apply(&mut image, &reloc).ok().flatten().expect("applied");
        bytes
    }

    #[test]
    fn rel32_forms_count_the_bytes_after_the_field_as_msvc_emits_them() {
        // `mov dword ptr [rip+x], 7` (c7 05 disp32 imm32): MSVC emits REL32_4 with a zero stored addend.
        let insn = [0xc7, 0x05, 0, 0, 0, 0, 7, 0, 0, 0];
        let out = apply(Machine::Amd64, 8, &insn, 2, 0x3000);
        // The instruction ends at 0x1000 + 10, so the displacement is 0x3000 - 0x100a.
        assert_eq!(i32::from_le_bytes(out[2..6].try_into().unwrap()), 0x3000 - 0x100a);
        // REL32 with an addend of -4 stored, as LLVM writes the same store.
        let insn = [0xc7, 0x05, 0xfc, 0xff, 0xff, 0xff, 7, 0, 0, 0];
        let out = apply(Machine::Amd64, 4, &insn, 2, 0x3000);
        assert_eq!(i32::from_le_bytes(out[2..6].try_into().unwrap()), 0x3000 - 0x100a);
    }

    #[test]
    fn section_and_secrel_give_the_section_number_and_the_offset_in_it() {
        let out = apply(Machine::Amd64, 10, &[0, 0], 0, 0x2010);
        assert_eq!(out, [3, 0]);
        let out = apply(Machine::Amd64, 11, &[4, 0, 0, 0], 0, 0x2010);
        assert_eq!(u32::from_le_bytes(out.try_into().unwrap()), 0x14);
        let out = apply(Machine::I386, 11, &[0, 0, 0, 0], 0, 0x2020);
        assert_eq!(u32::from_le_bytes(out.try_into().unwrap()), 0x20);
    }

    #[test]
    fn arm64_branches_and_secrel_immediates() {
        // `b.eq` (BRANCH19) to 0x1100: (0x1100 - 0x1000) / 4 = 0x40 in bits 23:5.
        let out = apply(Machine::Arm64, 15, &0x5400_0000u32.to_le_bytes(), 0, 0x1100);
        assert_eq!(u32::from_le_bytes(out.try_into().unwrap()), 0x5400_0000 | (0x40 << 5));
        // `tbz` (BRANCH14) back to 0x0ff8: -2 in bits 18:5.
        let out = apply(Machine::Arm64, 16, &0x3600_0000u32.to_le_bytes(), 0, 0x0ff8);
        assert_eq!(u32::from_le_bytes(out.try_into().unwrap()), 0x3600_0000 | ((0x3ffe) << 5));
        // `add x0, x0, #:secrel_lo12:` and `#:secrel_hi12:` of an offset of 0x1234 (symbol at 0x3234).
        let add = 0x9100_0000u32.to_le_bytes();
        let low = apply(Machine::Arm64, 9, &add, 0, 0x3234);
        let high = apply(Machine::Arm64, 10, &add, 0, 0x3234);
        assert_eq!((u32::from_le_bytes(low.try_into().unwrap()) >> 10) & 0xfff, 0x234);
        assert_eq!((u32::from_le_bytes(high.try_into().unwrap()) >> 10) & 0xfff, 0x1);
    }
}
