//! Mach-O `MH_OBJECT` relocation types for x86-64 and arm64. An object's sections are laid out at their own
//! addresses plus [`super::OBJECT_BASE`], so one distance separates every placed section from where the object put
//! it: a field relocated against a section (not a symbol) keeps its PC-relative value and moves its absolute one by
//! that distance. Addends are implicit in the field, except arm64's `ADDEND` pairs, which `object` folds into the
//! relocation they precede, as it folds `SUBTRACTOR` pairs.

use rampage_arch::Arch;

use super::elf::{a64_adr, a64_field, get, page, put, sign_extend};
use super::{Applied, GotKey, Image, Refused, Reloc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Machine {
    X86_64,
    Arm64,
}

const X86_64: [&str; 10] =
    ["UNSIGNED", "SIGNED", "BRANCH", "GOT_LOAD", "GOT", "SUBTRACTOR", "SIGNED_1", "SIGNED_2", "SIGNED_4", "TLV"];

const ARM64: [&str; 12] = [
    "UNSIGNED",
    "SUBTRACTOR",
    "BRANCH26",
    "PAGE21",
    "PAGEOFF12",
    "GOT_LOAD_PAGE21",
    "GOT_LOAD_PAGEOFF12",
    "POINTER_TO_GOT",
    "TLVP_LOAD_PAGE21",
    "TLVP_LOAD_PAGEOFF12",
    "ADDEND",
    "AUTHENTICATED_POINTER",
];

impl Machine {
    pub fn of(arch: Arch) -> Option<Self> {
        match arch {
            Arch::X86_64 => Some(Self::X86_64),
            Arch::Aarch64 => Some(Self::Arm64),
            _ => None,
        }
    }

    pub fn type_name(self, r_type: u32) -> String {
        let (prefix, names): (&str, &[&str]) = match self {
            Self::X86_64 => ("X86_64", &X86_64),
            Self::Arm64 => ("ARM64", &ARM64),
        };
        names.get(r_type as usize).map_or_else(|| format!("type {r_type}"), |name| format!("{prefix}_RELOC_{name}"))
    }

    pub fn is_call(self, r_type: u32) -> bool {
        r_type == 2
    }

    pub fn uses_got(self, r_type: u32) -> bool {
        match self {
            Self::X86_64 => matches!(r_type, 3 | 4),
            Self::Arm64 => matches!(r_type, 5..=7),
        }
    }

    pub fn apply(self, image: &mut Image, reloc: &Reloc) -> Applied {
        match self {
            Self::X86_64 => x86_64(image, reloc),
            Self::Arm64 => arm64(image, reloc),
        }
    }
}

fn got(image: &Image, reloc: &Reloc) -> Result<u64, Refused> {
    let index = reloc.symbol_index.filter(|_| reloc.external).ok_or(Refused::Unsupported)?;
    image.got_entry(GotKey::Symbol(index)).ok_or(Refused::Unsupported)
}

/// `UNSIGNED`, alone or after a `SUBTRACTOR`: `S + A` (or `S - T + A`) for a symbol; for a section, the stored
/// address moved with the layout. A difference of two places in the object keeps its stored value.
fn unsigned(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    let width = reloc.length;
    if !matches!(width, 4 | 8) || reloc.pcrel {
        return Err(Refused::Unsupported);
    }
    let stored = get(image, p, width)?;
    let a = sign_extend(stored, width as u32 * 8);
    match (reloc.subtractor, reloc.external) {
        (Some(minus), true) => {
            let value = reloc.symbol.value.wrapping_sub(minus.value).wrapping_add(a as u64);
            put(image, p, width, value)?;
            Ok(Some((a, reloc.symbol.value.wrapping_add(a as u64))))
        }
        // The section-relative minuend and a subtrahend defined here moved by the same distance.
        (Some(minus), false) if minus.defined => Ok(Some((a, stored.wrapping_add(image.delta)))),
        (Some(_), false) => Err(Refused::Unsupported),
        (None, true) => {
            let target = reloc.symbol.value.wrapping_add(a as u64);
            put(image, p, width, target)?;
            Ok(Some((a, target)))
        }
        (None, false) => {
            let target = stored.wrapping_add(image.delta);
            put(image, p, width, target)?;
            Ok(Some((0, target)))
        }
    }
}

fn x86_64(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    match reloc.r_type {
        0 => unsigned(image, reloc),
        // SIGNED, BRANCH, SIGNED_1/2/4: the field is `S + stored - (P + 4)` whatever the bytes after it, since the
        // assembler stores the addend less those bytes. Against a section it already holds the distance.
        1 | 2 | 6 | 7 | 8 => {
            if reloc.length != 4 || !reloc.pcrel {
                return Err(Refused::Unsupported);
            }
            let after = match reloc.r_type {
                6 => 1,
                7 => 2,
                8 => 4,
                _ => 0,
            };
            let stored = sign_extend(get(image, p, 4)?, 32);
            // The site's addend is the offset from the symbol to the address referenced.
            let a = stored + after;
            if !reloc.external {
                return Ok(Some((0, p.wrapping_add(4 + after as u64).wrapping_add(stored as u64))));
            }
            let target = reloc.symbol.value.wrapping_add(a as u64);
            put(image, p, 4, reloc.symbol.value.wrapping_add(stored as u64).wrapping_sub(p.wrapping_add(4)))?;
            Ok(Some((a, target)))
        }
        // GOT_LOAD, GOT: `G + stored - (P + 4)`.
        3 | 4 => {
            if reloc.length != 4 {
                return Err(Refused::Unsupported);
            }
            let stored = sign_extend(get(image, p, 4)?, 32);
            let g = got(image, reloc)?;
            put(image, p, 4, g.wrapping_add(stored as u64).wrapping_sub(p.wrapping_add(4)))?;
            Ok(Some((stored, g)))
        }
        _ => Err(Refused::Unsupported),
    }
}

/// The page offset `value` encoded in an A64 `add` (unscaled) or load/store (scaled by its access size).
fn pageoff12(image: &mut Image, place: u64, value: u64) -> Result<(), Refused> {
    let insn = get(image, place, 4)?;
    let scale = if insn & 0x3b00_0000 == 0x3900_0000 {
        let size = (insn >> 30) as u32;
        if insn & 0x0480_0000 == 0x0480_0000 { size + 4 } else { size }
    } else {
        0
    };
    a64_field(image, place, (value & 0xfff) >> scale, 10, 12)
}

fn arm64(image: &mut Image, reloc: &Reloc) -> Applied {
    let p = reloc.place;
    // The `ADDEND` before it, or none: arm64 instruction fields hold no addend.
    let a = reloc.addend.unwrap_or(0);
    let x = reloc.symbol.value.wrapping_add(a as u64);
    match reloc.r_type {
        0 => unsigned(image, reloc),
        // BRANCH26, PAGE21, PAGEOFF12 against a section hold their value already: the layout moved the object by
        // whole pages.
        2 if !reloc.external => {
            let offset = sign_extend(get(image, p, 4)? & 0x3ff_ffff, 26) << 2;
            Ok(Some((0, p.wrapping_add(offset as u64))))
        }
        3 | 4 if !reloc.external => Ok(Some((0, reloc.symbol.value))),
        2 => {
            a64_field(image, p, x.wrapping_sub(p) >> 2, 0, 26)?;
            Ok(Some((a, x)))
        }
        3 => {
            a64_adr(image, p, page(x).wrapping_sub(page(p)) >> 12)?;
            Ok(Some((a, x)))
        }
        4 => {
            pageoff12(image, p, x)?;
            Ok(Some((a, x)))
        }
        5 => {
            let g = got(image, reloc)?;
            a64_adr(image, p, page(g).wrapping_sub(page(p)) >> 12)?;
            Ok(Some((a, g)))
        }
        6 => {
            let g = got(image, reloc)?;
            pageoff12(image, p, g)?;
            Ok(Some((a, g)))
        }
        // POINTER_TO_GOT: `G - P` in 32 bits, or `G` in a pointer.
        7 => {
            let g = got(image, reloc)?;
            match (reloc.pcrel, reloc.length) {
                (true, 4) => put(image, p, 4, g.wrapping_sub(p))?,
                (false, 8) => put(image, p, 8, g)?,
                _ => return Err(Refused::Unsupported),
            }
            Ok(Some((0, g)))
        }
        _ => Err(Refused::Unsupported),
    }
}
