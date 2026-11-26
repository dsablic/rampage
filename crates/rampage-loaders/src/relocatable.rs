//! Relocatable objects, loaded the way a linker would place them on their own, as IDA does: the allocated sections
//! laid out at synthetic, non-overlapping addresses from [`OBJECT_BASE`], each aligned as it asks; common symbols in
//! a zero-filled `COMMON` segment; an `extern` segment with one slot per undefined symbol, so calls and references to
//! it reach a named target; a synthetic `.got` holding one entry per symbol the code reaches through a GOT; and the
//! relocations applied into a loaded copy of the file, each site kept with its type, symbol and addend.
//!
//! The layout reads sections, symbols and relocations through `object`'s format-independent interface; which
//! sections are loaded and how a relocation type is computed and encoded are format-specific: ELF ([`elf`]), COFF
//! `.obj` ([`coff`], with `__imp_` import pointers and weak externals) and Mach-O `MH_OBJECT` ([`macho`], whose
//! sections keep the addresses the object gives them, moved by [`OBJECT_BASE`]).

mod coff;
mod elf;
mod macho;

use std::collections::{BTreeMap, HashMap};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionIndex, SymbolIndex, SymbolSection};
use rampage_arch::Arch;
use serde::Serialize;

use crate::model::{Perms, Segment};

/// Where the first allocated section of a relocatable object is placed: away from address 0, so a null pointer or
/// a small constant is never mistaken for one of its addresses.
pub const OBJECT_BASE: u64 = 0x10000;

/// The most relocation sites kept per object; the rest are still applied, only not listed.
pub const MAX_RELOCATION_SITES: usize = 1 << 20;

/// A relocation applied into the loaded image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelocationSite {
    /// The address of the field the relocation patches.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The relocation type's name, such as `R_X86_64_PLT32`, or its number when it has none.
    pub kind: String,
    /// The symbol the relocation refers to (a section's name for a section symbol), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub addend: i64,
    /// `S + A`, the symbol's address plus the addend (so `printf - 4` for an ELF x86 call's PC-relative field; COFF
    /// and Mach-O addends are the offset from the symbol to the address referenced), or the GOT entry's address for
    /// a reference through the GOT.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
    /// The bytes the relocation patched, from `address`: what a signature built from the object leaves out.
    #[serde(skip)]
    pub field: u8,
}

/// A relocation type the loader does not apply, reported once per type with how many sites use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsupportedRelocation {
    pub kind: String,
    pub count: usize,
    /// The first site, whose field is left as the file stores it.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub first: u64,
}

/// An undefined symbol's slot in the `extern` segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extern {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Whether a call or branch relocation reaches it, or the object types it as a function.
    pub function: bool,
    pub weak: bool,
}

/// A synthetic GOT entry: its address, the value it holds, and the extern it holds, if any.
pub(crate) type GotEntry = (u64, u64, Option<String>);

/// What a relocatable object's layout gives the loader.
#[derive(Debug)]
pub struct Relocated {
    /// The loaded image: the file's bytes with every applied relocation written in, followed by the synthetic GOT.
    pub(crate) bytes: Vec<u8>,
    pub(crate) segments: Vec<Segment>,
    /// Where the segments the layout adds (common symbols, externs, the GOT) start in `segments`.
    synthetic: usize,
    /// Where each symbol and section of the object lies.
    places: Places,
    pub externs: Vec<Extern>,
    /// The synthetic GOT: its address and each entry's (address, value, extern name if the value is an extern).
    pub(crate) got: Option<(u64, Vec<GotEntry>)>,
    /// The GOT entries holding a function the object defines.
    pub(crate) got_functions: Vec<crate::slots::GotFunction>,
    pub sites: Vec<RelocationSite>,
    pub sites_total: usize,
    pub unsupported: Vec<UnsupportedRelocation>,
    /// The fields of relocations left unapplied (at most [`MAX_UNAPPLIED_SITES`]): they hold the file's bytes, not
    /// a value to fold.
    pub unapplied: Vec<u64>,
    /// Each unapplied field's width in bytes, where the relocation gives one (Mach-O), else 4, by address.
    pub unapplied_widths: Vec<(u64, u8)>,
    pub warnings: Vec<String>,
    /// COFF: the linker directives of `.drectve` (`/DEFAULTLIB:...`, `/EXPORT:...`).
    pub directives: Vec<String>,
    /// COMDAT sections (COFF `IMAGE_SCN_LNK_COMDAT`, ELF groups), each laid out like any other.
    pub comdats: usize,
    /// COFF import pointers (`__imp_X`): a slot in the synthetic import table holding the extern `X`'s address.
    pub import_pointers: Vec<(String, u64)>,
    /// COFF weak externals the object defines through their default symbol: name, address and whether a function.
    pub weak_definitions: Vec<(String, u64, bool)>,
}

/// The most unapplied relocation fields kept.
pub const MAX_UNAPPLIED_SITES: usize = 4096;

/// The layout stops placing sections where it would pass this address.
pub const MAX_LAYOUT_ADDRESS: u64 = 1 << 48;

/// Where the object's sections, common symbols and externs lie: one place that resolves a symbol to its address.
#[derive(Debug, Default)]
struct Places {
    /// Each section's address by section index; `None` for one that is not placed.
    sections: Vec<Option<u64>>,
    /// Where each section was in the object's own addressing, by section index: 0 for ELF, whose symbol values
    /// are offsets in their sections; COFF and Mach-O symbols carry the section's address.
    origins: Vec<u64>,
    /// Common, undefined, weak external and import-pointer symbols' addresses, by symbol index.
    symbols: HashMap<usize, u64>,
}

impl Places {
    /// The address of `symbol` (with the Thumb bit a Thumb function's value carries); `None` for one in a section
    /// that is not placed.
    fn of(&self, symbol: &object::Symbol) -> Option<u64> {
        match symbol.section() {
            SymbolSection::Section(index) => {
                let origin = self.origins.get(index.0).copied().unwrap_or(0);
                Some(self.section(index)?.wrapping_add(symbol.address().wrapping_sub(origin)))
            }
            SymbolSection::Absolute => Some(symbol.address()),
            _ => self.symbols.get(&symbol.index().0).copied(),
        }
    }

    fn section(&self, index: SectionIndex) -> Option<u64> {
        self.sections.get(index.0).copied().flatten()
    }
}

impl Relocated {
    /// The address of a symbol of the object, with any Thumb bit its value carries; `None` for one in a section
    /// that is not placed.
    pub(crate) fn symbol_address(&self, symbol: &object::Symbol) -> Option<u64> {
        self.places.of(symbol)
    }

    pub(crate) fn section_address(&self, index: SectionIndex) -> Option<u64> {
        self.places.section(index)
    }

    /// The import slots of the synthetic GOT: each entry that holds an extern's address.
    pub(crate) fn got_imports(&self) -> Vec<crate::model::ImportSlot> {
        let Some((_, entries)) = &self.got else { return Vec::new() };
        entries
            .iter()
            .filter_map(|(address, _, name)| {
                Some(crate::model::ImportSlot { address: *address, name: name.clone()?, library: None })
            })
            .collect()
    }

    /// The segments the layout adds beyond the file's sections (`COMMON`, `extern`, `.got`), as sections, so an
    /// address in one names it and the GOT is found by name as a linked image's is.
    pub(crate) fn synthetic_sections(&self) -> impl Iterator<Item = crate::model::Section> + '_ {
        self.segments[self.synthetic..].iter().map(|segment| {
            let kind = match segment.name.as_str() {
                ".got" => crate::model::SectionKind::Data,
                "extern" => crate::model::SectionKind::Other,
                _ => crate::model::SectionKind::UninitializedData,
            };
            crate::model::Section {
                name: segment.name.clone(),
                address: segment.address,
                size: segment.size,
                kind,
                file_offset: None,
                file_size: 0,
            }
        })
    }

    /// The relocation sites in `range`, by address.
    pub fn sites_in(&self, range: std::ops::Range<u64>) -> &[RelocationSite] {
        let start = self.sites.partition_point(|site| site.address < range.start);
        let end = self.sites.partition_point(|site| site.address < range.end);
        &self.sites[start..end.max(start)]
    }
}

/// `value` rounded up to `align`, or `None` past [`MAX_LAYOUT_ADDRESS`].
fn align_up(value: u64, align: u64) -> Option<u64> {
    let align = align.max(1);
    let aligned = value.checked_next_multiple_of(align)?;
    (aligned <= MAX_LAYOUT_ADDRESS).then_some(aligned)
}

/// Where `size` bytes aligned to `align` go after `cursor`, and where they end; `None` when that passes
/// [`MAX_LAYOUT_ADDRESS`].
fn place(cursor: u64, align: u64, size: u64) -> Option<(u64, u64)> {
    let address = align_up(cursor, align)?;
    let end = address.checked_add(size).filter(|&end| end <= MAX_LAYOUT_ADDRESS)?;
    Some((address, end))
}

/// The bytes of a function extern's slot: a branch to itself, which the decompiler turns into a call to the extern
/// followed by a return wherever flow reaches it (a tail call, conditional or not). MIPS adds its delay slot.
fn extern_stub(arch: Arch, thumb: bool, big_endian: bool) -> Vec<u8> {
    let word = |value: u32| if big_endian { value.to_be_bytes() } else { value.to_le_bytes() }.to_vec();
    match arch {
        Arch::X86 | Arch::X86_64 => vec![0xeb, 0xfe],
        Arch::Arm if thumb => {
            if big_endian {
                vec![0xe7, 0xfe]
            } else {
                vec![0xfe, 0xe7]
            }
        }
        Arch::Arm => word(0xeaff_fffe),
        Arch::Aarch64 => 0x1400_0000u32.to_le_bytes().to_vec(),
        Arch::Mips | Arch::Mips64 => [word(0x1000_ffff), word(0)].concat(),
        Arch::Riscv32 | Arch::Riscv64 => 0x0000_006fu32.to_le_bytes().to_vec(),
        _ => Vec::new(),
    }
}

/// An extern's slot size: room for its stub and the pointer it stands for.
const EXTERN_SLOT: u64 = 8;

/// What a relocation needs from its symbol.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SymbolInfo {
    /// The symbol's address (with the Thumb bit of a Thumb function), or 0 for none.
    pub value: u64,
    /// Defined in this object (not an extern): a call to it may change ARM/Thumb state.
    pub defined: bool,
    pub local: bool,
    pub function: bool,
    pub size: u64,
    /// MIPS `_gp_disp`, whose value depends on the instruction using it.
    pub gp_disp: bool,
    /// COFF: the number of the symbol's section in the object (from 1), 0 for none.
    pub section_number: u16,
    /// The placed address of the symbol's section.
    pub section_base: u64,
    /// The symbol's section is code (an ARM pointer to it gets the Thumb bit).
    pub in_code: bool,
}

impl SymbolInfo {
    const NONE: Self = Self {
        value: 0,
        defined: false,
        local: true,
        function: false,
        size: 0,
        gp_disp: false,
        section_number: 0,
        section_base: 0,
        in_code: false,
    };
}

/// A relocation as the per-format code applies it.
pub(crate) struct Reloc {
    pub r_type: u32,
    /// The field's address.
    pub place: u64,
    pub symbol: SymbolInfo,
    pub symbol_index: Option<usize>,
    /// The explicit addend (RELA, a Mach-O `ADDEND` pair), or `None` when the addend is stored in the field (REL,
    /// COFF, Mach-O).
    pub addend: Option<i64>,
    /// Mach-O: whether the field is PC-relative, its width in bytes, whether it names a symbol (not a section), and
    /// the symbol a `SUBTRACTOR` pair subtracts.
    pub pcrel: bool,
    pub length: usize,
    pub external: bool,
    pub subtractor: Option<SymbolInfo>,
}

/// Results `apply` gives: the addend used and the resolved target, or nothing for a type that writes nothing.
pub(crate) type Applied = Result<Option<(i64, u64)>, Refused>;

/// The loaded image a relocation writes into, with the synthetic GOT and the global pointer.
pub(crate) struct Image<'a> {
    pub bytes: &'a mut [u8],
    pub big_endian: bool,
    /// Address to file offset of each placed section (address, size, file offset), for writing at an address.
    pub placed: &'a [(u64, u64, u64)],
    pub got: u64,
    /// GOT entries by key.
    pub got_entries: &'a HashMap<GotKey, u64>,
    /// The global pointer of MIPS (`.got` + 0x7ff0); the GOT base elsewhere.
    pub gp: u64,
    /// A GOT entry's width.
    pub pointer: usize,
    /// Mach-O: how far the layout moved every section from the address the object gave it.
    pub delta: u64,
    /// The bytes written at and after the current relocation's field: (place, end).
    touched: Option<(u64, u64)>,
    /// Mach-O arm64: the last section-relative `PAGE21`'s place and the page it reaches.
    pub last_page: Option<(u64, u64)>,
}

/// What a GOT entry holds: a symbol's address, or (MIPS local GOT16) a 64 KiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum GotKey {
    Symbol(usize),
    Page(u64),
}

impl Image<'_> {
    fn offset(&self, address: u64, width: usize) -> Option<usize> {
        let index = self.placed.partition_point(|&(start, _, _)| start <= address).checked_sub(1)?;
        let (start, size, file_offset) = self.placed[index];
        let within = address - start;
        if within.checked_add(width as u64)? > size {
            return None;
        }
        usize::try_from(file_offset.checked_add(within)?).ok()
    }

    pub fn get(&self, address: u64, width: usize) -> Option<u64> {
        let offset = self.offset(address, width)?;
        rampage_arch::bytes::read_uint(self.bytes, offset, width, self.big_endian)
    }

    pub fn put(&mut self, address: u64, width: usize, value: u64) -> Option<()> {
        let offset = self.offset(address, width)?;
        if let Some((place, end)) = &mut self.touched
            && address >= *place
            && address < place.saturating_add(16)
        {
            *end = (*end).max(address + width as u64);
        }
        let field = self.bytes.get_mut(offset..offset + width)?;
        let encoded = value.to_le_bytes();
        for (index, byte) in field.iter_mut().enumerate() {
            *byte = if self.big_endian { encoded[width - 1 - index] } else { encoded[index] };
        }
        Some(())
    }

    pub fn got_entry(&self, key: GotKey) -> Option<u64> {
        self.got_entries.get(&key).copied()
    }
}

/// Why a relocation was not applied.
pub(crate) enum Refused {
    /// The loader does not apply this type.
    Unsupported,
    /// The field lies outside its section.
    OutOfRange,
}

/// The object format's relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Machine {
    Elf(elf::Machine),
    Coff(coff::Machine),
    MachO(macho::Machine),
}

impl Machine {
    fn of(parsed: &object::File, arch: Arch) -> Option<Self> {
        if parsed.kind() != object::ObjectKind::Relocatable {
            return None;
        }
        match parsed.format() {
            object::BinaryFormat::Elf => elf::Machine::of(arch).map(Self::Elf),
            object::BinaryFormat::Coff => coff::Machine::of(arch).map(Self::Coff),
            object::BinaryFormat::MachO => macho::Machine::of(arch).map(Self::MachO),
            _ => None,
        }
    }

    /// The relocation's type and, for Mach-O, whether it is PC-relative and its field's width in bytes.
    fn r_type(flags: object::RelocationFlags) -> Option<(u32, bool, usize)> {
        match flags {
            object::RelocationFlags::Elf { r_type } => Some((r_type.0, false, 0)),
            object::RelocationFlags::Coff { typ } => Some((u32::from(typ.0), false, 0)),
            object::RelocationFlags::MachO { r_type, r_pcrel, r_length } => {
                Some((u32::from(r_type.0), r_pcrel, 1usize << r_length))
            }
            _ => None,
        }
    }

    fn type_name(self, r_type: u32) -> String {
        match self {
            Self::Elf(machine) => machine.type_name(object::elf::RelocationType(r_type)),
            Self::Coff(machine) => machine.type_name(r_type),
            Self::MachO(machine) => machine.type_name(r_type),
        }
    }

    fn is_call(self, r_type: u32, before: &[u8]) -> bool {
        match self {
            Self::Elf(machine) => machine.is_call(r_type, before),
            Self::Coff(machine) => machine.is_call(r_type, before),
            Self::MachO(machine) => machine.is_call(r_type),
        }
    }

    fn uses_got(self, r_type: u32) -> bool {
        match self {
            Self::Elf(machine) => machine.uses_got(r_type),
            Self::Coff(_) => false,
            Self::MachO(machine) => machine.uses_got(r_type),
        }
    }

    fn is_local_got_page(self, r_type: u32) -> bool {
        matches!(self, Self::Elf(machine) if machine.is_local_got_page(r_type))
    }

    fn special(self, name: &str) -> Option<elf::Special> {
        match self {
            Self::Elf(machine) => machine.special(name),
            _ => None,
        }
    }

    fn is_mips(self) -> bool {
        matches!(self, Self::Elf(machine) if machine.is_mips())
    }

    fn apply(self, image: &mut Image, reloc: &Reloc, state: &mut elf::State) -> Applied {
        match self {
            Self::Elf(machine) => machine.apply(image, reloc, state),
            Self::Coff(machine) => machine.apply(image, reloc),
            Self::MachO(machine) => machine.apply(image, reloc),
        }
    }

    /// The synthetic pointer table's name: a GOT, or COFF's import address table.
    fn got_name(self) -> &'static str {
        match self {
            Self::Elf(_) => ".got",
            Self::Coff(_) => ".idata",
            Self::MachO(_) => "__got",
        }
    }

    /// The permissions of a section the layout loads, or `None` for one it leaves out: ELF's non-`SHF_ALLOC`
    /// sections; COFF's linker directives, debug (`.debug$S`, `.debug$T`) and other discardable sections; Mach-O's
    /// debug sections and `__LD` (compact unwind, which the linker consumes).
    fn loaded(self, section: &object::Section) -> Option<Perms> {
        match section.flags() {
            object::SectionFlags::Elf { sh_flags, .. } => {
                let flag = |bit| sh_flags.contains(bit);
                flag(object::elf::SHF_ALLOC).then(|| Perms {
                    read: true,
                    write: flag(object::elf::SHF_WRITE),
                    execute: flag(object::elf::SHF_EXECINSTR),
                })
            }
            object::SectionFlags::Coff { characteristics } => {
                use object::pe;
                let flag = |bit: pe::SectionFlags| characteristics.0 & bit.0 != 0;
                let left_out = pe::SectionFlags(
                    pe::IMAGE_SCN_LNK_REMOVE.0 | pe::IMAGE_SCN_LNK_INFO.0 | pe::IMAGE_SCN_MEM_DISCARDABLE.0,
                );
                let contents = pe::SectionFlags(
                    pe::IMAGE_SCN_CNT_CODE.0
                        | pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0
                        | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0,
                );
                (!flag(left_out) && flag(contents)).then(|| Perms {
                    read: true,
                    write: flag(pe::IMAGE_SCN_MEM_WRITE),
                    execute: flag(pe::IMAGE_SCN_MEM_EXECUTE) || flag(pe::IMAGE_SCN_CNT_CODE),
                })
            }
            object::SectionFlags::MachO { flags, .. } => {
                use object::macho;
                let segment = section.segment_name().ok().flatten().unwrap_or_default();
                let flag = |bit: macho::SectionFlags| flags.0 & bit.0 != 0;
                if flag(macho::S_ATTR_DEBUG) || matches!(segment, "__LD" | "__DWARF") {
                    return None;
                }
                let code = flag(macho::S_ATTR_PURE_INSTRUCTIONS) || flag(macho::S_ATTR_SOME_INSTRUCTIONS);
                let constant = section.name().is_ok_and(|name| name == "__const");
                Some(Perms { read: true, write: segment == "__DATA" && !constant, execute: code })
            }
            _ => None,
        }
    }
}

/// The default symbol of a COFF weak external (`IMAGE_SYM_CLASS_WEAK_EXTERNAL`), which stands for the symbol
/// when nothing else defines it; `None` for any other symbol.
fn coff_weak_default(parsed: &object::File, index: SymbolIndex) -> Option<SymbolIndex> {
    use object::read::coff::Symbol as _;
    macro_rules! weak {
        ($file:expr) => {{
            let table = $file.coff_symbol_table();
            let symbol = table.symbol(index).ok()?;
            (symbol.storage_class() == object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
                && symbol.section_number() == object::pe::IMAGE_SYM_UNDEFINED)
                .then(|| table.aux_weak_external(index).ok().map(|aux| aux.default_symbol()))
                .flatten()
        }};
    }
    match parsed {
        object::File::Coff(file) => weak!(file),
        object::File::CoffBig(file) => weak!(file),
        _ => None,
    }
}

/// The linker directives of a COFF object's `.drectve` section, split as a command line is (quotes kept).
fn coff_directives(parsed: &object::File) -> Vec<String> {
    let Some(section) = parsed.section_by_name(".drectve") else { return Vec::new() };
    let Ok(data) = section.data() else { return Vec::new() };
    let text = String::from_utf8_lossy(data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data)).into_owned();
    let mut directives = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in text.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ' ' | '\t' | '\r' | '\n' | '\0' if !quoted => {
                if !current.is_empty() {
                    directives.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
        if directives.len() >= MAX_DIRECTIVES {
            break;
        }
    }
    if !current.is_empty() && directives.len() < MAX_DIRECTIVES {
        directives.push(current);
    }
    directives
}

/// The most `.drectve` directives kept.
const MAX_DIRECTIVES: usize = 256;

/// The prefix of a COFF import pointer: `__imp_X` is a slot holding the address of `X`, defined in a DLL.
const IMPORT_POINTER: &str = "__imp_";

/// Lays out `parsed`, a relocatable object (ELF, COFF or Mach-O), and applies its relocations into a copy of
/// `file`. `None` for an image that is not a relocatable object or an architecture with no relocation support.
/// `thumb` says function externs are reached in Thumb state (an M-profile or Windows ARM object), which their stubs
/// are encoded for.
pub(crate) fn load(parsed: &object::File, file: &[u8], arch: Arch, big_endian: bool, thumb: bool) -> Option<Relocated> {
    let machine = Machine::of(parsed, arch)?;
    let pointer = u64::from(arch.default_pointer_size().unwrap_or(if parsed.is_64() { 8 } else { 4 }));
    let mut warnings = Vec::new();
    // Mach-O sections keep their own addresses, moved by the base; the others are packed from it.
    let keep_addresses = matches!(machine, Machine::MachO(_));
    let delta = if keep_addresses { OBJECT_BASE } else { 0 };

    // Loaded sections, in file order.
    let section_count = parsed.sections().map(|section| section.index().0 + 1).max().unwrap_or(0);
    let mut places =
        Places { sections: vec![None; section_count], origins: vec![0; section_count], symbols: HashMap::new() };
    let mut segments = Vec::new();
    let mut placed = Vec::new();
    let mut code_sections = std::collections::HashSet::new();
    let mut cursor = OBJECT_BASE;
    for section in parsed.sections() {
        let Some(perms) = machine.loaded(&section) else { continue };
        if section.size() == 0 {
            continue;
        }
        let size = section.size();
        let spot = if keep_addresses {
            OBJECT_BASE.checked_add(section.address()).and_then(|address| {
                let end = address.checked_add(size).filter(|&end| end <= MAX_LAYOUT_ADDRESS)?;
                Some((address, end))
            })
        } else {
            place(cursor, section.align(), size)
        };
        let Some((address, end)) = spot else {
            warnings.push(format!(
                "section {} ({size:#x} bytes, aligned to {:#x}) is not placed: the layout would pass {MAX_LAYOUT_ADDRESS:#x}",
                section.name().unwrap_or_default(),
                section.align()
            ));
            continue;
        };
        cursor = cursor.max(end);
        places.sections[section.index().0] = Some(address);
        if !matches!(machine, Machine::Elf(_)) {
            places.origins[section.index().0] = section.address();
        }
        if perms.execute {
            code_sections.insert(section.index().0);
        }
        let file_range = section.file_range();
        let (file_offset, file_size) = file_range.unwrap_or((0, 0));
        if file_size > 0 {
            placed.push((address, file_size.min(size), file_offset));
        }
        segments.push(Segment {
            name: section.name().unwrap_or_default().to_owned(),
            address,
            size,
            file_offset,
            file_size: file_size.min(size),
            perms,
        });
    }

    // Symbols the relocations name, and what the GOT must hold.
    let symbols: Vec<object::Symbol> = parsed.symbols().collect();
    let by_index: HashMap<usize, &object::Symbol> = symbols.iter().map(|symbol| (symbol.index().0, symbol)).collect();
    let relocations: Vec<(SectionIndex, u64, object::Relocation)> = parsed
        .sections()
        .filter(|section| places.section(section.index()).is_some())
        .flat_map(|section| {
            let index = section.index();
            section.relocations().map(move |(offset, relocation)| (index, offset, relocation))
        })
        .collect();
    let import_pointer = |index: usize| {
        let symbol = by_index.get(&index)?;
        let name = symbol.name().ok()?.strip_prefix(IMPORT_POINTER)?;
        (matches!(machine, Machine::Coff(_)) && symbol.section() == SymbolSection::Undefined && !name.is_empty())
            .then_some(name)
    };
    let mut called = std::collections::HashSet::new();
    let mut got_symbols = std::collections::BTreeSet::new();
    let file_offsets: HashMap<usize, u64> =
        parsed.sections().filter_map(|section| Some((section.index().0, section.file_range()?.0))).collect();
    for (section, offset, relocation) in &relocations {
        let Some((r_type, _, _)) = Machine::r_type(relocation.flags()) else { continue };
        let RelocationTarget::Symbol(index) = relocation.target() else { continue };
        // The bytes before the field, which tell an x86 call or jump from a data reference of the same type. The
        // offset is the file's to give, so it may lie anywhere.
        let before = file_offsets
            .get(&section.0)
            .and_then(|start| usize::try_from(start.checked_add(*offset)?).ok())
            .and_then(|at| file.get(at.saturating_sub(2)..at))
            .unwrap_or_default();
        if import_pointer(index.0).is_some() {
            if let Machine::Coff(coff) = machine
                && coff.calls_through(r_type, before)
            {
                called.insert(index.0);
            }
            continue;
        }
        if machine.is_call(r_type, before) {
            called.insert(index.0);
        }
        let local = by_index.get(&index.0).is_some_and(|symbol| symbol.is_local());
        if machine.uses_got(r_type) && !(local && machine.is_local_got_page(r_type)) {
            got_symbols.insert(index.0);
        }
    }

    // Common symbols, then externs, then the GOT: the segments the layout adds, after the file's own.
    let synthetic = segments.len();
    let common: Vec<&object::Symbol> =
        symbols.iter().filter(|symbol| symbol.section() == SymbolSection::Common).collect();
    if !common.is_empty()
        && let Some(start) = align_up(cursor, 16)
    {
        let mut end = start;
        for symbol in common {
            let Some((address, next)) = place(end, common_alignment(parsed, symbol), symbol.size().max(1)) else {
                warnings.push(format!(
                    "common symbol {} is not placed: the layout would pass {MAX_LAYOUT_ADDRESS:#x}",
                    symbol.name().unwrap_or_default()
                ));
                continue;
            };
            end = next;
            places.symbols.insert(symbol.index().0, address);
        }
        // LLVM may emit an empty `COMMON` section of its own; the synthetic one then takes another name.
        let taken = parsed.sections().any(|section| section.name() == Ok("COMMON"));
        segments.push(Segment {
            name: if taken { ".common" } else { "COMMON" }.to_owned(),
            address: start,
            size: end - start,
            file_offset: 0,
            file_size: 0,
            perms: Perms { read: true, write: true, execute: false },
        });
        cursor = end;
    }
    let mut externs: Vec<Extern> = Vec::new();
    let mut extern_by_name: HashMap<&str, usize> = HashMap::new();
    let extern_start = align_up(cursor, 16).unwrap_or(MAX_LAYOUT_ADDRESS);
    let mut extern_end = extern_start;
    let mut add_extern = |externs: &mut Vec<Extern>, name: &str, function: bool, weak: bool| -> Option<usize> {
        let next = extern_end.checked_add(EXTERN_SLOT).filter(|&next| next <= MAX_LAYOUT_ADDRESS)?;
        let address = extern_end;
        extern_end = next;
        externs.push(Extern { name: name.to_owned(), address, function, weak });
        Some(externs.len() - 1)
    };
    // Import pointers (`__imp_X`, by symbol index) and the extern each one holds.
    let mut import_pointers: Vec<(usize, &str)> = Vec::new();
    let mut weak_definitions = Vec::new();
    for symbol in &symbols {
        let index = symbol.index().0;
        // A COFF weak external is its default symbol when the object defines that, else an extern of its own.
        let weak_default = coff_weak_default(parsed, symbol.index());
        if let Some(default) = weak_default {
            let defined = by_index
                .get(&default.0)
                .filter(|default| matches!(default.section(), SymbolSection::Section(_) | SymbolSection::Absolute))
                .and_then(|default| places.of(default));
            if let Some(address) = defined {
                places.symbols.insert(index, address);
                if let Ok(name) = symbol.name()
                    && !name.is_empty()
                {
                    let function = symbol.kind() == object::SymbolKind::Text
                        || by_index.get(&default.0).is_some_and(|default| default.kind() == object::SymbolKind::Text);
                    weak_definitions.push((name.to_owned(), address, function));
                }
                continue;
            }
        } else if symbol.section() != SymbolSection::Undefined {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() || machine.special(name).is_some() {
            continue;
        }
        if let Some(target) = import_pointer(index) {
            import_pointers.push((index, target));
            continue;
        }
        let function = called.contains(&index) || symbol.kind() == object::SymbolKind::Text;
        if let Some(&slot) = extern_by_name.get(name) {
            places.symbols.insert(index, externs[slot].address);
            externs[slot].function |= function;
            continue;
        }
        let weak = symbol.is_weak() || weak_default.is_some();
        let Some(slot) = add_extern(&mut externs, name, function, weak) else {
            warnings.push(format!("extern {name} has no slot: the layout would pass {MAX_LAYOUT_ADDRESS:#x}"));
            continue;
        };
        extern_by_name.insert(name, slot);
        places.symbols.insert(index, externs[slot].address);
    }
    // Each import pointer holds an extern of the name it imports: a function where code calls through it.
    let mut import_targets: HashMap<usize, (u64, String)> = HashMap::new();
    for &(index, target) in &import_pointers {
        let function = called.contains(&index);
        let slot = match extern_by_name.get(target) {
            Some(&slot) => Some(slot),
            None => add_extern(&mut externs, target, function, false).inspect(|&slot| {
                extern_by_name.insert(target, slot);
            }),
        };
        let Some(slot) = slot else {
            warnings.push(format!("extern {target} has no slot: the layout would pass {MAX_LAYOUT_ADDRESS:#x}"));
            continue;
        };
        externs[slot].function |= function;
        import_targets.insert(index, (externs[slot].address, target.to_owned()));
        got_symbols.insert(index);
    }
    let symbol_value = |places: &Places, index: usize| by_index.get(&index).and_then(|symbol| places.of(symbol));

    // MIPS GOT16 against a local symbol loads a 64 KiB page from the GOT; the pages are known only once each pairs
    // with its LO16, so one entry is reserved per such relocation and handed out as they are applied.
    let local_pages = relocations
        .iter()
        .filter(|(_, _, relocation)| match (Machine::r_type(relocation.flags()), relocation.target()) {
            (Some((r_type, _, _)), RelocationTarget::Symbol(index)) => {
                machine.is_local_got_page(r_type) && by_index.get(&index.0).is_some_and(|symbol| symbol.is_local())
            }
            _ => false,
        })
        .count();
    // The synthetic GOT: one entry per symbol reached through it, and MIPS local page entries.
    let needs_got = !got_symbols.is_empty()
        || local_pages > 0
        || symbols.iter().any(|symbol| symbol.name().is_ok_and(|name| machine.special(name).is_some()));
    let entries = got_symbols.len() + local_pages;
    let got_base = align_up(extern_end, pointer.max(16))
        .filter(|&base| base.checked_add(pointer * entries.max(1) as u64).is_some_and(|end| end <= MAX_LAYOUT_ADDRESS));
    if needs_got && got_base.is_none() {
        warnings.push(format!("no GOT is laid out: it would pass {MAX_LAYOUT_ADDRESS:#x}"));
    }
    let got = got_base.filter(|_| needs_got);
    let mut got_entries: HashMap<GotKey, u64> = HashMap::new();
    let mut got_values: Vec<GotEntry> = Vec::new();
    let mut got_functions = Vec::new();
    let mut pointer_slots = Vec::new();
    if let Some(base) = got {
        let mut add_entry = |key: GotKey, value: u64, name: Option<String>| {
            let address = base + pointer * got_values.len() as u64;
            got_entries.insert(key, address);
            got_values.push((address, value, name));
            address
        };
        for &index in &got_symbols {
            if let Some((value, name)) = import_targets.get(&index) {
                let slot = add_entry(GotKey::Symbol(index), *value, Some(name.clone()));
                pointer_slots.push((index, slot));
                continue;
            }
            let value = symbol_value(&places, index).unwrap_or(0);
            let symbol = by_index.get(&index);
            let name = symbol
                .filter(|symbol| symbol.section() == SymbolSection::Undefined)
                .and_then(|symbol| symbol.name().ok())
                .map(str::to_owned);
            let slot = add_entry(GotKey::Symbol(index), value, name);
            // An entry holding a function this object defines: calls through it are calls to that function.
            if let Some(symbol) = symbol.filter(|symbol| {
                symbol.kind() == object::SymbolKind::Text && matches!(symbol.section(), SymbolSection::Section(_))
            }) && let Ok(name) = symbol.name()
            {
                let address = if matches!(arch, Arch::Arm) { value & !1 } else { value };
                got_functions.push(crate::slots::GotFunction { slot, name: name.to_owned(), address });
            }
        }
        for page in 0..local_pages {
            add_entry(GotKey::Page(page as u64), 0, None);
        }
    }
    // An import pointer's symbol is its slot.
    let mut import_pointer_names = Vec::new();
    for (index, slot) in pointer_slots {
        places.symbols.insert(index, slot);
        if let Some(name) = by_index.get(&index).and_then(|symbol| symbol.name().ok()) {
            import_pointer_names.push((name.to_owned(), slot));
        }
    }
    let got_size = (got_values.len() as u64 * pointer).max(if got.is_some() { pointer } else { 0 });

    // The loaded image: the file, the externs' stubs, then the GOT.
    let stub = extern_stub(arch, thumb, big_endian);
    let width = pointer as usize;
    let mut bytes = Vec::with_capacity(file.len() + (extern_end - extern_start + got_size) as usize + 32);
    bytes.extend_from_slice(file);
    if extern_end > extern_start {
        let offset = bytes.len().next_multiple_of(16);
        bytes.resize(offset, 0);
        for item in &externs {
            let slot = bytes.len();
            if item.function {
                bytes.extend_from_slice(&stub);
            }
            bytes.resize(slot + EXTERN_SLOT as usize, 0);
        }
        let size = extern_end - extern_start;
        placed.push((extern_start, size, offset as u64));
        segments.push(Segment {
            name: "extern".to_owned(),
            address: extern_start,
            size,
            file_offset: offset as u64,
            file_size: size,
            // Writable, so an extern variable's slot never folds to its fill; executable for the stubs alone (the
            // segment is no code section, so discovery never runs into it).
            perms: Perms { read: true, write: true, execute: true },
        });
    }
    let got_offset = bytes.len().next_multiple_of(width.max(1));
    bytes.resize(got_offset, 0);
    if let Some(got) = got {
        for (_, value, _) in &got_values {
            let encoded = value.to_le_bytes();
            if big_endian {
                bytes.extend(encoded[..width].iter().rev());
            } else {
                bytes.extend_from_slice(&encoded[..width]);
            }
        }
        bytes.resize(got_offset + got_size as usize, 0);
        placed.push((got, got_size, got_offset as u64));
        segments.push(Segment {
            name: machine.got_name().to_owned(),
            address: got,
            size: got_size,
            file_offset: got_offset as u64,
            file_size: got_size,
            perms: Perms { read: true, write: false, execute: false },
        });
    }
    placed.sort_unstable();
    let gp = match got {
        Some(got) if machine.is_mips() => got + 0x7ff0,
        Some(got) => got,
        None => 0,
    };

    let mut image = Image {
        bytes: &mut bytes,
        big_endian,
        placed: &placed,
        got: got.unwrap_or(0),
        got_entries: &got_entries,
        gp,
        pointer: width,
        delta,
        touched: None,
        last_page: None,
    };
    let mut sites = Vec::new();
    let mut sites_total = 0;
    let mut unsupported: BTreeMap<u32, (usize, u64)> = BTreeMap::new();
    let mut unapplied = Vec::new();
    let mut unapplied_widths = Vec::new();
    let mut out_of_range = 0usize;
    let section_info = |index: SectionIndex| -> SymbolInfo {
        let base = places.section(index).unwrap_or(0);
        SymbolInfo {
            value: base,
            defined: true,
            local: true,
            section_number: u16::try_from(index.0).unwrap_or(0),
            section_base: base,
            in_code: code_sections.contains(&index.0),
            ..SymbolInfo::NONE
        }
    };
    let info = |index: Option<SymbolIndex>, place: u64| -> SymbolInfo {
        let Some(index) = index else { return SymbolInfo::NONE };
        let symbol = by_index.get(&index.0);
        let special = symbol.and_then(|symbol| machine.special(symbol.name().ok()?));
        let value = match special {
            Some(elf::Special::GotBase) => got.unwrap_or(0),
            Some(elf::Special::GlobalPointer) => gp,
            Some(elf::Special::GpDisp) => gp.wrapping_sub(place),
            None => symbol_value(&places, index.0).unwrap_or(0),
        };
        let section = symbol.and_then(|symbol| symbol.section_index());
        SymbolInfo {
            value,
            defined: symbol.is_some_and(|symbol| symbol.section() != SymbolSection::Undefined),
            local: symbol.is_some_and(|symbol| symbol.is_local()),
            function: symbol.is_some_and(|symbol| symbol.kind() == object::SymbolKind::Text),
            size: symbol.map_or(0, |symbol| symbol.size()),
            gp_disp: special == Some(elf::Special::GpDisp),
            section_number: section.and_then(|section| u16::try_from(section.0).ok()).unwrap_or(0),
            section_base: section.and_then(|section| places.section(section)).unwrap_or(0),
            in_code: section.is_some_and(|section| code_sections.contains(&section.0)),
        }
    };
    let named = |symbol: &object::Symbol| match symbol.section() {
        SymbolSection::Section(section) if symbol.kind() == object::SymbolKind::Section => {
            parsed.section_by_index(section).ok()?.name().ok().map(str::to_owned)
        }
        _ => symbol.name().ok().filter(|name| !name.is_empty()).map(str::to_owned),
    };
    let mut state = elf::State::default();
    for (section, offset, relocation) in &relocations {
        let Some((r_type, pcrel, length)) = Machine::r_type(relocation.flags()) else { continue };
        let Some(base) = places.section(*section) else { continue };
        let Some(place) = base.checked_add(*offset) else {
            out_of_range += 1;
            continue;
        };
        let (symbol, symbol_index, external) = match relocation.target() {
            RelocationTarget::Symbol(index) => (info(Some(index), place), Some(index.0), true),
            RelocationTarget::Section(index) => (section_info(index), None, false),
            _ => (SymbolInfo::NONE, None, false),
        };
        let reloc = Reloc {
            r_type,
            place,
            symbol,
            symbol_index,
            addend: (!relocation.has_implicit_addend()).then(|| relocation.addend()),
            pcrel,
            length,
            external,
            subtractor: relocation.subtractor().map(|index| info(Some(index), place)),
        };
        image.touched = Some((place, place));
        let applied = machine.apply(&mut image, &reloc, &mut state);
        let field = image.touched.take().map_or(0, |(start, end)| end.saturating_sub(start));
        match applied {
            Ok(Some((addend, target))) => {
                sites_total += 1;
                if sites.len() < MAX_RELOCATION_SITES {
                    let symbol = match relocation.target() {
                        RelocationTarget::Symbol(index) => by_index.get(&index.0).and_then(|symbol| named(symbol)),
                        RelocationTarget::Section(index) => parsed
                            .section_by_index(index)
                            .ok()
                            .and_then(|section| section.name().ok().map(str::to_owned)),
                        _ => None,
                    };
                    sites.push(RelocationSite {
                        address: place,
                        kind: machine.type_name(r_type),
                        symbol,
                        addend,
                        value: target,
                        field: u8::try_from(field).unwrap_or(u8::MAX),
                    });
                }
            }
            Ok(None) => {}
            Err(Refused::Unsupported) => {
                let entry = unsupported.entry(r_type).or_insert((0, place));
                entry.0 += 1;
                if unapplied.len() < MAX_UNAPPLIED_SITES {
                    unapplied.push(place);
                    unapplied_widths.push((place, u8::try_from(length).ok().filter(|&width| width > 0).unwrap_or(4)));
                }
            }
            Err(Refused::OutOfRange) => out_of_range += 1,
        }
    }
    if let Machine::Elf(elf) = &machine {
        elf::finish(&mut image, &mut state, elf);
    }
    sites.sort_by_key(|site| site.address);
    unapplied.sort_unstable();
    unapplied_widths.sort_unstable();
    let unsupported: Vec<UnsupportedRelocation> = unsupported
        .into_iter()
        .map(|(r_type, (count, first))| UnsupportedRelocation { kind: machine.type_name(r_type), count, first })
        .collect();
    for item in &unsupported {
        warnings.push(format!(
            "{} relocations are not applied ({} site{}, first at {:#x}): those fields hold the file's bytes",
            item.kind,
            item.count,
            if item.count == 1 { "" } else { "s" },
            item.first
        ));
    }
    if out_of_range > 0 {
        warnings.push(format!("{out_of_range} relocations patch a field outside their section and were skipped"));
    }
    if sites_total > sites.len() {
        warnings.push(format!("{} relocation sites applied; the first {} are listed", sites_total, sites.len()));
    }
    let directives = if matches!(machine, Machine::Coff(_)) { coff_directives(parsed) } else { Vec::new() };
    Some(Relocated {
        bytes,
        segments,
        synthetic,
        places,
        externs,
        got: got.map(|got| (got, got_values)),
        got_functions,
        sites,
        sites_total,
        unsupported,
        unapplied,
        unapplied_widths,
        warnings,
        directives,
        comdats: parsed.comdats().count(),
        import_pointers: import_pointer_names,
        weak_definitions,
    })
}

/// A common symbol's alignment: ELF stores it as the symbol's value.
fn common_alignment(parsed: &object::File, symbol: &object::Symbol) -> u64 {
    let object::SymbolFlags::Elf { .. } = symbol.flags() else { return 16 };
    let index = symbol.index();
    match parsed {
        object::File::Elf32(file) => file
            .elf_symbol_table()
            .symbol(index)
            .map(|raw| u64::from(object::read::elf::Sym::st_value(raw, file.endian())))
            .unwrap_or(16),
        object::File::Elf64(file) => file
            .elf_symbol_table()
            .symbol(index)
            .map(|raw| object::read::elf::Sym::st_value(raw, file.endian()))
            .unwrap_or(16),
        _ => 16,
    }
}
