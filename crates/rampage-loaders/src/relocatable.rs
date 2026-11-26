//! Relocatable objects, loaded the way a linker would place them on their own, as IDA does: the allocated sections
//! laid out at synthetic, non-overlapping addresses from [`OBJECT_BASE`], each aligned as it asks; common symbols in
//! a zero-filled `COMMON` segment; an `extern` segment with one slot per undefined symbol, so calls and references to
//! it reach a named target; a synthetic `.got` holding one entry per symbol the code reaches through a GOT; and the
//! relocations applied into a loaded copy of the file, each site kept with its type, symbol and addend.
//!
//! The layout reads sections, symbols and relocations through `object`'s format-independent interface; only how a
//! relocation type is computed and encoded is format-specific ([`elf`]). COFF and Mach-O `MH_OBJECT` plug in by
//! adding their relocation types beside it.

mod elf;

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
    /// `S + A`, the symbol's address plus the addend (so `printf - 4` for an x86 call's PC-relative field), or the
    /// GOT entry's address for a reference through the GOT.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub value: u64,
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

/// What a relocatable object's layout gives the loader.
#[derive(Debug)]
pub struct Relocated {
    /// The loaded image: the file's bytes with every applied relocation written in, followed by the synthetic GOT.
    pub(crate) bytes: Vec<u8>,
    pub(crate) segments: Vec<Segment>,
    /// Where the segments the layout adds (common symbols, externs, the GOT) start in `segments`.
    synthetic: usize,
    /// Each section's address by section index; `None` for one that is not allocated.
    section_addresses: Vec<Option<u64>>,
    pub externs: Vec<Extern>,
    /// Common symbols' addresses by symbol index.
    commons: HashMap<usize, u64>,
    /// The synthetic GOT: its address and each entry's (address, value, extern name if the value is an extern).
    pub(crate) got: Option<(u64, Vec<(u64, u64, Option<String>)>)>,
    /// The GOT entries holding a function the object defines.
    pub(crate) got_functions: Vec<crate::slots::GotFunction>,
    pub sites: Vec<RelocationSite>,
    pub sites_total: usize,
    pub unsupported: Vec<UnsupportedRelocation>,
    pub warnings: Vec<String>,
}

impl Relocated {
    /// The address of a symbol of the object, with any Thumb bit its value carries; `None` for one in a section
    /// that is not allocated.
    pub(crate) fn symbol_address(&self, symbol: &object::Symbol) -> Option<u64> {
        match symbol.section() {
            SymbolSection::Section(index) => {
                let base = self.section_address(index)?;
                Some(base.wrapping_add(raw_value(symbol)))
            }
            SymbolSection::Common => self.commons.get(&symbol.index().0).copied(),
            SymbolSection::Undefined => {
                let name = symbol.name().ok()?;
                self.externs.iter().find(|item| item.name == name).map(|item| item.address)
            }
            SymbolSection::Absolute => Some(raw_value(symbol)),
            _ => None,
        }
    }

    pub(crate) fn section_address(&self, index: SectionIndex) -> Option<u64> {
        self.section_addresses.get(index.0).copied().flatten()
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

/// A symbol's stored value. `object` reports a common symbol's value (its alignment) as 0, which is wanted here
/// only for commons, so the value is read as the file stores it.
fn raw_value(symbol: &object::Symbol) -> u64 {
    symbol.address()
}

fn align_up(value: u64, align: u64) -> u64 {
    let align = align.max(1);
    if !align.is_power_of_two() {
        return value.div_ceil(align).saturating_mul(align);
    }
    value.saturating_add(align - 1) & !(align - 1)
}

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
}

/// A relocation as the per-format code applies it.
pub(crate) struct Reloc {
    pub r_type: u32,
    /// The field's address.
    pub place: u64,
    pub symbol: SymbolInfo,
    pub symbol_index: Option<usize>,
    /// The explicit addend (RELA), or `None` when the addend is stored in the field (REL).
    pub addend: Option<i64>,
}

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

/// Lays out `parsed`, a relocatable object, and applies its relocations into a copy of `file`. `None` when the
/// format has no relocation support yet (only ELF does).
pub(crate) fn load(parsed: &object::File, file: &[u8], arch: Arch, big_endian: bool) -> Option<Relocated> {
    if parsed.format() != object::BinaryFormat::Elf || parsed.kind() != object::ObjectKind::Relocatable {
        return None;
    }
    let pointer = u64::from(arch.default_pointer_size().unwrap_or(if parsed.is_64() { 8 } else { 4 }));
    let machine = elf::Machine::of(arch, parsed.is_64())?;
    let mut warnings = Vec::new();

    // Allocated sections, in file order.
    let section_count = parsed.sections().map(|section| section.index().0 + 1).max().unwrap_or(0);
    let mut section_addresses = vec![None; section_count];
    let mut segments = Vec::new();
    let mut placed = Vec::new();
    let mut cursor = OBJECT_BASE;
    for section in parsed.sections() {
        let object::SectionFlags::Elf { sh_flags, .. } = section.flags() else { continue };
        if !sh_flags.contains(object::elf::SHF_ALLOC) || section.size() == 0 {
            continue;
        }
        let address = align_up(cursor, section.align());
        let size = section.size();
        cursor = address.saturating_add(size);
        section_addresses[section.index().0] = Some(address);
        let file_range = section.file_range();
        let (file_offset, file_size) = file_range.map_or((0, 0), |(offset, size)| (offset, size));
        if file_size > 0 {
            placed.push((address, file_size.min(size), file_offset));
        }
        segments.push(Segment {
            name: section.name().unwrap_or_default().to_owned(),
            address,
            size,
            file_offset,
            file_size: file_size.min(size),
            perms: Perms {
                read: true,
                write: sh_flags.contains(object::elf::SHF_WRITE),
                execute: sh_flags.contains(object::elf::SHF_EXECINSTR),
            },
        });
    }

    // Symbols the relocations name, and what the GOT must hold.
    let symbols: Vec<object::Symbol> = parsed.symbols().collect();
    let by_index: HashMap<usize, &object::Symbol> = symbols.iter().map(|symbol| (symbol.index().0, symbol)).collect();
    let relocations: Vec<(SectionIndex, u64, object::Relocation)> = parsed
        .sections()
        .filter(|section| section_addresses.get(section.index().0).copied().flatten().is_some())
        .flat_map(|section| {
            let index = section.index();
            section.relocations().map(move |(offset, relocation)| (index, offset, relocation))
        })
        .collect();
    let mut called = std::collections::HashSet::new();
    let mut got_symbols = std::collections::BTreeSet::new();
    let file_offsets: HashMap<usize, u64> =
        parsed.sections().filter_map(|section| Some((section.index().0, section.file_range()?.0))).collect();
    for (section, offset, relocation) in &relocations {
        let object::RelocationFlags::Elf { r_type } = relocation.flags() else { continue };
        let RelocationTarget::Symbol(index) = relocation.target() else { continue };
        // The bytes before the field, which tell an x86 call or jump from a data reference of the same type.
        let before = file_offsets
            .get(&section.0)
            .and_then(|start| usize::try_from(start.checked_add(*offset)?).ok())
            .map_or(&[][..], |at| &file[at.saturating_sub(2)..at.min(file.len())]);
        if machine.is_call(r_type.0, before) {
            called.insert(index.0);
        }
        let local = by_index.get(&index.0).is_some_and(|symbol| symbol.is_local());
        if machine.uses_got(r_type.0) && !(local && machine.is_local_got_page(r_type.0)) {
            got_symbols.insert(index.0);
        }
    }

    // Common symbols, then externs, then the GOT: the segments the layout adds, after the file's own.
    let synthetic = segments.len();
    let mut commons = HashMap::new();
    let common: Vec<&object::Symbol> =
        symbols.iter().filter(|symbol| symbol.section() == SymbolSection::Common).collect();
    if !common.is_empty() {
        let start = align_up(cursor, 16);
        let mut end = start;
        for symbol in common {
            let align = common_alignment(parsed, symbol).max(1);
            let address = align_up(end, align);
            end = address.saturating_add(symbol.size().max(1));
            commons.insert(symbol.index().0, address);
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
    let mut extern_by_name: HashMap<String, u64> = HashMap::new();
    let extern_start = align_up(cursor, 16);
    let mut extern_end = extern_start;
    for symbol in &symbols {
        if symbol.section() != SymbolSection::Undefined {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() || machine.special(name).is_some() || extern_by_name.contains_key(name) {
            continue;
        }
        let address = extern_end;
        extern_end += pointer;
        extern_by_name.insert(name.to_owned(), address);
        externs.push(Extern {
            name: name.to_owned(),
            address,
            function: called.contains(&symbol.index().0) || symbol.kind() == object::SymbolKind::Text,
            weak: symbol.is_weak(),
        });
    }
    if extern_end > extern_start {
        segments.push(Segment {
            name: "extern".to_owned(),
            address: extern_start,
            size: extern_end - extern_start,
            file_offset: 0,
            file_size: 0,
            // Writable: an extern variable's value is unknown here, so a read of it must never fold to the fill.
            perms: Perms { read: true, write: true, execute: false },
        });
        cursor = extern_end;
    }

    let symbol_value = |index: usize| -> Option<u64> {
        let symbol = by_index.get(&index)?;
        match symbol.section() {
            SymbolSection::Section(section) => {
                Some(section_addresses.get(section.0).copied().flatten()?.wrapping_add(raw_value(symbol)))
            }
            SymbolSection::Common => commons.get(&index).copied(),
            SymbolSection::Undefined => extern_by_name.get(symbol.name().ok()?).copied(),
            SymbolSection::Absolute => Some(raw_value(symbol)),
            _ => None,
        }
    };

    // MIPS GOT16 against a local symbol loads a 64 KiB page from the GOT; the pages are known only once each pairs
    // with its LO16, so one entry is reserved per such relocation and handed out as they are applied.
    let local_pages = relocations
        .iter()
        .filter(|(_, _, relocation)| match (relocation.flags(), relocation.target()) {
            (object::RelocationFlags::Elf { r_type }, RelocationTarget::Symbol(index)) => {
                machine.is_local_got_page(r_type.0) && by_index.get(&index.0).is_some_and(|symbol| symbol.is_local())
            }
            _ => false,
        })
        .count();
    // The synthetic GOT: one entry per symbol reached through it, and MIPS local page entries.
    let needs_got = !got_symbols.is_empty()
        || local_pages > 0
        || symbols.iter().any(|symbol| symbol.name().is_ok_and(|name| machine.special(name).is_some()));
    let got_base = align_up(cursor, pointer.max(16));
    let mut got_entries: HashMap<GotKey, u64> = HashMap::new();
    let mut got_values: Vec<(u64, u64, Option<String>)> = Vec::new();
    let mut add_entry = |key: GotKey, value: u64, name: Option<String>| {
        if let Some(&address) = got_entries.get(&key) {
            return address;
        }
        let address = got_base + pointer * got_values.len() as u64;
        got_entries.insert(key, address);
        got_values.push((address, value, name));
        address
    };
    let mut got_functions = Vec::new();
    for &index in &got_symbols {
        let value = symbol_value(index).unwrap_or(0);
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
    let got = needs_got.then_some(got_base);
    let got_size = (got_values.len() as u64 * pointer).max(if needs_got { pointer } else { 0 });

    // The loaded image: the file, then the GOT.
    let mut bytes = Vec::with_capacity(file.len() + got_size as usize + 16);
    bytes.extend_from_slice(file);
    let got_offset = align_up(bytes.len() as u64, pointer) as usize;
    bytes.resize(got_offset, 0);
    if let Some(got) = got {
        for (_, value, _) in &got_values {
            let encoded = value.to_le_bytes();
            let width = pointer as usize;
            if big_endian {
                bytes.extend(encoded[..width].iter().rev());
            } else {
                bytes.extend_from_slice(&encoded[..width]);
            }
        }
        bytes.resize(got_offset + got_size as usize, 0);
        placed.push((got, got_size, got_offset as u64));
        segments.push(Segment {
            name: ".got".to_owned(),
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
        pointer: pointer as usize,
    };
    let mut sites = Vec::new();
    let mut sites_total = 0;
    let mut unsupported: BTreeMap<u32, (usize, u64)> = BTreeMap::new();
    let mut out_of_range = 0usize;
    let info = |index: Option<SymbolIndex>, place: u64| -> SymbolInfo {
        let Some(index) = index else {
            return SymbolInfo { value: 0, defined: false, local: true, function: false, size: 0, gp_disp: false };
        };
        let symbol = by_index.get(&index.0);
        let special = symbol.and_then(|symbol| machine.special(symbol.name().ok()?));
        let value = match special {
            Some(elf::Special::GotBase) => got.unwrap_or(0),
            Some(elf::Special::GlobalPointer) => gp,
            Some(elf::Special::GpDisp) => gp.wrapping_sub(place),
            None => symbol_value(index.0).unwrap_or(0),
        };
        SymbolInfo {
            value,
            defined: symbol.is_some_and(|symbol| symbol.section() != SymbolSection::Undefined),
            local: symbol.is_some_and(|symbol| symbol.is_local()),
            function: symbol.is_some_and(|symbol| symbol.kind() == object::SymbolKind::Text),
            size: symbol.map_or(0, |symbol| symbol.size()),
            gp_disp: special == Some(elf::Special::GpDisp),
        }
    };
    let mut state = elf::State::default();
    for (section, offset, relocation) in &relocations {
        let object::RelocationFlags::Elf { r_type } = relocation.flags() else { continue };
        let Some(base) = section_addresses[section.0] else { continue };
        let place = base.wrapping_add(*offset);
        let symbol_index = match relocation.target() {
            RelocationTarget::Symbol(index) => Some(index),
            _ => None,
        };
        let reloc = Reloc {
            r_type: r_type.0,
            place,
            symbol: info(symbol_index, place),
            symbol_index: symbol_index.map(|index| index.0),
            addend: (!relocation.has_implicit_addend()).then(|| relocation.addend()),
        };
        match machine.apply(&mut image, &reloc, &mut state) {
            Ok(Some((addend, target))) => {
                sites_total += 1;
                if sites.len() < MAX_RELOCATION_SITES {
                    let symbol = symbol_index.and_then(|index| by_index.get(&index.0)).and_then(|symbol| match symbol
                        .section()
                    {
                        SymbolSection::Section(section) if symbol.kind() == object::SymbolKind::Section => {
                            parsed.section_by_index(section).ok()?.name().ok().map(str::to_owned)
                        }
                        _ => symbol.name().ok().filter(|name| !name.is_empty()).map(str::to_owned),
                    });
                    sites.push(RelocationSite {
                        address: place,
                        kind: machine.type_name(r_type),
                        symbol,
                        addend,
                        value: target,
                    });
                }
            }
            Ok(None) => {}
            Err(Refused::Unsupported) => {
                let entry = unsupported.entry(r_type.0).or_insert((0, place));
                entry.0 += 1;
            }
            Err(Refused::OutOfRange) => out_of_range += 1,
        }
    }
    elf::finish(&mut image, &mut state, &machine);
    sites.sort_by_key(|site| site.address);
    let unsupported: Vec<UnsupportedRelocation> = unsupported
        .into_iter()
        .map(|(r_type, (count, first))| UnsupportedRelocation {
            kind: machine.type_name(object::elf::RelocationType(r_type)),
            count,
            first,
        })
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
    Some(Relocated {
        bytes,
        segments,
        synthetic,
        section_addresses,
        externs,
        commons,
        got: got.map(|got| (got, got_values)),
        got_functions,
        sites,
        sites_total,
        unsupported,
        warnings,
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
