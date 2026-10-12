//! Import slots: the pointer-sized locations the dynamic loader fills with an imported symbol's address (GOT
//! entries, Mach-O lazy and non-lazy pointers, the PE import address table). Code reaches an import by loading
//! or jumping through its slot, so slots are how stubs and indirect calls are tied to import names.

use object::read::macho::LoadCommandVariant;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{
    LittleEndian as LE, Object, ObjectSegment, ObjectSymbol, ObjectSymbolTable, ReadRef, RelocationTarget, macho,
};

use crate::model::ImportSlot;

/// Collects the import slots of `parsed`. `image` is the file data of this (possibly fat-sliced) image.
/// Unreadable tables add a warning rather than failing the load.
pub(crate) fn collect(parsed: &object::File, image: &[u8], warnings: &mut Vec<String>) -> Vec<ImportSlot> {
    let result = match parsed {
        object::File::Elf32(_) | object::File::Elf64(_) => Ok(elf(parsed)),
        object::File::MachO32(_) | object::File::MachO64(_) => macho(parsed, image),
        object::File::Pe32(file) => pe_iat(file).map_err(|error| error.to_string()),
        object::File::Pe64(file) => pe_iat(file).map_err(|error| error.to_string()),
        _ => Ok(Vec::new()),
    };
    let mut slots = result.unwrap_or_else(|error| {
        warnings.push(format!("import slots unreadable: {error}"));
        Vec::new()
    });
    slots.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
    slots.dedup_by_key(|slot| slot.address);
    slots
}

fn elf(parsed: &object::File) -> Vec<ImportSlot> {
    let Some(symbols) = parsed.dynamic_symbol_table() else { return Vec::new() };
    // Imports are undefined symbols; COPY relocations name data objects the executable defines itself.
    let slot = |address: u64, index: object::SymbolIndex| {
        let symbol = symbols.symbol_by_index(index).ok()?;
        if !symbol.is_undefined() && symbol.kind() != object::SymbolKind::Text {
            return None;
        }
        let name = symbol.name().ok()?;
        (!name.is_empty()).then(|| ImportSlot { address, name: name.to_owned(), library: None })
    };
    let mut slots: Vec<ImportSlot> = parsed
        .dynamic_relocations()
        .into_iter()
        .flatten()
        .filter_map(|(address, relocation)| match relocation.target() {
            RelocationTarget::Symbol(index) => slot(address, index),
            _ => None,
        })
        .collect();
    // Every dynamic symbol from DT_MIPS_GOTSYM on has a global GOT entry, the ones a library defines and exports
    // as well as its imports; only the undefined ones are imports.
    let undefined = |index| symbols.symbol_by_index(index).is_ok_and(|symbol| symbol.is_undefined());
    let imported = mips_global_got(parsed).into_iter().filter(|&(_, index)| undefined(index));
    slots.extend(imported.filter_map(|(address, index)| slot(address, index)));
    slots
}

/// MIPS GOT entries for dynamic symbols, which take no relocations: after `DT_MIPS_LOCAL_GOTNO` local entries,
/// the GOT holds one entry per dynamic symbol from `DT_MIPS_GOTSYM` on. Returns each entry's address and symbol.
fn mips_global_got(parsed: &object::File) -> Vec<(u64, object::SymbolIndex)> {
    use crate::details::{DT_MIPS_GOTSYM, DT_MIPS_LOCAL_GOTNO, DT_PLTGOT, dynamic};
    let entries = match parsed {
        object::File::Elf32(file) if parsed.architecture() == object::Architecture::Mips => dynamic(file).0,
        object::File::Elf64(file) if parsed.architecture() == object::Architecture::Mips64 => dynamic(file).0,
        _ => return Vec::new(),
    };
    let value = |tag| entries.iter().find(|&&(entry_tag, _)| entry_tag == tag).map(|&(_, value)| value);
    let (Some(got), Some(local), Some(first)) = (value(DT_PLTGOT), value(DT_MIPS_LOCAL_GOTNO), value(DT_MIPS_GOTSYM))
    else {
        return Vec::new();
    };
    // The iterator skips the null symbol at index 0, so count by the highest index.
    let count =
        parsed.dynamic_symbol_table().and_then(|symbols| symbols.symbols().map(|symbol| symbol.index().0).max());
    let count = count.map_or(0, |last| last as u64 + 1);
    let size: u64 = if parsed.is_64() { 8 } else { 4 };
    (first..count)
        .filter_map(|index| {
            let entry = local.checked_add(index - first)?.checked_mul(size)?;
            Some((got.checked_add(entry)?, object::SymbolIndex(usize::try_from(index).ok()?)))
        })
        .collect()
}

/// A segment's address and size, and its file data.
struct MachoSegment<'data> {
    address: u64,
    size: u64,
    data: &'data [u8],
}

impl MachoSegment<'_> {
    /// The address of `offset` within the segment, if it lies inside.
    fn address_of(&self, offset: u64) -> Option<u64> {
        (offset < self.size).then(|| self.address.checked_add(offset)).flatten()
    }
}

fn macho(parsed: &object::File, image: &[u8]) -> Result<Vec<ImportSlot>, String> {
    let segments: Vec<MachoSegment> = parsed
        .segments()
        .map(|segment| MachoSegment {
            address: segment.address(),
            size: segment.size(),
            data: segment.data().unwrap_or_default(),
        })
        .collect();
    let text_address =
        parsed.segments().find(|segment| segment.name().ok().flatten() == Some("__TEXT")).map_or(0, |s| s.address());
    let pointer_size: u64 = if parsed.is_64() { 8 } else { 4 };
    // No valid stream binds more pointers than the segments' file data holds; a longer one is a crafted loop.
    let limit = segments.iter().map(|segment| segment.data.len() as u64 / pointer_size).sum::<u64>();
    let Some((mut commands, endian)) = crate::macho::load_commands(parsed) else { return Ok(Vec::new()) };
    let dylibs = crate::macho::dylibs(parsed);
    let library = |dylib: macho::BindDylib| -> Option<String> {
        dylib.index().and_then(|ordinal| dylibs.get((ordinal as usize).checked_sub(1)?).cloned().flatten())
    };
    let mut slots = Vec::new();
    while let Some(command) = commands.next().map_err(|error| error.to_string())? {
        match command.variant().map_err(|error| error.to_string())? {
            LoadCommandVariant::LinkeditData(linkedit) if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS => {
                chained_fixups(linkedit, endian, image, &segments, text_address, &library, &mut slots)
                    .map_err(|error| error.to_string())?;
            }
            LoadCommandVariant::DyldInfo(info) => {
                let size = pointer_size as u8;
                let streams = [info.binds(endian, image, size), info.lazy_binds(endian, image, size)];
                for binds in streams {
                    let mut binds = binds.map_err(|error| error.to_string())?;
                    let mut seen = 0u64;
                    while let Some(bind) = binds.next().map_err(|error| error.to_string())? {
                        seen += 1;
                        if seen > limit {
                            return Err(format!("bind stream yields more than the {limit} pointers its segments hold"));
                        }
                        let segment = segments.get(bind.segment_index as usize);
                        let Some(address) = segment.and_then(|segment| segment.address_of(bind.segment_offset)) else {
                            continue;
                        };
                        let name = String::from_utf8_lossy(bind.symbol).into_owned();
                        slots.push(ImportSlot { address, name, library: library(bind.dylib) });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(slots)
}

fn chained_fixups(
    linkedit: &macho::LinkeditDataCommand<object::Endianness>,
    endian: object::Endianness,
    image: &[u8],
    segments: &[MachoSegment],
    text_address: u64,
    library: &dyn Fn(macho::BindDylib) -> Option<String>,
    slots: &mut Vec<ImportSlot>,
) -> object::Result<()> {
    let fixups = linkedit.chained_fixups(endian, image)?;
    let imports = fixups
        .imports(endian)?
        .map(|import| import.map(|import| (String::from_utf8_lossy(import.name).into_owned(), library(import.dylib))))
        .collect::<object::Result<Vec<_>>>()?;
    for segment in fixups.segments(endian)? {
        let segment = segment?;
        let Some(target) = segments.get(segment.index() as usize) else { continue };
        for fixup in segment.fixups(endian, text_address, target.data) {
            let (offset, fixup) = fixup?;
            if let object::read::macho::Fixup::Bind(bind) = fixup
                && let Some((name, library)) = imports.get(bind.ordinal as usize)
                && let Some(address) = target.address_of(offset)
            {
                slots.push(ImportSlot { address, name: name.clone(), library: library.clone() });
            }
        }
    }
    Ok(())
}

fn pe_iat<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> object::Result<Vec<ImportSlot>> {
    let image_base = file.relative_address_base();
    let mut slots = Vec::new();
    pe_imports(file, |library, slot, import| {
        if let Some(address) = image_base.checked_add(slot) {
            let library = library.map(|library| String::from_utf8_lossy(library).into_owned());
            slots.push(ImportSlot { address, name: import_name(import), library });
        }
    })?;
    pe_delay_slots(file, image_base, &mut slots);
    Ok(slots)
}

/// An import's name, or `#ordinal` for one imported by ordinal only.
fn import_name(import: object::read::pe::Import) -> String {
    match import {
        object::read::pe::Import::Name(_, name) => String::from_utf8_lossy(name).into_owned(),
        object::read::pe::Import::Ordinal(ordinal) => format!("#{ordinal}"),
    }
}

/// Caps for the delay-load tables of an untrusted image: a benign binary has a handful of delay DLLs with far
/// fewer than these many functions, so these only bound a crafted or corrupt table.
const MAX_DELAY_DESCRIPTORS: usize = 4096;
const MAX_DELAY_THUNKS: u64 = 1 << 20;

/// Appends the import address table slots of the delay-load directory. Delay imports are bound lazily on first
/// use, so their slots live in a separate IAT the regular import table does not cover; code reaches a delayed
/// function through this slot just as it does a normal one. Best-effort and panic-free: a malformed descriptor
/// or thunk list stops the walk rather than failing the load, and the regular slots already collected stand.
fn pe_delay_slots<Pe: ImageNtHeaders>(file: &PeFile<Pe>, image_base: u64, slots: &mut Vec<ImportSlot>) {
    let Ok(Some(table)) = file.delay_load_import_table() else { return };
    let Ok(mut descriptors) = table.descriptors() else { return };
    let slot_size = if file.is_64() { 8 } else { 4 };
    for _ in 0..MAX_DELAY_DESCRIPTORS {
        let descriptor = match descriptors.next() {
            Ok(Some(descriptor)) => descriptor,
            // Ok(None) is the terminating null descriptor; an error is a corrupt table. Both stop the walk.
            _ => break,
        };
        // Only version-2 (RVA-based) descriptors store RVAs; the obsolete VA-based form is left unresolved,
        // matching how `object`'s own iterator declines it.
        if descriptor.attributes.get(LE) & object::pe::IMAGE_DELAYLOAD_RVA_BASED == 0 {
            continue;
        }
        let iat_rva = u64::from(descriptor.import_address_table_rva.get(LE));
        let name_table_rva = descriptor.import_name_table_rva.get(LE);
        let library = table
            .name(descriptor.dll_name_rva.get(LE))
            .ok()
            .map(|library| String::from_utf8_lossy(library).into_owned());
        let Ok(mut thunks) = table.thunks(name_table_rva) else { continue };
        let mut index = 0u64;
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            if index >= MAX_DELAY_THUNKS {
                break;
            }
            let address = index
                .checked_mul(slot_size)
                .and_then(|offset| iat_rva.checked_add(offset))
                .and_then(|rva| image_base.checked_add(rva));
            if let (Some(address), Ok(import)) = (address, table.import::<Pe>(thunk)) {
                slots.push(ImportSlot { address, name: import_name(import), library: library.clone() });
            }
            index += 1;
        }
    }
}

/// Walks the regular (not delay-load) import table, calling `visit` with each import's library name (`None` when
/// unreadable), the RVA of its import address table slot, and the import itself.
pub(crate) fn pe_imports<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
    file: &PeFile<'data, Pe, R>,
    mut visit: impl FnMut(Option<&'data [u8]>, u64, object::read::pe::Import<'data>),
) -> object::Result<()> {
    let Some(table) = file.import_table()? else { return Ok(()) };
    let slot_size = if file.is_64() { 8 } else { 4 };
    let mut descriptors = table.descriptors()?;
    while let Some(descriptor) = descriptors.next()? {
        let first_thunk = descriptor.first_thunk.get(LE);
        let lookup = match descriptor.original_first_thunk.get(LE) {
            0 => first_thunk,
            lookup => lookup,
        };
        let library = table.name(descriptor.name.get(LE)).ok();
        let mut thunks = table.thunks(lookup)?;
        let mut slot = u64::from(first_thunk);
        while let Some(thunk) = thunks.next::<Pe>()? {
            visit(library, slot, table.import::<Pe>(thunk)?);
            slot += slot_size;
        }
    }
    Ok(())
}
