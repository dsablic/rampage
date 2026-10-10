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
    let (Some(relocations), Some(symbols)) = (parsed.dynamic_relocations(), parsed.dynamic_symbol_table()) else {
        return Vec::new();
    };
    relocations
        .filter_map(|(address, relocation)| {
            let RelocationTarget::Symbol(index) = relocation.target() else { return None };
            let symbol = symbols.symbol_by_index(index).ok()?;
            if !symbol.is_undefined() && symbol.kind() != object::SymbolKind::Text {
                return None;
            }
            let name = symbol.name().ok()?;
            (!name.is_empty()).then(|| ImportSlot { address, name: name.to_owned(), library: None })
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
        let name = match import {
            object::read::pe::Import::Name(_, name) => String::from_utf8_lossy(name).into_owned(),
            object::read::pe::Import::Ordinal(ordinal) => format!("#{ordinal}"),
        };
        if let Some(address) = image_base.checked_add(slot) {
            let library = library.map(|library| String::from_utf8_lossy(library).into_owned());
            slots.push(ImportSlot { address, name, library });
        }
    })?;
    Ok(slots)
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
