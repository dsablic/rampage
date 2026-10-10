//! Import slots: the pointer-sized locations the dynamic loader fills with an imported symbol's address (GOT
//! entries, Mach-O lazy and non-lazy pointers, the PE import address table). Code reaches an import by loading
//! or jumping through its slot, so slots are how stubs and indirect calls are tied to import names.

use object::read::macho::LoadCommandVariant;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{Object, ObjectSegment, ObjectSymbol, ObjectSymbolTable, RelocationTarget, macho};

use crate::model::ImportSlot;
use crate::starts::macho_load_commands;

/// Collects the import slots of `parsed`. `image` is the file data of this (possibly fat-sliced) image.
/// Unreadable tables add a warning rather than failing the load.
pub(crate) fn collect(parsed: &object::File, image: &[u8], warnings: &mut Vec<String>) -> Vec<ImportSlot> {
    let result = match parsed {
        object::File::Elf32(_) | object::File::Elf64(_) => Ok(elf(parsed)),
        object::File::MachO32(_) | object::File::MachO64(_) => macho(parsed, image),
        object::File::Pe32(file) => pe_iat(file),
        object::File::Pe64(file) => pe_iat(file),
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
            let name = symbols.symbol_by_index(index).ok()?.name().ok()?;
            (!name.is_empty()).then(|| ImportSlot { address, name: name.to_owned() })
        })
        .collect()
}

fn macho(parsed: &object::File, image: &[u8]) -> object::Result<Vec<ImportSlot>> {
    let segments: Vec<(u64, &[u8])> =
        parsed.segments().map(|segment| (segment.address(), segment.data().unwrap_or_default())).collect();
    let text_address =
        parsed.segments().find(|segment| segment.name().ok().flatten() == Some("__TEXT")).map_or(0, |s| s.address());
    let Some((mut commands, endian)) = macho_load_commands(parsed) else { return Ok(Vec::new()) };
    let mut slots = Vec::new();
    while let Some(command) = commands.next()? {
        match command.variant()? {
            LoadCommandVariant::LinkeditData(linkedit) if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS => {
                let fixups = linkedit.chained_fixups(endian, image)?;
                let names = fixups
                    .imports(endian)?
                    .map(|import| import.map(|import| String::from_utf8_lossy(import.name).into_owned()))
                    .collect::<object::Result<Vec<_>>>()?;
                for segment in fixups.segments(endian)? {
                    let segment = segment?;
                    let Some(&(address, data)) = segments.get(segment.index() as usize) else { continue };
                    for fixup in segment.fixups(endian, text_address, data) {
                        let (offset, fixup) = fixup?;
                        if let object::read::macho::Fixup::Bind(bind) = fixup
                            && let Some(name) = names.get(bind.ordinal as usize)
                        {
                            slots.push(ImportSlot { address: address + offset, name: name.clone() });
                        }
                    }
                }
            }
            LoadCommandVariant::DyldInfo(info) => {
                let pointer_size = if parsed.is_64() { 8 } else { 4 };
                for binds in [info.binds(endian, image, pointer_size)?, info.lazy_binds(endian, image, pointer_size)?] {
                    let mut binds = binds;
                    while let Some(bind) = binds.next()? {
                        let Some(&(address, _)) = segments.get(bind.segment_index as usize) else { continue };
                        let name = String::from_utf8_lossy(bind.symbol).into_owned();
                        slots.push(ImportSlot { address: address + bind.segment_offset, name });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(slots)
}

fn pe_iat<Pe: ImageNtHeaders>(file: &PeFile<Pe>) -> object::Result<Vec<ImportSlot>> {
    let Some(table) = file.import_table()? else { return Ok(Vec::new()) };
    let image_base = file.relative_address_base();
    let slot_size = if file.is_64() { 8 } else { 4 };
    let mut slots = Vec::new();
    let mut descriptors = table.descriptors()?;
    while let Some(descriptor) = descriptors.next()? {
        let first_thunk = descriptor.first_thunk.get(object::LittleEndian);
        let lookup = match descriptor.original_first_thunk.get(object::LittleEndian) {
            0 => first_thunk,
            lookup => lookup,
        };
        let mut thunks = table.thunks(lookup)?;
        let mut index = 0u64;
        while let Some(thunk) = thunks.next::<Pe>()? {
            let name = match table.import::<Pe>(thunk)? {
                object::read::pe::Import::Name(_, name) => String::from_utf8_lossy(name).into_owned(),
                object::read::pe::Import::Ordinal(ordinal) => format!("#{ordinal}"),
            };
            let address = image_base + u64::from(first_thunk) + index * slot_size;
            slots.push(ImportSlot { address, name });
            index += 1;
        }
    }
    Ok(slots)
}
