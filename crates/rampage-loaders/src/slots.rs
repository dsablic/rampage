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
            let name = symbols.symbol_by_index(index).ok()?.name().ok()?;
            (!name.is_empty()).then(|| ImportSlot { address, name: name.to_owned() })
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
    // No valid stream binds more pointers than the segments hold; a longer one is a crafted loop.
    let limit = segments.iter().map(|segment| segment.size / pointer_size).fold(0u64, u64::saturating_add);
    let Some((mut commands, endian)) = macho_load_commands(parsed) else { return Ok(Vec::new()) };
    let mut slots = Vec::new();
    while let Some(command) = commands.next().map_err(|error| error.to_string())? {
        match command.variant().map_err(|error| error.to_string())? {
            LoadCommandVariant::LinkeditData(linkedit) if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS => {
                chained_fixups(linkedit, endian, image, &segments, text_address, &mut slots)
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
                        slots.push(ImportSlot { address, name: String::from_utf8_lossy(bind.symbol).into_owned() });
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
    slots: &mut Vec<ImportSlot>,
) -> object::Result<()> {
    let fixups = linkedit.chained_fixups(endian, image)?;
    let names = fixups
        .imports(endian)?
        .map(|import| import.map(|import| String::from_utf8_lossy(import.name).into_owned()))
        .collect::<object::Result<Vec<_>>>()?;
    for segment in fixups.segments(endian)? {
        let segment = segment?;
        let Some(target) = segments.get(segment.index() as usize) else { continue };
        for fixup in segment.fixups(endian, text_address, target.data) {
            let (offset, fixup) = fixup?;
            if let object::read::macho::Fixup::Bind(bind) = fixup
                && let Some(name) = names.get(bind.ordinal as usize)
                && let Some(address) = target.address_of(offset)
            {
                slots.push(ImportSlot { address, name: name.clone() });
            }
        }
    }
    Ok(())
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
            let address = image_base
                .checked_add(u64::from(first_thunk))
                .and_then(|address| address.checked_add(index * slot_size));
            if let Some(address) = address {
                slots.push(ImportSlot { address, name });
            }
            index += 1;
        }
    }
    Ok(slots)
}
