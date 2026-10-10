use std::fs::File;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags};
use rampage_arch::Arch;
use serde::Serialize;

use crate::model::{Export, Format, Import, Perms, Section, SectionKind, Segment, Symbol, SymbolKind};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("cannot parse binary: {0}")]
    Parse(#[from] object::Error),
    #[error("unsupported {0}")]
    Unsupported(String),
}

#[derive(Debug, Serialize)]
pub struct Binary {
    pub format: Format,
    pub arch: Arch,
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    #[serde(skip)]
    data: Mmap,
}

impl Binary {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let io_error = |source| LoadError::Io { path: path.to_owned(), source };
        let file = File::open(path).map_err(io_error)?;
        // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope,
        // the same assumption every mmap-based binary tool makes.
        let data = unsafe { Mmap::map(&file) }.map_err(io_error)?;
        let parsed = object::File::parse(&*data)?;

        let format = match parsed.format() {
            object::BinaryFormat::Elf => Format::Elf,
            object::BinaryFormat::Pe => Format::Pe,
            object::BinaryFormat::MachO => Format::MachO,
            other => return Err(LoadError::Unsupported(format!("format {other:?}"))),
        };
        let arch = match parsed.architecture() {
            object::Architecture::I386 => Arch::X86,
            object::Architecture::X86_64 => Arch::X86_64,
            object::Architecture::Aarch64 => Arch::Aarch64,
            other => return Err(LoadError::Unsupported(format!("architecture {other:?}"))),
        };

        let segments: Vec<Segment> = parsed
            .segments()
            .enumerate()
            .map(|(index, segment)| {
                let (file_offset, file_size) = segment.file_range();
                Segment {
                    name: segment.name().ok().flatten().map_or_else(|| format!("seg{index}"), str::to_owned),
                    address: segment.address(),
                    size: segment.size(),
                    file_offset,
                    file_size: file_size.min(segment.size()),
                    perms: perms_of(segment.flags()),
                }
            })
            .collect();

        let sections = parsed
            .sections()
            .map(|section| Section {
                name: section.name().unwrap_or_default().to_owned(),
                address: section.address(),
                size: section.size(),
                kind: section_kind_of(section.kind()),
            })
            .collect();

        let mut symbols: Vec<Symbol> = parsed
            .symbols()
            .chain(parsed.dynamic_symbols())
            .filter(|symbol| symbol.is_definition())
            .filter_map(|symbol| {
                let name = symbol.name().ok().filter(|name| !name.is_empty())?;
                Some(Symbol {
                    name: name.to_owned(),
                    address: symbol.address(),
                    size: symbol.size(),
                    kind: symbol_kind_of(symbol.kind()),
                })
            })
            .collect();
        symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        symbols.dedup();

        let imports = parsed
            .imports()?
            .map(|import| {
                let import = import?;
                let library = String::from_utf8_lossy(import.library()).into_owned();
                Ok(Import {
                    library: Some(library).filter(|library| !library.is_empty()),
                    name: name_of(import.name()),
                })
            })
            .collect::<Result<_, object::Error>>()?;

        let mut exports = Vec::new();
        for export in parsed.exports()? {
            let export = export?;
            if let object::ExportTarget::Address { address } = export.target() {
                exports.push(Export { name: name_of(export.name()), address });
            }
        }

        let entry = match macho_main_entry_offset(&parsed) {
            Some(offset) => file_offset_to_address(&segments, offset).unwrap_or(offset),
            None => parsed.entry(),
        };
        drop(parsed);
        Ok(Self { format, arch, entry, segments, sections, symbols, imports, exports, data })
    }

    pub fn segment_containing(&self, address: u64) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.contains(address))
    }

    pub fn symbol_by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }

    /// Returns `len` file-backed bytes at `address`, or `None` when any part of the range is unmapped or
    /// lies in a segment's zero-fill tail.
    pub fn read(&self, address: u64, len: u64) -> Option<&[u8]> {
        let segment = self.segment_containing(address)?;
        let offset = address - segment.address;
        if offset.checked_add(len)? > segment.file_size {
            return None;
        }
        let start = usize::try_from(segment.file_offset.checked_add(offset)?).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.data.get(start..end)
    }

    /// Returns the file-backed bytes from `address` to the end of its segment's file data.
    pub fn read_to_segment_end(&self, address: u64) -> Option<&[u8]> {
        let segment = self.segment_containing(address)?;
        let available = segment.file_size.checked_sub(address - segment.address)?;
        self.read(address, available)
    }
}

/// `LC_MAIN` stores the entry point as a file offset, which `object` passes through unchanged.
fn macho_main_entry_offset(parsed: &object::File) -> Option<u64> {
    let object::File::MachO64(file) = parsed else { return None };
    let mut commands = file.macho_load_commands().ok()?;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(main)) = command.entry_point() {
            return Some(main.entryoff.get(file.endian()));
        }
    }
    None
}

fn file_offset_to_address(segments: &[Segment], offset: u64) -> Option<u64> {
    segments
        .iter()
        .find(|segment| offset >= segment.file_offset && offset - segment.file_offset < segment.file_size)
        .map(|segment| segment.address + (offset - segment.file_offset))
}

fn name_of(name: object::NameOrOrdinal<&[u8]>) -> String {
    match name {
        object::NameOrOrdinal::Name(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        object::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
    }
}

fn perms_of(flags: SegmentFlags) -> Perms {
    match flags {
        SegmentFlags::Elf { p_flags, .. } => Perms {
            read: p_flags.contains(object::elf::PF_R),
            write: p_flags.contains(object::elf::PF_W),
            execute: p_flags.contains(object::elf::PF_X),
        },
        SegmentFlags::MachO { initprot, .. } => Perms {
            read: initprot.contains(object::macho::VM_PROT_READ),
            write: initprot.contains(object::macho::VM_PROT_WRITE),
            execute: initprot.contains(object::macho::VM_PROT_EXECUTE),
        },
        SegmentFlags::Coff { characteristics } => Perms {
            read: characteristics.contains(object::pe::IMAGE_SCN_MEM_READ),
            write: characteristics.contains(object::pe::IMAGE_SCN_MEM_WRITE),
            execute: characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE),
        },
        _ => Perms::default(),
    }
}

fn section_kind_of(kind: object::SectionKind) -> SectionKind {
    use object::SectionKind as K;
    match kind {
        K::Text => SectionKind::Code,
        K::Data | K::Tls => SectionKind::Data,
        K::ReadOnlyData | K::ReadOnlyString | K::ReadOnlyDataWithRel => SectionKind::ReadOnlyData,
        K::UninitializedData | K::UninitializedTls => SectionKind::UninitializedData,
        _ => SectionKind::Other,
    }
}

fn symbol_kind_of(kind: object::SymbolKind) -> SymbolKind {
    match kind {
        object::SymbolKind::Text => SymbolKind::Function,
        object::SymbolKind::Data => SymbolKind::Data,
        _ => SymbolKind::Other,
    }
}
