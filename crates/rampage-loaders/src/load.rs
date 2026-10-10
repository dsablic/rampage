use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use object::read::macho::{FatArch, FatArch32, FatArch64, MachOFatFile};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags};
use rampage_arch::Arch;
use serde::Serialize;

use crate::details::{Details, Overlay};
use crate::model::{Export, Format, Import, ImportSlot, Perms, Section, SectionKind, Segment, Symbol, SymbolKind};
use crate::starts;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("cannot read {path}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("cannot parse binary")]
    Parse(#[from] object::Error),
    #[error("malformed binary: {0}")]
    Malformed(String),
    #[error("unsupported {0}")]
    Unsupported(String),
}

#[derive(Debug, Serialize)]
pub struct Binary {
    pub format: Format,
    pub arch: Arch,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub entry: Option<u64>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    /// Where the dynamic loader stores each import's address, sorted by address.
    pub import_slots: Vec<ImportSlot>,
    pub exports: Vec<Export>,
    /// Function start addresses from format metadata (Mach-O `LC_FUNCTION_STARTS`, PE `.pdata`), sorted.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub function_starts: Vec<u64>,
    /// Architectures present in the file: several for a universal Mach-O, otherwise just `arch`.
    pub slices: Vec<Arch>,
    /// Problems with optional metadata that did not prevent loading.
    pub warnings: Vec<String>,
    /// Format-specific header facts (build metadata, linked libraries, hardening).
    pub details: Details,
    /// Data appended past everything the image's structures describe.
    pub overlay: Option<Overlay>,
    #[serde(skip)]
    code_ranges: Vec<Range<u64>>,
    #[serde(skip)]
    data: Mmap,
    #[serde(skip)]
    image: Range<usize>,
}

impl Binary {
    /// Opens a binary. For a universal Mach-O this picks the x86_64 slice when present, else the first one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        Self::open_with(path, None)
    }

    /// Opens a binary, requiring the given architecture when one is requested.
    pub fn open_with(path: impl AsRef<Path>, wanted: Option<Arch>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let io_error = |source| LoadError::Io { path: path.to_owned(), source };
        let file = File::open(path).map_err(io_error)?;
        // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope,
        // the same assumption every mmap-based binary tool makes.
        let data = unsafe { Mmap::map(&file) }.map_err(io_error)?;

        let (slices, image) = match object::FileKind::parse(&*data)? {
            object::FileKind::MachOFat32 => select_slice(fat_slices::<FatArch32>(&data)?, wanted)?,
            object::FileKind::MachOFat64 => select_slice(fat_slices::<FatArch64>(&data)?, wanted)?,
            _ => (Vec::new(), 0..data.len()),
        };
        let parsed = object::File::parse(&data[image.clone()])?;

        let format = match parsed.format() {
            object::BinaryFormat::Elf => Format::Elf,
            object::BinaryFormat::Pe => Format::Pe,
            object::BinaryFormat::MachO => Format::MachO,
            other => return Err(LoadError::Unsupported(format!("format {other:?}"))),
        };
        let arch = arch_of(parsed.architecture())
            .ok_or_else(|| LoadError::Unsupported(format!("architecture {:?}", parsed.architecture())))?;
        if wanted.is_some_and(|wanted| wanted != arch) {
            return Err(LoadError::Unsupported(format!("{} slice; the file contains {arch}", wanted.unwrap())));
        }
        let slices = if slices.is_empty() { vec![arch] } else { slices };

        let segments: Vec<Segment> = parsed
            .segments()
            .enumerate()
            .map(|(index, segment)| {
                let (file_offset, file_size) = segment.file_range();
                let size = segment.size().min(u64::MAX - segment.address());
                Segment {
                    name: segment.name().ok().flatten().map_or_else(|| format!("seg{index}"), str::to_owned),
                    address: segment.address(),
                    size,
                    file_offset,
                    file_size: file_size.min(size),
                    perms: perms_of(segment.flags()),
                }
            })
            .collect();

        let sections = parsed
            .sections()
            .map(|section| {
                let file_range = section.file_range();
                Section {
                    name: section.name().unwrap_or_default().to_owned(),
                    address: section.address(),
                    size: section.size(),
                    kind: section_kind_of(section.kind()),
                    file_offset: file_range.map(|(offset, _)| offset),
                    file_size: file_range.map_or(0, |(_, size)| size),
                }
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

        let mut warnings = Vec::new();
        let imports = parsed
            .imports()
            .and_then(|imports| {
                imports
                    .map(|import| {
                        let import = import?;
                        let library = String::from_utf8_lossy(import.library()).into_owned();
                        Ok(Import {
                            library: Some(library).filter(|library| !library.is_empty()),
                            name: name_of(import.name()),
                        })
                    })
                    .collect::<Result<_, object::Error>>()
            })
            .unwrap_or_else(|error| {
                warnings.push(format!("import table unreadable: {error}"));
                Vec::new()
            });

        let exports = parsed
            .exports()
            .and_then(|exports| {
                let mut found = Vec::new();
                for export in exports {
                    let export = export?;
                    if let object::ExportTarget::Address { address } = export.target() {
                        found.push(Export { name: name_of(export.name()), address });
                    }
                }
                Ok(found)
            })
            .unwrap_or_else(|error| {
                warnings.push(format!("export table unreadable: {error}"));
                Vec::new()
            });

        // A zero entry (relative to the image base, which PE adds) is how every format spells "none".
        let entry = match macho_main_entry_offset(&parsed) {
            Some(0) => None,
            Some(offset) => file_offset_to_address(&segments, offset),
            None => Some(parsed.entry()).filter(|&entry| entry != parsed.relative_address_base()),
        };
        let text_address = segments.iter().find(|segment| segment.name == "__TEXT").map(|segment| segment.address);
        let mut function_starts = text_address
            .map(|text_address| starts::macho(&parsed, &data[image.clone()], text_address))
            .unwrap_or_default();
        let exception_directory = starts::pe_exception_directory(&parsed);
        let image_base = parsed.relative_address_base();
        let import_slots = crate::slots::collect(&parsed, &data[image.clone()], &mut warnings);
        let details = crate::details::collect(&parsed);
        let overlay = crate::details::overlay(&parsed, &data[image.clone()])
            .map(|overlay| Overlay { file_offset: image.start as u64 + overlay.offset, ..overlay });
        drop(parsed);

        let mut binary = Self {
            format,
            arch,
            entry,
            segments,
            sections,
            symbols,
            imports,
            import_slots,
            exports,
            function_starts: Vec::new(),
            slices,
            warnings,
            details,
            overlay,
            code_ranges: Vec::new(),
            data,
            image,
        };
        binary.code_ranges = code_ranges(&binary.sections, &binary.segments);
        if let Some(directory) = exception_directory {
            let (starts, warning) = starts::pe(&binary, image_base, directory);
            function_starts.extend(starts);
            binary.warnings.extend(warning);
        }
        let (starts, warning) = starts::eh_frame(&binary);
        function_starts.extend(starts);
        binary.warnings.extend(warning);
        function_starts.retain(|&start| binary.is_code(start));
        function_starts.sort_unstable();
        function_starts.dedup();
        binary.function_starts = function_starts;
        Ok(binary)
    }

    /// The bytes of this image: the whole file, or one slice of a universal binary.
    pub fn image_bytes(&self) -> &[u8] {
        &self.data[self.image.clone()]
    }

    /// The whole file, including other slices of a universal binary.
    pub fn file_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn segment_containing(&self, address: u64) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.contains(address))
    }

    /// Whether `address` holds code: inside a code section, or inside an executable segment when the file has
    /// no code sections. Executable segments alone are too coarse; Mach-O `__TEXT` also holds headers and strings.
    pub fn is_code(&self, address: u64) -> bool {
        self.code_range_containing(address).is_some()
    }

    /// File-backed bytes from `address` to the end of its code range, or `None` when `address` is not code.
    pub fn code_from(&self, address: u64) -> Option<&[u8]> {
        let range = self.code_range_containing(address)?;
        let bytes = self.read_to_segment_end(address)?;
        let len = (range.end - address).min(bytes.len() as u64) as usize;
        Some(&bytes[..len])
    }

    fn code_range_containing(&self, address: u64) -> Option<&Range<u64>> {
        let index = self.code_ranges.partition_point(|range| range.end <= address);
        self.code_ranges.get(index).filter(|range| range.contains(&address))
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
        self.data[self.image.clone()].get(start..end)
    }

    /// Returns the file-backed bytes from `address` to the end of its segment's file data.
    /// Truncated files are cut short at the end of the file instead of failing.
    pub fn read_to_segment_end(&self, address: u64) -> Option<&[u8]> {
        let segment = self.segment_containing(address)?;
        let offset = address - segment.address;
        let in_segment = segment.file_size.checked_sub(offset)?;
        let file_position = segment.file_offset.checked_add(offset)?;
        let in_file = (self.image.len() as u64).checked_sub(file_position)?;
        self.read(address, in_segment.min(in_file)).filter(|bytes| !bytes.is_empty())
    }
}

/// Sorted, merged address ranges holding code.
fn code_ranges(sections: &[Section], segments: &[Segment]) -> Vec<Range<u64>> {
    let mut ranges: Vec<Range<u64>> = sections
        .iter()
        .filter(|section| section.kind == SectionKind::Code && section.size > 0)
        .map(|section| section.address..section.address.saturating_add(section.size))
        .collect();
    if ranges.is_empty() {
        ranges = segments
            .iter()
            .filter(|segment| segment.perms.execute && segment.size > 0)
            .map(|segment| segment.address..segment.address + segment.size)
            .collect();
    }
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

struct Slice {
    arch: Option<Arch>,
    range: Range<usize>,
}

fn fat_slices<Fat: FatArch>(data: &[u8]) -> Result<Vec<Slice>, LoadError> {
    let fat = MachOFatFile::<Fat>::parse(data)?;
    fat.arches()
        .iter()
        .map(|slice| {
            let start = usize::try_from(slice.offset().into()).ok();
            let len = usize::try_from(slice.size().into()).ok();
            let range = start.zip(len).and_then(|(start, len)| Some(start..start.checked_add(len)?));
            let range = range.filter(|range| range.end <= data.len());
            let range = range.ok_or_else(|| LoadError::Malformed("universal slice out of bounds".to_owned()))?;
            Ok(Slice { arch: arch_of(slice.architecture()), range })
        })
        .collect()
}

fn select_slice(slices: Vec<Slice>, wanted: Option<Arch>) -> Result<(Vec<Arch>, Range<usize>), LoadError> {
    let present: Vec<Arch> = slices.iter().filter_map(|slice| slice.arch).collect();
    let chosen = match wanted {
        Some(wanted) => slices.iter().find(|slice| slice.arch == Some(wanted)),
        None => slices
            .iter()
            .find(|slice| slice.arch == Some(Arch::X86_64))
            .or_else(|| slices.iter().find(|slice| slice.arch.is_some())),
    };
    let Some(chosen) = chosen else {
        let present = present.iter().map(Arch::to_string).collect::<Vec<_>>().join(", ");
        let wanted = wanted.map_or_else(|| "any".to_owned(), |wanted| wanted.to_string());
        return Err(LoadError::Unsupported(format!("{wanted} slice; the file contains {present}")));
    };
    Ok((present, chosen.range.clone()))
}

fn arch_of(architecture: object::Architecture) -> Option<Arch> {
    match architecture {
        object::Architecture::I386 => Some(Arch::X86),
        object::Architecture::X86_64 => Some(Arch::X86_64),
        object::Architecture::Aarch64 => Some(Arch::Aarch64),
        _ => None,
    }
}

/// `LC_MAIN` stores the entry point as a file offset, which `object` passes through unchanged.
fn macho_main_entry_offset(parsed: &object::File) -> Option<u64> {
    let (mut commands, endian) = starts::macho_load_commands(parsed)?;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(Some(main)) = command.entry_point() {
            return Some(main.entryoff.get(endian));
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
