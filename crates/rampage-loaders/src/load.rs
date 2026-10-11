use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use object::read::macho::{FatArch, FatArch32, FatArch64, MachOFatFile};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolFlags};
use rampage_arch::Arch;
use serde::Serialize;
use std::ops::Deref;

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
    pub big_endian: bool,
    /// ARM only: the sorted address ranges holding Thumb code.
    pub thumb: Vec<Range<u64>>,
    /// Data appended past everything the image's structures describe.
    pub overlay: Option<Overlay>,
    /// Whether instructions are big-endian, which differs from `big_endian` for ARM BE8 images.
    #[serde(skip)]
    code_big_endian: bool,
    #[serde(skip)]
    code_ranges: Vec<Range<u64>>,
    /// What decoders get: the ABI's global pointer and the GOT, found once at load.
    #[serde(skip)]
    global_pointer: Option<u64>,
    #[serde(skip)]
    got: Option<rampage_arch::Got>,
    #[serde(skip)]
    data: Bytes,
    #[serde(skip)]
    snapshot_source: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshot_modules: Vec<crate::snapshot::SnapshotModule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub snapshot_registers: Vec<crate::snapshot::SnapshotRegister>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_target: Option<crate::snapshot::SnapshotTarget>,
    #[serde(skip)]
    image: Range<usize>,
}

#[derive(Debug)]
enum Bytes {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(data) => data,
            Self::Owned(data) => data,
        }
    }
}

impl Binary {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_snapshot(
        arch: Arch,
        big_endian: bool,
        data_big_endian: bool,
        provenance: String,
        data: Vec<u8>,
        source: Vec<u8>,
        segments: Vec<Segment>,
        sections: Vec<Section>,
        thumb: Vec<Range<u64>>,
        function_starts: Vec<u64>,
        entry: Option<u64>,
    ) -> Result<Self, LoadError> {
        let code_ranges = code_ranges(&sections, &segments);
        let len = data.len();
        Ok(Self {
            format: Format::Snapshot,
            arch,
            entry,
            segments,
            sections,
            thumb,
            function_starts,
            symbols: Vec::new(),
            imports: Vec::new(),
            import_slots: Vec::new(),
            exports: Vec::new(),
            slices: vec![arch],
            warnings: Vec::new(),
            details: Details::None,
            big_endian: data_big_endian,
            overlay: None,
            code_big_endian: big_endian,
            code_ranges,
            global_pointer: None,
            got: None,
            data: Bytes::Owned(data),
            image: 0..len,
            snapshot_source: Some(source),
            provenance: Some(provenance),
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
        })
    }

    /// Opens a binary. For a universal Mach-O this picks the x86_64, aarch64 or x86 slice, in that order of
    /// preference, else the first supported one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        Self::open_with(path, None)
    }

    /// Opens a binary, requiring the given architecture when one is requested.
    pub fn open_with(path: impl AsRef<Path>, wanted: Option<Arch>) -> Result<Self, LoadError> {
        let resolved = crate::container::resolve_executable(path.as_ref())?;
        let path = resolved.as_path();
        let io_error = |source| LoadError::Io { path: path.to_owned(), source };
        let file = File::open(path).map_err(io_error)?;
        // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope,
        // the same assumption every mmap-based binary tool makes.
        let data = unsafe { Mmap::map(&file) }.map_err(io_error)?;
        if data.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
            if data.len() > 2 * crate::snapshot::MAX_SNAPSHOT_BYTES + 1024 * 1024 {
                return Err(LoadError::Malformed("snapshot JSON exceeds size limit".to_owned()));
            }
            return crate::snapshot::load(data.to_vec(), wanted);
        }

        let (slices, image) = match object::FileKind::parse(&*data)? {
            object::FileKind::MachOFat32 => select_slice(fat_slices::<FatArch32>(&data)?, wanted)?,
            object::FileKind::MachOFat64 => select_slice(fat_slices::<FatArch64>(&data)?, wanted)?,
            _ => (Vec::new(), 0..data.len()),
        };
        let image_bytes = &data[image.clone()];
        let parsed = object::File::parse(image_bytes)?;

        let format = match parsed.format() {
            object::BinaryFormat::Elf => Format::Elf,
            object::BinaryFormat::Pe => Format::Pe,
            object::BinaryFormat::MachO => Format::MachO,
            other => return Err(LoadError::Unsupported(format!("format {other:?}"))),
        };
        let arch = arch_of(parsed.architecture())
            .ok_or_else(|| LoadError::Unsupported(format!("architecture {:?}", parsed.architecture())))?;
        if let Some(wanted) = wanted
            && wanted != arch
        {
            return Err(LoadError::Unsupported(format!("{wanted} slice; the file contains {arch}")));
        }
        let slices = if slices.is_empty() { vec![arch] } else { slices };
        // ARM marks Thumb code addresses with the low bit; code itself lives at the even address.
        let code_address = |address: u64| if arch == Arch::Arm { address & !1 } else { address };

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

        let sections: Vec<Section> = parsed
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
                if matches!(arch, Arch::Arm | Arch::Aarch64) && arm_mapping_symbol(name).is_some() {
                    return None;
                }
                let code = symbol.kind() == object::SymbolKind::Text;
                Some(Symbol {
                    name: name.to_owned(),
                    address: if code { code_address(symbol.address()) } else { symbol.address() },
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
                        // Exports carry no kind: only an address in executable memory is code.
                        let executable = |address| segments.iter().any(|s| s.perms.execute && s.contains(address));
                        let address = if executable(code_address(address)) { code_address(address) } else { address };
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
        let raw_entry = match macho_main_entry_offset(&parsed) {
            Some(0) => None,
            Some(offset) => file_offset_to_address(&segments, offset),
            None => Some(parsed.entry()).filter(|&entry| entry != parsed.relative_address_base()),
        };
        let text_address = segments.iter().find(|segment| segment.name == "__TEXT").map(|segment| segment.address);
        let macho_starts =
            text_address.map(|text_address| starts::macho(&parsed, image_bytes, text_address)).unwrap_or_default();
        let thumb = match arch {
            Arch::Arm => thumb_ranges(&parsed, raw_entry, &segments, &sections, &macho_starts),
            _ => Vec::new(),
        };
        let entry = raw_entry.map(code_address);
        let mut function_starts: Vec<u64> = macho_starts.into_iter().map(code_address).collect();
        let big_endian = !parsed.is_little_endian();
        // ARMv6 and later big-endian images (BE8) store instructions little-endian; older BE32 ones do not.
        let be8_flag = |flags| match flags {
            object::FileFlags::Elf { e_flags, .. } => e_flags.0 & object::elf::EF_ARM_BE8.0 != 0,
            _ => false,
        };
        let be8 = arch == Arch::Arm && be8_flag(parsed.flags());
        let code_big_endian = big_endian && !be8;
        let exception_directory = starts::pe_exception_directory(&parsed);
        let import_slots = crate::slots::collect(&parsed, image_bytes, &mut warnings);
        let details = crate::details::collect(&parsed);
        let overlay = crate::details::overlay(&parsed, image_bytes, image.start as u64).unwrap_or_else(|warning| {
            warnings.push(warning);
            None
        });
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
            big_endian,
            code_big_endian,
            thumb,
            code_ranges: Vec::new(),
            global_pointer: None,
            got: None,
            data: Bytes::Mapped(data),
            snapshot_source: None,
            provenance: None,
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            image,
        };
        binary.code_ranges = code_ranges(&binary.sections, &binary.segments);
        binary.global_pointer = binary.find_global_pointer();
        binary.got = binary.read_got();
        if let Some(directory) = exception_directory {
            let (starts, warning) = starts::pe(&binary, &directory);
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

    /// What a decoder needs to read this image's code.
    pub fn target(&self) -> rampage_arch::Target {
        rampage_arch::Target {
            arch: self.arch,
            big_endian: self.code_big_endian,
            data_big_endian: self.big_endian,
            thumb: self.thumb.clone().into(),
            global_pointer: self.global_pointer,
            got: self.got.clone(),
        }
    }

    /// The ABI's global-pointer value: the linker's symbol for it, or else its conventional place relative to the
    /// GOT (MIPS `_gp` is `.got + 0x7ff0`; the PowerPC64 TOC base is `.got + 0x8000`).
    fn find_global_pointer(&self) -> Option<u64> {
        let symbol = |name: &str| self.symbol_by_name(name).map(|symbol| symbol.address);
        let got = |offset: u64| {
            let got = self.sections.iter().find(|section| section.name == ".got")?;
            got.address.checked_add(offset)
        };
        match self.arch {
            Arch::Mips | Arch::Mips64 => symbol("_gp").or_else(|| got(0x7ff0)),
            Arch::PowerPc64 => symbol(".TOC.").or_else(|| got(0x8000)),
            Arch::Riscv32 | Arch::Riscv64 => symbol("__global_pointer$"),
            _ => None,
        }
    }

    /// The `.got` section's entries, in the image's byte order.
    fn read_got(&self) -> Option<rampage_arch::Got> {
        let section = self.sections.iter().find(|section| section.name == ".got")?;
        let bytes = self.read(section.address, section.size)?;
        let size = usize::from(self.arch.pointer_size());
        let entries = bytes
            .chunks_exact(size)
            .map(|entry| {
                let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
                if self.big_endian { entry.iter().fold(0, fold) } else { entry.iter().rev().fold(0, fold) }
            })
            .collect();
        Some(rampage_arch::Got { address: section.address, entries })
    }

    /// A decoder for this image's code.
    pub fn decoder(&self) -> Result<Box<dyn rampage_arch::Disassembler>, rampage_arch::UnsupportedArch> {
        rampage_arch::decoder(&self.target())
    }

    /// The bytes of this image: the whole file, or one slice of a universal binary.
    pub fn image_bytes(&self) -> &[u8] {
        &self.data[self.image.clone()]
    }

    /// The whole file, including other slices of a universal binary.
    pub fn file_bytes(&self) -> &[u8] {
        self.snapshot_source.as_deref().unwrap_or(&self.data)
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

    /// The import slot at exactly `address`.
    pub fn import_slot(&self, address: u64) -> Option<&ImportSlot> {
        let index = self.import_slots.binary_search_by_key(&address, |slot| slot.address).ok()?;
        Some(&self.import_slots[index])
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
        self.image_bytes().get(start..end)
    }

    /// Reads a pointer only from readable, non-writable memory; captures do not imply future load invariance.
    pub fn read_pointer(&self, address: u64, size: u8) -> Option<u64> {
        let permissions = self.segment_containing(address)?.perms;
        if !matches!(size, 4 | 8) || !permissions.read || permissions.write {
            return None;
        }
        let bytes = self.read(address, u64::from(size))?;
        let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
        Some(if self.big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) })
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
            .map(|segment| segment.address..segment.address.saturating_add(segment.size))
            .collect();
    }
    merged(ranges)
}

/// Sorts `ranges` and merges the overlapping and adjacent ones.
fn merged(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
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
        // Prefer the slices people most often analyze, then whichever supported slice comes first.
        None => [Arch::X86_64, Arch::Aarch64, Arch::X86]
            .iter()
            .find_map(|&preferred| slices.iter().find(|slice| slice.arch == Some(preferred)))
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
    use object::Architecture as A;
    Some(match architecture {
        A::I386 => Arch::X86,
        A::X86_64 => Arch::X86_64,
        A::Aarch64 => Arch::Aarch64,
        A::Arm => Arch::Arm,
        A::Mips => Arch::Mips,
        A::Mips64 | A::Mips64_N32 => Arch::Mips64,
        A::PowerPc => Arch::PowerPc,
        A::PowerPc64 => Arch::PowerPc64,
        A::Riscv32 => Arch::Riscv32,
        A::Riscv64 => Arch::Riscv64,
        A::Sparc | A::Sparc32Plus => Arch::Sparc,
        A::Sparc64 => Arch::Sparc64,
        A::S390x => Arch::S390x,
        A::M68k => Arch::M68k,
        _ => return None,
    })
}

/// Mapping symbols mark where ARM code (`$a`), Thumb code (`$t`), AArch64 code (`$x`) and data (`$d`) begin.
fn arm_mapping_symbol(name: &str) -> Option<char> {
    let mut chars = name.strip_prefix('$')?.chars();
    let kind = chars.next()?;
    let rest = chars.as_str();
    (matches!(kind, 'a' | 't' | 'x' | 'd') && (rest.is_empty() || rest.starts_with('.'))).then_some(kind)
}

/// The address ranges of Thumb code. A `$t` mapping symbol starts a range that runs to the next mapping symbol or
/// the end of its section. Thumb functions add theirs: ELF marks them with the low address bit, Mach-O with
/// `N_ARM_THUMB_DEF` or an odd `LC_FUNCTION_STARTS` entry, and one without a size runs to the next function.
/// Without any of these, a Thumb entry point makes all code Thumb.
fn thumb_ranges(
    parsed: &object::File,
    entry: Option<u64>,
    segments: &[Segment],
    sections: &[Section],
    function_starts: &[u64],
) -> Vec<Range<u64>> {
    let container_end = |address: u64| {
        let in_section = |section: &&Section| address >= section.address && address - section.address < section.size;
        let section = sections.iter().find(in_section).map(|section| section.address.saturating_add(section.size));
        let segment = || segments.iter().find(|segment| segment.contains(address));
        section
            .or_else(|| segment().map(|segment| segment.address.saturating_add(segment.size)))
            .unwrap_or(address.saturating_add(2))
    };
    let mut ranges = Vec::new();
    let mut mapping: Vec<(u64, char)> = parsed
        .symbols()
        .filter_map(|symbol| Some((symbol.address(), arm_mapping_symbol(symbol.name().ok()?)?)))
        .collect();
    mapping.sort_unstable();
    for (index, &(address, kind)) in mapping.iter().enumerate() {
        if kind == 't' {
            let end = container_end(address);
            ranges.push(address..mapping.get(index + 1).map_or(end, |&(next, _)| next.min(end)));
        }
    }

    // (start, size, thumb) of every function the file records.
    let thumb_def =
        |flags| matches!(flags, SymbolFlags::MachO { n_desc, .. } if n_desc.0 & object::macho::N_ARM_THUMB_DEF.0 != 0);
    let mut functions: Vec<(u64, u64, bool)> = parsed
        .symbols()
        .chain(parsed.dynamic_symbols())
        .filter(|symbol| symbol.kind() == object::SymbolKind::Text)
        .map(|symbol| (symbol.address() & !1, symbol.size(), symbol.address() & 1 == 1 || thumb_def(symbol.flags())))
        .chain(function_starts.iter().map(|&start| (start & !1, 0, start & 1 == 1)))
        .collect();
    functions.sort_unstable();
    // Walking backwards, `following` is the next function start above the current one.
    let mut following = None;
    for (index, &(start, size, thumb)) in functions.iter().enumerate().rev() {
        if let Some(&(next, _, _)) = functions.get(index + 1)
            && next > start
        {
            following = Some(next);
        }
        if !thumb {
            continue;
        }
        let end = match size {
            0 => following.map_or(container_end(start), |next| next.min(container_end(start))),
            _ => start.saturating_add(size),
        };
        ranges.push(start..end);
    }

    if mapping.is_empty() && entry.is_some_and(|entry| entry & 1 == 1) {
        ranges.extend(
            segments
                .iter()
                .filter(|segment| segment.perms.execute)
                .map(|segment| segment.address..segment.address.saturating_add(segment.size)),
        );
    }
    merged(ranges)
}

/// `LC_MAIN` stores the entry point as a file offset, which `object` passes through unchanged.
fn macho_main_entry_offset(parsed: &object::File) -> Option<u64> {
    let (mut commands, endian) = crate::macho::load_commands(parsed)?;
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
