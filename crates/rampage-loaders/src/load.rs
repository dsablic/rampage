use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use object::read::macho::{FatArch, FatArch32, FatArch64, MachOFatFile};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolFlags};
use rampage_arch::Arch;
use rampage_arch::bytes::read_uint;
use serde::Serialize;
use std::ops::Deref;

use crate::details::{Details, Overlay};
use crate::model::{Export, Format, Import, ImportSlot, Perms, Section, SectionKind, Segment, Symbol, SymbolKind};
use crate::starts;

pub type InventorySourceContext<'a> = (Range<usize>, &'a [Range<u64>], &'a [(u64, u64)]);

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
    #[error("invalid embedded image location: {0}")]
    Location(String),
}

/// Where an image opened with [`Binary::open_at`] lies in the file that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Embedded {
    /// The image's first byte in the outer file.
    pub offset: u64,
    /// Bytes from `offset` taken as the image (the whole universal binary, for an embedded fat Mach-O).
    pub size: u64,
    /// The outer file's size.
    pub file_size: u64,
    /// Bytes of the outer file after the image. They are not part of it, so they are not reported as overlay.
    pub trailing: u64,
}

/// Where the image to open lies in its file: from `offset`, for `length` bytes when given, else for the extent its
/// header tables give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImageAt {
    offset: u64,
    length: Option<u64>,
}

impl ImageAt {
    pub fn new(offset: u64, length: Option<u64>) -> Self {
        Self { offset, length }
    }

    pub fn offset(self) -> u64 {
        self.offset
    }

    pub fn length(self) -> Option<u64> {
        self.length
    }

    /// Whether this is the whole file as [`Binary::open`] takes it, overlay included: offset 0 and no length.
    pub fn is_whole_file(self) -> bool {
        self.offset == 0 && self.length.is_none()
    }
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
    /// Candidate function starts from format metadata, sorted; unwind ranges can include function fragments.
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
    /// A dynamically linked MIPS ELF's GOT layout, from its dynamic section.
    #[serde(skip)]
    mips_got: Option<crate::slots::MipsGot>,
    /// A MIPS ELF's global GOT entries whose dynamic symbol is a function it defines, by slot.
    #[serde(skip)]
    pub got_functions: Vec<crate::slots::GotFunction>,
    /// Mach-O chained-fixup rebases: each pointer's location and the target the loader writes there.
    #[serde(skip)]
    rebases: Vec<(u64, u64)>,
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
    /// Set when the image was opened at an offset inside a larger file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<Embedded>,
    /// The version of the Go pclntab that named functions, set by [`Binary::recover_go_symbols`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_table: Option<crate::gopclntab::GoTableVersion>,
    /// The Go pclntab's virtual address, which `moduledata` points at; set by [`Binary::recover_go_symbols`].
    #[serde(skip)]
    pub go_table_address: Option<u64>,
    /// Register-ABI Go functions' argument layouts by entry address, set by [`Binary::recover_go_symbols`].
    #[serde(skip)]
    pub go_arguments: std::collections::BTreeMap<u64, crate::gopclntab::GoArguments>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<crate::RawCodeImage>,
    /// PE only: the image base and exception directory from the headers.
    #[serde(skip)]
    pe_layout: Option<crate::msvc::PeLayout>,
    /// x86/x64 PE only: vftables and exception tables, read once at load.
    #[serde(skip)]
    msvc: Option<crate::msvc::MsvcMetadata>,
    #[serde(skip)]
    image: Range<usize>,
    /// The Raw interpretation identity, hashed once: `raw` and the owned image bytes never change after load.
    #[serde(skip)]
    raw_identity: std::sync::OnceLock<crate::RawInterpretationIdentity>,
    /// An ARM ELF whose build attributes name an M-profile CPU ([`Binary::m_profile`]).
    #[serde(skip)]
    elf_m_profile: bool,
    /// An Xtensa image built for the call0 ABI ([`Binary::xtensa_call0`]).
    #[serde(skip)]
    xtensa_call0: bool,
    /// A MIPS ELF whose header marks a compressed instruction set rampage does not decode
    /// ([`Binary::undecoded_isa`]).
    #[serde(skip)]
    undecoded_isa: Option<&'static str>,
    /// A 32-bit MIPS ELF whose header marks MIPS16e code, which is decoded ([`Binary::mips16`]).
    #[serde(skip)]
    mips16: bool,
    /// The MIPS16e code ranges its symbols mark ([`Binary::mips16_ranges`]).
    #[serde(skip)]
    mips16_ranges: Vec<Range<u64>>,
    /// A relocatable object's layout: the loaded bytes [`Binary::read`] serves, with relocations applied.
    #[serde(skip)]
    relocated: Option<Box<crate::relocatable::Relocated>>,
    /// The archive member this image is, when it was opened from a static archive (see [`crate::ar`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_member: Option<crate::ar::Member>,
}

#[derive(Debug)]
enum Bytes {
    Mapped(MappedSource),
    Owned(Vec<u8>),
}

#[derive(Debug)]
struct MappedSource {
    map: Mmap,
    file: File,
    path: PathBuf,
    stamp: Option<BackingStamp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackingStamp {
    length: u64,
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl BackingStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            metadata.is_file().then(|| Self {
                length: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }
}

impl Deref for MappedSource {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.map
    }
}

impl MappedSource {
    fn validate(&self) -> Result<(), LoadError> {
        let stamp =
            self.stamp.ok_or_else(|| LoadError::Unsupported("original mapped-file identity unavailable".into()))?;
        let io_error = |source| LoadError::Io { path: self.path.clone(), source };
        let descriptor = self.file.metadata().map_err(io_error)?;
        let pathname = std::fs::metadata(&self.path).map_err(io_error)?;
        if BackingStamp::from_metadata(&descriptor) != Some(stamp)
            || BackingStamp::from_metadata(&pathname) != Some(stamp)
        {
            return Err(LoadError::Malformed("backing file was modified or replaced since mapping".into()));
        }
        Ok(())
    }
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

#[cfg(test)]
thread_local! {
    static NATIVE_PARSE_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OPTIONAL_RECOVERY_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn note_optional_recovery_entry() {
    OPTIONAL_RECOVERY_ENTRIES.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn note_native_parse_entry() {
    NATIVE_PARSE_ENTRIES.with(|count| count.set(count.get() + 1));
}

impl Binary {
    /// Owns one explicitly interpreted code image. No header parsing, entry inference or filesystem access.
    /// All addresses are internal byte offsets; this is not a C data-space or capture mapping.
    pub fn from_raw_code(data: Vec<u8>, options: crate::RawCodeOptions) -> Result<Self, LoadError> {
        Self::from_raw_image(crate::RawImage {
            bytes: data,
            options,
            source: None,
            regions: Vec::new(),
            records: None,
            esp: None,
            scatter_load: None,
            writable: None,
        })
    }

    /// Owns one explicitly interpreted image of a primary code region and any further analyst-stated regions
    /// (code, constant data, RAM with or without bytes). Regions never overlap; no header parsing, entry
    /// inference or filesystem access. The owned bytes are the backed regions' bytes in region order.
    pub fn from_raw_image(image: crate::RawImage) -> Result<Self, LoadError> {
        let (raw, data) = crate::RawCodeImage::admit(image)?;
        let arch = raw.profile().arch();
        let len = data.len();
        let mut binary = Self {
            format: Format::Raw,
            arch,
            entry: raw.entry(),
            segments: raw.segments(),
            sections: raw.sections(),
            symbols: Vec::new(),
            imports: Vec::new(),
            import_slots: Vec::new(),
            exports: Vec::new(),
            function_starts: raw.seeds().to_vec(),
            slices: vec![arch],
            warnings: raw.vector_table_hint().into_iter().collect(),
            details: Details::None,
            big_endian: raw.profile().big_endian(),
            thumb: raw.thumb_ranges(),
            overlay: None,
            code_big_endian: raw.profile().code_big_endian(),
            code_ranges: raw.code_ranges(),
            global_pointer: None,
            got: None,
            mips_got: None,
            got_functions: Vec::new(),
            rebases: Vec::new(),
            data: Bytes::Owned(data),
            snapshot_source: None,
            provenance: None,
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            embedded: None,
            go_table: None,
            go_table_address: None,
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw_identity: std::sync::OnceLock::new(),
            elf_m_profile: false,
            xtensa_call0: false,
            undecoded_isa: None,
            mips16: false,
            mips16_ranges: Vec::new(),
            raw: Some(raw),
            image: 0..len,
            relocated: None,
            archive_member: None,
        };
        // An ESP image states its chip; other Raw Xtensa code is judged by its prologues.
        if arch == Arch::Xtensa && binary.raw.as_ref().is_some_and(|raw| raw.esp().is_none()) {
            binary.xtensa_call0 = xtensa_prologue_vote(&binary);
        }
        Ok(binary)
    }

    /// This Raw image's interpretation over replacement owned bytes of exactly the same length (a byte patch):
    /// the mapping, entry and seeds are kept, and each region's SHA-256 is recomputed.
    pub fn with_raw_bytes(&self, data: Vec<u8>) -> Result<Self, LoadError> {
        let raw = match &self.raw {
            Some(raw) if self.format == Format::Raw && matches!(self.data, Bytes::Owned(_)) => raw,
            _ => return Err(LoadError::Unsupported("replacement bytes need an admitted Raw image".into())),
        };
        if data.len() != self.data.len() {
            return Err(LoadError::Malformed("Raw replacement bytes must keep the owned length".into()));
        }
        let mut binary = Self::from_raw_code(
            vec![0],
            crate::RawCodeOptions {
                profile: raw.profile(),
                base: raw.base(),
                entry: None,
                seeds: Vec::new(),
                vector_table: None,
                pointer_tables: false,
            },
        )?;
        binary.entry = self.entry;
        binary.segments = self.segments.clone();
        binary.sections = self.sections.clone();
        binary.function_starts = self.function_starts.clone();
        binary.thumb = self.thumb.clone();
        binary.code_ranges = self.code_ranges.clone();
        binary.image = 0..data.len();
        binary.raw = Some(raw.with_bytes(&data));
        binary.data = Bytes::Owned(data);
        Ok(binary)
    }

    /// Retained admission facts, not translator-verified facts or source authority.
    pub fn raw_code_image(&self) -> Option<&crate::RawCodeImage> {
        self.raw.as_ref()
    }

    /// A Raw image a Sleigh translator decodes: no typed operands, pointer evidence or native IR. A Raw format
    /// without retained admission facts counts too, so nothing native is trusted for it.
    pub fn is_sleigh_raw(&self) -> bool {
        self.format == Format::Raw && !self.raw.as_ref().is_some_and(|raw| raw.profile().native_decoder())
    }

    /// The compressed MIPS instruction set the ELF header says the image holds when rampage does not decode it
    /// (microMIPS, or MIPS16e in a 64-bit image): functions in it are not discovered, disassembled or decompiled.
    pub fn undecoded_isa(&self) -> Option<&'static str> {
        self.undecoded_isa
    }

    /// A 32-bit MIPS ELF whose header marks MIPS16e code: odd code addresses are MIPS16e functions at the even
    /// address (symbols, exports and the entry already have bit 0 cleared), and `jalx` switches mode.
    pub fn mips16(&self) -> bool {
        self.mips16
    }

    /// musl's MIPS `_start` (`crt_arch.h`): `bal 1f; move $fp, $0`, then two words, the address of the first and
    /// of `_start_c`, each less the same base (`_gp` in a static build, nothing in a dynamic one); at `1:` it subtracts
    /// the first from the link register to get that base, and calls `_start_c` through `$t9`. Returns `_start_c`
    /// when it lies in code.
    pub fn musl_mips_start_c(&self) -> Option<u64> {
        self.musl_mips_start_c_pointer().map(|pointer| pointer & !1)
    }

    /// [`Binary::musl_mips_start_c`] as the word gives it: odd when `_start_c` is MIPS16e code.
    fn musl_mips_start_c_pointer(&self) -> Option<u64> {
        if self.arch != Arch::Mips || self.format != Format::Elf {
            return None;
        }
        let entry = self.entry?;
        let word = |address: u64| {
            let bytes: [u8; 4] = self.read(address, 4)?.try_into().ok()?;
            Some(if self.big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) })
        };
        // `bal` is `bgezal $zero, offset`; its link register then holds the address after its delay slot, where the
        // words are, and it branches past them to `lw $gp, 0($ra)` (0x8ffc0000).
        let bal = word(entry)?;
        if bal & 0xffff_0000 != 0x0411_0000 {
            return None;
        }
        let link = entry.checked_add(8)?;
        let target = entry.checked_add(4)?.checked_add(u64::from(bal & 0xffff) << 2)?;
        if word(target)? != 0x8ffc_0000 {
            return None;
        }
        let base = (link as u32).wrapping_sub(word(link)?);
        let start_c = u64::from(word(link.checked_add(4)?)?.wrapping_add(base));
        // A MIPS16e `_start_c` is an odd address in a MIPS16e image; MIPS32 code is 4-byte aligned.
        let aligned = start_c & 3 == 0 || (self.mips16 && start_c & 1 == 1);
        (aligned && self.is_code(start_c & !1)).then_some(start_c)
    }

    /// Whether code runs in two instruction sets whose mode discovery learns per address: 32-bit ARM (A32 and
    /// Thumb) or a [`Binary::mips16`] image (MIPS32 and MIPS16e).
    pub fn has_code_modes(&self) -> bool {
        self.arch == Arch::Arm || self.mips16
    }

    /// The MIPS16e code ranges the symbols of a [`Binary::mips16`] image mark: a function's size, or up to the next
    /// function. Discovery finds others from `jalx` and odd code pointers.
    pub fn mips16_ranges(&self) -> &[Range<u64>] {
        &self.mips16_ranges
    }

    /// [`Self::undecoded_isa`] as a sentence for results that list or read code.
    pub fn undecoded_isa_note(&self) -> Option<String> {
        self.undecoded_isa.map(undecoded_isa_note)
    }

    /// An Xtensa image for the call0 ABI (ESP8266): an ELF whose `.xtensa.info` says so, a Raw image whose
    /// interpretation does (an ESP8266 app image), or, where neither says, code whose prologues vote for it
    /// ([`xtensa_prologue_vote`]). Otherwise Xtensa code is taken to use register windows (ESP32).
    pub fn xtensa_call0(&self) -> bool {
        self.arch == Arch::Xtensa && (self.xtensa_call0 || self.raw.as_ref().is_some_and(|raw| raw.xtensa_call0()))
    }

    /// An ARMv6-M/ARMv7-M(E)/ARMv8-M image: all Thumb, no A32 state, M-profile instruction set. A Raw project with
    /// the Cortex-M profile, or an ARM ELF whose build attributes (`.ARM.attributes`) name an M-profile CPU; never
    /// keyed on load addresses, so ordinary ARM Linux, PE and Mach-O images are not.
    pub fn m_profile(&self) -> bool {
        self.elf_m_profile || self.raw.as_ref().is_some_and(|raw| raw.profile().m_profile())
    }

    /// Content-and-interpretation identity, not a mapped-file freshness or producer/capture proof.
    /// Public loader fields can be edited; refuse interpretation drift instead of returning a stale key.
    pub fn raw_interpretation_identity(&self) -> Result<Option<crate::RawInterpretationIdentity>, LoadError> {
        let Some(raw) = &self.raw else {
            return if self.format == Format::Raw {
                Err(LoadError::Malformed("Raw has no retained admission facts".into()))
            } else {
                Ok(None)
            };
        };
        if self.format != Format::Raw
            || !self.symbols.is_empty()
            || !self.imports.is_empty()
            || !self.import_slots.is_empty()
            || !self.exports.is_empty()
            || self.warnings.iter().ne(raw.vector_table_hint().iter())
            || !matches!(&self.details, Details::None)
            || self.overlay.is_some()
            || self.global_pointer.is_some()
            || self.got.is_some()
            || self.go_table.is_some()
            || !self.go_arguments.is_empty()
            || self.arch != raw.profile().arch()
            || self.entry != raw.entry()
            || self.function_starts != raw.seeds()
            || self.segments != raw.segments()
            || self.sections != raw.sections()
            || self.slices != [self.arch]
            || self.big_endian != raw.profile().big_endian()
            || self.code_big_endian != raw.profile().code_big_endian()
            || self.thumb != raw.thumb_ranges()
            || self.code_ranges != raw.code_ranges()
            || self.image != (0..self.data.len())
            || self.data.len() as u64 != raw.backed_bytes()
            || !matches!(&self.data, Bytes::Owned(_))
            || self.snapshot_source.is_some()
            || self.provenance.is_some()
            || !self.snapshot_modules.is_empty()
            || !self.snapshot_registers.is_empty()
            || self.snapshot_target.is_some()
            || self.embedded.is_some()
        {
            return Err(LoadError::Malformed("Raw interpretation differs from retained admission facts".into()));
        }
        // The checks above cover the public fields that can drift; the hashed facts and bytes cannot.
        Ok(Some(self.raw_identity.get_or_init(|| raw.identity(self.image_bytes())).clone()))
    }

    /// Bounded linkage evidence from this retained image, without opening dependency paths.
    pub fn linkage_metadata(&self, limits: crate::LinkageLimits) -> Result<crate::LinkageMetadata, LoadError> {
        crate::linkage_metadata(self, limits)
    }

    /// Actual retained selection and loader context for consistency keys; this grants no source authority.
    pub fn inventory_source_context(&self) -> InventorySourceContext<'_> {
        (self.image.clone(), &self.code_ranges, &self.rebases)
    }

    pub(crate) fn linkage_private_vectors_over_limit(&self, limit: usize) -> bool {
        self.code_ranges.len() > limit || self.rebases.len() > limit
    }

    /// Detects observable changes to the original mapped file without reading mapped bytes. This metadata check
    /// does not make subsequent reads atomic with external writes or truncation. Owned inputs have no such proof.
    pub fn validate_backing_source(&self) -> Result<(), LoadError> {
        match &self.data {
            Bytes::Mapped(source) => source.validate(),
            Bytes::Owned(_) => Err(LoadError::Unsupported("owned input has no mapped-file identity".into())),
        }
    }

    /// Checks an original mapping when present. False means owned bytes, not a physical-source identity proof.
    /// As with `validate_backing_source`, this does not make later reads atomic with external modification.
    pub fn validate_available_backing_source(&self) -> Result<bool, LoadError> {
        match &self.data {
            Bytes::Mapped(source) => source.validate().map(|()| true),
            Bytes::Owned(_) => Ok(false),
        }
    }

    /// The actual loaded executable source, not a bundle directory or target-reported provenance path.
    /// Owned snapshots have no original mapped-file path; callers must retain their explicit document source.
    pub fn backing_path(&self) -> Option<&Path> {
        match &self.data {
            Bytes::Mapped(source) => Some(&source.path),
            Bytes::Owned(_) => None,
        }
    }

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
            mips_got: None,
            got_functions: Vec::new(),
            rebases: Vec::new(),
            data: Bytes::Owned(data),
            image: 0..len,
            snapshot_source: Some(source),
            provenance: Some(provenance),
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            embedded: None,
            go_table: None,
            go_table_address: None,
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw_identity: std::sync::OnceLock::new(),
            elf_m_profile: false,
            xtensa_call0: false,
            undecoded_isa: None,
            mips16: false,
            mips16_ranges: Vec::new(),
            raw: None,
            relocated: None,
            archive_member: None,
        })
    }

    /// Opens a binary. For a universal Mach-O this picks the x86_64, aarch64 or x86 slice, in that order of
    /// preference, else the first supported one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        Self::open_with(path, None)
    }

    /// Validates and owns a complete snapshot document using the same semantic loader as file opening.
    /// This performs no filesystem access and provides no original mapped-file identity proof.
    pub fn from_snapshot_bytes(source: Vec<u8>) -> Result<Self, LoadError> {
        if source.len() > 2 * crate::snapshot::MAX_SNAPSHOT_BYTES + 1024 * 1024 {
            return Err(LoadError::Malformed("snapshot JSON exceeds size limit".to_owned()));
        }
        crate::snapshot::load(source, None)
    }

    /// Opens a binary, requiring the given architecture when one is requested.
    pub fn open_with(path: impl AsRef<Path>, wanted: Option<Arch>) -> Result<Self, LoadError> {
        if let (archive, _, Some(member)) = crate::ar::member_image(path.as_ref(), None, wanted)? {
            return Self::open_member(archive, member, wanted);
        }
        let data = map_executable(path.as_ref())?;
        Self::open_mapped(data, wanted)
    }

    /// Opens `member` of the static archive at `archive`, as [`crate::ar::resolve`] found it: the image at its
    /// location in the archive.
    pub fn open_member(
        archive: impl AsRef<Path>,
        member: crate::ar::Member,
        wanted: Option<Arch>,
    ) -> Result<Self, LoadError> {
        let data = map_executable(archive.as_ref())?;
        let (offset, size) = (member.offset, member.size);
        Self::open_mapped_at_recovery(data, offset, Some(size), wanted, true, Some(member))
    }

    fn open_mapped(data: MappedSource, wanted: Option<Arch>) -> Result<Self, LoadError> {
        Self::open_mapped_recovery(data, wanted, true)
    }

    fn open_mapped_recovery(data: MappedSource, wanted: Option<Arch>, recover: bool) -> Result<Self, LoadError> {
        #[cfg(test)]
        note_native_parse_entry();
        if recover && data.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
            if data.len() > 2 * crate::snapshot::MAX_SNAPSHOT_BYTES + 1024 * 1024 {
                return Err(LoadError::Malformed("snapshot JSON exceeds size limit".to_owned()));
            }
            return crate::snapshot::load(data.to_vec(), wanted);
        }
        let kind = object::FileKind::parse(&*data).map_err(|error| {
            if recover {
                LoadError::Parse(error)
            } else {
                LoadError::Unsupported("native image required for metadata inspection".into())
            }
        })?;
        let (slices, image) = match kind {
            object::FileKind::MachOFat32 | object::FileKind::MachOFat64 if crate::ar::is_static_library(&data) => {
                let library = crate::ar::read_library(&data, wanted)?;
                return Err(crate::ar::whole_archive_error(Some(&data.path), &library.archive));
            }
            object::FileKind::MachOFat32 => select_universal::<FatArch32>(&data, wanted)?,
            object::FileKind::MachOFat64 => select_universal::<FatArch64>(&data, wanted)?,
            object::FileKind::Archive => {
                let archive = crate::ar::read(&data)?;
                return Err(crate::ar::whole_archive_error(Some(&data.path), &archive));
            }
            object::FileKind::CoffImport => {
                let import = crate::ar::import_member(&data)
                    .ok_or_else(|| LoadError::Malformed("unreadable short import object".to_owned()))?;
                return Err(crate::ar::import_member_error(&import));
            }
            _ => (Vec::new(), 0..data.len()),
        };
        Self::load_recovery(data, image, slices, wanted, recover)
    }

    /// Opens the ELF, PE or Mach-O image embedded at `offset` in the file at `path`, such as one `carve` found.
    /// Its header must validate the way carving validates it. The image runs for `length` bytes, or else for the
    /// extent its header tables give (cut at the end of the file); only bytes within it can be overlay, and
    /// [`Embedded::trailing`] counts those after it. Addresses and file offsets are the image's own, as if it had
    /// been extracted; [`Binary::embedded`] records where it lies. For an embedded universal Mach-O, give the offset
    /// of its fat header and choose the slice with [`Binary::open_at_with`]; a slice's own offset opens that thin
    /// image alone, as a different image.
    pub fn open_at(path: impl AsRef<Path>, offset: u64, length: Option<u64>) -> Result<Self, LoadError> {
        Self::open_at_with(path, offset, length, None)
    }

    /// [`Binary::open_with`] the whole file, or with `image`, [`Binary::open_at_with`] the image there. A location
    /// that [is the whole file](ImageAt::is_whole_file) opens it as [`Binary::open_with`] does, so that one image
    /// has one identity.
    pub fn open_image(path: impl AsRef<Path>, image: Option<ImageAt>, wanted: Option<Arch>) -> Result<Self, LoadError> {
        let (path, image, member) = crate::ar::member_image(path.as_ref(), image, wanted)?;
        if let Some(member) = member {
            return Self::open_member(path, member, wanted);
        }
        match image.filter(|image| !image.is_whole_file()) {
            Some(image) => Self::open_at_with(path, image.offset, image.length, wanted),
            None => Self::open_with(path, wanted),
        }
    }

    /// Opens native format metadata and mappings without optional Go/Objective-C symbol-recovery scans.
    /// This still parses native headers/symbols and requires stable backing; it is not a raw-file loader.
    pub fn open_image_metadata(
        path: impl AsRef<Path>,
        image: Option<ImageAt>,
        wanted: Option<Arch>,
    ) -> Result<Self, LoadError> {
        let (path, image, member) = crate::ar::member_image(path.as_ref(), image, wanted)?;
        let data = map_executable(&path)?;
        match image.filter(|image| !image.is_whole_file()) {
            Some(image) => Self::open_mapped_at_recovery(data, image.offset, image.length, wanted, false, member),
            None => Self::open_mapped_recovery(data, wanted, false),
        }
    }

    /// Opens one explicit regular source without bundle resolution or following a final symlink.
    /// The 128 MiB source cap is enforced before mapping; metadata checks are not atomic with external writes.
    pub fn open_image_checked(
        path: impl AsRef<Path>,
        image: Option<ImageAt>,
        wanted: Option<Arch>,
    ) -> Result<Self, LoadError> {
        Self::open_image_checked_admitted(path, image, wanted, 128 * 1024 * 1024, |_| Ok(()))
    }

    /// Checked opening with an additional admission gate on the exact retained mapping, before any native
    /// image/carving/snapshot parser runs. `max_source_bytes` can lower, never raise, the 128 MiB checked cap
    /// and is enforced on the opened descriptor before mapping. The callback sees the complete outer source;
    /// callers admitting an embedded image must validate their selection within these bytes themselves.
    ///
    /// Original descriptor/path metadata are revalidated after the callback and before consuming the mapping.
    /// Neither metadata checks nor callback admission make reads atomic: sources must remain quiescent during
    /// the callback and subsequent parsing, including against concurrent truncation of the mapped file.
    pub fn open_image_checked_admitted(
        path: impl AsRef<Path>,
        image: Option<ImageAt>,
        wanted: Option<Arch>,
        max_source_bytes: usize,
        admit: impl FnOnce(&[u8]) -> Result<(), LoadError>,
    ) -> Result<Self, LoadError> {
        let (path, image, member) = crate::ar::member_image(path.as_ref(), image, wanted)?;
        let data = map_executable_checked(&path, max_source_bytes.min(128 * 1024 * 1024))?;
        consume_admitted_source(data, admit, |data| match image.filter(|image| !image.is_whole_file()) {
            Some(image) => Self::open_mapped_at_recovery(data, image.offset, image.length, wanted, true, member),
            None => {
                if data.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
                    crate::checked_snapshot::preflight(&data)?;
                }
                Self::open_mapped(data, wanted)
            }
        })
    }

    /// Checks the admission limits used by checked opening without reopening or deriving source identity.
    pub fn validate_checked_source_profile(&self) -> Result<(), LoadError> {
        if self.file_bytes().len() > 128 * 1024 * 1024 {
            return Err(LoadError::Unsupported("checked source exceeds 128 MiB".into()));
        }
        if self.format == Format::Snapshot {
            crate::checked_snapshot::preflight(self.file_bytes())?;
        }
        Ok(())
    }

    /// Enumerates supported universal-header architectures without requiring any individual slice to load.
    /// Thin images and snapshots use ordinary loading. Ambiguous duplicate architectures are rejected.
    pub fn architecture_slices(path: impl AsRef<Path>, image: Option<ImageAt>) -> Result<Vec<Arch>, LoadError> {
        let (path, image, _) = crate::ar::member_image(path.as_ref(), image, None)?;
        let path = path.as_path();
        let data = map_executable(path)?;
        let view = match image.filter(|image| !image.is_whole_file()) {
            Some(image) => {
                let start = usize::try_from(image.offset)
                    .ok()
                    .filter(|&start| start < data.len())
                    .ok_or_else(|| LoadError::Location("architecture probe offset is outside the file".to_owned()))?;
                let length = image.length.unwrap_or((data.len() - start) as u64);
                let length = usize::try_from(length)
                    .ok()
                    .filter(|&length| length > 0)
                    .ok_or_else(|| LoadError::Location("invalid architecture probe length".to_owned()))?;
                let end = start
                    .checked_add(length)
                    .ok_or_else(|| LoadError::Location("architecture probe range overflows".to_owned()))?;
                data.get(start..end)
                    .ok_or_else(|| LoadError::Location("architecture probe range is outside the file".to_owned()))?
            }
            None => &data,
        };
        let slices = match object::FileKind::parse(view) {
            Ok(object::FileKind::MachOFat32) => declared_architectures::<FatArch32>(view)?,
            Ok(object::FileKind::MachOFat64) => declared_architectures::<FatArch64>(view)?,
            _ => return Ok(Self::open_image(path, image, None)?.slices),
        };
        if slices.is_empty() {
            return Err(LoadError::Unsupported("no supported architecture slices".to_owned()));
        }
        Ok(slices)
    }

    /// [`Binary::open_at`], requiring the given architecture when one is requested.
    pub fn open_at_with(
        path: impl AsRef<Path>,
        offset: u64,
        length: Option<u64>,
        wanted: Option<Arch>,
    ) -> Result<Self, LoadError> {
        let data = map_executable(path.as_ref())?;
        Self::open_mapped_at(data, offset, length, wanted)
    }

    fn open_mapped_at(
        data: MappedSource,
        offset: u64,
        length: Option<u64>,
        wanted: Option<Arch>,
    ) -> Result<Self, LoadError> {
        Self::open_mapped_at_recovery(data, offset, length, wanted, true, None)
    }

    fn open_mapped_at_recovery(
        data: MappedSource,
        offset: u64,
        length: Option<u64>,
        wanted: Option<Arch>,
        recover: bool,
        member: Option<crate::ar::Member>,
    ) -> Result<Self, LoadError> {
        #[cfg(test)]
        note_native_parse_entry();
        let file_size = data.len() as u64;
        let start = usize::try_from(offset).ok().filter(|&start| start < data.len()).ok_or_else(|| {
            LoadError::Location(format!("offset {offset:#x} is past the end of the file ({file_size:#x} bytes)"))
        })?;
        let available = file_size - offset;
        if let Some(wanted) = wanted {
            let kind = object::FileKind::parse(&data[start..]).ok();
            let selected = match kind {
                Some(object::FileKind::MachOFat32) => {
                    Some(explicit_fat_image::<FatArch32>(&data, start, length, wanted)?)
                }
                Some(object::FileKind::MachOFat64) => {
                    Some(explicit_fat_image::<FatArch64>(&data, start, length, wanted)?)
                }
                _ => None,
            };
            if let Some((size, slices, image)) = selected {
                let mut binary = Self::load_recovery(data, image, slices, Some(wanted), recover)?;
                binary.embedded =
                    Some(Embedded { offset, size: size as u64, file_size, trailing: available - size as u64 });
                binary.warnings.push(
                    "explicit universal slice loaded independently; other slice bodies were not validated".to_owned(),
                );
                return Ok(binary);
            }
        }
        // An image at a member's offset in a static library is that member (read here unless the caller resolved it).
        let member = member.or_else(|| crate::ar::member_at(&data, offset));
        // A library member's extent is the member; COFF objects and import objects have no header carving knows.
        if let Some(found) = member.as_ref().filter(|found| found.offset == offset) {
            let end = usize::try_from(found.size)
                .ok()
                .and_then(|size| start.checked_add(size))
                .filter(|&end| end <= data.len());
            if let Some(end) = end.filter(|_| length.is_none_or(|length| length == found.size)) {
                match object::FileKind::parse(&data[start..end]) {
                    Ok(object::FileKind::CoffImport) => {
                        let import = crate::ar::import_member(&data[start..end])
                            .ok_or_else(|| LoadError::Malformed("unreadable short import object".to_owned()))?;
                        return Err(crate::ar::import_member_error(&import));
                    }
                    Ok(object::FileKind::Coff | object::FileKind::CoffBig) => {
                        let size = found.size;
                        let mut binary = Self::load_recovery(data, start..end, Vec::new(), wanted, recover)?;
                        binary.embedded = Some(Embedded { offset, size, file_size, trailing: available - size });
                        binary.archive_member = member;
                        return Ok(binary);
                    }
                    _ => {}
                }
            }
        }
        let candidate = crate::carve::executable(&data[start..])
            .ok_or_else(|| LoadError::Malformed(format!("no ELF, PE or Mach-O header at offset {offset:#x}")))?;
        if candidate.confidence != crate::carve::Confidence::Validated {
            let reason = candidate.notes.join("; ");
            return Err(LoadError::Malformed(format!("{} header at offset {offset:#x}: {reason}", candidate.kind)));
        }
        let size = match length {
            Some(length) if offset.checked_add(length).is_none() => {
                return Err(LoadError::Location(format!("offset {offset:#x} plus length {length:#x} overflows")));
            }
            Some(length) if length == 0 || length > available => {
                return Err(LoadError::Location(format!(
                    "length {length:#x} at offset {offset:#x} does not fit the file ({file_size:#x} bytes)"
                )));
            }
            Some(length) => length,
            None => candidate.extent.map_or(available, |extent| extent.min(available)),
        };
        // `size` is at most `available`, so the image ends within the mapping.
        let image = start..start + size as usize;
        let (slices, image) = match candidate.kind {
            crate::carve::Kind::MachOFat => {
                let fat = &data[image.clone()];
                let (slices, slice) = match object::FileKind::parse(fat)? {
                    object::FileKind::MachOFat64 => select_slice(fat_slices::<FatArch64>(fat)?, wanted)?,
                    _ => select_slice(fat_slices::<FatArch32>(fat)?, wanted)?,
                };
                (slices, start + slice.start..start + slice.end)
            }
            _ => (Vec::new(), image),
        };
        let mut binary = Self::load_recovery(data, image, slices, wanted, recover)?;
        binary.embedded = Some(Embedded { offset, size, file_size, trailing: available - size });
        binary.archive_member = member;
        Ok(binary)
    }

    /// Loads the ELF, PE or Mach-O image at `image` within `data`; `slices` lists a universal binary's
    /// architectures.
    fn load_recovery(
        data: MappedSource,
        image: Range<usize>,
        slices: Vec<Arch>,
        wanted: Option<Arch>,
        recover: bool,
    ) -> Result<Self, LoadError> {
        Self::load_native(Bytes::Mapped(data), image, slices, wanted, recover)
    }

    /// Re-parses an owned whole native image without claiming original-file provenance or recovering
    /// producer-derived Go/Objective-C facts. The caller is responsible for admitting permitted byte changes.
    pub fn from_owned_native_bytes(data: Vec<u8>, wanted: Arch) -> Result<Self, LoadError> {
        if data.len() > 256 * 1024 * 1024 {
            return Err(LoadError::Unsupported("owned native images are limited to 256 MiB".into()));
        }
        let length = data.len();
        Self::load_native(Bytes::Owned(data), 0..length, Vec::new(), Some(wanted), false)
    }

    fn load_native(
        data: Bytes,
        image: Range<usize>,
        slices: Vec<Arch>,
        wanted: Option<Arch>,
        recover: bool,
    ) -> Result<Self, LoadError> {
        #[cfg(test)]
        note_native_parse_entry();
        let image_bytes = &data[image.clone()];
        let parsed = object::File::parse(image_bytes)?;

        let format = match parsed.format() {
            object::BinaryFormat::Elf => Format::Elf,
            // A COFF object is the PE/COFF format: Windows code, laid out the way a relocatable object is.
            object::BinaryFormat::Pe | object::BinaryFormat::Coff => Format::Pe,
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
        let compressed_isa = (format == Format::Elf && matches!(arch, Arch::Mips | Arch::Mips64))
            .then(|| elf_mips_compressed_isa(&parsed))
            .flatten();
        // MIPS16e is decoded in 32-bit images; microMIPS and 64-bit MIPS16e are not.
        let mips16 = arch == Arch::Mips && compressed_isa == Some("MIPS16e");
        // ARM marks Thumb code addresses with the low bit, MIPS its MIPS16e ones; code lives at the even address.
        let code_address = |address: u64| if arch == Arch::Arm || mips16 { address & !1 } else { address };
        // A relocatable object is laid out at synthetic addresses with its relocations applied.
        // Windows on ARM is Thumb-2 only, as an M-profile processor is.
        let coff_thumb = parsed.format() == object::BinaryFormat::Coff && arch == Arch::Arm;
        let thumb_externs =
            coff_thumb || (format == Format::Elf && arch == Arch::Arm && elf_m_profile(&parsed, &mut Vec::new()));
        let relocated = crate::relocatable::load(&parsed, image_bytes, arch, !parsed.is_little_endian(), thumb_externs);
        // Where a symbol of the file lies: its value, or for a relocatable object its placed address (`None` for one
        // in a section that is not loaded).
        let place = |symbol: &object::Symbol| -> Option<u64> {
            match &relocated {
                Some(relocated) => relocated.symbol_address(symbol),
                None => Some(symbol.address()),
            }
        };

        // A relocatable object's segments are its placed sections (a COFF object's sections and a Mach-O object's one
        // segment are at the object's own addresses).
        let mut segments: Vec<Segment> = parsed
            .segments()
            .filter(|_| relocated.is_none())
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
        if let Some(relocated) = &relocated {
            segments.extend(relocated.segments.iter().cloned());
        }

        let mut sections: Vec<Section> = parsed
            .sections()
            .map(|section| {
                let file_range = section.file_range();
                let placed = relocated.as_ref().and_then(|relocated| relocated.section_address(section.index()));
                Section {
                    name: section.name().unwrap_or_default().to_owned(),
                    address: placed.unwrap_or_else(|| section.address()),
                    size: section.size(),
                    kind: section_kind_of(section.kind()),
                    file_offset: file_range.map(|(offset, _)| offset),
                    file_size: file_range.map_or(0, |(_, size)| size),
                }
            })
            .collect();
        // The segments a relocatable object's layout adds are sections too, so an address in them names one.
        if let Some(relocated) = &relocated {
            sections.extend(relocated.synthetic_sections());
        }

        let mut symbols: Vec<Symbol> = parsed
            .symbols()
            .chain(parsed.dynamic_symbols())
            // A relocatable object's common symbols are definitions too, placed in its `COMMON` segment.
            .filter(|symbol| symbol.is_definition() || (relocated.is_some() && symbol.is_common()))
            .filter_map(|symbol| {
                let name = symbol.name().ok().filter(|name| !name.is_empty())?;
                if matches!(arch, Arch::Arm | Arch::Aarch64) && arm_mapping_symbol(name).is_some() {
                    return None;
                }
                // The assembler's section-start labels of a Mach-O object (`ltmp0`) would shadow the functions there.
                if relocated.is_some() && format == Format::MachO && macho_section_label(name) {
                    return None;
                }
                let code = symbol.kind() == object::SymbolKind::Text;
                let address = place(&symbol)?;
                Some(Symbol {
                    name: name.to_owned(),
                    address: if code { code_address(address) } else { address },
                    size: symbol.size(),
                    kind: symbol_kind_of(symbol.kind()),
                })
            })
            .collect();
        // Without a `.dynsym` section (OpenWrt's `sstrip` removes every section header), the dynamic linker's own
        // route through PT_DYNAMIC still reaches the dynamic symbols.
        let sectionless = format == Format::Elf && parsed.dynamic_symbol_table().is_none();
        let mut dynamic = (format == Format::Elf).then(|| crate::dynsym::read(image_bytes, sectionless)).flatten();
        let dynamic_warnings =
            dynamic.as_mut().map(|dynamic| std::mem::take(&mut dynamic.warnings)).unwrap_or_default();
        let dynamic_symbols = dynamic.as_ref().map_or(&[][..], |dynamic| dynamic.symbols.as_slice());
        symbols.extend(dynamic_symbols.iter().filter(|symbol| symbol.is_definition() && !symbol.name.is_empty()).map(
            |symbol| {
                let code = symbol.is_function();
                Symbol {
                    name: symbol.name.clone(),
                    address: if code { code_address(symbol.value) } else { symbol.value },
                    size: symbol.size,
                    kind: match symbol.kind {
                        _ if code => SymbolKind::Function,
                        crate::dynsym::STT_OBJECT => SymbolKind::Data,
                        _ => SymbolKind::Other,
                    },
                }
            },
        ));
        if let Some(relocated) = &relocated {
            symbols.extend(relocated.externs.iter().map(|item| Symbol {
                name: item.name.clone(),
                address: item.address,
                size: 0,
                kind: if item.function { SymbolKind::Function } else { SymbolKind::Data },
            }));
            symbols.extend(relocated.import_pointers.iter().map(|(name, slot)| Symbol {
                name: name.clone(),
                address: *slot,
                size: 0,
                kind: SymbolKind::Data,
            }));
            // A COFF weak definition is named for what it defines, not for LLVM's `.weak.NAME.default.X` label.
            symbols.retain(|symbol| {
                !(symbol.name.starts_with(".weak.") && symbol.name.contains(".default."))
                    || !relocated.weak_definitions.iter().any(|(_, address, _)| *address == symbol.address)
            });
            symbols.extend(relocated.weak_definitions.iter().map(|(name, address, function)| Symbol {
                name: name.clone(),
                address: if *function { code_address(*address) } else { *address },
                size: 0,
                kind: if *function { SymbolKind::Function } else { SymbolKind::Data },
            }));
        }
        symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        symbols.dedup();

        let mut warnings = dynamic_warnings;
        let mut imports = parsed
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

        let mut exports = parsed
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

        if let Some(relocated) = &relocated {
            // Undefined symbols are what an object imports; its global definitions are what it exports.
            imports.extend(relocated.externs.iter().map(|item| Import { library: None, name: item.name.clone() }));
            let executable = |address| segments.iter().any(|s: &Segment| s.perms.execute && s.contains(address));
            exports = parsed
                .symbols()
                .filter(|symbol| symbol.is_definition() && symbol.is_global())
                .filter_map(|symbol| {
                    let name = symbol.name().ok().filter(|name| !name.is_empty())?;
                    let address = place(&symbol)?;
                    let address = if executable(code_address(address)) { code_address(address) } else { address };
                    Some(Export { name: name.to_owned(), address })
                })
                .collect();
        }
        if sectionless && let Some(dynamic) = &dynamic {
            let executable = |address| segments.iter().any(|s: &Segment| s.perms.execute && s.contains(address));
            imports.extend(
                dynamic
                    .symbols
                    .iter()
                    .filter(|symbol| symbol.is_undefined() && !symbol.name.is_empty())
                    .map(|symbol| Import { library: None, name: symbol.name.clone() }),
            );
            exports.extend(dynamic.symbols.iter().filter(|symbol| !symbol.name.is_empty()).filter_map(|symbol| {
                let address = symbol.exported_address()?;
                let address = if executable(code_address(address)) { code_address(address) } else { address };
                Some(Export { name: symbol.name.clone(), address })
            }));
        }

        // A zero entry (relative to the image base, which PE adds) is how every format spells "none".
        let raw_entry = match macho_main_entry_offset(&parsed) {
            Some(0) => None,
            Some(offset) => file_offset_to_address(&segments, offset),
            None => Some(parsed.entry()).filter(|&entry| entry != parsed.relative_address_base()),
        };
        let text_address = segments.iter().find(|segment| segment.name == "__TEXT").map(|segment| segment.address);
        let macho_starts =
            text_address.map(|text_address| starts::macho(&parsed, image_bytes, text_address)).unwrap_or_default();
        // Dynamic symbols read through PT_DYNAMIC mark Thumb functions with the low bit, as `.dynsym` ones do.
        let dynamic_functions = dynamic_symbols.iter().filter(|symbol| symbol.is_function() && symbol.is_definition());
        let marked = |symbol: &crate::dynsym::DynamicSymbol| symbol.value | u64::from(symbol.other & 0xf0 == 0xf0);
        let marked_constructors = dynamic.as_ref().map_or(&[][..], |dynamic| dynamic.constructors.as_slice());
        // MIPS16e code dispatches through tables of odd function pointers (busybox's applet table) that no
        // instruction references directly.
        let pointer_tables = if mips16 {
            let (headers_end, tables) = dynamic.as_ref().map_or_else(
                || (crate::dynsym::program_headers_end(image_bytes).unwrap_or(u64::MAX), Vec::new()),
                |dynamic| (dynamic.headers_end, dynamic.tables.clone()),
            );
            let scan = PointerTableScan { segments: &segments, image: image_bytes, headers_end, tables: &tables };
            scan.mips16_pointers(!parsed.is_little_endian())
        } else {
            Vec::new()
        };
        // A Thumb constructor in an ARM image is odd too; on MIPS16e an unsized one marks only its first
        // instruction (below).
        let arm_constructors = marked_constructors.iter().copied().filter(|_| arch == Arch::Arm);
        let marked_starts: Vec<u64> =
            macho_starts.iter().copied().chain(dynamic_functions.map(marked)).chain(arm_constructors).collect();
        let thumb = match arch {
            Arch::Arm => thumb_ranges(&parsed, &place, raw_entry, &segments, &sections, &marked_starts),
            _ => Vec::new(),
        };
        // A MIPS16e pointer with no size names only where a function starts: its range is its first instruction, and
        // the decoder keeps the mode along straight-line code from there.
        let mips16_ranges = if mips16 {
            let unsized_starts = marked_constructors.iter().chain(&pointer_tables).filter(|&&pointer| pointer & 1 == 1);
            let starts = unsized_starts.map(|&pointer| (pointer & !1)..(pointer & !1).saturating_add(2));
            merged(
                thumb_ranges(&parsed, &place, raw_entry, &segments, &sections, &marked_starts)
                    .into_iter()
                    .chain(starts)
                    .collect(),
            )
        } else {
            Vec::new()
        };
        let pointer_table_starts: Vec<u64> = pointer_tables.iter().map(|&pointer| code_address(pointer)).collect();
        let entry = raw_entry.map(code_address);
        let mut function_starts: Vec<u64> = macho_starts.into_iter().map(code_address).collect();
        function_starts.extend(pointer_table_starts);
        let big_endian = !parsed.is_little_endian();
        // ARMv6 and later big-endian images (BE8) store instructions little-endian; older BE32 ones do not.
        let be8_flag = |flags| match flags {
            object::FileFlags::Elf { e_flags, .. } => e_flags.0 & object::elf::EF_ARM_BE8.0 != 0,
            _ => false,
        };
        let be8 = arch == Arch::Arm && be8_flag(parsed.flags());
        let code_big_endian = big_endian && !be8;
        let exception_directory = starts::pe_exception_directory(&parsed);
        let pe_layout = (format == Format::Pe).then(|| crate::msvc::PeLayout {
            image_base: parsed.relative_address_base(),
            exception_directory: exception_directory.as_ref().map(starts::ExceptionDirectory::span),
        });
        let tls_directory = starts::pe_tls_directory(&parsed);
        let arm_exidx_tables = starts::arm_exidx_tables(&parsed, &mut warnings);
        let mips_got = crate::slots::mips_got(&parsed, dynamic.as_ref().map(|dynamic| dynamic.symbols.len()));
        if let Some(dynamic) = &mut dynamic {
            dynamic.mips_got = mips_got;
        }
        let mut import_slots = crate::slots::collect(&parsed, image_bytes, dynamic.as_ref(), &mut warnings);
        if let Some(relocated) = &relocated {
            import_slots.extend(relocated.got_imports());
            import_slots.sort_by_key(|slot| slot.address);
            warnings.extend(relocated.warnings.iter().cloned());
        }
        let rebases = crate::slots::chained_rebases(&parsed, image_bytes, &mut warnings);
        let details = crate::details::collect(&parsed);
        let elf_m_profile = format == Format::Elf && arch == Arch::Arm && elf_m_profile(&parsed, &mut warnings);
        let mut got_functions = crate::slots::mips_got_functions(&parsed, dynamic.as_ref());
        if let Some(relocated) = &relocated {
            got_functions.extend(relocated.got_functions.iter().cloned());
        }
        // Constructors and destructors run from the dynamic section, so nothing else may call them.
        let constructors = dynamic.as_ref().map_or(&[][..], |dynamic| dynamic.constructors.as_slice());
        // MIPS32 code is 4-byte aligned and MIPS16e code pointers are odd; anything else is not a function.
        let mips = matches!(arch, Arch::Mips | Arch::Mips64);
        let aligned = |start: u64| !mips || start & 3 == 0 || (mips16 && start & 1 == 1);
        function_starts.extend(constructors.iter().copied().filter(|&start| aligned(start)).map(code_address));
        let xtensa_abi_note =
            (format == Format::Elf && arch == Arch::Xtensa).then(|| elf_xtensa_call0(&parsed)).flatten();
        let xtensa_call0 = xtensa_abi_note == Some(true);
        let undecoded_isa = compressed_isa.filter(|_| !mips16);
        if let Some(isa) = undecoded_isa {
            warnings.push(undecoded_isa_note(isa));
        }
        let overlay = crate::details::overlay(&parsed, image_bytes, image.start as u64).unwrap_or_else(|warning| {
            warnings.push(warning);
            None
        });
        drop(parsed);
        let relocated = relocated.map(Box::new);

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
            mips_got,
            got_functions,
            rebases,
            data,
            snapshot_source: None,
            provenance: None,
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            embedded: None,
            go_table: None,
            go_table_address: None,
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw_identity: std::sync::OnceLock::new(),
            elf_m_profile,
            xtensa_call0,
            undecoded_isa,
            mips16,
            mips16_ranges,
            raw: None,
            image,
            relocated,
            archive_member: None,
        };
        binary.code_ranges = code_ranges(&binary.sections, &binary.segments);
        if arch == Arch::Xtensa && xtensa_abi_note.is_none() {
            binary.xtensa_call0 = xtensa_prologue_vote(&binary);
        }
        if coff_thumb && binary.relocated.is_some() {
            let executable = binary.segments.iter().filter(|segment| segment.perms.execute && segment.size > 0);
            let ranges = executable.map(|segment| segment.address..segment.address.saturating_add(segment.size));
            binary.thumb = merged(binary.thumb.drain(..).chain(ranges).collect());
        }
        if elf_m_profile {
            // An M-profile processor has no A32 state: all of its executable memory is Thumb, `$d` islands and code
            // no `$t` or odd symbol covers alike, as a Cortex-M Raw image's code regions are.
            let executable = binary.segments.iter().filter(|segment| segment.perms.execute && segment.size > 0);
            let ranges = executable.map(|segment| segment.address..segment.address.saturating_add(segment.size));
            binary.thumb = merged(binary.thumb.drain(..).chain(ranges).collect());
        }
        if let Some(tables) = arm_exidx_tables {
            let (starts, warnings) = starts::arm_exidx(&binary, &tables);
            function_starts.extend(starts);
            binary.warnings.extend(warnings);
        }
        binary.global_pointer = binary.find_global_pointer();
        if binary.sections.iter().any(|section| section.name == ".got")
            && !matches!(binary.arch.default_pointer_size(), Some(4 | 8))
        {
            binary
                .warnings
                .push("GOT entries not inspected: native pointer-slot width is unavailable or unsupported".to_owned());
        }
        binary.got = binary.read_got();
        if let Some(directory) = exception_directory {
            let (starts, warning) = starts::pe(&binary, &directory);
            function_starts.extend(starts);
            binary.warnings.extend(warning);
        }
        if let Some(directory) = tls_directory {
            function_starts.extend(starts::pe_tls(&binary, &directory));
        }
        binary.pe_layout = pe_layout;
        let msvc = crate::msvc::read(&binary);
        function_starts.extend(crate::msvc::code_targets(&binary, &msvc));
        binary.msvc = (binary.format == Format::Pe).then_some(msvc);
        // musl's MIPS `_start` reaches `_start_c` only through a word after its `bal`, which discovery cannot follow.
        if let Some(pointer) = binary.musl_mips_start_c_pointer() {
            function_starts.push(pointer & !1);
            if pointer & 1 == 1 {
                let start = pointer & !1;
                binary.mips16_ranges =
                    merged(binary.mips16_ranges.drain(..).chain(std::iter::once(start..start + 2)).collect());
            }
        }
        let (starts, warning) = starts::eh_frame(&binary);
        function_starts.extend(starts);
        binary.warnings.extend(warning);
        // Stripped firmware names its interrupt handlers only in the vector table, as a Raw image does.
        if elf_m_profile && let Some(table) = crate::raw_vectors::elf_table(&binary) {
            function_starts.extend(table.handlers());
        }
        function_starts.retain(|&start| binary.is_code(start));
        function_starts.sort_unstable();
        function_starts.dedup();
        binary.function_starts = function_starts;
        // Stripped Go binaries keep their function names only in the pclntab; recover them as symbols.
        if recover {
            let go = binary.recover_go_symbols();
            binary.warnings.extend(go.warnings);
            let objc = binary.recover_objc_symbols();
            binary.warnings.extend(objc.warnings);
        }
        Ok(binary)
    }

    /// What a decoder needs to read this image's code.
    pub fn target(&self) -> rampage_arch::Target {
        rampage_arch::Target {
            arch: self.arch,
            big_endian: self.code_big_endian,
            data_big_endian: self.big_endian,
            thumb: if self.mips16 { self.mips16_ranges.clone().into() } else { self.thumb.clone().into() },
            global_pointer: self.global_pointer,
            got: self.got.clone(),
            m_profile: self.m_profile(),
            mips16: self.mips16,
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
        // Without section headers, the dynamic section's DT_PLTGOT gives the GOT.
        let dynamic_got = || self.mips_got.and_then(|layout| layout.address.checked_add(0x7ff0));
        match self.arch {
            Arch::Mips | Arch::Mips64 => symbol("_gp").or_else(|| got(0x7ff0)).or_else(dynamic_got),
            Arch::PowerPc64 => symbol(".TOC.").or_else(|| got(0x8000)),
            Arch::Riscv32 | Arch::Riscv64 => symbol("__global_pointer$"),
            _ => None,
        }
    }

    /// The `.got` section's entries, in the image's byte order; for a dynamically linked MIPS ELF, the GOT its
    /// dynamic section describes, with its local entries marked.
    fn read_got(&self) -> Option<rampage_arch::Got> {
        let size = usize::from(self.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8))?);
        let section = self.sections.iter().find(|section| section.name == ".got");
        let mips = self.mips_got.filter(|layout| section.is_none_or(|section| section.address == layout.address));
        let mips = mips.and_then(|layout| {
            // A layout that runs past the mapped bytes is malformed: the section, if any, is used instead.
            let length = layout.entries().checked_mul(size as u64)?;
            self.read(layout.address, length)?;
            Some((layout.address, length, usize::try_from(layout.local).ok()?))
        });
        let (address, length, local_entries) = match (mips, section) {
            (Some(layout), _) => layout,
            (None, Some(section)) => (section.address, section.size, 0),
            (None, None) => return None,
        };
        let bytes = self.read(address, length)?;
        let entries = bytes.chunks_exact(size).filter_map(|entry| read_uint(entry, 0, size, self.big_endian)).collect();
        Some(rampage_arch::Got { address, entries, local_entries })
    }

    /// A decoder for this image's code.
    pub fn decoder(&self) -> Result<Box<dyn rampage_arch::Disassembler>, rampage_arch::UnsupportedArch> {
        rampage_arch::decoder(&self.target())
    }

    /// What the file stores for `section`, from its own file offset rather than through a segment, so it also
    /// serves sections outside any segment (relocatable objects, unloaded ELF sections). A section running past
    /// the end of a truncated image is cut short there, like [`Self::read_to_segment_end`]. `None` for a zero-fill
    /// section or one that starts past the end of the image.
    pub fn section_file_bytes(&self, section: &Section) -> Option<&[u8]> {
        let image = self.image_bytes();
        let start = usize::try_from(section.file_offset?).ok()?;
        let len = usize::try_from(section.file_size).unwrap_or(usize::MAX);
        image.get(start..start.saturating_add(len).min(image.len()))
    }

    /// The bytes of this image: the whole file, one slice of a universal binary, or an embedded image.
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
    /// The address ranges of code, ascending, as [`Binary::is_code`] reads them.
    pub fn code_ranges(&self) -> &[Range<u64>] {
        &self.code_ranges
    }

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

    pub(crate) fn pe_layout(&self) -> Option<crate::msvc::PeLayout> {
        self.pe_layout
    }

    /// The MSVC C++ vftables and exception tables of an x86 or x64 PE image, read once at load under a bounded
    /// budget; `None` for other formats.
    pub fn msvc_metadata(&self) -> Option<&crate::msvc::MsvcMetadata> {
        self.msvc.as_ref()
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
        self.loaded_bytes().get(start..end)
    }

    /// The bytes segments map: the image's, or a relocatable object's loaded copy with its relocations applied.
    fn loaded_bytes(&self) -> &[u8] {
        match &self.relocated {
            Some(relocated) => &relocated.bytes,
            None => self.image_bytes(),
        }
    }

    /// A relocatable object's layout: its relocation sites, externs and the relocation types left unapplied.
    pub fn relocated(&self) -> Option<&crate::relocatable::Relocated> {
        self.relocated.as_deref()
    }

    /// Reads a pointer only from readable, non-writable memory; captures do not imply future load invariance.
    pub fn read_pointer(&self, address: u64, size: u8) -> Option<u64> {
        self.read_constant(address, size).filter(|_| matches!(size, 4 | 8))
    }

    /// Reads a 1- to 8-byte value only from file-backed, readable, non-writable memory, such as a switch table.
    pub fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
        let permissions = self.segment_containing(address)?.perms;
        if !permissions.read || permissions.write {
            return None;
        }
        read_uint(self.read(address, u64::from(size))?, 0, usize::from(size), self.big_endian)
    }

    /// The address a pointer stored at `address` holds once loaded, when a Mach-O chained fixup rebases it. The
    /// stored bytes are then a chain encoding, so they must not be read as an address.
    pub fn rebase_target(&self, address: u64) -> Option<u64> {
        let index = self.rebases.binary_search_by_key(&address, |&(location, _)| location).ok()?;
        Some(self.rebases[index].1)
    }

    /// Every Mach-O chained rebase as (location, loaded target), sorted by location.
    pub fn rebases(&self) -> &[(u64, u64)] {
        &self.rebases
    }

    /// Whether this image's pointers are encoded as chained fixups rather than stored as addresses.
    pub fn has_chained_fixups(&self) -> bool {
        !self.rebases.is_empty()
    }

    /// Returns the file-backed bytes from `address` to the end of its segment's file data.
    /// Truncated files are cut short at the end of the file instead of failing.
    pub fn read_to_segment_end(&self, address: u64) -> Option<&[u8]> {
        let segment = self.segment_containing(address)?;
        let offset = address - segment.address;
        let in_segment = segment.file_size.checked_sub(offset)?;
        let file_position = segment.file_offset.checked_add(offset)?;
        let in_file = (self.loaded_bytes().len() as u64).checked_sub(file_position)?;
        self.read(address, in_segment.min(in_file)).filter(|bytes| !bytes.is_empty())
    }

    /// Recovers function names from an embedded Go `gopclntab` and attaches them as `SymbolKind::Function`
    /// symbols, the way IDA and Ghidra name stripped Go binaries. This is purely additive: it fills only
    /// addresses that have no symbol yet, so real symbols always win, and it never alters how the image
    /// loaded. The returned [`crate::gopclntab::GoReport`] is the separately typed record of what the table
    /// contributed; its `GoFunction` entries are the source marker distinguishing recovered names from real
    /// ones. An image with no usable table yields an empty report, never an error.
    pub fn recover_go_symbols(&mut self) -> crate::gopclntab::GoReport {
        #[cfg(test)]
        note_optional_recovery_entry();
        let mut report = self.read_gopclntab();
        if report.functions.is_empty() {
            return report;
        }
        self.go_table = report.version;
        self.go_table_address = report.table_address;
        self.go_arguments = match self.read_go_arguments(&report) {
            Ok(arguments) => arguments,
            Err(reason) => {
                report.warn(reason.to_owned());
                std::collections::BTreeMap::new()
            }
        };
        let mut taken: std::collections::HashSet<u64> = self.symbols.iter().map(|symbol| symbol.address).collect();
        for function in &report.functions {
            if !taken.insert(function.address) {
                continue;
            }
            self.symbols.push(Symbol {
                name: function.name.clone(),
                address: function.address,
                size: 0,
                kind: SymbolKind::Function,
            });
        }
        self.symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        report
    }

    /// Locates the `gopclntab` via its dedicated section (`.gopclntab` on ELF, `__gopclntab` on Mach-O) and
    /// parses it against the image's text base, pointer width and byte order.
    fn read_gopclntab(&self) -> crate::gopclntab::GoReport {
        let mut report = crate::gopclntab::GoReport::default();
        let text = self.sections.iter().find(|section| section.name == ".text" || section.name == "__text");
        let Some(section) = self.sections.iter().find(|section| is_gopclntab(&section.name)) else {
            return text.map_or(report, |text| self.scan_gopclntab(text.address));
        };
        let Some(bytes) = self.read(section.address, section.size) else {
            report.warn("gopclntab section bytes are not mapped".to_owned());
            return report;
        };
        let Some(text) = text else {
            report.warn("gopclntab found but no text section to anchor addresses".to_owned());
            return report;
        };
        let width = match go_pointer_size(self.arch.default_pointer_size()) {
            Ok(width) => width,
            Err(reason) => {
                report.warn(reason.to_owned());
                return report;
            }
        };
        let mut report = crate::gopclntab::parse(bytes, text.address, width, self.big_endian);
        report.table_address = Some(section.address);
        report
    }

    /// Fallback for a stripped or packed image whose pclntab keeps no recognizable section name: scans the
    /// read-only and relro data sections for the table (an externally linked PIE merges it into a writable
    /// `.data.rel.ro`). A candidate is accepted only once it parses cleanly and all of its recovered addresses
    /// sit in code, so arbitrary data cannot masquerade as a table.
    fn scan_gopclntab(&self, text_base: u64) -> crate::gopclntab::GoReport {
        let pointer_size = match go_pointer_size(self.arch.default_pointer_size()) {
            Ok(width) => width,
            Err(reason) => {
                let mut report = crate::gopclntab::GoReport::default();
                report.warn(reason.to_owned());
                return report;
            }
        };
        for section in &self.sections {
            let relro = section.kind == SectionKind::Data && section.name.starts_with(".data.rel.ro");
            if !(section.kind == SectionKind::ReadOnlyData || relro) || section.size == 0 {
                continue;
            }
            let Some(bytes) = self.read(section.address, section.size) else { continue };
            let Some((offset, mut report)) =
                crate::gopclntab::scan_blob(bytes, text_base, pointer_size, self.big_endian)
            else {
                continue;
            };
            report.table_address = section.address.checked_add(offset as u64);
            let sample: Vec<u64> = report.functions.iter().take(32).map(|function| function.address).collect();
            if !sample.is_empty() && sample.iter().all(|&address| self.is_code(address)) {
                return report;
            }
        }
        crate::gopclntab::GoReport::default()
    }

    /// Decodes the argument layout of each register-ABI function in `report`. Assembly functions use ABI0,
    /// and a function with arguments but no ArgInfo has no recoverable inputs; both are left out.
    fn read_go_arguments(
        &self,
        report: &crate::gopclntab::GoReport,
    ) -> Result<std::collections::BTreeMap<u64, crate::gopclntab::GoArguments>, &'static str> {
        let pointer_size = go_pointer_size(self.arch.default_pointer_size())?;
        let framed: Vec<_> = report
            .functions
            .iter()
            .filter_map(|function| Some((function.address, function.frame?)))
            .filter(|(_, frame)| !frame.assembly)
            .collect();
        let gofunc = self.find_gofunc(report, &framed, pointer_size);
        Ok(framed
            .into_iter()
            .filter_map(|(address, frame)| {
                let inputs = match frame.arg_info {
                    Some(offset) => self.arg_info(gofunc?, offset)?,
                    None if frame.args == 0 => Vec::new(),
                    None => return None,
                };
                Some((address, crate::gopclntab::GoArguments { args: frame.args, inputs }))
            })
            .collect())
    }

    fn arg_info(&self, gofunc: u64, offset: u32) -> Option<Vec<Vec<crate::gopclntab::GoSlot>>> {
        let bytes = self.read_to_segment_end(gofunc.checked_add(u64::from(offset))?)?;
        crate::gopclntab::decode_arg_info(&bytes[..bytes.len().min(crate::gopclntab::ARG_INFO_MAX_LEN)])
    }

    /// `moduledata.gofunc`, the base of ArgInfo offsets. `moduledata` begins with a pointer to the pclntab and
    /// holds `minpc` 20 words in; `gofunc` follows a run of fields that differs between Go releases, so each
    /// plausible position is tried and the one under which sampled ArgInfo all decode is taken.
    fn find_gofunc(
        &self,
        report: &crate::gopclntab::GoReport,
        framed: &[(u64, crate::gopclntab::GoFrame)],
        pointer_size: u8,
    ) -> Option<u64> {
        const MINPC: usize = 20;
        const GOFUNC_CANDIDATES: std::ops::RangeInclusive<usize> = 36..=48;
        let table = report.table_address?;
        let minpc = report.functions.iter().map(|function| function.address).min()?;
        let sample: Vec<u32> = framed.iter().filter_map(|(_, frame)| frame.arg_info).take(64).collect();
        if sample.is_empty() {
            return None;
        }
        let pointer = usize::from(pointer_size);
        for section in &self.sections {
            if !matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData) {
                continue;
            }
            let Some(bytes) = self.read(section.address, section.size) else { continue };
            let word =
                |at: usize, index: usize| read_uint(bytes, at.checked_add(index * pointer)?, pointer, self.big_endian);
            for at in (0..bytes.len()).step_by(pointer) {
                if word(at, 0) != Some(table) || word(at, MINPC) != Some(minpc) {
                    continue;
                }
                let found = GOFUNC_CANDIDATES.filter_map(|index| word(at, index)).find(|&candidate| {
                    candidate != 0 && sample.iter().all(|&offset| self.arg_info(candidate, offset).is_some())
                });
                if found.is_some() {
                    return found;
                }
            }
        }
        None
    }
}

fn go_pointer_size(width: Option<u8>) -> Result<u8, &'static str> {
    width
        .filter(|width| matches!(width, 4 | 8))
        .ok_or("Go runtime metadata unavailable: native word width is unknown or unsupported")
}

/// Maps the file at `path`, or the executable inside the bundle directory it names.
fn map_executable(path: &Path) -> Result<MappedSource, LoadError> {
    let resolved = crate::container::resolve_executable(path)?;
    let path = resolved.as_path();
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    let file = File::open(path).map_err(io_error)?;
    let stamp = file.metadata().ok().and_then(|metadata| BackingStamp::from_metadata(&metadata));
    // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope,
    // the same assumption every mmap-based binary tool makes.
    let map = unsafe { Mmap::map(&file) }.map_err(io_error)?;
    let after = file.metadata().ok().and_then(|metadata| BackingStamp::from_metadata(&metadata));
    let stamp = stamp.filter(|stamp| Some(*stamp) == after);
    Ok(MappedSource { map, file, path: std::path::absolute(path).unwrap_or_else(|_| path.to_owned()), stamp })
}

#[cfg(unix)]
fn map_executable_checked(path: &Path, max_source_bytes: usize) -> Result<MappedSource, LoadError> {
    use rustix::fs::{Mode, OFlags, open};
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(open(path, flags, Mode::empty()).map_err(|error| io_error(error.into()))?);
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_source_bytes as u64 {
        if max_source_bytes == 128 * 1024 * 1024 {
            return Err(LoadError::Unsupported(
                "checked source must be a nonempty regular file of at most 128 MiB".into(),
            ));
        }
        return Err(LoadError::Unsupported(format!(
            "checked source must be a nonempty regular file within the {max_source_bytes}-byte limit"
        )));
    }
    let stamp = BackingStamp::from_metadata(&metadata)
        .ok_or_else(|| LoadError::Unsupported("checked source identity is unavailable".into()))?;
    // SAFETY: this read-only mapping is capped before creation. External truncation still requires quiescent inputs.
    let map = unsafe { memmap2::MmapOptions::new().len(metadata.len() as usize).map(&file) }.map_err(io_error)?;
    let source = MappedSource { map, file, path: std::path::absolute(path).map_err(io_error)?, stamp: Some(stamp) };
    if !std::fs::symlink_metadata(path).map_err(io_error)?.is_file() {
        return Err(LoadError::Unsupported("checked source pathname is no longer a regular file".into()));
    }
    source.validate()?;
    Ok(source)
}

#[cfg(not(unix))]
fn map_executable_checked(_: &Path, _: usize) -> Result<MappedSource, LoadError> {
    Err(LoadError::Unsupported("checked workspace sources are unsupported on this platform".into()))
}

fn consume_admitted_source<T>(
    data: MappedSource,
    admit: impl FnOnce(&[u8]) -> Result<(), LoadError>,
    consume: impl FnOnce(MappedSource) -> Result<T, LoadError>,
) -> Result<T, LoadError> {
    let admitted = admit(&data);
    data.validate()?;
    let pathname =
        std::fs::symlink_metadata(&data.path).map_err(|source| LoadError::Io { path: data.path.clone(), source })?;
    if !pathname.is_file() {
        return Err(LoadError::Unsupported("checked source pathname is no longer a regular file".into()));
    }
    admitted?;
    consume(data)
}

#[cfg(all(test, unix))]
mod checked_admission_tests {
    #[test]
    fn rejecting_actual_macho_mapping_never_enters_native_open_or_object_parsing() {
        use super::*;
        for name in ["hello-x64.macho", "hello-x64-stripped.macho"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
            let before = NATIVE_PARSE_ENTRIES.with(std::cell::Cell::get);
            let mut called = false;
            let result = Binary::open_image_checked_admitted(&path, None, None, 16 * 1024 * 1024, |_| {
                called = true;
                assert_eq!(NATIVE_PARSE_ENTRIES.with(std::cell::Cell::get), before);
                Err(LoadError::Unsupported("deliberate mapped admission refusal".into()))
            });
            assert!(called && result.is_err());
            assert_eq!(NATIVE_PARSE_ENTRIES.with(std::cell::Cell::get), before);
            Binary::open_image_checked_admitted(&path, None, None, 16 * 1024 * 1024, |_| Ok(())).unwrap();
            assert!(NATIVE_PARSE_ENTRIES.with(std::cell::Cell::get) > before);
        }
    }

    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct Files {
        source: PathBuf,
        replacement: PathBuf,
    }

    impl Files {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let source = std::env::temp_dir().join(format!(
                "rampage-admitted-loader-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            let replacement = source.with_extension("replacement");
            let file = File::options().write(true).create_new(true).open(&source).unwrap();
            let files = Self { source, replacement };
            file.set_len(4).unwrap();
            files
        }
    }

    impl Drop for Files {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.source);
            let _ = std::fs::remove_file(&self.replacement);
        }
    }

    #[test]
    fn replacement_is_admitted_on_actual_mapping_and_rejection_never_enters_producer() {
        let files = Files::new();
        let original = map_executable_checked(&files.source, 1024).unwrap();
        std::fs::write(&files.replacement, b"replacement profile").unwrap();
        std::fs::rename(&files.replacement, &files.source).unwrap();
        assert!(original.validate().is_err());
        let replacement = map_executable_checked(&files.source, 1024).unwrap();
        let producer_entered = Cell::new(false);
        let result: Result<(), LoadError> = consume_admitted_source(
            replacement,
            |actual| {
                assert_eq!(actual, b"replacement profile");
                Err(LoadError::Unsupported("raw replacement rejected".into()))
            },
            |_| {
                producer_entered.set(true);
                Ok(())
            },
        );
        assert!(result.unwrap_err().to_string().contains("raw replacement rejected"));
        assert!(!producer_entered.get());
    }

    #[test]
    fn lower_limit_applies_to_replacement_descriptor_before_mapping_or_callback() {
        let files = Files::new();
        let original = map_executable_checked(&files.source, 1024).unwrap();
        File::create(&files.replacement).unwrap().set_len(1025).unwrap();
        std::fs::rename(&files.replacement, &files.source).unwrap();
        let callback_entered = Cell::new(false);
        let result = Binary::open_image_checked_admitted(&files.source, None, None, 1024, |_| {
            callback_entered.set(true);
            Ok(())
        });
        assert!(result.unwrap_err().to_string().contains("1024-byte limit"));
        assert!(!callback_entered.get());
        assert!(original.validate().is_err());
    }

    #[test]
    fn callback_time_replacement_is_revalidated_before_entering_any_producer() {
        let files = Files::new();
        let source = map_executable_checked(&files.source, 1024).unwrap();
        std::fs::write(&files.replacement, b"other bytes").unwrap();
        let producer_entered = Cell::new(false);
        let result: Result<(), LoadError> = consume_admitted_source(
            source,
            |_| {
                std::fs::rename(&files.replacement, &files.source).unwrap();
                Ok(())
            },
            |_| {
                producer_entered.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!producer_entered.get());
    }
}

/// Whether a section name is the Go pclntab under any of its spellings. Go's linker names a PIE's relro copy
/// `.data.rel.ro.gopclntab`, which Go's own objfile reader falls back to.
fn is_gopclntab(name: &str) -> bool {
    matches!(name, ".gopclntab" | ".data.rel.ro.gopclntab" | "__gopclntab")
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

/// Whether `name` is a section-start label an assembler gives a Mach-O object's sections (`ltmp0`, `ltmp1`).
fn macho_section_label(name: &str) -> bool {
    name.strip_prefix("ltmp").is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
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

struct SliceHeader {
    arch: Option<Arch>,
    range: Option<Range<usize>>,
}

fn fat_headers<Fat: FatArch>(data: &[u8]) -> Result<Vec<SliceHeader>, LoadError> {
    let fat = MachOFatFile::<Fat>::parse(data)?;
    if fat.arches().len() > 64 {
        return Err(LoadError::Malformed("architecture probe exceeds the 64-slice limit".to_owned()));
    }
    let table_end = 8 + std::mem::size_of_val(fat.arches());
    Ok(fat
        .arches()
        .iter()
        .map(|slice| {
            let start = usize::try_from(slice.offset().into()).ok();
            let length = usize::try_from(slice.size().into()).ok();
            let range = start
                .zip(length)
                .and_then(|(start, length)| Some(start..start.checked_add(length)?))
                .filter(|range| range.end <= data.len() && range.start >= table_end && !range.is_empty())
                .filter(|range| slice.align() <= 20 && range.start.is_multiple_of(1usize << slice.align()));
            SliceHeader { arch: arch_of(slice.architecture()), range }
        })
        .collect())
}

fn select_universal<Fat: FatArch>(data: &[u8], wanted: Option<Arch>) -> Result<(Vec<Arch>, Range<usize>), LoadError> {
    let Some(wanted) = wanted else { return select_slice(fat_slices::<Fat>(data)?, None) };
    let headers = fat_headers::<Fat>(data)?;
    let present: Vec<_> = headers.iter().filter_map(|header| header.arch).collect();
    let mut selected = headers.iter().filter(|header| header.arch == Some(wanted));
    let first = selected.next().ok_or_else(|| {
        LoadError::Unsupported(format!(
            "no {wanted} slice; the file contains {}",
            present.iter().map(Arch::to_string).collect::<Vec<_>>().join(", "),
        ))
    })?;
    if selected.next().is_some() {
        return Err(LoadError::Unsupported(format!("multiple {wanted} slices cannot be selected uniquely")));
    }
    let range = first
        .range
        .clone()
        .ok_or_else(|| LoadError::Malformed(format!("{wanted} slice has an invalid file range or alignment",)))?;
    if !matches!(
        object::FileKind::parse(&data[range.clone()]),
        Ok(object::FileKind::MachO32 | object::FileKind::MachO64)
    ) {
        return Err(LoadError::Malformed(format!("{wanted} universal slice is not a Mach-O image")));
    }
    Ok((present, range))
}

fn explicit_fat_image<Fat: FatArch>(
    data: &[u8],
    start: usize,
    length: Option<u64>,
    wanted: Arch,
) -> Result<(usize, Vec<Arch>, Range<usize>), LoadError> {
    let available = data.len() - start;
    let size = usize::try_from(length.unwrap_or(available as u64))
        .ok()
        .filter(|&size| size > 0 && size <= available)
        .ok_or_else(|| LoadError::Location("universal image length is outside the file".to_owned()))?;
    let view = &data[start..start + size];
    let headers = fat_headers::<Fat>(view)?;
    let extent = headers.iter().filter_map(|header| header.range.as_ref().map(|range| range.end)).max().unwrap_or(0);
    let size = if length.is_some() { size } else { extent };
    let (slices, selected) = select_universal::<Fat>(view, Some(wanted))?;
    Ok((size, slices, start + selected.start..start + selected.end))
}

fn declared_architectures<Fat: FatArch>(data: &[u8]) -> Result<Vec<Arch>, LoadError> {
    let mut architectures = Vec::new();
    for slice in fat_headers::<Fat>(data)? {
        if let Some(arch) = slice.arch {
            if architectures.contains(&arch) {
                return Err(LoadError::Unsupported(format!(
                    "multiple {arch} slices cannot be selected uniquely; open a thin image at an explicit offset",
                )));
            }
            architectures.push(arch);
        }
    }
    Ok(architectures)
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

pub(crate) fn arch_of(architecture: object::Architecture) -> Option<Arch> {
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
        A::Xtensa => Arch::Xtensa,
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

/// What an Xtensa ELF's `.xtensa.info` note says of its ABI: `Some(true)` for call0 (`ABI=` with a nonzero value;
/// ESP8266's LX106 has no register windows), `Some(false)` for windowed (`ABI=0`), `None` without the note or the
/// line, when [`xtensa_prologue_vote`] decides.
fn elf_xtensa_call0(parsed: &object::File) -> Option<bool> {
    let data = parsed.section_by_name(".xtensa.info").and_then(|section| section.data().ok())?;
    let text = String::from_utf8_lossy(data);
    let value = text.split(['\n', '\0']).find_map(|line| line.trim().strip_prefix("ABI="))?;
    Some(value.trim() != "0")
}

/// Whether Xtensa code with nothing saying its ABI is call0: at 4-byte aligned addresses of its executable bytes
/// (where both ABIs start functions), call0 frame allocations (`addi a1, a1, -N`) outnumber windowed `entry a1, N`
/// prologues four to one. Literal-pool words can spell either, so neither count alone decides.
pub(crate) fn xtensa_prologue_vote(binary: &Binary) -> bool {
    let (mut windowed, mut call0) = (0usize, 0usize);
    for segment in binary.segments.iter().filter(|segment| segment.perms.execute) {
        let Some(bytes) = binary.read(segment.address, segment.size.min(segment.file_size)) else { continue };
        let first = (segment.address.next_multiple_of(4) - segment.address) as usize;
        for offset in (first..bytes.len().saturating_sub(2)).step_by(4) {
            let [a, b, c] = [bytes[offset], bytes[offset + 1], bytes[offset + 2]];
            if a == 0x36 && b & 0xf == 1 && ((u32::from(c) << 4) | u32::from(b >> 4)) >= 2 {
                windowed += 1;
            } else if a == 0x12 && b == 0xc1 && c >= 0x80 && c & 0xf == 0 {
                call0 += 1;
            }
        }
    }
    call0 > 0 && windowed.saturating_mul(4) < call0
}

/// Most pointers [`PointerTableScan::mips16_pointers`] returns.
const MAX_MIPS16_TABLE_POINTERS: usize = 1 << 16;
/// Fewest consecutive, distinct odd code pointers that make a table.
const MIN_MIPS16_TABLE_RUN: usize = 4;
/// Least span of a table's targets: a table whose targets all lie this close together is a switch's label table
/// inside one function (`.word L|1`), not a table of functions.
const MIN_MIPS16_TABLE_SPAN: u64 = 0x80;

/// What a scan for MIPS16e function-pointer tables must leave alone.
struct PointerTableScan<'a> {
    segments: &'a [Segment],
    image: &'a [u8],
    /// File offset just past the program headers: the ELF header and program headers are not code, though the
    /// first executable segment of an image based at 0 covers them.
    headers_end: u64,
    /// Address ranges of the dynamic section's tables (hash, symbol, string and relocation tables): data whose
    /// small odd words (hash buckets, symbol indices) would otherwise pass for pointers into code at 0.
    tables: &'a [Range<u64>],
}

impl PointerTableScan<'_> {
    fn file_offset(&self, address: u64) -> Option<u64> {
        let segment = self.segments.iter().find(|segment| {
            address >= segment.address && address - segment.address < segment.file_size.min(segment.size)
        })?;
        segment.file_offset.checked_add(address - segment.address)
    }

    fn in_tables(&self, address: u64) -> bool {
        self.tables.iter().any(|range| range.contains(&address))
    }

    /// The file bytes from `address` on.
    fn bytes(&self, address: u64) -> Option<&[u8]> {
        self.image.get(usize::try_from(self.file_offset(address)?).ok()?..)
    }

    /// Whether `address` starts a NUL-terminated run of at least `minimum` printable bytes.
    fn starts_text(&self, address: u64, minimum: usize) -> bool {
        let Some(bytes) = self.bytes(address) else { return false };
        let printable = |byte: u8| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
        let run = bytes.iter().take(256).take_while(|&&byte| printable(byte)).count();
        run >= minimum && bytes.get(run) == Some(&0)
    }

    /// Whether `value` may point at a MIPS16e function: odd, inside file-backed executable memory past the headers
    /// and outside the dynamic tables, at no string (read-only data shares the executable segment, and a table of
    /// string pointers would pass for code pointers), and at bytes that decode as a MIPS16e instruction.
    fn plausible(&self, value: u64, big_endian: bool) -> bool {
        let code = value & !1;
        let executable = self.segments.iter().any(|segment| {
            segment.perms.execute
                && code >= segment.address
                && code - segment.address < segment.file_size.min(segment.size)
        });
        // At the even address, where code starts, a short printable run before a NUL can be instructions
        // (`li $v0, 0` is `6a 00`), so only a longer one counts as a string there.
        value & 1 == 1
            && executable
            && self.file_offset(code).is_some_and(|offset| offset >= self.headers_end)
            && !self.in_tables(code)
            && !self.starts_text(value, 1)
            && !self.starts_text(code, 3)
            && self.bytes(code).is_some_and(|bytes| rampage_arch::decodes_as_mips16(bytes, big_endian))
    }

    /// MIPS16e function pointers in tables: runs of at least [`MIN_MIPS16_TABLE_RUN`] consecutive aligned words in
    /// the segments' file data outside the headers and dynamic tables, each [`Self::plausible`], with that many
    /// distinct targets spread over at least [`MIN_MIPS16_TABLE_SPAN`]. Returned with the ISA bit, deduplicated.
    fn mips16_pointers(&self, big_endian: bool) -> Vec<u64> {
        let mut found = std::collections::BTreeSet::new();
        let accept = |run: &mut Vec<u64>, found: &mut std::collections::BTreeSet<u64>| {
            let distinct: std::collections::BTreeSet<u64> = run.iter().copied().collect();
            let span = distinct.last().zip(distinct.first()).map_or(0, |(last, first)| last - first);
            if distinct.len() >= MIN_MIPS16_TABLE_RUN && span >= MIN_MIPS16_TABLE_SPAN {
                found.extend(distinct);
            }
            run.clear();
        };
        for segment in self.segments {
            let Some(start) = usize::try_from(segment.file_offset).ok() else { continue };
            let length = usize::try_from(segment.file_size).unwrap_or(usize::MAX);
            let Some(bytes) = self.image.get(start..start.saturating_add(length).min(self.image.len())) else {
                continue;
            };
            let skip = segment.address.next_multiple_of(4) - segment.address;
            let mut run = Vec::new();
            let words = bytes.get(skip as usize..).unwrap_or_default().as_chunks::<4>().0;
            for (index, &word) in words.iter().enumerate() {
                let at = segment.address.saturating_add(skip + 4 * index as u64);
                let offset = segment.file_offset.saturating_add(skip + 4 * index as u64);
                let value = u64::from(if big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) });
                if offset >= self.headers_end && !self.in_tables(at) && self.plausible(value, big_endian) {
                    run.push(value);
                } else {
                    accept(&mut run, &mut found);
                }
            }
            accept(&mut run, &mut found);
            if found.len() >= MAX_MIPS16_TABLE_POINTERS {
                break;
            }
        }
        found.into_iter().take(MAX_MIPS16_TABLE_POINTERS).collect()
    }
}

/// `e_flags` bits of a MIPS ELF holding MIPS16e (`EF_MIPS_ARCH_ASE_M16`) or microMIPS (`EF_MIPS_MICROMIPS`) code.
const EF_MIPS_ARCH_ASE_M16: u32 = 0x0400_0000;
const EF_MIPS_MICROMIPS: u32 = 0x0200_0000;

/// The compressed instruction set a MIPS ELF header marks, if any.
fn elf_mips_compressed_isa(parsed: &object::File) -> Option<&'static str> {
    let object::FileFlags::Elf { e_flags, .. } = parsed.flags() else { return None };
    if e_flags.0 & EF_MIPS_MICROMIPS != 0 {
        Some("microMIPS")
    } else if e_flags.0 & EF_MIPS_ARCH_ASE_M16 != 0 {
        Some("MIPS16e")
    } else {
        None
    }
}

fn undecoded_isa_note(isa: &str) -> String {
    let what = if isa == "MIPS16e" { "64-bit MIPS16e code" } else { "microMIPS code" };
    format!(
        "the ELF header marks {what}, which rampage does not decode (32-bit MIPS16e is decoded): functions compiled \
         as {isa} (entered through jalx or an odd address) are not discovered, listed, disassembled or decompiled, \
         symbols at odd addresses keep their names but seed no function, and calls into them are not followed. Only \
         the MIPS32 code is analysed, so function lists, call graphs and diffs are incomplete"
    )
}

/// Whether an ARM ELF's build attributes name an M-profile CPU; an unreadable section is a warning and not M.
fn elf_m_profile(parsed: &object::File, warnings: &mut Vec<String>) -> bool {
    let Some(section) = parsed.section_by_name(".ARM.attributes") else { return false };
    let parsed_attributes = section
        .data()
        .map_err(|_| crate::arm_attributes::AttributesError("section bytes are outside the file"))
        .and_then(|bytes| crate::arm_attributes::parse(bytes, !parsed.is_little_endian()));
    match parsed_attributes {
        Ok(attributes) => attributes.m_profile(),
        Err(error) => {
            warnings.push(format!(".ARM.attributes unreadable, so the image is not treated as M-profile: {error}"));
            false
        }
    }
}

/// The address ranges of Thumb code. A `$t` mapping symbol starts a range that runs to the next mapping symbol or
/// the end of its section. Thumb functions add theirs: ELF marks them with the low address bit, Mach-O with
/// `N_ARM_THUMB_DEF` or an odd `LC_FUNCTION_STARTS` entry, and one without a size runs to the next function.
/// Without any of these, a Thumb entry point makes all code Thumb.
fn thumb_ranges(
    parsed: &object::File,
    place: &dyn Fn(&object::Symbol) -> Option<u64>,
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
        .filter_map(|symbol| Some((place(&symbol)?, arm_mapping_symbol(symbol.name().ok()?)?)))
        .collect();
    mapping.sort_unstable();
    for (index, &(address, kind)) in mapping.iter().enumerate() {
        if kind == 't' {
            let end = container_end(address);
            ranges.push(address..mapping.get(index + 1).map_or(end, |&(next, _)| next.min(end)));
        }
    }

    // (start, size, thumb) of every function the file records.
    // MIPS ELF also marks MIPS16e functions with `STO_MIPS16` in `st_other`, which is zero there on ARM.
    let thumb_def = |flags| match flags {
        SymbolFlags::MachO { n_desc, .. } => n_desc.0 & object::macho::N_ARM_THUMB_DEF.0 != 0,
        SymbolFlags::Elf { st_other, .. } => st_other.0 & 0xf0 == 0xf0,
        _ => false,
    };
    let mut functions: Vec<(u64, u64, bool)> = parsed
        .symbols()
        .chain(parsed.dynamic_symbols())
        .filter(|symbol| symbol.kind() == object::SymbolKind::Text)
        .filter_map(|symbol| {
            let address = place(&symbol)?;
            Some((address & !1, symbol.size(), address & 1 == 1 || thumb_def(symbol.flags())))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of at least four odd pointers into code seeds MIPS16e functions; shorter runs, pointers outside code
    /// and pointers to strings do not.
    #[test]
    fn mips16_pointer_tables_need_runs_of_code_pointers() {
        let mut image = vec![0u8; 0x200];
        // Code at 0x1000..0x1100 (file 0..0x100): 0x6500 (`nop`) halfwords, and a string at 0x10f0.
        for at in (0..0x100).step_by(2) {
            image[at..at + 2].copy_from_slice(&0x6500u16.to_be_bytes());
        }
        image[0xf0..0xf6].copy_from_slice(b"hello\0");
        let words = |image: &mut Vec<u8>, at: usize, values: &[u32]| {
            for (index, value) in values.iter().enumerate() {
                image[at + index * 4..at + index * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
        };
        // Data at 0x2000 (file 0x100): a table of four, a run of three, and a run broken by a string pointer.
        words(&mut image, 0x100, &[0x1001, 0x1031, 0x1061, 0x1091, 0]);
        words(&mut image, 0x120, &[0x1041, 0x1051, 0x1061, 0]);
        words(&mut image, 0x140, &[0x1071, 0x1081, 0x10f1, 0x1091, 0x10a1, 0]);
        words(&mut image, 0x160, &[0x3001, 0x3011, 0x3021, 0x3031, 0]);
        let perms = |execute: bool| Perms { read: true, write: !execute, execute };
        let segment = |address, file_offset, execute| Segment {
            name: String::new(),
            address,
            size: 0x100,
            file_offset,
            file_size: 0x100,
            perms: perms(execute),
        };
        let segments = [segment(0x1000, 0, true), segment(0x2000, 0x100, false)];
        let scan = PointerTableScan { segments: &segments, image: &image, headers_end: 0, tables: &[] };
        assert_eq!(scan.mips16_pointers(true), [0x1001, 0x1031, 0x1061, 0x1091]);
        // A table of repeated or close-together targets (a switch's labels) is no function table.
        let mut repeated = image.clone();
        words(&mut repeated, 0x100, &[0x1001, 0x1001, 0x1011, 0x1011, 0]);
        let close = PointerTableScan { segments: &segments, image: &repeated, headers_end: 0, tables: &[] };
        assert!(close.mips16_pointers(true).is_empty());
    }

    /// Review: in an image based at 0 the first executable segment covers the ELF header, program headers and the
    /// dynamic tables, whose small odd words (hash buckets {1, 3, 5, 7}) would otherwise seed functions at 0..8.
    #[test]
    fn mips16_pointer_tables_skip_headers_and_dynamic_tables_at_base_zero() {
        let mut image = vec![0u8; 0x400];
        for at in (0..0x400).step_by(2) {
            image[at..at + 2].copy_from_slice(&0x6500u16.to_be_bytes());
        }
        let words = |image: &mut Vec<u8>, at: usize, values: &[u32]| {
            for (index, value) in values.iter().enumerate() {
                image[at + index * 4..at + index * 4 + 4].copy_from_slice(&value.to_be_bytes());
            }
        };
        // Headers end at 0x80; a hash table at 0x100 holds buckets 1, 3, 5, 7 and chains 9, 0xb, 0xd, 0xf; data at
        // 0x40 (inside the headers) and a real table at 0x200 point at code past the headers.
        words(&mut image, 0x40, &[0x301, 0x311, 0x351, 0x391, 0]);
        words(&mut image, 0x100, &[1, 3, 5, 7, 9, 0xb, 0xd, 0xf, 0]);
        words(&mut image, 0x180, &[1, 3, 5, 7, 0]);
        words(&mut image, 0x200, &[0x301, 0x311, 0x351, 0x3a1, 0]);
        let segment = Segment {
            name: String::new(),
            address: 0,
            size: 0x400,
            file_offset: 0,
            file_size: 0x400,
            perms: Perms { read: true, write: false, execute: true },
        };
        let segments = [segment];
        let tables = vec![Range { start: 0x100, end: 0x124 }];
        let scan = PointerTableScan { segments: &segments, image: &image, headers_end: 0x80, tables: &tables };
        assert_eq!(scan.mips16_pointers(true), [0x301, 0x311, 0x351, 0x3a1]);
    }

    #[test]
    fn cold_metadata_open_skips_optional_recovery_for_whole_and_selected_images() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-go-x64.elf");
        let length = std::fs::metadata(&path).unwrap().len();
        for image in [None, Some(ImageAt::new(0, Some(length)))] {
            OPTIONAL_RECOVERY_ENTRIES.with(|count| count.set(0));
            let binary = Binary::open_image_metadata(&path, image, None).unwrap();
            assert!(binary.go_table.is_none());
            OPTIONAL_RECOVERY_ENTRIES.with(|count| assert_eq!(count.get(), 0));
        }
        OPTIONAL_RECOVERY_ENTRIES.with(|count| count.set(0));
        let ordinary = Binary::open(&path).unwrap();
        assert!(ordinary.go_table.is_some());
        OPTIONAL_RECOVERY_ENTRIES.with(|count| assert_eq!(count.get(), 2));
    }

    /// Every API call on a Raw project validates its analysis binding; the whole image is hashed once per load.
    #[test]
    fn raw_identity_hashes_the_owned_image_once_however_often_it_is_checked() {
        let options = crate::RawCodeOptions {
            profile: crate::RawProfile::Msp430,
            base: 0x1000,
            entry: None,
            seeds: vec![],
            vector_table: None,
            pointer_tables: false,
        };
        let binary = Binary::from_raw_code(vec![0x30, 0x41], options.clone()).unwrap();
        crate::raw::IDENTITY_HASHES.with(|count| count.set(0));
        let first = binary.raw_interpretation_identity().unwrap().unwrap();
        for _ in 0..100 {
            assert_eq!(binary.raw_interpretation_identity().unwrap().unwrap(), first);
        }
        crate::raw::IDENTITY_HASHES.with(|count| assert_eq!(count.get(), 1));
        // Facts outside the cached identity still drift-check on every call.
        let mut drifted = Binary::from_raw_code(vec![0x30, 0x41], options).unwrap();
        assert_eq!(drifted.raw_interpretation_identity().unwrap().unwrap(), first);
        drifted.function_starts.push(0x1000);
        assert!(drifted.raw_interpretation_identity().is_err());
    }

    #[test]
    fn pclntab_section_names_include_the_relro_spelling() {
        for name in [".gopclntab", ".data.rel.ro.gopclntab", "__gopclntab"] {
            assert!(is_gopclntab(name), "{name}");
        }
        assert!(!is_gopclntab(".data.rel.ro"));
    }
}

#[cfg(test)]
mod go_width_tests {
    #[test]
    fn missing_go_word_width_is_not_a_complete_empty_parse() {
        assert!(super::go_pointer_size(None).is_err());
        assert!(super::go_pointer_size(Some(2)).is_err());
        assert_eq!(super::go_pointer_size(Some(4)).unwrap(), 4);
        assert_eq!(super::go_pointer_size(Some(8)).unwrap(), 8);
    }
}
