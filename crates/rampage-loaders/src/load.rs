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
        Self::from_raw_image(crate::RawImage { bytes: data, options, source: None, regions: Vec::new(), records: None })
    }

    /// Owns one explicitly interpreted image of a primary code region and any further analyst-stated regions
    /// (code, constant data, RAM with or without bytes). Regions never overlap; no header parsing, entry
    /// inference or filesystem access. The owned bytes are the backed regions' bytes in region order.
    pub fn from_raw_image(image: crate::RawImage) -> Result<Self, LoadError> {
        let (raw, data) = crate::RawCodeImage::admit(image)?;
        let arch = raw.profile().arch();
        let len = data.len();
        Ok(Self {
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
            warnings: Vec::new(),
            details: Details::None,
            big_endian: raw.profile().big_endian(),
            thumb: raw.thumb_ranges(),
            overlay: None,
            code_big_endian: raw.profile().code_big_endian(),
            code_ranges: raw.code_ranges(),
            global_pointer: None,
            got: None,
            rebases: Vec::new(),
            data: Bytes::Owned(data),
            snapshot_source: None,
            provenance: None,
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            embedded: None,
            go_table: None,
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw: Some(raw),
            image: 0..len,
        })
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

    /// An ARMv6-M/ARMv7-M(E) image: all Thumb, no A32 state, M-profile instruction set (the Cortex-M Raw profile).
    pub fn m_profile(&self) -> bool {
        self.raw.as_ref().is_some_and(|raw| raw.profile().m_profile())
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
            || !self.warnings.is_empty()
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
        Ok(Some(raw.identity(self.image_bytes())))
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
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw: None,
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
        let data = map_executable(path.as_ref())?;
        Self::open_mapped(data, wanted)
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
            object::FileKind::MachOFat32 => select_universal::<FatArch32>(&data, wanted)?,
            object::FileKind::MachOFat64 => select_universal::<FatArch64>(&data, wanted)?,
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
        let data = map_executable(path.as_ref())?;
        match image.filter(|image| !image.is_whole_file()) {
            Some(image) => Self::open_mapped_at_recovery(data, image.offset, image.length, wanted, false),
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
        let data = map_executable_checked(path.as_ref(), max_source_bytes.min(128 * 1024 * 1024))?;
        consume_admitted_source(data, admit, |data| match image.filter(|image| !image.is_whole_file()) {
            Some(image) => Self::open_mapped_at(data, image.offset, image.length, wanted),
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
        let path = path.as_ref();
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
        Self::open_mapped_at_recovery(data, offset, length, wanted, true)
    }

    fn open_mapped_at_recovery(
        data: MappedSource,
        offset: u64,
        length: Option<u64>,
        wanted: Option<Arch>,
        recover: bool,
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
        let pe_layout = (format == Format::Pe).then(|| crate::msvc::PeLayout {
            image_base: parsed.relative_address_base(),
            exception_directory: exception_directory.as_ref().map(starts::ExceptionDirectory::span),
        });
        let tls_directory = starts::pe_tls_directory(&parsed);
        let arm_exidx_tables = starts::arm_exidx_tables(&parsed, &mut warnings);
        let import_slots = crate::slots::collect(&parsed, image_bytes, &mut warnings);
        let rebases = crate::slots::chained_rebases(&parsed, image_bytes, &mut warnings);
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
            rebases,
            data,
            snapshot_source: None,
            provenance: None,
            snapshot_modules: Vec::new(),
            snapshot_registers: Vec::new(),
            snapshot_target: None,
            embedded: None,
            go_table: None,
            pe_layout: None,
            msvc: None,
            go_arguments: std::collections::BTreeMap::new(),
            raw: None,
            image,
        };
        binary.code_ranges = code_ranges(&binary.sections, &binary.segments);
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
        let (starts, warning) = starts::eh_frame(&binary);
        function_starts.extend(starts);
        binary.warnings.extend(warning);
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
            thumb: self.thumb.clone().into(),
            global_pointer: self.global_pointer,
            got: self.got.clone(),
            m_profile: self.m_profile(),
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
        let size = usize::from(self.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8))?);
        let entries = bytes.chunks_exact(size).filter_map(|entry| read_uint(entry, 0, size, self.big_endian)).collect();
        Some(rampage_arch::Got { address: section.address, entries })
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
        self.image_bytes().get(start..end)
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
        let in_file = (self.image.len() as u64).checked_sub(file_position)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
