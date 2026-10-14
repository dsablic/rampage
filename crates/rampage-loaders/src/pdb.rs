//! Bounded function-name reads from explicitly selected Microsoft PDB files. No sidecar is opened implicitly.
//! Corruption, exhausted limits and conflicting names reject the whole read rather than returning partial names.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use ::pdb::{FallibleIterator, PDB, SymbolData};
use object::Object;
use object::read::pe::{ImageNtHeaders, PeFile};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{Binary, LoadError};

pub const MAX_PDB_BYTES: usize = 64 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 100_000;
const MAX_MODULES: usize = 10_000;
const MAX_RECORDS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;
const MAX_NAMES_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 4 * MAX_PDB_BYTES;
const MAX_DIRECTORY_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAMS: usize = 32_768;
const MAX_PAGE_REFERENCES: usize = 262_144;
const MAX_STRUCTURAL_WORK: usize = 4_000_000;
const MAX_SECTIONS: usize = 4096;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PdbReport {
    pub functions: Vec<PdbFunction>,
    pub warnings: Vec<String>,
    pub identity: Option<PdbIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdbIdentity {
    /// RSDS byte order, not the UUID's textual byte order.
    #[serde(serialize_with = "serialize_guid")]
    pub guid: [u8; 16],
    pub age: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdbFunction {
    /// Relative virtual address. Only `matched_symbols` returns virtual addresses.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
}

/// Observable provenance of one bounded, owned PDB read. This is not PDB authentication or a filesystem snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbProvenance {
    path: PathBuf,
    stamp: Option<PdbStamp>,
    sha256: [u8; 32],
}

impl PdbProvenance {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Rechecks the explicit file's current capped bytes and descriptor provenance, without parsing new names.
    pub fn validate_current(&self) -> Result<(), LoadError> {
        self.require_identity()?;
        let current = read_pdb_input(&self.path, open_pdb_file)?;
        current.provenance.require_identity()?;
        if current.provenance != *self {
            return Err(malformed("PDB bytes or provenance changed since preview"));
        }
        Ok(())
    }

    fn require_identity(&self) -> Result<(), LoadError> {
        self.stamp.ok_or_else(|| LoadError::Unsupported("PDB file identity unavailable".to_owned())).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PdbStamp {
    length: u64,
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl PdbStamp {
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

struct PdbInput {
    bytes: Vec<u8>,
    provenance: PdbProvenance,
}

fn serialize_guid<S: serde::Serializer>(guid: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&rampage_arch::hex::bytes(guid))
}

fn malformed(message: impl std::fmt::Display) -> LoadError {
    LoadError::Malformed(format!("PDB: {message}"))
}

/// A conventional candidate path only; neither this helper nor binary loading trusts or opens it.
pub fn sidecar_pdb_path(image_path: &Path) -> PathBuf {
    image_path.with_extension("pdb")
}

/// Reads bounded function RVAs from an explicit regular file, without asserting that it matches an image.
/// Final-component symlinks are refused, and regular-file checks use the opened descriptor.
/// Path reads require macOS, Linux or Windows: other hosts can use `pdb_symbols_bytes`.
pub fn pdb_symbols(path: &Path) -> Result<PdbReport, LoadError> {
    read_pdb_file(path, open_pdb_file)
}

fn read_pdb_file(path: &Path, open: impl FnOnce(&Path) -> io::Result<std::fs::File>) -> Result<PdbReport, LoadError> {
    pdb_symbols_bytes(&read_pdb_input(path, open)?.bytes)
}

fn read_pdb_input(path: &Path, open: impl FnOnce(&Path) -> io::Result<std::fs::File>) -> Result<PdbInput, LoadError> {
    let io_error = |source| LoadError::Io { path: path.to_path_buf(), source };
    let path = std::path::absolute(path).map_err(io_error)?;
    let io_error = |source| LoadError::Io { path: path.clone(), source };
    let mut file = open(&path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_PDB_BYTES as u64 {
        return Err(malformed("requires a regular file within the size limit"));
    }
    let stamp = PdbStamp::from_metadata(&metadata);
    let mut bytes = Vec::new();
    (&mut file).take(MAX_PDB_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > MAX_PDB_BYTES {
        return Err(malformed("file exceeds size limit"));
    }
    let after = file.metadata().map_err(io_error)?;
    let pathname = std::fs::symlink_metadata(&path).map_err(io_error)?;
    if !after.is_file()
        || !pathname.is_file()
        || after.len() != bytes.len() as u64
        || metadata.len() != after.len()
        || PdbStamp::from_metadata(&after) != stamp
        || PdbStamp::from_metadata(&pathname) != stamp
    {
        return Err(malformed("PDB file changed while reading"));
    }
    let sha256 = Sha256::digest(&bytes).into();
    Ok(PdbInput { bytes, provenance: PdbProvenance { path, stamp, sha256 } })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_pdb_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    #[cfg(target_os = "macos")]
    const FLAGS: i32 = 0x0004 | 0x0100;
    #[cfg(target_os = "linux")]
    const FLAGS: i32 = {
        let nonblock = if cfg!(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )) {
            0x0080
        } else if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
            0x4000
        } else {
            0x0800
        };
        let nofollow = if cfg!(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )) {
            0x8000
        } else {
            0x20000
        };
        nonblock | nofollow
    };
    // O_NONBLOCK prevents FIFO-open waits; O_NOFOLLOW refuses a swapped-in final-component symlink.
    std::fs::OpenOptions::new().read(true).custom_flags(FLAGS).open(path)
}

#[cfg(windows)]
fn open_pdb_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileType"]
        fn get_file_type(file: *mut std::ffi::c_void) -> u32;
    }
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_SHARE_READ: u32 = 1;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    // SAFETY: the handle belongs to the live File. Only disk objects, never pipes or character devices, are read.
    let kind = unsafe { get_file_type(file.as_raw_handle()) };
    if kind != FILE_TYPE_DISK {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "PDB input is not a disk file"));
    }
    Ok(file)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn open_pdb_file(_path: &Path) -> io::Result<std::fs::File> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "safe PDB path reads require macOS, Linux or Windows"))
}

/// The same bounded reader over bytes; useful for callers that already have the explicitly selected file.
pub fn pdb_symbols_bytes(bytes: &[u8]) -> Result<PdbReport, LoadError> {
    let mut budget = Budget { bytes: MAX_SOURCE_BYTES, work: MAX_STRUCTURAL_WORK };
    let msf = preflight_msf(bytes, &mut budget)?;
    preflight_symbols(&msf, &mut budget)?;
    read_pdb(bytes, budget)
}

/// Reads explicit PDB names only after matching a unique PE RSDS GUID and age. Returns checked virtual addresses.
/// Missing identity, ambiguous CodeView records or any invalid code RVA reject the entire report.
pub fn matched_symbols(binary: &Binary, path: &Path) -> Result<PdbReport, LoadError> {
    match_report(binary, || pdb_symbols(path))
}

/// Matches names and hashes the same capped owned PDB buffer. Refuses unavailable source identity.
pub fn matched_symbols_checked(binary: &Binary, path: &Path) -> Result<(PdbReport, PdbProvenance), LoadError> {
    binary.validate_backing_source()?;
    let input = read_pdb_input(path, open_pdb_file)?;
    input.provenance.require_identity()?;
    let report = pdb_symbols_bytes(&input.bytes)?;
    let report = with_backing_source(binary, || match_report(binary, || Ok(report)))?;
    Ok((report, input.provenance))
}

fn with_backing_source<T>(binary: &Binary, work: impl FnOnce() -> Result<T, LoadError>) -> Result<T, LoadError> {
    binary.validate_backing_source()?;
    let result = work();
    binary.validate_backing_source()?;
    result
}

fn match_report(
    binary: &Binary,
    read_report: impl FnOnce() -> Result<PdbReport, LoadError>,
) -> Result<PdbReport, LoadError> {
    let parsed = object::File::parse(binary.image_bytes())?;
    let identity = match &parsed {
        object::File::Pe32(file) => image_identity(file)?,
        object::File::Pe64(file) => image_identity(file)?,
        _ => return Err(LoadError::Unsupported("PDB names require a PE image".to_owned())),
    };
    let image_base = parsed.relative_address_base();
    let mut report = read_report()?;
    if report.identity.as_ref() != Some(&identity) {
        return Err(malformed("GUID/age does not match the PE image"));
    }
    for function in &mut report.functions {
        function.address = function.address.checked_add(image_base).ok_or_else(|| malformed("VA overflows"))?;
        let executable = binary
            .segment_containing(function.address)
            .is_some_and(|segment| segment.perms.execute && segment.perms.read);
        if !executable || !binary.is_code(function.address) || binary.read(function.address, 1).is_none() {
            return Err(malformed("function RVA is not readable, executable file-backed code in the PE image"));
        }
    }
    Ok(report)
}

fn image_identity<Pe: ImageNtHeaders>(file: &PeFile<'_, Pe>) -> Result<PdbIdentity, LoadError> {
    let directory = file
        .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG)
        .ok_or_else(|| malformed("PE image has no debug identity"))?;
    let bytes = directory.data(file.data(), &file.section_table())?;
    if bytes.len() > 64 * 28 || bytes.len() % 28 != 0 {
        return Err(malformed("invalid or oversized PE debug directory"));
    }
    let mut identity = None;
    for record in bytes.as_chunks::<28>().0 {
        if uint(record, 12)? != object::pe::IMAGE_DEBUG_TYPE_CODEVIEW.0 {
            continue;
        }
        if identity.is_some() {
            return Err(malformed("ambiguous PE CodeView identity"));
        }
        let length = uint(record, 16)? as usize;
        let offset = uint(record, 24)? as usize;
        if length > 24 + crate::MAX_CODEVIEW_PATH + 1 {
            return Err(malformed("PE CodeView record exceeds size limit"));
        }
        let end = offset.checked_add(length).ok_or_else(|| malformed("PE CodeView range overflows"))?;
        let info = file.data().get(offset..end).ok_or_else(|| malformed("truncated PE CodeView record"))?;
        if info.get(..4) != Some(b"RSDS") || info.get(24..).is_none_or(|path| !path.contains(&0)) {
            return Err(malformed("PE CodeView identity is not a complete RSDS record"));
        }
        let guid = info
            .get(4..20)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| malformed("truncated PE CodeView GUID"))?;
        identity = Some(PdbIdentity { guid, age: uint(info, 20)? });
    }
    identity.filter(|identity| identity.age > 0).ok_or_else(|| malformed("PE image has no usable RSDS identity"))
}

fn uint(bytes: &[u8], offset: usize) -> Result<u32, LoadError> {
    let value = bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| malformed("truncated header"))?;
    Ok(u32::from_le_bytes(value))
}

fn ushort(bytes: &[u8], offset: usize) -> Result<u16, LoadError> {
    let value = range(bytes, offset, 2)?.try_into().map_err(malformed)?;
    Ok(u16::from_le_bytes(value))
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], LoadError> {
    let end = offset.checked_add(length).ok_or_else(|| malformed("range overflows"))?;
    bytes.get(offset..end).ok_or_else(|| malformed("truncated stream"))
}

struct Budget {
    bytes: usize,
    work: usize,
}

impl Budget {
    fn bytes(&mut self, amount: usize) -> Result<(), LoadError> {
        self.bytes = self.bytes.checked_sub(amount).ok_or_else(|| malformed("read budget exceeded"))?;
        Ok(())
    }

    fn work(&mut self, amount: usize) -> Result<(), LoadError> {
        self.work = self.work.checked_sub(amount).ok_or_else(|| malformed("structural work budget exceeded"))?;
        Ok(())
    }
}

struct MsfStream {
    length: usize,
    pages: Vec<usize>,
}

struct Msf<'a> {
    bytes: &'a [u8],
    page_size: usize,
    streams: Vec<Option<MsfStream>>,
}

impl Msf<'_> {
    fn stream(&self, index: u16) -> Result<&MsfStream, LoadError> {
        self.streams
            .get(usize::from(index))
            .and_then(Option::as_ref)
            .ok_or_else(|| malformed("missing referenced stream"))
    }

    fn plan_read(&self, index: u16, budget: &mut Budget) -> Result<(), LoadError> {
        let stream = self.stream(index)?;
        budget.work(usize::from(index) + 1 + stream.pages.len())
    }

    fn read(&self, index: u16, budget: &mut Budget) -> Result<Vec<u8>, LoadError> {
        let stream = self.stream(index)?;
        // Account for both this preflight copy and the dependency's subsequent directory/page-list traversal.
        self.plan_read(index, budget)?;
        self.plan_read(index, budget)?;
        budget.bytes(stream.length)?;
        let mut bytes = Vec::with_capacity(stream.length);
        for &page in &stream.pages {
            let length = (stream.length - bytes.len()).min(self.page_size);
            bytes.extend_from_slice(range(self.bytes, page * self.page_size, length)?);
        }
        Ok(bytes)
    }
}

fn preflight_msf<'a>(bytes: &'a [u8], budget: &mut Budget) -> Result<Msf<'a>, LoadError> {
    if bytes.len() > MAX_PDB_BYTES {
        return Err(malformed("file exceeds size limit"));
    }
    if bytes.get(..32) != Some(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0") {
        return Err(malformed("not an MSF 7 PDB"));
    }
    let page_size = uint(bytes, 32)? as usize;
    let pages = uint(bytes, 40)? as usize;
    if !page_size.is_power_of_two()
        || !(256..=65536).contains(&page_size)
        || pages.checked_mul(page_size) != Some(bytes.len())
    {
        return Err(malformed("invalid or truncated MSF page layout"));
    }
    let directory_length = uint(bytes, 44)? as usize;
    if directory_length > MAX_DIRECTORY_BYTES || directory_length > bytes.len() {
        return Err(malformed("MSF directory exceeds size limit"));
    }
    let directory_pages = directory_length.div_ceil(page_size);
    let map_length = directory_pages * 4;
    let map_pages = map_length.div_ceil(page_size);
    if 52 + map_pages * 4 > 4096.min(bytes.len()) {
        return Err(malformed("MSF directory map exceeds header limit"));
    }
    budget.work(directory_pages + map_pages)?;
    budget.bytes(map_length + directory_length)?;
    let page = |number: u32| -> Result<usize, LoadError> {
        let number = number as usize;
        if number == 0 || number >= pages {
            return Err(malformed("MSF page reference is outside the file"));
        }
        Ok(number)
    };
    let mut map = Vec::with_capacity(map_length);
    for index in 0..map_pages {
        let at = page(uint(bytes, 52 + index * 4)?)? * page_size;
        map.extend_from_slice(range(bytes, at, (map_length - map.len()).min(page_size))?);
    }
    let mut directory = Vec::with_capacity(directory_length);
    for index in 0..directory_pages {
        let at = page(uint(&map, index * 4)?)? * page_size;
        directory.extend_from_slice(range(bytes, at, (directory_length - directory.len()).min(page_size))?);
    }
    let count = uint(&directory, 0)? as usize;
    if count > MAX_STREAMS {
        return Err(malformed("MSF stream count exceeds limit"));
    }
    let mut total_bytes = 0usize;
    let mut references = directory_pages + map_pages;
    for index in 0..count {
        let size = uint(&directory, 4 + index * 4)?;
        if size == u32::MAX {
            continue;
        }
        let size = size as usize;
        if size > MAX_PDB_BYTES {
            return Err(malformed("MSF stream size exceeds limit"));
        }
        total_bytes = total_bytes
            .checked_add(size)
            .filter(|&total| total <= MAX_PDB_BYTES)
            .ok_or_else(|| malformed("MSF aggregate stream bytes exceed limit"))?;
        references = references
            .checked_add(size.div_ceil(page_size))
            .filter(|&total| total <= MAX_PAGE_REFERENCES)
            .ok_or_else(|| malformed("MSF page-reference count exceeds limit"))?;
    }
    budget.work(references + count)?;
    let mut cursor = 4 + count * 4;
    let mut streams = Vec::with_capacity(count);
    for index in 0..count {
        let size = uint(&directory, 4 + index * 4)?;
        if size == u32::MAX {
            streams.push(None);
            continue;
        }
        let length = size as usize;
        let count = length.div_ceil(page_size);
        let serialized = range(&directory, cursor, count * 4)?;
        let mut stream_pages = Vec::with_capacity(count);
        for bytes in serialized.as_chunks::<4>().0 {
            stream_pages.push(page(uint(bytes, 0)?)?);
        }
        cursor += count * 4;
        streams.push(Some(MsfStream { length, pages: stream_pages }));
    }
    if cursor != directory.len() {
        return Err(malformed("MSF directory has unaccounted bytes"));
    }
    Ok(Msf { bytes, page_size, streams })
}

fn preflight_symbols(msf: &Msf<'_>, budget: &mut Budget) -> Result<(), LoadError> {
    let dbi = msf.read(3, budget)?;
    if uint(&dbi, 0)? != u32::MAX {
        return Err(malformed("unsupported DBI header"));
    }
    let mut extra = 64usize;
    for offset in [24, 28, 32, 36, 40, 52] {
        extra = extra
            .checked_add(uint(&dbi, offset)? as usize)
            .filter(|&extra| extra <= dbi.len())
            .ok_or_else(|| malformed("invalid DBI substream sizes"))?;
    }
    let debug = range(&dbi, extra, uint(&dbi, 48)? as usize)?;
    if debug.len() % 2 != 0 {
        return Err(malformed("invalid DBI debug-stream table"));
    }
    for index in [3, 4, 10] {
        if debug.len() >= (index + 1) * 2 && ushort(debug, index * 2)? != u16::MAX {
            return Err(LoadError::Unsupported("PDB OMAP/original-section address translation".to_owned()));
        }
    }
    let sections = ushort(debug, 5 * 2)?;
    let section_length = msf.stream(sections)?.length;
    if section_length == 0 || section_length % 40 != 0 || section_length / 40 > MAX_SECTIONS {
        return Err(malformed("invalid or oversized PDB section table"));
    }
    msf.plan_read(1, budget)?;
    msf.plan_read(sections, budget)?;
    msf.plan_read(3, budget)?;
    msf.plan_read(3, budget)?;
    let modules = range(&dbi, 64, uint(&dbi, 24)? as usize)?;
    let mut cursor = 0usize;
    let mut count = 0usize;
    let mut records = 0usize;
    while cursor < modules.len() {
        count += 1;
        if count > MAX_MODULES {
            return Err(malformed("module count exceeds limit"));
        }
        let header = range(modules, cursor, 64)?;
        let stream = ushort(header, 34)?;
        let size = uint(header, 36)? as usize;
        if stream != u16::MAX {
            if size == 0 {
                msf.plan_read(stream, budget)?;
            } else {
                let bytes = msf.read(stream, budget)?;
                let symbols = range(&bytes, 0, size)?;
                if uint(symbols, 0)? != 4 {
                    return Err(malformed("unsupported module symbol format"));
                }
                count_raw_symbols(&symbols[4..], &mut records, budget)?;
            }
        } else if size != 0 {
            return Err(malformed("missing module symbol stream"));
        }
        cursor += 64;
        for _ in 0..2 {
            let tail = range(modules, cursor, modules.len() - cursor)?;
            let end = tail.iter().position(|&byte| byte == 0).ok_or_else(|| malformed("unterminated module name"))?;
            cursor += end + 1;
        }
        cursor = cursor
            .checked_add(3)
            .map(|cursor| cursor & !3)
            .filter(|&cursor| cursor <= modules.len())
            .ok_or_else(|| malformed("truncated module padding"))?;
    }
    let globals = msf.read(ushort(&dbi, 20)?, budget)?;
    count_raw_symbols(&globals, &mut records, budget)
}

fn count_raw_symbols(bytes: &[u8], records: &mut usize, budget: &mut Budget) -> Result<(), LoadError> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        *records += 1;
        if *records > MAX_RECORDS {
            return Err(malformed("raw symbol record count exceeds limit"));
        }
        budget.work(1)?;
        let length = usize::from(ushort(bytes, cursor)?);
        if length < 2 {
            return Err(malformed("raw symbol record is too short"));
        }
        let record = range(bytes, cursor, length + 2)?;
        cursor += record.len();
    }
    Ok(())
}

#[derive(Debug)]
struct BoundedSource<'a> {
    bytes: &'a [u8],
    remaining: usize,
    remaining_work: usize,
}

#[derive(Debug)]
struct View(Vec<u8>);

impl ::pdb::SourceView<'_> for View {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> ::pdb::Source<'a> for BoundedSource<'a> {
    fn view(&mut self, slices: &[::pdb::SourceSlice]) -> io::Result<Box<dyn ::pdb::SourceView<'a>>> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "PDB source range or read budget exceeded");
        self.remaining_work = self.remaining_work.checked_sub(slices.len() + 1).ok_or_else(invalid)?;
        let mut length = 0usize;
        for slice in slices {
            let start = usize::try_from(slice.offset).map_err(|_| invalid())?;
            let end = start.checked_add(slice.size).ok_or_else(invalid)?;
            if end > self.bytes.len() {
                return Err(invalid());
            }
            length = length.checked_add(slice.size).filter(|&length| length <= self.bytes.len()).ok_or_else(invalid)?;
        }
        self.remaining = self.remaining.checked_sub(length).ok_or_else(invalid)?;
        let mut bytes = Vec::with_capacity(length);
        for slice in slices {
            let start = slice.offset as usize;
            bytes.extend_from_slice(&self.bytes[start..start + slice.size]);
        }
        Ok(Box::new(View(bytes)))
    }
}

fn read_pdb(bytes: &[u8], budget: Budget) -> Result<PdbReport, LoadError> {
    let source = BoundedSource { bytes, remaining: budget.bytes, remaining_work: budget.work };
    let mut pdb = PDB::open(source).map_err(malformed)?;
    let info = pdb.pdb_information().map_err(malformed)?;
    let identity = PdbIdentity { guid: info.guid.to_bytes_le(), age: info.age };
    let sections = pdb.sections().map_err(malformed)?.ok_or_else(|| malformed("missing section table"))?;
    let debug = pdb.debug_information().map_err(malformed)?;
    if identity.age == 0 || debug.age() != Some(identity.age) {
        return Err(malformed("missing or conflicting PDB age"));
    }
    let mut functions = BTreeMap::new();
    let mut names_bytes = 0usize;
    let mut modules = debug.modules().map_err(malformed)?;
    let mut count = 0usize;
    while let Some(module) = modules.next().map_err(malformed)? {
        count += 1;
        if count > MAX_MODULES {
            return Err(malformed("module count exceeds limit"));
        }
        if let Some(info) = pdb.module_info(&module).map_err(malformed)? {
            collect_procedures(info.symbols().map_err(malformed)?, &sections, &mut functions, &mut names_bytes)?;
        }
    }
    let globals = pdb.global_symbols().map_err(malformed)?;
    collect_procedures(globals.iter(), &sections, &mut functions, &mut names_bytes)?;
    Ok(PdbReport {
        functions: functions.into_iter().map(|(address, name)| PdbFunction { address, name }).collect(),
        identity: Some(identity),
        warnings: Vec::new(),
    })
}

fn collect_procedures(
    mut symbols: ::pdb::SymbolIter<'_>,
    sections: &[::pdb::ImageSectionHeader],
    functions: &mut BTreeMap<u64, String>,
    names_bytes: &mut usize,
) -> Result<(), LoadError> {
    while let Some(symbol) = symbols.next().map_err(malformed)? {
        validate_numeric_symbol(symbol.raw_bytes())?;
        let (offset, name) = match symbol.parse() {
            Ok(SymbolData::Procedure(procedure)) => (procedure.offset, procedure.name),
            Ok(SymbolData::Public(public)) if public.function => (public.offset, public.name),
            Ok(_) | Err(::pdb::Error::UnimplementedSymbolKind(_)) => continue,
            Err(error) => return Err(malformed(error)),
        };
        let index = usize::from(offset.section).checked_sub(1).ok_or_else(|| malformed("null function section"))?;
        let section = sections.get(index).ok_or_else(|| malformed("unknown function section"))?;
        let rva = section
            .virtual_address
            .checked_add(offset.offset)
            .ok_or_else(|| malformed("function section RVA plus offset overflows"))?;
        if offset.offset >= section.virtual_size.max(section.size_of_raw_data) {
            return Err(malformed("function offset is outside its section"));
        }
        let name = std::str::from_utf8(name.as_bytes()).map_err(malformed)?;
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(malformed("empty or oversized function name"));
        }
        if let Some(previous) = functions.get(&u64::from(rva)) {
            if previous != name {
                return Err(malformed("conflicting function names at one RVA"));
            }
            continue;
        }
        *names_bytes += name.len();
        if functions.len() >= MAX_FUNCTIONS || *names_bytes > MAX_NAMES_BYTES {
            return Err(malformed("function names exceed limit"));
        }
        functions.insert(u64::from(rva), name.to_owned());
    }
    Ok(())
}

fn validate_numeric_symbol(bytes: &[u8]) -> Result<(), LoadError> {
    if !matches!(ushort(bytes, 0)?, 0x1002 | 0x1107 | 0x112d) {
        return Ok(());
    }
    // pdb 0.8's Variant parser panics on other numeric leaves when debug assertions are enabled.
    let prefix = ushort(bytes, 6)?;
    match prefix {
        0..=0x7fff | 0x8000..=0x8004 | 0x8009 | 0x800a => Ok(()),
        _ => Err(malformed(format!("unsupported constant numeric prefix {prefix:#06x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::pdb::Source;

    #[allow(dead_code)]
    mod fixture_support {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/pdb/support.rs"));
    }

    #[test]
    fn malformed_inputs_are_clean_errors() {
        for bytes in [b"not a pdb file at all".as_slice(), b"Microsoft C/C++ MSF 7.00", b""] {
            assert!(matches!(pdb_symbols_bytes(bytes), Err(LoadError::Malformed(_))));
        }
    }

    #[test]
    fn missing_file_reports_io_error() {
        let error = pdb_symbols(Path::new("/nonexistent/does-not-exist.pdb")).unwrap_err();
        assert!(matches!(error, LoadError::Io { .. }));
    }

    #[test]
    fn absent_provenance_identity_is_refused_without_substituting_a_new_file_read() {
        let provenance =
            PdbProvenance { path: PathBuf::from("/nonexistent/does-not-exist.pdb"), stamp: None, sha256: [0; 32] };
        let error = provenance.validate_current().unwrap_err();
        assert!(matches!(error, LoadError::Unsupported(_)), "{error}");
        assert!(error.to_string().contains("identity unavailable"), "{error}");
    }

    #[test]
    fn sidecar_path_swaps_the_extension() {
        assert_eq!(sidecar_pdb_path(Path::new("/tmp/app.exe")), PathBuf::from("/tmp/app.pdb"));
    }

    #[test]
    fn source_checks_ranges_and_cumulative_budget_before_allocating() {
        let mut source = BoundedSource { bytes: b"12345678", remaining: 8, remaining_work: 100 };
        let slice = ::pdb::SourceSlice { offset: 0, size: 8 };
        assert!(source.view(&[slice, slice]).is_err());
        assert!(source.view(&[::pdb::SourceSlice { offset: u64::MAX, size: usize::MAX }]).is_err());
        assert_eq!(source.view(&[slice]).unwrap().as_slice(), b"12345678");
        assert!(source.view(&[slice]).is_err());
    }

    #[test]
    fn corrupt_real_fixture_constant_numeric_prefix_is_an_error_not_a_debug_assertion_panic() {
        let original = std::fs::read(fixture_support::fixture("fixture.pdb")).unwrap();
        for kind in [0x1002, 0x1107, 0x112d] {
            let corrupt = fixture_support::corrupt_local_constant_numeric_prefix(&original, kind, 0xffff);
            let error = pdb_symbols_bytes(&corrupt).unwrap_err();
            assert!(error.to_string().contains("unsupported constant numeric prefix 0xffff"), "{error}");
        }
    }

    #[test]
    fn numeric_prefix_guard_accepts_only_the_dependency_supported_integer_encodings() {
        for kind in [0x1002u16, 0x1107, 0x112d] {
            let mut record = kind.to_le_bytes().to_vec();
            record.extend_from_slice(&0x74u32.to_le_bytes());
            record.extend_from_slice(&0u16.to_le_bytes());
            for prefix in [0u16, 0x7fff, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8009, 0x800a] {
                record[6..8].copy_from_slice(&prefix.to_le_bytes());
                assert!(validate_numeric_symbol(&record).is_ok());
            }
            for prefix in [0x8005u16, 0x8008, 0x8010, 0xffff] {
                record[6..8].copy_from_slice(&prefix.to_le_bytes());
                assert!(validate_numeric_symbol(&record).is_err());
            }
            assert!(validate_numeric_symbol(&record[..7]).is_err());
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_regular_path_swapped_to_fifo_or_fifo_symlink_at_open_cannot_block() {
        use std::sync::mpsc;
        use std::time::Duration;

        for symlink in [false, true] {
            let files = fixture_support::TempFiles::new();
            let fifo = files.fifo("hostile-fifo.pdb");
            let path = files.write("selected.pdb", b"previous regular file");
            assert!(std::fs::metadata(&path).unwrap().is_file());
            let worker_path = path.clone();
            let (ready_tx, ready_rx) = mpsc::sync_channel(0);
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = read_pdb_file(&worker_path, |path| {
                    std::fs::remove_file(path)?;
                    if symlink {
                        std::os::unix::fs::symlink(&fifo, path)?;
                    } else {
                        std::fs::rename(&fifo, path)?;
                    }
                    ready_tx.send(()).unwrap();
                    open_pdb_file(path)
                });
                tx.send(result).unwrap();
            });
            ready_rx.recv().unwrap();
            let timely = rx.recv_timeout(Duration::from_secs(3));
            if timely.is_err() {
                // Pair a regressed blocking reader with a writer, then close it so the test can clean up and fail.
                drop(std::fs::OpenOptions::new().write(true).open(&path).unwrap());
                let _ = rx.recv_timeout(Duration::from_secs(3));
            }
            worker.join().unwrap();
            assert!(timely.is_ok(), "PDB open blocked on a FIFO after a path replacement");
            let error = timely.unwrap().unwrap_err();
            if symlink {
                assert!(matches!(error, LoadError::Io { .. }), "{error}");
            } else {
                assert!(error.to_string().contains("requires a regular file"), "{error}");
            }
        }
    }
}
