//! PyInstaller: the CArchive appended to a PyInstaller bootloader, found by its trailing cookie. Reports the cookie,
//! the package extent, the Python version and library, the table of contents and the PYZ header. Nothing is
//! extracted, decompressed or decompiled: entry payloads are located, not read (the PYZ header aside).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;

use crate::LoadError;
use crate::carve::open_regular_file;

/// The CArchive cookie magic, `MEI\014\013\012\013\016`.
pub const MAGIC: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
/// How far back from the end of the file the cookie is searched for: far enough to step over an Authenticode
/// certificate or Mach-O code signature written after the archive.
pub const MAX_COOKIE_SEARCH: u64 = 8 << 20;
/// The most magic matches tried as cookies before the search gives up.
pub const MAX_COOKIE_CANDIDATES: usize = 64;
/// The largest table of contents read; a longer one is walked only this far.
pub const MAX_TOC_BYTES: u64 = 16 << 20;
/// The most table-of-contents entries walked.
pub const MAX_TOC_ENTRIES: usize = 65_536;
/// The longest entry name retained, in bytes; longer ones are cut at a char boundary.
pub const MAX_NAME_BYTES: usize = 1024;
/// The size of a table-of-contents entry header: length, position, sizes, compression flag and typecode.
const ENTRY_HEADER: usize = 18;

/// Which cookie layout the archive uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieLayout {
    /// The 24-byte cookie of PyInstaller before 2.1: magic, package length, TOC offset and length, Python version.
    Legacy,
    /// The 88-byte cookie of PyInstaller 2.1 and later, adding the 64-byte Python library name.
    WithPythonLibrary,
}

impl CookieLayout {
    pub fn size(self) -> u64 {
        match self {
            CookieLayout::Legacy => 24,
            CookieLayout::WithPythonLibrary => 88,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TocEntry {
    /// Position in the table of contents.
    pub index: usize,
    /// File offset of this entry's TOC record.
    pub record_offset: u64,
    pub record_length: u32,
    /// The data's position as recorded, relative to the package start.
    pub data_position: u32,
    /// File offset of the data: the package start plus `data_position`.
    pub data_offset: u64,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    /// 0 stored, 1 zlib; other values are reported as found.
    pub compression_flag: u8,
    pub typecode: char,
    /// What the typecode means, or `unknown`.
    pub kind: &'static str,
    pub name: String,
    pub name_truncated: bool,
    /// Whether the data lies within the package.
    pub data_in_bounds: bool,
}

/// The header of a PYZ entry: `PYZ\0`, the pyc magic of the Python that wrote it and its TOC offset. The TOC itself
/// (marshalled and zlib-compressed) is not read.
#[derive(Debug, Clone, Serialize)]
pub struct PyzHeader {
    pub entry_index: usize,
    pub offset: u64,
    pub magic_valid: bool,
    /// The four pyc magic bytes, as hex.
    pub pyc_magic: String,
    /// The pyc magic number (its first two bytes, little-endian).
    pub pyc_magic_number: u16,
    /// The Python version that magic number belongs to, when known.
    pub python_version: Option<&'static str>,
    /// The PYZ TOC's offset from the PYZ entry's start.
    pub toc_offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypecodeCount {
    pub typecode: char,
    pub kind: &'static str,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PyInstallerArchive {
    pub file_size: u64,
    /// File offset of the cookie's magic.
    pub cookie_offset: u64,
    pub cookie_layout: CookieLayout,
    pub cookie_size: u64,
    /// Bytes after the cookie (such as a signature): not part of the archive.
    pub trailing_bytes: u64,
    /// File offset of the package (the archive's first byte): the cookie's end minus `package_length`.
    pub package_offset: u64,
    pub package_length: u32,
    /// File offset and length of the table of contents.
    pub toc_offset: u64,
    pub toc_length: u32,
    /// The cookie's Python version field as written, such as 312.
    pub python_version_raw: u32,
    /// `major.minor`, such as `3.12`.
    pub python_version: String,
    /// The Python shared library name, for the 88-byte layout.
    pub python_library: Option<String>,
    /// Entries walked; equal to the TOC's entry count when `toc_complete`.
    pub entries_total: usize,
    pub toc_complete: bool,
    pub typecodes: Vec<TypecodeCount>,
    /// The first PYZ entry's header, when it is stored uncompressed within the package.
    pub pyz: Option<PyzHeader>,
    /// Magic matches tried, from the end, before this cookie validated.
    pub cookie_candidates_examined: usize,
    pub warnings: Vec<String>,
    #[serde(skip)]
    pub entries: Vec<TocEntry>,
}

/// The outcome of a cookie search: the archive, when a cookie validated, and why magic matches did not.
#[derive(Debug, Clone)]
pub struct CookieSearch {
    pub archive: Option<PyInstallerArchive>,
    /// One reason per magic match that did not validate as a cookie, newest first, up to
    /// [`MAX_COOKIE_CANDIDATES`]; empty when the search window holds no magic at all.
    pub rejected: Vec<String>,
}

/// Finds and walks the CArchive of the regular file at `path`. A file whose last [`MAX_COOKIE_SEARCH`] bytes hold no
/// magic, or only magic that does not validate as a cookie (a bootloader holds the magic as a constant), has no
/// archive; the search then says why each match was rejected.
pub fn pyinstaller_file(path: &Path) -> Result<CookieSearch, LoadError> {
    let mut file = open_regular_file(path)?;
    archive(&mut file).map_err(|error| match error {
        Error::Io(source) => LoadError::Io { path: path.to_owned(), source },
        Error::Malformed(text) => LoadError::Malformed(text),
    })
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Malformed(String),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// [`pyinstaller_file`] over any seekable reader. Only reading the archive a validated cookie describes can fail.
pub fn archive(input: &mut (impl Read + Seek)) -> Result<CookieSearch, Error> {
    let file_size = input.seek(SeekFrom::End(0))?;
    let window = file_size.min(MAX_COOKIE_SEARCH);
    let base = file_size - window;
    let tail = read_at(input, base, window as usize)?;
    let mut rejected = Vec::new();
    let mut end = tail.len();
    while let Some(at) = tail[..end].windows(MAGIC.len()).rposition(|bytes| bytes == MAGIC) {
        end = at + MAGIC.len() - 1;
        if rejected.len() == MAX_COOKIE_CANDIDATES {
            rejected.push(format!("search stopped after {MAX_COOKIE_CANDIDATES} magic matches without a valid cookie"));
            break;
        }
        let offset = base + at as u64;
        match cookie(&tail[at..], offset, file_size) {
            Ok(cookie) => {
                let archive = walk(input, cookie, file_size, rejected.len() + 1)?;
                return Ok(CookieSearch { archive: Some(archive), rejected });
            }
            Err(reason) => rejected.push(format!("cookie magic at {offset:#x}: {reason}")),
        }
    }
    Ok(CookieSearch { archive: None, rejected })
}

struct Cookie {
    offset: u64,
    layout: CookieLayout,
    package_offset: u64,
    package_length: u32,
    toc_position: u32,
    toc_length: u32,
    python_version: u32,
    python_library: Option<String>,
}

/// The cookie whose magic starts `bytes` (at file offset `offset`), trying the 88-byte layout first.
fn cookie(bytes: &[u8], offset: u64, file_size: u64) -> Result<Cookie, String> {
    let with_library = cookie_as(bytes, offset, file_size, CookieLayout::WithPythonLibrary);
    with_library.or_else(|first| {
        cookie_as(bytes, offset, file_size, CookieLayout::Legacy)
            .map_err(|second| format!("not an 88-byte cookie ({first}) nor a 24-byte one ({second})"))
    })
}

fn cookie_as(bytes: &[u8], offset: u64, file_size: u64, layout: CookieLayout) -> Result<Cookie, String> {
    let size = layout.size();
    let Some(bytes) = bytes.get(..size as usize) else {
        return Err("truncated".to_owned());
    };
    let field = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    let (package_length, toc_position, toc_length, python_version) = (field(8), field(12), field(16), field(20));
    let end = offset + size;
    debug_assert!(end <= file_size);
    if u64::from(package_length) < size || u64::from(package_length) > end {
        return Err(format!("package length {package_length:#x} outside the {end:#x} bytes before the cookie's end"));
    }
    // The TOC lies within the package, before the cookie; toc_length is a signed field in the format.
    let before_cookie = u64::from(package_length) - size;
    if i32::try_from(toc_length).is_err() || u64::from(toc_position) + u64::from(toc_length) > before_cookie {
        return Err(format!("TOC {toc_position:#x}+{toc_length:#x} outside the package"));
    }
    if !(10..=999).contains(&python_version) {
        return Err(format!("implausible Python version {python_version}"));
    }
    let python_library = match layout {
        CookieLayout::Legacy => None,
        CookieLayout::WithPythonLibrary => {
            let name = &bytes[24..88];
            let length = name.iter().position(|&byte| byte == 0).ok_or("python library name is not terminated")?;
            let (text, padding) = name.split_at(length);
            if text.is_empty() || !text.iter().all(|byte| byte.is_ascii_graphic()) || padding.iter().any(|&b| b != 0) {
                return Err("python library name is not NUL-padded printable ASCII".to_owned());
            }
            Some(String::from_utf8_lossy(text).into_owned())
        }
    };
    Ok(Cookie {
        offset,
        layout,
        package_offset: end - u64::from(package_length),
        package_length,
        toc_position,
        toc_length,
        python_version,
        python_library,
    })
}

fn walk(
    input: &mut (impl Read + Seek),
    cookie: Cookie,
    file_size: u64,
    examined: usize,
) -> Result<PyInstallerArchive, Error> {
    let size = cookie.layout.size();
    let toc_offset = cookie.package_offset + u64::from(cookie.toc_position);
    let mut warnings = Vec::new();
    let mut toc_complete = true;
    let read_length = u64::from(cookie.toc_length).min(MAX_TOC_BYTES);
    if read_length < u64::from(cookie.toc_length) {
        toc_complete = false;
        warnings.push(format!("TOC of {:#x} bytes read only to {MAX_TOC_BYTES:#x}", cookie.toc_length));
    }
    let toc = read_at(input, toc_offset, read_length as usize)?;
    let mut entries = Vec::new();
    let mut at = 0;
    while at < toc.len() {
        if entries.len() == MAX_TOC_ENTRIES {
            toc_complete = false;
            warnings.push(format!("TOC walk stopped at {MAX_TOC_ENTRIES} entries"));
            break;
        }
        let Some(header) = toc.get(at..at + ENTRY_HEADER) else {
            toc_complete = false;
            warnings.push(format!("{} trailing TOC bytes at {:#x} are too short for an entry", toc.len() - at, at));
            break;
        };
        let field = |offset: usize| u32::from_be_bytes(header[offset..offset + 4].try_into().unwrap());
        let record_length = field(0);
        let record_end = at.saturating_add(record_length as usize);
        if (record_length as usize) < ENTRY_HEADER || record_end > toc.len() {
            toc_complete = false;
            warnings.push(format!("TOC entry {} at {:#x} has invalid length {record_length:#x}", entries.len(), at));
            break;
        }
        let raw_name = &toc[at + ENTRY_HEADER..record_end];
        let raw_name = &raw_name[..raw_name.iter().position(|&byte| byte == 0).unwrap_or(raw_name.len())];
        let (name, name_truncated) = clip_name(raw_name);
        let (data_position, compressed_size) = (field(4), field(8));
        let typecode = char::from(header[17]);
        entries.push(TocEntry {
            index: entries.len(),
            record_offset: toc_offset + at as u64,
            record_length,
            data_position,
            data_offset: cookie.package_offset + u64::from(data_position),
            compressed_size,
            uncompressed_size: field(12),
            compression_flag: header[16],
            typecode,
            kind: typecode_kind(typecode),
            name,
            name_truncated,
            data_in_bounds: u64::from(data_position) + u64::from(compressed_size) <= u64::from(cookie.package_length),
        });
        at = record_end;
    }
    let mut typecodes: Vec<TypecodeCount> = Vec::new();
    for entry in &entries {
        match typecodes.iter_mut().find(|count| count.typecode == entry.typecode) {
            Some(count) => count.count += 1,
            None => typecodes.push(TypecodeCount { typecode: entry.typecode, kind: entry.kind, count: 1 }),
        }
    }
    let pyz = match entries.iter().find(|entry| entry.typecode == 'z') {
        Some(entry) if entry.compression_flag != 0 => {
            warnings.push(format!("PYZ entry {} is compressed; its header is not read", entry.index));
            None
        }
        Some(entry) if !entry.data_in_bounds || entry.compressed_size < 12 => {
            warnings.push(format!("PYZ entry {} lies outside the package or is too short", entry.index));
            None
        }
        Some(entry) => Some(pyz_header(input, entry)?),
        None => None,
    };
    let version = cookie.python_version;
    Ok(PyInstallerArchive {
        file_size,
        cookie_offset: cookie.offset,
        cookie_layout: cookie.layout,
        cookie_size: size,
        trailing_bytes: file_size - cookie.offset - size,
        package_offset: cookie.package_offset,
        package_length: cookie.package_length,
        toc_offset,
        toc_length: cookie.toc_length,
        python_version_raw: version,
        // PyInstaller writes major * 100 + minor since Python 3.10, and major * 10 + minor before it.
        python_version: if version >= 100 {
            format!("{}.{}", version / 100, version % 100)
        } else {
            format!("{}.{}", version / 10, version % 10)
        },
        python_library: cookie.python_library,
        entries_total: entries.len(),
        toc_complete,
        typecodes,
        pyz,
        cookie_candidates_examined: examined,
        warnings,
        entries,
    })
}

fn pyz_header(input: &mut (impl Read + Seek), entry: &TocEntry) -> Result<PyzHeader, Error> {
    let bytes = read_at(input, entry.data_offset, 12)?;
    let magic: [u8; 4] = bytes[4..8].try_into().unwrap();
    let number = u16::from_le_bytes([magic[0], magic[1]]);
    Ok(PyzHeader {
        entry_index: entry.index,
        offset: entry.data_offset,
        magic_valid: &bytes[..4] == b"PYZ\0",
        pyc_magic: magic.iter().map(|byte| format!("{byte:02x}")).collect(),
        pyc_magic_number: number,
        python_version: (&magic[2..] == b"\r\n").then(|| pyc_python_version(number)).flatten(),
        toc_offset: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
    })
}

/// The Python version a pyc magic number belongs to, from CPython's `importlib._bootstrap_external` history.
pub fn pyc_python_version(number: u16) -> Option<&'static str> {
    Some(match number {
        20121 => "1.5",
        50428 => "1.6",
        50823 => "2.0",
        60202 => "2.1",
        60717 => "2.2",
        62011..=62021 => "2.3",
        62041..=62061 => "2.4",
        62071..=62131 => "2.5",
        62151..=62161 => "2.6",
        62171..=62211 => "2.7",
        3000..=3131 => "3.0",
        3141..=3151 => "3.1",
        3160..=3180 => "3.2",
        3190..=3230 => "3.3",
        3250..=3310 => "3.4",
        3320..=3351 => "3.5",
        3360..=3379 => "3.6",
        3390..=3399 => "3.7",
        3400..=3419 => "3.8",
        3420..=3429 => "3.9",
        3430..=3449 => "3.10",
        3450..=3499 => "3.11",
        3500..=3549 => "3.12",
        3550..=3599 => "3.13",
        3600..=3649 => "3.14",
        _ => return None,
    })
}

/// What a CArchive typecode means.
pub fn typecode_kind(typecode: char) -> &'static str {
    match typecode {
        'a' => "nested_package",
        'b' => "binary",
        'd' => "dependency",
        'l' => "splash",
        'm' => "module",
        'M' => "package",
        'n' => "symlink",
        'o' => "runtime_option",
        's' => "script",
        'x' => "data",
        'z' => "pyz",
        'Z' => "zipfile",
        _ => "unknown",
    }
}

fn clip_name(raw: &[u8]) -> (String, bool) {
    let text = String::from_utf8_lossy(raw);
    let (text, truncated) = crate::text::clip(&text, MAX_NAME_BYTES);
    (text.to_owned(), truncated)
}

/// Exactly `length` bytes at `offset`; a short file is malformed, not an I/O failure.
fn read_at(input: &mut (impl Read + Seek), offset: u64, length: usize) -> Result<Vec<u8>, Error> {
    input.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::with_capacity(length);
    input.take(length as u64).read_to_end(&mut bytes)?;
    if bytes.len() < length {
        return Err(Error::Malformed(format!("{length:#x} bytes at {offset:#x} run past the end of the file")));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn entry(position: u32, size: u32, flag: u8, typecode: u8, name: &str) -> Vec<u8> {
        let name_length = (name.len() + 1).next_multiple_of(16);
        let length = (ENTRY_HEADER + name_length) as u32;
        let mut bytes = Vec::new();
        for value in [length, position, size, size * 2] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.extend([flag, typecode]);
        bytes.extend(name.as_bytes());
        bytes.resize(length as usize, 0);
        bytes
    }

    /// A stub followed by a package of a script, a PYZ and a binary, its TOC and a cookie of `layout`.
    fn archive_bytes(layout: CookieLayout, trailing: usize) -> Vec<u8> {
        let mut bytes = b"\x7fELF stub with the magic MEI\x0c\x0b\x0a\x0b\x0e as a constant".to_vec();
        let package = bytes.len();
        let mut data = b"script".to_vec();
        let pyz = data.len() as u32;
        data.extend(b"PYZ\0\xcb\x0d\x0d\x0a\0\0\0\x10");
        data.extend(b"binary");
        let mut toc = entry(0, 6, 1, b's', "main");
        toc.extend(entry(pyz, 12, 0, b'z', "PYZ-00.pyz"));
        toc.extend(entry(pyz + 12, 6, 0, b'b', "libssl.so.3"));
        bytes.extend(&data);
        bytes.extend(&toc);
        let length = (data.len() + toc.len()) as u64 + layout.size();
        bytes.extend(MAGIC);
        for value in [length as u32, data.len() as u32, toc.len() as u32, 312] {
            bytes.extend(value.to_be_bytes());
        }
        if layout == CookieLayout::WithPythonLibrary {
            let mut name = b"libpython3.12.so.1.0".to_vec();
            name.resize(64, 0);
            bytes.extend(name);
        }
        assert_eq!(bytes.len() - package, length as usize);
        bytes.extend(vec![0xaa; trailing]);
        bytes
    }

    #[test]
    fn walks_both_cookie_layouts() {
        for (layout, library) in
            [(CookieLayout::WithPythonLibrary, Some("libpython3.12.so.1.0")), (CookieLayout::Legacy, None)]
        {
            let bytes = archive_bytes(layout, 100);
            let archive = archive(&mut Cursor::new(&bytes)).unwrap().archive.unwrap();
            assert_eq!(archive.cookie_layout, layout);
            assert_eq!(archive.python_library.as_deref(), library);
            assert_eq!((archive.python_version.as_str(), archive.trailing_bytes), ("3.12", 100));
            assert_eq!(&bytes[archive.cookie_offset as usize..][..8], MAGIC);
            assert!(archive.toc_complete, "{:?}", archive.warnings);
            let names: Vec<&str> = archive.entries.iter().map(|entry| entry.name.as_str()).collect();
            assert_eq!(names, ["main", "PYZ-00.pyz", "libssl.so.3"]);
            let kinds: Vec<&str> = archive.entries.iter().map(|entry| entry.kind).collect();
            assert_eq!(kinds, ["script", "pyz", "binary"]);
            assert_eq!(&bytes[archive.entries[2].data_offset as usize..][..6], b"binary");
            let pyz = archive.pyz.unwrap();
            assert!(pyz.magic_valid);
            assert_eq!((pyz.pyc_magic_number, pyz.python_version, pyz.toc_offset), (3531, Some("3.12"), 16));
        }
    }

    #[test]
    fn no_cookie_is_none_and_a_lone_magic_is_a_rejected_candidate() {
        for bytes in [&b"\x7fELF plain"[..], &[]] {
            let search = archive(&mut Cursor::new(bytes)).unwrap();
            assert!(search.archive.is_none() && search.rejected.is_empty());
        }
        let search = archive(&mut Cursor::new(b"stub MEI\x0c\x0b\x0a\x0b\x0e garbage")).unwrap();
        assert!(search.archive.is_none());
        assert_eq!(search.rejected.len(), 1);
        assert!(search.rejected[0].contains("cookie magic at 0x5"), "{:?}", search.rejected);

        let many = MAGIC.repeat(MAX_COOKIE_CANDIDATES + 10);
        let search = archive(&mut Cursor::new(&many)).unwrap();
        assert_eq!(search.rejected.len(), MAX_COOKIE_CANDIDATES + 1);
        assert!(search.rejected.last().unwrap().contains("search stopped"));
    }

    #[test]
    fn truncation_and_corruption_never_panic() {
        let bytes = archive_bytes(CookieLayout::WithPythonLibrary, 0);
        for end in 0..bytes.len() {
            let _ = archive(&mut Cursor::new(&bytes[..end]));
        }
        for at in 0..bytes.len() {
            for value in [0x00, 0x7f, 0xff] {
                let mut corrupt = bytes.clone();
                corrupt[at] = value;
                if let Ok(CookieSearch { archive: Some(archive), .. }) = archive(&mut Cursor::new(&corrupt)) {
                    assert!(archive.entries.len() <= 3);
                }
            }
        }
    }

    #[test]
    fn a_bad_toc_entry_stops_the_walk_with_a_warning() {
        let mut bytes = archive_bytes(CookieLayout::Legacy, 0);
        let archive = archive(&mut Cursor::new(&bytes)).unwrap().archive.unwrap();
        let second = archive.entries[1].record_offset as usize;
        bytes[second..second + 4].copy_from_slice(&0xffffu32.to_be_bytes());
        let cut = super::archive(&mut Cursor::new(&bytes)).unwrap().archive.unwrap();
        assert_eq!((cut.entries_total, cut.toc_complete), (1, false));
        assert!(cut.warnings[0].contains("invalid length"), "{:?}", cut.warnings);
    }

    #[test]
    fn a_compressed_or_out_of_bounds_pyz_is_reported_not_read() {
        let bytes = archive_bytes(CookieLayout::Legacy, 0);
        let record = archive(&mut Cursor::new(&bytes)).unwrap().archive.unwrap().entries[1].record_offset as usize;

        let mut compressed = bytes.clone();
        compressed[record + 16] = 1;
        let found = archive(&mut Cursor::new(&compressed)).unwrap().archive.unwrap();
        assert!(found.pyz.is_none());
        assert!(
            found.warnings.iter().any(|warning| warning.contains("PYZ entry 1 is compressed")),
            "{:?}",
            found.warnings
        );

        let mut outside = bytes;
        outside[record + 4..record + 8].copy_from_slice(&0x7fff_0000u32.to_be_bytes());
        let found = archive(&mut Cursor::new(&outside)).unwrap().archive.unwrap();
        assert!(found.pyz.is_none() && !found.entries[1].data_in_bounds);
        assert!(found.warnings.iter().any(|warning| warning.contains("outside the package")), "{:?}", found.warnings);
    }

    #[test]
    fn a_toc_longer_than_the_cap_is_read_only_to_it() {
        let toc_length = MAX_TOC_BYTES as u32 + 32;
        let mut bytes = entry(0, 0, 0, b'x', "data");
        bytes.resize(toc_length as usize, 0);
        bytes.extend(MAGIC);
        for value in [toc_length + 24, 0, toc_length, 312] {
            bytes.extend(value.to_be_bytes());
        }
        let found = archive(&mut Cursor::new(&bytes)).unwrap().archive.unwrap();
        assert_eq!((found.entries_total, found.toc_complete), (1, false));
        assert!(found.warnings[0].contains("read only to 0x1000000"), "{:?}", found.warnings);
    }

    #[test]
    fn versions_and_typecodes_map() {
        assert_eq!(pyc_python_version(3495), Some("3.11"));
        assert_eq!(pyc_python_version(62211), Some("2.7"));
        assert_eq!(pyc_python_version(1), None);
        assert_eq!(typecode_kind('o'), "runtime_option");
        assert_eq!(typecode_kind('?'), "unknown");
    }
}
