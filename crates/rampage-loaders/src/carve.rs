//! Carving: a bounded, read-only scan of a file for embedded executables (ELF, PE, Mach-O) and containers (zip,
//! gzip, xz, zstd, LZMA, squashfs, cpio, uImage, Android boot images), found by magic and checked against their
//! headers. Nothing is extracted, decompressed or executed: extents come from header tables alone.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;
use rampage_arch::Arch;
use rampage_arch::bytes::read_uint;
use serde::Serialize;

use crate::LoadError;

/// The most candidates one scan reports; the scan stops at the first candidate past it.
pub const MAX_CANDIDATES: usize = 4096;
/// The longest prefix of a file one scan reads.
pub const MAX_SCAN_BYTES: u64 = 4 << 30;
/// The most bytes one scan searches for the end of gzip header fields, whose terminator can be far from the header
/// that names them; past it, gzip headers carrying such fields are no longer checked.
pub const MAX_PROBE_BYTES: u64 = 64 << 20;
/// The most table entries (ELF program and section headers, Mach-O load commands, fat slices, archive members)
/// read for one candidate.
const MAX_TABLE_ENTRIES: usize = 4096;
/// The furthest `e_lfanew` may point; real linkers keep it within the first few hundred bytes.
const MAX_PE_HEADER_OFFSET: usize = 1 << 20;
const MAX_FAT_SLICES: u64 = 64;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_candidates: usize,
    pub max_scan_bytes: u64,
    pub max_probe_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_candidates: MAX_CANDIDATES, max_scan_bytes: MAX_SCAN_BYTES, max_probe_bytes: MAX_PROBE_BYTES }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Elf,
    Pe,
    MachO,
    MachOFat,
    Zip,
    Gzip,
    Xz,
    Zstd,
    Lzma,
    Squashfs,
    Cpio,
    UImage,
    AndroidBoot,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::MachO => "mach_o",
            Self::MachOFat => "mach_o_fat",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lzma => "lzma",
            Self::Squashfs => "squashfs",
            Self::Cpio => "cpio",
            Self::UImage => "u_image",
            Self::AndroidBoot => "android_boot",
        })
    }
}

/// How far a candidate's header was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The header's fields and tables were checked for consistency within the file.
    Validated,
    /// Only the magic (or, for LZMA, a plausible header) matched; the header is truncated, inconsistent or
    /// carries no checkable structure, so no other facts are reported.
    MagicOnly,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Validated => "validated",
            Self::MagicOnly => "magic_only",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        })
    }
}

/// One architecture slice of a universal Mach-O; `offset` is in the scanned file, not relative to the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FatSlice {
    pub arch: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// Where the candidate starts in the scanned file.
    pub offset: u64,
    pub kind: Kind,
    pub confidence: Confidence,
    pub arch: Option<String>,
    pub bits: Option<u8>,
    pub endianness: Option<Endianness>,
    /// The size the header records for the object as stored, where the format records one.
    pub declared_size: Option<u64>,
    /// The decompressed size the header records; not verified, since nothing is decompressed.
    pub uncompressed_size: Option<u64>,
    /// Estimated length in bytes from `offset`, from header tables; absent when only decompression or an
    /// unbounded walk could tell. It may run past the end of the file, which a note then says.
    pub extent: Option<u64>,
    /// Which header structures the extent was computed from.
    pub extent_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub slices: Vec<FatSlice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Candidate {
    fn new(kind: Kind) -> Self {
        Self {
            offset: 0,
            kind,
            confidence: Confidence::Validated,
            arch: None,
            bits: None,
            endianness: None,
            declared_size: None,
            uncompressed_size: None,
            extent: None,
            extent_source: None,
            slices: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// A candidate whose header did not validate: it keeps only the reason.
    fn magic_only(kind: Kind, reason: impl Into<String>) -> Self {
        Self { confidence: Confidence::MagicOnly, notes: vec![reason.into()], ..Self::new(kind) }
    }

    fn endian(mut self, big: bool) -> Self {
        self.endianness = Some(if big { Endianness::Big } else { Endianness::Little });
        self
    }

    fn extent(mut self, extent: u64, source: &'static str) -> Self {
        self.extent = Some(extent);
        self.extent_source = Some(source);
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Carving {
    pub file_size: u64,
    /// How many leading bytes were searched for candidates (header tables may be read past it).
    pub scanned_bytes: u64,
    pub candidates: Vec<Candidate>,
    /// Whether a limit cut the scan short; `limitations` says which.
    pub truncated: bool,
    pub limitations: Vec<String>,
    /// Whether a candidate past `Limits::max_candidates` stopped the scan; its limitation comes first.
    #[serde(skip)]
    candidate_cap_reached: bool,
    /// Whether a limit other than the candidate cap cut the scan short.
    #[serde(skip)]
    otherwise_truncated: bool,
}

impl Carving {
    /// For a caller that set the candidate cap to end a page rather than to limit the scan: drops the cap's
    /// limitation, keeping `truncated` only for the other limits.
    pub fn treat_candidate_cap_as_page_end(&mut self) {
        if std::mem::take(&mut self.candidate_cap_reached) {
            self.limitations.remove(0);
            self.truncated = self.otherwise_truncated;
        }
    }
}

/// Carves the regular file at `path`, mapping it read-only.
pub fn carve_file(path: &Path, limits: &Limits) -> Result<Carving, LoadError> {
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    // Checked before opening: opening a FIFO for reading blocks until a writer appears.
    if !std::fs::metadata(path).map_err(io_error)?.is_file() {
        return Err(io_error(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file")));
    }
    let file = File::open(path).map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() == 0 {
        return Ok(scan(&[], limits));
    }
    // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope, the same
    // assumption `Binary::open` makes.
    let data = unsafe { Mmap::map(&file) }.map_err(io_error)?;
    Ok(scan(&data, limits))
}

/// Scans `data` for embedded executables and containers, in offset order.
pub fn scan(data: &[u8], limits: &Limits) -> Carving {
    let scanned = data.len().min(usize::try_from(limits.max_scan_bytes).unwrap_or(usize::MAX));
    let mut candidates = Vec::new();
    let mut limitations = Vec::new();
    let mut otherwise_truncated = false;
    let mut candidate_cap_reached = false;
    // Archive member headers inside an archive already reported are part of it, not new archives.
    let mut zip_members_until = 0;
    let mut cpio_members_until = 0;
    let mut probe = Probe { left: limits.max_probe_bytes, exhausted: false };
    let mut probe_exhausted_at = None;
    for offset in 0..scanned {
        let bytes = &data[offset..];
        let found = match bytes[0] {
            0x7f => elf(bytes),
            b'M' => pe(bytes),
            0xfe | 0xce | 0xcf => macho(bytes),
            0xca => fat(bytes),
            b'P' if offset >= zip_members_until => zip(bytes).map(|(candidate, walked)| {
                zip_members_until = offset.saturating_add(walked);
                candidate
            }),
            0x1f => {
                let found = gzip(bytes, &mut probe);
                if probe.exhausted {
                    probe_exhausted_at.get_or_insert(offset);
                }
                found
            }
            0xfd => xz(bytes),
            0x28 => zstd(bytes),
            0x5d => lzma(bytes),
            b'h' | b's' => squashfs(bytes),
            b'0' if offset >= cpio_members_until => cpio(bytes).map(|(candidate, walked)| {
                cpio_members_until = offset.saturating_add(walked);
                candidate
            }),
            0x27 => uimage(bytes),
            b'A' => android_boot(bytes),
            _ => None,
        };
        let Some(mut candidate) = found else { continue };
        if candidates.len() >= limits.max_candidates {
            candidate_cap_reached = true;
            limitations.push(format!(
                "stopped at the candidate cap ({}) at offset {offset:#x}; later offsets were not scanned",
                limits.max_candidates
            ));
            break;
        }
        candidate.offset = offset as u64;
        for slice in &mut candidate.slices {
            slice.offset = slice.offset.saturating_add(offset as u64);
        }
        if let Some(extent) = candidate.extent
            && extent > bytes.len() as u64
        {
            candidate
                .notes
                .push(format!("extent runs {:#x} bytes past the end of the file", extent - bytes.len() as u64));
        }
        candidates.push(candidate);
    }
    if scanned < data.len() {
        otherwise_truncated = true;
        limitations.push(format!("scanned only the first {scanned:#x} of {:#x} bytes", data.len()));
    }
    if let Some(offset) = probe_exhausted_at {
        otherwise_truncated = true;
        limitations.push(format!(
            "the search for gzip header name and comment ends ran out of its {:#x}-byte budget at offset \
             {offset:#x}; gzip streams carrying those fields from there on were not reported",
            limits.max_probe_bytes
        ));
    }
    limitations.push(
        "candidates are found by magic and header checks only: nothing is extracted, decompressed or executed, \
         and compressed streams have no extent unless their header records one"
            .to_owned(),
    );
    limitations.push(
        "zip and cpio headers inside a reported archive, up to its end or its last member header read, are taken \
         as its members: an archive stored inside another archive's members is not reported separately"
            .to_owned(),
    );
    Carving {
        file_size: data.len() as u64,
        scanned_bytes: scanned as u64,
        candidates,
        truncated: candidate_cap_reached || otherwise_truncated,
        limitations,
        candidate_cap_reached,
        otherwise_truncated,
    }
}

fn end_of(offset: u64, size: u64) -> Option<u64> {
    offset.checked_add(size)
}

/// A table of `count` entries of `size` bytes at `offset`, if it lies within `bytes`.
fn table_fits(bytes: &[u8], offset: u64, count: u64, size: u64) -> Option<u64> {
    let end = offset.checked_add(count.checked_mul(size)?)?;
    (end <= bytes.len() as u64).then_some(end)
}

fn table_note(what: &str, count: u64) -> Option<String> {
    (count > MAX_TABLE_ENTRIES as u64)
        .then(|| format!("read only the first {MAX_TABLE_ENTRIES} of {count} {what}; the extent may be low"))
}

fn elf_arch(machine: u64, bits: u8) -> String {
    let arch = match (machine, bits) {
        (3, _) => Arch::X86,
        (62, _) => Arch::X86_64,
        (183, _) => Arch::Aarch64,
        (40, _) => Arch::Arm,
        (8 | 10, 64) => Arch::Mips64,
        (8 | 10, _) => Arch::Mips,
        (20, _) => Arch::PowerPc,
        (21, _) => Arch::PowerPc64,
        (243, 64) => Arch::Riscv64,
        (243, _) => Arch::Riscv32,
        (2 | 18, _) => Arch::Sparc,
        (43, _) => Arch::Sparc64,
        (22, 64) => Arch::S390x,
        (4, _) => Arch::M68k,
        _ => return format!("elf machine {machine:#x}"),
    };
    arch.to_string()
}

fn elf(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let (bits, wide) = match bytes.get(4)? {
        1 => (32, false),
        2 => (64, true),
        _ => return None,
    };
    let big = match bytes.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let read = |at: u64, width: usize| read_uint(bytes, usize::try_from(at).ok()?, width, big);
    let word = if wide { 8 } else { 4 };
    let at = |narrow: u64, wide_at: u64| if wide { wide_at } else { narrow };
    let header = || -> Option<[u64; 9]> {
        Some([
            read(16, 2)?,
            read(18, 2)?,
            read(20, 4)?,
            read(at(28, 32), word)?,
            read(at(32, 40), word)?,
            read(at(40, 52), 2)?,
            read(at(42, 54), 2)?,
            read(at(44, 56), 2)?,
            read(at(48, 60), 2)?,
        ])
    };
    let Some([kind, machine, version, phoff, shoff, ehsize, phentsize, phnum, shnum]) = header() else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF header is truncated"));
    };
    let shentsize = read(at(46, 58), 2)?;
    let (ehsize_ok, phent_ok, shent_ok) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    if bytes[6] != 1
        || version != 1
        || !(1..=4).contains(&kind)
        || ehsize != ehsize_ok
        || (phnum != 0 && phentsize != phent_ok)
        || (shnum != 0 && shentsize != shent_ok)
    {
        return Some(Candidate::magic_only(Kind::Elf, "ELF header fields are inconsistent"));
    }
    let Some(ph_end) = table_fits(bytes, phoff, phnum, phentsize) else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF program header table lies outside the file"));
    };
    let Some(sh_end) = table_fits(bytes, shoff, shnum, shentsize) else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF section header table lies outside the file"));
    };
    let mut candidate = Candidate::new(Kind::Elf).endian(big);
    candidate.bits = Some(bits);
    candidate.arch = Some(elf_arch(machine, bits));
    let mut end = ehsize.max(if phnum == 0 { 0 } else { ph_end }).max(if shnum == 0 { 0 } else { sh_end });
    let overflow = || Some(Candidate::magic_only(Kind::Elf, "an ELF segment or section ends past 2^64"));
    for index in 0..phnum.min(MAX_TABLE_ENTRIES as u64) {
        let entry = phoff + index * phentsize;
        let (offset, size) = (read(entry + at(4, 8), word)?, read(entry + at(16, 32), word)?);
        let Some(segment_end) = end_of(offset, size) else { return overflow() };
        end = end.max(segment_end);
    }
    for index in 0..shnum.min(MAX_TABLE_ENTRIES as u64) {
        let entry = shoff + index * shentsize;
        if matches!(read(entry + 4, 4)?, 0 | 8) {
            continue;
        }
        let (offset, size) = (read(entry + at(16, 24), word)?, read(entry + at(20, 32), word)?);
        let Some(section_end) = end_of(offset, size) else { return overflow() };
        end = end.max(section_end);
    }
    candidate.notes.extend(table_note("program headers", phnum));
    candidate.notes.extend(table_note("section headers", shnum));
    Some(candidate.extent(end, "ELF header, program and section header tables"))
}

fn pe_arch(machine: u64) -> String {
    let arch = match machine {
        0x14c => Arch::X86,
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::Aarch64,
        0x1c0 | 0x1c2 | 0x1c4 => Arch::Arm,
        0x166 | 0x168 | 0x169 => Arch::Mips,
        0x1f0 | 0x1f1 => Arch::PowerPc,
        0x5032 => Arch::Riscv32,
        0x5064 => Arch::Riscv64,
        _ => return format!("pe machine {machine:#x}"),
    };
    arch.to_string()
}

fn pe(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    // "MZ" alone is too common to report: a candidate needs the PE signature `e_lfanew` points at.
    let lfanew = read_uint(bytes, 0x3c, 4, false)? as usize;
    if !(0x40..=MAX_PE_HEADER_OFFSET).contains(&lfanew) || bytes.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let coff = lfanew + 4;
    let optional = coff + 20;
    let header = || Some([read(coff, 2)?, read(coff + 2, 2)?, read(coff + 16, 2)?, read(optional, 2)?]);
    let Some([machine, sections, optional_size, magic]) = header() else {
        return Some(Candidate::magic_only(Kind::Pe, "PE headers are truncated"));
    };
    let (bits, directories) = match magic {
        0x10b => (32, 96),
        0x20b => (64, 112),
        _ => return Some(Candidate::magic_only(Kind::Pe, "PE optional header magic is neither PE32 nor PE32+")),
    };
    let section_table = optional + optional_size as usize;
    if optional_size < directories || !(1..=96).contains(&sections) {
        return Some(Candidate::magic_only(Kind::Pe, "PE optional header or section count is inconsistent"));
    }
    if table_fits(bytes, section_table as u64, sections, 40).is_none() {
        return Some(Candidate::magic_only(Kind::Pe, "PE section table lies outside the file"));
    }
    let mut candidate = Candidate::new(Kind::Pe).endian(false);
    candidate.bits = Some(bits);
    candidate.arch = Some(pe_arch(machine));
    let mut end = read(optional + 60, 4)?.max(section_table as u64 + sections * 40);
    for index in 0..sections as usize {
        let entry = section_table + index * 40;
        let (size, offset) = (read(entry + 16, 4)?, read(entry + 20, 4)?);
        if size != 0 {
            end = end.max(offset + size);
        }
    }
    let mut source = "PE headers and section table";
    let (symbols, count) = (read(coff + 8, 4)?, read(coff + 12, 4)?);
    if symbols != 0 {
        let strings = symbols + count * 18;
        let string_size = usize::try_from(strings).ok().and_then(|at| read(at, 4)).unwrap_or(4);
        end = end.max(strings + string_size.max(4));
        source = "PE headers, section table and COFF symbol table";
    }
    // The Authenticode certificate table is the one data directory addressed by file offset, not RVA.
    let rva_count = read(optional + directories as usize - 4, 4)?;
    if rva_count > 4 && optional_size >= directories + 5 * 8 {
        let certificates = optional + directories as usize + 4 * 8;
        let (offset, size) = (read(certificates, 4)?, read(certificates + 4, 4)?);
        if offset != 0 && size != 0 {
            end = end.max(offset + size);
            source = "PE headers, section table and certificate table";
        }
    }
    Some(candidate.extent(end, source))
}

fn macho_arch(cputype: u64) -> String {
    let arch = match cputype {
        7 => Arch::X86,
        0x0100_0007 => Arch::X86_64,
        12 => Arch::Arm,
        0x0100_000c => Arch::Aarch64,
        0x0200_000c => return "arm64_32".to_owned(),
        18 => Arch::PowerPc,
        0x0100_0012 => Arch::PowerPc64,
        _ => return format!("mach-o cpu {cputype:#x}"),
    };
    arch.to_string()
}

fn macho_magic(bytes: &[u8]) -> Option<(u8, bool)> {
    match read_uint(bytes, 0, 4, true)? {
        0xfeed_face => Some((32, true)),
        0xcefa_edfe => Some((32, false)),
        0xfeed_facf => Some((64, true)),
        0xcffa_edfe => Some((64, false)),
        _ => None,
    }
}

fn macho(bytes: &[u8]) -> Option<Candidate> {
    let (bits, big) = macho_magic(bytes)?;
    let read = |at: u64, width: usize| read_uint(bytes, usize::try_from(at).ok()?, width, big);
    let header_size = if bits == 64 { 32 } else { 28 };
    let header = || Some([read(4, 4)?, read(12, 4)?, read(16, 4)?, read(20, 4)?]);
    let Some([cputype, filetype, commands, commands_size]) = header() else {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O header is truncated"));
    };
    if !(1..=12).contains(&filetype) || commands == 0 {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O header fields are inconsistent"));
    }
    let commands_end = header_size + commands_size;
    if commands_end > bytes.len() as u64 {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands lie outside the file"));
    }
    let mut end = commands_end;
    let mut at = header_size;
    for _ in 0..commands.min(MAX_TABLE_ENTRIES as u64) {
        let Some((command, size)) = read(at, 4).zip(read(at + 4, 4)) else {
            return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands are truncated"));
        };
        if size < 8 || !size.is_multiple_of(4) || at + size > commands_end {
            return Some(Candidate::magic_only(Kind::MachO, "Mach-O load command sizes are inconsistent"));
        }
        let fields = match command {
            0x1 => Some((32, 36, 4)),
            0x19 => Some((40, 48, 8)),
            0x2 => Some((16, 20, 4)),
            0x1d => Some((8, 12, 4)),
            _ => None,
        };
        if let Some((offset_at, size_at, width)) = fields {
            let Some((offset, size)) = read(at + offset_at, width).zip(read(at + size_at, width)) else {
                return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands are truncated"));
            };
            let Some(range_end) = end_of(offset, size) else {
                return Some(Candidate::magic_only(Kind::MachO, "a Mach-O segment or table ends past 2^64"));
            };
            end = end.max(range_end);
        }
        at += size;
    }
    let mut candidate = Candidate::new(Kind::MachO).endian(big);
    candidate.bits = Some(bits);
    candidate.arch = Some(macho_arch(cputype));
    candidate.notes.extend(table_note("load commands", commands));
    Some(candidate.extent(end, "Mach-O segments, symbol table and code signature"))
}

fn fat(bytes: &[u8]) -> Option<Candidate> {
    let entry_size = match read_uint(bytes, 0, 4, true)? {
        0xcafe_babe => 20,
        0xcafe_babf => 32,
        _ => return None,
    };
    // Java class files share the 0xcafebabe magic, so a fat header must prove itself through its slices.
    let count = read_uint(bytes, 4, 4, true)?;
    if count == 0 || count > MAX_FAT_SLICES {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, true);
    let mut candidate = Candidate::new(Kind::MachOFat).endian(true);
    let mut end = 8 + count * entry_size;
    let mut past_end = false;
    for index in 0..count as usize {
        let entry = 8 + index * entry_size as usize;
        let (cputype, offset, size, align) = if entry_size == 20 {
            (read(entry, 4)?, read(entry + 8, 4)?, read(entry + 12, 4)?, read(entry + 16, 4)?)
        } else {
            (read(entry, 4)?, read(entry + 8, 8)?, read(entry + 16, 8)?, read(entry + 24, 4)?)
        };
        if align > 20 || offset < 8 + count * entry_size || !offset.is_multiple_of(1 << align) || size == 0 {
            return None;
        }
        let slice_end = end_of(offset, size)?;
        match usize::try_from(offset).ok().and_then(|offset| bytes.get(offset..)).filter(|slice| slice.len() >= 4) {
            Some(slice) => _ = macho_magic(slice)?,
            None => past_end = true,
        }
        end = end.max(slice_end);
        candidate.slices.push(FatSlice { arch: macho_arch(cputype), offset, size });
    }
    if past_end {
        return Some(Candidate::magic_only(Kind::MachOFat, "universal Mach-O slices lie outside the file"));
    }
    candidate.notes.push(format!("{count} architecture slices"));
    Some(candidate.extent(end, "universal Mach-O slice table"))
}

const ZIP_METHODS: [u64; 13] = [0, 1, 6, 8, 9, 12, 14, 19, 93, 95, 96, 97, 98];
/// The most records (local and central directory headers) one zip walk reads.
const MAX_ZIP_RECORDS: usize = 2 * MAX_TABLE_ENTRIES;

/// A zip archive at its first local file header, and how many bytes from it the scan takes as the archive's own:
/// through its end when that is known, else through the last record header read whole.
fn zip(bytes: &[u8]) -> Option<(Candidate, usize)> {
    if !bytes.starts_with(b"PK\x03\x04") {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let header = || Some([read(4, 2)?, read(8, 2)?, read(26, 2)?]);
    let Some([version, method, name_len]) = header() else {
        return Some((Candidate::magic_only(Kind::Zip, "zip local header is truncated"), 4));
    };
    if version & 0xff > 63 || !ZIP_METHODS.contains(&method) || name_len == 0 || bytes.len() < 30 + name_len as usize {
        return Some((Candidate::magic_only(Kind::Zip, "zip local header fields are inconsistent"), 4));
    }
    let mut candidate = Candidate::new(Kind::Zip).endian(false);
    let past_end = "the archive runs past the end of the file";
    // `covered` ends the last record header read whole: a declared member size is not trusted past it.
    let (mut at, mut covered, mut members) = (0usize, 4usize, 0u64);
    let walk = 'walk: {
        for _ in 0..MAX_ZIP_RECORDS {
            let Some(signature) = read(at, 4) else { break 'walk Walk::Stopped(past_end) };
            let (header_end, data) = match signature {
                0x0403_4b50 => {
                    let fields =
                        (|| Some([read(at + 6, 2)?, read(at + 18, 4)?, read(at + 26, 2)?, read(at + 28, 2)?]))();
                    let Some([flags, compressed, name, extra]) = fields else { break 'walk Walk::Stopped(past_end) };
                    if flags & 8 != 0 || compressed == 0xffff_ffff {
                        break 'walk Walk::Stopped(
                            "a member's size is recorded after its data (data descriptor or zip64)",
                        );
                    }
                    (at + 30 + (name + extra) as usize, compressed as usize)
                }
                0x0201_4b50 => {
                    let fields = (|| Some([read(at + 28, 2)?, read(at + 30, 2)?, read(at + 32, 2)?]))();
                    let Some([name, extra, comment]) = fields else { break 'walk Walk::Stopped(past_end) };
                    (at + 46 + (name + extra + comment) as usize, 0)
                }
                0x0605_4b50 => {
                    let Some(comment) = read(at + 20, 2) else { break 'walk Walk::Stopped(past_end) };
                    let end = at + 22 + comment as usize;
                    candidate = candidate.extent(end as u64, "zip member headers and end of central directory");
                    covered = end.min(bytes.len());
                    break 'walk Walk::Ended;
                }
                _ => break 'walk Walk::Stopped("an unrecognized record follows the members"),
            };
            if header_end > bytes.len() {
                break 'walk Walk::Stopped(past_end);
            }
            members += u64::from(signature == 0x0403_4b50);
            covered = header_end;
            at = header_end.saturating_add(data);
        }
        Walk::Capped
    };
    match walk {
        Walk::Ended => {}
        Walk::Stopped(reason) => candidate.notes.push(format!("no extent: {reason}")),
        Walk::Capped => match zip_end(bytes, at.min(bytes.len())) {
            Some(end) => {
                candidate = candidate.extent(end as u64, "end of central directory found past the member walk's cap");
                candidate.notes.push(format!("the member walk stopped at its cap ({MAX_ZIP_RECORDS} records)"));
                covered = end.min(bytes.len());
            }
            None => {
                candidate.notes.push(format!(
                    "no extent: the member walk stopped at its cap ({MAX_ZIP_RECORDS} records) and no end of central \
                     directory follows; zip headers in the rest of the file are taken as its members"
                ));
                covered = bytes.len();
            }
        },
    }
    candidate.notes.push(format!("{members} members walked"));
    Some((candidate, covered))
}

/// The end of the first end-of-central-directory record from `from` on whose central directory ends right
/// before it, with offsets relative to the archive at the start of `bytes`.
fn zip_end(bytes: &[u8], mut from: usize) -> Option<usize> {
    while let Some(found) = bytes.get(from..)?.windows(4).position(|window| window == b"PK\x05\x06") {
        let record = from + found;
        let read = |at: usize, width: usize| read_uint(bytes, record + at, width, false);
        if let (Some(size), Some(start), Some(comment)) = (read(12, 4), read(16, 4), read(20, 2))
            && size + start == record as u64
        {
            return Some(record + 22 + comment as usize);
        }
        from = record + 1;
    }
    None
}

/// How an archive's member walk ended.
enum Walk {
    /// At the archive's terminating record, which gave the extent.
    Ended,
    Stopped(&'static str),
    Capped,
}

/// The longest zero-terminated gzip header field (original name, comment) read, terminator included: a file name
/// fits in it on common file systems, and a header with a longer field is not reported.
const MAX_GZIP_FIELD: usize = 256;

/// The bytes left for searching gzip header fields, so that a file of repeated plausible headers costs no more
/// than `Limits::max_probe_bytes` in all.
struct Probe {
    left: u64,
    exhausted: bool,
}

impl Probe {
    /// Where the first NUL in `field`'s first `MAX_GZIP_FIELD` bytes is, charging the bytes examined.
    fn nul(&mut self, field: &[u8]) -> Option<usize> {
        let allowed = usize::try_from(self.left).unwrap_or(usize::MAX).min(MAX_GZIP_FIELD);
        let window = &field[..field.len().min(allowed)];
        let end = window.iter().position(|&byte| byte == 0);
        self.left -= end.map_or(window.len(), |end| end + 1) as u64;
        if end.is_none() && window.len() < field.len().min(MAX_GZIP_FIELD) {
            self.exhausted = true;
        }
        end
    }
}

fn gzip(bytes: &[u8], probe: &mut Probe) -> Option<Candidate> {
    // Three magic bytes are too common to report alone: the reserved flag bits, the extra-flags and OS bytes and
    // the first deflate block header must also check out, or nothing is reported.
    if !bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        return None;
    }
    let flags = *bytes.get(3)?;
    if flags & 0xe0 != 0 || !matches!(bytes.get(8)?, 0 | 2 | 4) || !matches!(bytes.get(9)?, 0..=13 | 255) {
        return None;
    }
    let mut candidate = Candidate::new(Kind::Gzip);
    let mut at = 10;
    if flags & 0x04 != 0 {
        at += 2 + read_uint(bytes, at, 2, false)? as usize;
    }
    for (flag, what) in [(0x08, "original name"), (0x10, "comment")] {
        if flags & flag != 0 {
            let field = bytes.get(at..)?;
            let end = probe.nul(field)?;
            if flag == 0x08 {
                candidate.notes.push(format!("{what} {:?}", String::from_utf8_lossy(&field[..end])));
            }
            at += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        at += 2;
    }
    let block = *bytes.get(at)?;
    match (block >> 1) & 3 {
        // A stored block's length is followed by its ones' complement.
        0 if read_uint(bytes, at + 1, 2, false)? != !read_uint(bytes, at + 3, 2, false)? & 0xffff => None,
        3 => None,
        _ => Some(candidate),
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn xz(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"\xfd7zXZ\0") {
        return None;
    }
    let (Some(flags), Some(stored)) = (bytes.get(6..8), read_uint(bytes, 8, 4, false)) else {
        return Some(Candidate::magic_only(Kind::Xz, "xz stream header is truncated"));
    };
    if flags[0] != 0 || flags[1] & 0xf0 != 0 || u64::from(crc32(flags)) != stored {
        return Some(Candidate::magic_only(Kind::Xz, "xz stream flags or their CRC32 do not check out"));
    }
    Some(Candidate::new(Kind::Xz))
}

fn zstd(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return None;
    }
    let Some(&descriptor) = bytes.get(4) else {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header is truncated"));
    };
    if descriptor & 0x08 != 0 {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header's reserved bit is set"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let at = 5 + usize::from(!single_segment) + [0, 1, 2, 4][usize::from(descriptor & 3)];
    let width = match descriptor >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut candidate = Candidate::new(Kind::Zstd);
    let size = if width == 0 { Some(0) } else { read_uint(bytes, at, width, false) };
    let (Some(size), Some(block)) = (size, read_uint(bytes, at + width, 3, false)) else {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header is truncated"));
    };
    // The first block header: its type must not be the reserved one, and no block exceeds 128 KiB.
    if (block >> 1) & 3 == 3 || block >> 3 > 128 << 10 {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd first block header is invalid"));
    }
    if width > 0 {
        candidate.uncompressed_size = Some(if width == 2 { size + 256 } else { size });
    }
    Some(candidate)
}

fn lzma(bytes: &[u8]) -> Option<Candidate> {
    // LZMA-alone has no magic: only the common properties byte, a power-of-two dictionary between 64 KiB and
    // 1 GiB, a plausible size and the range coder's leading zero byte are checked.
    let dictionary = read_uint(bytes, 1, 4, false)?;
    let size = read_uint(bytes, 5, 8, false)?;
    if bytes[0] != 0x5d
        || !dictionary.is_power_of_two()
        || !(1 << 16..=1 << 30).contains(&dictionary)
        || (size != u64::MAX && size > 1 << 40)
        || *bytes.get(13)? != 0
    {
        return None;
    }
    let mut candidate = Candidate::magic_only(Kind::Lzma, "LZMA-alone has no magic; its header is only plausible");
    candidate.uncompressed_size = (size != u64::MAX).then_some(size);
    Some(candidate)
}

fn squashfs(bytes: &[u8]) -> Option<Candidate> {
    let big = match bytes.get(..4)? {
        b"hsqs" => false,
        b"sqsh" => true,
        _ => return None,
    };
    let read = |at: usize, width: usize| read_uint(bytes, at, width, big);
    let header = || Some([read(12, 4)?, read(20, 2)?, read(22, 2)?, read(28, 2)?, read(40, 8)?]);
    let Some([block_size, compression, block_log, major, used]) = header() else {
        return Some(Candidate::magic_only(Kind::Squashfs, "squashfs superblock is truncated"));
    };
    if major != 4
        || !(1..=6).contains(&compression)
        || !(12..=20).contains(&block_log)
        || block_size != 1 << block_log
        || used < 96
    {
        // "hsqs" and "sqsh" occur in ordinary text; only a consistent superblock is worth reporting.
        return None;
    }
    let mut candidate = Candidate::new(Kind::Squashfs).endian(big);
    let compressor = ["gzip", "lzma", "lzo", "xz", "lz4", "zstd"][compression as usize - 1];
    candidate.notes.push(format!("{compressor} compression, {block_size}-byte blocks"));
    candidate.declared_size = Some(used);
    Some(candidate.extent(used, "squashfs superblock bytes_used"))
}

/// A cpio (newc) archive at its first header, and how many bytes from it the scan takes as the archive's own:
/// through its end when that is known, else through the last member header read whole.
fn cpio(bytes: &[u8]) -> Option<(Candidate, usize)> {
    if !(bytes.starts_with(b"070701") || bytes.starts_with(b"070702")) {
        return None;
    }
    let field = |at: usize, index: usize| -> Option<u64> {
        let text = bytes.get(at + 6 + index * 8..at + 14 + index * 8)?;
        if !text.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u64::from_str_radix(std::str::from_utf8(text).ok()?, 16).ok()
    };
    let header = |at: usize| -> Option<(u64, &[u8])> {
        for index in 0..13 {
            field(at, index)?;
        }
        let name_size = field(at, 11)? as usize;
        let name = bytes.get(at + 110..at + 110 + name_size)?;
        Some((field(at, 6)?, name.strip_suffix(b"\0")?))
    };
    // Six ASCII digits alone are too common to report.
    header(0)?;
    let align = |at: usize| at.checked_add(3).map(|at| at & !3);
    // A member at `at`: its name, where its data starts and where the next member starts.
    let member = |at: usize| -> Option<(&[u8], usize, usize)> {
        let magic = bytes.get(at..at + 6)?;
        let (size, name) = header(at).filter(|_| magic == b"070701" || magic == b"070702")?;
        let data = align(at + 110 + name.len() + 1)?;
        Some((name, data, align(data.checked_add(usize::try_from(size).ok()?)?)?))
    };
    let mut candidate = Candidate::new(Kind::Cpio);
    // `covered` ends the last member header read whole: a declared member size is not trusted past it.
    let (mut at, mut covered, mut members) = (0usize, 6usize, 0u64);
    let walk = 'walk: {
        for _ in 0..MAX_TABLE_ENTRIES {
            let Some((name, data, next)) = member(at) else {
                break 'walk Walk::Stopped("a member header is missing or malformed");
            };
            covered = data.min(bytes.len());
            if name == b"TRAILER!!!" {
                candidate = candidate.extent(next as u64, "cpio member headers through TRAILER!!!");
                covered = next.min(bytes.len());
                break 'walk Walk::Ended;
            }
            members += 1;
            at = next;
        }
        Walk::Capped
    };
    match walk {
        Walk::Ended => {}
        Walk::Stopped(reason) => candidate.notes.push(format!("no extent: {reason}")),
        Walk::Capped => {
            // The trailer is the first member named TRAILER!!! after the cap, found by its name.
            let mut from = at.min(bytes.len());
            let trailer = loop {
                let Some(found) = bytes[from..].windows(11).position(|window| window == b"TRAILER!!!\0") else {
                    break None;
                };
                let name_at = from + found;
                if let Some((b"TRAILER!!!", _, next)) = name_at.checked_sub(110).and_then(member) {
                    break Some(next);
                }
                from = name_at + 1;
            };
            match trailer {
                Some(end) => {
                    candidate = candidate.extent(end as u64, "TRAILER!!! header found past the member walk's cap");
                    candidate.notes.push(format!("the member walk stopped at its cap ({MAX_TABLE_ENTRIES} members)"));
                    covered = end.min(bytes.len());
                }
                None => {
                    candidate.notes.push(format!(
                        "no extent: the member walk stopped at its cap ({MAX_TABLE_ENTRIES} members) and no \
                         TRAILER!!! header follows; cpio headers in the rest of the file are taken as its members"
                    ));
                    covered = bytes.len();
                }
            }
        }
    }
    candidate.notes.push(format!("{members} members walked"));
    Some((candidate, covered))
}

fn uimage(bytes: &[u8]) -> Option<Candidate> {
    if read_uint(bytes, 0, 4, true)? != 0x2705_1956 {
        return None;
    }
    let Some(header) = bytes.get(..64) else {
        return Some(Candidate::magic_only(Kind::UImage, "uImage header is truncated"));
    };
    let mut zeroed = [0u8; 64];
    zeroed.copy_from_slice(header);
    zeroed[4..8].fill(0);
    if u64::from(crc32(&zeroed)) != read_uint(header, 4, 4, true)? {
        return Some(Candidate::magic_only(Kind::UImage, "uImage header CRC32 does not match"));
    }
    let size = 64 + read_uint(header, 12, 4, true)?;
    let mut candidate = Candidate::new(Kind::UImage).endian(true);
    candidate.arch = Some(match header[29] {
        2 => Arch::Arm.to_string(),
        3 => Arch::X86.to_string(),
        5 => Arch::Mips.to_string(),
        6 => Arch::Mips64.to_string(),
        7 => Arch::PowerPc.to_string(),
        10 => Arch::Sparc.to_string(),
        11 => Arch::Sparc64.to_string(),
        12 => Arch::M68k.to_string(),
        22 => Arch::Aarch64.to_string(),
        24 => Arch::X86_64.to_string(),
        other => format!("uimage arch {other}"),
    });
    let name = &header[32..64];
    let name = &name[..name.iter().position(|&byte| byte == 0).unwrap_or(name.len())];
    candidate.notes.push(format!("image name {:?}, compression type {}", String::from_utf8_lossy(name), header[31]));
    candidate.declared_size = Some(size);
    Some(candidate.extent(size, "uImage header data size"))
}

fn android_boot(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"ANDROID!") {
        return None;
    }
    let read = |at: usize| read_uint(bytes, at, 4, false);
    let Some(version) = read(40) else {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image header is truncated"));
    };
    let parts = || -> Option<(u64, Vec<u64>)> {
        match version {
            0..=2 => {
                let mut parts = vec![read(8)?, read(16)?, read(24)?];
                if version >= 1 {
                    parts.push(read(1632)?);
                }
                if version == 2 {
                    parts.push(read(1648)?);
                }
                Some((read(36)?, parts))
            }
            3 => Some((4096, vec![read(8)?, read(12)?])),
            4 => Some((4096, vec![read(8)?, read(12)?, read(1580)?])),
            _ => None,
        }
    };
    let Some((page, parts)) = parts() else {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image header is truncated or unknown"));
    };
    if !page.is_power_of_two() || !(2048..=65536).contains(&page) {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image page size is implausible"));
    }
    let pages = parts.iter().map(|size| size.div_ceil(page)).sum::<u64>() + 1;
    let mut candidate = Candidate::new(Kind::AndroidBoot).endian(false);
    candidate.notes.push(format!("header version {version}, page size {page}"));
    candidate.declared_size = Some(pages * page);
    Some(candidate.extent(pages * page, "Android boot image header part sizes"))
}
