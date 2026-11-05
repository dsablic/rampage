//! Windows targets (step 9.6a): PE images as Windows stubs map them, Windows exception records and codes.
//!
//! Everything here is a pure parser with bounds-checked reads. Headers parse the same from a file or from target
//! memory (the first `SizeOfHeaders` bytes are mapped as they are in the file, except that the loader writes the
//! runtime base into `OptionalHeader.ImageBase` of a moved image). The stub behaviors these follow are from the stub
//! sources, not recorded from a live target: GDB's `gdbserver/win32-low.cc` and `gdb/nat/windows-nat.c`, and
//! LLVM's `lldb/source/Plugins/Process/Windows/Common/NativeProcessWindows.cpp`; see `docs/debug-control.md`.

use serde::Serialize;

use crate::stop::hex_address;

/// Header bytes read from target memory to parse a mapped image's headers.
pub const HEADER_READ: usize = 1024;
/// `IMAGE_FILE_DLL` in the COFF header's characteristics.
pub const IMAGE_FILE_DLL: u16 = 0x2000;
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`: the image may be moved (ASLR).
pub const DYNAMIC_BASE: u16 = 0x0040;
/// Data directory indexes.
pub const DIRECTORY_BASERELOC: usize = 5;
pub const DIRECTORY_DEBUG: usize = 6;
/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
const DEBUG_TYPE_CODEVIEW: u32 = 2;
/// Most sections and debug directory entries read from one image.
const MAX_SECTIONS: usize = 96;
const MAX_DEBUG_ENTRIES: usize = 16;
/// Most relocation entries read from one image.
pub const MAX_RELOCATIONS: usize = 1 << 20;
/// gdbserver reports a DLL at its base plus this, "the offset from 0 of the first byte in an image - because of
/// the file header and the section alignment" (`gdbserver/win32-low.cc`, `handle_load_dll` and
/// `handle_unload_dll`: `load_addr += 0x1000`). It is a constant, not the image's first section RVA.
pub const GDBSERVER_SEGMENT_OFFSET: u64 = 0x1000;

/// One section header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeSection {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
}

/// The parts of a PE image's headers rampage uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeHeader {
    pub machine: u16,
    /// PE32+ (64-bit) rather than PE32.
    pub pe32_plus: bool,
    pub characteristics: u16,
    pub timestamp: u32,
    /// `OptionalHeader.ImageBase` as the bytes state it: the preferred base in a file, the runtime base in a moved
    /// image's mapped headers.
    #[serde(serialize_with = "hex_address")]
    pub image_base: u64,
    /// Where the `ImageBase` field lies in the header bytes, and its width, so a comparison can leave it out.
    #[serde(skip)]
    pub image_base_field: (usize, usize),
    pub entry_rva: u32,
    pub section_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub dll_characteristics: u16,
    #[serde(skip)]
    pub directories: Vec<(u32, u32)>,
    pub sections: Vec<PeSection>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

impl PeHeader {
    /// Parses the DOS header, PE signature, COFF and optional headers and the section table at the start of
    /// `bytes`. `None` when they are not a well-formed PE32 or PE32+ header within `bytes`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.get(..2)? != b"MZ" {
            return None;
        }
        let lfanew = u32_at(bytes, 0x3c)? as usize;
        if lfanew > 0x1000 || bytes.get(lfanew..lfanew + 4)? != b"PE\0\0" {
            return None;
        }
        let coff = lfanew + 4;
        let machine = u16_at(bytes, coff)?;
        let section_count = u16_at(bytes, coff + 2)? as usize;
        let timestamp = u32_at(bytes, coff + 4)?;
        let optional_size = u16_at(bytes, coff + 16)? as usize;
        let characteristics = u16_at(bytes, coff + 18)?;
        let optional = coff + 20;
        let pe32_plus = match u16_at(bytes, optional)? {
            0x10b => false,
            0x20b => true,
            _ => return None,
        };
        let (image_base, image_base_field) = if pe32_plus {
            (u64_at(bytes, optional + 24)?, (optional + 24, 8))
        } else {
            (u64::from(u32_at(bytes, optional + 28)?), (optional + 28, 4))
        };
        let (directory_count_at, directories_at) = if pe32_plus { (108, 112) } else { (92, 96) };
        let directory_count = (u32_at(bytes, optional + directory_count_at)? as usize).min(16);
        if optional_size < directories_at + 8 * directory_count {
            return None;
        }
        let directories = (0..directory_count)
            .map(|index| {
                let at = optional + directories_at + 8 * index;
                Some((u32_at(bytes, at)?, u32_at(bytes, at + 4)?))
            })
            .collect::<Option<Vec<_>>>()?;
        if section_count > MAX_SECTIONS {
            return None;
        }
        let table = optional + optional_size;
        let sections = (0..section_count)
            .map(|index| {
                let at = table + 40 * index;
                let name = bytes.get(at..at + 8)?;
                let end = name.iter().position(|byte| *byte == 0).unwrap_or(8);
                Some(PeSection {
                    name: String::from_utf8_lossy(&name[..end]).into_owned(),
                    virtual_size: u32_at(bytes, at + 8)?,
                    rva: u32_at(bytes, at + 12)?,
                    raw_size: u32_at(bytes, at + 16)?,
                    raw_offset: u32_at(bytes, at + 20)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            machine,
            pe32_plus,
            characteristics,
            timestamp,
            image_base,
            image_base_field,
            entry_rva: u32_at(bytes, optional + 16)?,
            section_alignment: u32_at(bytes, optional + 32)?,
            size_of_image: u32_at(bytes, optional + 56)?,
            size_of_headers: u32_at(bytes, optional + 60)?,
            dll_characteristics: u16_at(bytes, optional + 70)?,
            directories,
            sections,
        })
    }

    pub fn dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }

    /// A data directory's RVA and size, when present and non-empty.
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories.get(index).copied().filter(|(rva, size)| *rva != 0 && *size != 0)
    }

    /// The lowest RVA of a section with contents.
    pub fn first_section_rva(&self) -> Option<u32> {
        self.sections.iter().filter(|section| section.virtual_size.max(section.raw_size) > 0).map(|s| s.rva).min()
    }

    /// The file offset of `rva`, through the section holding it (or the headers).
    pub fn file_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }
        self.sections.iter().find_map(|section| {
            let extent = section.virtual_size.max(section.raw_size);
            let offset = rva.checked_sub(section.rva).filter(|offset| *offset < extent)?;
            (offset < section.raw_size).then(|| section.raw_offset as usize + offset as usize)
        })
    }

    /// The machine's name: `x86-64`, `x86`, `arm64`, `arm` (Thumb-2), else the hex value.
    pub fn machine_name(&self) -> String {
        match self.machine {
            0x8664 => "x86-64".into(),
            0x14c => "x86".into(),
            0xaa64 => "arm64".into(),
            0x1c4 => "arm".into(),
            other => format!("{other:#06x}"),
        }
    }
}

/// A CodeView RSDS record: the GUID and age that tie an image to its PDB, and the PDB path the linker wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeView {
    /// The GUID's 16 bytes as stored, in hex (no byte-order shuffling into the textual GUID form), as
    /// `rampage_loaders`' `CodeView` gives it.
    #[serde(serialize_with = "hex_bytes")]
    pub guid: [u8; 16],
    pub age: u32,
    pub path: String,
}

fn hex_bytes<S: serde::Serializer>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&crate::packet::encode_hex(bytes))
}

/// Parses an RSDS record (`RSDS`, GUID, age, NUL-terminated PDB path).
pub fn parse_rsds(bytes: &[u8]) -> Option<CodeView> {
    if bytes.get(..4)? != b"RSDS" {
        return None;
    }
    let guid: [u8; 16] = bytes.get(4..20)?.try_into().ok()?;
    let age = u32_at(bytes, 20)?;
    let path = bytes.get(24..).unwrap_or_default();
    let end = path.iter().position(|byte| *byte == 0).unwrap_or(path.len()).min(1024);
    Some(CodeView { guid, age, path: String::from_utf8_lossy(&path[..end]).into_owned() })
}

/// The CodeView entry of a debug directory (`IMAGE_DEBUG_DIRECTORY` entries of 28 bytes): its RVA, file offset and
/// size.
pub fn codeview_entry(directory: &[u8]) -> Option<(u32, u32, u32)> {
    (0..(directory.len() / 28).min(MAX_DEBUG_ENTRIES)).find_map(|index| {
        let at = index * 28;
        if u32_at(directory, at + 12)? != DEBUG_TYPE_CODEVIEW {
            return None;
        }
        Some((u32_at(directory, at + 20)?, u32_at(directory, at + 24)?, u32_at(directory, at + 16)?))
    })
}

/// The CodeView record of a PE file.
pub fn file_codeview(file: &[u8], header: &PeHeader) -> Option<CodeView> {
    let (rva, size) = header.directory(DIRECTORY_DEBUG)?;
    let at = header.file_offset(rva)?;
    let directory = file.get(at..at.checked_add(size as usize)?)?;
    let (_, offset, size) = codeview_entry(directory)?;
    parse_rsds(file.get(offset as usize..(offset as usize).checked_add(size.min(1024 + 24) as usize)?)?)
}

/// The spans a base relocation patches, as `(rva, length)` sorted by RVA, from the file's `.reloc` blocks.
/// `ABSOLUTE` entries are padding; `HIGHADJ` takes the next entry as its parameter. Types this reader does not know
/// patch at most 8 bytes, which it assumes, so verification skips too much rather than too little.
pub fn relocations(file: &[u8], header: &PeHeader) -> Result<Vec<(u32, u8)>, String> {
    let Some((rva, size)) = header.directory(DIRECTORY_BASERELOC) else { return Ok(Vec::new()) };
    let at = header.file_offset(rva).ok_or("the base relocation directory is not in the file")?;
    let table = file
        .get(at..at.saturating_add(size as usize))
        .ok_or("the base relocation directory runs past the end of the file")?;
    let mut spans = Vec::new();
    let mut offset = 0usize;
    while offset + 8 <= table.len() {
        let page = u32_at(table, offset).expect("in bounds");
        let block = u32_at(table, offset + 4).expect("in bounds") as usize;
        if block < 8 || offset + block > table.len() {
            return Err(format!("malformed base relocation block at directory offset {offset:#x}"));
        }
        let mut parameter = false;
        for entry in (offset + 8..offset + block).step_by(2).filter_map(|at| u16_at(table, at)) {
            // HIGHADJ's second slot is its parameter, not an entry.
            if std::mem::take(&mut parameter) {
                continue;
            }
            let (kind, page_offset) = (entry >> 12, u32::from(entry & 0xfff));
            let length = match kind {
                0 => continue,
                1 | 2 => 2,
                3 => 4,
                4 => {
                    parameter = true;
                    2
                }
                _ => 8,
            };
            if spans.len() == MAX_RELOCATIONS {
                return Err(format!("the image has more than {MAX_RELOCATIONS} base relocations"));
            }
            spans.push((page.wrapping_add(page_offset), length));
        }
        offset += block;
    }
    spans.sort_unstable();
    Ok(spans)
}

/// A module's image as rampage read it from target memory: its runtime base, how that base was derived from the
/// stub's report, and its headers' identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImage {
    /// The image's runtime base (the address of its `MZ` header).
    #[serde(serialize_with = "hex_address")]
    pub base: u64,
    /// `segment_minus_0x1000` (gdbserver's `<segment>`), `section` (lldb-server's `<section>` is the base), or
    /// `peb` (the main executable, from the process environment block).
    pub base_from: &'static str,
    pub machine: String,
    pub dll: bool,
    pub size_of_image: u32,
    pub timestamp: u32,
    /// Whether the image allows the loader to move it (`DYNAMIC_BASE`).
    pub aslr: bool,
    /// The CodeView record read from the mapped debug directory.
    pub codeview: Option<CodeView>,
}

/// A Windows exception as a stub reports it: gdbserver's `EXCEPTION_RECORD` (`qXfer:siginfo:read`) or
/// lldb-server's stop description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsException {
    pub system: &'static str,
    /// The `NTSTATUS` exception code.
    #[serde(serialize_with = "hex_u32")]
    pub code: u32,
    /// The code's name (`EXCEPTION_ACCESS_VIOLATION`...), `UNKNOWN` for a code this client does not know.
    pub name: &'static str,
    /// `siginfo` (gdbserver's exception record) or `description` (lldb-server's stop description).
    pub source: &'static str,
    #[serde(serialize_with = "optional_hex", skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u32>,
    /// Whether the exception cannot be continued (`EXCEPTION_NONCONTINUABLE` in the flags).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noncontinuable: Option<bool>,
    #[serde(serialize_with = "hex_list", skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<u64>,
    /// `EXCEPTION_ACCESS_VIOLATION` and `EXCEPTION_IN_PAGE_ERROR`: what the access was (`read`, `write`, `execute`
    /// for a DEP violation) and the address it touched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<&'static str>,
    #[serde(serialize_with = "optional_hex", skip_serializing_if = "Option::is_none")]
    pub fault_address: Option<u64>,
}

fn hex_u32<S: serde::Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{value:#010x}"))
}

fn optional_hex<S: serde::Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.collect_str(&format_args!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

fn hex_list<S: serde::Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| format!("{value:#x}")))
}

pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xc000_0005;
pub const EXCEPTION_IN_PAGE_ERROR: u32 = 0xc000_0006;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
pub const STATUS_WX86_BREAKPOINT: u32 = 0x4000_001f;
pub const STATUS_WX86_SINGLE_STEP: u32 = 0x4000_001e;
pub const DBG_CONTROL_C: u32 = 0x4001_0005;
pub const DBG_CONTROL_BREAK: u32 = 0x4001_0008;

/// The name of a Windows exception code. The codes gdbserver maps to signals (`gdb/nat/windows-nat.c`,
/// `handle_exception`) are all named, with the common others.
pub fn exception_name(code: u32) -> &'static str {
    match code {
        EXCEPTION_ACCESS_VIOLATION => "EXCEPTION_ACCESS_VIOLATION",
        EXCEPTION_IN_PAGE_ERROR => "EXCEPTION_IN_PAGE_ERROR",
        EXCEPTION_BREAKPOINT => "EXCEPTION_BREAKPOINT",
        EXCEPTION_SINGLE_STEP => "EXCEPTION_SINGLE_STEP",
        STATUS_WX86_BREAKPOINT => "STATUS_WX86_BREAKPOINT",
        STATUS_WX86_SINGLE_STEP => "STATUS_WX86_SINGLE_STEP",
        DBG_CONTROL_C => "DBG_CONTROL_C",
        DBG_CONTROL_BREAK => "DBG_CONTROL_BREAK",
        0x8000_0001 => "EXCEPTION_GUARD_PAGE",
        0x8000_0002 => "EXCEPTION_DATATYPE_MISALIGNMENT",
        0xc000_0008 => "EXCEPTION_INVALID_HANDLE",
        0xc000_001d => "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xc000_0025 => "EXCEPTION_NONCONTINUABLE_EXCEPTION",
        0xc000_0026 => "EXCEPTION_INVALID_DISPOSITION",
        0xc000_008c => "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
        0xc000_008d => "EXCEPTION_FLT_DENORMAL_OPERAND",
        0xc000_008e => "EXCEPTION_FLT_DIVIDE_BY_ZERO",
        0xc000_008f => "EXCEPTION_FLT_INEXACT_RESULT",
        0xc000_0090 => "EXCEPTION_FLT_INVALID_OPERATION",
        0xc000_0091 => "EXCEPTION_FLT_OVERFLOW",
        0xc000_0092 => "EXCEPTION_FLT_STACK_CHECK",
        0xc000_0093 => "EXCEPTION_FLT_UNDERFLOW",
        0xc000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xc000_0095 => "EXCEPTION_INT_OVERFLOW",
        0xc000_0096 => "EXCEPTION_PRIV_INSTRUCTION",
        0xc000_00fd => "EXCEPTION_STACK_OVERFLOW",
        0xc000_0374 => "STATUS_HEAP_CORRUPTION",
        0xc000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0x406d_1388 => "MS_VC_EXCEPTION",
        0xe06d_7363 => "MSVC_CPP_EXCEPTION",
        _ => "UNKNOWN",
    }
}

impl WindowsException {
    fn new(code: u32, source: &'static str) -> Self {
        Self {
            system: "windows",
            code,
            name: exception_name(code),
            source,
            address: None,
            flags: None,
            noncontinuable: None,
            parameters: Vec::new(),
            access: None,
            fault_address: None,
        }
    }

    /// Whether the exception is a breakpoint or single-step trap, which stop classification treats as a
    /// breakpoint or a step rather than a fault.
    pub fn trap(&self) -> bool {
        matches!(
            self.code,
            EXCEPTION_BREAKPOINT | EXCEPTION_SINGLE_STEP | STATUS_WX86_BREAKPOINT | STATUS_WX86_SINGLE_STEP
        )
    }

    fn with_parameters(mut self, parameters: Vec<u64>) -> Self {
        if matches!(self.code, EXCEPTION_ACCESS_VIOLATION | EXCEPTION_IN_PAGE_ERROR) && parameters.len() >= 2 {
            self.access = access_kind(parameters[0]);
            self.fault_address = Some(parameters[1]);
        }
        self.parameters = parameters;
        self
    }
}

/// `ExceptionInformation[0]` of an access violation: 0 read, 1 write, 8 a DEP violation (execute).
fn access_kind(value: u64) -> Option<&'static str> {
    match value {
        0 => Some("read"),
        1 => Some("write"),
        8 => Some("execute"),
        _ => None,
    }
}

/// Parses the `EXCEPTION_RECORD` gdbserver returns for `qXfer:siginfo:read` (`gdb/nat/windows-nat.c`,
/// `windows_thread_info::xfer_siginfo`): 152 bytes of the 64-bit layout from a 64-bit process, or the 80-byte
/// `EXCEPTION_RECORD32` from a 32-bit process (WoW64, or a 32-bit gdbserver).
pub fn parse_exception_record(bytes: &[u8]) -> Option<WindowsException> {
    let (wide, count_at, parameters_at, width) = match bytes.len() {
        152.. => (true, 24, 32, 8),
        80..=151 => (false, 16, 20, 4),
        _ => return None,
    };
    let code = u32_at(bytes, 0)?;
    let flags = u32_at(bytes, 4)?;
    let address = if wide { u64_at(bytes, 16)? } else { u64::from(u32_at(bytes, 12)?) };
    let count = (u32_at(bytes, count_at)? as usize).min(15);
    let parameters = (0..count)
        .map(|index| {
            let at = parameters_at + width * index;
            if wide { u64_at(bytes, at) } else { u32_at(bytes, at).map(u64::from) }
        })
        .collect::<Option<Vec<_>>>()?;
    let mut exception = WindowsException::new(code, "siginfo").with_parameters(parameters);
    exception.address = Some(address);
    exception.flags = Some(flags);
    exception.noncontinuable = Some(flags & 1 != 0);
    Some(exception)
}

/// Parses lldb-server's description of a Windows exception stop: `Exception 0x<code> encountered at address
/// 0x<address>`, optionally followed by `: Access violation reading location 0x<address>` and the like
/// (`NativeProcessWindows.cpp`, `HandleBreakpointException` and `HandleGenericException`;
/// `ExceptionRecord.cpp`, `Dump`).
pub fn parse_exception_description(text: &str) -> Option<WindowsException> {
    let rest = text.strip_prefix("Exception ")?;
    let (code, rest) = rest.split_once(" encountered at address ")?;
    let code = u32::from_str_radix(code.strip_prefix("0x")?, 16).ok()?;
    let (address, detail) = match rest.split_once(':') {
        Some((address, detail)) => (address, Some(detail.trim())),
        None => (rest.trim(), None),
    };
    let address = u64::from_str_radix(address.strip_prefix("0x")?, 16).ok()?;
    let mut exception = WindowsException::new(code, "description");
    exception.address = Some(address);
    if let Some(detail) = detail
        && matches!(code, EXCEPTION_ACCESS_VIOLATION | EXCEPTION_IN_PAGE_ERROR)
    {
        let access = if detail.contains("reading") {
            Some("read")
        } else if detail.contains("writing") {
            Some("write")
        } else if detail.contains("data execution prevention") {
            Some("execute")
        } else {
            None
        };
        let location = detail
            .rsplit_once(" location ")
            .or_else(|| detail.rsplit_once(" at "))
            .and_then(|(_, location)| location.split_whitespace().next())
            .and_then(|location| u64::from_str_radix(location.strip_prefix("0x")?, 16).ok());
        exception.access = access;
        exception.fault_address = location;
    }
    Some(exception)
}

/// Parses lldb-server's description of a watchpoint stop: `<watchpoint address> <index> <address hit>`, in
/// decimal (`NativeProcessWindows.cpp`, `HandleSingleStepException`; debugserver writes the same form).
pub fn parse_watch_description(text: &str) -> Option<(u64, u64)> {
    let mut fields = text.split_whitespace();
    let address = fields.next()?.parse().ok()?;
    fields.next()?.parse::<u32>().ok()?;
    let hit = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some((address, hit))
}

/// Normalizes a Windows path for comparison: the `\\?\` and `\??\` prefixes taken off, `/` read as `\`, and ASCII
/// letters lowercased (Windows file names are case-insensitive).
pub fn normalize_path(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = path.strip_prefix("\\\\?\\").or_else(|| path.strip_prefix("\\??\\")).unwrap_or(&path);
    let path = path.strip_prefix("UNC\\").map(|rest| format!("\\\\{rest}")).unwrap_or_else(|| path.to_owned());
    path.to_ascii_lowercase()
}

/// The file name of a Windows or POSIX path.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ image: headers, `.text` at RVA 0x1000 and `.reloc` at 0x2000 with one DIR64 entry, and a
    /// CodeView record in `.text`.
    pub(crate) fn image() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 70..optional + 72].copy_from_slice(&0x8160u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let directory = |index: usize| optional + 112 + 8 * index;
        bytes[directory(5)..directory(5) + 8].copy_from_slice(&[0, 0x20, 0, 0, 0x10, 0, 0, 0]);
        bytes[directory(6)..directory(6) + 8].copy_from_slice(&[0x00, 0x11, 0, 0, 28, 0, 0, 0]);
        let table = optional + 240;
        for (index, (name, rva, raw)) in
            [(b".text\0\0\0", 0x1000u32, 0x200u32), (b".reloc\0\0", 0x2000, 0x400)].into_iter().enumerate()
        {
            let at = table + 40 * index;
            bytes[at..at + 8].copy_from_slice(name);
            bytes[at + 8..at + 12].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[at + 12..at + 16].copy_from_slice(&rva.to_le_bytes());
            bytes[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[at + 20..at + 24].copy_from_slice(&raw.to_le_bytes());
        }
        // The debug directory at RVA 0x1100 (file 0x300), its RSDS record at RVA 0x1120 (file 0x320).
        let entry = 0x300;
        bytes[entry + 12..entry + 16].copy_from_slice(&2u32.to_le_bytes());
        bytes[entry + 16..entry + 20].copy_from_slice(&30u32.to_le_bytes());
        bytes[entry + 20..entry + 24].copy_from_slice(&0x1120u32.to_le_bytes());
        bytes[entry + 24..entry + 28].copy_from_slice(&0x320u32.to_le_bytes());
        bytes[0x320..0x324].copy_from_slice(b"RSDS");
        bytes[0x324..0x334].copy_from_slice(&[0x11; 16]);
        bytes[0x334..0x338].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x338..0x33e].copy_from_slice(b"a.pdb\0");
        // One relocation block for page 0x1000: DIR64 at 0x1040, HIGHLOW at 0x1050, padding.
        bytes[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x404..0x408].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x408..0x40a].copy_from_slice(&0xa040u16.to_le_bytes());
        bytes[0x40a..0x40c].copy_from_slice(&0x3050u16.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_headers_codeview_and_relocations() {
        let bytes = image();
        let header = PeHeader::parse(&bytes).unwrap();
        assert!(header.pe32_plus && !header.dll());
        assert_eq!((header.image_base, header.image_base_field), (0x1_4000_0000, (0x84 + 20 + 24, 8)));
        assert_eq!((header.first_section_rva(), header.machine_name().as_str()), (Some(0x1000), "x86-64"));
        assert_eq!(header.file_offset(0x1120), Some(0x320));
        assert_eq!(header.file_offset(0x2400), None);
        let codeview = file_codeview(&bytes, &header).unwrap();
        assert_eq!((codeview.guid, codeview.age, codeview.path.as_str()), ([0x11; 16], 3, "a.pdb"));
        assert_eq!(relocations(&bytes, &header).unwrap(), vec![(0x1040, 8), (0x1050, 4)]);
        let mut broken = bytes.clone();
        broken[0x404..0x408].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(relocations(&broken, &header).is_err());
        assert!(PeHeader::parse(&bytes[..0x100]).is_none());
        let mut rng = crate::packet::tests::Rng::new(17);
        for _ in 0..2000 {
            let mut fuzzed = bytes.clone();
            for _ in 0..8 {
                let at = rng.below(0x200);
                fuzzed[at] = rng.below(256) as u8;
            }
            if let Some(header) = PeHeader::parse(&fuzzed) {
                let _ = relocations(&fuzzed, &header);
                let _ = file_codeview(&fuzzed, &header);
            }
        }
    }

    #[test]
    fn parses_exception_records_and_descriptions() {
        let mut record = vec![0u8; 152];
        record[..4].copy_from_slice(&EXCEPTION_ACCESS_VIOLATION.to_le_bytes());
        record[16..24].copy_from_slice(&0x7ff6_1234_1010u64.to_le_bytes());
        record[24..28].copy_from_slice(&2u32.to_le_bytes());
        record[32..40].copy_from_slice(&1u64.to_le_bytes());
        record[40..48].copy_from_slice(&0x10u64.to_le_bytes());
        let exception = parse_exception_record(&record).unwrap();
        assert_eq!(
            (exception.name, exception.address, exception.access, exception.fault_address),
            ("EXCEPTION_ACCESS_VIOLATION", Some(0x7ff6_1234_1010), Some("write"), Some(0x10))
        );
        let mut record32 = vec![0u8; 80];
        record32[..4].copy_from_slice(&EXCEPTION_BREAKPOINT.to_le_bytes());
        record32[12..16].copy_from_slice(&0x0040_1000u32.to_le_bytes());
        let exception = parse_exception_record(&record32).unwrap();
        assert!(exception.trap());
        assert_eq!(exception.address, Some(0x0040_1000));
        assert!(parse_exception_record(&record32[..40]).is_none());

        let exception = parse_exception_description(
            "Exception 0xc0000005 encountered at address 0x7ff612341010: Access violation writing location 0x00000010",
        )
        .unwrap();
        assert_eq!(
            (exception.code, exception.access, exception.fault_address),
            (0xc000_0005, Some("write"), Some(0x10))
        );
        let exception =
            parse_exception_description("Exception 0x80000003 encountered at address 0x7ffa00001000").unwrap();
        assert_eq!((exception.name, exception.address), ("EXCEPTION_BREAKPOINT", Some(0x7ffa_0000_1000)));
        assert!(parse_exception_description("interrupt").is_none());
        assert_eq!(parse_watch_description("5368725504 0 5368725508"), Some((5_368_725_504, 5_368_725_508)));
        assert_eq!(parse_watch_description("1 2"), None);
    }

    #[test]
    fn normalizes_windows_paths() {
        assert_eq!(normalize_path("\\\\?\\C:\\Work\\Prog.EXE"), "c:\\work\\prog.exe");
        assert_eq!(normalize_path("C:/work/prog.exe"), "c:\\work\\prog.exe");
        assert_eq!(normalize_path("\\\\?\\UNC\\server\\share\\a.dll"), "\\\\server\\share\\a.dll");
        assert_eq!(file_name("C:\\Windows\\System32\\KERNEL32.DLL"), "KERNEL32.DLL");
    }
}
