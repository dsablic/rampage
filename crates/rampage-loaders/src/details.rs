//! Format-specific header facts that triage cares about: build metadata, linked libraries, hardening flags, and
//! data appended past the end of the image (an overlay).

use object::read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader};
use object::read::macho::{LoadCommandVariant, MachHeader};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};
use object::{LittleEndian as LE, Object, ObjectSection, ReadRef};
use serde::Serialize;

use crate::macho;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "format", rename_all = "lowercase")]
pub enum Details {
    Pe(PeDetails),
    Elf(ElfDetails),
    #[serde(rename = "macho")]
    MachO(MachODetails),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeDetails {
    /// Link time from the COFF header, seconds since 1970 (often a hash in reproducible builds).
    pub timestamp: u32,
    pub timestamp_utc: String,
    pub subsystem: &'static str,
    pub linker_version: String,
    pub checksum: u32,
    /// Mitigations from DllCharacteristics: aslr, high_entropy_va, dep, cfg, force_integrity, no_seh, ...
    pub characteristics: Vec<&'static str>,
    /// Whether the image carries an Authenticode signature (a certificate table).
    pub signed: bool,
    /// Rich header entries: the Microsoft tools that built the image.
    pub rich: Vec<RichEntry>,
    /// The import hash (pefile's algorithm over the regular import table), which groups samples built from the
    /// same imports. pefile's ordinal-to-name tables for ws2_32 and oleaut32 are not applied.
    pub imphash: Option<String>,
    /// A .NET assembly (it has a CLR runtime header); its code is IL, not native.
    pub dotnet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RichEntry {
    pub product: u16,
    pub build: u16,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfDetails {
    /// executable, shared, relocatable or core.
    pub kind: &'static str,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub pie: bool,
    /// Non-executable stack (PT_GNU_STACK without PF_X).
    pub nx: bool,
    /// none, partial (PT_GNU_RELRO) or full (also BIND_NOW).
    pub relro: &'static str,
    pub build_id: Option<String>,
    /// No `.symtab`.
    pub stripped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachODetails {
    pub file_type: &'static str,
    pub flags: Vec<&'static str>,
    pub dylibs: Vec<String>,
    pub rpaths: Vec<String>,
    pub platform: Option<String>,
    pub min_os: Option<String>,
    pub sdk: Option<String>,
    pub uuid: Option<String>,
    pub code_signature: bool,
    /// LC_ENCRYPTION_INFO with a nonzero cryptid (App Store encryption).
    pub encrypted: bool,
    /// The tools LC_BUILD_VERSION records (the linker adds itself), at most [`MAX_BUILD_TOOLS`].
    pub build_tools: Vec<BuildTool>,
}

/// More tool entries than any toolchain writes; a hostile count cannot grow the details past this.
pub const MAX_BUILD_TOOLS: usize = 16;

/// One LC_BUILD_VERSION tool entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildTool {
    /// clang, swift, ld, lld or metal; any other id as `tool <n>`.
    pub tool: String,
    pub version: String,
}

/// Bytes past the last byte the image's headers, segments and sections account for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Overlay {
    /// Offset within the image (the slice, for a universal binary).
    pub offset: u64,
    pub size: u64,
    /// Offset within the whole file.
    pub file_offset: u64,
}

pub(crate) fn collect(parsed: &object::File) -> Details {
    match parsed {
        object::File::Pe32(file) => Details::Pe(pe(file)),
        object::File::Pe64(file) => Details::Pe(pe(file)),
        object::File::Elf32(file) => Details::Elf(elf(file)),
        object::File::Elf64(file) => Details::Elf(elf(file)),
        object::File::MachO32(_) | object::File::MachO64(_) => Details::MachO(macho_details(parsed)),
        _ => Details::None,
    }
}

/// The overlay of `image`, which starts at `image_start` in the file: data following everything its structures
/// describe. Zero padding does not count, and neither does a PE certificate table at the very end of the file,
/// though any payload in front of one does. Fails, with a warning, when structures run past the end of the file.
pub(crate) fn overlay(parsed: &object::File, image: &[u8], image_start: u64) -> Result<Option<Overlay>, String> {
    let len = image.len() as u64;
    let mut ranges: Vec<(u64, u64)> =
        parsed.segments().map(|segment| object::ObjectSegment::file_range(&segment)).collect();
    ranges.extend(parsed.sections().filter_map(|section| section.file_range()));
    let mut certificate = None;
    match parsed {
        object::File::Elf32(file) => ranges.extend(elf_headers(file)),
        object::File::Elf64(file) => ranges.extend(elf_headers(file)),
        object::File::Pe32(file) => {
            ranges.extend(pe_headers(file));
            certificate = pe_certificate(file);
        }
        object::File::Pe64(file) => {
            ranges.extend(pe_headers(file));
            certificate = pe_certificate(file);
        }
        object::File::MachO32(_) | object::File::MachO64(_) => ranges.extend(macho_tables(parsed)),
        _ => {}
    }
    // An image whose structures run past the end of the file is truncated: nothing follows it. A size field that
    // claims so falsely could hide an overlay, so the loader warns about it.
    if ranges.iter().any(|&(offset, size)| offset < len && offset.saturating_add(size) > len) {
        return Err(format!("structures extend past the end of the file ({len:#x} bytes): truncated or corrupt"));
    }
    let end =
        ranges.into_iter().filter(|&(offset, _)| offset < len).map(|(offset, size)| offset + size).max().unwrap_or(0);
    // A certificate table that ends the file belongs to the image; whatever lies before it does not.
    let stop = match certificate {
        Some((offset, size)) if offset >= end && offset.checked_add(size) == Some(len) => offset,
        _ => len,
    };
    // Both lie within the image, which is in memory.
    let tail = &image[end as usize..stop as usize];
    Ok(tail.iter().any(|&byte| byte != 0).then(|| Overlay {
        offset: end,
        size: stop - end,
        file_offset: image_start + end,
    }))
}

/// File ranges of a Mach-O's header and load commands, link-edit data, and section relocations (which follow the
/// segments in object files).
fn macho_tables(parsed: &object::File) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    if let Some(header) = macho_header(parsed) {
        ranges.push((0, header.end));
    }
    let Some((mut commands, endian)) = macho::load_commands(parsed) else { return ranges };
    let symbol_size: u64 = if parsed.is_64() { 16 } else { 12 };
    let mut add = |offset: u32, count: u32, size: u64| ranges.push((u64::from(offset), u64::from(count) * size));
    while let Ok(Some(command)) = commands.next() {
        match command.variant() {
            Ok(LoadCommandVariant::Symtab(symtab)) => {
                add(symtab.symoff.get(endian), symtab.nsyms.get(endian), symbol_size);
                add(symtab.stroff.get(endian), symtab.strsize.get(endian), 1);
            }
            Ok(LoadCommandVariant::Dysymtab(dysymtab)) => {
                add(dysymtab.indirectsymoff.get(endian), dysymtab.nindirectsyms.get(endian), 4);
                add(dysymtab.extreloff.get(endian), dysymtab.nextrel.get(endian), 8);
                add(dysymtab.locreloff.get(endian), dysymtab.nlocrel.get(endian), 8);
            }
            Ok(LoadCommandVariant::DyldInfo(info)) => {
                add(info.rebase_off.get(endian), info.rebase_size.get(endian), 1);
                add(info.bind_off.get(endian), info.bind_size.get(endian), 1);
                add(info.weak_bind_off.get(endian), info.weak_bind_size.get(endian), 1);
                add(info.lazy_bind_off.get(endian), info.lazy_bind_size.get(endian), 1);
                add(info.export_off.get(endian), info.export_size.get(endian), 1);
            }
            Ok(LoadCommandVariant::LinkeditData(linkedit)) => {
                add(linkedit.dataoff.get(endian), linkedit.datasize.get(endian), 1);
            }
            Ok(LoadCommandVariant::Segment64(segment, data)) => {
                for section in object::read::macho::Segment::sections(segment, endian, data).unwrap_or_default() {
                    add(section.reloff.get(endian), section.nreloc.get(endian), 8);
                }
            }
            Ok(LoadCommandVariant::Segment32(segment, data)) => {
                for section in object::read::macho::Segment::sections(segment, endian, data).unwrap_or_default() {
                    add(section.reloff.get(endian), section.nreloc.get(endian), 8);
                }
            }
            _ => {}
        }
    }
    ranges
}

struct MachoHeader {
    file_type: u32,
    flags: u32,
    /// The file offset just past the load commands.
    end: u64,
}

fn macho_header(parsed: &object::File) -> Option<MachoHeader> {
    fn read<Mach: MachHeader<Endian = object::Endianness>>(header: &Mach, endian: object::Endianness) -> MachoHeader {
        let size = std::mem::size_of::<Mach>() as u64;
        MachoHeader {
            file_type: header.filetype(endian).0,
            flags: header.flags(endian).0,
            end: size + u64::from(header.sizeofcmds(endian)),
        }
    }
    match parsed {
        object::File::MachO32(file) => Some(read(file.macho_header(), file.endian())),
        object::File::MachO64(file) => Some(read(file.macho_header(), file.endian())),
        _ => None,
    }
}

/// File ranges of the ELF header, the program header table and the section header table.
fn elf_headers<'data, Elf: FileHeader, R: ReadRef<'data>>(file: &ElfFile<'data, Elf, R>) -> [(u64, u64); 3] {
    let header = file.elf_header();
    let endian = file.endian();
    let table = |offset: u64, count: u16, size: u16| (offset, u64::from(count) * u64::from(size));
    [
        (0, header.e_ehsize(endian).into()),
        table(header.e_phoff(endian).into(), header.e_phnum(endian), header.e_phentsize(endian)),
        table(header.e_shoff(endian).into(), header.e_shnum(endian), header.e_shentsize(endian)),
    ]
}

/// File ranges of the PE headers (`SizeOfHeaders`) and of the sections' raw data.
fn pe_headers<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(file: &PeFile<'data, Pe, R>) -> [(u64, u64); 2] {
    [(0, file.nt_headers().optional_header().size_of_headers().into()), (0, pe_raw_data_end(file))]
}

/// The end of the sections' raw data including its file-alignment padding (`SizeOfRawData`).
fn pe_raw_data_end<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(file: &PeFile<'data, Pe, R>) -> u64 {
    file.section_table()
        .iter()
        .map(|section| {
            u64::from(section.pointer_to_raw_data.get(LE)).saturating_add(section.size_of_raw_data.get(LE).into())
        })
        .max()
        .unwrap_or(0)
}

/// The certificate table's file range (the security directory holds a file offset, not an RVA).
fn pe_certificate<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(file: &PeFile<'data, Pe, R>) -> Option<(u64, u64)> {
    let directory = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let size = u64::from(directory.size.get(LE));
    (size != 0).then(|| (u64::from(directory.virtual_address.get(LE)), size))
}

fn pe<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(file: &PeFile<'data, Pe, R>) -> PeDetails {
    let headers = file.nt_headers();
    let optional = headers.optional_header();
    let timestamp = headers.file_header().time_date_stamp.get(LE);
    const MITIGATIONS: [(u16, &str); 11] = [
        (0x0020, "high_entropy_va"),
        (0x0040, "aslr"),
        (0x0080, "force_integrity"),
        (0x0100, "dep"),
        (0x0200, "no_isolation"),
        (0x0400, "no_seh"),
        (0x0800, "no_bind"),
        (0x1000, "appcontainer"),
        (0x2000, "wdm_driver"),
        (0x4000, "cfg"),
        (0x8000, "terminal_server_aware"),
    ];
    let flags = optional.dll_characteristics().0;
    let subsystem = match optional.subsystem().0 {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        8 => "native_windows",
        5 => "os2_cui",
        7 => "posix_cui",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    };
    let rich = file
        .rich_header_info()
        .map(|info| {
            info.unmasked_entries()
                .map(|entry| RichEntry {
                    product: (entry.comp_id >> 16) as u16,
                    build: entry.comp_id as u16,
                    count: entry.count,
                })
                .collect()
        })
        .unwrap_or_default();
    let dotnet = file
        .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .is_some_and(|directory| directory.virtual_address.get(LE) != 0);
    PeDetails {
        imphash: imphash(file),
        dotnet,
        timestamp,
        timestamp_utc: utc(timestamp.into()),
        subsystem,
        linker_version: format!("{}.{}", optional.major_linker_version(), optional.minor_linker_version()),
        checksum: optional.check_sum(),
        characteristics: MITIGATIONS.iter().filter(|(bit, _)| flags & bit != 0).map(|&(_, name)| name).collect(),
        signed: pe_certificate(file).is_some(),
        rich,
    }
}

/// pefile's `get_imphash`: MD5 of `library.function` for each regular (not delay-load) import, lowercased, with
/// the library's .dll/.ocx/.sys extension removed and ordinals written `ord<n>`, joined by commas.
fn imphash<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(file: &PeFile<'data, Pe, R>) -> Option<String> {
    use md5::{Digest, Md5};
    let mut entries = Vec::new();
    crate::slots::pe_imports(file, |library, _, import| {
        let library = String::from_utf8_lossy(library.unwrap_or_default()).to_lowercase();
        let library = match library.rsplit_once('.') {
            Some((stem, "dll" | "ocx" | "sys")) => stem.to_owned(),
            _ => library,
        };
        let function = match import {
            object::read::pe::Import::Name(_, name) => String::from_utf8_lossy(name).to_lowercase(),
            object::read::pe::Import::Ordinal(ordinal) => format!("ord{ordinal}"),
        };
        entries.push(format!("{library}.{function}"));
    })
    .ok()?;
    (!entries.is_empty()).then(|| rampage_arch::hex::bytes(&Md5::digest(entries.join(",").as_bytes())))
}

/// `YYYY-MM-DD HH:MM:SS` for seconds since 1970 (Howard Hinnant's civil-from-days).
fn utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", time / 3600, time / 60 % 60, time % 60)
}

const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const DT_NEEDED: u64 = 1;
pub(crate) const DT_PLTGOT: u64 = 3;
pub(crate) const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
pub(crate) const DT_MIPS_GOTSYM: u64 = 0x7000_0013;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

fn elf<'data, Elf: FileHeader, R: ReadRef<'data>>(file: &ElfFile<'data, Elf, R>) -> ElfDetails {
    let endian = file.endian();
    let headers = file.elf_program_headers();
    let interpreter = headers
        .iter()
        .find_map(|header| header.interpreter(endian, file.data()).ok().flatten())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    let stack = headers.iter().find(|header| header.p_type(endian).0 == PT_GNU_STACK);
    let nx = stack.is_some_and(|header| header.p_flags(endian).0 & object::elf::PF_X.0 == 0);
    let has_relro = headers.iter().any(|header| header.p_type(endian).0 == PT_GNU_RELRO);

    let (entries, strings) = dynamic(file);
    let string = |offset: u64| {
        let start = usize::try_from(offset).ok()?;
        let tail = strings.get(start..)?;
        let end = tail.iter().position(|&byte| byte == 0)?;
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    };
    let value_of = |tag| entries.iter().filter(move |(t, _)| *t == tag).map(|(_, value)| *value);
    let bind_now = value_of(DT_BIND_NOW).next().is_some()
        || value_of(DT_FLAGS).any(|flags| flags & DF_BIND_NOW != 0)
        || value_of(DT_FLAGS_1).any(|flags| flags & DF_1_NOW != 0);
    let pie_flag = value_of(DT_FLAGS_1).any(|flags| flags & DF_1_PIE != 0);

    let kind = match file.elf_header().e_type(endian) {
        object::elf::ET_REL => "relocatable",
        object::elf::ET_EXEC => "executable",
        object::elf::ET_DYN => "shared",
        object::elf::ET_CORE => "core",
        _ => "unknown",
    };
    ElfDetails {
        kind,
        pie: kind == "shared" && (interpreter.is_some() || pie_flag),
        interpreter,
        needed: value_of(DT_NEEDED).filter_map(string).collect(),
        soname: value_of(DT_SONAME).find_map(string),
        nx,
        relro: match (has_relro, bind_now) {
            (false, _) => "none",
            (true, false) => "partial",
            (true, true) => "full",
        },
        build_id: file.build_id().ok().flatten().map(rampage_arch::hex::bytes),
        stripped: file.section_by_name(".symtab").is_none(),
    }
}

/// The `(d_tag, d_val)` pairs of the PT_DYNAMIC segment, and the dynamic string table DT_STRTAB names. Both are
/// found through the program headers, which loaders use, so they survive stripped section headers.
pub(crate) fn dynamic<'data, Elf: FileHeader, R: ReadRef<'data>>(
    file: &ElfFile<'data, Elf, R>,
) -> (Vec<(u64, u64)>, &'data [u8]) {
    let endian = file.endian();
    let headers = file.elf_program_headers();
    let data = file.data();
    let bytes = |offset: u64, size: u64| data.read_bytes_at(offset, size).ok();
    let entries: Vec<(u64, u64)> = headers
        .iter()
        .find_map(|header| header.dynamic(endian, data).ok().flatten())
        .unwrap_or_default()
        .iter()
        .map(|entry| (entry.d_tag(endian).0 as u64, entry.d_val(endian).into()))
        .take_while(|&(tag, _)| tag != 0)
        .collect();
    let value = |tag| entries.iter().find(|(t, _)| *t == tag).map(|(_, value)| *value);
    // DT_STRTAB holds an address: map it to a file offset through the PT_LOAD segment containing it.
    let strings = value(DT_STRTAB).zip(value(DT_STRSZ)).and_then(|(address, len)| {
        let load = headers.iter().find(|header| {
            let start: u64 = header.p_vaddr(endian).into();
            let file_size: u64 = header.p_filesz(endian).into();
            header.p_type(endian) == object::elf::PT_LOAD && address >= start && address - start < file_size
        })?;
        let start: u64 = load.p_vaddr(endian).into();
        let offset: u64 = load.p_offset(endian).into();
        let offset = offset.checked_add(address - start)?;
        bytes(offset, len)
    });
    (entries, strings.unwrap_or_default())
}

fn macho_details(parsed: &object::File) -> MachODetails {
    let (file_type, flags) = macho_header(parsed).map_or((0, 0), |header| (header.file_type, header.flags));
    const FLAGS: [(u32, &str); 12] = [
        (0x1, "noundefs"),
        (0x4, "dyldlink"),
        (0x80, "twolevel"),
        (0x8000, "weak_defines"),
        (0x10000, "binds_to_weak"),
        (0x20000, "allow_stack_execution"),
        (0x40000, "root_safe"),
        (0x80000, "setuid_safe"),
        (0x200000, "pie"),
        (0x800000, "has_tlv_descriptors"),
        (0x1000000, "no_heap_execution"),
        (0x2000000, "app_extension_safe"),
    ];
    let file_type = match file_type {
        1 => "object",
        2 => "execute",
        4 => "core",
        6 => "dylib",
        7 => "dylinker",
        8 => "bundle",
        10 => "dsym",
        11 => "kext_bundle",
        12 => "fileset",
        _ => "other",
    };
    let mut details = MachODetails {
        file_type,
        flags: FLAGS.iter().filter(|(bit, _)| flags & bit != 0).map(|&(_, name)| name).collect(),
        dylibs: macho::dylibs(parsed).into_iter().flatten().collect(),
        rpaths: Vec::new(),
        platform: None,
        min_os: None,
        sdk: None,
        uuid: parsed.mach_uuid().ok().flatten().map(|uuid| rampage_arch::hex::bytes(&uuid)),
        code_signature: false,
        encrypted: false,
        build_tools: Vec::new(),
    };
    let Some((mut commands, endian)) = macho::load_commands(parsed) else { return details };
    while let Ok(Some(command)) = commands.next() {
        let string = |name| command.string(endian, name).ok().map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        match command.variant() {
            Ok(LoadCommandVariant::Rpath(rpath)) => details.rpaths.extend(string(rpath.path)),
            Ok(LoadCommandVariant::BuildVersion(build, data)) => {
                details.platform = Some(platform(build.platform.get(endian).0));
                details.min_os = Some(version(build.minos.get(endian).0));
                details.sdk = Some(version(build.sdk.get(endian).0));
                // A count past the command's own bytes is refused whole rather than read beyond it.
                let tools = build.tools(endian, data).unwrap_or_default();
                details.build_tools = tools
                    .iter()
                    .take(MAX_BUILD_TOOLS)
                    .map(|entry| BuildTool {
                        tool: build_tool(entry.tool.get(endian).0),
                        version: version(entry.version.get(endian).0),
                    })
                    .collect();
            }
            Ok(LoadCommandVariant::VersionMin(minimum)) if details.min_os.is_none() => {
                details.platform = Some(
                    match command.cmd() {
                        object::macho::LC_VERSION_MIN_IPHONEOS => "ios",
                        object::macho::LC_VERSION_MIN_TVOS => "tvos",
                        object::macho::LC_VERSION_MIN_WATCHOS => "watchos",
                        _ => "macos",
                    }
                    .to_owned(),
                );
                details.min_os = Some(version(minimum.version.get(endian).0));
                details.sdk = Some(version(minimum.sdk.get(endian).0));
            }
            Ok(LoadCommandVariant::EncryptionInfo32(info)) => details.encrypted |= info.cryptid.get(endian) != 0,
            Ok(LoadCommandVariant::EncryptionInfo64(info)) => details.encrypted |= info.cryptid.get(endian) != 0,
            _ if command.cmd() == object::macho::LC_CODE_SIGNATURE => details.code_signature = true,
            _ => {}
        }
    }
    details
}

/// `TOOL_*` from `<mach-o/loader.h>`; 4 (lld) is newer than the `object` crate's constants.
fn build_tool(value: u32) -> String {
    match value {
        1 => "clang".to_owned(),
        2 => "swift".to_owned(),
        3 => "ld".to_owned(),
        4 => "lld".to_owned(),
        1024 => "metal".to_owned(),
        other => format!("tool {other}"),
    }
}

fn platform(value: u32) -> String {
    let name = match value {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "maccatalyst",
        7 => "ios_simulator",
        8 => "tvos_simulator",
        9 => "watchos_simulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionos_simulator",
        _ => return format!("platform {value}"),
    };
    name.to_owned()
}

/// Mach-O versions pack major.minor.patch as xxxx.yy.zz.
fn version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_utc_times() {
        assert_eq!(super::utc(0), "1970-01-01 00:00:00");
        assert_eq!(super::utc(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00:00");
    }
}
