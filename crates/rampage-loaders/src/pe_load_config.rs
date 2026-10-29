//! IMAGE_LOAD_CONFIG_DIRECTORY (32- and 64-bit): the security cookie, SafeSEH, Control Flow Guard and its
//! long-jump/EH-continuation tables, and the dynamic value relocation table. The structure's own Size decides which
//! fields exist; a field past it is reported absent, never read. Also reads CET compatibility from the
//! IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS debug entry and cross-checks the load config against the
//! DllCharacteristics mitigations triage reports.

use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile, SectionTable};
use serde::Serialize;

use crate::warnings::CappedWarnings;
use crate::{Binary, Format, LoadError};

/// SafeSEH handler RVAs listed; the count is always reported.
pub const MAX_SAFESEH_HANDLERS: usize = 256;
/// Debug directory entries examined for the extended DllCharacteristics.
pub const MAX_DEBUG_ENTRIES: usize = 64;
const WARNINGS: CappedWarnings = CappedWarnings::new(32, "load config");
const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;
const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x100;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x400;
const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xf000_0000;
const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: u32 = 0x01;

/// The load config, CET and mitigation evidence of one PE image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeLoadConfig {
    pub bits: u8,
    /// DllCharacteristics names, the same list triage reports as the PE's characteristics.
    pub dll_characteristics: Vec<&'static str>,
    /// `None` when the image has no load config directory.
    pub load_config: Option<LoadConfig>,
    /// From the IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS debug entry; `None` when there is none.
    pub cet: Option<ExtendedDllCharacteristics>,
    /// Where the load config and DllCharacteristics disagree, or a mitigation is incomplete.
    pub findings: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadConfig {
    pub rva: u32,
    /// The data directory's size, which Windows ignores in favour of `declared_size`.
    pub directory_size: u32,
    /// The structure's own Size field; `None` when even that is unreadable.
    pub declared_size: Option<u32>,
    /// Bytes of the structure actually read: the declared size, or less where the file ends first.
    pub read_size: u32,
    pub time_date_stamp: Option<u32>,
    /// `major.minor`.
    pub version: Option<String>,
    /// VA of the /GS security cookie.
    pub security_cookie: Option<u64>,
    /// 32-bit images only.
    pub safe_seh: Option<SafeSeh>,
    pub guard: Option<ControlFlowGuard>,
    pub address_taken_iat: Option<GuardTable>,
    pub long_jump_targets: Option<GuardTable>,
    pub eh_continuations: Option<GuardTable>,
    pub dynamic_value_relocations: Option<DynamicValueRelocations>,
    /// Reported fields lying past `declared_size`, so absent rather than zero.
    pub absent_fields: Vec<&'static str>,
}

/// A table of RVAs a load config field points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GuardTable {
    pub va: u64,
    pub count: u64,
    /// Bytes per entry: 4 RVA bytes plus the metadata bytes GuardFlags declares (4 for SafeSEH).
    pub entry_size: u32,
    /// Whether the whole table lies in a section and within SizeOfImage. False for a null table.
    pub in_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SafeSeh {
    pub table: GuardTable,
    /// The registered handler RVAs, at most [`MAX_SAFESEH_HANDLERS`], when the table is in the file.
    pub handlers: Vec<u32>,
    pub handlers_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlFlowGuard {
    pub flags: u32,
    /// IMAGE_GUARD_* names, lowercased without the prefix.
    pub flag_names: Vec<&'static str>,
    /// VA of the pointer the compiler calls through to check an indirect call target.
    pub check_function_pointer: Option<u64>,
    /// VA of the dispatch pointer (x64).
    pub dispatch_function_pointer: Option<u64>,
    pub function_table: Option<GuardTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DynamicValueRelocations {
    /// VA of the table (older linkers); zero when unused.
    pub table_va: Option<u64>,
    /// Offset of the table in `table_section` (newer linkers).
    pub table_offset: Option<u32>,
    /// One-based section index; zero when unused.
    pub table_section: Option<u16>,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendedDllCharacteristics {
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub cet_compatible: bool,
}

/// Field offsets, which differ between the 32- and 64-bit structures.
struct Layout {
    word: usize,
    security_cookie: usize,
    se_handler_table: usize,
    se_handler_count: usize,
    guard_cf_check: usize,
    guard_cf_dispatch: usize,
    guard_cf_table: usize,
    guard_cf_count: usize,
    guard_flags: usize,
    iat_table: usize,
    iat_count: usize,
    long_jump_table: usize,
    long_jump_count: usize,
    dynamic_value_reloc_table: usize,
    dynamic_value_reloc_offset: usize,
    dynamic_value_reloc_section: usize,
    eh_table: usize,
    eh_count: usize,
}

const LAYOUT_32: Layout = Layout {
    word: 4,
    security_cookie: 60,
    se_handler_table: 64,
    se_handler_count: 68,
    guard_cf_check: 72,
    guard_cf_dispatch: 76,
    guard_cf_table: 80,
    guard_cf_count: 84,
    guard_flags: 88,
    iat_table: 104,
    iat_count: 108,
    long_jump_table: 112,
    long_jump_count: 116,
    dynamic_value_reloc_table: 120,
    dynamic_value_reloc_offset: 136,
    dynamic_value_reloc_section: 140,
    eh_table: 164,
    eh_count: 168,
};

const LAYOUT_64: Layout = Layout {
    word: 8,
    security_cookie: 88,
    se_handler_table: 96,
    se_handler_count: 104,
    guard_cf_check: 112,
    guard_cf_dispatch: 120,
    guard_cf_table: 128,
    guard_cf_count: 136,
    guard_flags: 144,
    iat_table: 160,
    iat_count: 168,
    long_jump_table: 176,
    long_jump_count: 184,
    dynamic_value_reloc_table: 192,
    dynamic_value_reloc_offset: 224,
    dynamic_value_reloc_section: 228,
    eh_table: 264,
    eh_count: 272,
};

const GUARD_FLAGS: [(u32, &str); 17] = [
    (0x0000_0100, "cf_instrumented"),
    (0x0000_0200, "cfw_instrumented"),
    (0x0000_0400, "cf_function_table_present"),
    (0x0000_0800, "security_cookie_unused"),
    (0x0000_1000, "protect_delayload_iat"),
    (0x0000_2000, "delayload_iat_in_its_own_section"),
    (0x0000_4000, "cf_export_suppression_info_present"),
    (0x0000_8000, "cf_enable_export_suppression"),
    (0x0001_0000, "cf_longjump_table_present"),
    (0x0002_0000, "rf_instrumented"),
    (0x0004_0000, "rf_enable"),
    (0x0008_0000, "rf_strict"),
    (0x0010_0000, "retpoline_present"),
    (0x0040_0000, "eh_continuation_table_present"),
    (0x0080_0000, "xfg_enabled"),
    (0x0100_0000, "castguard_present"),
    (0x0200_0000, "memcpy_present"),
];

const EX_DLL_CHARACTERISTICS: [(u32, &str); 6] = [
    (0x01, "cet_compat"),
    (0x02, "cet_compat_strict_mode"),
    (0x04, "cet_set_context_ip_validation_relaxed_mode"),
    (0x08, "cet_dynamic_apis_allow_in_proc"),
    (0x40, "forward_cfi_compat"),
    (0x80, "hotpatch_compatible"),
];

fn names<const N: usize>(table: &[(u32, &'static str); N], flags: u32) -> Vec<&'static str> {
    table.iter().filter(|(bit, _)| flags & bit != 0).map(|&(_, name)| name).collect()
}

/// The load config evidence of a loaded image, or `None` when it is not a PE.
pub fn load_config(binary: &Binary) -> Result<Option<PeLoadConfig>, LoadError> {
    if binary.format != Format::Pe {
        return Ok(None);
    }
    parse_load_config(binary.image_bytes())
}

/// [`load_config`] for raw PE file bytes.
pub fn parse_load_config(image: &[u8]) -> Result<Option<PeLoadConfig>, LoadError> {
    match object::FileKind::parse(image) {
        Ok(object::FileKind::Pe32) => read::<object::pe::ImageNtHeaders32>(image, 32, &LAYOUT_32).map(Some),
        Ok(object::FileKind::Pe64) => read::<object::pe::ImageNtHeaders64>(image, 64, &LAYOUT_64).map(Some),
        _ => Ok(None),
    }
}

/// Maps VAs to the image for table placement checks.
struct Image<'data> {
    bytes: &'data [u8],
    sections: SectionTable<'data>,
    image_base: u64,
    size_of_image: u32,
}

impl<'data> Image<'data> {
    fn table(&self, va: u64, count: u64, entry_size: u32) -> GuardTable {
        let in_image = va != 0
            && va.checked_sub(self.image_base).and_then(|rva| u32::try_from(rva).ok()).is_some_and(|rva| {
                let end = count.checked_mul(entry_size.into()).and_then(|size| size.checked_add(rva.into()));
                end.is_some_and(|end| end <= u64::from(self.size_of_image))
                    && self.sections.section_containing(rva).is_some()
            });
        GuardTable { va, count, entry_size, in_image }
    }

    fn data_at_va(&self, va: u64) -> Option<&'data [u8]> {
        let rva = u32::try_from(va.checked_sub(self.image_base)?).ok()?;
        self.sections.pe_data_at(self.bytes, rva)
    }
}

fn read<Pe: ImageNtHeaders>(bytes: &[u8], bits: u8, layout: &Layout) -> Result<PeLoadConfig, LoadError> {
    let file = PeFile::<Pe>::parse(bytes)?;
    let optional = file.nt_headers().optional_header();
    let image = Image {
        bytes,
        sections: file.section_table(),
        image_base: optional.image_base(),
        size_of_image: optional.size_of_image(),
    };
    let mut report = PeLoadConfig {
        bits,
        dll_characteristics: crate::details::pe_mitigations(optional.dll_characteristics().0),
        load_config: None,
        cet: None,
        findings: Vec::new(),
        warnings: Vec::new(),
    };
    if let Some(directory) = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        let (rva, size) = directory.address_range();
        if rva != 0 {
            report.load_config = Some(directory_fields(&image, rva, size, layout, &mut report.warnings));
        }
    }
    report.cet = extended_characteristics(&file, &image, &mut report.warnings);
    report.findings = cross_check(&report);
    Ok(report)
}

fn directory_fields(
    image: &Image,
    rva: u32,
    directory_size: u32,
    layout: &Layout,
    warnings: &mut Vec<String>,
) -> LoadConfig {
    let mapped = image.sections.pe_data_at(image.bytes, rva).unwrap_or_default();
    if mapped.is_empty() {
        WARNINGS.push(warnings, format!("load config at RVA {rva:#x} is not in the file"));
    }
    let declared_size = mapped.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let declared = declared_size.map_or(0, |size| size as usize);
    if let Some(size) = declared_size
        && size != directory_size
    {
        WARNINGS
            .push(warnings, format!("load config declares {size} bytes but its data directory says {directory_size}"));
    }
    let read_size = declared.min(mapped.len());
    if read_size < declared {
        WARNINGS
            .push(warnings, format!("load config declares {declared} bytes but only {} are in the file", mapped.len()));
    }
    let structure = &mapped[..read_size];
    let mut absent = Vec::new();
    let mut field = |name: &'static str, offset: usize, width: usize| -> Option<u64> {
        // Without a readable Size nothing is known to be absent; every field is just unread.
        declared_size?;
        if offset + width > declared {
            absent.push(name);
            return None;
        }
        let bytes = structure.get(offset..offset + width)?;
        Some(bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)))
    };
    let word = layout.word;
    let time_date_stamp = field("time_date_stamp", 4, 4).map(|value| value as u32);
    let version = field("major_version", 8, 2)
        .zip(field("minor_version", 10, 2))
        .map(|(major, minor)| format!("{major}.{minor}"));
    let security_cookie = field("security_cookie", layout.security_cookie, word);
    let se_handlers = field("se_handler_table", layout.se_handler_table, word).zip(field(
        "se_handler_count",
        layout.se_handler_count,
        word,
    ));
    let guard_check = field("guard_cf_check_function_pointer", layout.guard_cf_check, word);
    let guard_dispatch = field("guard_cf_dispatch_function_pointer", layout.guard_cf_dispatch, word);
    let guard_table = field("guard_cf_function_table", layout.guard_cf_table, word).zip(field(
        "guard_cf_function_count",
        layout.guard_cf_count,
        word,
    ));
    let guard_flags = field("guard_flags", layout.guard_flags, 4).map(|value| value as u32);
    let iat = field("guard_address_taken_iat_entry_table", layout.iat_table, word).zip(field(
        "guard_address_taken_iat_entry_count",
        layout.iat_count,
        word,
    ));
    let long_jump = field("guard_long_jump_target_table", layout.long_jump_table, word).zip(field(
        "guard_long_jump_target_count",
        layout.long_jump_count,
        word,
    ));
    let dynamic_table = field("dynamic_value_reloc_table", layout.dynamic_value_reloc_table, word);
    let dynamic_offset = field("dynamic_value_reloc_table_offset", layout.dynamic_value_reloc_offset, 4);
    let dynamic_section = field("dynamic_value_reloc_table_section", layout.dynamic_value_reloc_section, 2);
    let eh = field("guard_eh_continuation_table", layout.eh_table, word).zip(field(
        "guard_eh_continuation_count",
        layout.eh_count,
        word,
    ));
    // The guard tables carry the metadata bytes GuardFlags declares after each RVA.
    let stride = 4 + (guard_flags.unwrap_or(0) & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK).checked_shr(28).unwrap_or(0);
    let table = |pair: Option<(u64, u64)>| pair.map(|(va, count)| image.table(va, count, stride));
    let safe_seh = (word == 4).then_some(se_handlers).flatten().map(|(va, count)| {
        let table = image.table(va, count, 4);
        let wanted = usize::try_from(count).unwrap_or(usize::MAX).min(MAX_SAFESEH_HANDLERS);
        let handlers: Vec<u32> = if table.in_image {
            image
                .data_at_va(va)
                .unwrap_or_default()
                .as_chunks::<4>()
                .0
                .iter()
                .take(wanted)
                .map(|bytes| u32::from_le_bytes(*bytes))
                .collect()
        } else {
            Vec::new()
        };
        SafeSeh { handlers_truncated: (handlers.len() as u64) < count, table, handlers }
    });
    let dynamic_value_relocations = (dynamic_table.is_some() || dynamic_offset.is_some()).then(|| {
        let table_section = dynamic_section.map(|value| value as u16);
        DynamicValueRelocations {
            table_va: dynamic_table,
            table_offset: dynamic_offset.map(|value| value as u32),
            table_section,
            present: dynamic_table.is_some_and(|va| va != 0) || table_section.is_some_and(|section| section != 0),
        }
    });
    LoadConfig {
        rva,
        directory_size,
        declared_size,
        read_size: read_size as u32,
        time_date_stamp,
        version,
        security_cookie,
        safe_seh,
        guard: guard_flags.map(|flags| ControlFlowGuard {
            flags,
            flag_names: names(&GUARD_FLAGS, flags),
            check_function_pointer: guard_check,
            dispatch_function_pointer: guard_dispatch,
            function_table: table(guard_table),
        }),
        address_taken_iat: table(iat),
        long_jump_targets: table(long_jump),
        eh_continuations: table(eh),
        dynamic_value_relocations,
        absent_fields: absent,
    }
}

/// The extended DllCharacteristics from the first IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS debug entry.
fn extended_characteristics<Pe: ImageNtHeaders>(
    file: &PeFile<Pe>,
    image: &Image,
    warnings: &mut Vec<String>,
) -> Option<ExtendedDllCharacteristics> {
    let directory = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DEBUG)?;
    let (rva, size) = directory.address_range();
    if rva == 0 || size == 0 {
        return None;
    }
    let Some(data) = image.sections.pe_data_at(image.bytes, rva) else {
        WARNINGS.push(warnings, format!("debug directory at RVA {rva:#x} is not in the file"));
        return None;
    };
    let entry_size = std::mem::size_of::<object::pe::ImageDebugDirectory>();
    let data = &data[..data.len().min(size as usize)];
    for entry in data.chunks_exact(entry_size).take(MAX_DEBUG_ENTRIES) {
        let at = |offset: usize| {
            u32::from_le_bytes([entry[offset], entry[offset + 1], entry[offset + 2], entry[offset + 3]])
        };
        if at(12) != IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS {
            continue;
        }
        let (length, pointer) = (at(16), at(24) as usize);
        let flags = image.bytes.get(pointer..pointer.saturating_add(4)).filter(|_| length >= 4);
        let Some(flags) = flags.map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) else {
            WARNINGS.push(warnings, "the extended DllCharacteristics debug entry is unreadable".to_owned());
            return None;
        };
        return Some(ExtendedDllCharacteristics {
            flags,
            flag_names: names(&EX_DLL_CHARACTERISTICS, flags),
            cet_compatible: flags & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT != 0,
        });
    }
    None
}

/// Disagreements between the load config and the DllCharacteristics triage reports.
fn cross_check(report: &PeLoadConfig) -> Vec<String> {
    let mut findings = Vec::new();
    let declares = |name: &str| report.dll_characteristics.contains(&name);
    let config = report.load_config.as_ref();
    let guard = config.and_then(|config| config.guard.as_ref());
    let instrumented = guard.is_some_and(|guard| guard.flags & IMAGE_GUARD_CF_INSTRUMENTED != 0);
    match (declares("cfg"), instrumented) {
        (true, false) => findings.push(
            "DllCharacteristics declares cfg (GUARD_CF) but the load config has no CF_INSTRUMENTED guard flags"
                .to_owned(),
        ),
        (false, true) => findings.push(
            "the load config is CF_INSTRUMENTED but DllCharacteristics lacks cfg (GUARD_CF), so the loader does \
             not enforce CFG"
                .to_owned(),
        ),
        _ => {}
    }
    if let Some(guard) = guard
        && guard.flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0
        && !guard.function_table.is_some_and(|table| table.in_image)
    {
        findings.push("GuardFlags declare a CF function table that is absent or outside the image".to_owned());
    }
    if report.bits == 32 {
        let handlers = config.and_then(|config| config.safe_seh.as_ref()).map_or(0, |seh| seh.table.count);
        match (declares("no_seh"), handlers) {
            (false, 0) => findings.push(
                "32-bit image without no_seh or a SafeSEH handler table: exception handlers are not validated"
                    .to_owned(),
            ),
            (true, count) if count > 0 => findings
                .push(format!("DllCharacteristics declares no_seh yet the load config lists {count} SafeSEH handlers")),
            _ => {}
        }
    }
    findings
}

#[cfg(test)]
mod tests;
