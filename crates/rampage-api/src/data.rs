use std::collections::BTreeSet;

use rampage_arch::Arch;
use rampage_loaders::{Binary, Details, Format, Perms, SectionKind, Segment, SymbolKind};
use serde::Serialize;

use crate::{ApiError, Project};

pub const MAX_DATA_BYTES: usize = 1024;
pub const MAX_DATA_RESULT_BYTES: usize = 48_000;
const MAX_MAPPINGS: usize = 4096;
const MAX_METADATA: usize = 131_072;
const PREVIEW_BYTES: usize = 64;
const MAX_LOADER_WARNINGS: usize = 16;
const MAX_LOADER_WARNING_BYTES: usize = 512;
const MAX_LOADER_DIAGNOSTIC_TEXT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct DataQuery {
    pub address: u64,
    pub size: usize,
    pub word_size: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct DataInspection {
    pub format: Format,
    pub arch: Arch,
    pub module_uuid: Option<String>,
    pub selected_image_file_offset: Option<u64>,
    pub selected_image_size: u64,
    pub backing_metadata_checked: bool,
    pub loader_diagnostics: DataLoaderDiagnostics,
    pub pointer_targets_suppressed: bool,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: usize,
    pub word_size: u8,
    pub data_big_endian: bool,
    pub trailing_bytes: usize,
    pub spans: Vec<DataSpan>,
    pub words: Vec<DataWord>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct DataLoaderDiagnostics {
    pub warnings_total: usize,
    pub warnings_omitted: usize,
    pub truncated: bool,
    pub warnings: Vec<DataLoaderWarning>,
}

#[derive(Debug, Serialize)]
pub struct DataLoaderWarning {
    pub message: String,
    pub text_truncated: bool,
}

fn loader_diagnostics(binary: &Binary) -> DataLoaderDiagnostics {
    let mut warnings = Vec::new();
    let mut remaining = MAX_LOADER_DIAGNOSTIC_TEXT_BYTES;
    for warning in binary.warnings.iter().take(MAX_LOADER_WARNINGS) {
        if remaining == 0 {
            break;
        }
        let mut end = warning.len().min(MAX_LOADER_WARNING_BYTES).min(remaining);
        while !warning.is_char_boundary(end) {
            end -= 1;
        }
        warnings.push(DataLoaderWarning { message: warning[..end].to_owned(), text_truncated: end < warning.len() });
        remaining -= end;
    }
    let warnings_omitted = binary.warnings.len() - warnings.len();
    DataLoaderDiagnostics {
        warnings_total: binary.warnings.len(),
        warnings_omitted,
        truncated: warnings_omitted != 0 || warnings.iter().any(|warning| warning.text_truncated),
        warnings,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataStatus {
    Stored,
    ZeroFill,
    Unavailable,
    Unmapped,
    Unreadable,
}

#[derive(Debug, Serialize)]
pub struct DataSpan {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: usize,
    pub status: DataStatus,
    pub image_offset: Option<u64>,
    pub file_offset: Option<u64>,
    pub permissions: Option<Perms>,
    pub hex: Option<String>,
    pub ascii: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DataWord {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub raw_value: Option<u64>,
    pub interpretation: &'static str,
    pub import: Option<DataImport>,
    pub candidate: Option<DataTarget>,
}

#[derive(Debug, Serialize)]
pub struct DataImport {
    pub name: String,
    pub library: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DataTarget {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub evidence: &'static str,
    pub address_adjustment: Option<&'static str>,
    pub permissions: Perms,
    pub code_range: bool,
    pub declared_function_start: bool,
    pub labels: Vec<String>,
    pub ascii_preview: Option<String>,
    pub ascii_terminated: bool,
}

struct View<'a> {
    binary: &'a Binary,
    segments: Vec<&'a Segment>,
    zero_fill: Vec<(u64, u64)>,
}

impl<'a> View<'a> {
    fn new(binary: &'a Binary) -> Result<Self, ApiError> {
        check_metadata(binary)?;
        let mut segments: Vec<_> = binary.segments.iter().filter(|segment| segment.size != 0).collect();
        segments.sort_by_key(|segment| segment.address);
        let mut end = 0;
        for segment in &segments {
            if segment.address < end || segment.file_size > segment.size {
                return Err(ApiError::Invalid("data inspection requires unambiguous memory mappings".into()));
            }
            end = segment.address.checked_add(segment.size).ok_or_else(|| invalid_range("mapping"))?;
            segment.file_offset.checked_add(segment.file_size).ok_or_else(|| invalid_range("file mapping"))?;
        }
        let zero_fill = binary
            .sections
            .iter()
            // ELF load segments define mapped zero-fill; TLS NOBITS can overlap real stored data.
            .filter(|section| binary.format != Format::Elf && section.kind == SectionKind::UninitializedData)
            .map(|section| {
                section
                    .address
                    .checked_add(section.size)
                    .map(|end| (section.address, end))
                    .ok_or_else(|| invalid_range("zero-fill section"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { binary, segments, zero_fill })
    }

    fn segment(&self, address: u64) -> Option<&'a Segment> {
        let index = self.segments.partition_point(|segment| segment.address <= address).checked_sub(1)?;
        self.segments.get(index).copied().filter(|segment| segment.contains(address))
    }

    fn byte(&self, address: u64) -> (DataStatus, Option<u8>, Option<u64>, Option<Perms>) {
        let Some(segment) = self.segment(address) else { return (DataStatus::Unmapped, None, None, None) };
        let perms = Some(segment.perms);
        if !segment.perms.read {
            return (DataStatus::Unreadable, None, None, perms);
        }
        let offset = address - segment.address;
        if offset >= segment.file_size || self.zero_fill.iter().any(|&(start, end)| start <= address && address < end) {
            return (DataStatus::ZeroFill, None, None, perms);
        }
        let image_offset = segment.file_offset + offset;
        match self.binary.read(address, 1).and_then(|bytes| bytes.first()).copied() {
            Some(byte) => (DataStatus::Stored, Some(byte), Some(image_offset), perms),
            None => (DataStatus::Unavailable, None, Some(image_offset), perms),
        }
    }

    fn target(&self, address: u64, evidence: &'static str) -> Option<DataTarget> {
        let thumb = self.binary.arch == Arch::Arm
            && address & 1 != 0
            && self.binary.thumb.iter().any(|range| range.contains(&(address & !1)))
            && self.binary.is_code(address & !1);
        let address = if thumb { address & !1 } else { address };
        let segment = self.segment(address)?;
        let mut preview = String::new();
        let mut terminated = false;
        for offset in 0..PREVIEW_BYTES as u64 {
            let Some(at) = address.checked_add(offset) else { break };
            let (DataStatus::Stored, Some(byte), _, _) = self.byte(at) else { break };
            if byte == 0 {
                terminated = true;
                break;
            }
            if !(0x20..=0x7e).contains(&byte) {
                preview.clear();
                break;
            }
            preview.push(char::from(byte));
        }
        Some(DataTarget {
            address,
            evidence,
            address_adjustment: thumb.then_some("thumb_bit_with_declared_mode"),
            permissions: segment.perms,
            code_range: self.binary.is_code(address),
            declared_function_start: false,
            labels: Vec::new(),
            ascii_terminated: preview.len() >= 4 && terminated,
            ascii_preview: (preview.len() >= 4).then_some(preview),
        })
    }
}

fn check_metadata(binary: &Binary) -> Result<(), ApiError> {
    if binary.segments.len() > MAX_MAPPINGS || binary.sections.len() > MAX_MAPPINGS || binary.thumb.len() > MAX_MAPPINGS
    {
        return Err(ApiError::Invalid("data inspection mapping budget exceeded".into()));
    }
    let (_, _, rebases) = binary.inventory_source_context();
    if binary
        .symbols
        .len()
        .saturating_add(binary.exports.len())
        .saturating_add(binary.function_starts.len())
        .saturating_add(binary.import_slots.len())
        .saturating_add(rebases.len())
        > MAX_METADATA
    {
        return Err(ApiError::Invalid("data inspection metadata budget exceeded".into()));
    }
    Ok(())
}

/// Resolve only numeric addresses or exact retained metadata, without building discovery/stub name indexes.
pub fn resolve_data_address(binary: &Binary, at: &str) -> Result<u64, ApiError> {
    if at.len() > 4096 {
        return Err(ApiError::Invalid("data address/name exceeds input budget".into()));
    }
    check_metadata(binary)?;
    if let Ok(address) = crate::parse_file_offset(at) {
        return Ok(address);
    }
    let mut found = None;
    for (address, name) in binary
        .symbols
        .iter()
        .map(|entry| (entry.address, entry.name.as_str()))
        .chain(binary.exports.iter().map(|entry| (entry.address, entry.name.as_str())))
        .chain(binary.import_slots.iter().map(|entry| (entry.address, entry.name.as_str())))
    {
        if name == at {
            if found.is_some_and(|previous| previous != address) {
                return Err(ApiError::Invalid("ambiguous metadata name; use an explicit image VA".into()));
            }
            found = Some(address);
        }
    }
    if let Some(address) = found {
        return Ok(address);
    }
    if let Some(hex) = at.strip_prefix("sub_")
        && let Ok(address) = u64::from_str_radix(hex, 16)
    {
        return Ok(address);
    }
    Err(ApiError::NotFound("data address/name not found in retained metadata".into()))
}

fn partial_pointer_metadata(binary: &Binary, address: u64, width: u8, pointer_size: u8) -> bool {
    let native = u64::from(pointer_size);
    let end = address + u64::from(width);
    let overlaps = |slot: u64| {
        slot < end && slot.saturating_add(native) > address && (slot != address || u64::from(width) != native)
    };
    let (_, _, rebases) = binary.inventory_source_context();
    binary.import_slots.iter().any(|slot| overlaps(slot.address)) || rebases.iter().any(|&(slot, _)| overlaps(slot))
}

fn invalid_range(what: &str) -> ApiError {
    ApiError::Invalid(format!("data inspection {what} overflows the address space"))
}

fn display_name(name: &str) -> String {
    let mut text: String = name.chars().take(96).collect();
    if name.chars().nth(96).is_some() {
        text.push_str(" [display truncated]");
    }
    text
}

/// Inspect retained native-image bytes without constructing a Project or its eager name indexes.
pub fn inspect_native_data(binary: &Binary, query: &DataQuery) -> Result<DataInspection, ApiError> {
    if binary.format == Format::Snapshot {
        return Err(ApiError::Invalid(
            "static data inspection requires a native image; use runtime tools for captures".into(),
        ));
    }
    inspect_static_data(binary, query)
}

/// Typed views may inspect immutable snapshot storage, without presenting synthetic offsets as file offsets.
pub(crate) fn inspect_static_data(binary: &Binary, query: &DataQuery) -> Result<DataInspection, ApiError> {
    // Existing native-image address bounds are independent of C pointer defaults.
    let code_address_highest = match binary.arch {
        Arch::X86 | Arch::Arm | Arch::Mips | Arch::PowerPc | Arch::Riscv32 | Arch::Sparc | Arch::M68k => {
            u64::from(u32::MAX)
        }
        Arch::X86_64 | Arch::Aarch64 | Arch::Mips64 | Arch::PowerPc64 | Arch::Riscv64 | Arch::Sparc64 | Arch::S390x => {
            u64::MAX
        }
    };
    inspect_static_data_with_widths(binary, query, binary.arch.default_pointer_size(), code_address_highest)
}

fn inspect_static_data_with_widths(
    binary: &Binary,
    query: &DataQuery,
    pointer_size: Option<u8>,
    code_address_highest: u64,
) -> Result<DataInspection, ApiError> {
    let snapshot = binary.format == Format::Snapshot;
    let word_size = query.word_size.or(pointer_size).ok_or_else(|| {
        ApiError::Invalid("data inspection has no default pointer width; supply scalar word_size 4 or 8".into())
    })?;
    if !(1..=MAX_DATA_BYTES).contains(&query.size) || !matches!(word_size, 4 | 8) {
        return Err(ApiError::Invalid("data inspection requires 1..=1024 bytes and word_size 4 or 8".into()));
    }
    let end = query.address.checked_add(query.size as u64).ok_or_else(|| invalid_range("request"))?;
    if end - 1 > code_address_highest {
        return Err(invalid_range("code-space request"));
    }
    let checked =
        binary.validate_available_backing_source().map_err(|error| ApiError::Unavailable(error.to_string()))?;
    let view = View::new(binary)?;
    let matching_pointer_width = pointer_size == Some(word_size);
    let pointer_targets_suppressed = snapshot || !binary.warnings.is_empty() || !matching_pointer_width;
    let (image, _, _) = binary.inventory_source_context();
    let mut spans: Vec<DataSpan> = Vec::new();
    let mut bytes = Vec::with_capacity(query.size);
    for at in query.address..end {
        let (status, byte, image_offset, permissions) = view.byte(at);
        let image_offset = if snapshot { None } else { image_offset };
        bytes.push(byte);
        let contiguous = spans.last().is_some_and(|span| {
            span.status == status
                && span.permissions == permissions
                && span.image_offset.map(|offset| offset + span.size as u64) == image_offset
        });
        if !contiguous {
            spans.push(DataSpan {
                address: at,
                size: 0,
                status,
                image_offset,
                file_offset: image_offset.and_then(|offset| (image.start as u64).checked_add(offset)),
                permissions,
                hex: byte.map(|_| String::new()),
                ascii: byte.map(|_| String::new()),
            });
        }
        let span = spans.last_mut().expect("byte has a span");
        span.size += 1;
        if let Some(byte) = byte {
            use std::fmt::Write;
            write!(span.hex.as_mut().unwrap(), "{byte:02x}").unwrap();
            span.ascii.as_mut().unwrap().push(if (0x20..=0x7e).contains(&byte) { char::from(byte) } else { '.' });
        }
    }
    let mut words = Vec::new();
    for (index, chunk) in bytes.chunks_exact(usize::from(word_size)).enumerate() {
        let address = query.address + (index * usize::from(word_size)) as u64;
        let raw = chunk.iter().copied().collect::<Option<Vec<_>>>();
        let raw_value = raw.as_ref().map(|bytes| {
            let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
            if binary.big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) }
        });
        let import = binary.import_slot(address).map(|import| DataImport {
            name: display_name(&import.name),
            library: import.library.as_deref().map(display_name),
        });
        let rebase = matching_pointer_width.then(|| binary.rebase_target(address)).flatten();
        let (interpretation, target) = if raw_value.is_none() {
            ("unavailable", None)
        } else if snapshot {
            ("snapshot_raw_word", None)
        } else if !binary.warnings.is_empty() {
            ("loader_warnings_pointer_targets_suppressed", None)
        } else if pointer_size.is_none() {
            ("unknown_pointer_width_pointer_targets_suppressed", None)
        } else if pointer_size.is_some_and(|width| partial_pointer_metadata(binary, address, word_size, width)) {
            ("partial_pointer_metadata", None)
        } else if !matching_pointer_width {
            ("scalar_word_pointer_targets_suppressed", None)
        } else if import.is_some() {
            ("import_binding", None)
        } else if let Some(target) = rebase {
            ("macho_chained_rebase", Some(target))
        } else if raw_value == Some(0) {
            ("zero_word", None)
        } else {
            ("raw_word_candidate", raw_value)
        };
        words.push(DataWord {
            address,
            raw_value,
            interpretation,
            import,
            candidate: target.and_then(|target| view.target(target, interpretation)),
        });
    }
    let targets: BTreeSet<_> =
        words.iter().filter_map(|word| word.candidate.as_ref().map(|target| target.address)).collect();
    for word in &mut words {
        let Some(target) = &mut word.candidate else { continue };
        target.declared_function_start = binary.function_starts.contains(&target.address)
            || binary
                .symbols
                .iter()
                .any(|symbol| symbol.address == target.address && symbol.kind == SymbolKind::Function);
    }
    let labels: Vec<_> = binary
        .symbols
        .iter()
        .map(|symbol| (symbol.address, &symbol.name))
        .chain(binary.exports.iter().map(|export| (export.address, &export.name)))
        .filter(|(address, _)| targets.contains(address))
        .collect();
    for word in &mut words {
        if let Some(target) = &mut word.candidate {
            target.labels = labels
                .iter()
                .filter(|(address, _)| *address == target.address)
                .take(2)
                .map(|(_, name)| display_name(name))
                .collect();
        }
    }
    binary.validate_available_backing_source().map_err(|error| ApiError::Unavailable(error.to_string()))?;
    let mut report = DataInspection {
        format: binary.format,
        arch: binary.arch,
        module_uuid: match &binary.details {
            Details::MachO(details) => details.uuid.clone(),
            _ => None,
        },
        selected_image_file_offset: (!snapshot).then_some(image.start as u64),
        selected_image_size: image.len() as u64,
        backing_metadata_checked: checked,
        loader_diagnostics: loader_diagnostics(binary),
        pointer_targets_suppressed,
        address: query.address,
        size: query.size,
        word_size,
        data_big_endian: binary.big_endian,
        trailing_bytes: query.size % usize::from(word_size),
        spans,
        words,
        limitations: vec![
            if snapshot {
                "Immutable snapshot region addresses; file/image offsets are unavailable. Selection size describes \
                 synthesized region storage, not an executable image or source-file range. No runtime execution proof."
            } else {
                "Native image only. Addresses are image VAs, not runtime addresses. Selection metadata is not a content hash."
            },
            "Words start at the analyst-supplied address; their interpretation does not establish \
             a pointer table or layout.",
            "Raw words are candidates only. Only retained Mach-O chained rebases are decoded; \
             other relocations are not applied.",
            "Any retained loader warning suppresses all pointer target interpretations and links, \
             including partial-width words and chained rebases; raw bytes/words and retained import identity remain.",
            "Loader diagnostics count retained warnings, not all possible loader problems. No warnings \
             does not establish metadata completeness. Display is capped at 16 warnings, 512 UTF-8 bytes each \
             and 4096 message bytes total; truncation flags and omitted counts describe this display only.",
            "Code ranges and declared entries are metadata, not validated instructions, call edges \
             or observed execution.",
            "ASCII previews are bounded to 64 stored bytes; display names to 96 characters and two labels per target.",
            "Zero-fill and unavailable bytes are not supplied as zeros. No discovery, annotations or target writes.",
            "Backing metadata is checked when available; reads are not atomic with external modification \
              or truncation.",
        ],
    };
    if !matching_pointer_width {
        report.limitations.push(
            "Scalar grouping does not establish pointer width. Unknown or mismatched defaults suppress all \
             pointer targets; retained import identity is metadata only.",
        );
    }
    if snapshot {
        report.limitations.push("Snapshot words remain raw and are never followed or treated as native relocations.");
    }
    if serde_json::to_vec(&report).map_err(|error| ApiError::Invalid(error.to_string()))?.len() > MAX_DATA_RESULT_BYTES
    {
        return Err(ApiError::Invalid("data inspection exceeds output budget; request a smaller size".into()));
    }
    Ok(report)
}

impl Project {
    pub fn inspect_data(&self, query: &DataQuery) -> Result<DataInspection, ApiError> {
        inspect_native_data(&self.binary, query)
    }
}

#[cfg(test)]
#[path = "data_tests.rs"]
mod tests;
