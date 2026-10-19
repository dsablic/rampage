//! Bounded PE linkage evidence from the retained selected image, never dependency discovery or function proof.
use std::cell::Cell;

use rampage_arch::Arch;
use serde::Serialize;

use crate::{Binary, Format, LoadError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LinkageLimits {
    pub max_records: usize,
    pub max_name_bytes: usize,
    pub max_total_name_bytes: usize,
    pub max_lookup_work: u64,
    pub max_image_bytes: usize,
}

impl Default for LinkageLimits {
    fn default() -> Self {
        Self {
            max_records: 65_536,
            max_name_bytes: 4096,
            max_total_name_bytes: 1024 * 1024,
            max_lookup_work: 1_000_000,
            max_image_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkageStatus {
    Available,
    Incomplete,
    Unavailable,
    Unsupported,
    InsufficientIdentity,
    WidthUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkageCoverageStatus {
    Complete,
    Incomplete,
    Unavailable,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkageLimitation {
    UnsupportedFormat,
    UnverifiedSource,
    ImageLimit,
    RecordLimit,
    NameLimit,
    LookupLimit,
    MalformedHeaders,
    UnavailableBytes,
    AmbiguousMapping,
    UnterminatedString,
    MalformedTable,
    DelayVaModeUnsupported,
    MissingProducerIdentity,
    UnsupportedWidth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkageCoverage {
    pub status: LinkageCoverageStatus,
    /// Known source-record upper bound, not necessarily the emitted count (aliases and empty export slots).
    pub declared_records: Option<u64>,
    pub records: usize,
    pub limitation: Option<LinkageLimitation>,
}

impl LinkageCoverage {
    fn complete(records: usize) -> Self {
        Self {
            status: LinkageCoverageStatus::Complete,
            declared_records: Some(records as u64),
            records,
            limitation: None,
        }
    }

    fn failed(reason: LinkageLimitation, declared_records: Option<u64>) -> Self {
        Self { status: LinkageCoverageStatus::Unavailable, declared_records, records: 0, limitation: Some(reason) }
    }
}

/// Raw bytes are comparison keys. Lossy text, if wanted, belongs only in a consumer's display layer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum LinkageSymbol {
    Named(Vec<u8>),
    Ordinal(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkageImportProvenance {
    PeImportDirectory,
    PeDelayImportDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkageImport {
    pub library: Vec<u8>,
    pub symbol: LinkageSymbol,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub slot_address: u64,
    pub provenance: LinkageImportProvenance,
    pub descriptor_rva: u32,
    pub lookup_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum LinkageExportTarget {
    Direct {
        #[serde(serialize_with = "rampage_arch::hex::address")]
        address: u64,
        executable_backing: bool,
    },
    Forwarder {
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkageExport {
    /// None is an ordinal-only export, not an invented `#ordinal` name.
    pub name: Option<Vec<u8>>,
    pub ordinal: u32,
    pub target: LinkageExportTarget,
    pub address_table_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkageMetadata {
    pub status: LinkageStatus,
    /// Raw validated PE directory declaration, not inferred from export rows or producer identity.
    /// False requires positively absent directory metadata and complete zero export coverage.
    pub export_directory_present: Option<bool>,
    /// The exact IMAGE_EXPORT_DIRECTORY.Name bytes. Never a file basename or debug/product identity.
    pub producer_library: Option<Vec<u8>>,
    pub imports: Vec<LinkageImport>,
    pub exports: Vec<LinkageExport>,
    pub regular_imports: LinkageCoverage,
    pub delay_imports: LinkageCoverage,
    pub export_coverage: LinkageCoverage,
    pub limitations: Vec<LinkageLimitation>,
    pub limits: LinkageLimits,
    pub lookup_work: u64,
    pub name_bytes: usize,
}

impl LinkageMetadata {
    fn unavailable(limits: LinkageLimits, reason: LinkageLimitation) -> Self {
        let status = match reason {
            LinkageLimitation::UnsupportedFormat | LinkageLimitation::UnverifiedSource => LinkageStatus::Unsupported,
            LinkageLimitation::UnsupportedWidth => LinkageStatus::WidthUnsupported,
            _ => LinkageStatus::Unavailable,
        };
        let mut coverage = LinkageCoverage::failed(reason, None);
        if status == LinkageStatus::Unsupported {
            coverage.status = LinkageCoverageStatus::Unsupported;
        }
        Self {
            status,
            export_directory_present: None,
            producer_library: None,
            imports: Vec::new(),
            exports: Vec::new(),
            regular_imports: coverage.clone(),
            delay_imports: coverage.clone(),
            export_coverage: coverage,
            limitations: vec![reason],
            limits,
            lookup_work: 0,
            name_bytes: 0,
        }
    }
}

/// Reads only the retained selected PE image. Callers must keep its mapped file quiescent: descriptor/path
/// metadata checks before and after parsing detect observable changes, but are not atomic with external writes.
/// Complete coverage, including both import tables, is necessary before a consumer claims a unique join.
pub fn linkage_metadata(binary: &Binary, limits: LinkageLimits) -> Result<LinkageMetadata, LoadError> {
    let verified = binary.validate_available_backing_source()?;
    let result = if binary.format != Format::Pe {
        LinkageMetadata::unavailable(limits, LinkageLimitation::UnsupportedFormat)
    } else if !verified {
        LinkageMetadata::unavailable(limits, LinkageLimitation::UnverifiedSource)
    } else if binary.image_bytes().len() > limits.max_image_bytes.min(128 * 1024 * 1024) {
        LinkageMetadata::unavailable(limits, LinkageLimitation::ImageLimit)
    } else if native_vectors_over_limit(binary, limits.max_records) {
        LinkageMetadata::unavailable(limits, LinkageLimitation::RecordLimit)
    } else {
        let header_work = Cell::new(0);
        match PeReader::new(binary.image_bytes(), binary.arch, binary.big_endian, limits, &header_work) {
            Ok(reader) => collect(reader),
            Err(reason) => {
                let mut metadata = LinkageMetadata::unavailable(limits, reason);
                metadata.lookup_work = header_work.get();
                metadata
            }
        }
    };
    binary.validate_available_backing_source()?;
    Ok(result)
}

fn native_vectors_over_limit(binary: &Binary, limit: usize) -> bool {
    [
        binary.segments.len(),
        binary.sections.len(),
        binary.symbols.len(),
        binary.imports.len(),
        binary.import_slots.len(),
        binary.exports.len(),
        binary.function_starts.len(),
        binary.slices.len(),
        binary.warnings.len(),
        binary.thumb.len(),
        binary.snapshot_modules.len(),
        binary.snapshot_registers.len(),
        binary.go_arguments.len(),
    ]
    .into_iter()
    .any(|length| length > limit)
        || binary.linkage_private_vectors_over_limit(limit)
        || match &binary.details {
            crate::Details::Pe(details) => details.characteristics.len() > limit || details.rich.len() > limit,
            crate::Details::Elf(details) => details.needed.len() > limit,
            crate::Details::MachO(details) => {
                [details.flags.len(), details.dylibs.len(), details.rpaths.len(), details.build_tools.len()]
                    .into_iter()
                    .any(|length| length > limit)
            }
            crate::Details::None => false,
        }
}

type Evidence<T> = Result<T, LinkageLimitation>;

fn bytes(data: &[u8], at: usize, len: usize) -> Evidence<&[u8]> {
    data.get(at..at.checked_add(len).ok_or(LinkageLimitation::UnavailableBytes)?)
        .ok_or(LinkageLimitation::UnavailableBytes)
}

fn u16_at(data: &[u8], at: usize) -> Evidence<u16> {
    let value = bytes(data, at, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Evidence<u32> {
    let value = bytes(data, at, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Evidence<u64> {
    let value = bytes(data, at, 8)?;
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| LinkageLimitation::UnavailableBytes)?))
}

fn add_rva(rva: u32, offset: usize) -> Evidence<u32> {
    rva.checked_add(u32::try_from(offset).map_err(|_| LinkageLimitation::MalformedTable)?)
        .ok_or(LinkageLimitation::MalformedTable)
}

#[derive(Clone, Copy)]
struct Directory {
    rva: u32,
    size: u32,
}

struct PeSection {
    rva: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
    executable: bool,
}

struct PeReader<'a> {
    data: &'a [u8],
    sections: Vec<PeSection>,
    headers: u32,
    base: u64,
    width: usize,
    image_size: u32,
    exports: Directory,
    imports: Directory,
    delay: Directory,
    limits: LinkageLimits,
    work: Cell<u64>,
    names: Cell<usize>,
    records: Cell<usize>,
}

impl<'a> PeReader<'a> {
    fn new(
        data: &'a [u8],
        arch: Arch,
        big_endian: bool,
        limits: LinkageLimits,
        charged_header_work: &Cell<u64>,
    ) -> Evidence<Self> {
        if big_endian || bytes(data, 0, 2)? != b"MZ" {
            return Err(LinkageLimitation::MalformedHeaders);
        }
        let pe = u32_at(data, 0x3c)? as usize;
        if bytes(data, pe, 4)? != b"PE\0\0" {
            return Err(LinkageLimitation::MalformedHeaders);
        }
        let coff = pe.checked_add(4).ok_or(LinkageLimitation::MalformedHeaders)?;
        let section_count = usize::from(u16_at(data, coff + 2)?);
        if section_count > limits.max_records {
            return Err(LinkageLimitation::RecordLimit);
        }
        let optional_len = usize::from(u16_at(data, coff + 16)?);
        let optional_at = coff + 20;
        let optional = bytes(data, optional_at, optional_len)?;
        let (width, directory_at, count_at, base) = match u16_at(optional, 0)? {
            0x10b => (4, 96, 92, u64::from(u32_at(optional, 28)?)),
            0x20b => (8, 112, 108, u64_at(optional, 24)?),
            _ => return Err(LinkageLimitation::MalformedHeaders),
        };
        let machine = u16_at(data, coff)?;
        let supported = matches!(
            (machine, arch, width),
            (0x14c, Arch::X86, 4)
                | (0x8664, Arch::X86_64, 8)
                | (0x1c0 | 0x1c2 | 0x1c4, Arch::Arm, 4)
                | (0xaa64, Arch::Aarch64, 8)
        );
        if !supported || arch.default_pointer_size().map(usize::from) != Some(width) {
            return Err(LinkageLimitation::UnsupportedWidth);
        }
        let image_size = u32_at(optional, 56)?;
        if image_size == 0 {
            return Err(LinkageLimitation::MalformedHeaders);
        }
        let last = base.checked_add(u64::from(image_size - 1)).ok_or(LinkageLimitation::UnsupportedWidth)?;
        if width == 4 && last > u64::from(u32::MAX) {
            return Err(LinkageLimitation::UnsupportedWidth);
        }
        let directory_count = u32_at(optional, count_at)? as usize;
        if directory_count > limits.max_records || directory_count > optional.len().saturating_sub(directory_at) / 8 {
            return Err(LinkageLimitation::MalformedHeaders);
        }
        let header_work = section_count as u64 + directory_count as u64 + 1;
        if header_work > limits.max_lookup_work {
            return Err(LinkageLimitation::LookupLimit);
        }
        charged_header_work.set(header_work);
        let directory = |index: usize| -> Evidence<Directory> {
            if index >= directory_count {
                return Ok(Directory { rva: 0, size: 0 });
            }
            let at = directory_at + index * 8;
            let result = Directory { rva: u32_at(optional, at)?, size: u32_at(optional, at + 4)? };
            if (result.rva == 0) != (result.size == 0) || result.rva.checked_add(result.size).is_none() {
                return Err(LinkageLimitation::MalformedHeaders);
            }
            Ok(result)
        };
        let section_at = optional_at + optional_len;
        let table = bytes(data, section_at, section_count * 40)?;
        let mut sections = Vec::with_capacity(section_count);
        for section in table.as_chunks::<40>().0 {
            let item = PeSection {
                virtual_size: u32_at(section, 8)?,
                rva: u32_at(section, 12)?,
                raw_size: u32_at(section, 16)?,
                raw_offset: u32_at(section, 20)?,
                executable: u32_at(section, 36)? & 0x2000_0000 != 0,
            };
            if item.rva.checked_add(item.virtual_size.max(item.raw_size)).is_none()
                || item.raw_offset.checked_add(item.raw_size).is_none()
            {
                return Err(LinkageLimitation::MalformedHeaders);
            }
            sections.push(item);
        }
        let headers = u32_at(optional, 60)?;
        if headers as usize > data.len() || (headers as usize) < section_at + table.len() {
            return Err(LinkageLimitation::MalformedHeaders);
        }
        Ok(Self {
            data,
            sections,
            headers,
            base,
            width,
            image_size,
            exports: directory(0)?,
            imports: directory(1)?,
            delay: directory(13)?,
            limits,
            work: Cell::new(header_work),
            names: Cell::new(0),
            records: Cell::new(0),
        })
    }

    fn charge(&self, amount: u64) -> Evidence<()> {
        let work = self.work.get().checked_add(amount).ok_or(LinkageLimitation::LookupLimit)?;
        if work > self.limits.max_lookup_work {
            return Err(LinkageLimitation::LookupLimit);
        }
        self.work.set(work);
        Ok(())
    }

    fn reserve_records(&self, amount: usize) -> Evidence<()> {
        let count = self.records.get().checked_add(amount).ok_or(LinkageLimitation::RecordLimit)?;
        if count > self.limits.max_records {
            return Err(LinkageLimitation::RecordLimit);
        }
        self.records.set(count);
        Ok(())
    }

    /// Returns a single unambiguous file-backed extent; virtual tails are never synthesized as zeroes.
    fn extent(&self, rva: u32) -> Evidence<(&'a [u8], bool)> {
        self.charge(self.sections.len() as u64 * 2 + 1)?;
        if rva >= self.image_size {
            return Err(LinkageLimitation::UnavailableBytes);
        }
        let mut found = (rva < self.headers).then(|| (rva as usize, self.headers as usize - rva as usize, false));
        let mut virtual_match = false;
        for section in &self.sections {
            let Some(offset) = rva.checked_sub(section.rva) else { continue };
            if offset >= section.virtual_size.max(section.raw_size) {
                continue;
            }
            if virtual_match || found.is_some() {
                return Err(LinkageLimitation::AmbiguousMapping);
            }
            virtual_match = true;
            if offset < section.raw_size {
                found = Some((
                    (section.raw_offset + offset) as usize,
                    (section.raw_size - offset) as usize,
                    section.executable,
                ));
            }
        }
        let (at, length, executable) = found.ok_or(LinkageLimitation::UnavailableBytes)?;
        let available = self.data.len().checked_sub(at).ok_or(LinkageLimitation::UnavailableBytes)?;
        let mut length = length.min(available).min((self.image_size - rva) as usize);
        // A later section may begin inside this extent, making a multi-byte read ambiguous there.
        for section in &self.sections {
            if section.rva > rva && section.virtual_size.max(section.raw_size) != 0 {
                length = length.min((section.rva - rva) as usize);
            }
        }
        Ok((bytes(self.data, at, length)?, executable))
    }

    fn read(&self, rva: u32, length: usize) -> Evidence<&'a [u8]> {
        bytes(self.extent(rva)?.0, 0, length)
    }

    fn name(&self, rva: u32, boundary: Option<u32>) -> Evidence<Vec<u8>> {
        if rva == 0 {
            return Err(LinkageLimitation::UnavailableBytes);
        }
        let extent = self.extent(rva)?.0;
        let bound = boundary.map_or(usize::MAX, |end| end.saturating_sub(rva) as usize);
        let max_name = self.limits.max_name_bytes.min(4096);
        let window_length = extent.len().min(max_name + 1).min(bound);
        let work_left = self.limits.max_lookup_work - self.work.get();
        let scan_length = window_length.min(usize::try_from(work_left).unwrap_or(usize::MAX));
        let window = &extent[..scan_length];
        let terminator = window.iter().position(|byte| *byte == 0);
        self.charge(terminator.map_or(window.len(), |index| index + 1) as u64)?;
        let length = terminator.ok_or({
            if scan_length < window_length {
                LinkageLimitation::LookupLimit
            } else if window.len() > max_name {
                LinkageLimitation::NameLimit
            } else {
                LinkageLimitation::UnterminatedString
            }
        })?;
        let total = self.names.get().checked_add(length).ok_or(LinkageLimitation::NameLimit)?;
        if total > self.limits.max_total_name_bytes {
            return Err(LinkageLimitation::NameLimit);
        }
        self.names.set(total);
        Ok(window[..length].to_vec())
    }

    fn address(&self, rva: u32) -> Evidence<u64> {
        if rva >= self.image_size {
            return Err(LinkageLimitation::UnavailableBytes);
        }
        let address = self.base.checked_add(u64::from(rva)).ok_or(LinkageLimitation::UnsupportedWidth)?;
        if self.width == 4 && address > u64::from(u32::MAX) {
            return Err(LinkageLimitation::UnsupportedWidth);
        }
        Ok(address)
    }

    fn thunk(&self, rva: u32) -> Evidence<u64> {
        let data = self.read(rva, self.width)?;
        if self.width == 4 { u32_at(data, 0).map(u64::from) } else { u64_at(data, 0) }
    }
}

struct ImportPlan {
    descriptor_rva: u32,
    library_rva: u32,
    lookup_rva: u32,
    slots_rva: u32,
    count: usize,
}

fn import_plan(reader: &PeReader<'_>, directory: Directory, delay: bool) -> Evidence<Vec<ImportPlan>> {
    if directory.rva == 0 {
        return Ok(Vec::new());
    }
    let size = if delay { 32 } else { 20 };
    let descriptors = directory.size as usize / size;
    if descriptors > reader.limits.max_records {
        return Err(LinkageLimitation::RecordLimit);
    }
    let mut plans = Vec::new();
    for index in 0..descriptors {
        let descriptor_rva = add_rva(directory.rva, index * size)?;
        let descriptor = reader.read(descriptor_rva, size)?;
        if descriptor.iter().all(|byte| *byte == 0) {
            return Ok(plans);
        }
        let (library_rva, lookup_rva, slots_rva) = if delay {
            if u32_at(descriptor, 0)? != 1 {
                return Err(LinkageLimitation::DelayVaModeUnsupported);
            }
            (u32_at(descriptor, 4)?, u32_at(descriptor, 16)?, u32_at(descriptor, 12)?)
        } else {
            let lookup = u32_at(descriptor, 0)?;
            let slots = u32_at(descriptor, 16)?;
            (u32_at(descriptor, 12)?, if lookup == 0 { slots } else { lookup }, slots)
        };
        if library_rva == 0 || lookup_rva == 0 || slots_rva == 0 {
            return Err(LinkageLimitation::MalformedTable);
        }
        let mut count: usize = 0;
        loop {
            let offset = count.checked_mul(reader.width).ok_or(LinkageLimitation::RecordLimit)?;
            let lookup = reader.thunk(add_rva(lookup_rva, offset)?)?;
            let slot_rva = add_rva(slots_rva, offset)?;
            let slot = reader.thunk(slot_rva)?;
            reader.address(slot_rva)?;
            // Nonterminal IAT values may be bound addresses or delay stubs, not lookup-table entries.
            if lookup == 0 {
                if slot != 0 {
                    return Err(LinkageLimitation::MalformedTable);
                }
                break;
            }
            reader.reserve_records(1)?;
            count += 1;
        }
        // Preserve descriptor evidence, including empty descriptors, within the same finite record budget.
        reader.reserve_records(1)?;
        plans.push(ImportPlan { descriptor_rva, library_rva, lookup_rva, slots_rva, count });
    }
    Err(LinkageLimitation::MalformedTable)
}

fn read_imports(reader: &PeReader<'_>, plans: &[ImportPlan], delay: bool) -> Evidence<Vec<LinkageImport>> {
    let mut imports = Vec::new();
    for plan in plans {
        let library = reader.name(plan.library_rva, None)?;
        if library.is_empty() {
            return Err(LinkageLimitation::MalformedTable);
        }
        for index in 0..plan.count {
            let lookup_rva = add_rva(plan.lookup_rva, index * reader.width)?;
            let thunk = reader.thunk(lookup_rva)?;
            let ordinal_flag = 1_u64 << (reader.width * 8 - 1);
            let symbol = if thunk & ordinal_flag != 0 {
                if thunk & !(ordinal_flag | 0xffff) != 0 {
                    return Err(LinkageLimitation::MalformedTable);
                }
                LinkageSymbol::Ordinal(thunk as u16)
            } else {
                let hint = u32::try_from(thunk).map_err(|_| LinkageLimitation::MalformedTable)?;
                reader.read(hint, 2)?;
                let name = reader.name(add_rva(hint, 2)?, None)?;
                if name.is_empty() {
                    return Err(LinkageLimitation::MalformedTable);
                }
                LinkageSymbol::Named(name)
            };
            // Every emitted library copy is charged, not only each descriptor's first spelling.
            let total = reader.names.get().checked_add(library.len()).ok_or(LinkageLimitation::NameLimit)?;
            if total > reader.limits.max_total_name_bytes {
                return Err(LinkageLimitation::NameLimit);
            }
            reader.names.set(total);
            imports.push(LinkageImport {
                library: library.clone(),
                symbol,
                slot_address: reader.address(add_rva(plan.slots_rva, index * reader.width)?)?,
                provenance: if delay {
                    LinkageImportProvenance::PeDelayImportDirectory
                } else {
                    LinkageImportProvenance::PeImportDirectory
                },
                descriptor_rva: plan.descriptor_rva,
                lookup_rva,
            });
        }
    }
    Ok(imports)
}

struct ExportPlan {
    ordinal_base: u32,
    functions_rva: u32,
    function_count: usize,
    names_rva: u32,
    ordinals_rva: u32,
    name_count: usize,
    library_rva: u32,
}

fn export_plan(reader: &PeReader<'_>, declared: &mut Option<u64>) -> Evidence<Option<ExportPlan>> {
    if reader.exports.rva == 0 {
        *declared = Some(0);
        return Ok(None);
    }
    if reader.exports.size < 40 {
        return Err(LinkageLimitation::MalformedTable);
    }
    let header = reader.read(reader.exports.rva, 40)?;
    let function_count = u32_at(header, 20)? as usize;
    let name_count = u32_at(header, 24)? as usize;
    *declared = Some(function_count as u64 + name_count as u64);
    let maximum = function_count.checked_add(name_count).ok_or(LinkageLimitation::RecordLimit)?;
    reader.reserve_records(maximum)?;
    let plan = ExportPlan {
        ordinal_base: u32_at(header, 16)?,
        function_count,
        name_count,
        functions_rva: u32_at(header, 28)?,
        names_rva: u32_at(header, 32)?,
        ordinals_rva: u32_at(header, 36)?,
        library_rva: u32_at(header, 12)?,
    };
    if function_count != 0 {
        plan.ordinal_base.checked_add(function_count as u32 - 1).ok_or(LinkageLimitation::MalformedTable)?;
        if plan.functions_rva == 0 {
            return Err(LinkageLimitation::MalformedTable);
        }
        reader.read(plan.functions_rva, function_count.checked_mul(4).ok_or(LinkageLimitation::RecordLimit)?)?;
    }
    if name_count != 0 {
        if plan.names_rva == 0 || plan.ordinals_rva == 0 {
            return Err(LinkageLimitation::MalformedTable);
        }
        reader.read(plan.names_rva, name_count.checked_mul(4).ok_or(LinkageLimitation::RecordLimit)?)?;
        reader.read(plan.ordinals_rva, name_count.checked_mul(2).ok_or(LinkageLimitation::RecordLimit)?)?;
    }
    Ok(Some(plan))
}

fn export_record(
    reader: &PeReader<'_>,
    plan: &ExportPlan,
    index: usize,
    name: Option<Vec<u8>>,
) -> Evidence<Option<LinkageExport>> {
    let address_table_rva = add_rva(plan.functions_rva, index * 4)?;
    let rva = u32_at(reader.read(address_table_rva, 4)?, 0)?;
    if rva == 0 {
        if name.is_some() {
            return Err(LinkageLimitation::MalformedTable);
        }
        return Ok(None);
    }
    let end = reader.exports.rva + reader.exports.size;
    let target = if (reader.exports.rva..end).contains(&rva) {
        let raw = reader.name(rva, Some(end))?;
        if raw.is_empty() {
            return Err(LinkageLimitation::MalformedTable);
        }
        LinkageExportTarget::Forwarder { raw }
    } else {
        let executable_backing = match reader.extent(rva) {
            Ok((data, executable)) => !data.is_empty() && executable,
            Err(LinkageLimitation::UnavailableBytes) => false,
            Err(reason) => return Err(reason),
        };
        LinkageExportTarget::Direct { address: reader.address(rva)?, executable_backing }
    };
    Ok(Some(LinkageExport { name, ordinal: plan.ordinal_base + index as u32, target, address_table_rva }))
}

fn read_exports(reader: &PeReader<'_>, plan: &ExportPlan) -> Evidence<Vec<LinkageExport>> {
    let mut named = vec![false; plan.function_count];
    let mut exports = Vec::new();
    for index in 0..plan.name_count {
        let ordinal = usize::from(u16_at(reader.read(add_rva(plan.ordinals_rva, index * 2)?, 2)?, 0)?);
        if ordinal >= plan.function_count {
            return Err(LinkageLimitation::MalformedTable);
        }
        let name_rva = u32_at(reader.read(add_rva(plan.names_rva, index * 4)?, 4)?, 0)?;
        let name = reader.name(name_rva, None)?;
        if name.is_empty() {
            return Err(LinkageLimitation::MalformedTable);
        }
        if let Some(export) = export_record(reader, plan, ordinal, Some(name))? {
            exports.push(export);
        }
        named[ordinal] = true;
    }
    for (index, named) in named.into_iter().enumerate() {
        if !named && let Some(export) = export_record(reader, plan, index, None)? {
            exports.push(export);
        }
    }
    Ok(exports)
}

fn collect(reader: PeReader<'_>) -> LinkageMetadata {
    let mut metadata = LinkageMetadata::unavailable(reader.limits, LinkageLimitation::MissingProducerIdentity);
    metadata.export_directory_present = Some(reader.exports.rva != 0);
    metadata.limitations.clear();
    // All table counts and thunk walks are preflighted before any name lookup or cloning.
    let regular = import_plan(&reader, reader.imports, false);
    let delay = import_plan(&reader, reader.delay, true);
    let mut declared_exports = None;
    let exports = export_plan(&reader, &mut declared_exports);
    for (plan, delayed) in [(regular, false), (delay, true)] {
        let result = plan.and_then(|plans| read_imports(&reader, &plans, delayed));
        let coverage = match result {
            Ok(imports) => {
                let coverage = LinkageCoverage::complete(imports.len());
                metadata.imports.extend(imports);
                coverage
            }
            Err(reason) => {
                metadata.limitations.push(reason);
                LinkageCoverage::failed(reason, None)
            }
        };
        if delayed { metadata.delay_imports = coverage } else { metadata.regular_imports = coverage }
    }
    let result = exports.and_then(|plan| match plan {
        Some(plan) => {
            match reader.name(plan.library_rva, None) {
                Ok(name) if !name.is_empty() => metadata.producer_library = Some(name),
                Ok(_) => metadata.limitations.push(LinkageLimitation::MissingProducerIdentity),
                Err(reason) => {
                    metadata.limitations.push(reason);
                    metadata.limitations.push(LinkageLimitation::MissingProducerIdentity);
                }
            }
            read_exports(&reader, &plan)
        }
        None => Ok(Vec::new()),
    });
    metadata.export_coverage = match result {
        Ok(exports) => {
            let mut coverage = LinkageCoverage::complete(exports.len());
            coverage.declared_records = declared_exports;
            metadata.exports = exports;
            coverage
        }
        Err(reason) => {
            metadata.limitations.push(reason);
            LinkageCoverage::failed(reason, declared_exports)
        }
    };
    if metadata.producer_library.is_none()
        && !metadata.limitations.contains(&LinkageLimitation::MissingProducerIdentity)
    {
        metadata.limitations.push(LinkageLimitation::MissingProducerIdentity);
    }
    metadata.status = if metadata.limitations.contains(&LinkageLimitation::UnsupportedWidth) {
        LinkageStatus::WidthUnsupported
    } else if [&metadata.regular_imports, &metadata.delay_imports, &metadata.export_coverage]
        .iter()
        .any(|coverage| coverage.status != LinkageCoverageStatus::Complete)
    {
        LinkageStatus::Incomplete
    } else if metadata.producer_library.is_none() {
        LinkageStatus::InsufficientIdentity
    } else {
        LinkageStatus::Available
    };
    metadata.lookup_work = reader.work.get();
    metadata.name_bytes = reader.names.get();
    metadata
}
