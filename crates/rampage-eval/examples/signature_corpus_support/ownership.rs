//! Opt-in ELF linked-artifact ownership; never changes the public-strong cohort.
//! Map symbol labels are deliberately ignored: LLD may print demangled names.
use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectSection, ObjectSymbol};
use rampage_loaders::Binary;
use serde::Serialize;

const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;

/// Buffers must be bounded, owned by the caller, and unchanged throughout this call.
/// Repeated archive paths must refer to the very same archive buffer. Ordinals are
/// zero-based in `object::read::archive::ArchiveFile::members()` order.
pub struct OwnedObject<'a> {
    pub archive_path: &'a str,
    pub archive_sha256: &'a str,
    pub archive_bytes: &'a [u8],
    pub member_ordinal: usize,
    pub original_name: &'a str,
    pub object_path: &'a str,
    pub object_sha256: &'a str,
    pub object_bytes: &'a [u8],
}

#[derive(Debug, Serialize)]
pub struct Definition {
    pub object_index: usize,
    pub source_symbol_index: usize,
    pub source_section_index: usize,
    pub raw_name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct Provenance {
    pub archive_path: String,
    pub archive_sha256: String,
    pub member_ordinal: usize,
    pub original_name: String,
    pub object_path: String,
    pub object_sha256: String,
}

#[derive(Debug, Default, Serialize)]
pub struct OwnershipReceipt {
    pub definitions: Vec<Definition>,
    pub excluded_definitions: usize,
    pub unresolved_definitions: usize,
    pub map_sha256: String,
    pub objects: Vec<Provenance>,
    pub byte_binding: &'static str,
}

fn bounded_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 4096 || name.chars().any(char::is_control) {
        return Err("empty, overlong or control-containing ownership name".into());
    }
    Ok(())
}

fn identity(name: &str) -> Result<(), String> {
    bounded_name(name)?;
    if name.chars().any(|c| c.is_whitespace() || matches!(c, '(' | ')' | ':')) {
        return Err("ambiguous LLD object/member path (spaces, parentheses or colon)".into());
    }
    Ok(())
}

fn charge(records: &mut usize) -> Result<(), String> {
    if *records >= MAX_RECORDS {
        return Err("ownership record budget exceeded".into());
    }
    *records += 1;
    Ok(())
}

fn validate_receipts(receipts: &[OwnedObject<'_>], records: &mut usize) -> Result<(), String> {
    if receipts.is_empty() || receipts.len() > super::signature_corpus_support::MAX_LIBRARY_OBJECTS {
        return Err("ownership requires 1..2048 explicit objects".into());
    }
    let mut archives = BTreeMap::<&str, Vec<usize>>::new();
    let mut object_bytes = 0usize;
    for (index, receipt) in receipts.iter().enumerate() {
        for name in [receipt.archive_path, receipt.original_name, receipt.object_path] {
            identity(name)?;
        }
        object_bytes = object_bytes.checked_add(receipt.object_bytes.len()).ok_or("object byte overflow")?;
        if object_bytes > MAX_BYTES || super::digest(receipt.object_bytes) != receipt.object_sha256 {
            return Err("object byte budget exceeded or SHA-256 mismatch".into());
        }
        archives.entry(receipt.archive_path).or_default().push(index);
    }
    let mut archive_bytes = 0usize;
    for indices in archives.values() {
        let first = &receipts[indices[0]];
        archive_bytes = archive_bytes.checked_add(first.archive_bytes.len()).ok_or("archive byte overflow")?;
        if archive_bytes > MAX_ARCHIVE_BYTES || super::digest(first.archive_bytes) != first.archive_sha256 {
            return Err("archive byte budget exceeded or SHA-256 mismatch".into());
        }
        let mut wanted = BTreeMap::new();
        for &index in indices {
            let receipt = &receipts[index];
            if !std::ptr::eq(first.archive_bytes, receipt.archive_bytes)
                || first.archive_sha256 != receipt.archive_sha256
                || wanted.insert(receipt.member_ordinal, index).is_some()
            {
                return Err("inconsistent archive buffers or duplicate member receipt".into());
            }
        }
        let archive =
            object::read::archive::ArchiveFile::parse(first.archive_bytes).map_err(|error| error.to_string())?;
        if !first.archive_bytes.starts_with(b"!<arch>\n") || archive.is_thin() {
            return Err("ownership requires a regular GNU/BSD Unix archive".into());
        }
        let mut names = BTreeSet::new();
        for (ordinal, member) in archive.members().enumerate() {
            charge(records)?;
            let member = member.map_err(|error| error.to_string())?;
            if member.name().len() > 4096 {
                return Err("archive member name budget exceeded".into());
            }
            if !names.insert(member.name()) {
                return Err("duplicate archive member names cannot identify an LLD map ordinal".into());
            }
            if let Some(index) = wanted.remove(&ordinal) {
                let receipt = &receipts[index];
                if member.name() != receipt.original_name.as_bytes()
                    || member.data(first.archive_bytes).map_err(|error| error.to_string())? != receipt.object_bytes
                {
                    return Err("archive ordinal/name/content does not match object receipt".into());
                }
            }
        }
        if !wanted.is_empty() {
            return Err("archive member ordinal not found".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Input<'a> {
    address: u64,
    size: u64,
    align: u64,
    output: (&'a str, u64, u64),
}

fn extent(address: u64, size: u64) -> Result<u64, String> {
    address.checked_add(size).ok_or_else(|| "ownership extent overflow".into())
}

/// The supported grammar is LLVM ELF's VMA/LMA/Size/Align/Out/In/Symbol table.
/// This is not a GNU ld map parser. Input spellings are exact, never basenames.
fn parse_map<'a>(
    bytes: &'a [u8],
    identities: &BTreeMap<String, usize>,
    records: &mut usize,
) -> Result<BTreeMap<(usize, &'a str), Input<'a>>, String> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("LLD map exceeds 64 MiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "LLD map is not UTF-8")?;
    let mut lines = text.lines();
    let header = lines.next().ok_or("empty LLD map")?;
    if !header.split_whitespace().eq(["VMA", "LMA", "Size", "Align", "Out", "In", "Symbol"]) {
        return Err("unsupported LLD ELF map header".into());
    }
    let columns = ["Out", "In", "Symbol"].map(|s| column(&header[..header.find(s).unwrap()]));
    let mut output = None;
    let mut inputs = BTreeMap::new();
    let mut ranges = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        charge(records)?;
        let mut rest = line;
        let mut numbers = [0u64; 4];
        for (index, value) in numbers.iter_mut().enumerate() {
            rest = rest.trim_start_matches([' ', '\t']);
            let end = rest.find([' ', '\t']).ok_or("missing LLD map columns")?;
            *value = u64::from_str_radix(&rest[..end], if index == 3 { 10 } else { 16 })
                .map_err(|_| "invalid LLD map number")?;
            rest = &rest[end..];
        }
        let payload = rest.trim_start_matches([' ', '\t']);
        let at = column(&line[..line.len() - payload.len()]);
        let [address, lma, size, align] = numbers;
        extent(address, size)?;
        if at < columns[0] || payload.is_empty() {
            return Err("invalid LLD map indentation".into());
        }
        if at < columns[1] {
            bounded_name(payload)?;
            output = Some((payload, address, size));
        } else if at < columns[2] {
            let (path, section) = payload.rsplit_once(":(").ok_or("unsupported LLD input spelling")?;
            let section = section.strip_suffix(')').ok_or("unterminated LLD input section")?;
            bounded_name(section)?;
            let output = output.ok_or("LLD input without output section")?;
            if size > 0 {
                ranges.push((output.0, address, extent(address, size)?, identities.contains_key(path)));
            }
            if let Some(&index) = identities.get(path) {
                if lma != address || align == 0 || !align.is_power_of_two() || address % align != 0 {
                    return Err("unsupported owned input LMA/alignment".into());
                }
                if address < output.1
                    || extent(address, size)? > extent(output.1, output.2)?
                    || inputs.insert((index, section), Input { address, size, align, output }).is_some()
                {
                    return Err("ambiguous or out-of-range owned input section".into());
                }
            }
        }
        // Symbol rows are intentionally not a source of raw names or sizes.
    }
    ranges.sort_unstable();
    let (mut group, mut all_end, mut owned_end) = ("", 0, 0);
    for (output, start, end, owned) in ranges {
        if output != group {
            (group, all_end, owned_end) = (output, 0, 0);
        }
        if (owned && start < all_end) || start < owned_end {
            return Err("owned section overlaps another input winner, including unowned/ICF input".into());
        }
        all_end = all_end.max(end);
        if owned {
            owned_end = owned_end.max(end);
        }
    }
    Ok(inputs)
}

fn column(prefix: &str) -> usize {
    prefix.bytes().fold(0, |n, c| if c == b'\t' { (n / 8 + 1) * 8 } else { n + 1 })
}

fn function(symbol: &object::Symbol<'_, '_>) -> bool {
    matches!(symbol.flags(), object::SymbolFlags::Elf { st_info, .. } if st_info.st_type() == object::elf::STT_FUNC)
}

fn code(section: &object::Section<'_, '_>) -> bool {
    matches!(section.flags(), object::SectionFlags::Elf { sh_flags, sh_type }
        if sh_type == object::elf::SHT_PROGBITS && sh_flags.contains(object::elf::SHF_ALLOC)
            && sh_flags.contains(object::elf::SHF_EXECINSTR))
}

struct RelocatedField {
    offset: u64,
    mask: [u8; 8],
    required_zero: [u8; 8],
    width: usize,
}

fn relocation_bits(arch: object::Architecture, typ: object::elf::RelocationType) -> Result<(usize, u64), String> {
    use object::Architecture::{Aarch64, Arm, I386, X86_64};
    use object::elf::*;
    let field = match (arch, typ) {
        (_, R_X86_64_NONE) => (0, 0),
        (X86_64, R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_32 | R_X86_64_32S)
        | (I386, R_386_32 | R_386_PC32 | R_386_PLT32)
        | (Aarch64, R_AARCH64_ABS32 | R_AARCH64_PREL32)
        | (Arm, R_ARM_ABS32 | R_ARM_REL32 | R_ARM_ABS32_NOI | R_ARM_REL32_NOI) => (4, u32::MAX as u64),
        (X86_64, R_X86_64_64) | (Aarch64, R_AARCH64_ABS64) => (8, u64::MAX),
        (Aarch64, R_AARCH64_CALL26 | R_AARCH64_JUMP26) => (4, 0x03ff_ffff),
        (Aarch64, R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_PREL_PG_HI21_NC) => (4, 0x60ff_ffe0),
        (Aarch64, R_AARCH64_ADD_ABS_LO12_NC | R_AARCH64_LDST8_ABS_LO12_NC) => (4, 0x003f_fc00),
        (Aarch64, R_AARCH64_LDST16_ABS_LO12_NC) => (4, 0x001f_fc00),
        (Aarch64, R_AARCH64_LDST32_ABS_LO12_NC) => (4, 0x000f_fc00),
        (Aarch64, R_AARCH64_LDST64_ABS_LO12_NC) => (4, 0x0007_fc00),
        (Aarch64, R_AARCH64_LDST128_ABS_LO12_NC) => (4, 0x0003_fc00),
        (Arm, R_ARM_THM_PC22 | R_ARM_THM_JUMP24) => (4, 0x2fff_07ff),
        (Arm, R_ARM_CALL | R_ARM_JUMP24) => (4, 0x00ff_ffff),
        _ => return Err(format!("unsupported native ELF text relocation {arch:?}/{typ:?}; ownership refused")),
    };
    Ok(field)
}

fn relocated_fields(
    source: &object::File<'_>, section: &object::Section<'_, '_>, records: &mut usize,
) -> Result<Vec<RelocatedField>, String> {
    let mut fields = Vec::new();
    for (offset, relocation) in section.relocations() {
        charge(records)?;
        let object::RelocationFlags::Elf { r_type } = relocation.flags() else {
            return Err("expected explicit native ELF relocation flags".into());
        };
        let (width, bits) = relocation_bits(source.architecture(), r_type)?;
        if width == 0 { continue; }
        if extent(offset, width as u64)? > section.size() { return Err("relocation exceeds owned section".into()); }
        let partial = width == 4 && bits != u32::MAX as u64;
        if partial && !source.is_little_endian() {
            return Err("big-endian ARM/AArch64 instruction relocations are unsupported".into());
        }
        let thumb = matches!(r_type, object::elf::R_ARM_THM_PC22 | object::elf::R_ARM_THM_JUMP24)
            && source.architecture() == object::Architecture::Arm;
        if partial && offset % (if thumb { 2 } else { 4 }) != 0 {
            return Err("unaligned native instruction relocation".into());
        }
        if thumb {
            let data = section.data().map_err(|error| error.to_string())?;
            let start = usize::try_from(offset).map_err(|_| "Thumb relocation offset overflow")?;
            let bytes = data.get(start..start + 4).ok_or("unbacked Thumb relocation")?;
            let first = u16::from_le_bytes([bytes[0], bytes[1]]);
            let second = u16::from_le_bytes([bytes[2], bytes[3]]);
            let opcode = if r_type == object::elf::R_ARM_THM_PC22 { 0xd000 } else { 0x9000 };
            if first & 0xf800 != 0xf000 || second & 0xd000 != opcode {
                return Err("unsupported Thumb branch encoding (including BLX); ownership refused".into());
            }
        }
        let mut mask = [0; 8];
        let mut required_zero = [0; 8];
        if width == 8 {
            mask = if source.is_little_endian() { bits.to_le_bytes() } else { bits.to_be_bytes() };
        } else {
            let bytes = if source.is_little_endian() {
                (bits as u32).to_le_bytes()
            } else {
                (bits as u32).to_be_bytes()
            };
            mask[..4].copy_from_slice(&bytes);
        }
        if source.architecture() == object::Architecture::Aarch64
            && matches!(r_type, object::elf::R_AARCH64_LDST16_ABS_LO12_NC
                | object::elf::R_AARCH64_LDST32_ABS_LO12_NC | object::elf::R_AARCH64_LDST64_ABS_LO12_NC
                | object::elf::R_AARCH64_LDST128_ABS_LO12_NC)
        {
            required_zero[..4].copy_from_slice(&(0x003f_fc00u32 & !(bits as u32)).to_le_bytes());
        }
        fields.push(RelocatedField { offset, mask, required_zero, width });
    }
    fields.sort_unstable_by_key(|field| field.offset);
    if fields.windows(2).any(|pair| pair[0].offset + pair[0].width as u64 > pair[1].offset) {
        return Err("overlapping native text relocation fields are unsupported".into());
    }
    Ok(fields)
}

fn verify_function_bytes(
    section: &[u8], offset: u64, linked: &[u8], fields: &[RelocatedField],
    byte_budget: &mut usize, records: &mut usize,
) -> Result<(), String> {
    *byte_budget = byte_budget.checked_sub(linked.len()).ok_or("ownership byte-comparison budget exceeded")?;
    let end = extent(offset, linked.len() as u64)?;
    let start = usize::try_from(offset).map_err(|_| "source function offset overflow")?;
    let limit = usize::try_from(end).map_err(|_| "source function extent overflow")?;
    let source = section.get(start..limit).ok_or("source function is not file backed")?;
    let first = fields.partition_point(|field| field.offset + field.width as u64 <= offset);
    let mut cursor = 0;
    let mut immutable = false;
    let mismatch = "owned function bytes differ outside native relocation bits; reject relaxation (replay --no-relax)";
    for field in fields[first..].iter().take_while(|field| field.offset < end) {
        charge(records)?;
        if field.offset < offset || extent(field.offset, field.width as u64)? > end {
            return Err("native relocation straddles producer function boundary".into());
        }
        let at = usize::try_from(field.offset - offset).map_err(|_| "function relocation offset overflow")?;
        if source[cursor..at] != linked[cursor..at] { return Err(mismatch.into()); }
        immutable |= at > cursor;
        for (((before, after), mask), zero) in source[at..at + field.width].iter()
            .zip(&linked[at..at + field.width]).zip(&field.mask[..field.width])
            .zip(&field.required_zero[..field.width])
        {
            if (*before | *after) & *zero != 0 {
                return Err("nonzero fixed high immediate bits in scaled AArch64 LDST LO12 relocation".into());
            }
            let keep = !*mask;
            immutable |= keep != 0;
            if (*before ^ *after) & keep != 0 { return Err(mismatch.into()); }
        }
        cursor = at + field.width;
    }
    if source[cursor..] != linked[cursor..] { return Err(mismatch.into()); }
    immutable |= cursor < source.len();
    if !immutable { return Err("producer function has no immutable bits outside relocation fields".into()); }
    Ok(())
}

/// Truth/training only: linked symbols identify the winning definition, including
/// hidden symbols localized by LLD. Never pass these raw names to held-out lookup.
/// An Err refuses the entire scope; successful receipts explicitly count omissions.
pub fn linked_definitions(
    map_bytes: &[u8],
    linked: &Binary,
    receipts: &[OwnedObject<'_>],
) -> Result<OwnershipReceipt, String> {
    if linked.format != rampage_loaders::Format::Elf {
        return Err("ownership supports ELF only".into());
    }
    if linked.image_bytes().len() > MAX_BYTES {
        return Err("linked image exceeds 256 MiB".into());
    }
    if !matches!(linked.image_bytes().get(7), Some(0 | 3)) {
        return Err("linked-artifact scope supports ELF System V/Linux ABI only".into());
    }
    let file = object::File::parse(linked.image_bytes()).map_err(|error| error.to_string())?;
    if !matches!(file.kind(), object::ObjectKind::Executable | object::ObjectKind::Dynamic)
        || !matches!(
            file.architecture(),
            object::Architecture::X86_64
                | object::Architecture::Aarch64
                | object::Architecture::I386
                | object::Architecture::Arm
        )
    {
        return Err("unsupported linked ELF kind/architecture".into());
    }
    let mut records = 0;
    validate_receipts(receipts, &mut records)?;
    let mut identities = BTreeMap::new();
    for (index, receipt) in receipts.iter().enumerate() {
        for name in [receipt.object_path.to_owned(), format!("{}({})", receipt.archive_path, receipt.original_name)] {
            if identities.insert(name, index).is_some() {
                return Err("duplicate object/map identity".into());
            }
        }
    }
    let inputs = parse_map(map_bytes, &identities, &mut records)?;
    let normalize = |address: u64| {
        if file.architecture() == object::Architecture::Arm { address & !1 } else { address }
    };
    let mut symbols = BTreeMap::<(u64, &str, u64), Vec<usize>>::new();
    for symbol in file.symbols() {
        charge(&mut records)?;
        if function(&symbol) && !symbol.is_undefined() {
            let name = symbol.name().map_err(|error| error.to_string())?;
            bounded_name(name)?;
            if let Some(section) = symbol.section_index() {
                symbols.entry((normalize(symbol.address()), name, symbol.size())).or_default().push(section.0);
            }
        }
    }
    let mut result = OwnershipReceipt {
        map_sha256: super::digest(map_bytes),
        byte_binding: "native_ELF_relocation_masked_producer_FUNC_bytes_v1",
        ..Default::default()
    };
    let mut byte_budget = 2 * MAX_BYTES;
    let mut ranges = BTreeMap::<u64, u64>::new();
    let mut name_bytes = 0usize;
    let mut output_names = BTreeMap::new();
    for section in file.sections() {
        charge(&mut records)?;
        if code(&section)
            && output_names.insert(section.name().map_err(|error| error.to_string())?, section.index()).is_some()
        {
            return Err("duplicate linked code section names are ambiguous".into());
        }
    }
    for (index, receipt) in receipts.iter().enumerate() {
        let source = object::File::parse(receipt.object_bytes).map_err(|error| error.to_string())?;
        if source.kind() != object::ObjectKind::Relocatable
            || source.format() != object::BinaryFormat::Elf
            || source.architecture() != file.architecture()
            || source.is_little_endian() != file.is_little_endian()
        {
            return Err("owned object is not same-architecture/endian relocatable ELF".into());
        }
        let mut sections = BTreeSet::new();
        for section in source.sections() {
            charge(&mut records)?;
            let name = section.name().map_err(|error| error.to_string())?;
            if code(&section) {
                identity(name)?;
            }
            if code(&section) && !sections.insert(name) {
                return Err("duplicate producer code section names are ambiguous in LLD map".into());
            }
        }
        let mut checked_sections = BTreeSet::new();
        let mut relocation_fields = BTreeMap::new();
        let mut definitions = BTreeSet::new();
        for symbol in source.symbols() {
            charge(&mut records)?;
            if !function(&symbol) {
                continue;
            }
            let Some(section_index) = symbol.section_index().filter(|_| !symbol.is_undefined()) else {
                result.excluded_definitions += 1;
                continue;
            };
            let section = source.section_by_index(section_index).map_err(|error| error.to_string())?;
            let section_name = section.name().map_err(|error| error.to_string())?;
            let Some(input) = inputs.get(&(index, section_name)).filter(|_| code(&section) && symbol.size() > 0) else {
                result.excluded_definitions += 1;
                continue;
            };
            let output_index = *output_names.get(input.output.0).ok_or("missing linked code output section")?;
            let output = file.section_by_index(output_index).map_err(|error| error.to_string())?;
            if checked_sections.insert(section_index.0) {
                if input.size != section.size()
                    || input.align != section.align()
                    || output.address() != input.output.1
                    || output.size() != input.output.2
                    || section.file_range().is_none_or(|(_, size)| size < section.size())
                    || output.file_range().is_none_or(|(_, size)| size < output.size())
                    || section.data().map_err(|error| error.to_string())?.len() as u64 != section.size()
                    || linked.code_from(input.address).is_none_or(|bytes| (bytes.len() as u64) < input.size)
                {
                    return Err("owned input/output extent, code backing or alignment disagrees with ELF".into());
                }
                let end = extent(input.address, input.size)?;
                if ranges.range(..end).next_back().is_some_and(|(_, &previous_end)| previous_end > input.address) {
                    return Err("overlapping owned section winners (including ICF) are unsupported".into());
                }
                ranges.insert(input.address, end);
                let (file_offset, _) = output.file_range().ok_or("unbacked output")?;
                let start = extent(file_offset, input.address - output.address())?;
                let end = extent(start, input.size)?;
                let start = usize::try_from(start).map_err(|_| "output offset overflow")?;
                let end = usize::try_from(end).map_err(|_| "output offset overflow")?;
                if linked.read(input.address, input.size).is_none()
                    || linked.read(input.address, input.size) != linked.image_bytes().get(start..end)
                {
                    return Err("ELF section and load-image file backing disagree".into());
                }
                relocation_fields.insert(section_index.0, relocated_fields(&source, &section, &mut records)?);
            }
            let offset = normalize(symbol.address()).checked_sub(section.address()).ok_or("invalid source offset")?;
            if extent(offset, symbol.size())? > input.size {
                return Err("source function exceeds input section".into());
            }
            let address = extent(input.address, offset)?;
            let name = symbol.name().map_err(|error| error.to_string())?;
            bounded_name(name)?;
            if !definitions.insert((address, name, symbol.size())) {
                return Err("duplicate producer definition identity".into());
            }
            let Some(matches) = symbols.get(&(address, name, symbol.size())) else {
                result.unresolved_definitions += 1;
                continue;
            };
            if matches.as_slice() != [output.index().0] {
                return Err("ambiguous linked raw-name/address/producer-size definition".into());
            }
            verify_function_bytes(
                section.data().map_err(|error| error.to_string())?, offset,
                linked.read(address, symbol.size()).ok_or("unbacked linked producer function")?,
                relocation_fields.get(&section_index.0).ok_or("missing checked section relocation fields")?,
                &mut byte_budget, &mut records,
            ).map_err(|error| format!("{name} at {address:#x}: {error}"))?;
            name_bytes = name_bytes.checked_add(name.len()).ok_or("definition name budget overflow")?;
            if name_bytes > 64 * 1024 * 1024 || result.definitions.len() >= 100_000 {
                return Err("definition name/count budget exceeded".into());
            }
            result.definitions.push(Definition {
                object_index: index,
                source_symbol_index: symbol.index().0,
                source_section_index: section_index.0,
                raw_name: name.to_owned(),
                address,
                size: symbol.size(),
            });
        }
        result.objects.push(Provenance {
            archive_path: receipt.archive_path.into(),
            archive_sha256: receipt.archive_sha256.into(),
            member_ordinal: receipt.member_ordinal,
            original_name: receipt.original_name.into(),
            object_path: receipt.object_path.into(),
            object_sha256: receipt.object_sha256.into(),
        });
    }
    if result.definitions.is_empty() {
        return Err(format!(
            "no verified winning linked definitions; excluded={}, unresolved={}; scope unsupported",
            result.excluded_definitions, result.unresolved_definitions
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    use crate::fixture_support;

    fn native_object(
        arch: object::Architecture, body: &[u8], relocation: Option<(u64, object::elf::RelocationType)>,
    ) -> Vec<u8> {
        let mut object = object::write::Object::new(object::BinaryFormat::Elf, arch, object::Endianness::Little);
        let text = object.add_section(Vec::new(), b".text.foo".to_vec(), object::SectionKind::Text);
        let mut bytes = body.to_vec();
        bytes.resize(16, 0x90);
        object.append_section_data(text, &bytes, 16);
        let symbol = object.add_symbol(object::write::Symbol {
            name: b"foo".to_vec(), value: 0, size: body.len() as u64, kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage, weak: true,
            section: object::write::SymbolSection::Section(text), flags: object::SymbolFlags::None,
        });
        if let Some((offset, r_type)) = relocation {
            object.add_relocation(text, object::write::Relocation {
                offset, symbol, addend: 0, flags: object::RelocationFlags::Elf { r_type },
            }).unwrap();
        }
        object.write().unwrap()
    }

    // A native ELF writer fixture, not captured LLD output and never executed.
    fn native_image(body: &[u8]) -> Vec<u8> {
        let object = native_object(object::Architecture::X86_64, body, None);
        let mut image = object::build::elf::Builder::read(object.as_slice()).unwrap();
        let text_id = image.sections.iter().find(|section| section.name.as_slice() == b".text.foo").unwrap().id();
        let text = image.sections.get_mut(text_id);
        text.name = b".text".as_slice().into();
        text.sh_addr = 0x201000;
        text.sh_offset = 0x1000;
        for symbol in &mut image.symbols {
            if symbol.section == Some(text_id) { symbol.st_value += 0x201000; }
        }
        image.header.e_type = object::elf::ET_EXEC;
        image.header.e_entry = 0x201000;
        image.header.e_phoff = 64;
        let segment = image.segments.add();
        segment.p_type = object::elf::PT_LOAD;
        segment.p_flags = object::elf::PF_R | object::elf::PF_X;
        segment.p_offset = 0x1000;
        segment.p_vaddr = 0x201000;
        segment.p_paddr = 0x201000;
        segment.p_filesz = 16;
        segment.p_memsz = 16;
        segment.p_align = 0x1000;
        segment.sections.push(text_id);
        let mut bytes = Vec::new();
        image.write(&mut bytes).unwrap();
        bytes
    }

    fn collect_native(source: &[u8], linked_body: &[u8]) -> Result<OwnershipReceipt, String> {
        let files = fixture_support::TempFiles::new();
        let image = native_image(linked_body);
        let path = files.write("linked.elf", &image);
        let binary = Binary::open(path).unwrap();
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend_from_slice(format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "foo.o/", 0, 0, 0, 644, source.len()).as_bytes());
        archive.extend_from_slice(source);
        if source.len() % 2 != 0 { archive.push(b'\n'); }
        let archive_sha256 = super::super::digest(&archive);
        let object_sha256 = super::super::digest(source);
        let receipt = OwnedObject {
            archive_path: "lib.a", archive_sha256: &archive_sha256, archive_bytes: &archive,
            member_ordinal: 0, original_name: "foo.o", object_path: "foo.o",
            object_sha256: &object_sha256, object_bytes: source,
        };
        let map = String::from_utf8(map("lib.a(foo.o)")).unwrap()
            .replace("       20    16 .text", "       10    16 .text");
        linked_definitions(map.as_bytes(), &binary, &[receipt])
    }

    #[test]
    fn native_archive_substitution_with_same_names_addresses_and_sizes_is_rejected() {
        let one = [0xb8, 1, 0, 0, 0, 0xc3];
        let two = [0xb8, 2, 0, 0, 0, 0xc3];
        let source_a = native_object(object::Architecture::X86_64, &one, None);
        let source_b = native_object(object::Architecture::X86_64, &two, None);
        let receipt = collect_native(&source_a, &one).unwrap();
        assert_eq!(receipt.definitions.len(), 1);
        assert_eq!(receipt.definitions[0].size, 6);
        assert!(collect_native(&source_b, &one).unwrap_err().contains("bytes differ outside"));
    }

    #[test]
    fn x64_native_pc_relative_field_can_change_but_opcode_and_other_bytes_cannot() {
        let body = [0xe8, 0, 0, 0, 0, 0xc3];
        let source = native_object(object::Architecture::X86_64, &body, Some((1, object::elf::R_X86_64_PC32)));
        let mut linked = body;
        linked[1..5].copy_from_slice(&0x10203040u32.to_le_bytes());
        assert!(collect_native(&source, &linked).is_ok());
        linked[0] = 0xe9;
        assert!(collect_native(&source, &linked).unwrap_err().contains("bytes differ outside"));
        linked[0] = 0xe8;
        linked[5] = 0x90;
        assert!(collect_native(&source, &linked).unwrap_err().contains("bytes differ outside"));
        let unknown = native_object(object::Architecture::X86_64, &body, Some((1, object::elf::R_X86_64_GOTPCREL)));
        assert!(collect_native(&unknown, &body).unwrap_err().contains("unsupported native ELF text relocation"));
    }

    #[test]
    fn native_instruction_relocations_preserve_a64_arm_and_thumb_opcode_bits() {
        use object::Architecture::{Aarch64, Arm};
        use object::elf::*;
        for (arch, typ, word, immediate, opcode) in [
            (Aarch64, R_AARCH64_CALL26, 0x94000000u32, 1u32, 1u32 << 31),
            (Aarch64, R_AARCH64_JUMP26, 0x14000000, 1, 1 << 31),
            (Aarch64, R_AARCH64_ADR_PREL_PG_HI21, 0x90000000, 1 << 29, 1 << 31),
            (Aarch64, R_AARCH64_ADD_ABS_LO12_NC, 0x91000000, 1 << 10, 1 << 22),
            (Aarch64, R_AARCH64_LDST64_ABS_LO12_NC, 0xf9400000, 1 << 10, 1 << 30),
            (Arm, R_ARM_THM_PC22, 0xf800f000, 1, 1 << 28),
            (Arm, R_ARM_THM_JUMP24, 0xb800f000, 1, 1 << 30),
            (Arm, R_ARM_CALL, 0xeb000000, 1, 1 << 24),
        ] {
            let source = native_object(arch, &word.to_le_bytes(), Some((0, typ)));
            let file = object::File::parse(source.as_slice()).unwrap();
            let section = file.section_by_name(".text.foo").unwrap();
            let fields = relocated_fields(&file, &section, &mut 0).unwrap();
            let bytes = section.data().unwrap();
            assert!(verify_function_bytes(bytes, 0, &(word ^ immediate).to_le_bytes(), &fields,
                &mut 1024, &mut 0).is_ok(), "{typ:?}");
            assert!(verify_function_bytes(bytes, 0, &(word ^ opcode).to_le_bytes(), &fields,
                &mut 1024, &mut 0).is_err(), "{typ:?}");
        }
    }

    #[test]
    fn scaled_a64_ldst_relocations_allow_only_low_address_bits_and_require_zero_high_bits() {
        use object::Architecture::Aarch64;
        use object::elf::*;
        for (typ, word, allowed, illegal) in [
            (R_AARCH64_LDST16_ABS_LO12_NC, 0x79400000u32, 0x001ffc00u32, 1u32 << 21),
            (R_AARCH64_LDST32_ABS_LO12_NC, 0xb9400000, 0x000ffc00, 1 << 20),
            (R_AARCH64_LDST64_ABS_LO12_NC, 0xf9400000, 0x0007fc00, 1 << 19),
            (R_AARCH64_LDST128_ABS_LO12_NC, 0x3dc00000, 0x0003fc00, 1 << 18),
        ] {
            let source = native_object(Aarch64, &word.to_le_bytes(), Some((0, typ)));
            let file = object::File::parse(source.as_slice()).unwrap();
            let section = file.section_by_name(".text.foo").unwrap();
            let fields = relocated_fields(&file, &section, &mut 0).unwrap();
            let bytes = section.data().unwrap();
            assert!(verify_function_bytes(bytes, 0, &(word | allowed).to_le_bytes(), &fields,
                &mut 1024, &mut 0).is_ok(), "{typ:?}");
            if typ == R_AARCH64_LDST64_ABS_LO12_NC {
                assert_eq!(word | illegal, 0xf9480000);
            }
            let error = verify_function_bytes(bytes, 0, &(word | illegal).to_le_bytes(), &fields,
                &mut 1024, &mut 0).unwrap_err();
            assert!(error.contains("fixed high immediate bits"), "{typ:?}: {error}");

            let invalid_word = word | illegal;
            let invalid_source = native_object(Aarch64, &invalid_word.to_le_bytes(), Some((0, typ)));
            let file = object::File::parse(invalid_source.as_slice()).unwrap();
            let section = file.section_by_name(".text.foo").unwrap();
            let fields = relocated_fields(&file, &section, &mut 0).unwrap();
            let error = verify_function_bytes(section.data().unwrap(), 0, &invalid_word.to_le_bytes(), &fields,
                &mut 1024, &mut 0).unwrap_err();
            assert!(error.contains("fixed high immediate bits"), "same invalid {typ:?}: {error}");
        }
    }

    #[test]
    fn a64_add_and_byte_load_relocations_keep_the_full_twelve_immediate_bits() {
        use object::elf::{R_AARCH64_ADD_ABS_LO12_NC, R_AARCH64_LDST8_ABS_LO12_NC};
        for (typ, word) in [(R_AARCH64_ADD_ABS_LO12_NC, 0x91000000u32),
            (R_AARCH64_LDST8_ABS_LO12_NC, 0x39400000)]
        {
            let source = native_object(object::Architecture::Aarch64, &word.to_le_bytes(), Some((0, typ)));
            let file = object::File::parse(source.as_slice()).unwrap();
            let section = file.section_by_name(".text.foo").unwrap();
            let fields = relocated_fields(&file, &section, &mut 0).unwrap();
            assert!(verify_function_bytes(section.data().unwrap(), 0, &(word | 0x003ffc00).to_le_bytes(), &fields,
                &mut 1024, &mut 0).is_ok(), "{typ:?}");
        }
    }

    #[test]
    fn fully_masked_functions_and_cross_boundary_relocations_refuse_ownership() {
        let source = native_object(object::Architecture::X86_64, &[0; 4], Some((0, object::elf::R_X86_64_32)));
        assert!(collect_native(&source, &[0; 4]).unwrap_err().contains("no immutable bits"));
        let source = native_object(object::Architecture::X86_64, &[0x90; 6], Some((4, object::elf::R_X86_64_PC32)));
        assert!(collect_native(&source, &[0x90; 6]).unwrap_err().contains("straddles producer function"));
    }

    // Hand-authored LLVM ELF table fixture, not a captured Zig/LLD invocation.
    fn map(input: &str) -> Vec<u8> {
        let header = "             VMA              LMA     Size Align Out     In      Symbol\n";
        let row = |size: &str, align: u64, payload: &str| {
            format!("{:>16} {:>16} {:>8} {:>5} {payload}\n", "201000", "201000", size, align)
        };
        format!(
            "{header}{}{}{}",
            row("20", 16, ".text"),
            row("10", 16, &format!("        {input}:(.text.foo)")),
            row("10", 1, "                demangled label()")
        )
        .into_bytes()
    }

    #[test]
    fn exact_archive_member_identity_not_basename_or_demangled_label() {
        let ids = BTreeMap::from([("/owned/lib.a(foo.o)".to_owned(), 0)]);
        let bytes = map("/owned/lib.a(foo.o)");
        let parsed = parse_map(&bytes, &ids, &mut 0).unwrap();
        assert_eq!(parsed[&(0, ".text.foo")].address, 0x201000);
        assert_eq!(parsed[&(0, ".text.foo")].size, 0x10);
        assert!(parse_map(&map("/dependency/lib.a(foo.o)"), &ids, &mut 0).unwrap().is_empty());
    }

    #[test]
    fn duplicate_kept_sections_and_extent_overflow_refuse_scope() {
        let ids = BTreeMap::from([("foo.o".to_owned(), 0)]);
        let mut bytes = map("foo.o");
        bytes.extend_from_slice(b"          201000           201000       10    16         foo.o:(.text.foo)\n");
        assert!(parse_map(&bytes, &ids, &mut 0).is_err());
        let overflow = String::from_utf8(map("foo.o")).unwrap().replace("201000", "fffffffffffffff8");
        assert!(parse_map(overflow.as_bytes(), &ids, &mut 0).is_err());
        let mut overlap = map("foo.o");
        overlap.extend_from_slice(b"          201000           201000       10    16         dependency.o:(.text)\n");
        assert!(parse_map(&overlap, &ids, &mut 0).is_err());
    }

    #[test]
    fn unsupported_grammar_paths_and_budgets_are_not_silently_accepted() {
        assert!(parse_map(b"Address Size Align Out In Symbol\n", &BTreeMap::new(), &mut 0).is_err());
        for path in ["/a b.o", "/a(b).o", "/a:b.o"] {
            assert!(identity(path).is_err());
        }
        let mut records = MAX_RECORDS;
        assert!(parse_map(&map("foo.o"), &BTreeMap::new(), &mut records).is_err());
        assert_eq!(column("\t\t"), 16);
    }

    fn archive(names: &[&str]) -> Vec<u8> {
        let mut bytes = b"!<arch>\n".to_vec();
        for name in names {
            let name = if matches!(*name, "/" | "//") { name.to_string() } else { format!("{name}/") };
            bytes.extend_from_slice(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 644, 4).as_bytes());
            bytes.extend_from_slice(b"body");
        }
        bytes
    }

    #[test]
    fn receipt_hash_ordinal_and_content_are_cross_checked_against_archive() {
        let bytes = archive(&["/", "//", "metadata", "owned.o"]);
        let hash = super::super::digest(&bytes);
        let object_hash = super::super::digest(b"body");
        let mut receipt = OwnedObject {
            archive_path: "/owned/lib.a",
            archive_sha256: &hash,
            archive_bytes: &bytes,
            member_ordinal: 1,
            original_name: "owned.o",
            object_path: "/owned/owned.o",
            object_sha256: &object_hash,
            object_bytes: b"body",
        };
        assert!(validate_receipts(std::slice::from_ref(&receipt), &mut 0).is_ok());
        receipt.member_ordinal = 0;
        assert!(validate_receipts(std::slice::from_ref(&receipt), &mut 0).is_err());
        receipt.member_ordinal = 1;
        receipt.object_bytes = b"evil";
        assert!(validate_receipts(std::slice::from_ref(&receipt), &mut 0).is_err());
        let evil_hash = super::super::digest(b"evil");
        receipt.object_sha256 = &evil_hash;
        assert!(validate_receipts(std::slice::from_ref(&receipt), &mut 0).is_err());
    }

    #[test]
    fn duplicate_archive_member_names_are_not_resolved_by_first_match() {
        let bytes = archive(&["same.o", "same.o"]);
        let receipt = OwnedObject {
            archive_path: "lib.a",
            archive_sha256: &super::super::digest(&bytes),
            archive_bytes: &bytes,
            member_ordinal: 0,
            original_name: "same.o",
            object_path: "same.o",
            object_sha256: &super::super::digest(b"body"),
            object_bytes: b"body",
        };
        assert!(validate_receipts(&[receipt], &mut 0).unwrap_err().contains("duplicate archive member"));
    }
}
