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
    pub tls_gd_to_le_policy: &'static str,
    pub tls_gd_to_le_verified_pairs: usize,
    pub tls_ld_to_le_policy: &'static str,
    pub tls_ld_to_le_verified_pairs: usize,
    pub tls_dtpoff32_verified_fields: usize,
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
    typ: object::elf::RelocationType,
    target: object::RelocationTarget,
    explicit_addend: Option<i64>,
}

struct StaticTls<'a> {
    base: u64,
    file_offset: u64,
    initialized_size: u64,
    memory_size: u64,
    block_size: u64,
    alignment: u64,
    symbols: BTreeMap<&'a str, (u64, u64, object::SectionIndex)>,
}

struct ObjectTlsContext<'object, 'data> {
    source: &'object object::File<'data>,
    input_sections: BTreeMap<usize, u64>,
}

fn static_tls_layout<'a>(file: &object::File<'a>, records: &mut usize) -> Result<StaticTls<'a>, String> {
    use object::read::elf::{Dyn, ProgramHeader};
    use object::elf::*;
    let object::File::Elf64(elf) = file else { return Err("TLS rewrite requires ELF64".into()); };
    if file.architecture() != object::Architecture::X86_64 || !file.is_little_endian() {
        return Err("TLS rewrite requires little-endian x86-64".into());
    }
    let endian = elf.endian();
    let mut tls = None;
    let mut pie = false;
    let mut dynamic_count = 0;
    for header in elf.elf_program_headers() {
        charge(records)?;
        if header.p_type(endian) == PT_INTERP { return Err("TLS rewrite refuses an ELF interpreter".into()); }
        if header.p_type(endian) == PT_TLS && tls.replace(header).is_some() {
            return Err("TLS rewrite requires exactly one PT_TLS".into());
        }
        if let Some(entries) = header.dynamic(endian, elf.data()).map_err(|error| error.to_string())? {
            dynamic_count += 1;
            if dynamic_count > 1 { return Err("ambiguous ELF dynamic segments for TLS rewrite".into()); }
            let mut terminated = false;
            let mut flags = None;
            for entry in entries {
                charge(records)?;
                let tag = entry.d_tag(endian);
                if tag == DT_NULL { terminated = true; break; }
                if matches!(tag, DT_NEEDED | DT_FILTER | DT_AUXILIARY) {
                    return Err("TLS rewrite refuses external dynamic modules".into());
                }
                if tag == DT_FLAGS_1 {
                    let value = entry.d_val(endian);
                    if flags.replace(value).is_some() { return Err("ambiguous static PIE flags".into()); }
                    pie = value & DF_1_PIE.0 != 0;
                }
            }
            if !terminated { return Err("unterminated ELF dynamic segment for TLS rewrite".into()); }
        }
    }
    if !matches!(file.kind(), object::ObjectKind::Executable)
        && !(file.kind() == object::ObjectKind::Dynamic && pie)
    {
        return Err("TLS rewrite requires static ET_EXEC or explicitly marked static PIE".into());
    }
    for symbol in file.dynamic_symbols() {
        charge(records)?;
        if !symbol.name_bytes().map_err(|error| error.to_string())?.is_empty() {
            return Err("TLS rewrite refuses externally visible dynamic symbols".into());
        }
    }
    let tls = tls.ok_or("TLS rewrite has no PT_TLS")?;
    let (base, offset, size, filesz, align) = (tls.p_vaddr(endian), tls.p_offset(endian),
        tls.p_memsz(endian), tls.p_filesz(endian), tls.p_align(endian));
    if align == 0 || !align.is_power_of_two() || base % align != 0 || offset % align != 0
        || size == 0 || size > MAX_BYTES as u64 || filesz > size
        || tls.data(endian, elf.data()).is_err()
    {
        return Err("unsupported PT_TLS size, alignment, first-byte placement or backing".into());
    }
    let end = extent(base, size)?;
    let file_end = extent(offset, filesz)?;
    let loads = elf.elf_program_headers().iter().filter(|header| {
        header.p_type(endian) == PT_LOAD && header.p_flags(endian).contains(PF_R | PF_W)
            && base >= header.p_vaddr(endian) && offset >= header.p_offset(endian)
            && base - header.p_vaddr(endian) == offset - header.p_offset(endian)
            && header.p_vaddr(endian).checked_add(header.p_memsz(endian)).is_some_and(|limit| end <= limit)
            && header.p_offset(endian).checked_add(header.p_filesz(endian)).is_some_and(|limit| file_end <= limit)
    }).count();
    if loads != 1 { return Err("PT_TLS does not have unique consistent writable PT_LOAD backing".into()); }
    let block_size = extent(size, align - 1)? & !(align - 1);
    let mut symbols = BTreeMap::new();
    for symbol in file.symbols() {
        charge(records)?;
        if matches!(symbol.flags(), object::SymbolFlags::Elf { st_info, .. } if st_info.st_type() == STT_TLS) {
            let name = symbol.name().map_err(|error| error.to_string())?;
            bounded_name(name)?;
            let section = symbol.section_index().ok_or("linked TLS symbol has no section")?;
            if symbols.insert(name, (symbol.address(), symbol.size(), section)).is_some() {
                return Err("ambiguous raw linked TLS symbol name".into());
            }
        }
    }
    Ok(StaticTls { base, file_offset: offset, initialized_size: filesz,
        memory_size: size, block_size, alignment: align, symbols })
}

enum ExactTlsBytes {
    GeneralDynamic([u8; 16]),
    LocalDynamicBase,
    LocalDynamicOffset([u8; 4]),
}

const TLS_LD_LOCAL_EXEC: [u8; 12] = [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0];

fn tls_symbol_value(
    context: &mut ObjectTlsContext<'_, '_>, linked_file: &object::File<'_>,
    layout: &StaticTls<'_>, field: &RelocatedField,
) -> Result<(u64, u64), String> {
    use object::elf::*;
    let source = context.source;
    let object::RelocationTarget::Symbol(tls_index) = field.target else {
        return Err("TLS relocation is not a native symbol index".into());
    };
    let symbol = source.symbol_by_index(tls_index).map_err(|error| error.to_string())?;
    if !matches!(symbol.flags(), object::SymbolFlags::Elf { st_info, .. } if st_info.st_type() == STT_TLS)
        || symbol.is_undefined() || symbol.is_weak() || symbol.size() == 0
    {
        return Err("TLS proof requires a defined nonweak native source STT_TLS symbol".into());
    }
    let name = symbol.name().map_err(|error| error.to_string())?;
    let &(value, size, section_index) = layout.symbols.get(name)
        .ok_or("raw source TLS name absent from linked TLS")?;
    let linked_section = linked_file.section_by_index(section_index).map_err(|error| error.to_string())?;
    let source_index = symbol.section_index().ok_or("source TLS has no section")?;
    let source_section = source.section_by_index(source_index)
        .map_err(|error| error.to_string())?;
    let tls_section = |section: &object::Section<'_, '_>| matches!(section.flags(),
        object::SectionFlags::Elf { sh_flags, sh_type } if sh_flags.contains(SHF_ALLOC | SHF_TLS)
            && matches!(sh_type, SHT_PROGBITS | SHT_NOBITS));
    let source_value = symbol.address().checked_sub(source_section.address()).ok_or("invalid source TLS value")?;
    let linked_value = extent(layout.base, value)?;
    if !tls_section(&source_section) || !tls_section(&linked_section) || size != symbol.size()
        || source_section.align() == 0 || !source_section.align().is_power_of_two()
        || linked_section.align() == 0 || !linked_section.align().is_power_of_two()
        || linked_section.align() > layout.alignment || linked_section.address() % linked_section.align() != 0
        || linked_section.address() < layout.base
        || extent(linked_section.address(), linked_section.size())? > extent(layout.base, layout.memory_size)?
        || extent(source_value, size)? > source_section.size() || extent(value, size)? > layout.memory_size
        || linked_value < linked_section.address()
        || extent(linked_value, size)? > extent(linked_section.address(), linked_section.size())?
    {
        return Err("source/linked TLS symbol type, size, section or PT_TLS range disagrees".into());
    }
    let input_base = linked_value.checked_sub(source_value).ok_or("source TLS input-section base underflow")?;
    let input_end = extent(input_base, source_section.size())?;
    if source_section.align() > layout.alignment || input_base % source_section.align() != 0
        || input_base < linked_section.address() || input_base < layout.base
        || input_end > extent(linked_section.address(), linked_section.size())?
        || input_end > extent(layout.base, layout.memory_size)?
    {
        return Err("derived source TLS input-section placement contradicts linked alignment or full range".into());
    }
    let object::SectionFlags::Elf { sh_type: source_type, .. } = source_section.flags() else {
        return Err("source TLS section has no native ELF storage type".into());
    };
    let object::SectionFlags::Elf { sh_type: linked_type, .. } = linked_section.flags() else {
        return Err("linked TLS section has no native ELF storage type".into());
    };
    if source_type != linked_type { return Err("source and linked TLS initialization classes disagree".into()); }
    let relative = linked_section.address().checked_sub(layout.base).ok_or("TLS section base underflow")?;
    if linked_type == SHT_PROGBITS {
        let expected_offset = extent(layout.file_offset, relative)?;
        if extent(relative, linked_section.size())? > layout.initialized_size
            || linked_section.file_range() != Some((expected_offset, linked_section.size()))
            || linked_section.data().map_err(|error| format!("TLS PROGBITS backing: {error}"))?.len() as u64
                != linked_section.size()
            || source_section.file_range().is_none_or(|(_, bytes)| bytes != source_section.size())
            || source_section.data().map_err(|error| format!("source TLS PROGBITS backing: {error}"))?.len() as u64
                != source_section.size()
        {
            return Err("TLS PROGBITS backing contradicts PT_TLS initialized bytes or actual file bounds".into());
        }
    } else if relative < layout.initialized_size || linked_section.file_range().is_some()
        || source_section.file_range().is_some()
    {
        return Err("TLS NOBITS overlaps initialized PT_TLS bytes or claims file backing".into());
    }
    // Per-object entries are bounded by the already-budgeted native source section inventory.
    match context.input_sections.entry(source_index.0) {
        std::collections::btree_map::Entry::Occupied(entry) if *entry.get() != input_base => {
            return Err("referenced symbols infer contradictory bases for one source TLS input section".into());
        }
        std::collections::btree_map::Entry::Vacant(entry) => { entry.insert(input_base); }
        _ => {}
    }
    Ok((value, size))
}

fn tls_rewrites(
    context: &mut ObjectTlsContext<'_, '_>, linked_file: &object::File<'_>, layout: &Result<StaticTls<'_>, String>,
    section: &[u8], offset: u64, linked: &[u8], fields: &[RelocatedField],
) -> Result<BTreeMap<u64, ExactTlsBytes>, String> {
    use object::elf::*;
    let source = context.source;
    const GD: [u8; 16] = [0x66, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0x66, 0x66, 0x48, 0xe8, 0, 0, 0, 0];
    const LE: [u8; 12] = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80];
    const LD: [u8; 12] = [0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0];
    let end = extent(offset, linked.len() as u64)?;
    let mut rewrites = BTreeMap::new();
    let first = fields.partition_point(|field| field.offset < offset);
    let last = fields.partition_point(|field| field.offset < end);
    let mut ld_pairs = 0;
    for (index, field) in fields.iter().enumerate().skip(first).take_while(|(_, field)| field.offset < end) {
        let local = field.typ == R_X86_64_TLSLD;
        if field.typ != R_X86_64_TLSGD && !local { continue; }
        let prefix = if local { 3 } else { 4 };
        let length = if local { 12 } else { 16 };
        let start = field.offset.checked_sub(prefix).ok_or("TLS pair prefix underflow")?;
        let Some(relative) = start.checked_sub(offset) else { continue; };
        let at = usize::try_from(relative).map_err(|_| "TLS pair offset overflow")?;
        if local {
            if linked.get(at..at + 12) != Some(TLS_LD_LOCAL_EXEC.as_slice()) {
                return Err("unsupported TLSLD linked opcode/register/padding sequence".into());
            }
        } else if linked.get(at..at + 12) != Some(LE.as_slice()) { continue; }
        if extent(start, length)? > end { return Err("TLS pair straddles producer function boundary".into()); }
        let model = if local { "TLSLD" } else { "TLSGD" };
        let layout = layout.as_ref().map_err(|error| format!("{model}-to-LE proof refused: {error}"))?;
        let first = usize::try_from(start).map_err(|_| "TLS source offset overflow")?;
        let template = if local { LD.as_slice() } else { GD.as_slice() };
        if section.get(first..first + length as usize) != Some(template) {
            return Err("noncanonical TLS source instruction/register sequence".into());
        }
        let call = fields.get(index + 1).ok_or("TLS rewrite lacks paired call relocation")?;
        if field.width != 4 || field.explicit_addend != Some(-4) || call.typ != R_X86_64_PLT32
            || call.offset != extent(field.offset, if local { 5 } else { 8 })?
            || call.width != 4 || call.explicit_addend != Some(-4)
            || index.checked_sub(1).is_some_and(|previous| {
                fields[previous].offset + fields[previous].width as u64 > start
            })
            || fields.get(index + 2).is_some_and(|next| next.offset < start + length)
        {
            return Err("TLS rewrite requires an isolated indexed TLS/PLT32 pair with explicit -4 addends".into());
        }
        let object::RelocationTarget::Symbol(call_index) = call.target else {
            return Err("TLS resolver relocation is not a native symbol index".into());
        };
        let resolver = source.symbol_by_index(call_index).map_err(|error| error.to_string())?;
        if resolver.name_bytes().map_err(|error| error.to_string())? != b"__tls_get_addr" || !resolver.is_undefined()
            || !resolver.is_global() || resolver.is_weak()
            || !matches!(resolver.flags(), object::SymbolFlags::Elf { st_info, .. }
                if matches!(st_info.st_type(), STT_FUNC | STT_NOTYPE))
        {
            return Err("TLS paired call does not reference exact undefined __tls_get_addr".into());
        }
        let (value, _) = tls_symbol_value(context, linked_file, layout, field)?;
        if local {
            rewrites.insert(field.offset, ExactTlsBytes::LocalDynamicBase);
            ld_pairs += 1;
            continue;
        }
        // Aligned main-module variant-II TLS occupies [-align_up(p_memsz, p_align), 0) relative to TP.
        let tpoff = i32::try_from(i128::from(value) - i128::from(layout.block_size))
            .map_err(|_| "variant-II TLS offset exceeds signed imm32")?;
        let mut expected = [0; 16];
        expected[..12].copy_from_slice(&LE);
        expected[12..].copy_from_slice(&tpoff.to_le_bytes());
        rewrites.insert(field.offset, ExactTlsBytes::GeneralDynamic(expected));
    }
    let has_dtp = fields[first..last].iter().any(|field| field.typ == R_X86_64_DTPOFF32);
    if ld_pairs > 0 && !has_dtp {
        return Err("TLSLD-to-LE requires DTPOFF32 fields in the same producer function".into());
    }
    for field in fields[first..last].iter().filter(|field| field.typ == R_X86_64_DTPOFF32) {
        if ld_pairs == 0 { return Err("DTPOFF32 has no proven TLSLD-to-LE frame in the producer function".into()); }
        if extent(field.offset, 4)? > end { return Err("DTPOFF32 straddles producer function boundary".into()); }
        let layout = layout.as_ref().map_err(|error| format!("DTPOFF32 proof refused: {error}"))?;
        let (value, size) = tls_symbol_value(context, linked_file, layout, field)?;
        let addend = field.explicit_addend.ok_or("DTPOFF32 requires an explicit native RELA addend")?;
        if addend < 0 || addend as u64 >= size { return Err("DTPOFF32 addend leaves native TLS symbol range".into()); }
        let at = usize::try_from(field.offset).map_err(|_| "DTPOFF32 source offset overflow")?;
        if section.get(at..at + 4) != Some([0; 4].as_slice()) {
            return Err("noncanonical DTPOFF32 RELA source field".into());
        }
        let value = i32::try_from(i128::from(value) + i128::from(addend) - i128::from(layout.block_size))
            .map_err(|_| "DTPOFF32 static TLS offset exceeds signed imm32")?;
        rewrites.insert(field.offset, ExactTlsBytes::LocalDynamicOffset(value.to_le_bytes()));
    }
    Ok(rewrites)
}

fn relocation_bits(arch: object::Architecture, typ: object::elf::RelocationType) -> Result<(usize, u64), String> {
    use object::Architecture::{Aarch64, Arm, I386, X86_64};
    use object::elf::*;
    let field = match (arch, typ) {
        (_, R_X86_64_NONE) => (0, 0),
        (X86_64, R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_32 | R_X86_64_32S
            | R_X86_64_GOTPCREL | R_X86_64_TLSGD | R_X86_64_TLSLD)
        | (I386, R_386_32 | R_386_PC32 | R_386_PLT32)
        | (Aarch64, R_AARCH64_ABS32 | R_AARCH64_PREL32)
        | (Arm, R_ARM_ABS32 | R_ARM_REL32 | R_ARM_ABS32_NOI | R_ARM_REL32_NOI) => (4, u32::MAX as u64),
        (X86_64, R_X86_64_64) | (Aarch64, R_AARCH64_ABS64) => (8, u64::MAX),
        (X86_64, R_X86_64_DTPOFF32) => (4, 0),
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
        let partial = matches!(source.architecture(), object::Architecture::Arm | object::Architecture::Aarch64)
            && width == 4 && bits != u32::MAX as u64;
        if partial && !source.is_little_endian() {
            return Err("big-endian ARM/AArch64 instruction relocations are unsupported".into());
        }
        let thumb = matches!(r_type, object::elf::R_ARM_THM_PC22 | object::elf::R_ARM_THM_JUMP24)
            && source.architecture() == object::Architecture::Arm;
        if partial && offset % (if thumb { 2 } else { 4 }) != 0 {
            return Err("unaligned native instruction relocation".into());
        }
        if source.architecture() == object::Architecture::X86_64 && r_type == object::elf::R_X86_64_TLSGD {
            let data = section.data().map_err(|error| error.to_string())?;
            let end = usize::try_from(offset).map_err(|_| "TLSGD relocation offset overflow")?;
            let start = end.checked_sub(4).ok_or("TLSGD relocation lacks canonical LEA prefix")?;
            if data.get(start..end) != Some([0x66, 0x48, 0x8d, 0x3d].as_slice()) {
                return Err("unsupported TLSGD encoding: expected 66 48 8d 3d followed by disp32".into());
            }
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
        fields.push(RelocatedField { offset, mask, required_zero, width, typ: r_type,
            target: relocation.target(),
            explicit_addend: (!relocation.has_implicit_addend()).then_some(relocation.addend()) });
    }
    fields.sort_unstable_by_key(|field| field.offset);
    if fields.windows(2).any(|pair| pair[0].offset + pair[0].width as u64 > pair[1].offset) {
        return Err("overlapping native text relocation fields are unsupported".into());
    }
    Ok(fields)
}

#[cfg(test)]
fn verify_function_bytes(
    section: &[u8], offset: u64, linked: &[u8], fields: &[RelocatedField],
    byte_budget: &mut usize, records: &mut usize,
) -> Result<(), String> {
    verify_function_binding(section, offset, linked, fields, byte_budget, records, &BTreeMap::new())
}

fn verify_function_binding(
    section: &[u8], offset: u64, linked: &[u8], fields: &[RelocatedField],
    byte_budget: &mut usize, records: &mut usize, rewrites: &BTreeMap<u64, ExactTlsBytes>,
) -> Result<(), String> {
    *byte_budget = byte_budget.checked_sub(linked.len()).ok_or("ownership byte-comparison budget exceeded")?;
    let end = extent(offset, linked.len() as u64)?;
    let start = usize::try_from(offset).map_err(|_| "source function offset overflow")?;
    let limit = usize::try_from(end).map_err(|_| "source function extent overflow")?;
    let source = section.get(start..limit).ok_or("source function is not file backed")?;
    let first = fields.partition_point(|field| field.offset + field.width as u64 <= offset);
    let mut cursor = 0;
    let mut immutable = false;
    let mismatch = |index: usize| format!(
        "owned function bytes differ outside native relocation bits at function offset {index:#x} \
         (producer={:#04x}, linked={:#04x}); opcode-changing relaxation is unsupported, including with --no-relax",
        source[index], linked[index],
    );
    let mut index = first;
    while let Some(field) = fields.get(index).filter(|field| field.offset < end) {
        charge(records)?;
        if let Some(proof) = rewrites.get(&field.offset) {
            let (prefix, consumed, expected) = match proof {
                ExactTlsBytes::GeneralDynamic(bytes) => (4, 2, bytes.as_slice()),
                ExactTlsBytes::LocalDynamicBase => (3, 2, TLS_LD_LOCAL_EXEC.as_slice()),
                ExactTlsBytes::LocalDynamicOffset(bytes) => (0, 1, bytes.as_slice()),
            };
            let at = usize::try_from(field.offset - prefix - offset).map_err(|_| "TLS pair range overflow")?;
            if let Some(difference) = source[cursor..at].iter().zip(&linked[cursor..at]).position(|(a, b)| a != b) {
                return Err(mismatch(cursor + difference));
            }
            if linked.get(at..at + expected.len()) != Some(expected) {
                return Err("TLS-to-LE linked bytes disagree with exact opcodes/registers or native TLS TPOFF".into());
            }
            immutable = true;
            cursor = at + expected.len();
            index += consumed;
            continue;
        }
        if matches!(field.typ, object::elf::R_X86_64_TLSLD | object::elf::R_X86_64_DTPOFF32) {
            return Err("TLSLD/DTPOFF32 field has no exact static TLS proof".into());
        }
        if field.offset < offset || extent(field.offset, field.width as u64)? > end {
            return Err("native relocation straddles producer function boundary".into());
        }
        let at = usize::try_from(field.offset - offset).map_err(|_| "function relocation offset overflow")?;
        if let Some(index) = source[cursor..at].iter().zip(&linked[cursor..at]).position(|(a, b)| a != b) {
            return Err(mismatch(cursor + index));
        }
        immutable |= at > cursor;
        for (index, (((before, after), mask), zero)) in source[at..at + field.width].iter()
            .zip(&linked[at..at + field.width]).zip(&field.mask[..field.width])
            .zip(&field.required_zero[..field.width]).enumerate()
        {
            if (*before | *after) & *zero != 0 {
                return Err("nonzero fixed high immediate bits in scaled AArch64 LDST LO12 relocation".into());
            }
            let keep = !*mask;
            immutable |= keep != 0;
            if (*before ^ *after) & keep != 0 { return Err(mismatch(at + index)); }
        }
        cursor = at + field.width;
        index += 1;
    }
    if let Some(index) = source[cursor..].iter().zip(&linked[cursor..]).position(|(a, b)| a != b) {
        return Err(mismatch(cursor + index));
    }
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
        tls_gd_to_le_policy: "canonical_x86_64_GD_PLT32_to_LE_aligned_static_variant_II_v1",
        tls_ld_to_le_policy: "canonical_x86_64_LD_PLT32_to_LE_exact_DTPOFF32_static_variant_II_v1",
        ..Default::default()
    };
    let mut byte_budget = 2 * MAX_BYTES;
    let tls_layout = static_tls_layout(&file, &mut records);
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
        let mut tls_context = ObjectTlsContext { source: &source, input_sections: BTreeMap::new() };
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
            let source_bytes = section.data().map_err(|error| error.to_string())?;
            let linked_bytes = linked.read(address, symbol.size()).ok_or("unbacked linked producer function")?;
            let fields = relocation_fields.get(&section_index.0).ok_or("missing checked section relocation fields")?;
            let rewrites = tls_rewrites(&mut tls_context, &file, &tls_layout,
                source_bytes, offset, linked_bytes, fields)?;
            verify_function_binding(
                source_bytes, offset, linked_bytes, fields, &mut byte_budget, &mut records, &rewrites,
            ).map_err(|error| format!("{name} at {address:#x}: {error}"))?;
            for proof in rewrites.values() {
                match proof {
                    ExactTlsBytes::GeneralDynamic(_) => result.tls_gd_to_le_verified_pairs += 1,
                    ExactTlsBytes::LocalDynamicBase => result.tls_ld_to_le_verified_pairs += 1,
                    ExactTlsBytes::LocalDynamicOffset(_) => result.tls_dtpoff32_verified_fields += 1,
                }
            }
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
        bytes.resize(body.len().max(16).next_multiple_of(16), 0x90);
        object.append_section_data(text, &bytes, 16);
        let symbol = object.add_symbol(object::write::Symbol {
            name: b"foo".to_vec(), value: 0, size: body.len() as u64, kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage, weak: true,
            section: object::write::SymbolSection::Section(text), flags: object::SymbolFlags::None,
        });
        if let Some((offset, r_type)) = relocation {
            let symbol = if matches!(r_type, object::elf::R_X86_64_TLSGD | object::elf::R_X86_64_TLSDESC)
                && arch == object::Architecture::X86_64
            {
                object.add_symbol(object::write::Symbol {
                    name: b"tls_variable".to_vec(), value: 0, size: 8, kind: object::SymbolKind::Tls,
                    scope: object::SymbolScope::Linkage, weak: false,
                    section: object::write::SymbolSection::Undefined, flags: object::SymbolFlags::None,
                })
            } else { symbol };
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
        let text_size = text.sh_size;
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
        segment.p_filesz = text_size;
        segment.p_memsz = text_size;
        segment.p_align = 0x1000;
        segment.sections.push(text_id);
        let mut bytes = Vec::new();
        image.write(&mut bytes).unwrap();
        bytes
    }

    fn collect_native(source: &[u8], linked_body: &[u8]) -> Result<OwnershipReceipt, String> {
        collect_native_image(source, &native_image(linked_body))
    }

    fn collect_native_image(source: &[u8], image: &[u8]) -> Result<OwnershipReceipt, String> {
        let files = fixture_support::TempFiles::new();
        let path = files.write("linked.elf", image);
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
        let object = object::File::parse(source).map_err(|error| error.to_string())?;
        let size = object.section_by_name(".text.foo").unwrap().size();
        let map = format!("             VMA              LMA     Size Align Out     In      Symbol\n\
            {:>16} {:>16} {:>8x} {:>5} .text\n{:>16} {:>16} {:>8x} {:>5}         lib.a(foo.o):(.text.foo)\n",
            "201000", "201000", size, 16, "201000", "201000", size, 16);
        linked_definitions(map.as_bytes(), &binary, &[receipt])
    }

    fn native_tls_source(gd_addend: i64, call_addend: Option<i64>, resolver: &[u8], target: &[u8]) -> Vec<u8> {
        native_tls_model_source(object::elf::R_X86_64_TLSGD, gd_addend, call_addend, resolver, target, None)
    }

    fn native_tls_model_source(
        model: object::elf::RelocationType, addend: i64, call_addend: Option<i64>,
        resolver: &[u8], target: &[u8], dtp_addend: Option<i64>,
    ) -> Vec<u8> {
        let mut object = object::write::Object::new(object::BinaryFormat::Elf,
            object::Architecture::X86_64, object::Endianness::Little);
        let text = object.add_section(Vec::new(), b".text.foo".to_vec(), object::SectionKind::Text);
        let local = model == object::elf::R_X86_64_TLSLD;
        let mut body = if local {
            vec![0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x48, 0x8b, 0x80, 0, 0, 0, 0, 0xc3]
        } else {
            vec![0x66, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0x66, 0x66, 0x48, 0xe8, 0, 0, 0, 0]
        };
        let function_size = body.len() as u64;
        body.resize(body.len().next_multiple_of(16), 0x90);
        object.append_section_data(text, &body, 16);
        object.add_symbol(object::write::Symbol {
            name: b"foo".to_vec(), value: 0, size: function_size, kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage, weak: false,
            section: object::write::SymbolSection::Section(text), flags: object::SymbolFlags::None,
        });
        let tls = object.add_section(Vec::new(), b".tbss.tls_variable".to_vec(), object::SectionKind::UninitializedTls);
        object.append_section_bss(tls, 8, 8);
        let variable = object.add_symbol(object::write::Symbol {
            name: target.to_vec(), value: 0, size: 8, kind: object::SymbolKind::Tls,
            scope: object::SymbolScope::Linkage, weak: false,
            section: object::write::SymbolSection::Section(tls), flags: object::SymbolFlags::None,
        });
        object.add_relocation(text, object::write::Relocation {
            offset: if local { 3 } else { 4 }, symbol: variable, addend,
            flags: object::RelocationFlags::Elf { r_type: model },
        }).unwrap();
        if let Some(addend) = call_addend {
            let resolver = object.add_symbol(object::write::Symbol {
                name: resolver.to_vec(), value: 0, size: 0, kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage, weak: false,
                section: object::write::SymbolSection::Undefined, flags: object::SymbolFlags::None,
            });
            object.add_relocation(text, object::write::Relocation {
                offset: if local { 8 } else { 12 }, symbol: resolver, addend,
                flags: object::RelocationFlags::Elf { r_type: object::elf::R_X86_64_PLT32 },
            }).unwrap();
        }
        if let Some(addend) = dtp_addend {
            object.add_relocation(text, object::write::Relocation {
                offset: 15, symbol: variable, addend,
                flags: object::RelocationFlags::Elf { r_type: object::elf::R_X86_64_DTPOFF32 },
            }).unwrap();
        }
        object.write().unwrap()
    }

    fn native_tls_image(body: &[u8], alter: impl FnOnce(&mut object::build::elf::Builder<'_>)) -> Vec<u8> {
        use object::elf::*;
        let plain = native_image(body);
        let mut image = object::build::elf::Builder::read(plain.as_slice()).unwrap();
        let file_offset = image.sections.iter().filter(|section| section.sh_flags.contains(SHF_EXECINSTR))
            .map(|section| section.sh_offset + section.sh_size).max().unwrap();
        let section = image.sections.add();
        section.name = b".tbss".as_slice().into();
        section.sh_type = SHT_NOBITS;
        section.sh_flags = SHF_ALLOC | SHF_WRITE | SHF_TLS;
        section.sh_addr = 0x202000;
        section.sh_offset = file_offset;
        section.sh_size = 0xa0;
        section.sh_addralign = 8;
        section.data = object::build::elf::SectionData::UninitializedData(0xa0);
        let id = section.id();
        let symbol = image.symbols.add();
        symbol.name = b"tls_variable".as_slice().into();
        symbol.set_st_info(STB_GLOBAL, STT_TLS);
        symbol.section = Some(id);
        symbol.st_value = 0x28;
        symbol.st_size = 8;
        for typ in [PT_LOAD, PT_TLS] {
            let segment = image.segments.add();
            segment.p_type = typ;
            segment.p_flags = if typ == PT_LOAD { PF_R | PF_W } else { PF_R };
            segment.p_offset = file_offset;
            segment.p_vaddr = 0x202000;
            segment.p_paddr = 0x202000;
            segment.p_memsz = 0xa0;
            segment.p_align = 8;
            segment.sections.push(id);
        }
        alter(&mut image);
        let mut bytes = Vec::new();
        image.write(&mut bytes).unwrap();
        bytes
    }

    fn probe_native_tls_target(source: &[u8], image: &[u8]) -> Result<(u64, u64), String> {
        let source = object::File::parse(source).map_err(|error| error.to_string())?;
        let linked = object::File::parse(image).map_err(|error| error.to_string())?;
        let section = source.section_by_name(".text.foo").ok_or("missing fixture code")?;
        let mut records = 0;
        let fields = relocated_fields(&source, &section, &mut records)?;
        let layout = static_tls_layout(&linked, &mut records)?;
        let mut context = ObjectTlsContext { source: &source, input_sections: BTreeMap::new() };
        tls_symbol_value(&mut context, &linked, &layout, &fields[0])
    }

    fn initialized_tls_fixture(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use object::build::elf::{Builder, SectionData};
        use object::elf::*;
        let original = native_tls_source(-4, Some(-4), b"__tls_get_addr", b"tls_variable");
        let mut source = Builder::read(original.as_slice()).unwrap();
        let id = source.symbols.iter().find(|symbol| symbol.name.as_slice() == b"tls_variable")
            .unwrap().section.unwrap();
        let section = source.sections.get_mut(id);
        section.name = b".tdata.tls_variable".as_slice().into();
        section.sh_type = SHT_PROGBITS;
        section.data = SectionData::Data(vec![0; 8].into());
        let mut bytes = Vec::new();
        source.write(&mut bytes).unwrap();
        let image = native_tls_image(body, |image| {
            let section = image.sections.iter_mut().find(|section| section.name.as_slice() == b".tbss").unwrap();
            section.name = b".tdata".as_slice().into();
            section.sh_type = SHT_PROGBITS;
            section.data = SectionData::Data(vec![0; 0xa0].into());
            for segment in image.segments.iter_mut().filter(|segment| {
                segment.p_type == PT_TLS || segment.p_type == PT_LOAD && segment.p_flags.contains(PF_W)
            }) {
                segment.p_filesz = 0xa0;
            }
        });
        (bytes, image)
    }

    fn mutate_tls_section_offset(image: &[u8], value: u64) -> Vec<u8> {
        let parsed = object::File::parse(image).unwrap();
        let section = parsed.section_by_name(".tdata").unwrap().index().0;
        let table = u64::from_le_bytes(image[40..48].try_into().unwrap()) as usize;
        let entry = u16::from_le_bytes(image[58..60].try_into().unwrap()) as usize;
        let offset = table + section * entry + 24;
        let mut bytes = image.to_vec();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    fn shared_tls_sources(split_objects: bool) -> Vec<Vec<u8>> {
        let groups = if split_objects { vec![vec![0], vec![1]] } else { vec![vec![0, 1]] };
        groups.into_iter().map(|group| {
            let mut object = object::write::Object::new(object::BinaryFormat::Elf,
                object::Architecture::X86_64, object::Endianness::Little);
            let tls = object.add_section(Vec::new(), b".tbss.shared".to_vec(), object::SectionKind::UninitializedTls);
            object.append_section_bss(tls, group.len() as u64 * 8, 8);
            let resolver = object.add_symbol(object::write::Symbol {
                name: b"__tls_get_addr".to_vec(), value: 0, size: 0, kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage, weak: false,
                section: object::write::SymbolSection::Undefined, flags: object::SymbolFlags::None,
            });
            for (offset, member) in group.into_iter().enumerate() {
                let suffix = if member == 0 { "a" } else { "b" };
                let variable = object.add_symbol(object::write::Symbol {
                    name: format!("tls_{suffix}").into_bytes(), value: offset as u64 * 8, size: 8,
                    kind: object::SymbolKind::Tls, scope: object::SymbolScope::Linkage, weak: false,
                    section: object::write::SymbolSection::Section(tls), flags: object::SymbolFlags::None,
                });
                let text = object.add_section(Vec::new(), format!(".text.foo_{suffix}").into_bytes(),
                    object::SectionKind::Text);
                object.append_section_data(text,
                    &[0x66, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0x66, 0x66, 0x48, 0xe8, 0, 0, 0, 0], 16);
                object.add_symbol(object::write::Symbol {
                    name: format!("foo_{suffix}").into_bytes(), value: 0, size: 16, kind: object::SymbolKind::Text,
                    scope: object::SymbolScope::Linkage, weak: false,
                    section: object::write::SymbolSection::Section(text), flags: object::SymbolFlags::None,
                });
                for (offset, symbol, r_type) in [(4, variable, object::elf::R_X86_64_TLSGD),
                    (12, resolver, object::elf::R_X86_64_PLT32)]
                {
                    object.add_relocation(text, object::write::Relocation {
                        offset, symbol, addend: -4, flags: object::RelocationFlags::Elf { r_type },
                    }).unwrap();
                }
            }
            object.write().unwrap()
        }).collect()
    }

    fn shared_tls_image(values: [u64; 2], tls_base: u64) -> Vec<u8> {
        use object::elf::*;
        let mut body = Vec::new();
        for value in values {
            body.extend_from_slice(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80]);
            body.extend_from_slice(&(value as i32 - 0xa0).to_le_bytes());
        }
        native_tls_image(&body, |image| {
            let text = image.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"foo").unwrap();
            let text_id = text.section;
            text.name = b"foo_a".as_slice().into();
            text.st_size = 16;
            text.set_st_info(STB_GLOBAL, STT_FUNC);
            let second = image.symbols.add();
            second.name = b"foo_b".as_slice().into();
            second.section = text_id;
            second.st_value = 0x201010;
            second.st_size = 16;
            second.set_st_info(STB_GLOBAL, STT_FUNC);
            let first = image.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap();
            let tls_id = first.section;
            first.name = b"tls_a".as_slice().into();
            first.st_value = values[0];
            let second = image.symbols.add();
            second.name = b"tls_b".as_slice().into();
            second.section = tls_id;
            second.st_value = values[1];
            second.st_size = 8;
            second.set_st_info(STB_GLOBAL, STT_TLS);
            image.sections.get_mut(tls_id.unwrap()).sh_addr = tls_base;
            for segment in image.segments.iter_mut().filter(|segment| {
                segment.p_type == PT_TLS || segment.p_type == PT_LOAD && segment.p_flags.contains(PF_W)
            }) {
                segment.p_vaddr = tls_base;
                segment.p_paddr = tls_base;
            }
        })
    }

    fn collect_shared_tls(sources: &[Vec<u8>], image: &[u8]) -> Result<OwnershipReceipt, String> {
        let files = fixture_support::TempFiles::new();
        let path = files.write("shared.elf", image);
        let binary = Binary::open(path).map_err(|error| error.to_string())?;
        let mut archive = b"!<arch>\n".to_vec();
        for (index, source) in sources.iter().enumerate() {
            archive.extend_from_slice(format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                format!("{index}.o/"), 0, 0, 0, 644, source.len()).as_bytes());
            archive.extend_from_slice(source);
            if source.len() % 2 != 0 { archive.push(b'\n'); }
        }
        let archive_hash = super::super::digest(&archive);
        let object_hashes: Vec<_> = sources.iter().map(|bytes| super::super::digest(bytes)).collect();
        let paths: Vec<_> = (0..sources.len()).map(|index| format!("object{index}.o")).collect();
        let names: Vec<_> = (0..sources.len()).map(|index| format!("{index}.o")).collect();
        let receipts: Vec<_> = sources.iter().enumerate().map(|(index, source)| OwnedObject {
            archive_path: "shared.a", archive_sha256: &archive_hash, archive_bytes: &archive,
            member_ordinal: index, original_name: &names[index], object_path: &paths[index],
            object_sha256: &object_hashes[index], object_bytes: source,
        }).collect();
        let mut map = String::from("             VMA              LMA     Size Align Out     In      Symbol\n");
        map.push_str(&format!("{:>16x} {:>16x} {:>8x} {:>5} .text\n", 0x201000, 0x201000, 32, 16));
        for (member, suffix) in ["a", "b"].into_iter().enumerate() {
            let address = 0x201000 + member * 16;
            let object = if sources.len() == 1 { 0 } else { member };
            map.push_str(&format!("{address:>16x} {address:>16x} {:>8x} {:>5}         {}:(.text.foo_{suffix})\n",
                16, 16, paths[object]));
        }
        linked_definitions(map.as_bytes(), &binary, &receipts)
    }

    #[test]
    fn tls_input_section_placement_is_shared_across_different_text_functions() {
        let sources = shared_tls_sources(false);
        let error = collect_shared_tls(&sources, &shared_tls_image([0x28, 0x40], 0x202000)).unwrap_err();
        assert!(error.contains("contradictory bases for one source TLS input section"), "{error}");
        let receipt = collect_shared_tls(&sources, &shared_tls_image([0x28, 0x30], 0x202000)).unwrap();
        assert_eq!(receipt.definitions.len(), 2);
        assert_eq!(receipt.tls_gd_to_le_verified_pairs, 2);
    }

    #[test]
    fn tls_input_section_placements_are_independent_between_objects_and_role_collections() {
        let split = shared_tls_sources(true);
        let first = object::File::parse(split[0].as_slice()).unwrap();
        let second = object::File::parse(split[1].as_slice()).unwrap();
        assert_eq!(first.section_by_name(".tbss.shared").unwrap().index(),
            second.section_by_name(".tbss.shared").unwrap().index());
        let receipt = collect_shared_tls(&split, &shared_tls_image([0x28, 0x40], 0x202000)).unwrap();
        assert_eq!(receipt.definitions.len(), 2);
        let shared = shared_tls_sources(false);
        let reference = collect_shared_tls(&shared, &shared_tls_image([0x28, 0x30], 0x202000)).unwrap();
        let target = collect_shared_tls(&shared, &shared_tls_image([0x28, 0x30], 0x203000)).unwrap();
        assert_eq!(reference.definitions.len(), 2);
        assert_eq!(target.definitions.len(), 2);
    }

    #[test]
    fn tls_input_section_alignment_uses_the_source_symbol_offset_and_full_placement() {
        use object::build::elf::{Builder, SectionData};
        use object::elf::*;
        let original = native_tls_source(-4, Some(-4), b"__tls_get_addr", b"tls_variable");
        let local = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0x88, 0xff, 0xff, 0xff];
        let image = native_tls_image(&local, |_| {});
        let mut source = Builder::read(original.as_slice()).unwrap();
        let variable = source.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap();
        let id = variable.section.unwrap();
        source.sections.get_mut(id).sh_addralign = 16;
        let mut mutated = Vec::new();
        source.write(&mut mutated).unwrap();
        let error = collect_native_image(&mutated, &image).unwrap_err();
        assert!(error.contains("derived source TLS input-section placement"), "{error}");

        let mut source = Builder::read(original.as_slice()).unwrap();
        source.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap().st_value = 8;
        let section = source.sections.get_mut(id);
        section.sh_addralign = 16;
        section.sh_size = 16;
        section.data = SectionData::UninitializedData(16);
        let mut valid = Vec::new();
        source.write(&mut valid).unwrap();
        let image = native_tls_image(&local, |image| {
            image.sections.iter_mut().find(|section| section.name.as_slice() == b".tbss").unwrap().sh_addralign = 16;
            image.segments.iter_mut().find(|segment| segment.p_type == PT_TLS).unwrap().p_align = 16;
        });
        let receipt = collect_native_image(&valid, &image).unwrap();
        assert_eq!(receipt.tls_gd_to_le_verified_pairs, 1);

        let mut source = Builder::read(original.as_slice()).unwrap();
        let section = source.sections.get_mut(id);
        section.sh_size = 0x100;
        section.data = SectionData::UninitializedData(0x100);
        let mut too_large = Vec::new();
        source.write(&mut too_large).unwrap();
        assert!(probe_native_tls_target(&too_large, &image).unwrap_err()
            .contains("derived source TLS input-section placement"));
    }

    #[test]
    fn initialized_tls_sections_must_match_pt_tls_file_offsets_and_initialized_extent() {
        use object::build::elf::Builder;
        use object::elf::*;
        let local = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0x88, 0xff, 0xff, 0xff];
        let (source, image) = initialized_tls_fixture(&local);
        assert_eq!(collect_native_image(&source, &image).unwrap().tls_gd_to_le_verified_pairs, 1);
        for offset in [0x1000, image.len() as u64 - 4] {
            let wrong = mutate_tls_section_offset(&image, offset);
            let error = probe_native_tls_target(&source, &wrong).unwrap_err();
            assert!(error.contains("TLS PROGBITS backing"), "{error}");
        }
        let mut truncated_initializer = Builder::read(image.as_slice()).unwrap();
        truncated_initializer.segments.iter_mut().find(|segment| segment.p_type == PT_TLS).unwrap().p_filesz = 8;
        let mut wrong = Vec::new();
        truncated_initializer.write(&mut wrong).unwrap();
        assert!(probe_native_tls_target(&source, &wrong).unwrap_err().contains("TLS PROGBITS backing"));
    }

    #[test]
    fn nobits_tls_is_explicit_zero_fill_not_readable_file_data() {
        use object::elf::*;
        let source = native_tls_source(-4, Some(-4), b"__tls_get_addr", b"tls_variable");
        let local = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0x88, 0xff, 0xff, 0xff];
        assert!(collect_native_image(&source, &native_tls_image(&local, |_| {})).is_ok());
        let zero_tail = native_tls_image(&local, |image| {
            let section = image.sections.iter_mut().find(|section| section.name.as_slice() == b".tbss").unwrap();
            section.sh_addr += 16;
            section.sh_size -= 16;
            section.data = object::build::elf::SectionData::UninitializedData(0x90);
            for segment in image.segments.iter_mut().filter(|segment| {
                segment.p_type == PT_TLS || segment.p_type == PT_LOAD && segment.p_flags.contains(PF_W)
            }) {
                segment.p_filesz = 8;
            }
        });
        assert!(collect_native_image(&source, &zero_tail).is_ok());
        let initialized_overlap = native_tls_image(&local, |image| {
            for segment in image.segments.iter_mut().filter(|segment| {
                segment.p_type == PT_TLS || segment.p_type == PT_LOAD && segment.p_flags.contains(PF_W)
            }) {
                segment.p_filesz = 8;
            }
        });
        assert!(probe_native_tls_target(&source, &initialized_overlap).unwrap_err().contains("TLS NOBITS"));
        let (initialized_source, _) = initialized_tls_fixture(&local);
        assert!(probe_native_tls_target(&initialized_source, &zero_tail).unwrap_err()
            .contains("initialization classes disagree"));
    }

    #[test]
    fn canonical_tls_gd_to_le_is_bound_to_native_tls_symbol_and_variant_ii_layout() {
        let source = native_tls_source(-4, Some(-4), b"__tls_get_addr", b"tls_variable");
        let local = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0x88, 0xff, 0xff, 0xff];
        let receipt = collect_native_image(&source, &native_tls_image(&local, |_| {})).unwrap();
        assert_eq!(receipt.tls_gd_to_le_verified_pairs, 1);
        for position in [0, 2, 3, 9, 11, 12, 15] {
            let mut wrong = local;
            wrong[position] ^= 1;
            assert!(collect_native_image(&source, &native_tls_image(&wrong, |_| {})).is_err(), "byte {position}");
        }
        for (gd, call, resolver, variable) in [
            (0, Some(-4), b"__tls_get_addr".as_slice(), b"tls_variable".as_slice()),
            (-4, Some(0), b"__tls_get_addr", b"tls_variable"),
            (-4, None, b"__tls_get_addr", b"tls_variable"),
            (-4, Some(-4), b"wrong_resolver", b"tls_variable"),
            (-4, Some(-4), b"__tls_get_addr", b"wrong_variable"),
        ] {
            let source = native_tls_source(gd, call, resolver, variable);
            assert!(collect_native_image(&source, &native_tls_image(&local, |_| {})).is_err());
        }
        let wrong_size = native_tls_image(&local, |image| {
            image.segments.iter_mut().find(|segment| segment.p_type == object::elf::PT_TLS).unwrap().p_memsz = 0x98;
        });
        assert!(collect_native_image(&source, &wrong_size).is_err());
        let wrong_align = native_tls_image(&local, |image| {
            image.segments.iter_mut().find(|segment| segment.p_type == object::elf::PT_TLS).unwrap().p_align = 3;
        });
        assert!(collect_native_image(&source, &wrong_align).is_err());
        let wrong_symbol = native_tls_image(&local, |image| {
            image.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap().st_value = 0x30;
        });
        assert!(collect_native_image(&source, &wrong_symbol).is_err());
        let dynamic = native_tls_image(&local, |image| { image.header.e_type = object::elf::ET_DYN; });
        assert!(collect_native_image(&source, &dynamic).is_err());
        let duplicate_tls = native_tls_image(&local, |image| { image.segments.add().p_type = object::elf::PT_TLS; });
        assert!(collect_native_image(&source, &duplicate_tls).is_err());

        let mut short_source = object::build::elf::Builder::read(source.as_slice()).unwrap();
        short_source.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"foo").unwrap().st_size = 13;
        let mut short_bytes = Vec::new();
        short_source.write(&mut short_bytes).unwrap();
        let error = collect_native_image(&short_bytes, &native_tls_image(&local[..13], |_| {})).unwrap_err();
        assert!(error.contains("straddles producer function"), "{error}");

        let mut overlapping = object::build::elf::Builder::read(source.as_slice()).unwrap();
        for section in &mut overlapping.sections {
            if let object::build::elf::SectionData::Relocation(relocations) = &mut section.data {
                let mut prefix = relocations[0];
                prefix.r_offset = 0;
                prefix.r_type = object::elf::R_X86_64_PC32;
                relocations.push(prefix);
            }
        }
        let mut overlap_bytes = Vec::new();
        overlapping.write(&mut overlap_bytes).unwrap();
        let error = collect_native_image(&overlap_bytes, &native_tls_image(&local, |_| {})).unwrap_err();
        assert!(error.contains("isolated indexed TLS/PLT32 pair"), "{error}");
    }

    #[test]
    fn canonical_tls_ld_to_le_binds_module_base_and_each_dtpoff32_field_exactly() {
        use object::elf::*;
        let source = native_tls_model_source(R_X86_64_TLSLD, -4, Some(-4),
            b"__tls_get_addr", b"tls_variable", Some(0));
        let local = [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
            0x48, 0x8b, 0x80, 0x88, 0xff, 0xff, 0xff, 0xc3];
        let image = native_tls_image(&local, |_| {});
        let receipt = collect_native_image(&source, &image).unwrap();
        assert_eq!(receipt.tls_gd_to_le_verified_pairs, 0);
        assert_eq!(receipt.tls_ld_to_le_verified_pairs, 1);
        assert_eq!(receipt.tls_dtpoff32_verified_fields, 1);
        for position in [0, 3, 5, 6, 7, 8, 11, 12, 13, 14, 15, 18, 19] {
            let mut wrong = local;
            wrong[position] ^= 1;
            assert!(collect_native_image(&source, &native_tls_image(&wrong, |_| {})).is_err(), "byte {position}");
        }
        for (ld, call, dtp, resolver, variable) in [
            (0, Some(-4), Some(0), b"__tls_get_addr".as_slice(), b"tls_variable".as_slice()),
            (-4, Some(0), Some(0), b"__tls_get_addr", b"tls_variable"),
            (-4, None, Some(0), b"__tls_get_addr", b"tls_variable"),
            (-4, Some(-4), None, b"__tls_get_addr", b"tls_variable"),
            (-4, Some(-4), Some(-1), b"__tls_get_addr", b"tls_variable"),
            (-4, Some(-4), Some(8), b"__tls_get_addr", b"tls_variable"),
            (-4, Some(-4), Some(0), b"wrong_resolver", b"tls_variable"),
            (-4, Some(-4), Some(0), b"__tls_get_addr", b"wrong_variable"),
        ] {
            let source = native_tls_model_source(R_X86_64_TLSLD, ld, call, resolver, variable, dtp);
            assert!(collect_native_image(&source, &image).is_err());
        }
        let parsed = object::File::parse(source.as_slice()).unwrap();
        let (text_offset, _) = parsed.section_by_name(".text.foo").unwrap().file_range().unwrap();
        let mut wrong_source = source.clone();
        wrong_source[text_offset as usize] ^= 1;
        assert!(collect_native_image(&wrong_source, &image).unwrap_err().contains("noncanonical TLS source"));
        let mut wrong_source = source.clone();
        wrong_source[text_offset as usize + 15] = 1;
        assert!(collect_native_image(&wrong_source, &image).unwrap_err().contains("noncanonical DTPOFF32"));

        let wrong_segment = native_tls_image(&local, |image| {
            image.segments.iter_mut().find(|segment| segment.p_type == PT_TLS).unwrap().p_memsz = 0x98;
        });
        assert!(collect_native_image(&source, &wrong_segment).is_err());
        let wrong_value = native_tls_image(&local, |image| {
            image.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap().st_value = 0x30;
        });
        assert!(collect_native_image(&source, &wrong_value).is_err());

        let mut wrong_target = object::build::elf::Builder::read(source.as_slice()).unwrap();
        let foo = wrong_target.symbols.iter().find(|symbol| symbol.name.as_slice() == b"foo").unwrap().id();
        for section in &mut wrong_target.sections {
            if let object::build::elf::SectionData::Relocation(relocations) = &mut section.data {
                for relocation in relocations.iter_mut().filter(|relocation| relocation.r_type == R_X86_64_DTPOFF32) {
                    relocation.symbol = Some(foo);
                }
            }
        }
        let mut bytes = Vec::new();
        wrong_target.write(&mut bytes).unwrap();
        assert!(collect_native_image(&bytes, &image).unwrap_err().contains("native source STT_TLS"));

        let mut short = object::build::elf::Builder::read(source.as_slice()).unwrap();
        short.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"foo").unwrap().st_size = 18;
        let mut bytes = Vec::new();
        short.write(&mut bytes).unwrap();
        assert!(collect_native_image(&bytes, &native_tls_image(&local[..18], |_| {})).unwrap_err()
            .contains("DTPOFF32 straddles producer function"));

        let mut missing_ld = object::build::elf::Builder::read(source.as_slice()).unwrap();
        for section in &mut missing_ld.sections {
            if let object::build::elf::SectionData::Relocation(relocations) = &mut section.data {
                relocations.retain(|relocation| relocation.r_type != R_X86_64_TLSLD);
            }
        }
        let mut bytes = Vec::new();
        missing_ld.write(&mut bytes).unwrap();
        assert!(collect_native_image(&bytes, &image).unwrap_err().contains("no proven TLSLD-to-LE frame"));
    }

    #[test]
    fn dtpoff32_subobject_addend_is_computed_from_its_native_symbol_and_checked_range() {
        use object::build::elf::{Builder, SectionData};
        use object::elf::*;
        let original = native_tls_model_source(R_X86_64_TLSLD, -4, Some(-4),
            b"__tls_get_addr", b"tls_variable", Some(8));
        let mut source = Builder::read(original.as_slice()).unwrap();
        let variable = source.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap();
        variable.st_size = 16;
        let id = variable.section.unwrap();
        let section = source.sections.get_mut(id);
        section.sh_size = 16;
        section.data = SectionData::UninitializedData(16);
        let mut bytes = Vec::new();
        source.write(&mut bytes).unwrap();
        let local = [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
            0x48, 0x8b, 0x80, 0x90, 0xff, 0xff, 0xff, 0xc3];
        let image = native_tls_image(&local, |image| {
            image.symbols.iter_mut().find(|symbol| symbol.name.as_slice() == b"tls_variable").unwrap().st_size = 16;
        });
        let receipt = collect_native_image(&bytes, &image).unwrap();
        assert_eq!(receipt.tls_dtpoff32_verified_fields, 1);
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
        let unknown = native_object(object::Architecture::X86_64, &body, Some((1, object::elf::R_X86_64_TLSDESC)));
        assert!(collect_native(&unknown, &body).unwrap_err().contains("unsupported native ELF text relocation"));
    }

    #[test]
    fn x64_got_pc_relative_displacement_does_not_mask_the_load_opcode() {
        let body = [0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3];
        let source = native_object(object::Architecture::X86_64, &body, Some((3, object::elf::R_X86_64_GOTPCREL)));
        let mut linked = body;
        linked[3..7].copy_from_slice(&0x10203040u32.to_le_bytes());
        assert!(collect_native(&source, &linked).is_ok());
        linked[1] = 0x8d;
        assert!(collect_native(&source, &linked).unwrap_err().contains("bytes differ outside"));
        linked[1] = 0x8b;
        linked[7] = 0x90;
        assert!(collect_native(&source, &linked).unwrap_err().contains("bytes differ outside"));
    }

    #[test]
    fn x64_tlsgd_masks_only_the_canonical_lea_displacement() {
        let body = [0x66, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xc3];
        let source = native_object(object::Architecture::X86_64, &body, Some((4, object::elf::R_X86_64_TLSGD)));
        let mut linked = body;
        linked[4..8].copy_from_slice(&0x10203040u32.to_le_bytes());
        assert!(collect_native(&source, &linked).is_ok());
        linked[2] = 0x8b;
        let error = collect_native(&source, &linked).unwrap_err();
        assert!(error.contains("function offset 0x2"), "{error}");
        linked[2] = 0x8d;
        linked[8] = 0x90;
        assert!(collect_native(&source, &linked).unwrap_err().contains("function offset 0x8"));

        let mut invalid = body;
        invalid[2] = 0x8b;
        let source = native_object(object::Architecture::X86_64, &invalid, Some((4, object::elf::R_X86_64_TLSGD)));
        assert!(collect_native(&source, &invalid).unwrap_err().contains("unsupported TLSGD encoding"));
    }

    #[test]
    fn x64_tlsgd_to_local_exec_without_static_tls_metadata_is_refused() {
        let general_dynamic = [0x66, 0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0x66, 0x66, 0x48, 0xe8, 0, 0, 0, 0];
        let local_exec = [0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0x88, 0xff, 0xff, 0xff];
        let source = native_object(object::Architecture::X86_64, &general_dynamic,
            Some((4, object::elf::R_X86_64_TLSGD)));
        let error = collect_native(&source, &local_exec).unwrap_err();
        assert!(error.contains("TLSGD-to-LE proof refused"), "{error}");
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
