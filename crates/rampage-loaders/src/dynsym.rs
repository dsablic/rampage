//! The dynamic symbol table, dynamic relocations and constructor arrays of an ELF file, read the way the dynamic
//! linker finds them: through the program headers and `PT_DYNAMIC`, never the section headers. Router firmware
//! ships programs with their section headers removed (OpenWrt's `sstrip`), so this is the only route to their
//! exports and imports there.
//!
//! The file is hostile input. Every address is mapped to file bytes through the file-backed part of one `PT_LOAD`
//! segment, every size and count is checked arithmetic, and counts are capped both by fixed limits and by the bytes
//! actually present. A malformed table gives fewer entries and a warning, never a panic or an unbounded loop.

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_RELENT: u64 = 19;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_PREINIT_ARRAY: u64 = 32;
const DT_PREINIT_ARRAYSZ: u64 = 33;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_MIPS_SYMTABNO: u64 = 0x7000_0011;

const EM_MIPS: u16 = 8;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_ABS: u16 = 0xfff1;
const SHN_XINDEX: u16 = 0xffff;
pub(crate) const STT_OBJECT: u8 = 1;
pub(crate) const STT_FUNC: u8 = 2;
const STT_NOTYPE: u8 = 0;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;
const STB_LOCAL: u8 = 0;

/// Most program headers read; `e_phnum` is 16 bits anyway.
const MAX_PROGRAM_HEADERS: usize = 0xffff;
/// Most `PT_DYNAMIC` entries read before `DT_NULL`.
const MAX_DYNAMIC_ENTRIES: usize = 1 << 16;
/// Most dynamic symbols read: far more than any real program has.
pub(crate) const MAX_SYMBOLS: usize = 1 << 20;
/// Most dynamic relocations read, over all tables.
const MAX_RELOCATIONS: usize = 1 << 20;
/// Most pointers read from one constructor or destructor array.
const MAX_ARRAY_ENTRIES: usize = 4096;
/// Most GNU hash buckets and Bloom words accepted.
const MAX_GNU_HASH_WORDS: u64 = 1 << 24;

#[derive(Debug, Clone, Copy)]
struct Load {
    address: u64,
    offset: u64,
    file_size: u64,
}

/// The parts of an ELF image the dynamic linker reads: its loadable segments and dynamic entries.
pub(crate) struct Image<'data> {
    data: &'data [u8],
    is_64: bool,
    big_endian: bool,
    machine: u16,
    loads: Vec<Load>,
    entries: Vec<(u64, u64)>,
}

impl<'data> Image<'data> {
    /// The image's loadable segments and dynamic entries, or `None` for a file that is not ELF or has no
    /// `PT_DYNAMIC` within its bytes.
    pub(crate) fn parse(data: &'data [u8]) -> Option<Self> {
        if data.get(..4)? != b"\x7fELF" {
            return None;
        }
        let is_64 = match data.get(4)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        let big_endian = match data.get(5)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        let mut image = Self { data, is_64, big_endian, machine: 0, loads: Vec::new(), entries: Vec::new() };
        image.machine = image.uint(18, 2)? as u16;
        let (phoff, phentsize, phnum) = if is_64 {
            (image.uint(32, 8)?, image.uint(54, 2)?, image.uint(56, 2)?)
        } else {
            (image.uint(28, 4)?, image.uint(42, 2)?, image.uint(44, 2)?)
        };
        let minimum = if is_64 { 56 } else { 32 };
        if phentsize < minimum || phoff == 0 {
            return None;
        }
        let mut dynamic = None;
        for index in 0..usize::try_from(phnum).ok()?.min(MAX_PROGRAM_HEADERS) {
            let Some(at) = phoff.checked_add(phentsize.checked_mul(index as u64)?) else { break };
            let Ok(at) = usize::try_from(at) else { break };
            let Some(kind) = image.uint(at, 4) else { break };
            let field = |delta: usize, size: usize| at.checked_add(delta).and_then(|at| image.uint(at, size));
            let header = if is_64 {
                (field(8, 8), field(16, 8), field(32, 8))
            } else {
                (field(4, 4), field(8, 4), field(16, 4))
            };
            let (Some(offset), Some(address), Some(file_size)) = header else { break };
            // A segment whose addresses or file range would wrap around 2^64 maps nothing.
            let sound = address.checked_add(file_size).is_some() && offset.checked_add(file_size).is_some();
            match kind as u32 {
                PT_LOAD if sound => image.loads.push(Load { address, offset, file_size }),
                PT_LOAD => {}
                PT_DYNAMIC if dynamic.is_none() => dynamic = Some((offset, file_size)),
                _ => {}
            }
        }
        let (offset, size) = dynamic?;
        let entry = if is_64 { 16 } else { 8 };
        let start = usize::try_from(offset).ok()?;
        let available = data.len().checked_sub(start)?.min(usize::try_from(size).unwrap_or(usize::MAX));
        for index in 0..(available / entry).min(MAX_DYNAMIC_ENTRIES) {
            let Some(at) = index.checked_mul(entry).and_then(|delta| start.checked_add(delta)) else { break };
            let half = entry / 2;
            let tag = image.uint(at, half);
            let value = at.checked_add(half).and_then(|at| image.uint(at, half));
            let (Some(tag), Some(value)) = (tag, value) else { break };
            if tag == DT_NULL {
                break;
            }
            image.entries.push((tag, value));
        }
        Some(image)
    }

    fn pointer_size(&self) -> u64 {
        if self.is_64 { 8 } else { 4 }
    }

    /// An unsigned integer of `size` bytes at file offset `offset`, in the image's byte order.
    fn uint(&self, offset: usize, size: usize) -> Option<u64> {
        let bytes = self.data.get(offset..offset.checked_add(size)?)?;
        let mut value = 0u64;
        for index in 0..size {
            let byte = if self.big_endian { bytes[index] } else { bytes[size - 1 - index] };
            value = value << 8 | u64::from(byte);
        }
        Some(value)
    }

    /// The first value of dynamic tag `tag`.
    pub(crate) fn value(&self, tag: u64) -> Option<u64> {
        self.entries.iter().find(|&&(entry, _)| entry == tag).map(|&(_, value)| value)
    }

    /// The file offset of the `length` bytes at `address`, all within the file-backed part of one `PT_LOAD`.
    fn offset_of(&self, address: u64, length: u64) -> Option<usize> {
        let load = self.loads.iter().find(|load| {
            address
                .checked_sub(load.address)
                .is_some_and(|delta| delta.checked_add(length).is_some_and(|end| end <= load.file_size))
        })?;
        let offset = load.offset.checked_add(address - load.address)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        (end <= self.data.len()).then_some(start)
    }

    /// An unsigned integer of `size` bytes at `address`.
    fn read(&self, address: u64, size: usize) -> Option<u64> {
        self.uint(self.offset_of(address, size as u64)?, size)
    }

    /// How many entries of `entry` bytes, at most `limit`, can be read from `address` on: all of them, or as many as
    /// lie in the same segment's file bytes.
    fn readable(&self, address: u64, entry: u64, limit: usize) -> usize {
        let Some(load) = self
            .loads
            .iter()
            .find(|load| address.checked_sub(load.address).is_some_and(|delta| delta < load.file_size))
        else {
            return 0;
        };
        let in_segment = load.file_size - (address - load.address);
        let Some(offset) = load.offset.checked_add(address - load.address) else { return 0 };
        let in_file = (self.data.len() as u64).saturating_sub(offset);
        usize::try_from(in_segment.min(in_file) / entry.max(1)).unwrap_or(usize::MAX).min(limit)
    }
}

/// `base + index * scale`, or `None` when it would wrap around 2^64.
fn element(base: u64, index: u64, scale: u64) -> Option<u64> {
    base.checked_add(index.checked_mul(scale)?)
}

/// One entry of the dynamic symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynamicSymbol {
    pub(crate) name: String,
    pub(crate) value: u64,
    pub(crate) size: u64,
    pub(crate) kind: u8,
    pub(crate) bind: u8,
    pub(crate) other: u8,
    shndx: u16,
}

impl DynamicSymbol {
    pub(crate) fn is_undefined(&self) -> bool {
        self.shndx == SHN_UNDEF
    }

    /// A definition in the image, as `object` counts one for a `.dynsym` symbol.
    pub(crate) fn is_definition(&self) -> bool {
        let section = self.shndx != SHN_UNDEF && (self.shndx < SHN_LORESERVE || self.shndx == SHN_XINDEX);
        section && matches!(self.kind, STT_NOTYPE | STT_OBJECT | STT_FUNC | STT_TLS | STT_GNU_IFUNC)
    }

    /// A function (or `ifunc` resolver).
    pub(crate) fn is_function(&self) -> bool {
        matches!(self.kind, STT_FUNC | STT_GNU_IFUNC)
    }

    /// An export at an address, as `object` reports one for a `.dynsym` symbol: not local, in a section (or
    /// `SHN_XINDEX`), of no type, an object or a function.
    pub(crate) fn exported_address(&self) -> Option<u64> {
        let special = self.shndx == SHN_UNDEF || (self.shndx >= SHN_LORESERVE && self.shndx != SHN_XINDEX);
        let exported = self.bind != STB_LOCAL && !special && self.shndx != SHN_ABS;
        (exported && matches!(self.kind, STT_NOTYPE | STT_OBJECT | STT_FUNC)).then_some(self.value)
    }
}

/// A dynamic relocation: where it applies, its symbol index (0 for none), its type, and its addend when the table
/// has explicit ones (`RELA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Relocation {
    pub(crate) offset: u64,
    pub(crate) symbol: u32,
    pub(crate) kind: u32,
    pub(crate) addend: Option<i64>,
}

/// What `PT_DYNAMIC` describes, for a file whose section headers may be gone.
#[derive(Debug, Default)]
pub(crate) struct Dynamic {
    /// The dynamic symbol table by index (index 0 is the null symbol), or empty when it was not read.
    pub(crate) symbols: Vec<DynamicSymbol>,
    pub(crate) relocations: Vec<Relocation>,
    /// Constructors and destructors: `DT_INIT`, `DT_FINI` and the pointers in the init, preinit and fini arrays.
    pub(crate) constructors: Vec<u64>,
    pub(crate) warnings: Vec<String>,
    pub(crate) is_64: bool,
    /// The MIPS GOT layout, which the loader completes with [`Dynamic::symbols`]'s count.
    pub(crate) mips_got: Option<crate::slots::MipsGot>,
}

/// Reads `data`'s dynamic section. With `symbols`, also the dynamic symbol table and relocations, which only a file
/// without a `.dynsym` section needs. `None` for a file with no readable `PT_DYNAMIC`.
pub(crate) fn read(data: &[u8], symbols: bool) -> Option<Dynamic> {
    let image = Image::parse(data)?;
    let mut dynamic = Dynamic { is_64: image.is_64, ..Dynamic::default() };
    if symbols {
        match symbol_table(&image, &mut dynamic.warnings) {
            Ok(table) => dynamic.symbols = table,
            Err(warning) => {
                dynamic.warnings.push(format!("dynamic symbol table (from PT_DYNAMIC) unreadable: {warning}"))
            }
        }
    }
    dynamic.relocations = relocations(&image, &mut dynamic.warnings);
    dynamic.constructors = constructors(&image, &dynamic.relocations);
    Some(dynamic)
}

/// How many entries the dynamic symbol table has: `DT_MIPS_SYMTABNO`, `DT_HASH`'s chain count, or one past the
/// highest symbol `DT_GNU_HASH` reaches. `None` when the file records none of them.
pub(crate) fn symbol_count(image: &Image) -> Result<Option<usize>, String> {
    let checked = |count: u64| {
        usize::try_from(count).ok().filter(|&count| count <= MAX_SYMBOLS).ok_or_else(|| format!("{count} symbols"))
    };
    if let Some(count) = image.value(DT_MIPS_SYMTABNO) {
        return checked(count).map(Some);
    }
    if let Some(hash) = image.value(DT_HASH) {
        let chains = hash.checked_add(4).and_then(|at| image.read(at, 4)).ok_or("DT_HASH is outside the file")?;
        return checked(chains).map(Some);
    }
    let Some(hash) = image.value(DT_GNU_HASH) else { return Ok(None) };
    let header = |index: u64| element(hash, index, 4).and_then(|at| image.read(at, 4));
    let (Some(buckets), Some(first), Some(bloom)) = (header(0), header(1), header(2)) else {
        return Err("DT_GNU_HASH is outside the file".into());
    };
    if buckets > MAX_GNU_HASH_WORDS || bloom > MAX_GNU_HASH_WORDS || first > MAX_SYMBOLS as u64 {
        return Err("DT_GNU_HASH header is implausible".into());
    }
    let outside = "DT_GNU_HASH buckets are outside the file";
    let buckets_at = hash.checked_add(16).and_then(|at| element(at, bloom, image.pointer_size())).ok_or(outside)?;
    let mut highest = None;
    for index in 0..buckets {
        let bucket = element(buckets_at, index, 4).and_then(|at| image.read(at, 4)).ok_or(outside)?;
        if bucket != 0 {
            highest = highest.max(Some(bucket));
        }
    }
    let Some(mut index) = highest else { return checked(first).map(Some) };
    if index < first {
        return Err("DT_GNU_HASH bucket below its first symbol".into());
    }
    let chains_at = element(buckets_at, buckets, 4).ok_or("DT_GNU_HASH chains are outside the file")?;
    // The last chain ends at the entry whose hash has the low bit set.
    loop {
        if index >= MAX_SYMBOLS as u64 {
            return Err("DT_GNU_HASH chain does not end".into());
        }
        let value = element(chains_at, index - first, 4)
            .and_then(|at| image.read(at, 4))
            .ok_or("DT_GNU_HASH chain is outside the file")?;
        if value & 1 == 1 {
            return checked(index + 1).map(Some);
        }
        index += 1;
    }
}

fn symbol_table(image: &Image, warnings: &mut Vec<String>) -> Result<Vec<DynamicSymbol>, String> {
    let (Some(table), Some(strings), Some(strings_size)) =
        (image.value(DT_SYMTAB), image.value(DT_STRTAB), image.value(DT_STRSZ))
    else {
        return Ok(Vec::new());
    };
    let entry = if image.is_64 { 24 } else { 16 };
    if let Some(size) = image.value(DT_SYMENT)
        && size != entry
    {
        return Err(format!("DT_SYMENT is {size}, not {entry}"));
    }
    let Some(count) = symbol_count(image)? else {
        return Err("no DT_HASH, DT_GNU_HASH or DT_MIPS_SYMTABNO gives its length".into());
    };
    let readable = image.readable(table, entry, count);
    let string_table = image
        .offset_of(strings, strings_size)
        .map(|start| &image.data[start..start + strings_size as usize])
        .ok_or("DT_STRTAB is outside the file")?;
    let mut symbols = Vec::with_capacity(readable);
    for index in 0..readable {
        let Some(at) = element(table, index as u64, entry) else { break };
        let field = |offset: u64, size: usize| at.checked_add(offset).and_then(|at| image.read(at, size));
        let fields = if image.is_64 {
            (field(0, 4), field(4, 1), field(5, 1), field(6, 2), field(8, 8), field(16, 8))
        } else {
            (field(0, 4), field(12, 1), field(13, 1), field(14, 2), field(4, 4), field(8, 4))
        };
        let (Some(name), Some(info), Some(other), Some(shndx), Some(value), Some(size)) = fields else { break };
        let name = usize::try_from(name)
            .ok()
            .and_then(|start| string_table.get(start..))
            .and_then(|tail| tail.iter().position(|&byte| byte == 0).map(|end| &tail[..end]))
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        symbols.push(DynamicSymbol {
            name,
            value,
            size,
            kind: info as u8 & 0xf,
            bind: info as u8 >> 4,
            other: other as u8,
            shndx: shndx as u16,
        });
    }
    if symbols.len() < count {
        let read = symbols.len();
        warnings.push(format!(
            "dynamic symbol table (from PT_DYNAMIC) has {count} symbols, of which {read} lie in the file"
        ));
    }
    Ok(symbols)
}

/// The relocations in `DT_REL`, `DT_RELA` and `DT_JMPREL`. 64-bit MIPS packs three types into `r_info` and is not
/// read.
fn relocations(image: &Image, warnings: &mut Vec<String>) -> Vec<Relocation> {
    let mut found = Vec::new();
    if image.is_64 && image.machine == EM_MIPS {
        return found;
    }
    let (rel, rela) = if image.is_64 { (16, 24) } else { (8, 12) };
    let jump_entry = match image.value(DT_PLTREL) {
        Some(DT_RELA) => rela,
        _ => rel,
    };
    let tables = [
        (DT_REL, DT_RELSZ, Some(DT_RELENT), rel),
        (DT_RELA, DT_RELASZ, Some(DT_RELAENT), rela),
        (DT_JMPREL, DT_PLTRELSZ, None, jump_entry),
    ];
    for (tag, size_tag, entry_tag, entry) in tables {
        let (Some(address), Some(size)) = (image.value(tag), image.value(size_tag)) else { continue };
        if entry_tag.and_then(|tag| image.value(tag)).is_some_and(|size| size != entry) || size % entry != 0 {
            warnings.push(format!("dynamic relocation table at {address:#x} has an unexpected entry size"));
            continue;
        }
        let wanted = usize::try_from(size / entry).unwrap_or(usize::MAX);
        let room = MAX_RELOCATIONS.saturating_sub(found.len());
        let count = image.readable(address, entry, wanted.min(room));
        if count < wanted {
            warnings.push(format!("dynamic relocation table at {address:#x} runs past the file; {count} read"));
        }
        let word = image.pointer_size() as usize;
        for index in 0..count {
            let Some(at) = element(address, index as u64, entry) else { break };
            let field = |index: u64| element(at, index, word as u64).and_then(|at| image.read(at, word));
            let (Some(offset), Some(info)) = (field(0), field(1)) else { break };
            let addend = (entry == rela)
                .then(|| field(2))
                .flatten()
                .map(|addend| if image.is_64 { addend as i64 } else { i64::from(addend as u32 as i32) });
            let (symbol, kind) =
                if image.is_64 { ((info >> 32) as u32, info as u32) } else { ((info >> 8) as u32, info as u32 & 0xff) };
            found.push(Relocation { offset, symbol, kind, addend });
        }
    }
    found
}

/// `DT_INIT`, `DT_FINI` and the pointers in the preinit, init and fini arrays. A slot that holds 0 because a
/// `RELA` relative relocation fills it takes the relocation's addend; slots holding 0 or all ones are skipped.
fn constructors(image: &Image, relocations: &[Relocation]) -> Vec<u64> {
    let mut found: Vec<u64> = [DT_INIT, DT_FINI].into_iter().filter_map(|tag| image.value(tag)).collect();
    let size = image.pointer_size();
    let all_ones = if image.is_64 { u64::MAX } else { u64::from(u32::MAX) };
    let addends: std::collections::BTreeMap<u64, u64> = relocations
        .iter()
        .filter(|relocation| relocation.symbol == 0 && relocation.kind != 0)
        .filter_map(|relocation| Some((relocation.offset, relocation.addend? as u64 & all_ones)))
        .collect();
    let arrays =
        [(DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ), (DT_INIT_ARRAY, DT_INIT_ARRAYSZ), (DT_FINI_ARRAY, DT_FINI_ARRAYSZ)];
    for (tag, size_tag) in arrays {
        let (Some(array), Some(bytes)) = (image.value(tag), image.value(size_tag)) else { continue };
        let wanted = usize::try_from(bytes / size).unwrap_or(usize::MAX).min(MAX_ARRAY_ENTRIES);
        for index in 0..image.readable(array, size, wanted) {
            let Some(slot) = element(array, index as u64, size) else { break };
            let Some(stored) = image.read(slot, size as usize) else { break };
            let value = if stored == 0 { addends.get(&slot).copied().unwrap_or(0) } else { stored };
            if value != 0 && value != all_ones {
                found.push(value);
            }
        }
    }
    found
}

#[cfg(test)]
#[path = "dynsym_tests.rs"]
mod tests;
