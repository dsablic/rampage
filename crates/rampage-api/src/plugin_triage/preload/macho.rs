//! Raw, allocation-free admission before object::File, Binary loading and Project's constructor Names.
//!
//! Whole-file little-endian x86_64 MH_EXECUTE only: canonical __PAGEZERO/__TEXT/__DATA_CONST/__LINKEDIT,
//! __text/__stubs/__cstring/__unwind_info/__got, format-6 bind-only chained fixups and regular export trees.
//! No classic dyld streams, rebases, ObjC/Swift/Go/debug/eh_frame recovery, relocations or mangled names.
//! Compact unwind is opaque: opening and Names do not parse __unwind_info. This is not linkage/runtime proof.
//! Fixed scratch arrays bound raw traversal; weighted events and repeated names fund native intermediates,
//! including pre-deduplication vectors, dylib reuse, trie prefixes, Names indexes and per-byte stub decoding.
//! Events cost eight records; referenced/prefix/stub names cost sixteen copies of length plus 32 bytes,
//! under the contract's aggregate 16,384-record and 1 MiB limits. Names reaching demanglers are restricted
//! to underscore-prefixed C identifiers; ignored radr://digits N_OPT rows are admitted separately.

use rampage_plugin_contract::{MAX_INPUT_BYTES, MAX_RECORDS};

use super::{MAX_PLUGIN_TRIAGE_SOURCE_BYTES, invalid, span, u16_at, u32_at};
use crate::ApiError;

const MAX_COMMANDS: usize = 32;
const MAX_LIBRARIES: usize = 8;
const MAX_NAME: usize = 256;
const MAX_TRIE_NODES: usize = 512;
const MAX_TRIE_DEPTH: usize = 32;
const BASE: u64 = 0x1_0000_0000;

#[derive(Default)]
struct Budget {
    records: usize,
    names: usize,
    longest_import: usize,
}

impl Budget {
    fn events(&mut self, count: usize) -> Result<(), ApiError> {
        self.records = count
            .checked_mul(8)
            .and_then(|count| self.records.checked_add(count))
            .ok_or_else(|| invalid("Mach-O record budget overflow"))?;
        if self.records > MAX_RECORDS {
            return Err(invalid("Mach-O producer records exceed raw preload admission"));
        }
        Ok(())
    }

    fn names(&mut self, count: usize, length: usize) -> Result<(), ApiError> {
        self.names = length
            .checked_add(32)
            .and_then(|length| length.checked_mul(16))
            .and_then(|length| length.checked_mul(count))
            .and_then(|length| self.names.checked_add(length))
            .ok_or_else(|| invalid("Mach-O repeated-name budget overflow"))?;
        if self.names > MAX_INPUT_BYTES {
            return Err(invalid("Mach-O repeated names exceed raw preload admission"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct Span {
    offset: usize,
    size: usize,
}

impl Span {
    fn end(self) -> Result<usize, ApiError> {
        self.offset.checked_add(self.size).ok_or_else(|| invalid("Mach-O file span overflow"))
    }

    fn overlaps(self, other: Self) -> Result<bool, ApiError> {
        Ok(self.size != 0 && other.size != 0 && self.offset < other.end()? && other.offset < self.end()?)
    }

    fn bytes(self, bytes: &[u8]) -> Result<&[u8], ApiError> {
        span(bytes, self.offset, self.size)
    }
}

#[derive(Clone, Copy, Default)]
struct Segment {
    address: u64,
    size: u64,
    file: Span,
}

impl Segment {
    fn end(self) -> Result<u64, ApiError> {
        self.address.checked_add(self.size).ok_or_else(|| invalid("Mach-O VM extent overflow"))
    }

    fn backing(self, address: u64, size: usize) -> Result<Span, ApiError> {
        let delta = address.checked_sub(self.address).ok_or_else(|| invalid("Mach-O VA precedes segment"))?;
        let delta = usize::try_from(delta).map_err(|_| invalid("Mach-O VA is not addressable"))?;
        if delta.checked_add(size).is_none_or(|end| end > self.file.size) {
            return Err(invalid("Mach-O VA requires complete file backing, never zero-fill"));
        }
        let offset = self.file.offset.checked_add(delta).ok_or_else(|| invalid("Mach-O backing overflow"))?;
        Ok(Span { offset, size })
    }
}

#[derive(Clone, Copy, Default)]
struct Section {
    address: u64,
    file: Span,
    indirect: usize,
}

struct Macho<'a> {
    bytes: &'a [u8],
    segments: [Segment; 4],
    sections: [Section; 5],
    libraries: [&'a [u8]; MAX_LIBRARIES],
    library_count: usize,
    tables: [Span; 7],
    dysymtab: &'a [u8],
    entry: usize,
}

pub(super) fn admit(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.is_empty() || bytes.len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
        return Err(invalid("Mach-O source exceeds the nonempty 16 MiB profile"));
    }
    let header = span(bytes, 0, 32)?;
    if &header[..4] != b"\xcf\xfa\xed\xfe"
        || u32_at(header, 4)? != 0x0100_0007
        || u32_at(header, 8)? != 3
        || u32_at(header, 12)? != 2
        || u32_at(header, 24)? != 0x0020_0085
        || u32_at(header, 28)? != 0
    {
        return Err(invalid("Mach-O preload requires ordinary little-endian x86_64 PIE MH_EXECUTE"));
    }
    let count = u32_at(header, 16)? as usize;
    let command_size = u32_at(header, 20)? as usize;
    if count == 0 || count > MAX_COMMANDS || command_size > 65536 {
        return Err(invalid("Mach-O load-command count/bytes exceed raw admission"));
    }
    let commands = span(bytes, 32, command_size)?;
    let mut budget = Budget::default();
    budget.events(count + 4 + 5 + 8)?;
    let mut macho = Macho {
        bytes,
        segments: [Segment::default(); 4],
        sections: [Section::default(); 5],
        libraries: [&[]; MAX_LIBRARIES],
        library_count: 0,
        tables: [Span::default(); 7],
        dysymtab: &[],
        entry: 0,
    };
    let mut kinds = [0u32; MAX_COMMANDS];
    let mut offset = 0;
    let mut segment_count = 0;
    for index in 0..count {
        let kind = u32_at(commands, offset)?;
        let size = u32_at(commands, offset + 4)? as usize;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(invalid("Mach-O load-command size must be positive and 8-byte aligned"));
        }
        let command = span(commands, offset, size)?;
        offset += size;
        if !matches!(kind, 0x19 | 0xc) && kinds[..index].contains(&kind) {
            return Err(invalid("Mach-O duplicate singleton load command is not admitted"));
        }
        kinds[index] = kind;
        match kind {
            0x19 => {
                macho.segment(command, segment_count, 32 + command_size, &mut budget)?;
                segment_count += 1;
            }
            0x2 => {
                exact(command, 24)?;
                macho.tables[0] = table(command, 8, 16)?;
                macho.tables[1] = table(command, 16, 1)?;
            }
            0xb => {
                exact(command, 80)?;
                macho.dysymtab = command;
                macho.tables[2] = table(command, 56, 4)?;
            }
            0x8000_0034 | 0x8000_0033 | 0x26 => {
                exact(command, 16)?;
                let index = match kind {
                    0x8000_0034 => 3,
                    0x8000_0033 => 4,
                    _ => 5,
                };
                macho.tables[index] = table(command, 8, 1)?;
            }
            0x29 => {
                exact(command, 16)?;
                macho.tables[6] = table(command, 8, 1)?;
                if macho.tables[6].size != 0 {
                    return Err(invalid("Mach-O nonempty data-in-code is outside preload admission"));
                }
            }
            0xc => macho.library(command, &mut budget)?,
            0xe => {
                let text = command_text(command, 12, u32_at(command, 8)? as usize)?;
                if text != b"/usr/lib/dyld" {
                    return Err(invalid("Mach-O noncanonical dylinker is outside preload admission"));
                }
                budget.names(1, text.len())?;
            }
            0x1b => exact(command, 24)?,
            0x32 => {
                if u32_at(command, 8)? != 1 || u32_at(command, 20)? != 1 {
                    return Err(invalid("Mach-O build-version requires macOS and one bounded build tool"));
                }
                exact(command, 32)?;
                if u32_at(command, 24)? != 3 {
                    return Err(invalid("Mach-O build-version tool is outside the ld profile"));
                }
            }
            0x2a => exact(command, 16)?,
            0x8000_0028 => {
                exact(command, 24)?;
                macho.entry = usize_at(command, 8)?;
                if u64_at(command, 16)? != 0 {
                    return Err(invalid("Mach-O nonzero LC_MAIN stack size is outside preload admission"));
                }
            }
            _ => return Err(invalid("Mach-O unknown or unsupported load command is outside preload admission")),
        }
    }
    let required = [0x2, 0xb, 0x8000_0034, 0x8000_0033, 0x26, 0x29, 0xe, 0x1b, 0x32, 0x2a, 0x8000_0028];
    if offset != commands.len()
        || segment_count != 4
        || macho.library_count == 0
        || required.iter().any(|kind| !kinds[..count].contains(kind))
    {
        return Err(invalid("Mach-O commands must exhaust the canonical executable profile"));
    }
    macho.validate_tables()?;
    macho.symbols(&mut budget)?;
    macho.fixups(&mut budget)?;
    macho.exports(&mut budget)?;
    macho.starts(&mut budget)?;
    // Names::stub_names decodes bytes, not reserved2-sized entries. Bound every possible instruction/name,
    // including repeated references to one imported name, before the decoder or constructor is entered.
    budget.events(macho.sections[1].file.size)?;
    budget.names(macho.sections[1].file.size, budget.longest_import)?;
    for candidate in bytes.windows(8) {
        if matches!(candidate, [0xfb | 0xfa | 0xf0 | 0xf1, 0xff, 0xff, 0xff, 0, 0, 1 | 2 | 4, 8]) {
            return Err(invalid("Mach-O possible hidden Go recovery table is outside preload admission"));
        }
    }
    Ok(())
}

impl<'a> Macho<'a> {
    fn segment(
        &mut self,
        command: &[u8],
        index: usize,
        header_end: usize,
        budget: &mut Budget,
    ) -> Result<(), ApiError> {
        let expected: &[u8] = match index {
            0 => b"__PAGEZERO",
            1 => b"__TEXT",
            2 => b"__DATA_CONST",
            3 => b"__LINKEDIT",
            _ => return Err(invalid("Mach-O segment count/order is outside the canonical profile")),
        };
        if inline(span(command, 8, 16)?)? != expected {
            return Err(invalid("Mach-O segment name/order is outside the canonical profile"));
        }
        budget.names(1, expected.len())?;
        let count = u32_at(command, 64)? as usize;
        let expected_count = match index {
            1 => 4,
            2 => 1,
            _ => 0,
        };
        if count != expected_count {
            return Err(invalid("Mach-O section count is outside the canonical profile"));
        }
        exact(command, 72 + count * 80)?;
        let segment = Segment {
            address: u64_at(command, 24)?,
            size: u64_at(command, 32)?,
            file: Span { offset: usize_at(command, 40)?, size: usize_at(command, 48)? },
        };
        let protection = match index {
            0 => 0,
            1 => 5,
            2 => 3,
            _ => 1,
        };
        if u32_at(command, 56)? != protection
            || u32_at(command, 60)? != protection
            || u32_at(command, 68)? != if index == 2 { 0x10 } else { 0 }
        {
            return Err(invalid("Mach-O segment protection/flags are outside the canonical profile"));
        }
        if index == 0 {
            if segment.address != 0 || segment.size != BASE || segment.file.offset != 0 || segment.file.size != 0 {
                return Err(invalid("Mach-O guard must be the inaccessible empty-file 4 GiB __PAGEZERO"));
            }
        } else {
            segment.file.bytes(self.bytes)?;
            if segment.size == 0
                || !segment.size.is_multiple_of(4096)
                || segment.file.size == 0
                || segment.file.size as u64 > segment.size
                || segment.address != BASE + segment.file.offset as u64
                || !segment.file.offset.is_multiple_of(4096)
                || (index == 1 && (segment.file.offset != 0 || segment.file.size < header_end))
                || (index != 1 && segment.file.offset < header_end)
            {
                return Err(invalid("Mach-O segment VM/file layout is outside full-backing admission"));
            }
            segment.end()?;
            for other in self.segments.iter().take(index) {
                if (segment.address < other.end()? && other.address < segment.end()?)
                    || segment.file.overlaps(other.file)?
                {
                    return Err(invalid("Mach-O segment backing is overlapping or ambiguous"));
                }
            }
        }
        self.segments[index] = segment;
        for (section_index, header) in command[72..].as_chunks::<80>().0.iter().enumerate() {
            let slot = if index == 1 { section_index } else { 4 };
            self.section(header, slot, segment, expected, header_end, budget)?;
        }
        Ok(())
    }

    fn section(
        &mut self,
        header: &[u8],
        index: usize,
        segment: Segment,
        segment_name: &[u8],
        header_end: usize,
        budget: &mut Budget,
    ) -> Result<(), ApiError> {
        let names: [&[u8]; 5] = [b"__text", b"__stubs", b"__cstring", b"__unwind_info", b"__got"];
        let flags = [0x8000_0400, 0x8000_0408, 2, 0, 6];
        if inline(&header[..16])? != names[index]
            || inline(&header[16..32])? != segment_name
            || u32_at(header, 64)? != flags[index]
            || u32_at(header, 56)? != 0
            || u32_at(header, 60)? != 0
            || u32_at(header, 76)? != 0
        {
            return Err(invalid("Mach-O section name/type/relocations are outside the canonical profile"));
        }
        let section = Section {
            address: u64_at(header, 32)?,
            file: Span { offset: u32_at(header, 48)? as usize, size: usize_at(header, 40)? },
            indirect: u32_at(header, 68)? as usize,
        };
        let alignment = u32_at(header, 52)?;
        if alignment > 12
            || section.file.size == 0
            || section.file.offset < header_end
            || !section.address.is_multiple_of(1u64 << alignment)
            || segment.backing(section.address, section.file.size)?.offset != section.file.offset
            || (index == 1 && (u32_at(header, 72)? != 6 || !section.file.size.is_multiple_of(6)))
            || (index != 1 && u32_at(header, 72)? != 0)
            || (!matches!(index, 1 | 4) && section.indirect != 0)
            || (index == 4 && (!section.file.size.is_multiple_of(8) || !section.address.is_multiple_of(8)))
        {
            return Err(invalid("Mach-O section must have canonical alignment and exact backed VA/file bytes"));
        }
        section.file.bytes(self.bytes)?;
        for other in self.sections.iter().take(index) {
            if section.file.overlaps(other.file)? {
                return Err(invalid("Mach-O section scan spans overlap"));
            }
        }
        budget.names(1, names[index].len())?;
        self.sections[index] = section;
        Ok(())
    }

    fn library(&mut self, command: &'a [u8], budget: &mut Budget) -> Result<(), ApiError> {
        if self.library_count == MAX_LIBRARIES || u32_at(command, 8)? != 24 {
            return Err(invalid("Mach-O dylib count/string layout exceeds raw admission"));
        }
        let name = command_text(command, 24, 24)?;
        if !name.starts_with(b"/usr/lib/") || self.libraries[..self.library_count].contains(&name) {
            return Err(invalid("Mach-O dylibs require unique /usr/lib/ install names"));
        }
        budget.events(1)?;
        budget.names(1, name.len())?;
        self.libraries[self.library_count] = name;
        self.library_count += 1;
        Ok(())
    }

    fn validate_tables(&self) -> Result<(), ApiError> {
        let linkedit = self.segments[3].file;
        for (index, table) in self.tables.iter().copied().enumerate() {
            if table.offset < linkedit.offset || table.end()? > linkedit.end()? || (index < 6 && table.size == 0) {
                return Err(invalid("Mach-O link-edit tables require complete __LINKEDIT backing"));
            }
            table.bytes(self.bytes)?;
            for other in self.tables.iter().take(index) {
                if table.overlaps(*other)? {
                    return Err(invalid("Mach-O link-edit tables overlap"));
                }
            }
        }
        if !self.tables[0].offset.is_multiple_of(8)
            || !self.tables[2].offset.is_multiple_of(4)
            || !self.tables[3].offset.is_multiple_of(8)
        {
            return Err(invalid("Mach-O symbol tables must have canonical alignment"));
        }
        let text = self.sections[0];
        if self.entry < text.file.offset || self.entry >= text.file.end()? {
            return Err(invalid("Mach-O LC_MAIN must point into fully backed __text code"));
        }
        Ok(())
    }

    fn symbols(&self, budget: &mut Budget) -> Result<(), ApiError> {
        let symbols = self.tables[0].bytes(self.bytes)?;
        let strings = self.tables[1].bytes(self.bytes)?;
        let count = symbols.len() / 16;
        budget.events(count)?;
        let mut next = 0;
        for at in [8, 16, 24] {
            let start = u32_at(self.dysymtab, at)? as usize;
            let length = u32_at(self.dysymtab, at + 4)? as usize;
            if start != next || start.checked_add(length).is_none_or(|end| end > count) {
                return Err(invalid("Mach-O dysymtab partitions must exhaust the bounded nlist table"));
            }
            next = start + length;
        }
        if next != count
            || self.dysymtab[32..56].iter().any(|byte| *byte != 0)
            || self.dysymtab[64..80].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("Mach-O auxiliary dysymtab/relocation tables are outside preload admission"));
        }
        let locals = u32_at(self.dysymtab, 12)? as usize;
        let undefined = u32_at(self.dysymtab, 24)? as usize;
        for (index, symbol) in symbols.as_chunks::<16>().0.iter().enumerate() {
            let name = text(strings, u32_at(symbol, 0)? as usize)?;
            budget.names(1, name.len())?;
            let kind = symbol[4];
            let partition_kind = if index < locals {
                0x3c
            } else if index < undefined {
                0x0f
            } else {
                1
            };
            if kind != partition_kind {
                return Err(invalid("Mach-O nlist kinds must agree with their dysymtab partitions"));
            }
            if kind != 0x3c {
                plain_name(name)?;
            }
            let section = symbol[5] as usize;
            let description = u16_at(symbol, 6)?;
            let value = u64_at(symbol, 8)?;
            match kind {
                0x0f if section > 0 && section <= 5 => {
                    let target = self.sections[section - 1];
                    let header_symbol = name == b"__mh_execute_header" && value == BASE && section == 1;
                    let expected_description = if header_symbol { 0x10 } else { 0 };
                    if description != expected_description
                        || (!header_symbol && !contains(target.address, target.file.size, value, 1)?)
                    {
                        return Err(invalid("Mach-O defined symbol is outside its exact backed section"));
                    }
                }
                1 if section == 0 && value == 0 => {
                    let ordinal = (description >> 8) as usize;
                    if description & 0xff != 0 || ordinal == 0 || ordinal > self.library_count {
                        return Err(invalid("Mach-O undefined symbol requires an admitted positive dylib ordinal"));
                    }
                    budget.names(1, self.libraries[ordinal - 1].len())?;
                }
                0x3c if section == 0
                    && description == 0
                    && name
                        .strip_prefix(b"radr://")
                        .is_some_and(|tail| !tail.is_empty() && tail.iter().all(u8::is_ascii_digit)) => {}
                _ => return Err(invalid("Mach-O nlist kind/flags are outside bounded ordinary symbols")),
            }
        }
        let indirect = self.tables[2].bytes(self.bytes)?;
        budget.events(indirect.len() / 4)?;
        let stub_count = self.sections[1].file.size / 6;
        let got_count = self.sections[4].file.size / 8;
        if self.sections[1].indirect != 0
            || self.sections[4].indirect != stub_count
            || stub_count.checked_add(got_count) != Some(indirect.len() / 4)
        {
            return Err(invalid("Mach-O indirect table must exactly cover stub and GOT rows"));
        }
        for row in indirect.as_chunks::<4>().0 {
            let index = u32_at(row, 0)? as usize;
            if index >= count || symbols[index * 16 + 4] != 1 {
                return Err(invalid("Mach-O indirect row must reference an admitted undefined nlist"));
            }
        }
        Ok(())
    }

    fn fixups(&self, budget: &mut Budget) -> Result<(), ApiError> {
        let data = self.tables[3].bytes(self.bytes)?;
        let starts = u32_at(data, 4)? as usize;
        let imports = u32_at(data, 8)? as usize;
        let strings = u32_at(data, 12)? as usize;
        let count = u32_at(data, 16)? as usize;
        budget.events(count)?;
        if u32_at(data, 0)? != 0 || u32_at(data, 20)? != 1 || u32_at(data, 24)? != 0 || count == 0 {
            return Err(invalid("Mach-O chained imports require version 0, format 1 and uncompressed symbols"));
        }
        let image_starts = Span { offset: starts, size: 20 };
        let import_table = Span { offset: imports, size: count * 4 };
        if starts < 28 || !starts.is_multiple_of(8) || !imports.is_multiple_of(4) || strings < import_table.end()? {
            return Err(invalid("Mach-O chained metadata offsets are outside canonical raw admission"));
        }
        let image = image_starts.bytes(data)?;
        if u32_at(image, 0)? != 4 || u32_at(image, 4)? != 0 || u32_at(image, 8)? != 0 || u32_at(image, 16)? != 0 {
            return Err(invalid("Mach-O chain starts must name only the canonical DATA_CONST segment"));
        }
        let segment_offset = u32_at(image, 12)? as usize;
        if segment_offset < image_starts.size {
            return Err(invalid("Mach-O chain segment header overlaps image starts"));
        }
        let segment_at = starts.checked_add(segment_offset).ok_or_else(|| invalid("Mach-O chain offset overflow"))?;
        if segment_at % 8 != 0 {
            return Err(invalid("Mach-O chained segment metadata requires canonical alignment"));
        }
        let size = u32_at(data, segment_at)? as usize;
        let segment_span = Span { offset: segment_at, size };
        let segment = segment_span.bytes(data)?;
        let pages = u16_at(segment, 20)? as usize;
        let target = self.segments[2];
        budget.events(pages)?;
        if size != 22 + pages * 2
            || u16_at(segment, 4)? != 4096
            || u16_at(segment, 6)? != 6
            || u64_at(segment, 8)? != target.address - BASE
            || u32_at(segment, 16)? != 0
            || pages != target.file.size.div_ceil(4096)
            || segment_span.end()? > imports
            || image_starts.end()? > segment_at
            || strings > data.len()
        {
            return Err(invalid("Mach-O chained page layout/format is outside fully backed format-6 admission"));
        }
        import_table.bytes(data)?;
        for index in 0..count {
            self.chain_import(data, imports, strings, index, budget)?;
        }
        let got = self.sections[4];
        for page in 0..pages {
            let start = u16_at(segment, 22 + page * 2)? as usize;
            if start == 0xffff {
                continue;
            }
            if start & 0x8000 != 0 {
                return Err(invalid("Mach-O chained MULTI page starts are outside preload admission"));
            }
            let mut offset = page * 4096 + start;
            loop {
                if offset / 4096 != page || offset % 4096 > 4088 || !offset.is_multiple_of(8) {
                    return Err(invalid("Mach-O chain pointer overlaps, is unaligned or crosses its page"));
                }
                let address = target.address.checked_add(offset as u64).ok_or_else(|| invalid("Mach-O chain VA"))?;
                if !contains(got.address, got.file.size, address, 8)? {
                    return Err(invalid("Mach-O chain pointer must have complete __got backing"));
                }
                let file = target.backing(address, 8)?;
                let pointer = u64_at(file.bytes(self.bytes)?, 0)?;
                budget.events(1)?;
                if pointer >> 63 != 1 || (pointer >> 24) & 0x07ff_ffff != 0 {
                    return Err(invalid(
                        "Mach-O chained rebases/addends/reserved bits are outside bind-only admission",
                    ));
                }
                let ordinal = (pointer & 0xff_ffff) as usize;
                if ordinal >= count {
                    return Err(invalid("Mach-O chained bind ordinal exceeds the admitted imports"));
                }
                self.chain_import(data, imports, strings, ordinal, budget)?;
                let next = ((pointer >> 51) & 0xfff) as usize * 4;
                if next == 0 {
                    break;
                }
                if next < 8 {
                    return Err(invalid("Mach-O chained pointers overlap"));
                }
                offset = offset.checked_add(next).ok_or_else(|| invalid("Mach-O chain walk overflow"))?;
            }
        }
        Ok(())
    }

    fn chain_import(
        &self,
        data: &[u8],
        imports: usize,
        strings: usize,
        index: usize,
        budget: &mut Budget,
    ) -> Result<(), ApiError> {
        let entry = u32_at(data, imports + index * 4)?;
        let ordinal = (entry & 0xff) as usize;
        if ordinal == 0 || ordinal > self.library_count || entry & 0x100 != 0 {
            return Err(invalid("Mach-O chained import requires a positive regular dylib ordinal"));
        }
        let name_offset =
            strings.checked_add((entry >> 9) as usize).ok_or_else(|| invalid("Mach-O chained name offset overflow"))?;
        let name = text(data, name_offset)?;
        plain_name(name)?;
        budget.names(1, name.len())?;
        budget.names(1, self.libraries[ordinal - 1].len())?;
        budget.longest_import = budget.longest_import.max(name.len());
        Ok(())
    }

    fn starts(&self, budget: &mut Budget) -> Result<(), ApiError> {
        let data = self.tables[5].bytes(self.bytes)?;
        let mut cursor = 0;
        let mut address = BASE;
        while cursor < data.len() {
            let delta = uleb(data, &mut cursor)?;
            if delta == 0 {
                if data[cursor..].iter().any(|byte| *byte != 0) {
                    return Err(invalid("Mach-O function-start termination requires zero padding"));
                }
                return Ok(());
            }
            budget.events(1)?;
            address = address.checked_add(delta).ok_or_else(|| invalid("Mach-O function-start VA overflow"))?;
            if !contains(self.sections[0].address, self.sections[0].file.size, address, 1)? {
                return Err(invalid("Mach-O function starts require fully backed __text addresses"));
            }
        }
        Err(invalid("Mach-O function-start stream is unterminated"))
    }

    fn exports(&self, budget: &mut Budget) -> Result<(), ApiError> {
        let data = self.tables[4].bytes(self.bytes)?;
        let mut prefix = [0u8; MAX_NAME];
        let mut stack = [Frame::default(); MAX_TRIE_DEPTH];
        let mut visited = [Span::default(); MAX_TRIE_NODES];
        let mut visited_count = 0;
        let mut depth = 1;
        stack[0] = self.trie_node(data, 0, &[], &mut visited, &mut visited_count, budget)?;
        while depth != 0 {
            let frame = &mut stack[depth - 1];
            if frame.remaining == 0 {
                depth -= 1;
                continue;
            }
            let edge = text(data, frame.cursor)?;
            frame.cursor += edge.len() + 1;
            let child = usize::try_from(uleb(data, &mut frame.cursor)?)
                .map_err(|_| invalid("Mach-O trie child offset is not addressable"))?;
            frame.remaining -= 1;
            let length = frame.prefix + edge.len();
            if length > MAX_NAME || depth == MAX_TRIE_DEPTH {
                return Err(invalid("Mach-O export prefix/depth exceeds raw admission"));
            }
            prefix[frame.prefix..length].copy_from_slice(edge);
            budget.names(1, length)?;
            let next = self.trie_node(data, child, &prefix[..length], &mut visited, &mut visited_count, budget)?;
            stack[depth] = next;
            depth += 1;
        }
        Ok(())
    }

    fn trie_node(
        &self,
        data: &[u8],
        offset: usize,
        prefix: &[u8],
        visited: &mut [Span; MAX_TRIE_NODES],
        visited_count: &mut usize,
        budget: &mut Budget,
    ) -> Result<Frame, ApiError> {
        budget.events(1)?;
        if *visited_count == MAX_TRIE_NODES || visited[..*visited_count].iter().any(|node| node.offset == offset) {
            return Err(invalid("Mach-O export trie node replay/cycle exceeds the non-DAG profile"));
        }
        let mut cursor = offset;
        let terminal = usize::try_from(uleb(data, &mut cursor)?)
            .map_err(|_| invalid("Mach-O export terminal size is not addressable"))?;
        let terminal_data = span(data, cursor, terminal)?;
        if terminal != 0 {
            plain_name(prefix)?;
            let mut at = 0;
            if uleb(terminal_data, &mut at)? != 0 {
                return Err(invalid("Mach-O export flags/resolver/reexport forms are outside preload admission"));
            }
            let address =
                BASE.checked_add(uleb(terminal_data, &mut at)?).ok_or_else(|| invalid("Mach-O export VA overflow"))?;
            let backed = self.segments[1..]
                .iter()
                .any(|segment| address >= segment.address && address - segment.address < segment.file.size as u64);
            if at != terminal_data.len() || !backed {
                return Err(invalid("Mach-O export terminal requires exact fields and complete image backing"));
            }
            budget.events(1)?;
            budget.names(1, prefix.len())?;
        }
        cursor += terminal;
        let children = span(data, cursor, 1)?[0] as usize;
        cursor += 1;
        budget.events(children)?;
        let edges = cursor;
        for _ in 0..children {
            let edge = text(data, cursor)?;
            cursor += edge.len() + 1;
            uleb(data, &mut cursor)?;
        }
        let node = Span { offset, size: cursor - offset };
        for other in visited.iter().take(*visited_count) {
            if node.overlaps(*other)? {
                return Err(invalid("Mach-O export trie nodes overlap"));
            }
        }
        visited[*visited_count] = node;
        *visited_count += 1;
        Ok(Frame { cursor: edges, remaining: children, prefix: prefix.len() })
    }
}

#[derive(Clone, Copy, Default)]
struct Frame {
    cursor: usize,
    remaining: usize,
    prefix: usize,
}

fn exact(bytes: &[u8], length: usize) -> Result<(), ApiError> {
    if bytes.len() != length {
        return Err(invalid("Mach-O command size is outside canonical preload admission"));
    }
    Ok(())
}

fn table(command: &[u8], offset: usize, width: usize) -> Result<Span, ApiError> {
    let offset_value = u32_at(command, offset)? as usize;
    let size = (u32_at(command, offset + 4)? as usize)
        .checked_mul(width)
        .ok_or_else(|| invalid("Mach-O table size overflow"))?;
    Ok(Span { offset: offset_value, size })
}

fn inline(bytes: &[u8]) -> Result<&[u8], ApiError> {
    let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if length == 0 || !bytes[..length].is_ascii() || bytes[length..].iter().any(|byte| *byte != 0) {
        return Err(invalid("Mach-O inline names require canonical ASCII and zero padding"));
    }
    Ok(&bytes[..length])
}

fn text(bytes: &[u8], offset: usize) -> Result<&[u8], ApiError> {
    let tail = bytes.get(offset..).ok_or_else(|| invalid("Mach-O name offset is outside its producer span"))?;
    let length = tail
        .iter()
        .take(MAX_NAME + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("Mach-O name is too long or unterminated"))?;
    let name = &tail[..length];
    if name.is_empty() || !name.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(invalid("Mach-O referenced names require nonempty printable ASCII"));
    }
    Ok(name)
}

fn plain_name(name: &[u8]) -> Result<(), ApiError> {
    // cpp_demangle accepts bare type encodings too, not just _Z names. A C-only underscore grammar avoids
    // that parser as well as Rust's bare R/ZN forms, Mach-O block invokes and global ctor/dtor encodings.
    let underscores = name.iter().take_while(|byte| **byte == b'_').count();
    let bare = &name[underscores..];
    if underscores == 0
        || bare.is_empty()
        || !bare[0].is_ascii_alphabetic()
        || !bare.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || [b"Z".as_slice(), b"R", b"T", b"GLOBAL_", b"OBJC", b"swift"].iter().any(|prefix| bare.starts_with(prefix))
    {
        return Err(invalid("Mach-O mangled/non-C names are outside pre-constructor admission"));
    }
    Ok(())
}

fn command_text(command: &[u8], minimum: usize, offset: usize) -> Result<&[u8], ApiError> {
    if offset != minimum {
        return Err(invalid("Mach-O load-command strings require canonical offsets"));
    }
    let name = text(command, offset)?;
    let end = offset + name.len() + 1;
    if command.len() != end.div_ceil(8) * 8 || command[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("Mach-O load-command strings require canonical zero padding"));
    }
    Ok(name)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ApiError> {
    Ok(u64::from_le_bytes(span(bytes, offset, 8)?.try_into().map_err(|_| invalid("Mach-O invalid u64"))?))
}

fn usize_at(bytes: &[u8], offset: usize) -> Result<usize, ApiError> {
    usize::try_from(u64_at(bytes, offset)?).map_err(|_| invalid("Mach-O value is not addressable"))
}

fn contains(start: u64, size: usize, address: u64, length: usize) -> Result<bool, ApiError> {
    let end = start.checked_add(size as u64).ok_or_else(|| invalid("Mach-O address extent overflow"))?;
    let requested = address.checked_add(length as u64).ok_or_else(|| invalid("Mach-O address extent overflow"))?;
    Ok(address >= start && address < end && requested <= end)
}

fn uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64, ApiError> {
    let mut value = 0;
    for index in 0..10 {
        let byte = span(bytes, *cursor, 1)?[0];
        *cursor += 1;
        if index == 9 && byte > 1 {
            return Err(invalid("Mach-O ULEB exceeds u64 width"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index != 0 && byte == 0 {
                return Err(invalid("Mach-O noncanonical ULEB is outside preload admission"));
            }
            return Ok(value);
        }
    }
    Err(invalid("Mach-O ULEB is unterminated"))
}

#[cfg(test)]
mod tests;
