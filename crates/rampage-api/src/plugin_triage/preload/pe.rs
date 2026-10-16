//! Raw admission for the native PE producers, before object::File or Binary exists. This is not linkage proof.
//!
//! Profile: whole-file AMD64 PE32+, <=96 nonoverlapping sections, inline UTF-8 section names, no COFF symbols,
//! no delay imports, resources, security, load-config, bound imports or unknown directories. Regular descriptors,
//! lookup thunks, IAT and referenced names must share one section (object's actual import-table mapping).
//! Exports and forwarders must fit the declared export-directory span. Debug records use matching raw/RVA
//! backing. TLS arrays and x64 unwind records must terminate/be fully backed; chained/indirect unwind is refused.
//! Relocations admit only ABSOLUTE padding and fully backed DIR64 targets. Section zero-fill is not metadata.
//! Referenced names are nonempty ASCII of at most 256 bytes; mangled-name prefixes are refused. The fixed
//! 240-byte optional header declares exactly 16 directories; NT headers must lie in the first 64 KiB. Export
//! tables require an address-table RVA and producer name even when empty. TLS zero-fill templates are refused.
//! Record admission uses the contract's 16,384-record cap; weighted repeated text has a 1 MiB cap, including
//! library reuse, constructor thunk names and imphash copies. Rich entries are bounded by the NT-header offset.
//!
//! Native opening also runs .eh_frame and Go recovery regardless of format: their section aliases/candidate
//! magics are refused. PE ObjC recovery is a no-op. RTTI, resource traversal, PDB/DWARF loading and base-relocation
//! iteration are not called by opening or triage preparation; no admission for those optional producers is
//! implied. Constructor Names does scan PE code for import thunks; its repeated names are charged here too.
//! Caps count referenced names on every use, not unique offsets, before any native vector or string allocation.

use rampage_plugin_contract::{MAX_INPUT_BYTES, MAX_RECORDS, MAX_TEXT_BYTES};

use super::{MAX_PLUGIN_TRIAGE_SOURCE_BYTES, invalid, span, u16_at, u32_at};
use crate::ApiError;

const MAX_SECTIONS: usize = 96;
const MAX_NAME: usize = 256;
const NAME_COPIES: usize = 16;

#[derive(Default)]
struct Budget {
    records: usize,
    names: usize,
    longest_import: usize,
}

impl Budget {
    fn records(&mut self, count: usize) -> Result<(), ApiError> {
        self.records = self.records.checked_add(count).ok_or_else(|| invalid("PE record budget overflow"))?;
        if self.records > MAX_RECORDS {
            return Err(invalid("PE metadata exceeds pre-loader record admission"));
        }
        Ok(())
    }

    fn name(&mut self, length: usize) -> Result<(), ApiError> {
        let copies = length.checked_add(8).and_then(|length| length.checked_mul(NAME_COPIES));
        self.names = copies
            .and_then(|length| self.names.checked_add(length))
            .ok_or_else(|| invalid("PE repeated-name budget overflow"))?;
        if self.names > MAX_INPUT_BYTES {
            return Err(invalid("PE repeated-name expansion exceeds pre-loader admission"));
        }
        Ok(())
    }
}

struct Pe<'a> {
    bytes: &'a [u8],
    sections: &'a [u8],
    optional: &'a [u8],
    base: u64,
}

impl<'a> Pe<'a> {
    fn section(&self, index: usize) -> Result<&'a [u8], ApiError> {
        span(self.sections, index * 40, 40)
    }

    fn directory(&self, index: usize) -> Result<(u32, usize), ApiError> {
        let offset = 112 + index * 8;
        Ok((u32_at(self.optional, offset)?, u32_at(self.optional, offset + 4)? as usize))
    }

    fn va(&self, rva: u32) -> Result<u64, ApiError> {
        self.base.checked_add(u64::from(rva)).ok_or_else(|| invalid("PE VA overflow"))
    }

    fn rva(&self, va: u64) -> Result<u32, ApiError> {
        va.checked_sub(self.base)
            .and_then(|rva| u32::try_from(rva).ok())
            .ok_or_else(|| invalid("PE TLS VA is not a width-safe RVA"))
    }

    fn locate(&self, rva: u32, length: usize) -> Result<(usize, &'a [u8]), ApiError> {
        let end = add(rva, length)?;
        self.va(end)?;
        for (index, section) in self.sections.as_chunks::<40>().0.iter().enumerate() {
            let start = u32_at(section, 12)?;
            let backed = u32_at(section, 8)?.min(u32_at(section, 16)?);
            if rva >= start && end <= add(start, backed as usize)? && rva < add(start, backed as usize)? {
                let offset = add(u32_at(section, 20)?, (rva - start) as usize)?;
                return Ok((index, span(self.bytes, offset as usize, length)?));
            }
        }
        Err(invalid("PE RVA requires full section backing, never raw padding, headers or zero-fill"))
    }

    fn within(&self, rva: u32, length: usize, section: usize) -> Result<&'a [u8], ApiError> {
        let (found, data) = self.locate(rva, length)?;
        if found != section {
            return Err(invalid("PE import references must share the producer's section mapping"));
        }
        Ok(data)
    }

    fn code(&self, rva: u32, length: usize) -> Result<(), ApiError> {
        let (index, _) = self.locate(rva, length)?;
        if u32_at(self.section(index)?, 36)? & 0x2000_0000 == 0 {
            return Err(invalid("PE function start is not fully backed executable code"));
        }
        Ok(())
    }

    fn text(&self, rva: u32, section: usize, budget: &mut Budget) -> Result<&'a [u8], ApiError> {
        let header = self.section(section)?;
        let end = add(u32_at(header, 12)?, u32_at(header, 8)?.min(u32_at(header, 16)?) as usize)?;
        let available = end.checked_sub(rva).ok_or_else(|| invalid("PE name RVA precedes its section"))?;
        let bytes = self.within(rva, (available as usize).min(MAX_NAME + 1), section)?;
        text(bytes, budget)
    }
}

pub(super) fn admit(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() > MAX_PLUGIN_TRIAGE_SOURCE_BYTES {
        return Err(invalid("plugin triage source exceeds 16 MiB"));
    }
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return Err(invalid("PE preload admission requires a DOS header"));
    }
    let nt = u32_at(bytes, 0x3c)? as usize;
    if !(64..=65536).contains(&nt) || span(bytes, nt, 4)? != b"PE\0\0" {
        return Err(invalid("PE DOS/NT header shape is outside preload admission"));
    }
    let coff = span(bytes, nt + 4, 20)?;
    if u16_at(coff, 0)? != 0x8664 || u16_at(coff, 16)? != 240 || u16_at(coff, 18)? & 2 == 0 {
        return Err(invalid("PE preload admission requires an AMD64 executable PE32+ header"));
    }
    if u32_at(coff, 8)? != 0 || u32_at(coff, 12)? != 0 {
        return Err(invalid("PE COFF symbol/string tables are outside preload admission"));
    }
    let count = u16_at(coff, 2)? as usize;
    if !(1..=MAX_SECTIONS).contains(&count) {
        return Err(invalid("PE section count exceeds preload admission"));
    }
    let optional = span(bytes, nt + 24, 240)?;
    if u16_at(optional, 0)? != 0x20b || u32_at(optional, 108)? != 16 {
        return Err(invalid("PE optional-header/directory shape is outside preload admission"));
    }
    let headers = u32_at(optional, 60)? as usize;
    if headers < nt + 264 + count * 40 {
        return Err(invalid("PE SizeOfHeaders does not cover the complete section table"));
    }
    span(bytes, 0, headers)?;
    let pe = Pe { bytes, optional, sections: span(bytes, nt + 264, count * 40)?, base: u64_at(optional, 24)? };
    let image_size = u32_at(optional, 56)?;
    pe.va(image_size)?;
    let mut budget = Budget::default();
    budget.records(count * 4 + nt / 8 + 16)?;
    for (index, section) in pe.sections.as_chunks::<40>().0.iter().enumerate() {
        let inline = &section[..8];
        let name = &inline[..inline.iter().position(|byte| *byte == 0).unwrap_or(8)];
        if name.starts_with(b"/") || std::str::from_utf8(name).is_err() {
            return Err(invalid("PE long or non-UTF-8 section names are outside preload admission"));
        }
        if matches!(name, b".got" | b".plt" | b".plt.sec" | b".plt.got" | b".iplt" | b"__stubs")
            || name.windows(7).any(|part| part == b"eh_fram")
            || name.windows(5).any(|part| part == b"gopcl")
        {
            return Err(invalid("PE cross-format recovery section alias is outside preload admission"));
        }
        budget.name(name.len())?;
        if u32_at(section, 24)? != 0
            || u32_at(section, 28)? != 0
            || u16_at(section, 32)? != 0
            || u16_at(section, 34)? != 0
        {
            return Err(invalid("PE COFF section relocation/line tables are outside preload admission"));
        }
        let start = u32_at(section, 12)?;
        let virtual_size = u32_at(section, 8)?;
        let raw_size = u32_at(section, 16)?;
        let raw = u32_at(section, 20)?;
        let end = add(start, virtual_size.max(raw_size) as usize)?;
        if start < headers as u32 || end > image_size || virtual_size == 0 {
            return Err(invalid("PE section RVA extent is outside the declared image"));
        }
        pe.va(end)?;
        let raw_end = add(raw, raw_size as usize)?;
        if raw_size != 0 {
            if raw < headers as u32 {
                return Err(invalid("PE raw section overlaps headers"));
            }
            span(bytes, raw as usize, raw_size as usize)?;
        }
        for other in pe.sections.as_chunks::<40>().0.iter().take(index) {
            let other_start = u32_at(other, 12)?;
            let other_end = add(other_start, u32_at(other, 8)?.max(u32_at(other, 16)?) as usize)?;
            let other_raw = u32_at(other, 20)?;
            let other_raw_size = u32_at(other, 16)?;
            if (start < other_end && other_start < end)
                || (raw_size != 0
                    && other_raw_size != 0
                    && raw < add(other_raw, other_raw_size as usize)?
                    && other_raw < raw_end)
            {
                return Err(invalid("PE ambiguous or overlapping section backing is not admitted"));
            }
        }
    }
    for index in 0..16 {
        let (rva, size) = pe.directory(index)?;
        if rva == 0 && size == 0 {
            continue;
        }
        if rva == 0 || size == 0 {
            return Err(invalid("PE half-present directory is outside preload admission"));
        }
        if !matches!(index, 0 | 1 | 3 | 5 | 6 | 9 | 12) {
            return Err(invalid("PE delay/resource/security/load-config or unknown directory is not admitted"));
        }
        pe.locate(rva, size)?;
    }
    if bytes
        .windows(8)
        .any(|header| matches!(header, [0xfb | 0xfa | 0xf0 | 0xf1, 0xff, 0xff, 0xff, 0, 0, 1 | 2 | 4, 8]))
    {
        return Err(invalid("possible Go recovery table is outside plugin preload admission"));
    }
    let entry = u32_at(optional, 16)?;
    if entry != 0 {
        pe.code(entry, 1)?;
    }
    imports(&pe, &mut budget)?;
    exports(&pe, &mut budget)?;
    unwind(&pe, &mut budget)?;
    tls(&pe, &mut budget)?;
    debug(&pe, &mut budget)?;
    relocations(&pe, &mut budget)?;
    // Names::new/thunk_names scans every six-byte code window, even overlapping candidates. Charge every
    // FF25 candidate, including ones that won't resolve, using the longest admitted import name.
    // object's Code classification accepts either CNT_CODE or MEM_EXECUTE, including execute-only sections.
    for section in pe.sections.as_chunks::<40>().0 {
        if u32_at(section, 36)? & (0x20 | 0x2000_0000) == 0 {
            continue;
        }
        let length = u32_at(section, 8)? as usize;
        if let Ok((_, data)) = pe.locate(u32_at(section, 12)?, length) {
            for _ in data.windows(6).filter(|window| window[..2] == [0xff, 0x25]) {
                budget.records(4)?;
                budget.name(budget.longest_import + 6)?;
            }
        }
    }
    Ok(())
}

fn imports(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(1)?;
    if rva == 0 {
        return Ok(());
    }
    let (section, table) = pe.locate(rva, size)?;
    for row in table.as_chunks::<20>().0 {
        budget.records(1)?;
        if row.iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        // A null native descriptor is recognized by OriginalFirstThunk, Name and FirstThunk, not timestamp.
        if u32_at(row, 0)? == 0 && u32_at(row, 12)? == 0 && u32_at(row, 16)? == 0 {
            return Err(invalid("PE noncanonical null import descriptor"));
        }
        let library = pe.text(u32_at(row, 12)?, section, budget)?;
        let iat = u32_at(row, 16)?;
        let lookup = match u32_at(row, 0)? {
            0 => iat,
            lookup => lookup,
        };
        let header = pe.section(section)?;
        let end = add(u32_at(header, 12)?, u32_at(header, 8)?.min(u32_at(header, 16)?) as usize)?;
        let length = end.checked_sub(lookup).ok_or_else(|| invalid("PE import lookup RVA precedes its section"))?;
        let thunks = pe.within(lookup, length as usize, section)?;
        let mut terminated = false;
        for (index, thunk) in thunks.as_chunks::<8>().0.iter().enumerate() {
            budget.records(4)?;
            let slot = pe.within(add(iat, index * 8)?, 8, section)?;
            let value = u64_at(thunk, 0)?;
            if value == 0 {
                if u64_at(slot, 0)? != 0 {
                    return Err(invalid("PE IAT is not terminated with its lookup table"));
                }
                terminated = true;
                break;
            }
            budget.name(library.len())?;
            let length = if value & (1 << 63) != 0 {
                // Keep ordinal semantics, not a textual '#n' lookup. Reject reserved bits and ordinal zero,
                // which object's masked address() would otherwise treat as a premature thunk terminator.
                if value & !(1 << 63 | 0xffff) != 0 || value as u16 == 0 {
                    return Err(invalid("PE ordinal thunk has reserved bits or a zero ordinal"));
                }
                6
            } else {
                if value > 0x7fff_ffff {
                    return Err(invalid("PE named thunk is not a width-safe canonical RVA"));
                }
                let name = value as u32;
                pe.within(name, 2, section)?;
                pe.text(add(name, 2)?, section, budget)?.len()
            };
            budget.longest_import = budget.longest_import.max(length);
            budget.name(length + 6)?;
        }
        if !terminated {
            return Err(invalid("PE import thunk list is not completely terminated"));
        }
    }
    Err(invalid("PE import descriptors must terminate inside their declared directory"))
}

fn exports(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(0)?;
    if rva == 0 {
        return Ok(());
    }
    let (_, table) = pe.locate(rva, size)?;
    let header = span(table, 0, 40)?;
    let functions = u32_at(header, 20)? as usize;
    let names = u32_at(header, 24)? as usize;
    budget.records(
        functions
            .checked_add(names)
            .and_then(|count| count.checked_mul(4))
            .ok_or_else(|| invalid("PE export count overflow"))?,
    )?;
    let ordinal_base = u32_at(header, 16)?;
    if ordinal_base > u32::from(u16::MAX) || ordinal_base.checked_add(functions as u32).is_none_or(|end| end > 65536) {
        return Err(invalid("PE export ordinal width exceeds native producer admission"));
    }
    let relative = |address: u32| {
        address
            .checked_sub(rva)
            .map(|offset| offset as usize)
            .ok_or_else(|| invalid("PE export reference precedes its producer directory"))
    };
    let producer = table
        .get(relative(u32_at(header, 12)?)?..)
        .ok_or_else(|| invalid("PE export producer name is outside its directory"))?;
    text(producer, budget)?;
    let addresses = span(table, relative(u32_at(header, 28)?)?, functions * 4)?;
    let pointers = if names == 0 { &[] } else { span(table, relative(u32_at(header, 32)?)?, names * 4)? };
    let ordinals = if names == 0 { &[] } else { span(table, relative(u32_at(header, 36)?)?, names * 2)? };
    let target = |address: u32, budget: &mut Budget| -> Result<(), ApiError> {
        if address >= rva && address < add(rva, size)? {
            let forwarder = text(&table[relative(address)?..], budget)?;
            let split = forwarder
                .iter()
                .rposition(|byte| *byte == b'.')
                .ok_or_else(|| invalid("PE forwarder has no library separator"))?;
            if split == 0 || split + 1 == forwarder.len() {
                return Err(invalid("PE forwarder has an empty library or symbol"));
            }
            if forwarder[split + 1] == b'#' {
                let digits = &forwarder[split + 2..];
                let ordinal = digits.iter().try_fold(0u16, |value, byte| {
                    byte.is_ascii_digit()
                        .then_some(())
                        .and_then(|_| value.checked_mul(10)?.checked_add(u16::from(*byte - b'0')))
                });
                if digits.is_empty() || ordinal.is_none_or(|ordinal| ordinal == 0) {
                    return Err(invalid("PE forwarder ordinal is not a nonzero u16"));
                }
            }
        } else if address != 0 {
            pe.locate(address, 1)?;
        }
        Ok(())
    };
    for address in addresses.as_chunks::<4>().0 {
        target(u32_at(address, 0)?, budget)?;
    }
    for index in 0..names {
        let ordinal = u16_at(ordinals, index * 2)? as usize;
        if ordinal >= functions || u32_at(addresses, ordinal * 4)? == 0 {
            return Err(invalid("PE named export references an absent address slot"));
        }
        let offset = relative(u32_at(pointers, index * 4)?)?;
        text(table.get(offset..).ok_or_else(|| invalid("PE export name is outside its directory"))?, budget)?;
        target(u32_at(addresses, ordinal * 4)?, budget)?;
    }
    Ok(())
}

fn unwind(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(3)?;
    if rva == 0 {
        return Ok(());
    }
    if size % 12 != 0 {
        return Err(invalid("PE exception directory has a partial runtime-function row"));
    }
    budget.records(size / 12 * 2)?;
    for row in pe.locate(rva, size)?.1.as_chunks::<12>().0 {
        let begin = u32_at(row, 0)?;
        let end = u32_at(row, 4)?;
        let info = u32_at(row, 8)?;
        if begin == 0 || end <= begin || info == 0 || info & 3 != 0 {
            return Err(invalid("PE indirect or malformed runtime-function row is not admitted"));
        }
        pe.code(begin, (end - begin) as usize)?;
        let header = pe.locate(info, 4)?.1;
        let flags = header[0] >> 3;
        if header[0] & 7 != 1 || flags & !3 != 0 {
            return Err(invalid("PE chained or unsupported unwind info is outside preload admission"));
        }
        let codes = usize::from(header[2]);
        let length = 4 + codes.next_multiple_of(2) * 2;
        pe.locate(info, length + if flags != 0 { 4 } else { 0 })?;
        if flags != 0 {
            let handler = u32_at(pe.locate(add(info, length)?, 4)?.1, 0)?;
            pe.code(handler, 1)?;
        }
    }
    Ok(())
}

fn tls(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(9)?;
    if rva == 0 {
        return Ok(());
    }
    if size != 40 {
        return Err(invalid("PE TLS directory must be exactly one PE32+ TLS header"));
    }
    let header = pe.locate(rva, size)?.1;
    let start = u64_at(header, 0)?;
    let end = u64_at(header, 8)?;
    if start != 0 || end != 0 {
        let length = end
            .checked_sub(start)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(|| invalid("PE TLS raw-data VA extent overflow"))?;
        pe.locate(pe.rva(start)?, length)?;
    }
    pe.locate(pe.rva(u64_at(header, 16)?)?, 4)?;
    if u32_at(header, 32)? != 0 {
        return Err(invalid("PE TLS zero-fill templates are outside preload admission"));
    }
    let callbacks = u64_at(header, 24)?;
    if callbacks == 0 {
        return Ok(());
    }
    let callbacks = pe.rva(callbacks)?;
    for index in 0..4096 {
        budget.records(2)?;
        let callback = u64_at(pe.locate(add(callbacks, index * 8)?, 8)?.1, 0)?;
        if callback == 0 {
            return Ok(());
        }
        pe.code(pe.rva(callback)?, 1)?;
    }
    Err(invalid("PE TLS callbacks exceed complete terminated-array admission"))
}

fn debug(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(6)?;
    if rva == 0 {
        return Ok(());
    }
    if size % 28 != 0 {
        return Err(invalid("PE debug directory contains a partial row"));
    }
    budget.records(size / 28)?;
    for row in pe.locate(rva, size)?.1.as_chunks::<28>().0 {
        let length = u32_at(row, 16)? as usize;
        let raw = u32_at(row, 24)? as usize;
        if length == 0 && raw == 0 && u32_at(row, 20)? == 0 && u32_at(row, 12)? != 2 {
            continue;
        }
        let data = span(pe.bytes, raw, length)?;
        let mapped = pe.locate(u32_at(row, 20)?, length)?.1;
        if data.as_ptr() != mapped.as_ptr() {
            return Err(invalid("PE debug raw offset and RVA do not identify the same backing"));
        }
        if u32_at(row, 12)? == 2 {
            if span(data, 0, 4)? != b"RSDS" {
                return Err(invalid("PE non-RSDS CodeView record is outside preload admission"));
            }
            span(data, 0, 24)?;
            text(&data[24..], budget)?;
        }
    }
    Ok(())
}

fn relocations(pe: &Pe<'_>, budget: &mut Budget) -> Result<(), ApiError> {
    let (rva, size) = pe.directory(5)?;
    if rva == 0 {
        return Ok(());
    }
    let mut data = pe.locate(rva, size)?.1;
    while !data.is_empty() {
        let page = u32_at(data, 0)?;
        let length = u32_at(data, 4)? as usize;
        if page & 0xfff != 0 || length <= 8 || !length.is_multiple_of(4) {
            return Err(invalid("PE relocation block shape is outside preload admission"));
        }
        let block = span(data, 0, length)?;
        budget.records(length / 2)?;
        for entry in block[8..].as_chunks::<2>().0 {
            let entry = u16_at(entry, 0)?;
            match entry >> 12 {
                0 => {}
                10 => {
                    pe.locate(add(page, usize::from(entry & 0xfff))?, 8)?;
                }
                _ => return Err(invalid("PE relocation type is outside AMD64 DIR64 preload admission")),
            }
        }
        data = &data[length..];
    }
    Ok(())
}

fn text<'a>(bytes: &'a [u8], budget: &mut Budget) -> Result<&'a [u8], ApiError> {
    let length = bytes
        .iter()
        .take(MAX_NAME + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid("PE referenced name exceeds bounded terminated-text admission"))?;
    let name = &bytes[..length];
    if length == 0 || length > MAX_TEXT_BYTES - 6 || !name.is_ascii() {
        return Err(invalid("PE preload names must be nonempty bounded ASCII"));
    }
    if name.starts_with(b"?")
        || name.starts_with(b"_Z")
        || name.starts_with(b"__Z")
        || name.starts_with(b"_R")
        || name.starts_with(b"__R")
        || name.starts_with(b"ZN")
    {
        return Err(invalid("PE mangled-name recovery is outside preload admission"));
    }
    budget.name(length)?;
    Ok(name)
}

fn add(rva: u32, length: usize) -> Result<u32, ApiError> {
    u32::try_from(length)
        .ok()
        .and_then(|length| rva.checked_add(length))
        .ok_or_else(|| invalid("PE RVA/file extent overflow"))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ApiError> {
    Ok(u64::from_le_bytes(span(bytes, offset, 8)?.try_into().map_err(|_| invalid("invalid PE u64"))?))
}

#[cfg(test)]
mod tests;
