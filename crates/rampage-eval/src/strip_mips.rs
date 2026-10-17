use std::borrow::Cow;
use std::mem::size_of;
use std::ops::Range;

use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{Endianness, FileKind};

pub(super) const SHT_MIPS_ABIFLAGS: elf::SectionType = elf::SectionType(0x7000_002a);

type Checked<T> = Result<T, Box<dyn std::error::Error>>;

fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    message.into()
}

pub(super) fn prepare(input: &[u8]) -> Result<(Cow<'_, [u8]>, Option<usize>), String> {
    let result = match FileKind::parse(input).map_err(|error| error.to_string())? {
        FileKind::Elf32 => prepare_elf::<elf::FileHeader32<Endianness>>(input),
        FileKind::Elf64 => prepare_elf::<elf::FileHeader64<Endianness>>(input),
        _ => return Err("Not an ELF file".to_owned()),
    };
    result.map_err(|error| error.to_string())
}

fn prepare_elf<Elf: FileHeader<Endian = Endianness>>(input: &[u8]) -> Checked<(Cow<'_, [u8]>, Option<usize>)> {
    let header = Elf::parse(input)?;
    let endian = header.endian()?;
    if header.e_machine(endian) != elf::EM_MIPS {
        return Ok((Cow::Borrowed(input), None));
    }
    let sections = header.sections(endian, input)?;
    let mut abiflags = None;
    for (index, section) in sections.enumerate().skip(1) {
        if section.sh_type(endian) != SHT_MIPS_ABIFLAGS {
            continue;
        }
        let data = section.data(endian, input)?;
        let size: u64 = section.sh_size(endian).into();
        let entry_size: u64 = section.sh_entsize(endian).into();
        let alignment: u64 = section.sh_addralign(endian).into();
        let offset: u64 = section.sh_offset(endian).into();
        let address: u64 = section.sh_addr(endian).into();
        if abiflags.is_some()
            || sections.section_name(endian, section)? != b".MIPS.abiflags"
            || section.sh_flags(endian) != elf::SHF_ALLOC
            || section.sh_link(endian) != 0
            || section.sh_info(endian) != 0
            || size != 24
            || entry_size != 24
            || alignment != 8
            || !offset.is_multiple_of(8)
            || !address.is_multiple_of(8)
            || data.get(..2) != Some(&[0, 0])
        {
            return Err(invalid("Unsupported MIPS ABI flags layout"));
        }
        abiflags = Some(index.0);
    }
    let Some(index) = abiflags else {
        return Ok((Cow::Borrowed(input), None));
    };

    let table_start: u64 = header.e_shoff(endian).into();
    let table_size = (sections.len() as u64)
        .checked_mul(size_of::<Elf::SectionHeader>() as u64)
        .ok_or_else(|| invalid("Invalid ELF section table size"))?;
    let table_end = table_start.checked_add(table_size).ok_or_else(|| invalid("Invalid ELF section table range"))?;
    let (program_range, _) = mapped_ranges::<Elf>(input)?;
    for section in sections.iter().skip(1) {
        if let Some((start, size)) = section.file_range(endian) {
            let end = start.checked_add(size).ok_or_else(|| invalid("Invalid ELF section range"))?;
            if size != 0 && start < table_end && table_start < end {
                return Err(invalid("ELF section data overlaps section table"));
            }
            if size != 0
                && (start < size_of::<Elf>() as u64
                    || (start < program_range.end as u64 && (program_range.start as u64) < end))
            {
                return Err(invalid("ELF section data overlaps file headers"));
            }
        }
    }

    let offset = table_start + index as u64 * size_of::<Elf::SectionHeader>() as u64 + 4;
    let offset = usize::try_from(offset).map_err(|_| invalid("Invalid ELF section type offset"))?;
    let mut normalized = input.to_vec();
    let field = normalized.get_mut(offset..offset + 4).ok_or_else(|| invalid("Invalid ELF section type range"))?;
    // ABIFlags_v0 has no section/symbol indices. The builder can copy it as opaque data,
    // but its reader lacks this type; strip restores the type before the writer sees it.
    let progbits =
        if header.is_little_endian() { elf::SHT_PROGBITS.0.to_le_bytes() } else { elf::SHT_PROGBITS.0.to_be_bytes() };
    field.copy_from_slice(&progbits);
    Ok((Cow::Owned(normalized), Some(index - 1)))
}

fn file_range(input: &[u8], start: u64, size: u64) -> Checked<Range<usize>> {
    let end = start.checked_add(size).ok_or_else(|| invalid("ELF file range overflow"))?;
    if end > input.len() as u64 {
        return Err(invalid("ELF file range out of bounds"));
    }
    Ok(start as usize..end as usize)
}

fn overlaps(left: &Range<usize>, right: &Range<usize>) -> bool {
    !left.is_empty() && !right.is_empty() && left.start < right.end && right.start < left.end
}

fn mapped_ranges<Elf: FileHeader<Endian = Endianness>>(input: &[u8]) -> Checked<(Range<usize>, Vec<Range<usize>>)> {
    let header = Elf::parse(input)?;
    let endian = header.endian()?;
    if usize::from(header.e_ehsize(endian)) != size_of::<Elf>() {
        return Err(invalid("Invalid ELF header size"));
    }
    let sections = header.sections(endian, input)?;
    let table = file_range(
        input,
        header.e_shoff(endian).into(),
        (sections.len() as u64)
            .checked_mul(size_of::<Elf::SectionHeader>() as u64)
            .ok_or_else(|| invalid("ELF section table size overflow"))?,
    )?;
    let programs = header.program_headers(endian, input)?;
    let program_range = file_range(input, header.e_phoff(endian).into(), std::mem::size_of_val(programs) as u64)?;
    let file_header = 0..size_of::<Elf>();
    if overlaps(&file_header, &program_range) || overlaps(&file_header, &table) || overlaps(&program_range, &table) {
        return Err(invalid("Overlapping ELF header tables"));
    }
    let mut loads = Vec::new();
    for program in programs {
        let size: u64 = program.p_filesz(endian).into();
        let range = file_range(input, program.p_offset(endian).into(), size)?;
        if program.p_type(endian) != elf::PT_LOAD {
            continue;
        }
        let memory_size: u64 = program.p_memsz(endian).into();
        let address: u64 = program.p_vaddr(endian).into();
        if size > memory_size || address.checked_add(memory_size).is_none() {
            return Err(invalid("Invalid ELF load memory range"));
        }
        if overlaps(&range, &table) {
            return Err(invalid("ELF load overlaps section table"));
        }
        loads.push(range);
    }
    Ok((program_range, loads))
}

pub(super) fn verify_loaded_bytes(input: &[u8], output: &[u8]) -> Result<(), String> {
    let result = match FileKind::parse(input).map_err(|error| error.to_string())? {
        FileKind::Elf32 => verify_elf::<elf::FileHeader32<Endianness>>(input, output),
        FileKind::Elf64 => verify_elf::<elf::FileHeader64<Endianness>>(input, output),
        _ => return Err("Not an ELF file".to_owned()),
    };
    result.map_err(|error| error.to_string())
}

fn verify_elf<Elf: FileHeader<Endian = Endianness>>(input: &[u8], output: &[u8]) -> Checked<()> {
    let (programs, loads) = mapped_ranges::<Elf>(input)?;
    let (output_programs, output_loads) = mapped_ranges::<Elf>(output)?;
    if programs != output_programs || loads != output_loads || input[programs.clone()] != output[output_programs] {
        return Err(invalid("Stripping changed ELF program headers"));
    }
    let header = Elf::parse(input)?;
    let (section_offset, section_counts) = if header.is_type_64() { (40..48, 60..64) } else { (32..36, 48..52) };
    // Only e_shoff, e_shnum and e_shstrndx may change, even when the ELF header is mapped.
    let allowed = |offset: usize| section_offset.contains(&offset) || section_counts.contains(&offset);
    for offset in 0..size_of::<Elf>() {
        if !allowed(offset) && input[offset] != output[offset] {
            return Err(invalid("Stripping changed ELF file header"));
        }
    }
    for range in loads {
        for offset in range {
            if !allowed(offset) && input[offset] != output[offset] {
                return Err(invalid("Stripping changed file-backed ELF load bytes"));
            }
        }
    }
    Ok(())
}
