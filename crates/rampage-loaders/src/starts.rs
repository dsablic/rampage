//! Function start addresses recorded by the toolchain in format metadata.

use object::Endianness;
use object::LittleEndian as LE;
use object::read::macho::{LoadCommandIterator, LoadCommandVariant};
use object::{Object, macho, pe};

use crate::Binary;

/// Decodes `LC_FUNCTION_STARTS`: ULEB128 deltas starting from `text_address`, ended by a zero delta.
pub(crate) fn macho(parsed: &object::File, image: &[u8], text_address: u64) -> Vec<u64> {
    let Some(data) = macho_function_starts_data(parsed, image) else { return Vec::new() };
    let mut starts = Vec::new();
    let mut address = text_address;
    let mut bytes = data;
    while let Some((delta, rest)) = read_uleb128(bytes) {
        if delta == 0 {
            break;
        }
        let Some(next) = address.checked_add(delta) else { break };
        address = next;
        starts.push(address);
        bytes = rest;
    }
    starts
}

fn macho_function_starts_data<'a>(parsed: &object::File, image: &'a [u8]) -> Option<&'a [u8]> {
    let (mut commands, endian) = macho_load_commands(parsed)?;
    while let Ok(Some(command)) = commands.next() {
        if command.cmd() != macho::LC_FUNCTION_STARTS {
            continue;
        }
        let Ok(LoadCommandVariant::LinkeditData(linkedit)) = command.variant() else { continue };
        let start = usize::try_from(linkedit.dataoff.get(endian)).ok()?;
        let len = usize::try_from(linkedit.datasize.get(endian)).ok()?;
        return image.get(start..start.checked_add(len)?);
    }
    None
}

pub(crate) fn macho_load_commands<'data>(
    parsed: &object::File<'data>,
) -> Option<(LoadCommandIterator<'data, Endianness>, Endianness)> {
    match parsed {
        object::File::MachO32(file) => Some((file.macho_load_commands().ok()?, file.endian())),
        object::File::MachO64(file) => Some((file.macho_load_commands().ok()?, file.endian())),
        _ => None,
    }
}

fn read_uleb128(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate() {
        let shift = 7 * index as u32;
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, &bytes[index + 1..]));
        }
    }
    None
}

/// The x64 exception directory (`.pdata`) location as an absolute address and size. Other machines use different
/// `RUNTIME_FUNCTION` layouts (ARM64 entries are 8 bytes), so they are not read here.
pub(crate) fn pe_exception_directory(parsed: &object::File) -> Option<(u64, u64)> {
    if parsed.architecture() != object::Architecture::X86_64 {
        return None;
    }
    let directory = match parsed {
        object::File::Pe64(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION),
        object::File::Pe32(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION),
        _ => None,
    }?;
    let address = parsed.relative_address_base().checked_add(directory.virtual_address.get(LE).into())?;
    Some((address, directory.size.get(LE).into()))
}

const RUNTIME_FUNCTION_SIZE: usize = 12;
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Reads x64 `RUNTIME_FUNCTION` entries, skipping chained entries, which describe fragments of another function.
/// A directory larger than its file data is read as far as the data goes, with a warning.
pub(crate) fn pe(binary: &Binary, image_base: u64, (address, size): (u64, u64)) -> (Vec<u64>, Option<String>) {
    let available = binary.read_to_segment_end(address).unwrap_or_default();
    let warning = (size > available.len() as u64)
        .then(|| format!(".pdata directory claims {size:#x} bytes but only {:#x} are present", available.len()));
    let table = &available[..size.min(available.len() as u64) as usize];
    let starts = table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .filter_map(|entry| {
            let begin = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            let unwind = u32::from_le_bytes(entry[8..12].try_into().unwrap());
            if begin == 0 || unwind & 1 != 0 {
                return None;
            }
            let flags = binary.read(image_base.checked_add(u64::from(unwind))?, 1)?[0] >> 3;
            if flags & UNW_FLAG_CHAININFO != 0 {
                return None;
            }
            image_base.checked_add(u64::from(begin))
        })
        .collect();
    (starts, warning)
}

#[cfg(test)]
mod tests {
    use super::read_uleb128;

    #[test]
    fn decodes_uleb128() {
        assert_eq!(read_uleb128(&[0x02, 0xff]), Some((2, &[0xff][..])));
        assert_eq!(read_uleb128(&[0xe5, 0x8e, 0x26]), Some((624485, &[][..])));
    }

    #[test]
    fn rejects_truncated_and_overlong_uleb128() {
        assert_eq!(read_uleb128(&[0x80]), None);
        assert_eq!(read_uleb128(&[0xff; 11]), None);
    }
}
