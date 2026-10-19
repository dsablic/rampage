//! Function start addresses recorded by the toolchain in format metadata.

use object::LittleEndian as LE;
use object::read::macho::LoadCommandVariant;
use object::{Object, macho, pe};
use rampage_arch::bytes::read_uint;

use crate::Binary;

mod arm_exidx;
pub(crate) use arm_exidx::{arm_exidx, arm_exidx_tables};

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
    let (mut commands, endian) = crate::macho::load_commands(parsed)?;
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

/// Where an x64 image's exception directory (`.pdata`) lies: the image base, and the directory's absolute address
/// and size. Other machines use different `RUNTIME_FUNCTION` layouts (ARM64 entries are 8 bytes), so they are not
/// read here.
pub(crate) struct ExceptionDirectory {
    image_base: u64,
    address: u64,
    size: u64,
}

pub(crate) fn pe_exception_directory(parsed: &object::File) -> Option<ExceptionDirectory> {
    if parsed.architecture() != object::Architecture::X86_64 {
        return None;
    }
    let directory = match parsed {
        object::File::Pe64(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION),
        object::File::Pe32(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION),
        _ => None,
    }?;
    let image_base = parsed.relative_address_base();
    let address = image_base.checked_add(directory.virtual_address.get(LE).into())?;
    Some(ExceptionDirectory { image_base, address, size: directory.size.get(LE).into() })
}

/// Where a PE's thread-local-storage directory lies: its absolute address and the image's pointer width.
pub(crate) struct TlsDirectory {
    address: u64,
    pointer_size: u8,
}

pub(crate) fn pe_tls_directory(parsed: &object::File) -> Option<TlsDirectory> {
    let directory = match parsed {
        object::File::Pe64(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_TLS),
        object::File::Pe32(file) => file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_TLS),
        _ => None,
    }?;
    let rva = directory.virtual_address.get(LE);
    if rva == 0 {
        return None;
    }
    let address = parsed.relative_address_base().checked_add(rva.into())?;
    Some(TlsDirectory { address, pointer_size: if parsed.is_64() { 8 } else { 4 } })
}

/// A hostile image cannot register more initializers than this; a benign one registers a handful.
const MAX_TLS_CALLBACKS: usize = 4096;

/// Reads the TLS callback array into function starts. The TLS directory's `AddressOfCallBacks` field (the
/// fourth pointer, after the two raw-data bounds and the index address) is the virtual address of a
/// NUL-terminated array of callback VAs. Each callback runs before `main` on thread creation and teardown, so
/// static discovery from the entry point misses it; init code is commonly hidden here. Bounded and
/// bounds-checked against mapped image bytes; non-code addresses are dropped by the caller's `is_code` filter.
pub(crate) fn pe_tls(binary: &Binary, directory: &TlsDirectory) -> Vec<u64> {
    let TlsDirectory { address, pointer_size } = *directory;
    let stride = u64::from(pointer_size);
    let Some(callbacks_field) = address.checked_add(stride.saturating_mul(3)) else { return Vec::new() };
    let Some(array) = read_le_pointer(binary, callbacks_field, pointer_size) else { return Vec::new() };
    if array == 0 {
        return Vec::new();
    }
    let mut starts = Vec::new();
    for index in 0..MAX_TLS_CALLBACKS as u64 {
        let Some(entry) = index.checked_mul(stride).and_then(|offset| array.checked_add(offset)) else { break };
        match read_le_pointer(binary, entry, pointer_size) {
            Some(0) | None => break,
            Some(callback) => starts.push(callback),
        }
    }
    starts
}

/// Reads a little-endian pointer (PE is always little-endian) from mapped image bytes, or `None` when the
/// location is not file-backed.
fn read_le_pointer(binary: &Binary, address: u64, size: u8) -> Option<u64> {
    read_uint(binary.read(address, u64::from(size))?, 0, usize::from(size), false)
}

const RUNTIME_FUNCTION_SIZE: usize = 12;
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Reads x64 `RUNTIME_FUNCTION` entries, skipping chained entries, which describe fragments of another function.
/// A directory larger than its file data is read as far as the data goes, with a warning.
pub(crate) fn pe(binary: &Binary, directory: &ExceptionDirectory) -> (Vec<u64>, Option<String>) {
    let ExceptionDirectory { image_base, address, size } = *directory;
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

/// Reads function starts from the `.eh_frame` call frame information that most ELF toolchains emit even in
/// stripped binaries: the initial location of every FDE. Parsing stops at the first malformed record, with a
/// warning.
pub(crate) fn eh_frame(binary: &Binary) -> (Vec<u64>, Option<String>) {
    let Some(section) =
        binary.sections.iter().find(|section| section.name == ".eh_frame" || section.name == "__eh_frame")
    else {
        return (Vec::new(), None);
    };
    let available = binary.read_to_segment_end(section.address).unwrap_or_default();
    let data = &available[..section.size.min(available.len() as u64) as usize];
    let Some(pointer_size) = binary.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8)) else {
        return (
            Vec::new(),
            Some(format!(
                "{} not inspected: absolute encoded-address width is unavailable or unsupported",
                section.name
            )),
        );
    };
    let pointer_size = usize::from(pointer_size);
    let mut starts = Vec::new();
    let mut cies: std::collections::HashMap<usize, Option<u8>> = std::collections::HashMap::new();
    let mut offset = 0;
    while offset < data.len() {
        match eh_frame_record(data, binary.big_endian, section.address, offset, pointer_size, &mut cies) {
            Some((next, start)) => {
                starts.extend(start);
                offset = next;
            }
            None => {
                let warning = format!("{} is malformed at offset {offset:#x}; later entries ignored", section.name);
                return (starts, Some(warning));
            }
        }
    }
    (starts, None)
}

/// Parses the record at `offset`, returning the next record's offset and, for an FDE, its initial location.
/// `cies` caches each CIE's FDE pointer encoding (`None` for the default absolute encoding).
fn eh_frame_record(
    data: &[u8],
    big_endian: bool,
    base: u64,
    offset: usize,
    pointer_size: usize,
    cies: &mut std::collections::HashMap<usize, Option<u8>>,
) -> Option<(usize, Option<u64>)> {
    let mut cursor = Cursor { data, position: offset, big_endian };
    let length = cursor.u32()?;
    if length == 0 {
        // A zero length is a terminator.
        return Some((data.len(), None));
    }
    let length = if length == 0xffff_ffff { usize::try_from(cursor.u64()?).ok()? } else { length as usize };
    let body = cursor.position;
    let end = body.checked_add(length).filter(|&end| end <= data.len())?;
    let id_position = cursor.position;
    let id = cursor.u32()?;
    if id == 0 {
        let mut cie = Cursor { data: &data[..end], ..cursor };
        cies.insert(offset, cie_pointer_encoding(&mut cie, pointer_size)?);
        return Some((end, None));
    }
    let cie = id_position.checked_sub(id as usize)?;
    let encoding = match cies.get(&cie) {
        Some(&encoding) => encoding,
        None => return Some((end, None)),
    };
    let mut cursor = Cursor { data: &data[..end], ..cursor };
    let start = cursor.encoded_pointer(encoding.unwrap_or(0), base, pointer_size)?;
    let range = cursor.encoded_pointer(encoding.unwrap_or(0) & 0x0f, base, pointer_size)?;
    Some((end, (range != 0 && start != 0).then_some(start)))
}

/// Skips a CIE's fields up to its augmentation data and returns the FDE pointer encoding (`R`), if any.
fn cie_pointer_encoding(cursor: &mut Cursor, pointer_size: usize) -> Option<Option<u8>> {
    let version = cursor.u8()?;
    let augmentation = cursor.c_string()?;
    if augmentation.contains("eh") {
        return None;
    }
    cursor.uleb128()?; // code alignment
    cursor.sleb128()?; // data alignment
    if version == 1 {
        cursor.u8()?;
    } else {
        cursor.uleb128()?;
    }
    let Some(flags) = augmentation.strip_prefix('z') else { return Some(None) };
    // Read the augmentation data on its own, so that a misread entry cannot run into the CIE's instructions.
    let length = usize::try_from(cursor.uleb128()?).ok()?;
    let augmentation_data = cursor.take(length)?;
    let mut cursor = Cursor { data: augmentation_data, position: 0, ..*cursor };
    for flag in flags.chars() {
        match flag {
            'R' => return Some(Some(cursor.u8()?)),
            'P' => {
                let encoding = cursor.u8()?;
                cursor.encoded_pointer(encoding, 0, pointer_size)?;
            }
            'L' => {
                cursor.u8()?;
            }
            'S' | 'B' | 'G' => {}
            _ => return Some(None),
        }
    }
    Some(None)
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
    big_endian: bool,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let bytes = self.data.get(self.position..self.position.checked_add(len)?)?;
        self.position += len;
        Some(bytes)
    }

    /// A `len`-byte unsigned integer in the data's byte order.
    fn unsigned(&mut self, len: usize) -> Option<u64> {
        read_uint(self.take(len)?, 0, len, self.big_endian)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.unsigned(4).map(|value| value as u32)
    }

    fn u64(&mut self) -> Option<u64> {
        self.unsigned(8)
    }

    fn c_string(&mut self) -> Option<String> {
        let rest = self.data.get(self.position..)?;
        let len = rest.iter().position(|&byte| byte == 0)?;
        let text = String::from_utf8_lossy(&rest[..len]).into_owned();
        self.position += len + 1;
        Some(text)
    }

    fn uleb128(&mut self) -> Option<u64> {
        let (value, rest) = read_uleb128(self.data.get(self.position..)?)?;
        self.position = self.data.len() - rest.len();
        Some(value)
    }

    fn sleb128(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            if shift >= 64 {
                return None;
            }
            value |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= -1 << shift;
                }
                return Some(value);
            }
        }
    }

    /// Reads a `DW_EH_PE_*` encoded pointer. Only absolute and PC-relative applications are supported.
    fn encoded_pointer(&mut self, encoding: u8, base: u64, pointer_size: usize) -> Option<u64> {
        let field = base.checked_add(self.position as u64)?;
        let value = match encoding & 0x0f {
            0x00 => self.unsigned(pointer_size)?,
            0x01 => self.uleb128()?,
            0x02 => self.unsigned(2)?,
            0x03 => u64::from(self.u32()?),
            0x04 | 0x0c => self.u64()?,
            0x09 => self.sleb128()? as u64,
            0x0a => self.unsigned(2)? as i16 as i64 as u64,
            0x0b => self.u32()? as i32 as i64 as u64,
            _ => return None,
        };
        match encoding & 0x70 {
            0x00 => Some(value),
            0x10 => Some(field.wrapping_add(value)),
            _ => None,
        }
    }
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
    fn eh_frame_records_survive_every_truncation() {
        // A CIE with augmentation "zR" and pcrel|sdata4 FDE pointers, then one FDE starting 0x10 bytes before
        // its initial-location field.
        let cie: &[u8] =
            &[0x14, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 0x10, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0];
        let fde: &[u8] = &[0x14, 0, 0, 0, 0x1c, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = [cie, fde].concat();
        let mut cies = std::collections::HashMap::new();
        let (next, start) = super::eh_frame_record(&data, false, 0x1000, 0, 8, &mut cies).unwrap();
        assert_eq!((next, start), (cie.len(), None));
        let (_, start) = super::eh_frame_record(&data, false, 0x1000, next, 8, &mut cies).unwrap();
        assert_eq!(start, Some(0x1000 + cie.len() as u64 + 8 - 0x10));
        for len in 0..data.len() {
            let mut cies = std::collections::HashMap::new();
            let _ = super::eh_frame_record(&data[..len], false, 0x1000, 0, 8, &mut cies);
        }
    }

    #[test]
    fn eh_frame_personality_pointers_use_the_target_pointer_size() {
        // CIE "zPLR" for i386: an absptr personality is 4 bytes, then L and R (absptr) encodings.
        let cie: &[u8] = &[
            0x1b, 0, 0, 0, 0, 0, 0, 0, 1, b'z', b'P', b'L', b'R', 0, 1, 0x7c, 8, 7, 0, 0x10, 0x20, 0x30, 0x40, 0, 0,
            0x0c, 4, 4, 0x88, 1, 0,
        ];
        // FDE: initial location 0x08049000, range 0x10, augmentation length 0.
        let fde: &[u8] = &[0x10, 0, 0, 0, 0x23, 0, 0, 0, 0x00, 0x90, 0x04, 0x08, 0x10, 0, 0, 0, 0, 0, 0, 0];
        let data = [cie, fde].concat();
        let mut cies = std::collections::HashMap::new();
        let (next, _) = super::eh_frame_record(&data, false, 0x1000, 0, 4, &mut cies).unwrap();
        assert_eq!(next, cie.len());
        let (_, start) = super::eh_frame_record(&data, false, 0x1000, next, 4, &mut cies).unwrap();
        assert_eq!(start, Some(0x0804_9000));
    }

    #[test]
    fn eh_frame_reads_big_endian_records() {
        // The first test's records, byte-swapped: a CIE with "zR" and pcrel|sdata4 pointers, then one FDE.
        let cie: &[u8] =
            &[0, 0, 0, 0x14, 0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 0x10, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0];
        let fde: &[u8] = &[0, 0, 0, 0x14, 0, 0, 0, 0x1c, 0xff, 0xff, 0xff, 0xf0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = [cie, fde].concat();
        let mut cies = std::collections::HashMap::new();
        let (next, _) = super::eh_frame_record(&data, true, 0x1000, 0, 8, &mut cies).unwrap();
        let (_, start) = super::eh_frame_record(&data, true, 0x1000, next, 8, &mut cies).unwrap();
        assert_eq!(start, Some(0x1000 + cie.len() as u64 + 8 - 0x10));
    }

    #[test]
    fn rejects_truncated_and_overlong_uleb128() {
        assert_eq!(read_uleb128(&[0x80]), None);
        assert_eq!(read_uleb128(&[0xff; 11]), None);
    }
}
