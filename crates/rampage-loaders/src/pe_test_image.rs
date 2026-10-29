//! A minimal PE builder for unit tests: headers, one read-write section at [`SECTION_RVA`] holding the given bytes,
//! and the given data directories.

pub(crate) const SECTION_RVA: u32 = 0x1000;
pub(crate) const IMAGE_BASE_32: u64 = 0x40_0000;
pub(crate) const IMAGE_BASE_64: u64 = 0x1_4000_0000;
const SECTION_FILE_OFFSET: u32 = 0x200;

pub(crate) struct TestPe {
    pub(crate) bits: u8,
    pub(crate) section: Vec<u8>,
    /// (directory index, RVA, size).
    pub(crate) directories: Vec<(usize, u32, u32)>,
    pub(crate) dll_characteristics: u16,
    /// The COFF Machine; `None` for x86 or x64 by `bits`.
    pub(crate) machine: Option<u16>,
}

impl TestPe {
    pub(crate) fn new(bits: u8, section: Vec<u8>) -> Self {
        Self { bits, section, directories: Vec::new(), dll_characteristics: 0, machine: None }
    }

    pub(crate) fn directory(mut self, index: usize, rva: u32, size: u32) -> Self {
        self.directories.push((index, rva, size));
        self
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let put16 =
            |bytes: &mut Vec<u8>, at: usize, value: u16| bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        let put32 =
            |bytes: &mut Vec<u8>, at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let raw_size = self.section.len().div_ceil(0x200).max(1) * 0x200;
        let mut bytes = vec![0; SECTION_FILE_OFFSET as usize + raw_size];
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let wide = self.bits == 64;
        put16(&mut bytes, 0x84, self.machine.unwrap_or(if wide { 0x8664 } else { 0x14c }));
        put16(&mut bytes, 0x86, 1);
        let optional_size: u16 = if wide { 240 } else { 224 };
        put16(&mut bytes, 0x94, optional_size);
        put16(&mut bytes, 0x96, if wide { 0x22 } else { 0x102 });
        let optional = 0x98;
        put16(&mut bytes, optional, if wide { 0x20b } else { 0x10b });
        put32(&mut bytes, optional + 16, SECTION_RVA);
        if wide {
            bytes[optional + 24..optional + 32].copy_from_slice(&IMAGE_BASE_64.to_le_bytes());
        } else {
            put32(&mut bytes, optional + 28, IMAGE_BASE_32 as u32);
        }
        put32(&mut bytes, optional + 32, 0x1000);
        put32(&mut bytes, optional + 36, 0x200);
        let image_size = SECTION_RVA + (self.section.len().div_ceil(0x1000).max(1) * 0x1000) as u32;
        put32(&mut bytes, optional + 56, image_size);
        put32(&mut bytes, optional + 60, SECTION_FILE_OFFSET);
        put16(&mut bytes, optional + 68, 3);
        put16(&mut bytes, optional + 70, self.dll_characteristics);
        let (count_at, directories) =
            if wide { (optional + 108, optional + 112) } else { (optional + 92, optional + 96) };
        put32(&mut bytes, count_at, 16);
        for &(index, rva, size) in &self.directories {
            put32(&mut bytes, directories + index * 8, rva);
            put32(&mut bytes, directories + index * 8 + 4, size);
        }
        let section = optional + usize::from(optional_size);
        bytes[section..section + 8].copy_from_slice(b".data\0\0\0");
        put32(&mut bytes, section + 8, self.section.len().max(1) as u32);
        put32(&mut bytes, section + 12, SECTION_RVA);
        put32(&mut bytes, section + 16, raw_size as u32);
        put32(&mut bytes, section + 20, SECTION_FILE_OFFSET);
        put32(&mut bytes, section + 36, 0xc000_0040);
        let start = SECTION_FILE_OFFSET as usize;
        bytes[start..start + self.section.len()].copy_from_slice(&self.section);
        bytes
    }
}
