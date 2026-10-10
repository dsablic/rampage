use rampage_loaders::Binary;

/// The view of a program's address space that analysis needs.
pub trait Memory: Sync {
    /// File-backed bytes from `address` to the end of its region, or `None` when unmapped.
    fn bytes_from(&self, address: u64) -> Option<&[u8]>;
    fn is_mapped(&self, address: u64) -> bool;
    fn is_executable(&self, address: u64) -> bool;
}

impl Memory for Binary {
    fn bytes_from(&self, address: u64) -> Option<&[u8]> {
        self.read_to_segment_end(address)
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.segment_containing(address).is_some()
    }

    fn is_executable(&self, address: u64) -> bool {
        self.is_code(address)
    }
}

/// A single executable region, for tests and raw shellcode.
pub struct FlatMemory {
    pub base: u64,
    pub bytes: Vec<u8>,
}

impl Memory for FlatMemory {
    fn bytes_from(&self, address: u64) -> Option<&[u8]> {
        let offset = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.bytes.get(offset..).filter(|rest| !rest.is_empty())
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.bytes_from(address).is_some()
    }

    fn is_executable(&self, address: u64) -> bool {
        self.is_mapped(address)
    }
}
