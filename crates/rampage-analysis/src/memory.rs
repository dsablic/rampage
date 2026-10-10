use rampage_loaders::Binary;

/// The view of a program's address space that analysis needs.
pub trait Memory: Sync {
    /// File-backed bytes from `address` to the end of its region, or `None` when unmapped.
    fn bytes_from(&self, address: u64) -> Option<&[u8]>;
    fn is_mapped(&self, address: u64) -> bool;
    fn is_executable(&self, address: u64) -> bool;
    /// Whether address-sized immediates may be pointers. Position-independent images based at zero reach code and
    /// data RIP-relatively, and small integers there land inside code, so their immediates are just numbers.
    fn immediates_may_be_addresses(&self) -> bool;
}

/// Images whose code starts below this are treated as based at zero.
const MIN_IMAGE_BASE_FOR_IMMEDIATES: u64 = 0x10000;

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

    fn immediates_may_be_addresses(&self) -> bool {
        let lowest_code =
            self.segments.iter().filter(|segment| segment.perms.execute).map(|segment| segment.address).min();
        lowest_code.is_some_and(|address| address >= MIN_IMAGE_BASE_FOR_IMMEDIATES)
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

    fn immediates_may_be_addresses(&self) -> bool {
        self.base >= MIN_IMAGE_BASE_FOR_IMMEDIATES
    }
}
