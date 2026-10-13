use rampage_loaders::Binary;

/// The view of a program's address space that analysis needs.
pub trait Memory: Sync {
    /// File-backed bytes from `address` to the end of its code region, or `None` when `address` is not code.
    fn code_from(&self, address: u64) -> Option<&[u8]>;
    fn is_mapped(&self, address: u64) -> bool;
    fn is_executable(&self, address: u64) -> bool;
    /// Whether address-sized immediates may be pointers. Position-independent images based at zero reach code and
    /// data RIP-relatively, and small integers there land inside code, so their immediates are just numbers.
    fn immediates_may_be_addresses(&self) -> bool;
    /// The address of the code a pointer to `address` runs. ARM marks pointers to Thumb code with the low bit.
    fn code_address(&self, address: u64) -> u64 {
        address
    }
    fn read_pointer(&self, _address: u64, _size: u8) -> Option<u64> {
        None
    }
    /// A 1-, 2-, 4- or 8-byte value from file-backed memory the program cannot write, such as a switch table.
    fn read_constant(&self, _address: u64, _size: u8) -> Option<u64> {
        None
    }
}

/// Images whose code starts below this are treated as based at zero.
const MIN_IMAGE_BASE_FOR_IMMEDIATES: u64 = 0x10000;

impl Memory for Binary {
    fn read_pointer(&self, address: u64, size: u8) -> Option<u64> {
        Binary::read_pointer(self, address, size)
    }

    fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
        Binary::read_constant(self, address, size)
    }

    fn code_from(&self, address: u64) -> Option<&[u8]> {
        Binary::code_from(self, address)
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.segment_containing(address).is_some()
    }

    fn is_executable(&self, address: u64) -> bool {
        self.is_code(address)
    }

    fn code_address(&self, address: u64) -> u64 {
        if self.arch == rampage_arch::Arch::Arm { address & !1 } else { address }
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
    fn code_from(&self, address: u64) -> Option<&[u8]> {
        let offset = usize::try_from(address.checked_sub(self.base)?).ok()?;
        self.bytes.get(offset..).filter(|rest| !rest.is_empty())
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.code_from(address).is_some()
    }

    fn is_executable(&self, address: u64) -> bool {
        self.is_mapped(address)
    }

    fn immediates_may_be_addresses(&self) -> bool {
        self.base >= MIN_IMAGE_BASE_FOR_IMMEDIATES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flat_region_has_no_constants_because_nothing_proves_it_read_only() {
        let memory = FlatMemory { base: 0x1000, bytes: vec![1, 0, 0, 0] };
        assert_eq!(memory.read_constant(0x1000, 4), None);
    }
}
