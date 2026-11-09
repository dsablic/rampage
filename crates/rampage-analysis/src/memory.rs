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
    /// Whether a value an instruction forms or loads can be a pointer to code rather than to data in an executable
    /// region. Only images whose code is all Thumb can tell: their code pointers have the low bit set.
    fn may_point_to_code(&self, _address: u64) -> bool {
        true
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
        if self.is_sleigh_raw() {
            return None;
        }
        Binary::read_pointer(self, address, size)
    }

    fn read_constant(&self, address: u64, size: u8) -> Option<u64> {
        if self.is_sleigh_raw() {
            return None;
        }
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

    /// An M-profile image is one executable mapping of Thumb code and constant data. An even address formed into
    /// it (a string, a switch table) is data, since every Thumb code pointer is odd; so is an odd one whose exact
    /// byte starts a printable NUL-terminated run, the usual odd-aligned string literal (`"Bc"` at 0x80000af).
    fn may_point_to_code(&self, address: u64) -> bool {
        if !self.m_profile() {
            return true;
        }
        address & 1 == 1 && !starts_text(self, address)
    }

    fn immediates_may_be_addresses(&self) -> bool {
        if self.is_sleigh_raw() {
            return false;
        }
        let lowest_code =
            self.segments.iter().filter(|segment| segment.perms.execute).map(|segment| segment.address).min();
        lowest_code.is_some_and(|address| address >= MIN_IMAGE_BASE_FOR_IMMEDIATES)
    }
}

/// Whether `address` holds at least one printable ASCII byte followed, within the run, by a NUL.
fn starts_text(binary: &Binary, address: u64) -> bool {
    const LIMIT: usize = 256;
    let Some(bytes) = binary.read_to_segment_end(address) else { return false };
    let printable = |byte: u8| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
    let run = bytes.iter().take(LIMIT).take_while(|&&byte| printable(byte)).count();
    run > 0 && bytes.get(run) == Some(&0)
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
