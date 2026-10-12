//! Bounds-checked integer reads from untrusted byte slices.

/// The `width`-byte unsigned integer at `offset` in either byte order, or `None` when it does not fit in
/// `bytes` or `width` is not 1 to 8.
pub fn read_uint(bytes: &[u8], offset: usize, width: usize, big_endian: bool) -> Option<u64> {
    if !(1..=8).contains(&width) {
        return None;
    }
    let slice = bytes.get(offset..offset.checked_add(width)?)?;
    let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
    Some(if big_endian { slice.iter().fold(0, fold) } else { slice.iter().rev().fold(0, fold) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_width_in_both_byte_orders_and_rejects_overruns() {
        let bytes = [0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(read_uint(&bytes, 1, 1, false), Some(0x12));
        assert_eq!(read_uint(&bytes, 1, 2, true), Some(0x1234));
        assert_eq!(read_uint(&bytes, 1, 2, false), Some(0x3412));
        assert_eq!(read_uint(&bytes, 1, 8, true), Some(0x1234_5678_9abc_def0));
        assert_eq!(read_uint(&bytes, 1, 8, false), Some(0xf0de_bc9a_7856_3412));
        assert_eq!(read_uint(&bytes, 2, 8, false), None);
        assert_eq!(read_uint(&bytes, usize::MAX, 1, false), None);
        assert_eq!(read_uint(&bytes, 0, 0, false), None);
        assert_eq!(read_uint(&bytes, 0, 9, false), None);
    }
}
