use rampage_decompiler::MemoryRegion;
use rampage_loaders::{Binary, Format};

use crate::ApiError;

pub(super) fn regions(binary: &Binary) -> Result<Vec<MemoryRegion<'_>>, ApiError> {
    let mut regions = Vec::new();
    for segment in &binary.segments {
        if segment.size == 0 || !(segment.perms.read || segment.perms.execute) {
            continue;
        }
        let region = |base, bytes, size| MemoryRegion {
            base,
            bytes,
            size,
            readable: segment.perms.read,
            writable: segment.perms.write,
            executable: segment.perms.execute,
        };
        let bytes =
            if segment.file_size == 0 { &[][..] } else { binary.read_to_segment_end(segment.address).unwrap_or(&[]) };
        let zero_fill = binary.format != Format::Snapshot;
        if bytes.len() as u64 == segment.file_size {
            let size = if zero_fill { segment.size } else { segment.file_size };
            if size != 0 {
                regions.push(region(segment.address, bytes, size));
            }
            continue;
        }
        if !bytes.is_empty() {
            regions.push(region(segment.address, bytes, bytes.len() as u64));
        }
        if segment.file_size < segment.size && zero_fill {
            let base = segment
                .address
                .checked_add(segment.file_size)
                .ok_or_else(|| ApiError::Invalid("zero-fill mapping overflows".to_owned()))?;
            regions.push(region(base, &[], segment.size - segment.file_size));
        }
    }
    Ok(regions)
}
