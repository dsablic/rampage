use rampage_decompiler::MemoryRegion;
use rampage_loaders::{Binary, Format, RawProfile};

use crate::ApiError;

/// Raw profiles with a reviewed exact-pair C model; the decompiler rechecks the pair and translator bounds.
fn has_reviewed_c_model(profile: RawProfile) -> bool {
    match profile {
        RawProfile::Msp430 | RawProfile::Avr8 => true,
        RawProfile::Mos6502 => false,
    }
}

/// One read-only RX mapping of exactly the admitted Raw code range. Nothing else, in no other space, is mapped.
fn raw_region(binary: &Binary) -> Result<MemoryRegion<'_>, ApiError> {
    let identity = binary.raw_interpretation_identity().map_err(|error| ApiError::Invalid(error.to_string()))?;
    let raw = binary
        .raw_code_image()
        .filter(|_| identity.is_some())
        .ok_or_else(|| ApiError::Invalid("Raw native memory requires retained admission facts".into()))?;
    let profile = raw.profile();
    if !has_reviewed_c_model(profile) {
        return Err(ApiError::Unavailable(format!("no reviewed C model for {}", profile.language_id())));
    }
    let bytes = binary.image_bytes();
    let range = raw.range();
    if bytes.len() as u64 != raw.length() || range.end - range.start != raw.length() {
        return Err(ApiError::Invalid("Raw code bytes disagree with the admitted mapping".into()));
    }
    Ok(MemoryRegion { base: range.start, bytes, size: raw.length(), readable: true, writable: false, executable: true })
}

pub(super) fn regions(binary: &Binary) -> Result<Vec<MemoryRegion<'_>>, ApiError> {
    if binary.format == Format::Raw || binary.raw_code_image().is_some() {
        return Ok(vec![raw_region(binary)?]);
    }
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

#[cfg(test)]
mod raw_tests {
    use super::regions;
    use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

    fn binary(profile: RawProfile) -> Binary {
        let input = RawCodeOptions { profile, base: 0x1000, entry: None, seeds: vec![] };
        Binary::from_raw_code(vec![0; 4], input).unwrap()
    }

    #[test]
    fn raw_maps_exactly_the_admitted_code_range_for_reviewed_c_models() {
        for profile in [RawProfile::Msp430, RawProfile::Avr8] {
            let binary = binary(profile);
            let regions = regions(&binary).unwrap();
            assert_eq!(regions.len(), 1);
            let region = &regions[0];
            assert_eq!((region.base, region.size, region.bytes), (0x1000, 4, &[0u8; 4][..]));
            assert!(region.readable && region.executable && !region.writable);
            // Backing-source digests stay refused for owned Raw bytes.
            let project = crate::Project::new(binary);
            assert!(crate::debug_layout_import::image_digest(&project).is_err());
        }
    }

    #[test]
    fn raw_without_a_reviewed_c_model_refuses_by_profile() {
        let binary = binary(RawProfile::Mos6502);
        let Err(error) = regions(&binary) else { panic!("6502 has no reviewed C model") };
        assert!(matches!(error, crate::ApiError::Unavailable(_)), "{error:?}");
        assert_eq!(error.to_string(), "no reviewed C model for 6502:LE:16:default");
    }

    #[test]
    fn edited_raw_loader_fields_refuse_native_memory() {
        let mut binary = binary(RawProfile::Msp430);
        binary.segments[0].address = 0x2000;
        assert!(matches!(regions(&binary), Err(crate::ApiError::Invalid(_))));
    }
}
