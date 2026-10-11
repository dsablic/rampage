use rampage_loaders::{Binary, Segment};
use serde::Serialize;

use crate::{ApiError, Project};

pub const MAX_COMPARISON_BYTES: u64 = 1024 * 1024;
const MAX_COMPARISON_SPANS: usize = 16384;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeRange {
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteComparison {
    Equal,
    Changed,
    CaptureUnavailable,
    OriginalUnavailable,
    BothUnavailable,
}

#[derive(Debug, Serialize)]
pub struct ComparedSpan {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_address: u64,
    pub size: u64,
    pub status: ByteComparison,
}

#[derive(Debug, Serialize)]
pub struct RuntimeComparison {
    pub module_uuid: String,
    pub capture_identity: rampage_analysis::capture_identity::CaptureIdentity,
    pub original_image_sha256: String,
    pub arch: rampage_arch::Arch,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_base: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_base: u64,
    pub requested_bytes: u64,
    pub equal_bytes: u64,
    pub changed_bytes: u64,
    pub unavailable_bytes: u64,
    pub spans: Vec<ComparedSpan>,
    pub limitations: Vec<String>,
}

struct ImageBytes<'a> {
    binary: &'a Binary,
    segments: Vec<&'a Segment>,
    zero_fill: Vec<(u64, u64)>,
}

impl<'a> ImageBytes<'a> {
    fn new(binary: &'a Binary) -> Result<Self, ApiError> {
        if binary.segments.len() > 16384 || binary.sections.len() > 16384 {
            return Err(ApiError::Invalid("comparison mapping limit exceeded".to_owned()));
        }
        let mut segments: Vec<_> = binary.segments.iter().collect();
        segments.sort_by_key(|segment| segment.address);
        for pair in segments.windows(2) {
            if pair[0].size > pair[1].address - pair[0].address {
                return Err(ApiError::Invalid("comparison requires non-overlapping memory mappings".to_owned()));
            }
        }
        let mut zero_fill: Vec<_> = binary
            .sections
            .iter()
            .filter(|section| section.kind == rampage_loaders::SectionKind::UninitializedData)
            .filter_map(|section| (section.size != 0).then_some((section.address, section.size)))
            .collect();
        zero_fill.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, size) in zero_fill {
            let end =
                start.checked_add(size).ok_or_else(|| ApiError::Invalid("zero-fill section overflows".to_owned()))?;
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(Self { binary, segments, zero_fill: merged })
    }

    fn byte(&self, address: u64) -> Option<u8> {
        if let Some(index) = self.zero_fill.partition_point(|&(start, _)| start <= address).checked_sub(1)
            && address < self.zero_fill[index].1
        {
            return None;
        }
        let index = self.segments.partition_point(|segment| segment.address <= address).checked_sub(1)?;
        let segment = self.segments[index];
        let offset = address - segment.address;
        if !segment.perms.read || offset >= segment.size || offset >= segment.file_size {
            return None;
        }
        let file = usize::try_from(segment.file_offset.checked_add(offset)?).ok()?;
        self.binary.image_bytes().get(file).copied()
    }
}

impl Project {
    /// Compares explicit captured ranges with original file-backed bytes; does not interpret relocations or execute code.
    pub fn compare_runtime_bytes(
        &self,
        module_uuid: &str,
        original: &Binary,
        ranges: &[RuntimeRange],
    ) -> Result<RuntimeComparison, ApiError> {
        let (module_uuid, image_base, runtime_base) = self.runtime_module_bases(module_uuid, original)?;
        if ranges.is_empty() || ranges.len() > 256 {
            return Err(ApiError::Invalid("select 1..256 runtime comparison ranges".to_owned()));
        }
        let mut ranges = ranges.to_vec();
        ranges.sort_by_key(|range| range.address);
        let mut requested_bytes = 0u64;
        let mut previous_end = 0;
        for range in &ranges {
            let end = range
                .address
                .checked_add(range.size)
                .ok_or_else(|| ApiError::Invalid("comparison range overflows address space".to_owned()))?;
            if range.size == 0 || range.address < previous_end {
                return Err(ApiError::Invalid("comparison ranges must be nonempty and non-overlapping".to_owned()));
            }
            requested_bytes = requested_bytes
                .checked_add(range.size)
                .filter(|&total| total <= MAX_COMPARISON_BYTES)
                .ok_or_else(|| ApiError::Invalid("comparison exceeds the one MiB byte limit".to_owned()))?;
            previous_end = end;
        }
        let capture = ImageBytes::new(&self.binary)?;
        let image = ImageBytes::new(original)?;
        let capture_identity = rampage_analysis::capture_identity::capture_identity(&self.binary)
            .ok_or_else(|| ApiError::Invalid("capture identity unavailable".to_owned()))?;
        let original_image_sha256 = rampage_analysis::triage::triage(original).image_hashes.sha256;
        let mut result = RuntimeComparison { module_uuid, capture_identity, original_image_sha256,
            arch: self.binary.arch, runtime_base, image_base, requested_bytes,
            equal_bytes: 0, changed_bytes: 0, unavailable_bytes: 0, spans: Vec::new(),
            limitations: vec![
                "Byte equality is not code/ABI/source correctness; differences can include relocations or debugger normalization.".to_owned(),
                "UUID and header slide identify a declared module mapping; no external paths are opened or annotations transferred.".to_owned(),
                "Unmapped, unreadable, unbacked and truncated bytes are unavailable, never synthesized as zeros.".to_owned(),
            ] };
        for range in ranges {
            let image_start =
                range.address.checked_sub(runtime_base).and_then(|offset| image_base.checked_add(offset)).ok_or_else(
                    || ApiError::Invalid("runtime range cannot be mapped with the header slide".to_owned()),
                )?;
            image_start.checked_add(range.size).ok_or_else(|| ApiError::Invalid("image range overflows".to_owned()))?;
            for offset in 0..range.size {
                let runtime_address = range.address + offset;
                let image_address = image_start + offset;
                let status = match (capture.byte(runtime_address), image.byte(image_address)) {
                    (Some(first), Some(second)) if first == second => ByteComparison::Equal,
                    (Some(_), Some(_)) => ByteComparison::Changed,
                    (None, Some(_)) => ByteComparison::CaptureUnavailable,
                    (Some(_), None) => ByteComparison::OriginalUnavailable,
                    (None, None) => ByteComparison::BothUnavailable,
                };
                match status {
                    ByteComparison::Equal => result.equal_bytes += 1,
                    ByteComparison::Changed => result.changed_bytes += 1,
                    _ => result.unavailable_bytes += 1,
                }
                if let Some(last) = result.spans.last_mut()
                    && last.status == status
                    && last.runtime_address.checked_add(last.size) == Some(runtime_address)
                {
                    last.size += 1;
                } else {
                    if result.spans.len() == MAX_COMPARISON_SPANS {
                        return Err(ApiError::Invalid(
                            "comparison span limit exceeded; select smaller ranges".to_owned(),
                        ));
                    }
                    result.spans.push(ComparedSpan { runtime_address, image_address, size: 1, status });
                }
            }
        }
        Ok(result)
    }
}
