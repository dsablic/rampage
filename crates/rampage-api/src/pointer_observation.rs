use rampage_arch::Arch;
use rampage_loaders::{Format, Perms};
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAssessment {
    Unavailable,
    Null,
    CodeCandidate,
    NotCode,
    UnsupportedArchitecture,
}

#[derive(Debug, Serialize)]
pub struct PointerObservation {
    pub capture_identity: rampage_analysis::capture_identity::CaptureIdentity,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub slot: u64,
    pub pointer_size: u8,
    pub data_big_endian: bool,
    pub slot_permissions: Option<Perms>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub raw_value: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub candidate_target: Option<u64>,
    pub assessment: PointerAssessment,
    pub limitations: Vec<String>,
}

fn observed_pointer_size(width: Option<u8>) -> Result<u8, ApiError> {
    width
        .filter(|width| matches!(width, 4 | 8))
        .ok_or_else(|| ApiError::Invalid("captured pointer-slot width is unavailable or unsupported".to_owned()))
}

impl Project {
    /// Observes one captured pointer slot without treating it as a proven branch target or changing discovery.
    pub fn observe_pointer(&self, slot: u64) -> Result<PointerObservation, ApiError> {
        if self.binary.format != Format::Snapshot {
            return Err(ApiError::Invalid("pointer observations require an explicit captured snapshot".to_owned()));
        }
        let capture_identity = rampage_analysis::capture_identity::capture_identity(&self.binary)
            .ok_or_else(|| ApiError::Invalid("capture identity unavailable".to_owned()))?;
        let pointer_size = observed_pointer_size(self.binary.arch.default_pointer_size())?;
        let segment = self.binary.segment_containing(slot);
        let slot_permissions = segment.map(|segment| segment.perms);
        let bytes = segment
            .filter(|segment| {
                segment.perms.read
                    && slot
                        .checked_sub(segment.address)
                        .and_then(|offset| offset.checked_add(u64::from(pointer_size)))
                        .is_some_and(|end| end <= segment.size)
            })
            .and_then(|_| self.binary.read(slot, u64::from(pointer_size)));
        let raw_value = bytes.map(|bytes| {
            let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
            if self.binary.big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) }
        });
        let mut candidate_target = None;
        let assessment = match raw_value {
            None => PointerAssessment::Unavailable,
            Some(0) => PointerAssessment::Null,
            Some(raw) => {
                let mode = self.binary.target().is_thumb(raw & !1);
                let supported = matches!(self.binary.arch, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Aarch64);
                let mode_matches = self.binary.arch != Arch::Arm || (raw & 1 != 0) == mode;
                let target = if self.binary.arch == Arch::Arm && raw & 1 != 0 && mode { raw & !1 } else { raw };
                let minimum = match self.binary.arch {
                    Arch::X86 | Arch::X86_64 => 1,
                    Arch::Arm if mode => 2,
                    Arch::Arm | Arch::Aarch64 => 4,
                    _ => 1,
                };
                let aligned = target.is_multiple_of(minimum);
                let target_segment = self.binary.segment_containing(target);
                let backed = target_segment.is_some_and(|segment| {
                    segment.perms.read
                        && segment.perms.execute
                        && target
                            .checked_sub(segment.address)
                            .and_then(|offset| offset.checked_add(minimum))
                            .is_some_and(|end| end <= segment.size)
                });
                let code = self.binary.code_from(target).is_some_and(|bytes| bytes.len() as u64 >= minimum);
                if !supported {
                    PointerAssessment::UnsupportedArchitecture
                } else if mode_matches && aligned && backed && code {
                    candidate_target = Some(target);
                    PointerAssessment::CodeCandidate
                } else {
                    PointerAssessment::NotCode
                }
            }
        };
        Ok(PointerObservation { capture_identity, slot, pointer_size, data_big_endian: self.binary.big_endian,
            slot_permissions, raw_value, candidate_target, assessment,
            limitations: vec![
                "Raw captured bytes are an observation, not proof of future load invariance or a call edge.".to_owned(),
                "Code candidates mean aligned, readable executable backing, not verified instructions or function starts.".to_owned(),
                "Writable slots remain observations only. No discovery edges, symbols or annotations are inserted.".to_owned(),
                "Pointer authentication and high-bit tags are not stripped or reconstructed.".to_owned(),
            ] })
    }
}

#[cfg(test)]
mod width_tests {
    #[test]
    fn absent_observation_width_is_a_capability_error_not_unreadable_bytes() {
        assert!(super::observed_pointer_size(None).is_err());
        assert!(super::observed_pointer_size(Some(2)).is_err());
        assert_eq!(super::observed_pointer_size(Some(4)).unwrap(), 4);
        assert_eq!(super::observed_pointer_size(Some(8)).unwrap(), 8);
    }
}
