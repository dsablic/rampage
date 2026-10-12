use rampage_loaders::Format;
use serde::Serialize;

use crate::{ApiError, PointerObservation, Project};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerChange {
    Equal,
    Changed,
    BeforeUnavailable,
    AfterUnavailable,
    BothUnavailable,
}

#[derive(Debug, Serialize)]
pub struct PointerComparison {
    pub before: PointerObservation,
    pub after: PointerObservation,
    pub raw_value_change: PointerChange,
    pub slot_permissions_changed: bool,
    pub target_assessment_changed: bool,
    pub limitations: Vec<String>,
}

impl Project {
    /// Compares two explicitly selected captured slots; supplied order and slot correspondence are not verified.
    pub fn compare_pointer_observations(
        &self,
        before_slot: u64,
        after: &Project,
        after_slot: u64,
    ) -> Result<PointerComparison, ApiError> {
        if self.binary.format != Format::Snapshot
            || after.binary.format != Format::Snapshot
            || self.binary.arch != after.binary.arch
            || self.binary.big_endian != after.binary.big_endian
        {
            return Err(ApiError::Invalid(
                "pointer comparison requires snapshots with matching architecture and data byte order".to_owned(),
            ));
        }
        let before = self.observe_pointer(before_slot)?;
        let after = after.observe_pointer(after_slot)?;
        let raw_value_change = match (before.raw_value, after.raw_value) {
            (Some(first), Some(second)) if first == second => PointerChange::Equal,
            (Some(_), Some(_)) => PointerChange::Changed,
            (None, Some(_)) => PointerChange::BeforeUnavailable,
            (Some(_), None) => PointerChange::AfterUnavailable,
            (None, None) => PointerChange::BothUnavailable,
        };
        let slot_permissions_changed = before.slot_permissions != after.slot_permissions;
        let target_assessment_changed =
            before.assessment != after.assessment || before.candidate_target != after.candidate_target;
        Ok(PointerComparison { before, after, raw_value_change, slot_permissions_changed, target_assessment_changed,
            limitations: vec![
                "Before/after is analyst-supplied ordering, not verified time or same-process provenance.".to_owned(),
                "Slot correspondence is explicit; no ASLR, module ownership or pointer normalization is inferred.".to_owned(),
                "Raw equality/difference does not establish what a branch loaded, future invariance or proven flow.".to_owned(),
                "Unavailable words are not zero. Mapping and target assessments are reported separately from raw values.".to_owned(),
                "Each observation retains its own capture identity; no discovery or annotation edits are performed.".to_owned(),
            ] })
    }
}
