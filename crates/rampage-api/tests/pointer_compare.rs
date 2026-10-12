use rampage_api::{PointerChange, Project};
use rampage_loaders::Binary;

fn project() -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    Project::new(Binary::open(path).unwrap())
}

#[test]
fn identical_words_retain_independent_permission_and_target_assessments() {
    let before = project();
    let mut after = project();
    after.binary.segments[1].perms.write = true;
    after.binary.segments[0].perms.execute = false;
    let result = before.compare_pointer_observations(0x3000, &after, 0x3000).unwrap();
    assert_eq!(result.raw_value_change, PointerChange::Equal);
    assert!(result.slot_permissions_changed);
    assert!(result.target_assessment_changed);
    assert_eq!(result.before.raw_value, Some(0x1010));
    assert_eq!(result.after.raw_value, Some(0x1010));
    assert_ne!(result.before.capture_identity.sha256, result.after.capture_identity.sha256);
    assert!(after.binary.read_pointer(0x3000, 8).is_none());
    assert!(before.annotation_list().names.is_empty());
    assert!(after.annotation_list().names.is_empty());
}

#[test]
fn explicitly_paired_slots_report_differences_without_slide_inference() {
    let before = project();
    let after = project();
    let result = before.compare_pointer_observations(0x3000, &after, 0x1000).unwrap();
    assert_eq!(result.raw_value_change, PointerChange::Changed);
    assert_eq!(result.before.slot, 0x3000);
    assert_eq!(result.after.slot, 0x1000);
    assert_ne!(result.before.raw_value, result.after.raw_value);
}

#[test]
fn unavailable_words_remain_distinct_from_observed_zero_or_equal_values() {
    let before = project();
    let after = project();
    for (first, second, expected) in [
        (0x4000, 0x3000, PointerChange::BeforeUnavailable),
        (0x3000, 0x4000, PointerChange::AfterUnavailable),
        (0x4000, 0x4000, PointerChange::BothUnavailable),
    ] {
        let result = before.compare_pointer_observations(first, &after, second).unwrap();
        assert_eq!(result.raw_value_change, expected);
    }
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-thumb-pointer.snapshot.json");
    let zero_capture = Project::new(Binary::open(path).unwrap());
    let equal = zero_capture.compare_pointer_observations(0x3008, &zero_capture, 0x3008).unwrap();
    assert_eq!(equal.raw_value_change, PointerChange::Equal);
    assert_eq!(equal.before.raw_value, Some(0));
    let missing = zero_capture.compare_pointer_observations(0x3008, &zero_capture, 0x4000).unwrap();
    assert_eq!(missing.raw_value_change, PointerChange::AfterUnavailable);
    assert_eq!(missing.before.raw_value, Some(0));
    assert_eq!(missing.after.raw_value, None);
}

#[test]
fn incompatible_architecture_data_order_or_non_snapshot_inputs_are_rejected() {
    let before = project();
    for issue in 0..3 {
        let mut after = project();
        match issue {
            0 => after.binary.arch = rampage_arch::Arch::Arm,
            1 => after.binary.big_endian = true,
            2 => after.binary.format = rampage_loaders::Format::Elf,
            _ => unreachable!(),
        }
        assert!(before.compare_pointer_observations(0x3000, &after, 0x3000).is_err());
    }
}
