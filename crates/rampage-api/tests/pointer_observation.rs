use rampage_api::{FunctionsQuery, PointerAssessment, Project};
use rampage_loaders::Binary;

fn binary() -> Binary {
    Binary::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json"))
        .unwrap()
}

#[test]
fn writable_captured_pointer_is_observed_without_becoming_a_proven_flow_target() {
    let mut capture = binary();
    capture.segments[1].perms.write = true;
    assert!(capture.read_pointer(0x3000, 8).is_none());
    let project = Project::new(capture);
    let before = project.functions(&FunctionsQuery::default()).unwrap().total;
    let observation = project.observe_pointer(0x3000).unwrap();
    assert_eq!(observation.raw_value, Some(0x1010));
    assert_eq!(observation.candidate_target, Some(0x1010));
    assert_eq!(observation.assessment, PointerAssessment::CodeCandidate);
    assert!(observation.slot_permissions.unwrap().write);
    assert_eq!(project.functions(&FunctionsQuery::default()).unwrap().total, before);
    assert!(project.binary.read_pointer(0x3000, 8).is_none());
    assert!(project.annotation_list().names.is_empty());
}

#[test]
fn unavailable_slot_and_nonexecutable_or_truncated_target_stay_unresolved() {
    for issue in 0..4 {
        let mut capture = binary();
        match issue {
            0 => capture.segments[1].perms.read = false,
            1 => capture.segments[1].file_size = 7,
            2 => capture.segments[0].perms.execute = false,
            3 => capture.segments[0].file_size = 0x12,
            _ => unreachable!(),
        }
        let result = Project::new(capture).observe_pointer(0x3000).unwrap();
        assert!(result.candidate_target.is_none());
        assert_eq!(
            result.assessment,
            if issue < 2 { PointerAssessment::Unavailable } else { PointerAssessment::NotCode }
        );
    }
}

#[test]
fn pointer_observations_require_explicit_snapshots() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.elf");
    assert!(Project::new(Binary::open(path).unwrap()).observe_pointer(0x3000).is_err());
}

#[test]
fn thumb_targets_require_a_matching_pointer_mode_bit_and_preserve_the_raw_value() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-thumb-pointer.snapshot.json");
    let project = Project::new(Binary::open(path).unwrap());
    let untagged = project.observe_pointer(0x3000).unwrap();
    assert_eq!(untagged.raw_value, Some(0x1002));
    assert_eq!(untagged.assessment, PointerAssessment::NotCode);
    assert_eq!(untagged.candidate_target, None);
    let tagged = project.observe_pointer(0x3004).unwrap();
    assert_eq!(tagged.raw_value, Some(0x1003));
    assert_eq!(tagged.assessment, PointerAssessment::CodeCandidate);
    assert_eq!(tagged.candidate_target, Some(0x1002));
    assert_eq!(project.observe_pointer(0x3008).unwrap().assessment, PointerAssessment::Null);
    let high_bits = project.observe_pointer(0x300c).unwrap();
    assert_eq!(high_bits.raw_value, Some(0x80001003));
    assert_eq!(high_bits.candidate_target, None);
    assert_eq!(project.observe_pointer(0x4000).unwrap().assessment, PointerAssessment::Unavailable);
    let json = serde_json::to_value(tagged).unwrap();
    assert_eq!(json["raw_value"], "0x1003");
    assert_eq!(json["candidate_target"], "0x1002");
}

#[test]
fn raw_pointer_words_use_the_captures_data_byte_order() {
    let mut capture = binary();
    capture.big_endian = true;
    let result = Project::new(capture).observe_pointer(0x3000).unwrap();
    assert_eq!(result.raw_value, Some(0x1010000000000000));
    assert!(result.candidate_target.is_none());
}
