use rampage_analysis::capture_identity::capture_identity;
use rampage_loaders::{
    Binary,
    snapshot::{SnapshotPlatform, SnapshotTarget},
};

fn binary() -> Binary {
    Binary::open(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64-stack.snapshot.json"),
    )
    .unwrap()
}

#[test]
fn mapping_context_changes_identity_without_changing_captured_bytes() {
    let original = binary();
    let baseline = capture_identity(&original).unwrap().sha256;
    for change in 0..6 {
        let mut capture = binary();
        match change {
            0 => capture.segments[0].address += 4,
            1 => capture.segments[0].perms.write = !capture.segments[0].perms.write,
            2 => capture.big_endian = !capture.big_endian,
            3 => capture.snapshot_target = Some(SnapshotTarget { platform: SnapshotPlatform::Darwin, compiler: None }),
            4 => capture.function_starts.push(0x1004),
            5 => capture.snapshot_modules[0].runtime_base = "0x2000".to_owned(),
            _ => unreachable!(),
        }
        assert_eq!(capture.image_bytes(), original.image_bytes());
        assert_ne!(capture_identity(&capture).unwrap().sha256, baseline);
    }
}

#[test]
fn region_order_and_display_provenance_do_not_change_identity() {
    let mut capture = binary();
    capture.snapshot_modules[0].uuid = "0123456789abcdef0123456789abcdef".to_owned();
    let mut second = capture.segments[0].clone();
    second.address = 0x2000;
    second.file_offset = 4;
    second.size = 4;
    second.file_size = 4;
    capture.segments[0].size = 4;
    capture.segments[0].file_size = 4;
    capture.segments.push(second);
    assert_ne!(&capture.image_bytes()[..4], &capture.image_bytes()[4..8]);
    let baseline = capture_identity(&capture).unwrap().sha256;
    capture.segments.reverse();
    capture.provenance = Some("another capture path or process".to_owned());
    for segment in &mut capture.segments {
        segment.name = "renamed".to_owned();
    }
    for module in &mut capture.snapshot_modules {
        module.path = "/not/opened/module".to_owned();
        module.uuid = module.uuid.to_uppercase();
        module.runtime_base = format!("0x{:016x}", u64::from_str_radix(&module.runtime_base[2..], 16).unwrap());
    }
    assert_eq!(capture_identity(&capture).unwrap().sha256, baseline);
}

#[test]
fn opaque_module_identifiers_are_not_collapsed_into_uuid_aliases() {
    for (first, second) in [
        ("fixture-uuid", "fixtureuuid"),
        ("-", "--"),
        ("0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef-"),
    ] {
        let mut capture = binary();
        capture.snapshot_modules[0].uuid = first.to_owned();
        let baseline = capture_identity(&capture).unwrap().sha256;
        capture.snapshot_modules[0].uuid = second.to_owned();
        assert_ne!(capture_identity(&capture).unwrap().sha256, baseline);
    }
}
