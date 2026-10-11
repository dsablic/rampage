use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{ByteComparison, Project, RuntimeRange};
use rampage_loaders::{Binary, Details};

struct Fixture {
    root: PathBuf,
    original: Binary,
    uuid: String,
    image_base: u64,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-runtime-compare-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
        let original = Binary::open(path).unwrap();
        let Details::MachO(details) = &original.details else { panic!("not Mach-O") };
        let uuid = details.uuid.clone().unwrap();
        let image_base =
            original.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
        Self { root, original, uuid, image_base }
    }

    fn project(&self, runtime: u64, offset: u64, bytes: &[u8]) -> Project {
        let snapshot = serde_json::json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "controlled comparison fixture",
            "regions": [{"name": "selected", "address": format!("{:#x}", runtime + offset),
                "permissions": "r--", "bytes": rampage_arch::hex::bytes(bytes)}], "entry": null,
            "modules": [{"name": "fixture", "path": "/never/opened/original", "uuid": self.uuid,
                "image_base": format!("{:#x}", self.image_base), "runtime_base": format!("{runtime:#x}")}]
        });
        let path = self.root.join("snapshot.json");
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        Project::new(Binary::open(path).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn comparison_preserves_equal_changed_and_missing_capture_spans_for_positive_and_negative_slides() {
    let fixture = Fixture::new();
    let mut bytes = fixture.original.image_bytes()[2..8].to_vec();
    bytes[2] ^= 0xff;
    for runtime in [0x1000, 0x200000000] {
        let project = fixture.project(runtime, 2, &bytes);
        let result = project
            .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: runtime, size: 10 }])
            .unwrap();
        assert_eq!((result.equal_bytes, result.changed_bytes, result.unavailable_bytes), (5, 1, 4));
        assert_eq!(
            result.spans.iter().map(|span| (span.status, span.size)).collect::<Vec<_>>(),
            vec![
                (ByteComparison::CaptureUnavailable, 2),
                (ByteComparison::Equal, 2),
                (ByteComparison::Changed, 1),
                (ByteComparison::Equal, 3),
                (ByteComparison::CaptureUnavailable, 2)
            ]
        );
        assert_eq!(result.spans[0].image_address, fixture.image_base);
        assert_eq!(result.requested_bytes, result.equal_bytes + result.changed_bytes + result.unavailable_bytes);
        assert_eq!(
            result.original_image_sha256,
            rampage_analysis::triage::triage(&fixture.original).image_hashes.sha256
        );
        assert_eq!(result.runtime_base, runtime);
    }
}

#[test]
fn unbacked_and_unreadable_bytes_are_not_synthesized_or_compared_as_zero() {
    let mut fixture = Fixture::new();
    let mut project = fixture.project(0x1000, 0, &[0; 8]);
    fixture
        .original
        .segments
        .iter_mut()
        .find(|segment| segment.file_offset == 0 && segment.file_size > 0)
        .unwrap()
        .file_size = 4;
    project.binary.segments[0].perms.read = false;
    let result = project
        .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: 0x1000, size: 8 }])
        .unwrap();
    assert_eq!(result.spans[0].status, ByteComparison::CaptureUnavailable);
    assert_eq!(result.spans[1].status, ByteComparison::BothUnavailable);
    project.binary.segments[0].perms.read = true;
    let result = project
        .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: 0x1004, size: 4 }])
        .unwrap();
    assert_eq!(result.spans[0].status, ByteComparison::OriginalUnavailable);
}

#[test]
fn malformed_or_amplifying_ranges_and_wrong_identity_are_rejected() {
    let fixture = Fixture::new();
    let project = fixture.project(0x1000, 0, &[0; 8]);
    for ranges in [
        vec![],
        vec![RuntimeRange { address: 0x1000, size: 0 }],
        vec![RuntimeRange { address: u64::MAX, size: 2 }],
        vec![RuntimeRange { address: 0x1000, size: 1024 * 1024 + 1 }],
        vec![RuntimeRange { address: 0x1000, size: 4 }, RuntimeRange { address: 0x1002, size: 4 }],
        vec![RuntimeRange { address: 0xfff, size: 1 }],
    ] {
        assert!(project.compare_runtime_bytes(&fixture.uuid, &fixture.original, &ranges).is_err());
    }
    assert!(
        project
            .compare_runtime_bytes(
                "00000000000000000000000000000000",
                &fixture.original,
                &[RuntimeRange { address: 0x1000, size: 1 }]
            )
            .is_err()
    );
}

#[test]
fn distinct_original_content_with_the_same_uuid_is_recorded_in_provenance() {
    let fixture = Fixture::new();
    let project = fixture.project(0x1000, 0, &fixture.original.image_bytes()[..4]);
    let first = project
        .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: 0x1000, size: 4 }])
        .unwrap();
    let mut bytes = fixture.original.image_bytes().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    let path = fixture.root.join("changed-original.macho");
    std::fs::write(&path, bytes).unwrap();
    let changed = Binary::open(path).unwrap();
    let second =
        project.compare_runtime_bytes(&fixture.uuid, &changed, &[RuntimeRange { address: 0x1000, size: 4 }]).unwrap();
    assert_eq!(first.equal_bytes, second.equal_bytes);
    assert_ne!(first.original_image_sha256, second.original_image_sha256);
}

#[test]
fn alternating_byte_results_stop_at_the_span_budget_without_partial_output() {
    let mut fixture = Fixture::new();
    let size = 16385;
    let source = &fixture.original.image_bytes()[..size];
    let bytes: Vec<_> =
        source.iter().enumerate().map(|(index, byte)| if index % 2 == 0 { *byte } else { *byte ^ 0xff }).collect();
    let header = fixture.original.segments.iter_mut().find(|segment| segment.address == fixture.image_base).unwrap();
    header.size = size as u64;
    header.file_size = size as u64;
    let header = header.clone();
    fixture.original.segments = vec![header];
    let project = fixture.project(0x1000, 0, &bytes);
    let error = project
        .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: 0x1000, size: size as u64 }])
        .unwrap_err();
    assert!(error.to_string().contains("span limit"), "{error}");
}

#[test]
fn declared_zero_fill_inside_a_backed_segment_remains_original_unavailable() {
    let mut fixture = Fixture::new();
    let bytes = fixture.original.image_bytes()[..8].to_vec();
    let project = fixture.project(0x1000, 0, &bytes);
    fixture.original.sections.push(rampage_loaders::Section {
        name: "declared_bss".to_owned(),
        address: fixture.image_base + 4,
        size: 4,
        kind: rampage_loaders::SectionKind::UninitializedData,
        file_offset: None,
        file_size: 0,
    });
    let result = project
        .compare_runtime_bytes(&fixture.uuid, &fixture.original, &[RuntimeRange { address: 0x1000, size: 8 }])
        .unwrap();
    assert_eq!((result.equal_bytes, result.changed_bytes, result.unavailable_bytes), (4, 0, 4));
    assert_eq!(result.spans[1].status, ByteComparison::OriginalUnavailable);
}
