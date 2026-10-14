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

#[test]
fn agent_comparison_pages_keep_full_range_totals_and_valid_json() {
    let fixture = Fixture::new();
    let mut bytes = fixture.original.image_bytes()[..400].to_vec();
    for (index, byte) in bytes.iter_mut().enumerate() {
        if index % 2 != 0 {
            *byte ^= 0xff;
        }
    }
    let project = fixture.project(0x1000, 0, &bytes);
    let tools = rampage_api::tools::tools();
    let original = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
    let input = serde_json::json!({"original": original, "module": fixture.uuid,
        "ranges": [{"address": "0x1000", "size": 400}], "limit": 1000});
    let (text, failed) = rampage_api::tools::call(&tools, &project, "compare_runtime_bytes", input.clone());
    assert!(!failed, "{text}");
    let first: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(first["spans_total"], 400);
    assert_eq!(first["spans"].as_array().unwrap().len(), 200);
    assert_eq!(first["changed_bytes"], 200);
    assert_eq!(first["equal_bytes"], 200);
    let mut input = input;
    input["offset"] = serde_json::json!(200);
    input["limit"] = serde_json::json!(200);
    let (text, failed) = rampage_api::tools::call(&tools, &project, "compare_runtime_bytes", input);
    assert!(!failed, "{text}");
    let second: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(second["offset"], 200);
    assert_eq!(second["spans"][0]["runtime_address"], "0x10c8");
    assert_eq!(second["capture_identity"], first["capture_identity"]);
    assert_eq!(second["original_image_sha256"], first["original_image_sha256"]);
    assert_eq!(second["requested_bytes"], 400);
}

const CONTROLLED_UUID: &str = "11111111111111111111111111111111";
const CONTROLLED_BASE: u64 = 0x100000000;
// Independent Python hashlib goldens shared with the CLI's committed controlled comparison specification.
// Raw 256-byte Mach-O; capture v1 BE u64 lengths/counts/addresses, aarch64, little-endian, no target context;
// read-only regions (0x1002, edfef3000001), (0x10fe, a5a50102), no Thumb/seeds/entry;
// module (CONTROLLED_UUID, CONTROLLED_BASE, 0x1000). Names, paths and provenance are excluded from identity.
const CONTROLLED_IMAGE_SHA256: &str = "8002eb6adf4b391fbb0e0561ad011f8b90b64ece0bc91f2a541d9f6e36647075";
const CONTROLLED_CAPTURE_SCHEMA: &str = "rampage-capture-identity-v1";
const CONTROLLED_CAPTURE_SHA256: &str = "bf2175b02e8fab15c29fa7920a9651613353d85b540d428f1cf1e44ac2445568";

fn controlled_macho(cpu: u32, uuid_byte: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xfeedfacf, cpu, 0, 2, 2, 96, 0, 0, 0x19, 72] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let segment_name: &[u8; 16] = b"__TEXT\0\0\0\0\0\0\0\0\0\0";
    bytes.extend_from_slice(segment_name);
    for word in [CONTROLLED_BASE, 0x200, 0, 0x100] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for word in [5u32, 5, 0, 0, 0x1b, 24] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(bytes.len(), 112);
    bytes.extend_from_slice(&[uuid_byte; 16]);
    assert_eq!(bytes.len(), 128);
    bytes.resize(0x100, 0xa5);
    bytes
}

fn controlled_universal(selected: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xcafebabfu32, 2] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    for (cpu, subtype, offset) in [(0x01000007u32, 3u32, 0x1000u64), (0x0100000c, 0, 0x2000)] {
        bytes.extend_from_slice(&cpu.to_be_bytes());
        bytes.extend_from_slice(&subtype.to_be_bytes());
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.extend_from_slice(&0x100u64.to_be_bytes());
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
    }
    bytes.resize(0x2000, 0);
    bytes[0x1000..0x1100].copy_from_slice(&controlled_macho(0x01000007, 0x22));
    bytes.extend_from_slice(selected);
    bytes
}

struct ControlledFixture {
    root: PathBuf,
    original: PathBuf,
    capture: PathBuf,
    bytes: Vec<u8>,
}

impl ControlledFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-api-selected-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let bytes = controlled_macho(0x0100000c, 0x11);
        let original = root.join("original.macho");
        std::fs::write(&original, &bytes).unwrap();
        let snapshot = serde_json::json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
            "provenance": "constructed API comparison fixture",
            "regions": [
                {"name": "selected", "address": "0x1002", "permissions": "r--", "bytes": "edfef3000001"},
                {"name": "file-end", "address": "0x10fe", "permissions": "r--", "bytes": "a5a50102"}
            ],
            "modules": [{"name": "fixture", "path": "/never/opened/original", "uuid": CONTROLLED_UUID,
                "image_base": "0x100000000", "runtime_base": "0x1000"}]
        });
        let capture = root.join("snapshot.json");
        std::fs::write(&capture, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        Self { root, original, capture, bytes }
    }

    fn wrap(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let mut wrapper = vec![b'w'; 37];
        wrapper.extend_from_slice(bytes);
        wrapper.extend_from_slice(&[b'z'; 59]);
        let path = self.root.join(name);
        std::fs::write(&path, wrapper).unwrap();
        path
    }

    fn arguments(&self, original: &std::path::Path) -> serde_json::Value {
        serde_json::json!({"original": original, "module": CONTROLLED_UUID,
            "ranges": [{"address": "0x1000", "size": 10}, {"address": "0x10fe", "size": 4},
                {"address": "0x1200", "size": 2}]})
    }
}

impl Drop for ControlledFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn agent_compare(project: &Project, arguments: serde_json::Value) -> Result<serde_json::Value, String> {
    let (text, failed) =
        rampage_api::tools::call(&rampage_api::tools::tools(), project, "compare_runtime_bytes", arguments);
    if failed { Err(text) } else { Ok(serde_json::from_str(&text).unwrap()) }
}

#[test]
fn agent_selected_original_uses_capture_architecture_and_independent_identity_goldens() {
    let fixture = ControlledFixture::new();
    let project = Project::new(Binary::open(&fixture.capture).unwrap());
    let standalone = agent_compare(&project, fixture.arguments(&fixture.original)).unwrap();
    assert_eq!(standalone["original_image_sha256"], CONTROLLED_IMAGE_SHA256);
    assert_eq!(
        standalone["capture_identity"],
        serde_json::json!({"schema": CONTROLLED_CAPTURE_SCHEMA, "sha256": CONTROLLED_CAPTURE_SHA256})
    );
    assert_eq!(standalone["module_uuid"], CONTROLLED_UUID);
    assert_eq!(standalone["arch"], "aarch64");
    assert_eq!(standalone["image_base"], "0x100000000");
    assert_eq!(standalone["runtime_base"], "0x1000");
    assert_eq!(standalone["requested_bytes"], 16);
    assert_eq!(standalone["equal_bytes"], 7);
    assert_eq!(standalone["changed_bytes"], 1);
    assert_eq!(standalone["unavailable_bytes"], 8);
    assert_eq!(standalone["spans_total"], 8);
    assert_eq!(
        standalone["spans"],
        serde_json::json!([
            {"runtime_address": "0x1000", "image_address": "0x100000000", "size": 2,
                "status": "capture_unavailable"},
            {"runtime_address": "0x1002", "image_address": "0x100000002", "size": 2, "status": "equal"},
            {"runtime_address": "0x1004", "image_address": "0x100000004", "size": 1, "status": "changed"},
            {"runtime_address": "0x1005", "image_address": "0x100000005", "size": 3, "status": "equal"},
            {"runtime_address": "0x1008", "image_address": "0x100000008", "size": 2,
                "status": "capture_unavailable"},
            {"runtime_address": "0x10fe", "image_address": "0x1000000fe", "size": 2, "status": "equal"},
            {"runtime_address": "0x1100", "image_address": "0x100000100", "size": 2,
                "status": "original_unavailable"},
            {"runtime_address": "0x1200", "image_address": "0x100000200", "size": 2,
                "status": "both_unavailable"}
        ])
    );
    let thin = fixture.wrap("thin.bin", &fixture.bytes);
    let fat = fixture.wrap("fat.bin", &controlled_universal(&fixture.bytes));
    for (path, length) in [(&thin, 0x100), (&fat, 0x2100)] {
        for offset in [serde_json::json!(37), serde_json::json!("37"), serde_json::json!("0x25")] {
            for length in
                [serde_json::Value::Null, serde_json::json!(length), serde_json::json!(format!("{length:#x}"))]
            {
                let mut input = fixture.arguments(path);
                input["original_image_offset"] = offset.clone();
                input["original_image_length"] = length;
                assert_eq!(agent_compare(&project, input).unwrap(), standalone);
            }
        }
    }
    for selectors in [
        serde_json::json!({"original_image_offset": null, "original_image_length": null}),
        serde_json::json!({"original_image_offset": 0}),
        serde_json::json!({"original_image_offset": "0", "original_image_length": "256"}),
    ] {
        let mut input = fixture.arguments(&fixture.original);
        input.as_object_mut().unwrap().extend(selectors.as_object().unwrap().clone());
        assert_eq!(agent_compare(&project, input).unwrap(), standalone);
    }
}

#[test]
fn agent_original_selectors_reject_bad_json_and_lone_length_before_original_io() {
    let fixture = ControlledFixture::new();
    let project = Project::new(Binary::open(&fixture.capture).unwrap());
    let missing = fixture.root.join("missing-original");
    for value in [
        serde_json::json!(true),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("0xzz"),
        serde_json::json!("18446744073709551616"),
        serde_json::json!("0x10000000000000000"),
    ] {
        for field in ["original_image_offset", "original_image_length"] {
            let mut input = fixture.arguments(&missing);
            input[field] = value.clone();
            let error = agent_compare(&project, input).unwrap_err();
            assert!(error.contains("file offset or byte count"), "{field}: {value}: {error}");
            assert!(!error.contains("missing-original"), "{error}");
        }
    }
    for offset in [None, Some(serde_json::Value::Null)] {
        let mut input = fixture.arguments(&missing);
        if let Some(offset) = offset {
            input["original_image_offset"] = offset;
        }
        input["original_image_length"] = serde_json::json!(0);
        let error = agent_compare(&project, input).unwrap_err();
        assert!(error.contains("original_image_length needs original_image_offset"), "{error}");
        assert!(!error.contains("missing-original"), "{error}");
    }
    let mut input = fixture.arguments(&fixture.original);
    input.as_object_mut().unwrap().remove("original");
    assert!(agent_compare(&project, input).unwrap_err().contains("missing field `original`"));
}

#[test]
fn agent_original_selector_typos_and_unknown_sources_are_refused_before_original_io() {
    let fixture = ControlledFixture::new();
    let project = Project::new(Binary::open(&fixture.capture).unwrap());
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let missing = fixture.root.join("missing-explicit-original");
    for path in [&wrapper, &missing] {
        for field in ["original_image_lenght", "original_source"] {
            let mut input = fixture.arguments(path);
            input["original_image_offset"] = serde_json::json!(37);
            input[field] = serde_json::json!(20);
            let error = agent_compare(&project, input).unwrap_err();
            assert!(error.contains(&format!("unknown field `{field}`")), "{error}");
            assert!(!error.contains("missing-explicit-original"), "{error}");
            assert!(!error.contains("original_image_sha256"), "{error}");
        }
    }
}

#[test]
fn agent_selected_original_pages_and_poisoned_annotation_logs_leave_no_annotations() {
    let fixture = ControlledFixture::new();
    let project = Project::new(Binary::open(&fixture.capture).unwrap());
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let mut logs = vec![
        fixture.capture.with_extension("json.rampage"),
        fixture.original.with_extension("macho.rampage"),
        fixture.root.join(format!(".{CONTROLLED_CAPTURE_SCHEMA}-{CONTROLLED_CAPTURE_SHA256}.jsonl")),
    ];
    for suffix in [".rampage", "@0x25.rampage-image", "@0x25+0x100.rampage-image"] {
        let mut path = wrapper.as_os_str().to_owned();
        path.push(suffix);
        logs.push(PathBuf::from(path));
    }
    for log in &logs {
        std::fs::write(log, b"poisoned annotation log\n").unwrap();
    }
    let mut input = fixture.arguments(&wrapper);
    input["original_image_offset"] = serde_json::json!(37);
    input["original_image_length"] = serde_json::json!(256);
    let full = agent_compare(&project, input.clone()).unwrap();
    input["offset"] = serde_json::json!(2);
    input["limit"] = serde_json::json!(2);
    let page = agent_compare(&project, input.clone()).unwrap();
    assert_eq!(page["spans"], serde_json::json!(&full["spans"].as_array().unwrap()[2..4]));
    for field in [
        "capture_identity",
        "original_image_sha256",
        "requested_bytes",
        "equal_bytes",
        "changed_bytes",
        "unavailable_bytes",
        "spans_total",
    ] {
        assert_eq!(page[field], full[field], "{field}");
    }
    input["offset"] = serde_json::json!(usize::MAX);
    let empty = agent_compare(&project, input).unwrap();
    assert_eq!(empty["offset"], 8);
    assert_eq!(empty["spans"], serde_json::json!([]));
    assert_eq!(empty["requested_bytes"], 16);
    assert!(project.annotation_list().names.is_empty());
    assert!(project.annotation_list().comments.is_empty());
    for log in logs {
        assert_eq!(std::fs::read(log).unwrap(), b"poisoned annotation log\n");
    }
}

#[test]
fn agent_selected_original_never_transfers_valid_original_annotations_to_capture() {
    let fixture = ControlledFixture::new();
    let project = Project::new(Binary::open(&fixture.capture).unwrap());
    let wrapper = fixture.wrap("original.bin", &fixture.bytes);
    let source_annotations = format!(
        "{{\"image\":\"{CONTROLLED_IMAGE_SHA256}\"}}\n\
         {{\"field\":\"name\",\"address\":\"0x100000004\",\"value\":\"original_alias\",\"previous\":null}}\n\
         {{\"field\":\"comment\",\"address\":\"0x100000004\",\"value\":\"original comment\",\"previous\":null}}\n"
    );
    let mut sidecar = wrapper.as_os_str().to_owned();
    sidecar.push("@0x25.rampage-image");
    let sidecar = PathBuf::from(sidecar);
    std::fs::write(&sidecar, &source_annotations).unwrap();
    let mut input = fixture.arguments(&wrapper);
    input["original_image_offset"] = serde_json::json!(37);
    let result = agent_compare(&project, input.clone()).unwrap();
    assert_eq!(result["equal_bytes"], 7);
    assert!(project.annotation_list().names.is_empty());
    assert!(project.annotation_list().comments.is_empty());
    assert!(project.resolve("original_alias").is_err());
    input["ranges"][0]["address"] = serde_json::json!("original_alias");
    assert!(agent_compare(&project, input).unwrap_err().contains("hexadecimal address"));
    assert_eq!(std::fs::read_to_string(sidecar).unwrap(), source_annotations);
}
