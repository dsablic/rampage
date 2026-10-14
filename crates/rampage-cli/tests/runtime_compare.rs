use std::path::{Path, PathBuf};

use assert_cmd::Command;
use rampage_loaders::{Binary, Details};
use serde_json::Value;

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            Self(std::env::temp_dir().join(format!("rampage-cli-runtime-compare-{name}-{}", std::process::id())));
        std::fs::create_dir(&root.0).unwrap();
        root
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn wrap(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let mut wrapper = vec![b'w'; 37];
        wrapper.extend_from_slice(bytes);
        wrapper.extend_from_slice(&[b'z'; 59]);
        self.write(name, &wrapper)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn byte_comparison_uses_explicit_inputs_without_loading_annotation_sidecars() {
    let root = Fixture(std::env::temp_dir().join(format!("rampage-cli-runtime-compare-{}", std::process::id())));
    std::fs::create_dir(&root.0).unwrap();
    let original_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
    let original = Binary::open(&original_path).unwrap();
    let Details::MachO(details) = &original.details else { panic!("not Mach-O") };
    let uuid = details.uuid.as_deref().unwrap();
    let image_base =
        original.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let snapshot_path = root.0.join("snapshot.json");
    let snapshot = serde_json::json!({"format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
        "provenance": "controlled CLI comparison", "regions": [{"name": "selected", "address": "0x1000",
            "permissions": "r--", "bytes": "cffaedfe"}],
        "modules": [{"name": "fixture", "path": "/never/opened", "uuid": uuid,
            "image_base": format!("{image_base:#x}"), "runtime_base": "0x1000"}]});
    std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    std::fs::create_dir(snapshot_path.with_extension("json.rampage")).unwrap();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "compare-runtime"])
        .arg(&snapshot_path)
        .arg("--original")
        .arg(original_path)
        .args(["--module", uuid, "--range", "0x1000:4"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["equal_bytes"], 4);
    assert_eq!(result["spans"][0]["runtime_address"], "0x1000");
    assert_eq!(result["spans"][0]["image_address"], format!("{image_base:#x}"));
}

const UUID: &str = "11111111111111111111111111111111";
const IMAGE_BASE: u64 = 0x100000000;
// Independent Python hashlib goldens: the raw 256-byte controlled Mach-O, and capture v1 canonical encoding.
// Capture fields use BE u64 lengths/counts/addresses and UTF-8 text; aarch64, little-endian, no target context;
// Read-only regions (0x1002, edfef3000001), (0x10fe, a5a50102); no Thumb/seeds/entry;
// module (UUID, IMAGE_BASE, 0x1000). Region names, module paths and provenance are excluded from the identity.
const ORIGINAL_SHA256: &str = "8002eb6adf4b391fbb0e0561ad011f8b90b64ece0bc91f2a541d9f6e36647075";
const CAPTURE_SCHEMA: &str = "rampage-capture-identity-v1";
const CAPTURE_SHA256: &str = "bf2175b02e8fab15c29fa7920a9651613353d85b540d428f1cf1e44ac2445568";

fn controlled_macho(cpu: u32, uuid_byte: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for word in [0xfeedfacf, cpu, 0, 2, 2, 96, 0, 0, 0x19, 72] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    for word in [IMAGE_BASE, 0x200, 0, 0x100] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for word in [5u32, 5, 0, 0, 0x1b, 24] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&[uuid_byte; 16]);
    bytes.resize(0x100, 0xa5);
    bytes
}

fn controlled_universal(selected: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    for word in [0xcafebabfu32, 2] {
        header.extend_from_slice(&word.to_be_bytes());
    }
    for (cpu, subtype, offset) in [(0x01000007u32, 3u32, 0x1000u64), (0x0100000c, 0, 0x2000)] {
        header.extend_from_slice(&cpu.to_be_bytes());
        header.extend_from_slice(&subtype.to_be_bytes());
        header.extend_from_slice(&offset.to_be_bytes());
        header.extend_from_slice(&0x100u64.to_be_bytes());
        header.extend_from_slice(&12u32.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes());
    }
    header.resize(0x2000, 0);
    header[0x1000..0x1100].copy_from_slice(&controlled_macho(0x01000007, 0x22));
    header.extend_from_slice(selected);
    header
}

struct ControlledComparison {
    root: Fixture,
    original: PathBuf,
    wrapper: PathBuf,
    capture: PathBuf,
    bytes: Vec<u8>,
}

impl ControlledComparison {
    fn new(name: &str) -> Self {
        let root = Fixture::new(name);
        let bytes = controlled_macho(0x0100000c, 0x11);
        let original = root.write("original.macho", &bytes);
        let wrapper = root.wrap("wrapper.bin", &bytes);
        let mut selected = bytes[2..8].to_vec();
        selected[2] ^= 0xff;
        let snapshot = serde_json::json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
            "provenance": "constructed CLI comparison fixture",
            "regions": [
                {"name": "selected", "address": "0x1002", "permissions": "r--",
                    "bytes": rampage_arch::hex::bytes(&selected)},
                {"name": "file-end", "address": "0x10fe", "permissions": "r--", "bytes": "a5a50102"}
            ],
            "modules": [{"name": "fixture", "path": "/never/opened/original", "uuid": UUID,
                "image_base": format!("{IMAGE_BASE:#x}"), "runtime_base": "0x1000"}]
        });
        let capture = root.write("snapshot.json", &serde_json::to_vec(&snapshot).unwrap());
        Self { root, original, wrapper, capture, bytes }
    }

    fn command(&self, route: &[&str], original: &Path, options: &[&str]) -> Command {
        let mut command = Command::cargo_bin("rampage").unwrap();
        command
            .env_remove("RAMPAGE_PACKS")
            .args(["--json"])
            .args(route)
            .arg(&self.capture)
            .arg("--original")
            .arg(original)
            .args(["--module", UUID, "--range", "0x1000:10", "--range", "0x10fe:4", "--range", "0x1200:2"])
            .args(options);
        command
    }
}

#[test]
fn selected_original_preserves_standalone_identity_hash_addresses_and_all_byte_statuses() {
    let fixture = ControlledComparison::new("embedded");
    let universal = controlled_universal(&fixture.bytes);
    let fat_wrapper = fixture.root.wrap("universal-wrapper.bin", &universal);
    let expected =
        fixture.command(&["compare-runtime"], &fixture.original, &[]).assert().success().get_output().clone();
    let result: Value = serde_json::from_slice(&expected.stdout).unwrap();
    assert_eq!(result["module_uuid"], UUID);
    assert_eq!(result["arch"], "aarch64");
    assert_eq!(result["runtime_base"], "0x1000");
    assert_eq!(result["image_base"], format!("{IMAGE_BASE:#x}"));
    assert_eq!(result["requested_bytes"], 16);
    assert_eq!(result["equal_bytes"], 7);
    assert_eq!(result["changed_bytes"], 1);
    assert_eq!(result["unavailable_bytes"], 8);
    assert_eq!(result["spans"][0]["runtime_address"], "0x1000");
    assert_eq!(result["spans"][0]["image_address"], format!("{IMAGE_BASE:#x}"));
    let statuses: Vec<_> =
        result["spans"].as_array().unwrap().iter().map(|span| span["status"].as_str().unwrap()).collect();
    assert_eq!(
        statuses,
        [
            "capture_unavailable",
            "equal",
            "changed",
            "equal",
            "capture_unavailable",
            "equal",
            "original_unavailable",
            "both_unavailable"
        ]
    );
    assert_eq!(result["original_image_sha256"], ORIGINAL_SHA256);
    assert_eq!(result["capture_identity"], serde_json::json!({"schema": CAPTURE_SCHEMA, "sha256": CAPTURE_SHA256}));
    let identity_log = fixture.root.0.join(format!(".{CAPTURE_SCHEMA}-{CAPTURE_SHA256}.jsonl"));
    std::fs::create_dir(&identity_log).unwrap();
    std::fs::create_dir(fixture.capture.with_extension("json.rampage")).unwrap();
    std::fs::create_dir(fixture.original.with_extension("macho.rampage")).unwrap();
    for (wrapper, length, arch_suffix) in [(&fixture.wrapper, "0x100", ""), (&fat_wrapper, "0x2100", ".aarch64")] {
        for suffix in [
            ".rampage".to_owned(),
            format!("@0x25{arch_suffix}.rampage-image"),
            format!("@0x25+{length}{arch_suffix}.rampage-image"),
        ] {
            let mut sidecar = wrapper.as_os_str().to_owned();
            sidecar.push(suffix);
            std::fs::create_dir(PathBuf::from(sidecar)).unwrap();
        }
        for route in [&["compare-runtime"][..], &["runtime", "bytes", "compare"][..]] {
            for options in [
                &["--original-image-offset", "37"][..],
                &["--original-image-offset", "0x25", "--original-image-length", length][..],
                &["--arch", "aarch64", "--original-image-offset", "37"][..],
            ] {
                let output = fixture.command(route, wrapper, options).assert().success().get_output().clone();
                assert_eq!(output.stdout, expected.stdout, "{route:?}: {options:?}");
                assert_eq!(output.stderr, expected.stderr, "{route:?}: {options:?}");
            }
        }
    }
    for route in [&["compare-runtime"][..], &["runtime", "bytes", "compare"][..]] {
        for options in [
            &[][..],
            &["--original-image-offset", "0"][..],
            &["--original-image-offset", "0", "--original-image-length", "0x100"][..],
        ] {
            let output = fixture.command(route, &fixture.original, options).assert().success().get_output().clone();
            assert_eq!(output.stdout, expected.stdout, "{route:?}: {options:?}");
            assert_eq!(output.stderr, expected.stderr, "{route:?}: {options:?}");
        }
    }
}

#[test]
fn selected_original_rejects_truncated_headers_invalid_bounds_and_uuid_or_architecture_mismatches() {
    let fixture = ControlledComparison::new("invalid-embedded");
    let mut truncated = vec![b'w'; 37];
    truncated.extend_from_slice(&fixture.bytes[..20]);
    let truncated = fixture.root.write("truncated.bin", &truncated);
    let wrong_uuid = fixture.root.wrap("wrong-uuid.bin", &controlled_macho(0x0100000c, 0x22));
    let wrong_arch = fixture.root.wrap("wrong-arch.bin", &controlled_macho(0x01000007, 0x11));
    let cases: &[(&Path, &[&str], &str)] = &[
        (&truncated, &["--original-image-offset", "37"], "truncated"),
        (&fixture.wrapper, &["--original-image-offset", "0"], "Unknown file magic"),
        (&fixture.wrapper, &["--original-image-offset", "0xffffffffffffffff"], "past the end"),
        (&fixture.wrapper, &["--original-image-offset", "37", "--original-image-length", "0"], "does not fit"),
        (&fixture.wrapper, &["--original-image-offset", "37", "--original-image-length", "0x1000"], "does not fit"),
        (&fixture.wrapper, &["--original-image-offset", "37", "--original-image-length", "20"], "cannot parse"),
        (
            &fixture.wrapper,
            &["--original-image-offset", "37", "--original-image-length", "0xffffffffffffffff"],
            "overflows",
        ),
        (&wrong_uuid, &["--original-image-offset", "37"], "UUID does not match"),
        (&wrong_arch, &["--original-image-offset", "37"], "contains x86_64"),
    ];
    for route in [&["compare-runtime"][..], &["runtime", "bytes", "compare"][..]] {
        for &(original, options, message) in cases {
            let output = fixture.command(route, original, options).assert().failure().get_output().clone();
            assert_eq!(output.status.code(), Some(1), "{options:?}");
            assert!(output.stdout.is_empty(), "{options:?}");
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains(message), "{route:?}: {options:?}: {error}");
        }
    }
}

#[test]
fn selected_original_rejects_malformed_universal_entries_duplicates_and_overflowing_slice_ranges() {
    let fixture = ControlledComparison::new("invalid-universal");
    let valid = controlled_universal(&fixture.bytes);
    let mut malformed = valid.clone();
    malformed[64..68].copy_from_slice(&21u32.to_be_bytes());
    let mut duplicate = valid.clone();
    duplicate[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
    let mut overflow = valid;
    overflow[48..56].copy_from_slice(&(u64::MAX - 0xf).to_be_bytes());
    overflow[64..68].copy_from_slice(&4u32.to_be_bytes());
    for (name, bytes, message) in [
        ("malformed.bin", malformed, "invalid file range or alignment"),
        ("duplicate.bin", duplicate, "multiple aarch64 slices"),
        ("overflow.bin", overflow, "invalid file range or alignment"),
    ] {
        let original = fixture.root.wrap(name, &bytes);
        for route in [&["compare-runtime"][..], &["runtime", "bytes", "compare"][..]] {
            for options in [
                &["--original-image-offset", "37"][..],
                &["--original-image-offset", "37", "--original-image-length", "0x2100"][..],
            ] {
                let output = fixture.command(route, &original, options).assert().failure().get_output().clone();
                assert_eq!(output.status.code(), Some(1), "{name}: {route:?}: {options:?}");
                assert!(output.stdout.is_empty(), "{name}: {route:?}: {options:?}");
                let error = String::from_utf8(output.stderr).unwrap();
                assert!(error.contains(message), "{name}: {route:?}: {options:?}: {error}");
            }
        }
    }
}
