//! The sample APK through the container reader, and binary XML: round trips and hostile documents.

use rampage_dex::apk::{Apk, Limits};
use rampage_dex::axml::{self, Value};
use rampage_dex::manifest::{ComponentKind, Manifest};
use rampage_dex::testkit::{XmlNode, XmlValue, sample_apk, sample_manifest, write_axml};

fn scratch(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("rampage-dex-{name}-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn the_manifest_round_trips_in_both_string_encodings() {
    for utf8 in [false, true] {
        let document = axml::parse(&write_axml(&sample_manifest(), utf8)).unwrap();
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
        let manifest = Manifest::from_document(&document);
        assert_eq!(manifest.package, "com.example.recorder");
        assert_eq!(manifest.version_code, Some(7));
        assert_eq!(manifest.version_name.as_deref(), Some("1.2"));
        assert_eq!((manifest.sdk.min, manifest.sdk.target, manifest.sdk.compile), (Some(21), Some(33), Some(33)));
        assert_eq!(manifest.uses_permissions.len(), 4);
        assert_eq!(manifest.application.uses_cleartext_traffic, Some(true));
        let receiver = manifest.components.iter().find(|component| component.kind == ComponentKind::Receiver).unwrap();
        assert_eq!(receiver.name, "com.example.recorder.BootReceiver");
        assert!(receiver.start_at_boot);
        assert!(!receiver.exported);
        let activity = manifest.components.iter().find(|component| component.kind == ComponentKind::Activity).unwrap();
        assert!(activity.exported && activity.exported_explicit);
        let service = manifest.components.iter().find(|component| component.kind == ComponentKind::Service).unwrap();
        assert_eq!(service.foreground_service_type.as_deref(), Some("microphone"));
    }
}

#[test]
fn blanked_attribute_names_fall_back_to_the_resource_map() {
    let mut bytes = write_axml(&sample_manifest(), false);
    // The first pooled string is the first mapped attribute name; blank its length so the name is empty.
    let strings_start = u32::from_le_bytes(bytes[8 + 20..8 + 24].try_into().unwrap()) as usize;
    let first = 8 + strings_start;
    bytes[first..first + 2].copy_from_slice(&0u16.to_le_bytes());
    let document = axml::parse(&bytes).unwrap();
    let manifest = Manifest::from_document(&document);
    assert_eq!(manifest.version_code, Some(7));
}

#[test]
fn the_sample_apk_opens_with_multidex_manifest_resources_and_libraries() {
    let path = scratch("apk", &sample_apk(Some(b"\x7fELF not really")));
    let apk = Apk::open(&path, Limits::default()).unwrap();
    std::fs::remove_file(&path).unwrap();
    let paths: Vec<&str> = apk.dex.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(paths, ["classes.dex", "classes2.dex"]);
    assert!(apk.dex.iter().all(|entry| entry.dex.is_ok()));
    assert_eq!(apk.manifest.unwrap().package, "com.example.recorder");
    assert_eq!(apk.resources.unwrap().packages, 1);
    assert_eq!(apk.native_libs.len(), 1);
    assert_eq!(apk.native_libs[0].abi, "arm64-v8a");
    assert!(apk.native_libs[0].bytes.is_some());
}

#[test]
fn a_file_that_is_not_a_zip_is_refused() {
    let path = scratch("not-zip", b"just text, no archive here at all");
    assert!(Apk::open(&path, Limits::default()).is_err());
    std::fs::remove_file(&path).unwrap();
}

fn string_pool_bomb(references: usize) -> Vec<u8> {
    // One 30000-unit string referenced by many attributes.
    let huge = "x".repeat(30_000);
    let mut node = XmlNode::new("manifest");
    for index in 0..references {
        node = node.plain(&format!("a{index}"), XmlValue::Str(huge.clone()));
    }
    write_axml(&node, false)
}

#[test]
fn a_string_referenced_too_often_exhausts_the_text_budget() {
    let limits = axml::Limits { max_text: 1 << 20, ..axml::Limits::default() };
    assert!(axml::parse_with(&string_pool_bomb(10), limits).is_ok());
    assert!(matches!(axml::parse_with(&string_pool_bomb(40), limits), Err(rampage_dex::DexError::Limit(_))));
}

#[test]
fn deep_nesting_and_lying_pools_are_refused() {
    let mut node = XmlNode::new("leaf");
    for _ in 0..100 {
        node = XmlNode::new("level").child(node);
    }
    assert!(axml::parse(&write_axml(&node, false)).is_err());
    let mut bytes = write_axml(&sample_manifest(), false);
    // A string count far beyond the pool.
    bytes[16..20].copy_from_slice(&0x4000_0000u32.to_le_bytes());
    assert!(axml::parse(&bytes).is_err());
}

#[test]
fn truncated_and_damaged_documents_never_panic() {
    let bytes = write_axml(&sample_manifest(), true);
    for len in 0..bytes.len() {
        if let Ok(document) = axml::parse(&bytes[..len]) {
            let _ = Manifest::from_document(&document);
        }
    }
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..3000 {
        let mut damaged = bytes.clone();
        for _ in 0..1 + next() % 6 {
            let at = (next() as usize) % damaged.len();
            damaged[at] = next() as u8;
        }
        if let Ok(document) = axml::parse(&damaged) {
            let _ = Manifest::from_document(&document);
        }
    }
    assert_eq!(Value::Int(3).text(), "3");
}

#[test]
fn dex_files_are_read_in_multidex_order_and_the_first_manifest_wins() {
    use rampage_dex::testkit::{sample_classes, sample_secondary_classes, write_dex, write_zip};
    let manifest = write_axml(&sample_manifest(), false);
    let other =
        write_axml(&XmlNode::new("manifest").plain("package", XmlValue::Str("com.example.other".to_owned())), false);
    let first = write_dex(&sample_classes(), 35);
    let second = write_dex(&sample_secondary_classes(), 35);
    let bytes = write_zip(&[
        ("classes2.dex", &second, false),
        ("AndroidManifest.xml", &manifest, false),
        ("classes.dex", &first, false),
        ("AndroidManifest.xml", &other, false),
    ]);
    let path = scratch("order", &bytes);
    let limits = Limits { max_dex_files: 1, ..Limits::default() };
    let apk = Apk::open(&path, limits).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(apk.dex[0].path, "classes.dex");
    assert!(apk.dex[0].dex.is_ok(), "the first multidex file is read first");
    assert!(apk.dex[1].dex.is_err());
    assert_eq!(apk.manifest.unwrap().package, "com.example.recorder");
    assert!(apk.warnings.iter().any(|warning| warning.contains("2 AndroidManifest.xml entries")), "{:?}", apk.warnings);
}

#[test]
fn an_aab_protobuf_manifest_is_named_as_such() {
    use rampage_dex::testkit::{sample_classes, write_dex, write_zip};
    let dex = write_dex(&sample_classes(), 35);
    let bytes = write_zip(&[
        ("base/manifest/AndroidManifest.xml", b"\x0a\x05proto", false),
        ("base/dex/classes.dex", &dex, false),
    ]);
    let path = scratch("aab", &bytes);
    let apk = Apk::open(&path, Limits::default()).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(apk.manifest_error.unwrap().contains("protobuf"));
    assert_eq!(apk.dex.len(), 1);
}

#[test]
fn axml_warnings_are_capped() {
    let mut bytes = write_axml(&sample_manifest(), false);
    // Many trailing nested-document chunks each add a warning.
    for _ in 0..1000 {
        bytes.extend_from_slice(&0x0003u16.to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
    }
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    let document = axml::parse(&bytes).unwrap();
    assert!(document.warnings.len() <= 17, "{}", document.warnings.len());
}
