//! The firmware patching round trip on an owned Cortex-M3 image whose boot code verifies a CRC-32 over its
//! application: integrity_checks finds the check, a patch invalidates it, fix corrects it, export_image writes the
//! original container and the reopened export is valid with the patch present.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::tools::{call_shared, tools};
use rampage_api::{Project, RawProjectRequest, Session};
use serde_json::{Value, json};

const FIRMWARE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-crc");
const APP: u64 = 0x0800_0400;
const CRC_FIELD: u64 = 0x0800_07fc;

struct Owned(PathBuf);

impl Owned {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-integrity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn copy(&self, extension: &str) -> PathBuf {
        let path = self.0.join(format!("firmware.{extension}"));
        std::fs::copy(format!("{FIRMWARE}.{extension}"), &path).unwrap();
        path
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(extension: &str) -> Vec<u8> {
    std::fs::read(format!("{FIRMWARE}.{extension}")).unwrap()
}

fn raw(format: &str) -> RawProjectRequest {
    let value = match format {
        "bin" => json!({ "profile": "cortex-m3", "offset": 0, "length": 0x800, "base_address": "0x8000000",
                         "vector_table": true }),
        "hex" => json!({ "profile": "cortex-m3", "format": "ihex", "vector_table": true }),
        _ => json!({ "profile": "cortex-m3", "format": "srec", "vector_table": true }),
    };
    serde_json::from_value(value).unwrap()
}

fn truth(name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(format!("{FIRMWARE}.elf")).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

fn call(project: &mut Arc<Project>, name: &str, input: Value) -> Value {
    let (text, failed) = call_shared(&tools(), project, name, input);
    assert!(!failed, "{name}: {text}");
    serde_json::from_str(&text).unwrap()
}

fn tokens(report: &Value) -> Value {
    json!({
        "source_sha256": report["receipt"]["source_sha256"],
        "expected_revision": report["receipt"]["revision_sha256"],
    })
}

fn the_check(report: &Value) -> &Value {
    let checks = report["checks"].as_array().unwrap();
    checks
        .iter()
        .find(|check| check["stored"]["address"] == format!("{CRC_FIELD:#x}"))
        .unwrap_or_else(|| panic!("no check at the CRC field: {report:#}"))
}

#[test]
fn integrity_checks_find_fix_and_export_the_application_crc() {
    let owned = Owned::new();
    let path = owned.copy("hex");
    let session = Session::default();
    let mut project = session.open_raw(&path, &raw("hex")).unwrap();

    // Found by brute force, explained by code, confirmed by running the boot code's own routine.
    let report = call(&mut project, "integrity_checks", json!({}));
    let check = the_check(&report);
    assert_eq!(check["algorithm"], "crc32", "{check:#}");
    assert_eq!(check["ranges"], json!([{ "start": format!("{APP:#x}"), "end": format!("{CRC_FIELD:#x}") }]));
    assert_eq!((check["valid"].as_bool(), check["stored"]["endian"].as_str()), (Some(true), Some("little")));
    assert_eq!(check["confidence"], "high", "{check:#}");
    assert_eq!(check["confirmed_by_emulation"], true, "{check:#}");
    let evidence = check["evidence"].to_string();
    assert!(
        evidence.contains("brute force") && evidence.contains("code:") && evidence.contains("emulation"),
        "{evidence}"
    );
    let routine = format!("{:#x}", truth("crc32_compute"));
    assert!(report["routines"].as_array().unwrap().iter().any(|row| row["address"] == routine), "{report:#}");
    assert_eq!(report["invalid"], 0);
    assert_eq!(report["fix"]["writes"], json!([]));

    // Patch one byte of the application's table: the check no longer holds, and the preview says how to fix it.
    let table = truth("app_table");
    let mut patch = tokens(&report);
    patch["at"] = json!(format!("{table:#x}"));
    patch["original_hex"] = json!("11");
    patch["replacement_hex"] = json!("42");
    patch["allow_data"] = json!(false);
    call(&mut project, "patch_bytes", patch);
    let report = call(&mut project, "integrity_checks", json!({ "emulate": false }));
    let check = the_check(&report);
    assert_eq!(check["valid"], false, "{check:#}");
    assert_eq!(report["fix"]["applied"], false);
    assert_eq!(report["fix"]["writes"][0]["action"], "patch");

    // Fix needs the reviewed receipt, then writes the corrected CRC as a second patch record.
    let (text, failed) = call_shared(&tools(), &mut project, "integrity_checks", json!({ "fix": true }));
    assert!(failed && text.contains("source_sha256"), "{text}");
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    fix["emulate"] = json!(false);
    let fixed = call(&mut project, "integrity_checks", fix);
    assert_eq!(fixed["fix"]["applied"], true, "{fixed:#}");
    assert_eq!(the_check(&fixed)["valid"], true, "{fixed:#}");
    assert_eq!(fixed["invalid"], 0);
    let patches = call(&mut project, "list_patches", json!({}));
    assert_eq!(patches["total"], 2, "{patches:#}");

    // Export the original container and reopen it: valid, patch present, records rewritten in place.
    let exported = owned.0.join("patched.hex");
    let export = json!({ "destination": exported, "expected_revision": fixed["receipt"]["revision_sha256"] });
    let receipt = call(&mut project, "export_image", export);
    assert_eq!(receipt["format"], "ihex", "{receipt:#}");
    assert_eq!(receipt["records_rewritten"], 2, "{receipt:#}");
    let original = String::from_utf8(fixture("hex")).unwrap();
    let written = String::from_utf8(std::fs::read(&exported).unwrap()).unwrap();
    let changed = original.lines().zip(written.lines()).filter(|(left, right)| left != right).count();
    assert_eq!((original.lines().count(), changed), (written.lines().count(), 2));
    let mut reopened = Session::default().open_raw(&exported, &raw("hex")).unwrap();
    let report = call(&mut reopened, "integrity_checks", json!({ "emulate": false }));
    assert_eq!(the_check(&report)["valid"], true, "{report:#}");
    assert_eq!(reopened.binary.read(table, 1), Some(&[0x42][..]));
    // Exporting again refuses to replace the file.
    let again = json!({ "destination": exported, "expected_revision": fixed["receipt"]["revision_sha256"] });
    let (text, failed) = call_shared(&tools(), &mut project, "export_image", again);
    assert!(failed, "{text}");
}

#[test]
fn unpatched_exports_are_byte_identical_to_each_container() {
    let owned = Owned::new();
    for extension in ["hex", "srec", "bin"] {
        let path = owned.copy(extension);
        let mut project = Session::default().open_raw(&path, &raw(extension)).unwrap();
        let report = call(&mut project, "integrity_checks", json!({ "emulate": false }));
        assert_eq!(the_check(&report)["algorithm"], "crc32", "{extension}: {report:#}");
        let destination = owned.0.join(format!("copy.{extension}"));
        let receipt = call(&mut project, "export_image", json!({ "destination": destination }));
        assert_eq!(std::fs::read(&destination).unwrap(), fixture(extension), "{extension}: {receipt:#}");
    }
    // The flat binary of the record files fills the gap between boot code and application like the .bin.
    let path = owned.copy("srec");
    let mut project = Session::default().open_raw(&path, &raw("srec")).unwrap();
    let destination = owned.0.join("flat.bin");
    let receipt = call(&mut project, "export_image", json!({ "destination": destination, "format": "binary" }));
    assert_eq!(receipt["base_address"], "0x8000000");
    assert_eq!(std::fs::read(&destination).unwrap(), fixture("bin"));
    let destination = owned.0.join("app.bin");
    let one = json!({ "destination": destination, "format": "binary", "region": format!("{APP:#x}") });
    call(&mut project, "export_image", one);
    assert_eq!(std::fs::read(&destination).unwrap(), &fixture("bin")[0x400..]);
}

/// The flat binary opened with the application declared as its own region finds the same check.
#[test]
fn the_flat_image_finds_the_check_after_the_padding() {
    let owned = Owned::new();
    let path = owned.copy("bin");
    let mut project = Session::default().open_raw(&path, &raw("bin")).unwrap();
    let report = call(&mut project, "integrity_checks", json!({}));
    let check = the_check(&report);
    assert_eq!(check["ranges"][0]["start"], format!("{APP:#x}"), "{check:#}");
    assert_eq!(check["confirmed_by_emulation"], true, "{check:#}");
    assert!(report["search"]["bytes_hashed"].as_u64().unwrap() <= report["search"]["budget_bytes"].as_u64().unwrap());
}
