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

/// A weak chance match (an 8-bit sum no code references and no routine confirms) is reported and previewed, but a
/// default fix leaves it alone; naming its id fixes it.
#[test]
fn a_default_fix_never_writes_an_unconfirmed_weak_match() {
    let mut bytes: Vec<u8> = (0..128u32).map(|index| (index * 29 + 7) as u8).collect();
    let sum = bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
    assert!(sum != 0 && sum != 0xff);
    bytes.push(sum);
    let options = rampage_loaders::RawCodeOptions {
        profile: rampage_loaders::RawProfile::Msp430,
        base: 0x1000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    let project = Arc::new(Project::new(rampage_loaders::Binary::from_raw_code(bytes, options).unwrap()));
    let field = format!("{:#x}", 0x1000 + 128);
    let mut current = project.patch_bytes(0x1010, &[(16 * 29 + 7) as u8], &[0x5a], false).unwrap().project;
    let report = call(&mut current, "integrity_checks", json!({ "emulate": false }));
    let check = report["checks"].as_array().unwrap().iter().find(|check| check["stored"]["address"] == field);
    let check = check.unwrap_or_else(|| panic!("{report:#}"));
    assert_eq!((check["valid"].as_bool(), check["confidence"].as_str()), (Some(false), Some("low")), "{check:#}");
    let id = check["id"].clone();
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    fix["emulate"] = json!(false);
    let fixed = call(&mut current, "integrity_checks", fix.clone());
    assert_eq!(fixed["fix"]["applied"], false, "{fixed:#}");
    let preview = fixed["fix"]["writes"].as_array().unwrap().iter().find(|write| write["address"] == field).unwrap();
    assert_eq!(preview["action"], "preview_only", "{fixed:#}");
    assert_eq!(current.list_patches().unwrap().len(), 1);
    fix["ids"] = json!([id]);
    let fixed = call(&mut current, "integrity_checks", fix);
    assert_eq!(fixed["fix"]["applied"], true, "{fixed:#}");
    assert_eq!(current.list_patches().unwrap().len(), 2);
}

/// A user patch that overlaps the stored value without matching it exactly refuses the whole fix before any write.
#[test]
fn a_fix_refuses_before_writing_when_a_patch_overlaps_the_stored_value() {
    let owned = Owned::new();
    let path = owned.copy("hex");
    let mut project = Session::default().open_raw(&path, &raw("hex")).unwrap();
    let table = truth("app_table");
    project = project.patch_bytes(table, &[0x11], &[0x42], false).unwrap().project;
    let stored = fixture("bin")[0x7fe..0x800].to_vec();
    let replacement: Vec<u8> = stored.iter().map(|byte| !byte).collect();
    project = project.patch_bytes(CRC_FIELD + 2, &stored, &replacement, true).unwrap().project;
    let report = call(&mut project, "integrity_checks", json!({ "emulate": false }));
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    fix["emulate"] = json!(false);
    let (text, failed) = call_shared(&tools(), &mut project, "integrity_checks", fix);
    assert!(failed && text.contains("overlaps the stored value"), "{text}");
    assert_eq!(project.effective_snapshot().unwrap().list_patches().unwrap().len(), 2);
}

/// Nested checks (the boot image of benchmark suite v4: a CRC-16 over a configuration block, inside the range of a
/// CRC-32 its boot code also verifies). The CRC-16 routine reads a table whose address movw/movt forms, and its
/// caller passes the range and reads the stored value through immediates, so both checks are found; a fix writes
/// the inner value first, and never the outer one over a stale inner value.
#[test]
fn nested_checks_are_found_and_fixed_inner_first() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bench-v4/bin/boot-cm4.bin");
    let length = std::fs::metadata(&path).unwrap().len();
    let request = json!({ "profile": "cortex-m4", "offset": 0, "length": length, "base_address": 0,
                          "vector_table": true });
    let mut project = Session::default().open_raw(&path, &serde_json::from_value(request).unwrap()).unwrap();
    let report = call(&mut project, "integrity_checks", json!({}));
    let check = |report: &Value, address: &str| {
        let checks = report["checks"].as_array().unwrap();
        checks.iter().find(|check| check["stored"]["address"] == address).cloned().unwrap_or_else(|| {
            panic!("no check at {address}: {report:#}");
        })
    };
    let (inner, outer) = (check(&report, "0x840"), check(&report, "0x13fc"));
    assert_eq!((inner["algorithm"].as_str(), outer["algorithm"].as_str()), (Some("crc16_ccitt_false"), Some("crc32")));
    assert_eq!(outer["depends_on"], json!([inner["id"]]), "{report:#}");

    // A configuration change invalidates both values.
    let (baud, slower) = (115_200u32.to_le_bytes(), 57_600u32.to_le_bytes());
    project = project.patch_bytes(0x808, &baud, &slower, true).unwrap().project;
    let report = call(&mut project, "integrity_checks", json!({}));
    assert_eq!(report["invalid"], 2, "{report:#}");
    // The preview computes the outer value over the planned inner one, as a fix would write it.
    let pairs = |report: &Value| -> Vec<(String, String)> {
        let writes = report["fix"]["writes"].as_array().unwrap();
        writes.iter().map(|write| (write["address"].to_string(), write["replacement_hex"].to_string())).collect()
    };
    let preview = pairs(&report);

    // Fixing only the outer check while the inner one is stale writes nothing and names the inner value.
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    fix["ids"] = json!([outer["id"]]);
    let blocked = call(&mut project, "integrity_checks", fix);
    let write = &blocked["fix"]["writes"][0];
    assert_eq!(write["action"], "blocked", "{blocked:#}");
    assert_eq!(blocked["fix"]["applied"], false, "{blocked:#}");
    assert!(write["detail"].as_str().unwrap().contains("0x840"), "{blocked:#}");
    assert_eq!(project.list_patches().unwrap().len(), 1);

    // The default fix writes the inner value, then the outer one over it: both hold afterwards.
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    let fixed = call(&mut project, "integrity_checks", fix);
    let writes = fixed["fix"]["writes"].as_array().unwrap();
    let order: Vec<&str> = writes.iter().map(|write| write["address"].as_str().unwrap()).collect();
    assert_eq!(order, ["0x840", "0x13fc"], "{fixed:#}");
    assert_eq!(pairs(&fixed), preview, "the preview showed other values than the fix wrote");
    assert_eq!(fixed["fix"]["applied"], true, "{fixed:#}");
    assert_eq!(fixed["invalid"], 0, "{fixed:#}");
}

/// The application CRC-32 is the image's only check: no weak value inside its range borrows the code reference to
/// that CRC's stored value as evidence of a range end of its own.
#[test]
fn the_elf_has_exactly_one_check() {
    let path = PathBuf::from(format!("{FIRMWARE}.elf"));
    let mut project = Session::default().open(&path, None).unwrap();
    let report = call(&mut project, "integrity_checks", json!({}));
    let checks = report["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{report:#}");
    assert_eq!(checks[0]["stored"]["address"], format!("{CRC_FIELD:#x}"), "{report:#}");
    assert_eq!(checks[0]["depends_on"], json!([]), "{report:#}");
}

const ELF_FIRMWARE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/elf-cortex-m-crc");

/// A copy of `elf-cortex-m-crc<bits>.elf` in its own directory (its annotation log lands next to it).
fn elf_copy(owned: &Owned, bits: u32) -> PathBuf {
    let path = owned.0.join(format!("firmware{bits}.elf"));
    std::fs::copy(format!("{ELF_FIRMWARE}{bits}.elf"), &path).unwrap();
    path
}

fn elf_truth(bits: u32, name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(format!("{ELF_FIRMWARE}{bits}.elf")).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

/// The bytes at `address` of an ELF file, through its program headers (the test's own reading, not the loader's).
fn elf_bytes(file: &[u8], address: u64, length: usize) -> Vec<u8> {
    let word = |at: usize| u64::from(u32::from_le_bytes(file[at..at + 4].try_into().unwrap()));
    let (phoff, phnum) = (word(28) as usize, u16::from_le_bytes([file[44], file[45]]) as usize);
    for at in (0..phnum).map(|index| phoff + index * 32) {
        let (offset, vaddr, filesz) = (word(at + 4), word(at + 8), word(at + 16));
        if word(at) == 1 && vaddr <= address && address + length as u64 <= vaddr + filesz {
            let start = (offset + address - vaddr) as usize;
            return file[start..start + length].to_vec();
        }
    }
    panic!("{address:#x} is not file-backed");
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1)))
    })
}

fn crc16_arc(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0u16, |crc, &byte| {
        (0..8).fold(crc ^ u16::from(byte), |crc, _| if crc & 1 != 0 { (crc >> 1) ^ 0xa001 } else { crc >> 1 })
    })
}

/// A static ELF32 firmware executable is patched in place: integrity_checks fixes its CRC-32 as a patch to the ELF,
/// export_image writes the patched ELF (whose own bytes then pass the check by recompute) and a flat binary of its
/// loaded segments at their load addresses.
#[test]
fn an_elf_firmware_crc_is_fixed_and_exported_in_place() {
    const APP: u64 = 0x0800_0800;
    const FIELD: u64 = 0x0800_0bfc;
    let owned = Owned::new();
    let path = elf_copy(&owned, 32);
    let source = std::fs::read(&path).unwrap();
    let mut project = Session::default().open(&path, None).unwrap();
    let report = call(&mut project, "integrity_checks", json!({}));
    let check = report["checks"].as_array().unwrap().iter().find(|check| check["stored"]["address"] == "0x8000bfc");
    let check = check.unwrap_or_else(|| panic!("{report:#}"));
    assert_eq!((check["algorithm"].as_str(), check["valid"].as_bool()), (Some("crc32"), Some(true)), "{check:#}");
    assert_eq!(check["ranges"], json!([{ "start": format!("{APP:#x}"), "end": format!("{FIELD:#x}") }]));
    assert_eq!(check["confirmed_by_emulation"], true, "{check:#}");

    // Change the application's table and an initial value in .data, then let the fix write the CRC.
    let table = elf_truth(32, "app_table");
    let mut patch = tokens(&report);
    patch["at"] = json!(format!("{table:#x}"));
    patch["original_hex"] = json!("11");
    patch["replacement_hex"] = json!("42");
    patch["allow_data"] = json!(false);
    call(&mut project, "patch_bytes", patch);
    let receipt = call(&mut project, "list_patches", json!({}))["receipt"].clone();
    let mut period =
        json!({ "source_sha256": receipt["source_sha256"], "expected_revision": receipt["revision_sha256"] });
    period["at"] = json!("0x20000000"); // blink_period, the only .data word
    period["original_hex"] = json!("45230100");
    period["replacement_hex"] = json!("e8030000");
    period["allow_data"] = json!(true);
    call(&mut project, "patch_bytes", period);
    let report = call(&mut project, "integrity_checks", json!({ "emulate": false }));
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    let fixed = call(&mut project, "integrity_checks", fix);
    assert_eq!((fixed["fix"]["applied"].as_bool(), fixed["invalid"].as_u64()), (Some(true), Some(0)), "{fixed:#}");
    let patches = call(&mut project, "list_patches", json!({}));
    assert_eq!(patches["total"], 3, "{patches:#}");
    assert!(patches["patches"].as_array().unwrap().iter().all(|row| row["version"] == 3), "{patches:#}");

    // The patched ELF: only payload bytes changed, and its own CRC holds by recompute.
    let revision = fixed["receipt"]["revision_sha256"].clone();
    let exported = owned.0.join("patched.elf");
    let receipt = call(&mut project, "export_image", json!({ "destination": exported, "expected_revision": revision }));
    assert_eq!(receipt["format"], "native", "{receipt:#}");
    let written = std::fs::read(&exported).unwrap();
    assert_eq!(written.len(), source.len());
    assert!(written.iter().zip(&source).filter(|(left, right)| left != right).count() <= 1 + 4 + 4);
    assert_eq!(elf_bytes(&written, table, 1), [0x42]);
    let stored = u32::from_le_bytes(elf_bytes(&written, FIELD, 4).try_into().unwrap());
    assert_eq!(stored, crc32(&elf_bytes(&written, APP, (FIELD - APP) as usize)));
    assert_ne!(stored, crc32(&elf_bytes(&source, APP, (FIELD - APP) as usize)));
    let mut reopened = Session::default().open(&exported, None).unwrap();
    let report = call(&mut reopened, "integrity_checks", json!({ "emulate": false }));
    assert_eq!(report["invalid"], 0, "{report:#}");

    // The flat binary lays the loaded segments out at their load addresses, .data's initial values after .text.
    let flat = owned.0.join("patched.bin");
    let receipt = call(
        &mut project,
        "export_image",
        json!({ "destination": flat, "format": "binary", "expected_revision": revision }),
    );
    assert_eq!(receipt["base_address"], "0x8000000", "{receipt:#}");
    let mut expected = std::fs::read(format!("{ELF_FIRMWARE}32.bin")).unwrap();
    let data_load = 0x114; // .data loads from flash right after .text (0x08000000..0x08000114)
    expected[data_load as usize..data_load as usize + 4].copy_from_slice(&1000u32.to_le_bytes());
    let app = (APP - 0x0800_0000) as usize;
    expected[app..app + 0x3fc].copy_from_slice(&elf_bytes(&written, APP, 0x3fc));
    expected[app + 0x3fc..].copy_from_slice(&stored.to_le_bytes());
    assert_eq!(std::fs::read(&flat).unwrap(), expected);

    // Unpatched, the flat binary equals the toolchain's own (llvm-objcopy -O binary).
    let pristine = Owned::new();
    let mut original = Session::default().open(&elf_copy(&pristine, 32), None).unwrap();
    let plain = owned.0.join("plain.bin");
    call(&mut original, "export_image", json!({ "destination": plain, "format": "binary" }));
    assert_eq!(std::fs::read(&plain).unwrap(), std::fs::read(format!("{ELF_FIRMWARE}32.bin")).unwrap());
}

/// A CRC-16/ARC routine that forms its polynomial with one 16-bit movw (no literal, no movw/movt pair) is found as
/// code evidence, its check confirmed by running it, and a configuration change is fixed in the ELF.
#[test]
fn a_crc16_polynomial_formed_by_an_immediate_is_recognised() {
    const CONFIG: u64 = 0x0800_0c00;
    const FIELD: u64 = CONFIG + 66;
    let owned = Owned::new();
    let path = elf_copy(&owned, 16);
    let mut project = Session::default().open(&path, None).unwrap();
    let report = call(&mut project, "integrity_checks", json!({}));
    let routine = format!("{:#x}", elf_truth(16, "crc16_compute"));
    let row = report["routines"].as_array().unwrap().iter().find(|row| row["address"] == routine);
    let row = row.unwrap_or_else(|| panic!("{report:#}"));
    assert!(row["algorithms"].as_array().unwrap().contains(&json!("crc16_arc")), "{row:#}");
    assert!(row["evidence"].to_string().contains("polynomial 0xa001 formed by an immediate"), "{row:#}");
    let check =
        report["checks"].as_array().unwrap().iter().find(|check| check["stored"]["address"] == format!("{FIELD:#x}"));
    let check = check.unwrap_or_else(|| panic!("{report:#}"));
    assert_eq!(check["algorithm"], "crc16_arc", "{check:#}");
    assert_eq!(check["confirmed_by_emulation"], true, "{check:#}");

    // A slower baud rate invalidates the block; the fix rewrites its CRC-16 in the ELF.
    let mut patch = tokens(&report);
    patch["at"] = json!(format!("{:#x}", CONFIG + 4));
    patch["original_hex"] = json!(rampage_arch::hex::bytes(&115_200u32.to_le_bytes()));
    patch["replacement_hex"] = json!(rampage_arch::hex::bytes(&57_600u32.to_le_bytes()));
    patch["allow_data"] = json!(true);
    call(&mut project, "patch_bytes", patch);
    let report = call(&mut project, "integrity_checks", json!({}));
    assert_eq!(report["invalid"], 1, "{report:#}");
    let mut fix = tokens(&report);
    fix["fix"] = json!(true);
    let fixed = call(&mut project, "integrity_checks", fix);
    assert_eq!((fixed["fix"]["applied"].as_bool(), fixed["invalid"].as_u64()), (Some(true), Some(0)), "{fixed:#}");
    let exported = owned.0.join("patched.elf");
    let export = json!({ "destination": exported, "expected_revision": fixed["receipt"]["revision_sha256"] });
    call(&mut project, "export_image", export);
    let written = std::fs::read(&exported).unwrap();
    let stored = u16::from_le_bytes(elf_bytes(&written, FIELD, 2).try_into().unwrap());
    assert_eq!(stored, crc16_arc(&elf_bytes(&written, CONFIG, 66)));
    assert_eq!(elf_bytes(&written, CONFIG + 4, 4), 57_600u32.to_le_bytes());
}
