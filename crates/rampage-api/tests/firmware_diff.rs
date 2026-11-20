//! diff_firmware on version pairs of each input kind: a Cortex-M flash image as a plain binary, as ELF and wrapped
//! in an LZSS update container; a SquashFS tree and the same trees as directories; an ESP32 flash dump; an APK.
//! Each pair is also compared with itself (no change) and the other way round (the inverse), and hostile inputs
//! stay within the budgets.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rampage_api::{FirmwareDiffQuery, Packs, SideInput, diff_firmware};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory under the temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn query(old: &Path, new: &Path) -> FirmwareDiffQuery {
    FirmwareDiffQuery {
        old: SideInput { path: old.to_owned(), ..SideInput::default() },
        new: SideInput { path: new.to_owned(), ..SideInput::default() },
        ..FirmwareDiffQuery::default()
    }
}

fn run(query: &FirmwareDiffQuery) -> Value {
    diff_firmware(query, Arc::new(Packs::default())).unwrap()
}

fn diff(old: &Path, new: &Path) -> Value {
    run(&query(old, new))
}

fn component<'a>(result: &'a Value, id: &str) -> &'a Value {
    result["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["id"] == id)
        .unwrap_or_else(|| panic!("no component {id}: {result:#}"))
}

/// The `key` field of each row (the row itself for plain strings), sorted.
fn values(rows: &Value, key: &str) -> Vec<String> {
    let mut found: Vec<String> = rows
        .as_array()
        .unwrap_or_else(|| panic!("not a list: {rows}"))
        .iter()
        .map(
            |row| if key.is_empty() { row.as_str().unwrap().to_owned() } else { row[key].as_str().unwrap().to_owned() },
        )
        .collect();
    found.sort();
    found
}

fn update(version: &str) -> Vec<u8> {
    std::fs::read(fixture(&format!("firmware/raw-cortex-m-update-{version}.bin"))).unwrap()
}

/// `plain` wrapped as the update container the triage tests use: a load address, the packed and plain sizes and a
/// byte sum of the LZSS payload, then the payload and erased padding.
fn container(plain: &[u8]) -> Vec<u8> {
    use rampage_decode::{Lzss, encode};
    let packed = encode::lzss(&Lzss::classic_4k(4078, 0), plain);
    let mut file = vec![0xff; 256];
    file.extend(0x0800_0000u32.to_le_bytes());
    file.extend((packed.len() as u32).to_le_bytes());
    file.extend((plain.len() as u32).to_le_bytes());
    file.extend(packed.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))).to_le_bytes());
    file.extend(&packed);
    file.extend([0xff; 512]);
    file
}

/// One ESP partition table entry.
fn partition(kind: u8, subtype: u8, offset: u32, size: u32, label: &str) -> Vec<u8> {
    let mut entry = vec![0xaa, 0x50, kind, subtype];
    entry.extend(offset.to_le_bytes());
    entry.extend(size.to_le_bytes());
    let mut name = [0u8; 16];
    name[..label.len()].copy_from_slice(label.as_bytes());
    entry.extend(name);
    entry.extend(0u32.to_le_bytes());
    entry
}

/// The next version of tests/fixtures/xtensa/esp32-flash.bin: the v2 application image in the factory partition,
/// which shrinks to make room for a new `storage` SPIFFS partition (the partition table and its MD5 rewritten).
fn esp_flash_v2() -> Vec<u8> {
    use md5::Digest;
    let mut flash = std::fs::read(fixture("xtensa/esp32-flash.bin")).unwrap();
    let app = std::fs::read(fixture("xtensa/esp32-app-v2.bin")).unwrap();
    flash[0x10000..0x10000 + 0x20000].fill(0xff);
    flash[0x10000..0x10000 + app.len()].copy_from_slice(&app);
    let mut entries = Vec::new();
    entries.extend(partition(0x01, 0x02, 0x9000, 0x6000, "nvs"));
    entries.extend(partition(0x01, 0x01, 0xf000, 0x1000, "phy_init"));
    entries.extend(partition(0x00, 0x00, 0x10000, 0xc0000, "factory"));
    entries.extend(partition(0x01, 0x82, 0xd0000, 0x30000, "storage"));
    let mut table = entries.clone();
    table.extend([0xeb, 0xeb]);
    table.extend([0xff; 14]);
    table.extend(md5::Md5::digest(&entries));
    flash[0x8000..0x8c00].fill(0xff);
    flash[0x8000..0x8000 + table.len()].copy_from_slice(&table);
    flash
}

/// The sample APK and its next version: one more permission (CAMERA) and a native library.
fn apk_pair() -> (Vec<u8>, Vec<u8>) {
    use rampage_dex::testkit::{
        XmlNode, XmlValue, sample_apk, sample_classes, sample_manifest, sample_resources, sample_secondary_classes,
        write_axml, write_dex, write_zip,
    };
    let old = sample_apk(None);
    let camera = XmlNode::new("uses-permission").android("name", XmlValue::Str("android.permission.CAMERA".to_owned()));
    let manifest = write_axml(&sample_manifest().child(camera), false);
    let classes = write_dex(&sample_classes(), 35);
    let secondary = write_dex(&sample_secondary_classes(), 35);
    let resources = sample_resources();
    let lib = std::fs::read(fixture("android/libnet-arm64.so")).unwrap();
    let new = write_zip(&[
        ("AndroidManifest.xml", &manifest, true),
        ("classes.dex", &classes, true),
        ("classes2.dex", &secondary, false),
        ("resources.arsc", &resources, false),
        ("lib/arm64-v8a/libnet.so", &lib, false),
    ]);
    (old, new)
}

/// The SquashFS update pair's trees as directories.
fn tree_dirs(scratch: &Scratch) -> (PathBuf, PathBuf) {
    for version in ["v1", "v2"] {
        let root = format!("{version}/");
        scratch.write(&format!("{root}etc/hostname"), b"demo-device\n");
        scratch.write(&format!("{root}etc/device.conf"), b"telemetry=off\nmicrophone=push-to-talk\n");
        scratch.write(&format!("{root}bin/hello"), &std::fs::read(fixture("bin/hello-mips.elf")).unwrap());
        let controller = std::fs::read(fixture(&format!("firmware/raw-cortex-m-update-{version}.elf"))).unwrap();
        scratch.write(&format!("{root}bin/controller"), &controller);
        if version == "v1" {
            scratch.write(&format!("{root}etc/legacy.conf"), b"legacy_port=8080\n");
        } else {
            scratch.write(&format!("{root}etc/cloud.conf"), b"upload_endpoint=https://cloud.example.net/v2/ingest\n");
        }
    }
    (scratch.0.join("v1"), scratch.0.join("v2"))
}

/// What the Cortex-M update pair changes, function by function, read from a code component.
fn assert_cortex_m_update(code: &Value, named: bool) {
    let functions = &code["functions"];
    assert_eq!(
        (functions["changed"].as_u64(), functions["added"].as_u64(), functions["removed"].as_u64()),
        (Some(2), Some(2), Some(1)),
        "{code:#}"
    );
    if named {
        assert_eq!(values(&code["changed"], "name"), ["report_status", "reset_handler"], "{code:#}");
        assert_eq!(values(&code["added"], "name"), ["debugger_attached", "halt"], "{code:#}");
        assert_eq!(values(&code["removed"], "name"), ["legacy_selftest"], "{code:#}");
    }
    // boot_fail's string moved: the same instructions once addresses are normalised.
    assert_eq!(functions["unchanged"], 6, "{code:#}");
    assert_eq!(values(&code["versions"]["added"], ""), ["fw-version 2.1.0"], "{code:#}");
    assert_eq!(values(&code["versions"]["removed"], ""), ["fw-version 2.0.7"], "{code:#}");
    assert_eq!(values(&code["endpoints"]["added"], "value"), ["https://telemetry.example.net/v2/upload"], "{code:#}");
    assert_eq!(code["endpoints"]["removed_total"], 0, "{code:#}");
    let strings = values(&code["strings"]["removed"], "");
    assert!(strings.contains(&"selftest passed".to_owned()), "{code:#}");
    assert_eq!(values(&code["locks"]["added"], "category"), ["debug_lock"], "{code:#}");
    assert_eq!(code["locks"]["removed_total"], 0, "{code:#}");
    assert_eq!(code["integrity"]["changed_total"], 1, "{code:#}");
    assert_eq!(code["integrity"]["added_total"], 0, "{code:#}");
    assert_eq!(code["integrity"]["changed"][0]["what"], json!(["covered bytes 1020 -> 1532"]), "{code:#}");
    assert_eq!(code["capture"]["applies"], false, "{code:#}");
}

/// The other direction of the same pair reports the inverse.
fn assert_inverse(forward: &Value, backward: &Value) {
    let functions = |code: &Value| {
        let f = &code["functions"];
        (f["changed"].as_u64(), f["added"].as_u64(), f["removed"].as_u64())
    };
    let (changed, added, removed) = functions(forward);
    assert_eq!(functions(backward), (changed, removed, added), "{forward:#}\n{backward:#}");
    for key in ["strings", "versions", "endpoints", "locks"] {
        assert_eq!(forward[key]["added"], backward[key]["removed"], "{key}: {forward:#}\n{backward:#}");
        assert_eq!(forward[key]["removed"], backward[key]["added"], "{key}: {forward:#}\n{backward:#}");
    }
    assert_eq!(forward["integrity"]["changed_total"], backward["integrity"]["changed_total"]);
}

fn assert_unchanged(result: &Value) {
    assert_eq!(result["identical"], true, "{result:#}");
    assert_eq!(result["components"], json!([]), "{result:#}");
}

#[test]
fn a_raw_cortex_m_update_pair_reports_its_functions_strings_endpoints_locks_and_checks() {
    let (old, new) = (fixture("firmware/raw-cortex-m-update-v1.bin"), fixture("firmware/raw-cortex-m-update-v2.bin"));
    let result = diff(&old, &new);
    assert_eq!((&result["old"]["kind"], &result["new"]["kind"]), (&json!("raw_image"), &json!("raw_image")));
    let image = component(&result, "image");
    assert_eq!(image["status"], "changed");
    assert_eq!(image["old"]["base_address"], "0x8000000", "{image:#}");
    assert_cortex_m_update(&image["code"], false);
    assert_eq!(result["not_compared"], json!([]), "{result:#}");
    assert!(result["summary"][2].as_str().unwrap().contains("lock mechanisms +1"), "{result:#}");
    let backward = diff(&new, &old);
    assert_inverse(&image["code"], &component(&backward, "image")["code"]);
    assert_unchanged(&diff(&old, &old));
}

#[test]
fn an_elf_update_pair_names_what_changed() {
    let (old, new) = (fixture("firmware/raw-cortex-m-update-v1.elf"), fixture("firmware/raw-cortex-m-update-v2.elf"));
    let result = diff(&old, &new);
    let image = component(&result, "image");
    assert_eq!(image["changes"], json!(["entry: 0x80002e8 -> 0x80002a0"]), "{image:#}");
    assert_cortex_m_update(&image["code"], true);
    let backward = diff(&new, &old);
    assert_inverse(&image["code"], &component(&backward, "image")["code"]);
}

#[test]
fn an_lzss_update_container_is_decoded_on_both_sides_and_compared() {
    let scratch = Scratch::new("rampage-diff-container");
    let old = scratch.write("v1.upd", &container(&update("v1")));
    let new = scratch.write("v2.upd", &container(&update("v2")));
    let result = diff(&old, &new);
    assert_eq!(result["old"]["kind"], "container", "{result:#}");
    let stream = component(&result, "stream:0");
    assert_eq!(stream["status"], "changed");
    let changes = stream["changes"].as_array().unwrap();
    assert!(changes.contains(&json!("decoded_size: 3072 -> 3584")), "{stream:#}");
    assert_eq!(stream["old"]["checksum"], "byte_sum32", "{stream:#}");
    assert_eq!(stream["new"]["checksum"], "byte_sum32", "{stream:#}");
    assert_eq!(stream["new"]["decoded_with"], "the other version's parameters", "{stream:#}");
    assert_eq!(stream["old"]["base_address"], "0x8000000", "{stream:#}");
    assert_cortex_m_update(&stream["code"], false);
    // The decoded images are the plain flash images.
    let plain = diff(&fixture("firmware/raw-cortex-m-update-v1.bin"), &old);
    let paired = component(&plain, "image~stream:0");
    assert_eq!(paired["status"], "unchanged", "{plain:#}");
    assert_eq!(paired["paired_by"], "only_remaining_code", "{plain:#}");
    assert_eq!(stream["paired_by"], "id", "{stream:#}");
    // The probe could not tell the ring fill apart; the choice is recorded, and the newer side reused it.
    let choice = &stream["old"]["fill_choice"];
    assert!(choice["candidates"].as_array().unwrap().len() > 1, "{stream:#}");
    assert_eq!(choice["chosen"], 0, "{stream:#}");
    assert_eq!(stream["old"]["dictionary_fill_ambiguous"], true, "{stream:#}");
    assert_eq!(stream["new"]["dictionary_fill_ambiguous"], true, "{stream:#}");
    assert!(!changes.iter().any(|change| change.as_str().unwrap().contains("dictionary_fill")), "{stream:#}");
    let backward = diff(&new, &old);
    assert_inverse(&stream["code"], &component(&backward, "stream:0")["code"]);
    assert_unchanged(&diff(&old, &old));
}

#[test]
fn a_squashfs_update_lists_files_and_takes_the_changed_executable_apart() {
    let (old, new) = (fixture("fsimages/update-v1.sqfs"), fixture("fsimages/update-v2.sqfs"));
    let result = diff(&old, &new);
    let files = &component(&result, "fs")["files"];
    assert_eq!(values(&files["changed"], "path"), ["bin/controller"], "{files:#}");
    assert_eq!(values(&files["added"], "path"), ["etc/cloud.conf"], "{files:#}");
    assert_eq!(values(&files["removed"], "path"), ["etc/legacy.conf"], "{files:#}");
    assert_eq!(files["unchanged"], 4, "{files:#}");
    assert_eq!(files["changed"][0]["format"], "elf", "{files:#}");
    assert_eq!(values(&files["endpoints"]["added"], "value"), ["https://cloud.example.net/v2/ingest"], "{files:#}");
    let controller = component(&result, "fs::bin/controller::image");
    assert_cortex_m_update(&controller["code"], true);
    // The nested pair can be asked for alone, and one of its functions diffed.
    let mut drill = query(&old, &new);
    drill.component = Some("fs::bin/controller::image".to_owned());
    drill.list = Some("changed".to_owned());
    let page = run(&drill);
    assert_eq!(page["total"], 2, "{page:#}");
    drill.list = None;
    drill.function = Some("reset_handler".to_owned());
    let function = run(&drill);
    assert_eq!(function["function"]["changed"], true, "{function:#}");
    assert!(function["decompile"].is_string(), "files inside an image are not openable by path: {function:#}");
    let backward = diff(&new, &old);
    let back_files = &component(&backward, "fs")["files"];
    assert_eq!(back_files["added"][0]["path"], "etc/legacy.conf", "{backward:#}");
    assert_eq!(back_files["removed"][0]["path"], "etc/cloud.conf", "{backward:#}");
    assert_inverse(&controller["code"], &component(&backward, "fs::bin/controller::image")["code"]);
    assert_unchanged(&diff(&old, &old));
}

#[test]
fn directories_are_compared_like_filesystem_images() {
    let scratch = Scratch::new("rampage-diff-dirs");
    let (old, new) = tree_dirs(&scratch);
    let result = diff(&old, &new);
    let files = &component(&result, "tree")["files"];
    assert_eq!(values(&files["changed"], "path"), ["bin/controller"], "{files:#}");
    assert_eq!(values(&files["added"], "path"), ["etc/cloud.conf"], "{files:#}");
    assert_eq!(values(&files["removed"], "path"), ["etc/legacy.conf"], "{files:#}");
    let controller = component(&result, "tree::bin/controller::image");
    assert_cortex_m_update(&controller["code"], true);
    // Files in a directory are real paths, so decompile can open both sides.
    let mut drill = query(&old, &new);
    drill.component = Some("tree::bin/controller::image".to_owned());
    drill.function = Some("report_status".to_owned());
    let function = run(&drill);
    assert_eq!(function["decompile"].as_array().map(Vec::len), Some(2), "{function:#}");
    let texts: Vec<&str> = function["rows"].as_array().unwrap().iter().filter_map(|row| row["text"].as_str()).collect();
    assert!(texts.iter().any(|text| text.contains("telemetry.example.net")), "{function:#}");
    // A directory has no digest: its files decide, and none changed.
    let same = diff(&old, &old);
    assert_eq!(component(&same, "tree")["status"], "unchanged", "{same:#}");
    let files = &component(&same, "tree")["files"];
    assert_eq!((files["changed_total"].as_u64(), files["added_total"].as_u64()), (Some(0), Some(0)), "{same:#}");
    assert_eq!(files["removed_total"], 0, "{same:#}");
    let backward = diff(&new, &old);
    let back_files = &component(&backward, "tree")["files"];
    assert_eq!(values(&back_files["added"], "path"), ["etc/legacy.conf"], "{backward:#}");
    assert_inverse(&controller["code"], &component(&backward, "tree::bin/controller::image")["code"]);
}

#[test]
fn an_esp32_flash_update_compares_partitions_and_the_application() {
    let scratch = Scratch::new("rampage-diff-esp");
    let (old, new) = (fixture("xtensa/esp32-flash.bin"), scratch.write("flash-v2.bin", &esp_flash_v2()));
    let result = diff(&old, &new);
    assert_eq!(result["old"]["kind"], "esp_flash");
    assert_eq!(component(&result, "esp:bootloader")["status"], "unchanged");
    assert_eq!(component(&result, "esp:nvs")["status"], "unchanged");
    assert_eq!(component(&result, "esp:storage")["status"], "added");
    let table = component(&result, "esp:partition_table");
    assert_eq!(
        table["changes"],
        json!([
            "partition changed: factory app/factory at 0x10000, 0xf0000 bytes -> factory app/factory at 0x10000, \
             0xc0000 bytes",
            "partition added: storage data/spiffs at 0xd0000, 0x30000 bytes"
        ]),
        "{table:#}"
    );
    let app = component(&result, "esp:factory");
    assert!(app["changes"].as_array().unwrap().contains(&json!("version: 1.4.2 -> 1.5.0")), "{app:#}");
    assert_eq!(app["new"]["sha256_valid"], true, "{app:#}");
    let code = &app["code"];
    let functions = &code["functions"];
    // dispatch and app_main change, handle_update is new and walk is gone; crc32_le only moved and was realigned.
    assert_eq!(
        (functions["changed"].as_u64(), functions["added"].as_u64(), functions["removed"].as_u64()),
        (Some(2), Some(1), Some(1)),
        "{code:#}"
    );
    assert_eq!(values(&code["endpoints"]["added"], "value"), ["https://ota.example.com/v2/firmware"], "{code:#}");
    assert_eq!(values(&code["versions"]["added"], ""), ["1.5.0"], "{code:#}");
    let backward = diff(&new, &old);
    assert_eq!(component(&backward, "esp:storage")["status"], "removed");
    assert_inverse(code, &component(&backward, "esp:factory")["code"]);
    assert_unchanged(&diff(&old, &old));
}

/// Acceptance (MicroPython's ESP32 release files start at flash 0x1000, with the bootloader): the same update with
/// both dumps cut to start at the bootloader. Partition offsets are flash offsets, so the application is still found
/// and compared, not hashed from 0x1000 bytes too far.
#[test]
fn esp32_dumps_that_start_at_the_bootloader_are_read_at_flash_offset_0x1000() {
    let scratch = Scratch::new("rampage-diff-esp-base");
    let old = std::fs::read(fixture("xtensa/esp32-flash.bin")).unwrap()[0x1000..].to_vec();
    let new = esp_flash_v2()[0x1000..].to_vec();
    let (old, new) = (scratch.write("old.bin", &old), scratch.write("new.bin", &new));
    let result = diff(&old, &new);
    assert_eq!(result["old"]["kind"], "esp_flash", "{result:#}");
    assert_eq!(component(&result, "esp:partition_table")["old"]["offset"], "0x7000", "{result:#}");
    assert_eq!(component(&result, "esp:phy_init")["status"], "unchanged", "{result:#}");
    let app = component(&result, "esp:factory");
    assert_eq!(app["old"]["offset"], "0xf000", "{app:#}");
    assert_eq!(app["old"]["partition_offset"], "0x10000", "{app:#}");
    let functions = &app["code"]["functions"];
    assert_eq!(
        (functions["changed"].as_u64(), functions["added"].as_u64(), functions["removed"].as_u64()),
        (Some(2), Some(1), Some(1)),
        "{app:#}"
    );
}

#[test]
fn an_apk_update_reports_permissions_and_native_libraries() {
    let scratch = Scratch::new("rampage-diff-apk");
    let (old, new) = apk_pair();
    let (old, new) = (scratch.write("v1.apk", &old), scratch.write("v2.apk", &new));
    let result = diff(&old, &new);
    assert_eq!(result["old"]["kind"], "android_package", "{result:#}");
    let package = component(&result, "fs");
    let android = &package["android"];
    assert_eq!(android["permissions"]["added"], json!(["android.permission.CAMERA"]), "{android:#}");
    assert_eq!(android["native_libs"]["added"], json!(["lib/arm64-v8a/libnet.so"]), "{android:#}");
    let files = &package["files"];
    assert_eq!(values(&files["changed"], "path"), ["AndroidManifest.xml"], "{files:#}");
    assert_eq!(values(&files["added"], "path"), ["lib/arm64-v8a/libnet.so"], "{files:#}");
    let backward = diff(&new, &old);
    assert_eq!(component(&backward, "fs")["android"]["permissions"]["removed"], json!(["android.permission.CAMERA"]));
    assert_unchanged(&diff(&old, &old));
}

#[test]
fn a_component_pages_its_lists_and_unknown_ids_are_refused() {
    let (old, new) = (fixture("firmware/raw-cortex-m-update-v1.bin"), fixture("firmware/raw-cortex-m-update-v2.bin"));
    let mut drill = query(&old, &new);
    drill.component = Some("image".to_owned());
    drill.list = Some("unchanged".to_owned());
    drill.limit = Some(2);
    let first = run(&drill);
    assert_eq!(first["rows"].as_array().unwrap().len(), 2, "{first:#}");
    assert_eq!(first["next_offset"], 2, "{first:#}");
    assert_eq!(first["total"], 6, "{first:#}");
    drill.offset = 2;
    let second = run(&drill);
    let addresses = |page: &Value| values(&page["rows"], "old").into_iter().collect::<BTreeSet<_>>();
    assert!(addresses(&first).is_disjoint(&addresses(&second)), "{first:#}\n{second:#}");
    drill.list = Some("endpoints".to_owned());
    drill.offset = 0;
    let endpoints = run(&drill);
    assert_eq!(endpoints["rows"][0]["change"], "added", "{endpoints:#}");
    drill.component = Some("nothing".to_owned());
    assert!(diff_firmware(&drill, Arc::new(Packs::default())).unwrap_err().contains("no component `nothing`"));
    let mut no_component = query(&old, &new);
    no_component.list = Some("changed".to_owned());
    assert!(diff_firmware(&no_component, Arc::new(Packs::default())).is_err());
}

#[test]
fn the_function_view_shows_the_changed_instructions_with_addresses_normalised() {
    let (old, new) = (fixture("firmware/raw-cortex-m-update-v1.elf"), fixture("firmware/raw-cortex-m-update-v2.elf"));
    let mut drill = query(&old, &new);
    drill.component = Some("image".to_owned());
    drill.function = Some("reset_handler".to_owned());
    let result = run(&drill);
    let rows = result["rows"].as_array().unwrap();
    let texts = |op: &str| -> Vec<&str> {
        rows.iter().filter(|row| row["op"] == op).filter_map(|row| row["text"].as_str()).collect()
    };
    assert!(texts("+").iter().any(|text| text.contains("new:debugger_attached")), "{result:#}");
    assert!(texts("-").iter().any(|text| text.contains("\"fw-version 2.0.7\"")), "{result:#}");
    assert!(texts("+").iter().any(|text| text.contains("\"fw-version 2.1.0\"")), "{result:#}");
    // Calls to functions that only moved read the same on both sides.
    assert!(!texts("-").iter().any(|text| text.contains("crc32_compute")), "{result:#}");
    // An unchanged function reads the same throughout.
    drill.function = Some("boot_fail".to_owned());
    let same = run(&drill);
    assert_eq!(same["function"]["changed"], false, "{same:#}");
    assert_eq!(same["differing_rows"], 0, "{same:#}");
    // A function only in the newer version.
    drill.function = Some("new:halt".to_owned());
    let added = run(&drill);
    assert_eq!(added["function"]["only_in"], "new", "{added:#}");
}

#[test]
fn budgets_bound_the_work_and_say_what_was_left_out() {
    let (old, new) = (fixture("fsimages/update-v1.sqfs"), fixture("fsimages/update-v2.sqfs"));
    let mut limited = query(&old, &new);
    limited.max_images = Some(0);
    let result = run(&limited);
    assert_eq!(result["budget"]["stopped"], "images", "{result:#}");
    let skipped: Vec<&str> =
        result["not_compared"].as_array().unwrap().iter().filter_map(|row| row["what"].as_str()).collect();
    assert_eq!(skipped, ["fs::bin/controller::image"], "{result:#}");
    assert!(component(&result, "fs::bin/controller::image").get("code").is_none());

    let mut hurried =
        query(&fixture("firmware/raw-cortex-m-update-v1.bin"), &fixture("firmware/raw-cortex-m-update-v2.bin"));
    hurried.timeout_ms = Some(1);
    let started = Instant::now();
    let result = run(&hurried);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(result["budget"]["stopped"], "time", "{result:#}");
    assert!(!result["not_compared"].as_array().unwrap().is_empty(), "{result:#}");

    // A container's decodes and probes stop at the deadline too.
    let scratch = Scratch::new("rampage-diff-hurried");
    let (a, b) =
        (scratch.write("v1.upd", &container(&update("v1"))), scratch.write("v2.upd", &container(&update("v2"))));
    let mut hurried = query(&a, &b);
    hurried.timeout_ms = Some(1);
    let started = Instant::now();
    let result = run(&hurried);
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert_eq!(result["budget"]["stopped"], "time", "{result:#}");

    let mut starved = query(&old, &new);
    starved.max_bytes = Some(10_000);
    let result = run(&starved);
    assert_eq!(result["budget"]["stopped"], "bytes", "{result:#}");
    assert!(result["budget"]["bytes_read"].as_u64().unwrap() <= 10_000, "{result:#}");

    for bad in [Some(0), Some(600_001)] {
        let mut wrong = query(&old, &new);
        wrong.timeout_ms = bad;
        assert!(diff_firmware(&wrong, Arc::new(Packs::default())).is_err());
    }
}

#[test]
fn a_decompression_bomb_in_a_changed_file_stops_at_the_ratio_limit() {
    // repeat-xz.sqfs holds repeat.bin, 200 MiB of one byte; the directory holds a sparse file of the same name and
    // size, so the contents must be hashed to compare them.
    let scratch = Scratch::new("rampage-diff-bomb");
    let file = std::fs::File::create(scratch.0.join("repeat.bin")).unwrap();
    file.set_len(200 << 20).unwrap();
    drop(file);
    let started = Instant::now();
    let result = diff(&scratch.0, &fixture("fsimages/repeat-xz.sqfs"));
    assert!(started.elapsed() < Duration::from_secs(60), "{:?}", started.elapsed());
    let notes = serde_json::to_string(&result["not_compared"]).unwrap();
    assert!(notes.contains("ratio") || notes.contains("bomb"), "{result:#}");
}

#[test]
fn hostile_and_unrelated_inputs_never_panic() {
    let scratch = Scratch::new("rampage-diff-hostile");
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let random: Vec<u8> = (0..8192).map(|_| next() as u8).collect();
    let noise = scratch.write("noise.bin", &random);
    let result = diff(&noise, &fixture("fsimages/update-v1.sqfs"));
    assert_eq!(result["old"]["kind"], "opaque", "{result:#}");
    assert_eq!(component(&result, "file")["status"], "removed", "{result:#}");
    let originals = [
        std::fs::read(fixture("fsimages/update-v2.sqfs")).unwrap(),
        container(&update("v2")),
        std::fs::read(fixture("xtensa/esp32-flash.bin")).unwrap()[..0x30000].to_vec(),
    ];
    for (index, original) in originals.iter().enumerate() {
        let old = scratch.write(&format!("original-{index}"), original);
        for round in 0..6 {
            let mut mutated = original.clone();
            for _ in 0..(1 << round) {
                let at = (next() as usize) % mutated.len();
                mutated[at] = next() as u8;
            }
            if round == 5 {
                mutated.truncate(mutated.len() / 3);
            }
            let new = scratch.write(&format!("mutated-{index}-{round}"), &mutated);
            let mut bounded = query(&old, &new);
            bounded.timeout_ms = Some(20_000);
            let started = Instant::now();
            let outcome = diff_firmware(&bounded, Arc::new(Packs::default()));
            assert!(started.elapsed() < Duration::from_secs(90), "{index}/{round}: {:?}", started.elapsed());
            if let Ok(result) = outcome {
                assert!(serde_json::to_string(&result).unwrap().len() < 60_000);
            }
        }
    }
}

/// Review: a constant that changed only in a literal pool was reported as no change.
#[test]
fn a_constant_changed_in_a_literal_pool_is_a_changed_function() {
    let (old, new) =
        (fixture("firmware/raw-cortex-m-literals-v1.bin"), fixture("firmware/raw-cortex-m-literals-v2.bin"));
    let result = diff(&old, &new);
    let code = &component(&result, "image")["code"];
    let functions = &code["functions"];
    assert_eq!(
        (functions["changed"].as_u64(), functions["added"].as_u64(), functions["removed"].as_u64()),
        (Some(1), Some(0), Some(0)),
        "{code:#}"
    );
    let changed = code["changed"][0]["old"].as_str().unwrap().to_owned();
    let mut drill = query(&old, &new);
    drill.component = Some("image".to_owned());
    drill.function = Some(changed);
    let view = run(&drill);
    let texts: Vec<&str> = view["rows"].as_array().unwrap().iter().filter_map(|row| row["text"].as_str()).collect();
    assert!(texts.iter().any(|text| text.ends_with("= 0x12345")), "{view:#}");
    assert!(texts.iter().any(|text| text.ends_with("= 0x54321")), "{view:#}");
    // Bytes that change outside every compared function are said to, not left unexplained.
    let scratch = Scratch::new("rampage-diff-padding");
    let mut padded = std::fs::read(&old).unwrap();
    padded.extend([0x5a; 16]);
    let padded = scratch.write("padded.bin", &padded);
    let result = diff(&old, &padded);
    let image = component(&result, "image");
    assert_eq!(image["status"], "changed", "{result:#}");
    assert!(image["notes"].to_string().contains("outside the compared functions"), "{result:#}");
    assert!(result["summary"].to_string().contains("outside the compared functions"), "{result:#}");
}

/// A ustar archive holding `members` (name, content).
fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, content) in members {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend(header);
        out.extend(*content);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend([0u8; 1024]);
    out
}

/// Review: with one summary line per component, hundreds of changed archives overflowed the result cap.
#[test]
fn many_changed_components_stay_within_the_result_cap() {
    let scratch = Scratch::new("rampage-diff-many");
    for index in 0..300 {
        for (version, text) in [("v1", "first"), ("v2", "second")] {
            let archive = tar(&[("member.txt", text.as_bytes()), ("same.txt", b"unchanged")]);
            scratch.write(&format!("{version}/archive-{index:03}.tar"), &archive);
        }
    }
    let result = diff(&scratch.0.join("v1"), &scratch.0.join("v2"));
    let text = serde_json::to_string(&result).unwrap();
    assert!(text.len() <= 56_000, "{} bytes", text.len());
    assert_eq!(result["components_total"], 301, "{}", &text[..2000]);
    let summary = result["summary"].as_array().unwrap();
    assert!(summary.len() <= 23, "{summary:#?}");
    assert!(summary.iter().any(|line| line.as_str().unwrap().contains("more changed components")), "{summary:#?}");
    assert!(result["not_compared_total"].is_u64(), "{}", &text[..2000]);
}

/// Acceptance (an ESP32 pair's 546 changed functions): a page cut to fit the result continues where its rows end,
/// not at offset + limit, so paging reads every row.
#[test]
fn a_page_cut_to_fit_continues_after_its_last_row() {
    let scratch = Scratch::new("rampage-diff-page-cut");
    let names: Vec<String> = (0..500)
        .map(|index| format!("etc/a/rather/long/directory/path/to/one/config/file/number-{index:04}.conf"))
        .collect();
    for (version, text) in [("v1", "first"), ("v2", "second")] {
        let members: Vec<(&str, &[u8])> = names.iter().map(|name| (name.as_str(), text.as_bytes())).collect();
        scratch.write(&format!("{version}.tar"), &tar(&members));
    }
    let (old, new) = (scratch.0.join("v1.tar"), scratch.0.join("v2.tar"));
    let id = diff(&old, &new)["components"][0]["id"].as_str().unwrap().to_owned();
    let mut drill = query(&old, &new);
    drill.component = Some(id);
    drill.list = Some("files".to_owned());
    drill.limit = Some(500);
    let mut seen = BTreeSet::new();
    let mut pages = 0;
    loop {
        let page = run(&drill);
        let rows = page["rows"].as_array().unwrap();
        pages += 1;
        assert!(!rows.is_empty() && pages < 20, "{page:#}");
        seen.extend(values(&page["rows"], "path"));
        match page["next_offset"].as_u64() {
            Some(next) => {
                assert_eq!(next as usize, drill.offset + rows.len(), "{}", page["truncated"]);
                drill.offset = next as usize;
            }
            None => break,
        }
    }
    assert!(pages > 1, "one page: either it was not cut or paging stopped after it");
    assert_eq!(seen.len(), 500);
}

/// The integrity_checks preview change: a check whose stored value cannot be patched (it lies in decoded bytes)
/// is noted, and the report still comes back.
#[test]
fn an_integrity_preview_notes_a_stored_value_it_cannot_patch() {
    let scratch = Scratch::new("rampage-diff-integrity");
    let plain = update("v2");
    let path = scratch.write("v2.upd", &container(&plain));
    let packed = std::fs::metadata(&path).unwrap().len() - 256 - 16 - 512;
    // The wrong ring fill decodes the stored CRC's range differently, so the check is invalid and a fix is planned.
    let request: rampage_api::RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m", "offset": "0x110", "length": packed, "base_address": "0x8000000", "vector_table": true,
        "decode": {"codec": "lzss-4k", "expected_output_size": plain.len(), "dictionary_fill": 255}}))
    .unwrap();
    let project = rampage_api::Session::default().open_raw(&path, &request).unwrap();
    let report = project.integrity_checks(&rampage_api::IntegrityRequest::default()).unwrap().report;
    let notes = report.notes.join("\n");
    assert!(notes.contains("the stored value cannot be patched"), "{notes}");
    assert!(report.fix.writes.iter().all(|write| write.action != "patch"), "{:?}", report.fix.writes);
}

#[test]
fn a_selector_for_each_side_reads_headerless_code_the_detection_would_miss() {
    let (old, new) = (fixture("firmware/raw-cortex-m-update-v1.bin"), fixture("firmware/raw-cortex-m-update-v2.bin"));
    let mut selected = query(&old, &new);
    let raw = |length: usize| {
        json!({"profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000",
               "vector_table": true})
    };
    selected.old.raw = Some(raw(update("v1").len()));
    selected.new.raw = Some(raw(update("v2").len()));
    let result = run(&selected);
    assert_eq!(result["old"]["kind"], "raw", "{result:#}");
    assert_cortex_m_update(&component(&result, "image")["code"], false);
    selected.old.image_offset = Some(4);
    assert!(diff_firmware(&selected, Arc::new(Packs::default())).is_err(), "a Raw selector takes no image_offset");
}
