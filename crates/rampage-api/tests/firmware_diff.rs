//! diff_firmware on version pairs of each input kind: a Cortex-M flash image as a plain binary, as ELF and wrapped
//! in an LZSS update container; a SquashFS tree; an ESP32 flash dump; an APK; and the unchanged and swapped cases.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

fn texts(rows: &Value, key: &str) -> Vec<String> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(
            |row| if key.is_empty() { row.as_str().unwrap().to_owned() } else { row[key].as_str().unwrap().to_owned() },
        )
        .collect()
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

#[test]
#[ignore]
fn explore_esp() {
    let scratch = Scratch::new("rampage-diff-explore-esp");
    let new = scratch.write("flash-v2.bin", &esp_flash_v2());
    let mut result = diff(&fixture("xtensa/esp32-flash.bin"), &new);
    for component in result["components"].as_array_mut().unwrap() {
        if let Some(code) = component.get_mut("code") {
            code["unchanged"] = json!("...");
        }
    }
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    let mut q = query(&fixture("xtensa/esp32-flash.bin"), &new);
    q.component = Some("esp:factory".to_owned());
    q.function = Some("0x400d0130".to_owned());
    println!("{}", serde_json::to_string_pretty(&run(&q)["rows"]).unwrap());
}

#[test]
#[ignore]
fn explore() {
    let scratch = Scratch::new("rampage-diff-explore");
    let v1 = std::fs::read(fixture("firmware/raw-cortex-m-update-v1.bin")).unwrap();
    let v2 = std::fs::read(fixture("firmware/raw-cortex-m-update-v2.bin")).unwrap();
    let (a, b) = (scratch.write("v1.upd", &container(&v1)), scratch.write("v2.upd", &container(&v2)));
    let pairs = [
        (fixture("firmware/raw-cortex-m-update-v1.bin"), fixture("firmware/raw-cortex-m-update-v2.bin")),
        (a, b),
        (fixture("fsimages/update-v1.sqfs"), fixture("fsimages/update-v2.sqfs")),
    ];
    for (old, new) in &pairs {
        let mut result = diff(old, new);
        for component in result["components"].as_array_mut().unwrap() {
            if let Some(code) = component.get_mut("code") {
                code["unchanged"] = json!("...");
            }
        }
        println!("{}", serde_json::to_string_pretty(&result["components"]).unwrap());
        println!("{}", serde_json::to_string_pretty(&result["summary"]).unwrap());
    }
    let (old, new) = &pairs[0];
    let mut q = query(old, new);
    q.component = Some("image".to_owned());
    q.function = Some("entry".to_owned());
    println!("{}", serde_json::to_string_pretty(&run(&q)).unwrap());
}

#[test]
#[ignore]
fn explore_integrity() {
    let scratch = Scratch::new("rampage-diff-explore-int");
    for name in ["v1", "v2"] {
        let plain = std::fs::read(fixture(&format!("firmware/raw-cortex-m-update-{name}.bin"))).unwrap();
        let path = scratch.write("u.upd", &container(&plain));
        let packed = std::fs::metadata(&path).unwrap().len() - 256 - 16 - 512;
        let probe = rampage_api::probe_compression(
            &path,
            &rampage_api::ProbeCompressionRequest {
                offset: rampage_api::FileOffset(0x110),
                length: rampage_api::FileOffset(packed),
                expected_output_size: Some(rampage_api::FileOffset(plain.len() as u64)),
                candidate_limit: Some(8),
                timeout_ms: None,
                preview_size: Some(0),
            },
        )
        .unwrap();
        for candidate in &probe.candidates {
            println!(
                "{name} candidate {} {} fill {:?} exercised {:?} size {} consumed {} bases {:?}",
                candidate.rank,
                candidate.verdict,
                candidate.decode_arguments.dictionary_fill,
                candidate.dictionary_fill_exercised,
                candidate.output_size,
                candidate.input_consumed,
                candidate
                    .base_candidates
                    .as_ref()
                    .map(|b| b.iter().map(|b| (b.base_address, b.score)).collect::<Vec<_>>())
            );
        }
        for fill in [0, 255] {
            let request: rampage_api::RawProjectRequest = serde_json::from_value(json!({"profile":"cortex-m","offset":"0x110","length":packed,"decode":{"codec":"lzss","expected_output_size":plain.len(),"lzss":{"window_bits":12,"min_match":3,"flag_order":"lsb_first","literal_bit":1,"reference_layout":"split_byte","offset_mode":"ring_position"},"initial_write_offset":4078,"dictionary_fill":fill},"base_address":"0x8000000","vector_table":true})).unwrap();
            let session = rampage_api::Session::default();
            let project = session.open_raw(&path, &request).unwrap();
            let report = project.integrity_checks(&rampage_api::IntegrityRequest::default()).unwrap().report;
            println!(
                "{name} fill {fill}: {:?} {}",
                report.checks.iter().map(|c| (c.algorithm, c.confidence)).collect::<Vec<_>>(),
                serde_json::to_string(&report.search).unwrap()
            );
        }
    }
}
