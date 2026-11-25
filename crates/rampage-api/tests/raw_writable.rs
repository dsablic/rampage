//! Raw code regions the program writes: a Cortex-M application that runs from the memory it is loaded into (mapped
//! in SRAM, or decoded and storing into itself) is writable for the decompiler, so reads of its globals are never
//! folded into the bytes the image holds and stores to them are no writes to read-only memory, while its literal
//! pools still fold. A flash mapping keeps folding; `writable` in the selector states the verdict either way.

use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::tools::{call_shared, tools};
use rampage_api::{RawProjectRequest, Session};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

/// The fixture's symbol `name`, linked at 0x20000000 (`ramapp`) or 0x01000000 (`lo`).
fn truth(elf: &str, name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(fixture(&format!("firmware/{elf}"))).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

fn sram(name: &str) -> u64 {
    truth("raw-cortex-m-ramapp.elf", name)
}

fn low(name: &str) -> u64 {
    truth("raw-cortex-m-ramapp-lo.elf", name)
}

fn open(file: &str, request: Value) -> Arc<rampage_api::Project> {
    let request: RawProjectRequest = serde_json::from_value(request).unwrap();
    Session::default().open_raw(&fixture(&format!("firmware/{file}")), &request).unwrap()
}

fn refusal(file: &str, request: Value) -> String {
    match serde_json::from_value::<RawProjectRequest>(request) {
        Err(error) => error.to_string(),
        Ok(request) => {
            let error = Session::default().open_raw(&fixture(file), &request).err().expect("Raw open must refuse");
            let mut text = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                text.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            text
        }
    }
}

fn decompile(project: &mut Arc<rampage_api::Project>, at: u64) -> String {
    let (text, failed) = call_shared(&tools(), project, "decompile", json!({ "at": format!("{at:#x}") }));
    assert!(!failed, "{text}");
    serde_json::from_str::<Value>(&text).unwrap()["code"].as_str().unwrap().to_owned()
}

fn primary(project: &mut Arc<rampage_api::Project>) -> Value {
    // binary_info reports the stores verdict once discovery has run.
    project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    serde_json::to_value(project.summary()).unwrap()["raw"]["regions"][0].clone()
}

fn sram_request(writable: Option<bool>) -> Value {
    let mut request = json!({
        "profile": "cortex-m0",
        "base_address": "0x20000000",
        "entry": format!("{:#x}", sram("reset_handler")),
    });
    if let Some(writable) = writable {
        request["writable"] = json!(writable);
    }
    request
}

fn low_request(writable: Option<bool>) -> Value {
    let mut request = json!({
        "profile": "cortex-m0",
        "base_address": "0x1000000",
        "entry": format!("{:#x}", low("reset_handler")),
    });
    if let Some(writable) = writable {
        request["writable"] = json!(writable);
    }
    request
}

fn decoded_request(writable: Option<bool>) -> Value {
    let length = std::fs::metadata(fixture("firmware/raw-cortex-m-ramapp-lzss.bin")).unwrap().len();
    let size = std::fs::metadata(fixture("firmware/raw-cortex-m-ramapp-lo.bin")).unwrap().len();
    let mut request = low_request(writable);
    request["length"] = json!(length);
    request["decode"] = json!({ "codec": "lzss-4k", "expected_output_size": size });
    request
}

/// `get_mode` reads `mode` (initially 3) through a pointer loaded in its first block; a writable mapping keeps the
/// read of the global, a read-only one folds it into its initial value.
fn reads_mode(code: &str) -> bool {
    !code.contains(" = 3;") && !code.contains("return 3;")
}

/// The reset handler's literal pools fold in a writable region too: the UART register, the loop bound and the calls
/// read as what the pool words hold, never as globals named by the pool's address.
fn assert_pools_fold(reset: &str, set_mode: u64, pool: u64) {
    assert!(reset.contains("periph_40011004 = ") && reset.contains("0x1234 <"), "{reset}");
    assert!(reset.contains(&format!("sub_{set_mode:x}(5)")), "{reset}");
    for word in (0..16).step_by(4) {
        assert!(!reset.contains(&format!("_{:x}", pool + word)), "{reset}");
    }
}

#[test]
fn an_image_mapped_in_sram_is_writable_and_its_globals_are_never_folded() {
    let mut project = open("raw-cortex-m-ramapp.bin", sram_request(None));
    let region = primary(&mut project);
    assert_eq!((region["writable"].as_bool(), region["writable_reason"].as_str()), (Some(true), Some("ram_address")));
    let get_mode = decompile(&mut project, sram("get_mode"));
    assert!(reads_mode(&get_mode), "{get_mode}");
    let set_mode = decompile(&mut project, sram("set_mode"));
    assert!(!set_mode.contains("Read-only address"), "{set_mode}");
    // Literal pools still fold: the UART address and the loop bound read as the constants they hold.
    let reset = decompile(&mut project, sram("reset_handler"));
    assert_pools_fold(&reset, sram("set_mode"), sram("reset_handler") + 0x3c);
}

#[test]
fn a_flash_mapping_keeps_folding_and_a_stated_verdict_wins() {
    let mut flash = open("raw-cortex-m-ramapp-lo.bin", low_request(None));
    let region = primary(&mut flash);
    assert_eq!(region["writable"], json!(false));
    assert!(region.get("writable_reason").is_none(), "{region}");
    let get_mode = decompile(&mut flash, low("get_mode"));
    assert!(!reads_mode(&get_mode), "a flash constant folds: {get_mode}");

    let mut stated = open("raw-cortex-m-ramapp-lo.bin", low_request(Some(true)));
    let region = primary(&mut stated);
    assert_eq!((region["writable"].as_bool(), region["writable_reason"].as_str()), (Some(true), Some("stated")));
    let get_mode = decompile(&mut stated, low("get_mode"));
    assert!(reads_mode(&get_mode), "{get_mode}");

    let mut read_only = open("raw-cortex-m-ramapp.bin", sram_request(Some(false)));
    let region = primary(&mut read_only);
    assert_eq!((region["writable"].as_bool(), region["writable_reason"].as_str()), (Some(false), Some("stated")));
    let get_mode = decompile(&mut read_only, sram("get_mode"));
    assert!(!reads_mode(&get_mode), "{get_mode}");
}

/// The same application LZSS-compressed and decoded at 0x01000000: no SRAM address, but discovered code stores into
/// the decoded bytes, so it was decoded into the memory it runs from.
#[test]
fn a_decoded_image_the_code_stores_into_is_writable() {
    let mut project = open("raw-cortex-m-ramapp-lzss.bin", decoded_request(None));
    let region = primary(&mut project);
    assert_eq!(region["source"]["type"], "decoded");
    assert_eq!((region["writable"].as_bool(), region["writable_reason"].as_str()), (Some(true), Some("stores")));
    let get_mode = decompile(&mut project, low("get_mode"));
    assert!(reads_mode(&get_mode), "{get_mode}");
    let set_mode = decompile(&mut project, low("set_mode"));
    assert!(!set_mode.contains("Read-only address"), "{set_mode}");
    let reset = decompile(&mut project, low("reset_handler"));
    assert_pools_fold(&reset, low("set_mode"), low("reset_handler") + 0x3c);
    // The string the reset handler passes reads as it does from flash, its bytes read-only again.
    let mut flash = open("raw-cortex-m-ramapp-lo.bin", low_request(None));
    let flash_reset = decompile(&mut flash, low("reset_handler"));
    let call = |code: &str| {
        let prefix = format!("sub_{:x}(", low("uart_puts"));
        code.lines().find(|line| line.contains(&prefix)).map(str::to_owned)
    };
    assert!(call(&reset).is_some() && call(&reset) == call(&flash_reset), "{reset}\n{flash_reset}");

    // Stated read-only, the decoded image folds as flash does.
    let mut stated = open("raw-cortex-m-ramapp-lzss.bin", decoded_request(Some(false)));
    let region = primary(&mut stated);
    assert_eq!((region["writable"].as_bool(), region["writable_reason"].as_str()), (Some(false), Some("stated")));
    let get_mode = decompile(&mut stated, low("get_mode"));
    assert!(!reads_mode(&get_mode), "{get_mode}");
}

#[test]
fn the_selector_validates_writable() {
    let bin = "firmware/raw-cortex-m-ramapp.bin";
    let mut request = sram_request(None);
    request["writable"] = json!("yes");
    assert!(refusal(bin, request).contains("invalid type"));
    let region = |kind: &str, writable: bool| {
        let mut request = sram_request(None);
        request["regions"] =
            json!([{ "kind": kind, "base_address": "0x30000000", "offset": 0, "length": 16, "writable": writable }]);
        request
    };
    assert!(refusal(bin, region("data", true)).contains("map bytes the program writes as a ram region"));
    assert!(refusal(bin, region("ram", false)).contains("map constant bytes as a data region"));
    // A code region the program writes is stated, and reported.
    let project = open("raw-cortex-m-ramapp.bin", region("code", true));
    let summary = serde_json::to_value(project.summary()).unwrap();
    let further = &summary["raw"]["regions"][1];
    assert_eq!((further["writable"].as_bool(), further["writable_reason"].as_str()), (Some(true), Some("stated")));
    assert_eq!(summary["segments"][1]["perms"], json!({ "read": true, "write": false, "execute": true }));
    // An ESP image maps its segments by the chip's memory map.
    let esp = json!({ "profile": "esp32", "format": "esp", "offset": "0x10000", "writable": true });
    assert!(refusal("xtensa/esp32-flash.bin", esp).contains("omit writable"));
}
