//! Owned raw fixtures exercise the file-tool surface, not native executable admission or execution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::tools;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Owned(PathBuf);
impl Owned {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-api-sleigh-surface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn fixture(&self, name: &str) -> (PathBuf, Vec<u8>) {
        let original = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/fixtures/sleigh/{name}.bin")),
        )
        .unwrap();
        let mut padded = vec![0xab; 7];
        padded.extend_from_slice(&original);
        padded.extend_from_slice(&[0xcd; 3]);
        let path = self.0.join(format!("{name}.raw"));
        std::fs::write(&path, padded).unwrap();
        (path, original)
    }
    fn files(&self) -> BTreeMap<OsString, Vec<u8>> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect()
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(profile: &str, base: u64, length: usize) -> Value {
    json!({"profile":profile,"offset":"0x7","length":length,"base_address":format!("{base:#x}"),"listing_limit":1})
}
fn call(path: &Path, mut args: Value) -> Result<Value, String> {
    args["path"] = json!(path);
    let registry = tools::file_tools();
    registry.iter().find(|tool| tool.name == "inspect_sleigh").unwrap().call(&rampage_api::Packs::default(), args)
}

#[test]
fn standalone_file_tool_lists_three_owned_profiles_with_nonzero_offsets_and_no_abi_or_native_image_claim() {
    let owned = Owned::new();
    let registry = tools::file_tools();
    let tool = registry.iter().find(|tool| tool.name == "inspect_sleigh").unwrap();
    assert_eq!(tool.group, tools::Group::Core);
    assert!(!tools::tools().iter().any(|tool| tool.name == "inspect_sleigh"));
    assert!(tool.input_schema["properties"].get("arch").is_none());
    assert!(
        tool.input_schema["properties"]["profile"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "avr8:LE:16:default")
    );
    for (name, profile, base, length) in [
        ("msp430", "TI_MSP430:LE:16:default", 0x4400, 30),
        ("avr8", "avr8:LE:16:default", 0x200, 32),
        ("6502", "6502:LE:16:default", 0x8000, 25),
    ] {
        let (path, bytes) = owned.fixture(name);
        assert_eq!(bytes.len(), length);
        let before = owned.files();
        let mut args = request(profile, base, length);
        args["include_pcode"] = json!(true);
        let report = call(&path, args).unwrap();
        assert!(report.to_string().len() <= 60000);
        assert_eq!(report["source_offset"], 7);
        assert_eq!(report["source_length"], length);
        assert_eq!(report["rows"][0]["source_byte_offset"], 7);
        assert_eq!(report["rows"][0]["window_byte_offset"], 0);
        assert_eq!(report["base_address"], format!("{base:#x}"));
        assert_eq!(report["end_address_exclusive"], format!("{:#x}", base + length as u64));
        assert!(report["code_coordinate_space"].as_str().unwrap().contains("byte"));
        assert_eq!(report["rows"][0]["address"], format!("{base:#x}"));
        assert_eq!(report["rows"][0]["flow"]["kind"], "direct_call");
        assert_eq!(report["rows"][0]["flow"]["target"], base + 16);
        assert!(!report["rows"][0]["pcode"].as_array().unwrap().is_empty());
        assert_eq!(report["listing_next_offset"], 1);
        assert!(report["program"].is_null());
        assert!(report["profile"]["abi"].as_str().unwrap().contains("unknown"));
        assert!(report["profile"]["mapping_validation"].as_str().unwrap().contains("analyst_asserted"));
        let hash = rampage_arch::hex::bytes(&Sha256::digest(&bytes));
        assert_eq!(report["source_range_sha256"], hash);
        assert_eq!(report["source_range_sha256_after"], hash);
        assert_eq!(owned.files(), before);
    }
}

#[test]
fn paged_discovery_keeps_six_manual_functions_and_avr_unknown_flow_is_not_an_invalid_opcode() {
    let owned = Owned::new();
    let mut total = 0;
    for (name, profile, base, length) in [
        ("msp430", "TI_MSP430:LE:16:default", 0x4400, 30),
        ("avr8", "avr8:LE:16:default", 0x200, 32),
        ("6502", "6502:LE:16:default", 0x8000, 25),
    ] {
        let (path, _) = owned.fixture(name);
        let before = owned.files();
        let mut args = request(profile, base, length);
        args["discover"] = json!(true);
        args["seeds"] =
            if name == "avr8" { json!([format!("{base:#x}"), format!("{:#x}", base + 22)]) } else { json!([base]) };
        let report = call(&path, args).unwrap();
        let functions = report["program"]["functions"].as_array().unwrap();
        let addresses: Vec<_> = functions.iter().map(|function| function["address"].as_str().unwrap()).collect();
        assert_eq!(addresses, vec![format!("{base:#x}"), format!("{:#x}", base + 16)]);
        total += functions.len();
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert!(report["program"]["xrefs"].as_array().unwrap().iter().any(|xref| xref["kind"] == "call"
            && xref["from"] == format!("{base:#x}")
            && xref["to"] == format!("{:#x}", base + 16)));
        if name == "avr8" {
            let code = report["profile"]["spaces"]
                .as_array()
                .unwrap()
                .iter()
                .find(|space| space["id"] == report["profile"]["code_space"])
                .unwrap();
            assert_eq!(code["word_size"], 2);
            let gate = report["stops"].as_array().unwrap().iter().find(|stop| stop["address"] == "0x216").unwrap();
            assert_eq!(gate["status"], "valid");
            assert_eq!(gate["flow"]["kind"], "unknown");
            assert_eq!(gate["unknown_gate"]["reason"], "context_mediated_flow");
            assert_eq!(gate["reason"], "conservative_unknown_flow_not_invalid_opcode");
        }
        assert_eq!(owned.files(), before);
    }
    assert_eq!(total, 6);
}

#[test]
fn strict_request_helpers_reject_names_profiles_unknown_fields_and_unsafe_request_files() {
    let owned = Owned::new();
    let (path, _) = owned.fixture("6502");
    let before = owned.files();
    let valid = request("6502:LE:16:default", 0x8000, 25);
    for (field, value) in [
        ("profile", json!("../../arbitrary.sla")),
        ("arch", json!("6502")),
        ("base_address", json!("main")),
        ("length", json!(0)),
        ("length", json!(65537)),
        ("decode_attempt_limit", json!(0)),
        ("instruction_limit", json!(0)),
        ("compiler", json!("gcc")),
        ("image_offset", json!(0)),
    ] {
        let mut args = valid.clone();
        args[field] = value;
        assert!(call(&path, args).is_err(), "{field}");
        assert_eq!(owned.files(), before);
    }
    let mut exhausted = valid.clone();
    exhausted["discover"] = json!(true);
    exhausted["seeds"] = json!(["0x8000"]);
    exhausted["instruction_limit"] = json!(1);
    assert!(call(&path, exhausted).unwrap_err().contains("instruction budget"));
    let query = owned.0.join("request.json");
    std::fs::write(&query, valid.to_string()).unwrap();
    assert!(tools::read_sleigh_window_request(&query).is_ok());
    #[cfg(unix)]
    {
        let link = owned.0.join("link.json");
        std::os::unix::fs::symlink(&query, &link).unwrap();
        assert!(tools::read_sleigh_window_request(&link).is_err());
        assert!(tools::read_sleigh_window_request(Path::new("/dev/zero")).is_err());
    }
    std::fs::OpenOptions::new().write(true).open(&query).unwrap().set_len(1024 * 1024 + 1).unwrap();
    assert!(tools::read_sleigh_window_request(&query).is_err());
}

#[test]
fn oversized_escaped_request_is_rejected_before_path_open_or_native_profile_work() {
    let registry = tools::file_tools();
    let tool = registry.iter().find(|tool| tool.name == "inspect_sleigh").unwrap();
    let path = format!("/must/not/be/opened/{}", "\"".repeat(1024 * 1024 / 2 + 1));
    let error = tool
        .call(
            &rampage_api::Packs::default(),
            json!({
                "path":path,"profile":"6502:LE:16:default","offset":0,"length":1,"base_address":"0x8000"
            }),
        )
        .unwrap_err();
    assert_eq!(error, "Sleigh request exceeds 1 MiB");
}
