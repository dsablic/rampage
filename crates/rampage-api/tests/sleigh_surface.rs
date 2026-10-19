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
fn standalone_roster_uses_native_metadata_and_keeps_expanded_profiles_gated_without_abi_or_packet_claims() {
    let owned = Owned::new();
    let registry = tools::file_tools();
    let tool = registry.iter().find(|tool| tool.name == "inspect_sleigh").unwrap();
    assert_eq!(tool.group, tools::Group::Core);
    assert!(!tools::tools().iter().any(|tool| tool.name == "inspect_sleigh"));
    assert!(tool.input_schema["properties"].get("arch").is_none());
    let roster = tool.input_schema["properties"]["profile"]["enum"].as_array().unwrap();
    assert_eq!(
        roster.iter().map(|id| id.as_str().unwrap()).collect::<Vec<_>>(),
        rampage_decompiler::sleigh_decode::SleighDecoder::registered_profile_ids().collect::<Vec<_>>()
    );
    assert_eq!(roster.len(), 20);
    assert_eq!(
        roster.iter().map(|profile| profile.as_str().unwrap()).collect::<std::collections::BTreeSet<_>>().len(),
        20
    );
    assert!(roster.iter().all(|profile| rampage_decompiler::sleigh_decode::SleighDecoder::is_registered_profile(
        profile.as_str().unwrap()
    )));
    for profile in [
        "8051:BE:16:default",
        "PIC-16:LE:16:PIC-16",
        "SuperH:BE:32:SH-2",
        "V850:LE:32:default",
        "tricore:LE:32:default",
        "Xtensa:LE:32:default",
        "z80:LE:16:default",
        "HCS-12:BE:24:default",
        "6805:BE:16:default",
        "CR16C:LE:16:default",
        "eBPF:LE:64:default",
        "Loongarch:LE:64:lp64d",
        "Hexagon:LE:32:default",
    ] {
        assert!(roster.iter().any(|id| id == profile));
    }
    for sibling in ["MIPS:BE:32:default", "68000:BE:32:default", "x86:LE:16:Real Mode", "/tmp/arbitrary.sla"] {
        assert!(!roster.iter().any(|id| id == sibling));
        assert!(!rampage_decompiler::sleigh_decode::SleighDecoder::is_registered_profile(sibling));
    }
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
    for (profile, name, seed, gate_address) in
        [("Hexagon:LE:32:default", "Hexagon-v2", 0x1000, 0x1000), ("SuperH:BE:32:SH-2", "SuperH-v2", 0x1010, 0x1012)]
    {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/fixtures/sleigh/extended/{name}.bin")),
        )
        .unwrap();
        let path = owned.0.join(format!("{name}.raw"));
        let mut padded = vec![0xab; 7];
        padded.extend_from_slice(&bytes);
        std::fs::write(&path, padded).unwrap();
        let before = owned.files();
        let mut args = request(profile, 0x1000, bytes.len());
        args["discover"] = json!(true);
        args["seeds"] = json!([seed]);
        args["listing_limit"] = json!(16);
        let report = call(&path, args).unwrap();
        let functions = report["program"]["functions"].as_array().unwrap();
        assert_eq!(
            functions.iter().map(|function| function["address"].as_str().unwrap()).collect::<Vec<_>>(),
            vec![format!("{seed:#x}")]
        );
        let gate = report["program"]["decode_gates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| {
                entry["function"] == format!("{seed:#x}") && entry["gate"]["address"] == format!("{gate_address:#x}")
            })
            .unwrap();
        let row = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["address"] == format!("{gate_address:#x}"))
            .unwrap();
        assert_eq!(row["status"], "valid");
        assert_eq!(row["flow"]["kind"], "unknown");
        assert_eq!(gate["len"], row["length"]);
        assert_eq!(gate["gate"]["reason"], row["unknown_gate"]["reason"]);
        assert!(report["profile"]["alignment_bytes"].as_u64().unwrap() > 0);
        assert!(
            report["program"]["xrefs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|xref| xref["from"] != format!("{gate_address:#x}"))
        );
        let seed_address = format!("{seed:#x}");
        assert!(
            report["program"]["noreturn"]
                .as_array()
                .is_none_or(|items| !items.iter().any(|item| item.as_str() == Some(seed_address.as_str())))
        );
        if name == "Hexagon-v2" {
            assert_eq!(row["processor_helper_required"], true);
            assert_eq!(gate["gate"]["reason"], "processor_helper_required");
            assert!(!report["profile"]["required_parallel_helper"].as_str().unwrap().is_empty());
        } else {
            assert_eq!(gate["gate"]["reason"], "delay_slot_aggregation");
        }
        assert_eq!(owned.files(), before);
    }
}

#[test]
fn paged_discovery_keeps_caller_only_six_and_explicit_valid_avr_unknown_entry() {
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
        args["seeds"] = json!([base]);
        let caller_only = call(&path, args.clone()).unwrap();
        let caller_entries: Vec<_> = caller_only["program"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|function| function["address"].as_str().unwrap())
            .collect();
        assert_eq!(caller_entries, vec![format!("{base:#x}"), format!("{:#x}", base + 16)]);
        args["seeds"] =
            if name == "avr8" { json!([format!("{base:#x}"), format!("{:#x}", base + 22)]) } else { json!([base]) };
        let report = call(&path, args.clone()).unwrap();
        let functions = report["program"]["functions"].as_array().unwrap();
        let addresses: Vec<_> = functions.iter().map(|function| function["address"].as_str().unwrap()).collect();
        let mut expected = vec![format!("{base:#x}"), format!("{:#x}", base + 16)];
        if name == "avr8" {
            expected.push("0x216".to_owned());
        }
        assert_eq!(addresses, expected);
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
            assert_eq!(gate["context_mediated_flow"], true);
            let retained = functions.iter().find(|function| function["address"] == "0x216").unwrap();
            assert_eq!(retained["instruction_count"], 1);
            assert_eq!(retained["blocks"], json!([{"start":"0x216","end":"0x218"}]));
            let production = report["program"]["decode_gates"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["function"] == "0x216" && entry["gate"]["address"] == "0x216")
                .unwrap();
            assert_eq!(production["len"], 2);
            assert_eq!(production["gate"]["backend"], "sleigh");
            assert_eq!(production["gate"]["profile"], profile);
            assert_eq!(production["gate"]["reason"], "context_mediated_flow");
            assert!(report["program"]["xrefs"].as_array().unwrap().iter().all(|xref| xref["from"] != "0x216"));
            for field in ["noreturn", "inferred_noreturn", "noreturn_calls"] {
                assert!(
                    report["program"][field].as_array().is_none_or(|items| !items.iter().any(|item| item == "0x216"))
                );
            }
            assert!(
                caller_only["program"]["decode_gates"]
                    .as_array()
                    .is_none_or(|gates| !gates.iter().any(|gate| gate["gate"]["address"] == "0x216"))
            );
            assert!(functions.iter().flat_map(|function| function["blocks"].as_array().unwrap()).all(|block| {
                let start = u64::from_str_radix(block["start"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                let end = u64::from_str_radix(block["end"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                !(start <= 0x218 && 0x218 < end)
            }));
            args["listing_offset"] = json!(report["listing_total"].as_u64().unwrap() - 1);
            let gate_page = call(&path, args).unwrap();
            assert_eq!(gate_page["rows"][0]["address"], "0x216");
            assert_eq!(gate_page["rows"][0]["length"], 2);
            assert_eq!(gate_page["rows"][0]["status"], "valid");
            assert_eq!(gate_page["rows"][0]["flow"]["kind"], "unknown");
            assert_eq!(gate_page["stops"], report["stops"]);
        }
        assert_eq!(owned.files(), before);
    }
    assert_eq!(total, 7);
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
