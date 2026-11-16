//! Multi-region Raw projects: a two-stage Cortex-M image whose first stage in flash puts a second stage into SRAM
//! (copied, or LZSS-decoded through the decoder provider) and calls it, mapped as separate regions; and the same
//! image as Intel HEX and S-records.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rampage_api::tools::{call_shared, tools};
use rampage_api::{RawProjectRequest, Session};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware").join(name)
}

fn truth(name: &str) -> u64 {
    truth_in("raw-cortex-m-stages.elf", name)
}

fn truth_in(elf: &str, name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(fixture(elf)).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

fn request(value: Value) -> RawProjectRequest {
    serde_json::from_value(value).unwrap()
}

/// Stage 1 in flash, stage 2 (code) at its SRAM base from flash 0x400, its initialised data as RAM from flash
/// 0x800, and unbacked RAM above it.
fn stages(stage2: Value) -> Value {
    json!({
        "profile": "cortex-m3",
        "offset": 0,
        "length": 1024,
        "base_address": "0x8000000",
        "vector_table": true,
        "regions": [
            stage2,
            { "kind": "ram", "base_address": "0x20000800", "offset": "0x800", "length": 8 },
            { "kind": "ram", "base_address": "0x20001000", "length": "0x4000" },
        ],
    })
}

fn copied() -> Value {
    stages(json!({ "kind": "code", "base_address": "0x20000000", "offset": "0x400", "length": 128 }))
}

fn decoded() -> Value {
    stages(json!({
        "kind": "code", "base_address": "0x20000000", "offset": "0x408", "length": 128,
        "decode": { "codec": "lzss-4k", "expected_output_size": 128 },
    }))
}

fn refusal(path: &Path, value: Value) -> String {
    let error = Session::default().open_raw(path, &request(value)).err().expect("Raw open must refuse");
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}

fn call(project: &mut Arc<rampage_api::Project>, name: &str, input: Value) -> String {
    let (text, failed) = call_shared(&tools(), project, name, input);
    assert!(!failed, "{name}: {text}");
    text
}

/// Every function of both stages is found from the vector table alone: stage 2 through the literal-pool pointer
/// stage 1 calls, and the flash routine stage 2 calls back through its own literal pool.
fn assert_cross_region_resolution(project: &mut Arc<rampage_api::Project>, elf: &str) {
    let truth = |name: &str| truth_in(elf, name);
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    for name in ["reset_handler", "copy_bytes", "flash_service", "stage2_entry", "stage2_step", "stage2_mix"] {
        assert!(found.contains(&truth(name)), "{name} at {:#x} missing from {found:x?}", truth(name));
    }
    // Stage 1's literal pool holds stage 2's Thumb pointer; stage 2's direct call and its literal-pool pointer to
    // flash both resolve across regions.
    let xrefs = call(project, "xrefs", json!({ "to": format!("{:#x}", truth("stage2_entry") | 1) }));
    assert!(xrefs.contains("\"from_function\":\"entry\""), "{xrefs}");
    let xrefs = call(project, "xrefs", json!({ "to": format!("{:#x}", truth("flash_service") | 1) }));
    assert!(xrefs.contains(&format!("sub_{:x}", truth("stage2_entry"))), "{xrefs}");
    let xrefs = call(project, "xrefs", json!({ "to": format!("{:#x}", truth("stage2_step")) }));
    assert!(xrefs.contains("\"kind\":\"call\""), "{xrefs}");
    // Stage 2 decompiles; it calls into flash by name, and its counter in writable RAM is never folded to the
    // initial value its region holds.
    let c = call(project, "decompile", json!({ "at": format!("{:#x}", truth("stage2_entry")) }));
    assert!(c.contains(&format!("sub_{:x}(", truth("flash_service"))), "{c}");
    assert!(c.contains(&format!("sub_{:x}(", truth("stage2_step"))), "{c}");
    let c = call(project, "decompile", json!({ "at": format!("{:#x}", truth("stage2_step")) }));
    assert!(c.contains("ram_20000800 + 1") && !c.contains("0x1235"), "{c}");
    let c = call(project, "decompile", json!({ "at": format!("{:#x}", truth("reset_handler")) }));
    assert!(c.contains(&format!("sub_{:x}(1)", truth("stage2_entry"))), "{c}");
}

#[test]
fn a_copied_second_stage_maps_at_its_ram_base_and_references_resolve_across_regions() {
    let path = fixture("raw-cortex-m-stages.bin");
    let session = Session::default();
    let mut project = session.open_raw(&path, &request(copied())).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let regions = summary["raw"]["regions"].as_array().unwrap();
    let shape: Vec<(&str, &str, &str, u64)> = regions
        .iter()
        .map(|region| {
            let text = |key: &str| region[key].as_str().unwrap();
            (text("name"), text("kind"), text("base_address"), region["length"].as_u64().unwrap())
        })
        .collect();
    assert_eq!(
        shape,
        [
            ("raw.code", "code", "0x8000000", 1024),
            ("raw.code.1", "code", "0x20000000", 128),
            ("raw.ram.2", "ram", "0x20000800", 8),
            ("raw.ram.3", "ram", "0x20001000", 0x4000),
        ]
    );
    assert_eq!(regions[1]["source"], json!({ "type": "file_range", "offset": 1024, "length": 128 }));
    assert_eq!(regions[3]["source"], json!({ "type": "unbacked" }));
    assert!(regions[3].get("sha256").is_none());
    assert_eq!(summary["segments"][2]["perms"], json!({ "read": true, "write": true, "execute": false }));
    assert_cross_region_resolution(&mut project, "raw-cortex-m-stages.elf");
}

/// The LZSS-compressed second stage decodes through the decoder provider in memory: the same bytes, a receipt
/// linking them to the source range, and no file written.
#[test]
fn a_compressed_second_stage_maps_from_the_decoder_provider_with_its_receipt() {
    let path = fixture("raw-cortex-m-stages-lzss.bin");
    let session = Session::default();
    let mut project = session.open_raw(&path, &request(decoded())).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let region = &summary["raw"]["regions"][1];
    let copied = Session::default().open_raw(&fixture("raw-cortex-m-stages.bin"), &request(copied())).unwrap();
    let plain = serde_json::to_value(copied.summary()).unwrap();
    assert_eq!(region["sha256"], plain["raw"]["regions"][1]["sha256"]);
    let receipt = &region["source"]["receipt"];
    assert_eq!(region["source"]["type"], "decoded");
    assert_eq!((receipt["codec"].as_str(), receipt["source_offset"].as_u64()), (Some("lzss-4k"), Some(0x408)));
    assert_eq!(receipt["output_sha256"], region["sha256"]);
    assert_eq!(receipt["input_fully_consumed"], true);
    assert!(receipt.get("file_path").is_none() && receipt.get("preview").is_none());
    assert_cross_region_resolution(&mut project, "raw-cortex-m-stages-lzss.elf");
    // A bad decode is refused with the provider's reason, and nothing is mapped.
    let mut bad = decoded();
    bad["regions"][0]["decode"]["expected_output_size"] = json!(4096);
    assert!(refusal(&path, bad).contains("regions[0]: decode"));
}

/// The whole flash image as the primary region, stage 2 and its data mapped at their run addresses as copies of
/// the primary region's bytes: the same bytes as the file-range mapping, with the slice as the source.
fn sliced() -> Value {
    json!({
        "profile": "cortex-m3",
        "offset": 0,
        "length": 2056,
        "base_address": "0x8000000",
        "vector_table": true,
        "regions": [
            { "kind": "code", "base_address": "0x20000000", "length": 128, "from": { "region": "primary", "offset": "0x400" } },
            { "kind": "ram", "base_address": "0x20000800", "length": 8, "from": { "region": 0, "offset": "0x800" } },
            { "kind": "ram", "base_address": "0x20001000", "length": "0x4000" },
        ],
    })
}

#[test]
fn a_region_copied_from_a_slice_of_another_maps_at_its_run_address_with_its_receipt() {
    let path = fixture("raw-cortex-m-stages.bin");
    let mut project = Session::default().open_raw(&path, &request(sliced())).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let regions = &summary["raw"]["regions"];
    assert_eq!(regions[1]["source"], json!({ "type": "slice", "region": "raw.code", "offset": 1024, "length": 128 }));
    assert_eq!(regions[2]["source"], json!({ "type": "slice", "region": "raw.code", "offset": 2048, "length": 8 }));
    let copied = Session::default().open_raw(&path, &request(copied())).unwrap();
    let plain = serde_json::to_value(copied.summary()).unwrap();
    for index in [1, 2] {
        assert_eq!(regions[index]["sha256"], plain["raw"]["regions"][index]["sha256"], "{index}");
    }
    // Slices count against the backed-byte cap: the primary region's 2056 bytes and both copies.
    let raw = project.binary.raw_code_image().unwrap();
    assert_eq!(raw.backed_bytes(), 2056 + 128 + 8);
    assert_cross_region_resolution(&mut project, "raw-cortex-m-stages.elf");

    // A slice of a later region names it by number or name; the selector round-trips through serde.
    let mut chained = sliced();
    chained["regions"][2] = json!({ "kind": "data", "base_address": "0x30000000", "length": 4,
                                    "from": { "region": "raw.code.1", "offset": 2 } });
    let binary = rampage_api::open_raw_binary(&path, &request(chained.clone())).unwrap();
    let region = &binary.raw_code_image().unwrap().regions()[3];
    assert_eq!(
        serde_json::to_value(&region.source).unwrap(),
        json!({ "type": "slice", "region": "raw.code.1", "offset": 2, "length": 4 })
    );
    chained["regions"][2]["from"]["region"] = json!(1);
    let again = rampage_api::open_raw_binary(&path, &request(chained)).unwrap();
    assert_eq!(again.raw_interpretation_identity().unwrap(), binary.raw_interpretation_identity().unwrap());

    // Out-of-range, forward, unbacked and over-budget slices are refused before anything is copied.
    let refused = |pointer: &str, value: Value| {
        let mut changed = sliced();
        *changed.pointer_mut(pointer).unwrap() = value;
        refusal(&path, changed)
    };
    let error = refused("/regions/0/from/offset", json!(2000));
    assert!(error.contains("is not inside the 0x808 bytes of raw.code"), "{error}");
    // A name states the kind too; it must match the region it numbers.
    let error = refused("/regions/1/from/region", json!("raw.ram.1"));
    assert!(error.contains("from.region raw.ram.1 names a ram region, but regions[0] is code: raw.code.1"), "{error}");
    let error = refused("/regions/0/from/region", json!(2));
    assert!(
        error.contains("regions[0]: from.region 2 must name the primary region (0) or an earlier region"),
        "{error}"
    );
    let error = refused(
        "/regions/2",
        json!({ "kind": "ram", "base_address": "0x30000000", "length": 4,
                                              "from": { "region": 3, "offset": 0 } }),
    );
    assert!(error.contains("must name the primary region"), "{error}");
    let mut unbacked = sliced();
    unbacked["regions"][1] = json!({ "kind": "ram", "base_address": "0x30000000", "length": 4,
                                     "from": { "region": "raw.ram.2", "offset": 0 } });
    unbacked["regions"].as_array_mut().unwrap().swap(1, 2);
    let error = refusal(&path, unbacked);
    assert!(error.contains("slice source raw.ram.2 is unbacked"), "{error}");
    let error = refused("/regions/0/length", json!(4 * 1024 * 1024));
    assert!(error.contains("all backed regions together hold at most 4194304 bytes"), "{error}");
    let mut misnamed = sliced();
    misnamed["regions"][0]["from"]["region"] = json!("raw.rom.1");
    let error = serde_json::from_value::<RawProjectRequest>(misnamed).unwrap_err().to_string();
    assert!(error.contains("from.region \"raw.rom.1\""), "{error}");
    let mut both = sliced();
    both["regions"][0]["offset"] = json!(0);
    let error = refusal(&path, both);
    assert!(error.contains("omit offset and decode"), "{error}");
    // Patches go to the source region, never into a copy of it.
    let original = std::fs::read(&path).unwrap()[0x400..0x402].to_vec();
    let error = project.patch_bytes(0x2000_0000, &original, &[0x00, 0xbf], false).err().unwrap().to_string();
    assert!(error.contains("is a copy of raw.code's bytes"), "{error}");
}

#[test]
fn every_region_input_changes_the_interpretation_identity() {
    let path = fixture("raw-cortex-m-stages.bin");
    let identity = |value: Value| {
        let binary = rampage_api::open_raw_binary(&path, &request(value)).unwrap();
        let identity = binary.raw_interpretation_identity().unwrap().unwrap();
        assert_eq!(identity.schema, "rampage-raw-interpretation-v6");
        identity.sha256
    };
    let base = identity(copied());
    let mut variants = vec![base.clone()];
    for (pointer, value) in [
        ("/regions/0/base_address", json!("0x20000100")),
        ("/regions/0/kind", json!("data")),
        ("/regions/1/kind", json!("data")),
        ("/regions/2/length", json!("0x2000")),
        ("/regions/0/length", json!(120)),
    ] {
        let mut changed = copied();
        *changed.pointer_mut(pointer).unwrap() = value;
        variants.push(identity(changed));
    }
    let mut fewer = copied();
    fewer["regions"].as_array_mut().unwrap().pop();
    variants.push(identity(fewer));
    let unique: std::collections::BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len(), "{variants:?}");
    assert_eq!(identity(copied()), base);
    // The same stage-2 bytes from a decoder receipt are another interpretation than from a plain file range.
    let decoded = rampage_api::open_raw_binary(&fixture("raw-cortex-m-stages-lzss.bin"), &request(decoded())).unwrap();
    let decoded = decoded.raw_interpretation_identity().unwrap().unwrap().sha256;
    assert_ne!(decoded, base);
    // The decode deadline is not part of the interpretation: the same bytes are the same project.
    let mut slower = self::decoded();
    slower["regions"][0]["decode"]["timeout_ms"] = json!(9000);
    let slower = rampage_api::open_raw_binary(&fixture("raw-cortex-m-stages-lzss.bin"), &request(slower)).unwrap();
    assert_eq!(slower.raw_interpretation_identity().unwrap().unwrap().sha256, decoded);
}

#[test]
fn overlaps_misplaced_seeds_and_other_profiles_are_refused() {
    let path = fixture("raw-cortex-m-stages.bin");
    let mut overlap = copied();
    overlap["regions"][1]["base_address"] = json!("0x2000007c");
    let error = refusal(&path, overlap);
    assert!(error.contains("Raw regions overlap: raw.code.1 0x20000000..0x20000080 and raw.ram.2"), "{error}");
    let mut overlap = copied();
    overlap["regions"][0]["base_address"] = json!("0x8000300");
    assert!(refusal(&path, overlap).contains("overlap"));
    // Seeds may lie in any code region, never in RAM.
    let mut seeded = copied();
    seeded["seeds"] = json!(["0x20000015"]);
    Session::default().open_raw(&path, &request(seeded)).unwrap();
    let mut seeded = copied();
    seeded["seeds"] = json!(["0x20000800"]);
    assert!(refusal(&path, seeded).contains("backed by code bytes"));
    // Only a RAM region may be unbacked.
    let mut unbacked = copied();
    unbacked["regions"][0].as_object_mut().unwrap().remove("offset");
    assert!(refusal(&path, unbacked).contains("only a ram region"));
    // Additional regions are for the natively decoded Cortex-M profile only.
    let msp430 = fixture("../sleigh/msp430.bin");
    let error = refusal(
        &msp430,
        json!({ "profile": "msp430", "offset": 0, "length": 16, "base_address": "0x4400",
                "regions": [{ "kind": "ram", "base_address": "0x200", "length": 16 }] }),
    );
    assert!(error.contains("only for ARM:LE:32:Cortex"), "{error}");
    let mut many = copied();
    many["regions"] = json!(
        (0..16)
            .map(|index| json!({ "kind": "ram", "base_address": 0x3000_0000 + index * 16, "length": 16 }))
            .collect::<Vec<_>>()
    );
    assert!(refusal(&path, many).contains("at most 16 regions"));
}

/// Intel HEX states flash load addresses, S-records here state the run addresses: each contiguous run of records
/// is a code region, and the start-address record is the entry, reported with its verdict.
#[test]
fn intel_hex_and_s_records_map_their_record_runs_and_start_address() {
    let open = |name: &str, value: Value| Session::default().open_raw(&fixture(name), &request(value)).unwrap();
    let hex = open("raw-cortex-m-stages.hex", json!({ "profile": "cortex-m3", "format": "ihex" }));
    let summary = serde_json::to_value(hex.summary()).unwrap();
    assert_eq!(summary["entry"], format!("{:#x}", truth("reset_handler")));
    let records = &summary["raw"]["records"];
    assert_eq!(
        (records["format"].as_str(), records["start_address"]["status"].as_str()),
        (Some("ihex"), Some("accepted"))
    );
    let bases: Vec<&str> = summary["raw"]["regions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|region| region["base_address"].as_str().unwrap())
        .collect();
    // The reset code copies stage 2 and its data from flash to SRAM, so both are mapped where they run too.
    assert_eq!(bases, ["0x8000000", "0x8000400", "0x8000800", "0x20000000", "0x20000800"]);
    assert_eq!(summary["raw"]["regions"][1]["source"], json!({ "type": "records", "format": "ihex" }));
    assert_eq!(
        summary["raw"]["regions"][3]["source"],
        json!({ "type": "scatter_load", "copy": 0, "region": "raw.code.1", "offset": 0 })
    );
    assert_eq!(summary["raw"]["regions"][3]["kind"], "code");

    // The S-records' stage-2 data run is stated writable RAM by a `regions` entry matching it exactly.
    let srec = json!({
        "profile": "cortex-m3", "format": "srec", "vector_table": "0x8000000",
        "regions": [{ "kind": "ram", "base_address": "0x20000800", "length": 8 }],
    });
    let mut project = open("raw-cortex-m-stages.srec", srec);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let kinds: Vec<(&str, &str)> = summary["raw"]["regions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|region| (region["base_address"].as_str().unwrap(), region["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("0x8000000", "code"), ("0x20000000", "code"), ("0x20000800", "ram")]);
    assert_eq!(summary["raw"]["records"]["start_address"]["target"], format!("{:#x}", truth("reset_handler")));
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    for name in ["flash_service", "stage2_entry", "stage2_step", "stage2_mix"] {
        assert!(found.contains(&truth(name)), "{name} missing from {found:x?}");
    }
    let c = call(&mut project, "decompile", json!({ "at": format!("{:#x}", truth("stage2_step")) }));
    assert!(c.contains("ram_20000800 + 1"), "{c}");

    // Regions of record input never read the record text itself.
    for region in [
        json!({ "kind": "code", "base_address": "0x30000000", "offset": 0, "length": 16 }),
        json!({ "kind": "code", "base_address": "0x30000000", "offset": 0, "length": 16,
                "decode": { "codec": "lzss-4k", "expected_output_size": 16 } }),
    ] {
        let error = refusal(
            &fixture("raw-cortex-m-stages.srec"),
            json!({ "profile": "cortex-m3", "format": "srec", "regions": [region] }),
        );
        assert!(error.contains("regions[0]: format srec reads record text"), "{error}");
    }
    let unbacked = json!({ "profile": "cortex-m3", "format": "srec",
        "regions": [{ "kind": "ram", "base_address": "0x30000000", "length": 16 }] });
    Session::default().open_raw(&fixture("raw-cortex-m-stages.srec"), &request(unbacked)).unwrap();

    // Record input takes no offset/length/base_address; a refused start address is reported, not used.
    let error =
        refusal(&fixture("raw-cortex-m-stages.hex"), json!({ "profile": "cortex-m3", "format": "ihex", "offset": 0 }));
    assert!(error.contains("omit offset, length, base_address and decode"), "{error}");
    let error = refusal(&fixture("raw-cortex-m-stages.bin"), json!({ "profile": "cortex-m3", "format": "srec" }));
    assert!(error.contains("srec record line 1"), "{error}");
}
