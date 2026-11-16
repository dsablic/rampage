//! Scatter-load following on Cortex-M Raw projects: startup code that copies a function and initialised data from
//! flash to their run addresses and zeroes .bss, either in GCC-style loops over linker symbols or by walking an
//! Arm-style region table with copy and zero handlers. The copies are found from the entry, mapped at their run
//! addresses, and discovery continues into the copied code.

use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::tools::{call_shared, tools};
use rampage_api::{RawProjectRequest, Session};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware").join(name)
}

fn truth(variant: &str, name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(fixture(&format!("raw-cortex-m-scatter-{variant}.elf"))).unwrap();
    elf.symbol_by_name(name).unwrap_or_else(|| panic!("{name}")).address & !1
}

/// A section's run address and size from the ELF, and its load address: where its bytes lie in the flash image.
fn section(variant: &str, name: &str) -> (u64, u64, Option<u64>) {
    let elf = rampage_loaders::Binary::open(fixture(&format!("raw-cortex-m-scatter-{variant}.elf"))).unwrap();
    let section = elf.sections.iter().find(|section| section.name == name).unwrap();
    let image = std::fs::read(fixture(&format!("raw-cortex-m-scatter-{variant}.bin"))).unwrap();
    let load = elf.section_file_bytes(section).filter(|bytes| !bytes.is_empty()).map(|bytes| {
        let offset = image.windows(bytes.len()).position(|window| window == bytes).unwrap();
        0x0800_0000 + offset as u64
    });
    (section.address, section.size, load)
}

fn selector(variant: &str) -> Value {
    let length = std::fs::metadata(fixture(&format!("raw-cortex-m-scatter-{variant}.bin"))).unwrap().len();
    json!({ "profile": "cortex-m4", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true })
}

fn open(variant: &str, raw: Value) -> Arc<rampage_api::Project> {
    let request: RawProjectRequest = serde_json::from_value(raw).unwrap();
    Session::default().open_raw(&fixture(&format!("raw-cortex-m-scatter-{variant}.bin")), &request).unwrap()
}

/// A reported copy: kind, destination, length, source, status and mapped region.
type CopyRow<'a> = (&'a str, String, u64, Option<&'a str>, &'a str, &'a str);

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn call(project: &mut Arc<rampage_api::Project>, name: &str, input: Value) -> (String, bool) {
    call_shared(&tools(), project, name, input)
}

fn functions(project: &rampage_api::Project) -> Vec<u64> {
    project.functions(&rampage_api::FunctionsQuery::default()).unwrap().items.iter().map(|row| row.address).collect()
}

#[test]
fn startup_copies_are_found_from_the_entry_and_mapped_at_their_run_addresses() {
    for variant in ["gcc", "table"] {
        let truth = |name: &str| truth(variant, name);
        let mut project = open(variant, selector(variant));
        let summary = serde_json::to_value(project.summary()).unwrap();
        let scatter = &summary["raw"]["scatter_load"];
        assert_eq!(scatter["stop"], "jumped_into_copied_code", "{variant}: {scatter:#}");
        assert_eq!(scatter["continues_at"], hex(truth("ram_main")), "{variant}");
        let copies: Vec<CopyRow<'_>> = scatter["copies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|copy| {
                (
                    copy["kind"].as_str().unwrap(),
                    copy["destination"].as_str().unwrap().to_owned(),
                    copy["length"].as_u64().unwrap(),
                    copy["source"].as_str(),
                    copy["status"].as_str().unwrap(),
                    copy["region"].as_str().unwrap_or(""),
                )
            })
            .collect();
        let (ramfunc, ramfunc_size, ramfunc_load) = section(variant, ".ramfunc");
        let (data, data_size, data_load) = section(variant, ".data");
        let (bss, bss_size, _) = section(variant, ".bss");
        let (ramfunc_load, data_load) = (hex(ramfunc_load.unwrap()), hex(data_load.unwrap()));
        assert_eq!(
            copies,
            [
                ("copy", hex(ramfunc), ramfunc_size, Some(ramfunc_load.as_str()), "mapped", "raw.code.1"),
                ("copy", hex(data), data_size, Some(data_load.as_str()), "mapped", "raw.ram.2"),
                ("zero", hex(bss), bss_size, None, "mapped", "raw.ram.3"),
            ],
            "{variant}"
        );
        if variant == "table" {
            // Each copy names the handler the table walk called.
            assert_eq!(scatter["copies"][0]["routine"], hex(truth("region_copy")));
            assert_eq!(scatter["copies"][2]["routine"], hex(truth("region_zero")));
        }
        let regions = &summary["raw"]["regions"];
        assert_eq!(
            regions[1]["source"],
            json!({ "type": "scatter_load", "copy": 0, "region": "raw.code",
                    "offset": section(variant, ".ramfunc").2.unwrap() - 0x0800_0000 })
        );
        assert_eq!(regions[3]["source"], json!({ "type": "scatter_load", "copy": 2 }));
        assert!(regions[3].get("sha256").is_none());

        // The copied code installs the vector table copied with it; its SysTick handler, referenced only from that
        // table, is seeded.
        assert_eq!(
            scatter["vtor_stores"],
            json!([{ "value": hex(truth("ram_vectors")), "site": scatter["vtor_stores"][0]["site"] }])
        );
        let table = &scatter["vector_table"];
        assert_eq!(table["address"], hex(truth("ram_vectors")), "{variant}: {scatter:#}");
        assert_eq!(table["vectors"][15]["target"], hex(truth("ram_systick_handler")));
        assert_eq!(table["vectors"][15]["status"], "accepted");

        // Discovery continues into the copied code, which decompiles at its run address.
        let found = functions(&project);
        for name in ["reset_handler", "ram_main", "ram_mix", "ram_systick_handler"] {
            assert!(found.contains(&truth(name)), "{variant}: {name} missing from {found:x?}");
        }
        let (c, failed) = call(&mut project, "decompile", json!({ "at": hex(truth("ram_main")) }));
        assert!(!failed && c.contains(&format!("sub_{:x}(", truth("ram_mix"))), "{variant}: {c}");
    }
}

#[test]
fn scatter_load_false_reports_the_copies_without_mapping_them() {
    let mut raw = selector("gcc");
    raw["scatter_load"] = json!(false);
    let mut project = open("gcc", raw);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let copies = summary["raw"]["scatter_load"]["copies"].as_array().unwrap();
    assert_eq!(copies.len(), 3);
    assert!(copies.iter().all(|copy| copy["status"] == "not_mapped" && copy["not_mapped_reason"] == "not_requested"));
    assert_eq!(summary["raw"]["regions"].as_array().unwrap().len(), 1);
    assert!(!functions(&project).contains(&truth("gcc", "ram_main")));
    let (text, failed) = call(&mut project, "decompile", json!({ "at": hex(truth("gcc", "ram_main")) }));
    assert!(failed, "{text}");
    // Following and mapping are part of the interpretation.
    let identity = |project: &rampage_api::Project| project.binary.raw_interpretation_identity().unwrap().unwrap();
    assert_ne!(identity(&project), identity(&open("gcc", selector("gcc"))));

    // A destination the analyst already maps is reported, not mapped again.
    let mut raw = selector("gcc");
    raw["regions"] = json!([{ "kind": "ram", "base_address": "0x20000000", "length": "0x1000" }]);
    let summary = serde_json::to_value(open("gcc", raw).summary()).unwrap();
    let reasons: Vec<&str> = summary["raw"]["scatter_load"]["copies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|copy| copy["not_mapped_reason"].as_str().unwrap_or("mapped"))
        .collect();
    assert_eq!(reasons, ["mapped", "destination_mapped", "destination_mapped"]);

    // Other profiles have no reset-code follow.
    let msp430 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh/msp430.bin");
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "msp430", "offset": 0, "length": 16, "base_address": "0x4400", "scatter_load": true
    }))
    .unwrap();
    let error = Session::default().open_raw(&msp430, &request).err().unwrap().to_string();
    assert!(error.contains("scatter_load is defined only for ARM:LE:32:Cortex"), "{error}");
}
