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
        // Patches go to the load image the copy was taken from.
        let at = truth("ram_mix");
        let original = project.binary.read(at, 2).unwrap().to_vec();
        let error = project.patch_bytes(at, &original, &[0x00, 0xbf], false).err().unwrap().to_string();
        let load = section(variant, ".ramfunc").2.unwrap() + (at - section(variant, ".ramfunc").0);
        assert!(error.contains(&format!("copy of raw.code at {load:#x}; patch {load:#x} in raw.code")), "{error}");
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

/// Few functions for much code means discovery stopped early: binary_info and list_functions say what to try, and
/// stay silent once the options are in use or discovery is in proportion.
#[test]
fn a_small_discovery_in_a_large_image_suggests_pointer_tables_and_mapping_the_copies() {
    let directory = std::env::temp_dir().join(format!("rampage-raw-scatter-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    // The GCC-style image padded with erased flash to 1 MiB: three functions before the copies are mapped, seven after.
    let mut bytes = std::fs::read(fixture("raw-cortex-m-scatter-gcc.bin")).unwrap();
    bytes.resize(1024 * 1024, 0xff);
    let path = directory.join("padded.bin");
    std::fs::write(&path, &bytes).unwrap();
    let open_padded = |changes: Value| {
        let mut raw = json!({ "profile": "cortex-m4", "offset": 0, "length": bytes.len(),
                              "base_address": "0x8000000", "vector_table": true });
        raw.as_object_mut().unwrap().extend(changes.as_object().unwrap().clone());
        let request: RawProjectRequest = serde_json::from_value(raw).unwrap();
        Session::default().open_raw(&path, &request).unwrap()
    };
    let next = |project: &rampage_api::Project| {
        // binary_info never starts discovery: before list_functions it has no hint.
        assert!(serde_json::to_value(project.summary()).unwrap().get("next").is_none());
        let query = rampage_api::FunctionsQuery::default();
        let page = serde_json::to_value(project.functions_page(&query).unwrap()).unwrap();
        let summary = serde_json::to_value(project.summary()).unwrap();
        assert_eq!(summary["next"], page["next"]);
        summary["next"].as_str().map(str::to_owned)
    };
    let hint = next(&open_padded(json!({ "scatter_load": false, "pointer_tables": false })))
        .expect("three functions in 1 MiB");
    assert!(hint.starts_with("Discovery from the entry and seeds found 3 functions covering 1 of 1024 KiB"), "{hint}");
    assert!(hint.contains("\"pointer_tables\": true") && hint.contains("3 startup copies"), "{hint}");
    // Mapped copies alone leave the pointer-table suggestion; with pointer tables too, nothing is suggested.
    let hint = next(&open_padded(json!({ "pointer_tables": false }))).unwrap();
    assert!(hint.contains("pointer_tables") && !hint.contains("scatter_load"), "{hint}");
    assert_eq!(next(&open_padded(json!({ "pointer_tables": true }))), None);
    // A small image in proportion gets no hint.
    assert_eq!(next(&open("gcc", selector("gcc"))), None);
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A Cortex-M image at 0x8000000 whose only path from the entry (`bx lr`) finds one function, with `functions`
/// further functions (`push {r4, lr}; pop {r4, pc}`) reached only through tables of four code pointers each,
/// separated by a word that is no pointer, in at least 64 KiB.
fn table_image(functions: usize) -> Vec<u8> {
    let mut image = vec![0x70, 0x47];
    image.resize(0x10, 0);
    for _ in 0..functions {
        image.extend([0x10, 0xb5, 0x10, 0xbd]);
    }
    for group in (0..functions).collect::<Vec<_>>().chunks(4) {
        for &index in group {
            image.extend((0x0800_0010 + 4 * index as u32 + 1).to_le_bytes());
        }
        image.extend(0x1234_5678u32.to_le_bytes());
    }
    // Erased flash after the tables, so one function is fewer than one per 16 KiB.
    image.resize(image.len().max(64 * 1024), 0xff);
    image
}

fn open_table_image(
    session: &Session,
    directory: &std::path::Path,
    functions: usize,
    pointer_tables: Value,
) -> Arc<rampage_api::Project> {
    let bytes = table_image(functions);
    let path = directory.join(format!("tables-{functions}.bin"));
    std::fs::write(&path, &bytes).unwrap();
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m4", "offset": 0, "length": bytes.len(), "base_address": "0x8000000",
        "entry": "0x8000000", "pointer_tables": pointer_tables,
    }))
    .unwrap();
    session.open_raw(&path, &request).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-raw-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// With `pointer_tables` unset, a sparse discovery runs the pointer-table scan itself: binary_info's pointer-table
/// section and list_functions say it ran automatically and why, and no hint asks for it. The project then also
/// answers an explicit `pointer_tables: true`, keeping its annotations. A discovery in proportion leaves the
/// project exactly as `pointer_tables` false would.
#[test]
fn a_sparse_discovery_runs_the_pointer_table_scan_automatically() {
    let directory = scratch("auto-tables");
    let session = Session::default();
    let project = open_table_image(&session, &directory, 400, Value::Null);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let automatic = &summary["raw"]["pointer_tables"]["automatic"];
    assert_eq!(automatic["functions_before"], 1, "{automatic:#}");
    assert_eq!(automatic["applied"], true, "{automatic:#}");
    assert_eq!(automatic["outcome"], "applied", "{automatic:#}");
    assert!(automatic["reason"].as_str().unwrap().contains("pointer_tables was unset"), "{automatic:#}");
    assert_eq!(summary["raw"]["pointer_tables"]["accepted_tables"], 100);
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    assert_eq!(page["total"], 401);
    let note = page["note"].as_str().unwrap();
    assert!(note.contains("found 1 function covering") && note.contains("ran automatically"), "{note}");
    assert!(page.get("next").is_none() && summary.get("next").is_none(), "{page:#}");
    // The scan's interpretation is pointer_tables true's, and that request finds the same project.
    project.rename(0x0800_0010, Some("first")).unwrap();
    let explicit = open_table_image(&session, &directory, 400, json!(true));
    assert!(Arc::ptr_eq(&project, &explicit));
    assert!(Arc::ptr_eq(&project, &open_table_image(&session, &directory, 400, Value::Null)));
    assert_eq!(explicit.function_name(0x0800_0010), "first");
    let off = open_table_image(&session, &directory, 400, json!(false));
    assert!(serde_json::to_value(off.summary()).unwrap()["raw"].get("pointer_tables").is_none());

    // A scan that accepts no table keeps pointer_tables false's interpretation and says so.
    let mut bytes = std::fs::read(fixture("raw-cortex-m-scatter-gcc.bin")).unwrap();
    bytes.resize(1024 * 1024, 0xff);
    let path = directory.join("padded.bin");
    std::fs::write(&path, &bytes).unwrap();
    let padded = |pointer_tables: Value| {
        let request: RawProjectRequest = serde_json::from_value(json!({
            "profile": "cortex-m4", "offset": 0, "length": bytes.len(), "base_address": "0x8000000",
            "vector_table": true, "pointer_tables": pointer_tables,
        }))
        .unwrap();
        session.open_raw(&path, &request).unwrap()
    };
    let project = padded(Value::Null);
    let identity = |project: &rampage_api::Project| project.binary.raw_interpretation_identity().unwrap().unwrap();
    assert_eq!(identity(&project), identity(&padded(json!(false))));
    let summary = serde_json::to_value(project.summary()).unwrap();
    let automatic = &summary["raw"]["pointer_tables"]["automatic"];
    assert_eq!(automatic["outcome"], "found_none", "{summary:#}");
    assert_eq!(automatic["applied"], false);
    assert!(summary["raw"]["pointer_tables"].get("tables").is_none());
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    assert!(page["note"].as_str().unwrap().contains("accepted no table"), "{page:#}");
    std::fs::remove_dir_all(&directory).unwrap();

    // In proportion: no scan, the identity of pointer_tables false, no note.
    let project = open("gcc", selector("gcc"));
    let mut off = selector("gcc");
    off["pointer_tables"] = json!(false);
    assert_eq!(identity(&project), identity(&open("gcc", off)));
    assert!(serde_json::to_value(project.summary()).unwrap()["raw"].get("pointer_tables").is_none());
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    assert!(page.get("note").is_none(), "{page:#}");
}

/// An automatic scan whose seeds exceed the 8192-seed cap is refused: the sparse project stays, binary_info reports
/// the refusal under raw.pointer_tables.automatic, and the hint says what to do instead.
#[test]
fn a_refused_automatic_scan_is_reported() {
    let directory = scratch("auto-refused");
    let session = Session::default();
    let project = open_table_image(&session, &directory, 8300, Value::Null);
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    assert_eq!(page["total"], 1);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let automatic = &summary["raw"]["pointer_tables"]["automatic"];
    assert_eq!(automatic["outcome"], "refused", "{summary:#}");
    assert!(automatic["refused"].as_str().unwrap().contains("8192"), "{automatic:#}");
    assert!(page["note"].as_str().unwrap().contains("not applied"), "{page:#}");
    let next = summary["next"].as_str().unwrap();
    assert!(next.contains("automatic pointer-table scan was refused"), "{next}");
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A Raw project with a thousand pointer tables: binary_info's summary and full views fit the tool budget, with
/// every list under `raw` shortened and counted.
#[test]
fn binary_info_on_a_large_raw_project_fits_the_budget() {
    let directory = scratch("large-info");
    let mut project = open_table_image(&Session::default(), &directory, 4000, json!(true));
    for view in ["summary", "full"] {
        let (text, failed) = call(&mut project, "binary_info", json!({ "view": view }));
        assert!(!failed, "{view}: {text}");
        assert!(text.len() <= 60_000, "{view}: {}", text.len());
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["raw"]["pointer_tables"]["tables_count"], 1000, "{view}");
        assert_eq!(value["raw"]["pointer_tables"]["accepted_tables"], 1000);
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

/// Opened at a wrong base (a copy destination, as an agent guessed) without reading the vector table, binary_info
/// says the base looks wrong and names the linked base; at the linked base it is consistent.
#[test]
fn a_wrong_base_is_named_with_the_linked_one() {
    for variant in ["gcc", "table"] {
        let wrong = 0x0100_0000u64;
        let entry = wrong + (truth(variant, "reset_handler") - 0x0800_0000);
        let mut raw = selector(variant);
        raw["base_address"] = json!(hex(wrong));
        raw["entry"] = json!(hex(entry));
        raw.as_object_mut().unwrap().remove("vector_table");
        let project = open(variant, raw);
        let summary = serde_json::to_value(project.summary()).unwrap();
        let check = &summary["raw"]["base_check"];
        assert_eq!(check["verdict"], "looks_wrong", "{variant}: {summary:#}");
        assert_eq!(check["better_candidate"]["base_address"], "0x8000000", "{variant}: {check:#}");
        let next = summary["next"].as_str().unwrap();
        assert!(next.contains("base_address 0x8000000"), "{variant}: {next}");
        if summary["raw"]["scatter_load"]["stop"] == "bad_fetch" {
            assert_eq!(check["bad_fetch"]["candidate_base"], "0x8000000", "{variant}: {check:#}");
        }

        let right = open(variant, selector(variant));
        let summary = serde_json::to_value(right.summary()).unwrap();
        assert_eq!(summary["raw"]["base_check"]["verdict"], "consistent", "{variant}: {summary:#}");
        assert!(summary["raw"]["base_check"].get("next").is_none());
    }
}

/// Reset code that jumps through a literal to an absolute address: opened at a wrong base, the follow fetches
/// outside every region, and the candidate base that maps that address is named.
#[test]
fn a_bad_fetch_inside_the_image_under_another_base_names_that_base() {
    let mut image = vec![0u8; 0x400];
    // ldr r0, [pc, #0]; bx r0; .word 0x08000101
    image[..8].copy_from_slice(&[0x00, 0x48, 0x00, 0x47, 0x01, 0x01, 0x00, 0x08]);
    for (index, function) in [0x100usize, 0x140, 0x180].into_iter().enumerate() {
        // push {r7, lr}; pop {r7, pc}
        image[function..function + 4].copy_from_slice(&[0x80, 0xb5, 0x80, 0xbd]);
        let pointer = 0x0800_0001u32 + function as u32;
        image[0x200 + index * 4..0x204 + index * 4].copy_from_slice(&pointer.to_le_bytes());
    }
    let path = std::env::temp_dir().join(format!("rampage-bad-fetch-{}.bin", std::process::id()));
    std::fs::write(&path, &image).unwrap();
    let open = |base: &str| {
        let raw = json!({ "profile": "cortex-m4", "offset": 0, "length": image.len(), "base_address": base,
            "entry": base });
        let request: RawProjectRequest = serde_json::from_value(raw).unwrap();
        let project = Session::default().open_raw(&path, &request).unwrap();
        serde_json::to_value(project.summary()).unwrap()
    };
    let wrong = open("0x1000000");
    let right = open("0x8000000");
    std::fs::remove_file(&path).unwrap();

    assert_eq!(wrong["raw"]["scatter_load"]["stop"], "bad_fetch", "{wrong:#}");
    let check = &wrong["raw"]["base_check"];
    assert_eq!(check["verdict"], "looks_wrong", "{check:#}");
    assert_eq!(check["bad_fetch"]["target"], "0x8000100");
    assert_eq!(check["bad_fetch"]["candidate_base"], "0x8000000");
    assert_eq!(check["better_candidate"]["base_address"], "0x8000000");
    let next = wrong["next"].as_str().unwrap();
    assert!(next.contains("fetched an instruction at 0x8000100") && next.contains("base_address 0x8000000"), "{next}");

    assert_eq!(right["raw"]["base_check"]["verdict"], "consistent", "{right:#}");
    assert!(right["raw"]["base_check"].get("bad_fetch").is_none());
}

/// find_crypto and triage read every mapped region at its mapped address: a CRC-32 table that only exists after
/// decoding, and its copy in another region, are both found; triage measures the startup copies scatter-load maps.
#[test]
fn find_crypto_and_triage_read_decoded_regions_and_copies() {
    let table: Vec<u8> = (0..256u32)
        .flat_map(|index| {
            let mut crc = index;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { 0xedb8_8320 ^ (crc >> 1) } else { crc >> 1 };
            }
            crc.to_le_bytes()
        })
        .collect();
    let packed = rampage_decode::encode::lzss(&rampage_decode::Lzss::classic_4k(4078, 0), &table);
    let mut file = vec![0x70, 0x47];
    file.resize(256, 0);
    file.extend(&packed);
    let directory = scratch("crypto-regions");
    let path = directory.join("packed.bin");
    std::fs::write(&path, &file).unwrap();
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m4", "offset": 0, "length": 256, "base_address": "0x8000000", "entry": "0x8000000",
        "pointer_tables": false,
        "regions": [
            { "kind": "data", "base_address": "0x20000000", "offset": 256, "length": packed.len(),
              "decode": { "codec": "lzss-4k", "expected_output_size": 1024 } },
            { "kind": "data", "base_address": "0x30000000", "length": 1024, "from": { "region": 1, "offset": 0 } },
        ],
    }))
    .unwrap();
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let (text, failed) = call(&mut project, "find_crypto", json!({}));
    assert!(!failed, "{text}");
    for address in ["\"0x20000000\"", "\"0x30000000\""] {
        assert!(text.contains(address), "{address}: {text}");
    }
    assert!(text.contains("CRC"), "{text}");
    std::fs::remove_dir_all(&directory).unwrap();

    // The GCC-style image: the startup copies scatter-load maps are triage sections, with their entropy.
    let mut project = open("gcc", selector("gcc"));
    let summary = serde_json::to_value(project.summary()).unwrap();
    let copies: Vec<String> = summary["raw"]["regions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|region| region["source"]["type"] == "scatter_load")
        .map(|region| region["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(!copies.is_empty(), "{summary:#}");
    let (text, failed) = call(&mut project, "triage", json!({}));
    assert!(!failed, "{text}");
    let triage: Value = serde_json::from_str(&text).unwrap();
    let sections: Vec<&str> =
        triage["sections"].as_array().unwrap().iter().map(|section| section["name"].as_str().unwrap()).collect();
    for copy in &copies {
        assert!(sections.contains(&copy.as_str()), "{copy}: {sections:?}");
    }
    assert!(triage["hints"].to_string().contains("Raw project (ARM:LE:32:Cortex)"), "{text}");
}
