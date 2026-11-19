//! Xtensa firmware (tests/fixtures/xtensa, built from esp.c): an ESP32 application (windowed ABI) and an ESP8266
//! one (call0 ABI), as ELF files and as the app images and flash dumps a device holds. -mlongcalls makes calls into
//! ROM `l32r` + `callx`, and every string, global and constant is an `l32r` literal. Each -sym ELF is the truth.

use rampage_api::{Project, XrefQuery};
use rampage_loaders::Binary;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/");

/// Each chip's ELF, and the Raw request that maps the same application from its flash dump.
const APPS: [(&str, &str); 2] = [
    ("esp32-app", r#"{"path":"esp32-flash.bin","profile":"esp32","format":"esp","offset":"0x10000"}"#),
    ("esp8266-app", r#"{"path":"esp8266-flash.bin","profile":"esp8266","format":"esp"}"#),
];

fn truth(name: &str, symbol: &str) -> u64 {
    let binary = Binary::open(format!("{DIR}{name}-sym.elf")).unwrap();
    binary.symbol_by_name(symbol).unwrap_or_else(|| panic!("{name}: no {symbol}")).address
}

fn truth_functions(name: &str) -> Vec<u64> {
    let binary = Binary::open(format!("{DIR}{name}-sym.elf")).unwrap();
    let mut starts: Vec<u64> = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function && binary.is_code(symbol.address))
        .map(|symbol| symbol.address)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    starts
}

fn elf(name: &str) -> Project {
    Project::new(Binary::open(format!("{DIR}{name}.elf")).unwrap())
}

fn flash(request: &str) -> Project {
    let mut request: serde_json::Value = serde_json::from_str(request).unwrap();
    let path = format!("{DIR}{}", request["path"].as_str().unwrap());
    request.as_object_mut().unwrap().remove("path");
    let request: rampage_api::RawProjectRequest = serde_json::from_value(request).unwrap();
    Project::new(rampage_api::open_raw_binary(std::path::Path::new(&path), &request).unwrap())
}

/// Both views of each application: the stripped ELF and the app image in the flash dump.
fn views() -> Vec<(&'static str, &'static str, Project)> {
    APPS.iter().flat_map(|&(name, request)| [(name, "elf", elf(name)), (name, "flash", flash(request))]).collect()
}

fn string(project: &Project, text: &str) -> u64 {
    let binary = &project.binary;
    let needle = [text.as_bytes(), &[0]].concat();
    binary
        .segments
        .iter()
        .find_map(|segment| {
            let bytes = binary.read(segment.address, segment.size.min(segment.file_size))?;
            let at = bytes.windows(needle.len()).position(|window| window == needle)?;
            Some(segment.address + at as u64)
        })
        .unwrap_or_else(|| panic!("{text:?} not in the image"))
}

fn referencing_functions(project: &Project, address: u64) -> Vec<String> {
    let rows = project.xrefs(XrefQuery::To(address), None, None).unwrap();
    rows.items.into_iter().filter_map(|row| row.from_function).collect()
}

/// Every function is found without symbols: windowed ones from their `entry` prologue or a call, call0 ones from
/// their stack adjustment (before which GCC schedules argument moves), and those reached only through a pointer
/// (the task entry, the command handlers) from those prologues. Nothing else is taken for a function.
#[test]
fn discovery_finds_every_function_and_nothing_else() {
    for (name, view, project) in views() {
        let found = project.functions(&rampage_api::FunctionsQuery { limit: Some(1000), ..Default::default() });
        let mut found: Vec<u64> = found.unwrap().items.iter().map(|function| function.address).collect();
        found.sort_unstable();
        assert_eq!(found, truth_functions(name), "{name} {view}");
    }
}

/// Strings are reached through `l32r` literals: each is referenced from the function that loads it.
#[test]
fn strings_are_referenced_through_literals() {
    for (name, view, project) in views() {
        for (text, function) in
            [("https://telemetry.example.com/v1/report", "handle_report"), ("admin unlocked\n", "app_main")]
        {
            let from = referencing_functions(&project, string(&project, text));
            let expected = format!("sub_{:x}", truth(name, function));
            assert!(from.contains(&expected), "{name} {view}: {text:?} referenced from {from:?}");
        }
    }
}

/// `l32r a8, ets_printf; callx8 a8` is a call to the ROM address, and ESP-IDF's main_task leads to app_main.
#[test]
fn find_main_takes_app_main_from_main_task() {
    for (name, view, project) in views() {
        let report = project.find_main(rampage_api::ReportLimits::default(), false).unwrap();
        let report = serde_json::to_value(&report).unwrap();
        let candidate = &report["sections"][0]["findings"][0];
        assert_eq!(candidate["address"], format!("{:#x}", truth(name, "app_main")), "{name} {view}: {report:#}");
        assert_eq!(candidate["confidence"], "high", "{name} {view}");
    }
}

/// Literals fold to what they hold: calls name their targets, and no literal-pool slot is left as a variable.
#[test]
fn decompiled_code_folds_literals() {
    for (name, view, project) in views() {
        let code = project.decompile(truth(name, "app_main")).unwrap().code;
        let crc = format!("sub_{:x}(0,", truth(name, "crc32_le"));
        assert!(code.contains(&crc), "{name} {view}: {code}");
        assert!(!code.contains("Ram40"), "{name} {view}: {code}");
        let rom = if name == "esp32-app" { "0x40007d54" } else { "0x400024cc" };
        assert!(code.contains(rom), "{name} {view}: {code}");
    }
}

/// evaluate_function runs both ABIs: a windowed call's result comes back in the caller's a10, and the ESP32's
/// zero-overhead loop iterates.
#[test]
fn evaluation_runs_windowed_and_call0_code() {
    for (name, view, project) in views() {
        let evaluate = |symbol: &str, args: serde_json::Value| {
            let request = serde_json::json!({ "at": format!("{:#x}", truth(name, symbol)), "args": args });
            let report = project.evaluate_function(&serde_json::from_value(request).unwrap()).unwrap();
            let report = serde_json::to_value(report).unwrap();
            assert_eq!(report["stop"], "returned", "{name} {view} {symbol}: {report}");
            report["result"]["unsigned"].as_u64().unwrap()
        };
        let text = |text: &str| serde_json::json!({ "buffer": { "text": text } });
        assert_eq!(evaluate("crc32_le", serde_json::json!([0, text("123456789"), 9])), 0xcbf4_3926, "{name} {view}");
        assert_eq!(evaluate("check_password", serde_json::json!([text("hunter2-esp")])), 1, "{name} {view}");
        assert_eq!(evaluate("check_password", serde_json::json!([text("hunter3-esp")])), 0, "{name} {view}");
        assert_eq!(evaluate("scale_add", serde_json::json!([5, 2, 1])), 16, "{name} {view}");
    }
}

/// The CRC-32 polynomial an `l32r` loads is a searchable constant and names the routine in integrity_checks.
#[test]
fn literal_constants_are_searchable() {
    let registry = rampage_api::tools::tools();
    for (name, view, project) in views() {
        let mut project = std::sync::Arc::new(project);
        let mode = serde_json::json!({ "kind": "functions_referencing", "reference": { "kind": "constant", "immediate": { "value": { "kind": "unsigned", "value": 0xedb8_8320u32 } } } });
        let (text, failed) =
            rampage_api::tools::call_shared(&registry, &mut project, "search", serde_json::json!({ "mode": mode }));
        assert!(!failed, "{text}");
        let report: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["hits"][0]["address"], format!("{:#x}", truth(name, "crc32_le")), "{name} {view}");
        let (text, failed) =
            rampage_api::tools::call_shared(&registry, &mut project, "integrity_checks", serde_json::json!({}));
        let crc = format!("\"address\":\"{:#x}\"", truth(name, "crc32_le"));
        assert!(!failed && text.contains("polynomial 0xedb88320") && text.contains(&crc), "{name} {view}: {text}");
    }
}

/// binary_info reports what the app image states and whether its digests hold.
#[test]
fn app_image_facts_are_reported() {
    let project = flash(APPS[0].1);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let esp = &summary["raw"]["esp"];
    assert_eq!(esp["chip"], "esp32", "{esp:#}");
    assert_eq!(
        (&esp["abi"], &esp["entry"]),
        (&"windowed".into(), &format!("{:#x}", truth("esp32-app", "call_start_cpu0")).into())
    );
    assert_eq!((&esp["checksum"]["valid"], &esp["sha256"]["valid"]), (&true.into(), &true.into()));
    assert_eq!(esp["app_desc"]["project_name"], "thermostat");
    assert_eq!(project.binary.entry, Some(truth("esp32-app", "call_start_cpu0")));
    let esp8266 = flash(APPS[1].1);
    assert!(esp8266.binary.xtensa_call0());
    // The rest of the ESP8266 flash maps as IROM at 0x40200000 plus its offset.
    assert!(esp8266.binary.is_code(truth("esp8266-app", "app_main")));
    assert!(!project.binary.xtensa_call0() && elf("esp8266-app").binary.xtensa_call0());
}

/// The headerless hint names the selector for each application of a flash dump, and for an app image.
#[test]
fn headerless_hints_name_the_esp_selector() {
    let hint = rampage_api::headerless_guidance_for(std::path::Path::new(&format!("{DIR}esp32-flash.bin")));
    assert!(
        hint.contains("factory with \"raw\":{\"profile\":\"xtensa\",\"format\":\"esp\",\"offset\":\"0x10000\"}"),
        "{hint}"
    );
    assert!(hint.contains("nvs (data/nvs) at 0x9000"), "{hint}");
    let hint = rampage_api::headerless_guidance_for(std::path::Path::new(&format!("{DIR}esp32-app.bin")));
    assert!(hint.starts_with("The file starts with an ESP32 app image"), "{hint}");
}
