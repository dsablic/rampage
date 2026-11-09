use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::tools::{RAW_CAPABLE_TOOLS, call_shared, raw_capable, raw_selector_schema, tools};
use rampage_api::{ApiError, MAX_RAW_PROJECTS, RawProjectRequest, Session, open_raw_binary};
use rampage_loaders::{MAX_RAW_BYTES, RawProfile};
use serde_json::{Value, json};

const MSP430: &[u8] = include_bytes!("../../../tests/fixtures/sleigh/msp430.bin");
const MOS6502: &[u8] = include_bytes!("../../../tests/fixtures/sleigh/6502.bin");

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-raw-project-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(value: Value) -> RawProjectRequest {
    serde_json::from_value(value).unwrap()
}

fn msp430(seeds: &[&str]) -> RawProjectRequest {
    request(json!({
        "profile": "TI_MSP430:LE:16:default",
        "offset": 0,
        "length": MSP430.len(),
        "base_address": "0x4400",
        "entry": "0x4400",
        "seeds": seeds,
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
    assert!(matches!(error, ApiError::Invalid(_) | ApiError::Unavailable(_) | ApiError::Load { .. }), "{text}");
    text
}

#[test]
fn same_interpretation_reuses_the_project_and_its_memory_only_comments() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", MSP430);
    let session = Session::default();
    let first = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    first.comment(0x4400, Some("main")).unwrap();
    // Seeds are a set: order and duplicates do not change the interpretation.
    let again = session.open_raw(&path, &msp430(&["0x4410", "0x4400", "0x4410"])).unwrap();
    assert!(Arc::ptr_eq(&first, &again));
    assert_eq!(again.comment_at(0x4400).as_deref(), Some("main"));
    assert_eq!(owned.names(), ["code.bin"], "Raw projects never write sidecars or annotation logs");
}

#[test]
fn changed_seeds_or_bytes_give_a_fresh_project() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", MSP430);
    let session = Session::default();
    let first = session.open_raw(&path, &msp430(&["0x4400"])).unwrap();
    first.comment(0x4400, Some("main")).unwrap();

    let reseeded = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    assert!(!Arc::ptr_eq(&first, &reseeded));
    assert_eq!(reseeded.comment_at(0x4400), None);

    let mut changed = MSP430.to_vec();
    changed[4] = 0x0f;
    std::fs::write(&path, &changed).unwrap();
    let rewritten = session.open_raw(&path, &msp430(&["0x4400"])).unwrap();
    assert!(!Arc::ptr_eq(&first, &rewritten));
    assert_eq!(rewritten.comment_at(0x4400), None);
    assert_eq!(rewritten.binary.image_bytes(), changed);

    std::fs::write(&path, MSP430).unwrap();
    let restored = session.open_raw(&path, &msp430(&["0x4400"])).unwrap();
    assert!(Arc::ptr_eq(&first, &restored));
    assert_eq!(owned.names(), ["code.bin"]);
}

#[test]
fn the_raw_cache_is_bounded_and_evicts_the_least_recently_used() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", &[0x30, 0x41].repeat(64));
    let session = Session::default();
    let open = |words: usize| {
        let request = request(json!({
            "profile": "TI_MSP430:LE:16:default",
            "offset": 0,
            "length": words * 2,
            "base_address": "0x1000",
        }));
        session.open_raw(&path, &request).unwrap()
    };
    let oldest = open(1);
    let kept = open(2);
    for words in 3..=MAX_RAW_PROJECTS {
        open(words);
    }
    assert!(Arc::ptr_eq(&oldest, &open(1)), "still within the bound");
    // 1 is now most recent, so the next interpretation evicts 2.
    open(MAX_RAW_PROJECTS + 1);
    assert!(!Arc::ptr_eq(&kept, &open(2)));
    assert!(Arc::ptr_eq(&oldest, &open(1)));
}

#[test]
fn invalid_ranges_and_sources_are_refused() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", MSP430);
    let base = |length: Value, offset: Value| json!({ "profile": "TI_MSP430:LE:16:default", "offset": offset, "length": length, "base_address": "0x4400" });
    assert!(refusal(&path, base(json!(0), json!(0))).contains("1..=131072"));
    assert!(refusal(&path, base(json!(MAX_RAW_BYTES + 1), json!(0))).contains("1..=131072"));
    assert!(refusal(&path, base(json!(MSP430.len() + 2), json!(0))).contains("outside"));
    assert!(refusal(&path, base(json!(2), json!(MSP430.len()))).contains("outside"));
    assert!(refusal(&path, base(json!(2), json!(u64::MAX))).contains("overflows"));

    let link = owned.0.join("link.bin");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    refusal(&link, base(json!(2), json!(0)));
    assert!(refusal(&owned.0, base(json!(2), json!(0))).contains("regular file"));
    assert!(refusal(&owned.0.join("missing.bin"), base(json!(2), json!(0))).contains("open"));

    let mut unknown = base(json!(2), json!(0));
    unknown["profile"] = json!("x86:LE:64:default");
    assert!(refusal(&path, unknown).contains("closed Raw language"));
    let mut misaligned = base(json!(2), json!(0));
    misaligned["seeds"] = json!(["0x4401"]);
    refusal(&path, misaligned);
    let mut outside = base(json!(2), json!(0));
    outside["entry"] = json!("0x4402");
    refusal(&path, outside);
    let mut many = base(json!(2), json!(0));
    many["seeds"] = json!(vec!["0x4400"; 8193]);
    assert!(refusal(&path, many).contains("8192"));
    assert_eq!(owned.names(), ["code.bin", "link.bin"]);
}

#[test]
fn open_raw_binary_reads_exactly_the_selected_range() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", MSP430);
    let binary = open_raw_binary(
        &path,
        &request(
            json!({ "profile": "TI_MSP430:LE:16:default", "offset": "0x10", "length": 4, "base_address": 0x4410 }),
        ),
    )
    .unwrap();
    assert_eq!(binary.image_bytes(), &MSP430[0x10..0x14]);
    assert_eq!(binary.raw_code_image().unwrap().range(), 0x4410..0x4414);
}

#[test]
fn the_selector_schema_is_closed_and_self_contained() {
    let error = serde_json::from_value::<RawProjectRequest>(json!({
        "profile": "TI_MSP430:LE:16:default", "offset": 0, "length": 2, "base_address": 0, "arch": "x86"
    }))
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"), "{error}");

    let schema = raw_selector_schema();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    let ids: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    assert_eq!(schema["properties"]["profile"]["enum"], json!(ids));
    let mut required: Vec<&str> = schema["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    required.sort();
    assert_eq!(required, ["base_address", "length", "offset", "profile"]);
    let text = schema.to_string();
    assert!(!text.contains("$ref") && !text.contains("$defs"), "embeddable without definitions: {text}");
}

#[test]
fn every_raw_capable_tool_answers_on_a_reviewed_msp430_project() {
    let owned = OwnedDirectory::new();
    let path = owned.file("code.bin", MSP430);
    let session = Session::default();
    let mut project = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    let registry = tools();
    let inputs = [
        ("binary_info", json!({})),
        ("list_functions", json!({})),
        ("disassemble", json!({ "at": "0x4400", "count": 4 })),
        ("function_graph", json!({ "at": "0x4400" })),
        ("xrefs", json!({ "to": "0x4410" })),
        ("search", json!({ "mode": { "kind": "bytes", "pattern": "30 41" } })),
        ("analysis_diagnostics", json!({ "include_discovery": true })),
        ("entry_diagnostics", json!({})),
        ("capabilities", json!({})),
        ("rename", json!({ "at": "0x4410", "name": "callee" })),
        ("set_comment", json!({ "at": "0x4400", "text": "main" })),
        ("annotate_batch", json!({ "entries": [{ "at": "0x4404", "comment": "nop" }] })),
        ("list_annotations", json!({})),
        ("undo", json!({})),
        ("redo", json!({})),
        ("decompile", json!({ "at": "0x4400" })),
    ];
    assert_eq!(inputs.each_ref().map(|(name, _)| *name), RAW_CAPABLE_TOOLS);
    let mut outcomes = Vec::new();
    for (name, input) in inputs {
        assert!(raw_capable(name));
        let (text, failed) = call_shared(&registry, &mut project, name, input);
        assert!(!failed, "{name}: {text}");
        serde_json::from_str::<Value>(&text).unwrap_or_else(|error| panic!("{name}: {error}: {text}"));
        outcomes.push((name, text));
    }
    let outcome = |name: &str| &outcomes.iter().find(|(tool, _)| *tool == name).unwrap().1;
    assert!(outcome("list_functions").contains("0x4410") || outcome("list_functions").contains("17424"));
    assert!(outcome("list_annotations").contains("callee"));
    // MSP430 has a reviewed C model, so Raw decompilation returns C that uses the analyst's name.
    assert!(outcome("decompile").contains("callee"), "{}", outcome("decompile"));
    assert!(!raw_capable("triage") && !raw_capable("inspect_sleigh"));

    let reopened = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    assert_eq!(reopened.comment_at(0x4404).as_deref(), Some("nop"), "redo restored the batch");
    assert_eq!(owned.names(), ["code.bin"]);
}

#[test]
fn raw_capable_tools_refuse_unsupported_raw_questions_explicitly() {
    let owned = OwnedDirectory::new();
    let registry = tools();
    let session = Session::default();

    let path = owned.file("code.bin", MSP430);
    let mut project = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    let immediate = json!({ "value": { "kind": "unsigned", "value": 0 } });
    for mode in [
        json!({ "kind": "immediate", "immediate": immediate }),
        json!({ "kind": "functions_referencing", "reference": { "kind": "constant", "immediate": immediate } }),
    ] {
        let (text, failed) = call_shared(&registry, &mut project, "search", json!({ "mode": mode }));
        assert!(failed, "{mode}: {text}");
        assert!(text.contains("no typed operand evidence; immediate search is unsupported"), "{mode}: {text}");
    }

    let path = owned.file("6502.bin", MOS6502);
    let mos6502 = request(json!({
        "profile": "6502:LE:16:default",
        "offset": 0,
        "length": MOS6502.len(),
        "base_address": "0x8000",
        "entry": "0x8000",
        "seeds": ["0x8000", "0x8010"],
    }));
    let mut project = session.open_raw(&path, &mos6502).unwrap();
    let (text, failed) = call_shared(&registry, &mut project, "list_functions", json!({}));
    assert!(!failed && text.contains("0x8010"), "6502 discovery still answers: {text}");
    let (text, failed) = call_shared(&registry, &mut project, "decompile", json!({ "at": "0x8000" }));
    assert!(failed, "{text}");
    assert!(text.contains("no reviewed C model for 6502:LE:16:default"), "{text}");
    assert_eq!(owned.names(), ["6502.bin", "code.bin"]);
}

const CORTEX_M: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m.bin");
const CORTEX_M_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m.elf");

fn cortex(profile: &str) -> RawProjectRequest {
    request(json!({
        "profile": profile,
        "offset": 0,
        "length": CORTEX_M.len(),
        "base_address": "0x8000000",
        "vector_table": true,
    }))
}

fn truth(name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(CORTEX_M_ELF).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

/// One call opens a headerless Cortex-M image: profile, range and base address, with the vector table seeding
/// the entry and handlers. Every function the unstripped ELF names is found from that alone.
#[test]
fn a_cortex_m_image_opens_in_one_call_and_recovers_every_elf_function() {
    let owned = OwnedDirectory::new();
    let path = owned.file("firmware.bin", CORTEX_M);
    let session = Session::default();
    let project = session.open_raw(&path, &cortex("cortex-m3")).unwrap();
    // Aliases and the language ID in any case are the same interpretation.
    for alias in ["ARM:LE:32:Cortex", "arm:le:32:cortex", "Cortex-M4", "thumb", "armv7m", "ARMv6-M"] {
        assert!(Arc::ptr_eq(&project, &session.open_raw(&path, &cortex(alias)).unwrap()), "{alias}");
    }
    let summary = serde_json::to_value(project.summary()).unwrap();
    assert_eq!(summary["arch"], "arm");
    assert_eq!(summary["entry"], format!("{:#x}", truth("reset_handler")));
    assert_eq!(summary["raw"]["profile"], "ARM:LE:32:Cortex");
    assert_eq!(summary["raw"]["vector_table"]["vectors"][1]["status"], "accepted");
    assert_eq!(summary["raw"]["vector_table"]["vectors"][0]["status"], "stack_pointer");

    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    let elf = rampage_loaders::Binary::open(CORTEX_M_ELF).unwrap();
    let mut names: Vec<&str> = elf
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
        .map(|symbol| symbol.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names.len(), 11, "{names:?}");
    for name in names {
        assert!(found.contains(&truth(name)), "{name} at {:#x} missing from {found:x?}", truth(name));
    }
    // String constants that movw/movt pairs form are even addresses: data, not function starts.
    assert!(!found.contains(&truth("BANNER")));
    assert!(found.len() <= 12, "{found:x?}");
    assert_eq!(owned.names(), ["firmware.bin"]);
}

#[test]
fn cortex_m_raw_projects_serve_every_raw_capable_tool_with_native_evidence() {
    let owned = OwnedDirectory::new();
    let path = owned.file("firmware.bin", CORTEX_M);
    let session = Session::default();
    let mut project = session.open_raw(&path, &cortex("cortex-m")).unwrap();
    let registry = tools();
    let reset = format!("{:#x}", truth("reset_handler"));
    let puts = format!("{:#x}", truth("uart_puts"));
    let inputs = [
        ("binary_info", json!({})),
        ("list_functions", json!({})),
        ("disassemble", json!({ "at": reset, "count": 8 })),
        ("function_graph", json!({ "at": reset })),
        ("xrefs", json!({ "to": format!("{:#x}", truth("BANNER")) })),
        (
            "search",
            json!({ "mode": { "kind": "immediate", "immediate": { "value": { "kind": "unsigned", "value": 0x1b } } } }),
        ),
        ("analysis_diagnostics", json!({ "include_discovery": true })),
        ("entry_diagnostics", json!({})),
        ("capabilities", json!({})),
        ("rename", json!({ "at": puts, "name": "uart_puts" })),
        ("set_comment", json!({ "at": reset, "text": "reset" })),
        ("annotate_batch", json!({ "entries": [{ "at": reset, "comment": "Reset vector" }] })),
        ("list_annotations", json!({})),
        ("undo", json!({})),
        ("redo", json!({})),
        ("decompile", json!({ "at": reset })),
    ];
    assert_eq!(inputs.each_ref().map(|(name, _)| *name), RAW_CAPABLE_TOOLS);
    let mut outcomes = Vec::new();
    for (name, input) in inputs {
        let (text, failed) = call_shared(&registry, &mut project, name, input);
        assert!(!failed, "{name}: {text}");
        serde_json::from_str::<Value>(&text).unwrap_or_else(|error| panic!("{name}: {error}: {text}"));
        outcomes.push((name, text));
    }
    let outcome = |name: &str| &outcomes.iter().find(|(tool, _)| *tool == name).unwrap().1;
    // reset_handler forms the banner string's address with movw/movt (the entry function, named `entry`).
    assert!(outcome("xrefs").contains("\"from_function\":\"entry\""), "{}", outcome("xrefs"));
    // The native decoder serves immediate search (Sleigh-decoded Raw profiles refuse it); ARM operand evidence
    // is partial, as for ARM ELF, and the result says so.
    assert!(outcome("search").contains("native operand evidence"), "{}", outcome("search"));
    assert!(outcome("binary_info").contains("\"vector_table\""), "{}", outcome("binary_info"));
    // ARM v8 Thumb with its reviewed C model decompiles the reset handler and names the analyst's callee.
    let decompiled = outcome("decompile");
    assert!(decompiled.contains("uart_puts(") && decompiled.contains("while"), "{decompiled}");
    assert_eq!(owned.names(), ["firmware.bin"]);
}

/// `disassemble` pages over the whole image as text, 1000 instructions at a time, data included.
#[test]
fn cortex_m_disassembly_lists_the_whole_image_in_pages() {
    let owned = OwnedDirectory::new();
    let path = owned.file("firmware.bin", CORTEX_M);
    let mut project = Session::default().open_raw(&path, &cortex("cortex-m3")).unwrap();
    let registry = tools();
    let end = 0x0800_0000 + CORTEX_M.len() as u64;
    let mut at = 0x0800_0000u64;
    let mut lines = 0;
    while at < end {
        let (text, failed) = call_shared(
            &registry,
            &mut project,
            "disassemble",
            json!({ "at": format!("{at:#x}"), "count": 1000, "view": "code" }),
        );
        assert!(!failed, "{text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        let rows = value.as_array().or_else(|| value["lines"].as_array()).expect("listing rows");
        let last = rows.last().unwrap();
        let address = u64::from_str_radix(last["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        at = address + last["bytes"].as_str().unwrap().len() as u64 / 2;
        lines += rows.len();
    }
    assert_eq!(at, end);
    assert!(lines > 300, "{lines}");
}

#[test]
fn cortex_m_requests_bound_size_and_refuse_vector_tables_elsewhere() {
    let owned = OwnedDirectory::new();
    let big = owned.file("big.bin", &vec![0; rampage_loaders::MAX_RAW_NATIVE_BYTES + 2]);
    let full = request(json!({
        "profile": "cortex-m", "offset": 0, "length": rampage_loaders::MAX_RAW_NATIVE_BYTES, "base_address": "0x8000000"
    }));
    let project = Session::default().open_raw(&big, &full).unwrap();
    assert_eq!(project.binary.image_bytes().len(), 4 * 1024 * 1024);
    let text =
        refusal(&big, json!({ "profile": "cortex-m", "offset": 0, "length": 4 * 1024 * 1024 + 1, "base_address": 0 }));
    assert!(text.contains("1..=4194304 bytes for ARM:LE:32:Cortex"), "{text}");
    let path = owned.file("code.bin", MSP430);
    let text = refusal(
        &path,
        json!({ "profile": "msp430", "offset": 0, "length": MSP430.len(), "base_address": "0x4400", "vector_table": true }),
    );
    assert!(text.contains("only for ARM:LE:32:Cortex"), "{text}");
    let error = serde_json::from_value::<RawProjectRequest>(json!({
        "profile": "cortex-m", "offset": 0, "length": 2, "base_address": 0, "vector_table": "nowhere"
    }))
    .unwrap_err();
    assert!(error.to_string().contains("vector_table"), "{error}");
}
