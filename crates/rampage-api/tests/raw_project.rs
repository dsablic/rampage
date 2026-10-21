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
    let text = error.to_string();
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
