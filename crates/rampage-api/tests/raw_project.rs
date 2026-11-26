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

fn svd(name: &str) -> String {
    format!("{}/../../tests/fixtures/svd/{name}", env!("CARGO_MANIFEST_DIR"))
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

/// The input of a patch-review tool that needs the current receipt; `None` for the other tools.
fn reviewed_input(
    project: &Arc<rampage_api::Project>,
    name: &str,
    at: u64,
    original: &[u8],
    export: &Path,
) -> Option<Value> {
    let receipt = project.patch_receipt().unwrap();
    let tokens = json!({ "source_sha256": receipt.source_sha256, "expected_revision": receipt.revision_sha256 });
    let mut input = match name {
        "patch_bytes" => {
            let replacement: Vec<u8> = original.iter().map(|byte| byte ^ 0xff).collect();
            json!({
                "at": format!("{at:#x}"),
                "original_hex": original.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "replacement_hex": replacement.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "allow_data": false,
            })
        }
        "revert_patch" => json!({ "at": format!("{at:#x}") }),
        "export_image" => return Some(json!({ "destination": export, "expected_revision": receipt.revision_sha256 })),
        _ => return None,
    };
    input.as_object_mut().unwrap().extend(tokens.as_object().unwrap().clone());
    Some(input)
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
    // An explicit length past the profile's cap is refused before the file is read: even a missing file says so.
    let text = refusal(&owned.0.join("missing.bin"), base(json!(MAX_RAW_BYTES + 1), json!(0)));
    assert!(text.contains("1..=131072") && !text.contains("open"), "{text}");
    // With length omitted, an offset at the end of the file is refused without a length.
    let text = refusal(&path, json!({ "profile": "msp430", "offset": MSP430.len(), "base_address": "0x4400" }));
    assert!(text.contains("is at or past the end of the file") && !text.contains("length"), "{text}");

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
    assert_eq!(required, ["profile"]);
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
        ("list_strings", json!({})),
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
        ("evaluate_function", json!({ "at": "0x4410" })),
        ("check_claim", json!({ "claims": [{ "kind": "references", "target": "0x4410" }] })),
        ("import_svd", json!({ "svd": svd("edge-cases.svd"), "apply": true })),
        ("peripheral_access", json!({ "peripheral": "CTRL" })),
        ("peripheral_map", json!({})),
        ("list_patches", json!({})),
        ("patch_bytes", Value::Null),
        ("revert_patch", Value::Null),
        ("integrity_checks", json!({})),
        ("export_image", Value::Null),
        ("identify_functions", json!({})),
        ("lock_mechanisms", json!({})),
        ("function_summary", json!({ "at": "0x4400" })),
        ("find_crypto", json!({})),
        ("triage", json!({})),
        ("triage_report", json!({})),
        ("find_main", json!({})),
    ];
    assert_eq!(inputs.each_ref().map(|(name, _)| *name), RAW_CAPABLE_TOOLS);
    let export = owned.0.join("export.bin");
    let mut outcomes = Vec::new();
    for (name, input) in inputs {
        assert!(raw_capable(name));
        let input = reviewed_input(&project, name, 0x4404, &MSP430[4..6], &export).unwrap_or(input);
        let (text, failed) = call_shared(&registry, &mut project, name, input);
        if name == "evaluate_function" {
            // The interpreter has no MSP430 semantics: an explicit refusal naming the processor.
            assert!(failed && text.contains("Msp430"), "{text}");
            continue;
        }
        assert!(!failed, "{name}: {text}");
        serde_json::from_str::<Value>(&text).unwrap_or_else(|error| panic!("{name}: {error}: {text}"));
        outcomes.push((name, text));
    }
    let outcome = |name: &str| &outcomes.iter().find(|(tool, _)| *tool == name).unwrap().1;
    assert!(outcome("list_functions").contains("0x4410") || outcome("list_functions").contains("17424"));
    assert!(outcome("list_annotations").contains("callee"));
    // MSP430 has a reviewed C model, so Raw decompilation returns C that uses the analyst's name.
    assert!(outcome("decompile").contains("callee"), "{}", outcome("decompile"));
    assert!(outcome("triage").contains("Raw project (TI_MSP430"), "{}", outcome("triage"));
    assert!(outcome("triage_report").contains("no file header"), "{}", outcome("triage_report"));
    assert!(raw_capable("find_main") && !raw_capable("inspect_sleigh"));

    assert!(outcome("patch_bytes").contains("\"active_ranges\":1"), "{}", outcome("patch_bytes"));
    // The patch was reverted, so the exported file is the input, byte for byte.
    assert!(outcome("export_image").contains("\"format\":\"binary_file\""), "{}", outcome("export_image"));
    assert_eq!(std::fs::read(&export).unwrap(), MSP430);

    let reopened = session.open_raw(&path, &msp430(&["0x4400", "0x4410"])).unwrap();
    assert_eq!(reopened.comment_at(0x4404).as_deref(), Some("nop"), "redo restored the batch");
    assert_eq!(owned.names(), ["code.bin", "export.bin"]);
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

/// An lzss-4k stream of `bytes` (LSB-first flags, 1 = literal) that repeats its first 16 bytes once through a
/// reference, so the decoder's ring matters, then holds every byte as a literal.
fn lzss_4k(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut items: Vec<Vec<u8>> = bytes.iter().map(|&byte| vec![byte]).collect();
    // Prefix the stream with 16 literal bytes and one 16-byte reference to them (ring start 0xfee, length 16 =
    // nibble 13 + 3); the payload follows, so the decoded image is `prefix ++ prefix ++ bytes`.
    let prefix: Vec<Vec<u8>> = bytes[..16].iter().map(|&byte| vec![byte]).collect();
    let position: u16 = 0xfee;
    let reference = vec![(position & 0xff) as u8, (((position >> 4) & 0xf0) as u8) | 13];
    let mut stream = prefix;
    stream.push(reference);
    stream.append(&mut items);
    for group in stream.chunks(8) {
        let flags = group.iter().enumerate().fold(0u8, |flags, (bit, item)| flags | (u8::from(item.len() == 1) << bit));
        out.push(flags);
        group.iter().for_each(|item| out.extend_from_slice(item));
    }
    out
}

/// A compressed image opens as the primary Raw region: the vector table and seeds read the decoded bytes, and
/// binary_info reports the decode receipt as the region's source.
#[test]
fn a_compressed_image_opens_as_the_primary_raw_region() {
    let owned = OwnedDirectory::new();
    // 32 header bytes, then the stream; the decoded image is the fixture behind a 32-byte copy of its own start,
    // so the fixture's vector table lies 32 bytes above the base.
    let stream = lzss_4k(CORTEX_M);
    let mut file = vec![0xa5; 32];
    file.extend_from_slice(&stream);
    let path = owned.file("update.bin", &file);
    let decoded = 32 + CORTEX_M.len();
    let selector = |size: usize| {
        json!({
            "profile": "cortex-m3", "offset": 32, "length": stream.len(), "base_address": "0x7ffffe0",
            "vector_table": "0x8000000",
            "decode": { "codec": "lzss-4k", "expected_output_size": size },
        })
    };
    let project = Session::default().open_raw(&path, &request(selector(decoded))).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    assert_eq!(summary["entry"], format!("{:#x}", truth("reset_handler")));
    let region = &summary["raw"]["regions"][0];
    assert_eq!((region["name"].as_str(), region["length"].as_u64()), (Some("raw.code"), Some(decoded as u64)));
    let receipt = &region["source"]["receipt"];
    assert_eq!(region["source"]["type"], "decoded");
    assert_eq!((receipt["source_offset"].as_u64(), receipt["input_fully_consumed"].as_bool()), (Some(32), Some(true)));
    assert_eq!(receipt["output_sha256"], region["sha256"]);
    // The stream runs to the end of the file, so an omitted length (the rest of the file) reads the same encoded
    // bytes and opens the same interpretation.
    let mut rest = selector(decoded);
    rest.as_object_mut().unwrap().remove("length");
    let same = Session::default().open_raw(&path, &request(rest)).unwrap();
    assert_eq!(serde_json::to_value(same.summary()).unwrap(), summary);
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    for name in ["reset_handler", "format_hex", "systick_handler"] {
        assert!(found.contains(&truth(name)), "{name} at {:#x} missing from {found:x?}", truth(name));
    }
    // The decoded size obeys the profile's cap; the encoded length the decoder's input cap; a wrong size is the
    // provider's refusal.
    let text = refusal(&path, selector(rampage_loaders::MAX_RAW_NATIVE_BYTES + 1));
    assert!(text.contains("decode.expected_output_size must be 1..=4194304"), "{text}");
    let mut long = selector(decoded);
    long["length"] = json!(8 * 1024 * 1024 + 1);
    assert!(refusal(&path, long).contains("encoded bytes with decode"));
    let text = refusal(&path, selector(decoded + 64));
    assert!(text.contains("Raw decode:"), "{text}");
    // The provider's budgets hold for the primary region: 128:1 expansion and a 10 s deadline at most.
    let mut expansive = selector(4096);
    expansive["length"] = json!(16);
    let text = refusal(&path, expansive);
    assert!(text.contains("Raw decode:") && text.contains("128"), "{text}");
    let mut slow = selector(decoded);
    slow["decode"]["timeout_ms"] = json!(10_001);
    let text = refusal(&path, slow);
    assert!(text.contains("timeout_ms must be 1..=10000"), "{text}");
    // Record input states no byte range to decode.
    let mut records = selector(decoded);
    records["format"] = json!("ihex");
    for key in ["offset", "length", "base_address"] {
        records.as_object_mut().unwrap().remove(key);
    }
    assert!(refusal(&path, records).contains("base_address and decode"));
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
        ("list_strings", json!({ "contains": "fixture" })),
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
        (
            "evaluate_function",
            json!({ "at": format!("{:#x}", truth("checksum")), "args": [format!("{:#x}", truth("BANNER")), 27] }),
        ),
        ("check_claim", json!({ "claims": [{ "kind": "calls", "function": reset, "callee": "uart_puts" }] })),
        ("import_svd", json!({ "svd": svd("ARM_Example.svd"), "apply": true })),
        ("peripheral_access", json!({})),
        ("peripheral_map", json!({ "by_function": true })),
        ("list_patches", json!({})),
        ("patch_bytes", Value::Null),
        ("revert_patch", Value::Null),
        ("integrity_checks", json!({})),
        ("export_image", Value::Null),
        ("identify_functions", json!({})),
        ("lock_mechanisms", json!({})),
        ("function_summary", json!({ "at": reset })),
        ("find_crypto", json!({})),
        ("triage", json!({})),
        ("triage_report", json!({})),
        ("find_main", json!({})),
    ];
    assert_eq!(inputs.each_ref().map(|(name, _)| *name), RAW_CAPABLE_TOOLS);
    let export = owned.0.join("export.bin");
    let at = truth("uart_puts");
    let offset = (at - 0x0800_0000) as usize;
    let mut outcomes = Vec::new();
    for (name, input) in inputs {
        let input = reviewed_input(&project, name, at, &CORTEX_M[offset..offset + 2], &export).unwrap_or(input);
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
    // The Raw-only tools read the mapped regions at mapped addresses.
    assert!(outcome("function_summary").contains(&reset), "{}", outcome("function_summary"));
    assert!(outcome("triage").contains("Raw project (ARM:LE:32:Cortex)"), "{}", outcome("triage"));
    assert!(outcome("triage_report").contains("functions discovered"), "{}", outcome("triage_report"));
    // Strings among the flash code are listed at their mapped addresses when a NUL ends them.
    let strings: Value = serde_json::from_str(outcome("list_strings")).unwrap();
    assert_eq!(strings["items"][0]["text"], "rampage cortex-m fixture v1", "{strings}");
    assert_eq!(strings["items"][0]["address"], format!("{:#x}", truth("BANNER")), "{strings}");
    let (text, failed) = call_shared(&registry, &mut project, "list_strings", json!({ "limit": 100 }));
    assert!(!failed, "{text}");
    for expected in ["\"cmd> \"", "\"unknown command\"", "\"hard fault\"", "\"0123456789abcdef\""] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // ARM v8 Thumb with its reviewed C model decompiles the reset handler and names the analyst's callee.
    let decompiled = outcome("decompile");
    assert!(decompiled.contains("uart_puts(") && decompiled.contains("while"), "{decompiled}");
    // The image's own checksum routine runs over its banner string.
    let banner = b"rampage cortex-m fixture v1";
    let expected = banner.iter().fold(0x811c_9dc5u32, |sum, &byte| (sum ^ u32::from(byte)).wrapping_mul(0x0100_0193));
    let evaluated: Value = serde_json::from_str(outcome("evaluate_function")).unwrap();
    assert_eq!(evaluated["stop"], "returned", "{evaluated}");
    assert_eq!(evaluated["result"]["hex"], format!("{expected:#010x}"), "{evaluated}");
    // uart_putc polls the status register: it stops at the unmapped peripheral, and returns once mmio sets TXE.
    let putc = format!("{:#x}", truth("uart_putc"));
    let (text, failed) =
        call_shared(&registry, &mut project, "evaluate_function", json!({ "at": putc, "args": [0x41] }));
    assert!(!failed && text.contains("\"stop\":\"unmapped_read\""), "{text}");
    let input = json!({ "at": putc, "args": [0x41], "mmio": [{ "at": "0x40011000", "value": "0x80" }] });
    let (text, failed) = call_shared(&registry, &mut project, "evaluate_function", input);
    assert!(!failed && text.contains("\"stop\":\"returned\""), "{text}");
    assert_eq!(std::fs::read(&export).unwrap(), CORTEX_M);
    assert_eq!(owned.names(), ["export.bin", "firmware.bin"]);
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
    for absent in [json!(false), Value::Null] {
        let request: RawProjectRequest = serde_json::from_value(json!({
            "profile": "cortex-m", "offset": 0, "length": 2, "base_address": 0, "vector_table": absent
        }))
        .unwrap();
        assert!(request.vector_table.is_none(), "{absent}");
        let request: RawProjectRequest = serde_json::from_value(json!({
            "profile": "cortex-m", "offset": 0, "length": 2, "base_address": 0, "pointer_tables": absent
        }))
        .unwrap();
        assert_ne!(request.pointer_tables, Some(true), "{absent}");
    }
    let text = refusal(
        &path,
        json!({ "profile": "msp430", "offset": 0, "length": MSP430.len(), "base_address": "0x4400", "pointer_tables": true }),
    );
    assert!(text.contains("pointer-table seeding is defined only for ARM:LE:32:Cortex"), "{text}");
}

/// Thumb `movs rN, #imm` reads as a character and a register byte, and `movs r0, #0` as a NUL: a function of such
/// moves is a NUL-terminated printable run, which list_strings leaves out because discovered instructions cover it;
/// the same text after the function's return is a string.
#[test]
fn cortex_m_instruction_bytes_are_not_strings() {
    let mut bytes = vec![
        0x41, 0x21, 0x42, 0x22, 0x43, 0x23, 0x44, 0x24, // movs r1..r4, #'A'..'D': "A!B\"C#D$"
        0x00, 0x20, 0x70, 0x47, 0x00, 0x00, // movs r0, #0; bx lr; padding
    ];
    bytes.extend_from_slice(b"real text\0\0\0");
    let owned = OwnedDirectory::new();
    let path = owned.file("moves.bin", &bytes);
    let mut project = Session::default()
        .open_raw(
            &path,
            &request(
                json!({ "profile": "cortex-m3", "offset": 0, "length": bytes.len(), "base_address": 0, "entry": 0 }),
            ),
        )
        .unwrap();
    let (text, failed) = call_shared(&tools(), &mut project, "list_strings", json!({}));
    assert!(!failed, "{text}");
    assert!(text.contains("\"real text\"") && !text.contains("A!B"), "{text}");
}

/// An M-profile processor has no A32 state: `blx 0x14` (00 f0 08 e8) at the entry is UNDEFINED, not a call into A32
/// code, and the zero words at 0x14 list as Thumb (`movs r0, r0`), never as A32 (`andeq r0, r0, r0`).
#[test]
fn cortex_m_never_switches_to_a32() {
    let mut bytes = vec![0x00, 0xf0, 0x08, 0xe8];
    bytes.extend([0x00, 0xbf].repeat(6));
    bytes.extend([0x70, 0x47, 0x00, 0xbf]);
    bytes.extend([0; 12]);
    let owned = OwnedDirectory::new();
    let path = owned.file("blx.bin", &bytes);
    let mut project = Session::default()
        .open_raw(
            &path,
            &request(
                json!({ "profile": "cortex-m4", "offset": 0, "length": bytes.len(), "base_address": 0, "entry": 0 }),
            ),
        )
        .unwrap();
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    assert!(functions.items.iter().all(|function| function.address != 0x14), "{:?}", functions.items);
    let (text, failed) =
        call_shared(&tools(), &mut project, "disassemble", json!({ "at": "0x0", "count": 40, "view": "code" }));
    assert!(!failed, "{text}");
    assert!(!text.contains("blx") && !text.contains("andeq"), "{text}");
    assert!(text.contains("movs r0, r0"), "{text}");
}

const CORTEX_M_STRINGS: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-strings.bin");
const CORTEX_M_STRINGS_ELF: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-strings.elf");

/// zig packs "A", "Bc", "Cde" and "Defg" so that "Cde" and "Bc" start at odd addresses, which movw/movt form like
/// Thumb code pointers. Exactly the ELF's functions are found, no string.
#[test]
fn cortex_m_odd_string_literals_are_not_function_starts() {
    let owned = OwnedDirectory::new();
    let path = owned.file("strings.bin", CORTEX_M_STRINGS);
    let request = request(json!({
        "profile": "cortex-m3", "offset": 0, "length": CORTEX_M_STRINGS.len(), "base_address": "0x8000000",
        "vector_table": true,
    }));
    let project = Session::default().open_raw(&path, &request).unwrap();
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    let elf = rampage_loaders::Binary::open(CORTEX_M_STRINGS_ELF).unwrap();
    let mut truth: Vec<u64> = elf
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
        .map(|symbol| symbol.address & !1)
        .collect();
    truth.sort_unstable();
    assert_eq!(truth.len(), 6);
    assert_eq!(found, truth);
}

const CORTEX_M_TABLES: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-tables.bin");
const CORTEX_M_TABLES_ELF: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-tables.elf");

/// Precision and recall of discovery against the ELF's function symbols on an image whose handlers are reached
/// only through tables: with `pointer_tables` every function is found and nothing else; without it the record pass
/// finds the same handlers from the tables Reset addresses, and still nothing else.
#[test]
fn cortex_m_pointer_tables_recover_table_only_functions() {
    let owned = OwnedDirectory::new();
    let path = owned.file("tables.bin", CORTEX_M_TABLES);
    let elf = rampage_loaders::Binary::open(CORTEX_M_TABLES_ELF).unwrap();
    let mut truth: Vec<u64> = elf
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
        .map(|symbol| symbol.address & !1)
        .collect();
    truth.sort_unstable();
    assert_eq!(truth.len(), 18);
    let session = Session::default();
    let discover = |pointer_tables: bool| {
        let request = request(json!({
            "profile": "cortex-m0", "offset": 0, "length": CORTEX_M_TABLES.len(), "base_address": "0x8000000",
            "vector_table": true, "pointer_tables": pointer_tables,
        }));
        let project = session.open_raw(&path, &request).unwrap();
        let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
        let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
        let hits = found.iter().filter(|address| truth.contains(address)).count();
        (project, found.len(), hits)
    };
    let (_, without_found, without_hits) = discover(false);
    let scans = rampage_loaders::raw_pointers::scans_run();
    let (project, found, hits) = discover(true);
    // Every tool call reopens the request; the same bytes and mapping reuse the scan and the cached project.
    let (again, _, _) = discover(true);
    assert!(Arc::ptr_eq(&project, &again));
    assert_eq!(rampage_loaders::raw_pointers::scans_run(), scans + 1);
    // Without tables: Reset, the two other vector-table handlers and classify, which Reset calls, and every table
    // handler, from the records Reset addresses (each handler opens with push {..., lr}); the switch's case labels
    // and MAGIC's odd constants, which do not, are left out: precision 17/17, recall 17/18.
    assert_eq!((without_found, without_hits), (17, 17));
    // With them: precision 17/17, recall 17/18. The miss is run_command, which clang inlined into reset_handler and
    // nothing references; no seed can reach dead code.
    assert_eq!((found, hits), (17, 17));
    let elf_run_command = elf.symbol_by_name("run_command").unwrap().address & !1;
    let listed = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    assert!(listed.items.iter().all(|function| function.address != elf_run_command));
    let summary = serde_json::to_value(project.summary()).unwrap();
    let tables = &summary["raw"]["pointer_tables"];
    assert_eq!(tables["accepted_tables"], 2, "{tables:#}");
    assert_eq!(tables["refused_tables"], 2, "{tables:#}");
    assert_eq!(tables["tables"][0]["refused_reason"], "no_strong_evidence");
    assert_eq!(tables["tables"][1]["entries"][0]["evidence"], json!(["push_lr", "reaches_exit"]));
    // Two vector-table handlers besides Reset, the entry, and eleven table targets.
    assert_eq!(summary["raw"]["seed_count"], 13);
}

/// Four 4 MiB Cortex-M images would pin 16 MiB each time; the cache also bounds total input bytes, evicting the least
/// recently used.
#[test]
fn the_raw_cache_is_bounded_by_total_input_bytes() {
    let owned = OwnedDirectory::new();
    let size = rampage_loaders::MAX_RAW_NATIVE_BYTES;
    let session = Session::default();
    let count = rampage_api::MAX_RAW_PROJECT_BYTES / size;
    let paths: Vec<PathBuf> =
        (0..=count).map(|index| owned.file(&format!("image{index}.bin"), &vec![index as u8; size])).collect();
    let open = |path: &Path| {
        session
            .open_raw(
                path,
                &request(json!({ "profile": "cortex-m", "offset": 0, "length": size, "base_address": "0x8000000" })),
            )
            .unwrap()
    };
    let first = open(&paths[0]);
    for path in &paths[1..count] {
        open(path);
    }
    assert!(Arc::ptr_eq(&first, &open(&paths[0])), "still within the byte bound");
    let second = open(&paths[1]);
    // One more image passes the byte bound: the least recently used (paths[2]) goes, the reused ones stay.
    open(&paths[count]);
    assert!(Arc::ptr_eq(&first, &open(&paths[0])));
    assert!(Arc::ptr_eq(&second, &open(&paths[1])));
}

/// On Cortex-M Raw images a flash word the code reads through an address it forms stays a read (it is written by
/// whoever programs the image, not the compiler), while literal pools still fold; a store to a system register
/// before an endless loop is kept.
#[test]
fn cortex_m_decompilation_keeps_flash_data_reads_and_system_register_stores() {
    let firmware = |name: &str| {
        let path = project_path(name);
        let elf = rampage_loaders::Binary::open(path.with_extension("elf")).unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        let selector = json!({ "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000",
                               "vector_table": true });
        (Session::default().open_raw(&path, &request(selector)).unwrap(), elf)
    };
    let decompile = |project: &Arc<rampage_api::Project>, elf: &rampage_loaders::Binary, symbol: &str| {
        project.decompile(elf.symbol_by_name(symbol).unwrap().address & !1).unwrap().code
    };
    // reset_handler compares the application's CRC-32 with the word stored at 0x080007fc.
    let (project, elf) = firmware("raw-cortex-m-crc.bin");
    let code = decompile(&project, &elf, "reset_handler");
    let bytes = std::fs::read(project_path("raw-cortex-m-crc.bin")).unwrap();
    let stored = u32::from_le_bytes(bytes[0x7fc..0x800].try_into().unwrap());
    assert!(code.contains("code_80007fc"), "{code}");
    assert!(!code.contains(&format!("{stored:#x}")), "{code}");
    // system_reset requests a reset through SCB.AIRCR, then spins.
    let (project, elf) = firmware("raw-cortex-m-locks.bin");
    let code = decompile(&project, &elf, "system_reset");
    assert!(code.contains("ppb_e000ed0c = 0x5fa0004"), "{code}");
}

fn project_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware").join(name)
}

const CORTEX_M_RECORDS: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-records.bin");
const CORTEX_M_RECORDS_ELF: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-records.elf");

fn records_request() -> RawProjectRequest {
    request(json!({
        "profile": "cortex-m4", "offset": 0, "length": CORTEX_M_RECORDS.len(), "base_address": "0x8000000",
        "vector_table": true,
    }))
}

fn elf_symbol(path: &str, name: &str) -> u64 {
    let elf = rampage_loaders::Binary::open(path).unwrap();
    elf.symbols.iter().find(|symbol| symbol.name == name).unwrap_or_else(|| panic!("no {name}")).address & !1
}

/// Fifth Haiku run: `xrefs` on the updater's error strings returned nothing, because the code that loads them was
/// reached only through an RTOS thread-definition record. Discovery now follows code pointers in records the code
/// addresses, so the worker task is found, and xrefs, `references` search and `functions_referencing` agree on the
/// function loading each string by a literal-pool word, a movw/movt pair or adr.
#[test]
fn cortex_m_strings_loaded_from_record_reached_code_have_xrefs() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let mut project = Session::default().open_raw(&path, &records_request()).unwrap();
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let found: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    let worker = elf_symbol(CORTEX_M_RECORDS_ELF, "worker_task");
    assert!(found.contains(&worker), "the task named only by its record is a function: {found:x?}");
    let registry = tools();
    for (text, loader) in
        [("image sum err", "check_sum"), ("HEADER ERROR", "report_header"), ("COMPARE ERROR", "compare_error_text")]
    {
        let string = CORTEX_M_RECORDS.windows(text.len()).position(|window| window == text.as_bytes()).unwrap();
        let string = 0x0800_0000 + string as u64;
        let loader = elf_symbol(CORTEX_M_RECORDS_ELF, loader);
        let xrefs = project.xrefs(rampage_api::XrefQuery::To(string), None, None).unwrap();
        let from: Vec<u64> =
            xrefs.items.iter().filter_map(|row| project.function_containing(row.from).unwrap()).collect();
        assert_eq!(from, [loader], "{text}: {:?}", xrefs.items);
        let (references, failed) = call_shared(
            &registry,
            &mut project,
            "search",
            json!({ "mode": { "kind": "references", "target": format!("{string:#x}") } }),
        );
        assert!(!failed && references.contains(&format!("\"address\":\"{loader:#x}\"")), "{text}: {references}");
        let (referencing, failed) = call_shared(
            &registry,
            &mut project,
            "search",
            json!({ "mode": { "kind": "functions_referencing",
                              "reference": { "kind": "string", "text": text, "encoding": "utf8" } } }),
        );
        assert!(!failed && referencing.contains(&format!("\"address\":\"{loader:#x}\"")), "{text}: {referencing}");
    }
}

fn find_main(project: &mut Arc<rampage_api::Project>) -> Value {
    let (text, failed) = call_shared(&tools(), project, "find_main", json!({ "decompile": false }));
    assert!(!failed, "{text}");
    serde_json::from_str(&text).unwrap()
}

/// Fifth Haiku run: find_main refused Raw projects. On Cortex-M the reset handler is followed past the C runtime
/// init (copy and zero loops, the init-hook walk) to the first call that never returns: main, which starts the
/// scheduler.
#[test]
fn cortex_m_find_main_follows_the_reset_handler_past_the_runtime_init() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let mut project = Session::default().open_raw(&path, &records_request()).unwrap();
    let report = find_main(&mut project);
    let candidate = &report["sections"][0]["findings"][0];
    let main = elf_symbol(CORTEX_M_RECORDS_ELF, "main");
    assert_eq!(candidate["address"], format!("{main:#x}"), "{report:#}");
    assert_eq!(candidate["confidence"], "medium", "{report:#}");
    let evidence = candidate["evidence"].to_string();
    assert!(evidence.contains("calls through a table in a loop") && evidence.contains("ICSR"), "{evidence}");
    assert!(report["limitations"].to_string().contains("Raw Cortex-M"), "{report:#}");
}

/// After scatter-load's jump into copied code, the copied function that loops forever is main.
#[test]
fn cortex_m_find_main_takes_the_code_scatter_load_jumps_into() {
    let owned = OwnedDirectory::new();
    let bytes = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-scatter-gcc.bin");
    let path = owned.file("scatter.bin", bytes);
    let request = request(json!({
        "profile": "cortex-m4", "offset": 0, "length": bytes.len(), "base_address": "0x8000000", "vector_table": true,
    }));
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let report = find_main(&mut project);
    let candidate = &report["sections"][0]["findings"][0];
    let elf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-scatter-gcc.elf");
    assert_eq!(candidate["address"], format!("{:#x}", elf_symbol(elf, "ram_main")), "{report:#}");
    assert_eq!(candidate["confidence"], "medium", "{report:#}");
    assert!(candidate["evidence"].to_string().contains("scatter-load follows the reset code"), "{report:#}");
}

/// A reset handler that calls a few functions and then loops itself, with no runtime init, has no main to claim.
#[test]
fn cortex_m_find_main_claims_nothing_without_startup_evidence() {
    let owned = OwnedDirectory::new();
    let path = owned.file("strings.bin", CORTEX_M_STRINGS);
    let request = request(json!({
        "profile": "cortex-m3", "offset": 0, "length": CORTEX_M_STRINGS.len(), "base_address": "0x8000000",
        "vector_table": true,
    }));
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let report = find_main(&mut project);
    assert_eq!(report["sections"][0]["total"], 0, "{report:#}");
    assert!(report["summary"][0].as_str().unwrap().starts_with("No main candidate found"), "{report:#}");
}

/// Fifth Haiku run: `decompile` with `exact_entry` refused ARM. On a Raw Cortex-M project it decompiles an asserted
/// Thumb start, here a CRC routine nothing calls directly, with flash literals folded as plain decompile does.
#[test]
fn cortex_m_exact_entry_decompiles_an_asserted_thumb_start() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    // pointer_tables false: discovery stays lazy and no inferred CRC seed is added, so nothing seeds the routine.
    let request = request(json!({
        "profile": "cortex-m4", "offset": 0, "length": CORTEX_M_RECORDS.len(), "base_address": "0x8000000",
        "vector_table": true, "pointer_tables": false,
    }));
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let crc = elf_symbol(CORTEX_M_RECORDS_ELF, "crc32_update");
    assert_eq!(project.function_containing(crc).unwrap(), None, "nothing discovered the routine");
    let registry = tools();
    let (text, failed) = call_shared(
        &registry,
        &mut project,
        "decompile",
        json!({ "at": format!("{crc:#x}"), "exact_entry": true, "view": "code" }),
    );
    assert!(!failed, "{text}");
    assert!(text.contains("0xedb88320"), "{text}");
    let (text, failed) = call_shared(
        &registry,
        &mut project,
        "decompile",
        json!({ "at": format!("{:#x}", crc | 1), "exact_entry": true, "view": "code" }),
    );
    // Seventh Haiku run: an address copied with its Thumb bit was refused. It names the code at the even address.
    assert!(!failed && text.contains("0xedb88320"), "{text}");
    assert!(text.contains("has bit 0 set") && text.contains(&format!("Thumb code at {crc:#x}")), "{text}");
    let (text, failed) =
        call_shared(&registry, &mut project, "disassemble", json!({ "at": format!("{:#x}", crc | 1) }));
    assert!(!failed && text.contains(&format!("\"address\":\"{crc:#x}\"")), "{text}");
}

/// Fifth Haiku run: integrity_checks inferred a CRC routine from its polynomial literal, but it was no function, so
/// decompile and lock_mechanisms never saw it. The session now seeds such starts, with the evidence, and reports them.
#[test]
fn cortex_m_inferred_crc_routines_are_seeded_into_discovery() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let session = Session::default();
    let mut project = session.open_raw(&path, &records_request()).unwrap();
    let crc = elf_symbol(CORTEX_M_RECORDS_ELF, "crc32_update");
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    assert!(functions.items.iter().any(|function| function.address == crc), "{:?}", functions.items);
    let summary = serde_json::to_value(project.summary()).unwrap();
    let seeds = &summary["raw"]["inferred_seeds"];
    assert_eq!(seeds[0]["address"], format!("{crc:#x}"), "{summary:#}");
    assert!(seeds[0]["reason"].as_str().unwrap().contains("polynomial 0xedb88320"), "{seeds:#}");
    // Seventh Haiku run: `xrefs` to the inferred routine was empty because its caller was undiscovered too. The
    // checker that calls it with `bl` is seeded after it, so the call is a reference now.
    let verify = elf_symbol(CORTEX_M_RECORDS_ELF, "verify_image");
    assert_eq!(seeds[1]["address"], format!("{verify:#x}"), "{summary:#}");
    assert!(seeds[1]["reason"].as_str().unwrap().contains("calls the inferred routine"), "{seeds:#}");
    let callers = project.xrefs(rampage_api::XrefQuery::To(crc), None, None).unwrap();
    let call = callers.items.iter().find(|row| row.from >= verify && row.from < verify + 0x20);
    assert_eq!(call.map(|row| row.from_function.clone()), Some(Some(format!("sub_{verify:x}"))), "{callers:?}");
    // The same request finds the same seeded project.
    assert!(Arc::ptr_eq(&project, &session.open_raw(&path, &records_request()).unwrap()));
    let registry = tools();
    let (text, failed) = call_shared(&registry, &mut project, "integrity_checks", json!({}));
    assert!(!failed, "{text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    let routine =
        report["routines"].as_array().unwrap().iter().find(|routine| routine["address"] == format!("{crc:#x}"));
    let routine = routine.unwrap_or_else(|| panic!("{report:#}"));
    assert!(routine.get("inferred_range").is_none(), "a discovered function now: {routine:#}");
    let decompiled = project.decompile(crc).unwrap();
    assert!(decompiled.code.contains("0xedb88320"), "{}", decompiled.code);
    let (text, failed) = call_shared(&registry, &mut project, "lock_mechanisms", json!({}));
    assert!(!failed, "{text}");
    // The seeded CRC routine is evidence that selects functions for analysis.
    let report: Value = serde_json::from_str(&text).unwrap();
    assert!(report["coverage"]["functions_analyzed"].as_u64().unwrap() > 0, "{report:#}");
    assert!(
        report["coverage"]["functions_discovered"].as_u64() >= report["coverage"]["functions_analyzed"].as_u64(),
        "{report:#}"
    );
    // Seventh Haiku run: `xrefs` to an address inside a string was a bare empty list. It names the string's start.
    let header = elf_symbol(CORTEX_M_RECORDS_ELF, "header_error");
    let (text, failed) = call_shared(&registry, &mut project, "xrefs", json!({ "to": format!("{:#x}", header + 2) }));
    assert!(!failed, "{text}");
    assert!(text.contains(&format!("lies 2 bytes into the string \\\"HEADER ERROR\\\" at {header:#x}")), "{text}");
    assert!(text.contains("pointers or computed addresses"), "{text}");
    // An address with the Thumb bit names the Thumb code in every tool that takes it, with a note saying so.
    let odd = format!("{:#x}", crc | 1);
    for (tool, input) in [
        ("function_summary", json!({ "at": odd, "view": "summary" })),
        ("function_graph", json!({ "at": odd, "view": "summary" })),
        ("disassemble", json!({ "at": odd, "count": 2 })),
        ("xrefs", json!({ "from": odd })),
    ] {
        let (text, failed) = call_shared(&registry, &mut project, tool, input);
        assert!(!failed && text.contains(&format!("read as the Thumb code at {crc:#x}")), "{tool}: {text}");
    }
}

/// Review of the seventh run's fixes: the Thumb-bit reading and the undiscovered-`bl` scan are for Thumb code
/// only. An odd x86 address is untouched; an odd address in A32 code is used as given, with a note; and an empty
/// `xrefs` on an A32 image names no Thumb `bl` sites.
#[test]
fn thumb_bit_and_bl_notes_stay_out_of_non_thumb_code() {
    let fixture = |name: &str| format!("{}/../../tests/fixtures/bin/{name}", env!("CARGO_MANIFEST_DIR"));
    let session = Session::default();
    let x64 = session.open(Path::new(&fixture("hello-x64.elf")), None).unwrap();
    let entry = x64.binary.entry.unwrap();
    assert_eq!(x64.thumb_code_address(entry | 1), (entry | 1, None));

    let mut arm = session.open(Path::new(&fixture("hello-arm.elf")), None).unwrap();
    assert!(arm.binary.thumb.is_empty() && !arm.binary.m_profile());
    let entry = arm.binary.entry.unwrap();
    let (address, note) = arm.thumb_code_address(entry | 1);
    assert_eq!(address, entry | 1);
    assert!(note.unwrap().contains("not known to be Thumb"));
    let registry = tools();
    let (text, failed) = call_shared(&registry, &mut arm, "xrefs", json!({ "to": format!("{:#x}", entry + 4) }));
    assert!(!failed && text.contains("\"notes\"") && !text.contains("Thumb `bl`"), "{text}");
}

/// Seventh Haiku run: `search` for the functions referencing a CRC polynomial ran out of match work a tenth into a
/// Thumb image and could not have matched anyway: ARM has no typed operands, and the polynomial sits in a literal
/// pool. Literal-pool loads and MOVW/MOVT pairs now match as `loaded_constant`; the result stays a lower bound,
/// since compilers build constants other ways too (review: shift-and-add and split `add.w` sequences).
#[test]
fn cortex_m_constant_search_matches_literal_pool_loads_as_a_lower_bound() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let mut project = Session::default().open_raw(&path, &records_request()).unwrap();
    let registry = tools();
    let search = |project: &mut Arc<rampage_api::Project>, value: u64, kind: &str| {
        let mode = json!({ "kind": kind, "immediate": { "value": { "kind": "unsigned", "value": value } } });
        let mode = if kind == "functions_referencing" {
            json!({ "kind": kind, "reference": { "kind": "constant", "immediate": mode["immediate"] } })
        } else {
            mode
        };
        let (text, failed) = call_shared(&registry, project, "search", json!({ "mode": mode }));
        assert!(!failed, "{text}");
        serde_json::from_str::<Value>(&text).unwrap()
    };
    let crc = elf_symbol(CORTEX_M_RECORDS_ELF, "crc32_update");
    let report = search(&mut project, 0xedb8_8320, "functions_referencing");
    assert_eq!(report["hits"][0]["address"], format!("{crc:#x}"), "{report:#}");
    assert_eq!(report["total_is_exact"], false, "{report:#}");
    // A MOVW/MOVT pair builds the header string's address.
    let header = elf_symbol(CORTEX_M_RECORDS_ELF, "header_error");
    let report = search(&mut project, header, "immediate");
    let report_header = elf_symbol(CORTEX_M_RECORDS_ELF, "report_header");
    let hit = &report["hits"][0];
    assert_eq!(hit["function"]["address"], format!("{report_header:#x}"), "{report:#}");
    assert_eq!(hit["code"]["native"]["kind"], "loaded_constant", "{report:#}");

    // Review: a function building 0x12034 with `movs; lsls; adds` and 0x12340 with two `add.w` has no literal or
    // MOVW/MOVT, so nothing matches, and the empty result must not claim to be exact.
    let mut image = vec![0u8; 512];
    image[..8].copy_from_slice(&[0x00, 0x10, 0x00, 0x20, 0x41, 0x00, 0x00, 0x08]);
    let code =
        [0x10, 0xb5, 0x12, 0x20, 0x00, 0x03, 0x34, 0x30, 0x00, 0xf5, 0x90, 0x30, 0x00, 0xf5, 0x50, 0x70, 0x10, 0xbd];
    image[0x40..0x40 + code.len()].copy_from_slice(&code);
    let path = owned.file("built.bin", &image);
    let request = request(json!({
        "profile": "cortex-m3", "offset": 0, "length": image.len(), "base_address": "0x8000000",
        "vector_table": true,
    }));
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    for value in [0x12034, 0x12340] {
        let report = search(&mut project, value, "immediate");
        assert_eq!((&report["total"], &report["total_is_exact"]), (&json!(0), &json!(false)), "{report:#}");
    }
}

/// Fifth Haiku run: an image that starts with code was read as a vector table and its first word reported as the
/// stack pointer. The candidate is now refused as a whole, with the reason and what to do; nothing is seeded.
#[test]
fn cortex_m_code_read_as_a_vector_table_is_refused() {
    let owned = OwnedDirectory::new();
    // The records fixture from its first function on: Thumb code where a table would be.
    let code = &CORTEX_M_RECORDS[0x40..];
    let path = owned.file("code.bin", code);
    let code_first = request(json!({
        "profile": "cortex-m4", "offset": 0, "length": code.len(), "base_address": "0x8000040", "vector_table": true,
        "pointer_tables": false,
    }));
    let project = Session::default().open_raw(&path, &code_first).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let table = &summary["raw"]["vector_table"];
    let reason = table["refused_reason"].as_str().unwrap_or_else(|| panic!("{table:#}"));
    assert!(reason.starts_with("not a reset vector table") && reason.contains("give entry"), "{reason}");
    assert!(summary["entry"].is_null(), "{summary:#}");
    assert_eq!(summary["raw"]["seed_count"], 0, "{summary:#}");
    // binary_info's warnings and list_functions' next say so where an agent reads first: set entry, drop
    // vector_table.
    let warnings = summary["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{summary:#}");
    let warning = warnings[0].as_str().unwrap();
    assert!(warning.starts_with("the vector table at 0x8000040 was refused (not a reset vector table"), "{warning}");
    assert!(warning.contains("the project has no entry"), "{warning}");
    assert!(
        warning.ends_with(
            "reopen without \"vector_table\" and give \"entry\" (its first instruction; 0x8000040 when \
                           the code starts at the base)"
        ),
        "{warning}"
    );
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    let next = page["next"].as_str().unwrap_or_else(|| panic!("{page:#}"));
    assert!(next.starts_with("The vector table at 0x8000040 was refused") && next.contains("give \"entry\""), "{next}");
    // Given an entry, the warning says only to drop vector_table, and list_functions' pages carry no next.
    let with_entry = request(json!({
        "profile": "cortex-m4", "offset": 0, "length": code.len(), "base_address": "0x8000040", "vector_table": true,
        "pointer_tables": false, "entry": "0x8000040",
    }));
    let project = Session::default().open_raw(&path, &with_entry).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let warning = summary["warnings"][0].as_str().unwrap();
    assert!(
        warning.ends_with("the entry, 0x8000040, is used: reopen without \"vector_table\" to drop the refused table"),
        "{warning}"
    );
    assert!(!warning.contains("give \"entry\""), "{warning}");
    let page = serde_json::to_value(project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap()).unwrap();
    assert!(page.get("next").is_none_or(Value::is_null), "{page:#}");
    // The real table is still accepted.
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let project = Session::default().open_raw(&path, &records_request()).unwrap();
    let summary = serde_json::to_value(project.summary()).unwrap();
    assert!(summary["raw"]["vector_table"].get("refused_reason").is_none(), "{summary:#}");
    assert_eq!(summary["entry"], format!("{:#x}", elf_symbol(CORTEX_M_RECORDS_ELF, "reset_handler")));
    assert_eq!(summary["warnings"], json!([]), "{summary:#}");
}

/// The starting points binary_info lists, as (address, reasons joined).
fn starting_points(project: &rampage_api::Project) -> Vec<(u64, String)> {
    let summary = serde_json::to_value(project.summary()).unwrap();
    summary["raw"]["starting_points"]
        .as_array()
        .unwrap_or_else(|| panic!("{summary:#}"))
        .iter()
        .map(|point| {
            let address = u64::from_str_radix(point["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            (address, point["reasons"].to_string())
        })
        .collect()
}

/// Run-to-run variance in the Haiku runs came from where each run started reading. binary_info now names the first
/// functions worth reading: the reset handler, find_main's candidate, the init routines the startup calls through
/// its table, and the CRC routine integrity_checks infers.
#[test]
fn cortex_m_binary_info_names_the_starting_points() {
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", CORTEX_M_RECORDS);
    let project = Session::default().open_raw(&path, &records_request()).unwrap();
    let points = starting_points(&project);
    let reason = |name: &str| {
        let address = elf_symbol(CORTEX_M_RECORDS_ELF, name);
        points.iter().find(|(at, _)| *at == address).map(|(_, reasons)| reasons.clone())
    };
    assert!(reason("reset_handler").unwrap().contains("reset handler"), "{points:?}");
    assert!(reason("main").unwrap().contains("find_main (medium confidence)"), "{points:?}");
    for init in ["init_uart", "init_timer"] {
        assert!(reason(init).unwrap().contains("init routines the startup calls through the table"), "{points:?}");
    }
    assert!(reason("crc32_update").unwrap().contains("raw.inferred_seeds"), "{points:?}");
    assert!(points.len() <= 8);
}

/// After scatter-load's jump, the copied function it lands in is named, with why.
#[test]
fn cortex_m_binary_info_names_the_scatter_jump_target() {
    let owned = OwnedDirectory::new();
    let bytes = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-scatter-gcc.bin");
    let path = owned.file("scatter.bin", bytes);
    let request = request(json!({
        "profile": "cortex-m4", "offset": 0, "length": bytes.len(), "base_address": "0x8000000", "vector_table": true,
    }));
    let project = Session::default().open_raw(&path, &request).unwrap();
    let points = starting_points(&project);
    let elf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-scatter-gcc.elf");
    let ram_main = elf_symbol(elf, "ram_main");
    let (_, reasons) = points.iter().find(|(at, _)| *at == ram_main).unwrap_or_else(|| panic!("{points:?}"));
    assert!(reasons.contains("scatter-load's jump") && reasons.contains("find_main"), "{reasons}");
}

/// A Thumb `bl` from `pc` to `target`.
fn thumb_bl(pc: u64, target: u64) -> [u8; 4] {
    let offset = target.wrapping_sub(pc + 4) as u32;
    let s = (offset >> 24) & 1;
    let (i1, i2) = ((offset >> 23) & 1, (offset >> 22) & 1);
    let (j1, j2) = ((1 - i1) ^ s, (1 - i2) ^ s);
    let first = 0xf000 | (s << 10) | ((offset >> 12) & 0x3ff);
    let second = 0xd000 | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x7ff);
    let mut bytes = [0; 4];
    bytes[..2].copy_from_slice(&(first as u16).to_le_bytes());
    bytes[2..].copy_from_slice(&(second as u16).to_le_bytes());
    bytes
}

/// Review of the find_main follow: three functions of `fan` calls each, each calling the next level `fan` times.
/// Unmemoised, judging whether calls return grew as fan³ (80 calls took 29 s in a debug build); each verdict is
/// now computed once per depth, within an instruction budget, and binary_info's starting points once per project.
#[test]
fn cortex_m_find_main_stays_bounded_on_a_fan_of_calls() {
    let fan = 80u64;
    let base = 0x0800_0000u64;
    let mut image = vec![0u8; 0x40];
    image[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
    image[4..8].copy_from_slice(&((base + 0x41) as u32).to_le_bytes());
    let size = 4 + 4 * fan;
    let starts = [0x40, 0x40 + size, 0x40 + 2 * size, 0x40 + 3 * size];
    for level in 0..3 {
        let mut code = vec![0x00, 0xb5]; // push {lr}
        for _ in 0..fan {
            let pc = base + starts[level] + code.len() as u64;
            code.extend(thumb_bl(pc, base + starts[level + 1]));
        }
        code.extend([0x00, 0xbd]); // pop {pc}
        while code.len() % 4 != 0 {
            code.extend([0x00, 0xbf]);
        }
        image.extend(code);
    }
    image.extend([0x70, 0x47, 0x00, 0xbf]);
    let owned = OwnedDirectory::new();
    let path = owned.file("fan.bin", &image);
    let request = request(json!({
        "profile": "cortex-m", "offset": 0, "length": image.len(), "base_address": "0x8000000", "vector_table": true,
    }));
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let started = std::time::Instant::now();
    find_main(&mut project);
    for _ in 0..3 {
        serde_json::to_value(project.summary()).unwrap();
    }
    let elapsed = started.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(3), "{elapsed:?}");
}

/// Review of the record pass: many records of pointers into a run of `nop`s (each decodes, none reaches an exit,
/// alternating with zero words so no array filter applies), plus a chain of records each found one round later.
/// Rounds stay at most three, the record words and decodes stay within the shared budget, and the pass says so.
#[test]
fn cortex_m_record_pass_work_is_bounded() {
    let base = 0x0800_0000u64;
    let records = 2000u64;
    let chain = 4u64;
    let load = |address: u64| {
        // ldr r0, [pc, #0]; b.n +2; .word address
        let mut bytes = vec![0x00, 0x48, 0x01, 0xe0];
        bytes.extend((address as u32).to_le_bytes());
        bytes
    };
    let reset = 0x40u64;
    let code_len = 4 + 8 * (records + 1) + 4;
    let functions = reset + code_len;
    let chain_records = functions + 16 * chain;
    let plain_records = chain_records + 64 * (chain + 1);
    let sled = plain_records + 64 * records;
    let mut image = vec![0u8; 0x40];
    image[..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
    image[4..8].copy_from_slice(&((base + reset + 1) as u32).to_le_bytes());
    image.extend([0x00, 0xb5, 0x00, 0xbf]);
    for index in 0..records {
        image.extend(load(base + plain_records + 64 * index));
    }
    image.extend(load(base + chain_records));
    image.extend([0x00, 0xbd, 0x00, 0xbf]);
    assert_eq!(image.len() as u64, functions);
    for link in 0..chain {
        image.extend([0x00, 0xb5, 0x00, 0xbf]);
        image.extend(load(base + chain_records + 64 * (link + 1)));
        image.extend([0x00, 0xbd, 0x00, 0xbf]);
    }
    for link in 0..=chain {
        let mut record = [0u32; 16];
        if link < chain {
            record[0] = (base + functions + 16 * link + 1) as u32;
        }
        image.extend(record.iter().flat_map(|word| word.to_le_bytes()));
    }
    let mut target = 0u64;
    for _ in 0..records {
        let mut record = [0u32; 16];
        for slot in (0..16).step_by(2) {
            record[slot] = (base + sled + 2 * target + 1) as u32;
            target += 1;
        }
        image.extend(record.iter().flat_map(|word| word.to_le_bytes()));
    }
    for _ in 0..(target + 256) {
        image.extend([0x00, 0xbf]);
    }
    let owned = OwnedDirectory::new();
    let path = owned.file("records.bin", &image);
    let request = request(json!({
        "profile": "cortex-m", "offset": 0, "length": image.len(), "base_address": "0x8000000", "vector_table": true,
    }));
    let started = std::time::Instant::now();
    let project = Session::default().open_raw(&path, &request).unwrap();
    let elapsed = started.elapsed();
    let summary = serde_json::to_value(project.summary()).unwrap();
    let record = &summary["raw"]["record_seeds"];
    assert!(record["rounds"].as_u64().unwrap() <= 3, "{record:#}");
    assert!(record["work"].as_u64().unwrap() <= 1_000_000, "{record:#}");
    assert_eq!(record["truncated"], true, "{record:#}");
    // The chain's first links are found, one round each, up to the round bound.
    let functions_found = project.functions(&rampage_api::FunctionsQuery::default()).unwrap().total;
    assert!((3..=6).contains(&functions_found), "{functions_found}");
    assert!(elapsed < std::time::Duration::from_secs(60), "{elapsed:?}");
}
