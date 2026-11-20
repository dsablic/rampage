//! check_claim on committed fixtures: each claim kind verified, refuted and left unknown, adversarial near misses
//! (CRC variants one parameter apart, expressions that agree on common inputs only, calls through pointers), and
//! the evaluation-backed kinds across Cortex-M (Raw and ELF), x86, x86-64, 32-bit ARM, MIPS and Xtensa.

use std::sync::Arc;

use rampage_api::{Project, RawProjectRequest, Session};
use rampage_loaders::Binary;
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/");

fn open(path: &str) -> Arc<Project> {
    Arc::new(Project::new(Binary::open(format!("{FIXTURES}{path}")).unwrap()))
}

fn symbol(path: &str, name: &str) -> String {
    let binary = Binary::open(format!("{FIXTURES}{path}")).unwrap();
    let address = binary.symbol_by_name(name).unwrap_or_else(|| panic!("{path}: no {name}")).address;
    format!("{:#x}", address & if binary.arch == rampage_arch::Arch::Arm { !1 } else { !0 })
}

/// The Raw Cortex-M3 CRC image (tests/fixtures/firmware/raw-cortex-m-crc.c), with its ELF as the truth.
fn cortex_m() -> Arc<Project> {
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": 0x800, "base_address": "0x8000000", "vector_table": true
    }))
    .unwrap();
    let path = std::path::PathBuf::from(format!("{FIXTURES}firmware/raw-cortex-m-crc.bin"));
    Session::default().open_raw(&path, &request).unwrap()
}

fn cm(name: &str) -> String {
    symbol("firmware/raw-cortex-m-crc.elf", name)
}

fn check_all(project: &Arc<Project>, claims: Vec<Value>) -> Vec<Value> {
    let report = project.check_claims(&claims, None).unwrap();
    let report = serde_json::to_value(report).unwrap();
    report["results"].as_array().unwrap().clone()
}

fn check(project: &Arc<Project>, claim: Value) -> Value {
    check_all(project, vec![claim]).remove(0)
}

#[track_caller]
fn verdict(result: &Value, expected: &str) {
    assert_eq!(result["verdict"], expected, "{result:#}");
}

#[test]
fn computes_tells_crc32_from_its_near_misses_on_cortex_m() {
    let project = cortex_m();
    let crc = cm("crc32_compute");
    let result = check(&project, json!({"kind": "computes", "function": crc, "algorithm": "crc32"}));
    verdict(&result, "verified");
    assert_eq!(result["confidence"], "sampled");
    assert_eq!(result["evidence"]["samples"], 16);
    let lengths = result["evidence"]["lengths"].as_array().unwrap();
    assert!(lengths.contains(&json!(0)) && lengths.contains(&json!(1024)), "{result:#}");
    // One parameter away each: another polynomial, unreflected, no final XOR, another initial value.
    for algorithm in [
        json!("crc32c"),
        json!("crc32_bzip2"),
        json!("crc32_jamcrc"),
        json!({"crc": {"width": 32, "poly": "0x04c11db7", "init": "0xfffffffe", "refin": true, "xorout": "0xffffffff"}}),
        json!({"crc": {"width": 32, "poly": "0x04c11db5", "init": "0xffffffff", "refin": true, "xorout": "0xffffffff"}}),
        json!("crc16_arc"),
    ] {
        let result = check(&project, json!({"kind": "computes", "function": crc, "algorithm": algorithm}));
        verdict(&result, "refuted");
        let counterexample = &result["evidence"]["counterexample"];
        assert_ne!(counterexample["expected"], counterexample["actual"], "{result:#}");
        assert_eq!(result["confidence"], "exact");
    }
    // Negated: "crc32_compute does not compute CRC-32C" holds.
    let result = check(&project, json!({"kind": "computes", "function": crc, "algorithm": "crc32c", "not": true}));
    verdict(&result, "verified");
    assert_eq!(result["negated"], true);
}

#[test]
fn expressions_agreeing_on_common_inputs_are_refuted_by_the_edge_cases() {
    let project = cortex_m();
    let scale = cm("app_scale");
    verdict(&check(&project, json!({"kind": "computes", "function": scale, "expression": "x*5+3"})), "verified");
    for wrong in ["x*5+4", "(x*5+3) & 0x7fffffff", "min(x, 0x10000000)*5+3", "ite(x == 0xffffffff, 0, x*5+3)"] {
        let result = check(&project, json!({"kind": "computes", "function": scale, "expression": wrong}));
        verdict(&result, "refuted");
        assert!(result["evidence"]["counterexample"]["args"].is_array(), "{result:#}");
    }
    // At 8 bits the low byte is all that is compared, and it holds.
    let result = check(&project, json!({"kind": "computes", "function": scale, "expression": "x*5+3", "bits": 8}));
    verdict(&result, "verified");
}

#[test]
fn returns_compares_exactly_and_explains_a_stop() {
    let project = cortex_m();
    let scale = cm("app_scale");
    let results = check_all(
        &project,
        vec![
            json!({"kind": "returns", "function": scale, "args": [2], "value": 13}),
            json!({"kind": "returns", "function": scale, "args": [2], "value": "0xe"}),
            json!({"kind": "returns", "function": cm("crc32_compute"),
                   "args": [{"buffer": {"text": "123456789"}}, 9], "value": "0xcbf43926"}),
            // app_main never returns: the run stops at the step budget.
            json!({"kind": "returns", "function": cm("app_main"), "value": 0, "max_steps": 2000,
                   "mmio": [{"at": "0x40020014", "value": 0}]}),
            json!({"kind": "returns", "function": scale, "value": 1, "bits": 7}),
            json!({"kind": "frobnicates"}),
        ],
    );
    verdict(&results[0], "verified");
    verdict(&results[1], "refuted");
    assert_eq!(results[1]["evidence"]["result"], "0xd");
    verdict(&results[2], "verified");
    verdict(&results[3], "unknown");
    assert!(results[3]["needs"].as_str().unwrap().contains("max_steps"), "{:#}", results[3]);
    verdict(&results[4], "invalid");
    verdict(&results[5], "invalid");
}

#[test]
fn region_recomputes_a_stored_crc_and_consults_detected_checks() {
    let project = cortex_m();
    let claim = |algorithm: &str, stored: Option<&str>| {
        let mut claim = json!({"kind": "region", "start": "0x8000400", "end": "0x80007fc", "algorithm": algorithm});
        if let Some(stored) = stored {
            claim["stored"] = json!(stored);
        }
        claim
    };
    let results = check_all(
        &project,
        vec![
            claim("crc32", Some("0x80007fc")),
            claim("crc32c", Some("0x80007fc")),
            claim("crc32", None),
            json!({"kind": "region", "start": "0x8000400", "end": "0x80007f8", "algorithm": "crc32",
                   "stored": "0x80007fc"}),
            json!({"kind": "region", "start": "0x8000000", "end": "0x8000100", "algorithm": "crc32"}),
        ],
    );
    verdict(&results[0], "verified");
    assert_eq!(results[0]["evidence"]["stored"], results[0]["evidence"]["computed"]);
    verdict(&results[1], "refuted");
    verdict(&results[2], "verified");
    verdict(&results[3], "refuted");
    verdict(&results[4], "unknown");
}

#[test]
fn calls_follow_the_call_graph_and_order_on_cortex_m() {
    let project = cortex_m();
    let reset = cm("reset_handler");
    let results = check_all(
        &project,
        vec![
            json!({"kind": "calls", "function": reset, "callee": cm("crc32_compute")}),
            json!({"kind": "calls", "function": cm("default_handler"), "callee": cm("crc32_compute")}),
            json!({"kind": "calls", "function": reset, "callee": cm("app_scale")}),
            json!({"kind": "calls", "function": reset, "callee": cm("app_scale"), "depth": 2}),
            json!({"kind": "calls", "function": reset, "callee": cm("crc32_compute"), "before": cm("app_main")}),
            json!({"kind": "calls", "function": reset, "callee": cm("app_main"), "before": cm("crc32_compute")}),
            json!({"kind": "calls", "function": cm("crc32_compute") , "callee": cm("app_main"), "not": true}),
        ],
    );
    verdict(&results[0], "verified");
    assert_eq!(results[0]["confidence"], "static");
    verdict(&results[1], "refuted");
    verdict(&results[2], "refuted");
    verdict(&results[3], "verified");
    assert_eq!(results[3]["evidence"]["chain"].as_array().unwrap().len(), 2, "{:#}", results[3]);
    verdict(&results[4], "verified");
    verdict(&results[5], "refuted");
    verdict(&results[6], "verified");
}

#[test]
fn constants_on_arm_are_lower_bounds() {
    let project = cortex_m();
    let crc = cm("crc32_compute");
    let found = check(&project, json!({"kind": "constant", "function": crc, "value": "0xedb88320"}));
    verdict(&found, "verified");
    assert!(!found["evidence"]["sites"].as_array().unwrap().is_empty());
    // Absent on ARM: the search is a lower bound, so it cannot refute.
    let absent = check(&project, json!({"kind": "constant", "function": crc, "value": "0x12345678"}));
    verdict(&absent, "unknown");
}

/// MIPS: crc32_update reads a table crc32_init fills in .bss. Without the initialiser the run reads the table unset
/// and the mismatch is unknown, never a refutation; with it as setup the claim is verified.
#[test]
fn a_table_crc_needs_its_initialiser_and_never_refutes_without_it() {
    for name in ["router-mipsel", "router-mips"] {
        let path = format!("mips/{name}-sym.elf");
        let project = open(&path);
        let update = symbol(&path, "crc32_update");
        let claim = json!({"kind": "computes", "function": update, "algorithm": "crc32",
                           "args": [0, "data", "length"], "samples": 8});
        let result = check(&project, claim.clone());
        verdict(&result, "unknown");
        assert!(result["reason"].as_str().unwrap().contains("no initial value"), "{name}: {result:#}");
        assert!(result["needs"].as_str().unwrap().contains("setup"), "{name}");
        let mut with_setup = claim;
        with_setup["setup"] = json!([{"at": symbol(&path, "crc32_init")}]);
        let result = check(&project, with_setup.clone());
        verdict(&result, "verified");
        assert!(result["evidence"]["setup"].is_array(), "{name}");
        with_setup["algorithm"] = json!("crc32c");
        verdict(&check(&project, with_setup), "refuted");
        // A pure helper: a*3 + b - c at 32 bits.
        let scale = symbol(&path, "scale_add");
        verdict(&check(&project, json!({"kind": "computes", "function": scale, "expression": "a*3+b-c"})), "verified");
        verdict(&check(&project, json!({"kind": "computes", "function": scale, "expression": "a*3+b+c"})), "refuted");
    }
}

/// A MIPS boot ROM whose boot_main calls the loaded image through a pointer: calls it makes directly are verified,
/// but a callee it does not call directly is unknown, since the pointer may reach it.
#[test]
fn calls_through_a_pointer_leave_absence_unknown() {
    let path = "mips/boot-mips.elf";
    let project = open(path);
    let main = symbol(path, "boot_main");
    let results = check_all(
        &project,
        vec![
            json!({"kind": "calls", "function": main, "callee": symbol(path, "crc32_bitwise")}),
            json!({"kind": "calls", "function": main, "callee": symbol(path, "uart_putc")}),
            json!({"kind": "calls", "function": main, "callee": symbol(path, "uart_putc"), "depth": 2}),
            json!({"kind": "calls", "function": main, "callee": symbol(path, "crc16_modbus"),
                   "before": symbol(path, "crc32_bitwise")}),
            json!({"kind": "calls", "function": main, "callee": symbol(path, "crc32_bitwise"),
                   "before": symbol(path, "uart_puts")}),
            json!({"kind": "computes", "function": symbol(path, "crc16_modbus"), "algorithm": "crc16_modbus"}),
            json!({"kind": "computes", "function": symbol(path, "crc16_modbus"), "algorithm": "crc16_arc"}),
            json!({"kind": "computes", "function": symbol(path, "crc32_bitwise"), "algorithm": "crc32"}),
        ],
    );
    verdict(&results[0], "verified");
    verdict(&results[1], "unknown");
    assert!(results[1]["evidence"]["unresolved"].as_array().is_some_and(|rows| !rows.is_empty()), "{:#}", results[1]);
    verdict(&results[2], "verified");
    verdict(&results[3], "verified");
    // The banner is printed before either CRC: a path reaches uart_puts first, and later calls follow the CRC.
    verdict(&results[4], "unknown");
    assert!(results[4]["evidence"]["path_without_first"].is_object(), "{:#}", results[4]);
    verdict(&results[5], "verified");
    verdict(&results[6], "refuted");
    verdict(&results[7], "verified");
}

#[test]
fn x86_64_calls_references_constants_and_ints() {
    let path = "bin/hello-x64.elf";
    let project = open(path);
    let results = check_all(
        &project,
        vec![
            json!({"kind": "calls", "function": "main", "callee": "puts"}),
            // main returns add(2, 3) folded to 5: no call.
            json!({"kind": "calls", "function": "main", "callee": "add"}),
            json!({"kind": "calls", "function": "add", "callee": "puts"}),
            json!({"kind": "references", "string": "rampage fixture greeting"}),
            json!({"kind": "references", "string": "rampage fixture greeting", "only_by": ["add"]}),
            json!({"kind": "references", "string": "rampage fixture greeting", "only_by": ["main"]}),
            json!({"kind": "references", "string": "rampage fixture greeting", "by": "add"}),
            json!({"kind": "constant", "function": "main", "value": "0xdeadbeef"}),
            json!({"kind": "computes", "function": "add", "expression": "a+b"}),
            json!({"kind": "computes", "function": "add", "expression": "a-b"}),
            // A C int on a 64-bit target: -1 in eax leaves the upper register bits zero.
            json!({"kind": "returns", "function": "add", "args": [-2, 1], "value": -1}),
            json!({"kind": "returns", "function": "add", "args": [-2, 1], "value": -1, "bits": 32}),
        ],
    );
    verdict(&results[0], "verified");
    verdict(&results[1], "refuted");
    verdict(&results[2], "refuted");
    verdict(&results[3], "verified");
    verdict(&results[4], "refuted");
    assert_eq!(results[4]["evidence"]["outside"][0]["function"], "main");
    verdict(&results[5], "verified");
    verdict(&results[6], "unknown");
    verdict(&results[7], "refuted");
    verdict(&results[8], "verified");
    verdict(&results[9], "refuted");
    assert!(matches!(results[10]["verdict"].as_str(), Some("unknown" | "verified")), "{:#}", results[10]);
    verdict(&results[11], "verified");
}

/// Suite v3's semantics fixture on 32-bit x86 and ARM: a Collatz walk (27 takes 111 steps, peaking at 9232).
#[test]
fn semantics_fixtures_on_x86_and_arm() {
    for path in ["bench-v3/twins/semantics-x86.elf", "bench-v3/twins/semantics-arm32.elf"] {
        let project = open(path);
        let walk = "walk";
        let expected = (9232u64 << 8) | 111;
        let results = check_all(
            &project,
            vec![
                json!({"kind": "returns", "function": walk, "args": [27, 1000], "value": expected}),
                json!({"kind": "returns", "function": walk, "args": [27, 1000], "value": expected + 1}),
                json!({"kind": "returns", "function": walk, "args": [27, 50], "value": expected}),
                // fold_bits and fold_bytes share a shape and differ in constants.
                json!({"kind": "constant", "function": "fold_bits", "value": "0x9e3779b9"}),
                json!({"kind": "constant", "function": "fold_bytes", "value": "0x9e3779b9"}),
            ],
        );
        let x86 = path.contains("x86");
        verdict(&results[3], "verified");
        // Absent: never verified; on x86 the scan of this function has instructions without typed operands, so it
        // is incomplete and cannot refute either; on ARM loaded constants are lower bounds.
        assert_ne!(results[4]["verdict"], "verified", "{x86}: {:#}", results[4]);
        verdict(&results[0], "verified");
        verdict(&results[1], "refuted");
        verdict(&results[2], "refuted");
    }
}

#[test]
fn xtensa_crc_is_verified() {
    let path = "xtensa/esp32-app-sym.elf";
    let project = open(path);
    let crc = symbol(path, "crc32_le");
    let claim = json!({"kind": "computes", "function": crc, "algorithm": "crc32", "args": [0, "data", "length"],
                       "samples": 8});
    verdict(&check(&project, claim), "verified");
}

#[test]
fn layout_reads_debug_information() {
    let project = open("bin/debug-x64.elf");
    let claim =
        |member: &str, offset: u64| json!({"kind": "layout", "type": "debug_pair", "member": member, "offset": offset});
    let results = check_all(
        &project,
        vec![
            claim("second", 4),
            claim("second", 0),
            json!({"kind": "layout", "type": "debug_pair", "member": "first", "size": 4}),
            claim("third", 8),
        ],
    );
    verdict(&results[0], "verified");
    assert_eq!(results[0]["confidence"], "exact");
    verdict(&results[1], "refuted");
    verdict(&results[2], "verified");
    verdict(&results[3], "invalid");
}

#[test]
fn batches_are_budgeted_and_report_each_claim() {
    let project = cortex_m();
    let claims: Vec<Value> =
        (0..33).map(|_| json!({"kind": "returns", "function": cm("app_scale"), "args": [1], "value": 8})).collect();
    assert!(project.check_claims(&claims, None).is_err(), "more than 32 claims are refused");
    // A tight budget: claims after it ran out are unknown, with what to do.
    let claims: Vec<Value> = (0..4)
        .map(|_| json!({"kind": "computes", "function": cm("crc32_compute"), "algorithm": "crc32", "samples": 64}))
        .collect();
    let report = serde_json::to_value(project.check_claims(&claims, Some(50)).unwrap()).unwrap();
    let results = report["results"].as_array().unwrap();
    assert!(results.iter().all(|result| result["verdict"] != "refuted"), "{report:#}");
    assert!(results.iter().any(|result| result["verdict"] == "unknown"), "{report:#}");
    // Deterministic: the same claim twice gives the same evidence.
    let claim = json!({"kind": "computes", "function": cm("crc32_compute"), "algorithm": "crc32", "samples": 4});
    let first = check(&project, claim.clone());
    let second = check(&project, claim);
    assert_eq!(first["evidence"], second["evidence"]);
}

/// Over every named algorithm, only CRC-32 (and its catalogue alias) is verified for the CRC-32 routine.
#[test]
fn only_the_right_algorithm_is_ever_verified() {
    let project = cortex_m();
    let crc = cm("crc32_compute");
    let names = [
        "crc32",
        "crc32_iso_hdlc",
        "crc32c",
        "crc32_bzip2",
        "crc32_mpeg2",
        "crc32_jamcrc",
        "crc32_posix",
        "crc16_arc",
        "crc16_modbus",
        "crc16_ccitt_false",
        "crc16_xmodem",
        "crc16_kermit",
        "crc16_x25",
        "crc8",
        "crc8_maxim",
        "crc64_xz",
        "crc64_ecma",
        "adler32",
        "fletcher16",
        "fletcher32",
        "fnv1a32",
        "fnv1_32",
        "djb2",
        "djb2_xor",
        "sdbm",
        "sum8",
        "sum16",
        "sum32",
        "xor8",
    ];
    let claims: Vec<Value> =
        names.iter().map(|name| json!({"kind": "computes", "function": crc, "algorithm": name, "id": name})).collect();
    let results = check_all(&project, claims);
    for result in &results {
        let right = matches!(result["id"].as_str(), Some("crc32" | "crc32_iso_hdlc"));
        verdict(result, if right { "verified" } else { "refuted" });
    }
}

/// The same C function on each architecture's hello fixture.
#[test]
fn expressions_across_architectures() {
    for path in
        ["bin/hello-arm64.elf", "bin/hello-arm.elf", "bin/hello-thumb.elf", "bin/hello-x64.exe", "bin/hello-mipsel.elf"]
    {
        let project = open(path);
        let results = check_all(
            &project,
            vec![
                json!({"kind": "computes", "function": "add", "expression": "a+b", "samples": 8}),
                json!({"kind": "computes", "function": "add", "expression": "a|b", "samples": 8}),
            ],
        );
        verdict(&results[0], "verified");
        verdict(&results[1], "refuted");
    }
}
