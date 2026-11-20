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
    // An absent constant is never refuted.
    verdict(&results[7], "unknown");
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

/// Acceptance (zlib's `crc32(crc, buf, len)` on MIPS was refuted as CRC-32): a checksum claim without args also tries
/// the running-value layouts `(seed, data, length)` and `(data, length, seed)` before refuting. ESP-IDF's
/// `crc32_le(crc, buf, len)` has zlib's shape.
#[test]
fn checksum_claims_without_args_try_the_running_value_layouts() {
    let path = "xtensa/esp32-app-sym.elf";
    let project = open(path);
    let crc = symbol(path, "crc32_le");
    let result = check(&project, json!({"kind": "computes", "function": crc, "algorithm": "crc32", "samples": 8}));
    verdict(&result, "verified");
    assert_eq!(result["evidence"]["args"], "[0x0, data, length]", "{result:#}");
    assert!(result["method"].as_str().unwrap().contains("no args were given"), "{result:#}");
    // Another algorithm fails every layout and stays refuted, naming the layouts tried.
    let result = check(&project, json!({"kind": "computes", "function": crc, "algorithm": "crc32c", "samples": 8}));
    verdict(&result, "refuted");
    assert_eq!(result["evidence"]["tried"].as_array().unwrap().len(), 3, "{result:#}");
    // Given args are taken as stated.
    let claim = json!({"kind": "computes", "function": crc, "algorithm": "crc32", "args": ["data", "length"],
                       "samples": 8});
    verdict(&check(&project, claim), "refuted");
}

/// Review: when the right layout `(0, data, length)` runs out of steps, another layout's quick mismatch must not
/// refute a true claim: the answer is unknown and still says to raise max_steps.
#[test]
fn an_undecided_layout_keeps_a_checksum_claim_unknown() {
    let path = "xtensa/esp32-app-sym.elf";
    let project = open(path);
    let crc = symbol(path, "crc32_le");
    let claim = json!({"kind": "computes", "function": crc, "algorithm": "crc32", "samples": 8, "max_steps": 200});
    let result = check(&project, claim);
    verdict(&result, "unknown");
    assert!(result["needs"].as_str().unwrap().contains("max_steps"), "{result:#}");
    assert!(result["method"].as_str().unwrap().contains("[0x0, data, length]"), "{result:#}");
    assert_eq!(result["evidence"]["tried"].as_array().unwrap().len(), 3, "{result:#}");
    // An invalid claim is answered once, not run again with other layouts.
    let invalid = json!({"kind": "computes", "function": crc, "algorithm": "crc32", "samples": 0});
    let result = check(&project, invalid);
    verdict(&result, "invalid");
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

/// Review 1: a claimed value wider than the result register is never compared masked.
#[test]
fn review_wide_values_are_never_masked() {
    for path in ["bench-v3/twins/semantics-x86.elf", "bench-v3/twins/semantics-arm32.elf"] {
        let project = open(path);
        for value in [json!("0x10024106f"), json!("-0xffdbef91")] {
            let result =
                check(&project, json!({"kind": "returns", "function": "walk", "args": [27, 1000], "value": value}));
            assert_ne!(result["verdict"], "verified", "{path}: {result:#}");
            assert!(result["needs"].as_str().unwrap_or("").contains("bits 64"), "{path}: {result:#}");
        }
        let claim =
            json!({"kind": "returns", "function": "walk", "args": [27, 1000], "value": "0x10024106f", "bits": 32});
        verdict(&check(&project, claim), "invalid");
    }
    // scale64 returns 64 bits in EDX:EAX: the whole value with bits 64, never EAX alone.
    let project = open("bench-v3/twins/semantics-x86.elf");
    let wide = (16u64 * 3).wrapping_add(16 << 21);
    let expected = (wide ^ (wide >> 29)).wrapping_sub(3 * 0x1_0000_0001);
    let claim = |bits: Option<u32>| {
        let mut claim =
            json!({"kind": "returns", "function": "scale64", "args": [16, 3], "value": format!("{expected:#x}")});
        if let Some(bits) = bits {
            claim["bits"] = json!(bits);
        }
        claim
    };
    verdict(&check(&project, claim(None)), "unknown");
    verdict(&check(&project, claim(Some(64))), "verified");
}

/// Review 2: with depth, the later callee of a `before` claim is searched through callees too.
#[test]
fn review_before_searches_both_callees_to_the_depth() {
    let project = cortex_m();
    let claim = json!({"kind": "calls", "function": cm("reset_handler"), "callee": cm("crc32_compute"),
                       "before": cm("app_scale"), "depth": 2});
    verdict(&check(&project, claim), "verified");
    let reversed = json!({"kind": "calls", "function": cm("reset_handler"), "callee": cm("app_scale"),
                          "before": cm("crc32_compute"), "depth": 2});
    verdict(&check(&project, reversed), "refuted");
}

/// Review 3: an absent constant is never refuted, whatever the architecture.
#[test]
fn review_absent_constants_are_unknown() {
    let project = open("bench-v3/twins/semantics-x86.elf");
    let result = check(&project, json!({"kind": "constant", "function": "scale64", "value": "0x100000001"}));
    verdict(&result, "unknown");
}

/// Review 4: expression arguments have their own widths, and samples stay within them.
#[test]
fn review_expression_arguments_have_their_own_widths() {
    let project = open("bench-v3/twins/semantics-x86.elf");
    let expression = "((a*b + (a<<21)) ^ ((a*b + (a<<21)) >> 29)) - 0x100000001*(b&7)";
    let args = json!([{"name": "a", "bits": 32}, {"name": "b", "bits": 32}]);
    let right = json!({"kind": "computes", "function": "scale64", "expression": expression, "bits": 64, "args": args});
    verdict(&check(&project, right), "verified");
    let wrong = json!({"kind": "computes", "function": "scale64", "expression": "a*b + (a<<21)", "bits": 64,
                       "args": args});
    let result = check(&project, wrong);
    verdict(&result, "refuted");
    for arg in result["evidence"]["counterexample"]["args"].as_array().unwrap() {
        let value = u64::from_str_radix(arg.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert!(value <= 0xffff_ffff, "{result:#}");
    }
    let bad =
        json!({"kind": "computes", "function": "scale64", "expression": "a", "args": [{"name": "a", "bits": 12}]});
    verdict(&check(&project, bad), "invalid");
}

/// Review 5: an FNV-1a routine still verifies; a narrower reference that agrees on the low bits would not (unit
/// tested on the register rule, `claims::run::tests`).
#[test]
fn review_full_width_checksums_still_verify() {
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": 800, "base_address": "0x8000000", "vector_table": true
    }))
    .unwrap();
    let path = std::path::PathBuf::from(format!("{FIXTURES}firmware/raw-cortex-m.bin"));
    let project = Session::default().open_raw(&path, &request).unwrap();
    let checksum = symbol("firmware/raw-cortex-m.elf", "checksum");
    verdict(&check(&project, json!({"kind": "computes", "function": checksum, "algorithm": "fnv1a32"})), "verified");
    verdict(&check(&project, json!({"kind": "computes", "function": checksum, "algorithm": "fnv1_32"})), "refuted");
}

/// Review 6: callee names match exactly; a name the binary does not have is invalid, not "not called".
#[test]
fn review_callee_names_match_exactly() {
    let project = open("bin/hello-x64.elf");
    verdict(&check(&project, json!({"kind": "calls", "function": "main", "callee": "_puts"})), "invalid");
    verdict(&check(&project, json!({"kind": "calls", "function": "main", "callee": "put"})), "invalid");
    verdict(&check(&project, json!({"kind": "calls", "function": "main", "callee": "puts"})), "verified");
}

/// Review 13: a call into an import that calls back through a pointer leaves absence unknown.
#[test]
fn review_callback_imports_leave_absence_unknown() {
    let project = open("bin/hello-x64-dyn.elf");
    let result = check(&project, json!({"kind": "calls", "function": "_start", "callee": "main"}));
    assert_ne!(result["verdict"], "refuted", "{result:#}");
}

/// Review 7: a detected check verifies a region only while its stored value holds.
#[test]
fn review_region_needs_a_valid_detected_check() {
    use rampage_api::tools::{call_shared, tools};
    let directory = std::env::temp_dir().join(format!("rampage-claims-region-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("raw-cortex-m-crc.bin");
    std::fs::copy(format!("{FIXTURES}firmware/raw-cortex-m-crc.bin"), &path).unwrap();
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": 0x800, "base_address": "0x8000000", "vector_table": true
    }))
    .unwrap();
    let mut project = Session::default().open_raw(&path, &request).unwrap();
    let mut call = |name: &str, input: Value| -> Value {
        let (text, failed) = call_shared(&tools(), &mut project, name, input);
        assert!(!failed, "{name}: {text}");
        serde_json::from_str(&text).unwrap()
    };
    let region = json!({"kind": "region", "start": "0x8000400", "end": "0x80007fc", "algorithm": "crc32"});
    let report = call("check_claim", json!({"claims": [region]}));
    assert_eq!(report["results"][0]["verdict"], "verified", "{report:#}");
    // Patch one byte of the application's table: the stored CRC no longer holds.
    let integrity = call("integrity_checks", json!({"emulate": false}));
    let patch = json!({
        "at": cm("app_table"), "original_hex": "11", "replacement_hex": "42", "allow_data": false,
        "source_sha256": integrity["receipt"]["source_sha256"],
        "expected_revision": integrity["receipt"]["revision_sha256"],
    });
    call("patch_bytes", patch);
    let mut stored = region.clone();
    stored["stored"] = json!("0x80007fc");
    let report = call("check_claim", json!({"claims": [region, stored]}));
    assert_ne!(report["results"][0]["verdict"], "verified", "{report:#}");
    assert_eq!(report["results"][1]["verdict"], "refuted", "{report:#}");
    let _ = std::fs::remove_dir_all(&directory);
}

/// Review 8: an expected text is a C string (its NUL included); hex states the whole buffer unless `prefix`.
#[test]
fn review_buffers_compare_whole() {
    let project = open("bin/hello-thumb.elf");
    let claim = |expected: Value| {
        json!({"kind": "returns", "function": "0x20e9e", "args": [{"buffer": {"size": 8}}, 65, 4],
               "buffers": [expected]})
    };
    let results = check_all(
        &project,
        vec![
            claim(json!({"argument": 0, "text": "AAA"})),
            claim(json!({"argument": 0, "text": "AAAA"})),
            claim(json!({"argument": 0, "hex": "41414141"})),
            claim(json!({"argument": 0, "hex": "4141414100000000"})),
            claim(json!({"argument": 0, "hex": "414141", "prefix": true})),
        ],
    );
    verdict(&results[0], "refuted");
    verdict(&results[1], "verified");
    verdict(&results[2], "invalid");
    verdict(&results[3], "verified");
    verdict(&results[4], "verified");
}

/// Review 9: a refutation that read initialised writable data states that assumption.
#[test]
fn review_refutations_state_their_data_assumptions() {
    let path = "firmware/elf-cortex-m-crc32.elf";
    let project = open(path);
    // app_scale returns value * 5 + blink_period, an initialised SRAM variable (0x12345 in the file).
    let scale = symbol(path, "app_scale");
    let right = check(&project, json!({"kind": "returns", "function": scale, "args": [1], "value": 0x1234a}));
    verdict(&right, "verified");
    assert!(right["evidence"]["assumes_initial_data"].is_array(), "{right:#}");
    let wrong = check(&project, json!({"kind": "returns", "function": scale, "args": [1], "value": 6}));
    verdict(&wrong, "refuted");
    assert!(wrong["evidence"]["assumes"].as_str().is_some(), "{wrong:#}");
}

/// Review 10: negating a sampled verification is unknown, not a refutation without a counterexample.
#[test]
fn review_negated_samples_are_unknown() {
    let project = cortex_m();
    let claim = json!({"kind": "computes", "function": cm("crc32_compute"), "algorithm": "crc32", "samples": 4,
                       "not": true});
    let result = check(&project, claim);
    verdict(&result, "unknown");
    assert_eq!(result["negated"], true);
}

/// Review 11: a deep search under a tiny budget is unknown, never refuted.
#[test]
fn review_static_searches_respect_the_deadline() {
    let project = open("bin/hello-x64.elf");
    let claim = json!({"kind": "calls", "function": "main", "callee": "add", "before": "puts", "depth": 8});
    let report = serde_json::to_value(project.check_claims(&[claim], Some(30)).unwrap()).unwrap();
    assert_ne!(report["results"][0]["verdict"], "verified", "{report:#}");
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
