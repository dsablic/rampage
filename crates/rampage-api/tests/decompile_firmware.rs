//! Decompiler accuracy on a headerless Cortex-M image opened through the Raw profile: literal-pool globals, callers
//! that keep an argument in a call-clobbered register across a call (interprocedural register allocation), and
//! arguments that are another call's result. tests/fixtures/firmware/raw-cortex-m-decompile.c is the source; its
//! .elf keeps the symbols as the truth.

use std::collections::{BTreeMap, BTreeSet};

use rampage_api::{FunctionsQuery, Project, XrefQuery};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

const IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-decompile.bin");
const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-decompile.elf");

fn truth(name: &str) -> u64 {
    let elf = Binary::open(ELF).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

/// Raw projects name functions by address, as an analyst sees them before renaming anything.
fn sub(name: &str) -> String {
    format!("sub_{:x}", truth(name))
}

fn project() -> Project {
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    Project::new(Binary::from_raw_code(IMAGE.to_vec(), options).unwrap())
}

fn decompile(project: &Project, name: &str) -> String {
    project.decompile(truth(name)).unwrap_or_else(|error| panic!("{name}: {error}")).code
}

/// Literal-pool words are read-only code: they fold into the addresses they hold, and globals at those addresses are
/// named by their Cortex-M region rather than as `iRam…`/`pxRam…` variables for the pool words themselves.
#[test]
fn literal_pool_globals_are_named_by_cortex_m_region() {
    let project = project();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("ram_20000048 = ram_20000048 + 4;"), "{code}");
    // The peripheral range is volatile: the register is read once, then the result written.
    let read =
        code.lines().find(|line| line.trim().ends_with("= periph_40021000;")).unwrap_or_else(|| panic!("{code}"));
    let variable = read.trim().split(' ').next().unwrap();
    assert!(code.contains(&format!("periph_40021004 = {variable} | 0x100;")), "{code}");
    assert!(!code.contains("Ram"), "{code}");
    // The analyst's name for a data address wins over the region name.
    project.rename(0x2000_0048, Some("cursor")).unwrap();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("cursor = cursor + 4;"), "{code}");
}

/// verify_image keeps its length in r2 across probe_status, which never writes r2 (LLVM's IPRA relied on that), then
/// moves it to r1 for checksum. checksum_after_quiet keeps it in r1 itself across quiet_leaf, which writes only r3.
#[test]
fn arguments_kept_in_registers_a_callee_never_writes_reach_the_next_call() {
    let project = project();
    let checksum = sub("checksum");
    let code = decompile(&project, "verify_image");
    assert!(code.contains(&format!("ram_20000044 = {checksum}(0x20000004,param_1);")), "{code}");
    assert!(!code.contains("extraout"), "{code}");
    let code = decompile(&project, "checksum_after_quiet");
    assert!(code.contains(&format!("{checksum}(param_1,param_2)")), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

/// scratch_r1 overwrites r1, so checksum_after_scratch really passes scratch_r1's r1: the call's output, not the
/// caller's parameter. Inference never marks a register the callee writes as preserved.
#[test]
fn a_register_the_callee_writes_still_reads_as_its_output() {
    let project = project();
    let code = decompile(&project, "checksum_after_scratch");
    assert!(code.contains(&format!("{}(param_1,extraout_r1)", sub("checksum"))), "{code}");
}

/// With each callee's prototype committed from its own decompilation, a call's result feeds the next call.
#[test]
fn call_results_feed_the_calls_that_use_them() {
    let project = project();
    let code = decompile(&project, "reset_handler");
    // reset_handler keeps unpack_field's result for a later call too, so it lands in a variable first. Its argument
    // is the (volatile) peripheral register, read into a variable of its own.
    let call = format!(" = {}(", sub("unpack_field"));
    assert!(code.contains("= periph_40021000;"), "{code}");
    let line = code.lines().find(|line| line.contains(&call)).unwrap_or_else(|| panic!("{code}"));
    let variable = line.trim().split(' ').next().unwrap();
    assert!(code.contains(&format!("{}({variable})", sub("verify_image"))), "{code}");
    assert!(!code.contains(&format!("{}()", sub("verify_image"))), "{code}");
    assert!(!code.contains(&format!("{}()", sub("place_field"))), "{code}");
}

/// The shift-and-mask is Ghidra's faithful reading of `ubfx r0, r0, #4, #12`: bits 4..15, written as a 16-bit mask
/// before the shift. Not rewritten; checked so a change to it is noticed.
#[test]
fn bit_field_extracts_read_as_mask_then_shift() {
    let project = project();
    let code = decompile(&project, "unpack_field");
    assert!(code.contains("return (param_1 & 0xffff) >> 4;"), "{code}");
}

/// In every format, a global the binary's data symbols name reads by that name (only the name: no folding, region
/// names or callee inference outside Raw images).
#[test]
fn data_symbols_name_their_globals_in_every_format() {
    for (name, exit) in [("hello-x64.elf", 0x10023ea), ("hello-thumb.elf", 0x20cbc)] {
        let code = fixture(name).decompile(exit).unwrap().code;
        assert!(code.contains("close_file(__stderr_used);"), "{name}: {code}");
        assert!(code.contains("close_file(__stdout_used);"), "{name}: {code}");
    }
}

/// One engine serves every decompilation and keeps the callee prototypes and effects it derives, each of which
/// depends only on the callee, so a function reads the same whatever was decompiled before it. chain0..chain70 is
/// longer than the 64 functions a derivation may reach: decompiling chain30 first locks chain31..chain70, which must
/// not let chain_head's own decompilation reach chain0.
#[test]
fn raw_decompilation_does_not_depend_on_history() {
    let reversed = project();
    let project = project();
    let first = decompile(&project, "chain_head");
    assert!(first.contains(&format!("{}()", sub("chain0"))), "{first}");
    let reset = decompile(&project, "reset_handler");
    let others = ["chain30", "chain60", "verify_image", "checksum_after_quiet", "checksum", "unpack_field"];
    for name in others {
        decompile(&project, name);
    }
    assert_eq!(decompile(&project, "chain_head"), first);
    assert_eq!(decompile(&project, "reset_handler"), reset);
    for name in others.iter().rev() {
        decompile(&reversed, name);
    }
    assert_eq!(decompile(&reversed, "reset_handler"), reset);
    assert_eq!(decompile(&reversed, "chain_head"), first);
}

/// depth_probe keeps its argument in r2 across chain54, whose callees the register scan can follow to the end, just
/// after calling chain53, whose callees it cannot. Seeing chain54 too deep below chain53 must not make it unknown.
#[test]
fn a_callee_too_deep_below_another_is_still_scanned_on_its_own() {
    let code = decompile(&project(), "depth_probe");
    assert!(code.contains(&format!("{}(param_1,param_1)", sub("checksum"))), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

/// An analyst may name any address; a name beyond the 32-bit data space is left out rather than refusing the
/// decompilation.
#[test]
fn names_beyond_the_data_space_are_left_out() {
    let project = project();
    project.rename(0x1_2000_0048, Some("beyond")).unwrap();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("ram_20000048 = ram_20000048 + 4;"), "{code}");
}

/// A supervisor-call wrapper hides its parameter from its own decompilation (`mov r1, r0; svc #0`), so its
/// prototype is never derived and the caller's argument stays.
#[test]
fn a_supervisor_call_wrapper_keeps_its_argument() {
    let code = decompile(&project(), "report_length");
    assert!(code.contains(&format!("{}(param_1 * 3 + 1);", sub("sys_report"))), "{code}");
}

/// A thunk (`b.w checksum`) and a conditional tail call (`cmp r0, #0; bne.w checksum`) are never derived from
/// their own flow, which runs into checksum's code.
#[test]
fn tail_call_thunks_keep_their_arguments() {
    let code = decompile(&project(), "sum_through_tail");
    assert!(code.contains(&format!("{}(0x20000004,param_1)", sub("checksum_tail"))), "{code}");
    let code = decompile(&project(), "sum_if_data");
    assert!(code.contains(&format!("{}(0x20000004,param_1)", sub("checksum_if_data"))), "{code}");
}

/// musl's __syscall_ret shape: the input on one path, -1 on the other, after a call to a derived callee. A
/// derived callee return would make Ghidra drop this function's own return.
#[test]
fn a_return_of_input_or_constant_survives_a_derived_callee() {
    let code = decompile(&project(), "syscall_ret");
    assert!(code.contains(&format!("uint4 {}(uint4 param_1)", sub("syscall_ret"))), "{code}");
    assert!(code.contains("return param_1;") && code.contains("return 0xffffffff;"), "{code}");
}

/// checksum_after_probes keeps its length in r2 across probe_twice, which calls probe_status twice; the callee's
/// own calls are followed to see that none of them writes r2.
#[test]
fn arguments_survive_a_callee_whose_callees_leave_them_alone() {
    let code = decompile(&project(), "checksum_after_probes");
    assert!(code.contains(&format!("{}(param_1,param_2)", sub("checksum"))), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

fn fixture(name: &str) -> Project {
    let path = format!("{}/../../tests/fixtures/bin/{name}", env!("CARGO_MANIFEST_DIR"));
    Project::new(Binary::open(path).unwrap())
}

/// The firmware inference (callee effects and prototypes, read-only folding, region names) is for Raw images only:
/// headered binaries keep Ghidra's defaults.
#[test]
fn headered_binaries_keep_ghidra_defaults() {
    // musl `exit` passes its status in r0 to `_Exit`, whose body is `mov r1, r0; svc #0`.
    let thumb = fixture("hello-thumb.elf");
    let code = thumb.decompile(0x207ec).unwrap().code;
    assert!(code.contains("_Exit(status);"), "{code}");
    // Returns its input on one path and -1 on the other.
    let code = thumb.decompile(0x20b36).unwrap().code;
    assert!(code.contains("uint4 __syscall_ret(uint4 param_1)"), "{code}");
    assert!(code.contains("return param_1;") && code.contains("return 0xffffffff;"), "{code}");
    let arm = fixture("hello-arm.elf");
    let code = arm.decompile(0x202fc).unwrap().code;
    assert!(code.contains("0,0,param_1);"), "{code}");
    // mingw's pseudo-relocator writes `.rdata` at run time: its words stay variables, not constants.
    let exe = fixture("hello-x64.exe");
    let code = exe.decompile(0x1_4000_1fc0).unwrap().code;
    assert!(code.contains("*param_1 ^ uRam00000001400293c0"), "{code}");
}

/// An ELF build of Cortex-M firmware is M-profile by its build attributes and decompiles with the same settings as
/// the Raw image: the reset request before system_reset's endless loop is a volatile store and stays; literal-pool
/// words fold into the addresses they hold, so advance_cursor reads and writes `cursor` itself rather than through
/// a pool pointer (`*piRam080001c0`) and the peripheral it touches is named by region; and the CRC word
/// reset_handler reads through an address it forms stays a read instead of folding to its flash value.
#[test]
fn m_profile_elf_firmware_gets_the_cortex_m_settings() {
    let elf = |name: &str| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware").join(name);
        let project = Project::new(Binary::open(path).unwrap());
        assert!(project.binary.m_profile(), "{name}");
        project
    };
    let decompile = |project: &Project, name: &str| {
        project.decompile(project.binary.symbol_by_name(name).unwrap().address & !1).unwrap().code
    };
    let locks = elf("raw-cortex-m-locks.elf");
    let code = decompile(&locks, "system_reset");
    assert!(code.contains("= 0x5fa0004;"), "{code}");
    let pools = elf("raw-cortex-m-decompile.elf");
    let code = decompile(&pools, "advance_cursor");
    assert!(code.contains("cursor = cursor + 4;"), "{code}");
    assert!(code.contains("periph_40021004 = "), "{code}");
    assert!(!code.contains("Ram"), "{code}");
    let crc = elf("raw-cortex-m-crc.elf");
    let code = decompile(&crc, "reset_handler");
    let stored = u32::from_le_bytes(crc.binary.read(0x0800_07fc, 4).unwrap().try_into().unwrap());
    assert!(code.contains("app_crc"), "{code}");
    assert!(!code.contains(&format!("{stored:#x}")), "{code}");
}

/// The direct calls between an image's functions, by caller, from discovery's call references.
fn call_graph(project: &Project) -> BTreeMap<u64, BTreeSet<u64>> {
    let query = FunctionsQuery { limit: Some(100_000), ..Default::default() };
    let functions: BTreeSet<u64> = project.functions(&query).unwrap().items.iter().map(|row| row.address).collect();
    functions
        .iter()
        .map(|&function| {
            let rows = project.xrefs(XrefQuery::From(function), None, Some(100_000)).unwrap().items;
            let callees = rows
                .iter()
                .filter(|row| row.kind.as_str() == "call" && row.to != function && functions.contains(&row.to))
                .map(|row| row.to)
                .collect();
            (function, callees)
        })
        .collect()
}

fn reachable(graph: &BTreeMap<u64, BTreeSet<u64>>, from: u64) -> BTreeSet<u64> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![from];
    while let Some(function) = pending.pop() {
        for &callee in graph.get(&function).into_iter().flatten() {
            if seen.insert(callee) {
                pending.push(callee);
            }
        }
    }
    seen
}

/// Library-heavy Cortex-M firmware: each function decompiles to the same C first on a fresh engine, after a set
/// of other functions (its callers among them, which derive its own prototype first), and after all of them in
/// reverse (so after itself too). The sample covers functions on call cycles, functions whose callees reach more
/// than the 64 functions a derivation may, and the largest one, whose callees together exceed that budget.
#[test]
fn cortex_m_elf_decompilation_does_not_depend_on_history() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/embedded-libs-m0.elf");
    let open = || Project::new(Binary::open(path).unwrap());
    let graph = call_graph(&open());
    let reach: BTreeMap<u64, BTreeSet<u64>> =
        graph.keys().map(|&function| (function, reachable(&graph, function))).collect();
    let on_cycle: Vec<u64> = reach.iter().filter(|(function, set)| set.contains(function)).map(|(&f, _)| f).collect();
    let over_budget: Vec<u64> = reach
        .iter()
        .filter(|(function, set)| set.len() > 64 && !set.contains(function))
        .map(|(&function, _)| function)
        .collect();
    assert!(on_cycle.len() >= 2 && over_budget.len() >= 2, "{on_cycle:x?} {over_budget:x?}");
    let mut sample = vec![on_cycle[0], on_cycle[on_cycle.len() - 1], over_budget[0], over_budget[1], 0x80092ca];
    // A leaf and a caller of a sampled function, so some are decompiled after being derived as a callee.
    let (leaf, derived) = graph
        .iter()
        .find_map(|(&caller, callees)| {
            callees.iter().find(|callee| graph[callee].is_empty()).map(|&leaf| (leaf, caller))
        })
        .unwrap();
    sample.extend([leaf, derived]);
    // Functions that read differently once other analyses had run: one whose type propagation does not settle
    // (Ghidra kept that verdict across analyses of the same function), and one that used a global another
    // function's analysis had typed.
    sample.extend([0x8002dd4, 0x80020b0]);
    let caller = |target: u64| graph.iter().find(|(_, callees)| callees.contains(&target)).map(|(&caller, _)| caller);
    let others: BTreeSet<u64> = sample
        .iter()
        .flat_map(|&function| caller(function).into_iter().chain(graph[&function].iter().take(2).copied()))
        .filter(|function| !sample.contains(function))
        .collect();

    let decompile = |project: &Project, function: u64| {
        project.decompile(function).unwrap_or_else(|error| panic!("{function:#x}: {error}")).code
    };
    let fresh: BTreeMap<u64, String> =
        sample.iter().map(|&function| (function, decompile(&open(), function))).collect();

    let after_others = open();
    for &function in &others {
        decompile(&after_others, function);
    }
    for &function in &sample {
        assert_eq!(decompile(&after_others, function), fresh[&function], "{function:#x} after {others:x?}");
    }

    let after_all = open();
    for &function in others.iter().chain(&sample).rev() {
        decompile(&after_all, function);
    }
    for &function in &sample {
        assert_eq!(decompile(&after_all, function), fresh[&function], "{function:#x} after all");
    }
}

/// An address discovery placed in no function (here depth_probe, when only chain_head seeds discovery) is
/// registered for its own decompilation only: decompiling it twice, with a registered function that reaches the
/// same callees in between, gives the same C both times and the same as on a fresh engine, and the registered
/// function reads the same before and after it.
#[test]
fn an_address_outside_every_function_decompiles_the_same_each_time() {
    let open = || {
        let options = RawCodeOptions {
            profile: RawProfile::CortexM,
            base: 0x0800_0000,
            entry: None,
            seeds: vec![truth("chain_head")],
            vector_table: None,
            pointer_tables: false,
        };
        Project::new(Binary::from_raw_code(IMAGE.to_vec(), options).unwrap())
    };
    let probe = truth("depth_probe");
    let query = FunctionsQuery { limit: Some(100_000), ..Default::default() };
    let functions = open().functions(&query).unwrap().items;
    assert!(functions.iter().all(|row| row.address != probe), "depth_probe was discovered");
    assert!(functions.iter().any(|row| row.address == truth("chain53")), "chain53 was not discovered");
    let code = |project: &Project, address: u64| project.decompile(address).unwrap().code;
    let fresh_probe = code(&open(), probe);
    let fresh_head = code(&open(), truth("chain_head"));
    let project = open();
    assert_eq!(code(&project, probe), fresh_probe);
    assert_eq!(code(&project, truth("chain_head")), fresh_head);
    assert_eq!(code(&project, probe), fresh_probe);
    assert_eq!(code(&project, truth("chain_head")), fresh_head);
}

/// A function with an analyst signature whose return comes from its last call decompiles that callee first as a
/// return-type context, inside its own decompilation; it reads the same on a fresh engine, after its callee and
/// callers, and after itself.
#[test]
fn cortex_m_return_contexts_do_not_depend_on_history() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/embedded-libs-m0.elf");
    let open = || Project::new(Binary::open(path).unwrap());
    let graph = call_graph(&open());
    let scan = open();
    // A void function whose last statement before its return is a call: given a signature with an int return, its
    // decompilation takes that callee's return type from a context decompilation of the callee. Some such contexts
    // are refused as unsupported (on main too); the first that decompiles is taken.
    let signed = |function: u64, declaration: &str| {
        let project = open();
        project.set_signature(function, Some(&format!("{declaration};"))).unwrap();
        project
    };
    let (function, callee, declaration, fresh) = graph
        .iter()
        .filter(|(_, callees)| !callees.is_empty() && callees.len() <= 4)
        .filter_map(|(&function, callees)| {
            let code = scan.decompile(function).ok()?.code;
            let lines: Vec<&str> = code.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
            let [.., last_call, "return;", "}"] = lines.as_slice() else { return None };
            let callee = *callees.iter().find(|callee| last_call.starts_with(&format!("sub_{callee:x}(")))?;
            let declaration = lines.iter().find(|line| line.starts_with(&format!("void sub_{function:x}(")))?;
            Some((function, callee, declaration.replacen("void ", "int4 ", 1)))
        })
        .take(16)
        .find_map(|(function, callee, declaration)| {
            let fresh = signed(function, &declaration).decompile(function).ok()?.code;
            Some((function, callee, declaration, fresh))
        })
        .expect("a void function ending in a call that decompiles with an int return");
    let code = |project: &Project, address: u64| project.decompile(address).unwrap().code;
    let project = signed(function, &declaration);
    // Warming only: a caller's own decompilation may refuse a context as unsupported too.
    let _ = project.decompile(callee);
    for (&caller, callees) in &graph {
        if callees.contains(&function) {
            let _ = project.decompile(caller);
        }
    }
    assert_eq!(code(&project, function), fresh, "{function:#x} after its callee and callers");
    assert_eq!(code(&project, function), fresh, "{function:#x} after itself");
}

/// A callee without a symbol, discovered or not, is named `sub_<hex>` in decompiled C, as listings, xrefs and the
/// other tools name it, never Ghidra's `func_0x…`; the name read off the C resolves back to the callee's address.
/// In the library-heavy image some calls land in code discovery did not reach as a function start.
#[test]
fn decompiled_callees_use_the_default_names_other_tools_resolve() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/embedded-libs-m0.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let query = FunctionsQuery { limit: Some(usize::MAX), ..Default::default() };
    let mut rows = project.functions(&query).unwrap().items;
    let known: BTreeSet<u64> = rows.iter().map(|row| row.address).collect();
    // Largest first: they make the most calls, those into undiscovered code among them. A few dozen are enough.
    rows.sort_by_key(|row| std::cmp::Reverse(row.size));
    let call = regex::Regex::new(r"\bsub_([0-9a-f]+)\(").unwrap();
    let (mut checked, mut named, mut undiscovered) = (0, 0, 0);
    for function in rows.iter().map(|row| row.address) {
        if checked >= 24 && named > 0 && undiscovered > 0 {
            break;
        }
        let Ok(decompilation) = project.decompile(function) else { continue };
        checked += 1;
        assert!(!decompilation.code.contains("func_0x"), "{function:#x}: {}", decompilation.code);
        for capture in call.captures_iter(&decompilation.code) {
            let address = u64::from_str_radix(&capture[1], 16).unwrap();
            let name = format!("sub_{}", &capture[1]);
            assert_eq!(project.resolve(&name).unwrap(), address, "{name}");
            assert_eq!(name, rampage_analysis::functions::default_name(address));
            named += 1;
            if !known.contains(&address) {
                undiscovered += 1;
                // The structured call carries the name the C calls it by.
                let calls = &decompilation.structure.calls;
                assert!(
                    calls.iter().any(|call| call.target == Some(address) && call.name.as_deref() == Some(&name)),
                    "{name}: {calls:?}"
                );
                // The name works where any address does: disassembly starts at the callee.
                let lines = project.disassemble(Some(&name), 1).unwrap();
                assert_eq!(lines[0].address, address, "{name}");
            }
        }
    }
    assert!(named > 0 && undiscovered > 0, "{named} named calls, {undiscovered} to undiscovered code");
}

/// Haiku v4 1.11.0: decompile refused six large Cortex-M0 functions of the held-out library build over the byte
/// budget, one in view=summary. A summary or code view that does not fit keeps fewer variable rows, counted; C too
/// long for one result refuses naming `page` and the page count, and the pages cover every line once.
#[test]
fn large_decompilations_trim_evidence_and_page_long_c() {
    use rampage_api::tools;
    use serde_json::{Value, json};

    const M0: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/embedded-libs-m0.elf");
    let project = Project::new(Binary::open(M0).unwrap());
    let registry = tools::tools();
    let call = |arguments: Value| {
        let (text, failed) = tools::call(&registry, &project, "decompile", arguments);
        assert!(text.len() <= 60_000, "{} bytes", text.len());
        (serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)), failed)
    };
    // The largest: about 60 KB of C and 128 variables, 825 KB in full.
    let large = "0x800a0b0";
    let full = project.decompile(0x800a0b0).unwrap();
    let (summary, failed) = call(json!({ "at": large, "view": "summary" }));
    assert!(!failed, "{summary}");
    let kept = summary["variables"].as_array().unwrap().len();
    assert_eq!(kept + summary["variables_omitted"].as_u64().unwrap() as usize, full.variables.len(), "{summary}");
    assert!(kept > 0 && kept < full.variables.len());
    let omissions = summary["view_projection"]["omissions"].as_array().unwrap();
    assert!(omissions.iter().any(|receipt| receipt["path"] == "/variables" && receipt["kept"] == kept), "{summary}");
    assert!(summary.get("code").is_none());

    let (refusal, failed) = call(json!({ "at": large, "view": "code" }));
    let refusal = refusal.as_str().unwrap().to_owned();
    assert!(
        failed && refusal.contains("page 0 through 1 (the `page` argument") && refusal.contains("in 2 pages"),
        "{refusal}"
    );
    let mut code = String::new();
    let mut page = Some(0);
    while let Some(index) = page {
        let (value, failed) = call(json!({ "at": large, "view": "code", "page": index }));
        assert!(!failed, "{value}");
        assert_eq!(value["code_page"]["page"], index);
        assert_eq!(value["code_page"]["pages"], 2);
        assert_eq!(value["code_page"]["total_lines"], full.code.lines().count());
        assert_eq!(value["code_page"]["first_line"], code.lines().count() + 1);
        code.push_str(value["code"].as_str().unwrap());
        page = value["code_page"]["next_page"].as_u64();
    }
    assert_eq!(code, full.code);
    let (past, failed) = call(json!({ "at": large, "view": "code", "page": 2 }));
    assert!(failed && past.as_str().unwrap().contains("2 pages, 0 through 1"), "{past}");
    let (wrong, failed) = call(json!({ "at": large, "view": "summary", "page": 0 }));
    assert!(failed && wrong.as_str().unwrap().contains("view=\"code\""), "{wrong}");

    // About 26 KB of C: one page, so the code view keeps all of it and trims the variable rows instead.
    let (value, failed) = call(json!({ "at": "0x800e412", "view": "code" }));
    assert!(!failed, "{value}");
    assert_eq!(value["code"], project.decompile(0x800e412).unwrap().code);
    assert!(value.get("code_page").is_none() && value["variables_omitted"].as_u64() > Some(0), "{value}");
}
