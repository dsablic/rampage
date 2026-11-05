#![cfg(unix)]

//! Static ↔ runtime correlation (phase 9.3) against the scripted fake stub: binding a project to a runtime module,
//! breakpoints by static address and function name, stop and register locations, step over and out with temporary
//! breakpoints, and ledger evidence. The static side is the owned x86-64 PIE in `tests/fixtures/debug-correlation`
//! (rebuilt with its `build.sh`), mapped into the fake target at a load bias.

use std::path::PathBuf;
use std::time::Duration;

use rampage_api::tools::{DebugTool, debug_tools};
use rampage_api::{DebugCancel, DebugRegistry};
use rampage_debug::fake::{Action, FakeStub, Report, Script, le_hex};
use rampage_loaders::Binary;
use serde_json::{Value, json};

/// Where the fake target maps the fixture: its svr4 load bias.
const BASE: u64 = 0x5555_5555_4000;
const STACK: u64 = 0x7fff_ffff_e000;
/// Static addresses in the fixture (see `correlation-a.c`; checked against its symbols below).
const HELPER_A: u64 = 0x1290;
const HELPER_B: u64 = 0x12e0;
const LEAF: u64 = 0x12a0;
const CALLER: u64 = 0x12b0;
/// `call leaf` in caller, five bytes, and the instruction after it.
const CALL_LEAF: u64 = 0x12b9;
const AFTER_CALL: u64 = 0x12be;
const GREETING: u64 = 0x270;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/debug-correlation/correlation-x64.elf")
        .canonicalize()
        .unwrap()
}

fn symbol(name: &str) -> Vec<u64> {
    let binary = Binary::open(fixture()).unwrap();
    binary.symbols.iter().filter(|symbol| symbol.name == name).map(|symbol| symbol.address).collect()
}

fn hex(value: Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// The `g` reply for rip, rsp and rdi (every other register 0).
fn g(rip: u64, rsp: u64, rdi: u64) -> String {
    let mut registers = [0u64; 16];
    registers[5] = rdi;
    registers[7] = rsp;
    registers.iter().map(|value| le_hex(*value, 8)).collect::<String>() + &le_hex(rip, 8) + &le_hex(0x246, 4)
}

/// A stop reply with rip expedited.
fn stop(rip: u64) -> String {
    format!("T05thread:p01.01;10:{};", le_hex(rip, 8))
}

/// gdbserver-like x86-64 Linux stub stopped at runtime `rip`, listing the fixture as the main module (named
/// `module`) at [`BASE`]; `header` maps the ELF header and program headers too, so the build ID is readable.
fn x64(rip: u64, module: &str, header: bool) -> Script {
    x64_rdi(rip, module, header, 0)
}

/// [`x64`] without a module list, stopped at `rip` (an image linked where it runs, like firmware).
fn x64_bare(rip: u64) -> Script {
    let mut core = String::from(
        "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.i386.core\">",
    );
    for name in
        ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    {
        core.push_str(&format!("<reg name=\"{name}\" bitsize=\"64\"/>"));
    }
    core.push_str(
        "<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\"/><reg name=\"eflags\" bitsize=\"32\"/></feature>",
    );
    Script::new()
        .on(
            "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
            "PacketSize=4000;qXfer:features:read+;multiprocess+;vContSupported+",
        )
        .xfer(
            "features",
            "target.xml",
            "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
             <architecture>i386:x86-64</architecture><xi:include href=\"core.xml\"/></target>",
        )
        .xfer("features", "core.xml", &core)
        .on("?", &stop(rip))
        .on("qfThreadInfo", "mp01.01")
        .on("qsThreadInfo", "l")
        .on("qThreadExtraInfo,p1.1", "")
        .on("Hgp1.1", "OK")
        .on("g", &g(rip, STACK, 0))
        .on("qOffsets", "")
        .on("D;1", "OK")
}

/// [`x64`] with `rdi` set in the `g` reply.
fn x64_rdi(rip: u64, module: &str, header: bool, rdi: u64) -> Script {
    let mut core = String::from(
        "<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.i386.core\">",
    );
    for name in
        ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    {
        core.push_str(&format!("<reg name=\"{name}\" bitsize=\"64\"/>"));
    }
    core.push_str(
        "<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\"/><reg name=\"eflags\" bitsize=\"32\"/></feature>",
    );
    let mut script = Script::new()
        .on(
            "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
            "PacketSize=4000;qXfer:features:read+;qXfer:libraries-svr4:read+;multiprocess+;vContSupported+",
        )
        .xfer(
            "features",
            "target.xml",
            "<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target>\
             <architecture>i386:x86-64</architecture><xi:include href=\"core.xml\"/></target>",
        )
        .xfer("features", "core.xml", &core)
        .xfer(
            "libraries-svr4",
            "",
            &format!(
                "<library-list-svr4 version=\"1.0\" main-lm=\"0x7ffff7ffe190\"><library name=\"{module}\" \
                 lm=\"0x7ffff7ffe190\" l_addr=\"{BASE:#x}\" l_ld=\"0x0\" lmid=\"0x0\"/></library-list-svr4>"
            ),
        )
        .on("?", &stop(rip))
        .on("qfThreadInfo", "mp01.01")
        .on("qsThreadInfo", "l")
        .on("qThreadExtraInfo,p1.1", "")
        .on("Hgp1.1", "OK")
        .on("g", &g(rip, STACK, rdi))
        .on("qOffsets", "")
        .on("D;1", "OK")
        .execution()
        .on("vCont?", "vCont;c;C;s;S")
        // Detaching removes whatever is still inserted.
        .on_prefix("z0,", vec![Action::Reply("OK".into())])
        .on_prefix("z1,", vec![Action::Reply("OK".into())]);
    let binary = Binary::open(fixture()).unwrap();
    for segment in binary.segments.iter().filter(|segment| segment.file_size > 0) {
        let bytes = binary.read(segment.address, segment.file_size).unwrap();
        let skip = if header || segment.file_offset != 0 { 0 } else { 0x1000.min(bytes.len()) };
        if skip < bytes.len() {
            script = script.memory(BASE + segment.address + skip as u64, &bytes[skip..]);
        }
    }
    script.memory(STACK, &[0; 0x100])
}

struct Harness {
    registry: DebugRegistry,
    tools: Vec<DebugTool>,
}

impl Harness {
    fn new(stub: &FakeStub) -> Self {
        let harness =
            Self { registry: DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap(), tools: debug_tools() };
        assert_eq!(harness.call("debug_connect", json!({})).unwrap()["epoch"], 1);
        harness
    }

    /// Connects and binds the fixture.
    fn bound(stub: &FakeStub) -> Self {
        let harness = Self::new(stub);
        let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
        assert_eq!(bound["binding"]["verification"]["outcome"], "matched", "{bound}");
        harness
    }

    fn call(&self, name: &str, input: Value) -> Result<Value, String> {
        self.call_cancellable(name, input, &DebugCancel::new())
    }

    fn call_cancellable(&self, name: &str, input: Value, cancel: &DebugCancel) -> Result<Value, String> {
        self.tools.iter().find(|tool| tool.name == name).unwrap().call_cancellable(&self.registry, input, cancel)
    }

    fn code(&self, name: &str, input: Value) -> String {
        let error = self.call(name, input).unwrap_err();
        error.split(':').next().unwrap().to_owned()
    }
}

/// The breakpoint and resume packets the stub received before the session started detaching (which first removes
/// every breakpoint still inserted, just before `D`).
fn execution(report: &Report) -> Vec<&String> {
    let detach = report.received.iter().position(|packet| packet == "D;1").unwrap_or(report.received.len());
    let removals = report.received[..detach].iter().rev().take_while(|packet| packet.starts_with('z')).count();
    report.received[..detach - removals]
        .iter()
        .filter(|packet| packet.starts_with(['Z', 'z']) || packet.starts_with("vCont;"))
        .collect()
}

/// Drops the harness (which detaches) and checks the stub saw only allowed packets.
fn finish(stub: FakeStub, harness: Harness) -> Report {
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    report
}

#[test]
fn the_fixture_has_the_layout_the_tests_assume() {
    assert_eq!(symbol("helper"), vec![HELPER_A, HELPER_B]);
    assert_eq!(symbol("leaf"), vec![LEAF]);
    assert_eq!(symbol("caller"), vec![CALLER]);
    assert_eq!(symbol("greeting"), vec![GREETING]);
    let binary = Binary::open(fixture()).unwrap();
    let call = binary.read(CALL_LEAF, 5).unwrap();
    assert_eq!(call[0], 0xe8, "call rel32 at {CALL_LEAF:#x}");
    assert!(matches!(&binary.details, rampage_loaders::Details::Elf(elf) if elf.build_id.is_some() && elf.pie));
}

#[test]
fn binds_by_build_id_with_a_verified_slide_and_replaces_on_rebinding() {
    let stub = FakeStub::tcp(x64(BASE + CALLER, "", true));
    let harness = Harness::new(&stub);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
    let binding = &bound["binding"];
    assert_eq!(binding["evidence"]["kind"], "build_id", "{bound}");
    assert_eq!(binding["evidence"]["build_id"], "96e90027b21845ab6c0893653a8e4b9d8f155c17");
    assert_eq!(binding["slide"], format!("{BASE:#x}"));
    assert_eq!(binding["verification"]["outcome"], "matched");
    assert_eq!(binding["arch"], "x86_64");
    assert_eq!(bound["replaced"], false);
    let again = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
    assert_eq!((again["replaced"].as_bool(), again["bindings"].as_u64()), (Some(true), Some(1)));
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(status["bindings"][0]["evidence"]["kind"], "build_id");
    // Disconnecting drops the bindings with the session.
    harness.call("debug_disconnect", json!({"session": "s1"})).unwrap();
    finish(stub, harness);
}

#[test]
fn binds_by_path_or_file_name_when_the_build_id_is_unreadable() {
    // The headers are not mapped, so only the module's name can match; the entry's bytes verify the slide.
    let path = fixture().display().to_string();
    let stub = FakeStub::tcp(x64(BASE + CALLER, &path, false));
    let harness = Harness::new(&stub);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": path})).unwrap();
    assert_eq!(bound["binding"]["evidence"]["kind"], "path", "{bound}");
    assert_eq!(bound["binding"]["verification"]["outcome"], "matched");
    finish(stub, harness);

    let stub = FakeStub::tcp(x64(BASE + CALLER, "/opt/elsewhere/correlation-x64.elf", false));
    let harness = Harness::new(&stub);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
    assert_eq!(bound["binding"]["evidence"]["kind"], "basename", "{bound}");
    assert_eq!(bound["binding"]["module"], "/opt/elsewhere/correlation-x64.elf");
    // A module filter that names no module refuses.
    assert_eq!(
        harness.code("debug_bind", json!({"session": "s1", "path": fixture(), "module": "libother.so"})),
        "no_module_match"
    );
    finish(stub, harness);
}

#[test]
fn refuses_without_a_match_unless_the_slide_is_explicit() {
    let stub = FakeStub::tcp(x64(BASE + CALLER, "/lib/libunrelated.so", false));
    let harness = Harness::new(&stub);
    let refused = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap_err();
    assert!(refused.starts_with("no_module_match"), "{refused}");
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["bindings"], json!([]));
    let bound =
        harness.call("debug_bind", json!({"session": "s1", "path": fixture(), "slide": format!("{BASE:#x}")})).unwrap();
    assert_eq!(bound["binding"]["evidence"]["kind"], "explicit_slide");
    assert_eq!(bound["binding"]["explicit_slide"], true);
    assert_eq!(bound["binding"]["verification"]["outcome"], "matched");
    finish(stub, harness);
}

#[test]
fn a_slide_that_does_not_verify_refuses_unless_explicit() {
    // The module's name matches, but the code mapped at its load bias is not the file's.
    let path = fixture().display().to_string();
    let script = x64(BASE + CALLER, &path, false).memory(BASE + 0x1000, &[0xcc; 0x400]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::new(&stub);
    let refused = harness.call("debug_bind", json!({"session": "s1", "path": path})).unwrap_err();
    assert!(refused.starts_with("slide_mismatch"), "{refused}");
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": path, "slide": BASE})).unwrap();
    assert_eq!(bound["binding"]["verification"]["outcome"], "mismatched");
    let limitations = bound["binding"]["limitations"].to_string();
    assert!(limitations.contains("slide verification failed"), "{limitations}");
    finish(stub, harness);
}

#[test]
fn a_project_of_another_architecture_is_refused() {
    let stub = FakeStub::tcp(x64(BASE + CALLER, "", true));
    let harness = Harness::new(&stub);
    let firmware =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware/cortex-m3.elf").canonicalize();
    let error = harness.call("debug_bind", json!({"session": "s1", "path": firmware.unwrap()})).unwrap_err();
    assert!(error.starts_with("arch_mismatch"), "{error}");
    finish(stub, harness);
}

#[test]
fn breakpoints_by_function_name_and_static_address_record_their_placement() {
    let script = x64(BASE + CALLER, "", true)
        .on(&format!("Z1,{:x},1", BASE + LEAF), "OK")
        .on(&format!("Z0,{:x},1", BASE + CALL_LEAF), "OK");
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let set = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "leaf"}),
        )
        .unwrap();
    let breakpoint = &set["breakpoint"];
    assert_eq!(breakpoint["address"], format!("{:#x}", BASE + LEAF));
    assert_eq!(breakpoint["placement"]["static_address"], format!("{LEAF:#x}"));
    assert_eq!(breakpoint["placement"]["function"], "leaf");
    assert_eq!(breakpoint["placement"]["offset_in_function"], 0);
    let set = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "software", "static_address": format!("{CALL_LEAF:#x}"), "path": fixture()}),
        )
        .unwrap();
    assert_eq!(set["breakpoint"]["address"], format!("{:#x}", BASE + CALL_LEAF));
    assert_eq!(set["breakpoint"]["placement"]["function"], "caller");
    assert_eq!(set["breakpoint"]["placement"]["offset_in_function"], CALL_LEAF - CALLER);
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["items"][0]["placement"]["function"], "leaf");

    // Exactly one placement, and only within the bound image.
    let both =
        json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "leaf", "address": 4});
    assert_eq!(harness.code("debug_breakpoints", both), "invalid_argument");
    let outside =
        json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "static_address": "0x900000"});
    assert_eq!(harness.code("debug_breakpoints", outside), "invalid_argument");
    let missing = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "no_such_fn"});
    assert!(harness.call("debug_breakpoints", missing).unwrap_err().contains("no function or symbol named"));
    finish(stub, harness);
}

#[test]
fn an_ambiguous_function_name_is_refused_with_its_candidates() {
    let stub = FakeStub::tcp(x64(BASE + CALLER, "", true));
    let harness = Harness::bound(&stub);
    let error = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "helper"}),
        )
        .unwrap_err();
    assert!(error.starts_with("ambiguous_name"), "{error}");
    assert!(error.contains(&format!("helper@{HELPER_A:#x}")) && error.contains(&format!("helper@{HELPER_B:#x}")));
    // Unbound sessions have nothing to resolve names in.
    finish(stub, harness);
    let stub = FakeStub::tcp(x64(BASE + CALLER, "", true));
    let harness = Harness::new(&stub);
    let unbound = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "leaf"});
    assert_eq!(harness.code("debug_breakpoints", unbound), "not_bound");
    finish(stub, harness);
}

#[test]
fn stops_are_located_in_the_bound_project() {
    let script = x64(BASE + CALLER, "", true)
        .on(&format!("Z1,{:x},1", BASE + LEAF), "OK")
        .on_actions("vCont;c", vec![Action::Reply(stop(BASE + LEAF))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "leaf"}),
        )
        .unwrap();
    let hit = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(hit["event"]["reason"], "breakpoint", "{hit}");
    let pc = &hit["locations"]["pc"]["location"];
    assert_eq!(pc["function"], "leaf");
    assert_eq!(pc["offset_in_function"], 0);
    assert_eq!(pc["static_address"], format!("{LEAF:#x}"));
    assert_eq!(pc["show_address"]["at"], format!("{LEAF:#x}"));
    assert_eq!(pc["show_address"]["path"], fixture().display().to_string());
    assert_eq!(hit["locations"]["breakpoints"][0]["location"]["function"], "leaf");
    finish(stub, harness);

    // Without a binding the location is null with the reason.
    let stub = FakeStub::tcp(
        x64(BASE + CALLER, "", true)
            .on_actions("vCont;c", vec![Action::Reply(format!("T05thread:p01.01;10:{};", le_hex(0x1234, 8)))]),
    );
    let harness = Harness::new(&stub);
    let stopped = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(stopped["locations"]["pc"]["location"], Value::Null);
    assert!(stopped["locations"]["pc"]["reason"].as_str().unwrap().contains("no project is bound"));
    finish(stub, harness);
}

#[test]
fn register_values_pointing_into_the_image_are_annotated() {
    let script = x64_rdi(BASE + CALL_LEAF, "", true, BASE + GREETING);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let registers = harness
        .call("debug_registers", json!({"session": "s1", "names": ["rip", "rdi", "rsp", "rax"], "annotate": true}))
        .unwrap();
    let items = registers["registers"]["items"].as_array().unwrap();
    let by_name = |name: &str| items.iter().find(|item| item["name"] == name).unwrap();
    let rip = &by_name("rip")["points_to"];
    assert_eq!((rip["kind"].as_str(), rip["function"].as_str()), (Some("code"), Some("caller")));
    assert_eq!(rip["offset_in_function"], CALL_LEAF - CALLER);
    let rdi = &by_name("rdi")["points_to"];
    assert_eq!(rdi["kind"], "string", "{rdi}");
    assert_eq!(rdi["string"], "rampage correlation fixture");
    assert_eq!(rdi["symbol"], "greeting");
    // The stack and zero are outside the image.
    assert!(by_name("rsp").get("points_to").is_none());
    assert!(by_name("rax").get("points_to").is_none());
    // Without annotate the result is as before.
    let plain = harness.call("debug_registers", json!({"session": "s1", "names": ["rdi"]})).unwrap();
    assert!(plain["registers"]["items"][0].get("points_to").is_none());
    finish(stub, harness);
}

#[test]
fn stepping_over_a_call_runs_to_the_next_instruction_and_removes_the_temporary_breakpoint() {
    let script = x64(BASE + CALL_LEAF, "", true)
        // Before the call, at the return (its frame checked) and before the next step.
        .once("g", vec![Action::Reply(g(BASE + CALL_LEAF, STACK, 0))])
        .once("g", vec![Action::Reply(g(BASE + AFTER_CALL, STACK, 0))])
        .once("g", vec![Action::Reply(g(BASE + AFTER_CALL, STACK, 0))])
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;c", vec![Action::Reply(stop(BASE + AFTER_CALL))])
        .on_actions("vCont;s:p1.1", vec![Action::Reply(stop(BASE + AFTER_CALL + 3))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true, "count": 2})).unwrap();
    assert_eq!((over["completed"].as_u64(), over["epoch"].as_u64()), (Some(2), Some(3)), "{over}");
    let steps = over["steps"].as_array().unwrap();
    assert_eq!(steps[0]["flow"], "call");
    assert_eq!(steps[0]["bytes_source"], "target_memory");
    assert_eq!(steps[0]["outcome"], "returned");
    assert_eq!(steps[0]["return_address"], format!("{:#x}", BASE + AFTER_CALL));
    assert_eq!(steps[1]["flow"], "next");
    assert_eq!(steps[1]["outcome"], "stepped");
    assert_eq!(over["locations"]["pc"]["location"]["function"], "caller");
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);
    let report = finish(stub, harness);
    assert_eq!(
        execution(&report),
        [
            &format!("Z1,{:x},1", BASE + AFTER_CALL),
            &"vCont;c".to_owned(),
            &format!("z1,{:x},1", BASE + AFTER_CALL),
            &"vCont;s:p1.1".to_owned()
        ]
    );
}

#[test]
fn the_stop_of_a_call_over_is_reported_when_it_is_not_the_temporary_breakpoint() {
    // A fault inside the callee stops the run first: the temporary breakpoint still goes at that stop.
    let script = x64(BASE + CALL_LEAF, "", true)
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;c", vec![Action::Reply(format!("T0bthread:p01.01;10:{};", le_hex(BASE + LEAF + 4, 8)))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true})).unwrap();
    assert_eq!(over["completed"], 0, "{over}");
    assert_eq!(over["steps"][0]["outcome"], "stopped_elsewhere");
    assert_eq!(over["event"]["reason"], "signal");
    assert_eq!(over["event"]["temporary"][0]["hit"], false);
    assert_eq!(over["event"]["temporary"][0]["removed"], true);
    assert_eq!(over["locations"]["pc"]["location"]["function"], "leaf");
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);
    finish(stub, harness);
}

#[test]
fn a_call_over_that_times_out_or_is_cancelled_removes_its_breakpoint_at_the_next_stop() {
    for cancelled in [false, true] {
        let script = x64(BASE + CALL_LEAF, "", true)
            .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
            .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
            .on_actions("vCont;c", vec![])
            .on_interrupt(vec![Action::Reply(format!("T02thread:p01.01;10:{};", le_hex(BASE + LEAF + 1, 8)))]);
        let stub = FakeStub::tcp(script);
        let harness = Harness::bound(&stub);
        let cancel = DebugCancel::new();
        let input =
            json!({"session": "s1", "epoch": 1, "over": true, "timeout_ms": if cancelled { 30_000 } else { 200 }});
        let over = if cancelled {
            let canceller = cancel.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                canceller.cancel();
            });
            harness.call_cancellable("debug_step", input, &cancel).unwrap()
        } else {
            harness.call("debug_step", input).unwrap()
        };
        assert_eq!(over["state"], "running", "{over}");
        assert_eq!(over["cancelled"], cancelled);
        assert_eq!(over["steps"][0]["outcome"], if cancelled { "cancelled" } else { "running" });
        assert!(over["warnings"].to_string().contains("removed at the next stop"));
        let listed = harness.call("debug_status", json!({"session": "s1"})).unwrap();
        assert_eq!(listed["state"], "running");
        let interrupted = harness.call("debug_interrupt", json!({"session": "s1"})).unwrap();
        assert_eq!(interrupted["event"]["reason"], "interrupted", "{interrupted}");
        assert_eq!(interrupted["event"]["temporary"][0]["removed"], true);
        assert_eq!(interrupted["event"]["temporary"][0]["hit"], false);
        let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
        assert_eq!(listed["breakpoints"]["total"], 0);
        let report = finish(stub, harness);
        assert!(report.received.contains(&format!("z1,{:x},1", BASE + AFTER_CALL)));
    }
}

#[test]
fn user_breakpoints_at_the_pc_and_the_return_address_survive_a_step_over() {
    // A user breakpoint at the call is stepped past (taken out, one step, put back); one at the return address
    // stands in for the temporary breakpoint and stays.
    let script = x64(BASE + CALL_LEAF, "", true)
        .once("g", vec![Action::Reply(g(BASE + CALL_LEAF, STACK, 0))])
        .on(&format!("Z1,{:x},1", BASE + CALL_LEAF), "OK")
        .on(&format!("z1,{:x},1", BASE + CALL_LEAF), "OK")
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;s:p1.1", vec![Action::Reply(stop(BASE + LEAF))])
        .on_actions("vCont;c", vec![Action::Reply(stop(BASE + AFTER_CALL))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let at_pc = harness
        .call("debug_breakpoints", json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "static_address": format!("{CALL_LEAF:#x}")}))
        .unwrap()["breakpoint"]["id"]
        .as_u64()
        .unwrap();
    let at_return = harness
        .call("debug_breakpoints", json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "static_address": format!("{AFTER_CALL:#x}")}))
        .unwrap()["breakpoint"]["id"]
        .as_u64()
        .unwrap();
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true})).unwrap();
    assert_eq!(over["completed"], 1, "{over}");
    assert_eq!(over["steps"][0]["outcome"], "returned");
    assert_eq!(over["steps"][0]["temporary_breakpoint"], Value::Null);
    assert_eq!(over["steps"][0]["user_breakpoint"], at_return);
    assert_eq!(over["event"]["reason"], "breakpoint");
    assert_eq!(over["event"]["breakpoints"], json!([at_return]));
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    let items = listed["breakpoints"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item["inserted"] == true && item.get("temporary").is_none()));
    assert_eq!(items.iter().find(|item| item["id"] == at_return).unwrap()["hits"], 1);
    assert_eq!(items.iter().find(|item| item["id"] == at_pc).unwrap()["hits"], 0);
    let report = finish(stub, harness);
    assert_eq!(
        execution(&report),
        [
            &format!("Z1,{:x},1", BASE + CALL_LEAF),
            &format!("Z1,{:x},1", BASE + AFTER_CALL),
            &format!("z1,{:x},1", BASE + CALL_LEAF),
            &"vCont;s:p1.1".to_owned(),
            &format!("Z1,{:x},1", BASE + CALL_LEAF),
            &"vCont;c".to_owned(),
        ]
    );
}

#[test]
fn a_non_call_over_step_steps_past_a_user_breakpoint_at_the_pc() {
    let script = x64(BASE + AFTER_CALL, "", true)
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;s:p1.1", vec![Action::Reply(stop(BASE + AFTER_CALL + 3))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    harness
        .call("debug_breakpoints", json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "static_address": format!("{AFTER_CALL:#x}")}))
        .unwrap();
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true})).unwrap();
    assert_eq!(
        (over["completed"].as_u64(), over["steps"][0]["outcome"].as_str()),
        (Some(1), Some("stepped")),
        "{over}"
    );
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["items"][0]["inserted"], true);
    let report = finish(stub, harness);
    assert_eq!(
        execution(&report),
        [
            &format!("Z1,{:x},1", BASE + AFTER_CALL),
            &format!("z1,{:x},1", BASE + AFTER_CALL),
            &"vCont;s:p1.1".to_owned(),
            &format!("Z1,{:x},1", BASE + AFTER_CALL),
        ]
    );
}

#[test]
fn stepping_out_runs_from_a_function_entry_to_its_return_address() {
    let mut stack = vec![0u8; 0x100];
    stack[..8].copy_from_slice(&(BASE + AFTER_CALL).to_le_bytes());
    // At the return, ret has popped the return address: the stack pointer is 8 above the entry's.
    let script = x64(BASE + LEAF, "", true)
        .memory(STACK, &stack)
        .once("g", vec![Action::Reply(g(BASE + LEAF, STACK, 0))])
        .once("g", vec![Action::Reply(g(BASE + AFTER_CALL, STACK + 8, 0))])
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;c", vec![Action::Reply(stop(BASE + AFTER_CALL))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let out = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "out": true})).unwrap();
    assert_eq!(out["mode"], "out");
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(out["steps"][0]["return_address"], format!("{:#x}", BASE + AFTER_CALL));
    assert_eq!(out["event"]["reason"], "temporary_breakpoint");
    assert_eq!(out["locations"]["pc"]["location"]["function"], "caller");
    assert_eq!(out["locations"]["pc"]["location"]["offset_in_function"], AFTER_CALL - CALLER);
    assert!(out["rule"].as_str().unwrap().contains("first instruction"));
    assert_eq!(hex(out["event"]["pc"].clone()), BASE + AFTER_CALL);
    finish(stub, harness);

    // Anywhere but a function's entry, the return address is not trusted.
    let stub = FakeStub::tcp(x64(BASE + LEAF + 4, "", true));
    let harness = Harness::bound(&stub);
    let refused = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "out": true})).unwrap_err();
    assert!(refused.starts_with("step_out_refused") && refused.contains("leaf+0x4"), "{refused}");
    let both = json!({"session": "s1", "epoch": 1, "out": true, "over": true});
    assert_eq!(harness.code("debug_step", both), "invalid_argument");
    finish(stub, harness);
}

#[test]
fn evidence_is_bounded_and_accepted_by_the_findings_ledger() {
    let script = x64_rdi(BASE + LEAF, "", true, BASE + GREETING);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let evidence = harness
        .call(
            "debug_evidence",
            json!({"session": "s1", "epoch": 1, "memory": [{"address": format!("{:#x}", BASE + GREETING), "length": 8}]}),
        )
        .unwrap();
    assert_eq!(evidence["epoch"], 1);
    assert_eq!(evidence["pc"]["location"]["function"], "leaf");
    assert_eq!(evidence["memory"][0]["hex"], rampage_arch::hex::bytes(b"rampage "));
    let item = evidence["ledger_evidence"].clone();
    assert_eq!(item["tool"], "debug_evidence");
    let detail = item["detail"].as_str().unwrap();
    assert!(detail.len() <= 300 && detail.contains("(leaf+0x0)") && detail.contains("epoch 1"), "{detail}");
    let too_many = json!({"session": "s1", "memory": [{"address": 0, "length": 65}]});
    assert_eq!(harness.code("debug_evidence", too_many), "invalid_argument");
    finish(stub, harness);

    // record_finding takes it as one of its evidence items.
    let directory = std::env::temp_dir().join(format!("rampage-debug-evidence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let copy = directory.join("correlation-x64.elf");
    std::fs::copy(fixture(), &copy).unwrap();
    let project = rampage_api::Session::default().open(&copy, None).unwrap();
    let request: rampage_api::LedgerRequest = serde_json::from_value(json!({
        "kind": "finding",
        "text": "leaf is reached with rdi pointing at greeting",
        "function": "leaf",
        "evidence": [item],
    }))
    .unwrap();
    let recorded = project.record_finding(&request).unwrap();
    assert_eq!(recorded.finding.evidence[0].tool, "debug_evidence");
    drop(project);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn a_return_address_reached_by_an_inner_frame_is_not_a_return() {
    // A recursive call reaches the instruction after the call with a deeper stack: the run stops there, reported
    // as inner_frame, and nothing more runs.
    let script = x64(BASE + CALL_LEAF, "", true)
        .once("g", vec![Action::Reply(g(BASE + CALL_LEAF, STACK, 0))])
        .once("g", vec![Action::Reply(g(BASE + AFTER_CALL, STACK - 0x40, 0))])
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;c", vec![Action::Reply(stop(BASE + AFTER_CALL))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true, "count": 3})).unwrap();
    assert_eq!(over["completed"], 0, "{over}");
    assert_eq!(over["steps"].as_array().unwrap().len(), 1);
    assert_eq!(over["steps"][0]["outcome"], "inner_frame");
    assert!(over["warnings"].to_string().contains("inner (recursive) frame"));
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);
    finish(stub, harness);

    // Another thread reaching it is not the return either.
    let script = x64(BASE + CALL_LEAF, "", true)
        .on("qfThreadInfo", "mp01.01,p01.02")
        .on("qThreadExtraInfo,p1.2", "")
        .on(&format!("Z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on(&format!("z1,{:x},1", BASE + AFTER_CALL), "OK")
        .on_actions("vCont;c", vec![Action::Reply(format!("T05thread:p01.02;10:{};", le_hex(BASE + AFTER_CALL, 8)))]);
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let over = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "over": true})).unwrap();
    assert_eq!(over["steps"][0]["outcome"], "other_thread", "{over}");
    assert_eq!(over["completed"], 0);
    finish(stub, harness);
}

/// A copy of the fixture with one byte of `use_b` (far from the entry point and headers) changed: a rebuild that
/// keeps the build ID and the first bytes of every segment.
fn stale_copy(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-debug-stale-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let copy = directory.join("correlation-x64.elf");
    let mut bytes = std::fs::read(fixture()).unwrap();
    let binary = Binary::open(fixture()).unwrap();
    let use_b = symbol("use_b")[0];
    let segment = binary.segment_containing(use_b).unwrap();
    let offset = (segment.file_offset + use_b - segment.address) as usize;
    bytes[offset] ^= 0xff;
    std::fs::write(&copy, bytes).unwrap();
    copy
}

#[test]
fn a_stale_build_does_not_verify() {
    // The build ID still matches (only code changed), so only the bytes compared over the image tell them apart.
    let stub = FakeStub::tcp(x64(BASE + CALLER, "", true));
    let harness = Harness::new(&stub);
    let stale = stale_copy("id");
    let refused = harness.call("debug_bind", json!({"session": "s1", "path": stale})).unwrap_err();
    assert!(refused.starts_with("slide_mismatch") && refused.contains("differs from the file"), "{refused}");
    finish(stub, harness);
    std::fs::remove_dir_all(stale.parent().unwrap()).unwrap();

    // Without a module list (bare metal), the same image mapped at 0 matches, and the stale one does not.
    let bare = |script: Script| {
        let binary = Binary::open(fixture()).unwrap();
        let mut script = script;
        for segment in binary.segments.iter().filter(|segment| segment.file_size > 0) {
            script = script.memory(segment.address, binary.read(segment.address, segment.file_size).unwrap());
        }
        script
    };
    let stub = FakeStub::tcp(bare(x64_bare(CALLER)));
    let harness = Harness::new(&stub);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
    assert_eq!(bound["binding"]["evidence"]["kind"], "mapped_bytes", "{bound}");
    assert!(bound["binding"]["evidence"]["windows"].as_u64().unwrap() > 3);
    let stale = stale_copy("bare");
    let refused = harness.call("debug_bind", json!({"session": "s1", "path": stale})).unwrap_err();
    assert!(refused.starts_with("no_module_match"), "{refused}");
    finish(stub, harness);
    std::fs::remove_dir_all(stale.parent().unwrap()).unwrap();
}

#[test]
fn function_breakpoints_need_code() {
    let script = x64(BASE + CALLER, "", true)
        .on(&format!("Z2,{:x},4", BASE + GREETING), "OK")
        .on(&format!("z2,{:x},4", BASE + GREETING), "OK");
    let stub = FakeStub::tcp(script);
    let harness = Harness::bound(&stub);
    let data = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "greeting"});
    assert_eq!(harness.code("debug_breakpoints", data), "not_code");
    // A watchpoint on the data is placed by static address, at its exact runtime address.
    let watch = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "write", "length": 4, "static_address": GREETING}),
        )
        .unwrap();
    assert_eq!(watch["breakpoint"]["address"], format!("{:#x}", BASE + GREETING));
    finish(stub, harness);
}
