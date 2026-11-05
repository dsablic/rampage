#![cfg(unix)]

//! The debug write tools and kill (phase 9.4) against the scripted fake stub. Scripts accept writes only when
//! marked `.writes()` and kill only when marked `.kill()`, checked independently of the client's allowlist.

use rampage_api::tools::{DebugTool, Effect, debug_tools, debug_tools_with};
use rampage_api::{DebugConsent, DebugRegistry};
use rampage_debug::fake::{Action, FakeStub, Script, le_hex, transcripts};
use serde_json::{Value, json};

const WRITES: DebugConsent = DebugConsent { writes: true, kill: false };
const KILL: DebugConsent = DebugConsent { writes: false, kill: true };
const BOTH: DebugConsent = DebugConsent { writes: true, kill: true };

/// The Cortex-M transcript's `g` reply with r0 and r1 set.
fn g_with(r0: u32, r1: u32) -> String {
    let mut g = le_hex(u64::from(r0), 4) + &le_hex(u64::from(r1), 4);
    g.push_str(&"00000000".repeat(11));
    g.push_str("00000120ffffffff4800000000000041");
    g
}

/// QEMU's Cortex-M3 transcript accepting writes, with `qSupported` advertising `size`-byte packets.
fn qemu(size: &str) -> Script {
    transcripts::qemu_cortex_m3().writes().once(
        "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
        vec![Action::Reply(format!(
            "PacketSize={size};qXfer:features:read+;vContSupported+;multiprocess+;qXfer:memory-map:read+"
        ))],
    )
}

struct Harness {
    registry: DebugRegistry,
    tools: Vec<DebugTool>,
}

impl Harness {
    fn new(stub: &FakeStub, consent: DebugConsent) -> Self {
        Self::listing(stub, consent, consent)
    }

    /// A registry with `consent` serving the tools a server with `listed` would list.
    fn listing(stub: &FakeStub, consent: DebugConsent, listed: DebugConsent) -> Self {
        let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap().with_consent(consent);
        let harness = Self { registry, tools: debug_tools_with(listed) };
        assert_eq!(harness.call("debug_connect", json!({})).unwrap()["epoch"], 1);
        harness
    }

    fn call(&self, name: &str, input: Value) -> Result<Value, String> {
        self.tools.iter().find(|tool| tool.name == name).unwrap().call(&self.registry, input)
    }

    fn code(&self, name: &str, input: Value) -> String {
        let error = self.call(name, input).unwrap_err();
        error.split(':').next().unwrap().to_owned()
    }

    fn write(&self, address: u64, bytes: &str) -> Result<Value, String> {
        self.call("debug_write_memory", json!({"session": "s1", "epoch": 1, "address": address, "bytes": bytes}))
    }

    fn read(&self, address: u64, length: usize) -> String {
        let read = self.call("debug_read_memory", json!({"session": "s1", "address": address, "length": length}));
        read.unwrap()["data"][0]["hex"].as_str().unwrap().to_owned()
    }
}

/// The write and kill packets among `received`.
fn writes(received: &[String]) -> Vec<&str> {
    received
        .iter()
        .filter(|packet| ["M", "X", "P", "G", "k", "vKill"].iter().any(|prefix| packet.starts_with(prefix)))
        .map(String::as_str)
        .collect()
}

#[test]
fn write_tools_and_the_kill_option_exist_only_with_the_operators_flags() {
    let names = |tools: &[DebugTool]| tools.iter().map(|tool| tool.name).collect::<Vec<_>>();
    let schema =
        |tools: &[DebugTool]| tools.iter().find(|tool| tool.name == "debug_disconnect").unwrap().input_schema.clone();
    let plain = debug_tools();
    assert_eq!(names(&plain), names(&debug_tools_with(DebugConsent::default())));
    assert!(!names(&plain).iter().any(|name| name.starts_with("debug_write")));
    assert!(schema(&plain)["properties"].get("kill").is_none());
    assert!(!names(&debug_tools_with(KILL)).iter().any(|name| name.starts_with("debug_write")));
    assert!(schema(&debug_tools_with(KILL))["properties"]["kill"].is_object());
    assert!(schema(&debug_tools_with(WRITES))["properties"].get("kill").is_none());
    let with_writes = debug_tools_with(WRITES);
    assert_eq!(with_writes.len(), plain.len() + 2);
    for name in ["debug_write_memory", "debug_write_register"] {
        let tool = with_writes.iter().find(|tool| tool.name == name).unwrap();
        assert_eq!(tool.effect, Effect::TargetWrite, "{name}");
        for phrase in ["--debug-writes", "verified", "No automatic writes", "Destructive"] {
            assert!(tool.description.contains(phrase), "{name}: {phrase}");
        }
    }
    let memory = with_writes.iter().find(|tool| tool.name == "debug_write_memory").unwrap();
    assert!(memory.description.contains("No flash programming"));
    let kill = debug_tools_with(KILL);
    let disconnect = kill.iter().find(|tool| tool.name == "debug_disconnect").unwrap();
    assert!(disconnect.description.contains("--debug-kill") && disconnect.description.contains("vKill"));
    assert!(plain.iter().find(|tool| tool.name == "debug_disconnect").unwrap().description.contains("never kills"));
}

#[test]
fn without_the_flags_writes_and_kill_are_refused_before_anything_is_sent() {
    // A read-only script: any write or kill packet fails the test.
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    // The tools are listed as though writes were allowed; the registry still refuses.
    let harness = Harness::listing(&stub, DebugConsent::default(), WRITES);
    for (name, input) in [
        ("debug_write_memory", json!({"session": "s1", "epoch": 1, "address": 0x2000_0000u32, "bytes": "01"})),
        ("debug_write_register", json!({"session": "s1", "epoch": 1, "name": "r0", "value": "01000000"})),
        ("debug_disconnect", json!({"session": "s1", "kill": true})),
    ] {
        let error = harness.call(name, input).unwrap_err();
        assert!(error.starts_with("not_allowed"), "{name}: {error}");
        assert!(error.contains("--debug-writes") || error.contains("--debug-kill"), "{error}");
    }
    // A kill refused leaves the session open; a plain disconnect then detaches.
    let detached = harness.call("debug_disconnect", json!({"session": "s1", "kill": false})).unwrap();
    assert_eq!((detached["state"].as_str(), detached["detached"].as_bool()), (Some("detached"), Some(true)));
    assert!(detached.get("kill").is_none());
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert!(writes(&report.received).is_empty(), "{:?}", report.received);
}

/// The session's own check, independent of the registry and the tools.
#[test]
fn a_session_refuses_writes_and_kill_it_was_not_configured_for() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let config = rampage_debug::Config { consent: WRITES, ..rampage_debug::Config::default() };
    let session = rampage_debug::Session::connect(&stub.endpoint().parse().unwrap(), config).unwrap();
    let error = session.kill().unwrap_err();
    assert_eq!(error.code(), "not_allowed");
    assert!(error.to_string().contains("--debug-kill"), "{error}");
    let read_only = rampage_debug::Config::default();
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let session = rampage_debug::Session::connect(&stub.endpoint().parse().unwrap(), read_only).unwrap();
    for error in [
        session.write_memory(Some(1), 0x2000_0000, &[1], None).unwrap_err(),
        session.write_register(Some(1), None, "r0", &[0; 4]).unwrap_err(),
    ] {
        assert_eq!(error.code(), "not_allowed");
        assert!(error.to_string().contains("--debug-writes"), "{error}");
    }
    assert_eq!(session.status().unwrap().state, rampage_debug::State::Stopped);
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn a_memory_write_reads_before_writes_with_x_and_verifies() {
    let stub = FakeStub::tcp(qemu("20020"));
    let harness = Harness::new(&stub, WRITES);
    let written = harness.write(0x2000_0010, "deadbeef").unwrap();
    assert_eq!((written["before"].as_str(), written["after"].as_str()), (Some("00000000"), Some("deadbeef")));
    assert_eq!((written["complete"].as_bool(), written["verified"].as_bool()), (Some(true), Some(true)));
    assert_eq!(written["epoch"], 1);
    assert_eq!(
        written["chunks"],
        json!([{"address": "0x20000010", "length": 4, "packet": "X", "written": true, "error": null}])
    );
    assert_eq!(harness.read(0x2000_0010, 4), "deadbeef");

    // A stale view: expect differs from what is there, so nothing is written.
    let refused = harness
        .call(
            "debug_write_memory",
            json!({"session": "s1", "epoch": 1, "address": 0x2000_0010, "bytes": "01020304", "expect": "00000000"}),
        )
        .unwrap_err();
    assert!(refused.starts_with("expect_mismatch") && refused.contains("deadbeef"), "{refused}");
    assert_eq!(harness.read(0x2000_0010, 4), "deadbeef");
    let swapped = harness
        .call(
            "debug_write_memory",
            json!({"session": "s1", "epoch": 1, "address": 0x2000_0010, "bytes": "01020304", "expect": "deadbeef"}),
        )
        .unwrap();
    assert_eq!(swapped["verified"], true);

    // Argument and epoch checks.
    for (input, code) in [
        (json!({"session": "s1", "epoch": 7, "address": 0x2000_0000, "bytes": "00"}), "stale_epoch"),
        (json!({"session": "s1", "epoch": 1, "address": 0x2000_0000, "bytes": ""}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "address": 0x2000_0000, "bytes": "0x00"}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "address": 0x2000_0000, "bytes": "abc"}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "address": 0x2000_0000, "bytes": "00".repeat(4097)}), "invalid_argument"),
        (
            json!({"session": "s1", "epoch": 1, "address": 0x2000_0000, "bytes": "00", "expect": "0000"}),
            "invalid_argument",
        ),
        (json!({"session": "s1", "epoch": 1, "address": "0xffffffffffffffff", "bytes": "0000"}), "invalid_argument"),
    ] {
        assert_eq!(harness.code("debug_write_memory", input.clone()), code, "{input}");
    }
    // Unmapped memory cannot be read first, so nothing is written there.
    let unmapped = harness.write(0x3000_0000, "00").unwrap_err();
    assert!(unmapped.starts_with("target_error") && unmapped.contains("nothing was written"), "{unmapped}");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(writes(&report.received).len(), 2, "{:?}", report.received);
}

#[test]
fn a_stub_without_x_gets_m_and_later_writes_skip_the_probe() {
    let stub = FakeStub::tcp(qemu("20020").on_prefix("X", vec![Action::Reply(String::new())]));
    let harness = Harness::new(&stub, WRITES);
    let first = harness.write(0x2000_0020, "0102").unwrap();
    assert_eq!(first["chunks"][0]["packet"], "M");
    assert_eq!(first["verified"], true);
    let second = harness.write(0x2000_0022, "0304").unwrap();
    assert_eq!(second["chunks"][0]["packet"], "M");
    assert_eq!(harness.read(0x2000_0020, 4), "01020304");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(writes(&report.received), ["X20000020,2:\u{1}\u{2}", "M20000020,2:0102", "M20000022,2:0304"]);
}

#[test]
fn a_refused_chunk_stops_the_write_and_reports_exactly_what_was_written() {
    // 96-byte packets carry 32-byte chunks; the second chunk's range refuses writes.
    let stub = FakeStub::tcp(qemu("60").refuse_writes(0x2000_0030, 1));
    let harness = Harness::new(&stub, WRITES);
    let written = harness.write(0x2000_0000, &"ab".repeat(80)).unwrap();
    assert_eq!((written["complete"].as_bool(), written["verified"].as_bool()), (Some(false), Some(false)));
    let chunks = written["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 2, "{chunks:?}");
    assert_eq!((chunks[0]["address"].as_str(), chunks[0]["written"].as_bool()), (Some("0x20000000"), Some(true)));
    assert_eq!((chunks[1]["address"].as_str(), chunks[1]["written"].as_bool()), (Some("0x20000020"), Some(false)));
    assert!(chunks[1]["error"].as_str().unwrap().contains("E0e"));
    assert_eq!(written["after"].as_str().unwrap(), "ab".repeat(32) + &"00".repeat(48));
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    // Nothing after the refusal, and no retry.
    assert_eq!(writes(&report.received).len(), 2);
}

#[test]
fn a_write_the_target_drops_is_reported_unverified() {
    // Flash that answers OK and keeps its contents.
    let stub = FakeStub::tcp(qemu("20020").ignore_writes(0, 0x40000));
    let harness = Harness::new(&stub, WRITES);
    let written = harness.write(0, "ffffffff").unwrap();
    assert_eq!((written["complete"].as_bool(), written["verified"].as_bool()), (Some(true), Some(false)));
    assert_eq!((written["before"].as_str(), written["after"].as_str()), (Some("00000120"), Some("00000120")));
    drop(harness);
    stub.finish().assert_clean();
}

#[test]
fn a_write_under_a_software_breakpoint_is_refused_temporary_ones_included() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .execution()
            .on("Z0,20000004,2", "OK")
            .on("z0,20000004,2", "OK")
            .on("Z1,20000100,2", "")
            .on("Z0,20000100,2", "OK")
            .on("z0,20000100,2", "OK")
            .on("Z1,20000080,2", "OK")
            .on("z1,20000080,2", "OK"),
    );
    let harness = Harness::new(&stub, WRITES);
    let set = |kind: &str, address: u64| {
        harness
            .call(
                "debug_breakpoints",
                json!({"session": "s1", "action": "set", "epoch": 1, "kind": kind, "address": address}),
            )
            .unwrap()
    };
    set("software", 0x2000_0004);
    let refused = harness.write(0x2000_0000, "0000000000").unwrap_err();
    assert!(refused.starts_with("invalid_argument") && refused.contains("software breakpoint 1"), "{refused}");
    // Bytes next to it are fine.
    assert_eq!(harness.write(0x2000_0000, "11223344").unwrap()["verified"], true);
    assert_eq!(harness.write(0x2000_0006, "55").unwrap()["verified"], true);
    // A hardware breakpoint keeps no bytes, so it does not stand in the way.
    set("hardware", 0x2000_0080);
    assert_eq!(harness.write(0x2000_0080, "66").unwrap()["verified"], true);
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with("X20000000,5")));
}

/// A step's temporary software breakpoint (when no hardware one can be placed) stands in the way as a table one does.
#[test]
fn a_write_under_a_temporary_software_breakpoint_is_refused() {
    let stub = FakeStub::tcp(
        qemu("20020").execution().on("Z1,20000100,2", "").on("Z0,20000100,2", "OK").on("z0,20000100,2", "OK"),
    );
    let config = rampage_debug::Config { consent: WRITES, ..rampage_debug::Config::default() };
    let session = rampage_debug::Session::connect(&stub.endpoint().parse().unwrap(), config).unwrap();
    let placed = session.set_temporary(Some(1), 0x2000_0100, None, None).unwrap();
    assert!(matches!(placed, rampage_debug::TemporaryPlacement::Inserted { ref breakpoint } if breakpoint.temporary));
    let error = session.write_memory(Some(1), 0x2000_00ff, &[0, 0], None).unwrap_err();
    assert_eq!(error.code(), "invalid_argument");
    assert!(error.to_string().contains("temporary software breakpoint"), "{error}");
    assert!(session.write_memory(Some(1), 0x2000_00fe, &[7, 7], None).unwrap().verified);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with("X200000ff")));
}

#[test]
fn a_register_write_uses_p_and_reads_back() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .on("P0=78563412", "OK")
            .once("g", vec![Action::Reply(g_with(0, 0))])
            .once("g", vec![Action::Reply(g_with(0x1234_5678, 0))]),
    );
    let harness = Harness::new(&stub, WRITES);
    let written = harness
        .call("debug_write_register", json!({"session": "s1", "epoch": 1, "name": "r0", "value": 0x1234_5678}))
        .unwrap();
    assert_eq!((written["packet"].as_str(), written["verified"].as_bool()), (Some("P"), Some(true)));
    assert_eq!((written["before"].as_str(), written["after"].as_str()), (Some("00000000"), Some("78563412")));
    assert_eq!(written["after_value"], "0x12345678");
    assert_eq!((written["epoch"].as_u64(), written["thread"].as_str()), (Some(1), Some("p1.1")));
    for (input, code) in [
        (json!({"session": "s1", "epoch": 1, "name": "r0", "value": 0x1_0000_0000u64}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "name": "r0", "value": "785634"}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "name": "r0", "value": "0x78563412"}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 1, "name": "r99", "value": 1}), "invalid_argument"),
        (json!({"session": "s1", "epoch": 2, "name": "r0", "value": 1}), "stale_epoch"),
        (json!({"session": "s1", "epoch": 1, "name": "r0", "value": -1}), "invalid arguments"),
    ] {
        assert_eq!(harness.code("debug_write_register", input.clone()), code, "{input}");
    }
    // Writing does not move the epoch, even though nothing stopped.
    assert_eq!(harness.call("debug_status", json!({"session": "s1"})).unwrap()["epoch"], 1);
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(writes(&report.received), ["P0=78563412"]);
}

#[test]
fn a_stub_without_p_gets_g_then_g_with_one_register_changed() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .on_prefix("P", vec![Action::Reply(String::new())])
            .on(&format!("G{}", g_with(0, 0xcafe)), "OK")
            .once("g", vec![Action::Reply(g_with(0, 0))])
            .once("g", vec![Action::Reply(g_with(0, 0))])
            .once("g", vec![Action::Reply(g_with(0, 0xcafe))]),
    );
    let harness = Harness::new(&stub, WRITES);
    let written = harness
        .call("debug_write_register", json!({"session": "s1", "epoch": 1, "name": "r1", "value": "feca0000"}))
        .unwrap();
    assert_eq!((written["packet"].as_str(), written["verified"].as_bool()), (Some("G"), Some(true)));
    assert_eq!(written["after_value"], "0x0000cafe");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(writes(&report.received), ["P1=feca0000".to_owned(), format!("G{}", g_with(0, 0xcafe))]);
}

#[test]
fn writes_are_refused_while_the_target_runs() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .execution()
            .kill()
            .on("vKill;1", "")
            .on("vCont?", "vCont;c;C;s;S")
            .on("pf", &le_hex(0x48, 4))
            .on_actions("vCont;c", vec![])
            .on_interrupt(vec![Action::Reply("T02thread:p01.01;".into())]),
    );
    let harness = Harness::new(&stub, BOTH);
    let running = harness.call("debug_continue", json!({"session": "s1", "epoch": 1, "timeout_ms": 20})).unwrap();
    assert_eq!(running["state"], "running");
    assert_eq!(
        harness
            .code("debug_write_memory", json!({"session": "s1", "epoch": 1, "address": 0x2000_0000u32, "bytes": "00"})),
        "target_running"
    );
    assert_eq!(
        harness.code("debug_write_register", json!({"session": "s1", "epoch": 1, "name": "r0", "value": "00000000"})),
        "target_running"
    );
    // Killing a running target interrupts it first; this stub refuses the kill, so the session stays.
    let refused = harness.call("debug_disconnect", json!({"session": "s1", "kill": true})).unwrap();
    assert_eq!((refused["closed"].as_bool(), refused["kill"]["killed"].as_bool()), (Some(false), Some(false)));
    assert!(refused["kill"]["error"].as_str().unwrap().starts_with("unsupported"), "{refused}");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
}

#[test]
fn killing_removes_breakpoints_then_sends_vkill_and_reports_the_final_state() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .execution()
            .kill()
            .on("Z1,80,2", "OK")
            .on("z1,80,2", "OK")
            .once("vKill;1", vec![Action::Reply("E01".into())])
            .on("vKill;1", "OK"),
    );
    let harness = Harness::new(&stub, KILL);
    harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": "0x80"}),
        )
        .unwrap();
    // A refused kill keeps the session open and attached, and says the breakpoints are already gone.
    let refused = harness.call("debug_disconnect", json!({"session": "s1", "kill": true})).unwrap();
    assert_eq!((refused["state"].as_str(), refused["closed"].as_bool()), (Some("stopped"), Some(false)));
    assert_eq!(refused["breakpoints_removed"], 1, "{refused}");
    let error = refused["kill"]["error"].as_str().unwrap();
    assert!(error.starts_with("target_error") && error.contains("without its breakpoints"), "{refused}");
    assert_eq!(
        (refused["kill"]["packets"].clone(), refused["kill"]["confirmed"].clone()),
        (json!(["vKill;1"]), json!([]))
    );
    assert_eq!(harness.call("debug_status", json!({"session": "s1"})).unwrap()["state"], "stopped");
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);
    let killed = harness.call("debug_disconnect", json!({"session": "s1", "kill": true})).unwrap();
    assert_eq!((killed["state"].as_str(), killed["closed"].as_bool()), (Some("killed"), Some(true)));
    assert_eq!(
        killed["kill"],
        json!({"killed": true, "already_ended": false, "packets": ["vKill;1"], "confirmed": ["vKill;1"],
               "reply": "OK", "error": null})
    );
    assert_eq!(harness.code("debug_status", json!({"session": "s1"})), "unknown_session");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    let order: Vec<&str> = report
        .received
        .iter()
        .filter(|packet| packet.starts_with('z') || packet.starts_with("vKill") || packet.starts_with('D'))
        .map(String::as_str)
        .collect();
    assert_eq!(order, ["z1,80,2", "vKill;1", "vKill;1"]);
}

#[test]
fn a_stub_that_closes_the_connection_on_k_leaves_the_kill_unconfirmed() {
    let stub = FakeStub::tcp(
        transcripts::qemu_cortex_m3()
            .kill()
            .once(
                "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
                vec![Action::Reply("PacketSize=1000;qXfer:features:read+".into())],
            )
            .on_actions("k", vec![Action::Close]),
    );
    let harness = Harness::new(&stub, KILL);
    let killed = harness.call("debug_disconnect", json!({"session": "s1", "kill": true})).unwrap();
    assert_eq!((killed["state"].as_str(), killed["closed"].as_bool()), (Some("lost"), Some(true)));
    assert_eq!((killed["kill"]["killed"].as_bool(), killed["kill"]["packets"].clone()), (Some(false), json!(["k"])));
    assert!(killed["reason"].as_str().unwrap().contains("no reply to `k`"), "{killed}");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
}

fn firmware() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware/cortex-m3.elf")
}

/// A tool's arguments, built when it is called (some need the current epoch).
type Input = Box<dyn Fn(&Harness) -> Value>;

#[test]
fn read_execution_and_binding_tools_send_no_writes_or_kill_with_both_flags_on() {
    // Execution only (no `.writes()` or `.kill()`): a write or kill packet from any of these tools fails the test,
    // and so does a `?` while a breakpoint is inserted.
    let stub = FakeStub::tcp(
        transcripts::qemu_cortex_m3()
            .execution()
            .on("vCont?", "vCont;c;C;s;S")
            .on("pf", &le_hex(0x48, 4))
            .on_prefix("Z0,", vec![Action::Reply("OK".into())])
            .on_prefix("z0,", vec![Action::Reply("OK".into())])
            .on_prefix("Z1,", vec![Action::Reply("OK".into())])
            .on_prefix("z1,", vec![Action::Reply("OK".into())])
            .on_prefix("Z2,", vec![Action::Reply("OK".into())])
            .on_prefix("z2,", vec![Action::Reply("OK".into())])
            .on_prefix("vCont;s:", vec![Action::Reply("T05thread:p01.01;".into())])
            .on_actions("vCont;c", vec![Action::Reply("T05thread:p01.01;".into())]),
    );
    let harness = Harness::new(&stub, BOTH);
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-writes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(&directory).unwrap();
    let epoch = |harness: &Harness| harness.call("debug_status", json!({"session": "s1"})).unwrap()["epoch"].clone();
    let calls: Vec<(&str, Input)> = vec![
        ("debug_status", Box::new(|_| json!({"session": "s1"}))),
        ("debug_registers", Box::new(|_| json!({"session": "s1"}))),
        ("debug_read_memory", Box::new(|_| json!({"session": "s1", "address": 0x2000_0000u32, "length": 16}))),
        ("debug_modules", Box::new(|_| json!({"session": "s1"}))),
        ("debug_bind", Box::new(|_| json!({"session": "s1", "path": firmware(), "slide": 0}))),
        ("debug_evidence", Box::new(|_| json!({"session": "s1"}))),
        ("debug_registers", Box::new(|_| json!({"session": "s1", "annotate": true}))),
        (
            "debug_breakpoints",
            Box::new(
                move |h| json!({"session": "s1", "action": "set", "epoch": epoch(h), "kind": "software", "address": "0x90"}),
            ),
        ),
        (
            "debug_breakpoints",
            Box::new(
                move |h| json!({"session": "s1", "action": "set", "epoch": epoch(h), "kind": "hardware", "function": "tick"}),
            ),
        ),
        (
            "debug_breakpoints",
            Box::new(move |h| {
                json!({"session": "s1", "action": "set", "epoch": epoch(h), "kind": "write", "address": "0x20000200",
                       "length": 4})
            }),
        ),
        (
            "debug_snapshot",
            Box::new({
                let output = directory.join("capture.json");
                move |_| json!({"session": "s1", "output": output, "ranges": [{"address": "0x20000000", "length": 16}]})
            }),
        ),
        ("debug_step", Box::new(move |h| json!({"session": "s1", "epoch": epoch(h)}))),
        ("debug_step", Box::new(move |h| json!({"session": "s1", "epoch": epoch(h), "over": true}))),
        ("debug_step", Box::new(move |h| json!({"session": "s1", "epoch": epoch(h), "out": true, "timeout_ms": 100}))),
        ("debug_continue", Box::new(move |h| json!({"session": "s1", "epoch": epoch(h)}))),
        ("debug_wait", Box::new(|_| json!({"session": "s1", "timeout_ms": 0}))),
        (
            "debug_breakpoints",
            Box::new(move |h| json!({"session": "s1", "action": "clear", "epoch": epoch(h), "id": 1})),
        ),
        ("debug_breakpoints", Box::new(|_| json!({"session": "s1", "action": "list"}))),
    ];
    for (name, input) in calls {
        let input = input(&harness);
        let result = harness.call(name, input.clone());
        // Step out lands where the transcript's stop says, or is refused; neither may write.
        if !(name == "debug_step" && input.get("out").is_some()) {
            result.unwrap_or_else(|error| panic!("{name} {input}: {error}"));
        }
    }
    // Dropped without debug_disconnect: closing removes the breakpoints and detaches, and still writes nothing.
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert!(writes(&report.received).is_empty(), "{:?}", report.received);
    assert!(report.received.iter().any(|packet| packet.starts_with("Z0,")), "a software breakpoint was set");
    assert!(report.received.iter().any(|packet| packet == "D;1"), "closing detached");
    assert_eq!(report.received.iter().filter(|packet| *packet == "?").count(), 1);
    std::fs::remove_dir_all(directory).unwrap();
}

/// After the pc is written, a continue must not step past a breakpoint at the old pc the stop reply sent.
#[test]
fn a_pc_write_drops_the_stop_replys_expedited_pc() {
    let stub = FakeStub::tcp(
        qemu("20020")
            .execution()
            // gdbserver-like: the stop reply carries the pc (regnum 15), 0x48.
            .once("?", vec![Action::Reply(format!("T05thread:p01.01;0f:{};", le_hex(0x48, 4)))])
            .on("vCont?", "vCont;c;C;s;S")
            .on("Z1,48,2", "OK")
            .on("z1,48,2", "OK")
            .on(&format!("Pf={}", le_hex(0x80, 4)), "OK")
            .on("pf", &le_hex(0x80, 4))
            .on_actions("vCont;c", vec![Action::Reply("T05thread:p01.01;".into())]),
    );
    let harness = Harness::new(&stub, WRITES);
    let set = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": "0x48"});
    harness.call("debug_breakpoints", set).unwrap();
    let written = harness
        .call("debug_write_register", json!({"session": "s1", "epoch": 1, "name": "pc", "value": 0x80}))
        .unwrap();
    assert_eq!(written["packet"], "P");
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["stop"]["registers"], json!([]), "{status}");
    let ran = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(ran["state"], "stopped", "{ran}");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    // The continue resumed at once: no step past the breakpoint at the old pc.
    let resumed = report.received.iter().position(|packet| packet == "vCont;c").unwrap();
    assert!(!report.received[..resumed].iter().any(|packet| packet == "z1,48,2" || packet.starts_with("vCont;s")));
}

/// A large write over small packets takes many round trips; a slow but healthy stub must not lose the session.
#[test]
fn a_large_write_on_small_packets_gets_a_deadline_for_its_chunks() {
    // 64-byte packets carry 16-byte chunks: 1024 bytes are 64 writes, each answered after 10 ms, longer in all than the
    // 500 ms command timeout.
    let stub = FakeStub::tcp(
        qemu("40")
            .memory(0x2000_0000, &[0; 0x1000])
            .on_prefix("X", vec![Action::Sleep(std::time::Duration::from_millis(10)), Action::Reply("OK".into())]),
    );
    let config = rampage_debug::Config { command_timeout: std::time::Duration::from_millis(500), ..Default::default() };
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap().with_config(config).with_consent(WRITES);
    let harness = Harness { registry, tools: debug_tools_with(WRITES) };
    harness.call("debug_connect", json!({})).unwrap();
    let written = harness.write(0x2000_0000, &"5a".repeat(1024)).unwrap();
    assert_eq!((written["complete"].as_bool(), written["chunks"].as_array().unwrap().len()), (Some(true), 64));
    // The rule answers without writing, so the read-back shows the write was dropped.
    assert_eq!(written["verified"], false);
    assert_eq!(harness.call("debug_status", json!({"session": "s1"})).unwrap()["state"], "stopped");
    drop(harness);
    stub.finish().assert_clean();
}
