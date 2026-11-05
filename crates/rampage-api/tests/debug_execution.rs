#![cfg(unix)]

//! The debug execution tools (continue, wait, interrupt, step, breakpoints) against the scripted fake stub, which
//! accepts only step 9.2's execution packets and fails on writes, kill, launch, attach and signal delivery.

use std::time::{Duration, Instant};

use rampage_api::tools::{DebugTool, Effect, debug_tools};
use rampage_api::{DebugCancel, DebugRegistry};
use rampage_debug::fake::{Action, FakeStub, INTERRUPT, Script, le_hex, transcripts};
use serde_json::{Value, json};

/// QEMU's Cortex-M3 transcript with vCont, a hardware breakpoint at 0x80, a write watchpoint at 0x20000200 and a
/// pc register; the target stops with SIGINT when interrupted.
fn qemu() -> Script {
    transcripts::qemu_cortex_m3()
        .execution()
        .on("vCont?", "vCont;c;C;s;S")
        .on("pf", &le_hex(0x48, 4))
        .on("Z1,80,2", "OK")
        .on("z1,80,2", "OK")
        .on("Z2,20000200,4", "OK")
        .on("z2,20000200,4", "OK")
        .on_prefix("Z0,", vec![Action::Reply(String::new())])
        .on_interrupt(vec![Action::Reply("T02thread:p01.01;".into())])
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

#[test]
fn execution_tools_are_marked_as_changing_the_target() {
    let tools = debug_tools();
    let effect = |name: &str| tools.iter().find(|tool| tool.name == name).unwrap().effect;
    for name in ["debug_continue", "debug_interrupt", "debug_step", "debug_breakpoints", "debug_disconnect"] {
        assert_eq!(effect(name), Effect::Execution, "{name}");
    }
    for name in ["debug_connect", "debug_status", "debug_registers", "debug_read_memory", "debug_modules", "debug_wait"]
    {
        assert_eq!(effect(name), Effect::None, "{name}");
    }
    assert_eq!(effect("debug_snapshot"), Effect::FileWrite);
    let description = |name: &str| tools.iter().find(|tool| tool.name == name).unwrap().description;
    for name in ["debug_continue", "debug_step", "debug_interrupt"] {
        assert!(description(name).contains("No signal") || description(name).contains("no signal"), "{name}");
        assert!(description(name).contains("All-stop") || description(name).contains("all-stop"), "{name}");
    }
    assert!(description("debug_breakpoints").contains("runtime address only"));
    assert!(description("debug_breakpoints").contains("never plants a software breakpoint by writing memory"));
}

#[test]
fn a_breakpoint_hit_is_matched_counted_and_epoch_checked() {
    let stub = FakeStub::tcp(
        qemu()
            .on_actions(
                "vCont;c",
                vec![Action::Sleep(Duration::from_millis(30)), Action::Reply("T05thread:p01.01;".into())],
            )
            .once("pf", vec![Action::Reply(le_hex(0x48, 4))])
            .once("pf", vec![Action::Reply(le_hex(0x80, 4))]),
    );
    let harness = Harness::new(&stub);
    let set = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": "0x80"}),
        )
        .unwrap();
    assert_eq!((set["breakpoint"]["id"].as_u64(), set["breakpoint"]["size"].as_u64()), (Some(1), Some(2)));
    assert_eq!(set["breakpoint"]["address"], "0x80");
    let refused = |input: Value| harness.code("debug_breakpoints", input);
    assert_eq!(
        refused(json!({"session": "s1", "action": "set", "kind": "hardware", "address": 0x90})),
        "invalid_argument"
    );
    assert_eq!(
        refused(json!({"session": "s1", "action": "set", "epoch": 1, "kind": "write", "address": 0x10, "size": 4})),
        "invalid_argument"
    );
    assert_eq!(refused(json!({"session": "s1", "action": "list", "id": 1})), "invalid_argument");
    // A stub that has no software breakpoints says so; rampage never writes the instruction itself.
    let software = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "software", "address": 0x80}),
        )
        .unwrap_err();
    assert!(software.starts_with("unsupported") && software.contains("writing memory"), "{software}");

    let stopped = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!((stopped["state"].as_str(), stopped["epoch"].as_u64()), (Some("stopped"), Some(2)));
    let event = &stopped["event"];
    assert_eq!(event["reason"], "breakpoint");
    assert_eq!((event["pc"].as_str(), event["thread"].as_str()), (Some("0x80"), Some("p1.1")));
    assert_eq!(event["breakpoints"], json!([1]));
    let listed = harness.call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["items"][0]["hits"], 1);
    assert_eq!(listed["breakpoints"]["total"], 1);

    // The old epoch is refused for execution and, when given, for reads.
    let stale = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap_err();
    assert!(stale.starts_with("stale_epoch") && stale.contains("at epoch 2 and stopped"), "{stale}");
    assert_eq!(harness.code("debug_registers", json!({"session": "s1", "epoch": 1})), "stale_epoch");
    assert_eq!(
        harness.code("debug_read_memory", json!({"session": "s1", "address": 0, "length": 4, "epoch": 1})),
        "stale_epoch"
    );
    assert_eq!(harness.code("debug_modules", json!({"session": "s1", "epoch": 1})), "stale_epoch");
    let registers = harness.call("debug_registers", json!({"session": "s1", "names": ["pc"], "epoch": 2})).unwrap();
    assert_eq!(registers["epoch"], 2);
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!((status["epoch"].as_u64(), status["last_stop"]["reason"].as_str()), (Some(2), Some("breakpoint")));

    let cleared =
        harness.call("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": 2, "id": 1})).unwrap();
    assert_eq!(cleared["breakpoint"]["inserted"], false);
    assert_eq!(
        harness.code("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": 2, "id": 1})),
        "invalid_argument"
    );
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.contains(&"z1,80,2".to_owned()));
}

#[test]
fn a_running_target_refuses_everything_but_status_wait_interrupt_and_disconnect() {
    let stub = FakeStub::tcp(qemu().on_actions("vCont;c", vec![]));
    let harness = Harness::new(&stub);
    let running = harness.call("debug_continue", json!({"session": "s1", "epoch": 1, "timeout_ms": 50})).unwrap();
    assert_eq!((running["state"].as_str(), running["event"].is_null()), (Some("running"), true));
    for (name, input) in [
        ("debug_registers", json!({"session": "s1"})),
        ("debug_read_memory", json!({"session": "s1", "address": 0, "length": 4})),
        ("debug_modules", json!({"session": "s1"})),
        ("debug_step", json!({"session": "s1", "epoch": 1})),
        ("debug_continue", json!({"session": "s1", "epoch": 1})),
        ("debug_breakpoints", json!({"session": "s1", "action": "list"})),
        (
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": 0x80}),
        ),
    ] {
        assert_eq!(harness.code(name, input), "target_running", "{name}");
    }
    assert_eq!(
        harness.code("debug_continue", json!({"session": "s1", "epoch": 1, "timeout_ms": 60_001})),
        "invalid_argument"
    );
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["state"], "running");
    assert!(status["running_for_ms"].is_u64());
    let waited = harness.call("debug_wait", json!({"session": "s1", "timeout_ms": 20})).unwrap();
    assert_eq!((waited["state"].as_str(), waited["cancelled"].as_bool()), (Some("running"), Some(false)));

    // Cancelling the call returns promptly, leaving the target running.
    let cancel = DebugCancel::new();
    let started = Instant::now();
    let cancelled = std::thread::scope(|scope| {
        let waiting = scope
            .spawn(|| harness.call_cancellable("debug_wait", json!({"session": "s1", "timeout_ms": 60_000}), &cancel));
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
        waiting.join().unwrap()
    })
    .unwrap();
    assert_eq!((cancelled["state"].as_str(), cancelled["cancelled"].as_bool()), (Some("running"), Some(true)));
    assert!(started.elapsed() < Duration::from_secs(5));
    let cancel = DebugCancel::new();
    cancel.cancel();
    let cancelled = harness.call_cancellable("debug_continue", json!({"session": "s1", "epoch": 1}), &cancel);
    assert_eq!(cancelled.unwrap_err().split(':').next(), Some("target_running"));

    let interrupted = harness.call("debug_interrupt", json!({"session": "s1"})).unwrap();
    assert_eq!((interrupted["state"].as_str(), interrupted["epoch"].as_u64()), (Some("stopped"), Some(2)));
    assert_eq!(interrupted["event"]["reason"], "interrupted");
    assert_eq!(interrupted["event"]["signal"], 2);
    assert_eq!(harness.code("debug_interrupt", json!({"session": "s1"})), "not_running");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(report.received.iter().filter(|packet| *packet == INTERRUPT).count(), 1);
}

#[test]
fn a_multi_step_stops_early_at_a_watchpoint() {
    let stub = FakeStub::tcp(
        qemu()
            .once("vCont;s:p1.1", vec![Action::Reply("T05thread:p01.01;".into())])
            .once("vCont;s:p1.1", vec![Action::Reply("T05thread:p01.01;watch:20000200;".into())])
            .once("pf", vec![Action::Reply(le_hex(0x4a, 4))]),
    );
    let harness = Harness::new(&stub);
    let watch = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "write", "address": "0x20000200", "length": 4}),
        )
        .unwrap();
    assert_eq!(watch["breakpoint"]["size"], 4);
    assert_eq!(harness.code("debug_step", json!({"session": "s1", "epoch": 1, "count": 1001})), "invalid_argument");
    let steps = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "count": 10})).unwrap();
    assert_eq!((steps["requested"].as_u64(), steps["completed"].as_u64()), (Some(10), Some(1)));
    assert_eq!(steps["pcs"], json!(["0x4a"]));
    assert_eq!((steps["epoch"].as_u64(), steps["thread"].as_str()), (Some(3), Some("p1.1")));
    assert_eq!(steps["event"]["reason"], "watchpoint");
    assert_eq!(steps["event"]["watch"], json!({"access": "write", "address": "0x20000200"}));
    assert_eq!(steps["event"]["breakpoints"], json!([1]));
    // Disconnecting removes the watchpoint before detaching.
    let disconnected = harness.call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!(
        (disconnected["state"].as_str(), disconnected["breakpoints_removed"].as_u64()),
        (Some("detached"), Some(1))
    );
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    let tail: Vec<&str> = report.received.iter().rev().take(2).map(String::as_str).collect();
    assert_eq!(tail, ["D;1", "z2,20000200,4"]);
}

#[test]
fn disconnecting_a_running_target_interrupts_removes_breakpoints_and_detaches() {
    let stub = FakeStub::tcp(qemu().on_actions("vCont;c", vec![]));
    let harness = Harness::new(&stub);
    harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": 0x80}),
        )
        .unwrap();
    harness.call("debug_continue", json!({"session": "s1", "epoch": 1, "timeout_ms": 0})).unwrap();
    let disconnected = harness.call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!(disconnected["state"], "detached");
    assert_eq!((disconnected["breakpoints_removed"].as_u64(), disconnected["closed"].as_bool()), (Some(1), Some(true)));
    assert_eq!(disconnected["removal_failures"], json!([]));
    assert_eq!(harness.code("debug_status", json!({"session": "s1"})), "unknown_session");
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    let control: Vec<&str> = report
        .received
        .iter()
        .filter(|packet| *packet == INTERRUPT || packet.starts_with('z') || packet.starts_with('D'))
        .map(String::as_str)
        .collect();
    assert_eq!(control, [INTERRUPT, "z1,80,2", "D;1"]);
}

#[test]
fn a_target_that_ignores_the_interrupt_is_reported_lost_on_disconnect() {
    let stub = FakeStub::tcp(
        transcripts::qemu_cortex_m3()
            .execution()
            .on("vCont?", "vCont;c;s")
            .on_actions("vCont;c", vec![])
            .on_interrupt(vec![]),
    );
    let harness = Harness::new(&stub);
    harness.call("debug_continue", json!({"session": "s1", "epoch": 1, "timeout_ms": 0})).unwrap();
    let interrupted = harness.call("debug_interrupt", json!({"session": "s1"})).unwrap();
    assert_eq!(interrupted["state"], "running");
    let disconnected = harness.call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!((disconnected["state"].as_str(), disconnected["detached"].as_bool()), (Some("lost"), Some(false)));
    assert!(disconnected["reason"].as_str().unwrap().contains("did not stop"));
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('D')));
}

#[test]
fn a_snapshot_is_cancelled_between_reads_and_writes_nothing() {
    let stub = FakeStub::tcp(qemu().lenient());
    let harness = Harness::new(&stub);
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-debug-cancel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(&directory).unwrap();
    let output = directory.join("capture.json");
    let cancel = DebugCancel::new();
    cancel.cancel();
    let input = json!({"session": "s1", "output": output, "ranges": [{"address": "0x20000000", "length": "0x200"}]});
    let error = harness.call_cancellable("debug_snapshot", input.clone(), &cancel).unwrap_err();
    assert!(error.starts_with("cancelled"), "{error}");
    assert!(!output.exists());
    assert_eq!(
        harness.code(
            "debug_snapshot",
            json!({"session": "s1", "output": output, "ranges": [{"address": 0, "length": 8}], "epoch": 9})
        ),
        "stale_epoch"
    );
    let snapshot = harness.call("debug_snapshot", input).unwrap();
    assert_eq!(snapshot["epoch"], 1);
    drop(harness);
    stub.finish();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn an_oversized_stop_reply_still_fits_every_result() {
    // 200 expedited registers of 2 KiB each, after 4 KiB of console output.
    let fields: String = (0x100..0x100 + 200).map(|regnum| format!("{regnum:x}:{};", "ab".repeat(1024))).collect();
    let output =
        rampage_debug::packet::encode(format!("O{}", rampage_debug::packet::encode_hex(&[b'x'; 4096])).as_bytes());
    let stop = rampage_debug::packet::encode(format!("T05thread:p01.01;{fields}").as_bytes());
    let stub = FakeStub::tcp(qemu().on_actions("vCont;c", vec![Action::Raw(output), Action::Raw(stop)]));
    let harness = Harness::new(&stub);
    let stopped = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(stopped["state"], "stopped");
    assert_eq!(stopped["event"]["console"]["text"].as_str().unwrap().len(), 4096);
    for (name, input) in [
        ("debug_continue", stopped.clone()),
        ("debug_wait", harness.call("debug_wait", json!({"session": "s1"})).unwrap()),
        ("debug_status", harness.call("debug_status", json!({"session": "s1"})).unwrap()),
    ] {
        assert!(input.to_string().len() <= 60_000, "{name}: {} bytes", input.to_string().len());
    }
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["last_stop"]["console"]["text"], "");
    drop(harness);
    stub.finish().assert_clean();
}
