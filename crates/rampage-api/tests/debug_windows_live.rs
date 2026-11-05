#![cfg(unix)]

//! Live acceptance against a Windows stub the operator started on a Windows host, running the owned fixture in
//! `tests/fixtures/debug-windows` (rebuilt with its `build.sh`). Opt-in, and it launches nothing:
//!
//! ```sh
//! RAMPAGE_WINDOWS_LIVE=1 RAMPAGE_WINDOWS_ENDPOINT=winhost:2345 \
//!     cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_windows_live::)'
//! ```
//!
//! On the Windows host, copy `pe-loop-x64.exe` over and start one of (see `docs/debug-control.md`):
//!
//! ```text
//! gdbserver.exe --once 0.0.0.0:2345 pe-loop-x64.exe
//! lldb-server.exe gdbserver 0.0.0.0:2345 -- pe-loop-x64.exe
//! ```
//!
//! `RAMPAGE_WINDOWS_FIXTURE=pe-loop-x86.exe` runs it against the 32-bit fixture (a WoW64 process). The test
//! connects with the endpoint allowed, binds the fixture (by its CodeView record), breaks on `tick` by name, steps
//! out to `start`, catches the write to `counter` with a watchpoint, interrupts a running continue, snapshots the
//! image's code and detaches (the program then runs on; the operator ends it).

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rampage_api::tools::{DebugTool, debug_tools};
use rampage_api::{DebugRange, DebugRegistry};
use serde_json::{Value, json};

fn fixture() -> PathBuf {
    let name = std::env::var("RAMPAGE_WINDOWS_FIXTURE").unwrap_or_else(|_| "pe-loop-x64.exe".into());
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/debug-windows")
        .join(name)
        .canonicalize()
        .unwrap()
}

/// The endpoint, when the operator opted in.
fn endpoint() -> Option<String> {
    let live = std::env::var("RAMPAGE_WINDOWS_LIVE").as_deref() == Ok("1");
    match (live, std::env::var("RAMPAGE_WINDOWS_ENDPOINT")) {
        (true, Ok(endpoint)) if !endpoint.is_empty() => Some(endpoint),
        _ => {
            eprintln!(
                "skipped: set RAMPAGE_WINDOWS_LIVE=1 and RAMPAGE_WINDOWS_ENDPOINT=host:port, with gdbserver.exe or \
                 lldb-server running the fixture on a Windows host (see docs/debug-control.md)"
            );
            None
        }
    }
}

struct Harness {
    registry: DebugRegistry,
    tools: Vec<DebugTool>,
}

impl Harness {
    fn call(&self, name: &str, input: Value) -> Value {
        let tool = self.tools.iter().find(|tool| tool.name == name).unwrap();
        tool.call(&self.registry, input).unwrap_or_else(|error| panic!("{name}: {error}"))
    }
}

/// The watchpoint length on `counter`: the pointer width. 32-bit x86 debug registers watch at most 4 bytes, and
/// the x86 fixture writes the counter's low half in a 4-byte store.
fn pointer_width() -> u64 {
    let binary = rampage_loaders::Binary::open(fixture()).unwrap();
    u64::from(binary.arch.default_pointer_size().unwrap())
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// `counter`'s static address: `counter_address`, the one pointer in `.data`, holds it.
fn counter() -> u64 {
    let binary = rampage_loaders::Binary::open(fixture()).unwrap();
    let data = binary.sections.iter().find(|section| section.name == ".data").unwrap();
    let width = binary.arch.default_pointer_size().unwrap();
    binary.read_pointer(data.address, width).unwrap()
}

#[test]
#[ignore = "needs a Windows host running gdbserver.exe or lldb-server on the fixture; run with RAMPAGE_WINDOWS_LIVE=1"]
fn breaks_steps_out_watches_interrupts_and_snapshots_on_windows() {
    let Some(endpoint) = endpoint() else { return };
    let harness = Harness { registry: DebugRegistry::new(&[endpoint]).unwrap(), tools: debug_tools() };
    let deadline = Instant::now() + Duration::from_secs(20);
    let connect = harness.tools.iter().find(|tool| tool.name == "debug_connect").unwrap();
    let connection = loop {
        match connect.call(&harness.registry, json!({"path": fixture()})) {
            Ok(connection) => break connection,
            Err(error) if Instant::now() < deadline && error.starts_with("connect_failed") => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) => panic!("{error}"),
        }
    };
    assert!(connection["windows"]["stub"].is_string(), "{connection}");
    let binding = &connection["binding"];
    assert_eq!(binding["evidence"]["kind"], "codeview", "{connection}");
    assert_eq!(binding["verification"]["outcome"], "matched", "{connection}");
    let slide = hex(&binding["slide"]);
    let session = "s1";
    let mut epoch = connection["epoch"].as_u64().unwrap();

    // Break on tick by name and run to it.
    let placed = harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "set", "epoch": epoch, "kind": "software", "function": "tick"}),
    );
    let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 10000}));
    assert_eq!(run["event"]["reason"], "breakpoint", "{run}");
    assert_eq!(run["locations"]["pc"]["location"]["function"], "tick", "{run}");
    epoch = run["epoch"].as_u64().unwrap();

    // Step out to start.
    let out = harness.call("debug_step", json!({"session": session, "epoch": epoch, "out": true, "timeout_ms": 10000}));
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(out["locations"]["pc"]["location"]["function"], "start", "{out}");
    epoch = out["epoch"].as_u64().unwrap();
    harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "clear", "epoch": epoch, "id": placed["breakpoint"]["id"]}),
    );

    // A write watchpoint on the counter stops in tick.
    let watch = harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "set", "epoch": epoch, "kind": "write", "static_address": format!("{:#x}", counter()), "length": pointer_width()}),
    );
    let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 10000}));
    assert_eq!(run["event"]["reason"], "watchpoint", "{run}");
    assert_eq!(run["locations"]["pc"]["location"]["function"], "tick", "{run}");
    epoch = run["epoch"].as_u64().unwrap();
    harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "clear", "epoch": epoch, "id": watch["breakpoint"]["id"]}),
    );

    // A short continue keeps running; an interrupt stops it, in a thread Windows created for it.
    let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 200}));
    assert_eq!(run["state"], "running", "{run}");
    let run = harness.call("debug_interrupt", json!({"session": session}));
    assert_eq!(run["event"]["reason"], "interrupted", "{run}");
    eprintln!("interrupt: {}", run["event"]);

    // A snapshot of the image's code.
    let binary = rampage_loaders::Binary::open(fixture()).unwrap();
    let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-windows-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let output = directory.join("pe-loop.json");
    let ranges: Vec<DebugRange> = serde_json::from_value(json!([
        { "address": format!("{:#x}", text.address.wrapping_add(slide)), "length": format!("{:#x}", text.size), "permissions": "r-x" }
    ]))
    .unwrap();
    let snapshot = harness.registry.snapshot(session, &output, &ranges).unwrap();
    assert_eq!(snapshot.captured_bytes, text.size);

    let disconnected = harness.call("debug_disconnect", json!({"session": session}));
    assert_eq!(disconnected["state"], "detached", "{disconnected}");
    std::fs::remove_dir_all(directory).unwrap();
}
