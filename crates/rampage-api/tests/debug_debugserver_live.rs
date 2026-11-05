#![cfg(target_os = "macos")]

//! Live acceptance against Apple's `debugserver` attached to the owned arm64 fixture in `tests/fixtures/debug-macho`
//! (rebuilt with its `build.sh`, ad-hoc signed with `get-task-allow`). Opt-in:
//!
//! ```sh
//! RAMPAGE_DEBUGSERVER_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_debugserver_live::)'
//! ```
//!
//! debugserver may control a process only on a Mac whose operator allowed it: run `sudo DevToolsSecurity -enable`
//! (or enable developer mode) first. Without that, debugserver waits for an authorization prompt instead of
//! listening, and the test fails after its connect timeout saying so. `RAMPAGE_DEBUGSERVER` names the debugserver
//! binary; by default the Command Line Tools' and Xcode's are tried.
//!
//! The harness plays the operator: it starts the program, then `debugserver 127.0.0.1:<port> --attach=<pid>`. The
//! program is past dyld's start by then, so its images are listed. Rampage itself only connects to the endpoint it
//! is given. debugserver and the program are killed whatever the outcome.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rampage_api::tools::{DebugTool, debug_tools};
use rampage_api::{DebugRange, DebugRegistry};
use serde_json::{Value, json};

/// The program and the debugserver attached to it, both killed when dropped.
struct Processes {
    program: Child,
    debugserver: Option<Child>,
}

impl Drop for Processes {
    fn drop(&mut self) {
        if let Some(debugserver) = &mut self.debugserver {
            let _ = debugserver.kill();
            let _ = debugserver.wait();
        }
        let _ = self.program.kill();
        let _ = self.program.wait();
    }
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/debug-macho/macho-loop")
        .canonicalize()
        .unwrap()
}

fn debugserver_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("RAMPAGE_DEBUGSERVER") {
        return PathBuf::from(path);
    }
    [
        "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver",
        "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
    .expect("no debugserver found; set RAMPAGE_DEBUGSERVER")
}

/// Starts the fixture, then debugserver attached to it on a free loopback port.
fn start() -> Option<(Processes, String)> {
    if std::env::var("RAMPAGE_DEBUGSERVER_LIVE").as_deref() != Ok("1") {
        eprintln!(
            "skipped: set RAMPAGE_DEBUGSERVER_LIVE=1 to run the live debugserver acceptance (needs `sudo \
             DevToolsSecurity -enable` or developer mode)"
        );
        return None;
    }
    let program = Command::new(fixture())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the fixture starts");
    let mut processes = Processes { program, debugserver: None };
    // Let dyld finish and the loop run before attaching.
    std::thread::sleep(Duration::from_millis(300));
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let debugserver = Command::new(debugserver_binary())
        .arg(format!("127.0.0.1:{port}"))
        .arg(format!("--attach={}", processes.program.id()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("debugserver starts");
    processes.debugserver = Some(debugserver);
    Some((processes, format!("127.0.0.1:{port}")))
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

/// Connects (binding the fixture) once debugserver listens.
fn connect(harness: &Harness) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    let input = json!({"path": fixture()});
    let tool = harness.tools.iter().find(|tool| tool.name == "debug_connect").unwrap();
    loop {
        match tool.call(&harness.registry, input.clone()) {
            Ok(connection) => return connection,
            Err(error) if Instant::now() < deadline && error.starts_with("connect_failed") => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => panic!(
                "{error}: debugserver did not accept a connection; on a Mac without developer tools security \
                 enabled it waits for an authorization prompt (run `sudo DevToolsSecurity -enable`)"
            ),
        }
    }
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn symbol(name: &str) -> u64 {
    let binary = rampage_loaders::Binary::open(fixture()).unwrap();
    binary.symbols.iter().find(|symbol| symbol.name == name).unwrap_or_else(|| panic!("no `{name}`")).address
}

#[test]
#[ignore = "needs debugserver and developer tools security; run with RAMPAGE_DEBUGSERVER_LIVE=1"]
fn breaks_steps_out_watches_interrupts_and_snapshots_under_debugserver() {
    let Some((processes, endpoint)) = start() else { return };
    let harness = Harness { registry: DebugRegistry::new(&[endpoint]).unwrap(), tools: debug_tools() };
    let connection = connect(&harness);
    assert_eq!(connection["family"], "aarch64", "{connection}");
    assert_eq!(connection["endianness"], "little");
    assert_eq!(connection["lldb"]["apple"], true);
    assert_eq!(connection["lldb"]["process"]["pid"], processes.program.id());
    let binding = &connection["binding"];
    assert_eq!(binding["evidence"]["kind"], "uuid", "{connection}");
    assert_eq!(binding["verification"]["outcome"], "matched", "{connection}");
    let slide = hex(&binding["slide"]);
    let session = "s1";
    let mut epoch = connection["epoch"].as_u64().unwrap();

    // Break on tick by name and run to it.
    let placed = harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "set", "epoch": epoch, "kind": "software", "function": "_tick"}),
    );
    let tick_breakpoint = placed["breakpoint"]["id"].clone();
    let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 10000}));
    assert_eq!(run["event"]["reason"], "breakpoint", "{run}");
    assert_eq!(run["locations"]["pc"]["location"]["function"], "_tick", "{run}");
    epoch = run["epoch"].as_u64().unwrap();

    // Step out to main.
    let out = harness.call("debug_step", json!({"session": session, "epoch": epoch, "out": true, "timeout_ms": 10000}));
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(out["locations"]["pc"]["location"]["function"], "_main", "{out}");
    epoch = out["epoch"].as_u64().unwrap();
    harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "clear", "epoch": epoch, "id": tick_breakpoint}),
    );

    // A write watchpoint on the counter stops at tick's store; continuing with it still set steps past the store
    // (debugserver on ARM stops before the access) and stops at the next tick's store.
    let counter = symbol("_counter");
    let watch = harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "set", "epoch": epoch, "kind": "write", "static_address": format!("{counter:#x}"), "length": 8}),
    );
    for _ in 0..2 {
        let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 10000}));
        assert_eq!(run["event"]["reason"], "watchpoint", "{run}");
        assert_eq!(run["locations"]["pc"]["location"]["function"], "_tick", "{run}");
        epoch = run["epoch"].as_u64().unwrap();
    }
    let listed = harness.call("debug_breakpoints", json!({"session": session, "action": "list"}));
    let entry = listed["breakpoints"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == watch["breakpoint"]["id"])
        .cloned()
        .unwrap();
    assert_eq!(entry["hits"], 2, "{listed}");
    harness.call(
        "debug_breakpoints",
        json!({"session": session, "action": "clear", "epoch": epoch, "id": watch["breakpoint"]["id"]}),
    );

    // A short continue keeps running; an interrupt stops it.
    let run = harness.call("debug_continue", json!({"session": session, "epoch": epoch, "timeout_ms": 200}));
    assert_eq!(run["state"], "running", "{run}");
    let run = harness.call("debug_interrupt", json!({"session": session}));
    assert_eq!(run["event"]["reason"], "interrupted", "{run}");

    // A snapshot of the program's code.
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-debugserver-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let output = directory.join("macho-loop.json");
    let ranges: Vec<DebugRange> = serde_json::from_value(json!([
        { "address": format!("{:#x}", 0x1_0000_0000u64 + slide), "length": "0x4000", "permissions": "r-x" }
    ]))
    .unwrap();
    let snapshot = harness.registry.snapshot(session, &output, &ranges).unwrap();
    assert_eq!(snapshot.captured_bytes, 0x4000);
    let binary = rampage_loaders::Binary::open(&output).unwrap();
    assert_eq!(binary.arch, rampage_arch::Arch::Aarch64);

    let disconnected = harness.call("debug_disconnect", json!({"session": session}));
    assert_eq!(disconnected["state"], "detached", "{disconnected}");
    drop(processes);
    std::fs::remove_dir_all(directory).unwrap();
}
