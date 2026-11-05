#![cfg(unix)]

//! Live acceptance against QEMU's GDB stub running the owned Cortex-M3 firmware in
//! `tests/fixtures/firmware` (rebuild it with `build-firmware.sh`). Opt-in:
//!
//! ```sh
//! RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_qemu::)'
//! ```
//!
//! The harness plays the operator and starts `qemu-system-arm`; rampage itself only connects to the endpoint it is
//! given. QEMU is killed whatever the outcome. Symbol addresses come from the firmware's ELF symbol table.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rampage_api::tools::debug_tools;
use rampage_api::{DebugCancel, DebugRange, DebugRegistry};
use serde_json::{Value, json};

struct Qemu(Child);

impl Drop for Qemu {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn firmware() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/firmware/cortex-m3.elf")
}

/// Starts QEMU's lm3s6965evb with the firmware and a GDB stub on a free loopback port; `halted` adds `-S`.
fn start(halted: bool) -> Option<(Qemu, String)> {
    if std::env::var("RAMPAGE_QEMU_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set RAMPAGE_QEMU_LIVE=1 to run the live QEMU acceptance");
        return None;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut command = Command::new("qemu-system-arm");
    command
        .args(["-M", "lm3s6965evb", "-nographic", "-monitor", "none", "-serial", "null", "-kernel"])
        .arg(firmware())
        .args(["-gdb", &format!("tcp:127.0.0.1:{port}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if halted {
        command.arg("-S");
    }
    let qemu = Qemu(command.spawn().expect("qemu-system-arm is installed"));
    Some((qemu, format!("127.0.0.1:{port}")))
}

/// Connects once QEMU's stub listens. QEMU serves one client at a time, so only rampage connects.
fn connect(registry: &DebugRegistry) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match registry.connect(None) {
            Ok(connection) => return serde_json::to_value(connection).unwrap(),
            Err(error) if Instant::now() < deadline && error.to_string().starts_with("connect_failed") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("{error}"),
        }
    }
}

/// The address (Thumb bit clear) and size of `name` in the firmware's symbol table.
fn symbol(name: &str) -> (u64, u64) {
    let binary = rampage_loaders::Binary::open(firmware()).unwrap();
    let symbol = binary.symbols.iter().find(|symbol| symbol.name == name).unwrap_or_else(|| panic!("no `{name}`"));
    (symbol.address & !1, symbol.size)
}

fn register(registry: &DebugRegistry, name: &str) -> u64 {
    let registers = registry.registers("s1", None, Some(&[name.to_owned()]), None, None).unwrap();
    registers.registers.items[0].integer().unwrap()
}

#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn reads_and_snapshots_a_halted_cortex_m3() {
    let Some((qemu, endpoint)) = start(true) else { return };
    let registry = DebugRegistry::new(&[endpoint]).unwrap();
    let connection = connect(&registry);
    assert_eq!(connection["architecture"], "arm");
    assert_eq!(connection["endianness"], "little");
    assert_eq!(connection["state"], "stopped");
    assert_eq!(connection["epoch"], 1);
    assert_eq!(connection["threads"]["total"], 1);

    // Reset state: pc is the reset handler (Thumb bit clear), sp the vector table's initial stack, xPSR.T set.
    let (reset, _) = symbol("reset_handler");
    assert_eq!(register(&registry, "pc"), reset);
    assert_eq!(register(&registry, "sp"), 0x2001_0000);
    assert_ne!(register(&registry, "xpsr") & 0x0100_0000, 0);
    let vectors = serde_json::to_value(registry.read_memory("s1", 0, 8, None).unwrap()).unwrap();
    let vector = format!("00000120{}", rampage_arch::hex::bytes(&((reset | 1) as u32).to_le_bytes()));
    assert_eq!(vectors["data"][0]["hex"], vector);
    // The firmware has not run, so its RAM pattern is not there yet.
    let pattern = serde_json::to_value(registry.read_memory("s1", 0x2000_0100, 16, None).unwrap()).unwrap();
    assert_eq!(pattern["data"][0]["hex"], "00".repeat(16));

    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-qemu-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let output = directory.join("cortex-m3.json");
    let ranges: Vec<DebugRange> = serde_json::from_value(json!([
        { "address": "0x0", "length": "0x100", "permissions": "r-x" },
        { "address": "0x20000000", "length": "0x400" }
    ]))
    .unwrap();
    let snapshot = registry.snapshot("s1", &output, &ranges).unwrap();
    assert_eq!(snapshot.captured_bytes, 0x500);
    let binary = rampage_loaders::Binary::open(&output).unwrap();
    assert_eq!(binary.arch, rampage_arch::Arch::Arm);
    assert_eq!(binary.segments.len(), 2);
    let pc = binary.snapshot_registers.iter().find(|register| register.name == "pc").unwrap();
    assert_eq!(pc.value, format!("{reset:#x}"));

    assert_eq!(serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap()["state"], "detached");
    drop(qemu);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn reads_ram_the_firmware_wrote_after_running_briefly() {
    // QEMU starts unhalted; its stub stops the machine when a debugger connects. rampage never resumes it.
    let Some((qemu, endpoint)) = start(false) else { return };
    std::thread::sleep(Duration::from_millis(500));
    let registry = DebugRegistry::new(&[endpoint]).unwrap();
    let connection = connect(&registry);
    assert_eq!(connection["state"], "stopped");
    let pattern = serde_json::to_value(registry.read_memory("s1", 0x2000_0100, 16, None).unwrap()).unwrap();
    assert_eq!(pattern["data"][0]["hex"], rampage_arch::hex::bytes(b"RAMPAGE-DEBUG-91"));
    let pc = register(&registry, "pc");
    let ((tick, tick_size), (reset, reset_size)) = (symbol("tick"), symbol("reset_handler"));
    let within = |(start, size): (u64, u64)| (start..start + size).contains(&pc);
    assert!(within((tick, tick_size)) || within((reset, reset_size)), "pc {pc:#x} is in the counter loop");
    assert_eq!(serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap()["state"], "detached");
    drop(qemu);
}

#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn breaks_steps_watches_and_interrupts_a_cortex_m3() {
    let Some((qemu, endpoint)) = start(true) else { return };
    let registry = DebugRegistry::new(&[endpoint]).unwrap();
    let tools = debug_tools();
    let call = |name: &str, input: Value| {
        tools.iter().find(|tool| tool.name == name).unwrap().call_cancellable(&registry, input, &DebugCancel::new())
    };
    let connection = connect(&registry);
    assert_eq!(connection["epoch"], 1);
    let (tick, tick_size) = symbol("tick");
    let (counter, _) = symbol("counter");
    assert!(tick_size > 0);

    // A hardware breakpoint on tick(): the first continue stops at its first instruction.
    let set = call(
        "debug_breakpoints",
        json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": tick}),
    )
    .unwrap();
    let breakpoint = set["breakpoint"]["id"].as_u64().unwrap();
    assert_eq!(set["breakpoint"]["size"], 2);
    let hit = call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(hit["state"], "stopped", "{hit}");
    let epoch = hit["epoch"].as_u64().unwrap();
    assert_eq!(epoch, 2);
    assert_eq!(hit["event"]["reason"], "breakpoint", "{hit}");
    assert_eq!(hit["event"]["pc"], format!("{tick:#x}"));
    assert_eq!(hit["event"]["breakpoints"], json!([breakpoint]));
    let registers = call("debug_registers", json!({"session": "s1", "names": ["pc", "lr"], "epoch": epoch})).unwrap();
    let value = |name: &str| {
        let items = registers["registers"]["items"].as_array().unwrap();
        let value = items.iter().find(|item| item["name"] == name).unwrap()["value"].as_str().unwrap();
        u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
    };
    assert_eq!(value("pc"), tick);
    let (reset, reset_size) = symbol("reset_handler");
    let lr = value("lr");
    assert!((reset..reset + reset_size).contains(&(lr & !1)), "tick returns into the reset handler's loop");

    // Continuing with the breakpoint still set steps past it, puts it back and stops at the next call: counter
    // advances by one each time, and the breakpoint counts every hit.
    let read_counter = || {
        let read = registry.read_memory("s1", counter, 4, None).unwrap();
        u32::from_le_bytes(read.chunks[0].bytes[..].try_into().unwrap())
    };
    let mut epoch = epoch;
    let mut last = read_counter();
    for hits in 2..=3 {
        let again = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap();
        assert_eq!(again["event"]["reason"], "breakpoint", "{again}");
        assert_eq!(again["event"]["pc"], format!("{tick:#x}"));
        assert_eq!(again["warnings"], json!([]));
        epoch = again["epoch"].as_u64().unwrap();
        let now = read_counter();
        assert_eq!(now, last + 1, "counter advanced past the breakpoint");
        last = now;
        let listed = call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
        assert_eq!(listed["breakpoints"]["items"][0]["hits"], hits);
        assert_eq!(listed["breakpoints"]["items"][0]["inserted"], true);
    }

    // Three instructions, each a stop and an epoch.
    let steps = call("debug_step", json!({"session": "s1", "epoch": epoch, "count": 3})).unwrap();
    assert_eq!((steps["completed"].as_u64(), steps["epoch"].as_u64()), (Some(3), Some(epoch + 3)), "{steps}");
    let pcs: Vec<u64> = steps["pcs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pc| u64::from_str_radix(pc.as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
        .collect();
    assert!(
        pcs.windows(2).all(|pair| pair[0] < pair[1]) && pcs.iter().all(|pc| (tick..tick + tick_size).contains(pc)),
        "{pcs:x?}"
    );
    let epoch = epoch + 3;

    // Clear the breakpoint; a write watchpoint on counter stops at tick's store.
    call("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": epoch, "id": breakpoint})).unwrap();
    let watch = call(
        "debug_breakpoints",
        json!({"session": "s1", "action": "set", "epoch": epoch, "kind": "write", "address": counter, "length": 4}),
    )
    .unwrap();
    let watch = watch["breakpoint"]["id"].as_u64().unwrap();
    let watched = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap();
    assert_eq!(watched["event"]["reason"], "watchpoint", "{watched}");
    assert_eq!(watched["event"]["watch"]["address"], format!("{counter:#x}"));
    assert_eq!(watched["event"]["breakpoints"], json!([watch]));
    let epoch = watched["epoch"].as_u64().unwrap();
    call("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": epoch, "id": watch})).unwrap();
    let listed = call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);

    // Nothing stops the loop now: a short continue reports running, and an interrupt stops it at a new epoch.
    let running = call("debug_continue", json!({"session": "s1", "epoch": epoch, "timeout_ms": 300})).unwrap();
    assert_eq!(running["state"], "running", "{running}");
    let status = call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["state"], "running");
    assert!(call("debug_registers", json!({"session": "s1"})).unwrap_err().starts_with("target_running"));
    let interrupted = call("debug_interrupt", json!({"session": "s1"})).unwrap();
    assert_eq!(interrupted["state"], "stopped", "{interrupted}");
    assert_eq!(interrupted["event"]["reason"], "interrupted");
    let new_epoch = interrupted["epoch"].as_u64().unwrap();
    assert_eq!(new_epoch, epoch + 1);
    let stale = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap_err();
    assert!(stale.starts_with("stale_epoch"), "{stale}");
    let counted = registry.read_memory("s1", counter, 4, None).unwrap();
    assert!(counted.chunks[0].bytes.iter().any(|byte| *byte != 0), "the loop ran");

    // Disconnecting removes the remaining breakpoint and detaches.
    call(
        "debug_breakpoints",
        json!({"session": "s1", "action": "set", "epoch": new_epoch, "kind": "hardware", "address": tick}),
    )
    .unwrap();
    let disconnected = call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!(disconnected["state"], "detached", "{disconnected}");
    assert_eq!(disconnected["breakpoints_removed"], 1);
    assert_eq!(disconnected["removal_failures"], json!([]));
    drop(qemu);
}

/// The address of the `bl` that calls `target` inside `caller`, decoded with rampage's Thumb decoder.
fn call_site(caller: (u64, u64), target: u64) -> u64 {
    let binary = rampage_loaders::Binary::open(firmware()).unwrap();
    let mut decoder = binary.decoder().unwrap();
    let (start, size) = caller;
    let mut at = start;
    while at < start + size {
        let bytes = binary.read(at, (start + size - at).min(4)).unwrap();
        let insn = decoder.decode(bytes, at);
        if insn.flow == rampage_arch::Flow::Call(target) {
            return at;
        }
        at += u64::from(insn.len.max(2));
    }
    panic!("no call to {target:#x} in {start:#x}..{:#x}", start + size);
}

#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn correlates_a_cortex_m3_with_its_firmware() {
    let Some((qemu, endpoint)) = start(true) else { return };
    // A copy, so the finding recorded at the end does not write beside the committed fixture.
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-qemu-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("cortex-m3.elf");
    std::fs::copy(firmware(), &path).unwrap();
    let registry = DebugRegistry::new(&[endpoint]).unwrap();
    let tools = debug_tools();
    let call = |name: &str, input: Value| {
        tools.iter().find(|tool| tool.name == name).unwrap().call_cancellable(&registry, input, &DebugCancel::new())
    };
    // debug_connect with path binds the firmware: there is no module list, so the image's code must be mapped
    // byte for byte at slide 0.
    let deadline = Instant::now() + Duration::from_secs(15);
    let connection = loop {
        match call("debug_connect", json!({ "path": path })) {
            Ok(connection) => break connection,
            Err(error) if Instant::now() < deadline && error.starts_with("connect_failed") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("{error}"),
        }
    };
    let binding = &connection["binding"];
    assert_eq!(binding["evidence"]["kind"], "mapped_bytes", "{connection}");
    assert_eq!(binding["slide"], "0x0");
    assert_eq!(binding["verification"]["outcome"], "matched");
    let (tick, _) = symbol("tick");
    let (reset, reset_size) = symbol("reset_handler");
    let (counter, _) = symbol("counter");
    let site = call_site((reset, reset_size), tick);

    // Break on tick by name: the stop is located in tick.
    let set = call(
        "debug_breakpoints",
        json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "function": "tick"}),
    )
    .unwrap();
    assert_eq!(set["breakpoint"]["placement"]["function"], "tick");
    let breakpoint = set["breakpoint"]["id"].as_u64().unwrap();
    let hit = call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(hit["event"]["reason"], "breakpoint", "{hit}");
    assert_eq!(hit["locations"]["pc"]["location"]["function"], "tick", "{hit}");
    assert_eq!(hit["locations"]["pc"]["location"]["offset_in_function"], 0);
    let epoch = hit["epoch"].as_u64().unwrap();

    // Registers that point into the image are annotated: pc in tick, lr back in reset_handler.
    let registers = call("debug_registers", json!({"session": "s1", "epoch": epoch, "annotate": true})).unwrap();
    let items = registers["registers"]["items"].as_array().unwrap();
    let annotated = |name: &str| items.iter().find(|item| item["name"] == name).unwrap()["points_to"].clone();
    assert_eq!(annotated("pc")["function"], "tick", "{registers}");
    assert_eq!(annotated("lr")["function"], "reset_handler", "{registers}");

    // Evidence for the ledger, recorded as a finding on the bound copy at the end.
    let evidence = call("debug_evidence", json!({"session": "s1", "epoch": epoch})).unwrap();
    assert!(evidence["ledger_evidence"]["detail"].as_str().unwrap().contains("(tick+0x0)"), "{evidence}");

    // Step out: back in reset_handler, right after the call.
    let out = call("debug_step", json!({"session": "s1", "epoch": epoch, "out": true})).unwrap();
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(out["event"]["reason"], "temporary_breakpoint", "{out}");
    assert_eq!(out["event"]["pc"], format!("{:#x}", site + 4));
    assert_eq!(out["locations"]["pc"]["location"]["function"], "reset_handler", "{out}");
    let listed = call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 1, "only the user's breakpoint is left: {listed}");
    let epoch = out["epoch"].as_u64().unwrap();

    // Step over the bl tick call site without stopping inside tick: clear tick's breakpoint, step to the call
    // (the loop's branch back) and over it.
    call("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": epoch, "id": breakpoint})).unwrap();
    let read_counter = || {
        let read = registry.read_memory("s1", counter, 4, None).unwrap();
        u32::from_le_bytes(read.chunks[0].bytes[..].try_into().unwrap())
    };
    let before = read_counter();
    let over = call("debug_step", json!({"session": "s1", "epoch": epoch, "over": true, "count": 2})).unwrap();
    assert_eq!(over["completed"], 2, "{over}");
    assert_eq!(over["steps"][0]["outcome"], "stepped");
    assert_eq!(over["steps"][1]["pc"], format!("{site:#x}"));
    assert_eq!(over["steps"][1]["flow"], "call");
    assert_eq!(over["steps"][1]["outcome"], "returned");
    assert_eq!(over["event"]["reason"], "temporary_breakpoint");
    assert_eq!(over["event"]["pc"], format!("{:#x}", site + 4));
    assert_eq!(over["locations"]["pc"]["location"]["function"], "reset_handler");
    assert_eq!(read_counter(), before + 1, "tick ran once, without a stop inside it");
    let listed = call("debug_breakpoints", json!({"session": "s1", "action": "list"})).unwrap();
    assert_eq!(listed["breakpoints"]["total"], 0);

    let disconnected = call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!(disconnected["state"], "detached", "{disconnected}");
    drop(qemu);

    let project = rampage_api::Session::default().open(&path, None).unwrap();
    let request: rampage_api::LedgerRequest = serde_json::from_value(json!({
        "kind": "finding",
        "text": format!("tick increments counter: it read {} after one call over", before + 1),
        "function": "tick",
        "evidence": [evidence["ledger_evidence"]],
    }))
    .unwrap();
    assert_eq!(project.record_finding(&request).unwrap().finding.evidence[0].tool, "debug_evidence");
    drop(project);
    std::fs::remove_dir_all(directory).unwrap();
}

/// QEMU removes every breakpoint and watchpoint when asked `?`; status and snapshots must leave them in place.
#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn breakpoints_and_watchpoints_survive_status_and_snapshots() {
    let Some((qemu, endpoint)) = start(true) else { return };
    let registry = DebugRegistry::new(&[endpoint]).unwrap();
    let tools = debug_tools();
    let call = |name: &str, input: Value| {
        tools.iter().find(|tool| tool.name == name).unwrap().call_cancellable(&registry, input, &DebugCancel::new())
    };
    connect(&registry);
    let (tick, _) = symbol("tick");
    let (counter, _) = symbol("counter");
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-qemu-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let observe = |epoch: u64, name: &str| {
        let status = call("debug_status", json!({"session": "s1"})).unwrap();
        assert_eq!((status["state"].as_str(), status["epoch"].as_u64()), (Some("stopped"), Some(epoch)), "{status}");
        let output = directory.join(name);
        let ranges = json!([{"address": "0x20000000", "length": "0x400"}]);
        call("debug_snapshot", json!({"session": "s1", "output": output, "ranges": ranges, "epoch": epoch})).unwrap();
    };

    // A software breakpoint on tick, observed before the continue: the continue still stops there.
    let set = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "software", "address": tick});
    let breakpoint = call("debug_breakpoints", set).unwrap()["breakpoint"]["id"].as_u64().unwrap();
    observe(1, "before-break.json");
    let hit = call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(
        (hit["event"]["reason"].as_str(), hit["event"]["pc"].clone()),
        (Some("breakpoint"), json!(format!("{tick:#x}"))),
        "{hit}"
    );
    let epoch = hit["epoch"].as_u64().unwrap();

    // A write watchpoint on counter, observed the same way: the continue stops at tick's store.
    call("debug_breakpoints", json!({"session": "s1", "action": "clear", "epoch": epoch, "id": breakpoint})).unwrap();
    let set =
        json!({"session": "s1", "action": "set", "epoch": epoch, "kind": "write", "address": counter, "length": 4});
    call("debug_breakpoints", set).unwrap();
    observe(epoch, "before-watch.json");
    let watched = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap();
    assert_eq!(watched["event"]["reason"], "watchpoint", "{watched}");

    let disconnected = call("debug_disconnect", json!({"session": "s1"})).unwrap();
    assert_eq!(
        (disconnected["breakpoints_removed"].as_u64(), disconnected["removal_failures"].clone()),
        (Some(1), json!([]))
    );
    drop(qemu);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "needs qemu-system-arm; run with RAMPAGE_QEMU_LIVE=1"]
fn writes_ram_registers_and_flash_then_kills_a_cortex_m3() {
    let Some((mut qemu, endpoint)) = start(true) else { return };
    let consent = rampage_api::DebugConsent { writes: true, kill: true };
    let registry = DebugRegistry::new(&[endpoint]).unwrap().with_consent(consent);
    let tools = rampage_api::tools::debug_tools_with(consent);
    let call = |name: &str, input: Value| {
        tools.iter().find(|tool| tool.name == name).unwrap().call_cancellable(&registry, input, &DebugCancel::new())
    };
    connect(&registry);
    let (tick, _) = symbol("tick");
    let (counter, _) = symbol("counter");
    let set = json!({"session": "s1", "action": "set", "epoch": 1, "kind": "hardware", "address": tick});
    call("debug_breakpoints", set).unwrap();
    let hit = call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(hit["event"]["reason"], "breakpoint", "{hit}");
    let epoch = hit["epoch"].as_u64().unwrap();

    // RAM: write counter (compare-and-set against what is there), then tick reads the written value and adds one.
    let current = registry.read_memory("s1", counter, 4, None).unwrap().chunks[0].bytes.clone();
    let expect = rampage_arch::hex::bytes(&current);
    let input = json!({"session": "s1", "epoch": epoch, "address": counter, "bytes": "00100000", "expect": expect});
    let written = call("debug_write_memory", input).unwrap();
    assert_eq!((written["verified"].as_bool(), written["after"].as_str()), (Some(true), Some("00100000")), "{written}");
    assert_eq!(written["epoch"].as_u64(), Some(epoch), "a write does not move the epoch");
    let again = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap();
    assert_eq!(again["event"]["reason"], "breakpoint", "{again}");
    let epoch = again["epoch"].as_u64().unwrap();
    let read = registry.read_memory("s1", counter, 4, None).unwrap();
    assert_eq!(u32::from_le_bytes(read.chunks[0].bytes[..].try_into().unwrap()), 0x1001, "tick read the written value");

    // A scratch register (r12, ip) the loop does not use: written as an integer, read back.
    let input = json!({"session": "s1", "epoch": epoch, "name": "r12", "value": 0x5a5a_1234});
    let register = call("debug_write_register", input).unwrap();
    assert_eq!(register["verified"], true, "{register}");
    assert_eq!(register["after_value"], "0x5a5a1234");
    eprintln!("register write used `{}`", register["packet"]);
    let registers = call("debug_registers", json!({"session": "s1", "names": ["r12"], "epoch": epoch})).unwrap();
    assert_eq!(registers["registers"]["items"][0]["value"], "0x5a5a1234");

    // Flash, past the firmware image: report what QEMU did and check the report against an independent read.
    let flash = 0x3_fff0u64;
    let before = registry.read_memory("s1", flash, 4, None).unwrap().chunks[0].bytes.clone();
    let input = json!({"session": "s1", "epoch": epoch, "address": flash, "bytes": "a55aa55a"});
    let outcome = call("debug_write_memory", input);
    let after = registry.read_memory("s1", flash, 4, None).unwrap().chunks[0].bytes.clone();
    match &outcome {
        Ok(result) => {
            eprintln!("flash write: verified {} chunks {}", result["verified"], result["chunks"]);
            let verified = result["verified"].as_bool().unwrap();
            assert_eq!(verified, after == [0xa5, 0x5a, 0xa5, 0x5a], "{result}");
            if !verified {
                assert_eq!(after, before, "an unverified flash write left the bytes alone");
            }
        }
        Err(error) => {
            eprintln!("flash write refused: {error}");
            assert_eq!(after, before);
        }
    }

    // The writes left the breakpoint in place and the loop running: one more call to tick adds one again.
    let third = call("debug_continue", json!({"session": "s1", "epoch": epoch})).unwrap();
    assert_eq!(third["event"]["reason"], "breakpoint", "{third}");
    let read = registry.read_memory("s1", counter, 4, None).unwrap();
    assert_eq!(u32::from_le_bytes(read.chunks[0].bytes[..].try_into().unwrap()), 0x1002);

    // Kill: breakpoints are removed, then vKill (QEMU is multiprocess); QEMU in system mode exits.
    let killed = call("debug_disconnect", json!({"session": "s1", "kill": true})).unwrap();
    eprintln!("kill: {killed}");
    assert_eq!(killed["breakpoints_removed"], 1, "{killed}");
    assert_eq!(killed["kill"]["packets"], json!(["vKill;1"]), "{killed}");
    assert!(matches!(killed["state"].as_str(), Some("killed" | "lost")), "{killed}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = qemu.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    eprintln!("qemu after the kill: {status:?}");
    assert!(status.is_some(), "QEMU exits when killed through its stub");
    drop(qemu);
}
