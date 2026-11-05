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
