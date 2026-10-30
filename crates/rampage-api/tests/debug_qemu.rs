#![cfg(unix)]

//! Live acceptance against QEMU's GDB stub running the owned Cortex-M3 firmware in
//! `tests/fixtures/firmware` (rebuild it with `build-firmware.sh`). Opt-in:
//!
//! ```sh
//! RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(debug_qemu::)'
//! ```
//!
//! The harness plays the operator and starts `qemu-system-arm`; rampage itself only connects to the endpoint it is
//! given. QEMU is killed whatever the outcome.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rampage_api::{DebugRange, DebugRegistry};
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
    assert_eq!(register(&registry, "pc"), 0x48);
    assert_eq!(register(&registry, "sp"), 0x2001_0000);
    assert_ne!(register(&registry, "xpsr") & 0x0100_0000, 0);
    let vectors = serde_json::to_value(registry.read_memory("s1", 0, 8, None).unwrap()).unwrap();
    assert_eq!(vectors["data"][0]["hex"], "0000012049000000");
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
    assert_eq!(pc.value, "0x48");

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
    assert!((0xb4..=0xcc).contains(&pc), "pc {pc:#x} is in the counter loop");
    assert_eq!(serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap()["state"], "detached");
    drop(qemu);
}
