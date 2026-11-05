#![cfg(unix)]

//! The debug registry and inspection tools against the scripted fake stub. These scripts are read-only: the stub
//! fails any test that receives an execution-control packet (resume, step, breakpoint, write or kill).

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;

use rampage_api::tools::debug_tools;
use rampage_api::{ApiError, DebugRange, DebugRegistry, MAX_DEBUG_SESSIONS};
use rampage_debug::fake::{Action, FakeStub, Script, transcripts};
use serde_json::{Value, json};

fn private_directory(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-debug-api-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
    directory
}

fn range(address: u64, length: u64, permissions: Option<&str>) -> DebugRange {
    serde_json::from_value(json!({
        "address": format!("{address:#x}"),
        "length": length,
        "permissions": permissions,
    }))
    .unwrap()
}

fn code(error: &ApiError) -> String {
    error.to_string().split(':').next().unwrap().to_owned()
}

#[test]
fn only_listed_endpoints_can_be_reached() {
    let registry = DebugRegistry::new(&["127.0.0.1:1".to_owned(), "unix:/nonexistent/stub.sock".to_owned()]).unwrap();
    let error = registry.connect(Some("127.0.0.1:2")).unwrap_err();
    assert_eq!(code(&error), "endpoint_not_allowed");
    assert!(error.to_string().contains("127.0.0.1:1, unix:/nonexistent/stub.sock"));
    // A resolvable spelling of a listed endpoint is still a different endpoint.
    assert_eq!(code(&registry.connect(Some("localhost:1")).unwrap_err()), "endpoint_not_allowed");
    assert_eq!(code(&registry.connect(None).unwrap_err()), "invalid_argument");
    assert_eq!(code(&registry.status("s1", None, None).unwrap_err()), "unknown_session");
    assert!(matches!(registry.status("bogus", None, None), Err(ApiError::NotFound(_))));
    assert!(DebugRegistry::new(&["no-port".to_owned()]).is_err());
}

#[test]
fn inspects_and_snapshots_a_cortex_m_target_through_the_registry() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    let connection = registry.connect(None).unwrap();
    assert_eq!(connection.session, "s1");
    let value = serde_json::to_value(&connection).unwrap();
    assert_eq!(value["architecture"], "arm");
    assert_eq!(value["endianness"], "little");
    assert_eq!(value["state"], "stopped");
    assert_eq!(value["epoch"], 1);
    assert_eq!(value["stop"]["kind"], "signal");
    assert_eq!(value["threads"]["items"][0]["id"], "p1.1");
    assert_eq!(value["memory_map_available"], true);
    assert_eq!(value["local_endpoint"], true);

    let registers = registry.registers("s1", None, Some(&["pc".to_owned(), "xpsr".to_owned()]), None, None).unwrap();
    let registers = serde_json::to_value(registers).unwrap();
    assert_eq!(registers["registers"]["total"], 2);
    assert_eq!(registers["registers"]["items"][0]["value"], "0x00000048");
    assert_eq!(registers["registers"]["items"][1]["value"], "0x41000000");
    let error = registry.registers("s1", None, Some(&["bogus".to_owned()]), None, None).unwrap_err();
    assert_eq!(code(&error), "invalid_argument");
    let error = registry.registers("s1", Some("p9.9"), None, None, None).unwrap_err();
    assert_eq!(code(&error), "invalid_argument");

    let memory = serde_json::to_value(registry.read_memory("s1", 0, 8, Some("p1.1")).unwrap()).unwrap();
    assert_eq!(memory["data"][0]["hex"], "0000012049000000");
    assert_eq!(memory["complete"], true);
    assert_eq!(memory["atomic"], false);
    let memory = serde_json::to_value(registry.read_memory("s1", 0x2000_01f0, 0x20, None).unwrap()).unwrap();
    assert_eq!(memory["complete"], false);
    assert_eq!(memory["bytes_read"], 0x10);
    assert!(memory["chunks"][0]["error"].as_str().unwrap().contains("16 of 32"));

    let modules = serde_json::to_value(registry.modules("s1", None, None).unwrap()).unwrap();
    assert_eq!(modules["regions"][0]["type"], "flash");
    assert_eq!(modules["regions"][0]["flash_block_size"], 0x400);
    assert_eq!(modules["modules"]["total"], 0);

    let directory = private_directory("cortex");
    let output = directory.join("capture.json");
    let snapshot =
        registry.snapshot("s1", &output, &[range(0, 8, Some("r-x")), range(0x2000_0000, 0x100, None)]).unwrap();
    assert_eq!(snapshot.arch, "arm");
    assert!(!snapshot.data_big_endian);
    assert_eq!((snapshot.regions, snapshot.captured_bytes, snapshot.threads), (2, 0x108, 1));
    assert_eq!(std::fs::metadata(&output).unwrap().permissions().mode() & 0o777, 0o600);
    // The written snapshot loads through the ordinary snapshot loader.
    let binary = rampage_loaders::Binary::open(&output).unwrap();
    assert_eq!(binary.arch, rampage_arch::Arch::Arm);
    assert_eq!(binary.segments.len(), 2);
    assert!(binary.segments[0].perms.execute && !binary.segments[1].perms.execute);
    assert!(binary.target().thumb.iter().any(|range| range.start == 0 && range.end == 8), "M-profile code is Thumb");
    assert!(!binary.big_endian && !binary.target().data_big_endian);
    let pc = binary.snapshot_registers.iter().find(|register| register.name == "pc").unwrap();
    assert_eq!((pc.thread_id.as_str(), pc.value.as_str()), ("0x1", "0x48"));
    assert_eq!(snapshot.registers_recorded, binary.snapshot_registers.len());
    // Never overwrites.
    let error = registry.snapshot("s1", &output, &[range(0, 8, Some("r-x"))]).unwrap_err();
    assert!(error.to_string().contains("already exists"), "{error}");
    // Unreadable or malformed ranges are refused before anything is written.
    let partial = directory.join("partial.json");
    let error = registry.snapshot("s1", &partial, &[range(0x2000_01f0, 0x20, None)]).unwrap_err();
    assert_eq!(code(&error), "target_error");
    for ranges in [
        vec![range(0, 8, Some("--x"))],
        vec![range(0, 8, None), range(4, 8, None)],
        vec![range(0, 17 * 1024 * 1024, None)],
        vec![],
    ] {
        assert_eq!(code(&registry.snapshot("s1", &partial, &ranges).unwrap_err()), "invalid_argument");
    }
    assert!(!partial.exists());

    let disconnected = serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap();
    assert_eq!(disconnected["state"], "detached");
    assert_eq!(code(&registry.status("s1", None, None).unwrap_err()), "unknown_session");
    drop(registry);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.contains(&"D;1".to_owned()));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn aarch64_values_and_snapshots_wait_for_byte_order_evidence() {
    let stub = FakeStub::tcp(transcripts::gdbserver_aarch64());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    let connection = serde_json::to_value(registry.connect(Some(stub.endpoint())).unwrap()).unwrap();
    assert_eq!(connection["endianness"], "unknown");
    assert_eq!(connection["threads"]["total"], 2);
    let registers = serde_json::to_value(registry.registers("s1", None, None, Some(32), Some(2)).unwrap()).unwrap();
    assert_eq!(registers["registers"]["items"][0]["name"], "pc");
    assert_eq!(registers["registers"]["items"][0]["value"], Value::Null);
    assert_eq!(registers["registers"]["next_offset"], 34);
    assert!(registers["limitations"][0].as_str().unwrap().contains("AArch64"));

    let modules = serde_json::to_value(registry.modules("s1", Some(2), Some(1)).unwrap()).unwrap();
    assert_eq!(modules["modules"]["total"], 3);
    assert_eq!(modules["modules"]["items"][0]["build_id"], "deadbeef01020304");
    assert_eq!(modules["modules"]["items"][0]["l_addr"], "0x7ffff7e00000");
    assert_eq!(modules["exec_file"], "/home/user/prog");

    let directory = private_directory("aarch64");
    let error = registry.snapshot("s1", &directory.join("capture.json"), &[range(0x1000, 8, None)]).unwrap_err();
    assert_eq!(code(&error), "unsupported");
    assert!(error.to_string().contains("byte order"));
    drop(registry);
    stub.finish().assert_clean();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn at_most_four_sessions_are_open_at_once() {
    let stubs: Vec<FakeStub> = (0..MAX_DEBUG_SESSIONS).map(|_| FakeStub::tcp(transcripts::qemu_cortex_m3())).collect();
    let mut endpoints: Vec<String> = stubs.iter().map(|stub| stub.endpoint().to_owned()).collect();
    endpoints.push("127.0.0.1:9".to_owned());
    let registry = DebugRegistry::new(&endpoints).unwrap();
    for (index, endpoint) in endpoints[..MAX_DEBUG_SESSIONS].iter().enumerate() {
        assert_eq!(registry.connect(Some(endpoint)).unwrap().session, format!("s{}", index + 1));
    }
    let error = registry.connect(Some("127.0.0.1:9")).unwrap_err();
    assert_eq!(code(&error), "session_limit");
    registry.disconnect("s2").unwrap();
    // Dropping the registry detaches every remaining session.
    drop(registry);
    for stub in stubs {
        let report = stub.finish();
        report.assert_clean();
        assert_eq!(report.received.last().map(String::as_str), Some("D;1"));
    }
}

#[test]
fn debug_tools_validate_arguments_and_bound_reads() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    let tools = debug_tools();
    let call = |name: &str, input: Value| tools.iter().find(|tool| tool.name == name).unwrap().call(&registry, input);
    let connected = call("debug_connect", json!({})).unwrap();
    assert_eq!(connected["session"], "s1");
    assert!(
        call("debug_connect", json!({"endpoint": "10.0.0.1:2345"})).unwrap_err().starts_with("endpoint_not_allowed")
    );
    assert!(
        call(
            "debug_read_memory",
            json!({"session": "s1", "address": "0x0", "length": connected["max_read_length"].as_u64().unwrap() + 1})
        )
        .unwrap_err()
        .starts_with("invalid_argument")
    );
    assert!(call("debug_read_memory", json!({"session": "s1", "address": 0, "length": 4, "bogus": 1})).is_err());
    let memory = call("debug_read_memory", json!({"session": "s1", "address": "0x20000000", "length": 512})).unwrap();
    assert_eq!(memory["data"][0]["hex"].as_str().unwrap().len(), 1024);
    assert!(call("debug_status", json!({"session": "s9"})).unwrap_err().starts_with("unknown_session"));
    let status = call("debug_status", json!({"session": "s1", "limit": 1})).unwrap();
    assert_eq!(status["threads"]["items"][0]["extra"], "CPU#0 [halted ]");
    let snapshot = tools.iter().find(|tool| tool.name == "debug_snapshot").unwrap();
    assert_eq!(snapshot.effect, rampage_api::tools::Effect::FileWrite);
    for tool in
        tools.iter().filter(|tool| ["debug_status", "debug_registers", "debug_read_memory"].contains(&tool.name))
    {
        assert_eq!(tool.effect, rampage_api::tools::Effect::None, "{}", tool.name);
    }
    assert_eq!(call("debug_disconnect", json!({"session": "s1"})).unwrap()["state"], "detached");
    drop(registry);
    stub.finish().assert_clean();
}

/// An x86-64 stub (little-endian by architecture) with `registers` 64-bit registers, the given threads, svr4
/// modules `(path, l_addr, build_id)` and RAM at 0x1000.
fn x86_stub(registers: usize, threads: &[&str], modules: &[(String, u64, Option<Vec<u8>>)]) -> Script {
    let mut feature = String::from("<feature name=\"org.gnu.gdb.i386.core\"><reg name=\"rip\" bitsize=\"64\"/>");
    for index in 1..registers {
        feature.push_str(&format!("<reg name=\"r{index}\" bitsize=\"64\"/>"));
    }
    feature.push_str("</feature>");
    let mut libraries = String::from("<library-list-svr4 version=\"1.0\">");
    for (index, (path, l_addr, _)) in modules.iter().enumerate() {
        libraries.push_str(&format!(
            "<library name=\"{path}\" lm=\"{:#x}\" l_addr=\"{l_addr:#x}\" l_ld=\"{:#x}\"/>",
            0x10_0000 + index * 0x100,
            l_addr + 0x1000
        ));
    }
    libraries.push_str("</library-list-svr4>");
    let mut script = Script::new()
        .on(
            "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
            "PacketSize=4000;qXfer:features:read+;qXfer:libraries-svr4:read+;multiprocess+",
        )
        .xfer(
            "features",
            "target.xml",
            "<target><architecture>i386:x86-64</architecture><xi:include href=\"core.xml\"/></target>",
        )
        .xfer("features", "core.xml", &feature)
        .xfer("libraries-svr4", "", &libraries)
        .on("?", &format!("T05thread:{};", threads[0]))
        .on("qfThreadInfo", &format!("m{}", threads.join(",")))
        .on("qsThreadInfo", "l")
        .on(&format!("qThreadExtraInfo,{}", threads[0]), "")
        .on("g", &"00".repeat(registers * 8))
        .on("qOffsets", "")
        .memory(0x1000, &[0x90; 0x100]);
    for thread in threads {
        script = script.on(&format!("Hg{thread}"), "OK");
    }
    let mut pids: Vec<&str> = threads.iter().map(|thread| thread[1..].split('.').next().unwrap()).collect();
    pids.dedup();
    for pid in pids {
        script = script.on(&format!("D;{pid}"), "OK");
    }
    for (_, l_addr, build_id) in modules {
        if let Some(id) = build_id {
            let mut image = vec![0u8; 0x200];
            image[..6].copy_from_slice(b"\x7fELF\x02\x01");
            image[32..40].copy_from_slice(&64u64.to_le_bytes());
            image[54..56].copy_from_slice(&56u16.to_le_bytes());
            image[56..58].copy_from_slice(&1u16.to_le_bytes());
            image[64..68].copy_from_slice(&4u32.to_le_bytes());
            image[64 + 16..64 + 24].copy_from_slice(&0x100u64.to_le_bytes());
            image[64 + 32..64 + 40].copy_from_slice(&(16 + id.len() as u64).to_le_bytes());
            image[0x100..0x104].copy_from_slice(&4u32.to_le_bytes());
            image[0x104..0x108].copy_from_slice(&(id.len() as u32).to_le_bytes());
            image[0x108..0x10c].copy_from_slice(&3u32.to_le_bytes());
            image[0x10c..0x110].copy_from_slice(b"GNU\0");
            image[0x110..0x110 + id.len()].copy_from_slice(id);
            script = script.memory(*l_addr, &image);
        }
    }
    script
}

#[test]
fn snapshots_keep_threads_of_several_processes_apart_and_fit_long_build_ids() {
    let id = vec![0xab; 64];
    let stub = FakeStub::tcp(x86_stub(4, &["p1.1", "p2.1"], &[("/lib/libx.so".into(), 0x7000_0000, Some(id))]));
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    assert_eq!(serde_json::to_value(registry.connect(None).unwrap()).unwrap()["endianness"], "little");
    let directory = private_directory("processes");
    let output = directory.join("capture.json");
    let snapshot = registry.snapshot("s1", &output, &[range(0x1000, 0x100, None)]).unwrap();
    assert_eq!((snapshot.threads, snapshot.registers_recorded, snapshot.modules), (2, 8, 1));
    let binary = rampage_loaders::Binary::open(&output).unwrap();
    let mut threads: Vec<&str> = binary.snapshot_registers.iter().map(|register| register.thread_id.as_str()).collect();
    threads.dedup();
    assert_eq!(threads, ["0x100000001", "0x200000001"]);
    assert_eq!(binary.snapshot_modules[0].uuid, "ab".repeat(64));
    drop(registry);
    stub.finish().assert_clean();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn snapshots_over_the_register_or_metadata_limits_are_refused_before_reading_memory() {
    let threads: Vec<String> = (1..=64).map(|tid| format!("p1.{tid:x}")).collect();
    let threads: Vec<&str> = threads.iter().map(String::as_str).collect();
    let stub = FakeStub::tcp(x86_stub(100, &threads, &[]));
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    registry.connect(None).unwrap();
    let directory = private_directory("limits");
    let error = registry.snapshot("s1", &directory.join("registers.json"), &[range(0x1000, 0x10, None)]).unwrap_err();
    assert_eq!(code(&error), "unsupported");
    assert!(error.to_string().contains("4096 register entries"), "{error}");
    drop(registry);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('m')));

    // 130 modules with 4096-byte paths need more than the MiB a snapshot keeps for everything but memory.
    let modules: Vec<(String, u64, Option<Vec<u8>>)> = (0..130u64)
        .map(|index| (format!("{index:04}{}", "x".repeat(4092)), 0x4000_0000 + index * 0x10_0000, None))
        .collect();
    let stub = FakeStub::tcp(x86_stub(4, &["p1.1"], &modules).lenient());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    registry.connect(None).unwrap();
    let error = registry.snapshot("s1", &directory.join("modules.json"), &[range(0x1000, 0x10, None)]).unwrap_err();
    assert_eq!(code(&error), "unsupported");
    assert!(error.to_string().contains("budget"), "{error}");
    drop(registry);
    let report = stub.finish();
    assert!(!report.received.iter().any(|packet| packet == "m1000,10"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn reads_ending_at_the_top_of_the_address_space_are_reported_not_wrapped() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    registry.connect(None).unwrap();
    let memory = serde_json::to_value(registry.read_memory("s1", u64::MAX - 15, 16, None).unwrap()).unwrap();
    assert_eq!(memory["complete"], false);
    assert_eq!(memory["chunks"][0]["error"], "E14");
    assert_eq!(memory["thread"], "p1.1");
    drop(registry);
    stub.finish().assert_clean();
}

#[test]
fn the_largest_read_fits_the_result_budget_at_small_packet_sizes() {
    for packet_size in ["400", "40"] {
        let stub = FakeStub::tcp(
            Script::new()
                .on(
                    "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
                    &format!("PacketSize={packet_size}"),
                )
                .on("?", "S05")
                .on("qfThreadInfo", "")
                .on("g", &"00".repeat(536))
                .on("D", "OK")
                .memory(0x10_0000, &[0xa5; 0x10000]),
        );
        let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
        let tools = debug_tools();
        let call =
            |name: &str, input: Value| tools.iter().find(|tool| tool.name == name).unwrap().call(&registry, input);
        let connected = call("debug_connect", json!({})).unwrap();
        let limit = connected["max_read_length"].as_u64().unwrap();
        // Every chunk read, and every chunk failing.
        for address in [0x10_0000u64, 0x80_0000] {
            let memory = call("debug_read_memory", json!({"session": "s1", "address": address, "length": limit}));
            let memory = memory.unwrap_or_else(|error| panic!("PacketSize={packet_size}, {limit} bytes: {error}"));
            assert!(memory.to_string().len() <= 60_000);
        }
        drop(registry);
        stub.finish().assert_clean();
    }
}

#[test]
fn concurrent_connects_cannot_exceed_the_session_limit() {
    let stubs: Vec<FakeStub> =
        (0..MAX_DEBUG_SESSIONS + 1).map(|_| FakeStub::tcp(transcripts::qemu_cortex_m3())).collect();
    let endpoints: Vec<String> = stubs.iter().map(|stub| stub.endpoint().to_owned()).collect();
    let registry = DebugRegistry::new(&endpoints).unwrap();
    for endpoint in &endpoints[..MAX_DEBUG_SESSIONS - 1] {
        registry.connect(Some(endpoint)).unwrap();
    }
    let results: Vec<Result<String, String>> = std::thread::scope(|scope| {
        let racers: Vec<_> = endpoints[MAX_DEBUG_SESSIONS - 1..]
            .iter()
            .map(|endpoint| {
                let registry = &registry;
                scope.spawn(move || {
                    registry.connect(Some(endpoint)).map(|connection| connection.session).map_err(|error| code(&error))
                })
            })
            .collect();
        racers.into_iter().map(|racer| racer.join().unwrap()).collect()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1, "{results:?}");
    assert!(results.iter().any(|result| result.as_ref().err().map(String::as_str) == Some("session_limit")));
    // The loser reserved no slot, so it never contacted its stub.
    let loser = endpoints[MAX_DEBUG_SESSIONS - 1..]
        .iter()
        .zip(&results)
        .find(|(_, result)| result.is_err())
        .map(|(endpoint, _)| endpoint.clone())
        .unwrap();
    drop(registry);
    for stub in stubs {
        if stub.endpoint() == loser {
            // Its accept loop is still waiting; the test process ends it.
            continue;
        }
        let report = stub.finish();
        report.assert_clean();
        assert_eq!(report.received.last().map(String::as_str), Some("D;1"));
    }
}

#[test]
fn a_refused_detach_leaves_the_session_open_and_attached() {
    let stub =
        FakeStub::tcp(transcripts::qemu_cortex_m3().once("D;1", vec![Action::Reply("E01".into())]).on("D;1", "OK"));
    let registry = DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap();
    registry.connect(None).unwrap();
    let refused = serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap();
    assert_eq!(refused["state"], "stopped");
    assert_eq!((refused["detached"].as_bool(), refused["closed"].as_bool()), (Some(false), Some(false)));
    assert!(refused["detach_error"].as_str().unwrap().starts_with("target_error"));
    assert_eq!(serde_json::to_value(registry.status("s1", None, None).unwrap()).unwrap()["state"], "stopped");
    let detached = serde_json::to_value(registry.disconnect("s1").unwrap()).unwrap();
    assert_eq!((detached["state"].as_str(), detached["closed"].as_bool()), (Some("detached"), Some(true)));
    drop(registry);
    stub.finish().assert_clean();
}
