use std::io::{Read, Write};
use std::time::Duration;

use rampage_debug::fake::{Action, FakeStub, Script, le_hex, le_value, transcripts};
use rampage_debug::{ByteOrder, Config, DebugError, Endpoint, Family, Session, State, StopReply, ThreadId};

fn config() -> Config {
    Config { connect_timeout: Duration::from_secs(5), command_timeout: Duration::from_secs(5) }
}

fn connect(stub: &FakeStub) -> Result<Session, DebugError> {
    Session::connect(&stub.endpoint().parse::<Endpoint>().unwrap(), config())
}

fn socket_path(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-debug-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("stub.sock")
}

#[test]
fn reads_a_halted_cortex_m_like_qemu() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let session = connect(&stub).unwrap();
    let info = session.info();
    assert_eq!(info.architecture.as_deref(), Some("arm"));
    assert_eq!(info.family, Family::Arm);
    assert_eq!(info.byte_order, ByteOrder::Little);
    assert!(info.byte_order_evidence.contains("AIRCR"), "{}", info.byte_order_evidence);
    assert_eq!(info.pointer_size, Some(4));
    assert_eq!(info.packet_size, 0x20020);
    assert!(info.multiprocess && info.memory_map_available && !info.modules_available && !info.no_ack_mode);

    let status = session.status().unwrap();
    assert_eq!(status.state, State::Stopped);
    assert_eq!(status.epoch, 1);
    assert!(matches!(status.stop, Some(StopReply::Signal { signal: 5, .. })));
    assert_eq!(status.threads.len(), 1);
    assert_eq!(status.threads[0].id, ThreadId { pid: Some(1), tid: 1 });
    assert_eq!(status.threads[0].extra.as_deref(), Some("CPU#0 [halted ]"));

    let registers = session.registers(None).unwrap();
    let value = |name: &str| registers.registers.iter().find(|register| register.name == name).unwrap();
    assert_eq!(value("pc").value.as_deref(), Some("0x00000048"));
    assert_eq!(value("pc").bytes.as_deref(), Some("48000000"));
    assert_eq!(value("sp").integer(), Some(0x2001_0000));
    assert_eq!(value("xpsr").integer(), Some(0x4100_0000));
    // Registers past the end of the `g` reply come from `p`.
    assert_eq!(value("msp").integer(), Some(0x2001_0000));
    assert_eq!(value("faultmask").integer(), Some(0));

    let memory = session.read_memory(0, 8, None).unwrap();
    assert!(memory.complete());
    assert_eq!(memory.chunks[0].bytes, transcripts::CORTEX_M_FLASH);
    assert_eq!(memory.packet, "m");
    // Past the end of RAM: the readable prefix, then an explicit error.
    let memory = session.read_memory(0x2000_0100, 0x200, None).unwrap();
    assert!(!memory.complete());
    assert_eq!(memory.chunks[0].read, 0x100);
    assert!(memory.chunks[0].error.as_deref().unwrap().contains("256 of 512"));
    let memory = session.read_memory(0x3000_0000, 4, None).unwrap();
    assert_eq!(memory.chunks[0].error.as_deref(), Some("E14"));

    let modules = session.modules().unwrap();
    assert!(modules.modules.is_empty());
    assert_eq!(modules.regions.len(), 2);
    assert_eq!((modules.regions[0].kind.as_str(), modules.regions[0].flash_block_size), ("flash", Some(0x400)));
    assert_eq!((modules.regions[1].start, modules.regions[1].length), (0x2000_0000, 0x10000));

    assert_eq!(session.detach().unwrap().state, State::Detached);
    assert!(matches!(session.status(), Err(DebugError::State(_))));
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.iter().any(|packet| packet == "D;1"), "{:?}", report.received);
    assert!(!report.received.iter().any(|packet| packet == "D"));
}

#[test]
fn reads_aarch64_gdbserver_over_a_unix_socket() {
    let path = socket_path("aarch64");
    let stub = FakeStub::unix(&path, transcripts::gdbserver_aarch64());
    let session = connect(&stub).unwrap();
    let info = session.info();
    assert_eq!(info.family, Family::Aarch64);
    assert!(info.no_ack_mode && info.modules_available && !info.memory_map_available);
    assert_eq!(info.byte_order, ByteOrder::Unknown);
    assert_eq!(info.pointer_size, Some(8));

    let status = session.status().unwrap();
    let Some(StopReply::Signal { thread, registers, core, .. }) = &status.stop else { panic!() };
    assert_eq!(thread.unwrap().to_string(), "p6a1b.6a1b");
    assert_eq!(*core, Some(2));
    assert_eq!(registers.len(), 3);
    assert_eq!(status.threads.len(), 2);
    assert!(status.threads.iter().all(|thread| thread.extra.is_none()));

    // Without byte-order evidence, register values stay as transmitted bytes.
    let (_, _, pc, _) = transcripts::aarch64_values();
    let registers = session.registers(None).unwrap();
    let register = |registers: &rampage_debug::Registers, name: &str| {
        registers.registers.iter().find(|register| register.name == name).unwrap().clone()
    };
    assert_eq!(register(&registers, "pc").value, None);
    assert_eq!(register(&registers, "pc").bytes, Some(le_hex(pc, 8)));
    assert_eq!(register(&registers, "v31").bitsize, 128);
    let second = ThreadId::parse("p6a1b.6a1c").unwrap();
    let registers = session.registers(Some(second)).unwrap();
    assert_eq!(registers.thread, Some(second));
    assert_eq!(le_value(&register(&registers, "pc").bytes.unwrap()), transcripts::aarch64_second_thread_pc());
    let unknown = ThreadId::parse("p6a1b.1").unwrap();
    assert!(matches!(session.registers(Some(unknown)), Err(DebugError::Invalid(_))));

    // `binary-upload+` selects `x` reads.
    let (_, sp, _, _) = transcripts::aarch64_values();
    let memory = session.read_memory(sp, 0x100, None).unwrap();
    assert_eq!(memory.packet, "x");
    assert_eq!(memory.chunks[0].bytes, vec![0x5a; 0x100]);

    let modules = session.modules().unwrap();
    assert_eq!(modules.modules.len(), 3);
    assert!(modules.modules[0].main);
    let libc = &modules.modules[2];
    assert_eq!(libc.name, "/lib/aarch64-linux-gnu/libc.so.6");
    assert_eq!(libc.build_id.as_deref(), Some("deadbeef01020304"));
    assert_eq!(modules.modules[1].build_id, None);
    assert_eq!(modules.exec_file.as_deref(), Some("/home/user/prog"));
    assert!(modules.regions.is_empty());

    assert_eq!(session.detach().unwrap().state, State::Detached);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.iter().any(|packet| packet == "D;6a1b"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// A minimal stub without a target description, threads or acks quirks.
fn bare(stop: &str) -> Script {
    Script::new()
        .on("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm", "PacketSize=1000")
        .on("?", stop)
        .on("qfThreadInfo", "")
        .on("D", "OK")
}

#[test]
fn falls_back_to_builtin_layouts_by_g_size() {
    let mut g = String::new();
    for index in 0..31u64 {
        g += &le_hex(index, 8);
    }
    g += &(le_hex(0x8000, 8) + &le_hex(0x400000, 8) + &le_hex(0, 4));
    let stub = FakeStub::tcp(bare("S05").on("g", &g));
    let session = connect(&stub).unwrap();
    let info = session.info();
    assert_eq!(info.family, Family::Aarch64);
    assert!(info.limitations.iter().any(|limitation| limitation.contains("built-in `aarch64` layout")));
    assert!(!info.limitations.iter().any(|limitation| limitation.contains("no PacketSize")));
    assert_eq!(session.status().unwrap().threads.len(), 0);
    let registers = session.registers(None).unwrap();
    assert_eq!(registers.registers.len(), 34);
    drop(session);
    stub.finish().assert_clean();

    let stub = FakeStub::tcp(bare("S05").on("g", "0011"));
    let session = connect(&stub).unwrap();
    assert!(session.info().layout.is_none());
    assert!(matches!(session.registers(None), Err(DebugError::Unsupported(_))));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn an_exited_process_has_nothing_to_read_or_detach() {
    let stub = FakeStub::tcp(bare("W00;process:2a"));
    let session = connect(&stub).unwrap();
    assert_eq!(session.status().unwrap().state, State::Exited);
    assert!(matches!(session.registers(None), Err(DebugError::State(_))));
    assert!(matches!(session.read_memory(0, 4, None), Err(DebugError::State(_))));
    assert_eq!(session.detach().unwrap().state, State::Exited);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('D')));
}

#[test]
fn retransmits_naked_packets_and_recovers_from_corrupt_replies() {
    let stub = FakeStub::tcp(
        bare("S05")
            .nak("qfThreadInfo", 2, "")
            .once("g", vec![Action::Corrupt("00".repeat(68))])
            .on("g", &"00".repeat(68)),
    );
    let session = connect(&stub).unwrap();
    assert_eq!(session.info().family, Family::Arm);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
}

#[test]
fn slow_replies_time_out_and_lose_the_session() {
    let stub = FakeStub::tcp(
        bare("S05")
            .once("g", vec![Action::Reply("00".repeat(68))])
            .once("g", vec![Action::Reply("00".repeat(68))])
            .on_actions("g", vec![Action::Sleep(Duration::from_millis(1500)), Action::Reply("00".repeat(68))]),
    );
    let short = Config { connect_timeout: Duration::from_secs(5), command_timeout: Duration::from_millis(500) };
    let session = Session::connect(&stub.endpoint().parse().unwrap(), short).unwrap();
    assert!(matches!(session.registers(None), Err(DebugError::Timeout(_))));
    let status = session.status().unwrap();
    assert!(matches!(status.state, State::Lost { .. }), "{status:?}");
    assert!(matches!(session.registers(None), Err(DebugError::State(_))));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn a_disconnect_mid_command_loses_the_session() {
    let stub = FakeStub::tcp(
        bare("S05")
            .once("g", vec![Action::Reply("00".repeat(68))])
            .once("g", vec![Action::Reply("00".repeat(68))])
            .on_actions("g", vec![Action::Close]),
    );
    let session = connect(&stub).unwrap();
    assert!(matches!(session.registers(None), Err(DebugError::Lost(_))));
    assert!(matches!(session.status().unwrap().state, State::Lost { .. }));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn malformed_and_oversized_replies_are_refused() {
    let stub = FakeStub::tcp(bare("Tzz"));
    assert!(matches!(connect(&stub), Err(DebugError::Protocol(_))));
    // The stream was still in step, so the failed handshake detached rather than just disconnecting.
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(report.received.last().map(String::as_str), Some("D"));

    let mut oversized = b"$".to_vec();
    oversized.extend(std::iter::repeat_n(b'0', 2 * 1024 * 1024));
    oversized.extend_from_slice(b"#00");
    let stub = FakeStub::tcp(
        bare("S05")
            .once("g", vec![Action::Reply("00".repeat(68))])
            .once("g", vec![Action::Reply("00".repeat(68))])
            .on_actions("g", vec![Action::Raw(oversized)]),
    );
    let session = connect(&stub).unwrap();
    let error = session.registers(None).unwrap_err();
    assert!(matches!(error, DebugError::Protocol(ref message) if message.contains("limit")), "{error:?}");
    drop(session);
    stub.finish().assert_clean();

    // A `g` reply longer than the layout, and memory replies that are not hex.
    let stub = FakeStub::tcp(
        bare("S05")
            .once("g", vec![Action::Reply("00".repeat(68))])
            .once("g", vec![Action::Reply("00".repeat(68))])
            .on("g", &"00".repeat(69))
            .on("m0,4", "zzzzzzzz"),
    );
    let session = connect(&stub).unwrap();
    assert!(matches!(session.registers(None), Err(DebugError::Protocol(_))));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn dropping_a_session_detaches() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let session = connect(&stub).unwrap();
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(report.received.last().map(String::as_str), Some("D;1"));
}

#[test]
fn the_fake_stub_fails_any_execution_control_packet() {
    for packet in
        ["c", "s", "vCont?", "vCont;c", "Z0,1000,4", "M1000,1:00", "G00", "P1=00", "k", "vKill;1", "qRcmd,6869"]
    {
        assert!(rampage_debug::fake::execution_control(packet), "{packet}");
        let stub = FakeStub::tcp(Script::new());
        let mut stream = std::net::TcpStream::connect(stub.endpoint()).unwrap();
        stream.write_all(&rampage_debug::packet::encode(packet.as_bytes())).unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        let report = stub.finish();
        assert_eq!(report.violations.len(), 1, "{packet}: {:?}", report.violations);
        assert!(report.violations[0].contains("forbidden"));
    }
    for packet in ["?", "g", "m0,4", "D", "D;1", "qXfer:features:read:target.xml:0,10"] {
        assert!(!rampage_debug::fake::execution_control(packet), "{packet}");
    }
}

fn multiprocess() -> Script {
    Script::new()
        .on("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm", "PacketSize=1000;multiprocess+")
        .on("?", "T05thread:p1.1;")
        .on("qfThreadInfo", "mp1.1,p2.1")
        .on("qsThreadInfo", "l")
        .on("qThreadExtraInfo,p1.1", "")
        .on("Hgp1.1", "OK")
        .on("Hgp2.1", "OK")
        .on("g", &"00".repeat(68))
}

#[test]
fn a_refused_detach_keeps_the_session_and_a_retry_detaches_only_the_rest() {
    let stub =
        FakeStub::tcp(multiprocess().on("D;1", "OK").once("D;2", vec![Action::Reply("E01".into())]).on("D;2", "OK"));
    let session = connect(&stub).unwrap();
    let error = session.detach().unwrap_err();
    assert!(matches!(error, DebugError::Target(ref message) if message.contains("D;2")), "{error:?}");
    // Still attached to process 2, and still serving.
    let status = session.status().unwrap();
    assert_eq!(status.state, State::Stopped);
    assert_eq!(status.threads.iter().map(|thread| thread.id.to_string()).collect::<Vec<_>>(), ["p1.1", "p2.1"]);
    assert_eq!(session.detach().unwrap().state, State::Detached);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    let detaches: Vec<&str> =
        report.received.iter().filter(|packet| packet.starts_with('D')).map(String::as_str).collect();
    assert_eq!(detaches, ["D;1", "D;2", "D;1", "D;2"]);
}

#[test]
fn reads_at_the_top_of_the_address_space_do_not_overflow() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let session = connect(&stub).unwrap();
    let memory = session.read_memory(u64::MAX - 15, 16, None).unwrap();
    assert!(!memory.complete());
    assert_eq!(memory.chunks.len(), 1);
    assert_eq!((memory.chunks[0].address, memory.chunks[0].requested), (u64::MAX - 15, 16));
    assert!(matches!(session.read_memory(u64::MAX - 15, 17, None), Err(DebugError::Invalid(_))));
    assert_eq!(session.status().unwrap().state, State::Stopped);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.contains(&"mfffffffffffffff0,10".to_owned()));
}

#[test]
fn reads_without_a_thread_use_the_stop_thread_not_the_last_selection() {
    let stub = FakeStub::tcp(transcripts::gdbserver_aarch64());
    let session = connect(&stub).unwrap();
    let second = ThreadId::parse("p6a1b.6a1c").unwrap();
    assert_eq!(session.registers(Some(second)).unwrap().thread, Some(second));
    let registers = session.registers(None).unwrap();
    assert_eq!(registers.thread, ThreadId::parse("p6a1b.6a1b"));
    let (_, _, pc, _) = transcripts::aarch64_values();
    let value = registers.registers.iter().find(|register| register.name == "pc").unwrap();
    assert_eq!(value.bytes, Some(le_hex(pc, 8)));
    session.registers(Some(second)).unwrap();
    assert_eq!(session.read_memory(0x1000, 4, None).unwrap().thread, ThreadId::parse("p6a1b.6a1b"));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn a_new_stop_reply_is_a_new_epoch() {
    let stub = FakeStub::tcp(
        Script::new()
            .on("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm", "PacketSize=1000")
            .once("?", vec![Action::Reply("S05".into())])
            .once("?", vec![Action::Reply("S05".into())])
            .on("?", "S0b")
            .on("qfThreadInfo", "")
            .on("g", "0011")
            .on("D", "OK"),
    );
    let session = connect(&stub).unwrap();
    assert_eq!(session.status().unwrap().epoch, 1);
    let status = session.status().unwrap();
    assert_eq!(status.epoch, 2);
    assert!(matches!(status.stop, Some(StopReply::Signal { signal: 11, .. })));
    assert_eq!(session.status().unwrap().epoch, 2);
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn big_endian_cortex_m_is_read_from_aircr_endianness() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3().memory(0xe000_ed0c, &[0x00, 0x80, 0x05, 0xfa]));
    let session = connect(&stub).unwrap();
    assert_eq!(session.info().byte_order, ByteOrder::Big);
    assert!(session.info().byte_order_evidence.contains("ENDIANNESS set"));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn an_unusable_target_description_falls_back_with_a_limitation() {
    let stub = FakeStub::tcp(
        Script::new()
            .on(
                "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
                "PacketSize=1000;qXfer:features:read+",
            )
            .on("?", "S05")
            .on("qfThreadInfo", "")
            .on("D", "OK")
            .xfer("features", "target.xml", "<target><xi:include href=\"cores/missing.xml\"/></target>")
            .on_prefix("qXfer:features:read:cores/missing.xml:", vec![Action::Reply("E00".into())])
            .on("g", &"00".repeat(68)),
    );
    let session = connect(&stub).unwrap();
    let info = session.info();
    assert!(
        info.limitations.iter().any(|limitation| limitation.contains("target description is unusable")),
        "{:?}",
        info.limitations
    );
    assert_eq!(info.family, Family::Arm);
    drop(session);
    stub.finish().assert_clean();
}
