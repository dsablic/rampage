//! Apple's debugserver (RSP with LLDB's extensions) against the scripted fake stub: the handshake through
//! `qHostInfo`, `qProcessInfo` and a description without an architecture, `qRegisterInfo`-only register
//! discovery, `jThreadsInfo`, the dyld image list and memory regions, Mach exception stops and execution control.

use std::time::Duration;

use rampage_debug::fake::transcripts::{self, DebugserverTarget};
use rampage_debug::fake::{Action, FakeStub, INTERRUPT, Script};
use rampage_debug::{
    BreakKind, ByteOrder, Cancel, Config, Endpoint, Family, LayoutSource, Session, State, StopCause, StopReason,
    ThreadId,
};

fn connect(stub: &FakeStub) -> Session {
    let config = Config {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    Session::connect(&stub.endpoint().parse::<Endpoint>().unwrap(), config).unwrap()
}

fn wait() -> Duration {
    Duration::from_secs(5)
}

fn thread() -> ThreadId {
    ThreadId::parse(&format!("{:x}", transcripts::DEBUGSERVER_THREAD)).unwrap()
}

/// The stop reply of `target` with the pc at `pc`, Mach exception `exception` and extra fields.
fn stop_at(pc: u64, signal: u8, exception: (u32, Vec<u64>), extra: &str) -> String {
    let mut target = DebugserverTarget { signal, exception, ..DebugserverTarget::default() };
    target.registers[transcripts::DEBUGSERVER_PC as usize] = pc;
    transcripts::debugserver_stop(&target, transcripts::DEBUGSERVER_THREAD, extra)
}

fn assert_handshake(session: &Session, source: LayoutSource) {
    let info = session.info();
    assert_eq!(info.family, Family::Aarch64);
    assert_eq!(info.architecture.as_deref(), Some("aarch64"));
    assert_eq!(info.pointer_size, Some(8));
    assert_eq!(info.byte_order, ByteOrder::Little);
    assert_eq!(info.byte_order_evidence, "qProcessInfo states endian:little");
    let lldb = info.lldb.as_ref().unwrap();
    assert!(lldb.apple && !lldb.arm64e, "the host is arm64e, the process plain arm64");
    assert_eq!(lldb.process.as_ref().unwrap().pid, Some(transcripts::DEBUGSERVER_PID));
    let mask = info.address_mask.as_ref().unwrap();
    assert_eq!((mask.low_bits, mask.source.as_str()), (47, "qHostInfo addressing_bits:47"));
    assert_eq!(info.strip_code_address(0x0023_8001_0000_3f5c), 0x1_0000_3f5c);
    let layout = info.layout.as_ref().unwrap();
    assert_eq!(layout.source, source);
    // Views (w0..w28) have no bytes of their own; v0 starts after cpsr's padding.
    assert!(layout.register("w0").is_none());
    assert_eq!(layout.register_or_alias("x30").unwrap().name, "lr");
    assert_eq!(layout.generic("pc").unwrap().regnum, transcripts::DEBUGSERVER_PC);
    // Stated offsets have no gaps: v0 follows cpsr directly.
    assert_eq!(layout.register("v0").unwrap().offset, 268);
    assert!(info.modules_available && info.memory_map_available);
}

#[test]
fn connects_to_debugserver_with_its_description_host_and_process_info() {
    let target = DebugserverTarget::default();
    let stub = FakeStub::tcp(transcripts::debugserver_arm64(&target));
    let session = connect(&stub);
    assert_handshake(&session, LayoutSource::TargetDescription);

    let status = session.status().unwrap();
    assert_eq!(status.state, State::Stopped);
    assert_eq!(status.threads.len(), 2);
    let main = status.threads[0].detail.as_ref().unwrap();
    assert_eq!((main.name.as_deref(), main.queue.as_deref()), (Some("macho-loop"), Some("com.apple.main-thread")));
    assert_eq!(main.exception.as_ref().map(|exception| exception.name), Some("EXC_SOFTWARE"));
    assert!(status.threads[1].detail.as_ref().unwrap().name.is_none());
    let rampage_debug::StopReply::Signal { signal, reasons, .. } = status.stop.unwrap() else { panic!() };
    assert_eq!(signal, 0x11);
    assert!(matches!(&reasons[0], StopReason::Exception(exception) if exception.signal == Some(0x11)));

    let registers = session.registers(None).unwrap();
    let value = |name: &str| registers.registers.iter().find(|register| register.name == name).unwrap().integer();
    assert_eq!(value("pc"), Some(0x1_0000_3f50));
    assert_eq!(value("lr"), Some(0x1_8c4a_6e8c));
    assert_eq!(value("cpsr"), Some(0x6000_0000));
    assert_eq!(value("x7"), Some(0x107));

    let modules = session.modules().unwrap();
    assert_eq!(modules.modules.len(), 3);
    let main = &modules.modules[0];
    let image = main.dyld.as_ref().unwrap();
    assert!(main.main && !image.in_shared_cache);
    assert_eq!(image.uuid.as_deref(), Some("4C4C44A5-5555-3144-A1C2-3B6E5D7E8F90"));
    assert_eq!((image.load_address, image.text_vmaddr), (0x1_0000_0000, Some(0x1_0000_0000)));
    let libc = modules.modules[2].dyld.as_ref().unwrap();
    assert!(libc.in_shared_cache);
    assert_eq!(libc.load_address - libc.text_vmaddr.unwrap(), 0xc05_0000);
    assert!(modules.limitations.iter().any(|limitation| limitation.contains("dyld shared cache")));
    let text = modules.regions.iter().find(|region| region.start == 0x1_0000_0000).unwrap();
    assert_eq!((text.length, text.permissions.as_deref(), text.kind.as_str()), (0x4000, Some("rx"), "mapped"));
    assert!(modules.regions.iter().all(|region| region.permissions.as_deref().is_some_and(|p| !p.is_empty())));
    // The busy stack's reply (a dirty-page list past 4 KiB) does not end the walk, which reaches the end.
    assert_eq!(modules.regions.len(), 7);
    assert!(!modules.regions_partial);
    assert!(modules.regions.iter().any(|region| region.permissions.as_deref() == Some("rw")));

    // Registers read twice at one stop cost one round of `p`.
    session.registers(None).unwrap();

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with("qXfer:libraries")), "{:?}", report.received);
    assert_eq!(report.received.iter().filter(|packet| *packet == "?").count(), 1);
    // No `g` or `G` reaches debugserver; the stop's expedited registers stand in for x0..cpsr of the main thread.
    assert!(!report.received.iter().any(|packet| packet == "g" || packet.starts_with('G')));
    assert!(!report.received.iter().any(|packet| packet == "p20" || packet == "p0"), "{:?}", report.received);
    let v0 = report.received.iter().filter(|packet| *packet == "p3f").count();
    assert_eq!(v0, 1, "v0 is read once and cached for the stop");
    // The image list: addresses first, then one batch of full information.
    let images: Vec<&String> =
        report.received.iter().filter(|packet| packet.starts_with("jGetLoadedDynamicLibrariesInfos")).collect();
    assert_eq!(images.len(), 2, "{images:?}");
    assert_eq!(images[1], "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[4294967296,6648627200,6649446400]}");
}

#[test]
fn discovers_registers_with_qregisterinfo_when_there_is_no_description() {
    let target = DebugserverTarget { target_xml: false, ..DebugserverTarget::default() };
    let stub = FakeStub::tcp(transcripts::debugserver_arm64(&target));
    let session = connect(&stub);
    assert_handshake(&session, LayoutSource::RegisterInfo);
    let layout = session.info().layout.as_ref().unwrap();
    assert_eq!(layout.register("sp").unwrap().alt_name.as_deref(), Some("xsp"));
    assert_eq!(layout.registers.len(), 34 + 32 + 5);
    let registers = session.registers(None).unwrap();
    let pc = registers.registers.iter().find(|register| register.name == "pc").unwrap();
    assert_eq!(pc.integer(), Some(0x1_0000_3f50));
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.iter().any(|packet| packet == "qRegisterInfo47"), "asked until E45");
    assert!(!report.received.iter().any(|packet| packet.starts_with("qXfer")));
}

#[test]
fn gdb_stubs_are_not_asked_lldb_queries() {
    let stub = FakeStub::tcp(transcripts::gdbserver_aarch64());
    let session = connect(&stub);
    assert!(session.info().lldb.is_none() && session.info().address_mask.is_none());
    session.modules().unwrap();
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    let lldb = ["qHostInfo", "qProcessInfo", "qRegisterInfo", "qMemoryRegionInfo", "j"];
    for packet in &report.received {
        assert!(!lldb.iter().any(|prefix| packet.starts_with(prefix)), "{packet}");
    }
}

/// debugserver with execution control: `vCont`, software breakpoints of kind 4 and an 8-byte watchpoint.
fn executing(target: &DebugserverTarget) -> Script {
    let main = format!("{:x}", transcripts::DEBUGSERVER_THREAD);
    transcripts::debugserver_arm64(target)
        .execution()
        .on("vCont?", "vCont;c;C;s;S")
        .on("Z0,100003f60,4", "OK")
        .on("z0,100003f60,4", "OK")
        .on("Z2,100008000,8", "OK")
        .on("z2,100008000,8", "OK")
        .once("vCont;c", vec![Action::Reply(stop_at(0x1_0000_3f60, 5, (6, vec![1, 0x1_0000_3f60]), ""))])
        .once(&format!("vCont;s:{main}"), vec![Action::Reply(stop_at(0x1_0000_3f64, 5, (6, vec![1, 0]), ""))])
        // A watchpoint stop has no exception and signal 0; `watch_addr` is the watchpoint's start and
        // `me_watch_addr` the address accessed.
        .once(
            "vCont;c",
            vec![Action::Reply(stop_at(
                0x1_0000_3f70,
                0,
                (0, vec![]),
                "reason:watchpoint;description:34323934393939393332382030203432393439393933323b;\
                 watch_addr:100008000;me_watch_addr:100008004;wp_hw_idx:0;",
            ))],
        )
        // debugserver on ARM reports the hit before the store executes: the next continue steps past it first.
        .once(&format!("vCont;s:{main}"), vec![Action::Reply(stop_at(0x1_0000_3f74, 5, (6, vec![1, 0]), ""))])
        .once("vCont;c", vec![])
        .on_interrupt(vec![Action::Reply(stop_at(0x1_0000_3f68, 0x11, (5, vec![0x10003, 0x11]), ""))])
        .once("vCont;c", vec![Action::Reply(stop_at(0x10, 0x91, (1, vec![1, 0x10]), ""))])
}

#[test]
fn maps_mach_exceptions_into_stop_events_and_steps_with_vcont() {
    let target = DebugserverTarget::default();
    let stub = FakeStub::tcp(executing(&target));
    let session = connect(&stub);
    let breakpoint = session.set_breakpoint(Some(1), BreakKind::Software, 0x1_0000_3f60, None).unwrap();
    assert_eq!(breakpoint.size, 4, "arm64 software breakpoints are kind 4");

    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(
        (event.reason, event.pc, event.breakpoints.clone()),
        (StopCause::Breakpoint, Some(0x1_0000_3f60), vec![1])
    );
    assert_eq!(event.exception.as_ref().map(|exception| exception.name), Some("EXC_BREAKPOINT"));

    // A step from the breakpoint: vCont;s on the main thread, a SIGTRAP with EXC_BREAKPOINT and no reason.
    let steps = session.step_with(Some(run.epoch), None, 1, true, &Cancel::new()).unwrap();
    assert_eq!((steps.completed, steps.event.as_ref().unwrap().reason), (1, StopCause::Step));
    assert_eq!(steps.thread, Some(thread()));

    let watch = session.set_breakpoint(Some(steps.epoch), BreakKind::Write, 0x1_0000_8000, Some(8)).unwrap();
    let run = session.resume(Some(steps.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(event.reason, StopCause::Watchpoint);
    assert_eq!(event.breakpoints, vec![watch.id]);
    let hit = event.watch.as_ref().unwrap();
    assert_eq!((hit.access, hit.address, hit.accessed), ("access", 0x1_0000_8000, Some(0x1_0000_8004)));
    assert!(event.exception.is_none());

    // The next continue, with the watchpoint still set, steps the store first so it does not fire again, then
    // keeps running; an interrupt stops it, which debugserver does with SIGSTOP.
    let run = session.resume(Some(run.epoch), Duration::from_millis(100), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Running);
    let run = session.interrupt(wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(event.reason, StopCause::Interrupted);
    assert_eq!(event.exception.as_ref().and_then(|exception| exception.code_name), Some("EXC_SOFT_SIGNAL"));

    // A fault: EXC_BAD_ACCESS (KERN_INVALID_ADDRESS) at 0x10, a signal stop carrying the fault address.
    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.signal), (StopCause::Signal, Some(0x91)));
    let exception = event.exception.as_ref().unwrap();
    assert_eq!((exception.name, exception.fault_address), ("EXC_BAD_ACCESS", Some(0x10)));
    assert_eq!(exception.code_name, Some("KERN_INVALID_ADDRESS"));
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["exception"]["fault_address"], "0x10");

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    let control: Vec<&str> = report
        .received
        .iter()
        .map(String::as_str)
        .filter(|packet| {
            packet.starts_with("vCont;") || packet.starts_with('Z') || packet.starts_with('z') || *packet == INTERRUPT
        })
        .collect();
    let main = format!("vCont;s:{:x}", transcripts::DEBUGSERVER_THREAD);
    assert_eq!(
        control,
        [
            "Z0,100003f60,4",
            "vCont;c",
            "z0,100003f60,4",
            main.as_str(),
            "Z0,100003f60,4",
            "Z2,100008000,8",
            "vCont;c",
            "z2,100008000,8",
            main.as_str(),
            "Z2,100008000,8",
            "vCont;c",
            INTERRUPT,
            "vCont;c",
            "z2,100008000,8",
            "z0,100003f60,4",
        ]
    );
}
