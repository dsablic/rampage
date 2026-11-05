//! Windows stubs (step 9.6a) against the scripted fake stub: MinGW-w64 gdbserver and lldb-server on Windows x64,
//! and a WoW64 process under gdbserver. The transcripts are built from the stubs' sources (see
//! `rampage_debug::fake::windows`), not recorded: module lists and the main executable, exception stops,
//! breakpoints, watchpoints and interrupts that stop in a thread Windows creates.

use std::time::Duration;

use rampage_debug::fake::windows::{self, BREAKIN_THREAD, MAIN_THREAD, SECOND_THREAD, WindowsImage, WindowsProcess};
use rampage_debug::fake::{Action, FakeStub, INTERRUPT, Script};
use rampage_debug::pe;
use rampage_debug::{
    BreakKind, Cancel, Config, DebugError, Endpoint, Exception, Family, Session, State, StopCause, StopReason, ThreadId,
};

const EXE_BASE: u64 = 0x7ff6_1234_0000;
const NTDLL_BASE: u64 = 0x7ffb_1d40_0000;
const KERNEL32_BASE: u64 = 0x7ffb_1c20_0000;
const STACK: u64 = 0xd1_2350_f000;

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

fn thread(id: u64) -> ThreadId {
    ThreadId::parse(&format!("{id:x}")).unwrap()
}

/// The executable (not a DLL, with a CodeView record), ntdll and kernel32.
fn images(wide: bool) -> Vec<WindowsImage> {
    let (exe, ntdll, kernel32) =
        if wide { (EXE_BASE, NTDLL_BASE, KERNEL32_BASE) } else { (0x0040_0000, 0x7720_0000, 0x7600_0000) };
    let system = if wide { "C:\\Windows\\SYSTEM32" } else { "C:\\Windows\\SysWOW64" };
    vec![
        WindowsImage {
            path: "C:\\work\\pe-loop.exe".into(),
            base: exe,
            mapped: windows::synthetic_image(wide, false, exe, 0x2000, Some(([0xab; 16], 1))),
        },
        WindowsImage {
            path: format!("{system}\\ntdll.dll"),
            base: ntdll,
            mapped: windows::synthetic_image(wide, true, ntdll, 0x2000, Some(([0x11; 16], 1))),
        },
        WindowsImage {
            path: format!("{system}\\KERNEL32.DLL"),
            base: kernel32,
            mapped: windows::synthetic_image(wide, true, kernel32, 0x2000, None),
        },
    ]
}

fn x64() -> WindowsProcess {
    let mut process = WindowsProcess::x64(images(true), EXE_BASE + 0x1000, STACK);
    process.memory.push((STACK, vec![0x5a; 0x100]));
    process
}

#[test]
fn gdbserver_lists_dlls_at_their_base_and_adds_the_executable_from_the_peb() {
    let process = x64();
    let stub = FakeStub::tcp(windows::gdbserver_windows(&process));
    let session = connect(&stub);
    let info = session.info();
    assert_eq!(info.family, Family::X86_64);
    let windows = info.windows.as_ref().unwrap();
    assert_eq!(windows.stub, "gdbserver");
    assert!(windows.evidence.contains("Windows"), "{}", windows.evidence);
    assert!(info.lldb.is_none(), "gdbserver is not asked LLDB's queries");

    let modules = session.modules().unwrap();
    assert_eq!(modules.exec_file.as_deref(), Some("C:\\work\\pe-loop.exe"));
    // gdbserver leaves the executable out (`add_dll` enumerates from index 1); it comes from the PEB.
    let main = &modules.modules[0];
    assert_eq!((main.name.as_str(), main.source, main.main), ("C:\\work\\pe-loop.exe", "peb", true));
    let image = main.pe.as_ref().unwrap();
    assert_eq!((image.base, image.base_from, image.dll), (EXE_BASE, "peb", false));
    assert_eq!(image.codeview.as_ref().map(|codeview| codeview.guid), Some([0xab; 16]));
    // DLLs: the segment address is the base plus 0x1000 (`win32-low.cc`, `handle_load_dll`).
    let ntdll = &modules.modules[1];
    assert_eq!(ntdll.segments, vec![NTDLL_BASE + 0x1000]);
    let image = ntdll.pe.as_ref().unwrap();
    assert_eq!(
        (image.base, image.base_from, image.dll, image.machine.as_str()),
        (NTDLL_BASE, "segment_minus_0x1000", true, "x86-64")
    );
    assert_eq!(image.codeview.as_ref().map(|codeview| codeview.age), Some(1));
    assert!(modules.modules[2].pe.as_ref().unwrap().codeview.is_none());
    assert!(!ntdll.main);

    let registers = session.registers(None).unwrap();
    let value = |name: &str| registers.registers.iter().find(|register| register.name == name).unwrap().integer();
    assert_eq!(value("rip"), Some(EXE_BASE + 0x1000));
    assert_eq!(value("rsp"), Some(STACK));

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.iter().any(|packet| packet == &format!("qGetTIBAddr:{MAIN_THREAD:x}")));
    assert!(!report.received.iter().any(|packet| packet.starts_with("qHostInfo")), "{:?}", report.received);
}

/// gdbserver on `process` with execution control, `vCont`, and the given stops and exception records.
fn executing(process: &WindowsProcess) -> Script {
    windows::gdbserver_windows(process)
        .execution()
        .on("vCont?", "vCont;c;C;t;s;S")
        .on(&format!("Z0,{:x},1", EXE_BASE + 0x1040), "OK")
        .on(&format!("z0,{:x},1", EXE_BASE + 0x1040), "OK")
        // gdbserver on Windows has no read watchpoints (`win32-i386-low.cc`, `i386_supports_z_point_type`).
        .on(&format!("Z3,{:x},8", EXE_BASE + 0x3000), "")
        .on(&format!("Z2,{:x},8", EXE_BASE + 0x3000), "OK")
        .on(&format!("z2,{:x},8", EXE_BASE + 0x3000), "OK")
}

#[test]
fn gdbserver_reports_windows_exceptions_through_siginfo_and_breakpoints_as_breakpoints() {
    let process = x64();
    let breakpoint = EXE_BASE + 0x1040;
    let stub = FakeStub::tcp(
        executing(&process)
            // The breakpoint: SIGTRAP with swbreak and the pc already moved back onto the int3.
            .once(
                "vCont;c",
                vec![Action::Reply(windows::gdbserver_stop(
                    &process,
                    &process.at(breakpoint),
                    MAIN_THREAD,
                    5,
                    "swbreak:;",
                ))],
            )
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(true, pe::EXCEPTION_BREAKPOINT, breakpoint, &[0]))],
            )
            // Stepping past it: a single-step trap, whose exception record is not asked for.
            .once(
                &format!("vCont;s:{MAIN_THREAD:x}"),
                vec![Action::Reply(windows::gdbserver_stop(&process, &process.at(breakpoint + 4), MAIN_THREAD, 5, ""))],
            )
            // A write to address 0x10: EXCEPTION_ACCESS_VIOLATION as SIGSEGV.
            .once(
                "vCont;c",
                vec![Action::Reply(windows::gdbserver_stop(
                    &process,
                    &process.at(breakpoint + 8),
                    MAIN_THREAD,
                    0x0b,
                    "",
                ))],
            )
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(
                    true,
                    pe::EXCEPTION_ACCESS_VIOLATION,
                    breakpoint + 8,
                    &[1, 0x10],
                ))],
            ),
    );
    let session = connect(&stub);
    let entry = session.set_breakpoint(Some(1), BreakKind::Software, breakpoint, None).unwrap();
    assert_eq!(entry.size, 1);
    let read = session.set_breakpoint(Some(1), BreakKind::Read, EXE_BASE + 0x3000, Some(8)).unwrap_err();
    assert!(matches!(read, DebugError::Unsupported(_)), "{read}");

    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(
        (event.reason, event.pc, event.breakpoints.clone()),
        (StopCause::Breakpoint, Some(breakpoint), vec![entry.id])
    );
    let exception = event.exception.as_ref().and_then(Exception::windows).unwrap();
    assert_eq!(
        (exception.name, exception.source, exception.address),
        ("EXCEPTION_BREAKPOINT", "siginfo", Some(breakpoint))
    );
    assert!(event.warnings.is_empty(), "{:?}", event.warnings);

    // The step past the breakpoint is a step (EXCEPTION_SINGLE_STEP), then the continue faults.
    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.signal), (StopCause::Signal, Some(0x0b)));
    let exception = event.exception.as_ref().and_then(Exception::windows).unwrap();
    assert_eq!(
        (exception.name, exception.access, exception.fault_address, exception.noncontinuable),
        ("EXCEPTION_ACCESS_VIOLATION", Some("write"), Some(0x10), Some(false))
    );
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["exception"]["code"], "0xc0000005");
    assert_eq!(json["exception"]["system"], "windows");
    assert!(matches!(&event.reasons[0], StopReason::WindowsException(_)));

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    let siginfo = report.received.iter().filter(|packet| *packet == windows::SIGINFO_REQUEST).count();
    assert_eq!(siginfo, 2, "one exception record per stop but the step: {:?}", report.received);
}

#[test]
fn an_interrupt_stops_in_a_new_thread_that_reads_and_steps_pass_over() {
    let process = x64();
    let breakin_pc = NTDLL_BASE + 0x1500;
    // gdbserver interrupts with DebugBreakProcess when Ctrl-Break fails (an attached process): the int3 in the new
    // thread, its pc moved back onto it.
    let stub = FakeStub::tcp(
        executing(&process)
            .once("vCont;c", vec![])
            .on_interrupt(vec![Action::Reply(windows::gdbserver_stop(
                &process,
                &process.at(breakin_pc),
                BREAKIN_THREAD,
                5,
                "swbreak:;",
            ))])
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(true, pe::EXCEPTION_BREAKPOINT, breakin_pc, &[0]))],
            )
            .once(
                &format!("vCont;s:{MAIN_THREAD:x}"),
                vec![Action::Reply(windows::gdbserver_stop(
                    &process,
                    &process.at(EXE_BASE + 0x1004),
                    MAIN_THREAD,
                    5,
                    "",
                ))],
            )
            // The continue after it names every thread but the parked break-in thread.
            .once(
                &format!("vCont;c:{MAIN_THREAD:x};c:{SECOND_THREAD:x}"),
                vec![Action::Reply(windows::gdbserver_stop(
                    &process,
                    &process.at(EXE_BASE + 0x1008),
                    MAIN_THREAD,
                    0x0b,
                    "",
                ))],
            )
            .once(windows::SIGINFO_REQUEST, vec![Action::Reply("E01".into())]),
    );
    let session = connect(&stub);
    let run = session.resume(Some(1), Duration::from_millis(50), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Running);
    let run = session.interrupt(wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.thread), (StopCause::Interrupted, Some(thread(BREAKIN_THREAD))));
    assert_eq!(event.pc, Some(breakin_pc));
    assert!(event.warnings.iter().any(|warning| warning.contains("Windows created")), "{:?}", event.warnings);
    assert!(event.warnings.iter().any(|warning| warning.contains("int3")), "{:?}", event.warnings);

    // Reads and steps without a thread use the main thread, not the break-in thread.
    let registers = session.registers(None).unwrap();
    assert_eq!(registers.thread, Some(thread(MAIN_THREAD)));
    let steps = session.step_with(Some(run.epoch), None, 1, false, &Cancel::new()).unwrap();
    assert_eq!((steps.thread, steps.completed), (Some(thread(MAIN_THREAD)), 1));
    let explicit = session.registers(Some(thread(SECOND_THREAD))).unwrap();
    assert_eq!(explicit.thread, Some(thread(SECOND_THREAD)));

    // gdbserver would run the break-in thread into its int3 again; it stays suspended while the others run.
    let run = session.resume(Some(steps.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.thread), (StopCause::Signal, Some(thread(MAIN_THREAD))));
    assert_eq!(session.registers(None).unwrap().thread, Some(thread(MAIN_THREAD)));

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    let interrupt = report.received.iter().position(|packet| packet == INTERRUPT).unwrap();
    assert!(!report.received[interrupt..].iter().any(|packet| packet == "vCont;c"), "{:?}", report.received);
    assert!(report.received.iter().any(|packet| packet == INTERRUPT));
}

#[test]
fn gdbserver_before_16_is_recognized_without_an_os_abi_and_the_peb_names_the_executable() {
    let mut process = x64();
    process.osabi = false;
    // A loaded `.exe` in gdbserver's library list is not the program: the PEB says which image is.
    process.images.push(WindowsImage {
        path: "C:\\work\\plugin.exe".into(),
        base: 0x7ff7_0000_0000,
        mapped: windows::synthetic_image(true, false, 0x7ff7_0000_0000, 0x2000, None),
    });
    let stub = FakeStub::tcp(windows::gdbserver_windows(&process));
    let session = connect(&stub);
    let windows = session.info().windows.clone().unwrap();
    assert_eq!(windows.stub, "gdbserver");
    assert!(windows.evidence.contains("qGetTIBAddr"), "{}", windows.evidence);
    let modules = session.modules().unwrap();
    let main: Vec<&str> =
        modules.modules.iter().filter(|module| module.main).map(|module| module.name.as_str()).collect();
    assert_eq!(main, ["C:\\work\\pe-loop.exe"]);
    assert_eq!(modules.modules[0].source, "peb");
    session.detach().unwrap();
    stub.finish().assert_clean();
}

#[test]
fn a_dll_load_stop_racing_an_interrupt_leaves_the_interrupt_pending() {
    let process = x64();
    let stub = FakeStub::tcp(
        executing(&process)
            .once("vCont;c", vec![])
            // The DLL load got ahead of the Ctrl-Break: signal 0 with `library`, in the main thread.
            .on_interrupt(vec![Action::Reply(
                windows::gdbserver_stop(&process, &process.registers, MAIN_THREAD, 0, "") + "library:;",
            )])
            // The interrupt's own stop, after the next continue: DBG_CONTROL_BREAK (SIGINT) in a new thread.
            .once(
                "vCont;c",
                vec![Action::Reply(windows::gdbserver_stop(
                    &process,
                    &process.at(NTDLL_BASE + 0x1600),
                    BREAKIN_THREAD,
                    2,
                    "",
                ))],
            )
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(
                    true,
                    pe::DBG_CONTROL_BREAK,
                    NTDLL_BASE + 0x1600,
                    &[],
                ))],
            ),
    );
    let session = connect(&stub);
    session.resume(Some(1), Duration::from_millis(50), &Cancel::new()).unwrap();
    let run = session.interrupt(wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.signal), (StopCause::Signal, Some(0)));
    assert!(event.reasons.contains(&StopReason::Library));
    assert_eq!(session.registers(None).unwrap().thread, Some(thread(MAIN_THREAD)));
    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.thread), (StopCause::Interrupted, Some(thread(BREAKIN_THREAD))));
    assert_eq!(
        event.exception.as_ref().and_then(Exception::windows).map(|exception| exception.name),
        Some("DBG_CONTROL_BREAK")
    );
    // Ctrl-Break leaves the pc alone, so nothing is parked: the next continue is a plain one.
    assert!(!event.warnings.iter().any(|warning| warning.contains("suspended")), "{:?}", event.warnings);
    session.detach().unwrap();
    stub.finish().assert_clean();
}

#[test]
fn a_wow64_process_under_gdbserver_is_32_bit_x86() {
    let mut process = WindowsProcess::wow64(images(false), 0x0040_1000, 0x0019_ff00);
    process.memory.push((0x0019_ff00, vec![0x5a; 0x100]));
    let stub = FakeStub::tcp(
        windows::gdbserver_windows(&process)
            .execution()
            .on("vCont?", "vCont;c;C;t;s;S")
            .once(
                "vCont;c",
                vec![Action::Reply(windows::gdbserver_stop(&process, &process.at(0x0040_1010), MAIN_THREAD, 0x0b, ""))],
            )
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(
                    false,
                    pe::EXCEPTION_ACCESS_VIOLATION,
                    0x0040_1010,
                    &[0, 0x20],
                ))],
            ),
    );
    let session = connect(&stub);
    let info = session.info();
    assert_eq!((info.family, info.pointer_size), (Family::X86, Some(4)));
    assert!(info.is_windows());
    let modules = session.modules().unwrap();
    let main = &modules.modules[0];
    assert_eq!(
        (main.source, main.pe.as_ref().unwrap().base, main.pe.as_ref().unwrap().machine.as_str()),
        ("peb", 0x0040_0000, "x86")
    );
    assert_eq!(modules.modules[1].pe.as_ref().unwrap().base, 0x7720_0000);
    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.pc), (StopCause::Signal, Some(0x0040_1010)));
    let exception = event.exception.as_ref().and_then(Exception::windows).unwrap();
    assert_eq!((exception.access, exception.fault_address), (Some("read"), Some(0x20)));
    session.detach().unwrap();
    stub.finish().assert_clean();
}

fn lldb_executing(process: &WindowsProcess) -> Script {
    windows::lldb_server_windows(process)
        .execution()
        .on("vCont?", "vCont;c;C;s;S;t")
        .on(&format!("Z0,{:x},1", EXE_BASE + 0x1040), "OK")
        .on(&format!("z0,{:x},1", EXE_BASE + 0x1040), "OK")
        // lldb-server on Windows sets no hardware breakpoints (`NativeThreadWindows.cpp`, "unimplemented.").
        .on(&format!("Z1,{:x},1", EXE_BASE + 0x1040), "E09")
        .on(&format!("Z2,{:x},8", EXE_BASE + 0x3000), "OK")
        .on(&format!("z2,{:x},8", EXE_BASE + 0x3000), "OK")
}

#[test]
fn lldb_server_lists_every_image_at_its_base_and_marks_the_executable() {
    let process = x64();
    let stub = FakeStub::tcp(windows::lldb_server_windows(&process));
    let session = connect(&stub);
    let info = session.info();
    assert_eq!((info.family, info.architecture.as_deref()), (Family::X86_64, Some("i386:x86-64")));
    let windows = info.windows.as_ref().unwrap();
    assert_eq!((windows.stub, windows.evidence.as_str()), ("lldb-server", "qProcessInfo states ostype:windows"));
    let lldb = info.lldb.as_ref().unwrap();
    assert!(!lldb.apple);
    assert_eq!(lldb.process.as_ref().unwrap().triple.as_deref(), Some("x86_64-pc-windows-msvc"));

    let modules = session.modules().unwrap();
    assert_eq!(modules.modules.len(), 3);
    let main = &modules.modules[0];
    assert_eq!((main.name.as_str(), main.source, main.main), ("C:\\work\\pe-loop.exe", "libraries", true));
    assert_eq!(main.sections, vec![EXE_BASE]);
    let image = main.pe.as_ref().unwrap();
    assert_eq!((image.base, image.base_from), (EXE_BASE, "section"));
    assert!(!modules.modules[1].main);
    assert!(modules.regions.iter().any(|region| region.start == EXE_BASE));

    let registers = session.registers(None).unwrap();
    let value = |name: &str| registers.registers.iter().find(|register| register.name == name).unwrap().integer();
    assert_eq!((value("rip"), value("rsp"), value("rdi")), (Some(EXE_BASE + 0x1000), Some(STACK), Some(0x105)));
    assert!(registers.registers.iter().all(|register| register.name != "eax"), "views are left out");

    session.detach().unwrap();
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with("qGetTIBAddr")), "the executable is listed");
    assert!(!report.received.iter().any(|packet| packet.starts_with("qXfer:siginfo")), "{:?}", report.received);
}

#[test]
fn lldb_server_describes_exceptions_watchpoints_and_interrupts() {
    let process = x64();
    let breakpoint = EXE_BASE + 0x1040;
    let watched = EXE_BASE + 0x3000;
    let stub = FakeStub::tcp(
        lldb_executing(&process)
            .once("vCont;c", vec![Action::Reply(windows::lldb_stop(&process, &process.at(breakpoint), MAIN_THREAD, 5, "breakpoint", ""))])
            .once(&format!("vCont;s:{MAIN_THREAD:x}"), vec![Action::Reply(windows::lldb_stop(&process, &process.at(breakpoint + 4), MAIN_THREAD, 5, "trace", ""))])
            .once(
                "vCont;c",
                vec![Action::Reply(windows::lldb_stop(
                    &process,
                    &process.at(breakpoint + 8),
                    MAIN_THREAD,
                    5,
                    "watchpoint",
                    &format!("{watched} 0 {}", watched + 4),
                ))],
            )
            .once(
                "vCont;c",
                vec![Action::Reply(windows::lldb_stop(
                    &process,
                    &process.at(breakpoint + 12),
                    MAIN_THREAD,
                    5,
                    "exception",
                    &format!(
                        "Exception 0xc0000005 encountered at address {:#x}: Access violation writing location 0x00000010",
                        breakpoint + 12
                    ),
                ))],
            )
            // A compiled-in int3: lldb-server reports it as an exception, the pc after the int3.
            .once(
                "vCont;c",
                vec![Action::Reply(windows::lldb_stop(
                    &process,
                    &process.at(breakpoint + 0x21),
                    MAIN_THREAD,
                    5,
                    "exception",
                    &format!("Exception 0x80000003 encountered at address {:#x}", breakpoint + 0x20),
                ))],
            )
            .once("vCont;c", vec![])
            .on_interrupt(vec![Action::Reply(windows::lldb_stop(
                &process,
                &process.at(NTDLL_BASE + 0x1501),
                BREAKIN_THREAD,
                0x11,
                "signal",
                "interrupt",
            ))]),
    );
    let session = connect(&stub);
    let entry = session.set_breakpoint(Some(1), BreakKind::Software, breakpoint, None).unwrap();
    let hardware = session.set_breakpoint(Some(1), BreakKind::Hardware, breakpoint, None).unwrap_err();
    assert!(matches!(hardware, DebugError::Target(_)), "{hardware}");

    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.breakpoints.clone()), (StopCause::Breakpoint, vec![entry.id]));
    let watch = session.set_breakpoint(Some(run.epoch), BreakKind::Write, watched, Some(8)).unwrap();

    // Past the breakpoint (`reason:trace`), then the watchpoint: `<address> <index> <hit>` in decimal.
    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.breakpoints.clone()), (StopCause::Watchpoint, vec![watch.id]));
    let hit = event.watch.as_ref().unwrap();
    assert_eq!((hit.address, hit.accessed), (watched, Some(watched + 4)));

    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(event.reason, StopCause::Signal);
    let exception = event.exception.as_ref().and_then(Exception::windows).unwrap();
    assert_eq!(
        (exception.name, exception.source, exception.access, exception.fault_address),
        ("EXCEPTION_ACCESS_VIOLATION", "description", Some("write"), Some(0x10))
    );

    // An int3 that is not a breakpoint of the table is still a breakpoint stop, not a signal.
    let run = session.resume(Some(run.epoch), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.breakpoints.clone()), (StopCause::Breakpoint, vec![]));

    let run = session.resume(Some(run.epoch), Duration::from_millis(50), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Running);
    let run = session.interrupt(wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!(
        (event.reason, event.signal, event.thread),
        (StopCause::Interrupted, Some(0x11), Some(thread(BREAKIN_THREAD)))
    );
    assert!(!event.warnings.iter().any(|warning| warning.contains("int3")), "lldb-server does not move the pc back");
    assert_eq!(session.registers(None).unwrap().thread, Some(thread(MAIN_THREAD)));

    session.detach().unwrap();
    stub.finish().assert_clean();
}
