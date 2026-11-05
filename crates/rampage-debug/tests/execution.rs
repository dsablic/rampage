//! Execution control against the scripted fake stub: continue, wait, interrupt, step, breakpoints and watchpoints,
//! stop epochs, and detaching from a running target.

use std::time::{Duration, Instant};

use rampage_debug::fake::{Action, FakeStub, INTERRUPT, Script, le_hex, transcripts};
use rampage_debug::packet::{encode, encode_hex};
use rampage_debug::{BreakKind, Cancel, Config, DebugError, Endpoint, Session, State, StopCause};

fn connect(stub: &FakeStub) -> Session {
    let config = Config {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    Session::connect(&stub.endpoint().parse::<Endpoint>().unwrap(), config).unwrap()
}

/// QEMU's Cortex-M3 transcript with vCont, hardware breakpoints, watchpoints and a pc register.
fn qemu() -> Script {
    transcripts::qemu_cortex_m3()
        .execution()
        .on("vCont?", "vCont;c;C;s;S")
        .on("pf", &le_hex(0x48, 4))
        .on("Z1,80,2", "OK")
        .on("z1,80,2", "OK")
        .on("Z2,20000200,4", "OK")
        .on("z2,20000200,4", "OK")
}

/// [`qemu`] whose target stops with SIGINT when interrupted, and otherwise runs until then.
fn running_qemu() -> Script {
    qemu().on_actions("vCont;c", vec![]).on_interrupt(vec![Action::Reply("T02thread:p01.01;".into())])
}

/// The interrupts, removals and detaches among `received`, in order.
fn control(received: &[String]) -> Vec<&str> {
    received
        .iter()
        .filter(|packet| *packet == INTERRUPT || packet.starts_with('z') || packet.starts_with('D'))
        .map(String::as_str)
        .collect()
}

fn wait() -> Duration {
    Duration::from_secs(5)
}

#[test]
fn a_continue_stops_at_a_hardware_breakpoint_and_moves_the_epoch() {
    let stub = FakeStub::tcp(
        qemu()
            .on_actions(
                "vCont;c",
                vec![Action::Sleep(Duration::from_millis(50)), Action::Reply("T05thread:p01.01;".into())],
            )
            // The pc where the continue starts, then the pc of its stop.
            .once("pf", vec![Action::Reply(le_hex(0x48, 4))])
            .once("pf", vec![Action::Reply(le_hex(0x80, 4))]),
    );
    let session = connect(&stub);
    let breakpoint = session.set_breakpoint(Some(1), BreakKind::Hardware, 0x81, None).unwrap();
    assert_eq!((breakpoint.id, breakpoint.address, breakpoint.size), (1, 0x80, 2));
    let error = session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap_err();
    assert!(matches!(error, DebugError::Invalid(ref message) if message.contains("already set")), "{error:?}");

    // A call cancelled before it is served resumes nothing.
    let cancelled = Cancel::new();
    cancelled.cancel();
    assert_eq!(session.resume(Some(1), wait(), &cancelled).unwrap_err().code(), "cancelled");

    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Stopped);
    assert_eq!(run.epoch, 2);
    let event = run.event.unwrap();
    assert_eq!(event.reason, StopCause::Breakpoint);
    assert_eq!((event.epoch, event.pc, event.breakpoints.clone()), (2, Some(0x80), vec![1]));
    assert_eq!(event.thread.unwrap().to_string(), "p1.1");
    assert_eq!(session.breakpoints().unwrap()[0].hits, 1);

    // Reads and execution at the old epoch are refused, with the current epoch and state.
    let stale = session.registers_at(None, Some(1)).unwrap_err();
    assert_eq!(stale.code(), "stale_epoch");
    assert!(stale.to_string().contains("epoch 2 and stopped"), "{stale}");
    assert_eq!(session.resume(Some(1), wait(), &Cancel::new()).unwrap_err().code(), "stale_epoch");
    assert_eq!(session.registers_at(None, Some(2)).unwrap().epoch, 2);
    // `?` answers in QEMU's own words, which sets a baseline and is not a new stop.
    assert_eq!(session.status().unwrap().epoch, 2);
    assert_eq!(session.status().unwrap().last_stop.unwrap().epoch, 2);

    let cleared = session.clear_breakpoint(Some(2), 1).unwrap();
    assert!(!cleared.inserted);
    assert!(session.breakpoints().unwrap().is_empty());
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(report.received.iter().any(|packet| packet == "z1,80,2"));
    assert_eq!(report.received.iter().filter(|packet| *packet == "vCont;c").count(), 1);
    assert_eq!(report.received.last().map(String::as_str), Some("D;1"));
}

#[test]
fn a_stop_reply_in_pieces_and_between_console_output_is_one_stop() {
    let output = |text: &[u8]| encode(format!("O{}", encode_hex(text)).as_bytes());
    let stop = encode(b"T05thread:p01.01;");
    let (head, tail) = stop.split_at(6);
    let pause = || Action::Sleep(Duration::from_millis(30));
    let stub = FakeStub::tcp(qemu().on_actions(
        "vCont;c",
        vec![
            Action::Raw(output(b"hello ")),
            pause(),
            Action::Raw(b"%Stop:T05#00".to_vec()),
            Action::Raw(output(b"world")),
            pause(),
            Action::Raw(head.to_vec()),
            pause(),
            Action::Raw(tail.to_vec()),
        ],
    ));
    let session = connect(&stub);
    let event = session.resume(None, wait(), &Cancel::new()).unwrap().event.unwrap();
    assert_eq!(event.reason, StopCause::Signal);
    assert_eq!(event.console.text, "hello world");
    assert_eq!(event.epoch, 2);
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn a_running_target_serves_only_status_wait_interrupt_and_disconnect() {
    let stub = FakeStub::tcp(running_qemu());
    let session = connect(&stub);
    let run = session.resume(Some(1), Duration::from_millis(100), &Cancel::new()).unwrap();
    assert_eq!((run.state.clone(), run.epoch, run.event.is_none()), (State::Running, 1, true));
    for error in [
        session.registers(None).unwrap_err(),
        session.read_memory(0, 4, None).unwrap_err(),
        session.modules().unwrap_err(),
        session.set_breakpoint(Some(1), BreakKind::Hardware, 0x80, None).unwrap_err(),
        session.step(Some(1), None, 1, &Cancel::new()).unwrap_err(),
        session.resume(Some(1), wait(), &Cancel::new()).unwrap_err(),
        session.breakpoints().unwrap_err(),
    ] {
        assert_eq!(error.code(), "target_running", "{error:?}");
    }
    let status = session.status().unwrap();
    assert_eq!(status.state, State::Running);
    assert!(status.running_for_ms.is_some());
    assert_eq!(session.wait(Duration::from_millis(50), &Cancel::new()).unwrap().state, State::Running);

    // A cancelled wait returns at once and leaves the target running.
    let cancel = Cancel::new();
    let started = Instant::now();
    let waited = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| session.wait(Duration::from_secs(30), &cancel));
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
        waiting.join().unwrap()
    })
    .unwrap();
    assert!(waited.cancelled && waited.state == State::Running);
    assert!(started.elapsed() < Duration::from_secs(5));

    let run = session.interrupt(wait(), &Cancel::new()).unwrap();
    assert_eq!((run.state, run.epoch), (State::Stopped, 2));
    assert_eq!(run.event.unwrap().reason, StopCause::Interrupted);
    assert_eq!(session.interrupt(wait(), &Cancel::new()).unwrap_err().code(), "not_running");
    // A wait on a stopped target answers at once with the last stop.
    assert_eq!(session.wait(wait(), &Cancel::new()).unwrap().event.unwrap().epoch, 2);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(report.received.iter().filter(|packet| *packet == INTERRUPT).count(), 1);
}

#[test]
fn an_early_stop_ends_a_multi_step_and_counts_the_watchpoint() {
    let stub = FakeStub::tcp(
        qemu()
            .once("vCont;s:p1.1", vec![Action::Reply("T05thread:p01.01;".into())])
            .once("vCont;s:p1.1", vec![Action::Reply("T05thread:p01.01;".into())])
            .once("vCont;s:p1.1", vec![Action::Reply("T05thread:p01.01;watch:20000200;".into())])
            .once("pf", vec![Action::Reply(le_hex(0x4a, 4))])
            .once("pf", vec![Action::Reply(le_hex(0x4c, 4))])
            .once("pf", vec![Action::Reply(le_hex(0x4e, 4))]),
    );
    let session = connect(&stub);
    let watch = session.set_breakpoint(Some(1), BreakKind::Write, 0x2000_0200, Some(4)).unwrap();
    assert!(session.set_breakpoint(Some(1), BreakKind::Write, 0x2000_0200, None).is_err());
    assert_eq!(session.step(Some(1), None, 0, &Cancel::new()).unwrap_err().code(), "invalid_argument");
    let steps = session.step(Some(1), None, 5, &Cancel::new()).unwrap();
    assert_eq!((steps.requested, steps.completed), (5, 2));
    assert_eq!(steps.pcs, [Some("0x4a".to_owned()), Some("0x4c".to_owned())]);
    assert_eq!((steps.state, steps.epoch), (State::Stopped, 4));
    let event = steps.event.unwrap();
    assert_eq!(event.reason, StopCause::Watchpoint);
    assert_eq!(event.breakpoints, [watch.id]);
    assert_eq!(event.watch.unwrap().address, 0x2000_0200);
    assert_eq!(session.breakpoints().unwrap()[0].hits, 1);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    // Detaching removed the watchpoint first.
    let tail: Vec<&str> = report.received.iter().rev().take(2).map(String::as_str).collect();
    assert_eq!(tail, ["D;1", "z2,20000200,4"]);
}

#[test]
fn a_stub_without_vcont_steps_with_hc_and_s() {
    let stub = FakeStub::tcp(
        qemu()
            .once("vCont?", vec![Action::Reply(String::new())])
            .on("Hcp1.1", "OK")
            .once("Hc-1", vec![Action::Reply("E01".into())])
            .on("Hc-1", "OK")
            .on("s", "T05thread:p01.01;")
            .on("c", "T0bthread:p01.01;"),
    );
    let session = connect(&stub);
    let steps = session.step(None, None, 2, &Cancel::new()).unwrap();
    assert_eq!(steps.completed, 2);
    // After Hc<thread>, a plain `c` could resume only that thread: Hc-1 must be accepted first.
    let refused = session.resume(None, wait(), &Cancel::new()).unwrap_err();
    assert!(matches!(refused, DebugError::Unsupported(ref message) if message.contains("Hc-1")), "{refused:?}");
    let event = session.resume(None, wait(), &Cancel::new()).unwrap().event.unwrap();
    assert_eq!((event.reason, event.signal), (StopCause::Signal, Some(11)));
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    let resumes: Vec<&str> = report
        .received
        .iter()
        .filter(|packet| matches!(packet.as_str(), "s" | "c" | "Hcp1.1" | "Hc-1"))
        .map(String::as_str)
        .collect();
    assert_eq!(resumes, ["Hcp1.1", "s", "Hcp1.1", "s", "Hc-1", "Hc-1", "c"]);
}

/// The pc reads of a continue from a breakpoint: where it starts, where its step past the breakpoint stops, then
/// where the continue stops.
fn from_breakpoint(step: &str, stop: &str) -> Script {
    qemu()
        .on("Z1,80,2", "OK")
        .once("vCont;s:p1.1", vec![Action::Reply(step.into())])
        .on("vCont;c", stop)
        .once("pf", vec![Action::Reply(le_hex(0x80, 4))])
        .once("pf", vec![Action::Reply(le_hex(0x82, 4))])
        .once("pf", vec![Action::Reply(le_hex(0x80, 4))])
}

#[test]
fn a_continue_from_a_breakpoint_steps_past_it_and_puts_it_back() {
    let stub = FakeStub::tcp(from_breakpoint("T05thread:p01.01;", "T05thread:p01.01;"));
    let session = connect(&stub);
    let id = session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap().id;
    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.breakpoints.clone(), event.pc), (StopCause::Breakpoint, vec![id], Some(0x80)));
    // The step past the breakpoint was a stop too.
    assert_eq!(run.epoch, 3);
    assert!(run.warnings.is_empty() && event.warnings.is_empty());
    let table = session.breakpoints().unwrap();
    assert!(table[0].inserted);
    assert_eq!(table[0].hits, 1);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    let order: Vec<&str> = report
        .received
        .iter()
        .filter(|packet| packet.starts_with('z') || packet.starts_with('Z') || packet.starts_with("vCont;"))
        .map(String::as_str)
        .collect();
    assert_eq!(order, ["Z1,80,2", "z1,80,2", "vCont;s:p1.1", "Z1,80,2", "vCont;c", "z1,80,2"]);
}

#[test]
fn a_step_past_a_breakpoint_that_stops_otherwise_answers_the_continue() {
    let stub = FakeStub::tcp(
        from_breakpoint("T0bthread:p01.01;", "T05thread:p01.01;").once("Z1,80,2", vec![Action::Reply("OK".into())]),
    );
    let session = connect(&stub);
    session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap();
    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Stopped);
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.signal), (StopCause::Signal, Some(11)));
    assert!(session.breakpoints().unwrap()[0].inserted);
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet == "vCont;c"));
}

#[test]
fn a_breakpoint_the_stub_will_not_put_back_is_reported() {
    let stub = FakeStub::tcp(
        from_breakpoint("T05thread:p01.01;", "T05thread:p01.01;")
            .once("Z1,80,2", vec![Action::Reply("OK".into())])
            .once("Z1,80,2", vec![Action::Reply("E09".into())]),
    );
    let session = connect(&stub);
    session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap();
    let run = session.resume(Some(1), wait(), &Cancel::new()).unwrap();
    assert!(run.warnings.iter().any(|warning| warning.contains("refused to re-insert")), "{:?}", run.warnings);
    assert!(!session.breakpoints().unwrap()[0].inserted);
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn status_and_detach_are_served_while_a_multi_step_runs() {
    let slow = || vec![Action::Sleep(Duration::from_millis(150)), Action::Reply("T05thread:p01.01;".into())];
    let stub = FakeStub::tcp(qemu().on_actions("vCont;s:p1.1", slow()).on_interrupt(vec![]));
    let session = std::sync::Arc::new(connect(&stub));
    let stepping = {
        let session = std::sync::Arc::clone(&session);
        std::thread::spawn(move || session.step(Some(1), None, 1000, &Cancel::new()))
    };
    std::thread::sleep(Duration::from_millis(400));
    let started = Instant::now();
    let status = session.status().unwrap();
    assert_eq!(status.state, State::Running);
    assert!(status.epoch > 1);
    assert!(started.elapsed() < Duration::from_secs(1), "status waited {:?}", started.elapsed());
    let detached = session.detach().unwrap();
    assert_eq!(detached.state, State::Detached);
    assert!(started.elapsed() < Duration::from_secs(3), "detach waited {:?}", started.elapsed());
    let steps = stepping.join().unwrap().unwrap();
    assert!(steps.completed >= 1 && steps.completed < 1000);
    assert!(steps.truncated.unwrap().contains("detaching"));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn a_later_stop_after_an_ignored_interrupt_is_a_signal_and_interrupts_are_resent() {
    let stub = FakeStub::tcp(qemu().on_actions("vCont;c", vec![]).on_interrupt(vec![]));
    let session = connect(&stub);
    session.resume(None, Duration::ZERO, &Cancel::new()).unwrap();
    for _ in 0..2 {
        let run = session.interrupt(Duration::from_millis(50), &Cancel::new()).unwrap();
        assert_eq!(run.state, State::Running);
    }
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    // Two interrupts, then the one closing the session sends.
    assert_eq!(report.received.iter().filter(|packet| *packet == INTERRUPT).count(), 3);
}

#[test]
fn rejected_breakpoints_are_typed_and_never_emulated() {
    let stub = FakeStub::tcp(
        qemu().on_prefix("Z0,", vec![Action::Reply(String::new())]).on("Z1,90,2", "E0e").on("Z3,0,10000", "OK"),
    );
    let session = connect(&stub);
    let error = session.set_breakpoint(None, BreakKind::Software, 0x80, None).unwrap_err();
    assert_eq!(error.code(), "unsupported");
    assert!(error.to_string().contains("does not plant breakpoints by writing memory"), "{error}");
    assert_eq!(session.set_breakpoint(None, BreakKind::Hardware, 0x90, None).unwrap_err().code(), "target_error");
    assert_eq!(
        session.set_breakpoint(None, BreakKind::Hardware, 0x90, Some(4)).unwrap_err().code(),
        "invalid_argument"
    );
    assert_eq!(session.set_breakpoint(None, BreakKind::Read, 0, Some(0x10000)).unwrap_err().code(), "invalid_argument");
    assert!(session.breakpoints().unwrap().is_empty());
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('M') || packet.starts_with('X')));
}

#[test]
fn detaching_a_running_target_interrupts_removes_breakpoints_and_detaches() {
    let stub = FakeStub::tcp(running_qemu());
    let session = connect(&stub);
    session.set_breakpoint(Some(1), BreakKind::Hardware, 0x80, None).unwrap();
    assert_eq!(session.resume(Some(1), Duration::ZERO, &Cancel::new()).unwrap().state, State::Running);
    let detached = session.detach().unwrap();
    assert_eq!((detached.state, detached.breakpoints_removed), (State::Detached, 1));
    assert!(detached.removal_failures.is_empty());
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(control(&report.received), [INTERRUPT, "z1,80,2", "D;1"]);
}

#[test]
fn dropping_a_running_session_interrupts_and_detaches() {
    let stub = FakeStub::tcp(running_qemu());
    let session = connect(&stub);
    session.resume(None, Duration::ZERO, &Cancel::new()).unwrap();
    drop(session);
    let report = stub.finish();
    report.assert_clean();
    assert_eq!(control(&report.received), [INTERRUPT, "D;1"]);
}

#[test]
fn a_target_that_never_stops_after_an_interrupt_is_abandoned_not_detached() {
    let stub = FakeStub::tcp(qemu().on_actions("vCont;c", vec![]).on_interrupt(vec![]));
    let session = connect(&stub);
    session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap();
    session.resume(None, Duration::ZERO, &Cancel::new()).unwrap();
    let run = session.interrupt(Duration::from_millis(200), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Running);
    let detached = session.detach().unwrap();
    assert!(matches!(detached.state, State::Lost { ref reason } if reason.contains("did not stop")), "{detached:?}");
    assert_eq!(detached.removal_failures.len(), 1);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('D') || packet.starts_with('z')));
}

#[test]
fn a_resume_the_stub_refuses_leaves_the_target_stopped() {
    let stub = FakeStub::tcp(qemu().on("vCont;c", "E01"));
    let session = connect(&stub);
    assert_eq!(session.resume(Some(1), wait(), &Cancel::new()).unwrap_err().code(), "target_error");
    let status = session.status().unwrap();
    assert_eq!((status.state, status.epoch), (State::Stopped, 1));
    drop(session);
    stub.finish().assert_clean();
}

#[test]
fn an_exit_while_running_ends_the_process_and_its_breakpoints() {
    let stub = FakeStub::tcp(qemu().on("vCont;c", "W00;process:1"));
    let session = connect(&stub);
    session.set_breakpoint(None, BreakKind::Hardware, 0x80, None).unwrap();
    let run = session.resume(None, wait(), &Cancel::new()).unwrap();
    assert_eq!(run.state, State::Exited);
    let event = run.event.unwrap();
    assert_eq!((event.reason, event.exit_status), (StopCause::Exited, Some(0)));
    assert!(!session.breakpoints().unwrap()[0].inserted);
    assert_eq!(session.detach().unwrap().state, State::Exited);
    let report = stub.finish();
    report.assert_clean();
    assert!(!report.received.iter().any(|packet| packet.starts_with('z') || packet.starts_with('D')));
}

#[test]
fn a_read_only_script_fails_on_execution_packets() {
    let stub = FakeStub::tcp(transcripts::qemu_cortex_m3());
    let session = connect(&stub);
    assert!(session.resume(None, wait(), &Cancel::new()).is_err());
    drop(session);
    let report = stub.finish();
    assert_eq!(report.violations.len(), 1, "{:?}", report.violations);
    assert!(report.violations[0].contains("read-only script"));
}
