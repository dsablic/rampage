#![cfg(unix)]

//! The debug tools against Windows stubs (step 9.6a), through the fake stub's Windows transcripts, which are built
//! from gdbserver's and lldb-server's sources (no Windows host was available; see `rampage_debug::fake::windows`):
//! binding the owned PE fixtures in `tests/fixtures/debug-windows` (rebuilt with its `build.sh`) by their CodeView
//! record at an ASLR slide, with the base relocations the loader applied left out of slide verification; Windows
//! path rules; breakpoints by function name, stop locations and step out; Windows exceptions in stop events; the
//! thread an interrupt creates; and a WoW64 (32-bit x86) process.

use std::path::PathBuf;

use rampage_api::DebugRegistry;
use rampage_api::tools::{DebugTool, debug_tools};
use rampage_debug::fake::windows::{self, BREAKIN_THREAD, MAIN_THREAD, WindowsImage, WindowsProcess};
use rampage_debug::fake::{Action, FakeStub, Report};
use rampage_debug::pe;
use rampage_loaders::Binary;
use serde_json::{Value, json};

/// Where the fake target's loader put the x64 fixture (its preferred base is 0x140000000), and its stack.
const BASE: u64 = 0x7ff6_1234_0000;
const NTDLL: u64 = 0x7ffb_1d40_0000;
const STACK: u64 = 0xd1_2350_f000;
/// The x86 fixture's runtime base in the WoW64 process (preferred 0x400000), and its stack.
const BASE32: u64 = 0x00ab_0000;
const STACK32: u64 = 0x0019_f000;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/debug-windows")
        .join(name)
        .canonicalize()
        .unwrap()
}

fn x64_file() -> Vec<u8> {
    std::fs::read(fixture("pe-loop-x64.exe")).unwrap()
}

fn header(file: &[u8]) -> pe::PeHeader {
    pe::PeHeader::parse(file).unwrap()
}

/// An exported function's static address.
fn export(name: &str, path: &str) -> u64 {
    let binary = Binary::open(fixture(path)).unwrap();
    binary.exports.iter().find(|export| export.name == name).unwrap_or_else(|| panic!("no `{name}`")).address
}

/// The instruction after `start`'s `call tick`: where `tick` returns.
fn after_call(path: &str) -> u64 {
    let binary = Binary::open(fixture(path)).unwrap();
    let (start, tick) = (export("start", path), export("tick", path));
    let code = binary.read_to_segment_end(start).unwrap();
    for at in 0..code.len() - 5 {
        let displacement = i32::from_le_bytes(code[at + 1..at + 5].try_into().unwrap());
        let next = start + at as u64 + 5;
        if code[at] == 0xe8
            && next.wrapping_add(displacement as i64 as u64) & 0xffff_ffff_ffff == tick & 0xffff_ffff_ffff
        {
            return next;
        }
    }
    panic!("start does not call tick");
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// An x64 process with the fixture loaded at `BASE` (relocated, as the loader does), ntdll and kernel32, stopped
/// at `pc` with the stack at `STACK`, its first word `return_address`.
fn x64_process(pc: u64, return_address: u64) -> WindowsProcess {
    let images = vec![
        WindowsImage {
            path: "C:\\work\\pe-loop-x64.exe".into(),
            base: BASE,
            mapped: windows::map_pe(&x64_file(), BASE),
        },
        WindowsImage {
            path: "C:\\Windows\\SYSTEM32\\ntdll.dll".into(),
            base: NTDLL,
            mapped: windows::synthetic_image(true, true, NTDLL, 0x2000, Some(([0x11; 16], 1))),
        },
        WindowsImage {
            path: "C:\\Windows\\System32\\KERNEL32.DLL".into(),
            base: 0x7ffb_1c20_0000,
            mapped: windows::synthetic_image(true, true, 0x7ffb_1c20_0000, 0x2000, None),
        },
    ];
    let mut process = WindowsProcess::x64(images, pc, STACK);
    let mut stack = return_address.to_le_bytes().to_vec();
    stack.resize(0x100, 0);
    process.memory.push((STACK, stack));
    process
}

/// The fixture's static address `address` at its runtime base.
fn runtime(address: u64) -> u64 {
    address - 0x1_4000_0000 + BASE
}

struct Harness {
    registry: DebugRegistry,
    tools: Vec<DebugTool>,
    connection: Value,
}

impl Harness {
    fn new(stub: &FakeStub) -> Self {
        let mut harness = Self {
            registry: DebugRegistry::new(&[stub.endpoint().to_owned()]).unwrap(),
            tools: debug_tools(),
            connection: Value::Null,
        };
        harness.connection = harness.call("debug_connect", json!({})).unwrap();
        harness
    }

    fn call(&self, name: &str, input: Value) -> Result<Value, String> {
        self.tools.iter().find(|tool| tool.name == name).unwrap().call(&self.registry, input)
    }
}

fn finish(stub: FakeStub, harness: Harness) -> Report {
    drop(harness);
    let report = stub.finish();
    report.assert_clean();
    report
}

#[test]
fn the_fixtures_have_the_layout_the_tests_assume() {
    let file = x64_file();
    let header = header(&file);
    assert_eq!((header.machine_name().as_str(), header.image_base, header.dll()), ("x86-64", 0x1_4000_0000, false));
    assert_ne!(header.dll_characteristics & pe::DYNAMIC_BASE, 0, "ASLR-enabled");
    assert!(pe::file_codeview(&file, &header).is_some(), "an RSDS record");
    // A base relocation in .text, where slide verification compares code.
    let relocations = pe::relocations(&file, &header).unwrap();
    let text = header.sections.iter().find(|section| section.name == ".text").unwrap();
    assert!(
        relocations.iter().any(|(rva, length)| *length == 8 && (text.rva..text.rva + text.virtual_size).contains(rva))
    );
    assert!(
        export("tick", "pe-loop-x64.exe") >= 0x1_4000_1000
            && after_call("pe-loop-x64.exe") > export("start", "pe-loop-x64.exe")
    );
    let file32 = std::fs::read(fixture("pe-loop-x86.exe")).unwrap();
    let header32 = pe::PeHeader::parse(&file32).unwrap();
    assert_eq!((header32.machine_name().as_str(), header32.image_base), ("x86", 0x40_0000));
    assert!(pe::relocations(&file32, &header32).unwrap().iter().any(|(_, length)| *length == 4));
}

#[test]
fn binds_the_executable_by_codeview_at_an_aslr_slide_skipping_relocated_bytes() {
    let process = x64_process(runtime(export("tick", "pe-loop-x64.exe")), 0);
    // The loader patched the pointer in .text: the mapped bytes differ from the file there, so a byte-for-byte
    // comparison would fail.
    let file = x64_file();
    let header = header(&file);
    let (rva, _) = pe::relocations(&file, &header).unwrap()[0];
    let offset = header.file_offset(rva).unwrap();
    assert_ne!(&process.images[0].mapped[rva as usize..rva as usize + 8], &file[offset..offset + 8]);

    let stub = FakeStub::tcp(windows::gdbserver_windows(&process));
    let harness = Harness::new(&stub);
    assert_eq!(harness.connection["windows"]["stub"], "gdbserver", "{}", harness.connection);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x64.exe")})).unwrap();
    let binding = &bound["binding"];
    assert_eq!(binding["evidence"]["kind"], "codeview", "{bound}");
    assert_eq!(binding["evidence"]["age"], 1);
    assert_eq!(binding["module"], "C:\\work\\pe-loop-x64.exe");
    assert_eq!(hex(&binding["slide"]), BASE - 0x1_4000_0000);
    assert_eq!(binding["verification"]["outcome"], "matched", "{bound}");
    let detail = binding["verification"]["detail"].as_str().unwrap();
    assert!(detail.contains("base relocations patch were left out"), "{detail}");

    let modules = harness.call("debug_modules", json!({"session": "s1"})).unwrap();
    let main = &modules["modules"]["items"][0];
    assert_eq!((main["source"].as_str(), main["main"].as_bool()), (Some("peb"), Some(true)));
    assert_eq!(hex(&main["pe"]["base"]), BASE);
    finish(stub, harness);
}

#[test]
fn a_moved_image_whose_unrelocated_code_differs_does_not_bind() {
    // A byte of .text that no relocation covers differs: the image running is not the file.
    let mut process = x64_process(runtime(export("tick", "pe-loop-x64.exe")), 0);
    let tick = (export("tick", "pe-loop-x64.exe") - 0x1_4000_0000) as usize;
    process.images[0].mapped[tick] ^= 0xff;
    let stub = FakeStub::tcp(windows::gdbserver_windows(&process));
    let harness = Harness::new(&stub);
    let error = harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x64.exe")})).unwrap_err();
    assert!(error.starts_with("slide_mismatch") && error.contains("codeview"), "{error}");
    finish(stub, harness);
}

#[test]
fn windows_paths_match_case_insensitively() {
    // Without a CodeView record in the mapped image (its signature cleared), the module matches only by name:
    // `\\?\C:\WORK\PE-LOOP-X64.EXE` names the file, whatever the case and prefix.
    let mut process = x64_process(runtime(export("tick", "pe-loop-x64.exe")), 0);
    let file = x64_file();
    let rsds = file.windows(4).position(|window| window == b"RSDS").unwrap();
    let rsds_rva = rsds - header(&file).file_offset(0x3000).unwrap() + 0x3000;
    process.images[0].mapped[rsds_rva] = 0;
    process.images[0].path = "\\\\?\\C:\\WORK\\PE-LOOP-X64.EXE".into();
    process.exec_file = process.images[0].path.clone();
    let stub = FakeStub::tcp(windows::lldb_server_windows(&process));
    let harness = Harness::new(&stub);
    assert_eq!(harness.connection["windows"]["stub"], "lldb-server");
    let bound = harness
        .call(
            "debug_bind",
            json!({"session": "s1", "path": fixture("pe-loop-x64.exe"), "module": "c:/work/pe-loop-x64.exe"}),
        )
        .unwrap();
    let binding = &bound["binding"];
    assert_eq!(binding["evidence"]["kind"], "basename", "{bound}");
    assert_eq!(hex(&binding["slide"]), BASE - 0x1_4000_0000);
    assert_eq!(binding["verification"]["outcome"], "matched", "{bound}");
    finish(stub, harness);
}

#[test]
fn breaks_on_a_function_by_name_continues_and_locates_the_stop() {
    let tick = runtime(export("tick", "pe-loop-x64.exe"));
    let start = runtime(export("start", "pe-loop-x64.exe"));
    let process = x64_process(start, 0);
    let stub = FakeStub::tcp(
        windows::gdbserver_windows(&process)
            .execution()
            .on("vCont?", "vCont;c;C;t;s;S")
            .on(&format!("Z0,{tick:x},1"), "OK")
            .on(&format!("z0,{tick:x},1"), "OK")
            .once(
                "vCont;c",
                vec![Action::Reply(windows::gdbserver_stop(&process, &process.at(tick), MAIN_THREAD, 5, "swbreak:;"))],
            )
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(true, pe::EXCEPTION_BREAKPOINT, tick, &[0]))],
            ),
    );
    let harness = Harness::new(&stub);
    harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x64.exe")})).unwrap();
    let placed = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "software", "function": "tick"}),
        )
        .unwrap();
    assert_eq!(hex(&placed["breakpoint"]["address"]), tick, "{placed}");
    assert_eq!(placed["breakpoint"]["size"], 1);
    let run = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    assert_eq!(run["event"]["reason"], "breakpoint", "{run}");
    assert_eq!(run["event"]["exception"]["name"], "EXCEPTION_BREAKPOINT");
    let location = &run["locations"]["pc"]["location"];
    assert_eq!(location["function"], "tick", "{run}");
    assert_eq!(hex(&location["static_address"]), export("tick", "pe-loop-x64.exe"));
    finish(stub, harness);
}

#[test]
fn steps_out_of_a_function_to_its_caller_by_the_return_address_at_rsp() {
    let tick = runtime(export("tick", "pe-loop-x64.exe"));
    let back = runtime(after_call("pe-loop-x64.exe"));
    let process = x64_process(tick, back);
    let mut returned = process.at(back);
    returned[7] = STACK + 8;
    let stub = FakeStub::tcp(
        windows::gdbserver_windows(&process)
            .execution()
            .on("vCont?", "vCont;c;C;t;s;S")
            .on(&format!("Z1,{back:x},1"), "OK")
            .on(&format!("z1,{back:x},1"), "OK")
            .once("vCont;c", vec![Action::Reply(windows::gdbserver_stop(&process, &returned, MAIN_THREAD, 5, ""))])
            .after("vCont;c", "g", &windows::gdbserver_g(&process, &returned))
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(true, pe::EXCEPTION_SINGLE_STEP, back, &[]))],
            ),
    );
    let harness = Harness::new(&stub);
    harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x64.exe")})).unwrap();
    let out = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "out": true})).unwrap();
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(hex(&out["steps"][0]["return_address"]), back);
    assert_eq!(out["event"]["reason"], "temporary_breakpoint");
    assert_eq!(out["locations"]["pc"]["location"]["function"], "start", "{out}");
    let report = finish(stub, harness);
    assert!(report.received.contains(&format!("Z1,{back:x},1")));
}

#[test]
fn windows_exceptions_and_the_interrupt_thread_reach_the_tools() {
    let start = runtime(export("start", "pe-loop-x64.exe"));
    let process = x64_process(start, 0);
    let faulting = start + 4;
    let stub = FakeStub::tcp(
        windows::lldb_server_windows(&process)
            .execution()
            .on("vCont?", "vCont;c;C;s;S;t")
            .once(
                "vCont;c",
                vec![Action::Reply(windows::lldb_stop(
                    &process,
                    &process.at(faulting),
                    MAIN_THREAD,
                    5,
                    "exception",
                    &format!("Exception 0xc0000005 encountered at address {faulting:#x}: Access violation reading location 0x00000000"),
                ))],
            )
            .once("vCont;c", vec![])
            .on_interrupt(vec![Action::Reply(windows::lldb_stop(&process, &process.at(NTDLL + 0x1501), BREAKIN_THREAD, 0x11, "signal", "interrupt"))]),
    );
    let harness = Harness::new(&stub);
    harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x64.exe")})).unwrap();
    let run = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    let event = &run["event"];
    assert_eq!(event["reason"], "signal", "{run}");
    assert_eq!(event["exception"]["system"], "windows");
    assert_eq!(event["exception"]["code"], "0xc0000005");
    assert_eq!(
        (event["exception"]["access"].as_str(), event["exception"]["fault_address"].as_str()),
        (Some("read"), Some("0x0"))
    );
    assert_eq!(run["locations"]["pc"]["location"]["function"], "start");

    let epoch = run["epoch"].as_u64().unwrap();
    let running = harness.call("debug_continue", json!({"session": "s1", "epoch": epoch, "timeout_ms": 50})).unwrap();
    assert_eq!(running["state"], "running");
    let stopped = harness.call("debug_interrupt", json!({"session": "s1"})).unwrap();
    assert_eq!(stopped["event"]["reason"], "interrupted", "{stopped}");
    assert_eq!(stopped["event"]["thread"], format!("{BREAKIN_THREAD:x}"));
    // Reads without a thread use the main thread; evidence reads the Windows x64 argument registers.
    let registers = harness.call("debug_registers", json!({"session": "s1", "names": ["rip"]})).unwrap();
    assert_eq!(registers["thread"], format!("{MAIN_THREAD:x}"), "{registers}");
    let evidence = harness.call("debug_evidence", json!({"session": "s1"})).unwrap();
    let names: Vec<&str> =
        evidence["registers"].as_array().unwrap().iter().map(|register| register["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"rcx") && names.contains(&"r9") && !names.contains(&"rdi"), "{names:?}");
    assert_eq!(evidence["pc"]["location"]["function"], "start", "{evidence}");
    finish(stub, harness);
}

#[test]
fn a_wow64_process_binds_the_x86_fixture_and_steps_out_by_esp() {
    let file = std::fs::read(fixture("pe-loop-x86.exe")).unwrap();
    let rebased = |address: u64| address - 0x40_0000 + BASE32;
    let tick = rebased(export("tick", "pe-loop-x86.exe"));
    let back = rebased(after_call("pe-loop-x86.exe"));
    let images = vec![
        WindowsImage { path: "C:\\work\\pe-loop-x86.exe".into(), base: BASE32, mapped: windows::map_pe(&file, BASE32) },
        WindowsImage {
            path: "C:\\Windows\\SysWOW64\\ntdll.dll".into(),
            base: 0x7720_0000,
            mapped: windows::synthetic_image(false, true, 0x7720_0000, 0x2000, None),
        },
    ];
    let mut process = WindowsProcess::wow64(images, tick, STACK32);
    let mut stack = (back as u32).to_le_bytes().to_vec();
    stack.resize(0x100, 0);
    process.memory.push((STACK32, stack));
    let mut returned = process.at(back);
    returned[4] = STACK32 + 4;
    let stub = FakeStub::tcp(
        windows::gdbserver_windows(&process)
            .execution()
            .on("vCont?", "vCont;c;C;t;s;S")
            .on(&format!("Z1,{back:x},1"), "OK")
            .on(&format!("z1,{back:x},1"), "OK")
            .once("vCont;c", vec![Action::Reply(windows::gdbserver_stop(&process, &returned, MAIN_THREAD, 5, ""))])
            .after("vCont;c", "g", &windows::gdbserver_g(&process, &returned))
            .once(
                windows::SIGINFO_REQUEST,
                vec![windows::siginfo(&windows::exception_record(false, pe::EXCEPTION_SINGLE_STEP, back, &[]))],
            ),
    );
    let harness = Harness::new(&stub);
    assert_eq!(harness.connection["family"], "x86", "{}", harness.connection);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture("pe-loop-x86.exe")})).unwrap();
    let binding = &bound["binding"];
    assert_eq!(binding["evidence"]["kind"], "codeview", "{bound}");
    assert_eq!(hex(&binding["slide"]), BASE32 - 0x40_0000);
    assert_eq!(binding["verification"]["outcome"], "matched", "{bound}");
    let out = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "out": true})).unwrap();
    assert_eq!(out["event"]["reason"], "temporary_breakpoint", "{out}");
    assert_eq!(hex(&out["steps"][0]["return_address"]), back);
    assert_eq!(out["locations"]["pc"]["location"]["function"], "start", "{out}");
    finish(stub, harness);
}
