#![cfg(unix)]

//! The debug tools against Apple's debugserver (RSP with LLDB's extensions), through the scripted fake stub's
//! debugserver transcript: binding the owned arm64 Mach-O in `tests/fixtures/debug-macho` (rebuilt with its
//! `build.sh`) by `LC_UUID` at the slide dyld reports, refusing a dyld shared-cache library unless its extracted
//! image is given, pointer authentication codes on return addresses, and Mach exception stops.

use std::path::PathBuf;

use rampage_api::DebugRegistry;
use rampage_api::tools::{DebugTool, debug_tools};
use rampage_debug::fake::transcripts::{self, DebugserverImage, DebugserverTarget};
use rampage_debug::fake::{Action, FakeStub, Report, Script};
use rampage_loaders::{Binary, Details};
use serde_json::{Value, json};

/// The fixture's `__TEXT` link-time address, and where the fake target loads it.
const TEXT: u64 = 0x1_0000_0000;
const SLIDE: u64 = 0x280_0000;
/// A PAC an arm64e process might put on a return address: bits above the 47 address bits.
const PAC: u64 = 0x0023_8000_0000_0000;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/debug-macho/macho-loop")
        .canonicalize()
        .unwrap()
}

fn binary() -> Binary {
    Binary::open(fixture()).unwrap()
}

/// The fixture's `LC_UUID`, as debugserver formats it.
fn uuid() -> String {
    let Details::MachO(details) = &binary().details else { panic!("the fixture is Mach-O") };
    rampage_debug::lldb::canonical_uuid(details.uuid.as_deref().unwrap()).unwrap()
}

fn symbol(name: &str) -> u64 {
    let binary = binary();
    binary.symbols.iter().find(|symbol| symbol.name == name).unwrap_or_else(|| panic!("no `{name}`")).address
}

/// The instruction after `main`'s `bl tick`: where `tick` returns.
fn after_call() -> u64 {
    let (binary, main, tick) = (binary(), symbol("_main"), symbol("_tick"));
    for index in 0..32 {
        let at = main + 4 * index;
        let word = u32::from_le_bytes(binary.read(at, 4).unwrap().try_into().unwrap());
        let offset = (((word & 0x03ff_ffff) << 6) as i32 >> 6) as i64 * 4;
        if word & 0xfc00_0000 == 0x9400_0000 && at.wrapping_add(offset as u64) == tick {
            return at + 4;
        }
    }
    panic!("main does not call tick");
}

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// debugserver attached to the fixture loaded at `TEXT + SLIDE`, stopped at `pc` with `lr`, its `__TEXT` mapped.
fn target(pc: u64, lr: u64) -> DebugserverTarget {
    let mut target = DebugserverTarget::default();
    target.images[0] = DebugserverImage {
        path: "/Users/op/debug-macho/macho-loop".into(),
        uuid: uuid(),
        load_address: TEXT + SLIDE,
        text_vmaddr: TEXT,
        text_size: 0x4000,
        filetype: 2,
        in_shared_cache: false,
    };
    target.registers[transcripts::DEBUGSERVER_PC as usize] = pc;
    target.registers[transcripts::DEBUGSERVER_LR as usize] = lr;
    target
}

fn script(target: &DebugserverTarget) -> Script {
    let text = binary().read(TEXT, 0x4000).unwrap().to_vec();
    let mut script = transcripts::debugserver_arm64(target);
    for image in &target.images {
        if image.load_address != TEXT + SLIDE && image.text_vmaddr == TEXT {
            script = script.memory(image.load_address, &text);
        }
    }
    script.memory(TEXT + SLIDE, &text)
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
        let connection = &harness.connection;
        assert_eq!(
            (connection["family"].as_str(), connection["endianness"].as_str()),
            (Some("aarch64"), Some("little"))
        );
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
fn the_fixture_has_the_layout_the_tests_assume() {
    let binary = binary();
    assert_eq!(binary.arch, rampage_arch::Arch::Aarch64);
    assert_eq!(
        binary.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address,
        TEXT
    );
    assert!(symbol("_tick") > TEXT && after_call() > symbol("_main"));
    assert!(binary.symbols.iter().any(|symbol| symbol.name == "_counter"));
    assert_eq!(uuid().len(), 36);
}

#[test]
fn binds_the_executable_by_uuid_at_the_slide_dyld_reports() {
    let tick = symbol("_tick");
    let stub = FakeStub::tcp(
        script(&target(tick + SLIDE, 0x1_8c4a_6e8c))
            .execution()
            .on(&format!("Z0,{:x},4", tick + SLIDE), "OK")
            .on(&format!("z0,{:x},4", tick + SLIDE), "OK"),
    );
    let harness = Harness::new(&stub);
    let bound = harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();
    let binding = &bound["binding"];
    assert_eq!(binding["evidence"]["kind"], "uuid", "{bound}");
    assert_eq!(binding["evidence"]["uuid"], uuid().replace('-', "").to_ascii_lowercase());
    assert_eq!(binding["module"], "/Users/op/debug-macho/macho-loop");
    assert_eq!(hex(&binding["slide"]), SLIDE);
    assert_eq!(binding["verification"]["outcome"], "matched", "{bound}");

    // The modules show dyld's view; the stop's pc locates in tick.
    let modules = harness.call("debug_modules", json!({"session": "s1"})).unwrap();
    let main = &modules["modules"]["items"][0];
    assert_eq!(main["dyld"]["uuid"], uuid());
    assert_eq!(hex(&main["dyld"]["load_address"]), TEXT + SLIDE);
    let placed = harness
        .call(
            "debug_breakpoints",
            json!({"session": "s1", "action": "set", "epoch": 1, "kind": "software", "function": "_tick"}),
        )
        .unwrap();
    assert_eq!(hex(&placed["breakpoint"]["address"]), tick + SLIDE);
    assert_eq!(placed["breakpoint"]["size"], 4);
    finish(stub, harness);
}

#[test]
fn a_shared_cache_library_binds_only_from_its_extracted_image() {
    let tick = symbol("_tick");
    let cached = "/usr/lib/system/libsystem_rampage_test.dylib";
    let mut shared = target(tick + SLIDE, 0x1_8c4a_6e8c);
    shared.images[0].uuid = "11111111-2222-3333-4444-555555555555".into();
    shared.images[2].path = cached.into();
    let stub = FakeStub::tcp(script(&shared));
    let harness = Harness::new(&stub);
    // Its path has no file, and a file of another UUID does not stand in for it, even with a slide.
    let error = harness.call("debug_bind", json!({"session": "s1", "path": cached})).unwrap_err();
    assert!(error.starts_with("shared_cache_image") && error.contains("extract"), "{error}");
    let error = harness
        .call(
            "debug_bind",
            json!({"session": "s1", "path": fixture(), "module": "libsystem_rampage_test.dylib", "slide": "0x0"}),
        )
        .unwrap_err();
    assert!(error.starts_with("shared_cache_image"), "{error}");
    let modules = harness.call("debug_modules", json!({"session": "s1"})).unwrap();
    assert_eq!(modules["modules"]["items"][2]["dyld"]["in_shared_cache"], true);
    finish(stub, harness);

    // The image extracted from the cache carries the cached image's UUID, and binds at the cache's slide.
    let load = 0x1_8c56_8000;
    let mut extracted = target(tick + SLIDE, 0x1_8c4a_6e8c);
    extracted.images[0].uuid = "11111111-2222-3333-4444-555555555555".into();
    extracted.images[2] = DebugserverImage {
        path: cached.into(),
        uuid: uuid(),
        load_address: load,
        text_vmaddr: TEXT,
        text_size: 0x4000,
        filetype: 6,
        in_shared_cache: true,
    };
    let stub = FakeStub::tcp(script(&extracted));
    let harness = Harness::new(&stub);
    let bound = harness
        .call("debug_bind", json!({"session": "s1", "path": fixture(), "module": "libsystem_rampage_test.dylib"}))
        .unwrap();
    assert_eq!(bound["binding"]["evidence"]["kind"], "uuid", "{bound}");
    assert_eq!(hex(&bound["binding"]["slide"]), load - TEXT);
    assert_eq!(bound["binding"]["verification"]["outcome"], "matched");
    finish(stub, harness);
}

#[test]
/// debugserver strips pointer authentication codes from lr, fp, sp and pc when it reads them, so these signed values
/// come from a stub that does not; rampage strips them defensively.
fn signed_return_addresses_are_stripped_defensively() {
    let (tick, back) = (symbol("_tick") + SLIDE, after_call() + SLIDE);
    let signed = back | PAC;
    let returned = {
        let mut at_return = target(back, signed);
        at_return.signal = 5;
        at_return.exception = (6, vec![1, 0]);
        transcripts::debugserver_stop(&at_return, transcripts::DEBUGSERVER_THREAD, "")
    };
    // x0 holds the same signed bits but is a plain integer register: it is not read as a code pointer.
    let mut stopped = target(tick, signed);
    stopped.registers[0] = signed;
    let stub = FakeStub::tcp(
        script(&stopped)
            .execution()
            .on("vCont?", "vCont;c;C;s;S")
            .on(&format!("Z1,{back:x},4"), "OK")
            .on(&format!("z1,{back:x},4"), "OK")
            .once("vCont;c", vec![Action::Reply(returned)]),
    );
    let harness = Harness::new(&stub);
    assert_eq!(harness.connection["address_mask"]["low_bits"], 47, "{}", harness.connection);
    assert_eq!(harness.connection["lldb"]["apple"], true);
    harness.call("debug_bind", json!({"session": "s1", "path": fixture()})).unwrap();

    // lr is signed: it locates in main once the PAC is off, and says what it was.
    let registers = harness
        .call("debug_registers", json!({"session": "s1", "names": ["lr", "pc", "x0"], "annotate": true}))
        .unwrap();
    let items = registers["registers"]["items"].as_array().unwrap();
    let lr = &items.iter().find(|item| item["name"] == "lr").unwrap()["points_to"];
    assert_eq!(lr["function"], "_main", "{registers}");
    assert_eq!(hex(&lr["runtime_address"]), back);
    assert_eq!(hex(&lr["signed_value"]), signed);
    assert!(items.iter().find(|item| item["name"] == "x0").unwrap().get("points_to").is_none(), "{registers}");

    // Step out from tick's first instruction: the temporary breakpoint goes at the stripped return address.
    let out = harness.call("debug_step", json!({"session": "s1", "epoch": 1, "out": true})).unwrap();
    assert_eq!(out["completed"], 1, "{out}");
    assert_eq!(hex(&out["steps"][0]["return_address"]), back);
    assert_eq!(out["event"]["reason"], "temporary_breakpoint");
    assert_eq!(out["locations"]["pc"]["location"]["function"], "_main");
    assert!(
        out["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("pointer authentication code"))
    );
    let report = finish(stub, harness);
    assert!(report.received.contains(&format!("Z1,{back:x},4")));
}

#[test]
fn mach_exceptions_reach_the_stop_event() {
    let tick = symbol("_tick") + SLIDE;
    let mut faulted = target(0x10, 0);
    faulted.signal = 0x91;
    faulted.exception = (1, vec![2, 0x1_0000_8000]);
    let stub = FakeStub::tcp(script(&target(tick, 0x1_8c4a_6e8c)).execution().on("vCont?", "vCont;c;C;s;S").once(
        "vCont;c",
        vec![Action::Reply(transcripts::debugserver_stop(&faulted, transcripts::DEBUGSERVER_THREAD, ""))],
    ));
    let harness = Harness::new(&stub);
    let run = harness.call("debug_continue", json!({"session": "s1", "epoch": 1})).unwrap();
    let event = &run["event"];
    assert_eq!((event["reason"].as_str(), event["signal"].as_u64()), (Some("signal"), Some(0x91)));
    assert_eq!(event["exception"]["name"], "EXC_BAD_ACCESS");
    assert_eq!(event["exception"]["code_name"], "KERN_PROTECTION_FAILURE");
    assert_eq!(hex(&event["exception"]["fault_address"]), 0x1_0000_8000);
    let status = harness.call("debug_status", json!({"session": "s1"})).unwrap();
    assert_eq!(status["threads"]["items"][0]["queue"], "com.apple.main-thread");
    finish(stub, harness);
}
