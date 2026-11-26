//! CMSIS-SVD peripheral maps on headerless Cortex-M images: tests/fixtures/firmware/raw-cortex-m-svd.c drives the
//! timers of tests/fixtures/svd/ARM_Example.svd through raw MMIO addresses (movw/movt), and
//! raw-cortex-m-decompile.c reaches tests/fixtures/svd/edge-cases.svd's CTRL block through literal pools.

use rampage_api::{ImportSvdRequest, PeripheralAccessQuery, PeripheralMapQuery, Project, XrefQuery};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

const FIRMWARE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/");
const SVD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/svd/");

fn project(name: &str) -> Project {
    let image = std::fs::read(format!("{FIRMWARE}{name}.bin")).unwrap();
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    Project::new(Binary::from_raw_code(image, options).unwrap())
}

fn truth(name: &str, symbol: &str) -> u64 {
    let elf = Binary::open(format!("{FIRMWARE}{name}.elf")).unwrap();
    elf.symbol_by_name(symbol).unwrap().address & !1
}

fn import(project: &Project, svd: &str, apply: bool) -> rampage_api::ImportSvdReport {
    project.import_svd(&ImportSvdRequest { svd: format!("{SVD}{svd}").into(), apply }).unwrap()
}

#[test]
fn import_previews_then_applies_and_undoes() {
    let project = project("raw-cortex-m-svd");
    let preview = import(&project, "ARM_Example.svd", false);
    assert_eq!((preview.device.as_str(), preview.peripherals, preview.added), ("ARM_Example", 3, 3));
    assert!(project.resolve("TIMER0.CR").is_err(), "a preview stores nothing");
    let applied = import(&project, "ARM_Example.svd", true);
    assert!(applied.applied && applied.untyped.is_empty(), "{applied:?}");
    assert_eq!(project.resolve("TIMER1.COUNT").unwrap(), 0x4001_0120);
    assert_eq!(project.resolve("TIMER0").unwrap(), 0x4001_0000);
    assert_eq!(project.name_at(0x4001_0058).as_deref(), Some("TIMER0.RELOAD[2]"));
    assert_eq!(project.name_at(0x4001_0002).as_deref(), Some("TIMER0.CR+2"));
    // Re-importing the same map changes nothing; another map replaces it.
    let again = import(&project, "ARM_Example.svd", true);
    assert_eq!((again.added, again.replaced, again.removed, again.unchanged), (0, 0, 0, 3));
    let replaced = import(&project, "edge-cases.svd", true);
    assert_eq!((replaced.added, replaced.removed), (2, 3));
    assert!(project.resolve("TIMER0").is_err());
    project.undo().unwrap();
    assert_eq!(project.resolve("TIMER0").unwrap(), 0x4001_0000);
}

#[test]
fn decompiled_register_accesses_read_as_peripheral_fields() {
    let project = project("raw-cortex-m-svd");
    let decompile = |symbol: &str| project.decompile(truth("raw-cortex-m-svd", symbol)).unwrap().code;
    let before = decompile("timer0_start");
    assert!(before.contains("periph_40010000"), "{before}");
    import(&project, "ARM_Example.svd", true);
    let code = decompile("timer0_start");
    assert!(code.contains("TIMER0.MATCH = param_1;"), "{code}");
    // Registers are volatile: the read-modify-write keeps its read as its own statement.
    assert!(code.contains("uVar1 = TIMER0.CR;"), "{code}");
    assert!(code.contains("TIMER0.CR = uVar1 | 0x21; /* CR: EN|MODE=Single_MATCH */"), "{code}");
    let code = decompile("timer0_stop");
    assert!(code.contains("/* CR: ~(EN) */"), "{code}");
    let code = decompile("timer0_wait");
    assert!(code.contains("TIMER0.SR") && code.contains("TIMER0.COUNT"), "{code}");
    // The compiler tests SR.MATCH by shifting it into the sign bit; a shift count names no field.
    assert!(!code.contains("/*"), "{code}");
    let code = decompile("timer0_reload");
    assert!(code.contains("TIMER0.RELOAD[2] = param_1;"), "{code}");
    let code = decompile("timer1_count");
    assert!(code.contains("uVar1 = TIMER1.COUNT;"), "{code}");
}

#[test]
fn literal_pool_accesses_resolve_to_registers() {
    let project = project("raw-cortex-m-decompile");
    import(&project, "edge-cases.svd", true);
    let at = truth("raw-cortex-m-decompile", "advance_cursor");
    let code = project.decompile(at).unwrap().code;
    assert!(code.contains("uVar1 = CTRL.STATUS;") && code.contains("CTRL.CONTROL = uVar1 | 0x100;"), "{code}");
    let listing = project.function_listing(at).unwrap();
    let comments: Vec<String> = listing.blocks.iter().flatten().filter_map(|line| line.comment.clone()).collect();
    assert!(comments.iter().any(|comment| comment.contains("=CTRL.STATUS")), "{comments:?}");
    assert!(comments.iter().any(|comment| comment.contains("CTRL.CONTROL")), "{comments:?}");
}

#[test]
fn xrefs_and_access_listing_name_the_functions_touching_a_register() {
    let project = project("raw-cortex-m-svd");
    import(&project, "ARM_Example.svd", true);
    let function = |address: u64| project.function_name(project.function_containing(address).unwrap().unwrap());
    let cr = project.xrefs(XrefQuery::To(project.resolve("TIMER0.CR").unwrap()), None, None).unwrap();
    let mut users: Vec<String> = cr.items.iter().map(|row| function(row.from)).collect();
    users.sort();
    users.dedup();
    let start = project.function_name(truth("raw-cortex-m-svd", "timer0_start"));
    let stop = project.function_name(truth("raw-cortex-m-svd", "timer0_stop"));
    let mut expected = vec![start.clone(), stop];
    expected.sort();
    assert_eq!(users, expected);
    assert!(cr.items.iter().any(|row| row.access == Some("write")));
    assert!(cr.items.iter().all(|row| row.to_name.as_deref() == Some("TIMER0.CR")));
    // A peripheral's name covers all its registers.
    let all = project.xrefs(project.xref_query_to("TIMER0").unwrap(), None, None).unwrap();
    assert!(all.total > cr.total);
    assert!(all.items.iter().all(|row| row.to_name.as_deref().is_some_and(|name| name.starts_with("TIMER0."))));
    let timer1 = project.xrefs(project.xref_query_to("TIMER1").unwrap(), None, None).unwrap();
    assert_eq!(timer1.total, 1);
    assert_eq!(function(timer1.items[0].from), project.function_name(truth("raw-cortex-m-svd", "timer1_count")));

    let listing = project.peripheral_access(&PeripheralAccessQuery { peripheral: None, offset: 0, limit: 10 }).unwrap();
    assert_eq!(listing.total, 3);
    let timer2 = listing.peripherals.iter().find(|row| row.name == "TIMER2").unwrap();
    assert_eq!((timer2.reads, timer2.writes, timer2.functions), (0, 0, 0));
    let registers = project
        .peripheral_access(&PeripheralAccessQuery { peripheral: Some("TIMER0".into()), offset: 0, limit: 100 })
        .unwrap();
    let cr = registers.registers.iter().find(|row| row.name == "CR").unwrap();
    assert_eq!((cr.reads, cr.writes), (2, 2));
    assert!(cr.functions.contains(&start));
    assert!(cr.fields.contains(&"MODE[6:4]".to_owned()) && cr.fields.contains(&"EN[0]".to_owned()));
    let count = registers.registers.iter().find(|row| row.name == "COUNT").unwrap();
    assert_eq!((count.reads, count.writes), (1, 0));
}

#[test]
fn disassembly_names_register_accesses() {
    let project = project("raw-cortex-m-svd");
    import(&project, "ARM_Example.svd", true);
    let at = truth("raw-cortex-m-svd", "timer0_start");
    let lines = project.disassemble(Some(&format!("{at:#x}")), 8).unwrap();
    let comments: Vec<String> = lines.iter().filter_map(|line| line.comment.clone()).collect();
    assert!(comments.iter().any(|comment| comment == "TIMER0.MATCH"), "{comments:?}");
    assert!(comments.iter().any(|comment| comment == "TIMER0.CR"), "{comments:?}");
}

#[test]
fn evaluation_names_registers_and_reads_supplied_values() {
    let project = project("raw-cortex-m-svd");
    import(&project, "ARM_Example.svd", true);
    let request = |mmio: serde_json::Value| -> rampage_api::evaluate::EvaluateRequest {
        serde_json::from_value(serde_json::json!({"at": "0x800006c", "mmio": mmio})).unwrap()
    };
    let wait = truth("raw-cortex-m-svd", "timer0_wait");
    assert_eq!(wait, 0x0800_006c);
    let report = serde_json::to_value(project.evaluate_function(&request(serde_json::json!([]))).unwrap()).unwrap();
    assert_eq!(report["stop"], "unmapped_read", "{report}");
    assert!(report.to_string().contains("(TIMER0.SR)"), "{report}");
    // With SR.MATCH set and COUNT given, the poll ends and COUNT is returned.
    let mmio = serde_json::json!([{"at": "TIMER0.SR", "value": "0x100"}, {"at": "TIMER0.COUNT", "value": 1234}]);
    let report = serde_json::to_value(project.evaluate_function(&request(mmio)).unwrap()).unwrap();
    assert_eq!(report["stop"], "returned", "{report}");
    assert_eq!(report["result"]["unsigned"], 1234, "{report}");
}

#[test]
fn refuses_files_that_are_not_svd() {
    let project = project("raw-cortex-m-svd");
    let error = project
        .import_svd(&ImportSvdRequest { svd: format!("{FIRMWARE}raw-cortex-m-svd.c").into(), apply: false })
        .unwrap_err();
    assert!(error.to_string().contains("XML") || error.to_string().contains("SVD"), "{error}");
}

/// Peripheral registers are volatile: two consecutive writes both stay, and a read right after a write reads the
/// register rather than the value written.
#[test]
fn register_stores_and_loads_are_volatile() {
    let project = project("raw-cortex-m-svd-volatile");
    import(&project, "ARM_Example.svd", true);
    let decompile = |symbol: &str| project.decompile(truth("raw-cortex-m-svd-volatile", symbol)).unwrap().code;
    let pulse = decompile("timer0_pulse");
    assert!(pulse.contains("TIMER0.CR = 2;") && pulse.contains("TIMER0.CR = 1;"), "{pulse}");
    let echo = decompile("timer0_echo");
    assert!(echo.contains("TIMER0.MATCH = param_1;") && echo.contains("uVar1 = TIMER0.MATCH;"), "{echo}");
}

/// A name both a symbol and an imported peripheral use is refused rather than silently picking one.
#[test]
fn a_name_shared_by_a_symbol_and_a_peripheral_is_ambiguous() {
    let project = project("raw-cortex-m-svd");
    import(&project, "ARM_Example.svd", true);
    project.rename(truth("raw-cortex-m-svd", "scale"), Some("TIMER1")).unwrap();
    for error in [project.resolve("TIMER1").unwrap_err(), project.xref_query_to("TIMER1").unwrap_err()] {
        assert!(error.to_string().contains("ambiguous"), "{error}");
    }
    assert_eq!(project.resolve("TIMER0").unwrap(), 0x4001_0000);
}

// peripheral_map: tests/fixtures/firmware/raw-cortex-m-peripherals.c reaches an audio-like block, a GPIO-like block
// and the Cortex-M core blocks through literal-pool bases; its `routing` table holds address-like words that are
// never dereferenced.

fn map(project: &Project, query: PeripheralMapQuery) -> rampage_api::PeripheralMapReport {
    project.map_peripherals(&PeripheralMapQuery { limit: 100, ..query }).unwrap()
}

fn block(report: &rampage_api::PeripheralMapReport, base: u64) -> &rampage_api::PeripheralBlockRow {
    report.blocks.iter().find(|block| block.base == base).unwrap_or_else(|| panic!("{base:#x}: {report:#?}"))
}

fn registers(block: &rampage_api::PeripheralBlockRow) -> Vec<(u64, Option<&str>, &str, u8)> {
    block.registers.iter().map(|r| (r.offset, r.name.as_deref(), r.access, r.width)).collect()
}

#[test]
fn peripheral_map_without_an_svd_groups_loads_and_stores_into_blocks() {
    let project = project("raw-cortex-m-peripherals");
    let truth = |symbol: &str| truth("raw-cortex-m-peripherals", symbol);
    let report = map(&project, PeripheralMapQuery::default());
    let bases: Vec<(u64, &str, &str)> =
        report.blocks.iter().map(|block| (block.base, block.name.as_str(), block.source)).collect();
    // The routing table's 0x40030000 and 0x4003ff00 are never dereferenced, so no block holds them.
    assert_eq!(
        bases,
        [
            (0x4001_5800, "periph_40015800", "address"),
            (0x4002_0000, "periph_40020000", "address"),
            (0xe000_e010, "SysTick", "core"),
            (0xe000_e100, "NVIC", "core"),
            (0xe000_ed00, "SCB", "core"),
        ]
    );
    assert_eq!((report.counts.blocks, report.counts.functions), (5, 5));
    // Bases 0x40015804 (offset -4) and 0x40015818 (loaded once, used in a loop) both land in one block.
    let audio = block(&report, 0x4001_5800);
    assert_eq!(
        registers(audio),
        [
            (0x0, None, "w", 4),
            (0x4, None, "rw", 4),
            (0xc, None, "w", 4),
            (0x10, None, "w", 4),
            (0x14, None, "w", 4),
            (0x18, None, "r", 4),
            (0x20, None, "w", 4)
        ]
    );
    let configure = project.function_name(truth("audio_configure"));
    let write = project.function_name(truth("audio_write"));
    assert_eq!(audio.registers[0].functions, std::slice::from_ref(&configure));
    assert_eq!(audio.registers[6].functions, [write]);
    let gpio = block(&report, 0x4002_0000);
    assert_eq!(registers(gpio), [(0x10, None, "r", 1), (0x18, None, "w", 2)]);
    assert_eq!(registers(block(&report, 0xe000_ed00)), [(0x8, Some("VTOR"), "w", 4)]);
    assert_eq!(registers(block(&report, 0xe000_e100)), [(0x0, Some("ISER0"), "w", 4)]);
    assert_eq!(registers(block(&report, 0xe000_e010)), [(0x0, Some("CTRL"), "w", 4), (0x4, Some("LOAD"), "w", 4)]);
    // The function writing the most registers is the one to read first.
    assert!(
        report.next.as_deref().is_some_and(|next| next.starts_with(&format!("decompile {configure}"))),
        "{report:?}"
    );

    // Per function: core_setup touches the three core blocks.
    let by_function = map(&project, PeripheralMapQuery { by_function: true, ..PeripheralMapQuery::default() });
    let core = by_function.functions.iter().find(|row| row.address == truth("core_setup")).unwrap();
    let touched: Vec<(&str, Vec<&str>)> = core
        .blocks
        .iter()
        .map(|block| (block.name.as_str(), block.offsets.iter().map(String::as_str).collect()))
        .collect();
    assert_eq!(
        touched,
        [("SysTick", vec!["0x0 CTRL w", "0x4 LOAD w"]), ("NVIC", vec!["0x0 ISER0 w"]), ("SCB", vec!["0x8 VTOR w"])]
    );
    assert_eq!((core.reads, core.writes), (0, 4));
    assert_eq!(by_function.functions[0].address, truth("core_setup"), "most blocks first");

    // Filters: one function, and an address range; then paging.
    let one = map(&project, PeripheralMapQuery { function: Some(truth("gpio_set")), ..PeripheralMapQuery::default() });
    assert_eq!((one.counts.accesses, one.counts.writes, one.blocks.len()), (1, 1, 1));
    let range =
        PeripheralMapQuery { start: Some(0xe000_0000), end: Some(0xe010_0000), ..PeripheralMapQuery::default() };
    assert_eq!(map(&project, range).counts.blocks, 3);
    let paged =
        project.map_peripherals(&PeripheralMapQuery { offset: 1, limit: 2, ..PeripheralMapQuery::default() }).unwrap();
    assert_eq!((paged.total, paged.offset, paged.blocks.len(), paged.blocks[0].base), (5, 1, 2, 0x4002_0000));
}

#[test]
fn peripheral_map_takes_block_and_register_names_from_an_imported_svd() {
    let project = project("raw-cortex-m-svd");
    let before = map(&project, PeripheralMapQuery::default());
    // Without the SVD the two timers 0x100 apart share one 1 KiB block.
    let timers = block(&before, 0x4001_0000);
    assert_eq!(timers.source, "address");
    let offsets: Vec<u64> = timers.registers.iter().map(|register| register.offset).collect();
    assert_eq!(offsets, [0x0, 0x4, 0x20, 0x24, 0x58, 0x120]);
    import(&project, "ARM_Example.svd", true);
    let after = map(&project, PeripheralMapQuery::default());
    let names: Vec<(&str, &str)> = after.blocks.iter().map(|block| (block.name.as_str(), block.source)).collect();
    assert_eq!(names, [("TIMER0", "svd"), ("TIMER1", "svd")]);
    let timer0 = block(&after, 0x4001_0000);
    assert_eq!(
        registers(timer0),
        [
            (0x0, Some("CR"), "rw", 4),
            (0x4, Some("SR"), "r", 2),
            (0x20, Some("COUNT"), "r", 4),
            (0x24, Some("MATCH"), "w", 4),
            (0x58, Some("RELOAD[2]"), "w", 4)
        ]
    );
    assert_eq!(timer0.registers[3].functions, [project.function_name(truth("raw-cortex-m-svd", "timer0_start"))]);
    assert_eq!(registers(block(&after, 0x4001_0100)), [(0x20, Some("COUNT"), "r", 4)]);
}

#[test]
fn peripheral_map_reads_an_elf_cortex_m_image() {
    let project = Project::new(Binary::open(format!("{FIRMWARE}raw-cortex-m-peripherals.elf")).unwrap());
    let report = map(&project, PeripheralMapQuery::default());
    let names: Vec<&str> = report.blocks.iter().map(|block| block.name.as_str()).collect();
    assert_eq!(names, ["periph_40015800", "periph_40020000", "SysTick", "NVIC", "SCB"]);
    assert_eq!(block(&report, 0x4001_5800).accessed_by, ["audio_write", "audio_configure"]);
}

#[test]
fn peripheral_map_on_a_hosted_binary_is_empty_with_a_note() {
    for name in ["hello-arm.elf", "hello-x64.elf"] {
        let path = format!("{}/../../tests/fixtures/bin/{name}", env!("CARGO_MANIFEST_DIR"));
        let project = Project::new(Binary::open(path).unwrap());
        let report = map(&project, PeripheralMapQuery::default());
        assert_eq!((report.counts.accesses, report.total), (0, 0), "{name}");
        assert!(report.blocks.is_empty() && report.next.is_none(), "{name}");
        assert_eq!(report.notes.len(), 1, "{name}: {report:?}");
    }
}
