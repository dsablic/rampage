use super::*;

fn arm_example() -> PeripheralMap {
    let device = svd::parse(include_str!("../../../../tests/fixtures/svd/ARM_Example.svd")).unwrap();
    let stored = device.peripherals.iter().map(|peripheral| (peripheral.base, encode(peripheral).unwrap())).collect();
    PeripheralMap::new(&stored)
}

#[test]
fn addresses_name_registers_and_names_resolve() {
    let map = arm_example();
    assert_eq!(map.name(0x4001_0000).as_deref(), Some("TIMER0.CR"));
    assert_eq!(map.name(0x4001_0005).as_deref(), Some("TIMER0.SR+1"));
    // Alternates share an offset; the first declared names it.
    assert_eq!(map.name(0x4001_0028).as_deref(), Some("PRESCALE_RD").map(|name| format!("TIMER0.{name}")).as_deref());
    assert_eq!(map.name(0x4001_0030).as_deref(), Some("TIMER0+0x30"));
    assert_eq!(map.name(0x4001_0060), None);
    assert_eq!(map.name(0x4000_ffff), None);
    assert_eq!(map.resolve("TIMER2.RELOAD[3]"), Some(0x4001_025c));
    assert_eq!(map.resolve("TIMER2"), Some(0x4001_0200));
    assert_eq!(map.resolve("TIMER2.NOPE"), None);
}

#[test]
fn structs_pad_gaps_group_arrays_and_skip_alternates() {
    let map = arm_example();
    let (declaration, size) = struct_declaration(map.named("TIMER0").unwrap()).unwrap();
    assert_eq!(size, 0x60);
    assert_eq!(
        declaration,
        "struct TIMER0_regs { uint4 CR; uint2 SR; uint1 _reserved_6[10]; uint2 INT; uint1 _reserved_12[14]; \
         uint4 COUNT; uint4 MATCH; uint4 PRESCALE_RD; uint1 _reserved_2c[36]; uint4 RELOAD[4]; };"
    );
    let (typed, untyped) = struct_plan(&map, &[(0x4001_0104, 0x4001_0108)], &[], u64::from(u32::MAX));
    assert_eq!(typed.iter().map(|typed| typed.base).collect::<Vec<_>>(), [0x4001_0000, 0x4001_0200]);
    assert_eq!(typed[0].global, "struct TIMER0_regs TIMER0;");
    assert!(typed[0].unmapped);
    assert_eq!(untyped, ["TIMER1"]);
    // Inside a mapped data range a peripheral needs no region of its own; across code or a range edge it is
    // left untyped.
    let mapped =
        [(0x4001_0000, 0x4001_0100, false), (0x4001_0100, 0x4001_0180, true), (0x4001_0200, 0x4001_0210, false)];
    let (typed, untyped) = struct_plan(&map, &[], &mapped, u64::from(u32::MAX));
    assert_eq!(typed.len(), 1);
    assert!(!typed[0].unmapped);
    assert_eq!(untyped, ["TIMER1", "TIMER2"]);
    let (typed, _) = struct_plan(&map, &[], &[], 0x4001_0100);
    assert_eq!(typed.len(), 1);
}

#[test]
fn constants_name_the_fields_they_set_or_clear() {
    let map = arm_example();
    let timer = map.named("TIMER0").unwrap();
    let cr = &timer.registers[0];
    assert_eq!(describe_constant(cr, 0x21).as_deref(), Some("EN|MODE=Single_MATCH"));
    assert_eq!(describe_constant(cr, 0xffff_fffe).as_deref(), Some("~(EN)"));
    assert_eq!(describe_constant(cr, 0x70).as_deref(), Some("MODE"));
    assert_eq!(describe_constant(cr, 0x30).as_deref(), Some("MODE=Reload_ZERO_MAX"));
    assert_eq!(describe_constant(cr, 0), None);
    let sr = timer.registers.iter().find(|register| register.name == "SR").unwrap();
    assert_eq!(describe_constant(sr, 0x100).as_deref(), Some("MATCH"));
}

#[test]
fn lines_yield_their_literals_and_registers() {
    let map = arm_example();
    assert_eq!(literals("  TIMER0.RELOAD[2] = x + 0x10 + 3U;"), [0x10, 3]);
    assert_eq!(literals("uVar1 = DAT_4 + 7;"), [7]);
    assert_eq!(literals("while (-1 < x - 2)"), [2]);
    assert_eq!(literals("x = (uint4)TIMER0.SR << 0x17 >> 2 & 4;"), [4]);
    let line = "  TIMER0.RELOAD[2] = TIMER0.RELOAD[2] | 1;";
    let found = registers_on(&map, line);
    assert_eq!(found.iter().map(|register| register.name.as_str()).collect::<Vec<_>>(), ["RELOAD[2]"]);
    assert_eq!(registers_on(&map, "  TIMER0.CR = TIMER1.SR;").len(), 2);
    assert!(registers_on(&map, "  local.CR = 1;").is_empty());
}

#[test]
fn stored_values_are_validated() {
    let map = arm_example();
    let mut peripheral = map.named("TIMER0").unwrap().clone();
    assert_eq!(decode(&encode(&peripheral).unwrap()).unwrap(), peripheral);
    peripheral.registers[0].fields[0].lsb = 40;
    assert!(decode(&encode(&peripheral).unwrap()).is_err());
    peripheral.registers[0].fields.clear();
    peripheral.name = "not an identifier".into();
    assert!(decode(&encode(&peripheral).unwrap()).is_err());
    assert!(decode("{\"name\":\"X\"}").is_err());
}

fn register(name: &str, offset: u64, bits: u32) -> Register {
    Register { name: name.into(), offset, bits, access: None, reset: None, description: None, fields: Vec::new() }
}

fn map_of(peripherals: Vec<Peripheral>) -> PeripheralMap {
    let stored = peripherals.iter().map(|peripheral| (peripheral.base, encode(peripheral).unwrap())).collect();
    PeripheralMap::new(&stored)
}

fn peripheral(name: &str, base: u64, registers: Vec<Register>) -> Peripheral {
    Peripheral { device: "D".into(), name: name.into(), group: None, description: None, base, registers }
}

/// An exact offset wins; otherwise the covering register starting highest, the first declared breaking ties. The
/// stored order does not matter: decoding sorts by offset.
#[test]
fn registers_resolve_to_the_exact_or_highest_covering_one() {
    // A 64-bit DATA at 0 overlaps 32-bit HIGH at 4 and its alternate HIGH_ALT; LOW at 0 is declared after DATA.
    let registers =
        vec![register("HIGH", 4, 32), register("DATA", 0, 64), register("LOW", 0, 32), register("HIGH_ALT", 4, 32)];
    let map = map_of(vec![peripheral("P", 0x1000, registers)]);
    assert_eq!(map.name(0x1000).as_deref(), Some("P.DATA"));
    assert_eq!(map.name(0x1002).as_deref(), Some("P.DATA+2"));
    assert_eq!(map.name(0x1004).as_deref(), Some("P.HIGH"));
    assert_eq!(map.name(0x1006).as_deref(), Some("P.HIGH+2"));
}

/// A peripheral whose base is lower still names addresses past a later, shorter peripheral's span.
#[test]
fn overlapping_peripherals_do_not_hide_each_other() {
    let wide = peripheral("WIDE", 0x1000, vec![register("A", 0, 32), register("Z", 0x100, 32)]);
    let narrow = peripheral("NARROW", 0x1010, vec![register("B", 0, 32)]);
    let map = map_of(vec![wide, narrow]);
    assert_eq!(map.name(0x1010).as_deref(), Some("NARROW.B"));
    assert_eq!(map.name(0x1100).as_deref(), Some("WIDE.Z"));
    assert_eq!(map.name(0x1020).as_deref(), Some("WIDE+0x20"));
}

#[test]
fn names_shared_with_symbols_are_ambiguous() {
    assert_eq!(unambiguous("X", Some(1), None).unwrap(), Some(1));
    assert_eq!(unambiguous("X", None, Some(2)).unwrap(), Some(2));
    assert_eq!(unambiguous("X", Some(2), Some(2)).unwrap(), Some(2));
    let error = unambiguous("X", Some(1), Some(2)).unwrap_err().to_string();
    assert!(error.contains("ambiguous") && error.contains("0x1") && error.contains("0x2"), "{error}");
}

fn cortex_project(name: &str) -> Project {
    let path = format!("{}/../../tests/fixtures/firmware/{name}.bin", env!("CARGO_MANIFEST_DIR"));
    let options = rampage_loaders::RawCodeOptions {
        profile: rampage_loaders::RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    Project::new(rampage_loaders::Binary::from_raw_code(std::fs::read(path).unwrap(), options).unwrap())
}

/// A function the budget cuts short contributes no accesses at all.
#[test]
fn the_scan_budget_drops_partial_functions() {
    let project = cortex_project("raw-cortex-m-svd");
    let full = project.scan_accesses_within(MAX_SCAN_INSTRUCTIONS, MAX_ACCESSES).unwrap();
    assert!(!full.incomplete && full.by_address.len() > 4);
    let functions: std::collections::BTreeSet<u64> = full.by_address.iter().map(|access| access.function).collect();
    for limit in 1..full.by_address.len() {
        let cut = project.scan_accesses_within(MAX_SCAN_INSTRUCTIONS, limit).unwrap();
        assert!(cut.incomplete);
        for function in &functions {
            let part = cut.by_address.iter().filter(|access| access.function == *function).count();
            let whole = full.by_address.iter().filter(|access| access.function == *function).count();
            assert!(part == 0 || part == whole, "{function:#x}: {part} of {whole} at limit {limit}");
        }
    }
    let cut = project.scan_accesses_within(5, MAX_ACCESSES).unwrap();
    assert!(cut.incomplete && cut.by_address.is_empty());
}

/// After an in-instruction CBRANCH (ARM conditional execution) the instruction's outputs are unknown.
#[test]
fn conditionally_written_values_are_unknown() {
    let project = cortex_project("raw-cortex-m-svd");
    let node = |space: u32, offset: u64| Varnode {
        space,
        size: 4,
        address_size: 4,
        word_size: 1,
        offset: Some(offset),
        selected_space: None,
    };
    let (constant, register, ram) = (0, 1, 2);
    let evaluator =
        Evaluator { binary: &project.binary, constant, register: Some(register), ram, preserved: Vec::new() };
    let op = |name: &str, output: Option<Varnode>, inputs: Vec<Varnode>| rampage_decompiler::sleigh_decode::PcodeOp {
        opcode: 0,
        name: name.into(),
        address: 0,
        output,
        inputs,
    };
    let mut values = Values::new();
    let ops = [
        op("COPY", Some(node(register, 0)), vec![node(constant, 0x4001_0000)]),
        op("CBRANCH", None, vec![node(ram, 0x0800_0100), node(constant, 1)]),
        op("COPY", Some(node(register, 4)), vec![node(constant, 0x4001_0100)]),
        op("COPY", Some(node(register, 0)), vec![node(constant, 0x4001_0200)]),
    ];
    evaluator.step(&ops, &mut values, |_, _| {});
    assert_eq!(values.get(&(register, 0, 4)), None);
    assert_eq!(values.get(&(register, 4, 4)), None);
    // Without the branch both are known.
    let mut values = Values::new();
    evaluator.step(&[ops[0].clone(), ops[2].clone()], &mut values, |_, _| {});
    assert_eq!(values.get(&(register, 0, 4)), Some(&0x4001_0000));
    assert_eq!(values.get(&(register, 4, 4)), Some(&0x4001_0100));
}

/// An immediate is named as a register only where its function accesses that peripheral, and never below 0x100.
#[test]
fn immediates_are_named_only_where_used_as_register_addresses() {
    let project = cortex_project("raw-cortex-m-svd");
    let device = svd::parse(include_str!("../../../../tests/fixtures/svd/ARM_Example.svd")).unwrap();
    let changes: Vec<_> =
        device.peripherals.iter().map(|p| (Field::Peripheral, p.base, Some(encode(p).unwrap()))).collect();
    project.set_peripheral_annotations(&changes).unwrap();
    // timer0_start (0x8000040) stores to TIMER0; scale (0x80000b4) touches no peripheral.
    assert_eq!(project.immediate_register_name(0x0800_0046, 0x4001_0000).as_deref(), Some("TIMER0.CR"));
    assert_eq!(project.immediate_register_name(0x0800_00b8, 0x4001_0000), None);
    // On a low-address map a small constant is never a register name.
    let low = peripheral("LOW", 0x40, vec![register("R", 0, 32)]);
    project.set_peripheral_annotations(&[(Field::Peripheral, 0x40, Some(encode(&low).unwrap()))]).unwrap();
    assert_eq!(project.peripheral_name(0x40).as_deref(), Some("LOW.R"));
    assert_eq!(project.immediate_register_name(0x0800_0046, 0x40), None);
}
