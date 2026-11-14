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
