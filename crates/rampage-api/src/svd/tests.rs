use super::*;

const ARM_EXAMPLE: &str = include_str!("../../../../tests/fixtures/svd/ARM_Example.svd");
const EDGE: &str = include_str!("../../../../tests/fixtures/svd/edge-cases.svd");

fn register<'a>(peripheral: &'a Peripheral, name: &str) -> &'a Register {
    peripheral.registers.iter().find(|register| register.name == name).unwrap_or_else(|| panic!("{name}"))
}

#[test]
fn reads_the_arm_example_device() {
    let device = parse(ARM_EXAMPLE).unwrap();
    assert_eq!(device.name, "ARM_Example");
    let names: Vec<_> =
        device.peripherals.iter().map(|peripheral| (peripheral.name.as_str(), peripheral.base)).collect();
    assert_eq!(names, [("TIMER0", 0x4001_0000), ("TIMER1", 0x4001_0100), ("TIMER2", 0x4001_0200)]);
    let timer0 = &device.peripherals[0];
    let cr = register(timer0, "CR");
    assert_eq!((cr.offset, cr.bits, cr.reset), (0, 32, Some(0)));
    let mode = cr.fields.iter().find(|field| field.name == "MODE").unwrap();
    assert_eq!((mode.lsb, mode.width), (4, 3));
    assert!(mode.values.contains(&("Single_MATCH".to_owned(), 2)));
    assert_eq!((register(timer0, "SR").bits, register(timer0, "SR").offset), (16, 4));
    // Alternate registers share an offset; the array keeps C subscripts because its elements are contiguous.
    assert_eq!(register(timer0, "PRESCALE_RD").offset, register(timer0, "PRESCALE_WR").offset);
    assert_eq!(register(timer0, "RELOAD[2]").offset, 0x58);
    // Derived peripherals copy the registers at their own base.
    assert_eq!(device.peripherals[1].registers, timer0.registers);
    assert_eq!(timer0.span(), 0x60);
}

#[test]
fn reads_clusters_dim_lists_and_derivations() {
    let device = parse(EDGE).unwrap();
    let ctrl = &device.peripherals[0];
    assert_eq!(ctrl.group.as_deref(), Some("SYS"));
    assert_eq!(ctrl.description.as_deref(), Some("Control & status block"));
    // The peripheral's resetValue reaches registers without their own.
    assert_eq!(register(ctrl, "STATUS").reset, Some(0x11));
    assert_eq!(register(ctrl, "CONTROL").reset, Some(0));
    assert_eq!(register(ctrl, "STATUS").access.as_deref(), Some("read-only"));
    let status = register(ctrl, "STATUS");
    let fields: Vec<_> = status.fields.iter().map(|field| (field.name.as_str(), field.lsb, field.width)).collect();
    assert_eq!(fields, [("READY", 0, 1), ("MODE", 4, 2), ("ERR", 8, 1)]);
    // A value with don't-care bits names no single value.
    assert_eq!(status.fields[1].values, [("Idle".to_owned(), 0), ("Busy".to_owned(), 2)]);
    let control = register(ctrl, "CONTROL");
    assert!(control.fields.iter().any(|field| field.name == "IE1" && field.lsb == 13));
    for (name, offset, bits) in
        [("CH0_CR", 0x10, 32), ("CH0_DR", 0x14, 16), ("CH1_CR", 0x20, 32), ("DATAB", 0x44, 32), ("BYTE", 0x54, 8)]
    {
        let found = register(ctrl, name);
        assert_eq!((found.offset, found.bits), (offset, bits), "{name}");
    }
    assert_eq!(register(ctrl, "ALT").fields, status.fields);
    assert_eq!(device.peripherals[1].name, "CTRL2");
    assert_eq!(device.peripherals[1].base, 0x4002_2000);
    // The circular pair is left out with a warning, not looped over.
    assert_eq!(device.peripherals.len(), 2);
    assert!(device.warnings.iter().any(|warning| warning.contains("circular")), "{:?}", device.warnings);
}

#[test]
fn numbers_follow_scaled_non_negative_integer() {
    for (text, value) in [("16", 16), ("0x10", 16), ("0X1f", 31), ("#101", 5), ("4k", 4096), ("1M", 1 << 20)] {
        assert_eq!(number(text), Some(value), "{text}");
    }
    for text in ["", "0x", "#12", "-1", "1x", "99999999999999999999", "16777216T"] {
        assert_eq!(number(text), None, "{text}");
    }
}

#[test]
fn refuses_hostile_and_malformed_documents() {
    let wrap = |peripherals: &str| format!("<device><name>D</name><peripherals>{peripherals}</peripherals></device>");
    for text in [
        String::new(),
        "<device>".to_owned(),
        "<notsvd/>".to_owned(),
        "<device><name>D</name></device>".to_owned(),
        // No entity is expanded, internal DTD or not.
        "<!DOCTYPE device [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;\">]><device><name>&b;</name></device>".to_owned(),
        "<device><name>&custom;</name></device>".to_owned(),
        "<a>".repeat(MAX_DEPTH + 2) + &"</a>".repeat(MAX_DEPTH + 2),
    ] {
        assert!(parse(&text).is_err(), "{text}");
    }
    // An oversized dim is refused for its peripheral, which is left out with a warning.
    let device = parse(&wrap(
        "<peripheral><name>P</name><baseAddress>0</baseAddress><registers><register><name>R%s</name>\
         <dim>100000</dim><dimIncrement>4</dimIncrement><addressOffset>0</addressOffset></register></registers>\
         </peripheral>",
    ))
    .unwrap();
    assert!(device.peripherals.is_empty() && !device.warnings.is_empty());
    // Addresses that overflow are refused, not wrapped.
    let device = parse(&wrap(
        "<peripheral><name>P</name><baseAddress>0xfffffffffffffff0</baseAddress><registers><register><name>R</name>\
         <addressOffset>0x20</addressOffset></register></registers></peripheral>",
    ))
    .unwrap();
    assert!(device.peripherals.is_empty());
    // Clusters nested past the limit are refused.
    let nested = "<cluster><name>C</name><addressOffset>0</addressOffset>".repeat(MAX_CLUSTER_DEPTH + 2)
        + "<register><name>R</name><addressOffset>0</addressOffset></register>"
        + &"</cluster>".repeat(MAX_CLUSTER_DEPTH + 2);
    let device = parse(&wrap(&format!(
        "<peripheral><name>P</name><baseAddress>0</baseAddress><registers>{nested}</registers></peripheral>"
    )))
    .unwrap();
    assert!(device.peripherals.is_empty());
}

#[test]
fn names_become_identifiers() {
    assert_eq!(identifier("GPIO-A"), "GPIO_A");
    assert_eq!(identifier("3V3"), "_3V3");
    assert_eq!(register_name("RELOAD[12]"), "RELOAD[12]");
    assert_eq!(register_name("X[a]"), "X_a_");
}

#[test]
fn random_text_never_panics() {
    let alphabet: Vec<char> = "<>/=\"'ab&;#x!-?[] devicpharlsznm0123%".chars().collect();
    let mut state = 0x1234_5678_u64;
    for _ in 0..3000 {
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let length = (next() % 160) as usize;
        let text: String = (0..length).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect();
        let _ = parse(&text);
    }
}

fn device(peripherals: &str) -> String {
    format!("<device><name>D</name><peripherals>{peripherals}</peripherals></device>")
}

/// A peripheral array copies every register; the copies count against the device-wide limits before any is made.
#[test]
fn peripheral_arrays_are_charged_before_they_are_copied() {
    let registers: String = (0..64)
        .map(|index| format!("<register><name>R{index}</name><addressOffset>{}</addressOffset></register>", index * 4))
        .collect();
    let array = |name: &str, base: u64| {
        format!(
            "<peripheral><name>{name}[%s]</name><dim>4096</dim><dimIncrement>0x1000</dimIncrement>\
             <baseAddress>{base:#x}</baseAddress><registers>{registers}</registers></peripheral>"
        )
    };
    // 4096 copies of 64 registers pass the register limit: the whole file is refused.
    let error = parse(&device(&array("P", 0x4000_0000))).unwrap_err();
    assert!(error.contains("registers"), "{error}");
    // Two arrays of 4096 pass the peripheral limit.
    let small = |name: &str, base: u64| {
        format!(
            "<peripheral><name>{name}[%s]</name><dim>4096</dim><dimIncrement>0x1000</dimIncrement>\
             <baseAddress>{base:#x}</baseAddress></peripheral>"
        )
    };
    let error = parse(&device(&(small("A", 0x4000_0000) + &small("B", 0x5000_0000)))).unwrap_err();
    assert!(error.contains("peripherals"), "{error}");
}

/// Fields and enumerated values share one device-wide budget, every copy counted; past it the file is refused.
#[test]
fn fields_and_values_have_a_device_wide_budget() {
    let values: String = (0..255)
        .map(|index| format!("<enumeratedValue><name>V{index}</name><value>{index}</value></enumeratedValue>"))
        .collect();
    let peripheral = format!(
        "<peripheral><name>P</name><baseAddress>0</baseAddress><registers><register><name>R%s</name><dim>65</dim>\
         <dimIncrement>4</dimIncrement><addressOffset>0</addressOffset><fields><field><name>F%s</name><dim>64</dim>\
         <dimIncrement>0</dimIncrement><bitOffset>0</bitOffset><bitWidth>8</bitWidth><enumeratedValues>{values}\
         </enumeratedValues></field></fields></register></registers></peripheral>"
    );
    let error = parse(&device(&peripheral)).unwrap_err();
    assert!(error.contains("fields and enumerated values"), "{error}");
}

/// Field positions that overflow or lie outside the register skip that field with a warning; the rest import.
#[test]
fn overflowing_field_positions_skip_the_field() {
    let peripheral = "<peripheral><name>P</name><baseAddress>0</baseAddress><registers><register><name>R</name>\
        <addressOffset>0</addressOffset><fields>\
        <field><name>HUGE</name><bitOffset>0xffffffffffffffff</bitOffset><bitWidth>2</bitWidth></field>\
        <field><name>WIDE</name><lsb>0</lsb><msb>0xffffffffffffffff</msb></field>\
        <field><name>RANGE</name><bitRange>[18446744073709551615:0]</bitRange></field>\
        <field><name>SHIFTED%s</name><dim>2</dim><dimIncrement>0xffffffffffffffff</dimIncrement><bitOffset>4</bitOffset>\
        <bitWidth>1</bitWidth></field>\
        <field><name>OK</name><bitOffset>3</bitOffset><bitWidth>2</bitWidth></field>\
        </fields></register></registers></peripheral>";
    let parsed = parse(&device(peripheral)).unwrap();
    let fields: Vec<_> = parsed.peripherals[0].registers[0].fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(fields, ["OK", "SHIFTED0"]);
    assert!(parsed.warnings.iter().filter(|warning| warning.contains("skipped")).count() >= 4, "{:?}", parsed.warnings);
}

/// A dotted register `derivedFrom` resolves in another peripheral; one that names nothing warns.
#[test]
fn dotted_register_derivations_cross_peripherals() {
    let peripherals = "<peripheral><name>A</name><baseAddress>0x1000</baseAddress><registers>\
        <register><name>CTL</name><addressOffset>0</addressOffset><size>16</size><fields><field><name>GO</name>\
        <bitOffset>2</bitOffset><bitWidth>1</bitWidth></field></fields></register></registers></peripheral>\
        <peripheral><name>B</name><baseAddress>0x2000</baseAddress><registers>\
        <register derivedFrom=\"A.CTL\"><name>CTL2</name><addressOffset>8</addressOffset></register>\
        <register derivedFrom=\"A.NOPE\"><name>X</name><addressOffset>12</addressOffset></register>\
        </registers></peripheral>";
    let parsed = parse(&device(peripherals)).unwrap();
    let ctl2 = &parsed.peripherals[1].registers[0];
    assert_eq!((ctl2.name.as_str(), ctl2.bits, ctl2.offset, ctl2.fields[0].name.as_str()), ("CTL2", 16, 8, "GO"));
    assert!(parsed.warnings.iter().any(|warning| warning.contains("A.NOPE")), "{:?}", parsed.warnings);
}
