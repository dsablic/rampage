//! Hostile DEX files: truncation, lying counts and offsets, LEB128 overflow, cycles, bad strings and random damage.
//! None may panic, loop or allocate from an unchecked count.

use rampage_dex::insn::disassemble;
use rampage_dex::testkit::{ClassSpec, fix_checksums, sample_classes, write_dex};
use rampage_dex::{Dex, DexError};

fn sample() -> Vec<u8> {
    write_dex(&sample_classes(), 35)
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Reads everything the parsed file offers, as a tool would.
fn exercise(dex: &Dex) {
    let mut budget = dex.limits.max_members;
    for index in 0..dex.header.strings.count.min(10_000) {
        let _ = dex.string(index);
    }
    for index in 0..dex.header.methods.count.min(10_000) {
        let _ = dex.method(index);
    }
    for index in 0..dex.header.fields.count.min(10_000) {
        let _ = dex.field(index);
    }
    for index in 0..dex.class_count().min(10_000) {
        let Ok(class) = dex.class_def(index) else { continue };
        let _ = dex.superclasses(&class);
        let Ok(data) = dex.class_data(&class, &mut budget) else { continue };
        for method in data.methods() {
            if let Ok(code) = dex.code_item(method.code_off) {
                let _ = disassemble(dex, &code.insns);
            }
        }
    }
}

#[test]
fn truncation_at_every_length_is_refused_or_survived() {
    let bytes = sample();
    for len in 0..bytes.len() {
        if let Ok(dex) = Dex::parse(bytes[..len].to_vec()) {
            exercise(&dex);
        }
    }
}

#[test]
fn huge_table_counts_are_refused_before_allocation() {
    for at in [0x38, 0x40, 0x48, 0x50, 0x58, 0x60] {
        let mut bytes = sample();
        put32(&mut bytes, at, 0xffff_fff0);
        assert!(Dex::parse(bytes.clone()).is_err(), "count at {at:#x}");
        put32(&mut bytes, at, 3);
        put32(&mut bytes, at + 4, 0xffff_fff0);
        assert!(Dex::parse(bytes).is_err(), "offset at {at:#x}");
    }
}

#[test]
fn a_declared_file_size_past_the_end_is_truncation() {
    let mut bytes = sample();
    let len = bytes.len() as u32;
    put32(&mut bytes, 0x20, len + 100);
    assert!(matches!(Dex::parse(bytes), Err(DexError::Malformed(text)) if text.contains("truncated")));
}

#[test]
fn overlapping_map_sections_are_reported() {
    let mut bytes = sample();
    // Point the header's type_ids at the string_ids table: both fit, but the map now overlaps.
    let map = u32_at(&bytes, 0x34) as usize;
    let count = u32_at(&bytes, map) as usize;
    let strings = u32_at(&bytes, 0x3c);
    for item in 0..count {
        let at = map + 4 + item * 12;
        if u16::from_le_bytes([bytes[at], bytes[at + 1]]) == 0x0002 {
            put32(&mut bytes, at + 8, strings);
        }
    }
    fix_checksums(&mut bytes);
    let dex = Dex::parse(bytes).unwrap();
    assert!(dex.warnings.iter().any(|warning| warning.contains("overlap")), "{:?}", dex.warnings);
    assert!(dex.warnings.iter().any(|warning| warning.contains("disagrees")), "{:?}", dex.warnings);
}

#[test]
fn class_data_with_lying_counts_and_leb_overflow_is_refused() {
    let bytes = sample();
    let dex = Dex::parse(bytes.clone()).unwrap();
    let class = dex.class_def(0).unwrap();
    let offset = class.class_data_off as usize;
    let mut lying = bytes.clone();
    lying[offset..offset + 5].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    let dex = Dex::parse(lying).unwrap();
    let mut budget = usize::MAX;
    assert!(dex.class_data(&dex.class_def(0).unwrap(), &mut budget).is_err());
    let mut overflow = bytes;
    overflow[offset..offset + 6].copy_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    let dex = Dex::parse(overflow).unwrap();
    assert!(dex.class_data(&dex.class_def(0).unwrap(), &mut budget).is_err());
}

#[test]
fn the_member_budget_stops_shared_class_data() {
    let mut bytes = sample();
    let dex = Dex::parse(bytes.clone()).unwrap();
    let shared = dex.class_def(0).unwrap().class_data_off;
    let classes = u32_at(&bytes, 0x64) as usize;
    put32(&mut bytes, classes + 32 + 24, shared);
    let dex = Dex::parse(bytes).unwrap();
    let mut budget = 10;
    assert!(dex.class_data(&dex.class_def(0).unwrap(), &mut budget).is_ok());
    assert!(matches!(dex.class_data(&dex.class_def(1).unwrap(), &mut budget), Err(DexError::Limit(_))));
}

#[test]
fn cyclic_superclasses_end_the_walk() {
    // A extends B, B extends A.
    let classes = vec![ClassSpec::new("LA;", "LB;"), ClassSpec::new("LB;", "LA;")];
    let dex = Dex::parse(write_dex(&classes, 35)).unwrap();
    for index in 0..2 {
        let chain = dex.superclasses(&dex.class_def(index).unwrap());
        assert_eq!(chain.len(), 1, "{chain:?}");
    }
    let looped = vec![ClassSpec::new("LA;", "LA;")];
    let dex = Dex::parse(write_dex(&looped, 35)).unwrap();
    assert!(dex.superclasses(&dex.class_def(0).unwrap()).is_empty());
}

#[test]
fn malformed_mutf8_is_flagged_and_unterminated_strings_refused() {
    let mut bytes = sample();
    let first = u32_at(&bytes, u32_at(&bytes, 0x3c) as usize) as usize;
    // The first string's length prefix is one byte; damage its first character.
    bytes[first + 1] = 0xff;
    let dex = Dex::parse(bytes.clone()).unwrap();
    assert!(dex.string(0).unwrap().malformed);
    // A string longer than the cap has no terminator within it.
    let limits = rampage_dex::Limits { max_string_bytes: 4, ..Default::default() };
    let dex = Dex::parse_with(sample(), limits).unwrap();
    let long = (0..dex.header.strings.count).find(|&index| Dex::parse(sample()).unwrap().string_text(index).len() > 4);
    assert!(dex.string(long.unwrap()).is_err());
}

#[test]
fn code_items_with_lying_sizes_are_refused() {
    let bytes = sample();
    let dex = Dex::parse(bytes.clone()).unwrap();
    let mut budget = usize::MAX;
    let data = dex.class_data(&dex.class_def(0).unwrap(), &mut budget).unwrap();
    let code = data.methods().find(|method| method.code_off != 0).unwrap().code_off as usize;
    let mut huge = bytes.clone();
    put32(&mut huge, code + 12, 0x7fff_ffff);
    assert!(Dex::parse(huge).unwrap().code_item(code as u32).is_err());
    let mut past = bytes.clone();
    put32(&mut past, code + 12, 0x0010_0000);
    assert!(Dex::parse(past).unwrap().code_item(code as u32).is_err());
    let mut tries = bytes;
    tries[code + 6..code + 8].copy_from_slice(&0xffffu16.to_le_bytes());
    assert!(Dex::parse(tries).unwrap().code_item(code as u32).is_err());
}

#[test]
fn random_damage_never_panics() {
    let bytes = sample();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..3000 {
        let mut damaged = bytes.clone();
        for _ in 0..1 + next() % 8 {
            let at = (next() as usize) % damaged.len();
            damaged[at] = next() as u8;
        }
        if let Ok(dex) = Dex::parse(damaged) {
            exercise(&dex);
        }
    }
}
