use rampage_loaders::{Binary, Format, MAX_RAW_BYTES, MAX_RAW_SEEDS, RawCodeOptions, RawProfile};

fn options() -> RawCodeOptions {
    RawCodeOptions { profile: RawProfile::Msp430, base: 0x1000, entry: None, seeds: vec![] }
}

fn identity(bytes: Vec<u8>, options: RawCodeOptions) -> String {
    Binary::from_raw_code(bytes, options).unwrap().raw_interpretation_identity().unwrap().unwrap().sha256
}

#[test]
fn exact_owned_bytes_have_no_native_or_capture_wrapper_and_no_inferred_starts() {
    let bytes = vec![0x30, 0x41, 0xff];
    let binary = Binary::from_raw_code(bytes.clone(), options()).unwrap();
    assert_eq!(binary.format, Format::Raw);
    assert_eq!(binary.file_bytes(), bytes);
    assert_eq!(binary.image_bytes(), bytes);
    assert_eq!(binary.read(0x1000, 3), Some(bytes.as_slice()));
    assert_eq!(binary.code_from(0x1000), Some(bytes.as_slice()));
    assert!(binary.read(0x1003, 1).is_none());
    assert!(binary.read(0x0fff, 1).is_none());
    assert!(binary.entry.is_none());
    assert!(binary.function_starts.is_empty());
    assert!(binary.symbols.is_empty());
    assert!(binary.snapshot_target.is_none());
    assert!(binary.snapshot_modules.is_empty());
    assert!(binary.provenance.is_none());
    assert!(binary.backing_path().is_none());
    assert!(!binary.validate_available_backing_source().unwrap());
    assert!(binary.validate_backing_source().is_err());
}

#[test]
fn every_interpretation_component_changes_the_domain_separated_identity() {
    let bytes = vec![0; 4];
    let baseline = identity(bytes.clone(), options());
    assert_ne!(baseline, identity(vec![1, 0, 0, 0], options()));
    let mut changed = options();
    changed.profile = RawProfile::Avr8;
    assert_ne!(baseline, identity(bytes.clone(), changed));
    let mut changed = options();
    changed.profile = RawProfile::Mos6502;
    assert_ne!(baseline, identity(bytes.clone(), changed));
    let mut changed = options();
    changed.base = 0x2000;
    assert_ne!(baseline, identity(bytes.clone(), changed));
    let mut changed = options();
    changed.entry = Some(0x1000);
    assert_ne!(baseline, identity(bytes.clone(), changed));
    let mut changed = options();
    changed.seeds = vec![0x1000];
    assert_ne!(baseline, identity(bytes.clone(), changed));
    assert_ne!(baseline, identity(vec![0; 3], options()));
    assert_eq!(baseline, identity(bytes, options()));
}

#[test]
fn seed_canonicalization_drives_both_discovery_input_and_identity_without_merging_entry() {
    let mut input = options();
    input.seeds = vec![0x1002, 0x1000, 0x1002];
    let binary = Binary::from_raw_code(vec![0; 4], input).unwrap();
    assert_eq!(binary.function_starts, [0x1000, 0x1002]);
    let mut canonical = options();
    canonical.seeds = vec![0x1000, 0x1002];
    assert_eq!(binary.raw_interpretation_identity().unwrap().unwrap().sha256, identity(vec![0; 4], canonical));
    let mut entry_only = options();
    entry_only.entry = Some(0x1000);
    let binary = Binary::from_raw_code(vec![0; 4], entry_only.clone()).unwrap();
    assert!(binary.function_starts.is_empty());
    let mut seed_only = options();
    seed_only.seeds = vec![0x1000];
    assert_ne!(identity(vec![0; 4], entry_only), identity(vec![0; 4], seed_only));
}

#[test]
fn admission_refuses_empty_oversize_overflow_misalignment_and_unbacked_starts() {
    assert!(Binary::from_raw_code(vec![], options()).is_err());
    assert!(Binary::from_raw_code(vec![0; MAX_RAW_BYTES + 1], options()).is_err());
    let mut input = options();
    input.seeds = vec![0x1000; MAX_RAW_SEEDS + 1];
    assert!(Binary::from_raw_code(vec![0; 4], input).is_err());
    for base in [0x1001, u64::MAX - 1, u64::MAX] {
        let mut input = options();
        input.base = base;
        assert!(Binary::from_raw_code(vec![0; 4], input).is_err());
    }
    for bad_start in [0x0ffe, 0x1001, 0x1004, u64::MAX] {
        let mut input = options();
        input.entry = Some(bad_start);
        assert!(Binary::from_raw_code(vec![0; 4], input).is_err());
        let mut input = options();
        input.seeds = vec![bad_start];
        assert!(Binary::from_raw_code(vec![0; 4], input).is_err());
    }
}

#[test]
fn profile_highest_bytes_are_byte_scaled_and_inclusive() {
    for (profile, base) in [(RawProfile::Msp430, 0xfffe), (RawProfile::Avr8, 0x1fffe), (RawProfile::Mos6502, 0xfffe)] {
        let input = RawCodeOptions { profile, base, entry: Some(base), seeds: vec![base] };
        let binary = Binary::from_raw_code(vec![0; 2], input.clone()).unwrap();
        assert_eq!(binary.read(base + 1, 1), Some([0].as_slice()));
        assert!(Binary::from_raw_code(vec![0; 3], input).is_err());
    }
    let input = RawCodeOptions { profile: RawProfile::Mos6502, base: 0xffff, entry: Some(0xffff), seeds: vec![] };
    assert!(Binary::from_raw_code(vec![0x60], input).is_ok());
}

#[test]
fn only_exact_pilot_languages_are_admitted() {
    for language in [
        "avr8:LE:16:extended",
        "TI_MSP430X:LE:32:default",
        "65C02:LE:16:default",
        "avr8:LE:16:default:gcc",
        "6502",
        "../../profile.sla",
    ] {
        assert!(RawProfile::from_language_id(language).is_err());
    }
    let profile = RawProfile::from_language_id("avr8:LE:16:default").unwrap();
    let input = RawCodeOptions { profile, base: 0x10000, entry: None, seeds: vec![] };
    assert!(Binary::from_raw_code(vec![0x08, 0x95], input.clone()).is_ok());
    let mut unaligned = input;
    unaligned.base += 1;
    assert!(Binary::from_raw_code(vec![0x08, 0x95], unaligned).is_err());
    let full = RawCodeOptions { profile, base: 0, entry: None, seeds: vec![] };
    assert!(Binary::from_raw_code(vec![0; MAX_RAW_BYTES], full).is_ok());
}

#[test]
fn changing_public_mapping_entry_or_seeds_cannot_return_a_stale_admission_identity() {
    let mut binary = Binary::from_raw_code(vec![0; 4], options()).unwrap();
    binary.entry = Some(0x1000);
    assert!(binary.raw_interpretation_identity().is_err());
    let mut binary = Binary::from_raw_code(vec![0; 4], options()).unwrap();
    binary.segments[0].address += 2;
    assert!(binary.raw_interpretation_identity().is_err());
    let mut binary = Binary::from_raw_code(vec![0; 4], options()).unwrap();
    binary.function_starts.push(0x1000);
    assert!(binary.raw_interpretation_identity().is_err());
    let mut binary = Binary::from_raw_code(vec![0; 4], options()).unwrap();
    binary.format = Format::Snapshot;
    assert!(binary.raw_interpretation_identity().is_err());
}
