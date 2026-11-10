use rampage_loaders::raw_pointers::{EntryStatus, Evidence, TableRefusedReason, TableStatus};
use rampage_loaders::raw_vectors::{RefusedReason, StopReason, VectorStatus};
use rampage_loaders::{Binary, Format, MAX_RAW_BYTES, MAX_RAW_NATIVE_BYTES, MAX_RAW_SEEDS, RawCodeOptions, RawProfile};

fn options() -> RawCodeOptions {
    RawCodeOptions {
        profile: RawProfile::Msp430,
        base: 0x1000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    }
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
        let input = RawCodeOptions {
            profile,
            base,
            entry: Some(base),
            seeds: vec![base],
            vector_table: None,
            pointer_tables: false,
        };
        let binary = Binary::from_raw_code(vec![0; 2], input.clone()).unwrap();
        assert_eq!(binary.read(base + 1, 1), Some([0].as_slice()));
        assert!(Binary::from_raw_code(vec![0; 3], input).is_err());
    }
    let input = RawCodeOptions {
        profile: RawProfile::Mos6502,
        base: 0xffff,
        entry: Some(0xffff),
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    assert!(Binary::from_raw_code(vec![0x60], input).is_ok());
}

#[test]
fn only_exact_roster_languages_are_admitted() {
    for profile in RawProfile::ALL {
        assert_eq!(RawProfile::from_language_id(profile.language_id()).unwrap(), profile);
    }
    for language in [
        "avr8:LE:16:extended",
        "TI_MSP430X:LE:32:default",
        "65C02:LE:16:default",
        "avr8:LE:16:default:gcc",
        "6502",
        "../../profile.sla",
        "SuperH:BE:32:SH-4",
        "8051:LE:16:default",
        "Hexagon:LE:32:default:default",
        "x86:LE:64:default",
        "AARCH64:BE:64:v8A",
    ] {
        assert!(RawProfile::from_language_id(language).is_err(), "{language}");
    }
    let profile = RawProfile::from_language_id("avr8:LE:16:default").unwrap();
    let input = RawCodeOptions {
        profile,
        base: 0x10000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    assert!(Binary::from_raw_code(vec![0x08, 0x95], input.clone()).is_ok());
    let mut unaligned = input;
    unaligned.base += 1;
    assert!(Binary::from_raw_code(vec![0x08, 0x95], unaligned).is_err());
    let full =
        RawCodeOptions { profile, base: 0, entry: None, seeds: vec![], vector_table: None, pointer_tables: false };
    assert!(Binary::from_raw_code(vec![0; MAX_RAW_BYTES], full).is_ok());
}

#[test]
fn every_profile_admits_its_inclusive_highest_byte_and_alignment() {
    for profile in RawProfile::ALL {
        let space = profile.code_space();
        let alignment = u64::from(space.instruction_alignment);
        let length = alignment.max(2);
        let base = space.highest_byte - (length - 1);
        let input = RawCodeOptions {
            profile,
            base,
            entry: Some(base),
            seeds: vec![base],
            vector_table: None,
            pointer_tables: false,
        };
        if space.highest_byte == u64::MAX {
            // The exclusive end must still be representable, so the 64-bit top byte is never backed.
            assert!(Binary::from_raw_code(vec![0; length as usize], input).is_err(), "{profile:?}");
            let base = base - alignment;
            let input = RawCodeOptions {
                profile,
                base,
                entry: Some(base),
                seeds: vec![base],
                vector_table: None,
                pointer_tables: false,
            };
            assert!(Binary::from_raw_code(vec![0; length as usize], input).is_ok(), "{profile:?}");
            continue;
        }
        let binary = Binary::from_raw_code(vec![0; length as usize], input.clone()).unwrap();
        assert_eq!(binary.arch, profile.arch());
        assert_eq!(binary.big_endian, profile.big_endian());
        assert!(Binary::from_raw_code(vec![0; length as usize + 1], input).is_err(), "{profile:?}");
        if alignment > 1 {
            let input = RawCodeOptions {
                profile,
                base: 0x1000 + 1,
                entry: None,
                seeds: vec![],
                vector_table: None,
                pointer_tables: false,
            };
            assert!(Binary::from_raw_code(vec![0; 4], input).is_err(), "{profile:?}");
        }
    }
}

#[test]
fn identities_separate_every_profile_and_include_byte_order() {
    let identities: std::collections::BTreeSet<_> = RawProfile::ALL
        .into_iter()
        .map(|profile| {
            identity(
                vec![0; 4],
                RawCodeOptions {
                    profile,
                    base: 0x1000,
                    entry: None,
                    seeds: vec![],
                    vector_table: None,
                    pointer_tables: false,
                },
            )
        })
        .collect();
    assert_eq!(identities.len(), RawProfile::ALL.len());
    assert!(RawProfile::ALL.into_iter().any(RawProfile::big_endian));
    assert!(RawProfile::ALL.into_iter().any(|profile| !profile.big_endian()));
    for profile in RawProfile::ALL {
        let input = RawCodeOptions {
            profile,
            base: 0x1000,
            entry: None,
            seeds: vec![],
            vector_table: None,
            pointer_tables: false,
        };
        let binary = Binary::from_raw_code(vec![0; 4], input.clone()).unwrap();
        assert_eq!(binary.big_endian, profile.big_endian());
        assert!(binary.raw_interpretation_identity().unwrap().is_some());
        let mut data = Binary::from_raw_code(vec![0; 4], input.clone()).unwrap();
        data.big_endian = !profile.big_endian();
        assert!(data.raw_interpretation_identity().is_err(), "{profile:?}");
        let mut code = Binary::from_raw_code(vec![0; 4], input).unwrap();
        code.arch = rampage_arch::Arch::X86;
        assert!(code.raw_interpretation_identity().is_err(), "{profile:?}");
    }
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

const CORTEX_M: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m.bin");
const CORTEX_M_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m.elf");

fn cortex(base: u64, vector_table: Option<u64>) -> RawCodeOptions {
    RawCodeOptions {
        profile: RawProfile::CortexM,
        base,
        entry: None,
        seeds: vec![],
        vector_table,
        pointer_tables: false,
    }
}

#[test]
fn cortex_m_is_native_thumb_with_a_4_mib_cap() {
    let profile = RawProfile::from_language_id("ARM:LE:32:Cortex").unwrap();
    assert_eq!(profile, RawProfile::CortexM);
    assert!(profile.native_decoder() && !profile.big_endian());
    assert_eq!(profile.arch(), rampage_arch::Arch::Arm);
    assert_eq!(profile.max_bytes(), MAX_RAW_NATIVE_BYTES);
    let binary = Binary::from_raw_code(vec![0; MAX_RAW_NATIVE_BYTES], cortex(0x0800_0000, None)).unwrap();
    assert_eq!(binary.thumb.len(), 1);
    assert_eq!(binary.thumb[0], 0x0800_0000..0x0840_0000);
    assert!(binary.target().is_thumb(0x0800_0000) && binary.target().is_thumb(0x083f_fffe));
    assert!(binary.raw_interpretation_identity().unwrap().is_some());
    assert!(Binary::from_raw_code(vec![0; MAX_RAW_NATIVE_BYTES + 1], cortex(0, None)).is_err());
    // Sleigh-decoded profiles keep the 128 KiB cap.
    let msp430 = RawCodeOptions { profile: RawProfile::Msp430, ..options() };
    assert!(Binary::from_raw_code(vec![0; MAX_RAW_BYTES + 1], msp430).is_err());
    // Editing the Thumb ranges is interpretation drift.
    let mut edited = Binary::from_raw_code(vec![0; 8], cortex(0x1000, None)).unwrap();
    edited.thumb.clear();
    assert!(edited.raw_interpretation_identity().is_err());
}

#[test]
fn cortex_m_thumb_pointers_name_their_even_instruction() {
    let mut input = cortex(0x1000, None);
    input.entry = Some(0x1003);
    input.seeds = vec![0x1005, 0x1004];
    let binary = Binary::from_raw_code(vec![0; 8], input).unwrap();
    assert_eq!(binary.entry, Some(0x1002));
    assert_eq!(binary.function_starts, [0x1004]);
    let mut outside = cortex(0x1000, None);
    outside.seeds = vec![0x1009];
    assert!(Binary::from_raw_code(vec![0; 8], outside).is_err());
}

/// The fixture's vector table seeds the entry and every handler; the ELF's symbols are the truth.
#[test]
fn cortex_m_vector_table_seeds_entry_and_handlers_from_the_fixture() {
    let binary = Binary::from_raw_code(CORTEX_M.to_vec(), cortex(0x0800_0000, Some(0x0800_0000))).unwrap();
    let truth = Binary::open(std::path::Path::new(CORTEX_M_ELF)).unwrap();
    let symbol = |name: &str| truth.symbol_by_name(name).unwrap().address & !1;
    assert_eq!(binary.entry, Some(symbol("reset_handler")));
    let mut handlers: Vec<u64> =
        ["default_handler", "hardfault_handler", "systick_handler", "timer_irq_handler", "uart_irq_handler"]
            .into_iter()
            .map(symbol)
            .collect();
    handlers.sort_unstable();
    assert_eq!(binary.function_starts, handlers);
    let table = binary.raw_code_image().unwrap().vector_table().unwrap();
    assert_eq!(table.words_read, 24);
    assert_eq!(table.vectors[0].status, VectorStatus::StackPointer);
    assert_eq!(table.vectors[0].word, 0x2000_5000);
    assert_eq!(table.vectors[1].name, "Reset");
    let irq3 = table.vectors.iter().find(|vector| vector.name == "IRQ3").unwrap();
    assert_eq!(irq3.target, Some(symbol("uart_irq_handler")));
    assert_eq!(table.empty_external_vectors, 3);
    // uart_putc's first instructions follow the table: an even word that is not a handler ends it.
    assert_eq!(table.stop_reason, StopReason::NonHandlerWord);
    assert!(table.stop_detail.contains("0x466fb580 at slot 0x8000060"), "{}", table.stop_detail);
    assert!(table.base_address_suggestion.is_none());
    // An explicit entry wins; Reset becomes a seed.
    let mut explicit = cortex(0x0800_0000, Some(0x0800_0000));
    explicit.entry = Some(symbol("uart_puts"));
    let binary = Binary::from_raw_code(CORTEX_M.to_vec(), explicit).unwrap();
    assert_eq!(binary.entry, Some(symbol("uart_puts")));
    assert!(binary.function_starts.contains(&symbol("reset_handler")));
}

#[test]
fn cortex_m_vector_table_with_a_wrong_base_seeds_nothing_and_suggests_one() {
    let binary = Binary::from_raw_code(CORTEX_M.to_vec(), cortex(0, Some(0))).unwrap();
    assert_eq!(binary.entry, None);
    assert!(binary.function_starts.is_empty());
    let table = binary.raw_code_image().unwrap().vector_table().unwrap();
    let refused: Vec<_> = table.vectors.iter().filter(|vector| vector.status == VectorStatus::Refused).collect();
    assert_eq!(refused.len(), 10, "{table:?}");
    assert!(refused.iter().all(|vector| vector.refused_reason == Some(RefusedReason::OutsideImage)));
    let suggestion = table.base_address_suggestion.as_ref().unwrap();
    assert_eq!(suggestion.base_address, 0x0800_0000);
    assert!(suggestion.note.contains("not applied"));
    // The project keeps the asserted base.
    assert_eq!(binary.segments[0].address, 0);
}

#[test]
fn vector_tables_refuse_other_profiles_bad_places_and_change_the_identity() {
    let msp430 = RawCodeOptions { vector_table: Some(0x1000), ..options() };
    let error = Binary::from_raw_code(vec![0; 64], msp430).unwrap_err().to_string();
    assert!(error.contains("only for ARM:LE:32:Cortex"), "{error}");
    for address in [0x0800_0002, 0x07ff_fffc, 0x0800_0320, 0x0800_031c] {
        assert!(Binary::from_raw_code(CORTEX_M.to_vec(), cortex(0x0800_0000, Some(address))).is_err(), "{address:#x}");
    }
    let plain = identity(CORTEX_M.to_vec(), cortex(0x0800_0000, None));
    let seeded = identity(CORTEX_M.to_vec(), cortex(0x0800_0000, Some(0x0800_0000)));
    assert_ne!(plain, seeded);
    // The same entry and seeds supplied by hand are still a different interpretation from the table request.
    let table = Binary::from_raw_code(CORTEX_M.to_vec(), cortex(0x0800_0000, Some(0x0800_0000))).unwrap();
    let mut manual = cortex(0x0800_0000, None);
    manual.entry = table.entry;
    manual.seeds = table.function_starts.clone();
    assert_ne!(identity(CORTEX_M.to_vec(), manual), seeded);
}

const TABLES: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-tables.bin");
const TABLES_ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-tables.elf");

fn tables(pointer_tables: bool) -> RawCodeOptions {
    RawCodeOptions { pointer_tables, ..cortex(0x0800_0000, Some(0x0800_0000)) }
}

/// The tables fixture's command, state and callback tables seed their handlers; the switch jump table, the string
/// pointers and the odd constants seed nothing. The ELF's symbols are the truth.
#[test]
fn cortex_m_pointer_tables_seed_handlers_and_refuse_decoys() {
    let truth = Binary::open(std::path::Path::new(TABLES_ELF)).unwrap();
    let symbol = |name: &str| truth.symbol_by_name(name).unwrap().address & !1;
    let binary = Binary::from_raw_code(TABLES.to_vec(), tables(true)).unwrap();
    let found = binary.raw_code_image().unwrap().pointer_tables().unwrap();
    let accepted: Vec<(u64, u8)> = found
        .tables
        .iter()
        .filter(|table| table.status == TableStatus::Accepted)
        .map(|table| (table.address, table.stride))
        .collect();
    // COMMANDS' handlers at stride 8; its last handler sits right before CALLBACKS and STATES, which are adjacent,
    // so those form one plain array of nine slots.
    let reboot = symbol("COMMANDS") + 28;
    assert_eq!(reboot + 4, symbol("CALLBACKS"));
    assert_eq!(accepted, [(symbol("COMMANDS") + 4, 8), (reboot, 4)], "{found:#?}");
    let handlers = [
        "cmd_help",
        "cmd_status",
        "cmd_version",
        "cmd_reboot",
        "on_tick",
        "on_rx",
        "on_tx",
        "state_idle",
        "state_run",
        "state_stop",
        "state_fault",
    ];
    for name in handlers {
        assert!(binary.function_starts.contains(&symbol(name)), "{name}");
    }
    assert_eq!(found.seeds, handlers.len());
    // The case-label table inside reset_handler is found and refused.
    let switch = found.tables.iter().find(|table| table.status == TableStatus::Refused).unwrap();
    assert_eq!(switch.refused_reason, Some(TableRefusedReason::NoStrongEvidence));
    assert!((symbol("reset_handler")..symbol("COMMANDS")).contains(&switch.address));
    // Every seed is a symbol: nothing from NAMES, MAGIC or the case labels.
    let starts: Vec<u64> = truth.symbols.iter().map(|symbol| symbol.address & !1).collect();
    for seed in &binary.function_starts {
        assert!(starts.contains(seed), "{seed:#x} is not a function");
    }
    // Case labels reach an exit but never open with a prologue; every accepted entry has a prologue here.
    assert!(switch.entries.iter().all(|entry| entry.evidence == [Evidence::ReachesExit]));
    let entries = || found.tables.iter().flat_map(|table| &table.entries);
    assert!(
        entries()
            .filter(|entry| entry.status == EntryStatus::Accepted)
            .all(|entry| entry.evidence.contains(&Evidence::PushLr))
    );
    // MAGIC's odd constants point inside run_command: refused for the same reason.
    let magic = found.tables.iter().find(|table| table.address == symbol("MAGIC")).unwrap();
    assert_eq!(magic.refused_reason, Some(TableRefusedReason::NoStrongEvidence));
    // Off by default, refused elsewhere, and part of the identity.
    let plain = Binary::from_raw_code(TABLES.to_vec(), tables(false)).unwrap();
    assert!(plain.raw_code_image().unwrap().pointer_tables().is_none());
    assert!(!plain.function_starts.contains(&symbol("cmd_help")));
    assert_ne!(identity(TABLES.to_vec(), tables(true)), identity(TABLES.to_vec(), tables(false)));
    let msp430 = RawCodeOptions { pointer_tables: true, ..options() };
    let error = Binary::from_raw_code(vec![0; 64], msp430).unwrap_err().to_string();
    assert!(error.contains("pointer-table seeding is defined only for ARM:LE:32:Cortex"), "{error}");
}
