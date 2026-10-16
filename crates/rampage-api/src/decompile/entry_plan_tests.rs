use super::*;
use crate::annotations::Field;
use rampage_loaders::{Export, ImportSlot, Symbol};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct SnapshotFile(PathBuf);

impl Drop for SnapshotFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn snapshot(input: serde_json::Value) -> Binary {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("rampage-entry-plan-{}-{sequence}.json", std::process::id()));
    let mut writer = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    let file = SnapshotFile(path);
    writer.write_all(&serde_json::to_vec(&input).unwrap()).unwrap();
    drop(writer);
    Binary::open(&file.0).unwrap()
}

fn region(name: &str, address: u64, permissions: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "address": format!("{address:#x}"),
        "permissions": permissions,
        "bytes": rampage_arch::hex::bytes(bytes),
    })
}

fn input(arch: &str, regions: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "format": "rampage-snapshot-v1",
        "arch": arch,
        "provenance": "entry planner synthetic owned input",
        "regions": regions,
    })
}

fn code_binary(bytes: &[u8]) -> Binary {
    snapshot(input("x86_64", vec![region(".text", 0x1000, "r-x", bytes), region(".data", 0x8000, "rw-", &[0; 16])]))
}

fn function(binary: &mut Binary, address: u64, size: u64, name: &str) {
    binary.symbols.push(Symbol { name: name.to_owned(), address, size, kind: SymbolKind::Function });
}

fn request(address: u64, validation: EntryValidation) -> DecompileEntryRequest {
    DecompileEntryRequest { address, validation }
}

fn plan(project: &Project, annotations: &Annotations, address: u64) -> Result<EntryPlan, ApiError> {
    prepare(project, annotations, &request(address, EntryValidation::MetadataBacked), &|_| Ok(()))
}

fn has_symbol(plan: &EntryPlan, expected: u64) -> bool {
    plan.operations
        .iter()
        .any(|operation| matches!(operation, WorkerOperation::Symbol { address, .. } if *address == expected))
}

fn has_runtime(plan: &EntryPlan, expected: u64, raw: &str) -> bool {
    plan.operations.iter().any(|operation| {
        matches!(operation, WorkerOperation::RuntimePrototype { address, name, .. }
            if *address == expected && name == raw)
    })
}

fn has_noreturn(plan: &EntryPlan, expected: u64) -> bool {
    plan.operations
        .iter()
        .any(|operation| matches!(operation, WorkerOperation::NoReturn { address, .. } if *address == expected))
}

#[test]
fn numeric_default_and_analyst_labels_do_not_supply_entry_metadata() {
    let project = Project::new(code_binary(&[0x90, 0xc3]));
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Name, 0x1001, Some("analyst_label".to_owned())).unwrap();
    for text in ["4097", "0x1001", "sub_1001", "analyst_label"] {
        let address = project.resolve_in(&annotations, text).unwrap();
        assert_eq!(address, 0x1001);
        assert!(plan(&project, &annotations, address).is_err(), "{text}");
    }
    let selected =
        prepare(&project, &annotations, &request(0x1001, EntryValidation::AnalystAsserted), &|_| Ok(())).unwrap();
    assert_eq!(selected.address, 0x1001);
    assert_eq!(selected.name, "analyst_label");
    assert_eq!(selected.origins, [EntryOrigin::AnalystAssertion]);
    assert!(!has_runtime(&selected, 0x1001, "analyst_label"));
}

#[test]
fn each_independent_origin_is_exact_and_analyst_policy_preserves_metadata() {
    for expected in
        [EntryOrigin::FunctionSymbol, EntryOrigin::Export, EntryOrigin::FormatFunctionStart, EntryOrigin::ImageEntry]
    {
        let mut binary = code_binary(&[0x90, 0xc3]);
        match expected {
            EntryOrigin::FunctionSymbol => function(&mut binary, 0x1000, 2, "selected"),
            EntryOrigin::Export => binary.exports.push(Export { name: "selected".to_owned(), address: 0x1000 }),
            EntryOrigin::FormatFunctionStart => binary.function_starts.push(0x1000),
            EntryOrigin::ImageEntry => binary.entry = Some(0x1000),
            EntryOrigin::AnalystAssertion => unreachable!(),
        }
        let project = Project::new(binary);
        let annotations = Annotations::in_memory();
        let selected = plan(&project, &annotations, 0x1000).unwrap();
        assert_eq!(selected.origins, [expected]);
        assert!(plan(&project, &annotations, 0x1001).is_err());
        let selected =
            prepare(&project, &annotations, &request(0x1000, EntryValidation::AnalystAsserted), &|_| Ok(())).unwrap();
        assert_eq!(selected.origins, [expected, EntryOrigin::AnalystAssertion]);
    }
}

#[test]
fn interior_assertions_never_inherit_the_enclosing_name_or_runtime_identity() {
    let mut binary = code_binary(&[0x90, 0xc3]);
    function(&mut binary, 0x1000, 2, "abort");
    let project = Project::new(binary);
    let annotations = Annotations::in_memory();
    assert!(plan(&project, &annotations, 0x1001).is_err());
    let selected =
        prepare(&project, &annotations, &request(0x1001, EntryValidation::AnalystAsserted), &|_| Ok(())).unwrap();
    assert!(selected.inside_symbol_extent);
    assert_eq!(selected.address, 0x1001);
    assert_eq!(selected.name, "sub_1001");
    assert!(!has_symbol(&selected, 0x1000));
    assert!(!has_runtime(&selected, 0x1001, "abort"));
    assert!(!has_noreturn(&selected, 0x1001));
    assert!(!selected.omissions.is_empty());

    let mut binary = code_binary(&[0x90, 0xc3]);
    function(&mut binary, 0x1000, 2, "outer");
    binary.function_starts.push(0x1001);
    let selected = plan(&Project::new(binary), &annotations, 0x1001).unwrap();
    assert!(selected.inside_symbol_extent);
    assert_eq!(selected.origins, [EntryOrigin::FormatFunctionStart]);
}

#[test]
fn data_symbols_and_other_named_code_are_not_function_evidence() {
    for kind in [SymbolKind::Data, SymbolKind::Other] {
        let mut binary = code_binary(&[0x90, 0xc3]);
        binary.symbols.push(Symbol { name: "exit".to_owned(), address: 0x1000, size: 2, kind });
        let project = Project::new(binary);
        let annotations = Annotations::in_memory();
        assert!(plan(&project, &annotations, 0x1000).is_err());
        let asserted = prepare(&project, &annotations, &request(0x1000, EntryValidation::AnalystAsserted), &|_| Ok(()));
        if kind == SymbolKind::Data {
            assert!(asserted.is_err());
            assert!(
                prepare(&project, &annotations, &request(0x1001, EntryValidation::AnalystAsserted), &|_| Ok(()),)
                    .is_err()
            );
        } else {
            let asserted = asserted.unwrap();
            assert_eq!(asserted.name, "exit");
            assert!(!has_runtime(&asserted, 0x1000, "exit"));
            assert!(!has_noreturn(&asserted, 0x1000));
        }
    }
}

#[test]
fn data_extents_exclude_selected_entries_referenced_callees_and_actual_signature_addresses() {
    for evidence in ["function", "export", "format_start", "image_entry"] {
        let mut binary = snapshot(input(
            "x86_64",
            vec![
                region("caller", 0x1000, "r-x", &[0xe8, 3, 1, 0, 0, 0xe8, 0xf6, 1, 0, 0, 0xc3]),
                region("data_in_code", 0x1100, "r-x", &[0xc3; 33]),
                region("continuation", 0x1200, "r-x", &[0xc3]),
            ],
        ));
        function(&mut binary, 0x1000, 11, "caller");
        function(&mut binary, 0x1120, 1, "after_data");
        function(&mut binary, 0x1200, 1, "continuation");
        binary.symbols.extend([
            Symbol { address: 0x1100, name: "literal_data".to_owned(), size: 32, kind: SymbolKind::Data },
            Symbol { address: 0x1104, name: "short_inner_data".to_owned(), size: 1, kind: SymbolKind::Data },
            Symbol { address: 0x1107, name: "wild_label".to_owned(), size: u64::MAX, kind: SymbolKind::Other },
        ]);
        match evidence {
            "function" => function(&mut binary, 0x1108, 1, "abort"),
            "export" => binary.exports.push(Export { address: 0x1108, name: "abort".to_owned() }),
            "format_start" => binary.function_starts.push(0x1108),
            "image_entry" => binary.entry = Some(0x1108),
            _ => unreachable!(),
        }
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        let selected = plan(&project, &annotations, 0x1000).unwrap();
        assert!(!has_symbol(&selected, 0x1108), "{evidence}");
        assert!(!has_runtime(&selected, 0x1108, "abort"), "{evidence}");
        assert!(!has_noreturn(&selected, 0x1108), "{evidence}");
        assert!(has_symbol(&selected, 0x1200), "{evidence}");
        assert!(plan(&project, &annotations, 0x1120).is_ok(), "{evidence}");
        for validation in [EntryValidation::MetadataBacked, EntryValidation::AnalystAsserted] {
            assert!(prepare(&project, &annotations, &request(0x1108, validation), &|_| Ok(())).is_err());
        }
        for address in [0x1108, 0x1109] {
            annotations.set(Field::Signature, address, Some("void exact(void);".to_owned())).unwrap();
            assert!(plan(&project, &annotations, 0x1000).is_err(), "{evidence}: {address:#x}");
            annotations.set(Field::Signature, address, None).unwrap();
        }
    }
}

#[test]
fn zero_sized_data_is_exact_and_data_extent_overflow_is_not_allowed_to_wrap() {
    let mut binary = code_binary(&[0xc3, 0xc3]);
    function(&mut binary, 0x1000, 1, "selected");
    function(&mut binary, 0x1001, 1, "next");
    binary.symbols.extend([
        Symbol { address: 0x1000, name: "exact_data".to_owned(), size: 0, kind: SymbolKind::Data },
        Symbol { address: u64::MAX, name: "last_byte".to_owned(), size: 0, kind: SymbolKind::Data },
    ]);
    let project = Project::new(binary);
    assert!(plan(&project, &Annotations::in_memory(), 0x1000).is_err());
    assert!(plan(&project, &Annotations::in_memory(), 0x1001).is_ok());

    let mut binary = code_binary(&[0xc3]);
    function(&mut binary, 0x1000, 1, "selected");
    binary.symbols.push(Symbol {
        address: u64::MAX - 2,
        name: "overflowing_data".to_owned(),
        size: 8,
        kind: SymbolKind::Data,
    });
    assert!(plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).is_err());
}

#[test]
fn mapped_data_gaps_nonexecutable_code_import_slots_and_unavailable_tails_are_refused() {
    for address in [0x2000, 0x8000] {
        let mut binary = code_binary(&[0xc3]);
        binary.function_starts.push(address);
        let project = Project::new(binary);
        assert!(plan(&project, &Annotations::in_memory(), address).is_err());
        assert!(
            prepare(&project, &Annotations::in_memory(), &request(address, EntryValidation::AnalystAsserted), &|_| Ok(
                ()
            ),)
            .is_err()
        );
    }
    for variant in ["no_execute", "slot", "unavailable_tail", "data_in_execute_segment"] {
        let mut binary = code_binary(&[0xc3]);
        binary.function_starts.push(0x1000);
        let address = if variant == "data_in_execute_segment" { 0x8000 } else { 0x1000 };
        match variant {
            "no_execute" => binary.segments[0].perms.execute = false,
            "slot" => {
                binary.import_slots.push(ImportSlot { address, name: "exit".to_owned(), library: None });
            }
            "unavailable_tail" => binary.segments[0].file_size = 0,
            "data_in_execute_segment" => {
                binary.segments[1].perms.execute = true;
                binary.exports.push(Export { address, name: "not_code".to_owned() });
            }
            _ => unreachable!(),
        }
        assert!(plan(&Project::new(binary), &Annotations::in_memory(), address).is_err(), "{variant}");
    }
}

#[test]
fn target_width_alignment_endianness_and_unsupported_modes_are_not_guessed() {
    let high = 0x1_0000_0000;
    let mut binary = snapshot(input("x86", vec![region("code", high, "r-x", &[0xc3])]));
    binary.function_starts.push(high);
    assert!(plan(&Project::new(binary), &Annotations::in_memory(), high).is_err());

    for arch in ["arm", "mips", "powerpc"] {
        let mut binary = snapshot(input(arch, vec![region("code", 0x1000, "r-x", &[0; 8])]));
        binary.function_starts.push(0x1000);
        assert!(plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).is_err(), "{arch}");
    }
    let mut binary = snapshot(input(
        "aarch64",
        vec![region("code", 0x1000, "r-x", &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6])],
    ));
    binary.function_starts.extend([0x1000, 0x1001]);
    let project = Project::new(binary);
    assert!(plan(&project, &Annotations::in_memory(), 0x1000).is_ok());
    assert!(plan(&project, &Annotations::in_memory(), 0x1001).is_err());

    for field in ["big_endian", "data_big_endian"] {
        let mut source = input("aarch64", vec![region("code", 0x1000, "r-x", &[0xc0, 0x03, 0x5f, 0xd6])]);
        source[field] = true.into();
        let mut binary = snapshot(source);
        binary.function_starts.push(0x1000);
        assert!(plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).is_err(), "{field}");
    }
    let mut binary = snapshot(input("aarch64", vec![region("code", 0x1000, "r-x", &[0xc0, 0x03])]));
    binary.function_starts.push(0x1000);
    assert!(plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).is_err());
}

fn caller_binary(callee: &str) -> Binary {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xe8, 0xfb, 0, 0, 0, 0xe8, 0xf6, 1, 0, 0, 0xc3]),
            region("callee", 0x1100, "r-x", &[0xe8, 0xfb, 1, 0, 0, 0xc3]),
            region("after_call", 0x1200, "r-x", &[0xc3]),
            region("nested", 0x1300, "r-x", &[0xc3]),
        ],
    ));
    function(&mut binary, 0x1000, 11, "caller");
    function(&mut binary, 0x1100, 6, callee);
    function(&mut binary, 0x1200, 1, "after_call");
    function(&mut binary, 0x1300, 1, "nested");
    binary
}

#[test]
fn referenced_callees_are_registered_without_walking_their_bodies() {
    let selected = plan(&Project::new(caller_binary("callee")), &Annotations::in_memory(), 0x1000).unwrap();
    assert!(has_symbol(&selected, 0x1100));
    assert!(has_symbol(&selected, 0x1200));
    assert!(!has_symbol(&selected, 0x1300));
    assert_eq!(selected.counts.decoded_instructions, 3);
    assert_eq!(selected.counts.references, 2);
}

#[test]
fn display_renames_neither_remove_nor_invent_runtime_and_noreturn_identity() {
    for (raw, display, expected_noreturn) in [("abort", "safe_name", true), ("callee", "abort", false)] {
        let project = Project::new(caller_binary(raw));
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Name, 0x1100, Some(display.to_owned())).unwrap();
        let selected = plan(&project, &annotations, 0x1000).unwrap();
        assert!(has_runtime(&selected, 0x1100, raw));
        assert!(!has_runtime(&selected, 0x1100, display));
        assert_eq!(has_noreturn(&selected, 0x1100), expected_noreturn);
        assert_eq!(has_symbol(&selected, 0x1200), !expected_noreturn);
        assert!(selected.operations.iter().any(|operation| {
            matches!(operation, WorkerOperation::Symbol { address: 0x1100, name } if name == display)
        }));
    }
}

#[test]
fn unknown_indirect_transfers_stop_context_without_claiming_boundary_verification() {
    let mut binary = code_binary(&[0xff, 0xe0, 0xe8, 0xf9, 0, 0, 0, 0xc3]);
    function(&mut binary, 0x1000, 8, "caller");
    let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
    assert_eq!(selected.counts.decoded_instructions, 1);
    assert_eq!(selected.counts.references, 0);
    assert!(!selected.omissions.is_empty());
}

#[test]
fn conditional_local_paths_are_walked_but_metadata_tail_targets_are_not() {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0x74, 1, 0xc3, 0xe9, 0xf8, 0, 0, 0]),
            region("tail", 0x1100, "r-x", &[0xe8, 0xfb, 0, 0, 0, 0xc3]),
            region("nested", 0x1200, "r-x", &[0xc3]),
        ],
    ));
    function(&mut binary, 0x1000, 8, "caller");
    function(&mut binary, 0x1100, 6, "tail");
    function(&mut binary, 0x1200, 1, "nested");
    let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
    assert!(has_symbol(&selected, 0x1100));
    assert!(!has_symbol(&selected, 0x1200));
    assert_eq!(selected.counts.decoded_instructions, 3);
    assert!(!selected.omissions.is_empty());
}

#[test]
fn optional_decode_caps_are_visible_but_required_metadata_and_annotation_caps_refuse() {
    let mut binary = code_binary(&vec![0x90; MAX_INSTRUCTIONS + 2]);
    binary.function_starts.push(0x1000);
    let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
    assert!(selected.counts.context_budget_exhausted);
    assert!(selected.counts.decoded_instructions <= MAX_INSTRUCTIONS);
    assert!(selected.counts.decoded_bytes <= MAX_BYTES);
    assert!(!selected.omissions.is_empty());

    let mut binary = code_binary(&[0xc3]);
    binary.function_starts = vec![0x1000; MAX_METADATA_RECORDS + 1];
    assert!(plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).is_err());

    let mut binary = code_binary(&[0xc3]);
    function(&mut binary, 0x1000, 1, &"n".repeat(MAX_NAME_BYTES + 1));
    let project = Project::new(binary);
    assert!(plan(&project, &Annotations::in_memory(), 0x1000).is_err());

    let project = Project::new(code_binary(&[0xc3]));
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0x1000, Some("x".repeat(1024 * 1024 + 1))).unwrap();
    assert!(prepare(&project, &annotations, &request(0x1000, EntryValidation::AnalystAsserted), &|_| Ok(()),).is_err());
}

#[test]
fn actual_signature_symbols_cannot_be_silently_dropped_at_the_target_cap() {
    let mut binary = code_binary(&vec![0xc3; MAX_TARGETS + 1]);
    binary.function_starts.push(0x1000);
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    for offset in 0..=MAX_TARGETS {
        annotations.set(Field::Signature, 0x1000 + offset as u64, Some("void required(void);".to_owned())).unwrap();
    }
    assert!(plan(&project, &annotations, 0x1000).is_err());
}

#[test]
fn cancellation_is_checked_during_metadata_walk_and_operation_stages() {
    let mut binary = code_binary(&[0x90, 0xc3]);
    function(&mut binary, 0x1000, 2, "selected");
    let project = Project::new(binary);
    for stopped_stage in [
        "entry preparation",
        "entry function metadata",
        "entry reference instruction",
        "entry symbol operation",
        "entry plan complete",
    ] {
        let error =
            prepare(&project, &Annotations::in_memory(), &request(0x1000, EntryValidation::MetadataBacked), &|stage| {
                if stage == stopped_stage { Err(ApiError::Unavailable("cancelled".to_owned())) } else { Ok(()) }
            })
            .unwrap_err();
        assert!(matches!(error, ApiError::Unavailable(_)), "{stopped_stage}");
    }
    let state = project.decompiler.lock().unwrap();
    assert!(state.engine.is_none());
    assert!(state.names.is_empty());
    assert!(state.signatures.is_empty());
    assert!(state.types.is_empty());
    assert!(state.globals.is_empty());
}

#[test]
fn actual_import_signatures_receive_exact_declared_stub_aliases() {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xc3]),
            region(".plt", 0x2000, "r-x", &[0xff, 0x25, 0xfa, 0x5f, 0, 0, 0xff, 0x25, 0xf4, 0x5f, 0, 0]),
            region("slots", 0x8000, "rw-", &[0; 8]),
        ],
    ));
    function(&mut binary, 0x1000, 1, "caller");
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "exit".to_owned(), library: None });
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Name, 0x8000, Some("safe_import".to_owned())).unwrap();
    annotations.set(Field::Signature, 0x8000, Some("void custom_exit(int);".to_owned())).unwrap();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert_eq!(selected.stub_targets[&0x8000], [0x2000, 0x2006]);
    assert_eq!(selected.counts.stub_aliases, 2);
    for address in [0x2000, 0x2006, 0x8000] {
        assert!(has_runtime(&selected, address, "exit"));
        assert!(has_noreturn(&selected, address));
    }
    assert!(!has_symbol(&selected, 0x2001));
    assert_eq!(selected.counts.retained_imports, 1);
}

#[test]
fn canonical_two_byte_nop_padding_requires_the_exact_decoded_neutral_instruction() {
    for arch in ["x86", "x86_64"] {
        let binary = snapshot(input(arch, vec![region("code", 0x1000, "r-x", &[0xc3])]));
        let mut decoder = binary.decoder().unwrap();
        for (bytes, expected) in [
            (&[0x66, 0x90][..], true),
            (&[0x66, 0x91][..], false),
            (&[0x66, 0x87, 0][..], false),
            (&[0xf3, 0x90][..], false),
            (&[0x0f, 0x1f, 0x40, 0][..], true),
        ] {
            decoder.begin_run();
            let instruction = decoder.decode(bytes, 0x1000);
            assert_eq!(stub_padding(&binary, decoder.as_mut(), &instruction, bytes), expected, "{arch}: {bytes:x?}");
        }
        let bytes = [0x66, 0x90];
        let mut instruction = decoder.decode(&bytes, 0x1000);
        instruction.conditional = true;
        assert!(!stub_padding(&binary, decoder.as_mut(), &instruction, &bytes));
        instruction.conditional = false;
        instruction.len = 1;
        assert!(!stub_padding(&binary, decoder.as_mut(), &instruction, &bytes));
    }
}

#[test]
fn operand_size_nops_between_plt_got_stubs_do_not_receive_import_signatures() {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xe8, 3, 0x10, 0, 0, 0xc3]),
            region(
                ".plt.got",
                0x2000,
                "r-x",
                &[0xff, 0x25, 0xfa, 0x5f, 0, 0, 0x66, 0x90, 0xff, 0x25, 0xfa, 0x5f, 0, 0, 0x66, 0x90],
            ),
            region("slots", 0x8000, "rw-", &[0; 16]),
        ],
    ));
    function(&mut binary, 0x1000, 6, "caller");
    binary.import_slots.extend([
        ImportSlot { address: 0x8000, name: "unused".to_owned(), library: None },
        ImportSlot { address: 0x8008, name: "puts".to_owned(), library: None },
    ]);
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 0x8008, Some("int puts(const char *);".to_owned())).unwrap();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert_eq!(selected.stub_targets[&0x8000], [0x2000]);
    assert_eq!(selected.stub_targets[&0x8008], [0x2008]);
    assert!(has_runtime(&selected, 0x2008, "puts"));
    assert!(!has_symbol(&selected, 0x2006));
    let replay = super::super::types::plan_entry(&project, &annotations, &[], &selected.stub_targets).unwrap();
    assert!(
        replay.iter().any(|operation| {
            matches!(operation, WorkerOperation::Prototype { address: 0x2008, indirect: false, .. })
        })
    );
    assert!(
        !replay.iter().any(|operation| {
            matches!(operation, WorkerOperation::Prototype { address: 0x2006, indirect: false, .. })
        })
    );
}

#[test]
fn plt0_multi_byte_nop_padding_does_not_shift_the_following_import_entry() {
    let plt = [
        0xff, 0x35, 0xf2, 0x5f, 0, 0, 0xff, 0x25, 0xf4, 0x5f, 0, 0, 0x0f, 0x1f, 0x40, 0, 0xff, 0x25, 0xfa, 0x5f, 0, 0,
        0x68, 0, 0, 0, 0, 0xe9, 0xe0, 0xff, 0xff, 0xff,
    ];
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xe8, 0x0b, 0x10, 0, 0, 0xc3]),
            region(".plt", 0x2000, "r-x", &plt),
            region("slots", 0x7ff0, "rw-", &[0; 48]),
        ],
    ));
    function(&mut binary, 0x1000, 6, "caller");
    binary.import_slots.push(ImportSlot { address: 0x8010, name: "puts".to_owned(), library: None });
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 0x8010, Some("int puts(const char *);".to_owned())).unwrap();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert_eq!(selected.stub_targets[&0x8010], [0x2010]);
    assert!(has_runtime(&selected, 0x2010, "puts"));
    assert!(!has_symbol(&selected, 0x200c));
    let replay = super::super::types::plan_entry(&project, &annotations, &[], &selected.stub_targets).unwrap();
    assert!(
        replay.iter().any(|operation| {
            matches!(operation, WorkerOperation::Prototype { address: 0x2010, indirect: false, .. })
        })
    );
    assert!(
        !replay.iter().any(|operation| {
            matches!(operation, WorkerOperation::Prototype { address: 0x200c, indirect: false, .. })
        })
    );
}

#[test]
fn a_nop_with_a_memory_shaped_operand_is_not_an_import_slot_read() {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xe8, 2, 0x10, 0, 0, 0xc3]),
            region(".plt.got", 0x2000, "r-x", &[0x0f, 0x1f, 5, 0xf9, 0x5f, 0, 0, 0xff, 0x25, 0xfb, 0x5f, 0, 0]),
            region("slots", 0x8000, "rw-", &[0; 16]),
        ],
    ));
    function(&mut binary, 0x1000, 6, "caller");
    binary.import_slots.extend([
        ImportSlot { address: 0x8000, name: "abort".to_owned(), library: None },
        ImportSlot { address: 0x8008, name: "puts".to_owned(), library: None },
    ]);
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 0x8000, Some("void abort(void);".to_owned())).unwrap();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert!(!selected.stub_targets.contains_key(&0x8000));
    assert_eq!(selected.stub_targets[&0x8008], [0x2007]);
    assert!(!has_symbol(&selected, 0x2000));
    assert!(has_runtime(&selected, 0x2007, "puts"));
    assert!(!has_noreturn(&selected, 0x2007));
}

#[test]
fn caller_nop_operands_do_not_create_import_context() {
    let mut binary = code_binary(&[0x0f, 0x1f, 5, 0xf9, 0x6f, 0, 0, 0xc3]);
    function(&mut binary, 0x1000, 8, "caller");
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "abort".to_owned(), library: None });
    let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
    assert_eq!(selected.counts.retained_imports, 0);
    assert!(!has_runtime(&selected, 0x8000, "abort"));
    assert!(!has_noreturn(&selected, 0x8000));
}

#[test]
fn exact_abi_starts_at_a_nop_are_preserved_but_ordinary_labels_are_not_boundary_evidence() {
    for evidence in ["function", "format_start", "signature", "label"] {
        let mut binary = snapshot(input(
            "x86_64",
            vec![
                region("caller", 0x1000, "r-x", &[0xc3]),
                region(".plt.got", 0x2000, "r-x", &[0x66, 0x90, 0xff, 0x25, 0xf8, 0x5f, 0, 0]),
                region("slots", 0x8000, "rw-", &[0; 8]),
            ],
        ));
        function(&mut binary, 0x1000, 1, "caller");
        let mut annotations = Annotations::in_memory();
        match evidence {
            "function" => function(&mut binary, 0x2000, 8, "abi_start"),
            "format_start" => binary.function_starts.push(0x2000),
            "signature" => {
                annotations.set(Field::Signature, 0x2000, Some("int exact(const char *);".to_owned())).unwrap();
            }
            "label" => {
                binary.symbols.push(Symbol {
                    address: 0x2000,
                    name: "ordinary_label".to_owned(),
                    size: 8,
                    kind: SymbolKind::Other,
                });
            }
            _ => unreachable!(),
        }
        binary.import_slots.push(ImportSlot { address: 0x8000, name: "puts".to_owned(), library: None });
        let selected = plan(&Project::new(binary), &annotations, 0x1000).unwrap();
        let expected = if evidence == "label" { 0x2002 } else { 0x2000 };
        assert_eq!(selected.stub_targets[&0x8000], [expected], "{evidence}");
    }
}

#[test]
fn the_compiled_hello_fixture_retains_the_exact_puts_plt_runtime_prototype() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let caller = project.resolve("main").unwrap();
    let puts = project.resolve("puts").unwrap();
    let selected = plan(&project, &Annotations::in_memory(), caller).unwrap();
    assert!(has_runtime(&selected, puts, "puts"));
    assert!(selected.stub_targets.values().any(|targets| targets.contains(&puts)));
    assert!(selected.operations.iter().any(|operation| {
        matches!(operation, WorkerOperation::Symbol { address, name } if *address == puts && name == "puts@plt")
    }));
}

#[test]
fn caller_references_precede_unreferenced_stub_filler_without_losing_noreturn() {
    let mut stubs = Vec::new();
    for index in 0..MAX_TARGETS {
        let next = 0x2000 + index as i64 * 6 + 6;
        stubs.extend_from_slice(&[0xff, 0x25]);
        stubs.extend_from_slice(&i32::try_from(0x8000 - next).unwrap().to_le_bytes());
    }
    let referenced = 0x2000 + (MAX_TARGETS as u64 - 1) * 6;
    let mut caller = vec![0xe8];
    caller.extend_from_slice(&i32::try_from(referenced - 0x1005).unwrap().to_le_bytes());
    caller.extend_from_slice(&[0xe8, 0xf6, 1, 0, 0, 0xe8, 0xf1, 2, 0, 0, 0xc3]);
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &caller),
            region("required", 0x1100, "r-x", &[0xc3]),
            region("abort", 0x1200, "r-x", &[0xc3]),
            region("after_abort", 0x1300, "r-x", &[0xc3]),
            region(".plt", 0x2000, "r-x", &stubs),
            region("slots", 0x8000, "rw-", &[0; 8]),
        ],
    ));
    function(&mut binary, 0x1000, caller.len() as u64, "caller");
    function(&mut binary, 0x1100, 1, "required");
    function(&mut binary, 0x1200, 1, "abort");
    function(&mut binary, 0x1300, 1, "after_abort");
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "puts".to_owned(), library: None });
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 0x1100, Some("void required(void);".to_owned())).unwrap();
    let selected = plan(&Project::new(binary), &annotations, 0x1000).unwrap();
    assert!(has_symbol(&selected, 0x1100));
    assert!(has_runtime(&selected, referenced, "puts"));
    assert!(has_noreturn(&selected, 0x1200));
    assert!(!has_symbol(&selected, 0x1300));
    assert_eq!(selected.counts.retained_symbols, MAX_TARGETS);
    assert!(selected.counts.context_budget_exhausted);
}

#[test]
fn aarch64_slot_loads_must_feed_the_actual_stub_branch_register() {
    for (branch, valid) in [(0xd61f_0220u32, true), (0xd61f_0240u32, false)] {
        let stub: Vec<_> = [0xd000_0030u32, 0xf940_0211, branch].into_iter().flat_map(u32::to_le_bytes).collect();
        let mut binary = snapshot(input(
            "aarch64",
            vec![
                region("caller", 0x1000, "r-x", &0xd65f_03c0u32.to_le_bytes()),
                region("__stubs", 0x2000, "r-x", &stub),
                region("slots", 0x8000, "rw-", &[0; 8]),
            ],
        ));
        binary.function_starts.push(0x1000);
        binary.import_slots.push(ImportSlot { address: 0x8000, name: "callee".to_owned(), library: None });
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x8000, Some("void called(void);".to_owned())).unwrap();
        let result = plan(&project, &annotations, 0x1000);
        if valid {
            assert_eq!(result.unwrap().stub_targets[&0x8000], [0x2000]);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn aarch64_literal_import_stubs_preserve_the_leading_nop_and_require_a_64_bit_matching_load() {
    for (load, branch, valid) in
        [(0x5802_fff0u32, 0xd61f_0200u32, true), (0x1802_fff0, 0xd61f_0200, false), (0x5802_fff0, 0xd61f_0220, false)]
    {
        let caller: Vec<_> = [0x9400_0400u32, 0xd65f_03c0].into_iter().flat_map(u32::to_le_bytes).collect();
        let stub: Vec<_> = [0xd503_201fu32, load, branch].into_iter().flat_map(u32::to_le_bytes).collect();
        let mut binary = snapshot(input(
            "aarch64",
            vec![
                region("caller", 0x1000, "r-x", &caller),
                region("__stubs", 0x2000, "r-x", &stub),
                region("slots", 0x8000, "rw-", &[0; 8]),
            ],
        ));
        binary.format = Format::MachO;
        binary.function_starts.push(0x1000);
        binary.import_slots.push(ImportSlot { address: 0x8000, name: "___stack_chk_fail".to_owned(), library: None });
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x8000, Some("void failure(void);".to_owned())).unwrap();
        let result = plan(&project, &annotations, 0x1000);
        if valid {
            let selected = result.unwrap();
            assert_eq!(selected.stub_targets[&0x8000], [0x2000]);
            assert!(has_noreturn(&selected, 0x2000));
            assert!(has_runtime(&selected, 0x2000, "___stack_chk_fail"));
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn aarch64_elf_resolver_padding_does_not_shift_the_first_import_entry() {
    let caller: Vec<_> = [0x9400_0408u32, 0xd65f_03c0].into_iter().flat_map(u32::to_le_bytes).collect();
    let stubs: Vec<_> = [
        0xa9bf_7bf0u32,
        0xd000_0030,
        0xf940_0a11,
        0x9100_4210,
        0xd61f_0220,
        0xd503_201f,
        0xd503_201f,
        0xd503_201f,
        0xd000_0030,
        0xf940_0211,
        0x9100_0210,
        0xd61f_0220,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut binary = snapshot(input(
        "aarch64",
        vec![
            region("caller", 0x1000, "r-x", &caller),
            region(".plt", 0x2000, "r-x", &stubs),
            region("slots", 0x8000, "rw-", &[0; 24]),
        ],
    ));
    binary.format = Format::Elf;
    binary.function_starts.push(0x1000);
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "__stack_chk_fail".to_owned(), library: None });
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, 0x8000, Some("void failure(void);".to_owned())).unwrap();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert_eq!(selected.stub_targets[&0x8000], [0x2020]);
    assert!(has_noreturn(&selected, 0x2020));
    assert!(!has_noreturn(&selected, 0x2014));
}

#[test]
fn pe_import_signatures_are_refused_instead_of_rescanning_text_or_losing_aliases() {
    let mut binary = code_binary(&[0xc3]);
    binary.format = Format::Pe;
    binary.function_starts.push(0x1000);
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "exit".to_owned(), library: None });
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert!(!selected.omissions.is_empty());
    annotations.set(Field::Signature, 0x8000, Some("void stop(int);".to_owned())).unwrap();
    assert!(plan(&project, &annotations, 0x1000).is_err());
}

#[test]
fn a_stub_scan_cap_is_optional_only_without_required_slot_signatures() {
    let mut binary = snapshot(input(
        "x86_64",
        vec![
            region("caller", 0x1000, "r-x", &[0xc3]),
            region(".plt", 0x2000, "r-x", &vec![0x90; MAX_STUB_INSTRUCTIONS + 1]),
            region("slots", 0x8000, "rw-", &[0; 8]),
        ],
    ));
    binary.function_starts.push(0x1000);
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "callee".to_owned(), library: None });
    let project = Project::new(binary);
    let mut annotations = Annotations::in_memory();
    let selected = plan(&project, &annotations, 0x1000).unwrap();
    assert!(selected.counts.context_budget_exhausted);
    assert!(selected.counts.decoded_instructions <= MAX_INSTRUCTIONS);
    annotations.set(Field::Signature, 0x8000, Some("void required(void);".to_owned())).unwrap();
    assert!(plan(&project, &annotations, 0x1000).is_err());
}

fn aarch64_wrapper_binary(words: &[u32]) -> Binary {
    let bytes = |words: &[u32]| words.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<_>>();
    let mut binary = snapshot(input(
        "aarch64",
        vec![
            region("caller", 0x1000, "r-x", &bytes(&[0x9400_0040, 0x9400_007f, 0xd65f_03c0])),
            region("wrapper", 0x1100, "r-x", &bytes(words)),
            region("after_call", 0x1200, "r-x", &bytes(&[0xd65f_03c0])),
            region("unreferenced_wrapper", 0x1300, "r-x", &bytes(&[0x1400_0340])),
            region("__stubs", 0x2000, "r-x", &bytes(&[0xd503_201f, 0x5802_fff0, 0xd61f_0200])),
            region("slots", 0x8000, "rw-", &[0; 8]),
        ],
    ));
    binary.format = Format::MachO;
    binary.function_starts.extend([0x1000, 0x1100, 0x1200, 0x1300]);
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "___assert_rtn".to_owned(), library: None });
    binary
}

#[test]
fn referenced_exact_metadata_wrappers_to_noreturn_stubs_stop_caller_fallthrough() {
    for transfer in [0x9400_03bfu32, 0x1400_03bf] {
        for evidence in ["function", "export", "format_start", "image_entry"] {
            let mut binary = aarch64_wrapper_binary(&[0xa9bf_7bfd, transfer, 0xd65f_03c0]);
            binary.function_starts.retain(|&address| address != 0x1100);
            match evidence {
                "function" => function(&mut binary, 0x1100, 12, "failure_wrapper"),
                "export" => binary.exports.push(Export { address: 0x1100, name: "failure_wrapper".to_owned() }),
                "format_start" => binary.function_starts.push(0x1100),
                "image_entry" => binary.entry = Some(0x1100),
                _ => unreachable!(),
            }
            let project = Project::new(binary);
            let mut annotations = Annotations::in_memory();
            annotations.set(Field::Name, 0x1100, Some("safe_display_name".to_owned())).unwrap();
            annotations.set(Field::Name, 0x2000, Some("renamed_stub".to_owned())).unwrap();
            let selected = plan(&project, &annotations, 0x1000).unwrap();
            assert!(has_symbol(&selected, 0x1100), "{evidence}: {transfer:x}");
            assert!(has_noreturn(&selected, 0x1100), "{evidence}: {transfer:x}");
            assert!(!has_symbol(&selected, 0x1200), "{evidence}: {transfer:x}");
            assert!(!has_noreturn(&selected, 0x1000));
            assert!(!has_symbol(&selected, 0x1300));
            assert!(has_runtime(&selected, 0x2000, "___assert_rtn"));
            assert!(!has_runtime(&selected, 0x1100, "___assert_rtn"));
            assert!(!has_runtime(&selected, 0x1100, "safe_display_name"));
            assert_eq!(selected.counts.decoded_instructions, 6);
            assert_eq!(selected.counts.decoded_bytes, 24);
            assert_eq!(selected.counts.references, 1);
            assert_eq!(annotations.names().len(), 2);
            assert!(annotations.signatures().is_empty());
        }
    }
}

#[test]
fn conditional_return_and_unproven_transfers_are_not_noreturn_wrappers() {
    for (name, words) in [
        ("conditional_return", vec![0x3400_0040, 0x9400_03bf, 0xd65f_03c0]),
        ("return_before_stub", vec![0xd65f_03c0, 0x9400_03bf]),
        ("indirect_jump", vec![0xd61f_0000, 0x9400_03bf]),
        ("indirect_call", vec![0xd63f_0000, 0x9400_03bf]),
        ("invalid", vec![0xffff_ffff, 0x9400_03bf]),
        ("resumable_breakpoint", vec![0xd420_0000, 0x9400_03bf]),
        ("halt", vec![0xd420_0020, 0x9400_03bf]),
        ("semihosting_trap", vec![0xd45e_0000, 0x9400_03bf]),
        ("supervisor_call", vec![0xd400_0001, 0x9400_03bf]),
        ("unknown_call", vec![0x9400_0100, 0x9400_03bf]),
        ("unknown_jump", vec![0x1400_0100, 0x9400_03bf]),
        ("call_to_next", vec![0x9400_0001, 0xaa1e_03e0, 0x9400_03be]),
        ("unavailable_tail", vec![0xd503_201f]),
    ] {
        let binary = aarch64_wrapper_binary(&words);
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Name, 0x1100, Some("abort".to_owned())).unwrap();
        annotations.set(Field::Name, 0x1500, Some("___assert_rtn".to_owned())).unwrap();
        let selected = plan(&project, &annotations, 0x1000).unwrap();
        assert!(has_symbol(&selected, 0x1100), "{name}");
        assert!(!has_noreturn(&selected, 0x1100), "{name}");
        assert!(has_symbol(&selected, 0x1200), "{name}");
        assert!(!has_symbol(&selected, 0x1300), "{name}");
        assert!(!has_symbol(&selected, 0x1500), "{name}");
        assert!(!has_runtime(&selected, 0x1100, "abort"), "{name}");
    }
}

#[test]
fn throwing_imports_and_fatal_lookalikes_do_not_prove_wrappers_even_with_fatal_stub_context() {
    for (raw, known_noreturn) in
        [("__cxa_throw", true), ("objc_exception_throw", true), ("__assert_rtn_catchable", false)]
    {
        assert_eq!(is_noreturn_import(raw), known_noreturn, "{raw}");
        for transfer in [0xe8, 0xe9] {
            let mut binary = snapshot(input(
                "x86_64",
                vec![
                    region("caller", 0x1000, "r-x", &[0xe8, 0xfb, 0, 0, 0, 0xe8, 0xf6, 1, 0, 0, 0xc3]),
                    region("wrapper", 0x1100, "r-x", &[0x90, transfer, 0xfa, 0x0e, 0, 0, 0xc3]),
                    region("after_call", 0x1200, "r-x", &[0xc3]),
                    region(".plt", 0x2000, "r-x", &[0xff, 0x25, 0xfa, 0x5f, 0, 0, 0xff, 0x25, 0xfc, 0x5f, 0, 0]),
                    region("slots", 0x8000, "rw-", &[0; 16]),
                ],
            ));
            binary.function_starts.extend([0x1000, 0x1100, 0x1200]);
            binary.import_slots.extend([
                ImportSlot { address: 0x8000, name: raw.to_owned(), library: None },
                ImportSlot { address: 0x8008, name: "abort".to_owned(), library: None },
            ]);
            let project = Project::new(binary);
            let mut annotations = Annotations::in_memory();
            for address in [0x1100, 0x2000, 0x8000] {
                annotations.set(Field::Name, address, Some("abort".to_owned())).unwrap();
            }
            let selected = plan(&project, &annotations, 0x1000).unwrap();
            assert!(has_symbol(&selected, 0x1100), "{raw}: {transfer:x}");
            assert!(!has_noreturn(&selected, 0x1100), "{raw}: {transfer:x}");
            assert!(has_symbol(&selected, 0x1200), "{raw}: {transfer:x}");
            assert_eq!(has_noreturn(&selected, 0x2000), known_noreturn, "{raw}: {transfer:x}");
            assert!(has_noreturn(&selected, 0x2006));
        }
    }
}

#[test]
fn fatal_termination_import_wrappers_remain_proven_for_calls_and_tail_jumps() {
    for raw in ["abort", "_abort", "__assert_fail", "___assert_rtn", "__stack_chk_fail", "___stack_chk_fail"] {
        for transfer in [0x9400_03bf, 0x1400_03bf] {
            let mut binary = aarch64_wrapper_binary(&[0xd503_201f, transfer]);
            binary.import_slots[0].name = raw.to_owned();
            let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
            assert!(has_noreturn(&selected, 0x1100), "{raw}: {transfer:x}");
            assert!(!has_symbol(&selected, 0x1200), "{raw}: {transfer:x}");
        }
    }
}

#[test]
fn wrapper_proofs_do_not_cross_metadata_data_or_source_boundaries() {
    for variant in ["next_entry", "symbol_end", "data", "unavailable", "missing_metadata", "returning_import"] {
        let mut binary = aarch64_wrapper_binary(&[0xd503_201f, 0x9400_03bf]);
        match variant {
            "next_entry" => binary.function_starts.push(0x1104),
            "symbol_end" => function(&mut binary, 0x1100, 4, "small_function"),
            "data" => binary.symbols.push(Symbol {
                address: 0x1104,
                name: "literal".to_owned(),
                size: 4,
                kind: SymbolKind::Data,
            }),
            "unavailable" => {
                binary.segments.iter_mut().find(|segment| segment.address == 0x1100).unwrap().file_size = 4;
            }
            "missing_metadata" => binary.function_starts.retain(|&address| address != 0x1100),
            "returning_import" => binary.import_slots[0].name = "puts".to_owned(),
            _ => unreachable!(),
        }
        let project = Project::new(binary);
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Name, 0x1100, Some("abort".to_owned())).unwrap();
        annotations.set(Field::Name, 0x8000, Some("___assert_rtn".to_owned())).unwrap();
        let selected = plan(&project, &annotations, 0x1000).unwrap();
        assert!(!has_noreturn(&selected, 0x1100), "{variant}");
        assert!(has_symbol(&selected, 0x1200), "{variant}");
    }
}

#[test]
fn wrapper_inference_is_not_recursive_and_does_not_discover_unreferenced_functions() {
    for name in ["nested_wrapper", "abort"] {
        let mut binary = aarch64_wrapper_binary(&[0x9400_0080]);
        function(&mut binary, 0x1300, 4, name);
        let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
        assert!(has_symbol(&selected, 0x1100));
        assert!(!has_noreturn(&selected, 0x1100), "{name}");
        assert!(!has_symbol(&selected, 0x1300));
        assert!(!has_noreturn(&selected, 0x1300));
        assert!(has_symbol(&selected, 0x1200));
    }
}

#[test]
fn wrapper_decoding_charges_shared_budgets_and_checks_cancellation() {
    let project = Project::new(aarch64_wrapper_binary(&[0xd503_201f, 0x9400_03bf]));
    for stopped_stage in ["entry noreturn wrapper", "entry noreturn wrapper instruction"] {
        let error =
            prepare(&project, &Annotations::in_memory(), &request(0x1000, EntryValidation::MetadataBacked), &|stage| {
                if stage == stopped_stage { Err(ApiError::Unavailable("cancelled".to_owned())) } else { Ok(()) }
            })
            .unwrap_err();
        assert!(matches!(error, ApiError::Unavailable(_)), "{stopped_stage}");
    }
    let binary = &project.binary;
    let (metadata, _, _) = metadata(binary, 0x1000, &|_| Ok(())).unwrap();
    let stubs = BTreeMap::from([(0x2000, Identity { raw: Some("___assert_rtn"), import: true })]);
    for (instructions, bytes) in [(MAX_INSTRUCTIONS - 1, 0), (0, MAX_BYTES - 4), (0, MAX_BYTES - 2)] {
        let mut counts =
            EntryPlanCounts { decoded_instructions: instructions, decoded_bytes: bytes, ..EntryPlanCounts::default() };
        let mut omissions = Vec::new();
        assert!(
            !noreturn_wrapper(binary, 0x1100, &metadata, &stubs, &mut counts, &mut omissions, &|_| Ok(())).unwrap()
        );
        assert!(counts.context_budget_exhausted);
        assert!(counts.decoded_instructions <= MAX_INSTRUCTIONS);
        assert!(counts.decoded_bytes <= MAX_BYTES);
        assert!(!omissions.is_empty());
    }
}

fn x86_wrapper_binary(wrapper: &[u8]) -> Binary {
    x86_wrapper_binary_for_arch("x86_64", wrapper)
}

fn x86_wrapper_binary_for_arch(arch: &str, wrapper: &[u8]) -> Binary {
    let stub = if arch == "x86" { [0xff, 0x25, 0, 0x80, 0, 0] } else { [0xff, 0x25, 0xfa, 0x5f, 0, 0] };
    let mut binary = snapshot(input(
        arch,
        vec![
            region("caller", 0x1000, "r-x", &[0xe8, 0xfb, 0, 0, 0, 0xe8, 0xf6, 1, 0, 0, 0xc3]),
            region("wrapper", 0x1100, "r-x", wrapper),
            region("after_call", 0x1200, "r-x", &[0xc3]),
            region(".plt", 0x2000, "r-x", &stub),
            region("slots", 0x8000, "rw-", &[0; 8]),
        ],
    ));
    binary.function_starts.extend([0x1000, 0x1100, 0x1200]);
    binary.import_slots.push(ImportSlot { address: 0x8000, name: "abort".to_owned(), library: None });
    binary
}

#[test]
fn x86_wrappers_require_a_direct_known_stub_transfer_without_call_to_next_reclassification() {
    for (wrapper, expected) in [
        (vec![0x55, 0x48, 0x89, 0xe5, 0xe8, 0xf7, 0x0e, 0, 0], true),
        (vec![0x90, 0xe9, 0xfa, 0x0e, 0, 0], true),
        (vec![0xe8, 0, 0, 0, 0, 0x58, 0xe9, 0xf5, 0x0e, 0, 0], false),
        (vec![0x74, 1, 0xc3, 0xe9, 0xf8, 0x0e, 0, 0], false),
    ] {
        let selected = plan(&Project::new(x86_wrapper_binary(&wrapper)), &Annotations::in_memory(), 0x1000).unwrap();
        assert_eq!(has_noreturn(&selected, 0x1100), expected, "{wrapper:x?}");
        assert_eq!(has_symbol(&selected, 0x1200), !expected, "{wrapper:x?}");
    }
}

#[test]
fn x86_interrupts_with_legacy_and_rex_prefixes_do_not_prove_fatal_wrappers() {
    for arch in ["x86", "x86_64"] {
        let mut prefixes =
            vec![vec![], vec![0x66], vec![0x67], vec![0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65], vec![0xf2], vec![0xf3]];
        if arch == "x86_64" {
            prefixes.extend([vec![0x40], vec![0x48], vec![0x4f], vec![0x66, 0x48], vec![0x48, 0x66]]);
        }
        for opcode in [vec![0xcd, 0x80], vec![0xcc], vec![0xf1], vec![0xce]] {
            if arch == "x86_64" && opcode == [0xce] {
                continue;
            }
            for prefix in &prefixes {
                let mut interrupt = prefix.clone();
                interrupt.extend_from_slice(&opcode);
                let mut wrapper = vec![0xb8, 173, 0, 0, 0];
                wrapper.extend_from_slice(&interrupt);
                let next = 0x1100 + wrapper.len() as i64 + 5;
                wrapper.push(0xe9);
                wrapper.extend_from_slice(&i32::try_from(0x2000 - next).unwrap().to_le_bytes());
                let binary = x86_wrapper_binary_for_arch(arch, &wrapper);
                let instruction = binary.decoder().unwrap().decode(&interrupt, 0x1105);
                assert_eq!(instruction.flow, Flow::Next, "{arch}: {interrupt:x?}");
                assert_eq!(usize::from(instruction.len), interrupt.len(), "{arch}: {interrupt:x?}");
                let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
                assert!(has_noreturn(&selected, 0x2000), "{arch}: {interrupt:x?}");
                assert!(!has_noreturn(&selected, 0x1100), "{arch}: {interrupt:x?}");
                assert!(has_symbol(&selected, 0x1200), "{arch}: {interrupt:x?}");
                assert!(selected.counts.decoded_instructions <= MAX_INSTRUCTIONS);
                assert!(selected.counts.decoded_bytes <= MAX_BYTES);
            }
        }
    }
}

#[test]
fn x86_normal_setup_and_interrupt_shaped_immediates_remain_eligible_for_wrapper_proofs() {
    for arch in ["x86", "x86_64"] {
        let wrapper = [0x40, 0xb8, 0xcc, 0xcd, 0xce, 0xf1, 0xe9, 0xf5, 0x0e, 0, 0];
        let selected =
            plan(&Project::new(x86_wrapper_binary_for_arch(arch, &wrapper)), &Annotations::in_memory(), 0x1000)
                .unwrap();
        assert!(has_noreturn(&selected, 0x1100), "{arch}");
        assert!(!has_symbol(&selected, 0x1200), "{arch}");
    }
}

#[test]
fn wrapper_instruction_and_byte_caps_never_promote_an_unproven_wrapper() {
    let mut words = vec![0xd503_201f; MAX_WRAPPER_INSTRUCTIONS];
    let at = 0x1100 + words.len() as u32 * 4;
    words.push(0x9400_0000 | ((0x2000 - at) / 4));
    let selected = plan(&Project::new(aarch64_wrapper_binary(&words)), &Annotations::in_memory(), 0x1000).unwrap();
    assert!(!has_noreturn(&selected, 0x1100));
    assert!(has_symbol(&selected, 0x1200));
    assert!(selected.counts.context_budget_exhausted);

    let long_nop = [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0];
    let mut wrapper = long_nop.repeat(MAX_WRAPPER_BYTES / long_nop.len() + 1);
    let next = 0x1100 + wrapper.len() as i64 + 5;
    wrapper.push(0xe9);
    wrapper.extend_from_slice(&i32::try_from(0x2000 - next).unwrap().to_le_bytes());
    let selected = plan(&Project::new(x86_wrapper_binary(&wrapper)), &Annotations::in_memory(), 0x1000).unwrap();
    assert!(!has_noreturn(&selected, 0x1100));
    assert!(has_symbol(&selected, 0x1200));
    assert!(selected.counts.context_budget_exhausted);
    assert!(selected.counts.decoded_bytes <= MAX_BYTES);
}

#[test]
fn wrapper_candidate_budget_counts_unique_callees_and_reports_skipped_proofs() {
    for repeat in [false, true] {
        let mut caller = Vec::new();
        let mut regions = vec![
            region(".plt", 0x2000, "r-x", &[0xff, 0x25, 0xfa, 0x5f, 0, 0]),
            region("slots", 0x8000, "rw-", &[0; 8]),
            region("after_call", 0x4000, "r-x", &[0xc3]),
        ];
        let last = 0x3000 + MAX_NORETURN_WRAPPERS as u64 * 16;
        for index in 0..=MAX_NORETURN_WRAPPERS {
            let address = 0x3000 + index as u64 * 16;
            let mut wrapper = vec![0xc3];
            if address == last {
                wrapper = vec![0xe9];
                wrapper.extend_from_slice(&i32::try_from(0x2000i64 - address as i64 - 5).unwrap().to_le_bytes());
            }
            regions.push(region("wrapper", address, "r-x", &wrapper));
            let target = if repeat && address != last { 0x3000 } else { address };
            let next = 0x1000 + caller.len() as u64 + 5;
            caller.push(0xe8);
            caller.extend_from_slice(&i32::try_from(target as i64 - next as i64).unwrap().to_le_bytes());
        }
        let next = 0x1000 + caller.len() as u64 + 5;
        caller.push(0xe8);
        caller.extend_from_slice(&i32::try_from(0x4000 - next).unwrap().to_le_bytes());
        caller.push(0xc3);
        regions.push(region("caller", 0x1000, "r-x", &caller));
        let mut binary = snapshot(input("x86_64", regions));
        binary.function_starts.extend([0x1000, 0x4000]);
        binary.function_starts.extend((0..=MAX_NORETURN_WRAPPERS).map(|index| 0x3000 + index as u64 * 16));
        binary.import_slots.push(ImportSlot { address: 0x8000, name: "abort".to_owned(), library: None });
        let selected = plan(&Project::new(binary), &Annotations::in_memory(), 0x1000).unwrap();
        assert!(has_symbol(&selected, last));
        assert_eq!(has_noreturn(&selected, last), repeat);
        assert_eq!(has_symbol(&selected, 0x4000), !repeat);
        assert_eq!(selected.counts.context_budget_exhausted, !repeat);
    }
}
