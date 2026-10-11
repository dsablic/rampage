use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, MemoryRegion, Segment};

use rampage_decompiler::results::{RecoveryStatus, ResultProvenance, StorageKind, parse_results};

fn snapshot() -> serde_json::Value {
    serde_json::json!({
        "provenance": "engine_recovered",
        "signature": {
            "return_type": {"name": "int4", "size": 4},
            "calling_convention": "__cdecl",
            "variadic": false,
            "parameters": []
        },
        "variables": [],
        "blocks": [],
        "calls": [],
        "jump_tables": []
    })
}

#[test]
fn parser_preserves_full_width_addresses_and_unknown_call_targets() {
    let mut value = snapshot();
    value["calls"] = serde_json::json!([
        {"source": u64::MAX, "target": null, "name": null, "indirect": true},
        {"source": 0, "target": u64::MAX - 1, "name": "callee", "indirect": false}
    ]);
    let result = parse_results(&value.to_string()).unwrap();
    assert_eq!(result.calls[0].source, Some(u64::MAX));
    assert_eq!(result.calls[0].target, None);
    assert_eq!(result.calls[0].name, None);
    assert!(result.calls[0].indirect);
    assert_eq!(result.calls[1].source, Some(0));
    assert_eq!(result.calls[1].target, Some(u64::MAX - 1));
    assert_eq!(result.provenance, ResultProvenance::EngineRecovered);
    assert_eq!(result.recovery_status(), RecoveryStatus::Unavailable);
}

#[test]
fn parser_preserves_dynamic_storage_and_partial_jump_tables() {
    let mut value = snapshot();
    value["variables"] = serde_json::json!([{
        "name": "temporary\n\"λ\\",
        "data_type": {"name": "char *", "size": 8},
        "kind": "local",
        "storage": [{"kind": "dynamic", "space": null, "address": null, "size": 8}]
    }]);
    value["jump_tables"] = serde_json::json!([{
        "switch_address": 0x1008,
        "targets": [0x1020, 0x1030, 0x1020],
        "partial": true
    }]);
    let result = parse_results(&value.to_string()).unwrap();
    assert_eq!(result.variables[0].name, "temporary\n\"λ\\");
    assert_eq!(result.variables[0].storage[0].kind, StorageKind::Dynamic);
    assert_eq!(result.variables[0].storage[0].address, None);
    assert_eq!(result.variables[0].storage[0].dynamic_hash, None);
    assert_eq!(result.variables[0].storage[0].use_ranges, None);
    assert!(result.variables[0].storage[0].pieces.is_empty());
    assert_eq!(result.jump_tables[0].targets, [0x1020, 0x1030, 0x1020]);
    assert!(result.jump_tables[0].partial);
}

#[test]
fn parser_rejects_invalid_addresses_schema_and_oversized_results() {
    let mut negative = snapshot();
    negative["blocks"] = serde_json::json!([{"index": 0, "start": -1, "end": null, "successors": []}]);
    let mut overflow = snapshot();
    overflow["calls"] = serde_json::json!([{
        "source": 1.8446744073709552e19,
        "target": null,
        "name": null,
        "indirect": false
    }]);
    let mut provenance = snapshot();
    provenance["provenance"] = serde_json::json!("guessed");
    for text in ["{}".to_owned(), negative.to_string(), overflow.to_string(), provenance.to_string()] {
        assert!(parse_results(&text).is_err(), "accepted {text}");
    }
    let mut oversized = snapshot();
    oversized["signature"]["return_type"]["name"] = serde_json::json!("x".repeat(4 * 1024 * 1024));
    let error = parse_results(&oversized.to_string()).unwrap_err();
    assert!(error.to_string().contains("limit"), "{error}");
}

#[test]
fn engine_result_contains_parameter_types_storage_and_instruction_boundaries() {
    let bytes = [0x89, 0xf8, 0xc3];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.set_symbol(0x1000, "identity").unwrap();
    engine.apply_prototype(0x1000, false, "int4 identity(int4 value);").unwrap();
    engine.decompile(0x1000, "identity", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.signature.return_type.size, 4);
    assert_eq!(result.signature.parameters.len(), 1);
    let parameter = &result.signature.parameters[0];
    assert_eq!(parameter.name, "value");
    assert_eq!(parameter.data_type.size, 4);
    assert_eq!(parameter.storage.space.as_deref(), Some("register"));
    assert!(parameter.storage.address.is_some());
    assert_eq!(parameter.storage.size, 4);
    assert!(result.variables.iter().any(|variable| {
        variable.name == "value"
            && variable.data_type.size == 4
            && variable.storage.iter().any(|storage| storage.space.as_deref() == Some("register"))
    }));
    assert_eq!(result.blocks.len(), 1);
    assert_eq!(result.blocks[0].start, Some(0x1000));
    assert_eq!(result.blocks[0].end, Some(0x1002));
    assert!(result.blocks[0].successors.is_empty());
    assert_eq!(result.recovery_status(), RecoveryStatus::NoReportedIssues);
}

#[test]
fn engine_result_links_direct_calls_to_their_source_instruction() {
    let caller = [0xe8, 0x0b, 0, 0, 0, 0xc3];
    let callee = [0xb8, 7, 0, 0, 0, 0xc3];
    let mut engine = Decompiler::open(
        Arch::X86_64,
        false,
        &[
            Segment { base: 0x1000, bytes: &caller, writable: false },
            Segment { base: 0x1010, bytes: &callee, writable: false },
        ],
    )
    .unwrap();
    engine.set_symbol(0x1010, "callee").unwrap();
    engine.apply_prototype(0x1010, false, "int4 callee(void);").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.calls.len(), 1);
    assert_eq!(result.calls[0].source, Some(0x1000));
    assert_eq!(result.calls[0].target, Some(0x1010));
    assert_eq!(result.calls[0].name.as_deref(), Some("callee"));
    assert!(!result.calls[0].indirect);
    engine.decompile(0x1010, "callee", false).unwrap();
    assert!(engine.structured_result().unwrap().calls.is_empty());
}

#[test]
fn engine_result_preserves_conditional_control_flow_successor_indices() {
    let bytes = [0x85, 0xff, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.decompile(0x1000, "conditional", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert!(result.blocks.iter().any(|block| block.successors.len() == 2), "{result:?}");
    for block in &result.blocks {
        for successor in &block.successors {
            assert!(result.blocks.iter().any(|target| target.index == *successor), "{result:?}");
        }
        assert!(block.start.is_some());
        assert!(block.end >= block.start);
    }
}

#[test]
fn engine_result_recovers_switch_address_and_jump_table_targets() {
    let mut code = vec![0; 0x56];
    code[..14].copy_from_slice(&[0x83, 0xff, 2, 0x77, 0x4b, 0x89, 0xf8, 0xff, 0x24, 0xc5, 0, 0x20, 0, 0]);
    for (offset, value) in [(0x20, 1), (0x30, 2), (0x40, 3), (0x50, 0)] {
        code[offset..offset + 6].copy_from_slice(&[0xb8, value, 0, 0, 0, 0xc3]);
    }
    let table: Vec<_> = [0x1020u64, 0x1030, 0x1040].into_iter().flat_map(u64::to_le_bytes).collect();
    let mut engine = Decompiler::open(
        Arch::X86_64,
        false,
        &[
            Segment { base: 0x1000, bytes: &code, writable: false },
            Segment { base: 0x2000, bytes: &table, writable: false },
        ],
    )
    .unwrap();
    engine.decompile(0x1000, "switcher", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.jump_tables.len(), 1, "{result:?}");
    let table = &result.jump_tables[0];
    assert_eq!(table.switch_address, Some(0x1007));
    for target in [0x1020, 0x1030, 0x1040] {
        assert!(table.targets.contains(&target), "{table:?}");
    }
    assert!(!table.partial);
    assert_eq!(table.case_values, vec![Some(0), Some(1), Some(2), None]);
}

#[test]
fn engine_result_preserves_unresolved_indirect_calls_without_inventing_targets() {
    let bytes = [0xff, 0xd7, 0xc3];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.decompile(0x1000, "indirect", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.calls.len(), 1, "{result:?}");
    assert_eq!(result.calls[0].source, Some(0x1000));
    assert_eq!(result.calls[0].target, None);
    assert!(result.calls[0].indirect);
    assert_eq!(result.recovery_status(), RecoveryStatus::Warnings);
    assert_eq!(result.diagnostics.unwrap().unresolved_calls, 1);
}

#[test]
fn bad_instruction_output_has_engine_diagnostics_and_warnings_do_not_accumulate() {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&[0x0f, 0x04]);
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    let code = engine.decompile(0x1000, "bad_code", false).unwrap();
    assert!(code.contains("halt_baddata"), "{code}");
    let first = engine.structured_result().unwrap();
    assert_eq!(first.recovery_status(), RecoveryStatus::Incomplete);
    let diagnostics = first.diagnostics.unwrap();
    assert!(diagnostics.bad_data);
    assert!(diagnostics.warnings.iter().any(|warning| warning.message.contains("Bad instruction")));
    assert!(diagnostics.warnings.iter().any(|warning| warning.address == Some(0x1000)));
    engine.decompile(0x1000, "bad_code", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().diagnostics.unwrap(), diagnostics);
}

#[test]
fn unresolved_wrapper_jump_remains_a_recovery_warning() {
    let bytes = [0xff, 0x25, 0xfa, 0x1f, 0, 0];
    let regions = [
        MemoryRegion { base: 0x1000, bytes: &bytes, size: 6, readable: true, writable: false, executable: true },
        MemoryRegion { base: 0x3000, bytes: &[0; 8], size: 8, readable: true, writable: true, executable: false },
    ];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.decompile(0x1000, "wrapper", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.recovery_status(), RecoveryStatus::Warnings);
    let diagnostics = result.diagnostics.unwrap();
    assert_eq!(diagnostics.unresolved_calls, 1);
    assert!(diagnostics.warnings.iter().any(|warning| warning.message.contains("Treating indirect jump")));
}

#[test]
fn recovery_flags_are_reset_when_a_function_is_redecoded_in_another_mode() {
    let bytes = [0x70, 0x47, 0xff, 0xff];
    let mut engine = Decompiler::open(Arch::Arm, false,
        &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.decompile(0x1000, "mixed_mode", false).unwrap();
    assert!(engine.structured_result().unwrap().diagnostics.unwrap().bad_data);
    engine.decompile(0x1000, "mixed_mode", true).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.recovery_status(), RecoveryStatus::NoReportedIssues);
    let mut fresh = Decompiler::open(Arch::Arm, false,
        &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    fresh.decompile(0x1000, "mixed_mode", true).unwrap();
    assert_eq!(result.diagnostics, fresh.structured_result().unwrap().diagnostics);
}

#[test]
fn engine_result_json_escapes_symbol_names_and_preserves_unicode() {
    let caller = [0xe8, 0x0b, 0, 0, 0, 0xc3];
    let callee = [0xb8, 7, 0, 0, 0, 0xc3];
    let name = "callee\"\\\nλ";
    let mut engine = Decompiler::open(
        Arch::X86_64,
        false,
        &[
            Segment { base: 0x1000, bytes: &caller, writable: false },
            Segment { base: 0x1010, bytes: &callee, writable: false },
        ],
    )
    .unwrap();
    engine.set_symbol(0x1010, name).unwrap();
    engine.apply_prototype(0x1010, false, "int4 canonical(void);").unwrap();
    engine.decompile(0x1000, "caller", false).unwrap();
    let result = engine.structured_result().unwrap();
    assert_eq!(result.calls[0].name.as_deref(), Some(name));
}

#[test]
fn engine_result_resolves_struct_parameter_join_pieces_and_symbol_offsets() {
    let bytes = [0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3];
    let mut engine =
        Decompiler::open(Arch::X86_64, false, &[Segment { base: 0x1000, bytes: &bytes, writable: false }]).unwrap();
    engine.parse_c("struct Pair { uint8 first; uint8 second; };").unwrap();
    engine.set_symbol(0x1000, "sum_pair").unwrap();
    engine.apply_prototype(0x1000, false, "uint8 sum_pair(Pair value);").unwrap();
    engine.decompile(0x1000, "sum_pair", false).unwrap();
    let result = engine.structured_result().unwrap();
    let storage = &result.signature.parameters[0].storage;
    assert_eq!(storage.kind, StorageKind::Join, "{result:?}");
    assert_eq!(storage.join_logical_size, Some(16));
    assert_eq!(storage.pieces.len(), 2);
    for (piece, offset) in storage.pieces.iter().zip([0, 8]) {
        assert_eq!(piece.space, "register");
        assert_eq!(piece.size, 8);
        assert_eq!(piece.logical_offset, offset);
    }
    assert_eq!(storage.pieces[0].address, 0x38);
    assert_eq!(storage.pieces[1].address, 0x30);
    assert_eq!(storage.symbol_offset, Some(0));
    assert_eq!(storage.is_piece, Some(false));
    let variable = result.variables.iter().find(|variable| variable.name == "value").unwrap();
    assert!(variable.storage.iter().any(|storage| storage.is_piece == Some(false)));
    for piece in &storage.pieces {
        assert!(
            variable.storage.iter().any(|storage| {
                storage.is_piece == Some(true)
                    && storage.symbol_offset == Some(piece.logical_offset)
                    && storage.address == Some(piece.address)
                    && storage.size == piece.size
            }),
            "{variable:?}"
        );
    }
}

#[test]
fn engine_result_distinguishes_reused_call_return_registers_by_use_range() {
    let caller = [0x53, 0xe8, 0xfa, 0, 0, 0, 0x89, 0xc3, 0xe8, 0x03, 1, 0, 0, 0x01, 0xd8, 0x5b, 0xc3];
    let callee = [0xb8, 7, 0, 0, 0, 0xc3];
    let mut engine = Decompiler::open(
        Arch::X86_64,
        false,
        &[
            Segment { base: 0x1000, bytes: &caller, writable: false },
            Segment { base: 0x1100, bytes: &callee, writable: false },
            Segment { base: 0x1110, bytes: &callee, writable: false },
        ],
    )
    .unwrap();
    for (address, name) in [(0x1000, "add_returns"), (0x1100, "first"), (0x1110, "second")] {
        engine.set_symbol(address, name).unwrap();
        engine.apply_prototype(address, false, &format!("int4 {name}(void);")).unwrap();
    }
    engine.decompile(0x1000, "add_returns", false).unwrap();
    let result = engine.structured_result().unwrap();
    let returns: Vec<_> = result
        .variables
        .iter()
        .flat_map(|variable| &variable.storage)
        .filter(|storage| storage.space.as_deref() == Some("register") && storage.address == Some(0))
        .collect();
    assert!(returns.len() >= 2, "{result:?}");
    assert!(returns.iter().all(|storage| storage.use_ranges.as_ref().is_some_and(|ranges| !ranges.is_empty())));
    assert!(returns.iter().any(|left| returns.iter().any(|right| left.use_ranges != right.use_ranges)), "{result:?}");
    for address in [0x1001, 0x1008] {
        assert!(
            returns.iter().any(|storage| storage
                .use_ranges
                .as_ref()
                .unwrap()
                .iter()
                .any(|range| { range.space == "ram" && range.start == address && range.end == address })),
            "{result:?}"
        );
    }
}

#[test]
fn parser_preserves_dynamic_identity_ranges_and_precision_piece_metadata() {
    let mut value = snapshot();
    value["variables"] = serde_json::json!([{
        "name": "temporary",
        "data_type": {"name": "uint8", "size": 8},
        "kind": "local",
        "storage": [{
            "kind": "dynamic", "space": null, "address": null, "size": 4,
            "dynamic_hash": u64::MAX,
            "symbol_offset": 4,
            "is_piece": true,
            "use_ranges": [{"space": "ram", "start": 0x1004, "end": 0x1004}]
        }]
    }]);
    let result = parse_results(&value.to_string()).unwrap();
    let storage = &result.variables[0].storage[0];
    assert_eq!(storage.dynamic_hash, Some(u64::MAX));
    assert_eq!(storage.symbol_offset, Some(4));
    assert_eq!(storage.is_piece, Some(true));
    let range = &storage.use_ranges.as_ref().unwrap()[0];
    assert_eq!(range.space, "ram");
    assert_eq!((range.start, range.end), (0x1004, 0x1004));
}

#[test]
fn native_import_results_use_slot_addresses_instead_of_synthetic_targets() {
    let caller = [0xff, 0x15, 0xfa, 0x1f, 0, 0, 0xc3];
    let regions = [
        MemoryRegion {
            base: 0x1000,
            bytes: &caller,
            size: caller.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        },
        MemoryRegion { base: 0x3000, bytes: &[0; 8], size: 8, readable: true, writable: true, executable: false },
    ];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.add_import(0x3000, None, "external").unwrap();
    engine.apply_prototype(0x3000, true, "int4 external(void);").unwrap();
    assert_ne!(engine.import_target(0x3000), Some(0x3000));
    engine.decompile(0x1000, "caller", false).unwrap();
    assert_eq!(engine.structured_result().unwrap().calls[0].target, Some(0x3000));
}
