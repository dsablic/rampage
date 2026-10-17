use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decompiler::results::{StructuredResult, Variable};
use rampage_decompiler::worker::WorkerConfig;
use serde_json::json;

use super::*;
use crate::VariableEditRequest;
use crate::annotations::Annotations;

const ENTRY: u64 = 0x4000ae;

fn storage(kind: &str, space: Option<&str>, address: Option<&str>) -> serde_json::Value {
    json!({
        "kind": kind,
        "space": space,
        "address": address,
        "size": 8,
        "use_ranges": [],
        "symbol_offset": 0,
        "is_piece": false,
        "pieces": []
    })
}

fn variable(name: &str, kind: &str, storage: Vec<serde_json::Value>) -> Variable {
    serde_json::from_value(json!({
        "name": name,
        "kind": kind,
        "data_type": { "name": "undefined8", "size": 8 },
        "storage": storage
    }))
    .unwrap()
}

fn decompilation(structure: StructuredResult) -> Decompilation {
    let variables = crate::variables::descriptors(&structure);
    Decompilation {
        address: ENTRY,
        name: "frame_fixture".to_owned(),
        code: String::new(),
        language_id: "test".to_owned(),
        tokens: Vec::new(),
        recovery_status: structure.recovery_status(),
        structure,
        variables,
    }
}

#[test]
fn signed_offsets_require_the_actual_space_width_and_preserve_boundaries() {
    for (address, bits, expected) in [
        (Some(0x7fff_ffff), Some(32), Some("2147483647")),
        (Some(0x8000_0000), Some(32), Some("-2147483648")),
        (Some(0xffff_ffff), Some(32), Some("-1")),
        (Some(0x7fff_ffff_ffff_ffff), Some(64), Some("9223372036854775807")),
        (Some(0x8000_0000_0000_0000), Some(64), Some("-9223372036854775808")),
        (Some(u64::MAX), Some(64), Some("-1")),
        (Some(0x1_0000_0000), Some(32), None),
        (Some(u64::MAX), None, None),
        (None, Some(64), None),
        (Some(1), Some(0), None),
        (Some(1), Some(65), None),
    ] {
        assert_eq!(signed_offset(address, bits).as_deref(), expected, "{address:?}/{bits:?}");
    }
}

#[test]
fn native_mapping_and_join_piece_offsets_use_each_actual_space_width() {
    let mut stack32 = storage("spacebase", Some("stack"), Some("0x80000000"));
    stack32["address_size_bytes"] = json!(4);
    let mut stack64 = storage("spacebase", Some("stack"), Some("0x8000000000000000"));
    stack64["address_size_bytes"] = json!(8);
    let mut register = storage("processor", Some("register"), Some("0xfffffff0"));
    register["address_size_bytes"] = json!(4);
    let mut join = storage("join", Some("join"), Some("0x1"));
    join["address_size_bytes"] = json!(8);
    join["pieces"] = json!([
        { "kind": "spacebase", "space": "stack", "address": "0xfffffff0", "size": 4,
          "logical_offset": 0, "address_size_bytes": 4 },
        { "kind": "spacebase", "space": "stack", "address": "0xfffffff0", "size": 4,
          "logical_offset": 4 }
    ]);
    let mut structure = StructuredResult::empty();
    structure.frame_context = Some(
        serde_json::from_value(json!({
            "stack_space": "stack", "address_size_bytes": 8, "base_convention": "native_spacebase_register",
            "base_register": { "space": "register", "address": "0x20", "size": 8 }
        }))
        .unwrap(),
    );
    let context = structure.frame_context.clone();
    structure.variables = vec![
        variable("a", "local", vec![stack32]),
        variable("b", "local", vec![stack64]),
        variable("c", "local", vec![register]),
        variable("joined", "local", vec![join]),
        variable("width_unknown", "local", vec![storage("spacebase", Some("stack"), Some("0xfffffff0"))]),
    ];
    let (report, _) = native_workset(decompilation(structure));
    assert_eq!(report.native.frame_context, context);
    assert_eq!(report.rows[0].signed_offset.as_deref(), Some("-2147483648"));
    assert_eq!(report.rows[1].signed_offset.as_deref(), Some("-9223372036854775808"));
    assert!(report.rows[2].signed_offset.is_none());
    assert_eq!(report.rows[3].locations[1].signed_offset.as_deref(), Some("-16"));
    assert!(report.rows[3].locations[2].signed_offset.is_none());
    assert!(report.rows[4].signed_offset.is_none());
    assert!(
        report
            .coordinates
            .iter()
            .all(|coordinate| { coordinate.origin.as_deref() != Some("function_entry_stack_pointer") })
    );
}

#[test]
fn unsupported_dynamic_and_split_native_mappings_are_not_dropped_or_made_editable() {
    let mut dynamic = storage("dynamic", None, None);
    dynamic["dynamic_hash"] = json!(123);
    let mut join = storage("join", Some("join"), Some("0x10"));
    join["join_logical_size"] = json!(8);
    join["pieces"] = json!([
        { "kind": "processor", "space": "register", "address": "0x0", "size": 4, "logical_offset": 0 },
        { "kind": "spacebase", "space": "stack", "address": "0xfffffff0", "size": 4,
          "logical_offset": 4 }
    ]);
    let mut structure = StructuredResult::empty();
    structure.variables = vec![
        variable("dynamic", "local", vec![dynamic]),
        variable("split", "local", vec![join]),
        variable("unknown", "local", vec![storage("unknown", None, None)]),
        variable(
            "multi",
            "local",
            vec![
                storage("spacebase", Some("stack"), Some("0xfffffff0")),
                storage("processor", Some("register"), Some("0x10")),
            ],
        ),
        variable("missing", "local", Vec::new()),
        variable("input", "parameter", vec![storage("processor", Some("register"), Some("0x20"))]),
    ];
    let raw: Vec<_> = structure.variables.iter().map(|variable| variable.storage.clone()).collect();
    let (report, _) = native_workset(decompilation(structure));
    assert_eq!(report.rows.len(), raw.len());
    for (row, storage) in report.rows.iter().zip(raw) {
        assert_eq!(row.raw_native_storage, storage);
    }
    assert!(report.rows[..5].iter().all(|row| !row.editable));
    assert_eq!(report.rows[1].locations.len(), 3);
    assert!(report.rows[1].locations.iter().all(|location| location.signed_offset.is_none()));
    let input = report.rows.last().unwrap();
    assert_eq!(input.category, FrameCategory::Parameter);
    assert_eq!(input.locations[0].coordinate_id.as_deref(), Some("native:register"));
    assert!(input.locations[0].signed_offset.is_none());
    assert!(report.coordinates.iter().all(|coordinate| coordinate.origin.is_none()));
}

#[test]
fn paging_is_explicit_and_work_omissions_are_not_hidden_as_a_complete_frame() {
    let mut structure = StructuredResult::empty();
    structure.variables =
        (0..MAX_FRAME_WORK + 3).map(|index| variable(&format!("v{index}"), "local", Vec::new())).collect();
    let (mut report, work) = native_workset(decompilation(structure));
    assert_eq!(work, MAX_FRAME_WORK);
    page(&mut report, &FrameQuery { offset: MAX_FRAME_WORK - 2, limit: 2, include_tracker: false });
    assert_eq!(report.total_rows, MAX_FRAME_WORK + 3);
    assert_eq!(report.available_rows, MAX_FRAME_WORK);
    assert_eq!(report.omitted_rows, 3);
    assert_eq!(report.native.omitted_variables, 3);
    assert_eq!(report.rows.len(), 2);
    assert!(report.next_offset.is_none());
    let encoded = serde_json::to_value(&report).unwrap();
    assert_eq!(encoded["omitted_rows"], 3);
    assert!(!report.limitations.is_empty());

    let mut structure = StructuredResult::empty();
    structure.variables =
        (0..MAX_FRAME_PAGE + 1).map(|index| variable(&format!("p{index}"), "local", Vec::new())).collect();
    let (mut report, _) = native_workset(decompilation(structure));
    page(&mut report, &FrameQuery { offset: 0, limit: MAX_FRAME_PAGE, include_tracker: false });
    assert_eq!(report.next_offset, Some(MAX_FRAME_PAGE));
    assert_eq!(report.rows.len(), MAX_FRAME_PAGE);
    assert_eq!(report.omitted_rows, 0);
}

#[test]
fn oversized_split_mapping_is_omitted_whole_with_mapping_and_row_counts() {
    let mut huge = storage("join", Some("join"), Some("0x1"));
    huge["pieces"] = json!(vec![
        json!({
            "kind": "processor", "space": "register", "address": "0x0", "size": 1, "logical_offset": 0
        });
        MAX_FRAME_WORK
    ]);
    let mut structure = StructuredResult::empty();
    structure.variables = vec![variable("huge", "local", vec![huge]), variable("visible", "local", Vec::new())];
    let (mut report, work) = native_workset(decompilation(structure));
    page(&mut report, &FrameQuery::default());
    assert_eq!(work, 1);
    assert_eq!(report.total_rows, 2);
    assert_eq!(report.omitted_rows, 1);
    assert_eq!(report.native.omitted_mappings, 1);
    assert_eq!(report.rows[0].native_variable.as_ref().unwrap().name, "visible");
}

#[test]
fn paging_preserves_complete_large_rows_for_the_callers_complete_envelope_byte_budget() {
    let large_name = "native_name_".repeat(16_384);
    let mut structure = StructuredResult::empty();
    structure.variables = vec![
        variable("small", "local", Vec::new()),
        variable(&large_name, "local", vec![storage("dynamic", None, None)]),
    ];
    let (mut first, _) = native_workset(decompilation(structure.clone()));
    let (mut second, _) = native_workset(decompilation(structure));
    page(&mut first, &FrameQuery { offset: 0, limit: 1, include_tracker: false });
    page(&mut second, &FrameQuery { offset: 1, limit: 1, include_tracker: false });
    assert_eq!(first.next_offset, Some(1));
    assert!(second.next_offset.is_none());
    assert_eq!(second.rows[0].native_variable.as_ref().unwrap().name, large_name);
    assert_eq!(second.rows[0].raw_native_storage.len(), 1);
    assert_eq!(second.omitted_rows, 0);
    let first_bytes = serde_json::to_vec(&first).unwrap();
    let second_bytes = serde_json::to_vec(&second).unwrap();
    assert!(second_bytes.len() > first_bytes.len() + large_name.len());
    let encoded: serde_json::Value = serde_json::from_slice(&second_bytes).unwrap();
    assert_eq!(encoded["rows"][0]["native_variable"]["name"], large_name);
}

#[test]
fn oversized_repeated_metadata_is_bounded_on_every_page_without_reducing_complete_rows() {
    let hostile = format!("{}界🦀", "\u{0001}".repeat(65_536));
    let mut structure = StructuredResult::empty();
    structure.signature.return_type.name = hostile.clone();
    structure.signature.calling_convention = Some(hostile.clone());
    structure.signature.parameters = (0..32)
        .map(|index| {
            serde_json::from_value(json!({
                "name": if index == 0 { "first" } else { hostile.as_str() },
                "data_type": { "name": "undefined8", "size": 8 },
                "storage": storage("processor", Some("register"), Some("0x20"))
            }))
            .unwrap()
        })
        .collect();
    structure.frame_context = Some(
        serde_json::from_value(json!({
            "stack_space": hostile, "address_size_bytes": 8, "base_convention": "unknown",
            "base_register": { "space": hostile, "address": "0x20", "size": 8 }
        }))
        .unwrap(),
    );
    structure.diagnostics = Some(RecoveryDiagnostics {
        bad_data: true,
        unimplemented: true,
        unresolved_calls: 7,
        unresolved_indirect_jumps: 9,
        partial_jump_tables: 11,
        warnings: (0..24)
            .map(|_| rampage_decompiler::results::RecoveryWarning {
                kind: rampage_decompiler::results::WarningKind::Header,
                address: Some(u64::MAX),
                message: hostile.clone(),
            })
            .collect(),
    });
    let full_rows = vec![
        variable("first_complete_parameter", "parameter", vec![storage("processor", Some("register"), Some("0x20"))]),
        variable("second_complete_local", "local", vec![storage("unknown", None, None)]),
    ];
    structure.variables = full_rows.clone();
    for (offset, expected) in full_rows.iter().enumerate() {
        let mut decompiled = decompilation(structure.clone());
        decompiled.name = hostile.clone();
        decompiled.language_id = hostile.clone();
        let (mut report, _) = native_workset(decompiled);
        report.coordinates = (0..24)
            .map(|index| FrameCoordinate {
                id: if index == 0 { "native:register".to_owned() } else { hostile.clone() },
                source: FrameSource::NativeDecompiler,
                space: None,
                origin: None,
            })
            .collect();
        report.tracker.limitations = vec![hostile.clone(); 24];
        page(&mut report, &FrameQuery { offset, limit: 1, include_tracker: true });
        let serialized = serde_json::to_vec(&report).unwrap();
        assert!(serialized.len() < 60_000, "{} bytes at offset {offset}", serialized.len());
        assert!(crate::tools::data_typing_view(&report).is_ok());
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.rows[0].native_variable.as_ref().unwrap().name, expected.name);
        assert_eq!(report.rows[0].raw_native_storage, expected.storage);
        assert_eq!(report.native.recovery_status, RecoveryStatus::Incomplete);
        let diagnostics = report.native.diagnostics.as_ref().unwrap();
        assert!(diagnostics.bad_data && diagnostics.unimplemented);
        assert_eq!(diagnostics.unresolved_calls, 7);
        assert_eq!(diagnostics.unresolved_indirect_jumps, 9);
        assert_eq!(diagnostics.partial_jump_tables, 11);
        assert_eq!(report.metadata.signature_parameters_total, 32);
        assert_eq!(report.native.signature.parameters.len(), 1);
        assert_eq!(report.metadata.signature_parameters_omitted, 31);
        assert_eq!(report.metadata.warnings_total, Some(24));
        assert_eq!(report.metadata.warnings_omitted, 24 - diagnostics.warnings.len());
        assert!(report.metadata.warnings_omitted > 0);
        assert!(report.metadata.frame_context_omitted);
        assert!(report.native.frame_context.is_none());
        assert_eq!(report.metadata.coordinates_total, 24);
        assert_eq!(report.metadata.coordinates_omitted, 23);
        assert_eq!(report.metadata.tracker_limitations_total, 24);
        assert!(report.metadata.tracker_limitations_omitted > 0);
        assert!(report.metadata.text_truncations.iter().any(|entry| {
            entry.path == "native.signature.return_type.name" && entry.original_bytes == hostile.len()
        }));
        assert_eq!(report.omitted_rows, 0);
        bound_frame_header(&mut report);
        assert_eq!(serde_json::to_vec(&report).unwrap(), serialized);
    }
}

#[test]
fn bounded_header_text_clips_only_at_utf8_boundaries_and_reports_original_byte_lengths() {
    let mut structure = StructuredResult::empty();
    structure.signature.return_type.name = "界".repeat(30_000);
    let (mut report, _) = native_workset(decompilation(structure));
    page(&mut report, &FrameQuery { limit: 1, ..Default::default() });
    assert_eq!(report.native.signature.return_type.name.len(), 255);
    assert!(report.metadata.text_truncations.iter().any(|entry| {
        entry.path == "native.signature.return_type.name"
            && entry.original_bytes == 90_000
            && entry.retained_bytes == 255
    }));
    assert!(serde_json::to_vec(&report).unwrap().len() < 60_000);
}

#[test]
fn native_warnings_are_retained_without_changing_types_or_claiming_complete_recovery() {
    let mut structure = StructuredResult::empty();
    structure.variables = vec![variable("state", "local", Vec::new())];
    structure.diagnostics = Some(
        serde_json::from_value(json!({
            "bad_data": false,
            "unimplemented": false,
            "unresolved_calls": 1,
            "unresolved_indirect_jumps": 0,
            "partial_jump_tables": 0,
            "warnings": [{ "kind": "header", "address": u64::MAX, "message": "fixture warning" }]
        }))
        .unwrap(),
    );
    let diagnostics = structure.diagnostics.clone();
    let (report, _) = native_workset(decompilation(structure));
    assert_eq!(report.native.diagnostics, diagnostics);
    assert_eq!(report.native.recovery_status, RecoveryStatus::Warnings);
    assert_eq!(report.rows[0].native_variable.as_ref().unwrap().data_type.name, "undefined8");
    let encoded = serde_json::to_value(&report).unwrap();
    assert_eq!(encoded["native"]["diagnostics"]["warnings"][0]["address"], "0xffffffffffffffff");
}

fn tracker(
    slots: Vec<rampage_analysis::dataflow::StackSlot>,
    registers: Vec<rampage_analysis::dataflow::StackRegisterEvidence>,
) -> rampage_analysis::dataflow::DataFlow {
    rampage_analysis::dataflow::DataFlow {
        constants: Vec::new(),
        stack_slots: slots,
        stack_registers: registers,
        argument_registers: Vec::new(),
        integer_returns: Vec::new(),
        forwarded_loads: Vec::new(),
        indirect_targets: Vec::new(),
        incomplete_instructions: 2,
        limitations: vec!["fixture contains incomplete instruction semantics".to_owned()],
    }
}

#[test]
fn tracker_accesses_register_provenance_and_incomplete_ir_are_preserved_separately() {
    let mut stack = storage("spacebase", Some("stack"), Some("0xfffffffffffffff0"));
    stack["address_size_bytes"] = json!(8);
    let mut structure = StructuredResult::empty();
    structure.variables = vec![variable("native_local", "local", vec![stack])];
    let (mut report, mut work) = native_workset(decompilation(structure));
    let dataflow = tracker(
        vec![rampage_analysis::dataflow::StackSlot {
            offset: -16,
            bits: 64,
            reads: vec![ENTRY + 8],
            writes: vec![ENTRY + 4],
        }],
        vec![rampage_analysis::dataflow::StackRegisterEvidence {
            register: 19,
            offset: -16,
            bits: 64,
            stores: vec![ENTRY + 4],
            restores: vec![ENTRY + 8],
            classification: "matching_register_reload",
            evidence: vec!["entry_register_store", "matching_register_reload"],
            confidence: "ssa_proven",
        }],
    );
    append_tracker(&mut report, &mut work, dataflow);
    page(&mut report, &FrameQuery::default());
    assert_eq!(report.rows.len(), 3);
    assert_eq!(report.rows[0].coordinate_id.as_deref(), Some("native:stack"));
    assert_eq!(report.rows[1].coordinate_id.as_deref(), Some("tracker:entry_sp"));
    assert_eq!(report.rows[2].category, FrameCategory::RegisterEvidence);
    assert!(!report.rows[1].editable);
    assert!(!report.rows[2].editable);
    assert_eq!(report.rows[2].register_evidence.as_ref().unwrap().confidence, "ssa_proven");
    assert_eq!(report.tracker.incomplete_instructions, Some(2));
    assert_eq!(report.tracker.limitations.len(), 1);
    let encoded = serde_json::to_value(report).unwrap();
    assert_eq!(encoded["rows"][1]["tracker_slot"]["offset"], "-16");
    assert_eq!(encoded["rows"][1]["tracker_slot"]["writes"][0], format!("{:#x}", ENTRY + 4));
    assert_eq!(encoded["rows"][2]["register_evidence"]["offset"], "-16");
}

#[test]
fn native_and_tracker_rows_share_the_work_bound_and_report_tracker_omissions() {
    let mut structure = StructuredResult::empty();
    structure.variables =
        (0..MAX_FRAME_WORK - 1).map(|index| variable(&format!("v{index}"), "local", Vec::new())).collect();
    let (mut report, mut work) = native_workset(decompilation(structure));
    append_tracker(
        &mut report,
        &mut work,
        tracker(
            (0..3)
                .map(|index| rampage_analysis::dataflow::StackSlot {
                    offset: index * 8,
                    bits: 64,
                    reads: Vec::new(),
                    writes: vec![ENTRY],
                })
                .collect(),
            Vec::new(),
        ),
    );
    page(&mut report, &FrameQuery { offset: MAX_FRAME_WORK - 1, limit: 1, include_tracker: true });
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].category, FrameCategory::TrackerSlot);
    assert_eq!(report.tracker.slot_total, 3);
    assert_eq!(report.tracker.omitted_slots, 2);
    assert_eq!(report.omitted_rows, 2);
    assert_eq!(work, MAX_FRAME_WORK);
}

struct AnnotationFixture(PathBuf);

impl AnnotationFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "rampage-frame-api-{}-{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )))
    }

    fn lock_path(&self) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
        path.push(".lock");
        PathBuf::from(path)
    }

    fn project(&self, worker: Option<WorkerConfig>) -> Project {
        let binary = rampage_loaders::Binary::from_snapshot_bytes(
            include_bytes!("../../../tests/data/local-variables-x64.snapshot.json").to_vec(),
        )
        .unwrap();
        let project = Project::with_annotations(binary, Annotations::open_checked(self.0.clone()).unwrap());
        project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
            compiler: Some("gcc".to_owned()),
            ..Default::default()
        }));
        project.set_decompiler_worker(worker);
        project
    }
}

impl Drop for AnnotationFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.lock_path());
    }
}

fn current_names_and_types(worker: Option<WorkerConfig>) {
    let fixture = AnnotationFixture::new();
    let project = fixture.project(worker);
    let report = project.function_frame(ENTRY, &FrameQuery::default()).unwrap();
    assert!(report.native.available);
    assert!(!report.tracker.available);
    assert!(report.tracker.unavailable_reason.as_deref().unwrap().contains("no SSA"));
    assert!(!fixture.0.exists());
    assert!(!fixture.lock_path().exists());
    let local = report
        .rows
        .iter()
        .find_map(|row| {
            row.native_variable.as_ref().filter(|variable| {
                variable.editable
                    && variable.kind == VariableKind::Local
                    && variable
                        .storage
                        .as_ref()
                        .is_some_and(|storage| storage.kind == StorageKind::Spacebase && storage.size == 8)
            })
        })
        .unwrap();
    let selector = local.storage.clone().unwrap();
    let key = local.key.clone();
    assert!(report.rows.iter().any(|row| row.category == FrameCategory::Parameter));
    project.set_types(ENTRY, Some("struct frameState { int4 gain; int4 bias; }; ")).unwrap();
    project
        .edit_variable(
            ENTRY,
            &VariableEditRequest {
                storage: Some(selector.clone()),
                name: Some("frame_state".to_owned()),
                data_type: Some("struct frameState *".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
    let log = std::fs::read(&fixture.0).unwrap();
    let report = project.function_frame(ENTRY + 1, &FrameQuery::default()).unwrap();
    assert_eq!(report.address, ENTRY);
    let edited = report
        .rows
        .iter()
        .find_map(|row| row.native_variable.as_ref().filter(|variable| variable.storage.as_ref() == Some(&selector)))
        .unwrap();
    assert_eq!(edited.name, "frame_state");
    assert!(edited.data_type.name.contains("frameState"));
    assert_eq!(edited.key, key);
    assert!(edited.editable);
    assert_eq!(std::fs::read(&fixture.0).unwrap(), log);
    let encoded = serde_json::to_value(&report).unwrap();
    assert!(encoded["rows"].as_array().unwrap().iter().any(|row| { row["native_variable"]["name"] == "frame_state" }));
}

#[test]
fn native_frame_uses_current_storage_keyed_edits_without_read_side_effects() {
    current_names_and_types(None);
}

#[test]
fn supervised_frame_uses_current_storage_keyed_edits_without_fallback() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    current_names_and_types(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
}

#[test]
fn missing_configured_worker_is_an_error_not_empty_native_evidence() {
    let fixture = AnnotationFixture::new();
    let missing = fixture.0.with_extension("missing-worker");
    let project = fixture.project(Some(WorkerConfig { executable: Some(missing), ..Default::default() }));
    assert!(project.function_frame(ENTRY, &FrameQuery::default()).is_err());
    assert!(!fixture.0.exists());
    assert!(!fixture.lock_path().exists());
}

#[test]
fn frame_summary_infrastructure_errors_cannot_be_downgraded_to_unavailable_success() {
    let (mut report, mut work) = native_workset(decompilation(StructuredResult::empty()));
    report.tracker.requested = true;
    let result =
        append_frame_summary(&mut report, &mut work, Err(ApiError::Unavailable("configured worker failed".to_owned())));
    assert!(matches!(result, Err(ApiError::Unavailable(message)) if message == "configured worker failed"));
    assert!(!report.tracker.available);
    assert!(report.rows.is_empty());
}

#[test]
fn frame_tracker_ir_does_not_render_operand_annotations_or_launch_native_type_workers() {
    use crate::annotations::{Field, OperandTypeAnnotation, OperandTypeKind, encode_operand_types};

    let mut annotations = Annotations::in_memory();
    annotations
        .set(
            Field::OperandType,
            0x210124,
            Some(
                encode_operand_types(&[OperandTypeAnnotation {
                    operand: 1,
                    kind: OperandTypeKind::Enum,
                    type_name: "Mode".to_owned(),
                    instruction_hex: "ffc300d1".to_owned(),
                }])
                .unwrap(),
            ),
        )
        .unwrap();
    let binary = rampage_loaders::Binary::from_snapshot_bytes(
        include_bytes!("../../../tests/data/function-frame-arm64.snapshot.json").to_vec(),
    )
    .unwrap();
    let project = Project::with_annotations(binary, annotations);
    let fixture = AnnotationFixture::new();
    project.set_decompiler_worker(Some(WorkerConfig {
        executable: Some(fixture.0.with_extension("missing-worker")),
        ..Default::default()
    }));

    assert!(project.function_summary(0x210124).is_err());
    let summary = project.function_summary_for_frame(0x210124).unwrap();
    assert!(summary.dataflow.is_some());
    assert!(summary.graph.blocks.iter().flat_map(|block| &block.lines).all(|line| line.operand_annotations.is_empty()));
    let (mut report, mut work) = native_workset(decompilation(StructuredResult::empty()));
    append_frame_summary(&mut report, &mut work, Ok(summary)).unwrap();
    assert!(report.tracker.available);
    assert!(report.tracker.slot_total > 0);
    assert!(project.function_frame(0x210124, &FrameQuery::default()).is_err());
    assert!(!fixture.0.exists());
    assert!(!fixture.lock_path().exists());
}

#[test]
fn invalid_page_limit_is_rejected_before_native_work() {
    let fixture = AnnotationFixture::new();
    let project = fixture.project(None);
    for limit in [0, MAX_FRAME_PAGE + 1, usize::MAX] {
        assert!(matches!(
            project.function_frame(ENTRY, &FrameQuery { limit, ..Default::default() }),
            Err(ApiError::Invalid(_))
        ));
    }
    assert!(!fixture.0.exists());
    assert!(!fixture.lock_path().exists());
}

#[test]
fn owned_arm64_frame_includes_stack_access_and_register_evidence_without_coordinate_merging() {
    let binary = rampage_loaders::Binary::from_snapshot_bytes(
        include_bytes!("../../../tests/data/function-frame-arm64.snapshot.json").to_vec(),
    )
    .unwrap();
    let project = Project::with_annotations(binary, Annotations::default());
    let report = project.function_frame(0x210124, &FrameQuery::default()).unwrap();
    assert!(report.native.available);
    assert!(report.native.frame_context.is_some());
    assert!(report.tracker.available, "{:?}", report.tracker.unavailable_reason);
    assert!(report.rows.iter().any(|row| row.category == FrameCategory::TrackerSlot));
    assert!(report.rows.iter().any(|row| {
        row.register_evidence.as_ref().is_some_and(|evidence| {
            evidence.register == 19
                && evidence.classification == "reload_candidate"
                && evidence.confidence == "conditional"
                && evidence.stores.is_empty()
        })
    }));
    assert!(
        report
            .rows
            .iter()
            .filter_map(|row| row.register_evidence.as_ref())
            .all(|evidence| evidence.classification != "matching_register_reload")
    );
    for row in &report.rows {
        if row.source == FrameSource::StackTracker {
            assert_eq!(row.coordinate_id.as_deref(), Some("tracker:entry_sp"));
            assert!(row.raw_native_storage.is_empty());
            assert!(row.native_variable.is_none());
            assert!(!row.editable);
        }
    }
    let native_only =
        project.function_frame(0x210124, &FrameQuery { include_tracker: false, ..Default::default() }).unwrap();
    assert!(!native_only.tracker.requested);
    assert!(!native_only.tracker.available);
    assert!(native_only.rows.iter().all(|row| row.source == FrameSource::NativeDecompiler));
    assert_eq!(native_only.native.signature, report.native.signature);
}
