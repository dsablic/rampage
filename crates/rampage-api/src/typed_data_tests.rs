use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decompiler::worker::WorkerConfig;
use rampage_loaders::Binary;

use super::*;
use crate::{DeclareTypesRequest, DecompilerOptions};

fn binary() -> Binary {
    Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64",
            "target": {"platform": "default", "compiler": "gcc"},
            "provenance": "Owned typed data snapshot; bytes are inspected, never executed",
            "regions": [
                {"name": "read_records", "address": "0x1000", "permissions": "r-x",
                 "bytes": "8b05fe0f0000030508100000c3"},
                {"name": "records", "address": "0x2000", "permissions": "rw-",
                 "bytes": "010000002a000000616263000000000002000000f9ffffff78797a0000000000"}
            ], "entry": "0x1000", "seeds": ["0x1000"]
        }))
        .unwrap(),
    )
    .unwrap()
}

fn project(annotations: Annotations, worker: Option<WorkerConfig>) -> Project {
    let project = Project::with_annotations(binary(), annotations);
    project.set_decompiler_options(Some(DecompilerOptions { compiler: Some("gcc".into()), ..Default::default() }));
    project.set_decompiler_worker(worker);
    project
}

fn records() -> ApplyDataTypeRequest {
    ApplyDataTypeRequest { type_name: Some("Record".into()), count: Some(2), ..Default::default() }
}

#[test]
fn native_char_is_a_type_selector_not_a_variable_identifier() {
    let project = project(Annotations::in_memory(), None);
    let applied = project
        .apply_data_type(
            0x2000,
            &ApplyDataTypeRequest { type_name: Some("char".into()), count: Some(4), ..Default::default() },
        )
        .unwrap();
    assert_eq!(applied.binding.unwrap().byte_length, 4);
    let data = project.read_data(&TypedDataQuery { address: 0x2000, size: Some(4) }).unwrap();
    assert_eq!(data.objects[0].binding.type_name.as_deref(), Some("char"));
    assert!(!data.objects[0].fields.is_empty());
}

#[test]
fn shared_typed_binding_name_conflicts_block_rename_undo_and_redo_without_writing() {
    for redo in [false, true] {
        let log = Log::new();
        let client = project(log.annotations(), None);
        client.rename(0x2000, Some("custom")).unwrap();
        if redo {
            client.rename(0x2000, None).unwrap();
            client.undo().unwrap();
        }
        let other = project(log.annotations(), None);
        other.rename(0x2010, Some("data_2000")).unwrap();
        other
            .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() })
            .unwrap();
        let accepted = log.bytes();
        let result = if redo { client.redo() } else { client.undo() };
        assert!(result.is_err());
        assert_eq!(log.bytes(), accepted);
        assert_eq!(client.name_at(0x2000).as_deref(), Some("custom"));
        assert!(other.read_data(&TypedDataQuery { address: 0x2000, size: Some(4) }).is_ok());
    }
}

fn declare(project: &Project, text: &str, replace: bool) -> Result<crate::TypeLibraryEdit, ApiError> {
    project.declare_types(&DeclareTypesRequest { declarations: Some(text.into()), replace, ..Default::default() })
}

fn declare_records(project: &Project) {
    declare(project, "enum Mode { first = 1, second = 2 };", false).unwrap();
    declare(project, "struct Record { Mode mode; int4 value; char label[8]; };", false).unwrap();
}

struct Log(PathBuf);

impl Log {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "rampage-typed-data-{}-{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn annotations(&self) -> Annotations {
        Annotations::open_checked(self.0.clone()).unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap_or_default()
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

fn native_replay(worker: Option<WorkerConfig>) {
    let log = Log::new();
    let project = project(log.annotations(), worker.clone());
    declare_records(&project);
    let original = project.binary.image_bytes().to_vec();
    let edit = project.apply_data_type(0x2000, &records()).unwrap();
    assert_eq!(edit.binding.as_ref().unwrap().byte_length, 32);
    assert_eq!(edit.native_declaration.as_deref(), Some("Record data_2000[2];"));
    let code = project.decompile(0x1000).unwrap().code;
    assert!(code.contains("value"), "{code}");
    assert!(code.contains("data_2000"), "{code}");
    let exact = project
        .decompile_entry(&crate::DecompileEntryRequest {
            address: 0x1000,
            validation: crate::EntryValidation::AnalystAsserted,
        })
        .unwrap();
    assert!(exact.decompilation.code.contains("value"), "{}", exact.decompilation.code);
    assert!(exact.decompilation.code.contains("data_2000"), "{}", exact.decompilation.code);
    assert_eq!(project.binary.image_bytes(), original);
    let accepted = log.bytes();
    assert!(!project.apply_data_type(0x2000, &records()).unwrap().changed);
    assert_eq!(log.bytes(), accepted);
    let reopened = super::tests::project(log.annotations(), worker);
    assert_eq!(reopened.decompile(0x1000).unwrap().code, code);
    project.undo().unwrap();
    assert!(project.annotations().data_types().is_empty());
    project.redo().unwrap();
    assert_eq!(project.decompile(0x1000).unwrap().code, code);
}

#[test]
fn native_array_bindings_change_real_c_and_survive_history_and_reopen() {
    native_replay(None);
}

#[test]
fn worker_array_bindings_match_native_without_fallback() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    native_replay(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
}

#[test]
fn fixed_footprints_reject_library_size_changes_missing_types_and_manual_global_collisions() {
    let project = project(Annotations::in_memory(), None);
    declare_records(&project);
    project.apply_data_type(0x2000, &records()).unwrap();
    let before = serde_json::to_value(project.annotation_list()).unwrap();
    assert!(declare(&project, "struct Record { Mode mode; int4 value; char label[16]; };", true).is_err());
    assert!(project.delete_type("Record").is_err());
    assert!(project.set_global(0x2004, Some("int4 manual; ")).is_err());
    assert!(project.set_global(0x2000, Some("Record manual[2];")).is_err());
    assert!(
        project
            .apply_data_type(0x2008, &ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() })
            .is_err()
    );
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
    declare(&project, "struct Record { Mode mode; int4 renamed; char label[8]; };", true).unwrap();
    assert!(project.decompile(0x1000).unwrap().code.contains("renamed"));
    assert!(
        project
            .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("Missing".into()), ..Default::default() })
            .is_err()
    );
}

#[test]
fn manual_arrays_are_accepted_when_disjoint_and_refuse_enclosing_overlap() {
    let project = project(Annotations::in_memory(), None);
    project.set_global(0x2000, Some("int4 manual[2];")).unwrap();
    assert!(
        project
            .apply_data_type(0x2004, &ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() })
            .is_err()
    );
    project
        .apply_data_type(
            0x2010,
            &ApplyDataTypeRequest { type_name: Some("int4".into()), count: Some(2), ..Default::default() },
        )
        .unwrap();
}

#[test]
fn response_preflight_failure_publishes_no_edit_or_history() {
    let log = Log::new();
    let project = project(log.annotations(), None);
    declare_records(&project);
    let before = log.bytes();
    let revision = project.annotation_revision().unwrap();
    let error = project
        .apply_data_type_with_preflight(0x2000, &records(), |edit| {
            assert!(edit.changed);
            assert_eq!(edit.binding.as_ref().unwrap().byte_length, 32);
            Err(invalid("response refused"))
        })
        .unwrap_err();
    assert!(error.to_string().contains("response refused"));
    assert_eq!(log.bytes(), before);
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    assert!(project.annotations().data_types().is_empty());
    assert_eq!(project.undo().unwrap()[0].field, Field::TypeLibrary);
}

#[test]
fn another_client_blocks_undo_of_a_changed_binding() {
    let log = Log::new();
    let first = project(log.annotations(), None);
    first
        .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() })
        .unwrap();
    let second = project(log.annotations(), None);
    second
        .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("uint4".into()), ..Default::default() })
        .unwrap();
    let accepted = log.bytes();
    assert!(first.undo().is_err());
    assert_eq!(log.bytes(), accepted);
}

#[test]
fn absent_workers_never_fall_back_or_append_bindings() {
    let project = project(
        Annotations::in_memory(),
        Some(WorkerConfig {
            executable: Some(PathBuf::from("/nonexistent/rampage-typed-data-worker")),
            ..Default::default()
        }),
    );
    assert!(
        project
            .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() })
            .is_err()
    );
    assert!(project.annotations().data_types().is_empty());
}

#[test]
fn strict_strings_preserve_unicode_and_reject_invalid_code_units_without_lossy_replacement() {
    let text = "e\u{301}\u{1f600}\0";
    assert_eq!(decode_string(text.as_bytes(), DataStringEncoding::Utf8).unwrap(), text);
    let little: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let big: Vec<_> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    assert_eq!(decode_string(&little, DataStringEncoding::Utf16Le).unwrap(), text);
    assert_eq!(decode_string(&big, DataStringEncoding::Utf16Be).unwrap(), text);
    for (bytes, encoding) in [
        (&[0xff][..], DataStringEncoding::Utf8),
        (&[0xc0, 0xaf][..], DataStringEncoding::Utf8),
        (&[0x00, 0xd8][..], DataStringEncoding::Utf16Le),
        (&[0xdc, 0x00][..], DataStringEncoding::Utf16Be),
        (&[0x61][..], DataStringEncoding::Utf16Le),
        (&[0x80][..], DataStringEncoding::Ascii),
    ] {
        assert!(decode_string(bytes, encoding).is_err());
    }
}

#[test]
fn native_negative_enum_identity_labels_the_signed_word_in_an_owned_snapshot() {
    let binary = Binary::from_snapshot_bytes(
        serde_json::to_vec(&json!({
            "format": "rampage-snapshot-v1", "arch": "x86_64",
            "target": {"platform": "default", "compiler": "gcc"},
            "provenance": "Owned negative enum data; inspected, never executed",
            "regions": [
                {"name": "return", "address": "0x1000", "permissions": "r-x", "bytes": "c3"},
                {"name": "mode", "address": "0x2000", "permissions": "rw-", "bytes": "fdffffff"}
            ], "entry": "0x1000", "seeds": ["0x1000"]
        }))
        .unwrap(),
    )
    .unwrap();
    let project = Project::new(binary);
    declare(&project, "enum TypedMode { MODE_OFF = 0, MODE_READY = 7, MODE_FAULT = -3 };", false).unwrap();
    let metadata = project.get_type("TypedMode").unwrap().metadata;
    assert!(metadata.enum_values.iter().any(|entry| entry.name == "MODE_FAULT" && entry.value == "-3"));
    let identity = metadata.identity.as_ref().unwrap();
    assert!(
        identity["enum_values"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["name"] == "MODE_FAULT" && entry["value"] == "4294967293" })
    );
    let value = scalar_value(&[0xfd, 0xff, 0xff, 0xff], identity["kind"].as_u64(), false, identity).unwrap();
    assert_eq!(value["decimal"], "-3");
    assert_eq!(value["enum_names"], json!(["MODE_FAULT"]));
    project
        .apply_data_type(0x2000, &ApplyDataTypeRequest { type_name: Some("TypedMode".into()), ..Default::default() })
        .unwrap();
    let report = project.read_data(&TypedDataQuery { address: 0x2000, size: Some(4) }).unwrap();
    let value = report.objects[0].fields[0].value.as_ref().unwrap();
    assert_eq!(value["decimal"], "-3");
    assert_eq!(value["enum_names"], json!(["MODE_FAULT"]));
}

#[test]
fn enum_alias_matching_compares_exact_width_bit_patterns_without_changing_signed_display() {
    let identity = json!({"enum_values": [
        {"name": "signed_alias", "value": "-3"},
        {"name": "unsigned_alias", "value": "4294967293"},
        {"name": "different", "value": "7"},
        {"name": "invalid", "value": "not decimal"}
    ]});
    let value = scalar_value(&[0xfd, 0xff, 0xff, 0xff], Some(14), false, &identity).unwrap();
    assert_eq!(value["decimal"], "-3");
    assert_eq!(value["enum_names"], json!(["signed_alias", "unsigned_alias"]));
    assert_eq!(enum_value_bits("-170141183460469231731687303715884105728", 16), Some(1u128 << 127));
    assert_eq!(enum_value_bits("340282366920938463463374607431768211455", 16), Some(u128::MAX));
    assert_eq!(enum_value_bits("340282366920938463463374607431768211456", 16), None);
}

#[test]
fn exact_scalars_obey_data_byte_order_preserve_nonfinite_bits_and_never_dereference_pointers() {
    assert_eq!(scalar_value(&[0x12, 0x34, 0x56, 0x78], Some(13), true, &json!({})).unwrap()["decimal"], "305419896");
    assert_eq!(scalar_value(&[0xff; 8], Some(13), false, &json!({})).unwrap()["decimal"], "18446744073709551615");
    assert_eq!(scalar_value(&[0xff; 8], Some(14), true, &json!({})).unwrap()["decimal"], "-1");
    for bits in [f64::NAN.to_bits(), f64::INFINITY.to_bits(), f64::NEG_INFINITY.to_bits()] {
        let value = scalar_value(&bits.to_le_bytes(), Some(10), false, &json!({})).unwrap();
        assert_eq!(value["finite"], false);
        assert!(value["display"].is_string());
        assert!(serde_json::to_string(&value).is_ok());
    }
    let pointer = scalar_value(&0x2000u64.to_le_bytes(), Some(9), false, &json!({})).unwrap();
    assert_eq!(pointer["dereferenced"], false);
    assert!(pointer.get("resolved_target").is_none());
}

#[test]
fn native_image_reads_decode_the_exact_stored_window_without_mutating_annotations() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let binary = Binary::open(path).unwrap();
    let address = binary
        .segments
        .iter()
        .find(|segment| segment.perms.read && !segment.perms.execute && segment.file_size >= 4)
        .unwrap()
        .address;
    let bytes: [u8; 4] = binary.read(address, 4).unwrap().try_into().unwrap();
    let expected = if binary.big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) };
    let project = Project::new(binary);
    project
        .apply_data_type(address, &ApplyDataTypeRequest { type_name: Some("uint4".into()), ..Default::default() })
        .unwrap();
    let revision = project.annotation_revision().unwrap();
    let report = project.read_data(&TypedDataQuery { address, size: Some(4) }).unwrap();
    assert_eq!(report.objects.len(), 1);
    assert_eq!(report.objects[0].fields[0].value.as_ref().unwrap()["decimal"], expected.to_string());
    assert_eq!(report.objects[0].fields[0].raw_hex.as_deref(), Some(rampage_arch::hex::bytes(&bytes).as_str()));
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    let partial = project.read_data(&TypedDataQuery { address: address + 1, size: Some(2) }).unwrap();
    assert_eq!(partial.objects[0].fields[0].status, "partial");
    assert!(partial.objects[0].fields[0].value.is_none());
    assert!(project.read_data(&TypedDataQuery { address, size: Some(crate::MAX_DATA_BYTES + 1) }).is_err());
}

#[test]
fn invalid_assignments_refuse_code_gaps_bad_lengths_and_ambiguous_strings() {
    let project = project(Annotations::in_memory(), None);
    for (address, request) in [
        (0x1000, ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() }),
        (0x1fff, ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() }),
        (0x201f, ApplyDataTypeRequest { type_name: Some("int4".into()), ..Default::default() }),
        (
            u64::MAX,
            ApplyDataTypeRequest {
                encoding: Some(DataStringEncoding::Utf8),
                byte_length: Some(4),
                ..Default::default()
            },
        ),
        (0x2000, ApplyDataTypeRequest { type_name: Some("int4".into()), count: Some(0), ..Default::default() }),
        (0x2000, ApplyDataTypeRequest { type_name: Some("int4".into()), byte_length: Some(8), ..Default::default() }),
        (
            0x2000,
            ApplyDataTypeRequest {
                encoding: Some(DataStringEncoding::Utf8),
                count: Some(2),
                byte_length: Some(4),
                ..Default::default()
            },
        ),
        (
            0x2000,
            ApplyDataTypeRequest {
                type_name: Some("int4".into()),
                encoding: Some(DataStringEncoding::Utf8),
                byte_length: Some(4),
                ..Default::default()
            },
        ),
        (0x2000, ApplyDataTypeRequest { clear: true, count: Some(1), ..Default::default() }),
    ] {
        assert!(project.apply_data_type(address, &request).is_err(), "{request:?}");
    }
    assert!(project.annotations().data_types().is_empty());
}

fn raw(bytes: &[u8]) -> DataInspection {
    DataInspection {
        format: rampage_loaders::Format::Elf,
        arch: rampage_arch::Arch::X86_64,
        module_uuid: None,
        selected_image_file_offset: Some(0),
        selected_image_size: bytes.len() as u64,
        backing_metadata_checked: false,
        loader_diagnostics: crate::data::DataLoaderDiagnostics {
            warnings_total: 0,
            warnings_omitted: 0,
            truncated: false,
            warnings: Vec::new(),
        },
        pointer_targets_suppressed: false,
        address: 0x2000,
        size: bytes.len(),
        word_size: 8,
        data_big_endian: false,
        trailing_bytes: bytes.len() % 8,
        spans: vec![crate::DataSpan {
            address: 0x2000,
            size: bytes.len(),
            status: DataStatus::Stored,
            image_offset: Some(0),
            file_offset: Some(0),
            permissions: None,
            hex: Some(rampage_arch::hex::bytes(bytes)),
            ascii: None,
        }],
        words: Vec::new(),
        limitations: Vec::new(),
    }
}

#[test]
fn partial_and_zero_fill_fields_never_gain_invented_values() {
    let mut raw = raw(&[1, 2]);
    let mut decoder =
        Decoder { types: &[], bytes: window_bytes(&raw).unwrap(), raw: &raw, big_endian: false, nodes: 0 };
    let field = decoder.field("object.value", "int4", 0x2000, 0x2000, 4, false).unwrap();
    assert_eq!(field.status, "partial");
    assert_eq!(field.raw_hex.as_deref(), Some("0102"));
    assert_eq!(field.raw_size, 2);
    assert!(field.value.is_none());
    raw.spans[0].status = DataStatus::ZeroFill;
    raw.spans[0].hex = None;
    let mut decoder =
        Decoder { types: &[], bytes: window_bytes(&raw).unwrap(), raw: &raw, big_endian: false, nodes: 0 };
    let field = decoder.field("object.value", "uint2", 0x2000, 0x2000, 2, false).unwrap();
    assert_eq!(field.status, "zero_fill");
    assert!(field.raw_hex.is_none());
    assert!(field.value.is_none());
}

#[test]
fn anonymous_arrays_and_union_candidates_use_native_identity_not_display_type_parsing() {
    let raw = raw(&[1, 2, 3, 4]);
    let mut decoder =
        Decoder { types: &[], bytes: window_bytes(&raw).unwrap(), raw: &raw, big_endian: false, nodes: 0 };
    let identity = json!({"kind": 3, "size": 4, "fields": [
        {"name": "whole", "offset": 0, "type": {"kind": 13, "size": 4}},
        {"name": "bytes", "offset": 0, "type": {"kind": 7, "size": 4, "length": 4,
            "element": {"kind": 13, "size": 1}}}
    ]});
    let mut fields = Vec::new();
    decoder
        .decode_identity(
            DecodeSite { path: "data_2000", base: 0x2000, address: 0x2000, union: false, depth: 0 },
            "not parsed as C",
            &identity,
            4,
            &mut fields,
        )
        .unwrap();
    assert_eq!(
        fields.iter().find(|field| field.path == "data_2000.whole").unwrap().value.as_ref().unwrap()["decimal"],
        "67305985"
    );
    let last = fields.iter().find(|field| field.path == "data_2000.bytes[3]").unwrap();
    assert!(last.union_candidate);
    assert_eq!(last.offset, 3);
    assert_eq!(last.value.as_ref().unwrap()["decimal"], "4");
}

#[test]
fn oversized_views_refuse_instead_of_returning_a_truncated_field_list() {
    let raw = raw(&[1; 300]);
    let mut decoder =
        Decoder { types: &[], bytes: window_bytes(&raw).unwrap(), raw: &raw, big_endian: false, nodes: 0 };
    let identity = json!({"kind": 7, "size": 300, "length": 300, "element": {"kind": 13, "size": 1}});
    assert!(
        decoder
            .decode_identity(
                DecodeSite { path: "data", base: 0x2000, address: 0x2000, union: false, depth: 0 },
                "anonymous array",
                &identity,
                300,
                &mut Vec::new(),
            )
            .is_err()
    );
}

#[test]
fn pointer_typedefs_do_not_query_or_decode_their_cyclic_pointee_graph() {
    let identity = json!({"kind": 9, "size": 8,
        "typedef": {"reference": "NodePtr"}, "target": {"reference": "Node"}});
    let mut names = BTreeSet::new();
    identity_references(&identity, &mut names, 0, &mut 0).unwrap();
    assert!(names.is_empty());
    let raw = raw(&0x2000u64.to_le_bytes());
    let mut decoder =
        Decoder { types: &[], bytes: window_bytes(&raw).unwrap(), raw: &raw, big_endian: false, nodes: 0 };
    let mut fields = Vec::new();
    decoder
        .decode_identity(
            DecodeSite { path: "data", base: 0x2000, address: 0x2000, union: false, depth: 0 },
            "NodePtr",
            &identity,
            8,
            &mut fields,
        )
        .unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value.as_ref().unwrap()["raw_address"], "0x0000000000002000");
}
