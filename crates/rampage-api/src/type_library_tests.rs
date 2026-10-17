use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decompiler::worker::WorkerConfig;
use rampage_loaders::Binary;

use super::*;
use crate::{DecompileEntryRequest, EntryValidation, NamedTypeKind};

const ENTRY: u64 = 0x4000ae;

#[test]
fn empty_history_does_not_create_annotation_files_or_lockfiles() {
    for checked in [false, true] {
        let log = LogFixture::new();
        let annotations = if checked { log.annotations() } else { Annotations::open(log.0.clone()).unwrap() };
        let project = project(annotations, None);
        assert!(project.undo().unwrap().is_empty());
        assert!(project.redo().unwrap().is_empty());
        assert!(!log.0.exists());
        let mut lock = log.0.as_os_str().to_owned();
        lock.push(".lock");
        assert!(!PathBuf::from(lock).exists());
    }
}

#[test]
fn bundled_c_posix_and_windows_types_use_explicit_target_profiles_and_keep_opaque_layouts_unknown() {
    let linux = project(Annotations::in_memory(), None);
    linux
        .declare_types(&DeclareTypesRequest { profiles: vec!["c".into(), "posix-linux".into()], ..Default::default() })
        .unwrap();
    let file = linux.get_type("FILE").unwrap().metadata;
    assert!(file.incomplete);
    assert_eq!(file.size, None);
    assert!(file.fields.is_empty());
    let socket = linux.get_type("sockaddr").unwrap().metadata;
    assert_eq!(socket.size, Some(16));
    assert!(socket.fields.iter().any(|field| field.name == "sa_family" && field.offset == 0 && field.size == Some(2)));
    assert!(socket.fields.iter().any(|field| field.name == "sa_data" && field.offset == 2 && field.size == Some(14)));
    let before = linux.annotation_list();
    assert!(
        linux.declare_types(&DeclareTypesRequest { profiles: vec!["win32".into()], ..Default::default() }).is_err()
    );
    assert_eq!(serde_json::to_value(linux.annotation_list()).unwrap(), serde_json::to_value(before).unwrap());
    for (arch, pointer) in [("x86", 4), ("x86_64", 8)] {
        let binary = Binary::from_snapshot_bytes(
            serde_json::to_vec(&serde_json::json!({
                "format":"rampage-snapshot-v1", "arch":arch,
                "provenance":"Owned return-only fixture with explicitly selected Windows compiler types",
                "regions":[{"name":"owned-return","address":"0x1000","permissions":"r-x","bytes":"c3"}],
                "entry":"0x1000", "seeds":["0x1000"],
            }))
            .unwrap(),
        )
        .unwrap();
        let windows = Project::with_annotations(binary, Annotations::in_memory());
        windows.set_decompiler_options(Some(DecompilerOptions {
            platform: rampage_decompiler::Platform::Windows,
            compiler: Some("windows".into()),
            ..Default::default()
        }));
        windows.declare_types(&DeclareTypesRequest { profiles: vec!["win32".into()], ..Default::default() }).unwrap();
        for (name, size) in [("HANDLE", pointer), ("DWORD", 4), ("BOOL", 4), ("WCHAR", 2), ("LARGE_INTEGER", 8)] {
            assert_eq!(windows.get_type(name).unwrap().metadata.size, Some(size), "{arch} {name}");
        }
        let large = windows.get_type("LARGE_INTEGER").unwrap().metadata;
        let native_union =
            if let Some(target) = large.target { windows.get_type(&target).unwrap().metadata } else { large };
        assert!(native_union.fields.iter().any(|field| field.name == "u" && field.offset == 0));
        assert!(native_union.fields.iter().any(|field| field.name == "QuadPart" && field.offset == 0));
    }
}

fn binary() -> Binary {
    Binary::from_snapshot_bytes(include_bytes!("../../../tests/data/local-variables-x64.snapshot.json").to_vec())
        .unwrap()
}

fn project(annotations: Annotations, worker: Option<WorkerConfig>) -> Project {
    let project = Project::with_annotations(binary(), annotations);
    project.set_decompiler_options(Some(DecompilerOptions { compiler: Some("gcc".to_owned()), ..Default::default() }));
    project.set_decompiler_worker(worker);
    project
}

fn declaration(text: &str) -> DeclareTypesRequest {
    DeclareTypesRequest { declarations: Some(text.to_owned()), ..Default::default() }
}

struct LogFixture(PathBuf);

impl LogFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-type-library-{}-{index}.jsonl", std::process::id())))
    }

    fn annotations(&self) -> Annotations {
        Annotations::open_checked(self.0.clone()).unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap_or_default()
    }
}

impl Drop for LogFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut lock = self.0.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }
}

#[test]
fn legacy_oversized_comment_keeps_undo_and_redo_compatibility() {
    let log = LogFixture::new();
    let project = project(Annotations::open(log.0.clone()).unwrap(), None);
    let text = "x".repeat(1024 * 1024 + 1);
    project.comment(ENTRY, Some(&text)).unwrap();
    assert_eq!(project.comment_at(ENTRY).as_deref(), Some(text.as_str()));
    let undone = project.undo().unwrap();
    assert_eq!(undone.len(), 1);
    assert_eq!(undone[0].field, Field::Comment);
    assert!(project.comment_at(ENTRY).is_none());
    let redone = project.redo().unwrap();
    assert_eq!(redone, undone);
    assert_eq!(project.comment_at(ENTRY).as_deref(), Some(text.as_str()));
    assert_eq!(Annotations::open(log.0.clone()).unwrap().comment(ENTRY), Some(text.as_str()));
}

#[test]
fn legacy_history_over_1024_regular_steps_keeps_last_step_undoable() {
    let project = project(Annotations::in_memory(), None);
    for step in 0..1025 {
        project.comment(ENTRY, Some(&format!("step {step}"))).unwrap();
    }
    let undone = project.undo().unwrap();
    assert_eq!(undone.len(), 1);
    assert_eq!(project.comment_at(ENTRY).as_deref(), Some("step 1023"));
    assert_eq!(project.redo().unwrap(), undone);
    assert_eq!(project.comment_at(ENTRY).as_deref(), Some("step 1024"));
}

#[test]
fn library_history_rejects_oversized_shared_edits_before_publishing_refresh_or_history() {
    use std::io::Write;

    for redo in [false, true] {
        let log = LogFixture::new();
        let project = project(Annotations::open(log.0.clone()).unwrap(), None);
        project.declare_types(&declaration("typedef int4 HistoryType;")).unwrap();
        if redo {
            project.undo().unwrap();
            assert!(project.annotations().type_library().is_empty());
        }
        let before = serde_json::to_value(project.annotation_list()).unwrap();
        let revision = project.annotation_revision().unwrap();
        let mut external = std::fs::OpenOptions::new().append(true).open(&log.0).unwrap();
        serde_json::to_writer(
            &mut external,
            &crate::annotations::Edit {
                field: Field::Comment,
                address: ENTRY,
                value: Some("x".repeat(1024 * 1024 + 1)),
                previous: None,
            },
        )
        .unwrap();
        external.write_all(b"\n").unwrap();
        drop(external);
        let shared_bytes = log.bytes();
        let result = if redo { project.redo() } else { project.undo() };
        assert!(result.is_err(), "redo={redo}");
        assert_eq!(log.bytes(), shared_bytes, "redo={redo}");
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before, "redo={redo}");
        assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()), "redo={redo}");
    }
}

#[test]
fn serde_and_input_bounds_refuse_unsupported_input_before_native_work() {
    assert!(
        serde_json::from_str::<DeclareTypesRequest>(r#"{"declarations":"typedef int4 X;","unknown":true}"#).is_err()
    );
    let project = Project::new(binary());
    for request in [
        DeclareTypesRequest::default(),
        declaration(&"x".repeat(MAX_TEXT_BYTES + 1)),
        DeclareTypesRequest { header: Some("#include \"private.h\"\n".into()), ..Default::default() },
        DeclareTypesRequest { header: Some("#define X 1\n".into()), ..Default::default() },
        DeclareTypesRequest { packing: Some(3), ..declaration("struct X { int4 value; };") },
    ] {
        assert!(project.declare_types(&request).is_err(), "{request:?}");
        assert!(project.annotations().type_library().is_empty());
    }
}

#[test]
fn unavailable_executable_context_and_missing_worker_never_fall_back() {
    let mut image = binary();
    for segment in &mut image.segments {
        segment.perms.execute = false;
    }
    let project = Project::new(image);
    assert!(project.declare_types(&declaration("typedef int4 T;")).is_err());
    assert!(project.annotations().type_library().is_empty());

    let project = Project::new(binary());
    project.set_decompiler_worker(Some(WorkerConfig {
        executable: Some(PathBuf::from("/nonexistent/rampage-type-library-worker")),
        ..Default::default()
    }));
    assert!(project.list_types(None, 0, 10).is_err());
    assert!(project.get_type("int4").is_err());
    assert!(project.declare_types(&declaration("typedef int4 T;")).is_err());
    assert!(project.annotations().type_library().is_empty());
}

fn crud_layout_and_replay(worker: Option<WorkerConfig>) {
    let log = LogFixture::new();
    let project = project(log.annotations(), worker.clone());
    project.declare_types(&declaration("struct State { int4 gain; int4 bias; }; ")).unwrap();
    let state = project.get_type("State").unwrap();
    assert_eq!(state.metadata.size, Some(8));
    assert_eq!(state.metadata.fields[1].offset, 4);
    let accepted = log.bytes();
    assert!(!project.declare_types(&declaration(" struct State{int4 gain;int4 bias;};")).unwrap().changed);
    assert_eq!(log.bytes(), accepted);
    project.declare_types(&declaration("typedef struct State *StatePtr;")).unwrap();
    let pointer = project.get_type("StatePtr").unwrap();
    assert_eq!(pointer.metadata.size, Some(8));
    assert!(pointer.metadata.dependencies.contains(&"State".to_owned()));
    let accepted = log.bytes();
    assert!(project.delete_type("State").is_err());
    assert_eq!(log.bytes(), accepted);
    project.delete_type("StatePtr").unwrap();
    project.undo().unwrap();
    assert!(project.get_type("StatePtr").is_ok());
    project.redo().unwrap();
    assert!(project.get_type("StatePtr").is_err());
    let reopened = super::tests::project(log.annotations(), worker);
    assert_eq!(reopened.get_type("State").unwrap().metadata, state.metadata);
    let exact = reopened
        .decompile_entry(&DecompileEntryRequest { address: ENTRY, validation: EntryValidation::AnalystAsserted })
        .unwrap();
    assert!(!exact.decompilation.code.is_empty());
    reopened.delete_type("State").unwrap();
    assert_eq!(reopened.list_types(None, 0, 10).unwrap().total, 0);
}

#[test]
fn native_crud_uses_real_layouts_and_survives_history_reopen_and_exact_entry() {
    crud_layout_and_replay(None);
}

#[test]
fn worker_crud_matches_native_without_host_fallback() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    crud_layout_and_replay(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
}

#[test]
fn enums_unions_callbacks_and_packing_report_native_metadata() {
    let project = project(Annotations::in_memory(), None);
    project.declare_types(&declaration("enum Color { red = 1, blue = 7 }; ")).unwrap();
    let color = project.get_type("Color").unwrap().metadata;
    assert_eq!(color.kind, NamedTypeKind::Enum);
    assert!(color.enum_values.iter().any(|value| value.name == "blue" && value.value == "7"));
    project.declare_types(&declaration("union Number { int4 integer; float8 floating; }; ")).unwrap();
    let number = project.get_type("Number").unwrap().metadata;
    assert_eq!(number.kind, NamedTypeKind::Union);
    assert_eq!(number.size, Some(8));
    assert!(number.fields.iter().all(|field| field.offset == 0));
    project.declare_types(&declaration("typedef int4 (*Callback)(union Number *value);")).unwrap();
    let callback = project.get_type("Callback").unwrap().metadata;
    assert!(callback.callback.is_some());
    assert!(callback.dependencies.contains(&"Number".to_owned()));
    assert!(project.delete_type("Number").is_err());
    project
        .declare_types(&DeclareTypesRequest {
            header: Some("#pragma pack(push,1)\nstruct Packed { char tag; int4 value; };\n#pragma pack(pop)\n".into()),
            ..Default::default()
        })
        .unwrap();
    let packed = project.get_type("Packed").unwrap().metadata;
    assert_eq!(packed.packing, Some(1));
    assert_eq!(packed.alignment, Some(1));
    assert_eq!(packed.size, Some(5));
    assert_eq!(packed.fields[1].offset, 1);
}

#[test]
fn replacement_and_response_preflight_failures_append_nothing() {
    let log = LogFixture::new();
    let project = project(log.annotations(), None);
    project.declare_types(&declaration("struct State { int4 gain; int4 bias; }; ")).unwrap();
    project.set_signature(ENTRY, Some("int4 subject(struct State *state, int4 n);")).unwrap();
    let accepted = log.bytes();
    assert!(project.delete_type("State").is_err());
    assert_eq!(log.bytes(), accepted);
    assert!(
        project
            .declare_types_with_preflight(
                &DeclareTypesRequest { replace: true, ..declaration("struct State { int8 gain; }; ") },
                |_| Err(ApiError::Invalid("response exceeds 60000 bytes".into())),
            )
            .is_err()
    );
    assert_eq!(log.bytes(), accepted);
    assert_eq!(project.get_type("State").unwrap().metadata.fields.len(), 2);
    let result = project
        .declare_types(&DeclareTypesRequest {
            replace: true,
            ..declaration("struct State { int8 gain; int8 bias; }; ")
        })
        .unwrap();
    assert!(result.changed);
    assert_eq!(project.get_type("State").unwrap().metadata.size, Some(16));
}

#[test]
fn legacy_types_remain_read_only_and_cannot_redefine_library_types() {
    let log = LogFixture::new();
    let project = project(log.annotations(), None);
    project.set_types(ENTRY, Some("struct Legacy { int4 value; }; ")).unwrap();
    assert_eq!(project.get_type("Legacy").unwrap().scope, "native");
    assert!(project.delete_type("Legacy").is_err());
    project.declare_types(&declaration("struct Current { int4 value; }; ")).unwrap();
    assert_eq!(project.list_types(None, 0, 10).unwrap().total, 1);
    let accepted = log.bytes();
    assert!(project.set_types(ENTRY + 1, Some("struct Current { int8 changed; }; ")).is_err());
    assert_eq!(log.bytes(), accepted);
    assert!(project.declare_types(&declaration("struct Legacy { int8 changed; }; ")).is_err());
    assert_eq!(log.bytes(), accepted);
}

#[test]
fn multi_name_units_are_not_silently_split_or_partially_deleted() {
    let project = project(Annotations::in_memory(), None);
    let result = project.declare_types(&declaration("typedef int4 First, Second;")).unwrap();
    assert!(!result.warnings.is_empty());
    assert!(project.delete_type("First").is_err());
    assert!(
        project.declare_types(&DeclareTypesRequest { replace: true, ..declaration("typedef int8 First;") }).is_err()
    );
    assert_eq!(project.get_type("First").unwrap().metadata.size, Some(4));
    assert_eq!(project.get_type("Second").unwrap().metadata.size, Some(4));
}

#[test]
fn independent_statements_in_one_request_remain_independently_removable() {
    let project = project(Annotations::in_memory(), None);
    project
        .declare_types(&declaration(
            "struct State { int4 value; }; typedef struct State *StatePtr; \
         enum Mode { idle = 0, ready = 1 }; typedef int4 Scratch;",
        ))
        .unwrap();
    let value = serde_json::to_value(project.get_type("State").unwrap()).unwrap();
    assert_eq!(value["name"], "State");
    assert_eq!(value["size"], 4);
    assert!(value.get("metadata").is_none());
    project.delete_type("Scratch").unwrap();
    project.delete_type("StatePtr").unwrap();
    assert!(project.get_type("State").is_ok());
    assert!(project.get_type("Mode").is_ok());
    project.delete_type("State").unwrap();
}

fn import_source_header(worker: Option<WorkerConfig>) {
    let project = project(Annotations::in_memory(), worker);
    let request = DeclareTypesRequest {
        header: Some(include_str!("../../../tests/fixtures/src/type-library.h").to_owned()),
        ..Default::default()
    };
    project.declare_types(&request).unwrap();
    let record = project.get_type("TypeLibraryRecord").unwrap();
    assert_eq!(record.metadata.size, Some(32));
    assert_eq!(record.metadata.fields.iter().map(|field| field.offset).collect::<Vec<_>>(), vec![0, 4, 8, 16, 24]);
    let group = record.declaration.unwrap();
    assert!(group.names.contains(&"TypeLibraryCallback".to_owned()));
    assert!(group.names.contains(&"TypeLibraryRecord".to_owned()));
    assert_eq!(group.declarations.matches("struct TypeLibraryRecord;").count(), 1);
    let units = stored_declarations(&project.annotations()).unwrap();
    let names: Vec<_> = units.iter().flat_map(|unit| &unit.names).collect();
    assert_eq!(names.iter().copied().collect::<BTreeSet<_>>().len(), names.len());
    for (name, size, offset, packing) in [
        ("TypeLibraryPacked", 7, 1, Some(1)),
        ("TypeLibraryPackTwo", 6, 2, Some(2)),
        ("TypeLibraryRestoredPackOne", 5, 1, Some(1)),
        ("TypeLibraryNatural", 8, 4, None),
    ] {
        let ty = project.get_type(name).unwrap().metadata;
        assert_eq!(ty.size, Some(size), "{name}");
        assert_eq!(ty.fields[1].offset, offset, "{name}");
        assert_eq!(ty.packing, packing, "{name}");
    }
    let accepted = serde_json::to_value(project.annotation_list()).unwrap();
    assert!(!project.declare_types(&request).unwrap().changed);
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), accepted);
}

#[test]
fn source_header_preserves_forward_callback_cycles_and_each_packing_context() {
    import_source_header(None);
}

#[test]
fn source_header_worker_preserves_forward_callback_cycles_and_each_packing_context() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    import_source_header(Some(WorkerConfig { executable: Some(PathBuf::from(executable)), ..Default::default() }));
}

#[test]
fn forward_completion_merges_intervening_units_but_never_crosses_packing_contexts() {
    let log = LogFixture::new();
    let project = project(log.annotations(), None);
    project.declare_types(&declaration("struct Forward;")).unwrap();
    project.declare_types(&declaration("typedef int4 (*Callback)(struct Forward *record);")).unwrap();
    let accepted = log.bytes();
    assert!(
        project
            .declare_types(&DeclareTypesRequest {
                packing: Some(1),
                ..declaration("struct Forward { Callback callback; };")
            })
            .is_err()
    );
    assert_eq!(log.bytes(), accepted);
    assert!(project.get_type("Forward").unwrap().metadata.incomplete);
    project.declare_types(&declaration("struct Forward { Callback callback; };")).unwrap();
    let forward = project.get_type("Forward").unwrap();
    assert_eq!(forward.metadata.size, Some(8));
    assert_eq!(forward.declaration.unwrap().names, vec!["Callback", "Forward"]);
    assert!(project.delete_type("Forward").is_err());
    assert!(project.declare_types(&declaration("struct Forward { int4 changed; };")).is_err());
    assert_eq!(project.get_type("Forward").unwrap().metadata.size, Some(8));
}

#[test]
fn deletion_uses_native_edges_not_field_name_substrings() {
    let project = project(Annotations::in_memory(), None);
    project.declare_types(&declaration("struct String { int4 value; }; ")).unwrap();
    project.declare_types(&declaration("struct Holder { int4 String; }; ")).unwrap();
    project.delete_type("String").unwrap();
    assert_eq!(project.get_type("Holder").unwrap().metadata.fields[0].name, "String");
}

#[test]
fn replacement_with_an_incomplete_by_value_dependency_does_not_persist() {
    let log = LogFixture::new();
    let project = project(log.annotations(), None);
    project.declare_types(&declaration("struct Value { int4 value; }; ")).unwrap();
    project.declare_types(&declaration("struct Wrapper { struct Value value; }; ")).unwrap();
    let accepted = log.bytes();
    assert!(project.declare_types(&DeclareTypesRequest { replace: true, ..declaration("struct Value;") }).is_err());
    assert_eq!(log.bytes(), accepted);
    assert_eq!(project.get_type("Value").unwrap().metadata.size, Some(4));
}

#[test]
fn undo_refuses_external_signature_that_would_recreate_a_removed_forward() {
    let log = LogFixture::new();
    let project = project(log.annotations(), None);
    project.declare_types(&declaration("struct State { int4 value; }; ")).unwrap();
    let mut external = log.annotations();
    external.set(Field::Signature, ENTRY, Some("int4 subject(struct State *state, int4 n);".into())).unwrap();
    let accepted = log.bytes();
    assert!(project.undo().is_err());
    assert_eq!(log.bytes(), accepted);
    assert_eq!(project.get_type("State").unwrap().metadata.size, Some(4));
}
