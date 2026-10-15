#![cfg(unix)]

use std::fs::{DirBuilder, File, Permissions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use rampage_api::{
    DebuggerBackend, DebuggerCapturePreview, DebuggerCapturePublicationStatus, DebuggerCaptureRequest,
    DebuggerPermissions, DebuggerToken, Project, prepare_debugger_capture, read_debugger_capture_publication,
};
use rampage_loaders::{Binary, Details, Format, SectionKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SLIDE: u64 = 0x4000_0000;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "dc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Fixture {
    directory: Directory,
    source_path: PathBuf,
    source: Arc<Project>,
    request: DebuggerCaptureRequest,
    replies: Vec<Value>,
}

impl Fixture {
    fn new() -> Self {
        let directory = Directory::new();
        let source_path = directory.join("original.macho");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.macho");
        std::fs::copy(fixture, &source_path).unwrap();
        let source = Arc::new(Project::new(Binary::open(&source_path).unwrap()));
        let Details::MachO(details) = &source.binary.details else { panic!("owned Mach-O fixture") };
        let section = source
            .binary
            .sections
            .iter()
            .find(|section| section.kind == SectionKind::Code && section.file_size >= 4)
            .unwrap();
        let request = DebuggerCaptureRequest {
            expected_token: DebuggerToken {
                backend: DebuggerBackend::LldbSb,
                session_id: "controlled-client-capture".into(),
                process_unique_id: 7,
                stop_id: 3,
                target_index: 0,
            },
            module_index: 0,
            module_uuid: details.uuid.clone().unwrap(),
            thread_id: 0x123,
            file_address: section.address,
            size: 4,
            permissions: DebuggerPermissions::ReadExecute,
        };
        let replies = replies(&source.binary, &request);
        Self { directory, source_path, source, request, replies }
    }

    fn prepare(&self, socket: &Path) -> Result<DebuggerCapturePreview, rampage_api::ApiError> {
        prepare_debugger_capture(
            Arc::clone(&self.source),
            socket,
            &self.request,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
    }

    fn server(&self) -> Server {
        Server::new(self.directory.join("s"), self.replies.clone(), |_, _| {})
    }
}

fn response(request: &DebuggerCaptureRequest, operation: &str, data: Value) -> Value {
    json!({
        "protocol": "rampage-lldb-query-v1", "ok": true, "operation": operation,
        "token": request.expected_token, "data": data,
        "observation": {
            "content_sha256": "0".repeat(64), "consistency": "revalidated-non-atomic", "atomic_snapshot": false,
            "identity_scope": "content hash is not stop identity or proof of a point-in-time snapshot",
        },
    })
}

fn replies(binary: &Binary, request: &DebuggerCaptureRequest) -> Vec<Value> {
    let mapping = binary.segment_containing(request.file_address).unwrap();
    let header = binary.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap();
    let leaf = binary.sections.iter().find(|section| section.address == request.file_address).unwrap();
    let data_order = json!({"order": "little", "source": "LLDB target byte order"});
    let session = json!({
        "pid": 42, "state": "stopped", "triple": "x86_64-apple-macosx14.0.0", "architecture": "x86_64",
        "target_byte_order": "little", "data_byte_order": data_order, "address_byte_size": 8,
        "module_count": 1, "thread_count": 1,
        "operations": [
            "describe_session", "list_modules", "list_threads", "read_registers", "read_memory",
            "resolve_module_address",
        ],
        "limits": {
            "request_bytes": 16384, "response_bytes": 262144, "memory_bytes": 65536, "page_items": 128,
            "modules": 4096, "threads": 4096, "resolution_work": 16384, "module_sections": 4096,
            "section_depth": 32, "module_uuid_bytes": 64,
        },
    });
    let module = json!({
        "index": request.module_index, "name": "controlled fixture", "path": "/backend-provenance/never-open.macho",
        "uuid": request.module_uuid, "triple": "x86_64-apple-macosx14.0.0", "target_byte_order": "little",
        "lldb_byte_order": 4, "address_byte_size": 8,
        "image_base": format!("{:#x}", header.address), "runtime_base": format!("{:#x}", header.address + SLIDE),
    });
    let page = json!({"items": [module], "offset": request.module_index, "total": 1, "next_offset": null});
    let mut resolved_module = module.clone();
    resolved_module.as_object_mut().unwrap().remove("image_base");
    resolved_module.as_object_mut().unwrap().remove("runtime_base");
    let resolution = json!({
        "module_uuid": request.module_uuid, "module": resolved_module,
        "module_context": {
            "triple": "x86_64-apple-macosx14.0.0", "object_byte_order": "little", "address_byte_size": 8,
            "data_byte_order": {"order": "unknown", "source": "no runtime data interpretation"},
        },
        "file_address": format!("{:#x}", request.file_address),
        "load_address": format!("{:#x}", request.file_address + SLIDE),
        "section": {
            "index_path": [0, 0], "name": leaf.name,
            "file_base": format!("{:#x}", leaf.address), "file_end": format!("{:#x}", leaf.address + leaf.size),
            "load_base": format!("{:#x}", leaf.address + SLIDE),
            "load_end": format!("{:#x}", leaf.address + leaf.size + SLIDE), "offset": "0x0",
            "ancestors": [{
                "index_path": [0], "name": mapping.name, "file_base": format!("{:#x}", mapping.address),
                "file_end": format!("{:#x}", mapping.address + mapping.size),
                "load_base": format!("{:#x}", mapping.address + SLIDE),
                "load_end": format!("{:#x}", mapping.address + mapping.size + SLIDE),
            }],
        },
        "mapping": {
            "base": format!("{:#x}", mapping.address + SLIDE),
            "end": format!("{:#x}", mapping.address + mapping.size + SLIDE), "permissions": "r-x",
        },
        "interpretation": "raw-addresses-only",
        "address_semantics": "LLDB file virtual address, not a file byte offset",
        "proven_flow": false, "proven_layout": false,
    });
    let stop = json!({
        "source": "SBThread.GetStopReason/current-process-stop", "is_stopped": false, "stop_reason": 3,
    });
    let registers = json!({
        "thread_id": format!("{:#x}", request.thread_id), "required_registers": ["rflags", "rip", "rsp"],
        "data_byte_order": data_order,
        "context": {
            "stop_evidence": stop, "frame_id": 0, "pc": format!("{:#x}", request.file_address + SLIDE),
            "sp": "0x7fff0000", "registers": {
                "rip": format!("{:#x}", request.file_address + SLIDE), "rsp": "0x7fff0000", "rflags": "0x202",
            },
        },
    });
    let bytes = binary.read(request.file_address, request.size).unwrap();
    let memory = json!({
        "address": format!("{:#x}", request.file_address + SLIDE), "size": request.size, "permissions": "r-x",
        "bytes_hex": rampage_arch::hex::bytes(bytes), "data_byte_order": data_order,
        "stop_evidence": stop, "thread_id": request.thread_id, "interpretation": "raw-bytes-only",
        "read_semantics": "LLDB ReadMemory may normalize software-breakpoint trap bytes",
    });
    [
        ("describe_session", session.clone()),
        ("list_modules", page.clone()),
        ("resolve_module_address", resolution.clone()),
        ("read_registers", registers.clone()),
        ("read_memory", memory),
        ("read_registers", registers),
        ("resolve_module_address", resolution),
        ("list_modules", page),
        ("describe_session", session),
    ]
    .into_iter()
    .map(|(operation, data)| response(request, operation, data))
    .collect()
}

struct Server {
    path: PathBuf,
    stop: Option<Sender<()>>,
    worker: Option<JoinHandle<Vec<Value>>>,
}

impl Server {
    fn new(
        path: PathBuf,
        replies: Vec<Value>,
        mut before_reply: impl FnMut(usize, &mut Value) + Send + 'static,
    ) -> Self {
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped) = channel();
        let worker = std::thread::spawn(move || {
            let mut requests = Vec::new();
            loop {
                let (stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match stopped.recv_timeout(Duration::from_millis(2)) {
                            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        }
                    }
                    Err(error) => panic!("fake server accept: {error}"),
                };
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let mut tail = Vec::new();
                reader.read_to_end(&mut tail).unwrap();
                assert!(tail.is_empty());
                let index = requests.len();
                requests.push(request);
                let mut reply = replies
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| panic!("unexpected retry or enlarged query sequence at {index}"));
                before_reply(index, &mut reply);
                let _ = reader.into_inner().write_all(format!("{reply}\n").as_bytes());
            }
            requests
        });
        Self { path, stop: Some(stop), worker: Some(worker) }
    }

    fn finish(mut self) -> Vec<Value> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn hash(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(&Sha256::digest(bytes))
}

fn assert_queries(requests: &[Value], selection: &DebuggerCaptureRequest) {
    let sequence = [
        "describe_session",
        "list_modules",
        "resolve_module_address",
        "read_registers",
        "read_memory",
        "read_registers",
        "resolve_module_address",
        "list_modules",
        "describe_session",
    ];
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request["operation"], sequence[index]);
        assert_eq!(request["version"], 1);
        assert_eq!(request["expected_token"], serde_json::to_value(&selection.expected_token).unwrap());
        assert!(request["response_budget"].as_u64().unwrap() <= 65536);
        assert!(request.get("path").is_none() && request.get("output").is_none());
        assert!(request.get("socket").is_none());
        match sequence[index] {
            "list_modules" => {
                assert_eq!(request["offset"], selection.module_index);
                assert_eq!(request["limit"], 1);
            }
            "resolve_module_address" => {
                assert_eq!(request["module_uuid"], selection.module_uuid);
                assert_eq!(request["file_address"], selection.file_address);
            }
            "read_registers" => {
                assert_eq!(request["thread_id"], selection.thread_id);
                assert_eq!(request["registers"], json!(["rip", "rsp", "rflags"]));
            }
            "read_memory" => {
                assert_eq!(request["thread_id"], selection.thread_id);
                assert_eq!(request["address"], selection.file_address + SLIDE);
                assert_eq!(request["size"], selection.size);
                assert_eq!(request["permissions"], serde_json::to_value(&selection.permissions).unwrap());
            }
            _ => {}
        }
    }
}

#[test]
fn nine_queries_prepare_without_publishing_and_explicit_compare_uses_exact_original() {
    let fixture = Fixture::new();
    let server = fixture.server();
    let preview = fixture.prepare(&server.path).unwrap();
    let requests = server.finish();
    assert_eq!(requests.len(), 9);
    assert_queries(&requests, &fixture.request);
    assert!(Arc::ptr_eq(preview.source_project(), &fixture.source));
    assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), 2);
    let summary = preview.summary();
    assert!(summary.retained_staging_paths.is_empty());
    assert_eq!(summary.file_address, fixture.request.file_address);
    assert_eq!(summary.load_address, fixture.request.file_address + SLIDE);
    assert_eq!(summary.size, fixture.request.size);
    let bytes = fixture.source.binary.read(fixture.request.file_address, fixture.request.size).unwrap();
    assert_eq!(summary.bytes_sha256, hash(bytes));
    assert_eq!(summary.source_image_sha256, hash(fixture.source.binary.image_bytes()));
    let display = serde_json::to_value(summary).unwrap();
    assert_eq!(display["file_address"], format!("{:#x}", fixture.request.file_address));
    assert_eq!(display["permissions"], "r-x");
    let comparison = preview.compare_original().unwrap();
    assert_eq!(comparison.requested_bytes, fixture.request.size);
    assert_eq!(comparison.equal_bytes, fixture.request.size);
    assert_eq!(comparison.changed_bytes, 0);
    assert_eq!(comparison.unavailable_bytes, 0);
    assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), 2);
}

#[test]
fn prepare_keeps_semantically_validated_bytes_owned_without_staging_or_output_namespace_changes() {
    let fixture = Fixture::new();
    let output_directory = Directory::new();
    let server = fixture.server();
    let names = || {
        let mut names: Vec<_> =
            std::fs::read_dir(&fixture.directory.0).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        names.sort();
        names
    };
    let before_names = names();
    let before_output = std::fs::metadata(&output_directory.0).unwrap();
    let before_source = std::fs::metadata(&fixture.source_path).unwrap();
    let preview = fixture.prepare(&server.path).unwrap();
    assert_eq!(server.finish().len(), 9);
    assert!(preview.summary().retained_staging_paths.is_empty());
    assert_eq!(names(), before_names);
    assert_eq!(std::fs::read_dir(&output_directory.0).unwrap().count(), 0);
    let after_output = std::fs::metadata(&output_directory.0).unwrap();
    assert_eq!((after_output.mtime(), after_output.mtime_nsec()), (before_output.mtime(), before_output.mtime_nsec()));
    assert_eq!((after_output.ctime(), after_output.ctime_nsec()), (before_output.ctime(), before_output.ctime_nsec()));
    let after_source = std::fs::metadata(&fixture.source_path).unwrap();
    assert_eq!(
        (after_source.dev(), after_source.ino(), after_source.len()),
        (before_source.dev(), before_source.ino(), before_source.len())
    );
    assert_eq!((after_source.mtime(), after_source.mtime_nsec()), (before_source.mtime(), before_source.mtime_nsec()));
    assert!(Arc::ptr_eq(preview.source_project(), &fixture.source));
    assert_eq!(preview.compare_original().unwrap().equal_bytes, fixture.request.size);
    assert!(preview.summary().retained_staging_paths.is_empty());
}

#[test]
fn explicit_save_is_semantically_readable_without_entry_seeds_or_copied_compiler_context() {
    let fixture = Fixture::new();
    let server = fixture.server();
    let preview = fixture.prepare(&server.path).unwrap();
    server.finish();
    let output = fixture.directory.join("chosen.capture.json");
    assert!(!output.exists());
    let publication = preview.publish(&output).unwrap();
    assert_eq!(publication.path, output);
    assert_eq!(publication.document_sha256, preview.summary().document_sha256);
    assert_eq!(publication.captured_bytes, fixture.request.size);
    assert_eq!(publication.status, DebuggerCapturePublicationStatus::Published);
    assert!(publication.warnings.is_empty());
    assert_eq!(publication.retained_staging_paths.len(), 1);
    let document = std::fs::read(&output).unwrap();
    assert_eq!(hash(&document), publication.document_sha256);
    let raw: Value = serde_json::from_slice(&document).unwrap();
    assert_eq!(raw["entry"], Value::Null);
    assert_eq!(raw["seeds"], json!([]));
    assert_eq!(raw["target"], json!({"platform": "darwin"}));
    assert_eq!(raw["regions"].as_array().unwrap().len(), 1);
    let binary = Binary::open(&output).unwrap();
    assert_eq!(binary.format, Format::Snapshot);
    assert!(binary.entry.is_none() && binary.function_starts.is_empty());
    assert_eq!(binary.snapshot_registers.len(), 3);
    assert_eq!(binary.snapshot_modules.len(), 1);
    assert_eq!(binary.snapshot_modules[0].path, "/backend-provenance/never-open.macho");
    assert_eq!(binary.segments[0].size, fixture.request.size);
    assert_eq!(binary.segments[0].address, preview.summary().load_address);
    assert_eq!(binary.image_bytes().len(), fixture.request.size as usize);
    let provenance: Value = serde_json::from_str(binary.provenance.as_deref().unwrap()).unwrap();
    assert_eq!(provenance["atomic_snapshot"], false);
    assert_eq!(provenance["historical_token"], serde_json::to_value(&fixture.request.expected_token).unwrap());
    assert_eq!(provenance["observations"].as_array().unwrap().len(), 9);
    assert_eq!(
        provenance["observations"][4]["data"]["read_semantics"],
        "LLDB ReadMemory may normalize software-breakpoint trap bytes"
    );
    assert!(preview.summary().limitations.iter().any(|text| text.contains("Historical token")));
    assert!(preview.summary().limitations.iter().any(|text| text.contains("intersecting-section")));
    assert_eq!(std::fs::metadata(output).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), 4, "staging retention is explicit");
    assert!(publication.retained_staging_paths.iter().all(|path| path.exists()));
}

#[test]
fn exact_range_end_is_accepted_but_leaf_ancestor_mapping_gaps_and_permissions_refuse() {
    let fixture = Fixture::new();
    let leaf = &fixture.replies[2]["data"]["section"];
    let file_end = format!("{:#x}", fixture.request.file_address + fixture.request.size);
    let load_end = format!("{:#x}", fixture.request.file_address + SLIDE + fixture.request.size);
    let mut exact = fixture.replies.clone();
    exact[2]["data"]["section"]["file_end"] = json!(file_end);
    exact[2]["data"]["section"]["load_end"] = json!(load_end);
    exact[6] = exact[2].clone();
    let server = Server::new(fixture.directory.join("exact"), exact, |_, _| {});
    fixture.prepare(&server.path).unwrap();
    assert_eq!(server.finish().len(), 9);
    assert!(leaf["file_end"].is_string());
    for (pointer, value) in [
        ("/data/section/file_end", json!(format!("{:#x}", fixture.request.file_address + 3))),
        ("/data/section/load_end", json!(format!("{:#x}", fixture.request.file_address + SLIDE + 3))),
        ("/data/section/ancestors/0/file_end", json!(format!("{:#x}", fixture.request.file_address + 3))),
        ("/data/section/index_path", json!([1, 0])),
        ("/data/section/offset", json!("0x1")),
        ("/data/mapping/base", json!(format!("{:#x}", fixture.request.file_address + SLIDE + 1))),
        ("/data/mapping/end", json!(format!("{:#x}", fixture.request.file_address + SLIDE + 3))),
        ("/data/mapping/permissions", json!("rw-")),
        ("/data/mapping/permissions", json!("r?x")),
    ] {
        assert_refusal_at(&fixture, 2, pointer, value);
    }
}

fn assert_refusal_at(fixture: &Fixture, index: usize, pointer: &str, value: Value) {
    let mut replies = fixture.replies.clone();
    *replies[index].pointer_mut(pointer).unwrap() = value;
    let name = format!("r{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let server = Server::new(fixture.directory.join(&name), replies, |_, _| {});
    assert!(fixture.prepare(&server.path).is_err(), "query {index}: {pointer}");
    let requests = server.finish();
    assert_eq!(requests.len(), index + 1, "must refuse without refresh/retry: {pointer}");
    assert_queries(&requests, &fixture.request);
}

#[test]
fn unknown_data_endianness_unsupported_variants_and_conflicting_identity_refuse_early() {
    let fixture = Fixture::new();
    for (index, pointer, value) in [
        (0, "/data/data_byte_order/order", json!("unknown")),
        (0, "/data/data_byte_order/order", json!("big")),
        (0, "/data/architecture", json!("aarch64")),
        (0, "/data/triple", json!("arm64-apple-macosx14.0.0")),
        (0, "/data/triple", json!("x86_64h-apple-macosx14.0.0")),
        (0, "/data/triple", json!("x86_64-unknown-linux-gnu")),
        (0, "/data/triple", json!("x86_64-apple-ios17.0-simulator")),
        (0, "/data/address_byte_size", json!(4)),
        (1, "/data/items/0/index", json!(1)),
        (1, "/data/items/0/uuid", json!("00112233-4455-6677-8899-aabbccddeeff")),
        (1, "/data/items/0/uuid", json!("00000000-0000-0000-0000-000000000000-")),
        (1, "/data/items/0/triple", json!("x86_64h-apple-macosx14.0.0")),
        (1, "/data/items/0/target_byte_order", json!("unknown")),
        (1, "/data/items/0/image_base", json!("0x0")),
        (1, "/data/items/0/runtime_base", Value::Null),
        (1, "/data/offset", json!(1)),
        (1, "/data/total", json!(2)),
        (2, "/data/module/index", json!(1)),
        (2, "/data/module/name", json!("different module")),
        (2, "/data/module_context/address_byte_size", json!(4)),
        (2, "/data/proven_flow", json!(true)),
        (2, "/data/address_semantics", json!("file byte offset")),
        (3, "/data/data_byte_order/order", json!("unknown")),
        (4, "/data/data_byte_order/order", json!("unknown")),
    ] {
        assert_refusal_at(&fixture, index, pointer, value);
    }
}

#[test]
fn partial_bytes_thread_context_changes_and_all_revalidation_differences_refuse() {
    let fixture = Fixture::new();
    for (index, pointer, value) in [
        (3, "/data/thread_id", json!("0x124")),
        (3, "/data/context/frame_id", json!(1)),
        (3, "/data/context/registers/rflags", json!("0x100000000")),
        (3, "/data/context/registers/rip", json!("0x0")),
        (4, "/data/bytes_hex", json!("90")),
        (4, "/data/bytes_hex", json!("0000000g")),
        (4, "/data/bytes_hex", json!("000000000")),
        (4, "/data/bytes_hex", json!("éééé")),
        (4, "/data/size", json!(5)),
        (4, "/data/thread_id", Value::Null),
        (4, "/data/permissions", json!("rwx")),
        (4, "/data/read_semantics", json!("unmodified trap bytes")),
        (4, "/data/stop_evidence/stop_reason", json!(4)),
        (5, "/data/context/registers/rsp", json!("0x7fff0008")),
        (6, "/data/section/name", json!("changed")),
        (7, "/data/items/0/path", json!("changed provenance")),
        (8, "/data/pid", json!(43)),
    ] {
        assert_refusal_at(&fixture, index, pointer, value);
    }
    for index in 0..9 {
        assert_refusal_at(&fixture, index, "/token/stop_id", json!(4));
        let mut replies = fixture.replies.clone();
        replies[index] = json!({
            "protocol": "rampage-lldb-query-v1", "ok": false, "operation": replies[index]["operation"],
            "error": {"code": "stale_token", "message": "controlled stale stop"},
        });
        let name = format!("stale{index}");
        let server = Server::new(fixture.directory.join(&name), replies, |_, _| {});
        assert!(fixture.prepare(&server.path).unwrap_err().to_string().contains("stale_token"));
        let requests = server.finish();
        assert_eq!(requests.len(), index + 1);
        assert_queries(&requests, &fixture.request);
    }
}

#[test]
fn fallback_stop_evidence_accepts_recognized_sdk_reasons_and_refuses_unknowns_in_each_observation() {
    for reason in [2, 3, 15] {
        let mut fixture = Fixture::new();
        for index in [3, 5] {
            fixture.replies[index]["data"]["context"]["stop_evidence"]["stop_reason"] = json!(reason);
        }
        fixture.replies[4]["data"]["stop_evidence"]["stop_reason"] = json!(reason);
        let server = fixture.server();
        fixture.prepare(&server.path).unwrap();
        assert_eq!(server.finish().len(), 9);
    }
    let fixture = Fixture::new();
    for (index, pointer) in [
        (3, "/data/context/stop_evidence/stop_reason"),
        (4, "/data/stop_evidence/stop_reason"),
        (5, "/data/context/stop_evidence/stop_reason"),
    ] {
        for reason in [16u64, 999, u32::MAX as u64] {
            assert_refusal_at(&fixture, index, pointer, json!(reason));
        }
    }
    let mut fixture = Fixture::new();
    let affirmative = json!({"source": "SBThread.IsStopped", "is_stopped": true, "stop_reason": u32::MAX});
    for index in [3, 5] {
        fixture.replies[index]["data"]["context"]["stop_evidence"] = affirmative.clone();
    }
    fixture.replies[4]["data"]["stop_evidence"] = affirmative;
    let server = fixture.server();
    fixture.prepare(&server.path).unwrap();
    assert_eq!(server.finish().len(), 9);
}

#[test]
fn unknown_evidence_fields_never_silently_gain_capture_authority() {
    let fixture = Fixture::new();
    for (index, pointer) in [
        (0, "/data"),
        (0, "/data/data_byte_order"),
        (0, "/data/limits"),
        (1, "/data/items/0"),
        (2, "/data"),
        (2, "/data/module_context"),
        (2, "/data/section"),
        (2, "/data/section/ancestors/0"),
        (2, "/data/mapping"),
        (3, "/data/context"),
        (3, "/data/context/registers"),
        (4, "/data"),
    ] {
        let mut replies = fixture.replies.clone();
        replies[index].pointer_mut(pointer).unwrap()["future_authority"] = json!(true);
        let name = format!("u{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let server = Server::new(fixture.directory.join(&name), replies, |_, _| {});
        assert!(fixture.prepare(&server.path).is_err());
        assert_eq!(server.finish().len(), index + 1);
    }
}

#[test]
fn cancellation_and_zero_composition_deadline_issue_no_queries_and_never_enlarge_selection() {
    let fixture = Fixture::new();
    let server = fixture.server();
    for (timeout, cancelled) in [(Duration::ZERO, false), (Duration::from_secs(5), true)] {
        assert!(
            prepare_debugger_capture(
                Arc::clone(&fixture.source),
                &server.path,
                &fixture.request,
                timeout,
                &AtomicBool::new(cancelled),
            )
            .is_err()
        );
    }
    for size in [0, 4097, u64::MAX] {
        let mut request = fixture.request.clone();
        request.size = size;
        assert!(
            prepare_debugger_capture(
                Arc::clone(&fixture.source),
                &server.path,
                &request,
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .is_err()
        );
    }
    assert!(server.finish().is_empty());
}

#[test]
fn cancellation_between_queries_refuses_without_retry_or_publishing() {
    let fixture = Fixture::new();
    let cancellation = Arc::new(AtomicBool::new(false));
    let cancel = Arc::clone(&cancellation);
    let server = Server::new(fixture.directory.join("s"), fixture.replies.clone(), move |index, _| {
        if index == 3 {
            cancel.store(true, Ordering::Release);
        }
    });
    let result = prepare_debugger_capture(
        Arc::clone(&fixture.source),
        &server.path,
        &fixture.request,
        Duration::from_secs(5),
        &cancellation,
    );
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert_eq!(server.finish().len(), 4);
    assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), 2);
}

#[test]
fn composition_deadline_includes_waiting_for_a_response_and_does_not_refresh_the_token() {
    let fixture = Fixture::new();
    let (release, held) = channel();
    let server = Server::new(fixture.directory.join("s"), fixture.replies.clone(), move |index, _| {
        if index == 0 {
            held.recv_timeout(Duration::from_secs(3)).unwrap();
        }
    });
    let result = prepare_debugger_capture(
        Arc::clone(&fixture.source),
        &server.path,
        &fixture.request,
        Duration::from_millis(100),
        &AtomicBool::new(false),
    );
    release.send(()).unwrap();
    assert!(result.unwrap_err().to_string().contains("deadline"));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_queries(&requests, &fixture.request);
}

#[test]
fn explicit_comparison_reports_changed_prepared_bytes_and_owned_inputs_have_no_source_proof() {
    let mut fixture = Fixture::new();
    let original = fixture.source.binary.read(fixture.request.file_address, fixture.request.size).unwrap();
    let changed: Vec<_> = original.iter().map(|byte| byte ^ 0xff).collect();
    fixture.replies[4]["data"]["bytes_hex"] = json!(rampage_arch::hex::bytes(&changed));
    let server = fixture.server();
    let preview = fixture.prepare(&server.path).unwrap();
    assert_eq!(server.finish().len(), 9);
    let comparison = preview.compare_original().unwrap();
    assert_eq!(comparison.changed_bytes, fixture.request.size);
    assert_eq!(comparison.equal_bytes, 0);
    let output = fixture.directory.join("explicit.json");
    preview.publish(&output).unwrap();
    let owned = Arc::new(Project::new(Binary::open(&output).unwrap()));
    let server = Server::new(fixture.directory.join("owned"), fixture.replies.clone(), |_, _| {});
    let result = prepare_debugger_capture(
        owned,
        &server.path,
        &fixture.request,
        Duration::from_secs(5),
        &AtomicBool::new(false),
    );
    assert!(result.unwrap_err().to_string().contains("owned input"));
    assert!(server.finish().is_empty());
}

#[test]
fn in_place_source_mutation_and_path_replacement_are_revalidated_before_prepare_and_save() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let source_path = fixture.source_path.clone();
        let server = Server::new(fixture.directory.join("s"), fixture.replies.clone(), move |index, _| {
            if index == 8 {
                if replace {
                    let replacement = source_path.with_extension("replacement");
                    std::fs::copy(&source_path, &replacement).unwrap();
                    std::fs::rename(replacement, &source_path).unwrap();
                } else {
                    let file = File::options().append(true).open(&source_path).unwrap();
                    (&file).write_all(b"changed source").unwrap();
                    file.sync_all().unwrap();
                }
            }
        });
        assert!(fixture.prepare(&server.path).unwrap_err().to_string().contains("backing"));
        assert_eq!(server.finish().len(), 9);
    }
    for replace in [false, true] {
        let fixture = Fixture::new();
        let server = fixture.server();
        let preview = fixture.prepare(&server.path).unwrap();
        server.finish();
        if replace {
            let replacement = fixture.directory.join("replacement");
            std::fs::copy(&fixture.source_path, &replacement).unwrap();
            std::fs::rename(replacement, &fixture.source_path).unwrap();
        } else {
            let mut file = File::options().append(true).open(&fixture.source_path).unwrap();
            file.write_all(b"changed after preview").unwrap();
            file.sync_all().unwrap();
        }
        let output = fixture.directory.join("must-not-exist.json");
        assert!(preview.publish(&output).is_err());
        assert!(preview.compare_original().is_err());
        assert!(!output.exists());
        assert!(Arc::ptr_eq(preview.source_project(), &fixture.source));
        assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), 2);
    }
}

#[test]
fn source_arc_is_not_rebound_to_a_reopened_identical_project() {
    let fixture = Fixture::new();
    let server = fixture.server();
    let preview = fixture.prepare(&server.path).unwrap();
    server.finish();
    let reloaded = Arc::new(Project::new(Binary::open(&fixture.source_path).unwrap()));
    assert!(!Arc::ptr_eq(preview.source_project(), &reloaded));
    assert!(Arc::ptr_eq(preview.source_project(), &fixture.source));
    assert!(preview.compare_original().is_ok());
}

#[test]
fn private_parent_no_clobber_symlink_and_racing_publications_preserve_existing_files() {
    let fixture = Fixture::new();
    let server = fixture.server();
    let preview = Arc::new(fixture.prepare(&server.path).unwrap());
    server.finish();
    let existing = fixture.directory.join("existing.json");
    std::fs::write(&existing, b"keep exactly").unwrap();
    assert!(preview.publish(&existing).is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep exactly");
    let link = fixture.directory.join("link.json");
    symlink(&existing, &link).unwrap();
    assert!(preview.publish(&link).is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep exactly");
    let parent = fixture.directory.join("public");
    DirBuilder::new().mode(0o755).create(&parent).unwrap();
    assert!(preview.publish(&parent.join("refused.json")).is_err());
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    let alias = fixture.directory.join("alias");
    symlink(&fixture.directory.0, &alias).unwrap();
    assert!(preview.publish(&alias.join("refused.json")).is_err());
    assert!(!fixture.directory.join("refused.json").exists());
    for path in [PathBuf::from("relative.json"), fixture.directory.join("public/../refused.json")] {
        assert!(preview.publish(&path).is_err());
    }
    let output = fixture.directory.join("race.json");
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let preview = Arc::clone(&preview);
            let output = output.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                preview.publish(&output)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(hash(&std::fs::read(&output).unwrap()), preview.summary().document_sha256);
    assert_eq!(std::fs::metadata(&output).unwrap().nlink(), 2, "staging link is explicitly retained");
    let second = fixture.directory.join("second-explicit-save.json");
    let publication = preview.publish(&second).unwrap();
    assert_eq!(std::fs::read(&second).unwrap(), std::fs::read(&output).unwrap());
    assert!(publication.retained_staging_paths.iter().all(|path| path.exists()));
}

#[test]
fn static_cpu_variant_uuid_width_backing_and_unbacked_ranges_refuse_without_queries() {
    for (offset, bytes) in [(8, 8u32.to_le_bytes()), (4, 7u32.to_le_bytes())] {
        let fixture = Fixture::new();
        let mut image = std::fs::read(&fixture.source_path).unwrap();
        image[offset..offset + 4].copy_from_slice(&bytes);
        let changed = fixture.directory.join("variant.macho");
        std::fs::write(&changed, image).unwrap();
        let Ok(binary) = Binary::open(&changed) else { continue };
        let server = fixture.server();
        assert!(
            prepare_debugger_capture(
                Arc::new(Project::new(binary)),
                &server.path,
                &fixture.request,
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .is_err()
        );
        assert!(server.finish().is_empty());
    }
    let fixture = Fixture::new();
    let server = fixture.server();
    let mut request = fixture.request.clone();
    request.module_uuid = "00112233-4455-6677-8899-aabbccddeeff".into();
    assert!(
        prepare_debugger_capture(
            Arc::clone(&fixture.source),
            &server.path,
            &request,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .is_err()
    );
    request = fixture.request.clone();
    request.file_address = 0;
    assert!(
        prepare_debugger_capture(
            Arc::clone(&fixture.source),
            &server.path,
            &request,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .is_err()
    );
    assert!(server.finish().is_empty());
}

fn private_publication(directory: &Directory, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    let mut file = File::options().write(true).create_new(true).mode(0o600).open(&path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    path
}

#[test]
fn publication_reader_returns_exact_saved_bytes_without_queries_writes_or_workspace_changes() {
    let fixture = Fixture::new();
    let server = fixture.server();
    let preview = fixture.prepare(&server.path).unwrap();
    assert_eq!(server.finish().len(), 9);
    let output = fixture.directory.join("explicit-saved.json");
    let publication = preview.publish(&output).unwrap();
    let before = std::fs::read_dir(&fixture.directory.0).unwrap().count();
    let expected = std::fs::read(&output).unwrap();
    let verified = read_debugger_capture_publication(&output, &publication.document_sha256).unwrap();
    assert_eq!(verified, expected);
    assert_eq!(hash(&verified), preview.summary().document_sha256);
    assert!(Arc::ptr_eq(preview.source_project(), &fixture.source));
    assert_eq!(std::fs::read_dir(&fixture.directory.0).unwrap().count(), before);
    assert_eq!(std::fs::read(&output).unwrap(), expected);
}

#[test]
fn publication_reader_refuses_unknown_noncanonical_or_mismatching_document_hashes() {
    let directory = Directory::new();
    let bytes = br#"{"format":"controlled-read-only-verification-fixture"}"#;
    let path = private_publication(&directory, "document.json", bytes);
    for expected in [String::new(), "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), "0".repeat(64)] {
        assert!(read_debugger_capture_publication(&path, &expected).is_err(), "{expected}");
    }
    assert_eq!(read_debugger_capture_publication(&path, &hash(bytes)).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn publication_reader_refuses_mutated_or_replaced_saved_content() {
    for replace in [false, true] {
        let directory = Directory::new();
        let bytes = b"controlled original saved bytes";
        let path = private_publication(&directory, "saved.json", bytes);
        let expected_sha256 = hash(bytes);
        if replace {
            let replacement = private_publication(&directory, "replacement", b"different replacement bytes");
            std::fs::rename(replacement, &path).unwrap();
        } else {
            let mut file = File::options().write(true).truncate(true).open(&path).unwrap();
            file.write_all(b"mutated saved bytes").unwrap();
            file.sync_all().unwrap();
        }
        let changed = std::fs::read(&path).unwrap();
        assert!(read_debugger_capture_publication(&path, &expected_sha256).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), changed);
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}

#[test]
fn publication_reader_rejects_symlink_components_nonregular_files_and_nonprivate_modes() {
    let directory = Directory::new();
    let bytes = b"operator-owned local document";
    let expected_sha256 = hash(bytes);
    let path = private_publication(&directory, "saved.json", bytes);
    let link = directory.join("link.json");
    symlink(&path, &link).unwrap();
    assert!(read_debugger_capture_publication(&link, &expected_sha256).is_err());
    let alias = directory.join("alias");
    symlink(&directory.0, &alias).unwrap();
    assert!(read_debugger_capture_publication(&alias.join("saved.json"), &expected_sha256).is_err());
    let child = directory.join("child");
    DirBuilder::new().mode(0o700).create(&child).unwrap();
    assert!(read_debugger_capture_publication(&child, &expected_sha256).is_err());
    let socket = directory.join("socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    assert!(read_debugger_capture_publication(&socket, &expected_sha256).is_err());
    let fifo = directory.join("fifo");
    assert!(std::process::Command::new("/usr/bin/mkfifo").args(["-m", "600"]).arg(&fifo).status().unwrap().success());
    assert!(read_debugger_capture_publication(&fifo, &expected_sha256).is_err());
    std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert!(read_debugger_capture_publication(&path, &expected_sha256).is_err());
    std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&directory.0, Permissions::from_mode(0o755)).unwrap();
    let public_parent = read_debugger_capture_publication(&path, &expected_sha256);
    std::fs::set_permissions(&directory.0, Permissions::from_mode(0o700)).unwrap();
    assert!(public_parent.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn publication_reader_requires_explicit_absolute_path_and_bounds_bytes_before_reading() {
    let directory = Directory::new();
    let bytes = b"bounded publication";
    let path = private_publication(&directory, "saved.json", bytes);
    for invalid in [
        PathBuf::from("saved.json"),
        directory.join("./saved.json"),
        directory.join("child/../saved.json"),
        PathBuf::from(format!("{}//saved.json", directory.0.display())),
    ] {
        assert!(read_debugger_capture_publication(&invalid, &hash(bytes)).is_err());
    }
    let empty = private_publication(&directory, "empty.json", b"");
    assert!(read_debugger_capture_publication(&empty, &hash(b"")).is_err());
    let maximum = vec![b' '; 1024 * 1024];
    let boundary = private_publication(&directory, "boundary.json", &maximum);
    assert_eq!(read_debugger_capture_publication(&boundary, &hash(&maximum)).unwrap(), maximum);
    File::options().write(true).open(&boundary).unwrap().set_len(1024 * 1024 + 1).unwrap();
    assert!(read_debugger_capture_publication(&boundary, &hash(&maximum)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 3);
}
